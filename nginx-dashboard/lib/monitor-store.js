'use strict';
/**
 * Storage for continuous backend monitoring (features/monitor.js): every
 * probe result for a monitored target, plus an incidents table recording
 * when each target went down and when it came back — "stats dispo backend
 * et voir quand le backend a ete off", the feature as the user asked for it.
 *
 * Same idiom as lib/events.js: node:sqlite, built into Node 22, so this
 * stays dependency-free like the rest of the dashboard. Degrades to an
 * in-memory ring if SQLite is unavailable rather than refusing to start —
 * monitoring then simply loses history across a restart, it doesn't stop
 * working. Its own database file (MONITOR_DB_PATH) rather than reusing
 * events.db: unrelated tables, and unrelated write volume (a probe every
 * few seconds per monitored target vs. a handful of operator actions a day).
 */

const cfg = require('./config');

let db = null;
const MEMORY_CAP = 500; // per target — bounds memory when SQLite is unavailable
const memory = { checks: new Map(), incidents: new Map() };

function initMonitorDb() {
  try {
    const { DatabaseSync } = require('node:sqlite');
    db = new DatabaseSync(cfg.MONITOR_DB_PATH);
    db.exec(`
      PRAGMA journal_mode = WAL;

      CREATE TABLE IF NOT EXISTS checks (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        target_key TEXT    NOT NULL,
        ts         INTEGER NOT NULL,
        ok         INTEGER NOT NULL,
        status     INTEGER,
        ms         INTEGER,
        error      TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_checks_key_ts ON checks(target_key, ts);

      CREATE TABLE IF NOT EXISTS incidents (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        target_key TEXT    NOT NULL,
        started_at INTEGER NOT NULL,
        ended_at   INTEGER,
        last_error TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents(target_key, started_at);
    `);
    purgeOld();
    console.log(`[monitor] DB ready: ${cfg.MONITOR_DB_PATH} (retention: ${cfg.MONITOR_RETENTION_DAYS}d)`);
  } catch (e) {
    console.warn('[monitor] SQLite unavailable — monitoring history will be in-memory only:', e.message);
    db = null;
  }
}

function purgeOld() {
  if (!db) return;
  try {
    const cutoff = Date.now() - cfg.MONITOR_RETENTION_DAYS * 86400_000;
    db.prepare('DELETE FROM checks WHERE ts < ?').run(cutoff);
    // A closed incident older than the retention window is no longer
    // reachable from any surviving check either. An open one is left alone
    // regardless of age — an ongoing outage should never silently disappear.
    db.prepare('DELETE FROM incidents WHERE ended_at IS NOT NULL AND ended_at < ?').run(cutoff);
  } catch { /* a full disk should not take the dashboard down */ }
}

/**
 * Record one probe result and update the incident log: a failed check opens
 * (or continues) an incident for that target, the first success after one
 * closes it.
 *
 * Returns `{ becameDown, becameUp }` — true only on the exact edge where the
 * target's state actually changed (a fresh incident opening / the open
 * incident just closing), never on a check that merely repeats the previous
 * state. features/monitor.js uses this to push a notification only once per
 * transition instead of once per probe (every few seconds otherwise).
 */
function recordCheck(targetKey, { ok, status = null, ms = null, error = null, ts = Date.now() } = {}) {
  if (db) {
    try {
      db.prepare('INSERT INTO checks (target_key, ts, ok, status, ms, error) VALUES (?, ?, ?, ?, ?, ?)')
        .run(targetKey, ts, ok ? 1 : 0, status, ms, error);
      const open = db.prepare(
        'SELECT id FROM incidents WHERE target_key = ? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1'
      ).get(targetKey);
      if (!ok) {
        if (open) db.prepare('UPDATE incidents SET last_error = ? WHERE id = ?').run(error, open.id);
        else db.prepare('INSERT INTO incidents (target_key, started_at, last_error) VALUES (?, ?, ?)').run(targetKey, ts, error);
      } else if (open) {
        db.prepare('UPDATE incidents SET ended_at = ? WHERE id = ?').run(ts, open.id);
      }
      return { becameDown: !ok && !open, becameUp: ok && !!open };
    } catch (e) { console.warn('[monitor] recordCheck error:', e.message); return { becameDown: false, becameUp: false }; }
  }

  // Memory fallback — same open/close logic, no query language to lean on.
  const checks = memory.checks.get(targetKey) || [];
  checks.push({ ts, ok, status, ms, error });
  if (checks.length > MEMORY_CAP) checks.shift();
  memory.checks.set(targetKey, checks);

  const incidents = memory.incidents.get(targetKey) || [];
  const openIncident = incidents.find(i => i.endedAt === null);
  const wasOpen = !!openIncident;
  if (!ok) {
    if (openIncident) openIncident.lastError = error;
    else incidents.push({ startedAt: ts, endedAt: null, lastError: error });
  } else if (openIncident) {
    openIncident.endedAt = ts;
  }
  if (incidents.length > MEMORY_CAP) incidents.shift();
  memory.incidents.set(targetKey, incidents);
  return { becameDown: !ok && !wasOpen, becameUp: ok && wasOpen };
}

/** Most recent checks first. */
function getHistory(targetKey, limit = 200) {
  if (db) {
    try {
      return db.prepare('SELECT ts, ok, status, ms, error FROM checks WHERE target_key = ? ORDER BY ts DESC LIMIT ?')
        .all(targetKey, limit).map(r => ({ ...r, ok: !!r.ok }));
    } catch (e) { console.warn('[monitor] getHistory error:', e.message); return []; }
  }
  return [...(memory.checks.get(targetKey) || [])].reverse().slice(0, limit);
}

/** Incidents for a target — an ongoing one (endedAt null) always sorts first, then most recent. */
function getIncidents(targetKey, limit = 50) {
  if (db) {
    try {
      return db.prepare(
        'SELECT started_at as startedAt, ended_at as endedAt, last_error as lastError FROM incidents ' +
        'WHERE target_key = ? ORDER BY (ended_at IS NULL) DESC, started_at DESC LIMIT ?'
      ).all(targetKey, limit);
    } catch (e) { console.warn('[monitor] getIncidents error:', e.message); return []; }
  }
  return [...(memory.incidents.get(targetKey) || [])]
    .sort((a, b) => (b.endedAt === null) - (a.endedAt === null) || b.startedAt - a.startedAt)
    .slice(0, limit);
}

/** Summary used by the list view: last check, current up/down state, uptime % over the given window. */
function getSummary(targetKey, windowMs = 24 * 3600_000) {
  const since = Date.now() - windowMs;
  let history;
  if (db) {
    try { history = db.prepare('SELECT ok FROM checks WHERE target_key = ? AND ts >= ?').all(targetKey, since); }
    catch { history = []; }
  } else {
    history = (memory.checks.get(targetKey) || []).filter(c => c.ts >= since);
  }
  const total = history.length;
  const okCount = history.filter(c => c.ok).length;
  const last = getHistory(targetKey, 1)[0] || null;
  const openIncident = getIncidents(targetKey, 1).find(i => i.endedAt === null) || null;
  return {
    last,
    up: last ? !!last.ok : null,
    uptimePct: total ? Math.round((okCount / total) * 1000) / 10 : null,
    checksInWindow: total,
    downSince: openIncident ? openIncident.startedAt : null,
  };
}

/**
 * Close a still-open incident for a target that stopped being monitored —
 * the vhost file was edited or deleted, the monitoring flag was turned off,
 * or (targetKey being positional — file::blockIndex::locationIndex::
 * targetIndex) an earlier block/location in the same file was added or
 * removed, shifting every index after it onto a new key.
 *
 * Fix (audit finding MISC-12): without this, an incident opened under a key
 * that later stops being probed (for any of the reasons above) never
 * received another recordCheck() call at all — nothing ever ran the
 * ok-after-failure branch that closes it — so it stayed "open" (down)
 * forever, even though the target might be perfectly healthy again or gone
 * entirely. features/monitor.js's rescan() calls this for every key that
 * disappears between one rescan and the next. `endedAt` is stamped with the
 * given `ts` (when the disappearance was noticed) since the real recovery
 * time, if any, was never observed — an honest "we stopped watching here",
 * not a fabricated recovery time.
 */
function closeOrphanedIncident(targetKey, ts = Date.now()) {
  if (db) {
    try {
      db.prepare('UPDATE incidents SET ended_at = ? WHERE target_key = ? AND ended_at IS NULL')
        .run(ts, targetKey);
    } catch (e) { console.warn('[monitor] closeOrphanedIncident error:', e.message); }
    return;
  }
  const incidents = memory.incidents.get(targetKey);
  if (!incidents) return;
  for (const inc of incidents) if (inc.endedAt === null) inc.endedAt = ts;
}

/** Test/shutdown helper — closes the SQLite handle and clears the memory fallback. */
function closeDb() {
  try { if (db) db.close(); } catch { /* ignore */ }
  db = null;
  memory.checks.clear();
  memory.incidents.clear();
}

module.exports = { initMonitorDb, recordCheck, getHistory, getIncidents, getSummary, purgeOld, closeDb, closeOrphanedIncident };
