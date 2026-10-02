'use strict';
/**
 * Event log and webhook dispatch.
 *
 * Events live in two places: a short in-memory ring for instant reads, and a
 * SQLite table for history that survives a restart. SQLite comes from
 * node:sqlite — built into Node 22, so this stays dependency-free. If it is
 * unavailable the module degrades to memory-only rather than failing to boot.
 *
 * Knows nothing about authentication: routes decide who may read or clear.
 */

const http  = require('http');
const https = require('https');
const cfg   = require('./config');
const { safeLookup } = require('./ssrf-guard');

const MAX_LOG = 200;

const eventLog = [];   // newest first
const webhooks = [];

let eventsDb = null;

// ─── SQLite persistence ──────────────────────────────────────────────────────
function initEventsDb() {
  try {
    const { DatabaseSync } = require('node:sqlite');
    eventsDb = new DatabaseSync(cfg.EVENTS_DB_PATH);
    eventsDb.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER NOT NULL,
        type    TEXT    NOT NULL,
        data    TEXT,
        source  TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    `);
    initStateTable();
    initDigestsTable();
    purgeOldEvents();
    purgeOldDigests();
    console.log(`[events] DB ready: ${cfg.EVENTS_DB_PATH} (retention: ${cfg.EVENTS_RETENTION_DAYS}d)`);
  } catch (e) {
    console.warn('[events] SQLite unavailable — events will be in-memory only:', e.message);
    eventsDb = null;
  }
}

function purgeOldEvents() {
  if (!eventsDb) return;
  try {
    const cutoff = Date.now() - cfg.EVENTS_RETENTION_DAYS * 86400_000;
    eventsDb.prepare('DELETE FROM events WHERE ts < ?').run(cutoff);
  } catch { /* a full disk should not take the dashboard down */ }
}

/**
 * Without this, `digests` grows forever — nothing else in this file ever
 * called it, unlike every other table here (events, traffic-style rollups
 * elsewhere in the project all have an explicit retention window). Reuses
 * EVENTS_RETENTION_DAYS rather than a new env var: same database, same
 * general "how long do we keep operational history" question, one fewer
 * setting to think about. A digest is generated at most daily, so even the
 * default 30-day window caps this at a few dozen rows — this is about
 * keeping the dashboard's history dropdown and the underlying table bounded
 * indefinitely, not about an imminent size problem.
 */
function purgeOldDigests() {
  if (!eventsDb) return;
  try {
    const cutoff = Date.now() - cfg.EVENTS_RETENTION_DAYS * 86400_000;
    eventsDb.prepare('DELETE FROM digests WHERE generated_at < ?').run(cutoff);
  } catch { /* a full disk should not take the dashboard down */ }
}

function persistEvent(type, data, source) {
  if (!eventsDb) return;
  try {
    eventsDb.prepare('INSERT INTO events (ts, type, data, source) VALUES (?, ?, ?, ?)')
      .run(Date.now(), type, typeof data === 'string' ? data : JSON.stringify(data), source || 'system');
  } catch (e) {
    console.warn('[events] persist error:', e.message);
  }
}

const safeParse = s => { try { return JSON.parse(s); } catch { return s; } };

/**
 * Query persisted events. `fromDb: false` means SQLite is unavailable and the
 * caller should fall back to the in-memory ring — the UI shows which is in use.
 */
function queryEvents({ limit = 200, offset = 0, type = null, since = null, until = null } = {}) {
  if (!eventsDb) return { events: [], total: 0, fromDb: false };
  try {
    let where = '1=1';
    const params = [];
    if (type)  { where += ' AND type = ?'; params.push(type); }
    if (since) { where += ' AND ts >= ?';  params.push(since); }
    if (until) { where += ' AND ts <= ?';  params.push(until); }
    const total = eventsDb.prepare(`SELECT COUNT(*) as n FROM events WHERE ${where}`).get(...params).n;
    const rows  = eventsDb.prepare(
      `SELECT * FROM events WHERE ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    // `ts` is the raw epoch-ms column used for the query itself (ORDER BY,
    // since/until filters) — kept on the returned object for anyone that
    // wants it as a number. The UI (and the in-memory recentEvents() path
    // below) expects `timestamp` as an ISO string; without it here, every
    // event read from SQLite (the normal case once it's available — the
    // in-memory ring is only a fallback) rendered as an Invalid Date, shown
    // as "NaNh"/"NaNm" in the events list.
    return {
      events: rows.map(e => ({ ...e, timestamp: new Date(e.ts).toISOString(), data: safeParse(e.data) })),
      total, fromDb: true,
    };
  } catch (e) {
    console.warn('[events] query error:', e.message);
    return { events: [], total: 0, fromDb: false };
  }
}

// ─── Key/value state ─────────────────────────────────────────────────────────
// Shared with anything that needs to survive a restart — currently the session
// table, which used to be lost on every image update.
function initStateTable() {
  if (!eventsDb) return;
  try {
    eventsDb.exec(`CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)`);
  } catch (e) { console.warn('[events] state table:', e.message); }
}

// ─── Digests ──────────────────────────────────────────────────────────────────
// A generated digest (see lib/digest.js) is a compiled snapshot report, not a
// one-line action log entry — it gets its own small table in the same
// database file rather than a second SQLite connection, and rather than
// squeezing a large structured object into the events table's flat `data`
// column meant for short entries.
function initDigestsTable() {
  if (!eventsDb) return;
  try {
    eventsDb.exec(`
      CREATE TABLE IF NOT EXISTS digests (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        generated_at INTEGER NOT NULL,
        period_hours INTEGER NOT NULL,
        content      TEXT    NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_digests_generated_at ON digests(generated_at);
    `);
  } catch (e) { console.warn('[events] digests table:', e.message); }
}

/** Persist a generated digest. Returns the new row's id, or null without SQLite. */
function saveDigest(digest) {
  if (!eventsDb) return null;
  try {
    const r = eventsDb.prepare('INSERT INTO digests (generated_at, period_hours, content) VALUES (?, ?, ?)')
      .run(digest.generatedAt, digest.periodHours, JSON.stringify(digest));
    // A digest is written rarely (daily/weekly at most), so purging on every
    // write is cheap and keeps the table bounded even across a container
    // that runs for months without restarting — unlike purgeOldEvents(),
    // which only runs at boot because events can be written far more often.
    purgeOldDigests();
    return Number(r.lastInsertRowid);
  } catch (e) { console.warn('[events] saveDigest error:', e.message); return null; }
}

/** Most recent digests first, summaries only (no content) — for a history list. */
function listDigests(limit = 20) {
  if (!eventsDb) return [];
  try {
    return eventsDb.prepare('SELECT id, generated_at, period_hours FROM digests ORDER BY generated_at DESC LIMIT ?')
      .all(limit);
  } catch (e) { console.warn('[events] listDigests error:', e.message); return []; }
}

/** One full digest, content included. */
function getDigest(id) {
  if (!eventsDb) return null;
  try {
    const row = eventsDb.prepare('SELECT * FROM digests WHERE id = ?').get(id);
    if (!row) return null;
    return { id: row.id, generatedAt: row.generated_at, periodHours: row.period_hours, ...safeParse(row.content) };
  } catch (e) { console.warn('[events] getDigest error:', e.message); return null; }
}

/** The single most recent digest, content included, or null if none exist yet. */
function getLatestDigest() {
  const recent = listDigests(1);
  return recent.length ? getDigest(recent[0].id) : null;
}

/**
 * Manual delete, requested by the operator (retention purges old digests
 * automatically — see purgeOldDigests() — this is the "I want this one gone
 * now" case, e.g. a test run or a digest generated with the wrong period).
 * Returns true only if a row actually existed and was removed, so the
 * caller can tell "already gone" from "deleted just now".
 */
function deleteDigest(id) {
  if (!eventsDb) return false;
  try {
    const r = eventsDb.prepare('DELETE FROM digests WHERE id = ?').run(id);
    return r.changes > 0;
  } catch (e) { console.warn('[events] deleteDigest error:', e.message); return false; }
}

function getState(key) {
  if (!eventsDb) return null;
  try {
    const row = eventsDb.prepare('SELECT value FROM state WHERE key = ?').get(key);
    return row ? safeParse(row.value) : null;
  } catch { return null; }
}

function setState(key, value) {
  if (!eventsDb) return;
  try {
    eventsDb.prepare(`INSERT INTO state (key, value) VALUES (?, ?)
                      ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
      .run(key, JSON.stringify(value));
  } catch (e) { console.warn('[events] setState:', e.message); }
}

/** Poignee SQLite partagee (null si indisponible) : lib/blocklist-history.js y ajoute sa propre table. */
function getDb() { return eventsDb; }

function clearEvents() {
  eventLog.length = 0;
  if (eventsDb) { try { eventsDb.exec('DELETE FROM events'); } catch { /* ignore */ } }
}

// ─── Webhooks ────────────────────────────────────────────────────────────────
function fireWebhook(wh, payload) {
  try {
    const body = JSON.stringify({
      event: payload.type, timestamp: payload.timestamp, data: payload.data,
    });
    const url = new URL(wh.url);
    // Fix (audit finding, Basse/"Sécurité et durcissement"): anti-SSRF —
    // `lookup` runs on every actual DNS resolution, right before this
    // request connects, so it catches DNS rebinding too (a hostname that
    // validated as public when the webhook was saved but now resolves to an
    // internal address). See lib/ssrf-guard.js's header comment.
    const req = (url.protocol === 'https:' ? https : http).request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': cfg.HTTP_USER_AGENT,
        'Content-Length': Buffer.byteLength(body),
        // v12.32.0: getWebhookSecret() also returns a value generated from
        // the UI (page Systeme) when WEBHOOK_SECRET is not set in .env —
        // see lib/config.js's own comment for why this one must stay
        // reversible (sent out here) rather than hashed like API_TOKEN.
        'X-Nginx-Dashboard-Secret': cfg.getWebhookSecret(),
      },
      timeout: 10_000,
      lookup: safeLookup,
    });
    req.on('error', () => { /* a dead endpoint must not break the action */ });
    req.on('timeout', () => req.destroy());
    req.write(body);
    req.end();
    wh.lastFired = new Date().toISOString();
    wh.fireCount = (wh.fireCount || 0) + 1;
  } catch { /* malformed URL — ignore */ }
}

// ─── Public API ──────────────────────────────────────────────────────────────
/** Record an event: memory ring, SQLite, then any matching webhook. */
function logEvent(type, data, source = 'system') {
  const entry = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toISOString(),
    type, data, source,
  };
  eventLog.unshift(entry);
  if (eventLog.length > MAX_LOG) eventLog.pop();
  persistEvent(type, data, source);
  for (const wh of webhooks) {
    if (!wh.events || wh.events.includes(type) || wh.events.includes('*')) fireWebhook(wh, entry);
  }
  return entry;
}

/** In-memory events, newest first. Used when SQLite is unavailable. */
function recentEvents(limit = MAX_LOG, offset = 0) {
  return eventLog.slice(offset, offset + limit);
}

module.exports = {
  MAX_LOG, eventLog, webhooks,
  initEventsDb, purgeOldEvents, persistEvent, queryEvents, clearEvents,
  logEvent, recentEvents, fireWebhook, getState, setState, getDb,
  saveDigest, listDigests, getDigest, getLatestDigest, deleteDigest, purgeOldDigests,
};
