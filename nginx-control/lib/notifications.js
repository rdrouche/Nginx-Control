'use strict';
/**
 * In-app notification center — a shared, dismissible feed of things the
 * operator should notice at a glance (certificate expiring, a monitored
 * backend going down, an abnormal pattern from the log analyzer, a scheduled
 * reload that just ran or failed, ...), surfaced as a bell/dropdown in the
 * header (public/index.html).
 *
 * Deliberately separate from two modules that look similar but solve a
 * different problem:
 *  - lib/notify.js sends EMAIL. It has its own enable/recipients rules per
 *    type (config/notifications.yml) and no notion of "read". A caller often
 *    wants BOTH (an email so nobody has to be watching, and an in-app entry
 *    for whoever opens the dashboard next) — this module never calls that
 *    one or vice versa; each call site decides for itself which channel(s)
 *    to push to, exactly like features/certbot.js already calls logEvent()
 *    and lib/notify.js independently today.
 *  - lib/events.js is a generic audit trail (every action, admin-oriented,
 *    no read/unread state, fires outbound webhooks). A notification is
 *    narrower: only things worth an operator's attention, with a read state
 *    and a severity `level` the header badge/dropdown render directly.
 *
 * Modular on purpose — the whole public surface is `pushNotification()`,
 * a single function any feature can call directly:
 *
 *   require('../lib/notifications').pushNotification({
 *     type: 'cert_expiring', level: 'warning',
 *     message: 'Certificate example.com expires in 5 day(s)',
 *     data: { domain: 'example.com', daysLeft: 5 },
 *   });
 *
 * `type` is a free-form string (no registry to update elsewhere) and `level`
 * is one of 'info' | 'success' | 'warning' | 'error' — the four the header
 * dropdown already has a badge color for. Adding a new kind of notification
 * from a new feature never touches this file.
 *
 * Same SQLite-via-node:sqlite idiom as lib/monitor-store.js: its own
 * database file (unrelated table, unrelated write volume from events.db),
 * degrades to an in-memory ring if SQLite is unavailable rather than
 * refusing to start.
 *
 * Shared/global, not per-user: like the event log, every session sees the
 * same feed and the same read state. Fine for this project's scale
 * (a handful of operators sharing one instance) and keeps the schema simple
 * — a per-user read state would need a join table for little practical gain
 * here.
 */

const cfg = require('./config');

let db = null;
const MEMORY_CAP = 300;
const memory = []; // newest first when db is unavailable

function initNotificationsDb() {
  try {
    const { DatabaseSync } = require('node:sqlite');
    db = new DatabaseSync(cfg.NOTIF_CENTER_DB_PATH);
    db.exec(`
      PRAGMA journal_mode = WAL;

      CREATE TABLE IF NOT EXISTS notifications (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER NOT NULL,
        type    TEXT    NOT NULL,
        level   TEXT    NOT NULL DEFAULT 'info',
        message TEXT    NOT NULL,
        data    TEXT,
        read    INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(ts);
    `);
    purgeOld();
    console.log(`[notifications] DB ready: ${cfg.NOTIF_CENTER_DB_PATH} (retention: ${cfg.NOTIF_CENTER_RETENTION_DAYS}d)`);
  } catch (e) {
    console.warn('[notifications] SQLite unavailable — notification history will be in-memory only:', e.message);
    db = null;
  }
}

function purgeOld() {
  if (!db) {
    const cutoff = Date.now() - cfg.NOTIF_CENTER_RETENTION_DAYS * 86400_000;
    for (let i = memory.length - 1; i >= 0; i--) if (memory[i].ts < cutoff) memory.splice(i, 1);
    return;
  }
  try {
    const cutoff = Date.now() - cfg.NOTIF_CENTER_RETENTION_DAYS * 86400_000;
    db.prepare('DELETE FROM notifications WHERE ts < ?').run(cutoff);
  } catch { /* a full disk should not take the dashboard down */ }
}

const VALID_LEVELS = new Set(['info', 'success', 'warning', 'error']);

/**
 * Push one notification. `type` is a free-form identifier (e.g.
 * 'cert_expiring', 'monitor_down') — nothing here validates it against a
 * fixed list, so a new call site never needs to register its type anywhere.
 * Returns the stored row, mostly useful for tests.
 */
function pushNotification({ type, level = 'info', message, data = null } = {}) {
  if (!type || !message) throw new Error('pushNotification requires at least { type, message }');
  const safeLevel = VALID_LEVELS.has(level) ? level : 'info';
  const ts = Date.now();
  const row = { ts, type, level: safeLevel, message, data: data ?? null, read: false };

  if (db) {
    try {
      const result = db.prepare(
        'INSERT INTO notifications (ts, type, level, message, data) VALUES (?, ?, ?, ?, ?)'
      ).run(ts, type, safeLevel, message, data != null ? JSON.stringify(data) : null);
      return { id: Number(result.lastInsertRowid), ...row };
    } catch (e) {
      console.warn('[notifications] pushNotification error:', e.message);
    }
  }

  // Memory fallback (or SQLite insert failed) — synthesize a local id so the
  // frontend still has something stable to key mark-read/delete on for the
  // lifetime of this process.
  const id = memory.length ? memory[0].id + 1 : 1;
  memory.unshift({ id, ...row });
  if (memory.length > MEMORY_CAP) memory.pop();
  return { id, ...row };
}

function rowFromDb(r) {
  return { id: r.id, ts: r.ts, type: r.type, level: r.level, message: r.message,
    data: r.data ? JSON.parse(r.data) : null, read: !!r.read };
}

/**
 * Most recent first. `type`, added for features/alerting.js (v12.45.0) to
 * find its own notifications (type: 'alerting') without pulling every
 * other kind just to filter them out in JS — optional, every existing
 * caller keeps working unchanged (type: null means "no filter", same
 * behavior as before this parameter existed).
 */
function listNotifications({ limit = 50, offset = 0, unreadOnly = false, type = null } = {}) {
  if (db) {
    try {
      const conditions = [];
      const params = [];
      if (unreadOnly) conditions.push('read = 0');
      if (type) { conditions.push('type = ?'); params.push(type); }
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      params.push(limit, offset);
      return db.prepare(`SELECT * FROM notifications ${where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`)
        .all(...params).map(rowFromDb);
    } catch (e) { console.warn('[notifications] listNotifications error:', e.message); return []; }
  }
  let source = memory;
  if (unreadOnly) source = source.filter(n => !n.read);
  if (type) source = source.filter(n => n.type === type);
  return source.slice(offset, offset + limit);
}

function getUnreadCount() {
  if (db) {
    try { return db.prepare('SELECT COUNT(*) as n FROM notifications WHERE read = 0').get().n; }
    catch (e) { console.warn('[notifications] getUnreadCount error:', e.message); return 0; }
  }
  return memory.filter(n => !n.read).length;
}

function markRead(id) {
  const numId = Number(id);
  if (db) {
    try { db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(numId); return true; }
    catch (e) { console.warn('[notifications] markRead error:', e.message); return false; }
  }
  const n = memory.find(m => m.id === numId);
  if (n) n.read = true;
  return !!n;
}

function markAllRead() {
  if (db) {
    try { db.prepare('UPDATE notifications SET read = 1 WHERE read = 0').run(); return true; }
    catch (e) { console.warn('[notifications] markAllRead error:', e.message); return false; }
  }
  memory.forEach(n => { n.read = true; });
  return true;
}

function deleteNotification(id) {
  const numId = Number(id);
  if (db) {
    try { db.prepare('DELETE FROM notifications WHERE id = ?').run(numId); return true; }
    catch (e) { console.warn('[notifications] deleteNotification error:', e.message); return false; }
  }
  const idx = memory.findIndex(m => m.id === numId);
  if (idx !== -1) memory.splice(idx, 1);
  return idx !== -1;
}

/** Deletes every read notification, keeping anything still unread untouched. */
function clearRead() {
  if (db) {
    try { db.prepare('DELETE FROM notifications WHERE read = 1').run(); return true; }
    catch (e) { console.warn('[notifications] clearRead error:', e.message); return false; }
  }
  for (let i = memory.length - 1; i >= 0; i--) if (memory[i].read) memory.splice(i, 1);
  return true;
}

/** Deletes everything, read or not — an explicit "empty the bell" action. */
function clearAll() {
  if (db) {
    try { db.prepare('DELETE FROM notifications').run(); return true; }
    catch (e) { console.warn('[notifications] clearAll error:', e.message); return false; }
  }
  memory.length = 0;
  return true;
}

/** Test/shutdown helper — closes the SQLite handle and clears the memory fallback. */
function closeDb() {
  try { if (db) db.close(); } catch { /* ignore */ }
  db = null;
  memory.length = 0;
}

module.exports = {
  initNotificationsDb, pushNotification, listNotifications, getUnreadCount,
  markRead, markAllRead, deleteNotification, clearRead, clearAll, purgeOld, closeDb,
};
