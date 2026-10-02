'use strict';
/**
 * Historique des ajouts/retraits d'IP de la source "analyzer" (v12.53.0).
 *
 * Retour utilisateur : "possible d'avoir des logs pour savoir quand une IP est
 * ajoutee, quand une IP est retiree ? dans Evenements il faudrait filtrer et
 * il y a plus de 100 entrees". Ces changements ont donc leur propre table,
 * interrogeable avec filtres + pagination, plutot que d'etre noyes dans le
 * journal d'evenements general (un cycle par minute peut en produire).
 *
 * Actions :
 *   added     IP ajoutee a la liste de blocage (regle remediation:true)
 *   removed   IP retiree (raison : expired | no-longer-qualifies)
 *   detected  IP detectee par une regle SANS remediation ("observation seule")
 *             ou sur un vhost exempte : visible ici, jamais bloquee
 *
 * Stockage : base SQLite du journal d'evenements (lib/events.js), meme retention
 * (EVENTS_RETENTION_DAYS). Repli en memoire (anneau borne) si SQLite est indisponible.
 */
const events = require('./events');
const cfg = require('./config');

const ACTIONS = new Set(['added', 'removed', 'detected']);
const MEMORY_MAX = 2000;
const memory = []; // newest first, repli uniquement

let tableReady = false;

function db() {
  const d = events.getDb && events.getDb();
  if (!d) return null;
  if (!tableReady) {
    try {
      d.exec(`
        CREATE TABLE IF NOT EXISTS blocklist_history (
          id      INTEGER PRIMARY KEY AUTOINCREMENT,
          ts      INTEGER NOT NULL,
          ip      TEXT    NOT NULL,
          action  TEXT    NOT NULL,
          source  TEXT,
          rule    TEXT,
          reason  TEXT,
          until   INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_blh_ts ON blocklist_history(ts);
        CREATE INDEX IF NOT EXISTS idx_blh_ip ON blocklist_history(ip);
      `);
      tableReady = true;
    } catch (e) {
      console.warn('[blocklist-history] table:', e.message);
      return null;
    }
  }
  return d;
}

/** @param {Array<{ip,action,source?,rule?,reason?,until?}>} entries */
function record(entries, ts = Date.now()) {
  const rows = (entries || []).filter(e => e && e.ip && ACTIONS.has(e.action));
  if (!rows.length) return 0;
  const d = db();
  if (d) {
    try {
      const ins = d.prepare('INSERT INTO blocklist_history (ts, ip, action, source, rule, reason, until) VALUES (?, ?, ?, ?, ?, ?, ?)');
      d.exec('BEGIN');
      try {
        for (const e of rows) ins.run(ts, String(e.ip), e.action, e.source || null, e.rule || null, e.reason || null, e.until || null);
        d.exec('COMMIT');
      } catch (err) { d.exec('ROLLBACK'); throw err; }
      return rows.length;
    } catch (e) {
      console.warn('[blocklist-history] record:', e.message);
    }
  }
  for (const e of rows) {
    memory.unshift({ id: Date.now() + Math.random(), ts, ip: String(e.ip), action: e.action, source: e.source || null,
      rule: e.rule || null, reason: e.reason || null, until: e.until || null });
  }
  if (memory.length > MEMORY_MAX) memory.length = MEMORY_MAX;
  return rows.length;
}

const clamp = (v, def, min, max) => {
  const n = Math.trunc(Number(v));
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
};

/**
 * Filtres : ip (sous-chaine), action, rule, source, since/until (epoch ms).
 * Renvoie { entries, total, limit, offset, fromDb }.
 */
function query({ limit, offset, ip, action, rule, source, since, until } = {}) {
  const lim = clamp(limit, 50, 1, 500);
  const off = clamp(offset, 0, 0, 10_000_000);
  const f = {
    ip: ip ? String(ip).trim().slice(0, 64) : '',
    action: ACTIONS.has(action) ? action : '',
    rule: rule ? String(rule).slice(0, 64) : '',
    source: source ? String(source).slice(0, 128) : '',
    since: Number(since) > 0 ? Number(since) : 0,
    until: Number(until) > 0 ? Number(until) : 0,
  };
  const d = db();
  if (d) {
    try {
      let where = '1=1'; const p = [];
      if (f.ip)     { where += " AND ip LIKE ? ESCAPE '\\'"; p.push('%' + f.ip.replace(/[\\%_]/g, m => '\\' + m) + '%'); }
      if (f.action) { where += ' AND action = ?'; p.push(f.action); }
      if (f.rule)   { where += ' AND rule = ?';   p.push(f.rule); }
      if (f.source) { where += ' AND source = ?'; p.push(f.source); }
      if (f.since)  { where += ' AND ts >= ?';    p.push(f.since); }
      if (f.until)  { where += ' AND ts <= ?';    p.push(f.until); }
      const total = d.prepare(`SELECT COUNT(*) AS n FROM blocklist_history WHERE ${where}`).get(...p).n;
      const rows = d.prepare(`SELECT id, ts, ip, action, source, rule, reason, until FROM blocklist_history WHERE ${where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`)
        .all(...p, lim, off);
      return { entries: rows, total, limit: lim, offset: off, fromDb: true };
    } catch (e) {
      console.warn('[blocklist-history] query:', e.message);
    }
  }
  const all = memory.filter(e =>
    (!f.ip || e.ip.includes(f.ip)) && (!f.action || e.action === f.action) && (!f.rule || e.rule === f.rule)
    && (!f.source || e.source === f.source) && (!f.since || e.ts >= f.since) && (!f.until || e.ts <= f.until));
  return { entries: all.slice(off, off + lim), total: all.length, limit: lim, offset: off, fromDb: false };
}

function purge(retentionDays = cfg.EVENTS_RETENTION_DAYS) {
  const d = db();
  if (!d) return 0;
  try { return d.prepare('DELETE FROM blocklist_history WHERE ts < ?').run(Date.now() - retentionDays * 86400_000).changes || 0; }
  catch { return 0; }
}

/** CSV (tableur) ; les champs sont proteges contre l'injection de formule. */
function toCsv(entries) {
  const esc = v => {
    let s = v == null ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const lines = ['date,ip,action,source,rule,reason,until'];
  for (const e of entries) {
    lines.push([new Date(e.ts).toISOString(), e.ip, e.action, e.source, e.rule, e.reason, e.until ? new Date(e.until).toISOString() : ''].map(esc).join(','));
  }
  return lines.join('\n') + '\n';
}

/**
 * Compare deux etats successifs de la source analyzer et renvoie les entrees
 * a enregistrer. Pur (aucune E/S) pour etre testable.
 */
function diffAnalyzer({ source, prevIps = [], newIps = [], prevDetected = [], newDetected = [], ipRules = {}, expired = [], manualRemoved = [] }) {
  const prev = new Set(prevIps), next = new Set(newIps), exp = new Set(expired), manual = new Set(manualRemoved);
  const out = [];
  for (const ip of newIps) {
    if (prev.has(ip)) continue;
    const info = ipRules[ip] || {};
    out.push({ ip, action: 'added', source, rule: info.rule || null, until: info.until || null });
  }
  for (const ip of prevIps) {
    if (next.has(ip)) continue;
    out.push({ ip, action: 'removed', source, reason: manual.has(ip) ? 'manual' : exp.has(ip) ? 'expired' : 'no-longer-qualifies' });
  }
  const prevDet = new Set(prevDetected);
  for (const ip of newDetected) {
    if (prevDet.has(ip) || next.has(ip)) continue; // deja connue, ou bloquee (alors deja 'added')
    out.push({ ip, action: 'detected', source, reason: 'observation-only' });
  }
  return out;
}

module.exports = { record, query, purge, toCsv, diffAnalyzer, ACTIONS };
