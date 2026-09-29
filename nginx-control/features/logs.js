'use strict';
/**
 * Log viewing — nginx access/error files, and the dashboard's own event log.
 *
 * Two distinct things share this module because they share a page:
 *
 *  - nginx logs: read from DIR_LOGS, tailed, optionally streamed over SSE and
 *    enriched with GeoIP.
 *  - dashboard events: the SQLite-backed journal from lib/events.
 *
 * Any path supplied by a client is resolved and confined to DIR_LOGS. A plain
 * startsWith() check once let "…/logs/../../proc/self/environ" through, which
 * exposed every secret in the process environment to a viewer account.
 *
 * SECURITY (fix v12.21.1, audit finding SEC-06): the SSE endpoint used to
 * authenticate ONLY from a `?token=` query parameter carrying the raw
 * session token — fetched by the frontend from a dedicated
 * `/api/auth/stream-token` endpoint that read it back out of the HttpOnly
 * cookie for JS to see. That defeated the entire point of HttpOnly, and
 * worse: since this dashboard is typically deployed behind the very nginx it
 * manages, that URL (session token included) ends up verbatim in nginx's own
 * access log — readable by anyone with PERMS.VIEW_LOGS (a `viewer` account),
 * who could then replay it as an admin's session. It turns out no query
 * parameter was ever needed: EventSource sends cookies automatically for a
 * same-origin request regardless of `withCredentials` (that flag only
 * matters cross-origin), so handleStream() below now authenticates from the
 * `ngx_session` cookie first, exactly like every other route. The `token=`
 * query parameter is kept ONLY as a fallback for the separate, deliberate
 * API_TOKEN bearer mechanism (a script that cannot use a browser session at
 * all) — never a session token.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const tree    = require('../lib/fs-tree');
const events  = require('../lib/events');
const { geoipCached } = require('../lib/geoip');

const { PERMS, hasPerm, safeCompare, getSessionFromReq } = auth;
const { send, parseBody } = httpLib;
const { safeResolveWithin, safeStat, safeReadDir, safeReadFile } = tree;
const { DIR_LOGS, API_TOKEN, API_TOKEN_ENABLED } = cfg;

function listLogFiles() {
  return safeReadDir(DIR_LOGS)
    .filter(name => name.endsWith('.log'))
    .map(name => {
      const fullPath = path.join(DIR_LOGS, name);
      const stat = safeStat(fullPath);
      if (!stat || stat.isDirectory()) return null;
      const vhost = name.replace(/\.(access|error|stream)\.log$/, '').replace(/\.log$/, '') || name;
      const type  = name.includes('error') ? 'error' : name.includes('stream') ? 'stream' : 'access';
      return { name, path: fullPath, size: stat.size, mtime: stat.mtime.toISOString(), vhost, type };
    }).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name));
}

function tailFile(filePath, lines) {
  try {
    const stat = safeStat(filePath);
    if (!stat) return [];
    const CHUNK = Math.min(stat.size, lines * 300);
    const fd  = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(CHUNK);
    fs.readSync(fd, buf, 0, CHUNK, Math.max(0, stat.size - CHUNK));
    fs.closeSync(fd);
    return buf.toString('utf8').split('\n').filter(Boolean).slice(-lines);
  } catch { return []; }
}

function parseNginxLine(line) {
  const m = line.match(/^(\S+)\s+(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$/);
  if (m) {
    const r = { vhost: m[1], ip: m[2], user: m[3], time: m[4], request: m[5], status: parseInt(m[6]), bytes: parseInt(m[7]), referer: m[8], ua: m[9], raw: line };
    const geo = geoipCached(r.ip); if (geo) r.geo = geo;
    return r;
  }
  const m2 = line.match(/^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$/);
  if (m2) {
    const r = { vhost: null, ip: m2[1], user: m2[2], time: m2[3], request: m2[4], status: parseInt(m2[5]), bytes: parseInt(m2[6]), referer: m2[7], ua: m2[8], raw: line };
    const geo = geoipCached(r.ip); if (geo) r.geo = geo;
    return r;
  }
  return { raw: line };
}

function startTailSSE(res, filePath, initialLines) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    // Fix v12.21.1 (SEC-06): this stream now authenticates from the session
    // cookie (see handleStream() above), so a wildcard ACAO would let ANY
    // origin read it cross-site with the browser silently attaching that
    // cookie. Same-origin only, like every other route.
    'X-Accel-Buffering': 'no',
  });
  const initial = tailFile(filePath, initialLines);
  for (const line of initial) res.write(`data: ${JSON.stringify({ type: 'line', ...parseNginxLine(line) })}\n\n`);
  res.write(`data: ${JSON.stringify({ type: 'ready', file: path.basename(filePath), lines: initial.length })}\n\n`);
  let lastSize = safeStat(filePath)?.size || 0;
  function poll() {
    try {
      const stat = safeStat(filePath);
      if (!stat) return;
      if (stat.size > lastSize) {
        const fd = fs.openSync(filePath, 'r');
        const buf = Buffer.alloc(stat.size - lastSize);
        fs.readSync(fd, buf, 0, stat.size - lastSize, lastSize);
        fs.closeSync(fd);
        lastSize = stat.size;
        buf.toString('utf8').split('\n').filter(Boolean).forEach(l => res.write(`data: ${JSON.stringify({ type: 'line', ...parseNginxLine(l) })}\n\n`));
      } else if (stat.size < lastSize) {
        lastSize = stat.size;
        res.write(`data: ${JSON.stringify({ type: 'rotated', file: path.basename(filePath) })}\n\n`);
      }
    } catch(e) { try { res.write(`data: ${JSON.stringify({ type: 'error', message: e.message })}\n\n`); } catch {} }
  }
  let watcher;
  try { watcher = fs.watch(filePath, { persistent: false }, () => poll()); } catch {}
  const timer = setInterval(() => { try { res.write(': ping\n\n'); poll(); } catch { cleanup(); } }, 15000);
  function cleanup() { try { watcher?.close(); } catch {} clearInterval(timer); }
  res.on('close', cleanup);
  res.on('error', cleanup);
}
// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/nginx-logs', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_LOGS)) return httpLib.forbidden(res);
    return send(res, 200, { files: listLogFiles(), dir: DIR_LOGS });
  });

  router.get('/api/nginx-logs/tail', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_LOGS)) return httpLib.forbidden(res);
    const rawPath = url.searchParams.get('path');
    const lines   = Math.min(parseInt(url.searchParams.get('lines') || '200'), 2000);
    if (!rawPath) return httpLib.badRequest(res, 'path param required');
    const filePath = safeResolveWithin(rawPath, [DIR_LOGS]);
    if (!filePath) return httpLib.forbidden(res, 'Access denied');
    return send(res, 200, {
      file: path.basename(filePath),
      lines: tailFile(filePath, lines).map(parseNginxLine),
    });
  });

  // ── Dashboard event log ────────────────────────────────────────────────────
  router.get('/api/logs', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const limit  = parseInt(url.searchParams.get('limit')  || '200');
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const type   = url.searchParams.get('type') || null;
    const since  = url.searchParams.get('since') ? parseInt(url.searchParams.get('since')) : null;
    const db = events.queryEvents({ limit, offset, type, since });
    // fromDb tells the UI whether history survives a restart.
    if (db.fromDb) return send(res, 200, { logs: db.events, total: db.total, fromDb: true });
    return send(res, 200, {
      logs: events.recentEvents(limit, offset),
      total: events.eventLog.length,
      fromDb: false,
    });
  });

  router.post('/api/logs/clear', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    events.clearEvents();
    return send(res, 200, { ok: true });
  });

  router.post('/api/events', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.NGINX_CONTROL)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    return send(res, 201,
      events.logEvent(body.type || 'custom', { ...body.data, by: session.username }, 'external'));
  });
}

/**
 * SSE tail. Registered outside the router because it runs before the normal
 * session check: EventSource cannot send an Authorization header, so the
 * credential arrives as a query parameter.
 */
function handleStream(req, res, url) {
  // Cookie first (fix v12.21.1, SEC-06 — see this module's header comment):
  // same-origin EventSource sends it automatically, no query token needed.
  let session = getSessionFromReq(req);
  if (!session) {
    // Fallback for the API_TOKEN bearer mechanism only — a non-browser
    // client with no cookie to send. Never a session token: validateSession()
    // on an arbitrary query string would defeat the fix above just as badly.
    const qtoken = url.searchParams.get('token') || '';
    if (API_TOKEN_ENABLED && qtoken && safeCompare(qtoken, API_TOKEN)) {
      session = { username: 'api', role: 'admin', name: 'API Token' };
    }
  }
  if (!session || !hasPerm(session, PERMS.VIEW_LOGS)) {
    res.writeHead(401); return res.end('Unauthorized');
  }
  const rawPath = url.searchParams.get('path');
  const lines   = Math.min(parseInt(url.searchParams.get('lines') || '100'), 500);
  if (!rawPath) { res.writeHead(400); return res.end('path required'); }
  const filePath = safeResolveWithin(rawPath, [DIR_LOGS]);
  if (!filePath) { res.writeHead(403); return res.end('Access denied'); }
  startTailSSE(res, filePath, lines);
}

module.exports = {
  register, handleStream,
  listLogFiles, tailFile, parseNginxLine, startTailSSE,
};
