'use strict';
/**
 * Page Administration > Conteneurs (v12.67.0) : vue centralisee de tous les
 * conteneurs du perimetre du dashboard — nginx, le dashboard lui-meme et tout
 * conteneur label `managed-by=nginx-dashboard` (certbot, analyzer, challenge,
 * error-pages, geoipupdate, godns...).
 *
 * Securite : admin uniquement ; un conteneur n est actionnable que s il figure
 * dans ce perimetre recalcule a chaque requete (jamais d id arbitraire vers le
 * socket Docker) ; le dashboard ne peut pas s arreter lui-meme ; le rebuild
 * est reserve aux conteneurs geres.
 */
const http = require('http');

const cfg      = require('../lib/config');
const httpLib  = require('../lib/http');
const auth     = require('../lib/auth');
const docker   = require('../lib/docker');
const events   = require('../lib/events');
const stream   = require('../lib/docker-stream');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const ID_RE = /^[a-f0-9]{12,64}$/;
const MAX_STREAMS = 8;
let activeStreams = 0;

async function inspectOne(idOrName) {
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(idOrName)}/json`);
  return r.status === 200 && r.body && typeof r.body === 'object' ? r.body : null;
}

/** Perimetre : [{ id, name, role, info }] — nginx, self, conteneurs geres. */
async function scope() {
  const out = new Map();
  const add = (info, role) => {
    if (!info || !info.Id || out.has(info.Id)) return;
    out.set(info.Id, { id: info.Id, name: String(info.Name || '').replace(/^\//, ''), role, info });
  };
  let nginxId = null;
  try { nginxId = await docker.getContainerId(); } catch { /* nginx absent */ }
  if (nginxId) add(await inspectOne(nginxId), 'nginx');
  for (const h of [process.env.HOSTNAME, require('os').hostname()].filter(Boolean)) {
    const i = await inspectOne(h);
    if (i) { add(i, 'dashboard'); break; }
  }
  const filters = encodeURIComponent(JSON.stringify({ label: ['managed-by=nginx-dashboard'] }));
  const l = await dockerCall('GET', `/containers/json?all=1&filters=${filters}`);
  if (l.status === 200 && Array.isArray(l.body)) {
    for (const c of l.body) if (!out.has(c.Id)) add(await inspectOne(c.Id), 'managed');
  }
  return [...out.values()];
}

async function findInScope(rawId) {
  if (typeof rawId !== 'string' || !ID_RE.test(rawId)) return null;
  const all = await scope();
  return all.find(c => c.id.startsWith(rawId)) || null;
}

function describe(c, stats) {
  const st = c.info.State || {};
  return {
    id: c.id.slice(0, 12), fullId: c.id, name: c.name, role: c.role,
    image: (c.info.Config || {}).Image || '',
    state: st.Status || 'unknown', running: !!st.Running,
    health: (st.Health && st.Health.Status) || null,
    startedAt: st.Running ? st.StartedAt : null,
    finishedAt: !st.Running ? st.FinishedAt : null,
    restartCount: c.info.RestartCount || 0,
    restartPolicy: ((c.info.HostConfig || {}).RestartPolicy || {}).Name || '',
    canStop: c.role !== 'dashboard',
    canRebuild: c.role === 'managed',
    stats: stats || null,
  };
}

async function listAll(withStats) {
  const all = await scope();
  return Promise.all(all.map(async c => {
    let stats = null;
    if (withStats && c.info.State && c.info.State.Running) {
      const timeout = new Promise(r => setTimeout(() => r(null), 4000));
      stats = await Promise.race([
        dockerCall('GET', `/containers/${c.id}/stats?stream=false`)
          .then(r => (r.status === 200 && r.body ? docker.computeContainerStats(r.body) : null)).catch(() => null),
        timeout,
      ]);
    }
    return describe(c, stats);
  }));
}

/** Rebuild : stop -> rename -> create(copie de la config) -> start, rollback si echec. */
async function rebuild(c, { pull }) {
  const image = (c.info.Config || {}).Image;
  if (pull) {
    const p = await docker.pullAndCheckUpdate(image);
    if (!p.ok) throw new Error(`pull ${image}: ${p.error}`);
  }
  const body = stream.buildRecreateBody(c.info);
  const wasRunning = !!(c.info.State || {}).Running;
  if (wasRunning) await dockerCall('POST', `/containers/${c.id}/stop?t=10`);
  const oldName = `${c.name}.old-${Date.now()}`;
  let r = await dockerCall('POST', `/containers/${c.id}/rename?name=${encodeURIComponent(oldName)}`);
  if (r.status !== 204) throw new Error(`rename: HTTP ${r.status}`);
  const rollback = async (why) => {
    await dockerCall('DELETE', `/containers/${encodeURIComponent(c.name)}?force=1`);
    await dockerCall('POST', `/containers/${c.id}/rename?name=${encodeURIComponent(c.name)}`);
    if (wasRunning) await dockerCall('POST', `/containers/${c.id}/start`);
    throw new Error(why);
  };
  r = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(c.name)}`, body);
  if (r.status !== 201) return rollback(`create: HTTP ${r.status} ${r.body && r.body.message ? r.body.message : ''}`);
  {
    const s = await dockerCall('POST', `/containers/${encodeURIComponent(c.name)}/start`);
    if (s.status !== 204 && s.status !== 304) return rollback(`start: HTTP ${s.status}`);
  }
  await dockerCall('DELETE', `/containers/${c.id}?force=1`);
  return { ok: true };
}

function sse(res, obj) { res.write(`data: ${JSON.stringify(obj)}\n\n`); }

function streamLogs(res, c, tail) {
  if (activeStreams >= MAX_STREAMS) return send(res, 429, { error: 'Too many log streams' });
  activeStreams++;
  res.writeHead(200, {
    'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache',
    'Connection': 'keep-alive', 'X-Accel-Buffering': 'no',
  });
  const parser = stream.createLogParser({ tty: !!(c.info.Config || {}).Tty });
  const q = `follow=1&stdout=1&stderr=1&timestamps=1&tail=${tail}`;
  const req = http.request({ socketPath: cfg.DOCKER_SOCKET, path: `/containers/${c.id}/logs?${q}`, method: 'GET' }, (up) => {
    if (up.statusCode !== 200) { sse(res, { type: 'error', message: `HTTP ${up.statusCode}` }); return res.end(); }
    sse(res, { type: 'ready' });
    up.on('data', d => { for (const l of parser.push(d)) sse(res, { type: 'line', s: l.stream, t: l.line }); });
    up.on('end', () => { for (const l of parser.flush()) sse(res, { type: 'line', s: l.stream, t: l.line }); sse(res, { type: 'end' }); res.end(); });
  });
  req.on('error', e => { try { sse(res, { type: 'error', message: e.code || e.message }); res.end(); } catch { /* closed */ } });
  req.end();
  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch { cleanup(); } }, 15000);
  let done = false;
  function cleanup() { if (done) return; done = true; clearInterval(ping); activeStreams--; req.destroy(); }
  res.on('close', cleanup); res.on('error', cleanup);
}

function register(router) {
  const guard = (session, res) => { if (!hasPerm(session, PERMS.ADMIN)) { httpLib.forbidden(res); return false; } return true; };

  router.get('/api/containers', async ({ res, session, url }) => {
    if (!guard(session, res)) return;
    try { return send(res, 200, { containers: await listAll(url.searchParams.get('stats') !== '0') }); }
    catch (e) { return httpLib.serverError(res, e); }
  });

  router.get('/api/containers/logs', async ({ res, session, url }) => {
    if (!guard(session, res)) return;
    const c = await findInScope(url.searchParams.get('id'));
    if (!c) return httpLib.badRequest(res, 'unknown container');
    const tail = Math.min(Math.max(parseInt(url.searchParams.get('tail') || '200', 10) || 200, 1), 2000);
    const text = await docker.getContainerLogs(c.id, { tail, timestamps: true });
    return send(res, 200, { name: c.name, text });
  });

  router.get('/api/containers/logs/stream', async ({ res, session, url }) => {
    if (!guard(session, res)) return;
    const c = await findInScope(url.searchParams.get('id'));
    if (!c) return httpLib.badRequest(res, 'unknown container');
    const tail = Math.min(Math.max(parseInt(url.searchParams.get('tail') || '100', 10) || 100, 0), 1000);
    return streamLogs(res, c, tail);
  });

  router.post('/api/containers/action', async ({ req, res, session }) => {
    if (!guard(session, res)) return;
    const body = await httpLib.parseBody(req).catch(() => null);
    if (!body) return httpLib.badRequest(res, 'invalid body');
    const action = String(body.action || '');
    if (!['start', 'stop', 'restart', 'update', 'rebuild'].includes(action)) return httpLib.badRequest(res, 'unknown action');
    const c = await findInScope(body.id);
    if (!c) return httpLib.badRequest(res, 'unknown container');
    const who = session.username;
    try {
      if (action === 'stop' && c.role === 'dashboard') return httpLib.badRequest(res, 'the dashboard cannot stop itself');
      if (action === 'rebuild' && c.role !== 'managed') return httpLib.badRequest(res, 'rebuild is limited to managed containers');
      if (action === 'start' || action === 'stop') {
        const r = await dockerCall('POST', `/containers/${c.id}/${action}${action === 'stop' ? '?t=10' : ''}`);
        if (![204, 304].includes(r.status)) return send(res, 200, { ok: false, error: `HTTP ${r.status}` });
      } else if (action === 'restart') {
        if (c.role === 'dashboard') {
          setTimeout(() => dockerCall('POST', `/containers/${c.id}/restart?t=5`), 500);
        } else {
          const r = await dockerCall('POST', `/containers/${c.id}/restart?t=10`);
          if (![204, 304].includes(r.status)) return send(res, 200, { ok: false, error: `HTTP ${r.status}` });
        }
      } else if (action === 'update') {
        const image = (c.info.Config || {}).Image;
        const p = await docker.pullAndCheckUpdate(image);
        if (!p.ok) return send(res, 200, { ok: false, error: p.error });
        let recreated = false;
        if (p.updated && c.role === 'managed') { await rebuild(c, { pull: false }); recreated = true; }
        logEvent('containers.update', `${c.name}: image ${image} ${p.updated ? 'updated' : 'up to date'}${recreated ? ', recreated' : ''}`, who);
        return send(res, 200, { ok: true, updated: !!p.updated, recreated, needsManualRecreate: !!p.updated && c.role !== 'managed' });
      } else {
        await rebuild(c, { pull: body.pull !== false });
      }
      logEvent(`containers.${action}`, `${c.name} (${c.role})`, who);
      return send(res, 200, { ok: true });
    } catch (e) {
      logEvent('containers.error', `${action} ${c.name}: ${e.message}`, who);
      return send(res, 200, { ok: false, error: e.message });
    }
  });
}

module.exports = { register, ID_RE };
