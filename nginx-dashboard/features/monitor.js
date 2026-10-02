'use strict';
/**
 * Continuous backend monitoring — opt-in per vhost, via the comment flag the
 * user proposed:
 *
 *   server {
 *     # nginx-control-monitoring: on
 *     # nginx-control-monitoring-interval: 60s
 *     ...
 *
 *     location /api {
 *       # nginx-control-monitoring-ignore-location: on
 *       proxy_pass http://same-backend-as-above;
 *     }
 *   }
 *
 * (parsed in lib/vhost-targets.js's parseVhostFile(), a comment so it never
 * touches the actual nginx config). Every resolved, non-unresolved,
 * non-ignored target inside an enabled block gets probed on its own
 * interval, using the exact same probe as the on-demand check
 * (features/backends.js's checkTarget, injected via setDeps() rather than
 * required directly — "features never import each other"), and results are
 * persisted through lib/monitor-store.js: response codes/times, and a
 * downtime history (start/end of each incident) — "stats dispo backend et
 * voir quand le backend a ete off", as asked.
 *
 * The per-location `-ignore-location` flag is a follow-up request: several
 * locations in the same block can proxy to the very same backend (different
 * paths, same target), and monitoring each one is just duplicate probes of
 * the same thing — the flag opts a specific location out without touching
 * the block's own monitoring flag or its other locations.
 *
 * Deliberately a single ticking loop rather than one timer per target: with
 * potentially dozens of monitored targets, one setInterval that checks "is
 * anyone due?" is simpler to reason about, self-heals across a rescan
 * (a vhost edited, or the flag toggled off, is picked up within RESCAN_MS
 * without restarting anything), and is trivially testable by calling tick()
 * directly with a controlled clock rather than waiting on real timers.
 */

const cfg = require('../lib/config');
const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const { listVhostTargets } = require('../lib/vhost-targets');
const monitorStore = require('../lib/monitor-store');
const { isStatusUp } = require('../lib/monitor-status');
const { pushNotification } = require('../lib/notifications');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { DIR_SITES, DIR_CONF } = cfg;

const UPSTREAM_DIRS = [DIR_CONF, DIR_SITES];
const TICK_MS = 5000;
const RESCAN_MS = 30000;

let checkTargetFn = async () => ({ ok: false, error: 'monitor not wired' });
function setDeps({ checkTarget } = {}) {
  if (checkTarget) checkTargetFn = checkTarget;
}

let targets = new Map();       // key -> descriptor, rebuilt on every rescan()
let lastCheckedAt = new Map(); // key -> ts of the last probe, survives a rescan
let rescanTimer = null, tickTimer = null, started = false;

function targetKey(file, blockIndex, locationIndex, targetIndex) {
  return `${file}::${blockIndex}::${locationIndex}::${targetIndex}`;
}

/** Rebuild the set of currently-monitored targets from the vhost files on disk. */
function rescan() {
  const next = new Map();
  const vhosts = listVhostTargets({ sitesDir: DIR_SITES, upstreamDirs: UPSTREAM_DIRS });
  for (const v of vhosts) {
    // Fix (audit finding MISC-12): a `.conf.DISABLE` vhost — nginx never
    // loads it, so it has no live backend to probe — was still scanned for
    // `# nginx-control-monitoring: on` blocks and monitored like any other
    // vhost. `listVhostTargets()` already flags this via `v.enabled`; it
    // just wasn't checked here.
    if (!v.enabled) continue;
    (v.serverBlocks || []).forEach((block, blockIndex) => {
      if (!block.monitoring || !block.monitoring.enabled) return;
      const hostHeader = block.serverNames.find(n => n !== '_') || null;
      (block.locations || []).forEach((loc, locationIndex) => {
        if (loc.kind === 'unresolved') return;
        // Opt-out granulaire par location (# nginx-control-monitoring-ignore-location: on)
        // — plusieurs locations d un meme vhost proxifiant la meme cible
        // (chemins differents, meme backend) n ont pas besoin d etre sondees
        // chacune independamment.
        if (loc.monitoringIgnored) return;
        (loc.targets || []).forEach((t, targetIndex) => {
          const key = targetKey(v.file, blockIndex, locationIndex, targetIndex);
          next.set(key, {
            key, file: v.file, vhostName: v.name, blockIndex, locationIndex, targetIndex,
            serverNames: block.serverNames, path: loc.path,
            scheme: t.scheme, host: t.host, port: t.port,
            hostHeader: hostHeader || t.host,
            intervalSec: block.monitoring.intervalSec,
            validHttpCodes: block.monitoring.validHttpCodes,
          });
        });
      });
    });
  }
  // Fix (audit finding MISC-12): a target that stops being monitored (file
  // deleted/edited, flag turned off, or its positional key shifted because
  // an earlier block/location in the same file changed) never gets another
  // recordCheck() call, so any incident still open under its old key would
  // otherwise stay "down" forever — see monitor-store.js's
  // closeOrphanedIncident() for the full rationale. Computed against the
  // PREVIOUS `targets`, before it's replaced below.
  for (const key of targets.keys()) {
    if (!next.has(key)) monitorStore.closeOrphanedIncident(key);
  }
  targets = next;
  // Forget the last-checked timestamp of anything that vanished (file
  // deleted, edited, or the flag turned off) — otherwise a target removed
  // and later re-added under the same key would wait out its old interval
  // instead of being probed on the next tick.
  for (const key of lastCheckedAt.keys()) if (!targets.has(key)) lastCheckedAt.delete(key);
  return targets;
}

/**
 * One tick: probe every target whose interval has elapsed. Exported so
 * tests can call it directly with a controlled `now` instead of waiting on
 * real timers. `force: true` (used by the manual "check now" route below)
 * ignores each target's own interval and probes everyone immediately.
 */
async function tick(now = Date.now(), { force = false } = {}) {
  for (const t of targets.values()) {
    const last = lastCheckedAt.get(t.key) || 0;
    if (!force && now - last < t.intervalSec * 1000) continue;
    lastCheckedAt.set(t.key, now);
    const result = await checkTargetFn({ scheme: t.scheme, host: t.host, port: t.port, hostHeader: t.hostHeader });
    // checkTargetFn's own `ok` only means "a response came back at all" — a
    // stopped backend fronted by something like Traefik can still answer
    // with a normal-looking 404. isStatusUp() applies the real up/down rule
    // (default: 5xx and no-response are down) or the per-vhost override.
    const status = result.ok ? (result.status ?? null) : null;
    const up = isStatusUp(status, t.validHttpCodes);
    let error = result.error ?? null;
    if (result.ok && !up) {
      error = t.validHttpCodes
        ? `code HTTP inattendu : ${result.status} (attendu : ${t.validHttpCodes.join(', ')})`
        : `code HTTP inattendu : ${result.status} (>= 500)`;
    }
    const { becameDown, becameUp } = monitorStore.recordCheck(t.key, { ok: up, status: result.status ?? null, ms: result.ms ?? null, error });
    // Uniquement sur la transition (pas a chaque probe, sinon une cible en
    // panne spammerait le centre de notification a chaque tick) — voir le
    // commentaire de recordCheck() dans lib/monitor-store.js.
    const label = (t.serverNames || []).find(n => n !== '_') || t.host;
    if (becameDown) {
      pushNotification({ type: 'monitor_down', level: 'error',
        message: `${label} (${t.path || '/'}) est down${error ? ' : ' + error : ''}`,
        data: { key: t.key, vhostName: t.vhostName, host: t.host, path: t.path, error } });
    } else if (becameUp) {
      pushNotification({ type: 'monitor_up', level: 'success',
        message: `${label} (${t.path || '/'}) est de nouveau up`,
        data: { key: t.key, vhostName: t.vhostName, host: t.host, path: t.path } });
    }
  }
}

/** Idempotent — a second call (a restart path calling it twice, a test) never doubles the timers. */
function start() {
  if (started) return;
  started = true;
  rescan();
  rescanTimer = setInterval(rescan, RESCAN_MS);
  tickTimer = setInterval(() => { tick().catch(e => console.error('[monitor] tick error:', e.message)); }, TICK_MS);
  if (rescanTimer.unref) rescanTimer.unref();
  if (tickTimer.unref) tickTimer.unref();
  console.log('[monitor] started');
}

/** Test helper — stops the timers and clears in-memory state (not the persisted history). */
function stop() {
  started = false;
  if (rescanTimer) clearInterval(rescanTimer);
  if (tickTimer) clearInterval(tickTimer);
  rescanTimer = null; tickTimer = null;
  targets = new Map();
  lastCheckedAt = new Map();
}

// A compact up/down history for the list view's sparkline — oldest first, so
// it draws left-to-right like the "20 derniers checks" list does. Kept
// small (20 points): this is a glance, not the detailed history panel
// (GET /api/monitor/history still returns the full 200).
function sparklineFor(key) {
  return monitorStore.getHistory(key, 20).reverse().map(c => c.ok);
}

function register(router) {
  router.get('/api/monitor', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const list = [...targets.values()].map(t => ({ ...t, summary: monitorStore.getSummary(t.key), sparkline: sparklineFor(t.key) }));
    return send(res, 200, { targets: list });
  });

  // Manual "check now" — probes every currently-monitored target right
  // away instead of waiting for its own interval. A rescan first, so a
  // vhost just edited (flag just turned on, interval just changed) is
  // picked up immediately rather than on the next 30s cycle. Same
  // permission as reading the list: this is a probe of the operator's own
  // configured targets, not a write to anything.
  router.post('/api/monitor/check-now', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    rescan();
    await tick(Date.now(), { force: true });
    const list = [...targets.values()].map(t => ({ ...t, summary: monitorStore.getSummary(t.key), sparkline: sparklineFor(t.key) }));
    return send(res, 200, { targets: list });
  });

  router.get('/api/monitor/history', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const key = url.searchParams.get('key');
    // Only a key currently returned by GET /api/monitor is accepted — this
    // is a read of our own resolved state, not a client-supplied lookup
    // into arbitrary storage.
    if (!key || !targets.has(key)) return httpLib.badRequest(res, 'unknown or no longer monitored target key');
    return send(res, 200, {
      history: monitorStore.getHistory(key, 200),
      incidents: monitorStore.getIncidents(key, 50),
    });
  });
}

module.exports = { register, setDeps, rescan, tick, start, stop, targetKey };
