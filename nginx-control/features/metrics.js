'use strict';
/**
 * Traffic metrics, read from the nginx VTS module.
 *
 * VTS exposes a synthetic `*` server zone holding nginx-wide totals. When it is
 * present the totals are read straight from it; summing the individual vhosts
 * instead would double-count, since `*` already aggregates them. `*` is
 * likewise excluded from any per-vhost listing.
 *
 * Field names differ between VTS versions (`requestCounter` vs
 * `requests.total`, `inBytes` vs `traffic.in`), hence the `??` chains.
 *
 * A five-second poll keeps a short rolling history in memory for the overview
 * chart — five minutes at MAX_HISTORY = 60.
 */

const http  = require('http');
const https = require('https');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { NGINX_VTS_URL } = cfg;

const MAX_HISTORY    = 60;   // 60 x 5 s = 5 minutes — feeds the existing cumulative chart
const metricsHistory = { timestamps: [], requests: [], errors: [], bytes: [] };

// A second, longer buffer for the requests/sec graph: 60 minutes at 5 s
// resolution. Kept separate from MAX_HISTORY/metricsHistory above rather than
// just extending it, since the existing chart and its 5-minute window are
// unaffected either way — this only adds capacity, it doesn't change what the
// original chart already does.
const RATE_HISTORY_MINUTES = 60;
const MAX_RATE_HISTORY = (RATE_HISTORY_MINUTES * 60) / 5;   // 720 samples
const globalRateHistory = { timestamps: [], requests: [] };
// Per-vhost cumulative series, same resolution and window. Keyed by zone
// name; a vhost not seen in the last two windows is dropped so a renamed or
// removed vhost does not accumulate forever in memory over a long uptime.
const vhostRateHistory = new Map();   // name -> { timestamps: [], requests: [], lastSeen: ms }
const VHOST_STALE_MS = RATE_HISTORY_MINUTES * 60_000 * 2;

// Fix (audit finding MISC-11): an unreachable or hanging VTS endpoint had no
// timeout at all — `http.get`/`https.get` wait on the OS's own TCP timeout
// (minutes), and every route below (`/api/metrics`, `/api/status`,
// `/api/zones`, `/api/upstreams`) awaits fetchVTS() directly, so one stuck
// upstream connection stalled the request that triggered it. Concurrent
// requests each open their own new connection here (no shared keep-alive
// agent), so a persistently down VTS endpoint accumulates one hung socket
// per poll tick / per page load indefinitely.
const VTS_FETCH_TIMEOUT_MS = 5000;

async function fetchVTS() {
  return new Promise((resolve) => {
    const proto = NGINX_VTS_URL.startsWith('https') ? https : http;
    const req = proto.get(NGINX_VTS_URL, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(VTS_FETCH_TIMEOUT_MS, () => { req.destroy(); resolve(null); });
  });
}
/**
 * Totals for a VTS payload, preferring the `*` zone when present.
 *
 * Fix (audit finding MISC-11): `active` used to add `requestMsecCounter` —
 * a CUMULATIVE count of milliseconds spent processing requests since the
 * zone was created, not a connection/request count at all. Summed across
 * zones it produced a number with no real meaning (worse, one that grows
 * unboundedly like a byte counter, nothing like "requests active right
 * now"). The only field that actually means "requests currently being
 * processed in this zone" is `requests.processing` (present on VTS builds
 * new enough to expose it as structured JSON); older `requestCounter`/
 * `inBytes`-style payloads don't carry a per-zone processing count at all,
 * so those default to 0 — an honest "unknown", not a fabricated figure
 * pulled from an unrelated field.
 */
function computeTotals(vts) {
  let requests = 0, errors = 0, bytes = 0, active = 0;
  if (!vts?.serverZones) return { requests, errors, bytes, active };
  const star = vts.serverZones['*'];
  const add = z => {
    requests += z.requestCounter ?? z.requests?.total ?? 0;
    active   += z.requests?.processing ?? 0;
    errors   += (z.responses?.['4xx'] ?? 0) + (z.responses?.['5xx'] ?? 0);
    bytes    += (z.inBytes ?? z.traffic?.in ?? 0) + (z.outBytes ?? z.traffic?.out ?? 0);
  };
  if (star) add(star);
  else Object.entries(vts.serverZones).forEach(([, z]) => add(z));
  return { requests, errors, bytes, active };
}

/** Per-vhost zones, with `*` filtered out. */
function listZones(vts) {
  if (!vts?.serverZones) return [];
  return Object.entries(vts.serverZones)
    .filter(([name]) => name !== '*')
    .map(([name, z]) => ({
      name,
      requests: {
        total:      z.requestCounter ?? z.requests?.total      ?? 0,
        // See computeTotals()'s comment (fix MISC-11): requestMsecCounter is
        // a cumulative millisecond counter, not a "currently processing"
        // count — it must not be used as a fallback here either.
        processing: z.requests?.processing ?? 0,
      },
      responses: z.responses || {},
      traffic: {
        in:  z.inBytes  ?? z.traffic?.in  ?? 0,
        out: z.outBytes ?? z.traffic?.out ?? 0,
      },
      inBytes:  z.inBytes  ?? z.traffic?.in  ?? 0,
      outBytes: z.outBytes ?? z.traffic?.out ?? 0,
      cache: z.cache || {},
    }));
}

/** Sample the current totals into the rolling history. */
function recordSample(vts) {
  const t = computeTotals(vts);
  metricsHistory.timestamps.push(Date.now());
  metricsHistory.requests.push(t.requests);
  metricsHistory.errors.push(t.errors);
  metricsHistory.bytes.push(t.bytes);
  if (metricsHistory.timestamps.length > MAX_HISTORY) {
    metricsHistory.timestamps.shift();
    metricsHistory.requests.shift();
    metricsHistory.errors.shift();
    metricsHistory.bytes.shift();
  }

  const now = Date.now();
  const pushCapped = (series, ts, val) => {
    series.timestamps.push(ts);
    series.requests.push(val);
    if (series.timestamps.length > MAX_RATE_HISTORY) {
      series.timestamps.shift();
      series.requests.shift();
    }
  };

  pushCapped(globalRateHistory, now, t.requests);

  for (const z of listZones(vts)) {
    let series = vhostRateHistory.get(z.name);
    if (!series) { series = { timestamps: [], requests: [], lastSeen: now }; vhostRateHistory.set(z.name, series); }
    series.lastSeen = now;
    pushCapped(series, now, z.requests.total);
  }
  for (const [name, series] of vhostRateHistory) {
    if (now - series.lastSeen > VHOST_STALE_MS) vhostRateHistory.delete(name);
  }
}

/**
 * Turn a cumulative counter series into a requests/sec series: the delta
 * between consecutive samples divided by the actual elapsed time, rather
 * than assuming a fixed 5 s spacing — a slow poll tick or a gap must not
 * silently distort the rate. A negative delta means the underlying VTS
 * counter reset (an nginx reload or restart zeroes it) rather than traffic
 * running backwards; treated as zero for that tick instead of a fabricated
 * negative rate.
 */
function computeRateSeries(timestamps, cumulative, windowMinutes) {
  const windowMs = Math.max(1, windowMinutes) * 60_000;
  const cutoff = Date.now() - windowMs;
  let start = timestamps.findIndex(ts => ts >= cutoff);
  if (start === -1) start = timestamps.length;   // nothing recent enough
  if (start === 0) start = 1;                    // need a predecessor for the first delta

  const outTimestamps = [], outRps = [];
  for (let i = start; i < timestamps.length; i++) {
    const dtSec = (timestamps[i] - timestamps[i - 1]) / 1000;
    if (dtSec <= 0) continue;
    const delta = Math.max(0, cumulative[i] - cumulative[i - 1]);
    outTimestamps.push(timestamps[i]);
    outRps.push(+(delta / dtSec).toFixed(2));
  }
  return { timestamps: outTimestamps, rps: outRps };
}

let pollTimer = null;

/** Start the background sampler. unref()'d so it never holds the process open. */
function startPolling(intervalMs = 5000) {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    const vts = await fetchVTS();
    if (vts) recordSample(vts);
  }, intervalMs);
  pollTimer.unref();
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  const requireMetrics = session => hasPerm(session, PERMS.VIEW_METRICS);

  router.get('/api/metrics', async ({ res, session }) => {
    if (!requireMetrics(session)) return httpLib.forbidden(res, 'Forbidden — role insufficient');
    const vts = await fetchVTS();
    return send(res, 200, { vts, history: metricsHistory, timestamp: new Date().toISOString() });
  });

  /**
   * Requests/sec, global or for one vhost, over a selectable window. Rate
   * computation happens here rather than on the client: the client just
   * plots whatever comes back, and the same tested logic serves every window
   * size and every vhost instead of being duplicated in the frontend.
   */
  router.get('/api/metrics/rate', async ({ res, session, url }) => {
    if (!requireMetrics(session)) return httpLib.forbidden(res, 'Forbidden — role insufficient');
    const requestedWindow = +url.searchParams.get('window');
    const windowMinutes = [5, 15, 30, 60].includes(requestedWindow) ? requestedWindow : 5;
    const vhost = url.searchParams.get('vhost') || null;

    const series = vhost ? vhostRateHistory.get(vhost) : globalRateHistory;
    if (vhost && !series) return send(res, 200, { timestamps: [], rps: [], vhost, window: windowMinutes });

    const { timestamps, requests } = series || globalRateHistory;
    return send(res, 200, { ...computeRateSeries(timestamps, requests, windowMinutes), vhost, window: windowMinutes });
  });

  router.get('/api/status', async ({ res, session }) => {
    if (!requireMetrics(session)) return httpLib.forbidden(res, 'Forbidden — role insufficient');
    const vts = await fetchVTS();
    if (!vts) return send(res, 503, { error: 'Cannot reach nginx VTS endpoint' });
    const t = computeTotals(vts);
    return send(res, 200, {
      nginxVersion: vts.nginxVersion,
      loadMsec: vts.loadMsec,
      nowMsec: vts.nowMsec,
      connections: vts.connections,
      totalRequests: t.requests,
      activeConnections: t.active,
      totalBytes: t.bytes,
      totalErrors: t.errors,
      zones: listZones(vts).length,
      upstreams: vts.upstreamZones ? Object.keys(vts.upstreamZones).length : 0,
    });
  });

  router.get('/api/zones', async ({ res, session }) => {
    if (!requireMetrics(session)) return httpLib.forbidden(res, 'Forbidden — role insufficient');
    const vts = await fetchVTS();
    if (!vts?.serverZones) return send(res, 503, { error: 'No VTS data' });
    return send(res, 200, { zones: listZones(vts) });
  });

  router.get('/api/upstreams', async ({ res, session }) => {
    if (!requireMetrics(session)) return httpLib.forbidden(res, 'Forbidden — role insufficient');
    const vts = await fetchVTS();
    if (!vts?.upstreamZones) return send(res, 200, { upstreams: [] });
    return send(res, 200, {
      upstreams: Object.entries(vts.upstreamZones).map(([name, servers]) => ({ name, servers })),
    });
  });
}

module.exports = {
  register, startPolling, fetchVTS,
  computeTotals, listZones, recordSample, metricsHistory, MAX_HISTORY,
  computeRateSeries, globalRateHistory, vhostRateHistory, MAX_RATE_HISTORY,
};
