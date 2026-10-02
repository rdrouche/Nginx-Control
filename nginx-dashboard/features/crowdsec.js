'use strict';
/**
 * CrowdSec integration.
 *
 * Two sources of truth, in order of preference:
 *
 *  - Prometheus (CROWDSEC_PROMETHEUS_URL): richer, and purely local. Engine
 *    metrics come from the local agent, so nothing leaves the machine.
 *  - LAPI (CROWDSEC_URL + CROWDSEC_API_KEY): decisions and alerts.
 *
 * CROWDSEC_LOCAL_ONLY hides everything sourced from the central API, for
 * operators who do not want remote data surfaced in the dashboard.
 *
 * Every endpoint degrades to `{ configured: false }` rather than erroring when
 * CrowdSec is absent: it is an optional integration, not a dependency.
 *
 * Bouncers removed entirely (retour utilisateur v12.41.0) : le compteur et le
 * tableau "Bouncers connectes" avaient d abord ete conserves avec un message
 * "non disponible" (v12.41.0, premiere iteration) plutot que de laisser
 * croire a 0 bouncer connecte. Retour utilisateur suivant : si la valeur
 * n a jamais d interet a s afficher (limitation permanente de la LAPI de
 * CrowdSec, pas un etat transitoire), autant retirer completement l element
 * d UI plutot que de justifier son absence en permanence. Ni ce fichier, ni
 * public/assets/js/crowdsec.js, ni index.html n exposent donc plus aucun
 * champ bouncers/totalBouncers — pour les retrouver, `cscli bouncers list`
 * sur l hote CrowdSec reste le seul moyen (la LAPI n a toujours pas d
 * endpoint HTTP pour ca).
 */

const http = require('http');
const https = require('https');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const lapi    = require('../lib/crowdsec-lapi');
const events  = require('../lib/events');
// getCrowdsecCfg() reads crowdsec.yml fresh (env as fallback) — see
// lib/crowdsec-cfg.js. Shared with lib/crowdsec-lapi.js so both the metrics
// side (here) and the machine/ban side agree on the same effective settings.
const { getCrowdsecCfg } = require('../lib/crowdsec-cfg');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { logEvent } = events;

function crowdsecConfigured() {
  const c = getCrowdsecCfg();
  return !!(c.promUrl || (c.url && c.apiKey));
}

function crowdsecGet(endpoint) {
  const c = getCrowdsecCfg();
  return new Promise((resolve, reject) => {
    const url = new URL(c.url.replace(/\/$/, '') + endpoint);
    const proto = url.protocol === 'https:' ? require('https') : http;
    const opts = {
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search, method: 'GET',
      headers: { 'X-Api-Key': c.apiKey, 'Content-Type': 'application/json',
                 'User-Agent': cfg.HTTP_USER_AGENT },
      timeout: 8000,
    };
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode === 200) {
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        } else {
          reject({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('CrowdSec timeout')); });
    req.end();
  });
}

/** Fetch raw Prometheus text from CrowdSec /metrics endpoint */
function fetchPrometheus() {
  return new Promise((resolve, reject) => {
    const url  = new URL((getCrowdsecCfg().promUrl || '').replace(/\/$/, '') + '/metrics');
    const proto = url.protocol === 'https:' ? require('https') : http;
    const opts = {
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname, method: 'GET', timeout: 8000,
    };
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => res.statusCode === 200 ? resolve(data) : reject({ status: res.statusCode }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Prometheus timeout')); });
    req.end();
  });
}

/**
 * Parse Prometheus text format into a structured object.
 * Returns: { metricName: [ { labels: {k:v,...}, value: Number }, ... ], ... }
 */
function parsePrometheus(text) {
  const result = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // metric_name{label="val",...} value [timestamp]
    const m = trimmed.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([\d.eE+\-]+)/);
    if (!m) continue;
    const name   = m[1];
    const lblStr = m[2] || '';
    const value  = parseFloat(m[3]);
    if (isNaN(value)) continue;
    // Parse labels
    const labels = {};
    for (const lm of lblStr.matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"/g)) {
      labels[lm[1]] = lm[2];
    }
    if (!result[name]) result[name] = [];
    result[name].push({ labels, value });
  }
  return result;
}

/** Build CrowdSec dashboard data from Prometheus metrics (CrowdSec v1.7+)
 *  Actual metric names: cs_active_decisions, cs_bucket_overflowed_total,
 *  cs_filesource_hits_total, cs_parser_hits_ok_total, etc.
 */
/** Sum all series of a metric, optionally filtered by label key/value */
function promSum(metrics, name, filterLabel, filterValue) {
  const series = metrics[name] || [];
  return series
    .filter(s => !filterLabel || s.labels[filterLabel] === filterValue)
    .reduce((acc, s) => acc + s.value, 0);
}

async function getCrowdSecPrometheus() {
  const c       = getCrowdsecCfg();
  const raw     = await fetchPrometheus();
  const metrics = parsePrometheus(raw);

  // ── Active decisions — cs_active_decisions{action, origin, reason} ────────
  const activeDecisions = metrics['cs_active_decisions'] || [];
  let localBans = 0, capiDecisions = 0, totalActive = 0;
  const decisionsByType   = {};
  const decisionsByOrigin = {};

  for (const s of activeDecisions) {
    const origin = s.labels.origin || 'unknown';
    const action = s.labels.action || s.labels.type || 'ban'; // action=ban/captcha
    totalActive += s.value;
    // origin='crowdsec' = local decisions, 'CAPI' = community
    if (origin === 'CAPI') {
      capiDecisions += s.value;
    } else {
      localBans += s.value; // crowdsec + cscli + etc.
    }
    decisionsByType[action]   = (decisionsByType[action]   || 0) + s.value;
    decisionsByOrigin[origin] = (decisionsByOrigin[origin] || 0) + s.value;
  }

  const displayTotal    = c.localOnly ? localBans : totalActive;
  const displayByOrigin = c.localOnly
    ? Object.entries(decisionsByOrigin).filter(([k]) => k !== 'CAPI')
    : Object.entries(decisionsByOrigin);

  // ── Local alerts — cs_alerts{reason} (excludes CAPI) ─────────────────────
  const alertSeries = metrics['cs_alerts'] || [];
  const alertMap = {};
  for (const s of alertSeries) {
    const reason = s.labels.reason || 'unknown';
    alertMap[reason] = (alertMap[reason] || 0) + s.value;
  }
  const topScenarios = Object.entries(alertMap)
    .sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([name, count]) => ({ name, count }));
  const totalAlerts = alertSeries.reduce((a, s) => a + s.value, 0);

  // ── Bucket overflows — cs_bucket_overflowed_total{name} ──────────────────
  const bucketsOverflowed = promSum(metrics, 'cs_bucket_overflowed_total');
  const bucketsCreated    = promSum(metrics, 'cs_bucket_instantiation_total');

  // ── Log acquisition — cs_filesource_hits_total{acquis_type, source, ...} ──
  const acqSeries = metrics['cs_filesource_hits_total'] || [];
  const acqBySrc  = {};
  for (const s of acqSeries) {
    const src  = s.labels.source || 'unknown';
    const type = s.labels.acquis_type || s.labels.datasource_type || '';
    if (!acqBySrc[src]) acqBySrc[src] = { source: src, type, lines: 0 };
    acqBySrc[src].lines += s.value;
  }
  const acquisition = Object.values(acqBySrc).sort((a, b) => b.lines - a.lines);

  // ── Parser health — cs_parser_hits_ok_total / cs_parser_hits_ko_total ─────
  const parserOk = promSum(metrics, 'cs_parser_hits_ok_total');
  const parserKo = promSum(metrics, 'cs_parser_hits_ko_total');

  // ── Decisions list from LAPI (for IP details) ─────────────────────────────
  //
  // The IP list needs LAPI credentials: Prometheus metrics are aggregate
  // counts and never carry a decision's address (that would be a cardinality
  // explosion), so without CROWDSEC_URL/CROWDSEC_API_KEY there is no way to
  // list banned addresses at all — only the counts above are available.
  let recentDecisions = [];
  let lapiUnavailable = !(c.url && c.apiKey);
  if (!lapiUnavailable) {
    // "Local" here must mean exactly what it means in the counts above — any
    // origin other than CAPI, not only origin=crowdsec. Filtering strictly to
    // origin=crowdsec previously hid every decision added by cscli or coming
    // from a community blocklist ('cscli', 'lists'): the summary counted them
    // as local, but the fetch that lists actual addresses never returned them,
    // so the table stayed empty while every other figure looked correct.
    recentDecisions = await crowdsecGet('/v1/decisions?limit=200')
      .then(d => Array.isArray(d) ? d
        .filter(dec => !c.localOnly || dec.origin !== 'CAPI')
        .slice(0, 100)
        .map(dec => ({
          value:    dec.value,
          type:     dec.type,
          scenario: dec.scenario,
          origin:   dec.origin,
          duration: dec.duration,
          until:    dec.until,
        })) : [])
      .catch(() => []);
  }

  return {
    configured:    true,
    mode:          'prometheus',
    localOnly:     c.localOnly,
    lapiUnavailable,
    summary: {
      totalActive,
      localBans,
      capiDecisions,
      displayTotal,
      totalAlerts,
      bucketsOverflowed,
      bucketsCreated,
      parserOk,
      parserKo,
      decisionsByType,
    },
    decisionsByOrigin: displayByOrigin.map(([o, c]) => ({ origin: o, count: c })),
    topScenarios,
    acquisition,
    recentDecisions,
  };
}

/**
 * Fix (audit report, Basse/Divers dashboard, "CrowdSec en mode LAPI seul :
 * /v1/alerts est appele avec la cle bouncer et /v1/watchers n'existe pas,
 * donc les alertes sont toujours vides ou en 500"):
 *
 *  - GET /v1/alerts is a MACHINE (watcher) resource in CrowdSec's own LAPI —
 *    a bouncer's `X-Api-Key` (what `crowdsecGet()` sends, and all a bouncer
 *    is meant to have — see lib/crowdsec-lapi.js's module header on that
 *    security boundary) is rejected by the LAPI for it, every time, in
 *    "LAPI-only" setups where the operator only configured a bouncer key
 *    (no machine credentials). It is now fetched with the same MACHINE JWT
 *    used for ban/unban (`lapi.machineRequest`) when machine credentials are
 *    configured, and simply left empty — never even attempted with the
 *    wrong credential type — when they are not, exactly like the
 *    already-established pattern for `recentDecisions`/`lapiUnavailable` on
 *    the Prometheus side of this same file.
 *  - GET /v1/watchers, as a list-of-registered-machines endpoint, does not
 *    exist in the LAPI at all (confirmed against its published spec, same
 *    verification already done for the allowlist write endpoints below) —
 *    it always 404s. Bouncer/machine inventories are `cscli`-only, with no
 *    HTTP equivalent at all — see "Bouncers removed entirely (v12.41.0)"
 *    below for why this dashboard no longer surfaces that field at all.
 */
async function getCrowdSecMetrics() {
  const [decisions, alerts] = await Promise.all([
    crowdsecGet('/v1/decisions').catch(() => []),
    lapi.machineConfigured()
      ? lapi.machineRequest('GET', '/v1/alerts?limit=50').then(r => (r.status === 200 ? r.body : [])).catch(() => [])
      : Promise.resolve([]),
  ]);

  const decArr   = Array.isArray(decisions) ? decisions : [];
  const alertArr = Array.isArray(alerts)    ? alerts    : [];

  // Group decisions by type
  const byType = {};
  const byCountry = {};
  const byScenario = {};
  decArr.forEach(d => {
    byType[d.type]         = (byType[d.type]         || 0) + 1;
    byCountry[d.origin]    = (byCountry[d.origin]    || 0) + 1;
    if (d.scenario) byScenario[d.scenario] = (byScenario[d.scenario] || 0) + 1;
  });

  // Top scenarios from alerts
  alertArr.forEach(a => {
    const sc = a.scenario || (a.decisions?.[0]?.scenario) || 'unknown';
    byScenario[sc] = (byScenario[sc] || 0) + 1;
  });

  const topScenarios = Object.entries(byScenario)
    .sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  const recentAlerts = alertArr.slice(0, 20).map(a => ({
    id:        a.id,
    scenario:  a.scenario,
    source_ip: a.source?.ip,
    country:   a.source?.cn,
    createdAt: a.created_at,
    decisions: a.decisions?.length || 0,
  }));

  return {
    configured: true,
    // `alertsUnavailable` tells the frontend WHY the alerts panel might be
    // empty (no machine credentials configured) rather than it looking like
    // "no alerts right now" — see this function's own comment.
    alertsUnavailable: !lapi.machineConfigured(),
    summary: {
      totalDecisions: decArr.length,
      totalAlerts:    alertArr.length,
      byType,
    },
    topScenarios,
    recentAlerts,
    decisions: decArr.slice(0, 100).map(d => ({
      id:       d.id,
      type:     d.type,
      value:    d.value,
      origin:   d.origin,
      scenario: d.scenario,
      duration: d.duration,
      until:    d.until,
    })),
  };
}
// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/crowdsec/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    if (!crowdsecConfigured()) return send(res, 200, { configured: false });
    try {
      // Prometheus first: richer, and local-only.
      if (getCrowdsecCfg().promUrl) return send(res, 200, await getCrowdSecPrometheus());
      return send(res, 200, { ...(await getCrowdSecMetrics()), mode: 'lapi' });
    } catch (e) {
      // Reported as a 200 with ok:false — CrowdSec being down is a state to
      // display, not a dashboard failure.
      return send(res, 200, { configured: true, ok: false, error: e.message || JSON.stringify(e) });
    }
  });

  router.get('/api/crowdsec/decisions', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    if (!crowdsecConfigured()) return send(res, 200, { configured: false });
    try {
      const limit = url.searchParams.get('limit') || '100';
      const type  = url.searchParams.get('type')  || '';
      let endpoint = `/v1/decisions?limit=${encodeURIComponent(limit)}`;
      if (type) endpoint += `&type=${encodeURIComponent(type)}`;
      const decisions = await crowdsecGet(endpoint);
      return send(res, 200, { decisions: Array.isArray(decisions) ? decisions : [] });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.get('/api/crowdsec/alerts', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    if (!crowdsecConfigured()) return send(res, 200, { configured: false });
    try {
      const limit  = url.searchParams.get('limit') || '50';
      const alerts = await crowdsecGet(`/v1/alerts?limit=${encodeURIComponent(limit)}`);
      return send(res, 200, { alerts: Array.isArray(alerts) ? alerts : [] });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  // ── Ban / unban — require a separate machine credential, see lib/crowdsec-lapi.js ──
  router.get('/api/crowdsec/machine-status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    if (!lapi.machineConfigured()) {
      return send(res, 200, { configured: false,
        hint: "Run 'cscli machines add nginx-dashboard --password <une-phrase-secrete>' on the CrowdSec host (never --auto: it generates a password nobody is shown), then set CROWDSEC_MACHINE_ID=nginx-dashboard and CROWDSEC_MACHINE_PASSWORD to that same value, restart the dashboard, and delete any other stale machine entry." });
    }
    // Echoing the machine_id (never the password) is what actually lets an
    // operator catch a mismatch quickly: `cscli machines list` on the
    // CrowdSec host and this value must name the exact same entry, or the
    // login will keep failing no matter how many times the password is
    // re-checked.
    try {
      await lapi.getMachineToken();
      return send(res, 200, { configured: true, ok: true, machineId: getCrowdsecCfg().machineId });
    } catch (e) {
      return send(res, 200, { configured: true, ok: false, machineId: getCrowdsecCfg().machineId,
        error: e.error || e.message, detail: e.body });
    }
  });

  router.post('/api/crowdsec/ban', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    if (!lapi.machineConfigured()) return httpLib.badRequest(res, 'Machine credentials not configured');
    const body = await parseBody(req);
    try {
      const r = await lapi.banIp({ ip: body.ip, duration: body.duration, reason: body.reason || `Ban manuel par ${session.username}` });
      logEvent('crowdsec.ban', { ip: body.ip, duration: body.duration, by: session.username }, 'crowdsec');
      return send(res, 200, r);
    } catch (e) { return send(res, e.status && e.status >= 400 && e.status < 500 ? 400 : 500, e); }
  });

  router.post('/api/crowdsec/unban', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    if (!lapi.machineConfigured()) return httpLib.badRequest(res, 'Machine credentials not configured');
    const body = await parseBody(req);
    try {
      const r = body.id ? await lapi.unbanDecisionId(body.id) : await lapi.unbanIp(body.ip);
      logEvent('crowdsec.unban', { id: body.id, ip: body.ip, by: session.username }, 'crowdsec');
      return send(res, 200, r);
    } catch (e) { return send(res, e.status && e.status >= 400 && e.status < 500 ? 400 : 500, e); }
  });

  // ── Listes blanches centralisees ──────────────────────────────────────────
  router.get('/api/crowdsec/allowlists', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    if (!lapi.machineConfigured()) return send(res, 200, { configured: false, allowlists: [] });
    try { return send(res, 200, { configured: true, allowlists: await lapi.listAllowlists() }); }
    catch (e) { return send(res, 200, { configured: true, ok: false, error: e.error, detail: e.body }); }
  });

  // Confirmed absent from the LAPI itself (see lib/crowdsec-lapi.js's module
  // header): no POST, PUT or DELETE exists anywhere under /allowlists in its
  // published spec. These three routes are kept, rather than removed, so a
  // client hitting them gets one clear, immediate 501 naming the real path
  // (cscli) instead of a 404 that looks like a routing mistake.
  const allowlistWriteUnsupported = (fn) => async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try { await fn(); }
    catch (e) { return send(res, e.status || 500, e); }
  };
  router.post('/api/crowdsec/allowlists', allowlistWriteUnsupported(lapi.createAllowlist));
  router.post('/api/crowdsec/allowlists/items', allowlistWriteUnsupported(lapi.addAllowlistItem));
  router.post('/api/crowdsec/allowlists/items/remove', allowlistWriteUnsupported(lapi.removeAllowlistItem));

  /** Whether an address or range is covered by any allowlist — real and read-only. */
  router.get('/api/crowdsec/allowlists/check', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CROWDSEC)) return httpLib.forbidden(res);
    const value = url.searchParams.get('value');
    if (!value) return httpLib.badRequest(res, 'value required');
    if (!lapi.machineConfigured()) return send(res, 200, { configured: false });
    try { return send(res, 200, { configured: true, ...(await lapi.checkAllowlist(value)) }); }
    catch (e) { return send(res, 200, { configured: true, ok: false, error: e.error, detail: e.body }); }
  });
}

module.exports = {
  register, crowdsecConfigured, crowdsecGet,
  getCrowdSecMetrics, getCrowdSecPrometheus, parsePrometheus, promSum,
};
