'use strict';
/**
 * Log analyzer integration.
 *
 * The analysis runs in its own container: parsing a busy access log is steady
 * CPU work, and keeping it out of the dashboard means a spike in traffic cannot
 * make the interface unresponsive. The dashboard owns its lifecycle — pull,
 * start, stop, update — and proxies its API, exactly like GoAccess and GoDNS.
 *
 * The analyzer's port is never published. It is reachable only on the internal
 * Docker network — but that network (nginx-net) is shared with every backend
 * the reverse proxy fronts, not just this dashboard, so the analyzer's API
 * also checks a shared secret this dashboard generates and passes at
 * container-creation time (see lib/analyzer-token.js and audit finding
 * ANA-10) rather than trusting network placement alone.
 *
 * Alerts are pulled rather than pushed. The analyzer stores them and the
 * dashboard polls; email notification reuses the existing SMTP configuration,
 * with the same rule as everywhere else — an alert type must be enabled and
 * have recipients before anything is sent.
 */

const fs   = require('fs');
const path = require('path');
const http = require('http');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const notify  = require('../lib/notify');
const events  = require('../lib/events');
const { pushNotification } = require('../lib/notifications');
const { listVhostTargets } = require('../lib/vhost-targets');
const { getAnalyzerToken } = require('../lib/analyzer-token');

const { DIR_SITES, DIR_CONF } = cfg;
const UPSTREAM_DIRS = [DIR_CONF, DIR_SITES];

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const ANALYZER_CONFIG_FILE = path.join(cfg.CONFIG_DIR, 'analyzer.yml');

let ANALYZER_CFG = null;

/** Minimal YAML reader, same shape as the other feature configs. */
function loadAnalyzerConfig() {
  if (!fs.existsSync(ANALYZER_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(ANALYZER_CONFIG_FILE, 'utf8');
    const out = {};
    for (const rawLine of raw.split('\n')) {
      const line = rawLine.replace(/\r/g, '');
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const m = line.match(/^([a-z_]+)\s*:\s*(.+)$/);
      if (!m) continue;
      const v = m[2].trim().replace(/^["']|["']$/g, '');
      out[m[1]] = v === 'true' ? true : v === 'false' ? false
                : (v !== '' && !isNaN(v)) ? Number(v) : v;
    }
    return out;
  } catch (e) {
    console.warn('[analyzer] Config load error:', e.message);
    return null;
  }
}

function getAnalyzerCfg() { ANALYZER_CFG = loadAnalyzerConfig(); return ANALYZER_CFG; }

const containerName = c => (c && c.container_name) || 'ngx-analyzer';
const analyzerPort  = c => (c && c.port) || 9100;

// ─── Container lifecycle ─────────────────────────────────────────────────────
async function analyzerStatus() {
  const c = getAnalyzerCfg();
  const name = containerName(c);
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  // status 0 : le demon est injoignable — a distinguer d un conteneur absent.
  if (r.status === 0)   return { exists: false, running: false, name, dockerUnavailable: true, error: r.error };
  if (r.status === 404) return { exists: false, running: false, name };
  if (r.status !== 200) return { exists: false, running: false, name, error: `HTTP ${r.status}` };
  return {
    exists: true,
    running: r.body?.State?.Running === true,
    status:  r.body?.State?.Status || 'unknown',
    image:   r.body?.Config?.Image || '',
    started: r.body?.State?.StartedAt || '',
    name,
  };
}

async function pullAnalyzerImage(c) {
  const image = c.container_image || cfg.ANALYZER_DEFAULT_IMAGE;
  console.log(`[analyzer] Pulling image: ${image}`);
  await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  const inspect = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
  return inspect.status === 200;
}

/**
 * Create and start the analyzer.
 *
 * Bind-mount sources must be HOST paths: handing the daemon a path that only
 * exists inside the dashboard makes it create an empty directory and mount
 * that, and the analyzer would silently see no logs at all.
 */
async function startAnalyzer(c) {
  const name  = containerName(c);
  const image = c.container_image || cfg.ANALYZER_DEFAULT_IMAGE;

  const hostLogs = c.host_logs_path || cfg.HOST_LOGS;
  const hostData = c.host_data_path;
  if (!hostData) {
    throw new Error('host_data_path manquant dans analyzer.yml : sans lui, l historique et la baseline sont perdus a chaque redemarrage');
  }
  const hostGeoip = c.host_geoip_path || null;

  await dockerCall('POST',   `/containers/${encodeURIComponent(name)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`).catch(() => {});

  const binds = [
    `${hostLogs}:/nginx/logs:ro`,
    `${hostData}:/analyzer`,
  ];
  if (hostGeoip) binds.push(`${hostGeoip}:/geoip:ro`);

  const env = [
    `LOGS_DIR=/nginx/logs`,
    `DB_PATH=/analyzer/state.db`,
    // Fix (audit finding ANA-10): shared secret checked on every analyzer
    // API request — see lib/analyzer-token.js.
    `ANALYZER_TOKEN=${getAnalyzerToken()}`,
    // Fix v12.22.x (audit finding ANA-02): the old default never matched
    // this project's own logging.conf ("vhosts_access.log", an underscore
    // rather than a dot before "access") — see config/analyzer.yml's own
    // comment on log_pattern for the full rationale.
    `LOG_PATTERN=${c.log_pattern || '(^|[._])access\\.log$'}`,
    `LEARNING_DAYS=${c.learning_days ?? 21}`,
    `SIGMA_THRESHOLD=${c.sigma_threshold ?? 6}`,
    `BF_MIN_FAILURES=${c.bruteforce_min_failures ?? 15}`,
    `SCAN_MIN_REQUESTS=${c.scan_min_requests ?? 40}`,
    `FLOOD_MIN_REQUESTS=${c.flood_min_requests ?? 600}`,
    // Codes HTTP ignores par la detection (ex. 444 : deja bloque ailleurs) — vide = aucun.
    `DETECT_IGNORE_STATUS=${String(c.ignore_status ?? '').replace(/[^0-9,; ]/g, '')}`,
    `ALERT_RETENTION_DAYS=${c.alert_retention_days ?? 90}`,
    `WAF_LOG_PATTERN=${c.waf_log_pattern || '\\.waf\\.log$'}`,
    `WAF_RETENTION_DAYS=${c.waf_retention_days ?? 60}`,
    // Etat par defaut au tout premier demarrage seulement — passe ce point,
    // l analyzer persiste ses propres reglages (bascules faites depuis la
    // modale "Regles" du dashboard) et ces variables sont ignorees. Voir
    // lib/rules-manager.js cote analyzer.
    `RULE_BRUTEFORCE_ENABLE=${c.rule_bruteforce_enable ?? true}`,
    `RULE_SCAN_ENABLE=${c.rule_scan_enable ?? true}`,
    `RULE_FLOOD_ENABLE=${c.rule_flood_enable ?? true}`,
    `RULE_SCRAPING_ENABLE=${c.rule_scraping_enable ?? true}`,
    `RULE_VOLUMETRIC_ENABLE=${c.rule_volumetric_enable ?? true}`,
    `RULE_COUNTRY_TRAFFIC_ENABLE=${c.rule_country_traffic_enable ?? true}`,
  ];

  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(name)}`, {
    Image: image,
    Env: env,
    HostConfig: {
      Binds: binds,
      RestartPolicy: { Name: 'unless-stopped' },
      NetworkMode: cfg.NGINX_NETWORK || 'nginx-net',
    },
    Labels: { 'managed-by': 'nginx-dashboard' },
  });
  if (create.status !== 201) {
    throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);
  }
  const start = await dockerCall('POST', `/containers/${encodeURIComponent(name)}/start`);
  if (start.status !== 204 && start.status !== 304) {
    throw new Error(`Start failed: ${start.status}`);
  }
  return { ok: true, name, binds };
}

async function stopAnalyzer(c) {
  await dockerCall('POST', `/containers/${encodeURIComponent(containerName(c))}/stop?t=10`);
  return { ok: true };
}

/**
 * Redemarre le conteneur analyzer (tache planifiee « Redemarrer l'analyzer »,
 * et utilisable a la demande) puis attend que son API reponde de nouveau.
 *
 * Un `docker restart` conserve le conteneur, son image et ses montages : la
 * base d'historique et la baseline survivent (ils sont sur le volume
 * host_data_path), contrairement a startAnalyzer() qui recree le conteneur.
 * L'attente de /api/health est volontairement incluse : l'API n'est pas
 * joignable tout de suite apres un redemarrage (chargement de la base,
 * relecture des journaux) et un redemarrage « reussi » dont l'API ne revient
 * jamais doit etre signale comme un echec, pas comme un succes.
 *
 * @returns {{ok:boolean, skipped?:boolean, message:string, healthy?:boolean, waitedMs?:number}}
 *          leve une exception quand Docker est injoignable ou le conteneur absent.
 */
async function restartAnalyzer({ graceSeconds = 10, waitHealthy = true, healthTimeoutMs = 90_000, pollMs = 2_000 } = {}) {
  const c = getAnalyzerCfg();
  if (!c?.enable) return { ok: false, skipped: true, message: "L'analyzer est desactive (analyzer.yml : enable: false)" };
  const st = await analyzerStatus();
  if (st.dockerUnavailable) throw new Error(`Docker injoignable : ${st.error || 'socket indisponible'}`);
  if (!st.exists) throw new Error(`Conteneur « ${st.name} » absent : demarrez-le depuis la page Analyse`);
  const grace = Math.max(1, Math.min(120, Math.floor(Number(graceSeconds)) || 10));
  const r = await dockerCall('POST', `/containers/${encodeURIComponent(st.name)}/restart?t=${grace}`);
  if (r.status !== 204 && r.status !== 304) throw new Error(`Redemarrage refuse par Docker : HTTP ${r.status}`);
  if (!waitHealthy) return { ok: true, healthy: null, message: `Conteneur « ${st.name} » redemarre` };

  const t0 = Date.now();
  while (Date.now() - t0 < healthTimeoutMs) {
    await new Promise(res => setTimeout(res, pollMs));
    const h = await analyzerApi('/api/health');
    if (h && h.status === 200) {
      const waitedMs = Date.now() - t0;
      return { ok: true, healthy: true, waitedMs, message: `Conteneur « ${st.name} » redemarre, API de nouveau joignable apres ${(waitedMs / 1000).toFixed(1)} s` };
    }
  }
  return { ok: false, healthy: false, waitedMs: Date.now() - t0,
    message: `Conteneur « ${st.name} » redemarre mais l'API ne repond toujours pas apres ${Math.round(healthTimeoutMs / 1000)} s (voir les logs du conteneur)` };
}

/**
 * Same reasoning as certbot's/geoipupdate's/error-pages' own
 * ensure*AtBoot(): `RestartPolicy: unless-stopped` only ever restarts a
 * container Docker already knows about — it does nothing the very first
 * time `enable: true` is set, nor after an operator-triggered stop that
 * removed the container outright (stopAnalyzer here only stops it, but the
 * other three managed containers' own stop removes theirs, and this keeps
 * the same shape for consistency and for whichever comes next).
 */
async function ensureContainerAtBoot() {
  const c = getAnalyzerCfg();
  if (!c?.enable) return { skipped: 'not enabled' };
  if (!c.host_data_path) return { skipped: 'host_data_path missing' };
  try {
    const status = await analyzerStatus();
    if (status.dockerUnavailable) return { skipped: 'docker unavailable', error: status.error };
    if (status.exists) return { skipped: 'already exists' };
    await pullAnalyzerImage(c);
    await startAnalyzer(c);
    console.log('[analyzer] Container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[analyzer] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── API proxy ───────────────────────────────────────────────────────────────
/**
 * Call the analyzer's API. Returns null when it is unreachable — a stopped
 * analyzer is a state to display, not a dashboard failure.
 */
function analyzerApi(pathAndQuery, method = 'GET') {
  const c = getAnalyzerCfg();
  return new Promise(resolve => {
    const req = http.request({
      hostname: containerName(c), port: analyzerPort(c),
      path: pathAndQuery, method, timeout: 8000,
      headers: { 'X-Analyzer-Token': getAnalyzerToken(), 'User-Agent': cfg.HTTP_USER_AGENT },
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, data: null }); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

/** Same as analyzerApi(), but for the two endpoints that need a JSON body (custom rules YAML, vhost-rules map) rather than query params. */
function analyzerApiJson(pathAndQuery, method, bodyObj) {
  const c = getAnalyzerCfg();
  const body = JSON.stringify(bodyObj || {});
  return new Promise(resolve => {
    const req = http.request({
      hostname: containerName(c), port: analyzerPort(c),
      path: pathAndQuery, method, timeout: 8000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
                 'X-Analyzer-Token': getAnalyzerToken(), 'User-Agent': cfg.HTTP_USER_AGENT },
    }, res => {
      let out = '';
      res.on('data', d => out += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(out) }); }
        catch { resolve({ status: res.statusCode, data: null }); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end(body);
  });
}

/**
 * Recompute the per-vhost analyze opt-out from the vhost files' own comments
 * (# nginx-control-analyze: off / # nginx-control-analyze-ignore-rules: ...,
 * see lib/vhost-targets.js) and push it to the analyzer, which applies it
 * immediately (lib/detect.js Detector.setVhostRules()) — no restart needed.
 * The vhost files are the source of truth: this is meant to be called on a
 * timer (see startAlertPolling) so an edited vhost file takes effect within
 * a minute, without the operator having to remember a separate sync step.
 */
async function pushVhostRules() {
  const c = getAnalyzerCfg();
  if (!c?.enable) return;
  // A single logical vhost is almost always TWO server{} blocks in the same
  // file (the plain-HTTP :80 redirect + the real :443 block) sharing the
  // same server_name — see features/vhost-generator.js's own output, and
  // every hand-written vhost in this project. Real bug found in the wild:
  // this loop used to unconditionally overwrite vhosts[name] per block, so
  // whichever block came LAST in the file always won — a redirect block
  // (no comments, so `enabled:true, ignore:[]` by default) coming after the
  // real block silently erased that block's `# nginx-control-analyze-*`
  // settings, and every rule stayed active despite the operator's comment.
  // Fixed by merging across every block sharing a name instead: `enabled`
  // is AND'd (any block saying "off" wins, matching the opt-out semantics)
  // and `ignore` is unioned (a rule id ignored by either block is ignored
  // for the vhost as a whole) — order of the blocks in the file no longer
  // matters.
  const vhosts = buildVhostRulesMap();
  await analyzerApiJson('/api/vhost-rules', 'POST', { vhosts });
}

/** Union par regle de deux maps { [ruleId]: string[] } de motifs paths-ignore. */
function mergePathsIgnore(a, b) {
  const out = {};
  for (const src of [a || {}, b || {}]) {
    for (const [id, list] of Object.entries(src)) {
      out[id] = [...new Set([...(out[id] || []), ...list])];
    }
  }
  return out;
}

/**
 * Recompute the { enabled, ignore, noRemediation } map straight from the
 * vhost files, without pushing it anywhere — extracted out of pushVhostRules()
 * so features/blocklists.js's own "Blocklist a la CrowdSec" computation
 * (v12.50.0) can read the `noRemediation` opt-out (# nginx-control-analyze-
 * no-remediation: on) directly, the same source of truth, without a round
 * trip through the analyzer (which never needs this field itself: it only
 * affects the dashboard's own blocking decision, never detection/alerting).
 */
function buildVhostRulesMap() {
  const vhosts = {};
  for (const v of listVhostTargets({ sitesDir: DIR_SITES, upstreamDirs: UPSTREAM_DIRS })) {
    for (const block of v.serverBlocks || []) {
      for (const name of block.serverNames || []) {
        if (name === '_' || !name) continue;
        const enabled = block.analyzeEnabled !== false;
        const ignore = block.analyzeIgnoreRuleIds || [];
        const noRemediation = !!block.analyzeNoRemediation;
        const pathsIgnore = block.analyzePathsIgnore || {};
        const prev = vhosts[name];
        const entry = prev
          ? {
              enabled: prev.enabled && enabled,
              ignore: [...new Set([...prev.ignore, ...ignore])],
              // OR/union, meme semantique que `ignore` ci-dessus : un seul
              // bloc partageant ce nom de vhost suffit a exempter le nom
              // entier de la remediation automatique.
              noRemediation: prev.noRemediation || noRemediation,
              // Union par regle, comme `ignore` : un motif declare dans l un des
              // blocs partageant ce nom de vhost s applique au vhost entier.
              pathsIgnore: mergePathsIgnore(prev.pathsIgnore, pathsIgnore),
            }
          : { enabled, ignore: [...ignore], noRemediation, pathsIgnore: mergePathsIgnore({}, pathsIgnore) };
        // Charge utile inchangee tant qu aucun motif n est declare.
        if (!Object.keys(entry.pathsIgnore).length) delete entry.pathsIgnore;
        vhosts[name] = entry;
      }
    }
  }
  return vhosts;
}

// ─── Alert forwarding ────────────────────────────────────────────────────────
// Fix (audit finding ANA-08): this used to be a timestamp (lastAlertSeen)
// driving `limit=50&since=<ts>&ORDER BY ts DESC`, jumping straight to the
// newest alert's ts every poll. Past 50 new alerts in a single minute — a
// real flood is exactly when that happens — everything older than the
// newest 50 was silently skipped, and the cursor's jump to the newest ts
// made sure those skipped alerts would never be asked for again. This is
// now an alert id (a strictly increasing cursor, see Store.listAlerts()),
// and pollAlerts() pages forward with `order=asc` until the whole backlog
// since the last poll has actually been consumed, however large it is.
let lastAlertId = null; // null until the first successful poll seeds it
const ALERT_POLL_PAGE = 200;
const ALERT_POLL_MAX_PAGES = 25; // safety cap: 5000 alerts/poll is already far more than any real backlog

/**
 * Poll the analyzer for new alerts, mirror them into the dashboard event log
 * and send mail when the notification rule allows it.
 *
 * Only alerts after the last one seen are fetched, so a restart does not
 * replay a week of history into the operator's inbox — but see lastAlertId's
 * comment above: once seeded, every alert since is actually consumed, not
 * just the newest handful.
 */
async function pollAlerts() {
  const c = getAnalyzerCfg();
  if (!c?.enable) return;

  const fresh = [];
  let pages = 0;
  for (;;) {
    const query = lastAlertId === null
      // Pas encore de curseur (premier appel, ou dashboard qui redemarre) :
      // on ne remonte que la derniere heure, pour ne pas rejouer une semaine
      // d alertes dans la boite mail de l operateur.
      ? `since=${Date.now() - 3_600_000}&order=asc&limit=${ALERT_POLL_PAGE}`
      : `sinceId=${lastAlertId}&order=asc&limit=${ALERT_POLL_PAGE}`;
    const r = await analyzerApi(`/api/alerts?${query}`);
    const batch = r?.data?.alerts;
    if (!batch?.length) break;
    fresh.push(...batch);
    lastAlertId = Math.max(...batch.map(a => a.id), lastAlertId ?? -Infinity);
    pages++;
    if (batch.length < ALERT_POLL_PAGE || pages >= ALERT_POLL_MAX_PAGES) break;
  }
  if (!fresh.length) return;

  const minSeverity = c.notify_min_severity || 'medium';
  const rank = { low: 1, medium: 2, high: 3 };
  const severityLevel = { low: 'info', medium: 'warning', high: 'error' };

  for (const a of fresh) {
    logEvent(`analyzer.${a.type}`, {
      severity: a.severity, ip: a.ip, vhost: a.vhost, summary: a.summary,
    }, 'analyzer');

    if ((rank[a.severity] || 0) < (rank[minSeverity] || 2)) continue;
    // Meme seuil notify_min_severity que l email ci-dessous : le centre de
    // notification et l email partagent la meme regle de bruit, seuls les
    // canaux different (chacun sa propre decision, meme convention que les
    // autres call sites de ce fichier).
    pushNotification({
      type: 'analyzer_alert', level: severityLevel[a.severity] || 'warning',
      message: `${a.summary}${a.vhost ? ' (' + a.vhost + ')' : ''}`,
      data: { alertType: a.type, severity: a.severity, ip: a.ip, vhost: a.vhost, ts: a.ts },
    });
    await notify.sendNotification('analyzer_alert',
      `[Nginx Dashboard] ${a.severity.toUpperCase()} — ${a.type}`,
      [
        a.summary, '',
        `Type      : ${a.type}`,
        `Severite  : ${a.severity}`,
        a.ip    ? `Adresse   : ${a.ip}` : '',
        a.vhost ? `VHost     : ${a.vhost}` : '',
        `Date      : ${new Date(a.ts).toISOString()}`,
        '',
        'Preuves :',
        JSON.stringify(a.evidence, null, 2).slice(0, 2000),
      ].filter(Boolean).join('\n'),
    ).catch(() => {});
  }
}

let pollTimer = null;
function startAlertPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    pollAlerts().catch(() => {});
    pushVhostRules().catch(() => {});
  }, 60_000);
  pollTimer.unref();
  // Applique tout de suite au demarrage plutot que d attendre la premiere
  // minute — un dashboard qui redemarre ne doit pas laisser l analyzer sur
  // un opt-out perime (vhost supprime, regle reactivee, etc.).
  pushVhostRules().catch(() => {});
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/analyzer/config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const c = getAnalyzerCfg();
    if (!c) return send(res, 200, { configured: false, enabled: false });
    return send(res, 200, {
      configured: true,
      enabled: !!c.enable,
      image: c.container_image || cfg.ANALYZER_DEFAULT_IMAGE,
      containerName: containerName(c),
      learningDays: c.learning_days ?? 21,
      sigmaThreshold: c.sigma_threshold ?? 6,
      notifyMinSeverity: c.notify_min_severity || 'medium',
    });
  });

  router.get('/api/analyzer/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const c = getAnalyzerCfg();
    if (!c?.enable) return send(res, 200, { enabled: false });
    const container = await analyzerStatus();
    const agent = await analyzerApi('/api/status');
    return send(res, 200, {
      enabled: true,
      container,
      // A stopped analyzer is reported, not treated as an error.
      agent: agent?.data || null,
      reachable: !!agent,
    });
  });

  router.get('/api/analyzer/alerts', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const q = url.searchParams.toString();
    const r = await analyzerApi(`/api/alerts${q ? '?' + q : ''}`);
    if (!r) return send(res, 200, { reachable: false, alerts: [], total: 0 });
    return send(res, 200, { reachable: true, ...r.data });
  });

  // ── Exceptions, par vhost ──────────────────────────────────────────────
  router.get('/api/analyzer/exceptions', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const vhost = url.searchParams.get('vhost');
    const r = await analyzerApi('/api/exceptions' + (vhost ? `?vhost=${encodeURIComponent(vhost)}` : ''));
    if (!r) return send(res, 200, { reachable: false, exceptions: [] });
    return send(res, 200, { reachable: true, ...r.data });
  });

  router.post('/api/analyzer/exceptions', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.vhost || !body.ip) return httpLib.badRequest(res, 'vhost and ip required');
    const q = new URLSearchParams({
      vhost: body.vhost, ip: body.ip,
      reason: body.reason || '', author: session.username,
    });
    const r = await analyzerApi('/api/exceptions?' + q.toString(), 'POST');
    logEvent('analyzer.exception_add',
      { vhost: body.vhost, ip: body.ip, reason: body.reason, by: session.username });
    return send(res, 200, r?.data || { ok: false });
  });

  router.post('/api/analyzer/exceptions/remove', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.id) return httpLib.badRequest(res, 'id required');
    const r = await analyzerApi(`/api/exceptions/${encodeURIComponent(body.id)}`, 'DELETE');
    logEvent('analyzer.exception_remove', { id: body.id, by: session.username });
    return send(res, 200, r?.data || { ok: false });
  });

  router.post('/api/analyzer/alerts/ack', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.id) return httpLib.badRequest(res, 'id required');
    const r = await analyzerApi(`/api/alerts/${encodeURIComponent(body.id)}/ack`, 'POST');
    return send(res, 200, r?.data || { ok: false });
  });

  /** Acknowledge everything matching the current filters — an operator action. */
  router.post('/api/analyzer/alerts/ack-all', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const q = new URLSearchParams();
    if (body.type)     q.set('type', body.type);
    if (body.severity) q.set('severity', body.severity);
    if (body.vhost)    q.set('vhost', body.vhost);
    const r = await analyzerApi('/api/alerts/ack-all' + (q.toString() ? '?' + q : ''), 'POST');
    if (r?.data?.updated) logEvent('analyzer.ack_all', { count: r.data.updated, by: session.username });
    return send(res, 200, r?.data || { updated: 0 });
  });

  /**
   * Delete alerts matching the filters. Irreversible, so it follows the same
   * rule as clearing the dashboard's own event log: admin only.
   */
  router.post('/api/analyzer/alerts/clear', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const q = new URLSearchParams();
    if (body.type)     q.set('type', body.type);
    if (body.severity) q.set('severity', body.severity);
    if (body.vhost)    q.set('vhost', body.vhost);
    const r = await analyzerApi('/api/alerts/clear' + (q.toString() ? '?' + q : ''), 'POST');
    if (r?.data?.deleted) logEvent('analyzer.clear_all', { count: r.data.deleted, by: session.username });
    return send(res, 200, r?.data || { deleted: 0 });
  });

  for (const kind of ['series', 'countries', 'vhosts', 'recent', 'bots']) {
    router.get(`/api/analyzer/traffic/${kind}`, async ({ res, session, url }) => {
      if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
      const q = url.searchParams.toString();
      const r = await analyzerApi(`/api/traffic/${kind}${q ? '?' + q : ''}`);
      if (!r) return send(res, 200, { reachable: false });
      return send(res, 200, { reachable: true, ...r.data });
    });
  }

  // Human/bot split per vhost and per country — extra columns for the
  // Analyse page's existing tables, not new tabs of their own.
  for (const kind of ['bots/vhosts', 'bots/countries']) {
    router.get(`/api/analyzer/traffic/${kind}`, async ({ res, session, url }) => {
      if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
      const q = url.searchParams.toString();
      const r = await analyzerApi(`/api/traffic/${kind}${q ? '?' + q : ''}`);
      if (!r) return send(res, 200, { reachable: false });
      return send(res, 200, { reachable: true, ...r.data });
    });
  }

  // ── ModSecurity / WAF — read-only, separate view, no notifications ────────
  router.get('/api/analyzer/waf/events', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const q = url.searchParams.toString();
    const r = await analyzerApi(`/api/waf/events${q ? '?' + q : ''}`);
    if (!r) return send(res, 200, { reachable: false, events: [], total: 0 });
    return send(res, 200, { reachable: true, ...r.data });
  });

  /** One full event — raw line, engine, per-rule category and reference link. */
  router.addPrefix('GET', '/api/analyzer/waf/events/', async ({ res, session, pathname }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const id = pathname.split('/').pop();
    const r = await analyzerApi(`/api/waf/events/${encodeURIComponent(id)}`);
    if (!r) return send(res, 200, { reachable: false });
    if (r.status === 404) return httpLib.notFound(res, 'Not found');
    return send(res, 200, { reachable: true, ...r.data });
  });

  for (const kind of ['top-rules', 'top-ips', 'series']) {
    router.get(`/api/analyzer/waf/${kind}`, async ({ res, session, url }) => {
      if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
      const q = url.searchParams.toString();
      const r = await analyzerApi(`/api/waf/${kind}${q ? '?' + q : ''}`);
      if (!r) return send(res, 200, { reachable: false });
      return send(res, 200, { reachable: true, ...r.data });
    });
  }

  /**
   * Purge WAF events, filtered or total. Irreversible, so it follows the same
   * rule as clearing the alert log or the dashboard's own event log: admin
   * only, regardless of whether a filter narrows the scope.
   */
  router.post('/api/analyzer/waf/clear', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const q = new URLSearchParams();
    if (body.vhost)    q.set('vhost', body.vhost);
    if (body.severity) q.set('severity', body.severity);
    if (body.blocked !== undefined && body.blocked !== '') q.set('blocked', body.blocked);
    const r = await analyzerApi('/api/waf/clear' + (q.toString() ? '?' + q : ''), 'POST');
    if (r?.data?.deleted) logEvent('analyzer.waf_clear', { count: r.data.deleted, by: session.username });
    return send(res, 200, r?.data || { deleted: 0 });
  });

  // ── Regles : catalogue, activation/desactivation, regles personnalisees ──
  router.get('/api/analyzer/rules', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const r = await analyzerApi('/api/rules');
    if (!r) return send(res, 200, { reachable: false, builtins: [], custom: [] });
    return send(res, 200, { reachable: true, ...r.data });
  });

  /** Enable/disable one built-in rule (bruteforce, scan, flood, scraping, volumetric, country_traffic). */
  router.post('/api/analyzer/rules/toggle', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.key) return httpLib.badRequest(res, 'key required');
    const r = await analyzerApi(
      `/api/rules/toggle?key=${encodeURIComponent(body.key)}&enable=${body.enable ? '1' : '0'}`, 'POST');
    if (r?.data?.ok) logEvent('analyzer.rule_toggle', { key: body.key, enable: !!body.enable, by: session.username });
    return send(res, r?.status || 200, r?.data || { ok: false });
  });

  /**
   * "Blocklist a la CrowdSec" par regle (v12.50.0) : threshold/fenetre/
   * remediation/duree de remediation d UNE regle integree — voir
   * nginx-analyzer/lib/rules-manager.js#setBlocklistConfig(). Une regle
   * personnalisee (id >= 100) porte deja ses propres champs blocklist_* dans
   * son YAML (voir /api/analyzer/rules/custom ci-dessous), donc aucune route
   * dediee n est necessaire pour elle.
   */
  router.post('/api/analyzer/rules/blocklist', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const key = new URL(req.url, 'http://localhost').searchParams.get('key');
    if (!key) return httpLib.badRequest(res, 'key required');
    const body = await parseBody(req);
    const r = await analyzerApiJson(`/api/rules/blocklist?key=${encodeURIComponent(key)}`, 'POST', {
      threshold: body.threshold, windowMinutes: body.windowMinutes,
      remediation: body.remediation === true, remediationMinutes: body.remediationMinutes,
      remediationType: body.remediationType,
    });
    if (!r) return send(res, 200, { ok: false, errors: ['Analyzer injoignable'] });
    if (r.data?.ok) logEvent('analyzer.rule_blocklist_config', { key, ...body, by: session.username });
    return send(res, r.status, r.data || { ok: false, errors: ['Reponse invalide'] });
  });

  /** Raw YAML of the custom rules, for the editor's textarea. */
  router.get('/api/analyzer/rules/custom', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const r = await analyzerApi('/api/rules/custom');
    if (!r) return send(res, 200, { reachable: false, yaml: '', errors: [] });
    return send(res, 200, { reachable: true, ...r.data });
  });

  /** Replace the custom rules. Rejected wholesale on any syntax/validation error — never a partial apply. */
  router.post('/api/analyzer/rules/custom', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const r = await analyzerApiJson('/api/rules/custom', 'PUT', { yaml: body.yaml || '' });
    if (!r) return send(res, 200, { ok: false, errors: ['Analyzer injoignable'] });
    if (r.data?.ok) logEvent('analyzer.rules_custom_update', { count: r.data.count, by: session.username });
    return send(res, r.status, r.data || { ok: false, errors: ['Reponse invalide'] });
  });

  router.get('/api/analyzer/baseline', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const r = await analyzerApi('/api/baseline');
    if (!r) return send(res, 200, { reachable: false });
    return send(res, 200, { reachable: true, ...r.data });
  });

  // v12.68.0 : ce que la baseline a appris — resume par cle, puis profil des 168 creneaux.
  router.get('/api/analyzer/baseline/keys', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const type = url.searchParams.get('type') === 'country' ? 'country' : 'vhost';
    const r = await analyzerApi(`/api/baseline/keys?type=${type}`);
    if (!r) return send(res, 200, { reachable: false, keys: [] });
    return send(res, 200, { reachable: true, ...r.data });
  });

  router.get('/api/analyzer/baseline/profile', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const type = url.searchParams.get('type') === 'country' ? 'country' : 'vhost';
    const key = String(url.searchParams.get('key') || '');
    if (!key || key.length > 253) return httpLib.badRequest(res, 'key required');
    const r = await analyzerApi(`/api/baseline/profile?type=${type}&key=${encodeURIComponent(key)}`);
    if (!r) return send(res, 200, { reachable: false });
    return send(res, 200, { reachable: true, ...r.data });
  });

  /** Mark an hour as normal so a legitimate spike stops skewing the baseline. */
  router.post('/api/analyzer/baseline/exclude', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.vhost || !body.hour) return httpLib.badRequest(res, 'vhost and hour required');
    const r = await analyzerApi(
      `/api/baseline/exclude?vhost=${encodeURIComponent(body.vhost)}&hour=${encodeURIComponent(body.hour)}`,
      'POST');
    logEvent('analyzer.baseline_exclude', { vhost: body.vhost, hour: body.hour, by: session.username });
    return send(res, 200, r?.data || { ok: false });
  });

  // Same pair, for the country-level baseline (alerte de trafic inhabituel
  // par pays) — a separate engine instance in the analyzer, same shape.
  router.get('/api/analyzer/baseline/country', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const r = await analyzerApi('/api/baseline/country');
    if (!r) return send(res, 200, { reachable: false });
    return send(res, 200, { reachable: true, ...r.data });
  });

  router.post('/api/analyzer/baseline/country/exclude', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!body.country || !body.hour) return httpLib.badRequest(res, 'country and hour required');
    const r = await analyzerApi(
      `/api/baseline/country/exclude?country=${encodeURIComponent(body.country)}&hour=${encodeURIComponent(body.hour)}`,
      'POST');
    logEvent('analyzer.baseline_country_exclude', { country: body.country, hour: body.hour, by: session.username });
    return send(res, 200, r?.data || { ok: false });
  });

  for (const [action, fn] of [['start', startAnalyzer], ['stop', stopAnalyzer]]) {
    router.post(`/api/analyzer/container/${action}`, async ({ res, session }) => {
      if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
      const c = getAnalyzerCfg();
      if (!c?.enable) return httpLib.badRequest(res, 'Analyzer not enabled');
      try {
        if (action === 'start') await pullAnalyzerImage(c);
        const result = await fn(c);
        logEvent(`analyzer.${action}`, `Analyzer container ${action}ed`);
        return send(res, 200, result);
      } catch (e) { return httpLib.serverError(res, e); }
    });
  }

  /** Same shape as certbot's/geoipupdate's/error-pages' own image/update. */
  router.post('/api/analyzer/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const c = getAnalyzerCfg();
    if (!c?.enable) return httpLib.badRequest(res, 'Analyzer not enabled');
    const image = c.container_image || cfg.ANALYZER_DEFAULT_IMAGE;
    const result = await docker.pullAndCheckUpdate(image);
    if (!result.ok) return send(res, 200, { ok: false, error: result.error });
    let recreated = false;
    if (result.updated) {
      const status = await analyzerStatus();
      if (status.exists) {
        try { await startAnalyzer(c); recreated = true; }
        catch (e) { return send(res, 200, { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message }); }
      }
    }
    logEvent('analyzer.image_update', `Image ${image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });
}

module.exports = {
  register, startAlertPolling, pollAlerts, pushVhostRules, buildVhostRulesMap,
  getAnalyzerCfg, loadAnalyzerConfig, analyzerStatus, analyzerApi, analyzerApiJson,
  startAnalyzer, stopAnalyzer, restartAnalyzer, ensureContainerAtBoot,
};
