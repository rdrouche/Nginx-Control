'use strict';
/**
 * GoAccess — one analytics container per log source.
 *
 * Each vhost log gets its own `ngx-goaccess-<id>` container running in
 * real-time HTML mode. The dashboard owns their lifecycle and proxies both the
 * generated report and the WebSocket that keeps it live.
 *
 * Persistence is the subtle part. GoAccess writes its database on SIGTERM, not
 * while running, and needs three flags together:
 *
 *   --db-path=/db   where to keep it
 *   --persist       write it out on exit
 *   --restore       read it back on start (only when files already exist,
 *                   otherwise the first run errors out)
 *
 * The log file is passed with --log-file rather than as a positional argument:
 * only then does GoAccess track its offset across restarts instead of
 * re-parsing everything.
 *
 * Bind-mount sources are built from HOST_GOACCESS directly. Deriving them from
 * the in-container path produced directories the daemon could not find, so it
 * silently created empty ones and every statistic was lost on restart.
 */

const fs   = require('fs');
const path = require('path');
const http = require('http');
const net  = require('net');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');

const { PERMS, hasPerm, roleHasPerm, parseCookies, validateSession } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;
const { safeReadDir, safeStat } = require('../lib/fs-tree');
const { parseFlatYaml } = require('../lib/simple-yaml');

// Etat du telechargement de l image, partage entre le pull et la route status.
let GOACCESS_IMAGE_STATUS = 'unknown';   // 'pulling' | 'ready' | 'error'
let GOACCESS_IMAGE_ERROR  = '';

const {
  GOACCESS_CONTAINER_PREFIX,
  DIR_GOACCESS, DIR_GOACCESS_DB, DIR_GOACCESS_CONF,
  HOST_GOACCESS, HOST_LOGS, DIR_LOGS, NGINX_NETWORK,
} = cfg;

/**
 * Effective GoAccess settings: goaccess.yml overlaid on the env-derived
 * defaults (GOACCESS_IMAGE/GOACCESS_LOG_FORMAT/GOACCESS_REFRESH), which now
 * act only as a fallback — same rule as git.yml/crowdsec.yml. DIR_GOACCESS
 * stays env-only: it is a path inside THIS container (bind-mount target),
 * the same category as DIR_SITES/DIR_CONF, not a behaviour setting.
 *
 * container_image and refresh_seconds are live: read fresh on every call, so
 * a change from the Configuration page takes effect on the next request
 * without restarting the dashboard. log_format is carried through for
 * parity with the env var it replaces (GOACCESS_LOG_FORMAT) — neither one is
 * currently read anywhere else in this file; both exist for a future format
 * override that isn't wired up yet.
 */
function getGoaccessCfg() {
  const fromEnv = {
    image: cfg.GOACCESS_IMAGE, logFormat: cfg.GOACCESS_LOG_FORMAT, refreshSec: cfg.GOACCESS_REFRESH_SEC,
  };
  if (!fs.existsSync(cfg.GOACCESS_CONFIG_FILE)) return fromEnv;
  try {
    const raw = fs.readFileSync(cfg.GOACCESS_CONFIG_FILE, 'utf8');
    // Fix (audit finding MISC-10): shared parser strips a trailing inline
    // comment — see lib/simple-yaml.js.
    const y = parseFlatYaml(raw);
    const refreshFromYaml = parseInt(y.refresh_seconds, 10);
    return {
      image:      y.container_image || fromEnv.image,
      logFormat:  y.log_format      || fromEnv.logFormat,
      refreshSec: Number.isFinite(refreshFromYaml) && refreshFromYaml > 0 ? refreshFromYaml : fromEnv.refreshSec,
    };
  } catch (e) {
    console.warn('[goaccess] goaccess.yml load error, falling back to env:', e.message);
    return fromEnv;
  }
}

function goAccessConfigured() { return !!getGoaccessCfg().image; }

function goAccessContainerName(sourceId) {
  return GOACCESS_CONTAINER_PREFIX + sourceId.toLowerCase().replace(/[^a-z0-9-]/g, '-');
}

/** Detect log format by peeking at first line of log file */
function detectLogFormat(logPath) {
  try {
    const fd  = fs.openSync(logPath, 'r');
    const buf = Buffer.alloc(2048);
    const n   = fs.readSync(fd, buf, 0, 2048, 0);
    fs.closeSync(fd);
    const firstLine = buf.slice(0, n).toString('utf8').split('\n').find(l => l.trim());
    if (!firstLine) return 'vhost';
    // combined_vhost starts with hostname (has dot, not an IP)
    // combined starts with IP address (digits.digits.digits.digits)
    const firstToken = firstLine.split(' ')[0];
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(firstToken) || /^[0-9a-f:]+$/i.test(firstToken);
    return isIp ? 'combined' : 'vhost';
  } catch { return 'vhost'; }
}

/** Ensure GoAccess conf files exist — one per log format */
function ensureGoAccessConf(type) {
  fs.mkdirSync(DIR_GOACCESS_CONF, { recursive: true });

  // Note: real-time-html and ws-url are CLI args only — NOT in conf
  // GoAccess 1.10.x fails when both conf file and CLI args specify real-time-html
  const COMMON = [
    'date-format %d/%b/%Y',
    'time-format %H:%M:%S',
  ];

  // combined_vhost: "vhost ip - user [date:time tz] ..."
  // example: forge.rdr-it.com 1.2.3.4 - - [18/May/2026:16:39:00 +0000] "GET /" 200 1234 "-" "UA"
  const confVhost = path.join(DIR_GOACCESS_CONF, 'goaccess-vhost.conf');
  if (!fs.existsSync(confVhost)) {
    fs.writeFileSync(confVhost, [
      '# nginx combined_vhost: vhost ip - user [date:time tz] "req" status bytes "ref" "ua"',
      'log-format %v %h %^ %^ [%d:%t %^] "%r" %s %b "%R" "%u"',
      ...COMMON,
      '', // trailing newline — required by GoAccess parser
    ].join('\n'), 'utf8');
  }

  // combined (standard): "ip - user [date:time tz] ..."
  // example: 1.2.3.4 - - [18/May/2026:16:39:00 +0000] "GET /" 200 1234 "-" "UA"
  const confCombined = path.join(DIR_GOACCESS_CONF, 'goaccess-combined.conf');
  if (!fs.existsSync(confCombined)) {
    fs.writeFileSync(confCombined, [
      '# nginx combined: ip - user [date:time tz] "req" status bytes "ref" "ua"',
      'log-format %h %^ %^ [%d:%t %^] "%r" %s %b "%R" "%u"',
      ...COMMON,
      '', // trailing newline — required by GoAccess parser
    ].join('\n'), 'utf8');
  }

  return type === 'combined' ? confCombined : confVhost;
}

async function pullGoAccessImage() {
  const image = getGoaccessCfg().image;
  if (!image) { GOACCESS_IMAGE_STATUS = 'error'; GOACCESS_IMAGE_ERROR = 'GOACCESS_IMAGE not set'; return; }
  GOACCESS_IMAGE_STATUS = 'pulling';
  console.log(`[goaccess] Pulling image: ${image}`);
  const r = await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  if (r.status === 200 || r.status === 204) {
    GOACCESS_IMAGE_STATUS = 'ready';
    console.log(`[goaccess] Image ready: ${image}`);
  } else {
    // Check if image already exists locally
    const inspect = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
    if (inspect.status === 200) {
      GOACCESS_IMAGE_STATUS = 'ready';
      console.log(`[goaccess] Image already present: ${image}`);
    } else {
      GOACCESS_IMAGE_STATUS = 'error';
      GOACCESS_IMAGE_ERROR  = `Pull failed (HTTP ${r.status})`;
      console.warn(`[goaccess] Image pull failed: ${GOACCESS_IMAGE_ERROR}`);
    }
  }
}

/** List all .access.log and .log files in DIR_LOGS, grouped by vhost */
function listGoAccessSources() {
  const files = safeReadDir(DIR_LOGS);
  const sources = [];

  // Dedicated vhost files: example.com.access.log or example.com.log
  const vhostFiles = files.filter(f =>
    f.endsWith('.access.log') ||
    (f.endsWith('.log') && !['access.log','error.log','stream.log','vhosts_access.log'].includes(f))
  );
  for (const f of vhostFiles) {
    const vhost = f.replace(/\.access\.log$/, '').replace(/\.log$/, '');
    const fp = path.join(DIR_LOGS, f);
    const stat = safeStat(fp);
    sources.push({ id: vhost.replace(/[^a-zA-Z0-9-]/g, '-'), vhost, file: f, path: fp, size: stat?.size || 0, type: 'vhost' });
  }

  // Combined vhosts_access.log (consolidated view)
  const consolidated = path.join(DIR_LOGS, 'vhosts_access.log');
  if (fs.existsSync(consolidated)) {
    const stat = safeStat(consolidated);
    sources.push({ id: 'all', vhost: 'Tous les vhosts', file: 'vhosts_access.log', path: consolidated, size: stat?.size || 0, type: 'consolidated' });
  }

  // Also include access.log if present
  const accessLog = path.join(DIR_LOGS, 'access.log');
  if (fs.existsSync(accessLog)) {
    const stat = safeStat(accessLog);
    sources.push({ id: 'access', vhost: 'access.log', file: 'access.log', path: accessLog, size: stat?.size || 0, type: 'default' });
  }

  return sources;
}

async function getGoAccessContainerStatus(sourceId) {
  const name = goAccessContainerName(sourceId);
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  if (r.status === 404) return { running: false, exists: false, name };
  if (r.status === 200) return {
    running: r.body?.State?.Running || false,
    exists:  true,
    name,
    id:      r.body?.Id,
    status:  r.body?.State?.Status,
    started: r.body?.State?.StartedAt,
  };
  return { running: false, exists: false, name, error: r.body };
}

/**
 * Fix (audit report, Basse/Divers dashboard, "Compose : HOST_LOGS=./logs est
 * un chemin relatif, donc la creation du conteneur GoAccess echoue sans
 * .env"): Docker's bind-mount API requires an ABSOLUTE path on the host side
 * — HOST_LOGS/HOST_GOACCESS exist specifically because the dashboard itself
 * only ever sees the CONTAINER-side path, so it has no way to derive the
 * host-side absolute path a bind mount needs unless the operator provides
 * it (see lib/system-info.js's own description of these two settings). A
 * relative default (as shipped in the example docker-compose.yml, meant to
 * be overridden per deployment) reaches Docker's own API verbatim and fails
 * with an opaque low-level error there — this checks it up front and fails
 * with a message that names the actual missing piece of configuration.
 */
function requireAbsoluteHostPath(value, envName) {
  if (!path.isAbsolute(value)) {
    throw { error: `${envName} must be an absolute host path, got "${value}" — ` +
      `Docker's bind-mount API needs the real path on the HOST filesystem, which this ` +
      `container cannot infer on its own. Set ${envName} (and its sibling HOST_LOGS/` +
      `HOST_GOACCESS) to an absolute path in your .env, matching where these directories ` +
      `actually live on the Docker host — see README.md, "Variables d'environnement".` };
  }
}

async function startGoAccessContainer(sourceId, logPath, opts = {}) {
  requireAbsoluteHostPath(HOST_LOGS, 'HOST_LOGS');
  requireAbsoluteHostPath(HOST_GOACCESS, 'HOST_GOACCESS');
  const name     = goAccessContainerName(sourceId);
  const dbPath   = path.join(DIR_GOACCESS_DB, sourceId);
  const rptPath  = path.join(DIR_GOACCESS, 'reports', sourceId);
  fs.mkdirSync(dbPath,  { recursive: true });
  fs.mkdirSync(rptPath, { recursive: true });
  const logFormat  = detectLogFormat(logPath);
  const confFile   = ensureGoAccessConf(logFormat);
  const confInContainer = '/etc/goaccess/goaccess.conf';
  console.log(`[goaccess] ${path.basename(logPath)} → format: ${logFormat} → conf: ${path.basename(confFile)}`);

  // Remove existing stopped container if present
  const existing = await getGoAccessContainerStatus(sourceId);
  if (existing.exists && !existing.running) {
    await dockerCall('DELETE', `/containers/${encodeURIComponent(existing.id)}?force=1`);
  }
  if (existing.running && !opts.force) return { ok: true, already: true, name };

  const createBody = {
    name,
    Image: getGoaccessCfg().image,
    Cmd: (() => {
      // Pass ALL options as CLI args — avoids GoAccess 1.10.x conf parsing bugs
      const isVhost = logFormat === 'vhost';
      const logFmt  = isVhost
        ? '%v %h %^ %^ [%d:%t %^] "%r" %s %b "%R" "%u"'
        : '%h %^ %^ [%d:%t %^] "%r" %s %b "%R" "%u"';
      const args = [
        '--log-file=/nginx/logs/' + path.basename(logPath),  // use -f flag for proper --restore offset tracking
        '--log-format=' + logFmt,
        '--date-format=%d/%b/%Y',
        '--time-format=%H:%M:%S',
        '--output=/report/report.html',
        '--real-time-html',
        '--port=7890',
        '--no-global-config',
      ];
      // Persistence (DB) — enabled by default, disable with persist:false in startGoAccessContainer options
      if (opts.persist !== false) {
        args.push('--db-path=/db');
        args.push('--persist');   // write data to disk on exit
        // --restore only if DB files already exist — avoids error on first run
        const dbDir = path.join(DIR_GOACCESS, 'db', sourceId);
        const dbHasFiles = fs.existsSync(dbDir) && fs.readdirSync(dbDir).some(f => !f.startsWith('.'));
        if (dbHasFiles) args.push('--restore');
      }
      // GeoIP — add if DB files are mounted
      if (opts.geoip) {
        args.push('--geoip-database=/geoip/GeoLite2-City.mmdb');
      }
      return args;
    })(),
    HostConfig: {
      RestartPolicy: { Name: 'unless-stopped' },
      // Use HOST_* paths — Docker socket needs host-side absolute paths
      Binds: (() => {
        // Use HOST_GOACCESS as the base for host-side paths (Docker needs absolute host paths)
        const hostDbPath  = path.join(HOST_GOACCESS, 'db',      sourceId);
        const hostRptPath = path.join(HOST_GOACCESS, 'reports', sourceId);
        const binds = [
          `${HOST_LOGS}:/nginx/logs:ro`,
          `${hostRptPath}:/report`,
        ];
        if (opts.persist !== false) binds.push(`${hostDbPath}:/db`);
        if (opts.geoip) binds.push(`${process.env.HOST_GEOIP || path.join(HOST_GOACCESS, '../geoip_data')}:/geoip:ro`);
        return binds;
      })(),
      // Same network as dashboard — container reachable by name via Docker DNS
      NetworkMode: NGINX_NETWORK,
    },
  };
  const created = await dockerCall('POST', '/containers/create?name=' + encodeURIComponent(name), createBody);
  if (created.status !== 201) throw { error: `Cannot create GoAccess container: ${JSON.stringify(created.body)}` };
  await dockerCall('POST', `/containers/${created.body.Id}/start`);
  return { ok: true, name, id: created.body.Id };
}

async function stopGoAccessContainer(sourceId) {
  clearGoAccessProxyCache(sourceId);
  const status = await getGoAccessContainerStatus(sourceId);
  if (!status.exists) return { ok: true, notFound: true };
  if (status.running) await dockerCall('POST', `/containers/${encodeURIComponent(status.id)}/stop`);
  await dockerCall('DELETE', `/containers/${encodeURIComponent(status.id)}?force=1`);
  return { ok: true, name: status.name };
}

/** Restart GoAccess container gracefully (preserves data in mounted volumes) */
async function restartGoAccessContainer(sourceId) {
  const name = `${GOACCESS_CONTAINER_PREFIX}${sourceId}`;
  // docker restart sends SIGTERM then SIGKILL after timeout — GoAccess flushes DB on SIGTERM
  const r = await dockerCall('POST', `/containers/${encodeURIComponent(name)}/restart?t=10`);
  if (r.status !== 204 && r.status !== 304) {
    throw new Error(`Restart failed: HTTP ${r.status}`);
  }
  return { ok: true, name };
}

/** Read the generated HTML report for a source */
function readGoAccessReport(sourceId) {
  const rptFile = path.join(DIR_GOACCESS, 'reports', sourceId, 'report.html');
  if (!fs.existsSync(rptFile)) return null;
  const stat = safeStat(rptFile);
  const html = fs.readFileSync(rptFile, 'utf8');
  // Note: no meta refresh — WebSocket handles real-time updates
  // Note: WebSocket URL is rewritten in the /api/goaccess/report route (not here)
  return { html, mtime: stat?.mtime?.toISOString(), size: stat?.size };
}

/**
 * Builds the inline <script> injected into a GoAccess report page that
 * redirects its hard-coded `:7890` WebSocket connection attempt through this
 * dashboard's own proxy (see the /api/goaccess/report route).
 *
 * Fix (audit report, Basse/Divers dashboard, "sourceId (GoAccess) est
 * injecte dans du JS inline"): `sourceId` is a raw query-string parameter
 * (`url.searchParams.get('sourceId')`), previously concatenated DIRECTLY
 * into this script's JS string literal. A value such as
 * `x'+alert(document.cookie)+'` closed the literal early and ran arbitrary
 * script in the dashboard's own origin for anyone who could be made to open
 * a crafted `/api/goaccess/report?sourceId=...` link — a reflected-XSS
 * primitive against an authenticated session, not merely a theoretical one.
 * `JSON.stringify()` produces a properly escaped JS string literal for ANY
 * input, which is what string interpolation into a script body always needs
 * and never had here. Extracted to its own function so this specific
 * escaping behavior can be unit-tested without a running GoAccess container.
 */
function buildWsOverrideScript(sourceId) {
  const sourceIdJs = JSON.stringify(String(sourceId));
  return '<script>\n' +
    '(function(){\n' +
    '  var _ows=window.WebSocket;\n' +
    '  window.WebSocket=function(url,p){\n' +
    '    if(url&&String(url).indexOf(":7890")!==-1){\n' +
    '      try{\n' +
    '        var u=new URL(String(url));\n' +
    '        url=(location.protocol==="https:"?"wss://":"ws://")+\n' +
    '          location.host+"/api/goaccess/ws/"+' + sourceIdJs + '+u.pathname+u.search;\n' +
    '      }catch(e){}\n' +
    '    }\n' +
    '    return p?new _ows(url,p):new _ows(url);\n' +
    '  };\n' +
    '  window.WebSocket.prototype=_ows.prototype;\n' +
    '  window.WebSocket.CONNECTING=_ows.CONNECTING;\n' +
    '  window.WebSocket.OPEN=_ows.OPEN;\n' +
    '  window.WebSocket.CLOSING=_ows.CLOSING;\n' +
    '  window.WebSocket.CLOSED=_ows.CLOSED;\n' +
    '})();\n' +
    '</script>';
}

function resolveGoAccessProxy(sourceId) {
  const status = getGoAccessContainerStatus(sourceId);
  // Docker DNS: container name resolves on shared network
  return Promise.resolve({
    host: goAccessContainerName(sourceId),
    port: 7890,
  });
}

function clearGoAccessProxyCache(sourceId) { /* no-op — no cache needed */ }

/**
 * Proxy a plain HTTP request to GoAccess (for assets: CSS, JS, fonts).
 */
function proxyGoAccessHttp(req, res, host, port, targetPath) {
  // Fix (audit finding MISC-09): this used to spread ALL inbound headers,
  // including `cookie` and `authorization` — the dashboard's own session
  // cookie / bearer token, sent verbatim to a third-party container
  // (GoAccess) that has no use for it and no business seeing it.
  const headers = { ...req.headers };
  delete headers.cookie;
  delete headers.authorization;
  headers.host = `${host}:${port}`;
  const opts = {
    hostname: host, port, method: req.method,
    path: targetPath || req.url,
    headers,
  };
  const proxy = http.request(opts, (pres) => {
    // Same origin as the dashboard (proxied under /api/goaccess/...): a
    // Set-Cookie from GoAccess would land in the dashboard's own cookie
    // jar, so it's stripped rather than passed through. See the matching
    // fix in features/godns.js.
    const respHeaders = { ...pres.headers };
    delete respHeaders['set-cookie'];
    respHeaders['content-security-policy'] = "frame-ancestors 'self'";
    respHeaders['x-frame-options'] = 'SAMEORIGIN';
    res.writeHead(pres.statusCode, respHeaders);
    pres.pipe(res, { end: true });
  });
  proxy.on('error', (e) => {
    if (!res.headersSent) res.writeHead(502).end('GoAccess proxy error: ' + e.message);
  });
  req.pipe(proxy, { end: true });
}

/**
 * Proxy a WebSocket upgrade to GoAccess.
 * Called from the 'upgrade' event on the HTTP server.
 */
function proxyGoAccessWS(req, socket, head, host, port) {
  const net = require('net');
  const upstream = net.createConnection({ host, port }, () => {
    // Extract GoAccess path+token from dashboard proxy URL
    // Dashboard: /api/goaccess/ws/{sourceId}/ws?token=xxx → GoAccess: /ws?token=xxx
    const urlObj  = new URL(req.url, 'http://localhost');
    const gaPath  = urlObj.pathname.replace(/^\/api\/goaccess\/ws\/[^\/]+/, '') || '/ws';
    const forwardPath = gaPath + (urlObj.search || '');
    upstream.write(
      'GET ' + forwardPath + ' HTTP/1.1\r\n' +
      'Host: ' + host + ':' + port + '\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Key: ' + (req.headers['sec-websocket-key'] || '') + '\r\n' +
      'Sec-WebSocket-Version: ' + (req.headers['sec-websocket-version'] || '13') + '\r\n' +
      'Origin: http://' + host + ':' + port + '\r\n' +
      '\r\n'
    );
    if (head && head.length) upstream.write(head);
  });
  upstream.on('data', (data) => socket.write(data));
  upstream.on('end',  ()     => socket.end());
  upstream.on('error', (e)   => { console.error('[goaccess-ws]', e.message); socket.end(); });
  socket.on('data',  (data) => upstream.write(data));
  socket.on('end',   ()     => upstream.end());
  socket.on('error', ()     => upstream.destroy());
}
// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.post('/api/goaccess/recreate', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body     = await parseBody(req);
    const sourceId = body.sourceId;
    const opts     = { persist: body.persist !== false, geoip: !!body.geoip };
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');
    const sources = listGoAccessSources();
    const source  = sources.find(s => s.id === sourceId);
    if (!source) return httpLib.notFound(res, 'Source not found');
    try {
      // Stop and remove existing container
      const status = await getGoAccessContainerStatus(sourceId);
      if (status.exists) {
        await dockerCall('POST',   `/containers/${encodeURIComponent(status.id)}/stop?t=10`).catch(() => {});
        // Wait for container to stop
        await new Promise(r => setTimeout(r, 2000));
        await dockerCall('DELETE', `/containers/${encodeURIComponent(status.id)}?force=1`).catch(() => {});
        await new Promise(r => setTimeout(r, 500));
      }
      // Recreate with new options (force=true bypasses already-running check)
      const result = await startGoAccessContainer(sourceId, source.path, { ...opts, force: true });
      logEvent('goaccess_recreate', `Recreated GoAccess for ${sourceId} (persist=${opts.persist}, geoip=${opts.geoip})`);
      return send(res, 200, { ok: true, ...result });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/goaccess/restart', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body     = await parseBody(req);
    const sourceId = body.sourceId;
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');
    try {
      const result = await restartGoAccessContainer(sourceId);
      logEvent('goaccess_restart', `Restarted GoAccess for ${sourceId}`);
      return send(res, 200, result);
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.get('/api/goaccess/sources', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_GOACCESS)) return httpLib.forbidden(res);
    if (!goAccessConfigured()) return send(res, 200, { configured: false });
    const sources = listGoAccessSources();
    // Add container status for each source
    const withStatus = await Promise.all(sources.map(async s => {
      const st = await getGoAccessContainerStatus(s.id).catch(() => ({ running: false, exists: false }));
      return { ...s, container: st };
    }));
    const gcfg = getGoaccessCfg();
    return send(res, 200, { configured: true, sources: withStatus, image: gcfg.image, refreshSec: gcfg.refreshSec });
  });

  router.get('/api/goaccess/image-status', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_GOACCESS)) return httpLib.forbidden(res);
    return send(res, 200, { status: GOACCESS_IMAGE_STATUS, error: GOACCESS_IMAGE_ERROR, image: getGoaccessCfg().image });
  });

  router.post('/api/goaccess/pull-image', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    pullGoAccessImage().catch(() => {});
    return send(res, 200, { message: 'Pull started', image: getGoaccessCfg().image });
  });

  router.post('/api/goaccess/start', async ({ req, res, session, url }) => {
    // Fix v12.21.1 (audit finding MISC-01): this only required VIEW_GOACCESS,
    // which the `viewer` role holds, while /recreate and /restart right below
    // both correctly require DEPLOY for the exact same class of action
    // (creating/destroying a container through the Docker socket). A viewer
    // account could create arbitrary containers with this route alone.
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    if (!goAccessConfigured()) return httpLib.badRequest(res, 'GOACCESS_IMAGE not configured');
    const body = await parseBody(req);
    const sourceId = body.sourceId;
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');
    const sources = listGoAccessSources();
    const source  = sources.find(s => s.id === sourceId);
    if (!source) return httpLib.notFound(res, 'Source not found');
    try {
      const opts = { persist: body.persist !== false, geoip: !!body.geoip };
      const result = await startGoAccessContainer(sourceId, source.path, opts);
      logEvent('goaccess.start', { sourceId, by: session.username }, 'goaccess');
      return send(res, 200, result);
    } catch(e) { return send(res, 500, { error: e.error || e.message }); }
  });

  router.get('/api/goaccess/logs', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_GOACCESS)) return httpLib.forbidden(res);
    const sourceId = url.searchParams.get('sourceId');
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');
    const status = await getGoAccessContainerStatus(sourceId).catch(() => null);
    if (!status?.exists) return httpLib.notFound(res, 'Container not found');
    const tail = url.searchParams.get('tail') || '50';
    const logsRes = await dockerCall('GET',
      `/containers/${encodeURIComponent(status.id)}/logs?stdout=1&stderr=1&tail=${tail}&timestamps=1`
    );
    // Same fix as GoDNS, certbot and deploy: demux from the raw bytes via the
    // shared, TTY-aware helper. The previous hand-rolled version stripped an
    // 8-byte frame header unconditionally, which corrupts the text whenever
    // the container is TTY-allocated (no framing at all in that case).
    let logText = '';
    if (logsRes.rawBuffer) {
      try { logText = docker.demuxToText(logsRes.rawBuffer); }
      catch { logText = String(logsRes.body || ''); }
    }
    return send(res, 200, {
      sourceId, name: goAccessContainerName(sourceId),
      status: status.status, running: status.running,
      logs: logText.trim().split('\n').filter(Boolean).slice(-100),
    });
  });

  router.post('/api/goaccess/stop', async ({ req, res, session, url }) => {
    // Fix v12.21.1 (audit finding MISC-01): same reasoning as /start above —
    // stopping/removing a container is a DEPLOY-level action everywhere else
    // in this project.
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const sourceId = body.sourceId;
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');
    try {
      const result = await stopGoAccessContainer(sourceId);
      logEvent('goaccess.stop', { sourceId, by: session.username }, 'goaccess');
      return send(res, 200, result);
    } catch(e) { return send(res, 500, { error: e.error || e.message }); }
  });

  router.addPrefix('GET', '/api/goaccess/proxy/', async ({ req, res, session, url, pathname }) => {
    // Proxy all GoAccess HTTP requests (assets: JS, CSS, fonts, etc.)
    // URL format: /api/goaccess/proxy/{sourceId}/{...asset path}
    const parts    = pathname.slice('/api/goaccess/proxy/'.length).split('/');
    const sourceId = parts[0];
    const assetPath = '/' + parts.slice(1).join('/') + (url.search || '');
    if (!hasPerm(session, PERMS.VIEW_GOACCESS)) return httpLib.forbidden(res);
    const proxy = await resolveGoAccessProxy(sourceId);
    if (!proxy) {
      res.writeHead(503); return res.end('GoAccess not running');
    }
    return proxyGoAccessHttp(req, res, proxy.host, proxy.port, assetPath);
  });

  router.get('/api/goaccess/report', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_GOACCESS)) return httpLib.forbidden(res);
    const sourceId = url.searchParams.get('sourceId');
    if (!sourceId) return httpLib.badRequest(res, 'sourceId required');

    const st = await getGoAccessContainerStatus(sourceId).catch(() => ({}));

    if (!st.running) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<!DOCTYPE html><html><body style="font-family:monospace;background:#0a0b0d;color:#9ba3b8;padding:40px;text-align:center">
        <p style="font-size:16px;margin-bottom:12px">GoAccess stopped or not yet started.</p>
        <p style="font-size:12px;color:#5a6278">Start GoAccess then refresh.</p>
      </body></html>`);
    }

    // GoAccess --real-time-html only accepts WebSocket — not plain HTTP GET
    // Read the report HTML from disk (GoAccess writes it via --output)
    const report = readGoAccessReport(sourceId);
    if (!report) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<!DOCTYPE html><html><body style="font-family:monospace;background:#0a0b0d;color:#9ba3b8;padding:40px;text-align:center">' +
        '<p>GoAccess started — generating report, please wait...</p>' +
        '<meta http-equiv="refresh" content="3">' +
        '</body></html>');
    }

    const wsOverride = buildWsOverrideScript(sourceId);

    let html = httpLib.injectBeforeFirstScript(report.html, wsOverride, 'GoAccess WebSocket override');

    res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache',
      'X-Report-Mtime': report.mtime || '' });
    return res.end(html);
  });
}

/**
 * WebSocket upgrade for the live report. Registered on the HTTP server rather
 * than the router: an upgrade is not a normal request, and EventSource-style
 * query auth does not apply — the browser sends the session cookie.
 */
async function handleUpgrade(req, socket, head) {
  const url = new URL(req.url, 'http://localhost');
  const m = url.pathname.match(/^\/api\/goaccess\/ws\/([^/]+)/);
  if (!m) { socket.destroy(); return; }
  const sourceId = m[1];

  const session = validateSession(parseCookies(req).ngx_session || '');
  if (!session || !roleHasPerm(session.role, PERMS.VIEW_GOACCESS)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy(); return;
  }

  const proxy = await resolveGoAccessProxy(sourceId).catch(() => null);
  if (!proxy) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy(); return;
  }
  proxyGoAccessWS(req, socket, head, proxy.host, proxy.port);
}

module.exports = {
  register, handleUpgrade,
  getGoaccessCfg,
  goAccessConfigured, goAccessContainerName, detectLogFormat, ensureGoAccessConf,
  pullGoAccessImage, listGoAccessSources, getGoAccessContainerStatus,
  startGoAccessContainer, stopGoAccessContainer, restartGoAccessContainer,
  readGoAccessReport, resolveGoAccessProxy, clearGoAccessProxyCache,
  proxyGoAccessHttp, proxyGoAccessWS, buildWsOverrideScript,
  requireAbsoluteHostPath,
};
