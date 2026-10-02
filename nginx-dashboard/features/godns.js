'use strict';
/**
 * GoDNS — dynamic DNS updates.
 *
 * The dashboard owns the container lifecycle: pull, start, stop, restart,
 * update. GoDNS reads its own configuration from a file the dashboard also
 * edits, in YAML or JSON.
 *
 * Two details the upstream image imposes:
 *
 *  - JSON is the default and is read from /config.json with no extra flag;
 *    YAML requires CONFIG=/config.yaml in the environment.
 *  - The bind-mount source must be a HOST path. The dashboard sees the file at
 *    /config/…, the daemon does not, so the two are kept apart:
 *    `internalPath` for reading and writing, `hostPath` for the mount.
 *
 * There is no REST API upstream, so status is reconstructed by parsing the
 * container logs: public IP, provider, and per-domain state.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const secrets = require('../lib/secrets');
const events  = require('../lib/events');
const { parseFlatYaml } = require('../lib/simple-yaml');
const { checkPublicIp } = require('../lib/ip-check');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { maskSecretsInConfig, unmaskSecrets } = secrets;
const { logEvent } = events;
const { GODNS_CONFIG_FILE, USERS_FILE, NGINX_NETWORK, GODNS_IP_CHECK, GODNS_IP_CHECK_URLS } = cfg;

let GODNS_CFG = null;

function loadGoDNSConfig() {
  if (!fs.existsSync(GODNS_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(GODNS_CONFIG_FILE, 'utf8');
    // Fix (audit finding MISC-10): shared parser strips a trailing inline
    // comment (`enable: false  # pause` used to parse as "false # pause",
    // which is truthy) — see lib/simple-yaml.js.
    const cfg = parseFlatYaml(raw);
    cfg.enable = cfg.enable === 'true' || cfg.enable === '1';
    cfg.port   = parseInt(cfg.port) || 9000;
    return cfg;
  } catch(e) {
    console.warn('[godns] Config load error:', e.message);
    return null;
  }
}

function getGoDNSCfg() {
  GODNS_CFG = loadGoDNSConfig();
  return GODNS_CFG;
}

function getGoDNSConfigFilePath(cfg) {
  const fmt           = (cfg.config_format || 'yaml').toLowerCase();
  const ext           = fmt === 'json' ? 'json' : 'yaml';
  const fileName      = `godns.config.${ext}`;
  // internalPath: path inside the dashboard container — used for fs.existsSync / read / write
  const internalPath  = path.join(path.dirname(USERS_FILE), fileName);
  // hostPath: absolute path on the HOST — used only for Docker bind mount when creating GoDNS container
  const hostDir       = (cfg.config_host_path || '').trim().replace(/\r/g, '').replace(/\/$/, '');
  const hostPath      = hostDir ? `${hostDir}/${fileName}` : internalPath;
  // containerPath: where GoDNS expects its config (at root of its container)
  const containerPath = `/config.${ext}`;
  return { internalPath, hostPath, containerPath, format: fmt };
}

async function godnsContainerStatus() {
  const cfg  = getGoDNSCfg();
  const name = (cfg && cfg.container_name) || 'godns';
  const r    = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  // status 0 : le demon est injoignable — a distinguer d un conteneur absent.
  if (r.status === 0)   return { exists: false, running: false, name, dockerUnavailable: true, error: r.error };
  if (r.status === 404) return { exists: false, running: false, name };
  if (r.status !== 200) return { exists: false, running: false, name, error: `HTTP ${r.status}` };
  return {
    exists:  true,
    running: r.body?.State?.Running === true,
    status:  r.body?.State?.Status || 'unknown',
    image:   r.body?.Config?.Image || '',
    started: r.body?.State?.StartedAt || '',
    name,
    id:      r.body?.Id || '',
  };
}

async function godnsStartContainer(cfg) {
  const name       = cfg.container_name || 'godns';
  const image      = cfg.container_image || 'timothyye/godns:latest';
  const port       = cfg.port || 9000;
  const cfgFile    = getGoDNSConfigFilePath(cfg);

  // Ensure config file exists
  if (!fs.existsSync(cfgFile.internalPath)) {
    throw new Error(`GoDNS config file not found: ${cfgFile.internalPath} (host: ${cfgFile.hostPath})`);
  }

  // Stop + remove existing
  await dockerCall('POST', `/containers/${encodeURIComponent(name)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`).catch(() => {});

  // GoDNS config loading:
  // - JSON: mount as /config.json (default, no extra env needed)
  // - YAML: mount as /config.yaml + set CONFIG=/config.yaml env var
  const env = cfgFile.format === 'yaml' ? [`CONFIG=${cfgFile.containerPath}`] : [];

  // Optional: expose web panel port on host
  const webPanelEnabled  = cfg.web_panel_enabled === 'true' || cfg.web_panel_enabled === true;
  const externalPort     = parseInt(cfg.web_panel_external_port) || port;
  const portBindings     = webPanelEnabled
    ? { [`${port}/tcp`]: [{ HostIp: '0.0.0.0', HostPort: String(externalPort) }] }
    : {};
  const exposedPorts     = webPanelEnabled ? { [`${port}/tcp`]: {} } : {};

  const body = {
    Image: image,
    Env: env,
    HostConfig: {
      Binds: [`${cfgFile.hostPath}:${cfgFile.containerPath}:ro`],
      RestartPolicy: { Name: 'unless-stopped' },
      NetworkMode:   NGINX_NETWORK || 'nginx-net',
      PortBindings:  portBindings,
    },
    ExposedPorts: exposedPorts,
    Labels: { 'managed-by': 'nginx-dashboard' },
  };

  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(name)}`, body);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);

  const start = await dockerCall('POST', `/containers/${encodeURIComponent(name)}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  return true;
}

async function godnsStopContainer(cfg) {
  const name = (cfg && cfg.container_name) || 'godns';
  await dockerCall('POST', `/containers/${encodeURIComponent(name)}/stop`);
  return true;
}

async function godnsGetLogs(cfg) {
  const name = (cfg && cfg.container_name) || 'godns';
  const r    = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/logs?stdout=1&stderr=1&tail=100&timestamps=1`);
  // Demuxing was reimplemented here by hand, without the guard against a
  // TTY-allocated container: when Tty:true, Docker sends the log stream
  // completely unframed, and blindly reading an 8-byte header off the front
  // of real log text corrupts every line — the dashboard showed nothing while
  // `docker logs` on the same container looked perfectly fine. Reusing the
  // shared demuxToText() keeps this in one place and handles both cases.
  if (!r.rawBuffer) return typeof r.body === 'string' ? r.body : '';
  return docker.demuxToText(r.rawBuffer);
}

async function godnsPullImage(cfg) {
  const image = (cfg && cfg.container_image) || 'timothyye/godns:latest';
  console.log(`[godns] Pulling image: ${image}`);
  await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  const inspect = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
  return inspect.status === 200;
}

/** Parse GoDNS logs to extract status info */
function parseGoDNSLogs(rawLogs) {
  const lines   = rawLogs.split('\n').filter(Boolean);
  let   publicIP  = null;
  let   provider  = null;
  let   lastUpdate = null;
  const domains  = {};
  const errors   = [];

  for (const line of lines) {
    // Strip docker timestamp prefix [godns] 2026-...Z
    const clean = line.replace(/^\[godns\]\s+\S+\s+/, '').trim();
    const lineTime = clean.match(/time="([^"]+)"/)?.[1] || null;

    // Provider
    const mProv = clean.match(/Creating DNS handler with provider: ([^\s"]+)/);
    if (mProv) provider = mProv[1];

    // New IP detected
    const mIP = clean.match(/new IP: ([\d.a-fA-F:]+)/);
    if (mIP && mIP[1] !== '<nil>') { publicIP = mIP[1]; if (lineTime) lastUpdate = lineTime; }

    // Record OK
    const mOK = clean.match(/Record OK: ([\w.*-]+) - ([\d.a-fA-F:]+)/);
    if (mOK) { domains[mOK[1]] = { status: 'ok', ip: mOK[2], time: lineTime }; if (lineTime) lastUpdate = lineTime; }

    // Updating
    const mUp = clean.match(/Updating domain: ([\w.*-]+), current IP: ([^,]+), new IP: ([\d.a-fA-F:]+)/);
    if (mUp) {
      publicIP = mUp[3] !== '<nil>' ? mUp[3] : publicIP;
      domains[mUp[1]] = { status: 'updating', currentIP: mUp[2] === '<nil>' ? null : mUp[2], newIP: mUp[3], time: lineTime };
      if (lineTime) lastUpdate = lineTime;
    }

    // Fix (retour utilisateur v12.40.0, page Status vide malgre des journaux
    // qui montrent une activite continue) : en regime stable (IP publique
    // inchangee depuis le dernier cycle, le cas le plus frequent en usage
    // normal), GoDNS n emet ni "new IP", ni "Record OK", ni "Updating
    // domain" — seulement cette ligne, une fois par domaine et par cycle.
    // Aucune des regles ci-dessus ne la reconnaissait : IP publique,
    // derniere MAJ et tableau des domaines restaient tous vides alors que
    // GoDNS tournait parfaitement.
    const mSkip = clean.match(/Domain ([\w.*-]+): IP is the same as cached one \(([\d.a-fA-F:]+)\)\. Skip update\./);
    if (mSkip) {
      publicIP = publicIP || mSkip[2];
      domains[mSkip[1]] = { status: 'ok', ip: mSkip[2], time: lineTime };
      if (lineTime) lastUpdate = lineTime;
    }

    // Errors
    const mErr = clean.match(/level=(error|fatal) msg="([^"]+)"/);
    if (mErr) errors.push({ level: mErr[1], msg: mErr[2] });
  }

  return { publicIP, provider, lastUpdate, domains, errors };
}

// Fix (retour utilisateur v12.41.0) : le bouton "Web Panel" restait invisible
// meme quand l utilisateur avait bien active `web_panel.enabled: true` dans
// SA config GoDNS (godns.config.yaml/.json, celle que le binaire GoDNS lit
// reellement) — il ne verifiait que `web_panel_enabled` dans config/godns.yml,
// un reglage DIFFERENT et sans rapport (celui-la ne sert qu a decider si le
// dashboard doit publier le port sur l hote, voir godnsStartContainer() plus
// haut ; depuis que le panel s ouvre via le proxy interne (/api/godns/panel),
// publier ce port n est plus necessaire pour l afficher). Cette fonction lit
// la VRAIE config GoDNS pour savoir si son panel est reellement actif.
function detectWebPanelEnabled(cfgFile) {
  try {
    if (!fs.existsSync(cfgFile.internalPath)) return false;
    const raw = fs.readFileSync(cfgFile.internalPath, 'utf8');
    if (cfgFile.format === 'json') {
      const parsed = JSON.parse(raw);
      return !!(parsed.web_panel && (parsed.web_panel.enabled === true || parsed.web_panel.enabled === 'true'));
    }
    // YAML : lib/simple-yaml.js est volontairement plat (pas d imbrication),
    // donc pas question de "parser" godns.config.yaml avec lui. On se limite
    // ici a reperer le bloc top-level "web_panel:" et sa cle "enabled:"
    // indentee dessous — suffisant pour cette seule question booleenne, sans
    // pretendre comprendre tout le fichier.
    const m = raw.match(/^web_panel:\s*\n((?:[ \t]+\S.*\n?)*)/m);
    if (!m) return false;
    return /^\s*enabled:\s*true\s*$/m.test(m[1]);
  } catch (e) {
    console.warn('[godns] detectWebPanelEnabled:', e.message);
    return false;
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
// Le relais /api/godns/panel (proxy HTTP embarquant le panel GoDNS dans un
// iframe de meme origine) a ete retire en v12.43.0 (retour utilisateur) : le
// panel GoDNS est une appli Next.js dont les requetes d assets relatives
// (_next/static/chunks/*.js/.css) ne passent pas correctement a travers un
// relai generique — elles reviennent en 404 ou avec un Content-Type
// application/json, que le navigateur refuse d executer/appliquer
// ("Refused to execute script"/"Refused to apply style... strict MIME
// checking"). Corriger cela demanderait de reecrire un vrai proxy HTTP
// conscient de Next.js (reecriture des chemins d assets, gestion du routing
// client-side, etc.) pour un gain marginal : ouvrir le panel directement via
// un vhost nginx normal fonctionne nativement, sans aucun de ces problemes,
// et n a besoin d aucun code cote dashboard. Voir godnsOpenPanel() dans
// public/assets/js/godns.js : le bouton "Web Panel" ouvre desormais une
// modale d instructions (creer un vhost pointant sur le conteneur GoDNS) au
// lieu d un iframe embarque.
function register(router) {
  router.get('/api/godns/config', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg) return send(res, 200, { configured: false, enabled: false });
    const cfgFile = getGoDNSConfigFilePath(cfg);
    // webPanelEnabled : publie-t-on le port sur l hote (config/godns.yml,
    // n affecte que godnsStartContainer()) — distinct de webPanelConfigured,
    // ce que la vraie config GoDNS dit (voir detectWebPanelEnabled()), qui
    // seul determine si le bouton "Web Panel"/le proxy interne a un sens.
    const webPanelEnabled = cfg.web_panel_enabled === 'true' || cfg.web_panel_enabled === true;
    const externalPort    = parseInt(cfg.web_panel_external_port) || cfg.port || 9000;
    return send(res, 200, {
      configured:          true,
      enabled:             cfg.enable,
      image:               cfg.container_image || 'timothyye/godns:latest',
      containerName:       cfg.container_name  || 'godns',
      port:                cfg.port || 9000,
      configFormat:        cfgFile.format,
      configExists:        fs.existsSync(cfgFile.internalPath),
      configPath:          cfgFile.internalPath,
      webPanelEnabled:     webPanelEnabled,
      webPanelExternalPort: externalPort,
      webPanelConfigured:  detectWebPanelEnabled(cfgFile),
    });
  });

  router.get('/api/godns/status', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false });
    const status = await godnsContainerStatus();
    return send(res, 200, { enabled: true, container: status });
  });

  router.get('/api/godns/info', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false });
    const logs   = await godnsGetLogs(cfg).catch(() => '');
    const status = await godnsContainerStatus();
    const parsed = parseGoDNSLogs(logs);
    // SECURITY (v12.39.0, retour utilisateur) : verification multi-source de
    // l IP que GoDNS pense avoir detectee — voir lib/ip-check.js et
    // GODNS_IP_CHECK/GODNS_IP_CHECK_URLS dans lib/config.js pour le
    // "pourquoi" (un ip_url derriere un CDN peut faire remonter l IP du CDN
    // plutot que l IP reelle, et GoDNS ne le detecte jamais lui-meme).
    // Best-effort : n empeche jamais la reponse si desactive ou si les
    // services externes sont injoignables (deploiement sans acces reseau
    // sortant, par exemple).
    const ipCheck = GODNS_IP_CHECK
      ? await checkPublicIp(parsed.publicIP, GODNS_IP_CHECK_URLS, 5000).catch(() => ({ checked: false, consensusIp: null, sources: [], mismatch: false }))
      : { checked: false, consensusIp: null, sources: [], mismatch: false };
    return send(res, 200, { enabled: true, container: status, ...parsed, ipCheck });
  });

  router.get('/api/godns/logs', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false, logs: '' });
    const logs = await godnsGetLogs(cfg).catch(e => 'Error: ' + e.message);
    return send(res, 200, { enabled: true, logs });
  });

  router.get('/api/godns/config-file', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg) return httpLib.badRequest(res, 'GoDNS not configured');
    const cfgFile = getGoDNSConfigFilePath(cfg);
    if (!fs.existsSync(cfgFile.internalPath)) return send(res, 200, { exists: false, format: cfgFile.format, content: '' });
    const raw    = fs.readFileSync(cfgFile.internalPath, 'utf8');
    const reveal = hasPerm(session, PERMS.MANAGE_USERS) && url.searchParams.get('reveal') === '1';
    return send(res, 200, {
      exists: true, format: cfgFile.format,
      content: reveal ? raw : maskSecretsInConfig(raw),
      masked: !reveal, canReveal: hasPerm(session, PERMS.MANAGE_USERS),
    });
  });

  router.post('/api/godns/config-file', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg) return httpLib.badRequest(res, 'GoDNS not configured');
    const body    = await parseBody(req);
    const content = body.content;
    const format  = body.format || cfg.config_format || 'yaml';
    if (!content) return httpLib.badRequest(res, 'content required');
    // Basic validation
    if (format === 'json') {
      try { JSON.parse(content); } catch(e) { return send(res, 400, { error: 'Invalid JSON: ' + e.message }); }
    }
    const cfgFile = getGoDNSConfigFilePath(cfg);
    const prevRaw = fs.existsSync(cfgFile.internalPath) ? fs.readFileSync(cfgFile.internalPath, 'utf8') : '';
    fs.writeFileSync(cfgFile.internalPath, unmaskSecrets(content, prevRaw), 'utf8');
    logEvent('godns_config_save', 'GoDNS config file saved');
    return send(res, 200, { ok: true, path: cfgFile.hostPath });
  });

  router.post('/api/godns/container/start', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'GoDNS not enabled');
    try {
      await godnsPullImage(cfg);
      await godnsStartContainer(cfg);
      logEvent('godns_start', 'GoDNS container started');
      return send(res, 200, { ok: true });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/godns/container/stop', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    try {
      await godnsStopContainer(cfg);
      logEvent('godns_stop', 'GoDNS container stopped');
      return send(res, 200, { ok: true });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/godns/container/restart', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'GoDNS not enabled');
    try {
      await godnsStartContainer(cfg);
      logEvent('godns_restart', 'GoDNS container restarted');
      return send(res, 200, { ok: true });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/godns/container/update', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGoDNSCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'GoDNS not enabled');
    try {
      await godnsPullImage(cfg);
      await godnsStartContainer(cfg);
      logEvent('godns_update', 'GoDNS container updated and restarted');
      return send(res, 200, { ok: true, message: 'Image pulled and container recreated' });
    } catch(e) { return httpLib.serverError(res, e); }
  });

}

module.exports = { register, getGoDNSCfg, loadGoDNSConfig, parseGoDNSLogs, getGoDNSConfigFilePath, detectWebPanelEnabled };
