'use strict';
/**
 * error-pages (tarampampam/error-pages) — the simplest of the three managed
 * containers requested alongside certbot and geoipupdate: no secret, no
 * volume, no host-path pitfall. It only renders an HTML theme from the
 * status code nginx forwards it (X-Code header) and never writes anything
 * to disk, so "start" can safely mean "destroy and recreate with the
 * current config" every time — the only way a changed template_name ever
 * takes effect, since it is baked in as an environment variable at
 * container creation, not read at request time.
 *
 * One deliberate difference from certbot/geoipupdate: this project's own
 * example nginx config (global-error.conf, shipped as reference material)
 * already resolves this container by the literal Docker name "error-pages"
 * on port 8080 — not a "nginx-dashboard-…" prefix. Naming it anything else
 * here would silently break that snippet for anyone using it as shipped.
 */

const fs = require('fs');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;
const { ERROR_PAGES_CONFIG_FILE } = cfg;

const CONTAINER_NAME = 'error-pages';

function loadErrorPagesConfig() {
  if (!fs.existsSync(ERROR_PAGES_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(ERROR_PAGES_CONFIG_FILE, 'utf8');
    const cfg = {};
    raw.split('\n').forEach(line => {
      const m = line.replace(/\r/g, '').match(/^([a-z_]+)\s*:\s*(.*)$/);
      if (m) cfg[m[1].trim()] = m[2].trim().replace(/\r/g, '').replace(/^["']|["']$/g, '');
    });
    cfg.enable = cfg.enable === 'true' || cfg.enable === '1';
    return cfg;
  } catch (e) {
    console.warn('[error-pages] Config load error:', e.message);
    return null;
  }
}

function getErrorPagesCfg() {
  return loadErrorPagesConfig();
}

async function containerStatus() {
  const r = await dockerCall('GET', `/containers/${CONTAINER_NAME}/json`);
  if (r.status === 0)   return { exists: false, running: false, dockerUnavailable: true, error: r.error };
  if (r.status === 404) return { exists: false, running: false };
  if (r.status !== 200) return { exists: false, running: false, error: `HTTP ${r.status}` };
  return {
    exists:  true,
    running: r.body?.State?.Running === true,
    status:  r.body?.State?.Status,
    started: r.body?.State?.StartedAt,
    image:   r.body?.Config?.Image,
    templateName: (r.body?.Config?.Env || [])
      .find(e => e.startsWith('TEMPLATE_NAME='))?.split('=')[1] || null,
  };
}

async function startContainer(cfg) {
  await dockerCall('POST', `/containers/${CONTAINER_NAME}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${CONTAINER_NAME}?force=true`).catch(() => {});

  const image = cfg.container_image || 'tarampampam/error-pages:latest';

  const body = {
    Image: image,
    Env: [`TEMPLATE_NAME=${cfg.template_name || 'connection'}`],
    HostConfig: {
      RestartPolicy: { Name: 'unless-stopped' },
      // Fix v12.21.2 (audit finding MISC-08): compose creates the network as
      // "<project>_nginx-net", not the literal "nginx-net" — falling back to
      // NGINX_NETWORK (settable, same as features/analyzer.js/godns.js) instead
      // of hardcoding the bare name so container creation doesn't fail on a
      // standard docker-compose deployment.
      NetworkMode: cfg.NGINX_NETWORK || 'nginx-net',
    },
    Labels: { 'managed-by': 'nginx-dashboard' },
  };

  const create = await dockerCall('POST', `/containers/create?name=${CONTAINER_NAME}`, body);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);
  const start = await dockerCall('POST', `/containers/${CONTAINER_NAME}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  return true;
}

async function stopContainer() {
  await dockerCall('POST', `/containers/${CONTAINER_NAME}/stop`);
  await dockerCall('DELETE', `/containers/${CONTAINER_NAME}?force=true`);
}

/** Same reasoning as certbot's and geoipupdate's own ensure*AtBoot(): Docker's
 * `unless-stopped` only ever restarts a container it already knows about. */
async function ensureContainerAtBoot() {
  const cfg = getErrorPagesCfg();
  if (!cfg?.enable) return { skipped: 'not enabled' };
  try {
    const status = await containerStatus();
    if (status.dockerUnavailable) return { skipped: 'docker unavailable', error: status.error };
    if (status.exists) return { skipped: 'already exists' };
    // Meme geste que la route /container/start : evite un echec silencieux
    // au redemarrage de l hote si l image n a jamais ete pullee.
    await docker.pullAndCheckUpdate(cfg.container_image || 'tarampampam/error-pages:latest');
    await startContainer(cfg);
    console.log('[error-pages] Container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[error-pages] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/error-pages/config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getErrorPagesCfg();
    return send(res, 200, {
      configured:   !!cfg,
      enabled:      !!(cfg?.enable),
      image:        cfg?.container_image || 'tarampampam/error-pages:latest',
      templateName: cfg?.template_name || 'connection',
    });
  });

  router.get('/api/error-pages/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getErrorPagesCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false });
    const container = await containerStatus();
    return send(res, 200, { enabled: true, container });
  });

  /**
   * Doubles as "apply config": recreates the container so a template_name
   * change edited in error-pages.yml actually takes effect, since it is an
   * environment variable baked in at creation — restarting the same
   * container would keep serving the old theme.
   */
  router.post('/api/error-pages/container/start', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getErrorPagesCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'error-pages is not enabled in error-pages.yml');
    try {
      // Meme geste que certbot/certbot-dns/godns/analyzer : on pull avant de
      // creer le conteneur, pour que "Demarrer" marche du premier coup meme
      // si l image n a jamais ete recuperee.
      const image = cfg.container_image || 'tarampampam/error-pages:latest';
      const pull = await docker.pullAndCheckUpdate(image);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${image} echoue : ${pull.error}`));
      await startContainer(cfg);
      logEvent('error_pages.start', `error-pages container (re)started, template=${cfg.template_name || 'connection'}`, session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/error-pages/container/stop', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      await stopContainer();
      logEvent('error_pages.stop', 'error-pages container stopped', session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  /** Same shape as certbot's and geoipupdate's own image/update. */
  router.post('/api/error-pages/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getErrorPagesCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'error-pages is not enabled in error-pages.yml');
    const image = cfg.container_image || 'tarampampam/error-pages:latest';
    const result = await docker.pullAndCheckUpdate(image);
    if (!result.ok) return send(res, 200, { ok: false, error: result.error });
    let recreated = false;
    if (result.updated) {
      const status = await containerStatus();
      if (status.exists) {
        try { await startContainer(cfg); recreated = true; }
        catch (e) { return send(res, 200, { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message }); }
      }
    }
    logEvent('error_pages.image_update', `Image ${image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });
}

module.exports = {
  register, getErrorPagesCfg, loadErrorPagesConfig,
  CONTAINER_NAME, ensureContainerAtBoot,
};
