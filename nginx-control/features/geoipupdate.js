'use strict';
/**
 * geoipupdate — lifecycle for the single `maxmindinc/geoipupdate` container
 * that keeps the GeoLite2 .mmdb files fresh (used by lib/geoip.js here and by
 * nginx-analyzer's country-level detection).
 *
 * Same shape as features/certbot.js on purpose: a single persistent
 * container, a config file the operator edits directly (geoipupdate.yml —
 * no route ever writes it back, license_key never leaves the server), and a
 * host-path field (geoip_host_path) for the same structural reason
 * certbot.yml has webroot_host_path/certs_host_path — the dashboard cannot
 * see its own compose project's host-side paths from inside a container.
 *
 * The official image already loops internally (run once, sleep
 * GEOIPUPDATE_FREQUENCY hours, repeat) — unlike this project's certbot
 * container, which wraps a plain `certbot` invocation in a shell loop of its
 * own. That means "update now" needs no exec, no cron, no extra script:
 * restarting the container makes its entrypoint run geoipupdate immediately,
 * exactly like a fresh start does.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');
const { parseFlatYaml } = require('../lib/simple-yaml');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;
const { GEOIPUPDATE_CONFIG_FILE, DIR_GEOIP } = cfg;

const CONTAINER_NAME = 'nginx-dashboard-geoipupdate';

function loadGeoipupdateConfig() {
  if (!fs.existsSync(GEOIPUPDATE_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(GEOIPUPDATE_CONFIG_FILE, 'utf8');
    // Fix (audit finding MISC-10): shared parser strips a trailing inline
    // comment — see lib/simple-yaml.js.
    const cfg = parseFlatYaml(raw);
    cfg.enable = cfg.enable === 'true' || cfg.enable === '1';
    cfg.frequency_hours = parseInt(cfg.frequency_hours, 10) || 168;
    return cfg;
  } catch (e) {
    console.warn('[geoipupdate] Config load error:', e.message);
    return null;
  }
}

function getGeoipupdateCfg() {
  return loadGeoipupdateConfig();
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
  };
}

/** File age/size for each configured edition, read straight off DIR_GEOIP —
 * requires the dashboard's own container to mount the same shared directory
 * (documented in docker-compose.yml, ./geoip_data:/geoip:ro). */
function databaseStatus(cfg) {
  const editions = (cfg?.edition_ids || 'GeoLite2-City GeoLite2-Country GeoLite2-ASN')
    .split(/\s+/).filter(Boolean);
  return editions.map(edition => {
    const file = path.join(DIR_GEOIP, `${edition}.mmdb`);
    try {
      const st = fs.statSync(file);
      return { edition, exists: true, sizeBytes: st.size, mtime: st.mtime.toISOString() };
    } catch {
      return { edition, exists: false, sizeBytes: null, mtime: null };
    }
  });
}

/**
 * Same fallback reasoning as certbot's resolveCertsHostPath(): an unset
 * geoip_host_path would otherwise silently bind-mount a relative "geoip_data"
 * path resolved by the Docker daemon against ITS OWN working directory, not
 * this project's — invisible to nginx and nginx-analyzer, exactly like the
 * certs-not-visible bug this same pattern already fixed once for certbot.
 */
function resolveGeoipHostPath(cfg) {
  const explicit = typeof cfg.geoip_host_path === 'string' && cfg.geoip_host_path.trim();
  if (explicit) return explicit;
  console.warn('[geoipupdate] geoip_host_path is not set in geoipupdate.yml — '
    + 'falling back to the relative path "geoip_data", which will very likely '
    + 'NOT match the host directory your nginx/nginx-analyzer containers '
    + 'mount as ./geoip_data. Set geoip_host_path to that same absolute host path.');
  return 'geoip_data';
}

async function startContainer(cfg) {
  await dockerCall('POST', `/containers/${CONTAINER_NAME}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${CONTAINER_NAME}?force=true`).catch(() => {});

  const image      = cfg.container_image || 'maxmindinc/geoipupdate:latest';
  const geoipHost  = resolveGeoipHostPath(cfg);
  const editionIds = cfg.edition_ids || 'GeoLite2-City GeoLite2-Country GeoLite2-ASN';

  const body = {
    Image: image,
    Env: [
      `GEOIPUPDATE_ACCOUNT_ID=${cfg.account_id || ''}`,
      `GEOIPUPDATE_LICENSE_KEY=${cfg.license_key || ''}`,
      `GEOIPUPDATE_EDITION_IDS=${editionIds}`,
      `GEOIPUPDATE_FREQUENCY=${cfg.frequency_hours || 168}`,
    ],
    HostConfig: {
      Binds: [`${geoipHost}:/usr/share/GeoIP:rw`],
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

/**
 * Called once at dashboard boot (server.js) — same reasoning and same
 * shape as certbot's ensureRenewalContainerAtBoot(): `unless-stopped` only
 * restarts a container Docker already knows about. The very first boot
 * after setting `enable: true` (nothing has been created yet) or any boot
 * after the "Arreter" button removed the container outright leaves nothing
 * for Docker's own restart policy to act on — only the dashboard's own next
 * start can notice "enabled but missing" and recreate it. Without this, a
 * host reboot could silently leave GeoIP data going stale until someone
 * happens to open the page.
 */
async function ensureContainerAtBoot() {
  const cfg = getGeoipupdateCfg();
  if (!cfg?.enable) return { skipped: 'not enabled' };
  if (!cfg.license_key || !cfg.license_key.trim()) return { skipped: 'no license_key' };
  try {
    const status = await containerStatus();
    if (status.dockerUnavailable) return { skipped: 'docker unavailable', error: status.error };
    if (status.exists) return { skipped: 'already exists' };
    // Meme geste que la route /container/start : evite un echec silencieux
    // au redemarrage de l hote si l image n a jamais ete pullee.
    await docker.pullAndCheckUpdate(cfg.container_image || 'maxmindinc/geoipupdate:latest');
    await startContainer(cfg);
    console.log('[geoipupdate] Container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[geoipupdate] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/geoipupdate/config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGeoipupdateCfg();
    return send(res, 200, {
      configured:     !!cfg,
      enabled:        !!(cfg?.enable),
      image:          cfg?.container_image || 'maxmindinc/geoipupdate:latest',
      editionIds:     cfg?.edition_ids || null,
      frequencyHours: cfg?.frequency_hours || null,
      accountId:      cfg?.account_id || null,
      // Never sent to the client: only whether one is set, same reasoning
      // as certbot.yml never exposing anything beyond its own summary.
      licenseKeySet:  !!(cfg?.license_key && cfg.license_key.trim()),
      geoipHostPath:  cfg?.geoip_host_path || null,
    });
  });

  router.get('/api/geoipupdate/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getGeoipupdateCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false });
    const container = await containerStatus();
    return send(res, 200, { enabled: true, container, databases: databaseStatus(cfg) });
  });

  router.post('/api/geoipupdate/container/start', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGeoipupdateCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'geoipupdate is not enabled in geoipupdate.yml');
    if (!cfg.license_key || !cfg.license_key.trim())
      return httpLib.badRequest(res, 'license_key is not set in geoipupdate.yml');
    try {
      // Meme geste que certbot/certbot-dns/godns/analyzer : on pull avant de
      // creer le conteneur, pour que "Demarrer" marche du premier coup meme
      // si l image n a jamais ete recuperee (sans quoi il fallait d abord
      // cliquer sur "Mettre a jour l'image", contre-intuitif au premier lancement).
      const image = cfg.container_image || 'maxmindinc/geoipupdate:latest';
      const pull = await docker.pullAndCheckUpdate(image);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${image} echoue : ${pull.error}`));
      await startContainer(cfg);
      logEvent('geoipupdate.start', 'geoipupdate container started', session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/geoipupdate/container/stop', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      await stopContainer();
      logEvent('geoipupdate.stop', 'geoipupdate container stopped', session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  /**
   * Pull the configured image's tag from its registry and, only if that
   * actually changed the locally cached image, recreate the container so it
   * runs the new content — `docker pull` alone never affects a container
   * that already exists. A no-op pull (already the latest content) leaves
   * the running container untouched, no interruption for nothing.
   */
  router.post('/api/geoipupdate/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGeoipupdateCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'geoipupdate is not enabled in geoipupdate.yml');
    const image = cfg.container_image || 'maxmindinc/geoipupdate:latest';
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
    logEvent('geoipupdate.image_update', `Image ${image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });

  /**
   * "Update now" — restart if already running (the entrypoint re-runs
   * geoipupdate immediately on every start, before it goes back to sleeping
   * for frequency_hours), or start fresh if it wasn't running at all. Either
   * way the operator gets an immediate run without waiting for the next
   * scheduled one, with no exec and no code path beyond what start/stop
   * already exercise.
   */
  router.post('/api/geoipupdate/update-now', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getGeoipupdateCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'geoipupdate is not enabled in geoipupdate.yml');
    if (!cfg.license_key || !cfg.license_key.trim())
      return httpLib.badRequest(res, 'license_key is not set in geoipupdate.yml');
    try {
      const status = await containerStatus();
      if (status.exists) {
        const r = await dockerCall('POST', `/containers/${CONTAINER_NAME}/restart?t=10`);
        if (r.status !== 204 && r.status !== 304) throw new Error(`Restart failed: HTTP ${r.status}`);
      } else {
        await startContainer(cfg);
      }
      logEvent('geoipupdate.update_now', 'Manual GeoIP database update triggered', session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });
}

module.exports = {
  register, getGeoipupdateCfg, loadGeoipupdateConfig,
  resolveGeoipHostPath, databaseStatus, CONTAINER_NAME, ensureContainerAtBoot,
};
