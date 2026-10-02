'use strict';
/**
 * Conteneur du challenge navigateur, géré depuis le dashboard (v12.63.0) — même
 * modèle que error-pages / geoipupdate / analyzer : config/challenge.yml
 * (enable, image, réglages), démarrage = pull + (re)création, arrêt,
 * mise à jour de l'image, recréation au démarrage de l'hôte.
 *
 * Le moteur (builtin | anubis), l'upstream et donc le NOM du conteneur viennent
 * de config/blocklists.yml (challenge_engine / challenge_upstream) : le nom du
 * conteneur est l'hôte que nginx résout dans le DNS Docker, il ne doit jamais
 * diverger de celui du snippet généré. La logique pure est dans
 * lib/challenge-container.js.
 *
 * Secret : celui de config/challenge.yml s'il est fourni, sinon généré une fois
 * et conservé (base d'événements, volume /config) pour que les cookies déjà
 * délivrés survivent à une recréation du conteneur.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const appCfg  = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');
const CC      = require('../lib/challenge-container');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { readChallengeOverrides } = require('../lib/challenge-settings');
const blocklists = require('./blocklists');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const SECRET_STATE_KEY = 'challenge_container_secrets';

function readFileOr(f, def = '') { try { return fs.readFileSync(f, 'utf8'); } catch { return def; } }

/** Toute la configuration utile, relue à chaque appel (les fichiers sont éditables à chaud). */
function resolve() {
  const parsed = CC.parseChallengeConfig(readFileOr(appCfg.CHALLENGE_CONFIG_FILE));
  // ENV (NC_*) > config/challenge.yml > défaut
  const withEnv = CC.applyEnv(parsed.config, {
    secret: appCfg.NC_SECRET, difficultyBits: appCfg.NC_DIFFICULTY_BITS, cookieHours: appCfg.NC_COOKIE_HOURS,
    goodbots: appCfg.NC_GOODBOTS, goodbotsExtra: appCfg.NC_GOODBOTS_EXTRA, language: appCfg.NC_LANG,
  });
  const config = withEnv.config;
  const errors = [...parsed.errors, ...withEnv.errors];
  const bl = parseAndValidate(readFileOr(appCfg.BLOCKLIST_CONFIG_FILE), readChallengeOverrides(appCfg.CHALLENGE_CONFIG_FILE));
  const ch = bl.settings.challenge;
  const engine = ch.engine;
  const upstream = ch.upstreamEffective;
  return {
    config, errors, engine, upstream, challengeEnabled: ch.enable,
    name: CC.containerNameFor(upstream, engine),
    image: CC.imageFor(config, engine, { challengeImage: appCfg.CHALLENGE_DEFAULT_IMAGE, anubisImage: appCfg.ANUBIS_DEFAULT_IMAGE }),
  };
}

/**
 * Secret effectif : ENV NC_SECRET > yml > généré et conservé (comme SESSION_SECRET,
 * dans .generated-secrets.json). Anubis exige 64 caractères hexadécimaux.
 */
function secretFor(r) {
  const given = r.config.secret;
  if (given) {
    if (r.engine === 'anubis' && !/^[0-9a-fA-F]{64}$/.test(given)) {
      throw new Error('secret : Anubis attend une clé de 64 caractères hexadécimaux (openssl rand -hex 32)');
    }
    return given;
  }
  const key = `challengeSecret_${r.engine}`;
  const stored = appCfg.readGeneratedSecrets()[key];
  if (stored) return stored;
  const value = crypto.randomBytes(32).toString('hex');
  appCfg.persistGeneratedSecret(key, value);
  console.log(`[challenge] Secret ${r.engine} généré et conservé dans ${appCfg.GENERATED_SECRETS_FILE}`);
  return value;
}

async function containerStatus(name) {
  const res = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  if (res.status === 0)   return { exists: false, running: false, dockerUnavailable: true, error: res.error };
  if (res.status === 404) return { exists: false, running: false };
  if (res.status !== 200) return { exists: false, running: false, error: `HTTP ${res.status}` };
  return {
    exists: true, running: res.body?.State?.Running === true, status: res.body?.State?.Status,
    started: res.body?.State?.StartedAt, image: res.body?.Config?.Image,
    engine: res.body?.Config?.Labels?.['nginx-dashboard.engine'] || null,
  };
}

async function startContainer(r) {
  const spec = CC.buildContainerSpec({
    engine: r.engine, image: r.image, network: appCfg.NGINX_NETWORK, upstream: r.upstream,
    config: r.config, secret: secretFor(r),
  });
  await dockerCall('POST', `/containers/${encodeURIComponent(r.name)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(r.name)}?force=true`).catch(() => {});
  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(r.name)}`, spec);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);
  const start = await dockerCall('POST', `/containers/${encodeURIComponent(r.name)}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  return true;
}

async function stopContainer(name) {
  await dockerCall('POST', `/containers/${encodeURIComponent(name)}/stop`);
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`);
}

/** `unless-stopped` ne relance qu'un conteneur déjà connu de Docker : on le recrée s'il manque. */
async function ensureContainerAtBoot() {
  const r = resolve();
  if (!r.config.enable) return { skipped: 'not enabled' };
  try {
    const st = await containerStatus(r.name);
    if (st.dockerUnavailable) return { skipped: 'docker unavailable', error: st.error };
    if (st.exists) return { skipped: 'already exists' };
    await docker.pullAndCheckUpdate(r.image);
    await startContainer(r);
    console.log(`[challenge] Container ${r.name} recreated at boot (was missing while enabled)`);
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[challenge] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/challenge/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const r = resolve();
    const out = {
      enabled: r.config.enable, challengeEnabled: r.challengeEnabled, engine: r.engine,
      name: r.name, image: r.image, upstream: r.upstream, errors: r.errors,
      configFile: appCfg.CHALLENGE_CONFIG_FILE,
    };
    if (r.config.enable) out.container = await containerStatus(r.name);
    // v12.65.0 : vue complete de la page « Challenge HTTP »
    const ch = blocklists.computeChallengeFiles();
    const fileState = blocklists.getChallengeFilesState();
    out.settings = {
      engine: ch.challenge.engine, upstream: ch.challenge.upstreamEffective, resolver: ch.challenge.resolver,
      exemptPathRegex: ch.challenge.exemptPathRegex, exemptUaRegex: ch.challenge.exemptUaRegex,
      goodbots: r.config.goodbots, goodbotsExtra: r.config.goodbotsExtra,
      difficultyBits: r.config.difficultyBits, cookieHours: r.config.cookieHours,
      profiles: ch.challenge.profiles.map(pr => ({ name: pr.name, mode: pr.mode, file: pr.file, exemptPathRegex: pr.exemptPathRegex, exemptUaRegex: pr.exemptUaRegex })),
    };
    out.blocklistEnabled = ch.settings.enable;
    out.files = fileState.files;
    out.ips = { count: fileState.ips.length, sample: fileState.ips.slice(0, 100) };
    return send(res, 200, out);
  });

  // v12.68.0 : statistiques d'efficacite (compteurs agreges du conteneur builtin,
  // jamais d'IP). Lues en HTTP sur le reseau Docker interne (/stats n'est pas
  // routee par nginx et refuse toute requete portant X-Real-IP).
  router.get('/api/challenge/stats', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const r = resolve();
    if (r.engine !== 'builtin') return send(res, 200, { available: false, reason: 'engine' });
    const hours = Math.min(Math.max(parseInt(url.searchParams.get('hours') || '24', 10) || 24, 1), 720);
    const m = /^([a-z0-9][a-z0-9.-]*)(?::(\d{1,5}))?$/i.exec(String(r.upstream || ''));
    if (!m) return send(res, 200, { available: false, reason: 'upstream' });
    const data = await new Promise((resolveP) => {
      const req = http.get({ host: m[1], port: m[2] || 80, path: `/stats?hours=${hours}`, timeout: 3000,
        headers: { 'User-Agent': appCfg.HTTP_USER_AGENT } }, (up) => {
        let buf = '';
        up.on('data', d => { buf += d; if (buf.length > 2_000_000) up.destroy(); });
        up.on('end', () => { try { resolveP(up.statusCode === 200 ? JSON.parse(buf) : null); } catch { resolveP(null); } });
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => resolveP(null));
    });
    if (!data) return send(res, 200, { available: false, reason: 'unreachable' });
    return send(res, 200, { available: true, ...data });
  });

  // Regenere les fichiers nginx du challenge (independant de la blocklist).
  router.post('/api/challenge/apply', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      const result = await blocklists.applyChallengeFiles({ actor: session.username });
      return send(res, 200, result);
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/container/start', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    if (!r.config.enable) return httpLib.badRequest(res, 'challenge is not enabled in challenge.yml');
    if (r.errors.length) return httpLib.badRequest(res, r.errors.join(' ; '));
    try {
      const pull = await docker.pullAndCheckUpdate(r.image);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${r.image} echoue : ${pull.error}`));
      await startContainer(r);
      logEvent('challenge.start', `challenge container ${r.name} (${r.engine}) (re)started`, session.username);
      return send(res, 200, { ok: true, name: r.name });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/container/stop', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    try {
      await stopContainer(r.name);
      logEvent('challenge.stop', `challenge container ${r.name} stopped`, session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    if (!r.config.enable) return httpLib.badRequest(res, 'challenge is not enabled in challenge.yml');
    const result = await docker.pullAndCheckUpdate(r.image);
    if (!result.ok) return send(res, 200, { ok: false, error: result.error });
    let recreated = false;
    if (result.updated) {
      const st = await containerStatus(r.name);
      if (st.exists) {
        try { await startContainer(r); recreated = true; }
        catch (e) { return send(res, 200, { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message }); }
      }
    }
    logEvent('challenge.image_update', `Image ${r.image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });
}

module.exports = { register, resolve, secretFor, startContainer, containerStatus, ensureContainerAtBoot };
