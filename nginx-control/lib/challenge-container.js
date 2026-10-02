'use strict';
/**
 * Conteneur du challenge navigateur géré depuis le dashboard (v12.63.0).
 *
 * Données pures (aucune E/S, aucun appel Docker) : lecture/validation de
 * config/challenge.yml et construction de la définition du conteneur. Le
 * cycle de vie (pull, création, démarrage, arrêt) est dans
 * features/challenge-container.js, sur le même modèle que error-pages,
 * geoipupdate ou l'analyzer.
 *
 * Deux moteurs, choisis par `challenge_engine` dans blocklists.yml :
 *  - builtin : image nginx-challenge (maison, voir ../nginx-challenge)
 *  - anubis  : image Anubis (https://anubis.techaro.lol), mode auth_request
 */

const { stripInlineComment } = require('./simple-yaml');

const DEFAULT_PORT = { builtin: 8080, anubis: 8923 };
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]{0,200}$/;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const DOMAINS_RE = /^[A-Za-z0-9.,*-]{0,500}$/;
const HOST_RE = /^[A-Za-z0-9.-]{0,100}$/;
const SECRET_RE = /^[A-Za-z0-9_.=+\/-]{32,200}$/;

const DEFAULTS = Object.freeze({
  enable: false, containerImage: '', secret: '',
  difficultyBits: 16, cookieHours: 24, goodbots: true, goodbotsExtra: '', language: 'auto',
  anubisDifficulty: 4, redirectDomains: '', cookieDomain: '',
});

function parseScalar(raw) {
  const v = stripInlineComment(raw);
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return '';
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

/** @returns {{ config: object, errors: string[] }} config est toujours valide (défauts si erreur). */
function parseChallengeConfig(text) {
  const raw = {};
  for (const line of String(text || '').split('\n')) {
    const l = line.replace(/\r$/, '');
    if (!l.trim() || l.trim().startsWith('#')) continue;
    const m = l.match(/^([a-z_]+)\s*:\s*(.*)$/);
    if (m) raw[m[1]] = parseScalar(m[2]);
  }
  const errors = [];
  const c = { ...DEFAULTS };
  const bool = (key, field) => {
    if (raw[key] === undefined || raw[key] === '') return;
    const v = String(raw[key]).toLowerCase();
    if (v === 'true' || v === '1') c[field] = true;
    else if (v === 'false' || v === '0') c[field] = false;
    else errors.push(`${key} : true ou false attendu`);
  };
  const int = (key, field, lo, hi) => {
    if (raw[key] === undefined || raw[key] === '') return;
    const n = /^\d+$/.test(raw[key]) ? Number(raw[key]) : NaN;
    if (!Number.isInteger(n) || n < lo || n > hi) errors.push(`${key} : entier entre ${lo} et ${hi} attendu`);
    else c[field] = n;
  };
  const str = (key, field, re, msg) => {
    if (raw[key] === undefined || raw[key] === '') return;
    if (!re.test(raw[key])) errors.push(`${key} : ${msg}`);
    else c[field] = raw[key];
  };
  bool('enable', 'enable');
  str('container_image', 'containerImage', IMAGE_RE, 'nom d image invalide');
  str('secret', 'secret', SECRET_RE, '32 caractères minimum (lettres, chiffres, _ . = + / -)');
  int('difficulty_bits', 'difficultyBits', 8, 64);
  int('cookie_hours', 'cookieHours', 1, 720);
  bool('goodbots', 'goodbots');
  str('language', 'language', /^(auto|fr|en)$/i, 'auto, fr ou en attendu');
  c.language = String(c.language).toLowerCase();
  if (raw.goodbots_extra) {
    const v = raw.goodbots_extra;
    const ok = v.length <= 1000 && !/[\r\n]/.test(v) && v.split(';').filter(Boolean).every(x => x.split('|').length === 3);
    if (!ok) errors.push('goodbots_extra : attendu nom|regex|.suffixe[,.suffixe][;nom2|…] (1000 caractères maximum)');
    else c.goodbotsExtra = v;
  }
  int('anubis_difficulty', 'anubisDifficulty', 1, 8);
  str('redirect_domains', 'redirectDomains', DOMAINS_RE, 'liste de domaines séparés par des virgules');
  str('cookie_domain', 'cookieDomain', HOST_RE, 'nom de domaine invalide');
  return { config: c, errors };
}

/**
 * Applique les variables d'environnement NC_* par-dessus la config lue du yml
 * (priorité : ENV > yml > défaut). Une valeur d'environnement invalide est
 * ignorée avec une erreur (le yml/défaut reste appliqué). Réutilise le parseur
 * du yml pour garder une seule définition des règles de validation.
 */
function applyEnv(config, env) {
  const spec = [ // [champ de env, clé yml, champ de config]
    ['secret', 'secret', 'secret'], ['difficultyBits', 'difficulty_bits', 'difficultyBits'],
    ['cookieHours', 'cookie_hours', 'cookieHours'], ['goodbots', 'goodbots', 'goodbots'],
    ['goodbotsExtra', 'goodbots_extra', 'goodbotsExtra'], ['language', 'language', 'language'],
  ];
  const lines = spec.filter(([k]) => env[k]).map(([k, y]) => `${y}: "${env[k]}"`);
  if (!lines.length) return { config, errors: [] };
  const { config: over, errors } = parseChallengeConfig(lines.join('\n'));
  const bad = new Set(errors.map(e => e.split(' ')[0]));
  const out = { ...config };
  for (const [k, y, field] of spec) if (env[k] && !bad.has(y)) out[field] = over[field];
  return { config: out, errors: errors.map(e => `ENV ${e}`) };
}

/** Nom du conteneur = hôte de l'upstream (c'est ce que nginx résout dans le DNS Docker). */
function containerNameFor(upstreamEffective, engine) {
  const host = String(upstreamEffective || '').split(':')[0];
  return NAME_RE.test(host) ? host : (engine === 'anubis' ? 'anubis' : 'nginx-challenge');
}

function portFor(upstreamEffective, engine) {
  const m = String(upstreamEffective || '').match(/:(\d+)$/);
  return m ? Number(m[1]) : DEFAULT_PORT[engine] || 8080;
}

function imageFor(config, engine, defaults) {
  return config.containerImage || (engine === 'anubis' ? defaults.anubisImage : defaults.challengeImage);
}

/**
 * Corps de POST /containers/create. `secret` : valeur déjà résolue (config ou
 * générée) — NC_SECRET pour builtin, clé ed25519 (64 hex) pour Anubis.
 * Durcissement : aucun port publié, toutes les capacités retirées, pas de
 * nouveaux privilèges, mémoire et nombre de processus bornés.
 */
function buildContainerSpec({ engine, image, network, upstream, config, secret }) {
  const port = portFor(upstream, engine);
  let env;
  if (engine === 'anubis') {
    env = [
      `BIND=:${port}`, 'TARGET= ', `DIFFICULTY=${config.anubisDifficulty}`,
      `ED25519_PRIVATE_KEY_HEX=${secret}`, 'SERVE_ROBOTS_TXT=false',
    ];
    if (config.redirectDomains) env.push(`REDIRECT_DOMAINS=${config.redirectDomains}`);
    if (config.cookieDomain) env.push(`COOKIE_DOMAIN=${config.cookieDomain}`);
  } else {
    env = [
      `NC_BIND=:${port}`, `NC_SECRET=${secret}`, `NC_DIFFICULTY_BITS=${config.difficultyBits}`,
      `NC_COOKIE_HOURS=${config.cookieHours}`, `NC_LANG=${config.language}`, `NC_GOODBOTS=${config.goodbots ? 'true' : 'false'}`,
    ];
    if (config.goodbotsExtra) env.push(`NC_GOODBOTS_EXTRA=${config.goodbotsExtra}`);
  }
  return {
    Image: image,
    Env: env,
    Labels: { 'managed-by': 'nginx-dashboard', 'nginx-dashboard.role': 'challenge', 'nginx-dashboard.engine': engine },
    HostConfig: {
      RestartPolicy: { Name: 'unless-stopped' },
      NetworkMode: network || 'nginx-net',
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'],
      Memory: 256 * 1024 * 1024,
      PidsLimit: 256,
      ...(engine === 'builtin' ? { ReadonlyRootfs: true } : {}),
    },
  };
}

module.exports = {
  DEFAULTS, parseChallengeConfig, applyEnv, containerNameFor, portFor, imageFor, buildContainerSpec,
};
