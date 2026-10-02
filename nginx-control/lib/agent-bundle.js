'use strict';
/**
 * Kit de déploiement d'un agent distant : fichiers `.env` et `compose.yml`
 * prêts à copier sur l'hôte distant, jeton inclus (v12.58.0).
 *
 * Avant : l'agent devait d'abord s'enrôler (démarrer sans jeton), l'opérateur
 * l'approuvait puis recopiait le jeton sur l'hôte — plusieurs allers-retours.
 * Désormais l'opérateur crée l'agent depuis le dashboard : il est approuvé
 * d'emblée, son jeton est généré par le serveur, et les deux fichiers sont
 * produits avec les bonnes valeurs.
 *
 * Module pur (aucune E/S) : validation des options saisies, puis rendu texte.
 * Tout ce qui est écrit dans les fichiers est validé par liste blanche — les
 * valeurs finissent dans un `.env` interprété par docker compose (`$`, `#`,
 * guillemets, espaces y ont un sens) et dans un YAML.
 */

const DEFAULT_IMAGE = 'forge.rdr-it.com/dockerfiles/nginx-control-agent';
const RESTART_POLICIES = ['always', 'unless-stopped', 'on-failure', 'no'];
const TOKEN_MODES = ['env', 'file'];

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const IMAGE_RE = /^[a-z0-9][a-z0-9._\/-]{0,200}$/i;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const SAFE_URL_RE = /^https?:\/\/[A-Za-z0-9._~:\/\[\]%-]+$/;
const SAFE_TEXT_RE = /^[^\s"'`$#\\\u0000-\u001f\u007f]*$/;

const DEFAULTS = {
  pollInterval: '30s', tunnelEnable: true, insecureSkipVerify: false, restartPolicy: 'always',
  image: DEFAULT_IMAGE, tag: 'latest', tokenMode: 'env', fingerprint: '',
  relay: { enabled: false, host: '', httpPort: 8080, httpsEnabled: false, httpsPort: 8443, backendInsecure: false },
};

function isPort(n) { return Number.isInteger(n) && n >= 1024 && n <= 65535; }

/**
 * @returns {{ok:true, value:object, warnings:string[]}|{ok:false, error:string}}
 */
function validateOptions(input) {
  const i = input && typeof input === 'object' ? input : {};
  const warnings = [];

  const name = String(i.name ?? '').trim();
  if (!NAME_RE.test(name)) return { ok: false, error: 'Nom : lettres, chiffres, « . _ - », 64 caractères maximum, commence par une lettre ou un chiffre' };

  let dashboardUrl;
  try {
    const u = new URL(String(i.dashboardUrl ?? '').trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('protocole');
    if (u.username || u.password || u.search || u.hash) throw new Error('éléments interdits');
    if (!HOST_RE.test(u.hostname.replace(/^\[|\]$/g, '')) && !/^[0-9a-f:.]+$/i.test(u.hostname.replace(/^\[|\]$/g, ''))) throw new Error('hôte');
    dashboardUrl = (u.origin + (u.pathname !== '/' ? u.pathname.replace(/\/+$/, '') : ''));
  } catch { return { ok: false, error: 'URL du dashboard invalide (http(s)://hôte[:port], sans identifiants ni paramètres)' }; }
  if (!SAFE_URL_RE.test(dashboardUrl)) return { ok: false, error: 'URL du dashboard : caractères non autorisés' };
  if (dashboardUrl.startsWith('http://')) warnings.push('URL en http:// : le jeton circulera en clair entre l\'hôte distant et le dashboard. Préférez https://.');

  const fingerprint = String(i.fingerprint ?? '').trim();
  if (fingerprint.length > 80 || !SAFE_TEXT_RE.test(fingerprint)) return { ok: false, error: 'Empreinte : 80 caractères maximum, sans espace, guillemet, « $ », « # » ni « \\ »' };

  const poll = String(i.pollInterval ?? DEFAULTS.pollInterval).trim();
  const pm = poll.match(/^(\d{1,4})(s|m)$/);
  const pollSec = pm ? Number(pm[1]) * (pm[2] === 'm' ? 60 : 1) : 0;
  if (!pm || pollSec < 5 || pollSec > 3600) return { ok: false, error: 'Intervalle de poussée : entre 5s et 60m (ex. 30s, 2m)' };

  const restartPolicy = String(i.restartPolicy ?? DEFAULTS.restartPolicy);
  if (!RESTART_POLICIES.includes(restartPolicy)) return { ok: false, error: `Politique de redémarrage : ${RESTART_POLICIES.join(', ')}` };
  const tokenMode = String(i.tokenMode ?? DEFAULTS.tokenMode);
  if (!TOKEN_MODES.includes(tokenMode)) return { ok: false, error: 'Mode du jeton : env ou file' };

  const image = String(i.image ?? DEFAULTS.image).trim();
  if (!IMAGE_RE.test(image)) return { ok: false, error: 'Image : nom d\'image Docker invalide' };
  const tag = String(i.tag ?? DEFAULTS.tag).trim();
  if (!TAG_RE.test(tag)) return { ok: false, error: 'Tag d\'image invalide' };

  const insecureSkipVerify = i.insecureSkipVerify === true;
  if (insecureSkipVerify) warnings.push('Vérification TLS du dashboard désactivée : à ne jamais utiliser en production.');

  const r = i.relay && typeof i.relay === 'object' ? i.relay : {};
  const relay = { ...DEFAULTS.relay, enabled: r.enabled === true };
  if (relay.enabled) {
    const host = String(r.host ?? '').trim();
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) && host.split('.').every(p => Number(p) <= 255);
    if (!host || !(ipv4 || HOST_RE.test(host))) return { ok: false, error: 'Relais : adresse (IP ou nom) de l\'hôte distant, joignable depuis nginx, obligatoire' };
    relay.host = host;
    relay.httpPort = Number(r.httpPort ?? DEFAULTS.relay.httpPort);
    if (!isPort(relay.httpPort)) return { ok: false, error: 'Relais : port HTTP entre 1024 et 65535' };
    relay.httpsEnabled = r.httpsEnabled === true;
    relay.httpsPort = Number(r.httpsPort ?? DEFAULTS.relay.httpsPort);
    if (relay.httpsEnabled && (!isPort(relay.httpsPort) || relay.httpsPort === relay.httpPort)) return { ok: false, error: 'Relais : port HTTPS entre 1024 et 65535, différent du port HTTP' };
    relay.backendInsecure = r.backendInsecure === true;
  }

  return { ok: true, warnings, value: {
    name, dashboardUrl, fingerprint, pollInterval: poll, tunnelEnable: i.tunnelEnable !== false,
    insecureSkipVerify, restartPolicy, image, tag, tokenMode, relay,
  } };
}

/** Options conservées avec l'agent (aucun secret) pour régénérer le kit après une rotation de jeton. */
function storableOptions(v) {
  const { name, dashboardUrl, ...rest } = v;
  return { ...rest, dashboardUrl };
}

/** Contenu du `.env`. */
function buildEnv(v, token) {
  const L = [];
  L.push(`# nginx-control-agent — généré par le dashboard le ${new Date().toISOString().slice(0, 10)} pour « ${v.name} »`);
  L.push('# À placer à côté de compose.yml, sur l\'HÔTE DISTANT. Protégez ce fichier (chmod 600).');
  L.push(`DASHBOARD_URL=${v.dashboardUrl}`);
  L.push(`AGENT_HOSTNAME=${v.name}`);
  L.push(`AGENT_FINGERPRINT=${v.fingerprint}`);
  L.push(`AGENT_IMAGE=${v.image}`);
  L.push(`AGENT_VERSION=${v.tag}`);
  L.push(`AGENT_RESTART_POLICY=${v.restartPolicy}`);
  L.push(`POLL_INTERVAL=${v.pollInterval}`);
  L.push(`TUNNEL_ENABLE=${v.tunnelEnable}`);
  L.push(`INSECURE_SKIP_VERIFY=${v.insecureSkipVerify}`);
  if (v.tokenMode === 'env') {
    L.push('# Jeton de l\'agent (secret — affiché une seule fois dans le dashboard)');
    L.push(`TOKEN=${token}`);
  } else {
    L.push('# Mode « fichier » : le jeton est lu dans ./data/token (voir la commande indiquée par le dashboard).');
  }
  if (v.relay.enabled) {
    L.push('# Mode relais : un seul port par schéma, adresse annoncée à nginx = hôte distant');
    L.push('RELAY_HTTP_LISTEN=:8080');
    L.push(`RELAY_HTTP_HOST_PORT=${v.relay.httpPort}`);
    L.push(`RELAY_HTTP_ADVERTISE=http://${v.relay.host}:${v.relay.httpPort}`);
    if (v.relay.httpsEnabled) {
      L.push('RELAY_HTTPS_LISTEN=:8443');
      L.push(`RELAY_HTTPS_HOST_PORT=${v.relay.httpsPort}`);
      L.push(`RELAY_HTTPS_ADVERTISE=https://${v.relay.host}:${v.relay.httpsPort}`);
    }
    L.push(`RELAY_BACKEND_INSECURE_SKIP_VERIFY=${v.relay.backendInsecure}`);
  }
  return L.join('\n') + '\n';
}

/** Contenu du `compose.yml` (image publiée : aucun fichier source à copier sur l'hôte distant). */
function buildCompose(v) {
  const L = [];
  L.push('# nginx-control-agent — généré par le dashboard. Usage : docker compose up -d');
  L.push('services:');
  L.push('  nginx-control-agent:');
  L.push(`    image: \${AGENT_IMAGE:-${DEFAULT_IMAGE}}:\${AGENT_VERSION:-latest}`);
  L.push('    container_name: nginx-control-agent');
  L.push('    restart: ${AGENT_RESTART_POLICY:-always}');
  L.push('    security_opt:');
  L.push('      - no-new-privileges:true');
  L.push('    environment:');
  L.push('      - DASHBOARD_URL=${DASHBOARD_URL:?DASHBOARD_URL manquant dans .env}');
  L.push('      - AGENT_HOSTNAME=${AGENT_HOSTNAME:-}');
  L.push('      - AGENT_FINGERPRINT=${AGENT_FINGERPRINT:-}');
  L.push(v.tokenMode === 'env' ? '      - TOKEN=${TOKEN:?TOKEN manquant dans .env}' : '      - TOKEN_FILE=/data/token');
  L.push('      - STATE_FILE=/data/nginx-control-agent-state.json');
  L.push('      - DOCKER_SOCKET=/var/run/docker.sock');
  L.push('      - POLL_INTERVAL=${POLL_INTERVAL:-30s}');
  L.push('      - INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY:-false}');
  L.push('      - TUNNEL_ENABLE=${TUNNEL_ENABLE:-true}');
  if (v.relay.enabled) {
    L.push('      - RELAY_HTTP_LISTEN=${RELAY_HTTP_LISTEN:-}');
    L.push('      - RELAY_HTTP_ADVERTISE=${RELAY_HTTP_ADVERTISE:-}');
    if (v.relay.httpsEnabled) {
      L.push('      - RELAY_HTTPS_LISTEN=${RELAY_HTTPS_LISTEN:-}');
      L.push('      - RELAY_HTTPS_ADVERTISE=${RELAY_HTTPS_ADVERTISE:-}');
    }
    L.push('      - RELAY_BACKEND_INSECURE_SKIP_VERIFY=${RELAY_BACKEND_INSECURE_SKIP_VERIFY:-false}');
    L.push('    ports:');
    L.push('      - "${RELAY_HTTP_HOST_PORT:-8080}:8080"');
    if (v.relay.httpsEnabled) L.push('      - "${RELAY_HTTPS_HOST_PORT:-8443}:8443"');
  }
  L.push('    volumes:');
  L.push('      # Socket Docker LOCAL de cet hôte, en lecture seule (liste les conteneurs et lit leurs labels).');
  L.push('      - /var/run/docker.sock:/var/run/docker.sock:ro');
  L.push('      # État persistant (agentId, jeton) — sans ce volume l\'agent perd son identité au redémarrage.');
  L.push('      - ./data:/data');
  return L.join('\n') + '\n';
}

/** Commande shell à exécuter sur l'hôte distant (mode « fichier » : dépose le jeton avec les bons droits). */
function buildShell(v, token) {
  const L = ['mkdir -p nginx-control-agent && cd nginx-control-agent', '# … collez .env et compose.yml dans ce dossier, puis :', 'chmod 600 .env'];
  if (v.tokenMode === 'file') L.push(`mkdir -p data && umask 077 && printf '%s' '${token}' > data/token`);
  L.push('docker compose up -d', 'docker compose logs -f');
  return L.join('\n') + '\n';
}

function buildBundle(v, token) {
  return { env: buildEnv(v, token), compose: buildCompose(v), shell: buildShell(v, token), tokenMode: v.tokenMode };
}

module.exports = { DEFAULTS, DEFAULT_IMAGE, RESTART_POLICIES, TOKEN_MODES, validateOptions, storableOptions, buildEnv, buildCompose, buildShell, buildBundle };
