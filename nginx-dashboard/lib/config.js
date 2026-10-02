'use strict';
/**
 * Central configuration.
 *
 * Every environment variable the dashboard reads is resolved here, once, and
 * exported frozen. No other module calls process.env — that way the full
 * surface of what can be configured is visible in a single file, and a typo in
 * a variable name cannot silently produce `undefined` deep inside a feature.
 *
 * .trim() and the quote-stripping are deliberate: docker-compose happily passes
 * values still wrapped in quotes when they come from a .env file.
 */

const path   = require('path');
const crypto = require('crypto');

/** Read an env var, trimming whitespace and surrounding quotes. */
const str = (name, fallback = '') =>
  (process.env[name] ?? fallback).trim().replace(/^["']|["']$/g, '');

/** Read a boolean env var. Defaults to false unless `defaultTrue` is set. */
const bool = (name, defaultTrue = false) => {
  const v = str(name).toLowerCase();
  if (v === '') return defaultTrue;
  return defaultTrue ? v !== 'false' && v !== '0' : v === 'true' || v === '1';
};

/** Read an integer env var, ignoring any stray non-numeric characters. */
const int = (name, fallback) => {
  const v = parseInt(str(name).replace(/[^0-9-]/g, ''), 10);
  return Number.isFinite(v) ? v : fallback;
};

// Injectee au build via `ARG APP_VERSION` / `ENV APP_VERSION` dans le
// Dockerfile (docker-build.yml passe `--build-arg APP_VERSION=${TAG_NAME}`
// sur chaque tag Git) — meme mecanisme que ANALYZER_DEFAULT_IMAGE plus haut.
// Avant ce changement, cette constante etait un litteral en dur, a modifier
// a la main dans le code source a chaque version : le tag Git et le numero
// affiche dans le dashboard pouvaient diverger silencieusement. Le fallback
// ne sert qu en dehors d un conteneur construit par ce Dockerfile (tests
// locaux, `node server.js` execute directement) — l ARG du Dockerfile a lui
// meme deja son propre defaut ("dev") pour un build sans --build-arg.
const VERSION = str('APP_VERSION', '12.68.0');

// ─── Core ────────────────────────────────────────────────────────────────────
const PORT            = int('PORT', 3000);
const NGINX_VTS_URL   = str('NGINX_VTS_URL', 'http://nginx:8080/status.json');
const NGINX_CONTAINER = str('NGINX_CONTAINER', 'nginx');
const NGINX_IMAGE     = str('NGINX_IMAGE');
const NGINX_CONF_FILE = str('NGINX_CONF_FILE', '/etc/nginx/nginx.conf');
const NGINX_NETWORK   = str('NGINX_NETWORK', 'nginx-net');

// SECURITY (fix v12.21.1, audit finding SEC-05): comma-separated list of
// IPs/CIDRs allowed to set X-Forwarded-For. The dashboard normally sits
// behind the very nginx it manages (same Docker network), so the default
// covers Docker's private ranges — an operator who fronts it with something
// else (an external load balancer, a different proxy) must list that proxy's
// address explicitly. Empty means "trust nothing": every request is
// attributed to req.socket.remoteAddress, XFF is ignored outright. See
// lib/http.js#clientIp() for how this list is used.
const TRUSTED_PROXIES = str('TRUSTED_PROXIES', '127.0.0.1,::1,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8')
  .split(',').map(s => s.trim()).filter(Boolean);

// ─── Client-side polling (v12.21.2) ─────────────────────────────────────────
// The browser's notification-center bell (GET /api/notifications) polled on
// the SAME fixed 5s cadence as the header status/metrics refresh, with no
// way to change it short of editing public/index.html. Exposed here so an
// operator with a slow link, a very large team, or simply a preference for
// fewer background requests can widen it — clamped to a sane floor so a
// stray "0" or "1" in the env doesn't turn it into a self-inflicted
// denial-of-service against the dashboard's own event log. Read by
// server.js and injected into the page as `window.NOTIF_POLL_INTERVAL_MS`,
// the same mechanism already used for window.BRANDING/window.DASHBOARD_VERSION.
const NOTIF_POLL_INTERVAL_SEC = Math.max(2, int('NOTIF_POLL_INTERVAL_SEC', 5));

// ─── Config files (all live beside users.yml) ────────────────────────────────
// Declared here (ahead of "Secrets & auth" below) because resolveGeneratedSecret()
// needs CONFIG_DIR to persist an auto-generated secret across restarts.
const USERS_FILE        = process.env.USERS_FILE || '/config/users.yml';
const CONFIG_DIR        = path.dirname(USERS_FILE);

// ─── Secrets & auth ──────────────────────────────────────────────────────────
// v12.32.0: SESSION_SECRET used to be re-randomised on EVERY boot whenever the
// operator did not set it explicitly — a real bug, not a hardening measure:
// it silently logged out every active session on every restart/update, with
// nothing in the logs to explain why. resolveGeneratedSecret() keeps the same
// "manual value always wins" rule, but when nothing is set it now generates a
// value ONCE and persists it to GENERATED_SECRETS_FILE (inside CONFIG_DIR,
// which docker-compose.yml already bind-mounts, so it survives container
// restarts/upgrades exactly like users.yml does) instead of regenerating it
// every time. An operator who wants to set their own value can still do so at
// any moment — SESSION_SECRET in .env always takes priority over the
// generated file, checked first, unconditionally.
const GENERATED_SECRETS_FILE = path.join(CONFIG_DIR, '.generated-secrets.json');

function readGeneratedSecrets() {
  try {
    return JSON.parse(require('fs').readFileSync(GENERATED_SECRETS_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function persistGeneratedSecret(key, value) {
  const fs = require('fs');
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    const store = readGeneratedSecrets();
    store[key] = value;
    const tmp = GENERATED_SECRETS_FILE + '.tmp';
    // Atomic write (tmp + rename) and 0600 permissions, same convention used
    // elsewhere in this project (see lib/blocklists.js's atomicWrite()) for
    // any file holding secret material.
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, GENERATED_SECRETS_FILE);
  } catch (e) {
    console.warn(`[config] Impossible d'ecrire ${GENERATED_SECRETS_FILE} (${e.message}) : la valeur generee pour "${key}" sera reguneree a chaque redemarrage tant que ce fichier reste inaccessible en ecriture.`);
  }
}

/**
 * Resout un secret : la variable d'environnement, si l'operateur l'a definie
 * explicitement, gagne TOUJOURS (aucune automatisation ne doit pouvoir passer
 * outre un choix manuel). Sinon, reutilise une valeur precedemment generee et
 * persistee ; sinon en genere une nouvelle, la persiste immediatement, et la
 * retourne avec generated:true/isNew:true pour que l'appelant puisse logger
 * l'evenement une seule fois (au moment ou la valeur est creee, pas a chaque
 * boot suivant ou elle est simplement relue).
 */
function resolveGeneratedSecret(envName, key, bytes = 32) {
  const envValue = str(envName);
  if (envValue) return { value: envValue, generated: false, isNew: false };
  const store = readGeneratedSecrets();
  if (store[key]) return { value: store[key], generated: true, isNew: false };
  const value = crypto.randomBytes(bytes).toString('hex');
  persistGeneratedSecret(key, value);
  return { value, generated: true, isNew: true };
}

const sessionSecretResolved = resolveGeneratedSecret('SESSION_SECRET', 'sessionSecret', 32);
const SESSION_SECRET = sessionSecretResolved.value;
if (sessionSecretResolved.isNew) {
  console.log(`[config] SESSION_SECRET n'est pas definie : une valeur aleatoire a ete generee et enregistree dans ${GENERATED_SECRETS_FILE} — les sessions resteront valides d'un redemarrage a l'autre. Pour la choisir vous-meme, definissez SESSION_SECRET dans .env (ex. \`openssl rand -hex 32\`) : elle sera alors toujours prioritaire sur la valeur generee.`);
}
// v12.67.1 : identifiant unique et PERSISTANT de cette installation (UUID v4),
// prerequis de la future remontee d alertes vers « Nginx Control Intelligence »
// (mode anonyme ou authentifie). Priorite ENV INSTANCE_ID (UUID valide) > valeur
// persistee dans config/.generated-secrets.json > generee au premier demarrage.
// Ce n est PAS un secret (il identifie l instance) : ne jamais l utiliser comme preuve d identite.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INSTANCE_ID = (() => {
  const env = str('INSTANCE_ID');
  if (env) {
    if (UUID_RE.test(env)) return env.toLowerCase();
    console.warn('[config] INSTANCE_ID ignoree : un UUID est attendu (ex. 3f2b8c1e-9d4a-4e6b-8a57-1c2d3e4f5a6b).');
  }
  const stored = readGeneratedSecrets().instanceId;
  if (typeof stored === 'string' && UUID_RE.test(stored)) return stored.toLowerCase();
  const id = crypto.randomUUID();
  // Repertoire de config absent : on ne le cree PAS ici (le diagnostic de demarrage doit
  // pouvoir le signaler) — l ID reste alors ephemere jusqu a ce que le repertoire existe.
  if (!require('fs').existsSync(CONFIG_DIR)) return id;
  persistGeneratedSecret('instanceId', id);
  console.log(`[config] Identifiant d'instance genere et enregistre dans ${GENERATED_SECRETS_FILE} : ${id}`);
  return id;
})();
const SESSION_TTL_MS = int('SESSION_TTL_HOURS', 8) * 3600_000;
// Sliding TTL keeps active users signed in; the absolute cap bounds how long a
// stolen cookie stays useful.
const SESSION_ABSOLUTE_MAX_MS = int('SESSION_MAX_HOURS', 24) * 3600_000;

// SECURITY (fix v12.21.1, audit finding SEC-03): the shipped
// docker-compose.yml and sample.env both set a *placeholder* value
// (`changeme-set-in-env`, `changeme-generate-with-openssl-rand-hex-32`) as
// the compose-level default for NGINX_DASHBOARD_API_TOKEN — meant to be
// overridden in `.env`, but a deployment that never edits `.env` still gets
// a real, publicly-known string here. The old check only rejected the exact
// literal "changeme" plus anything under 16 characters, so both shipped
// placeholders (well over 16 characters) sailed straight through and
// enabled `Authorization: Bearer <that same public string>` as full admin
// on whatever port 3000 is reachable from. isPlaceholderToken() now rejects
// any value that still starts with "changeme" (case-insensitive), not just
// that exact word, closing this without changing behaviour for anyone who
// actually generated their own token.
function isPlaceholderToken(v) {
  return !v || /^changeme/i.test(v);
}

const API_TOKEN = process.env.API_TOKEN || 'changeme';
// Bearer auth stays DISABLED until a real token is supplied. Left enabled with a
// placeholder, `Authorization: Bearer changeme` would hand out full admin.
const API_TOKEN_ENABLED = !!process.env.API_TOKEN
  && !isPlaceholderToken(process.env.API_TOKEN)
  && process.env.API_TOKEN.length >= 32;

const WEBHOOK_SECRET     = process.env.WEBHOOK_SECRET || 'changeme';
const WEBHOOK_SECRET_SET = !!process.env.WEBHOOK_SECRET && !isPlaceholderToken(process.env.WEBHOOK_SECRET);

if (process.env.API_TOKEN && !API_TOKEN_ENABLED) {
  console.warn('[config] API_TOKEN est defini mais ressemble a une valeur d\'exemple ou fait moins de 32 caracteres : authentification Bearer DESACTIVEE. Generez une vraie valeur avec `openssl rand -hex 32`.');
}

/**
 * Supprime une valeur precedemment generee (regeneration/revocation depuis
 * l'interface — page Systeme, v12.32.0). N'affecte jamais une variable
 * d'environnement : ceci ne touche que le fichier des valeurs auto-generees.
 */
function clearGeneratedSecret(key) {
  const fs = require('fs');
  try {
    const store = readGeneratedSecrets();
    if (!(key in store)) return;
    delete store[key];
    const tmp = GENERATED_SECRETS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, GENERATED_SECRETS_FILE);
  } catch (e) {
    console.warn(`[config] Impossible de supprimer "${key}" de ${GENERATED_SECRETS_FILE} (${e.message}).`);
  }
}

// v12.32.0: API_TOKEN peut aussi etre genere depuis l'interface (page Systeme,
// bouton "Generer") plutot que dans .env — dans ce cas seul son EMPREINTE
// (scrypt, meme format que les mots de passe utilisateur) est persistee dans
// GENERATED_SECRETS_FILE, jamais la valeur en clair : le jeton n'est affiche
// qu'une seule fois, au moment de sa generation, exactement comme un mot de
// passe. Contrairement a SESSION_SECRET, ceci reste strictement OPT-IN — rien
// n'est genere automatiquement au demarrage — pour ne pas revenir sur le
// durcissement SEC-03 (v12.21.1) qui a deliberement rendu l'auth Bearer
// inactive tant que l'operateur n'a pas agi explicitement.
function apiTokenActive() {
  return API_TOKEN_ENABLED || !!readGeneratedSecrets().apiTokenHash;
}

/**
 * Verifie un jeton Bearer presente par un appelant : contre la valeur d'env
 * (comparaison directe, en clair) si API_TOKEN_ENABLED, sinon contre
 * l'empreinte generee (comparaison par hash, comme un mot de passe). Vit ici
 * plutot que dans lib/auth.js pour rester pres de la resolution/persistance
 * du secret ; lib/auth.js l'importe pour requireApiAuth()/authenticateQueryToken().
 */
function verifyApiToken(presented) {
  if (!presented) return false;
  if (API_TOKEN_ENABLED) {
    // Comparaison a temps constant, meme logique que lib/auth.js#safeCompare()
    // (pas d'import croise : ce module ne depend jamais de lib/auth.js).
    try {
      const a = Buffer.from(String(presented)), b = Buffer.from(String(API_TOKEN));
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
  }
  const hash = readGeneratedSecrets().apiTokenHash;
  if (!hash) return false;
  // Required lazily: lib/auth.js requires this module at its own top level,
  // so a top-level require here would be circular. By the time this function
  // is actually CALLED (a real Bearer request, well after boot), both
  // modules are fully loaded and this resolves from the require cache.
  return require('./auth').verifyPassword(presented, hash);
}

// v12.32.0: WEBHOOK_SECRET, a l'inverse d'API_TOKEN, doit rester LISIBLE par
// le dashboard lui-meme : c'est lui qui l'envoie (X-Nginx-Dashboard-Secret)
// a chaque webhook sortant (lib/events.js#fireWebhook) — un hash ne
// permettrait jamais de reconstituer la valeur a transmettre. Genere depuis
// l'interface, il est donc persiste EN CLAIR dans GENERATED_SECRETS_FILE
// (ecriture atomique, permissions 0600 — meme fichier, memes garanties que
// SESSION_SECRET ci-dessus), affiche une seule fois au moment de sa
// generation pour que l'operateur puisse le reporter cote destinataire du
// webhook, puis jamais reaffiche ensuite.
function getWebhookSecret() {
  if (WEBHOOK_SECRET_SET) return WEBHOOK_SECRET;
  const generated = readGeneratedSecrets().webhookSecret;
  return generated || WEBHOOK_SECRET;
}
function isWebhookSecretConfigured() {
  return WEBHOOK_SECRET_SET || !!readGeneratedSecrets().webhookSecret;
}

const LOGIN_MAX_ATTEMPTS = int('LOGIN_MAX_ATTEMPTS', 10);
const LOGIN_WINDOW_MS    = int('LOGIN_WINDOW_MIN', 15) * 60_000;
const LOGIN_LOCKOUT_MS   = int('LOGIN_LOCKOUT_MIN', 15) * 60_000;

// Cross-origin access is opt-in: the dashboard is served from the same origin,
// and a wildcard would only widen the attack surface.
const CORS_ORIGIN = str('CORS_ORIGIN');

// ─── Config files (suite — USERS_FILE/CONFIG_DIR declared earlier, see above) ─
const SMTP_CONFIG_FILE  = path.join(CONFIG_DIR, 'smtp.yml');
const NOTIF_CONFIG_FILE = path.join(CONFIG_DIR, 'notifications.yml');
const SCHED_CONFIG_FILE = path.join(CONFIG_DIR, 'scheduler.yml');
const CERTBOT_CONFIG_FILE = path.join(CONFIG_DIR, 'certbot.yml');
const CERTBOT_DNS_CONFIG_FILE = path.join(CONFIG_DIR, 'certbot-dns.yml');
const GODNS_CONFIG_FILE = path.join(CONFIG_DIR, 'godns.yml');
// v12.39.0 (retour utilisateur) : visibilite des elements de menu optionnels
// (WAF, GoDNS, ...) — voir lib/menu-visibility.js. Fichier separe plutot
// qu ajoute a un des .yml existants : ce n est pas la configuration d une
// integration precise (comme godns.yml/crowdsec.yml), mais un reglage
// transverse d affichage qui touche plusieurs pages a la fois, et qui doit
// pouvoir grandir (d autres elements optionnels) sans re-ouvrir un fichier
// deja dedie a autre chose.
const MENU_CONFIG_FILE = path.join(CONFIG_DIR, 'menu.yml');
// v12.45.0 (retour utilisateur) : premier occupant d un fichier de reglages
// transversaux distinct de menu.yml (qui ne gere QUE la visibilite d un item
// de nav, jamais si une fonctionnalite tourne reellement — voir le
// commentaire de DOCKER_AUTOCONFIG_MENU dans lib/menu-visibility.js) et de
// nginx-control.js (le NOM de ce fichier n a rien a voir avec la
// fonctionnalite features/nginx-control.js — reload/redemarrage/stats nginx
// — c est un pur hasard de vocabulaire ; le choisir quand meme aurait pu
// laisser croire a un lien qui n existe pas, d ou "features.yml"). Objectif
// : accueillir de petits interrupteurs marche/arret qui n ont pas leur
// propre fichier dedie (contrairement a docker-autoconfig.yml/agents.yml,
// qui configurent aussi le COMPORTEMENT detaille d une fonctionnalite, pas
// seulement si elle tourne) — voir lib/feature-flags.js pour la resolution
// ENV > YAML > defaut, meme discipline que resolveToggle() dans
// lib/menu-visibility.js.
const FEATURES_CONFIG_FILE = path.join(CONFIG_DIR, 'features.yml');

// SECURITY (v12.39.0, retour utilisateur) : verification multi-source de l IP
// publique detectee par GoDNS. Un `ip_url` dans godns.config.yaml qui pointe
// vers un service maison lui-meme proxy par un CDN (Cloudflare en front,
// nuage orange) renvoie l IP du CDN (celle qui s est connectee au service),
// pas l IP publique reelle du visiteur/du serveur qui interroge — GoDNS met
// alors a jour tous les enregistrements DNS vers l IP du CDN au lieu de l IP
// reelle, sans jamais le signaler (il fait confiance a la reponse de son
// ip_url). Le dashboard interroge lui-meme, independamment de GoDNS, quelques
// services publics connus pour ne pas etre eux-memes derriere un tel CDN, et
// compare le resultat majoritaire a l IP que GoDNS rapporte dans ses journaux
// — voir lib/ip-check.js. Desactivable (aucun appel sortant supplementaire)
// pour un deploiement sans acces reseau externe ou qui prefere s en passer.
const GODNS_IP_CHECK = bool('GODNS_IP_CHECK', true);
const GODNS_IP_CHECK_URLS = str('GODNS_IP_CHECK_URLS',
  'https://api.ipify.org,https://icanhazip.com,https://ifconfig.me/ip')
  .split(',').map(s => s.trim()).filter(Boolean);

// L image par defaut de l analyzer, utilisee quand analyzer.yml ne definit pas
// container_image. Contrairement aux autres conteneurs geres (certbot,
// geoipupdate, error-pages...), qui pointent tous vers une image publique
// tierce, l analyzer est une image maison (voir nginx-analyzer/) — quelqu un
// qui build sa propre image sous un autre nom/registre doit pouvoir changer
// ce defaut sans toucher a analyzer.yml. Injecte via ARG/ENV dans le
// Dockerfile pour etre configurable au moment du build (--build-arg), tout en
// restant surchargeable a l execution comme n importe quelle autre variable.
const ANALYZER_DEFAULT_IMAGE = str('ANALYZER_DEFAULT_IMAGE', 'forge.rdr-it.com/dockerfiles/nginx-analyzer:latest');
const EVENTS_DB_PATH    = path.join(CONFIG_DIR, 'events.db');
const EVENTS_RETENTION_DAYS = int('EVENTS_RETENTION_DAYS', 30);

// Continuous backend monitoring (features/monitor.js) — its own database
// file rather than reusing events.db: unrelated tables, unrelated write
// volume (a probe every few seconds per monitored target vs. a handful of
// operator actions a day). Lives beside users.yml/events.db like everything
// else in CONFIG_DIR, so no new volume is needed in docker-compose.yml.
const MONITOR_DB_PATH = path.join(CONFIG_DIR, 'monitoring.db');
const MONITOR_RETENTION_DAYS = int('MONITOR_RETENTION_DAYS', 30);

// In-app notification center (lib/notifications.js) — the bell/dropdown in
// the header. Its own database file, same reasoning as MONITOR_DB_PATH
// above: an unrelated table from events.db, and separate from
// NOTIF_CONFIG_FILE (notifications.yml) below, which configures EMAIL rules
// and has nothing to do with what shows up in the header.
const NOTIF_CENTER_DB_PATH = path.join(CONFIG_DIR, 'notifications-center.db');
const NOTIF_CENTER_RETENTION_DAYS = int('NOTIF_CENTER_RETENTION_DAYS', 90);

// ─── Nginx directories (as seen from inside this container) ──────────────────
const DIR_SITES    = str('DIR_SITES',    '/nginx/sites');
const DIR_CONF     = str('DIR_CONF',     '/nginx/conf');
const DIR_SNIPPETS = str('DIR_SNIPPETS', '/nginx/snippets');
const DIR_STREAMS  = str('DIR_STREAMS',  '/nginx/streams');
const DIR_SSL      = str('DIR_SSL',      '/nginx/ssl');
const DIR_CERTS    = str('DIR_CERTS',    '/nginx/certs');
const DIR_LOGS     = str('DIR_LOGS',     '/nginx/logs');
const DIR_CACHE    = str('DIR_CACHE');
const DIR_BACKUPS  = str('DIR_BACKUPS',  '/nginx/backups');
const DIR_GIT_WORK = str('DIR_GIT_WORK', '/git-work');

// Host-side paths, required when creating containers through the Docker socket.
// The daemon resolves bind-mount sources on the HOST, so a path that only exists
// inside this container makes it silently mount an empty directory instead.
// lib/docker.js can derive these automatically; these remain as overrides.
const HOST_LOGS     = str('HOST_LOGS',     process.env.DIR_LOGS     || '/nginx/logs');
const HOST_GOACCESS = str('HOST_GOACCESS', process.env.DIR_GOACCESS || '/nginx/goaccess');
// geoipupdate's own container is the one exception in this group: its host
// path is not read from an env var here but from geoip_host_path in
// geoipupdate.yml (features/geoipupdate.js), the same convention already
// used for certbot's webroot_host_path/certs_host_path — a Docker-managed
// container's bind-mount source is inherently one of those "the dashboard
// cannot see its own compose project's host paths" cases, and putting it in
// the feature's own config file next to enable/account_id/license_key beat
// splitting one feature's settings across an env var and a yaml file.

// ─── Git ─────────────────────────────────────────────────────────────────────
const GIT_REPO_URL      = str('GIT_REPO_URL');
const GIT_BRANCH        = str('GIT_BRANCH', 'main');
const GIT_BACKUP_BRANCH = str('GIT_BACKUP_BRANCH', 'backup');
const GIT_SSH_KEY       = str('GIT_SSH_KEY');
const GIT_TOKEN         = str('GIT_TOKEN');
const GIT_USER_NAME     = str('GIT_USER_NAME',  'Nginx Dashboard');
const GIT_USER_EMAIL    = str('GIT_USER_EMAIL', 'dashboard@localhost');
const BACKUP_KEEP       = int('BACKUP_KEEP', 20);

// ─── Deploy behaviour ────────────────────────────────────────────────────────
const ALLOW_EDIT = bool('ALLOW_EDIT');
// Creating a brand new site/conf/snippet/stream file from the dashboard
// (features/configs.js) — separate from ALLOW_EDIT so either can be turned
// on without the other. Only takes effect when Git is NOT configured
// (checked at request time via getGitCfg(), not here): with Git configured,
// new files are expected to come from the reference repository instead, so
// the managed directories stay reproducible from it.
const ALLOW_CREATE = bool('ALLOW_CREATE');
// ssl/ holds user-supplied certificates (purchased, internal CA): configuration
// like any other, versioned and deployed. Not to be confused with certs/
// (Let's Encrypt, produced by certbot), which deploy never touches.
const DEPLOY_SYNC_SSL = bool('DEPLOY_SYNC_SSL', true);

// ─── Docker ──────────────────────────────────────────────────────────────────
const DOCKER_SOCKET = str('DOCKER_SOCKET', '/var/run/docker.sock');

// ─── GeoIP (MaxMind databases) ───────────────────────────────────────────────
const GEOIP_CITY_DB    = str('GEOIP_CITY_DB',    '/geoip/GeoLite2-City.mmdb');
const GEOIP_COUNTRY_DB = str('GEOIP_COUNTRY_DB', '/geoip/GeoLite2-Country.mmdb');
const GEOIP_ASN_DB     = str('GEOIP_ASN_DB',     '/geoip/GeoLite2-ASN.mmdb');
// Directory holding the three files above — read by features/geoipupdate.js
// to report file age/size regardless of which editions are configured,
// without hardcoding the three GEOIP_*_DB paths a second time.
const DIR_GEOIP = str('DIR_GEOIP', '/geoip');
const GEOIPUPDATE_CONFIG_FILE = path.join(CONFIG_DIR, 'geoipupdate.yml');
const ERROR_PAGES_CONFIG_FILE = path.join(CONFIG_DIR, 'error-pages.yml');

// Conteneur du challenge navigateur (v12.63.0, features/challenge-container.js).
// Images par defaut injectees via ARG/ENV du Dockerfile (--build-arg) et
// surchargeables a l execution, comme ANALYZER_DEFAULT_IMAGE ci-dessus ; une
// image fixee dans config/challenge.yml (container_image) reste prioritaire.
const CHALLENGE_CONFIG_FILE = path.join(CONFIG_DIR, 'challenge.yml');
const CHALLENGE_DEFAULT_IMAGE = str('CHALLENGE_DEFAULT_IMAGE', 'forge.rdr-it.com/dockerfiles/nginx-challenge:latest');
// User-Agent de TOUTES les requetes HTTP sortantes de Nginx Control (listes, depots,
// webhooks, LAPI, hotes distants, git...) : un seul nom, sans version, pour pouvoir
// le filtrer ou l exempter cote nginx (ex. challenge_exempt_ua_regex: '^NginxControl$').
const HTTP_USER_AGENT = (() => {
  const v = str('HTTP_USER_AGENT', 'NginxControl');
  return /^[A-Za-z0-9._\/-]{1,60}$/.test(v) ? v : 'NginxControl';
})();
const ANUBIS_DEFAULT_IMAGE = str('ANUBIS_DEFAULT_IMAGE', 'ghcr.io/techarohq/anubis:latest');
// Reglages du conteneur de challenge (v12.64.0). Priorite : ENV > config/challenge.yml > defaut.
// Chaines brutes, validees par lib/challenge-container.js#applyEnv. NC_SECRET absent :
// genere et conserve dans .generated-secrets.json (comme SESSION_SECRET), cf. features/challenge-container.js.
const NC_SECRET = str('NC_SECRET');
const NC_DIFFICULTY_BITS = str('NC_DIFFICULTY_BITS');
const NC_COOKIE_HOURS = str('NC_COOKIE_HOURS');
const NC_GOODBOTS = str('NC_GOODBOTS');
const NC_GOODBOTS_EXTRA = str('NC_GOODBOTS_EXTRA');
const NC_LANG = str('NC_LANG');

// ─── CrowdSec ────────────────────────────────────────────────────────────────
const CROWDSEC_URL        = str('CROWDSEC_URL');
const CROWDSEC_API_KEY    = str('CROWDSEC_API_KEY');
// Distinct from the bouncer key above: banning, unbanning and managing
// allowlists are machine (watcher) operations in CrowdSec's LAPI, gated
// separately from the bouncer's read-only API key by design — a compromised
// remediation component must not be able to unban attackers or ban arbitrary
// addresses network-wide. Created once via `cscli machines add` on the
// CrowdSec host; the resulting id/password work over plain HTTPS afterwards,
// the same way the bouncer key already does remotely.
const CROWDSEC_MACHINE_ID       = str('CROWDSEC_MACHINE_ID');
const CROWDSEC_MACHINE_PASSWORD = str('CROWDSEC_MACHINE_PASSWORD');
const CROWDSEC_PROM_URL   = str('CROWDSEC_PROMETHEUS_URL') || str('CROWDSEC_PROM_URL');
const CROWDSEC_LOCAL_ONLY = bool('CROWDSEC_LOCAL_ONLY');
const CROWDSEC_CONFIG_FILE = path.join(CONFIG_DIR, 'crowdsec.yml');

// ─── GoAccess ────────────────────────────────────────────────────────────────
const GOACCESS_IMAGE      = str('GOACCESS_IMAGE', 'allinurl/goaccess:latest');
const GOACCESS_LOG_FORMAT = str('GOACCESS_LOG_FORMAT', 'COMBINED');
const DIR_GOACCESS        = str('DIR_GOACCESS', '/nginx/goaccess');
const DIR_GOACCESS_DB     = path.join(DIR_GOACCESS, 'db');
const DIR_GOACCESS_CONF   = path.join(DIR_GOACCESS, 'conf');
const GOACCESS_CONTAINER_PREFIX = 'ngx-goaccess-';
const GOACCESS_REFRESH_SEC = int('GOACCESS_REFRESH', 30) || 30;
const GOACCESS_CONFIG_FILE = path.join(CONFIG_DIR, 'goaccess.yml');
// Git config file — the loader itself lives in lib/git.js (getGitCfg()),
// since deploy.js and sync-ref.js both consume it through that module; the
// path alone is exported here for symmetry with the other *_CONFIG_FILE
// constants (config-editor.js's fixed file list, error messages, etc).
const GIT_CONFIG_FILE = path.join(CONFIG_DIR, 'git.yml');

// ─── Blocklists IP (agregation de sources externes) ──────────────────────────
const BLOCKLIST_CONFIG_FILE = path.join(CONFIG_DIR, 'blocklists.yml');
const DEPLOY_TOKENS_FILE    = path.join(CONFIG_DIR, 'deploy-tokens.yml');

// ─── Auto-config Docker (labels façon Traefik) ───────────────────────────────
const DOCKER_AUTOCONFIG_CONFIG_FILE = path.join(CONFIG_DIR, 'docker-autoconfig.yml');

// ─── Hôtes Docker distants (agents) — Partie 2 du document de conception ────
const AGENTS_CONFIG_FILE = path.join(CONFIG_DIR, 'agents.yml');

// ─── Reference sync & version checks ─────────────────────────────────────────
const SYNC_REF_URL      = str('SYNC_REF_URL');
const SYNC_REF_SECTIONS = ['conf', 'sites', 'snippets', 'streams'];
// Optional subfolder inside the reference repo, e.g. "Nginx-RProxy" for a
// layout where conf/sites/snippets/streams sit under that folder instead of
// at the repo root. Empty (the default) matches a repo dedicated entirely to
// these four folders — the recommended layout for a repo used only for this.
const SYNC_REF_PATH_PREFIX = str('SYNC_REF_PATH_PREFIX', '').replace(/^\/+|\/+$/g, '');
const DASHBOARD_VERSION_URL = str('DASHBOARD_VERSION_URL');
const NGINX_VERSION_URL     = str('NGINX_VERSION_URL');

// URL brute (raw.githubusercontent.com, un raccourci Forgejo/GitLab "raw",
// etc.) d'un CHANGELOG.md — sert la modale "Changelog" de la page Systeme
// (v12.41.0, retour utilisateur). Meme mecanisme que DASHBOARD_VERSION_URL/
// SYNC_REF_URL ci-dessus : injectable au build via ARG (voir Dockerfile),
// surchargeable a l execution via .env. Vide par defaut — la modale l
// explique plutot que d afficher une erreur si l operateur ne l a pas
// renseignee (le CHANGELOG.md n est pas embarque dans l image : il vit dans
// le depot, a cote du code, et change a chaque version).
const CHANGELOG_URL = str('CHANGELOG_URL');

// URL brute d'un fichier Markdown de "messages importants" (maintenance
// planifiee, incident en cours, annonce...) — voir features/alerting.js
// (v12.45.0, retour utilisateur). Meme mecanisme que CHANGELOG_URL
// ci-dessus : pas embarque dans l image, injectable au build via ARG (voir
// Dockerfile), surchargeable a l execution. Vide par defaut : aucun appel
// reseau, aucune alerte possible tant que l operateur ne l a pas renseignee
// — independant du toggle ALERTING_ENABLE (voir lib/feature-flags.js) pour
// qu un operateur puisse desactiver la fonctionnalite sans avoir a effacer
// l URL (utile si elle est injectee au build, commune a toute une flotte
// d images, et que seule une instance doit la desactiver).
const ALERTING_URL = str('ALERTING_URL');
// Intervalle (minutes) entre deux verifications du fichier ci-dessus par le
// planificateur serveur (features/alerting.js#startScheduler()) — minimum
// impose a 5 min pour ne jamais marteler une URL publique par erreur de
// configuration (ex. "0"). Le client (public/assets/js/alerting.js) ne
// recharge lui-meme que ce que le serveur a deja recupere : c est bien ce
// reglage, pas un intervalle cote navigateur, qui fixe la frequence reelle
// des appels sortants.
const ALERTING_POLL_INTERVAL_MIN = Math.max(5, int('ALERTING_POLL_INTERVAL_MIN', 60));

// ─── Branding (serialised into the page as window.BRANDING) ──────────────────
const BRANDING = {
  kofi:      str('BRANDING_KOFI'),
  kofiLabel: str('BRANDING_KOFI_LABEL', 'Support on Ko-fi'),
  site:      str('BRANDING_SITE'),
  siteLabel: str('BRANDING_SITE_LABEL'),
  repo:      str('BRANDING_REPO'),
  repoLabel: str('BRANDING_REPO_LABEL', 'Source repository'),
  doc:       str('BRANDING_DOC'),
  docLabel:  str('BRANDING_DOC_LABEL', 'Documentation'),
  // Texte libre affiche dans l en-tete, entre le nom "Nginx Control" et les
  // badges de version — pour distinguer un environnement (nom de client,
  // "STAGING", etc.) directement dans l en-tete sans toucher au code.
  headerText: str('BRANDING_HEADER_TEXT'),
};

// ─── File type sets ──────────────────────────────────────────────────────────
const CONF_EXTS = new Set(['.conf', '.DISABLE', '.sample', '.inc', '.nginx', '.txt']);
const CERT_EXTS = new Set(['.cer', '.crt', '.pem']);

module.exports = Object.freeze({
  VERSION,
  PORT, NGINX_VTS_URL, NGINX_CONTAINER, NGINX_IMAGE, NGINX_CONF_FILE, NGINX_NETWORK,
  TRUSTED_PROXIES, NOTIF_POLL_INTERVAL_SEC,
  INSTANCE_ID, SESSION_SECRET, SESSION_TTL_MS, SESSION_ABSOLUTE_MAX_MS, GENERATED_SECRETS_FILE,
  API_TOKEN, API_TOKEN_ENABLED, WEBHOOK_SECRET, WEBHOOK_SECRET_SET,
  readGeneratedSecrets, persistGeneratedSecret, clearGeneratedSecret,
  apiTokenActive, verifyApiToken, getWebhookSecret, isWebhookSecretConfigured,
  LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS, LOGIN_LOCKOUT_MS, CORS_ORIGIN,
  USERS_FILE, CONFIG_DIR, SMTP_CONFIG_FILE, NOTIF_CONFIG_FILE, SCHED_CONFIG_FILE,
  CERTBOT_CONFIG_FILE, CERTBOT_DNS_CONFIG_FILE, GODNS_CONFIG_FILE, GEOIPUPDATE_CONFIG_FILE, ERROR_PAGES_CONFIG_FILE,
  MENU_CONFIG_FILE, FEATURES_CONFIG_FILE, GODNS_IP_CHECK, GODNS_IP_CHECK_URLS,
  ANALYZER_DEFAULT_IMAGE,
  EVENTS_DB_PATH, EVENTS_RETENTION_DAYS,
  MONITOR_DB_PATH, MONITOR_RETENTION_DAYS,
  NOTIF_CENTER_DB_PATH, NOTIF_CENTER_RETENTION_DAYS,
  DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL, DIR_CERTS, DIR_LOGS,
  DIR_CACHE, DIR_BACKUPS, DIR_GIT_WORK, HOST_LOGS, HOST_GOACCESS,
  GIT_REPO_URL, GIT_BRANCH, GIT_BACKUP_BRANCH, GIT_SSH_KEY, GIT_TOKEN,
  GIT_USER_NAME, GIT_USER_EMAIL, GIT_CONFIG_FILE, BLOCKLIST_CONFIG_FILE, DEPLOY_TOKENS_FILE, CHALLENGE_CONFIG_FILE, CHALLENGE_DEFAULT_IMAGE, ANUBIS_DEFAULT_IMAGE, HTTP_USER_AGENT,
  NC_SECRET, NC_DIFFICULTY_BITS, NC_COOKIE_HOURS, NC_GOODBOTS, NC_GOODBOTS_EXTRA, NC_LANG,
  DOCKER_AUTOCONFIG_CONFIG_FILE, AGENTS_CONFIG_FILE, BACKUP_KEEP,
  ALLOW_EDIT, ALLOW_CREATE, DEPLOY_SYNC_SSL,
  DOCKER_SOCKET, GEOIP_CITY_DB, GEOIP_COUNTRY_DB, GEOIP_ASN_DB, DIR_GEOIP,
  CROWDSEC_URL, CROWDSEC_API_KEY, CROWDSEC_MACHINE_ID, CROWDSEC_MACHINE_PASSWORD,
  CROWDSEC_PROM_URL, CROWDSEC_LOCAL_ONLY, CROWDSEC_CONFIG_FILE,
  GOACCESS_IMAGE, GOACCESS_LOG_FORMAT, DIR_GOACCESS, DIR_GOACCESS_DB,
  DIR_GOACCESS_CONF, GOACCESS_CONTAINER_PREFIX, GOACCESS_REFRESH_SEC, GOACCESS_CONFIG_FILE,
  SYNC_REF_URL, SYNC_REF_SECTIONS, SYNC_REF_PATH_PREFIX, DASHBOARD_VERSION_URL, NGINX_VERSION_URL,
  CHANGELOG_URL,
  ALERTING_URL, ALERTING_POLL_INTERVAL_MIN,
  BRANDING, CONF_EXTS, CERT_EXTS,
});
