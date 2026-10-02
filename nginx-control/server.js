'use strict';
/**
 * nginx-dashboard — entry point.
 *
 * v12 splits the former single file into lib/ (foundation) and, progressively,
 * features/ (one domain per file, routes living next to their logic). Anything
 * still inline below is awaiting extraction.
 *
 * Load order matters: every module is required before the boot sequence runs,
 * so a constant can never be referenced before it exists — a failure mode that
 * bit this project repeatedly when code was appended past the boot call.
 */

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

// ─── Foundation ──────────────────────────────────────────────────────────────
const cfg     = require('./lib/config');
const httpLib = require('./lib/http');
const auth    = require('./lib/auth');
const docker  = require('./lib/docker');
const tree    = require('./lib/fs-tree');
const secrets = require('./lib/secrets');
const events  = require('./lib/events');
const { validateWebhookUrl } = require('./lib/ssrf-guard');
const pageRoutes = require('./lib/page-routes');

// Wire the pieces that must not import each other directly: auth emits login
// events, but events must not depend on auth for permissions.
auth.setEventLogger(events.logEvent);

// ─── Names used throughout the (still inline) feature code ───────────────────
// Re-exported locally so the code below reads unchanged during the migration.
const {
  VERSION, PORT, NGINX_VTS_URL, NGINX_CONTAINER, NGINX_IMAGE, NGINX_CONF_FILE,
  NGINX_NETWORK, SESSION_SECRET, SESSION_TTL_MS, API_TOKEN, API_TOKEN_ENABLED,
  WEBHOOK_SECRET, WEBHOOK_SECRET_SET, USERS_FILE, CONFIG_DIR,
  SMTP_CONFIG_FILE, NOTIF_CONFIG_FILE, SCHED_CONFIG_FILE, CERTBOT_CONFIG_FILE,
  GODNS_CONFIG_FILE, EVENTS_DB_PATH, EVENTS_RETENTION_DAYS,
  DIR_SITES, DIR_CONF, DIR_SNIPPETS, DIR_STREAMS, DIR_SSL, DIR_CERTS, DIR_LOGS,
  DIR_CACHE, DIR_BACKUPS, DIR_GIT_WORK, HOST_LOGS, HOST_GOACCESS,
  GIT_REPO_URL, GIT_BRANCH, GIT_BACKUP_BRANCH, GIT_SSH_KEY, GIT_TOKEN,
  GIT_USER_NAME, GIT_USER_EMAIL, BACKUP_KEEP, ALLOW_EDIT, DEPLOY_SYNC_SSL,
  DOCKER_SOCKET, GEOIP_CITY_DB, GEOIP_COUNTRY_DB, GEOIP_ASN_DB,
  CROWDSEC_URL, CROWDSEC_API_KEY, CROWDSEC_PROM_URL, CROWDSEC_LOCAL_ONLY,
  GOACCESS_IMAGE, GOACCESS_LOG_FORMAT, DIR_GOACCESS, DIR_GOACCESS_DB,
  DIR_GOACCESS_CONF, GOACCESS_CONTAINER_PREFIX, GOACCESS_REFRESH_SEC,
  SYNC_REF_URL, SYNC_REF_SECTIONS, DASHBOARD_VERSION_URL, NGINX_VERSION_URL,
  BRANDING, CONF_EXTS, CERT_EXTS, NOTIF_POLL_INTERVAL_SEC,
} = cfg;

const { PERMS, ROLE_PERMS, roleHasPerm, hasPerm, hashPassword, verifyPassword,
        needsRehash, safeCompare, verifyCredentials, loadUsers, findUser, getUsers, saveUsers,
        upgradePasswordHash, parseYmlUsers, rewriteUsersFile, createSession,
        validateSession, destroySession, sessions, checkLoginRate,
        recordLoginFailure, clearLoginFailures, parseCookies, setCookieHeader,
        clearCookieHeader, getTokenFromReq, getSessionFromReq, requireSession,
        requireApiAuth, authenticateQueryToken, authenticateDeployToken, authenticateAgentToken, authenticateCertsyncToken,
        loginOriginAllowed } = auth;

const { send, parseBody, readRawBody, clientIp, Router } = httpLib;

const { dockerCall, getContainerLogs, demuxStream, demuxToText, resolveContainer,
        getContainerId, invalidateContainerId, getSelfMounts, toHostPath,
        execNginx } = docker;
// Historic name for the ephemeral-test network helper.
const getTestNetworkMode = docker.getNginxNetworkMode;

const { safeStat, isProtectedFile, hasProtectedSegment, listTreeFiles, copyTree,
        pruneEmptyDirs, safeResolveWithin, isDirWritable } = tree;

const { SECRET_KEY_RE, MASK_PLACEHOLDER, maskSecretsInConfig, unmaskSecrets } = secrets;

// Log enrichment still lives in the legacy chain; it will move with the logs
// feature. server.js is the composition root, so importing a feature here is
// acceptable — features themselves never import each other.
const { geoipCached } = require('./lib/geoip');
const { fetchVTS, startPolling } = require('./features/metrics');
const logsFeature = require('./features/logs');
const { listConfDir } = require('./features/configs');
const notify = require('./lib/notify');
const { getCertbotCfg, ensureRenewalContainerAtBoot, issueCertificate: issueCertbotHttp, resolveWebrootNginxPath } = require('./features/certbot');
const { ensureContainerAtBoot: ensureCertbotDnsContainerAtBoot, getCertbotDnsCfg, issueCertificate: issueCertbotDns } = require('./features/certbot-dns');
const { getGoDNSCfg, getGoDNSConfigFilePath } = require('./features/godns');
const { ensureContainerAtBoot: ensureGeoipupdateContainerAtBoot } = require('./features/geoipupdate');
const { ensureContainerAtBoot: ensureErrorPagesContainerAtBoot } = require('./features/error-pages');
const { ensureContainerAtBoot: ensureChallengeContainerAtBoot } = require('./features/challenge-container');
const goaccessFeature   = require('./features/goaccess');
const deployFeature     = require('./features/deploy');
const { deployFromGit, deployFromGitWork, cleanLegacyTestDirs } = deployFeature;
const { createBackupZip, listBackups } = require('./lib/backup');
const { gitBackupPush, runCmd, getGitCfg } = require('./lib/git');
const { getCrowdsecCfg } = require('./lib/crowdsec-cfg');
const { getGoaccessCfg } = goaccessFeature;
const { listGoAccessSources, getGoAccessContainerStatus, restartGoAccessContainer,
        pullGoAccessImage } = goaccessFeature;
const { sendMail, sendNotification, loadSmtpConfig, loadNotifConfig, loadSchedConfig } = notify;
const { listSSLSnippets, listSnippetsWithMeta } = require('./lib/snippets');

// Certificate helpers, still used by the legacy chain (certbot, notifications).
// They move out with their own features; lib/certs is the shared home.
const { parseCert, parseCertSANs, listExistingCerts, checkDomainConflict,
        getAllCertificates } = require('./lib/certs');
const { safeReadDir, safeReadFile } = tree;

const { eventLog, webhooks, logEvent, queryEvents, clearEvents, recentEvents,
        initEventsDb, persistEvent, fireWebhook } = events;

// ─── Static assets (public/assets — extracted pieces of index.html) ──────────
const STATIC_ASSETS_DIR = path.join(__dirname, 'public', 'assets');
// .woff2 added in v12.30.0 alongside assets/fonts/ and assets/vendor/ — the
// dashboard now self-hosts its font files and Chart.js instead of loading
// them from fonts.googleapis.com/fonts.gstatic.com/cdn.jsdelivr.net (see
// CHANGELOG for why: those hosts were never in the CSP's script-src/font-src
// to begin with, silently breaking the chart and the chosen typography for
// any operator without unrestricted outbound access from the browser).
const STATIC_ASSET_TYPES = { '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.woff2': 'font/woff2' };

// ─── Deep-linking (v12.31.0) ───────────────────────────────────────────────
// Une URL directe par page ("/map", "/live-logs", ...) est une SPA route :
// le NAVIGATEUR envoie une vraie requête HTTP sur un F5, un lien direct ou
// un favori — il n'y a alors aucun JavaScript encore chargé pour "router"
// quoi que ce soit. Ce n'importe quel de ces chemins doit donc recevoir le
// même index.html que "/" (même contrôle de session), pour que le JS puisse
// ensuite lire l'URL et afficher la bonne page. Liste blanche dérivée de
// lib/page-routes.js (source de vérité unique, aussi injectée au client via
// window.PAGE_ROUTES ci-dessous) plutôt qu'une règle générale — un chemin
// qui n'y figure pas continue de faire un 404 propre.
const DEEP_LINK_PATHS = new Set(Object.keys(pageRoutes.SLUG_TO_PAGE).map(slug => '/' + slug));

// ─── Core helpers ─────────────────────────────────────────────────────────────


// Docker socket path (can be overridden via env)


// Resolve container: find by exact name OR by name containing NGINX_CONTAINER
// Handles docker-compose prefixes (e.g. "nginx-rproxy-nginx-1", "mystack_nginx_1")


/**
 * Execute a command in the nginx container via Docker HTTP API (Unix socket).
 * Uses the exec endpoint: POST /containers/{id}/exec → POST /exec/{id}/start
 * Falls back to CLI if socket not available.
 */


/**
 * Resolve a user-supplied path and guarantee it stays inside one of `bases`.
 * Returns the normalized absolute path, or null if it escapes (../, symlink-ish,
 * or plain prefix trickery like "/nginx/logs/../../etc/shadow").
 */
/** Mask secret-looking values in a YAML/JSON config before sending it to a client. */
// Groups: 1=indent 2=openQuote 3=key 4=":" separator 5=value 6=trailing comma (JSON)


/**
 * Re-inject real secret values when the client sends back a masked config.
 * Without this, saving a masked view would overwrite passwords with "********".
 */


// Cross-origin access is opt-in. Default is same-origin only: the dashboard is
// served from the same host, and a wildcard here only widens the attack surface.
const CORS_ORIGIN = (process.env.CORS_ORIGIN || '').trim();


// ─── Filesystem helpers ───────────────────────────────────────────────────────


// ─── SSL helpers ──────────────────────────────────────────────────────────────


// ─── Log file helpers ─────────────────────────────────────────────────────────


// ─── Login page HTML ──────────────────────────────────────────────────────────
function loginPage(error = '', lang = 'en') {
  const L = lang === 'fr' ? {
    title: 'Connexion', sub: 'Authentification requise',
    user: 'Identifiant', pass: 'Mot de passe', btn: 'Se connecter'
  } : {
    title: 'Sign in', sub: 'Authentication required',
    user: 'Username', pass: 'Password', btn: 'Sign in'
  };

  // Fix (audit finding, Basse/"Sécurité et durcissement"): this page used to
  // load Google Fonts (fonts.googleapis.com/fonts.gstatic.com) BEFORE any
  // authentication — every visitor's browser made a third-party request just
  // to render the login screen, for no functional need (the dashboard's
  // theme survives fine on a system font stack). Removed here rather than on
  // the authenticated dashboard UI (public/index.html), which the audit
  // finding does not flag and where an operator may reasonably want the
  // exact original typography.
  const SANS_STACK = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
  const MONO_STACK  = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace";
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx Control — Connexion</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:#0a0b0d;display:flex;align-items:center;justify-content:center;font-family:${SANS_STACK}}
.wrap{width:100%;max-width:380px;padding:20px}
.card{background:#14171d;border:1px solid #ffffff0f;border-radius:14px;padding:40px 36px}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;justify-content:center}
.logo-icon{width:36px;height:36px;background:#00e87a;border-radius:8px;display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:20px;height:20px;fill:none;stroke:#000;stroke-width:2.5;stroke-linecap:round}
.logo-text{font-size:20px;font-weight:800;color:#e8eaf0;letter-spacing:-.5px}
h1{font-size:15px;font-weight:700;color:#e8eaf0;margin-bottom:6px;text-align:center}
.sub{font-size:12px;color:#5a6278;text-align:center;margin-bottom:28px;font-family:${MONO_STACK}}
label{display:block;font-family:${MONO_STACK};font-size:11px;color:#5a6278;letter-spacing:.3px;margin-bottom:5px}
input{width:100%;background:#1c202a;border:1px solid #ffffff18;border-radius:6px;color:#e8eaf0;font-family:${MONO_STACK};font-size:13px;padding:10px 14px;outline:none;transition:.15s;margin-bottom:16px}
input:focus{border-color:#00e87a;box-shadow:0 0 0 2px #00e87a22}
button{width:100%;padding:12px;background:#00e87a;color:#000;font-family:${SANS_STACK};font-size:14px;font-weight:700;border:none;border-radius:6px;cursor:pointer;transition:.15s;margin-top:4px}
button:hover{background:#00ff85}
.error{background:#ff4d6a22;border:1px solid #ff4d6a44;border-radius:6px;color:#ff4d6a;font-family:${MONO_STACK};font-size:12px;padding:10px 14px;margin-bottom:16px;display:${error ? 'block' : 'none'}}
</style></head><body>
<div class="wrap"><div class="card">
  <div class="logo">
    <div class="logo-icon"><svg viewBox="0 0 16 16"><polyline points="2,12 5,7 8,9 11,4 14,6"/></svg></div>
    <div class="logo-text">Nginx Control</div>
  </div>
  <h1>Connexion</h1>
  <div class="sub">Authentification requise</div>
  <div class="error">${error}</div>
  <form method="POST" action="/auth/login">
    <label>${L.user}</label>
    <input type="text" name="username" autocomplete="username" autofocus required>
    <label>${L.pass}</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">${L.btn}</button>
  </form>
</div>
</div>
</body></html>`;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────
// The fixed set of routes a scoped CI/CD deploy token (lib/deploy-tokens.js)
// may ever authenticate for — see the dispatch below and
// lib/auth.js's authenticateDeployToken(). Deliberately a hardcoded literal
// list, not derived from PERMS.DEPLOY or the router: a permission bit or a
// route table can grow over time for unrelated reasons, and this allowlist
// must not grow along with it by accident. Extending what a deploy token can
// reach is a deliberate security decision, made here, in one place.
const DEPLOY_TOKEN_ROUTES = new Set([
  'POST /api/git/pull',
  'POST /api/git/test',
  'POST /api/git/deploy',
  'GET /api/git/status',
  'POST /api/backups',
]);

// The ONE route a remote agent's own scoped bearer token (Partie 2 —
// lib/agents-store.js) may ever authenticate for — same fixed-allowlist
// containment as DEPLOY_TOKEN_ROUTES just above, and for the same reason:
// this must be a deliberate, reviewable list, never derived from PERMS or
// the router, so it cannot silently grow as unrelated routes are added.
const AGENT_TOKEN_ROUTES = new Set([
  'POST /api/agent/manifest',
]);

// Les trois routes qu'un jeton de synchronisation de certificats
// (lib/certsync-store.js, v12.59.0) peut atteindre — liste fixe, même
// confinement que ci-dessus : la portée (pull/push) et les noms autorisés sont
// ensuite contrôlés par features/certsync.js.
const CERTSYNC_TOKEN_ROUTES = new Set([
  'GET /api/certsync/list',
  'GET /api/certsync/pull',
  'POST /api/certsync/push',
]);

// ─── Route registry ──────────────────────────────────────────────────────────
// Features register their own routes here. Anything not matched falls through
// to the legacy if-chain below, which shrinks with each extracted feature.
const router = new Router();
const FEATURES = [
  require('./features/cache'),
  require('./features/users'),
  require('./features/geoip'),
  require('./features/ssl'),
  require('./features/certsync'),
  require('./features/crowdsec'),
  require('./features/metrics'),
  require('./features/logs'),
  require('./features/configs'),
  require('./features/vhost-generator'),
  require('./features/notifications'),
  require('./features/certbot'),
  require('./features/certbot-dns'),
  require('./features/godns'),
  require('./features/geoipupdate'),
  require('./features/error-pages'),
  require('./features/challenge-container'),
  require('./features/goaccess'),
  require('./features/sync-ref'),
  require('./features/deploy'),
  require('./features/nginx-control'),
  require('./features/analyzer'),
  require('./features/analyzer-rules'),
  require('./features/digest'),
  require('./features/scheduler'),
  require('./features/config-editor'),
  require('./features/backends'),
  require('./features/audit'),
  require('./features/monitor'),
  require('./features/system-info'),
  require('./features/notification-center'),
  require('./features/blocklists'),
  require('./features/docker-autoconfig'),
  require('./features/agents'),
  require('./features/menu-config'),
  require('./features/changelog'),
  require('./features/alerting'),
  require('./features/containers'),
];
for (const f of FEATURES) f.register(router);

// Blocklists IP — the two nginx snippets (blocklist-ips.conf,
// blocklist-enforce.conf) must exist and be syntactically valid the moment
// any vhost's `include` line could be read, i.e. before this process can
// possibly trigger (or race) an nginx reload. Called synchronously, here,
// ahead of every other feature's boot-time container/polling work below.
const blocklistsFeature = require('./features/blocklists');
blocklistsFeature.ensureSnippetsAtBoot();
blocklistsFeature.startBlocklistScheduler();

// Auto-config Docker (labels façon Traefik, étape 1 "socle") — own poll
// scheduler, same pattern as blocklists above. No boot-time placeholder
// files needed here: unlike blocklist-enforce.conf (referenced by an
// operator's own vhost `include`), a docker_*.conf only ever exists once a
// labelled container is actually detected, so there is nothing to race.
const dockerAutoconfigFeature = require('./features/docker-autoconfig');
dockerAutoconfigFeature.startScheduler();
dockerAutoconfigFeature.startEventsWatcher();

// Message important (alertes distantes) — own poll scheduler, same
// self-contained pattern as blocklists/docker-autoconfig above. Checks its
// own enable flag (lib/feature-flags.js) on every tick, so toggling
// ALERTING_ENABLE/config/features.yml takes effect without a restart.
require('./features/alerting').startScheduler();

// Hôtes Docker distants (agents, Partie 2 "fondations") — no boot-time
// scheduler of its own: unlike Partie 1's poll loop, this feature is purely
// reactive to whatever an agent pushes (POST /api/agent/manifest is its own
// heartbeat) — nothing to start here beyond routing, see features/agents.js.
const agentsFeature = require('./features/agents');

// Tunnel NAT sortant (Partie 2 "avance", mode 3) — aucune route Router
// (l'upgrade WebSocket et l'interception de trafic tunnel sont branches
// directement, voir plus bas et handleRequest() ci-dessus), donc pas dans
// FEATURES : ce module n'a pas de register(router) a appeler.
const agentTunnelFeature = require('./features/agent-tunnel');
agentsFeature.setDeps({
  isTunnelConnected: agentTunnelFeature.isConnected,
  // Fix (audit report, Basse/"Agents (dashboard)"): revoking an agent or
  // regenerating its token used to leave any already-open tunnel connection
  // alive — a client mid-conversation kept being served through it, and
  // worse, the OLD token stays valid for authenticating the tunnel's own
  // http-request/http-response protocol frames for as long as that socket
  // stays up, even though lib/agents-store.js's tokenHash was already
  // cleared/replaced. See features/agents.js's own call sites for the two
  // triggers (revoke, regenerate-token).
  closeTunnel: agentTunnelFeature.closeConnection,
});

// Wire the cross-feature dependency: sync-ref triggers a deployment, but
// features never import each other — server.js is the composition root.
// L analyseur tourne dans son propre conteneur ; le dashboard remonte ses
// alertes dans le journal d evenements et par courriel.
const analyzerFeature = require('./features/analyzer');
setTimeout(() => analyzerFeature.startAlertPolling(), 5000);

const scheduler = require('./lib/scheduler');
scheduler.setTasks({
  createBackupZip:            require('./lib/backup').createBackupZip,
  gitBackupPush:              require('./lib/git').gitBackupPush,
  restartAnalyzer:            analyzerFeature.restartAnalyzer,
  runCertsync:                require('./features/certsync').runSync,
  listCertsyncRemotes:        require('./features/certsync').listRemotesForScheduler,
  listGoAccessSources:        goaccessFeature.listGoAccessSources,
  getGoAccessContainerStatus: goaccessFeature.getGoAccessContainerStatus,
  restartGoAccessContainer:   goaccessFeature.restartGoAccessContainer,
  // Fix (audit report, Basse/"Agents (dashboard)"): give remote agents'
  // vhosts the same periodic SSL re-check Docker auto-config's own poll
  // cycle already gives Partie 1's — see lib/scheduler.js's own comment on
  // this task, and features/agents.js#listAgentsNeedingSslRecheck().
  listAgentsNeedingSslRecheck: agentsFeature.listAgentsNeedingSslRecheck,
  reapplyAgentManifest:        agentsFeature.reapplyAgentManifest,
});

// The digest (lib/digest.js) composes data from the analyzer (a feature
// module) and CrowdSec (another feature module) — lib/ modules never import
// features/ directly, so this wiring, like the scheduler's above, happens
// once here at the composition root instead.
require('./lib/digest').configure({
  analyzerApi:         analyzerFeature.analyzerApi,
  crowdsecGet:          require('./features/crowdsec').crowdsecGet,
  crowdsecConfigured:   require('./features/crowdsec').crowdsecConfigured,
  getBlocklistStats:    (opts) => blocklistsFeature.getDigestStats(opts),
});

// blocklists.js reads the analyzer's blocklist-hits window summary
// (getHitStats()) and, since v12.29.0, pushes its own per-source IP/CIDR
// cache to the analyzer on a timer (pushBlocklistSources()) so the analyzer
// can attribute hits to a source and, in "approx" mode, detect them itself
// straight from the access log(s) it already tails.
blocklistsFeature.setDeps({
  analyzerApi: analyzerFeature.analyzerApi,
  analyzerApiJson: analyzerFeature.analyzerApiJson,
  // v12.50.0 : meme source de verite que pushVhostRules() pour savoir quels
  // vhosts ont opte pour "# nginx-control-analyze-no-remediation: on" — voir
  // computeAnalyzerBlocklist() dans features/blocklists.js.
  buildVhostRulesMap: analyzerFeature.buildVhostRulesMap,
});

require('./features/sync-ref').setDeployHandlers({
  fromGit:     deployFromGit,
  fromGitWork: deployFromGitWork,
});

// Wire configs.js's own cross-feature dependencies the same way: it needs
// deploy.js's ephemeral config test (to validate a new/edited file before it
// ever reaches the live directories) and sync-ref.js's reference-file lookup
// (to refuse editing a file that's supposed to come from Git instead).
require('./features/configs').setDeps({
  testConfigEphemeral: deployFeature.testConfigEphemeral,
  fetchRefFileList:    require('./features/sync-ref').fetchRefFileList,
});

// nginx-control.js: the "test in an ephemeral container" action runs the same
// sandbox as the Git test and the config editor (features/deploy.js).
require('./features/nginx-control').setDeps({
  testConfigEphemeral: deployFeature.testConfigEphemeral,
});

// monitor.js reuses the exact same probe as the on-demand backend check
// rather than a second implementation of it — same wiring pattern.
require('./features/monitor').setDeps({
  checkTarget: require('./features/backends').checkTarget,
});
// audit.js's live header probe (proxy side + backend side) is the same
// probe again, just aimed at nginx itself for the proxy side.
require('./features/audit').setDeps({
  checkTarget: require('./features/backends').checkTarget,
});

// Auto-config Docker's certbot_http/certbot_dns SSL modes must know whether
// Certbot (or Certbot-DNS) is actually configured/activated upstream before
// leaning on it — composition-root wiring, same reason deploy.js's
// generatedFiles is injected below rather than required directly.
// Fix (audit report, Basse/"Partie 1 et certificats"): the nginx path
// certbot's HTTP-01 challenge is actually served from, only when that
// challenge is configured AND enabled — same shape as getCertbotCfg/
// getCertbotDnsCfg above, resolved lazily so a later enable/disable via the
// config file is picked up on the very next vhost-generation cycle.
const getCertbotWebrootPath = () => {
  const c = getCertbotCfg();
  return c?.enable ? resolveWebrootNginxPath(c) : null;
};

dockerAutoconfigFeature.setDeps({
  getCertbotCfg,
  getCertbotDnsCfg,
  // v12.16.0 : declenchement actif d une emission Certbot/Certbot-DNS depuis
  // un label (voir features/docker-autoconfig.js#triggerCertbotIssuanceIfDue).
  // Reutilise exactement la meme logique (conflit de domaine, journal
  // d evenements, notification) que les routes /api/certbot/issue et
  // /api/certbot-dns/issue elles-memes, sans round-trip HTTP interne.
  issueHttp: issueCertbotHttp,
  issueDns: issueCertbotDns,
  getCertbotWebrootPath,
});

// Meme wiring pour les agents distants (v12.21.0 — voir
// features/agents.js#resolveAgentSsl(), miroir exact de resolveSsl()
// ci-dessus pour sslCertificate=certbot_http/certbot_dns cote Partie 2).
agentsFeature.setDeps({
  getCertbotCfg,
  getCertbotDnsCfg,
  issueHttp: issueCertbotHttp,
  issueDns: issueCertbotDns,
  getCertbotWebrootPath,
});

// deploy.js's Git-driven full sync must never delete, and must see present
// during its ephemeral nginx -t test, files another feature generates at
// runtime inside the directories it mirrors — blocklists.js's generated
// nginx snippets are the first case (see features/deploy.js's isGeneratedFile()).
// A function, not a static array: features/docker-autoconfig.js's own list
// changes at runtime (one file per labelled container, appearing/disappearing
// as containers start/stop) — see features/deploy.js's getGeneratedFilesList()
// for how either shape is resolved, and isGeneratedFile()'s prefix check for
// the belt-and-suspenders fallback that covers a momentarily-stale list.
deployFeature.setDeps({
  generatedFiles: () => [
    ...blocklistsFeature.getGeneratedFiles(),
    ...dockerAutoconfigFeature.getGeneratedFiles(),
    ...agentsFeature.getGeneratedFiles(),
  ],
});

console.log(`[router] ${router.list().length} route(s) from ${FEATURES.length} feature module(s)`);

const server = http.createServer((req, res) => {
  // Le gestionnaire est asynchrone : sans ce garde, une exception devient une
  // promesse rejetee non geree, et Node 22 termine alors le processus. Le
  // conteneur redemarre, la table des sessions en memoire est videe, et tout le
  // monde se retrouve sur la page de connexion.
  handleRequest(req, res).catch(err => {
    console.error(`[http] ${req.method} ${req.url}:`, err);
    if (!res.headersSent) {
      try { send(res, 500, { error: 'Internal error' }); } catch { try { res.end(); } catch {} }
    } else {
      try { res.end(); } catch {}
    }
  });
});

async function handleRequest(req, res) {
  const url      = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  // Fix v12.21.1 (audit finding SEC-05): this used to be a local, unguarded
  // "leftmost X-Forwarded-For" reimplementation that shadowed the imported
  // httpLib.clientIp() for this entire function — so fixing clientIp() alone
  // would not have closed the bypass. Now the one, trusted-proxy-aware
  // implementation is used everywhere, including here.
  const reqClientIp = clientIp(req);

  // Trafic tunnel (Partie 2, mode 3) : une requete pour le vhost publie par
  // un agent distant arrive ici comme une requete HTTP tout a fait normale
  // (nginx fait un simple proxy_pass vers ce dashboard, voir
  // config/agents.yml#tunnel_target) — reconnue par son Host, jamais par un
  // chemin /api/, donc verifiee avant TOUT le reste (avant meme OPTIONS, un
  // vhost distant pouvant tout a fait servir une API avec CORS).
  if (await agentTunnelFeature.maybeHandleTunnelRequest(req, res)) return;

  if (req.method === 'OPTIONS') return send(res, 204, '');

  // ── Static assets (CSS/JS split out of the single index.html) ─────────────
  // Public, unauthenticated — same as any other static asset a browser
  // fetches before it even has a session cookie. No user data, no secrets,
  // nothing dynamic: just what used to be inlined inside index.html's
  // <style>/<script> tags, one file per extracted piece. Still resolved
  // safely rather than trusting the URL directly, the same discipline as
  // every other path built from a request in this codebase.
  if (pathname.startsWith('/assets/') && req.method === 'GET') {
    const rel = pathname.slice('/assets/'.length);
    const filePath = path.join(STATIC_ASSETS_DIR, rel);
    const ext = path.extname(filePath).toLowerCase();
    const ct = STATIC_ASSET_TYPES[ext];
    if (!ct || !filePath.startsWith(STATIC_ASSETS_DIR + path.sep)) {
      return send(res, 404, { error: 'Not found' });
    }
    try {
      return send(res, 200, fs.readFileSync(filePath), ct, { 'Cache-Control': 'no-cache' });
    } catch {
      return send(res, 404, { error: 'Not found' });
    }
  }

  // ── Auth routes (public, no session required) ─────────────────────────────
  if (pathname === '/auth/login') {
    if (req.method === 'GET') { const lc=parseCookies(req);const ql=lc.ngx_lang||'en';return send(res, 200, loginPage('',ql), 'text/html'); }
    if (req.method === 'POST') {
      // Fix (audit finding, Basse/"Sécurité et durcissement"): "login CSRF"
      // — see loginOriginAllowed()'s comment in lib/auth.js. Rejected before
      // any credential is even looked at, and not counted as a failed login
      // (recordLoginFailure), since no real credential guess happened.
      if (!loginOriginAllowed(req)) return httpLib.forbidden(res, 'Origin invalide');

      // Parse application/x-www-form-urlencoded body — bounded (SEC-13 fix,
      // v12.21.1): this route requires no authentication, so an unbounded
      // `d += c` accumulator let a single oversized POST exhaust the
      // process's memory and take every session down with it.
      const body = await readRawBody(req, { limitBytes: 4 * 1024 });
      const params   = new URLSearchParams(body);
      const username = params.get('username')?.trim() || '';
      const password = params.get('password') || '';
      const lc0 = parseCookies(req); const ql0 = lc0.ngx_lang || 'en';

      // Brute-force guard — checked before any password comparison.
      // reqClientIp is now trusted-proxy-aware (SEC-05 fix, v12.21.1): a
      // direct client can no longer reset its own per-IP bucket by sending a
      // different X-Forwarded-For on every attempt.
      const rate = checkLoginRate(reqClientIp, username);
      if (rate.blocked) {
        logEvent('auth.login.blocked', { username, ip: reqClientIp, retryAfterSec: rate.retryAfterSec }, 'auth');
        const mins = Math.ceil(rate.retryAfterSec / 60);
        const msg  = ql0 === 'fr'
          ? `Trop de tentatives. Reessayez dans ${mins} minute(s).`
          : `Too many attempts. Try again in ${mins} minute(s).`;
        return send(res, 429, loginPage(msg, ql0), 'text/html', { 'Retry-After': String(rate.retryAfterSec) });
      }

      // Fix (audit finding, Basse/"Sécurité et durcissement"): user
      // enumeration by timing — see verifyCredentials()'s comment in
      // lib/auth.js. Always spends the same scrypt-shaped CPU time whether
      // or not `username` is real.
      const user = verifyCredentials(username, password);
      if (user) {
        clearLoginFailures(reqClientIp, username);
        // Transparently upgrade legacy sha256 digests to scrypt on successful login
        if (needsRehash(user.password)) upgradePasswordHash(user, password);
        const token = createSession(user, reqClientIp);
        res.writeHead(302, { 'Set-Cookie': setCookieHeader(token, req), 'Location': '/' });
        return res.end();
      }
      // Failed login — log and count it
      recordLoginFailure(reqClientIp, username);
      logEvent('auth.login.failed', { username, ip: reqClientIp }, 'auth');
      { const lc2=parseCookies(req);const ql2=lc2.ngx_lang||'en';const errMsg=ql2==='fr'?'Identifiant ou mot de passe incorrect':'Invalid username or password';return send(res, 200, loginPage(errMsg,ql2), 'text/html'); }
    }
  }

  if (pathname === '/auth/logout') {
    // Fix (audit finding, Basse/"Sécurité et durcissement"): GET used to
    // both destroy the session AND respond, so a plain cross-site navigation
    // (<img src="…/auth/logout">, a redirect, a <link rel=prefetch>) forced
    // a logged-in operator out at will — a real, if low-severity, CSRF (no
    // state-changing route should ever be reachable via GET). Only POST
    // performs the logout now; the dashboard's own logout button sends one
    // (see doLogout() in index.html). GET/HEAD get a no-op redirect to the
    // login page instead of a 405 — simplest safe response for a bookmarked
    // or hand-typed URL, and it reveals nothing an unauthenticated GET to
    // any other page wouldn't already.
    if (req.method !== 'POST') {
      res.writeHead(302, { 'Location': '/auth/login' });
      return res.end();
    }
    const tok = getTokenFromReq(req);
    destroySession(tok);
    res.writeHead(302, { 'Set-Cookie': clearCookieHeader(req), 'Location': '/auth/login' });
    return res.end();
  }

  // ── Dashboard UI (session required) ──────────────────────────────────────
  // v12.31.0 : "/" et "/dashboard" ne sont plus les seuls chemins servis ici
  // — chaque route de deep-linking (DEEP_LINK_PATHS, ex. "/map",
  // "/live-logs") reçoit exactement le même index.html. Volontairement
  // simple : login redirige toujours vers "/" (jamais un "?next=" qui
  // ramènerait sur la page demandée) — après connexion, on atterrit toujours
  // sur Vue d'ensemble, quel que soit le lien qui a déclenché la redirection.
  if (pathname === '/' || pathname === '/dashboard' || DEEP_LINK_PATHS.has(pathname)) {
    const session = requireSession(req);
    if (!session) {
      res.writeHead(302, { 'Location': '/auth/login' });
      return res.end();
    }
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    // Injects window.BRANDING / window.DASHBOARD_VERSION /
    // window.UPDATE_CHECK_URL_CONFIGURED. Why this doesn't just insert before
    // `</head>` — a minifier can and does strip that tag entirely — is
    // explained on injectBeforeFirstScript() itself in lib/http.js.
    // window.NOTIF_POLL_INTERVAL_MS (v12.21.2): lets public/index.html's own
    // notification-center poll run on the operator-configured cadence
    // (NOTIF_POLL_INTERVAL_SEC) instead of a cadence hardcoded in the page.
    // window.PAGE_ROUTES (v12.31.0): the deep-linking slug<->page table,
    // straight from lib/page-routes.js — the client never keeps its own copy
    // that could drift from DEEP_LINK_PATHS above.
    const brandingScript = `<script>window.BRANDING=${JSON.stringify(BRANDING)};window.DASHBOARD_VERSION=${JSON.stringify(RUNTIME_VERSION !== VERSION ? RUNTIME_VERSION : (process.env.APP_VERSION || RUNTIME_VERSION))};window.UPDATE_CHECK_URL_CONFIGURED=${JSON.stringify(!!(DASHBOARD_VERSION_URL||NGINX_VERSION_URL))};window.NOTIF_POLL_INTERVAL_MS=${JSON.stringify(NOTIF_POLL_INTERVAL_SEC * 1000)};window.PAGE_ROUTES=${JSON.stringify({ slugToPage: pageRoutes.SLUG_TO_PAGE, pageToSlug: pageRoutes.PAGE_TO_SLUG })};</script>`;
    html = httpLib.injectBeforeFirstScript(html, brandingScript, 'branding');
    return send(res, 200, html, 'text/html');
  }

  // ── API routes ────────────────────────────────────────────────────────────
  if (!pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });

  // SSE stream uses query token (EventSource can't set headers)
  if (pathname === '/api/nginx-logs/stream') {
    return logsFeature.handleStream(req, res, url);
  }

  // Remote-agent enrollment (Partie 2) is the one API route with no
  // credential at all — an agent's very first contact, before it has been
  // approved and handed a token, cannot present one. Deliberately
  // special-cased here, ahead of the session check below, same treatment as
  // the SSE stream just above; features/agents.js#handleEnroll() only ever
  // creates a 'pending' record — it can never approve itself.
  if (pathname === '/api/agent/enroll' && req.method === 'POST') {
    // Fix v12.22.0 (audit finding AGT-06): handleEnroll() rate-limits per
    // source IP — clientIp() already resolved above (SEC-05, trusted-proxy
    // aware), so the public/unauthenticated enrollment route is not left to
    // trust a raw X-Forwarded-For of its own.
    return agentsFeature.handleEnroll(req, res, reqClientIp);
  }

  // All other API routes: session cookie or the global admin Bearer token
  let session = requireApiAuth(req);
  // Fallback: a scoped CI/CD deploy token (lib/deploy-tokens.js), but ONLY
  // for this fixed, small allowlist of git/backup routes — never a general
  // auth path. This is what actually contains a deploy token to "trigger a
  // deploy", not "do anything PERMS.DEPLOY happens to allow": the route
  // check below runs BEFORE the token is even looked up, so a session with
  // role 'deploy_ci' can never be produced for any other path.
  if (!session && DEPLOY_TOKEN_ROUTES.has(`${req.method} ${pathname}`)) {
    session = authenticateDeployToken(req);
  }
  // Fallback: a remote agent's own scoped token (lib/agents-store.js), but
  // ONLY for its one fixed route — same containment reasoning as the deploy
  // token just above, see AGENT_TOKEN_ROUTES's own comment.
  if (!session && AGENT_TOKEN_ROUTES.has(`${req.method} ${pathname}`)) {
    session = authenticateAgentToken(req);
  }
  // Jeton de synchronisation de certificats : uniquement ses trois routes.
  if (!session && CERTSYNC_TOKEN_ROUTES.has(`${req.method} ${pathname}`)) {
    session = authenticateCertsyncToken(req);
    if (session) session.ip = reqClientIp;
  }
  if (!session) return send(res, 401, { error: 'Unauthorized. Login at /auth/login or pass Authorization: Bearer <token>.' });

  // SECURITY (fix, audit finding SEC-12): CSRF guard for state-changing
  // requests authenticated purely via the automatically attached session
  // cookie. SameSite=Strict already blocks most cross-site cookie-carrying
  // requests, but SameSite governs the registrable domain, not the exact
  // origin — a malicious or compromised sibling vhost served by this SAME
  // reverse proxy (same registrable domain, different origin) still gets
  // the cookie attached. Two checks close that gap:
  //  1. Content-Type must be application/json — every API POST/PUT/DELETE
  //     this dashboard's own frontend makes already sends it (see the `api()`
  //     helper in index.html); a cross-site <form> POST or a "simple
  //     request" fetch() cannot set it without triggering a CORS preflight
  //     this server does not answer for an unlisted origin.
  //  2. Origin (or, lacking that, Referer), when the browser sends one,
  //     must match this request's own Host.
  // Authorization-header auth (the global API token, a deploy token, an
  // agent token) is exempt: a cross-origin page cannot attach an arbitrary
  // header without our CORS policy already allowing it, which it does not
  // by default, so none of those are CSRF-exploitable in the first place —
  // and a legitimate non-browser API client has no reason to send an Origin
  // a browser would, nor to always use application/json.
  if (!req.headers['authorization'] && req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
    const ct = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') {
      return send(res, 403, { error: 'Content-Type application/json requis' });
    }
    const originHeader = req.headers['origin'] || req.headers['referer'];
    if (originHeader) {
      let originHost = null;
      try { originHost = new URL(originHeader).host; } catch { /* en-tete malforme : traite comme absent ci-dessous */ }
      if (originHost && originHost !== req.headers.host) {
        return send(res, 403, { error: 'Origin invalide' });
      }
    }
  }

  // Registered feature routes take precedence over the legacy chain.
  const handler = router.match(req.method, pathname);
  if (handler) {
    try {
      return await handler({ req, res, session, url, pathname, clientIp: reqClientIp });
    } catch (e) {
      console.error(`[router] ${req.method} ${pathname}:`, e);
      if (!res.headersSent) return httpLib.serverError(res, e);
      return;
    }
  }

  // ── /api/auth/me — current session info ─────────────────────────────────
  if (pathname === '/api/auth/me' && req.method === 'GET') {
    // Fix (audit finding, Basse/"Sécurité et durcissement"): `sessions` is
    // now keyed by a one-way hash of the token (see lib/auth.js), not the
    // raw token — this used to look it back up with the plaintext cookie
    // value as the key, which no longer matches anything. `session` itself
    // (already resolved above by requireApiAuth -> validateSession) already
    // carries its own live `expiresAt`, so there was never a need to go
    // back to the `sessions` map here at all.
    return send(res, 200, {
      username: session.username, role: session.role, name: session.name,
      permissions: ROLE_PERMS[session.role] || [],
      expiresAt: session.expiresAt,
    });
  }

  // Removed in v12.21.1 (audit finding SEC-06): `/api/auth/stream-token`
  // used to hand the raw HttpOnly session token back to JS so the log
  // viewer's EventSource could put it in a `?token=` query string — which
  // then landed in nginx's own access log, readable by any `viewer` account.
  // No longer needed: features/logs.js#handleStream() now authenticates the
  // SSE connection straight from the session cookie, which EventSource
  // already sends automatically for a same-origin request.

  // ── /api/auth/sessions — active sessions (admin only) ───────────────────
  if (pathname === '/api/auth/sessions' && req.method === 'GET') {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return send(res, 403, { error: 'Forbidden' });
    const list = [...sessions.entries()].map(([, s]) => ({
      username: s.username, role: s.role, name: s.name,
      createdAt: new Date(s.createdAt).toISOString(),
      expiresAt: new Date(s.expiresAt).toISOString(),
      ip: s.ip,
    }));
    return send(res, 200, { sessions: list, count: list.length });
  }

  // ── Nginx Control ─────────────────────────────────────────────────────────
  if (pathname === '/api/webhooks') {
    if (!hasPerm(session, PERMS.MANAGE_WEBHOOKS)) return send(res, 403, { error: 'Forbidden' });
    if (req.method === 'GET') return send(res, 200, { webhooks });
    if (req.method === 'POST') {
      const body = await parseBody(req);
      if (!body.url) return send(res, 400, { error: 'url required' });
      // Fix (audit finding, Basse/"Sécurité et durcissement"): anti-SSRF —
      // see lib/ssrf-guard.js. Checked here for immediate feedback; the
      // real enforcement (including against DNS rebinding) is at fire time
      // in lib/events.js's fireWebhook().
      const urlCheck = await validateWebhookUrl(body.url);
      if (!urlCheck.ok) return send(res, 400, { error: urlCheck.error });
      const wh = { id: `wh_${Date.now()}`, url: body.url, events: body.events || ['*'], description: body.description || '', active: true, createdAt: new Date().toISOString(), fireCount: 0, lastFired: null };
      webhooks.push(wh);
      logEvent('webhook.created', { id: wh.id, url: wh.url, by: session.username }, 'api');
      return send(res, 201, wh);
    }
  }
  if (pathname.startsWith('/api/webhooks/')) {
    if (!hasPerm(session, PERMS.MANAGE_WEBHOOKS)) return send(res, 403, { error: 'Forbidden' });
    const id = pathname.split('/')[3], idx = webhooks.findIndex(w => w.id === id);
    if (idx === -1) return send(res, 404, { error: 'Webhook not found' });
    if (req.method === 'DELETE') { const [r] = webhooks.splice(idx, 1); logEvent('webhook.deleted', { id: r.id, by: session.username }, 'api'); return send(res, 200, { ok: true }); }
    if (req.method === 'PUT') {
      const body = await parseBody(req);
      // Fix (audit finding, Basse/"Sécurité et durcissement"): mass
      // assignment — `Object.assign(webhooks[idx], body)` let a PUT
      // overwrite ANY field, including ones this route never meant to
      // expose for editing (`id`, `createdAt`, `fireCount`, `lastFired`),
      // letting a caller corrupt this webhook's own bookkeeping (forge its
      // fire history, or even change its `id` and orphan/duplicate the
      // entry). Only the fields this route actually offers to edit are
      // copied now, each still defaulting to its current value when absent
      // so a partial PUT keeps working exactly as before.
      if (body.url !== undefined) {
        const urlCheck = await validateWebhookUrl(body.url);
        if (!urlCheck.ok) return send(res, 400, { error: urlCheck.error });
      }
      const wh = webhooks[idx];
      if (body.url !== undefined)         wh.url = body.url;
      if (body.events !== undefined)      wh.events = body.events;
      if (body.description !== undefined) wh.description = body.description;
      if (body.active !== undefined)      wh.active = !!body.active;
      return send(res, 200, wh);
    }
    if (req.method === 'POST' && pathname.endsWith('/test')) { fireWebhook(webhooks[idx], logEvent('webhook.test', { by: session.username }, 'api')); return send(res, 200, { ok: true }); }
  }


  // ── Git status & sync ─────────────────────────────────────────────────────────

  // GET /api/git/test-connection — test repo access without pulling
  // ── CrowdSec routes ───────────────────────────────────────────────────────────


  // ── Inline config edit + creation (features/configs.js) ───────────────────
  // Moved to features/configs.js: /api/configs/save (ALLOW_EDIT) and the new
  // /api/configs/create (ALLOW_CREATE, Git not configured). See setDeps()
  // wiring below FEATURES registration for why this needed a real fix, not
  // just a move — the inline version called testConfigEphemeral()/
  // fetchRefFileList() without ever importing them.


  // ── Reference files sync routes ───────────────────────────────────────────────


  // GET /api/version — current version + update check
  if (pathname === '/api/version' && req.method === 'GET') {
    const checkUpdates = url.searchParams.get('check') === '1';
    const result = {
      dashboard: {
        current:  RUNTIME_VERSION,
        revision: RUNTIME_REVISION,
        created:  RUNTIME_CREATED,
        hardcoded: VERSION,
      },
      nginx: {
        current: null,
        image:   null,
      },
      updates: {
        dashboard: null,
        nginx:     null,
      },
    };

    // Nginx version from VTS
    try {
      const vts = await fetchVTS();
      if (vts?.nginxVersion) result.nginx.current = vts.nginxVersion;
    } catch {}

    // Nginx image version from container labels
    try {
      const r = await dockerCall('GET', `/containers/${encodeURIComponent(NGINX_CONTAINER)}/json`);
      if (r.status === 200 && r.body) {
        const labels = r.body.Config?.Labels || {};
        // The OCI label, if the image sets one, is already a clean version.
        // Falling back to Config.Image was the actual bug reported: that
        // field is the *whole* reference the container was created from —
        // e.g. "ghcr.io/rdrouche/nginx-dashboard:1.4.2-waf" — and comparing
        // that whole string against a bare version from an update-check feed
        // could never meaningfully match. docker.parseImageTag() pulls out
        // just the tag; this project also ships -waf and -coraza variants of
        // the same nginx version, so the raw tag is kept here (still shown
        // to the operator as-is) while the update comparison below strips
        // that suffix separately.
        const rawImage = r.body.Config?.Image || null;
        result.nginx.image = labels['org.opencontainers.image.version']
          || (rawImage ? docker.parseImageTag(rawImage) : null);
        result.nginx.fullImage = rawImage;
      }
    } catch {}

    // Check for updates if requested
    if (checkUpdates) {
      if (DASHBOARD_VERSION_URL) {
        result.updates.dashboard = await fetchVersionFile(DASHBOARD_VERSION_URL).catch(() => null);
      }
      if (NGINX_VERSION_URL) {
        result.updates.nginx = await fetchVersionFile(NGINX_VERSION_URL).catch(() => null);
      }
    }

    return send(res, 200, result);
  }

  // ── Snippet metadata routes ───────────────────────────────────────────────────

  // ── VHost generator ───────────────────────────────────────────────────────────


  return send(res, 404, { error: 'Not found' });
}


// ─── Version resolution ───────────────────────────────────────────────────────

let RUNTIME_VERSION  = VERSION;
let RUNTIME_REVISION = '';
let RUNTIME_CREATED  = '';

async function resolveRuntimeVersion() {
  const selfId = process.env.HOSTNAME || '';
  if (!selfId) return;
  try {
    const r = await dockerCall('GET', `/containers/${selfId}/json`);
    if (r.status !== 200 || !r.body) return;
    const labels = r.body.Config?.Labels || {};
    const v = labels['org.opencontainers.image.version'];
    if (v && v.trim()) RUNTIME_VERSION = v.trim();
    RUNTIME_REVISION = (labels['org.opencontainers.image.revision'] || '').slice(0, 8);
    RUNTIME_CREATED  = labels['org.opencontainers.image.created'] || '';
  } catch {}
}

/**
 * Fetch a plain-text version file from a URL — returns the trimmed version
 * string or null.
 *
 * Fix (audit finding, Basse/"Sécurité et durcissement"): despite the old
 * comment ("Follow single redirect"), this recursed on every 301/302 with no
 * depth limit at all — a redirect LOOP (misconfigured target, or one
 * crafted by whoever controls DASHBOARD_VERSION_URL/NGINX_VERSION_URL, both
 * operator-editable) recursed indefinitely, one unresolved Promise and one
 * pending socket per hop, until the process either ran out of stack or (with
 * a slow attacker-controlled server) just hung this check forever. `depth`
 * now caps it at a fixed number of hops.
 */
async function fetchVersionFile(fileUrl, depth = 5) {
  if (!fileUrl) return null;
  if (depth <= 0) return null;
  return new Promise((resolve) => {
    try {
      const proto = fileUrl.startsWith('https') ? require('https') : http;
      const req = proto.request(
        Object.assign(new URL(fileUrl), { method: 'GET', headers: { 'User-Agent': cfg.HTTP_USER_AGENT }, timeout: 8000 }),
        (res) => {
          if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
            resolve(fetchVersionFile(res.headers.location, depth - 1));
            return;
          }
          if (res.statusCode !== 200) { resolve(null); return; }
          let data = '';
          res.on('data', d => data += d);
          res.on('end', () => {
            const v = data.trim().split('\n')[0].trim(); // first non-empty line
            resolve(v || null);
          });
        }
      );
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    } catch { resolve(null); }
  });
}


// ─── Git helpers ──────────────────────────────────────────────────────────────


// ─── Backup helpers ───────────────────────────────────────────────────────────


// ─── Ephemeral test container ─────────────────────────────────────────────────


/**
 * Network for the ephemeral test container. Mirrors the production nginx
 * container when possible so DNS resolution matches exactly; falls back to the
 * configured shared network, then to the default bridge. Never "none": without a
 * resolver, nginx -t fails on any upstream referring to a hostname.
 */

/**
 * List every file under `dir` as a path relative to it, recursing into
 * subdirectories. Config trees are not flat — ssl/ commonly holds a per-CA
 * subfolder — and a flat readdir silently drops everything nested.
 */

/** Recursively copy a directory tree, creating intermediate directories. */

/** Remove directories left empty after a sync, deepest first. */


// Docker resolves bind-mount sources on the HOST. Passing a path that only
// exists inside this container makes the daemon silently create an empty
// directory there and mount that instead — which is how the ephemeral config
// test could pass while validating nothing at all.


/**
 * Translate a path inside this container to the equivalent path on the host.
 * Returns null when no bind mount covers it — callers must treat that as an
 * error rather than falling back to the raw path.
 */

/**
 * Validate a configuration set in a throwaway nginx container.
 *
 * `srcDirs` points at what is about to be deployed (the Git work tree), never at
 * a backup. The sandbox is assembled under the deploy workspace — it is staging
 * material, and it must sit on a host-mounted path for Docker to bind-mount it.
 */


// ─── Git backup push ──────────────────────────────────────────────────────────


// Test Git repository connectivity and auth

// Create the backup orphan branch on remote without pushing any files
// Called from the UI "Initialiser la branche backup" button

// ─── Deploy pipeline ──────────────────────────────────────────────────────────


/** Deploy from git-work directly — no Git pull, for local mode (no GIT_REPO_URL) */

/** Returns true if a directory exists and is writable by this process. */

/** Files never touched by deploy sync (VCS placeholders, hidden files). */


// ─── CrowdSec Prometheus parser ───────────────────────────────────────────────

function promConfigured() { return !!(getCrowdsecCfg().promUrl); }


/** Group metric series by a label, summing values */
function promGroupBy(metrics, name, labelKey, filterFn) {
  const series = (metrics[name] || []).filter(s => !filterFn || filterFn(s));
  const grouped = {};
  for (const s of series) {
    const key = s.labels[labelKey] || 'unknown';
    grouped[key] = (grouped[key] || 0) + s.value;
  }
  return Object.entries(grouped)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
}


// ─── CrowdSec helpers ─────────────────────────────────────────────────────────


// ─── GeoIP lookup ─────────────────────────────────────────────────────────────


// Simple MMDB reader — reads binary MaxMind DB without external deps
// Returns basic geo data or null


/** Parse a nginx log line — supports combined and combined_vhost formats */
function parseLogLine(line) {
  // combined_vhost: vhost ip - user [date:time tz] "req" status bytes "ref" "ua"
  // combined:             ip - user [date:time tz] "req" status bytes "ref" "ua"
  const reVhost    = /^(\S+) (\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"$/;
  const reCombined = /^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"$/;
  let m;
  if ((m = line.match(reVhost)) && m[2].includes('.') === false || (m = line.match(reVhost))) {
    const firstToken = m[1];
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(firstToken) || /^[0-9a-f:]+$/i.test(firstToken);
    if (!isIp) {
      return { vhost: m[1], ip: m[2], time: m[3], request: m[4], status: parseInt(m[5]), bytes: parseInt(m[6]), referer: m[7], ua: m[8] };
    }
  }
  if ((m = line.match(reCombined))) {
    return { vhost: null, ip: m[1], time: m[2], request: m[3], status: parseInt(m[4]), bytes: parseInt(m[5]), referer: m[6], ua: m[7] };
  }
  return { raw: line };
}

// ─── GoAccess helpers ─────────────────────────────────────────────────────────


// ─── GoAccess WebSocket + HTTP proxy ─────────────────────────────────────────

// getGoAccessPort removed — using Docker DNS instead


// Resolve GoAccess proxy target using Docker internal DNS
// Container name = ngx-goaccess-{sourceId}, reachable on nginx-net by name


// ─── WebSocket upgrade ───────────────────────────────────────────────────────
// Only GoAccess uses upgrades today; the feature owns the handler.
server.on('upgrade', (req, socket, head) => {
  // Chaque handler se retire lui-meme (pathname non reconnu) sans toucher au
  // socket, sauf agentTunnelFeature qui repond explicitement true/false
  // (handleUpgrade() de goaccess, plus ancien, detruit toujours le socket
  // sur une non-correspondance — donc verifie en dernier).
  if (agentTunnelFeature.handleUpgrade(req, socket, head)) return;
  goaccessFeature.handleUpgrade(req, socket, head);
});


// ─── Snippet metadata parser ──────────────────────────────────────────────────


// ─── Nginx cache management ───────────────────────────────────────────────────

/** List cache zones (subdirs of DIR_CACHE, excluding *_temp dirs) */

/** Recursively count files and total bytes in a directory */

/** Recursively delete contents of a directory (not the dir itself) */

/** Clear one or all cache zones, then reload nginx */


// ─── Certbot HTTP challenge management ───────────────────────────────────────


// ── Certificate scanning ──────────────────────────────────────────────────────


// ── Certbot container lifecycle ───────────────────────────────────────────────


// ─── GoDNS management ────────────────────────────────────────────────────────


// ─── Global safety net ───────────────────────────────────────────────────────
// Un rejet non gere ailleurs que dans une route ne doit pas non plus emporter le
// processus : perdre toutes les sessions coute plus cher que de laisser tourner
// un dashboard dont une tache de fond a echoue.
process.on('unhandledRejection', (reason) => {
  console.error('[fatal] Promesse rejetee non geree :', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[fatal] Exception non capturee :', err);
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
// Diagnosed live: an operator saw "Cannot read /config/users.yml: ENOENT" and
// suspected a CRLF/LF encoding issue — ENOENT means the path does not exist at
// all, which is unrelated. The fallback to a default admin:admin account below
// (in loadUsers()) already handles this without crashing, but the warning it
// logs is easy to miss among everything else printed at startup. This check
// runs first and names the actual problem plainly: either the config volume
// is not mounted where the dashboard expects it, or it is mounted read-only,
// in which case even the one remaining write path this project has — the
// automatic upgrade of a legacy password hash on login — will keep failing
// silently on every restart.
(function checkConfigDirAtBoot() {
  try {
    if (!fs.existsSync(CONFIG_DIR)) {
      console.warn(`[boot] Config directory missing: ${CONFIG_DIR}`);
      console.warn(`[boot] Expected a volume mounted here containing users.yml. `
        + `Falling back to a default admin:admin account until this is fixed.`);
      return;
    }
    fs.accessSync(CONFIG_DIR, fs.constants.W_OK);
  } catch (e) {
    console.warn(`[boot] Config directory is not writable: ${CONFIG_DIR} (${e.code || e.message})`);
    console.warn('[boot] User accounts can still be read, but a legacy password '
      + 'hash will fail to upgrade and persist on every login.');
  }
})();

loadUsers();
getCertbotCfg();
getGoDNSCfg();
initEventsDb();
require('./lib/monitor-store').initMonitorDb();
require('./lib/notifications').initNotificationsDb();
// Apres l ouverture de la base seulement : les sessions vivaient en memoire, et
// toute mise a jour de l image deconnectait tout le monde.
auth.setSessionStore(events);
cleanLegacyTestDirs();
// Start scheduler after event loop is ready — non-blocking
setTimeout(() => { try { scheduler.startScheduler(); } catch(e) { console.warn("[scheduler] Start error:", e.message); } }, 1000);
// Same non-blocking delay as the scheduler above, and for the same reason —
// the monitor's first rescan touches the filesystem (DIR_SITES/DIR_CONF),
// which should never compete with the server's own startup.
setTimeout(() => { try { require('./features/monitor').start(); } catch(e) { console.warn("[monitor] Start error:", e.message); } }, 1000);
startPolling();
resolveRuntimeVersion().catch(() => {});
pullGoAccessImage().catch(() => {});
// Pre-resolve container at startup (non-blocking)
resolveContainer().catch(() => {});
// Recreate an enabled-but-missing managed container after a host reboot —
// RestartPolicy: unless-stopped only ever restarts a container Docker
// already knows about (see ensureRenewalContainerAtBoot()'s own comment for
// why that is not the same thing). Non-blocking and independently
// swallowed: one feature's Docker error must never delay the HTTP server
// coming up, let alone take another feature down with it.
ensureRenewalContainerAtBoot().catch(() => {});
ensureCertbotDnsContainerAtBoot().catch(() => {});
ensureGeoipupdateContainerAtBoot().catch(() => {});
ensureErrorPagesContainerAtBoot().catch(() => {});
ensureChallengeContainerAtBoot().catch(() => {});
analyzerFeature.ensureContainerAtBoot().catch(() => {});
server.listen(PORT, () => {
  const imageVersion = process.env.APP_VERSION || VERSION;
  const imageMismatch = imageVersion !== VERSION ? ` (code: ${VERSION})` : '';
  console.log(`[nginx-dashboard v${imageVersion}${imageMismatch}] :${PORT}`);
  if (imageVersion !== VERSION) {
    console.log(`[warn] Image tag (${imageVersion}) differs from hardcoded version (${VERSION})`);
  }
  console.log(`  Users   : ${USERS_FILE}`);
  console.log(`  Session : TTL ${Math.floor(SESSION_TTL_MS / 3600000)}h`);
  console.log(`  VTS     : ${NGINX_VTS_URL}`);
  console.log(`  Logs    : ${DIR_LOGS}`);
  // Git/CrowdSec/GoAccess sont lus via leurs fonctions de fusion (getGitCfg,
  // getCrowdsecCfg, getGoaccessCfg) plutot que les constantes figees
  // importees ci-dessus : depuis que git.yml/crowdsec.yml/goaccess.yml
  // peuvent surcharger la variable Docker, un diagnostic base sur la
  // constante figee mentirait des qu un operateur renseigne le YAML.
  const gCfg  = getGitCfg();
  const csCfg = getCrowdsecCfg();
  const gaCfg = getGoaccessCfg();
  console.log(`  Git     : ${gCfg.repoUrl ? gCfg.repoUrl.replace(/\/\/[^@]+@/, '//***@') : '(not configured)'}`);
  console.log(`  Backups : ${DIR_BACKUPS} (keep ${BACKUP_KEEP})`);
  console.log(`  NginxImg: ${NGINX_IMAGE || '(auto-detect)'}`);
  console.log(`  CrowdSec LAPI  : ${csCfg.url || '(not configured)'}`);
  console.log(`  CrowdSec Prom  : ${csCfg.promUrl || '(not configured)'}`);
  console.log(`  CrowdSec Local : ${csCfg.localOnly}`);
  console.log(`  GoAccess: ${gaCfg.image} → ${DIR_GOACCESS}`);
  const cbCfg  = getCertbotCfg();
  const dnsCfg = getGoDNSCfg();
  console.log(`  Certbot : ${CERTBOT_CONFIG_FILE} → ${cbCfg ? (cbCfg.enable ? 'enabled' : 'disabled') : 'NOT FOUND'}`);
  console.log(`  GoDNS   : ${GODNS_CONFIG_FILE} → ${dnsCfg ? (dnsCfg.enable ? 'enabled' : 'disabled') : 'NOT FOUND'}`);
  if (dnsCfg && dnsCfg.enable) {
    const gf = getGoDNSConfigFilePath(dnsCfg);
    console.log(`  GoDNS cfg: internal=${gf.internalPath} host=${gf.hostPath} → container=${gf.containerPath} (${gf.format})`);
  }
  fs.mkdirSync(DIR_BACKUPS, { recursive: true });
  fs.mkdirSync(DIR_GOACCESS, { recursive: true });
  fs.mkdirSync(DIR_GOACCESS_DB, { recursive: true });
  fs.mkdirSync(path.join(DIR_GOACCESS, 'reports'), { recursive: true });
  fs.mkdirSync(DIR_GIT_WORK, { recursive: true });
  logEvent('dashboard.start', { port: PORT, version: VERSION }, 'system');
});

// ─── Config loaders — SMTP / Notifications / Scheduler ───────────────────────

// SMTP/Notif/Sched config paths — declared near USERS_FILE below


let smtpCfg   = null;
let notifCfg  = null;
let schedCfg  = null;


// ─── SMTP mailer (Node.js native — no deps) ───────────────────────────────────


// ─── Scheduler (cron-like, pure JS) ──────────────────────────────────────────


let lastSchedulerMinute = -1;

