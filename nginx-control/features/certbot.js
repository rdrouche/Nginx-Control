'use strict';
/**
 * Let's Encrypt certificates over the HTTP-01 challenge.
 *
 * Two container roles, both driven from here:
 *
 *  - one-shot runs for issuing, dry-running and revoking;
 *  - a long-lived renewal loop (`certbot renew` every 12 h).
 *
 * The certbot image sets ENTRYPOINT ["certbot"], so a one-shot passes its
 * arguments directly while the renewal loop overrides the entrypoint to run a
 * shell. Getting this wrong makes certbot read the shell script as a config
 * file and fail with a misleading "Unable to open config file".
 *
 * Renewal never touches nginx: it writes the new certificate and stops there.
 * Reloading is the operator's call, from the control page.
 *
 * Before issuing, the requested domains are checked against existing
 * certificates — including wildcards — so an HTTP-challenge certificate cannot
 * silently shadow one obtained through the DNS challenge.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const certs   = require('../lib/certs');
const events  = require('../lib/events');
const { pushNotification } = require('../lib/notifications');
// HOSTNAME_RE lives in lib/agent-manifest.js (shared with lib/docker-autoconfig.js's
// own identical copy) — reused here rather than duplicated again, purely for
// the revocation route's domain check below (fix, audit report, Basse/
// "Partie 1 et certificats").
const { HOSTNAME_RE } = require('../lib/agent-manifest');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { listExistingCerts, checkDomainConflict } = certs;
const { logEvent } = events;
const { CERTBOT_CONFIG_FILE, DIR_CERTS } = cfg;

/**
 * Best-effort excerpt of *why* a certbot run failed, for surfacing to an
 * operator who otherwise only ever saw "echec inconnu" (fix, audit report,
 * Basse/"Partie 1 et certificats" — issueCertificate() used to return
 * `{ok:false, logs}` with no `error` field at all). Certbot's own output is
 * unstructured free text, so this is deliberately simple: the last few
 * non-empty lines, capped in length, which in practice already covers its
 * common failure shapes ("Detail: ...", "Domain: ...", rate-limit messages,
 * connection-refused during the HTTP-01 challenge, etc). Never throws.
 */
function extractCertbotError(logs) {
  if (!logs || typeof logs !== 'string') return null;
  const lines = logs.split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) return null;
  const excerpt = lines.slice(-5).join(' | ');
  return excerpt.length > 500 ? excerpt.slice(0, 500) + '…' : excerpt;
}

const CERTBOT_CONTAINER_NAME = 'nginx-dashboard-certbot';

let CERTBOT_CFG = null;

function loadCertbotConfig() {
  if (!fs.existsSync(CERTBOT_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(CERTBOT_CONFIG_FILE, 'utf8');
    const cfg = {};
    raw.split('\n').forEach(line => {
      const m = line.replace(/\r/g, '').match(/^([a-z_]+)\s*:\s*(.+)$/);
      if (m) cfg[m[1].trim()] = m[2].trim().replace(/\r/g, '').replace(/^["']|["']$/g, '');
    });
    cfg.enable  = cfg.enable  === 'true' || cfg.enable  === '1';
    cfg.staging = cfg.staging === 'true' || cfg.staging === '1';
    return cfg;
  } catch(e) {
    console.warn('[certbot] Config load error:', e.message);
    return null;
  }
}

function getCertbotCfg() {
  CERTBOT_CFG = loadCertbotConfig();
  return CERTBOT_CFG;
}

async function certbotContainerStatus() {
  const r = await dockerCall('GET', `/containers/${CERTBOT_CONTAINER_NAME}/json`);
  // status 0 : le demon est injoignable — a distinguer d un conteneur absent.
  if (r.status === 0)   return { exists: false, running: false, dockerUnavailable: true, error: r.error };
  if (r.status === 404) return { exists: false, running: false };
  if (r.status !== 200) return { exists: false, running: false, error: `HTTP ${r.status}` };
  return {
    exists:  true,
    running: r.body?.State?.Running === true,
    status:  r.body?.State?.Status || 'unknown',
    image:   r.body?.Config?.Image || '',
    started: r.body?.State?.StartedAt || '',
  };
}

async function certbotPullImage(image) {
  console.log(`[certbot] Pulling image: ${image}`);
  const r = await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  // Check if already present
  const inspect = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
  return inspect.status === 200;
}

/**
 * Host-side directory to bind-mount as /etc/letsencrypt in both the one-off
 * issue/dry-run container and the persistent renewal container.
 *
 * This used to be derived from `cfg._hostConfigDir`, a field nothing in this
 * codebase ever set — path.dirname(undefined || '') resolves to '.', so the
 * bind source was always the *relative* path 'certs', resolved by the Docker
 * daemon against its own working directory rather than the operator's compose
 * project directory. Certbot itself reported success (it wrote the cert
 * somewhere), but that somewhere was never the ./certs the real nginx and
 * nginx-dashboard containers mount — hence certs "generated" but invisible to
 * either container.
 *
 * Fixed the same way `webroot_host_path` already solves the identical
 * problem for the webroot directory: an explicit host path, since the
 * dashboard container has no reliable way to learn its own compose project's
 * host-side path from inside a container. When `certs_host_path` isn't set,
 * fall back to the sibling `certs/` directory next to `webroot_host_path` —
 * true for every shipped docker-compose.yml layout (`./webroot` and
 * `./certs` side by side) — rather than silently reproducing the old broken
 * relative path.
 */
function resolveCertsHostPath(cfg) {
  const explicit = typeof cfg.certs_host_path === 'string' && cfg.certs_host_path.trim();
  if (explicit) return explicit;

  const webrootHost = typeof cfg.webroot_host_path === 'string' && cfg.webroot_host_path.trim();
  if (webrootHost) return path.join(path.dirname(webrootHost), 'certs');

  console.warn('[certbot] Neither certs_host_path nor webroot_host_path is set — '
    + 'falling back to the relative path "certs", which will very likely NOT '
    + 'match the host directory your nginx/nginx-dashboard containers mount. '
    + 'Set certs_host_path in certbot.yml to the absolute host path used for '
    + '`./certs` in your docker-compose.yml.');
  return 'certs';
}

/**
 * Path INSIDE THE NGINX CONTAINER where the webroot challenge directory
 * (webroot_host_path, mounted read-write into certbot's own containers at
 * /var/www/certbot) is mounted for nginx to serve it back to the ACME
 * server. The dashboard has no way to see nginx's own docker-compose
 * volumes — it only knows its own host-side path — so this can only ever be
 * a best-effort default, overridable when it doesn't match a given
 * deployment.
 *
 * Previously hardcoded to `/var/www/letsencrypt` in the post-issuance
 * snippet below, which does not match this project's own shipped
 * convention of mounting the webroot at `/var/www` in nginx — a vhost that
 * copied that suggested snippet verbatim would have nginx serving from the
 * wrong directory, returning 404 to the ACME server's HTTP-01 validation
 * request and failing authorization silently (no per-domain error, just
 * "All authorizations were not finalized by the CA").
 */
function resolveWebrootNginxPath(cfg) {
  const explicit = typeof cfg.webroot_nginx_path === 'string' && cfg.webroot_nginx_path.trim();
  return explicit || '/var/www';
}

/**
 * Bind mounts and env vars needed for an internal ACME server's own TLS
 * certificate to be trusted — shared between the one-off issue/dry-run
 * container and the persistent renewal container, since a renewal talks to
 * the exact same ACME server and would hit the exact same trust problem
 * otherwise.
 */
function certbotTrustExtras(cfg) {
  const binds = [];
  const env = [];
  const caBundleHost = typeof cfg.ca_bundle_host_path === 'string' && cfg.ca_bundle_host_path.trim();
  if (caBundleHost) {
    binds.push(`${caBundleHost}:/etc/ssl/certs/internal-ca.pem:ro`);
    env.push('REQUESTS_CA_BUNDLE=/etc/ssl/certs/internal-ca.pem');
  }
  return { binds, env };
}

async function certbotStartContainer(cfg) {
  // Stop + remove existing if present
  await dockerCall('POST', `/containers/${CERTBOT_CONTAINER_NAME}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${CERTBOT_CONTAINER_NAME}?force=true`).catch(() => {});

  const image         = cfg.container_image || 'certbot/certbot:latest';
  const webrootHost   = cfg.webroot_host_path || '';
  const certsHost     = resolveCertsHostPath(cfg);
  const trust = certbotTrustExtras(cfg);

  const body = {
    Image: image,
    // Override entrypoint (certbot image default is ["certbot"]) to run renewal loop
    Entrypoint: ['/bin/sh'],
    // Renewal only — no nginx interaction. Nginx reloads certs on next TLS handshake.
    Cmd: ['-c', 'trap exit TERM INT; while :; do certbot renew --webroot -w /var/www/certbot --quiet 2>&1; sleep 43200 & wait $!; done'],
    ...(trust.env.length ? { Env: trust.env } : {}),
    HostConfig: {
      Binds: [
        `${webrootHost}:/var/www/certbot:rw`,
        `${certsHost}:/etc/letsencrypt:rw`,
        ...trust.binds,
      ],
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

  const create = await dockerCall('POST', `/containers/create?name=${CERTBOT_CONTAINER_NAME}`, body);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);

  const start = await dockerCall('POST', `/containers/${CERTBOT_CONTAINER_NAME}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);

  return true;
}

async function certbotStopContainer() {
  await dockerCall('POST', `/containers/${CERTBOT_CONTAINER_NAME}/stop`);
  await dockerCall('DELETE', `/containers/${CERTBOT_CONTAINER_NAME}?force=true`);
}

/**
 * Called once at dashboard boot (server.js) — never on a route.
 *
 * `RestartPolicy: unless-stopped` only covers the Docker daemon restarting
 * an EXISTING container after a host reboot; it does nothing the first time
 * `enable: true` is set (nothing has ever created the container yet) or
 * after an operator used the "Arreter" button, which removes the container
 * outright rather than merely stopping it (see certbotStopContainer above).
 * Either way, only the dashboard itself — on its own next start — can
 * notice "enabled but missing" and fix it; Docker has no opinion on a
 * container that was never told to exist. Without this, a host reboot could
 * silently leave certificates unrenewed until someone happens to check the
 * page.
 *
 * Deliberately does nothing when the container already exists: an existing
 * one, running or exited, is left to RestartPolicy / the operator's own
 * stop/start, exactly as before this function existed.
 */
async function ensureRenewalContainerAtBoot() {
  const cfg = getCertbotCfg();
  if (!cfg?.enable) return { skipped: 'not enabled' };
  try {
    const status = await certbotContainerStatus();
    if (status.dockerUnavailable) return { skipped: 'docker unavailable', error: status.error };
    if (status.exists) return { skipped: 'already exists' };
    // Meme geste que la route /container/start : sans ca, un hote qui
    // redemarre avant le tout premier pull manuel echouerait silencieusement
    // ici (avertissement log seulement, cf. commentaire plus haut).
    await certbotPullImage(cfg.container_image || 'certbot/certbot:latest');
    await certbotStartContainer(cfg);
    console.log('[certbot] Renewal container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[certbot] ensureRenewalContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

/** Run a one-shot certbot operation (issue / dry-run / revoke) */
async function certbotRunOnce(cfg, args) {
  const image       = cfg.container_image || 'certbot/certbot:latest';
  const webrootHost = cfg.webroot_host_path || '';
  const certsHost   = resolveCertsHostPath(cfg);
  const tmpName     = `nginx-dashboard-certbot-run-${Date.now()}`;
  const trust       = certbotTrustExtras(cfg);

  // Ensure webroot dir exists
  if (webrootHost) fs.mkdirSync(webrootHost, { recursive: true });

  const body = {
    Image: image,
    // Image entrypoint is ['certbot'] — pass args directly, no need to repeat 'certbot'
    Entrypoint: ['certbot'],
    Cmd: args,
    ...(trust.env.length ? { Env: trust.env } : {}),
    HostConfig: {
      Binds: [
        `${webrootHost}:/var/www/certbot:rw`,
        `${certsHost}:/etc/letsencrypt:rw`,
        ...trust.binds,
      ],
      AutoRemove: false,
      NetworkMode: cfg.NGINX_NETWORK || 'nginx-net',
    },
  };

  const create = await dockerCall('POST', `/containers/create?name=${tmpName}`, body);
  if (create.status !== 201) throw new Error(`Container create failed: ${create.status}`);
  const id = create.body?.Id;

  await dockerCall('POST', `/containers/${id}/start`);

  // Wait for completion (max 120s)
  let waited = 0;
  while (waited < 120) {
    await new Promise(r => setTimeout(r, 2000)); waited += 2;
    const inspect = await dockerCall('GET', `/containers/${id}/json`);
    if (!inspect.body?.State?.Running) break;
  }

  // Get logs
  const logsR = await dockerCall('GET', `/containers/${id}/logs?stdout=1&stderr=1&timestamps=0`);
  // Demuxed by hand here, without the guard for a TTY-allocated container —
  // when Tty:true the stream carries no 8-byte frame headers at all, and
  // blindly stripping them off the front corrupts the log text. Reusing the
  // shared, TTY-aware demuxToText() fixes this the same way it was fixed for
  // GoDNS, and keeps the logic in one place instead of four copies.
  const logs = logsR.rawBuffer
    ? docker.demuxToText(logsR.rawBuffer)
    : (typeof logsR.body === 'string' ? logsR.body : JSON.stringify(logsR.body));

  // Get exit code
  const inspect2 = await dockerCall('GET', `/containers/${id}/json`);
  const exitCode  = inspect2.body?.State?.ExitCode ?? -1;

  // Cleanup
  await dockerCall('DELETE', `/containers/${id}?force=true`).catch(() => {});

  return { ok: exitCode === 0, exitCode, logs };
}

/**
 * Merge a per-request staging override into the configured cfg — the
 * "staging" checkbox on the issue form previously sent its value nowhere
 * useful, since buildCertbotArgs() only ever saw scheduler.yml's own
 * `staging`. A custom `server`, configured in the YAML, still overrides
 * either staging source inside buildCertbotArgs() itself — this function
 * only decides what "staging" means for this one request, not whether it
 * gets used at all.
 */
function applyStagingOverride(cfg, requestStaging) {
  return typeof requestStaging === 'boolean' ? { ...cfg, staging: requestStaging } : cfg;
}

/** Build certbot args for HTTP webroot challenge */
function buildCertbotArgs(cfg, domains, dryRun) {
  const args = [
    'certonly',
    '--webroot', '-w', '/var/www/certbot',
    '--non-interactive',
    '--agree-tos',
    '--email', cfg.email || 'admin@localhost',
  ];
  // A custom ACME server — an internal CA such as step-ca, or any other
  // ACME-compatible endpoint — takes priority over `staging`: the latter is
  // really just certbot's own shortcut for pointing --server at Let's
  // Encrypt's own staging directory, which is meaningless once a different
  // CA is already configured. Left unset (the default), certbot falls back
  // to its own built-in production Let's Encrypt URL exactly as before —
  // no behavior change for anyone not setting this.
  const server = typeof cfg.server === 'string' && cfg.server.trim();
  if (server) {
    args.push('--server', server);
  } else if (cfg.staging) {
    args.push('--staging');
  }
  if (dryRun) args.push('--dry-run');
  for (const d of domains) args.push('-d', d);
  return args;
}

/**
 * Actually run an HTTP-01 issuance for `domains`. Extracted from the
 * `/api/certbot/issue` route so a caller OTHER than an HTTP request — the
 * Docker auto-config feature, via its own injected `issueHttp` dep, see
 * `setDeps()` below — can trigger the exact same issuance, with the exact
 * same conflict-check/logging/notification behaviour, without going through
 * an internal HTTP round-trip or duplicating this logic.
 *
 * `source` is a short tag (default 'manual') recorded in the event log so
 * an operator can tell a docker-autoconfig-triggered issuance apart from
 * one they ran by hand from the Certbot page.
 *
 * Returns `{ error, conflict }` for a domain conflict (never throws for
 * that — same shape the route used to build a 409 from), `{ error }` for
 * any other failure, or the full result object on success/dry-run.
 */
async function issueCertificate(domains, { dryRun = false, staging, source = 'manual' } = {}) {
  const cfg = getCertbotCfg();
  if (!cfg?.enable) return { error: 'Certbot not enabled' };
  if (!domains || !domains.length) return { error: 'domains required' };

  // Fix (audit report, Basse/"Partie 1 et certificats"): the HTTP-01
  // challenge this module drives can only ever prove control of one exact
  // name at a time (a GET to that name's own /.well-known/acme-challenge/),
  // so it can never issue a wildcard — only DNS-01 (features/certbot-dns.js)
  // can. Before this fix, a `*.example.com` request was sent to certbot
  // anyway, which always fails; combined with any automatic retry (the
  // Docker auto-config / agent issuance loops), this retried forever instead
  // of failing once with a clear reason.
  const wildcard = domains.find(d => d.startsWith('*.'));
  if (wildcard) {
    return { error: `Le defi HTTP-01 ne peut pas emettre de certificat wildcard (${wildcard}) — utiliser le defi DNS-01 (certbot_dns) pour ce domaine.` };
  }

  const effectiveCfg = applyStagingOverride(cfg, staging);

  if (!dryRun) {
    for (const d of domains) {
      const conflict = checkDomainConflict(d);
      if (conflict.conflict) {
        return { error: `Domain ${d} is already covered by cert "${conflict.cert}" (${conflict.match})`, conflict };
      }
    }
  }

  try {
    if (cfg.webroot_host_path) fs.mkdirSync(cfg.webroot_host_path, { recursive: true });
    const args = buildCertbotArgs(effectiveCfg, domains, dryRun);
    const commandStr = 'certbot ' + args.join(' ');
    console.log(`[certbot] Running (${source}): ${commandStr}`);
    const result = await certbotRunOnce(cfg, args);
    logEvent('certbot_issue', `${dryRun ? 'Dry-run' : 'Issue'} for ${domains.join(', ')} (${source}): ${result.ok ? 'OK' : 'FAILED'}`);
    if (!dryRun) {
      pushNotification(result.ok
        ? { type: 'certbot_renewed', level: 'success',
            message: `Certbot : certificat obtenu/renouvele pour ${domains.join(', ')}` }
        : { type: 'certbot_failed', level: 'error',
            message: `Certbot : echec pour ${domains.join(', ')} (code ${result.exitCode})`,
            data: { domains, exitCode: result.exitCode } });
    }

    const primaryDomain   = domains[0];
    const webrootNginxDir = resolveWebrootNginxPath(cfg);
    const NL = '\n';
    const snippet = result.ok && !dryRun
      ? '# Add to your vhost (' + primaryDomain + ')' + NL
        + 'ssl_certificate     /etc/letsencrypt/live/' + primaryDomain + '/fullchain.pem;' + NL
        + 'ssl_certificate_key /etc/letsencrypt/live/' + primaryDomain + '/privkey.pem;' + NL
        + NL
        + '# Ensure this location exists in your vhost for renewals — root MUST' + NL
        + '# match wherever YOUR nginx container mounts webroot_host_path' + NL
        + '# (set webroot_nginx_path in certbot.yml if that is not ' + webrootNginxDir + '):' + NL
        + 'location /.well-known/acme-challenge/ {' + NL
        + '    root ' + webrootNginxDir + ';' + NL
        + '}'
      : null;

    return {
      ok: result.ok, dryRun, domains, command: commandStr, logs: result.logs,
      exitCode: result.exitCode, snippet,
      // Fix (audit report, Basse/"Partie 1 et certificats"): previously
      // missing entirely on failure, so every caller (the manual /issue
      // route, and the Docker auto-config / agent auto-issuance loops that
      // store it as `lastError`) always displayed a generic "echec inconnu"
      // no matter what certbot actually reported.
      error: result.ok ? undefined : (extractCertbotError(result.logs) || `certbot a echoue (code ${result.exitCode})`),
    };
  } catch (e) { return { error: e.message || String(e) }; }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/certbot/config', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getCertbotCfg();
    return send(res, 200, {
      configured: !!cfg,
      enabled:    !!(cfg?.enable),
      staging:    !!(cfg?.staging),
      server:     cfg?.server || null,
      email:      cfg?.email || null,
      image:      cfg?.container_image || 'certbot/certbot:latest',
      webrootHostPath: cfg?.webroot_host_path || null,
      certsHostPath:   cfg ? resolveCertsHostPath(cfg) : null,
      webrootNginxPath: cfg ? resolveWebrootNginxPath(cfg) : null,
    });
  });

  router.get('/api/certbot/status', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const cfg = getCertbotCfg();
    if (!cfg?.enable) return send(res, 200, { enabled: false });
    const containerStatus = await certbotContainerStatus();
    return send(res, 200, { enabled: true, container: containerStatus });
  });

  router.get('/api/certbot/certs', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    // La liste des certificats est purement basee sur le disque (lib/certs.js)
    // et commune aux deux defis (HTTP et DNS) — elle ne doit jamais dependre
    // de l etat "enable" du defi HTTP, sans quoi un site 100% DNS-01 ne
    // verrait jamais ses propres certificats sur cette page.
    return send(res, 200, { enabled: true, certs: listExistingCerts() });
  });

  router.get('/api/certbot/check-conflict', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const domain = url.searchParams.get('domain');
    if (!domain) return httpLib.badRequest(res, 'domain required');
    return send(res, 200, checkDomainConflict(domain));
  });

  router.post('/api/certbot/container/start', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getCertbotCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'Certbot not enabled');
    try {
      await certbotPullImage(cfg.container_image || 'certbot/certbot:latest');
      await certbotStartContainer(cfg);
      logEvent('certbot_start', 'Certbot renewal container started');
      return send(res, 200, { ok: true, message: 'Certbot container started' });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/certbot/container/stop', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      await certbotStopContainer();
      logEvent('certbot_stop', 'Certbot renewal container stopped');
      return send(res, 200, { ok: true });
    } catch(e) { return httpLib.serverError(res, e); }
  });

  /**
   * Same shape as geoipupdate's own image/update: pull the configured
   * image's tag, recreate the renewal container only if the pull actually
   * changed the locally cached image and the container currently exists.
   */
  router.post('/api/certbot/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getCertbotCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'Certbot not enabled');
    const image = cfg.container_image || 'certbot/certbot:latest';
    const result = await docker.pullAndCheckUpdate(image);
    if (!result.ok) return send(res, 200, { ok: false, error: result.error });
    let recreated = false;
    if (result.updated) {
      const status = await certbotContainerStatus();
      if (status.exists) {
        try { await certbotStartContainer(cfg); recreated = true; }
        catch (e) { return send(res, 200, { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message }); }
      }
    }
    logEvent('certbot_image_update', `Image ${image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });

  router.post('/api/certbot/issue', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg = getCertbotCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'Certbot not enabled');
    const body    = await parseBody(req);
    const domains = (body.domains || []).filter(Boolean);
    const dryRun  = body.dryRun === true;
    if (!domains.length) return httpLib.badRequest(res, 'domains required');

    const result = await issueCertificate(domains, { dryRun, staging: body.staging });
    if (result.conflict) return send(res, 409, { error: result.error, conflict: result.conflict });
    // `result.ok === undefined` is what actually distinguishes the two
    // shapes issueCertificate() can return: a pre-flight failure (not
    // enabled, missing domains, a wildcard rejected before ever running
    // certbot, or a thrown exception) never reaches a real `certbotRunOnce()`
    // call and so has no `ok` field at all — that one deserves a 500. Once
    // certbot actually ran, `ok:false` now ALSO carries `error` (the fix
    // below), but the full result (domains, logs, exitCode, command) must
    // still reach the caller as 200, exactly as before this fix — only now
    // with a real reason attached instead of none.
    if (result.error && result.ok === undefined) return httpLib.serverError(res, new Error(result.error));
    return send(res, 200, result);
  });

  router.post('/api/certbot/revoke', async ({ req, res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const cfg  = getCertbotCfg();
    if (!cfg?.enable) return httpLib.badRequest(res, 'Certbot not enabled');
    const body = await parseBody(req);
    const domain = body.domain;
    if (!domain) return httpLib.badRequest(res, 'domain required');
    // Fix (audit report, Basse/"Partie 1 et certificats"): `domain` reached
    // path.join() completely unvalidated — a value such as `../../etc` would
    // build a path outside DIR_CERTS/live/ entirely. Every other place a
    // domain-shaped value is trusted enough to build a filesystem path
    // already runs it through this exact same hostname check first.
    if (!HOSTNAME_RE.test(domain)) return httpLib.badRequest(res, `domain invalide : "${domain}"`);
    const certFile = path.join(DIR_CERTS, 'live', domain, 'cert.pem');
    if (!fs.existsSync(certFile)) return send(res, 404, { error: `No cert found for ${domain}` });
    try {
      const args   = ['revoke', '--cert-path', `/etc/letsencrypt/live/${domain}/cert.pem`, '--non-interactive'];
      const result = await certbotRunOnce(cfg, args);
      logEvent('certbot_revoke', `Revoke ${domain}: ${result.ok ? 'OK' : 'FAILED'}`);
      return send(res, 200, { ok: result.ok, logs: result.logs });
    } catch(e) { return httpLib.serverError(res, e); }
  });
}

module.exports = { register, getCertbotCfg, loadCertbotConfig, CERTBOT_CONTAINER_NAME, buildCertbotArgs, applyStagingOverride, certbotTrustExtras, resolveCertsHostPath, resolveWebrootNginxPath, ensureRenewalContainerAtBoot, issueCertificate, extractCertbotError };
