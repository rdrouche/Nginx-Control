'use strict';
/**
 * Let's Encrypt certificates over the DNS-01 challenge.
 *
 * Complementary to certbot.js (HTTP-01), not a replacement for it: DNS-01 is
 * the only way to get a wildcard certificate, and works even when port 80 is
 * not publicly reachable. Deliberately a separate feature file, config file
 * and managed container rather than a mode flag on certbot.js — the two use
 * different Docker images (this one needs the provider's plugin actually
 * installed) and different bind mounts (a credentials file instead of a
 * webroot), and this project's own convention is one feature per concern
 * (see certbot.js/geoipupdate.js/error-pages.js).
 *
 * Real production Let's Encrypt only, deliberately: DNS-01 is generally used
 * for public wildcard domains, where a --staging certificate is not useful
 * for a Cloudflare-facing production stack. Point `container_image` and
 * accept the ACME server's own default rather than adding a staging flag
 * nobody asked for.
 *
 * Multiple providers: certbot ships one plugin per DNS provider, each its
 * own image (certbot/dns-cloudflare, certbot/dns-ovh, ...). PROVIDERS below
 * has good defaults for a handful of common ones; an unlisted provider still
 * works by setting `provider: custom` and filling in container_image,
 * plugin_flag, credentials_flag and propagation_flag by hand in
 * certbot-dns.yml — the registry is a convenience, not a restriction.
 *
 * Multiple certificates in one request: the compose file this project ships
 * as an example issues several certificates sequentially from one
 * credentials file (one per domain group, e.g. one wildcard per brand).
 * POST /api/certbot-dns/issue accepts an array of domain groups and runs one
 * `certbot certonly` per group, in order, exactly like that example —
 * without requiring a static list in YAML, the same way certbot.js's own
 * /issue takes an arbitrary domain list per request rather than a fixed one.
 *
 * Conflict with the HTTP-01 feature: both containers write into the SAME
 * /etc/letsencrypt store (certs_host_path here MUST be the same host
 * directory as certbot.yml's own certs_host_path / docker-compose.yml's
 * ./certs) — this is certbot's own normal multi-authenticator layout, not a
 * merge to perform by hand. Each certificate remembers which authenticator
 * issued it in its own renewal config, so `certbot renew` in either
 * container only touches the certificates it can actually renew. The one
 * real conflict is requesting the SAME domain through both challenge types:
 * the second issuance overwrites which authenticator owns that domain's
 * renewal, so checkDomainConflict() (shared with certbot.js via lib/certs,
 * not a cross-feature import) is applied here exactly as it is there.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const certs   = require('../lib/certs');
const events  = require('../lib/events');
const { HOSTNAME_RE } = require('../lib/agent-manifest');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { listExistingCerts, checkDomainConflict } = certs;
const { logEvent } = events;
const { CERTBOT_DNS_CONFIG_FILE, DIR_CERTS } = cfg;

const CONTAINER_NAME = 'nginx-dashboard-certbot-dns';

/**
 * Known providers with a certbot/dns-<name> image following the common
 * "credentials INI file + optional propagation-seconds flag" shape used by
 * the majority of official certbot DNS plugins. Not exhaustive by design —
 * `provider: custom` plus manual plugin_flag/credentials_flag/
 * propagation_flag in certbot-dns.yml covers anything not listed here
 * (route53's AWS-env-var auth, in particular, does not fit this shape and is
 * intentionally left to that manual path rather than special-cased).
 */
const PROVIDERS = {
  cloudflare: {
    label: 'Cloudflare',
    defaultImage: 'certbot/dns-cloudflare:latest',
    pluginFlag: '--dns-cloudflare',
    credentialsFlag: '--dns-cloudflare-credentials',
    propagationFlag: '--dns-cloudflare-propagation-seconds',
    credentialsExample: 'dns_cloudflare_api_token = VOTRE_TOKEN_API',
  },
  ovh: {
    label: 'OVH',
    defaultImage: 'certbot/dns-ovh:latest',
    pluginFlag: '--dns-ovh',
    credentialsFlag: '--dns-ovh-credentials',
    propagationFlag: '--dns-ovh-propagation-seconds',
    credentialsExample: 'dns_ovh_endpoint = ovh-eu\ndns_ovh_application_key = ...\ndns_ovh_application_secret = ...\ndns_ovh_consumer_key = ...',
  },
  digitalocean: {
    label: 'DigitalOcean',
    defaultImage: 'certbot/dns-digitalocean:latest',
    pluginFlag: '--dns-digitalocean',
    credentialsFlag: '--dns-digitalocean-credentials',
    propagationFlag: '--dns-digitalocean-propagation-seconds',
    credentialsExample: 'dns_digitalocean_token = VOTRE_TOKEN',
  },
  google: {
    label: 'Google Cloud DNS',
    defaultImage: 'certbot/dns-google:latest',
    pluginFlag: '--dns-google',
    credentialsFlag: '--dns-google-credentials',
    propagationFlag: null,
    credentialsExample: '{ "type": "service_account", ... } (fichier JSON de la cle de service)',
  },
  custom: {
    label: 'Autre (reglages manuels)',
    defaultImage: '',
    pluginFlag: null,
    credentialsFlag: null,
    propagationFlag: null,
    credentialsExample: null,
  },
};

function resolveProvider(c) {
  const key = (c?.provider || 'cloudflare').toLowerCase();
  const known = PROVIDERS[key] || PROVIDERS.custom;
  return {
    key,
    label: known.label,
    image: c.container_image || known.defaultImage,
    pluginFlag: c.plugin_flag || known.pluginFlag,
    credentialsFlag: c.credentials_flag || known.credentialsFlag,
    propagationFlag: c.propagation_flag || known.propagationFlag,
    credentialsExample: known.credentialsExample,
  };
}

function loadCertbotDnsConfig() {
  if (!fs.existsSync(CERTBOT_DNS_CONFIG_FILE)) return null;
  try {
    const raw = fs.readFileSync(CERTBOT_DNS_CONFIG_FILE, 'utf8');
    const out = {};
    raw.split('\n').forEach(line => {
      const m = line.replace(/\r/g, '').match(/^([a-z_]+)\s*:\s*(.+)$/);
      if (m) out[m[1].trim()] = m[2].trim().replace(/\r/g, '').replace(/^["']|["']$/g, '');
    });
    out.enable = out.enable === 'true' || out.enable === '1';
    return out;
  } catch (e) {
    console.warn('[certbot-dns] Config load error:', e.message);
    return null;
  }
}

function getCertbotDnsCfg() { return loadCertbotDnsConfig(); }

async function containerStatus() {
  const r = await dockerCall('GET', `/containers/${CONTAINER_NAME}/json`);
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

async function pullImage(image) {
  await dockerCall('POST', `/images/create?fromImage=${encodeURIComponent(image)}`);
  const inspect = await dockerCall('GET', `/images/${encodeURIComponent(image)}/json`);
  return inspect.status === 200;
}

async function startContainer(c) {
  await dockerCall('POST', `/containers/${CONTAINER_NAME}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${CONTAINER_NAME}?force=true`).catch(() => {});

  const provider = resolveProvider(c);
  if (!provider.image) throw new Error('container_image manquant (fournisseur "custom" sans image explicite)');
  const certsHost = c.certs_host_path;
  if (!certsHost) throw new Error('certs_host_path manquant dans certbot-dns.yml');
  const credsHost = c.credentials_host_path;

  const binds = [`${certsHost}:/etc/letsencrypt:rw`];
  if (credsHost) binds.push(`${credsHost}:/dns/credentials.ini:ro`);

  // Same reasoning as certbot.js's own renewal loop: renew only, never
  // touches nginx — reloading remains the operator's own call.
  const body = {
    Image: provider.image,
    Entrypoint: ['/bin/sh'],
    Cmd: ['-c', 'trap exit TERM INT; while :; do certbot renew --quiet 2>&1; sleep 43200 & wait $!; done'],
    HostConfig: {
      Binds: binds,
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

/** Same reasoning as certbot.js's own ensureRenewalContainerAtBoot(). */
async function ensureContainerAtBoot() {
  const c = getCertbotDnsCfg();
  if (!c?.enable) return { skipped: 'not enabled' };
  if (!c.certs_host_path) return { skipped: 'certs_host_path missing' };
  try {
    const status = await containerStatus();
    if (status.dockerUnavailable) return { skipped: 'docker unavailable', error: status.error };
    if (status.exists) return { skipped: 'already exists' };
    // Meme geste que la route /container/start : evite un echec silencieux
    // au redemarrage de l hote si l image n a jamais ete pullee.
    const provider = resolveProvider(c);
    if (provider.image) await pullImage(provider.image);
    await startContainer(c);
    console.log('[certbot-dns] Renewal container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[certbot-dns] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

/**
 * Run one one-shot certbot invocation in a fresh temporary container and
 * return its outcome. Shared by issuance and revocation: both need the same
 * create/start/wait/logs/cleanup dance, only the args and binds differ.
 */
async function runContainerOnce(image, args, binds) {
  const tmpName = `nginx-dashboard-certbot-dns-run-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

  const create = await dockerCall('POST', `/containers/create?name=${tmpName}`, {
    Image: image,
    Entrypoint: ['certbot'],
    Cmd: args,
    HostConfig: { Binds: binds, AutoRemove: false, NetworkMode: cfg.NGINX_NETWORK || 'nginx-net' },
  });
  if (create.status !== 201) throw new Error(`Container create failed: ${create.status} ${JSON.stringify(create.body)}`);
  const id = create.body?.Id;

  await dockerCall('POST', `/containers/${id}/start`);

  let waited = 0;
  while (waited < 180) {
    await new Promise(r => setTimeout(r, 2000)); waited += 2;
    const inspect = await dockerCall('GET', `/containers/${id}/json`);
    if (!inspect.body?.State?.Running) break;
  }

  const logsR = await dockerCall('GET', `/containers/${id}/logs?stdout=1&stderr=1&timestamps=0`);
  const logs = logsR.rawBuffer
    ? docker.demuxToText(logsR.rawBuffer)
    : (typeof logsR.body === 'string' ? logsR.body : JSON.stringify(logsR.body));

  const inspect2 = await dockerCall('GET', `/containers/${id}/json`);
  const exitCode = inspect2.body?.State?.ExitCode ?? -1;

  await dockerCall('DELETE', `/containers/${id}?force=true`).catch(() => {});

  return { ok: exitCode === 0, exitCode, logs, command: 'certbot ' + args.join(' ') };
}

/** One `certbot certonly --dns-<provider> ...` run for one domain group. */
async function runOnce(c, domains, provider) {
  const args = [
    'certonly',
    provider.pluginFlag,
    ...(provider.credentialsFlag ? [provider.credentialsFlag, '/dns/credentials.ini'] : []),
    ...(provider.propagationFlag ? [provider.propagationFlag, String(c.propagation_seconds ?? 30)] : []),
    '--non-interactive',
    '--agree-tos',
    '--email', c.email || 'admin@localhost',
  ];
  for (const d of domains) args.push('-d', d);

  const binds = [`${c.certs_host_path}:/etc/letsencrypt:rw`];
  if (c.credentials_host_path) binds.push(`${c.credentials_host_path}:/dns/credentials.ini:ro`);

  const result = await runContainerOnce(provider.image, args, binds);
  return { ...result, domains };
}

/**
 * Single-group issuance, reusable by a caller OTHER than the
 * `/api/certbot-dns/issue` route — the Docker auto-config feature, via its
 * own injected `issueDns` dep (see setDeps() in features/docker-autoconfig.js).
 * Same conflict-check/config-validation/logging as the batch route, just for
 * exactly one domain group (a docker-autoconfig vhost's own server_names) —
 * the route's own sequential-batch shape is a UI convenience for issuing
 * several unrelated certificates in one click, which a single labelled
 * container never needs.
 *
 * Returns `{ error, conflict }` for a domain conflict or a config problem
 * (never throws for either), or the full run result on success/failure.
 */
async function issueCertificate(domains, { source = 'manual' } = {}) {
  const c = getCertbotDnsCfg();
  if (!c?.enable) return { error: 'Certbot DNS not enabled' };
  const cleanDomains = (domains || []).filter(Boolean);
  if (!cleanDomains.length) return { error: 'domains required' };

  const provider = resolveProvider(c);
  if (!provider.pluginFlag) return { error: 'plugin_flag manquant (fournisseur "custom" sans reglage manuel)' };
  if (provider.credentialsFlag && !c.credentials_host_path) return { error: 'credentials_host_path manquant dans certbot-dns.yml' };
  if (!c.certs_host_path) return { error: 'certs_host_path manquant dans certbot-dns.yml' };

  for (const d of cleanDomains) {
    const conflict = checkDomainConflict(d);
    if (conflict.conflict) return { error: `Domain ${d} is already covered by cert "${conflict.cert}" (${conflict.match})`, conflict };
  }

  try {
    await pullImage(provider.image);
    console.log(`[certbot-dns] Running (${source}): certbot certonly ${provider.pluginFlag} -d ${cleanDomains.join(' -d ')}`);
    const r = await runOnce(c, cleanDomains, provider);
    logEvent('certbot_dns_issue', `Issue for ${cleanDomains.join(', ')} (${source}): ${r.ok ? 'OK' : 'FAILED'}`);
    return r;
  } catch (e) { return { error: e.message || String(e) }; }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/certbot-dns/providers', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const list = Object.entries(PROVIDERS).map(([key, p]) => ({
      key, label: p.label, defaultImage: p.defaultImage,
      needsCredentialsFile: !!p.credentialsFlag || key === 'custom',
      credentialsExample: p.credentialsExample,
    }));
    return send(res, 200, { providers: list });
  });

  router.get('/api/certbot-dns/config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c) return send(res, 200, { configured: false, enabled: false });
    const provider = resolveProvider(c);
    return send(res, 200, {
      configured: true,
      enabled: !!c.enable,
      provider: provider.key,
      providerLabel: provider.label,
      image: provider.image,
      email: c.email || null,
      propagationSeconds: Number(c.propagation_seconds ?? 30),
      certsHostPath: c.certs_host_path || null,
      credentialsHostPath: c.credentials_host_path || null,
      credentialsConfigured: !!c.credentials_host_path,
    });
  });

  router.get('/api/certbot-dns/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return send(res, 200, { enabled: false });
    const container = await containerStatus();
    return send(res, 200, { enabled: true, container });
  });

  router.get('/api/certbot-dns/certs', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return send(res, 200, { enabled: false, certs: [] });
    return send(res, 200, { enabled: true, certs: listExistingCerts() });
  });

  router.get('/api/certbot-dns/check-conflict', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const domain = url.searchParams.get('domain');
    if (!domain) return httpLib.badRequest(res, 'domain required');
    return send(res, 200, checkDomainConflict(domain));
  });

  router.post('/api/certbot-dns/container/start', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return httpLib.badRequest(res, 'Certbot DNS not enabled');
    try {
      const provider = resolveProvider(c);
      if (provider.image) await pullImage(provider.image);
      await startContainer(c);
      logEvent('certbot_dns_start', 'Certbot DNS renewal container started');
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/certbot-dns/container/stop', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      await stopContainer();
      logEvent('certbot_dns_stop', 'Certbot DNS renewal container stopped');
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  /** Same shape as certbot.js's/geoipupdate's/error-pages' own image/update. */
  router.post('/api/certbot-dns/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return httpLib.badRequest(res, 'Certbot DNS not enabled');
    const provider = resolveProvider(c);
    if (!provider.image) return httpLib.badRequest(res, 'container_image manquant');
    const result = await docker.pullAndCheckUpdate(provider.image);
    if (!result.ok) return send(res, 200, { ok: false, error: result.error });
    let recreated = false;
    if (result.updated) {
      const status = await containerStatus();
      if (status.exists) {
        try { await startContainer(c); recreated = true; }
        catch (e) { return send(res, 200, { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message }); }
      }
    }
    logEvent('certbot_dns_image_update', `Image ${provider.image} ${result.updated ? 'updated' : 'already up to date'}${recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, { ok: true, pulled: true, updated: result.updated, recreated });
  });

  /**
   * Batch issuance: one `certbot certonly` per domain group, run
   * sequentially — mirrors the shipped docker-compose.yml example (several
   * `certbot certonly --dns-cloudflare ...` calls sharing one credentials
   * file) as a single dashboard action instead of a static compose script.
   * Each group is checked against the existing cert store before running,
   * same rule as certbot.js's own /issue: a domain already covered by
   * ANY certificate (HTTP- or DNS-issued — the store is shared) blocks that
   * group rather than silently reassigning its authenticator.
   */
  router.post('/api/certbot-dns/issue', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return httpLib.badRequest(res, 'Certbot DNS not enabled');
    const body = await parseBody(req);
    const groups = Array.isArray(body.certificates) ? body.certificates : (body.domains ? [{ domains: body.domains }] : []);
    const cleaned = groups
      .map(g => ({ domains: (g.domains || []).filter(Boolean) }))
      .filter(g => g.domains.length);
    if (!cleaned.length) return httpLib.badRequest(res, 'certificates (au moins un groupe de domaines) requis');

    const provider = resolveProvider(c);
    if (!provider.pluginFlag) return httpLib.badRequest(res, 'plugin_flag manquant (fournisseur "custom" sans reglage manuel)');
    if (provider.credentialsFlag && !c.credentials_host_path)
      return httpLib.badRequest(res, 'credentials_host_path manquant dans certbot-dns.yml');
    if (!c.certs_host_path) return httpLib.badRequest(res, 'certs_host_path manquant dans certbot-dns.yml');

    for (const g of cleaned) {
      for (const d of g.domains) {
        const conflict = checkDomainConflict(d);
        if (conflict.conflict)
          return send(res, 409, { error: `Domain ${d} is already covered by cert "${conflict.cert}" (${conflict.match})`, conflict });
      }
    }

    const results = [];
    try {
      await pullImage(provider.image);
      for (const g of cleaned) {
        console.log(`[certbot-dns] Running: certbot certonly ${provider.pluginFlag} -d ${g.domains.join(' -d ')}`);
        const r = await runOnce(c, g.domains, provider);
        results.push(r);
        logEvent('certbot_dns_issue', `Issue for ${g.domains.join(', ')}: ${r.ok ? 'OK' : 'FAILED'}`, session.username);
        // Stop at the first failure — later groups sharing the same
        // credentials are unlikely to succeed either, and running them
        // anyway would bury the real error under repeated noise.
        if (!r.ok) break;
      }
      const allOk = results.length === cleaned.length && results.every(r => r.ok);
      return send(res, 200, { ok: allOk, results });
    } catch (e) { return send(res, 200, { ok: false, error: e.message, results }); }
  });

  router.post('/api/certbot-dns/revoke', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const c = getCertbotDnsCfg();
    if (!c?.enable) return httpLib.badRequest(res, 'Certbot DNS not enabled');
    const body = await parseBody(req);
    const domain = body.domain;
    if (!domain) return httpLib.badRequest(res, 'domain required');
    // Fix (audit report, Basse/"Partie 1 et certificats"), mirror of
    // features/certbot.js's own revoke route fix: `domain` reached path.join()
    // completely unvalidated. HOSTNAME_RE (shared with lib/agent-manifest.js
    // and lib/docker-autoconfig.js) also accepts a leading `*.`, which this
    // DNS-01 revoke route must keep allowing (unlike the HTTP-01 one).
    if (!HOSTNAME_RE.test(domain)) return httpLib.badRequest(res, `domain invalide : "${domain}"`);
    const certFile = path.join(DIR_CERTS, 'live', domain, 'cert.pem');
    if (!fs.existsSync(certFile)) return send(res, 404, { error: `No cert found for ${domain}` });
    const provider = resolveProvider(c);
    try {
      // Revocation needs neither the DNS plugin nor credentials — only the
      // shared cert store — so it goes through runContainerOnce() directly
      // rather than through runOnce(), which always builds a `certonly`
      // invocation with the provider's plugin/credentials flags attached.
      const args = ['revoke', '--cert-path', `/etc/letsencrypt/live/${domain}/cert.pem`, '--non-interactive'];
      const binds = [`${c.certs_host_path}:/etc/letsencrypt:rw`];
      const result = await runContainerOnce(provider.image, args, binds);
      logEvent('certbot_dns_revoke', `Revoke ${domain}: ${result.ok ? 'OK' : 'FAILED'}`, session.username);
      return send(res, 200, { ok: result.ok, logs: result.logs });
    } catch (e) { return httpLib.serverError(res, e); }
  });
}

module.exports = {
  register, getCertbotDnsCfg, loadCertbotDnsConfig, CONTAINER_NAME, PROVIDERS,
  resolveProvider, ensureContainerAtBoot, issueCertificate,
};
