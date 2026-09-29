'use strict';
/**
 * Vhost/backend SSL-posture audit — the second piece of the "resolver +
 * on-demand check" work, per lib/vhost-audit.js's own header for the rules
 * applied. Two layers:
 *
 *  - GET /api/audit — static, config-only, no network calls (instant even
 *    with many vhosts). Reuses the same resolver as features/backends.js
 *    (lib/vhost-targets.js) so the two stay consistent.
 *  - POST /api/audit/headers — live, on-demand, per vhost: probes BOTH the
 *    reverse proxy itself and the backend directly, to tell an nginx-added
 *    (or nginx-stripped) header apart from one the backend sends on its
 *    own. Same probe as the on-demand backend check (features/backends.js's
 *    checkTarget, injected via setDeps — features never import each other),
 *    just aimed at the proxy for one side of it.
 */

const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const cfg = require('../lib/config');
const tree = require('../lib/fs-tree');
const { listVhostTargets, parseVhostFile, parseUpstreams } = require('../lib/vhost-targets');
const { auditVhosts, auditHeaderProbe } = require('../lib/vhost-audit');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { safeReadFile, safeResolveWithin } = tree;
const { DIR_SITES, DIR_CONF, NGINX_CONTAINER } = cfg;

const UPSTREAM_DIRS = [DIR_CONF, DIR_SITES];

let checkTargetFn = async () => ({ ok: false, error: 'audit not wired' });
function setDeps({ checkTarget } = {}) {
  if (checkTarget) checkTargetFn = checkTarget;
}

/**
 * The port nginx is actually listening on for this block — from its own
 * `listen` directive(s), not guessed.
 *
 * Fix (audit report, Basse/Divers dashboard, "features/audit.js:41"):
 * `^(\d+)` matched the FIRST run of digits in the line, which for
 * `listen 127.0.0.1:8443 ssl;` is "127" — the first octet of the bind
 * address, not the port after the colon. Every vhost bound to a specific
 * address (the common way to keep an internal-only vhost off the public
 * interface) had its header probe silently aimed at port 127 instead of its
 * real port, which either connects to nothing or, on a host that happens to
 * have something listening on 127, probes the wrong service entirely. The
 * port is now taken from after a `host:port` or `[ipv6]:port` prefix when
 * one is present, and from a bare leading number otherwise — matching
 * nginx's own `listen` syntax rather than "whatever digits come first".
 */
function primaryListenPort(block) {
  const lines = block.listen || [];
  const line = block.ssl ? (lines.find(l => /\bssl\b/.test(l)) || lines[0]) : (lines.find(l => !/\bssl\b/.test(l)) || lines[0]);
  const s = (line || '').trim();
  const fallback = block.ssl ? 443 : 80;
  if (!s) return fallback;

  // `listen unix:/path/to.sock;` — no TCP port to speak of at all.
  if (/^unix:/.test(s)) return fallback;

  // `listen [::1]:8443 ssl;` / `listen [::]:80;` — bracketed IPv6 address.
  let m = s.match(/^\[[^\]]*\]:(\d+)(?:\s|;|$)/);
  if (m) return Number(m[1]);

  // `listen 127.0.0.1:8443 ssl;` / `listen example.com:8443;` — a plain
  // address (IPv4 or hostname, neither of which contains ':') before the port.
  m = s.match(/^[^\s:[\]]+:(\d+)(?:\s|;|$)/);
  if (m) return Number(m[1]);

  // `listen 8443 ssl;` / `listen 8443;` — bare port, no address.
  m = s.match(/^(\d+)(?:\s|;|$)/);
  if (m) return Number(m[1]);

  return fallback;
}

function register(router) {
  router.get('/api/audit', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    // Opt-out flags (comments, never real nginx directives — see
    // lib/vhost-targets.js) scoped to the Diagnostic page only: a file with
    // # nginx-control-diagnostic: off never gets a card at all, and a block
    // with # nginx-control-diagnostic-vhost: off is dropped from its file's
    // card without affecting the file's other blocks. Other pages fed by
    // listVhostTargets() (Backends, Monitoring, Schéma) are untouched — this
    // filtering happens here, not inside listVhostTargets() itself.
    const vhosts = listVhostTargets({ sitesDir: DIR_SITES, upstreamDirs: UPSTREAM_DIRS })
      .filter(v => v.diagnosticEnabled !== false)
      .map(v => ({ ...v, serverBlocks: (v.serverBlocks || []).filter(b => b.diagnosticEnabled !== false) }));
    return send(res, 200, { vhosts: auditVhosts(vhosts) });
  });

  router.post('/api/audit/headers', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);

    const body = await parseBody(req);
    const { file, blockIndex } = body;
    if (!file) return httpLib.badRequest(res, 'file required');

    // Same traversal guard as the on-demand backend check — never trust a
    // client-supplied path.
    const filePath = safeResolveWithin(file, [DIR_SITES]);
    if (!filePath) return httpLib.forbidden(res, 'Access denied');
    const content = safeReadFile(filePath);
    if (content === null) return httpLib.notFound(res, 'File not found');

    const upstreams = parseUpstreams(UPSTREAM_DIRS);
    const blocks = parseVhostFile(content, upstreams);
    const block = blocks[blockIndex];
    if (!block) return httpLib.badRequest(res, 'no such server block — the file may have changed, refresh and try again');

    const hostHeader = block.serverNames.find(n => n !== '_');
    if (!hostHeader) return httpLib.badRequest(res, 'this server block has no server_name to probe');

    // Reverse-proxy side: hit nginx itself, on its own container, on the
    // port this exact block listens on, with the real Host (and, for
    // HTTPS, the real SNI — see checkTarget's own comment on this) — this
    // is what a real visitor's browser would actually see.
    const scheme = block.ssl ? 'https' : 'http';
    const port = primaryListenPort(block);
    const proxyResult = await checkTargetFn({ scheme, host: NGINX_CONTAINER, port, hostHeader }, { verbose: true });

    // Backend side: the first location that actually resolves to something —
    // enough to tell apart a header the backend sends on its own from one
    // nginx adds or strips. A vhost with no resolvable location (static-only,
    // or every location unresolved) simply has no backend side to compare.
    let backendTarget = null;
    for (const loc of block.locations || []) {
      if (loc.kind === 'unresolved') continue;
      if (loc.targets && loc.targets.length) { backendTarget = loc.targets[0]; break; }
    }
    // `skipped: true` distingue "il n'y avait rien a tester" (bloc qui ne
    // fait que rediriger, ou dont toutes les locations sont statiques —
    // c'est un etat normal, pas un echec) d'un vrai `ok:false` ou la cible
    // backend existe mais n a pas repondu. Sans cette distinction, le
    // frontend affichait "ECHEC" en rouge pour un vhost redirect http->https
    // qui n a, par construction, aucun backend a joindre.
    const backendResult = backendTarget
      ? await checkTargetFn({ ...backendTarget, hostHeader }, { verbose: true })
      : { ok: false, skipped: true, error: 'no resolvable backend target on this server block' };

    const findings = auditHeaderProbe({
      ssl: block.ssl,
      proxyHeaders: proxyResult.verbose?.responseHeaders || {},
      backendHeaders: backendResult.verbose?.responseHeaders || {},
      proxyOk: proxyResult.ok,
      backendOk: backendResult.ok,
    });

    return send(res, 200, { proxy: proxyResult, backend: backendResult, findings });
  });
}

module.exports = { register, setDeps, primaryListenPort };
