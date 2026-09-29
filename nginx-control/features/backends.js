'use strict';
/**
 * Backend resolver + on-demand health check ("what is this vhost actually
 * proxying to, and does it answer right now").
 *
 * Foundation piece for a family of features (this one, plus a planned
 * graphical vhost/target map and continuous per-vhost monitoring): resolving
 * a vhost's real backend(s) — direct proxy_pass, an `upstream{}` pool
 * (load-balancing/HA), or a Docker container reached through nginx's
 * embedded-DNS pattern — is genuinely shared logic, so it lives in
 * lib/vhost-targets.js rather than here. This module only adds the two
 * things that are specific to "check it right now": the actual outbound
 * HTTP(S) probe, and the routes.
 *
 * Security note: the check route never accepts a client-supplied host/port
 * directly (that would turn an authenticated page into an internal port
 * scanner). It always re-parses the vhost file server-side from
 * {file, blockIndex, locationIndex, targetIndex} and only ever contacts a
 * target that resolution itself produced.
 */

const http  = require('http');
const https = require('https');

const cfg  = require('../lib/config');
const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const tree = require('../lib/fs-tree');
const { listVhostTargets, parseVhostFile, parseUpstreams } = require('../lib/vhost-targets');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { safeReadFile, safeResolveWithin } = tree;
const { DIR_SITES, DIR_CONF } = cfg;

const UPSTREAM_DIRS = [DIR_CONF, DIR_SITES];

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * A single outbound probe, standing in for `curl -k -v <url> -H "Host: ..."`.
 * TLS verification is intentionally off (`-k`) — self-signed internal certs
 * are the common case for a backend behind the reverse proxy, and this only
 * ever contacts the operator's own configured targets, never the public
 * internet.
 *
 * `verbose` (`-v`) additionally captures the request/response headers and,
 * for an HTTPS target, a summary of the peer certificate actually presented
 * — useful to see it even though it's never validated.
 *
 * A plain-HTTP target that answers with a redirect to an `https://` URL is
 * flagged as `redirectsToHttps` rather than just reported by status code:
 * that's the backend itself enforcing HTTPS, a normal/expected pattern, not
 * a failed check.
 */
function checkTarget({ scheme, host, port, hostHeader }, { timeoutMs = 5000, verbose = false } = {}) {
  return new Promise((resolve) => {
    const proto = scheme === 'https' ? https : http;
    const start = Date.now();
    let settled = false;
    const finish = (result) => { if (!settled) { settled = true; resolve({ ...result, ms: Date.now() - start }); } };

    const requestHeaders = { Host: hostHeader || host, 'User-Agent': 'nginx-control-backend-check' };
    const reqOptions = {
      host, port, path: '/', method: 'GET',
      headers: requestHeaders,
      timeout: timeoutMs,
      rejectUnauthorized: false,
    };
    // TLS SNI must match the vhost's own hostname, not the IP/container name
    // we connect to — otherwise a server with per-vhost certificates (SNI
    // dispatch happens at the TLS handshake, before nginx ever reads the
    // Host header) hands back its default/catch-all block instead of the
    // one actually being tested. Node defaults SNI to `host` unless told
    // otherwise, so this has to be explicit.
    if (scheme === 'https') reqOptions.servername = hostHeader || host;
    const req = proto.request(reqOptions, (res) => {
      res.resume(); // drain — the check only cares about status and timing (and, in verbose mode, headers)
      const result = { ok: true, status: res.statusCode, statusMessage: res.statusMessage || '' };

      if (scheme === 'http' && REDIRECT_STATUSES.has(res.statusCode) && /^https:\/\//i.test(res.headers.location || '')) {
        result.redirectsToHttps = true;
        result.redirectLocation = res.headers.location;
      }

      if (verbose) {
        result.verbose = { requestHeaders, responseHeaders: res.headers };
        if (scheme === 'https' && typeof res.socket.getPeerCertificate === 'function') {
          const cert = res.socket.getPeerCertificate();
          if (cert && cert.subject) {
            result.verbose.tls = {
              subject: cert.subject.CN || JSON.stringify(cert.subject),
              issuer: cert.issuer ? (cert.issuer.CN || JSON.stringify(cert.issuer)) : null,
              validFrom: cert.valid_from || null,
              validTo: cert.valid_to || null,
              selfSigned: !!cert.subject && !!cert.issuer && cert.subject.CN === cert.issuer.CN,
            };
          }
        }
      }

      finish(result);
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, error: `timeout after ${timeoutMs}ms` }); });
    req.on('error', (e) => finish({ ok: false, error: e.message }));
    req.end();
  });
}

function register(router) {
  router.get('/api/backends', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, { vhosts: listVhostTargets({ sitesDir: DIR_SITES, upstreamDirs: UPSTREAM_DIRS }) });
  });

  router.post('/api/backends/check', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);

    const body = await parseBody(req);
    const { file, blockIndex, locationIndex, targetIndex, serverNameIndex, verbose } = body;
    if (!file) return httpLib.badRequest(res, 'file required');

    // Same traversal guard as the config browser — never trust a client path.
    const filePath = safeResolveWithin(file, [DIR_SITES]);
    if (!filePath) return httpLib.forbidden(res, 'Access denied');

    const content = safeReadFile(filePath);
    if (content === null) return httpLib.notFound(res, 'File not found');

    const upstreams = parseUpstreams(UPSTREAM_DIRS);
    const blocks = parseVhostFile(content, upstreams);
    const block = blocks[blockIndex];
    const location = block?.locations?.[locationIndex];
    const target = location?.targets?.[targetIndex];
    if (!target) return httpLib.badRequest(res, 'no such target — the file may have changed, refresh and try again');
    if (location.kind === 'unresolved') return httpLib.badRequest(res, 'this location could not be resolved to a real target');

    // A vhost commonly carries several server_name entries pointing at the
    // same target (aliases, www + apex, legacy domains...) and name-based
    // routing on the backend side means one of them can quietly stop being
    // served while the others keep working. The client may ask to test a
    // specific one, but only by INDEX into this file's own server_names —
    // never by sending a hostname itself, which would let an authenticated
    // page send an arbitrary Host header to an internal target.
    let hostHeader;
    if (Number.isInteger(serverNameIndex) && block.serverNames[serverNameIndex] && block.serverNames[serverNameIndex] !== '_') {
      hostHeader = block.serverNames[serverNameIndex];
    } else {
      hostHeader = block.serverNames.find(n => n !== '_') || target.host;
    }

    const result = await checkTarget({ ...target, hostHeader }, { verbose: !!verbose });
    return send(res, 200, { ...result, target: { ...target, hostHeader } });
  });
}

module.exports = { register, checkTarget };
