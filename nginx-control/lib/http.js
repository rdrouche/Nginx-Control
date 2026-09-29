'use strict';
/**
 * HTTP plumbing and the route registry.
 *
 * The registry exists to replace a single 1500-line if/else chain in which
 * routing and business logic were interleaved. Each feature now registers its
 * own routes next to the code that serves them, so adding a domain never
 * touches this file — which is what caused patches to land in the wrong place,
 * or after the boot sequence had already run.
 *
 * Matching is exact-path first, then prefix, longest prefix winning. Both are
 * scoped by method, so GET and POST on the same path are separate entries.
 */

const cfg = require('./config');
const { ipInCidr } = require('./cidr');

// ─── Responses ───────────────────────────────────────────────────────────────
/**
 * Send a response. JSON by default.
 *
 * Cross-origin access is opt-in: the dashboard is same-origin, so a wildcard
 * would only widen the attack surface for no benefit.
 */
function send(res, code, data, ct = 'application/json', extraHeaders = {}) {
  const body = ct === 'application/json' ? JSON.stringify(data) : data;
  const headers = {
    'Content-Type': ct,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'same-origin',
    // Fix (audit finding, Basse/"Sécurité et durcissement"): no HSTS, no CSP
    // at all previously. HSTS is inert over a plain-HTTP response (browsers
    // only honor it on a response actually delivered over TLS), so it's safe
    // to send unconditionally rather than threading request-scheme detection
    // through every one of this function's hundreds of call sites. The CSP
    // below is deliberately permissive on `script-src`/`style-src`
    // ('unsafe-inline') — the dashboard's own UI is built from a single
    // hand-written index.html full of inline `onclick=` handlers and inline
    // `<style>`/`<script>` blocks; a strict CSP would break the whole
    // interface. What it still buys: no script/style/font/frame/connection
    // from a THIRD-PARTY origin, ever — the actual floor an XSS or a
    // compromised dependency would otherwise be free to reach past — and
    // `frame-ancestors 'self'` closes the clickjacking gap X-Frame-Options
    // alone leaves for browsers that ignore it.
    //
    // Fix (v12.30.0): `font-src`/`style-src` used to also allow
    // fonts.gstatic.com/fonts.googleapis.com for public/index.html's Google
    // Fonts <link>, and Chart.js was loaded from cdn.jsdelivr.net — which
    // this policy's `script-src` never allowed in the first place (no
    // `https://cdn.jsdelivr.net` was ever added there), so the chart silently
    // failed to load for every operator running with the CSP actually
    // enforced (i.e. everyone). Rather than widen `script-src` to a
    // third-party origin — the exact thing this policy exists to prevent —
    // both are now vendored under public/assets/ (fonts/, vendor/) and served
    // same-origin, so `'self'` alone covers them and no third-party host
    // needs to be trusted at all, matching this policy's own stated intent.
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; "
      + "style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; "
      + "connect-src 'self' ws: wss:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
    ...extraHeaders,
  };
  if (cfg.CORS_ORIGIN) {
    headers['Access-Control-Allow-Origin']  = cfg.CORS_ORIGIN;
    headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Authorization,Content-Type';
    headers['Vary'] = 'Origin';
  }
  res.writeHead(code, headers);
  res.end(body);
}

const ok        = (res, data)           => send(res, 200, data);
const created   = (res, data)           => send(res, 201, data);
const forbidden = (res, msg = 'Forbidden')     => send(res, 403, { error: msg });
const notFound  = (res, msg = 'Not found')     => send(res, 404, { error: msg });
const badRequest= (res, msg = 'Bad request')   => send(res, 400, { error: msg });
const serverError = (res, e) =>
  send(res, 500, { error: (e && (e.error || e.message)) || String(e) });

// ─── Request body ────────────────────────────────────────────────────────────
/**
 * Read and JSON-parse a request body. Resolves {} on malformed input rather
 * than throwing: every caller treats a missing field as a validation error
 * anyway, and a 400 is friendlier than a 500.
 *
 * The size cap stops an unauthenticated POST from buffering unbounded memory.
 */
function parseBody(req, { limitBytes = 5 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let body = '', size = 0, aborted = false;
    req.on('data', d => {
      if (aborted) return;
      size += d.length;
      if (size > limitBytes) { aborted = true; resolve({}); req.destroy(); return; }
      body += d;
    });
    req.on('end', () => { if (!aborted) { try { resolve(JSON.parse(body)); } catch { resolve({}); } } });
    req.on('error', () => { if (!aborted) resolve({}); });
  });
}

/**
 * Bounded raw-body reader for non-JSON bodies (e.g. the login form's
 * application/x-www-form-urlencoded POST).
 *
 * SECURITY (fix v12.21.1, audit finding SEC-13): the login handler used to
 * accumulate `req.on('data', c => d += c)` with no limit at all, and no
 * authentication is required to reach it — a single POST of a few GB would
 * grow that string until the process ran out of memory, taking down every
 * session on the dashboard. Same shape as parseBody() above (default 4 KiB,
 * generous for a login form), but resolves the raw string rather than
 * attempting JSON.parse.
 */
function readRawBody(req, { limitBytes = 4 * 1024 } = {}) {
  return new Promise((resolve) => {
    let body = '', size = 0, aborted = false;
    req.on('data', d => {
      if (aborted) return;
      size += d.length;
      if (size > limitBytes) { aborted = true; resolve(''); req.destroy(); return; }
      body += d;
    });
    req.on('end', () => { if (!aborted) resolve(body); });
    req.on('error', () => { if (!aborted) resolve(''); });
  });
}

/** True when `ip` matches a plain address or CIDR block in cfg.TRUSTED_PROXIES. */
function isTrustedProxy(ip) {
  if (!ip) return false;
  const bare = ip.replace(/^::ffff:/, '');
  return cfg.TRUSTED_PROXIES.some(entry =>
    entry.includes('/') ? ipInCidr(bare, entry) : entry === bare || entry === ip);
}

/**
 * Client IP, honouring X-Forwarded-For only when it was set by a proxy we
 * actually trust.
 *
 * SECURITY (fix v12.21.1, audit finding SEC-05): this used to return the
 * LEFTMOST entry of X-Forwarded-For unconditionally — a header any client
 * fully controls when talking straight to this process (or even through
 * nginx: `$proxy_add_x_forwarded_for` only ever *appends*, it never removes
 * or rewrites what the client already sent as its first hop). That let a
 * client reset the login rate-limiter's per-IP bucket on every single
 * attempt just by sending a different X-Forwarded-For each time, making the
 * brute-force guard in lib/auth.js unlimited in practice.
 *
 * Fixed the standard way: only trust XFF when the actual TCP peer
 * (`req.socket.remoteAddress`) is itself a configured trusted proxy, and
 * even then take the RIGHTMOST entry that isn't itself a trusted proxy —
 * the last hop a trusted party could have appended, walking back through
 * any chain of trusted proxies in front of this one. A direct, untrusted
 * client's own socket address is used unconditionally, so no header it
 * sends can override its own identity.
 */
function clientIp(req) {
  const socketIp = req.socket?.remoteAddress || 'unknown';
  const fwd = req.headers['x-forwarded-for'];
  if (!fwd || !isTrustedProxy(socketIp)) return socketIp;
  const hops = String(fwd).split(',').map(s => s.trim()).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    if (!isTrustedProxy(hops[i])) return hops[i];
  }
  // Every hop (including the client-supplied ones) claims to be a trusted
  // proxy — fall back to the socket address rather than trusting blindly.
  return socketIp;
}

// ─── Route registry ──────────────────────────────────────────────────────────
class Router {
  constructor() {
    this.exact  = new Map();   // "GET /api/status" → handler
    this.prefix = [];          // [{ method, prefix, handler }]
  }

  /**
   * Register an exact-path route.
   * @param {string} method  HTTP verb
   * @param {string} path    exact pathname
   * @param {Function} handler  (ctx) => Promise<void>
   */
  add(method, path, handler) {
    const key = `${method} ${path}`;
    if (this.exact.has(key)) {
      // Silently shadowing a route is how duplicate handlers went unnoticed.
      throw new Error(`Duplicate route: ${key}`);
    }
    this.exact.set(key, handler);
    return this;
  }

  get(p, h)    { return this.add('GET', p, h); }
  post(p, h)   { return this.add('POST', p, h); }
  put(p, h)    { return this.add('PUT', p, h); }
  delete(p, h) { return this.add('DELETE', p, h); }

  /** Register a prefix route, for paths carrying a variable tail. */
  addPrefix(method, prefix, handler) {
    this.prefix.push({ method, prefix, handler });
    // Longest prefix wins, so a more specific route is never shadowed.
    this.prefix.sort((a, b) => b.prefix.length - a.prefix.length);
    return this;
  }

  /** Find a handler for a request, or null. */
  match(method, pathname) {
    const exact = this.exact.get(`${method} ${pathname}`);
    if (exact) return exact;
    for (const r of this.prefix) {
      if (r.method === method && pathname.startsWith(r.prefix)) return r.handler;
    }
    return null;
  }

  /** Every registered route, for start-up logging and drift checks. */
  list() {
    return [
      ...[...this.exact.keys()],
      ...this.prefix.map(r => `${r.method} ${r.prefix}*`),
    ].sort();
  }
}

/**
 * Inject a snippet of markup into an HTML document, just before its first
 * `<script>` tag rather than before `</head>`.
 *
 * `</head>` is, per the HTML5 spec, an optional tag — any minifier asked to
 * "remove optional tags" (a common flag: html-minifier-terser's
 * --remove-optional-tags, used in at least one real deployment pipeline for
 * this project) strips it entirely. `html.replace('</head>', snippet +
 * '</head>')` then finds nothing to replace and the snippet is silently
 * never injected — no error anywhere, just whatever the snippet was meant
 * to set up never happening. This bit twice in this project already: once
 * injecting the dashboard's own branding/version globals, once injecting a
 * WebSocket URL rewrite into a GoAccess report. `<script` cannot be
 * stripped the same way by any minifier — doing so would silently discard
 * the code that follows it — so it is the anchor here instead.
 *
 * Returns the modified HTML, or the original HTML unchanged (plus a
 * console.warn) if no `<script` tag exists to anchor on at all.
 */
function injectBeforeFirstScript(html, snippet, warnLabel) {
  const idx = html.indexOf('<script');
  if (idx === -1) {
    console.warn(`[http] Could not find a <script> tag to inject ${warnLabel || 'markup'} before — it will be missing.`);
    return html;
  }
  return html.slice(0, idx) + snippet + html.slice(idx);
}

module.exports = {
  send, ok, created, forbidden, notFound, badRequest, serverError,
  parseBody, readRawBody, clientIp, isTrustedProxy, Router, injectBeforeFirstScript,
};
