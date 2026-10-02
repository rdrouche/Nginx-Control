'use strict';
/**
 * Fix v12.22.0 (audit finding AGT-04, part 1 — primary fix): the tunnel
 * "mode 3" request-interception path (features/agent-tunnel.js's
 * maybeHandleTunnelRequest(), wired into server.js's handleRequest() BEFORE
 * any authentication) used to recognize a tunnel request by its Host header
 * alone. An approved-but-compromised agent could declare, as one of its own
 * `serverName`s, the exact hostname (or, before the companion fix in
 * lib/agent-manifest.js, a literal IP) by which operators reach the
 * dashboard itself — every request that arrived that way, `POST
 * /auth/login` included, would then be handed straight to that agent's
 * tunnel instead of the dashboard's own router.
 *
 * The fix: the generated tunnel vhost (lib/agent-manifest.js's
 * generateAgentVhostContent(), mode "tunnel" branch) now injects a secret,
 * dashboard-generated header — `X-NC-Tunnel: <token>` — via
 * `proxy_set_header` on its way to this dashboard. maybeHandleTunnelRequest()
 * only ever treats a request as tunnel traffic if that exact header is
 * present, so a request that reaches the dashboard any other way (a client
 * that merely forges the Host header, or hits the dashboard's real listener
 * directly by IP) can no longer be routed to an agent's tunnel — only nginx
 * itself, applying a vhost this dashboard generated and controls, can attach
 * that header.
 *
 * Persisted to a small 0600 file next to config/agents.yml rather than kept
 * purely in memory (unlike e.g. SESSION_SECRET): the header value is baked
 * into a generated nginx vhost FILE at manifest-apply time, so a value that
 * changed on every process restart would strand every already-generated
 * tunnel vhost until its next regeneration — needless breakage for a value
 * that gains nothing from rotating on its own.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cfg = require('./config');

const SECRET_FILE = path.join(cfg.CONFIG_DIR, '.agent-tunnel-secret');

let cached = null;

function getTunnelSecret() {
  if (cached) return cached;
  try {
    const existing = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (existing && /^[a-f0-9]{32,}$/i.test(existing)) { cached = existing; return cached; }
  } catch { /* absent — generated below */ }
  const fresh = crypto.randomBytes(24).toString('hex');
  try {
    fs.mkdirSync(cfg.CONFIG_DIR, { recursive: true });
    fs.writeFileSync(SECRET_FILE, fresh + '\n', { mode: 0o600 });
  } catch { /* best-effort persistence — still usable in-memory for this process */ }
  cached = fresh;
  return cached;
}

module.exports = { getTunnelSecret, SECRET_FILE };
