'use strict';
/**
 * Anti-SSRF guard for outbound HTTP requests this dashboard makes to a
 * URL an operator configured (currently: webhooks — see lib/events.js's
 * fireWebhook() and server.js's webhook routes).
 *
 * Fix (audit finding, Basse/"Sécurité et durcissement"): a webhook URL was
 * never checked against anything. Creating/editing webhooks is admin-only,
 * so this isn't a stranger-walks-in vulnerability, but it's still a real
 * confused-deputy risk: an admin session hijacked via XSS, or a
 * genuinely malicious admin on a shared instance, could point a webhook at
 * an internal-only service (another container on the same Docker network,
 * the cloud metadata endpoint at 169.254.169.254, the dashboard's own
 * loopback) and have THIS SERVER make the request — bypassing network
 * segmentation that would otherwise stop a browser or an outside caller
 * cold. Checking only at creation time isn't enough either (DNS rebinding:
 * a hostname that resolves to a public IP when validated and to a private
 * one when the webhook actually fires) — see `lookup` below, which is
 * passed directly to `http.request`/`https.request` so Node resolves DNS
 * and this guard inspects the ANSWER right before connecting, not before.
 */

const dns = require('dns');
const { ipInCidr } = require('./cidr');

// RFC 1918/5735/4193/4291 etc. — loopback, link-local (includes the cloud
// metadata address, 169.254.0.0/16), private, carrier-grade NAT, multicast,
// reserved/benchmarking, and IPv6 equivalents (ULA, link-local, loopback,
// IPv4-mapped handled by normalizing below).
const BLOCKED_RANGES = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '64:ff9b::/96',
];

/** Strip a `::ffff:a.b.c.d` IPv4-mapped prefix so the IPv4 ranges above still match. */
function normalizeIp(ip) {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip || '');
  return m ? m[1] : ip;
}

function isBlockedIp(ip) {
  const norm = normalizeIp(ip);
  return BLOCKED_RANGES.some(range => ipInCidr(norm, range));
}

/**
 * Custom `lookup` for `http.request`/`https.request`'s options — resolves
 * the hostname exactly as Node normally would, then refuses to hand back an
 * address inside a blocked range. The request never gets far enough to
 * connect: `http.request` treats a `lookup` error the same as a DNS
 * failure.
 */
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addresses = Array.isArray(address) ? address : [{ address, family }];
    const blocked = addresses.find(a => isBlockedIp(a.address ?? a));
    if (blocked) {
      return callback(new Error(`SSRF guard: refusing to connect to ${hostname} (resolves to a private/reserved address)`));
    }
    callback(null, address, family);
  });
}

/**
 * Validate a webhook URL at creation/edit time — same-shape check as
 * safeLookup() but synchronous-ish (still does a DNS lookup) so an operator
 * gets immediate feedback instead of a silently-failing webhook. This is a
 * courtesy, not the actual security boundary — safeLookup() above, applied
 * at fire time, is what actually stops DNS rebinding.
 */
async function validateWebhookUrl(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { return { ok: false, error: 'URL invalide' }; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: 'Seuls http:// et https:// sont autorisés' };
  }
  return new Promise(resolve => {
    dns.lookup(url.hostname, { all: true }, (err, addresses) => {
      if (err) return resolve({ ok: true }); // DNS not yet resolvable (or offline) — let it through, checked again at fire time
      const blocked = addresses.find(a => isBlockedIp(a.address));
      if (blocked) return resolve({ ok: false, error: `L'hôte "${url.hostname}" pointe vers une adresse privée/réservée (${blocked.address})` });
      resolve({ ok: true });
    });
  });
}

module.exports = { isBlockedIp, safeLookup, validateWebhookUrl, BLOCKED_RANGES };
