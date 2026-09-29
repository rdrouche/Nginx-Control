'use strict';
/**
 * Fetches one blocklist source over HTTP(S). Same zero-dependency pattern as
 * features/sync-ref.js's fetchRefFileContent (Node's built-in http/https,
 * no library) — never throws, resolves { ok: false, error } on any failure
 * so a bad or unreachable source never takes down the refresh cycle.
 *
 * A size cap is enforced while streaming (not after buffering everything):
 * these URLs are supplied by the operator but the CONTENT is a third party's
 * to change at any time, and nothing stops a source from growing to gigabytes
 * or from being pointed at something else entirely after the fact.
 */

const http  = require('http');
const https = require('https');

const TIMEOUT_MS   = 15_000;
const MAX_BYTES     = 25 * 1024 * 1024; // 25MB — generous for an IP list, small enough to bound memory/time

function fetchBlocklistText(url) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, error: 'URL invalide' }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return resolve({ ok: false, error: 'Seuls http:// et https:// sont acceptes' });
    }
    const proto = u.protocol === 'https:' ? https : http;
    const req = proto.request(Object.assign(new URL(url), {
      method: 'GET',
      headers: { 'User-Agent': 'nginx-dashboard-blocklists' },
      timeout: TIMEOUT_MS,
    }), (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // drain so the socket can be reused/closed cleanly
        return resolve({ ok: false, error: `HTTP ${res.statusCode}` });
      }
      let data = '';
      let bytes = 0;
      let aborted = false;
      res.on('data', (chunk) => {
        if (aborted) return;
        bytes += chunk.length;
        if (bytes > MAX_BYTES) {
          aborted = true;
          req.destroy();
          return resolve({ ok: false, error: `Reponse trop volumineuse (> ${MAX_BYTES / 1024 / 1024}MB)` });
        }
        data += chunk;
      });
      res.on('end', () => { if (!aborted) resolve({ ok: true, text: data }); });
      res.on('error', (e) => { if (!aborted) resolve({ ok: false, error: e.message }); });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'Timeout' }); });
    req.end();
  });
}

module.exports = { fetchBlocklistText, MAX_BYTES, TIMEOUT_MS };
