'use strict';
/**
 * Fix v12.22.x (audit finding ANA-10): the analyzer's HTTP API trusted the
 * Docker network boundary alone ("only the dashboard is on nginx-net"). But
 * nginx-net is shared with every backend the reverse proxy fronts, and a
 * compromised backend container can reach the analyzer's port exactly as
 * easily as the dashboard can — from there it could silently disable
 * detection rules or add a 0.0.0.0/0 exception for itself, with nothing in
 * the analyzer's own API to stop it.
 *
 * The fix: a per-installation shared secret, generated here, passed to the
 * analyzer container as the ANALYZER_TOKEN env var at creation time
 * (features/analyzer.js startAnalyzer()), and sent back on every proxied
 * call as the X-Analyzer-Token header (analyzerApi()/analyzerApiJson()) —
 * see nginx-analyzer/server.js for the matching check.
 *
 * Persisted to a small 0600 file next to config/analyzer.yml, same
 * reasoning as lib/agent-tunnel-secret.js's own token: the value is baked
 * into the analyzer container's environment at create time, so a value that
 * changed on every dashboard restart would require recreating the analyzer
 * container (losing nothing itself, but an avoidable disruption) just to
 * keep talking to it.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cfg = require('./config');

const TOKEN_FILE = path.join(cfg.CONFIG_DIR, '.analyzer-token');

let cached = null;

function getAnalyzerToken() {
  if (cached) return cached;
  try {
    const existing = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (existing && /^[a-f0-9]{32,}$/i.test(existing)) { cached = existing; return cached; }
  } catch { /* absent — generated below */ }
  const fresh = crypto.randomBytes(24).toString('hex');
  try {
    fs.mkdirSync(cfg.CONFIG_DIR, { recursive: true });
    fs.writeFileSync(TOKEN_FILE, fresh + '\n', { mode: 0o600 });
  } catch { /* best-effort persistence — still usable in-memory for this process */ }
  cached = fresh;
  return cached;
}

module.exports = { getAnalyzerToken, TOKEN_FILE };
