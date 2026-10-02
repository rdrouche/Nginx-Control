'use strict';
/**
 * Deploy tokens — scoped credentials for CI/CD pipelines (Forgejo, GitHub,
 * GitLab, ...) to trigger a Git deployment (pull/test/deploy/backup) through
 * the API, without handing out the global admin API_TOKEN.
 *
 * Why this exists rather than reusing API_TOKEN: API_TOKEN authenticates as
 * a full admin (lib/auth.js's requireApiAuth() grants role 'admin') — every
 * route, every permission. Putting that in a CI secret means a leaked
 * secret (a compromised runner, a misconfigured public workflow log) is a
 * full dashboard compromise, not just an unwanted deploy. A deploy token
 * authenticates as role 'deploy_ci' (PERMS.DEPLOY only, see lib/auth.js),
 * AND — enforced one layer up, in server.js's dispatch — only for a fixed,
 * small allowlist of git/backup routes, never anything else, regardless of
 * what PERMS.DEPLOY happens to gate elsewhere in the app today or in the
 * future. Losing one is losing the ability to trigger a deploy, nothing
 * more.
 *
 * "en fonction des utilisateurs" (per the feature request this was built
 * for): each token also carries its own `actions` allowlist (a subset of
 * pull/test/deploy/backup) — one CI system can be handed a token that can
 * only run `test` (e.g. on every push, for a status check), another a
 * separate token that can `deploy` (e.g. only from a protected branch's
 * pipeline). Omitting `actions` grants all four, for the common case of one
 * token per CI system with no finer split needed.
 *
 * Same minimal-YAML-subset approach as lib/blocklist-yaml.js, for the same
 * reason: a flat list of small maps does not justify a real YAML parser in
 * this zero-npm-dependency project. Token values are masked automatically
 * wherever this file is served to the UI — lib/secrets.js's masking keys on
 * the field name "token", which config-editor.js already applies to every
 * *.yml it serves, deploy-tokens.yml included.
 *
 *   tokens:
 *     - name: forgejo-ci
 *       token: "a-long-random-secret-string"
 *       enable: true
 *       actions: [pull, test, deploy, backup]   # optional, defaults to all four
 */

const fs     = require('fs');
const crypto = require('crypto');

const cfg = require('./config');

const { DEPLOY_TOKENS_FILE } = cfg;

// A local copy of lib/auth.js's safeCompare(), not a shared import: this
// module is required BY lib/auth.js (authenticateDeployToken() there needs
// findByToken() here), so importing auth.js back would be circular.
function safeCompare(a, b) {
  try {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

const ACTIONS = new Set(['pull', 'test', 'deploy', 'backup']);
const NAME_RE = /^[A-Za-z0-9_-]+$/;

function parseScalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return null;
  if (v.toLowerCase() === 'true') return true;
  if (v.toLowerCase() === 'false') return false;
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

/**
 * Parse raw YAML text into { tokens, errors }. Same restricted shape as
 * blocklist-yaml.js's `sources:` list: a `tokens:` marker, then `  - key:
 * value` list items with `    key: value` continuation fields. `actions`,
 * when present, is a simple `[a, b, c]` bracketed inline list — this
 * project's minimal parser does not support a nested YAML list under a list
 * item, so the compact inline form is what operators write.
 */
function parseDeployTokensYaml(text) {
  const errors = [];
  const tokens = [];
  let current = null;
  let inList = false;
  const lines = String(text || '').split('\n');

  const closeCurrent = () => { if (current) { tokens.push(current); current = null; } };

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;

    if (/^tokens\s*:\s*$/.test(raw)) { closeCurrent(); inList = true; continue; }

    const itemMatch = raw.match(/^  - ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (inList && itemMatch) {
      closeCurrent();
      current = {};
      current[itemMatch[1]] = parseScalar(itemMatch[2]);
      continue;
    }

    const fieldMatch = raw.match(/^    ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (inList && fieldMatch && current) {
      const key = fieldMatch[1];
      const val = fieldMatch[2].trim();
      if (key === 'actions') {
        const inner = val.replace(/^\[/, '').replace(/\]$/, '');
        current[key] = inner.trim()
          ? inner.split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean)
          : [];
      } else {
        current[key] = parseScalar(val);
      }
      continue;
    }

    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  closeCurrent();
  return { tokens, errors };
}

/** Validate one already-parsed token entry. Returns a list of error strings (empty = valid). */
function validateToken(entry, seenNames) {
  const errs = [];
  const label = entry && entry.name ? `jeton "${entry.name}"` : 'jeton sans nom';
  if (!entry.name || typeof entry.name !== 'string' || !NAME_RE.test(entry.name)) {
    errs.push(`${label} : "name" est requis (lettres/chiffres/underscore/tiret uniquement)`);
  } else if (seenNames.has(entry.name)) {
    errs.push(`${label} : nom deja utilise par un autre jeton`);
  }
  if (!entry.token || typeof entry.token !== 'string' || entry.token.length < 16) {
    errs.push(`${label} : "token" est requis et doit faire au moins 16 caracteres`);
  }
  if (entry.actions !== undefined) {
    const bad = (entry.actions || []).filter(a => !ACTIONS.has(a));
    if (bad.length) errs.push(`${label} : action(s) inconnue(s) dans "actions" — ${bad.join(', ')} (attendu : ${[...ACTIONS].join(', ')})`);
  }
  if (entry.name && NAME_RE.test(entry.name)) seenNames.add(entry.name);
  return errs;
}

/**
 * Parse + validate in one pass. `valid` is the subset of `tokens` that
 * passed validation, normalized with defaults applied (`enable` defaults to
 * true, `actions` defaults to every action).
 */
function parseAndValidate(text) {
  const { tokens, errors } = parseDeployTokensYaml(text);
  const seenNames = new Set();
  const valid = [];
  for (const entry of tokens) {
    const entryErrors = validateToken(entry, seenNames);
    if (entryErrors.length) { errors.push(...entryErrors); continue; }
    valid.push({
      name: entry.name,
      token: entry.token,
      enable: entry.enable !== false,
      actions: Array.isArray(entry.actions) && entry.actions.length ? entry.actions : [...ACTIONS],
    });
  }
  return { tokens, errors, valid };
}

function loadDeployTokens() {
  let text = '';
  try { text = fs.readFileSync(DEPLOY_TOKENS_FILE, 'utf8'); } catch { /* missing = none configured */ }
  return parseAndValidate(text);
}

/**
 * Constant-time lookup by token value: every enabled entry is compared
 * (never short-circuiting on the first length mismatch across entries, only
 * within safeCompare's own per-candidate check) so response timing does not
 * leak which, if any, entry a guessed token was close to.
 */
function findByToken(rawToken) {
  if (!rawToken) return null;
  const { valid } = loadDeployTokens();
  let match = null;
  for (const entry of valid) {
    if (!entry.enable) continue;
    if (safeCompare(rawToken, entry.token)) match = entry;
  }
  return match;
}

module.exports = {
  ACTIONS, parseDeployTokensYaml, validateToken, parseAndValidate,
  loadDeployTokens, findByToken,
};
