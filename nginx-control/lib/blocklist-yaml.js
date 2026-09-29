'use strict';
/**
 * Minimal YAML subset for config/blocklists.yml.
 *
 * Same rationale and same restricted shape as nginx-analyzer's
 * lib/rules-yaml.js (zero-npm-dependency project, a full YAML parser is not
 * worth pulling in for what amounts to flat config + one list of flat maps).
 * This file adds top-level scalar settings on top of that shape, because
 * blocklists.yml needs both:
 *
 *   enable: true
 *   interval_cron: "0 3 * * *"
 *   block_action: deny_403
 *   hit_logging_enable: false
 *   hit_logging_method: dedicated
 *   sources:
 *     - name: datashield
 *       url: "https://example.org/list.txt"
 *       enable: true
 *
 * A line is either a comment (`#...`), blank, a top-level `key: value` pair
 * (0-indent), the `sources:` list marker, a new list item (`  - key: value`,
 * two-space indent), or a continuation field of the current item
 * (`    key: value`, four-space indent). Anything else is a syntax error,
 * reported with its line number.
 */

const { stripInlineComment } = require('./simple-yaml');

// Fix (audit finding MISC-10): an inline comment (`enable: false  # pause`)
// used to become part of the value here — `"false  # pause"` is not `'false'`
// so the `=== false` check below never matched, and a source or top-level
// flag meant to be disabled with an explanatory comment stayed enabled.
function parseScalar(raw) {
  const v = stripInlineComment(raw);
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return null;
  if (v.toLowerCase() === 'true') return true;
  if (v.toLowerCase() === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

/**
 * Parse raw YAML text into { config, sources, errors }. `config` holds the
 * top-level flat scalar keys (unvalidated); `sources` holds every list item
 * that parsed as a flat map (unvalidated field-wise — see validateSource);
 * `errors` holds line-numbered syntax problems. One malformed source does
 * not stop the rest of the file from parsing.
 */
function parseBlocklistYaml(text) {
  const errors = [];
  const config = {};
  const sources = [];
  let current = null;
  let inSourcesList = false;
  const lines = String(text || '').split('\n');

  const closeCurrent = () => { if (current) { sources.push(current); current = null; } };

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;

    if (/^sources\s*:\s*$/.test(raw)) { closeCurrent(); inSourcesList = true; continue; }

    const itemMatch = raw.match(/^  - ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (inSourcesList && itemMatch) {
      closeCurrent();
      current = {};
      current[itemMatch[1]] = parseScalar(itemMatch[2]);
      continue;
    }

    const fieldMatch = raw.match(/^    ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (inSourcesList && fieldMatch && current) {
      current[fieldMatch[1]] = parseScalar(fieldMatch[2]);
      continue;
    }

    // Top-level flat key — only recognized before/outside the sources list,
    // so a stray 0-indent line after "sources:" (a typo'd new top key, or a
    // list item that lost its indentation) is reported rather than silently
    // reopening `config`.
    const topMatch = raw.match(/^([A-Za-z_]+)\s*:\s*(.*)$/);
    if (!inSourcesList && topMatch) {
      config[topMatch[1]] = parseScalar(topMatch[2]);
      continue;
    }

    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  closeCurrent();
  return { config, sources, errors };
}

const NAME_RE = /^[A-Za-z0-9_-]+$/;

/** Validate one already-parsed source object. Returns a list of error strings (empty = valid). */
function validateSource(s, seenNames) {
  const errs = [];
  const label = s && s.name ? `source "${s.name}"` : 'source sans nom';
  if (!s.name || typeof s.name !== 'string' || !NAME_RE.test(s.name)) {
    errs.push(`${label} : "name" est requis (lettres/chiffres/underscore/tiret uniquement)`);
  } else if (seenNames.has(s.name)) {
    errs.push(`${label} : nom deja utilise par une autre source`);
  }
  if (!s.url || typeof s.url !== 'string' || !/^https?:\/\/.+/i.test(s.url)) {
    errs.push(`${label} : "url" est requise et doit commencer par http:// ou https://`);
  }
  if (s.name && NAME_RE.test(s.name)) seenNames.add(s.name);
  return errs;
}

const BLOCK_ACTIONS = new Set(['deny_403', 'drop_444']);
// "dedicated" (Methode 1, log global dedie via `access_log ... if=`, precis
// mais ecrit un fichier de plus) or "approx" (Methode 2, aucun log dedie —
// depuis la v12.29.0 l'analyseur derive les hits directement du/des log(s)
// d'acces qu'il suit deja, via les sources poussees par
// features/blocklists.js's pushBlocklistSources() — voir
// nginx-analyzer/lib/blocklist-sources.js). Operator-selectable per the
// project's explicit requirement — never hardcoded to one or the other.
const HIT_LOGGING_METHODS = new Set(['dedicated', 'approx']);

/**
 * Parse + validate in one pass. `valid` is the subset of `sources` that
 * passed validation, normalized with defaults applied. `settings` normalizes
 * the top-level flat config with defaults. `errors` covers both syntax and
 * validation problems.
 */
function parseAndValidate(text) {
  const { config, sources, errors } = parseBlocklistYaml(text);
  const seenNames = new Set();
  const valid = [];
  for (const s of sources) {
    const srcErrors = validateSource(s, seenNames);
    if (srcErrors.length) { errors.push(...srcErrors); continue; }
    valid.push({ name: s.name, url: s.url, enable: s.enable !== false });
  }
  const settings = {
    enable: config.enable !== false,
    intervalCron: typeof config.interval_cron === 'string' && config.interval_cron.trim()
      ? config.interval_cron.trim() : '0 */6 * * *',
    blockAction: BLOCK_ACTIONS.has(config.block_action) ? config.block_action : 'deny_403',
    hitLogging: {
      enable: config.hit_logging_enable === true,
      method: HIT_LOGGING_METHODS.has(config.hit_logging_method) ? config.hit_logging_method : 'dedicated',
    },
  };
  return { settings, sources, errors, valid };
}

module.exports = { parseBlocklistYaml, validateSource, parseAndValidate };
