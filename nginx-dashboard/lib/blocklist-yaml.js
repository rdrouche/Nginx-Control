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
 *   whitelist:
 *     - "10.0.0.0/8"
 *     - "203.0.113.10"
 *
 * A line is either a comment (`#...`), blank, a top-level `key: value` pair
 * (0-indent), the `sources:` list marker, a new list item (`  - key: value`,
 * two-space indent), a continuation field of the current item
 * (`    key: value`, four-space indent), the `whitelist:` list marker, or a
 * whitelist entry (`  - <ip-or-cidr>`, two-space indent, no colon-separated
 * key — a bare scalar). Anything else is a syntax error, reported with its
 * line number.
 *
 * `whitelist` (retour utilisateur, v12.50.0 : "gerer une liste blanche...
 * soit CIDR ou juste une ip") is a global safety net applied to the FINAL
 * merged IP set, after every source (url or analyzer-derived) — see
 * features/blocklists.js's refreshBlocklists(). An address or CIDR block
 * listed here is never written to the generated geo{} table, whichever
 * source(s) tried to include it — typically an operator's own private
 * ranges, so the analyzer-driven "Blocklist a la CrowdSec" mechanism can
 * never auto-block internal traffic even under a misconfiguration.
 */

const { stripInlineComment } = require('./simple-yaml');
const { isValidPattern } = require('./cidr');
const { normalizeChallengeSettings } = require('./challenge-gate');

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
  const whitelist = [];
  let current = null;
  let inSourcesList = false;
  let inWhitelistList = false;
  const lines = String(text || '').split('\n');

  const closeCurrent = () => { if (current) { sources.push(current); current = null; } };

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;

    if (/^sources\s*:\s*$/.test(raw)) { closeCurrent(); inSourcesList = true; inWhitelistList = false; continue; }
    if (/^whitelist\s*:\s*$/.test(raw)) { closeCurrent(); inSourcesList = false; inWhitelistList = true; continue; }

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

    // Entree de liste blanche : un scalaire brut, pas une map — jamais de
    // "cle: valeur", juste "  - 10.0.0.0/8" ou "  - 203.0.113.10".
    const whitelistItemMatch = raw.match(/^  - (.+)$/);
    if (inWhitelistList && whitelistItemMatch) {
      const v = stripInlineComment(whitelistItemMatch[1]);
      const cleaned = /^".*"$/.test(v) || /^'.*'$/.test(v) ? v.slice(1, -1) : v;
      whitelist.push({ raw: cleaned, lineNo });
      continue;
    }

    // Top-level flat key — only recognized before/outside the sources and
    // whitelist lists, so a stray 0-indent line after either marker (a
    // typo'd new top key, or a list item that lost its indentation) is
    // reported rather than silently reopening `config`.
    const topMatch = raw.match(/^([A-Za-z_]+)\s*:\s*(.*)$/);
    if (!inSourcesList && !inWhitelistList && topMatch) {
      config[topMatch[1]] = parseScalar(topMatch[2]);
      continue;
    }

    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  closeCurrent();
  return { config, sources, whitelist, errors };
}

const NAME_RE = /^[A-Za-z0-9_-]+$/;
const SOURCE_TYPES = new Set(['url', 'analyzer']);

/**
 * Validate one already-parsed source object. Returns a list of error strings
 * (empty = valid). Two source shapes, selected by `type` (default "url" —
 * absent from every source written before this field existed, so no
 * pre-existing config breaks):
 *
 *  - "url" (historique) : recupere une liste tierce par HTTP, comme documente
 *    en tete de ce fichier.
 *  - "analyzer" (retour utilisateur, v12.49.4) : ne recupere rien par HTTP —
 *    ses IP viennent de nginx-analyzer lui-meme. A partir de la v12.50.0, le
 *    seuil de repetition, la fenetre et la remediation se configurent au
 *    niveau de CHAQUE REGLE d Analyse (integree ou personnalisee — voir
 *    nginx-analyzer/lib/rules-manager.js#listBlocklistRules()), pas ici :
 *    une source "analyzer" n a donc plus que `name`/`enable`, et agrege le
 *    resultat de toutes les regles ayant opte (threshold configure).
 */
function validateSource(s, seenNames) {
  const errs = [];
  const label = s && s.name ? `source "${s.name}"` : 'source sans nom';
  if (!s.name || typeof s.name !== 'string' || !NAME_RE.test(s.name)) {
    errs.push(`${label} : "name" est requis (lettres/chiffres/underscore/tiret uniquement)`);
  } else if (seenNames.has(s.name)) {
    errs.push(`${label} : nom deja utilise par une autre source`);
  }
  const type = s.type && SOURCE_TYPES.has(s.type) ? s.type : 'url';
  if (s.type && !SOURCE_TYPES.has(s.type)) {
    errs.push(`${label} : "type" invalide ("${s.type}") — valeurs acceptees : url, analyzer`);
  }
  if (type === 'url') {
    if (!s.url || typeof s.url !== 'string' || !/^https?:\/\/.+/i.test(s.url)) {
      errs.push(`${label} : "url" est requise et doit commencer par http:// ou https://`);
    }
  }
  if (s.name && NAME_RE.test(s.name)) seenNames.add(s.name);
  return errs;
}

/**
 * Validate one whitelist entry. Returns an error string, or null if valid.
 * Accepts a bare address or a CIDR block (v4 or v6) — same `isValidPattern`
 * used to validate every IP/CIDR that ends up in the generated geo{} table,
 * so a whitelist entry can never itself be an injection vector.
 */
function validateWhitelistEntry(entry) {
  if (!isValidPattern(entry.raw)) {
    return `Ligne ${entry.lineNo} : liste blanche — "${entry.raw}" n est pas une adresse IP ou un bloc CIDR valide`;
  }
  return null;
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
function parseAndValidate(text, challengeOverrides) {
  const { config, sources, whitelist, errors } = parseBlocklistYaml(text);
  // v12.65.0 : config/challenge.yml peut porter les reglages challenge_* (page
  // « Challenge HTTP », utilisable sans blocklist) ; il l emporte sur blocklists.yml.
  if (challengeOverrides) Object.assign(config, challengeOverrides);
  const seenNames = new Set();
  const valid = [];
  for (const s of sources) {
    const srcErrors = validateSource(s, seenNames);
    if (srcErrors.length) { errors.push(...srcErrors); continue; }
    const type = s.type === 'analyzer' ? 'analyzer' : 'url';
    if (type === 'url') {
      valid.push({ name: s.name, type, url: s.url, enable: s.enable !== false });
    } else {
      valid.push({ name: s.name, type, enable: s.enable !== false });
    }
  }
  const validWhitelist = [];
  for (const entry of whitelist || []) {
    const err = validateWhitelistEntry(entry);
    if (err) { errors.push(err); continue; }
    validWhitelist.push(entry.raw);
  }
  const challenge = normalizeChallengeSettings(config);
  errors.push(...challenge.errors);
  const settings = {
    challenge: challenge.settings,
    enable: config.enable !== false,
    intervalCron: typeof config.interval_cron === 'string' && config.interval_cron.trim()
      ? config.interval_cron.trim() : '0 */6 * * *',
    // Cadence PROPRE a la source "analyzer" (v12.53.0) : elle se calcule
    // localement (aucun telechargement), et doit etre bien plus frequente que
    // interval_cron (6 h par defaut) sous peine de manquer des alertes dont la
    // fenetre de regle (ex. 5 min) est plus courte que l'intervalle.
    analyzerIntervalCron: typeof config.analyzer_interval_cron === 'string' && config.analyzer_interval_cron.trim()
      ? config.analyzer_interval_cron.trim() : '* * * * *',
    blockAction: BLOCK_ACTIONS.has(config.block_action) ? config.block_action : 'deny_403',
    hitLogging: {
      enable: config.hit_logging_enable === true,
      method: HIT_LOGGING_METHODS.has(config.hit_logging_method) ? config.hit_logging_method : 'dedicated',
    },
  };
  return { settings, sources, errors, valid, whitelist: validWhitelist };
}

module.exports = {
  parseBlocklistYaml, validateSource, validateWhitelistEntry, parseAndValidate, SOURCE_TYPES,
};
