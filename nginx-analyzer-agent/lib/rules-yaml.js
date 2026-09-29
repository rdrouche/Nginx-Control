'use strict';
/**
 * Minimal YAML subset for user-authored custom detection rules.
 *
 * The project is deliberately zero-npm-dependency (same rule as the
 * dashboard's own flat-YAML config readers), so a real YAML library is not
 * an option here. Rather than hand-roll a general YAML parser — a notoriously
 * deep spec, most of which nobody needs for this — this file supports exactly
 * one shape: a top-level `rules:` key holding a list of flat maps (scalar
 * values only, no nesting inside a rule). That is all a detection rule needs
 * (see the field list in `validateRule` below), and it is also exactly the
 * shape a CrowdSec scenario file or this project's own `analyzer.yml` uses —
 * so the restriction costs nothing in practice while keeping the parser
 * small enough to read in one sitting and trust without a fuzzer.
 *
 * Expected shape:
 *
 *   rules:
 *     - id: 101
 *       name: admin_probe
 *       enable: true
 *       severity: high
 *       description: "Beaucoup de requetes vers des chemins d administration"
 *       window_minutes: 5
 *       min_matches: 10
 *       path_hint: "(wp-admin|phpmyadmin|\\.env)"
 *       ua_hint: null
 *       status_in: [401, 403]
 *       method_in: []
 *
 * A line is either a comment (`#...`), blank, the top-level `rules:` marker,
 * a new list item (`  - key: value`, two-space indent), or a continuation
 * field of the current item (`    key: value`, four-space indent). Anything
 * else is a syntax error, reported with its line number rather than silently
 * ignored — a rule that fails to parse must never be mistaken for a rule
 * that parsed but does nothing.
 */

/**
 * Fix (audit report, Basse/Analyzer, "rules-yaml.js:45-51"): a double-quoted
 * scalar was returned with its quotes stripped but its backslash escapes
 * untouched. The project's own documented example,
 * `path_hint: "(wp-admin|phpmyadmin|\\.env)"`, is meant to compile to the
 * regex source `(wp-admin|phpmyadmin|\.env)` (one literal backslash before
 * the dot, i.e. "escaped dot") the way any YAML double-quoted string would
 * unescape it — but without this step, `\\` was handed to `new RegExp()`
 * completely unprocessed, so `RegExp('(wp-admin|phpmyadmin|\\\\.env)')`
 * required TWO literal backslashes in the traffic itself, never matching a
 * real request to `/.env`. Only the escapes meaningful for a regex source
 * string are handled (`\\`, `\"`, and the common whitespace escapes); an
 * unrecognized `\x` is left as `x`, matching standard YAML/JSON behavior for
 * an escape sequence.
 */
function unescapeDoubleQuoted(s) {
  return s.replace(/\\(.)/g, (_, c) => {
    switch (c) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      case '"': return '"';
      case '\\': return '\\';
      default: return c;
    }
  });
}

/** Parse one scalar value: null, boolean, number, quoted string, inline array, or bare string. */
function parseScalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return null;
  if (v.toLowerCase() === 'true') return true;
  if (v.toLowerCase() === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^\[.*\]$/.test(v)) {
    const inner = v.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map(x => parseScalar(x.trim()));
  }
  if (/^".*"$/.test(v)) return unescapeDoubleQuoted(v.slice(1, -1));
  // Simple-quoted: YAML's only escape inside '...' is '' for a literal quote.
  if (/^'.*'$/.test(v)) return v.slice(1, -1).replace(/''/g, "'");
  return v;
}

/**
 * Parse raw YAML text into { rules, errors }. `rules` holds every item that
 * parsed as a flat map (unvalidated field-wise — see validateRule for that);
 * `errors` holds line-numbered syntax problems. Both can be non-empty at
 * once: one malformed rule does not stop the rest of the file from parsing.
 */
function parseRulesYaml(text) {
  const errors = [];
  const rules = [];
  let current = null;
  let sawRulesKey = false;
  const lines = String(text || '').split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;

    if (/^rules\s*:\s*$/.test(raw)) { sawRulesKey = true; continue; }

    const itemMatch = raw.match(/^  - ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (itemMatch) {
      if (current) rules.push(current);
      current = {};
      current[itemMatch[1]] = parseScalar(itemMatch[2]);
      continue;
    }

    const fieldMatch = raw.match(/^    ([A-Za-z_]+)\s*:\s*(.*)$/);
    if (fieldMatch && current) {
      current[fieldMatch[1]] = parseScalar(fieldMatch[2]);
      continue;
    }

    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  if (current) rules.push(current);
  if (!sawRulesKey && rules.length === 0 && errors.length === 0 && text && text.trim()) {
    errors.push('Cle racine "rules:" introuvable — le fichier doit commencer par "rules:" suivi d une liste');
  }
  return { rules, errors };
}

const SEVERITIES = new Set(['low', 'medium', 'high']);

/** Validate one already-parsed rule object. Returns a list of error strings (empty = valid). */
function validateRule(r, seenIds) {
  const errs = [];
  const label = r && r.name ? `regle "${r.name}"` : `regle ${JSON.stringify(r?.id ?? '?')}`;
  if (!Number.isInteger(r.id) || r.id < 100) {
    errs.push(`${label} : "id" doit etre un entier >= 100 (0-99 sont reserves aux regles integrees)`);
  } else if (seenIds.has(r.id)) {
    errs.push(`${label} : id ${r.id} deja utilise par une autre regle`);
  }
  if (!r.name || typeof r.name !== 'string' || !/^[A-Za-z0-9_-]+$/.test(r.name)) {
    errs.push(`${label} : "name" est requis (lettres/chiffres/underscore/tiret uniquement)`);
  }
  if (r.severity !== undefined && !SEVERITIES.has(r.severity)) {
    errs.push(`${label} : "severity" doit etre low, medium ou high`);
  }
  if (!Number.isFinite(r.min_matches) || r.min_matches <= 0) {
    errs.push(`${label} : "min_matches" est requis et doit etre un nombre > 0`);
  }
  if (r.window_minutes !== undefined && (!Number.isFinite(r.window_minutes) || r.window_minutes <= 0)) {
    errs.push(`${label} : "window_minutes" doit etre un nombre > 0`);
  }
  for (const field of ['path_hint', 'ua_hint']) {
    if (r[field] != null) {
      try { new RegExp(r[field]); }
      catch (e) { errs.push(`${label} : "${field}" n est pas une expression reguliere valide (${e.message})`); }
    }
  }
  for (const field of ['status_in', 'method_in']) {
    if (r[field] != null && !Array.isArray(r[field])) {
      errs.push(`${label} : "${field}" doit etre une liste, ex: [401, 403]`);
    }
  }
  if (r.id != null && Number.isInteger(r.id)) seenIds.add(r.id);
  return errs;
}

/**
 * Parse + validate in one pass. Returns { rules, errors, valid } where
 * `valid` is the subset of `rules` that passed validation, normalized with
 * defaults applied — this is what gets handed to the Detector. `errors`
 * covers both syntax and validation problems, always line/rule-attributed
 * so the editor can point at the actual mistake.
 */
function parseAndValidate(text) {
  const { rules, errors } = parseRulesYaml(text);
  const seenIds = new Set();
  const valid = [];
  for (const r of rules) {
    const ruleErrors = validateRule(r, seenIds);
    if (ruleErrors.length) { errors.push(...ruleErrors); continue; }
    valid.push({
      id: r.id,
      name: r.name,
      enable: r.enable !== false,
      severity: r.severity || 'medium',
      description: r.description || '',
      windowMinutes: r.window_minutes || 5,
      minMatches: r.min_matches,
      pathHint: r.path_hint ? new RegExp(r.path_hint, 'i') : null,
      pathHintRaw: r.path_hint || null,
      uaHint: r.ua_hint ? new RegExp(r.ua_hint, 'i') : null,
      uaHintRaw: r.ua_hint || null,
      // Fix (audit report, Basse/Analyzer): `status_in: ["401"]` (a quoted
      // status code, easy to type by habit since most other YAML values in
      // this file are quoted) used to survive as the STRING "401", while
      // `entry.status` (lib/detect.js) is always a Number — an `Array#includes`
      // check between the two never matches, so the rule silently never
      // fires. Numeric-looking strings are coerced to Number here so both
      // spellings behave identically; a genuinely non-numeric entry (a typo)
      // is left as-is rather than guessed at.
      statusIn: Array.isArray(r.status_in)
        ? r.status_in.map(s => (typeof s === 'string' && /^\d+$/.test(s) ? Number(s) : s))
        : [],
      methodIn: Array.isArray(r.method_in) ? r.method_in.map(m => String(m).toUpperCase()) : [],
    });
  }
  return { rules, errors, valid };
}

/** Serialize a list of normalized rules (or raw parsed objects) back to YAML text, for the editor's default content. */
function stringifyRules(rules) {
  if (!rules || !rules.length) return 'rules: []\n';
  const lines = ['rules:'];
  for (const r of rules) {
    const raw = r.pathHintRaw !== undefined ? r : r; // already-raw objects and normalized ones both read fine below
    const get = (k, altK) => (raw[k] !== undefined ? raw[k] : (altK ? raw[altK] : undefined));
    const id = get('id');
    const name = get('name');
    const enable = get('enable');
    const severity = get('severity');
    const description = get('description');
    const windowMinutes = get('window_minutes', 'windowMinutes');
    const minMatches = get('min_matches', 'minMatches');
    const pathHint = get('path_hint', 'pathHintRaw');
    const uaHint = get('ua_hint', 'uaHintRaw');
    const statusIn = get('status_in', 'statusIn') || [];
    const methodIn = get('method_in', 'methodIn') || [];
    lines.push(`  - id: ${id}`);
    lines.push(`    name: ${name}`);
    lines.push(`    enable: ${enable !== false}`);
    lines.push(`    severity: ${severity || 'medium'}`);
    lines.push(`    description: "${String(description || '').replace(/"/g, '\\"')}"`);
    lines.push(`    window_minutes: ${windowMinutes || 5}`);
    lines.push(`    min_matches: ${minMatches}`);
    lines.push(`    path_hint: ${pathHint ? `"${pathHint}"` : 'null'}`);
    lines.push(`    ua_hint: ${uaHint ? `"${uaHint}"` : 'null'}`);
    lines.push(`    status_in: [${statusIn.join(', ')}]`);
    lines.push(`    method_in: [${methodIn.join(', ')}]`);
  }
  return lines.join('\n') + '\n';
}

module.exports = { parseRulesYaml, validateRule, parseAndValidate, stringifyRules };
