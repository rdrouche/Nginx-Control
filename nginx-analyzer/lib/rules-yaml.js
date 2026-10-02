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
 *       scope: ip              # ip (defaut) | global (toutes IP confondues, v12.60.0)
 *       min_ips: 5             # scope: global — nombre d'IP distinctes minimum (defaut 5)
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

// Retour utilisateur (v12.50.0) : le seuil de repetition + la remediation du
// mode "Blocklist a la CrowdSec" (v12.49.4) se configurent desormais au
// niveau de CHAQUE regle (integree ou personnalisee), plutot que sur une
// source globale — voir nginx-dashboard/features/blocklists.js. Une regle
// personnalisee peut donc porter, en plus de son propre critere de
// detection, ces quatre champs optionnels :
//
//   blocklist_threshold: 5          # nb de declenchements de CETTE regle,
//                                    # par IP, avant de la juger suspecte
//                                    # (absent/null = desactive pour cette
//                                    # regle : elle ne contribue jamais)
//   blocklist_window_minutes: 1440  # fenetre glissante de comptage, en
//                                    # MINUTES (24h par defaut)
//   blocklist_remediation: false    # applique reellement le blocage —
//                                    # meme convention "absent = false" que
//                                    # le reste du mecanisme (securite)
//   blocklist_remediation_minutes: null  # duree du blocage en minutes une
//                                    # fois applique (null = pas de duree
//                                    # propre : reste bloquee tant qu elle
//                                    # continue de depasser le seuil sur la
//                                    # fenetre glissante ci-dessus)
//   blocklist_remediation_type: block   # v12.63.0 : "block" (defaut, refus
//                                    # 403/444) ou "challenge" (l IP recoit une
//                                    # page de verification navigateur au lieu
//                                    # d un refus — voir nginx-challenge)
const REMEDIATION_TYPES = new Set(['block', 'challenge']);
const MAX_BLOCKLIST_WINDOW_MINUTES = 14 * 24 * 60;      // 14 jours, meme borne que MAX_CUSTOM_WINDOW_MINUTES (detect.js)
const MAX_BLOCKLIST_REMEDIATION_MINUTES = 30 * 24 * 60; // 30 jours : evite un blocage de facto permanent par erreur de saisie

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
  if (r.scope != null && r.scope !== 'ip' && r.scope !== 'global') {
    errs.push(`${label} : "scope" doit etre ip (defaut, comptage par IP) ou global (toutes IP confondues)`);
  }
  if (r.min_ips != null && (!Number.isInteger(r.min_ips) || r.min_ips < 1)) {
    errs.push(`${label} : "min_ips" doit etre un entier >= 1 (nombre d'IP distinctes, scope: global)`);
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
  if (r.blocklist_threshold != null && (typeof r.blocklist_threshold === 'boolean' || !Number.isFinite(+r.blocklist_threshold) || +r.blocklist_threshold < 1)) {
    errs.push(`${label} : "blocklist_threshold" doit etre un entier >= 1 (ou absent pour desactiver)`);
  }
  if (r.blocklist_window_minutes != null && (typeof r.blocklist_window_minutes === 'boolean' || !Number.isFinite(+r.blocklist_window_minutes) || +r.blocklist_window_minutes < 1)) {
    errs.push(`${label} : "blocklist_window_minutes" doit etre un entier >= 1`);
  }
  if (r.blocklist_remediation_minutes != null && (typeof r.blocklist_remediation_minutes === 'boolean' || !Number.isFinite(+r.blocklist_remediation_minutes) || +r.blocklist_remediation_minutes < 1)) {
    errs.push(`${label} : "blocklist_remediation_minutes" doit etre un entier >= 1 (ou absent pour ne pas fixer de duree propre)`);
  }
  if (r.blocklist_remediation_type != null && !REMEDIATION_TYPES.has(String(r.blocklist_remediation_type))) {
    errs.push(`${label} : "blocklist_remediation_type" doit valoir block ou challenge`);
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
      scope: r.scope === 'global' ? 'global' : 'ip',
      minIps: r.scope === 'global' ? (r.min_ips || 5) : null,
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
      // Blocklist "a la CrowdSec" (v12.50.0), par regle — voir le commentaire
      // au-dessus de validateRule(). blocklistThreshold null = cette regle ne
      // participe jamais a la blocklist, quel que soit son nombre de
      // declenchements (defaut sur : desactive).
      blocklistThreshold: (r.blocklist_threshold != null && +r.blocklist_threshold >= 1)
        ? Math.round(+r.blocklist_threshold) : null,
      blocklistWindowMinutes: Math.min(
        MAX_BLOCKLIST_WINDOW_MINUTES,
        (r.blocklist_window_minutes != null && +r.blocklist_window_minutes >= 1)
          ? Math.round(+r.blocklist_window_minutes) : 1440
      ),
      blocklistRemediation: r.blocklist_remediation === true,
      blocklistRemediationType: r.blocklist_remediation_type === 'challenge' ? 'challenge' : 'block',
      blocklistRemediationMinutes: (r.blocklist_remediation_minutes != null && +r.blocklist_remediation_minutes >= 1)
        ? Math.min(MAX_BLOCKLIST_REMEDIATION_MINUTES, Math.round(+r.blocklist_remediation_minutes)) : null,
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
    const blocklistThreshold = get('blocklist_threshold', 'blocklistThreshold');
    const blocklistWindowMinutes = get('blocklist_window_minutes', 'blocklistWindowMinutes');
    const blocklistRemediation = get('blocklist_remediation', 'blocklistRemediation');
    const blocklistRemediationMinutes = get('blocklist_remediation_minutes', 'blocklistRemediationMinutes');
    const blocklistRemediationType = get('blocklist_remediation_type', 'blocklistRemediationType');
    lines.push(`  - id: ${id}`);
    lines.push(`    name: ${name}`);
    lines.push(`    enable: ${enable !== false}`);
    lines.push(`    severity: ${severity || 'medium'}`);
    lines.push(`    description: "${String(description || '').replace(/"/g, '\\"')}"`);
    lines.push(`    window_minutes: ${windowMinutes || 5}`);
    lines.push(`    min_matches: ${minMatches}`);
    if (get('scope') === 'global') {
      lines.push('    scope: global');
      lines.push(`    min_ips: ${get('min_ips', 'minIps') || 5}`);
    }
    lines.push(`    path_hint: ${pathHint ? `"${pathHint}"` : 'null'}`);
    lines.push(`    ua_hint: ${uaHint ? `"${uaHint}"` : 'null'}`);
    lines.push(`    status_in: [${statusIn.join(', ')}]`);
    lines.push(`    method_in: [${methodIn.join(', ')}]`);
    // Blocklist "a la CrowdSec" par regle (v12.50.0) — absent/null = cette
    // regle ne contribue jamais a la blocklist automatique.
    lines.push(`    blocklist_threshold: ${blocklistThreshold != null ? blocklistThreshold : 'null'}`);
    lines.push(`    blocklist_window_minutes: ${blocklistWindowMinutes || 1440}`);
    lines.push(`    blocklist_remediation: ${blocklistRemediation === true}`);
    lines.push(`    blocklist_remediation_minutes: ${blocklistRemediationMinutes != null ? blocklistRemediationMinutes : 'null'}`);
    if (blocklistRemediationType === 'challenge') lines.push('    blocklist_remediation_type: challenge');
  }
  return lines.join('\n') + '\n';
}

module.exports = {
  parseRulesYaml, validateRule, parseAndValidate, stringifyRules,
  MAX_BLOCKLIST_WINDOW_MINUTES, MAX_BLOCKLIST_REMEDIATION_MINUTES, REMEDIATION_TYPES,
};
