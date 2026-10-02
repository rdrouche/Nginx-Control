'use strict';
/**
 * Règles d'analyse personnalisées : du formulaire vers le YAML.
 *
 * Le YAML reste LE format de stockage (base de l'analyzer, relu par les moteurs
 * Node et Go) : le formulaire de l'interface n'en est qu'une vue. Ce module
 * (1) valide/normalise ce que le formulaire envoie, (2) produit le YAML. Aucune
 * valeur n'est « corrigée » en silence ; les chaînes sont écrites entre
 * apostrophes (seule échappe : '' → une apostrophe), ce qui évite tout
 * problème avec les antislashs des expressions régulières, et un saut de ligne
 * est refusé (il pourrait injecter une clé).
 *
 * Le chargeur YAML de l'analyzer (nginx-analyzer/lib/rules-yaml.js, miroir Go)
 * revalide tout : ce module ne remplace pas cette validation, il évite que
 * l'interface produise un texte qu'elle refuserait.
 */

const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const RESERVED_NAMES = new Set(['true', 'false', 'null', '~']);
const SEVERITIES = ['low', 'medium', 'high'];
const SCOPES = ['ip', 'global'];
const REMEDIATION_TYPES = ['block', 'challenge'];
const METHOD_RE = /^[A-Z]{3,10}$/;
const MAX_RULES = 200;
const MAX_TEXT = 500;
const MAX_REGEX = 500;

const isInt = v => typeof v === 'number' && Number.isInteger(v);
const toInt = v => {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return Number(v.trim());
  return NaN;
};

function quote(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }

function cleanText(v, label, max, errs, { required = false } = {}) {
  if (v == null || v === '') {
    if (required) errs.push(`${label} : requis`);
    return '';
  }
  if (typeof v !== 'string') { errs.push(`${label} : texte attendu`); return ''; }
  if (/[\r\n]/.test(v)) { errs.push(`${label} : pas de saut de ligne`); return ''; }
  if (v.length > max) { errs.push(`${label} : ${max} caractères maximum`); return ''; }
  return v;
}

function cleanRegex(v, label, errs) {
  const s = cleanText(v, label, MAX_REGEX, errs);
  if (!s) return '';
  // Le moteur Go (RE2) n'a ni anticipation/rétrospection ni références arrière.
  if (/\(\?<?[=!]|\\[1-9]/.test(s)) { errs.push(`${label} : anticipation (?=, ?!, ?<=) et références arrière non supportées (moteur RE2)`); return ''; }
  try { new RegExp(s, 'i'); } catch (e) { errs.push(`${label} : expression régulière invalide (${e.message})`); return ''; }
  return s;
}

function optInt(v, label, min, max, errs) {
  if (v == null || v === '') return null;
  const n = toInt(v);
  if (!Number.isFinite(n) || !isInt(n) || n < min || n > max) {
    errs.push(`${label} : entier entre ${min} et ${max} attendu`);
    return null;
  }
  return n;
}

/**
 * Valide une règle du formulaire. Retourne { rule, errors }. `rule` est une
 * copie normalisée (jamais l'objet reçu), `errors` des messages lisibles.
 */
function normalizeRule(raw, idx = 0) {
  const errs = [];
  const r = raw && typeof raw === 'object' ? raw : {};
  const who = `Règle ${idx + 1}${typeof r.name === 'string' && r.name ? ` (${r.name})` : ''}`;
  const e = m => errs.push(`${who} : ${m}`);
  const sub = [];

  const id = toInt(r.id);
  if (!isInt(id) || id < 100 || id > 999999) e('id entier ≥ 100 requis (1 à 6 sont réservés aux règles intégrées)');
  const name = typeof r.name === 'string' ? r.name.trim() : '';
  if (!NAME_RE.test(name) || RESERVED_NAMES.has(name.toLowerCase()) || /^\d+(\.\d+)?$/.test(name)) {
    e('nom requis (lettres, chiffres, _ et - uniquement, 64 max, pas « true/false/null »)');
  }
  const severity = SEVERITIES.includes(r.severity) ? r.severity : (r.severity == null ? 'medium' : null);
  if (severity === null) e('gravité : low, medium ou high');
  const scope = r.scope == null || r.scope === '' ? 'ip' : r.scope;
  if (!SCOPES.includes(scope)) e('portée : ip ou global');

  const description = cleanText(r.description, 'description', MAX_TEXT, sub);
  const minMatches = toInt(r.minMatches);
  if (!isInt(minMatches) || minMatches < 1 || minMatches > 1000000) e('nombre de correspondances : entier ≥ 1');
  const windowMinutes = r.windowMinutes == null || r.windowMinutes === '' ? 5 : toInt(r.windowMinutes);
  if (!isInt(windowMinutes) || windowMinutes < 1 || windowMinutes > 1440) e('fenêtre : entier entre 1 et 1440 minutes');
  let minIps = null;
  if (scope === 'global') {
    minIps = r.minIps == null || r.minIps === '' ? 5 : toInt(r.minIps);
    if (!isInt(minIps) || minIps < 1 || minIps > 100000) e('IP distinctes minimum : entier ≥ 1');
  }

  const pathHint = cleanRegex(r.pathHint, 'motif du chemin', sub);
  const uaHint = cleanRegex(r.uaHint, 'motif du user-agent', sub);

  const statusIn = [];
  if (r.statusIn != null) {
    if (!Array.isArray(r.statusIn) || r.statusIn.length > 30) e('codes HTTP : liste attendue (30 max)');
    else for (const s of r.statusIn) {
      const n = toInt(s);
      if (!isInt(n) || n < 100 || n > 599) e(`code HTTP invalide : ${JSON.stringify(s)}`);
      else statusIn.push(n);
    }
  }
  const methodIn = [];
  if (r.methodIn != null) {
    if (!Array.isArray(r.methodIn) || r.methodIn.length > 12) e('méthodes : liste attendue (12 max)');
    else for (const m of r.methodIn) {
      const u = typeof m === 'string' ? m.trim().toUpperCase() : '';
      if (!METHOD_RE.test(u)) e(`méthode invalide : ${JSON.stringify(m)}`);
      else methodIn.push(u);
    }
  }

  if (!pathHint && !uaHint && !statusIn.length && !methodIn.length) {
    e('au moins un critère (chemin, user-agent, code HTTP ou méthode) — sans critère, la règle compterait toutes les requêtes');
  }

  const bl = r.blocklist && typeof r.blocklist === 'object' ? r.blocklist : {};
  const blThreshold = optInt(bl.threshold, 'blocklist : seuil', 1, 100000, sub);
  const blWindow = bl.windowMinutes == null || bl.windowMinutes === '' ? 1440 : optInt(bl.windowMinutes, 'blocklist : fenêtre', 1, 20160, sub);
  const blRemediation = bl.remediation === true;
  const blRemMinutes = optInt(bl.remediationMinutes, 'blocklist : durée du blocage', 1, 43200, sub);
  const blType = bl.remediationType == null || bl.remediationType === '' ? 'block' : bl.remediationType;
  if (!REMEDIATION_TYPES.includes(blType)) sub.push('blocklist : type de remédiation block ou challenge');
  for (const m of sub) errs.push(`${who} : ${m}`);

  const enable = r.enable !== false;
  return {
    rule: {
      id, name, enable, severity: severity || 'medium', description, scope, minIps,
      windowMinutes, minMatches, pathHint, uaHint, statusIn, methodIn,
      blocklist: { threshold: blThreshold, windowMinutes: blWindow || 1440, remediation: blRemediation, remediationMinutes: blRemMinutes, remediationType: REMEDIATION_TYPES.includes(blType) ? blType : 'block' },
    },
    errors: errs,
  };
}

/** Valide la liste ; ids et noms doivent être uniques. { rules, errors }. */
function normalizeRules(list) {
  if (!Array.isArray(list)) return { rules: [], errors: ['liste de règles attendue'] };
  if (list.length > MAX_RULES) return { rules: [], errors: [`${MAX_RULES} règles maximum`] };
  const errors = [];
  const rules = [];
  const ids = new Set(); const names = new Set();
  list.forEach((raw, i) => {
    const { rule, errors: es } = normalizeRule(raw, i);
    errors.push(...es);
    if (Number.isInteger(rule.id)) {
      if (ids.has(rule.id)) errors.push(`Règle ${i + 1} : id ${rule.id} déjà utilisé`);
      ids.add(rule.id);
    }
    if (rule.name) {
      if (names.has(rule.name.toLowerCase())) errors.push(`Règle ${i + 1} : nom « ${rule.name} » déjà utilisé`);
      names.add(rule.name.toLowerCase());
    }
    rules.push(rule);
  });
  return { rules, errors };
}

/** YAML canonique (règles déjà normalisées par normalizeRules). */
function rulesToYaml(rules) {
  if (!rules.length) return 'rules: []\n';
  const out = ['rules:'];
  for (const r of rules) {
    out.push(`  - id: ${r.id}`);
    out.push(`    name: ${r.name}`);
    out.push(`    enable: ${r.enable !== false}`);
    out.push(`    severity: ${r.severity}`);
    out.push(`    description: ${quote(r.description || '')}`);
    out.push(`    window_minutes: ${r.windowMinutes}`);
    out.push(`    min_matches: ${r.minMatches}`);
    if (r.scope === 'global') { out.push('    scope: global'); out.push(`    min_ips: ${r.minIps}`); }
    out.push(`    path_hint: ${r.pathHint ? quote(r.pathHint) : 'null'}`);
    out.push(`    ua_hint: ${r.uaHint ? quote(r.uaHint) : 'null'}`);
    out.push(`    status_in: [${r.statusIn.join(', ')}]`);
    out.push(`    method_in: [${r.methodIn.map(quote).join(', ')}]`);
    const b = r.blocklist || {};
    out.push(`    blocklist_threshold: ${b.threshold != null ? b.threshold : 'null'}`);
    out.push(`    blocklist_window_minutes: ${b.windowMinutes || 1440}`);
    out.push(`    blocklist_remediation: ${b.remediation === true}`);
    out.push(`    blocklist_remediation_minutes: ${b.remediationMinutes != null ? b.remediationMinutes : 'null'}`);
    if (b.remediationType === 'challenge') out.push('    blocklist_remediation_type: challenge');
  }
  return out.join('\n') + '\n';
}

module.exports = { normalizeRule, normalizeRules, rulesToYaml, quote, NAME_RE, MAX_RULES };
