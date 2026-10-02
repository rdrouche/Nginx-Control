'use strict';
/**
 * Central place for everything the "Regles" modal (dashboard) needs:
 * built-in rule enable/disable state, custom YAML rules, and the per-vhost
 * opt-out pushed from the dashboard's own vhost-file comment parsing.
 *
 * State persistence uses the same generic key/value `state` table the
 * baseline already relies on (lib/store.js getState/setState) rather than a
 * new table — this is small, infrequently-written config, not traffic data.
 * On first boot (nothing persisted yet), the env-var defaults from
 * server.js/analyzer.yml seed the initial enable flags, exactly like every
 * other threshold in this project; after that, the dashboard's live toggles
 * are the source of truth and survive a restart.
 */

const { RULE_IDS } = require('./detect');
const { parseAndValidate, stringifyRules, MAX_BLOCKLIST_WINDOW_MINUTES, MAX_BLOCKLIST_REMEDIATION_MINUTES, REMEDIATION_TYPES } = require('./rules-yaml');

const BUILTIN_KEYS = Object.keys(RULE_IDS); // ['bruteforce','scan','flood','scraping','volumetric','country_traffic']

// Defaut "eteint" pour chaque regle integree — meme convention de securite
// que le reste du mecanisme "Blocklist a la CrowdSec" (v12.49.4/v12.50.0) :
// une regle ne contribue a la blocklist automatique que si l operateur lui a
// explicitement donne un `threshold`, et ne bloque reellement (`remediation`)
// que si celui-ci vaut litteralement true.
const BLOCKLIST_DEFAULTS = Object.freeze({
  threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null, remediationType: 'block',
});

/** Validate+clamp one builtin rule's blocklist config. Returns { ok, errors, value }. */
function normalizeBlocklistConfig(input = {}) {
  const errors = [];
  let threshold = null;
  if (input.threshold != null) {
    if (!Number.isFinite(+input.threshold) || +input.threshold < 1) {
      errors.push('"threshold" doit etre un entier >= 1 (ou absent/null pour desactiver)');
    } else threshold = Math.round(+input.threshold);
  }
  let windowMinutes = BLOCKLIST_DEFAULTS.windowMinutes;
  if (input.windowMinutes != null) {
    if (!Number.isFinite(+input.windowMinutes) || +input.windowMinutes < 1) {
      errors.push('"windowMinutes" doit etre un entier >= 1');
    } else windowMinutes = Math.min(MAX_BLOCKLIST_WINDOW_MINUTES, Math.round(+input.windowMinutes));
  }
  let remediationMinutes = null;
  if (input.remediationMinutes != null) {
    if (!Number.isFinite(+input.remediationMinutes) || +input.remediationMinutes < 1) {
      errors.push('"remediationMinutes" doit etre un entier >= 1 (ou absent/null)');
    } else remediationMinutes = Math.min(MAX_BLOCKLIST_REMEDIATION_MINUTES, Math.round(+input.remediationMinutes));
  }
  const remediation = input.remediation === true;
  let remediationType = 'block';
  if (input.remediationType != null) {
    if (!REMEDIATION_TYPES.has(String(input.remediationType))) errors.push('"remediationType" doit valoir block ou challenge');
    else remediationType = String(input.remediationType);
  }
  if (errors.length) return { ok: false, errors, value: null };
  return { ok: true, errors: [], value: { threshold, windowMinutes, remediation, remediationMinutes, remediationType } };
}

// Limites defensives : la map vient du dashboard (donc de fichiers vhost edites
// a la main) ; on borne tout pour qu un fichier mal forme ne puisse pas gonfler
// la memoire ni le cout par requete de Detector.add().
const MAX_PATHS_IGNORE_PER_RULE = 50;
const MAX_PATH_IGNORE_LEN = 256;

/**
 * { "1": ["/a", "/b*"], ... } -> Map<number, string[]>. Un motif est un chemin
 * exact (sans query string) ou un prefixe termine par "*". Les motifs qui ne
 * commencent pas par "/" sont rejetes (un motif vide ou "*" masquerait tout).
 */
function sanitizePathsIgnore(raw) {
  const out = new Map();
  if (!raw || typeof raw !== 'object') return out;
  for (const [k, list] of Object.entries(raw)) {
    const id = Number(k);
    if (!Number.isInteger(id) || id < 0 || !Array.isArray(list)) continue;
    const pats = [];
    for (const v of list) {
      const pat = String(v).trim();
      if (pat.length < 1 || pat.length > MAX_PATH_IGNORE_LEN || pat[0] !== '/') continue;
      if (!pats.includes(pat)) pats.push(pat);
      if (pats.length >= MAX_PATHS_IGNORE_PER_RULE) break;
    }
    if (pats.length) out.set(id, pats);
  }
  return out;
}

class RulesManager {
  /**
   * @param {Store} store
   * @param {object} envDefaults  { [key]: boolean } — env-var-derived enable state, used only if nothing was persisted yet
   */
  constructor(store, envDefaults = {}) {
    this.store = store;
    const persisted = store.getState('rule_state') || {};
    this.state = {};
    for (const key of BUILTIN_KEYS) {
      // Fix/migration (v12.50.0): `rule_state[key]` used to be a plain
      // boolean (enable/disable only). It is now `{ enabled, blocklist }` so
      // each builtin rule can also carry its own "Blocklist a la CrowdSec"
      // threshold/remediation — see BLOCKLIST_DEFAULTS above. A
      // pre-v12.50.0 persisted value (a bare boolean, or nothing yet) is
      // transparently upgraded to the new shape on load, so an existing
      // deployment's enable/disable choices are never lost, and every rule
      // starts with blocklist disabled (threshold: null) until the operator
      // opts in.
      const p = persisted[key];
      const enabled = (typeof p === 'boolean') ? p
                     : (p && typeof p === 'object' && p.enabled !== undefined) ? !!p.enabled
                     : envDefaults[key] !== undefined ? !!envDefaults[key]
                     : true;
      const blocklistPersisted = (p && typeof p === 'object' && p.blocklist) ? p.blocklist : {};
      const { value: blocklist } = normalizeBlocklistConfig(blocklistPersisted);
      this.state[key] = { enabled, blocklist };
    }

    const customRaw = store.getState('custom_rules_yaml');
    this.customYaml = typeof customRaw === 'string' ? customRaw : '';
    const parsed = parseAndValidate(this.customYaml);
    this.customValid = parsed.valid;
    this.customErrors = parsed.errors;

    // Vhost opt-out, pushed periodically by the dashboard from vhost-file
    // comments. In-memory only: it is re-derived from the config files on
    // every push cycle, so nothing is lost by not persisting it — the
    // dashboard re-sends it within a minute of a restart either way.
    this.vhostRules = new Map();
  }

  isEnabled(key) { return this.state[key] ? this.state[key].enabled !== false : true; }

  /** Toggle one built-in rule and persist. Returns false for an unknown key. */
  toggle(key, enable) {
    if (!BUILTIN_KEYS.includes(key)) return false;
    this.state[key] = { ...this.state[key], enabled: !!enable };
    this.store.setState('rule_state', this.state);
    return true;
  }

  /** Current "Blocklist a la CrowdSec" config for one builtin rule (defaults if never configured). */
  getBlocklistConfig(key) {
    if (!BUILTIN_KEYS.includes(key)) return null;
    return { ...BLOCKLIST_DEFAULTS, ...(this.state[key] && this.state[key].blocklist) };
  }

  /**
   * Set one builtin rule's blocklist threshold/window/remediation/remediation
   * duration and persist. Returns { ok, errors, value }. Rejected wholesale on
   * validation error, same pattern as setCustomYaml() — never a partial apply.
   */
  setBlocklistConfig(key, input) {
    if (!BUILTIN_KEYS.includes(key)) return { ok: false, errors: [`Regle inconnue : ${key}`], value: null };
    const result = normalizeBlocklistConfig(input);
    if (!result.ok) return result;
    this.state[key] = { ...this.state[key], blocklist: result.value };
    this.store.setState('rule_state', this.state);
    return result;
  }

  /**
   * Unified list of every rule (builtin + custom) that opted into the
   * "Blocklist a la CrowdSec" mechanism (threshold configured) — this is all
   * the dashboard's features/blocklists.js needs to compute suspicious IPs,
   * without having to know the difference between a builtin and a custom rule.
   */
  listBlocklistRules() {
    const out = [];
    for (const key of BUILTIN_KEYS) {
      const bl = this.getBlocklistConfig(key);
      if (bl.threshold == null) continue;
      out.push({ id: RULE_IDS[key], key, name: key, custom: false, ...bl });
    }
    for (const r of this.customValid) {
      if (r.blocklistThreshold == null) continue;
      out.push({
        id: r.id, key: `custom_${r.id}`, name: r.name, custom: true,
        threshold: r.blocklistThreshold, windowMinutes: r.blocklistWindowMinutes,
        remediation: r.blocklistRemediation, remediationMinutes: r.blocklistRemediationMinutes,
        remediationType: r.blocklistRemediationType || 'block',
      });
    }
    return out;
  }

  /** Replace the custom rules from raw YAML text. Returns { ok, errors, count }. */
  setCustomYaml(text) {
    const { valid, errors } = parseAndValidate(text);
    if (errors.length) return { ok: false, errors };
    this.customYaml = text;
    this.customValid = valid;
    this.store.setState('custom_rules_yaml', text);
    return { ok: true, errors: [], count: valid.length };
  }

  /** Replace the per-vhost opt-out map. `vhosts` is { [name]: { enabled, ignore: number[] } }. */
  setVhostRules(vhosts) {
    const map = new Map();
    for (const [name, cfg] of Object.entries(vhosts || {})) {
      map.set(String(name).toLowerCase(), {
        enabled: cfg.enabled !== false,
        ignore: new Set(Array.isArray(cfg.ignore) ? cfg.ignore.map(Number) : []),
        // # nginx-control-analyze-rule-{ID}-paths-ignore: /a,/b  (v12.54.0)
        pathsIgnore: sanitizePathsIgnore(cfg.pathsIgnore),
      });
    }
    this.vhostRules = map;
    return map;
  }

  /** True when a vhost fully opted out of analysis (# nginx-control-analyze: off). */
  vhostDisabled(vhost) {
    if (!vhost) return false;
    const cfg = this.vhostRules.get(String(vhost).toLowerCase());
    return !!cfg && cfg.enabled === false;
  }

  /** True when this specific rule id is ignored for this vhost (opt-out entire vhost counts too). */
  ruleSuppressedForVhost(vhost, ruleId) {
    if (!vhost) return false;
    const cfg = this.vhostRules.get(String(vhost).toLowerCase());
    if (!cfg) return false;
    if (cfg.enabled === false) return true;
    return cfg.ignore.has(ruleId);
  }

  /**
   * Full catalog for the dashboard's "Regles" modal: built-ins + custom, each
   * with its live enabled state.
   *
   * `thresholds` (optional) carries the actual numeric configuration each
   * built-in rule runs with right now — server.js passes `detector.cfg`
   * (bruteforce/scan/flood/scraping + the shared `windowMs`) and each
   * Baseline's own `cfg` (volumetric/country_traffic) so the modal can show
   * real numbers ("600 requetes / 5 min") instead of only the static
   * what/why/legit/action text, which never changes even when an operator
   * tunes ANALYZER_* env vars. Shaped defensively (every read guarded) so a
   * caller that omits it entirely (existing tests, older callers) still gets
   * a valid catalog with `config: null` per rule rather than throwing.
   */
  catalog(explanations, thresholds = {}) {
    const windowMinutes = thresholds.windowMs ? thresholds.windowMs / 60_000 : null;
    const CONFIG_BUILDERS = {
      bruteforce: () => thresholds.bruteforce && { windowMinutes, minFailures: thresholds.bruteforce.minFailures },
      scan: () => thresholds.scan && {
        windowMinutes, minRequests: thresholds.scan.minRequests, minDistinct: thresholds.scan.minDistinct,
        minNotFoundRatioPercent: Math.round((thresholds.scan.minNotFoundRatio || 0) * 100),
      },
      flood: () => thresholds.flood && { windowMinutes, minRequests: thresholds.flood.minRequests },
      scraping: () => thresholds.scraping && {
        windowMinutes, minRequests: thresholds.scraping.minRequests, maxDistinct: thresholds.scraping.maxDistinct,
      },
      volumetric: () => thresholds.volumetric && {
        learningDays: thresholds.volumetric.learningDays, sigmaThreshold: thresholds.volumetric.sigmaThreshold,
        minAbsoluteRequests: thresholds.volumetric.minAbsoluteRequests,
      },
      country_traffic: () => thresholds.country_traffic && {
        learningDays: thresholds.country_traffic.learningDays, sigmaThreshold: thresholds.country_traffic.sigmaThreshold,
        minAbsoluteRequests: thresholds.country_traffic.minAbsoluteRequests,
      },
    };
    const builtins = BUILTIN_KEYS.map(key => ({
      key, id: RULE_IDS[key],
      enabled: this.isEnabled(key),
      custom: false,
      explanation: explanations[key],
      config: (CONFIG_BUILDERS[key] && CONFIG_BUILDERS[key]()) || null,
      // Config "Blocklist a la CrowdSec" propre a cette regle (v12.50.0) —
      // voir getBlocklistConfig()/setBlocklistConfig() ci-dessus.
      blocklist: this.getBlocklistConfig(key),
    }));
    const custom = this.customValid.map(r => ({
      key: `custom_${r.id}`, id: r.id, name: r.name,
      enabled: r.enable !== false, custom: true,
      severity: r.severity, description: r.description,
      windowMinutes: r.windowMinutes, minMatches: r.minMatches,
      scope: r.scope || 'ip', minIps: r.scope === 'global' ? r.minIps : null,
      pathHint: r.pathHintRaw, uaHint: r.uaHintRaw,
      statusIn: r.statusIn, methodIn: r.methodIn,
      blocklist: {
        threshold: r.blocklistThreshold, windowMinutes: r.blocklistWindowMinutes,
        remediation: r.blocklistRemediation, remediationMinutes: r.blocklistRemediationMinutes,
        remediationType: r.blocklistRemediationType || 'block',
      },
    }));
    return {
      builtins, custom, customYaml: this.customYaml, customErrors: this.customErrors,
      // Explication statique de la mecanique du moteur (fenetre glissante,
      // declenchement par transition, opt-out par vhost) — voir
      // buildProcessingInfo() ci-dessous. Le detail chiffre (fenetre reelle
      // en minutes) vient de `windowMinutes` ci-dessus quand disponible.
      processing: RulesManager.buildProcessingInfo(windowMinutes),
    };
  }

  /**
   * Texte explicatif (pas de configuration ici, juste de la documentation
   * vivante) sur COMMENT le moteur traite les regles — demande explicite :
   * "avoir une visu moins aveugle sur la fonction et voir comment le moteur
   * les traite". Regroupe ici plutot que dans le front pour que la fenetre
   * reelle (`windowMinutes`) et les identifiants de regle restent la seule
   * source de verite, jamais dupliques/desynchronises entre back et front.
   */
  static buildProcessingInfo(windowMinutes) {
    const w = windowMinutes || 5;
    return {
      aggregation: `Chaque regle integree (brute-force, scan, flood, aspiration) compte par adresse IP source, sur une fenetre glissante de ${w} min decoupee en petits intervalles (10 s) : seule l activite des ${w} dernieres minutes compte, jamais un cumul depuis le debut.`,
      edgeTriggered: "Une alerte se declenche au moment ou le seuil est franchi (transition), pas a chaque evaluation tant que le seuil reste depasse : un episode continu ne produit qu'une seule alerte, pas une rafale toutes les 30 s.",
      vhostOptOut: "L'opt-out par vhost (# nginx-control-analyze-ignore-rules / # nginx-control-analyze: off) s'applique par regle et par vhost. Si l'IP suspecte a touche PLUSIEURS vhosts pendant la fenetre, la regle n'est ignoree que si TOUS ces vhosts l'ont individuellement ignoree — un seul vhost qui n'a pas opte pour l'ignore-rule suffit a garder l'alerte visible, pour ne jamais masquer une attaque reelle sur ce vhost-la au pretexte qu'un autre partage la meme adresse IP.",
      customRules: "Les regles personnalisees (id >= 100) suivent exactement le meme moteur (comptage par IP, fenetre glissante propre a chaque regle, declenchement par transition, meme opt-out par vhost) — seul le critere de correspondance (chemin, agent, code HTTP, methode) et le seuil sont definis par vous.",
    };
  }

  /** Default template shown in an empty editor, so the syntax is discoverable without documentation elsewhere. */
  static template() {
    return stringifyRules([{
      id: 100, name: 'exemple_admin_probe', enable: false, severity: 'medium',
      description: 'Exemple desactive par defaut — dupliquez et adaptez.',
      window_minutes: 5, min_matches: 10,
      path_hint: '(wp-admin|phpmyadmin|\\.env)', ua_hint: null,
      status_in: [], method_in: [],
    }]);
  }
}

module.exports = { RulesManager, BUILTIN_KEYS, BLOCKLIST_DEFAULTS, sanitizePathsIgnore };
