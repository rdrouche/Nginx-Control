'use strict';
/**
 * Signature-based detection over a true sliding window.
 *
 * Two design mistakes in the first version caused the same complaint twice:
 * "everything eventually becomes a flood".
 *
 * The first version kept a single lifetime counter per address, reset only
 * when the address went fully silent for a whole window. A monitoring probe
 * or an indexing bot that never pauses that long never gets reset — its
 * counter climbs forever and eventually crosses any cumulative threshold,
 * regardless of how low its actual rate is. This is fixed here with real
 * time buckets: activity is tracked per short bucket (10 s by default), and
 * evaluating an address only sums the buckets that fall inside the last
 * `windowMs`. Old buckets are dropped, not carried forward.
 *
 * The second mistake was re-alerting on a timer: once fired, the same
 * (type, address, vhost) could fire again every `windowMs` for as long as the
 * condition stayed true, producing dozens of alerts for one continuous
 * episode. Detection is now edge-triggered: an alert fires on the transition
 * from "below threshold" to "above threshold", and the next one for the same
 * key only fires after the metric has genuinely dropped back below threshold
 * and crossed it again — a new episode, not a repeat of the same one.
 *
 * Everything else — the four detector types, the conservative defaults, the
 * evidence attached to each alert, the per-vhost exceptions — is unchanged.
 */

const cidr = require('./cidr');

// Fix (audit finding ANA-05): upper bound on a custom rule's window_minutes,
// so a bad or malicious rule config cannot blow up per-IP bucket retention
// (and with it, memory — bucket count scales with the window) arbitrarily.
// 24h is already generous for a per-IP sliding-window rule.
const MAX_CUSTOM_WINDOW_MINUTES = 24 * 60;
/** Clamp a custom rule's configured window to a sane, bounded range. */
// Tri deterministe (compte decroissant, puis cle croissante) : memes resultats que le moteur Go.
const cmpCount = (a, b) => b[1] - a[1] || (String(a[0]) < String(b[0]) ? -1 : String(a[0]) > String(b[0]) ? 1 : 0);
const bestKey = m => { const e = [...m.entries()].sort(cmpCount)[0]; return e ? e[0] : null; };

// Plafond d adresses listees dans une alerte de campagne (evidence.ips) : le blocage les lit.
const MAX_CAMPAIGN_IPS = 3000;

function clampCustomWindowMinutes(r) {
  return Math.max(1, Math.min(r.windowMinutes || 5, MAX_CUSTOM_WINDOW_MINUTES));
}

const DEFAULTS = {
  windowMs:            5 * 60_000,   // sliding window for all detectors
  bucketMs:            10_000,       // resolution of that window
  pruneEveryMs:        60_000,
  maxTrackedIps:       50_000,       // hard cap on memory

  bruteforce: {
    enable:      true,
    minFailures: 15,
    statuses:    [401, 403],
    pathHint:    /(login|signin|auth|admin|wp-login|session|token|oauth)/i,
  },

  scan: {
    enable:        true,
    minRequests:   40,
    minDistinct:   25,
    minNotFoundRatio: 0.5,
  },

  flood: {
    enable:      true,
    minRequests: 600,          // over the window, ~2/s sustained
  },

  scraping: {
    enable:        true,
    minRequests:   300,
    maxDistinct:   5,
    uaHint:        /(bot|crawler|spider|scrapy|python-requests|curl|wget|go-http|java|libwww)/i,
  },
};

function withDefaults(cfg = {}) {
  const out = { ...DEFAULTS, ...cfg };
  for (const k of ['bruteforce', 'scan', 'flood', 'scraping']) {
    out[k] = { ...DEFAULTS[k], ...(cfg[k] || {}) };
  }
  return out;
}

// Identifiants numeriques stables des regles integrees, utilises par la modale
// "Regles" du dashboard et par l opt-out par vhost
// (# nginx-control-analyze-ignore-rules: 1, 2, 4 dans un bloc server{}).
// 0-99 leur sont reserves ; une regle personnalisee (lib/rules-yaml.js) doit
// utiliser un id >= 100 pour ne jamais entrer en collision avec ceux-ci, y
// compris si de nouvelles regles integrees sont ajoutees plus tard.
const RULE_IDS = {
  bruteforce: 1,
  scan: 2,
  flood: 3,
  scraping: 4,
  volumetric: 5,
  country_traffic: 6,
};

const EXPLANATIONS = {
  bruteforce: {
    id: RULE_IDS.bruteforce,
    what: "Une meme adresse a enchaine les echecs d authentification sur une page de connexion.",
    why:  "C est le motif d une tentative de decouverte de mot de passe : un attaquant essaie des identifiants en serie.",
    legit: "Un utilisateur qui a oublie son mot de passe, ou un client automatise dont les identifiants ont expire, produisent le meme motif a plus petite echelle.",
    action: "Verifier si le compte vise existe. Si les tentatives continuent, bloquer l adresse ou renforcer l authentification.",
  },
  scan: {
    id: RULE_IDS.scan,
    what: "Une adresse a demande de nombreux chemins differents, dont la plupart n existent pas.",
    why:  "C est une reconnaissance : on cherche un fichier de configuration oublie, une interface d administration, une faille connue.",
    legit: "Un moteur d indexation mal configure, ou un lien casse massivement partage, peuvent generer beaucoup de 404 — mais rarement sur des chemins aussi varies.",
    action: "Regarder les chemins demandes. S ils visent des fichiers sensibles, l intention est claire.",
  },
  flood: {
    id: RULE_IDS.flood,
    what: "Une seule adresse a envoye un volume de requetes tres au-dessus de la normale, sur les dernieres minutes.",
    why:  "Saturation volontaire, ou client defectueux qui reessaie en boucle sans attendre.",
    legit: "Un script interne mal ecrit, une sonde de supervision trop frequente, un proxy qui regroupe le trafic de nombreux utilisateurs derriere une seule adresse.",
    action: "Verifier si l adresse vous appartient avant de bloquer : un proxy d entreprise concentre parfois des centaines d utilisateurs legitimes. Si c est le cas, ajoutez une exception pour ce vhost.",
  },
  scraping: {
    id: RULE_IDS.scraping,
    what: "Un volume important sur tres peu de chemins, depuis un agent automatise.",
    why:  "Recuperation systematique de contenu : catalogue, annuaire, donnees tarifaires.",
    legit: "Vos propres taches de sauvegarde, un agregateur autorise, ou un moteur de recherche partenaire.",
    action: "Si l agent vous appartient, ajoutez une exception pour ce vhost plutot que de baisser les seuils.",
  },
  volumetric: {
    id: RULE_IDS.volumetric,
    what: "Le trafic de ce creneau horaire s ecarte nettement de ce qui est habituel pour ce meme creneau.",
    why:  "Un ecart franc signale soit une attaque, soit un evenement reel — les deux produisent un pic.",
    legit: "Un article qui fonctionne, une campagne, une mise en avant. La structure du trafic les distingue : une audience reelle apporte beaucoup d adresses differentes, des chemins varies et peu d erreurs.",
    action: "Regarder le champ « structure » de l alerte. Si le trafic semble organique, marquez ce creneau comme normal pour qu il n influence pas la reference.",
  },
  country_traffic: {
    id: RULE_IDS.country_traffic,
    what: "Le volume de requetes en provenance d un pays s ecarte nettement de ce qui est habituel pour ce meme creneau horaire, tous vhosts confondus.",
    why:  "Un pays qui envoie brutalement beaucoup plus de trafic qu a l accoutumee est le motif d une attaque distribuee (credential stuffing, DDoS applicatif) menee depuis une plage d adresses concentree geographiquement, ou d un scan de masse.",
    legit: "Une actualite qui touche particulierement ce pays, une campagne marketing ciblee, ou un evenement (sportif, commercial) genèrent le meme pic sans etre malveillants — la encore, la structure (nombre d adresses distinctes, variete des chemins, taux d erreur) les distingue d un flood.",
    action: "Regarder le champ « structure » de l alerte et, si besoin, le detail par vhost sur la carte en direct filtree par ce pays. Si le trafic est legitime, marquez ce creneau comme normal.",
  },
};

/** Vrai si `path` correspond a l un des motifs (exact, ou prefixe si le motif finit par "*"). */
function pathIgnored(patterns, path) {
  if (!patterns || path == null) return false;
  // Les chemins du detecteur gardent leur query string ; le motif vise la partie stable.
  const q = path.indexOf('?');
  if (q !== -1) path = path.slice(0, q);
  for (const pat of patterns) {
    if (pat.endsWith('*') ? path.startsWith(pat.slice(0, -1)) : path === pat) return true;
  }
  return false;
}

class Detector {
  constructor(cfg = {}) {
    this.cfg = withDefaults(cfg);
    // The bucket must be no coarser than the window itself, or a window
    // smaller than one bucket can never actually slide: everything falls in
    // the same bucket and nothing ever ages out.
    this.cfg.bucketMs = Math.max(1, Math.min(this.cfg.bucketMs, this.cfg.windowMs));
    this.ips = new Map();          // ip → { buckets: Map<bucketIdx, Bucket>, last, samples }
    this.lastPrune = 0;
    // Bucket retention (what prune() keeps around) vs. the built-in rules'
    // own aggregation window (this.cfg.windowMs, used by _aggregate()) are
    // kept separate — see setCustomRules() below for why.
    this.retentionMs = this.cfg.windowMs;
    // Edge-triggered state lives on each IP's own record (s.active), not in a
    // separate global map. That matters when an address goes fully idle: its
    // record is dropped by prune(), and its active markers disappear with it.
    // A global map keyed by ip would keep a stale lock forever once the ip is
    // no longer iterated, and the same address would never alert again after
    // a genuine lull and a real second attack.
    // Addresses exempt from detection, scoped per vhost: expected on one site
    // is not automatically expected on the others. Each entry is
    // { vhost, ip } where `ip` may be a single address or a CIDR block
    // ("203.0.113.0/24") — a corporate proxy or a monitoring range does not
    // have to be excluded one address at a time.
    this.exceptions = [];
    // User-authored rules (lib/rules-yaml.js `valid` output), ids >= 100.
    // Kept separate from the four built-ins above: each one gets its own
    // per-bucket match counter (see add()) so several custom rules can watch
    // different traffic shapes on the same window without interfering.
    this.customRules = [];
    // Campagnes (regles scope: global) en cours : ruleId -> { emittedAt, ips }.
    this.campaigns = new Map();
    // Per-vhost opt-out, computed by the dashboard from the vhost files'
    // own comments (# nginx-control-analyze: off /
    // # nginx-control-analyze-ignore-rules: 1, 2, 4) and pushed here — see
    // setVhostRules(). Keyed by lowercased vhost name.
    //   Map<string, { enabled: boolean, ignore: Set<number> }>
    this.vhostRules = new Map();
    this.hasPathsIgnore = false;
  }

  setExceptions(list) { this.exceptions = Array.isArray(list) ? list : []; }
  isExcluded(ip, vhost) {
    return this.exceptions.some(e => e.vhost === vhost && cidr.ipInCidr(ip, e.ip));
  }

  /**
   * Same "every touched vhost must individually agree" requirement as
   * _ruleSuppressedForVhosts() below, applied to exceptions instead of
   * custom-rule opt-outs.
   *
   * Fix (audit finding ANA-06): evaluate() resolves `vhost` to a single name
   * only when agg.vhosts.size === 1, and to `null` the instant an address
   * touches a second vhost in the window. isExcluded(ip, null) can never
   * match a real exception, because every exception is recorded against a
   * named vhost — so a legitimately excepted address (a shared health-check
   * or CDN egress IP, say, excepted individually on each vhost it reaches)
   * stopped being recognized as excepted forever, the moment it touched a
   * second vhost, and started alerting despite the operator's exception
   * still being configured. Requiring every touched vhost to except the
   * address (rather than any one of them) keeps the same safety guarantee
   * as the rule-suppression case: a vhost that did NOT except this address
   * can still never have it silenced on its behalf.
   */
  isExcludedForVhosts(ip, vhosts) {
    if (!vhosts || vhosts.size === 0) return this.isExcluded(ip, null);
    for (const v of vhosts) {
      if (!this.isExcluded(ip, v)) return false;
    }
    return true;
  }

  /**
   * prune() drops buckets older than `this.retentionMs` for every tracked
   * address, regardless of which rule looks at them. A custom rule whose own
   * `windowMinutes` is longer than the built-ins' shared window would
   * silently never accumulate enough history — its buckets would already be
   * gone by the time _customCount() looks for them. Widening retention here
   * keeps that history available automatically instead of requiring the
   * operator to separately tune WINDOW_MS to match their longest custom rule.
   *
   * Fix (audit finding ANA-05), two bugs in the original version:
   *
   * 1. It widened `this.cfg.windowMs` itself — the SAME value _aggregate()
   *    uses for the built-in rules (brute force, flood, scraping...). A long
   *    custom rule window silently stretched every built-in rule's
   *    aggregation window too, changing their alerting semantics as a side
   *    effect, and — because it only ever grew, never shrank — the change
   *    was permanent: removing the custom rule (or shortening its window)
   *    afterwards never gave the built-ins their original window back for
   *    the life of the process. Retention now lives in its own
   *    `this.retentionMs`, recomputed from scratch on every call (so it can
   *    shrink again), and `this.cfg.windowMs` is never touched here — the
   *    built-ins keep the window the operator actually configured for them.
   * 2. `windowMinutes` was trusted as-is, with no upper bound: a bad or
   *    malicious rule config (`window_minutes: 100000`) would blow up
   *    retention — and with it, per-IP memory (bucket count scales with the
   *    window) — arbitrarily. Clamped to MAX_CUSTOM_WINDOW_MINUTES.
   */
  setCustomRules(list) {
    this.customRules = Array.isArray(list) ? list : [];
    const widestMs = this.customRules.reduce((max, r) => Math.max(max, clampCustomWindowMinutes(r) * 60_000), 0);
    this.retentionMs = Math.max(this.cfg.windowMs, widestMs);
  }

  setVhostRules(map) {
    this.vhostRules = map instanceof Map ? map : new Map(Object.entries(map || {}));
    // Evite un toLowerCase()+lookup par requete tant qu aucun vhost n a de motif.
    this.hasPathsIgnore = false;
    for (const cfg of this.vhostRules.values()) {
      if (cfg && cfg.pathsIgnore && cfg.pathsIgnore.size) { this.hasPathsIgnore = true; break; }
    }
  }

  /** { enabled, ignore } for a vhost, or null when nothing was configured for it (default: fully active). */
  _vhostCfg(vhost) {
    if (!vhost) return null;
    return this.vhostRules.get(vhost.toLowerCase()) || null;
  }

  /** True when this rule id must not fire for this vhost (opt-out entirely, or this rule specifically ignored). */
  _ruleSuppressed(vhostCfg, ruleId) {
    if (!vhostCfg) return false;
    if (vhostCfg.enabled === false) return true;
    return vhostCfg.ignore instanceof Set ? vhostCfg.ignore.has(ruleId) : false;
  }

  /**
   * Whether ruleId must be suppressed across the WHOLE set of vhosts this
   * IP's traffic touched in the window — not only in the single-vhost case.
   *
   * Real bug found in the wild: an IP legitimately hitting two vhosts that
   * BOTH carry the same `# nginx-control-analyze-ignore-rules` opt-out (a
   * single client, e.g. two ArcGIS front-ends behind the same reverse
   * proxy, both exempted from the same rule by an operator) never got
   * suppressed. `evaluate()` only ever resolved `vhost` to a name when
   * `agg.vhosts.size === 1` — the instant traffic touched a second vhost in
   * the same window, `vhost` became `null` and `_ruleSuppressed(null, ...)`
   * always answers `false`, so the opt-out silently stopped applying no
   * matter how it was configured.
   *
   * Requiring EVERY touched vhost to opt out (rather than "exactly one
   * vhost, which happens to") keeps the original safety guarantee intact —
   * a vhost that did NOT opt out can still never have this rule silenced on
   * its behalf, because a single non-opted-out vhost in the set fails this
   * check — while actually honouring the opt-out once the whole set agrees.
   */
  _ruleSuppressedForVhosts(vhosts, ruleId) {
    if (!vhosts || vhosts.size === 0) return false;
    for (const v of vhosts) {
      if (!this._ruleSuppressed(this._vhostCfg(v), ruleId)) return false;
    }
    return true;
  }

  _bucketIdx(ts) { return Math.floor(ts / this.cfg.bucketMs); }

  /** Per-IP state, created on demand. */
  _state(ip) {
    let s = this.ips.get(ip);
    if (!s) {
      if (this.ips.size >= this.cfg.maxTrackedIps) return null;
      s = { buckets: new Map(), last: 0, samples: [], active: new Set() };
      this.ips.set(ip, s);
    }
    return s;
  }

  _bucket(s, idx) {
    let b = s.buckets.get(idx);
    if (!b) {
      b = { requests: 0, authFail: 0, notFound: 0, paths: new Set(), uas: new Set(),
            vhosts: new Set(), statuses: new Map(), custom: new Map() };
      s.buckets.set(idx, b);
    }
    return b;
  }

  /**
   * Details kept ONLY for « scope: global » rules (v12.62.0): what the operator
   * needs to judge a distributed campaign (which paths, which user agents,
   * which status codes, from which addresses). Bounded per bucket and per rule
   * (a handful of distinct values), so one request per address costs almost
   * nothing and a flood cannot grow it.
   */
  _recordCampaignDetail(b, ruleId, entry, now) {
    if (!b.gm) b.gm = new Map();
    let d = b.gm.get(ruleId);
    if (!d) { d = { paths: new Map(), uas: new Map(), statuses: new Map(), vhosts: new Set(), last: 0 }; b.gm.set(ruleId, d); }
    d.last = Math.max(d.last, now);
    const bump = (m, k, cap) => { if (k == null || k === '') return; if (m.has(k) || m.size < cap) m.set(k, (m.get(k) || 0) + 1); };
    bump(d.paths, entry.path, 5);
    bump(d.uas, entry.ua, 3);
    d.statuses.set(entry.status, (d.statuses.get(entry.status) || 0) + 1);
    if (entry.vhost) d.vhosts.add(entry.vhost);
  }

  /**
   * Aggregates a global rule over the window: every eligible address (exceptions
   * and per-vhost opt-outs applied) with its own count, plus the campaign-level
   * tables. Returns null when nothing matched.
   */
  _campaignScan(rule, now) {
    const windowMs = clampCustomWindowMinutes(rule) * 60_000;
    const cutoffIdx = this._bucketIdx(now - windowMs);
    const ips = [];
    const paths = new Map(); const uas = new Map(); const statuses = new Map(); const vhosts = new Set();
    let total = 0; let first = Infinity; let last = 0;
    const add = (m, k, n) => m.set(k, (m.get(k) || 0) + n);
    for (const [ip, st] of this.ips) {
      let count = 0; let ipLast = 0; let sample = null;
      const ipVhosts = new Set();
      const ipPaths = new Map(); const ipUas = new Map(); const ipStatuses = new Map();
      for (const [idx, b] of st.buckets) {
        if (idx < cutoffIdx) continue;
        const n = b.custom.get(rule.id) || 0;
        if (!n) continue;
        count += n;
        const d = b.gm && b.gm.get(rule.id);
        if (!d) continue;
        ipLast = Math.max(ipLast, d.last);
        if (d.last && d.last < first) first = d.last;
        for (const v of d.vhosts) ipVhosts.add(v);
        for (const [k, c] of d.paths) add(ipPaths, k, c);
        for (const [k, c] of d.uas) add(ipUas, k, c);
        for (const [k, c] of d.statuses) add(ipStatuses, k, c);
      }
      if (!count) continue;
      if (this.isExcludedForVhosts(ip, ipVhosts) || this._ruleSuppressedForVhosts(ipVhosts, rule.id)) continue;
      total += count;
      if (ipLast > last) last = ipLast;
      for (const v of ipVhosts) vhosts.add(v);
      for (const [k, c] of ipPaths) add(paths, k, c);
      for (const [k, c] of ipUas) add(uas, k, c);
      for (const [k, c] of ipStatuses) add(statuses, k, c);
      sample = { ip, path: bestKey(ipPaths), ua: bestKey(ipUas), status: bestKey(ipStatuses), ts: ipLast };
      ips.push({ ip, count, last: ipLast, sample });
    }
    if (!ips.length) return null;
    ips.sort((a, b) => b.count - a.count || b.last - a.last || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
    return { windowMs, ips, total, paths, uas, statuses, vhosts, first: Number.isFinite(first) ? first : last, last };
  }

  /** Builds the single campaign alert for a global rule (evidence an operator can decide on). */
  _campaignAlert(rule, scan, windowMinutes, renewal) {
    const top = (m, n, key) => [...m.entries()].sort(cmpCount).slice(0, n).map(([k, c]) => ({ [key]: String(k).slice(0, 300), count: c }));
    const ipsOut = scan.ips.slice(0, MAX_CAMPAIGN_IPS).map(x => [x.ip, x.count]);
    const spanMin = Math.max(1, (scan.last - scan.first) / 60_000);
    const vhosts = [...scan.vhosts].sort();
    const vhost = vhosts.length === 1 ? vhosts[0] : null;
    const topPath = top(scan.paths, 1, 'path')[0];
    return {
      type: `custom_${rule.id}`, severity: rule.severity || 'medium', vhost,
      explanation: {
        what: rule.description || `Regle personnalisee "${rule.name}"`,
        why: 'Campagne repartie sur de nombreuses adresses : chacune reste sous les seuils par IP, c est leur total qui est anormal.',
        legit: 'Un pic de trafic reel (lien partage, evenement) peut produire un motif proche : verifiez les chemins, les user-agents et la repartition des IP ci-dessous.',
        action: 'Controler les preuves (chemins, user-agents, codes) ; si la campagne est confirmee, activer le blocage de la regle (blocklist) ou proteger la ressource (authentification, limite de debit).',
        id: rule.id,
      },
      summary: `Regle "${rule.name}" (campagne distribuee) : ${scan.total} correspondance(s) depuis ${scan.ips.length} IP sur les dernieres ${windowMinutes} min${vhost ? ' sur ' + vhost : ''}${topPath ? ' — ex. ' + topPath.path.slice(0, 120) : ''}${renewal ? ' (mise a jour)' : ''}`,
      evidence: {
        campaign: true, ip: null, vhost, vhosts, ruleId: rule.id, ruleName: rule.name,
        matches: scan.total, globalMatches: scan.total, globalIps: scan.ips.length,
        windowMinutes, firstSeen: scan.first, lastSeen: scan.last,
        requestsPerMinute: Math.round((scan.total / spanMin) * 10) / 10,
        topPaths: top(scan.paths, 10, 'path'), topUserAgents: top(scan.uas, 5, 'ua'),
        statuses: Object.fromEntries([...scan.statuses.entries()].sort(cmpCount)),
        samples: scan.ips.slice(0, 10).map(x => ({ ip: x.ip, path: x.sample.path, status: x.sample.status, ua: x.sample.ua, ts: x.sample.ts })),
        ips: ipsOut, ipsTruncated: scan.ips.length > ipsOut.length, renewal: !!renewal,
      },
    };
  }

  /** Record one parsed request. */
  add(entry) {
    const now = entry.ts || Date.now();
    const s = this._state(entry.ip);
    if (!s) return;
    s.last = now;

    const b = this._bucket(s, this._bucketIdx(now));
    b.requests++;
    // Fix (audit report, Basse/Analyzer, "parse.js:19, 22"): entry.path/
    // entry.method are now genuinely null for a bare "-" request (a
    // TLS/binary probe that never sent a parseable request line — see
    // parse.js) instead of that traffic being dropped before it got here.
    // A regex .test(null) would coerce to the string "null" and could
    // accidentally match a path-hint rule never meant to see it, so every
    // path-based check below is skipped (not silently "matched") for this
    // traffic; it is still counted in b.requests/b.statuses/b.vhosts like
    // any other request, and still visible to method_in/status_in rules
    // that do not care about a path.
    if (entry.path != null && b.paths.size < 500) b.paths.add(entry.path);
    if (entry.ua && b.uas.size < 50) b.uas.add(entry.ua);
    if (entry.vhost) b.vhosts.add(entry.vhost);
    b.statuses.set(entry.status, (b.statuses.get(entry.status) || 0) + 1);
    if (entry.status === 404) b.notFound++;
    const bf = this.cfg.bruteforce;
    if (entry.path != null && bf.statuses.includes(entry.status) && bf.pathHint.test(entry.path)) b.authFail++;

    // # nginx-control-analyze-rule-{ID}-paths-ignore (v12.54.0) : requetes de
    // ce vhost+chemin a ne pas compter pour la regle {ID}. Les compteurs
    // partages ci-dessus restent intacts (les AUTRES regles continuent de voir
    // la requete) ; on memorise a part ce qu il faudra retrancher pour la regle
    // concernee, voir _effective(). `ignored` ne sert que pour les regles
    // personnalisees, ou le filtrage se fait directement a l ecriture.
    let ignored = null;
    if (this.hasPathsIgnore && entry.vhost && entry.path != null) {
      const vcfg = this.vhostRules.get(entry.vhost.toLowerCase());
      if (vcfg && vcfg.pathsIgnore && vcfg.pathsIgnore.size) {
        for (const [ruleId, pats] of vcfg.pathsIgnore) {
          if (!pathIgnored(pats, entry.path)) continue;
          (ignored || (ignored = new Set())).add(ruleId);
          if (!b.ign) b.ign = new Map();
          let g = b.ign.get(ruleId);
          if (!g) { g = { requests: 0, authFail: 0, notFound: 0, paths: new Set() }; b.ign.set(ruleId, g); }
          g.requests++;
          if (entry.status === 404) g.notFound++;
          if (bf.statuses.includes(entry.status) && bf.pathHint.test(entry.path)) g.authFail++;
          if (g.paths.size < 500) g.paths.add(entry.path);
        }
      }
    }

    // Custom rules: a small, per-request check against each enabled rule's
    // filters. The list is short (hand-authored, not machine-generated), so
    // a linear scan per request is negligible next to log parsing itself.
    for (const rule of this.customRules) {
      if (rule.enable === false) continue;
      if (ignored && ignored.has(rule.id)) continue;
      if (rule.pathHint && (entry.path == null || !rule.pathHint.test(entry.path))) continue;
      if (rule.uaHint && !(entry.ua && rule.uaHint.test(entry.ua))) continue;
      if (rule.statusIn.length && !rule.statusIn.includes(entry.status)) continue;
      if (rule.methodIn.length && !rule.methodIn.includes(entry.method)) continue;
      b.custom.set(rule.id, (b.custom.get(rule.id) || 0) + 1);
      if (rule.scope === 'global') this._recordCampaignDetail(b, rule.id, entry, now);
    }

    // Evidence samples: kept separately from the counters, bounded in size
    // rather than by time — they only need to show a handful of examples,
    // not to track every request during a real flood.
    s.samples.push({ ts: now, method: entry.method, path: entry.path, status: entry.status });
    if (s.samples.length > 20) s.samples.shift();

    if (now - this.lastPrune > this.cfg.pruneEveryMs) this.prune(now);
  }

  /** Drop buckets and addresses that fell out of the window. */
  prune(now = Date.now()) {
    this.lastPrune = now;
    const cutoffIdx = this._bucketIdx(now - this.retentionMs);
    for (const [ip, s] of this.ips) {
      for (const idx of s.buckets.keys()) if (idx < cutoffIdx) s.buckets.delete(idx);
      if (s.buckets.size === 0) this.ips.delete(ip);
    }
  }

  /**
   * Same idea as _aggregate(), but scoped to one custom rule's own
   * `windowMinutes` rather than the detector's shared `windowMs`. A custom
   * rule commonly wants a tighter or looser window than the built-ins (a
   * short burst check vs. a slow-drip one), and reusing the shared window's
   * already-summed agg.custom would silently ignore that setting whenever it
   * differs — this recomputes from the raw per-bucket counters instead.
   */
  _customCount(s, now, ruleId, windowMs) {
    const cutoffIdx = this._bucketIdx(now - windowMs);
    let count = 0;
    for (const [idx, b] of s.buckets) {
      if (idx < cutoffIdx) continue;
      count += b.custom.get(ruleId) || 0;
    }
    return count;
  }

  /**
   * Sum every bucket still inside the window into one view. This is the
   * actual sliding window: an address active for hours at a trickle only
   * ever contributes the last few minutes to this total, never its whole
   * history.
   */
  _aggregate(s, now) {
    const cutoffIdx = this._bucketIdx(now - this.cfg.windowMs);
    let requests = 0, authFail = 0, notFound = 0;
    const paths = new Set(), uas = new Set(), vhosts = new Set(), statuses = new Map();
    const custom = new Map();
    let ign = null; // Map<ruleId, {requests, authFail, notFound, paths}> — voir _effective()
    let first = now;
    for (const [idx, b] of s.buckets) {
      if (idx < cutoffIdx) continue;
      first = Math.min(first, idx * this.cfg.bucketMs);
      requests += b.requests;
      authFail += b.authFail;
      notFound += b.notFound;
      for (const p of b.paths) if (paths.size < 2000) paths.add(p);
      for (const u of b.uas)   if (uas.size   < 100)  uas.add(u);
      for (const v of b.vhosts) vhosts.add(v);
      for (const [code, n] of b.statuses) statuses.set(code, (statuses.get(code) || 0) + n);
      for (const [id, n] of b.custom) custom.set(id, (custom.get(id) || 0) + n);
      if (b.ign) {
        if (!ign) ign = new Map();
        for (const [id, g] of b.ign) {
          let t = ign.get(id);
          if (!t) { t = { requests: 0, authFail: 0, notFound: 0, paths: new Set() }; ign.set(id, t); }
          t.requests += g.requests; t.authFail += g.authFail; t.notFound += g.notFound;
          for (const p of g.paths) t.paths.add(p);
        }
      }
    }
    const samples = s.samples.filter(x => x.ts >= now - this.cfg.windowMs).slice(-5);
    return { requests, authFail, notFound, paths, uas, vhosts, statuses, custom, ign, samples, first, last: s.last };
  }

  /**
   * Metriques de la fenetre pour UNE regle, une fois retranchees les requetes
   * que `# nginx-control-analyze-rule-{ID}-paths-ignore` exclut pour elle.
   * Sans motif applicable (cas courant) c est l agregat tel quel, sans copie.
   * Un chemin n est retire de l ensemble des chemins distincts que s il a ete
   * ignore ; limite assumee : si la meme URL est aussi demandee sur un vhost
   * qui ne l ignore pas, elle est retiree du decompte (ecart d au plus 1).
   */
  _effective(agg, ruleId) {
    const g = agg.ign && agg.ign.get(ruleId);
    if (!g) return agg;
    let pathCount = 0;
    for (const p of agg.paths) if (!g.paths.has(p)) pathCount++;
    return {
      requests: Math.max(0, agg.requests - g.requests),
      authFail: Math.max(0, agg.authFail - g.authFail),
      notFound: Math.max(0, agg.notFound - g.notFound),
      paths: { size: pathCount },
      uas: agg.uas,
    };
  }

  /**
   * True the first time this type crosses into the active state for this
   * address. False while it stays active — the caller must not re-fire —
   * and it becomes eligible again only once `_clear()` has been called, or
   * once the address has gone fully idle and its record was dropped.
   */
  _enter(s, type) {
    if (s.active.has(type)) return false;
    s.active.add(type);
    return true;
  }

  _clear(s, type) {
    s.active.delete(type);
  }

  /**
   * Evaluate every tracked address against the current window. Returns the
   * alerts newly entering an abnormal state on this pass — a sustained
   * episode produces exactly one, and a new one only after the metric has
   * genuinely gone back to normal in between.
   */
  evaluate(now = Date.now()) {
    this.prune(now);
    const alerts = [];
    const c = this.cfg;

    // Regles personnalisees « scope: global » : UNE alerte de campagne par regle
    // (pas une par IP), avec les preuves agregees et la liste des adresses ; le
    // blocage (dashboard, features/blocklists.js) lit evidence.ips. Declenchee a
    // l entree ; remise a jour quand le nombre d IP grandit de 50 % ou apres une
    // fenetre complete tant que la campagne dure.
    const liveCampaigns = new Set();
    for (const rule of this.customRules) {
      if (rule.scope !== 'global' || rule.enable === false) continue;
      const scan = this._campaignScan(rule, now);
      const met = scan && scan.total >= rule.minMatches && scan.ips.length >= (rule.minIps || 5);
      if (!met) continue;
      liveCampaigns.add(rule.id);
      const st = this.campaigns.get(rule.id);
      const grown = st && scan.ips.length >= st.ips * 1.5;
      const stale = st && now - st.emittedAt >= scan.windowMs;
      if (st && !grown && !stale) continue;
      this.campaigns.set(rule.id, { emittedAt: now, ips: scan.ips.length });
      alerts.push(this._campaignAlert(rule, scan, clampCustomWindowMinutes(rule), !!st));
    }
    for (const id of [...this.campaigns.keys()]) if (!liveCampaigns.has(id)) this.campaigns.delete(id);

    for (const [ip, s] of this.ips) {
      const agg = this._aggregate(s, now);
      const vhost = agg.vhosts.size === 1 ? [...agg.vhosts][0] : null;
      if (this.isExcludedForVhosts(ip, agg.vhosts)) continue;
      // Per-vhost opt-out from vhost-file comments (dashboard-pushed, see
      // setVhostRules above). Evaluated against EVERY vhost this IP's
      // traffic touched in the window (agg.vhosts), not just the single
      // resolved `vhost` above — see _ruleSuppressedForVhosts(): a shared-IP
      // situation (proxy, CDN) touching several vhosts only gets the rule
      // suppressed when ALL of those vhosts individually opt out, so a
      // vhost that did NOT opt out can never have the rule silenced on its
      // behalf.

      // `e` : metriques propres a une regle (voir _effective()) — par defaut
      // l agregat complet.
      const base = (e = agg) => ({
        ip, vhost,
        firstSeen: agg.first, lastSeen: agg.last,
        requests: e.requests,
        distinctPaths: e.paths.size,
        userAgents: [...agg.uas].slice(0, 3),
        statuses: Object.fromEntries(agg.statuses),
        samples: agg.samples,
      });

      // Brute force
      const bfE = this._effective(agg, RULE_IDS.bruteforce);
      const bfMet = c.bruteforce.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.bruteforce)
        && bfE.authFail >= c.bruteforce.minFailures;
      if (bfMet && this._enter(s, 'bruteforce')) {
        alerts.push({
          type: 'bruteforce', explanation: EXPLANATIONS.bruteforce, severity: 'high',
          summary: `${bfE.authFail} echecs d authentification depuis ${ip} sur les dernieres ${Math.round(c.windowMs / 60000)} min`,
          evidence: { ...base(bfE), authFailures: bfE.authFail },
        });
      } else if (!bfMet) this._clear(s, 'bruteforce');

      // Scan
      const scE = this._effective(agg, RULE_IDS.scan);
      const scanMet = c.scan.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.scan)
        && scE.requests >= c.scan.minRequests
        && scE.paths.size >= c.scan.minDistinct
        && scE.notFound / scE.requests >= c.scan.minNotFoundRatio;
      if (scanMet && this._enter(s, 'scan')) {
        alerts.push({
          type: 'scan', explanation: EXPLANATIONS.scan, severity: 'medium',
          summary: `${ip} sonde ${scE.paths.size} chemins distincts, ${Math.round(100 * scE.notFound / scE.requests)}% en 404`,
          evidence: { ...base(scE), notFound: scE.notFound },
        });
      } else if (!scanMet) this._clear(s, 'scan');

      // Flood
      const flE = this._effective(agg, RULE_IDS.flood);
      const floodMet = c.flood.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.flood)
        && flE.requests >= c.flood.minRequests;
      if (floodMet && this._enter(s, 'flood')) {
        const spanSec = Math.max(1, (agg.last - agg.first) / 1000);
        alerts.push({
          type: 'flood', explanation: EXPLANATIONS.flood, severity: 'high',
          summary: `${flE.requests} requetes depuis ${ip} sur les dernieres ${Math.round(c.windowMs / 60000)} min (${(flE.requests / spanSec).toFixed(1)}/s)`,
          evidence: { ...base(flE), requestsPerSecond: +(flE.requests / spanSec).toFixed(2) },
        });
      } else if (!floodMet) this._clear(s, 'flood');

      // Scraping
      const srE = this._effective(agg, RULE_IDS.scraping);
      const scrapeMet = c.scraping.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.scraping)
        && srE.requests >= c.scraping.minRequests
        && srE.paths.size <= c.scraping.maxDistinct
        && [...agg.uas].some(ua => c.scraping.uaHint.test(ua));
      if (scrapeMet && this._enter(s, 'scraping')) {
        alerts.push({
          type: 'scraping', explanation: EXPLANATIONS.scraping, severity: 'low',
          summary: `${srE.requests} requetes depuis ${ip} sur ${srE.paths.size} chemin(s), agent automatise, dernieres ${Math.round(c.windowMs / 60000)} min`,
          evidence: base(srE),
        });
      } else if (!scrapeMet) this._clear(s, 'scraping');

      // Regles personnalisees (lib/rules-yaml.js) : meme logique de bord
      // (edge-triggered) et memes exceptions/opt-out par vhost que les
      // quatre regles integrees ci-dessus, mais le seuil et les criteres de
      // correspondance sont entierement definis par l utilisateur.
      for (const rule of this.customRules) {
        if (rule.scope === 'global') continue; // traite plus haut : une alerte de campagne
        const stateKey = `custom:${rule.id}`;
        const windowMinutes = clampCustomWindowMinutes(rule);
        const count = this._customCount(s, now, rule.id, windowMinutes * 60_000);
        const met = rule.enable !== false && !this._ruleSuppressedForVhosts(agg.vhosts, rule.id)
          && count >= rule.minMatches;
        if (met && this._enter(s, stateKey)) {
          alerts.push({
            type: `custom_${rule.id}`, severity: rule.severity || 'medium',
            explanation: {
              what: rule.description || `Regle personnalisee "${rule.name}"`,
              why: 'Regle definie par l operateur — voir sa description.',
              legit: 'Depend entierement du critere choisi par l operateur.',
              action: 'Verifier le trafic correspondant et ajuster le seuil de la regle si besoin.',
              id: rule.id,
            },
            summary: `Regle "${rule.name}" declenchee par ${ip}${vhost ? ' sur ' + vhost : ''} : ${count} correspondance(s) sur les dernieres ${windowMinutes} min`,
            evidence: { ...base(), ruleId: rule.id, ruleName: rule.name, matches: count },
          });
        } else if (!met) this._clear(s, stateKey);
      }
    }
    return alerts;
  }

  stats() {
    let active = 0;
    for (const s of this.ips.values()) active += s.active.size;
    return { trackedIps: this.ips.size, activeAlerts: active };
  }
}

module.exports = { Detector, DEFAULTS, withDefaults, EXPLANATIONS, RULE_IDS };
