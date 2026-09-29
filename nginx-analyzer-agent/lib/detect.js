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
    // Per-vhost opt-out, computed by the dashboard from the vhost files'
    // own comments (# nginx-control-analyze: off /
    // # nginx-control-analyze-ignore-rules: 1, 2, 4) and pushed here — see
    // setVhostRules(). Keyed by lowercased vhost name.
    //   Map<string, { enabled: boolean, ignore: Set<number> }>
    this.vhostRules = new Map();
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

    // Custom rules: a small, per-request check against each enabled rule's
    // filters. The list is short (hand-authored, not machine-generated), so
    // a linear scan per request is negligible next to log parsing itself.
    for (const rule of this.customRules) {
      if (rule.enable === false) continue;
      if (rule.pathHint && (entry.path == null || !rule.pathHint.test(entry.path))) continue;
      if (rule.uaHint && !(entry.ua && rule.uaHint.test(entry.ua))) continue;
      if (rule.statusIn.length && !rule.statusIn.includes(entry.status)) continue;
      if (rule.methodIn.length && !rule.methodIn.includes(entry.method)) continue;
      b.custom.set(rule.id, (b.custom.get(rule.id) || 0) + 1);
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
    }
    const samples = s.samples.filter(x => x.ts >= now - this.cfg.windowMs).slice(-5);
    return { requests, authFail, notFound, paths, uas, vhosts, statuses, custom, samples, first, last: s.last };
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

      const base = () => ({
        ip, vhost,
        firstSeen: agg.first, lastSeen: agg.last,
        requests: agg.requests,
        distinctPaths: agg.paths.size,
        userAgents: [...agg.uas].slice(0, 3),
        statuses: Object.fromEntries(agg.statuses),
        samples: agg.samples,
      });

      // Brute force
      const bfMet = c.bruteforce.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.bruteforce)
        && agg.authFail >= c.bruteforce.minFailures;
      if (bfMet && this._enter(s, 'bruteforce')) {
        alerts.push({
          type: 'bruteforce', explanation: EXPLANATIONS.bruteforce, severity: 'high',
          summary: `${agg.authFail} echecs d authentification depuis ${ip} sur les dernieres ${Math.round(c.windowMs / 60000)} min`,
          evidence: { ...base(), authFailures: agg.authFail },
        });
      } else if (!bfMet) this._clear(s, 'bruteforce');

      // Scan
      const scanMet = c.scan.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.scan)
        && agg.requests >= c.scan.minRequests
        && agg.paths.size >= c.scan.minDistinct
        && agg.notFound / agg.requests >= c.scan.minNotFoundRatio;
      if (scanMet && this._enter(s, 'scan')) {
        alerts.push({
          type: 'scan', explanation: EXPLANATIONS.scan, severity: 'medium',
          summary: `${ip} sonde ${agg.paths.size} chemins distincts, ${Math.round(100 * agg.notFound / agg.requests)}% en 404`,
          evidence: { ...base(), notFound: agg.notFound },
        });
      } else if (!scanMet) this._clear(s, 'scan');

      // Flood
      const floodMet = c.flood.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.flood)
        && agg.requests >= c.flood.minRequests;
      if (floodMet && this._enter(s, 'flood')) {
        const spanSec = Math.max(1, (agg.last - agg.first) / 1000);
        alerts.push({
          type: 'flood', explanation: EXPLANATIONS.flood, severity: 'high',
          summary: `${agg.requests} requetes depuis ${ip} sur les dernieres ${Math.round(c.windowMs / 60000)} min (${(agg.requests / spanSec).toFixed(1)}/s)`,
          evidence: { ...base(), requestsPerSecond: +(agg.requests / spanSec).toFixed(2) },
        });
      } else if (!floodMet) this._clear(s, 'flood');

      // Scraping
      const scrapeMet = c.scraping.enable && !this._ruleSuppressedForVhosts(agg.vhosts, RULE_IDS.scraping)
        && agg.requests >= c.scraping.minRequests
        && agg.paths.size <= c.scraping.maxDistinct
        && [...agg.uas].some(ua => c.scraping.uaHint.test(ua));
      if (scrapeMet && this._enter(s, 'scraping')) {
        alerts.push({
          type: 'scraping', explanation: EXPLANATIONS.scraping, severity: 'low',
          summary: `${agg.requests} requetes depuis ${ip} sur ${agg.paths.size} chemin(s), agent automatise, dernieres ${Math.round(c.windowMs / 60000)} min`,
          evidence: base(),
        });
      } else if (!scrapeMet) this._clear(s, 'scraping');

      // Regles personnalisees (lib/rules-yaml.js) : meme logique de bord
      // (edge-triggered) et memes exceptions/opt-out par vhost que les
      // quatre regles integrees ci-dessus, mais le seuil et les criteres de
      // correspondance sont entierement definis par l utilisateur.
      for (const rule of this.customRules) {
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
