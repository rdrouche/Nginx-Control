'use strict';
/**
 * Volumetric anomaly detection.
 *
 * Three decisions shape this module, each learned from how this kind of
 * detector usually fails.
 *
 * **Seasonality is not optional.** Tuesday 2pm and Sunday 4am have nothing in
 * common. Comparing against a single global average produces a permanent alert
 * storm, so the baseline is per hour-of-week — 168 buckets.
 *
 * **Median and MAD, not mean and standard deviation.** A single past attack
 * skews a mean for weeks and inflates the deviation, after which the detector
 * goes quiet exactly when it should not. The median ignores outliers, and MAD
 * (median absolute deviation) measures spread the same way. The 1.4826 factor
 * makes MAD comparable to a standard deviation on normally distributed data,
 * so a threshold expressed in "sigmas" keeps its usual meaning.
 *
 * **Volume alone cannot separate an attack from success.** An article doing
 * well looks exactly like a volumetric attack on the request count. What
 * separates them is structure: a real audience brings many addresses, varied
 * user agents, varied paths and few errors. A flood usually brings the
 * opposite. Those signals are carried alongside the volume so the alert can
 * say which one it saw.
 */

const MAD_TO_SIGMA = 1.4826;
const HOURS_PER_WEEK = 168;
// Une cle (vhost, pays) n est « suivie » pour la couverture qu a partir de 24 heures
// observees : sinon un Host aleatoire ou un pays croise une fois gonfle le denominateur.
const RELEVANT_MIN_SAMPLES = 24;

const DEFAULTS = {
  minSamplesPerBucket: 3,     // below this, the bucket says nothing
  learningDays:        21,    // observation before the first alert
  sigmaThreshold:      6,     // deliberately high: false positives are costly
  minAbsoluteRequests: 100,   // ignore deviations on tiny volumes
  // Rule-level on/off (dashboard "Regles" modal). Learning still happens
  // while disabled — only the alert is withheld — so re-enabling later does
  // not start from scratch.
  enable: true,
};

const median = sorted =>
  sorted.length === 0 ? 0
  : sorted.length % 2 ? sorted[(sorted.length - 1) / 2]
  : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;

/** Median absolute deviation, scaled to be comparable to a standard deviation. */
function mad(values, med) {
  if (values.length === 0) return 0;
  const deviations = values.map(v => Math.abs(v - med)).sort((a, b) => a - b);
  return median(deviations) * MAD_TO_SIGMA;
}

/**
 * Bucket index: hour of week, Monday 00h = 0.
 *
 * Fix (audit report, Basse/Analyzer, "creneaux de baseline en UTC (decales
 * d'une heure pendant des mois apres un changement d'heure)"): this used to
 * bucket by UTC day/hour, which is a fixed offset from human wall-clock time
 * only half the year — the moment the local zone's DST shifts, "9am local"
 * (when a real audience actually shows up) starts landing in what used to be
 * the 8am/10am UTC bucket, and stays there until the learned history (up to
 * 12 weekly samples per bucket, ~3 months — see observe()) has fully rotated
 * past the old data. Bucketing by LOCAL day/hour instead tracks the same
 * human rhythm year-round, since JavaScript's local getters already follow
 * the runtime's DST rules for whatever IANA zone `TZ` names (see the
 * Dockerfiles: this only resolves correctly once TZ is actually set to the
 * deployment's real zone — with no TZ set, local time IS UTC, which is
 * simply the previous behavior, unchanged).
 */
function hourOfWeek(date) {
  const d = date instanceof Date ? date : new Date(date);
  const day = (d.getDay() + 6) % 7;          // Monday = 0
  return day * 24 + d.getHours();
}

class Baseline {
  /**
   * @param {object} cfg
   * @param {object} state  previously persisted state, to survive a restart
   */
  constructor(cfg = {}, state = null) {
    this.cfg = { ...DEFAULTS, ...cfg };
    // key = `${vhost}|${hourOfWeek}` → array of observed values
    this.buckets = new Map(Object.entries(state?.buckets || {}));
    this.startedAt = state?.startedAt || Date.now();
    this.excluded  = new Set(state?.excluded || []);   // periods marked as normal
  }

  _key(vhost, how) { return `${vhost}|${how}`; }

  /**
   * Record an hourly observation. `metrics` carries the volume and the
   * structural signals that tell a crowd apart from a flood.
   */
  observe(vhost, date, metrics) {
    const how = hourOfWeek(date);
    const key = this._key(vhost, how);
    const stamp = `${vhost}|${new Date(date).toISOString().slice(0, 13)}`;
    // A period the operator marked as normal must not teach the baseline.
    if (this.excluded.has(stamp)) return;

    let arr = this.buckets.get(key);
    if (!arr) { arr = []; this.buckets.set(key, arr); }
    arr.push(metrics.requests);
    // Keep the last 12 observations of each slot — about three months.
    if (arr.length > 12) arr.shift();
  }

  /** Days of observation so far. */
  learningDaysElapsed() {
    return (Date.now() - this.startedAt) / 86_400_000;
  }

  /** Whether enough history exists to alert at all. */
  isLearning() {
    return this.learningDaysElapsed() < this.cfg.learningDays;
  }

  /** Reference statistics for one slot, or null when the sample is too thin. */
  reference(vhost, date) {
    const arr = this.buckets.get(this._key(vhost, hourOfWeek(date)));
    if (!arr || arr.length < this.cfg.minSamplesPerBucket) return null;
    const sorted = [...arr].sort((a, b) => a - b);
    const med = median(sorted);
    return { median: med, mad: mad(arr, med), samples: arr.length };
  }

  /**
   * Compare an observation against its reference.
   *
   * Returns null when there is nothing to say — still learning, thin sample,
   * volume too small, or simply normal. When it does report, it says whether
   * the structure looks like an audience or like a flood, and never claims
   * more certainty than the data supports.
   */
  check(vhost, date, metrics) {
    if (this.isLearning()) {
      return { learning: true, daysElapsed: +this.learningDaysElapsed().toFixed(1),
               daysRequired: this.cfg.learningDays };
    }
    const ref = this.reference(vhost, date);
    if (!ref) return null;
    if (metrics.requests < this.cfg.minAbsoluteRequests) return null;

    // A MAD of zero means a perfectly stable slot; fall back to a relative
    // floor so the deviation stays finite instead of exploding to infinity.
    const spread = ref.mad > 0 ? ref.mad : Math.max(1, ref.median * 0.1);
    const deviation = (metrics.requests - ref.median) / spread;
    if (deviation < this.cfg.sigmaThreshold) return null;

    // Structure: does this look like a crowd, or like one machine?
    const ipsPerRequest  = metrics.distinctIps  / Math.max(1, metrics.requests);
    const errorRatio     = metrics.errors       / Math.max(1, metrics.requests);
    const pathsPerRequest = metrics.distinctPaths / Math.max(1, metrics.requests);

    // A real audience: many addresses, varied paths, few errors.
    const looksOrganic = ipsPerRequest > 0.1 && pathsPerRequest > 0.05 && errorRatio < 0.2;

    return {
      learning: false,
      anomaly: true,
      vhost,
      hour: new Date(date).toISOString().slice(0, 13),
      observed: metrics.requests,
      expected: Math.round(ref.median),
      deviation: +deviation.toFixed(1),
      samples: ref.samples,
      // Structure is reported rather than used to suppress the alert: the
      // detector says what it saw, the operator decides.
      structure: {
        distinctIps:   metrics.distinctIps,
        distinctPaths: metrics.distinctPaths,
        errorRatio:    +errorRatio.toFixed(3),
        looksOrganic,
      },
      severity: looksOrganic ? 'low' : deviation > this.cfg.sigmaThreshold * 2 ? 'high' : 'medium',
      summary: looksOrganic
        ? `Trafic inhabituel sur ${vhost} : ${metrics.requests} requetes contre ${Math.round(ref.median)} attendues, mais la structure ressemble a une audience reelle`
        : `Pic anormal sur ${vhost} : ${metrics.requests} requetes contre ${Math.round(ref.median)} attendues (${deviation.toFixed(1)} ecarts), peu d adresses distinctes`,
    };
  }

  /** Mark an hour as normal so it stops counting against the baseline. */
  exclude(vhost, isoHour) {
    this.excluded.add(`${vhost}|${isoHour.slice(0, 13)}`);
  }

  /** Serialisable state, to survive a restart. */
  toJSON() {
    return {
      startedAt: this.startedAt,
      buckets: Object.fromEntries(this.buckets),
      excluded: [...this.excluded],
    };
  }

  /**
   * Bug fixe (retour utilisateur, v12.49.3) : `coverage` divisait le nombre de
   * creneaux remplis par HOURS_PER_WEEK (168) sans jamais tenir compte du
   * nombre de vhosts suivis — alors que `this.buckets` est une grille PAR
   * VHOST (cle `${vhost}|${hourOfWeek}`, voir _key() plus haut) : avec 12
   * vhosts actifs, il existe jusqu a 12*168 = 2016 creneaux possibles, pas
   * 168. D ou des valeurs incoherentes comme "1888 / 168 (1123.8%)" des qu un
   * deploiement suit plus d un vhost. Le nombre de creneaux possibles est
   * desormais compte reellement (vhosts suivis x 168), et le taux de
   * couverture rapporte a CE total — jamais au nombre fixe de 168, qui n a de
   * sens que pour un seul vhost.
   */
  stats() {
    let filled = 0, filledRelevant = 0;
    const perKey = new Map(); // cle -> { samples, usable }
    for (const [key, arr] of this.buckets) {
      const k = key.slice(0, key.lastIndexOf('|'));
      const e = perKey.get(k) || { samples: 0, usable: 0 };
      e.samples += arr.length;
      if (arr.length >= this.cfg.minSamplesPerBucket) { e.usable++; filled++; }
      perKey.set(k, e);
    }
    let relevant = 0;
    for (const e of perKey.values()) {
      if (e.samples >= RELEVANT_MIN_SAMPLES) { relevant++; filledRelevant += e.usable; }
    }
    // v12.68.0 : le denominateur ne compte que les cles reellement suivies
    // (>= 24 heures observees). Avant, chaque Host ou pays croise une seule fois
    // ajoutait 168 creneaux « a apprendre », d ou des taux de 0,1 %.
    const totalSlots = Math.max(1, relevant) * HOURS_PER_WEEK;
    return {
      learning: this.isLearning(),
      daysElapsed: +this.learningDaysElapsed().toFixed(1),
      daysRequired: this.cfg.learningDays,
      startedAt: new Date(this.startedAt).toISOString(),
      bucketsTracked: this.buckets.size,
      bucketsUsable: filledRelevant,
      bucketsUsableAll: filled,
      vhostsTracked: relevant,
      keysTracked: perKey.size,
      sporadicKeys: perKey.size - relevant,
      totalSlots,
      coverage: +(100 * filledRelevant / totalSlots).toFixed(1),
    };
  }

  /**
   * Ce qui est appris pour une cle : 168 creneaux (lundi 0h = 0) avec la mediane
   * observee, l ecart (MAD) et le seuil au-dela duquel une alerte serait emise.
   */
  profile(key) {
    const slots = [];
    for (let how = 0; how < HOURS_PER_WEEK; how++) {
      const arr = this.buckets.get(this._key(key, how));
      if (!arr || arr.length === 0) { slots.push({ how, samples: 0, usable: false }); continue; }
      const sorted = [...arr].sort((a, b) => a - b);
      const med = median(sorted);
      const spread = mad(arr, med) > 0 ? mad(arr, med) : Math.max(1, med * 0.1);
      slots.push({
        how, samples: arr.length, usable: arr.length >= this.cfg.minSamplesPerBucket,
        median: Math.round(med), spread: +spread.toFixed(1),
        threshold: Math.round(Math.max(med + this.cfg.sigmaThreshold * spread, this.cfg.minAbsoluteRequests)),
      });
    }
    return { key, slots, sigma: this.cfg.sigmaThreshold, minAbsoluteRequests: this.cfg.minAbsoluteRequests,
      minSamples: this.cfg.minSamplesPerBucket };
  }

  /** Resume par cle, les plus volumineuses d abord : de quoi voir ce qui est appris sans ouvrir chaque profil. */
  keysSummary(limit = 100) {
    const per = new Map();
    for (const [bk, arr] of this.buckets) {
      const k = bk.slice(0, bk.lastIndexOf('|'));
      const how = +bk.slice(bk.lastIndexOf('|') + 1);
      const sorted = [...arr].sort((a, b) => a - b);
      const med = median(sorted);
      const e = per.get(k) || { key: k, samples: 0, usableSlots: 0, weekly: 0, peak: 0, peakHow: 0 };
      e.samples += arr.length;
      if (arr.length >= this.cfg.minSamplesPerBucket) e.usableSlots++;
      e.weekly += med;
      if (med > e.peak) { e.peak = med; e.peakHow = how; }
      per.set(k, e);
    }
    return [...per.values()]
      .map(e => ({ key: e.key, samples: e.samples, usableSlots: e.usableSlots, relevant: e.samples >= RELEVANT_MIN_SAMPLES,
        weeklyEstimate: Math.round(e.weekly), peakPerHour: Math.round(e.peak), peakHow: e.peakHow }))
      .sort((a, b) => b.weeklyEstimate - a.weeklyEstimate).slice(0, limit);
  }
}

module.exports = { RELEVANT_MIN_SAMPLES, Baseline, DEFAULTS, hourOfWeek, median, mad, MAD_TO_SIGMA };
