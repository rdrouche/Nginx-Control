'use strict';
/**
 * Generic "accumulate by key within the hour, close hours on a delay"
 * bucket — the mechanism behind server.js's per-vhost and per-country
 * hourly structural tracking feeding lib/baseline.js.
 *
 * Extracted into its own module (fix, audit finding ANA-07) so the fix could
 * be unit-tested directly, and so trackStructure()/trackCountryStructure()
 * in server.js share one implementation instead of two copies that could
 * drift apart.
 *
 * Two bugs this replaces, both in the original single-"current hour"-object
 * version:
 *
 * 1. Several log tailers (access, WAF, blocklist) advance independently and
 *    are polled in turn, so entries can reach the tracker slightly out of
 *    order across files — near an hour boundary this made the "current
 *    hour" appear to flip back and forth as entries interleaved, forcing a
 *    premature flush of a still-forming hour's partial data every time it
 *    did. Keeping one accumulator PER HOUR (a map keyed by hour timestamp)
 *    lets two hours' entries accumulate side by side without either
 *    stepping on the other, however interleaved their arrival is.
 * 2. Flushing "the current hour" on process shutdown treated an in-progress
 *    hour as finished. If the process restarted within that same hour, the
 *    remainder accumulated separately and got flushed again once the hour
 *    genuinely ended — the same real hour counted twice, both halves
 *    partial, in whatever downstream history observe()s it. closeFinished()
 *    only ever returns hours that ended more than `closeDelayMs` ago, well
 *    clear of the interleaving window, and the caller is expected to never
 *    force-close an hour some other way (in particular: not on shutdown).
 */
class HourlyAccumulator {
  constructor({ closeDelayMs = 3_600_000, hourMs = 3_600_000 } = {}) {
    this.hourMs = hourMs;
    this.closeDelayMs = closeDelayMs;
    this.byHour = new Map(); // hour ts -> Map<key, accumulator>
  }

  hourOf(ts) { return Math.floor(ts / this.hourMs) * this.hourMs; }

  /**
   * Fold one entry into its hour/key slot. `createFn()` builds a fresh
   * per-key accumulator on first use; `updateFn(acc)` mutates it in place.
   */
  add(ts, key, createFn, updateFn) {
    const h = this.hourOf(ts);
    let byKey = this.byHour.get(h);
    if (!byKey) { byKey = new Map(); this.byHour.set(h, byKey); }
    let acc = byKey.get(key);
    if (!acc) { acc = createFn(); byKey.set(key, acc); }
    updateFn(acc);
    return acc;
  }

  /**
   * Remove and return every hour bucket that ended more than `closeDelayMs`
   * ago, as `[hourTs, Map<key, accumulator>][]`, oldest first. Safe to call
   * as often as convenient — an hour not yet due is simply left in place.
   */
  closeFinished(now = Date.now()) {
    // An hour spans [hour, hour + hourMs) and "ends" at hour + hourMs; it is
    // only closed once that end is at least closeDelayMs in the past.
    const cutoff = now - this.closeDelayMs - this.hourMs;
    const closed = [];
    for (const [hour, byKey] of this.byHour) {
      if (hour <= cutoff) closed.push([hour, byKey]);
    }
    closed.sort((a, b) => a[0] - b[0]);
    for (const [hour] of closed) this.byHour.delete(hour);
    return closed;
  }

  /** Hours currently open (for tests/diagnostics), oldest first. */
  openHours() { return [...this.byHour.keys()].sort((a, b) => a - b); }
}

module.exports = { HourlyAccumulator };
