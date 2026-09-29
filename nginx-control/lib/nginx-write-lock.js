'use strict';
/**
 * Global async mutex shared by every nginx-config generator
 * (features/blocklists.js, features/docker-autoconfig.js, features/agents.js)
 * whose cycle writes one or more files, runs `nginx -t`, then `nginx -s
 * reload` (rolling its own writes back on a failed test).
 *
 * Fix v12.21.2 (audit finding DAC-05): each generator used to run this
 * write -> test -> reload sequence with zero coordination between them. The
 * docker-autoconfig scheduler, a Docker Events burst, an operator's
 * approve/reject click, a blocklist refresh, and an agent's manifest push
 * can all land within the same second — without a shared lock, cycle A can
 * test successfully, cycle B (a DIFFERENT feature) writes its own files in
 * the gap between A's `nginx -t` and `nginx -s reload`, and A ends up
 * reloading nginx with B's half-applied config; or A's rollback (triggered
 * by a failed test) overwrites a file B just wrote successfully. Every
 * feature's own write/test/reload critical section must run one at a time,
 * across ALL of them, not just within each one.
 *
 * `withLock(fn)` queues `fn` to run alone. A caller that asks for the lock
 * while one is already in flight does not queue indefinitely — a burst of
 * Docker events firing ten near-identical cycles back to back must not queue
 * ten runs one after another, it only needs ONE more run after the current
 * one finishes to pick up whatever changed meanwhile. So every concurrent
 * caller beyond the one currently running shares a single "coalesced" slot
 * for that one extra run, and all of them receive its result.
 */

let current = null;    // Promise of the run currently in flight, or null
let pendingRun = null; // Promise of the single queued "run once more" slot

function runAndClear(fn) {
  return Promise.resolve().then(fn).finally(() => { current = null; });
}

function withLock(fn) {
  if (!current) {
    current = runAndClear(fn);
    return current;
  }
  if (!pendingRun) {
    pendingRun = current.catch(() => {}).then(() => {
      // Clear the slot BEFORE starting the queued run so any caller that
      // arrives while this new run is itself in flight queues a fresh slot,
      // rather than being folded into a run that already started.
      pendingRun = null;
      current = runAndClear(fn);
      return current;
    });
  }
  return pendingRun;
}

/** For tests only: true while a run (current or queued) is in flight. */
function isLocked() {
  return !!current;
}

module.exports = { withLock, isLocked };
