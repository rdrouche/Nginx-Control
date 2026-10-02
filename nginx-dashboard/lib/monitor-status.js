'use strict';
/**
 * Pure logic deciding whether one HTTP probe result counts as "up" for
 * continuous monitoring (features/monitor.js) — kept separate from
 * features/backends.js's checkTarget(), which only reports whether a
 * response was received at all (used by the on-demand "test now" check
 * elsewhere in the dashboard, where showing the raw status code/color is
 * the whole point, not classifying it). Continuous monitoring needs a
 * stricter notion of "up", because plenty of setups relay a stopped
 * backend as an HTTP response rather than a connection error — a
 * container exposed through Traefik commonly answers "no such service"
 * with a 404, a live gateway with nothing behind it — so a monitored
 * vhost stuck on that 404 would otherwise never be flagged down.
 *
 * Default (no override): 2xx/3xx/4xx count as up, 5xx and no-response
 * count as down — the common case for a real HTTP backend.
 *
 * Per-vhost override via a comment flag (parsed in lib/vhost-targets.js),
 * the user's own proposed syntax:
 *   # nginx-control-monitoring-valid-http-code: 2xx, 3xx
 * A comma-separated list of patterns, each one of:
 *   - a whole status class: "2xx".."5xx"
 *   - an exact 3-digit code: "404"
 *   - a range: "200-299"
 */

const CLASS_RE = /^([1-5])xx$/i;
const EXACT_RE = /^[1-5]\d{2}$/;
const RANGE_RE = /^(\d{3})-(\d{3})$/;

/** Parses the raw flag value into a validated pattern list, or null if empty/entirely invalid. */
function parseValidHttpCodes(raw) {
  if (!raw) return null;
  const patterns = String(raw).split(',').map(s => s.trim()).filter(Boolean);
  const valid = patterns.filter(p => CLASS_RE.test(p) || EXACT_RE.test(p) || RANGE_RE.test(p));
  return valid.length ? valid : null;
}

function matchesPattern(status, pattern) {
  const cls = pattern.match(CLASS_RE);
  if (cls) return Math.floor(status / 100) === Number(cls[1]);
  const range = pattern.match(RANGE_RE);
  if (range) return status >= Number(range[1]) && status <= Number(range[2]);
  return status === Number(pattern);
}

/**
 * true = counts as "up". `status` null/undefined (timeout, connection
 * refused/reset, DNS failure...) is always down, regardless of patterns.
 * `patterns` is the parsed list from parseValidHttpCodes(), or falsy to
 * apply the default rule.
 */
function isStatusUp(status, patterns) {
  if (status == null) return false;
  if (!patterns || !patterns.length) return status < 500;
  return patterns.some(p => matchesPattern(status, p));
}

module.exports = { parseValidHttpCodes, isStatusUp };
