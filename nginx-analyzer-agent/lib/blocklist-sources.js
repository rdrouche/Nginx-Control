'use strict';
/**
 * Per-source blocklist IP/CIDR membership, synced in from nginx-dashboard
 * (v12.29.0) so the analyzer can attribute blocklist hits to a specific
 * source ("bySource") and, when hit_logging_method is "approx", detect hits
 * itself straight from the regular access log(s) it already tails instead
 * of requiring a separate dedicated blocklist-hits.log.
 *
 * Only the dashboard fetches and validates the blocklist sources
 * (features/blocklists.js) — this module just holds whatever it last
 * pushed, in memory, exactly like lib/detect.js's setVhostRules(): no
 * persistence, no independent source of truth. A restarted analyzer has an
 * empty index until the dashboard's next periodic push (same push loop as
 * pushVhostRules(), typically within a minute) — degrading to "no
 * attribution yet" rather than an error.
 */

const { toBytes, parseCidr, containsParsed } = require('./cidr');

let index = [];       // [{ name, exact: Set<"family:bytes">, blocks: [{bytes,family,prefix}] }]
let mode = 'dedicated'; // 'dedicated' | 'approx' — mirrors nginx-dashboard's hit_logging_method

/**
 * `sources` is { [name]: { ips: [pattern, ...] } } — the same shape
 * nginx-dashboard's blocklist cache holds per source. Invalid patterns are
 * skipped defensively (the dashboard already validates on fetch, but this
 * module never trusts a caller not to change).
 */
function setSources(sources) {
  const next = [];
  for (const [name, src] of Object.entries(sources || {})) {
    const ips = Array.isArray(src?.ips) ? src.ips : [];
    const exact = new Set();
    const blocks = [];
    for (const pattern of ips) {
      const block = parseCidr(pattern);
      if (!block) continue;
      const isHostRoute = (block.family === 4 && block.prefix === 32) || (block.family === 6 && block.prefix === 128);
      if (isHostRoute) exact.add(`${block.family}:${block.bytes.join('.')}`);
      else blocks.push(block);
    }
    next.push({ name, exact, blocks });
  }
  index = next;
}

function setMode(m) { mode = m === 'approx' ? 'approx' : 'dedicated'; }
function getMode() { return mode; }

/** Which synced source names currently list `ip`. Empty until setSources() has run at least once. */
function sourcesContaining(ip) {
  if (!index.length) return [];
  const addr = toBytes(ip);
  if (!addr) return [];
  const key = `${addr.family}:${addr.bytes.join('.')}`;
  const matches = [];
  for (const src of index) {
    if (src.exact.has(key) || src.blocks.some(block => containsParsed(addr, block))) matches.push(src.name);
  }
  return matches;
}

/** True as soon as at least one source has been synced — lets callers skip work cheaply otherwise. */
function hasSources() { return index.length > 0; }

module.exports = { setSources, setMode, getMode, sourcesContaining, hasSources };
