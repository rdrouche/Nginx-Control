'use strict';
/**
 * IP address and CIDR block matching, for both IPv4 and IPv6.
 *
 * Written by hand rather than pulled in as a dependency, like every other
 * parser in this project. A plain address (no `/prefix`) is treated as an
 * exact match — a /32 for IPv4, a /128 for IPv6 — so callers never need two
 * code paths for "one address" versus "a range".
 */

/** Parse an IPv4 address into 4 bytes, or null if invalid. */
function ipv4ToBytes(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const bytes = [];
  for (let i = 1; i <= 4; i++) {
    const n = +m[i];
    if (n < 0 || n > 255 || String(n) !== m[i].replace(/^0+(?=\d)/, '')) return null;
    bytes.push(n);
  }
  return bytes;
}

/**
 * Parse an IPv6 address into 16 bytes, or null if invalid.
 * Handles "::" compression and an IPv4-mapped tail (e.g. "::ffff:203.0.113.5").
 */
function ipv6ToBytes(ip) {
  if (ip.indexOf(':') === -1) return null;
  let head = ip, tail = '';
  const dc = ip.indexOf('::');
  if (dc !== -1) {
    if (ip.indexOf('::', dc + 1) !== -1) return null;   // "::" may appear once
    head = ip.slice(0, dc);
    tail = ip.slice(dc + 2);
  }

  const parseGroups = s => s === '' ? [] : s.split(':');
  let headGroups = parseGroups(head);
  let tailGroups = parseGroups(tail);

  // An IPv4 tail ("...:203.0.113.5") expands to two 16-bit groups.
  const expandV4Tail = groups => {
    if (!groups.length) return groups;
    const last = groups[groups.length - 1];
    if (last.indexOf('.') === -1) return groups;
    const v4 = ipv4ToBytes(last);
    if (!v4) return null;
    return [...groups.slice(0, -1),
      ((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16)];
  };
  headGroups = expandV4Tail(headGroups);
  tailGroups = expandV4Tail(tailGroups);
  if (headGroups === null || tailGroups === null) return null;

  const total = headGroups.length + tailGroups.length;
  if (dc === -1 && total !== 8) return null;
  if (dc !== -1 && total >= 8) return null;
  const fill = dc !== -1 ? 8 - total : 0;
  const allGroups = [...headGroups, ...Array(fill).fill('0'), ...tailGroups];
  if (allGroups.length !== 8) return null;

  const bytes = [];
  for (const g of allGroups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return bytes;
}

/** Bytes and address family for any supported address, or null if invalid. */
function toBytes(ip) {
  if (typeof ip !== 'string' || !ip) return null;
  const v4 = ipv4ToBytes(ip);
  if (v4) return { bytes: v4, family: 4 };
  const v6 = ipv6ToBytes(ip);
  if (v6) return { bytes: v6, family: 6 };
  return null;
}

/**
 * Parse a plain address or a CIDR block ("addr" or "addr/prefix").
 * Returns { bytes, family, prefix } or null if unparseable — including a
 * prefix out of range for the address family.
 */
function parseCidr(pattern) {
  if (typeof pattern !== 'string') return null;
  // Fix (audit report, Basse/Analyzer): a trailing (or leading) space around
  // the whole pattern — easy to pick up copy-pasting a blocklist entry —
  // used to make it past the address parse (toBytes() already trims the
  // address half below) but then fail the prefix's `^\d{1,3}$` test, since
  // that regex was run against the untrimmed remainder. A syntactically
  // valid CIDR was silently rejected as invalid for a purely cosmetic reason.
  pattern = pattern.trim();
  const i = pattern.indexOf('/');
  const addr = i === -1 ? pattern : pattern.slice(0, i);
  const parsed = toBytes(addr.trim());
  if (!parsed) return null;
  const maxPrefix = parsed.family === 4 ? 32 : 128;
  let prefix = maxPrefix;
  if (i !== -1) {
    const prefixStr = pattern.slice(i + 1).trim();
    if (!/^\d{1,3}$/.test(prefixStr)) return null;
    prefix = +prefixStr;
    if (prefix < 0 || prefix > maxPrefix) return null;
  }
  return { bytes: parsed.bytes, family: parsed.family, prefix };
}

/**
 * If `bytes16` (a 16-byte IPv6 address) is an IPv4-mapped address
 * (`::ffff:a.b.c.d`, the standard form for an IPv4 address carried over an
 * IPv6 socket — the shape Node's own `net`/`tls` APIs report a dual-stack
 * connection's remote address in), return its embedded 4 IPv4 bytes;
 * otherwise null.
 */
function mappedV4Bytes(bytes16) {
  for (let i = 0; i < 10; i++) if (bytes16[i] !== 0) return null;
  if (bytes16[10] !== 0xff || bytes16[11] !== 0xff) return null;
  return bytes16.slice(12, 16);
}

/**
 * True when `ip` falls within `pattern` (a plain address or a CIDR block).
 *
 * Fix (audit report, Basse/Analyzer): `::ffff:203.0.113.5` — the standard
 * IPv4-mapped IPv6 form, which is exactly what a dual-stack listener reports
 * an IPv4 peer as — used to never match an IPv4 CIDR/address at all, because
 * the two parsed to different `family` values and that alone short-circuited
 * the match to false, even though the address is the same one. Either side
 * being an IPv4-mapped IPv6 value is now unwrapped to its embedded IPv4
 * bytes before the family check, so both spellings of the same address
 * behave identically.
 */
/**
 * Same containment test as ipInCidr(), but taking already-parsed values —
 * ported from nginx-dashboard/lib/cidr.js (v12.29.0), where it exists so a
 * caller matching one address against many patterns (or vice versa) parses
 * each side exactly once instead of on every single comparison. The
 * analyzer needs the same shape for lib/blocklist-sources.js, which matches
 * every tailed access-log entry's IP against every synced blocklist source
 * when hit_logging_method is "approx" — parsing both sides fresh on every
 * request would be the same quadratic blow-up the dashboard fixed in
 * v12.21.2, just triggered by log volume instead of a page load.
 */
function containsParsed(addr, block) {
  if (!addr || !block) return false;

  let addrBytes = addr.bytes, addrFamily = addr.family;
  let blockBytes = block.bytes, blockFamily = block.family, blockPrefix = block.prefix;

  if (addrFamily !== blockFamily) {
    if (addrFamily === 6 && blockFamily === 4) {
      const v4 = mappedV4Bytes(addrBytes);
      if (!v4) return false;
      addrBytes = v4; addrFamily = 4;
    } else if (addrFamily === 4 && blockFamily === 6 && blockPrefix >= 96) {
      const v4 = mappedV4Bytes(blockBytes);
      if (!v4) return false;
      blockBytes = v4; blockFamily = 4; blockPrefix = Math.min(32, blockPrefix - 96);
    } else {
      return false;
    }
  }

  const fullBytes = blockPrefix >> 3;
  for (let i = 0; i < fullBytes; i++) if (addrBytes[i] !== blockBytes[i]) return false;

  const remBits = blockPrefix % 8;
  if (remBits === 0) return true;
  const mask = 0xff << (8 - remBits) & 0xff;
  return (addrBytes[fullBytes] & mask) === (blockBytes[fullBytes] & mask);
}

function ipInCidr(ip, pattern) {
  const addr = toBytes(ip);
  const block = parseCidr(pattern);
  return containsParsed(addr, block);
}

/** True when `pattern` is a syntactically valid address or CIDR block. */
function isValidPattern(pattern) { return parseCidr(pattern) !== null; }

module.exports = { ipv4ToBytes, ipv6ToBytes, toBytes, parseCidr, containsParsed, ipInCidr, isValidPattern, mappedV4Bytes };
