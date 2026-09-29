'use strict';
/**
 * IP address and CIDR block matching, for both IPv4 and IPv6.
 *
 * Ported from nginx-analyzer/lib/cidr.js (same zero-npm-dependency project
 * convention — this file is the dashboard's own copy rather than a shared
 * module, since the two services never share a require() path). Kept
 * byte-for-byte identical in behavior; only this header differs.
 *
 * Used by features/blocklists.js's IP-search endpoint to check whether a
 * given address falls inside any configured source's cached IP/CIDR list —
 * the cache stores the same raw entries (plain addresses or CIDR blocks)
 * that end up in the generated `geo{}` table, so membership here must use
 * the same containment rule nginx itself applies.
 */

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

function ipv6ToBytes(ip) {
  if (ip.indexOf(':') === -1) return null;
  let head = ip, tail = '';
  const dc = ip.indexOf('::');
  if (dc !== -1) {
    if (ip.indexOf('::', dc + 1) !== -1) return null;
    head = ip.slice(0, dc);
    tail = ip.slice(dc + 2);
  }

  const parseGroups = s => s === '' ? [] : s.split(':');
  let headGroups = parseGroups(head);
  let tailGroups = parseGroups(tail);

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

function toBytes(ip) {
  if (typeof ip !== 'string' || !ip) return null;
  const v4 = ipv4ToBytes(ip);
  if (v4) return { bytes: v4, family: 4 };
  const v6 = ipv6ToBytes(ip);
  if (v6) return { bytes: v6, family: 6 };
  return null;
}

function parseCidr(pattern) {
  if (typeof pattern !== 'string') return null;
  // Fix (audit report, Basse/Analyzer, ported from nginx-analyzer/lib/cidr.js):
  // a trailing (or leading) space around the whole pattern — easy to pick up
  // copy-pasting a blocklist entry — used to make it past the address parse
  // (toBytes() already trims the address half below) but then fail the
  // prefix's `^\d{1,3}$` test, since that regex ran against the untrimmed
  // remainder. A syntactically valid CIDR was silently rejected for a purely
  // cosmetic reason.
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
 * (`::ffff:a.b.c.d`), return its embedded 4 IPv4 bytes; otherwise null.
 */
function mappedV4Bytes(bytes16) {
  for (let i = 0; i < 10; i++) if (bytes16[i] !== 0) return null;
  if (bytes16[10] !== 0xff || bytes16[11] !== 0xff) return null;
  return bytes16.slice(12, 16);
}

/**
 * Core containment check on already-PARSED inputs (toBytes()/parseCidr()
 * results) — no string parsing at all. Extracted from ipInCidr() so a
 * caller checking the SAME IP or the SAME pattern list many times over
 * (features/blocklists.js's hit-stats attribution, matching up to 1000 IPs
 * against every configured source) can parse each address and each pattern
 * exactly ONCE instead of re-parsing both on every single comparison — see
 * that module's own comment (audit-independent fix, v12.21.2) for the
 * quadratic blow-up this was causing on the Blocklists IP page.
 *
 * Fix (audit report, Basse/Analyzer, "::ffff:a.b.c.d ne correspond pas a un
 * CIDR IPv4", ported from nginx-analyzer/lib/cidr.js): `::ffff:203.0.113.5`
 * — the standard IPv4-mapped IPv6 form, exactly what a dual-stack listener
 * reports an IPv4 peer as — used to never match an IPv4 CIDR/address at all,
 * because the two parsed to different `family` values and that alone
 * short-circuited the match to false, even though it is the same address.
 * Either side being IPv4-mapped is now unwrapped to its embedded IPv4 bytes
 * before the family check.
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

function isValidPattern(pattern) { return parseCidr(pattern) !== null; }

module.exports = { ipv4ToBytes, ipv6ToBytes, toBytes, parseCidr, containsParsed, ipInCidr, isValidPattern, mappedV4Bytes };
