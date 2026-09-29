'use strict';
/**
 * GeoIP lookups against MaxMind databases.
 *
 * Foundation rather than a feature: access-log enrichment needs it just as much
 * as the lookup endpoint, and features never import each other.
 *
 * Reads the .mmdb binary format directly rather than pulling in a library:
 * the dashboard ships with zero npm dependencies, and only IPv4 point lookups
 * are needed. The reader is deliberately minimal and returns null on anything
 * it does not understand, so a malformed or partially-downloaded database
 * degrades to "no geo data" instead of taking a request down.
 *
 * Results are cached: a busy access log would otherwise re-read the database
 * for every single line.
 */

const fs = require('fs');
const { ipv6ToBytes, mappedV4Bytes } = require('./cidr');

const cfg = require('./config');

const GEOIP_CITY_DB    = cfg.GEOIP_CITY_DB;
const GEOIP_COUNTRY_DB = cfg.GEOIP_COUNTRY_DB;
const GEOIP_ASN_DB     = cfg.GEOIP_ASN_DB;

// Bounded cache — cleared by halves rather than tracking exact LRU order,
// which is enough for a lookup that is cheap to recompute.
const GEOIP_CACHE = new Map();

function geoipLookup(ip) {
  // Try city DB first (has country + city), fall back to country, then ASN
  const result = { ip, country: null, city: null, asn: null, org: null };
  try {
    const city = mmdbLookup(GEOIP_CITY_DB, ip);
    if (city) {
      result.country = city.country?.iso_code || city.registered_country?.iso_code || null;
      result.city    = city.city?.names?.en || null;
    } else {
      const country = mmdbLookup(GEOIP_COUNTRY_DB, ip);
      if (country) result.country = country.country?.iso_code || null;
    }
  } catch {}
  try {
    const asn = mmdbLookup(GEOIP_ASN_DB, ip);
    if (asn) {
      result.asn = asn.autonomous_system_number ? `AS${asn.autonomous_system_number}` : null;
      result.org = asn.autonomous_system_organization || null;
    }
  } catch {}
  return (result.country || result.asn) ? result : null;
}

/** Index of a byte sequence in a buffer, searching backwards from the end. */
function bufIndexOf(buf, needle) {
  for (let i = buf.length - needle.length; i >= 0; i--) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (buf[i + j] !== needle[j]) { match = false; break; }
    }
    if (match) return i;
  }
  return -1;
}

/**
 * One record of a search-tree node. `bit` selects the left (0) or right (1)
 * branch. Record sizes other than 24, 28 and 32 bits do not occur in practice.
 */
function readNode(buf, node, nodeSize, recordSize, bit) {
  const offset = node * nodeSize;
  if (offset + nodeSize > buf.length) return null;
  if (recordSize === 24) {
    return bit === 0
      ? (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
      : (buf[offset + 3] << 16) | (buf[offset + 4] << 8) | buf[offset + 5];
  }
  if (recordSize === 28) {
    return bit === 0
      ? ((buf[offset + 3] & 0xf0) << 20) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
      : ((buf[offset + 3] & 0x0f) << 24) | (buf[offset + 4] << 16) | (buf[offset + 5] << 8) | buf[offset + 6];
  }
  if (recordSize === 32) {
    return bit === 0 ? buf.readUInt32BE(offset) : buf.readUInt32BE(offset + 4);
  }
  return null;
}

// Fix (audit findings ANA-03 / MISC-02): mmdbLookup() used to
// fs.readFileSync(dbPath) AND redo the metadata-marker byte scan AND
// recompute node_count/record_size/dataStart from scratch on EVERY call
// that missed geoipCached()'s per-IP cache — ~35-75ms of synchronous work
// PER NEW IP for a 60 MB City database, on this process's single event
// loop. A tail of 500 log lines with many distinct IPs could block the
// dashboard for 10+ seconds, and the analyzer sharing this same reader
// could stop responding to the dashboard entirely during a scan burst.
// DB_CACHE keeps the parsed buffer and header fields per path, invalidated
// only when the file's mtime or size changes (a cheap fs.statSync(), not a
// re-read of the whole buffer) — the database itself only changes when an
// operator/geoipupdate replaces it.
const MMDB_MARKER = Buffer.from([0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d]);
const DB_CACHE = new Map(); // dbPath -> { mtimeMs, size, buf, meta, nodeCount, recordSize, nodeSize, dataStart }

function loadDb(dbPath) {
  let stat;
  try { stat = fs.statSync(dbPath); } catch { DB_CACHE.delete(dbPath); return null; }
  const cached = DB_CACHE.get(dbPath);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached;

  let buf;
  try { buf = fs.readFileSync(dbPath); } catch { return null; }
  const markerPos = bufIndexOf(buf, MMDB_MARKER);
  if (markerPos < 0) return null;
  const meta = decodeMmdbNode(buf, markerPos + MMDB_MARKER.length, buf.length);
  const nodeCount  = meta.node_count  || 0;
  const recordSize = meta.record_size || 28;
  const nodeSize   = Math.ceil(recordSize * 2 / 8);
  const dataStart  = nodeCount * nodeSize + 16; // 16 byte separator

  const entry = { mtimeMs: stat.mtimeMs, size: stat.size, buf, meta, nodeCount, recordSize, nodeSize, dataStart };
  DB_CACHE.set(dbPath, entry);
  return entry;
}

/** Minimal MMDB binary reader — supports IPv4 lookups in MaxMind DB format */
/**
 * Address bytes to search the tree with, plus how many bits of it to walk.
 *
 * Fix (audit report, Basse/Analyzer, "IPv6 jamais géolocalisé", ported from
 * nginx-analyzer/lib/geoip.js): this used to hard-code
 * `ip.split('.').map(Number)` and a fixed 32-bit walk — any address
 * containing a ':' failed that split immediately and returned null before
 * the tree was ever touched, so an IPv6 visitor was silently never
 * geolocated at all, in a database (GeoLite2 City/Country/ASN) that is
 * itself dual-stack and perfectly able to answer that lookup. A genuine
 * IPv6 address now walks the full 128 bits; an IPv4-mapped IPv6 address
 * (`::ffff:a.b.c.d`) is unwrapped to its 4 embedded bytes first, since that
 * is the same address as `a.b.c.d` and should return the same result
 * either way.
 */
function addressBits(ip) {
  const v4 = ip.split('.').map(Number);
  if (v4.length === 4 && v4.every(p => Number.isInteger(p) && p >= 0 && p <= 255)) {
    return { bytes: v4, bitLength: 32 };
  }
  const v6 = ipv6ToBytes(ip);
  if (!v6) return null;
  const mapped = mappedV4Bytes(v6);
  if (mapped) return { bytes: [...mapped], bitLength: 32 };
  return { bytes: v6, bitLength: 128 };
}

function mmdbLookup(dbPath, ip) {
  try {
    const db = loadDb(dbPath);
    if (!db) return null;
    const { buf, meta, nodeCount, recordSize, nodeSize, dataStart } = db;

    const addr = addressBits(ip);
    if (!addr) return null;
    const { bytes, bitLength } = addr;

    // Traverse the tree.
    //
    // In an IPv6 database, IPv4 addresses live under ::/96. Reaching that
    // subtree means walking 96 zero bits from the root, not jumping to "node
    // 96" — the node index and the bit depth are unrelated, and the shortcut
    // landed in the middle of the tree, which is why every lookup returned
    // nothing.
    let node = 0;
    if (meta.ip_version === 6 && bitLength === 32) {
      for (let i = 0; i < 96 && node < nodeCount; i++) {
        node = readNode(buf, node, nodeSize, recordSize, 0);
      }
      if (node >= nodeCount) return null;
    } else if (meta.ip_version === 4 && bitLength === 128) {
      // A real (non-mapped) IPv6 address has no meaning in an IPv4-only
      // database — nothing to walk towards.
      return null;
    }

    for (let i = 0; i < bitLength; i++) {
      const bit = (bytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
      node = readNode(buf, node, nodeSize, recordSize, bit);
      if (node === null) return null;
      if (node >= nodeCount) break;
    }
    if (node <= nodeCount) return null;
    const dataOffset = dataStart + (node - nodeCount - 16);
    if (dataOffset >= buf.length) return null;
    return decodeMmdbData(buf, dataOffset, dataStart);
  } catch { return null; }
}

function decodeMmdbNode(buf, start, end) {
  // Decode metadata as map
  const [val] = decodeMmdbValue(buf, start, start);
  return val || {};
}

function decodeMmdbData(buf, pos, dataStart) {
  const [val] = decodeMmdbValue(buf, pos, dataStart);
  return val;
}

function decodeMmdbValue(buf, pos, dataStart) {
  if (pos >= buf.length) return [null, pos];
  const ctrl = buf[pos]; pos++;
  let type = (ctrl >> 5) & 0x7;
  let size = ctrl & 0x1f;
  if (type === 0) { type = buf[pos] + 7; pos++; }
  if (size === 29)      { size = buf[pos++] + 29; }
  else if (size === 30) { size = ((buf[pos] << 8) | buf[pos+1]) + 285; pos += 2; }
  else if (size === 31) { size = ((buf[pos] << 16) | (buf[pos+1] << 8) | buf[pos+2]) + 65821; pos += 3; }

  switch (type) {
    case 1: { // pointer
      const psize = (size >> 3) & 0x3;
      let ptr = size & 0x7;
      if (psize === 0)      { ptr = (ptr << 8)  | buf[pos++]; }
      else if (psize === 1) { ptr = (ptr << 16) | (buf[pos] << 8) | buf[pos+1]; ptr += 2048; pos += 2; }
      else if (psize === 2) { ptr = (ptr << 24) | (buf[pos] << 16) | (buf[pos+1] << 8) | buf[pos+2]; ptr += 526336; pos += 3; }
      const [v] = decodeMmdbValue(buf, dataStart + ptr, dataStart);
      return [v, pos];
    }
    case 2: return [buf.slice(pos, pos+size).toString('utf8'), pos+size];  // utf8
    case 5: { // uint16
      let v = 0; for (let i=0;i<size;i++) v = (v<<8)|buf[pos+i];
      return [v, pos+size];
    }
    case 6: { // uint32
      let v = 0; for (let i=0;i<size;i++) v = (v<<8)|buf[pos+i];
      return [v, pos+size];
    }
    case 7: { // map
      const obj = {}; let p = pos;
      for (let i=0;i<size;i++) {
        const [k, p2] = decodeMmdbValue(buf, p, dataStart); p = p2;
        const [v, p3] = decodeMmdbValue(buf, p, dataStart); p = p3;
        if (typeof k === 'string') obj[k] = v;
      }
      return [obj, p];
    }
    case 8: { // int32
      let v = 0; for (let i=0;i<size;i++) v = (v<<8)|buf[pos+i];
      if (v & 0x80000000) v = -(~v + 1);
      return [v, pos+size];
    }
    case 9: { // uint64 — return as number (precision loss OK for ASN)
      let v = 0; for (let i=0;i<size;i++) v = (v*256)+buf[pos+i];
      return [v, pos+size];
    }
    case 11: { // array
      const arr = []; let p = pos;
      for (let i=0;i<size;i++) { const [v,p2] = decodeMmdbValue(buf,p,dataStart); arr.push(v); p=p2; }
      return [arr, p];
    }
    case 14: return [true,  pos];  // bool true
    case 15: return [false, pos];  // bool false
    default: return [null, pos+size];
  }
}

function geoipCached(ip) {
  if (GEOIP_CACHE.has(ip)) return GEOIP_CACHE.get(ip);
  const result = geoipLookup(ip);
  if (GEOIP_CACHE.size > 20000) { // eviction: clear oldest half (fix ANA-03/MISC-02: raised from 2000 now that a cache miss is cheap, not a full mmdb re-read)
    const keys = [...GEOIP_CACHE.keys()].slice(0, 1000);
    keys.forEach(k => GEOIP_CACHE.delete(k));
  }
  GEOIP_CACHE.set(ip, result);
  return result;
}

module.exports = { geoipLookup, geoipCached, mmdbLookup,
                   GEOIP_CITY_DB, GEOIP_COUNTRY_DB, GEOIP_ASN_DB };
