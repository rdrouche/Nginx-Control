'use strict';
/**
 * Access log parsing.
 *
 * Two formats coexist in a typical setup, sometimes on the same server:
 *
 *   combined        127.0.0.1 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1234 "-" "curl/8"
 *   combined_vhost  example.com 127.0.0.1 - - [09/Sep/2026:...] "GET / HTTP/1.1" 200 1234 "-" "curl/8"
 *
 * The only difference is a leading hostname. Rather than guessing per line —
 * which breaks the moment a hostname looks like an IP — the format is detected
 * once per file from a sample and then applied consistently.
 *
 * A line that does not parse is dropped rather than throwing: a truncated write
 * at the tail of a rotating file is normal, not an error.
 */

// Fix (audit report, Basse/Analyzer, "parse.js:19, 22"): the request field
// used to be matched as `([A-Z_]+)\s+(\S+)[^"]*` unconditionally, which
// requires an actual HTTP method — but nginx logs a bare `$request` of `-`
// for exactly the traffic this analyzer exists to catch: a raw TLS/SSH/binary
// probe against a plain HTTP listener, or any connection that never sends a
// parseable request line at all. That case failed the whole line's regex,
// so it was silently dropped rather than counted or scored by any rule —
// scan traffic the tool is meant to surface was invisible before it even
// reached the detector. The request field now has an explicit `-` branch
// (named group `dash`); method/path are null in that case, and
// `parseLine`/`vhostFromFilename` callers can still distinguish it from a
// genuine request. Also switched to named capture groups: the two formats
// used to line up on plain numbered groups only by accident (one field
// apart), which is exactly the kind of thing a future edit could silently
// break.
const REQUEST_FIELD = '"(?:(?<method>[A-Z_]+)\\s+(?<path>\\S+)[^"]*|(?<dash>-))"';

// vhost ip - user [time] "method path proto" status bytes "referer" "ua"
// The leading vhost token is ordinary \S+ in the normal case, but nginx
// prints a literal "-" when the variable behind it ($host/$server_name) is
// empty (no SNI, no Host header, no matching server block) — previously
// indistinguishable from a real one-character vhost named "-", and treated
// as a legitimate (if odd) hostname instead of "no vhost matched".
const RE_VHOST = new RegExp(
  '^(?<vhost>\\S+)\\s+(?<ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[(?<time>[^\\]]+)\\]\\s+' +
  REQUEST_FIELD +
  '\\s+(?<status>\\d{3})\\s+(?<bytes>\\d+|-)\\s+"(?<referer>[^"]*)"\\s+"(?<ua>[^"]*)"'
);

// ip - user [time] "method path proto" status bytes "referer" "ua"
const RE_COMBINED = new RegExp(
  '^(?<ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[(?<time>[^\\]]+)\\]\\s+' +
  REQUEST_FIELD +
  '\\s+(?<status>\\d{3})\\s+(?<bytes>\\d+|-)\\s+"(?<referer>[^"]*)"\\s+"(?<ua>[^"]*)"'
);

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/**
 * Parse an nginx timestamp: 09/Sep/2026:10:00:00 +0200
 * Returns epoch milliseconds, or null when unparseable.
 */
function parseTime(s) {
  const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/.exec(s);
  if (!m) return null;
  const month = MONTHS[m[2]];
  if (month === undefined) return null;
  const utc = Date.UTC(+m[3], month, +m[1], +m[4], +m[5], +m[6]);
  if (!m[7]) return utc;
  // Offset is the log's local zone: subtract it to get real UTC.
  const sign = m[7][0] === '-' ? 1 : -1;
  const offsetMin = (+m[7].slice(1, 3)) * 60 + (+m[7].slice(3, 5));
  return utc + sign * offsetMin * 60_000;
}

const looksLikeIp = s =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s));

/**
 * Detect the format of a log file from sample lines.
 * Returns 'vhost' or 'combined'. Falls back to 'combined', the nginx default.
 */
function detectFormat(sampleLines) {
  let vhost = 0, combined = 0;
  for (const line of sampleLines) {
    if (!line.trim()) continue;
    const first = line.split(/\s+/)[0];
    // A leading token that is not an IP and carries a dot (or is the "no
    // vhost matched" placeholder "-") is a hostname field, not an IP.
    if ((first === '-' || (!looksLikeIp(first) && first.includes('.'))) && RE_VHOST.test(line)) vhost++;
    else if (RE_COMBINED.test(line)) combined++;
  }
  return vhost > combined ? 'vhost' : 'combined';
}

/**
 * Parse one line in a known format.
 * Returns null on anything unrecognised — a partial write is expected at the
 * tail of a file being rotated. A request logged as a bare "-" (no method,
 * no path — see RE_VHOST/RE_COMBINED's comment) still parses successfully:
 * method and path are both null, so callers can recognise and count this
 * traffic instead of it vanishing before ever reaching the detector.
 */
function parseLine(line, format, defaultVhost = '') {
  if (!line || line.length < 20) return null;

  const re = format === 'vhost' ? RE_VHOST : RE_COMBINED;
  const m = re.exec(line);
  if (!m) return null;
  const g = m.groups;
  const ts = parseTime(g.time);
  if (ts === null) return null;

  const vhostField = format === 'vhost' ? (g.vhost === '-' ? defaultVhost : g.vhost) : defaultVhost;

  return {
    vhost:   vhostField,
    ip:      g.ip,
    user:    g.user === '-' ? null : g.user,
    ts,
    // `dash` set (request was a bare "-") -> no method/path was ever sent.
    method:  g.dash ? null : g.method,
    path:    g.dash ? null : g.path,
    status:  +g.status,
    bytes:   g.bytes === '-' ? 0 : +g.bytes,
    referer: g.referer === '-' ? null : g.referer,
    ua:      g.ua === '-' ? null : g.ua,
  };
}

/**
 * Vhost name inferred from a log filename: "example.com.access.log" →
 * "example.com". Used for combined-format files, which carry no hostname.
 */
function vhostFromFilename(filename) {
  return filename
    .replace(/\.(access|error)\.log(\.\d+)?(\.gz)?$/, '')
    .replace(/\.log$/, '');
}

/** Strip the query string — paths are grouped by their stable part. */
function normalizePath(p) {
  const i = p.indexOf('?');
  return i === -1 ? p : p.slice(0, i);
}

module.exports = {
  parseLine, parseTime, detectFormat, vhostFromFilename, normalizePath,
  RE_VHOST, RE_COMBINED,
};
