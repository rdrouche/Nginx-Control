'use strict';
/**
 * Turns raw blocklist text (fetched from a third-party URL) into a list of
 * IPv4/IPv6 addresses or CIDR blocks — and nothing else.
 *
 * This is the security boundary of the whole feature: every line comes from
 * a source the operator does not control the content of (a public URL can
 * change owner, get compromised, or simply contain garbage), and the output
 * of this module is written verbatim into an nginx config file that gets
 * `include`d and reloaded. A single unvalidated line — one containing `;`,
 * `{`, `}`, a newline, or nginx directive text — would be config injection
 * into a live reverse proxy.
 *
 * The defense is a strict, fully-anchored regex per line: after comments and
 * whitespace are stripped, the ENTIRE remaining line must match one of the
 * two patterns below, start to end. There is no partial extraction (e.g. "take
 * the first token") — a line with anything trailing after a valid-looking IP
 * fails the anchor and is dropped, not truncated and half-accepted. Only
 * digits, dots, colons, hex letters and a leading `/`+digits can ever survive
 * this filter, which makes the characters an injection needs (`;{}"'` and
 * whitespace) structurally impossible to pass through.
 */

// IPv4, optionally with a /0-32 CIDR suffix.
const IPV4_RE = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/(3[0-2]|[12]?[0-9]))?$/;

// IPv6, optionally with a /0-128 CIDR suffix. Best-effort (accepts the
// common forms including "::" compression); a real address that this misses
// is simply dropped — safe by construction, since the failure mode of this
// module is "skip the line", never "pass it through unchecked".
const IPV6_RE = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))(\/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))?$/;

/** True if `s` is exactly (start to end) a valid IPv4/IPv6 address or CIDR block. */
function isValidIpOrCidr(s) {
  return IPV4_RE.test(s) || IPV6_RE.test(s);
}

/**
 * Parse one blocklist file's text into { valid: string[], invalidCount,
 * totalLines }. `valid` holds only lines that passed isValidIpOrCidr() —
 * anything else (comments, headers, empty lines, garbage) is counted in
 * `invalidCount` and dropped, never surfaced verbatim.
 */
function parseIpLines(text) {
  const lines = String(text || '').split(/\r?\n/);
  const valid = [];
  let invalidCount = 0;
  let totalLines = 0;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue; // blank lines don't count as "invalid" — just noise
    // A full-line comment is expected file structure (headers, section
    // dividers), not a data line that failed to parse — it doesn't count
    // toward totalLines/invalidCount, which describe the actual IP data.
    if (line.startsWith('#') || line.startsWith(';')) continue;
    totalLines++;
    // Strip a trailing inline comment ("1.2.3.4 # some note") — only when
    // preceded by whitespace, since a valid IP/CIDR never contains "#" or
    // ";" itself, so there is no ambiguity, and a marker glued directly to
    // the token (no space) is left alone: the whole line then either
    // validates as-is or is rejected, rather than an attempt to "rescue" a
    // fragment out of what may be a corrupted or hostile line.
    const withoutInlineComment = line.split(/\s+[#;]/)[0].trim();
    if (isValidIpOrCidr(withoutInlineComment)) {
      valid.push(withoutInlineComment);
    } else {
      invalidCount++;
    }
  }
  return { valid, invalidCount, totalLines };
}

module.exports = { isValidIpOrCidr, parseIpLines, IPV4_RE, IPV6_RE };
