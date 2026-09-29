'use strict';
/**
 * Blocklist-hits log parsing ("Method 1" — dedicated global log, see
 * nginx-dashboard's config/blocklists.yml `hit_logging` section).
 *
 * Unlike the per-vhost access log or the per-vhost WAF log, this is a SINGLE
 * GLOBAL file: nginx-dashboard generates one `access_log ... if=$blocklist_ip;`
 * directive, shared by every vhost that includes blocklist-enforce.conf, so
 * the vhost identity for each hit comes from a FIELD inside the line ($host),
 * never from the filename — vhostFromFilename() below is a fixed constant,
 * not a per-file suffix strip, for exactly that reason.
 *
 * The line format is fixed by nginx-dashboard's own generated log_format
 * directive (see its blocklist-hitlog-format.conf) and never varies by
 * deployment, so — mirroring lib/parse-waf.js's detectFormat() — there is
 * nothing to actually detect:
 *
 *   $time_iso8601 $remote_addr $host "$request" $status
 *
 * Example line:
 *   2026-09-24T10:15:03+00:00 203.0.113.5 example.com "GET /wp-login.php HTTP/1.1" 403
 *
 * As with every parser in this project, a line that does not match this
 * shape is dropped (returns null) rather than thrown on — a partial write at
 * the tail of a rotating file is normal, not an error.
 */

const LINE_RE = /^(\S+) (\S+) (\S+) "([^"]*)" (\d{3})\s*$/;

/** Always 'blocklist' — see the module header: exactly one fixed format. */
function detectFormat() { return 'blocklist'; }

/**
 * The hits log is one global file, not per-vhost, so there is no vhost to
 * recover from its name — the caller passes the file's basename through
 * unchanged and each parsed line's own `vhost` field (from $host) is what
 * actually identifies the site.
 */
function vhostFromFilename() { return null; }

/**
 * Parse one line of the dedicated blocklist-hits log.
 * Returns null on anything unparseable — never throws.
 */
function parseLine(line, format, defaultVhost = '') {
  if (!line || line.length < 10) return null;
  const m = LINE_RE.exec(line.trim());
  if (!m) return null;

  const ts = Date.parse(m[1]);
  if (Number.isNaN(ts)) return null;

  const [, , ip, host, request, statusStr] = m;
  const reqParts = request.split(' ');

  return {
    ts,
    ip: ip || null,
    vhost: (host && host !== '-') ? host : (defaultVhost || null),
    method: reqParts.length >= 2 ? reqParts[0] : null,
    uri:    reqParts.length >= 2 ? reqParts[1] : null,
    status: +statusStr,
  };
}

module.exports = { detectFormat, parseLine, vhostFromFilename };
