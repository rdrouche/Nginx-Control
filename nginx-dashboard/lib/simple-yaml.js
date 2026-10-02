'use strict';
/**
 * Shared helpers for the "flat key: value per line" YAML subset used by
 * several of this project's config files (godns.yml, geoipupdate.yml,
 * goaccess.yml, crowdsec.yml, and lib/notify.js's smtp/notifications/
 * scheduler.yml). Not a general YAML parser — just the handful of primitives
 * that were previously copy-pasted, near-identically, into each loader.
 *
 * Fix (audit finding MISC-10): every one of those loaders matched a line
 * with `/^([a-z_]+)\s*:\s*(.*)$/` and used the captured value as-is. None of
 * them stripped a trailing inline comment first, so `enable: false  # pause`
 * parsed as the literal string `"false  # pause"` — which is truthy for the
 * `=== 'true'` checks these loaders use, and non-empty for anything read as
 * a plain string. A config meant to disable a feature (or override a URL,
 * cron, etc.) with an explanatory comment on the same line silently did the
 * opposite, or picked up the comment as part of the value. `lib/notify.js`
 * already carried a correct `stripInlineComment()` for this exact case
 * (found and fixed there first); this module is that fix, extracted so
 * every flat-YAML loader in the project shares it instead of re-deriving
 * (or forgetting) it.
 */

/**
 * Strip a trailing inline comment from a raw YAML value. A quoted value's
 * comment starts after its OWN closing quote — the value itself may contain
 * a `#` and must not be truncated at it. An unquoted value's comment starts
 * at a `#` preceded by whitespace.
 */
function stripInlineComment(rawVal) {
  const s = String(rawVal ?? '').trim();
  if (s[0] === '"' || s[0] === "'") {
    const q = s[0];
    const closeIdx = s.indexOf(q, 1);
    if (closeIdx !== -1) return s.slice(0, closeIdx + 1);
    return s; // no closing quote found — leave as-is rather than guess
  }
  const hashIdx = s.search(/\s#/);
  return hashIdx === -1 ? s : s.slice(0, hashIdx).trimEnd();
}

/** Convert a scalar the same way at every call site. */
function coerceYmlValue(v) {
  if (v === 'true')  return true;
  if (v === 'false') return false;
  if (v !== '' && !isNaN(v)) return Number(v);
  return v;
}

/**
 * Parse a flat `key: value` per line YAML subset (no nesting, no lists) into
 * a plain object of trimmed, comment-stripped, unquoted string values.
 * Blank lines, whole-line comments, and lines that don't match `key: value`
 * are ignored. This is the shape godns.yml, geoipupdate.yml, goaccess.yml
 * and crowdsec.yml all use.
 */
function parseFlatYaml(raw) {
  const result = {};
  String(raw || '').replace(/\r/g, '').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const m = trimmed.match(/^([a-z_]+)\s*:\s*(.*)$/);
    if (!m) return;
    result[m[1]] = stripInlineComment(m[2]).replace(/^["']|["']$/g, '');
  });
  return result;
}

module.exports = { stripInlineComment, coerceYmlValue, parseFlatYaml };
