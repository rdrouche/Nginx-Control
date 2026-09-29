'use strict';
/**
 * Minimal YAML subset for config/docker-autoconfig.yml.
 *
 * Same restricted shape and rationale as lib/blocklist-yaml.js and
 * lib/deploy-tokens.js (zero-npm-dependency project): flat top-level scalar
 * settings, plus one list of bare strings for the allowlist patterns.
 *
 *   enable: true
 *   require_approval: true
 *   poll_interval_sec: 15
 *   allowed_server_name_patterns:
 *     - "*.example.com"
 *     - "app.internal"
 *
 * A line is either a comment (`#...`), blank, a top-level `key: value` pair
 * (0-indent), the `allowed_server_name_patterns:` list marker, or a list item
 * (`  - value`, two-space indent). Anything else is a syntax error, reported
 * with its line number — same convention as the other minimal YAML parsers
 * in this project.
 */

function parseScalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return null;
  if (v.toLowerCase() === 'true') return true;
  if (v.toLowerCase() === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

function parseDockerAutoconfigYaml(text) {
  const errors = [];
  const config = {};
  const patterns = [];
  let inPatternsList = false;
  const lines = String(text || '').split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw.trim() || raw.trim().startsWith('#')) continue;

    if (/^allowed_server_name_patterns\s*:\s*$/.test(raw)) { inPatternsList = true; continue; }

    const itemMatch = raw.match(/^  - (.+)$/);
    if (inPatternsList && itemMatch) {
      const v = parseScalar(itemMatch[1]);
      if (typeof v === 'string' && v) patterns.push(v);
      continue;
    }

    const topMatch = raw.match(/^([A-Za-z_]+)\s*:\s*(.*)$/);
    if (!inPatternsList && topMatch) {
      config[topMatch[1]] = parseScalar(topMatch[2]);
      continue;
    }

    // A stray 0-indent line closes the patterns list, same rule as the
    // other minimal parsers — but it must itself look like a valid top key.
    if (inPatternsList && topMatch) {
      inPatternsList = false;
      config[topMatch[1]] = parseScalar(topMatch[2]);
      continue;
    }

    errors.push(`Ligne ${lineNo} : syntaxe non reconnue — "${raw.trim()}"`);
  }
  return { config, patterns, errors };
}

/**
 * Simple glob matcher for `allowed_server_name_patterns`: `*` matches any
 * run of characters (including none), everything else is literal. Deliberately
 * not a full glob/regex engine — a domain pattern only ever needs this one
 * wildcard (e.g. "*.example.com"), and anything richer would just widen the
 * ways an operator could accidentally write an overly-permissive pattern.
 */
function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function matchesAnyPattern(serverName, patterns) {
  return (patterns || []).some(p => {
    try { return globToRegExp(p).test(serverName); } catch { return false; }
  });
}

/**
 * Parse + validate in one pass, normalizing defaults. `require_approval`
 * defaults to `true` — a deliberate secure-by-default choice (see the design
 * doc): an unrecognized server_name never gets applied silently just because
 * the operator never wrote this file at all.
 *
 * `enable` defaults to `false` (retour utilisateur v12.41.0) — auto-config
 * Docker watches the Docker socket and can turn a container's own labels
 * into a live vhost; an operator who never wrote this file, or who wrote it
 * without an explicit `enable: true`, should not get that behavior for free.
 * Opt-in, not opt-out (this reverses the previous default; existing
 * deployments that rely on the feature must add `enable: true` explicitly).
 */
function parseAndValidate(text) {
  const { config, patterns, errors } = parseDockerAutoconfigYaml(text);
  const settings = {
    enable: config.enable === true,
    requireApproval: config.require_approval !== false,
    pollIntervalSec: Number.isFinite(config.poll_interval_sec) && config.poll_interval_sec >= 5
      ? config.poll_interval_sec : 15,
    // Reactive detection (Docker Events) — on by default, poll_interval_sec
    // remains the safety net in case an event is ever missed (daemon
    // restart mid-stream, socket hiccup). events_debounce_ms bounds how long
    // a burst of container starts/stops is allowed to settle before one
    // combined cycle runs, so `docker compose up` on a ten-service stack
    // never triggers ten reloads back to back.
    eventsEnable: config.events_enable !== false,
    eventsDebounceMs: Number.isFinite(config.events_debounce_ms) && config.events_debounce_ms >= 500
      ? config.events_debounce_ms : 3000,
    // Backoff before RE-attempting a certbot_http/certbot_dns issuance after
    // a failure (bad DNS record, rate-limited by Let's Encrypt, credentials
    // missing...). Never retried every cycle (poll_interval_sec, or every
    // Docker event) — that would hammer the ACME server and burn through
    // Let's Encrypt's own rate limits within minutes. A fresh attempt (no
    // prior failure recorded yet) is never delayed by this value.
    certbotRetryMinutes: Number.isFinite(config.certbot_retry_minutes) && config.certbot_retry_minutes >= 1
      ? config.certbot_retry_minutes : 15,
    allowedServerNamePatterns: patterns,
  };
  return { settings, errors };
}

module.exports = { parseDockerAutoconfigYaml, parseAndValidate, matchesAnyPattern, globToRegExp };
