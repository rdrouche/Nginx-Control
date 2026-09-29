'use strict';
/**
 * Blocklists IP — periodic aggregation of one or more external IP blocklists
 * into a single nginx `geo` snippet, deduplicated and validated, applied via
 * a small enforcement snippet the operator includes in whichever vhosts they
 * want protected.
 *
 * Three safety properties this module exists to guarantee, in order of how
 * often they matter:
 *
 * 1. A third-party list must never be able to inject nginx config. Every
 *    line is validated by lib/blocklist-parse.js's fully-anchored regex
 *    before it is ever written to disk — see that file's header for why this
 *    makes injection structurally impossible, not just unlikely.
 * 2. A source that fails to fetch (network blip, 404, timeout) must never
 *    make its previously-known IPs disappear from the live snippet. The last
 *    successful fetch per source is cached (lib/events.js's generic
 *    getState/setState, same mechanism other features already use for
 *    exactly this kind of small persisted state) and reused until the next
 *    success.
 * 3. Nginx must never be reloaded onto a config that fails `nginx -t`. The
 *    previous snippet content is kept in memory before every overwrite and
 *    restored immediately if the test fails — see applySnippets() below.
 *    And the very first time the feature runs (no cache yet, nothing fetched
 *    yet), a minimal-but-valid empty snippet is written synchronously at
 *    server boot, before any scheduled fetch or vhost reload can race a
 *    missing `include` file — see ensureSnippetsAtBoot().
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const notify  = require('../lib/notify');
const events  = require('../lib/events');
const { pushNotification } = require('../lib/notifications');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { fetchBlocklistText } = require('../lib/blocklist-fetch');
const { parseIpLines } = require('../lib/blocklist-parse');
const { ipInCidr, isValidPattern, toBytes, parseCidr, containsParsed } = require('../lib/cidr');
const { withLock } = require('../lib/nginx-write-lock');

const { DIR_CONF, DIR_SNIPPETS, BLOCKLIST_CONFIG_FILE } = cfg;
const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { sendNotification } = notify;
const { logEvent } = events;

// blocklist-ips.conf holds the `geo{}` table: it must load exactly once, at
// http{} context. It lives in DIR_CONF (conf/), not DIR_SNIPPETS, because
// nginx.conf already does `include conf.d/*.conf;` inside http{} — dropping
// it there makes it load automatically the moment the feature is enabled,
// with no manual `include` line for the operator to remember. snippets/ is
// never auto-included anywhere; it only exists to be pulled into a vhost
// deliberately (`include .../<name>.conf;` inside a server{}), which is
// exactly what blocklist-enforce.conf needs.
const GEO_FILE     = path.join(DIR_CONF, 'blocklist-ips.conf');
const ENFORCE_FILE = path.join(DIR_SNIPPETS, 'blocklist-enforce.conf');
// The `log_format` directive for the dedicated hit log ("Methode 1") must
// live at http context exactly like blocklist-ips.conf's `geo{}` table, for
// the same reason: DIR_CONF is auto-loaded once via nginx.conf's
// `include conf.d/*.conf;`, DIR_SNIPPETS is not. Generated unconditionally
// (even when hit_logging is disabled) so toggling the setting on never races
// a missing `log_format` the moment the enforce snippet starts referencing
// it — see ensureSnippetsAtBoot().
const HITLOG_FORMAT_FILE = path.join(DIR_CONF, 'blocklist-hitlog-format.conf');
// Fixed path + name nginx-analyzer's BLOCKLIST_LOG_PATTERN expects by
// default (`^blocklist-hits\.log$`) — one single global file, not per-vhost,
// because $blocklist_ip can fire from any vhost that includes
// blocklist-enforce.conf. Keeping the name fixed (not operator-configurable)
// is what lets nginx-control and the analyzer "just work" without either
// side needing to learn the other's setting — see config/blocklists.yml's
// hit_logging_* comment.
//
// The DIRECTORY here is deliberately the hardcoded `/var/log/nginx` — the
// path as the NGINX CONTAINER itself sees its own log directory (see
// logging.conf's own convention and features/vhost-generator.js's default
// access_log, which both hardcode this same path) — never `DIR_LOGS`
// (`/nginx/logs` by default), which is only the DASHBOARD's own read-only
// mount of that same host folder, at a different container path. This was a
// real bug: the reference docker-compose.yml gives the nginx container no
// `/nginx/logs` mount at all, only `/var/log/nginx`, so as soon as
// `hit_logging_enable` was turned on, nginx -t failed on every subsequent
// blocklist refresh (auto or manual) — "nginx exited with code 1" — because
// it could not open an access_log file in a directory that does not exist
// inside its own container. The analyzer and the dashboard both still find
// the file fine afterwards: they read it by scanning their own mount of the
// same host directory for its filename, never by trusting this path.
const HIT_LOG_FILE = '/var/log/nginx/blocklist-hits.log';
const CACHE_KEY     = 'blocklist_cache'; // events.js generic state table

// All three are generated/overwritten by this feature, never by the
// operator or by Git. features/deploy.js's Git-driven full sync otherwise
// mirrors conf/ and snippets/ against the repository (deleting anything not
// tracked there) — these must survive that unrelated to whether they happen
// to be committed. Exposed for server.js to wire into features/deploy.js via
// setDeps(), same composition-root pattern already used for every other
// cross-feature dependency in this project.
const GENERATED_FILES = [GEO_FILE, ENFORCE_FILE, HITLOG_FORMAT_FILE];

// ─── Config ────────────────────────────────────────────────────────────────
function loadConfig() {
  let text = '';
  try { text = fs.readFileSync(BLOCKLIST_CONFIG_FILE, 'utf8'); } catch { /* missing = disabled, defaults apply */ }
  return { text, ...parseAndValidate(text) };
}

function loadCache() {
  return events.getState(CACHE_KEY) || { sources: {} };
}

function saveCache(cache) {
  events.setState(CACHE_KEY, cache);
}

// ─── Snippet generation ──────────────────────────────────────────────────────
/**
 * Every IP written here has already passed lib/blocklist-parse.js's anchored
 * regex — see that file's header. Sorting only makes the output stable
 * (deterministic diffs, and lets us skip a write+reload when nothing
 * actually changed), it is not part of the safety property.
 */
function buildGeoSnippet(mergedIps, sourceSummaries) {
  const lines = [
    '# name: blocklist-ips',
    '# description: Table geo des IP bloquees, agregee automatiquement par nginx-dashboard (voir config/blocklists.yml). Ne pas editer a la main : ecrasee a chaque rafraichissement.',
    '# emplacement: http',
    `# genere le: ${new Date().toISOString()}`,
    sourceSummaries.length
      ? `# sources: ${sourceSummaries.join(', ')} — total deduplique: ${mergedIps.length} IP`
      : '# sources: aucune (voir config/blocklists.yml)',
    '#',
    '# Charge automatiquement au niveau http (present dans conf/, deja inclus',
    '# par nginx.conf via `include conf.d/*.conf;`) — aucune action requise.',
    '# Pour activer le blocage sur un vhost, ajouter dans son bloc server{} :',
    '#   include snippets/blocklist-enforce.conf;',
    '',
    'geo $blocklist_ip {',
    '    default 0;',
  ];
  for (const ip of mergedIps) lines.push(`    ${ip} 1;`);
  lines.push('}', '');
  return lines.join('\n');
}

/**
 * The `log_format` directive backing hit_logging's "Methode 1" (dedicated
 * global log). Always generated, referenced only when the enforce snippet
 * below actually adds the matching `access_log` line — see HITLOG_FORMAT_FILE.
 */
function buildHitlogFormatSnippet() {
  return [
    '# name: blocklist-hitlog-format',
    '# description: Format de log dedie aux hits blocklist (voir hit_logging_* dans config/blocklists.yml). Reference par blocklist-enforce.conf quand la methode "dedicated" est active.',
    '# emplacement: http',
    `# genere le: ${new Date().toISOString()}`,
    '#',
    "log_format blocklist_hits '$time_iso8601 $remote_addr $host \"$request\" $status';",
    '',
  ].join('\n');
}

function buildEnforceSnippet(blockAction, hitLogging) {
  const code = blockAction === 'drop_444' ? '444' : '403';
  const dedicatedLogging = !!(hitLogging && hitLogging.enable && hitLogging.method === 'dedicated');
  const lines = [
    '# name: blocklist-enforce',
    '# description: Bloque les IP presentes dans $blocklist_ip (voir blocklist-ips.conf, inclus une seule fois au niveau http). A inclure dans chaque server{} a proteger.',
    '# emplacement: server, location',
    `# genere le: ${new Date().toISOString()}`,
    '#',
    'if ($blocklist_ip) {',
    `    return ${code};`,
    '}',
  ];
  if (dedicatedLogging) {
    // access_log's `if=` parameter makes this conditional on its own —
    // deliberately NOT nested inside the `if{}` block above, and deliberately
    // not touching the shared access_log/logging.conf snippet: one extra,
    // independent statement, sibling to the block above, referencing the
    // log_format declared once at http context in HITLOG_FORMAT_FILE.
    lines.push('', `access_log ${HIT_LOG_FILE} blocklist_hits if=$blocklist_ip;`);
  }
  lines.push('');
  return lines.join('\n');
}

/** Minimal, always-syntactically-valid placeholder — an empty geo table blocks nothing but never breaks `include`. */
function emptyGeoSnippet() {
  return buildGeoSnippet([], []);
}

function atomicWrite(filePath, content) {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, filePath); // same directory -> atomic on any real filesystem
}

/**
 * The very first thing this feature must guarantee, before any fetch, any
 * scheduler tick, or any vhost reload: the two snippet files exist and are
 * syntactically valid nginx, even with zero network access and an empty
 * cache. Without this, a vhost that already has `include
 * .../blocklist-enforce.conf;` would fail `nginx -t` on a fresh install
 * simply because the file doesn't exist yet — a background feature breaking
 * an unrelated vhost's config is exactly the class of regression the project
 * cannot ship.
 *
 * Idempotent and cheap: only writes when a file is actually missing, so it
 * is safe to call unconditionally on every boot.
 */
function ensureSnippetsAtBoot() {
  try {
    fs.mkdirSync(DIR_CONF, { recursive: true });
    fs.mkdirSync(DIR_SNIPPETS, { recursive: true });
    if (!fs.existsSync(GEO_FILE))           atomicWrite(GEO_FILE, emptyGeoSnippet());
    if (!fs.existsSync(HITLOG_FORMAT_FILE)) atomicWrite(HITLOG_FORMAT_FILE, buildHitlogFormatSnippet());
    if (!fs.existsSync(ENFORCE_FILE)) {
      const { settings } = loadConfig();
      atomicWrite(ENFORCE_FILE, buildEnforceSnippet(settings.blockAction, settings.hitLogging));
    }
  } catch (e) {
    console.error('[blocklists] ensureSnippetsAtBoot error:', e.message);
  }
}

// ─── Reload, with a test-first safety gate and rollback ──────────────────────
/**
 * Writes both snippets, tests the resulting config, and only reloads nginx
 * if the test passes. On failure the PREVIOUS content is restored before
 * returning, so a bad write never lingers as the live (untested) state for
 * the next reload — scheduled or manual — to pick up later.
 */
async function applySnippets(geoContent, enforceContent) {
  // Fix v12.21.2 (audit finding DAC-05): the whole write -> test -> reload
  // (and its rollback) now runs inside the mutex shared with
  // features/docker-autoconfig.js and features/agents.js — see
  // lib/nginx-write-lock.js's own header for why this must be a single
  // global lock, not one per feature.
  return withLock(async () => {
    const previousGeo     = fs.existsSync(GEO_FILE)     ? fs.readFileSync(GEO_FILE, 'utf8')     : null;
    const previousEnforce = fs.existsSync(ENFORCE_FILE) ? fs.readFileSync(ENFORCE_FILE, 'utf8') : null;

    atomicWrite(GEO_FILE, geoContent);
    atomicWrite(ENFORCE_FILE, enforceContent);

    try {
      await docker.execNginx('nginx -t');
    } catch (e) {
      // Roll back immediately — a failed test must never leave the broken
      // version as the file nginx will read on its next reload, scheduled or
      // manual, possibly hours from now.
      if (previousGeo !== null)     atomicWrite(GEO_FILE, previousGeo);
      if (previousEnforce !== null) atomicWrite(ENFORCE_FILE, previousEnforce);
      return { ok: false, reloaded: false, testFailed: true, error: e.error || e.message, stderr: e.stderr || e.stdout || '' };
    }

    try {
      await docker.execNginx('nginx -s reload');
      return { ok: true, reloaded: true };
    } catch (e) {
      return { ok: false, reloaded: false, testFailed: false, error: e.error || e.message, stderr: e.stderr || e.stdout || '' };
    }
  });
}

// ─── Refresh cycle ────────────────────────────────────────────────────────────
/**
 * Fetches every enabled source, merges with the cache, and applies the
 * result. `manual` only affects logging/notification wording — the safety
 * behavior (cache-on-failure, test-before-reload) is identical either way.
 */
async function refreshBlocklists({ manual = false, actor = 'scheduler' } = {}) {
  const { settings, valid: sources, errors: configErrors } = loadConfig();
  if (!settings.enable) return { skipped: true, reason: 'disabled' };
  if (!sources.length) return { skipped: true, reason: 'no-sources', configErrors };

  const cache = loadCache();
  cache.sources = cache.sources || {};
  const now = new Date().toISOString();
  const attempted = [];

  for (const source of sources) {
    if (!source.enable) continue;
    const prevEntry = cache.sources[source.name] || {};
    const result = await fetchBlocklistText(source.url);
    if (result.ok) {
      const { valid, invalidCount, totalLines } = parseIpLines(result.text);
      cache.sources[source.name] = {
        url: source.url, ips: valid, count: valid.length,
        invalidCount, totalLines,
        lastSuccessAt: now, lastAttemptAt: now, lastError: null,
      };
      attempted.push({ name: source.name, ok: true, count: valid.length });
    } else {
      cache.sources[source.name] = {
        ...prevEntry, url: source.url,
        lastAttemptAt: now, lastError: result.error,
      };
      attempted.push({ name: source.name, ok: false, error: result.error, cachedCount: prevEntry.count || 0 });
    }
  }

  // Merge only sources that are still configured+enabled — a source removed
  // from the config, or turned off, no longer contributes its cached IPs
  // even though the cache entry itself is left alone (re-enabling it later
  // reuses the cache instantly rather than waiting for the next fetch).
  const enabledNames = new Set(sources.filter(s => s.enable).map(s => s.name));
  const merged = new Set();
  const summaries = [];
  for (const name of enabledNames) {
    const entry = cache.sources[name];
    if (!entry || !Array.isArray(entry.ips)) continue;
    for (const ip of entry.ips) merged.add(ip);
    summaries.push(`${name} (${entry.ips.length} IP${entry.lastError ? ', en cache — derniere erreur: ' + entry.lastError : ''})`);
  }
  const mergedIps = Array.from(merged).sort();

  saveCache(cache);
  // Fire-and-forget: the analyzer's attribution/approx-detection catches up
  // to this cache within one push either way (see pushBlocklistSources()'s
  // own comment) — a refresh must never be slowed down or failed by the
  // analyzer being unreachable.
  pushBlocklistSources().catch(() => {});

  const anySuccessThisCycle = attempted.some(a => a.ok);
  const allFailedThisCycle  = attempted.length > 0 && attempted.every(a => !a.ok);
  const hadIpsBefore = fs.existsSync(GEO_FILE) && /\s1;\s*$/m.test(fs.readFileSync(GEO_FILE, 'utf8'));

  const geoContent     = buildGeoSnippet(mergedIps, summaries);
  const enforceContent = buildEnforceSnippet(settings.blockAction, settings.hitLogging);
  const currentGeo     = fs.existsSync(GEO_FILE)     ? fs.readFileSync(GEO_FILE, 'utf8')     : null;
  const currentEnforce = fs.existsSync(ENFORCE_FILE) ? fs.readFileSync(ENFORCE_FILE, 'utf8') : null;

  // Skip the write+reload entirely when the parts that actually matter to
  // nginx (the geo{} table, the enforce action) haven't changed. Both
  // generated files carry a "genere le: <timestamp>" header that changes on
  // every single call (down to the millisecond) — comparing the raw text
  // would make `unchanged` false on every cycle, defeating the point. The
  // per-source status summary in the geo file's header is the same kind of
  // metadata: it can reword every cycle (a source's error message updating)
  // without a single IP being added or removed. So each file is compared
  // only on the body that follows its marker line, which is exactly the
  // part nginx actually reads as configuration.
  const stripHeader        = (s) => (s || '').split('geo $blocklist_ip {')[1] || '';
  const stripEnforceHeader = (s) => (s || '').split('if ($blocklist_ip) {')[1] || '';
  const unchanged = currentGeo !== null && currentEnforce !== null
    && stripHeader(currentGeo) === stripHeader(geoContent)
    && stripEnforceHeader(currentEnforce) === stripEnforceHeader(enforceContent);

  let applyResult = { ok: true, reloaded: false, skippedNoChange: true };
  if (!unchanged) {
    applyResult = await applySnippets(geoContent, enforceContent);
  }

  const status = {
    ok: applyResult.ok, reloaded: applyResult.reloaded || false,
    totalUniqueIps: mergedIps.length, sources: attempted,
    allFailedThisCycle, anySuccessThisCycle,
    testFailed: applyResult.testFailed || false,
    error: applyResult.error || null, stderr: applyResult.stderr || null,
    at: now,
  };

  logEvent(manual ? 'blocklists.refresh.manual' : 'blocklists.refresh.scheduled',
    { by: actor, ...status }, 'api');

  if (applyResult.testFailed) {
    pushNotification({ type: 'blocklist_reload_failed', level: 'error',
      message: `Blocklists IP : nginx -t a echoue, la mise a jour a ete annulee (version precedente restauree)` });
    await sendNotification('blocklist_reload_failed',
      '[Nginx Dashboard] Blocklists IP — nginx -t FAILED',
      `The generated blocklist snippet failed nginx -t and was rolled back.\n\n${status.stderr || status.error || ''}`
    ).catch(() => {});
  } else if (!applyResult.ok) {
    pushNotification({ type: 'blocklist_reload_failed', level: 'error',
      message: `Blocklists IP : reload nginx echoue apres mise a jour — ${status.error || ''}` });
  } else if (allFailedThisCycle) {
    pushNotification({ type: 'blocklist_fetch_failed', level: 'warning',
      message: `Blocklists IP : toutes les sources ont echoue ce cycle — liste precedente conservee (${mergedIps.length} IP)` });
  } else if (!hadIpsBefore && mergedIps.length > 0) {
    pushNotification({ type: 'blocklist_populated', level: 'success',
      message: `Blocklists IP : ${mergedIps.length} IP chargees pour la premiere fois` });
  }

  return status;
}

// ─── Cross-feature: analyzer API (hit stats) ─────────────────────────────────
// Injected from server.js, same composition-root pattern as every other
// cross-feature dependency in this project (see features/deploy.js's
// setDeps() for the sibling precedent). null when unset — every consumer
// below degrades to "unavailable" rather than throwing.
let analyzerApi = null;
let analyzerApiJson = null;
function setDeps({ analyzerApi: a, analyzerApiJson: aj } = {}) {
  if (typeof a === 'function') analyzerApi = a;
  if (typeof aj === 'function') analyzerApiJson = aj;
}

/**
 * Pushes which sources are enabled (with each one's cached IP/CIDR list)
 * plus the configured hit_logging_method to the analyzer, so IT can
 * attribute blocklist hits to a source and, in "approx" mode, detect hits
 * itself straight from the access log(s) it already tails (v12.29.0 — see
 * nginx-analyzer/lib/blocklist-sources.js). Same push-on-a-timer pattern as
 * features/analyzer.js's pushVhostRules(): in-memory on the analyzer side,
 * so a dropped push or an analyzer restart just means one cycle (at most 30s
 * here, since it also fires right after every refresh) of stale/missing
 * attribution, never a crash or a stuck state.
 *
 * When the feature is disabled, an empty source map is still pushed —
 * deliberately, so a just-disabled feature doesn't leave the analyzer
 * attributing hits to sources the operator turned off.
 */
async function pushBlocklistSources() {
  if (!analyzerApiJson) return;
  const { settings, valid: configuredSources } = loadConfig();
  const sources = {};
  if (settings.enable) {
    const cache = loadCache();
    for (const source of configuredSources) {
      if (!source.enable) continue;
      const entry = cache.sources?.[source.name];
      if (!entry || !Array.isArray(entry.ips)) continue;
      sources[source.name] = { ips: entry.ips };
    }
  }
  const mode = settings.hitLogging?.method === 'approx' ? 'approx' : 'dedicated';
  try { await analyzerApiJson('/api/blocklist-sources', 'POST', { mode, sources }); }
  catch { /* analyzer unreachable — next tick (<=30s) retries, same as pushVhostRules */ }
}

// ─── IP search ────────────────────────────────────────────────────────────────
/**
 * Pre-parses every enabled source's cached IP/CIDR list ONCE into a fast
 * lookup shape: a plain address (the overwhelming majority of entries on
 * most public blocklists) goes into a Set for O(1) lookup, and only the
 * genuinely range-based entries (an actual CIDR block) are kept as a
 * parsed-once array. Perf fix (v12.21.2, found independently of the audit,
 * while addressing a report that the Blocklists IP page's hit-stats took a
 * long time to load): checkIp()/getHitStats() used to call the raw
 * ipInCidr(ip, pattern) — which re-parses BOTH the address and the pattern
 * from scratch — inside a `.some()` over every single entry of every
 * source, for EVERY ip being checked. getHitStats() checks up to 1000 top
 * IPs against every source's full list on every single request: with a
 * source holding tens of thousands of entries (a normal size for a public
 * blocklist), that is tens of millions of from-scratch string parses per
 * page load. Building this index once per call turns that into a handful of
 * Set lookups plus a much smaller number of CIDR containment checks against
 * already-parsed values.
 */
function buildSourceIndex(sources, cache) {
  const index = [];
  for (const source of sources) {
    if (!source.enable) continue;
    const entry = cache.sources?.[source.name];
    if (!entry || !Array.isArray(entry.ips)) continue;
    const exact = new Set();
    const blocks = [];
    for (const pattern of entry.ips) {
      const block = parseCidr(pattern);
      if (!block) continue; // already validated at fetch time, but stay defensive
      const isHostRoute = (block.family === 4 && block.prefix === 32) || (block.family === 6 && block.prefix === 128);
      if (isHostRoute) exact.add(`${block.family}:${block.bytes.join('.')}`);
      else blocks.push(block);
    }
    index.push({ name: source.name, exact, blocks });
  }
  return index;
}

/** Which source names (from a buildSourceIndex() result) contain `ip`. */
function sourcesContaining(ip, index) {
  const addr = toBytes(ip);
  if (!addr) return [];
  const key = `${addr.family}:${addr.bytes.join('.')}`;
  const matches = [];
  for (const src of index) {
    if (src.exact.has(key) || src.blocks.some(block => containsParsed(addr, block))) matches.push(src.name);
  }
  return matches;
}

/**
 * Which configured, enabled sources currently list `ip` — an address can be
 * in more than one, which is exactly the point per the feature request: an
 * operator investigating one IP wants to know every list responsible, not
 * just "yes/no blocked". Uses the same cache the geo table is built from, so
 * the answer always matches what nginx is actually enforcing right now.
 */
function checkIp(ip) {
  const { valid: sources } = loadConfig();
  const cache = loadCache();
  const matches = sourcesContaining(ip, buildSourceIndex(sources, cache));
  return { ip, blocked: matches.length > 0, sources: matches };
}

// ─── Hit stats (Digest + effectiveness) ──────────────────────────────────────
/**
 * Pulls the analyzer's blocklist-hits window summary — total hits, distinct
 * IPs, top IPs, and (v12.29.0) the per-source breakdown — and passes it
 * through essentially as-is. Works whichever hit_logging method is
 * configured ("dedicated" or "approx") and even with hit_logging disabled
 * entirely, in which case the analyzer simply has nothing recorded and this
 * returns zeros, degrading gracefully rather than erroring.
 *
 * Until v12.29.0 this function cross-referenced every top-hitting IP against
 * this feature's own per-source cache itself (see buildSourceIndex() above,
 * still used by checkIp()'s single-IP lookup) because only the dashboard
 * held that membership. Now that pushBlocklistSources() syncs the same
 * membership to the analyzer on a timer, the analyzer computes `bySource`
 * natively (from data it already has, right where the hits themselves are
 * recorded) and this just relays it — see nginx-analyzer/server.js's
 * /api/blocklist-hits/summary route.
 */
// Perf/UX fix (v12.21.2, kept in v12.29.0): the summary only changes as fast
// as the analyzer's own aggregation window, and the Blocklists IP page can
// re-fetch it (manual refresh, re-opening the tab) far more often than that.
// A short in-memory cache turns every repeat load within HIT_STATS_CACHE_MS
// into an instant response instead of a fresh round-trip to the analyzer.
const HIT_STATS_CACHE_MS = 20_000;
let hitStatsCache = null; // { hours, at, result }

async function getHitStats({ hours = 24 } = {}) {
  const { settings } = loadConfig();
  if (!analyzerApi) return { available: false, hitLogging: settings.hitLogging };
  if (hitStatsCache && hitStatsCache.hours === hours && (Date.now() - hitStatsCache.at) < HIT_STATS_CACHE_MS) {
    return hitStatsCache.result;
  }
  try {
    const res = await analyzerApi(`/api/blocklist-hits/summary?hours=${hours}&limit=1000`);
    const data = res?.data || {};
    const result = {
      available: true,
      hitLogging: settings.hitLogging,
      totalHits: data.totalHits || 0,
      uniqueHitIps: data.uniqueIps || 0,
      topIps: (Array.isArray(data.topIps) ? data.topIps : []).slice(0, 20),
      bySource: Array.isArray(data.bySource) ? data.bySource : [],
    };
    hitStatsCache = { hours, at: Date.now(), result };
    return result;
  } catch (e) {
    return { available: false, hitLogging: settings.hitLogging, error: e.message };
  }
}

/**
 * Everything lib/digest.js needs in one call: the always-available
 * "Nombre d'adresses IP globales" (no analyzer dependency — it's the geo
 * table's own IP count) plus whatever hit-logging stats getHitStats() can
 * provide. Kept separate from getHitStats() itself so the IP-search UI and
 * the /api/blocklists/hit-stats route aren't forced to pay for a config
 * reload + cache read they don't need.
 */
async function getDigestStats({ hours = 24 } = {}) {
  const { settings } = loadConfig();
  if (!settings.enable) return { enable: false };
  const totalUniqueIps = getBlocklistStatus().totalUniqueIps;
  const hitStats = await getHitStats({ hours });
  return { enable: true, totalUniqueIps, ...hitStats };
}

function getBlocklistStatus() {
  const { settings, sources: rawSources, valid, errors: configErrors } = loadConfig();
  const cache = loadCache();
  const geoStat     = (() => { try { return fs.statSync(GEO_FILE); }     catch { return null; } })();
  const enforceStat = (() => { try { return fs.statSync(ENFORCE_FILE); } catch { return null; } })();
  const sources = (rawSources.length ? rawSources : valid).map(s => {
    const entry = cache.sources?.[s.name];
    return {
      name: s.name, url: s.url, enable: s.enable !== false,
      count: entry?.count ?? 0, invalidCount: entry?.invalidCount ?? 0,
      lastSuccessAt: entry?.lastSuccessAt || null, lastAttemptAt: entry?.lastAttemptAt || null,
      lastError: entry?.lastError || null,
    };
  });
  const totalUniqueIps = new Set(
    sources.filter(s => s.enable).flatMap(s => cache.sources?.[s.name]?.ips || [])
  ).size;
  return {
    enable: settings.enable, intervalCron: settings.intervalCron, blockAction: settings.blockAction,
    hitLogging: settings.hitLogging,
    configErrors, sources, totalUniqueIps,
    geoFile:     { path: GEO_FILE,     exists: !!geoStat,     size: geoStat?.size || 0,     mtime: geoStat?.mtime || null },
    enforceFile: { path: ENFORCE_FILE, exists: !!enforceStat, size: enforceStat?.size || 0, mtime: enforceStat?.mtime || null },
  };
}

// ─── Scheduling ───────────────────────────────────────────────────────────────
// Self-contained periodic tick, same pattern as features/analyzer.js's
// startAlertPolling(): this feature owns its own interval rather than being
// wired into lib/scheduler.js, which is deliberately kept free of
// feature-specific imports (see that file's header comment).
const { matchCron } = require('../lib/scheduler');
let pollTimer = null;
let lastFiredMinute = null;

function startBlocklistScheduler() {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    // Independent of the cron-gated refresh below: mode/enablement can
    // change (settings edited) without a source list refresh being due, and
    // the analyzer should never be more than one tick behind either.
    pushBlocklistSources().catch(() => {});
    const { settings } = loadConfig();
    if (!settings.enable) return;
    const now = new Date();
    const minuteKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    if (minuteKey === lastFiredMinute) return;
    if (!matchCron(settings.intervalCron, now)) return;
    lastFiredMinute = minuteKey;
    refreshBlocklists({ manual: false }).catch(e => console.error('[blocklists] scheduled refresh error:', e.message));
  }, 30_000);
  pollTimer.unref();
  // Applied immediately rather than waiting up to 30s — a dashboard restart
  // must not leave the analyzer on stale/missing source data any longer than
  // features/analyzer.js's own pushVhostRules() leaves it on stale vhost data.
  pushBlocklistSources().catch(() => {});
}

// ─── Routes ───────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/blocklists/status', ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try { return send(res, 200, getBlocklistStatus()); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.post('/api/blocklists/refresh', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      const result = await refreshBlocklists({ manual: true, actor: session.username });
      return send(res, 200, result);
    } catch (e) {
      logEvent('blocklists.refresh.error', { by: session.username, error: e.message }, 'api');
      return send(res, 500, { error: e.message });
    }
  });

  // "Blocklist : rechercher une ip" — which configured list(s), if any,
  // currently contain this address. Mirrors GET /api/geoip/lookup and
  // GET /api/crowdsec/allowlists/check (same permission, same shape of
  // "one address in, structured facts out").
  router.get('/api/blocklists/check', ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const ip = url.searchParams.get('ip');
    if (!ip || !isValidPattern(ip)) return httpLib.badRequest(res, 'ip invalide');
    try { return send(res, 200, checkIp(ip)); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  // Digest-style effectiveness numbers: total hits, distinct hit IPs, and
  // which blocklists they trace back to — the analyzer computes the
  // per-source breakdown itself (v12.29.0), see getHitStats()'s comment.
  router.get('/api/blocklists/hit-stats', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const hours = +url.searchParams.get('hours') || 24;
    try { return send(res, 200, await getHitStats({ hours })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });
}

module.exports = {
  register, setDeps, ensureSnippetsAtBoot, refreshBlocklists, getBlocklistStatus, startBlocklistScheduler,
  checkIp, getHitStats, getDigestStats, pushBlocklistSources,
  // consumed by server.js to wire into features/deploy.js's setDeps()
  GENERATED_FILES,
  // exported for tests
  buildGeoSnippet, buildEnforceSnippet, buildHitlogFormatSnippet,
  GEO_FILE, ENFORCE_FILE, HITLOG_FORMAT_FILE, HIT_LOG_FILE,
};
