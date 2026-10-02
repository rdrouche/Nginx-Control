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
const blocklistHistory = require('../lib/blocklist-history');
const challengeGate = require('../lib/challenge-gate');
const { pushNotification } = require('../lib/notifications');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { readChallengeOverrides } = require('../lib/challenge-settings');
const { fetchBlocklistText } = require('../lib/blocklist-fetch');
const { parseIpLines } = require('../lib/blocklist-parse');
const { ipInCidr, isValidPattern, toBytes, parseCidr, containsParsed } = require('../lib/cidr');
const { withLock } = require('../lib/nginx-write-lock');

const { DIR_CONF, DIR_SNIPPETS, BLOCKLIST_CONFIG_FILE } = cfg;
const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
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
// v12.63.0 — remediation "challenge" : table geo + variables (http) et snippet
// a inclure dans les vhosts. Voir lib/challenge-gate.js.
const CHALLENGE_FILE = path.join(DIR_CONF, 'blocklist-challenge.conf');
const GATE_FILE      = path.join(DIR_SNIPPETS, challengeGate.GATE_VARIANTS.listed.file);
const GATE_FILES     = Object.fromEntries(Object.entries(challengeGate.GATE_VARIANTS).map(([k, v]) => [k, path.join(DIR_SNIPPETS, v.file)]));
const GENERATED_FILES = [GEO_FILE, ENFORCE_FILE, HITLOG_FORMAT_FILE, CHALLENGE_FILE, ...Object.values(GATE_FILES)];

/** GENERATED_FILES + un snippet par profil de challenge (liste dynamique, relue de challenge.yml). */
function getGeneratedFiles() {
  let extra = [];
  try { extra = (loadConfig().settings.challenge.profiles || []).map(pr => path.join(DIR_SNIPPETS, pr.file)); } catch { /* config illisible : liste de base */ }
  return [...GENERATED_FILES, ...extra];
}

// ─── Config ────────────────────────────────────────────────────────────────
function loadConfig() {
  let text = '';
  try { text = fs.readFileSync(BLOCKLIST_CONFIG_FILE, 'utf8'); } catch { /* missing = disabled, defaults apply */ }
  // challenge.yml (page « Challenge HTTP ») l emporte sur les cles challenge_* de blocklists.yml
  return { text, ...parseAndValidate(text, readChallengeOverrides(cfg.CHALLENGE_CONFIG_FILE)) };
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
    const { settings } = loadConfig();
    if (!fs.existsSync(ENFORCE_FILE)) {
      atomicWrite(ENFORCE_FILE, buildEnforceSnippet(settings.blockAction, settings.hitLogging));
    }
    if (!fs.existsSync(CHALLENGE_FILE)) atomicWrite(CHALLENGE_FILE, challengeGate.emptyChallengeHttp(settings.challenge));
    for (const g of challengeGate.buildAllGateSnippets(settings.challenge)) {
      const gf = path.join(DIR_SNIPPETS, g.name);
      if (!fs.existsSync(gf)) atomicWrite(gf, g.content);
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
async function applySnippets(geoContent, enforceContent, extra = []) {
  // Fix v12.21.2 (audit finding DAC-05): the whole write -> test -> reload
  // (and its rollback) now runs inside the mutex shared with
  // features/docker-autoconfig.js and features/agents.js — see
  // lib/nginx-write-lock.js's own header for why this must be a single
  // global lock, not one per feature.
  // `extra` (v12.63.0) : fichiers supplementaires [{ file, content }] (challenge),
  // ecrits, testes et restaures exactement comme les deux premiers.
  return withLock(async () => {
    const pairs = [[GEO_FILE, geoContent], [ENFORCE_FILE, enforceContent], ...extra.map(e => [e.file, e.content])];
    const previous = pairs.map(([f]) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null));
    const restore = () => pairs.forEach(([f], i) => { if (previous[i] !== null) atomicWrite(f, previous[i]); });

    for (const [f, c] of pairs) atomicWrite(f, c);

    try {
      await docker.execNginx('nginx -t');
    } catch (e) {
      // Roll back immediately — a failed test must never leave the broken
      // version as the file nginx will read on its next reload, scheduled or
      // manual, possibly hours from now.
      restore();
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
async function refreshBlocklistsNow({ manual = false, actor = 'scheduler', analyzerOnly = false } = {}) {
  const { settings, valid: sources, whitelist, errors: configErrors } = loadConfig();
  if (!settings.enable) return { skipped: true, reason: 'disabled' };
  if (!sources.length) return { skipped: true, reason: 'no-sources', configErrors };

  const cache = loadCache();
  cache.sources = cache.sources || {};
  const now = new Date().toISOString();
  const attempted = [];

  // Une seule interrogation de l analyseur par cycle, quel que soit le nombre
  // de sources "analyzer" configurees (v12.50.0 : le resultat n est plus
  // specifique a une source, il agrege TOUTES les regles d Analyse ayant
  // opte — voir computeAnalyzerBlocklist()). En pratique une seule source de
  // ce type a du sens, mais rien n empeche d en nommer plusieurs.
  let analyzerResult = null;
  const wlRemovedAtSource = new Set(); // IP retirees par la liste blanche des la source analyzer

  for (const source of sources) {
    if (!source.enable) continue;
    // analyzerOnly : cycle frequent limite a la source locale "analyzer" ; les
    // autres sources gardent leur cache (et restent fusionnees plus bas), elles
    // ne sont retelechargees qu'au cron general (interval_cron).
    if (analyzerOnly && source.type !== 'analyzer') continue;
    const prevEntry = cache.sources[source.name] || {};

    // Source "analyzer" (retour utilisateur, v12.49.4, redesign v12.50.0) :
    // rien a recuperer par HTTP — voir computeAnalyzerBlocklist() plus haut.
    if (source.type === 'analyzer') {
      if (!analyzerResult) analyzerResult = await computeAnalyzerBlocklist();
      // v12.67.1 : la liste blanche s applique des la source (et pas seulement a
      // la fusion finale) — sinon une IP whitelistee apparaissait « Ajoutee /
      // bloquee jusqu a… » dans l historique et dans les compteurs de la source
      // alors que nginx ne la bloquait pas. Elle reste « detectee » (visible).
      const wl = (ip) => {
        const hit = whitelist.some(w => ipInCidr(ip, w));
        if (hit) wlRemovedAtSource.add(ip);
        return hit;
      };
      const result = analyzerResult.ok
        ? { ...analyzerResult, ips: analyzerResult.ips.filter(ip => !wl(ip)),
            challengeIps: (analyzerResult.challengeIps || []).filter(ip => !wl(ip)) }
        : analyzerResult;
      if (result.ok) {
        const prevDetectedCount = prevEntry.detectedCount || 0;
        // Historique ajouts/retraits (v12.53.0), avant d'ecraser l'etat precedent.
        try {
          blocklistHistory.record(blocklistHistory.diffAnalyzer({
            source: source.name, prevIps: prevEntry.ips || [], newIps: result.ips,
            prevDetected: prevEntry.detectedIps || [], newDetected: result.detectedIps,
            ipRules: result.ipRules || {}, expired: result.expired || [],
            manualRemoved: result.manualRemoved || [],
          }));
        } catch (e) { console.warn('[blocklists] history:', e.message); }
        cache.sources[source.name] = {
          type: 'analyzer',
          detectedIps: result.detectedIps, detectedCount: result.detectedIps.length,
          byRule: result.byRule,
          // Le coeur de la demande utilisateur : une regle sans
          // remediation:true (defaut de securite explicite — voir
          // nginx-analyzer/lib/rules-manager.js) est calculee et visible
          // (detectedIps/byRule) mais ne participe jamais a `ips`, donc
          // jamais a la table geo fusionnee plus bas.
          ips: result.ips, count: result.ips.length,
          challengeIps: result.challengeIps || [], challengeCount: (result.challengeIps || []).length,
          lastSuccessAt: now, lastAttemptAt: now, lastError: null,
        };
        attempted.push({
          name: source.name, ok: true, type: 'analyzer',
          count: result.ips.length, detectedCount: result.detectedIps.length,
        });
        // Informe l operateur qu une nouvelle IP suspecte est apparue meme
        // quand aucune regle n a la remediation activee — sans cette
        // notification, une liste calculee mais jamais appliquee serait
        // invisible en dehors d une visite manuelle de la page.
        if (result.detectedIps.length > prevDetectedCount) {
          const activeRules = result.byRule.filter(r => r.detectedCount > 0).map(r => r.name).join(', ');
          pushNotification({ type: 'blocklist_analyzer_detected', level: 'warning',
            message: `Blocklists IP (${source.name}) : ${result.detectedIps.length} IP suspecte(s) detectee(s) par l analyse (regle(s) : ${activeRules || '—'})` });
        }
      } else {
        cache.sources[source.name] = {
          ...prevEntry, type: 'analyzer',
          lastAttemptAt: now, lastError: result.error,
        };
        attempted.push({ name: source.name, ok: false, type: 'analyzer', error: result.error, cachedCount: prevEntry.count || 0 });
      }
      continue;
    }

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
  // Liste blanche (retour utilisateur v12.50.0) : filet de securite GLOBAL,
  // applique apres la fusion de TOUTES les sources (url ou analyzer) — une
  // IP/CIDR configuree ici n est jamais ecrite dans la table geo, quelle que
  // soit la source qui l aurait sinon incluse. Cas d usage explicite : des
  // plages privees qu un faux positif de l analyse ne doit jamais bloquer.
  const whitelisted = [...merged].filter(ip => whitelist.some(w => ipInCidr(ip, w)));
  for (const ip of whitelisted) merged.delete(ip);
  const mergedIps = Array.from(merged).sort();

  // v12.63.0 — IP a soumettre au challenge : meme fusion des sources, meme liste
  // blanche ; le blocage l emporte (une IP deja bloquee n est jamais challengee).
  const mergedChallengeSet = new Set();
  for (const name of enabledNames) {
    const entry = cache.sources[name];
    if (entry && Array.isArray(entry.challengeIps)) for (const ip of entry.challengeIps) mergedChallengeSet.add(ip);
  }
  for (const ip of [...mergedChallengeSet]) {
    if (merged.has(ip) || whitelist.some(w => ipInCidr(ip, w))) mergedChallengeSet.delete(ip);
  }
  const challengeCfg = settings.challenge;
  // Challenge desactive : les IP restent detectees/affichees mais rien n est ecrit pour nginx.
  const mergedChallenge = challengeCfg.enable ? Array.from(mergedChallengeSet).sort() : [];

  saveCache(cache);
  if (!analyzerOnly) blocklistHistory.purge(); // meme retention que le journal d evenements
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

  const challengeContent = challengeGate.buildChallengeHttp(challengeCfg, mergedChallenge,
    `total: ${mergedChallenge.length} IP${challengeCfg.enable ? '' : ' (challenge desactive)'}`);
  const gates = challengeGate.buildAllGateSnippets(challengeCfg).map(g => ({ file: path.join(DIR_SNIPPETS, g.name), content: g.content }));
  const readOrNull = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null);
  const currentChallenge = readOrNull(CHALLENGE_FILE);
  const challengeUnchanged = currentChallenge !== null
    && challengeGate.stripComments(currentChallenge) === challengeGate.stripComments(challengeContent)
    && gates.every(g => { const cur = readOrNull(g.file); return cur !== null && challengeGate.stripComments(cur) === challengeGate.stripComments(g.content); });

  let applyResult = { ok: true, reloaded: false, skippedNoChange: true };
  if (!unchanged || !challengeUnchanged) {
    applyResult = await applySnippets(geoContent, enforceContent, [
      { file: CHALLENGE_FILE, content: challengeContent }, ...gates,
    ]);
  }

  const status = {
    ok: applyResult.ok, reloaded: applyResult.reloaded || false,
    totalUniqueIps: mergedIps.length, challengeIps: mergedChallenge.length, sources: attempted,
    whitelistedCount: new Set([...wlRemovedAtSource, ...whitelisted]).size,
    allFailedThisCycle, anySuccessThisCycle,
    testFailed: applyResult.testFailed || false,
    error: applyResult.error || null, stderr: applyResult.stderr || null,
    at: now,
  };

  // Un cycle analyzerOnly tourne chaque minute : ne journaliser que ce qui a
  // reellement change (ou echoue), sinon le journal d'evenements serait noye.
  const quietCycle = analyzerOnly && !manual && unchanged && challengeUnchanged && applyResult.ok && !allFailedThisCycle;
  if (!quietCycle) {
    logEvent(manual ? 'blocklists.refresh.manual' : 'blocklists.refresh.scheduled',
      { by: actor, analyzerOnly, ...status }, 'api');
  }

  // Meme echec qui se repete a chaque cycle (analyseur arrete, nginx -t qui echoue
  // sur le meme contenu...) : une notification par 30 min, pas une par minute.
  const notifyFailure = (key, payload) => {
    if (analyzerOnly && !manual) {
      const last = failureNotified.get(key);
      if (last && Date.now() - last < 30 * 60_000) return false;
      failureNotified.set(key, Date.now());
    }
    pushNotification(payload);
    return true;
  };

  if (applyResult.testFailed) {
    if (notifyFailure('blocklist_reload_failed:test', { type: 'blocklist_reload_failed', level: 'error',
      message: `Blocklists IP : nginx -t a echoue, la mise a jour a ete annulee (version precedente restauree)` })) {
      await sendNotification('blocklist_reload_failed',
        '[Nginx Dashboard] Blocklists IP — nginx -t FAILED',
        `The generated blocklist snippet failed nginx -t and was rolled back.\n\n${status.stderr || status.error || ''}`
      ).catch(() => {});
    }
  } else if (!applyResult.ok) {
    notifyFailure('blocklist_reload_failed:reload', { type: 'blocklist_reload_failed', level: 'error',
      message: `Blocklists IP : reload nginx echoue apres mise a jour — ${status.error || ''}` });
  } else if (allFailedThisCycle) {
    notifyFailure('blocklist_fetch_failed', { type: 'blocklist_fetch_failed', level: 'warning',
      message: `Blocklists IP : toutes les sources ont echoue ce cycle — liste precedente conservee (${mergedIps.length} IP)` });
  } else if (!hadIpsBefore && mergedIps.length > 0) {
    pushNotification({ type: 'blocklist_populated', level: 'success',
      message: `Blocklists IP : ${mergedIps.length} IP chargees pour la premiere fois` });
  }

  return status;
}

const failureNotified = new Map();

// Un seul rafraichissement a la fois : le cycle frequent de la source analyzer
// (chaque minute) ne doit jamais chevaucher un cycle complet (telechargements
// HTTP, reload nginx) ni un rafraichissement manuel - ils ecrivent le meme cache
// et les memes fichiers nginx.
let refreshChain = Promise.resolve();
function refreshBlocklists(opts = {}) {
  const run = refreshChain.then(() => refreshBlocklistsNow(opts));
  refreshChain = run.catch(() => {});
  return run;
}

/**
 * Deblocage manuel d une IP de la source "analyzer" (v12.54.0).
 *
 * Execute dans la meme file que les rafraichissements : computeAnalyzerBlocklist()
 * relit puis reecrit l etat de remediation a chaque cycle, une modification
 * concurrente serait ecrasee. Efface la duree de blocage de l IP, memorise le
 * deblocage (voir UNBLOCK_STATE_KEY) puis recalcule aussitot la liste, de sorte
 * que le retrait soit effectif dans nginx sans attendre le cycle suivant.
 *
 * `hours` : 0 = remise a zero du compteur (re-blocage possible si de nouvelles
 * alertes franchissent le seuil) ; > 0 = en plus, exemption pendant N heures.
 */
function unblockAnalyzerIp(ip, { hours = 0, actor = 'api' } = {}) {
  const run = refreshChain.then(async () => {
    const h = Math.max(0, Math.min(UNBLOCK_MAX_HOURS, Math.floor(Number(hours) || 0)));
    const now = Date.now();
    const cache = loadCache();
    const wasBlocked = Object.values(cache.sources || {})
      .some(s => s && s.type === 'analyzer' && Array.isArray(s.ips) && s.ips.includes(ip));

    const unblocked = events.getState(UNBLOCK_STATE_KEY) || {};
    unblocked[ip] = { ts: now, until: h > 0 ? now + h * 3600_000 : 0, by: actor, pendingLog: wasBlocked };
    const keys = Object.keys(unblocked);
    if (keys.length > UNBLOCK_MAX_ENTRIES) {
      keys.sort((a, b) => unblocked[a].ts - unblocked[b].ts)
        .slice(0, keys.length - UNBLOCK_MAX_ENTRIES).forEach(k => delete unblocked[k]);
    }
    events.setState(UNBLOCK_STATE_KEY, unblocked);

    const remediationState = events.getState(REMEDIATION_STATE_KEY) || {};
    if (remediationState[ip]) { delete remediationState[ip]; events.setState(REMEDIATION_STATE_KEY, remediationState); }

    logEvent('blocklists.unblock', { ip, by: actor, hours: h, wasBlocked }, 'api');

    let refreshed = false, error = null;
    try {
      const r = await refreshBlocklistsNow({ analyzerOnly: true, manual: true, actor });
      refreshed = !!r && !r.skipped && !r.error;
      if (r && r.error) error = r.error;
    } catch (e) { error = e.message; }
    return { ok: true, ip, wasBlocked, hours: h, until: h > 0 ? now + h * 3600_000 : null, refreshed, error };
  });
  refreshChain = run.catch(() => {});
  return run;
}

// ─── Cross-feature: analyzer API (hit stats) ─────────────────────────────────
// Injected from server.js, same composition-root pattern as every other
// cross-feature dependency in this project (see features/deploy.js's
// setDeps() for the sibling precedent). null when unset — every consumer
// below degrades to "unavailable" rather than throwing.
let analyzerApi = null;
let analyzerApiJson = null;
let buildVhostRulesMap = null;
function setDeps({ analyzerApi: a, analyzerApiJson: aj, buildVhostRulesMap: bvrm } = {}) {
  if (typeof a === 'function') analyzerApi = a;
  if (typeof aj === 'function') analyzerApiJson = aj;
  if (typeof bvrm === 'function') buildVhostRulesMap = bvrm;
}

// ─── Source "analyzer" : liste generee depuis les regles d Analyse ───────────
// Retour utilisateur (v12.49.4) : "un mode a la CrowdSec qui permet de
// generer une liste d IP douteuse ... base sur les regles Analysis ... un
// seuil de repetition pour bloquer ... permettre de pas faire de remediation
// si on le souhaite ... par defaut remediation est a false".
//
// Retour utilisateur de suivi (v12.50.0), apres la premiere livraison : "je
// vois ça au niveau des regles existantes (1-99) integre et sur les regles
// perso (100+) : threshold + remediation au niveau de la regle ; une liste
// blanche (CIDR ou IP) ; un commentaire vhost pour ignorer la remediation
// (garder les alertes, pas le blocage) ; un temps de remediation en minutes".
// Ce module ne porte donc plus lui-meme de threshold/fenetre/remediation —
// ils vivent desormais dans chaque regle d Analyse (voir
// nginx-analyzer/lib/rules-manager.js#listBlocklistRules(), qui fusionne
// regles integrees et personnalisees). Ce qui reste ici :
//   1. recuperer la liste des regles ayant opte (threshold configure),
//   2. compter, par regle et par IP, les alertes de cette regle sur SA
//      propre fenetre (desormais exprimee en MINUTES, pas en heures),
//   3. exclure les occurrences dont le vhost a le commentaire
//      "# nginx-control-analyze-no-remediation: on" (alerte gardee ailleurs,
//      juste jamais comptee ICI),
//   4. exclure toute IP/CIDR de la liste blanche (config/blocklists.yml),
//   5. pour les regles avec remediation:true, appliquer/prolonger un
//      blocage dont la duree est `remediationMinutes` (ou, si absent, aussi
//      longtemps que le seuil reste depasse sur la fenetre glissante).
const ANALYZER_ALERTS_PAGE_SIZE = 500;
// Borne dure sur le nombre de pages /api/alerts interrogees par cycle : un
// detecteur edge-triggered (une alerte par episode, jamais par requete) ne
// produit normalement qu un volume tres modere d alertes, meme sous attaque
// reelle — 20 pages (jusqu a 10 000 alertes) est deja tres large. Sans cette
// borne, une reponse anormale de l analyseur (bug, boucle) pourrait forcer ce
// module a paginer indefiniment a chaque cycle de rafraichissement.
const ANALYZER_ALERTS_MAX_PAGES = 20;
// Etat persiste (events.js#getState/setState, meme mecanisme que le cache
// des sources) du "temps de remediation" par IP : { [ip]: { ruleKey,
// blockedUntil } }. Uniquement pour les regles dont `remediationMinutes` est
// configure — voir computeAnalyzerBlocklist() ci-dessous.
const REMEDIATION_STATE_KEY = 'blocklist_analyzer_remediation_state';
// Deblocages manuels (v12.54.0) : { [ip]: { ts, until, by, pendingLog } }.
//  - ts : l instant du deblocage. Les alertes anterieures ou egales a ts ne
//    comptent plus pour cette IP (remise a zero du compteur) : elle ne revient
//    dans la liste que si de NOUVELLES alertes franchissent le seuil.
//  - until : si > maintenant, l IP est en plus exemptee de tout re-blocage
//    automatique jusqu a cet instant (0 = remise a zero seule).
//  - pendingLog : le retrait n a pas encore ete inscrit dans l historique.
const UNBLOCK_STATE_KEY = 'blocklist_analyzer_unblocked';
const UNBLOCK_MAX_HOURS = 24 * 30;
const UNBLOCK_MAX_ENTRIES = 1000;

/** Un type d alerte builtin ('bruteforce'|'scan'|'flood'|'scraping') ou `custom_<id>` -> id de regle numerique. */
const BUILTIN_ALERT_RULE_ID = { bruteforce: 1, scan: 2, flood: 3, scraping: 4 };
function alertRuleId(alertType) {
  if (BUILTIN_ALERT_RULE_ID[alertType] != null) return BUILTIN_ALERT_RULE_ID[alertType];
  const m = /^custom_(\d+)$/.exec(alertType || '');
  return m ? +m[1] : null;
}

/**
 * Vhosts ayant opte pour "# nginx-control-analyze-no-remediation: on" — les
 * alertes issues de ces vhosts restent visibles (rien ne change cote
 * detection/alerte) mais ne comptent jamais dans le seuil de blocage
 * automatique. Meme source de verite que pushVhostRules() (features/
 * analyzer.js), injectee via setDeps() pour eviter tout aller-retour reseau :
 * l information vient des fichiers vhost, deja lus cote dashboard.
 */
function getNoRemediationVhosts() {
  const set = new Set();
  if (typeof buildVhostRulesMap !== 'function') return set;
  try {
    const map = buildVhostRulesMap();
    for (const [name, cfg] of Object.entries(map || {})) {
      if (cfg && cfg.noRemediation) set.add(String(name).toLowerCase());
    }
  } catch { /* vhosts illisibles : par surete, aucune exclusion plutot qu une exception */ }
  return set;
}

/**
 * Calcule, pour CHAQUE regle d Analyse ayant opte (threshold configure), les
 * IP qui la declenchent assez souvent pour etre jugees suspectes — puis,
 * parmi celles-la, lesquelles doivent reellement etre bloquees maintenant
 * (remediation:true sur la regle, IP non blanchie, vhost non exclu).
 *
 * Une seule passe /api/alerts (paginee par sinceId/order=asc, meme mecanisme
 * de rattrapage que features/analyzer.js, jamais un simple `limit` qui sous-
 * compterait une IP active sous forte charge) couvrant la PLUS LARGE fenetre
 * parmi les regles opt-in, puis un filtrage par regle sur sa propre fenetre —
 * evite d interroger l analyseur une fois par regle a chaque cycle.
 */
async function computeAnalyzerBlocklist() {
  if (!analyzerApi) return { ok: false, error: 'analyseur non configure ou injoignable' };
  let rulesRes;
  try { rulesRes = await analyzerApi('/api/rules/blocklist-config'); }
  catch { rulesRes = null; }
  if (!rulesRes || rulesRes.status !== 200 || !rulesRes.data || !Array.isArray(rulesRes.data.rules)) {
    return { ok: false, error: 'analyseur injoignable ou reponse invalide (/api/rules/blocklist-config)' };
  }
  const rules = rulesRes.data.rules; // [{ id, key, name, threshold, windowMinutes, remediation, remediationMinutes }]
  if (!rules.length) return { ok: true, ips: [], detectedIps: [], byRule: [], ipRules: {}, expired: [], manualRemoved: [] };

  const now = Date.now();
  const maxWindowMs = Math.max(...rules.map(r => r.windowMinutes * 60_000));
  const since = now - maxWindowMs;
  const noRemediationVhosts = getNoRemediationVhosts();
  const unblocked = events.getState(UNBLOCK_STATE_KEY) || {};

  // alertsByRule[ruleId] = [{ ip, ts }] — seulement ce qui est necessaire au
  // comptage ci-dessous, pas l objet alerte entier.
  const alertsByRule = new Map();
  let sinceId = 0;
  for (let page = 0; page < ANALYZER_ALERTS_MAX_PAGES; page++) {
    let res;
    try {
      res = await analyzerApi(`/api/alerts?since=${since}&sinceId=${sinceId}&order=asc&limit=${ANALYZER_ALERTS_PAGE_SIZE}`);
    } catch { res = null; }
    if (!res || res.status !== 200 || !res.data || !Array.isArray(res.data.alerts)) {
      return { ok: false, error: 'analyseur injoignable ou reponse invalide (/api/alerts)' };
    }
    const alerts = res.data.alerts;
    for (const a of alerts) {
      if (typeof a.id === 'number' && a.id > sinceId) sinceId = a.id;
      // Alerte de CAMPAGNE (regle personnalisee scope: global, analyzer >= 12.62) : pas
      // d adresse propre, mais evidence.ips = [[ip, nb], ...] — chaque adresse listee
      // compte une fois pour cette alerte. Ignoree des qu un des vhosts touches a
      // opte pour no-remediation (on ne peut pas separer les adresses par vhost).
      if (!a.ip && a.evidence && a.evidence.campaign === true && Array.isArray(a.evidence.ips)) {
        const ruleId = alertRuleId(a.type);
        if (ruleId == null) continue;
        const vhs = Array.isArray(a.evidence.vhosts) ? a.evidence.vhosts : (a.vhost ? [a.vhost] : []);
        if (vhs.some(v => noRemediationVhosts.has(String(v).toLowerCase()))) continue;
        if (!alertsByRule.has(ruleId)) alertsByRule.set(ruleId, []);
        const list = alertsByRule.get(ruleId);
        for (const pair of a.evidence.ips) {
          const cip = Array.isArray(pair) ? pair[0] : null;
          if (typeof cip !== 'string') continue;
          const un = unblocked[cip];
          if (un && ((a.ts || now) <= un.ts || un.until > now)) continue;
          list.push({ ip: cip, ts: a.ts || now });
        }
        continue;
      }
      if (!a.ip) continue; // ex: volumetric/country_traffic, alerte au niveau pays/vhost, pas adresse
      // Retour utilisateur : "garde les alertes mais [pas] de blocage" pour
      // un vhost donne — l alerte existe toujours cote analyseur (/api/alerts
      // la montre), elle est simplement exclue de CE comptage.
      const vhost = a.vhost ? String(a.vhost).toLowerCase() : null;
      if (vhost && noRemediationVhosts.has(vhost)) continue;
      const ruleId = alertRuleId(a.type);
      if (ruleId == null) continue;
      // Deblocage manuel : on ignore ce qui date d avant le deblocage, et tout
      // tant que l exemption temporaire court.
      const un = unblocked[a.ip];
      if (un && ((a.ts || now) <= un.ts || un.until > now)) continue;
      if (!alertsByRule.has(ruleId)) alertsByRule.set(ruleId, []);
      alertsByRule.get(ruleId).push({ ip: a.ip, ts: a.ts || now });
    }
    if (alerts.length < ANALYZER_ALERTS_PAGE_SIZE) break; // dernier lot atteint
  }

  const remediationState = events.getState(REMEDIATION_STATE_KEY) || {};
  // Pour l'historique : quelle regle a bloque quelle IP (et jusqu'a quand), et
  // quelles IP viennent d'expirer (duree de remediation ecoulee).
  const ipRules = {};
  const expired = [];
  const detected = new Set();
  const byRule = [];
  for (const rule of rules) {
    const windowMs = rule.windowMinutes * 60_000;
    const cutoff = now - windowMs;
    const countsByIp = new Map();
    for (const entry of alertsByRule.get(rule.id) || []) {
      if (entry.ts < cutoff) continue;
      countsByIp.set(entry.ip, (countsByIp.get(entry.ip) || 0) + 1);
    }
    const qualifying = [...countsByIp.entries()]
      .filter(([, count]) => count >= rule.threshold)
      .map(([ip]) => ip)
      // Defense en profondeur (meme principe que pour une source url tierce,
      // voir l en-tete du fichier) : valider avant d ecrire quoi que ce soit
      // qui pourrait finir dans la config nginx generee.
      .filter(isValidPattern);
    for (const ip of qualifying) detected.add(ip);
    byRule.push({ id: rule.id, key: rule.key, name: rule.name, remediation: rule.remediation, remediationType: rule.remediationType === 'challenge' ? 'challenge' : 'block', detectedCount: qualifying.length });

    if (!rule.remediation) continue;
    const ruleKey = rule.key;
    const rType = rule.remediationType === 'challenge' ? 'challenge' : 'block';
    for (const ip of qualifying) {
      if (rule.remediationMinutes) {
        // Duree de blocage propre a la regle : (re)demarre a chaque cycle ou
        // l IP depasse encore le seuil, comme une decision CrowdSec renouvelee
        // tant que le comportement persiste.
        // v12.63.0 : un blocage encore actif n est jamais degrade en challenge
        // par une autre regle (le blocage l emporte).
        const prev = remediationState[ip];
        if (rType === 'challenge' && prev && prev.type !== 'challenge' && prev.blockedUntil > now) continue;
        remediationState[ip] = { ruleKey, blockedUntil: now + rule.remediationMinutes * 60_000, type: rType };
      } else {
        // Pas de duree propre : reste bloquee tant qu elle depasse le seuil
        // sur la fenetre glissante — retire toute entree TTL residuelle.
        delete remediationState[ip];
      }
    }
  }

  // IP encore sous blocage a duree fixe (remediationMinutes), meme si elles
  // ne re-declenchent plus ce cycle-ci — la duree annoncee doit etre tenue.
  const blockSet = new Set();
  const challengeSet = new Set(); // v12.63.0 : IP a soumettre au challenge au lieu d un refus
  for (const [ip, st] of Object.entries(remediationState)) {
    if (st.blockedUntil > now) {
      (st.type === 'challenge' ? challengeSet : blockSet).add(ip);
      ipRules[ip] = { rule: st.ruleKey, until: st.blockedUntil, ...(st.type === 'challenge' ? { type: 'challenge' } : {}) };
    }
    else { delete remediationState[ip]; expired.push(ip); }
  }
  // + toute IP qualifiante pour une regle remediation:true sans duree propre.
  for (const rule of rules) {
    if (!rule.remediation || rule.remediationMinutes) continue;
    const windowMs = rule.windowMinutes * 60_000;
    const cutoff = now - windowMs;
    const countsByIp = new Map();
    for (const entry of alertsByRule.get(rule.id) || []) {
      if (entry.ts < cutoff) continue;
      countsByIp.set(entry.ip, (countsByIp.get(entry.ip) || 0) + 1);
    }
    for (const [ip, count] of countsByIp) {
      if (count >= rule.threshold && isValidPattern(ip)) {
        if (rule.remediationType === 'challenge') {
          challengeSet.add(ip);
          if (!ipRules[ip]) ipRules[ip] = { rule: rule.key, until: null, type: 'challenge' };
        } else {
          blockSet.add(ip);
          if (!ipRules[ip] || ipRules[ip].type === 'challenge') ipRules[ip] = { rule: rule.key, until: null };
        }
      }
    }
  }

  events.setState(REMEDIATION_STATE_KEY, remediationState);
  // Le blocage l emporte : une IP presente dans les deux listes n est jamais seulement challengee.
  for (const ip of blockSet) challengeSet.delete(ip);

  // Retraits manuels a inscrire dans l historique (une seule fois), puis menage
  // des entrees dont l exemption est finie et dont les alertes sont hors fenetre.
  const manualRemoved = [];
  let unblockedDirty = false;
  for (const [ip, un] of Object.entries(unblocked)) {
    if (un.pendingLog) { manualRemoved.push(ip); un.pendingLog = false; unblockedDirty = true; }
    if (!(un.until > now) && un.ts < since) { delete unblocked[ip]; unblockedDirty = true; }
  }
  if (unblockedDirty) events.setState(UNBLOCK_STATE_KEY, unblocked);

  return {
    ok: true,
    manualRemoved,
    detectedIps: [...detected].sort(),
    ips: [...blockSet].sort(),
    challengeIps: [...challengeSet].sort(),
    byRule,
    ipRules,
    expired,
  };
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
  // v12.54.0 : l IP est-elle bloquee par une source "analyzer" (donc
  // debloquable a la main), et a-t-elle deja ete debloquee ?
  const analyzerNames = new Set(sources.filter(s => s.type === 'analyzer').map(s => s.name));
  const un = (events.getState(UNBLOCK_STATE_KEY) || {})[ip] || null;
  return {
    ip, blocked: matches.length > 0, sources: matches,
    analyzerBlocked: matches.some(n => analyzerNames.has(n)),
    challenged: !matches.length && sources.some(s => s.enable && (cache.sources?.[s.name]?.challengeIps || []).includes(ip)),
    unblocked: un ? { at: un.ts, until: un.until > Date.now() ? un.until : null, by: un.by } : null,
  };
}

// ─── Export (telecharger / visualiser une liste) ─────────────────────────────
/**
 * Retour utilisateur : pouvoir telecharger/visualiser via une URL la
 * blocklist calculee a partir des regles d Analyse (ou de n importe quelle
 * autre source configuree, ou la liste fusionnee — meme ensemble que la
 * table geo generee). Lit uniquement le cache deja peuple par
 * refreshBlocklists()/computeAnalyzerBlocklist() : aucun appel reseau ici,
 * donc une reponse instantanee et jamais bloquante pour l analyseur.
 *
 * `sourceName` :
 *  - omis ou 'all'  -> fusion de toutes les sources actuellement activees
 *                       (exactement l ensemble ecrit dans la table geo).
 *  - nom d une source configuree (ex. le nom donne a la source de type
 *    "analyzer") -> uniquement les IP de cette source.
 * `includeDetected` : pour une source "analyzer" uniquement — expose
 * `detectedIps` (toutes les IP ayant franchi un seuil de regle, meme sans
 * remediation:true) plutot que `ips` (le sous-ensemble reellement bloque).
 * Utile pour visualiser ce que l analyse a repere avant d activer un
 * blocage effectif.
 */
function getExportableIps(sourceName, { includeDetected = false } = {}) {
  const { valid: sources } = loadConfig();
  const cache = loadCache();
  const name = (sourceName || 'all').trim();

  if (!name || name === 'all') {
    const enabledNames = new Set(sources.filter(s => s.enable).map(s => s.name));
    const merged = new Set();
    for (const n of enabledNames) {
      for (const ip of (cache.sources?.[n]?.ips || [])) merged.add(ip);
    }
    return { ok: true, source: 'all', type: 'merged', ips: [...merged].sort() };
  }

  const entry = cache.sources?.[name];
  const norm  = sources.find(s => s.name === name);
  if (!entry && !norm) return { ok: false, error: `source "${name}" inconnue` };

  const isAnalyzer = norm?.type === 'analyzer' || entry?.type === 'analyzer';
  const raw = (includeDetected && isAnalyzer) ? (entry?.detectedIps || []) : (entry?.ips || []);
  return { ok: true, source: name, type: isAnalyzer ? 'analyzer' : 'url', ips: [...raw].sort() };
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

// ─── Challenge HTTP independant de la blocklist (v12.65.0) ───────────────────
const readOrNull = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null);

/**
 * Fichiers nginx du challenge tels qu ils DEVRAIENT etre maintenant, et IP
 * « challenge » (vide si le challenge ou la blocklist est desactive : seule la
 * source "analyzer" fournit des IP). Utilise par la regeneration manuelle et
 * par l etat « a jour / a regenerer » de la page.
 */
function computeChallengeFiles() {
  const { settings, valid: sources, whitelist } = loadConfig();
  const cache = loadCache();
  const cc = settings.challenge;
  let ips = [];
  if (cc.enable && settings.enable) {
    const names = sources.filter(s => s.enable).map(s => s.name);
    const blocked = new Set();
    const chal = new Set();
    for (const n of names) {
      const e = cache.sources?.[n];
      if (e && Array.isArray(e.ips)) e.ips.forEach(ip => blocked.add(ip));
      if (e && Array.isArray(e.challengeIps)) e.challengeIps.forEach(ip => chal.add(ip));
    }
    ips = [...chal].filter(ip => !blocked.has(ip) && !whitelist.some(w => ipInCidr(ip, w))).sort();
  }
  const files = [
    { name: 'blocklist-challenge.conf', file: CHALLENGE_FILE,
      content: challengeGate.buildChallengeHttp(cc, ips, `total: ${ips.length} IP${cc.enable ? '' : ' (challenge desactive)'}`) },
    ...challengeGate.buildAllGateSnippets(cc).map(g => ({ name: g.name, variant: g.variant, profile: g.profile || null, file: path.join(DIR_SNIPPETS, g.name), content: g.content })),
  ];
  return { settings, challenge: cc, ips, files };
}

function getChallengeFilesState() {
  const c = computeChallengeFiles();
  return {
    ips: c.ips,
    files: c.files.map(f => {
      const cur = readOrNull(f.file);
      return { name: f.name, variant: f.variant || null, path: f.file, exists: cur !== null,
        upToDate: cur !== null && challengeGate.stripComments(cur) === challengeGate.stripComments(f.content) };
    }),
  };
}

/** Regenere les fichiers challenge (sans toucher a la liste de blocage), nginx -t puis reload, retour arriere si echec. */
async function applyChallengeFiles({ actor = 'api' } = {}) {
  const c = computeChallengeFiles();
  const { settings } = c;
  const geo = readOrNull(GEO_FILE) ?? emptyGeoSnippet();
  const enforce = readOrNull(ENFORCE_FILE) ?? buildEnforceSnippet(settings.blockAction, settings.hitLogging);
  const state = getChallengeFilesState();
  if (state.files.every(f => f.upToDate)) return { ok: true, reloaded: false, unchanged: true };
  const res = await applySnippets(geo, enforce, c.files.map(f => ({ file: f.file, content: f.content })));
  logEvent('challenge.apply', { by: actor, ok: res.ok, reloaded: res.reloaded || false, ips: c.ips.length, error: res.error || null }, 'api');
  return res;
}

function getBlocklistStatus() {
  const { settings, sources: rawSources, valid, whitelist, errors: configErrors } = loadConfig();
  const cache = loadCache();
  const geoStat     = (() => { try { return fs.statSync(GEO_FILE); }     catch { return null; } })();
  const enforceStat = (() => { try { return fs.statSync(ENFORCE_FILE); } catch { return null; } })();
  const validByName = new Map(valid.map(s => [s.name, s]));
  const sources = (rawSources.length ? rawSources : valid).map(s => {
    const entry = cache.sources?.[s.name];
    const norm  = validByName.get(s.name);
    const isAnalyzer = norm?.type === 'analyzer' || entry?.type === 'analyzer';
    return {
      name: s.name, type: isAnalyzer ? 'analyzer' : 'url',
      url: isAnalyzer ? undefined : s.url,
      enable: s.enable !== false,
      count: entry?.count ?? 0, invalidCount: entry?.invalidCount ?? 0,
      lastSuccessAt: entry?.lastSuccessAt || null, lastAttemptAt: entry?.lastAttemptAt || null,
      lastError: entry?.lastError || null,
      // Uniquement pertinent pour une source "analyzer" (v12.50.0) — le
      // threshold/window/remediation ne vivent plus ici (voir chaque regle
      // dans le catalogue /api/rules), seul le resultat agrege reste :
      // combien d IP detectees au total, et le detail par regle.
      ...(isAnalyzer ? {
        detectedCount: entry?.detectedCount ?? 0,
        challengeCount: entry?.challengeCount ?? 0,
        byRule: entry?.byRule ?? [],
      } : {}),
    };
  });
  const totalUniqueIps = new Set(
    sources.filter(s => s.enable).flatMap(s => cache.sources?.[s.name]?.ips || [])
  ).size;
  return {
    enable: settings.enable, intervalCron: settings.intervalCron, blockAction: settings.blockAction,
    hitLogging: settings.hitLogging,
    configErrors, sources, totalUniqueIps, whitelist,
    challenge: {
      enable: settings.challenge.enable, engine: settings.challenge.engine,
      upstream: settings.challenge.upstreamEffective, exemptPathRegex: settings.challenge.exemptPathRegex,
      exemptUaRegex: settings.challenge.exemptUaRegex,
      ips: new Set(valid.filter(s => s.enable).flatMap(s => cache.sources?.[s.name]?.challengeIps || [])).size,
      gateFile: GATE_FILE, gateFiles: GATE_FILES, httpFile: CHALLENGE_FILE,
    },
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
let lastFiredAnalyzerMinute = null;

function startBlocklistScheduler() {
  if (pollTimer) return;
  pollTimer = setInterval(() => {
    // Independent of the cron-gated refresh below: mode/enablement can
    // change (settings edited) without a source list refresh being due, and
    // the analyzer should never be more than one tick behind either.
    pushBlocklistSources().catch(() => {});
    const { settings, valid } = loadConfig();
    if (!settings.enable) return;
    const now = new Date();
    const minuteKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
    if (matchCron(settings.intervalCron, now)) {
      if (minuteKey === lastFiredMinute) return;
      lastFiredMinute = minuteKey;
      lastFiredAnalyzerMinute = minuteKey; // un cycle complet inclut deja la source analyzer
      refreshBlocklists({ manual: false }).catch(e => console.error('[blocklists] scheduled refresh error:', e.message));
      return;
    }
    // Cadence dediee de la source "analyzer" (analyzer_interval_cron, chaque
    // minute par defaut) : local, sans telechargement, et sans ce cycle une alerte
    // dont la fenetre de regle est plus courte que interval_cron (6 h) serait
    // manquee ou appliquee des heures trop tard.
    if (!valid.some(src => src.enable && src.type === 'analyzer')) return;
    if (minuteKey === lastFiredAnalyzerMinute || !matchCron(settings.analyzerIntervalCron, now)) return;
    lastFiredAnalyzerMinute = minuteKey;
    refreshBlocklists({ manual: false, analyzerOnly: true }).catch(e => console.error('[blocklists] analyzer refresh error:', e.message));
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

  // Historique des ajouts/retraits/detections de la source analyzer
  // (lib/blocklist-history.js) : filtres ip/action/rule/source/since/until,
  // pagination limit/offset (defaut 50, max 500), ?format=csv pour un export.
  router.get('/api/blocklists/history', ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      const q = Object.fromEntries(url.searchParams);
      if (q.format === 'csv') {
        const r = blocklistHistory.query({ ...q, limit: 500, offset: 0 });
        res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="blocklist-history.csv"', 'X-Content-Type-Options': 'nosniff' });
        return res.end(blocklistHistory.toCsv(r.entries));
      }
      return send(res, 200, blocklistHistory.query(q));
    } catch (e) { return send(res, 500, { error: e.message }); }
  });

  // Deblocage manuel d une IP de la source "analyzer". Meme permission que le
  // rafraichissement manuel (ecrit la configuration nginx).
  router.post('/api/blocklists/unblock', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const ip = typeof body.ip === 'string' ? body.ip.trim() : '';
    // Une adresse seule : jamais un bloc CIDR (on ne debloque pas un /16 d un clic).
    if (!ip || ip.includes('/') || !isValidPattern(ip)) return httpLib.badRequest(res, 'ip invalide');
    const hours = Number(body.hours ?? 0);
    if (!Number.isFinite(hours) || hours < 0 || hours > UNBLOCK_MAX_HOURS) return httpLib.badRequest(res, 'hours invalide');
    try { return send(res, 200, await unblockAnalyzerIp(ip, { hours, actor: session.username })); }
    catch (e) {
      logEvent('blocklists.unblock.error', { ip, by: session.username, error: e.message }, 'api');
      return send(res, 500, { error: e.message });
    }
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

  // Telecharger/visualiser une blocklist via une URL directe. Meme
  // permission que les autres routes de lecture de cette feature ; une
  // requete authentifiee par le token API global (deja gere de facon
  // generique par server.js pour toute route /api/*) fonctionne tout aussi
  // bien, ce qui permet de coller cette URL dans un outil externe (curl,
  // une autre instance nginx-dashboard configuree en source "url", etc.).
  // format=txt renvoie une liste brute (une IP/CIDR par ligne), affichee
  // par le navigateur si on ouvre le lien directement ("visualiser"), et
  // enregistrable via "Enregistrer sous" ("telecharger") — &download=1
  // force l enregistrement immediat (Content-Disposition: attachment).
  router.get('/api/blocklists/export', ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const source          = url.searchParams.get('source') || 'all';
    const includeDetected = url.searchParams.get('detected') === '1';
    const format          = (url.searchParams.get('format') || 'json').toLowerCase();
    const forceDownload   = url.searchParams.get('download') === '1';
    let result;
    try { result = getExportableIps(source, { includeDetected }); }
    catch (e) { return send(res, 500, { error: e.message }); }
    if (!result.ok) return httpLib.badRequest(res, result.error);

    if (format === 'txt' || format === 'text') {
      const body = result.ips.length ? result.ips.join('\n') + '\n' : '';
      const headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
      };
      if (forceDownload) {
        headers['Content-Disposition'] = `attachment; filename="blocklist-${result.source}.txt"`;
      }
      res.writeHead(200, headers);
      return res.end(body);
    }
    return send(res, 200, {
      source: result.source, type: result.type, count: result.ips.length,
      generatedAt: new Date().toISOString(), ips: result.ips,
    });
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
  register, setDeps, ensureSnippetsAtBoot, refreshBlocklists, unblockAnalyzerIp, getBlocklistStatus, startBlocklistScheduler,
  computeChallengeFiles, getChallengeFilesState, applyChallengeFiles,
  checkIp, getHitStats, getDigestStats, pushBlocklistSources, getExportableIps,
  // consumed by server.js to wire into features/deploy.js's setDeps()
  GENERATED_FILES, getGeneratedFiles,
  // exported for tests
  buildGeoSnippet, buildEnforceSnippet, buildHitlogFormatSnippet, computeAnalyzerBlocklist,
  GEO_FILE, ENFORCE_FILE, HITLOG_FORMAT_FILE, HIT_LOG_FILE, CHALLENGE_FILE, GATE_FILE, GATE_FILES,
};
