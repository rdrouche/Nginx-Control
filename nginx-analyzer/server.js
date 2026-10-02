'use strict';
/**
 * nginx-analyzer — entry point.
 *
 * Reads nginx access logs, detects malicious behaviour and exposes the result
 * on an HTTP API the dashboard consumes. Runs as its own container so a heavy
 * log volume cannot slow the dashboard down, and so it can be stopped without
 * touching anything else.
 *
 * The port is never published — it is only reachable on the internal Docker
 * network. That network is shared with every backend the reverse proxy
 * fronts, though, not just the dashboard, so the API also checks a shared
 * secret (ANALYZER_TOKEN, see CONFIG.token below) rather than trusting
 * network placement alone (audit finding ANA-10). The token is optional:
 * left unset, the API stays open, so a container started outside the
 * dashboard's own lifecycle management (a manual docker-compose.yml, say)
 * keeps working exactly as before.
 */

const http = require('http');
const path = require('path');

const { Tailer }   = require('./lib/tail');
const { Store }    = require('./lib/store');
const { Detector, EXPLANATIONS, RULE_IDS } = require('./lib/detect');
const { Baseline } = require('./lib/baseline');
const { RulesManager } = require('./lib/rules-manager');
const geoip        = require('./lib/geoip');
const waf           = require('./lib/parse-waf');
const blocklistParse = require('./lib/parse-blocklist');
const blocklistSources = require('./lib/blocklist-sources');
const cidr           = require('./lib/cidr');
const botclass       = require('./lib/botclass');
const { HourlyAccumulator } = require('./lib/hourly-tracker');

const str = (n, d = '') => (process.env[n] ?? d).trim().replace(/^["']|["']$/g, '');
const int = (n, d) => { const v = parseInt(str(n), 10); return Number.isFinite(v) ? v : d; };

const CONFIG = {
  port:         int('PORT', 9100),
  logsDir:      str('LOGS_DIR', '/nginx/logs'),
  // Fix (audit finding ANA-02): the previous default ('\.access\.log$')
  // never matched nginx-dashboard's own shipped logging.conf, which writes
  // a single shared "vhosts_access.log" (an underscore, not a dot, before
  // "access") — a default installation followed zero files, and the
  // Analyse page stayed empty exactly like "no traffic" would, hiding a
  // configuration mismatch as a false negative. The new default matches
  // both that shared filename and a one-file-per-vhost convention
  // ("site.fr.access.log"). LOG_PATTERN stays fully overridable via env for
  // any other convention.
  logPattern:   new RegExp(str('LOG_PATTERN', '(^|[._])access\\.log$')),
  dbPath:       str('DB_PATH', '/analyzer/state.db'),
  pollMs:       int('POLL_MS', 1000),
  flushMs:      int('FLUSH_MS', 10_000),
  evaluateMs:   int('EVALUATE_MS', 30_000),
  rollupMs:     int('ROLLUP_MS', 3_600_000),
  // Fix (audit finding ANA-10): the API used to trust the network boundary
  // alone ("only the dashboard is on nginx-net"). But nginx-net is shared
  // with every backend the reverse proxy fronts — a compromised backend
  // container is exactly as able to reach port 9100 as the dashboard is,
  // and from there could silently disable detection rules or add a
  // 0.0.0.0/0 exception for itself. When the dashboard creates this
  // container (features/analyzer.js startAnalyzer()) it now generates and
  // passes a per-installation shared secret here; every request must carry
  // it back as the X-Analyzer-Token header. Left unset, auth is skipped —
  // preserving today's behaviour for anyone running the container by hand
  // outside the dashboard (docker-compose.yml), since there is no secret to
  // check in that case and refusing every request would be a regression,
  // not a fix.
  token:        str('ANALYZER_TOKEN', ''),
  learningDays: int('LEARNING_DAYS', 21),
  sigma:        int('SIGMA_THRESHOLD', 6),
  alertRetentionDays: int('ALERT_RETENTION_DAYS', 90),
  wafLogPattern: new RegExp(str('WAF_LOG_PATTERN', '\\.waf\\.log$')),
  wafRetentionDays: int('WAF_RETENTION_DAYS', 60),
  // Blocklist hits ("Method 1" dedicated log — see nginx-dashboard's
  // hit_logging config). One single global file, not per-vhost, hence a
  // literal filename match rather than a suffix pattern like the two above.
  blocklistLogPattern: new RegExp(str('BLOCKLIST_LOG_PATTERN', '^blocklist-hits\\.log$')),
  blocklistRetentionDays: int('BLOCKLIST_RETENTION_DAYS', 60),
  // Country-level volumetric alerting — same Baseline engine as per-vhost,
  // a separate instance keyed by country instead of vhost. A country's
  // traffic aggregates every vhost, so it is naturally larger and noisier
  // than any single vhost's — hence its own, higher default floor rather
  // than reusing FLOOD_MIN_REQUESTS's per-vhost figure.
  countrySigma:       int('COUNTRY_SIGMA_THRESHOLD', 6),
  countryMinRequests: int('COUNTRY_MIN_REQUESTS', 300),
};

const { parseIgnoreStatus } = require('./lib/ignore-status');
const IGNORE_STATUS = parseIgnoreStatus(str('DETECT_IGNORE_STATUS'));

const bool = (n, d) => { const v = str(n); return v === '' ? d : v === 'true' || v === '1'; };

const store = new Store(CONFIG.dbPath);

// Rule enable/disable + custom rules + per-vhost opt-out — see lib/rules-manager.js.
// Env vars only seed the very first boot; after that, the dashboard's live
// "Regles" modal is the source of truth and its choices are persisted.
const rulesManager = new RulesManager(store, {
  bruteforce: bool('RULE_BRUTEFORCE_ENABLE', true),
  scan: bool('RULE_SCAN_ENABLE', true),
  flood: bool('RULE_FLOOD_ENABLE', true),
  scraping: bool('RULE_SCRAPING_ENABLE', true),
  volumetric: bool('RULE_VOLUMETRIC_ENABLE', true),
  country_traffic: bool('RULE_COUNTRY_TRAFFIC_ENABLE', true),
});

const detector = new Detector({
  windowMs:   int('WINDOW_MS', 5 * 60_000),
  bruteforce: { enable: rulesManager.isEnabled('bruteforce'), minFailures: int('BF_MIN_FAILURES', 15) },
  scan:       { enable: rulesManager.isEnabled('scan'),
                minRequests: int('SCAN_MIN_REQUESTS', 40),
                minDistinct: int('SCAN_MIN_DISTINCT', 25) },
  flood:      { enable: rulesManager.isEnabled('flood'), minRequests: int('FLOOD_MIN_REQUESTS', 600) },
  scraping:   { enable: rulesManager.isEnabled('scraping'), minRequests: int('SCRAPE_MIN_REQUESTS', 300) },
});
detector.setCustomRules(rulesManager.customValid);

const baseline = new Baseline(
  { learningDays: CONFIG.learningDays, sigmaThreshold: CONFIG.sigma,
    enable: rulesManager.isEnabled('volumetric') },
  store.getState('baseline'),
);

// Same engine, keyed by country instead of vhost: Baseline's key is an
// opaque string (it was already generic before this), so a second instance
// with its own persisted state and thresholds is the entire feature —
// no change needed to lib/baseline.js itself.
const countryBaseline = new Baseline(
  { learningDays: CONFIG.learningDays, sigmaThreshold: CONFIG.countrySigma,
    minAbsoluteRequests: CONFIG.countryMinRequests,
    enable: rulesManager.isEnabled('country_traffic') },
  store.getState('country_baseline'),
);

// Structural signals for each in-progress hour, kept alongside the volume so
// the baseline can tell an audience apart from a flood.
//
// Fix (audit finding ANA-07): see lib/hourly-tracker.js's HourlyAccumulator
// for the full reasoning — in short, several log tailers interleaved could
// make "the current hour" flip back and forth and force premature partial
// flushes, and SIGTERM used to flush an in-progress hour as though it were
// complete, double-counting it if the process restarted within that hour.
// One accumulator per hour, closed only once genuinely over (and never on
// shutdown), fixes both.
const hourlyByHour        = new HourlyAccumulator(); // vhost-keyed
const hourlyCountryByHour = new HourlyAccumulator(); // country-keyed

function currentHour(ts) { return hourlyByHour.hourOf(ts); }

function trackStructure(entry) {
  hourlyByHour.add(entry.ts, entry.vhost,
    () => ({ requests: 0, errors: 0, ips: new Set(), paths: new Set() }),
    m => {
      m.requests++;
      if (entry.status >= 400) m.errors++;
      if (m.ips.size   < 20_000) m.ips.add(entry.ip);
      // entry.path is null for a bare "-" request (see lib/parse.js) — not a
      // distinct path to track for the baseline's distinctPaths signal.
      if (entry.path != null && m.paths.size < 20_000) m.paths.add(entry.path);
    });
}

/** Feed one finished hour's structural signals to the baseline and check it for anomalies. */
function flushHourlyBucket(hour, byVhost) {
  for (const [vhost, m] of byVhost) {
    const metrics = {
      requests: m.requests, errors: m.errors,
      distinctIps: m.ips.size, distinctPaths: m.paths.size,
    };
    const result = baseline.check(vhost, hour, metrics);
    // L apprentissage continue meme regle desactivee/vhost exclu (observe()
    // ci-dessous, hors de cette condition) — seule l alerte est retenue, pour
    // que reactiver la regle plus tard ne reparte pas de zero.
    if (result && result.anomaly && baseline.cfg.enable
        && !rulesManager.ruleSuppressedForVhost(vhost, RULE_IDS.volumetric)) {
      store.addAlert({
        type: 'volumetric', severity: result.severity,
        summary: result.summary,
        explanation: EXPLANATIONS.volumetric,
        evidence: { ...result, vhost },
      });
      console.log(`[alert] volumetric ${vhost}: ${result.summary}`);
    }
    baseline.observe(vhost, hour, metrics);
  }
  store.setState('baseline', baseline.toJSON());
}

/**
 * Close out every hour bucket that ended more than an hour ago — safely
 * clear of the file-interleaving jitter described above. Called on a timer
 * (see every(...) below), not per entry: an hour is closed once, when it is
 * genuinely over, regardless of how many files or how much reordering fed
 * it.
 */
function closeFinishedHourlyBuckets(now = Date.now()) {
  for (const [hour, byVhost] of hourlyByHour.closeFinished(now)) flushHourlyBucket(hour, byVhost);
}

/**
 * Same idea as trackStructure(), aggregated by country instead of vhost —
 * every vhost's traffic from a given country counts toward that country's
 * hourly volume. Distinct vhosts hit stands in for distinct paths: a real
 * audience from one country usually reaches more than one vhost, a
 * concentrated attack (credential stuffing against a single login page,
 * say) usually does not.
 */
function trackCountryStructure(entry, country) {
  hourlyCountryByHour.add(entry.ts, country,
    () => ({ requests: 0, errors: 0, ips: new Set(), vhosts: new Set() }),
    m => {
      m.requests++;
      if (entry.status >= 400) m.errors++;
      if (m.ips.size    < 20_000) m.ips.add(entry.ip);
      if (m.vhosts.size < 5_000)  m.vhosts.add(entry.vhost);
    });
}

/** Country-specific wording for the generic Baseline result — "depuis FR"
 *  reads more naturally than the vhost-phrased "sur FR" baseline.check()
 *  itself would produce, since it is written assuming a vhost name. */
function countrySummary(result, country) {
  return result.structure.looksOrganic
    ? `Trafic inhabituel depuis ${country} : ${result.observed} requetes contre ${result.expected} attendues, mais la structure ressemble a une audience reelle`
    : `Pic anormal depuis ${country} : ${result.observed} requetes contre ${result.expected} attendues (${result.deviation} ecarts), reparti sur peu de vhosts et/ou d adresses`;
}

/** Feed one finished hour's structural signals to the country baseline and check it for anomalies. */
function flushHourlyCountryBucket(hour, byCountry) {
  for (const [country, m] of byCountry) {
    const metrics = {
      requests: m.requests, errors: m.errors,
      distinctIps: m.ips.size, distinctPaths: m.vhosts.size,
    };
    const result = countryBaseline.check(country, hour, metrics);
    if (result && result.anomaly && countryBaseline.cfg.enable) {
      store.addAlert({
        type: 'country_traffic', severity: result.severity,
        summary: countrySummary(result, country),
        explanation: EXPLANATIONS.country_traffic,
        evidence: { ...result, vhost: undefined, country, distinctVhosts: m.vhosts.size },
      });
      console.log(`[alert] country_traffic ${country}: ${countrySummary(result, country)}`);
    }
    countryBaseline.observe(country, hour, metrics);
  }
  store.setState('country_baseline', countryBaseline.toJSON());
}

function closeFinishedHourlyCountryBuckets(now = Date.now()) {
  for (const [hour, byCountry] of hourlyCountryByHour.closeFinished(now)) flushHourlyCountryBucket(hour, byCountry);
}

const RECENT_GEO_MAX = 500;
// Matches the live map's own display window (GM_WINDOW_MS in the frontend):
// a fresh page load has no `since` yet, and without an age bound it would
// otherwise replay whatever the buffer happens to hold, however old.
const RECENT_GEO_MAX_AGE_MS = 5 * 60_000;
// Ephemeral, in-memory only: pulses on a live map don't need to survive a
// restart, and SQLite durability would be pure overhead for data that's
// irrelevant a few seconds after it's drawn.
const recentGeoEvents = [];
// Fix (audit finding ANA-09): each pushed event gets a strictly increasing
// ingestion sequence number, independent of both the browser's clock and
// the log's own timestamp — see /api/traffic/recent's comment below for why
// neither of those is safe to use as the live map's polling cursor.
let geoSeq = 0;

const tailer = new Tailer({
  dir: CONFIG.logsDir,
  pattern: CONFIG.logPattern,
  store,
  pollMs: CONFIG.pollMs,
  onEntry(entry) {
    // Statut ignore (ex. 444 : deja bloque par un autre mecanisme) : ni regles ni baseline,
    // mais le trafic reste enregistre plus bas (statistiques, hits de blocklist).
    const ignoredStatus = IGNORE_STATUS.has(entry.status);
    if (!ignoredStatus) {
      detector.add(entry);
      trackStructure(entry);
    }
    const country = geoip.countryOf(entry.ip);
    // No resolvable country (GeoIP absent, private/unroutable address, lookup
    // miss) means there is nothing to attribute this request to for a
    // per-country baseline — same reasoning as the live map below skipping
    // recentGeoEvents in that case, rather than inventing a "??" bucket
    // that would just accumulate everything GeoIP cannot place.
    if (country && !ignoredStatus) trackCountryStructure(entry, country);
    store.record(entry, country);

    // Bot/human classification is independent of GeoIP — a deployment with
    // no country database configured still gets a real human/bot breakdown,
    // it just can't place that traffic on a map or break it down by country.
    const { isBot, category } = botclass.classifyAgent(entry.ua);
    store.recordBot(entry, category, country);

    // A request with no resolvable country (GeoIP absent, private/unroutable
    // address, or a lookup miss) still happened — it's just not something a
    // world map can place anywhere, so it's skipped here rather than pushed
    // with a null country that would need special-casing on every consumer.
    if (country) {
      recentGeoEvents.push({ seq: ++geoSeq, ts: entry.ts, vhost: entry.vhost, country, isBot, category });
      if (recentGeoEvents.length > RECENT_GEO_MAX) recentGeoEvents.shift();
    }

    // hit_logging_method "approx" (nginx-dashboard/lib/blocklist-yaml.js):
    // no dedicated blocklist-hits.log — the operator asked the analyzer to
    // derive hits from the regular access log(s) it already tails, since
    // parsing logs is already its job (v12.29.0). Only does anything once
    // the dashboard has actually pushed source membership and selected this
    // mode; otherwise this is a single cheap check per request.
    if (blocklistSources.getMode() === 'approx' && blocklistSources.hasSources()) {
      if (blocklistSources.sourcesContaining(entry.ip).length) {
        store.recordBlocklistHit({
          ts: entry.ts, ip: entry.ip, vhost: entry.vhost,
          method: entry.method, uri: entry.path, status: entry.status,
        });
      }
    }
  },
});

/**
 * ModSecurity audit logs, read from the same directory with a different
 * filename pattern (`*.waf.log` by default). This reuses the Tailer's
 * rotation/truncation/offset handling as-is — only the line format differs,
 * so only the parser is swapped in.
 */
const wafTailer = new Tailer({
  dir: CONFIG.logsDir,
  pattern: CONFIG.wafLogPattern,
  store,
  pollMs: CONFIG.pollMs,
  detectFormat: waf.detectFormat,
  parseLine: waf.parseLine,
  vhostFromFilename: waf.vhostFromFilename,
  onEntry(entry) { store.recordWaf(entry); },
});

/**
 * Blocklist hits ("Method 1"), read from the same directory with a literal
 * filename match — see lib/parse-blocklist.js's header for why this is one
 * global file rather than a per-vhost one, and why vhostFromFilename returns
 * null (the vhost comes from a field inside each line, not the filename).
 */
const blocklistTailer = new Tailer({
  dir: CONFIG.logsDir,
  pattern: CONFIG.blocklistLogPattern,
  store,
  pollMs: CONFIG.pollMs,
  detectFormat: blocklistParse.detectFormat,
  parseLine: blocklistParse.parseLine,
  vhostFromFilename: blocklistParse.vhostFromFilename,
  onEntry(entry) { store.recordBlocklistHit(entry); },
});

// ─── Periodic work ───────────────────────────────────────────────────────────
function every(ms, fn, label) {
  const t = setInterval(() => {
    try { fn(); } catch (e) { console.warn(`[${label}]`, e.message); }
  }, ms);
  t.unref();
  return t;
}

every(CONFIG.flushMs, () => store.flush(), 'flush');

// Les exceptions sont relues a chaque evaluation : une exception ajoutee depuis
// le dashboard doit prendre effet sans redemarrer l agent.
every(CONFIG.evaluateMs, () => {
  detector.setExceptions(store.listExceptions());
}, 'exceptions');

every(CONFIG.evaluateMs, () => {
  for (const alert of detector.evaluate()) {
    store.addAlert(alert);
    console.log(`[alert] ${alert.type} ${alert.evidence?.ip || ''}: ${alert.summary}`);
  }
}, 'evaluate');

every(CONFIG.rollupMs, () => {
  store.rollup();
  store.purgeAlerts(Date.now() - CONFIG.alertRetentionDays * 86_400_000);
  store.purgeWaf(Date.now() - CONFIG.wafRetentionDays * 86_400_000);
  store.purgeBlocklistHits(Date.now() - CONFIG.blocklistRetentionDays * 86_400_000);
}, 'rollup');

// Fix (audit finding ANA-07): close out hour buckets on their own schedule,
// independent of when entries happen to arrive — see hourlyByHour's comment
// above for why. Five minutes is frequent enough that a closed hour reaches
// the baseline promptly without needing per-entry checks.
every(5 * 60_000, () => {
  closeFinishedHourlyBuckets();
  closeFinishedHourlyCountryBuckets();
}, 'hourly-close');

// ─── API ─────────────────────────────────────────────────────────────────────
const send = (res, code, data) => {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
};

/**
 * Read a JSON request body. Only two endpoints need one (custom rules YAML,
 * vhost-rules map) — everything else in this API takes query-string params,
 * which is fine for short scalar values but not for a multi-line YAML blob
 * or an arbitrarily-sized vhost map.
 */
// Fix (audit report, Basse/Analyzer, "readJsonBody ne se resout jamais
// au-dela de 2 Mo"): the size guard called `req.destroy()` but never
// resolved the promise itself — destroying a request mid-stream does not
// reliably raise 'error' on THIS end (it can just end via 'close'/'aborted'
// with neither 'end' nor 'error' ever firing here), so a body over the cap
// left the caller's `await readJsonBody(req)` hanging forever. It also reset
// the client's connection while it was still sending, which is a needlessly
// hostile way to say "too large" to an otherwise well-behaved caller. The
// promise now settles (once — see `settled`) the moment the cap is crossed,
// and further bytes are drained (not accumulated) instead of destroying the
// socket — the client still gets a clean HTTP response once its request
// finishes uploading, it is simply ignored rather than parsed.
function readJsonBody(req) {
  return new Promise((resolve) => {
    let data = '';
    let overCap = false;
    let settled = false;
    const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
    req.on('data', chunk => {
      if (overCap) return;
      data += chunk;
      if (data.length > 2_000_000) { overCap = true; data = ''; finish({}); }
    });
    req.on('end', () => { try { finish(JSON.parse(data || '{}')); } catch { finish({}); } });
    req.on('error', () => finish({}));
  });
}

/**
 * Fix (audit report, Basse/Analyzer, "limit=-1 renvoie toute la table"):
 * every one of these `limit` query parameters eventually reaches a raw SQL
 * `LIMIT ?` (see lib/store.js) — and SQLite treats a NEGATIVE limit as "no
 * limit at all", not as an error or as zero. `+url.searchParams.get('limit')
 * || 100` only ever replaces a value that is falsy (0, NaN, missing) with
 * the default; `-1` is truthy and sailed straight through as a literal SQL
 * "give me everything", against a table that can hold a long history of
 * alerts/WAF events/blocklist hits. Every limit read from a query string
 * now goes through this clamp instead.
 */
function clampLimit(raw, def, max, min = 1) {
  const n = Math.trunc(Number(raw));
  if (!Number.isFinite(n) || raw === null || raw === '') return def;
  return Math.max(min, Math.min(max, n));
}

const window = url => {
  const to = +url.searchParams.get('to') || Date.now();
  const hours = +url.searchParams.get('hours') || 24;
  return { from: +url.searchParams.get('from') || to - hours * 3_600_000, to };
};

/**
 * Constant-time string comparison — a plain `===` on the token would leak
 * how many leading bytes matched through response timing, letting a
 * network-adjacent attacker brute-force the token byte by byte.
 */
function tokensMatch(a, b) {
  const bufA = Buffer.from(String(a)), bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return require('crypto').timingSafeEqual(bufA, bufB);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  try {
    if (p === '/api/health') {
      return send(res, 200, { ok: true, uptime: process.uptime() });
    }

    // Fix (audit finding ANA-10): see CONFIG.token's comment above.
    if (CONFIG.token && !tokensMatch(req.headers['x-analyzer-token'] || '', CONFIG.token)) {
      return send(res, 401, { error: 'unauthorized' });
    }

    if (p === '/api/status') {
      const wafStatus = wafTailer.status();
      return send(res, 200, {
        version: '1.0.0',
        config: {
          logsDir: CONFIG.logsDir, dbPath: CONFIG.dbPath,
          learningDays: CONFIG.learningDays, sigma: CONFIG.sigma,
          countrySigma: CONFIG.countrySigma, countryMinRequests: CONFIG.countryMinRequests,
        },
        tail: tailer.status(),
        wafTail: wafStatus,
        blocklistTail: blocklistTailer.status(),
        blocklistSources: { mode: blocklistSources.getMode(), synced: blocklistSources.hasSources() },
        // Surfaced at the top level, not buried in per-file counters: a WAF
        // log producing lines but almost nothing parsed usually means the
        // wrong SecAuditLogFormat, and looks identical to "no attacks" unless
        // something says otherwise.
        wafWarnings: wafStatus.following
          .filter(f => f.suspectFormat)
          .map(f => ({ file: f.file, vhost: f.vhost, lines: f.lines, dropped: f.dropped })),
        // Fix (audit finding ANA-02, suggested companion warning): "zero
        // files followed" and "no traffic at all" are otherwise
        // indistinguishable in the UI — the first is a configuration
        // mismatch (wrong LOG_PATTERN or logsDir), the second is normal on a
        // quiet site. Surfaced explicitly so the dashboard can tell them
        // apart rather than just showing an empty Analyse page.
        accessLogPatternWarning: tailer.status().files === 0,
        waf: store.wafStats(),
        detector: detector.stats(),
        baseline: baseline.stats(),
        countryBaseline: countryBaseline.stats(),
        store: store.stats(),
        geoip: geoip.status(),
        memoryMb: +(process.memoryUsage().rss / 1048576).toFixed(1),
      });
    }

    if (p === '/api/alerts' && req.method === 'GET') {
      return send(res, 200, store.listAlerts({
        limit:    clampLimit(url.searchParams.get('limit'), 100, 500),
        offset:   Math.max(0, +url.searchParams.get('offset') || 0),
        type:     url.searchParams.get('type') || null,
        severity: url.searchParams.get('severity') || null,
        since:    +url.searchParams.get('since') || null,
        // Fix (audit finding ANA-08): a caller doing a full catch-up sweep
        // passes sinceId + order=asc instead of since=<ts>, so a backlog
        // larger than `limit` is paged through oldest-first rather than
        // silently truncated to the newest `limit` alerts. See
        // Store.listAlerts()'s own comment for the full reasoning.
        sinceId:  +url.searchParams.get('sinceId') || null,
        order:    url.searchParams.get('order') === 'asc' ? 'asc' : 'desc',
        acked:    url.searchParams.get('acked') === '1' ? true
                : url.searchParams.get('acked') === '0' ? false : null,
      }));
    }

    if (p.startsWith('/api/alerts/') && p.endsWith('/ack') && req.method === 'POST') {
      const id = +p.split('/')[3];
      return send(res, 200, { ok: store.ackAlert(id) });
    }

    if (p === '/api/alerts/ack-all' && req.method === 'POST') {
      return send(res, 200, store.ackAllAlerts({
        type:     url.searchParams.get('type') || null,
        severity: url.searchParams.get('severity') || null,
        vhost:    url.searchParams.get('vhost') || null,
      }));
    }

    if (p === '/api/alerts/clear' && req.method === 'POST') {
      return send(res, 200, store.clearAlerts({
        type:     url.searchParams.get('type') || null,
        severity: url.searchParams.get('severity') || null,
        vhost:    url.searchParams.get('vhost') || null,
      }));
    }

    if (p === '/api/traffic/series') {
      const { from, to } = window(url);
      return send(res, 200, {
        grain: url.searchParams.get('grain') || 'minute',
        series: store.series(url.searchParams.get('grain') || 'minute', from, to,
                             url.searchParams.get('vhost') || null),
      });
    }

    if (p === '/api/traffic/countries') {
      const { from, to } = window(url);
      return send(res, 200, { countries: store.byCountry(from, to, url.searchParams.get('vhost') || null) });
    }

    /**
     * Human vs bot breakdown, with the bot sub-categories, over a window —
     * for a stat card on the Analyse page and its hover detail. Real
     * aggregated history, unlike the live map's small in-memory buffer:
     * this is backed by the same bucket/rollup retention as every other
     * traffic figure.
     */
    if (p === '/api/traffic/bots') {
      const { from, to } = window(url);
      const rows = store.byBotCategory(from, to, url.searchParams.get('vhost') || null);
      const total = rows.reduce((a, r) => a + r.requests, 0);
      const bots = rows.filter(r => r.category !== 'human').reduce((a, r) => a + r.requests, 0);
      return send(res, 200, {
        total, human: total - bots, bots,
        byCategory: rows,
      });
    }

    /** Human/bot split per vhost — extra columns for the Analyse page's own vhost table. */
    if (p === '/api/traffic/bots/vhosts') {
      const { from, to } = window(url);
      return send(res, 200, { vhosts: store.botByVhost(from, to) });
    }

    /** Same, per country — extra columns for the countries table. */
    if (p === '/api/traffic/bots/countries') {
      const { from, to } = window(url);
      return send(res, 200, { countries: store.botByCountry(from, to, url.searchParams.get('vhost') || null) });
    }

    /**
     * Recent geo-located requests, for a live map's pulses.
     *
     * Fix (audit finding ANA-09): the cursor used to be `since`, either the
     * caller's clock or (in a first attempt at fixing clock skew between
     * browser and container) this server's own wall clock at the time of
     * the PREVIOUS response — compared against `entry.ts`, the log line's
     * own timestamp (1s precision, and written to recentGeoEvents only once
     * the tailer's next poll notices it). Those two clocks disagree just
     * enough to lose events: an entry can be pushed to the buffer with a
     * log timestamp measured before the previous response's serverTime,
     * simply because the tailer read it a little late — the next poll's
     * `since=<that serverTime>` cutoff then excludes it forever, even
     * though the client never actually saw it.
     *
     * `sinceSeq` sidesteps clocks entirely: every event gets a strictly
     * increasing ingestion sequence number when it is pushed (geoSeq
     * above), and the filter is "sequence number greater than the last one
     * you were sent" — true regardless of what timestamp is on the event or
     * how delayed the tailer was. `currentSeq` in the response lets a fresh
     * page load adopt "now" (the current sequence position) without
     * drawing anything, the same role `serverTime` used to play.
     *
     * `since` (epoch ms) is still accepted, for a first load with no cursor
     * yet: a max-age cutoff still applies there, since the buffer can hold
     * events far older than "recent" if traffic has been light, and without
     * this bound a first load would replay whatever stale snapshot happens
     * to be in the buffer. Empty and harmless when GeoIP isn't configured —
     * every request is simply skipped upstream in that case, never an error
     * here.
     */
    if (p === '/api/traffic/recent') {
      const sinceSeq = +url.searchParams.get('sinceSeq') || 0;
      const since = +url.searchParams.get('since') || 0;
      const limit = clampLimit(url.searchParams.get('limit'), 200, RECENT_GEO_MAX);
      const vhost = url.searchParams.get('vhost') || null;
      let events;
      if (sinceSeq) {
        events = recentGeoEvents.filter(e => e.seq > sinceSeq);
      } else {
        const cutoff = since || (Date.now() - RECENT_GEO_MAX_AGE_MS);
        events = recentGeoEvents.filter(e => e.ts > cutoff);
      }
      if (vhost) events = events.filter(e => e.vhost === vhost);
      return send(res, 200, {
        events: events.slice(-limit),
        geoipAvailable: geoip.status().available,
        serverTime: Date.now(),
        currentSeq: geoSeq,
      });
    }

    if (p === '/api/traffic/vhosts') {
      const { from, to } = window(url);
      return send(res, 200, { vhosts: store.byVhost(from, to) });
    }

    if (p === '/api/exceptions' && req.method === 'GET') {
      return send(res, 200, { exceptions: store.listExceptions(url.searchParams.get('vhost') || null) });
    }

    if (p === '/api/exceptions' && req.method === 'POST') {
      const vhost = url.searchParams.get('vhost');
      const ip    = url.searchParams.get('ip');
      if (!vhost || !ip) return send(res, 400, { error: 'vhost and ip required' });
      const r = store.addException({
        vhost, ip,
        reason: url.searchParams.get('reason') || '',
        author: url.searchParams.get('author') || '',
      });
      // Prise en compte immediate, sans attendre le prochain cycle.
      detector.setExceptions(store.listExceptions());
      return send(res, r.ok ? 200 : 400, r);
    }

    if (p.startsWith('/api/exceptions/') && req.method === 'DELETE') {
      const id = +p.split('/')[3];
      const ok = store.removeException(id);
      detector.setExceptions(store.listExceptions());
      return send(res, 200, { ok });
    }

    // ── Regles : catalogue, activation/desactivation, regles personnalisees ──
    if (p === '/api/rules' && req.method === 'GET') {
      // Config reelle de chaque regle integree (pas seulement le texte
      // explicatif statique) : la modale "Regles" du dashboard peut ainsi
      // afficher les vrais seuils actifs (ex. "600 requetes / 5 min"), qui
      // varient selon les variables d environnement ANALYZER_*/FLOOD_MIN_REQUESTS/etc.
      return send(res, 200, rulesManager.catalog(EXPLANATIONS, {
        windowMs: detector.cfg.windowMs,
        bruteforce: detector.cfg.bruteforce,
        scan: detector.cfg.scan,
        flood: detector.cfg.flood,
        scraping: detector.cfg.scraping,
        volumetric: baseline.cfg,
        country_traffic: countryBaseline.cfg,
      }));
    }

    /** Enable/disable one built-in rule (bruteforce, scan, flood, scraping, volumetric, country_traffic). */
    if (p === '/api/rules/toggle' && req.method === 'POST') {
      const key = url.searchParams.get('key');
      const enable = url.searchParams.get('enable') !== '0' && url.searchParams.get('enable') !== 'false';
      if (!rulesManager.toggle(key, enable)) return send(res, 400, { error: `Regle inconnue : ${key}` });
      // Repercute immediatement sur les moteurs concernes, sans attendre un
      // redemarrage — meme principe que les exceptions plus haut.
      if (key === 'bruteforce' || key === 'scan' || key === 'flood' || key === 'scraping') {
        detector.cfg[key].enable = enable;
      } else if (key === 'volumetric') {
        baseline.cfg.enable = enable;
      } else if (key === 'country_traffic') {
        countryBaseline.cfg.enable = enable;
      }
      return send(res, 200, { ok: true, key, enabled: enable });
    }

    /**
     * "Blocklist a la CrowdSec" (v12.50.0) : config threshold/window/
     * remediation/remediation_minutes de CHAQUE regle integree ayant opte
     * (threshold configure) + de chaque regle personnalisee (deja portee par
     * sa propre entree YAML, voir lib/rules-yaml.js) — voir
     * RulesManager.listBlocklistRules(). C est tout ce dont
     * nginx-dashboard/features/blocklists.js a besoin pour calculer les IP
     * suspectes, sans avoir a distinguer regle integree/personnalisee.
     */
    if (p === '/api/rules/blocklist-config' && req.method === 'GET') {
      return send(res, 200, { rules: rulesManager.listBlocklistRules() });
    }

    /** Set one builtin rule's blocklist threshold/window/remediation/remediation duration. */
    if (p === '/api/rules/blocklist' && req.method === 'POST') {
      const key = url.searchParams.get('key');
      const body = await readJsonBody(req);
      const result = rulesManager.setBlocklistConfig(key, {
        threshold: body?.threshold,
        windowMinutes: body?.windowMinutes,
        remediation: body?.remediation === true,
        remediationMinutes: body?.remediationMinutes,
        remediationType: body?.remediationType,
      });
      if (!result.ok) return send(res, 400, result);
      return send(res, 200, { ok: true, key, value: result.value });
    }

    /** Raw YAML of the custom rules, for the editor's textarea. */
    if (p === '/api/rules/custom' && req.method === 'GET') {
      return send(res, 200, {
        yaml: rulesManager.customYaml || RulesManager.template(),
        errors: rulesManager.customErrors,
      });
    }

    /** Replace the custom rules. Rejected wholesale on any syntax/validation error — never a partial apply. */
    if (p === '/api/rules/custom' && req.method === 'PUT') {
      const body = await readJsonBody(req);
      const result = rulesManager.setCustomYaml(String(body?.yaml ?? ''));
      if (!result.ok) return send(res, 400, result);
      detector.setCustomRules(rulesManager.customValid);
      return send(res, 200, result);
    }

    /**
     * Pushed by the dashboard (features/analyzer.js), derived from the vhost
     * files' own comments — see lib/vhost-targets.js on that side:
     *   # nginx-control-analyze: off
     *   # nginx-control-analyze-ignore-rules: 1, 2, 4
     * In-memory only here: the vhost files are the source of truth and the
     * dashboard re-sends this on every poll cycle, so nothing is lost by not
     * persisting it across a restart.
     */
    if (p === '/api/vhost-rules' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const map = rulesManager.setVhostRules(body?.vhosts || {});
      detector.setVhostRules(map);
      return send(res, 200, { ok: true, count: map.size });
    }

    /**
     * Pushed by the dashboard (features/blocklists.js's pushBlocklistSources(),
     * v12.29.0), on the same periodic cycle as /api/vhost-rules above: each
     * enabled source's own IP/CIDR list plus which hit_logging_method is
     * configured. In-memory only, exactly like vhost-rules — the dashboard's
     * blocklist cache is the source of truth and re-sends this every cycle,
     * so a restarted analyzer just has no attribution/approx-detection until
     * the next push (typically within a minute) rather than stale data.
     * Body: { mode: 'dedicated'|'approx', sources: { [name]: { ips: [...] } } }.
     */
    if (p === '/api/blocklist-sources' && req.method === 'POST') {
      const body = await readJsonBody(req);
      blocklistSources.setMode(body?.mode);
      blocklistSources.setSources(body?.sources || {});
      return send(res, 200, { ok: true, mode: blocklistSources.getMode() });
    }

    if (p === '/api/baseline') {
      return send(res, 200, baseline.stats());
    }

    if (p === '/api/baseline/country') {
      return send(res, 200, countryBaseline.stats());
    }

    // v12.68.0 : ce que la baseline a appris (resume par cle, profil des 168 creneaux).
    if (p === '/api/baseline/keys') {
      const b = url.searchParams.get('type') === 'country' ? countryBaseline : baseline;
      return send(res, 200, { keys: b.keysSummary(100) });
    }
    if (p === '/api/baseline/profile') {
      const b = url.searchParams.get('type') === 'country' ? countryBaseline : baseline;
      const key = String(url.searchParams.get('key') || '').slice(0, 253);
      if (!key) return send(res, 400, { error: 'key required' });
      return send(res, 200, b.profile(key));
    }

    // ── ModSecurity / WAF ────────────────────────────────────────────────────
    if (p === '/api/waf/events' && req.method === 'GET') {
      return send(res, 200, store.listWaf({
        limit:    clampLimit(url.searchParams.get('limit'), 100, 500),
        offset:   Math.max(0, +url.searchParams.get('offset') || 0),
        vhost:    url.searchParams.get('vhost') || null,
        severity: url.searchParams.get('severity') || null,
        blocked:  url.searchParams.get('blocked') === '1' ? true
                : url.searchParams.get('blocked') === '0' ? false : null,
        since:    +url.searchParams.get('since') || null,
      }));
    }

    // One full event, including its raw original line and per-rule
    // explanations — the detail view a "voir la ligne complete" modal opens.
    if (p.startsWith('/api/waf/events/') && req.method === 'GET') {
      const id = +p.split('/')[4];
      const ev = store.getWafEvent(id);
      if (!ev) return send(res, 404, { error: 'Not found' });
      return send(res, 200, {
        ...ev,
        rules: ev.ruleIds.map(id => ({ ruleId: id, ...waf.categorize(id), referenceUrl: waf.referenceUrl(id) })),
      });
    }

    if (p === '/api/waf/top-rules') {
      const { from, to } = window(url);
      return send(res, 200, { rules: store.wafTopRules(from, to, url.searchParams.get('vhost') || null) });
    }

    if (p === '/api/waf/top-ips') {
      const { from, to } = window(url);
      return send(res, 200, { ips: store.wafTopIps(from, to, url.searchParams.get('vhost') || null) });
    }

    if (p === '/api/waf/series') {
      const { from, to } = window(url);
      return send(res, 200, { series: store.wafSeries(from, to, url.searchParams.get('vhost') || null) });
    }

    // Manual purge, filtered or total — distinct from the automatic
    // age-based retention that runs on its own timer.
    if (p === '/api/waf/clear' && req.method === 'POST') {
      return send(res, 200, store.clearWaf({
        vhost:    url.searchParams.get('vhost') || null,
        severity: url.searchParams.get('severity') || null,
        blocked:  url.searchParams.get('blocked') === '1' ? true
                : url.searchParams.get('blocked') === '0' ? false : null,
      }));
    }

    // ── Blocklist hits ─────────────────────────────────────────────────────
    // A global window summary — how many hits, how many distinct IPs, which
    // IPs hit most, and (v12.29.0) a per-source breakdown — for
    // nginx-dashboard's Digest and effectiveness measurement. Works under
    // either hit_logging_method: "dedicated" hits arrive via blocklistTailer
    // below, "approx" hits are recorded straight from the main access-log
    // tailer above — this route does not need to know which. Attribution to
    // a specific source used to require the dashboard to cross-reference
    // these IPs against its own IP/CIDR cache on every request; now that the
    // dashboard pushes that same cache here (see /api/blocklist-sources
    // above), the analyzer can compute it once, from data it already has.
    if (p === '/api/blocklist-hits/summary') {
      const { from, to } = window(url);
      const limit = clampLimit(url.searchParams.get('limit'), 500, 5000);
      const summary = store.blocklistHitsSummary(from, to, limit);
      const bySourceCounts = new Map();
      for (const { ip, count } of summary.topIps || []) {
        for (const name of blocklistSources.sourcesContaining(ip)) {
          bySourceCounts.set(name, (bySourceCounts.get(name) || 0) + count);
        }
      }
      summary.bySource = [...bySourceCounts.entries()]
        .map(([name, hits]) => ({ name, hits }))
        .sort((a, b) => b.hits - a.hits);
      return send(res, 200, summary);
    }

    if (p === '/api/blocklist-hits/check') {
      const ip = url.searchParams.get('ip');
      if (!ip || !cidr.isValidPattern(ip)) return send(res, 400, { error: 'ip invalide' });
      const { from, to } = window(url);
      return send(res, 200, store.blocklistHitsForIp(ip, from, to));
    }

    if (p === '/api/blocklist-hits/clear' && req.method === 'POST') {
      return send(res, 200, store.clearBlocklistHits());
    }

    // Mark an hour as normal so a legitimate spike stops counting against the
    // baseline — and stops being learned as if it were routine.
    if (p === '/api/baseline/exclude' && req.method === 'POST') {
      const vhost = url.searchParams.get('vhost');
      const hour  = url.searchParams.get('hour');
      if (!vhost || !hour) return send(res, 400, { error: 'vhost and hour required' });
      baseline.exclude(vhost, hour);
      store.setState('baseline', baseline.toJSON());
      return send(res, 200, { ok: true });
    }

    // Same, for a country-level slot flagged organic rather than a vhost's.
    if (p === '/api/baseline/country/exclude' && req.method === 'POST') {
      const country = url.searchParams.get('country');
      const hour    = url.searchParams.get('hour');
      if (!country || !hour) return send(res, 400, { error: 'country and hour required' });
      countryBaseline.exclude(country, hour);
      store.setState('country_baseline', countryBaseline.toJSON());
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(`[api] ${p}:`, e);
    return send(res, 500, { error: e.message });
  }
});

// ─── Boot ────────────────────────────────────────────────────────────────────
geoip.init();
detector.setExceptions(store.listExceptions());
detector.setVhostRules(rulesManager.vhostRules);
tailer.start();
wafTailer.start();
blocklistTailer.start();

server.listen(CONFIG.port, () => {
  console.log(`[nginx-analyzer] :${CONFIG.port}`);
  console.log(`  Logs      : ${CONFIG.logsDir} (${CONFIG.logPattern})`);
  console.log(`  Base      : ${CONFIG.dbPath} (${store.persistent ? 'SQLite' : 'memoire seule'})`);
  console.log(`  GeoIP     : ${geoip.status().available ? geoip.status().database : 'indisponible'}`);
  const b = baseline.stats();
  console.log(`  Baseline  : ${b.learning ? `apprentissage ${b.daysElapsed}/${b.daysRequired} j` : 'active'}, ${b.coverage}% des creneaux`);
  const cb = countryBaseline.stats();
  console.log(`  Base.pays : ${cb.learning ? `apprentissage ${cb.daysElapsed}/${cb.daysRequired} j` : 'active'}, ${cb.coverage}% des creneaux`);
  console.log(`  WAF       : ${CONFIG.wafLogPattern} (${wafTailer.status().files} fichier(s))`);
  console.log(`  Blocklist : ${CONFIG.blocklistLogPattern} (${blocklistTailer.status().files} fichier(s))`);
});

// Flush pending minute buckets before exiting, or the last minutes are lost
// (store.close() -> store.flush()). The in-progress hour buckets above are
// deliberately NOT flushed here (fix, audit finding ANA-07): they are not
// yet complete, and observe()-ing a partial hour risks counting the same
// real hour twice in the baseline's history if the process comes back up
// within it — see hourlyByHour's comment for the full reasoning. Losing an
// in-progress hour's structural signal to a restart is an acceptable, small
// gap; corrupting the learned baseline on every restart is not.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`[nginx-analyzer] ${sig}, arret`);
    try { store.close(); } catch {}
    process.exit(0);
  });
}
