'use strict';
/**
 * CrowdSec LAPI — ban, unban, and read-only allowlist visibility.
 *
 * The bouncer API key already used elsewhere in this dashboard (X-Api-Key) is
 * read-only by design in CrowdSec's security model: a bouncer's job is to
 * enforce decisions, not create or delete them. A compromised remediation
 * component must not be able to unban attackers or ban arbitrary addresses
 * network-wide. Ban/unban require a "machine" (watcher) identity instead —
 * the same credential type `cscli` itself uses — obtained once via
 * `cscli machines add <name> --password <secret>` on the CrowdSec host —
 * never `--auto`, which generates a password the operator is never shown,
 * making the resulting machine permanently unusable from here — and usable
 * over plain HTTPS afterwards, exactly like the bouncer key already is.
 *
 * Authentication is a short-lived JWT obtained from POST /v1/watchers/login
 * and refreshed lazily on expiry or on a 401.
 *
 * The Alert payload shape POST /v1/alerts expects to create a manual ban
 * (decisions have no direct "create" endpoint of their own — they are always
 * attached to an Alert, mirroring what `cscli decisions add` sends
 * internally), and the Decision shape for unban filters, are both CONFIRMED
 * against the LAPI's own published Swagger/OpenAPI spec, obtained directly
 * from an operator's CrowdSec instance — not guessed. A first attempt at the
 * Alert shape omitted the `events` array entirely (sending only a derived
 * count), which the LAPI rejects outright; the fields sent now match the
 * spec's required list exactly (scenario, scenario_hash, scenario_version,
 * message, events_count, start_at, stop_at, capacity, leakspeed, simulated,
 * events, source), plus `decisions` to actually produce a ban, and
 * `remediation`/`labels`/`meta` — valid per the spec though not marked
 * required there.
 *
 * Allowlist management (create a list, add or remove an entry) is CONFIRMED
 * ABSENT from the LAPI entirely: its spec defines only GET on `/allowlists`
 * and `/allowlists/{name}` (plus a membership-check endpoint), no POST, PUT
 * or DELETE anywhere in that section. A `console_managed` field on each
 * allowlist in that same spec confirms why — a centralized allowlist is
 * created and edited via `cscli` or the CrowdSec Console, and the LAPI only
 * ever exposes it for reading. The functions below that used to attempt
 * creation/edit over HTTP now fail immediately, without a network round trip
 * to a route that was always going to answer 405.
 */

const http  = require('http');
const https = require('https');

const cfg = require('./config');
const { getCrowdsecCfg } = require('./crowdsec-cfg');

// CrowdSec logs "bad user agent ''" and its LAPI applies stricter validation
// to the watcher (machine) login than to bouncer reads — a request with no
// User-Agent at all can succeed against /v1/decisions while still being
// rejected on /v1/watchers/login. Node's http/https client sends none by
// default unless one is set explicitly, which this module previously never
// did.
const USER_AGENT = cfg.HTTP_USER_AGENT;

function machineConfigured() {
  const c = getCrowdsecCfg();
  return !!(c.url && c.machineId && c.machinePassword);
}

// ─── Low-level transport ─────────────────────────────────────────────────────
/**
 * One HTTP round-trip to the LAPI. Kept separate from every function that
 * builds a request, so the request-building logic (what tests actually check)
 * does not need a live server to exercise.
 */
function lapiRequest(method, endpoint, { body = null, token = null } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(getCrowdsecCfg().url.replace(/\/$/, '') + endpoint); }
    catch (e) { return reject({ error: 'Invalid CROWDSEC_URL', message: e.message }); }
    const proto = url.protocol === 'https:' ? https : http;
    const payload = body !== null ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

    const req = proto.request({
      hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search, method, headers, timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        let parsed = null;
        if (data) { try { parsed = JSON.parse(data); } catch { parsed = data; } }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', e => reject({ error: e.message }));
    req.on('timeout', () => { req.destroy(); reject({ error: 'CrowdSec LAPI timeout' }); });
    if (payload) req.write(payload);
    req.end();
  });
}

// ─── Machine authentication ──────────────────────────────────────────────────
let cachedToken = null;
let cachedExpiry = 0;

/** Reset the cached token — used by tests and after an auth failure. */
function clearTokenCache() { cachedToken = null; cachedExpiry = 0; }

/**
 * A valid bearer token, logging in again when the cache is empty or about to
 * expire. A minute of slack avoids a request racing against expiry mid-flight.
 */
async function getMachineToken(request = lapiRequest) {
  if (cachedToken && Date.now() < cachedExpiry - 60_000) return cachedToken;
  if (!machineConfigured()) {
    throw { error: 'CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD not configured',
            hint: "Run 'cscli machines add <name> --password <secret>' on the CrowdSec host once (not --auto: its generated password is never shown to the operator)." };
  }
  const c = getCrowdsecCfg();
  const r = await request('POST', '/v1/watchers/login', {
    body: { machine_id: c.machineId, password: c.machinePassword },
  });
  if (r.status !== 200 || !r.body?.token) {
    throw { error: 'CrowdSec machine login failed', status: r.status, body: r.body };
  }
  cachedToken = r.body.token;
  // `expire` is an ISO timestamp in the documented response; fall back to a
  // conservative 4-hour assumption if a future LAPI version omits it, rather
  // than caching a token forever on a guess.
  const expireAt = r.body.expire ? Date.parse(r.body.expire) : NaN;
  cachedExpiry = Number.isFinite(expireAt) ? expireAt : Date.now() + 4 * 3600_000;
  return cachedToken;
}

/** An authenticated LAPI call as the machine identity, retrying once on 401. */
async function machineRequest(method, endpoint, body, request = lapiRequest) {
  const token = await getMachineToken(request);
  let r = await request(method, endpoint, { body, token });
  if (r.status === 401) {
    clearTokenCache();
    const fresh = await getMachineToken(request);
    r = await request(method, endpoint, { body, token: fresh });
  }
  return r;
}

// ─── Duration parsing ────────────────────────────────────────────────────────
/**
 * CrowdSec expects a Go duration string ("4h0m0s"), not a human one. Accepts
 * a small set of simple suffixed inputs ("30m", "4h", "7d") and normalizes
 * them, rather than trusting free-form operator input straight into the LAPI.
 */
function toGoDuration(input) {
  const m = /^(\d+)\s*(m|h|d)$/i.exec(String(input).trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  if (unit === 'm') return `${n}m0s`;
  if (unit === 'h') return `${n}h0m0s`;
  return `${n * 24}h0m0s`;
}

// ─── Ban / unban ──────────────────────────────────────────────────────────────
/**
 * Create a manual ban. Decisions have no standalone "create" endpoint in the
 * LAPI — they are always attached to an Alert, which is how `cscli decisions
 * add` itself works under the hood. This assembles the minimal Alert shape a
 * manual ban needs.
 *
 * ASSUMPTION (unverified against live docs, see module header): the exact
 * field set below. If a CrowdSec version rejects it, the LAPI's own 4xx body
 * — returned as `r.body` here — names the missing or invalid field directly.
 */
async function banIp({ ip, duration = '4h', reason = 'Manual ban from nginx-dashboard' }, request = lapiRequest) {
  const goDuration = toGoDuration(duration);
  if (!goDuration) throw { error: `Invalid duration "${duration}" — use e.g. "30m", "4h", "7d"` };
  if (!ip || typeof ip !== 'string') throw { error: 'ip is required' };

  const now = new Date().toISOString();
  const alert = {
    scenario: "manual 'ban' from nginx-dashboard",
    scenario_hash: '', scenario_version: '',
    message: reason, events_count: 1,
    start_at: now, stop_at: now,
    // capacity/leakspeed describe a scenario's overflow bucket. A manual ban
    // has no such bucket, but an empty leakspeed string is not a valid Go
    // duration ("" fails time.ParseDuration, unlike "0s") — if CrowdSec's
    // alert ingestion parses it without checking that error, an empty string
    // here is a plausible cause of an unhandled server-side panic (a 500,
    // rather than a clean 4xx validation failure).
    capacity: 0, leakspeed: '0s', simulated: false,
    source: { scope: 'Ip', value: ip, ip },
    // Confirmed required by the LAPI itself: an alert with only events_count
    // (a derived total) and no `events` array is rejected outright with
    // "validation Failure: events in body is required". One minimal event
    // describing the ban action satisfies that requirement; CrowdSec's own
    // Meta model is a list of {key, value} pairs rather than a flat object,
    // which is what a real alert generated by a scenario would also send.
    events: [{
      timestamp: now,
      meta: [{ key: 'source_ip', value: ip }],
    }],
    // The three fields below are not confirmed required — no validation error
    // has named them — but they are part of the LAPI's own published Alert
    // schema (retrieved directly from its Swagger UI), so they are matched
    // here rather than omitted on a guess:
    //   - remediation: whether this alert is meant to produce an enforced
    //     decision. A manual ban plainly is, so true rather than the zero
    //     value.
    //   - labels / meta (alert-level, distinct from the per-event meta
    //     above): both arrays in the schema; empty ones match the shape
    //     without inventing content this project has no basis for.
    remediation: true,
    labels: [],
    meta: [],
    decisions: [{
      duration: goDuration, scope: 'Ip', value: ip, type: 'ban',
      origin: 'cscli', scenario: "manual 'ban' from nginx-dashboard",
    }],
  };
  const r = await machineRequest('POST', '/v1/alerts', [alert], request);
  if (r.status !== 201 && r.status !== 200) {
    throw { error: 'Ban request rejected by CrowdSec', status: r.status, body: r.body };
  }
  return { ok: true, alertIds: r.body };
}

/** Remove a decision by its numeric id. */
async function unbanDecisionId(id, request = lapiRequest) {
  const r = await machineRequest('DELETE', `/v1/decisions/${encodeURIComponent(id)}`, null, request);
  if (r.status !== 200) throw { error: 'Unban rejected by CrowdSec', status: r.status, body: r.body };
  return { ok: true, ...r.body };
}

/** Remove every decision matching an address — a ban can have more than one. */
async function unbanIp(ip, request = lapiRequest) {
  if (!ip) throw { error: 'ip is required' };
  const r = await machineRequest('DELETE', `/v1/decisions?ip=${encodeURIComponent(ip)}`, null, request);
  if (r.status !== 200) throw { error: 'Unban rejected by CrowdSec', status: r.status, body: r.body };
  return { ok: true, ...r.body };
}

// ─── Centralized allowlists ──────────────────────────────────────────────────
/**
 * ASSUMPTION (unverified — see module header): centralized allowlists are a
 * newer LAPI feature and this project could not reach
 * docs.crowdsec.net/docs/local_api/centralized_allowlists to confirm the
 * current paths and payload shape against a specific CrowdSec version. The
 * endpoints below follow the most consistent reading available without that
 * access. Any mismatch should surface as a clear 4xx from the LAPI — every
 * function returns `r.body` verbatim on failure so that response is visible
 * rather than swallowed.
 */
async function listAllowlists(request = lapiRequest) {
  const r = await machineRequest('GET', '/v1/allowlists', null, request);
  if (r.status !== 200) throw { error: 'Could not list allowlists', status: r.status, body: r.body };
  const lists = Array.isArray(r.body) ? r.body : [];

  // The collection endpoint plausibly returns summaries only (name,
  // description, item count) rather than the actual entries — a common REST
  // split between a list view and a detail view. An operator reported adding
  // an address successfully but never seeing it appear anywhere afterwards,
  // which matches that shape exactly: the UI reads `list.items`, and if the
  // collection response never populates it, nothing renders with no error at
  // all. For any list missing a populated `items` array here, its detail is
  // fetched separately and merged in; a list that already includes its items
  // in the collection response just makes one redundant, harmless call.
  await Promise.all(lists.map(async (list) => {
    if (Array.isArray(list.items) && list.items.length > 0) return;
    try {
      const d = await machineRequest('GET', `/v1/allowlists/${encodeURIComponent(list.name)}`, null, request);
      if (d.status === 200 && d.body && Array.isArray(d.body.items)) list.items = d.body.items;
    } catch { /* leave items as-is (absent or empty) rather than fail the whole list */ }
  }));
  return lists;
}

/**
 * Confirmed absent from the LAPI (see module header): no POST, PUT or DELETE
 * exists anywhere under /allowlists in its published spec. These used to
 * attempt one anyway and get a 405 back after a full round trip; they now
 * fail immediately; with the actual reason, and no network call at all.
 */
function allowlistWriteUnsupported(action) {
  throw {
    error: `CrowdSec ne permet pas de ${action} par son API (LAPI) — confirme absent de son `
      + `schema publie : seul GET existe sur /allowlists. Une liste blanche centralisee se cree `
      + `et se modifie via 'cscli allowlists ...' sur l hote CrowdSec, ou via la Console si elle y `
      + `est geree ; le dashboard peut ensuite lister et afficher son contenu, mais pas l ecrire.`,
    status: 501,
  };
}

async function createAllowlist() { allowlistWriteUnsupported('creer une liste'); }
async function addAllowlistItem() { allowlistWriteUnsupported('ajouter une adresse a une liste'); }
async function removeAllowlistItem() { allowlistWriteUnsupported('retirer une adresse d une liste'); }

/**
 * Whether an address or range is covered by any allowlist — confirmed real
 * and read-only (GET /allowlists/check/{value}), a genuine complement to
 * listing allowlists: an operator can check one address directly rather than
 * scanning every list's contents by eye.
 */
async function checkAllowlist(value, request = lapiRequest) {
  if (!value) throw { error: 'value is required' };
  const r = await machineRequest('GET', `/v1/allowlists/check/${encodeURIComponent(value)}`, null, request);
  if (r.status !== 200) throw { error: 'Could not check allowlist membership', status: r.status, body: r.body };
  return r.body;
}

module.exports = {
  machineConfigured, lapiRequest, getMachineToken, machineRequest, clearTokenCache,
  toGoDuration, banIp, unbanDecisionId, unbanIp,
  listAllowlists, createAllowlist, addAllowlistItem, removeAllowlistItem, checkAllowlist,
};
