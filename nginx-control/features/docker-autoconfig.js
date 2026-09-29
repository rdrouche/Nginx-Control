'use strict';
/**
 * Auto-config Docker (labels façon Traefik) — orchestration de l'étape 1
 * "socle" : détection par poll des conteneurs portant les labels
 * `nginx-control.*`, génération d'un vhost nginx simple (HTTP, une ou
 * plusieurs locations, resolver Docker), test avant reload et rollback en
 * cas d'échec — exactement le pipeline déjà construit pour
 * features/blocklists.js (voir ce fichier pour le précédent : cache/
 * unchanged-detection/test-before-reload).
 *
 * Tout le parsing/validation/rendu pur vit dans lib/docker-autoconfig.js;
 * ce fichier ne fait que l'orchestration : lire les conteneurs Docker,
 * décider quoi générer, écrire, tester, recharger, et exposer les routes.
 *
 * Sécurité — "require_approval" (voir config/docker-autoconfig.yml) :
 * actif par défaut. Un `server_name` qui ne correspond à aucun motif de
 * `allowed_server_name_patterns` reste "en attente" tant qu'un opérateur ne
 * l'a pas approuvé explicitement dans le Dashboard — jamais appliqué
 * silencieusement. Un conflit de `server_name` (deux conteneurs, ou un
 * conteneur contre un vhost écrit à la main) n'est non plus jamais résolu en
 * silence : aucun des deux n'est appliqué tant que le conflit existe.
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');
const notify  = require('../lib/notify');
const { pushNotification } = require('../lib/notifications');
const { checkDomainConflict } = require('../lib/certs');
const { listSSLSnippets } = require('../lib/snippets');
const { parseAndValidate, matchesAnyPattern } = require('../lib/docker-autoconfig-yaml');
const { withLock } = require('../lib/nginx-write-lock');
const {
  parseContainerLabels, validateDesiredVhost, dockerVhostFileName, generateVhostContent,
  parseBackendUrl,
} = require('../lib/docker-autoconfig');

const { DIR_SITES, DOCKER_AUTOCONFIG_CONFIG_FILE } = cfg;
const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { logEvent } = events;
const { sendNotification } = notify;

const STATE_KEY = 'docker_autoconfig_state';
const FILE_PREFIX = 'docker_';
// Fix v12.21.2 (audit finding AGT-05, applied here too for consistency —
// same triggerCertbotIssuanceIfDue() shape as features/agents.js): minimum
// pause after a successful issuance before this key can trigger a new one.
const MIN_DELAY_AFTER_SUCCESS_MS = 10 * 60_000;
// Fix v12.21.2 (audit finding DAC-09): minimum delay between two
// notifications for the exact same recurring `nginx -t` failure.
const TEST_FAILURE_NOTIFY_COOLDOWN_MS = 15 * 60_000;

// ─── Deps (composition-root pattern, see server.js) ────────────────────────
// Certbot readiness is read through injected getters, never a direct
// `require('../features/certbot')` — features never import each other
// directly in this project, server.js is the sole wiring point (same
// pattern as deployFeature.setDeps({generatedFiles}) below). Defaulted to
// "always disabled" so a boot order that hasn't called setDeps() yet (or a
// test that doesn't) fails safe: certbot_http/certbot_dns are treated as
// not configured rather than silently skipping the check.
// issueHttp/issueDns default to a safe "not wired" stub — same fail-safe
// reasoning as the two getters above: a boot order (or a test) that never
// called setDeps() must never end up silently doing nothing while looking
// like it tried; the stub's error surfaces immediately in the issuance
// state's `lastError` instead.
let deps = {
  getCertbotCfg: () => ({ enable: false }),
  getCertbotDnsCfg: () => ({ enable: false }),
  issueHttp: async () => ({ error: 'issueHttp not wired (setDeps() missing)' }),
  issueDns: async () => ({ error: 'issueDns not wired (setDeps() missing)' }),
  // Fix (audit report, Basse/"Partie 1 et certificats"): the nginx webroot
  // path certbot's HTTP-01 challenge is served from — null (never rendered)
  // until Certbot's HTTP challenge is actually enabled upstream, same
  // fail-safe default as the getters above.
  getCertbotWebrootPath: () => null,
};
function setDeps(overrides = {}) { deps = { ...deps, ...overrides }; }

// Fix v12.21.2 (audit finding DAC-07, part 2): an 'issuing' entry that never
// resolved (the process restarted mid-emission, killing the in-flight
// certbotRunOnce() before its .then()/.catch() ever ran) would otherwise
// stay 'issuing' forever — resolveSsl() reports it as merely "pending,
// issuing in progress" indefinitely, and triggerCertbotIssuanceIfDue()
// refuses to start a new attempt for the same reason. Any 'issuing' entry
// older than this is treated as a failed attempt instead, which re-enters
// the normal failed/retryMinutes backoff path.
const STUCK_ISSUING_MS = 10 * 60_000;
function effectiveIssuanceEntry(entry) {
  if (entry?.status === 'issuing' && (Date.now() - (entry.lastAttemptAt || 0)) > STUCK_ISSUING_MS) {
    return { ...entry, status: 'failed', lastError: entry.lastError || 'emission bloquee (redemarrage du processus pendant l emission ?), consideree en echec' };
  }
  return entry;
}

// ─── Config ───────────────────────────────────────────────────────────────
function loadConfig() {
  let text = '';
  try { text = fs.readFileSync(DOCKER_AUTOCONFIG_CONFIG_FILE, 'utf8'); } catch { /* missing = defaults apply */ }
  return { text, ...parseAndValidate(text) };
}

/**
 * Persisted state: per-server_name approval decision, and the set of files
 * this feature currently manages — needed to know what to remove when a
 * container disappears or a decision changes, the same role
 * features/blocklists.js's cache plays for its own generated files.
 */
function loadState() {
  const s = events.getState(STATE_KEY);
  return { decisions: {}, generatedFiles: {}, ...(s || {}) };
}
function saveState(state) { events.setState(STATE_KEY, state); }

/**
 * Fix v12.21.2 (audit finding DAC-03): an approval decision, and the
 * "auto-allowed" pattern check, used to be keyed/tested on `serverNames[0]`
 * alone. A container declaring `server_name="app.internal.lan
 * bank.example.com"` with `bank.example.com` NOT matching
 * `allowed_server_name_patterns` was still auto-applied (only the first name
 * was tested), writing a vhost that serves BOTH names. Same problem for a
 * manual approval: approving `a.com` on a vhost that also carries `b.com`
 * silently approved `b.com` too. Decisions are now tied to the full,
 * sorted, lower-cased set of server_names — approving one name never
 * approves a different set (adding or removing a name to a container's
 * labels requires a fresh decision), and `settings.allowedServerNamePatterns`
 * must match EVERY name, not just the first.
 */
function namesDecisionKey(serverNames) {
  return [...serverNames].map(n => String(n || '').toLowerCase()).sort().join(',');
}

function atomicWrite(filePath, content) {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, filePath);
}

// ─── Docker inspection ────────────────────────────────────────────────────
/**
 * Fix v12.21.2 (audit finding DAC-01): this used to return `[]` for ANY
 * non-200 status (Docker daemon restarting, a transient 500/502 from a
 * socket-proxy, invalid JSON, `dockerCall()`'s own `status: 0` when the
 * socket is entirely unreachable — see lib/docker.js's own comment on why
 * it never rejects). runCycle() would then read that empty array as "every
 * previously-generated vhost's container is gone" and delete them all,
 * reload nginx, and take down every Docker-labeled site until the next
 * successful cycle. A transient Docker error must be reported as a FAILURE,
 * never conflated with "the daemon really has zero matching containers".
 */
async function listCandidateContainers() {
  const r = await docker.dockerCall('GET', '/containers/json?all=0');
  if (r.status !== 200 || !Array.isArray(r.body)) {
    const detail = r.error || (r.body && r.body.message) || `HTTP ${r.status}`;
    throw new Error(`Docker API injoignable ou en erreur (${detail})`);
  }
  return r.body;
}

/** Networks actually attached to the nginx container right now. */
async function getNginxAttachedNetworks() {
  try {
    const id = await docker.getContainerId();
    const r = await docker.dockerCall('GET', `/containers/${encodeURIComponent(id)}/json`);
    if (r.status === 200) return Object.keys(r.body?.NetworkSettings?.Networks || {});
  } catch { /* fall through */ }
  return [];
}

/**
 * Decide what to actually render for a candidate's SSL mode. This is the one
 * place that touches lib/certs.js (a filesystem read) and, for the
 * `certbot_http`/`certbot_dns` modes, the injected Certbot config getters —
 * which is why it lives here and not in the pure lib/docker-autoconfig.js.
 * See that module's generateVhostContent() header comment for the exact
 * shape expected back.
 *
 * certbot_http / certbot_dns : Certbot itself must be configured AND
 * activated upstream (`config/certbot.yml` / `config/certbot-dns.yml`'s own
 * `enable: true`) before a label can lean on it — this is data an operator
 * could get wrong independently of any Docker label (forgot to flip
 * `enable`, or never filled in credentials), and a vhost silently staying
 * on plain HTTP with no explanation would hide that misconfiguration
 * indefinitely. So the check runs on every cycle, not just once: `type:
 * 'error'` is returned for as long as Certbot stays disabled, surfaced both
 * in the generated file's header (see generateVhostContent()) and in
 * getStatus() below, so an operator sees it without opening a generated
 * file at all.
 *
 * Once Certbot is confirmed enabled, the domain is checked against existing
 * certificates exactly like `auto` (`checkDomainConflict()`) — a
 * certificate already issued (by hand, by the scheduler, or by a previous
 * manual "Emettre" from the Certbot page) is picked up and used immediately.
 * Actively TRIGGERING a new issuance from a Docker label — queuing a
 * certbot run, tracking its async completion — is not done here yet: until
 * that lands, a domain with no existing certificate resolves to `pending`
 * (plain HTTP, regenerated in HTTPS automatically once a certificate
 * appears — e.g. issued manually from the Certbot/Certbot-DNS pages), the
 * same as `auto` today.
 *
 * ACTIVE issuance triggering (v12.16.0): resolveSsl() itself stays pure and
 * read-only — it is called from BOTH runCycle() (which writes files and may
 * act on what it sees) and getStatus() (a read-only GET route, never
 * allowed to have side effects). Deciding whether to actually kick off a
 * certbot run lives entirely in runCycle()'s own
 * `triggerCertbotIssuanceIfDue()`, called only from there. `issuanceState`
 * (this function's third argument — the persisted `state.issuance` map,
 * see loadState()) only ever makes resolveSsl() report what is ALREADY
 * known: a real certbot error if the last attempt failed and the retry
 * backoff hasn't elapsed yet, so an operator sees the actual ACME failure
 * instead of an indefinite silent "pending". Omitting it (as every existing
 * caller/test predating this feature does) simply skips that detail —
 * still falls back to `pending`.
 */
function resolveSsl(validated, serverNames, issuanceState = {}) {
  if (!validated.ssl.active) return undefined;
  if (validated.ssl.mode === 'snippet') return { type: 'snippet', file: validated.ssl.snippetFile };
  if (validated.ssl.mode === 'auto') {
    // Fix v12.21.2 (audit finding DAC-04): pass every server_name so the
    // matched certificate must cover the WHOLE vhost, not just the first name.
    const result = checkDomainConflict(serverNames[0], { allNames: serverNames });
    if (result.conflict) {
      return {
        type: 'cert',
        certPath: `/etc/letsencrypt/live/${result.cert}/fullchain.pem`,
        keyPath: `/etc/letsencrypt/live/${result.cert}/privkey.pem`,
      };
    }
    return { type: 'pending' };
  }
  if (validated.ssl.mode === 'certbot_http' || validated.ssl.mode === 'certbot_dns') {
    const isDns = validated.ssl.mode === 'certbot_dns';
    const certbotCfg = isDns ? deps.getCertbotDnsCfg() : deps.getCertbotCfg();
    if (!certbotCfg?.enable) {
      return {
        type: 'error',
        code: isDns ? 'certbot_dns_disabled' : 'certbot_http_disabled',
        message: isDns
          ? "Certbot-DNS n est pas active (config/certbot-dns.yml : enable: false) — l activer et renseigner ses identifiants avant d utiliser ssl_certificate=certbot_dns."
          : "Certbot n est pas active (config/certbot.yml : enable: false) — l activer avant d utiliser ssl_certificate=certbot_http.",
      };
    }
    const result = checkDomainConflict(serverNames[0], { allNames: serverNames });
    if (result.conflict) {
      return {
        type: 'cert',
        certPath: `/etc/letsencrypt/live/${result.cert}/fullchain.pem`,
        keyPath: `/etc/letsencrypt/live/${result.cert}/privkey.pem`,
      };
    }
    const entry = effectiveIssuanceEntry(issuanceState[serverNames[0].toLowerCase()]);
    if (entry?.status === 'issuing') return { type: 'pending', issuing: true };
    if (entry?.status === 'failed') {
      return {
        type: 'error',
        code: 'certbot_issuance_failed',
        message: `Emission ${isDns ? 'Certbot-DNS' : 'Certbot'} echouee (tentative ${entry.attempts || 1}) : ${entry.lastError || 'erreur inconnue'} — nouvelle tentative automatique a la prochaine fenetre.`,
      };
    }
    return { type: 'pending' };
  }
  return undefined;
}

/**
 * Whether to fire an ASYNC certbot/certbot-dns issuance right now for `key`,
 * and does so — never awaited by the caller (runCycle()): a real issuance
 * can take up to ~2 minutes (see certbotRunOnce()'s own wait loop), and
 * blocking a detection cycle on that would delay every OTHER container's
 * vhost from being applied for as long as one certificate takes to issue.
 *
 * State machine, persisted in `state.issuance[key]` (survives a restart):
 *   - no entry, or entry.status === 'idle' → attempt now.
 *   - entry.status === 'issuing' → an attempt is already in flight for this
 *     exact key; never start a second one concurrently.
 *   - entry.status === 'failed' → only re-attempt once `retryMinutes` have
 *     elapsed since the last attempt — an ACME server has real rate limits
 *     (Let's Encrypt in particular), and retrying every single detection
 *     cycle (as often as every few seconds via Docker Events) would burn
 *     through them within minutes for one misconfigured domain.
 *
 * Marks the key 'issuing' and persists that BEFORE returning — not at the
 * end of runCycle(), which may return early (skippedNoChange) without ever
 * calling its own saveState() again, and this mutation must never be lost.
 * The eventual result (success/failure) is written back by re-loading a
 * FRESH state when the async call resolves, since runCycle() itself may
 * have already returned and moved on by then.
 */
function triggerCertbotIssuanceIfDue(key, mode, serverNames, state, retryMinutes) {
  state.issuance = state.issuance || {};
  // Fix v12.21.2 (audit finding DAC-07, part 2): a stuck 'issuing' entry
  // (process restarted mid-emission) is treated as 'failed' so it re-enters
  // the normal backoff path below instead of blocking retries forever.
  const entry = effectiveIssuanceEntry(state.issuance[key]);
  const now = Date.now();
  if (entry?.status === 'issuing') return;
  if (entry?.status === 'failed' && (now - (entry.lastAttemptAt || 0)) < retryMinutes * 60_000) return;
  if (entry?.status === 'idle' && (now - (entry.lastAttemptAt || 0)) < MIN_DELAY_AFTER_SUCCESS_MS) return;

  const attempts = (entry?.attempts || 0) + 1;
  state.issuance[key] = { status: 'issuing', lastAttemptAt: now, lastError: entry?.lastError || null, attempts };
  saveState(state);
  logEvent('docker-autoconfig.certbot_issue.start', { key, mode, attempts }, 'system');

  const issueFn = mode === 'certbot_dns' ? deps.issueDns : deps.issueHttp;
  Promise.resolve(issueFn(serverNames, { source: 'docker-autoconfig' }))
    .then(result => {
      const fresh = loadState();
      fresh.issuance = fresh.issuance || {};
      if (result && result.ok) {
        fresh.issuance[key] = { status: 'idle', lastAttemptAt: now, lastError: null, attempts };
      } else {
        fresh.issuance[key] = { status: 'failed', lastAttemptAt: now, lastError: (result && result.error) || 'echec inconnu', attempts };
      }
      saveState(fresh);
    })
    .catch(e => {
      const fresh = loadState();
      fresh.issuance = fresh.issuance || {};
      fresh.issuance[key] = { status: 'failed', lastAttemptAt: now, lastError: e.message || String(e), attempts };
      saveState(fresh);
    });
}

/**
 * `upstream_group` (etape 2) : several containers — replicas of the same
 * service — can legitimately share one `server_name` instead of that being
 * a conflict, PROVIDED every one of them agrees, on every location, to
 * contribute to the same named group. This is the one place that decision
 * gets made; lib/docker-autoconfig.js stays pure and never sees more than
 * one container's labels at a time.
 *
 * `group` is an array of >= 2 candidates (from runCycle()'s `candidates`,
 * all already individually `valid: true`) that share the exact same
 * (sorted, lower-cased) set of server_names. Returns a merged `validated`
 * object ready for generateVhostContent() (locations replaced with their
 * aggregated shape — `upstreamGroup`/`upstreamBackends`/`upstreamScheme`
 * instead of a single `proxyPass`), or `null` when the group is NOT a safe
 * aggregation — in which case the caller must treat it as the ordinary
 * server_name conflict it always was (never silently pick a winner).
 *
 * Deliberately strict: every whole-vhost setting (network, listen, ssl,
 * http_to_https_auto, server snippets, monitor/diagnostic/analyze) must be
 * byte-for-byte identical across the group, every location path must be
 * the same set across every candidate, and every one of those locations
 * must name the SAME upstream_group with backends sharing the SAME scheme.
 * Any mismatch bails out to `null` rather than guessing which candidate's
 * settings should "win".
 */
function tryAggregateGroup(group) {
  const first = group[0];
  const network = first.desired.network;
  if (!group.every(c => c.desired.network === network)) return null;

  const v0 = first.validated;
  const sameJSON = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const wholeVhostMatches = group.every(c => (
    c.validated.listen === v0.listen
    && sameJSON(c.validated.ssl, v0.ssl)
    && c.validated.httpToHttpsAuto === v0.httpToHttpsAuto
    && sameJSON(c.validated.serverSnippets, v0.serverSnippets)
    && sameJSON(c.validated.monitor, v0.monitor)
    && sameJSON(c.validated.diagnostic, v0.diagnostic)
    && sameJSON(c.validated.analyze, v0.analyze)
  ));
  if (!wholeVhostMatches) return null;

  const paths = [...v0.locations.map(l => l.path)].sort();
  for (const c of group) {
    const p = [...c.validated.locations.map(l => l.path)].sort();
    if (p.length !== paths.length || p.some((x, i) => x !== paths[i])) return null;
  }

  const mergedLocations = [];
  for (const path_ of paths) {
    const perCandidateLoc = group.map(c => c.validated.locations.find(l => l.path === path_));
    const groupName = perCandidateLoc[0].upstreamGroup;
    if (!groupName || perCandidateLoc.some(l => l.upstreamGroup !== groupName)) return null;

    const backends = [];
    let scheme = null;
    for (const loc of perCandidateLoc) {
      const parsed = parseBackendUrl(loc.proxyPass);
      if (!parsed) return null;
      if (scheme === null) scheme = parsed.scheme;
      else if (scheme !== parsed.scheme) return null; // mixed http/https backends: ambiguous, refuse
      backends.push({ host: parsed.host, port: parsed.port });
    }
    mergedLocations.push({
      index: perCandidateLoc[0].index, path: path_,
      upstreamGroup: groupName, upstreamBackends: backends, upstreamScheme: scheme,
      snippets: [...new Set(perCandidateLoc.flatMap(l => l.snippets))],
      monitorIgnore: perCandidateLoc.some(l => l.monitorIgnore),
    });
  }

  return { ...v0, locations: mergedLocations };
}

// ─── Cycle: build the desired set of docker_*.conf files ────────────────────
/**
 * One full detection+apply cycle. Never throws — every failure mode (Docker
 * unreachable, nginx -t failing, a write error) is reported in the returned
 * object and logged, exactly like refreshBlocklists().
 */
async function runCycle({ manual = false, actor = 'scheduler' } = {}) {
  const { settings, errors: configErrors } = loadConfig();
  if (!settings.enable) return { skipped: true, reason: 'disabled' };

  const state = loadState();
  let containers;
  try {
    containers = await listCandidateContainers();
  } catch (e) {
    // Fix v12.21.2 (DAC-01): abort the whole cycle without touching a single
    // generated file — see listCandidateContainers()'s own comment. The next
    // scheduled tick (or the reconnecting Docker Events watcher) will retry
    // on its own; nothing here needs a human to intervene unless the daemon
    // stays unreachable for a long time, hence the notification.
    logEvent('docker-autoconfig.docker.unreachable', { by: actor, error: e.message }, 'api');
    pushNotification({ type: 'docker_autoconfig_docker_unreachable', level: 'error',
      message: `Auto-config Docker : API Docker injoignable (${e.message}) — cycle ignore, aucun vhost touche` });
    return { ok: false, error: e.message, dockerUnreachable: true };
  }
  const nginxNetworks = await getNginxAttachedNetworks();

  // Existing manually-authored vhosts' server_names — a Docker label must
  // never silently take over a vhost the operator wrote by hand.
  const manualServerNames = new Set();
  try {
    for (const name of fs.readdirSync(DIR_SITES)) {
      if (name.startsWith(FILE_PREFIX)) continue;
      const content = (() => { try { return fs.readFileSync(path.join(DIR_SITES, name), 'utf8'); } catch { return ''; } })();
      const m = content.match(/server_name\s+([^;]+);/g) || [];
      for (const line of m) {
        for (const tok of line.replace(/^server_name\s+/, '').replace(/;$/, '').split(/\s+/)) {
          if (tok && tok !== '_') manualServerNames.add(tok.toLowerCase());
        }
      }
    }
  } catch { /* DIR_SITES missing — nothing to conflict with */ }

  // SSL snippet filenames that actually exist right now — a label naming one
  // that isn't there must not render an `include` nginx can never satisfy.
  const availableSslSnippets = new Set(listSSLSnippets().map(s => s.file));

  const candidates = [];
  for (const c of containers) {
    const desired = parseContainerLabels(c.Labels || {});
    if (!desired) continue; // not opted in
    const containerName = (c.Names?.[0] || '').replace(/^\//, '');
    const validated = validateDesiredVhost(desired, { nginxNetworks });
    let { valid, errors: vErrors } = validated;
    const { serverNames, listen } = validated;

    if (valid && validated.ssl.mode === 'snippet' && !availableSslSnippets.has(validated.ssl.snippetFile)) {
      valid = false;
      vErrors = [...vErrors, `nginx-control.vhost.ssl_certificate.snippet introuvable : "${validated.ssl.snippetFile}"`];
    }

    candidates.push({
      containerId: c.Id, containerName, desired, validated, valid, errors: vErrors, serverNames, listen,
    });
  }

  // upstream_group (etape 2) : several containers legitimately sharing one
  // server_name (replicas of the same service) are merged into a single
  // synthetic candidate BEFORE conflict detection runs, so they never reach
  // the "same server_name claimed twice" check below at all. A group that
  // fails to aggregate cleanly (see tryAggregateGroup()'s own comment) is
  // left untouched and falls straight through to that same conflict check,
  // exactly as before this feature existed — never a silent guess.
  const byServerNameKey = new Map();
  for (const cand of candidates) {
    if (!cand.valid) continue;
    const key = [...cand.serverNames].map(n => n.toLowerCase()).sort().join(',');
    if (!byServerNameKey.has(key)) byServerNameKey.set(key, []);
    byServerNameKey.get(key).push(cand);
  }
  const aggregatedMembers = new Set();
  const effectiveCandidates = [];
  for (const [, group] of byServerNameKey) {
    if (group.length < 2) continue;
    const merged = tryAggregateGroup(group);
    if (!merged) continue; // not a safe aggregation: leave as individual candidates -> ordinary conflict path
    for (const c of group) aggregatedMembers.add(c);
    effectiveCandidates.push({
      containerId: group[0].containerId,
      containerName: group.map(c => c.containerName).join(', '),
      aggregated: true, memberContainerIds: group.map(c => c.containerId),
      validated: merged, valid: true, errors: [],
      serverNames: merged.serverNames, listen: merged.listen,
    });
  }
  for (const cand of candidates) {
    if (!aggregatedMembers.has(cand)) effectiveCandidates.push(cand);
  }

  // Cross-container conflicts: any server_name claimed by more than one
  // candidate, or already used by a manually-authored vhost.
  const claimCount = new Map();
  for (const cand of effectiveCandidates) {
    if (!cand.valid) continue;
    for (const name of cand.serverNames) claimCount.set(name.toLowerCase(), (claimCount.get(name.toLowerCase()) || 0) + 1);
  }
  for (const cand of effectiveCandidates) {
    if (!cand.valid) continue;
    const conflictNames = cand.serverNames.filter(n =>
      claimCount.get(n.toLowerCase()) > 1 || manualServerNames.has(n.toLowerCase()));
    if (conflictNames.length) {
      cand.conflict = true;
      cand.conflictNames = conflictNames;
    }
  }

  // Decide status for each valid, non-conflicting candidate.
  const eligible = []; // { key, file, content, candidate }
  const pending = [];
  const paused = [];
  for (const cand of effectiveCandidates) {
    if (!cand.valid || cand.conflict) continue;
    const key = cand.serverNames[0].toLowerCase();
    const decisionKey = namesDecisionKey(cand.serverNames);
    const decision = state.decisions[decisionKey]?.decision;
    const autoAllowed = cand.serverNames.every(n => matchesAnyPattern(n, settings.allowedServerNamePatterns));
    const needsApproval = settings.requireApproval && !autoAllowed && decision !== 'approved';
    if (needsApproval) {
      if (decision !== 'rejected') pending.push({ key, decisionKey, candidate: cand });
      continue;
    }
    // v12.35.0 (demande utilisateur) : une decision "approved" peut aussi
    // etre mise en pause SANS etre revoquee — la difference avec revoquer
    // (voir les routes /pause et /decisions/remove plus bas) est que
    // reprendre republie immediatement avec le MEME jeu de labels, sans repasser
    // par une nouvelle approbation. Un candidat en pause est simplement exclu
    // de `eligible` : son fichier genere existant (s il y en a un) sera
    // supprime par le diff toWrite/toRemove plus bas, exactement comme un
    // conteneur qui disparait — la publication s arrete, la decision reste.
    if (state.decisions[decisionKey]?.paused) { paused.push({ key, decisionKey, candidate: cand }); continue; }
    const file = path.join(DIR_SITES, dockerVhostFileName(cand.serverNames));
    const sslResolved = resolveSsl(cand.validated, cand.serverNames, state.issuance || {});
    // Only certbot_http/certbot_dns ever actively trigger an issuance — auto
    // and snippet stay purely reactive to whatever already exists on disk,
    // exactly as before this feature existed. Fires and forgets: see
    // triggerCertbotIssuanceIfDue()'s own header for why this must never be
    // awaited here.
    // Fix v12.21.2 (audit finding DAC-07, part 1): a PREVIOUSLY FAILED
    // attempt (sslResolved.type === 'error', code 'certbot_issuance_failed')
    // must also be allowed to re-enter triggerCertbotIssuanceIfDue() — it
    // used to only ever fire on 'pending', so a `failed` entry was retried
    // NEVER, despite the error message itself promising "nouvelle tentative
    // automatique". triggerCertbotIssuanceIfDue()'s own retryMinutes backoff
    // check still decides whether an attempt is actually due yet.
    const isCertbotMode = cand.validated.ssl.mode === 'certbot_http' || cand.validated.ssl.mode === 'certbot_dns';
    const dueForAttempt = (sslResolved?.type === 'pending' && !sslResolved.issuing)
      || (sslResolved?.type === 'error' && sslResolved.code === 'certbot_issuance_failed');
    if (isCertbotMode && dueForAttempt) {
      triggerCertbotIssuanceIfDue(key, cand.validated.ssl.mode, cand.serverNames, state, settings.certbotRetryMinutes);
    }
    // Fix v12.21.2 (audit finding DAC-09): `upstream_group` names are only
    // validated for SYNTAX (UPSTREAM_GROUP_NAME_RE, in
    // lib/docker-autoconfig.js), never for GLOBAL uniqueness across
    // unrelated candidates. Two containers that are NOT part of the same
    // tryAggregateGroup() (different server_names) but happen to pick the
    // same literal group name each render their own top-level `upstream
    // <name> { ... }` block in their own separate file — nginx rejects that
    // as a duplicate upstream, failing `nginx -t` for the WHOLE cycle (every
    // OTHER candidate's file gets tested and rolled back alongside it, even
    // though only one container's label was actually wrong). Prefixing every
    // group name with a token derived from this candidate's own (already
    // collision-resistant, see dockerVhostFileName()) file name keeps
    // legitimately-aggregated groups (one candidate, one file, one
    // `upstream{}` block — see tryAggregateGroup()) working exactly as
    // before, while making an accidental name clash between two UNRELATED
    // candidates structurally impossible.
    const upstreamPrefix = path.basename(file, '.conf').replace(/[^A-Za-z0-9_]/g, '_');
    const validatedForRender = cand.validated.locations.some(l => l.upstreamGroup)
      ? { ...cand.validated, locations: cand.validated.locations.map(l => (
          l.upstreamGroup ? { ...l, upstreamGroup: `${upstreamPrefix}__${l.upstreamGroup}` } : l
        )) }
      : cand.validated;
    const content = generateVhostContent(validatedForRender, cand.serverNames, cand.listen, {
      containerName: cand.containerName, containerId: cand.containerId, sslResolved,
      certbotWebrootPath: cand.validated.ssl?.mode === 'certbot_http' ? deps.getCertbotWebrootPath() : null,
    });
    eligible.push({ key, file, content, candidate: cand });
  }

  // Compute the write/remove set against what was previously generated.
  const nextGeneratedFiles = {};
  const toWrite = [];
  for (const e of eligible) {
    nextGeneratedFiles[e.key] = e.file;
    const current = fs.existsSync(e.file) ? fs.readFileSync(e.file, 'utf8') : null;
    // Skip only the timestamp line so re-running an unchanged label set never
    // forces a reload — same idiom as buildGeoSnippet()'s header comparison.
    // Content can now hold more than one `server {` block (the optional
    // http_to_https_auto redirect precedes the main one), so the comparison
    // must not split on that string — only the "# Genere le:" line varies
    // run-to-run for an otherwise-unchanged label set.
    const strip = s => (s || '').replace(/^# Genere le:.*$/m, '');
    if (strip(current) !== strip(e.content)) toWrite.push(e);
  }
  const toRemove = Object.entries(state.generatedFiles || {})
    .filter(([key]) => !nextGeneratedFiles[key])
    .map(([, file]) => file);

  // Fix v12.21.2 (audit finding DAC-01, extra safety valve suggested by the
  // audit on top of the listCandidateContainers() fix above): even a
  // legitimate, successful Docker API call could in principle return an
  // empty/near-empty result for the wrong reason (a socket-proxy silently
  // filtering everything, a mis-scoped `all=0` on a host where every
  // container was just recreated with new IDs). A SCHEDULED or event-driven
  // cycle that would remove every single previously-generated vhost at once
  // is treated as suspicious and aborted without touching any file — an
  // operator-triggered manual rescan/approve/reject is exempt, since that is
  // an explicit human action and may legitimately mean "yes, take all of
  // these down".
  const previousCount = Object.keys(state.generatedFiles || {}).length;
  if (!manual && previousCount > 1 && toRemove.length === previousCount && toWrite.length === 0) {
    logEvent('docker-autoconfig.mass_removal_guard', { by: actor, wouldRemove: toRemove.length }, 'api');
    pushNotification({ type: 'docker_autoconfig_mass_removal_guard', level: 'error',
      message: `Auto-config Docker : ${toRemove.length} vhost(s) genere(s) seraient tous supprimes d'un coup — cycle automatique bloque par securite, relancer manuellement (Rescanner) pour confirmer` });
    return { ok: false, error: 'mass_removal_guard', wouldRemove: toRemove.length };
  }

  if (!toWrite.length && !toRemove.length) {
    // Fix v12.21.2 (audit finding DAC-08): the file content already matches
    // `nextGeneratedFiles` (nothing to write/remove on disk), but the
    // BOOKKEEPING (`state.generatedFiles`) can still be out of date — most
    // commonly because a PREVIOUS cycle's reload failed after its writes
    // already succeeded (see the reload branch below, which now always
    // persists `nextGeneratedFiles` for exactly this reason) and this is the
    // very first "nothing changed" cycle since. Left unfixed, that key would
    // never be recorded as generated: getStatus() reports 'pending_apply'
    // forever, and the file would never be cleaned up either, since it's
    // simultaneously absent from `state.generatedFiles` (so never considered
    // "no longer needed") and already present on disk with the right content
    // (so `toWrite` never re-adds it).
    if (JSON.stringify(nextGeneratedFiles) !== JSON.stringify(state.generatedFiles || {})) {
      state.generatedFiles = nextGeneratedFiles;
      saveState(state);
    }
    return {
      ok: true, reloaded: false, skippedNoChange: true,
      candidates: candidates.length, pending: pending.length, paused: paused.length, conflicts: effectiveCandidates.filter(c => c.conflict).length,
    };
  }

  // Fix v12.21.2 (audit finding DAC-05): snapshot, write, test, rollback and
  // reload all now run inside the mutex shared with features/blocklists.js
  // and features/agents.js — see lib/nginx-write-lock.js's own header for
  // why a single GLOBAL lock is required, not one scoped to this feature
  // alone (the scheduler, Docker Events, an approve/reject click, a
  // blocklist refresh and an agent push can all race each other).
  return withLock(async () => {
    // Snapshot for rollback.
    const snapshot = new Map();
    for (const e of toWrite) snapshot.set(e.file, fs.existsSync(e.file) ? fs.readFileSync(e.file, 'utf8') : null);
    for (const f of toRemove) snapshot.set(f, fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null);

    try {
      fs.mkdirSync(DIR_SITES, { recursive: true });
      for (const e of toWrite) atomicWrite(e.file, e.content);
      for (const f of toRemove) { try { fs.unlinkSync(f); } catch {} }
    } catch (e) {
      logEvent('docker-autoconfig.write.error', { by: actor, error: e.message }, 'api');
      return { ok: false, error: e.message };
    }

    let applyResult;
    try {
      await docker.execNginx('nginx -t');
      applyResult = { ok: true };
    } catch (e) {
      // Roll back every file this cycle touched before returning.
      for (const [file, prev] of snapshot) {
        try { if (prev === null) fs.unlinkSync(file); else atomicWrite(file, prev); } catch {}
      }
      applyResult = { ok: false, testFailed: true, error: e.error || e.message, stderr: e.stderr || e.stdout || '' };
    }

    if (!applyResult.ok) {
      logEvent('docker-autoconfig.test.failed', { by: actor, error: applyResult.error, stderr: applyResult.stderr }, 'api');
      // Fix v12.21.2 (audit finding DAC-09, "deduplicate notifications"): a
      // single misconfigured container (e.g. a duplicate location the fixes
      // above don't yet catch, or an nginx-level error the regex validation
      // can't anticipate) used to send a fresh e-mail on EVERY poll — every
      // 15s by default — for as long as it stayed broken. The SAME failure
      // (by error text) is now only re-notified after a cooldown; a
      // DIFFERENT error (or the first one ever seen) always notifies right
      // away.
      const failureHash = crypto.createHash('sha1').update(String(applyResult.error || '') + String(applyResult.stderr || '')).digest('hex');
      const lastNotif = state.lastTestFailureNotif;
      const shouldNotify = !lastNotif || lastNotif.hash !== failureHash
        || (Date.now() - (lastNotif.at || 0)) > TEST_FAILURE_NOTIFY_COOLDOWN_MS;
      if (shouldNotify) {
        pushNotification({ type: 'docker_autoconfig_failed', level: 'error',
          message: `Auto-config Docker : nginx -t a echoue, la mise a jour a ete annulee` });
        await sendNotification('docker_autoconfig_failed',
          '[Nginx Dashboard] Auto-config Docker — nginx -t FAILED',
          `The generated vhost(s) failed nginx -t and were rolled back.\n\n${applyResult.stderr || applyResult.error || ''}`
        ).catch(() => {});
        const freshForNotif = loadState();
        freshForNotif.lastTestFailureNotif = { hash: failureHash, at: Date.now() };
        saveState(freshForNotif);
      }
      return { ok: false, reloaded: false, testFailed: true, error: applyResult.error, stderr: applyResult.stderr };
    }

    try {
      await docker.execNginx('nginx -s reload');
    } catch (e) {
      logEvent('docker-autoconfig.reload.failed', { by: actor, error: e.error || e.message }, 'api');
      // Fix v12.21.2 (audit finding DAC-08): `nginx -t` already passed and
      // every file this cycle touched is on disk in its NEW form — only the
      // reload command itself failed (e.g. a transient signal delivery
      // issue). Never leave `state.generatedFiles` behind the actual
      // filesystem state: the next cycle's diff is computed against what's
      // ACTUALLY on disk, and a stale `state.generatedFiles` here means that
      // diff sees "nothing changed" and never saves either (see the
      // skippedNoChange branch above), permanently losing track of the file.
      const freshOnFailure = loadState();
      freshOnFailure.generatedFiles = nextGeneratedFiles;
      saveState(freshOnFailure);
      return { ok: false, reloaded: false, error: e.error || e.message };
    }

    // Fix v12.21.2 (audit finding DAC-06): re-load a FRESH copy of the state
    // right before saving, instead of writing back the `state` object read
    // at the top of this cycle — a certbot issuance completing, or an
    // approve/reject decision made, WHILE this cycle's write/test/reload was
    // running would otherwise be silently overwritten by the stale snapshot.
    // Only the two fields this cycle is actually responsible for
    // (`generatedFiles`) are merged in; every other key keeps whatever the
    // fresh read has.
    const freshState = loadState();
    freshState.generatedFiles = nextGeneratedFiles;
    saveState(freshState);

    logEvent(manual ? 'docker-autoconfig.apply.manual' : 'docker-autoconfig.apply.scheduled',
      { by: actor, written: toWrite.map(e => e.key), removed: toRemove.map(f => path.basename(f)) }, 'api');
    if (toWrite.length) {
      pushNotification({ type: 'docker_autoconfig_applied', level: 'success',
        message: `Auto-config Docker : ${toWrite.length} vhost(s) genere(s)/mis a jour, ${toRemove.length} supprime(s)` });
    }

    return {
      ok: true, reloaded: true,
      written: toWrite.map(e => e.key), removed: toRemove.map(f => path.basename(f)),
      candidates: candidates.length, pending: pending.length, paused: paused.length, conflicts: effectiveCandidates.filter(c => c.conflict).length,
    };
  });
}

/**
 * Current list of absolute paths this feature manages — consumed by
 * server.js to feed features/deploy.js's generalized setDeps({generatedFiles}),
 * alongside the filename-prefix protection that also covers files this
 * function doesn't (yet) know about (e.g. right after a restart, before the
 * first cycle has run). See features/deploy.js's isGeneratedFile().
 */
function getGeneratedFiles() {
  return Object.values(loadState().generatedFiles || {});
}

// ─── Status (for the UI) ─────────────────────────────────────────────────
async function getStatus() {
  const { settings, errors: configErrors } = loadConfig();
  const state = loadState();
  // Fix v12.21.2 (audit finding DAC-01): listCandidateContainers() now
  // THROWS on a Docker error instead of silently returning `[]` (see its own
  // comment) — correct for runCycle(), which must never treat "Docker
  // unreachable" as "zero containers" and start deleting vhosts. This route
  // is read-only, though: a momentarily unreachable Docker socket should
  // degrade the status page (empty list, error surfaced to the UI), not
  // 500 the whole page.
  let containers = [];
  let dockerError = null;
  if (settings.enable) {
    try { containers = await listCandidateContainers(); }
    catch (e) { dockerError = e.message; }
  }
  const nginxNetworks = (settings.enable && !dockerError) ? await getNginxAttachedNetworks() : [];

  const list = [];
  for (const c of containers) {
    const desired = parseContainerLabels(c.Labels || {});
    if (!desired) continue;
    const containerName = (c.Names?.[0] || '').replace(/^\//, '');
    const validated = validateDesiredVhost(desired, { nginxNetworks });
    const { valid, errors, serverNames, listen } = validated;
    const key = serverNames[0]?.toLowerCase();
    const decisionKey = serverNames.length ? namesDecisionKey(serverNames) : null;
    const decisionEntry = decisionKey ? state.decisions[decisionKey] : null;
    const decision = decisionEntry?.decision || null;
    const autoAllowed = serverNames.length
      ? serverNames.every(n => matchesAnyPattern(n, settings.allowedServerNamePatterns)) : false;
    const sslResolved = valid ? resolveSsl(validated, serverNames, state.issuance || {}) : undefined;
    let status;
    if (!valid) status = 'invalid';
    else if (settings.requireApproval && !autoAllowed && decision !== 'approved') {
      status = decision === 'rejected' ? 'rejected' : 'pending_approval';
    // v12.35.0 (demande utilisateur) : une publication approuvee peut etre
    // mise en pause sans etre revoquee (voir runCycle() plus haut et les
    // routes /pause /resume plus bas) — verifie AVANT le statut ssl_error,
    // puisqu'un vhost en pause n'est de toute facon plus genere du tout.
    } else if (decisionEntry?.paused) {
      status = 'paused';
    // Un vhost s'applique bien (en HTTP simple, jamais casse — voir
    // resolveSsl()/generateVhostContent()), mais le mode SSL demande n'est
    // pas satisfait : signale explicitement plutot que de se fondre dans
    // 'applied'/'pending_apply', pour que l'operateur voie le probleme sans
    // avoir a ouvrir le fichier genere.
    } else if (sslResolved?.type === 'error') status = 'ssl_error';
    else status = state.generatedFiles?.[key] ? 'applied' : 'pending_apply';
    list.push({
      containerId: c.Id, containerName, serverNames, listen, valid, errors, status,
      pausedAt: decisionEntry?.paused ? (decisionEntry.pausedAt || null) : null,
      pausedBy: decisionEntry?.paused ? (decisionEntry.pausedBy || null) : null,
      ssl: {
        mode: validated.ssl.mode, resolved: sslResolved ? sslResolved.type : null,
        error: sslResolved?.type === 'error' ? { code: sslResolved.code, message: sslResolved.message } : null,
      },
    });
  }

  // v12.35.0 (demande utilisateur) : jusqu'ici, une decision (approuve/rejete)
  // n'etait visible QUE via le conteneur Docker actuellement en vie qui l'a
  // declenchee — un conteneur arrete (`docker compose stop`, sans le
  // detruire) disparait entierement de `list` ci-dessus (listCandidateContainers()
  // n'interroge que les conteneurs EN COURS D'EXECUTION), alors que sa
  // decision reste stockee indefiniment dans state.decisions. Resultat :
  // aucune trace visible de "ce qui a ete approuve", ni aucun moyen de
  // revoquer cette approbation avant de relancer le conteneur. `decisions`
  // liste desormais TOUTES les decisions enregistrees, qu'un conteneur
  // corresponde ou non en ce moment — associee, quand elle existe, a la
  // ligne de `list` ci-dessus pour son statut/nom de conteneur actuels.
  const decisions = Object.entries(state.decisions || {}).map(([decisionKey, d]) => {
    const names = d.names || [];
    const liveEntry = list.find(c => c.serverNames.length && namesDecisionKey(c.serverNames) === decisionKey);
    const primaryKey = (names[0] || '').toLowerCase();
    const generatedFile = state.generatedFiles?.[primaryKey];
    return {
      decisionKey, names, decision: d.decision, paused: !!d.paused,
      at: d.at || null, by: d.by || null,
      pausedAt: d.paused ? (d.pausedAt || null) : null, pausedBy: d.paused ? (d.pausedBy || null) : null,
      hasLiveContainer: !!liveEntry,
      containerName: liveEntry ? liveEntry.containerName : null,
      liveStatus: liveEntry ? liveEntry.status : null,
      generatedFile: generatedFile ? path.basename(generatedFile) : null,
    };
  }).sort((a, b) => (a.names[0] || '').localeCompare(b.names[0] || ''));

  return {
    settings, configErrors, dockerError,
    containers: list,
    decisions,
    generatedFiles: Object.entries(state.generatedFiles || {}).map(([key, file]) => ({ key, file })),
  };
}

// ─── Scheduling ───────────────────────────────────────────────────────────
// Self-contained periodic tick — same pattern as features/blocklists.js's
// startBlocklistScheduler(): this feature owns its own interval rather than
// being wired into lib/scheduler.js.
let pollTimer = null;

function startScheduler() {
  if (pollTimer) return;
  const tick = () => {
    const { settings } = loadConfig();
    if (!settings.enable) return;
    runCycle({ manual: false }).catch(e => console.error('[docker-autoconfig] cycle error:', e.message));
  };
  // The interval itself is fixed at startup from whatever poll_interval_sec
  // is at boot time — a change to the YAML takes effect on next restart,
  // same as every other interval-driven setting in this project. tick()
  // still re-reads the full config (including `enable`) on every fire.
  const { settings } = loadConfig();
  pollTimer = setInterval(tick, (settings.pollIntervalSec || 15) * 1000);
  pollTimer.unref();
}

// ─── Reactive detection: Docker Events + debounce ───────────────────────────
// The poll above (startScheduler()) is the safety net; this is the "react
// immediately" half described in the design doc. A single dropped/expired
// connection to /events must never mean auto-config silently stops working
// until the next restart — this reconnects on its own (capped backoff), and
// the poll keeps running underneath regardless of whether the stream is up.
let eventsHandle = null;
let debounceTimer = null;
let reconnectTimer = null;
let reconnectDelayMs = 1000;
const RECONNECT_DELAY_MAX_MS = 30_000;

function scheduleDebouncedCycle(debounceMs) {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    runCycle({ manual: false, actor: 'docker-events' })
      .catch(e => console.error('[docker-autoconfig] cycle error (events):', e.message));
  }, debounceMs);
  debounceTimer.unref?.();
}

// Only these container lifecycle events can possibly change what should be
// generated — filtering here (rather than trusting Docker's own `filters`
// query param, whose support/shape has drifted across engine versions)
// keeps this robust to whichever engine is on the other end of the socket.
const RELEVANT_EVENTS = new Set(['start', 'stop', 'die', 'update', 'destroy']);

function startEventsWatcher() {
  const attempt = () => {
    if (eventsHandle) return; // already connected
    const { settings } = loadConfig();
    if (!settings.enable || !settings.eventsEnable) {
      reconnectTimer = setTimeout(attempt, 30_000);
      reconnectTimer.unref?.();
      return;
    }
    // A connection that survives a few seconds is treated as healthy and
    // resets the backoff — only a run of consecutive, near-immediate
    // failures (socket truly unreachable) should make reconnection attempts
    // progressively rarer. Cleared in onEnd() if the stream drops first.
    const stableTimer = setTimeout(() => { reconnectDelayMs = 1000; }, 5000);
    stableTimer.unref?.();

    eventsHandle = docker.streamEvents({
      filters: { type: ['container'] },
      onEvent: (evt) => {
        if (!evt || evt.Type !== 'container' || !RELEVANT_EVENTS.has(evt.Action)) return;
        const { settings: current } = loadConfig();
        scheduleDebouncedCycle(current.eventsDebounceMs || 3000);
      },
      onEnd: () => {
        // The connection ended (daemon restart, socket hiccup, engine
        // closing idle streams, ...) — never fatal, just reconnect with a
        // capped exponential backoff so a persistently unreachable socket
        // doesn't spin this in a tight loop.
        clearTimeout(stableTimer);
        eventsHandle = null;
        reconnectTimer = setTimeout(attempt, reconnectDelayMs);
        reconnectTimer.unref?.();
        reconnectDelayMs = Math.min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS);
      },
    });
  };
  attempt();
}

// ─── Routes ───────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/docker-autoconfig/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try { return send(res, 200, await getStatus()); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.post('/api/docker-autoconfig/rescan', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  // Fix v12.21.2 (audit finding DAC-03): a decision now applies to the FULL,
  // exact set of server_names a candidate carries (see namesDecisionKey()
  // above) — never to just the first one. `serverNames` (array) is the
  // current contract (see public/assets/js/docker-autoconfig.js); a lone
  // `serverName` string is still accepted for any older API client, treated
  // as a single-name set.
  function namesFromBody(body) {
    if (Array.isArray(body.serverNames)) return body.serverNames.map(s => String(s || '').trim().toLowerCase()).filter(Boolean);
    if (typeof body.serverName === 'string' && body.serverName.trim()) return [body.serverName.trim().toLowerCase()];
    return [];
  }

  router.post('/api/docker-autoconfig/approve', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const serverNames = namesFromBody(body);
    if (!serverNames.length) return httpLib.badRequest(res, 'serverNames required');
    const decisionKey = namesDecisionKey(serverNames);
    const state = loadState();
    state.decisions[decisionKey] = { decision: 'approved', names: serverNames, at: new Date().toISOString(), by: session.username };
    saveState(state);
    logEvent('docker-autoconfig.approve', { by: session.username, serverNames }, 'api');
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.post('/api/docker-autoconfig/reject', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const serverNames = namesFromBody(body);
    if (!serverNames.length) return httpLib.badRequest(res, 'serverNames required');
    const decisionKey = namesDecisionKey(serverNames);
    const state = loadState();
    state.decisions[decisionKey] = { decision: 'rejected', names: serverNames, at: new Date().toISOString(), by: session.username };
    saveState(state);
    logEvent('docker-autoconfig.reject', { by: session.username, serverNames }, 'api');
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  // v12.35.0 (demande utilisateur) : mettre en pause une publication deja
  // approuvee, sans revoquer l'approbation elle-meme — reprendre republie
  // immediatement avec le meme jeu de labels, sans repasser par une nouvelle
  // approbation. Seule une decision DEJA 'approved' peut etre mise en pause
  // (mettre en pause quelque chose qui n'est pas applique de toute facon n'a
  // pas de sens et masquerait une vraie erreur d'utilisation).
  router.post('/api/docker-autoconfig/pause', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const serverNames = namesFromBody(body);
    if (!serverNames.length) return httpLib.badRequest(res, 'serverNames required');
    const decisionKey = namesDecisionKey(serverNames);
    const state = loadState();
    const entry = state.decisions[decisionKey];
    if (!entry || entry.decision !== 'approved') {
      return httpLib.badRequest(res, 'Cette publication n a pas ete approuvee — rien a mettre en pause');
    }
    entry.paused = true;
    entry.pausedAt = new Date().toISOString();
    entry.pausedBy = session.username;
    saveState(state);
    logEvent('docker-autoconfig.pause', { by: session.username, serverNames }, 'api');
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  router.post('/api/docker-autoconfig/resume', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const serverNames = namesFromBody(body);
    if (!serverNames.length) return httpLib.badRequest(res, 'serverNames required');
    const decisionKey = namesDecisionKey(serverNames);
    const state = loadState();
    const entry = state.decisions[decisionKey];
    if (!entry || !entry.paused) return httpLib.badRequest(res, 'Cette publication n est pas en pause');
    entry.paused = false;
    saveState(state);
    logEvent('docker-autoconfig.resume', { by: session.username, serverNames }, 'api');
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });

  // v12.35.0 (demande utilisateur) : jusqu'ici, une decision (approuve ou
  // rejete) etait permanente — aucune route ne pouvait la supprimer, et rien
  // ne la rendait visible une fois son conteneur arrete (voir getStatus()'s
  // nouveau champ `decisions`). Supprimer une decision la fait retomber dans
  // l'etat "jamais decide" : si le conteneur est toujours labellise et en
  // vie, il repasse par le circuit normal (auto-approuve si un motif
  // correspond, sinon de nouveau "en attente d'approbation") des le prochain
  // cycle, jamais silencieusement re-applique.
  router.post('/api/docker-autoconfig/decisions/remove', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const serverNames = namesFromBody(body);
    if (!serverNames.length) return httpLib.badRequest(res, 'serverNames required');
    const decisionKey = namesDecisionKey(serverNames);
    const state = loadState();
    if (!state.decisions[decisionKey]) return httpLib.notFound(res, 'Aucune decision enregistree pour ce jeu de server_name');
    delete state.decisions[decisionKey];
    saveState(state);
    logEvent('docker-autoconfig.decision.remove', { by: session.username, serverNames }, 'api');
    try { return send(res, 200, await runCycle({ manual: true, actor: session.username })); }
    catch (e) { return send(res, 500, { error: e.message }); }
  });
}

module.exports = {
  register, runCycle, getStatus, getGeneratedFiles, startScheduler, startEventsWatcher,
  loadConfig, FILE_PREFIX, setDeps,
  // Exportes uniquement pour test/docker-autoconfig-aggregation.test.js —
  // logique pure (aucun appel Docker/fs), testable sans mock du socket.
  tryAggregateGroup, resolveSsl, namesDecisionKey,
  // Exporte pour test/docker-autoconfig-certbot-issuance.test.js — la
  // machine a etats de declenchement d emission, testable directement avec
  // un `state` construit a la main plutot qu en passant par runCycle() (qui
  // a besoin d un vrai socket Docker, absent de ce bac a sable de test).
  triggerCertbotIssuanceIfDue,
};
