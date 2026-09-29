'use strict';
/**
 * Registry of remote agents (Partie 2 du document de conception — hôtes
 * Docker distants). Lives in lib/, not features/, for the same reason
 * lib/deploy-tokens.js does: lib/auth.js's authenticateAgentToken() needs to
 * look up a bearer token WITHOUT creating a lib → features dependency
 * (features never import each other, and never get required back by lib/ —
 * server.js is the sole wiring point in this project). features/agents.js is
 * the orchestration layer built on top of this module: HTTP routes,
 * manifest validation dispatch, writing/testing/reloading generated vhost
 * files. This module only owns the registry's data and its state machine.
 *
 * Persisted in the same SQLite-backed key/value `state` table every other
 * stateful feature already uses (lib/events.js) — same reasoning as
 * features/docker-autoconfig.js's own issuance/decisions state: a small,
 * occasionally-updated registry doesn't need its own file format.
 *
 * State machine per agent: pending → approved | rejected; approved → revoked.
 * A rejected or revoked agent's record is kept (for the audit trail visible
 * in the Agents page) until an operator explicitly deletes it with remove().
 */
const crypto = require('crypto');

const events = require('./events');
const { generateToken, hashToken, safeCompareHash } = require('./agent-tokens');

const STATE_KEY = 'agents_state';

function loadState() {
  const s = events.getState(STATE_KEY);
  return { agents: {}, ...(s || {}) };
}
function saveState(state) { events.setState(STATE_KEY, state); }

/** A short, URL-safe id — collision-checked against the current registry, though at 8 bytes of entropy a collision is not realistically expected. */
function newAgentId(state) {
  let id;
  do { id = crypto.randomBytes(8).toString('hex'); } while (state.agents[id]);
  return id;
}

function listAgents() {
  return Object.values(loadState().agents).sort((a, b) => b.createdAt - a.createdAt);
}

function getAgent(id) { return loadState().agents[id] || null; }

/** First-contact enrollment request — always created as 'pending', never auto-approved. */
function enroll({ hostnameProposed, fingerprint }) {
  const state = loadState();
  const id = newAgentId(state);
  const now = Date.now();
  const record = {
    id, hostnameProposed, fingerprint: fingerprint || '',
    status: 'pending', tokenHash: null,
    createdAt: now, decidedAt: null, decidedBy: null,
    lastManifestAt: null, lastManifestOk: null, lastManifestError: null,
    vhostCount: 0, generatedFiles: [], lastVhosts: [],
    protocolVersion: null, metrics: null, metricsAt: null,
    lastManifestBody: null,
  };
  state.agents[id] = record;
  saveState(state);
  return record;
}

/**
 * Approve a pending (or previously rejected/revoked, re-approved) agent:
 * generates a fresh bearer token, persists only its SHA-256 hash, and
 * returns the raw token exactly once — the caller (features/agents.js's
 * route) must hand it to the operator in that single HTTP response and never
 * again; there is no "reveal token" route, by design, same as a password.
 */
function approve(id, by) {
  const state = loadState();
  const a = state.agents[id];
  if (!a) return null;
  const rawToken = generateToken();
  a.status = 'approved';
  a.tokenHash = hashToken(rawToken);
  a.decidedAt = Date.now();
  a.decidedBy = by;
  saveState(state);
  return { agent: a, rawToken };
}

function reject(id, by) {
  const state = loadState();
  const a = state.agents[id];
  if (!a) return null;
  a.status = 'rejected';
  a.tokenHash = null;
  a.decidedAt = Date.now();
  a.decidedBy = by;
  saveState(state);
  return a;
}

/** Revoke: the token stops authenticating immediately (tokenHash cleared) — vhost cleanup itself is orchestrated by features/agents.js, which then calls recordManifestResult() to clear generatedFiles once the files are actually gone. */
function revoke(id, by) {
  const state = loadState();
  const a = state.agents[id];
  if (!a) return null;
  a.status = 'revoked';
  a.tokenHash = null;
  a.decidedAt = Date.now();
  a.decidedBy = by;
  saveState(state);
  return a;
}

/** Permanently remove a record — only meaningful for a non-approved agent (pending/rejected/revoked); an approved one must be revoked first. Enforced by the caller (features/agents.js's route), not here. */
function remove(id) {
  const state = loadState();
  if (!state.agents[id]) return false;
  delete state.agents[id];
  saveState(state);
  return true;
}

/** Only ever callable on an already-approved agent — regenerating a token for a pending/rejected one makes no sense (there is nothing to authenticate yet). */
function regenerateToken(id) {
  const state = loadState();
  const a = state.agents[id];
  if (!a || a.status !== 'approved') return null;
  const rawToken = generateToken();
  a.tokenHash = hashToken(rawToken);
  saveState(state);
  return { agent: a, rawToken };
}

/**
 * Constant-time lookup by token value, same discipline as
 * lib/deploy-tokens.js#findByToken(): every approved entry is compared
 * (never short-circuiting on the first match) so response timing does not
 * leak which, if any, agent a guessed token was close to.
 */
function findByToken(rawToken) {
  if (!rawToken) return null;
  const state = loadState();
  const hash = hashToken(rawToken);
  let match = null;
  for (const a of Object.values(state.agents)) {
    if (a.status !== 'approved' || !a.tokenHash) continue;
    if (safeCompareHash(a.tokenHash, hash)) match = a;
  }
  return match;
}

/**
 * Record the outcome of a manifest push (or a post-revoke cleanup) — called
 * by features/agents.js after it has actually written/removed files and
 * tested/reloaded nginx, never before.
 *
 * `protocolVersion` and `metrics` (both optional) are recorded even on a
 * push that ended up `ok:false` for its vhosts (a manifest can be rejected
 * for a bad vhost while still reporting a valid protocol version and host
 * metrics) — see features/agents.js for the exact call sites.
 */
// Fix v12.22.0 (audit finding AGT-03, remaining item): a pending/rejected/
// revoked agent must never have its manifest outcome recorded — the caller
// (features/agents.js#applyManifestForAgent) already re-checks status under
// the write lock before calling this for an actual push, but this is the
// authoritative last line of defense in the registry itself, in case a
// future call site forgets to. The one legitimate exception is the post-
// revoke cleanup (removeAgentVhosts()), which intentionally records against
// an already-'revoked' agent to clear its generatedFiles once the vhost
// files are actually gone — it opts in explicitly via allowNonApproved.
function recordManifestResult(id, { ok, error, generatedFiles, vhostCount, lastVhosts, protocolVersion, metrics, lastManifestBody }, { allowNonApproved = false } = {}) {
  const state = loadState();
  const a = state.agents[id];
  if (!a) return null;
  if (a.status !== 'approved' && !allowNonApproved) return null;
  a.lastManifestAt = Date.now();
  a.lastManifestOk = !!ok;
  a.lastManifestError = error || null;
  if (protocolVersion !== undefined) a.protocolVersion = protocolVersion;
  if (metrics !== undefined) { a.metrics = metrics; a.metricsAt = metrics ? Date.now() : a.metricsAt; }
  if (ok) {
    if (generatedFiles !== undefined) a.generatedFiles = generatedFiles;
    if (vhostCount !== undefined) a.vhostCount = vhostCount;
    if (lastVhosts !== undefined) a.lastVhosts = lastVhosts;
    // Fix (audit report, Basse/"Agents (dashboard)"): the raw, already-
    // validated manifest body is kept so a periodic background recheck (see
    // features/agents.js#reapplyAgentManifest) can regenerate this agent's
    // vhosts WITHOUT waiting for its next push — see that function's own
    // header comment for the real-world scenario this fixes (a certbot_http/
    // certbot_dns issuance that completes asynchronously, after the push
    // that triggered it already returned, never switching to HTTPS if the
    // agent doesn't happen to push again). Cleared on revoke (removeAgentVhosts()
    // records ok:true with lastVhosts:[] but no body — see below).
    if (lastManifestBody !== undefined) a.lastManifestBody = lastManifestBody;
  }
  if (lastManifestBody === null) a.lastManifestBody = null;
  saveState(state);
  return a;
}

/** Every file currently generated by any agent — for features/deploy.js's Git-protection setDeps({generatedFiles}), same role as features/docker-autoconfig.js's own getGeneratedFiles(). */
function getGeneratedFiles() {
  const state = loadState();
  const files = [];
  for (const a of Object.values(state.agents)) files.push(...(a.generatedFiles || []));
  return files;
}

module.exports = {
  STATE_KEY, loadState, saveState,
  listAgents, getAgent, enroll, approve, reject, revoke, remove,
  regenerateToken, findByToken, recordManifestResult, getGeneratedFiles,
};
