'use strict';
/**
 * Per-vhost PAUSE store for remote agents (Partie 2 du document de
 * conception — hôtes Docker distants, `nginx-agent`). Counterpart to
 * features/docker-autoconfig.js's own `docker_autoconfig_state.decisions`,
 * but for agent-pushed manifests, with one fundamental difference: a remote
 * agent has NO per-vhost approval gate today — approval happens once, at the
 * whole-AGENT level, in lib/agents-store.js (`pending -> approved`). Every
 * valid vhost in an approved agent's manifest is applied automatically.
 *
 * This store therefore only ever holds ONE kind of decision — `paused` — set
 * explicitly by an operator to stop a specific vhost from being published
 * without touching the agent's own approval or making the agent re-enroll.
 * There is no "approved"/"rejected" state to persist here: an entry that
 * isn't paused simply doesn't exist in this store at all.
 *
 * Keyed by `agentId` then by the vhost's own decision key (its sorted,
 * lower-cased server_names, same convention as
 * features/docker-autoconfig.js#namesDecisionKey()) so a pause survives
 * whether or not the agent is currently online/pushing, and independently of
 * `agent.lastVhosts` (which only reflects the MOST RECENT manifest push and
 * is cleared on revoke — see lib/agents-store.js).
 *
 * Persisted the same way as every other stateful feature (lib/events.js's
 * key/value `state` table) — no new file format for a small, occasionally-
 * updated map.
 */
const events = require('./events');

const STATE_KEY = 'agent_vhost_decisions_state';

function loadState() {
  const s = events.getState(STATE_KEY);
  return { decisions: {}, ...(s || {}) };
}
function saveState(state) { events.setState(STATE_KEY, state); }

/** Same convention as features/docker-autoconfig.js#namesDecisionKey(): a
 * decision is tied to the full, sorted, lower-cased set of server_names —
 * never just the first one — so adding/removing a name requires a fresh
 * decision instead of silently inheriting the old one. */
function namesDecisionKey(serverNames) {
  return [...(serverNames || [])].map(n => String(n || '').toLowerCase()).sort().join(',');
}

function getAgentDecisions(agentId) {
  return loadState().decisions[agentId] || {};
}

function getDecision(agentId, decisionKey) {
  return getAgentDecisions(agentId)[decisionKey] || null;
}

/** Pause a vhost: excluded from the next apply cycle until resume() is called — the underlying manifest entry (and the agent's own approval) is untouched. */
function setPaused(agentId, decisionKey, names, by) {
  const state = loadState();
  if (!state.decisions[agentId]) state.decisions[agentId] = {};
  state.decisions[agentId][decisionKey] = {
    names: [...(names || [])],
    paused: true,
    pausedAt: new Date().toISOString(),
    pausedBy: by || null,
  };
  saveState(state);
}

/** Resume a paused vhost — since this store only ever contains paused
 * entries, resuming and forgetting a stale entry (a vhost the agent no
 * longer declares at all) are the exact same operation: delete it. Returns
 * false if there was nothing to resume. */
function resume(agentId, decisionKey) {
  const state = loadState();
  const bucket = state.decisions[agentId];
  if (!bucket || !bucket[decisionKey]) return false;
  delete bucket[decisionKey];
  if (!Object.keys(bucket).length) delete state.decisions[agentId];
  saveState(state);
  return true;
}

/** Called when an agent record is permanently deleted (lib/agents-store.js#remove()) so orphaned pause entries never accumulate for an agent id that no longer exists. */
function removeAgent(agentId) {
  const state = loadState();
  if (!state.decisions[agentId]) return;
  delete state.decisions[agentId];
  saveState(state);
}

module.exports = {
  STATE_KEY, namesDecisionKey, getAgentDecisions, getDecision, setPaused, resume, removeAgent,
};
