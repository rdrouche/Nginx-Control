'use strict';
/**
 * Registre de la synchronisation de certificats (v12.59.0) : jetons d'accès
 * émis par CE nœud, et sources distantes configurées sur CE nœud.
 *
 * Stocké dans la table `state` clé/valeur de lib/events.js (comme les agents).
 *
 *  - Jeton émis (`tokens`) : seul le SHA-256 est conservé ; le jeton brut n'est
 *    montré qu'une fois, à la création. `scope` : 'pull' (l'autre nœud lit ces
 *    certificats) ou 'push' (l'autre nœud les écrit ici). Limité à une liste de
 *    noms de certificats.
 *  - Source distante (`remotes`) : l'autre Nginx Control à interroger (pull) ou
 *    à alimenter (push). Son jeton est un secret en clair (il doit être
 *    présenté) : il ne remonte jamais dans une réponse d'API.
 */
const crypto = require('crypto');
const events = require('./events');
const { hashToken, safeCompareHash } = require('./agent-tokens');

const STATE_KEY = 'certsync_state';
const TOKEN_PREFIX = 'cst_';
const MAX_TOKENS = 100;
const MAX_REMOTES = 50;

function load() {
  const s = events.getState(STATE_KEY) || {};
  return { tokens: s.tokens || {}, remotes: s.remotes || {} };
}
function save(state) { events.setState(STATE_KEY, state); }
const newId = (map) => { let id; do { id = crypto.randomBytes(6).toString('hex'); } while (map[id]); return id; };

// ─── Jetons émis ─────────────────────────────────────────────────────────────
function publicToken(t) {
  return { id: t.id, name: t.name, scope: t.scope, certs: t.certs, createdAt: t.createdAt, createdBy: t.createdBy, lastUsedAt: t.lastUsedAt || null, lastUsedIp: t.lastUsedIp || null };
}
function listTokens() { return Object.values(load().tokens).sort((a, b) => b.createdAt - a.createdAt).map(publicToken); }
function getToken(id) { return load().tokens[id] || null; }

function createToken({ name, scope, certs }, by) {
  const state = load();
  if (Object.keys(state.tokens).length >= MAX_TOKENS) return { ok: false, error: `${MAX_TOKENS} jetons maximum` };
  const raw = TOKEN_PREFIX + crypto.randomBytes(24).toString('hex');
  const id = newId(state.tokens);
  state.tokens[id] = { id, name, scope, certs, tokenHash: hashToken(raw), createdAt: Date.now(), createdBy: by, lastUsedAt: null, lastUsedIp: null };
  save(state);
  return { ok: true, token: publicToken(state.tokens[id]), rawToken: raw };
}

function revokeToken(id) {
  const state = load();
  if (!state.tokens[id]) return false;
  delete state.tokens[id];
  save(state);
  return true;
}

/** Recherche à temps constant (toutes les entrées sont comparées), comme lib/agents-store.js. */
function findByToken(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const hash = hashToken(raw);
  let match = null;
  for (const t of Object.values(load().tokens)) if (safeCompareHash(t.tokenHash, hash)) match = t;
  return match;
}

function touchToken(id, ip) {
  const state = load();
  if (!state.tokens[id]) return;
  state.tokens[id].lastUsedAt = Date.now();
  state.tokens[id].lastUsedIp = String(ip || '').slice(0, 64);
  save(state);
}

// ─── Sources distantes ───────────────────────────────────────────────────────
function publicRemote(r) {
  const { token, tls, ...rest } = r;
  return { ...rest, tokenSet: !!token, tls: { mode: tls.mode, pin: tls.pin || '', caSet: !!tls.ca } };
}
function listRemotes() { return Object.values(load().remotes).sort((a, b) => a.name.localeCompare(b.name)).map(publicRemote); }
function getRemote(id) { return load().remotes[id] || null; }

function saveRemote(id, value, by) {
  const state = load();
  const existing = id ? state.remotes[id] : null;
  if (id && !existing) return { ok: false, status: 404, error: 'source introuvable' };
  if (!existing && Object.keys(state.remotes).length >= MAX_REMOTES) return { ok: false, error: `${MAX_REMOTES} sources maximum` };
  const rid = existing ? existing.id : newId(state.remotes);
  // Nouvelle destination ou nouveau sens : les empreintes déjà poussées ne valent plus.
  if (existing && (existing.url !== value.url || existing.direction !== value.direction)) existing.lastPushed = {};
  state.remotes[rid] = {
    lastSyncAt: null, lastStatus: null, lastMessage: null, results: [], lastPushed: {},
    ...(existing || {}), ...value, id: rid, updatedAt: Date.now(), updatedBy: by, createdAt: existing ? existing.createdAt : Date.now(),
  };
  save(state);
  return { ok: true, remote: state.remotes[rid] };
}

function deleteRemote(id) {
  const state = load();
  if (!state.remotes[id]) return false;
  delete state.remotes[id];
  save(state);
  return true;
}

/** Résultat d'une synchro : statut global, message, détail par certificat, empreintes déjà poussées. */
function recordSync(id, { status, message, results, lastPushed }) {
  const state = load();
  const r = state.remotes[id];
  if (!r) return null;
  r.lastSyncAt = Date.now(); r.lastStatus = status; r.lastMessage = String(message || '').slice(0, 500);
  r.results = (results || []).slice(0, 100);
  if (lastPushed) r.lastPushed = { ...r.lastPushed, ...lastPushed };
  save(state);
  return r;
}

module.exports = {
  STATE_KEY, TOKEN_PREFIX, listTokens, getToken, createToken, revokeToken, findByToken, touchToken,
  listRemotes, getRemote, saveRemote, deleteRemote, recordSync,
};
