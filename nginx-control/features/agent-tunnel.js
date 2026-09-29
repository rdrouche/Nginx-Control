'use strict';
/**
 * Mode 3 — tunnel NAT sortant (Partie 2 "avancé" du document de conception).
 * Un agent derrière NAT, sans IP publique ni port entrant ouvert, ouvre
 * lui-même une connexion WebSocket SORTANTE vers ce dashboard
 * (`GET /api/agent/tunnel`, upgrade géré ici — jamais l'inverse, jamais le
 * dashboard qui tente de joindre l'agent). Le vhost généré pour ce mode
 * (voir lib/agent-manifest.js#generateAgentVhostContent, `mode: 'tunnel'`)
 * fait un simple `proxy_pass` vers ce dashboard lui-même
 * (`config/agents.yml#tunnel_target`, le même réseau Docker que nginx) : une
 * requête pour ce vhost arrive donc ici comme n'importe quelle requête HTTP
 * normale, AVANT d'atteindre le routeur applicatif — voir
 * `maybeHandleTunnelRequest()`, appelée tout en tête de `server.js`'s
 * `handleRequest()`.
 *
 * Protocole (JSON sur des frames texte WebSocket, voir lib/ws-lite.js) :
 *   Serveur -> Agent : {"type":"http-request","id","method","path","headers","bodyBase64"}
 *   Agent -> Serveur : {"type":"http-response","id","status","headers","bodyBase64"}
 *   Agent -> Serveur : {"type":"http-error","id","message"}   (echec local cote agent)
 *
 * Portée MVP délibérément limitée (voir le document de conception, section
 * "Mode 3", et le README) :
 * - une seule requête/réponse à la fois par connexion logique, corps
 *   entièrement bufferisé des deux côtés (pas de streaming, pas de SSE, pas
 *   de WebSocket-dans-le-tunnel) — plafonné à MAX_TUNNEL_BODY_BYTES ;
 * - un agent = une seule connexion active à la fois (une reconnexion
 *   remplace proprement la précédente, jamais deux en parallèle) ;
 * - une seule instance de dashboard : l'état des connexions vit en mémoire
 *   du process, jamais partagé/répliqué — un dashboard multi-instance (hors
 *   scope actuel de ce projet) devrait faire transiter cet état par un
 *   store partagé.
 * Ces limites sont documentées ici, dans le document de conception et dans
 * le README plutôt que masquées : elles suffisent à publier un service HTTP
 * classique (une appli web, une API) derrière NAT, pas à remplacer un vrai
 * tunnel générique.
 */

const crypto = require('crypto');

const cfg = require('../lib/config');
const httpLib = require('../lib/http');
const events = require('../lib/events');
const ws = require('../lib/ws-lite');
const agentsStore = require('../lib/agents-store');
const { parseAndValidate } = require('../lib/agents-yaml');
const { getTunnelSecret } = require('../lib/agent-tunnel-secret');

const { AGENTS_CONFIG_FILE } = cfg;
const { logEvent } = events;

const MAX_TUNNEL_BODY_BYTES = 5 * 1024 * 1024; // 5 Mo — voir le plafond de trame de lib/ws-lite.js (8 Mo, marge pour le base64 + JSON)
const TUNNEL_RESPONSE_TIMEOUT_MS = 30000;
// Fix (audit report, Basse/"Agents (dashboard)"): each in-flight tunnel
// request buffers its ENTIRE body/response in memory (up to
// MAX_TUNNEL_BODY_BYTES / the 8 Mo WebSocket frame cap) — the per-request
// caps alone say nothing about how many requests can be in flight AT ONCE,
// so a burst of concurrent large requests could still exhaust process
// memory. Two independent caps: per-agent (one compromised/misbehaving
// backend can't alone exhaust the budget) and a global one across every
// tunnel combined (the actual memory bound this whole file cares about).
// Both are deliberately generous for the MVP scope described in this file's
// own header comment (a handful of ordinary web requests, not a load
// balancer) — this is a circuit breaker against a memory blow-up, not a
// throughput tune.
const MAX_CONCURRENT_TUNNEL_REQUESTS_PER_AGENT = 20;
const MAX_CONCURRENT_TUNNEL_REQUESTS_GLOBAL = 200;
let globalInFlightRequests = 0;
const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

/** agentId -> { socket, parser, pending: Map(id -> {resolve, reject, timer}), connectedAt } */
const connections = new Map();

function loadConfig() {
  const fs = require('fs');
  let text = '';
  try { text = fs.readFileSync(AGENTS_CONFIG_FILE, 'utf8'); } catch { /* defaults */ }
  return parseAndValidate(text).settings;
}

function filterHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (HOP_BY_HOP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

function isConnected(agentId) { return connections.has(agentId); }

/** Every agentId that currently holds a live tunnel connection — for the Agents page. */
function connectedAgentIds() { return new Set(connections.keys()); }

/**
 * Build server_name(lowercase) -> agentId for every agent's currently
 * applied "tunnel" mode vhosts. Rebuilt on demand (small, in-memory data —
 * no need to cache) rather than maintained incrementally.
 */
function buildRouteTable() {
  const table = new Map();
  for (const a of agentsStore.listAgents()) {
    if (a.status !== 'approved') continue;
    for (const v of a.lastVhosts || []) {
      if (v.mode !== 'tunnel') continue;
      for (const name of v.serverNames || []) table.set(String(name).toLowerCase(), a.id);
    }
  }
  return table;
}

// Fix v12.22.0 (audit finding AGT-02): closeConnection() used to always
// remove/close whatever is CURRENTLY registered for agentId. On a fast
// reconnect, handleUpgrade() below replaces the registry entry for the old
// connection before that old socket's own 'close' event has necessarily
// fired yet; when it does fire a moment later, its handler used to call
// closeConnection(agent.id) again — which then deleted and closed the BRAND
// NEW connection instead of a no-op on the already-gone old one. Every event
// handler now captures its OWN `conn` object (see handleUpgrade()) and passes
// it here; a close is only actually applied if the registry still points at
// that exact same connection.
function closeConnection(agentId, reason, expectedConn) {
  const conn = connections.get(agentId);
  if (!conn) return;
  if (expectedConn !== undefined && conn !== expectedConn) return; // deja remplacee — rien a faire
  connections.delete(agentId);
  for (const { reject, timer } of conn.pending.values()) {
    clearTimeout(timer);
    reject(new Error(reason || 'tunnel ferme'));
  }
  try { conn.socket.end(); } catch { /* deja ferme */ }
}

/**
 * WebSocket upgrade handler for `GET /api/agent/tunnel`, registered on the
 * raw HTTP server's 'upgrade' event by server.js (see its own header comment
 * for why this can't go through the normal Router — same reasoning as
 * features/goaccess.js#handleUpgrade). Authenticated by the agent's own
 * bearer token (Authorization header — the WebSocket handshake itself is a
 * normal HTTP GET, so this is not a departure from how the rest of the
 * agent protocol authenticates).
 */
function handleUpgrade(req, socket, head) {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/api/agent/tunnel') return false; // pas pour nous — server.js essaie un autre handler

  const settings = loadConfig();
  if (!settings.tunnelEnable) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return true;
  }

  const authHeader = req.headers['authorization'] || '';
  const rawToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const agent = agentsStore.findByToken(rawToken);
  if (!agent) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return true;
  }

  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return true;
  }

  // Une reconnexion du meme agent remplace proprement la precedente —
  // jamais deux connexions actives en parallele pour le meme agent (voir
  // les limites MVP en tete de fichier).
  if (connections.has(agent.id)) closeConnection(agent.id, 'remplacee par une nouvelle connexion');

  socket.write(ws.handshakeResponse(key));

  // `inFlight` (fix, audit report, Basse/"Agents (dashboard)") counts
  // requests from the moment their body starts buffering — deliberately
  // NOT the same as `pending.size` (populated only once buffering finishes
  // and sendOverTunnel() actually sends the frame), so a burst of
  // concurrent requests still buffering is caught too, not just ones
  // already awaiting a response. See maybeHandleTunnelRequest()'s own cap.
  const conn = { socket, pending: new Map(), connectedAt: Date.now(), inFlight: 0 };
  const parser = new ws.FrameParser({
    onMessage: (opcode, payload) => {
      if (opcode === ws.OPCODE.CLOSE) { closeConnection(agent.id, 'ferme par l agent', conn); return; }
      if (opcode === ws.OPCODE.PING) { try { socket.write(ws.encodeFrame(payload, ws.OPCODE.PONG)); } catch {} return; }
      if (opcode !== ws.OPCODE.TEXT) return; // trames binaires non utilisees par ce protocole
      let msg;
      try { msg = JSON.parse(payload.toString('utf8')); } catch { return; }
      if (!msg || typeof msg !== 'object') return;

      if (msg.type === 'http-response' || msg.type === 'http-error') {
        const pending = conn.pending.get(msg.id);
        if (!pending) return; // reponse tardive (timeout deja ecoule) ou id inconnu
        conn.pending.delete(msg.id);
        clearTimeout(pending.timer);
        if (msg.type === 'http-error') pending.reject(new Error(msg.message || 'erreur cote agent'));
        else pending.resolve(msg);
      }
    },
    onError: (err) => {
      logEvent('agent-tunnel.protocol-error', { agentId: agent.id, error: err.message }, 'api');
      closeConnection(agent.id, err.message, conn);
    },
  });
  // Fix v12.22.0 (audit finding AGT-02): each handler below captures `conn`
  // (this exact connection object) and passes it to closeConnection() as
  // `expectedConn` — see that function's own header comment. Without this, a
  // slow-to-fire 'close'/'error' event from an OLD socket (already replaced
  // by a newer reconnection above) could tear down the NEW connection
  // instead, leaving every tunnel vhost for this agent returning 502 until
  // yet another reconnect.
  socket.on('data', (chunk) => parser.push(chunk));
  socket.on('close', () => closeConnection(agent.id, 'connexion fermee', conn));
  socket.on('error', () => closeConnection(agent.id, 'erreur socket', conn));
  if (head && head.length) parser.push(head);

  connections.set(agent.id, conn);
  logEvent('agent-tunnel.connected', { agentId: agent.id, hostname: agent.hostnameProposed }, 'api');
  return true;
}

/**
 * Send one HTTP request over an agent's tunnel and wait for its response.
 * Rejects on timeout, on a tunnel closing mid-flight, or on an explicit
 * http-error from the agent (its own local proxy_pass to the real backend
 * failed).
 */
function sendOverTunnel(agentId, requestMsg) {
  const conn = connections.get(agentId);
  if (!conn) return Promise.reject(new Error('tunnel non connecte'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      conn.pending.delete(requestMsg.id);
      reject(new Error('delai depasse (agent injoignable ou trop lent a repondre)'));
    }, TUNNEL_RESPONSE_TIMEOUT_MS);
    conn.pending.set(requestMsg.id, { resolve, reject, timer });
    try {
      conn.socket.write(ws.encodeText(JSON.stringify(requestMsg)));
    } catch (e) {
      conn.pending.delete(requestMsg.id);
      clearTimeout(timer);
      reject(e);
    }
  });
}

/**
 * Intercept an incoming HTTP request destined for a "tunnel" mode vhost,
 * BEFORE the normal `/api/*` dispatch in server.js#handleRequest() — this is
 * arbitrary third-party traffic for an end user's own vhost, not a dashboard
 * API call, so it carries no session and no `/api/` prefix in general.
 * Returns true if the request was handled here (whether successfully or
 * with an error response) — false means "not a tunnel request, continue the
 * normal dispatch chain".
 */
async function maybeHandleTunnelRequest(req, res) {
  // Fix v12.22.0 (audit finding AGT-04): recognizing tunnel traffic by Host
  // alone let any request that merely carried the right Host header be
  // routed to an agent's tunnel, before any authentication — see
  // lib/agent-tunnel-secret.js's header comment for the full scenario and
  // the fix. Only a request that carries this dashboard's own secret header
  // (attached by `proxy_set_header` in the generated tunnel vhost — nginx
  // adds it, not the original client) is eligible at all.
  const tunnelHeader = req.headers['x-nc-tunnel'];
  if (tunnelHeader !== getTunnelSecret()) return false;

  const hostHeader = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (!hostHeader) return false;
  const table = buildRouteTable();
  const agentId = table.get(hostHeader);
  if (!agentId) return false;

  const conn = connections.get(agentId);
  if (!conn) {
    httpLib.send(res, 502, { error: `Agent hors ligne (tunnel non connecte) pour ${hostHeader}` });
    return true;
  }

  // Fix (audit report, Basse/"Agents (dashboard)"): rejected BEFORE
  // buffering a single byte of this request's body — the whole point is to
  // never let an unbounded number of concurrent requests each hold up to
  // MAX_TUNNEL_BODY_BYTES in memory at once. 503 (not 502): the agent itself
  // is fine, the DASHBOARD is the one refusing, same semantics as any other
  // "server temporarily over capacity" response.
  if (conn.inFlight >= MAX_CONCURRENT_TUNNEL_REQUESTS_PER_AGENT) {
    httpLib.send(res, 503, { error: 'Trop de requetes en cours pour ce tunnel, reessayer' });
    return true;
  }
  if (globalInFlightRequests >= MAX_CONCURRENT_TUNNEL_REQUESTS_GLOBAL) {
    httpLib.send(res, 503, { error: 'Trop de requetes tunnel en cours, reessayer' });
    return true;
  }

  conn.inFlight++;
  globalInFlightRequests++;
  try {
    const chunks = [];
    let total = 0;
    let tooLarge = false;
    await new Promise((resolve) => {
      req.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_TUNNEL_BODY_BYTES) { tooLarge = true; return; } // on continue a drainer, mais sans garder
        chunks.push(chunk);
      });
      req.on('end', resolve);
      req.on('error', resolve);
    });
    if (tooLarge) { httpLib.send(res, 413, { error: 'Corps de requete trop volumineux pour le tunnel' }); return true; }

    const url = new URL(req.url, `http://${hostHeader}`);
    const requestMsg = {
      type: 'http-request',
      id: crypto.randomUUID(),
      method: req.method,
      path: url.pathname + url.search,
      headers: filterHeaders(req.headers),
      bodyBase64: chunks.length ? Buffer.concat(chunks).toString('base64') : '',
    };

    let reply;
    try {
      reply = await sendOverTunnel(agentId, requestMsg);
    } catch (e) {
      httpLib.send(res, 502, { error: `Tunnel agent : ${e.message}` });
      return true;
    }

    const status = Number.isInteger(reply.status) && reply.status >= 100 && reply.status <= 599 ? reply.status : 502;
    const headers = filterHeaders(reply.headers);
    let body = Buffer.alloc(0);
    if (typeof reply.bodyBase64 === 'string' && reply.bodyBase64) {
      try { body = Buffer.from(reply.bodyBase64, 'base64'); } catch { body = Buffer.alloc(0); }
    }
    try {
      res.writeHead(status, headers);
      res.end(body);
    } catch { /* client deja parti */ }
    return true;
  } finally {
    conn.inFlight--;
    globalInFlightRequests--;
  }
}

/**
 * No-op — ce module n'enregistre aucune route Router (voir l'en-tete de
 * fichier : upgrade WebSocket + interception par Host, tous les deux
 * branches directement par server.js). Exportee uniquement pour rester
 * compatible avec tout code qui parcourt features/*.js et appelle
 * register(router) de maniere generique sur chacun (voir
 * test/routes.test.js) — server.js lui-meme n'appelle jamais celle-ci, il
 * cable handleUpgrade()/maybeHandleTunnelRequest() a la main.
 */
function register() {}

module.exports = {
  MAX_TUNNEL_BODY_BYTES, TUNNEL_RESPONSE_TIMEOUT_MS,
  MAX_CONCURRENT_TUNNEL_REQUESTS_PER_AGENT, MAX_CONCURRENT_TUNNEL_REQUESTS_GLOBAL,
  register, handleUpgrade, maybeHandleTunnelRequest,
  isConnected, connectedAgentIds, buildRouteTable,
  // Exposes pour les tests unitaires uniquement.
  closeConnection, connections,
};
