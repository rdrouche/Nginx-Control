'use strict';
/**
 * Hôtes Docker distants (agents) — Partie 2 "fondations" du document de
 * conception (Projet Claude). Un agent léger tournant sur un hôte Docker
 * distant s'enrôle, se fait approuver par un opérateur (jeton scopé généré
 * ici, jamais choisi par l'agent), puis pousse un manifeste JSON de vhosts
 * désirés — même esprit que les labels Docker de la Partie 1
 * (features/docker-autoconfig.js), mais authentifié par un jeton Bearer
 * plutôt que lu depuis le socket Docker local, et en "mode direct"
 * uniquement (voir lib/agent-manifest.js : la cible d'une location est un
 * `scheme://ip:port` déjà joignable, jamais un nom de conteneur Docker à
 * résoudre — ce mécanisme n'a de sens que sur l'hôte de nginx lui-même).
 *
 * Tout le parsing/validation/rendu pur vit dans lib/agent-manifest.js ; la
 * registre des agents (état, jetons) vit dans lib/agents-store.js (voir son
 * propre en-tête pour pourquoi c'est un module lib/ et non features/) ; ce
 * fichier ne fait que l'orchestration : décider quoi générer à partir d'un
 * manifeste validé, écrire, tester, recharger, et exposer les routes —
 * exactement le même pipeline test-avant-reload/rollback déjà construit pour
 * features/blocklists.js et features/docker-autoconfig.js.
 *
 * Sécurité : un manifeste arrive du réseau, authentifié par un simple jeton
 * Bearer (V1, voir le document de conception — mTLS reste une option V2
 * future) — traité avec au moins autant de méfiance qu'un label Docker de la
 * Partie 1. Chaque valeur passe par lib/agent-manifest.js's validation
 * ancrée avant d'être écrite dans un fichier nginx. Un `serverName` déjà
 * revendiqué par un vhost manuel, par Partie 1 (docker_*.conf) ou par un
 * AUTRE agent n'est jamais résolu en silence — ce vhost-là est rejeté avec
 * une erreur explicite renvoyée à l'agent, les autres vhosts valides du même
 * manifeste sont appliqués normalement.
 */

const fs   = require('fs');
const path = require('path');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');
const notify  = require('../lib/notify');
const { pushNotification } = require('../lib/notifications');
const { checkDomainConflict } = require('../lib/certs');
const { listSSLSnippets } = require('../lib/snippets');
const { parseAndValidate } = require('../lib/agents-yaml');
const { validateManifest, agentVhostFileName, generateAgentVhostContent, sanitizeForFilename } = require('../lib/agent-manifest');
const { getTunnelSecret } = require('../lib/agent-tunnel-secret');
const agentsStore = require('../lib/agents-store');
const agentVhostDecisions = require('../lib/agent-vhost-decisions');
const { withLock } = require('../lib/nginx-write-lock');

const { DIR_SITES, DIR_CONF, AGENTS_CONFIG_FILE } = cfg;
// Fix v12.22.0 (audit finding AGT-04, part 2): the server_name conflict scan
// used to look only at DIR_SITES, never DIR_CONF (conf.d) — same two
// directories features/docker-autoconfig.js, features/analyzer.js and
// features/monitor.js already scan together as their own "upstream dirs".
// A manually-authored or Partie 1 vhost placed in conf.d could previously be
// silently shadowed by an agent's manifest.
const CONFLICT_SCAN_DIRS = [DIR_SITES, DIR_CONF];
const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { logEvent } = events;
const { sendNotification } = notify;

const AGENT_ID_RE = /^[0-9a-f]{16}$/;
const AGENT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

// Composition-root injection (server.js#setDeps) : ce module ne peut pas
// require() features/agent-tunnel.js ou features/certbot(-dns).js directement
// (les features ne se requierent jamais entre elles). isTunnelConnected()
// reste une fonction no-op, et les getters/emetteurs Certbot restent
// "toujours desactive"/"non cable", tant que server.js n'a pas injecte les
// vraies implementations — meme discipline fail-safe que
// features/docker-autoconfig.js's propre `deps` par defaut, utile aussi pour
// les tests unitaires qui n'appellent jamais setDeps().
let deps = {
  isTunnelConnected: () => false,
  // Fix (audit report, Basse/"Agents (dashboard)"): no-op by default (same
  // fail-safe discipline as the other stubs here) — a boot order or test
  // that never called setDeps() must never look like it closed a tunnel it
  // didn't actually touch.
  closeTunnel: () => {},
  getCertbotCfg: () => ({ enable: false }),
  getCertbotDnsCfg: () => ({ enable: false }),
  issueHttp: async () => ({ error: 'issueHttp not wired (setDeps() missing)' }),
  issueDns: async () => ({ error: 'issueDns not wired (setDeps() missing)' }),
  // Fix (audit report, Basse/"Partie 1 et certificats"), mirror of
  // features/docker-autoconfig.js's own deps entry: null (never rendered)
  // until Certbot's HTTP challenge is actually enabled upstream.
  getCertbotWebrootPath: () => null,
};
function setDeps(d) { deps = { ...deps, ...d }; }

// ─── Config ───────────────────────────────────────────────────────────────
function loadConfig() {
  let text = '';
  try { text = fs.readFileSync(AGENTS_CONFIG_FILE, 'utf8'); } catch { /* missing = defaults apply */ }
  return { text, ...parseAndValidate(text) };
}

// ─── Etat d'emission Certbot pour les agents (v12.21.0) ────────────────────
// Meme role que features/docker-autoconfig.js#loadState()'s `state.issuance`
// pour la Partie 1 : un etat persiste par cle "serverName" (idle/issuing/
// failed), separe car un meme domaine pourrait en theorie etre demande a la
// fois par un agent et par un conteneur local — deux cles/deux compteurs de
// tentatives distincts, jamais partages.
const CERTBOT_STATE_KEY = 'agents_certbot_state';
// Fix v12.21.2 (audit finding AGT-05, defense in depth): a minimum pause
// after a SUCCESSFUL issuance, on top of the case-normalization fix above —
// in case checkDomainConflict() ever misses a just-issued certificate for
// any other reason (a filesystem write not yet visible, a clock skew), this
// still stops a manifest push from re-triggering a brand-new ACME issuance
// within minutes of the last one, which is exactly what burns through
// Let's Encrypt's real-world rate limits.
const MIN_DELAY_AFTER_SUCCESS_MS = 10 * 60_000;
// Fix v12.21.2 (audit finding DAC-07, part 2 — same fix as
// features/docker-autoconfig.js, applied here for consistency): an
// 'issuing' entry that never resolved (process restarted mid-emission) is
// treated as a failed attempt after this long, so it re-enters the normal
// failed/retryMinutes backoff instead of blocking retries forever.
const STUCK_ISSUING_MS = 10 * 60_000;
function effectiveIssuanceEntry(entry) {
  if (entry?.status === 'issuing' && (Date.now() - (entry.lastAttemptAt || 0)) > STUCK_ISSUING_MS) {
    return { ...entry, status: 'failed', lastError: entry.lastError || 'emission bloquee (redemarrage du processus pendant l emission ?), consideree en echec' };
  }
  return entry;
}
function loadCertbotState() { return events.getState(CERTBOT_STATE_KEY) || { issuance: {} }; }
function saveCertbotState(state) { events.setState(CERTBOT_STATE_KEY, state); }

/**
 * Fix (audit report, Basse/"Agents (dashboard)"): CERTBOT_STATE_KEY's
 * issuance map is keyed purely by the FIRST server name of a vhost (see
 * triggerAgentCertbotIssuanceIfDue()'s own call site below) — never by
 * agentId, since the same domain issued for a revoked agent and then
 * re-declared by a brand new one must reuse the very same certificate
 * lookup. But that also means a stale 'failed' entry (with its own
 * `retryMinutes` backoff already running) was never cleared when the agent
 * that caused it was revoked — inherited unconditionally by the NEXT agent
 * to ever declare that exact server name, even years later, with no
 * relation to whatever actually caused the original failure. Called from
 * the revoke route below with every server name the just-revoked agent's
 * last-applied vhosts carried.
 */
function clearCertbotStateForServerNames(serverNames) {
  if (!serverNames || !serverNames.length) return;
  const state = loadCertbotState();
  state.issuance = state.issuance || {};
  let changed = false;
  for (const name of serverNames) {
    const key = String(name).toLowerCase();
    if (key in state.issuance) { delete state.issuance[key]; changed = true; }
  }
  if (changed) saveCertbotState(state);
}

function atomicWrite(filePath, content) {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, filePath);
}

/**
 * SSL resolution for an agent vhost — exact mirror of
 * features/docker-autoconfig.js#resolveSsl() (see that function's own header
 * for the full rationale), now including the certbot_http/certbot_dns
 * branches (v12.21.0 — the one gap the design doc's "Ce qu'il manque"
 * flagged for the agents path since v12.18.0). checkDomainConflict()
 * (lib/certs.js) is the same function Partie 1 uses: a certificate already
 * issued for this server_name (by hand, by the scheduled renewal, by Partie 1
 * itself, or by another agent) is detected and used immediately, regardless
 * of which mechanism originally requested it.
 *
 * Stays pure and read-only, called from BOTH applyManifestForAgent() (which
 * writes files) and the GET /api/agents route (never allowed side effects) —
 * exactly the same split as resolveSsl()/triggerCertbotIssuanceIfDue() in
 * docker-autoconfig.js. `issuanceState` (this function's second argument,
 * the persisted CERTBOT_STATE_KEY map) only ever makes this report what is
 * ALREADY known; deciding whether to actually kick off a new emission lives
 * entirely in triggerAgentCertbotIssuanceIfDue() below.
 */
function resolveAgentSsl(validated, issuanceState = {}) {
  if (!validated.ssl.active) return undefined;
  if (validated.ssl.mode === 'snippet') return { type: 'snippet', file: validated.ssl.snippetFile };
  if (validated.ssl.mode === 'auto') {
    // Fix v12.21.2 (audit finding DAC-04): pass every server_name so the
    // matched certificate must cover the WHOLE vhost, not just the first name.
    const result = checkDomainConflict(validated.serverNames[0], { allNames: validated.serverNames });
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
          ? "Certbot-DNS n est pas active (config/certbot-dns.yml : enable: false) — l activer et renseigner ses identifiants avant qu un agent puisse utiliser sslCertificate=certbot_dns."
          : "Certbot n est pas active (config/certbot.yml : enable: false) — l activer avant qu un agent puisse utiliser sslCertificate=certbot_http.",
      };
    }
    const result = checkDomainConflict(validated.serverNames[0], { allNames: validated.serverNames });
    if (result.conflict) {
      return {
        type: 'cert',
        certPath: `/etc/letsencrypt/live/${result.cert}/fullchain.pem`,
        keyPath: `/etc/letsencrypt/live/${result.cert}/privkey.pem`,
      };
    }
    const entry = effectiveIssuanceEntry(issuanceState[validated.serverNames[0].toLowerCase()]);
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
 * Whether to fire an ASYNC certbot/certbot-dns issuance right now for `key`
 * (le premier server_name du vhost, en minuscules), et le fait — jamais
 * attendu par l'appelant (applyManifestForAgent()) : miroir exact de
 * features/docker-autoconfig.js#triggerCertbotIssuanceIfDue(), voir sa propre
 * documentation pour la machine a etats complete (idle/issuing/failed,
 * backoff `retryMinutes`). Seule difference : persiste dans
 * CERTBOT_STATE_KEY plutot que dans l'etat de docker-autoconfig.js — deux
 * compteurs de tentatives independants si le meme domaine est un jour
 * demande par les deux mecanismes.
 */
function triggerAgentCertbotIssuanceIfDue(key, mode, serverNames, retryMinutes) {
  const state = loadCertbotState();
  state.issuance = state.issuance || {};
  const entry = effectiveIssuanceEntry(state.issuance[key]);
  const now = Date.now();
  if (entry?.status === 'issuing') return;
  if (entry?.status === 'failed' && (now - (entry.lastAttemptAt || 0)) < retryMinutes * 60_000) return;
  if (entry?.status === 'idle' && (now - (entry.lastAttemptAt || 0)) < MIN_DELAY_AFTER_SUCCESS_MS) return;

  const attempts = (entry?.attempts || 0) + 1;
  state.issuance[key] = { status: 'issuing', lastAttemptAt: now, lastError: entry?.lastError || null, attempts };
  saveCertbotState(state);
  logEvent('agents.certbot_issue.start', { key, mode, attempts }, 'system');

  const issueFn = mode === 'certbot_dns' ? deps.issueDns : deps.issueHttp;
  Promise.resolve(issueFn(serverNames, { source: 'agents' }))
    .then(result => {
      const fresh = loadCertbotState();
      fresh.issuance = fresh.issuance || {};
      if (result && result.ok) {
        fresh.issuance[key] = { status: 'idle', lastAttemptAt: now, lastError: null, attempts };
      } else {
        fresh.issuance[key] = { status: 'failed', lastAttemptAt: now, lastError: (result && result.error) || 'echec inconnu', attempts };
      }
      saveCertbotState(fresh);
    })
    .catch(e => {
      const fresh = loadCertbotState();
      fresh.issuance = fresh.issuance || {};
      fresh.issuance[key] = { status: 'failed', lastAttemptAt: now, lastError: e.message || String(e), attempts };
      saveCertbotState(fresh);
    });
}

/**
 * Apply one manifest push from an already-approved agent: validate, resolve
 * conflicts against everything NOT belonging to this same agent, render,
 * diff against what this agent generated last time, write/remove, test,
 * rollback on failure, reload. Returns a summary the caller (the route
 * handler) sends straight back to the agent as the HTTP response — the
 * agent's own script can then log/alert on a per-vhost basis without a
 * second round-trip.
 */
async function applyManifestForAgent(agent, body, { actor = `agent:${agent.id}` } = {}) {
  const { settings } = loadConfig();
  if (!settings.enable) {
    return { ok: false, error: "Agents distants desactives (config/agents.yml: enable: false)", vhosts: [] };
  }

  const manifestResult = validateManifest(body, { maxVhosts: settings.maxVhostsPerAgent, allowedListenPorts: settings.allowedListenPorts });
  if (!manifestResult.valid) {
    return { ok: false, error: manifestResult.errors.join('; '), vhosts: [] };
  }

  const certbotIssuanceState = loadCertbotState().issuance || {};
  const availableSslSnippets = new Set(listSSLSnippets().map(s => s.file));
  const thisPrefix = `agent_${sanitizeForFilename(agent.id)}_`;

  // server_name already claimed by anything NOT belonging to THIS agent
  // (a manually-authored vhost, a Partie 1 docker_*.conf, or another
  // agent's own agent_*.conf) — a manifest must never silently take one of
  // those over, same rule Partie 1 applies to its own manualServerNames
  // check. A lightweight regex scan (no full lib/vhost-targets.js parse
  // needed) — same technique features/docker-autoconfig.js already uses for
  // the same purpose.
  const claimedElsewhere = new Set();
  for (const dir of CONFLICT_SCAN_DIRS) {
    try {
      for (const name of fs.readdirSync(dir)) {
        if (name.startsWith(thisPrefix)) continue;
        let content = '';
        try { content = fs.readFileSync(path.join(dir, name), 'utf8'); } catch { /* raced removal */ }
        const lines = content.match(/server_name\s+([^;]+);/g) || [];
        for (const line of lines) {
          for (const tok of line.replace(/^server_name\s+/, '').replace(/;$/, '').split(/\s+/)) {
            if (tok && tok !== '_') claimedElsewhere.add(tok.toLowerCase());
          }
        }
      }
    } catch { /* dir missing — nothing to conflict with there */ }
  }

  const claimCountInManifest = new Map();
  for (const v of manifestResult.vhosts) {
    if (!v.valid) continue;
    for (const n of v.serverNames) claimCountInManifest.set(n.toLowerCase(), (claimCountInManifest.get(n.toLowerCase()) || 0) + 1);
  }

  const results = [];   // per-vhost outcome, returned to the agent
  const eligible = [];  // { file, content, serverNames, listen, sslMode }
  for (const v of manifestResult.vhosts) {
    const label = (v.serverNames && v.serverNames.length) ? v.serverNames.join(' ')
      : (v.raw && typeof v.raw.serverName === 'string' ? v.raw.serverName : '(sans serverName)');
    if (!v.valid) { results.push({ serverName: label, ok: false, errors: v.errors }); continue; }

    if (v.ssl.mode === 'snippet' && !availableSslSnippets.has(v.ssl.snippetFile)) {
      results.push({ serverName: label, ok: false, errors: [`sslCertificateSnippet introuvable : "${v.ssl.snippetFile}"`] });
      continue;
    }
    const conflictNames = v.serverNames.filter(n =>
      claimedElsewhere.has(n.toLowerCase()) || claimCountInManifest.get(n.toLowerCase()) > 1);
    if (conflictNames.length) {
      results.push({ serverName: label, ok: false, errors: [`conflit de server_name (deja utilise ailleurs, ou duplique dans ce meme manifeste) : ${conflictNames.join(', ')}`] });
      continue;
    }

    if (v.mode === 'tunnel' && !settings.tunnelEnable) {
      results.push({ serverName: label, ok: false, errors: ['mode "tunnel" desactive (config/agents.yml: tunnel_enable: false)'] });
      continue;
    }

    // Relay mode : la cible est fournie par l'AGENT lui-meme (enveloppe du
    // manifeste, `relay.http`/`relay.https`), pas par config/agents.yml
    // (contrairement au tunnel, ou le dashboard est la cible fixe). Deja
    // verifie plus haut par lib/agent-manifest.js#validateManifest() —
    // `v.valid` serait deja false ici si le schema choisi n'a pas d'adresse
    // correspondante dans l'enveloppe — mais on reste defensif.
    const relayTarget = v.mode === 'relay' ? (manifestResult.relay || {})[v.relayScheme] : undefined;
    if (v.mode === 'relay' && !relayTarget) {
      results.push({ serverName: label, ok: false, errors: [`mode "relay" (relayScheme=${v.relayScheme}) mais relay.${v.relayScheme} absent du manifeste`] });
      continue;
    }

    // Pause operateur (v12.36.0) : un vhost valide, sans conflit, peut malgre
    // tout etre volontairement exclu de la publication — meme mecanisme que
    // le "paused" de Partie 1 (features/docker-autoconfig.js), mais ici la
    // decision ne remplace aucune approbation existante (il n'y en a pas de
    // separee cote agent) : elle vient juste bloquer CE vhost precis tant que
    // l'operateur n'a pas repris la publication, sans toucher a l'approbation
    // de l'agent lui-meme ni aux autres vhosts de son manifeste.
    const decisionKey = agentVhostDecisions.namesDecisionKey(v.serverNames);
    const decision = agentVhostDecisions.getDecision(agent.id, decisionKey);
    if (decision?.paused) {
      results.push({ serverName: label, ok: true, paused: true });
      continue;
    }

    const file = path.join(DIR_SITES, agentVhostFileName(agent.id, v.serverNames));
    const sslResolved = resolveAgentSsl(v, certbotIssuanceState);
    const content = generateAgentVhostContent(v, v.serverNames, v.listen, {
      agentId: agent.id, agentName: agent.hostnameProposed, sslResolved,
      tunnelTarget: settings.tunnelTarget, relayTarget, tunnelSecret: getTunnelSecret(),
      certbotWebrootPath: v.ssl?.mode === 'certbot_http' ? deps.getCertbotWebrootPath() : null,
    });
    const sslStatus = sslResolved ? sslResolved.type : null;
    const sslError = sslResolved?.type === 'error' ? { code: sslResolved.code, message: sslResolved.message } : null;
    eligible.push({ file, content, serverNames: v.serverNames, listen: v.listen, sslMode: v.ssl.mode, sslStatus, sslError, mode: v.mode, relayTarget });
    results.push({ serverName: label, ok: true });

    // Declenchement actif d'une emission Certbot/Certbot-DNS (v12.21.0) —
    // jamais attendu ici (voir triggerAgentCertbotIssuanceIfDue()'s own
    // header), uniquement quand resolveAgentSsl() vient de rapporter un
    // "pending" simple (ni deja "issuing", ni en attente du backoff apres
    // un echec — ces deux cas sont deja geres par la machine a etats).
    // Fix v12.21.2 (audit finding DAC-07, part 1, applied here too): a
    // previously FAILED attempt must also be allowed to re-enter
    // triggerAgentCertbotIssuanceIfDue() — its own retryMinutes backoff
    // decides whether a new attempt is actually due yet.
    const isCertbotMode = v.ssl.mode === 'certbot_http' || v.ssl.mode === 'certbot_dns';
    const dueForAttempt = (sslResolved?.type === 'pending' && !sslResolved.issuing)
      || (sslResolved?.type === 'error' && sslResolved.code === 'certbot_issuance_failed');
    if (isCertbotMode && dueForAttempt) {
      triggerAgentCertbotIssuanceIfDue(v.serverNames[0].toLowerCase(), v.ssl.mode, v.serverNames, settings.certbotRetryMinutes);
    }
  }

  // Diff against what this agent generated on its previous push.
  const nextFiles = eligible.map(e => e.file);
  const prevFiles = agent.generatedFiles || [];
  const toWrite = [];
  const strip = s => (s || '').replace(/^# Genere le:.*$/m, '');
  for (const e of eligible) {
    const current = fs.existsSync(e.file) ? fs.readFileSync(e.file, 'utf8') : null;
    if (strip(current) !== strip(e.content)) toWrite.push(e);
  }
  const toRemove = prevFiles.filter(f => !nextFiles.includes(f));

  if (!toWrite.length && !toRemove.length) {
    // Fix v12.22.0 (audit finding AGT-03, remaining item): this fast path
    // writes nothing to disk, but it still calls recordManifestResult() —
    // re-check status here too (recordManifestResult() itself now refuses a
    // non-approved agent regardless, but failing fast with the same clear
    // error as the write path keeps behavior consistent for the caller).
    const freshAgent = agentsStore.getAgent(agent.id);
    if (!freshAgent || freshAgent.status !== 'approved') {
      logEvent('agents.manifest.rejected_stale_approval', { agentId: agent.id, by: actor }, 'api');
      return { ok: false, error: 'agent no longer approved', vhosts: results };
    }
    agentsStore.recordManifestResult(agent.id, {
      ok: true, generatedFiles: nextFiles, vhostCount: eligible.length,
      lastVhosts: eligible.map(e => ({ serverNames: e.serverNames, listen: e.listen, sslMode: e.sslMode, sslStatus: e.sslStatus, sslError: e.sslError, mode: e.mode, relayTarget: e.relayTarget })),
      protocolVersion: manifestResult.protocolVersion, metrics: manifestResult.metrics,
      lastManifestBody: body,
    });
    return { ok: true, reloaded: false, skippedNoChange: true, vhosts: results };
  }

  // Fix v12.21.2 (audit finding DAC-05, applied here too): write, test,
  // rollback and reload run inside the mutex shared with
  // features/blocklists.js and features/docker-autoconfig.js — see
  // lib/nginx-write-lock.js's own header.
  return withLock(async () => {
    // Fix v12.21.2 (audit finding AGT-03): re-read the agent's CURRENT
    // status here, right before writing anything, under the same lock that
    // serializes every write — the caller (the route handler) checked
    // `approved` before awaiting parseBody(req), which can take an
    // arbitrarily long time for a slow/malicious client. An agent revoked
    // while its request body was still arriving must never have its
    // manifest applied after the fact.
    const freshAgent = agentsStore.getAgent(agent.id);
    if (!freshAgent || freshAgent.status !== 'approved') {
      logEvent('agents.manifest.rejected_stale_approval', { agentId: agent.id, by: actor }, 'api');
      return { ok: false, error: 'agent no longer approved', vhosts: results };
    }

    const snapshot = new Map();
    for (const e of toWrite) snapshot.set(e.file, fs.existsSync(e.file) ? fs.readFileSync(e.file, 'utf8') : null);
    for (const f of toRemove) snapshot.set(f, fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null);

    try {
      fs.mkdirSync(DIR_SITES, { recursive: true });
      for (const e of toWrite) atomicWrite(e.file, e.content);
      for (const f of toRemove) { try { fs.unlinkSync(f); } catch {} }
    } catch (e) {
      logEvent('agents.write.error', { agentId: agent.id, by: actor, error: e.message }, 'api');
      return { ok: false, error: e.message, vhosts: results };
    }

    let applyResult;
    try {
      await docker.execNginx('nginx -t');
      applyResult = { ok: true };
    } catch (e) {
      for (const [file, prev] of snapshot) {
        try { if (prev === null) fs.unlinkSync(file); else atomicWrite(file, prev); } catch {}
      }
      applyResult = { ok: false, testFailed: true, error: e.error || e.message, stderr: e.stderr || e.stdout || '' };
    }

    if (!applyResult.ok) {
      logEvent('agents.test.failed', { agentId: agent.id, by: actor, error: applyResult.error, stderr: applyResult.stderr }, 'api');
      pushNotification({ type: 'agent_manifest_failed', level: 'error',
        message: `Agent ${agent.hostnameProposed || agent.id} : nginx -t a echoue, le manifeste a ete annule` });
      await sendNotification('agent_manifest_failed',
        '[Nginx Dashboard] Agent distant — nginx -t FAILED',
        `The manifest pushed by agent ${agent.hostnameProposed || agent.id} failed nginx -t and was rolled back.\n\n${applyResult.stderr || applyResult.error || ''}`
      ).catch(() => {});
      agentsStore.recordManifestResult(agent.id, { ok: false, error: applyResult.error, protocolVersion: manifestResult.protocolVersion, metrics: manifestResult.metrics });
      return { ok: false, reloaded: false, testFailed: true, error: applyResult.error, vhosts: results };
    }

    try {
      await docker.execNginx('nginx -s reload');
    } catch (e) {
      logEvent('agents.reload.failed', { agentId: agent.id, by: actor, error: e.error || e.message }, 'api');
      agentsStore.recordManifestResult(agent.id, { ok: false, error: e.error || e.message, protocolVersion: manifestResult.protocolVersion, metrics: manifestResult.metrics });
      return { ok: false, reloaded: false, error: e.error || e.message, vhosts: results };
    }

    logEvent('agents.manifest.applied', { agentId: agent.id, by: actor, written: toWrite.length, removed: toRemove.length }, 'api');
    agentsStore.recordManifestResult(agent.id, {
      ok: true, generatedFiles: nextFiles, vhostCount: eligible.length,
      lastVhosts: eligible.map(e => ({ serverNames: e.serverNames, listen: e.listen, sslMode: e.sslMode, sslStatus: e.sslStatus, sslError: e.sslError, mode: e.mode, relayTarget: e.relayTarget })),
      protocolVersion: manifestResult.protocolVersion, metrics: manifestResult.metrics,
      lastManifestBody: body,
    });
    return { ok: true, reloaded: true, vhosts: results };
  });
}

/**
 * Remove every vhost file a (now revoked) agent had generated — an explicit
 * operator action, never a background sweep on a mere heartbeat timeout (see
 * the design doc: "agent hors ligne ≠ suppression immédiate"). Same
 * write/test/rollback/reload discipline as applyManifestForAgent() above.
 */
async function removeAgentVhosts(agent, actor) {
  const files = agent.generatedFiles || [];
  if (!files.length) return { ok: true, reloaded: false };

  const snapshot = new Map();
  for (const f of files) snapshot.set(f, fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null);
  try {
    for (const f of files) { try { fs.unlinkSync(f); } catch {} }
  } catch (e) {
    return { ok: false, error: e.message };
  }

  try {
    await docker.execNginx('nginx -t');
  } catch (e) {
    for (const [file, prev] of snapshot) { try { if (prev !== null) atomicWrite(file, prev); } catch {} }
    return { ok: false, testFailed: true, error: e.error || e.message };
  }
  try {
    await docker.execNginx('nginx -s reload');
  } catch (e) {
    return { ok: false, error: e.error || e.message };
  }

  agentsStore.recordManifestResult(agent.id, { ok: true, generatedFiles: [], vhostCount: 0, lastVhosts: [], lastManifestBody: null }, { allowNonApproved: true });
  logEvent('agents.revoke.cleanup', { agentId: agent.id, by: actor, removed: files.length }, 'api');
  return { ok: true, reloaded: true };
}

/** Files this feature currently manages, for features/deploy.js's Git-protection setDeps({generatedFiles}) — same role as features/docker-autoconfig.js's own getGeneratedFiles(). */
function getGeneratedFiles() {
  return agentsStore.getGeneratedFiles();
}

/**
 * Merges what this agent last actually published (`agent.lastVhosts`, cleared
 * on revoke, updated on every successful push) with whatever pause decisions
 * are on record for it (survives a revoke, an offline agent, or a manifest
 * that stopped declaring that vhost) — same spirit as
 * features/docker-autoconfig.js#getStatus()'s own `decisions` list, which
 * shows a decision whether or not a live container currently backs it. A
 * vhost present in BOTH is merged into one row; a stale pause with no
 * matching current vhost still gets a row (`inLastManifest: false`) so an
 * operator can see and clear it even after the agent removed that vhost from
 * its own manifest.
 */
function buildAgentVhostView(agent) {
  const decisions = agentVhostDecisions.getAgentDecisions(agent.id);
  const byKey = new Map();
  for (const v of (agent.lastVhosts || [])) {
    const decisionKey = agentVhostDecisions.namesDecisionKey(v.serverNames);
    byKey.set(decisionKey, {
      decisionKey, serverNames: v.serverNames, listen: v.listen, sslMode: v.sslMode,
      sslStatus: v.sslStatus, sslError: v.sslError, mode: v.mode, relayTarget: v.relayTarget,
      inLastManifest: true, paused: false, pausedAt: null, pausedBy: null,
    });
  }
  for (const [decisionKey, d] of Object.entries(decisions)) {
    const existing = byKey.get(decisionKey);
    const row = existing || { decisionKey, serverNames: d.names, inLastManifest: false, paused: false };
    row.paused = !!d.paused;
    row.pausedAt = d.paused ? (d.pausedAt || null) : null;
    row.pausedBy = d.paused ? (d.pausedBy || null) : null;
    byKey.set(decisionKey, row);
  }
  return [...byKey.values()].sort((a, b) => (a.serverNames[0] || '').localeCompare(b.serverNames[0] || ''));
}

/**
 * Fix (audit report, Basse/"Agents (dashboard)"): candidate agent ids for
 * lib/scheduler.js#runScheduledAgentSslRecheck() — every approved agent that
 * (a) has a manifest body to replay at all (an agent that never successfully
 * pushed, or was just revoked, has none — see recordManifestResult()'s own
 * comment) and (b) currently has at least one vhost requesting
 * certbot_http/certbot_dns that ISN'T live yet (sslStatus other than 'cert'
 * or 'snippet' — 'pending' while an issuance is in flight/queued, or 'error'
 * if the last attempt failed and is due for a retry). An agent with nothing
 * SSL-pending is never touched by this — this exists purely to catch the
 * "issuance succeeded after the last push already returned" race, not to
 * needlessly re-apply every agent's manifest on a timer.
 */
function listAgentsNeedingSslRecheck() {
  return agentsStore.listAgents()
    .filter(a => a.status === 'approved' && a.lastManifestBody
      && (a.lastVhosts || []).some(v =>
        (v.sslMode === 'certbot_http' || v.sslMode === 'certbot_dns') && v.sslStatus !== 'cert' && v.sslStatus !== 'snippet'))
    .map(a => a.id);
}

/**
 * Re-apply an agent's last known manifest as-is, exactly as if it had just
 * pushed it again — see listAgentsNeedingSslRecheck()'s own comment for why
 * this exists. `applyManifestForAgent()` already re-resolves SSL from
 * scratch (resolveAgentSsl() -> lib/certs.js, never cached), so if a
 * certificate has landed since the last real push, this is exactly what
 * flips the vhost over to HTTPS without waiting on the agent itself.
 */
async function reapplyAgentManifest(agentId) {
  const agent = agentsStore.getAgent(agentId);
  if (!agent || agent.status !== 'approved' || !agent.lastManifestBody) {
    return { ok: false, error: 'agent introuvable, non approuve, ou sans manifeste a rejouer' };
  }
  return applyManifestForAgent(agent, agent.lastManifestBody, { actor: 'scheduler:ssl-recheck' });
}

// ─── Enrollment (public, no session/token — see server.js's dispatch for
// why this one route is special-cased ahead of the usual auth check, same
// treatment as logsFeature.handleStream's SSE route) ────────────────────────
//
// Fix v12.22.0 (audit finding AGT-06): this route has no credential at all
// by design (an agent's very first contact), so before this fix it had no
// rate limit, no cap on how many 'pending' entries could pile up, and no
// expiration — each call also re-reads/re-writes the WHOLE registry (see
// agents-store.js) and pushes a notification, so an unauthenticated flood
// was both a storage-growth and a notification-spam vector. Same in-memory
// bucket technique as lib/auth.js's login rate limiter (checkLoginRate),
// deliberately simple rather than pulled in as a shared helper: the shapes
// differ enough (per-IP only, no username/lockout concept) that sharing code
// would cost more clarity than it saves.
const ENROLL_MAX_PER_IP_PER_HOUR = 10;
const ENROLL_WINDOW_MS = 60 * 60 * 1000;
const MAX_PENDING_AGENTS = 50;
const PENDING_AGENT_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours
const enrollAttempts = new Map(); // ip -> { count, first }

function checkEnrollRate(ip) {
  const now = Date.now();
  const e = enrollAttempts.get(ip);
  if (!e || now - e.first > ENROLL_WINDOW_MS) return { blocked: false };
  if (e.count >= ENROLL_MAX_PER_IP_PER_HOUR) {
    return { blocked: true, retryAfterSec: Math.ceil((e.first + ENROLL_WINDOW_MS - now) / 1000) };
  }
  return { blocked: false };
}
function recordEnrollAttempt(ip) {
  const now = Date.now();
  let e = enrollAttempts.get(ip);
  if (!e || now - e.first > ENROLL_WINDOW_MS) e = { count: 0, first: now };
  e.count++;
  enrollAttempts.set(ip, e);
  // Purge occasionnelle des entrees expirees — cette Map ne grossit jamais
  // sans borne (une IP par attaquant reel, purgee au bout d une heure), mais
  // autant eviter de garder des IP inactives indefiniment en memoire.
  if (enrollAttempts.size > 10000) {
    for (const [k, v] of enrollAttempts) if (now - v.first > ENROLL_WINDOW_MS) enrollAttempts.delete(k);
  }
}

/**
 * Auto-reject 'pending' entries older than PENDING_AGENT_TTL_MS — an
 * operator who never approves/rejects a stray enrollment should not have it
 * linger forever, counting against MAX_PENDING_AGENTS and cluttering the
 * Agents page. Called lazily on each enroll attempt rather than on a
 * schedule: this registry has no background scheduler of its own, and this
 * keeps the fix contained to this one file.
 */
function expireStalePending() {
  const state = agentsStore.loadState();
  const now = Date.now();
  let changed = false;
  for (const a of Object.values(state.agents)) {
    if (a.status === 'pending' && now - a.createdAt > PENDING_AGENT_TTL_MS) {
      a.status = 'rejected';
      a.decidedAt = now;
      a.decidedBy = 'system:expired';
      changed = true;
    }
  }
  if (changed) agentsStore.saveState(state);
}

async function handleEnroll(req, res, clientIp) {
  const ip = clientIp || 'unknown';
  const rate = checkEnrollRate(ip);
  if (rate.blocked) {
    res.setHeader && res.setHeader('Retry-After', String(rate.retryAfterSec));
    return httpLib.send(res, 429, { error: `Trop de demandes d'enrolement depuis cette IP, reessayer dans ${rate.retryAfterSec}s` });
  }
  recordEnrollAttempt(ip);

  const { settings } = loadConfig();
  if (!settings.enable) return httpLib.forbidden(res, 'Agents distants desactives (config/agents.yml: enable: false)');

  expireStalePending();
  const pendingCount = agentsStore.listAgents().filter(a => a.status === 'pending').length;
  if (pendingCount >= MAX_PENDING_AGENTS) {
    return httpLib.send(res, 429, { error: "Trop d'agents en attente d'approbation — un operateur doit d'abord traiter la file" });
  }

  const body = await parseBody(req);
  const hostnameProposed = typeof body.hostname === 'string' ? body.hostname.trim() : '';
  const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint.trim().slice(0, 200) : '';
  if (!hostnameProposed || !AGENT_NAME_RE.test(hostnameProposed)) {
    return httpLib.badRequest(res, 'hostname requis (lettres/chiffres/underscore/point/tiret, 1 a 64 caracteres)');
  }
  const record = agentsStore.enroll({ hostnameProposed, fingerprint });
  logEvent('agents.enroll', { agentId: record.id, hostname: hostnameProposed, ip }, 'api');
  pushNotification({ type: 'agent_enroll_pending', level: 'info',
    message: `Nouvel agent en attente d'approbation : ${hostnameProposed} (${record.id})` });
  return send(res, 200, { agentId: record.id, status: record.status });
}

// ─── Routes ───────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/agents', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const { settings, errors } = loadConfig();
    const now = Date.now();
    const agents = agentsStore.listAgents().map(a => ({
      id: a.id, hostnameProposed: a.hostnameProposed, fingerprint: a.fingerprint,
      status: a.status, createdAt: a.createdAt, decidedAt: a.decidedAt, decidedBy: a.decidedBy,
      lastManifestAt: a.lastManifestAt, lastManifestOk: a.lastManifestOk, lastManifestError: a.lastManifestError,
      vhostCount: a.vhostCount, lastVhosts: a.lastVhosts,
      vhosts: buildAgentVhostView(a),
      protocolVersion: a.protocolVersion, metrics: a.metrics, metricsAt: a.metricsAt,
      tunnelConnected: a.status === 'approved' && deps.isTunnelConnected(a.id),
      online: a.status === 'approved' && !!a.lastManifestAt && (now - a.lastManifestAt) < settings.offlineAfterSec * 1000,
      // jamais tokenHash — un secret ne remonte jamais dans une reponse GET,
      // meme sous forme de hash (aucune raison operationnelle de l exposer).
    }));
    return send(res, 200, { settings, configErrors: errors, agents });
  });

  router.addPrefix('POST', '/api/agents/', async ({ req, res, session, pathname }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const parts = pathname.split('/').filter(Boolean); // ['api','agents','<id>','<action>'] ou ['api','agents','<id>','vhosts','<action>']
    if (parts.length < 4 || parts.length > 5 || !AGENT_ID_RE.test(parts[2])) return httpLib.notFound(res, 'Not found');
    const [, , id, action, vhostAction] = parts;
    const agent = agentsStore.getAgent(id);
    if (!agent) return httpLib.notFound(res, 'Agent introuvable');

    // POST /api/agents/:id/vhosts/pause | /resume — pause/reprise d'un vhost
    // precis publie par cet agent (v12.36.0), sans toucher a l'approbation de
    // l'agent lui-meme ni aux autres vhosts de son manifeste. Meme
    // permissivite que features/docker-autoconfig.js#approve() : `pause` ne
    // verifie pas que `serverNames` correspond a un vhost DEJA vu dans
    // `agent.lastVhosts` — la decision est enregistree telle quelle et ne
    // prend effet qu'au prochain manifeste qui la declare vraiment ; poser
    // une pause "a l'avance" sur un vhost pas encore publie est inoffensif
    // (rien a exclure tant qu'il n'existe pas). `resume`, lui, exige qu'une
    // pause existe deja (rien a reprendre sinon).
    if (action === 'vhosts' && (vhostAction === 'pause' || vhostAction === 'resume')) {
      const body = await parseBody(req).catch(() => ({}));
      const serverNames = Array.isArray(body?.serverNames) ? body.serverNames.filter(n => typeof n === 'string' && n) : [];
      if (!serverNames.length) return httpLib.badRequest(res, 'serverNames requis');
      const decisionKey = agentVhostDecisions.namesDecisionKey(serverNames);

      if (vhostAction === 'pause') {
        agentVhostDecisions.setPaused(id, decisionKey, serverNames, session.username);
        logEvent('agents.vhost.pause', { agentId: id, by: session.username, serverNames }, 'api');
      } else {
        const removed = agentVhostDecisions.resume(id, decisionKey);
        if (!removed) return httpLib.badRequest(res, "Ce vhost n'est pas en pause");
        logEvent('agents.vhost.resume', { agentId: id, by: session.username, serverNames }, 'api');
      }
      // Republie/retire immediatement, sans attendre le prochain push de
      // l'agent — meme raisonnement que reapplyAgentManifest() plus bas : le
      // dernier manifeste valide deja recu (lastManifestBody) est reapplique
      // tel quel, seule la decision de pause change entre les deux cycles.
      let applyResult = { skipped: true };
      if (agent.status === 'approved' && agent.lastManifestBody) {
        try {
          applyResult = await applyManifestForAgent(agent, agent.lastManifestBody, { actor: session.username });
        } catch (e) {
          return send(res, 500, { error: e.message });
        }
      }
      return send(res, 200, { ok: true, apply: applyResult, vhosts: buildAgentVhostView(agentsStore.getAgent(id)) });
    }

    if (action === 'approve') {
      if (agent.status === 'approved') return httpLib.badRequest(res, 'Deja approuve');
      const result = agentsStore.approve(id, session.username);
      logEvent('agents.approve', { agentId: id, by: session.username }, 'api');
      return send(res, 200, { agent: { id: result.agent.id, status: result.agent.status }, token: result.rawToken });
    }
    if (action === 'reject') {
      if (agent.status === 'approved') return httpLib.badRequest(res, 'Deja approuve — revoquer plutot que rejeter');
      agentsStore.reject(id, session.username);
      logEvent('agents.reject', { agentId: id, by: session.username }, 'api');
      return send(res, 200, { ok: true });
    }
    if (action === 'revoke') {
      if (agent.status !== 'approved') return httpLib.badRequest(res, "Cet agent n'est pas approuve");
      agentsStore.revoke(id, session.username);
      // Fix (audit report, Basse/"Agents (dashboard)"): tokenHash is now
      // cleared, but a tunnel connection opened BEFORE this revocation was
      // authenticated once at upgrade time and never re-checked afterwards
      // (see features/agent-tunnel.js#handleUpgrade) — without this, it
      // would keep serving traffic (and keep accepting this agent's own
      // protocol frames) indefinitely, right through the revocation.
      deps.closeTunnel(id, 'agent revoque');
      // Fix (audit report, Basse/"Agents (dashboard)"): purge this agent's
      // own certbot issuance state (by server name) — see
      // clearCertbotStateForServerNames()'s own header comment for why a
      // stale entry left here would otherwise be inherited by whichever
      // agent declares the same name next.
      clearCertbotStateForServerNames((agent.lastVhosts || []).flatMap(v => v.serverNames || []));
      logEvent('agents.revoke', { agentId: id, by: session.username }, 'api');
      const cleanup = await removeAgentVhosts(agent, session.username);
      return send(res, 200, { ok: cleanup.ok !== false, cleanup });
    }
    if (action === 'regenerate-token') {
      if (agent.status !== 'approved') return httpLib.badRequest(res, "Cet agent n'est pas approuve");
      const result = agentsStore.regenerateToken(id);
      // Fix (audit report, Basse/"Agents (dashboard)"): same reasoning as
      // revoke above — an already-open tunnel was authenticated with the OLD
      // token and would otherwise keep working after this call, defeating
      // the point of regenerating it (e.g. a suspected leak). The real agent
      // reconnects on its own with the new token; this just forces that to
      // happen right away instead of whenever the old connection eventually
      // drops.
      deps.closeTunnel(id, 'jeton regenere');
      logEvent('agents.regenerate-token', { agentId: id, by: session.username }, 'api');
      return send(res, 200, { token: result.rawToken });
    }
    return httpLib.notFound(res, 'Action inconnue');
  });

  router.addPrefix('DELETE', '/api/agents/', async ({ res, session, pathname }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const parts = pathname.split('/').filter(Boolean); // ['api','agents','<id>']
    if (parts.length !== 3 || !AGENT_ID_RE.test(parts[2])) return httpLib.notFound(res, 'Not found');
    const id = parts[2];
    const agent = agentsStore.getAgent(id);
    if (!agent) return httpLib.notFound(res, 'Agent introuvable');
    if (agent.status === 'approved') return httpLib.badRequest(res, 'Revoquer avant de supprimer un agent approuve');
    // Fix v12.21.2 (audit finding AGT-03): a revoked agent whose vhost files
    // failed to clean up (removeAgentVhosts() error, or a manifest that
    // finished writing after the revocation — see applyManifestForAgent()'s
    // own fresh status re-check above) must never have its registry entry
    // deleted while agent_*.conf files still exist on disk: once the entry
    // is gone, isGeneratedFile()'s prefix-based protection in
    // features/deploy.js is the only thing left recognizing those files —
    // they'd otherwise become invisible in the UI while still being served
    // by nginx.
    if (agent.generatedFiles && agent.generatedFiles.length) {
      return httpLib.badRequest(res, 'Cet agent a encore des vhosts generes — nettoyer (Revoquer) avant de supprimer');
    }
    agentsStore.remove(id);
    // L'entree du registre disparait pour de bon — toute pause encore posee
    // pour ce meme id deviendrait orpheline (aucun agent ne pourra plus
    // jamais la reprendre), donc purgee ici plutot que de s'accumuler.
    agentVhostDecisions.removeAgent(id);
    logEvent('agents.delete', { agentId: id, by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });

  // POST /api/agent/manifest — the ONE route an agent's own bearer token may
  // ever authenticate for (see server.js's AGENT_TOKEN_ROUTES, same
  // containment pattern as DEPLOY_TOKEN_ROUTES for a CI/CD deploy token).
  // `session.agentScope`/`session.agentId` only exist when
  // lib/auth.js#authenticateAgentToken() produced this session — never for an
  // ordinary operator session, even an admin one: pushing a manifest is the
  // agent's own job, not an action a human takes on its behalf from here.
  router.post('/api/agent/manifest', async ({ req, res, session }) => {
    if (!session.agentScope || !session.agentId) return httpLib.forbidden(res, 'Ce jeton ne peut pousser un manifeste que pour son propre agent');
    const agent = agentsStore.getAgent(session.agentId);
    if (!agent || agent.status !== 'approved') return httpLib.forbidden(res, 'Agent inconnu ou non approuve');
    const body = await parseBody(req);
    try {
      const result = await applyManifestForAgent(agent, body);
      return send(res, result.ok === false && !result.vhosts?.length ? 400 : 200, result);
    } catch (e) {
      return httpLib.serverError(res, e);
    }
  });
}

module.exports = {
  register, handleEnroll, loadConfig, getGeneratedFiles, setDeps,
  // Exportes pour les tests unitaires — logique pure/quasi-pure, testable
  // sans serveur reel pour resolveAgentSsl(); applyManifestForAgent() et
  // removeAgentVhosts() sont couvertes par test/agents-routes.test.js (un
  // vrai serveur, puisqu elles touchent fs + docker.execNginx).
  resolveAgentSsl, triggerAgentCertbotIssuanceIfDue, applyManifestForAgent, removeAgentVhosts,
  loadCertbotState, saveCertbotState, clearCertbotStateForServerNames,
  listAgentsNeedingSslRecheck, reapplyAgentManifest, buildAgentVhostView,
  AGENT_ID_RE, AGENT_NAME_RE,
};
