'use strict';
/**
 * Remote-agent manifest — Partie 2 "fondations" du document de conception
 * (Projet Claude : Hôtes Docker distants). Pure logic only, same split as
 * lib/docker-autoconfig.js: parsing/validating a manifest an approved agent
 * pushes, and rendering the resulting nginx server block(s). No HTTP, no
 * filesystem write, no Docker socket call, no certificate lookup — those
 * live in features/agents.js, the only place allowed to touch lib/certs.js,
 * lib/docker.js or the filesystem for this feature (composition-root split
 * already used by every other feature in this project).
 *
 * A remote agent is, by construction, further from Nginx Control's trust
 * boundary than a Docker label on the SAME host (Partie 1): the manifest
 * arrives over the network, authenticated only by a bearer token the agent
 * holds. Every value here goes through the exact same anchored-regex
 * discipline as lib/docker-autoconfig.js's validateDesiredVhost() — nothing
 * from a manifest is ever concatenated raw into a generated nginx file.
 *
 * `sslCertificate` accepte `none`/`snippet`/`auto`/`certbot_http`/
 * `certbot_dns` (les deux derniers depuis v12.21.0 — voir
 * features/agents.js#resolveAgentSsl(), miroir exact de
 * features/docker-autoconfig.js#resolveSsl() pour la meme logique
 * cote agents distants : verification que le Certbot concerne est bien
 * active, `checkDomainConflict()`, et declenchement actif d'une emission
 * quand aucun certificat n'existe deja).
 *
 * "Mode direct" only (see design doc, Partie 2 §"Les 3 modes"): a location's
 * `target` is a plain `scheme://host:port` the agent's own host can already
 * reach directly (bind-port or an existing frontal reverse proxy on the
 * remote host) — never a Docker container name needing the
 * `resolver 127.0.0.11` trick lib/docker-autoconfig.js uses for a container
 * on the SAME Docker network as nginx. That trick has no meaning here: the
 * target is a stable ip:port supplied fresh on every manifest push, not a
 * name docker's embedded DNS resolves.
 */

const crypto = require('crypto');

const HOSTNAME_RE = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
const LOCATION_RE = /^(=|~\*|~|\^~)?\s?\/[A-Za-z0-9_\-./]*$/;
// Direct target: scheme + hostname OR IPv4 literal (both fit this charset —
// an IPv4 octet is just digits, which the hostname-label alternation already
// allows) + optional port. No path, no query string.
const AGENT_TARGET_RE = /^(https?):\/\/([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:([0-9]{1,5}))?$/i;
const AGENT_SSL_MODE_RE = /^(none|snippet|auto|certbot_http|certbot_dns)$/i;

// Fix v12.22.0 (audit finding AGT-04, part 1) — see validateManifestVhost()'s
// call site for the full rationale.
function isIPv4Literal(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every(oct => Number(oct) <= 255);
}
const SNIPPET_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.conf$/;
const INTERVAL_RE = /^\d+s?$/;
const HTTP_CODE_TOKEN_RE = /^[1-5](xx|\d{2})$/i;
const RULE_ID_RE = /^\d+$/;

const MAX_LOCATIONS_PER_VHOST = 30;

// ─── Versionnement du protocole ────────────────────────────────────────────
// Un agent qui ne precise rien est traite comme protocolVersion=1 (retro-
// compatible avec tous les manifestes de la v12.18.0, qui n'avaient pas ce
// champ). SUPPORTED_PROTOCOL_VERSIONS liste ce que CE dashboard sait encore
// comprendre — un agent plus recent que le dashboard (version superieure a
// tout ce qui est liste ici) est rejete explicitement plutot que traite au
// mieux, pour ne jamais deviner un format qui a pu changer de sens.
const SUPPORTED_PROTOCOL_VERSIONS = [1];
const CURRENT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[SUPPORTED_PROTOCOL_VERSIONS.length - 1];

const MODE_RE = /^(direct|tunnel|relay)$/i;
const RELAY_SCHEME_RE = /^(http|https)$/i;

// ─── Metriques hote (optionnelles, section "Partie 2 - avance") ───────────
const METRIC_NUMBER_RE = /^-?\d+(\.\d+)?$/;
function isFiniteNumberLike(v) {
  if (typeof v === 'number') return Number.isFinite(v);
  if (typeof v === 'string') return METRIC_NUMBER_RE.test(v.trim());
  return false;
}
function toFiniteNumber(v) { return typeof v === 'number' ? v : parseFloat(v); }

/**
 * Valide le bloc `metrics` optionnel d'un manifeste (etat de l'hote distant
 * au moment du push : CPU/RAM/reseau/uptime). Toutes les cles sont
 * optionnelles — un agent minimal peut choisir de n'en remonter aucune.
 * Bornes larges mais reelles (jamais une valeur negative ou absurde ecrite
 * telle quelle dans l'UI) ; une valeur hors bornes est ignoree (mise a
 * null) plutot que de faire echouer tout le manifeste pour un souci de
 * metrique — ce n'est que de l'observabilite, pas la configuration nginx
 * elle-meme.
 */
function validateMetrics(raw) {
  if (!isPlainObject(raw)) return null;
  const out = {};
  const num = (key, min, max) => {
    if (raw[key] === undefined || raw[key] === null) return;
    if (!isFiniteNumberLike(raw[key])) return;
    const n = toFiniteNumber(raw[key]);
    if (n < min || n > max) return;
    out[key] = n;
  };
  num('cpuPercent', 0, 100);
  num('memPercent', 0, 100);
  num('memTotalMb', 0, 1024 * 1024); // 1 To, large marge
  num('uptimeSec', 0, 10 * 365 * 24 * 3600); // 10 ans, large marge
  num('netRxBytesPerSec', 0, Number.MAX_SAFE_INTEGER);
  num('netTxBytesPerSec', 0, Number.MAX_SAFE_INTEGER);
  return Object.keys(out).length ? out : null;
}

function isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

/**
 * Validate one manifest vhost entry. Returns { valid, errors, ...normalized }
 * — the same shape family as lib/docker-autoconfig.js's validateDesiredVhost()
 * so features/agents.js and generateAgentVhostContent() below feel familiar
 * to anyone who has already read that module.
 */
function validateManifestVhost(entry, { allowedListenPorts = null } = {}) {
  const errors = [];
  if (!isPlainObject(entry)) return { valid: false, errors: ['entree de vhost invalide (attendu un objet)'] };

  const serverNameRaw = typeof entry.serverName === 'string' ? entry.serverName : '';
  // Fix v12.21.2 (audit finding AGT-05): lower-cased here, once, at the
  // validation boundary — certificate SANs are always lower-case (RFC 5280),
  // so an un-normalized "App.example.com" never matched its own certificate
  // in checkDomainConflict(), triggering a brand-new certbot issuance on
  // every single manifest push (and burning through Let's Encrypt's
  // rate limits). Every other use of serverNames downstream (conflict
  // detection, file naming, the `server_name` line itself) is unaffected —
  // nginx's own server_name matching is already case-insensitive.
  const serverNames = serverNameRaw.split(/[\s,]+/).filter(Boolean).map(s => s.toLowerCase());
  if (!serverNames.length) {
    errors.push('"serverName" est requis');
  } else {
    for (const name of serverNames) {
      if (!HOSTNAME_RE.test(name)) { errors.push(`serverName invalide : "${name}"`); continue; }
      // Fix v12.22.0 (audit finding AGT-04, part 1): HOSTNAME_RE's label
      // charset ([a-z0-9-]) accepts an all-digit label, so a literal IPv4
      // address like "192.168.1.10" used to pass hostname validation. In
      // "tunnel" mode this let a compromised-but-approved agent declare the
      // IP address by which operators reach the dashboard itself as its own
      // serverName, hijacking every request that arrives by IP instead of by
      // name (server.js's Host-based tunnel interception ran before any
      // authentication) — see also the X-NC-Tunnel header check added to
      // features/agent-tunnel.js, the primary fix for that same finding.
      if (isIPv4Literal(name.replace(/^\*\./, ''))) {
        errors.push(`serverName invalide : "${name}" (une adresse IP litterale n'est pas un nom d'hote accepte)`);
      }
    }
  }

  // mode "tunnel" (Partie 2 - avance) : un seul proxy_pass genere vers le
  // relais du dashboard (voir features/agent-tunnel.js), le routage par
  // location se fait cote agent, pas cote nginx. Defaut "direct" pour rester
  // retro-compatible avec tous les manifestes v12.18.0 (aucun champ mode).
  const modeRaw = String(entry.mode || 'direct').toLowerCase();
  if (!MODE_RE.test(modeRaw)) errors.push(`mode invalide : "${entry.mode}" (attendu : direct, tunnel, relay)`);

  // mode "relay" (Partie 2 - avance, port unique/double) : comme "tunnel",
  // un seul proxy_pass genere, mais DIRECTEMENT vers le port fixe expose par
  // l'agent lui-meme (pas de saut par le dashboard) — voir
  // nginx-agent/relay.go. `relayScheme` choisit lequel des deux ports
  // (http/https) declares au niveau de l'enveloppe (voir validateManifest())
  // ce vhost doit utiliser ; defaut "http" si absent, coherent avec le
  // comportement par defaut du reste du manifeste.
  const relaySchemeRaw = String(entry.relayScheme || 'http').toLowerCase();
  if (!RELAY_SCHEME_RE.test(relaySchemeRaw)) {
    errors.push(`relayScheme invalide : "${entry.relayScheme}" (attendu : http, https)`);
  }

  const sslModeRaw = String(entry.sslCertificate || 'none').toLowerCase();
  if (!AGENT_SSL_MODE_RE.test(sslModeRaw)) {
    errors.push(`sslCertificate invalide : "${entry.sslCertificate}" (attendu : none, snippet, auto, certbot_http, certbot_dns)`);
  }
  const sslActive = AGENT_SSL_MODE_RE.test(sslModeRaw) && sslModeRaw !== 'none';
  let sslSnippetFile = '';
  if (sslModeRaw === 'snippet') {
    sslSnippetFile = typeof entry.sslCertificateSnippet === 'string' ? entry.sslCertificateSnippet : '';
    if (!sslSnippetFile) errors.push('sslCertificateSnippet est requis quand sslCertificate=snippet');
    else if (!SNIPPET_FILENAME_RE.test(sslSnippetFile)) errors.push(`sslCertificateSnippet invalide : "${sslSnippetFile}"`);
  }

  let listen;
  if (entry.listen === undefined || entry.listen === null || entry.listen === '') {
    listen = sslActive ? 443 : 80;
  } else if (Number.isInteger(entry.listen)) {
    listen = entry.listen;
  } else {
    listen = NaN;
  }
  if (!Number.isInteger(listen) || listen < 1 || listen > 65535) {
    errors.push(`listen invalide : "${entry.listen}"`);
  } else if (Array.isArray(allowedListenPorts) && !allowedListenPorts.includes(listen)) {
    // Fix (audit report, Basse/"Agents (dashboard)"): only enforced once an
    // operator has actually configured config/agents.yml#allowed_listen_ports
    // — see lib/agents-yaml.js's own comment on this setting.
    errors.push(`listen ${listen} non autorise (voir allowed_listen_ports dans config/agents.yml)`);
  }

  const httpToHttpsAuto = entry.httpToHttpsAuto === true;
  if (entry.httpToHttpsAuto !== undefined && typeof entry.httpToHttpsAuto !== 'boolean') {
    errors.push(`httpToHttpsAuto invalide : attendu un booleen, recu "${entry.httpToHttpsAuto}"`);
  }

  const serverSnippets = [];
  if (entry.serverSnippets !== undefined) {
    if (!Array.isArray(entry.serverSnippets)) errors.push('serverSnippets doit etre un tableau de noms de fichiers');
    else for (const f of entry.serverSnippets) {
      if (typeof f !== 'string' || !SNIPPET_FILENAME_RE.test(f)) errors.push(`serverSnippets invalide : "${f}"`);
      else serverSnippets.push(f);
    }
  }

  // ─── Monitor / diagnostic / analyze — memes commentaires magiques que
  // Partie 1 (voir lib/vhost-targets.js), juste des champs JSON plutot que
  // des labels Docker en entree. ─────────────────────────────────────────
  const monitorRaw = isPlainObject(entry.monitor) ? entry.monitor : {};
  const monitorEnable = monitorRaw.enable === true;
  if (monitorRaw.enable !== undefined && typeof monitorRaw.enable !== 'boolean') errors.push(`monitor.enable invalide : "${monitorRaw.enable}"`);
  let monitorInterval = '';
  if (monitorRaw.interval) {
    if (typeof monitorRaw.interval !== 'string' || !INTERVAL_RE.test(monitorRaw.interval)) errors.push(`monitor.interval invalide : "${monitorRaw.interval}"`);
    else monitorInterval = monitorRaw.interval;
  }
  let monitorValidHttpCodes = [];
  if (monitorRaw.validHttpCode) {
    const tokens = typeof monitorRaw.validHttpCode === 'string' ? monitorRaw.validHttpCode.split(/[\s,]+/).filter(Boolean) : null;
    if (!tokens || !tokens.length || tokens.some(t => !HTTP_CODE_TOKEN_RE.test(t))) {
      errors.push(`monitor.validHttpCode invalide : "${monitorRaw.validHttpCode}"`);
    } else monitorValidHttpCodes = tokens;
  }

  const diagnosticRaw = isPlainObject(entry.diagnostic) ? entry.diagnostic : {};
  const diagnosticEnable = diagnosticRaw.enable !== false;
  if (diagnosticRaw.enable !== undefined && typeof diagnosticRaw.enable !== 'boolean') errors.push(`diagnostic.enable invalide : "${diagnosticRaw.enable}"`);

  const analyzeRaw = isPlainObject(entry.analyze) ? entry.analyze : {};
  const analyzeEnable = analyzeRaw.enable !== false;
  if (analyzeRaw.enable !== undefined && typeof analyzeRaw.enable !== 'boolean') errors.push(`analyze.enable invalide : "${analyzeRaw.enable}"`);
  let analyzeIgnoreRules = [];
  if (analyzeRaw.ignoreRules !== undefined) {
    if (!Array.isArray(analyzeRaw.ignoreRules) || analyzeRaw.ignoreRules.some(id => !RULE_ID_RE.test(String(id)))) {
      errors.push(`analyze.ignoreRules invalide : attendu un tableau d'identifiants numeriques, recu "${JSON.stringify(analyzeRaw.ignoreRules)}"`);
    } else analyzeIgnoreRules = analyzeRaw.ignoreRules.map(id => parseInt(id, 10));
  }

  // ─── Locations ─────────────────────────────────────────────────────────
  const locationsRaw = Array.isArray(entry.locations) ? entry.locations : [];
  if (!locationsRaw.length) errors.push('au moins une location est requise');
  if (locationsRaw.length > MAX_LOCATIONS_PER_VHOST) errors.push(`trop de locations (${locationsRaw.length} > ${MAX_LOCATIONS_PER_VHOST})`);
  const locations = [];
  locationsRaw.slice(0, MAX_LOCATIONS_PER_VHOST).forEach((loc, i) => {
    if (!isPlainObject(loc)) { errors.push(`location #${i + 1} invalide (attendu un objet)`); return; }
    const path = typeof loc.path === 'string' ? loc.path : '';
    if (!LOCATION_RE.test(path)) errors.push(`location #${i + 1} : path invalide : "${loc.path}"`);
    const target = typeof loc.target === 'string' ? loc.target : '';
    if (!target) errors.push(`location #${i + 1} : "target" est requis`);
    else {
      const targetMatch = AGENT_TARGET_RE.exec(target);
      if (!targetMatch) errors.push(`location #${i + 1} : target invalide : "${target}"`);
      else {
        // Fix (audit report, Basse/"Agents (dashboard)"): AGENT_TARGET_RE's
        // port group only bounds the DIGIT COUNT (1-5), not the numeric
        // value — "99999" (5 digits) matched the regex despite being well
        // above the valid TCP port range, and was only ever caught later by
        // `nginx -t`, which then fails the WHOLE manifest (every other,
        // otherwise-valid vhost in the same push rolled back with it) rather
        // than this one bad location being rejected on its own up front.
        const targetPort = targetMatch[7];
        if (targetPort !== undefined && Number(targetPort) > 65535) {
          errors.push(`location #${i + 1} : port de target invalide : "${targetPort}" (max 65535)`);
        }
      }
    }
    const monitorIgnore = loc.monitorIgnore === true;
    const snippets = [];
    if (loc.snippets !== undefined) {
      if (!Array.isArray(loc.snippets)) errors.push(`location #${i + 1} : snippets doit etre un tableau`);
      else for (const f of loc.snippets) {
        if (typeof f !== 'string' || !SNIPPET_FILENAME_RE.test(f)) errors.push(`location #${i + 1} : snippet invalide : "${f}"`);
        else snippets.push(f);
      }
    }
    locations.push({ index: String(i + 1).padStart(2, '0'), path, target, monitorIgnore, snippets });
  });

  // Fix v12.21.2 (audit finding DAC-09, applied here too): two locations
  // sharing the exact same `path` both pass every check above individually,
  // but rendering both produces two `location <same path> { ... }` blocks in
  // the same server{} — nginx rejects that as a duplicate location, failing
  // `nginx -t` for this vhost (and, since the manifest is tested as a whole,
  // potentially every other vhost in the same push). Caught here as an
  // ordinary validation error instead.
  const seenPaths = new Map();
  for (const loc of locations) {
    if (seenPaths.has(loc.path)) {
      errors.push(`deux locations partagent le meme chemin "${loc.path}" (#${seenPaths.get(loc.path)} et #${loc.index})`);
    } else {
      seenPaths.set(loc.path, loc.index);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    mode: modeRaw,
    relayScheme: relaySchemeRaw,
    serverNames,
    listen: Number.isInteger(listen) ? listen : null,
    ssl: { mode: sslModeRaw, snippetFile: sslSnippetFile, active: sslActive },
    httpToHttpsAuto,
    serverSnippets,
    locations,
    monitor: { enable: monitorEnable, interval: monitorInterval, validHttpCodes: monitorValidHttpCodes },
    diagnostic: { enable: diagnosticEnable },
    analyze: { enable: analyzeEnable, ignoreRules: analyzeIgnoreRules },
  };
}

/**
 * Validate a whole manifest body. `valid: false` at the top level only for a
 * malformed envelope (not an object, no `vhosts` array, too many entries,
 * version de protocole non supportee) — never for one bad vhost among
 * otherwise-good ones, same "one bad label doesn't sink the others"
 * philosophy as features/docker-autoconfig.js's runCycle(). Each
 * `vhosts[i]` carries its own `valid`/`errors`; the caller
 * (features/agents.js) is the one deciding what to do with a mix of
 * valid/invalid entries (apply the valid ones, surface the rest as-is).
 *
 * `protocolVersion` (optionnel, defaut 1 pour la retro-compatibilite avec
 * les manifestes v12.18.0) et `metrics` (optionnel) vivent au niveau de
 * l'enveloppe, pas par vhost — un agent decrit un seul hote.
 */
function validateManifest(body, { maxVhosts = 50, allowedListenPorts = null } = {}) {
  if (!isPlainObject(body)) return { valid: false, errors: ['manifeste invalide (attendu un objet JSON)'], vhosts: [] };

  const protocolVersionRaw = body.protocolVersion;
  const protocolVersion = protocolVersionRaw === undefined || protocolVersionRaw === null
    ? 1
    : (Number.isInteger(protocolVersionRaw) ? protocolVersionRaw : NaN);
  if (!SUPPORTED_PROTOCOL_VERSIONS.includes(protocolVersion)) {
    return {
      valid: false,
      errors: [`protocolVersion non supportee : "${protocolVersionRaw}" (ce dashboard sait traiter : ${SUPPORTED_PROTOCOL_VERSIONS.join(', ')})`],
      vhosts: [],
      protocolVersion: protocolVersionRaw,
    };
  }

  if (!Array.isArray(body.vhosts)) return { valid: false, errors: ['"vhosts" est requis et doit etre un tableau'], vhosts: [], protocolVersion };
  if (body.vhosts.length > maxVhosts) {
    return { valid: false, errors: [`trop de vhosts dans ce manifeste (${body.vhosts.length} > ${maxVhosts}, voir max_vhosts_per_agent dans config/agents.yml)`], vhosts: [], protocolVersion };
  }
  const vhosts = body.vhosts.map(entry => ({ raw: entry, ...validateManifestVhost(entry, { allowedListenPorts }) }));
  const metrics = validateMetrics(body.metrics);

  // ─── Relais (Partie 2 - avance, port unique/double) ─────────────────────
  // Objet d'enveloppe optionnel `relay: { http, https }` — l'adresse du/des
  // port(s) fixes exposes par l'agent lui-meme (voir nginx-agent/relay.go),
  // au format `scheme://host:port` comme AGENT_TARGET_RE. Un vhost en mode
  // "relay" qui reference un schema absent de cet objet est invalide
  // individuellement (meme philosophie que les autres champs par vhost) —
  // jamais tout le manifeste pour ce seul souci.
  const relayRaw = isPlainObject(body.relay) ? body.relay : {};
  const relay = {};
  const relayErrors = [];
  for (const scheme of ['http', 'https']) {
    if (relayRaw[scheme] === undefined || relayRaw[scheme] === null) continue;
    if (typeof relayRaw[scheme] !== 'string' || !AGENT_TARGET_RE.test(relayRaw[scheme])) {
      relayErrors.push(`relay.${scheme} invalide : "${relayRaw[scheme]}"`);
      continue;
    }
    relay[scheme] = relayRaw[scheme];
  }
  for (const v of vhosts) {
    if (v.mode !== 'relay') continue;
    if (relayErrors.length) v.errors = [...v.errors, ...relayErrors];
    if (!relay[v.relayScheme]) v.errors = [...v.errors, `mode "relay" (relayScheme=${v.relayScheme}) mais relay.${v.relayScheme} absent ou invalide dans l'enveloppe du manifeste`];
    if (v.errors.length) v.valid = false;
  }

  return { valid: true, errors: [], vhosts, protocolVersion, metrics, relay };
}

/** Sanitize a server_name into a safe, stable filename component. */
function sanitizeForFilename(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'vhost';
}

/** Sanitize an agent id the same way — ids are server-generated (crypto.randomBytes hex), but this stays defensive. */
function agentVhostFileName(agentId, serverNames) {
  // Fix v12.21.2 (audit finding DAC-02, same bug on the agents side): two
  // different server_names for the same agent (e.g. "a-b.example.com" and
  // "a.b.example.com", or a bare name vs. its "*." wildcard) can sanitize to
  // the identical string, so a hash of the untouched, lower-cased name is
  // appended to keep file names collision-free — same reasoning as
  // lib/docker-autoconfig.js's dockerVhostFileName().
  const primary = String(serverNames[0] || '').toLowerCase();
  const hash = crypto.createHash('sha1').update(primary).digest('hex').slice(0, 8);
  return `agent_${sanitizeForFilename(agentId)}_${sanitizeForFilename(primary)}_${hash}.conf`;
}

/**
 * Render the nginx server block(s) for one validated manifest vhost. Callers
 * MUST have run validateManifestVhost() first and confirmed `valid: true`.
 *
 * meta: { agentId, agentName, generatedAt, sslResolved, tunnelTarget,
 * relayTarget } — `sslResolved` is decided by features/agents.js (the only
 * place here allowed to touch lib/certs.js), same three shapes as
 * lib/docker-autoconfig.js's generateVhostContent() meta.sslResolved:
 * undefined (mode "none"), { type:'snippet', file }, { type:'cert',
 * certPath, keyPath }, or { type:'pending' } (mode "auto", nothing matched
 * yet — plain HTTP, never a broken `ssl` directive). `tunnelTarget`
 * (required when validated.mode === 'tunnel') is the internal
 * `scheme://host:port` of the dashboard's own tunnel ingress (see
 * features/agent-tunnel.js) — never the agent's real backend, which nginx
 * can't reach directly in this mode. `relayTarget` (required when
 * validated.mode === 'relay') is the agent's OWN fixed relay address
 * (`scheme://host:port` resolved by features/agents.js from the manifest's
 * `relay.http`/`relay.https`, per validated.relayScheme) — unlike
 * tunnelTarget, nginx talks to it directly, no dashboard hop: this is the
 * whole point of relay mode (avoid opening one port per container across a
 * VLAN boundary while still keeping a single stable proxy_pass target).
 */
function generateAgentVhostContent(validated, serverNames, listen, meta = {}) {
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const sslResolved = validated.ssl?.active ? meta.sslResolved : undefined;
  // Fix v12.21.2 (audit finding AGT-01, regression v12.21.0): 'error' (e.g.
  // certbot_http requested but Certbot is disabled, or the last issuance
  // failed) is not 'pending' either, but it is just as far from a real,
  // usable certificate — lib/docker-autoconfig.js's own generateVhostContent()
  // already excludes both. Treating 'error' as "live" here wrote `listen 443
  // ssl;` with no matching ssl_certificate directive at all, which either
  // fails the whole manifest's `nginx -t` (rolling back every other vhost in
  // the same push) or silently falls through to nginx's default server's
  // certificate.
  const sslIsLive = !!sslResolved && sslResolved.type !== 'pending' && sslResolved.type !== 'error';
  const isTunnel = validated.mode === 'tunnel';
  const isRelay = validated.mode === 'relay';

  const header = [
    '# Genere automatiquement par nginx-control — NE PAS EDITER A LA MAIN',
    `# Source: manifeste de l'agent distant ${meta.agentName || '?'} (${meta.agentId || '?'})`,
    isTunnel
      ? '# Mode: tunnel (proxy_pass vers le relais du dashboard — routage reel cote agent)'
      : isRelay
      ? '# Mode: relay (proxy_pass vers le port unique expose par l agent)'
      : '# Mode: direct (proxy_pass vers une cible ip:port fournie par l agent)',
    `# Genere le: ${generatedAt}`,
    '#',
    '# Ce fichier est regenere a chaque manifeste recu de cet agent : toute',
    '# modification manuelle sera perdue au prochain push. Pour changer cette',
    '# config, modifier le manifeste cote agent.',
  ];
  if (validated.ssl?.active && sslResolved?.type === 'error') {
    header.push('#',
      `# ERREUR ssl_certificate=${validated.ssl.mode} : ${sslResolved.message}`,
      '# Ce vhost reste en HTTP simple tant que cette erreur persiste.');
  } else if (validated.ssl?.active && !sslIsLive) {
    header.push('#',
      `# sslCertificate=${validated.ssl.mode} demande mais aucun certificat correspondant n a`,
      '# encore ete trouve : ce vhost reste en HTTP simple en attendant. Il sera',
      '# regenere automatiquement en HTTPS des qu un certificat sera detecte.');
  }
  if (!validated.diagnostic.enable) header.push('#', '# nginx-control-diagnostic: off');
  header.push('');

  // Fix (audit report, Basse/"Partie 1 et certificats") — mirror of
  // lib/docker-autoconfig.js's own generateVhostContent() fix, same
  // reasoning: while ssl_certificate=certbot_http is requested but not yet
  // live, certbot's HTTP-01 challenge needs `GET
  // /.well-known/acme-challenge/<token>` to reach ITS OWN webroot on port 80
  // for this exact server_name, or it falls through to 00-default.conf's
  // default_server and can never succeed. `certbotWebrootPath` is only ever
  // set (see features/agents.js) when Certbot's HTTP challenge is actually
  // configured; without it this stays a no-op exactly as before.
  const needsAcmeChallenge = validated.ssl?.active && validated.ssl.mode === 'certbot_http' && !!meta.certbotWebrootPath;
  const acmeChallengeLines = needsAcmeChallenge ? [
    '    location /.well-known/acme-challenge/ {',
    `        root ${meta.certbotWebrootPath};`,
    '    }',
    '',
  ] : [];

  const lines = [...header];

  if (validated.httpToHttpsAuto && sslIsLive) {
    lines.push('server {', '    listen 80;', '    listen [::]:80;',
      `    server_name ${serverNames.join(' ')};`);
    lines.push(...acmeChallengeLines);
    lines.push('    return 301 https://$host$request_uri;', '}', '');
  }

  const effectiveListen = (needsAcmeChallenge && !sslIsLive) ? 80 : listen;
  lines.push('server {');
  lines.push(`    listen ${effectiveListen}${sslIsLive ? ' ssl' : ''};`);
  lines.push(`    listen [::]:${effectiveListen}${sslIsLive ? ' ssl' : ''};`);
  lines.push(`    server_name ${serverNames.join(' ')};`);
  lines.push('');
  if (needsAcmeChallenge && !sslIsLive) lines.push(...acmeChallengeLines);

  if (sslIsLive) {
    if (sslResolved.type === 'snippet') {
      lines.push(`    include snippets/${sslResolved.file};`);
    } else if (sslResolved.type === 'cert') {
      lines.push(`    ssl_certificate ${sslResolved.certPath};`);
      lines.push(`    ssl_certificate_key ${sslResolved.keyPath};`);
    }
    lines.push('');
  }

  if (validated.monitor.enable) {
    lines.push('    # nginx-control-monitoring: on');
    if (validated.monitor.interval) lines.push(`    # nginx-control-monitoring-interval: ${validated.monitor.interval}`);
    if (validated.monitor.validHttpCodes.length) lines.push(`    # nginx-control-monitoring-valid-http-code: ${validated.monitor.validHttpCodes.join(', ')}`);
  }
  if (!validated.analyze.enable) {
    lines.push('    # nginx-control-analyze: off');
  } else if (validated.analyze.ignoreRules.length) {
    lines.push(`    # nginx-control-analyze-ignore-rules: ${validated.analyze.ignoreRules.join(', ')}`);
  }
  if (validated.monitor.enable || !validated.analyze.enable || validated.analyze.ignoreRules.length) lines.push('');

  for (const file of validated.serverSnippets) lines.push(`    include snippets/${file};`);
  if (validated.serverSnippets.length) lines.push('');

  if (isTunnel || isRelay) {
    // Un seul location dans les deux cas : le routage reel par path se fait
    // cote agent (resolveLocalTarget() en Go), pas ici — les `locations[]`
    // du manifeste restent utilisees pour ca la-bas mais n'ont pas de sens a
    // repeter dans ce fichier nginx. Difference entre les deux modes : la
    // cible du proxy_pass. tunnel => relais du dashboard (saut WebSocket
    // JSON, tamponne, pour un agent injoignable en entree) ; relay => port
    // fixe expose directement par l'agent (connexion HTTP reelle, direct,
    // streaming complet).
    lines.push('    location / {');
    lines.push(`        proxy_pass ${isTunnel ? meta.tunnelTarget : meta.relayTarget};`);
    lines.push('        proxy_set_header Host $host;');
    lines.push('        proxy_set_header X-Real-IP $remote_addr;');
    lines.push('        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;');
    lines.push('        proxy_set_header X-Forwarded-Proto $scheme;');
    if (isTunnel) {
      // Fix v12.22.0 (audit finding AGT-04): see lib/agent-tunnel-secret.js's
      // header comment. Only nginx, applying this dashboard-generated vhost,
      // can attach this header — features/agent-tunnel.js refuses to route
      // any request that lacks it, no matter what Host it carries.
      lines.push(`        proxy_set_header X-NC-Tunnel "${meta.tunnelSecret}";`);
    }
    if (isRelay && validated.relayScheme === 'https') {
      lines.push('        # Le saut agent est en HTTPS avec un certificat probablement');
      lines.push('        # auto-signe (voir nginx-agent/relay.go) : verification desactivee');
      lines.push('        # ici volontairement. Pour la reactiver, fournir un vrai certificat');
      lines.push('        # au flag --relay-https-cert/--relay-https-key de l agent puis');
      lines.push('        # ajouter un server-snippet (serverSnippets du manifeste) avec');
      lines.push('        # `proxy_ssl_verify on; proxy_ssl_trusted_certificate ...;`.');
      lines.push('        proxy_ssl_verify off;');
    }
    lines.push('    }');
  } else {
    validated.locations.forEach((loc, i) => {
      lines.push(`    location ${loc.path} {`);
      lines.push(`        proxy_pass ${loc.target};`);
      if (loc.monitorIgnore) lines.push('        # nginx-control-monitoring-ignore-location: on');
      for (const file of loc.snippets) lines.push(`        include snippets/${file};`);
      lines.push('    }');
      if (i < validated.locations.length - 1) lines.push('');
    });
  }
  lines.push('}', '');
  return lines.join('\n');
}

module.exports = {
  HOSTNAME_RE, LOCATION_RE, AGENT_TARGET_RE, AGENT_SSL_MODE_RE, SNIPPET_FILENAME_RE, MODE_RE, RELAY_SCHEME_RE,
  MAX_LOCATIONS_PER_VHOST, SUPPORTED_PROTOCOL_VERSIONS, CURRENT_PROTOCOL_VERSION,
  validateManifestVhost, validateManifest, validateMetrics,
  sanitizeForFilename, agentVhostFileName, generateAgentVhostContent,
};
