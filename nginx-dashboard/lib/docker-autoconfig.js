'use strict';
/**
 * Auto-config Docker (labels façon Traefik) — étape 1 "socle" + étape 2
 * "complément Partie 1" (voir le document de conception dans le Projet
 * Claude : Partie 1, phasage §1-§2).
 *
 * Pure logic only: parsing a container's Docker labels into a desired vhost,
 * validating it, and rendering the nginx server block. No Docker socket call,
 * no filesystem write, no nginx test/reload, and — important for the SSL
 * "auto" mode added in étape 2 — no certificate lookup either: resolving
 * `nginx-control.vhost.ssl_certificate=auto` against the certificates that
 * actually exist on disk needs lib/certs.js's checkDomainConflict(), which
 * touches the filesystem, so that resolution happens in
 * features/docker-autoconfig.js and is handed to generateVhostContent() here
 * as an already-decided `sslResolved` value. Same split as
 * lib/blocklist-parse.js (pure) vs features/blocklists.js (orchestration).
 *
 * A Docker label can be set by anyone allowed to launch a container on the
 * host — it is treated with the same suspicion as an external IP blocklist
 * (see lib/blocklist-parse.js's header): every value is validated by a fully
 * anchored regex before it is ever allowed into a string that gets written
 * into an nginx config file. Nothing here ever concatenates a raw label value
 * into the generated file without first passing it through one of the
 * VALID_* checks below.
 *
 * Étape 2 scope actually implemented here: SSL modes (none/snippet/auto),
 * `http_to_https_auto`, server- and location-level `include` snippets, and
 * the monitor/diagnostic/analyze labels mapped onto the *existing* magic
 * comments already understood by lib/vhost-targets.js and features/monitor.js
 * — nothing new is invented on that side, a Docker-managed vhost just gets
 * the same comments an operator would type by hand. `upstream_group`
 * (multi-container aggregation) and the Docker Events/debounce reactive
 * detection are a separate, still-pending pass (see the design doc's
 * phasing) — this module's poll-based single-container model is unchanged.
 *
 * All `include` directives this project ever writes into a vhost use the
 * path nginx itself sees inside its own container (`snippets/<file>`), never
 * the dashboard's internal DIR_SNIPPETS — see dockerVhostFileName()'s
 * neighbours below for the snippet-rendering code that follows this rule.
 */

const crypto = require('crypto');

const LABEL_PREFIX = 'nginx-control.';

// server_name: a normal hostname, or a leading "*." wildcard (nginx's own
// wildcard syntax). Fully anchored — this is the only thing that ever ends
// up on nginx's `server_name` line.
const HOSTNAME_RE = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

// A location path: nginx's `=`/`~`/`~*`/`^~` prefixes plus a conservative
// character set for the path itself — no spaces, no braces, no semicolons,
// nothing that could break out of `location <this> {`.
const LOCATION_RE = /^(=|~\*|~|\^~)?\s?\/[A-Za-z0-9_\-./]*$/;

// proxy_pass target: scheme + hostname/container-name + optional port. No
// path suffix, no query string, nothing beyond what a Docker backend target
// needs — kept deliberately narrow.
const PROXY_PASS_RE = /^(https?):\/\/([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:([0-9]{1,5}))?$/i;

const NETWORK_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;

// ─── Étape 2 : validation primitives ────────────────────────────────────────
// certbot_http/certbot_dns : acceptés ici (validation pure, un conteneur à la
// fois) mais leur résolution réelle — vérifier que Certbot est configuré ET
// activé, chercher/emettre le certificat — vit dans
// features/docker-autoconfig.js#resolveSsl(), seul endroit qui touche
// features/certbot.js / features/certbot-dns.js (via setDeps, jamais un
// require direct entre features). Voir le commentaire de resolveSsl().
const SSL_MODE_RE = /^(none|snippet|auto|certbot_http|certbot_dns)$/i;
// A snippet filename: no path separators, no leading dot (no traversal, no
// hidden file), must end in .conf — the same shape every other feature in
// this project expects of a file living directly under DIR_SNIPPETS.
const SNIPPET_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.conf$/;
const BOOL_RE = /^(true|false)$/i;
const INTERVAL_RE = /^\d+s?$/;
const HTTP_CODE_TOKEN_RE = /^[1-5](xx|\d{2})$/i;
const RULE_ID_TOKEN_RE = /^\d+$/;
// nginx `upstream <name> { ... }` block name — same conservative charset as
// a network/snippet identifier, never interpolated raw without this check.
const UPSTREAM_GROUP_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

function parseBoolLabel(raw, fallback) {
  if (raw === undefined || raw === null || raw === '') return { ok: true, value: fallback };
  if (!BOOL_RE.test(raw)) return { ok: false, value: fallback };
  return { ok: true, value: raw.toLowerCase() === 'true' };
}

/**
 * Extract the nginx-control.* labels of one container into a desired-state
 * object. Returns `null` (not an object with enabled:false) when the
 * container has no `nginx-control.enable=true` label at all, so callers can
 * distinguish "not opted in" from "opted in but invalid" with a single
 * truthiness check.
 */
function parseContainerLabels(labels) {
  const l = labels || {};
  if (String(l[`${LABEL_PREFIX}enable`] || '').toLowerCase() !== 'true') return null;

  const desired = {
    network: (l[`${LABEL_PREFIX}network`] || '').trim(),
    serverNameRaw: (l[`${LABEL_PREFIX}vhost.server_name`] || '').trim(),
    // Left empty (not defaulted to "80" here) so validateDesiredVhost() can
    // pick 80 or 443 once it knows whether SSL was requested.
    listenRaw: (l[`${LABEL_PREFIX}vhost.listen`] || '').trim(),
    locations: [],
    serverSnippets: [],
    sslModeRaw: (l[`${LABEL_PREFIX}vhost.ssl_certificate`] || 'none').trim(),
    sslSnippetRaw: (l[`${LABEL_PREFIX}vhost.ssl_certificate.snippet`] || '').trim(),
    httpToHttpsAutoRaw: l[`${LABEL_PREFIX}vhost.http_to_https_auto`],
    monitor: {
      enableRaw: l[`${LABEL_PREFIX}vhost.monitor.enable`],
      intervalRaw: (l[`${LABEL_PREFIX}vhost.monitor.interval`] || '').trim(),
      validHttpCodeRaw: (l[`${LABEL_PREFIX}vhost.monitor.valid_http_code`] || '').trim(),
    },
    diagnostic: { enableRaw: l[`${LABEL_PREFIX}vhost.diagnostic.enable`] },
    analyze: {
      enableRaw: l[`${LABEL_PREFIX}vhost.analyze.enable`],
      ignoreRulesRaw: (l[`${LABEL_PREFIX}vhost.analyze.ignore_rules`] || '').trim(),
    },
  };

  // Collect locationNN / locationNN.proxy_pass / locationNN.snippetMM /
  // locationNN.monitor.ignore pairs, keyed by their index string so "01" and
  // "1" are never accidentally merged. Server-level snippets
  // (server.snippetNN) are collected separately, unindexed by location.
  const byIndex = new Map();
  const locRe = /^vhost\.location(\d+)$/;
  const proxyRe = /^vhost\.location(\d+)\.proxy_pass$/;
  // v12.34.0 : `.target` accepte comme alias de `.proxy_pass`, pour que le
  // meme jeu de labels fonctionne indifferemment ici et sur nginx-agent
  // (Partie 2, hotes Docker distants), qui accepte deja `.target` comme
  // forme principale et `.proxy_pass` comme alias (voir labels.go) — cette
  // asymetrie a fait qu un jeu de labels ecrit avec `.target` restait
  // invisible ici alors qu il fonctionne sur un agent distant. `.target`
  // est prioritaire si les deux sont poses, meme ordre de priorite que
  // labels.go, pour un comportement identique dans les deux sens.
  const targetRe = /^vhost\.location(\d+)\.target$/;
  const locSnippetRe = /^vhost\.location(\d+)\.snippet(\d+)$/;
  const locMonitorIgnoreRe = /^vhost\.location(\d+)\.monitor\.ignore$/;
  const locUpstreamGroupRe = /^vhost\.location(\d+)\.upstream_group$/;
  const serverSnippetRe = /^vhost\.server\.snippet(\d+)$/;

  const entry = idx => { const e = byIndex.get(idx) || { snippets: new Map() }; byIndex.set(idx, e); return e; };

  for (const [key, value] of Object.entries(l)) {
    if (!key.startsWith(LABEL_PREFIX)) continue;
    const rest = key.slice(LABEL_PREFIX.length);

    let m;
    if ((m = rest.match(serverSnippetRe))) {
      desired.serverSnippets.push({ index: m[1], file: (value || '').trim() });
      continue;
    }
    if ((m = rest.match(locSnippetRe))) {
      entry(m[1]).snippets.set(m[2], (value || '').trim());
      continue;
    }
    if ((m = rest.match(locMonitorIgnoreRe))) {
      entry(m[1]).monitorIgnoreRaw = value;
      continue;
    }
    if ((m = rest.match(locUpstreamGroupRe))) {
      entry(m[1]).upstreamGroupRaw = (value || '').trim();
      continue;
    }
    if ((m = rest.match(proxyRe))) {
      entry(m[1]).proxyPass = (value || '').trim();
      continue;
    }
    if ((m = rest.match(targetRe))) {
      entry(m[1]).target = (value || '').trim();
      continue;
    }
    if ((m = rest.match(locRe))) {
      entry(m[1]).path = (value || '').trim();
      continue;
    }
  }

  desired.serverSnippets.sort((a, b) => a.index.localeCompare(b.index, undefined, { numeric: true }));

  desired.locations = [...byIndex.entries()]
    .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
    .map(([index, e]) => ({
      index,
      path: e.path || '',
      proxyPass: e.target || e.proxyPass || '',
      monitorIgnoreRaw: e.monitorIgnoreRaw,
      upstreamGroupRaw: e.upstreamGroupRaw || '',
      snippets: [...e.snippets.entries()]
        .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
        .map(([snIndex, file]) => ({ index: snIndex, file })),
    }));

  return desired;
}

/**
 * Validate an already-parsed desired vhost. `context.nginxNetworks`, when
 * provided, is the list of Docker networks actually attached to the nginx
 * container — a `nginx-control.network` label naming anything else is
 * rejected explicitly rather than producing a vhost nginx can never reach.
 *
 * Returns { valid, errors, serverNames, listen, ssl, httpToHttpsAuto,
 * monitor, diagnostic, analyze }. `serverNames` is always an array (possibly
 * empty on failure) so a caller can check for cross-container conflicts even
 * when other parts of the same label set are invalid.
 */
function validateDesiredVhost(desired, context = {}) {
  const errors = [];

  const serverNames = desired.serverNameRaw
    ? desired.serverNameRaw.split(/[\s,]+/).filter(Boolean)
    : [];
  if (!serverNames.length) {
    errors.push('nginx-control.vhost.server_name est requis');
  } else {
    for (const name of serverNames) {
      if (!HOSTNAME_RE.test(name)) errors.push(`server_name invalide : "${name}"`);
    }
  }

  if (!desired.network) {
    errors.push('nginx-control.network est requis');
  } else if (!NETWORK_NAME_RE.test(desired.network)) {
    errors.push(`nginx-control.network invalide : "${desired.network}"`);
  } else if (Array.isArray(context.nginxNetworks) && context.nginxNetworks.length
             && !context.nginxNetworks.includes(desired.network)) {
    errors.push(`reseau "${desired.network}" non attache au conteneur nginx (reseaux disponibles : ${context.nginxNetworks.join(', ') || 'aucun'})`);
  }

  // ─── SSL mode ──────────────────────────────────────────────────────────
  const sslModeRaw = (desired.sslModeRaw || 'none').toLowerCase();
  if (!SSL_MODE_RE.test(sslModeRaw)) {
    errors.push(`nginx-control.vhost.ssl_certificate invalide : "${desired.sslModeRaw}" (attendu : none, snippet, auto, certbot_http, certbot_dns)`);
  }
  const sslActive = SSL_MODE_RE.test(sslModeRaw) && sslModeRaw !== 'none';
  let sslSnippetFile = '';
  if (sslModeRaw === 'snippet') {
    sslSnippetFile = desired.sslSnippetRaw || '';
    if (!sslSnippetFile) errors.push('nginx-control.vhost.ssl_certificate.snippet est requis quand ssl_certificate=snippet');
    else if (!SNIPPET_FILENAME_RE.test(sslSnippetFile)) errors.push(`nginx-control.vhost.ssl_certificate.snippet invalide : "${sslSnippetFile}"`);
  }

  // `listen` — default depends on whether SSL was requested (443 vs 80) so
  // an operator only setting ssl_certificate=auto still gets a sane default.
  // parseInt() alone would accept "80; rm -rf /" (it stops at the first
  // non-digit and returns 80) — the whole label value must be nothing but
  // digits before it is trusted as a port number.
  let listen;
  if (!desired.listenRaw) {
    listen = sslActive ? 443 : 80;
  } else if (/^\d+$/.test(desired.listenRaw)) {
    listen = parseInt(desired.listenRaw, 10);
  } else {
    listen = NaN;
  }
  if (!Number.isInteger(listen) || listen < 1 || listen > 65535) {
    errors.push(`nginx-control.vhost.listen invalide : "${desired.listenRaw}"`);
  }

  const httpToHttpsAuto = parseBoolLabel(desired.httpToHttpsAutoRaw, false);
  if (!httpToHttpsAuto.ok) errors.push(`nginx-control.vhost.http_to_https_auto invalide : "${desired.httpToHttpsAutoRaw}"`);

  // Server-level snippets. Sorted here (not just trusted from the caller) so
  // validateDesiredVhost() gives a deterministic, index-ordered result
  // regardless of the order its input arrived in — parseContainerLabels()
  // already sorts, but this is the contract callers (and tests) can rely on.
  const sortedServerSnippets = [...(desired.serverSnippets || [])]
    .sort((a, b) => String(a.index).localeCompare(String(b.index), undefined, { numeric: true }));
  const serverSnippets = [];
  for (const sn of sortedServerSnippets) {
    if (!SNIPPET_FILENAME_RE.test(sn.file)) errors.push(`vhost.server.snippet${sn.index} invalide : "${sn.file}"`);
    else serverSnippets.push(sn.file);
  }

  // ─── Monitor / diagnostic / analyze ───────────────────────────────────
  const monitorEnable = parseBoolLabel(desired.monitor?.enableRaw, false);
  if (!monitorEnable.ok) errors.push(`nginx-control.vhost.monitor.enable invalide : "${desired.monitor.enableRaw}"`);
  let monitorInterval = '';
  if (desired.monitor?.intervalRaw) {
    if (!INTERVAL_RE.test(desired.monitor.intervalRaw)) errors.push(`nginx-control.vhost.monitor.interval invalide : "${desired.monitor.intervalRaw}"`);
    else monitorInterval = desired.monitor.intervalRaw;
  }
  let monitorValidHttpCodes = [];
  if (desired.monitor?.validHttpCodeRaw) {
    const tokens = desired.monitor.validHttpCodeRaw.split(/[\s,]+/).filter(Boolean);
    if (!tokens.length || tokens.some(t => !HTTP_CODE_TOKEN_RE.test(t))) {
      errors.push(`nginx-control.vhost.monitor.valid_http_code invalide : "${desired.monitor.validHttpCodeRaw}"`);
    } else monitorValidHttpCodes = tokens;
  }

  const diagnosticEnable = parseBoolLabel(desired.diagnostic?.enableRaw, true);
  if (!diagnosticEnable.ok) errors.push(`nginx-control.vhost.diagnostic.enable invalide : "${desired.diagnostic.enableRaw}"`);

  const analyzeEnable = parseBoolLabel(desired.analyze?.enableRaw, true);
  if (!analyzeEnable.ok) errors.push(`nginx-control.vhost.analyze.enable invalide : "${desired.analyze.enableRaw}"`);
  let analyzeIgnoreRules = [];
  if (desired.analyze?.ignoreRulesRaw) {
    const tokens = desired.analyze.ignoreRulesRaw.split(/[\s,]+/).filter(Boolean);
    if (!tokens.length || tokens.some(t => !RULE_ID_TOKEN_RE.test(t))) {
      errors.push(`nginx-control.vhost.analyze.ignore_rules invalide : "${desired.analyze.ignoreRulesRaw}"`);
    } else analyzeIgnoreRules = tokens;
  }

  // ─── Locations ─────────────────────────────────────────────────────────
  if (!desired.locations.length) {
    errors.push('au moins une location (nginx-control.vhost.locationNN) est requise');
  }
  const locations = [];
  for (const loc of desired.locations) {
    if (!LOCATION_RE.test(loc.path)) {
      errors.push(`location${loc.index} invalide : "${loc.path}"`);
    }
    if (!loc.proxyPass) {
      errors.push(`location${loc.index}.proxy_pass (ou .target) est requis`);
    } else if (!PROXY_PASS_RE.test(loc.proxyPass)) {
      errors.push(`location${loc.index}.proxy_pass invalide : "${loc.proxyPass}"`);
    }
    const monitorIgnore = parseBoolLabel(loc.monitorIgnoreRaw, false);
    if (!monitorIgnore.ok) errors.push(`vhost.location${loc.index}.monitor.ignore invalide : "${loc.monitorIgnoreRaw}"`);
    const sortedLocSnippets = [...(loc.snippets || [])]
      .sort((a, b) => String(a.index).localeCompare(String(b.index), undefined, { numeric: true }));
    const locSnippets = [];
    for (const sn of sortedLocSnippets) {
      if (!SNIPPET_FILENAME_RE.test(sn.file)) errors.push(`vhost.location${loc.index}.snippet${sn.index} invalide : "${sn.file}"`);
      else locSnippets.push(sn.file);
    }
    // `upstream_group` (etape 2, agregation multi-conteneurs) : le nom de
    // groupe est valide ici (regex ancree), mais l AGREGATION elle-meme
    // (plusieurs conteneurs -> un seul bloc `upstream <nom> {...}`) ne peut
    // pas se faire dans ce module pur, un seul conteneur a la fois n a rien
    // a agreger avec. C est features/docker-autoconfig.js qui, en voyant
    // plusieurs candidats valides partager le meme server_name ET le meme
    // nom de groupe sur la meme location, construit lui-meme l objet
    // `locations` fourni a generateVhostContent() avec `upstreamBackends`
    // rempli (voir son propre header de commentaire).
    let upstreamGroup = '';
    if (loc.upstreamGroupRaw) {
      if (!UPSTREAM_GROUP_NAME_RE.test(loc.upstreamGroupRaw)) errors.push(`vhost.location${loc.index}.upstream_group invalide : "${loc.upstreamGroupRaw}"`);
      else upstreamGroup = loc.upstreamGroupRaw;
    }
    locations.push({
      index: loc.index, path: loc.path, proxyPass: loc.proxyPass,
      monitorIgnore: monitorIgnore.value, snippets: locSnippets, upstreamGroup,
    });
  }

  // Fix v12.21.2 (audit finding DAC-09): two locations sharing the exact
  // same `path` both pass every check above individually (each is a
  // perfectly valid location on its own), but rendering both produces two
  // `location <same path> { ... }` blocks in the same server{} — nginx
  // rejects that as a duplicate location, failing `nginx -t` for the WHOLE
  // batch this candidate's file was written alongside (see
  // features/docker-autoconfig.js#runCycle(), which tests every generated
  // file together). Caught here instead, as an ordinary validation error:
  // this one candidate is marked invalid (shown as such in the UI) and
  // every OTHER candidate in the same cycle is unaffected.
  const seenPaths = new Map();
  for (const loc of locations) {
    if (seenPaths.has(loc.path)) {
      errors.push(`location${loc.index} et location${seenPaths.get(loc.path)} partagent le meme chemin "${loc.path}"`);
    } else {
      seenPaths.set(loc.path, loc.index);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    serverNames,
    listen: Number.isInteger(listen) ? listen : null,
    ssl: { mode: sslModeRaw, snippetFile: sslSnippetFile, active: sslActive },
    httpToHttpsAuto: httpToHttpsAuto.value,
    serverSnippets,
    locations,
    monitor: { enable: monitorEnable.value, interval: monitorInterval, validHttpCodes: monitorValidHttpCodes },
    diagnostic: { enable: diagnosticEnable.value },
    analyze: { enable: analyzeEnable.value, ignoreRules: analyzeIgnoreRules },
  };
}

/**
 * Split an already-validated `proxy_pass` target (matches PROXY_PASS_RE)
 * into its scheme/host/port — used by features/docker-autoconfig.js to
 * build the `server host:port;` lines of an `upstream_group` block. Returns
 * `null` if the input somehow doesn't match (defense in depth: callers are
 * expected to only pass values already validated by validateDesiredVhost()).
 */
function parseBackendUrl(proxyPass) {
  const m = PROXY_PASS_RE.exec(proxyPass || '');
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const host = m[2];
  const port = m[7] ? parseInt(m[7], 10) : (scheme === 'https' ? 443 : 80);
  return { scheme, host, port };
}

/** Sanitize a server_name into a safe, stable filename component. */
function sanitizeForFilename(serverName) {
  return serverName.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'vhost';
}

/**
 * `sites/docker_<server_name>_<hash>.conf` — see the design doc's naming
 * section.
 *
 * Fix v12.21.2 (audit finding DAC-02): sanitizeForFilename() collapses every
 * run of non-alphanumeric characters to a single `_`, so `*.example.com` and
 * `example.com` (or `a-b.example.com` and `a.b.example.com`) used to produce
 * the exact same file name — two unrelated containers would then overwrite
 * each other's vhost on every cycle, or a single container flipping between
 * a bare name and its wildcard would have its own file written and removed
 * in the same pass (see runCycle()'s toWrite/toRemove diff). Appending a
 * short hash of the untouched, lower-cased server name makes the file name a
 * function of the exact string again: two different server_names collide
 * only in the astronomically unlikely case of a hash collision, which
 * runCycle() additionally guards against explicitly (never trusted blindly).
 */
function dockerVhostFileName(serverNames) {
  const primary = String(serverNames[0] || '').toLowerCase();
  const hash = crypto.createHash('sha1').update(primary).digest('hex').slice(0, 8);
  return `docker_${sanitizeForFilename(primary)}_${hash}.conf`;
}

/**
 * Render the nginx server block(s) for a validated desired vhost. Callers
 * MUST have run validateDesiredVhost() first and confirmed `valid: true` —
 * this function does not re-validate, it only formats already-trusted
 * values (the `validated` object returned by validateDesiredVhost(), NOT the
 * raw `desired` object from parseContainerLabels()).
 *
 * meta: { containerName, containerId, generatedAt, sslResolved } —
 * `sslResolved` is decided by features/docker-autoconfig.js (it alone talks
 * to lib/certs.js) and is one of:
 *   - undefined                          → ssl mode was "none"
 *   - { type: 'snippet', file }          → ssl mode "snippet"
 *   - { type: 'cert', certPath, keyPath} → ssl mode "auto", a matching
 *                                           certificate was found
 *   - { type: 'pending' }                → ssl mode "auto"/"certbot_*",
 *                                           nothing matched yet (or Certbot
 *                                           is configured but issuance
 *                                           hasn't completed): rendered as
 *                                           plain HTTP with a note, never as
 *                                           broken SSL.
 *   - { type: 'error', code, message }   → ssl mode "certbot_http"/
 *                                           "certbot_dns" requested, but
 *                                           Certbot (or Certbot-DNS) is not
 *                                           configured/activated upstream
 *                                           (config/certbot*.yml's own
 *                                           `enable: false`). Never silently
 *                                           dropped to plain HTTP without a
 *                                           trace: rendered like `pending`
 *                                           (plain HTTP, no broken `ssl`
 *                                           directive) but with an explicit
 *                                           error note in the file header,
 *                                           and surfaced by getStatus() so
 *                                           an operator sees it without
 *                                           having to open the file.
 */
function generateVhostContent(validated, serverNames, listen, meta = {}) {
  const generatedAt = meta.generatedAt || new Date().toISOString();
  const sslResolved = validated.ssl?.active ? meta.sslResolved : undefined;
  const sslIsLive = !!sslResolved && sslResolved.type !== 'pending' && sslResolved.type !== 'error';

  // Fix (audit report, Basse/"Partie 1 et certificats"): while
  // ssl_certificate=certbot_http is requested but not yet live (pending
  // first issuance, or already live and due for renewal), certbot's HTTP-01
  // challenge needs `GET /.well-known/acme-challenge/<token>` to reach ITS
  // OWN webroot on port 80 for this exact server_name. Before this fix, a
  // still-pending vhost rendered `listen 443` (no `ssl` keyword yet, since
  // sslIsLive is false) with no port-80 block at all — the request fell
  // through to 00-default.conf's `default_server` on port 80, which proxies
  // everything to the error-pages container, so the challenge could never
  // succeed and the vhost stayed "pending" forever. `certbotWebrootPath` is
  // only ever set (see features/docker-autoconfig.js) when Certbot's HTTP
  // challenge is actually configured; without it this stays a no-op exactly
  // as before.
  const needsAcmeChallenge = validated.ssl?.active && validated.ssl.mode === 'certbot_http' && !!meta.certbotWebrootPath;
  const acmeChallengeLines = needsAcmeChallenge ? [
    '    location /.well-known/acme-challenge/ {',
    `        root ${meta.certbotWebrootPath};`,
    '    }',
    '',
  ] : [];

  const header = [
    '# Genere automatiquement par nginx-control — NE PAS EDITER A LA MAIN',
    `# Source: labels Docker (nginx-control.*) sur le conteneur ${meta.containerName || '?'} (${(meta.containerId || '').slice(0, 12)})`,
    `# Genere le: ${generatedAt}`,
    '#',
    '# Ce fichier est regenere a chaque cycle de detection : toute modification',
    '# manuelle sera perdue au prochain passage. Pour changer cette config,',
    "# modifier les labels du conteneur puis le recreer/mettre a jour.",
  ];
  if (validated.ssl?.active && sslResolved?.type === 'error') {
    header.push('#',
      `# ERREUR ssl_certificate=${validated.ssl.mode} : ${sslResolved.message}`,
      '# Ce vhost reste en HTTP simple tant que ce n est pas corrige — jamais',
      '# de bloc ssl casse. Corriger la configuration Certbot puis relancer un',
      '# cycle (ou attendre le prochain sondage) pour re-tenter.');
  } else if (validated.ssl?.active && !sslIsLive) {
    header.push('#',
      `# ssl_certificate=${validated.ssl.mode} demande mais aucun certificat correspondant n a`,
      '# encore ete trouve : ce vhost reste en HTTP simple en attendant. Il sera',
      '# regenere automatiquement en HTTPS des qu un certificat sera detecte.');
  }
  // File-level diagnostic opt-out must appear before the first `server{}`
  // block — see lib/vhost-targets.js's own header comment for this exact
  // contract. Placed here, still inside the leading comment block.
  if (!validated.diagnostic.enable) header.push('#', '# nginx-control-diagnostic: off');
  header.push('');

  const lines = [...header];

  // `upstream <name> { server host:port; ... }` blocks for any aggregated
  // (`upstream_group`) location — built by features/docker-autoconfig.js
  // when several containers share both the same server_name and the same
  // group name on a location (see that module's own comment on this). A
  // plain single-container location never has `upstreamBackends` set and
  // is rendered the usual resolver/set/proxy_pass way further down. These
  // blocks sit at the top of the file, outside any server{} — legal
  // anywhere in the http{} context this file is included into.
  const upstreamBlocks = [];
  const seenGroups = new Set();
  for (const loc of validated.locations) {
    if (loc.upstreamGroup && loc.upstreamBackends && !seenGroups.has(loc.upstreamGroup)) {
      seenGroups.add(loc.upstreamGroup);
      upstreamBlocks.push(loc);
    }
  }
  for (const loc of upstreamBlocks) {
    lines.push(`upstream ${loc.upstreamGroup} {`);
    for (const b of loc.upstreamBackends) lines.push(`    server ${b.host}:${b.port};`);
    lines.push('}', '');
  }

  // Optional plain-HTTP → HTTPS redirect server, only meaningful once SSL is
  // actually live (never for a still-pending "auto" resolution — there is
  // nothing to redirect to yet).
  if (validated.httpToHttpsAuto && sslIsLive) {
    lines.push('server {', '    listen 80;', '    listen [::]:80;',
      `    server_name ${serverNames.join(' ')};`);
    // Renewal must keep working after go-live: without this, every request
    // (including certbot's own challenge) is unconditionally redirected to
    // https before it can be answered from the webroot.
    lines.push(...acmeChallengeLines);
    lines.push('    return 301 https://$host$request_uri;', '}', '');
  }

  // While the certbot_http challenge hasn't succeeded yet, this server block
  // itself has to be the one listening on plain port 80 (see
  // needsAcmeChallenge's comment above) — the normally-computed `listen`
  // (443 by default once SSL is requested, see validateDesiredVhost()) would
  // otherwise still apply and leave nothing on port 80 for the challenge.
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
    lines.push(`    # nginx-control-monitoring: on`);
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

  validated.locations.forEach((loc, i) => {
    lines.push(`    location ${loc.path} {`);
    if (loc.upstreamGroup && loc.upstreamBackends) {
      lines.push(`        proxy_pass ${loc.upstreamScheme || 'http'}://${loc.upstreamGroup};`);
    } else {
      const varName = `$backend${loc.index}`;
      lines.push('        resolver 127.0.0.11 valid=30s;');
      lines.push(`        set ${varName} "${loc.proxyPass}";`);
      lines.push(`        proxy_pass ${varName};`);
    }
    if (loc.monitorIgnore) lines.push('        # nginx-control-monitoring-ignore-location: on');
    for (const file of loc.snippets) lines.push(`        include snippets/${file};`);
    lines.push('    }');
    if (i < validated.locations.length - 1) lines.push('');
  });
  lines.push('}', '');
  return lines.join('\n');
}

module.exports = {
  LABEL_PREFIX, HOSTNAME_RE, LOCATION_RE, PROXY_PASS_RE, NETWORK_NAME_RE,
  SSL_MODE_RE, SNIPPET_FILENAME_RE, INTERVAL_RE, HTTP_CODE_TOKEN_RE, RULE_ID_TOKEN_RE,
  UPSTREAM_GROUP_NAME_RE,
  parseContainerLabels, validateDesiredVhost,
  sanitizeForFilename, dockerVhostFileName, generateVhostContent, parseBackendUrl,
};
