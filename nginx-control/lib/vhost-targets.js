'use strict';
/**
 * Best-effort resolver for "what does this vhost actually proxy to".
 *
 * nginx configuration is not context-free (variables, includes, conditional
 * directives), so this is deliberately NOT a general nginx config parser —
 * it recognises the handful of patterns this project's own vhost files
 * actually use (see features/vhost-generator.js, whose output this reads
 * back) and falls back to `kind: 'unresolved'` rather than guessing:
 *
 *  - direct:   proxy_pass http://host:port;              (or an IP, no port)
 *  - upstream: proxy_pass http://name;  where `upstream name { server a; server b; }`
 *              is defined somewhere in the managed conf/sites directories
 *              (load-balancing / HA: more than one `server` line)
 *  - docker:   proxy_pass $var; / proxy_pass http://$var:port;  where a
 *              `set $var ...;` line defines the value and a `resolver`
 *              directive is present in the file — the pattern
 *              features/vhost-generator.js emits for a Docker container
 *              target (Docker's embedded DNS at 127.0.0.11 resolves the
 *              container/service name), and the one already used by this
 *              project's own shipped examples (global-error.conf,
 *              00-default.conf: `set $upstream_errors error-pages;`).
 *  - variable: resolved through `set`, but no `resolver` directive found —
 *              probably not a Docker target, shown as best-effort anyway.
 *  - unresolved: a variable is used but no matching `set` was found, or the
 *              value doesn't parse as a URL at all. The raw text is always
 *              kept so the operator can read it themselves.
 */

const fs   = require('fs');
const path = require('path');

const tree = require('./fs-tree');
const { safeReadDir, safeReadFile } = tree;
const { parseValidHttpCodes } = require('./monitor-status');

/**
 * Find every `<headerRe> ... { ... }` block in `content`, respecting nested
 * braces (a naive `[^}]*` regex stops at the first inner `}`, e.g. a
 * location block's own closing brace inside a server block).
 * `headerRe` must be a global regex matching up to and including the
 * opening `{`.
 *
 * Real bug caught in the wild: `headerRe` must be word-bounded on its
 * keyword (e.g. `(?<![A-Za-z0-9_$.-])server\s*\{`, not just `server\s*\{`).
 * Without it, `upstream jitsiserver { ... }` is itself mistaken for a
 * `server{}` block, because "server" appears as a bare substring right
 * before " {" (…jitsi`server` `{`) — same risk for `location` inside an
 * identifier like `$geolocation`. `\b` alone isn't enough (it treats `_`
 * as a word character, so `$backend_server {` would still slip through) —
 * use the negative-lookbehind form above.
 */
function extractBlocks(content, headerRe) {
  const blocks = [];
  headerRe.lastIndex = 0;
  let m;
  while ((m = headerRe.exec(content))) {
    const bodyStart = m.index + m[0].length;
    let depth = 1, i = bodyStart;
    while (i < content.length && depth > 0) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') depth--;
      i++;
    }
    blocks.push({ match: m, body: content.slice(bodyStart, i - 1) });
    headerRe.lastIndex = i;
  }
  return blocks;
}

/** Split "host:port" (or a bare host, or "[::1]:port") into { host, port }. */
function splitHostPort(hostport) {
  const s = hostport.trim();
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close === -1) return { host: s, port: null };
    const host = s.slice(1, close);
    const rest = s.slice(close + 1);
    const portMatch = rest.match(/^:(\d+)/);
    return { host, port: portMatch ? Number(portMatch[1]) : null };
  }
  const lastColon = s.lastIndexOf(':');
  if (lastColon === -1) return { host: s, port: null };
  const maybePort = s.slice(lastColon + 1);
  if (/^\d+$/.test(maybePort)) return { host: s.slice(0, lastColon), port: Number(maybePort) };
  return { host: s, port: null };
}

function defaultPort(scheme) { return scheme === 'https' ? 443 : 80; }

/**
 * File-wide opt-out from the Diagnostic page: `# nginx-control-diagnostic: off`,
 * on its own comment line, anywhere BEFORE the first `server{}` block —
 * same idiom as the monitoring flags (a comment, never a real nginx
 * directive, so it has zero effect on the config nginx actually serves).
 * Placed outside every server block on purpose: it reads as a property of
 * the whole file (e.g. a snippet-heavy file the operator never wants a
 * Diagnostic card for), distinct from `nginx-control-diagnostic-vhost`
 * below, which opts out one server{} block at a time.
 */
function fileDiagnosticEnabled(content) {
  const firstServerIdx = content.search(/(?<![A-Za-z0-9_$.-])server\s*\{/);
  const preamble = firstServerIdx === -1 ? content : content.slice(0, firstServerIdx);
  const m = preamble.match(/^\s*#\s*nginx-control-diagnostic\s*:\s*(on|off)\s*$/im);
  return !(m && m[1].toLowerCase() === 'off');
}

/** All `upstream NAME { server host:port ...; ... }` blocks across the given directories. */
function parseUpstreams(dirs) {
  const upstreams = {};
  for (const dir of dirs) {
    if (!dir) continue;
    for (const name of safeReadDir(dir)) {
      if (!/\.conf(\.DISABLE)?$/.test(name)) continue;
      const content = safeReadFile(path.join(dir, name));
      if (!content) continue;
      for (const { match, body } of extractBlocks(content, /(?<![A-Za-z0-9_$.-])upstream\s+([A-Za-z0-9_.-]+)\s*\{/g)) {
        const servers = [];
        for (const sm of body.matchAll(/^\s*server\s+([^\s;]+)/gm)) {
          if (sm[1] === '0.0.0.0:0') continue; // "server ... backup;" placeholders, rare — skip junk lines defensively
          const { host, port } = splitHostPort(sm[1]);
          servers.push({ host, port });
        }
        if (servers.length) upstreams[match[1]] = servers;
      }
    }
  }
  return upstreams;
}

/** Resolve one `proxy_pass` value into { kind, targets, raw }. */
function resolveProxyPass(rawValue, fileContent, upstreams) {
  const raw = rawValue.trim();

  const hasResolver = /\bresolver\s+/.test(fileContent);
  const findSet = (varName) => {
    const m = fileContent.match(new RegExp(`set\\s+\\$${varName}\\s+([^;]+);`));
    return m ? m[1].trim() : null;
  };

  // Whole value is a bare variable: `proxy_pass $backend;`
  const wholeVar = raw.match(/^\$([A-Za-z_]\w*)$/);
  if (wholeVar) {
    const value = findSet(wholeVar[1]);
    if (!value) return { kind: 'unresolved', targets: [], raw };
    const urlMatch = value.match(/^(https?):\/\/(.+)$/);
    const scheme = urlMatch ? urlMatch[1] : 'http';
    const { host, port } = splitHostPort(urlMatch ? urlMatch[2] : value);
    return {
      kind: hasResolver ? 'docker' : 'variable',
      targets: [{ scheme, host, port: port || defaultPort(scheme) }],
      raw,
    };
  }

  const urlMatch = raw.match(/^(https?):\/\/(.+)$/);
  if (!urlMatch) return { kind: 'unresolved', targets: [], raw };
  const scheme = urlMatch[1];
  const rest = urlMatch[2].split('/')[0]; // drop any path suffix

  // Host portion is itself a variable: `proxy_pass http://$var:8080;`
  const varHost = rest.match(/^\$([A-Za-z_]\w*)(?::(\d+))?$/);
  if (varHost) {
    const value = findSet(varHost[1]);
    if (!value) return { kind: 'unresolved', targets: [], raw };
    const port = varHost[2] ? Number(varHost[2]) : defaultPort(scheme);
    return {
      kind: hasResolver ? 'docker' : 'variable',
      targets: [{ scheme, host: value, port }],
      raw,
    };
  }

  const { host, port } = splitHostPort(rest);
  if (!port && upstreams[host]) {
    return {
      kind: 'upstream',
      targets: upstreams[host].map(s => ({ scheme, host: s.host, port: s.port || defaultPort(scheme) })),
      raw,
    };
  }
  return { kind: 'direct', targets: [{ scheme, host, port: port || defaultPort(scheme) }], raw };
}

/** Parse one vhost file's server{} blocks into { serverNames, ssl, listen, locations }. */
function parseVhostFile(content, upstreams) {
  const serverBlocks = [];
  for (const { body } of extractBlocks(content, /(?<![A-Za-z0-9_$.-])server\s*\{/g)) {
    const nameMatch = body.match(/server_name\s+([^;]+);/);
    const serverNames = nameMatch ? nameMatch[1].trim().split(/\s+/) : [];
    const listen = [...body.matchAll(/listen\s+([^;]+);/g)].map(m => m[1].trim());
    const ssl = listen.some(l => /\bssl\b/.test(l)) || /ssl_certificate\s+/.test(body);

    // Server itself forces HTTP -> HTTPS (a `return 301 https://...;` or
    // `rewrite ... https://...` directive) — the audit feature uses this to
    // tell "HTTP with no redirect" (a real finding) apart from "this vhost's
    // whole job is redirecting" (expected, not a finding), and the Backends
    // page uses it to hide such a block (nothing to test there).
    const redirectsToHttps = /\breturn\s+30[1278]\s+https:\/\//i.test(body) || /\brewrite\s+\S+\s+https:\/\//i.test(body);

    // Continuous monitoring (features/monitor.js) is opt-in per server block,
    // via a comment flag rather than a real nginx directive (nginx ignores
    // comments, so this never affects the actual config) — the user's own
    // proposed syntax:
    //   # nginx-control-monitoring: on|off
    //   # nginx-control-monitoring-interval: 60s
    //   # nginx-control-monitoring-valid-http-code: 2xx, 3xx
    // Anchored to a whole line (^...$ with /m) so this only fires on an
    // actual comment line, not on the phrase appearing incidentally in a
    // proxy_pass value or a server_name. Interval floor of 10s guards
    // against a typo (or "0s") turning this into a probe flood.
    //
    // The valid-http-code flag overrides the default "up" rule (2xx/3xx/4xx
    // up, 5xx or no response down — see lib/monitor-status.js) with an
    // explicit allow-list of status classes/codes/ranges. Needed for a
    // backend fronted by something like Traefik, which answers a stopped
    // container with a normal HTTP response (often a 404) rather than a
    // connection error — without an override that always reads as "up".
    const monitoringOnMatch = body.match(/^\s*#\s*nginx-control-monitoring\s*:\s*(on|off)\s*$/im);
    const monitoringIntervalMatch = body.match(/^\s*#\s*nginx-control-monitoring-interval\s*:\s*(\d+)\s*s?\s*$/im);
    const monitoringValidCodesMatch = body.match(/^\s*#\s*nginx-control-monitoring-valid-http-code\s*:\s*(.+?)\s*$/im);
    const monitoring = {
      enabled: !!monitoringOnMatch && monitoringOnMatch[1].toLowerCase() === 'on',
      intervalSec: monitoringIntervalMatch ? Math.max(10, parseInt(monitoringIntervalMatch[1], 10)) : 60,
      validHttpCodes: monitoringValidCodesMatch ? parseValidHttpCodes(monitoringValidCodesMatch[1]) : null,
    };

    // Per-block opt-out from the Diagnostic page (features/audit.js drops
    // any block with diagnosticEnabled===false before running the audit) —
    // same comment idiom as the monitoring flags, but scoped to just this
    // server{} block rather than the whole file (see fileDiagnosticEnabled
    // above for the file-wide equivalent). Useful for a vhost that is a
    // known special case (a legacy redirect, an internal-only block) where
    // the audit's findings don't apply and would just be noise.
    const diagnosticVhostMatch = body.match(/^\s*#\s*nginx-control-diagnostic-vhost\s*:\s*(on|off)\s*$/im);
    const diagnosticEnabled = !(diagnosticVhostMatch && diagnosticVhostMatch[1].toLowerCase() === 'off');

    // Opt-out de l analyse de logs (features/analyzer.js / nginx-analyzer),
    // meme idiome que le flag de diagnostic ci-dessus — un commentaire,
    // jamais une vraie directive nginx, donc sans le moindre effet sur la
    // config nginx reellement servie :
    //   # nginx-control-analyze: off
    //   # nginx-control-analyze-ignore-rules: 1, 2, 4
    // Le premier flag coupe entierement la detection pour ce bloc server{}
    // (utile pour un vhost interne, une sonde, un site dont le trafic ne
    // doit jamais generer d alerte). Le second, plus fin, ne desactive que
    // les regles listees (identifiants numeriques stables, voir la modale
    // "Regles" de la page Analyse et lib/detect.js RULE_IDS cote analyzer) —
    // utile quand une seule regle est bruyante sur ce vhost precis (ex : un
    // proxy d entreprise qui ressemble en permanence a un flood) sans vouloir
    // perdre les autres detections sur le meme site.
    const analyzeMatch = body.match(/^\s*#\s*nginx-control-analyze\s*:\s*(on|off)\s*$/im);
    const analyzeEnabled = !(analyzeMatch && analyzeMatch[1].toLowerCase() === 'off');
    const analyzeIgnoreMatch = body.match(/^\s*#\s*nginx-control-analyze-ignore-rules\s*:\s*(.+?)\s*$/im);
    const analyzeIgnoreRuleIds = analyzeIgnoreMatch
      ? analyzeIgnoreMatch[1].split(',').map(s => parseInt(s.trim(), 10)).filter(Number.isFinite)
      : [];
    // Retour utilisateur (v12.50.0) : "prevoir aussi un commentaire dans la
    // configuration vhost pour ignore la remediation sur ce vhost particulier
    // -- comme cela on garde les alertes mais [pas] de blocage". Distinct de
    // `# nginx-control-analyze: off` (qui coupe l ALERTE elle-meme) : ce
    // commentaire ne change rien a la detection/aux alertes, il retire
    // seulement les occurrences de CE vhost du comptage utilise par le
    // mecanisme "Blocklist a la CrowdSec" (features/blocklists.js) pour
    // decider de bloquer une IP — voir pushVhostRules() qui agrege ce champ
    // par nom de vhost, meme mecanisme que analyzeEnabled/analyzeIgnoreRuleIds.
    const analyzeNoRemediationMatch = body.match(/^\s*#\s*nginx-control-analyze-no-remediation\s*:\s*(on|off)\s*$/im);
    const analyzeNoRemediation = !!analyzeNoRemediationMatch && analyzeNoRemediationMatch[1].toLowerCase() === 'on';

    // Retour utilisateur (v12.54.0) : un endpoint legitime qui repond 403 aux
    // visiteurs non connectes (ex. WordPress /wp-json/wpa/v1/verify-session)
    // declenche la regle brute force pour des visiteurs normaux. Directive par
    // regle et par bloc server{} :
    //   # nginx-control-analyze-rule-1-paths-ignore: /wp-json/wpa/v1/verify-session,/autre
    // Les requetes de CE vhost vers ces chemins (query string ignoree) ne
    // comptent plus pour la regle {ID} — les autres regles les voient toujours.
    // Motif : chemin exact, ou prefixe s il se termine par "*". Plusieurs
    // lignes pour une meme regle s additionnent.
    const analyzePathsIgnore = parseAnalyzePathsIgnore(body);

    const locations = [];
    for (const { match: lm, body: lbody } of extractBlocks(body, /(?<![A-Za-z0-9_$.-])location\s+([^{]+?)\s*\{/g)) {
      const ppMatch = lbody.match(/proxy_pass\s+([^;]+);/);
      if (!ppMatch) continue; // not every location proxies (static, return, etc.)
      // Fix (audit finding MISC-12): this used to pass the WHOLE file's
      // content here, not just this server{} block's own `body`. A single
      // vhost file with more than one server{} block (each defining its own
      // `set $backend ...;`, as features/vhost-generator.js itself emits)
      // had every block's proxy_pass resolved against whichever `set`
      // happened to appear FIRST in the file — a variable reused across
      // blocks (or even just named the same) silently resolved to the
      // wrong backend for every block but the first. `resolver` presence is
      // checked the same way, for the same reason: vhost-generator.js emits
      // both `set` and `resolver` together, inside the same server block.
      const resolved = resolveProxyPass(ppMatch[1], body, upstreams);
      // `proxy_ssl_verify off;` — expected/legitimate when the backend uses a
      // self-signed cert (the "full SSL, ignore backend cert errors" pattern
      // the audit recommends as the practical minimum for an SSL-offload vhost).
      const sslVerifyOff = /\bproxy_ssl_verify\s+off\s*;/i.test(lbody);
      // Meme idiome que le flag de monitoring du bloc server{} (commentaire,
      // jamais une vraie directive nginx) mais par location : plusieurs
      // locations d un meme bloc peuvent proxifier la meme cible (des chemins
      // differents vers le meme backend), et surveiller chacune separement
      // n a alors aucun interet — juste des sondes dupliquees. Ancre a une
      // ligne de commentaire entiere pour ne se declencher que sur un vrai
      // flag, jamais sur une mention incidente ailleurs dans la location.
      const monitoringIgnoreMatch = lbody.match(/^\s*#\s*nginx-control-monitoring-ignore-location\s*:\s*(on|off)\s*$/im);
      const monitoringIgnored = !!monitoringIgnoreMatch && monitoringIgnoreMatch[1].toLowerCase() === 'on';
      locations.push({ path: lm[1].trim(), ...resolved, sslVerifyOff, monitoringIgnored });
    }
    serverBlocks.push({ serverNames, ssl, listen, redirectsToHttps, monitoring, diagnosticEnabled, analyzeEnabled, analyzeIgnoreRuleIds, analyzeNoRemediation, analyzePathsIgnore, locations });
  }
  return serverBlocks;
}

// Memes bornes que sanitizePathsIgnore() cote analyzer : un fichier vhost mal
// forme ne doit pas pouvoir gonfler la requete poussee ni le cout par requete.
const PATHS_IGNORE_MAX_PER_RULE = 50;
const PATHS_IGNORE_MAX_LEN = 256;

/**
 * Extrait `# nginx-control-analyze-rule-{ID}-paths-ignore: /a,/b` d un corps de
 * bloc server{} -> { [ruleId]: string[] }. Les motifs invalides (ne commencent
 * pas par "/", trop longs) sont ecartes, les doublons fusionnes.
 */
function parseAnalyzePathsIgnore(body) {
  const out = {};
  const re = /^[ \t]*#[ \t]*nginx-control-analyze-rule-(\d{1,6})-paths-ignore[ \t]*:[ \t]*(.+?)[ \t]*$/gim;
  let m;
  while ((m = re.exec(body)) !== null) {
    const id = parseInt(m[1], 10);
    const list = out[id] || (out[id] = []);
    for (const raw of m[2].split(',')) {
      const pat = raw.trim();
      if (pat.length < 1 || pat.length > PATHS_IGNORE_MAX_LEN || pat[0] !== '/') continue;
      if (!list.includes(pat) && list.length < PATHS_IGNORE_MAX_PER_RULE) list.push(pat);
    }
    if (!list.length) delete out[id];
  }
  return out;
}

/** Every vhost in `sitesDir`, with each location's backend resolved. */
function listVhostTargets({ sitesDir, upstreamDirs }) {
  const upstreams = parseUpstreams(upstreamDirs);
  return safeReadDir(sitesDir)
    .filter(name => /\.conf(\.DISABLE)?$/.test(name))
    .map(name => {
      const filePath = path.join(sitesDir, name);
      const content = safeReadFile(filePath) || '';
      return {
        file: filePath,
        name,
        enabled: !name.endsWith('.DISABLE'),
        diagnosticEnabled: fileDiagnosticEnabled(content),
        serverBlocks: parseVhostFile(content, upstreams),
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = {
  extractBlocks, splitHostPort, parseUpstreams, resolveProxyPass, parseVhostFile, listVhostTargets,
  fileDiagnosticEnabled, parseAnalyzePathsIgnore,
};
