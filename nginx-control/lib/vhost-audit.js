'use strict';
/**
 * Static HTTP-vs-HTTPS audit, on both sides of the proxy: the vhost (does it
 * force HTTPS?) and the target it resolves to (is the backend leg encrypted
 * too?). Deliberately config-only — no network calls here, so listing the
 * audit is instant. Reachability/response time for a given target is a
 * separate, on-demand concern already covered by /api/backends/check: the
 * audit page reuses that same route (same {file, blockIndex, locationIndex,
 * targetIndex} reference shape, since both features share the same resolver
 * in lib/vhost-targets.js) rather than duplicating the probing logic here.
 *
 * Findings use three levels: 'ok' (compliant), 'info' (worth knowing, not a
 * problem by itself), 'warning' (worth fixing). The one nuance explicitly
 * called out for this feature: a vhost terminating TLS and then talking to
 * its backend in plain HTTP ("SSL offload") is common and not automatically
 * wrong, but the recommended minimum is to also encrypt that second leg —
 * accepting a self-signed backend certificate (`proxy_ssl_verify off;`) is
 * an acceptable middle ground when a trusted one isn't available.
 */

function auditServerBlock(block) {
  const findings = [];

  if (!block.ssl) {
    if (block.redirectsToHttps) {
      findings.push({
        level: 'info', code: 'http-redirect',
        message: "Vhost HTTP dont le seul role est de rediriger vers HTTPS (return/rewrite ... https://) — comportement attendu.",
      });
    } else {
      findings.push({
        level: 'warning', code: 'http-no-redirect',
        message: "Vhost accessible en HTTP sans redirection vers HTTPS. Bonne pratique : forcer la redirection (par ex. return 301 https://$host$request_uri;) ou terminer directement en HTTPS.",
      });
    }
  }

  for (const loc of block.locations || []) {
    if (loc.kind === 'unresolved') {
      findings.push({
        level: 'warning', code: 'unresolved-target', path: loc.path,
        message: `${loc.path} : cible non resolue (variable sans set correspondant, ou valeur qui ne ressemble pas a une URL) — impossible d'auditer ce chemin.`,
      });
      continue;
    }

    const targetScheme = (loc.targets || [])[0]?.scheme;
    if (block.ssl && targetScheme === 'http') {
      findings.push({
        level: 'info', code: 'ssl-offload', path: loc.path,
        message: `${loc.path} : decharge SSL — le vhost est en HTTPS mais la connexion vers le backend est en clair (HTTP). Bonne pratique a minima : passer le backend en HTTPS (proxy_pass https://...) avec proxy_ssl_verify off; si le certificat backend est auto-signe, plutot que du HTTP en clair cote interne.`,
      });
    } else if (block.ssl && targetScheme === 'https') {
      findings.push({
        level: 'ok', code: 'full-ssl', path: loc.path,
        message: loc.sslVerifyOff
          ? `${loc.path} : chiffre de bout en bout (verification du certificat backend desactivee via proxy_ssl_verify off — attendu avec un certificat auto-signe).`
          : `${loc.path} : chiffre de bout en bout.`,
      });
    } else if (!block.ssl && targetScheme === 'https') {
      findings.push({
        level: 'info', code: 'http-vhost-https-backend', path: loc.path,
        message: `${loc.path} : le vhost repond en HTTP mais contacte son backend en HTTPS.`,
      });
    }
  }

  return findings;
}

/** Decorate the output of lib/vhost-targets.js's listVhostTargets() with per-server-block findings. */
function auditVhosts(vhosts) {
  return vhosts.map(v => ({
    ...v,
    serverBlocks: (v.serverBlocks || []).map(b => ({ ...b, findings: auditServerBlock(b) })),
  }));
}

// ─── Live header audit ────────────────────────────────────────────────────────
// The checks above are config-only. These need an actual request/response —
// what a real client would see — so they're a separate, on-demand step
// (features/audit.js's POST /api/audit/headers), probing BOTH sides: the
// reverse proxy itself (does nginx add/strip what it should?) and the
// backend directly (is a leak coming from the backend, the proxy, or both?).
// Core, well-known checks — not exhaustive; a request for more can extend
// this list without touching the config-only checks above.
//
// Node's http/https response `headers` object always has lowercase keys —
// callers pass that object straight through, no normalization needed here.
const MISSING_HEADER_RULES = [
  { key: 'x-content-type-options', code: 'missing-nosniff',
    message: "En-tete X-Content-Type-Options absent : add_header X-Content-Type-Options nosniff always; empeche le navigateur de deviner un type MIME different de celui declare (protection contre certaines attaques de confusion de type)." },
  { key: 'x-frame-options', code: 'missing-frame-options',
    message: "En-tete X-Frame-Options (ou frame-ancestors dans une CSP) absent : add_header X-Frame-Options SAMEORIGIN always; protege contre le clickjacking (la page embarquee dans une iframe malveillante)." },
  { key: 'referrer-policy', code: 'missing-referrer-policy',
    message: "En-tete Referrer-Policy absent : add_header Referrer-Policy \"strict-origin-when-cross-origin\" always; limite les informations envoyees aux sites externes lors d'un clic sortant." },
  { key: 'content-security-policy', code: 'missing-csp',
    message: "En-tete Content-Security-Policy absent — plus complexe a regler correctement qu'un simple add_header (depend de l'application), mais reste la protection la plus efficace contre l'injection de script (XSS)." },
];
const HSTS_MIN_SECONDS = 15768000; // ~6 mois, valeur de depart courante avant d'envisager includeSubDomains/preload

function auditHeaderProbe({ ssl, proxyHeaders = {}, backendHeaders = {}, proxyOk, backendOk }) {
  const findings = [];

  if (!proxyOk) {
    // Sans reponse du proxy, tout le reste ("en-tete absent") serait un faux
    // positif — on ne sait rien, on ne pretend pas savoir.
    findings.push({
      level: 'warning', code: 'proxy-unreachable',
      message: "Impossible de joindre le reverse proxy pour ce vhost (verifier server_name/listen, ou que nginx tourne bien) — analyse des en-tetes incomplete.",
    });
    return findings;
  }

  if (ssl) {
    const hsts = proxyHeaders['strict-transport-security'];
    if (!hsts) {
      findings.push({
        level: 'warning', code: 'missing-hsts',
        message: "HSTS absent (Strict-Transport-Security) alors que le vhost est en HTTPS. Une fois le HTTPS confirme stable : add_header Strict-Transport-Security \"max-age=15768000; includeSubDomains\" always;",
      });
    } else {
      const m = hsts.match(/max-age=(\d+)/i);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      if (maxAge < HSTS_MIN_SECONDS) {
        findings.push({
          level: 'info', code: 'hsts-short',
          message: `HSTS present mais duree courte (max-age=${maxAge}s, ~${Math.round(maxAge / 86400)}j) — ${HSTS_MIN_SECONDS} (6 mois) est une valeur de depart courante avant d'envisager includeSubDomains/preload.`,
        });
      } else {
        findings.push({ level: 'ok', code: 'hsts-ok', message: `HSTS present avec une duree raisonnable (${hsts}).` });
      }
    }
  }

  const proxyServer = proxyHeaders['server'];
  if (proxyServer && /\d/.test(proxyServer)) {
    findings.push({
      level: 'warning', code: 'server-version-leak',
      message: `En-tete Server expose une version precise ("${proxyServer}") — server_tokens off; masque au moins le numero de version nginx.`,
    });
  } else if (proxyServer) {
    findings.push({ level: 'ok', code: 'server-generic', message: `En-tete Server generique ("${proxyServer}"), pas de version exposee.` });
  }

  if (proxyHeaders['x-powered-by']) {
    findings.push({
      level: 'warning', code: 'x-powered-by-leak',
      message: `En-tete X-Powered-By expose la techno backend ("${proxyHeaders['x-powered-by']}") — proxy_hide_header X-Powered-By; le masque cote nginx.`,
    });
  }

  for (const rule of MISSING_HEADER_RULES) {
    if (!proxyHeaders[rule.key]) findings.push({ level: 'info', code: rule.code, message: rule.message });
  }

  // Le meme en-tete Server, avec un numero de version, present a l identique
  // des deux cotes : le proxy ne fait que relayer ce que le backend envoie
  // (proxy_pass_header ou simplement rien qui le bloque), plutot que de le
  // masquer ou le remplacer lui-meme.
  if (backendOk && backendHeaders['server'] && proxyServer === backendHeaders['server'] && /\d/.test(backendHeaders['server'])) {
    findings.push({
      level: 'warning', code: 'backend-header-passthrough',
      message: `Le proxy laisse passer tel quel l'en-tete Server du backend ("${backendHeaders['server']}") — proxy_hide_header Server; (et au besoin add_header Server ...; pour le remplacer) evite d'exposer la stack backend.`,
    });
  }

  return findings;
}

module.exports = { auditServerBlock, auditVhosts, auditHeaderProbe };
