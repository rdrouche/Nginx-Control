'use strict';
/**
 * X.509 certificate reading.
 *
 * Foundation rather than a feature: both the SSL browser and certbot's
 * conflict detection need to know which domains a certificate covers, and
 * features never import each other.
 *
 * Two readers coexist. parseCert() uses Node's crypto.X509Certificate and is
 * the accurate one. parseCertSANs() walks the DER looking for domain-shaped
 * strings; it predates the switch and is kept because it tolerates files the
 * strict parser rejects, which matters when scanning a directory that may hold
 * a half-written certbot output.
 *
 * Both fail to null rather than throwing: an unreadable certificate must not
 * take a page down.
 */

const fs     = require('fs');
const crypto = require('crypto');
const path = require('path');
const cfg  = require('./config');
const { safeReadDir, safeReadFile, safeStat } = require('./fs-tree');

const DIR_SSL   = cfg.DIR_SSL;
const DIR_CERTS = cfg.DIR_CERTS;
const CERT_EXTS = cfg.CERT_EXTS;

/**
 * Seuil d'avertissement adapte a la duree de vie REELLE du certificat, pas
 * un nombre de jours fige.
 *
 * Signalement reel : certains fournisseurs ACME delivrent des certificats
 * valides seulement ~30 jours (au lieu des 90 jours habituels de Let's
 * Encrypt). Avec un seuil fixe "avertir a 30 jours", un tel certificat
 * bascule en "bientot expire" des sa delivrance — le seuil equivaut alors
 * a 100% de sa duree de vie au lieu d'une vraie marge d'anticipation.
 *
 * Regle : le seuil configure (`configuredDays`) reste la valeur par defaut
 * pour les certificats a duree de vie "normale" (90 jours et plus, ce qui
 * couvre Let's Encrypt), mais ne peut jamais depasser le tiers de la duree
 * de vie totale du certificat — c'est la meme proportion que certbot
 * utilise lui-meme pour decider quand renouveler un certificat Let's
 * Encrypt (renouvellement a J-30 sur 90 jours de validite = 1/3).
 */
function adaptiveThreshold(totalLifetimeDays, configuredDays, { minDays = 3 } = {}) {
  if (!totalLifetimeDays || totalLifetimeDays <= 0) return configuredDays;
  return Math.max(minDays, Math.min(configuredDays, Math.ceil(totalLifetimeDays / 3)));
}

function parseCert(pem) {
  try {
    const cert      = new crypto.X509Certificate(pem);
    const now       = Date.now();
    const notAfter  = new Date(cert.validTo);
    const notBefore = new Date(cert.validFrom);
    const daysLeft  = Math.floor((notAfter - now) / 86400000);
    const totalDays = Math.round((notAfter - notBefore) / 86400000);
    const warnDays  = adaptiveThreshold(totalDays, 30);
    let sans = [];
    try { sans = (cert.subjectAltName || '').split(',').map(s => s.trim().replace(/^DNS:|^IP Address:/i, '')).filter(Boolean); } catch {}
    return {
      subject: cert.subject, issuer: cert.issuer,
      validFrom: notBefore.toISOString(), validTo: notAfter.toISOString(), totalDays,
      daysLeft, expired: daysLeft < 0, warning: daysLeft >= 0 && daysLeft < warnDays,
      fingerprint: cert.fingerprint, fingerprint256: cert.fingerprint256,
      serialNumber: cert.serialNumber, sans, keyType: cert.publicKey?.asymmetricKeyType || 'unknown',
    };
  } catch(e) { return { error: e.message }; }
}

/** Parse minimal X.509 cert info from PEM — CN + SANs + expiry (no deps) */
function parseCertSANs(pem) {
  try {
    // Decode base64 DER
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const der  = Buffer.from(b64, 'base64');

    // Simple ASN.1 scanner — find SAN extension OID 2.5.29.17
    // and CN OID 2.5.4.3, and validity timestamps
    const domains = new Set();
    let notBefore = null, notAfter  = null;

    // Walk all printable/UTF8 strings looking for domain-like values
    let i = 0;
    while (i < der.length - 4) {
      const tag  = der[i];
      // PrintableString(0x13), UTF8String(0x0c), IA5String(0x16) — these
      // catch a Subject CN. Fix v12.21.2 (found while testing audit finding
      // DAC-04, not itself in the report): a SAN dNSName entry — the ONLY
      // place a multi-domain or wildcard certificate's actual names live —
      // is encoded as the context-specific IMPLICIT tag [2] (0x82), never as
      // one of the three generic string types above. This scanner never
      // recognized 0x82 at all, so any name that only exists as a SAN entry
      // (every name on a real Let's Encrypt certificate besides whichever
      // one — if any — happens to also be echoed in the Subject CN) was
      // silently invisible to checkDomainConflict(): `auto`/`certbot_*`
      // modes could treat an already-covered domain as uncovered (spurious
      // re-issuance, hitting ACME rate limits) or an actually-uncovered one
      // as covered (a vhost renders `ssl_certificate` pointing at a
      // certificate that doesn't actually cover it, a browser TLS error).
      if (tag === 0x13 || tag === 0x0c || tag === 0x16 || tag === 0x82) {
        const len = der[i+1] < 0x80 ? der[i+1] : null;
        if (len && i + 2 + len <= der.length) {
          const str = der.slice(i+2, i+2+len).toString('utf8');
          if (/^[\w*][\w\-.*]+\.[a-z]{2,}$/.test(str)) domains.add(str.toLowerCase());
        }
      }
      // UTCTime(0x17) — validity dates : le couple (notBefore, notAfter) se
      // suit toujours immediatement dans la sequence Validity de X.509,
      // notBefore capture desormais aussi (utilise pour la duree de vie
      // totale du certificat, cf. adaptiveThreshold() ci-dessus).
      if (tag === 0x17 && notAfter === null) {
        const len = der[i+1];
        if (len === 13 && i + 2 + 13 <= der.length) {
          const parseUtcTime = (s) => {
            const yr = parseInt(s.slice(0,2));
            const fullYr = yr >= 50 ? 1900+yr : 2000+yr;
            return new Date(`${fullYr}-${s.slice(2,4)}-${s.slice(4,6)}T${s.slice(6,8)}:${s.slice(8,10)}:${s.slice(10,12)}Z`);
          };
          notBefore = parseUtcTime(der.slice(i+2, i+15).toString('ascii'));
          const j = i + 2 + 13;
          if (j + 1 < der.length && der[j] === 0x17 && der[j+1] === 13) {
            notAfter = parseUtcTime(der.slice(j+2, j+15).toString('ascii'));
            i = j + 15;
            continue;
          }
        }
      }
      i++;
    }
    return { domains: [...domains], notBefore, notAfter };
  } catch { return { domains: [], notBefore: null, notAfter: null }; }
}

function scanCertsDir(certsDir) {
  const liveDir = path.join(certsDir, 'live');
  return safeReadDir(liveDir)
    .filter(d => d !== 'README')
    .map(domain => {
      const certFile = path.join(liveDir, domain, 'cert.pem');
      const stat = safeStat(certFile);
      if (!stat) return null;
      const pem = safeReadFile(certFile);
      if (!pem) return null;
      return { name: `${domain}/cert.pem`, domain, path: certFile, size: stat.size, mtime: stat.mtime.toISOString(), source: 'certbot', ...parseCert(pem) };
    }).filter(Boolean);
}

function scanSslDir(dir) {
  return safeReadDir(dir)
    .filter(name => CERT_EXTS.has(path.extname(name).toLowerCase()))
    .map(name => {
      const fullPath = path.join(dir, name);
      const stat = safeStat(fullPath);
      if (!stat || stat.isDirectory()) return null;
      const pem = safeReadFile(fullPath);
      if (!pem) return null;
      return { name, path: fullPath, size: stat.size, mtime: stat.mtime.toISOString(), source: 'ssl', ...parseCert(pem) };
    }).filter(Boolean);
}

function getAllCertificates() {
  const all     = [...scanSslDir(DIR_SSL), ...scanCertsDir(DIR_CERTS)];
  const summary = { total: all.length, expired: all.filter(c => c.expired).length, warning: all.filter(c => c.warning && !c.expired).length, ok: all.filter(c => !c.expired && !c.warning).length };
  return { certificates: all, summary };
}

/** List all existing certs in DIR_CERTS — returns array with domains + expiry */
function listExistingCerts() {
  if (!DIR_CERTS || !fs.existsSync(DIR_CERTS)) return [];
  const livePath = path.join(DIR_CERTS, 'live');
  if (!fs.existsSync(livePath)) return [];
  const certs = [];
  for (const entry of fs.readdirSync(livePath, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === 'README') continue;
    const certFile = path.join(livePath, entry.name, 'cert.pem');
    if (!fs.existsSync(certFile)) continue;
    try {
      const pem  = fs.readFileSync(certFile, 'utf8');
      const info = parseCertSANs(pem);
      const totalDays = (info.notBefore && info.notAfter)
        ? Math.round((info.notAfter - info.notBefore) / 86400000) : null;
      certs.push({ name: entry.name, certFile, ...info, totalDays,
        expired: info.notAfter ? info.notAfter < new Date() : null,
        daysLeft: info.notAfter ? Math.floor((info.notAfter - Date.now()) / 86400000) : null,
      });
    } catch {}
  }
  return certs;
}

/**
 * Whether `domain` is a name a wildcard SAN `*.base` covers, under nginx's
 * own (and the CA/Browser Forum's) rule: a wildcard covers exactly ONE
 * label deeper than its base — never the base itself, never two levels down.
 */
function wildcardCovers(base, domain) {
  if (!domain.endsWith('.' + base)) return false;
  const remainder = domain.slice(0, domain.length - base.length - 1);
  return remainder.length > 0 && !remainder.includes('.');
}

/**
 * Check if a domain — or, when `opts.allNames` is given, EVERY one of a set
 * of server_names — is already covered by a single existing, non-expired
 * certificate (exact SAN or wildcard).
 *
 * Fix v12.21.2 (audit finding DAC-04):
 *  - a wildcard `*.example.com` used to be treated as covering `example.com`
 *    itself AND anything nested under it (`a.b.example.com`) — neither is
 *    true for a real wildcard certificate, so a vhost could be rendered with
 *    a `ssl_certificate` that the browser rejects with a name mismatch, or
 *    (the opposite failure) certbot could refuse to issue a certificate for
 *    a domain it wrongly believed was already covered.
 *  - the comparison was case-sensitive (a SAN is stored lower-cased by
 *    parseCertSANs()/parseCert(), but the domain being checked was not),
 *    so `App.example.com` never matched its own certificate.
 *  - an EXPIRED certificate was still considered a valid match.
 *  - only the first server_name of a multi-name vhost was ever checked
 *    (callers now pass `opts.allNames` for that; the default single-name
 *    behaviour is unchanged when omitted, for the existing single-domain
 *    call sites in features/certbot.js / features/certbot-dns.js).
 */
function checkDomainConflict(domain, opts = {}) {
  const target = String(domain || '').toLowerCase();
  const allNames = (opts.allNames && opts.allNames.length ? opts.allNames : [domain])
    .map(d => String(d || '').toLowerCase());
  const certs = listExistingCerts().filter(c => !c.expired);
  for (const cert of certs) {
    const domains = (cert.domains || []).map(d => String(d || '').toLowerCase());
    const covers = (name) => domains.some(d => d === name || (d.startsWith('*.') && wildcardCovers(d.slice(2), name)));
    if (allNames.every(covers)) {
      const exactMatch = domains.find(d => d === target);
      const match = exactMatch || domains.find(d => d.startsWith('*.') && wildcardCovers(d.slice(2), target)) || domains[0];
      return { conflict: true, cert: cert.name, match, type: exactMatch ? 'exact' : 'wildcard' };
    }
  }
  return { conflict: false };
}
module.exports = {
  parseCert, parseCertSANs, adaptiveThreshold,
  scanSslDir, scanCertsDir, getAllCertificates,
  listExistingCerts, checkDomainConflict,
};
