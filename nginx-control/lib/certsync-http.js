'use strict';
/**
 * Client HTTPS vers un autre Nginx Control (synchro de certificats, v12.59.0).
 *
 * HTTPS obligatoire, mais le certificat de l'autre nœud n'est pas forcément
 * valide (auto-signé, autorité privée). Quatre modes de vérification :
 *   verify    : chaîne et nom vérifiés avec les autorités système (certificat « normal »)
 *   ca        : chaîne et nom vérifiés avec le(s) certificat(s) de VOTRE autorité (PEM collé)
 *   pin       : le certificat présenté doit avoir exactement cette empreinte SHA-256 —
 *               adapté à l'auto-signé ; la vérification a lieu AVANT l'envoi de la moindre
 *               requête (donc jamais de jeton envoyé à un serveur non reconnu)
 *   insecure  : aucune vérification (déconseillé : n'importe qui peut se faire passer pour l'autre nœud)
 * Les redirections ne sont jamais suivies ; réponse limitée à 8 Mo ; délai de 20 s.
 */
const https = require('https');
const tls = require('tls');
const cfg = require('./config');
const { normFingerprint } = require('./certsync-core');

const MAX_BODY = 8 * 1024 * 1024;
const TIMEOUT_MS = 20_000;

function hostPort(u) { return { host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || 443 }; }

/** Connexion TLS déjà vérifiée par empreinte (utilisée pour le mode « pin »). */
function connectPinned(u, pin) {
  return new Promise((resolve, reject) => {
    const { host, port } = hostPort(u);
    const sock = tls.connect({ host, port, servername: /^[\d.]+$|:/.test(host) ? undefined : host, rejectUnauthorized: false, timeout: TIMEOUT_MS });
    const fail = e => { sock.destroy(); reject(e); };
    sock.once('error', fail);
    sock.once('timeout', () => fail(new Error('délai dépassé')));
    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate();
      const fp = cert && cert.raw ? normFingerprint(cert.raw) : null;
      if (fp !== pin) return fail(new Error(`empreinte du certificat du serveur inattendue (${fp ? fp.slice(0, 16) + '…' : 'aucun certificat'}) — le serveur a changé ou n'est pas celui attendu`));
      sock.removeListener('error', fail);
      sock.setTimeout(0);
      resolve(sock);
    });
  });
}

/**
 * @param {{url:string, token:string, tls:{mode:string, ca?:string, pin?:string}}} remote
 * @returns {Promise<{status:number, json:any, text:string}>}
 */
async function request(remote, method, path, body) {
  const u = new URL(remote.url.replace(/\/+$/, '') + path);
  if (u.protocol !== 'https:') throw new Error('HTTPS obligatoire');
  const mode = (remote.tls && remote.tls.mode) || 'verify';
  const opts = {
    method, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || 443, path: u.pathname + u.search, timeout: TIMEOUT_MS,
    headers: { Authorization: `Bearer ${remote.token}`, Accept: 'application/json', 'User-Agent': cfg.HTTP_USER_AGENT },
  };
  if (mode === 'ca') opts.ca = remote.tls.ca;
  if (mode === 'insecure') opts.rejectUnauthorized = false;
  if (mode === 'pin') {
    const sock = await connectPinned(u, remote.tls.pin);
    opts.createConnection = () => sock;
    opts.agent = false;
    opts.rejectUnauthorized = false; // empreinte déjà vérifiée par connectPinned
  }
  let payload = null;
  if (body !== undefined) {
    payload = Buffer.from(JSON.stringify(body));
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['Content-Length'] = payload.length;
  }
  return new Promise((resolve, reject) => {
    const req = https.request(opts, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size > MAX_BODY) { req.destroy(new Error('réponse trop volumineuse')); return; } chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(text); } catch { /* non JSON */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('délai dépassé')));
    req.on('error', e => reject(new Error(explainTlsError(e))));
    if (payload) req.write(payload);
    req.end();
  });
}

function explainTlsError(e) {
  const c = e && e.code;
  if (c === 'DEPTH_ZERO_SELF_SIGNED_CERT' || c === 'SELF_SIGNED_CERT_IN_CHAIN') return 'certificat auto-signé non approuvé — utilisez le mode « empreinte » ou « autorité privée »';
  if (c === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || c === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY') return 'autorité du certificat inconnue — utilisez le mode « autorité privée » ou « empreinte »';
  if (c === 'ERR_TLS_CERT_ALTNAME_INVALID') return 'le nom dans l\'URL ne correspond pas au certificat du serveur';
  if (c === 'CERT_HAS_EXPIRED') return 'certificat du serveur expiré';
  if (c === 'ECONNREFUSED') return 'connexion refusée';
  if (c === 'ENOTFOUND') return 'nom d\'hôte introuvable';
  return e && e.message ? e.message : String(e);
}

/**
 * Récupère le certificat présenté par un serveur HTTPS SANS le valider (aide au
 * mode « empreinte » : l'opérateur compare l'empreinte avec celle de l'autre
 * nœud avant de l'enregistrer). Aucun jeton n'est envoyé.
 */
function probeServerCert(urlStr) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error('URL invalide')); }
    if (u.protocol !== 'https:') return reject(new Error('HTTPS obligatoire'));
    const { host, port } = hostPort(u);
    const sock = tls.connect({ host, port, servername: /^[\d.]+$|:/.test(host) ? undefined : host, rejectUnauthorized: false, timeout: 10_000 });
    const fail = e => { sock.destroy(); reject(new Error(explainTlsError(e))); };
    sock.once('error', fail);
    sock.once('timeout', () => fail(new Error('délai dépassé')));
    sock.once('secureConnect', () => {
      const c = sock.getPeerCertificate();
      const out = {
        fingerprint256: c && c.raw ? normFingerprint(c.raw) : null,
        subject: c && c.subject ? Object.values(c.subject).join(', ') : '', issuer: c && c.issuer ? Object.values(c.issuer).join(', ') : '',
        validTo: c && c.valid_to || '', trusted: sock.authorized === true, trustError: sock.authorizationError ? String(sock.authorizationError) : null,
      };
      sock.end();
      resolve(out);
    });
  });
}

module.exports = { request, probeServerCert, connectPinned, explainTlsError };
