'use strict';
/**
 * Changelog distant — bouton "Changelog" sur la page Systeme (v12.41.0,
 * retour utilisateur). Le fichier CHANGELOG.md n'est PAS embarque dans
 * l'image : il vit dans le depot, a cote du code, et change a chaque
 * version. Ce module va le chercher a l'URL configuree (CHANGELOG_URL,
 * injectable via ARG/ENV — voir Dockerfile — meme mecanisme que
 * DASHBOARD_VERSION_URL/SYNC_REF_URL dans lib/config.js), avec un court
 * cache en memoire pour ne pas retelecharger le fichier a chaque ouverture
 * de la fenetre par chaque utilisateur connecte.
 */
const https = require('https');
const http  = require('http');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { CHANGELOG_URL } = cfg;

const MAX_BYTES     = 2 * 1024 * 1024; // 2 Mo — tres large pour un CHANGELOG.md, evite un telechargement sans limite
const CACHE_TTL_MS  = 5 * 60 * 1000;
let cache = null; // { content, fetchedAt } | { error, fetchedAt }

/**
 * Meme discipline que fetchVersionFile() dans server.js : `depth` borne le
 * nombre de redirections suivies, pour ne jamais suivre une chaine de
 * redirects indefiniment (ou en boucle) sur une URL fournie par
 * l'operateur.
 */
function fetchChangelog(fileUrl, depth = 5) {
  return new Promise((resolve) => {
    if (!fileUrl || depth <= 0) return resolve({ error: 'URL invalide ou trop de redirections' });
    let u;
    try { u = new URL(fileUrl); } catch { return resolve({ error: 'URL invalide' }); }
    const proto = u.protocol === 'http:' ? http : https;
    const req = proto.request(u, { method: 'GET', headers: { 'User-Agent': cfg.HTTP_USER_AGENT }, timeout: 8000 }, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        res.resume();
        let next;
        try { next = new URL(res.headers.location, u).toString(); } catch { return resolve({ error: 'Redirection invalide' }); }
        return resolve(fetchChangelog(next, depth - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return resolve({ error: `HTTP ${res.statusCode}` }); }
      let data = '';
      let bytes = 0;
      res.on('data', (d) => {
        bytes += d.length;
        if (bytes > MAX_BYTES) { req.destroy(); return resolve({ error: 'Fichier trop volumineux' }); }
        data += d;
      });
      res.on('end', () => resolve({ content: data }));
      res.on('error', (e) => resolve({ error: e.message }));
    });
    req.on('error', (e) => resolve({ error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'Delai depasse' }); });
    req.end();
  });
}

async function getChangelog() {
  if (cache && (Date.now() - cache.fetchedAt) < CACHE_TTL_MS) return cache;
  const result = await fetchChangelog(CHANGELOG_URL);
  cache = { ...result, fetchedAt: Date.now() };
  return cache;
}

function register(router) {
  // VIEW_CONFIGS (pas ADMIN) : un changelog est une information utile a tous
  // les roles connectes, pas seulement aux admins — meme raisonnement que
  // /api/menu-visibility.
  router.get('/api/changelog', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    if (!CHANGELOG_URL) return send(res, 200, { configured: false });
    const forceRefresh = url.searchParams.get('refresh') === '1';
    if (forceRefresh) cache = null;
    const result = await getChangelog();
    if (result.error) return send(res, 200, { configured: true, error: result.error });
    return send(res, 200, { configured: true, content: result.content });
  });
}

module.exports = { register, fetchChangelog, getChangelog };
