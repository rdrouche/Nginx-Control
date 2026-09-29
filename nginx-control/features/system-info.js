'use strict';
/**
 * GET /api/system-info — le propre registre de configuration du dashboard
 * (lib/system-info.js), pour la page "Système" : chaque parametre lu par
 * lib/config.js, sa valeur courante, sa valeur par defaut, comment le
 * surcharger (env/yaml/docker), et une explication. Admin uniquement — meme
 * si aucune valeur brute de secret n y transite jamais (lib/system-info.js
 * ne renvoie qu un booleen "configure" pour les champs `sensitive: true`),
 * ce sont malgre tout des details d infrastructure interne (chemins,
 * conteneurs, reseaux) qui n ont rien a faire devant un simple viewer.
 */

const crypto = require('crypto');

const cfg = require('../lib/config');
const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const events = require('../lib/events');
const { buildSystemInfo } = require('../lib/system-info');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { logEvent } = events;

function register(router) {
  router.get('/api/system-info', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const info = await buildSystemInfo();
    return send(res, 200, info);
  });

  // v12.32.0 (demande utilisateur) : API_TOKEN/WEBHOOK_SECRET generables
  // depuis l'interface plutot que seulement via .env, sur le meme principe
  // qu'un mot de passe ou un jeton d'agent : affiches UNE SEULE FOIS au
  // moment de la generation, jamais revelables ensuite. Traitement different
  // pour les deux car leur usage differe (voir lib/config.js) :
  //  - API_TOKEN n'est jamais RE-LU par le dashboard, seulement VERIFIE face
  //    a ce qu'un appelant presente -> seule son empreinte (scrypt, meme
  //    format que les mots de passe) est persistee.
  //  - WEBHOOK_SECRET est au contraire ENVOYE par le dashboard a chaque
  //    webhook sortant -> il doit rester lisible, donc persiste en clair
  //    (fichier 0600 comme SESSION_SECRET), jamais reaffiche apres coup.
  router.post('/api/system-info/generate-api-token', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const token = crypto.randomBytes(32).toString('hex');
    cfg.persistGeneratedSecret('apiTokenHash', auth.hashPassword(token).digest);
    logEvent('security.api_token_generated', { by: session.username }, 'api');
    return send(res, 200, { token });
  });
  router.post('/api/system-info/revoke-api-token', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    cfg.clearGeneratedSecret('apiTokenHash');
    logEvent('security.api_token_revoked', { by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });
  router.post('/api/system-info/generate-webhook-secret', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const secret = crypto.randomBytes(32).toString('hex');
    cfg.persistGeneratedSecret('webhookSecret', secret);
    logEvent('security.webhook_secret_generated', { by: session.username }, 'api');
    return send(res, 200, { secret });
  });
  router.post('/api/system-info/revoke-webhook-secret', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    cfg.clearGeneratedSecret('webhookSecret');
    logEvent('security.webhook_secret_revoked', { by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });
}

module.exports = { register };
