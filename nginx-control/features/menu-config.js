'use strict';
/**
 * Visibilite des elements de menu optionnels (WAF, GoDNS, ...) — voir
 * lib/menu-visibility.js pour la logique de resolution (env > menu.yml >
 * defaut) et config/menu.yml pour les reglages persistes.
 *
 * Une seule route, en lecture seule, exposee a TOUS les roles authentifies
 * (permission VIEW_CONFIGS, que viewer/operator/admin possedent tous les
 * trois) — contrairement a features/system-info.js (ADMIN uniquement, la
 * configuration complete du dashboard), un viewer a lui aussi besoin de
 * savoir quels elements du menu afficher ou masquer au chargement de la
 * page (public/index.html#checkOptionalFeatures()).
 */
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const { resolveMenuVisibility } = require('../lib/menu-visibility');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;

function register(router) {
  router.get('/api/menu-visibility', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      const visibility = await resolveMenuVisibility();
      return send(res, 200, visibility);
    } catch (e) {
      return httpLib.serverError(res, e);
    }
  });
}

module.exports = { register };
