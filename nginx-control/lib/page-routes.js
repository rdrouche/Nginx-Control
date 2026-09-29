'use strict';
/**
 * Table unique page interne (`data-page` dans public/index.html) <-> slug
 * d'URL public — source de vérité unique pour le deep-linking (v12.31.0,
 * voir CHANGELOG et claude/design-routing-urls.md dans le Projet).
 *
 * server.js l'utilise pour la liste blanche des routes "virtuelles" de la
 * SPA (un F5/lien direct sur `/map` doit servir le même index.html que `/`,
 * jamais un 404) et l'injecte telle quelle dans index.html
 * (`window.PAGE_ROUTES`, même mécanisme que `window.BRANDING`) pour que le
 * JS côté client n'en garde jamais une deuxième copie qui pourrait diverger.
 *
 * Par défaut le slug est identique au `data-page` (déjà en kebab-case) —
 * seuls les deux noms ci-dessous ont été jugés plus parlants côté URL
 * publique que le nom interne historique. Liste blanche délibérée plutôt
 * qu'une règle générale ("tout ce qui n'est pas /api/") : une URL mal tapée
 * doit continuer à faire un 404 propre, jamais afficher silencieusement la
 * page Vue d'ensemble en masquant un lien cassé.
 */
const PAGE_SLUG_OVERRIDES = {
  geomap: 'map',
  logs: 'live-logs',
};

// Liste exhaustive des `data-page` valides de public/index.html — tenue à
// jour manuellement. Une page ajoutée côté UI sans être ajoutée ici reste
// utilisable par simple clic (le routage n'intervient pas dans le clic
// lui-même), elle n'obtient juste pas encore de route serveur ni d'URL
// canonique directe tant qu'elle n'est pas listée ici.
const PAGES = [
  'overview', 'zones', 'upstreams', 'configs', 'ssl', 'logviewer', 'sync',
  'vhostgen', 'diagnostic', 'monitoring', 'graph', 'deploy', 'backups',
  'control', 'cache', 'logs', 'notif-history', 'crowdsec', 'blocklists',
  'analyzer', 'waf', 'geomap', 'digest', 'goaccess', 'api', 'webhooks',
  'godns', 'certbot', 'docker-autoconfig', 'agents', 'geoipupdate',
  'error-pages', 'notify', 'scheduler', 'config-editor', 'system-info',
  'admin',
];

const PAGE_TO_SLUG = {};
const SLUG_TO_PAGE = {};
for (const page of PAGES) {
  const slug = PAGE_SLUG_OVERRIDES[page] || page;
  PAGE_TO_SLUG[page] = slug;
  SLUG_TO_PAGE[slug] = page;
}

module.exports = { PAGES, PAGE_SLUG_OVERRIDES, PAGE_TO_SLUG, SLUG_TO_PAGE };
