'use strict';
/**
 * Registry of the dashboard's own configuration — every setting lib/config.js
 * resolves from the environment, described alongside its default and how to
 * override it, for the "Système" page (features/system-info.js).
 *
 * This is documentation-as-data on purpose: one array here, instead of a
 * paragraph in README.md that silently drifts from lib/config.js as settings
 * are added. Adding a new env var to lib/config.js and to this file is one
 * extra step, checked by test/system-info.test.js (every key exported by
 * lib/config.js must appear in exactly one entry here, or be explicitly
 * listed as intentionally omitted).
 *
 * Security: this file only ever describes and formats values already
 * resolved by lib/config.js — it never reads process.env directly, and any
 * entry flagged `sensitive: true` has its actual value replaced by a
 * configured/not-configured boolean before it ever reaches formatEntries()'s
 * caller (features/system-info.js, itself gated to admins only).
 */

const cfg = require('./config');
const { getContainerId, dockerCall } = require('./docker');
const { resolveMenuVisibility } = require('./menu-visibility');
const { resolveFlag } = require('./feature-flags');
const { getGitCfg } = require('./git');

/** One row of the "override" column — env is the overwhelmingly common case. */
const ENV = (name) => ({ kind: 'env', var: name });
const YAML = (file) => ({ kind: 'yaml', file });
const FIXED = () => ({ kind: 'fixed' });
// v12.39.0 : a setting that genuinely accepts both an env var AND a YAML
// file, env winning — see lib/menu-visibility.js. Every other entry above
// only ever has one override source, hence ENV()/YAML() staying separate.
const ENV_OR_YAML = (name, file) => ({ kind: 'env_yaml', var: name, file });

const ENTRIES = [
  // ─── General ───────────────────────────────────────────────────────────
  { key: 'VERSION', category: 'Général', value: cfg.VERSION, default: null, override: FIXED(),
    description: "Version du dashboard, fixee dans lib/config.js a chaque livraison — voir CHANGELOG.md. Ne se configure pas." },
  { key: 'PORT', category: 'Général', value: cfg.PORT, default: 3000, override: ENV('PORT'),
    description: "Port HTTP interne ecoute par le dashboard. Change rarement — le port publie sur l hote se regle plutot via le mapping `ports:` de docker-compose.yml." },
  { key: 'NGINX_CONTAINER', category: 'Général', value: cfg.NGINX_CONTAINER, default: 'nginx', override: ENV('NGINX_CONTAINER'),
    description: "Nom (ou ID) du conteneur nginx a piloter (nginx -t / -s reload, stats, sondes) — doit correspondre au `container_name:` (ou nom de service) declare dans docker-compose.yml." },
  { key: 'NGINX_IMAGE', category: 'Général', value: cfg.NGINX_IMAGE, default: '', override: ENV('NGINX_IMAGE'), autoDetect: true,
    description: "Image utilisee pour le conteneur de test ephemere (validation d une config avant deploiement). Laisse vide, elle est detectee automatiquement depuis l image du conteneur nginx en cours d execution — la surcharger n a d interet que pour tester avec une image differente de celle en prod." },
  { key: 'NGINX_NETWORK', category: 'Général', value: cfg.NGINX_NETWORK, default: 'nginx-net', override: ENV('NGINX_NETWORK'),
    description: "Reseau Docker partage utilise pour le conteneur de test ephemere et pour la resolution DNS entre conteneurs — doit correspondre au reseau reellement utilise par la stack (voir `docker network ls`)." },
  { key: 'NGINX_VTS_URL', category: 'Général', value: cfg.NGINX_VTS_URL, default: 'http://nginx:8080/status.json', override: ENV('NGINX_VTS_URL'),
    description: "Endpoint du module VTS (statistiques par vhost) expose par nginx, lu par la page Overview/Virtual Hosts." },
  { key: 'NGINX_CONF_FILE', category: 'Général', value: cfg.NGINX_CONF_FILE, default: '/etc/nginx/nginx.conf', override: ENV('NGINX_CONF_FILE'),
    description: "Chemin du fichier nginx.conf principal, tel que vu DANS le conteneur nginx (utilise pour `nginx -t`)." },
  { key: 'NOTIF_POLL_INTERVAL_SEC', category: 'Général', value: cfg.NOTIF_POLL_INTERVAL_SEC, default: 5, override: ENV('NOTIF_POLL_INTERVAL_SEC'),
    description: "Frequence (secondes) a laquelle le navigateur interroge GET /api/notifications pour le centre de notification (v12.21.2). Decouple du cycle de rafraichissement du statut/des metriques. Plancher impose a 2s." },

  // ─── Deploy / edit behaviour ───────────────────────────────────────────
  { key: 'ALLOW_EDIT', category: 'Comportement de déploiement', value: cfg.ALLOW_EDIT, default: false, override: ENV('ALLOW_EDIT'),
    description: "Autorise l edition en ligne des fichiers de configuration nginx depuis le dashboard (test + backup + prod automatiques a chaque sauvegarde). Desactive par defaut — activer volontairement, avec le role admin uniquement pouvant y toucher." },
  { key: 'ALLOW_CREATE', category: 'Comportement de déploiement', value: cfg.ALLOW_CREATE, default: false, override: ENV('ALLOW_CREATE'),
    description: "Autorise la creation de nouveaux fichiers (site/conf/snippet/stream) depuis le dashboard. Ignore si Git est configure (GIT_REPO_URL) : les nouveaux fichiers sont alors attendus depuis le depot de reference, pour que les repertoires geres restent reproductibles depuis lui." },
  { key: 'DEPLOY_SYNC_SSL', category: 'Comportement de déploiement', value: cfg.DEPLOY_SYNC_SSL, default: true, override: ENV('DEPLOY_SYNC_SSL'),
    description: "Inclut le repertoire ssl/ (certificats fournis par l operateur) dans le pipeline de deploiement Git. Sans effet sur certs/ (Let's Encrypt), jamais synchronise quelle que soit cette valeur." },

  // ─── Security & sessions ───────────────────────────────────────────────
  { key: 'SESSION_SECRET', category: 'Sécurité & sessions', sensitive: true, value: !!process.env.SESSION_SECRET, default: false, override: ENV('SESSION_SECRET'),
    description: "Cle de signature des sessions. Non definie manuellement, une valeur aleatoire est generee UNE SEULE FOIS puis persistee dans config/.generated-secrets.json (v12.32.0) — les sessions survivent donc aux redemarrages meme sans y toucher. La fixer soi-meme (ex. `openssl rand -hex 32`) reste possible et prend toujours le pas sur la valeur generee." },
  { key: 'SESSION_TTL_HOURS', category: 'Sécurité & sessions', value: cfg.SESSION_TTL_MS / 3600_000, default: 8, override: ENV('SESSION_TTL_HOURS'),
    description: "Duree de vie glissante d une session (renouvelee tant que l utilisateur est actif)." },
  { key: 'SESSION_MAX_HOURS', category: 'Sécurité & sessions', value: cfg.SESSION_ABSOLUTE_MAX_MS / 3600_000, default: 24, override: ENV('SESSION_MAX_HOURS'),
    description: "Duree de vie ABSOLUE d une session, meme active sans interruption — borne la fenetre d exploitation d un cookie vole." },
  // value: cfg.API_TOKEN_ENABLED ici n'est qu'un defaut au chargement du module —
  // buildSystemInfo() le recalcule a chaque requete via cfg.apiTokenActive()
  // (v12.32.0) pour refleter un jeton genere depuis l'interface sans redemarrage.
  { key: 'API_TOKEN', category: 'Sécurité & sessions', sensitive: true, value: cfg.API_TOKEN_ENABLED, default: false, override: ENV('API_TOKEN'),
    description: "Jeton pour l authentification API par `Authorization: Bearer ...` (en plus de la session par cookie). Reste DESACTIVE tant qu il vaut la valeur par defaut ou fait moins de 16 caracteres — jamais actif par accident. Peut aussi etre genere depuis cette page (bouton dedie) : dans ce cas seule son empreinte est conservee, la valeur n est affichee qu une seule fois." },
  // Meme remarque : recalcule a chaque requete via cfg.isWebhookSecretConfigured().
  { key: 'WEBHOOK_SECRET', category: 'Sécurité & sessions', sensitive: true, value: cfg.WEBHOOK_SECRET_SET, default: false, override: ENV('WEBHOOK_SECRET'),
    description: "Secret de signature des webhooks sortants. Considere non configure tant qu il vaut la valeur par defaut. Peut aussi etre genere depuis cette page (bouton dedie) — affiche une seule fois, a reporter cote destinataire du webhook." },
  { key: 'LOGIN_MAX_ATTEMPTS', category: 'Sécurité & sessions', value: cfg.LOGIN_MAX_ATTEMPTS, default: 10, override: ENV('LOGIN_MAX_ATTEMPTS'),
    description: "Nombre de tentatives de connexion echouees toleraees avant blocage temporaire (anti brute-force sur /auth/login)." },
  { key: 'LOGIN_WINDOW_MIN', category: 'Sécurité & sessions', value: cfg.LOGIN_WINDOW_MS / 60_000, default: 15, override: ENV('LOGIN_WINDOW_MIN'),
    description: "Fenetre glissante (minutes) sur laquelle les tentatives echouees sont comptees." },
  { key: 'LOGIN_LOCKOUT_MIN', category: 'Sécurité & sessions', value: cfg.LOGIN_LOCKOUT_MS / 60_000, default: 15, override: ENV('LOGIN_LOCKOUT_MIN'),
    description: "Duree du blocage (minutes) une fois le seuil de tentatives atteint." },
  { key: 'CORS_ORIGIN', category: 'Sécurité & sessions', value: cfg.CORS_ORIGIN, default: '', override: ENV('CORS_ORIGIN'),
    description: "Origine autorisee en cross-origin pour l API. Vide (recommande) = same-origin uniquement ; un joker elargirait inutilement la surface d attaque." },
  { key: 'TRUSTED_PROXIES', category: 'Sécurité & sessions', value: cfg.TRUSTED_PROXIES.join(', '),
    default: '127.0.0.1, ::1, 172.16.0.0/12, 192.168.0.0/16, 10.0.0.0/8', override: ENV('TRUSTED_PROXIES'),
    description: "IP/CIDR autorisees a fixer X-Forwarded-For (v12.21.1). Seule une requete dont l adresse socket figure ici peut faire confiance a cet en-tete pour le rate-limit de connexion et les logs d audit ; sinon l adresse TCP directe est utilisee, quoi que le client envoie." },

  // ─── Git & backups ─────────────────────────────────────────────────────
  // Bug fixe (retour utilisateur, v12.49.3) : ces six lignes affichaient
  // cfg.GIT_* — la valeur resolue UNE FOIS au demarrage depuis l environnement
  // seulement — alors que lib/git.js#getGitCfg() permet de configurer repoUrl/
  // branch/backupBranch/token/userName/userEmail depuis git.yml (page
  // Configuration), surcharge par-dessus l env, RELUE A CHAQUE APPEL. Un
  // operateur qui configurait Git uniquement via git.yml (sans jamais toucher
  // GIT_REPO_URL/GIT_TOKEN dans .env) voyait donc la page Systeme afficher ces
  // deux champs comme non configures, alors que le deploiement Git
  // fonctionnait bel et bien (chaque feature appelle getGitCfg(), jamais
  // cfg.GIT_* directement). Valeur/override recalcules a chaque requete dans
  // buildSystemInfo(), meme registre ENV_OR_YAML que WAF_MENU plus haut.
  { key: 'GIT_REPO_URL', category: 'Déploiement Git', value: cfg.GIT_REPO_URL, default: '', override: ENV_OR_YAML('GIT_REPO_URL', 'git.yml'),
    description: "URL du depot Git de reference. Vide = deploiement Git desactive (edition directe des fichiers montes selon ALLOW_EDIT/ALLOW_CREATE)." },
  { key: 'GIT_BRANCH', category: 'Déploiement Git', value: cfg.GIT_BRANCH, default: 'main', override: ENV_OR_YAML('GIT_BRANCH', 'git.yml'),
    description: "Branche source du deploiement." },
  { key: 'GIT_BACKUP_BRANCH', category: 'Déploiement Git', value: cfg.GIT_BACKUP_BRANCH, default: 'backup', override: ENV_OR_YAML('GIT_BACKUP_BRANCH', 'git.yml'),
    description: "Branche ou l etat precedent est pousse avant chaque deploiement, pour pouvoir revenir en arriere." },
  { key: 'GIT_TOKEN', category: 'Déploiement Git', sensitive: true, value: !!cfg.GIT_TOKEN, default: false, override: ENV_OR_YAML('GIT_TOKEN', 'git.yml'),
    description: "Jeton d authentification HTTPS vers le depot (alternative a GIT_SSH_KEY)." },
  { key: 'GIT_SSH_KEY', category: 'Déploiement Git', sensitive: true, value: !!cfg.GIT_SSH_KEY, default: false, override: ENV('GIT_SSH_KEY'),
    description: "Cle privee SSH vers le depot (alternative a GIT_TOKEN). Reste env-only : c est un chemin DANS ce conteneur (bind-mount), pas un reglage de comportement — jamais surcharge par git.yml (voir getGitCfg())." },
  { key: 'GIT_USER_NAME', category: 'Déploiement Git', value: cfg.GIT_USER_NAME, default: 'Nginx Dashboard', override: ENV_OR_YAML('GIT_USER_NAME', 'git.yml'),
    description: "Identite Git (auteur des commits) utilisee par le dashboard." },
  { key: 'GIT_USER_EMAIL', category: 'Déploiement Git', value: cfg.GIT_USER_EMAIL, default: 'dashboard@localhost', override: ENV_OR_YAML('GIT_USER_EMAIL', 'git.yml'),
    description: "Email Git associe aux commits du dashboard." },
  { key: 'BACKUP_KEEP', category: 'Déploiement Git', value: cfg.BACKUP_KEEP, default: 20, override: ENV('BACKUP_KEEP'),
    description: "Nombre de sauvegardes ZIP locales conservees avant rotation (la plus ancienne est supprimee)." },

  // ─── Docker ─────────────────────────────────────────────────────────────
  { key: 'DOCKER_SOCKET', category: 'Docker', value: cfg.DOCKER_SOCKET, default: '/var/run/docker.sock', override: ENV('DOCKER_SOCKET'),
    description: "Chemin du socket Docker monte dans le conteneur, utilise pour piloter nginx et les conteneurs geres (certbot, geoipupdate, error-pages, analyzer, GoAccess)." },

  // ─── Nginx-managed directories (as seen from this container) ──────────
  { key: 'DIR_SITES', category: 'Répertoires nginx', value: cfg.DIR_SITES, default: '/nginx/sites', override: ENV('DIR_SITES'), path: true },
  { key: 'DIR_CONF', category: 'Répertoires nginx', value: cfg.DIR_CONF, default: '/nginx/conf', override: ENV('DIR_CONF'), path: true },
  { key: 'DIR_SNIPPETS', category: 'Répertoires nginx', value: cfg.DIR_SNIPPETS, default: '/nginx/snippets', override: ENV('DIR_SNIPPETS'), path: true },
  { key: 'DIR_STREAMS', category: 'Répertoires nginx', value: cfg.DIR_STREAMS, default: '/nginx/streams', override: ENV('DIR_STREAMS'), path: true },
  { key: 'DIR_SSL', category: 'Répertoires nginx', value: cfg.DIR_SSL, default: '/nginx/ssl', override: ENV('DIR_SSL'), path: true },
  { key: 'DIR_CERTS', category: 'Répertoires nginx', value: cfg.DIR_CERTS, default: '/nginx/certs', override: ENV('DIR_CERTS'), path: true },
  { key: 'DIR_LOGS', category: 'Répertoires nginx', value: cfg.DIR_LOGS, default: '/nginx/logs', override: ENV('DIR_LOGS'), path: true },
  { key: 'DIR_CACHE', category: 'Répertoires nginx', value: cfg.DIR_CACHE, default: '', override: ENV('DIR_CACHE'), path: true,
    description: "Repertoire du cache nginx (pour le bouton \"vider le cache\"). Vide = fonctionnalite inactive." },
  { key: 'DIR_BACKUPS', category: 'Répertoires nginx', value: cfg.DIR_BACKUPS, default: '/nginx/backups', override: ENV('DIR_BACKUPS'), path: true },
  { key: 'DIR_GIT_WORK', category: 'Répertoires nginx', value: cfg.DIR_GIT_WORK, default: '/git-work', override: ENV('DIR_GIT_WORK'), path: true },
  { key: 'DIR_GOACCESS', category: 'Répertoires nginx', value: cfg.DIR_GOACCESS, default: '/nginx/goaccess', override: ENV('DIR_GOACCESS'), path: true },
  { key: 'DIR_GEOIP', category: 'Répertoires nginx', value: cfg.DIR_GEOIP, default: '/geoip', override: ENV('DIR_GEOIP'), path: true },
  { key: 'HOST_LOGS', category: 'Répertoires nginx', value: cfg.HOST_LOGS, default: '(= DIR_LOGS)', override: ENV('HOST_LOGS'), path: true,
    description: "Chemin sur l HOTE (pas dans ce conteneur) pour les bind-mounts crees via le socket Docker — Docker resout les sources de bind-mount cote hote, un chemin qui n existe que dans ce conteneur monterait un repertoire vide." },
  { key: 'HOST_GOACCESS', category: 'Répertoires nginx', value: cfg.HOST_GOACCESS, default: '(= DIR_GOACCESS)', override: ENV('HOST_GOACCESS'), path: true,
    description: "Meme principe que HOST_LOGS, pour les conteneurs GoAccess crees a la demande." },

  // ─── GeoIP ──────────────────────────────────────────────────────────────
  { key: 'GEOIP_CITY_DB', category: 'GeoIP', value: cfg.GEOIP_CITY_DB, default: '/geoip/GeoLite2-City.mmdb', override: ENV('GEOIP_CITY_DB'), path: true },
  { key: 'GEOIP_COUNTRY_DB', category: 'GeoIP', value: cfg.GEOIP_COUNTRY_DB, default: '/geoip/GeoLite2-Country.mmdb', override: ENV('GEOIP_COUNTRY_DB'), path: true },
  { key: 'GEOIP_ASN_DB', category: 'GeoIP', value: cfg.GEOIP_ASN_DB, default: '/geoip/GeoLite2-ASN.mmdb', override: ENV('GEOIP_ASN_DB'), path: true },

  // ─── CrowdSec ───────────────────────────────────────────────────────────
  { key: 'CROWDSEC_URL', category: 'CrowdSec', value: cfg.CROWDSEC_URL, default: '', override: ENV('CROWDSEC_URL'),
    description: "URL de l API locale (LAPI) du bouncer CrowdSec. Vide = integration CrowdSec desactivee." },
  { key: 'CROWDSEC_API_KEY', category: 'CrowdSec', sensitive: true, value: !!cfg.CROWDSEC_API_KEY, default: false, override: ENV('CROWDSEC_API_KEY'),
    description: "Cle bouncer (lecture seule : decisions/alertes)." },
  { key: 'CROWDSEC_MACHINE_ID', category: 'CrowdSec', value: cfg.CROWDSEC_MACHINE_ID, default: '', override: ENV('CROWDSEC_MACHINE_ID'),
    description: "Identifiant machine (cscli machines add), pour les operations d ecriture (ban/unban/allowlists) — separe volontairement de la cle bouncer en lecture seule." },
  { key: 'CROWDSEC_MACHINE_PASSWORD', category: 'CrowdSec', sensitive: true, value: !!cfg.CROWDSEC_MACHINE_PASSWORD, default: false, override: ENV('CROWDSEC_MACHINE_PASSWORD'),
    description: "Mot de passe associe a CROWDSEC_MACHINE_ID." },
  { key: 'CROWDSEC_PROMETHEUS_URL', category: 'CrowdSec', value: cfg.CROWDSEC_PROM_URL, default: '', override: ENV('CROWDSEC_PROMETHEUS_URL'),
    description: "Endpoint Prometheus du moteur CrowdSec (metriques locales, recommande en plus de la LAPI)." },
  { key: 'CROWDSEC_LOCAL_ONLY', category: 'CrowdSec', value: cfg.CROWDSEC_LOCAL_ONLY, default: false, override: ENV('CROWDSEC_LOCAL_ONLY'),
    description: "N affiche que les decisions locales, masque les decisions issues de la Central API (liste communautaire)." },

  // ─── GoAccess ───────────────────────────────────────────────────────────
  { key: 'GOACCESS_IMAGE', category: 'GoAccess', value: cfg.GOACCESS_IMAGE, default: 'allinurl/goaccess:latest', override: ENV('GOACCESS_IMAGE') },
  { key: 'GOACCESS_LOG_FORMAT', category: 'GoAccess', value: cfg.GOACCESS_LOG_FORMAT, default: 'COMBINED', override: ENV('GOACCESS_LOG_FORMAT') },
  { key: 'GOACCESS_REFRESH', category: 'GoAccess', value: cfg.GOACCESS_REFRESH_SEC, default: 30, override: ENV('GOACCESS_REFRESH'),
    description: "Intervalle (secondes) de regeneration du rapport HTML GoAccess." },

  // ─── Sync & version checks ──────────────────────────────────────────────
  { key: 'SYNC_REF_URL', category: 'Sync & mises à jour', value: cfg.SYNC_REF_URL, default: '', override: ENV('SYNC_REF_URL'),
    description: "URL du depot de reference pour la synchronisation de snippets/conf. Vide = page Sync desactivee." },
  { key: 'SYNC_REF_PATH_PREFIX', category: 'Sync & mises à jour', value: cfg.SYNC_REF_PATH_PREFIX, default: '', override: ENV('SYNC_REF_PATH_PREFIX'),
    description: "Sous-dossier du depot de reference si conf/sites/snippets/streams n y sont pas a la racine." },
  { key: 'DASHBOARD_VERSION_URL', category: 'Sync & mises à jour', value: cfg.DASHBOARD_VERSION_URL, default: '', override: ENV('DASHBOARD_VERSION_URL'),
    description: "URL consultee pour verifier si une nouvelle version du dashboard est disponible. Vide = verification desactivee." },
  { key: 'NGINX_VERSION_URL', category: 'Sync & mises à jour', value: cfg.NGINX_VERSION_URL, default: '', override: ENV('NGINX_VERSION_URL'),
    description: "Meme principe pour l image nginx." },
  { key: 'CHANGELOG_URL', category: 'Sync & mises à jour', value: cfg.CHANGELOG_URL, default: '', override: ENV('CHANGELOG_URL'),
    description: "URL brute (raw) du CHANGELOG.md du projet, utilisee par le bouton \"Changelog\" de cette page. Vide = bouton masque (voir Dockerfile pour l injecter au build)." },

  // ─── Alertes (message important, v12.45.0, retour utilisateur) ─────────
  // ALERTING_ENABLE recalcule a chaque requete dans buildSystemInfo() (comme
  // les lignes *_MENU ci-dessus), avec le mode et la source (env/yaml/
  // defaut) reellement resolus par lib/feature-flags.js.
  { key: 'ALERTING_URL', category: 'Alertes', value: cfg.ALERTING_URL, default: '', override: ENV('ALERTING_URL'),
    description: "URL brute d un fichier Markdown de messages importants (voir features/alerting.js). Vide = aucune alerte possible, quel que soit ALERTING_ENABLE (voir Dockerfile pour l injecter au build)." },
  { key: 'ALERTING_ENABLE', category: 'Alertes', value: false, default: false, override: YAML('features.yml'),
    description: "Active/desactive la verification periodique d ALERTING_URL, independamment de sa valeur — utile pour desactiver la fonctionnalite sans toucher a une URL injectee au build. Priorite ENV (ALERTING_ENABLE) > config/features.yml (alerting_enable) > defaut (desactive)." },
  { key: 'ALERTING_POLL_INTERVAL_MIN', category: 'Alertes', value: cfg.ALERTING_POLL_INTERVAL_MIN, default: 60, override: ENV('ALERTING_POLL_INTERVAL_MIN'),
    description: "Intervalle (minutes) entre deux verifications d ALERTING_URL par le planificateur serveur. Minimum impose : 5. Le bouton \"Rafraichir maintenant\" (modale Alertes) force une verification immediate sans attendre cet intervalle." },
  { key: 'ANALYZER_DEFAULT_IMAGE', category: 'Sync & mises à jour', value: cfg.ANALYZER_DEFAULT_IMAGE, default: 'forge.rdr-it.com/dockerfiles/nginx-analyzer:latest', override: ENV('ANALYZER_DEFAULT_IMAGE'),
    description: "Image par defaut du conteneur analyzer quand config/analyzer.yml ne definit pas container_image. Injectee au build (--build-arg) pour rester surchargeable a l execution comme les autres variables." },

  // ─── Retention ──────────────────────────────────────────────────────────
  { key: 'EVENTS_RETENTION_DAYS', category: 'Rétention', value: cfg.EVENTS_RETENTION_DAYS, default: 30, override: ENV('EVENTS_RETENTION_DAYS'),
    description: "Duree de conservation du journal d evenements (page Evenements)." },
  { key: 'MONITOR_RETENTION_DAYS', category: 'Rétention', value: cfg.MONITOR_RETENTION_DAYS, default: 30, override: ENV('MONITOR_RETENTION_DAYS'),
    description: "Duree de conservation de l historique du monitoring continu (checks + incidents clos — un incident encore ouvert n est jamais purge)." },
  { key: 'NOTIF_CENTER_RETENTION_DAYS', category: 'Rétention', value: cfg.NOTIF_CENTER_RETENTION_DAYS, default: 90, override: ENV('NOTIF_CENTER_RETENTION_DAYS'),
    description: "Duree de conservation des notifications du centre de notification (cloche d en-tete), lues ou non." },

  // ─── Branding ───────────────────────────────────────────────────────────
  { key: 'BRANDING_SITE', category: 'Branding', value: cfg.BRANDING.site, default: '', override: ENV('BRANDING_SITE') },
  { key: 'BRANDING_REPO', category: 'Branding', value: cfg.BRANDING.repo, default: '', override: ENV('BRANDING_REPO') },
  { key: 'BRANDING_DOC', category: 'Branding', value: cfg.BRANDING.doc, default: '', override: ENV('BRANDING_DOC'),
    description: "Lien \"Documentation\" affiche dans le pied de menu. Ces reglages de marque (voir aussi BRANDING_KOFI, BRANDING_*_LABEL) sont surcharges au moment du BUILD (docker-compose.yml, section `build.args`), pas seulement a l execution." },

  // ─── Menu (v12.39.0, retour utilisateur) ───────────────────────────────
  // Valeurs par defaut ici ('auto'/'show') ; buildSystemInfo() les recalcule
  // a chaque requete avec le mode et la source (env/yaml/defaut) reellement
  // resolus par lib/menu-visibility.js, pour ne jamais afficher un etat perime.
  { key: 'WAF_MENU', category: 'Menu', value: 'auto', default: 'auto', override: ENV_OR_YAML('MENU_WAF', 'menu.yml'),
    description: "Visibilite du menu WAF. `auto` (defaut) ne l affiche que si l image nginx en cours d execution se termine par -waf ou -coraza ; `show`/`hide` forcent l affichage independamment de l image. Valeurs acceptees : auto, show, hide." },
  { key: 'GODNS_MENU', category: 'Menu', value: 'show', default: 'show', override: ENV_OR_YAML('MENU_GODNS', 'menu.yml'),
    description: "Visibilite du menu GoDNS — utile pour le masquer completement si le DNS dynamique n est jamais utilise sur ce deploiement. Valeurs acceptees : show, hide (pas de mode auto, rien dans une image de conteneur n indique un usage de DNS dynamique)." },
  // v12.41.0 (retour utilisateur) : quatre menus optionnels de plus, meme
  // registre ENV_OR_YAML que WAF_MENU/GODNS_MENU ci-dessus.
  { key: 'API_MENU', category: 'Menu', value: 'auto', default: 'auto', override: ENV_OR_YAML('MENU_API', 'menu.yml'),
    description: "Visibilite du menu REST API. `auto` (defaut) ne l affiche que si API_TOKEN est configure (sinon la page n a rien a montrer) ; `show`/`hide` forcent l affichage." },
  { key: 'WEBHOOKS_MENU', category: 'Menu', value: 'auto', default: 'auto', override: ENV_OR_YAML('MENU_WEBHOOKS', 'menu.yml'),
    description: "Visibilite du menu Webhooks. `auto` (defaut) ne l affiche que si WEBHOOK_SECRET est configure ; `show`/`hide` forcent l affichage." },
  { key: 'DOCKER_AUTOCONFIG_MENU', category: 'Menu', value: 'auto', default: 'auto', override: ENV_OR_YAML('MENU_DOCKER_AUTOCONFIG', 'menu.yml'),
    description: "Visibilite du menu Auto-config Docker. `auto` (defaut) reflete `enable:` dans docker-autoconfig.yml (la fonctionnalite tourne deja en arriere-plan quel que soit ce reglage d affichage — desactiver la fonctionnalite se fait dans ce fichier, pas ici) ; `show`/`hide` forcent l affichage independamment." },
  { key: 'AGENTS_MENU', category: 'Menu', value: 'auto', default: 'auto', override: ENV_OR_YAML('MENU_AGENTS', 'menu.yml'),
    description: "Visibilite du menu Hotes distants. `auto` (defaut) reflete `enable:` dans agents.yml ; `show`/`hide` forcent l affichage independamment." },

  // ─── GoDNS (v12.39.0, retour utilisateur) ──────────────────────────────
  // SECURITE : verification multi-source de l IP publique — voir
  // lib/ip-check.js et le commentaire de GODNS_IP_CHECK dans lib/config.js.
  { key: 'GODNS_IP_CHECK', category: 'GoDNS', value: cfg.GODNS_IP_CHECK, default: true, override: ENV('GODNS_IP_CHECK'),
    description: "Verifie l IP publique rapportee par GoDNS contre le consensus de plusieurs services independants, et affiche un avertissement en cas de desaccord (par exemple : un ip_url mal configure, derriere un CDN, qui renvoie l IP du CDN au lieu de l IP reelle). Aucun appel externe supplementaire si desactive." },
  { key: 'GODNS_IP_CHECK_URLS', category: 'GoDNS', value: cfg.GODNS_IP_CHECK_URLS.join(', '), default: 'https://api.ipify.org, https://icanhazip.com, https://ifconfig.me/ip', override: ENV('GODNS_IP_CHECK_URLS'),
    description: "Services \"what is my IP\" interroges pour GODNS_IP_CHECK (liste separee par des virgules). Choisir des services qui ne sont pas eux-memes derriere un CDN/reverse-proxy, sans quoi ils souffrent du meme probleme qu ils sont censes detecter." },
];

/**
 * Where a key is stored in CONFIG_DIR (users.yml, smtp.yml, ...) rather than
 * an env var — informational only, these already have their own dedicated
 * page in the dashboard (Notifications, Certbot, GeoIP, ...), so they are
 * intentionally not duplicated as full entries above.
 */
const YAML_BACKED_SETTINGS = [
  { file: 'users.yml', purpose: 'Comptes et roles — page Users' },
  { file: 'smtp.yml', purpose: 'Serveur SMTP pour les notifications par email' },
  { file: 'notifications.yml', purpose: 'Canaux de notification — page Notifications' },
  { file: 'scheduler.yml', purpose: 'Taches planifiees — page Scheduler' },
  { file: 'certbot.yml', purpose: "Conteneur Certbot gere par le dashboard — page SSL/Certbot" },
  { file: 'certbot-dns.yml', purpose: "Defi DNS-01 (fournisseur, identifiants) — page SSL/Certbot" },
  { file: 'godns.yml', purpose: 'DNS dynamique — page GoDNS' },
  { file: 'geoipupdate.yml', purpose: 'Conteneur geoipupdate gere par le dashboard — page GeoIP' },
  { file: 'error-pages.yml', purpose: "Conteneur de pages d'erreur gere par le dashboard — page Pages d'erreur" },
  { file: 'crowdsec.yml', purpose: 'Reglages complementaires CrowdSec' },
  { file: 'git.yml', purpose: 'Configuration Git alternative geree depuis le dashboard' },
  { file: 'analyzer.yml', purpose: "Conteneur de l'analyseur de journaux — page Analyse" },
  { file: 'blocklists.yml', purpose: 'Sources de blocklists IP externes (URL, cron, action) — page Blocklists IP' },
  { file: 'deploy-tokens.yml', purpose: 'Jetons scopes pour declencher un deploiement Git depuis un pipeline CI/CD (Forgejo/GitHub/GitLab)' },
  { file: 'docker-autoconfig.yml', purpose: 'Auto-config Docker par labels (approbation, motifs autorises, intervalle de sondage) — page Auto-config Docker' },
  { file: 'menu.yml', purpose: 'Visibilite des elements de menu optionnels (WAF, GoDNS, REST API, Webhooks, Auto-config Docker, Hotes distants) — voir aussi MENU_WAF/MENU_GODNS/MENU_API/MENU_WEBHOOKS/MENU_DOCKER_AUTOCONFIG/MENU_AGENTS' },
  { file: 'features.yml', purpose: 'Interrupteurs marche/arret transversaux (alerting_enable pour le moment) — voir aussi ALERTING_ENABLE' },
];

/** Every key lib/config.js exports that ENTRIES intentionally doesn't list as its own row (aliases, computed/derived, or purely internal). */
const INTENTIONALLY_OMITTED = new Set([
  // Shown converted to hours/minutes instead (SESSION_TTL_HOURS, SESSION_MAX_HOURS,
  // LOGIN_WINDOW_MIN, LOGIN_LOCKOUT_MIN).
  'SESSION_TTL_MS', 'SESSION_ABSOLUTE_MAX_MS',
  'LOGIN_WINDOW_MS', 'LOGIN_LOCKOUT_MS',
  // Shown as the "sensitive" rows for their own settings instead.
  'API_TOKEN_ENABLED', 'WEBHOOK_SECRET_SET',
  // Shown under its env-var name instead (the two ended up diverging historically).
  'CROWDSEC_PROM_URL',
  // Shown under its env-var name instead.
  'GOACCESS_REFRESH_SEC',
  // Internal file-layout plumbing (where users.yml/config files live), not an operational toggle.
  'USERS_FILE', 'CONFIG_DIR', 'GENERATED_SECRETS_FILE',
  // Functions, not settings — lib/config.js's generated-secret helpers
  // (v12.32.0). API_TOKEN/WEBHOOK_SECRET rows above already reflect their
  // live state via apiTokenActive()/isWebhookSecretConfigured().
  'readGeneratedSecrets', 'persistGeneratedSecret', 'clearGeneratedSecret',
  'apiTokenActive', 'verifyApiToken', 'getWebhookSecret', 'isWebhookSecretConfigured',
  'SMTP_CONFIG_FILE', 'NOTIF_CONFIG_FILE', 'SCHED_CONFIG_FILE', 'CERTBOT_CONFIG_FILE',
  'CERTBOT_DNS_CONFIG_FILE', 'GODNS_CONFIG_FILE', 'GEOIPUPDATE_CONFIG_FILE', 'ERROR_PAGES_CONFIG_FILE',
  // MENU_CONFIG_FILE (v12.39.0) : chemin derive de CONFIG_DIR, comme les
  // autres *_CONFIG_FILE ci-dessus. Les reglages qu il contient (visibilite
  // WAF/GoDNS) sont documentes juste en dessous, comme des entrees a part
  // entiere (ENV(MENU_WAF)/ENV(MENU_GODNS)) — voir lib/menu-visibility.js.
  'MENU_CONFIG_FILE',
  // FEATURES_CONFIG_FILE (v12.45.0) : meme raisonnement que MENU_CONFIG_FILE
  // ci-dessus — le reglage qu il contient (ALERTING_ENABLE) est documente
  // comme une entree a part entiere dans la categorie "Alertes".
  'FEATURES_CONFIG_FILE',
  'CROWDSEC_CONFIG_FILE', 'GOACCESS_CONFIG_FILE', 'GIT_CONFIG_FILE', 'BLOCKLIST_CONFIG_FILE',
  'DEPLOY_TOKENS_FILE', 'DOCKER_AUTOCONFIG_CONFIG_FILE', 'AGENTS_CONFIG_FILE',
  'EVENTS_DB_PATH', 'MONITOR_DB_PATH', 'NOTIF_CENTER_DB_PATH',
  // Derived from the GoAccess directory row already listed above.
  'DIR_GOACCESS_DB', 'DIR_GOACCESS_CONF',
  // Internal constant, not configurable.
  'GOACCESS_CONTAINER_PREFIX',
  // Fixed list, not configurable.
  'SYNC_REF_SECTIONS',
  // Expanded field-by-field above instead (BRANDING_SITE, BRANDING_REPO, BRANDING_DOC).
  'BRANDING',
  // Internal file-type sets, not configurable.
  'CONF_EXTS', 'CERT_EXTS',
]);

/** The live (auto-detected when unset) nginx image, for the NGINX_IMAGE row. */
async function detectNginxImage() {
  if (cfg.NGINX_IMAGE) return { value: cfg.NGINX_IMAGE, autoDetected: false };
  try {
    const id = await getContainerId();
    const r = await dockerCall('GET', `/containers/${encodeURIComponent(id)}/json`);
    if (r.status === 200 && r.body?.Config?.Image) return { value: r.body.Config.Image, autoDetected: true };
    return { value: null, autoDetected: true, error: 'Conteneur nginx introuvable' };
  } catch (e) {
    return { value: null, autoDetected: true, error: e.message };
  }
}

/** Build the full, request-ready payload: entries grouped by category, with the live NGINX_IMAGE value resolved. */
async function buildSystemInfo() {
  const nginxImage = await detectNginxImage();
  // Reutilise l'image deja detectee ci-dessus plutot que de la re-detecter
  // (resolveMenuVisibility() ferait sinon un second appel Docker) — meme
  // detection, une seule fois par requete.
  const menuVisibility = await resolveMenuVisibility(nginxImage.value);
  const categories = new Map();
  for (const entry of ENTRIES) {
    const row = { ...entry };
    if (row.key === 'NGINX_IMAGE') {
      row.value = nginxImage.value;
      row.autoDetected = nginxImage.autoDetected;
      if (nginxImage.error) row.detectError = nginxImage.error;
    }
    // v12.32.0 : recalcule a chaque requete (pas au chargement du module) pour
    // refleter un jeton/secret genere depuis l'interface sans redemarrage.
    if (row.key === 'API_TOKEN') row.value = cfg.apiTokenActive();
    if (row.key === 'WEBHOOK_SECRET') row.value = cfg.isWebhookSecretConfigured();
    // Bug fixe (retour utilisateur, v12.49.3) : meme raisonnement — getGitCfg()
    // fusionne git.yml par-dessus l'env et doit etre relu a chaque requete
    // (un operateur peut modifier git.yml depuis la page Configuration sans
    // redemarrer le dashboard), jamais fige a la valeur cfg.GIT_* resolue une
    // seule fois au demarrage.
    if (row.key === 'GIT_REPO_URL') row.value = getGitCfg().repoUrl;
    if (row.key === 'GIT_BRANCH') row.value = getGitCfg().branch;
    if (row.key === 'GIT_BACKUP_BRANCH') row.value = getGitCfg().backupBranch;
    if (row.key === 'GIT_TOKEN') row.value = !!getGitCfg().token;
    if (row.key === 'GIT_USER_NAME') row.value = getGitCfg().userName;
    if (row.key === 'GIT_USER_EMAIL') row.value = getGitCfg().userEmail;
    if (row.key === 'WAF_MENU') {
      row.value = `${menuVisibility.waf.mode} (${menuVisibility.waf.source}) -> ${menuVisibility.waf.visible ? 'affiche' : 'masque'}`;
      if (menuVisibility.waf.mode === 'auto') {
        row.value += menuVisibility.waf.detectedImage
          ? ` [image detectee: ${menuVisibility.waf.detectedImage}]`
          : ' [image nginx non detectee]';
      }
    }
    if (row.key === 'GODNS_MENU') {
      row.value = `${menuVisibility.godns.mode} (${menuVisibility.godns.source}) -> ${menuVisibility.godns.visible ? 'affiche' : 'masque'}`;
    }
    if (row.key === 'API_MENU') {
      row.value = `${menuVisibility.api.mode} (${menuVisibility.api.source}) -> ${menuVisibility.api.visible ? 'affiche' : 'masque'}`;
    }
    if (row.key === 'WEBHOOKS_MENU') {
      row.value = `${menuVisibility.webhooks.mode} (${menuVisibility.webhooks.source}) -> ${menuVisibility.webhooks.visible ? 'affiche' : 'masque'}`;
    }
    if (row.key === 'DOCKER_AUTOCONFIG_MENU') {
      row.value = `${menuVisibility.dockerAutoconfig.mode} (${menuVisibility.dockerAutoconfig.source}) -> ${menuVisibility.dockerAutoconfig.visible ? 'affiche' : 'masque'}`;
    }
    if (row.key === 'AGENTS_MENU') {
      row.value = `${menuVisibility.agents.mode} (${menuVisibility.agents.source}) -> ${menuVisibility.agents.visible ? 'affiche' : 'masque'}`;
    }
    if (row.key === 'ALERTING_ENABLE') {
      const flag = resolveFlag('alerting');
      row.value = `${flag.enabled ? 'true' : 'false'} (${flag.source})`;
    }
    if (!categories.has(row.category)) categories.set(row.category, []);
    categories.get(row.category).push(row);
  }
  return {
    categories: [...categories.entries()].map(([name, entries]) => ({ name, entries })),
    yamlBackedSettings: YAML_BACKED_SETTINGS,
  };
}

module.exports = { ENTRIES, YAML_BACKED_SETTINGS, INTENTIONALLY_OMITTED, detectNginxImage, buildSystemInfo };
