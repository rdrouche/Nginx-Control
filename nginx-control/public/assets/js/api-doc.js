// Extrait de public/index.html (voir CHANGELOG.md).

// ── API Doc ───────────────────────────────────────────────────────────────────
// v12.41.0 (retour utilisateur) : liste enormement etendue (19 -> ~130
// endpoints, groupes par categorie comme les sections du menu), filtre texte
// + categorie, bouton "Exemple" en modale, et tryEP() corrige pour les
// chemins avec parametre (":id") qui echouaient silencieusement (appelaient
// litteralement l URL avec ":id" dedans). Toujours maintenue a la main (pas
// d introspection des fichiers features/*.js) : une nouvelle route doit
// encore etre ajoutee ici pour apparaitre dans cette doc — voir la case
// "amelioration possible" dans le README pour ce que ferait une vraie
// introspection automatique.
// Chaque categorie porte une cle stable `catKey` (traduite via
// t('api.cat.'+catKey), voir fr.json/en.json) — `cat` (FR) reste le nom
// d affichage par defaut/repli. Chaque endpoint porte `d` (description FR)
// et `dEn` (description EN) : garder les deux versions cote a cote, au plus
// pres de la route elle-meme, plutot que dans des cles i18n separees —
// ~130 entrees deja tres repetitives, une cle par description doublerait
// le fichier fr.json/en.json pour un gain de lisibilite nul (voir
// apiDescFor() plus bas, seul point qui choisit entre les deux).
const ENDPOINT_GROUPS=[
  {cat:'Monitoring', catKey:'monitoring', items:[
    {m:'GET',p:'/status',d:'Résumé global nginx',dEn:'Global nginx summary'},
    {m:'GET',p:'/metrics',d:'VTS + historique métriques',dEn:'VTS + metrics history'},
    {m:'GET',p:'/metrics/rate',d:'Débit requêtes/s (fenêtre glissante)',dEn:'Requests/sec rate (sliding window)'},
    {m:'GET',p:'/zones',d:'Stats par virtual host',dEn:'Stats per virtual host'},
    {m:'GET',p:'/upstreams',d:'Backends upstream',dEn:'Upstream backends'},
    {m:'GET',p:'/nginx/stats',d:'Stats brutes du module stub_status/VTS',dEn:'Raw stats from the stub_status/VTS module'},
    {m:'GET',p:'/backends',d:'Résolution des cibles proxy_pass (diagnostic)',dEn:'Resolved proxy_pass targets (diagnostic)'},
    {m:'POST',p:'/backends/check',d:'Sonde live un backend {file,blockIndex}',dEn:'Live-probe a backend {file,blockIndex}'},
    {m:'GET',p:'/audit',d:'Audit statique de tous les vhosts (sécurité)',dEn:'Static security audit of all vhosts'},
    {m:'POST',p:'/audit/headers',d:'Analyse live des en-têtes HTTP {file,blockIndex}',dEn:'Live analysis of HTTP headers {file,blockIndex}'},
    {m:'GET',p:'/monitor',d:'État du monitoring continu (checks + incidents ouverts)',dEn:'Continuous monitoring state (checks + open incidents)'},
    {m:'GET',p:'/monitor/history',d:'Historique du monitoring (?days=N)',dEn:'Monitoring history (?days=N)'},
    {m:'POST',p:'/monitor/check-now',d:'Force un cycle de vérification immédiat',dEn:'Force an immediate check cycle'},
  ]},
  {cat:'Configuration', catKey:'configuration', items:[
    {m:'GET',p:'/configs',d:'Liste les fichiers de conf (?content=1 pour inclure le contenu)',dEn:'List config files (?content=1 to include content)'},
    {m:'GET',p:'/configs/file?path=…',d:'Lire un fichier de configuration',dEn:'Read a configuration file'},
    {m:'POST',p:'/configs/save',d:'Écrire un fichier de configuration existant {path,content}',dEn:'Write an existing configuration file {path,content}'},
    {m:'POST',p:'/configs/create',d:'Créer un nouveau fichier nginx {path,content}',dEn:'Create a new nginx file {path,content}'},
    {m:'GET',p:'/config-editor/files',d:'Liste des fichiers de fonctionnalités éditables',dEn:'List of editable feature config files'},
    {m:'GET',p:'/config-editor/file?key=…',d:'Lire un fichier de fonctionnalité (secrets masqués)',dEn:'Read a feature config file (secrets masked)'},
    {m:'POST',p:'/config-editor/file',d:'Écrire un fichier de fonctionnalité {key,content}',dEn:'Write a feature config file {key,content}'},
    {m:'GET',p:'/ssl',d:'Liste et parse tous les certificats SSL',dEn:'List and parse all SSL certificates'},
    {m:'GET',p:'/ssl/file?path=…',d:'Parser un certificat PEM',dEn:'Parse a PEM certificate'},
    {m:'GET',p:'/vhost/ssl-sources',d:'Sources SSL disponibles pour le générateur de vhost',dEn:'SSL sources available to the vhost generator'},
    {m:'POST',p:'/vhost/generate',d:'Générer un fichier vhost à partir d’un formulaire',dEn:'Generate a vhost file from a form'},
    {m:'GET',p:'/snippets/meta',d:'Métadonnées des snippets (nom, description, emplacement)',dEn:'Snippet metadata (name, description, location)'},
    {m:'GET',p:'/snippets/ssl',d:'Snippets SSL disponibles',dEn:'Available SSL snippets'},
    {m:'GET',p:'/sync/status',d:'État de la synchronisation des fichiers de référence',dEn:'Reference file sync status'},
    {m:'GET',p:'/sync/check',d:'Vérifie les écarts avec le dépôt de référence',dEn:'Check for drift against the reference repository'},
    {m:'POST',p:'/sync/preview',d:'Prévisualise les changements d’une synchronisation',dEn:'Preview a sync operation\'s changes'},
    {m:'POST',p:'/sync/apply',d:'Applique la synchronisation des fichiers de référence',dEn:'Apply the reference file sync'},
  ]},
  {cat:'Déploiement Git', catKey:'git', items:[
    {m:'GET',p:'/git/status',d:'État du dépôt (diff, hash, log)',dEn:'Repository status (diff, hash, log)'},
    {m:'GET',p:'/git/test-connection',d:'Vérifie l’accès au dépôt distant',dEn:'Check access to the remote repository'},
    {m:'POST',p:'/git/pull',d:'git pull — étape 1 de l’automatisation CI/CD',dEn:'git pull — step 1 of the CI/CD automation'},
    {m:'POST',p:'/git/test',d:'nginx -t sur un checkout éphémère — étape 2, renvoie 422 si invalide',dEn:'nginx -t on an ephemeral checkout — step 2, returns 422 if invalid'},
    {m:'POST',p:'/git/deploy',d:'Pipeline complet PULL → TEST → BACKUP → DEPLOY en un seul appel — voir l’exemple',
      dEn:'Full PULL → TEST → BACKUP → DEPLOY pipeline in one call — see the example',
      example:true},
    {m:'POST',p:'/git/init-backup-branch',d:'Initialise la branche de sauvegarde Git',dEn:'Initialize the Git backup branch'},
    {m:'GET',p:'/backups',d:'Liste les sauvegardes locales',dEn:'List local backups'},
    {m:'POST',p:'/backups',d:'Créer une sauvegarde manuelle {mode:"local"|"git"|"both"}',dEn:'Create a manual backup {mode:"local"|"git"|"both"}'},
    {m:'GET',p:'/backups/download?name=…',d:'Télécharger une sauvegarde (zip)',dEn:'Download a backup (zip)'},
    {m:'POST',p:'/backups/restore',d:'Restaurer une sauvegarde {name}',dEn:'Restore a backup {name}'},
    {m:'DELETE',p:'/backups/:name',d:'Supprimer une sauvegarde',dEn:'Delete a backup'},
  ]},
  {cat:'Contrôle', catKey:'control', items:[
    {m:'POST',p:'/nginx/test',d:'Exécute nginx -t',dEn:'Run nginx -t'},
    {m:'POST',p:'/nginx/test-verbose',d:'nginx -t avec sortie complète',dEn:'nginx -t with full output'},
    {m:'POST',p:'/nginx/reload',d:'Recharge nginx sans coupure',dEn:'Reload nginx without downtime'},
    {m:'POST',p:'/nginx/restart-container',d:'Redémarre le conteneur nginx',dEn:'Restart the nginx container'},
    {m:'GET',p:'/cache/zones',d:'Zones de cache proxy configurées',dEn:'Configured proxy cache zones'},
    {m:'POST',p:'/cache/clear',d:'Vide une zone de cache {zone}',dEn:'Clear a cache zone {zone}'},
  ]},
  {cat:'Logs', catKey:'logs', items:[
    {m:'GET',p:'/nginx-logs',d:'Liste les fichiers .log disponibles',dEn:'List available .log files'},
    {m:'GET',p:'/nginx-logs/tail?path=…&lines=N',d:'Dernières N lignes (JSON parsé)',dEn:'Last N lines (parsed as JSON)'},
    {m:'GET',p:'/nginx-logs/stream?path=…&token=…',d:'Stream SSE temps réel (EventSource)',dEn:'Real-time SSE stream (EventSource)'},
    {m:'GET',p:'/logs',d:'Journal des événements dashboard (?limit=N)',dEn:'Dashboard event log (?limit=N)'},
    {m:'POST',p:'/logs/clear',d:'Vide le journal des événements',dEn:'Clear the event log'},
    {m:'POST',p:'/events',d:'Injecter un événement custom {type,message}',dEn:'Inject a custom event {type,message}'},
  ]},
  {cat:'Notifications & Webhooks', catKey:'notifications', items:[
    {m:'GET',p:'/notifications',d:'Centre de notification (?unread=1)',dEn:'Notification center (?unread=1)'},
    {m:'GET',p:'/notifications/unread-count',d:'Nombre de notifications non lues',dEn:'Unread notification count'},
    {m:'POST',p:'/notifications/read-all',d:'Marquer toutes les notifications comme lues',dEn:'Mark all notifications as read'},
    {m:'POST',p:'/notifications/clear-read',d:'Purger les notifications déjà lues',dEn:'Purge already-read notifications'},
    {m:'POST',p:'/notifications/clear',d:'Purger toutes les notifications',dEn:'Purge all notifications'},
    {m:'GET',p:'/notify/config-files',d:'Lister smtp.yml/notifications.yml/scheduler.yml',dEn:'List smtp.yml/notifications.yml/scheduler.yml'},
    {m:'POST',p:'/notify/config-files',d:'Écrire un de ces fichiers {key,content}',dEn:'Write one of these files {key,content}'},
    {m:'GET',p:'/notify/smtp-config',d:'Config SMTP courante (secrets masqués)',dEn:'Current SMTP config (secrets masked)'},
    {m:'POST',p:'/notify/test',d:'Envoyer une notification de test',dEn:'Send a test notification'},
    {m:'GET',p:'/webhooks',d:'Lister les webhooks',dEn:'List webhooks'},
    {m:'POST',p:'/webhooks',d:'Créer un webhook {url,events,description}',dEn:'Create a webhook {url,events,description}',example:true},
    {m:'DELETE',p:'/webhooks/:id',d:'Supprimer un webhook',dEn:'Delete a webhook'},
    {m:'POST',p:'/webhooks/:id/test',d:'Tester un webhook',dEn:'Test a webhook'},
  ]},
  {cat:'CrowdSec', catKey:'crowdsec', items:[
    {m:'GET',p:'/crowdsec/status',d:'Statistiques CrowdSec (Prometheus ou LAPI selon config)',dEn:'CrowdSec statistics (Prometheus or LAPI depending on config)'},
    {m:'GET',p:'/crowdsec/alerts',d:'Alertes récentes (mode LAPI, nécessite un compte machine)',dEn:'Recent alerts (LAPI mode, requires a machine account)'},
    {m:'GET',p:'/crowdsec/decisions',d:'Décisions actives (bans)',dEn:'Active decisions (bans)'},
    {m:'GET',p:'/crowdsec/machine-status',d:'État de l’auth machine (LAPI)',dEn:'Machine auth status (LAPI)'},
    {m:'POST',p:'/crowdsec/ban',d:'Bannir une IP {ip,duration,reason}',dEn:'Ban an IP {ip,duration,reason}',example:true},
    {m:'POST',p:'/crowdsec/unban',d:'Débannir une IP {ip}',dEn:'Unban an IP {ip}'},
    {m:'GET',p:'/crowdsec/allowlists',d:'Listes blanches CrowdSec',dEn:'CrowdSec allowlists'},
    {m:'POST',p:'/crowdsec/allowlists',d:'Créer une liste blanche {name,description}',dEn:'Create an allowlist {name,description}'},
    {m:'POST',p:'/crowdsec/allowlists/items',d:'Ajouter une entrée {name,value}',dEn:'Add an entry {name,value}'},
    {m:'POST',p:'/crowdsec/allowlists/items/remove',d:'Retirer une entrée {name,value}',dEn:'Remove an entry {name,value}'},
    {m:'GET',p:'/crowdsec/allowlists/check?ip=…',d:'Vérifie si une IP est sur liste blanche',dEn:'Check whether an IP is allowlisted'},
  ]},
  {cat:'Blocklists IP', catKey:'blocklists', items:[
    {m:'GET',p:'/blocklists/status',d:'Sources configurées et leur dernier rafraîchissement',dEn:'Configured sources and their last refresh'},
    {m:'POST',p:'/blocklists/refresh',d:'Force le rafraîchissement de toutes les sources',dEn:'Force a refresh of all sources'},
    {m:'GET',p:'/blocklists/check?ip=…',d:'Vérifie si une IP est dans une blocklist',dEn:'Check whether an IP is on a blocklist'},
    {m:'GET',p:'/blocklists/hit-stats',d:'Statistiques de blocage (hits journalisés)',dEn:'Blocking stats (logged hits)'},
  ]},
  {cat:'Analyse & WAF', catKey:'analyzer', items:[
    {m:'GET',p:'/analyzer/status',d:'État du conteneur analyzer',dEn:'Analyzer container status'},
    {m:'GET',p:'/analyzer/config',d:'Configuration courante de l’analyzer',dEn:'Current analyzer configuration'},
    {m:'POST',p:'/analyzer/container/:action',d:'start|stop|restart|update le conteneur analyzer',dEn:'start|stop|restart|update the analyzer container'},
    {m:'POST',p:'/analyzer/image/update',d:'Met à jour l’image de l’analyzer',dEn:'Update the analyzer image'},
    {m:'GET',p:'/analyzer/alerts',d:'Alertes détectées (brute-force, scan, flood…)',dEn:'Detected alerts (brute-force, scan, flood…)'},
    {m:'POST',p:'/analyzer/alerts/ack',d:'Acquitter une alerte {id}',dEn:'Acknowledge an alert {id}'},
    {m:'POST',p:'/analyzer/alerts/ack-all',d:'Acquitter toutes les alertes',dEn:'Acknowledge all alerts'},
    {m:'POST',p:'/analyzer/alerts/clear',d:'Purger les alertes',dEn:'Purge alerts'},
    {m:'GET',p:'/analyzer/baseline',d:'Référence de trafic hebdomadaire (volumétrie)',dEn:'Weekly traffic baseline (volume)'},
    {m:'GET',p:'/analyzer/baseline/country',d:'Référence par pays d’origine',dEn:'Baseline by country of origin'},
    {m:'POST',p:'/analyzer/baseline/exclude',d:'Exclure un créneau de la référence',dEn:'Exclude a time slot from the baseline'},
    {m:'POST',p:'/analyzer/baseline/country/exclude',d:'Exclure un pays de la référence',dEn:'Exclude a country from the baseline'},
    {m:'GET',p:'/analyzer/rules',d:'Règles de détection intégrées',dEn:'Built-in detection rules'},
    {m:'POST',p:'/analyzer/rules/toggle',d:'Activer/désactiver une règle {id,enabled}',dEn:'Enable/disable a rule {id,enabled}'},
    {m:'GET',p:'/analyzer/rules/custom',d:'Règles personnalisées (YAML)',dEn:'Custom rules (YAML)'},
    {m:'POST',p:'/analyzer/rules/custom',d:'Remplacer les règles personnalisées {yaml}',dEn:'Replace the custom rules {yaml}'},
    {m:'GET',p:'/analyzer/exceptions',d:'Exceptions d’analyse par vhost',dEn:'Per-vhost analysis exceptions'},
    {m:'POST',p:'/analyzer/exceptions',d:'Ajouter une exception',dEn:'Add an exception'},
    {m:'POST',p:'/analyzer/exceptions/remove',d:'Retirer une exception',dEn:'Remove an exception'},
    {m:'GET',p:'/analyzer/waf/status',d:'État du WAF (ModSecurity/Coraza)',dEn:'WAF status (ModSecurity/Coraza)'},
    {m:'GET',p:'/analyzer/waf/events',d:'Événements WAF récents',dEn:'Recent WAF events'},
    {m:'GET',p:'/analyzer/waf/events/:id',d:'Détail d’un événement WAF',dEn:'Detail of a WAF event'},
    {m:'POST',p:'/analyzer/waf/clear',d:'Purger les événements WAF',dEn:'Purge WAF events'},
  ]},
  {cat:'Résumé, Carte & GoAccess', catKey:'digest', items:[
    {m:'GET',p:'/digest/latest',d:'Dernier résumé périodique généré',dEn:'Latest generated periodic digest'},
    {m:'GET',p:'/digest/history',d:'Historique des résumés',dEn:'Digest history'},
    {m:'GET',p:'/digest/:id',d:'Détail d’un résumé',dEn:'Detail of a digest'},
    {m:'POST',p:'/digest/generate',d:'Générer un résumé maintenant',dEn:'Generate a digest now'},
    {m:'POST',p:'/digest/remove',d:'Supprimer un résumé',dEn:'Delete a digest'},
    {m:'GET',p:'/goaccess/sources',d:'Sources de logs GoAccess disponibles',dEn:'Available GoAccess log sources'},
    {m:'POST',p:'/goaccess/start',d:'Démarrer un rapport GoAccess {sourceId}',dEn:'Start a GoAccess report {sourceId}'},
    {m:'POST',p:'/goaccess/stop',d:'Arrêter un rapport {sourceId}',dEn:'Stop a report {sourceId}'},
    {m:'GET',p:'/goaccess/report?sourceId=…',d:'Rapport HTML (iframe)',dEn:'HTML report (iframe)'},
    {m:'GET',p:'/goaccess/logs?sourceId=…',d:'Logs du conteneur GoAccess',dEn:'GoAccess container logs'},
    {m:'POST',p:'/goaccess/restart',d:'Redémarrer un rapport {sourceId}',dEn:'Restart a report {sourceId}'},
    {m:'POST',p:'/goaccess/recreate',d:'Recréer un conteneur GoAccess {sourceId}',dEn:'Recreate a GoAccess container {sourceId}'},
    {m:'GET',p:'/goaccess/image-status',d:'État de l’image GoAccess',dEn:'GoAccess image status'},
    {m:'POST',p:'/goaccess/pull-image',d:'Télécharger l’image GoAccess',dEn:'Pull the GoAccess image'},
  ]},
  {cat:'GoDNS', catKey:'godns', items:[
    {m:'GET',p:'/godns/config',d:'Configuration courante (container, port, web panel)',dEn:'Current configuration (container, port, web panel)'},
    {m:'GET',p:'/godns/status',d:'État du conteneur GoDNS',dEn:'GoDNS container status'},
    {m:'GET',p:'/godns/info',d:'IP publique, provider, domaines, vérification multi-source',dEn:'Public IP, provider, domains, multi-source check'},
    {m:'GET',p:'/godns/logs',d:'Logs bruts du conteneur',dEn:'Raw container logs'},
    {m:'GET',p:'/godns/config-file?reveal=…',d:'Lire godns.config.yaml/.json (secrets masqués)',dEn:'Read godns.config.yaml/.json (secrets masked)'},
    {m:'POST',p:'/godns/config-file',d:'Écrire godns.config.yaml/.json {content,format}',dEn:'Write godns.config.yaml/.json {content,format}'},
    {m:'POST',p:'/godns/container/start',d:'Démarrer le conteneur GoDNS',dEn:'Start the GoDNS container'},
    {m:'POST',p:'/godns/container/stop',d:'Arrêter le conteneur GoDNS',dEn:'Stop the GoDNS container'},
    {m:'POST',p:'/godns/container/restart',d:'Redémarrer le conteneur GoDNS',dEn:'Restart the GoDNS container'},
    {m:'POST',p:'/godns/container/update',d:'Mettre à jour l’image GoDNS',dEn:'Update the GoDNS image'},
  ]},
  {cat:'SSL / Certbot', catKey:'ssl', items:[
    {m:'GET',p:'/certbot/status',d:'État Certbot (défi HTTP-01)',dEn:'Certbot status (HTTP-01 challenge)'},
    {m:'GET',p:'/certbot/config',d:'Configuration courante',dEn:'Current configuration'},
    {m:'GET',p:'/certbot/certs',d:'Certificats émis',dEn:'Issued certificates'},
    {m:'GET',p:'/certbot/check-conflict?domain=…',d:'Vérifie un conflit de domaine avant émission',dEn:'Check for a domain conflict before issuance'},
    {m:'POST',p:'/certbot/issue',d:'Émettre un certificat {domain}',dEn:'Issue a certificate {domain}'},
    {m:'POST',p:'/certbot/revoke',d:'Révoquer un certificat {domain}',dEn:'Revoke a certificate {domain}'},
    {m:'POST',p:'/certbot/container/start',d:'Démarrer le conteneur Certbot',dEn:'Start the Certbot container'},
    {m:'POST',p:'/certbot/container/stop',d:'Arrêter le conteneur Certbot',dEn:'Stop the Certbot container'},
    {m:'POST',p:'/certbot/image/update',d:'Mettre à jour l’image Certbot',dEn:'Update the Certbot image'},
    {m:'GET',p:'/certbot-dns/status',d:'État Certbot (défi DNS-01)',dEn:'Certbot status (DNS-01 challenge)'},
    {m:'GET',p:'/certbot-dns/providers',d:'Fournisseurs DNS supportés',dEn:'Supported DNS providers'},
    {m:'GET',p:'/certbot-dns/config',d:'Configuration courante (défi DNS-01)',dEn:'Current configuration (DNS-01 challenge)'},
    {m:'GET',p:'/certbot-dns/certs',d:'Certificats émis (DNS-01, wildcards inclus)',dEn:'Issued certificates (DNS-01, wildcards included)'},
    {m:'GET',p:'/certbot-dns/check-conflict?domain=…',d:'Vérifie un conflit de domaine',dEn:'Check for a domain conflict'},
    {m:'POST',p:'/certbot-dns/issue',d:'Émettre un certificat {domain} (défi DNS-01)',dEn:'Issue a certificate {domain} (DNS-01 challenge)'},
    {m:'POST',p:'/certbot-dns/revoke',d:'Révoquer un certificat',dEn:'Revoke a certificate'},
    {m:'POST',p:'/certbot-dns/container/start',d:'Démarrer le conteneur Certbot-DNS',dEn:'Start the Certbot-DNS container'},
    {m:'POST',p:'/certbot-dns/container/stop',d:'Arrêter le conteneur Certbot-DNS',dEn:'Stop the Certbot-DNS container'},
    {m:'POST',p:'/certbot-dns/image/update',d:'Mettre à jour l’image Certbot-DNS',dEn:'Update the Certbot-DNS image'},
  ]},
  {cat:'Auto-config Docker', catKey:'dockerAutoconfig', items:[
    {m:'GET',p:'/docker-autoconfig/status',d:'Conteneurs détectés et décisions en attente',dEn:'Detected containers and pending decisions'},
    {m:'POST',p:'/docker-autoconfig/approve',d:'Approuver un vhost proposé {serverNames}',dEn:'Approve a proposed vhost {serverNames}'},
    {m:'POST',p:'/docker-autoconfig/reject',d:'Rejeter une proposition',dEn:'Reject a proposal'},
    {m:'POST',p:'/docker-autoconfig/pause',d:'Suspendre l’auto-config pour un vhost',dEn:'Pause auto-config for a vhost'},
    {m:'POST',p:'/docker-autoconfig/resume',d:'Reprendre l’auto-config pour un vhost',dEn:'Resume auto-config for a vhost'},
    {m:'POST',p:'/docker-autoconfig/decisions/remove',d:'Oublier une décision enregistrée',dEn:'Forget a recorded decision'},
    {m:'POST',p:'/docker-autoconfig/rescan',d:'Forcer un nouveau scan des conteneurs Docker',dEn:'Force a new scan of Docker containers'},
  ]},
  {cat:'Hôtes distants (agents)', catKey:'agents', items:[
    {m:'GET',p:'/agents',d:'Liste des agents enrôlés',dEn:'List of enrolled agents'},
    {m:'POST',p:'/agent/enroll',d:'Premier contact d’un agent (public, sans jeton)',dEn:'First contact from an agent (public, no token)'},
    {m:'POST',p:'/agent/manifest',d:'Un agent pousse son manifeste de vhosts (Bearer = jeton agent)',dEn:'An agent pushes its vhost manifest (Bearer = agent token)'},
    {m:'POST',p:'/agents/:id/approve',d:'Approuver un agent en attente',dEn:'Approve a pending agent'},
    {m:'POST',p:'/agents/:id/reject',d:'Rejeter un agent en attente',dEn:'Reject a pending agent'},
    {m:'POST',p:'/agents/:id/revoke',d:'Révoquer un agent approuvé',dEn:'Revoke an approved agent'},
    {m:'POST',p:'/agents/:id/regenerate-token',d:'Régénérer le jeton d’un agent',dEn:'Regenerate an agent\'s token'},
    {m:'POST',p:'/agents/:id/vhosts/pause',d:'Suspendre un vhost publié par cet agent {serverNames}',dEn:'Pause a vhost published by this agent {serverNames}'},
    {m:'POST',p:'/agents/:id/vhosts/resume',d:'Reprendre un vhost publié par cet agent',dEn:'Resume a vhost published by this agent'},
    {m:'DELETE',p:'/agents/:id',d:'Supprimer un agent',dEn:'Delete an agent'},
  ]},
  {cat:'GeoIP', catKey:'geoip', items:[
    {m:'GET',p:'/geoip/lookup?ip=…',d:'Localise une IP (pays, ville, ASN)',dEn:'Locate an IP (country, city, ASN)'},
    {m:'GET',p:'/geoipupdate/status',d:'État du conteneur geoipupdate',dEn:'geoipupdate container status'},
    {m:'GET',p:'/geoipupdate/config',d:'Configuration courante',dEn:'Current configuration'},
    {m:'POST',p:'/geoipupdate/update-now',d:'Forcer une mise à jour des bases GeoIP',dEn:'Force a GeoIP database update'},
    {m:'POST',p:'/geoipupdate/container/start',d:'Démarrer le conteneur',dEn:'Start the container'},
    {m:'POST',p:'/geoipupdate/container/stop',d:'Arrêter le conteneur',dEn:'Stop the container'},
    {m:'POST',p:'/geoipupdate/image/update',d:'Mettre à jour l’image',dEn:'Update the image'},
  ]},
  {cat:'Pages d’erreur', catKey:'errorPages', items:[
    {m:'GET',p:'/error-pages/status',d:'État du conteneur de pages d’erreur',dEn:'Error pages container status'},
    {m:'GET',p:'/error-pages/config',d:'Configuration courante',dEn:'Current configuration'},
    {m:'POST',p:'/error-pages/container/start',d:'Démarrer le conteneur',dEn:'Start the container'},
    {m:'POST',p:'/error-pages/container/stop',d:'Arrêter le conteneur',dEn:'Stop the container'},
    {m:'POST',p:'/error-pages/image/update',d:'Mettre à jour l’image',dEn:'Update the image'},
  ]},
  {cat:'Administration', catKey:'admin', items:[
    {m:'GET',p:'/system-info',d:'Registre de configuration du dashboard (admin)',dEn:'Dashboard configuration registry (admin)'},
    {m:'POST',p:'/system-info/generate-api-token',d:'Générer un nouveau API_TOKEN (affiché une seule fois)',dEn:'Generate a new API_TOKEN (shown once)'},
    {m:'POST',p:'/system-info/revoke-api-token',d:'Révoquer l’API_TOKEN courant',dEn:'Revoke the current API_TOKEN'},
    {m:'POST',p:'/system-info/generate-webhook-secret',d:'Générer un nouveau WEBHOOK_SECRET',dEn:'Generate a new WEBHOOK_SECRET'},
    {m:'POST',p:'/system-info/revoke-webhook-secret',d:'Révoquer le WEBHOOK_SECRET courant',dEn:'Revoke the current WEBHOOK_SECRET'},
    {m:'GET',p:'/menu-visibility',d:'État résolu des éléments de menu optionnels',dEn:'Resolved state of optional menu items'},
    {m:'GET',p:'/changelog',d:'Contenu du CHANGELOG.md distant (si CHANGELOG_URL configurée)',dEn:'Remote CHANGELOG.md content (if CHANGELOG_URL is set)'},
    {m:'GET',p:'/auth/users',d:'Liste des comptes utilisateurs',dEn:'List of user accounts'},
    {m:'POST',p:'/auth/hash',d:'Hacher un mot de passe (utilitaire admin)',dEn:'Hash a password (admin utility)'},
  ]},
];
// Fix (retour utilisateur v12.41.0) : chaque endpoint doit avoir un id DOM
// stable et unique (epb-N/echv-N/ebi-N/epr-N). `idx` est fixe une fois pour
// toutes ici, sur les objets ENDPOINTS eux-memes — renderApiDoc() les relit
// directement (voir plus bas) au lieu de chercher leur position par
// egalite de reference, qui echouait systematiquement (voir commentaire
// juste avant l ancien bug, desormais corrige).
const ENDPOINTS=ENDPOINT_GROUPS.flatMap(g=>g.items.map(e=>({...e,cat:g.cat})));
ENDPOINTS.forEach((e,i)=>{e.idx=i;});

// Choisit la description dans la langue courante — voir le commentaire au
// dessus d ENDPOINT_GROUPS sur pourquoi `d`/`dEn` restent a cote de chaque
// route plutot que dans des cles i18n separees.
function apiDescFor(e){ return (LANG==='en' && e.dEn) ? e.dEn : e.d; }
// Idem pour le nom de categorie : `t('api.cat.'+catKey)` si la cle existe,
// sinon repli sur le nom francais d origine (`cat`) — jamais de categorie
// vide si une traduction manque.
function apiCatLabel(g){ const k='api.cat.'+g.catKey; const v=t(k); return v===k ? g.cat : v; }

// Fix (retour utilisateur v12.43.0) : le textarea de corps de requete
// affichait un placeholder generique `{"key":"value"}` identique pour les
// ~90 endpoints POST/PUT/PATCH, sans aucun rapport avec les champs reels
// attendus — aucune information exploitable. La plupart des descriptions
// documentent deja la forme du corps entre accolades (ex. "Bannir une IP
// {ip,duration,reason}") : on extrait ces noms de champs pour batir un
// placeholder JSON concret ({"ip":"<ip>","duration":"<duration>", ...}),
// sans dupliquer cette information ailleurs. Pas d annotation `{...}` dans
// la description (beaucoup d actions n attendent reellement aucun corps,
// ex. /nginx/reload, /analyzer/alerts/ack-all) -> pas de placeholder
// trompeur, un message explicite ("Aucun corps requis") a la place.
function apiBodyHint(e){
  const src=e.dEn || e.d || '';
  const m=src.match(/\{([^}]+)\}/);
  if(!m) return null;
  const fields=m[1].split(',').map(f=>f.split(':')[0].trim()).filter(Boolean);
  if(!fields.length) return null;
  const obj={};
  fields.forEach(k=>{ obj[k]='<'+k+'>'; });
  return JSON.stringify(obj);
}

function apiExampleFor(e){
  // Exemples ecrits a la main pour les endpoints les plus utiles a
  // l automatisation (marques `example:true` ci-dessus) — pas question d en
  // ecrire un pour chacun des ~130 endpoints, mais ceux-la meritent un cas
  // concret plutot que le curl generique deja affiche sous chaque ligne.
  if(e.p==='/git/deploy') return {
    title:'Automatiser un déploiement (CI/CD)',
    titleEn:'Automate a deployment (CI/CD)',
    body:`# Étape 1 : obtenir un jeton scopé depuis la page Déploiement Git\n# (config/deploy-tokens.yml, actions: [pull, test, deploy])\n\ncurl -X POST https://votre-dashboard/api/git/deploy \\\n  -H "Authorization: Bearer <DEPLOY_TOKEN>" \\\n  -H "Content-Type: application/json"\n\n# Réponse (200 si succès, 422 si "nginx -t" échoue après le pull) :\n{\n  "ok": true,\n  "log": [\n    { "step": "pull",   "ok": true, "commit": "a1b2c3d" },\n    { "step": "test",   "ok": true },\n    { "step": "backup", "ok": true, "file": "backup-2026-09-28.zip" },\n    { "step": "deploy", "ok": true, "filesChanged": 4 },\n    { "step": "reload", "ok": true }\n  ]\n}\n\n# Ce SEUL appel enchaîne : pull -> test (nginx -t sur un checkout\n# éphémère, jamais sur la config active) -> backup (zip + git) ->\n# copie vers les répertoires actifs -> reload. Si le test échoue, rien\n# n'est copié ni rechargé (réponse 422, le pull reste dans DIR_GIT_WORK\n# pour inspection).`,
    bodyEn:`# Step 1: get a scoped token from the Git Deploy page\n# (config/deploy-tokens.yml, actions: [pull, test, deploy])\n\ncurl -X POST https://your-dashboard/api/git/deploy \\\n  -H "Authorization: Bearer <DEPLOY_TOKEN>" \\\n  -H "Content-Type: application/json"\n\n# Response (200 on success, 422 if "nginx -t" fails after the pull):\n{\n  "ok": true,\n  "log": [\n    { "step": "pull",   "ok": true, "commit": "a1b2c3d" },\n    { "step": "test",   "ok": true },\n    { "step": "backup", "ok": true, "file": "backup-2026-09-28.zip" },\n    { "step": "deploy", "ok": true, "filesChanged": 4 },\n    { "step": "reload", "ok": true }\n  ]\n}\n\n# This SINGLE call chains: pull -> test (nginx -t on an ephemeral\n# checkout, never on the live config) -> backup (zip + git) ->\n# copy to the live directories -> reload. If the test fails, nothing\n# is copied or reloaded (422 response, the pull stays in DIR_GIT_WORK\n# for inspection).`
  };
  if(e.p==='/webhooks') return {
    title:'Créer un webhook',
    titleEn:'Create a webhook',
    body:`curl -X POST https://votre-dashboard/api/webhooks \\\n  -H "Authorization: Bearer <API_TOKEN>" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "url": "https://exemple.com/hook",\n    "events": ["nginx_reload", "cert_renewed"],\n    "description": "Notifie mon outil interne"\n  }'\n\n# Réponse :\n{ "id": "wh_abc123", "url": "https://exemple.com/hook", "events": ["nginx_reload","cert_renewed"] }`,
    bodyEn:`curl -X POST https://your-dashboard/api/webhooks \\\n  -H "Authorization: Bearer <API_TOKEN>" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "url": "https://example.com/hook",\n    "events": ["nginx_reload", "cert_renewed"],\n    "description": "Notifies my internal tool"\n  }'\n\n# Response:\n{ "id": "wh_abc123", "url": "https://example.com/hook", "events": ["nginx_reload","cert_renewed"] }`
  };
  if(e.p==='/crowdsec/ban') return {
    title:'Bannir une IP manuellement',
    titleEn:'Manually ban an IP',
    body:`curl -X POST https://votre-dashboard/api/crowdsec/ban \\\n  -H "Authorization: Bearer <API_TOKEN>" \\\n  -H "Content-Type: application/json" \\\n  -d '{ "ip": "203.0.113.42", "duration": "4h", "reason": "abus manuel" }'\n\n# Réponse :\n{ "ok": true }`,
    bodyEn:`curl -X POST https://your-dashboard/api/crowdsec/ban \\\n  -H "Authorization: Bearer <API_TOKEN>" \\\n  -H "Content-Type: application/json" \\\n  -d '{ "ip": "203.0.113.42", "duration": "4h", "reason": "manual abuse" }'\n\n# Response:\n{ "ok": true }`
  };
  return null;
}

function renderApiDoc(){
  const catSel=document.getElementById('api-cat-filter');
  // Reconstruit la liste des categories a chaque appel (17 options, cout
  // negligeable) plutot qu une seule fois : necessaire pour que les libelles
  // suivent un changement de langue en cours de session, tout en conservant
  // la selection courante (par catKey, stable, jamais par le libelle traduit).
  if(catSel){
    const prevVal=catSel.value;
    catSel.innerHTML=`<option value="" data-i18n="api.allCategories">${svgEsc(t('api.allCategories'))}</option>` +
      ENDPOINT_GROUPS.map(g=>`<option value="${svgEsc(g.catKey)}">${svgEsc(apiCatLabel(g))}</option>`).join('');
    catSel.value=prevVal;
  }
  const q=(document.getElementById('api-search')?.value||'').trim().toLowerCase();
  const catFilter=catSel?.value||'';
  let shown=0;
  document.getElementById('api-doc').innerHTML=ENDPOINT_GROUPS.map(g=>{
    if(catFilter && catFilter!==g.catKey) return '';
    // Bug reel corrige (retour utilisateur v12.41.0) : cette liste venait de
    // `g.items` (les objets originaux d ENDPOINT_GROUPS), alors que ENDPOINTS
    // ne contient que des COPIES (`{...e,cat:g.cat}`) — `ENDPOINTS.indexOf(e)`
    // ne trouvait donc jamais l objet original et renvoyait -1 pour CHAQUE
    // endpoint. Consequence : tous les id DOM generes plus bas etaient
    // identiques ("epb--1", "echv--1", ...) et onclick="toggleEP(-1)"
    // partout — seul le premier element trouve par getElementById (toujours
    // le meme, le premier du DOM) reagissait au clic, quel que soit
    // l endpoint sur lequel on cliquait. On filtre desormais directement les
    // objets ENDPOINTS (qui portent deja `idx`), plus jamais `g.items`.
    const items=ENDPOINTS.filter(e=>e.cat===g.cat && (!q || e.m.toLowerCase().includes(q) || e.p.toLowerCase().includes(q) || apiDescFor(e).toLowerCase().includes(q) || e.d.toLowerCase().includes(q)));
    if(!items.length) return '';
    shown+=items.length;
    return `<div class="ctitle" style="margin:18px 0 8px">${svgEsc(apiCatLabel(g))}</div>` + items.map((e)=>{
      const i=e.idx;
      const bodyHint=apiBodyHint(e);
      const bodyPlaceholder=svgEsc(bodyHint || t('api.body.none'));
      return `
  <div class="ep"><div class="eph" onclick="toggleEP(${i})">
    <span class="meth ${e.m}">${e.m}</span><span style="color:var(--text);flex:1">${svgEsc(e.p)}</span>
    <span style="color:var(--text3);font-size:11px">${svgEsc(apiDescFor(e))}</span>
    <svg class="chv" id="echv-${i}" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="2,4 6,8 10,4"/></svg>
  </div>
  <div class="epb" id="epb-${i}">
    <div style="margin-top:12px;font-family:monospace;font-size:11px;color:var(--text3)">
      <code style="color:var(--amber)">curl</code> -H "Authorization: Bearer &lt;API_TOKEN&gt;" ${e.m!=='GET'?`-X ${e.m} `:''}http://localhost:3000/api${e.p}
    </div>
    ${e.m!=='GET'&&e.m!=='DELETE'?`<textarea id="ebi-${i}" rows="2" style="margin-top:8px" placeholder='${bodyPlaceholder}'></textarea>`:''}
    <div style="margin-top:8px;display:flex;gap:8px">
      <button class="sm primary" onclick='tryEP(${i},"${e.m}",${JSON.stringify(e.p)})'>&#9654; <span data-i18n="api.try">Essayer</span></button>
      ${e.example?`<button class="sm" onclick='apiExampleOpen(${JSON.stringify(e.p)})'>&#128220; <span data-i18n="api.example">Exemple</span></button>`:''}
    </div>
    <pre class="epr" id="epr-${i}"></pre>
  </div></div>`;
    }).join('');
  }).join('') || `<div style="color:var(--text3);font-size:12px;padding:12px 0">${svgEsc(t('api.noResults'))}</div>`;
  // renderApiDoc() re-genere le HTML (recherche/filtre a chaque frappe) ; les
  // data-i18n fraichement injectes (boutons Essayer/Exemple) doivent etre
  // retraduits immediatement, sans attendre le prochain changement de langue.
  applyTranslations();
}

function toggleEP(i){const b=document.getElementById('epb-'+i),c=document.getElementById('echv-'+i);b.classList.toggle('open');c.classList.toggle('open');}

function apiExampleOpen(p){
  const e=ENDPOINTS.find(x=>x.p===p);
  const ex=e&&apiExampleFor(e);
  if(!ex) return;
  document.getElementById('api-example-title').textContent=(LANG==='en' && ex.titleEn) ? ex.titleEn : ex.title;
  document.getElementById('api-example-content').textContent=(LANG==='en' && ex.bodyEn) ? ex.bodyEn : ex.body;
  document.getElementById('api-example-overlay').style.display='flex';
}
function apiExampleClose(){document.getElementById('api-example-overlay').style.display='none';}

async function tryEP(i,m,p){
  const el=document.getElementById('epr-'+i);el.className='epr show';el.textContent='…';
  // Fix (retour utilisateur v12.41.0) : un chemin avec un parametre nomme
  // (":id", ":name"...) etait envoye tel quel — ":id" litteralement dans l
  // URL, qui 404ait toujours en silence (le bouton "semblait" fonctionner,
  // il renvoyait juste systematiquement une erreur). Chaque parametre est
  // desormais demande via une invite avant l appel.
  let path=p.split('?')[0];
  const query=p.includes('?')?'?'+p.split('?')[1]:'';
  const params=[...path.matchAll(/:([A-Za-z_]+)/g)].map(m=>m[1]);
  for(const name of params){
    const val=prompt(t('api.promptParam',{name}));
    if(val===null){el.textContent='';return;} // annule
    path=path.replace(':'+name, encodeURIComponent(val));
  }
  const bi=document.getElementById('ebi-'+i);
  const opts={method:m};if(bi?.value.trim())opts.body=bi.value;
  const r=await api(path+query,opts).catch(e=>({error:e.message}));
  el.textContent=JSON.stringify(r,null,2);
}
renderApiDoc();
