'use strict';
/**
 * Catalogue de modèles de règles d'analyse (« dictionnaire » par application).
 *
 * Données pures : ajouter une application = ajouter un pack ci-dessous, sans
 * toucher au reste (le test test/rule-templates.test.js valide chaque règle
 * avec le même validateur que le formulaire, et — si le dépôt contient
 * nginx-analyzer — avec le chargeur YAML réel). Les expressions régulières sont
 * compatibles RE2 (moteur Go) et JavaScript : pas d'anticipation ni de
 * références arrière ; elles sont évaluées sans tenir compte de la casse.
 *
 * Une règle de modèle n'a PAS d'id : il est attribué à l'insertion (premier id
 * libre ≥ 100). `scope: global` = comptage toutes IP confondues (campagnes
 * distribuées, v12.60.0).
 */

const L = (fr, en) => ({ fr, en });

const block = (threshold, minutes) => ({ threshold, windowMinutes: 1440, remediation: true, remediationMinutes: minutes });

const PACKS = [
  {
    id: 'forgejo', app: 'Forgejo / Gitea',
    title: L('Forgejo / Gitea', 'Forgejo / Gitea'),
    description: L('Aspiration distribuée des dépôts publics (botnets résidentiels) et force brute.', 'Distributed scraping of public repositories (residential botnets) and brute force.'),
    note: L('Contre l\'aspiration, REQUIRE_SIGNIN_VIEW = true dans app.ini reste la mesure la plus efficace.', 'Against scraping, REQUIRE_SIGNIN_VIEW = true in app.ini remains the most effective measure.'),
    rules: [
      { slug: 'forgejo_scraper_commit_walk', severity: 'high', scope: 'global', minIps: 10, minMatches: 20, windowMinutes: 10,
        pathHint: '/(commits/commit|src/commit|raw/commit|blame/commit)/[0-9a-f]{40}', methodIn: ['GET'], blocklist: block(1, 1440),
        description: L('Aspiration Forgejo distribuée : parcours de commits/fichiers par hash', 'Distributed Forgejo scraping: walking commits/files by hash') },
      { slug: 'forgejo_scraper_filtered_lists', severity: 'high', scope: 'global', minIps: 15, minMatches: 30, windowMinutes: 10,
        pathHint: '/(issues|pulls)\\?.*(labels|milestone|poster|assignee|project)=.*sort=', methodIn: ['GET'], blocklist: block(1, 1440),
        description: L('Aspiration Forgejo distribuée : listes issues/pulls avec combinaisons de filtres', 'Distributed Forgejo scraping: issue/PR lists with filter combinations') },
      { slug: 'forgejo_scraper_login_redirect', severity: 'medium', scope: 'global', minIps: 10, minMatches: 15, windowMinutes: 10,
        pathHint: '^/user/login\\?redirect_to=%2F.+%2F(src|commits|issues|pulls)', methodIn: ['GET'], blocklist: block(1, 1440),
        description: L('Aspiration Forgejo distribuée : renvois vers la connexion depuis des pages profondes', 'Distributed Forgejo scraping: login redirects from deep pages') },
      { slug: 'forgejo_login_bruteforce', severity: 'high', scope: 'ip', minMatches: 10, windowMinutes: 5,
        pathHint: '^/user/login($|\\?)', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Tentatives répétées sur le formulaire de connexion', 'Repeated attempts on the login form') },
      { slug: 'forgejo_api_auth_failures', severity: 'medium', scope: 'ip', minMatches: 15, windowMinutes: 5,
        pathHint: '^/api/v1/', statusIn: [401, 403],
        description: L('Échecs d\'authentification répétés sur l\'API', 'Repeated authentication failures on the API') },
    ],
  },
  {
    id: 'gitlab', app: 'GitLab',
    title: L('GitLab', 'GitLab'),
    description: L('Force brute de connexion, échecs d\'API et aspiration par hash.', 'Login brute force, API failures and hash-based scraping.'),
    rules: [
      { slug: 'gitlab_login_bruteforce', severity: 'high', scope: 'ip', minMatches: 10, windowMinutes: 5,
        pathHint: '^/users/sign_in', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Tentatives répétées sur la connexion GitLab', 'Repeated attempts on the GitLab sign-in') },
      { slug: 'gitlab_api_auth_failures', severity: 'medium', scope: 'ip', minMatches: 15, windowMinutes: 5,
        pathHint: '^/api/v4/', statusIn: [401, 403],
        description: L('Échecs d\'authentification répétés sur l\'API v4', 'Repeated authentication failures on API v4') },
      { slug: 'gitlab_scraper_blob_walk', severity: 'high', scope: 'global', minIps: 10, minMatches: 20, windowMinutes: 10,
        pathHint: '/-/(blob|blame|raw|commit|tree)/[0-9a-f]{40}', methodIn: ['GET'], blocklist: block(1, 1440),
        description: L('Aspiration GitLab distribuée : parcours de fichiers/commits par hash', 'Distributed GitLab scraping: walking files/commits by hash') },
      { slug: 'gitlab_password_reset_abuse', severity: 'medium', scope: 'ip', minMatches: 5, windowMinutes: 10,
        pathHint: '^/users/password', methodIn: ['POST'],
        description: L('Demandes de réinitialisation de mot de passe en rafale', 'Burst of password reset requests') },
    ],
  },
  {
    id: 'wordpress', app: 'WordPress',
    title: L('WordPress', 'WordPress'),
    description: L('Force brute wp-login, XML-RPC, énumération d\'utilisateurs, scan de plugins.', 'wp-login brute force, XML-RPC, user enumeration, plugin scans.'),
    note: L('À désactiver sur un site qui n\'est pas WordPress (voir « Sonde wp-admin » dans le guide).', 'Disable on non-WordPress sites.'),
    rules: [
      { slug: 'wp_login_bruteforce', severity: 'high', scope: 'ip', minMatches: 8, windowMinutes: 5,
        pathHint: '/wp-login\\.php', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Force brute sur wp-login.php', 'Brute force on wp-login.php') },
      { slug: 'wp_login_distributed', severity: 'high', scope: 'global', minIps: 10, minMatches: 40, windowMinutes: 10,
        pathHint: '/wp-login\\.php', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Force brute distribuée sur wp-login.php (botnet)', 'Distributed brute force on wp-login.php (botnet)') },
      { slug: 'wp_xmlrpc_abuse', severity: 'high', scope: 'ip', minMatches: 5, windowMinutes: 5,
        pathHint: '/xmlrpc\\.php', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Abus de xmlrpc.php (amplification de force brute, pingback)', 'xmlrpc.php abuse (brute force amplification, pingback)') },
      { slug: 'wp_user_enumeration', severity: 'medium', scope: 'ip', minMatches: 5, windowMinutes: 10,
        pathHint: '(\\?author=[0-9]+|/wp-json/wp/v2/users)', methodIn: ['GET'],
        description: L('Énumération des comptes WordPress', 'WordPress account enumeration') },
      { slug: 'wp_plugin_scan', severity: 'medium', scope: 'ip', minMatches: 10, windowMinutes: 5,
        pathHint: '/wp-content/(plugins|themes)/', statusIn: [404],
        description: L('Scan de plugins/thèmes inexistants (404 en série)', 'Scan for non-existent plugins/themes (404 series)') },
    ],
  },
  {
    id: 'nextcloud', app: 'Nextcloud',
    title: L('Nextcloud', 'Nextcloud'),
    description: L('Force brute de connexion, WebDAV et API OCS.', 'Login brute force, WebDAV and OCS API.'),
    rules: [
      { slug: 'nextcloud_login_bruteforce', severity: 'high', scope: 'ip', minMatches: 10, windowMinutes: 5,
        pathHint: '^/(index\\.php/)?login', methodIn: ['POST'], blocklist: block(1, 1440),
        description: L('Tentatives répétées sur la connexion Nextcloud', 'Repeated attempts on the Nextcloud login') },
      { slug: 'nextcloud_dav_auth_failures', severity: 'high', scope: 'ip', minMatches: 15, windowMinutes: 5,
        pathHint: '^/(remote\\.php/(dav|webdav)|public\\.php/(dav|webdav))', statusIn: [401, 403], blocklist: block(1, 1440),
        description: L('Échecs d\'authentification WebDAV répétés', 'Repeated WebDAV authentication failures') },
      { slug: 'nextcloud_ocs_auth_failures', severity: 'medium', scope: 'ip', minMatches: 20, windowMinutes: 5,
        pathHint: '^/ocs/v[12]\\.php', statusIn: [401, 403],
        description: L('Échecs d\'authentification répétés sur l\'API OCS', 'Repeated authentication failures on the OCS API') },
    ],
  },
  {
    id: 'bad-ua', app: 'User-agents',
    title: L('Mauvais user-agents', 'Bad user agents'),
    description: L('Outils d\'attaque déclarés, bibliothèques de scraping, crawlers d\'IA.', 'Declared attack tools, scraping libraries, AI crawlers.'),
    note: L('Les crawlers d\'IA sont désactivés par défaut (choix de politique, pas une attaque).', 'AI crawlers are disabled by default (a policy choice, not an attack).'),
    rules: [
      { slug: 'ua_attack_tools', severity: 'high', scope: 'ip', minMatches: 1, windowMinutes: 5,
        uaHint: 'sqlmap|nikto|nessus|acunetix|dirbuster|gobuster|wfuzz|ffuf|nuclei|masscan|zgrab|nmap|openvas|havij|w3af|burpcollaborator', blocklist: block(1, 1440),
        description: L('User-agent d\'un outil d\'attaque ou de scan connu', 'User agent of a known attack or scan tool') },
      { slug: 'ua_http_libraries_flood', severity: 'low', scope: 'ip', minMatches: 200, windowMinutes: 5,
        uaHint: 'python-requests|python-urllib|go-http-client|libwww-perl|okhttp|scrapy|aiohttp|node-fetch|axios|java/',
        description: L('Volume anormal depuis une bibliothèque HTTP de script', 'Abnormal volume from a scripting HTTP library') },
      { slug: 'ua_ai_crawlers', enable: false, severity: 'low', scope: 'ip', minMatches: 20, windowMinutes: 10,
        uaHint: 'GPTBot|ClaudeBot|CCBot|Bytespider|PerplexityBot|Amazonbot|meta-externalagent|anthropic-ai|Diffbot|ImagesiftBot|Omgilibot|Timpibot',
        description: L('Crawler d\'entraînement d\'IA (activez pour être alerté ou bloquer)', 'AI training crawler (enable to be alerted or block)') },
    ],
  },
  {
    id: 'web-generic', app: 'Web',
    title: L('Web générique', 'Generic web'),
    description: L('Fichiers sensibles, outils d\'administration, injections et traversée de chemin.', 'Sensitive files, admin tools, injections and path traversal.'),
    rules: [
      { slug: 'probe_sensitive_files', severity: 'high', scope: 'ip', minMatches: 3, windowMinutes: 10,
        pathHint: '/(\\.env|\\.git/|\\.svn/|\\.aws/|\\.ssh/|\\.DS_Store|id_rsa|wp-config\\.php|config\\.php\\.(bak|old|orig)|phpinfo\\.php|backup\\.(sql|zip|tar))', blocklist: block(1, 1440),
        description: L('Recherche de fichiers sensibles (.env, .git, clés, sauvegardes)', 'Probing for sensitive files (.env, .git, keys, backups)') },
      { slug: 'probe_admin_tools', severity: 'medium', scope: 'ip', minMatches: 3, windowMinutes: 10,
        pathHint: '/(phpmyadmin|pma|adminer)(/|\\.php|$|\\?)|/manager/html|/solr/admin|/actuator/(env|heapdump)|/jmx-console|/server-status',
        description: L('Recherche d\'outils d\'administration exposés', 'Probing for exposed admin tools') },
      { slug: 'attack_injection_patterns', severity: 'high', scope: 'ip', minMatches: 2, windowMinutes: 5,
        pathHint: '(\\.\\./|%2e%2e|%252e|/etc/passwd|union(%20|\\+| )+select|<script|%3cscript|\\$\\{jndi:)', blocklist: block(1, 1440),
        description: L('Motifs d\'injection / traversée de chemin / Log4Shell', 'Injection / path traversal / Log4Shell patterns') },
      { slug: 'scan_404_distributed', severity: 'medium', scope: 'global', minIps: 20, minMatches: 200, windowMinutes: 10,
        statusIn: [404],
        description: L('Vague de 404 toutes IP confondues (scan distribué) — à ajuster selon votre trafic', 'Wave of 404s across all IPs (distributed scan) — tune to your traffic') },
    ],
  },
];

const pick = (l, lang) => (l && typeof l === 'object' ? (l[lang] || l.en || l.fr || '') : (l || ''));

/** Liste résolue dans une langue (sans id : attribué à l'insertion). */
function listTemplates(lang = 'fr') {
  const lg = lang === 'en' ? 'en' : 'fr';
  return PACKS.map(p => ({
    id: p.id, app: p.app, title: pick(p.title, lg), description: pick(p.description, lg), note: pick(p.note, lg) || null,
    rules: p.rules.map(r => ({
      slug: r.slug, name: r.slug, enable: r.enable !== false, severity: r.severity, scope: r.scope || 'ip',
      minIps: r.scope === 'global' ? r.minIps : null, minMatches: r.minMatches, windowMinutes: r.windowMinutes,
      pathHint: r.pathHint || '', uaHint: r.uaHint || '', statusIn: r.statusIn || [], methodIn: r.methodIn || [],
      description: pick(r.description, lg),
      blocklist: r.blocklist || { threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null },
    })),
  }));
}

module.exports = { PACKS, listTemplates };
