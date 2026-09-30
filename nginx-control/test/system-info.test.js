'use strict';
/**
 * lib/system-info.js — le registre doit rester synchronise avec lib/config.js
 * (aucune variable ajoutee/renommee dans config.js ne doit pouvoir passer
 * inapercue), et detectNginxImage()/buildSystemInfo() doivent se comporter
 * correctement dans les deux branches (image fixee vs. auto-detection).
 */
const assert = require('assert');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/system-info.js — registre de configuration');

// ─── Sync avec lib/config.js ────────────────────────────────────────────────
check('chaque cle exportee par lib/config.js apparait dans ENTRIES ou INTENTIONALLY_OMITTED, jamais aucune des deux ni les deux', () => {
  const cfg = require('../lib/config');
  const { ENTRIES, INTENTIONALLY_OMITTED } = require('../lib/system-info');
  const entryKeys = new Set(ENTRIES.map(e => e.key));
  const missing = [];
  const both = [];
  for (const key of Object.keys(cfg)) {
    const inEntries = entryKeys.has(key);
    const inOmitted = INTENTIONALLY_OMITTED.has(key);
    if (!inEntries && !inOmitted) missing.push(key);
    if (inEntries && inOmitted) both.push(key);
  }
  assert.deepStrictEqual(missing, [], `cle(s) de lib/config.js absente(s) du registre : ${missing.join(', ')}`);
  assert.deepStrictEqual(both, [], `cle(s) a la fois listee(s) et omise(s) : ${both.join(', ')}`);
});

check('INTENTIONALLY_OMITTED ne contient que des cles reellement exportees par lib/config.js (pas de reference morte)', () => {
  const cfg = require('../lib/config');
  const { INTENTIONALLY_OMITTED } = require('../lib/system-info');
  const stale = [...INTENTIONALLY_OMITTED].filter(k => !(k in cfg));
  assert.deepStrictEqual(stale, [], `reference(s) morte(s) : ${stale.join(', ')}`);
});

check('chaque entree a une cle unique', () => {
  const { ENTRIES } = require('../lib/system-info');
  const keys = ENTRIES.map(e => e.key);
  assert.strictEqual(new Set(keys).size, keys.length);
});

check('aucun champ sensible n expose jamais une valeur non booleenne', () => {
  const { ENTRIES } = require('../lib/system-info');
  for (const e of ENTRIES.filter(e => e.sensitive)) {
    assert.strictEqual(typeof e.value, 'boolean', `${e.key} : valeur sensible non booleenne (${typeof e.value})`);
  }
});

check('chaque entree a une categorie et un override renseignes', () => {
  const { ENTRIES } = require('../lib/system-info');
  for (const e of ENTRIES) {
    assert.ok(e.category, `${e.key} sans categorie`);
    assert.ok(e.override && e.override.kind, `${e.key} sans override`);
  }
});

// ─── detectNginxImage() ──────────────────────────────────────────────────────
(async () => {
  // NGINX_IMAGE est lu une seule fois par lib/config.js au chargement du module,
  // donc on ne peut pas la modifier ici via process.env — on verifie plutot
  // les DEUX comportements via des modules isoles (cache require distinct),
  // avec un jeu d env vars different pour chacun.
  const path = require('path');
  const Module = require('module');

  function freshSystemInfo(envOverrides) {
    const savedEnv = { ...process.env };
    Object.assign(process.env, envOverrides);
    // Vide le cache pour lib/config.js, lib/system-info.js et lib/docker.js
    // (docker.js n a pas besoin d etre isole : il n est pas configure par env,
    // seul son usage differe selon si NGINX_IMAGE est deja connue).
    for (const id of [require.resolve('../lib/config'), require.resolve('../lib/system-info')]) {
      delete require.cache[id];
    }
    const mod = require('../lib/system-info');
    process.env = savedEnv;
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../lib/system-info')];
    return mod;
  }

  await (async () => {
    try {
      const { detectNginxImage } = freshSystemInfo({ NGINX_IMAGE: 'my-registry/nginx:1.27' });
      const r = await detectNginxImage();
      assert.strictEqual(r.value, 'my-registry/nginx:1.27');
      assert.strictEqual(r.autoDetected, false);
      console.log('  PASS  detectNginxImage() : NGINX_IMAGE fixee -> renvoyee telle quelle, pas de detection'); pass++;
    } catch (e) { console.log('  FAIL  detectNginxImage() : NGINX_IMAGE fixee\n        ' + e.message); fail++; }
  })();

  await (async () => {
    try {
      // NGINX_IMAGE vide (pas de conteneur Docker dans ce test) -> tente la
      // detection, echoue proprement (pas de docker.sock ici), et remonte une
      // erreur plutot que de planter.
      const { detectNginxImage } = freshSystemInfo({ NGINX_IMAGE: '', DOCKER_SOCKET: '/nonexistent/docker.sock' });
      const r = await detectNginxImage();
      assert.strictEqual(r.value, null);
      assert.strictEqual(r.autoDetected, true);
      assert.ok(r.error, 'attend une erreur quand la detection Docker echoue');
      console.log('  PASS  detectNginxImage() : NGINX_IMAGE absente -> tente la detection, erreur geree proprement'); pass++;
    } catch (e) { console.log('  FAIL  detectNginxImage() : NGINX_IMAGE absente\n        ' + e.message); fail++; }
  })();

  // ─── buildSystemInfo() ─────────────────────────────────────────────────────
  await (async () => {
    try {
      const { buildSystemInfo } = freshSystemInfo({ NGINX_IMAGE: 'fixed-image:latest' });
      const info = await buildSystemInfo();
      assert.ok(Array.isArray(info.categories) && info.categories.length > 0);
      assert.ok(Array.isArray(info.yamlBackedSettings) && info.yamlBackedSettings.length > 0);
      const generalCat = info.categories.find(c => c.name === 'Général');
      assert.ok(generalCat, 'categorie Général manquante');
      const imgRow = generalCat.entries.find(e => e.key === 'NGINX_IMAGE');
      assert.strictEqual(imgRow.value, 'fixed-image:latest');
      assert.strictEqual(imgRow.autoDetected, false);
      console.log('  PASS  buildSystemInfo() : regroupe par categorie et resout NGINX_IMAGE'); pass++;
    } catch (e) { console.log('  FAIL  buildSystemInfo()\n        ' + e.message); fail++; }
  })();

  // ─── Git configure via git.yml (bug reel, retour utilisateur v12.49.3) ──────
  // buildSystemInfo() affichait cfg.GIT_REPO_URL/cfg.GIT_TOKEN — resolus une
  // seule fois au demarrage depuis l env — meme quand l operateur configure
  // Git uniquement via git.yml (page Configuration), jamais touche a l env :
  // la page Systeme montrait alors ces deux champs comme non configures alors
  // que le deploiement Git fonctionnait reellement (chaque feature appelle
  // getGitCfg(), qui fusionne git.yml par-dessus l env). Reproduit ici avec un
  // CONFIG_DIR isole contenant un git.yml, et AUCUNE variable GIT_* dans l env.
  await (async () => {
    const fs = require('fs');
    const os = require('os');
    const path2 = require('path');
    const tmp = fs.mkdtempSync(path2.join(os.tmpdir(), 'sysinfo-git-'));
    fs.writeFileSync(path2.join(tmp, 'users.yml'), 'users: []\n');
    fs.writeFileSync(path2.join(tmp, 'git.yml'),
      'repo_url: https://forge.example.com/team/nginx-conf.git\n' +
      'branch: production\n' +
      'token: un-token-secret-de-test\n');
    const savedEnv = { ...process.env };
    // Retire toute variable GIT_* heritee de l environnement ambiant pour que
    // le test reproduise vraiment "configure uniquement via git.yml".
    for (const k of Object.keys(process.env)) if (k.startsWith('GIT_')) delete process.env[k];
    process.env.USERS_FILE = path2.join(tmp, 'users.yml');
    for (const id of [require.resolve('../lib/config'), require.resolve('../lib/git'), require.resolve('../lib/system-info')]) {
      delete require.cache[id];
    }
    try {
      const { buildSystemInfo } = require('../lib/system-info');
      const info = await buildSystemInfo();
      const gitCat = info.categories.find(c => c.name === 'Déploiement Git');
      assert.ok(gitCat, 'categorie Déploiement Git manquante');
      const repoRow  = gitCat.entries.find(e => e.key === 'GIT_REPO_URL');
      const tokenRow = gitCat.entries.find(e => e.key === 'GIT_TOKEN');
      const branchRow = gitCat.entries.find(e => e.key === 'GIT_BRANCH');
      assert.strictEqual(repoRow.value, 'https://forge.example.com/team/nginx-conf.git',
        'GIT_REPO_URL doit remonter depuis git.yml, pas seulement depuis l env');
      assert.strictEqual(tokenRow.value, true,
        'GIT_TOKEN doit etre signale configure quand il vient de git.yml');
      assert.strictEqual(branchRow.value, 'production');
      console.log('  PASS  buildSystemInfo() : GIT_REPO_URL/GIT_TOKEN/GIT_BRANCH configures via git.yml remontent correctement (sans rien dans l env)'); pass++;
    } catch (e) { console.log('  FAIL  buildSystemInfo() : Git via git.yml\n        ' + e.message); fail++; }
    process.env = savedEnv;
    for (const id of [require.resolve('../lib/config'), require.resolve('../lib/git'), require.resolve('../lib/system-info')]) {
      delete require.cache[id];
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  })();

  // ─── Traduction du contenu backend (categories, descriptions, reglages YAML) ──
  // Le frontend (public/assets/js/system-info.js) traduit ce contenu via des
  // tables de correspondance francais/fichier -> slug de cle data-i18n, avec
  // repli gracieux sur le texte francais brut si la cle manque. Un repli
  // silencieux ne doit pas dispenser de la traduire : ce test la rend visible
  // des qu une entree ou un reglage YAML est ajoute sans sa traduction.
  console.log('\ntraduction du contenu backend de la page Systeme (categories, descriptions, reglages YAML)');
  check('chaque categorie utilisee par ENTRIES a sa cle sysinfo.category.* dans les deux langues, ou est identique en fr/en', () => {
    const { ENTRIES } = require('../lib/system-info');
    const en = require('../public/assets/lang/en.json');
    const fr = require('../public/assets/lang/fr.json');
    // Categories identiques en francais et en anglais : pas besoin de cle.
    const IDENTICAL = new Set(['Docker', 'GeoIP', 'CrowdSec', 'GoAccess', 'Branding', 'Menu', 'GoDNS']);
    const SLUG = {
      'Général': 'general', 'Comportement de déploiement': 'deployBehavior',
      'Sécurité & sessions': 'security', 'Déploiement Git': 'gitDeploy',
      'Répertoires nginx': 'nginxDirs', 'Sync & mises à jour': 'syncUpdates', 'Rétention': 'retention',
      'Alertes': 'alerting',
    };
    const categories = new Set(ENTRIES.map(e => e.category));
    const missing = [];
    for (const cat of categories) {
      if (IDENTICAL.has(cat)) continue;
      const slug = SLUG[cat];
      if (!slug) { missing.push(cat + ' (aucun slug connu — mettre a jour SYSINFO_CATEGORY_SLUG cote frontend et SLUG ici)'); continue; }
      const key = 'sysinfo.category.' + slug;
      if (!(key in en) || !(key in fr)) missing.push(cat + ' -> ' + key);
    }
    assert.deepStrictEqual(missing, [], `categorie(s) sans traduction : ${missing.join(', ')}`);
  });

  check('chaque entree avec une description a sa cle sysinfo.entryDesc.<KEY> dans les deux langues', () => {
    const { ENTRIES } = require('../lib/system-info');
    const en = require('../public/assets/lang/en.json');
    const fr = require('../public/assets/lang/fr.json');
    const missing = ENTRIES.filter(e => e.description)
      .map(e => e.key)
      .filter(k => !(('sysinfo.entryDesc.' + k) in en) || !(('sysinfo.entryDesc.' + k) in fr));
    assert.deepStrictEqual(missing, [], `description(s) non traduite(s) : ${missing.join(', ')}`);
  });

  check('chaque reglage YAML a sa cle sysinfo.yamlPurpose.* dans les deux langues', () => {
    const { YAML_BACKED_SETTINGS } = require('../lib/system-info');
    const en = require('../public/assets/lang/en.json');
    const fr = require('../public/assets/lang/fr.json');
    const SLUG = {
      'users.yml': 'users_yml', 'smtp.yml': 'smtp_yml', 'notifications.yml': 'notifications_yml',
      'scheduler.yml': 'scheduler_yml', 'certbot.yml': 'certbot_yml', 'certbot-dns.yml': 'certbot_dns_yml',
      'godns.yml': 'godns_yml', 'geoipupdate.yml': 'geoipupdate_yml', 'error-pages.yml': 'error_pages_yml',
      'crowdsec.yml': 'crowdsec_yml', 'git.yml': 'git_yml', 'analyzer.yml': 'analyzer_yml',
      'blocklists.yml': 'blocklists_yml', 'deploy-tokens.yml': 'deploy_tokens_yml',
      'docker-autoconfig.yml': 'docker_autoconfig_yml',
      'menu.yml': 'menu_yml',
      'features.yml': 'features_yml',
    };
    const missing = [];
    for (const y of YAML_BACKED_SETTINGS) {
      const slug = SLUG[y.file];
      if (!slug) { missing.push(y.file + ' (aucun slug connu — mettre a jour SYSINFO_YAML_PURPOSE_SLUG cote frontend et SLUG ici)'); continue; }
      const key = 'sysinfo.yamlPurpose.' + slug;
      if (!(key in en) || !(key in fr)) missing.push(y.file + ' -> ' + key);
    }
    assert.deepStrictEqual(missing, [], `reglage(s) YAML sans traduction : ${missing.join(', ')}`);
  });

  check('public/assets/js/system-info.js reste la seule source de ces tables de correspondance (pas de doublon divergent)', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '..', 'public', 'assets', 'js', 'system-info.js'), 'utf8');
    assert.ok(/function sysinfoCategoryName\(name\)/.test(src));
    assert.ok(/function sysinfoEntryDesc\(entry\)/.test(src));
    assert.ok(/function sysinfoYamlPurpose\(y\)/.test(src));
    assert.ok(/function sysinfoLookup\(key, fallback\)/.test(src),
      'le repli gracieux (texte francais brut si la cle manque) doit rester en place');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
