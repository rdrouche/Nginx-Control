'use strict';
/**
 * L agent d analyse (features/analyzer.js) etait deja gere en conteneur
 * (pull/start/stop, deja utilise en production) mais n avait encore aucun
 * test dedie. Ce fichier couvre ce qui a ete ajoute pour l aligner sur les
 * trois autres conteneurs geres (certbot/geoipupdate/error-pages) : le
 * chargement de configuration, et ensureContainerAtBoot() — la
 * reconstitution apres redemarrage de l hote, meme piege que les trois
 * autres (RestartPolicy: unless-stopped ne couvre pas un conteneur jamais
 * cree).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nloadAnalyzerConfig — fichier absent, types corrects');
check('fichier absent -> null, pas d exception', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzertest-noconf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/analyzer')];
  const A = require('../features/analyzer');
  assert.strictEqual(A.loadAnalyzerConfig(), null);
});

check('enable et les nombres sont types correctement', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzertest-conf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  fs.writeFileSync(path.join(dir, 'analyzer.yml'), [
    'enable: true',
    'container_image: forge.rdr-it.com/dockerfiles/nginx-analyzer:2.0.0',
    'host_data_path: /containers/analyzer',
    'learning_days: 14',
    'sigma_threshold: 5',
    '',
  ].join('\n'));
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/analyzer')];
  const A = require('../features/analyzer');
  const cfg = A.loadAnalyzerConfig();
  assert.strictEqual(cfg.enable, true);
  assert.strictEqual(cfg.container_image, 'forge.rdr-it.com/dockerfiles/nginx-analyzer:2.0.0');
  assert.strictEqual(cfg.learning_days, 14);
  assert.strictEqual(cfg.sigma_threshold, 5);
});

console.log('\nANALYZER_DEFAULT_IMAGE — image par defaut configurable au build (Dockerfile ARG/ENV)');
check('sans ANALYZER_DEFAULT_IMAGE -> le defaut historique reste inchange', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzertest-defimg-a-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete process.env.ANALYZER_DEFAULT_IMAGE;
  delete require.cache[require.resolve('../lib/config')];
  const cfg = require('../lib/config');
  assert.strictEqual(cfg.ANALYZER_DEFAULT_IMAGE, 'forge.rdr-it.com/dockerfiles/nginx-analyzer:latest');
});
check('avec ANALYZER_DEFAULT_IMAGE -> surcharge prise en compte par lib/config', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzertest-defimg-b-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  process.env.ANALYZER_DEFAULT_IMAGE = 'registry.example.com/mon-fork/nginx-analyzer:latest';
  delete require.cache[require.resolve('../lib/config')];
  const cfg = require('../lib/config');
  assert.strictEqual(cfg.ANALYZER_DEFAULT_IMAGE, 'registry.example.com/mon-fork/nginx-analyzer:latest');
  delete process.env.ANALYZER_DEFAULT_IMAGE;
});
// Verification bout-en-bout (la route /api/analyzer/config reflete bien la
// surcharge quand container_image est absent d analyzer.yml) : voir
// analyzer-routes.test.js.

console.log('\nensureContainerAtBoot — reconstitution apres redemarrage de l hote (meme piege que certbot/geoipupdate/error-pages)');
(async () => {
  const check2 = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
    catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

  await check2('analyzer.yml absent -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerboot-none-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/analyzer')];
    const A = require('../features/analyzer');
    const r = await A.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'not enabled');
  });

  await check2('active mais sans host_data_path -> skipped, jamais d appel Docker (l etat serait perdu)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerboot-nopath-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'analyzer.yml'), 'enable: true\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/analyzer')];
    const A = require('../features/analyzer');
    const r = await A.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'host_data_path missing');
  });

  await check2('active, host_data_path present, Docker injoignable -> skipped proprement, pas d exception', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerboot-nodocker-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'analyzer.yml'), 'enable: true\nhost_data_path: /containers/analyzer\n');
    process.env.DOCKER_SOCKET = path.join(dir, 'no-such-docker.sock');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/analyzer')];
    const A = require('../features/analyzer');
    const r = await A.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'docker unavailable');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
