'use strict';
/**
 * error-pages est le plus simple des trois conteneurs annexes geres depuis
 * le dashboard (pas de secret, pas de volume) — l essentiel a verifier est
 * que son nom Docker reste EXACTEMENT "error-pages" (pas de prefixe
 * "nginx-dashboard-..." comme les autres), puisque le snippet nginx fourni
 * en exemple (global-error.conf) le resout par ce nom precis.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const EP = require('../features/error-pages');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nnom du conteneur — doit rester "error-pages" (regression : cablage nginx deja fourni)');
check('CONTAINER_NAME est exactement "error-pages", pas prefixe', () => {
  assert.strictEqual(EP.CONTAINER_NAME, 'error-pages');
});

console.log('\nloadErrorPagesConfig — fichier absent, booleen enable');
check('fichier absent -> null, pas d exception', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'errpagestest-noconf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/error-pages')];
  const EP2 = require('../features/error-pages');
  assert.strictEqual(EP2.loadErrorPagesConfig(), null);
});
check('enable type correctement, template_name preserve tel quel', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'errpagestest-conf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  fs.writeFileSync(path.join(dir, 'error-pages.yml'), [
    'enable: true',
    'container_image: tarampampam/error-pages:5',
    'template_name: matrix',
    '',
  ].join('\n'));
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/error-pages')];
  const EP2 = require('../features/error-pages');
  const cfg = EP2.loadErrorPagesConfig();
  assert.strictEqual(cfg.enable, true);
  assert.strictEqual(cfg.template_name, 'matrix');
  assert.strictEqual(cfg.container_image, 'tarampampam/error-pages:5');
});

console.log('\nensureContainerAtBoot — reconstitution apres redemarrage de l hote (meme piege que certbot/geoipupdate)');
(async () => {
  const check2 = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
    catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

  await check2('error-pages.yml absent -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'errpagesboot-none-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/error-pages')];
    const EP2 = require('../features/error-pages');
    const r = await EP2.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'not enabled');
  });

  await check2('active mais Docker injoignable -> skipped proprement, pas d exception', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'errpagesboot-nodocker-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'error-pages.yml'), 'enable: true\n');
    process.env.DOCKER_SOCKET = path.join(dir, 'no-such-docker.sock');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/error-pages')];
    const EP2 = require('../features/error-pages');
    const r = await EP2.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'docker unavailable');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
