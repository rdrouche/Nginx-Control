'use strict';
/**
 * getGoaccessCfg() (features/goaccess.js) — meme regle de fusion YAML/env.
 * refresh_seconds merite un test dedie : c est un entier parse depuis une
 * chaine, donc une valeur invalide ou vide dans le YAML doit retomber
 * proprement sur l entier issu de l env plutot que de produire NaN/0.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshEnv(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gacfg-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  for (const k of ['GOACCESS_IMAGE', 'GOACCESS_LOG_FORMAT', 'GOACCESS_REFRESH', 'DIR_GOACCESS']) delete process.env[k];
  Object.assign(process.env, env || {});
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/goaccess')];
  return { dir, ga: require('../features/goaccess') };
}

console.log('\ngetGoaccessCfg() — sans fichier YAML');
(() => {
  const { dir, ga } = freshEnv({ GOACCESS_IMAGE: 'env/goaccess:custom', GOACCESS_REFRESH: '45' });
  check('retombe sur les variables Docker', () => {
    const g = ga.getGoaccessCfg();
    assert.strictEqual(g.image, 'env/goaccess:custom');
    assert.strictEqual(g.refreshSec, 45);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGoaccessCfg() — YAML present, champs vides');
(() => {
  const { dir, ga } = freshEnv({ GOACCESS_IMAGE: 'env/goaccess:custom', GOACCESS_REFRESH: '45' });
  fs.writeFileSync(path.join(dir, 'goaccess.yml'), [
    'container_image:',
    'log_format:',
    'refresh_seconds:',
    '',
  ].join('\n'));
  check('champs vides -> env conserve, y compris le refresh entier', () => {
    const g = ga.getGoaccessCfg();
    assert.strictEqual(g.image, 'env/goaccess:custom');
    assert.strictEqual(g.refreshSec, 45);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGoaccessCfg() — YAML prioritaire');
(() => {
  const { dir, ga } = freshEnv({ GOACCESS_IMAGE: 'env/goaccess:custom', GOACCESS_REFRESH: '45' });
  fs.writeFileSync(path.join(dir, 'goaccess.yml'), [
    'container_image: yaml/goaccess:pinned',
    'log_format: CADDY',
    'refresh_seconds: 10',
    '',
  ].join('\n'));
  check('le YAML l emporte champ par champ', () => {
    const g = ga.getGoaccessCfg();
    assert.strictEqual(g.image, 'yaml/goaccess:pinned');
    assert.strictEqual(g.logFormat, 'CADDY');
    assert.strictEqual(g.refreshSec, 10);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGoaccessCfg() — refresh_seconds invalide retombe sur env');
(() => {
  const { dir, ga } = freshEnv({ GOACCESS_REFRESH: '45' });
  fs.writeFileSync(path.join(dir, 'goaccess.yml'), [
    'refresh_seconds: pas-un-nombre',
    '',
  ].join('\n'));
  check('une valeur non numerique ne produit pas NaN, retombe sur env', () => {
    const g = ga.getGoaccessCfg();
    assert.strictEqual(g.refreshSec, 45);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGoaccessCfg() — DIR_GOACCESS reste hors YAML');
(() => {
  const { dir, ga } = freshEnv({ DIR_GOACCESS: '/nginx/goaccess' });
  fs.writeFileSync(path.join(dir, 'goaccess.yml'), [
    'dir_goaccess: /tentative/malveillante',
    '',
  ].join('\n'));
  check('un champ dir_goaccess dans le YAML n a aucun effet, ce n est pas un champ reconnu', () => {
    const g = ga.getGoaccessCfg();
    assert.ok(!('dirGoaccess' in g));
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
