'use strict';
/**
 * getCrowdsecCfg() (lib/crowdsec-cfg.js) — meme regle de fusion que
 * getGitCfg()/ANALYZER_DEFAULT_IMAGE : YAML prioritaire, env en repli.
 * local_only merite un test dedie car c est un booleen : une chaine vide
 * doit retomber sur l env, alors que "false" explicite dans le YAML doit
 * bien l emporter (et ne pas etre confondu avec une chaine vide/absente).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshEnv(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cseccfg-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  for (const k of ['CROWDSEC_URL', 'CROWDSEC_API_KEY', 'CROWDSEC_PROMETHEUS_URL', 'CROWDSEC_PROM_URL', 'CROWDSEC_LOCAL_ONLY', 'CROWDSEC_MACHINE_ID', 'CROWDSEC_MACHINE_PASSWORD']) {
    delete process.env[k];
  }
  Object.assign(process.env, env || {});
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/crowdsec-cfg')];
  return { dir, cc: require('../lib/crowdsec-cfg') };
}

console.log('\ngetCrowdsecCfg() — sans fichier YAML');
(() => {
  const { dir, cc } = freshEnv({ CROWDSEC_URL: 'http://env-crowdsec:8080', CROWDSEC_LOCAL_ONLY: 'true' });
  check('retombe sur les variables Docker', () => {
    const c = cc.getCrowdsecCfg();
    assert.strictEqual(c.url, 'http://env-crowdsec:8080');
    assert.strictEqual(c.localOnly, true);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetCrowdsecCfg() — YAML present, champs vides');
(() => {
  const { dir, cc } = freshEnv({ CROWDSEC_URL: 'http://env-crowdsec:8080', CROWDSEC_LOCAL_ONLY: 'true' });
  fs.writeFileSync(path.join(dir, 'crowdsec.yml'), [
    'url:',
    'api_key:',
    'prometheus_url:',
    'local_only:',
    'machine_id:',
    'machine_password:',
    '',
  ].join('\n'));
  check('champs vides -> valeurs env conservees, y compris le booleen', () => {
    const c = cc.getCrowdsecCfg();
    assert.strictEqual(c.url, 'http://env-crowdsec:8080');
    assert.strictEqual(c.localOnly, true);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetCrowdsecCfg() — YAML prioritaire, y compris local_only: false explicite');
(() => {
  const { dir, cc } = freshEnv({ CROWDSEC_URL: 'http://env-crowdsec:8080', CROWDSEC_LOCAL_ONLY: 'true' });
  fs.writeFileSync(path.join(dir, 'crowdsec.yml'), [
    'url: http://yaml-crowdsec:8080',
    'api_key: yaml-bouncer-key',
    'prometheus_url: http://yaml-crowdsec:6060/metrics',
    'local_only: false',
    'machine_id: yaml-watcher',
    'machine_password: yaml-pw',
    '',
  ].join('\n'));
  check('le YAML l emporte, un false explicite n est pas pris pour une valeur absente', () => {
    const c = cc.getCrowdsecCfg();
    assert.strictEqual(c.url, 'http://yaml-crowdsec:8080');
    assert.strictEqual(c.apiKey, 'yaml-bouncer-key');
    assert.strictEqual(c.promUrl, 'http://yaml-crowdsec:6060/metrics');
    assert.strictEqual(c.localOnly, false);
    assert.strictEqual(c.machineId, 'yaml-watcher');
    assert.strictEqual(c.machinePassword, 'yaml-pw');
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
