'use strict';
/**
 * lib/feature-flags.js — priorite ENV > config/features.yml > defaut, meme
 * discipline que resolveToggle() dans lib/menu-visibility.js
 * (test/menu-visibility.test.js).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'feature-flags-'));
fs.mkdirSync(path.join(tmp, 'config'), { recursive: true });
process.env.CONFIG_DIR = path.join(tmp, 'config');
process.env.USERS_FILE = path.join(tmp, 'config', 'users.yml');

console.log('\nlib/feature-flags.js');

function fresh() {
  delete require.cache[require.resolve('../lib/feature-flags')];
  delete require.cache[require.resolve('../lib/config')];
  return require('../lib/feature-flags');
}
function writeFeatures(content) {
  fs.writeFileSync(path.join(tmp, 'config', 'features.yml'), content);
}
function rmFeatures() {
  try { fs.rmSync(path.join(tmp, 'config', 'features.yml')); } catch { /* deja absent */ }
}

check('sans fichier ni env -> defaut (false pour alerting)', () => {
  rmFeatures();
  delete process.env.ALERTING_ENABLE;
  const { resolveFlag } = fresh();
  assert.deepStrictEqual(resolveFlag('alerting'), { enabled: false, source: 'default' });
});

check('config/features.yml: alerting_enable: true -> yaml l emporte sur le defaut', () => {
  writeFeatures('alerting_enable: true\n');
  delete process.env.ALERTING_ENABLE;
  const { resolveFlag } = fresh();
  assert.deepStrictEqual(resolveFlag('alerting'), { enabled: true, source: 'yaml' });
});

check('ALERTING_ENABLE=false (env) l emporte sur yaml: true', () => {
  writeFeatures('alerting_enable: true\n');
  process.env.ALERTING_ENABLE = 'false';
  const { resolveFlag } = fresh();
  assert.deepStrictEqual(resolveFlag('alerting'), { enabled: false, source: 'env' });
  delete process.env.ALERTING_ENABLE;
});

check('ALERTING_ENABLE="" (definie mais vide) ne compte pas, retombe sur yaml/defaut', () => {
  rmFeatures();
  process.env.ALERTING_ENABLE = '';
  const { resolveFlag } = fresh();
  assert.deepStrictEqual(resolveFlag('alerting'), { enabled: false, source: 'default' });
  delete process.env.ALERTING_ENABLE;
});

check('valeur env non reconnue ("peut-etre") est ignoree avec avertissement, retombe sur yaml/defaut', () => {
  rmFeatures();
  process.env.ALERTING_ENABLE = 'peut-etre';
  const { resolveFlag } = fresh();
  assert.deepStrictEqual(resolveFlag('alerting'), { enabled: false, source: 'default' });
  delete process.env.ALERTING_ENABLE;
});

check('isFeatureEnabled() est un raccourci pour resolveFlag(key).enabled', () => {
  writeFeatures('alerting_enable: true\n');
  const { isFeatureEnabled } = fresh();
  assert.strictEqual(isFeatureEnabled('alerting'), true);
});

rmFeatures();
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
