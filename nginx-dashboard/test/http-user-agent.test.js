'use strict';
/** User-Agent unique des requetes sortantes (v12.66.0). */
const assert = require('assert');
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const ua = (env) => execFileSync(process.execPath, ['-e', "console.log(require('./lib/config').HTTP_USER_AGENT)"],
  { cwd: path.join(__dirname, '..'), env: { ...process.env, SESSION_SECRET: 'x'.repeat(40), ...env } }).toString().trim();

check('defaut : NginxControl, sans version', () => assert.strictEqual(ua({ HTTP_USER_AGENT: '' }), 'NginxControl'));
check('surcharge valide', () => assert.strictEqual(ua({ HTTP_USER_AGENT: 'MonCtl/1' }), 'MonCtl/1'));
check('valeur invalide (espace, guillemet, retour ligne) : retour au defaut', () => {
  assert.strictEqual(ua({ HTTP_USER_AGENT: 'a b' }), 'NginxControl');
  assert.strictEqual(ua({ HTTP_USER_AGENT: 'a"b' }), 'NginxControl');
});
check('plus aucun User-Agent code en dur dans les requetes sortantes', () => {
  const root = path.join(__dirname, '..');
  const hard = [];
  for (const dir of ['lib', 'features', '.']) {
    const d = path.join(root, dir);
    for (const f of fs.readdirSync(d)) {
      if (!f.endsWith('.js')) continue;
      const src = fs.readFileSync(path.join(d, f), 'utf8');
      if (/['"]user-agent['"]\s*:\s*['"]/i.test(src)) hard.push(path.join(dir, f));
    }
  }
  assert.deepStrictEqual(hard, []);
});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
