'use strict';
/** lib/challenge-settings.js : challenge.yml surcharge blocklists.yml (v12.65.0). */
const assert = require('assert');
const { challengeOverridesFromText } = require('../lib/challenge-settings');
const { parseAndValidate } = require('../lib/blocklist-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

check('seules les cles challenge_* sont reprises', () => {
  const o = challengeOverridesFromText('# c\nchallenge_enable: true\nchallenge_engine: anubis\nenable: true\nsecret: x\n');
  assert.deepStrictEqual(o, { challenge_enable: true, challenge_engine: 'anubis' });
});
check('texte vide ou invalide : aucun reglage', () => {
  assert.deepStrictEqual(challengeOverridesFromText(''), {});
});
check('challenge.yml l emporte sur blocklists.yml, sans blocklist active', () => {
  const r = parseAndValidate('enable: false\nchallenge_enable: false\nchallenge_engine: builtin\n',
    challengeOverridesFromText('challenge_enable: true\nchallenge_engine: anubis\n'));
  assert.strictEqual(r.settings.enable, false);
  assert.strictEqual(r.settings.challenge.enable, true);
  assert.strictEqual(r.settings.challenge.engine, 'anubis');
});
check('valeur dangereuse dans challenge.yml refusee comme dans blocklists.yml', () => {
  const r = parseAndValidate('', challengeOverridesFromText('challenge_upstream: "a;b"\n'));
  assert.ok(r.errors.some(e => /challenge_upstream/.test(e)));
});
check('sans surcharge : comportement inchange', () => {
  const r = parseAndValidate('challenge_enable: true\n');
  assert.strictEqual(r.settings.challenge.enable, true);
});
console.log(`\n${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
