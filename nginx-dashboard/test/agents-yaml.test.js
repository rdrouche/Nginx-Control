'use strict';
const assert = require('assert');
const { parseAndValidate } = require('../lib/agents-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

check('fichier vide -> tous les defauts, y compris tunnel et certbot_retry_minutes ; enable desactive par defaut (v12.41.0, opt-in)', () => {
  const { settings, errors } = parseAndValidate('');
  assert.strictEqual(errors.length, 0);
  assert.deepStrictEqual(settings, {
    enable: false, offlineAfterSec: 90, maxVhostsPerAgent: 50,
    tunnelEnable: true, tunnelTarget: 'http://nginx-dashboard:3000',
    certbotRetryMinutes: 15, allowedListenPorts: null,
  });
});

check('enable: true explicite -> active', () => {
  const { settings } = parseAndValidate('enable: true\n');
  assert.strictEqual(settings.enable, true);
});

console.log('\nallowed_listen_ports (fix, audit report Basse/"Agents (dashboard)")');
check('absent -> null (non-regression : aucune restriction par defaut)', () => {
  const { settings, errors } = parseAndValidate('');
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(settings.allowedListenPorts, null);
});
check('liste valide -> tableau de nombres', () => {
  const { settings, errors } = parseAndValidate('allowed_listen_ports: "80,443,8443"\n');
  assert.strictEqual(errors.length, 0);
  assert.deepStrictEqual(settings.allowedListenPorts, [80, 443, 8443]);
});
check('liste avec un port hors bornes -> erreur, restriction ignoree (repli sur null = non restreint)', () => {
  const { settings, errors } = parseAndValidate('allowed_listen_ports: "80,99999"\n');
  assert.ok(errors.length > 0);
  assert.strictEqual(settings.allowedListenPorts, null);
});

check('certbot_retry_minutes valide est repris tel quel', () => {
  const { settings, errors } = parseAndValidate('certbot_retry_minutes: 30\n');
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(settings.certbotRetryMinutes, 30);
});

check('certbot_retry_minutes invalide (< 1) -> repli sur 15, meme defaut que docker-autoconfig.yml', () => {
  const { settings } = parseAndValidate('certbot_retry_minutes: 0\n');
  assert.strictEqual(settings.certbotRetryMinutes, 15);
});

check('tunnel_target valide est repris tel quel', () => {
  const { settings, errors } = parseAndValidate('tunnel_target: http://mon-dashboard:4000\n');
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(settings.tunnelTarget, 'http://mon-dashboard:4000');
});

check('tunnel_target invalide -> erreur + repli sur la valeur par defaut (jamais une valeur non ancree ecrite dans nginx)', () => {
  const { settings, errors } = parseAndValidate('tunnel_target: not-a-url\n');
  assert.strictEqual(errors.length, 1);
  assert.ok(/tunnel_target invalide/.test(errors[0]));
  assert.strictEqual(settings.tunnelTarget, 'http://nginx-dashboard:3000');
});

check('tunnel_enable: false est respecte', () => {
  const { settings } = parseAndValidate('tunnel_enable: false\n');
  assert.strictEqual(settings.tunnelEnable, false);
});

check('enable/offline_after_sec/max_vhosts_per_agent inchanges par cet ajout', () => {
  const { settings } = parseAndValidate('enable: false\noffline_after_sec: 30\nmax_vhosts_per_agent: 5\n');
  assert.strictEqual(settings.enable, false);
  assert.strictEqual(settings.offlineAfterSec, 30);
  assert.strictEqual(settings.maxVhostsPerAgent, 5);
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
