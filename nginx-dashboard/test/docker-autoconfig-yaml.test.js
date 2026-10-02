'use strict';
/**
 * lib/docker-autoconfig-yaml.js — parsing de config/docker-autoconfig.yml et
 * le petit matcher de motifs (allowed_server_name_patterns).
 */
const assert = require('assert');
const { parseDockerAutoconfigYaml, parseAndValidate, matchesAnyPattern, globToRegExp } = require('../lib/docker-autoconfig-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseDockerAutoconfigYaml() — syntaxe');
check('fichier vide -> config vide, aucune erreur', () => {
  const { config, patterns, errors } = parseDockerAutoconfigYaml('');
  assert.deepStrictEqual(config, {});
  assert.deepStrictEqual(patterns, []);
  assert.deepStrictEqual(errors, []);
});
check('reglages plats + liste de motifs, tout parse', () => {
  const { config, patterns, errors } = parseDockerAutoconfigYaml([
    'enable: true',
    'require_approval: false',
    'poll_interval_sec: 30',
    'allowed_server_name_patterns:',
    '  - "*.example.com"',
    '  - internal.example.lan',
  ].join('\n'));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, true);
  assert.strictEqual(config.require_approval, false);
  assert.strictEqual(config.poll_interval_sec, 30);
  assert.deepStrictEqual(patterns, ['*.example.com', 'internal.example.lan']);
});
check('commentaires et lignes vides ignores', () => {
  const { config, errors } = parseDockerAutoconfigYaml('# commentaire\n\nenable: true\n');
  assert.strictEqual(config.enable, true);
  assert.deepStrictEqual(errors, []);
});
check('ligne non reconnue -> erreur avec numero de ligne', () => {
  const { errors } = parseDockerAutoconfigYaml('enable: true\nceci n est pas du yaml valide ici');
  assert.ok(errors.some(e => e.startsWith('Ligne 2')));
});

console.log('\nparseAndValidate() — defauts');
check('fichier absent/vide -> require_approval actif par defaut (choix de securite) ; enable desactive par defaut (v12.41.0, opt-in)', () => {
  const { settings } = parseAndValidate('');
  assert.strictEqual(settings.enable, false);
  assert.strictEqual(settings.requireApproval, true);
  assert.strictEqual(settings.pollIntervalSec, 15);
  assert.strictEqual(settings.eventsEnable, true);
  assert.strictEqual(settings.eventsDebounceMs, 3000);
  assert.deepStrictEqual(settings.allowedServerNamePatterns, []);
});
check('enable: true explicite -> active', () => {
  const { settings } = parseAndValidate('enable: true');
  assert.strictEqual(settings.enable, true);
});
check('events_enable: false explicitement respecte', () => {
  const { settings } = parseAndValidate('events_enable: false');
  assert.strictEqual(settings.eventsEnable, false);
});
check('events_debounce_ms trop bas (< 500) -> retombe sur le defaut', () => {
  const { settings } = parseAndValidate('events_debounce_ms: 10');
  assert.strictEqual(settings.eventsDebounceMs, 3000);
});
check('events_debounce_ms valide -> respecte', () => {
  const { settings } = parseAndValidate('events_debounce_ms: 5000');
  assert.strictEqual(settings.eventsDebounceMs, 5000);
});
check('require_approval: false explicitement respecte', () => {
  const { settings } = parseAndValidate('require_approval: false');
  assert.strictEqual(settings.requireApproval, false);
});
check('poll_interval_sec trop bas (< 5) -> retombe sur le defaut', () => {
  const { settings } = parseAndValidate('poll_interval_sec: 1');
  assert.strictEqual(settings.pollIntervalSec, 15);
});
check('enable: false respecte', () => {
  const { settings } = parseAndValidate('enable: false');
  assert.strictEqual(settings.enable, false);
});

console.log('\nmatchesAnyPattern() / globToRegExp()');
check('motif exact', () => {
  assert.ok(matchesAnyPattern('internal.example.lan', ['internal.example.lan']));
  assert.ok(!matchesAnyPattern('other.example.lan', ['internal.example.lan']));
});
check('wildcard "*" en tete', () => {
  assert.ok(matchesAnyPattern('app.example.com', ['*.example.com']));
  assert.ok(matchesAnyPattern('a.b.example.com', ['*.example.com']));
  assert.ok(!matchesAnyPattern('example.com', ['*.example.com']), '"*." doit exiger un sous-domaine, pas matcher le domaine nu par accident du "." litteral');
});
check('aucun motif -> jamais de correspondance automatique', () => {
  assert.ok(!matchesAnyPattern('app.example.com', []));
  assert.ok(!matchesAnyPattern('app.example.com', undefined));
});
check('un caractere special de regex dans le motif est neutralise (pas d injection regex)', () => {
  assert.ok(!matchesAnyPattern('anyexamplexcom', ['*.example.com']), 'le "." du motif doit rester litteral, jamais "n importe quel caractere"');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
