'use strict';
const assert = require('assert');
const { parseBlocklistYaml, validateSource, parseAndValidate } = require('../lib/blocklist-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseBlocklistYaml() — syntaxe');
check('cles racine + une source, tout parse correctement', () => {
  const text = [
    'enable: true',
    'interval_cron: "0 3 * * *"',
    'block_action: deny_403',
    'sources:',
    '  - name: datashield',
    '    url: "https://example.org/list.txt"',
    '    enable: true',
  ].join('\n');
  const { config, sources, errors } = parseBlocklistYaml(text);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, true);
  assert.strictEqual(config.interval_cron, '0 3 * * *');
  assert.strictEqual(config.block_action, 'deny_403');
  assert.strictEqual(sources.length, 1);
  assert.strictEqual(sources[0].name, 'datashield');
  assert.strictEqual(sources[0].url, 'https://example.org/list.txt');
  assert.strictEqual(sources[0].enable, true);
});

check('plusieurs sources, commentaires et lignes vides ignores', () => {
  const text = [
    '# commentaire d en-tete',
    'enable: true',
    '',
    'sources:',
    '  - name: source-un',
    '    url: "https://a.example/list.txt"',
    '  # commentaire au milieu de la liste',
    '  - name: source-deux',
    '    url: "https://b.example/list.txt"',
    '    enable: false',
  ].join('\n');
  const { sources, errors } = parseBlocklistYaml(text);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(sources.length, 2);
  assert.strictEqual(sources[1].enable, false);
});

check('ligne non reconnue a l interieur de la liste -> erreur avec numero de ligne', () => {
  const text = [
    'sources:',
    '  - name: ok',
    '    url: "https://a.example/list.txt"',
    'ceci n est pas une cle racine valide sans les deux points',
  ].join('\n');
  const { errors } = parseBlocklistYaml(text);
  assert.strictEqual(errors.length, 1);
  assert.ok(errors[0].startsWith('Ligne 4'));
});

check('fichier vide -> aucune source, aucune erreur', () => {
  const { config, sources, errors } = parseBlocklistYaml('');
  assert.deepStrictEqual(config, {});
  assert.deepStrictEqual(sources, []);
  assert.deepStrictEqual(errors, []);
});

console.log('\nvalidateSource()');
check('source valide -> aucune erreur', () => {
  assert.deepStrictEqual(validateSource({ name: 'ok-1', url: 'https://example.org/x.txt' }, new Set()), []);
});
check('nom manquant -> erreur', () => {
  const errs = validateSource({ url: 'https://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"name"')));
});
check('nom avec caracteres invalides -> erreur', () => {
  const errs = validateSource({ name: 'a b/c', url: 'https://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"name"')));
});
check('nom deja utilise -> erreur', () => {
  const seen = new Set(['dup']);
  const errs = validateSource({ name: 'dup', url: 'https://example.org/x.txt' }, seen);
  assert.ok(errs.some(e => e.includes('deja utilise')));
});
check('url manquante -> erreur', () => {
  const errs = validateSource({ name: 'ok-1' }, new Set());
  assert.ok(errs.some(e => e.includes('"url"')));
});
check('url sans schema http(s) -> erreur (evite ftp://, file://, etc.)', () => {
  const errs = validateSource({ name: 'ok-1', url: 'ftp://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"url"')));
});

console.log('\nparseAndValidate()');
check('une source invalide n empeche pas les autres d etre retenues', () => {
  const text = [
    'sources:',
    '  - name: bonne-source',
    '    url: "https://a.example/list.txt"',
    '  - name: "invalide car pas de url"',
    '  - name: autre-bonne',
    '    url: "https://b.example/list.txt"',
  ].join('\n');
  const { valid, errors } = parseAndValidate(text);
  assert.strictEqual(valid.length, 2);
  assert.deepStrictEqual(valid.map(s => s.name), ['bonne-source', 'autre-bonne']);
  assert.ok(errors.length >= 1);
});

check('parametres par defaut appliques quand absents', () => {
  const { settings } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(settings.enable, true);
  assert.strictEqual(settings.intervalCron, '0 */6 * * *');
  assert.strictEqual(settings.blockAction, 'deny_403');
  assert.strictEqual(settings.hitLogging.enable, false);
  assert.strictEqual(settings.hitLogging.method, 'dedicated');
});

check('hit_logging_enable/hit_logging_method lus quand presents', () => {
  const { settings } = parseAndValidate('hit_logging_enable: true\nhit_logging_method: approx\nsources: []');
  assert.strictEqual(settings.hitLogging.enable, true);
  assert.strictEqual(settings.hitLogging.method, 'approx');
});

check('hit_logging_method invalide retombe sur dedicated', () => {
  const { settings } = parseAndValidate('hit_logging_method: n_importe_quoi\nsources: []');
  assert.strictEqual(settings.hitLogging.method, 'dedicated');
});

check('block_action invalide retombe sur deny_403 (jamais une valeur non reconnue par le generateur de snippet)', () => {
  const { settings } = parseAndValidate('block_action: rm_rf_slash\nsources: []');
  assert.strictEqual(settings.blockAction, 'deny_403');
});

check('enable: false au niveau racine est respecte', () => {
  const { settings } = parseAndValidate('enable: false\nsources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(settings.enable, false);
});

check('source enable par defaut a true si absent', () => {
  const { valid } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(valid[0].enable, true);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
