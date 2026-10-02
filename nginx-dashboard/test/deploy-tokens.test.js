'use strict';
/**
 * lib/deploy-tokens.js — parsing/validation of config/deploy-tokens.yml, and
 * findByToken()'s lookup. The route-level enforcement (which endpoints a
 * deploy token may even reach) is covered separately in
 * test/deploy-tokens-routes.test.js, since that lives in server.js's
 * dispatch, not here.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-tokens-'));
process.env.USERS_FILE = path.join(dir, 'config', 'users.yml');
fs.mkdirSync(path.dirname(process.env.USERS_FILE), { recursive: true });
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const DT = require('../lib/deploy-tokens');
const { DEPLOY_TOKENS_FILE } = require('../lib/config');

const write = (text) => fs.writeFileSync(DEPLOY_TOKENS_FILE, text);

console.log('\nparseDeployTokensYaml() — syntaxe');
check('un jeton complet, tout parse correctement', () => {
  const { tokens, errors } = DT.parseDeployTokensYaml([
    'tokens:',
    '  - name: forgejo-ci',
    '    token: "0123456789abcdef"',
    '    enable: true',
    '    actions: [pull, test, deploy, backup]',
  ].join('\n'));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(tokens.length, 1);
  assert.strictEqual(tokens[0].name, 'forgejo-ci');
  assert.deepStrictEqual(tokens[0].actions, ['pull', 'test', 'deploy', 'backup']);
});
check('fichier vide -> aucun jeton, aucune erreur', () => {
  const { tokens, errors } = DT.parseDeployTokensYaml('');
  assert.deepStrictEqual(tokens, []);
  assert.deepStrictEqual(errors, []);
});
check('actions vide "[]" -> tableau vide au parsing (le defaut "toutes" s applique plus tard, dans parseAndValidate)', () => {
  const { tokens } = DT.parseDeployTokensYaml('tokens:\n  - name: x\n    token: "0123456789abcdef"\n    actions: []');
  assert.deepStrictEqual(tokens[0].actions, []);
});

console.log('\nvalidateToken()');
check('jeton valide -> aucune erreur', () => {
  assert.deepStrictEqual(DT.validateToken({ name: 'ok-1', token: '0123456789abcdef' }, new Set()), []);
});
check('nom manquant -> erreur', () => {
  const errs = DT.validateToken({ token: '0123456789abcdef' }, new Set());
  assert.ok(errs.some(e => e.includes('"name"')));
});
check('token trop court -> erreur (evite un jeton devinable)', () => {
  const errs = DT.validateToken({ name: 'ok-1', token: 'trop-court' }, new Set());
  assert.ok(errs.some(e => e.includes('"token"')));
});
check('nom deja utilise -> erreur', () => {
  const seen = new Set(['dup']);
  const errs = DT.validateToken({ name: 'dup', token: '0123456789abcdef' }, seen);
  assert.ok(errs.some(e => e.includes('deja utilise')));
});
check('action inconnue dans "actions" -> erreur', () => {
  const errs = DT.validateToken({ name: 'ok-1', token: '0123456789abcdef', actions: ['deploy', 'delete-everything'] }, new Set());
  assert.ok(errs.some(e => e.includes('actions')));
});

console.log('\nparseAndValidate() — normalisation des defauts');
check('"actions" absent -> les quatre actions autorisees par defaut', () => {
  write('tokens:\n  - name: x\n    token: "0123456789abcdef"');
  const { valid } = DT.parseAndValidate(fs.readFileSync(DEPLOY_TOKENS_FILE, 'utf8'));
  assert.deepStrictEqual(valid[0].actions.sort(), ['backup', 'deploy', 'pull', 'test']);
});
check('"enable" absent -> true par defaut', () => {
  const { valid } = DT.parseAndValidate('tokens:\n  - name: x\n    token: "0123456789abcdef"');
  assert.strictEqual(valid[0].enable, true);
});
check('un jeton invalide n empeche pas les autres d etre retenus', () => {
  const { valid, errors } = DT.parseAndValidate([
    'tokens:',
    '  - name: bon-jeton',
    '    token: "0123456789abcdef"',
    '  - name: "invalide car pas de token"',
    '  - name: autre-bon',
    '    token: "fedcba9876543210"',
  ].join('\n'));
  assert.strictEqual(valid.length, 2);
  assert.deepStrictEqual(valid.map(v => v.name), ['bon-jeton', 'autre-bon']);
  assert.ok(errors.length >= 1);
});

console.log('\nfindByToken() — recherche, jamais un faux positif');
write([
  'tokens:',
  '  - name: full-access',
  '    token: "aaaa1111aaaa1111"',
  '    enable: true',
  '  - name: test-only',
  '    token: "bbbb2222bbbb2222"',
  '    enable: true',
  '    actions: [test]',
  '  - name: disabled-token',
  '    token: "cccc3333cccc3333"',
  '    enable: false',
].join('\n'));
check('jeton valide et active -> trouve, avec ses actions', () => {
  const r = DT.findByToken('aaaa1111aaaa1111');
  assert.strictEqual(r.name, 'full-access');
  assert.deepStrictEqual(r.actions.sort(), ['backup', 'deploy', 'pull', 'test']);
});
check('jeton restreint -> ses actions sont bien limitees', () => {
  const r = DT.findByToken('bbbb2222bbbb2222');
  assert.strictEqual(r.name, 'test-only');
  assert.deepStrictEqual(r.actions, ['test']);
});
check('jeton desactive -> jamais trouve, meme correct', () => {
  assert.strictEqual(DT.findByToken('cccc3333cccc3333'), null);
});
check('jeton inconnu ou vide -> jamais trouve, jamais d exception', () => {
  assert.strictEqual(DT.findByToken('nimportequoi'), null);
  assert.strictEqual(DT.findByToken(''), null);
  assert.strictEqual(DT.findByToken(undefined), null);
});

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
