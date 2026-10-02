'use strict';
/**
 * lib/agent-tokens.js — generation/hachage/comparaison des jetons Bearer
 * d'agent distant (Partie 2). Logique pure, memes garanties attendues que
 * lib/deploy-tokens.js's safeCompare(): jamais la meme valeur pour deux
 * appels, jamais de comparaison en temps variable exploitable.
 */
const assert = require('assert');
const { TOKEN_PREFIX, generateToken, hashToken, safeCompareHash } = require('../lib/agent-tokens');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\ngenerateToken()');
check('commence par le prefixe agt_', () => {
  assert.ok(generateToken().startsWith(TOKEN_PREFIX));
});
check('deux jetons generes ne sont jamais identiques', () => {
  assert.notStrictEqual(generateToken(), generateToken());
});
check('assez d entropie (48 caracteres hex apres le prefixe, 192 bits)', () => {
  const t = generateToken();
  assert.strictEqual(t.length, TOKEN_PREFIX.length + 48);
  assert.ok(/^[0-9a-f]{48}$/.test(t.slice(TOKEN_PREFIX.length)));
});

console.log('\nhashToken()');
check('deterministe : le meme jeton hache toujours la meme empreinte', () => {
  const t = generateToken();
  assert.strictEqual(hashToken(t), hashToken(t));
});
check('deux jetons differents -> empreintes differentes', () => {
  assert.notStrictEqual(hashToken(generateToken()), hashToken(generateToken()));
});
check('empreinte SHA-256 hex (64 caracteres)', () => {
  assert.ok(/^[0-9a-f]{64}$/.test(hashToken(generateToken())));
});
check('ne jette jamais sur une entree vide/absente', () => {
  assert.strictEqual(typeof hashToken(''), 'string');
  assert.strictEqual(typeof hashToken(undefined), 'string');
});

console.log('\nsafeCompareHash()');
check('deux empreintes identiques -> true', () => {
  const h = hashToken('agt_abcdef');
  assert.strictEqual(safeCompareHash(h, h), true);
});
check('deux empreintes differentes -> false', () => {
  assert.strictEqual(safeCompareHash(hashToken('a'), hashToken('b')), false);
});
check('longueurs differentes -> false, jamais une exception', () => {
  assert.strictEqual(safeCompareHash('abcd', hashToken('a')), false);
});
check('entrees non-hex/vides -> false, jamais une exception', () => {
  assert.strictEqual(safeCompareHash('', ''), false);
  assert.strictEqual(safeCompareHash('zz', 'zz'), false);
  assert.strictEqual(safeCompareHash(null, undefined), false);
});
check("un jeton different d un seul caractere ne matche jamais l empreinte stockee", () => {
  const raw = generateToken();
  const stored = hashToken(raw);
  const tampered = raw.slice(0, -1) + (raw.slice(-1) === '0' ? '1' : '0');
  assert.strictEqual(safeCompareHash(hashToken(tampered), stored), false);
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
