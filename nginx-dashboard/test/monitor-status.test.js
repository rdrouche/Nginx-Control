'use strict';
/**
 * Logique pure de lib/monitor-status.js — decide si un code HTTP compte
 * comme "up" pour le monitoring continu (features/monitor.js). Teste
 * separement du reste (pas de serveur, pas de fichiers) car c est une
 * fonction pure : parsing du flag + regle par defaut + surcharge.
 */
const assert = require('assert');
const { parseValidHttpCodes, isStatusUp } = require('../lib/monitor-status');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseValidHttpCodes()');
check('liste simple de classes -> tableau', () => {
  assert.deepStrictEqual(parseValidHttpCodes('2xx, 3xx'), ['2xx', '3xx']);
});
check('code exact et plage acceptes', () => {
  assert.deepStrictEqual(parseValidHttpCodes('404, 200-299'), ['404', '200-299']);
});
check('espaces et casse tolerees', () => {
  assert.deepStrictEqual(parseValidHttpCodes(' 2XX ,3xx '), ['2XX', '3xx']);
});
check('vide ou absent -> null', () => {
  assert.strictEqual(parseValidHttpCodes(''), null);
  assert.strictEqual(parseValidHttpCodes(undefined), null);
});
check('entierement invalide -> null (retombe sur la regle par defaut)', () => {
  assert.strictEqual(parseValidHttpCodes('n-importe-quoi'), null);
});
check('melange valide/invalide -> seuls les patterns valides sont gardes', () => {
  assert.deepStrictEqual(parseValidHttpCodes('2xx, pas-un-code, 404'), ['2xx', '404']);
});

console.log('\nisStatusUp() — regle par defaut (pas de surcharge)');
check('pas de reponse (timeout/erreur reseau) -> toujours down', () => {
  assert.strictEqual(isStatusUp(null, null), false);
  assert.strictEqual(isStatusUp(undefined, null), false);
});
check('2xx/3xx/4xx -> up par defaut', () => {
  assert.strictEqual(isStatusUp(200, null), true);
  assert.strictEqual(isStatusUp(301, null), true);
  assert.strictEqual(isStatusUp(404, null), true);
});
check('5xx -> down par defaut (le bug signale : avant, tout code repondu comptait comme up)', () => {
  assert.strictEqual(isStatusUp(500, null), false);
  assert.strictEqual(isStatusUp(503, null), false);
});

console.log('\nisStatusUp() — surcharge par patterns (cas Traefik : conteneur arrete -> 404 quand meme repondu)');
check('surcharge "2xx, 3xx" : un 404 devient down', () => {
  assert.strictEqual(isStatusUp(404, ['2xx', '3xx']), false);
});
check('surcharge "4xx" explicite : le meme 404 reste up', () => {
  assert.strictEqual(isStatusUp(404, ['4xx']), true);
});
check('surcharge par code exact', () => {
  assert.strictEqual(isStatusUp(418, ['418']), true);
  assert.strictEqual(isStatusUp(404, ['418']), false);
});
check('surcharge par plage', () => {
  assert.strictEqual(isStatusUp(250, ['200-299']), true);
  assert.strictEqual(isStatusUp(404, ['200-299']), false);
});
check('surcharge : toujours down si pas de reponse, meme avec des patterns larges', () => {
  assert.strictEqual(isStatusUp(null, ['2xx', '3xx', '4xx', '5xx']), false);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
