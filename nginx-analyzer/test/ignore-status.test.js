'use strict';
const assert = require('assert');
const { parseIgnoreStatus } = require('../lib/ignore-status');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
check('codes valides lus, le reste ignore', () => {
  assert.deepStrictEqual([...parseIgnoreStatus('444, 403;abc 99 600 4444 502')].sort(), [403, 444, 502]);
});
check('vide / absent : aucun code', () => {
  assert.strictEqual(parseIgnoreStatus('').size, 0);
  assert.strictEqual(parseIgnoreStatus(undefined).size, 0);
});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
