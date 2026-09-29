'use strict';
const assert = require('assert');
const { ipInCidr, isValidPattern } = require('../lib/cidr');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nipInCidr() — utilise par le controle de recherche IP dans les blocklists');
check('adresse exacte (IPv4)', () => {
  assert.ok(ipInCidr('1.2.3.4', '1.2.3.4'));
  assert.ok(!ipInCidr('1.2.3.5', '1.2.3.4'));
});
check('bloc CIDR IPv4', () => {
  assert.ok(ipInCidr('5.6.7.42', '5.6.7.0/24'));
  assert.ok(!ipInCidr('5.6.8.1', '5.6.7.0/24'));
});
check('IPv6', () => {
  assert.ok(ipInCidr('2001:db8::1', '2001:db8::/32'));
  assert.ok(!ipInCidr('2001:db9::1', '2001:db8::/32'));
});
check('familles differentes -> jamais un faux positif', () => {
  assert.ok(!ipInCidr('1.2.3.4', '::1'));
});

// Fix (audit report, Basse/Analyzer, ported ici aussi car cidr.js est une
// copie de nginx-analyzer/lib/cidr.js) : une IPv4-mappee EST la meme adresse
// que sa forme IPv4 nue.
check('adresse IPv4-mappee correspond a un bloc IPv4 equivalent (fix Basse/Analyzer)', () => {
  assert.ok(ipInCidr('::ffff:5.6.7.42', '5.6.7.0/24'));
  assert.ok(!ipInCidr('::ffff:5.6.8.1', '5.6.7.0/24'));
  assert.ok(ipInCidr('5.6.7.42', '::ffff:5.6.7.0/120'));
});
check('espace final dans un prefixe -> toujours valide (fix Basse/Analyzer)', () => {
  assert.ok(isValidPattern('5.6.7.0/24 '));
  assert.ok(ipInCidr('5.6.7.42', '5.6.7.0/24 '));
});
check('isValidPattern() distingue une IP/CIDR valide d un texte quelconque', () => {
  assert.ok(isValidPattern('1.2.3.4'));
  assert.ok(isValidPattern('5.6.7.0/24'));
  assert.ok(!isValidPattern('n importe quoi'));
  assert.ok(!isValidPattern('999.1.1.1'));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
