'use strict';
/**
 * Fix (audit report, Basse/Divers dashboard, "features/audit.js:41") :
 * primaryListenPort() lisait "listen 127.0.0.1:8443 ssl;" comme le port 127
 * (premiere suite de chiffres de la ligne, soit le premier octet de
 * l adresse) au lieu du vrai port apres les ":". Unitaire, sans reseau.
 */
const assert = require('assert');
const { primaryListenPort } = require('../features/audit');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nprimaryListenPort() — bug reel : adresse:port lu comme le premier octet');
check('listen host:port ssl -> le vrai port, pas le premier octet de l adresse', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: ['127.0.0.1:8443 ssl;'] }), 8443);
});
check('listen host:port (sans ssl)', () => {
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['10.0.0.5:8080;'] }), 8080);
});
check('listen bare port ssl', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: ['443 ssl;'] }), 443);
});
check('listen bare port sans ssl', () => {
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['8080;'] }), 8080);
});
check('listen [ipv6]:port', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: ['[::1]:8443 ssl;'] }), 8443);
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['[::]:80;'] }), 80);
});
check('listen hostname:port', () => {
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['example.internal:9000;'] }), 9000);
});
check('listen unix: -> repli sur le port par defaut (443/80), pas d exception', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: ['unix:/run/nginx.sock ssl;'] }), 443);
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['unix:/run/nginx.sock;'] }), 80);
});
check('aucune directive listen -> repli sur le port par defaut', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: [] }), 443);
  assert.strictEqual(primaryListenPort({ ssl: false, listen: [] }), 80);
});
check('plusieurs listen : celui qui correspond a ssl est choisi', () => {
  assert.strictEqual(primaryListenPort({ ssl: true, listen: ['80;', '127.0.0.1:8443 ssl;'] }), 8443);
  assert.strictEqual(primaryListenPort({ ssl: false, listen: ['127.0.0.1:8443 ssl;', '80;'] }), 80);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
