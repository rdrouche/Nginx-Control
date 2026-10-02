'use strict';
const assert=require('assert');
const B=require('../lib/parse-blocklist');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const line = '2026-09-24T10:15:03+00:00 203.0.113.5 example.com "GET /wp-login.php HTTP/1.1" 403';

console.log('\nanalyse d une ligne de hits blocklist');
check('format toujours "blocklist" (une seule forme possible)', ()=>{
  assert.strictEqual(B.detectFormat(), 'blocklist');
});
check('vhostFromFilename ne derive rien du nom de fichier (fichier global)', ()=>{
  assert.strictEqual(B.vhostFromFilename('blocklist-hits.log'), null);
});
check('champs de base extraits', ()=>{
  const r = B.parseLine(line, 'blocklist');
  assert.strictEqual(r.ip, '203.0.113.5');
  assert.strictEqual(r.vhost, 'example.com');
  assert.strictEqual(r.method, 'GET');
  assert.strictEqual(r.uri, '/wp-login.php');
  assert.strictEqual(r.status, 403);
  assert.strictEqual(typeof r.ts, 'number');
});
check('host "-" retombe sur le vhost par defaut fourni', ()=>{
  const l = '2026-09-24T10:15:03+00:00 203.0.113.5 - "GET / HTTP/1.1" 403';
  const r = B.parseLine(l, 'blocklist', 'defaut.fr');
  assert.strictEqual(r.vhost, 'defaut.fr');
});
check('ligne vide ou tronquee -> null, jamais d exception', ()=>{
  assert.strictEqual(B.parseLine(''), null);
  assert.strictEqual(B.parseLine(null), null);
  assert.strictEqual(B.parseLine('2026-09-24T10:15:03+00:00 203.0.113.5 example.com "GET /'), null);
});
check('ligne sans le bon nombre de champs -> null', ()=>{
  assert.strictEqual(B.parseLine('n importe quoi'), null);
});
check('date invalide -> null', ()=>{
  assert.strictEqual(B.parseLine('pas-une-date 203.0.113.5 example.com "GET / HTTP/1.1" 403'), null);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
