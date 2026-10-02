'use strict';
const assert=require('assert');
const P=require('../lib/parse');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const COMBINED = '203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET /index.html HTTP/1.1" 200 1234 "https://ref.example" "Mozilla/5.0"';
const VHOST    = 'example.com 203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.5.0"';

console.log('\nformat combined');
check('champs extraits', ()=>{
  const r=P.parseLine(COMBINED,'combined','site.fr');
  assert.strictEqual(r.ip,'203.0.113.5');
  assert.strictEqual(r.method,'GET');
  assert.strictEqual(r.path,'/index.html');
  assert.strictEqual(r.status,200);
  assert.strictEqual(r.bytes,1234);
  assert.strictEqual(r.ua,'Mozilla/5.0');
  assert.strictEqual(r.vhost,'site.fr','le vhost vient du nom de fichier');
});

console.log('\nformat combined_vhost');
check('le vhost est lu dans la ligne', ()=>{
  const r=P.parseLine(VHOST,'vhost');
  assert.strictEqual(r.vhost,'example.com');
  assert.strictEqual(r.ip,'203.0.113.5');
  assert.strictEqual(r.status,200);
});
check('referer et user absents -> null', ()=>{
  const r=P.parseLine(VHOST,'vhost');
  assert.strictEqual(r.referer,null);
  assert.strictEqual(r.user,null);
});

console.log('\ndetection de format');
check('combined reconnu',      ()=>assert.strictEqual(P.detectFormat([COMBINED,COMBINED]),'combined'));
check('vhost reconnu',         ()=>assert.strictEqual(P.detectFormat([VHOST,VHOST]),'vhost'));
check('majorite l emporte',    ()=>assert.strictEqual(P.detectFormat([VHOST,VHOST,COMBINED]),'vhost'));
check('lignes vides ignorees', ()=>assert.strictEqual(P.detectFormat(['','  ',COMBINED]),'combined'));
check('echantillon vide -> combined par defaut', ()=>assert.strictEqual(P.detectFormat([]),'combined'));

console.log('\nhorodatage');
check('fuseau applique', ()=>{
  // 10:00:00 +0200 correspond a 08:00:00 UTC
  const t=P.parseTime('09/Sep/2026:10:00:00 +0200');
  assert.strictEqual(new Date(t).toISOString(),'2026-09-09T08:00:00.000Z');
});
check('fuseau negatif', ()=>{
  const t=P.parseTime('09/Sep/2026:10:00:00 -0500');
  assert.strictEqual(new Date(t).toISOString(),'2026-09-09T15:00:00.000Z');
});
check('sans fuseau', ()=>assert.ok(P.parseTime('09/Sep/2026:10:00:00')));
check('date invalide -> null', ()=>{
  assert.strictEqual(P.parseTime('pas une date'),null);
  assert.strictEqual(P.parseTime('09/Xyz/2026:10:00:00 +0200'),null);
});

console.log('\nrobustesse (une ligne tronquee est normale en fin de fichier)');
for (const [label,line] of [
  ['ligne vide',''],
  ['ligne tronquee','203.0.113.5 - - [09/Sep'],
  ['texte quelconque','n importe quoi'],
  ['statut non numerique','203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" ABC 1 "-" "-"'],
  ['guillemets non fermes','203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1 200 1 "-" "-"'],
])
  check(`${label} -> null`, ()=>assert.strictEqual(P.parseLine(line,'combined'),null));

check('octets a tiret -> 0', ()=>{
  const r=P.parseLine('203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 304 - "-" "-"','combined');
  assert.strictEqual(r.bytes,0);
});
check('methode inhabituelle acceptee', ()=>{
  const r=P.parseLine('203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "PROPFIND /x HTTP/1.1" 405 0 "-" "-"','combined');
  assert.strictEqual(r.method,'PROPFIND');
});
check('IPv6 acceptee', ()=>{
  const r=P.parseLine('2001:db8::1 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "-"','combined');
  assert.strictEqual(r.ip,'2001:db8::1');
});

console.log('\nutilitaires');
check('vhost depuis le nom de fichier', ()=>{
  assert.strictEqual(P.vhostFromFilename('forge.rdr-it.com.access.log'),'forge.rdr-it.com');
  assert.strictEqual(P.vhostFromFilename('site.access.log.1'),'site');
});
check('chemin sans query string', ()=>{
  assert.strictEqual(P.normalizePath('/search?q=x&p=2'),'/search');
  assert.strictEqual(P.normalizePath('/plain'),'/plain');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
