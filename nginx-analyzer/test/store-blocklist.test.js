'use strict';
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { Store }=require('../lib/store');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'blocklist-store-'));
const s=new Store(path.join(tmp,'b.db'));
const T=Date.now();
const hit=(o={})=>({ts:T,ip:'203.0.113.5',vhost:'site.fr',method:'GET',uri:'/wp-login.php',status:403,...o});

console.log('\nenregistrement et resume de fenetre');
check('un hit se relit dans le resume', ()=>{
  s.recordBlocklistHit(hit());
  const sum = s.blocklistHitsSummary(T-1000, T+1000);
  assert.strictEqual(sum.totalHits, 1);
  assert.strictEqual(sum.uniqueIps, 1);
  assert.strictEqual(sum.topIps[0].ip, '203.0.113.5');
  assert.strictEqual(sum.topIps[0].count, 1);
});
check('plusieurs hits de la meme IP se cumulent, IP distinctes comptees a part', ()=>{
  s.recordBlocklistHit(hit());
  s.recordBlocklistHit(hit({ip:'198.51.100.9'}));
  const sum = s.blocklistHitsSummary(T-1000, T+1000);
  assert.strictEqual(sum.totalHits, 3);
  assert.strictEqual(sum.uniqueIps, 2);
  const top = sum.topIps.find(r=>r.ip==='203.0.113.5');
  assert.strictEqual(top.count, 2);
});
check('hors fenetre temporelle -> ignore', ()=>{
  const sum = s.blocklistHitsSummary(T+10_000, T+20_000);
  assert.strictEqual(sum.totalHits, 0);
});

console.log('\nrecherche par IP');
check('blocklistHitsForIp compte et borne premiere/derniere occurrence', ()=>{
  const r = s.blocklistHitsForIp('203.0.113.5', T-1000, T+1000);
  assert.strictEqual(r.count, 2);
  assert.ok(r.firstSeen !== null && r.lastSeen !== null);
});
check('IP jamais vue -> compte 0, pas d exception', ()=>{
  const r = s.blocklistHitsForIp('192.0.2.1', T-1000, T+1000);
  assert.strictEqual(r.count, 0);
  assert.strictEqual(r.firstSeen, null);
});

console.log('\npurge et effacement manuel');
check('purgeBlocklistHits supprime uniquement les hits plus vieux que le seuil', ()=>{
  const before = s.blocklistHitsSummary(T-1000, T+1000).totalHits;
  assert.ok(before > 0);
  const deleted = s.purgeBlocklistHits(T - 500);
  assert.strictEqual(deleted, 0, 'rien de plus vieux que T-500 dans ce jeu de test');
});
check('clearBlocklistHits vide completement la table', ()=>{
  const { deleted } = s.clearBlocklistHits();
  assert.ok(deleted >= 3);
  assert.strictEqual(s.blocklistHitsSummary(T-1000, T+1000).totalHits, 0);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
