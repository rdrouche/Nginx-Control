'use strict';
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { Store }=require('../lib/store');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'waf-store-'));
const s=new Store(path.join(tmp,'w.db'));
const T=Date.now();
const evt=(o={})=>({ts:T,vhost:'site.fr',ip:'203.0.113.5',method:'GET',uri:'/login',
  status:403,blocked:true,severity:'critical',ruleIds:['942100'],
  messages:[{ruleId:'942100',message:'SQLi',severity:'critical',tags:[]}],
  uniqueId:'u1',...o});

console.log('\nenregistrement et relecture');
check('un evenement se relit a l identique', ()=>{
  s.recordWaf(evt());
  const r=s.listWaf();
  assert.strictEqual(r.total,1);
  assert.strictEqual(r.events[0].ip,'203.0.113.5');
  assert.deepStrictEqual(r.events[0].ruleIds,['942100']);
  assert.strictEqual(r.events[0].blocked,true);
});
check('filtrage par vhost, severite, blocage', ()=>{
  s.recordWaf(evt({vhost:'autre.fr',severity:'warning',blocked:false,ruleIds:['920100']}));
  assert.strictEqual(s.listWaf({vhost:'autre.fr'}).total,1);
  assert.strictEqual(s.listWaf({severity:'critical'}).total,1);
  assert.strictEqual(s.listWaf({blocked:false}).total,1);
  assert.strictEqual(s.listWaf({blocked:true}).total,1);
});

console.log('\nregles les plus declenchees');
check('comptage correct, meme sur plusieurs regles par evenement', ()=>{
  s.recordWaf(evt({ruleIds:['942100','949110'],
    messages:[{ruleId:'942100',message:'SQLi'},{ruleId:'949110',message:'Anomaly'}]}));
  const top=s.wafTopRules(T-1000,T+1000);
  const r942=top.find(r=>r.ruleId==='942100');
  assert.strictEqual(r942.count,2,'declenchee dans les deux evenements crees jusqu ici');
  assert.strictEqual(r942.example,'SQLi');
});

console.log('\nadresses les plus actives');
check('comptage et part bloquee', ()=>{
  const top=s.wafTopIps(T-1000,T+1000);
  const ip=top.find(x=>x.ip==='203.0.113.5');
  assert.ok(ip.count>=2);
  assert.ok(ip.blocked>=1);
});

console.log('\nserie temporelle');
check('regroupement par heure', ()=>{
  const series=s.wafSeries(T-3600000,T+3600000);
  assert.ok(series.length>=1);
  assert.ok(series[0].count>0);
});

console.log('\nretention');
check('purge par anciennete', ()=>{
  s.recordWaf(evt({ts:T-100*86400000}));   // tres ancien
  const before=s.wafStats().rows;
  const deleted=s.purgeWaf(T-30*86400000);
  assert.ok(deleted>=1);
  assert.ok(s.wafStats().rows<before);
});

console.log('\ndegradation sans SQLite');
check('un chemin invalide bascule en memoire sans exception', ()=>{
  const blocker=path.join(tmp,'pas-un-dossier'); fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'w.db'));
  assert.strictEqual(bad.persistent,false);
  assert.doesNotThrow(()=>bad.recordWaf(evt()));
  assert.strictEqual(bad.listWaf().events.length,1);
  assert.ok(bad.wafTopRules(T-1000,T+1000).length>=1);
});


console.log('\nrecuperation d un evenement complet (pour le detail)');
check('getWafEvent renvoie la ligne brute, absente de la liste paginee', ()=>{
  s.recordWaf(evt({raw:'{"transaction":{"client_ip":"203.0.113.5"}}', engine:'DetectionOnly'}));
  const listed = s.listWaf({limit:1});
  assert.strictEqual(listed.events[0].raw, undefined, 'la liste ne doit pas transporter la ligne brute');
  const full = s.getWafEvent(listed.events[0].id);
  assert.ok(full.raw.includes('203.0.113.5'));
  assert.strictEqual(full.engine, 'DetectionOnly');
});
check('identifiant inconnu -> null, pas d exception', ()=>{
  assert.strictEqual(s.getWafEvent(999999999), null);
});

console.log('\nmigration de colonnes (bases creees avant engine/raw)');
check('une base existante sans les colonnes recentes ne fait pas planter le demarrage', ()=>{
  const oldDb = path.join(tmp,'old-schema.db');
  const { DatabaseSync } = require('node:sqlite');
  const raw = new DatabaseSync(oldDb);
  raw.exec(`CREATE TABLE waf_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, vhost TEXT NOT NULL,
    ip TEXT, method TEXT, uri TEXT, status INTEGER, blocked INTEGER NOT NULL DEFAULT 0,
    severity TEXT, ruleIds TEXT, messages TEXT, uniqueId TEXT)`);
  raw.close();
  const migrated = new Store(oldDb);
  assert.doesNotThrow(()=>migrated.recordWaf(evt({engine:'On',raw:'test'})));
  const got = migrated.listWaf({limit:1});
  assert.strictEqual(got.events[0].engine, 'On');
  migrated.close();
});

s.close();
fs.rmSync(tmp,{recursive:true,force:true});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
