'use strict';
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { Store }=require('../lib/store');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'store-'));
const s=new Store(path.join(tmp,'state.db'));
const T=Date.parse('2026-09-09T10:00:00Z');
const e=(o={})=>({ts:T,vhost:'site.fr',status:200,method:'GET',bytes:100,...o});

console.log('\nstockage');
check('SQLite disponible', ()=>assert.strictEqual(s.persistent,true));
check('agregation en buckets', ()=>{
  for(let i=0;i<10;i++) s.record(e({ts:T+i*1000}),'FR');
  const n=s.flush();
  assert.ok(n>0,'des buckets doivent etre ecrits');
});
check('les requetes sont cumulees, pas dupliquees', ()=>{
  for(let i=0;i<5;i++) s.record(e(),'FR');
  s.flush();
  const v=s.byVhost(T-60000,T+60000);
  assert.strictEqual(v.length,1);
  assert.strictEqual(v[0].requests,15,'10 + 5');
});

console.log('\nventilation');
check('par pays', ()=>{
  s.record(e({ts:T+2000}),'DE'); s.record(e({ts:T+2000}),'DE'); s.flush();
  const c=s.byCountry(T-60000,T+60000);
  const fr=c.find(x=>x.country==='FR'), de=c.find(x=>x.country==='DE');
  assert.strictEqual(fr.requests,15);
  assert.strictEqual(de.requests,2);
});
check('pays inconnu regroupe', ()=>{
  s.record(e({ts:T+3000}),null); s.flush();
  assert.ok(s.byCountry(T-60000,T+60000).some(x=>x.country==='??'));
});
check('erreurs comptees a part', ()=>{
  s.record(e({ts:T+4000,status:404}),'FR');
  s.record(e({ts:T+4000,status:500}),'FR'); s.flush();
  const v=s.byVhost(T-60000,T+60000);
  assert.strictEqual(v[0].errors,2,'4xx et 5xx uniquement');
});

console.log('\nmetriques horaires pour la baseline');
check('agregation par heure', ()=>{
  const h=s.hourlyMetrics('site.fr',T-3600000,T+3600000);
  assert.ok(h.length>=1);
  assert.ok(h[0].requests>0);
  assert.ok('errors' in h[0]);
});

console.log('\nretention par paliers');
check('les minutes anciennes deviennent des heures', ()=>{
  const s2=new Store(path.join(tmp,'r.db'));
  const vieux=Date.now()-48*3600*1000;
  for(let i=0;i<20;i++) s2.record(e({ts:vieux+i*60000}),'FR');
  s2.flush();
  const avant=s2.stats().rows;
  const r=s2.rollup();
  const apres=s2.stats().rows;
  assert.ok(r.rolled>0||r.deleted>0,'le rollup doit agir');
  assert.ok(!apres.minute||apres.minute<(avant.minute||0),'les minutes anciennes doivent disparaitre');
  assert.ok(apres.hour>0,'elles doivent survivre en heures');
  s2.close();
});
check('les donnees recentes sont preservees', ()=>{
  const s3=new Store(path.join(tmp,'r2.db'));
  const now=Date.now();
  for(let i=0;i<5;i++) s3.record(e({ts:now-i*60000}),'FR');
  s3.flush();
  s3.rollup();
  assert.ok(s3.stats().rows.minute>0,'les 24 dernieres heures restent en minutes');
  s3.close();
});

console.log('\nalertes');
check('enregistrement et relecture', ()=>{
  s.addAlert({type:'bruteforce',severity:'high',summary:'test',
              evidence:{ip:'1.2.3.4',vhost:'site.fr',requests:20}});
  const r=s.listAlerts();
  assert.strictEqual(r.total,1);
  assert.strictEqual(r.alerts[0].ip,'1.2.3.4');
  assert.strictEqual(r.alerts[0].evidence.requests,20,'les preuves survivent au JSON');
});
check('filtrage par type et severite', ()=>{
  s.addAlert({type:'scan',severity:'low',summary:'x',evidence:{ip:'5.6.7.8'}});
  assert.strictEqual(s.listAlerts({type:'scan'}).total,1);
  assert.strictEqual(s.listAlerts({severity:'high'}).total,1);
});
check('acquittement', ()=>{
  const id=s.listAlerts().alerts[0].id;
  assert.ok(s.ackAlert(id));
  assert.strictEqual(s.listAlerts().alerts.find(a=>a.id===id).acked,true);
});

console.log('\netat et offsets');
check('cle/valeur', ()=>{
  s.setState('baseline',{startedAt:123,buckets:{a:[1,2]}});
  assert.strictEqual(s.getState('baseline').startedAt,123);
});
check('offset de lecture par fichier', ()=>{
  s.setOffset('/logs/a.log',42,1000,'vhost');
  const o=s.getOffset('/logs/a.log');
  assert.strictEqual(o.inode,42);
  assert.strictEqual(o.offset,1000);
  assert.strictEqual(o.format,'vhost');
});
check('offset inconnu -> null', ()=>assert.strictEqual(s.getOffset('/nope'),null));

console.log('\ndegradation sans SQLite');
check('un chemin invalide ne fait pas echouer le demarrage', ()=>{
  // Un fichier ordinaire la ou un dossier est attendu : echec immediat et net.
  const blocker=path.join(tmp,'pas-un-dossier');
  fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'x.db'));
  assert.strictEqual(bad.persistent,false);
  assert.doesNotThrow(()=>bad.record(e(),'FR'));
  assert.doesNotThrow(()=>bad.flush());
  bad.addAlert({type:'x',summary:'y',evidence:{}});
  assert.strictEqual(bad.listAlerts().alerts.length,1,'les alertes restent en memoire');
});

console.log('\nANA-04 : les buckets memoire ne grossissent plus indefiniment sans SQLite');
check('flush() elague les buckets de plus de minuteHours en mode memoire (avant : aucune purge, fuite memoire)', ()=>{
  const blocker=path.join(tmp,'pas-un-dossier-2');
  fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'x.db'), { retention: { minuteHours: 1 } });
  assert.strictEqual(bad.persistent,false);
  const now = Date.now(); // la purge compare au temps reel, pas a T (fige en 2026-09-09)
  const old = now - 3 * 3600_000; // bien avant la fenetre d 1h
  bad.record(e({ts:old}),'FR');
  bad.recordBot(e({ts:old}),'bot','FR');
  bad.record(e({ts:now}),'FR'); // recent, doit survivre
  assert.strictEqual(bad.memory.buckets.size,2);
  bad.flush(); // en mode memoire, flush() n ecrit rien mais doit elaguer
  assert.strictEqual(bad.memory.buckets.size,1,'le bucket ancien doit avoir ete elague');
  assert.strictEqual(bad.memory.botBuckets.size,0,'le bot-bucket ancien doit avoir ete elague');
});

console.log('\nANA-11 : les purges age-based en mode memoire respectent olderThanMs (avant : elles videaient tout)');
check('purgeAlerts(olderThanMs) ne supprime que les alertes plus vieilles que olderThanMs', ()=>{
  const blocker=path.join(tmp,'pas-un-dossier-3');
  fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'x.db'));
  bad.memory.alerts=[{id:1,ts:T-100000,type:'a'},{id:2,ts:T,type:'b'}];
  const n=bad.purgeAlerts(T-50000);
  assert.strictEqual(n,1,'une seule alerte est plus vieille que le seuil');
  assert.strictEqual(bad.listAlerts().alerts.length,1,'l alerte recente doit survivre');
  assert.strictEqual(bad.listAlerts().alerts[0].id,2);
});
check('purgeWaf(olderThanMs) ne supprime que les evenements plus vieux que olderThanMs', ()=>{
  const blocker=path.join(tmp,'pas-un-dossier-4');
  fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'x.db'));
  bad.memory.waf=[{id:1,ts:T-100000},{id:2,ts:T}];
  const n=bad.purgeWaf(T-50000);
  assert.strictEqual(n,1);
  assert.strictEqual(bad.memory.waf.length,1);
  assert.strictEqual(bad.memory.waf[0].id,2);
});
check('purgeBlocklistHits(olderThanMs) ne supprime que les hits plus vieux que olderThanMs', ()=>{
  const blocker=path.join(tmp,'pas-un-dossier-5');
  fs.writeFileSync(blocker,'x');
  const bad=new Store(path.join(blocker,'x.db'));
  bad.memory.blocklistHits=[{id:1,ts:T-100000},{id:2,ts:T}];
  const n=bad.purgeBlocklistHits(T-50000);
  assert.strictEqual(n,1);
  assert.strictEqual(bad.memory.blocklistHits.length,1);
  assert.strictEqual(bad.memory.blocklistHits[0].id,2);
});

console.log('\nmigration d une base existante (bot_traffic sans country dans la cle)');
check('une base de la version precedente est reconstruite, historique preserve, ecritures debloquees', ()=>{
  // Bug reel signale en production : les chiffres humains/robots restaient
  // figes a la valeur exacte d avant la mise a jour. Cause : la colonne
  // country fait partie de la cle primaire, or ALTER TABLE ADD COLUMN ajoute
  // bien la colonne mais NE PEUT PAS elargir la cle. Le
  // INSERT ... ON CONFLICT(bucket, grain, vhost, category, country) de flush()
  // exige un index unique sur ces cinq colonnes ; la table migree n en avait
  // qu un sur quatre, et SQLite rejette la requete. Chaque ecriture echouait,
  // l erreur etait avalee par le try/catch de flush(), et les totaux
  // n avancaient plus. Invisible avec une base neuve — donc invisible dans
  // tous les tests precedents, qui en creaient systematiquement une.
  const { DatabaseSync } = require('node:sqlite');
  const oldPath = path.join(tmp, 'ancienne-version.db');
  const raw = new DatabaseSync(oldPath);
  raw.exec(`CREATE TABLE bot_traffic (
    bucket INTEGER NOT NULL, grain TEXT NOT NULL, vhost TEXT NOT NULL,
    category TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, grain, vhost, category));`);
  const ins = raw.prepare('INSERT INTO bot_traffic VALUES (?,?,?,?,?)');
  ins.run(1789500000, 'minute', 'site.fr', 'human', 10738);
  ins.run(1789500000, 'minute', 'site.fr', 'good', 252);
  raw.close();

  const migrated = new Store(oldPath);
  const pk = migrated.db.prepare('PRAGMA table_info(bot_traffic)').all().filter(c=>c.pk>0).map(c=>c.name);
  assert.deepStrictEqual(pk, ['bucket','grain','vhost','category','country'],
    'country doit faire partie de la cle primaire apres migration');

  const hist = Object.fromEntries(
    migrated.db.prepare('SELECT category, SUM(requests) r FROM bot_traffic GROUP BY category').all()
      .map(x=>[x.category, x.r]));
  assert.strictEqual(hist.human, 10738, 'l historique doit etre preserve intact');
  assert.strictEqual(hist.good, 252);

  // Et surtout : les nouvelles ecritures doivent enfin aboutir.
  migrated.recordBot({ts: Date.now(), vhost:'site.fr'}, 'human', 'FR');
  migrated.recordBot({ts: Date.now(), vhost:'site.fr'}, 'human', 'FR');
  const written = migrated.flush();
  assert.ok(written > 0, 'flush() doit ecrire, pas echouer en silence');
  const apres = migrated.db.prepare(
    `SELECT SUM(requests) r FROM bot_traffic WHERE category='human'`).get().r;
  assert.strictEqual(apres, 10740, 'les totaux doivent progresser apres la migration');
  migrated.close();
});
check('la migration est idempotente et ne touche pas une base neuve', ()=>{
  const { DatabaseSync } = require('node:sqlite');
  const p2 = path.join(tmp, 'idempotence.db');
  const raw = new DatabaseSync(p2);
  raw.exec(`CREATE TABLE bot_traffic (
    bucket INTEGER NOT NULL, grain TEXT NOT NULL, vhost TEXT NOT NULL,
    category TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, grain, vhost, category));`);
  raw.prepare('INSERT INTO bot_traffic VALUES (?,?,?,?,?)').run(1789500000,'minute','s.fr','human',5);
  raw.close();
  const a = new Store(p2); a.close();
  const b = new Store(p2);   // 2e ouverture : ne doit ni re-migrer ni perdre de donnees
  const total = b.db.prepare('SELECT SUM(requests) r FROM bot_traffic').get().r;
  assert.strictEqual(total, 5, 'une seconde ouverture ne doit ni dupliquer ni perdre de lignes');
  b.recordBot({ts:Date.now(), vhost:'s.fr'}, 'human', 'FR');
  assert.ok(b.flush() > 0, 'les ecritures fonctionnent toujours apres une 2e ouverture');
  b.close();
});

console.log('\nrepartition bot/humain par pays et par vhost (tableaux Analyse)');
check('botByVhost pivote correctement humains vs robots par vhost', () => {
  const T4 = Date.now() + 300_000;
  s.recordBot({ts:T4,vhost:'p1.fr'}, 'human', 'FR');
  s.recordBot({ts:T4,vhost:'p1.fr'}, 'human', 'FR');
  s.recordBot({ts:T4,vhost:'p1.fr'}, 'good', 'FR');
  s.recordBot({ts:T4,vhost:'p2.fr'}, 'bad', 'DE');
  s.flush();
  const rows = s.botByVhost(T4-3_600_000, T4+3_600_000);
  const p1 = rows.find(r=>r.vhost==='p1.fr');
  const p2 = rows.find(r=>r.vhost==='p2.fr');
  assert.strictEqual(p1.human, 2);
  assert.strictEqual(p1.bots, 1);
  assert.strictEqual(p1.total, 3);
  assert.strictEqual(p2.human, 0);
  assert.strictEqual(p2.bots, 1);
});
check('botByCountry pivote correctement, avec filtre vhost optionnel', () => {
  const T5 = Date.now() + 400_000;
  s.recordBot({ts:T5,vhost:'x.fr'}, 'human', 'FR');
  s.recordBot({ts:T5,vhost:'x.fr'}, 'ai', 'FR');
  s.recordBot({ts:T5,vhost:'y.fr'}, 'human', 'FR');
  s.flush();
  // Chaque appel filtre par vhost pour rester isole : sans filtre, la requete
  // agregerait legitimement le code pays "FR" a travers tous les vhosts du
  // fichier de test, y compris ceux d autres verifications precedentes.
  const forX = s.botByCountry(T5-3_600_000, T5+3_600_000, 'x.fr');
  const frX = forX.find(r=>r.country==='FR');
  assert.strictEqual(frX.human, 1, 'le filtre vhost doit exclure y.fr');
  assert.strictEqual(frX.bots, 1);
  const forY = s.botByCountry(T5-3_600_000, T5+3_600_000, 'y.fr');
  const frY = forY.find(r=>r.country==='FR');
  assert.strictEqual(frY.human, 1);
  assert.strictEqual(frY.bots, 0);
});
check('adresse non resolue (pas de GeoIP) regroupee sous ??', () => {
  const T6 = Date.now() + 500_000;
  s.recordBot({ts:T6,vhost:'z.fr'}, 'human');   // pas de pays fourni
  s.flush();
  const rows = s.botByCountry(T6-3_600_000, T6+3_600_000, 'z.fr');
  assert.strictEqual(rows[0].country, '??');
  assert.strictEqual(rows[0].human, 1);
});
check('rollup preserve la dimension pays lors de la promotion', () => {
  const old = new Store(path.join(tmp,'rollup-bot-country.db'));
  const past = Date.now() - 40*3600*1000;
  old.recordBot({ts:past,vhost:'r.fr'}, 'human', 'JP');
  old.flush();
  old.rollup(Date.now());
  const rows = old.db.prepare(`SELECT * FROM bot_traffic WHERE grain='hour'`).all();
  assert.ok(rows.some(r=>r.country==='JP'), 'le pays doit survivre a la promotion minute -> heure');
  old.close();
});

console.log('\nrepartition bot/humain (independante de GeoIP)');
check('categories agregees correctement', ()=>{
  const T2 = Date.now() + 100_000;   // fenetre distincte du reste des tests
  for (let i=0;i<5;i++) s.recordBot({ts:T2,vhost:'bots.fr'}, 'human');
  for (let i=0;i<3;i++) s.recordBot({ts:T2,vhost:'bots.fr'}, 'good');
  for (let i=0;i<2;i++) s.recordBot({ts:T2,vhost:'bots.fr'}, 'bad');
  s.flush();
  const rows = s.byBotCategory(T2-3_600_000, T2+3_600_000, 'bots.fr');
  const byCategory = Object.fromEntries(rows.map(r=>[r.category,r.requests]));
  assert.strictEqual(byCategory.human, 5);
  assert.strictEqual(byCategory.good, 3);
  assert.strictEqual(byCategory.bad, 2);
});
check('categorie absente (pas de User-Agent) ignoree sans exception', ()=>{
  assert.doesNotThrow(()=>s.recordBot({ts:Date.now(),vhost:'x.fr'}, null));
  assert.doesNotThrow(()=>s.recordBot({ts:Date.now(),vhost:'x.fr'}, undefined));
});
check('filtre par vhost', ()=>{
  const T3 = Date.now() + 200_000;
  s.recordBot({ts:T3,vhost:'v1.fr'}, 'human');
  s.recordBot({ts:T3,vhost:'v2.fr'}, 'human');
  s.flush();
  const rows = s.byBotCategory(T3-3_600_000, T3+3_600_000, 'v1.fr');
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].requests, 1);
});
check('rollup promeut aussi bot_traffic (minute -> heure -> jour)', ()=>{
  const old = new Store(path.join(tmp,'rollup-bot.db'));
  const past = Date.now() - 40*3600*1000;   // au-dela de la retention minute
  old.recordBot({ts:past,vhost:'r.fr'}, 'human');
  old.flush();
  const before = old.db.prepare(`SELECT COUNT(*) n FROM bot_traffic WHERE grain='minute'`).get().n;
  old.rollup(Date.now());
  const afterMinute = old.db.prepare(`SELECT COUNT(*) n FROM bot_traffic WHERE grain='minute'`).get().n;
  const afterHour = old.db.prepare(`SELECT COUNT(*) n FROM bot_traffic WHERE grain='hour'`).get().n;
  assert.ok(before>=1, 'la bucket minute doit exister avant le rollup');
  assert.strictEqual(afterMinute,0,'la bucket minute perimee doit avoir ete promue puis supprimee');
  assert.ok(afterHour>=1,'elle doit reapparaitre en grain heure');
  old.close();
});

s.close();
fs.rmSync(tmp,{recursive:true,force:true});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
