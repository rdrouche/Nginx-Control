'use strict';
/**
 * Le calcul des totaux VTS a deja produit un double comptage en production :
 * la zone '*' agrege deja tous les vhosts, l additionner aux zones
 * individuelles double les chiffres.
 */
const assert=require('assert');
const M=require('../features/metrics');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const zone=(req,e4,e5,inB,outB)=>({requestCounter:req,responses:{'4xx':e4,'5xx':e5},inBytes:inB,outBytes:outB});

console.log('\ntotaux (piege du double comptage)');
check('la zone * prime sur la somme des vhosts', ()=>{
  const vts={serverZones:{'*':zone(1000,10,5,500,1500),'a.com':zone(600,6,3,300,900),'b.com':zone(400,4,2,200,600)}};
  const t=M.computeTotals(vts);
  assert.strictEqual(t.requests,1000,'doit valoir * et non 2000');
  assert.strictEqual(t.errors,15);
  assert.strictEqual(t.bytes,2000);
});
check('sans zone *, on somme les vhosts', ()=>{
  const vts={serverZones:{'a.com':zone(600,6,3,300,900),'b.com':zone(400,4,2,200,600)}};
  const t=M.computeTotals(vts);
  assert.strictEqual(t.requests,1000);
  assert.strictEqual(t.errors,15);
  assert.strictEqual(t.bytes,2000);
});
check('payload vide', ()=>{
  assert.deepStrictEqual(M.computeTotals(null),{requests:0,errors:0,bytes:0,active:0});
  assert.deepStrictEqual(M.computeTotals({}),{requests:0,errors:0,bytes:0,active:0});
});

console.log('\ncompatibilite des noms de champs entre versions VTS');
check('forme requests.total / traffic.in', ()=>{
  const vts={serverZones:{'a.com':{requests:{total:50,processing:2},responses:{'4xx':1,'5xx':1},traffic:{in:100,out:200}}}};
  const t=M.computeTotals(vts);
  assert.strictEqual(t.requests,50);
  assert.strictEqual(t.bytes,300);
  assert.strictEqual(t.errors,2);
});

console.log('\nlisting des zones');
check('* est exclu', ()=>{
  const vts={serverZones:{'*':zone(1,0,0,0,0),'a.com':zone(1,0,0,0,0)}};
  const names=M.listZones(vts).map(z=>z.name);
  assert.deepStrictEqual(names,['a.com']);
});
check('sans donnees VTS', ()=>assert.deepStrictEqual(M.listZones(null),[]));

console.log('\nhistorique glissant');
check('plafonne a MAX_HISTORY', ()=>{
  const vts={serverZones:{'*':zone(1,0,0,0,0)}};
  for(let i=0;i<M.MAX_HISTORY+20;i++) M.recordSample(vts);
  assert.strictEqual(M.metricsHistory.timestamps.length,M.MAX_HISTORY);
  assert.strictEqual(M.metricsHistory.requests.length,M.MAX_HISTORY);
});

console.log('\ncalcul du debit (requetes/sec) pour le graphe Overview');
check('debit correct sur un intervalle regulier', () => {
  const T = Date.now();
  const r = M.computeRateSeries([T-10000, T-5000, T], [1000, 1500, 2000], 5);
  assert.deepStrictEqual(r.rps, [100, 100]);
});
check('une remise a zero du compteur (reload nginx) donne 0, jamais un pic negatif', () => {
  const T = Date.now();
  const r = M.computeRateSeries([T-10000, T-5000, T], [1000, 1500, 50], 5);
  assert.strictEqual(r.rps[1], 0, 'un compteur qui redemarre a zero ne doit jamais produire un debit negatif');
});
check('espacement irregulier entre echantillons pris en compte, pas suppose fixe', () => {
  const T = Date.now();
  // 10s puis 2s d ecart : le debit par seconde doit refleter l ecart reel, pas un pas fixe de 5s
  const r = M.computeRateSeries([T-12000, T-2000, T], [0, 1000, 1200], 5);
  assert.strictEqual(r.rps[0], 100);   // 1000 sur 10s
  assert.strictEqual(r.rps[1], 100);   // 200 sur 2s
});
check('la fenetre demandee exclut les echantillons trop anciens', () => {
  const T = Date.now();
  const ts = [], vals = [];
  for (let i = 0; i < 20; i++) { ts.push(T - (20 - i) * 60_000); vals.push(i * 100); }
  const r = M.computeRateSeries(ts, vals, 5);
  assert.ok(r.timestamps.length <= 5, `attendu au plus 5 points sur une fenetre de 5 min, obtenu ${r.timestamps.length}`);
  assert.ok(r.timestamps.every(t => t >= T - 5 * 60_000 - 1000));
});
check('un seul echantillon -> aucun debit calculable, pas d exception', () => {
  const T = Date.now();
  assert.deepStrictEqual(M.computeRateSeries([T], [100], 5), { timestamps: [], rps: [] });
});
check('historique vide -> pas d exception', () => {
  assert.deepStrictEqual(M.computeRateSeries([], [], 5), { timestamps: [], rps: [] });
});
check('fenetre invalide ou nulle ne provoque pas de division par zero', () => {
  const T = Date.now();
  assert.doesNotThrow(() => M.computeRateSeries([T-1000, T], [10, 20], 0));
  assert.doesNotThrow(() => M.computeRateSeries([T-1000, T], [10, 20], -5));
});

console.log('\nechantillonnage par vhost (pour le filtre du graphe)');
check('recordSample alimente un historique global et par vhost', () => {
  M.globalRateHistory.timestamps.length = 0; M.globalRateHistory.requests.length = 0;
  M.vhostRateHistory.clear();
  M.recordSample({ serverZones: {
    '*':          { requestCounter: 500 },
    'site-a.fr':  { requestCounter: 300 },
    'site-b.fr':  { requestCounter: 200 },
  }});
  assert.strictEqual(M.globalRateHistory.requests.at(-1), 500, 'le global doit venir de la zone *, pas de la somme des vhosts');
  assert.strictEqual(M.vhostRateHistory.get('site-a.fr').requests.at(-1), 300);
  assert.strictEqual(M.vhostRateHistory.get('site-b.fr').requests.at(-1), 200);
  assert.ok(!M.vhostRateHistory.has('*'), 'la zone agregee ne doit pas apparaitre comme un vhost filtrable');
});
check('un vhost disparu longtemps est purge, pas accumule indefiniment', () => {
  M.vhostRateHistory.clear();
  M.vhostRateHistory.set('vieux-site.fr', { timestamps: [1], requests: [1], lastSeen: Date.now() - 999_999_999 });
  M.recordSample({ serverZones: { '*': { requestCounter: 1 } } });
  assert.ok(!M.vhostRateHistory.has('vieux-site.fr'), 'un vhost non revu depuis longtemps doit etre purge');
});
check('le nombre d echantillons par serie est plafonne', () => {
  M.vhostRateHistory.clear();
  for (let i = 0; i < M.MAX_RATE_HISTORY + 50; i++) {
    M.recordSample({ serverZones: { '*': { requestCounter: i }, 'x.fr': { requestCounter: i } } });
  }
  assert.ok(M.globalRateHistory.timestamps.length <= M.MAX_RATE_HISTORY);
  assert.ok(M.vhostRateHistory.get('x.fr').timestamps.length <= M.MAX_RATE_HISTORY);
});

console.log('\nchamp actif/en cours de traitement (fix MISC-11)');
check('requestMsecCounter (compteur cumule en ms) n est plus utilise comme "active"', () => {
  const vts = { serverZones: { '*': { requestCounter: 10, requestMsecCounter: 999_999_999 } } };
  assert.strictEqual(M.computeTotals(vts).active, 0, 'un compteur de millisecondes cumulees n est pas un nombre de requetes actives');
});
check('requests.processing est bien lu quand il est present (forme JSON recente)', () => {
  const vts = { serverZones: { '*': { requests: { total: 10, processing: 3 } } } };
  assert.strictEqual(M.computeTotals(vts).active, 3);
});
check('listZones : idem pour le champ processing par vhost', () => {
  const vts = { serverZones: { 'a.com': { requestCounter: 5, requestMsecCounter: 123456, requests: { processing: 2 } } } };
  const z = M.listZones(vts)[0];
  assert.strictEqual(z.requests.processing, 2);
});
check('listZones : forme ancienne sans champ processing -> 0, pas le compteur ms', () => {
  const vts = { serverZones: { 'a.com': { requestCounter: 5, requestMsecCounter: 123456 } } };
  const z = M.listZones(vts)[0];
  assert.strictEqual(z.requests.processing, 0);
});

console.log('\nfetchVTS : timeout sur un endpoint VTS injoignable (fix MISC-11)');
(async () => {
  const net = require('net');
  // Un serveur qui accepte la connexion TCP mais ne repond jamais : sans
  // timeout applicatif, fetchVTS() resterait en attente indefiniment.
  const hang = net.createServer(() => {});
  await new Promise(r => hang.listen(0, '127.0.0.1', r));
  const port = hang.address().port;
  const before = process.env.NGINX_VTS_URL;
  process.env.NGINX_VTS_URL = `http://127.0.0.1:${port}/status/format/json`;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/metrics')];
  const M2 = require('../features/metrics');
  const start = Date.now();
  const result = await M2.fetchVTS();
  const elapsed = Date.now() - start;
  await check('fetchVTS() se resout (avec null) plutot que de pendre indefiniment', () => {
    assert.strictEqual(result, null);
    assert.ok(elapsed < 8000, `fetchVTS a mis ${elapsed}ms, le timeout applicatif ne semble pas actif`);
  });
  if (before === undefined) delete process.env.NGINX_VTS_URL; else process.env.NGINX_VTS_URL = before;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/metrics')];
  hang.close();
})().then(() => {
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
});
