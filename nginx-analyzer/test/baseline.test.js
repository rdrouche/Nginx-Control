'use strict';
/**
 * La detection volumetrique echoue habituellement de trois facons : elle ignore
 * la saisonnalite, elle se laisse empoisonner par une attaque passee, et elle
 * confond un succes avec une attaque. Ces tests couvrent les trois.
 */
// Fix (audit report, Basse/Analyzer, "creneaux de baseline en UTC..."):
// hourOfWeek() bucket désormais par heure LOCALE (voir lib/baseline.js), pas
// UTC — ce test construit ses dates avec Date.UTC() et attend des numeros de
// creneau precis, donc il fixe explicitement le fuseau du PROCESSUS de test
// a UTC pour rester deterministe quel que soit le fuseau systeme de la
// machine qui l execute (elle peut tres bien ne pas etre en UTC).
process.env.TZ = 'UTC';
const assert=require('assert');
const { Baseline, hourOfWeek, median, mad }=require('../lib/baseline');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const OLD = Date.now() - 30*86400000;   // apprentissage termine
const m=(requests,o={})=>({requests,distinctIps:Math.ceil(requests/2),distinctPaths:Math.ceil(requests/10),errors:0,...o});
// Mardi 14h UTC, puis les mardis suivants
const tue=(w=0,h=14)=>new Date(Date.UTC(2026,8,8+7*w,h,0,0));

console.log('\nstatistiques robustes');
check('mediane', ()=>{
  assert.strictEqual(median([1,2,3]),2);
  assert.strictEqual(median([1,2,3,4]),2.5);
});
check('MAD ignore les valeurs extremes', ()=>{
  const normal=[100,102,98,101,99];
  const avecAttaque=[100,102,98,101,99,50000];
  const madN=mad(normal,median([...normal].sort((a,b)=>a-b)));
  const madA=mad(avecAttaque,median([...avecAttaque].sort((a,b)=>a-b)));
  // L ecart-type exploserait ; le MAD reste du meme ordre.
  assert.ok(madA < madN*3, `MAD passe de ${madN.toFixed(1)} a ${madA.toFixed(1)}`);
});
check('heure de la semaine', ()=>{
  assert.strictEqual(hourOfWeek(new Date(Date.UTC(2026,8,7,0,0))),0,'lundi 00h');
  assert.strictEqual(hourOfWeek(new Date(Date.UTC(2026,8,8,14,0))),38,'mardi 14h');
});

console.log('\nperiode d apprentissage');
check('aucune alerte pendant l apprentissage', ()=>{
  const b=new Baseline({learningDays:21});
  for(let w=0;w<5;w++) b.observe('site.fr',tue(w),m(100));
  const r=b.check('site.fr',tue(5),m(100000));
  assert.strictEqual(r.learning,true,'doit signaler l apprentissage, pas alerter');
  assert.ok(!r.anomaly);
});
check('l etat indique la progression', ()=>{
  const b=new Baseline({learningDays:21});
  const s=b.stats();
  assert.strictEqual(s.learning,true);
  assert.strictEqual(s.daysRequired,21);
});

console.log('\nsaisonnalite');
check('un creneau creux ne declenche pas sur le trafic d un creneau charge', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  // Mardi 14h : 1000 requetes. Dimanche 4h : 20 requetes.
  for(let w=0;w<6;w++){
    b.observe('site.fr',tue(w,14),m(1000));
    b.observe('site.fr',new Date(Date.UTC(2026,8,13+7*w,4,0)),m(20));
  }
  // 1000 requetes un mardi 14h : normal.
  assert.strictEqual(b.check('site.fr',tue(6,14),m(1000)),null);
  // 1000 requetes un dimanche 4h : anormal.
  const r=b.check('site.fr',new Date(Date.UTC(2026,8,55,4,0)),m(1000,{distinctIps:2,distinctPaths:1}));
  assert.ok(r && r.anomaly,'un pic hors creneau doit alerter');
});

console.log('\nechantillon insuffisant');
check('moins de 3 observations -> silence', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  b.observe('site.fr',tue(0),m(100));
  b.observe('site.fr',tue(1),m(100));
  assert.strictEqual(b.check('site.fr',tue(2),m(10000)),null);
});
check('petit volume ignore', ()=>{
  const b=new Baseline({minAbsoluteRequests:100},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(2));
  assert.strictEqual(b.check('site.fr',tue(6),m(50)),null,'50 requetes ne meritent pas une alerte');
});

console.log('\ndetection d ecart');
check('un pic important alerte', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(1000));
  const r=b.check('site.fr',tue(6),m(50000,{distinctIps:3,distinctPaths:2,errors:40000}));
  assert.ok(r && r.anomaly);
  assert.ok(r.deviation>6);
  assert.strictEqual(r.expected,1000);
});
check('une variation normale n alerte pas', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(const v of [900,1100,950,1050,1000,980]) b.observe('site.fr',tue(0),m(v));
  assert.strictEqual(b.check('site.fr',tue(6),m(1150)),null);
});

console.log('\nsucces ou attaque : la structure tranche');
check('une audience reelle est signalee comme telle', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(1000));
  // Beaucoup d IP distinctes, chemins varies, peu d erreurs : un article qui marche.
  const r=b.check('site.fr',tue(6),{requests:20000,distinctIps:8000,distinctPaths:1500,errors:100});
  assert.ok(r.anomaly);
  assert.strictEqual(r.structure.looksOrganic,true);
  assert.strictEqual(r.severity,'low','ne doit pas etre traite comme une attaque');
});
check('un flood est signale comme tel', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(1000));
  // Peu d IP, un seul chemin, beaucoup d erreurs.
  const r=b.check('site.fr',tue(6),{requests:20000,distinctIps:4,distinctPaths:1,errors:15000});
  assert.strictEqual(r.structure.looksOrganic,false);
  assert.ok(['medium','high'].includes(r.severity));
});

console.log('\nempoisonnement de la reference');
check('une periode marquee normale n entre pas dans la baseline', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(1000));
  const spike=tue(6);
  b.exclude('site.fr',spike.toISOString());
  b.observe('site.fr',spike,m(99999));
  const ref=b.reference('site.fr',tue(7));
  assert.strictEqual(ref.median,1000,'le pic exclu ne doit pas deplacer la mediane');
});

console.log('\npersistance');
check('l etat survit a un redemarrage', ()=>{
  const b=new Baseline({},{startedAt:OLD});
  for(let w=0;w<6;w++) b.observe('site.fr',tue(w),m(1000));
  const b2=new Baseline({},JSON.parse(JSON.stringify(b.toJSON())));
  assert.strictEqual(b2.reference('site.fr',tue(6)).median,1000);
  assert.strictEqual(b2.isLearning(),false,'la date de depart doit etre conservee');
});

console.log('\ncouverture (bug reel : % incoherent avec plusieurs vhosts)');
check('coverage() rapporte au nombre REEL de creneaux possibles (vhosts suivis x 168), jamais a 168 fixe', ()=>{
  // Bug reel, retour utilisateur : "Usable time slots: 1888 / 168 (1123.8%)".
  // this.buckets est une grille PAR VHOST (cle `${vhost}|${hourOfWeek}`) : avec
  // plusieurs vhosts actifs, il existe vhosts*168 creneaux possibles, pas 168.
  // Diviser par 168 fixe fait donc largement depasser 100% des qu on suit plus
  // d un vhost — exactement le symptome signale.
  const b = new Baseline({ minSamplesPerBucket: 1 }, { startedAt: OLD });
  // 3 vhosts suivis (>= 24 heures observees chacun) : 24 creneaux utilisables par
  // vhost sur un total reel de 3*168 = 504, jamais sur 168.
  for (const v of ['a.example.com', 'b.example.com', 'c.example.com']) for (let h = 0; h < 24; h++) b.observe(v, tue(0, h), m(100));
  const s = b.stats();
  assert.strictEqual(s.vhostsTracked, 3, 'doit compter les vhosts distincts, pas les creneaux');
  assert.strictEqual(s.bucketsUsable, 72);
  assert.strictEqual(s.totalSlots, 3 * 168, 'le total doit suivre le nombre de vhosts suivis');
  assert.ok(s.coverage <= 100, `coverage ne doit jamais depasser 100% (obtenu ${s.coverage}%)`);
  assert.strictEqual(s.coverage, +(100 * 72 / (3 * 168)).toFixed(1));
});
check('un seul vhost retombe sur le comportement historique (total = 168)', ()=>{
  const b = new Baseline({ minSamplesPerBucket: 1 }, { startedAt: OLD });
  for (let h = 0; h < 24; h++) b.observe('site.fr', tue(0, h), m(100));
  const s = b.stats();
  assert.strictEqual(s.vhostsTracked, 1);
  assert.strictEqual(s.totalSlots, 168);
  assert.strictEqual(s.coverage, +(100 * 24 / 168).toFixed(1));
});
check('aucun vhost suivi -> pas de division par zero', ()=>{
  const b = new Baseline({}, { startedAt: OLD });
  const s = b.stats();
  assert.strictEqual(s.vhostsTracked, 0);
  assert.strictEqual(s.bucketsUsable, 0);
  assert.strictEqual(s.coverage, 0);
});

console.log('\nv12.68.0 : cles sporadiques, profil appris');
check('un Host croise une fois (cle sporadique) ne gonfle plus le denominateur', ()=>{
  const b = new Baseline({ minSamplesPerBucket: 1 }, { startedAt: OLD });
  for (let h = 0; h < 24; h++) b.observe('site.fr', tue(0, h), m(100));
  for (let i = 0; i < 50; i++) b.observe('scan' + i + '.bot', tue(0, 3), m(2));
  const s = b.stats();
  assert.strictEqual(s.vhostsTracked, 1);
  assert.strictEqual(s.keysTracked, 51);
  assert.strictEqual(s.sporadicKeys, 50);
  assert.strictEqual(s.totalSlots, 168);
  assert.strictEqual(s.coverage, +(100 * 24 / 168).toFixed(1));
});
check('profile() : 168 creneaux, mediane/seuil pour les creneaux appris, vide sinon', ()=>{
  const b = new Baseline({ minSamplesPerBucket: 3, sigmaThreshold: 6, minAbsoluteRequests: 100 }, { startedAt: OLD });
  for (let w = 0; w < 3; w++) b.observe('site.fr', tue(w, 14), m(1000 + w * 10));
  b.observe('site.fr', tue(0, 15), m(500));
  const p = b.profile('site.fr');
  assert.strictEqual(p.slots.length, 168);
  const tue14 = p.slots[hourOfWeek(tue(0, 14))];
  assert.strictEqual(tue14.usable, true);
  assert.strictEqual(tue14.median, 1010);
  assert.ok(tue14.threshold > tue14.median);
  const tue15 = p.slots[hourOfWeek(tue(0, 15))];
  assert.strictEqual(tue15.usable, false);
  assert.strictEqual(tue15.samples, 1);
  assert.strictEqual(p.slots[0].samples, 0);
});
check('keysSummary() : tri par volume hebdomadaire, creneau de pointe', ()=>{
  const b = new Baseline({ minSamplesPerBucket: 1 }, { startedAt: OLD });
  for (let h = 0; h < 24; h++) b.observe('gros.fr', tue(0, h), m(h === 14 ? 900 : 100));
  for (let h = 0; h < 24; h++) b.observe('petit.fr', tue(0, h), m(10));
  const k = b.keysSummary();
  assert.strictEqual(k[0].key, 'gros.fr');
  assert.strictEqual(k[0].peakPerHour, 900);
  assert.strictEqual(k[0].peakHow, hourOfWeek(tue(0, 14)));
  assert.strictEqual(k[0].relevant, true);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
