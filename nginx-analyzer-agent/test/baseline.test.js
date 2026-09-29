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

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
