'use strict';
/**
 * Les routes CrowdSec capturent leurs erreurs et repondent 200 avec un champ
 * `error`. Une erreur de programmation y devient donc un succes HTTP, invisible
 * au test de fumee : c est ainsi que `promSum is not defined` a survecu.
 * On exerce ici les fonctions d agregation directement.
 */
const assert=require('assert');
const CS=require('../features/crowdsec');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const METRICS = `
# HELP cs_bucket_overflowed_total
cs_bucket_overflowed_total{name="http-crawl"} 12
cs_bucket_overflowed_total{name="ssh-bf"} 30
cs_bucket_instantiation_total{name="http-crawl"} 100
cs_parser_hits_ok_total{source="file:/var/log/nginx/access.log"} 4200
cs_parser_hits_ok_total{source="file:/var/log/auth.log"} 800
cs_parser_hits_ko_total{source="file:/var/log/nginx/access.log"} 15
cs_lapi_request_total{route="/v1/decisions",method="GET"} 42
`.trim();

console.log('\nanalyse du format Prometheus');
check('metriques et labels extraits', ()=>{
  const m=CS.parsePrometheus(METRICS);
  assert.strictEqual(m.cs_bucket_overflowed_total.length,2);
  assert.strictEqual(m.cs_bucket_overflowed_total[0].labels.name,'http-crawl');
  assert.strictEqual(m.cs_bucket_overflowed_total[0].value,12);
});
check('lignes de commentaire ignorees', ()=>{
  assert.ok(!('# HELP cs_bucket_overflowed_total' in CS.parsePrometheus(METRICS)));
});
check('texte vide', ()=>assert.deepStrictEqual(CS.parsePrometheus(''),{}));
check('valeurs en notation scientifique', ()=>{
  const m=CS.parsePrometheus('cs_x{a="b"} 1.5e3');
  assert.strictEqual(m.cs_x[0].value,1500);
});
check('metrique sans label', ()=>{
  const m=CS.parsePrometheus('cs_simple 7');
  assert.strictEqual(m.cs_simple[0].value,7);
  assert.deepStrictEqual(m.cs_simple[0].labels,{});
});

console.log('\nagregation (le chemin ou promSum manquait)');
check('promSum est defini et somme les series', ()=>{
  assert.strictEqual(typeof CS.promSum,'function','promSum doit etre exporte');
  const m=CS.parsePrometheus(METRICS);
  assert.strictEqual(CS.promSum(m,'cs_bucket_overflowed_total'),42);
  assert.strictEqual(CS.promSum(m,'cs_parser_hits_ok_total'),5000);
});
check('filtrage par label', ()=>{
  const m=CS.parsePrometheus(METRICS);
  assert.strictEqual(CS.promSum(m,'cs_bucket_overflowed_total','name','ssh-bf'),30);
  assert.strictEqual(CS.promSum(m,'cs_bucket_overflowed_total','name','inexistant'),0);
});
check('metrique absente -> 0, sans exception', ()=>{
  assert.strictEqual(CS.promSum(CS.parsePrometheus(METRICS),'cs_inexistant'),0);
});

console.log('\nconfiguration');
check('non configure sans variables', ()=>assert.strictEqual(CS.crowdsecConfigured(),false));

console.log('\ncoherence du filtre local/CAPI (IP bannies manquantes malgre des stats correctes)');
check('la liste des decisions ne filtre plus sur origin=crowdsec exact', ()=>{
  const src=require('fs').readFileSync(require('path').join(__dirname,'..','features','crowdsec.js'),'utf8');
  // Un ban ajoute par cscli ou une liste communautaire (origin != CAPI, != crowdsec)
  // devait disparaitre de la liste tout en restant compte dans les stats.
  assert.ok(!/&origin=crowdsec/.test(src),
    'le filtre LAPI ne doit plus restreindre strictement a origin=crowdsec');
  assert.ok(/dec\.origin !== 'CAPI'/.test(src),
    'le filtre applique doit etre le meme "local = pas CAPI" que celui des compteurs');
});
check('lapiUnavailable est expose quand les identifiants LAPI manquent', ()=>{
  const src=require('fs').readFileSync(require('path').join(__dirname,'..','features','crowdsec.js'),'utf8');
  assert.ok(/lapiUnavailable/.test(src),
    'l absence de LAPI doit etre signalee explicitement, pas seulement une liste vide');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
