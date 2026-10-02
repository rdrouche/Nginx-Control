'use strict';
/**
 * Les montages du conteneur de test etaient figes en dur. Chaque montage ajoute
 * en production cassait ensuite `nginx -t` avec une erreur qui ressemblait a un
 * probleme de configuration : d abord les certificats, puis les bases GeoIP.
 * On verifie ici la logique de selection.
 */
const assert=require('assert');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

// Reproduit la logique de buildTestBinds sans dependre de Docker
const overridden = new Set(['/etc/nginx/sites','/etc/nginx/conf.d','/etc/nginx/snippets',
                            '/etc/nginx/streams','/ssl','/etc/letsencrypt']);
const writable   = new Set(['/var/log/nginx','/var/cache/nginx','/run','/tmp']);
function select(mounts){
  return mounts.filter(m => m.Source && m.Destination
    && !overridden.has(m.Destination) && !writable.has(m.Destination))
    .map(m => `${m.Source}:${m.Destination}:ro`);
}

// Montages typiques du nginx de production
const prod = [
  {Source:'/c/nginx-rproxy/geoip_data', Destination:'/geoip'},
  {Source:'/c/nginx-rproxy/webroot',    Destination:'/var/www'},
  {Source:'/c/nginx-rproxy/modules',    Destination:'/etc/nginx/modules'},
  {Source:'/c/nginx-rproxy/sites',      Destination:'/etc/nginx/sites'},
  {Source:'/c/nginx-rproxy/conf',       Destination:'/etc/nginx/conf.d'},
  {Source:'/c/nginx-rproxy/ssl',        Destination:'/ssl'},
  {Source:'/c/nginx-rproxy/certs',      Destination:'/etc/letsencrypt'},
  {Source:'/c/nginx-rproxy/logs',       Destination:'/var/log/nginx'},
  {Source:'/c/nginx-rproxy/cache',      Destination:'/var/cache/nginx'},
];

console.log('\nselection des montages herites');
const got = select(prod);
check('la base GeoIP est heritee (le bug du jour)', ()=>{
  assert.ok(got.some(b=>b.endsWith(':/geoip:ro')), got.join(' | '));
});
check('le webroot est herite (challenge ACME)', ()=>assert.ok(got.some(b=>b.endsWith(':/var/www:ro'))));
check('les modules sont herites', ()=>assert.ok(got.some(b=>b.endsWith(':/etc/nginx/modules:ro'))));

console.log('\nexclusions');
for (const d of ['/etc/nginx/sites','/etc/nginx/conf.d','/ssl','/etc/letsencrypt'])
  check(`${d} vient du bac a sable, pas de la prod`, ()=>assert.ok(!got.some(b=>b.includes(':'+d+':'))));
for (const d of ['/var/log/nginx','/var/cache/nginx'])
  check(`${d} n est pas monte en lecture seule`, ()=>{
    // nginx -t doit pouvoir ouvrir ses fichiers de log
    assert.ok(!got.some(b=>b.includes(':'+d+':')));
  });

console.log('\nrobustesse');
check('montage sans Source ignore', ()=>{
  assert.deepStrictEqual(select([{Destination:'/x'}]), []);
});
check('aucun montage', ()=>assert.deepStrictEqual(select([]), []));
check('tous herites en lecture seule', ()=>assert.ok(got.every(b=>b.endsWith(':ro'))));

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
