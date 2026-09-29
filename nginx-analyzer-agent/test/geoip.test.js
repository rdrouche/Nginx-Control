'use strict';
/**
 * Le lecteur MMDB est ecrit a la main, sans dependance. Il a echoue de deux
 * facons a la fois, toutes deux silencieuses parce qu un `catch` renvoyait
 * `null` : une fonction manquante, et un depart d arbre errone pour les IPv4
 * dans une base IPv6. Resultat visible : une ventilation par pays entierement
 * vide, alors que la base etait bien detectee.
 *
 * Les IP utilisees ici viennent du jeu de test officiel de MaxMind.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const DB=path.join(__dirname,'fixtures','test-country.mmdb');
process.env.GEOIP_COUNTRY_DB=DB;
process.env.GEOIP_CITY_DB='/nexiste/pas.mmdb';
process.env.GEOIP_ASN_DB='/nexiste/pas.mmdb';
const G=require('../lib/geoip');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\nbase de test presente');
check('le fichier existe', ()=>assert.ok(fs.existsSync(DB)));
check('init detecte la base', ()=>assert.strictEqual(G.init(),true));

console.log('\nresolution (jeu de test MaxMind)');
for (const [ip,cc] of [['81.2.69.160','GB'],['2.125.160.216','GB'],
                       ['89.160.20.112','SE'],['67.43.156.1','BT']])
  check(`${ip} -> ${cc}`, ()=>assert.strictEqual(G.countryOf(ip),cc));

check('une IP absente de la base -> null, sans exception', ()=>{
  assert.strictEqual(G.countryOf('8.8.8.8'),null);
});

// Fix (audit report, Basse/Analyzer, "IPv6 jamais geolocalise") : le lecteur
// ne savait parser QUE des adresses IPv4 (ip.split('.').map(Number)) et
// renvoyait null immediatement sur toute adresse contenant ':' — alors que
// la base elle-meme est bien double-pile (ip_version=6) et sait repondre.
console.log('\nresolution IPv6 (fix Basse/Analyzer)');
check('adresse IPv6 native -> JP (jeu de test MaxMind)', ()=>{
  const r = G.mmdbLookup(DB,'2001:218::');
  assert.ok(r && r.country && r.country.iso_code === 'JP', JSON.stringify(r));
});
check('adresse IPv6 native -> SE (jeu de test MaxMind)', ()=>{
  const r = G.mmdbLookup(DB,'2001:220::');
  assert.ok(r && r.country && r.country.iso_code === 'SE', JSON.stringify(r));
});
check('adresse IPv4-mappee (::ffff:a.b.c.d) donne le meme resultat que l IPv4 nue', ()=>{
  assert.strictEqual(G.countryOf('::ffff:89.160.20.112'), G.countryOf('89.160.20.112'));
});
check('adresse IPv6 sans correspondance -> null, sans exception', ()=>{
  assert.strictEqual(G.mmdbLookup(DB,'2003::'),null);
});
check('adresse IPv6 malformee -> null, sans exception', ()=>{
  assert.strictEqual(G.mmdbLookup(DB,':::'),null);
  assert.strictEqual(G.mmdbLookup(DB,'::ffff:999.1.1.1'),null);
});

console.log('\nrobustesse');
check('adresse malformee', ()=>{
  for (const bad of ['pas-une-ip','999.1.1.1','',null,'1.2.3'])
    assert.strictEqual(G.countryOf(bad),null);
});
check('base inexistante', ()=>assert.strictEqual(G.mmdbLookup('/nexiste/pas.mmdb','8.8.8.8'),null));
check('fichier non-MMDB', ()=>{
  const tmp='/tmp/pas-une-base.mmdb';
  fs.writeFileSync(tmp,'ceci n est pas une base');
  assert.strictEqual(G.mmdbLookup(tmp,'8.8.8.8'),null);
  fs.unlinkSync(tmp);
});

console.log('\ncache');
check('deux appels identiques donnent le meme resultat', ()=>{
  assert.strictEqual(G.countryOf('81.2.69.160'),G.countryOf('81.2.69.160'));
  assert.ok(G.status().cached>0,'le cache doit se remplir');
});

console.log('\nnon-regression : les fonctions internes existent');
check('bufIndexOf et readNode definis', ()=>{
  // Une fonction manquante ici ne se voit pas : le catch renvoie null et la
  // ventilation par pays reste vide sans qu aucune erreur ne remonte.
  const src=fs.readFileSync(path.join(__dirname,'..','lib','geoip.js'),'utf8');
  assert.ok(/function bufIndexOf/.test(src),'bufIndexOf manquant');
  assert.ok(/function readNode/.test(src),'readNode manquant');
});
check('pas de saut direct au noeud 96', ()=>{
  const src=fs.readFileSync(path.join(__dirname,'..','lib','geoip.js'),'utf8');
  assert.ok(!/=\s*\(meta\.ip_version === 6\)\s*\?\s*96/.test(src),
    'le raccourci vers le noeud 96 est faux : il faut parcourir 96 bits');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
