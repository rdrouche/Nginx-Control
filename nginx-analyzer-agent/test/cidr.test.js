'use strict';
const assert=require('assert');
const C=require('../lib/cidr');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\nIPv4');
check('appartenance a un bloc /24',   ()=>assert.ok(C.ipInCidr('203.0.113.5','203.0.113.0/24')));
check('hors du bloc',                 ()=>assert.ok(!C.ipInCidr('203.0.114.5','203.0.113.0/24')));
check('bloc /32 = adresse exacte',    ()=>assert.ok(C.ipInCidr('203.0.113.5','203.0.113.5/32')));
check('sans prefixe = exact',         ()=>{
  assert.ok(C.ipInCidr('203.0.113.5','203.0.113.5'));
  assert.ok(!C.ipInCidr('203.0.113.5','203.0.113.6'));
});
check('/0 englobe toute adresse v4',  ()=>assert.ok(C.ipInCidr('1.2.3.4','0.0.0.0/0')));
check('frontiere de bloc respectee',  ()=>{
  assert.ok(C.ipInCidr('10.0.0.0','10.0.0.0/8'));
  assert.ok(C.ipInCidr('10.255.255.255','10.0.0.0/8'));
  assert.ok(!C.ipInCidr('11.0.0.0','10.0.0.0/8'));
});
check('prefixe non multiple de 8',    ()=>{
  assert.ok(C.ipInCidr('192.168.1.5','192.168.0.0/20'));
  assert.ok(!C.ipInCidr('192.168.16.5','192.168.0.0/20'));
});

console.log('\nIPv6');
check('appartenance a un bloc /32',   ()=>assert.ok(C.ipInCidr('2001:db8::1','2001:db8::/32')));
check('hors du bloc',                 ()=>assert.ok(!C.ipInCidr('2001:db9::1','2001:db8::/32')));
check('adresse exacte sans prefixe',  ()=>assert.ok(C.ipInCidr('::1','::1')));
check('compression :: correctement decompressee', ()=>{
  const a=C.ipv6ToBytes('2001:db8::1');
  const b=C.ipv6ToBytes('2001:0db8:0000:0000:0000:0000:0000:0001');
  assert.deepStrictEqual(a,b);
});
check('adresse IPv4-mappee reconnue', ()=>{
  const r=C.toBytes('::ffff:203.0.113.5');
  assert.strictEqual(r.family,6);
  assert.deepStrictEqual(r.bytes.slice(-4),[203,0,113,5]);
});

console.log('\nisolation entre familles');
check('une adresse v4 n appartient jamais a un bloc v6', ()=>assert.ok(!C.ipInCidr('1.2.3.4','::1/128')));
check('une adresse v6 n appartient jamais a un bloc v4', ()=>assert.ok(!C.ipInCidr('::1','1.2.3.4/32')));

// Fix (audit report, Basse/Analyzer, "::ffff:a.b.c.d ne correspond pas a un
// CIDR IPv4") : une IPv4-mappee EST la meme adresse que sa forme IPv4 nue, et
// doit matcher un bloc v4 (et reciproquement pour un bloc v6 mappe).
console.log('\nadresses IPv4-mappees (fix Basse/Analyzer)');
check('::ffff:a.b.c.d correspond a un bloc IPv4 qui la contient', ()=>{
  assert.ok(C.ipInCidr('::ffff:203.0.113.5','203.0.113.0/24'));
  assert.ok(!C.ipInCidr('::ffff:203.0.113.5','203.0.114.0/24'));
});
check('::ffff:a.b.c.d exacte correspond a l adresse IPv4 nue equivalente', ()=>{
  assert.ok(C.ipInCidr('::ffff:203.0.113.5','203.0.113.5'));
});
check('une adresse IPv6 non mappee ne correspond jamais a un bloc IPv4', ()=>{
  assert.ok(!C.ipInCidr('2001:db8::1','0.0.0.0/0'));
});
check('une adresse IPv4 nue correspond a un bloc IPv6-mappe qui la contient', ()=>{
  assert.ok(C.ipInCidr('203.0.113.5','::ffff:203.0.113.0/120'));
  assert.ok(!C.ipInCidr('203.0.114.5','::ffff:203.0.113.0/120'));
});
check('un bloc IPv6-mappe avec moins de 96 bits fixes ne se ramene pas a un bloc IPv4', ()=>{
  assert.ok(!C.ipInCidr('203.0.113.5','::ffff:203.0.113.0/64'));
});

console.log('\nrobustesse (rien ne doit lever)');
for (const [label,ip,pat] of [
  ['IP vide','',''],
  ['IP invalide','pas-une-ip','0.0.0.0/0'],
  ['octet hors limite','999.1.1.1','0.0.0.0/0'],
  ['CIDR sans adresse','','/24'],
  ['prefixe hors limite (v4)','1.2.3.4','1.2.3.4/99'],
  ['prefixe hors limite (v6)','::1','::1/999'],
  ['prefixe negatif','1.2.3.4','1.2.3.4/-1'],
  ['double ::','1::2::3','1::2::3/64'],
  ['null/undefined',null,undefined],
])
  check(`${label} -> false, pas d exception`, ()=>assert.strictEqual(C.ipInCidr(ip,pat),false));

// Fix (audit report, Basse/Analyzer, "un espace final dans un prefixe le
// rend invalide") : un CIDR par ailleurs valide etait rejete a cause d une
// espace de trop, cosmetique, autour du motif.
console.log('\nespaces superflus (fix Basse/Analyzer)');
check('espace final apres le prefixe -> toujours valide', ()=>{
  assert.ok(C.isValidPattern('203.0.113.0/24 '));
  assert.ok(C.ipInCidr('203.0.113.5','203.0.113.0/24 '));
});
check('espace au debut et/ou autour du "/" -> toujours valide', ()=>{
  assert.ok(C.isValidPattern(' 203.0.113.0/24'));
  assert.ok(C.isValidPattern('2001:db8::/32 '));
});

console.log('\nvalidation de motif (pour le formulaire d exception)');
check('adresse simple valide',  ()=>assert.ok(C.isValidPattern('203.0.113.5')));
check('CIDR valide',            ()=>assert.ok(C.isValidPattern('203.0.113.0/24')));
check('CIDR v6 valide',         ()=>assert.ok(C.isValidPattern('2001:db8::/32')));
check('motif invalide rejete',  ()=>{
  assert.ok(!C.isValidPattern('pas-une-ip'));
  assert.ok(!C.isValidPattern('1.2.3.4/33'));
  assert.ok(!C.isValidPattern(''));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
