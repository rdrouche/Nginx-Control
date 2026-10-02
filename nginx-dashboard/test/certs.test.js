'use strict';
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const {execSync}=require('child_process');
const C=require('../lib/certs');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'certs-'));
const crt=path.join(tmp,'c.pem');
let haveOpenssl=true;
try{
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${tmp}/k.pem -out ${crt} -days 30 -nodes `+
           `-subj "/CN=test.example.com" -addext "subjectAltName=DNS:test.example.com,DNS:*.test.example.com" 2>/dev/null`);
}catch{ haveOpenssl=false; }

console.log('\nrobustesse (le plus important : ne jamais lever)');
check('PEM invalide -> objet erreur',   ()=>{const r=C.parseCert('bidon'); assert.ok(r.error);});
check('chaine vide -> objet erreur',    ()=>{assert.ok(C.parseCert('').error);});
check('parseCertSANs sur bidon',        ()=>{const r=C.parseCertSANs('bidon'); assert.deepStrictEqual(r.domains,[]);});
check('safeReadFile vit dans fs-tree', ()=>{const T=require('../lib/fs-tree'); assert.strictEqual(T.safeReadFile('/nexiste/pas'),null);});
check('scanCertsDir dossier absent',    ()=>assert.deepStrictEqual(C.scanCertsDir('/nexiste/pas'),[]));
check('listExistingCerts sans dossier', ()=>assert.ok(Array.isArray(C.listExistingCerts())));

console.log('\nagregation (le chemin qui appelle toutes les autres fonctions)');
check('getAllCertificates ne leve pas', ()=>{
  const r=C.getAllCertificates();
  assert.ok(r && typeof r==='object');
  assert.ok(Array.isArray(r.certificates), 'certificates doit etre un tableau');
  assert.ok(r.summary && typeof r.summary.total==='number');
});
check('scanSslDir dossier absent', ()=>assert.deepStrictEqual(C.scanSslDir('/nexiste/pas'),[]));

console.log('\ndetection de conflit de domaine');
check('aucun cert -> aucun conflit', ()=>{
  const r=C.checkDomainConflict('site.example.com');
  assert.strictEqual(r.conflict,false);
});

if (haveOpenssl) {
  console.log('\nlecture d un certificat reel');
  const pem=fs.readFileSync(crt,'utf8');
  check('sujet lu',        ()=>assert.ok(C.parseCert(pem).subject.includes('test.example.com')));
  check('expiration lue',  ()=>{const r=C.parseCert(pem); assert.ok(r.daysLeft>=28&&r.daysLeft<=30);});
  check('non expire',      ()=>assert.strictEqual(C.parseCert(pem).expired,false));
  check('empreinte sha256',()=>assert.ok(/^[0-9A-F:]+$/.test(C.parseCert(pem).fingerprint256)));
  check('SANs remontes',   ()=>assert.ok(C.parseCert(pem).sans));
  check('parseCertSANs trouve le domaine', ()=>{
    assert.ok(C.parseCertSANs(pem).domains.includes('test.example.com'));
  });
  check('parseCertSANs lit la date de fin', ()=>assert.ok(C.parseCertSANs(pem).notAfter instanceof Date));
  check('parseCertSANs lit aussi la date de debut (notBefore)', ()=>{
    const r = C.parseCertSANs(pem);
    assert.ok(r.notBefore instanceof Date);
    assert.ok(r.notBefore < r.notAfter);
  });

  console.log('\nseuil d avertissement adapte a la duree de vie reelle (pas un nombre de jours fige)');
  check('parseCert() calcule totalDays (duree de vie totale en jours)', () => {
    const r = C.parseCert(pem);
    assert.ok(r.totalDays >= 29 && r.totalDays <= 31, `totalDays=${r.totalDays}`);
  });
  check('signalement reel : un certificat delivre pour seulement 30 jours ne doit PAS ' +
        'basculer "bientot expire" des sa delivrance (avant ce correctif, le seuil fixe ' +
        'de 30 jours == 100% de sa duree de vie, donc warning:true immediatement)', () => {
    const r = C.parseCert(pem);
    assert.strictEqual(r.warning, false, `warning ne devrait pas etre vrai a J-${r.daysLeft} sur une duree de vie de ${r.totalDays}j`);
  });
} else {
  console.log('\n  (openssl indisponible — tests sur certificat reel ignores)');
}

console.log('\nadaptiveThreshold() — seuil plafonne au tiers de la duree de vie totale');
check('certificat 90 jours (Let\'s Encrypt) : seuil configure (30j) inchange, c est deja 1/3', () => {
  assert.strictEqual(C.adaptiveThreshold(90, 30), 30);
});
check('certificat 30 jours : seuil ramene a 10j (30/3), pas les 30j configures', () => {
  assert.strictEqual(C.adaptiveThreshold(30, 30), 10);
});
check('certificat 1 an (365j) : seuil configure (30j) inchange, tres inferieur au tiers', () => {
  assert.strictEqual(C.adaptiveThreshold(365, 30), 30);
});
check('certificat tres court (6 jours) : seuil plancher a 3 jours, jamais 0', () => {
  assert.strictEqual(C.adaptiveThreshold(6, 30), 3);
});
check('duree de vie totale inconnue (null/0) -> repli sur le seuil configure tel quel', () => {
  assert.strictEqual(C.adaptiveThreshold(null, 30), 30);
  assert.strictEqual(C.adaptiveThreshold(0, 30), 30);
});

fs.rmSync(tmp,{recursive:true,force:true});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
