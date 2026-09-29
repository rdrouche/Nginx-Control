'use strict';
/**
 * La rotation est toute la difficulte : suivre un chemin naivement relit tout
 * depuis le debut, ou continue de lire un fichier renomme. L inode identifie le
 * fichier, pas le chemin.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { Tailer }=require('../lib/tail');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'tail-'));
const LOG=path.join(tmp,'site.fr.access.log');
const line=(p='/')=>`203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET ${p} HTTP/1.1" 200 100 "-" "curl/8"\n`;

// Faux store en memoire
const mkStore=()=>{const m=new Map();return{
  getOffset:f=>m.get(f)||null,
  setOffset:(f,i,o,fmt)=>m.set(f,{file:f,inode:i,offset:o,format:fmt}),
}};

console.log('\nlecture incrementale');
check('un nouveau fichier demarre a la fin', ()=>{
  fs.writeFileSync(LOG,line('/ancien').repeat(50));
  const got=[]; const t=new Tailer({dir:tmp,store:mkStore(),onEntry:e=>got.push(e)});
  t.poll();
  assert.strictEqual(got.length,0,'l historique ne doit pas etre reingere');
});
check('les nouvelles lignes sont lues', ()=>{
  const got=[]; const t=new Tailer({dir:tmp,store:mkStore(),onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(LOG,line('/nouveau'));
  t.poll();
  assert.strictEqual(got.length,1);
  assert.strictEqual(got[0].path,'/nouveau');
});
check('rien de nouveau -> rien de relu', ()=>{
  const got=[]; const t=new Tailer({dir:tmp,store:mkStore(),onEntry:e=>got.push(e)});
  t.poll(); fs.appendFileSync(LOG,line()); t.poll();
  const n=got.length; t.poll(); t.poll();
  assert.strictEqual(got.length,n);
});

console.log('\nrotation');
check('un nouvel inode fait repartir de zero', ()=>{
  const store=mkStore(); const got=[];
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(LOG,line('/avant')); t.poll();
  // logrotate : renomme puis nginx recree
  fs.renameSync(LOG,LOG+'.1');
  fs.writeFileSync(LOG,line('/apres'));
  t.poll();
  assert.ok(got.some(e=>e.path==='/apres'),'le nouveau fichier doit etre lu');
  assert.ok(t.status().rotations>0,'la rotation doit etre comptee');
  fs.unlinkSync(LOG+'.1');
});
check('une troncature en place est detectee', ()=>{
  const store=mkStore(); const got=[];
  fs.writeFileSync(LOG,line().repeat(10));
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(LOG,line('/a')); t.poll();
  const avant=t.status().rotations;
  fs.writeFileSync(LOG,line('/apres-troncature'));   // > fichier
  t.poll();
  assert.ok(t.status().rotations>avant);
  assert.ok(got.some(e=>e.path==='/apres-troncature'));
});

// Fix (audit finding ANA-01): before this fix, a rotation redetected the
// format IMMEDIATELY, synchronously, on the brand-new (empty) file at the
// same path — sampling nothing always falls back to detectFormat()'s default
// ('combined'). A vhost-format log rotated at 3am would then be silently
// misread as plain combined forever after: RE_VHOST-shaped lines never match
// RE_COMBINED, so every single line is dropped, and only a process restart
// would notice. This test reproduces exactly that scenario end to end.
check('apres rotation, le format vhost est correctement redetecte (pas fige a combined)', ()=>{
  const store=mkStore(); const got=[];
  const vhostLine=(v,p='/')=>`${v} 203.0.113.9 - - [09/Sep/2026:10:00:00 +0200] "GET ${p} HTTP/1.1" 200 100 "-" "curl/8"\n`;
  // Avant rotation : un journal AU FORMAT VHOST bien etabli (plusieurs lignes
  // pour que detectFormat() le reconnaisse sans ambiguite a l ouverture).
  fs.writeFileSync(LOG, vhostLine('avant.example.com').repeat(5));
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(LOG, vhostLine('avant.example.com','/deja-vu')); t.poll();
  assert.ok(got.some(e=>e.path==='/deja-vu' && e.vhost==='avant.example.com'),
    'sanity check : le format vhost est bien actif avant la rotation');

  // Rotation : logrotate renomme, nginx recree un fichier VIDE au meme chemin.
  fs.renameSync(LOG, LOG+'.1');
  fs.writeFileSync(LOG, '');
  t.poll(); // le fichier est vide : rien a echantillonner, format doit rester "pending"

  // Puis du VRAI contenu arrive, toujours au format vhost.
  fs.appendFileSync(LOG, vhostLine('apres.example.com','/apres-rotation'));
  t.poll();
  assert.ok(got.some(e=>e.path==='/apres-rotation' && e.vhost==='apres.example.com'),
    'la ligne post-rotation (format vhost) doit etre parsee, pas silencieusement perdue par un format fige a "combined"');
  fs.unlinkSync(LOG+'.1');
});

console.log('\nreprise apres redemarrage');
check('l offset persiste evite la relecture', ()=>{
  const store=mkStore();
  fs.writeFileSync(LOG,line().repeat(5));
  const t1=new Tailer({dir:tmp,store,onEntry:()=>{}});
  t1.poll();
  fs.appendFileSync(LOG,line('/x'));
  const got1=[]; t1.onEntry=e=>got1.push(e); t1.poll();
  assert.strictEqual(got1.length,1);
  // Nouveau tailer, meme store : ne doit rien relire
  const got2=[]; const t2=new Tailer({dir:tmp,store,onEntry:e=>got2.push(e)});
  t2.poll();
  assert.strictEqual(got2.length,0,'la reprise ne doit pas dupliquer');
});

console.log('\nlignes partielles');
check('une ligne coupee attend la suite', ()=>{
  const store=mkStore(); const got=[];
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll();
  const l=line('/complet');
  fs.appendFileSync(LOG,l.slice(0,30));    // moitie de ligne
  t.poll();
  assert.strictEqual(got.length,0,'une ligne incomplete ne doit pas etre parsee');
  fs.appendFileSync(LOG,l.slice(30));
  t.poll();
  assert.strictEqual(got.length,1);
  assert.strictEqual(got[0].path,'/complet');
});

console.log('\nformats');
check('format detecte par fichier', ()=>{
  const V=path.join(tmp,'vhosts_access.log');
  fs.writeFileSync(V,'');
  const store=mkStore(); const got=[];
  const t=new Tailer({dir:tmp,pattern:/vhosts_access\.log$/,store,onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(V,'autre.fr 1.2.3.4 - - [09/Sep/2026:10:00:00 +0200] "GET /v HTTP/1.1" 200 5 "-" "curl/8"\n');
  t.poll();
  // Le fichier etait vide a l ouverture : format devine combined, puis la ligne
  // vhost ne parse pas. C est le comportement attendu — le format se fige a
  // l ouverture. On verifie surtout l absence de plantage.
  assert.ok(t.status().following.length>0);
});
check('le vhost vient du nom de fichier en format combined', ()=>{
  const store=mkStore(); const got=[];
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll(); fs.appendFileSync(LOG,line()); t.poll();
  assert.strictEqual(got[0].vhost,'site.fr');
});

console.log('\nrobustesse');
check('dossier inexistant', ()=>{
  const t=new Tailer({dir:'/nexiste/pas',store:mkStore(),onEntry:()=>{}});
  assert.doesNotThrow(()=>t.poll());
  assert.deepStrictEqual(t.listFiles(),[]);
});
check('un fichier supprime est oublie', ()=>{
  const F=path.join(tmp,'temporaire.access.log');
  fs.writeFileSync(F,'');
  const t=new Tailer({dir:tmp,store:mkStore(),onEntry:()=>{}});
  t.poll();
  fs.unlinkSync(F);
  assert.doesNotThrow(()=>t.poll());
  assert.ok(!t.status().following.some(f=>f.file==='temporaire.access.log'));
});
check('une ligne illisible est comptee mais ne bloque pas', ()=>{
  const store=mkStore(); const got=[];
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:e=>got.push(e)});
  t.poll();
  fs.appendFileSync(LOG,'n importe quoi\n'+line('/ok'));
  t.poll();
  assert.strictEqual(got.length,1);
  assert.ok(t.status().dropped>0);
});



console.log('\ndetection d un mauvais format (le journal avance, rien n est stocke)');
check('un fichier au format natif ModSecurity est signale suspect', ()=>{
  const store=mkStore();
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:()=>{}});
  t.poll();
  // Format natif ModSecurity au lieu du JSON attendu : chaque ligne est
  // syntaxiquement valide pour un journal, mais aucune ne correspond au
  // format d acces nginx que ce Tailer suit ici (le meme mecanisme sert au
  // format WAF via un parseur injecte).
  const native = '--a1b2-A--\n[27/Sep/2026:10:00:00] abc 1.2.3.4\n--a1b2-B--\nGET /x HTTP/1.1\n--a1b2-Z--\n';
  fs.appendFileSync(LOG, native);
  t.poll();
  const f = t.status().following.find(x=>x.file===path.basename(LOG));
  assert.ok(f.lines>=5,'les lignes doivent etre comptees malgre l echec de parsing');
  assert.strictEqual(f.parsed,0);
  assert.strictEqual(f.suspectFormat,true,
    'un journal qui avance sans jamais rien parser doit etre signale, sinon indiscernable d une absence d activite');
});
check('un fichier valide n est jamais signale suspect', ()=>{
  const store=mkStore();
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:()=>{}});
  t.poll();
  fs.appendFileSync(LOG, line('/ok').repeat(10));
  t.poll();
  const f = t.status().following.find(x=>x.file===path.basename(LOG));
  assert.strictEqual(f.suspectFormat,false);
});
check('un tout petit nombre de lignes illisibles ne declenche pas le signal', ()=>{
  // Une ligne tronquee en fin de fichier est normale ; il ne faut pas alerter
  // sur un echantillon trop court pour etre significatif.
  const store=mkStore();
  fs.writeFileSync(LOG,'');
  const t=new Tailer({dir:tmp,store,onEntry:()=>{}});
  t.poll();
  fs.appendFileSync(LOG, 'ligne illisible\n' + line('/ok'));
  t.poll();
  const f = t.status().following.find(x=>x.file===path.basename(LOG));
  assert.strictEqual(f.suspectFormat,false,'echantillon trop petit (2 lignes) pour conclure');
});

fs.rmSync(tmp,{recursive:true,force:true});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
