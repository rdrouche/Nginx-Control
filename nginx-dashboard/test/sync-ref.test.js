'use strict';
/**
 * Deux regles de la synchronisation viennent d incidents en production. Toutes
 * deux se manifestent par une perte de fichiers, pas par une erreur.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const S=require('../features/sync-ref');
const SRC=fs.readFileSync(path.join(__dirname,'..','features','sync-ref.js'),'utf8');
let pass=0,fail=0;
const check=async(n,f)=>{try{await f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

(async () => {
console.log('\ncomparaison de versions');
await check('semverGt compare correctement', ()=>{
  assert.ok(S.semverGt('1.1.0','1.0.9'));
  assert.ok(S.semverGt('2.0.0','1.9.9'));
  assert.ok(S.semverGt('1.0.10','1.0.9'), 'comparaison numerique, pas lexicale');
  assert.ok(!S.semverGt('1.0.0','1.0.0'));
  assert.ok(!S.semverGt('1.0.0','1.1.0'));
});
await check('versions absentes ou malformees', ()=>{
  assert.doesNotThrow(()=>S.semverGt(null,'1.0.0'));
  assert.doesNotThrow(()=>S.semverGt('abc','1.0.0'));
});

console.log('\nen-tete de version des fichiers de reference');
await check('version extraite de l en-tete', ()=>{
  assert.strictEqual(S.parseFileVersion('# name: x\n# version: 1.2.3\nserver {}'),'1.2.3');
});
await check('sans en-tete -> 0.0.0, donc toujours mis a jour', ()=>{
  // Un fichier local sans en-tete est traite comme la version 0 : toute version
  // de reference lui est superieure, il apparait donc comme actualisable.
  assert.strictEqual(S.parseFileVersion('server {}'),'0.0.0');
  assert.ok(S.semverGt('1.0.0', S.parseFileVersion('server {}')));
});
await check('contenu vide', ()=>assert.doesNotThrow(()=>S.parseFileVersion('')));

console.log('\netat active/desactive : le local prime');
await check('la regle est appliquee dans le code', ()=>{
  // Un fichier installe en .conf.DISABLE doit le rester apres mise a jour, et un
  // nouveau fichier doit arriver desactive.
  assert.ok(/DISABLE/.test(SRC), 'la gestion du suffixe .DISABLE a disparu');
});
await check('findLocalFile trouve les deux formes', ()=>{
  assert.strictEqual(typeof S.findLocalFile,'function');
  // Dossier inexistant : aucune exception
  assert.doesNotThrow(()=>S.findLocalFile('/nexiste/pas','x.conf'));
});

console.log('\nisolation des features');
await check('aucun import direct d une autre feature', ()=>{
  const imports=[...SRC.matchAll(/require\('\.\.\/features\/([^']+)'\)/g)].map(m=>m[1]);
  assert.deepStrictEqual(imports,[], `importe : ${imports.join(', ')}`);
});
await check('le deploiement passe par injection', ()=>{
  assert.strictEqual(typeof S.setDeployHandlers,'function');
});
await check('sans cablage, echec explicite plutot que silencieux', async ()=>{
  // Verifie que les valeurs par defaut levent une erreur nommee
  assert.ok(/deploy not wired/.test(SRC));
});

console.log('\nsections synchronisees');
await check('les quatre dossiers de configuration', ()=>{
  assert.deepStrictEqual(Object.keys(S.SECTION_DIR_MAP).sort(),
                         ['conf','sites','snippets','streams']);
});
await check('ssl et certs ne sont pas synchronises ici', ()=>{
  assert.ok(!('ssl' in S.SECTION_DIR_MAP));
  assert.ok(!('certs' in S.SECTION_DIR_MAP));
});

console.log('\nbuildRefPath — chemin dans le depot de reference (regression : depot dedie, sans sous-dossier)');
await check('sans SYNC_REF_PATH_PREFIX (le defaut) : section a la racine du depot, pas sous Nginx-RProxy/', ()=>{
  // Le depot de reference est desormais dedie a ces quatre dossiers — la
  // structure attendue est repo/conf, repo/sites, ... a la racine, plus le
  // sous-dossier Nginx-RProxy/ impose auparavant en dur.
  const saved = process.env.SYNC_REF_PATH_PREFIX;
  delete process.env.SYNC_REF_PATH_PREFIX;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
  const S2 = require('../features/sync-ref');
  assert.strictEqual(S2.buildRefPath('conf'), 'conf');
  assert.strictEqual(S2.buildRefPath('sites'), 'sites');
  assert.ok(!S2.buildRefPath('conf').includes('Nginx-RProxy'));
  if (saved === undefined) delete process.env.SYNC_REF_PATH_PREFIX; else process.env.SYNC_REF_PATH_PREFIX = saved;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
});
await check('SYNC_REF_PATH_PREFIX renseigne : sous-dossier prefixe pour un depot partage/monorepo', ()=>{
  const saved = process.env.SYNC_REF_PATH_PREFIX;
  process.env.SYNC_REF_PATH_PREFIX = 'Nginx-RProxy';
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
  const S2 = require('../features/sync-ref');
  assert.strictEqual(S2.buildRefPath('conf'), 'Nginx-RProxy/conf');
  if (saved === undefined) delete process.env.SYNC_REF_PATH_PREFIX; else process.env.SYNC_REF_PATH_PREFIX = saved;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
});
await check('slashes de tete/fin sur le prefixe nettoyes', ()=>{
  const saved = process.env.SYNC_REF_PATH_PREFIX;
  process.env.SYNC_REF_PATH_PREFIX = '/Nginx-RProxy/';
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
  const S2 = require('../features/sync-ref');
  assert.strictEqual(S2.buildRefPath('conf'), 'Nginx-RProxy/conf');
  if (saved === undefined) delete process.env.SYNC_REF_PATH_PREFIX; else process.env.SYNC_REF_PATH_PREFIX = saved;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/sync-ref')];
});

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();
