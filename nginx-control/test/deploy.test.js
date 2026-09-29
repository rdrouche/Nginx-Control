'use strict';
/**
 * Le pipeline de deploiement concentre les comportements les plus couteux a
 * retrouver : chacun s est manifeste en production par une perte de fichiers ou
 * par un test au vert qui ne validait rien.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const D=require('../features/deploy');
const S=require('../lib/scheduler');
const SRC=fs.readFileSync(path.join(__dirname,'..','features','deploy.js'),'utf8');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\ntest ephemere : ce qui le rendait inoperant');
check('les chemins de montage sont traduits vers l hote', ()=>{
  // Un chemin interne au conteneur fait creer un dossier vide au demon : le test
  // demarrait alors sur une configuration inexistante et passait toujours.
  assert.ok(/toHostPath\(tmpDir\)/.test(SRC));
  assert.ok(/Cannot map/.test(SRC), 'l echec de traduction doit etre explicite');
});
check('un jeu de configuration vide est refuse', ()=>{
  assert.ok(/Refusing to test an empty configuration set/.test(SRC));
});
check('les montages sont herites de la production', ()=>{
  assert.ok(/buildTestBinds/.test(SRC));
  assert.ok(/inherited/.test(SRC));
});
check('le conteneur de test tourne sur le reseau de production', ()=>{
  // Sans resolveur, nginx -t echoue sur tout upstream nomme.
  assert.ok(/getTestNetworkMode|getNginxNetworkMode/.test(SRC));
  assert.ok(!/NetworkMode: 'none'/.test(SRC), 'reseau isole : les upstreams ne resoudront pas');
});
check('le bac a sable vit dans l espace de deploiement, pas dans les sauvegardes', ()=>{
  assert.ok(/DIR_GIT_WORK, '\.sandbox'/.test(SRC) || /\.sandbox/.test(SRC));
  assert.ok(!/DIR_BACKUPS, '_test_'/.test(SRC));
});

console.log('\ncopie : structure et suppressions');
check('la copie est recursive', ()=>{
  // Les arborescences ne sont pas plates : ssl/<ca>/ etait ignore.
  assert.ok(/listTreeFiles|copyTree/.test(SRC));
});
check('les fichiers caches ne sont jamais supprimes', ()=>{
  assert.ok(/isProtectedFile/.test(SRC));
});
check('une source vide n efface pas la destination', ()=>{
  // Un dossier du depot ne contenant qu un .gitkeep aurait tout supprime.
  assert.ok(/Skip deletions in/.test(SRC));
});
check('les dossiers en lecture seule sont sautes, pas fatals', ()=>{
  assert.ok(/isDirWritable/.test(SRC));
  assert.ok(/mounted read-only/.test(SRC));
});

console.log('\nordonnanceur');
check('cron : correspondance exacte', ()=>{
  assert.ok(S.matchCron('0 3 * * *', new Date('2026-01-01T03:00:00')));
  assert.ok(!S.matchCron('0 3 * * *', new Date('2026-01-01T04:00:00')));
});
check('cron : pas horaire', ()=>{
  assert.ok(S.matchCron('0 */6 * * *', new Date('2026-01-01T12:00:00')));
  assert.ok(!S.matchCron('0 */6 * * *', new Date('2026-01-01T13:00:00')));
});
check('cron : liste et intervalle', ()=>{
  assert.ok(S.matchCron('0 3,15 * * *', new Date('2026-01-01T15:00:00')));
  assert.ok(S.matchCron('0 9-17 * * *', new Date('2026-01-01T12:00:00')));
  assert.ok(!S.matchCron('0 9-17 * * *', new Date('2026-01-01T20:00:00')));
});
check('cron invalide -> false, jamais d exception', ()=>{
  assert.strictEqual(S.matchCron('n importe quoi', new Date()), false);
  assert.strictEqual(S.matchCron('', new Date()), false);
});
check('les taches des features sont injectees', ()=>{
  assert.strictEqual(typeof S.setTasks,'function');
  const SS=fs.readFileSync(path.join(__dirname,'..','lib','scheduler.js'),'utf8');
  assert.ok(/not wired/.test(SS), 'sans cablage, l echec doit etre nomme');
  const imports=[...SS.matchAll(/require\('\.\.\/features\//g)];
  assert.deepStrictEqual(imports.map(m=>m[0]),[], 'le socle ne doit pas importer de feature');
});

console.log('\ninterface');
check('deploy exporte ses points d entree', ()=>{
  for (const f of ['deployFromGit','deployFromGitWork','testConfigEphemeral','buildTestBinds'])
    assert.strictEqual(typeof D[f],'function',`${f} non exporte`);
});

console.log('\nfichiers generes par une autre feature (blocklists.js) : jamais supprimes par le sync Git');
check('setDeps() est disponible et isGeneratedFile() reflete ce qui a ete injecte', ()=>{
  // Meme mecanisme d injection que sync-ref/configs/monitor/audit (server.js
  // est le seul point qui cable les features entre elles) : sans appel a
  // setDeps(), la liste est vide et rien n est protege — ce test verifie que
  // l injection elle-meme fonctionne, la protection reelle (deployFromGit)
  // n est exercee qu au niveau du code source ci-dessous car elle appelle
  // Docker et Git, indisponibles dans ce bac a sable de tests.
  assert.strictEqual(typeof D.setDeps, 'function');
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/blocklist-ips.conf'), false, 'rien injecte -> rien protege');
  D.setDeps({ generatedFiles: ['/nginx/conf/blocklist-ips.conf', '/nginx/snippets/blocklist-enforce.conf'] });
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/blocklist-ips.conf'), true);
  assert.strictEqual(D.isGeneratedFile('/nginx/snippets/blocklist-enforce.conf'), true);
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/autre-fichier.conf'), false, 'un fichier non injecte n est jamais protege par accident');
  D.setDeps({ generatedFiles: [] }); // ne pas polluer les tests suivants de ce process
});
check('deployFromGit() ignore un fichier genere dans sa boucle de suppression (jamais efface car absent du depot)', ()=>{
  assert.ok(/isGeneratedFile\(path\.join\(dst, rel\)\)/.test(SRC), 'la boucle de suppression doit consulter isGeneratedFile() avant unlinkSync');
});
check('un seul helper construit la vue de test git-work — pas de copie ad-hoc par route (c est exactement ce qui a cause la regression du 24/09)', ()=>{
  // Bug reel : le premier correctif n avait fusionne les fichiers generes que
  // dans deployFromGit(), en oubliant que /api/git/test construisait sa
  // propre liste de dossiers a la main, sans passer par le meme helper — le
  // bouton "Tester la config" seul echouait donc toujours sur un vhost
  // incluant blocklist-enforce.conf. Toute nouvelle route qui a besoin de
  // tester git-work doit desormais passer par buildGitWorkTestSrcDirs(),
  // jamais reconstruire les chemins DIR_GIT_WORK/<section> a la main.
  const rawGitWorkListings = [...SRC.matchAll(/path\.join\(DIR_GIT_WORK, 'sites'\)/g)];
  assert.strictEqual(rawGitWorkListings.length, 2,
    `un jeu de chemins git-work "a la main" ne doit exister qu au seul endroit legitime ` +
    `(dans buildGitWorkTestSrcDirs() lui-meme, et dans les srcDirs de deployFromGit() utilises ` +
    `par la copie/suppression, jamais reconstruit pour un test) ; trouve ${rawGitWorkListings.length} occurrence(s)`);
  assert.ok(/function buildGitWorkTestSrcDirs/.test(SRC));
  const testRoute = SRC.slice(SRC.indexOf("router.post('/api/git/test'"), SRC.indexOf("router.post('/api/git/deploy'"));
  assert.ok(/buildGitWorkTestSrcDirs\(\)/.test(testRoute), '/api/git/test doit utiliser le meme helper que deployFromGit()');
  assert.ok(!/path\.join\(DIR_GIT_WORK, 'sites'\)/.test(testRoute), '/api/git/test ne doit plus lister les dossiers git-work a la main');
});
check('deployFromGit() fusionne l etat actif des fichiers generes dans le test ephemere (sinon nginx -t echoue sur un include absent du depot)', ()=>{
  const start = SRC.indexOf('async function deployFromGit');
  const end   = SRC.indexOf('\nfunction ', start); // debut de la prochaine declaration top-level
  const deployFn = SRC.slice(start, end > start ? end : undefined);
  assert.ok(/buildGitWorkTestSrcDirs\(\)/.test(deployFn), 'deployFromGit() doit utiliser le helper partage');
  assert.ok(/cleanup\(\)/.test(deployFn), 'le dossier de fusion temporaire doit etre nettoye apres le test');
});

console.log('\ngeneralisation pour l auto-config Docker (nombre de fichiers dynamique)');
check('setDeps() accepte aussi une fonction (pas seulement un tableau statique)', ()=>{
  // features/docker-autoconfig.js genere un fichier par conteneur labellise,
  // qui apparait/disparait au fil des cycles — un tableau capture une seule
  // fois au demarrage deviendrait perime des le premier conteneur demarre ou
  // arrete apres le boot. setDeps() doit donc accepter soit l ancien tableau
  // (retrocompatible avec blocklists.js), soit une fonction rappelee a
  // chaque verification.
  D.setDeps({ generatedFiles: [] });
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/dynamique.conf'), false);
  let current = ['/nginx/conf/dynamique.conf'];
  D.setDeps({ generatedFiles: () => current });
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/dynamique.conf'), true, 'la fonction doit etre appelee, pas juste stockee');
  current = []; // le conteneur a disparu entre deux cycles
  assert.strictEqual(D.isGeneratedFile('/nginx/conf/dynamique.conf'), false, 'la fonction doit etre re-appelee a chaque verification, jamais mise en cache');
  D.setDeps({ generatedFiles: [] }); // ne pas polluer les tests suivants
});
check('un fichier sites/docker_*.conf est protege par prefixe, meme absent de la liste injectee', ()=>{
  // Deuxieme protection, independante de l injection : le nombre de vhosts
  // Docker est dynamique, et la liste injectee peut etre momentanement
  // perimee juste apres un redemarrage (avant le premier cycle de
  // features/docker-autoconfig.js) — voir le commentaire d isGeneratedFile().
  const { DIR_SITES } = require('../lib/config');
  D.setDeps({ generatedFiles: [] });
  assert.strictEqual(D.isGeneratedFile(path.join(DIR_SITES, 'docker_example_com.conf')), true,
    'un fichier docker_*.conf dans sites/ doit etre protege par son seul prefixe');
  assert.strictEqual(D.isGeneratedFile(path.join(DIR_SITES, 'manuel.conf')), false,
    'un vhost sans le prefixe docker_ ne doit jamais etre protege par accident');
  assert.strictEqual(D.isGeneratedFile(path.join(require('../lib/config').DIR_CONF, 'docker_example_com.conf')), false,
    'le prefixe ne protege que dans sites/ — un fichier "docker_*" ailleurs n a aucune raison d etre protege');
});
check('buildGitWorkTestSrcDirs() ramasse aussi les docker_*.conf/agent_*.conf reellement presents sur le disque (pas seulement la liste injectee)', ()=>{
  const start = SRC.indexOf('function buildGitWorkTestSrcDirs');
  const end   = SRC.indexOf('\nasync function getNginxImage', start);
  const fn = SRC.slice(start, end > start ? end : undefined);
  assert.ok(/readdirSync\(DIR_SITES\)/.test(fn), 'doit lister DIR_SITES pour retrouver les vhosts Docker/agent generes hors de la liste injectee');
  assert.ok(/GENERATED_FILE_PREFIXES\.some/.test(fn), 'doit filtrer par le meme jeu de prefixes que isGeneratedFile() (docker_ ET agent_)');
});
check('GENERATED_FILE_PREFIXES couvre bien docker_ (Partie 1) et agent_ (Partie 2)', ()=>{
  assert.deepStrictEqual(D.GENERATED_FILE_PREFIXES ? [...D.GENERATED_FILE_PREFIXES] : null, ['docker_', 'agent_']);
});
check('un fichier sites/agent_*.conf est protege par prefixe, meme absent de la liste injectee', ()=>{
  const { DIR_SITES } = require('../lib/config');
  D.setDeps({ generatedFiles: [] });
  assert.strictEqual(D.isGeneratedFile(path.join(DIR_SITES, 'agent_abc123_example_com.conf')), true,
    'un fichier agent_*.conf dans sites/ doit etre protege par son seul prefixe');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
