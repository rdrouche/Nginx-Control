'use strict';
/**
 * GoAccess a coute plusieurs allers-retours en production. Ces tests figent les
 * quatre invariants qui en sont sortis, pour qu un refactor ne les defasse pas
 * silencieusement — chacun se manifeste par une perte de donnees, pas par une
 * erreur visible.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const G=require('../features/goaccess');
const SRC=fs.readFileSync(path.join(__dirname,'..','features','goaccess.js'),'utf8');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\npersistance des statistiques');
check('--db-path, --persist et --restore sont tous les trois presents', ()=>{
  // --db-path seul ne persiste rien : GoAccess ecrit sur SIGTERM avec --persist
  // et relit avec --restore.
  for (const flag of ['--db-path=/db','--persist','--restore'])
    assert.ok(SRC.includes(flag), `${flag} absent`);
});
check('--restore est conditionne a l existence de la base', ()=>{
  // Au premier demarrage la base n existe pas : --restore ferait echouer GoAccess.
  assert.ok(/dbHasFiles/.test(SRC));
  assert.ok(/if \(dbHasFiles\) args\.push\('--restore'\)/.test(SRC));
});
check('le journal est passe par --log-file, pas en argument positionnel', ()=>{
  // En positionnel, GoAccess ne suit pas son offset et reparse tout au restart.
  assert.ok(SRC.includes("'--log-file=/nginx/logs/'"), 'argument positionnel detecte');
});

console.log('\nmontages');
check('les chemins hote viennent de HOST_GOACCESS', ()=>{
  // Les deduire du chemin interne produisait des dossiers introuvables cote
  // demon : Docker en creait des vides et les stats disparaissaient au restart.
  assert.ok(/hostDbPath\s*=\s*path\.join\(HOST_GOACCESS/.test(SRC));
  assert.ok(/hostRptPath\s*=\s*path\.join\(HOST_GOACCESS/.test(SRC));
  assert.ok(!/\.replace\(DIR_GOACCESS,\s*HOST_GOACCESS\)/.test(SRC), 'ancienne derivation par replace() encore presente');
});
check('la base n est montee que si la persistance est active', ()=>{
  assert.ok(/opts\.persist !== false\) binds\.push/.test(SRC));
});

console.log('\ncycle de vie');
check('le restart laisse 10 s a GoAccess pour ecrire sa base', ()=>{
  // SIGTERM puis SIGKILL : sans delai, la base n est jamais ecrite.
  assert.ok(/restart\?t=10/.test(SRC));
});
check('recreate force le redemarrage malgre un conteneur actif', ()=>{
  assert.ok(/force/.test(SRC), 'le garde "deja demarre" doit pouvoir etre contourne');
});

console.log('\ninterface du module');
check('register et handleUpgrade exportes', ()=>{
  assert.strictEqual(typeof G.register,'function');
  assert.strictEqual(typeof G.handleUpgrade,'function');
});
check('toutes les fonctions internes sont exportees', ()=>{
  // Une fonction manquante devient alors une erreur au chargement du module,
  // pas au premier appel de route.
  for (const f of ['listGoAccessSources','startGoAccessContainer','restartGoAccessContainer',
                   'detectLogFormat','readGoAccessReport','resolveGoAccessProxy'])
    assert.strictEqual(typeof G[f],'function',`${f} non exporte`);
});
check('sources listees sans planter hors contexte', ()=>{
  assert.ok(Array.isArray(G.listGoAccessSources()));
});

console.log('\nHOST_LOGS/HOST_GOACCESS doivent etre des chemins absolus (fix Basse/Divers dashboard)');
check('un chemin relatif est rejete avec un message actionnable', ()=>{
  let thrown = null;
  try { G.requireAbsoluteHostPath('./logs', 'HOST_LOGS'); } catch (e) { thrown = e; }
  assert.ok(thrown, 'aurait du lever');
  assert.ok(/HOST_LOGS/.test(thrown.error), 'le message doit nommer la variable en cause');
  assert.ok(/absolute/i.test(thrown.error));
});
check('un chemin absolu passe sans exception', ()=>{
  assert.doesNotThrow(() => G.requireAbsoluteHostPath('/srv/nginx/logs', 'HOST_LOGS'));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
