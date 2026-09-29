'use strict';
/**
 * Verifie que le cablage de server.js correspond aux exports reels du socle.
 * Un nom mal orthographie dans une destructuration ne leve aucune erreur : il
 * vaut simplement undefined. C est ainsi que PERMS.ADMIN a refuse tout le monde.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const root = path.join(__dirname,'..');
const src  = fs.readFileSync(path.join(root,'server.js'),'utf8');

const mods = {
  cfg:     require('../lib/config'),
  auth:    require('../lib/auth'),
  httpLib: require('../lib/http'),
  docker:  require('../lib/docker'),
  tree:    require('../lib/fs-tree'),
  secrets: require('../lib/secrets'),
  events:  require('../lib/events'),
};

console.log('\ndestructurations de server.js');
// const { a, b } = mod;
const re = /const\s*\{([^}]+)\}\s*=\s*(cfg|auth|httpLib|docker|tree|secrets|events)\s*;/g;
let m, blocks=0;
while ((m = re.exec(src))) {
  blocks++;
  const names = m[1].split(',').map(s=>s.trim().split(':')[0].trim()).filter(Boolean);
  const mod = mods[m[2]];
  const missing = names.filter(n => !(n in mod));
  check(`${m[2]} : ${names.length} noms`, () =>
    assert.deepStrictEqual(missing, [], `absents des exports : ${missing.join(', ')}`));
}
check('toutes les destructurations sont analysees', ()=>assert.ok(blocks>=5, `${blocks} blocs trouves`));

console.log('\nidentifiants devenus prives');
for (const priv of ['usersCache','resolvedContainerId','selfMountsCache','eventsDb','usersFileMtime','loginAttempts'])
  check(`${priv} n est plus reference`, () => {
    const hits = src.split('\n')
      .map((l,i)=>[i+1,l])
      .filter(([,l]) => new RegExp('\\b'+priv+'\\b').test(l) && !l.trim().startsWith('//'));
    assert.deepStrictEqual(hits.map(h=>h[0]), [], `lignes : ${hits.map(h=>h[0]).join(', ')}`);
  });

console.log('\nexports critiques presents');
check('PERMS.ADMIN defini',        ()=>assert.ok(mods.auth.PERMS.ADMIN));
check('dockerCall rend rawBuffer', ()=>assert.ok(/rawBuffer/.test(fs.readFileSync(path.join(root,'lib/docker.js'),'utf8'))));
check('BRANDING.doc expose',       ()=>assert.ok('doc' in mods.cfg.BRANDING && 'docLabel' in mods.cfg.BRANDING));


console.log('\ninventaire des fonctions (aucune perdue par le decoupage)');
check('toutes les fonctions d origine sont retrouvees', ()=>{
  const orig = path.join(root,'server.js.orig');
  if (!fs.existsSync(orig)) return;   // reference absente hors depot de travail
  const names = s => new Set([...s.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)/gm)].map(m=>m[1]));
  const before = names(fs.readFileSync(orig,'utf8'));
  const after  = names(src);
  for (const dir of ['lib','features'])
    for (const f of fs.readdirSync(path.join(root,dir)))
      names(fs.readFileSync(path.join(root,dir,f),'utf8')).forEach(n=>after.add(n));
  // Renommages et alias assumes lors de l extraction
  const renamed = new Set(['loginRateKey','requireSession','getTestNetworkMode','safeParse']);
  const lost = [...before].filter(n => !after.has(n) && !renamed.has(n));
  assert.deepStrictEqual(lost, [], `disparues : ${lost.join(', ')}`);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
