'use strict';
/**
 * Une constante de configuration utilisee sans etre importee ne se voit ni a la
 * compilation ni dans un test unitaire : elle produit une `ReferenceError` au
 * premier appel de la route concernee. C est ainsi que `GIT_BACKUP_BRANCH` a
 * casse le statut Git apres le decoupage.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const root=path.join(__dirname,'..');
const cfgKeys=Object.keys(require('../lib/config'));
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const files=[
  ...fs.readdirSync(path.join(root,'features')).map(f=>'features/'+f),
  ...fs.readdirSync(path.join(root,'lib')).map(f=>'lib/'+f),
].filter(f=>f!=='lib/config.js' && f.endsWith('.js'));

console.log(`\nconstantes de configuration (${files.length} modules)`);
for (const f of files) {
  const raw=fs.readFileSync(path.join(root,f),'utf8');
  // Retirer commentaires et chaines : une constante citee dans un commentaire
  // d en-tete n est pas un usage.
  const src=raw
    .replace(/\/\*[\s\S]*?\*\//g,'')
    .replace(/^\s*\/\/.*$/gm,'')
    // Regex literals can contain quote characters inside a character class
    // (e.g. /([^"]*)"/) that the naive string-stripper below would mistake
    // for the start of a string, desyncing it for the rest of the file —
    // this masked a real usage further down in one file during development.
    // Blanked first, targeting how this codebase actually writes them: right
    // after .match(/.test(/.exec(/.replace(/.matchAll( or an assignment.
    .replace(/(\.(?:match|test|exec|replace|matchAll)\()\/(?:[^/\\\n]|\\.)*\/[a-z]*(?=\))/g, '$1""')
    .replace(/(=\s*)\/(?:[^/\\\n]|\\.)*\/[a-z]*/g, '$1""')
    .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g,'""');
  const bound=new Set();
  // Toute destructuration, quelle que soit la source
  for(const m of raw.matchAll(/(?:const|let)\s*\{([^}]+)\}\s*=/g))
    m[1].split(',').forEach(n=>bound.add(n.trim().split(':').pop().trim()));
  for(const m of raw.matchAll(/^const ([A-Z_][A-Z0-9_]*)\s*=/gm)) bound.add(m[1]);

  const missing=new Set();
  // Usages nus : ni precedes d un point, ni dans une chaine
  for(const m of src.matchAll(/(^|[^.\w$'"`])([A-Z][A-Z0-9_]{3,})\b/gm)) {
    const n=m[2];
    if (cfgKeys.includes(n) && !bound.has(n)) missing.add(n);
  }
  check(f, ()=>assert.deepStrictEqual([...missing],[],
    `utilise sans import : ${[...missing].join(', ')}`));
}


// ─── Fonctions du socle ──────────────────────────────────────────────────────
// Une constante manquante n est qu une moitie du probleme : un helper appele
// sans etre importe produit la meme `ReferenceError` au premier passage. C est
// ainsi que `safeReadFile` a casse le pull Git.
console.log('\nfonctions du socle');

const libExports=new Set();
for (const f of fs.readdirSync(path.join(root,'lib')))
  try { Object.keys(require(path.join(root,'lib',f))).forEach(n=>libExports.add(n)); } catch {}

const BUILTINS=new Set(['require','parseInt','parseFloat','setTimeout','setInterval',
  'clearInterval','clearTimeout','encodeURIComponent','decodeURIComponent','isNaN',
  'String','Number','Boolean','Promise','Buffer','Date','Error','Math','JSON','Object',
  'Array','Set','Map','URL','URLSearchParams','fetch','process','console','if','for',
  'while','switch','catch','return','typeof','await','function','async','new','delete',
  'RegExp','Symbol','WeakMap']);

for (const f of files) {
  const raw=fs.readFileSync(path.join(root,f),'utf8');
  const src=raw
    .replace(/\/\*[\s\S]*?\*\//g,'')
    .replace(/^\s*\/\/.*$/gm,'')
    // Regex literals can contain quote characters inside a character class
    // (e.g. /([^"]*)"/) that the naive string-stripper below would mistake
    // for the start of a string, desyncing it for the rest of the file —
    // this masked a real usage further down in one file during development.
    // Blanked first, targeting how this codebase actually writes them: right
    // after .match(/.test(/.exec(/.replace(/.matchAll( or an assignment.
    .replace(/(\.(?:match|test|exec|replace|matchAll)\()\/(?:[^/\\\n]|\\.)*\/[a-z]*(?=\))/g, '$1""')
    .replace(/(=\s*)\/(?:[^/\\\n]|\\.)*\/[a-z]*/g, '$1""')
    .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g,'""');

  // Tout ce qui est lie localement : imports, declarations, parametres, boucles
  const bound=new Set();
  for(const m of raw.matchAll(/(?:const|let|var)\s*\{([^}]+)\}\s*=/g))
    m[1].split(',').forEach(n=>bound.add(n.trim().split(':').pop().trim()));
  for(const m of raw.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) bound.add(m[1]);
  for(const m of raw.matchAll(/^(?:async )?function ([\w$]+)/gm)) bound.add(m[1]);
  for(const m of raw.matchAll(/function\s*[\w$]*\s*\(([^)]*)\)/g))
    m[1].split(',').forEach(a=>bound.add(a.trim().split(/[=\s]/)[0]));
  for(const m of raw.matchAll(/\(([^)]*)\)\s*=>/g))
    m[1].split(',').forEach(a=>bound.add(a.trim().split(/[=\s]/)[0]));
  for(const m of raw.matchAll(/([\w$]+)\s*=>/g)) bound.add(m[1]);

  const missing=new Set();
  // Appels nus : ni precedes d un point, ni locaux
  for(const m of src.matchAll(/(^|[^.\w$])([a-z][\w$]{2,})\s*\(/gm)) {
    const n=m[2];
    if (libExports.has(n) && !bound.has(n) && !BUILTINS.has(n)) missing.add(n);
  }
  check(f, ()=>assert.deepStrictEqual([...missing],[],
    `appele sans import : ${[...missing].map(x=>x+'()').join(', ')}`));
}

console.log('\nsanite du controle');
check('les cles de config sont bien chargees', ()=>assert.ok(cfgKeys.length>50));
check('les modules sont bien trouves', ()=>assert.ok(files.length>=20,`${files.length} modules`));

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
