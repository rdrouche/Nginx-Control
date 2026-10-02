'use strict';
/**
 * Un nom appele sans etre defini ni importe ne se voit ni a la compilation ni
 * dans un test unitaire : il leve au premier passage. Dans l agent, un `catch`
 * l avait meme transforme en silence complet — la ventilation par pays restait
 * vide sans qu aucune erreur ne remonte.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const root=path.join(__dirname,'..');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const files=['server.js', ...fs.readdirSync(path.join(root,'lib')).map(f=>'lib/'+f)]
  .filter(f=>f.endsWith('.js'));

const exported=new Set();
for (const f of fs.readdirSync(path.join(root,'lib')))
  try { Object.keys(require(path.join(root,'lib',f))).forEach(n=>exported.add(n)); } catch {}

const BUILTINS=new Set(['require','parseInt','parseFloat','setTimeout','setInterval',
  'clearInterval','clearTimeout','encodeURIComponent','decodeURIComponent','isNaN',
  'String','Number','Boolean','Promise','Buffer','Date','Error','Math','JSON','Object',
  'Array','Set','Map','URL','URLSearchParams','fetch','process','console','if','for',
  'while','switch','catch','return','typeof','await','function','async','new','delete',
  'RegExp','Symbol','WeakMap','structuredClone']);

console.log(`\nappels non resolus (${files.length} fichiers)`);
for (const f of files) {
  const raw=fs.readFileSync(path.join(root,f),'utf8');
  const src=raw
    .replace(/\/\*[\s\S]*?\*\//g,'')
    .replace(/^\s*\/\/.*$/gm,'')
    .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g,'""');

  const bound=new Set();
  for(const m of raw.matchAll(/(?:const|let|var)\s*\{([^}]+)\}\s*=/g))
    m[1].split(',').forEach(n=>bound.add(n.trim().split(':').pop().trim()));
  for(const m of raw.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) bound.add(m[1]);
  for(const m of raw.matchAll(/^(?:async )?function ([\w$]+)/gm)) bound.add(m[1]);
  for(const m of raw.matchAll(/^\s+(?:async )?function ([\w$]+)/gm)) bound.add(m[1]);
  for(const m of raw.matchAll(/function\s*[\w$]*\s*\(([^)]*)\)/g))
    m[1].split(',').forEach(a=>bound.add(a.trim().split(/[=\s]/)[0]));
  for(const m of raw.matchAll(/\(([^)]*)\)\s*=>/g))
    m[1].split(',').forEach(a=>bound.add(a.trim().split(/[=\s]/)[0]));
  for(const m of raw.matchAll(/([\w$]+)\s*=>/g)) bound.add(m[1]);
  for(const m of raw.matchAll(/^\s*([\w$]+)\s*\(/gm)) { /* methodes de classe */ }
  for(const m of raw.matchAll(/^\s{2}([\w$]+)\s*\([^)]*\)\s*\{/gm)) bound.add(m[1]);

  const missing=new Set();
  for(const m of src.matchAll(/(^|[^.\w$])([a-z][\w$]{2,})\s*\(/gm)) {
    const n=m[2];
    if (exported.has(n) && !bound.has(n) && !BUILTINS.has(n)) missing.add(n);
  }
  check(f, ()=>assert.deepStrictEqual([...missing],[],
    `appele sans import : ${[...missing].map(x=>x+'()').join(', ')}`));
}

console.log('\nsanite');
check('des exports ont ete collectes', ()=>assert.ok(exported.size>20,`${exported.size}`));

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
