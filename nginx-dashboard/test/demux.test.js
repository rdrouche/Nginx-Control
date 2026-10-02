'use strict';
/**
 * Le decodage du flux multiplexe Docker a ete reimplemente a la main a quatre
 * endroits (GoDNS, certbot, deploy, GoAccess), chacun sans le garde-fou pour
 * un conteneur avec TTY alloue. Sans ce garde, Docker n envoie **aucun**
 * en-tete de trame — huit octets de texte reel sont alors pris pour un
 * en-tete et le journal entier est corrompu. C est ce qui rendait les
 * informations GoDNS invisibles dans le dashboard alors que `docker logs`
 * sur le meme conteneur semblait parfaitement normal : deux chemins de
 * lecture differents, un seul cassait.
 *
 * Ce test verifie qu aucune de ces reimplementations n est revenue, et que
 * chaque module utilise bien le demultiplexeur partage et teste de lib/docker.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
const root=path.join(__dirname,'..');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\naucune reimplementation manuelle du demultiplexage');
for (const f of ['features/godns.js','features/certbot.js','features/deploy.js','features/goaccess.js']) {
  check(f, ()=>{
    const src=fs.readFileSync(path.join(root,f),'utf8');
    assert.ok(!/readUInt32BE\(pos\s*\+\s*4\)/.test(src),
      'decodage manuel de trame Docker detecte — doit passer par docker.demuxToText()');
    assert.ok(/demuxToText/.test(src), 'devrait utiliser le demultiplexeur partage');
  });
}

console.log('\nle demultiplexeur partage gere le cas TTY (celui qui manquait partout)');
check('flux sans trame (TTY) rendu tel quel', ()=>{
  const { demuxToText } = require(path.join(root,'lib','docker'));
  const plain = Buffer.from('2026-09-11 log line without framing\n', 'utf8');
  assert.strictEqual(demuxToText(plain), plain.toString('utf8'));
});
check('flux trame (sans TTY) correctement decode', ()=>{
  const { demuxToText } = require(path.join(root,'lib','docker'));
  const payload = Buffer.from('hello docker\n', 'utf8');
  const header = Buffer.alloc(8); header[0]=1; header.writeUInt32BE(payload.length,4);
  assert.strictEqual(demuxToText(Buffer.concat([header,payload])), 'hello docker\n');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
