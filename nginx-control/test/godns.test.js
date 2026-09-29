'use strict';
/**
 * Deux bugs distincts rendaient les informations GoDNS invisibles dans le
 * dashboard alors que `docker logs` sur le meme conteneur semblait normal :
 *
 *  - `godnsGetLogs()` reimplementait a la main le decodage du flux Docker,
 *    sans le garde-fou pour un conteneur avec TTY alloue. Sans lui, aucune
 *    trame n est envoyee et les huit premiers octets du texte reel sont pris
 *    pour un en-tete, corrompant tout le journal.
 *  - la regex du fournisseur DNS ne s arretait pas au guillemet fermant d un
 *    champ `msg="..."`, capturant "cloudflare"" au lieu de "cloudflare".
 */
const assert=require('assert');
const G=require('../features/godns');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\nanalyse des journaux GoDNS');
check('fournisseur detecte sans le guillemet fermant', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:00Z" level=info msg="Creating DNS handler with provider: cloudflare"');
  assert.strictEqual(p.provider,'cloudflare');
});
check('nouvelle IP publique detectee', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:00Z" level=info msg="Checking IP, new IP: 203.0.113.42"');
  assert.strictEqual(p.publicIP,'203.0.113.42');
});
check('IP nulle (<nil>) ignoree', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:00Z" level=info msg="Checking IP, new IP: <nil>"');
  assert.strictEqual(p.publicIP,null);
});
check('domaine a jour', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:05Z" level=info msg="Record OK: example.com - 203.0.113.42"');
  assert.deepStrictEqual(p.domains['example.com'], { status:'ok', ip:'203.0.113.42', time:'2026-09-11T08:00:05Z' });
});
check('domaine en cours de mise a jour', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:05Z" level=info msg="Updating domain: example.com, current IP: 203.0.113.1, new IP: 203.0.113.42"');
  assert.strictEqual(p.domains['example.com'].status,'updating');
  assert.strictEqual(p.domains['example.com'].newIP,'203.0.113.42');
});
check('erreurs remontees', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-11T08:00:05Z" level=error msg="DNS provider authentication failed"');
  assert.strictEqual(p.errors.length,1);
  assert.strictEqual(p.errors[0].level,'error');
});
check('regime stable ("Skip update") : IP publique, domaine et derniere MAJ tous remplis (bug v12.40.0)', ()=>{
  const p=G.parseGoDNSLogs('time="2026-09-27T17:47:19Z" level=info msg="Domain drawdb.app.rdr-it.com: IP is the same as cached one (109.209.67.163). Skip update."');
  assert.strictEqual(p.publicIP,'109.209.67.163');
  assert.deepStrictEqual(p.domains['drawdb.app.rdr-it.com'], { status:'ok', ip:'109.209.67.163', time:'2026-09-27T17:47:19Z' });
  assert.strictEqual(p.lastUpdate,'2026-09-27T17:47:19Z');
});
check('plusieurs domaines en "Skip update" a la suite -> tous dans le tableau, derniere MAJ = dernier cycle', ()=>{
  const raw = [
    'time="2026-09-27T17:47:19Z" level=info msg="Domain a.example.com: IP is the same as cached one (109.209.67.163). Skip update."',
    'time="2026-09-27T17:47:20Z" level=info msg="Domain b.example.com: IP is the same as cached one (109.209.67.163). Skip update."',
  ].join('\n');
  const p=G.parseGoDNSLogs(raw);
  assert.strictEqual(Object.keys(p.domains).length,2);
  assert.strictEqual(p.lastUpdate,'2026-09-27T17:47:20Z');
});
check('prefixe horodate docker toleré', ()=>{
  const p=G.parseGoDNSLogs('[godns] 2026-09-11T08:00:00.123456789Z time="2026-09-11T08:00:00Z" level=info msg="Record OK: a.com - 1.2.3.4"');
  assert.strictEqual(p.domains['a.com'].ip,'1.2.3.4');
});
check('journal vide ou illisible -> aucune exception', ()=>{
  assert.doesNotThrow(()=>G.parseGoDNSLogs(''));
  assert.doesNotThrow(()=>G.parseGoDNSLogs('n importe quoi\nsans aucun format connu'));
});

console.log('\nregression : decodage du flux Docker');
check('godnsGetLogs utilise le demultiplexeur partage', ()=>{
  const src=require('fs').readFileSync(require('path').join(__dirname,'..','features','godns.js'),'utf8');
  assert.ok(/demuxToText/.test(src));
  assert.ok(!/readUInt32BE\(pos\s*\+\s*4\)/.test(src),
    'un decodage manuel de trame Docker est revenu : il ne gere pas le cas TTY');
});
check('un flux GoDNS sans trame (TTY) reste lisible de bout en bout', ()=>{
  const { demuxToText } = require('../lib/docker');
  const raw = Buffer.from('time="2026-09-11T08:00:00Z" level=info msg="Record OK: example.com - 203.0.113.42"\n','utf8');
  const parsed = G.parseGoDNSLogs(demuxToText(raw));
  assert.strictEqual(parsed.domains['example.com'].ip,'203.0.113.42');
});

console.log('\ndetectWebPanelEnabled() — lit la VRAIE config GoDNS, pas config/godns.yml (bug v12.41.0)');
{
  const fs = require('fs'), os = require('os'), path = require('path');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'godns-webpanel-'));

  check('YAML : web_panel.enabled true -> detecte', () => {
    const f = path.join(tmp, 'a.yaml');
    fs.writeFileSync(f, 'provider: Cloudflare\nweb_panel:\n  enabled: true\n  addr: 0.0.0.0:9000\n');
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: f, format: 'yaml' }), true);
  });
  check('YAML : web_panel.enabled false -> non detecte', () => {
    const f = path.join(tmp, 'b.yaml');
    fs.writeFileSync(f, 'provider: Cloudflare\nweb_panel:\n  enabled: false\n');
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: f, format: 'yaml' }), false);
  });
  check('YAML : pas de bloc web_panel -> non detecte, pas d exception', () => {
    const f = path.join(tmp, 'c.yaml');
    fs.writeFileSync(f, 'provider: Cloudflare\n');
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: f, format: 'yaml' }), false);
  });
  check('JSON : web_panel.enabled true -> detecte', () => {
    const f = path.join(tmp, 'd.json');
    fs.writeFileSync(f, JSON.stringify({ provider: 'Cloudflare', web_panel: { enabled: true } }));
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: f, format: 'json' }), true);
  });
  check('JSON invalide -> non detecte, pas d exception', () => {
    const f = path.join(tmp, 'e.json');
    fs.writeFileSync(f, '{ not json');
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: f, format: 'json' }), false);
  });
  check('fichier absent -> non detecte, pas d exception', () => {
    assert.strictEqual(G.detectWebPanelEnabled({ internalPath: path.join(tmp, 'nope.yaml'), format: 'yaml' }), false);
  });
}

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
