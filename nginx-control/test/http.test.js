'use strict';
const assert=require('assert');
const H=require('../lib/http');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

// Faux objet response
function fakeRes(){ return { code:null, headers:null, body:null,
  writeHead(c,h){this.code=c;this.headers=h}, end(b){this.body=b} }; }

console.log('\nreponses');
check('send serialise le JSON', ()=>{
  const r=fakeRes(); H.send(r,200,{a:1});
  assert.strictEqual(r.code,200); assert.strictEqual(r.body,'{"a":1}');
});
check('en-tetes de securite presents', ()=>{
  const r=fakeRes(); H.send(r,200,{});
  assert.strictEqual(r.headers['X-Content-Type-Options'],'nosniff');
  assert.strictEqual(r.headers['X-Frame-Options'],'SAMEORIGIN');
});
check('pas de CORS wildcard par defaut', ()=>{
  const r=fakeRes(); H.send(r,200,{});
  assert.ok(!('Access-Control-Allow-Origin' in r.headers));
});
check('raccourcis de statut', ()=>{
  let r=fakeRes(); H.forbidden(r);  assert.strictEqual(r.code,403);
  r=fakeRes(); H.notFound(r);       assert.strictEqual(r.code,404);
  r=fakeRes(); H.badRequest(r);     assert.strictEqual(r.code,400);
  r=fakeRes(); H.serverError(r,new Error('boum'));
  assert.strictEqual(r.code,500); assert.ok(r.body.includes('boum'));
});

console.log('\nregistre de routes');
check('correspondance exacte', ()=>{
  const r=new H.Router(); const h=()=>'x';
  r.get('/api/status',h);
  assert.strictEqual(r.match('GET','/api/status'),h);
  assert.strictEqual(r.match('POST','/api/status'),null);
  assert.strictEqual(r.match('GET','/api/autre'),null);
});
check('methodes distinctes sur un meme chemin', ()=>{
  const r=new H.Router(); const g=()=>'g', p=()=>'p';
  r.get('/api/x',g); r.post('/api/x',p);
  assert.strictEqual(r.match('GET','/api/x'),g);
  assert.strictEqual(r.match('POST','/api/x'),p);
});
check('une route dupliquee leve une erreur', ()=>{
  const r=new H.Router(); r.get('/api/x',()=>{});
  assert.throws(()=>r.get('/api/x',()=>{}),/Duplicate route/);
});
check('prefixe et priorite au plus long', ()=>{
  const r=new H.Router(); const court=()=>'c', long=()=>'l';
  r.addPrefix('GET','/api/go',court);
  r.addPrefix('GET','/api/goaccess/report',long);
  assert.strictEqual(r.match('GET','/api/goaccess/report/x'),long);
  assert.strictEqual(r.match('GET','/api/gonow'),court);
});
check('exact prime sur prefixe', ()=>{
  const r=new H.Router(); const e=()=>'e', p=()=>'p';
  r.addPrefix('GET','/api/x',p); r.get('/api/x',e);
  assert.strictEqual(r.match('GET','/api/x'),e);
});
check('list() enumere tout', ()=>{
  const r=new H.Router(); r.get('/a',()=>{}); r.post('/b',()=>{}); r.addPrefix('GET','/c',()=>{});
  assert.deepStrictEqual(r.list(),['GET /a','GET /c*','POST /b']);
});

console.log('\ninjectBeforeFirstScript — insertion robuste face a une minification agressive');
check('insere juste avant le premier <script>', ()=>{
  const html = '<html><head></head><body><script>x</script></body></html>';
  const out = H.injectBeforeFirstScript(html, '<script>INJECTE</script>', 'test');
  assert.strictEqual(out, '<html><head></head><body><script>INJECTE</script><script>x</script></body></html>');
});
check('fonctionne toujours sans balise </head> — l etat exact produit par un minifieur avec --remove-optional-tags', ()=>{
  // Bug reel, trouve deux fois dans ce projet (branding du dashboard, puis
  // reecriture WebSocket des rapports GoAccess) : </head> est une balise
  // optionnelle au sens HTML5, que ce flag de minification supprime
  // entierement. Un simple html.replace('</head>', ...) ne trouve alors
  // plus rien, sans la moindre erreur.
  const htmlSansHead = '<html><head><body><script>x</script></body></html>';
  const out = H.injectBeforeFirstScript(htmlSansHead, '<script>INJECTE</script>', 'test');
  assert.ok(out.includes('INJECTE'), 'l injection doit reussir meme sans </head>');
  assert.ok(out.indexOf('INJECTE') < out.indexOf('>x<'), 'l injection doit precéder le script existant');
});
check('aucun <script> du tout -> retourne le HTML inchange avec un avertissement, pas une exception', ()=>{
  const html = '<html><body>rien ici</body></html>';
  assert.doesNotThrow(() => {
    const out = H.injectBeforeFirstScript(html, '<script>INJECTE</script>', 'test');
    assert.strictEqual(out, html, 'sans point d ancrage, le HTML doit rester tel quel plutot que corrompu');
  });
});
check('avec plusieurs <script>, insere avant le PREMIER (ordre d execution correct)', ()=>{
  const html = '<script src="cdn.js"></script><script>principal</script>';
  const out = H.injectBeforeFirstScript(html, '<script>INJECTE</script>', 'test');
  assert.ok(out.indexOf('INJECTE') < out.indexOf('cdn.js'),
    'les variables injectees doivent etre definies avant TOUT autre script, y compris un CDN externe');
});

console.log('\nparseBody');
const {Readable}=require('stream');
const mkReq=(txt)=>{const s=new Readable({read(){}});s.push(txt);s.push(null);s.destroy=()=>{};return s;};
(async()=>{
  const t=[
    ['JSON valide',   '{"a":1}', d=>assert.strictEqual(d.a,1)],
    ['JSON invalide', 'pas json', d=>assert.deepStrictEqual(d,{})],
    ['corps vide',    '',        d=>assert.deepStrictEqual(d,{})],
  ];
  for(const [n,body,verif] of t){
    try{ verif(await H.parseBody(mkReq(body))); console.log('  PASS  '+n); pass++; }
    catch(e){ console.log('  FAIL  '+n+'\n        '+e.message); fail++; }
  }
  try{
    const big=await H.parseBody(mkReq('x'.repeat(200)),{limitBytes:100});
    assert.deepStrictEqual(big,{}); console.log('  PASS  corps trop volumineux rejete'); pass++;
  }catch(e){ console.log('  FAIL  limite de taille\n        '+e.message); fail++; }

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();
