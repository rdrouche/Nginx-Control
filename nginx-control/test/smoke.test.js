'use strict';
/**
 * Demarre un vrai serveur et appelle CHAQUE route declaree.
 *
 * Les tests unitaires et `node --check` ne voient pas une fonction supprimee par
 * erreur : la syntaxe reste valide et l erreur ne survient qu a l execution.
 * C est ainsi que `listConfDir` a disparu sans qu aucun test ne bronche, jusqu a
 * ce qu un appel a /api/configs fasse tomber le processus.
 *
 * Le critere n est pas le code de retour — beaucoup de routes repondent 503 sans
 * nginx, ou 400 sans parametre — mais l absence de 5xx et surtout l absence de
 * crash : un ReferenceError tue le processus et toutes les requetes suivantes.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { spawn } = require('child_process');
const http=require('http');

let pass=0, fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const root=path.join(__dirname,'..');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'smoke-'));
for (const d of ['config','sites','conf','snippets','streams','logs','backups','goaccess','gitwork','ssl','certs','cache'])
  fs.mkdirSync(path.join(tmp,d),{recursive:true});
fs.writeFileSync(path.join(tmp,'config','users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
fs.writeFileSync(path.join(tmp,'logs','access.log'),'x\n');
fs.writeFileSync(path.join(tmp,'sites','a.conf'),'server { listen 80; }\n');

const PORT=3899, BASE=`http://127.0.0.1:${PORT}`;
const env={...process.env, PORT:String(PORT),
  USERS_FILE:path.join(tmp,'config','users.yml'),
  DIR_SITES:path.join(tmp,'sites'), DIR_CONF:path.join(tmp,'conf'),
  DIR_SNIPPETS:path.join(tmp,'snippets'), DIR_STREAMS:path.join(tmp,'streams'),
  DIR_LOGS:path.join(tmp,'logs'), DIR_BACKUPS:path.join(tmp,'backups'),
  DIR_GOACCESS:path.join(tmp,'goaccess'), DIR_GIT_WORK:path.join(tmp,'gitwork'),
  DIR_SSL:path.join(tmp,'ssl'), DIR_CERTS:path.join(tmp,'certs'),
  DIR_CACHE:path.join(tmp,'cache')};

function req(method, p, cookie) {
  return new Promise(resolve=>{
    const r=http.request({host:'127.0.0.1',port:PORT,path:p,method,
      headers:cookie?{Cookie:cookie}:{} ,timeout:5000},res=>{
      let b=''; res.on('data',d=>b+=d);
      res.on('end',()=>resolve({status:res.statusCode,body:b,headers:res.headers}));
    });
    r.on('error',e=>resolve({status:0,body:e.message}));
    r.on('timeout',()=>{r.destroy();resolve({status:0,body:'timeout'})});
    r.end();
  });
}

(async ()=>{
  const srv=spawn('node',[path.join(root,'server.js')],{env,cwd:root,stdio:['ignore','pipe','pipe']});
  let stderr='';
  srv.stderr.on('data',d=>stderr+=d);
  await new Promise(r=>setTimeout(r,2500));

  // Connexion
  const login=await new Promise(resolve=>{
    const body='username=admin&password=admin123';
    const r=http.request({host:'127.0.0.1',port:PORT,path:'/auth/login',method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':body.length}},
      res=>resolve({status:res.statusCode,cookie:(res.headers['set-cookie']||[''])[0].split(';')[0]}));
    r.on('error',()=>resolve({status:0,cookie:''}));
    r.write(body); r.end();
  });

  console.log('\nconnexion');
  check('login accepte', ()=>assert.strictEqual(login.status,302));
  const ck=login.cookie;

  // Toutes les routes GET declarees
  const routes=fs.readFileSync(path.join(root,'routes-before.txt'),'utf8')
    .split('\n').map(s=>s.trim())
    .filter(r=>r.startsWith('/api/') && !r.endsWith('/'));

  console.log(`\nappel de ${routes.length} routes GET (aucun 5xx, aucun crash)`);
  const errors=[], swallowed=[];
  // Une erreur de programmation avalee par un try/catch ressort en 200 avec un
  // champ error : c est ainsi que `promSum is not defined` a survecu au test.
  const looksLikeCodeError = /is not defined|is not a function|Cannot read propert|undefined is not/i;
  for (const r of routes) {
    const res=await req('GET', r, ck);
    if (res.status===0) errors.push(`${r} -> pas de reponse (${res.body})`);
    else if (res.status>=500 && res.status!==503) errors.push(`${r} -> ${res.status} ${res.body.slice(0,90)}`);
    else if (looksLikeCodeError.test(res.body)) swallowed.push(`${r} -> ${res.status} ${res.body.slice(0,110)}`);
  }
  check('aucune route ne casse', ()=>assert.deepStrictEqual(errors,[],'\n        '+errors.join('\n        ')));
  check('aucune erreur de code avalee en 200', ()=>assert.deepStrictEqual(swallowed,[],'\n        '+swallowed.join('\n        ')));


  console.log('\ntraversee de chemin (compte viewer)');
  const traversals = [
    '/api/configs/file?path=' + encodeURIComponent(tmp + '/sites/../../../etc/passwd'),
    '/api/nginx-logs/tail?path=' + encodeURIComponent(tmp + '/logs/../../../etc/passwd'),
    '/api/ssl/file?path=' + encodeURIComponent(tmp + '/ssl/../../../etc/passwd'),
  ];
  for (const t of traversals) {
    const res = await req('GET', t, ck);
    check(t.split('?')[0] + ' refuse la traversee', () => {
      assert.strictEqual(res.status, 403, `statut ${res.status}`);
      assert.ok(!res.body.includes('root:x:'), 'contenu de /etc/passwd renvoye');
    });
  }

  console.log('\nsurvie du processus');
  const alive=await req('GET','/api/auth/me',ck);
  check('le serveur repond encore', ()=>assert.strictEqual(alive.status,200));
  check('aucune exception non capturee', ()=>{
    const boom=stderr.split('\n').filter(l=>/ReferenceError|TypeError:.*not a function/.test(l));
    assert.deepStrictEqual(boom,[],'\n        '+boom.join('\n        '));
  });

  srv.kill();
  fs.rmSync(tmp,{recursive:true,force:true});
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();
