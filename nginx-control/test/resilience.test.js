'use strict';
/**
 * Deux defauts se combinaient pour deconnecter tout le monde a chaque
 * rafraichissement :
 *
 *  - le gestionnaire de requetes est asynchrone et n avait pas de garde : une
 *    exception dans une route devenait une promesse rejetee non geree, que
 *    Node 22 traite en terminant le processus ;
 *  - les sessions vivaient uniquement en memoire, donc le redemarrage du
 *    conteneur qui suivait les effacait toutes.
 *
 * Le second seul suffisait deja a deconnecter tout le monde a chaque mise a
 * jour de l image.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { spawn }=require('child_process'); const http=require('http');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const root=path.join(__dirname,'..');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'resil-'));
for (const d of ['config','sites','conf','snippets','streams','logs','backups','goaccess','gitwork','ssl','certs'])
  fs.mkdirSync(path.join(tmp,d),{recursive:true});
fs.writeFileSync(path.join(tmp,'config','users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT=3899;
const env={...process.env, PORT:String(PORT),
  SESSION_SECRET:'secret-fixe-pour-le-test',
  USERS_FILE:path.join(tmp,'config','users.yml'),
  DIR_SITES:path.join(tmp,'sites'), DIR_CONF:path.join(tmp,'conf'),
  DIR_SNIPPETS:path.join(tmp,'snippets'), DIR_STREAMS:path.join(tmp,'streams'),
  DIR_LOGS:path.join(tmp,'logs'), DIR_BACKUPS:path.join(tmp,'backups'),
  DIR_GOACCESS:path.join(tmp,'goaccess'), DIR_GIT_WORK:path.join(tmp,'gitwork'),
  DIR_SSL:path.join(tmp,'ssl'), DIR_CERTS:path.join(tmp,'certs')};

const wait=ms=>new Promise(r=>setTimeout(r,ms));
const req=(p,cookie)=>new Promise(r=>{
  const q=http.request({host:'127.0.0.1',port:PORT,path:p,method:'GET',
    headers:cookie?{Cookie:cookie}:{},timeout:4000},res=>{
    let b=''; res.on('data',d=>b+=d); res.on('end',()=>r({status:res.statusCode,body:b}));
  });
  q.on('error',()=>r({status:0})); q.on('timeout',()=>{q.destroy();r({status:0})}); q.end();
});
const login=()=>new Promise(r=>{
  const body='username=admin&password=admin123';
  const q=http.request({host:'127.0.0.1',port:PORT,path:'/auth/login',method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':body.length}},
    res=>r({status:res.statusCode,cookie:(res.headers['set-cookie']||[''])[0].split(';')[0]}));
  q.on('error',()=>r({status:0,cookie:''})); q.write(body); q.end();
});
const boot=()=>{
  const p=spawn('node',[path.join(root,'server.js')],{env,cwd:root,stdio:['ignore','pipe','pipe']});
  let out=''; p.stdout.on('data',d=>out+=d); p.stderr.on('data',d=>out+=d);
  p.log=()=>out;
  return p;
};

(async()=>{
  let srv=boot();
  await wait(2500);

  console.log('\npage de connexion (avant authentification)');
  // Optimisation securite (retour utilisateur, v12.49.3) : la page de connexion
  // affichait "vX.Y.Z — Nginx Reverse Proxy Stack" en pied de page, visible par
  // QUICONQUE atteint /auth/login sans etre authentifie — une information de
  // reconnaissance gratuite (version exacte du dashboard) qui n a aucune
  // utilite pour se connecter. Retiree de server.js#loginPage().
  const pageLogin=await req('/auth/login');
  check('la page de connexion ne fuit plus la version du dashboard avant authentification', ()=>{
    assert.strictEqual(pageLogin.status,200);
    assert.ok(!/Nginx Reverse Proxy Stack/.test(pageLogin.body),
      'le pied de page affichant la version a ete retire de loginPage()');
    assert.ok(!/v\d+\.\d+\.\d+/.test(pageLogin.body),
      'aucun numero de version ne doit apparaitre sur une page non authentifiee');
  });

  console.log('\nsession');
  const l=await login();
  check('connexion acceptee', ()=>assert.strictEqual(l.status,302));
  const ck=l.cookie;

  const trois=[];
  for(let i=0;i<3;i++) trois.push((await req('/',ck)).status);
  check('trois rafraichissements successifs', ()=>assert.deepStrictEqual(trois,[200,200,200]));

  console.log('\nsurvie au redemarrage');
  srv.kill('SIGTERM'); await wait(800);
  srv=boot(); await wait(2500);
  const apres=await req('/',ck);
  check('la session survit au redemarrage', ()=>{
    assert.strictEqual(apres.status,200,
      'un redemarrage ne doit plus deconnecter — c est ce qui se produisait a chaque mise a jour');
  });
  check('la restauration est journalisee', ()=>assert.ok(/session\(s\) restauree/.test(srv.log())));

  console.log('\nresilience du gestionnaire');
  // Le handler doit encaisser une route inconnue et rester debout
  const nf=await req('/api/nexiste-pas',ck);
  check('route inconnue -> 404', ()=>assert.strictEqual(nf.status,404));
  const vivant=await req('/api/auth/me',ck);
  check('le processus repond toujours', ()=>assert.strictEqual(vivant.status,200));

  console.log('\ngardes en place');
  const src=fs.readFileSync(path.join(root,'server.js'),'utf8');
  check('le gestionnaire asynchrone est enveloppe', ()=>{
    assert.ok(/handleRequest\(req, res\)\.catch/.test(src),
      'sans ce garde, une exception de route tue le processus');
  });
  check('filet global present', ()=>{
    assert.ok(/unhandledRejection/.test(src));
    assert.ok(/uncaughtException/.test(src));
  });
  check('les sessions sont persistees', ()=>{
    const a=fs.readFileSync(path.join(root,'lib','auth.js'),'utf8');
    assert.ok(/setSessionStore/.test(a));
    assert.ok(/persistSessions/.test(a));
  });

  srv.kill();
  fs.rmSync(tmp,{recursive:true,force:true});

  // Bug reel, retour utilisateur (v12.49.3) : le scenario ci-dessus fixe
  // SESSION_SECRET dans l env (ligne 29), donc il ne rejoue jamais le mode
  // "automatique" (rien defini, secret genere-et-persiste dans
  // .generated-secrets.json — voir lib/config.js#resolveGeneratedSecret()) qui
  // est le mode par defaut, sans .env personnalise. restoreSessions() (lib/
  // auth.js) verifiait `process.env.SESSION_SECRET` — toujours absent dans ce
  // mode — au lieu de `cfg.SESSION_SECRET` (qui, lui, reste stable d un
  // redemarrage a l autre) : la session ne survivait donc JAMAIS a un
  // redemarrage en mode automatique, exactement le bug signale.
  console.log('\nsession en mode automatique (SESSION_SECRET non definie, generee et persistee)');
  const tmp2=fs.mkdtempSync(path.join(os.tmpdir(),'resil-auto-'));
  for (const d of ['config','sites','conf','snippets','streams','logs','backups','goaccess','gitwork','ssl','certs'])
    fs.mkdirSync(path.join(tmp2,d),{recursive:true});
  fs.writeFileSync(path.join(tmp2,'config','users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  const { SESSION_SECRET: _omit, ...envSansSecret } = env;   // retire le secret fixe herite
  const env2={...envSansSecret, PORT:String(PORT+1),
    USERS_FILE:path.join(tmp2,'config','users.yml'),
    DIR_SITES:path.join(tmp2,'sites'), DIR_CONF:path.join(tmp2,'conf'),
    DIR_SNIPPETS:path.join(tmp2,'snippets'), DIR_STREAMS:path.join(tmp2,'streams'),
    DIR_LOGS:path.join(tmp2,'logs'), DIR_BACKUPS:path.join(tmp2,'backups'),
    DIR_GOACCESS:path.join(tmp2,'goaccess'), DIR_GIT_WORK:path.join(tmp2,'gitwork'),
    DIR_SSL:path.join(tmp2,'ssl'), DIR_CERTS:path.join(tmp2,'certs')};
  const PORT2=PORT+1;
  const req2=(p,cookie)=>new Promise(r=>{
    const q=http.request({host:'127.0.0.1',port:PORT2,path:p,method:'GET',
      headers:cookie?{Cookie:cookie}:{},timeout:4000},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>r({status:res.statusCode,body:b}));
    });
    q.on('error',()=>r({status:0})); q.on('timeout',()=>{q.destroy();r({status:0})}); q.end();
  });
  const login2=()=>new Promise(r=>{
    const body='username=admin&password=admin123';
    const q=http.request({host:'127.0.0.1',port:PORT2,path:'/auth/login',method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':body.length}},
      res=>r({status:res.statusCode,cookie:(res.headers['set-cookie']||[''])[0].split(';')[0]}));
    q.on('error',()=>r({status:0,cookie:''})); q.write(body); q.end();
  });
  const boot2=()=>{
    const p=spawn('node',[path.join(root,'server.js')],{env:env2,cwd:root,stdio:['ignore','pipe','pipe']});
    let out=''; p.stdout.on('data',d=>out+=d); p.stderr.on('data',d=>out+=d);
    p.log=()=>out;
    return p;
  };

  let srv2=boot2();
  await wait(2500);
  check('SESSION_SECRET generee automatiquement (aucune definie dans l env)', ()=>{
    assert.ok(/SESSION_SECRET n'est pas definie.*generee/.test(srv2.log()),
      'le premier demarrage doit signaler la generation automatique');
  });
  const l2=await login2();
  check('connexion acceptee (mode automatique)', ()=>assert.strictEqual(l2.status,302));
  const ck2=l2.cookie;
  const secretApresBoot1=JSON.parse(fs.readFileSync(path.join(tmp2,'config','.generated-secrets.json'),'utf8')).sessionSecret;

  srv2.kill('SIGTERM'); await wait(800);
  srv2=boot2(); await wait(2500);
  const secretApresBoot2=JSON.parse(fs.readFileSync(path.join(tmp2,'config','.generated-secrets.json'),'utf8')).sessionSecret;
  check('la valeur generee est stable d un redemarrage a l autre (jamais reguneree)', ()=>{
    assert.strictEqual(secretApresBoot2, secretApresBoot1);
  });
  const apres2=await req2('/',ck2);
  check('la session survit au redemarrage MEME en mode automatique (bug reel corrige)', ()=>{
    assert.strictEqual(apres2.status,200,
      'restoreSessions() ne doit plus se fier a process.env.SESSION_SECRET (absent en mode automatique) mais a cfg.SESSION_SECRET (stable via .generated-secrets.json)');
  });
  check('la restauration est journalisee (mode automatique)', ()=>assert.ok(/session\(s\) restauree/.test(srv2.log())));

  srv2.kill();
  fs.rmSync(tmp2,{recursive:true,force:true});

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();
