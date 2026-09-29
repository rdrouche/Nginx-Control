'use strict';
/**
 * Signalement reel : un pipeline de build minifiait public/index.html avec
 * html-minifier-terser --remove-optional-tags avant de construire l image.
 * `</head>` est une balise optionnelle au sens HTML5, et ce flag la retire
 * entierement — confirme directement avec la commande exacte de l operateur
 * contre ce fichier reel. `html.replace('</head>', ...)` ne trouvait alors
 * plus rien a remplacer : window.BRANDING, window.DASHBOARD_VERSION et
 * window.UPDATE_CHECK_URL_CONFIGURED n etaient jamais injectes, sans la
 * moindre erreur. Seul symptome visible : la verification automatique de
 * version ne se declenchait plus, le bouton manuel restant fonctionnel
 * puisqu il ne depend pas de ce dernier drapeau.
 *
 * Plutot que de re-executer le vrai minifieur ici (qui deviendrait une
 * dependance permanente de la suite de tests, contraire au zero-dependance
 * de ce projet), ce test simule directement l etat post-minification qui
 * causait le bug — un fichier prive de sa balise </head> — et verifie que
 * le serveur reel, sans aucune modification de configuration, sert quand
 * meme la page correctement instrumentee.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { spawn } = require('child_process');
const http=require('http');

let pass=0, fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const root=path.join(__dirname,'..');
const appDir=fs.mkdtempSync(path.join(os.tmpdir(),'branding-app-'));
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'branding-data-'));

// Copie minimale du projet : lib/, features/, server.js, et une version de
// public/index.html privee de sa balise fermante </head> — exactement ce
// que produit html-minifier-terser --remove-optional-tags sur ce fichier.
fs.cpSync(path.join(root,'lib'), path.join(appDir,'lib'), {recursive:true});
fs.cpSync(path.join(root,'features'), path.join(appDir,'features'), {recursive:true});
fs.copyFileSync(path.join(root,'server.js'), path.join(appDir,'server.js'));
fs.mkdirSync(path.join(appDir,'public'));
const realHtml = fs.readFileSync(path.join(root,'public','index.html'), 'utf8');
assert.ok(realHtml.includes('</head>'), 'le fichier source doit bien contenir </head> avant simulation');
const strippedHtml = realHtml.split('</head>').join('');   // toutes les occurrences, comme le ferait le minifieur
assert.ok(!strippedHtml.includes('</head>'), 'la simulation doit avoir retire toute occurrence de </head>');
fs.writeFileSync(path.join(appDir,'public','index.html'), strippedHtml);

for (const d of ['config','sites','conf','snippets','streams','logs','backups','goaccess','gitwork','ssl','certs','cache'])
  fs.mkdirSync(path.join(tmp,d),{recursive:true});
fs.writeFileSync(path.join(tmp,'config','users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT=3898, BASE=`http://127.0.0.1:${PORT}`;
const env={...process.env, PORT:String(PORT),
  USERS_FILE:path.join(tmp,'config','users.yml'),
  DIR_SITES:path.join(tmp,'sites'), DIR_CONF:path.join(tmp,'conf'),
  DIR_SNIPPETS:path.join(tmp,'snippets'), DIR_STREAMS:path.join(tmp,'streams'),
  DIR_LOGS:path.join(tmp,'logs'), DIR_BACKUPS:path.join(tmp,'backups'),
  DIR_GOACCESS:path.join(tmp,'goaccess'), DIR_GIT_WORK:path.join(tmp,'gitwork'),
  DIR_SSL:path.join(tmp,'ssl'), DIR_CERTS:path.join(tmp,'certs'),
  DIR_CACHE:path.join(tmp,'cache'),
  BRANDING_HEADER_TEXT:'Client ACME — Staging'};

function req(method, p, cookie) {
  return new Promise(resolve=>{
    const r=http.request({host:'127.0.0.1',port:PORT,path:p,method,
      headers:cookie?{Cookie:cookie}:{},timeout:5000},res=>{
      let b=''; res.on('data',d=>b+=d);
      res.on('end',()=>resolve({status:res.statusCode,body:b}));
    });
    r.on('error',e=>resolve({status:0,body:e.message}));
    r.on('timeout',()=>{r.destroy();resolve({status:0,body:'timeout'})});
    r.end();
  });
}

(async ()=>{
  const srv=spawn('node',['server.js'],{env,cwd:appDir,stdio:['ignore','pipe','pipe']});
  let stderr=''; srv.stderr.on('data',d=>stderr+=d);
  await new Promise(r=>setTimeout(r,2000));

  const login=await new Promise(resolve=>{
    const body='username=admin&password=admin123';
    const r=http.request({host:'127.0.0.1',port:PORT,path:'/auth/login',method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':body.length}},
      res=>resolve({status:res.statusCode,cookie:(res.headers['set-cookie']||[''])[0].split(';')[0]}));
    r.on('error',()=>resolve({status:0,cookie:''}));
    r.write(body); r.end();
  });
  console.log('\ninjection du branding sur un index.html sans balise </head> (etat post-minification)');
  check('la connexion fonctionne malgre le fichier modifie', ()=>assert.strictEqual(login.status,302));

  const page = await req('GET','/',login.cookie);
  check('la page se sert sans planter', ()=>assert.strictEqual(page.status,200));
  check('window.BRANDING est bien injecte', ()=>assert.ok(page.body.includes('window.BRANDING=')));
  check('BRANDING_HEADER_TEXT (texte libre de l en-tete) atteint bien window.BRANDING.headerText', ()=>{
    assert.ok(page.body.includes('"headerText":"Client ACME'),
      'sans ca, la variable ENV existe cote serveur mais rien ne la porte jusqu au navigateur');
  });
  check('window.DASHBOARD_VERSION est bien injecte', ()=>assert.ok(page.body.includes('window.DASHBOARD_VERSION=')));
  check('window.UPDATE_CHECK_URL_CONFIGURED est bien injecte — le coeur du bug signale', ()=>{
    assert.ok(page.body.includes('window.UPDATE_CHECK_URL_CONFIGURED='),
      'sans cette variable, la verification automatique de version ne se declenche jamais, silencieusement');
  });
  check('le script de branding precede le script principal (ordre d execution correct)', ()=>{
    const brandingIdx = page.body.indexOf('window.BRANDING=');
    const mainScriptIdx = page.body.indexOf('function poll(');
    assert.ok(brandingIdx >= 0 && mainScriptIdx >= 0 && brandingIdx < mainScriptIdx,
      'les variables globales doivent etre definies avant que le script principal ne les lise');
  });

  srv.kill();
  fs.rmSync(appDir,{recursive:true,force:true});
  fs.rmSync(tmp,{recursive:true,force:true});
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();
