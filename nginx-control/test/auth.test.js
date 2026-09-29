'use strict';
const assert=require('assert'), fs=require('fs'), path=require('path'), os=require('os');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'auth-'));
process.env.USERS_FILE=path.join(tmp,'users.yml');
process.env.LOGIN_MAX_ATTEMPTS='3';
fs.writeFileSync(process.env.USERS_FILE,
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
  '  - username: bob\n    password: bob12345\n    role: viewer\n    name: Bob\n    enabled: true\n' +
  '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');

const A=require('../lib/auth');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\npermissions');
check('admin a tout',                 ()=>assert.ok(A.hasPerm({role:'admin'},A.PERMS.MANAGE_USERS)));
check('viewer ne deploie pas',        ()=>assert.ok(!A.hasPerm({role:'viewer'},A.PERMS.DEPLOY)));
check('operator deploie',             ()=>assert.ok(A.hasPerm({role:'operator'},A.PERMS.DEPLOY)));
check('viewer ne gere pas les users', ()=>assert.ok(!A.hasPerm({role:'viewer'},A.PERMS.MANAGE_USERS)));
check('PERMS.ADMIN est defini (le bug du 403 pour tous)', ()=>{
  assert.ok(A.PERMS.ADMIN);
  assert.ok(A.hasPerm({role:'admin'},A.PERMS.ADMIN));
  assert.ok(!A.hasPerm({role:'operator'},A.PERMS.ADMIN));
});
check('session absente = aucun droit', ()=>assert.ok(!A.hasPerm(null,A.PERMS.VIEW_METRICS)));

console.log('\nmots de passe');
check('les mdp en clair sont haches au chargement', ()=>{
  A.loadUsers();   // le chargement est paresseux
  assert.ok(fs.readFileSync(process.env.USERS_FILE,'utf8').includes('scrypt:'));
  assert.ok(!fs.readFileSync(process.env.USERS_FILE,'utf8').includes('admin123'));
});
check('scrypt accepte le bon mdp',    ()=>assert.ok(A.verifyPassword('admin123',A.findUser('admin').password)));
check('scrypt refuse le mauvais',     ()=>assert.ok(!A.verifyPassword('nope',A.findUser('admin').password)));
check('compat sha256 heritee',        ()=>{
  const crypto=require('crypto'), salt='abc';
  const legacy='sha256:'+salt+':'+crypto.createHmac('sha256',salt).update('hunter2').digest('hex');
  assert.ok(A.verifyPassword('hunter2',legacy));
  assert.ok(A.needsRehash(legacy));
  assert.ok(!A.needsRehash(A.hashPassword('x').digest));
});
check('digest malforme refuse',       ()=>assert.ok(!A.verifyPassword('x','nimporte-quoi')));
check('utilisateur desactive ignore', ()=>assert.strictEqual(A.findUser('off'),undefined));

console.log('\nsessions');
check('cycle de vie',()=>{
  const t=A.createSession({username:'admin',role:'admin',name:'A'},'1.2.3.4');
  assert.strictEqual(A.validateSession(t).username,'admin');
  A.destroySession(t);
  assert.strictEqual(A.validateSession(t),null);
});
check('jeton inconnu refuse',()=>assert.strictEqual(A.validateSession('faux'),null));
check('plafond absolu applique',()=>{
  const t=A.createSession({username:'admin',role:'admin'},'ip');
  // Fix, audit report Basse/"Sécurité et durcissement" : `sessions` est
  // desormais indexee par sha256(token), pas le jeton en clair (voir
  // hashToken() dans lib/auth.js) — d ou le passage par A.hashToken(t) ici.
  A.sessions.get(A.hashToken(t)).createdAt = Date.now() - 25*3600_000;   // au-dela de 24 h
  assert.strictEqual(A.validateSession(t),null);
});

console.log('\nfix, audit report Basse/"Sécurité et durcissement" : jetons de session non stockes en clair');
check('sessions est indexee par sha256(token), pas par le jeton lui-meme', () => {
  const t = A.createSession({ username: 'admin', role: 'admin' }, 'ip');
  assert.strictEqual(A.sessions.has(t), false, 'le jeton en clair ne doit PAS etre une cle de la map');
  assert.strictEqual(A.sessions.has(A.hashToken(t)), true, 'sha256(token) doit etre la cle');
});
check('aucune valeur de la map sessions ne contient le jeton en clair d une autre entree', () => {
  const t1 = A.createSession({ username: 'admin', role: 'admin' }, 'ip');
  const t2 = A.createSession({ username: 'bob', role: 'viewer' }, 'ip');
  for (const key of A.sessions.keys()) {
    assert.notStrictEqual(key, t1);
    assert.notStrictEqual(key, t2);
  }
});

console.log('\nSEC-09 : la session est revalidee contre le compte reel a chaque appel');
check('un compte desactive apres coup perd sa session immediatement, pas seulement a l expiration', ()=>{
  const t=A.createSession({username:'bob',role:'viewer'},'ip');
  assert.strictEqual(A.validateSession(t).username,'bob','la session doit d abord etre valide');
  // On desactive bob directement dans users.yml, comme le ferait un admin
  // depuis la page Utilisateurs — sans jamais toucher a la session elle-meme.
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: bob\n    password: bob12345\n    role: viewer\n    name: Bob\n    enabled: false\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
  assert.strictEqual(A.validateSession(t), null, 'un compte desactive ne doit plus valider ses sessions ouvertes');
});
check('un role change (promotion/retrogradation) prend effet sur la session ouverte, sans attendre un nouveau login', ()=>{
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: bob\n    password: bob12345\n    role: viewer\n    name: Bob\n    enabled: true\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
  const t=A.createSession({username:'bob',role:'viewer'},'ip');
  assert.strictEqual(A.validateSession(t).role,'viewer');
  // bob est promu admin directement dans users.yml, la session reste la meme.
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: bob\n    password: bob12345\n    role: admin\n    name: Bob\n    enabled: true\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
  assert.strictEqual(A.validateSession(t).role,'admin','le nouveau role doit etre visible immediatement');
  // On restaure l etat d origine pour les tests suivants.
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: bob\n    password: bob12345\n    role: viewer\n    name: Bob\n    enabled: true\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
});
check('un compte supprime perd sa session', ()=>{
  const t=A.createSession({username:'bob',role:'viewer'},'ip');
  assert.strictEqual(A.validateSession(t).username,'bob');
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
  assert.strictEqual(A.validateSession(t), null, 'un compte qui n existe plus ne doit plus valider ses sessions');
  // Restauration pour la suite de la suite.
  fs.writeFileSync(process.env.USERS_FILE,
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: Admin\n    enabled: true\n' +
    '  - username: bob\n    password: bob12345\n    role: viewer\n    name: Bob\n    enabled: true\n' +
    '  - username: off\n    password: x\n    role: viewer\n    name: Off\n    enabled: false\n');
});

console.log('\nfix, audit report Basse/"Sécurité et durcissement" : enumeration d utilisateurs par le temps de reponse');
check('verifyCredentials() renvoie null pour un utilisateur inexistant, sans jamais planter', () => {
  assert.strictEqual(A.verifyCredentials('nobody-such-user', 'whatever'), null);
});
check('verifyCredentials() renvoie null pour un mauvais mot de passe', () => {
  assert.strictEqual(A.verifyCredentials('admin', 'wrong-password'), null);
});
check('verifyCredentials() renvoie l utilisateur pour un bon mot de passe', () => {
  assert.strictEqual(A.verifyCredentials('admin', 'admin123')?.username, 'admin');
});
check('un utilisateur inexistant et un mauvais mot de passe coutent sensiblement le meme temps (scrypt toujours calcule)', () => {
  const N = 8;
  const timeIt = fn => { const t0 = process.hrtime.bigint(); for (let i = 0; i < N; i++) fn(); return Number(process.hrtime.bigint() - t0); };
  const tUnknown = timeIt(() => A.verifyCredentials('this-username-does-not-exist-at-all', 'x'.repeat(10)));
  const tWrongPw = timeIt(() => A.verifyCredentials('admin', 'x'.repeat(10)));
  // scrypt (~tens of ms) dominates completely over a Map miss (~microseconds);
  // a ratio check tolerates machine noise far better than an absolute delta.
  const ratio = Math.max(tUnknown, tWrongPw) / Math.min(tUnknown, tWrongPw);
  assert.ok(ratio < 3, `ecart de temps trop marque entre utilisateur inconnu et mauvais mot de passe (ratio ${ratio.toFixed(2)}) — fuite possible par timing`);
});

console.log('\nanti brute-force');
check('verrouillage apres N echecs',()=>{
  const ip='9.9.9.9';
  assert.ok(!A.checkLoginRate(ip,'admin').blocked);
  for(let i=0;i<3;i++) A.recordLoginFailure(ip,'admin');
  const r=A.checkLoginRate(ip,'admin');
  assert.ok(r.blocked && r.retryAfterSec>0);
});
check('un login reussi remet a zero',()=>{
  const ip='8.8.8.8';
  for(let i=0;i<3;i++) A.recordLoginFailure(ip,'bob');
  assert.ok(A.checkLoginRate(ip,'bob').blocked);
  A.clearLoginFailures(ip,'bob');
  assert.ok(!A.checkLoginRate(ip,'bob').blocked);
});

console.log('\ncomparaison a temps constant');
check('egalite',        ()=>assert.ok(A.safeCompare('secret','secret')));
check('difference',     ()=>assert.ok(!A.safeCompare('secret','secrez')));
check('longueurs differentes',()=>assert.ok(!A.safeCompare('a','abc')));

fs.rmSync(tmp,{recursive:true,force:true});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
