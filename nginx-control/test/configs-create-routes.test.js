'use strict';
/**
 * Routes de creation de fichiers (features/configs.js, /api/configs/create*)
 * contre un vrai serveur — meme convention que les autres *-routes.test.js.
 *
 * Le point central : la creation n est jamais possible sans les DEUX
 * conditions reunies (ALLOW_CREATE=true ET Git non configure), et les
 * validations de securite (section connue, nom de fichier sans traversee,
 * extension autorisee, pas d ecrasement d un fichier existant) s appliquent
 * avant que le pipeline de test/backup/reload ne soit meme tente — ce
 * dernier a besoin de Docker, indisponible dans ce bac a sable, donc ces
 * routes sont testees jusqu au point ou testConfigEphemeral() serait appele,
 * pas au-dela (meme limite que les tests geoipupdate/error-pages "sans
 * Docker joignable").
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgcreateroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgcreateroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3908, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT), ALLOW_CREATE: 'true',
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };
delete env.GIT_REPO_URL;

function req(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
      timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
    });
    r.on('error', e => resolve({ status: 0, body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
    if (data) r.write(data);
    r.end();
  });
}

function login(username, password) {
  return new Promise(resolve => {
    const b = `username=${username}&password=${password}`;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
}

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroutes de creation de fichiers, contre un vrai serveur (ALLOW_CREATE=true, sans Git)');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  check('login viewer ok', () => assert.strictEqual(viewerLogin.status, 302));
  const ck = adminLogin.cookie;
  const vk = viewerLogin.cookie;

  const status = await req('GET', '/api/configs/create-status', ck);
  check('create-status -> enabled quand ALLOW_CREATE=true et Git absent', () => {
    assert.strictEqual(status.status, 200);
    assert.strictEqual(status.body.allowCreate, true);
    assert.strictEqual(status.body.gitConfigured, false);
    assert.strictEqual(status.body.enabled, true);
    assert.deepStrictEqual(status.body.sections.sort(), ['conf', 'sites', 'snippets', 'streams']);
  });

  const noAuth = await req('POST', '/api/configs/create', '', { section: 'sites', name: 'x.conf', content: 'a' });
  check('creation sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const viewerTry = await req('POST', '/api/configs/create', vk, { section: 'sites', name: 'x.conf', content: 'a' });
  check('creation avec un role viewer (pas DEPLOY) -> refuse', () => assert.strictEqual(viewerTry.status, 403));

  const badSection = await req('POST', '/api/configs/create', ck, { section: 'ssl', name: 'x.conf', content: 'a' });
  check('section inconnue (ssl n est pas creable ici) -> 400', () => assert.strictEqual(badSection.status, 400));

  const traversal = await req('POST', '/api/configs/create', ck, { section: 'sites', name: '../../etc/passwd', content: 'a' });
  check('nom avec traversee de repertoire -> 400, rien ecrit hors du dossier', () => {
    assert.strictEqual(traversal.status, 400);
    assert.ok(!fs.existsSync(path.join(tmp, 'etc', 'passwd')));
  });

  const slashInName = await req('POST', '/api/configs/create', ck, { section: 'sites', name: 'sub/x.conf', content: 'a' });
  check('nom contenant un slash -> 400', () => assert.strictEqual(slashInName.status, 400));

  const badExt = await req('POST', '/api/configs/create', ck, { section: 'sites', name: 'x.php', content: 'a' });
  check('extension non autorisee -> 400', () => assert.strictEqual(badExt.status, 400));

  const noContent = await req('POST', '/api/configs/create', ck, { section: 'sites', name: 'x.conf' });
  check('sans content -> 400', () => assert.strictEqual(noContent.status, 400));

  // Un fichier deja present ne doit jamais etre ecrase par /create (c est le
  // role de /save) : on en pose un a la main puis on tente de le "creer".
  fs.writeFileSync(path.join(tmp, 'sites', 'existing.conf'), 'server { listen 80; }\n');
  const alreadyExists = await req('POST', '/api/configs/create', ck, { section: 'sites', name: 'existing.conf', content: 'server { listen 81; }' });
  check('fichier deja existant -> 409, contenu original intact', () => {
    assert.strictEqual(alreadyExists.status, 409);
    assert.strictEqual(fs.readFileSync(path.join(tmp, 'sites', 'existing.conf'), 'utf8'), 'server { listen 80; }\n');
  });

  // Le pipeline complet (test ephemere -> backup -> ecriture -> reload) a
  // besoin de Docker, indisponible ici : on verifie seulement qu une
  // creation valide passe les gardes-fous jusque-la sans planter le serveur
  // (meme limite que les tests geoipupdate/error-pages "sans Docker").
  const validAttempt = await req('POST', '/api/configs/create', ck, { section: 'snippets', name: 'new-snippet.conf', content: '# test\n' });
  check('creation valide -> ne plante pas le serveur (echec propre si Docker indisponible)', () => {
    assert.ok(validAttempt.status === 200 || validAttempt.status === 500, `status inattendu: ${validAttempt.status}`);
  });
  const alive = await req('GET', '/api/configs/create-status', ck);
  check('le serveur repond toujours apres la tentative', () => assert.strictEqual(alive.status, 200));

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });

  // ── Deuxieme serveur : ALLOW_CREATE=false par defaut ──────────────────────
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgcreateroutes-data2-'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp2, d), { recursive: true });
  fs.writeFileSync(path.join(tmp2, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  const PORT2 = 3909, BASE2 = `http://127.0.0.1:${PORT2}`;
  const env2 = { ...process.env, PORT: String(PORT2),
    USERS_FILE: path.join(tmp2, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp2, 'config'),
    DIR_SITES: path.join(tmp2, 'sites'), DIR_CONF: path.join(tmp2, 'conf'),
    DIR_SNIPPETS: path.join(tmp2, 'snippets'), DIR_STREAMS: path.join(tmp2, 'streams'),
    DIR_LOGS: path.join(tmp2, 'logs'), DIR_BACKUPS: path.join(tmp2, 'backups'),
    DIR_GOACCESS: path.join(tmp2, 'goaccess'), DIR_GIT_WORK: path.join(tmp2, 'gitwork'),
    DIR_SSL: path.join(tmp2, 'ssl'), DIR_CERTS: path.join(tmp2, 'certs'),
    DIR_CACHE: path.join(tmp2, 'cache'), DIR_GEOIP: path.join(tmp2, 'geoip') };
  delete env2.ALLOW_CREATE;
  delete env2.GIT_REPO_URL;

  function req2(method, p, cookie, body) {
    return new Promise(resolve => {
      const data = body !== undefined ? JSON.stringify(body) : null;
      const r = http.request({ host: '127.0.0.1', port: PORT2, path: p, method,
        headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
        timeout: 5000 }, res => {
        let b = ''; res.on('data', d => b += d);
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
      });
      r.on('error', e => resolve({ status: 0, body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
      if (data) r.write(data);
      r.end();
    });
  }
  function login2(username, password) {
    return new Promise(resolve => {
      const b = `username=${username}&password=${password}`;
      const r = http.request({ host: '127.0.0.1', port: PORT2, path: '/auth/login', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
        res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
      r.on('error', () => resolve({ status: 0, cookie: '' }));
      r.write(b); r.end();
    });
  }

  const appDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgcreateroutes-app2-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir2, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir2, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir2, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir2, 'server.js'));

  const srv2 = spawn('node', ['server.js'], { env: env2, cwd: appDir2, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const admin2 = await login2('admin', 'admin123');
  console.log('\nALLOW_CREATE desactive par defaut');
  check('login admin ok (2e serveur)', () => assert.strictEqual(admin2.status, 302));
  const ck2 = admin2.cookie;

  const statusOff = await req2('GET', '/api/configs/create-status', ck2);
  check('create-status -> disabled par defaut (ALLOW_CREATE non defini)', () => {
    assert.strictEqual(statusOff.body.allowCreate, false);
    assert.strictEqual(statusOff.body.enabled, false);
  });

  const createOff = await req2('POST', '/api/configs/create', ck2, { section: 'sites', name: 'x.conf', content: 'a' });
  check('creation refusee quand ALLOW_CREATE est desactive', () => assert.strictEqual(createOff.status, 403));

  // Git configure -> creation bloquee meme avec ALLOW_CREATE=true.
  fs.writeFileSync(path.join(tmp2, 'config', 'git.yml'), 'repo_url: https://forge.example.com/x/y.git\n');
  srv2.kill();
  await new Promise(r => setTimeout(r, 300));
  const env3 = { ...env2, ALLOW_CREATE: 'true' };
  const srv3 = spawn('node', ['server.js'], { env: env3, cwd: appDir2, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const admin3 = await login2('admin', 'admin123');
  console.log('\nGit configure (git.yml) -> creation bloquee malgre ALLOW_CREATE=true');
  check('login admin ok (3e serveur)', () => assert.strictEqual(admin3.status, 302));
  const ck3 = admin3.cookie;

  const statusGit = await req2('GET', '/api/configs/create-status', ck3);
  check('create-status -> gitConfigured:true, enabled:false malgre ALLOW_CREATE=true', () => {
    assert.strictEqual(statusGit.body.allowCreate, true);
    assert.strictEqual(statusGit.body.gitConfigured, true);
    assert.strictEqual(statusGit.body.enabled, false);
  });
  const createBlockedByGit = await req2('POST', '/api/configs/create', ck3, { section: 'sites', name: 'x.conf', content: 'a' });
  check('creation refusee (403) quand git.yml a un repo_url, meme avec ALLOW_CREATE=true', () => {
    assert.strictEqual(createBlockedByGit.status, 403);
    assert.ok(!fs.existsSync(path.join(tmp2, 'sites', 'x.conf')));
  });

  srv3.kill();
  fs.rmSync(appDir2, { recursive: true, force: true });
  fs.rmSync(tmp2, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
