'use strict';
/**
 * Routes d edition inline (features/configs.js, /api/configs/save et
 * /api/configs/edit-status) contre un vrai serveur — meme convention que
 * test/configs-create-routes.test.js.
 *
 * Retour utilisateur (v12.46.0) : avec Git configure, ALLOW_EDIT=true
 * laissait quand meme modifier un fichier en place — un changement que Git
 * ignore completement, et que le prochain pull/deploiement ecrase
 * silencieusement (ou, pire, qui ressemble a une derive la prochaine fois
 * qu on diffe contre le depot). Meme regle que ALLOW_CREATE (deja
 * couverte par configs-create-routes.test.js) : une fois Git configure, le
 * depot est la source de verite, donc l edition en place n est sure que
 * tant qu il n y a pas de depot avec lequel diverger.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');

function req(port, method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, path: p, method,
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

function login(port, username, password) {
  return new Promise(resolve => {
    const b = `username=${username}&password=${password}`;
    const r = http.request({ host: '127.0.0.1', port, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
}

function makeApp(dataDir, extraEnv) {
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditroutes-app-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(dataDir, d), { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  const env = { ...process.env, ALLOW_EDIT: 'true',
    USERS_FILE: path.join(dataDir, 'config', 'users.yml'), CONFIG_DIR: path.join(dataDir, 'config'),
    DIR_SITES: path.join(dataDir, 'sites'), DIR_CONF: path.join(dataDir, 'conf'),
    DIR_SNIPPETS: path.join(dataDir, 'snippets'), DIR_STREAMS: path.join(dataDir, 'streams'),
    DIR_LOGS: path.join(dataDir, 'logs'), DIR_BACKUPS: path.join(dataDir, 'backups'),
    DIR_GOACCESS: path.join(dataDir, 'goaccess'), DIR_GIT_WORK: path.join(dataDir, 'gitwork'),
    DIR_SSL: path.join(dataDir, 'ssl'), DIR_CERTS: path.join(dataDir, 'certs'),
    DIR_CACHE: path.join(dataDir, 'cache'), DIR_GEOIP: path.join(dataDir, 'geoip'),
    ...extraEnv };
  delete env.GIT_REPO_URL;
  return { appDir, env };
}

(async () => {
  // ── Serveur 1 : ALLOW_EDIT=true, Git non configure ──────────────────────
  const tmp1 = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditroutes-data1-'));
  const PORT1 = 3910;
  const { appDir: appDir1, env: env1 } = makeApp(tmp1, { PORT: String(PORT1) });
  fs.writeFileSync(path.join(tmp1, 'sites', 'existing.conf'), 'server { listen 80; }\n');

  const srv1 = spawn('node', ['server.js'], { env: env1, cwd: appDir1, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const admin1 = await login(PORT1, 'admin', 'admin123');
  console.log('\nroutes d edition inline, contre un vrai serveur (ALLOW_EDIT=true, sans Git)');
  check('login admin ok', () => assert.strictEqual(admin1.status, 302));
  const ck1 = admin1.cookie;

  const status1 = await req(PORT1, 'GET', '/api/configs/edit-status', ck1);
  check('edit-status -> enabled quand ALLOW_EDIT=true et Git absent', () => {
    assert.strictEqual(status1.status, 200);
    assert.strictEqual(status1.body.allowEdit, true);
    assert.strictEqual(status1.body.gitConfigured, false);
    assert.strictEqual(status1.body.enabled, true);
  });

  const filePath1 = path.join(tmp1, 'sites', 'existing.conf');
  const save1 = await req(PORT1, 'POST', '/api/configs/save', ck1, { path: filePath1, content: 'server { listen 81; }' });
  check('edition valide (sans Git) -> ne plante pas le serveur (echec propre si Docker indisponible)', () => {
    assert.ok(save1.status === 200 || save1.status === 500, `status inattendu: ${save1.status}`);
  });

  srv1.kill();
  fs.rmSync(appDir1, { recursive: true, force: true });
  fs.rmSync(tmp1, { recursive: true, force: true });

  // ── Serveur 2 : ALLOW_EDIT=true ET Git configure (git.yml) ──────────────
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditroutes-data2-'));
  const PORT2 = 3911;
  const { appDir: appDir2, env: env2 } = makeApp(tmp2, { PORT: String(PORT2) });
  fs.writeFileSync(path.join(tmp2, 'sites', 'existing.conf'), 'server { listen 80; }\n');
  fs.writeFileSync(path.join(tmp2, 'config', 'git.yml'), 'repo_url: https://forge.example.com/x/y.git\n');

  const srv2 = spawn('node', ['server.js'], { env: env2, cwd: appDir2, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const admin2 = await login(PORT2, 'admin', 'admin123');
  console.log('\nGit configure (git.yml) -> edition inline bloquee malgre ALLOW_EDIT=true');
  check('login admin ok (2e serveur)', () => assert.strictEqual(admin2.status, 302));
  const ck2 = admin2.cookie;

  const status2 = await req(PORT2, 'GET', '/api/configs/edit-status', ck2);
  check('edit-status -> gitConfigured:true, enabled:false malgre ALLOW_EDIT=true', () => {
    assert.strictEqual(status2.body.allowEdit, true);
    assert.strictEqual(status2.body.gitConfigured, true);
    assert.strictEqual(status2.body.enabled, false);
  });

  const filePath2 = path.join(tmp2, 'sites', 'existing.conf');
  const save2 = await req(PORT2, 'POST', '/api/configs/save', ck2, { path: filePath2, content: 'server { listen 81; }' });
  check('edition refusee (403) quand git.yml a un repo_url, meme avec ALLOW_EDIT=true', () => {
    assert.strictEqual(save2.status, 403);
    assert.strictEqual(fs.readFileSync(filePath2, 'utf8'), 'server { listen 80; }\n');
  });

  srv2.kill();
  fs.rmSync(appDir2, { recursive: true, force: true });
  fs.rmSync(tmp2, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
