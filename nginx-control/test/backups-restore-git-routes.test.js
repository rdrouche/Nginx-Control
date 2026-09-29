'use strict';
/**
 * POST /api/backups/restore contre un vrai serveur — retour utilisateur
 * (v12.46.0) : restaurer une sauvegarde locale restait possible meme avec
 * Git configure, alors que le depot devient la source de verite une fois
 * configure — une restauration locale le desynchronise silencieusement.
 * Meme convention que test/configs-edit-routes.test.js et
 * test/configs-create-routes.test.js (ALLOW_EDIT/ALLOW_CREATE, meme regle).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const { execFileSync } = require('child_process');

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

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bkprestoregit-data-'));
  const PORT = 3912;
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bkprestoregit-app-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp, d), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  // Git configure des le depart : repo_url renseigne dans git.yml.
  fs.writeFileSync(path.join(tmp, 'config', 'git.yml'), 'repo_url: https://forge.example.com/x/y.git\n');

  // Une vraie sauvegarde a restaurer, pour verifier qu elle n est pas touchee.
  const zipPath = path.join(tmp, 'backups', 'pre-existing.zip');
  execFileSync('zip', ['-j', zipPath, path.join(tmp, 'config', 'users.yml')]);
  const zipContentBefore = fs.readFileSync(zipPath);

  const env = { ...process.env, PORT: String(PORT),
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };
  delete env.GIT_REPO_URL;

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const admin = await login(PORT, 'admin', 'admin123');
  console.log('\nGit configure (git.yml) -> restauration de sauvegarde locale bloquee');
  check('login admin ok', () => assert.strictEqual(admin.status, 302));
  const ck = admin.cookie;

  const listResp = await req(PORT, 'GET', '/api/backups', ck);
  check('GET /api/backups -> gitConfigured:true', () => {
    assert.strictEqual(listResp.status, 200);
    assert.strictEqual(listResp.body.gitConfigured, true);
  });

  const restore = await req(PORT, 'POST', '/api/backups/restore', ck, { name: 'pre-existing.zip' });
  check('POST /api/backups/restore -> 403 quand Git est configure, sauvegarde intacte', () => {
    assert.strictEqual(restore.status, 403);
    assert.ok(/Git/.test(restore.body.error || ''), `message attendu mentionnant Git : ${JSON.stringify(restore.body)}`);
    assert.ok(fs.readFileSync(zipPath).equals(zipContentBefore), 'la sauvegarde ne doit jamais etre touchee par une tentative refusee');
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
