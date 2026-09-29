'use strict';
/**
 * Route de la page Système (features/system-info.js), contre un vrai
 * serveur — meme convention que les autres *-routes.test.js. Point central
 * a verifier ici : la route est reservee aux admins (aucune valeur brute de
 * secret, mais des chemins/details d infrastructure quand meme sensibles),
 * et un champ sensible n expose jamais autre chose qu un booleen.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sysinforoutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sysinforoutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3913, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip'),
  SESSION_SECRET: 'a-real-session-secret-not-empty', GIT_TOKEN: 'super-secret-git-token' };

function req(method, p, cookie) {
  return new Promise(resolve => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}) }, timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
    });
    r.on('error', e => resolve({ status: 0, body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
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
  console.log('\nroute de la page Systeme, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  check('login viewer ok', () => assert.strictEqual(viewerLogin.status, 302));
  const ck = adminLogin.cookie;
  const vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/system-info', '');
  check('sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const asViewer = await req('GET', '/api/system-info', vk);
  check('role viewer (pas admin) -> refuse', () => assert.ok([401, 403].includes(asViewer.status)));

  const asAdmin = await req('GET', '/api/system-info', ck);
  check('role admin -> 200', () => assert.strictEqual(asAdmin.status, 200));
  check('categories et reglages yaml presents', () => {
    assert.ok(Array.isArray(asAdmin.body.categories) && asAdmin.body.categories.length > 5);
    assert.ok(Array.isArray(asAdmin.body.yamlBackedSettings) && asAdmin.body.yamlBackedSettings.length > 0);
  });

  const allEntries = asAdmin.body.categories.flatMap(c => c.entries);
  check('aucun secret configure n apparait jamais en clair, seulement un booleen', () => {
    const gitToken = allEntries.find(e => e.key === 'GIT_TOKEN');
    const sessionSecret = allEntries.find(e => e.key === 'SESSION_SECRET');
    assert.strictEqual(gitToken.sensitive, true);
    assert.strictEqual(typeof gitToken.value, 'boolean');
    assert.strictEqual(gitToken.value, true); // GIT_TOKEN est bien defini dans cet env de test
    assert.notStrictEqual(gitToken.value, 'super-secret-git-token');
    assert.strictEqual(sessionSecret.sensitive, true);
    assert.strictEqual(typeof sessionSecret.value, 'boolean');
    assert.strictEqual(sessionSecret.value, true); // SESSION_SECRET est bien defini dans cet env de test
  });
  check('un secret non configure ressort a false, jamais une chaine vide ambigue', () => {
    const crowdsecKey = allEntries.find(e => e.key === 'CROWDSEC_API_KEY');
    assert.strictEqual(crowdsecKey.value, false);
  });
  check('ALLOW_EDIT / ALLOW_CREATE / NGINX_IMAGE sont bien presents, comme demande explicitement', () => {
    assert.ok(allEntries.some(e => e.key === 'ALLOW_EDIT'));
    assert.ok(allEntries.some(e => e.key === 'ALLOW_CREATE'));
    const nginxImage = allEntries.find(e => e.key === 'NGINX_IMAGE');
    assert.ok(nginxImage);
    assert.strictEqual(nginxImage.autoDetected, true); // pas de NGINX_IMAGE fixee dans cet env de test
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
