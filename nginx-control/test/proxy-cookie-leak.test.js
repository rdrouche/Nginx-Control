'use strict';
/**
 * Le cookie de session du dashboard ne doit pas fuiter vers des conteneurs
 * tiers proxifies (GoDNS, GoAccess), et ces conteneurs ne doivent pas
 * pouvoir poser un Set-Cookie sur l origine du dashboard (fix, audit finding
 * MISC-09). Contre un vrai serveur, meme convention que csrf-guard.test.js :
 * le "conteneur" GoDNS/GoAccess est simule par un serveur HTTP local (le nom
 * de conteneur configure pointe vers 127.0.0.1).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcl-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pcl-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3922;
const GODNS_PORT = 3923;
const GOACCESS_PORT = 3924;

fs.writeFileSync(path.join(tmp, 'config', 'godns.yml'),
  `enable: true\ncontainer_name: 127.0.0.1\nport: ${GODNS_PORT}\n`);

const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

function rawGet(p, cookie) {
  return new Promise(resolve => {
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method: 'GET', headers, timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
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
  // Fake "GoDNS" container: records every inbound header it receives, and
  // deliberately tries to plant its own cookie on the response.
  let godnsSawHeaders = null;
  const godnsFake = http.createServer((req, res) => {
    godnsSawHeaders = req.headers;
    res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'godns_evil=1; Path=/' });
    res.end('<html>godns panel</html>');
  });
  await new Promise(r => godnsFake.listen(GODNS_PORT, '127.0.0.1', r));

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));

  const { cookie } = await login('admin', 'admin123');
  console.log('\nfuite du cookie de session vers un conteneur tiers proxifie (fix MISC-09)');
  check('login admin ok', () => assert.ok(cookie));

  const panelRes = await rawGet('/api/godns/panel/', cookie);
  check('la reponse du panneau GoDNS arrive bien (proxy fonctionnel)', () => assert.strictEqual(panelRes.status, 200));
  check('le cookie de session du dashboard n est PAS transmis au conteneur GoDNS', () => {
    assert.ok(godnsSawHeaders, 'le faux conteneur GoDNS n a recu aucune requete');
    assert.strictEqual(godnsSawHeaders.cookie, undefined,
      `le conteneur GoDNS a recu un en-tete Cookie : ${godnsSawHeaders.cookie}`);
  });
  check('un Set-Cookie pose par GoDNS n est pas repercute sur l origine du dashboard', () => {
    assert.strictEqual(panelRes.headers['set-cookie'], undefined);
  });
  check('une CSP frame-ancestors restrictive protege la page proxifiee', () => {
    assert.ok(/frame-ancestors 'self'/.test(panelRes.headers['content-security-policy'] || ''));
  });

  srv.kill('SIGTERM');
  godnsFake.close();
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
