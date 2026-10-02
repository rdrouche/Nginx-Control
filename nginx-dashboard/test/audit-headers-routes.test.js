'use strict';
/**
 * Route de l analyse live des en-tetes (features/audit.js's POST
 * /api/audit/headers) contre un vrai serveur. Simule le reverse proxy et le
 * backend avec deux petits serveurs HTTP reels locaux — pas de vraie
 * instance nginx ici, mais NGINX_CONTAINER pointe vers 127.0.0.1 et le
 * fichier vhost declare `listen <port du faux proxy>`, donc la route
 * contacte exactement ce que ferait un vrai visiteur (Host header inclus).
 * La logique de decision (HSTS, etc.) est deja couverte en isolation par
 * vhost-audit.test.js — ce test ne verifie que la plomberie : bon
 * host/port/Host contactes, les deux cotes bien distingues, permissions,
 * fichier/bloc invalides.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditheaders-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'auditheaders-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

// Faux reverse proxy : renvoie un Server avec version + X-Powered-By, comme
// un nginx par defaut (server_tokens on) qui laisse aussi passer un en-tete
// backend sans le filtrer — de quoi declencher plusieurs findings a la fois.
const fakeProxy = http.createServer((req, res) => {
  res.writeHead(200, { Server: 'nginx/1.24.0', 'X-Powered-By': 'Express', 'X-Seen-Host': req.headers.host || '' });
  res.end('ok');
});
// Faux backend : meme Server (avec version) que le proxy -> declenche le
// finding "le proxy laisse passer tel quel l en-tete Server du backend".
const fakeBackend = http.createServer((req, res) => {
  res.writeHead(200, { Server: 'nginx/1.24.0' });
  res.end('backend');
});

const PORT = 3913, BASE = `http://127.0.0.1:${PORT}`;
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
  await new Promise(resolve => fakeProxy.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => fakeBackend.listen(0, '127.0.0.1', resolve));
  const proxyPort = fakeProxy.address().port;
  const backendPort = fakeBackend.address().port;

  fs.writeFileSync(path.join(tmp, 'sites', 'sec.conf'), [
    'server {',
    `    listen ${proxyPort};`,
    '    server_name sec.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'no-name.conf'), [
    'server {',
    `    listen ${proxyPort};`,
    '    location / { return 404; }',
    '}',
  ].join('\n'));
  // Signalement reel : un vhost qui ne fait que rediriger HTTP -> HTTPS n a,
  // par construction, aucune location avec proxy_pass — donc aucune cible
  // backend a joindre. Le frontend affichait pourtant "Backend : ECHEC" en
  // rouge pour ce cas parfaitement normal.
  fs.writeFileSync(path.join(tmp, 'sites', 'redirect-only.conf'), [
    'server {',
    `    listen ${proxyPort};`,
    '    server_name redirect.example.com;',
    '    return 301 https://$host$request_uri;',
    '}',
  ].join('\n'));

  const env = { ...process.env, PORT: String(PORT), NGINX_CONTAINER: '127.0.0.1',
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroute d analyse live des en-tetes, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  const vk = viewerLogin.cookie;

  const noAuth = await req('POST', '/api/audit/headers', '', { file: path.join(tmp, 'sites', 'sec.conf'), blockIndex: 0 });
  check('sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const secFile = path.join(tmp, 'sites', 'sec.conf');
  const r = await req('POST', '/api/audit/headers', vk, { file: secFile, blockIndex: 0 });
  check('un role viewer (VIEW_CONFIGS) peut lancer l analyse -> 200', () => assert.strictEqual(r.status, 200));
  check('cote proxy contacte avec le bon Host (le server_name du vhost)', () => {
    assert.strictEqual(r.body.proxy.ok, true);
    assert.strictEqual(r.body.proxy.verbose.requestHeaders.Host, 'sec.example.com');
  });
  check('cote backend contacte independamment, meme resultat de sonde', () => {
    assert.strictEqual(r.body.backend.ok, true);
  });
  check('findings : fuite de version + X-Powered-By + passthrough backend, tous presents', () => {
    const codes = r.body.findings.map(f => f.code);
    assert.ok(codes.includes('server-version-leak'));
    assert.ok(codes.includes('x-powered-by-leak'));
    assert.ok(codes.includes('backend-header-passthrough'));
  });

  const badFile = await req('POST', '/api/audit/headers', vk, { file: '/etc/passwd', blockIndex: 0 });
  check('fichier hors de DIR_SITES -> refuse (403)', () => assert.strictEqual(badFile.status, 403));

  const badBlock = await req('POST', '/api/audit/headers', vk, { file: secFile, blockIndex: 9 });
  check('index de bloc inexistant -> 400, pas une exception serveur', () => assert.strictEqual(badBlock.status, 400));

  const noNameFile = path.join(tmp, 'sites', 'no-name.conf');
  const noName = await req('POST', '/api/audit/headers', vk, { file: noNameFile, blockIndex: 0 });
  check('bloc sans server_name -> 400, rien a sonder du cote Host', () => assert.strictEqual(noName.status, 400));

  const redirectFile = path.join(tmp, 'sites', 'redirect-only.conf');
  const redirectR = await req('POST', '/api/audit/headers', vk, { file: redirectFile, blockIndex: 0 });
  check('vhost redirect-only : le proxy repond normalement (200)', () => {
    assert.strictEqual(redirectR.status, 200);
    assert.strictEqual(redirectR.body.proxy.ok, true);
  });
  check('vhost redirect-only : le backend est marque "skipped", pas "ECHEC" — aucune cible n existe, ce n est pas une panne', () => {
    assert.strictEqual(redirectR.body.backend.ok, false);
    assert.strictEqual(redirectR.body.backend.skipped, true,
      'sans ce marqueur, le frontend affiche a tort "ECHEC" en rouge pour un vhost qui ne fait que rediriger');
  });

  srv.kill();
  fakeProxy.close();
  fakeBackend.close();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
