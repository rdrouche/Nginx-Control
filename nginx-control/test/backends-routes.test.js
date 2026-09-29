'use strict';
/**
 * Routes de l analyseur de backend (features/backends.js) contre un vrai
 * serveur — meme convention que les autres *-routes.test.js. Point central :
 * /api/backends/check ne doit jamais pouvoir contacter autre chose que ce
 * que la resolution server-side a elle-meme produit a partir du fichier
 * vhost (jamais un host/port fourni tel quel par le client).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'backendsroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'backendsroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

// A tiny real backend to probe — a plain HTTP server answering 200, and a
// closed port (nothing listening) to exercise the failure path. A request
// with Host: redirect.example.com gets a 301 to https://, to exercise the
// "backend itself enforces HTTPS" detection.
const backend = http.createServer((req, res) => {
  if ((req.headers.host || '') === 'redirect.example.com') {
    res.writeHead(301, { Location: 'https://redirect.example.com/' });
    return res.end();
  }
  res.writeHead(203, { 'X-Seen-Host': req.headers.host || '', 'X-Extra': 'demo' });
  res.end('ok');
});
const CLOSED_PORT = 3919;

const PORT = 3910, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

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
  await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
  const backendPort = backend.address().port;

  fs.writeFileSync(path.join(tmp, 'sites', 'direct.conf'), [
    'server {',
    '    listen 80;',
    '    server_name direct.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'down.conf'), [
    'server {',
    '    listen 80;',
    '    server_name down.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${CLOSED_PORT}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'static-only.conf'), [
    'server {',
    '    listen 80;',
    '    server_name static.example.com;',
    '    location / { root /var/www; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'conf', 'pool.conf'), [
    'upstream lb_pool {',
    '    server 10.0.0.1:9000;',
    '    server 10.0.0.2:9000;',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'lb.conf'), [
    'server {',
    '    listen 443 ssl;',
    '    server_name lb.example.com;',
    '    location / { proxy_pass http://lb_pool; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'redirect.conf'), [
    'server {',
    '    listen 80;',
    '    server_name redirect.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'multi.conf'), [
    'server {',
    '    listen 80;',
    '    server_name multi-a.example.com multi-b.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroutes de l analyseur de backend, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  check('login viewer ok', () => assert.strictEqual(viewerLogin.status, 302));
  const ck = adminLogin.cookie;
  const vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/backends', '');
  check('liste sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const list = await req('GET', '/api/backends', vk);
  check('un role viewer (VIEW_CONFIGS) peut lister -> 200', () => assert.strictEqual(list.status, 200));

  let direct, down, staticOnly, lb, redirectV, multi;
  check('six vhosts renvoyes, tries par nom', () => {
    assert.strictEqual(list.body.vhosts.length, 6);
    direct = list.body.vhosts.find(v => v.name === 'direct.conf');
    down = list.body.vhosts.find(v => v.name === 'down.conf');
    staticOnly = list.body.vhosts.find(v => v.name === 'static-only.conf');
    lb = list.body.vhosts.find(v => v.name === 'lb.conf');
    redirectV = list.body.vhosts.find(v => v.name === 'redirect.conf');
    multi = list.body.vhosts.find(v => v.name === 'multi.conf');
    assert.ok(direct && down && staticOnly && lb && redirectV && multi);
  });
  check('direct.conf resout en kind direct avec le bon port', () => {
    const loc = direct.serverBlocks[0].locations[0];
    assert.strictEqual(loc.kind, 'direct');
    assert.strictEqual(loc.targets[0].port, backendPort);
  });
  check('static-only.conf n a aucune location proxy_pass', () => {
    assert.strictEqual(staticOnly.serverBlocks[0].locations.length, 0);
  });
  check('lb.conf resout le pool sur deux cibles (conf/ vu depuis sites/)', () => {
    const loc = lb.serverBlocks[0].locations[0];
    assert.strictEqual(loc.kind, 'upstream');
    assert.strictEqual(loc.targets.length, 2);
  });

  const okCheck = await req('POST', '/api/backends/check', vk, {
    file: direct.file, blockIndex: 0, locationIndex: 0, targetIndex: 0,
  });
  check('check sur une cible vivante -> ok:true, statut 203 renvoye par le vrai backend', () => {
    assert.strictEqual(okCheck.status, 200);
    assert.strictEqual(okCheck.body.ok, true);
    assert.strictEqual(okCheck.body.status, 203);
    assert.ok(typeof okCheck.body.ms === 'number');
  });
  check('le Host envoye au backend est bien le server_name du vhost, pas l IP', () => {
    // Le backend de test renvoie X-Seen-Host, mais notre check() ne lit pas
    // les headers de reponse — on verifie donc plutot via hostHeader echo.
    assert.strictEqual(okCheck.body.target.hostHeader, 'direct.example.com');
  });

  const verboseCheck = await req('POST', '/api/backends/check', vk, {
    file: direct.file, blockIndex: 0, locationIndex: 0, targetIndex: 0, verbose: true,
  });
  check('avec verbose:true -> en-tetes requete/reponse presents', () => {
    assert.strictEqual(verboseCheck.status, 200);
    assert.ok(verboseCheck.body.verbose);
    assert.strictEqual(verboseCheck.body.verbose.requestHeaders.Host, 'direct.example.com');
    assert.strictEqual(verboseCheck.body.verbose.responseHeaders['x-extra'], 'demo');
  });
  const nonVerboseCheck = await req('POST', '/api/backends/check', vk, {
    file: direct.file, blockIndex: 0, locationIndex: 0, targetIndex: 0,
  });
  check('sans verbose -> pas de champ verbose dans la reponse', () => {
    assert.strictEqual(nonVerboseCheck.body.verbose, undefined);
  });

  const redirectCheck = await req('POST', '/api/backends/check', vk, {
    file: redirectV.file, blockIndex: 0, locationIndex: 0, targetIndex: 0,
  });
  check('backend HTTP qui redirige vers https:// -> redirectsToHttps:true, pas presente comme un statut brut ambigu', () => {
    assert.strictEqual(redirectCheck.status, 200);
    assert.strictEqual(redirectCheck.body.ok, true);
    assert.strictEqual(redirectCheck.body.status, 301);
    assert.strictEqual(redirectCheck.body.redirectsToHttps, true);
    assert.strictEqual(redirectCheck.body.redirectLocation, 'https://redirect.example.com/');
  });

  const multiA = await req('POST', '/api/backends/check', vk, {
    file: multi.file, blockIndex: 0, locationIndex: 0, targetIndex: 0, serverNameIndex: 0,
  });
  const multiB = await req('POST', '/api/backends/check', vk, {
    file: multi.file, blockIndex: 0, locationIndex: 0, targetIndex: 0, serverNameIndex: 1,
  });
  check('plusieurs server_name sur la meme cible -> serverNameIndex choisit bien le Host teste', () => {
    assert.strictEqual(multiA.body.target.hostHeader, 'multi-a.example.com');
    assert.strictEqual(multiB.body.target.hostHeader, 'multi-b.example.com');
  });
  const multiDefault = await req('POST', '/api/backends/check', vk, {
    file: multi.file, blockIndex: 0, locationIndex: 0, targetIndex: 0,
  });
  check('serverNameIndex omis -> repli sur le premier nom (comportement pre-existant conserve)', () => {
    assert.strictEqual(multiDefault.body.target.hostHeader, 'multi-a.example.com');
  });
  const multiBadIndex = await req('POST', '/api/backends/check', vk, {
    file: multi.file, blockIndex: 0, locationIndex: 0, targetIndex: 0, serverNameIndex: 99,
  });
  check('serverNameIndex hors bornes -> repli propre, pas une exception serveur', () => {
    assert.strictEqual(multiBadIndex.status, 200);
    assert.strictEqual(multiBadIndex.body.target.hostHeader, 'multi-a.example.com');
  });

  const downCheck = await req('POST', '/api/backends/check', vk, {
    file: down.file, blockIndex: 0, locationIndex: 0, targetIndex: 0,
  });
  check('check sur un port ferme -> ok:false, erreur explicite, pas un crash', () => {
    assert.strictEqual(downCheck.status, 200);
    assert.strictEqual(downCheck.body.ok, false);
    assert.ok(downCheck.body.error);
  });

  const badFile = await req('POST', '/api/backends/check', vk, { file: '/etc/passwd', blockIndex: 0, locationIndex: 0, targetIndex: 0 });
  check('fichier hors de DIR_SITES -> refuse (403), pas de sonde envoyee', () => {
    assert.strictEqual(badFile.status, 403);
  });

  const badIndex = await req('POST', '/api/backends/check', vk, { file: direct.file, blockIndex: 9, locationIndex: 0, targetIndex: 0 });
  check('index de bloc inexistant -> 400, pas une exception serveur', () => assert.strictEqual(badIndex.status, 400));

  const staticIndex = await req('POST', '/api/backends/check', vk, { file: staticOnly.file, blockIndex: 0, locationIndex: 0, targetIndex: 0 });
  check('tenter de tester une location sans proxy_pass -> 400', () => assert.strictEqual(staticIndex.status, 400));

  srv.kill();
  backend.close();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
