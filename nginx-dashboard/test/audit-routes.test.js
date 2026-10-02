'use strict';
/**
 * Route de l audit (features/audit.js) contre un vrai serveur — meme
 * convention que les autres *-routes.test.js. L audit est purement statique
 * (pas de sonde reseau), donc pas besoin d un vrai backend a interroger ici :
 * seuls les fichiers vhost comptent.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'auditroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3911, BASE = `http://127.0.0.1:${PORT}`;
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
  fs.writeFileSync(path.join(tmp, 'sites', 'plain-http.conf'), [
    'server {',
    '    listen 80;',
    '    server_name plain.example.com;',
    '    location / { proxy_pass http://10.0.0.1:8080; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'http-redirect.conf'), [
    'server {',
    '    listen 80;',
    '    server_name legacy.example.com;',
    '    return 301 https://$host$request_uri;',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'ssl-offload.conf'), [
    'server {',
    '    listen 443 ssl;',
    '    server_name offload.example.com;',
    '    location / { proxy_pass http://10.0.0.2:8080; }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'full-ssl.conf'), [
    'server {',
    '    listen 443 ssl;',
    '    server_name secure.example.com;',
    '    location / { proxy_ssl_verify off; proxy_pass https://10.0.0.3:8443; }',
    '}',
  ].join('\n'));
  // Opt-out fichier entier : ce fichier ne doit meme pas apparaitre dans la
  // reponse (pas de card Diagnostic du tout).
  fs.writeFileSync(path.join(tmp, 'sites', 'diag-off-file.conf'), [
    '# nginx-control-diagnostic: off',
    'server {',
    '    listen 80;',
    '    server_name noise.example.com;',
    '    location / { proxy_pass http://10.0.0.9:8080; }',
    '}',
  ].join('\n'));
  // Opt-out d un seul bloc : le fichier reste, mais seul le bloc actif
  // (le second) doit apparaitre dans serverBlocks.
  fs.writeFileSync(path.join(tmp, 'sites', 'diag-off-vhost.conf'), [
    'server {',
    '    # nginx-control-diagnostic-vhost: off',
    '    listen 80;',
    '    server_name excluded.example.com;',
    '    location / { proxy_pass http://10.0.0.10:8080; }',
    '}',
    'server {',
    '    listen 443 ssl;',
    '    server_name kept.example.com;',
    '    location / { proxy_pass http://10.0.0.11:8080; }',
    '}',
  ].join('\n'));

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroute de l audit HTTP/HTTPS, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  const vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/audit', '');
  check('sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const d = await req('GET', '/api/audit', vk);
  check('un role viewer (VIEW_CONFIGS) peut lire l audit -> 200', () => assert.strictEqual(d.status, 200));
  check('six fichiers vhost sur le disque, mais diag-off-file.conf est exclu -> cinq vhosts audites', () => {
    assert.strictEqual(d.body.vhosts.length, 5);
    assert.ok(!d.body.vhosts.some(v => v.name === 'diag-off-file.conf'),
      '# nginx-control-diagnostic: off doit retirer tout le fichier de la reponse');
  });
  check('diag-off-vhost.conf : present (le fichier n est pas exclu), mais un seul bloc sur les deux (celui sans le flag)', () => {
    const v = d.body.vhosts.find(v => v.name === 'diag-off-vhost.conf');
    assert.ok(v, 'le fichier doit rester present : seul UN de ses deux blocs est exclu, pas le fichier entier');
    assert.strictEqual(v.serverBlocks.length, 1);
    assert.deepStrictEqual(v.serverBlocks[0].serverNames, ['kept.example.com']);
  });

  const byName = (n) => d.body.vhosts.find(v => v.name === n);
  check('plain-http.conf : warning http-no-redirect', () => {
    const findings = byName('plain-http.conf').serverBlocks[0].findings;
    assert.ok(findings.some(f => f.code === 'http-no-redirect' && f.level === 'warning'));
  });
  check('http-redirect.conf : info http-redirect, pas de warning', () => {
    const findings = byName('http-redirect.conf').serverBlocks[0].findings;
    assert.ok(findings.some(f => f.code === 'http-redirect' && f.level === 'info'));
    assert.ok(!findings.some(f => f.code === 'http-no-redirect'));
  });
  check('ssl-offload.conf : info ssl-offload (decharge SSL)', () => {
    const findings = byName('ssl-offload.conf').serverBlocks[0].findings;
    assert.ok(findings.some(f => f.code === 'ssl-offload' && f.level === 'info'));
  });
  check('full-ssl.conf : ok full-ssl, note le certificat auto-signe', () => {
    const findings = byName('full-ssl.conf').serverBlocks[0].findings;
    const f = findings.find(f => f.code === 'full-ssl');
    assert.ok(f && f.level === 'ok' && /auto-signe/.test(f.message));
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
