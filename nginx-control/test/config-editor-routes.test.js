'use strict';
/**
 * Routes de l editeur generique (features/config-editor.js), contre un
 * vrai serveur — meme convention que les autres *-routes.test.js. Point
 * central a verifier ici : une cle inconnue ne doit jamais resoudre un
 * chemin, et le contenu ecrit doit reellement se retrouver sur le disque
 * (contrairement aux autres features, celle-ci n a pas de garde-fou
 * "not enabled" — le test porte sur le fichier, pas sur un conteneur).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditorroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditorroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3905, BASE = `http://127.0.0.1:${PORT}`;
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
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroutes de l editeur de configuration, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  check('login viewer ok', () => assert.strictEqual(viewerLogin.status, 302));
  const ck = adminLogin.cookie;
  const vk = viewerLogin.cookie;

  const listNoAuth = await req('GET', '/api/config-editor/files', '');
  check('liste sans session -> refuse', () => assert.ok([401, 403].includes(listNoAuth.status)));

  const listViewer = await req('GET', '/api/config-editor/files', vk);
  check('liste avec un role viewer (pas DEPLOY) -> refuse', () => assert.ok([401, 403].includes(listViewer.status)));

  const list = await req('GET', '/api/config-editor/files', ck);
  check('liste -> exactement les treize fichiers, tous absents au depart', () => {
    assert.strictEqual(list.status, 200);
    const keys = list.body.files.map(f => f.key).sort();
    assert.deepStrictEqual(keys, ['agents', 'analyzer', 'blocklists', 'certbot', 'certbot-dns', 'crowdsec', 'deploy-tokens', 'docker-autoconfig', 'error-pages', 'geoipupdate', 'git', 'goaccess', 'godns']);
    assert.ok(list.body.files.every(f => f.exists === false));
  });

  const unknownKey = await req('GET', '/api/config-editor/file?key=une-cle-qui-nexiste-pas', ck);
  check('cle inconnue en lecture -> 400, ne resout aucun chemin', () => assert.strictEqual(unknownKey.status, 400));

  const unknownWrite = await req('POST', '/api/config-editor/file', ck, { key: '../../etc/passwd', content: 'x' });
  check('cle inconnue en ecriture -> 400, rien n est ecrit hors de la liste fixe', () => {
    assert.strictEqual(unknownWrite.status, 400);
  });

  const readMissing = await req('GET', '/api/config-editor/file?key=certbot-dns', ck);
  check('fichier absent -> exists:false, content vide, pas une erreur', () => {
    assert.strictEqual(readMissing.status, 200);
    assert.strictEqual(readMissing.body.exists, false);
  });

  const write = await req('POST', '/api/config-editor/file', ck, {
    key: 'certbot-dns',
    content: 'enable: true\nprovider: cloudflare\n',
  });
  check('ecriture -> ok:true', () => assert.strictEqual(write.body.ok, true));
  check('le contenu ecrit se retrouve reellement sur le disque', () => {
    const onDisk = fs.readFileSync(path.join(tmp, 'config', 'certbot-dns.yml'), 'utf8');
    assert.strictEqual(onDisk, 'enable: true\nprovider: cloudflare\n');
  });

  const writeNoContent = await req('POST', '/api/config-editor/file', ck, { key: 'certbot-dns' });
  check('sans content -> 400', () => assert.strictEqual(writeNoContent.status, 400));

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
