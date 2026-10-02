'use strict';
/**
 * Route /api/certbot/image/update (features/certbot.js), contre un vrai
 * serveur — meme convention que geoipupdate-routes.test.js /
 * error-pages-routes.test.js. Les autres routes de certbot.js sont deja
 * couvertes en tests unitaires purs dans certbot.test.js ; ce fichier ne
 * couvre que la nouvelle route de mise a jour d image, pour s assurer
 * qu elle est bien branchee et gardee (meme classe de bug que
 * stripVariantSuffix() : une fonction ecrite mais jamais appelee).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'certbotroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'certbotroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3902, BASE = `http://127.0.0.1:${PORT}`;
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
    const data = body ? JSON.stringify(body) : null;
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

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const login = await new Promise(resolve => {
    const b = 'username=admin&password=admin123';
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
  const ck = login.cookie;

  console.log('\nroute de mise a jour d image certbot, contre un vrai serveur');
  check('login ok', () => assert.strictEqual(login.status, 302));

  const cfgNotConfigured = await req('GET', '/api/certbot/config', ck);
  check('sans certbot.yml -> configured:false, pas une erreur', () => {
    assert.strictEqual(cfgNotConfigured.status, 200);
    assert.strictEqual(cfgNotConfigured.body.configured, false);
  });

  console.log('\nmise a jour de l image (/api/certbot/image/update)');
  const updateNoAuth = await req('POST', '/api/certbot/image/update', '', {});
  check('sans session -> refuse', () => assert.ok([401, 403].includes(updateNoAuth.status)));

  const updateNotConfigured = await req('POST', '/api/certbot/image/update', ck, {});
  check('sans certbot.yml du tout -> 400, jamais d appel Docker', () => assert.strictEqual(updateNotConfigured.status, 400));

  fs.writeFileSync(path.join(tmp, 'config', 'certbot.yml'), 'enable: false\n');
  const updateDisabled = await req('POST', '/api/certbot/image/update', ck, {});
  check('non active -> 400, jamais d appel Docker', () => assert.strictEqual(updateDisabled.status, 400));

  console.log('\n/api/certbot/certs — commun HTTP+DNS, independant du defi HTTP (bug corrige)');
  // Regression : cette route ne doit JAMAIS dependre de l etat "enable" de
  // certbot.yml (defi HTTP) — un site en DNS-01 pur doit voir ses certs ici.
  const certsWhileHttpDisabled = await req('GET', '/api/certbot/certs', ck);
  check('certbot.yml enable:false -> quand meme enabled:true, certs:[] (pas de faux vide "feature off")', () => {
    assert.strictEqual(certsWhileHttpDisabled.status, 200);
    assert.strictEqual(certsWhileHttpDisabled.body.enabled, true);
    assert.deepStrictEqual(certsWhileHttpDisabled.body.certs, []);
  });

  fs.rmSync(path.join(tmp, 'config', 'certbot.yml'));
  const certsWithoutCertbotYml = await req('GET', '/api/certbot/certs', ck);
  check('certbot.yml absent -> route repond quand meme 200', () => assert.strictEqual(certsWithoutCertbotYml.status, 200));

  fs.mkdirSync(path.join(tmp, 'certs', 'live', 'exemple.com'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'certs', 'live', 'exemple.com', 'cert.pem'), 'fake');
  const certsFromDnsIssuance = await req('GET', '/api/certbot/certs', ck);
  check('un certificat sur le disque (ex. emis par le defi DNS) apparait ici', () => {
    assert.strictEqual(certsFromDnsIssuance.body.certs.length, 1);
    assert.strictEqual(certsFromDnsIssuance.body.certs[0].name, 'exemple.com');
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
