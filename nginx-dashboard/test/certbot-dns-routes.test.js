'use strict';
/**
 * Routes API du defi DNS (features/certbot-dns.js), contre un vrai serveur —
 * meme convention que certbot-routes.test.js / geoipupdate-routes.test.js /
 * error-pages-routes.test.js / analyzer-routes.test.js. Sans Docker
 * disponible dans ce bac a sable, tout ce qui doit etre refuse AVANT d y
 * arriver (permission, pas active, prerequis de configuration manquants)
 * doit l etre sans jamais y toucher.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnsroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnsroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3904, BASE = `http://127.0.0.1:${PORT}`;
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

  console.log('\nroutes du defi DNS, contre un vrai serveur');
  check('login ok', () => assert.strictEqual(login.status, 302));

  const providers = await req('GET', '/api/certbot-dns/providers', ck);
  check('liste des fournisseurs -> cloudflare present avec ses reglages', () => {
    assert.strictEqual(providers.status, 200);
    const cf = providers.body.providers.find(p => p.key === 'cloudflare');
    assert.ok(cf, 'cloudflare absent de la liste');
    assert.strictEqual(cf.defaultImage, 'certbot/dns-cloudflare:latest');
    assert.strictEqual(cf.needsCredentialsFile, true);
  });

  const cfgNotConfigured = await req('GET', '/api/certbot-dns/config', ck);
  check('sans certbot-dns.yml -> configured:false, pas une erreur', () => {
    assert.strictEqual(cfgNotConfigured.status, 200);
    assert.strictEqual(cfgNotConfigured.body.configured, false);
  });

  const statusNotConfigured = await req('GET', '/api/certbot-dns/status', ck);
  check('status sans config -> enabled:false', () => {
    assert.strictEqual(statusNotConfigured.status, 200);
    assert.strictEqual(statusNotConfigured.body.enabled, false);
  });

  const startNotConfigured = await req('POST', '/api/certbot-dns/container/start', ck, {});
  check('start sans configuration active -> 400, jamais d appel Docker', () => {
    assert.strictEqual(startNotConfigured.status, 400);
  });

  const issueNotConfigured = await req('POST', '/api/certbot-dns/issue', ck, { certificates: [{ domains: ['example.com'] }] });
  check('issue sans configuration active -> 400, jamais d appel Docker', () => {
    assert.strictEqual(issueNotConfigured.status, 400);
  });

  fs.writeFileSync(path.join(tmp, 'config', 'certbot-dns.yml'), [
    'enable: true',
    'provider: cloudflare',
    'email: admin@example.com',
    // credentials_host_path deliberately omitted below.
    'certs_host_path: /containers/certs',
    '',
  ].join('\n'));

  const cfgConfigured = await req('GET', '/api/certbot-dns/config', ck);
  check('configure -> reflete le fournisseur et l image par defaut', () => {
    assert.strictEqual(cfgConfigured.status, 200);
    assert.strictEqual(cfgConfigured.body.configured, true);
    assert.strictEqual(cfgConfigured.body.provider, 'cloudflare');
    assert.strictEqual(cfgConfigured.body.image, 'certbot/dns-cloudflare:latest');
    assert.strictEqual(cfgConfigured.body.credentialsConfigured, false);
  });

  const issueNoCreds = await req('POST', '/api/certbot-dns/issue', ck, { certificates: [{ domains: ['exemple.tld', '*.exemple.tld'] }] });
  check('active mais sans credentials_host_path -> 400, jamais d appel Docker', () => {
    assert.strictEqual(issueNoCreds.status, 400);
  });

  const issueEmpty = await req('POST', '/api/certbot-dns/issue', ck, { certificates: [] });
  check('aucun groupe de domaines -> 400', () => {
    assert.strictEqual(issueEmpty.status, 400);
  });

  const stopNoAuth = await req('POST', '/api/certbot-dns/container/stop', '', {});
  check('sans session -> refuse, pas une fuite', () => assert.ok([401, 403].includes(stopNoAuth.status)));

  console.log('\nmise a jour de l image (/api/certbot-dns/image/update)');
  const updateNoAuth = await req('POST', '/api/certbot-dns/image/update', '', {});
  check('sans session -> refuse', () => assert.ok([401, 403].includes(updateNoAuth.status)));

  fs.writeFileSync(path.join(tmp, 'config', 'certbot-dns.yml'), 'enable: false\n');
  const updateDisabled = await req('POST', '/api/certbot-dns/image/update', ck, {});
  check('non active -> 400, jamais d appel Docker', () => assert.strictEqual(updateDisabled.status, 400));

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
