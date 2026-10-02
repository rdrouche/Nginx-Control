'use strict';
/**
 * Route /api/analyzer/image/update (features/analyzer.js), contre un vrai
 * serveur — meme convention que certbot-routes.test.js /
 * geoipupdate-routes.test.js / error-pages-routes.test.js. Le reste des
 * routes de analyzer.js (proxy vers l agent, alertes...) n est pas couvert
 * ici : elles dependent d un agent HTTP joignable, hors de portee d un test
 * de garde de route.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3903, BASE = `http://127.0.0.1:${PORT}`;
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

  console.log('\nroute de mise a jour d image analyzer, contre un vrai serveur');
  check('login ok', () => assert.strictEqual(login.status, 302));

  const cfgNotConfigured = await req('GET', '/api/analyzer/config', ck);
  check('sans analyzer.yml -> configured:false, pas une erreur', () => {
    assert.strictEqual(cfgNotConfigured.status, 200);
    assert.strictEqual(cfgNotConfigured.body.configured, false);
  });

  console.log('\nmise a jour de l image (/api/analyzer/image/update)');
  const updateNoAuth = await req('POST', '/api/analyzer/image/update', '', {});
  check('sans session -> refuse', () => assert.ok([401, 403].includes(updateNoAuth.status)));

  const updateNotConfigured = await req('POST', '/api/analyzer/image/update', ck, {});
  check('sans analyzer.yml du tout -> 400, jamais d appel Docker', () => assert.strictEqual(updateNotConfigured.status, 400));

  fs.writeFileSync(path.join(tmp, 'config', 'analyzer.yml'), 'enable: false\n');
  const updateDisabled = await req('POST', '/api/analyzer/image/update', ck, {});
  check('non active -> 400, jamais d appel Docker', () => assert.strictEqual(updateDisabled.status, 400));

  console.log('\nregles (proxy vers un agent injoignable en test — verifie juste la degradation propre et les gardes)');
  const rulesNoAuth = await req('GET', '/api/analyzer/rules', '');
  check('sans session -> refuse', () => assert.ok([401, 403].includes(rulesNoAuth.status)));
  const rulesUnreachable = await req('GET', '/api/analyzer/rules', ck);
  check('agent injoignable -> reachable:false plutot qu une erreur HTTP', () => {
    assert.strictEqual(rulesUnreachable.status, 200);
    assert.strictEqual(rulesUnreachable.body.reachable, false);
    assert.deepStrictEqual(rulesUnreachable.body.builtins, []);
  });
  const toggleNoKey = await req('POST', '/api/analyzer/rules/toggle', ck, {});
  check('bascule sans "key" -> 400', () => assert.strictEqual(toggleNoKey.status, 400));
  const toggleNoAuth = await req('POST', '/api/analyzer/rules/toggle', '', { key: 'scan', enable: false });
  check('bascule sans session -> refuse', () => assert.ok([401, 403].includes(toggleNoAuth.status)));
  const customGetUnreachable = await req('GET', '/api/analyzer/rules/custom', ck);
  check('YAML brut, agent injoignable -> reachable:false, jamais d erreur', () => {
    assert.strictEqual(customGetUnreachable.status, 200);
    assert.strictEqual(customGetUnreachable.body.reachable, false);
  });
  const customPutNoAuth = await req('POST', '/api/analyzer/rules/custom', '', { yaml: 'rules: []' });
  check('remplacement des regles personnalisees sans session -> refuse', () => assert.ok([401, 403].includes(customPutNoAuth.status)));

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });

  // ── ANALYZER_DEFAULT_IMAGE — surcharge bout-en-bout via /api/analyzer/config ──
  // Second serveur, sur un autre port, avec la variable d env positionnee au
  // demarrage (comme le ferait le Dockerfile via ARG/ENV) — un simple
  // require.cache ne suffirait pas ici puisque c est un process separe.
  console.log('\nANALYZER_DEFAULT_IMAGE — surcharge visible via /api/analyzer/config (Dockerfile ARG/ENV)');
  const appDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerroutes-app2-'));
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzerroutes-data2-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir2, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir2, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir2, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir2, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp2, d), { recursive: true });
  fs.writeFileSync(path.join(tmp2, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
  fs.writeFileSync(path.join(tmp2, 'config', 'analyzer.yml'), 'enable: true\nhost_data_path: /containers/analyzer\n');

  const PORT2 = 3906;
  const env2 = { ...env, PORT: String(PORT2),
    USERS_FILE: path.join(tmp2, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp2, 'config'),
    DIR_SITES: path.join(tmp2, 'sites'), DIR_CONF: path.join(tmp2, 'conf'),
    DIR_SNIPPETS: path.join(tmp2, 'snippets'), DIR_STREAMS: path.join(tmp2, 'streams'),
    DIR_LOGS: path.join(tmp2, 'logs'), DIR_BACKUPS: path.join(tmp2, 'backups'),
    DIR_GOACCESS: path.join(tmp2, 'goaccess'), DIR_GIT_WORK: path.join(tmp2, 'gitwork'),
    DIR_SSL: path.join(tmp2, 'ssl'), DIR_CERTS: path.join(tmp2, 'certs'),
    DIR_CACHE: path.join(tmp2, 'cache'), DIR_GEOIP: path.join(tmp2, 'geoip'),
    ANALYZER_DEFAULT_IMAGE: 'registry.example.com/mon-fork/nginx-analyzer:latest' };
  const srv2 = spawn('node', ['server.js'], { env: env2, cwd: appDir2, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  function req2(method, p, cookie, body) {
    return new Promise(resolve => {
      const data = body ? JSON.stringify(body) : null;
      const r = http.request({ host: '127.0.0.1', port: PORT2, path: p, method,
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
  const login2 = await new Promise(resolve => {
    const b = 'username=admin&password=admin123';
    const r = http.request({ host: '127.0.0.1', port: PORT2, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
  const ck2 = login2.cookie;

  const cfgWithOverride = await req2('GET', '/api/analyzer/config', ck2);
  check('container_image absent d analyzer.yml -> /api/analyzer/config reflete ANALYZER_DEFAULT_IMAGE, pas le literal historique', () => {
    assert.strictEqual(cfgWithOverride.status, 200);
    assert.strictEqual(cfgWithOverride.body.image, 'registry.example.com/mon-fork/nginx-analyzer:latest');
  });

  srv2.kill();
  fs.rmSync(appDir2, { recursive: true, force: true });
  fs.rmSync(tmp2, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
