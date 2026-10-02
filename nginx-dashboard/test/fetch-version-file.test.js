'use strict';
/**
 * Fix, audit report Basse/"Sécurité et durcissement" : fetchVersionFile()
 * (server.js) recursait sur chaque redirection 301/302 SANS limite de
 * profondeur malgre son propre commentaire ("Follow single redirect") — une
 * boucle de redirections (cible mal configuree, ou faconnee par quiconque
 * controle DASHBOARD_VERSION_URL/NGINX_VERSION_URL) recursait indefiniment.
 * Verifie ici contre un vrai serveur : une boucle de redirections A -> B ->
 * A -> ... doit se terminer (resultat null), pas pendre indefiniment.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const root = path.join(__dirname, '..');
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fvf-app-'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fvf-data-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp, d), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

  const PORT = 3932;
  const REDIRECT_PORT = 3933;
  let hopCount = 0;
  // A -> B -> A -> B -> ... forever.
  const loopServer = http.createServer((req, res) => {
    hopCount++;
    const next = req.url === '/a' ? '/b' : '/a';
    res.writeHead(302, { Location: `http://127.0.0.1:${REDIRECT_PORT}${next}` });
    res.end();
  });
  await new Promise(r => loopServer.listen(REDIRECT_PORT, '127.0.0.1', r));

  const env = { ...process.env, PORT: String(PORT),
    DASHBOARD_VERSION_URL: `http://127.0.0.1:${REDIRECT_PORT}/a`,
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

  function login() {
    return new Promise(resolve => {
      const b = 'username=admin&password=admin123';
      const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
        res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
      r.on('error', () => resolve({ status: 0, cookie: '' }));
      r.write(b); r.end();
    });
  }
  function get(p, cookie) {
    return new Promise(resolve => {
      const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method: 'GET',
        headers: { Cookie: cookie }, timeout: 15000 }, res => {
        let b = ''; res.on('data', d => b += d);
        res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
      });
      r.on('error', e => resolve({ status: 0, body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
      r.end();
    });
  }

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));
  const { cookie } = await login();

  const start = Date.now();
  const r = await get('/api/version?check=1', cookie);
  const elapsed = Date.now() - start;

  check('la requete se termine (ne pend pas indefiniment sur une boucle de redirections)', () => {
    assert.strictEqual(r.status, 200);
    assert.ok(elapsed < 10000, `la requete a mis ${elapsed}ms — la boucle de redirections ne semble pas bornee`);
  });
  check('le resultat degrade proprement a null plutot que de planter', () => {
    assert.strictEqual(r.body?.updates?.dashboard, null);
  });
  check('le nombre de sauts effectues est borne (pas des centaines/milliers)', () => {
    assert.ok(hopCount < 20, `${hopCount} sauts de redirection effectues — la limite de profondeur ne semble pas appliquee`);
  });

  srv.kill('SIGTERM');
  loopServer.close();
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
