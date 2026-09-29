'use strict';
/**
 * server.js — routes de deep-linking (v12.31.0) : un F5, un lien direct ou
 * un favori sur "/map"/"/live-logs"/etc. doit servir le meme index.html que
 * "/", pas un 404 — et une URL qui n'est dans aucune des deux listes doit
 * continuer a faire un 404 propre. Meme pattern de serveur reel (spawn) que
 * test/security-hardening-basse.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const pageRoutes = require('../lib/page-routes');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const root = path.join(__dirname, '..');
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeplink-app-'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deeplink-data-'));
  fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
  fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
  fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
  fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
  for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
    fs.mkdirSync(path.join(tmp, d), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
    'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

  const PORT = 3931;
  const env = { ...process.env, PORT: String(PORT),
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

  function rawReq(method, p, { headers = {}, body } = {}) {
    return new Promise(resolve => {
      const data = body !== undefined ? body : null;
      const h = { ...headers };
      if (data) h['Content-Length'] = Buffer.byteLength(data);
      const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers: h, timeout: 5000 }, res => {
        // Fix (flaky sur grosse page comme index.html) : concatener des
        // Buffers directement dans une string (`b += d`) decode chaque
        // morceau independamment en UTF-8 des qu il arrive — un caractere
        // multi-octets (accents, box-drawing "─"...) coupe pile a la
        // frontiere de deux paquets TCP est alors corrompu de facon non
        // deterministe (depend du decoupage reseau, donc plus visible sous
        // charge, comme dans la suite complete). On accumule les Buffers
        // bruts et on ne decode qu une fois le corps entierement recu.
        const chunks = [];
        res.on('data', d => chunks.push(d));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      });
      r.on('error', e => resolve({ status: 0, body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
      if (data) r.write(data);
      r.end();
    });
  }

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));

  console.log('\nsans session : toute route de deep-linking redirige vers /auth/login, comme "/"');
  const anonMap = await rawReq('GET', '/map');
  check('GET /map (anonyme) -> 302 vers /auth/login', () => {
    assert.strictEqual(anonMap.status, 302);
    assert.strictEqual(anonMap.headers['location'], '/auth/login');
  });

  const loginOk = await rawReq('POST', '/auth/login', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=admin&password=admin123' });
  const cookie = (loginOk.headers['set-cookie'] || [''])[0].split(';')[0];
  check('connexion OK, cookie de session obtenu', () => assert.ok(cookie));

  console.log('\navec session : chaque route de deep-linking sert le meme index.html que "/"');
  const home = await rawReq('GET', '/', { headers: { Cookie: cookie } });
  const map = await rawReq('GET', '/map', { headers: { Cookie: cookie } });
  check('GET /map (authentifie) -> 200, meme contenu que "/"', () => {
    assert.strictEqual(map.status, 200);
    assert.strictEqual(map.body, home.body);
  });
  const liveLogs = await rawReq('GET', '/live-logs', { headers: { Cookie: cookie } });
  check('GET /live-logs (authentifie) -> 200', () => assert.strictEqual(liveLogs.status, 200));
  const overview = await rawReq('GET', '/overview', { headers: { Cookie: cookie } });
  check('GET /overview (slug identique au data-page) -> 200', () => assert.strictEqual(overview.status, 200));
  const dashboardAlias = await rawReq('GET', '/dashboard', { headers: { Cookie: cookie } });
  check('l alias historique "/dashboard" continue de fonctionner', () => assert.strictEqual(dashboardAlias.status, 200));

  console.log('\nune route inconnue continue de faire un 404 propre (liste blanche, pas une regle generale)');
  const unknown = await rawReq('GET', '/ceci-nexiste-pas', { headers: { Cookie: cookie } });
  check('GET /ceci-nexiste-pas -> 404', () => assert.strictEqual(unknown.status, 404));
  const apiStillWorks = await rawReq('GET', '/api/auth/me', { headers: { Cookie: cookie } });
  check('les routes /api/* ne sont pas avalees par la liste blanche', () => assert.strictEqual(apiStillWorks.status, 200));

  console.log('\nwindow.PAGE_ROUTES est injecte et correspond exactement a lib/page-routes.js');
  check('la page servie embarque bien window.PAGE_ROUTES avec la table complete', () => {
    const m = home.body.match(/window\.PAGE_ROUTES=(\{.*?\});/);
    assert.ok(m, 'window.PAGE_ROUTES absent de la page servie');
    const injected = JSON.parse(m[1]);
    assert.deepStrictEqual(injected, { slugToPage: pageRoutes.SLUG_TO_PAGE, pageToSlug: pageRoutes.PAGE_TO_SLUG });
  });

  srv.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
