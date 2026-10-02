'use strict';
/**
 * Routes du monitoring continu (features/monitor.js) contre un vrai serveur
 * — meme convention que backends-routes.test.js, dont il reutilise le tout
 * petit backend HTTP reel. Le rescan/tick automatiques tournent sur de vrais
 * timers (30s / 5s, voir features/monitor.js) — trop lents pour un test :
 * on attend le tout premier rescan (declenche 1s apres le boot par
 * server.js), puis on force les sondes via POST /api/monitor/check-now
 * plutot que d attendre le prochain tick naturel.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'monitorroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'monitorroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

// Backend reel, toujours vivant — pour la cible surveillee "up". La cible
// surveillee "down" pointe vers un port ferme (personne n ecoute), comme
// dans backends-routes.test.js.
const backend = http.createServer((req, res) => { res.writeHead(200); res.end('ok'); });
const CLOSED_PORT = 3929;

// Backends renvoyant des codes non-2xx mais bien une vraie reponse HTTP —
// le cas signale par l utilisateur : un conteneur arrete derriere un
// reverse proxy type Traefik repond quand meme (souvent 404), ce qui ne
// doit pas etre confondu avec "en ligne" selon la regle configuree.
const backend404 = http.createServer((req, res) => { res.writeHead(404); res.end('not found'); });
const backend500 = http.createServer((req, res) => { res.writeHead(500); res.end('boom'); });

const PORT = 3912, BASE = `http://127.0.0.1:${PORT}`;
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
    // Content-Type: application/json toujours envoye pour une methode non-GET
    // (fix SEC-12 : exige par le serveur), meme sans corps.
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}),
                 ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
                 ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
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
  await new Promise(resolve => backend404.listen(0, '127.0.0.1', resolve));
  const backend404Port = backend404.address().port;
  await new Promise(resolve => backend500.listen(0, '127.0.0.1', resolve));
  const backend500Port = backend500.address().port;

  fs.writeFileSync(path.join(tmp, 'sites', 'mon-up.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-interval: 3600s',
    '    listen 443 ssl;',
    '    server_name up.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-down.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name down.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${CLOSED_PORT}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-off.conf'), [
    'server {',
    '    # nginx-control-monitoring: off',
    '    listen 443 ssl;',
    '    server_name off.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '}',
  ].join('\n'));
  // Deux locations vers la meme cible : sans le flag, monitor.js sonderait
  // les deux independamment pour rien (demande de suivi de l utilisateur).
  // Regle par defaut (pas de flag valid-http-code) : une reponse 500 est
  // down, une reponse 404 reste up (seul le 5xx ou l absence de reponse est
  // down par defaut).
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-default-5xx.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name default-5xx.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backend500Port}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-default-404.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name default-404.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backend404Port}; }`,
    '}',
  ].join('\n'));
  // Surcharge : seuls 2xx/3xx comptent comme up — le cas Traefik signale par
  // l utilisateur (conteneur arrete -> 404 quand meme repondu).
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-strict-404.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-valid-http-code: 2xx, 3xx',
    '    listen 443 ssl;',
    '    server_name strict-404.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backend404Port}; }`,
    '}',
  ].join('\n'));
  // Surcharge inverse : 4xx explicitement accepte -> le meme backend 404
  // reste up cette fois.
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-allow-4xx.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    # nginx-control-monitoring-valid-http-code: 4xx',
    '    listen 443 ssl;',
    '    server_name allow-4xx.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backend404Port}; }`,
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(tmp, 'sites', 'mon-ignore-loc.conf'), [
    'server {',
    '    # nginx-control-monitoring: on',
    '    listen 443 ssl;',
    '    server_name dup.example.com;',
    `    location / { proxy_pass http://127.0.0.1:${backendPort}; }`,
    '    location /api {',
    '        # nginx-control-monitoring-ignore-location: on',
    `        proxy_pass http://127.0.0.1:${backendPort};`,
    '    }',
    '}',
  ].join('\n'));

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2500)); // boot + the monitor's first rescan (fires 1s after boot)

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroutes du monitoring continu, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  const vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/monitor', '');
  check('liste sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const list1 = await req('GET', '/api/monitor', vk);
  check('un role viewer (VIEW_CONFIGS) peut lister -> 200', () => assert.strictEqual(list1.status, 200));
  check('seules les deux cibles avec le flag "on" apparaissent (celle "off" est exclue)', () => {
    const names = list1.body.targets.map(t => t.vhostName);
    assert.ok(names.includes('mon-up.conf'));
    assert.ok(names.includes('mon-down.conf'));
    assert.ok(!names.includes('mon-off.conf'));
  });

  check('location marquee ignore-location -> exclue, seule l autre location du meme vhost est surveillee', () => {
    const dupTargets = list1.body.targets.filter(t => t.vhostName === 'mon-ignore-loc.conf');
    assert.strictEqual(dupTargets.length, 1);
    assert.strictEqual(dupTargets[0].path, '/');
  });

  const upTarget = list1.body.targets.find(t => t.vhostName === 'mon-up.conf');
  const downTarget = list1.body.targets.find(t => t.vhostName === 'mon-down.conf');
  check('avant toute sonde, aucun historique donc pas d etat courant (up:null)', () => {
    assert.strictEqual(upTarget.summary.up, null);
  });

  const checkNow = await req('POST', '/api/monitor/check-now', vk);
  check('check-now force une sonde immediate malgre le grand intervalle configure (3600s)', () => {
    assert.strictEqual(checkNow.status, 200);
    const up = checkNow.body.targets.find(t => t.vhostName === 'mon-up.conf');
    const down = checkNow.body.targets.find(t => t.vhostName === 'mon-down.conf');
    assert.strictEqual(up.summary.up, true);
    assert.strictEqual(down.summary.up, false);
    assert.ok(down.summary.downSince);
  });
  check('sparkline (mini-historique pour la grille) reflete le dernier check de chaque cible', () => {
    const up = checkNow.body.targets.find(t => t.vhostName === 'mon-up.conf');
    const down = checkNow.body.targets.find(t => t.vhostName === 'mon-down.conf');
    assert.ok(Array.isArray(up.sparkline));
    assert.strictEqual(up.sparkline[up.sparkline.length - 1], true);
    assert.strictEqual(down.sparkline[down.sparkline.length - 1], false);
  });

  console.log('\ncode HTTP attendu configurable (# nginx-control-monitoring-valid-http-code)');
  check('regle par defaut : une reponse 500 est down (le bug signale — avant, seule l absence de reponse comptait)', () => {
    const t = checkNow.body.targets.find(x => x.vhostName === 'mon-default-5xx.conf');
    assert.strictEqual(t.summary.up, false);
  });
  check('regle par defaut : une reponse 404 reste up (seul le 5xx ou l absence de reponse est down par defaut)', () => {
    const t = checkNow.body.targets.find(x => x.vhostName === 'mon-default-404.conf');
    assert.strictEqual(t.summary.up, true);
  });
  check('surcharge "2xx, 3xx" : le meme 404 passe down (cas Traefik : conteneur arrete mais reponse HTTP quand meme)', () => {
    const t = checkNow.body.targets.find(x => x.vhostName === 'mon-strict-404.conf');
    assert.strictEqual(t.summary.up, false);
    assert.ok(/404/.test(t.summary.last.error || ''));
  });
  check('surcharge "4xx" : le meme backend 404 est cette fois considere up', () => {
    const t = checkNow.body.targets.find(x => x.vhostName === 'mon-allow-4xx.conf');
    assert.strictEqual(t.summary.up, true);
  });

  const history = await req('GET', `/api/monitor/history?key=${encodeURIComponent(upTarget.key)}`, vk);
  check('historique de la cible up : au moins un check ok:true', () => {
    assert.strictEqual(history.status, 200);
    assert.ok(history.body.history.length >= 1);
    assert.strictEqual(history.body.history[0].ok, true);
  });

  const downHistory = await req('GET', `/api/monitor/history?key=${encodeURIComponent(downTarget.key)}`, vk);
  check('historique de la cible down : un incident ouvert (endedAt null)', () => {
    assert.ok(downHistory.body.incidents.length >= 1);
    assert.strictEqual(downHistory.body.incidents[0].endedAt, null);
  });

  const badKey = await req('GET', '/api/monitor/history?key=inexistante', vk);
  check('cle de cible inconnue -> 400, pas une lecture arbitraire du store', () => assert.strictEqual(badKey.status, 400));

  const noKey = await req('GET', '/api/monitor/history', vk);
  check('cle absente -> 400', () => assert.strictEqual(noKey.status, 400));

  srv.kill();
  backend.close();
  backend404.close();
  backend500.close();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
