'use strict';
/**
 * Routes du centre de notification (features/notification-center.js) contre
 * un vrai serveur — meme convention que monitor-routes.test.js. Comme il n y
 * a pas de moyen simple de declencher un vrai push depuis l exterieur du
 * serveur (pushNotification() est appele en interne par d autres modules),
 * ce test verifie la permission (VIEW_METRICS, ouverte a tous les roles) et
 * la mecanique CRUD elle-meme : la liste demarre vide, faute d evenement
 * reel ayant eu l occasion de se produire pendant le test.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'notifroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'notifroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3913, BASE = `http://127.0.0.1:${PORT}`;
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
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  console.log('\nroutes du centre de notification, contre un vrai serveur');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  const ak = adminLogin.cookie, vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/notifications', '');
  check('liste sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const list0 = await req('GET', '/api/notifications', vk);
  check('role viewer (VIEW_METRICS) peut lister -> 200, liste vide au demarrage', () => {
    assert.strictEqual(list0.status, 200);
    assert.deepStrictEqual(list0.body.notifications, []);
    assert.strictEqual(list0.body.unreadCount, 0);
  });

  const unread0 = await req('GET', '/api/notifications/unread-count', vk);
  check('unread-count -> 0 au demarrage', () => assert.strictEqual(unread0.body.unreadCount, 0));

  // Pas de route pour injecter une notification depuis l exterieur (par
  // conception : seul pushNotification() cote serveur le fait) — les
  // actions de mutation sont donc verifiees pour leur permission et leur
  // resilience sur un id inexistant plutot que sur un vrai cycle de vie.
  const markOneUnknown = await req('POST', '/api/notifications/999999/read', vk);
  check('marquer lu un id inexistant -> 200 ok:true quand meme (idempotent, pas une 404 fantaisiste)', () => {
    assert.strictEqual(markOneUnknown.status, 200);
    assert.strictEqual(markOneUnknown.body.ok, true);
  });

  const deleteUnknown = await req('DELETE', '/api/notifications/999999', vk);
  check('supprimer un id inexistant -> 200 ok:true (idempotent)', () => assert.strictEqual(deleteUnknown.status, 200));

  const badId = await req('POST', '/api/notifications/not-a-number/read', vk);
  check('id non numerique -> 404, jamais interprete comme une action', () => assert.strictEqual(badId.status, 404));

  const readAll = await req('POST', '/api/notifications/read-all', vk);
  check('read-all -> 200 ok:true', () => assert.strictEqual(readAll.status, 200));

  const clearRead = await req('POST', '/api/notifications/clear-read', vk);
  check('clear-read -> 200 ok:true', () => assert.strictEqual(clearRead.status, 200));

  const clearAll = await req('POST', '/api/notifications/clear', vk);
  check('clear -> 200 ok:true', () => assert.strictEqual(clearAll.status, 200));

  const adminList = await req('GET', '/api/notifications', ak);
  check('meme surface accessible avec une session admin (VIEW_METRICS commun aux deux roles)', () => {
    assert.strictEqual(adminList.status, 200);
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
