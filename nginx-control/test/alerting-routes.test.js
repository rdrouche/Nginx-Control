'use strict';
/**
 * Message important (features/alerting.js) — routes, contre un vrai
 * serveur. Un petit serveur HTTP local joue le role du fichier distant
 * (ALERTING_URL) — meme convention que proxy-cookie-leak.test.js/
 * changelog.test.js pour simuler "l exterieur" sans reseau reel.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alerting-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'alerting-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');
// alerting_enable: false est le defaut (opt-in) — active explicitement ici,
// ce fichier teste le comportement de la fonctionnalite elle-meme.
fs.writeFileSync(path.join(tmp, 'config', 'features.yml'), 'alerting_enable: true\n');

const ALERT_MD = [
  '## Maintenance planifiée',
  'ID: 1700000001',
  'LEVEL: warning',
  '',
  'Coupure **samedi** de 2h à 4h.',
  '',
  '## Alerte sans ID (doit être ignorée)',
  '',
  'Ce bloc ne doit jamais apparaître.',
  '',
  '## Nouvelle fonctionnalité',
  'ID: 1700000002',
  '',
  'Voir le [changelog](https://example.com/changelog).',
  '',
].join('\n');

(async () => {
  const alertSrv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(ALERT_MD);
  });
  await new Promise(r => alertSrv.listen(0, '127.0.0.1', r));
  const alertUrl = `http://127.0.0.1:${alertSrv.address().port}/alerts.md`;

  const PORT = 3925, BASE = `http://127.0.0.1:${PORT}`;
  const env = { ...process.env, PORT: String(PORT),
    USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
    DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
    DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
    DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
    DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip'),
    ALERTING_URL: alertUrl };

  function req(method, p, cookie, body) {
    return new Promise(resolve => {
      const data = body !== undefined ? JSON.stringify(body) : null;
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

  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 1500));

  console.log('\nroutes de features/alerting.js, contre un vrai serveur');
  const adminLogin = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  check('login admin ok', () => assert.strictEqual(adminLogin.status, 302));
  const ak = adminLogin.cookie, vk = viewerLogin.cookie;

  const noAuth = await req('GET', '/api/alerting/unread', '');
  check('sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));

  const unread0 = await req('GET', '/api/alerting/unread', vk);
  check('role viewer (VIEW_METRICS) peut lire -> 200, rien avant le premier cycle', () => {
    assert.strictEqual(unread0.status, 200);
    assert.strictEqual(unread0.body.configured, true);
    assert.strictEqual(unread0.body.enabled, true);
    assert.deepStrictEqual(unread0.body.alerts, []);
  });

  // VIEW_CONFIGS (pas ADMIN) : meme gating que /api/changelog — forcer une
  // relecture d un flux distant en lecture seule n a rien de sensible, le
  // role viewer l a deja pour le changelog.
  const refreshNoAuth = await req('POST', '/api/alerting/refresh', '');
  check('rafraichir sans session -> refuse', () => assert.ok([401, 403].includes(refreshNoAuth.status)));

  const refresh = await req('POST', '/api/alerting/refresh', vk);
  check('viewer rafraichit -> 2 alertes trouvees (la 3e, sans ID, est ignoree), 2 poussees', () => {
    assert.strictEqual(refresh.status, 200);
    assert.strictEqual(refresh.body.found, 2);
    assert.strictEqual(refresh.body.pushed, 2);
  });

  const unread1 = await req('GET', '/api/alerting/unread', vk);
  check('apres rafraichissement, les 2 alertes apparaissent en non-lues, plus recente d abord', () => {
    assert.strictEqual(unread1.body.alerts.length, 2);
    assert.strictEqual(unread1.body.alerts[0].externalId, '1700000002');
    assert.strictEqual(unread1.body.alerts[0].title, 'Nouvelle fonctionnalité');
    assert.strictEqual(unread1.body.alerts[1].externalId, '1700000001');
    assert.strictEqual(unread1.body.alerts[1].level, 'warning');
    assert.ok(unread1.body.alerts[1].body.includes('**samedi**'), 'le corps Markdown brut est conserve (rendu cote client)');
  });

  const refresh2 = await req('POST', '/api/alerting/refresh', ak);
  check('un second rafraichissement ne repousse pas les memes alertes (dedup par ID externe)', () => {
    assert.strictEqual(refresh2.body.pushed, 0);
  });

  const notifId = unread1.body.alerts[1].id;
  const markRead = await req('POST', `/api/notifications/${notifId}/read`, vk);
  check('marquer lu reutilise directement la route du centre de notification existant', () => {
    assert.strictEqual(markRead.status, 200);
  });

  const unread2 = await req('GET', '/api/alerting/unread', vk);
  check('l alerte marquee lue disparait de la liste des non-lues', () => {
    assert.strictEqual(unread2.body.alerts.length, 1);
    assert.strictEqual(unread2.body.alerts[0].externalId, '1700000002');
  });

  const history = await req('GET', '/api/alerting/history', vk);
  check('l historique complet (page Systeme) montre les 2, lue et non lue', () => {
    assert.strictEqual(history.body.alerts.length, 2);
    assert.strictEqual(history.body.alerts.filter(a => a.read).length, 1);
  });

  srv.kill('SIGTERM');
  alertSrv.close();
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
