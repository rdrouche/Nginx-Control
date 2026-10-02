'use strict';
/**
 * Fixes, audit report Basse/"Sécurité et durcissement" :
 *  - webhooks : aucun filtre anti-SSRF sur l URL (server.js:624 a l epoque
 *    du rapport) — lib/ssrf-guard.js ajoute une verification a la creation
 *    ET a l envoi (contre le DNS rebinding, via l option `lookup`) ;
 *  - webhooks : mass-assignment sur PUT (`Object.assign(webhook, body)`)
 *    permettait d ecraser n importe quel champ, y compris `id`/`createdAt`/
 *    `fireCount`/`lastFired`.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const dns = require('dns');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/ssrf-guard.js — unites');
const { isBlockedIp, safeLookup } = require('../lib/ssrf-guard');

check('isBlockedIp() : loopback (127.0.0.1) bloque', () => assert.strictEqual(isBlockedIp('127.0.0.1'), true));
check('isBlockedIp() : lien-local / metadonnees cloud (169.254.169.254) bloque', () => assert.strictEqual(isBlockedIp('169.254.169.254'), true));
check('isBlockedIp() : RFC1918 (10.x, 172.16-31.x, 192.168.x) bloques', () => {
  assert.strictEqual(isBlockedIp('10.0.0.5'), true);
  assert.strictEqual(isBlockedIp('172.20.0.5'), true);
  assert.strictEqual(isBlockedIp('192.168.1.5'), true);
});
check('isBlockedIp() : IPv6 loopback/ULA/lien-local bloques', () => {
  assert.strictEqual(isBlockedIp('::1'), true);
  assert.strictEqual(isBlockedIp('fc00::1'), true);
  assert.strictEqual(isBlockedIp('fe80::1'), true);
});
check('isBlockedIp() : IPv4-mappe en IPv6 (::ffff:127.0.0.1) bloque aussi', () => {
  assert.strictEqual(isBlockedIp('::ffff:127.0.0.1'), true);
});
check('isBlockedIp() : une IP publique ordinaire n est pas bloquee', () => {
  assert.strictEqual(isBlockedIp('8.8.8.8'), false);
  assert.strictEqual(isBlockedIp('93.184.216.34'), false);
});

console.log('\nsafeLookup() — utilisable comme option `lookup` de http.request');
(() => {
  const fakeDns = (hostname, options, cb) => cb(null, '127.0.0.1', 4);
  const origLookup = dns.lookup;
  dns.lookup = fakeDns;
  safeLookup('internal.example', {}, (err) => {
    check('une resolution vers une IP privee est refusee', () => {
      assert.ok(err, 'safeLookup aurait du refuser 127.0.0.1');
    });
    dns.lookup = origLookup;
  });
})();

console.log('\ncontre un vrai serveur : creation/edition de webhook');
(async () => {
  const root = path.join(__dirname, '..');
  const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssrf-app-'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssrf-data-'));
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

  function req(method, p, cookie, body) {
    return new Promise(resolve => {
      const data = body !== undefined ? JSON.stringify(body) : null;
      const headers = { ...(cookie ? { Cookie: cookie } : {}),
        ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) };
      const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers, timeout: 8000 }, res => {
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
  const { cookie } = await login('admin', 'admin123');

  const badSsrf = await req('POST', '/api/webhooks', cookie, { url: 'http://127.0.0.1:9999/internal' });
  check('creation d un webhook pointant vers 127.0.0.1 refusee (anti-SSRF)', () => {
    assert.strictEqual(badSsrf.status, 400);
  });
  const badMeta = await req('POST', '/api/webhooks', cookie, { url: 'http://169.254.169.254/latest/meta-data/' });
  check('creation d un webhook pointant vers l adresse de metadonnees cloud refusee', () => {
    assert.strictEqual(badMeta.status, 400);
  });

  const good = await req('POST', '/api/webhooks', cookie, { url: 'http://93.184.216.34/hook', description: 'ok' });
  check('creation d un webhook vers une IP publique acceptee (pas de regression)', () => {
    assert.strictEqual(good.status, 201);
  });
  const whId = good.body.id;
  const createdAtBefore = good.body.createdAt;
  // Note : un nouveau webhook s abonne par defaut a tous les evenements
  // ('*'), donc son propre evenement "webhook.created" le declenche aussitot
  // — fireCount peut deja valoir 1 ici, pas 0. Ce n est pas ce que ce test
  // verifie : ce qui compte est qu un PUT ne puisse pas FORGER une valeur
  // arbitraire (999999) pour ce champ.
  const fireCountBefore = good.body.fireCount;

  const massAssign = await req('PUT', `/api/webhooks/${whId}`, cookie, {
    id: 'wh_hacked', createdAt: '1999-01-01T00:00:00.000Z', fireCount: 999999, lastFired: '2099-01-01T00:00:00.000Z',
    description: 'nouvelle description',
  });
  check('PUT accepte (200) et applique bien les champs editables (description)', () => {
    assert.strictEqual(massAssign.status, 200);
    assert.strictEqual(massAssign.body.description, 'nouvelle description');
  });
  check('mass-assignment : id/createdAt/fireCount/lastFired ne sont PAS ecrasables via PUT', () => {
    assert.strictEqual(massAssign.body.id, whId, 'l id a ete modifie par le corps de la requete');
    assert.strictEqual(massAssign.body.createdAt, createdAtBefore, 'createdAt a ete modifie par le corps de la requete');
    assert.strictEqual(massAssign.body.fireCount, fireCountBefore, 'fireCount a ete falsifie par le corps de la requete');
    assert.notStrictEqual(massAssign.body.lastFired, '2099-01-01T00:00:00.000Z', 'lastFired a ete falsifie par le corps de la requete');
  });

  const putSsrf = await req('PUT', `/api/webhooks/${whId}`, cookie, { url: 'http://10.0.0.1/internal' });
  check('PUT vers une IP privee refuse aussi (pas seulement la creation)', () => {
    assert.strictEqual(putSsrf.status, 400);
  });

  srv.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
