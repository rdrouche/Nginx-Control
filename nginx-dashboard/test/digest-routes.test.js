'use strict';
/**
 * Routes API du digest (features/digest.js), verifiees contre un vrai
 * serveur — meme convention que test/branding-injection.test.js : plus
 * fiable qu un mock de Router pour confirmer que /api/digest/latest et
 * /api/digest/history (routes exactes) priment bien sur /api/digest/
 * (route a prefixe, pour un id numerique) au lieu de se faire piquer la
 * priorite l une l autre.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'digestroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'digestroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3897, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache') };

function req(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body ? JSON.stringify(body) : null;
    // Content-Type: application/json toujours envoye pour une methode non-GET
    // (fix SEC-12 : le serveur l exige desormais), meme sans corps.
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

  console.log('\nroutes du digest, contre un vrai serveur');
  check('login ok', () => assert.strictEqual(login.status, 302));

  const empty = await req('GET', '/api/digest/latest', ck);
  check('latest avant toute generation -> digest: null, pas une erreur', () => {
    assert.strictEqual(empty.status, 200);
    assert.strictEqual(empty.body.digest, null);
  });

  const emptyHist = await req('GET', '/api/digest/history', ck);
  check('history avant generation -> tableau vide', () => {
    assert.deepStrictEqual(emptyHist.body.digests, []);
  });

  const gen = await req('POST', '/api/digest/generate?period_hours=24', ck);
  check('generation manuelle reussie', () => {
    assert.strictEqual(gen.status, 200);
    assert.ok(gen.body.digest.id > 0);
    assert.strictEqual(gen.body.digest.periodHours, 24);
  });

  const latestAfter = await req('GET', '/api/digest/latest', ck);
  check('latest reflete la generation manuelle', () => {
    assert.strictEqual(latestAfter.body.digest.id, gen.body.digest.id);
  });

  const hist = await req('GET', '/api/digest/history', ck);
  check('history liste bien le digest genere, sans son contenu complet', () => {
    assert.strictEqual(hist.body.digests.length, 1);
    assert.strictEqual(hist.body.digests[0].content, undefined);
  });

  const byId = await req('GET', `/api/digest/${gen.body.digest.id}`, ck);
  check('recuperation par id (route a prefixe) fonctionne, sans etre masquee par /latest ou /history', () => {
    assert.strictEqual(byId.status, 200);
    assert.strictEqual(byId.body.digest.id, gen.body.digest.id);
  });

  const notFound = await req('GET', '/api/digest/999999', ck);
  check('id inconnu -> 404, pas une exception', () => assert.strictEqual(notFound.status, 404));

  const badId = await req('GET', '/api/digest/pas-un-nombre', ck);
  check('id non numerique -> 400, pas une exception', () => assert.strictEqual(badId.status, 400));

  const noAuth = await req('GET', '/api/digest/latest', '');
  check('sans session -> refuse, pas une fuite de donnees', () => assert.ok([401, 403].includes(noAuth.status)));

  console.log('\nsuppression manuelle (/api/digest/remove)');
  const removeNoId = await req('POST', '/api/digest/remove', ck, {});
  check('sans id -> 400, pas une exception', () => assert.strictEqual(removeNoId.status, 400));

  const removeUnknown = await req('POST', '/api/digest/remove', ck, { id: 999999 });
  check('id inconnu -> ok:false plutot qu une erreur (rien a supprimer)', () => {
    assert.strictEqual(removeUnknown.status, 200);
    assert.strictEqual(removeUnknown.body.ok, false);
  });

  const removed = await req('POST', '/api/digest/remove', ck, { id: gen.body.digest.id });
  check('suppression reelle -> ok:true', () => {
    assert.strictEqual(removed.status, 200);
    assert.strictEqual(removed.body.ok, true);
  });

  const afterRemove = await req('GET', `/api/digest/${gen.body.digest.id}`, ck);
  check('le digest supprime n existe plus (404)', () => assert.strictEqual(afterRemove.status, 404));

  const histAfterRemove = await req('GET', '/api/digest/history', ck);
  check('l historique ne le liste plus non plus', () => {
    assert.deepStrictEqual(histAfterRemove.body.digests, []);
  });

  const removeNoAuth = await req('POST', '/api/digest/remove', '', { id: 1 });
  check('sans session -> refuse', () => assert.ok([401, 403].includes(removeNoAuth.status)));

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
