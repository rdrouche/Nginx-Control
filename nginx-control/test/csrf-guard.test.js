'use strict';
/**
 * Garde CSRF sur les requetes authentifiees par cookie (fix, audit finding
 * SEC-12) — contre un vrai serveur, meme convention que
 * notification-center-routes.test.js.
 *
 * SameSite=Strict bloque deja la plupart des requetes intersites qui
 * portent le cookie, mais SameSite protege le domaine enregistrable, pas
 * l origine exacte : un sous-domaine malveillant ou compromis servi par ce
 * MEME reverse proxy (meme domaine enregistrable, origine differente)
 * recoit quand meme le cookie. Ce test verifie les deux gardes ajoutees
 * pour ce cas precis : Content-Type obligatoire, et Origin/Referer qui, une
 * fois presents, doivent correspondre au Host de la requete.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'csrf-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csrf-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3921, API_TOKEN = 'test-bearer-token-0123456789abcdef0123456789';
const env = { ...process.env, PORT: String(PORT), API_TOKEN,
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

/** Requete brute — AUCUN Content-Type/Origin ajoute automatiquement, contrairement
 *  aux autres suites de tests : c est precisement ce que ce fichier veut controler. */
function rawReq(method, p, { cookie, bearer, contentType, origin, referer, body } = {}) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (contentType !== undefined) headers['Content-Type'] = contentType;
    if (origin) headers.Origin = origin;
    if (referer) headers.Referer = referer;
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers, timeout: 5000 }, res => {
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

  const { cookie } = await login('admin', 'admin123');
  console.log('\ngarde CSRF (fix SEC-12) sur les requetes authentifiees par cookie');
  check('login admin ok', () => assert.ok(cookie));

  const withoutCt = await rawReq('POST', '/api/webhooks', { cookie, body: { url: 'http://x' } });
  check('cookie + methode non-GET SANS Content-Type -> refuse (403)', () => assert.strictEqual(withoutCt.status, 403));

  const wrongCt = await rawReq('POST', '/api/webhooks', { cookie, contentType: 'text/plain', body: { url: 'http://x' } });
  check('cookie + Content-Type text/plain (requete "simple", pas de preflight CORS) -> refuse (403)', () => assert.strictEqual(wrongCt.status, 403));

  const formCt = await rawReq('POST', '/api/webhooks', { cookie, contentType: 'application/x-www-form-urlencoded', body: { url: 'http://x' } });
  check('cookie + Content-Type form-urlencoded (le cas d un <form> intersite) -> refuse (403)', () => assert.strictEqual(formCt.status, 403));

  const badOrigin = await rawReq('POST', '/api/webhooks', { cookie, contentType: 'application/json', origin: 'http://attacker.example', body: { url: 'http://x' } });
  check('cookie + JSON + Origin different du Host -> refuse (403)', () => assert.strictEqual(badOrigin.status, 403));

  const badReferer = await rawReq('POST', '/api/webhooks', { cookie, contentType: 'application/json', referer: 'http://attacker.example/evil.html', body: { url: 'http://x' } });
  check('cookie + JSON + Referer different du Host (pas d Origin) -> refuse (403)', () => assert.strictEqual(badReferer.status, 403));

  const goodOrigin = await rawReq('POST', '/api/webhooks', { cookie, contentType: 'application/json', origin: `http://127.0.0.1:${PORT}`, body: { url: 'http://x', events: ['auth.login'] } });
  check('cookie + JSON + Origin identique au Host -> accepte', () => assert.ok([200, 201].includes(goodOrigin.status), `status inattendu : ${goodOrigin.status} ${JSON.stringify(goodOrigin.body)}`));

  const noOriginAtAll = await rawReq('DELETE', `/api/webhooks/${goodOrigin.body && goodOrigin.body.id}`, { cookie, contentType: 'application/json' });
  check('cookie + JSON + aucun Origin/Referer du tout (navigateur qui n en envoie pas) -> accepte (pas de faux positif)', () => {
    assert.ok([200, 204].includes(noOriginAtAll.status), `status inattendu : ${noOriginAtAll.status} ${JSON.stringify(noOriginAtAll.body)}`);
  });

  console.log('\nauth par jeton (Authorization: Bearer) : jamais concernee par la garde CSRF');
  const bearerNoCt = await rawReq('GET', '/api/auth/me', { bearer: API_TOKEN });
  check('Bearer sans Content-Type sur un GET -> inchange (200)', () => assert.strictEqual(bearerNoCt.status, 200));
  const bearerPostWrongCt = await rawReq('POST', '/api/webhooks', { bearer: API_TOKEN, contentType: 'text/plain', origin: 'http://attacker.example', body: { url: 'http://y' } });
  check('Bearer + Content-Type quelconque + Origin quelconque sur un POST -> jamais bloque par la garde CSRF (l Authorization n est jamais attachee automatiquement par un navigateur)', () => {
    assert.notStrictEqual(bearerPostWrongCt.status, 403);
  });

  const noAuthAtAll = await rawReq('POST', '/api/webhooks', { contentType: 'application/json', body: { url: 'http://x' } });
  check('aucune authentification du tout -> 401, pas 403 (l absence de session prime sur la garde CSRF)', () => assert.strictEqual(noAuthAtAll.status, 401));

  srv.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
