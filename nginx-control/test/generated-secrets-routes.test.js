'use strict';
/**
 * v12.32.0 (demande utilisateur) : API_TOKEN et WEBHOOK_SECRET generables
 * depuis l'interface (page Systeme) plutot que seulement via .env.
 *
 *  - API_TOKEN : seule son EMPREINTE (scrypt) est persistee — jamais la
 *    valeur en clair — puisque le dashboard ne fait que VERIFIER un jeton
 *    presente, il n'a jamais besoin de le relire.
 *  - WEBHOOK_SECRET : persiste EN CLAIR (fichier 0600), puisque le dashboard
 *    doit au contraire l'ENVOYER a chaque webhook sortant.
 *
 * Contre un vrai serveur, meme convention que test/system-info-routes.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gensecrets-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gensecrets-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3934;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };
delete env.API_TOKEN; delete env.WEBHOOK_SECRET;

function req(method, p, { cookie, bearer, body } = {}) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
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
  await new Promise(r => setTimeout(r, 2000));

  const adminLogin  = await login('admin', 'admin123');
  const viewerLogin = await login('viewer', 'viewer123');
  const ck = adminLogin.cookie, vk = viewerLogin.cookie;

  console.log('\nAPI_TOKEN genere depuis l interface : reserve aux admins, empreinte seule persistee, verifiable, revocable');
  const forbidden1 = await req('POST', '/api/system-info/generate-api-token', {});
  check('sans session -> refuse', () => assert.ok([401, 403].includes(forbidden1.status)));
  const forbidden2 = await req('POST', '/api/system-info/generate-api-token', { cookie: vk });
  check('role viewer -> refuse', () => assert.ok([401, 403].includes(forbidden2.status)));

  const beforeGen = await req('GET', '/api/system-info', { cookie: ck });
  const apiTokenEntryBefore = beforeGen.body.categories.flatMap(c => c.entries).find(e => e.key === 'API_TOKEN');
  check('avant generation : API_TOKEN ressort a false (aucune valeur en env dans ce test)', () => assert.strictEqual(apiTokenEntryBefore.value, false));

  const gen = await req('POST', '/api/system-info/generate-api-token', { cookie: ck });
  check('generation -> 200 avec le jeton en clair (affiche une seule fois)', () => {
    assert.strictEqual(gen.status, 200);
    assert.ok(typeof gen.body.token === 'string' && gen.body.token.length >= 32);
  });
  const generatedToken = gen.body.token;

  check('config/.generated-secrets.json ne contient jamais le jeton en clair, seulement son empreinte scrypt', () => {
    const onDisk = fs.readFileSync(path.join(tmp, 'config', '.generated-secrets.json'), 'utf8');
    assert.ok(!onDisk.includes(generatedToken));
    assert.ok(/apiTokenHash.*scrypt:/.test(onDisk));
  });

  const withGeneratedToken = await req('GET', '/api/system-info', { bearer: generatedToken });
  check('le jeton genere authentifie bien un appel API (Bearer) apres coup', () => assert.strictEqual(withGeneratedToken.status, 200));

  const withWrongToken = await req('GET', '/api/system-info', { bearer: 'ceci-nest-pas-le-bon-jeton-du-tout-0000000000' });
  check('un jeton incorrect est toujours refuse', () => assert.ok([401, 403].includes(withWrongToken.status)));

  const afterGen = await req('GET', '/api/system-info', { cookie: ck });
  const apiTokenEntryAfter = afterGen.body.categories.flatMap(c => c.entries).find(e => e.key === 'API_TOKEN');
  check('apres generation : API_TOKEN ressort a true sans redemarrage', () => assert.strictEqual(apiTokenEntryAfter.value, true));

  const revoke = await req('POST', '/api/system-info/revoke-api-token', { cookie: ck });
  check('revocation -> 200', () => assert.strictEqual(revoke.status, 200));
  const afterRevoke = await req('GET', '/api/system-info', { bearer: generatedToken });
  check('apres revocation, l ancien jeton ne fonctionne plus', () => assert.ok([401, 403].includes(afterRevoke.status)));

  console.log('\nWEBHOOK_SECRET genere depuis l interface : reserve aux admins, persiste en clair (il doit etre renvoye), revocable');
  const genWh = await req('POST', '/api/system-info/generate-webhook-secret', { cookie: ck });
  check('generation -> 200 avec le secret en clair (affiche une seule fois)', () => {
    assert.strictEqual(genWh.status, 200);
    assert.ok(typeof genWh.body.secret === 'string' && genWh.body.secret.length >= 32);
  });
  check('persiste en clair dans config/.generated-secrets.json (il doit pouvoir etre renvoye tel quel)', () => {
    const onDisk = fs.readFileSync(path.join(tmp, 'config', '.generated-secrets.json'), 'utf8');
    assert.ok(onDisk.includes(genWh.body.secret));
  });
  const afterWhGen = await req('GET', '/api/system-info', { cookie: ck });
  const whEntry = afterWhGen.body.categories.flatMap(c => c.entries).find(e => e.key === 'WEBHOOK_SECRET');
  check('apres generation : WEBHOOK_SECRET ressort a true sans redemarrage', () => assert.strictEqual(whEntry.value, true));

  const revokeWh = await req('POST', '/api/system-info/revoke-webhook-secret', { cookie: ck });
  check('revocation -> 200', () => assert.strictEqual(revokeWh.status, 200));
  const afterWhRevoke = await req('GET', '/api/system-info', { cookie: ck });
  const whEntryAfter = afterWhRevoke.body.categories.flatMap(c => c.entries).find(e => e.key === 'WEBHOOK_SECRET');
  check('apres revocation : WEBHOOK_SECRET ressort a false', () => assert.strictEqual(whEntryAfter.value, false));

  srv.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(appDir, { recursive: true, force: true });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
