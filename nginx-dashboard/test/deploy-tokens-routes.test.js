'use strict';
/**
 * Deploy tokens against a real server — the property that actually matters
 * is enforced across TWO files and must be tested together: lib/auth.js's
 * authenticateDeployToken() grants role 'deploy_ci' (PERMS.DEPLOY), but
 * server.js's dispatch only ever calls it for DEPLOY_TOKEN_ROUTES. A deploy
 * token must therefore:
 *   1. work on the git/backup routes it's scoped for,
 *   2. get a clean 403 (not silently ignored) on an action its own
 *      `actions` allowlist excludes,
 *   3. NEVER authenticate at all on any route outside that fixed allowlist —
 *      this is the actual containment: a leaked deploy token is not a
 *      "reduced admin", it is unable to reach anything else, period.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deploytokenroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deploytokenroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
fs.writeFileSync(path.join(tmp, 'config', 'deploy-tokens.yml'), [
  'tokens:',
  '  - name: full-access',
  '    token: "full-access-secret-0001"',
  '    enable: true',
  '  - name: test-only',
  '    token: "test-only-secret-00002"',
  '    enable: true',
  '    actions: [test]',
  '  - name: disabled-token',
  '    token: "disabled-secret-000003"',
  '    enable: false',
].join('\n'));

const PORT = 3916, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

function req(method, p, token, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) };
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

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  console.log('\nsans jeton, ou jeton invalide/desactive');
  const noAuth = await req('POST', '/api/git/pull');
  check('POST /api/git/pull sans jeton -> 401', () => assert.strictEqual(noAuth.status, 401));

  const badToken = await req('POST', '/api/git/pull', 'ceci-nexiste-pas');
  check('jeton inconnu -> 401', () => assert.strictEqual(badToken.status, 401));

  const disabledTok = await req('POST', '/api/git/pull', 'disabled-secret-000003');
  check('jeton desactive -> 401, jamais authentifie', () => assert.strictEqual(disabledTok.status, 401));

  console.log('\njeton complet (toutes actions) — autorise sur les routes de son perimetre');
  const pullOk = await req('POST', '/api/git/pull', 'full-access-secret-0001');
  check('POST /api/git/pull -> passe l autorisation (pas 401/403 ; 400 attendu, GIT_REPO_URL absent)', () => {
    assert.ok(![401, 403].includes(pullOk.status), `status inattendu : ${pullOk.status}`);
  });

  const statusOk = await req('GET', '/api/git/status', 'full-access-secret-0001');
  check('GET /api/git/status -> 200, configured:false (pas de depot configure)', () => {
    assert.strictEqual(statusOk.status, 200);
    assert.strictEqual(statusOk.body.configured, false);
  });

  const backupOk = await req('POST', '/api/backups', 'full-access-secret-0001', { mode: 'local', label: 'ci-test' });
  check('POST /api/backups (mode local) -> 201, sauvegarde reellement creee', () => {
    assert.strictEqual(backupOk.status, 201);
    assert.strictEqual(backupOk.body.ok, true);
  });

  console.log('\njeton restreint a une seule action ("test") — refuse sur tout le reste');
  const restrictedDeploy = await req('POST', '/api/git/deploy', 'test-only-secret-00002');
  check('POST /api/git/deploy avec un jeton limite a "test" -> 403 (action hors perimetre)', () => {
    assert.strictEqual(restrictedDeploy.status, 403);
  });
  const restrictedPull = await req('POST', '/api/git/pull', 'test-only-secret-00002');
  check('POST /api/git/pull avec un jeton limite a "test" -> 403', () => {
    assert.strictEqual(restrictedPull.status, 403);
  });
  const restrictedBackup = await req('POST', '/api/backups', 'test-only-secret-00002', { mode: 'local' });
  check('POST /api/backups avec un jeton limite a "test" -> 403', () => {
    assert.strictEqual(restrictedBackup.status, 403);
  });
  const restrictedTest = await req('POST', '/api/git/test', 'test-only-secret-00002');
  check('POST /api/git/test avec un jeton limite a "test" -> passe l autorisation (pas 401/403)', () => {
    assert.ok(![401, 403].includes(restrictedTest.status), `status inattendu : ${restrictedTest.status}`);
  });

  console.log('\nconfinement structurel : un jeton de deploiement n authentifie JAMAIS une route hors perimetre');
  const outOfScope1 = await req('GET', '/api/config-editor/files', 'full-access-secret-0001');
  check('GET /api/config-editor/files avec le jeton "toutes actions" -> 401, jamais authentifie', () => {
    assert.strictEqual(outOfScope1.status, 401);
  });
  const outOfScope2 = await req('GET', '/api/auth/users', 'full-access-secret-0001');
  check('GET /api/auth/users avec le jeton "toutes actions" -> 401, jamais authentifie', () => {
    assert.strictEqual(outOfScope2.status, 401);
  });
  const outOfScope3 = await req('POST', '/api/backups/restore', 'full-access-secret-0001', { name: 'x.zip' });
  check('POST /api/backups/restore (destructeur, hors liste) -> 401, jamais authentifie meme avec le jeton complet', () => {
    assert.strictEqual(outOfScope3.status, 401);
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
