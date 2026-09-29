'use strict';
/**
 * Auto-config Docker — routes, contre un vrai serveur. Le socket Docker n
 * est pas disponible dans ce bac a sable (dockerCall()/getContainerId()
 * degradent proprement a une liste vide — voir lib/docker.js), donc ces
 * tests portent sur ce qui NE depend PAS d un vrai conteneur : permissions,
 * persistance des decisions d approbation/rejet, et le fait qu un cycle sans
 * conteneur candidat ne casse jamais rien (skippedNoChange).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dockerautoconfig-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dockerautoconfig-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'), [
  'users:',
  '  - username: admin',
  '    password: admin123',
  '    role: admin',
  '    name: A',
  '    enabled: true',
  '  - username: viewer',
  '    password: viewer123',
  '    role: viewer',
  '    name: V',
  '    enabled: true',
].join('\n'));
// require_approval reste au defaut (true) — non ecrit ici, exactement le cas
// "operateur n a jamais touche au fichier" que le parseur doit couvrir.
// enable: false est desormais le defaut (v12.41.0, opt-in) — ce fichier
// teste le comportement de la fonctionnalite elle-meme, donc active
// explicitement ici (sans quoi tout deviendrait "disabled": true).
fs.writeFileSync(path.join(tmp, 'config', 'docker-autoconfig.yml'), 'enable: true\n');

const PORT = 3917, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip'),
  // Socket volontairement absent/invalide : le sous-systeme Docker doit
  // degrader proprement (liste de conteneurs vide), jamais planter le cycle.
  DOCKER_SOCKET: path.join(tmp, 'no-such-docker.sock') };

function req(method, p, auth, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = { ...(auth ? { Authorization: `Bearer ${auth}` } : {}),
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

/** Log in via the cookie flow and return the session cookie. */
function login(username, password) {
  return new Promise(resolve => {
    const params = new URLSearchParams({ username, password }).toString();
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(params) } },
      res => { res.resume(); resolve((res.headers['set-cookie'] || [])[0]?.split(';')[0] || ''); });
    r.write(params); r.end();
  });
}

function reqCookie(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    // Content-Type: application/json toujours envoye pour une methode non-GET
    // (fix SEC-12 : exige par le serveur pour toute requete authentifiee par
    // cookie), meme sans corps.
    const headers = { Cookie: cookie,
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

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  const adminCookie  = await login('admin', 'admin123');
  const viewerCookie = await login('viewer', 'viewer123');

  console.log('\npermissions');
  const noAuth = await req('GET', '/api/docker-autoconfig/status');
  check('sans authentification -> 401', () => assert.strictEqual(noAuth.status, 401));

  const viewerStatus = await reqCookie('GET', '/api/docker-autoconfig/status', viewerCookie);
  check('viewer (VIEW_CONFIGS) peut lire le statut -> 200', () => assert.strictEqual(viewerStatus.status, 200));

  const viewerRescan = await reqCookie('POST', '/api/docker-autoconfig/rescan', viewerCookie);
  check('viewer ne peut pas forcer un rescan (DEPLOY requis) -> 403', () => assert.strictEqual(viewerRescan.status, 403));

  const viewerApprove = await reqCookie('POST', '/api/docker-autoconfig/approve', viewerCookie, { serverName: 'x.example.com' });
  check('viewer ne peut pas approuver -> 403', () => assert.strictEqual(viewerApprove.status, 403));

  console.log('\naucun socket Docker dans ce bac a sable -> degrade proprement (fix v12.21.2, DAC-01)');
  // Fix v12.21.2 (audit finding DAC-01): an unreachable Docker socket is no
  // longer silently read as "zero candidate containers" — GET status (a
  // read-only route) still degrades to an empty list with the error
  // surfaced in `dockerError`, but POST rescan (which WRITES/DELETES vhost
  // files) now correctly reports failure instead of pretending there was
  // nothing to do, precisely so it never mistakes "Docker is unreachable"
  // for "every container is gone" and deletes every generated vhost.
  const status0 = await reqCookie('GET', '/api/docker-autoconfig/status', adminCookie);
  check('GET status -> 200, liste de conteneurs vide, erreur Docker surfacee (jamais un 500)', () => {
    assert.strictEqual(status0.status, 200);
    assert.deepStrictEqual(status0.body.containers, []);
    assert.ok(status0.body.dockerError, 'dockerError doit etre renseigne');
    assert.strictEqual(status0.body.settings.requireApproval, true, 'defaut securise sans fichier de config ecrit');
  });

  const rescan0 = await reqCookie('POST', '/api/docker-autoconfig/rescan', adminCookie);
  check('POST rescan sans Docker joignable -> ok:false, dockerUnreachable, aucun fichier touche', () => {
    assert.strictEqual(rescan0.status, 200);
    assert.strictEqual(rescan0.body.ok, false);
    assert.strictEqual(rescan0.body.dockerUnreachable, true);
  });

  console.log('\napprobation/rejet — persistance des decisions (independant d un vrai conteneur)');
  const approve = await reqCookie('POST', '/api/docker-autoconfig/approve', adminCookie, { serverName: 'app.example.com' });
  check('POST approve -> 200 (la decision est enregistree meme sans conteneur correspondant actuellement)', () => {
    assert.strictEqual(approve.status, 200);
  });
  const approveMissing = await reqCookie('POST', '/api/docker-autoconfig/approve', adminCookie, {});
  check('POST approve sans serverName -> 400', () => assert.strictEqual(approveMissing.status, 400));

  const reject = await reqCookie('POST', '/api/docker-autoconfig/reject', adminCookie, { serverName: 'app.example.com' });
  check('POST reject -> 200', () => assert.strictEqual(reject.status, 200));
  const rejectMissing = await reqCookie('POST', '/api/docker-autoconfig/reject', adminCookie, {});
  check('POST reject sans serverName -> 400', () => assert.strictEqual(rejectMissing.status, 400));

  console.log('\nv12.35.0 : la decision est visible dans GET status meme sans conteneur correspondant, et revocable');
  const approve2 = await reqCookie('POST', '/api/docker-autoconfig/approve', adminCookie, { serverNames: ['stopped.example.com'] });
  check('approve d un server_name sans conteneur vivant -> 200', () => assert.strictEqual(approve2.status, 200));
  const statusAfterApprove = await reqCookie('GET', '/api/docker-autoconfig/status', adminCookie);
  check('la decision apparait dans `decisions`, avec hasLiveContainer:false (conteneur "arrete"/absent)', () => {
    const d = (statusAfterApprove.body.decisions || []).find(x => x.names.includes('stopped.example.com'));
    assert.ok(d, 'decision introuvable dans la liste');
    assert.strictEqual(d.decision, 'approved');
    assert.strictEqual(d.hasLiveContainer, false);
    assert.strictEqual(d.paused, false);
  });

  console.log('\nv12.35.0 : pause/reprise d une publication approuvee');
  const pauseNotApproved = await reqCookie('POST', '/api/docker-autoconfig/pause', adminCookie, { serverNames: ['jamais-approuve.example.com'] });
  check('pause sur un server_name jamais approuve -> 400', () => assert.strictEqual(pauseNotApproved.status, 400));

  const pauseOk = await reqCookie('POST', '/api/docker-autoconfig/pause', adminCookie, { serverNames: ['stopped.example.com'] });
  check('pause sur une decision approuvee -> 200', () => assert.strictEqual(pauseOk.status, 200));
  const statusAfterPause = await reqCookie('GET', '/api/docker-autoconfig/status', adminCookie);
  check('la decision reste "approved" mais paused:true, avec pausedBy renseigne', () => {
    const d = (statusAfterPause.body.decisions || []).find(x => x.names.includes('stopped.example.com'));
    assert.strictEqual(d.decision, 'approved');
    assert.strictEqual(d.paused, true);
    assert.strictEqual(d.pausedBy, 'admin');
    assert.ok(d.pausedAt);
  });

  const resumeOk = await reqCookie('POST', '/api/docker-autoconfig/resume', adminCookie, { serverNames: ['stopped.example.com'] });
  check('resume -> 200', () => assert.strictEqual(resumeOk.status, 200));
  const statusAfterResume = await reqCookie('GET', '/api/docker-autoconfig/status', adminCookie);
  check('paused revient a false, decision toujours approved', () => {
    const d = (statusAfterResume.body.decisions || []).find(x => x.names.includes('stopped.example.com'));
    assert.strictEqual(d.decision, 'approved');
    assert.strictEqual(d.paused, false);
  });
  const resumeAlready = await reqCookie('POST', '/api/docker-autoconfig/resume', adminCookie, { serverNames: ['stopped.example.com'] });
  check('resume sur une decision deja active (pas en pause) -> 400', () => assert.strictEqual(resumeAlready.status, 400));

  console.log('\nv12.35.0 : suppression (revocation) d une decision — le probleme signale par l utilisateur');
  const removeMissing = await reqCookie('POST', '/api/docker-autoconfig/decisions/remove', adminCookie, { serverNames: ['inconnu.example.com'] });
  check('suppression d une decision qui n existe pas -> 404', () => assert.strictEqual(removeMissing.status, 404));

  const removeOk = await reqCookie('POST', '/api/docker-autoconfig/decisions/remove', adminCookie, { serverNames: ['stopped.example.com'] });
  check('suppression d une decision existante -> 200', () => assert.strictEqual(removeOk.status, 200));
  const statusAfterRemove = await reqCookie('GET', '/api/docker-autoconfig/status', adminCookie);
  check('la decision a bien disparu de `decisions` apres suppression', () => {
    const d = (statusAfterRemove.body.decisions || []).find(x => x.names.includes('stopped.example.com'));
    assert.strictEqual(d, undefined);
  });

  console.log('\npermissions sur les nouvelles routes (DEPLOY requis, pas VIEW_CONFIGS seul)');
  const viewerPause = await reqCookie('POST', '/api/docker-autoconfig/pause', viewerCookie, { serverNames: ['x.example.com'] });
  check('viewer ne peut pas mettre en pause -> 403', () => assert.strictEqual(viewerPause.status, 403));
  const viewerResume = await reqCookie('POST', '/api/docker-autoconfig/resume', viewerCookie, { serverNames: ['x.example.com'] });
  check('viewer ne peut pas reprendre -> 403', () => assert.strictEqual(viewerResume.status, 403));
  const viewerRemove = await reqCookie('POST', '/api/docker-autoconfig/decisions/remove', viewerCookie, { serverNames: ['x.example.com'] });
  check('viewer ne peut pas revoquer une decision -> 403', () => assert.strictEqual(viewerRemove.status, 403));

  console.log('\naucun fichier sites/ n est cree sans conteneur reel labellise');
  check('DIR_SITES reste vide apres tous ces cycles', () => {
    const files = fs.readdirSync(path.join(tmp, 'sites'));
    assert.deepStrictEqual(files, []);
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
