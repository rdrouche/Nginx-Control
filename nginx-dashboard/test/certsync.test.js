'use strict';
/**
 * v12.59.0 — synchronisation de certificats : controles du certificat recu,
 * installation atomique + retour arriere, modes TLS (verifie / CA privee /
 * empreinte / sans verification), jetons scopes, pull et push de bout en bout
 * contre un vrai serveur HTTPS auto-signe.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), https = require('https'), cp = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csync-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
process.env.DIR_CERTS = path.join(dir, 'certs');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
fs.mkdirSync(process.env.DIR_CERTS, { recursive: true });
const events = require('../lib/events');
events.initEventsDb();
const core = require('../lib/certsync-core');
const store = require('../lib/certsync-store');
const client = require('../lib/certsync-http');
const auth = require('../lib/auth');
const feature = require('../features/certsync');
const CERTS = process.env.DIR_CERTS;

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function mkCert(cn, { days = 60, ca } = {}) {
  const d = fs.mkdtempSync(path.join(dir, 'k-'));
  const k = path.join(d, 'k.pem'), c = path.join(d, 'c.pem');
  const base = ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', k, '-out', c, '-days', String(days), '-subj', `/CN=${cn}`, '-addext', `subjectAltName=DNS:${cn},DNS:*.${cn},IP:127.0.0.1`];
  cp.execFileSync('openssl', base, { stdio: 'ignore' });
  return { cert: fs.readFileSync(c, 'utf8'), key: fs.readFileSync(k, 'utf8') };
}
function putLive(name, b) {
  const d = path.join(CERTS, 'live', name); fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'fullchain.pem'), b.cert); fs.writeFileSync(path.join(d, 'privkey.pem'), b.key);
}

const routes = {};
feature.register({ get: (p, h) => { routes['GET ' + p] = h; }, post: (p, h) => { routes['POST ' + p] = h; } });
let nginx = { test: [], reload: [], failTest: false, failReload: false };
feature.setDeps({
  nginxTest: async () => { nginx.test.push(1); if (nginx.failTest) throw new Error('emerg: boom'); },
  nginxReload: async () => { nginx.reload.push(1); if (nginx.failReload) throw new Error('reload down'); },
});
const callAdmin = async (method, p, body = {}) => {
  let status = null, out = null;
  const res = { writeHead(s) { status = s; }, end(b) { try { out = JSON.parse(b); } catch { out = b; } }, setHeader() {} };
  await routes[method + ' ' + p]({ req: require('stream').Readable.from([JSON.stringify(body)]), res, session: { role: 'admin', username: 'adm' }, url: new URL('http://x' + p) });
  return { status, body: out };
};

(async () => {
  const A = mkCert('example.org');
  const B = mkCert('other.example.org');

  await check('inspectBundle : valide ; cle non correspondante, expire, PEM absent refuses', () => {
    assert.ok(core.inspectBundle(A.cert, A.key).ok);
    const r = core.inspectBundle(A.cert, A.key).info;
    assert.ok(r.domains.includes('example.org') && r.domains.includes('*.example.org'));
    assert.strictEqual(core.inspectBundle(A.cert, B.key).ok, false);
    assert.strictEqual(core.inspectBundle('nop', A.key).ok, false);
    assert.strictEqual(core.inspectBundle(A.cert, 'nop').ok, false);
    assert.strictEqual(core.inspectBundle(A.cert, A.key, Date.now() + 400 * 86400000).ok, false, 'expire');
    assert.strictEqual(core.inspectBundle(A.cert, A.key.replace('PRIVATE KEY', 'PRIVATE KEYX')).ok, false);
  });
  await check('noms : chemin interdit', () => {
    for (const n of ['../x', 'a/b', '', '.x', 'a b', 'x'.repeat(200)]) assert.strictEqual(core.validName(n), false, n);
    assert.ok(core.validName('example.org') && core.validName('wild_card-1.example'));
    assert.strictEqual(core.installSynced(CERTS, '../evil', { fullchain: A.cert, privkey: A.key }).ok, false);
  });
  await check('installSynced : fichiers, droits, idempotence, retour arriere, anti-downgrade', () => {
    const r = core.installSynced(CERTS, 'a', { fullchain: A.cert, privkey: A.key, source: 't' });
    assert.ok(r.ok && r.changed);
    const d = path.join(CERTS, 'synced', 'a');
    assert.strictEqual(fs.statSync(path.join(d, 'privkey.pem')).mode & 0o077, 0, 'cle 0600');
    assert.ok(fs.existsSync(path.join(d, 'fullchain.pem')) && fs.existsSync(path.join(d, 'meta.json')));
    assert.strictEqual(core.installSynced(CERTS, 'a', { fullchain: A.cert, privkey: A.key }).changed, false);
    const long = mkCert('example.org', { days: 200 });
    const short = mkCert('example.org', { days: 10 });
    assert.ok(core.installSynced(CERTS, 'a', { fullchain: long.cert, privkey: long.key }).changed);
    assert.strictEqual(core.installSynced(CERTS, 'a', { fullchain: short.cert, privkey: short.key }).ok, false, 'retour en arriere refuse');
    assert.ok(core.installSynced(CERTS, 'a', { fullchain: short.cert, privkey: short.key }, { force: true }).changed);
    assert.ok(core.rollbackSynced(CERTS, 'a', true));
    assert.strictEqual(core.readSyncedMeta(CERTS, 'a').fingerprint256, core.inspectBundle(long.cert, long.key).info.fingerprint256);
    assert.ok(core.removeSynced(CERTS, 'a'));
    assert.strictEqual(core.readSyncedMeta(CERTS, 'a'), null);
  });
  await check('validateRemote : HTTPS obligatoire, modes TLS, doublons, jeton conserve', () => {
    const ok = { name: 'dmz', url: 'https://dmz.lan:3000', direction: 'pull', token: 'cst_abc', tlsMode: 'verify', certs: [{ remote: 'example.org' }] };
    assert.ok(core.validateRemote(ok).ok);
    for (const p of [{ url: 'http://x' }, { url: 'https://u:p@x' }, { url: 'https://x/?a=1' }, { direction: 'x' }, { token: '' }, { token: 'a b' },
      { tlsMode: 'x' }, { tlsMode: 'pin' }, { tlsMode: 'pin', pin: 'zz' }, { tlsMode: 'ca' }, { tlsMode: 'ca', ca: 'pas pem' }, { certs: [] }, { certs: [{ remote: '../x' }] },
      { certs: [{ remote: 'a', local: 'z' }, { remote: 'b', local: 'z' }] }, { name: '' }])
      assert.strictEqual(core.validateRemote({ ...ok, ...p }).ok, false, JSON.stringify(p));
    assert.strictEqual(core.validateRemote({ ...ok, token: '' }, { token: 'cst_old' }).value.token, 'cst_old');
    const pin = 'AA:'.repeat(31) + 'AA';
    assert.strictEqual(core.validateRemote({ ...ok, tlsMode: 'pin', pin }).value.tls.pin, 'aa'.repeat(32));
    assert.ok(core.validateRemote({ ...ok, tlsMode: 'ca', ca: A.cert }).ok);
  });

  // ── Jetons et routes ────────────────────────────────────────────────────────
  putLive('example.org', A);
  let pullTok, pushTok;
  await check('jetons : creation, hash seul stocke, portee et noms controles', async () => {
    const r = await callAdmin('POST', '/api/certsync/tokens/create', { name: 'lan', scope: 'pull', certs: ['example.org'] });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    pullTok = r.body.rawToken;
    assert.ok(/^cst_[0-9a-f]{48}$/.test(pullTok));
    assert.ok(!JSON.stringify(store.getToken(r.body.token.id)).includes(pullTok));
    const p = await callAdmin('POST', '/api/certsync/tokens/create', { name: 'vps', scope: 'push', certs: ['pushed'] });
    pushTok = p.body.rawToken;
    for (const b of [{ name: 'x', scope: 'z', certs: ['a'] }, { name: 'x', scope: 'pull', certs: [] }, { name: 'x', scope: 'pull', certs: ['../a'] }])
      assert.strictEqual((await callAdmin('POST', '/api/certsync/tokens/create', b)).status, 400);
    assert.ok(!JSON.stringify((await callAdmin('GET', '/api/certsync/overview')).body).includes(pullTok), 'jamais de jeton dans overview');
  });
  const asToken = (raw) => auth.authenticateCertsyncToken({ headers: { authorization: 'Bearer ' + raw } });
  await check('auth : jeton inconnu refuse, session sans permission', () => {
    assert.strictEqual(asToken('cst_' + '0'.repeat(48)), null);
    const s = asToken(pullTok);
    assert.strictEqual(s.role, 'certsync');
    assert.strictEqual(auth.hasPerm(s, auth.PERMS.MANAGE_USERS), false);
    assert.strictEqual(auth.hasPerm(s, auth.PERMS.DEPLOY), false);
  });

  // ── Serveur HTTPS (auto-signe) qui expose les routes d'un nœud ───────────────
  const S = mkCert('localhost');
  const server = https.createServer({ key: S.key, cert: S.cert }, async (req, res) => {
    const url = new URL(req.url, 'https://x');
    const session = auth.authenticateCertsyncToken(req);
    const h = routes[req.method + ' ' + url.pathname];
    if (!session || !h) { res.writeHead(session ? 404 : 401, { 'Content-Type': 'application/json' }); return res.end('{"error":"x"}'); }
    session.ip = '127.0.0.1';
    await h({ req, res: Object.assign(res, { setHeader: res.setHeader.bind(res) }), session, url, pathname: url.pathname });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const url = `https://127.0.0.1:${port}`;
  const serverFp = core.normFingerprint(new (require('crypto').X509Certificate)(S.cert).raw);
  const remoteBase = { url, token: pullTok };

  await check('TLS : auto-signe refuse en mode verify, message explicite', async () => {
    await assert.rejects(client.request({ ...remoteBase, tls: { mode: 'verify' } }, 'GET', '/api/certsync/list'), /auto-sign|autorit/i);
  });
  await check('TLS : mode empreinte accepte la bonne, refuse la mauvaise sans envoyer le jeton', async () => {
    const r = await client.request({ ...remoteBase, tls: { mode: 'pin', pin: serverFp } }, 'GET', '/api/certsync/list');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.certs.map(c => c.name), ['example.org']);
    await assert.rejects(client.request({ ...remoteBase, tls: { mode: 'pin', pin: 'a'.repeat(64) } }, 'GET', '/api/certsync/list'), /empreinte/);
  });
  await check('TLS : mode autorite privee (CA = certificat du serveur) et mode sans verification', async () => {
    const r1 = await client.request({ ...remoteBase, tls: { mode: 'ca', ca: S.cert } }, 'GET', '/api/certsync/list');
    assert.strictEqual(r1.status, 200);
    const r2 = await client.request({ ...remoteBase, tls: { mode: 'insecure' } }, 'GET', '/api/certsync/list');
    assert.strictEqual(r2.status, 200);
  });
  await check('probe : empreinte du serveur, sans jeton', async () => {
    const p = await client.probeServerCert(url);
    assert.strictEqual(p.fingerprint256, serverFp);
    assert.strictEqual(p.trusted, false);
    await assert.rejects(client.probeServerCert('http://x'), /HTTPS/);
  });

  await check('routes certsync : jeton push ne lit pas, jeton pull n\'ecrit pas, nom non autorise refuse', async () => {
    const tls = { mode: 'insecure' };
    const get = (tok, name) => client.request({ url, token: tok, tls }, 'GET', `/api/certsync/pull?name=${name}`);
    assert.strictEqual((await get(pullTok, 'example.org')).status, 200);
    assert.strictEqual((await get(pullTok, 'autre')).status, 403);
    assert.strictEqual((await get(pushTok, 'pushed')).status, 403);
    assert.strictEqual((await get('cst_' + '1'.repeat(48), 'example.org')).status, 401);
    const push = (tok, name) => client.request({ url, token: tok, tls }, 'POST', '/api/certsync/push', { name, fullchain: A.cert, privkey: A.key });
    assert.strictEqual((await push(pullTok, 'example.org')).status, 403);
    assert.strictEqual((await push(pushTok, 'example.org')).status, 403);
  });

  // ── Bout en bout ─────────────────────────────────────────────────────────────
  const pinRemote = (direction, token, certs) => ({ id: 'r', name: 'nœud B', url, token, direction, enabled: true, tls: { mode: 'pin', pin: serverFp }, certs, lastPushed: {} });
  await check('pull : installe sous synced/, rechargement nginx, 2e passage = inchange, forcer = retelecharge', async () => {
    nginx = { ...nginx, test: [], reload: [] };
    let r = await feature.syncRemote(pinRemote('pull', pullTok, [{ remote: 'example.org', local: 'copie' }]), {});
    assert.strictEqual(r.results[0].status, 'updated', JSON.stringify(r.results));
    assert.ok(fs.existsSync(path.join(CERTS, 'synced', 'copie', 'privkey.pem')));
    assert.strictEqual(nginx.test.length, 1); assert.strictEqual(nginx.reload.length, 1);
    r = await feature.syncRemote(pinRemote('pull', pullTok, [{ remote: 'example.org', local: 'copie' }]), {});
    assert.strictEqual(r.results[0].status, 'unchanged');
    assert.strictEqual(nginx.reload.length, 1, 'pas de rechargement inutile');
    r = await feature.syncRemote(pinRemote('pull', pullTok, [{ remote: 'example.org', local: 'copie' }]), { force: true });
    assert.strictEqual(r.results[0].status, 'unchanged', 'meme certificat : installSynced idempotent');
  });
  await check('pull : nginx -t en echec = retour a l\'etat precedent (premiere install supprimee)', async () => {
    nginx.failTest = true;
    const r = await feature.syncRemote(pinRemote('pull', pullTok, [{ remote: 'example.org', local: 'echec' }]), {});
    nginx.failTest = false;
    assert.strictEqual(r.results[0].status, 'error');
    assert.match(r.results[0].message, /nginx -t/);
    assert.ok(!fs.existsSync(path.join(CERTS, 'synced', 'echec')));
  });
  await check('pull : erreurs distantes lisibles (jeton refuse, certificat non autorise)', async () => {
    let r = await feature.syncRemote(pinRemote('pull', 'cst_' + '2'.repeat(48), [{ remote: 'example.org', local: 'x1' }]), {});
    assert.match(r.results[0].message, /jeton refus/);
    r = await feature.syncRemote(pinRemote('pull', pullTok, [{ remote: 'secret', local: 'x2' }]), {});
    assert.match(r.results[0].message, /non autoris/);
  });
  await check('push : envoie le certificat local, installe chez le destinataire, 2e passage = deja envoye', async () => {
    nginx = { ...nginx, test: [], reload: [] };
    const remote = pinRemote('push', pushTok, [{ local: 'example.org', remote: 'pushed' }]);
    let r = await feature.syncRemote(remote, {});
    assert.strictEqual(r.results[0].status, 'pushed', JSON.stringify(r.results));
    assert.ok(fs.existsSync(path.join(CERTS, 'synced', 'pushed', 'fullchain.pem')));
    assert.strictEqual(nginx.reload.length, 1);
    remote.lastPushed = r.lastPushed;
    r = await feature.syncRemote(remote, {});
    assert.strictEqual(r.results[0].status, 'unchanged');
    r = await feature.syncRemote(remote, { force: true });
    assert.strictEqual(r.results[0].status, 'unchanged', 'deja a jour chez le destinataire');
    r = await feature.syncRemote(pinRemote('push', pushTok, [{ local: 'absent', remote: 'pushed' }]), {});
    assert.match(r.results[0].message, /introuvable/);
  });
  await check('push : certificat dont la cle ne correspond pas refuse par le destinataire', async () => {
    const res = await client.request({ url, token: pushTok, tls: { mode: 'insecure' } }, 'POST', '/api/certsync/push', { name: 'pushed', fullchain: A.cert, privkey: B.key });
    assert.strictEqual(res.status, 422);
    assert.match(res.json.error, /ne correspond pas/);
  });
  await check('runSync : sources configurees, statut enregistre, notification en cas d\'erreur', async () => {
    const v = core.validateRemote({ name: 'B', url, direction: 'pull', token: pullTok, tlsMode: 'pin', pin: serverFp, certs: [{ remote: 'example.org', local: 'via-run' }] });
    const saved = store.saveRemote(null, v.value, 'adm');
    let r = await feature.runSync({ ids: [saved.remote.id] });
    assert.strictEqual(r.ok, true, r.message);
    assert.strictEqual(store.getRemote(saved.remote.id).lastStatus, 'ok');
    const pub = store.listRemotes().find(x => x.id === saved.remote.id);
    assert.ok(!JSON.stringify(pub).includes(pullTok), 'le jeton ne sort jamais');
    store.saveRemote(saved.remote.id, { ...saved.remote, token: 'cst_' + '3'.repeat(48) }, 'adm');
    r = await feature.runSync({ ids: [saved.remote.id] });
    assert.strictEqual(r.ok, false);
    assert.match(r.message, /jeton refus/);
  });
  await check('routes admin : droits, sauvegarde, test, suppression d\'un certificat synchronise', async () => {
    const viewer = async (m, p) => { let s = null; await routes[m + ' ' + p]({ req: require('stream').Readable.from(['{}']), res: { writeHead(x) { s = x; }, end() {}, setHeader() {} }, session: { role: 'operator', username: 'op' }, url: new URL('http://x' + p) }); return s; };
    for (const [m, p] of [['GET', '/api/certsync/overview'], ['POST', '/api/certsync/remotes/save'], ['POST', '/api/certsync/remotes/sync'], ['POST', '/api/certsync/tokens/create']])
      assert.strictEqual(await viewer(m, p), 403, p);
    const save = await callAdmin('POST', '/api/certsync/remotes/save', { name: 'T', url, direction: 'pull', token: pullTok, tlsMode: 'pin', pin: serverFp, certs: [{ remote: 'example.org', local: 'tst' }] });
    assert.strictEqual(save.status, 200, JSON.stringify(save.body));
    const t = await callAdmin('POST', '/api/certsync/remotes/test', { id: save.body.remote.id });
    assert.strictEqual(t.body.ok, true, JSON.stringify(t.body));
    assert.deepStrictEqual(t.body.missing, []);
    assert.strictEqual((await callAdmin('POST', '/api/certsync/remotes/probe', { url })).body.fingerprint256, serverFp);
    assert.strictEqual((await callAdmin('POST', '/api/certsync/remotes/probe', { url: 'http://x' })).body.ok, false);
    assert.strictEqual((await callAdmin('POST', '/api/certsync/synced/delete', { name: '../x' })).status, 404);
    assert.strictEqual((await callAdmin('POST', '/api/certsync/synced/delete', { name: 'pushed' })).status, 200);
  });
  await check('scheduler : le type certsync existe et appelle runCertsync', async () => {
    const reg = require('../lib/scheduler-tasks');
    assert.ok(reg.getType('certsync'));
    let got = null;
    const r = await reg.getType('certsync').run({ remotes: ['a'] }, { tasks: { runCertsync: async x => { got = x; return { ok: true, message: 'ok' }; } }, task: {} });
    assert.deepStrictEqual(got.ids, ['a']);
    assert.strictEqual(r.status, 'ok');
  });
  await check('SSL : les certificats synchronises apparaissent dans l\'inventaire', () => {
    const list = require('../lib/certs').scanSyncedDir(CERTS);
    assert.ok(list.some(c => c.source === 'synced' && c.domain === 'copie' && c.daysLeft > 0));
  });

  server.close();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
