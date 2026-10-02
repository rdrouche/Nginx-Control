'use strict';
/**
 * v12.58.0 — kit de deploiement d'agent (.env + compose.yml + jeton) et
 * creation d'un agent deja approuve depuis le dashboard.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abun-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
events.initEventsDb();
const cfg = require('../lib/config');
fs.writeFileSync(cfg.AGENTS_CONFIG_FILE, 'enable: true\n');
const B = require('../lib/agent-bundle');
const store = require('../lib/agents-store');
const feature = require('../features/agents');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const routes = {}, prefixes = [];
feature.register({
  get: (p, h) => { routes['GET ' + p] = h; }, post: (p, h) => { routes['POST ' + p] = h; },
  addPrefix: (m, p, h) => { prefixes.push({ m, p, h }); },
});
const call = async (method, p, { role = 'operator', body = {} } = {}) => {
  let status = null, out = null;
  const res = { writeHead(s) { status = s; }, end(b) { try { out = JSON.parse(b); } catch { out = b; } }, setHeader() {} };
  const req = require('stream').Readable.from([JSON.stringify(body)]);
  const session = role ? { role, username: 'tester' } : null;
  const exact = routes[method + ' ' + p];
  const h = exact || prefixes.find(x => x.m === method && p.startsWith(x.p)).h;
  await h({ req, res, session, pathname: p, url: new URL('http://x' + p) });
  return { status, body: out };
};

const good = { name: 'vps-paris-1', dashboardUrl: 'https://dash.example.com' };

(async () => {
  await check('options valides : valeurs par defaut', () => {
    const r = B.validateOptions(good);
    assert.ok(r.ok, r.error);
    assert.strictEqual(r.value.dashboardUrl, 'https://dash.example.com');
    assert.strictEqual(r.value.pollInterval, '30s');
    assert.strictEqual(r.value.tokenMode, 'env');
    assert.deepStrictEqual(r.warnings, []);
  });
  await check('options : refus (nom, URL, empreinte, intervalle, image, relais)', () => {
    const bad = [
      { name: '' }, { name: 'a b' }, { name: 'x;rm' }, { name: '../x' },
      { dashboardUrl: 'ftp://x' }, { dashboardUrl: 'pas une url' }, { dashboardUrl: 'https://u:p@x.fr' }, { dashboardUrl: 'https://x.fr/?a=1' },
      { fingerprint: 'a b' }, { fingerprint: 'a$HOME' }, { fingerprint: 'a"b' }, { fingerprint: 'a#b' }, { fingerprint: 'x'.repeat(81) },
      { pollInterval: '1s' }, { pollInterval: 'abc' }, { pollInterval: '99999s' },
      { restartPolicy: 'x' }, { tokenMode: 'x' }, { image: 'a b' }, { image: 'x$y' }, { tag: '-x' },
      { relay: { enabled: true } }, { relay: { enabled: true, host: 'a b' } },
      { relay: { enabled: true, host: '10.0.0.5', httpPort: 80 } },
      { relay: { enabled: true, host: '10.0.0.5', httpPort: 8080, httpsEnabled: true, httpsPort: 8080 } },
    ];
    for (const p of bad) assert.strictEqual(B.validateOptions({ ...good, ...p }).ok, false, JSON.stringify(p));
  });
  await check('avertissements : http:// et TLS non verifie', () => {
    const r = B.validateOptions({ ...good, dashboardUrl: 'http://10.0.0.2:3000', insecureSkipVerify: true });
    assert.ok(r.ok);
    assert.strictEqual(r.warnings.length, 2);
  });
  await check('.env : jeton, hote, relais ; aucune ligne supplementaire injectee', () => {
    const v = B.validateOptions({ ...good, fingerprint: 'sn-123', relay: { enabled: true, host: '10.0.5.9', httpPort: 9000, httpsEnabled: true, httpsPort: 9443 } }).value;
    const env = B.buildEnv(v, 'agt_' + 'a'.repeat(48));
    const kv = Object.fromEntries(env.split('\n').filter(l => l && !l.startsWith('#')).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
    assert.strictEqual(kv.TOKEN, 'agt_' + 'a'.repeat(48));
    assert.strictEqual(kv.DASHBOARD_URL, 'https://dash.example.com');
    assert.strictEqual(kv.AGENT_HOSTNAME, 'vps-paris-1');
    assert.strictEqual(kv.RELAY_HTTP_ADVERTISE, 'http://10.0.5.9:9000');
    assert.strictEqual(kv.RELAY_HTTPS_ADVERTISE, 'https://10.0.5.9:9443');
    assert.strictEqual(kv.RELAY_HTTP_HOST_PORT, '9000');
  });
  await check('mode fichier : pas de TOKEN dans .env ni compose, commande de depot en 0600', () => {
    const v = B.validateOptions({ ...good, tokenMode: 'file' }).value;
    const tok = 'agt_' + 'b'.repeat(48);
    const bundle = B.buildBundle(v, tok);
    assert.ok(!bundle.env.includes(tok) && !bundle.compose.includes(tok));
    assert.ok(bundle.compose.includes('TOKEN_FILE=/data/token'));
    assert.ok(bundle.shell.includes('umask 077') && bundle.shell.includes(tok));
  });
  await check('compose : image publiee, socket en lecture seule, ports seulement avec relais', () => {
    const a = B.buildCompose(B.validateOptions(good).value);
    assert.ok(a.includes('/var/run/docker.sock:/var/run/docker.sock:ro') && a.includes('no-new-privileges'));
    assert.ok(!a.includes('ports:') && !a.includes('build:'));
    assert.ok(a.includes('TOKEN=${TOKEN:?'));
    const b = B.buildCompose(B.validateOptions({ ...good, relay: { enabled: true, host: 'h.example.com', httpPort: 8080 } }).value);
    assert.ok(b.includes('ports:') && b.includes('RELAY_HTTP_HOST_PORT') && !b.includes('RELAY_HTTPS_HOST_PORT'));
  });

  await check('API create : permissions', async () => {
    assert.strictEqual((await call('POST', '/api/agents/create', { role: 'viewer', body: good })).status, 403);
    assert.strictEqual((await call('POST', '/api/agents/create', { role: null, body: good })).status, 403);
  });
  let created;
  await check('API create : agent approuve d\'emblee, jeton valide, kit renvoye, hash seul stocke', async () => {
    const r = await call('POST', '/api/agents/create', { body: good });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    created = r.body;
    assert.strictEqual(created.agent.status, 'approved');
    assert.ok(/^agt_[0-9a-f]{48}$/.test(created.token));
    assert.ok(created.bundle.env.includes('TOKEN=' + created.token));
    assert.strictEqual(store.findByToken(created.token).id, created.agent.id, 'le jeton doit authentifier');
    const rec = store.getAgent(created.agent.id);
    assert.ok(!JSON.stringify(rec).includes(created.token), 'jamais le jeton en clair en base');
    assert.strictEqual(rec.provisioned, true);
  });
  await check('API create : doublon de nom, option invalide, agents desactives', async () => {
    assert.strictEqual((await call('POST', '/api/agents/create', { body: good })).status, 400);
    assert.strictEqual((await call('POST', '/api/agents/create', { body: { ...good, name: 'autre', dashboardUrl: 'x' } })).status, 400);
    fs.writeFileSync(cfg.AGENTS_CONFIG_FILE, 'enable: false\n');
    assert.strictEqual((await call('POST', '/api/agents/create', { body: { ...good, name: 'autre' } })).status, 403);
    fs.writeFileSync(cfg.AGENTS_CONFIG_FILE, 'enable: true\n');
  });
  await check('GET /api/agents : jamais de jeton ni de hash', async () => {
    const r = await call('GET', '/api/agents');
    const s = JSON.stringify(r.body);
    assert.ok(!s.includes(created.token) && !s.includes('tokenHash'));
    assert.ok(r.body.agents.some(a => a.id === created.agent.id && a.status === 'approved'));
  });
  await check('regenerer le jeton : nouveau kit avec les options conservees, ancien jeton invalide', async () => {
    const r = await call('POST', `/api/agents/${created.agent.id}/regenerate-token`, { body: { dashboardUrl: 'https://dash.example.com' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.notStrictEqual(r.body.token, created.token);
    assert.ok(r.body.bundle.env.includes('TOKEN=' + r.body.token));
    assert.strictEqual(store.findByToken(created.token), null);
    assert.strictEqual(store.findByToken(r.body.token).id, created.agent.id);
  });
  await check('enrolement manuel : approuver propose aussi le kit', async () => {
    const rec = store.enroll({ hostnameProposed: 'enrole-1', fingerprint: 'fp' });
    const r = await call('POST', `/api/agents/${rec.id}/approve`, { body: { dashboardUrl: 'https://dash.example.com' } });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.bundle.env.includes('AGENT_HOSTNAME=enrole-1') && r.body.bundle.env.includes('AGENT_FINGERPRINT=fp'));
    const r2 = await call('POST', `/api/agents/${store.enroll({ hostnameProposed: 'enrole-2', fingerprint: '' }).id}/approve`, { body: {} });
    assert.ok(r2.body.token && !r2.body.bundle, 'sans URL du dashboard : jeton seul, comme avant');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
