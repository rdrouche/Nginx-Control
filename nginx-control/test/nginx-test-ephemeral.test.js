'use strict';
/**
 * v12.54.0 — POST /api/nginx/test-ephemeral : test de la config ACTIVE dans un
 * conteneur nginx jetable, sortie complete renvoyee a l UI.
 * Retour utilisateur : "ajouter la possibilite de tester dans un conteneur
 * ephemere Nginx et avoir la sortie complete en dessous".
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nte-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
events.initEventsDb();
const feature = require('../features/nginx-control');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const routes = {};
feature.register({
  get: (p, h) => { routes['GET ' + p] = h; },
  post: (p, h) => { routes['POST ' + p] = h; },
});
const call = async (role = 'operator') => {
  let status = null, body = null;
  const res = {
    writeHead(s) { status = s; }, end(b) { try { body = JSON.parse(b); } catch { body = b; } },
    setHeader() {},
  };
  await routes['POST /api/nginx/test-ephemeral']({ req: {}, res, session: role ? { role, username: 't' } : null });
  return { status, body };
};

(async () => {
  await check('route declaree', () => assert.strictEqual(typeof routes['POST /api/nginx/test-ephemeral'], 'function'));

  let calls = [];
  feature.setDeps({ testConfigEphemeral: async (srcDirs) => {
    calls.push(srcDirs);
    return { valid: true, exitCode: 0, image: 'nginx:test', output: '=== Mapping du test ===\nnginx: configuration file /etc/nginx/nginx.conf test is successful' };
  } });

  await check('config valide : 200, valid, sortie complete, config ACTIVE (srcDirs vide)', async () => {
    const r = await call();
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.body.ok, r.body.valid, r.body.exitCode, r.body.image], [true, true, 0, 'nginx:test']);
    assert.ok(r.body.output.includes('Mapping du test') && r.body.output.includes('successful'));
    assert.ok(Number.isFinite(r.body.durationMs));
    assert.deepStrictEqual(calls[0], {}, 'doit tester les repertoires actifs, pas un checkout Git');
  });

  await check('permissions : un viewer et une absence de session sont refuses, sans lancer de conteneur', async () => {
    const before = calls.length;
    assert.strictEqual((await call('viewer')).status, 403);
    assert.strictEqual((await call(null)).status, 403);
    assert.strictEqual(calls.length, before);
  });

  feature.setDeps({ testConfigEphemeral: async () => ({ valid: false, exitCode: 1, image: 'nginx:test', output: 'nginx: [emerg] unknown directive "foo" in /etc/nginx/sites/a.conf:3' }) });
  await check('config invalide : 200 avec valid:false et la sortie d erreur complete (pas une erreur HTTP)', async () => {
    const r = await call();
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.body.ok, r.body.valid, r.body.exitCode], [true, false, 1]);
    assert.ok(r.body.output.includes('unknown directive'));
  });

  feature.setDeps({ testConfigEphemeral: async () => { throw new Error('Cannot create test container: docker injoignable'); } });
  await check('bac a sable impossible a lancer : 500 avec le message', async () => {
    const r = await call();
    assert.strictEqual(r.status, 500);
    assert.strictEqual(r.body.ok, false);
    assert.ok(r.body.error.includes('docker injoignable'));
  });
  await check('apres une erreur, le verrou est libere (un test suivant peut tourner)', async () => {
    feature.setDeps({ testConfigEphemeral: async () => ({ valid: true, exitCode: 0, image: 'i', output: 'ok' }) });
    assert.strictEqual((await call()).status, 200);
  });

  let release;
  feature.setDeps({ testConfigEphemeral: () => new Promise(r => { release = () => r({ valid: true, exitCode: 0, image: 'i', output: 'ok' }); }) });
  await check('un seul test a la fois : le second recoit 409 tant que le premier tourne', async () => {
    const first = call();
    await new Promise(r => setTimeout(r, 20));
    const second = await call();
    assert.strictEqual(second.status, 409);
    release();
    assert.strictEqual((await first).status, 200);
  });

  await check('evenements journalises (nginx.test.ephemeral + .error)', () => {
    const types = events.queryEvents({ limit: 500 }).events.map(e => e.type);
    assert.ok(types.includes('nginx.test.ephemeral'));
    assert.ok(types.includes('nginx.test.ephemeral.error'));
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
