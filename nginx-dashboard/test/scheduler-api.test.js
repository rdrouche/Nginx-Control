'use strict';
/**
 * v12.56.0 — taches planifiees en base : moteur cron, validation, import/export
 * (fichier tache) et API HTTP (permissions, erreurs, execution manuelle).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sch-api-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
events.initEventsDb();
const cron = require('../lib/schedule-cron');
const store = require('../lib/scheduler-store');
const registry = require('../lib/scheduler-tasks');
const scheduler = require('../lib/scheduler');
const feature = require('../features/scheduler');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const routes = {};
feature.register({ get: (p, h) => { routes['GET ' + p] = h; }, post: (p, h) => { routes['POST ' + p] = h; } });
const call = async (method, p, { role = 'operator', body = {}, query = '' } = {}) => {
  let status = null, out = null, headers = {};
  const res = { writeHead(s, h) { status = s; headers = h || {}; }, end(b) { try { out = JSON.parse(b); } catch { out = b; } }, setHeader() {} };
  const req = require('stream').Readable.from([JSON.stringify(body)]);
  const url = new URL('http://x' + p + query);
  await routes[method + ' ' + p]({ req, res, session: role ? { role, username: 'tester' } : null, url, body });
  return { status, body: out, headers };
};

(async () => {
  await check('cron : buildSchedule produit les bonnes expressions', () => {
    assert.strictEqual(cron.buildSchedule({ mode: 'daily', time: '03:00' }).cron, '0 3 * * *');
    assert.strictEqual(cron.buildSchedule({ mode: 'weekly', days: [4, 1], time: '07:30' }).cron, '30 7 * * 1,4');
    assert.strictEqual(cron.buildSchedule({ mode: 'monthly', day: 1, time: '02:00' }).cron, '0 2 1 * *');
    assert.strictEqual(cron.buildSchedule({ mode: 'interval', unit: 'minutes', every: 15 }).cron, '*/15 * * * *');
    assert.strictEqual(cron.buildSchedule({ mode: 'interval', unit: 'hours', every: 6, minute: 5 }).cron, '5 */6 * * *');
  });
  await check('cron : entrees invalides refusees', () => {
    for (const s of [null, { mode: 'x' }, { mode: 'daily', time: '25:00' }, { mode: 'weekly', days: [], time: '01:00' },
      { mode: 'weekly', days: [9], time: '01:00' }, { mode: 'monthly', day: 32, time: '01:00' },
      { mode: 'interval', unit: 'minutes', every: 7 }, { mode: 'cron', cron: '99 * * * *' }, { mode: 'cron', cron: 'a b c' }])
      assert.strictEqual(cron.buildSchedule(s).ok, false, JSON.stringify(s));
  });
  await check('cron : nextRuns et describeCron', () => {
    const from = new Date(2026, 9, 1, 12, 0, 0);
    const n = cron.nextRuns('0 3 * * *', from, 3);
    assert.strictEqual(n.length, 3);
    assert.strictEqual(n[0].getHours(), 3);
    assert.ok(n[1] - n[0] === 86400000 || Math.abs(n[1] - n[0] - 86400000) <= 3600000);
    assert.ok(cron.describeCron('0 3 * * *', 'fr').length > 3);
    assert.ok(cron.describeCron('0 3 * * *', 'en').length > 3);
  });

  await check('registre : validateParams borne les valeurs', () => {
    const ty = registry.getType('analyzer_restart');
    assert.ok(ty);
    assert.strictEqual(registry.validateParams(ty, { grace_seconds: 5 }).value.grace_seconds, 5);
    assert.strictEqual(registry.validateParams(ty, {}).value.grace_seconds, 10);
    assert.strictEqual(registry.validateParams(ty, { grace_seconds: 9999 }).ok, false);
    const dg = registry.getType('digest');
    assert.strictEqual(registry.validateParams(dg, { recipients: ['a@b.fr', 'pas-un-mail'] }).ok, false);
    assert.deepStrictEqual(registry.validateParams(dg, { recipients: 'a@b.fr, a@b.fr' }).value.recipients, ['a@b.fr']);
  });
  await check('registre : describeTypes expose analyzer_restart avec libelles fr/en', () => {
    const t = registry.describeTypes().find(x => x.id === 'analyzer_restart');
    assert.ok(t && t.label.fr && t.label.en && t.params.length >= 1);
  });

  const base = { name: 'Nuit', type: 'nginx_reload', enabled: true, schedule: { mode: 'daily', time: '03:00' }, params: {}, notify: false };
  let id;
  await check('API : un viewer peut lire mais pas ecrire', async () => {
    assert.strictEqual((await call('GET', '/api/scheduler/tasks', { role: 'viewer' })).status, 200);
    for (const [m, p] of [['POST', '/api/scheduler/tasks/save'], ['POST', '/api/scheduler/tasks/toggle'], ['POST', '/api/scheduler/tasks/delete'],
      ['POST', '/api/scheduler/tasks/run'], ['POST', '/api/scheduler/import']])
      assert.strictEqual((await call(m, p, { role: 'viewer', body: base })).status, 403, p);
    assert.strictEqual((await call('GET', '/api/scheduler/tasks', { role: null })).status, 403);
  });
  await check('API : creation, lecture decoree, mise a jour', async () => {
    const c = await call('POST', '/api/scheduler/tasks/save', { body: base });
    assert.strictEqual(c.status, 200, JSON.stringify(c.body));
    id = c.body.task.id;
    assert.strictEqual(c.body.task.cron, '0 3 * * *');
    const l = await call('GET', '/api/scheduler/tasks');
    const t = l.body.tasks.find(x => x.id === id);
    assert.ok(t && t.scheduleText && t.nextRun > Date.now());
    const u = await call('POST', '/api/scheduler/tasks/save', { body: { ...base, id, name: 'Nuit 2', schedule: { mode: 'weekly', days: [1], time: '01:00' } } });
    assert.strictEqual(u.body.task.name, 'Nuit 2');
    assert.strictEqual(u.body.task.cron, '0 1 * * 1');
  });
  await check('API : validation (type inconnu, nom vide, planification invalide, id inconnu)', async () => {
    for (const b of [{ ...base, type: 'rm_rf' }, { ...base, name: '  ' }, { ...base, schedule: { mode: 'cron', cron: '* *' } }]) {
      const r = await call('POST', '/api/scheduler/tasks/save', { body: b });
      assert.ok(r.status >= 400 && r.body.ok === false, JSON.stringify(b));
    }
    assert.ok((await call('POST', '/api/scheduler/tasks/toggle', { body: { id: 99999, enabled: true } })).status >= 400);
    assert.strictEqual((await call('POST', '/api/scheduler/tasks/run', { body: { id: 99999 } })).status, 404);
  });
  await check('API : bascule, apercu, types', async () => {
    const t = await call('POST', '/api/scheduler/tasks/toggle', { body: { id, enabled: false } });
    assert.strictEqual(t.body.task.enabled, false);
    assert.strictEqual(t.body.task.nextRun, null);
    const p = await call('POST', '/api/scheduler/preview', { body: { schedule: { mode: 'interval', unit: 'hours', every: 6 } } });
    assert.strictEqual(p.body.ok, true);
    assert.strictEqual(p.body.next.length, 5);
    assert.strictEqual((await call('POST', '/api/scheduler/preview', { body: { schedule: { mode: 'zzz' } } })).body.ok, false);
    const ty = await call('GET', '/api/scheduler/types');
    assert.ok(ty.body.types.some(x => x.id === 'analyzer_restart'));
  });
  await check('API : export puis import (fusion / remplacement), fichier invalide refuse', async () => {
    const e = await call('GET', '/api/scheduler/export');
    assert.strictEqual(e.status, 200);
    assert.ok(/attachment/.test(e.headers['Content-Disposition']));
    const file = e.body;
    assert.ok(file && Array.isArray(file.tasks) && file.tasks.length >= 1);
    const m = await call('POST', '/api/scheduler/import', { body: { content: JSON.stringify(file), mode: 'merge' } });
    assert.strictEqual(m.body.ok, true);
    const n1 = store.listTasks().length;
    const r = await call('POST', '/api/scheduler/import', { body: { content: JSON.stringify(file), mode: 'replace' } });
    assert.strictEqual(r.body.ok, true);
    assert.strictEqual(store.listTasks().length, file.tasks.length);
    assert.ok(n1 >= file.tasks.length);
    assert.strictEqual((await call('POST', '/api/scheduler/import', { body: { content: 'pas du json', mode: 'merge' } })).status, 400);
    assert.strictEqual((await call('POST', '/api/scheduler/import', { body: { content: JSON.stringify({ format: 'autre', tasks: [] }), mode: 'merge' } })).status, 400);
  });
  await check('API : suppression et historique vide', async () => {
    const t = store.listTasks()[0];
    assert.deepStrictEqual((await call('GET', '/api/scheduler/runs', { query: '?id=' + t.id })).body.runs, []);
    assert.strictEqual((await call('POST', '/api/scheduler/tasks/delete', { body: { id: t.id } })).body.ok, true);
    assert.strictEqual(store.getTask(t.id), null);
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
