'use strict';
/** Stockage du monitoring continu (lib/monitor-store.js) — checks + incidents,
 * meme idiome SQLite que digest-storage.test.js (lib/events.js). */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
process.env.USERS_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'monitorstore-')), 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const store = require('../lib/monitor-store');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

store.initMonitorDb();

console.log('\nrecordCheck() / getHistory() — checks bruts');
check('un check ok est bien enregistre et relu, le plus recent en premier', () => {
  store.recordCheck('k1', { ok: true, status: 200, ms: 12, ts: 1000 });
  store.recordCheck('k1', { ok: true, status: 200, ms: 15, ts: 2000 });
  const h = store.getHistory('k1', 10);
  assert.strictEqual(h.length, 2);
  assert.strictEqual(h[0].ts, 2000);
  assert.strictEqual(h[0].ok, true);
  assert.strictEqual(h[0].status, 200);
});
check('une cible jamais vue renvoie un historique vide, pas une exception', () => {
  assert.deepStrictEqual(store.getHistory('inconnue', 10), []);
});

console.log('\nincidents — ouverture / fermeture automatique');
check('un echec ouvre un incident (endedAt null)', () => {
  store.recordCheck('k2', { ok: false, error: 'timeout', ts: 1000 });
  const incidents = store.getIncidents('k2');
  assert.strictEqual(incidents.length, 1);
  assert.strictEqual(incidents[0].startedAt, 1000);
  assert.strictEqual(incidents[0].endedAt, null);
  assert.strictEqual(incidents[0].lastError, 'timeout');
});
check('des echecs consecutifs ne dupliquent pas l incident, mettent juste a jour la derniere erreur', () => {
  store.recordCheck('k2', { ok: false, error: 'connection refused', ts: 2000 });
  const incidents = store.getIncidents('k2');
  assert.strictEqual(incidents.length, 1);
  assert.strictEqual(incidents[0].lastError, 'connection refused');
});
check('le premier succes apres une panne referme l incident (endedAt pose)', () => {
  store.recordCheck('k2', { ok: true, status: 200, ms: 8, ts: 3000 });
  const incidents = store.getIncidents('k2');
  assert.strictEqual(incidents.length, 1);
  assert.strictEqual(incidents[0].endedAt, 3000);
});
check('une nouvelle panne apres reprise ouvre un second incident distinct', () => {
  store.recordCheck('k2', { ok: false, error: 'timeout', ts: 4000 });
  const incidents = store.getIncidents('k2');
  assert.strictEqual(incidents.length, 2);
  assert.strictEqual(incidents[0].endedAt, null); // le plus recent (en cours) en premier
});

console.log('\ngetSummary() — etat courant + taux de disponibilite');
check('cible actuellement en panne : up:false, downSince renseigne', () => {
  const s = store.getSummary('k2');
  assert.strictEqual(s.up, false);
  assert.strictEqual(s.downSince, 4000);
});
check('cible saine : up:true, downSince null', () => {
  store.recordCheck('k3', { ok: true, status: 200, ms: 5, ts: Date.now() });
  const s = store.getSummary('k3');
  assert.strictEqual(s.up, true);
  assert.strictEqual(s.downSince, null);
  assert.strictEqual(s.uptimePct, 100);
});
check('cible jamais vue : up null, pas d exception', () => {
  const s = store.getSummary('jamais-vue');
  assert.strictEqual(s.up, null);
  assert.strictEqual(s.uptimePct, null);
});
check('taux de disponibilite calcule sur la fenetre glissante fournie', () => {
  store.recordCheck('k4', { ok: true,  ts: Date.now() - 100 });
  store.recordCheck('k4', { ok: false, ts: Date.now() - 50 });
  store.recordCheck('k4', { ok: true,  ts: Date.now() });
  const s = store.getSummary('k4', 3600_000);
  assert.strictEqual(s.checksInWindow, 3);
  assert.strictEqual(s.uptimePct, Math.round((2 / 3) * 1000) / 10);
});

console.log('\nrecordCheck() — flags de transition becameDown/becameUp (utilises par le centre de notification)');
check('premiere panne -> becameDown:true, becameUp:false', () => {
  const r = store.recordCheck('k5', { ok: false, error: 'timeout', ts: 1000 });
  assert.deepStrictEqual(r, { becameDown: true, becameUp: false });
});
check('panne qui continue -> ni becameDown ni becameUp (deja en panne)', () => {
  const r = store.recordCheck('k5', { ok: false, error: 'timeout', ts: 2000 });
  assert.deepStrictEqual(r, { becameDown: false, becameUp: false });
});
check('premier succes apres panne -> becameUp:true', () => {
  const r = store.recordCheck('k5', { ok: true, status: 200, ts: 3000 });
  assert.deepStrictEqual(r, { becameDown: false, becameUp: true });
});
check('succes qui continue -> ni l un ni l autre (deja up)', () => {
  const r = store.recordCheck('k5', { ok: true, status: 200, ts: 4000 });
  assert.deepStrictEqual(r, { becameDown: false, becameUp: false });
});
check('nouvelle cible directement up -> jamais becameUp (rien a refermer)', () => {
  const r = store.recordCheck('k6', { ok: true, status: 200, ts: 1000 });
  assert.deepStrictEqual(r, { becameDown: false, becameUp: false });
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
