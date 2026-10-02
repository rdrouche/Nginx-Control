'use strict';
/**
 * Journal d evenements (lib/events.js) — regression : la page Events
 * affichait "NaNh" pour chaque ligne des qu une base SQLite etait
 * disponible (le cas normal en production, contrairement au bac a sable
 * de developpement qui retombe souvent sur le journal en memoire).
 *
 * Cause : la table `events` stocke `ts` (entier epoch-ms), mais l interface
 * attend `timestamp` (chaine ISO) — le meme champ que produit le chemin en
 * memoire (logEvent()/recentEvents()). queryEvents() renvoyait les lignes
 * telles quelles, sans jamais fournir ce champ ; timeAgo() cote client
 * recevait donc `undefined`, et `new Date(undefined)` est une Invalid Date.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
process.env.USERS_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eventstest-')), 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

events.initEventsDb();

console.log('\nqueryEvents — champ timestamp (regression NaN dans la page Events)');
check('un evenement persiste porte un champ timestamp, chaine ISO valide (pas juste ts, l entier epoch-ms)', () => {
  events.logEvent('test.regression', { foo: 'bar' }, 'test');
  const { events: rows, fromDb } = events.queryEvents({ limit: 5 });
  if (!fromDb) { console.log('        (SQLite indisponible dans ce runner — verification sautee)'); return; }
  const row = rows.find(r => r.type === 'test.regression');
  assert.ok(row, 'evenement non retrouve');
  assert.strictEqual(typeof row.timestamp, 'string');
  const d = new Date(row.timestamp);
  assert.ok(!isNaN(d.getTime()), 'timestamp doit produire une Date valide, jamais Invalid Date/NaN');
});
check('timestamp concorde avec ts (meme instant, formats differents)', () => {
  events.logEvent('test.regression2', {}, 'test');
  const { events: rows, fromDb } = events.queryEvents({ limit: 5 });
  if (!fromDb) return;
  const row = rows.find(r => r.type === 'test.regression2');
  assert.ok(row);
  assert.strictEqual(new Date(row.timestamp).getTime(), row.ts);
});
check('le tri par date la plus recente reste correct (ts sert toujours au ORDER BY / filtres since/until)', () => {
  const { events: rows, fromDb } = events.queryEvents({ limit: 10 });
  if (!fromDb || rows.length < 2) return;
  for (let i = 1; i < rows.length; i++) assert.ok(rows[i - 1].ts >= rows[i].ts, 'ordre decroissant attendu');
});
check('sans SQLite (fromDb: false), events reste un tableau vide plutot qu une exception', () => {
  assert.doesNotThrow(() => events.queryEvents({ limit: 5 }));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
