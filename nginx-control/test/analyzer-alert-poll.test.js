'use strict';
/**
 * Fix (audit finding ANA-08) : pollAlerts() (features/analyzer.js) demandait
 * `limit=50&since=<ts>` trie par ts DESC, puis avancait son curseur au ts le
 * plus recent recu — au-dela de 50 nouvelles alertes en une minute (un vrai
 * pic en produit facilement plus), tout ce qui etait plus ancien que les 50
 * dernieres etait perdu pour de bon, le curseur ayant deja saute par-dessus.
 * Ce test simule un faux serveur analyzer paginant ses alertes et verifie
 * qu un arrieré plus grand qu une page est integralement consomme, dans
 * l ordre, sans rien sauter.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzer-poll-'));
const configDir = path.join(tmp, 'config');
fs.mkdirSync(configDir, { recursive: true });
process.env.USERS_FILE = path.join(configDir, 'users.yml'); // lib/config.js derives CONFIG_DIR from this
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

(async () => {
  // Un faux "analyzer" HTTP qui genere 130 alertes (id 1..130, croissant) et
  // ne repond jamais plus de 50 a la fois — exactement la forme du vrai
  // Store.listAlerts() pagine.
  const ALL = [];
  const BASE_TS = Date.now() - 60_000; // dans la derniere heure : passe le filtre "since" du tout premier appel
  for (let i = 1; i <= 130; i++) ALL.push({ id: i, ts: BASE_TS + i, type: 'bruteforce', severity: 'medium', ip: '203.0.113.' + (i % 250), vhost: 'site.fr', summary: `alerte ${i}`, evidence: {} });

  const fake = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/api/alerts') { res.writeHead(404); return res.end(); }
    const sinceId = +url.searchParams.get('sinceId') || 0;
    const since = +url.searchParams.get('since') || 0;
    const limit = +url.searchParams.get('limit') || 100;
    const order = url.searchParams.get('order');
    let rows = ALL.filter(a => a.id > sinceId && a.ts >= since);
    if (order === 'asc') rows = rows.slice(0, limit);
    else rows = rows.slice(-limit).reverse();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ alerts: rows, total: ALL.length }));
  });
  await new Promise(r => fake.listen(0, '127.0.0.1', r));
  const port = fake.address().port;

  fs.writeFileSync(path.join(configDir, 'analyzer.yml'),
    `enable: true\ncontainer_name: 127.0.0.1\nport: ${port}\n`);

  const analyzer = require('../features/analyzer');
  const events = require('../lib/events');

  console.log('\npollAlerts pagine tout l arriere, sans en sauter aucune (fix ANA-08)');
  await analyzer.pollAlerts();
  const seen = events.recentEvents(500).filter(e => e.type && e.type.startsWith('analyzer.'));
  check('les 130 alertes sont toutes remontees, pas seulement les 50 plus recentes', () => {
    assert.strictEqual(seen.length, 130, `${seen.length} alertes vues (attendu 130)`);
  });
  check('aucune alerte n est sautee au milieu (les toutes premieres, celles qu un curseur "saute au plus recent" aurait perdues pour de bon, sont bien presentes)', () => {
    const summaries = new Set(seen.map(e => e.data && e.data.summary));
    for (const i of [1, 2, 3, 49, 50, 51, 80, 129, 130]) {
      assert.ok(summaries.has(`alerte ${i}`), `alerte ${i} manquante`);
    }
  });

  console.log('\nun second appel sans nouvelle alerte ne re-notifie rien (curseur bien avance)');
  const beforeCount = events.recentEvents(500).length;
  await analyzer.pollAlerts();
  const afterCount = events.recentEvents(500).length;
  check('aucun nouvel evenement sur un poll sans nouvelle alerte', () => assert.strictEqual(afterCount, beforeCount));

  console.log('\nde nouvelles alertes arrivees apres coup sont bien reprises depuis le curseur');
  ALL.push({ id: 131, ts: Date.now(), type: 'flood', severity: 'high', ip: '198.51.100.9', vhost: 'site.fr', summary: 'alerte 131', evidence: {} });
  await analyzer.pollAlerts();
  const finalCount = events.recentEvents(500).filter(e => e.type && e.type.startsWith('analyzer.')).length;
  check('la 131e alerte est bien vue apres le poll suivant', () => assert.strictEqual(finalCount, 131));

  fake.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
