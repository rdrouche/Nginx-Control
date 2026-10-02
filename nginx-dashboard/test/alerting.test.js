'use strict';
/**
 * features/alerting.js — fetch (memes protections que fetchChangelog(), voir
 * test/changelog.test.js) et parseAlertsMarkdown() (decoupage du fichier
 * distant en alertes independantes).
 */
const assert = require('assert');
const http   = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const checkAsync = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

process.env.CONFIG_DIR = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'alerting-unit-'));
const { fetchAlertingFile, parseAlertsMarkdown } = require('../features/alerting');

console.log('\nfeatures/alerting.js — parseAlertsMarkdown()');

check('une alerte avec ID et LEVEL est extraite correctement', () => {
  const alerts = parseAlertsMarkdown([
    '## Titre',
    'ID: 42',
    'LEVEL: warning',
    '',
    'Corps **markdown**.',
  ].join('\n'));
  assert.strictEqual(alerts.length, 1);
  assert.deepStrictEqual(alerts[0], { externalId: '42', level: 'warning', title: 'Titre', body: 'Corps **markdown**.' });
});

check('ID et LEVEL peuvent apparaitre dans n importe quel ordre', () => {
  const alerts = parseAlertsMarkdown(['## T', 'LEVEL: error', 'ID: 7', '', 'X'].join('\n'));
  assert.strictEqual(alerts[0].externalId, '7');
  assert.strictEqual(alerts[0].level, 'error');
});

check('LEVEL est optionnel, defaut "info"', () => {
  const alerts = parseAlertsMarkdown(['## T', 'ID: 1', '', 'X'].join('\n'));
  assert.strictEqual(alerts[0].level, 'info');
});

check('une alerte sans "ID:" est ignoree, pas de crash', () => {
  const alerts = parseAlertsMarkdown(['## T sans id', '', 'Corps'].join('\n'));
  assert.strictEqual(alerts.length, 0);
});

check('LEVEL avec une valeur non reconnue n est pas consommee comme metadonnee (reste dans le corps)', () => {
  const alerts = parseAlertsMarkdown(['## T', 'ID: 9', 'LEVEL: critical', '', 'X'].join('\n'));
  assert.strictEqual(alerts[0].level, 'info'); // "critical" n est pas une valeur acceptee (info/warning/error)
  assert.ok(alerts[0].body.startsWith('LEVEL: critical'));
});

check('plusieurs alertes dans un seul fichier sont toutes retrouvees, dans l ordre du fichier', () => {
  const alerts = parseAlertsMarkdown([
    '## Première', 'ID: 1', '', 'A',
    '## Deuxième', 'ID: 2', '', 'B',
  ].join('\n'));
  assert.strictEqual(alerts.length, 2);
  assert.strictEqual(alerts[0].externalId, '1');
  assert.strictEqual(alerts[1].externalId, '2');
});

check('fichier vide -> aucune alerte, pas d erreur', () => {
  assert.deepStrictEqual(parseAlertsMarkdown(''), []);
  assert.deepStrictEqual(parseAlertsMarkdown(undefined), []);
});

check('texte avant la premiere alerte (pas de ## en tete) est ignore sans planter', () => {
  const alerts = parseAlertsMarkdown(['Un chapeau libre.', '', '## T', 'ID: 5', '', 'X'].join('\n'));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].externalId, '5');
});

console.log('\nfeatures/alerting.js — fetchAlertingFile() (memes protections que fetchChangelog())');

(async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/alerts.md' }); return res.end(); }
    if (req.url === '/404') { res.writeHead(404); return res.end(); }
    if (req.url === '/big') { res.writeHead(200); return res.end(Buffer.alloc(3 * 1024 * 1024, 'a')); }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('## T\nID: 1\n\nX\n');
  });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${srv.address().port}`;

  await checkAsync('recupere le contenu tel quel sur 200', async () => {
    const r = await fetchAlertingFile(base + '/alerts.md');
    assert.strictEqual(r.content, '## T\nID: 1\n\nX\n');
  });
  await checkAsync('suit une redirection 302', async () => {
    const r = await fetchAlertingFile(base + '/redirect');
    assert.strictEqual(r.content, '## T\nID: 1\n\nX\n');
  });
  await checkAsync('404 -> erreur explicite, pas de contenu (fichier absent : pas de crash)', async () => {
    const r = await fetchAlertingFile(base + '/404');
    assert.ok(r.error);
    assert.strictEqual(r.content, undefined);
  });
  await checkAsync('fichier trop volumineux -> erreur', async () => {
    const r = await fetchAlertingFile(base + '/big');
    assert.ok(r.error);
  });
  await checkAsync('URL vide -> erreur explicite, pas d exception (fonctionnalite non configuree)', async () => {
    const r = await fetchAlertingFile('');
    assert.ok(r.error);
  });
  await checkAsync('hote injoignable -> erreur, pas de crash', async () => {
    const r = await fetchAlertingFile('http://127.0.0.1:1/nope');
    assert.ok(r.error);
  });

  srv.close();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
