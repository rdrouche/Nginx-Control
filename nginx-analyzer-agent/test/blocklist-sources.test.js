'use strict';
/**
 * lib/blocklist-sources.js — the per-source membership synced in from
 * nginx-dashboard (v12.29.0) that lets the analyzer attribute blocklist hits
 * ("bySource") and, in "approx" mode, detect them itself off the main
 * access-log tailer instead of a dedicated blocklist-hits.log.
 */
const assert = require('assert');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nmode');
check('mode par defaut = dedicated', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  assert.strictEqual(B.getMode(), 'dedicated');
});
check('setMode accepte approx, rejette tout le reste vers dedicated', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setMode('approx');
  assert.strictEqual(B.getMode(), 'approx');
  B.setMode('n-importe-quoi');
  assert.strictEqual(B.getMode(), 'dedicated');
  B.setMode(undefined);
  assert.strictEqual(B.getMode(), 'dedicated');
});

console.log('\nsourcesContaining — avant tout sync');
check('index vide -> aucune correspondance, pas d exception', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  assert.deepStrictEqual(B.sourcesContaining('203.0.113.5'), []);
  assert.strictEqual(B.hasSources(), false);
});

console.log('\nsourcesContaining — apres sync');
check('adresse exacte (host route) correspond a sa source', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setSources({ firehol: { ips: ['203.0.113.5'] } });
  assert.strictEqual(B.hasSources(), true);
  assert.deepStrictEqual(B.sourcesContaining('203.0.113.5'), ['firehol']);
  assert.deepStrictEqual(B.sourcesContaining('203.0.113.6'), []);
});
check('bloc CIDR correspond a toute adresse qu il couvre', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setSources({ spamhaus: { ips: ['198.51.100.0/24'] } });
  assert.deepStrictEqual(B.sourcesContaining('198.51.100.42'), ['spamhaus']);
  assert.deepStrictEqual(B.sourcesContaining('198.51.101.1'), []);
});
check('une IP presente dans plusieurs sources renvoie toutes les sources', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setSources({
    a: { ips: ['203.0.113.5'] },
    b: { ips: ['203.0.113.0/24'] },
    c: { ips: ['192.0.2.0/24'] },
  });
  const matches = B.sourcesContaining('203.0.113.5');
  assert.strictEqual(matches.length, 2);
  assert.ok(matches.includes('a') && matches.includes('b'));
});
check('adresse IPv4-mappee (::ffff:a.b.c.d) correspond a un CIDR IPv4 (fix Basse/Analyzer)', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setSources({ src: { ips: ['203.0.113.0/24'] } });
  assert.deepStrictEqual(B.sourcesContaining('::ffff:203.0.113.5'), ['src']);
});
check('un pattern invalide dans la liste est ignore sans planter', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  assert.doesNotThrow(() => B.setSources({ src: { ips: ['pas-une-ip', '203.0.113.5'] } }));
  assert.deepStrictEqual(B.sourcesContaining('203.0.113.5'), ['src']);
});
check('setSources({}) vide l index (retrait/desactivation cote dashboard)', () => {
  delete require.cache[require.resolve('../lib/blocklist-sources')];
  const B = require('../lib/blocklist-sources');
  B.setSources({ src: { ips: ['203.0.113.5'] } });
  assert.strictEqual(B.hasSources(), true);
  B.setSources({});
  assert.strictEqual(B.hasSources(), false);
  assert.deepStrictEqual(B.sourcesContaining('203.0.113.5'), []);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
