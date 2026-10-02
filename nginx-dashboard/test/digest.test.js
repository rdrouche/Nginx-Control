'use strict';
const assert = require('assert');
const digest = require('../lib/digest');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {

console.log('\ngenerateDigest — assemblage des donnees deja calculees ailleurs');

await (async () => {
  digest.configure({
    analyzerApi: async (path) => {
      if (path.includes('/bots')) return { data: { total: 1000, human: 800, bots: 200, byCategory: [{ category: 'good', requests: 150 }] } };
      if (path.includes('/countries')) return { data: { countries: [{ country: 'FR', requests: 600 }, { country: 'US', requests: 200 }] } };
      if (path.includes('/vhosts')) return { data: { vhosts: [{ vhost: 'a.fr', requests: 700, bytes: 1000, errors: 5 }, { vhost: 'b.fr', requests: 300, bytes: 500, errors: 1 }] } };
      if (path.includes('/waf')) return { data: { total: 7 } };
      return { data: null };
    },
    crowdsecGet: async () => [{ origin: 'crowdsec' }, { origin: 'crowdsec' }, { origin: 'cscli' }],
    crowdsecConfigured: () => true,
    getBlocklistStats: async () => ({ enable: true, available: true, totalUniqueIps: 42,
      totalHits: 10, uniqueHitIps: 4, topIps: [], bySource: [{ name: 'datashield', hits: 10 }] }),
    listExistingCerts: () => [
      { name: 'bientot.fr', daysLeft: 5, notAfter: '2026-01-01' },
      { name: 'loin.fr', daysLeft: 200, notAfter: '2027-01-01' },
      { name: 'expire.fr', daysLeft: -3, notAfter: '2025-01-01' },
    ],
  });
  const d = await digest.generateDigest(24);

  await check('trafic total agrege sur tous les vhosts', () => {
    assert.strictEqual(d.traffic.totalRequests, 1000);
    assert.strictEqual(d.traffic.totalBytes, 1500);
    assert.strictEqual(d.traffic.totalErrors, 6);
  });
  await check('vhosts tries par requetes decroissantes', () => {
    assert.strictEqual(d.traffic.byVhost[0].vhost, 'a.fr');
  });
  await check('repartition bot/humain transmise telle quelle', () => {
    assert.strictEqual(d.bots.human, 800);
    assert.strictEqual(d.bots.bots, 200);
  });
  await check('top pays limite a 5, tries par requetes', () => {
    assert.strictEqual(d.topCountries[0].country, 'FR');
    assert.ok(d.topCountries.length <= 5);
  });
  await check('WAF : compte des evenements bloques sur la periode', () => {
    assert.strictEqual(d.waf.configured, true);
    assert.strictEqual(d.waf.blockedCount, 7);
  });
  await check('Blocklists : stats injectees transmises telles quelles', () => {
    assert.strictEqual(d.blocklists.enable, true);
    assert.strictEqual(d.blocklists.totalUniqueIps, 42);
    assert.strictEqual(d.blocklists.bySource[0].name, 'datashield');
  });
  await check('CrowdSec : instantane du total actif, reparti par origine (pas de "nouveaux depuis X")', () => {
    // Une Decision CrowdSec ne porte aucun horodatage de creation dans son
    // propre schema publie — annoncer un delta serait fabriquer une
    // precision que l API ne fournit pas.
    assert.strictEqual(d.crowdsec.activeTotal, 3);
    assert.deepStrictEqual(d.crowdsec.byOrigin, { crowdsec: 2, cscli: 1 });
  });
  await check('certificats : seuls ceux entre 0 et 30 jours sont retenus', () => {
    assert.strictEqual(d.certs.expiringSoon.length, 1);
    assert.strictEqual(d.certs.expiringSoon[0].name, 'bientot.fr');
  });
  await check('aucune erreur quand tout repond correctement', () => {
    assert.deepStrictEqual(d.errors, []);
  });
})();

await (async () => {
  console.log('\ndegradation : rien de configure ou tout injoignable');
  digest.configure({
    analyzerApi: null,
    crowdsecGet: null,
    crowdsecConfigured: () => false,
    getBlocklistStats: null,
    listExistingCerts: () => [],
  });
  const d = await digest.generateDigest(24);
  await check('aucune exception, sections absentes plutot que fausses', () => {
    assert.strictEqual(d.traffic, null);
    assert.strictEqual(d.bots, null);
    assert.strictEqual(d.crowdsec.configured, false);
    assert.strictEqual(d.waf.configured, false);
    assert.strictEqual(d.blocklists.enable, false);
  });
})();

await (async () => {
  console.log('\ndegradation partielle : une source echoue, les autres restent utilisables');
  digest.configure({
    analyzerApi: async (path) => {
      if (path.includes('/bots')) throw new Error('timeout');
      if (path.includes('/countries')) return { data: { countries: [] } };
      if (path.includes('/vhosts')) return { data: { vhosts: [{ vhost: 'a.fr', requests: 10, bytes: 1, errors: 0 }] } };
      return { data: null };
    },
    crowdsecGet: null,
    crowdsecConfigured: () => false,
    listExistingCerts: () => [],
  });
  const d = await digest.generateDigest(24);
  await check('une source en echec n empeche pas les autres de se remplir', () => {
    assert.strictEqual(d.bots, null, 'la source en echec reste absente');
    assert.strictEqual(d.traffic.totalRequests, 10, 'les autres sources restent renseignees');
    assert.ok(d.errors.some(e => e.includes('traffic')), 'l echec doit etre trace, pas juste avale');
  });
})();

await (async () => {
  console.log('\nCrowdSec "configure" mais LAPI injoignable (fix MISC-07)');
  // Reproduit exactement le cas signale : crowdsecConfigured() dit vrai
  // (une config Prometheus seule suffit a la faire repondre vrai), mais
  // l appel LAPI lui-meme echoue. Avant le correctif, activeTotal restait
  // indefini et formatDigestText() plantait sur `.toLocaleString()`,
  // empechant l envoi du digest en entier — pas seulement sa section
  // CrowdSec.
  digest.configure({
    analyzerApi: null,
    crowdsecGet: async () => { throw new Error('ECONNREFUSED'); },
    crowdsecConfigured: () => true,
    getBlocklistStats: null,
    listExistingCerts: () => [],
  });
  const d = await digest.generateDigest(24);
  await check('activeTotal/byOrigin ont une valeur par defaut plutot que undefined', () => {
    assert.strictEqual(d.crowdsec.configured, true);
    assert.strictEqual(d.crowdsec.activeTotal, 0);
    assert.deepStrictEqual(d.crowdsec.byOrigin, {});
    assert.ok(d.errors.some(e => e.includes('crowdsec')), 'l echec doit rester trace');
  });
  await check('formatDigestText ne plante pas et produit bien la section CrowdSec', () => {
    let text;
    assert.doesNotThrow(() => { text = digest.formatDigestText(d); });
    assert.ok(text.includes('CrowdSec : 0 décision'), `section CrowdSec absente ou fausse :\n${text}`);
  });
})();

console.log('\nformatDigestText — rendu texte pour l e-mail');
await (async () => {
  const d = {
    generatedAt: Date.now(), periodHours: 24,
    traffic: { totalRequests: 1234, totalBytes: 5_000_000, totalErrors: 3 },
    bots: { total: 1234, human: 1000, bots: 234, byCategory: [] },
    topCountries: [{ country: 'FR', requests: 800 }],
    crowdsec: { configured: true, activeTotal: 2, byOrigin: { crowdsec: 2 } },
    waf: { configured: true, blockedCount: 9 },
    blocklists: { enable: true, available: true, totalUniqueIps: 42, totalHits: 7, uniqueHitIps: 3,
      bySource: [{ name: 'datashield', hits: 5 }] },
    certs: { expiringSoon: [{ name: 'site.fr', daysLeft: 4, notAfter: '2026-01-01' }] },
    errors: [],
  };
  const text = digest.formatDigestText(d);
  await check('contient les chiffres cles, lisible en texte brut', () => {
    assert.ok(/1.?234/.test(text), 'le nombre 1234 doit apparaitre, quel que soit le separateur de milliers utilise par la locale');
    assert.ok(text.includes('FR'));
    assert.ok(text.includes('site.fr'));
    assert.ok(!text.includes('<'), 'pas de balises HTML dans un rendu texte brut');
  });
  await check('periode hebdomadaire lisible distinctement (168h -> "1 semaine")', () => {
    const weekly = digest.formatDigestText({ ...d, periodHours: 168 });
    assert.ok(/semaine/.test(weekly));
  });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
})();
