'use strict';
/**
 * lib/rules-manager.js#catalog() — le contenu envoye a la modale "Regles"
 * du dashboard : etat live des regles integrees/personnalisees, seuils reels
 * (pas seulement le texte statique what/why/legit/action), et l explication
 * de la mecanique du moteur (fenetre glissante, declenchement par
 * transition, opt-out multi-vhost) demandee pour rendre le moteur "moins
 * aveugle" a l operateur.
 */
const assert = require('assert');
const { RulesManager } = require('../lib/rules-manager');
const { EXPLANATIONS } = require('../lib/detect');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

/** Store minimal, en memoire — pas besoin d une vraie base sqlite ici. */
function fakeStore() {
  const data = {};
  return { getState: k => data[k], setState: (k, v) => { data[k] = v; } };
}

console.log('\ncatalog() — sans thresholds (retro-compatibilite : jamais une exception)');
check('config: null pour chaque regle integree quand aucun threshold n est fourni', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS);
  assert.strictEqual(cat.builtins.length, 6);
  for (const b of cat.builtins) assert.strictEqual(b.config, null, `${b.key} devrait avoir config: null`);
  assert.ok(cat.processing && typeof cat.processing === 'object', 'processing doit toujours etre present, meme sans thresholds');
});

console.log('\ncatalog() — avec thresholds (config reelle exposee)');
check('flood : windowMinutes + minRequests exposes tels que configures', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS, {
    windowMs: 5 * 60_000,
    bruteforce: { minFailures: 15 },
    scan: { minRequests: 40, minDistinct: 25, minNotFoundRatio: 0.5 },
    flood: { minRequests: 600 },
    scraping: { minRequests: 300, maxDistinct: 5 },
  });
  const flood = cat.builtins.find(b => b.key === 'flood');
  assert.deepStrictEqual(flood.config, { windowMinutes: 5, minRequests: 600 });
});
check('scan : minNotFoundRatio converti en pourcentage entier', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS, {
    windowMs: 10 * 60_000,
    scan: { minRequests: 40, minDistinct: 25, minNotFoundRatio: 0.5 },
  });
  const scan = cat.builtins.find(b => b.key === 'scan');
  assert.deepStrictEqual(scan.config, { windowMinutes: 10, minRequests: 40, minDistinct: 25, minNotFoundRatioPercent: 50 });
});
check('volumetric/country_traffic : config Baseline (learningDays/sigma/minAbsolute), pas de windowMinutes (mecanisme different)', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS, {
    volumetric: { learningDays: 21, sigmaThreshold: 6, minAbsoluteRequests: 100 },
    country_traffic: { learningDays: 21, sigmaThreshold: 6, minAbsoluteRequests: 300 },
  });
  const vol = cat.builtins.find(b => b.key === 'volumetric');
  const country = cat.builtins.find(b => b.key === 'country_traffic');
  assert.deepStrictEqual(vol.config, { learningDays: 21, sigmaThreshold: 6, minAbsoluteRequests: 100 });
  assert.deepStrictEqual(country.config, { learningDays: 21, sigmaThreshold: 6, minAbsoluteRequests: 300 });
});
check('un threshold absent pour UNE regle -> config:null seulement pour celle-la, les autres restent renseignees', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS, { windowMs: 5 * 60_000, flood: { minRequests: 600 } });
  assert.strictEqual(cat.builtins.find(b => b.key === 'flood').config.minRequests, 600);
  assert.strictEqual(cat.builtins.find(b => b.key === 'bruteforce').config, null);
});

console.log('\ncatalog().processing — documentation vivante de la mecanique du moteur');
check('mentionne la fenetre reelle en minutes quand windowMs est fourni', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS, { windowMs: 7 * 60_000 });
  assert.ok(cat.processing.aggregation.includes('7 min'), cat.processing.aggregation);
});
check('sans windowMs fourni -> repli sur 5 min (jamais une chaine cassee/"undefined min")', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS);
  assert.ok(cat.processing.aggregation.includes('5 min'));
  assert.ok(!cat.processing.aggregation.includes('undefined'));
});
check('explique le declenchement par transition (edge-triggered)', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS);
  assert.ok(/transition/i.test(cat.processing.edgeTriggered));
});
check('explique la regle multi-vhost de l opt-out (TOUS les vhosts touches doivent l ignorer)', () => {
  const rm = new RulesManager(fakeStore());
  const cat = rm.catalog(EXPLANATIONS);
  assert.ok(/TOUS/.test(cat.processing.vhostOptOut));
  assert.ok(/plusieurs vhosts/i.test(cat.processing.vhostOptOut));
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
