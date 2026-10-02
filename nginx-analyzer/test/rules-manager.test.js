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

console.log('\n"Blocklist a la CrowdSec" par regle (v12.50.0) — regles integrees');
check('getBlocklistConfig() par defaut : threshold null (desactive), fenetre 1440 min, remediation false', () => {
  const rm = new RulesManager(fakeStore());
  assert.deepStrictEqual(rm.getBlocklistConfig('flood'), {
    threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null, remediationType: 'block',
  });
});
check('setBlocklistConfig() valide, persiste et se relit via getBlocklistConfig()', () => {
  const store = fakeStore();
  const rm = new RulesManager(store);
  const result = rm.setBlocklistConfig('flood', { threshold: 5, windowMinutes: 60, remediation: true, remediationMinutes: 120 });
  assert.strictEqual(result.ok, true);
  assert.deepStrictEqual(rm.getBlocklistConfig('flood'), { threshold: 5, windowMinutes: 60, remediation: true, remediationMinutes: 120, remediationType: 'block' });
  // persiste : un nouveau RulesManager sur le meme store retrouve la config
  const rm2 = new RulesManager(store);
  assert.deepStrictEqual(rm2.getBlocklistConfig('flood'), { threshold: 5, windowMinutes: 60, remediation: true, remediationMinutes: 120, remediationType: 'block' });
  // et l etat enabled/disabled de la regle (non touche par setBlocklistConfig) survit aussi
  assert.strictEqual(rm2.isEnabled('flood'), true);
});
check('setBlocklistConfig() : threshold/windowMinutes/remediationMinutes invalides -> erreur explicite, rien de persiste', () => {
  const rm = new RulesManager(fakeStore());
  assert.strictEqual(rm.setBlocklistConfig('flood', { threshold: 0 }).ok, false);
  assert.strictEqual(rm.setBlocklistConfig('flood', { windowMinutes: -1 }).ok, false);
  assert.strictEqual(rm.setBlocklistConfig('flood', { remediationMinutes: 0 }).ok, false);
  assert.strictEqual(rm.setBlocklistConfig('inconnue', { threshold: 5 }).ok, false);
  // rien n a ete altere par les tentatives invalides
  assert.deepStrictEqual(rm.getBlocklistConfig('flood'), {
    threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null, remediationType: 'block',
  });
});
check('migration : un rule_state pre-v12.50.0 (booleen brut) est repris comme enabled, blocklist par defaut', () => {
  const store = fakeStore();
  store.setState('rule_state', { flood: false, scan: true });
  const rm = new RulesManager(store);
  assert.strictEqual(rm.isEnabled('flood'), false);
  assert.strictEqual(rm.isEnabled('scan'), true);
  assert.deepStrictEqual(rm.getBlocklistConfig('flood'), {
    threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null, remediationType: 'block',
  });
});
check('toggle() ne touche jamais a la config blocklist deja definie', () => {
  const rm = new RulesManager(fakeStore());
  rm.setBlocklistConfig('flood', { threshold: 3 });
  rm.toggle('flood', false);
  assert.strictEqual(rm.isEnabled('flood'), false);
  assert.strictEqual(rm.getBlocklistConfig('flood').threshold, 3);
});

console.log('\nlistBlocklistRules() — fusion regles integrees + personnalisees ayant opte');
check('seules les regles avec threshold configure apparaissent (integrees ET personnalisees)', () => {
  const rm = new RulesManager(fakeStore());
  rm.setBlocklistConfig('flood', { threshold: 5, remediation: true });
  rm.setCustomYaml([
    'rules:',
    '  - id: 100',
    '    name: admin_probe',
    '    min_matches: 10',
    '    path_hint: "/wp-admin"',
    '    blocklist_threshold: 3',
    '    blocklist_remediation: true',
    '    blocklist_remediation_minutes: 30',
  ].join('\n'));
  const list = rm.listBlocklistRules();
  assert.strictEqual(list.length, 2);
  const flood = list.find(r => r.key === 'flood');
  const custom = list.find(r => r.key === 'custom_100');
  assert.deepStrictEqual(flood, { id: 3, key: 'flood', name: 'flood', custom: false, threshold: 5, windowMinutes: 1440, remediation: true, remediationMinutes: null, remediationType: 'block' });
  assert.deepStrictEqual(custom, { id: 100, key: 'custom_100', name: 'admin_probe', custom: true, threshold: 3, windowMinutes: 1440, remediation: true, remediationMinutes: 30, remediationType: 'block' });
});
check('aucune regle opt-in -> liste vide', () => {
  const rm = new RulesManager(fakeStore());
  assert.deepStrictEqual(rm.listBlocklistRules(), []);
});

console.log('\ncatalog() expose la config blocklist de chaque regle');
check('chaque regle integree porte son bloc "blocklist" (defaut ou configure)', () => {
  const rm = new RulesManager(fakeStore());
  rm.setBlocklistConfig('scan', { threshold: 8 });
  const cat = rm.catalog(EXPLANATIONS);
  const scan = cat.builtins.find(b => b.key === 'scan');
  const flood = cat.builtins.find(b => b.key === 'flood');
  assert.strictEqual(scan.blocklist.threshold, 8);
  assert.strictEqual(flood.blocklist.threshold, null);
});

check('remediationType : challenge persiste, valeur inconnue refusee, exposee par listBlocklistRules()', () => {
  const store = fakeStore();
  const rm = new RulesManager(store);
  assert.strictEqual(rm.setBlocklistConfig('flood', { threshold: 3, remediation: true, remediationType: 'captcha' }).ok, false);
  assert.strictEqual(rm.setBlocklistConfig('flood', { threshold: 3, remediation: true, remediationType: 'challenge' }).ok, true);
  assert.strictEqual(new RulesManager(store).getBlocklistConfig('flood').remediationType, 'challenge');
  assert.strictEqual(rm.listBlocklistRules().find(r => r.key === 'flood').remediationType, 'challenge');
  rm.setCustomYaml(`rules:
  - id: 120
    name: x
    min_matches: 2
    blocklist_threshold: 1
    blocklist_remediation: true
    blocklist_remediation_type: challenge
`);
  assert.strictEqual(rm.listBlocklistRules().find(r => r.key === 'custom_120').remediationType, 'challenge');
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
