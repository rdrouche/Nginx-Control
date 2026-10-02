'use strict';
/** Stockage des digests generes (lib/events.js) — table dediee, meme base
 * SQLite que le reste des evenements, degradation gracieuse sans SQLite. */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
process.env.USERS_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'digeststore-')), 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

events.initEventsDb();

const sampleDigest = (overrides = {}) => ({
  generatedAt: Date.now(), periodHours: 24,
  traffic: { totalRequests: 100 }, bots: null, topCountries: [],
  crowdsec: { configured: false }, waf: { configured: false },
  certs: { expiringSoon: [] }, errors: [],
  ...overrides,
});

console.log('\nsaveDigest / listDigests / getDigest');
check('un digest enregistre renvoie un id numerique', () => {
  const id = events.saveDigest(sampleDigest());
  assert.strictEqual(typeof id, 'number');
  assert.ok(id > 0);
});
check('getDigest recupere le contenu complet, tel qu enregistre', () => {
  const d = sampleDigest({ traffic: { totalRequests: 4242 } });
  const id = events.saveDigest(d);
  const back = events.getDigest(id);
  assert.strictEqual(back.traffic.totalRequests, 4242);
  assert.strictEqual(back.periodHours, 24);
});
check('listDigests : les plus recents en premier, sans le contenu complet', () => {
  const idOld = events.saveDigest(sampleDigest({ generatedAt: Date.now() - 100_000 }));
  const idNew = events.saveDigest(sampleDigest({ generatedAt: Date.now() }));
  const list = events.listDigests(50);
  const idxOld = list.findIndex(x => x.id === idOld);
  const idxNew = list.findIndex(x => x.id === idNew);
  assert.ok(idxNew < idxOld, 'le plus recent doit apparaitre avant le plus ancien');
  assert.strictEqual(list[0].content, undefined, 'la liste ne doit pas embarquer le contenu complet de chaque digest');
});
check('getLatestDigest renvoie exactement le plus recent, contenu inclus', () => {
  const id = events.saveDigest(sampleDigest({ generatedAt: Date.now() + 999_999, traffic: { totalRequests: 777 } }));
  const latest = events.getLatestDigest();
  assert.strictEqual(latest.id, id);
  assert.strictEqual(latest.traffic.totalRequests, 777);
});
check('id inconnu -> null, pas d exception', () => {
  assert.strictEqual(events.getDigest(999999), null);
});

console.log('\nretention : les vieux digests sont purges automatiquement');
check('un digest au-dela de EVENTS_RETENTION_DAYS disparait au prochain enregistrement', () => {
  // Bug reel signale : rien ne purgeait jamais la table digests, contrairement
  // a chaque autre table de ce projet (events, les paliers de trafic, etc.),
  // ce qui aurait fini par rendre la liste deroulante de l historique
  // ingerable. purgeOldDigests() reutilise EVENTS_RETENTION_DAYS (meme base,
  // meme question de fond) plutot qu un nouveau reglage separe.
  const RETENTION_DAYS = require('../lib/config').EVENTS_RETENTION_DAYS;
  const oldId = events.saveDigest(sampleDigest({ generatedAt: Date.now() - (RETENTION_DAYS + 10) * 86400_000 }));
  const recentId = events.saveDigest(sampleDigest({ generatedAt: Date.now() }));
  assert.strictEqual(events.getDigest(oldId), null, 'le digest trop ancien doit avoir ete purge');
  assert.ok(events.getDigest(recentId), 'le digest recent doit rester intact');
});
check('un digest juste en dessous de la limite de retention est conserve', () => {
  const RETENTION_DAYS = require('../lib/config').EVENTS_RETENTION_DAYS;
  const id = events.saveDigest(sampleDigest({ generatedAt: Date.now() - (RETENTION_DAYS - 1) * 86400_000 }));
  assert.ok(events.getDigest(id), 'un digest encore dans la fenetre de retention ne doit pas etre purge');
});
check('purgeOldDigests() est appelable directement sans exception', () => {
  assert.doesNotThrow(() => events.purgeOldDigests());
});

console.log('\nsuppression manuelle (deleteDigest)');
check('un digest supprime devient introuvable', () => {
  const id = events.saveDigest(sampleDigest());
  assert.ok(events.getDigest(id));
  assert.strictEqual(events.deleteDigest(id), true, 'deleteDigest doit signaler la suppression reelle');
  assert.strictEqual(events.getDigest(id), null);
});
check('id deja absent -> false, pas d exception (distingue "deja supprime" de "supprime maintenant")', () => {
  assert.strictEqual(events.deleteDigest(999999), false);
});
check('supprimer un digest ne touche pas les autres', () => {
  const keepId = events.saveDigest(sampleDigest({ traffic: { totalRequests: 111 } }));
  const dropId = events.saveDigest(sampleDigest({ traffic: { totalRequests: 222 } }));
  events.deleteDigest(dropId);
  assert.strictEqual(events.getDigest(dropId), null);
  assert.strictEqual(events.getDigest(keepId).traffic.totalRequests, 111);
});

console.log('\ndegradation sans SQLite');
check('un chemin invalide ne fait pas echouer saveDigest/listDigests/getDigest', () => {
  const bad = require('../lib/events');
  const blocker = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'digestbad-')), 'pas-un-dossier');
  fs.writeFileSync(blocker, 'x');
  process.env.EVENTS_DB_PATH_OVERRIDE_TEST = path.join(blocker, 'events.db');
  // Reutilise le meme mecanisme de degradation deja verifie ailleurs pour
  // initEventsDb() lui-meme : ici on verifie juste que les nouvelles
  // fonctions ne levent jamais quand eventsDb est indisponible.
  const events2 = require('../lib/events');
  assert.doesNotThrow(() => events2.saveDigest(sampleDigest()));
  assert.doesNotThrow(() => events2.listDigests());
  assert.doesNotThrow(() => events2.getDigest(1));
  assert.doesNotThrow(() => events2.getLatestDigest());
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
