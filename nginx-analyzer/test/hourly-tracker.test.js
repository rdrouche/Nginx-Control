'use strict';
const assert = require('assert');
const { HourlyAccumulator } = require('../lib/hourly-tracker');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const H = 3_600_000;
const T0 = Date.parse('2026-09-09T14:00:00Z'); // pile sur une heure ronde

console.log('\nHourlyAccumulator (fix ANA-07)');

check('deux entrees de la meme heure/cle sont cumulees dans le meme accumulateur', () => {
  const a = new HourlyAccumulator();
  a.add(T0 + 1000, 'site.fr', () => ({ n: 0 }), m => m.n++);
  a.add(T0 + 2000, 'site.fr', () => ({ n: 0 }), m => m.n++);
  const [[hour, byKey]] = a.closeFinished(T0 + 3 * H); // largement clos
  assert.strictEqual(hour, T0);
  assert.strictEqual(byKey.get('site.fr').n, 2);
});

check('deux heures differentes ne se melangent jamais, meme entrelacees dans l ordre d arrivee', () => {
  // Reproduit le scenario du bug reel : des entrees de deux heures arrivent
  // entremelees (deux tailers qui avancent independamment), sans jamais se
  // marcher dessus grace a un accumulateur par heure plutot qu un seul
  // "heure courante" partage.
  const a = new HourlyAccumulator();
  a.add(T0,              'site.fr', () => ({ n: 0 }), m => m.n++);          // 14:00
  a.add(T0 + H + 1000,   'site.fr', () => ({ n: 0 }), m => m.n++);          // 15:00
  a.add(T0 + 500,        'site.fr', () => ({ n: 0 }), m => m.n++);          // encore 14:00 (arrivee tardive)
  a.add(T0 + H + 2000,   'site.fr', () => ({ n: 0 }), m => m.n++);          // encore 15:00
  const closed = a.closeFinished(T0 + 10 * H);
  const byHour = new Map(closed.map(([h, byKey]) => [h, byKey.get('site.fr').n]));
  assert.strictEqual(byHour.get(T0), 2, 'les deux entrees de 14:00 doivent etre comptees ensemble');
  assert.strictEqual(byHour.get(T0 + H), 2, 'les deux entrees de 15:00 doivent etre comptees ensemble, separement');
});

check('une heure n est fermee que plus de closeDelayMs apres sa fin (par defaut 1h) — pas au premier pas de temps suivant', () => {
  const a = new HourlyAccumulator();
  a.add(T0, 'site.fr', () => ({ n: 0 }), m => m.n++);
  // On est encore DANS l heure T0 (donc a fortiori pas 1h apres sa fin) :
  // rien ne doit se fermer, meme si "l heure courante" a change au sens
  // naif d un simple hourOf(now) !== hourOf(entryTs).
  assert.deepStrictEqual(a.closeFinished(T0 + 30 * 60_000), [], 'encore dans l heure -> rien a fermer');
  // Juste apres la fin de l heure (T0+H), toujours a l interieur du delai de
  // fermeture (1h) -> encore rien.
  assert.deepStrictEqual(a.closeFinished(T0 + H + 1000), [], 'heure finie mais dans le delai de fermeture -> encore ouverte');
  // Plus d une heure apres la fin de l heure -> fermee.
  const closed = a.closeFinished(T0 + 2 * H + 1000);
  assert.strictEqual(closed.length, 1);
  assert.strictEqual(closed[0][0], T0);
});

check('une heure fermee est retiree : la refermer ne la renvoie pas une seconde fois (pas de double comptage)', () => {
  // C est exactement le bug ANA-07 : avant le correctif, un redemarrage
  // pendant l heure en cours pouvait faire flusher deux fois la MEME heure
  // reelle (une fois via SIGTERM sur des donnees partielles, une fois a la
  // fermeture naturelle suivante). Ici, l API elle-meme garantit qu une
  // heure fermee disparait de l accumulateur et ne peut plus etre refermee.
  const a = new HourlyAccumulator();
  a.add(T0, 'site.fr', () => ({ n: 0 }), m => m.n++);
  const first = a.closeFinished(T0 + 2 * H + 1000);
  assert.strictEqual(first.length, 1);
  const second = a.closeFinished(T0 + 3 * H);
  assert.deepStrictEqual(second, [], 'la meme heure ne doit plus jamais etre rendue une fois fermee');
});

check('les heures sont rendues dans l ordre chronologique', () => {
  const a = new HourlyAccumulator();
  a.add(T0 + 2 * H, 'x', () => ({ n: 0 }), m => m.n++);
  a.add(T0,         'x', () => ({ n: 0 }), m => m.n++);
  a.add(T0 + H,     'x', () => ({ n: 0 }), m => m.n++);
  const closed = a.closeFinished(T0 + 10 * H);
  assert.deepStrictEqual(closed.map(([h]) => h), [T0, T0 + H, T0 + 2 * H]);
});

check('openHours() reflete les heures pas encore fermees', () => {
  const a = new HourlyAccumulator();
  a.add(T0, 'x', () => ({ n: 0 }), m => m.n++);
  a.add(T0 + H, 'x', () => ({ n: 0 }), m => m.n++);
  assert.deepStrictEqual(a.openHours(), [T0, T0 + H]);
  a.closeFinished(T0 + 2 * H + 1000); // ferme seulement T0
  assert.deepStrictEqual(a.openHours(), [T0 + H]);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
