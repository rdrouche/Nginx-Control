'use strict';
/**
 * lib/page-routes.js — la table slug<->page unique qui porte le
 * deep-linking (v12.31.0). Le risque principal ici n'est pas la logique
 * (une poignee d'objets statiques) mais la DERIVE : une page ajoutee dans
 * public/index.html sans etre ajoutee a PAGES, ou l'inverse.
 */
const assert = require('assert'), fs = require('fs'), path = require('path');
const R = require('../lib/page-routes');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\ncoherence PAGE_TO_SLUG / SLUG_TO_PAGE');
check('chaque page de PAGES a un slug, chaque slug retrouve sa page', () => {
  for (const page of R.PAGES) {
    const slug = R.PAGE_TO_SLUG[page];
    assert.ok(slug, `pas de slug pour "${page}"`);
    assert.strictEqual(R.SLUG_TO_PAGE[slug], page, `SLUG_TO_PAGE["${slug}"] ne repointe pas vers "${page}"`);
  }
});
check('aucun doublon de slug (deux pages qui se marcheraient dessus en URL)', () => {
  const slugs = R.PAGES.map(p => R.PAGE_TO_SLUG[p]);
  assert.strictEqual(new Set(slugs).size, slugs.length, 'des pages differentes partagent le meme slug');
});
check('les overrides demandes sont bien appliques (geomap -> map, logs -> live-logs)', () => {
  assert.strictEqual(R.PAGE_TO_SLUG.geomap, 'map');
  assert.strictEqual(R.PAGE_TO_SLUG.logs, 'live-logs');
  assert.strictEqual(R.SLUG_TO_PAGE.map, 'geomap');
  assert.strictEqual(R.SLUG_TO_PAGE['live-logs'], 'logs');
});
check('une page sans override garde son nom tel quel en slug', () => {
  assert.strictEqual(R.PAGE_TO_SLUG.overview, 'overview');
  assert.strictEqual(R.PAGE_TO_SLUG.waf, 'waf');
});

console.log('\npas de derive avec public/index.html (chaque data-page existe ici, et reciproquement)');
check('PAGES == l ensemble des data-page reellement presents dans index.html', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  const found = new Set([...html.matchAll(/data-page="([a-z-]+)"/g)].map(m => m[1]));
  const listed = new Set(R.PAGES);
  const missingFromList = [...found].filter(p => !listed.has(p));
  const missingFromHtml = [...listed].filter(p => !found.has(p));
  assert.deepStrictEqual(missingFromList, [], `data-page present dans index.html mais absent de lib/page-routes.js: ${missingFromList}`);
  assert.deepStrictEqual(missingFromHtml, [], `page listee dans lib/page-routes.js mais introuvable dans index.html: ${missingFromHtml}`);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
