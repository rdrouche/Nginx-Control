'use strict';
/**
 * Fix, audit report Basse/"Sécurité et durcissement" : /api/nginx/test-verbose
 * exigeait seulement VIEW_CONFIGS (que possède un simple viewer) alors qu il
 * declenche, sur un test en echec, un dump complet de la config effective
 * (`nginx -T`) et une notification d erreur (email/webhook) — deux actions a
 * effet de bord, pas une simple lecture. Desormais aligne sur NGINX_CONTROL,
 * comme /api/nginx/test juste au-dessus dans le meme fichier.
 */
const assert = require('assert');
const { PERMS, roleHasPerm } = require('../lib/auth');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nfeatures/nginx-control.js — permission de /api/nginx/test-verbose');
check('la route exige bien NGINX_CONTROL, pas seulement VIEW_CONFIGS', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'features', 'nginx-control.js'), 'utf8');
  const routeIdx = src.indexOf("/api/nginx/test-verbose");
  const guardIdx = src.indexOf('hasPerm(session,', routeIdx);
  const guardLine = src.slice(guardIdx, guardIdx + 60);
  assert.ok(guardLine.includes('PERMS.NGINX_CONTROL'),
    `la garde de /api/nginx/test-verbose n utilise pas NGINX_CONTROL : "${guardLine}"`);
});
check('un role viewer n a PAS la permission NGINX_CONTROL (donc n atteint plus cette route)', () => {
  assert.strictEqual(roleHasPerm('viewer', PERMS.NGINX_CONTROL), false);
});
check('un role operator/admin garde bien acces (aucune regression pour les roles habilites)', () => {
  assert.strictEqual(roleHasPerm('operator', PERMS.NGINX_CONTROL), true);
  assert.strictEqual(roleHasPerm('admin', PERMS.NGINX_CONTROL), true);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
