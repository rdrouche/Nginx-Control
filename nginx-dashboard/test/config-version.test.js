'use strict';
/**
 * lib/config.js — VERSION.
 *
 * Avant ce changement, VERSION etait un litteral en dur dans le source
 * ("const VERSION = '12.x.y';"), a bumper a la main a chaque sortie —
 * alors que le Dockerfile a deja `ARG APP_VERSION` / `ENV APP_VERSION`
 * (docker-build.yml passe `--build-arg APP_VERSION=${TAG_NAME}` sur chaque
 * tag Git), pour l instant utilises seulement pour les labels OCI. Le tag
 * Git et le numero affiche par le dashboard (badge d en-tete,
 * window.DASHBOARD_VERSION, GET /api/status) pouvaient donc diverger
 * silencieusement d une release a l autre.
 *
 * Ce test verifie que lib/config.js lit desormais APP_VERSION comme
 * n importe quelle autre variable (meme mecanisme que
 * ANALYZER_DEFAULT_IMAGE), avec un repli raisonnable quand elle est absente
 * (execution hors conteneur, ex. ces tests eux-memes).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshConfig(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfg-version-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  delete process.env.APP_VERSION;
  Object.assign(process.env, env || {});
  delete require.cache[require.resolve('../lib/config')];
  const cfg = require('../lib/config');
  fs.rmSync(dir, { recursive: true, force: true });
  return cfg;
}

console.log('\nlib/config.js — VERSION injectable via APP_VERSION (ARG/ENV du Dockerfile)');

check('APP_VERSION absent -> repli sur une valeur par defaut non vide (execution hors conteneur, ex. ces tests)', () => {
  const cfg = freshConfig({});
  assert.ok(typeof cfg.VERSION === 'string' && cfg.VERSION.length > 0);
});

check('APP_VERSION="13.4.2" (valeur qu injecterait --build-arg APP_VERSION=${TAG_NAME}) -> VERSION la reprend telle quelle', () => {
  const cfg = freshConfig({ APP_VERSION: '13.4.2' });
  assert.strictEqual(cfg.VERSION, '13.4.2');
});

check('APP_VERSION="dev" (defaut de l ARG du Dockerfile quand aucun --build-arg n est passe) -> VERSION vaut "dev", pas le fallback', () => {
  // Ce cas est le point precis du bug signale : sans cette lecture d env,
  // un `docker build` sans --build-arg affichait quand meme l ancien
  // numero fige dans le source, jamais "dev" ni le vrai tag.
  const cfg = freshConfig({ APP_VERSION: 'dev' });
  assert.strictEqual(cfg.VERSION, 'dev');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
