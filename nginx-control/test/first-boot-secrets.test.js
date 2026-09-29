'use strict';
/**
 * v12.32.0 — simplification du premier demarrage :
 *  - SESSION_SECRET, non definie manuellement, est generee UNE SEULE FOIS et
 *    persistee (au lieu d etre re-generee a chaque boot, ce qui invalidait
 *    silencieusement toutes les sessions actives a chaque redemarrage) ;
 *  - une valeur manuelle (env) garde TOUJOURS priorite sur la valeur generee ;
 *  - le compte admin livre avec le mot de passe d exemple "admin" est
 *    remplace automatiquement par un mot de passe aleatoire au premier
 *    demarrage, sans jamais toucher a un mot de passe choisi par l operateur.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshConfig(env) {
  delete require.cache[require.resolve('../lib/config')];
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; process.env[k] = env[k]; }
  const cfg = require('../lib/config');
  for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  return cfg;
}

console.log('\nSESSION_SECRET : generation unique et persistee (config/ est un volume monte, donc ca survit aux redemarrages)');
(() => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'first-boot-'));
  const usersFile = path.join(tmp, 'users.yml');
  fs.writeFileSync(usersFile, 'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

  delete process.env.SESSION_SECRET;
  const cfg1 = freshConfig({ USERS_FILE: usersFile });
  const generatedFile = path.join(tmp, '.generated-secrets.json');
  check('config/.generated-secrets.json est cree au premier boot', () => assert.ok(fs.existsSync(generatedFile)));
  check('SESSION_SECRET est une chaine non vide', () => assert.ok(cfg1.SESSION_SECRET && cfg1.SESSION_SECRET.length >= 32));

  const cfg2 = freshConfig({ USERS_FILE: usersFile });
  check('un second boot (sans env) reutilise EXACTEMENT la meme valeur, pas une nouvelle', () => {
    assert.strictEqual(cfg2.SESSION_SECRET, cfg1.SESSION_SECRET);
  });

  const cfg3 = freshConfig({ USERS_FILE: usersFile, SESSION_SECRET: 'ma-valeur-manuelle-a-moi' });
  check('une valeur manuelle (env) gagne toujours sur la valeur generee, meme si un fichier genere existe deja', () => {
    assert.strictEqual(cfg3.SESSION_SECRET, 'ma-valeur-manuelle-a-moi');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

console.log('\nadmin/admin (mot de passe d exemple livre) : remplace automatiquement au premier boot, une valeur manuelle ne l est jamais');
(() => {
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/auth')];

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'first-boot-admin-'));
  const usersFile = path.join(tmp, 'users.yml');
  fs.writeFileSync(usersFile, 'users:\n  - username: admin\n    password: admin\n    role: admin\n    name: A\n    enabled: true\n');
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  const auth = require('../lib/auth');

  const users = auth.getUsers();
  check('le compte admin livre avec "admin" est rehash e avec une AUTRE valeur, jamais laisse en clair', () => {
    assert.ok(users[0].password.startsWith('scrypt:') || users[0].password.startsWith('sha256:'));
  });
  check('le litteral "admin" ne fonctionne plus comme mot de passe apres coup', () => {
    assert.strictEqual(auth.verifyCredentials('admin', 'admin'), null);
  });
  check('users.yml sur disque ne contient plus jamais "password: admin" en clair', () => {
    const onDisk = fs.readFileSync(usersFile, 'utf8');
    assert.ok(!/password:\s*admin\s*$/m.test(onDisk));
  });

  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/auth')];
  delete process.env.USERS_FILE;

  fs.rmSync(tmp, { recursive: true, force: true });
})();

console.log('\nadmin avec un mot de passe manuel (meme faible) : jamais touche par la generation automatique');
(() => {
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/auth')];

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'first-boot-manual-'));
  const usersFile = path.join(tmp, 'users.yml');
  fs.writeFileSync(usersFile, 'users:\n  - username: admin\n    password: mon-choix-a-moi\n    role: admin\n    name: A\n    enabled: true\n');
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  const auth = require('../lib/auth');

  check('un mot de passe manuel (different du litteral "admin") est hashe normalement et reste utilisable', () => {
    assert.ok(auth.verifyCredentials('admin', 'mon-choix-a-moi'));
  });

  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/auth')];
  delete process.env.USERS_FILE;

  fs.rmSync(tmp, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
