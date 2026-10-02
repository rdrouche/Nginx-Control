'use strict';
/**
 * lib/git.js#ensureGitRepo() — retour utilisateur (v12.46.0) : le tout
 * premier clone dans DIR_GIT_WORK echouait apres quelques heures d usage,
 * "resolu" en pratique par un `docker compose down -v`. Cause reelle :
 * DIR_GIT_WORK sert aussi d espace de travail ephemere aux tests de config
 * (ALLOW_EDIT, ALLOW_CREATE — voir features/deploy.js#testConfigEphemeral()),
 * meme quand Git n est pas encore configure. Un test interrompu peut y
 * laisser un `.sandbox`/`.test-merge*` que `git clone` refuse ensuite
 * (repertoire non vide) — et le sweep existant ne se declenche qu au
 * PROCHAIN test, jamais sur ce chemin. Ce fichier verifie que ensureGitRepo()
 * nettoie desormais ces restes connus avant de cloner, et refuse
 * explicitement (sans jamais rien supprimer) si autre chose d inattendu
 * traine dans ce repertoire.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/git.js#ensureGitRepo() — restes de sandbox de test avant le premier clone');

/**
 * DIR_GIT_WORK est lu une seule fois par lib/config.js au chargement du
 * module (meme contrainte que test/system-info.test.js) — chaque scenario
 * isole ses env vars via un cache require frais.
 */
function freshGit(envOverrides) {
  const savedEnv = { ...process.env };
  Object.assign(process.env, envOverrides);
  for (const id of [require.resolve('../lib/config'), require.resolve('../lib/git')]) {
    delete require.cache[id];
  }
  const mod = require('../lib/git');
  process.env = savedEnv;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/git')];
  return mod;
}

(async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'git-ensure-repo-'));

  await (async () => {
    const workDir = path.join(tmpRoot, 'work-known-leftovers');
    fs.mkdirSync(path.join(workDir, '.sandbox', 'test_123'), { recursive: true });
    fs.writeFileSync(path.join(workDir, '.sandbox', 'test_123', 'leftover.txt'), 'x');
    fs.mkdirSync(path.join(workDir, '.test-merge'), { recursive: true });
    fs.mkdirSync(path.join(workDir, '.test-merge-generated'), { recursive: true });

    const { ensureGitRepo } = freshGit({
      DIR_GIT_WORK: workDir,
      // Port ferme -> le client git echoue vite (connexion refusee), pas de
      // timeout de 120s a attendre : seul le comportement AVANT le clone
      // nous interesse ici.
      GIT_REPO_URL: 'https://127.0.0.1:1/unreachable.git',
      GIT_BRANCH: 'main',
    });

    try {
      await ensureGitRepo();
      fail++; console.log('  FAIL  restes connus : le clone (URL injoignable) aurait du echouer');
    } catch (e) {
      const msg = e.error || e.message || String(e);
      check('restes connus (.sandbox/.test-merge*) nettoyes avant le clone, seule l\'erreur reseau remonte', () => {
        assert.ok(!/n'est pas vide/.test(msg), `ne doit pas etre bloque par des restes connus : ${msg}`);
        assert.ok(!fs.existsSync(path.join(workDir, '.sandbox')), '.sandbox aurait du etre nettoye avant le clone');
        assert.ok(!fs.existsSync(path.join(workDir, '.test-merge')), '.test-merge aurait du etre nettoye avant le clone');
        assert.ok(!fs.existsSync(path.join(workDir, '.test-merge-generated')), '.test-merge-generated aurait du etre nettoye avant le clone');
      });
    }
  })();

  await (async () => {
    const workDir = path.join(tmpRoot, 'work-unknown-leftover');
    fs.mkdirSync(workDir, { recursive: true });
    fs.writeFileSync(path.join(workDir, 'mystery.txt'), 'x');

    const { ensureGitRepo } = freshGit({
      DIR_GIT_WORK: workDir,
      // Jamais atteinte : le controle du repertoire doit echouer avant que
      // cette URL (invalide) ne soit meme regardee.
      GIT_REPO_URL: 'not-a-valid-url',
      GIT_BRANCH: 'main',
    });

    try {
      await ensureGitRepo();
      fail++; console.log('  FAIL  reste inconnu : ensureGitRepo() aurait du refuser de cloner');
    } catch (e) {
      const msg = e.message || String(e);
      check('reste inconnu (mystery.txt) : clone refuse, fichier jamais supprime, message actionnable', () => {
        assert.ok(/n'est pas vide/.test(msg), `message attendu sur repertoire non vide : ${msg}`);
        assert.ok(msg.includes('mystery.txt'), `le nom du fichier en trop doit apparaitre dans le message : ${msg}`);
        assert.ok(fs.existsSync(path.join(workDir, 'mystery.txt')), 'un fichier inconnu ne doit jamais etre supprime automatiquement');
      });
    }
  })();

  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
