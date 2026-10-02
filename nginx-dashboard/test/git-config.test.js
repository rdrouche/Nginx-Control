'use strict';
/**
 * getGitCfg() (lib/git.js) — merge YAML/env pour les reglages Git, uniformise
 * avec la meme regle que ANALYZER_DEFAULT_IMAGE : un champ YAML renseigne
 * l emporte, un champ absent/vide retombe sur la variable Docker. GIT_SSH_KEY
 * reste volontairement hors du fichier YAML (chemin de montage fixe par
 * docker-compose.yml, pas un reglage de comportement) : ce test verifie que
 * getGitCfg() l ignore meme si un fichier hostile tentait de le fournir.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshEnv(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitcfg-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  for (const k of ['GIT_REPO_URL', 'GIT_BRANCH', 'GIT_BACKUP_BRANCH', 'GIT_TOKEN', 'GIT_SSH_KEY', 'GIT_USER_NAME', 'GIT_USER_EMAIL']) {
    delete process.env[k];
  }
  Object.assign(process.env, env || {});
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/git')];
  return { dir, git: require('../lib/git') };
}

console.log('\ngetGitCfg() — sans fichier YAML');
(() => {
  const { dir, git } = freshEnv({ GIT_REPO_URL: 'https://forge.example.com/env/repo.git', GIT_BRANCH: 'env-branch' });
  check('retombe integralement sur les variables Docker (pas de git.yml)', () => {
    const g = git.getGitCfg();
    assert.strictEqual(g.repoUrl, 'https://forge.example.com/env/repo.git');
    assert.strictEqual(g.branch, 'env-branch');
    assert.strictEqual(g.backupBranch, 'backup');
    assert.strictEqual(g.userName, 'Nginx Dashboard');
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGitCfg() — YAML present mais champs vides');
(() => {
  const { dir, git } = freshEnv({ GIT_REPO_URL: 'https://forge.example.com/env/repo.git', GIT_BRANCH: 'env-branch' });
  fs.writeFileSync(git.GIT_CONFIG_FILE, [
    'repo_url:',
    'branch:',
    'backup_branch:',
    'token:',
    'user_name:',
    'user_email:',
    '',
  ].join('\n'));
  check('un champ vide dans le YAML ne remplace pas la variable Docker', () => {
    const g = git.getGitCfg();
    assert.strictEqual(g.repoUrl, 'https://forge.example.com/env/repo.git');
    assert.strictEqual(g.branch, 'env-branch');
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGitCfg() — YAML prioritaire quand renseigne');
(() => {
  const { dir, git } = freshEnv({ GIT_REPO_URL: 'https://forge.example.com/env/repo.git', GIT_BRANCH: 'env-branch' });
  fs.writeFileSync(git.GIT_CONFIG_FILE, [
    'repo_url: https://forge.example.com/yaml/repo.git',
    'branch: yaml-branch',
    'backup_branch: yaml-backup',
    'token: yaml-token',
    'user_name: Yaml User',
    'user_email: yaml@example.com',
    '',
  ].join('\n'));
  check('le YAML l emporte sur la variable Docker champ par champ', () => {
    const g = git.getGitCfg();
    assert.strictEqual(g.repoUrl, 'https://forge.example.com/yaml/repo.git');
    assert.strictEqual(g.branch, 'yaml-branch');
    assert.strictEqual(g.backupBranch, 'yaml-backup');
    assert.strictEqual(g.token, 'yaml-token');
    assert.strictEqual(g.userName, 'Yaml User');
    assert.strictEqual(g.userEmail, 'yaml@example.com');
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngetGitCfg() — GIT_SSH_KEY reste hors YAML');
(() => {
  const { dir, git } = freshEnv({ GIT_SSH_KEY: '/run/secrets/id_ed25519' });
  fs.writeFileSync(git.GIT_CONFIG_FILE, [
    'ssh_key: /tentative/malveillante',
    '',
  ].join('\n'));
  check('un champ ssh_key dans le YAML est ignore, GIT_SSH_KEY vient toujours de l env', () => {
    const g = git.getGitCfg();
    assert.strictEqual(g.sshKey, '/run/secrets/id_ed25519');
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\ngitEnv() — verification de la cle hote SSH (fix, audit report Basse/"Sécurité et durcissement")');
(() => {
  const { dir, git } = freshEnv({ GIT_SSH_KEY: '/run/secrets/id_ed25519' });
  const env = git.gitEnv(git.getGitCfg());
  check('StrictHostKeyChecking=no a disparu (verification MITM desactivee)', () => {
    assert.ok(!/StrictHostKeyChecking=no\b/.test(env.GIT_SSH_COMMAND),
      `GIT_SSH_COMMAND desactive encore toute verification : ${env.GIT_SSH_COMMAND}`);
  });
  check('accept-new est utilise a la place (verifie apres la premiere connexion, sans prompt interactif)', () => {
    assert.ok(/StrictHostKeyChecking=accept-new\b/.test(env.GIT_SSH_COMMAND));
  });
  check('un UserKnownHostsFile persistant (sous CONFIG_DIR) est fourni', () => {
    assert.ok(env.GIT_SSH_COMMAND.includes(`UserKnownHostsFile=${dir}`),
      `known_hosts ne pointe pas vers CONFIG_DIR : ${env.GIT_SSH_COMMAND}`);
  });
  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
