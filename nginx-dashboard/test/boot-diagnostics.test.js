'use strict';
/**
 * Un operateur a vu "Cannot read /config/users.yml: ENOENT" au demarrage et
 * a soupçonne un probleme d encodage CRLF/LF — ENOENT signifie que le chemin
 * n existe pas du tout, une cause sans rapport. Le repli sur un compte
 * admin:admin par defaut fonctionnait deja sans planter, mais son
 * avertissement se perdait au milieu du reste des journaux de demarrage.
 * Un diagnostic explicite tourne desormais en tout premier, avant meme le
 * chargement des utilisateurs.
 */
const assert = require('assert'), fs = require('fs'), path = require('path'), os = require('os');
const { spawn } = require('child_process');
let pass = 0, fail = 0;
const check = async (n, f) => {
  try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
};

const root = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boot-diag-'));
for (const d of ['sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });

function bootWith(usersFile, port) {
  return new Promise((resolve) => {
    const env = { ...process.env, PORT: String(port), SESSION_SECRET: 'x',
      USERS_FILE: usersFile,
      DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
      DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
      DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
      DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
      DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs') };
    const p = spawn('node', [path.join(root, 'server.js')], { env, cwd: root });
    let out = '';
    p.stdout.on('data', d => out += d);
    p.stderr.on('data', d => out += d);
    setTimeout(() => { p.kill(); resolve(out); }, 1500);
  });
}

(async () => {
  console.log('\ndiagnostic au demarrage : repertoire de configuration');
  await check('un chemin manquant produit un avertissement explicite, avant loadUsers', async () => {
    const out = await bootWith(path.join(tmp, 'n-existe-vraiment-pas', 'users.yml'), 3969);
    assert.ok(/\[boot\] Config directory missing/.test(out),
      'le diagnostic explicite doit apparaitre au demarrage');
    const bootIdx = out.indexOf('[boot] Config directory missing');
    const authIdx = out.indexOf('[auth] Cannot read');
    assert.ok(bootIdx >= 0 && authIdx >= 0 && bootIdx < authIdx,
      'le diagnostic clair doit precéder le message cryptique original, pas le suivre');
  });
  await check('un repertoire present et accessible ne declenche aucun avertissement de demarrage', async () => {
    const usersFile = path.join(tmp, 'conf', 'users.yml');
    fs.writeFileSync(usersFile, 'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
    const out = await bootWith(usersFile, 3968);
    assert.ok(!/\[boot\] Config directory/.test(out));
  });
  await check('le controle est bien present dans le code (garde contre une regression future)', () => {
    const src = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
    assert.ok(/checkConfigDirAtBoot/.test(src));
    assert.ok(/fs\.constants\.W_OK/.test(src), 'doit verifier aussi l ecriture, pas seulement l existence');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
