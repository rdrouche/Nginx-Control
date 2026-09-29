'use strict';
/**
 * Editeur generique (features/config-editor.js) — le point critique n est
 * pas la lecture/ecriture elle-meme (deja eprouvee par le meme mecanisme
 * dans notifications.js et godns.js) mais deux choses propres a cette
 * variante generique :
 *  - la cle envoyee par le client ne resout JAMAIS un chemin arbitraire,
 *    seulement l un des fichiers de la liste fixe FILES ;
 *  - un secret (license_key, credentials_host_path, etc.) renvoye masque
 *    et resauvegarde sans modification n ecrase jamais la vraie valeur.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshEnv() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgeditor-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/secrets')];
  delete require.cache[require.resolve('../features/config-editor')];
  return { dir, CE: require('../features/config-editor') };
}

console.log('\nliste fixe des fichiers geres');
(() => {
  const { CE } = freshEnv();
  check('exactement les treize fichiers geres par l editeur generique', () => {
    const keys = CE.FILES.map(f => f.key).sort();
    assert.deepStrictEqual(keys, ['agents', 'analyzer', 'blocklists', 'certbot', 'certbot-dns', 'crowdsec', 'deploy-tokens', 'docker-autoconfig', 'error-pages', 'geoipupdate', 'git', 'goaccess', 'godns']);
  });
  check('aucun chemin en dehors de CONFIG_DIR', () => {
    for (const f of CE.FILES) {
      assert.ok(f.file.startsWith(process.env.CONFIG_DIR), `${f.key} pointe hors de CONFIG_DIR : ${f.file}`);
    }
  });
})();

console.log('\nmasquage/preservation des secrets (meme mecanisme que notifications.js/godns.js)');
(() => {
  const { dir, CE } = freshEnv();
  const { maskSecretsInConfig, unmaskSecrets } = require('../lib/secrets');
  const certbotDnsFile = CE.FILES.find(f => f.key === 'certbot-dns').file;
  fs.writeFileSync(certbotDnsFile, [
    'enable: true',
    'provider: cloudflare',
    'credentials_host_path: /containers/dns/credentials.ini',
    'email: admin@example.com',
    '',
  ].join('\n'));

  check('credentials_host_path n est PAS un champ masque (chemin, pas un secret)', () => {
    const raw = fs.readFileSync(certbotDnsFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    assert.ok(masked.includes('/containers/dns/credentials.ini'));
  });

  // Simule un fichier contenant un vrai champ secret (ex. licence GeoIP) pour
  // verifier le mecanisme de masquage/reinjection tel qu utilise par
  // config-editor.js — le meme lib/secrets.js que notifications.js.
  const geoFile = CE.FILES.find(f => f.key === 'geoipupdate').file;
  fs.writeFileSync(geoFile, [
    'enable: true',
    'license_key: SECRET-ABC-123',
    'account_id: 456',
    '',
  ].join('\n'));

  check('license_key est masque a la lecture', () => {
    const raw = fs.readFileSync(geoFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    assert.ok(!masked.includes('SECRET-ABC-123'), 'le secret ne doit jamais apparaitre en clair');
    assert.ok(masked.includes('********'));
  });

  check('resauvegarder le texte masque tel quel preserve la vraie valeur', () => {
    const raw = fs.readFileSync(geoFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    // Le client renvoie exactement ce qu il a recu (n a pas touche au champ secret).
    const restored = unmaskSecrets(masked, raw);
    assert.ok(restored.includes('SECRET-ABC-123'), 'la vraie valeur doit etre reinjectee, pas ecrasee par ********');
  });

  check('un champ explicitement change par le client est bien pris en compte', () => {
    const raw = fs.readFileSync(geoFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    const edited = masked.replace('********', 'NOUVELLE-CLE');
    const restored = unmaskSecrets(edited, raw);
    assert.ok(restored.includes('NOUVELLE-CLE'));
    assert.ok(!restored.includes('SECRET-ABC-123'));
  });

  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log('\nmasquage de machine_password (crowdsec.yml)');
(() => {
  const { dir, CE } = freshEnv();
  const { maskSecretsInConfig, unmaskSecrets } = require('../lib/secrets');
  const crowdsecFile = CE.FILES.find(f => f.key === 'crowdsec').file;
  fs.writeFileSync(crowdsecFile, [
    'url: http://crowdsec:8080',
    'api_key: BOUNCER-KEY-XYZ',
    'machine_id: dashboard-watcher',
    'machine_password: SECRET-MACHINE-PW',
    '',
  ].join('\n'));

  check('machine_password est masque a la lecture (ajoute a SECRET_KEY_RE)', () => {
    const raw = fs.readFileSync(crowdsecFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    assert.ok(!masked.includes('SECRET-MACHINE-PW'), 'le mot de passe machine ne doit jamais apparaitre en clair');
    assert.ok(masked.includes('********'));
  });

  check('api_key (bouncer) est aussi masque', () => {
    const raw = fs.readFileSync(crowdsecFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    assert.ok(!masked.includes('BOUNCER-KEY-XYZ'));
  });

  check('machine_id (pas un secret) reste en clair', () => {
    const raw = fs.readFileSync(crowdsecFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    assert.ok(masked.includes('dashboard-watcher'));
  });

  check('resauvegarder tel quel preserve machine_password', () => {
    const raw = fs.readFileSync(crowdsecFile, 'utf8');
    const masked = maskSecretsInConfig(raw);
    const restored = unmaskSecrets(masked, raw);
    assert.ok(restored.includes('SECRET-MACHINE-PW'));
  });

  fs.rmSync(dir, { recursive: true, force: true });
})();

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
