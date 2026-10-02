'use strict';
/**
 * Fix, audit finding MISC-10 : un commentaire en fin de ligne (`enable:
 * false  # pause`) devenait partie de la valeur dans tous les loaders YAML
 * "plats" du projet sauf lib/notify.js (qui avait deja son propre correctif,
 * MISC-06-adjacent). `"false  # pause"` n est pas strictement egal a
 * `'false'`, donc un flag qu on croyait desactiver restait actif.
 *
 * lib/simple-yaml.js centralise desormais stripInlineComment/parseFlatYaml ;
 * ce fichier verifie le module partage lui-meme, puis chaque loader qui s en
 * sert (godns, geoipupdate, goaccess, crowdsec-cfg, blocklist-yaml) avec une
 * config ecrite sur disque, comme ces loaders la lisent reellement.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'simple-yaml-'));
process.env.USERS_FILE = path.join(tmp, 'config', 'users.yml');
fs.mkdirSync(path.join(tmp, 'config'), { recursive: true });
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const { stripInlineComment, parseFlatYaml } = require('../lib/simple-yaml');

console.log('\nlib/simple-yaml.js — stripInlineComment/parseFlatYaml');

check('valeur non guillemetee : commentaire en fin de ligne retire', () => {
  assert.strictEqual(stripInlineComment('false  # pause'), 'false');
});
check('valeur guillemetee : le commentaire apres le guillemet fermant est retire', () => {
  assert.strictEqual(stripInlineComment('"0 3 * * *"  # tous les jours a 3h'), '"0 3 * * *"');
});
check('un # colle a la valeur (pas precede d espace) reste dans la valeur', () => {
  assert.strictEqual(stripInlineComment('foo#bar'), 'foo#bar');
});
check('parseFlatYaml : enable desactive malgre un commentaire sur la meme ligne', () => {
  const y = parseFlatYaml('enable: false  # temporairement coupe\nport: 9000\n');
  assert.strictEqual(y.enable, 'false');
  assert.strictEqual(y.port, '9000');
});
check('parseFlatYaml : lignes vides et commentaires de ligne entiere ignores', () => {
  const y = parseFlatYaml('# commentaire\n\nfoo: bar\n');
  assert.deepStrictEqual(y, { foo: 'bar' });
});

console.log('\nfeatures/godns.js — loadGoDNSConfig respecte les commentaires en fin de ligne');
(() => {
  const cfgDir = path.join(tmp, 'godns-config');
  fs.mkdirSync(cfgDir, { recursive: true });
  const usersFile = path.join(cfgDir, 'users.yml');
  fs.writeFileSync(usersFile, 'users: []\n');
  const oldUsersFile = process.env.USERS_FILE;
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  fs.writeFileSync(path.join(cfgDir, 'godns.yml'),
    'enable: false  # desactive le temps de migrer le provider\ncontainer_name: godns\nport: 9000\n');
  delete require.cache[require.resolve('../features/godns')];
  const G = require('../features/godns');
  check('enable: false + commentaire -> reste desactive', () => {
    assert.strictEqual(G.getGoDNSCfg().enable, false);
  });
  process.env.USERS_FILE = oldUsersFile;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/godns')];
})();

console.log('\nfeatures/geoipupdate.js — loadGeoipupdateConfig respecte les commentaires en fin de ligne');
(() => {
  const cfgDir = path.join(tmp, 'geoip-config');
  fs.mkdirSync(cfgDir, { recursive: true });
  const usersFile = path.join(cfgDir, 'users.yml');
  fs.writeFileSync(usersFile, 'users: []\n');
  const oldUsersFile = process.env.USERS_FILE;
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  fs.writeFileSync(path.join(cfgDir, 'geoipupdate.yml'),
    'enable: false  # licence expiree\nfrequency_hours: 168\n');
  delete require.cache[require.resolve('../features/geoipupdate')];
  const GI = require('../features/geoipupdate');
  check('enable: false + commentaire -> reste desactive', () => {
    assert.strictEqual(GI.getGeoipupdateCfg().enable, false);
  });
  process.env.USERS_FILE = oldUsersFile;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
})();

console.log('\nfeatures/goaccess.js — getGoaccessCfg respecte les commentaires en fin de ligne');
(() => {
  const cfgDir = path.join(tmp, 'ga-config');
  fs.mkdirSync(cfgDir, { recursive: true });
  const usersFile = path.join(cfgDir, 'users.yml');
  fs.writeFileSync(usersFile, 'users: []\n');
  const oldUsersFile = process.env.USERS_FILE;
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  const cfgMod = require('../lib/config');
  fs.writeFileSync(cfgMod.GOACCESS_CONFIG_FILE,
    'log_format: combined  # format nginx par defaut\nrefresh_seconds: 5\n');
  delete require.cache[require.resolve('../features/goaccess')];
  const GA = require('../features/goaccess');
  check('log_format sans le commentaire colle a la fin', () => {
    assert.strictEqual(GA.getGoaccessCfg().logFormat, 'combined');
  });
  process.env.USERS_FILE = oldUsersFile;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/goaccess')];
})();

console.log('\nlib/crowdsec-cfg.js — getCrowdsecCfg respecte les commentaires en fin de ligne');
(() => {
  const cfgDir = path.join(tmp, 'cs-config');
  fs.mkdirSync(cfgDir, { recursive: true });
  const usersFile = path.join(cfgDir, 'users.yml');
  fs.writeFileSync(usersFile, 'users: []\n');
  const oldUsersFile = process.env.USERS_FILE;
  process.env.USERS_FILE = usersFile;
  delete require.cache[require.resolve('../lib/config')];
  const cfgMod = require('../lib/config');
  fs.writeFileSync(cfgMod.CROWDSEC_CONFIG_FILE,
    'url: http://crowdsec:8080  # LAPI interne\nlocal_only: true  # pas d acces externe\n');
  delete require.cache[require.resolve('../lib/crowdsec-cfg')];
  const CS = require('../lib/crowdsec-cfg');
  check('url sans le commentaire colle a la fin', () => {
    assert.strictEqual(CS.getCrowdsecCfg().url, 'http://crowdsec:8080');
  });
  check('local_only: true + commentaire -> bien interprete comme un booleen vrai', () => {
    assert.strictEqual(CS.getCrowdsecCfg().localOnly, true);
  });
  process.env.USERS_FILE = oldUsersFile;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/crowdsec-cfg')];
})();

console.log('\nlib/blocklist-yaml.js — parseScalar respecte les commentaires en fin de ligne');
(() => {
  const { parseBlocklistYaml } = require('../lib/blocklist-yaml');
  const { config, sources } = parseBlocklistYaml(
    'enable: false  # pause temporaire\n' +
    'sources:\n' +
    '  - name: datashield\n' +
    '    url: "https://example.org/list.txt"\n' +
    '    enable: false  # source cassee, a corriger\n'
  );
  check('config top-niveau : enable reste un booleen false malgre le commentaire', () => {
    assert.strictEqual(config.enable, false);
  });
  check('champ imbrique de la source : idem', () => {
    assert.strictEqual(sources[0].enable, false);
    assert.strictEqual(sources[0].url, 'https://example.org/list.txt');
  });
})();

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
