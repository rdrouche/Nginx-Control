'use strict';
/**
 * Fix, audit finding MISC-12 : trois bugs distincts dans la surveillance
 * continue des backends (features/monitor.js, lib/vhost-targets.js,
 * lib/monitor-store.js) :
 *
 *  - un vhost `.conf.DISABLE` (jamais charge par nginx) etait quand meme
 *    scanne pour le flag de monitoring et sonde comme un vhost actif ;
 *  - resolveProxyPass() recevait le contenu ENTIER du fichier plutot que le
 *    bloc server{} courant : un fichier a plusieurs blocs server{} (chacun
 *    avec son propre `set $backend ...;`) resolvait tout sauf le premier
 *    bloc vers la mauvaise cible ;
 *  - un incident ouvert sous une cle qui cesse d etre surveillee (fichier
 *    edite/supprime, flag coupe, cle decalee) ne recevait plus jamais
 *    d appel recordCheck() et restait "down" pour toujours.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'misc12-'));
const usersFile = path.join(tmp, 'config', 'users.yml');
fs.mkdirSync(path.join(tmp, 'config'), { recursive: true });
fs.writeFileSync(usersFile, 'users: []\n');
process.env.USERS_FILE = usersFile;
const sitesDir = path.join(tmp, 'sites');
const confDir  = path.join(tmp, 'conf');
fs.mkdirSync(sitesDir, { recursive: true });
fs.mkdirSync(confDir,  { recursive: true });
process.env.DIR_SITES = sitesDir;
process.env.DIR_CONF  = confDir;

const { resolveProxyPass, parseVhostFile } = require('../lib/vhost-targets');

console.log('\nlib/vhost-targets.js — resolveProxyPass scope au bloc server{}, pas au fichier entier');
(() => {
  // Deux blocs server{} dans le MEME fichier, chacun definissant sa propre
  // variable $backend — exactement la forme emise par vhost-generator.js.
  const content = `
server {
  server_name a.example.com;
  set $backend http://container-a:8080;
  resolver 127.0.0.11 valid=30s;
  location / { proxy_pass $backend; }
}
server {
  server_name b.example.com;
  set $backend http://container-b:9090;
  resolver 127.0.0.11 valid=30s;
  location / { proxy_pass $backend; }
}
`;
  const blocks = parseVhostFile(content, {});
  check('deux blocs extraits', () => assert.strictEqual(blocks.length, 2));
  check('le premier bloc resout vers SA propre variable (container-a)', () => {
    assert.strictEqual(blocks[0].locations[0].targets[0].host, 'container-a');
  });
  check('le second bloc resout vers SA PROPRE variable (container-b), pas celle du premier bloc', () => {
    assert.strictEqual(blocks[1].locations[0].targets[0].host, 'container-b',
      'le second bloc a recu la cible du premier — resolveProxyPass a cherche le "set" dans tout le fichier au lieu du bloc courant');
  });
})();

console.log('\nfeatures/monitor.js — un vhost .conf.DISABLE n est pas surveille');
(() => {
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/monitor')];
  delete require.cache[require.resolve('../lib/monitor-store')];
  const monitor = require('../features/monitor');
  const monitorStore = require('../lib/monitor-store');
  monitorStore.closeDb(); // force memory mode, isolated from any real DB path

  fs.writeFileSync(path.join(sitesDir, 'active.conf'),
    'server {\n  server_name active.example.com;\n  # nginx-control-monitoring: on\n' +
    '  location / { proxy_pass http://127.0.0.1:65000; }\n}\n');
  fs.writeFileSync(path.join(sitesDir, 'disabled.conf.DISABLE'),
    'server {\n  server_name disabled.example.com;\n  # nginx-control-monitoring: on\n' +
    '  location / { proxy_pass http://127.0.0.1:65001; }\n}\n');

  const targets = monitor.rescan();
  const vhostNames = [...targets.values()].map(t => t.vhostName);
  check('le vhost actif est surveille', () => assert.ok(vhostNames.includes('active.conf')));
  check('le vhost .DISABLE n est PAS surveille malgre son flag de monitoring', () => {
    assert.ok(!vhostNames.includes('disabled.conf.DISABLE'),
      'un vhost desactive (jamais charge par nginx) a ete sonde comme un vhost actif');
  });

  console.log('\nlib/monitor-store.js — un incident orphelin (cle qui disparait) est referme, pas laisse ouvert pour toujours');
  return (async () => {
    monitor.setDeps({ checkTarget: async () => ({ ok: false, error: 'connection refused' }) });
    await monitor.tick(Date.now(), { force: true });
    const key = [...targets.keys()].find(k => k.startsWith(path.join(sitesDir, 'active.conf')));
    const before = monitorStore.getIncidents(key, 1)[0];
    await check('l incident est bien ouvert apres la premiere sonde en echec', () => {
      assert.ok(before, 'aucun incident cree');
      assert.strictEqual(before.endedAt, null);
    });

    // Le vhost est supprime (ou son flag coupe) — la cle disparait du prochain rescan.
    fs.rmSync(path.join(sitesDir, 'active.conf'));
    monitor.rescan();
    const after = monitorStore.getIncidents(key, 1)[0];
    await check('l incident est referme au rescan qui suit la disparition de la cible', () => {
      assert.ok(after, 'l incident a disparu au lieu d etre simplement referme');
      assert.notStrictEqual(after.endedAt, null, 'l incident est reste ouvert indefiniment');
    });
  })();
})().then(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
});
