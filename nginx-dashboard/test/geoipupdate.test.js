'use strict';
/**
 * geoipupdate — meme classe de bug que celle deja corrigee pour certbot :
 * un chemin hote non renseigne (geoip_host_path) doit se signaler par un
 * avertissement explicite plutot que de monter silencieusement un chemin
 * relatif que Docker resout contre son propre repertoire de travail.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const G = require('../features/geoipupdate');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nresolveGeoipHostPath — meme piege que resolveCertsHostPath pour certbot');
check('chemin explicite renvoye tel quel', () => {
  assert.strictEqual(G.resolveGeoipHostPath({ geoip_host_path: '/containers/nginx-rproxy/geoip_data' }),
    '/containers/nginx-rproxy/geoip_data');
});
check('espaces autour du chemin nettoyes', () => {
  assert.strictEqual(G.resolveGeoipHostPath({ geoip_host_path: '  /data/geoip  ' }), '/data/geoip');
});
check('non renseigne -> repli relatif "geoip_data" (documente comme casse probable)', () => {
  const warn = console.warn;
  let warned = false;
  console.warn = () => { warned = true; };
  try {
    assert.strictEqual(G.resolveGeoipHostPath({}), 'geoip_data');
  } finally { console.warn = warn; }
  assert.ok(warned, 'un chemin hote absent doit avertir, pas echouer silencieusement');
});
check('chaine vide -> meme repli que non renseigne', () => {
  const warn = console.warn; console.warn = () => {};
  try { assert.strictEqual(G.resolveGeoipHostPath({ geoip_host_path: '' }), 'geoip_data'); }
  finally { console.warn = warn; }
});

console.log('\ndatabaseStatus — age/taille des .mmdb, independamment des editions configurees');
check('fichier present -> exists:true avec taille et date', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-'));
  fs.writeFileSync(path.join(dir, 'GeoLite2-City.mmdb'), 'x'.repeat(100));
  process.env.DIR_GEOIP = dir;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  const dbs = G2.databaseStatus({ edition_ids: 'GeoLite2-City' });
  assert.strictEqual(dbs.length, 1);
  assert.strictEqual(dbs[0].edition, 'GeoLite2-City');
  assert.strictEqual(dbs[0].exists, true);
  assert.strictEqual(dbs[0].sizeBytes, 100);
  assert.ok(dbs[0].mtime);
});
check('fichier absent -> exists:false, pas d exception', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-empty-'));
  process.env.DIR_GEOIP = dir;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  const dbs = G2.databaseStatus({ edition_ids: 'GeoLite2-ASN' });
  assert.deepStrictEqual(dbs, [{ edition: 'GeoLite2-ASN', exists: false, sizeBytes: null, mtime: null }]);
});
check('edition_ids absent -> retombe sur les trois editions par defaut', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-default-'));
  process.env.DIR_GEOIP = dir;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  const dbs = G2.databaseStatus({});
  assert.deepStrictEqual(dbs.map(d => d.edition), ['GeoLite2-City', 'GeoLite2-Country', 'GeoLite2-ASN']);
});

console.log('\nloadGeoipupdateConfig — fichier absent, booleens et entiers');
check('fichier absent -> null, pas d exception', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-noconf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  assert.strictEqual(G2.loadGeoipupdateConfig(), null);
});
check('enable/frequency_hours types correctement, license_key preservee telle quelle', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-conf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  fs.writeFileSync(path.join(dir, 'geoipupdate.yml'), [
    'enable: true',
    'account_id: 123456',
    'license_key: abcDEF123',
    'edition_ids: GeoLite2-City GeoLite2-ASN',
    'frequency_hours: 72',
    'geoip_host_path: /data/geoip',
    '',
  ].join('\n'));
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  const cfg = G2.loadGeoipupdateConfig();
  assert.strictEqual(cfg.enable, true);
  assert.strictEqual(cfg.frequency_hours, 72);
  assert.strictEqual(cfg.license_key, 'abcDEF123');
  assert.strictEqual(cfg.geoip_host_path, '/data/geoip');
});
check('frequency_hours absent ou invalide -> repli a 168 (une semaine)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoiptest-conf2-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  fs.writeFileSync(path.join(dir, 'geoipupdate.yml'), 'enable: true\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/geoipupdate')];
  const G2 = require('../features/geoipupdate');
  assert.strictEqual(G2.loadGeoipupdateConfig().frequency_hours, 168);
});

console.log('\nensureContainerAtBoot — reconstitution apres redemarrage de l hote (meme piege que certbot)');
(async () => {
  const check2 = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
    catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

  await check2('geoipupdate.yml absent -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoipboot-none-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/geoipupdate')];
    const G2 = require('../features/geoipupdate');
    const r = await G2.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'not enabled');
  });

  await check2('active mais sans license_key -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoipboot-nokey-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'geoipupdate.yml'), 'enable: true\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/geoipupdate')];
    const G2 = require('../features/geoipupdate');
    const r = await G2.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'no license_key');
  });

  await check2('active avec license_key mais Docker injoignable -> skipped proprement, pas d exception', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'geoipboot-nodocker-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'geoipupdate.yml'), 'enable: true\nlicense_key: abc\n');
    process.env.DOCKER_SOCKET = path.join(dir, 'no-such-docker.sock');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/geoipupdate')];
    const G2 = require('../features/geoipupdate');
    const r = await G2.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'docker unavailable');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
