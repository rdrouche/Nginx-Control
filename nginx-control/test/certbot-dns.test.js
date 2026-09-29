'use strict';
/**
 * Defi DNS-01 (features/certbot-dns.js) — chargement de configuration,
 * resolution du registre de fournisseurs (le point qui rend le fournisseur
 * extensible sans toucher au code : provider inconnu -> "custom", reglages
 * manuels prioritaires sur le registre integre), et ensureContainerAtBoot
 * (meme piege que certbot HTTP/geoipupdate/error-pages/analyzer).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nloadCertbotDnsConfig — fichier absent, booleen enable');
check('fichier absent -> null, pas d exception', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnstest-noconf-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/certbot-dns')];
  const CD = require('../features/certbot-dns');
  assert.strictEqual(CD.loadCertbotDnsConfig(), null);
});

console.log('\nresolveProvider — registre integre + reglages manuels');
(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnstest-provider-'));
  process.env.CONFIG_DIR = dir;
  process.env.USERS_FILE = path.join(dir, 'users.yml');
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../features/certbot-dns')];
  const CD = require('../features/certbot-dns');

  check('cloudflare (defaut) -> image et drapeaux corrects', () => {
    const p = CD.resolveProvider({ provider: 'cloudflare' });
    assert.strictEqual(p.image, 'certbot/dns-cloudflare:latest');
    assert.strictEqual(p.pluginFlag, '--dns-cloudflare');
    assert.strictEqual(p.credentialsFlag, '--dns-cloudflare-credentials');
    assert.strictEqual(p.propagationFlag, '--dns-cloudflare-propagation-seconds');
  });

  check('ovh -> image et drapeaux distincts de cloudflare', () => {
    const p = CD.resolveProvider({ provider: 'ovh' });
    assert.strictEqual(p.image, 'certbot/dns-ovh:latest');
    assert.strictEqual(p.pluginFlag, '--dns-ovh');
  });

  check('fournisseur non reconnu -> "custom", aucun drapeau par defaut', () => {
    const p = CD.resolveProvider({ provider: 'un-fournisseur-qui-nexiste-pas' });
    assert.strictEqual(p.pluginFlag, null);
    assert.strictEqual(p.image, '');
  });

  check('container_image/plugin_flag explicites -> priment sur le registre', () => {
    const p = CD.resolveProvider({
      provider: 'cloudflare',
      container_image: 'mon-depot/mon-image:1.2.3',
      plugin_flag: '--mon-plugin',
    });
    assert.strictEqual(p.image, 'mon-depot/mon-image:1.2.3');
    assert.strictEqual(p.pluginFlag, '--mon-plugin');
    // Les autres reglages cloudflare restent hors override explicite.
    assert.strictEqual(p.credentialsFlag, '--dns-cloudflare-credentials');
  });

  check('provider "custom" avec reglages manuels complets fonctionne', () => {
    const p = CD.resolveProvider({
      provider: 'custom',
      container_image: 'certbot/dns-monfournisseur:latest',
      plugin_flag: '--dns-monfournisseur',
      credentials_flag: '--dns-monfournisseur-credentials',
      propagation_flag: '--dns-monfournisseur-propagation-seconds',
    });
    assert.strictEqual(p.image, 'certbot/dns-monfournisseur:latest');
    assert.strictEqual(p.pluginFlag, '--dns-monfournisseur');
  });
})();

console.log('\nensureContainerAtBoot — reconstitution apres redemarrage de l hote (meme piege que les quatre autres conteneurs geres)');
(async () => {
  const check2 = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
    catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

  await check2('certbot-dns.yml absent -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnsboot-none-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/certbot-dns')];
    const CD = require('../features/certbot-dns');
    const r = await CD.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'not enabled');
  });

  await check2('active mais sans certs_host_path -> skipped, jamais d appel Docker', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnsboot-nopath-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'certbot-dns.yml'), 'enable: true\n');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/certbot-dns')];
    const CD = require('../features/certbot-dns');
    const r = await CD.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'certs_host_path missing');
  });

  await check2('active, certs_host_path present, Docker injoignable -> skipped proprement, pas d exception', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbdnsboot-nodocker-'));
    process.env.CONFIG_DIR = dir;
    process.env.USERS_FILE = path.join(dir, 'users.yml');
    fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
    fs.writeFileSync(path.join(dir, 'certbot-dns.yml'), 'enable: true\ncerts_host_path: /containers/certs\n');
    process.env.DOCKER_SOCKET = path.join(dir, 'no-such-docker.sock');
    delete require.cache[require.resolve('../lib/config')];
    delete require.cache[require.resolve('../features/certbot-dns')];
    const CD = require('../features/certbot-dns');
    const r = await CD.ensureContainerAtBoot();
    assert.strictEqual(r.skipped, 'docker unavailable');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
