'use strict';
/**
 * resolveSsl() (features/docker-autoconfig.js) — modes `certbot_http` /
 * `certbot_dns` : Certbot (ou Certbot-DNS) doit etre configure ET active en
 * amont (config/certbot.yml / config/certbot-dns.yml : `enable: true`)
 * avant qu'un conteneur puisse s'appuyer dessus via un label. Sans ca, la
 * demande doit renvoyer une erreur explicite plutot que de silencieusement
 * retomber sur un vhost casse ou en attente sans explication.
 *
 * Certbot lui-meme n'est jamais require() directement ici (composition-root
 * : features/docker-autoconfig.js#setDeps({ getCertbotCfg, getCertbotDnsCfg })).
 * checkDomainConflict() (lib/certs.js) est laisse tel quel (pas de mock) :
 * dans cet environnement de test, DIR_CERTS ne contient jamais de
 * certificat correspondant, donc "certbot active, aucun certificat trouve"
 * resout systematiquement en `pending`, jamais en `cert` — c'est le
 * comportement teste ici, pas un raccourci.
 */
const assert = require('assert');
const { validateDesiredVhost } = require('../lib/docker-autoconfig');
const { resolveSsl, setDeps } = require('../features/docker-autoconfig');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
  finally { setDeps({ getCertbotCfg: () => ({ enable: false }), getCertbotDnsCfg: () => ({ enable: false }) }); } };

function validatedFor(sslModeRaw) {
  const r = validateDesiredVhost({
    network: 'nginx-net', serverNameRaw: 'app.example.com', listenRaw: '',
    locations: [{ index: '01', path: '/', proxyPass: 'http://backend:8080' }],
    sslModeRaw,
  });
  assert.strictEqual(r.valid, true, `fixture invalide : ${r.errors.join('; ')}`);
  return r;
}

console.log('\nresolveSsl() — certbot_http / certbot_dns : verification pre-vol');

check('sans setDeps() (defaut de securite) -> traite comme non configure', () => {
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com']);
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_http_disabled');
});

check('certbot_http, Certbot desactive (enable:false) -> erreur explicite, jamais un vhost silencieux', () => {
  setDeps({ getCertbotCfg: () => ({ enable: false }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com']);
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_http_disabled');
  assert.ok(/certbot\.yml/.test(r.message));
});

check('certbot_dns, Certbot-DNS desactive -> erreur explicite dediee (pas le message HTTP)', () => {
  setDeps({ getCertbotDnsCfg: () => ({ enable: false }) });
  const r = resolveSsl(validatedFor('certbot_dns'), ['app.example.com']);
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_dns_disabled');
  assert.ok(/certbot-dns\.yml/.test(r.message));
});

check('certbot_http, Certbot active mais aucun certificat existant -> pending (jamais une erreur, jamais un cert invente)', () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com']);
  assert.strictEqual(r.type, 'pending');
});

check('certbot_dns, Certbot-DNS active mais aucun certificat existant -> pending', () => {
  setDeps({ getCertbotDnsCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_dns'), ['app.example.com']);
  assert.strictEqual(r.type, 'pending');
});

check('desactiver Certbot HTTP n affecte pas Certbot DNS, et inversement (les deux checks sont independants)', () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }), getCertbotDnsCfg: () => ({ enable: false }) });
  const http = resolveSsl(validatedFor('certbot_http'), ['app.example.com']);
  const dns  = resolveSsl(validatedFor('certbot_dns'), ['app.example.com']);
  assert.strictEqual(http.type, 'pending');
  assert.strictEqual(dns.type, 'error');
  assert.strictEqual(dns.code, 'certbot_dns_disabled');
});

console.log('\nresolveSsl() — 3e argument issuanceState : reflete une emission en cours/en echec, sans jamais en declencher une elle-meme');

check("entree 'issuing' -> reste 'pending' (le rendu HTTP simple ne change pas), avec un indicateur issuing:true", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com'], {
    'app.example.com': { status: 'issuing', lastAttemptAt: Date.now(), attempts: 1 },
  });
  assert.strictEqual(r.type, 'pending');
  assert.strictEqual(r.issuing, true);
});

check("entree 'failed' -> type 'error' avec le vrai message certbot et le numero de tentative, pas un 'pending' silencieux", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com'], {
    'app.example.com': { status: 'failed', lastAttemptAt: Date.now(), lastError: 'rate limited by Let\'s Encrypt', attempts: 3 },
  });
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_issuance_failed');
  assert.ok(r.message.includes("rate limited by Let's Encrypt"));
  assert.ok(r.message.includes('3'));
});

check("aucune entree pour ce vhost (jamais tente) -> pending ordinaire, comme avant cette fonctionnalite", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com'], {});
  assert.strictEqual(r.type, 'pending');
  assert.strictEqual(r.issuing, undefined);
});

check("issuanceState omis entierement (compat retro) -> pending, jamais une exception", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['app.example.com']);
  assert.strictEqual(r.type, 'pending');
});

check("un certificat existe deja -> priorite absolue sur l etat d emission (jamais une erreur affichee si le cert est deja la)", () => {
  // Ce cas ne peut pas etre exerce sans un vrai certificat sur disque
  // (checkDomainConflict()), mais la garde est structurelle : le bloc
  // `certbot_*` renvoie tot des que result.conflict est vrai, avant meme de
  // lire issuanceState — verifie ici que passer un etat 'failed' pour un
  // domaine SANS certificat ne change rien au comportement pending/erreur
  // d un domaine different qui, lui, n a pas d entree du tout.
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveSsl(validatedFor('certbot_http'), ['autre.example.com'], {
    'app.example.com': { status: 'failed', lastAttemptAt: Date.now(), lastError: 'peu importe', attempts: 1 },
  });
  assert.strictEqual(r.type, 'pending');
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
