'use strict';
/**
 * resolveAgentSsl() (features/agents.js) — modes `certbot_http`/`certbot_dns`
 * pour les agents distants (v12.21.0). Miroir exact de
 * test/docker-autoconfig-certbot-ssl.test.js pour la Partie 1 : Certbot (ou
 * Certbot-DNS) doit etre configure ET active en amont
 * (config/certbot.yml / config/certbot-dns.yml : `enable: true`) avant qu'un
 * agent puisse s'appuyer dessus via son manifeste. Sans ca, la demande doit
 * renvoyer une erreur explicite plutot que de silencieusement retomber sur un
 * vhost casse ou en attente sans explication.
 *
 * Certbot lui-meme n'est jamais require() directement ici (composition-root :
 * features/agents.js#setDeps({ getCertbotCfg, getCertbotDnsCfg })).
 * checkDomainConflict() (lib/certs.js) est laisse tel quel (pas de mock) :
 * dans cet environnement de test, DIR_CERTS ne contient jamais de certificat
 * correspondant, donc "certbot active, aucun certificat trouve" resout
 * systematiquement en `pending`, jamais en `cert`.
 */
const assert = require('assert');
const { validateManifestVhost } = require('../lib/agent-manifest');
const { resolveAgentSsl, setDeps } = require('../features/agents');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
  finally { setDeps({ getCertbotCfg: () => ({ enable: false }), getCertbotDnsCfg: () => ({ enable: false }) }); } };

function validatedFor(sslCertificate) {
  const r = validateManifestVhost({
    serverName: 'app.distant.example.com',
    locations: [{ path: '/', target: 'http://203.0.113.10:8080' }],
    sslCertificate,
  });
  assert.strictEqual(r.valid, true, `fixture invalide : ${r.errors.join('; ')}`);
  return r;
}

console.log('\nresolveAgentSsl() — certbot_http / certbot_dns : verification pre-vol');

check('sans setDeps() (defaut de securite) -> traite comme non configure', () => {
  const r = resolveAgentSsl(validatedFor('certbot_http'));
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_http_disabled');
});

check('certbot_http, Certbot desactive (enable:false) -> erreur explicite, jamais un vhost silencieux', () => {
  setDeps({ getCertbotCfg: () => ({ enable: false }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'));
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_http_disabled');
  assert.ok(/certbot\.yml/.test(r.message));
});

check('certbot_dns, Certbot-DNS desactive -> erreur explicite dediee (pas le message HTTP)', () => {
  setDeps({ getCertbotDnsCfg: () => ({ enable: false }) });
  const r = resolveAgentSsl(validatedFor('certbot_dns'));
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_dns_disabled');
  assert.ok(/certbot-dns\.yml/.test(r.message));
});

check('certbot_http, Certbot active mais aucun certificat existant -> pending (jamais une erreur, jamais un cert invente)', () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'));
  assert.strictEqual(r.type, 'pending');
});

check('certbot_dns, Certbot-DNS active mais aucun certificat existant -> pending', () => {
  setDeps({ getCertbotDnsCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_dns'));
  assert.strictEqual(r.type, 'pending');
});

check('desactiver Certbot HTTP n affecte pas Certbot DNS, et inversement (les deux checks sont independants)', () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }), getCertbotDnsCfg: () => ({ enable: false }) });
  const http = resolveAgentSsl(validatedFor('certbot_http'));
  const dns  = resolveAgentSsl(validatedFor('certbot_dns'));
  assert.strictEqual(http.type, 'pending');
  assert.strictEqual(dns.type, 'error');
  assert.strictEqual(dns.code, 'certbot_dns_disabled');
});

console.log('\nresolveAgentSsl() — 2e argument issuanceState : reflete une emission en cours/en echec, sans jamais en declencher une elle-meme');

check("entree 'issuing' -> reste 'pending' (le rendu HTTP simple ne change pas), avec un indicateur issuing:true", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'), {
    'app.distant.example.com': { status: 'issuing', lastAttemptAt: Date.now(), attempts: 1 },
  });
  assert.strictEqual(r.type, 'pending');
  assert.strictEqual(r.issuing, true);
});

check("entree 'failed' -> type 'error' avec le vrai message certbot et le numero de tentative, pas un 'pending' silencieux", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'), {
    'app.distant.example.com': { status: 'failed', lastAttemptAt: Date.now(), lastError: 'rate limited by Let\'s Encrypt', attempts: 3 },
  });
  assert.strictEqual(r.type, 'error');
  assert.strictEqual(r.code, 'certbot_issuance_failed');
  assert.ok(r.message.includes("rate limited by Let's Encrypt"));
  assert.ok(r.message.includes('3'));
});

check("aucune entree pour ce vhost (jamais tente) -> pending ordinaire", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'), {});
  assert.strictEqual(r.type, 'pending');
  assert.strictEqual(r.issuing, undefined);
});

check("issuanceState omis entierement (compat retro) -> pending, jamais une exception", () => {
  setDeps({ getCertbotCfg: () => ({ enable: true }) });
  const r = resolveAgentSsl(validatedFor('certbot_http'));
  assert.strictEqual(r.type, 'pending');
});

check('sslCertificate=auto/snippet/none restent inchanges (non-regression)', () => {
  const auto = resolveAgentSsl(validatedFor('auto'));
  assert.strictEqual(auto.type, 'pending');

  const snippetVhost = validateManifestVhost({
    serverName: 'app.distant.example.com',
    locations: [{ path: '/', target: 'http://203.0.113.10:8080' }],
    sslCertificate: 'snippet', sslCertificateSnippet: 'ssl-wildcard.conf',
  });
  const snippet = resolveAgentSsl(snippetVhost);
  assert.strictEqual(snippet.type, 'snippet');
  assert.strictEqual(snippet.file, 'ssl-wildcard.conf');

  const none = resolveAgentSsl(validateManifestVhost({
    serverName: 'app.distant.example.com',
    locations: [{ path: '/', target: 'http://203.0.113.10:8080' }],
  }));
  assert.strictEqual(none, undefined);
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
