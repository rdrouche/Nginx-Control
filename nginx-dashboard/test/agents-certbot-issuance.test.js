'use strict';
/**
 * triggerAgentCertbotIssuanceIfDue() (features/agents.js) — miroir exact de
 * test/docker-autoconfig-certbot-issuance.test.js pour les agents distants
 * (v12.21.0) : la meme machine a etats (idle/issuing/failed + backoff), mais
 * persistee dans sa propre cle d'etat (CERTBOT_STATE_KEY, distincte de celle
 * de docker-autoconfig.js) — deux compteurs de tentatives independants si le
 * meme domaine est un jour demande par les deux mecanismes.
 *
 * Requires a working `state` table (lib/events.js, SQLite) — initEventsDb()
 * is never called automatically outside server.js's own boot sequence.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-issuance-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

const { triggerAgentCertbotIssuanceIfDue, setDeps, loadCertbotState, saveCertbotState } = require('../features/agents');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function resetState() { saveCertbotState({ issuance: {} }); }

/** Wait a macrotask so the fire-and-forget promise chain has settled. */
const flush = () => new Promise(r => setImmediate(r));

console.log('\ntriggerAgentCertbotIssuanceIfDue() — declenchement de base');
(async () => {

await (async () => {
  resetState();
  let called = 0;
  setDeps({ issueHttp: async () => { called++; return { ok: true }; }, issueDns: async () => ({ ok: true }) });
  triggerAgentCertbotIssuanceIfDue('app.distant.example.com', 'certbot_http', ['app.distant.example.com'], 15);
  check("marque 'issuing' de maniere synchrone, avant meme la resolution de la promesse d emission", () => {
    assert.strictEqual(loadCertbotState().issuance['app.distant.example.com'].status, 'issuing');
  });
  await flush();
  check('appelle bien issueHttp (pas issueDns) pour le mode certbot_http', () => {
    assert.strictEqual(called, 1);
  });
  check("une fois la promesse resolue en succes -> passe a 'idle'", () => {
    assert.strictEqual(loadCertbotState().issuance['app.distant.example.com'].status, 'idle');
  });
})();

await (async () => {
  resetState();
  let httpCalled = 0, dnsCalled = 0;
  setDeps({ issueHttp: async () => { httpCalled++; return { ok: true }; }, issueDns: async () => { dnsCalled++; return { ok: true }; } });
  triggerAgentCertbotIssuanceIfDue('site.distant.example.com', 'certbot_dns', ['site.distant.example.com'], 15);
  await flush();
  check('mode certbot_dns -> appelle issueDns, jamais issueHttp', () => {
    assert.strictEqual(dnsCalled, 1);
    assert.strictEqual(httpCalled, 0);
  });
})();

console.log('\ntriggerAgentCertbotIssuanceIfDue() — jamais deux emissions concurrentes pour la meme cle');
await (async () => {
  resetState();
  let calls = 0;
  let resolveFirst;
  const pending = new Promise(r => { resolveFirst = r; });
  setDeps({ issueHttp: async () => { calls++; await pending; return { ok: true }; }, issueDns: async () => ({ ok: true }) });
  triggerAgentCertbotIssuanceIfDue('dup.distant.example.com', 'certbot_http', ['dup.distant.example.com'], 15);
  await flush();
  triggerAgentCertbotIssuanceIfDue('dup.distant.example.com', 'certbot_http', ['dup.distant.example.com'], 15);
  await flush();
  check("un deuxieme declenchement pendant qu une emission est deja 'issuing' n appelle jamais issueHttp une seconde fois", () => {
    assert.strictEqual(calls, 1);
  });
  resolveFirst();
  await flush();
})();

console.log("\ntriggerAgentCertbotIssuanceIfDue() — echec : passe a 'failed' avec le vrai message d erreur");
await (async () => {
  resetState();
  setDeps({ issueHttp: async () => ({ error: 'DNS-01 challenge non propage a temps' }), issueDns: async () => ({ ok: true }) });
  triggerAgentCertbotIssuanceIfDue('fail.distant.example.com', 'certbot_http', ['fail.distant.example.com'], 15);
  await flush();
  check("statut 'failed' avec le message d erreur reel de certbot conserve", () => {
    const entry = loadCertbotState().issuance['fail.distant.example.com'];
    assert.strictEqual(entry.status, 'failed');
    assert.strictEqual(entry.lastError, 'DNS-01 challenge non propage a temps');
    assert.strictEqual(entry.attempts, 1);
  });
})();

console.log('\ntriggerAgentCertbotIssuanceIfDue() — echec du dep lui-meme (rejet de promesse) traite comme un echec, jamais une exception non geree');
await (async () => {
  resetState();
  setDeps({ issueHttp: async () => { throw new Error('agent injoignable'); }, issueDns: async () => ({ ok: true }) });
  triggerAgentCertbotIssuanceIfDue('reject.distant.example.com', 'certbot_http', ['reject.distant.example.com'], 15);
  await flush();
  check("un dep qui rejette -> 'failed' avec son message, pas de crash", () => {
    const entry = loadCertbotState().issuance['reject.distant.example.com'];
    assert.strictEqual(entry.status, 'failed');
    assert.strictEqual(entry.lastError, 'agent injoignable');
  });
})();

console.log('\ntriggerAgentCertbotIssuanceIfDue() — backoff apres un echec');
await (async () => {
  resetState();
  let calls = 0;
  setDeps({ issueHttp: async () => { calls++; return { error: 'echec persistant' }; }, issueDns: async () => ({ ok: true }) });
  triggerAgentCertbotIssuanceIfDue('backoff.distant.example.com', 'certbot_http', ['backoff.distant.example.com'], 15);
  await flush();
  check('premiere tentative effectuee (calls === 1)', () => assert.strictEqual(calls, 1));

  triggerAgentCertbotIssuanceIfDue('backoff.distant.example.com', 'certbot_http', ['backoff.distant.example.com'], 15);
  await flush();
  check("dans la fenetre de backoff (retryMinutes) -> aucune nouvelle tentative", () => assert.strictEqual(calls, 1));

  const s = loadCertbotState();
  s.issuance['backoff.distant.example.com'].lastAttemptAt = Date.now() - 16 * 60_000;
  saveCertbotState(s);
  triggerAgentCertbotIssuanceIfDue('backoff.distant.example.com', 'certbot_http', ['backoff.distant.example.com'], 15);
  await flush();
  check('backoff ecoule -> nouvelle tentative (calls === 2), compteur attempts incremente', () => {
    assert.strictEqual(calls, 2);
    assert.strictEqual(loadCertbotState().issuance['backoff.distant.example.com'].attempts, 2);
  });
})();

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);

})();
