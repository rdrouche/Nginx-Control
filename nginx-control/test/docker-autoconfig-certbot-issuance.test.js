'use strict';
/**
 * triggerCertbotIssuanceIfDue() (features/docker-autoconfig.js) — the state
 * machine that decides whether to actually fire an async certbot/certbot-dns
 * issuance for a `certbot_http`/`certbot_dns` vhost, and never twice
 * concurrently, and never in a hot retry loop after a failure.
 *
 * Requires a working `state` table (lib/events.js, SQLite) — initEventsDb()
 * is never called automatically outside server.js's own boot sequence, so
 * this test does it itself against an isolated CONFIG_DIR, exactly like
 * test/scheduler.test.js and test/blocklists.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dac-issuance-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

const { triggerCertbotIssuanceIfDue, setDeps } = require('../features/docker-autoconfig');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const STATE_KEY = 'docker_autoconfig_state';
function loadState() { return { decisions: {}, generatedFiles: {}, ...(events.getState(STATE_KEY) || {}) }; }
function resetState() { events.setState(STATE_KEY, { decisions: {}, generatedFiles: {} }); }

/** Wait a macrotask so the fire-and-forget promise chain has settled. */
const flush = () => new Promise(r => setImmediate(r));

console.log('\ntriggerCertbotIssuanceIfDue() — declenchement de base');
(async () => {

await (async () => {
  resetState();
  let called = 0;
  setDeps({ issueHttp: async () => { called++; return { ok: true }; }, issueDns: async () => ({ ok: true }) });
  const state = loadState();
  triggerCertbotIssuanceIfDue('app.example.com', 'certbot_http', ['app.example.com'], state, 15);
  // Marque 'issuing' de facon SYNCHRONE (avant la resolution de la promesse) :
  // c est cette persistance immediate qui protege contre un runCycle() qui
  // retournerait tot (skippedNoChange) sans jamais rappeler saveState().
  check("marque 'issuing' de maniere synchrone, avant meme la resolution de la promesse d emission", () => {
    assert.strictEqual(loadState().issuance['app.example.com'].status, 'issuing');
  });
  await flush();
  check('appelle bien issueHttp (pas issueDns) pour le mode certbot_http', () => {
    assert.strictEqual(called, 1);
  });
  check("une fois la promesse resolue en succes -> passe a 'idle'", () => {
    assert.strictEqual(loadState().issuance['app.example.com'].status, 'idle');
  });
})();

await (async () => {
  resetState();
  let httpCalled = 0, dnsCalled = 0;
  setDeps({ issueHttp: async () => { httpCalled++; return { ok: true }; }, issueDns: async () => { dnsCalled++; return { ok: true }; } });
  const state = loadState();
  triggerCertbotIssuanceIfDue('site.example.com', 'certbot_dns', ['site.example.com'], state, 15);
  await flush();
  check('mode certbot_dns -> appelle issueDns, jamais issueHttp', () => {
    assert.strictEqual(dnsCalled, 1);
    assert.strictEqual(httpCalled, 0);
  });
})();

console.log('\ntriggerCertbotIssuanceIfDue() — jamais deux emissions concurrentes pour la meme cle');
await (async () => {
  resetState();
  let calls = 0;
  let resolveFirst;
  const pending = new Promise(r => { resolveFirst = r; });
  setDeps({ issueHttp: async () => { calls++; await pending; return { ok: true }; }, issueDns: async () => ({ ok: true }) });
  const state = loadState();
  // Premier declenchement : reste "en vol" (la promesse ne se resout pas encore).
  triggerCertbotIssuanceIfDue('dup.example.com', 'certbot_http', ['dup.example.com'], state, 15);
  await flush();
  // Deuxieme declenchement pour la MEME cle, cycle suivant, pendant que le
  // premier est toujours en cours -> ne doit jamais rappeler issueHttp.
  const state2 = loadState();
  triggerCertbotIssuanceIfDue('dup.example.com', 'certbot_http', ['dup.example.com'], state2, 15);
  await flush();
  check("un deuxieme declenchement pendant qu une emission est deja 'issuing' n appelle jamais issueHttp une seconde fois", () => {
    assert.strictEqual(calls, 1);
  });
  resolveFirst();
  await flush();
})();

console.log("\ntriggerCertbotIssuanceIfDue() — echec : passe a 'failed' avec le vrai message d erreur");
await (async () => {
  resetState();
  setDeps({ issueHttp: async () => ({ error: 'DNS-01 challenge non propage a temps' }), issueDns: async () => ({ ok: true }) });
  const state = loadState();
  triggerCertbotIssuanceIfDue('fail.example.com', 'certbot_http', ['fail.example.com'], state, 15);
  await flush();
  check("statut 'failed' avec le message d erreur reel de certbot conserve", () => {
    const entry = loadState().issuance['fail.example.com'];
    assert.strictEqual(entry.status, 'failed');
    assert.strictEqual(entry.lastError, 'DNS-01 challenge non propage a temps');
    assert.strictEqual(entry.attempts, 1);
  });
})();

console.log('\ntriggerCertbotIssuanceIfDue() — echec du dep lui-meme (rejet de promesse) traite comme un echec, jamais une exception non geree');
await (async () => {
  resetState();
  setDeps({ issueHttp: async () => { throw new Error('docker socket indisponible'); }, issueDns: async () => ({ ok: true }) });
  const state = loadState();
  triggerCertbotIssuanceIfDue('reject.example.com', 'certbot_http', ['reject.example.com'], state, 15);
  await flush();
  check("un dep qui rejette -> 'failed' avec son message, pas de crash", () => {
    const entry = loadState().issuance['reject.example.com'];
    assert.strictEqual(entry.status, 'failed');
    assert.strictEqual(entry.lastError, 'docker socket indisponible');
  });
})();

console.log('\ntriggerCertbotIssuanceIfDue() — backoff apres un echec');
await (async () => {
  resetState();
  let calls = 0;
  setDeps({ issueHttp: async () => { calls++; return { error: 'echec persistant' }; }, issueDns: async () => ({ ok: true }) });
  // Premiere tentative : echoue.
  triggerCertbotIssuanceIfDue('backoff.example.com', 'certbot_http', ['backoff.example.com'], loadState(), 15);
  await flush();
  check('premiere tentative effectuee (calls === 1)', () => assert.strictEqual(calls, 1));

  // Cycle suivant, immediatement apres (bien avant les 15 min de backoff) :
  // ne doit PAS re-tenter.
  triggerCertbotIssuanceIfDue('backoff.example.com', 'certbot_http', ['backoff.example.com'], loadState(), 15);
  await flush();
  check("dans la fenetre de backoff (retryMinutes) -> aucune nouvelle tentative", () => assert.strictEqual(calls, 1));

  // On simule l ecoulement du backoff en reculant lastAttemptAt manuellement
  // (equivalent a laisser le temps reel s ecouler, sans faire dormir le test).
  const s = loadState();
  s.issuance['backoff.example.com'].lastAttemptAt = Date.now() - 16 * 60_000;
  events.setState(STATE_KEY, s);
  triggerCertbotIssuanceIfDue('backoff.example.com', 'certbot_http', ['backoff.example.com'], loadState(), 15);
  await flush();
  check('backoff ecoule -> nouvelle tentative (calls === 2), compteur attempts incremente', () => {
    assert.strictEqual(calls, 2);
    assert.strictEqual(loadState().issuance['backoff.example.com'].attempts, 2);
  });
})();

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);

})();
