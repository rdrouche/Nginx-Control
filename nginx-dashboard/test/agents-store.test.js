'use strict';
/**
 * lib/agents-store.js — registre des agents distants (Partie 2) : machine a
 * etats (pending -> approved -> revoked, etc.), emission/rotation de jetons,
 * lookup constant-time par jeton. Meme isolation CONFIG_DIR/initEventsDb()
 * que test/scheduler.test.js et test/docker-autoconfig-certbot-issuance.test.js
 * (getState/setState sont des no-op tant que initEventsDb() n a pas ete
 * appele, ce que server.js ne fait qu a son propre boot).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-store-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

const store = require('../lib/agents-store');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function reset() { events.setState(store.STATE_KEY, { agents: {} }); }

console.log('\nenroll() — toujours pending, jamais auto-approuve');
reset();
check("un enrolement cree un agent 'pending', jamais de jeton", () => {
  const a = store.enroll({ hostnameProposed: 'vps-1', fingerprint: 'abc' });
  assert.strictEqual(a.status, 'pending');
  assert.strictEqual(a.tokenHash, null);
  assert.ok(a.id);
  assert.strictEqual(store.getAgent(a.id).status, 'pending');
});
check('deux enrolements successifs obtiennent des ids distincts', () => {
  const a = store.enroll({ hostnameProposed: 'vps-2', fingerprint: '' });
  const b = store.enroll({ hostnameProposed: 'vps-3', fingerprint: '' });
  assert.notStrictEqual(a.id, b.id);
});

console.log('\napprove() — jeton emis exactement une fois, jamais recuperable ensuite');
reset();
check('approve() renvoie un jeton brut, et seul son empreinte est persistee', () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  const { agent, rawToken } = store.approve(a.id, 'admin');
  assert.strictEqual(agent.status, 'approved');
  assert.ok(rawToken.startsWith('agt_'));
  const persisted = store.getAgent(a.id);
  assert.notStrictEqual(persisted.tokenHash, rawToken, 'le jeton brut ne doit jamais etre stocke tel quel');
  assert.strictEqual(persisted.tokenHash.length, 64, 'seule l empreinte SHA-256 est persistee');
});
check('findByToken() retrouve l agent approuve par son jeton brut', () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  const { rawToken } = store.approve(a.id, 'admin');
  const found = store.findByToken(rawToken);
  assert.ok(found);
  assert.strictEqual(found.id, a.id);
});
check('findByToken() renvoie null pour un jeton inconnu, ou vide', () => {
  assert.strictEqual(store.findByToken('agt_ce-jeton-nexiste-pas'), null);
  assert.strictEqual(store.findByToken(''), null);
  assert.strictEqual(store.findByToken(null), null);
});

console.log('\nreject()/revoke() — un jeton revoque cesse immediatement d authentifier');
reset();
check("reject() sur un agent 'pending' -> statut 'rejected', jamais de jeton emis", () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  const rejected = store.reject(a.id, 'admin');
  assert.strictEqual(rejected.status, 'rejected');
  assert.strictEqual(rejected.tokenHash, null);
});
check("revoke() sur un agent approuve -> le jeton precedent ne matche plus jamais", () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  const { rawToken } = store.approve(a.id, 'admin');
  assert.ok(store.findByToken(rawToken));
  store.revoke(a.id, 'admin');
  assert.strictEqual(store.findByToken(rawToken), null);
  assert.strictEqual(store.getAgent(a.id).status, 'revoked');
});

console.log('\nregenerateToken() — invalide immediatement l ancien jeton');
reset();
check('regenerateToken() sur un agent approuve : nouveau jeton fonctionne, ancien non', () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  const { rawToken: first } = store.approve(a.id, 'admin');
  const { rawToken: second } = store.regenerateToken(a.id);
  assert.notStrictEqual(first, second);
  assert.strictEqual(store.findByToken(first), null);
  assert.ok(store.findByToken(second));
});
check("regenerateToken() sur un agent non-approuve (pending/rejected/revoked) -> null, jamais de jeton fantome", () => {
  const pending = store.enroll({ hostnameProposed: 'vps-x' });
  assert.strictEqual(store.regenerateToken(pending.id), null);
  const rejected = store.enroll({ hostnameProposed: 'vps-y' });
  store.reject(rejected.id, 'admin');
  assert.strictEqual(store.regenerateToken(rejected.id), null);
});

console.log('\nremove() — supprime uniquement le registre, jamais un raccourci pour revoquer');
reset();
check('remove() efface bien un agent pending/rejected du registre', () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  assert.strictEqual(store.remove(a.id), true);
  assert.strictEqual(store.getAgent(a.id), null);
});
check('remove() sur un id inconnu -> false, jamais une exception', () => {
  assert.strictEqual(store.remove('id-inexistant'), false);
});

console.log('\nrecordManifestResult() / getGeneratedFiles() — agrege les fichiers de tous les agents approuves');
reset();
check('un succes met a jour generatedFiles/vhostCount ; un echec ne les touche jamais', () => {
  const a = store.enroll({ hostnameProposed: 'vps-1' });
  store.approve(a.id, 'admin');
  store.recordManifestResult(a.id, { ok: true, generatedFiles: ['/sites/agent_x_app.conf'], vhostCount: 1, lastVhosts: [{ serverNames: ['app.example.com'] }] });
  let agent = store.getAgent(a.id);
  assert.strictEqual(agent.lastManifestOk, true);
  assert.deepStrictEqual(agent.generatedFiles, ['/sites/agent_x_app.conf']);
  assert.strictEqual(agent.vhostCount, 1);

  store.recordManifestResult(a.id, { ok: false, error: 'nginx -t failed' });
  agent = store.getAgent(a.id);
  assert.strictEqual(agent.lastManifestOk, false);
  assert.strictEqual(agent.lastManifestError, 'nginx -t failed');
  assert.deepStrictEqual(agent.generatedFiles, ['/sites/agent_x_app.conf'], 'un echec ne doit jamais effacer le dernier etat reussi connu');
});
reset();
check('getGeneratedFiles() agrege bien tous les agents, jamais les revoques dont on a deja nettoye les fichiers', () => {
  const a = store.enroll({ hostnameProposed: 'vps-a' });
  const b = store.enroll({ hostnameProposed: 'vps-b' });
  store.approve(a.id, 'admin');
  store.approve(b.id, 'admin');
  store.recordManifestResult(a.id, { ok: true, generatedFiles: ['/sites/agent_a_1.conf'], vhostCount: 1 });
  store.recordManifestResult(b.id, { ok: true, generatedFiles: ['/sites/agent_b_1.conf'], vhostCount: 1 });
  assert.deepStrictEqual(store.getGeneratedFiles().sort(), ['/sites/agent_a_1.conf', '/sites/agent_b_1.conf']);
  store.revoke(a.id, 'admin');
  // Fix v12.22.0 (audit finding AGT-03, remaining item): recordManifestResult()
  // now refuses to touch a non-'approved' agent unless the caller opts in
  // via { allowNonApproved: true } — the one legitimate case being exactly
  // this one, features/agents.js#removeAgentVhosts()'s post-revoke cleanup
  // clearing generatedFiles once the vhost files are actually gone. Without
  // that flag this call is now correctly a no-op (see the new check below).
  const noop = store.recordManifestResult(a.id, { ok: true, generatedFiles: [], vhostCount: 0 });
  assert.strictEqual(noop, null, 'recordManifestResult() sans allowNonApproved doit refuser un agent revoque');
  assert.deepStrictEqual(store.getGeneratedFiles().sort(), ['/sites/agent_a_1.conf', '/sites/agent_b_1.conf'],
    'un appel refuse ne doit rien avoir change');
  store.recordManifestResult(a.id, { ok: true, generatedFiles: [], vhostCount: 0 }, { allowNonApproved: true });
  assert.deepStrictEqual(store.getGeneratedFiles(), ['/sites/agent_b_1.conf']);
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail) process.exit(1);
