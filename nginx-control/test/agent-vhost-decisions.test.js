'use strict';
/**
 * lib/agent-vhost-decisions.js — store de pause par vhost pour les agents
 * distants (Partie 2). Meme isolation CONFIG_DIR/initEventsDb() que
 * test/agents-store.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-vhost-decisions-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');

const events = require('../lib/events');
events.initEventsDb();

const store = require('../lib/agent-vhost-decisions');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function reset() { events.setState(store.STATE_KEY, { decisions: {} }); }

console.log('\nnamesDecisionKey() — meme convention que docker-autoconfig (triee, minuscules)');
check('ordre et casse ignores', () => {
  assert.strictEqual(store.namesDecisionKey(['B.com', 'a.com']), store.namesDecisionKey(['a.COM', 'b.COM']));
});
check('un ensemble different produit une cle differente', () => {
  assert.notStrictEqual(store.namesDecisionKey(['a.com']), store.namesDecisionKey(['a.com', 'b.com']));
});

console.log('\nsetPaused() / getDecision() / getAgentDecisions()');
reset();
check("aucune decision au depart", () => {
  assert.strictEqual(store.getDecision('agent1', 'a.com'), null);
  assert.deepStrictEqual(store.getAgentDecisions('agent1'), {});
});
check('setPaused() enregistre paused:true avec pausedAt/pausedBy', () => {
  const key = store.namesDecisionKey(['app.example.com']);
  store.setPaused('agent1', key, ['app.example.com'], 'admin');
  const d = store.getDecision('agent1', key);
  assert.strictEqual(d.paused, true);
  assert.ok(d.pausedAt);
  assert.strictEqual(d.pausedBy, 'admin');
  assert.deepStrictEqual(d.names, ['app.example.com']);
});
check("deux agents distincts ne se marchent pas dessus (meme decisionKey)", () => {
  const key = store.namesDecisionKey(['shared.example.com']);
  store.setPaused('agentA', key, ['shared.example.com'], 'admin');
  assert.strictEqual(store.getDecision('agentB', key), null, "l autre agent ne doit rien voir");
  assert.ok(store.getDecision('agentA', key));
});

console.log('\nresume()');
reset();
check('resume() sur une decision existante -> true, entree supprimee', () => {
  const key = store.namesDecisionKey(['app.example.com']);
  store.setPaused('agent1', key, ['app.example.com'], 'admin');
  assert.strictEqual(store.resume('agent1', key), true);
  assert.strictEqual(store.getDecision('agent1', key), null);
});
check('resume() sur une decision inexistante -> false, aucun effet', () => {
  assert.strictEqual(store.resume('agent1', 'nope'), false);
});
check('un agent sans plus aucune decision disparait de state.decisions (pas de bucket vide qui traine)', () => {
  const key = store.namesDecisionKey(['app.example.com']);
  store.setPaused('agent1', key, ['app.example.com'], 'admin');
  store.resume('agent1', key);
  const raw = events.getState(store.STATE_KEY);
  assert.strictEqual('agent1' in raw.decisions, false);
});

console.log('\nremoveAgent()');
reset();
check('removeAgent() purge toutes les decisions de cet agent, jamais celles des autres', () => {
  const key1 = store.namesDecisionKey(['a.example.com']);
  const key2 = store.namesDecisionKey(['b.example.com']);
  store.setPaused('agent1', key1, ['a.example.com'], 'admin');
  store.setPaused('agent2', key2, ['b.example.com'], 'admin');
  store.removeAgent('agent1');
  assert.strictEqual(store.getDecision('agent1', key1), null);
  assert.ok(store.getDecision('agent2', key2), "agent2 ne doit pas etre touche");
});
check('removeAgent() sur un agent sans aucune decision -> aucune erreur', () => {
  assert.doesNotThrow(() => store.removeAgent('agent-inconnu'));
});

console.log(`\n${pass} pass, ${fail} fail`);
if (fail > 0) process.exit(1);
