'use strict';
/**
 * Fix (audit finding ANA-10) : l API n avait aucune authentification alors
 * qu elle partage nginx-net avec tous les backends du reverse proxy — un
 * backend compromis pouvait desactiver les regles ou ajouter une exception
 * 0.0.0.0/0 en interrogeant l analyzer directement. Demarre le vrai serveur
 * deux fois : une avec ANALYZER_TOKEN pose (le cas normal, gere par le
 * dashboard), une sans (le cas manuel/docker-compose, qui doit continuer a
 * fonctionner exactement comme avant).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ana-token-'));
const logs = path.join(tmp, 'logs'), data = path.join(tmp, 'data');
fs.mkdirSync(logs); fs.mkdirSync(data);

const get = (port, headers = {}) => new Promise(r => {
  http.get({ host: '127.0.0.1', port, path: '/api/status', timeout: 4000, headers }, res => {
    let b = ''; res.on('data', d => b += d);
    res.on('end', () => { try { r({ status: res.statusCode, body: JSON.parse(b) }); } catch { r({ status: res.statusCode, body: null }); } });
  }).on('error', () => r(null)).on('timeout', function () { this.destroy(); r(null); });
});
const wait = ms => new Promise(r => setTimeout(r, ms));

function spawnServer(port, extraEnv) {
  return spawn('node', [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(port), LOGS_DIR: logs, DB_PATH: path.join(data, `s-${port}.db`),
           POLL_MS: '200', FLUSH_MS: '500', EVALUATE_MS: '800', LEARNING_DAYS: '21', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

(async () => {
  console.log('\nANALYZER_TOKEN pose : les requetes sans jeton (ou avec un mauvais) sont refusees');
  const TOKEN = 'abc123token';
  const PORT1 = 9197;
  const srv1 = spawnServer(PORT1, { ANALYZER_TOKEN: TOKEN });
  await wait(1500);
  const noToken = await get(PORT1);
  check('sans en-tete X-Analyzer-Token -> 401', () => assert.strictEqual(noToken.status, 401));
  const wrongToken = await get(PORT1, { 'X-Analyzer-Token': 'nope' });
  check('avec un jeton incorrect -> 401', () => assert.strictEqual(wrongToken.status, 401));
  const rightToken = await get(PORT1, { 'X-Analyzer-Token': TOKEN });
  check('avec le bon jeton -> 200', () => assert.strictEqual(rightToken.status, 200));
  // /api/health doit rester joignable sans jeton : c est le seul point que
  // Docker ou un operateur pourraient sonder sans passer par le dashboard.
  const health = await new Promise(r => {
    http.get({ host: '127.0.0.1', port: PORT1, path: '/api/health', timeout: 4000 }, res => {
      let b = ''; res.on('data', d => b += d); res.on('end', () => r(res.statusCode));
    }).on('error', () => r(null));
  });
  check('/api/health reste accessible sans jeton', () => assert.strictEqual(health, 200));
  srv1.kill('SIGTERM');
  await wait(300);

  console.log('\nANALYZER_TOKEN absent : comportement inchange (deploiement manuel, sans dashboard)');
  const PORT2 = 9198;
  const srv2 = spawnServer(PORT2, {});
  await wait(1500);
  const open = await get(PORT2);
  check('sans ANALYZER_TOKEN configure, aucune authentification n est exigee (non-regression)', () => assert.strictEqual(open.status, 200));
  srv2.kill('SIGTERM');
  await wait(300);

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
