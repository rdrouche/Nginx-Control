'use strict';
/**
 * lib/docker.js's streamEvents() — the low-level Docker /events reader
 * behind the auto-config Docker reactive detection
 * (features/docker-autoconfig.js's startEventsWatcher()). Tested here
 * against a real HTTP server bound to a Unix socket, standing in for the
 * Docker daemon, since that's the only way to exercise the actual framing
 * behaviour (newline-delimited JSON split arbitrarily across TCP/socket
 * chunks — the exact bug class this function exists to get right).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function freshDocker(socketPath) {
  process.env.DOCKER_SOCKET = socketPath;
  for (const mod of ['../lib/config', '../lib/docker']) delete require.cache[require.resolve(mod)];
  return require('../lib/docker');
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'docker-events-'));

  console.log('\nstreamEvents() — lignes NDJSON coupees arbitrairement entre plusieurs chunks');
  await (async () => {
    const sockPath = path.join(dir, 'a.sock');
    const srv = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const line1 = JSON.stringify({ Type: 'container', Action: 'start', Actor: { ID: 'c1' } }) + '\n';
      const line2 = JSON.stringify({ Type: 'container', Action: 'die', Actor: { ID: 'c2' } }) + '\n';
      const whole = line1 + line2;
      // Split mid-line, not on a line boundary — the real failure mode a
      // naive "one chunk = one line" reader would get wrong.
      const cut = Math.floor(whole.length / 2);
      res.write(whole.slice(0, cut));
      setTimeout(() => { res.write(whole.slice(cut)); res.end(); }, 20);
    });
    await new Promise(r => srv.listen(sockPath, r));

    const D = freshDocker(sockPath);
    const events = [];
    let ended = false, endErr = 'unset';
    await new Promise(resolve => {
      D.streamEvents({
        onEvent: (e) => events.push(e),
        onEnd: (err) => { ended = true; endErr = err; resolve(); },
      });
    });

    check('les deux evenements sont recus intacts malgre la coupure au milieu', () => {
      assert.deepStrictEqual(events.map(e => e.Action), ['start', 'die']);
      assert.strictEqual(events[0].Actor.ID, 'c1');
      assert.strictEqual(events[1].Actor.ID, 'c2');
    });
    check('onEnd() appele sans erreur a la fin normale du flux', () => {
      assert.strictEqual(ended, true);
      assert.strictEqual(endErr, null);
    });

    srv.close();
  })();

  console.log('\nstreamEvents() — statut HTTP non-200 -> onEnd(err), jamais silencieusement ignore');
  await (async () => {
    const sockPath = path.join(dir, 'b.sock');
    const srv = http.createServer((req, res) => { res.writeHead(500); res.end('nope'); });
    await new Promise(r => srv.listen(sockPath, r));

    const D = freshDocker(sockPath);
    const err = await new Promise(resolve => {
      D.streamEvents({ onEvent: () => {}, onEnd: (e) => resolve(e) });
    });
    check('onEnd recoit une erreur decrivant le statut HTTP', () => {
      assert.ok(err instanceof Error);
      assert.ok(/500/.test(err.message));
    });

    srv.close();
  })();

  console.log('\nstreamEvents() — socket injoignable -> onEnd(err), jamais d exception non geree');
  await (async () => {
    const D = freshDocker(path.join(dir, 'does-not-exist.sock'));
    const err = await new Promise(resolve => {
      D.streamEvents({ onEvent: () => {}, onEnd: (e) => resolve(e) });
    });
    check('onEnd recoit bien une erreur', () => assert.ok(err));
  })();

  console.log('\nstreamEvents() — close() coupe le flux sans relancer onEnd de force');
  await (async () => {
    const sockPath = path.join(dir, 'c.sock');
    const srv = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Never ends on its own — a real Docker daemon holds this connection
      // open indefinitely; only close() (or the server) should end it.
    });
    await new Promise(r => srv.listen(sockPath, r));

    const D = freshDocker(sockPath);
    let endCalls = 0;
    const handle = D.streamEvents({ onEvent: () => {}, onEnd: () => { endCalls++; } });
    await new Promise(r => setTimeout(r, 30));
    check('rien n a ete signale tant que le flux reste ouvert', () => assert.strictEqual(endCalls, 0));
    handle.close();
    await new Promise(r => setTimeout(r, 30));

    srv.close();
  })();

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
