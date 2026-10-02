'use strict';
/**
 * pullAndCheckUpdate() / getImageId() (lib/docker.js) against a fake Docker
 * daemon on a real Unix socket — the tricky part is that the Engine API
 * always answers an image pull with HTTP 200 and a stream of
 * newline-delimited JSON progress objects, even on failure (bad tag, auth
 * wall): the error lives INSIDE that stream, never in the HTTP status. A
 * mock keeps this test from silently drifting from that real API shape the
 * way a hardcoded "docker unavailable" case never could.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const http = require('http');
const url = require('url');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dockerimg-'));
const sockPath = path.join(sockDir, 'docker.sock');

// Mutable fake-daemon state, reset per test.
let images = {};       // name -> Id
let pullBehavior = 'update'; // 'update' | 'same' | 'error'

const fakeDaemon = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (req.method === 'GET' && /^\/images\/[^/]+\/json$/.test(parsed.pathname)) {
    const name = decodeURIComponent(parsed.pathname.split('/')[2]);
    if (images[name]) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ Id: images[name] })); }
    else { res.writeHead(404); res.end('{}'); }
    return;
  }
  if (req.method === 'POST' && parsed.pathname === '/images/create') {
    const name = parsed.query.fromImage;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (pullBehavior === 'error') {
      res.write(JSON.stringify({ status: 'Pulling from ' + name }) + '\n');
      res.write(JSON.stringify({ error: 'manifest for ' + name + ' not found' }) + '\n');
      res.end();
      return;
    }
    res.write(JSON.stringify({ status: 'Pulling from ' + name }) + '\n');
    res.write(JSON.stringify({ status: 'Downloading', progress: '50%' }) + '\n');
    if (pullBehavior === 'update') images[name] = 'sha256:' + Math.random().toString(16).slice(2);
    res.write(JSON.stringify({ status: 'Status: Downloaded newer image for ' + name }) + '\n');
    res.end();
    return;
  }
  res.writeHead(404); res.end('{}');
});

(async () => {
  await new Promise(resolve => fakeDaemon.listen(sockPath, resolve));
  process.env.DOCKER_SOCKET = sockPath;
  delete require.cache[require.resolve('../lib/config')];
  delete require.cache[require.resolve('../lib/docker')];
  const docker = require('../lib/docker');

  console.log('\ngetImageId');
  await check('image connue -> Id', async () => {
    images = { 'nginx:latest': 'sha256:AAA' };
    assert.strictEqual(await docker.getImageId('nginx:latest'), 'sha256:AAA');
  });
  await check('image inconnue -> null, pas d exception', async () => {
    images = {};
    assert.strictEqual(await docker.getImageId('nginx:latest'), null);
  });

  console.log('\npullAndCheckUpdate — le flux NDJSON, pas le statut HTTP, dit si ca a reussi');
  await check('nouvelle image disponible -> updated:true, avant/apres differents', async () => {
    images = { 'nginx:latest': 'sha256:AAA' };
    pullBehavior = 'update';
    const r = await docker.pullAndCheckUpdate('nginx:latest');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.pulled, true);
    assert.strictEqual(r.updated, true);
    assert.strictEqual(r.before, 'sha256:AAA');
    assert.notStrictEqual(r.after, 'sha256:AAA');
  });
  await check('deja a jour -> updated:false, meme si le pull reussit', async () => {
    images = { 'nginx:latest': 'sha256:AAA' };
    pullBehavior = 'same';
    const r = await docker.pullAndCheckUpdate('nginx:latest');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.updated, false);
    assert.strictEqual(r.before, 'sha256:AAA');
    assert.strictEqual(r.after, 'sha256:AAA');
  });
  await check('image inconnue au depart -> updated:true (avant:null, apres: une image)', async () => {
    images = {};
    pullBehavior = 'update';
    const r = await docker.pullAndCheckUpdate('nginx:latest');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.before, null);
    assert.strictEqual(r.updated, true);
  });
  await check('erreur DANS le flux (statut HTTP 200 quand meme) -> ok:false, jamais pris pour un succes', async () => {
    images = { 'private/image:latest': 'sha256:AAA' };
    pullBehavior = 'error';
    const r = await docker.pullAndCheckUpdate('private/image:latest');
    assert.strictEqual(r.ok, false);
    assert.ok(/manifest/.test(r.error), 'le message d erreur du flux Docker doit remonter');
  });
  await check('sans image configuree -> refuse immediatement, aucun appel Docker', async () => {
    const r = await docker.pullAndCheckUpdate('');
    assert.strictEqual(r.ok, false);
  });

  fakeDaemon.close();
  fs.rmSync(sockDir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
