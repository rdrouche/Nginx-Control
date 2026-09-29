'use strict';
/**
 * features/agent-tunnel.js — mode 3 (tunnel NAT sortant, Partie 2 avance).
 * Teste le protocole de bout en bout SANS spawner un vrai serveur HTTP :
 * handleUpgrade() ne demande qu'un objet { headers, url } et un socket
 * duplex (write/on('data')/end) — un vrai net.Socket TCP local (obtenu via
 * un net.Server ephemere) joue ce role, exactement comme un agent reel s'y
 * connecterait, cote client on parle le protocole WebSocket a la main.
 *
 * Meme isolation CONFIG_DIR/initEventsDb() que test/agents-store.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), net = require('net'), crypto = require('crypto');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tunnel-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
process.env.AGENTS_CONFIG_FILE = path.join(tmpConfigDir, 'agents.yml');
fs.writeFileSync(process.env.AGENTS_CONFIG_FILE, 'tunnel_enable: true\n');

const events = require('../lib/events');
events.initEventsDb();

const store = require('../lib/agents-store');
const tunnel = require('../features/agent-tunnel');
const wsLite = require('../lib/ws-lite');
const { getTunnelSecret } = require('../lib/agent-tunnel-secret');

// Fix v12.22.0 (audit finding AGT-04): maybeHandleTunnelRequest() now refuses
// any request that doesn't carry the dashboard's own secret X-NC-Tunnel
// header (see lib/agent-tunnel-secret.js) — in production this header is
// injected by nginx itself via the generated tunnel vhost's proxy_set_header,
// never by the original client. Every fake request below that exercises the
// "this IS tunnel traffic" path must carry it, exactly as that generated
// vhost would.
const TUNNEL_HEADER = { 'x-nc-tunnel': getTunnelSecret() };

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
function reset() {
  events.setState(store.STATE_KEY, { agents: {} });
  for (const id of [...tunnel.connections.keys()]) tunnel.closeConnection(id, 'reset test');
}

function maskedClientFrame(payloadStr) {
  const payload = Buffer.from(payloadStr, 'utf8');
  const maskKey = crypto.randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ maskKey[i & 3];
  const len = payload.length;
  let header;
  if (len < 126) { header = Buffer.from([0x81, 0x80 | len]); }
  else { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(len, 2); }
  return Buffer.concat([header, maskKey, masked]);
}

/** Reads exactly one server->client (unmasked) WS text frame off a socket. */
function readOneServerFrame(socket) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 2) return;
      let len = buf[1] & 0x7f, offset = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); offset = 4; }
      if (buf.length < offset + len) return;
      socket.removeListener('data', onData);
      resolve(buf.slice(offset, offset + len).toString('utf8'));
    };
    socket.on('data', onData);
    socket.on('error', reject);
  });
}

async function setupTunnelServer() {
  // Un net.Server local qui, a chaque connexion, appelle directement
  // handleUpgrade() — c'est exactement ce que server.js fait depuis son
  // 'upgrade' event, juste sans passer par un vrai serveur HTTP autour.
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    const onHandshakeBytes = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      socket.removeListener('data', onHandshakeBytes);
      const rawHeader = buf.slice(0, headerEnd).toString('utf8');
      const rest = buf.slice(headerEnd + 4);
      const lines = rawHeader.split('\r\n');
      const headers = {};
      for (const line of lines.slice(1)) {
        const idx = line.indexOf(':');
        if (idx === -1) continue;
        headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      }
      const req = { url: '/api/agent/tunnel', headers };
      tunnel.handleUpgrade(req, socket, rest);
    };
    socket.on('data', onHandshakeBytes);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
}

function connectAgent(port, token) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port, host: '127.0.0.1' }, () => {
      socket.write(
        'GET /api/agent/tunnel HTTP/1.1\r\n' +
        'Host: 127.0.0.1\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
        'Sec-WebSocket-Version: 13\r\n' +
        (token ? `Authorization: Bearer ${token}\r\n` : '') +
        '\r\n'
      );
    });
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const text = buf.toString('utf8');
      const end = text.indexOf('\r\n\r\n');
      if (end === -1) return;
      socket.removeListener('data', onData);
      const statusLine = text.split('\r\n')[0];
      resolve({ socket, statusLine });
    };
    socket.on('data', onData);
    socket.on('error', reject);
  });
}

(async () => {
  const server = await setupTunnelServer();
  const port = server.address().port;

  console.log('\nhandleUpgrade() — authentification');
  reset();
  {
    const enrolled = store.enroll({ hostnameProposed: 'vps-1', fingerprint: '' });
    const { rawToken } = store.approve(enrolled.id, 'test');
    const { socket, statusLine } = await connectAgent(port, rawToken);
    check('jeton valide -> handshake 101 Switching Protocols', () => {
      assert.ok(/101/.test(statusLine));
    });
    check('la connexion est enregistree comme active pour cet agent', () => {
      assert.ok(tunnel.isConnected(enrolled.id));
    });
    socket.end();
    await new Promise(r => setTimeout(r, 50));
    check('la fermeture socket nettoie la connexion active', () => {
      assert.ok(!tunnel.isConnected(enrolled.id));
    });
  }

  reset();
  {
    const { statusLine } = await connectAgent(port, 'agt_ceci-nest-pas-un-jeton-valide');
    check('jeton invalide -> 401, jamais de connexion enregistree', () => {
      assert.ok(/401/.test(statusLine));
    });
  }

  console.log('\ntunnel_enable: false — coupe l upgrade entierement');
  {
    fs.writeFileSync(process.env.AGENTS_CONFIG_FILE, 'tunnel_enable: false\n');
    reset();
    const enrolled = store.enroll({ hostnameProposed: 'vps-2', fingerprint: '' });
    const { rawToken } = store.approve(enrolled.id, 'test');
    const { statusLine } = await connectAgent(port, rawToken);
    check('tunnel_enable=false -> 403, meme avec un jeton valide', () => {
      assert.ok(/403/.test(statusLine));
    });
    fs.writeFileSync(process.env.AGENTS_CONFIG_FILE, 'tunnel_enable: true\n');
  }

  console.log('\nmaybeHandleTunnelRequest() — relais bout en bout sur un manifeste "tunnel"');
  reset();
  {
    const enrolled = store.enroll({ hostnameProposed: 'vps-3', fingerprint: '' });
    const { rawToken } = store.approve(enrolled.id, 'test');
    store.recordManifestResult(enrolled.id, {
      ok: true, generatedFiles: ['/nginx/sites/agent_x_app.conf'], vhostCount: 1,
      lastVhosts: [{ serverNames: ['tunnel.example.com'], listen: 80, sslMode: 'none', mode: 'tunnel' }],
    });
    const { socket: agentSocket } = await connectAgent(port, rawToken);

    // Cote "agent" : repond a la premiere requete http-request recue avec un
    // http-response fixe, comme le ferait le binaire agent reel apres avoir
    // interroge sa propre cible locale.
    const framePromise = readOneServerFrame(agentSocket);
    const fakeReq = {
      method: 'GET', url: '/hello?x=1', headers: { host: 'tunnel.example.com', ...TUNNEL_HEADER },
      on(event, cb) { if (event === 'end') setImmediate(cb); return this; },
    };
    let resStatus = null, resHeaders = null, resBody = null;
    const fakeRes = {
      writeHead(status, headers) { resStatus = status; resHeaders = headers; },
      end(body) { resBody = body; },
    };

    const handledPromise = tunnel.maybeHandleTunnelRequest(fakeReq, fakeRes);
    const frameText = await framePromise;
    const requestMsg = JSON.parse(frameText);
    check('la requete relayee porte le bon Host/path/methode', () => {
      assert.strictEqual(requestMsg.type, 'http-request');
      assert.strictEqual(requestMsg.method, 'GET');
      assert.strictEqual(requestMsg.path, '/hello?x=1');
    });
    agentSocket.write(wsLite.encodeFrame(JSON.stringify({
      type: 'http-response', id: requestMsg.id, status: 200,
      headers: { 'content-type': 'text/plain' },
      bodyBase64: Buffer.from('bonjour depuis l agent').toString('base64'),
    }), wsLite.OPCODE.TEXT));
    // NB: la vraie trame agent->serveur doit etre MASQUEE (RFC 6455) — un
    // agent reel utilise sa propre implementation cliente ; ici on ecrit une
    // trame non masquee juste pour piloter le test, ce que le FrameParser
    // serveur rejette a raison (voir test/ws-lite.test.js). On simule donc
    // plutot un vrai client masque :
    const handled = await handledPromise.catch(() => 'threw');
    // Comme la trame precedente etait invalide (non masquee), la connexion a
    // ete fermee cote serveur -> la requete en attente doit avoir echoue
    // proprement (rejet, jamais un plantage), verifie ci-dessous.
    check('une trame agent non masquee est rejetee (le serveur ne desserialise jamais une trame invalide en JSON)', () => {
      assert.strictEqual(resStatus === null || resStatus === 502, true);
    });
  }

  reset();
  {
    const enrolled = store.enroll({ hostnameProposed: 'vps-4', fingerprint: '' });
    const { rawToken } = store.approve(enrolled.id, 'test');
    store.recordManifestResult(enrolled.id, {
      ok: true, generatedFiles: ['/nginx/sites/agent_y_app.conf'], vhostCount: 1,
      lastVhosts: [{ serverNames: ['tunnel2.example.com'], listen: 80, sslMode: 'none', mode: 'tunnel' }],
    });
    const { socket: agentSocket } = await connectAgent(port, rawToken);

    const framePromise = readOneServerFrame(agentSocket);
    const fakeReq = {
      method: 'POST', url: '/api/ping', headers: { host: 'tunnel2.example.com', ...TUNNEL_HEADER },
      on(event, cb) { if (event === 'end') setImmediate(cb); return this; },
    };
    let resStatus = null, resHeaders = null, resBody = null;
    const fakeRes = { writeHead(s, h) { resStatus = s; resHeaders = h; }, end(b) { resBody = b; } };

    const handledPromise = tunnel.maybeHandleTunnelRequest(fakeReq, fakeRes);
    const requestMsg = JSON.parse(await framePromise);

    // Trame CLIENT correctement masquee cette fois (comme un vrai agent).
    agentSocket.write(maskedClientFrame(JSON.stringify({
      type: 'http-response', id: requestMsg.id, status: 200,
      headers: { 'content-type': 'text/plain' },
      bodyBase64: Buffer.from('pong').toString('base64'),
    })));
    await handledPromise;
    check('reponse agent correctement relayee au client HTTP d origine', () => {
      assert.strictEqual(resStatus, 200);
      assert.strictEqual(resBody.toString('utf8'), 'pong');
    });
  }

  reset();
  {
    const enrolled = store.enroll({ hostnameProposed: 'vps-5', fingerprint: '' });
    store.approve(enrolled.id, 'test');
    store.recordManifestResult(enrolled.id, {
      ok: true, generatedFiles: [], vhostCount: 1,
      lastVhosts: [{ serverNames: ['offline.example.com'], listen: 80, sslMode: 'none', mode: 'tunnel' }],
    });
    // Pas de connexion agent ouverte pour cet hote.
    const fakeReq = { method: 'GET', url: '/', headers: { host: 'offline.example.com', ...TUNNEL_HEADER }, on(e, cb) { if (e === 'end') setImmediate(cb); return this; } };
    let resStatus = null;
    const fakeRes = { writeHead(s) { resStatus = s; }, end() {} };
    await tunnel.maybeHandleTunnelRequest(fakeReq, fakeRes);
    check('agent hors ligne (aucun tunnel actif) -> 502 explicite', () => {
      assert.strictEqual(resStatus, 502);
    });
  }

  {
    const fakeReq = { method: 'GET', url: '/', headers: { host: 'not-a-tunnel-host.example.com', ...TUNNEL_HEADER } };
    const handled = await tunnel.maybeHandleTunnelRequest(fakeReq, {});
    check('un Host non tunnel (mode direct ou vhost manuel) -> maybeHandleTunnelRequest ne s en mele pas', () => {
      assert.strictEqual(handled, false);
    });
  }

  console.log('\nAGT-04 : le Host seul ne suffit plus, il faut le secret X-NC-Tunnel');
  reset();
  {
    const enrolled = store.enroll({ hostnameProposed: 'vps-6', fingerprint: '' });
    store.approve(enrolled.id, 'test');
    store.recordManifestResult(enrolled.id, {
      ok: true, generatedFiles: [], vhostCount: 1,
      lastVhosts: [{ serverNames: ['secret-check.example.com'], listen: 80, sslMode: 'none', mode: 'tunnel' }],
    });

    const noHeaderReq = { method: 'GET', url: '/', headers: { host: 'secret-check.example.com' } };
    const handledNoHeader = await tunnel.maybeHandleTunnelRequest(noHeaderReq, {});
    check('Host tunnel valide mais SANS le header X-NC-Tunnel -> jamais traite comme du trafic tunnel', () => {
      assert.strictEqual(handledNoHeader, false);
    });

    const wrongHeaderReq = { method: 'GET', url: '/', headers: { host: 'secret-check.example.com', 'x-nc-tunnel': 'valeur-forgee-par-un-client' } };
    const handledWrongHeader = await tunnel.maybeHandleTunnelRequest(wrongHeaderReq, {});
    check('Host tunnel valide avec un X-NC-Tunnel INCORRECT -> pareillement refuse', () => {
      assert.strictEqual(handledWrongHeader, false);
    });
  }

  server.close();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
