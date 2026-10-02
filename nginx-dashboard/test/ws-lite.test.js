'use strict';
const assert = require('assert');
const crypto = require('crypto');
const ws = require('../lib/ws-lite');

let passed = 0, failed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log('  PASS  ' + name); }
  catch (e) { failed++; console.log('  FAIL  ' + name + ' -- ' + e.message); }
}

check('acceptKeyFor produit la valeur de reference RFC 6455', () => {
  // Exemple canonique de la RFC 6455 section 1.3.
  const key = 'dGhlIHNhbXBsZSBub25jZQ==';
  assert.strictEqual(ws.acceptKeyFor(key), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});

check('handshakeResponse contient le bon Sec-WebSocket-Accept', () => {
  const key = 'dGhlIHNhbXBsZSBub25jZQ==';
  const resp = ws.handshakeResponse(key);
  assert.ok(resp.startsWith('HTTP/1.1 101 Switching Protocols\r\n'));
  assert.ok(resp.includes('Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo='));
});

function maskedClientFrame(payloadStr, opcode) {
  const payload = Buffer.from(payloadStr, 'utf8');
  const maskKey = crypto.randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ maskKey[i & 3];
  let header;
  const len = payload.length;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 0x80 | len;
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
  }
  return Buffer.concat([header, maskKey, masked]);
}

check('FrameParser decode une trame texte masquee simple', () => {
  const frame = maskedClientFrame('bonjour', ws.OPCODE.TEXT);
  let received = null;
  const p = new ws.FrameParser({ onMessage: (opcode, payload) => { received = { opcode, text: payload.toString('utf8') }; } });
  p.push(frame);
  assert.deepStrictEqual(received, { opcode: ws.OPCODE.TEXT, text: 'bonjour' });
});

check('FrameParser gere un payload arrivant en plusieurs morceaux (TCP chunking)', () => {
  const frame = maskedClientFrame('un message un peu plus long pour forcer plusieurs paquets', ws.OPCODE.TEXT);
  let received = null;
  const p = new ws.FrameParser({ onMessage: (opcode, payload) => { received = payload.toString('utf8'); } });
  const mid = Math.floor(frame.length / 2);
  p.push(frame.slice(0, mid));
  assert.strictEqual(received, null); // pas encore une trame complete
  p.push(frame.slice(mid));
  assert.ok(received && received.includes('plusieurs paquets'));
});

check('FrameParser decode plusieurs trames concatenees dans un seul push', () => {
  const f1 = maskedClientFrame('un', ws.OPCODE.TEXT);
  const f2 = maskedClientFrame('deux', ws.OPCODE.TEXT);
  const out = [];
  const p = new ws.FrameParser({ onMessage: (opcode, payload) => out.push(payload.toString('utf8')) });
  p.push(Buffer.concat([f1, f2]));
  assert.deepStrictEqual(out, ['un', 'deux']);
});

check('FrameParser rejette une trame non masquee (violation RFC cote client)', () => {
  const payload = Buffer.from('x');
  const header = Buffer.from([0x80 | ws.OPCODE.TEXT, payload.length]); // pas de bit mask
  let err = null;
  const p = new ws.FrameParser({ onMessage: () => {}, onError: (e) => { err = e; } });
  p.push(Buffer.concat([header, payload]));
  assert.ok(err && /non masquee/.test(err.message));
});

check('FrameParser rejette une trame fragmentee (FIN=0)', () => {
  const frame = maskedClientFrame('x', ws.OPCODE.TEXT);
  frame[0] = frame[0] & 0x7f; // clear FIN bit
  let err = null;
  const p = new ws.FrameParser({ onMessage: () => {}, onError: (e) => { err = e; } });
  p.push(frame);
  assert.ok(err && /fragmentation/.test(err.message));
});

check('FrameParser rejette une trame au-dela de MAX_FRAME_BYTES', () => {
  // On construit juste l'entete annoncant une taille excessive, sans les
  // octets reels (le rejet doit intervenir avant tout buffering du payload).
  const header = Buffer.alloc(10);
  header[0] = 0x80 | ws.OPCODE.BINARY;
  header[1] = 0x80 | 127;
  header.writeUInt32BE(0, 2);
  header.writeUInt32BE(ws.MAX_FRAME_BYTES + 1, 6);
  const maskKey = Buffer.from([1, 2, 3, 4]);
  let err = null;
  const p = new ws.FrameParser({ onMessage: () => {}, onError: (e) => { err = e; } });
  p.push(Buffer.concat([header, maskKey]));
  assert.ok(err && /trop volumineuse/.test(err.message));
});

check('encodeText/encodeFrame produisent une trame non masquee decodable', () => {
  // On reutilise notre propre decodeur en inversant juste le bit mask pour
  // verifier la structure (server->client n'est jamais masque).
  const frame = ws.encodeText('reponse serveur');
  assert.strictEqual((frame[1] & 0x80), 0);
  const len = frame[1] & 0x7f;
  const payload = frame.slice(2, 2 + len).toString('utf8');
  assert.strictEqual(payload, 'reponse serveur');
});

check('encodeFrame gere un payload > 65535 octets (longueur etendue 127)', () => {
  const big = Buffer.alloc(70000, 65);
  const frame = ws.encodeFrame(big, ws.OPCODE.BINARY);
  assert.strictEqual(frame[1] & 0x7f, 127);
  const len = frame.readUInt32BE(6);
  assert.strictEqual(len, 70000);
  assert.strictEqual(frame.length, 10 + 70000);
});

check('encodeClose encode le code de fermeture', () => {
  const frame = ws.encodeClose(1001);
  const len = frame[1] & 0x7f;
  assert.strictEqual(len, 2);
  assert.strictEqual(frame.readUInt16BE(2), 1001);
});

console.log(`\n${passed} pass, ${failed} fail`);
process.exit(failed ? 1 : 0);
