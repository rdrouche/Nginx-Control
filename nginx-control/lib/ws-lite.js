'use strict';
/**
 * Minimal WebSocket server primitives (RFC 6455) — no npm dependency, same
 * "zero-dependency" discipline as the rest of this project. Written
 * specifically for features/agent-tunnel.js (Partie 2 "avancé", mode 3 —
 * tunnel NAT sortant) : the dashboard needs to actually TERMINATE the
 * WebSocket protocol itself (parse incoming frames, decide what to do with
 * each message, write framed responses back) rather than blindly relay raw
 * bytes to another real WebSocket server the way
 * features/goaccess.js#proxyGoAccessWS() already does for GoAccess's own
 * live report.
 *
 * Deliberately NOT a general-purpose WebSocket library: only what the agent
 * tunnel needs.
 * - Server-side handshake only (we are always the server, the agent is
 *   always the client).
 * - Single-frame messages only (FIN=1, no continuation frames). The agent
 *   reference implementation (see agent/) never fragments a message; a
 *   fragmented incoming frame is treated as a protocol error and the
 *   connection is closed. This keeps the parser small and easy to audit,
 *   at the cost of not being a conformant general WebSocket server.
 * - No permessage-deflate / extension negotiation.
 * - Payloads are capped (see MAX_FRAME_BYTES) — a larger frame closes the
 *   connection rather than buffering unbounded attacker-controlled memory.
 */

const crypto = require('crypto');

const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OPCODE = { CONTINUATION: 0x0, TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };
const MAX_FRAME_BYTES = 8 * 1024 * 1024; // 8MB — generous for a JSON control frame + a buffered HTTP body

/** Sec-WebSocket-Accept value for a given Sec-WebSocket-Key (RFC 6455 §1.3). */
function acceptKeyFor(secWebSocketKey) {
  return crypto.createHash('sha1').update(String(secWebSocketKey || '') + WS_MAGIC).digest('base64');
}

/** The raw HTTP response text that completes a server-side WS handshake. */
function handshakeResponse(secWebSocketKey) {
  return (
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKeyFor(secWebSocketKey) + '\r\n' +
    '\r\n'
  );
}

/** Encode one unmasked server->client frame (server frames are never masked, per RFC 6455). */
function encodeFrame(payload, opcode) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 127;
    header.writeUInt32BE(0, 2); // high 32 bits — frames here never approach 4GB
    header.writeUInt32BE(len, 6);
  }
  return Buffer.concat([header, data]);
}

function encodeText(str) { return encodeFrame(str, OPCODE.TEXT); }
function encodeClose(code) {
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(code || 1000, 0);
  return encodeFrame(buf, OPCODE.CLOSE);
}

/**
 * Incremental frame parser for the CLIENT->SERVER direction (client frames
 * are always masked per RFC 6455 — a server MUST close the connection if it
 * receives an unmasked frame from a client, enforced below).
 *
 * Usage: const p = new FrameParser({ onMessage(opcode, payload) {...},
 * onError(err) {...} }); socket.on('data', chunk => p.push(chunk));
 */
class FrameParser {
  constructor({ onMessage, onError }) {
    this.onMessage = onMessage;
    this.onError = onError;
    this.buf = Buffer.alloc(0);
    this.closed = false;
  }

  push(chunk) {
    if (this.closed) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    // A single push() can contain several complete frames (or none yet) —
    // drain everything currently buffered before waiting for more data.
    for (;;) {
      const consumed = this._tryConsumeOne();
      if (consumed === 0) return; // not enough bytes yet for a full frame
      if (this.closed) return;
    }
  }

  /** Returns 0 if the buffer doesn't yet hold a complete frame, else the number of bytes consumed. */
  _tryConsumeOne() {
    const buf = this.buf;
    if (buf.length < 2) return 0;
    const fin = (buf[0] & 0x80) !== 0;
    const opcode = buf[0] & 0x0f;
    const masked = (buf[1] & 0x80) !== 0;
    let len = buf[1] & 0x7f;
    let offset = 2;

    if (!fin) return this._fail('fragmentation non supportee (FIN=0)');
    if (!masked) return this._fail('trame client non masquee (RFC 6455 viole)');

    if (len === 126) {
      if (buf.length < offset + 2) return 0;
      len = buf.readUInt16BE(offset);
      offset += 2;
    } else if (len === 127) {
      if (buf.length < offset + 8) return 0;
      const high = buf.readUInt32BE(offset);
      const low = buf.readUInt32BE(offset + 4);
      if (high !== 0) return this._fail('trame trop volumineuse');
      len = low;
      offset += 8;
    }
    if (len > MAX_FRAME_BYTES) return this._fail(`trame trop volumineuse (${len} > ${MAX_FRAME_BYTES})`);

    if (buf.length < offset + 4) return 0;
    const maskKey = buf.slice(offset, offset + 4);
    offset += 4;

    if (buf.length < offset + len) return 0;
    const masked_ = buf.slice(offset, offset + len);
    const payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = masked_[i] ^ maskKey[i & 3];
    offset += len;

    this.buf = buf.slice(offset);
    try {
      this.onMessage(opcode, payload);
    } catch (e) {
      this._fail('erreur de traitement du message : ' + e.message);
      return 0;
    }
    return offset;
  }

  _fail(msg) {
    this.closed = true;
    if (this.onError) this.onError(new Error(msg));
    return 0;
  }
}

module.exports = {
  OPCODE, MAX_FRAME_BYTES,
  acceptKeyFor, handshakeResponse,
  encodeFrame, encodeText, encodeClose,
  FrameParser,
};
