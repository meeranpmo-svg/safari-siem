// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* ws.js - the server side of a WebSocket (RFC 6455), no dependency: used by the remote console tunnel (engine/remote-console.js).
 *   accept(req, socket, head, { protocol, maxMessage }) → ws { send(text), close(code, reason), on('message' | 'close', fn) }
 * Client frames must be masked (the RFC), a message larger than maxMessage (default 1 MB) closes the socket with 1009, pings are
 * answered, fragmented messages are joined. Text and binary messages both arrive as a string (the Guacamole protocol is text).
 */
const crypto = require('node:crypto');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function accept(req, socket, head, opts = {}) {
  const key = String(req.headers['sec-websocket-key'] || '');
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket' || !/^[A-Za-z0-9+/=]{16,40}$/.test(key)) throw Object.assign(new Error('not a WebSocket request'), { status: 400 });
  const offered = String(req.headers['sec-websocket-protocol'] || '').split(',').map((x) => x.trim()).filter(Boolean);
  if (opts.protocol && offered.length && !offered.includes(opts.protocol)) throw Object.assign(new Error('unsupported WebSocket sub-protocol'), { status: 400 });
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n'
    + (opts.protocol && offered.includes(opts.protocol) ? 'Sec-WebSocket-Protocol: ' + opts.protocol + '\r\n' : '') + '\r\n');
  socket.setNoDelay(true);
  const max = opts.maxMessage || 1024 * 1024, handlers = { message: [], close: [] };
  let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0), frag = [], fragLen = 0, closed = false;
  const emit = (ev, ...a) => handlers[ev].forEach((fn) => { try { fn(...a); } catch (e) { /* a handler error must not kill the parser - the handler logs its own */ } });
  function frame(op, payload) {
    const len = payload.length, h = len < 126 ? Buffer.from([0x80 | op, len]) : len < 65536 ? Buffer.from([0x80 | op, 126, len >> 8, len & 255]) : Buffer.concat([Buffer.from([0x80 | op, 127]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(len)); return b; })()]);
    return Buffer.concat([h, payload]);
  }
  function close(code = 1000, reason = '') {
    if (closed) return; closed = true;
    const r = Buffer.from(String(reason).slice(0, 120)), p = Buffer.alloc(2 + r.length); p.writeUInt16BE(code); r.copy(p, 2);
    try { socket.write(frame(0x8, p)); socket.end(); } catch (e) { /* the peer already went away */ }
    setTimeout(() => socket.destroy(), 1000).unref();
    emit('close', code, reason);
  }
  function parse() {
    while (buf.length >= 2) {
      const fin = (buf[0] & 0x80) !== 0, op = buf[0] & 0x0f, masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; } else if (len === 127) { if (buf.length < 10) return; const big = buf.readBigUInt64BE(2); if (big > BigInt(max)) return close(1009, 'message too big'); len = Number(big); off = 10; }
      if (!masked) return close(1002, 'client frames must be masked');
      if (len > max) return close(1009, 'message too big');
      if (buf.length < off + 4 + len) return;
      const mask = buf.slice(off, off + 4), data = Buffer.alloc(len);
      for (let i = 0; i < len; i++) data[i] = buf[off + 4 + i] ^ mask[i & 3];
      buf = buf.slice(off + 4 + len);
      if (op === 0x8) return close(1000, 'bye');
      if (op === 0x9) { try { socket.write(frame(0xA, data)); } catch (e) { /* peer gone */ } continue; }
      if (op === 0xA) continue;
      if (op === 0x1 || op === 0x2 || op === 0x0) {
        frag.push(data); fragLen += len;
        if (fragLen > max) return close(1009, 'message too big');
        if (fin) { const m = Buffer.concat(frag).toString('utf8'); frag = []; fragLen = 0; emit('message', m); }
        continue;
      }
      return close(1002, 'unknown opcode');
    }
  }
  socket.on('data', (d) => { if (closed) return; buf = Buffer.concat([buf, d]); parse(); });
  socket.on('close', () => { if (!closed) { closed = true; emit('close', 1006, 'connection lost'); } });
  socket.on('error', () => { /* followed by 'close', handled there */ });
  if (buf.length) setImmediate(parse);
  return {
    send(text) { if (!closed) try { socket.write(frame(0x1, Buffer.from(String(text), 'utf8'))); } catch (e) { close(1011, 'write failed'); } },
    close, on(ev, fn) { if (handlers[ev]) handlers[ev].push(fn); return this; }, get closed() { return closed; },
  };
}

module.exports = { accept };
