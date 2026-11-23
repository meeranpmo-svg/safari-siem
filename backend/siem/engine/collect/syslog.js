// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Syslog listeners: UDP, TCP (LF framing and RFC 6587 octet-counting, auto-detected per connection) and optional TLS.
//   createSyslog({config, parser, pipeline, log}) → { start() → Promise, stop() → Promise, stats() }
// Each message → parser.parse(line, meta) → pipeline.emit(event). Lines longer than syslog.max_line (64 KB) are truncated
// (fields.truncated = "1"). Peer IP → configured source via config.sources, else the collector's default source.
const dgram = require('node:dgram');
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const { createSourceMap, normPeer } = require('./sources');

const MAX_PEERS = 10000;

// Stream framer. onFrame(buf, truncated). Mode is decided on the first frame of a connection:
// "octet" if it starts with `<digits> <`, otherwise "lf". In octet mode a frame that does not start with digits
// falls back to LF handling for that frame.
function createFramer(maxLine, onFrame) {
  let buf = null;
  let mode = null;
  let skip = 0;        // octet bytes still to discard (oversized frame)
  let dropToLF = false; // discard until next LF (oversized LF frame)

  function emit(b, truncated) {
    let end = b.length;
    while (end > 0 && (b[end - 1] === 10 || b[end - 1] === 13 || b[end - 1] === 0)) end--;
    if (end > 0) onFrame(end === b.length ? b : b.subarray(0, end), truncated);
  }

  function push(chunk) {
    buf = buf && buf.length ? Buffer.concat([buf, chunk]) : chunk;
    let off = 0;
    const n = buf.length;
    while (off < n) {
      if (skip > 0) { const k = Math.min(skip, n - off); off += k; skip -= k; continue; }
      if (dropToLF) { const nl = buf.indexOf(10, off); if (nl < 0) { off = n; break; } off = nl + 1; dropToLF = false; continue; }
      const c = buf[off];
      if (c === 10 || c === 13 || c === 0 || c === 32) { off++; continue; }
      if (c >= 0x31 && c <= 0x39 && mode !== 'lf') {
        let j = off;
        let len = 0;
        while (j < n && j - off < 8 && buf[j] >= 0x30 && buf[j] <= 0x39) { len = len * 10 + (buf[j] - 0x30); j++; }
        if (j >= n) { if (j - off < 8) break; } // need more bytes to decide
        else if (buf[j] === 0x20) {
          if (mode === null) {
            if (j + 1 >= n) break;
            if (buf[j + 1] === 0x3c) mode = 'octet';
          }
          if (mode === 'octet') {
            const start = j + 1;
            if (len > maxLine) {
              if (n - start < maxLine) break;
              emit(buf.subarray(start, start + maxLine), true);
              off = start + maxLine;
              skip = len - maxLine;
              continue;
            }
            if (n - start < len) break;
            emit(buf.subarray(start, start + len), false);
            off = start + len;
            continue;
          }
        }
      }
      // LF framing
      if (mode === null) mode = 'lf';
      const nl = buf.indexOf(10, off);
      if (nl < 0) {
        if (n - off > maxLine) { emit(buf.subarray(off, off + maxLine), true); off = n; dropToLF = true; }
        break;
      }
      if (nl - off > maxLine) emit(buf.subarray(off, off + maxLine), true);
      else emit(buf.subarray(off, nl), false);
      off = nl + 1;
    }
    buf = off >= n ? null : buf.subarray(off);
    if (buf && buf.length > maxLine * 2 + 16) { emit(buf.subarray(0, maxLine), true); buf = null; dropToLF = mode !== 'octet'; }
  }

  function end() {
    if (buf && buf.length && !skip && !dropToLF) {
      if (buf.length > maxLine) emit(buf.subarray(0, maxLine), true);
      else emit(buf, false);
    }
    buf = null;
  }

  return { push, end, mode: () => mode };
}

function createSyslog({ config, parser, pipeline, log }) {
  const sc = config.syslog;
  const maxLine = sc.max_line || 65536;
  let sources = createSourceMap(config.sources || [], sc.default_sources || {});
  const peers = new Map();
  const servers = [];
  const conns = new Set();
  const listeners = {};
  const counters = { messages: 0, bytes: 0, truncated: 0, errors: 0, connections: 0, rejected_connections: 0 };

  function peerStat(ip, collector, srcId) {
    const k = collector + '|' + ip;
    let p = peers.get(k);
    if (!p) {
      if (peers.size >= MAX_PEERS) { const first = peers.keys().next().value; peers.delete(first); }
      p = { peer: ip, collector, src_id: srcId, messages: 0, bytes: 0, truncated: 0, first_seen: Date.now(), last_seen: 0, min: 0, cur: 0, prev: 0 };
      peers.set(k, p);
    }
    return p;
  }

  function handle(frame, peerIp, collector, truncated) {
    const now = Date.now();
    let line = frame.toString('utf8');
    if (collector === 'syslog-udp') { line = line.replace(/[\r\n\0]+$/, ''); if (!line) return; }
    const src = sources.lookup(peerIp, collector);
    const def = (sc.default_sources || {})[collector];
    const unregistered = src.id === 'unknown' || (def && src.id === def.id);
    if (unregistered && sc.unknown_sources !== 'accept') {
      if (log) log.every('syslog-unregistered-' + peerIp, 3600000, 'warn', sc.unknown_sources === 'drop' ? 'syslog: dropped events from an unregistered sender' : 'syslog: events from an unregistered sender (add it to config.json "sources")', { peer: peerIp, collector });
      if (sc.unknown_sources === 'drop') { counters.dropped_unregistered = (counters.dropped_unregistered || 0) + 1; return; }
    }
    const meta = { collector, src_id: src.id, src_type: src.type || 'syslog', peer_ip: peerIp, rts: now, tz_offset_min: src.tz_offset_min !== undefined ? src.tz_offset_min : sc.tz_offset_min };
    counters.messages++;
    counters.bytes += frame.length;
    const p = peerStat(peerIp, collector, src.id);
    p.messages++;
    p.bytes += frame.length;
    p.last_seen = now;
    const m = Math.floor(now / 60000);
    if (m !== p.min) { p.prev = m === p.min + 1 ? p.cur : 0; p.cur = 0; p.min = m; }
    p.cur++;
    let ev;
    try {
      ev = parser.parse(line, meta);
    } catch (e) {
      counters.errors++;
      if (log) log.every('syslog-parse', 30000, 'error', 'syslog: parser failed', { err: e.message });
      return;
    }
    if (truncated) { counters.truncated++; p.truncated++; ev.fields.truncated = '1'; }
    if (unregistered && sc.unknown_sources !== 'accept') { if (!Array.isArray(ev.tags)) ev.tags = []; ev.tags.push('unregistered-source'); }
    pipeline.emit(ev);
  }

  // Connection limits: a global cap, a per-peer cap and an idle timeout, so one host holding thousands of silent
  // sockets cannot lock every TCP/TLS log source out (the slots used to be held until the attacker let go).
  const perPeer = new Map();
  function onConnection(sock, collector) {
    const peer = normPeer(sock.remoteAddress);
    const maxConn = (sc.tcp && sc.tcp.max_connections) || 2000;
    const maxPerPeer = (sc.tcp && sc.tcp.max_connections_per_peer) || 20;
    const idleMs = ((sc.tcp && sc.tcp.idle_timeout_s) || 600) * 1000;
    const mine = perPeer.get(peer) || 0;
    if (conns.size >= maxConn || mine >= maxPerPeer) {
      counters.rejected_connections++;
      if (log) log.every('syslog-conn-limit-' + peer, 60000, 'warn', 'syslog: connection refused (limit reached)', { peer, collector, peer_connections: mine, total: conns.size });
      sock.destroy();
      return;
    }
    conns.add(sock);
    perPeer.set(peer, mine + 1);
    counters.connections++;
    sock.setKeepAlive(true, 60000);
    sock.setTimeout(idleMs, () => { counters.idle_closed = (counters.idle_closed || 0) + 1; sock.destroy(); });
    const framer = createFramer(maxLine, (buf, trunc) => handle(buf, peer, collector, trunc));
    sock.on('data', (chunk) => { try { framer.push(chunk); } catch (e) { counters.errors++; if (log) log.every('syslog-frame', 30000, 'error', 'syslog: framing error', { err: e.message, peer }); } });
    sock.on('end', () => framer.end());
    sock.on('error', (e) => { if (log) log.every('syslog-sock-' + peer, 60000, 'debug', 'syslog: socket error', { peer, err: e.message }); });
    sock.on('close', () => {
      conns.delete(sock);
      const n = (perPeer.get(peer) || 1) - 1;
      if (n > 0) perPeer.set(peer, n); else perPeer.delete(peer);
    });
  }

  function listenTcp(server, port, host, name) {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen({ port, host }, () => {
        server.removeListener('error', reject);
        server.on('error', (e) => log && log.error('syslog: server error', { listener: name, err: e.message }));
        listeners[name] = { host, port: server.address().port };
        resolve();
      });
    });
  }

  async function start() {
    const host = sc.host || '127.0.0.1';
    if (sc.udp && sc.udp.enabled !== false) {
      const sock = dgram.createSocket({ type: net.isIPv6(host) ? 'udp6' : 'udp4', reuseAddr: true, recvBufferSize: 8 * 1024 * 1024 });
      sock.on('message', (msg, rinfo) => {
        try {
          const trunc = msg.length > maxLine;
          handle(trunc ? msg.subarray(0, maxLine) : msg, normPeer(rinfo.address), 'syslog-udp', trunc);
        } catch (e) { counters.errors++; if (log) log.every('syslog-udp', 30000, 'error', 'syslog: udp handler error', { err: e.message }); }
      });
      await new Promise((resolve, reject) => {
        sock.once('error', reject);
        sock.bind({ port: sc.udp.port, address: host }, () => {
          sock.removeListener('error', reject);
          sock.on('error', (e) => log && log.error('syslog: udp error', { err: e.message }));
          try { sock.setRecvBufferSize(8 * 1024 * 1024); } catch { /* OS limit (net.core.rmem_max) */ }
          listeners.udp = { host, port: sock.address().port };
          resolve();
        });
      });
      servers.push({ close: () => new Promise((r) => sock.close(() => r())) });
    }
    if (sc.tcp && sc.tcp.enabled !== false) {
      const srv = net.createServer((s) => onConnection(s, 'syslog-tcp'));
      await listenTcp(srv, sc.tcp.port, host, 'tcp');
      servers.push({ close: () => new Promise((r) => srv.close(() => r())) });
    }
    if (sc.tls && sc.tls.enabled) {
      let opts;
      try {
        opts = { cert: fs.readFileSync(sc.tls.cert), key: fs.readFileSync(sc.tls.key), minVersion: 'TLSv1.2' };
        if (sc.tls.ca) opts.ca = fs.readFileSync(sc.tls.ca);
        // client certificates without our own CA would trust every public CA - any certificate bought anywhere would get in
        if (sc.tls.request_cert && !sc.tls.ca) throw new Error('syslog.tls.request_cert needs syslog.tls.ca (the CA that issues the senders\' certificates)');
        if (sc.tls.request_cert) { opts.requestCert = true; opts.rejectUnauthorized = true; }
      } catch (e) {
        if (log) log.error('syslog: TLS listener disabled — cannot read certificate/key', { err: e.message, cert: sc.tls.cert, key: sc.tls.key });
        opts = null;
      }
      if (opts) {
        const srv = tls.createServer(opts, (s) => onConnection(s, 'syslog-tls'));
        srv.on('tlsClientError', (e) => log && log.every('syslog-tls-client', 60000, 'warn', 'syslog: TLS handshake failed', { err: e.message }));
        await listenTcp(srv, sc.tls.port, host, 'tls');
        servers.push({ close: () => new Promise((r) => srv.close(() => r())) });
      }
    }
    if (log) log.info('syslog: listening', { listeners });
  }

  async function stop() {
    for (const s of conns) s.end();
    const t = setTimeout(() => { for (const s of conns) s.destroy(); }, 2000);
    t.unref();
    await Promise.all(servers.map((s) => s.close()));
    for (const s of conns) s.destroy();
    clearTimeout(t);
  }

  function stats() {
    const now = Date.now();
    const m = Math.floor(now / 60000);
    const list = [];
    for (const p of peers.values()) {
      const lastMin = p.min === m ? p.prev : (p.min === m - 1 ? p.cur : 0);
      list.push({ peer: p.peer, collector: p.collector, src_id: p.src_id, messages: p.messages, bytes: p.bytes, truncated: p.truncated, first_seen: p.first_seen, last_seen: p.last_seen, eps_1m: Math.round((lastMin / 60) * 100) / 100 });
    }
    list.sort((a, b) => b.last_seen - a.last_seen);
    return { listeners, ...counters, open_connections: conns.size, peers: list.slice(0, 500) };
  }

  // reloadSources(): rebuild the peer → source map after config.sources changed in place (Connect hub); open
  // connections keep their current mapping until the next line is looked up
  function reloadSources() { sources = createSourceMap(config.sources || [], sc.default_sources || {}); }
  return { start, stop, stats, reloadSources, get sources() { return sources; } };
}

module.exports = { createSyslog, createFramer };
