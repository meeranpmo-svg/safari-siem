// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Minimal SNMP client (Node stdlib only) for read-only polling: GET, GETNEXT, GETBULK and WALK.
 *   createSnmp({ host, port=161, version:'2c'|'3', community, user, authProto:'sha'|'sha256', authKey, privProto:'aes',
 *                privKey, timeoutMs=2500, retries=1 }) → { get(oids[]), walk(rootOid, {maxRows}), close() }
 *   get() resolves {oid: value}; walk() resolves [[oid, value], ...] in lexical order under rootOid.
 * Values: INTEGER/Counter32/Gauge32/TimeTicks → Number, Counter64 → BigInt, OCTET STRING → Buffer (use str()),
 *         IpAddress → "a.b.c.d", OID → "1.3.6…", noSuchObject/noSuchInstance/endOfMibView → null.
 * SNMPv3: USM authPriv / authNoPriv (RFC 3414) with HMAC-SHA-96 or HMAC-SHA-256-192 (RFC 7860) and AES-128-CFB
 * (RFC 3826); engine discovery and time synchronisation follow RFC 3414 §4. There is no SET: this client cannot change
 * a device. Passwords are kept only as localised keys in memory.
 */
const dgram = require('node:dgram');
const crypto = require('node:crypto');
const net = require('node:net');

const T = { INT: 0x02, OCTETS: 0x04, NULL: 0x05, OID: 0x06, SEQ: 0x30, IP: 0x40, C32: 0x41, G32: 0x42, TT: 0x43, OPAQUE: 0x44, C64: 0x46,
  NOSUCHOBJ: 0x80, NOSUCHINST: 0x81, ENDMIB: 0x82, GET: 0xa0, GETNEXT: 0xa1, RESP: 0xa2, BULK: 0xa5, REPORT: 0xa8 };

/* ---------------- BER */
function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = []; while (n > 0) { b.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | b.length, ...b]);
}
function tlv(type, content) { return Buffer.concat([Buffer.from([type]), len(content.length), content]); }
function encInt(v, type = T.INT) { // minimal two's-complement
  let n = BigInt(v); const out = [];
  for (;;) { const byte = Number(n & 0xffn); out.unshift(byte); n >>= 8n; if ((n === 0n && !(byte & 0x80)) || (n === -1n && byte & 0x80)) break; }
  return tlv(type, Buffer.from(out));
}
function encOctets(b) { return tlv(T.OCTETS, Buffer.isBuffer(b) ? b : Buffer.from(String(b), 'utf8')); }
function encOid(oid) {
  const p = String(oid).replace(/^\./, '').split('.').map(Number);
  if (p.length < 2 || p.some((x) => !Number.isInteger(x) || x < 0)) throw new Error('bad OID ' + oid);
  const out = [p[0] * 40 + p[1]];
  for (let i = 2; i < p.length; i++) { let v = p[i]; const s = [v & 0x7f]; v = Math.floor(v / 128); while (v > 0) { s.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); } out.push(...s); }
  return tlv(T.OID, Buffer.from(out));
}
function seq(type, parts) { return tlv(type, Buffer.concat(parts)); }

function readTlv(buf, off) {
  if (off + 2 > buf.length) throw new Error('truncated');
  const type = buf[off]; let l = buf[off + 1], p = off + 2;
  if (l & 0x80) { const n = l & 0x7f; if (n > 4) throw new Error('length too long'); l = 0; for (let i = 0; i < n; i++) l = l * 256 + buf[p + i]; p += n; }
  if (p + l > buf.length) throw new Error('truncated value');
  return { type, start: p, end: p + l, next: p + l, content: buf.subarray(p, p + l) };
}
function decInt(b, unsigned) {
  if (!b.length) return 0;
  let n = BigInt(!unsigned && b[0] & 0x80 ? -1 : 0);
  for (const x of b) n = (n << 8n) | BigInt(x);
  if (!unsigned && b[0] & 0x80) n = BigInt.asIntN(b.length * 8, n);
  return n;
}
function decOid(b) {
  const out = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { out.push(v); v = 0; } }
  return out.join('.');
}
function decValue(t) {
  switch (t.type) {
    case T.INT: return Number(decInt(t.content, false));
    case T.C32: case T.G32: case T.TT: return Number(decInt(t.content, true));
    case T.C64: return decInt(t.content, true);
    case T.OCTETS: case T.OPAQUE: return Buffer.from(t.content);
    case T.OID: return decOid(t.content);
    case T.IP: return Array.from(t.content).join('.');
    case T.NULL: case T.NOSUCHOBJ: case T.NOSUCHINST: case T.ENDMIB: return null;
    default: return Buffer.from(t.content);
  }
}
function children(buf, t) { const out = []; let o = t.start; while (o < t.end) { const c = readTlv(buf, o); out.push(c); o = c.next; } return out; }

function encPdu(type, reqId, oids, a = 0, b = 0) {
  const vbs = oids.map((o) => seq(T.SEQ, [encOid(o), tlv(T.NULL, Buffer.alloc(0))]));
  return seq(type, [encInt(reqId), encInt(a), encInt(b), seq(T.SEQ, vbs)]);
}
function decPdu(buf, t) {
  const [rid, es, ei, vbl] = children(buf, t);
  const vbs = children(buf, vbl).map((vb) => { const [o, v] = children(buf, vb); return { oid: decOid(o.content), type: v.type, value: decValue(v) }; });
  return { type: t.type, reqId: Number(decInt(rid.content)), errorStatus: Number(decInt(es.content)), errorIndex: Number(decInt(ei.content)), vbs };
}

/* ---------------- USM (RFC 3414 / 3826 / 7860) */
const AUTH = { sha: { hash: 'sha1', mac: 12 }, sha256: { hash: 'sha256', mac: 24 } };
function passwordToKey(password, hash) {
  const pw = Buffer.from(String(password), 'utf8');
  if (pw.length < 8) throw new Error('SNMPv3 passwords must be at least 8 characters');
  const h = crypto.createHash(hash), chunk = Buffer.alloc(64); let idx = 0;
  for (let count = 0; count < 1048576; count += 64) { for (let i = 0; i < 64; i++) chunk[i] = pw[idx++ % pw.length]; h.update(chunk); }
  return h.digest();
}
function localizeKey(ku, engineId, hash) { return crypto.createHash(hash).update(Buffer.concat([ku, engineId, ku])).digest(); }

function createSnmp(opts = {}) {
  const host = opts.host;
  if (!host || !net.isIP(host)) throw new Error('SNMP host must be an IP address');
  const port = opts.port || 161, timeoutMs = opts.timeoutMs || 2500, retries = opts.retries === undefined ? 1 : opts.retries;
  const v3 = String(opts.version || '2c') === '3';
  const sock = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
  let reqId = crypto.randomInt(1, 0x7fffffff), pending = new Map(), closed = false;
  sock.on('message', (msg, rinfo) => {
    if (rinfo.address.replace(/^::ffff:/, '') !== host || rinfo.port !== port) return; // only answers from the polled device
    let parsed; try { parsed = v3 ? parseV3(msg) : parseV2(msg); } catch (e) { return; }
    const p = pending.get(parsed.matchId); if (!p) return;
    pending.delete(parsed.matchId); clearTimeout(p.timer); p.resolve(parsed);
  });
  sock.on('error', () => {});
  sock.unref();

  /* --- v3 state */
  let auth = null, privOn = false, engine = null, ku = null, kp = null;
  if (v3) {
    if (!opts.user) throw new Error('SNMPv3 needs a user');
    if (opts.authKey) { auth = AUTH[String(opts.authProto || 'sha').toLowerCase()]; if (!auth) throw new Error('auth protocol must be sha or sha256'); ku = passwordToKey(opts.authKey, auth.hash); }
    if (opts.privKey) { if (!auth) throw new Error('privacy needs authentication'); if (String(opts.privProto || 'aes').toLowerCase() !== 'aes') throw new Error('privacy protocol must be aes'); privOn = true; kp = passwordToKey(opts.privKey, auth.hash); }
  }
  let localAuth = null, localPriv = null;
  function setEngine(id, boots, time) {
    engine = { id, boots, time, at: Date.now() };
    if (ku) localAuth = localizeKey(ku, id, auth.hash);
    if (kp) localPriv = localizeKey(kp, id, auth.hash).subarray(0, 16);
  }
  function engineTime() { return engine.time + Math.floor((Date.now() - engine.at) / 1000); }

  function parseV2(msg) {
    const top = readTlv(msg, 0), [ver, , pdu] = children(msg, top);
    if (Number(decInt(ver.content)) !== 1) throw new Error('not v2c');
    const d = decPdu(msg, pdu); d.matchId = d.reqId; return d;
  }
  function parseV3(msg) {
    const top = readTlv(msg, 0), [ver, hdr, secp, data] = children(msg, top);
    if (Number(decInt(ver.content)) !== 3) throw new Error('not v3');
    const [mid, , flags] = children(msg, hdr), msgId = Number(decInt(mid.content)), fl = flags.content[0] || 0;
    const sp = readTlv(secp.content, 0), [eid, boots, time, , authP, privP] = children(secp.content, sp);
    const out = { matchId: msgId, engineId: Buffer.from(eid.content), boots: Number(decInt(boots.content)), time: Number(decInt(time.content)) };
    if (fl & 1 && localAuth) { // verify the response really comes from the device holding our key
      const got = Buffer.from(authP.content), copy = Buffer.from(msg);
      const at = secp.start + authP.start; copy.fill(0, at, at + got.length);
      const want = crypto.createHmac(auth.hash, localAuth).update(copy).digest().subarray(0, auth.mac);
      if (got.length !== auth.mac || !crypto.timingSafeEqual(got, want)) throw new Error('bad authentication on response');
    }
    let scoped = data, sbuf = msg;
    if (fl & 2) {
      if (!localPriv) throw new Error('encrypted response without a privacy key');
      const iv = Buffer.concat([u32(out.boots), u32(out.time), Buffer.from(privP.content)]);
      const d = crypto.createDecipheriv('aes-128-cfb', localPriv, iv); sbuf = Buffer.concat([d.update(data.content), d.final()]);
      scoped = readTlv(sbuf, 0);
    }
    const [, , pdu] = children(sbuf, scoped);
    Object.assign(out, decPdu(sbuf, pdu)); return out;
  }
  function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; }

  function buildV2(pdu) { return seq(T.SEQ, [encInt(1), encOctets(opts.community || 'public'), pdu]); }
  function buildV3(pdu, msgId, discovery) {
    const useAuth = !discovery && !!localAuth, usePriv = useAuth && privOn;
    const flags = (useAuth ? 1 : 0) | (usePriv ? 2 : 0) | 4;
    const eid = discovery ? Buffer.alloc(0) : engine.id, boots = discovery ? 0 : engine.boots, time = discovery ? 0 : engineTime();
    const scoped = seq(T.SEQ, [encOctets(eid), encOctets(Buffer.alloc(0)), pdu]);
    let data = scoped, privParams = Buffer.alloc(0);
    if (usePriv) {
      privParams = crypto.randomBytes(8);
      const c = crypto.createCipheriv('aes-128-cfb', localPriv, Buffer.concat([u32(boots), u32(time), privParams]));
      data = encOctets(Buffer.concat([c.update(scoped), c.final()]));
    }
    const marker = useAuth ? crypto.randomBytes(auth.mac) : Buffer.alloc(0);
    const sec = seq(T.SEQ, [encOctets(eid), encInt(boots), encInt(time), encOctets(discovery ? '' : opts.user), encOctets(marker), encOctets(privParams)]);
    const hdr = seq(T.SEQ, [encInt(msgId), encInt(65507), encOctets(Buffer.from([flags])), encInt(3)]);
    const msg = seq(T.SEQ, [encInt(3), hdr, encOctets(sec), data]);
    if (useAuth) {
      const at = msg.indexOf(marker); msg.fill(0, at, at + marker.length);
      crypto.createHmac(auth.hash, localAuth).update(msg).digest().copy(msg, at, 0, auth.mac);
    }
    return msg;
  }

  function send(buf, id) {
    return new Promise((resolve, reject) => {
      let tries = 0;
      const attempt = () => {
        if (closed) return reject(new Error('closed'));
        const timer = setTimeout(() => { if (tries++ < retries) attempt(); else { pending.delete(id); reject(Object.assign(new Error('SNMP timeout'), { code: 'ETIMEDOUT' })); } }, timeoutMs);
        pending.set(id, { resolve, timer });
        sock.send(buf, port, host, (e) => { if (e) { clearTimeout(timer); pending.delete(id); reject(e); } });
      };
      attempt();
    });
  }
  async function discover() {
    const id = nextId(), r = await send(buildV3(encPdu(T.GET, id, []), id, true), id);
    if (!r.engineId || !r.engineId.length) throw new Error('SNMPv3 engine discovery failed');
    setEngine(r.engineId, r.boots, r.time);
  }
  function nextId() { reqId = (reqId % 0x7ffffffe) + 1; return reqId; }

  async function request(type, oids, a, b) {
    if (v3 && !engine) await discover();
    for (let round = 0; round < 2; round++) {
      const id = nextId(), pdu = encPdu(type, id, oids, a, b);
      const r = await send(v3 ? buildV3(pdu, id, false) : buildV2(pdu), id);
      if (r.type === T.REPORT) { // notInTimeWindow → resync once; anything else is an authentication / user problem
        const rep = r.vbs[0] && r.vbs[0].oid;
        if (rep === '1.3.6.1.6.3.15.1.1.2.0' && round === 0) { setEngine(r.engineId, r.boots, r.time); continue; }
        const why = { '1.3.6.1.6.3.15.1.1.3.0': 'unknown SNMPv3 user', '1.3.6.1.6.3.15.1.1.5.0': 'wrong SNMPv3 authentication password', '1.3.6.1.6.3.15.1.1.6.0': 'wrong SNMPv3 privacy password', '1.3.6.1.6.3.15.1.1.1.0': 'unsupported security level' }[rep];
        throw new Error(why || 'SNMPv3 report ' + rep);
      }
      if (r.errorStatus) throw new Error('SNMP error status ' + r.errorStatus);
      return r.vbs;
    }
    throw new Error('SNMPv3 time synchronisation failed');
  }

  async function get(oids) {
    const out = {};
    for (let i = 0; i < oids.length; i += 20) {
      const vbs = await request(T.GET, oids.slice(i, i + 20));
      for (const v of vbs) out[v.oid] = v.value;
    }
    return out;
  }
  async function walk(root, { maxRows = 5000 } = {}) {
    root = String(root).replace(/^\./, '');
    const rows = []; let cur = root;
    while (rows.length < maxRows) {
      const vbs = await request(T.BULK, [cur], 0, 25);
      let done = false;
      for (const v of vbs) {
        if (v.type === T.ENDMIB || !(v.oid === root || v.oid.startsWith(root + '.'))) { done = true; break; }
        if (v.oid === cur) { done = true; break; } // agent not advancing
        rows.push([v.oid, v.value]); cur = v.oid;
      }
      if (done || !vbs.length) break;
    }
    return rows;
  }
  function close() { closed = true; for (const p of pending.values()) clearTimeout(p.timer); pending.clear(); try { sock.close(); } catch (e) { /* closed */ } }
  return { get, walk, close };
}

function str(v) { return Buffer.isBuffer(v) ? v.toString('utf8').replace(/\0+$/, '') : v == null ? '' : String(v); }

module.exports = { createSnmp, str, passwordToKey, localizeKey, _ber: { encInt, encOid, encOctets, tlv, seq, readTlv, decInt, decOid, decValue, children, encPdu, decPdu, T } };
