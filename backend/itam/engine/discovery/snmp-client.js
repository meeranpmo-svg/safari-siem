// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read-only SNMP client (v1 / v2c / v3 USM) — Node standard library only (dgram + crypto).
 * COPIED unchanged from sentra-print/collector/snmp.js (proven against its in-process fake agent; sentra-netops only has
 * v2c). Keep the copies in step; do not import across repos.
 *
 *   BER codec   encodeValue / decodeValue, encodePdu / decodePdu, encodeCommunityMessage, encodeV3Message, decodeMessage
 *   USM         passwordToKey + localizeKey (RFC 3414 A.2, SHA-1 and SHA-256 per RFC 7860), HMAC-SHA-96 (12 bytes) and
 *               HMAC-SHA-256-192 (24 bytes), AES-128-CFB privacy (RFC 3826: IV = engineBoots | engineTime | salt)
 *   Session     createSession({host, port, version:'1'|'2c'|'3', community, user, authProtocol:'sha'|'sha256',
 *               authPassword, privProtocol:'aes', privPassword, timeout, retries, maxRepetitions})
 *               → { get(oids), getNext(oids), getBulk(oids, nonRepeaters, maxRepetitions), walk(root), table(root),
 *                   discoverEngine(), close() }
 *
 * SAFETY: this module can only produce GetRequest, GetNextRequest, GetBulkRequest (and, for the test agent, Response /
 * Report). There is deliberately NO SetRequest anywhere: encodePdu() refuses every PDU type outside ALLOWED_PDU and
 * the message encoders re-check the PDU tag of the bytes they wrap. tests/snmp-ber.test.js asserts this.
 */
const dgram = require('node:dgram');
const crypto = require('node:crypto');

// ---- BER tags ------------------------------------------------------------------------------------------------------
const TAG = Object.freeze({
  INTEGER: 0x02, OCTET_STRING: 0x04, NULL: 0x05, OID: 0x06, SEQUENCE: 0x30,
  IP_ADDRESS: 0x40, COUNTER32: 0x41, GAUGE32: 0x42, TIMETICKS: 0x43, OPAQUE: 0x44, COUNTER64: 0x46,
  NO_SUCH_OBJECT: 0x80, NO_SUCH_INSTANCE: 0x81, END_OF_MIB_VIEW: 0x82,
});
// PDU tags this code may produce. Read-only by construction: no SetRequest, no traps/informs.
const PDU = Object.freeze({ GET: 0xa0, GETNEXT: 0xa1, RESPONSE: 0xa2, GETBULK: 0xa5, REPORT: 0xa8 });
const ALLOWED_PDU = new Set([PDU.GET, PDU.GETNEXT, PDU.RESPONSE, PDU.GETBULK, PDU.REPORT]);
const REQUEST_PDU = new Set([PDU.GET, PDU.GETNEXT, PDU.GETBULK]);

const ERROR_STATUS = ['noError', 'tooBig', 'noSuchName', 'badValue', 'readOnly', 'genErr', 'noAccess', 'wrongType',
  'wrongLength', 'wrongEncoding', 'wrongValue', 'noCreation', 'inconsistentValue', 'resourceUnavailable', 'commitFailed',
  'undoFailed', 'authorizationError', 'notWritable', 'inconsistentName'];

const USM_REPORTS = {
  '1.3.6.1.6.3.15.1.1.1.0': 'unsupportedSecLevels',
  '1.3.6.1.6.3.15.1.1.2.0': 'notInTimeWindows',
  '1.3.6.1.6.3.15.1.1.3.0': 'unknownUserNames',
  '1.3.6.1.6.3.15.1.1.4.0': 'unknownEngineIDs',
  '1.3.6.1.6.3.15.1.1.5.0': 'wrongDigests',
  '1.3.6.1.6.3.15.1.1.6.0': 'decryptionErrors',
};

class SnmpError extends Error {
  constructor(code, message) { super(message || code); this.code = code; this.name = 'SnmpError'; }
}

// ---- length / TLV --------------------------------------------------------------------------------------------------
function encLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, value) { return Buffer.concat([Buffer.from([tag]), encLen(value.length), value]); }

function readTLV(buf, pos) {
  if (pos + 2 > buf.length) throw new SnmpError('ber', 'truncated TLV header');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new SnmpError('ber', 'high-tag-number form not supported');
  let len = buf[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) throw new SnmpError('ber', 'indefinite length not allowed');
    if (n > 4) throw new SnmpError('ber', 'length too large');
    if (p + n > buf.length) throw new SnmpError('ber', 'truncated length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) throw new SnmpError('ber', 'truncated value');
  return { tag, hdr: pos, start: p, len, end: p + len };
}
function children(buf, t) {
  const out = [];
  let p = t.start;
  while (p < t.end) { const c = readTLV(buf, p); out.push(c); p = c.end; }
  if (p !== t.end) throw new SnmpError('ber', 'constructed value overruns');
  return out;
}

// ---- INTEGER (signed, two's complement, minimal) ------------------------------------------------------------------
function encIntBody(v) {
  let n = BigInt(v);
  const bytes = [];
  for (;;) {
    const b = Number(n & 0xffn);
    bytes.unshift(b);
    const rest = n >> 8n;
    if ((rest === 0n && (b & 0x80) === 0) || (rest === -1n && (b & 0x80) !== 0)) break;
    n = rest;
  }
  return Buffer.from(bytes);
}
function decIntBig(body) {
  if (!body.length) throw new SnmpError('ber', 'empty INTEGER');
  let n = 0n;
  for (const b of body) n = (n << 8n) | BigInt(b);
  if (body[0] & 0x80) n -= 1n << BigInt(body.length * 8);
  return n;
}
function toNum(big) { return big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big; }
const encInt = (v) => tlv(TAG.INTEGER, encIntBody(v));
function decUnsigned(body, bits) {
  let n = decIntBig(body);
  if (n < 0n) n += 1n << BigInt(bits); // tolerate agents that forget the leading 0x00
  return n & ((1n << BigInt(bits)) - 1n);
}

// ---- OBJECT IDENTIFIER --------------------------------------------------------------------------------------------
function parseOid(oid) {
  const arcs = Array.isArray(oid) ? oid.slice() : String(oid).replace(/^\./, '').split('.').map((s) => (s === '' ? NaN : Number(s)));
  if (arcs.length < 2) throw new SnmpError('oid', `invalid OID "${oid}"`);
  for (const a of arcs) if (!Number.isInteger(a) || a < 0 || a > 4294967295) throw new SnmpError('oid', `invalid OID "${oid}"`);
  if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) throw new SnmpError('oid', `invalid OID "${oid}"`);
  return arcs;
}
function pushArc(out, v) {
  const tmp = [v % 128];
  v = Math.floor(v / 128);
  while (v > 0) { tmp.unshift((v % 128) | 0x80); v = Math.floor(v / 128); }
  for (const b of tmp) out.push(b);
}
function encOidBody(oid) {
  const arcs = parseOid(oid);
  const out = [];
  pushArc(out, arcs[0] * 40 + arcs[1]);
  for (let i = 2; i < arcs.length; i++) pushArc(out, arcs[i]);
  return Buffer.from(out);
}
function decOidBody(body) {
  if (!body.length) throw new SnmpError('ber', 'empty OID');
  const arcs = [];
  let v = 0; let inArc = false;
  for (const b of body) {
    v = v * 128 + (b & 0x7f);
    inArc = !!(b & 0x80);
    if (!inArc) { arcs.push(v); v = 0; }
    if (v > 0xffffffff * 128) throw new SnmpError('ber', 'OID arc too large');
  }
  if (inArc) throw new SnmpError('ber', 'truncated OID');
  const first = arcs.shift();
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return head.concat(arcs).join('.');
}
function oidCompare(a, b) {
  const x = parseOid(a); const y = parseOid(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}
function oidStartsWith(oid, root) {
  const o = String(oid).replace(/^\./, ''); const r = String(root).replace(/^\./, '');
  return o.startsWith(r + '.');
}

// ---- values ---------------------------------------------------------------------------------------------------------
function checkUnsigned(v, bits, type) {
  const n = BigInt(v);
  if (n < 0n || n >= (1n << BigInt(bits))) throw new SnmpError('range', `${type} out of range`);
  return n;
}
function encodeValue(val) {
  const type = val && val.type ? val.type : 'Null';
  const v = val ? val.value : null;
  switch (type) {
    case 'Integer': {
      const n = BigInt(v);
      if (n < -(1n << 31n) || n >= (1n << 31n)) throw new SnmpError('range', 'Integer32 out of range');
      return tlv(TAG.INTEGER, encIntBody(n));
    }
    case 'OctetString': return tlv(TAG.OCTET_STRING, Buffer.isBuffer(v) ? v : Buffer.from(String(v === null || v === undefined ? '' : v), 'utf8'));
    case 'Null': return Buffer.from([TAG.NULL, 0]);
    case 'OID': return tlv(TAG.OID, encOidBody(v));
    case 'IpAddress': {
      const parts = String(v).split('.').map(Number);
      if (parts.length !== 4 || parts.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) throw new SnmpError('range', 'invalid IpAddress');
      return tlv(TAG.IP_ADDRESS, Buffer.from(parts));
    }
    case 'Counter32': return tlv(TAG.COUNTER32, encIntBody(checkUnsigned(v, 32, type)));
    case 'Gauge32': return tlv(TAG.GAUGE32, encIntBody(checkUnsigned(v, 32, type)));
    case 'TimeTicks': return tlv(TAG.TIMETICKS, encIntBody(checkUnsigned(v, 32, type)));
    case 'Counter64': return tlv(TAG.COUNTER64, encIntBody(checkUnsigned(v, 64, type)));
    case 'Opaque': return tlv(TAG.OPAQUE, Buffer.isBuffer(v) ? v : Buffer.alloc(0));
    case 'NoSuchObject': return Buffer.from([TAG.NO_SUCH_OBJECT, 0]);
    case 'NoSuchInstance': return Buffer.from([TAG.NO_SUCH_INSTANCE, 0]);
    case 'EndOfMibView': return Buffer.from([TAG.END_OF_MIB_VIEW, 0]);
    default: throw new SnmpError('type', `unknown value type ${type}`);
  }
}
function decodeValue(tag, body) {
  switch (tag) {
    case TAG.INTEGER: return { type: 'Integer', value: toNum(decIntBig(body)) };
    case TAG.OCTET_STRING: return { type: 'OctetString', value: Buffer.from(body) };
    case TAG.NULL: return { type: 'Null', value: null };
    case TAG.OID: return { type: 'OID', value: decOidBody(body) };
    case TAG.IP_ADDRESS: if (body.length !== 4) throw new SnmpError('ber', 'bad IpAddress'); return { type: 'IpAddress', value: [...body].join('.') };
    case TAG.COUNTER32: return { type: 'Counter32', value: Number(decUnsigned(body, 32)) };
    case TAG.GAUGE32: return { type: 'Gauge32', value: Number(decUnsigned(body, 32)) };
    case TAG.TIMETICKS: return { type: 'TimeTicks', value: Number(decUnsigned(body, 32)) };
    case TAG.COUNTER64: return { type: 'Counter64', value: decUnsigned(body, 64) };
    case TAG.OPAQUE: return { type: 'Opaque', value: Buffer.from(body) };
    case TAG.NO_SUCH_OBJECT: return { type: 'NoSuchObject', value: null };
    case TAG.NO_SUCH_INSTANCE: return { type: 'NoSuchInstance', value: null };
    case TAG.END_OF_MIB_VIEW: return { type: 'EndOfMibView', value: null };
    default: return { type: 'Unknown', value: Buffer.from(body), tag };
  }
}

// ---- PDUs -----------------------------------------------------------------------------------------------------------
function assertAllowed(pduType) {
  if (!ALLOWED_PDU.has(pduType)) throw new SnmpError('forbidden', `PDU type 0x${Number(pduType).toString(16)} is not allowed: this SNMP code is read-only`);
}
function encodePdu(pduType, { requestId, errorStatus = 0, errorIndex = 0, varbinds = [] } = {}) {
  assertAllowed(pduType);
  const vbs = varbinds.map((vb) => tlv(TAG.SEQUENCE, Buffer.concat([tlv(TAG.OID, encOidBody(vb.oid)), encodeValue(vb.type ? vb : { type: 'Null' })])));
  return tlv(pduType, Buffer.concat([encInt(requestId), encInt(errorStatus), encInt(errorIndex), tlv(TAG.SEQUENCE, Buffer.concat(vbs))]));
}
function decodePdu(buf, t) {
  if (!t) t = readTLV(buf, 0);
  const [rid, es, ei, list] = children(buf, t);
  if (!list || rid.tag !== TAG.INTEGER || es.tag !== TAG.INTEGER || ei.tag !== TAG.INTEGER || list.tag !== TAG.SEQUENCE) throw new SnmpError('ber', 'malformed PDU');
  const varbinds = children(buf, list).map((vbT) => {
    const [o, v] = children(buf, vbT);
    if (!o || !v || o.tag !== TAG.OID) throw new SnmpError('ber', 'malformed varbind');
    return Object.assign({ oid: decOidBody(buf.subarray(o.start, o.end)) }, decodeValue(v.tag, buf.subarray(v.start, v.end)));
  });
  return {
    type: t.tag,
    requestId: Number(decIntBig(buf.subarray(rid.start, rid.end))),
    errorStatus: Number(decIntBig(buf.subarray(es.start, es.end))),
    errorIndex: Number(decIntBig(buf.subarray(ei.start, ei.end))),
    varbinds,
  };
}

// v1 (version 0) / v2c (version 1) community message
function encodeCommunityMessage(version, community, pduBuf) {
  if (version !== 0 && version !== 1) throw new SnmpError('version', 'community messages are v1 (0) or v2c (1)');
  assertAllowed(pduBuf[0]);
  return tlv(TAG.SEQUENCE, Buffer.concat([encInt(version), tlv(TAG.OCTET_STRING, Buffer.from(String(community), 'utf8')), pduBuf]));
}

// ---- SNMPv3 / USM (RFC 3412, 3414, 3826, 7860) ---------------------------------------------------------------------
const AUTH = Object.freeze({
  sha: { name: 'sha', hash: 'sha1', macLen: 12, oid: '1.3.6.1.6.3.10.1.1.3' },      // usmHMACSHAAuthProtocol (HMAC-SHA-96)
  sha256: { name: 'sha256', hash: 'sha256', macLen: 24, oid: '1.3.6.1.6.3.10.1.1.5' }, // usmHMAC192SHA256AuthProtocol
});
function authProto(name) {
  if (!name) return null;
  const n = String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (n === 'sha' || n === 'sha1' || n === 'hmacsha96') return AUTH.sha;
  if (n === 'sha256' || n === 'hmac192sha256' || n === 'hmacsha256') return AUTH.sha256;
  throw new SnmpError('config', `unsupported auth protocol "${name}" (sha or sha256)`);
}
function privProto(name) {
  if (!name) return null;
  const n = String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (n === 'aes' || n === 'aes128' || n === 'aescfb128') return 'aes128';
  throw new SnmpError('config', `unsupported privacy protocol "${name}" (aes)`);
}

// RFC 3414 A.2: hash 1 MiB of the repeated passphrase → Ku; localise: Kul = H(Ku | engineID | Ku)
function passwordToKey(password, hashName) {
  const pw = Buffer.from(String(password), 'utf8');
  if (pw.length < 8) throw new SnmpError('config', 'SNMPv3 passphrases must be at least 8 characters');
  const h = crypto.createHash(hashName);
  const chunk = Buffer.alloc(64);
  let idx = 0;
  for (let count = 0; count < 1048576; count += 64) {
    for (let i = 0; i < 64; i++) chunk[i] = pw[idx++ % pw.length];
    h.update(chunk);
  }
  return h.digest();
}
function localizeKey(ku, engineId, hashName) {
  return crypto.createHash(hashName).update(Buffer.concat([ku, engineId, ku])).digest();
}

function aesIv(boots, time, salt) {
  const iv = Buffer.alloc(16);
  iv.writeUInt32BE(boots >>> 0, 0);
  iv.writeUInt32BE(time >>> 0, 4);
  salt.copy(iv, 8, 0, 8);
  return iv;
}
function aesEncrypt(privKey, boots, time, salt, plain) {
  const c = crypto.createCipheriv('aes-128-cfb', privKey.subarray(0, 16), aesIv(boots, time, salt));
  return Buffer.concat([c.update(plain), c.final()]);
}
function aesDecrypt(privKey, boots, time, salt, data) {
  if (!salt || salt.length !== 8) throw new SnmpError('decryptionError', 'privacy parameters must be 8 bytes');
  const d = crypto.createDecipheriv('aes-128-cfb', privKey.subarray(0, 16), aesIv(boots, time, salt));
  return Buffer.concat([d.update(data), d.final()]);
}

function encodeScopedPdu(contextEngineId, contextName, pduBuf) {
  assertAllowed(pduBuf[0]);
  return tlv(TAG.SEQUENCE, Buffer.concat([tlv(TAG.OCTET_STRING, contextEngineId || Buffer.alloc(0)), tlv(TAG.OCTET_STRING, Buffer.from(contextName || '', 'utf8')), pduBuf]));
}
function decodeScopedPdu(buf) {
  const t = readTLV(buf, 0);
  if (t.tag !== TAG.SEQUENCE) throw new SnmpError('decryptionError', 'scoped PDU is not a SEQUENCE (wrong privacy key?)');
  const [ce, cn, pdu] = children(buf, t);
  if (!pdu || ce.tag !== TAG.OCTET_STRING || cn.tag !== TAG.OCTET_STRING) throw new SnmpError('ber', 'malformed scoped PDU');
  return { contextEngineId: Buffer.from(buf.subarray(ce.start, ce.end)), contextName: buf.subarray(cn.start, cn.end).toString('utf8'), pdu: decodePdu(buf, pdu) };
}

/**
 * encodeV3Message({msgId, maxSize, flags, engineId, boots, time, user, authParams, privParams, scopedPdu | encryptedPdu})
 * authParams must be the zero placeholder of the right length when the message is to be signed (signV3()).
 */
function encodeV3Message(m) {
  if (m.scopedPdu) {
    const sp = readTLV(m.scopedPdu, 0);
    const inner = children(m.scopedPdu, sp);
    assertAllowed(m.scopedPdu[inner[2].hdr]);
  }
  const global = tlv(TAG.SEQUENCE, Buffer.concat([encInt(m.msgId), encInt(m.maxSize || 65507), tlv(TAG.OCTET_STRING, Buffer.from([m.flags & 0xff])), encInt(3)]));
  const usm = tlv(TAG.SEQUENCE, Buffer.concat([
    tlv(TAG.OCTET_STRING, m.engineId || Buffer.alloc(0)), encInt(m.boots || 0), encInt(m.time || 0),
    tlv(TAG.OCTET_STRING, Buffer.from(m.user || '', 'utf8')), tlv(TAG.OCTET_STRING, m.authParams || Buffer.alloc(0)), tlv(TAG.OCTET_STRING, m.privParams || Buffer.alloc(0)),
  ]));
  const data = m.encryptedPdu ? tlv(TAG.OCTET_STRING, m.encryptedPdu) : m.scopedPdu;
  if (!data) throw new SnmpError('ber', 'v3 message needs scopedPdu or encryptedPdu');
  return tlv(TAG.SEQUENCE, Buffer.concat([encInt(3), global, tlv(TAG.OCTET_STRING, usm), data]));
}

// position of msgAuthenticationParameters inside a v3 message (for signing and verification)
function locateAuthParams(buf) {
  const outer = readTLV(buf, 0);
  const parts = children(buf, outer);
  const sec = parts[2];
  const usm = readTLV(buf, sec.start);
  const f = children(buf, usm);
  return { start: f[4].start, end: f[4].end, len: f[4].len };
}
function hmacOf(proto, key, buf) { return crypto.createHmac(proto.hash, key).update(buf).digest().subarray(0, proto.macLen); }
function signV3(buf, proto, authKey) {
  const loc = locateAuthParams(buf);
  if (loc.len !== proto.macLen) throw new SnmpError('ber', 'auth placeholder has the wrong length');
  const out = Buffer.from(buf);
  out.fill(0, loc.start, loc.end);
  hmacOf(proto, authKey, out).copy(out, loc.start);
  return out;
}
function verifyV3(buf, proto, authKey) {
  const loc = locateAuthParams(buf);
  if (loc.len !== proto.macLen) return false;
  const got = Buffer.from(buf.subarray(loc.start, loc.end));
  const copy = Buffer.from(buf);
  copy.fill(0, loc.start, loc.end);
  return crypto.timingSafeEqual(got, hmacOf(proto, authKey, copy));
}

/** decodeMessage(buf) → v1/v2c: {version, community, pdu}; v3: {version:3, msgId, maxSize, flags, secModel, usm, scopedPdu?, encryptedPdu?} */
function decodeMessage(buf) {
  const outer = readTLV(buf, 0);
  if (outer.tag !== TAG.SEQUENCE || outer.end !== buf.length) throw new SnmpError('ber', 'message is not a single SEQUENCE');
  const parts = children(buf, outer);
  if (!parts.length || parts[0].tag !== TAG.INTEGER) throw new SnmpError('ber', 'missing version');
  const version = Number(decIntBig(buf.subarray(parts[0].start, parts[0].end)));
  if (version === 0 || version === 1) {
    const [, c, p] = parts;
    if (!c || !p || c.tag !== TAG.OCTET_STRING) throw new SnmpError('ber', 'malformed community message');
    return { version, community: buf.subarray(c.start, c.end).toString('utf8'), pdu: decodePdu(buf, p) };
  }
  if (version !== 3) throw new SnmpError('version', `unsupported SNMP version ${version}`);
  const [, g, s, d] = parts;
  if (!g || !s || !d || g.tag !== TAG.SEQUENCE || s.tag !== TAG.OCTET_STRING) throw new SnmpError('ber', 'malformed v3 message');
  const gf = children(buf, g);
  const int = (t) => Number(decIntBig(buf.subarray(t.start, t.end)));
  const usmT = readTLV(buf, s.start);
  const u = children(buf, usmT);
  if (u.length !== 6) throw new SnmpError('ber', 'malformed USM parameters');
  const usm = {
    engineId: Buffer.from(buf.subarray(u[0].start, u[0].end)), boots: int(u[1]), time: int(u[2]),
    user: buf.subarray(u[3].start, u[3].end).toString('utf8'),
    authParams: Buffer.from(buf.subarray(u[4].start, u[4].end)), privParams: Buffer.from(buf.subarray(u[5].start, u[5].end)),
  };
  const flagsBuf = buf.subarray(gf[2].start, gf[2].end);
  const msg = { version: 3, msgId: int(gf[0]), maxSize: int(gf[1]), flags: flagsBuf.length ? flagsBuf[0] : 0, secModel: int(gf[3]), usm };
  if (d.tag === TAG.OCTET_STRING) msg.encryptedPdu = Buffer.from(buf.subarray(d.start, d.end));
  else msg.scopedPdu = Buffer.from(buf.subarray(d.hdr, d.end));
  return msg;
}

// ---- value helpers ---------------------------------------------------------------------------------------------------
const isException = (vb) => !vb || vb.type === 'NoSuchObject' || vb.type === 'NoSuchInstance' || vb.type === 'EndOfMibView';
function vbString(vb) {
  if (isException(vb) || vb.value === null || vb.value === undefined) return null;
  if (Buffer.isBuffer(vb.value)) return vb.value.toString('utf8').replace(/\u0000+$/g, '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').trim();
  return String(vb.value);
}
function vbNumber(vb) {
  if (isException(vb)) return null;
  if (typeof vb.value === 'number') return vb.value;
  if (typeof vb.value === 'bigint') return vb.value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(vb.value) : null;
  return null;
}
function vbHex(vb) { return isException(vb) || !Buffer.isBuffer(vb.value) ? null : vb.value.toString('hex'); }

// ---- session ----------------------------------------------------------------------------------------------------------
let idSeed = crypto.randomBytes(4).readUInt32BE(0) & 0x3fffffff;
function nextId() { idSeed = (idSeed + 1) & 0x7fffffff; if (idSeed === 0) idSeed = 1; return idSeed; }

const keyCache = new Map(); // `${hash}\0${password}` → Ku (passphrase-derived master key; never logged)
function masterKey(password, hash) {
  const k = `${hash}\u0000${password}`;
  let v = keyCache.get(k);
  if (!v) { v = passwordToKey(password, hash); keyCache.set(k, v); if (keyCache.size > 64) keyCache.delete(keyCache.keys().next().value); }
  return v;
}

function createSession(opts = {}) {
  const host = opts.host;
  const port = opts.port || 161;
  const version = String(opts.version || '2c');
  if (!['1', '2c', '3'].includes(version)) throw new SnmpError('config', `unsupported SNMP version ${version}`);
  const timeout = opts.timeout || 2000;
  const retries = opts.retries === undefined ? 1 : opts.retries;
  const maxRep = opts.maxRepetitions || 20;
  const community = opts.community === undefined ? 'public' : String(opts.community);
  const v3 = version === '3' ? {
    user: String(opts.user || ''),
    auth: authProto(opts.authProtocol),
    priv: privProto(opts.privProtocol),
    authPassword: opts.authPassword, privPassword: opts.privPassword,
    context: opts.context || '',
  } : null;
  if (v3) {
    if (!v3.user) throw new SnmpError('config', 'SNMPv3 needs a user name');
    if (v3.priv && !v3.auth) throw new SnmpError('config', 'SNMPv3 privacy requires authentication');
    if (v3.auth && !v3.authPassword) throw new SnmpError('config', 'SNMPv3 auth passphrase missing');
    if (v3.priv && !v3.privPassword) throw new SnmpError('config', 'SNMPv3 privacy passphrase missing');
  }
  let sock = null;
  const pending = new Map();
  let engine = null;           // {id, boots, time, at}
  let keys = null;             // {engineHex, auth, priv}
  let salt = BigInt('0x' + crypto.randomBytes(8).toString('hex'));
  let closed = false;

  function socket() {
    if (sock) return sock;
    sock = dgram.createSocket('udp4');
    sock.on('message', (msg, rinfo) => {
      if (rinfo.port !== port || (rinfo.address !== host && host !== 'localhost')) return;
      let key;
      try {
        const m = decodeMessage(msg);
        if (m.version === 3) key = 'm' + m.msgId;
        else key = 'r' + m.pdu.requestId;
        const p = pending.get(key);
        if (p) p.done(null, { raw: msg, msg: m });
      } catch { /* malformed datagram: ignore, the request times out */ }
    });
    sock.on('error', () => { /* per-request errors surface as timeouts */ });
    sock.unref();
    return sock;
  }

  function exchange(buf, key) {
    if (closed) return Promise.reject(new SnmpError('closed', 'session closed'));
    const s = socket();
    return new Promise((resolve, reject) => {
      let tries = 0; let timer = null;
      const done = (err, res) => {
        clearTimeout(timer);
        pending.delete(key);
        if (err) reject(err); else resolve(res);
      };
      const send = () => {
        tries++;
        s.send(buf, port, host, (err) => { if (err) done(new SnmpError('send', err.message)); });
        timer = setTimeout(() => { if (tries <= retries) send(); else done(new SnmpError('timeout', `no response from ${host}:${port}`)); }, timeout);
      };
      pending.set(key, { done });
      send();
    });
  }

  function checkPdu(pdu, reqId) {
    if (pdu.requestId !== reqId) throw new SnmpError('mismatch', 'response request-id mismatch');
    if (pdu.errorStatus) {
      const e = new SnmpError(ERROR_STATUS[pdu.errorStatus] || `error${pdu.errorStatus}`, `SNMP error ${ERROR_STATUS[pdu.errorStatus] || pdu.errorStatus} (index ${pdu.errorIndex})`);
      e.errorStatus = pdu.errorStatus; e.errorIndex = pdu.errorIndex;
      throw e;
    }
    return pdu.varbinds;
  }

  async function requestCommunity(type, varbinds, a = 0, b = 0) {
    const requestId = nextId();
    const pdu = encodePdu(type, { requestId, errorStatus: a, errorIndex: b, varbinds });
    const buf = encodeCommunityMessage(version === '1' ? 0 : 1, community, pdu);
    const { msg } = await exchange(buf, 'r' + requestId);
    if (msg.pdu.type !== PDU.RESPONSE) throw new SnmpError('unexpected', 'unexpected PDU type in response');
    return checkPdu(msg.pdu, requestId);
  }

  function engineTimeNow() {
    return engine.time + Math.floor((Date.now() - engine.at) / 1000);
  }
  function setEngine(usm) {
    engine = { id: Buffer.from(usm.engineId), boots: usm.boots, time: usm.time, at: Date.now() };
    const hex = engine.id.toString('hex');
    if (!keys || keys.engineHex !== hex) {
      keys = { engineHex: hex, auth: null, priv: null };
      if (v3.auth) {
        keys.auth = localizeKey(masterKey(v3.authPassword, v3.auth.hash), engine.id, v3.auth.hash);
        if (v3.priv) keys.priv = localizeKey(masterKey(v3.privPassword, v3.auth.hash), engine.id, v3.auth.hash);
      }
    }
  }

  async function discoverEngine() {
    if (engine) return { engineId: engine.id.toString('hex'), boots: engine.boots, time: engineTimeNow() };
    const msgId = nextId();
    const pdu = encodePdu(PDU.GET, { requestId: nextId(), varbinds: [] });
    const buf = encodeV3Message({ msgId, flags: 0x04, engineId: Buffer.alloc(0), boots: 0, time: 0, user: '', scopedPdu: encodeScopedPdu(Buffer.alloc(0), '', pdu) });
    const { msg } = await exchange(buf, 'm' + msgId);
    if (msg.version !== 3 || !msg.usm.engineId.length) throw new SnmpError('discovery', 'engine discovery failed');
    setEngine(msg.usm);
    return { engineId: engine.id.toString('hex'), boots: engine.boots, time: engine.time };
  }

  function openV3(msg) {
    // authentication (when the agent claims it) with our localised key
    if (msg.flags & 0x01) {
      if (!v3.auth) throw new SnmpError('authenticationFailure', 'unexpected authenticated response');
      if (msg.usm.engineId.toString('hex') !== keys.engineHex) throw new SnmpError('authenticationFailure', 'response from a different engine');
      if (!verifyV3(msg.raw, v3.auth, keys.auth)) throw new SnmpError('authenticationFailure', 'response failed HMAC verification');
    }
    let scoped = msg.scopedPdu;
    if (msg.flags & 0x02) {
      if (!v3.priv || !msg.encryptedPdu) throw new SnmpError('decryptionError', 'unexpected encrypted response');
      scoped = aesDecrypt(keys.priv, msg.usm.boots, msg.usm.time, msg.usm.privParams, msg.encryptedPdu);
    }
    if (!scoped) throw new SnmpError('ber', 'response without scoped PDU');
    return decodeScopedPdu(scoped).pdu;
  }

  async function requestV3(type, varbinds, a = 0, b = 0) {
    await discoverEngine();
    for (let attempt = 0; attempt < 2; attempt++) {
      const requestId = nextId();
      const msgId = nextId();
      const pdu = encodePdu(type, { requestId, errorStatus: a, errorIndex: b, varbinds });
      const scoped = encodeScopedPdu(engine.id, v3.context, pdu);
      const boots = engine.boots; const time = engineTimeNow();
      let flags = 0x04;
      let privParams = Buffer.alloc(0); let encryptedPdu = null;
      if (v3.auth) flags |= 0x01;
      if (v3.priv) {
        flags |= 0x02;
        salt = (salt + 1n) & 0xffffffffffffffffn;
        privParams = Buffer.from(salt.toString(16).padStart(16, '0'), 'hex');
        encryptedPdu = aesEncrypt(keys.priv, boots, time, privParams, scoped);
      }
      let buf = encodeV3Message({
        msgId, flags, engineId: engine.id, boots, time, user: v3.user,
        authParams: v3.auth ? Buffer.alloc(v3.auth.macLen) : Buffer.alloc(0), privParams,
        scopedPdu: encryptedPdu ? null : scoped, encryptedPdu,
      });
      if (v3.auth) buf = signV3(buf, v3.auth, keys.auth);
      const { raw, msg } = await exchange(buf, 'm' + msgId);
      msg.raw = raw;
      const rpdu = openV3(msg);
      if (msg.flags & 0x01 && msg.usm.boots >= engine.boots) {
        // authenticated: resynchronise the engine clock
        engine.boots = msg.usm.boots; engine.time = msg.usm.time; engine.at = Date.now();
      }
      if (rpdu.type === PDU.REPORT) {
        const oid = rpdu.varbinds[0] && rpdu.varbinds[0].oid;
        const what = USM_REPORTS[oid] || 'report';
        if (what === 'notInTimeWindows' && attempt === 0) {
          engine.boots = msg.usm.boots; engine.time = msg.usm.time; engine.at = Date.now();
          continue;
        }
        if (what === 'unknownEngineIDs' && attempt === 0) { engine = null; await discoverEngine(); continue; }
        throw new SnmpError(what, `SNMPv3 report: ${what}`);
      }
      if (rpdu.type !== PDU.RESPONSE) throw new SnmpError('unexpected', 'unexpected PDU type in response');
      return checkPdu(rpdu, requestId);
    }
    throw new SnmpError('notInTimeWindows', 'SNMPv3 time synchronisation failed');
  }

  const request = (type, vbs, a, b) => (version === '3' ? requestV3(type, vbs, a, b) : requestCommunity(type, vbs, a, b));
  const asVbs = (oids) => (Array.isArray(oids) ? oids : [oids]).map((oid) => ({ oid: String(oid).replace(/^\./, '') }));

  async function getNextWalkStep(cur) {
    try { return await request(PDU.GETNEXT, asVbs([cur])); } catch (e) {
      if (version === '1' && e.code === 'noSuchName') return [{ oid: cur, type: 'EndOfMibView', value: null }];
      throw e;
    }
  }

  async function walk(root, { maxRows = 10000 } = {}) {
    const base = String(root).replace(/^\./, '');
    const out = [];
    let cur = base;
    for (;;) {
      const vbs = version === '1' ? await getNextWalkStep(cur) : await request(PDU.GETBULK, asVbs([cur]), 0, maxRep);
      if (!vbs.length) break;
      let done = false;
      for (const vb of vbs) {
        if (vb.type === 'EndOfMibView' || !oidStartsWith(vb.oid, base)) { done = true; break; }
        if (oidCompare(vb.oid, cur) <= 0) throw new SnmpError('loop', `agent returned a non-increasing OID after ${cur}`);
        out.push(vb);
        cur = vb.oid;
        if (out.length >= maxRows) { done = true; break; }
      }
      if (done) break;
    }
    return out;
  }

  // table(entryOid) → [{index:'1.2', cols:{<column number>: varbind}}] ordered by index
  async function table(entry, opts2) {
    const base = String(entry).replace(/^\./, '');
    const rows = new Map();
    for (const vb of await walk(base, opts2)) {
      const rest = vb.oid.slice(base.length + 1).split('.');
      const col = Number(rest.shift());
      const index = rest.join('.');
      if (!rows.has(index)) rows.set(index, { index, cols: {} });
      rows.get(index).cols[col] = vb;
    }
    return [...rows.values()];
  }

  return {
    host, port, version,
    get: (oids) => request(PDU.GET, asVbs(oids)),
    getNext: (oids) => request(PDU.GETNEXT, asVbs(oids)),
    getBulk: (oids, nonRepeaters = 0, maxRepetitions = maxRep) => {
      if (version === '1') return Promise.reject(new SnmpError('version', 'GETBULK needs SNMP v2c or v3'));
      return request(PDU.GETBULK, asVbs(oids), nonRepeaters, maxRepetitions);
    },
    walk, table,
    discoverEngine: () => (version === '3' ? discoverEngine() : Promise.reject(new SnmpError('version', 'engine discovery is SNMPv3 only'))),
    close() {
      closed = true;
      for (const p of pending.values()) p.done(new SnmpError('closed', 'session closed'));
      if (sock) { try { sock.close(); } catch { /* already closed */ } sock = null; }
    },
  };
}

module.exports = {
  TAG, PDU, ALLOWED_PDU, REQUEST_PDU, ERROR_STATUS, USM_REPORTS, AUTH, SnmpError,
  encodeValue, decodeValue, encodePdu, decodePdu, encodeCommunityMessage, decodeMessage,
  encodeV3Message, encodeScopedPdu, decodeScopedPdu, locateAuthParams, signV3, verifyV3,
  passwordToKey, localizeKey, aesEncrypt, aesDecrypt, authProto, privProto,
  encOidBody, decOidBody, oidCompare, oidStartsWith, readTLV, encIntBody, decIntBig,
  vbString, vbNumber, vbHex, isException, createSession,
};
