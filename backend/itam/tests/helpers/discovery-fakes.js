// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * TEST ONLY — in-process fakes for Asset Discovery. Everything listens on 127.0.0.1; all data is SYNTHETIC
 * (TEST-* names, 02:… locally administered MACs or documented vendor OUIs, RFC 1918 / RFC 5737 addresses).
 *   startFakeSnmpAgent({rows, communities, users, engineId}) → {port, seen, close}   (v1/v2c/v3 USM, adapted from sentra-print)
 *   deviceMib({…}) → rows                     a switch/firewall MIB incl. ENTITY serial, LLDP and CDP neighbours
 *   startHttpsFake(handler) → {url, port, caFile, requests, close}   HTTPS with a throw-away CA (cert for 127.0.0.1)
 *   startHttpFake(handler)  → {url, port, requests, close}           plain HTTP on loopback (SIEM, cloud fakes)
 *   fakeExec({alive}) / fakeConnect({open, closed}) — sweep fakes (record every argv for the no-shell assertions)
 */
const dgram = require('node:dgram');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const snmp = require('../../engine/discovery/snmp-client');
const { makeCA, makeServerCert } = require('./x509');

// ---------------- SNMP agent ----------------
function sortRows(rows) {
  const arcs = (o) => o.split('.').map(Number);
  for (const r of rows) r.arcs = arcs(r.oid);
  rows.sort((a, b) => { for (let i = 0; i < Math.min(a.arcs.length, b.arcs.length); i++) if (a.arcs[i] !== b.arcs[i]) return a.arcs[i] - b.arcs[i]; return a.arcs.length - b.arcs.length; });
  return rows;
}
const macBuf = (m) => Buffer.from(m.replace(/:/g, ''), 'hex');

function deviceMib(o) {
  const rows = [];
  const add = (oid, type, value) => rows.push({ oid, type, value });
  add('1.3.6.1.2.1.1.1.0', 'OctetString', o.descr || 'SYNTHETIC TEST DEVICE');
  add('1.3.6.1.2.1.1.2.0', 'OID', o.objectId || '1.3.6.1.4.1.99999.1');
  add('1.3.6.1.2.1.1.5.0', 'OctetString', o.name || 'TEST-DEV');
  add('1.3.6.1.2.1.1.6.0', 'OctetString', o.location || 'SYNTHETIC LAB');
  (o.macs || []).forEach((m, i) => add(`1.3.6.1.2.1.2.2.1.6.${i + 1}`, 'OctetString', macBuf(m)));
  Object.entries(o.ifNames || {}).forEach(([i, n]) => add(`1.3.6.1.2.1.31.1.1.1.1.${i}`, 'OctetString', n));
  (o.entity || []).forEach((e, i) => {
    add(`1.3.6.1.2.1.47.1.1.1.1.5.${i + 1}`, 'Integer', e.cls);
    add(`1.3.6.1.2.1.47.1.1.1.1.11.${i + 1}`, 'OctetString', e.serial || '');
    add(`1.3.6.1.2.1.47.1.1.1.1.13.${i + 1}`, 'OctetString', e.model || '');
  });
  for (const n of o.lldp || []) {
    const ix = `0.${n.localPort}.${n.remIndex || 1}`;
    add(`1.0.8802.1.1.2.1.4.1.1.4.${ix}`, 'Integer', 4);
    add(`1.0.8802.1.1.2.1.4.1.1.5.${ix}`, 'OctetString', macBuf(n.chassisMac));
    add(`1.0.8802.1.1.2.1.4.1.1.7.${ix}`, 'OctetString', n.portId || 'gi1');
    add(`1.0.8802.1.1.2.1.4.1.1.8.${ix}`, 'OctetString', n.portDesc || '');
    add(`1.0.8802.1.1.2.1.4.1.1.9.${ix}`, 'OctetString', n.sysName || '');
    add(`1.0.8802.1.1.2.1.3.7.1.3.${n.localPort}`, 'OctetString', n.localPortName || `port${n.localPort}`);
    if (n.manIp) add(`1.0.8802.1.1.2.1.4.2.1.3.${ix}.1.4.${n.manIp}`, 'Integer', 2);
  }
  for (const c of o.cdp || []) {
    const ix = `${c.ifIndex}.${c.devIndex || 1}`;
    add(`1.3.6.1.4.1.9.9.23.1.2.1.1.3.${ix}`, 'Integer', 1);
    add(`1.3.6.1.4.1.9.9.23.1.2.1.1.4.${ix}`, 'OctetString', Buffer.from(c.ip.split('.').map(Number)));
    add(`1.3.6.1.4.1.9.9.23.1.2.1.1.6.${ix}`, 'OctetString', c.deviceId);
    add(`1.3.6.1.4.1.9.9.23.1.2.1.1.7.${ix}`, 'OctetString', c.port || 'GigabitEthernet0/1');
    add(`1.3.6.1.4.1.9.9.23.1.2.1.1.8.${ix}`, 'OctetString', c.platform || 'SYNTHETIC CDP PLATFORM');
  }
  (o.arp || []).forEach((r) => add(`1.3.6.1.2.1.4.22.1.2.${r.ifIndex || 1}.${r.ip}`, 'OctetString', macBuf(r.mac)));   // IP-MIB ARP table
  return sortRows(rows);
}

function startFakeSnmpAgent(o = {}) {
  let mib = o.rows || deviceMib({});
  const communities = o.communities || ['public'];
  const engineId = o.engineId || Buffer.from('80001f8880' + crypto.randomBytes(8).toString('hex'), 'hex');
  const users = new Map((o.users || []).map((u) => {
    const a = snmp.authProto(u.auth); const keys = {};
    if (a) { keys.auth = snmp.localizeKey(snmp.passwordToKey(u.authPassword, a.hash), engineId, a.hash); if (u.priv) keys.priv = snmp.localizeKey(snmp.passwordToKey(u.privPassword, a.hash), engineId, a.hash); }
    return [u.user, { a, priv: !!u.priv, keys }];
  }));
  const boots = 3; const t0 = Date.now() - 1000 * 1000;
  const engineTime = () => Math.floor((Date.now() - t0) / 1000);
  const seen = [], reqs = []; let salt = 1n;   // reqs: every request decoded (PDU type, OIDs, GETBULK size) - parity tests compare them
  const sock = dgram.createSocket('udp4');
  const cmp = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
  const getExact = (oid) => { const r = mib.find((x) => x.oid === oid); return r ? { oid, type: r.type, value: r.value } : { oid, type: 'NoSuchObject', value: null }; };
  const getNext = (oid) => { const a = oid.split('.').map(Number); const r = mib.find((x) => cmp(x.arcs, a) > 0); return r ? { oid: r.oid, type: r.type, value: r.value } : { oid, type: 'EndOfMibView', value: null }; };
  function answer(pdu) {
    reqs.push([pdu.type, pdu.varbinds.map((vb) => vb.oid).join(','), pdu.type === snmp.PDU.GETBULK ? pdu.errorIndex : 0]);
    let vbs = [];
    if (pdu.type === snmp.PDU.GET) vbs = pdu.varbinds.map((vb) => getExact(vb.oid));
    else if (pdu.type === snmp.PDU.GETNEXT) vbs = pdu.varbinds.map((vb) => getNext(vb.oid));
    else if (pdu.type === snmp.PDU.GETBULK) {
      const maxRep = Math.min(pdu.errorIndex, 50); let cur = pdu.varbinds.map((vb) => vb.oid);
      for (let r = 0; r < maxRep && cur.length; r++) { const step = cur.map(getNext); vbs.push(...step); if (step.every((x) => x.type === 'EndOfMibView')) break; cur = step.map((x) => x.oid); }
    } else return null;
    return snmp.encodePdu(snmp.PDU.RESPONSE, { requestId: pdu.requestId, varbinds: vbs });
  }
  function report(msg, oid) {
    const pdu = snmp.encodePdu(snmp.PDU.REPORT, { requestId: 0, varbinds: [{ oid, type: 'Counter32', value: 1 }] });
    return snmp.encodeV3Message({ msgId: msg.msgId, flags: 0, engineId, boots, time: engineTime(), user: msg.usm.user, scopedPdu: snmp.encodeScopedPdu(engineId, '', pdu) });
  }
  function handleV3(raw, msg) {
    if (!msg.usm.engineId.length) return report(msg, '1.3.6.1.6.3.15.1.1.4.0');
    const u = users.get(msg.usm.user);
    if (!u) return report(msg, '1.3.6.1.6.3.15.1.1.3.0');
    if (u.a && !snmp.verifyV3(raw, u.a, u.keys.auth)) return report(msg, '1.3.6.1.6.3.15.1.1.5.0');
    let sb = msg.scopedPdu;
    if (u.priv) { try { sb = snmp.aesDecrypt(u.keys.priv, msg.usm.boots, msg.usm.time, msg.usm.privParams, msg.encryptedPdu); } catch { return null; } }
    let sc; try { sc = snmp.decodeScopedPdu(sb); } catch { return report(msg, '1.3.6.1.6.3.15.1.1.6.0'); }
    seen.push(sc.pdu.type);
    const pdu = answer(sc.pdu); if (!pdu) return null;
    const out = snmp.encodeScopedPdu(engineId, '', pdu); const time = engineTime();
    let privParams = Buffer.alloc(0); let enc = null;
    if (u.priv) { salt++; privParams = Buffer.from(salt.toString(16).padStart(16, '0'), 'hex'); enc = snmp.aesEncrypt(u.keys.priv, boots, time, privParams, out); }
    let buf = snmp.encodeV3Message({ msgId: msg.msgId, flags: msg.flags & 3, engineId, boots, time, user: msg.usm.user, authParams: u.a ? Buffer.alloc(u.a.macLen) : Buffer.alloc(0), privParams, scopedPdu: enc ? null : out, encryptedPdu: enc });
    if (u.a) buf = snmp.signV3(buf, u.a, u.keys.auth);
    return buf;
  }
  sock.on('message', (raw, rinfo) => {
    let reply = null;
    try {
      const msg = snmp.decodeMessage(raw);
      if (msg.version === 3) reply = handleV3(raw, msg);
      else { seen.push(msg.pdu.type); if (!communities.includes(msg.community)) return; reply = answer(msg.pdu); if (reply) reply = snmp.encodeCommunityMessage(msg.version, msg.community, reply); }
    } catch { seen.push(-1); return; }
    if (reply) sock.send(reply, rinfo.port, rinfo.address);
  });
  return new Promise((resolve) => sock.bind(0, '127.0.0.1', () => resolve({ port: sock.address().port, seen, reqs, engineId, set(rows) { mib = rows; }, close: () => new Promise((r) => sock.close(() => r())) })));
}

// ---------------- HTTP(S) fakes ----------------
function collect(req) { return new Promise((resolve) => { const c = []; req.on('data', (x) => c.push(x)); req.on('end', () => resolve(Buffer.concat(c).toString('utf8'))); }); }
function serve(server, requests, handler) {
  server.on('request', async (req, res) => {
    const body = await collect(req);
    const rec = { method: req.method, url: req.url, headers: req.headers, body };
    requests.push(rec);
    let out;
    try { out = await handler(rec); } catch (e) { out = { status: 500, body: { error: e.message } }; }
    out = out || { status: 404, body: { error: 'not found' } };
    const isText = typeof out.body === 'string';
    const data = isText ? out.body : JSON.stringify(out.body === undefined ? {} : out.body);
    res.writeHead(out.status || 200, Object.assign({ 'Content-Type': isText ? (out.type || 'text/xml') : 'application/json' }, out.headers || {}));
    res.end(data);
  });
}
let shared = null;
function testPki() {
  if (shared) return shared;
  const ca = makeCA('Synthetic Discovery Test CA');
  const leaf = makeServerCert(ca, { cn: '127.0.0.1', dns: ['localhost'], ip: ['127.0.0.1'] });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-itam-pki-'));
  const caFile = path.join(dir, 'ca.pem');
  fs.writeFileSync(caFile, ca.cert);
  shared = { ca, leaf, caFile };
  return shared;
}
function startHttpsFake(handler) {
  const pki = testPki();
  const requests = [];
  const server = https.createServer({ key: pki.leaf.key, cert: pki.leaf.cert });
  serve(server, requests, handler);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, url: `https://127.0.0.1:${server.address().port}`, caFile: pki.caFile, caPem: pki.ca.cert, requests, close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }) })));
}
function startHttpFake(handler) {
  const requests = [];
  const server = http.createServer();
  serve(server, requests, handler);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, url: `http://127.0.0.1:${server.address().port}`, requests, close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }) })));
}

// ---------------- sweep fakes ----------------
function fakeExec({ alive = [] } = {}) {
  const calls = [];
  const fn = async (bin, args, opts) => {
    calls.push({ bin, args: args.slice(), opts });
    if (bin.endsWith('fping')) { const ips = args.filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a)); const up = ips.filter((ip) => alive.includes(ip)); return { code: up.length === ips.length ? 0 : 1, stdout: up.join('\n') + '\n' }; }
    const ip = args[args.length - 1];
    return { code: alive.includes(ip) ? 0 : 1, stdout: '' };
  };
  fn.calls = calls;
  return fn;
}
function fakeConnect({ open = {}, closed = [] } = {}) {
  const calls = [];
  const fn = async (ip, port) => { calls.push([ip, port]); if ((open[ip] || []).includes(port)) return 'open'; if (closed.includes(ip)) return 'closed'; return 'timeout'; };
  fn.calls = calls;
  return fn;
}

module.exports = { startFakeSnmpAgent, deviceMib, sortRows, startHttpsFake, startHttpFake, fakeExec, fakeConnect, testPki };
