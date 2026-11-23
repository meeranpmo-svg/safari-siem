// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Builders for SYNTHETIC NetFlow v5 / v9, IPFIX and sFlow v5 datagrams (tests only - not a flow generator for the network).
const net = require('node:net');

const u8 = (v) => Buffer.from([v & 255]);
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
const ip = (s) => Buffer.from(s.split('.').map(Number));
function ip6(s) {
  if (!net.isIPv6(s)) throw new Error('bad v6 ' + s);
  const [h, t] = s.split('::'); const a = h ? h.split(':') : [], b = t !== undefined && t ? t.split(':') : [];
  const parts = t === undefined ? a : a.concat(Array(8 - a.length - b.length).fill('0'), b);
  return Buffer.concat(parts.map((p) => u16(parseInt(p, 16))));
}
const pad4 = (b) => (b.length % 4 ? Buffer.concat([b, Buffer.alloc(4 - (b.length % 4))]) : b);
const varlen = (b) => Buffer.concat([b.length < 255 ? u8(b.length) : Buffer.concat([u8(255), u16(b.length)]), b]);

function v5(records, o = {}) {
  const h = Buffer.alloc(24); h.writeUInt16BE(5, 0); h.writeUInt16BE(records.length, 2); h.writeUInt32BE(1000, 4); h.writeUInt32BE(1700000000, 8); h.writeUInt16BE(o.sampling || 0, 22);
  return Buffer.concat([h].concat(records.map((r) => {
    const b = Buffer.alloc(48); ip(r.src).copy(b, 0); ip(r.dst).copy(b, 4); b.writeUInt16BE(r.if_in || 0, 12); b.writeUInt16BE(r.if_out || 0, 14);
    b.writeUInt32BE(r.packets || 0, 16); b.writeUInt32BE(r.bytes || 0, 20); b.writeUInt16BE(r.sport || 0, 32); b.writeUInt16BE(r.dport || 0, 34);
    b[37] = r.flags || 0; b[38] = r.proto || 0; b[39] = r.tos || 0; return b;
  })));
}
const set = (id, body) => { const b = pad4(body); return Buffer.concat([u16(id), u16(b.length + 4), b]); };
const v9Template = (id, fields) => set(0, Buffer.concat([u16(id), u16(fields.length)].concat(fields.map(([f, l]) => Buffer.concat([u16(f), u16(l)])))));
const v9OptionsTemplate = (id, scope, opts) => set(1, Buffer.concat([u16(id), u16(scope.length * 4), u16(opts.length * 4)].concat(scope.concat(opts).map(([f, l]) => Buffer.concat([u16(f), u16(l)])))));
const v9Data = (id, recs) => set(id, Buffer.concat(recs.map((r) => Buffer.concat(r))));
function v9(sourceId, sets) { return Buffer.concat([u16(9), u16(sets.length), u32(1000), u32(1700000000), u32(1), u32(sourceId)].concat(sets)); }
function ipfixTemplate(id, fields) {
  return set(2, Buffer.concat([u16(id), u16(fields.length)].concat(fields.map((f) => (Array.isArray(f) ? Buffer.concat([u16(f[0]), u16(f[1])]) : Buffer.concat([u16(f.id | 0x8000), u16(f.len), u32(f.ent)]))))));
}
const ipfixData = (id, recs) => set(id, Buffer.concat(recs.map((r) => Buffer.concat(r))));
function ipfix(domain, sets) { const body = Buffer.concat(sets); return Buffer.concat([u16(10), u16(16 + body.length), u32(1700000000), u32(1), u32(domain), body]); }

function l4(o) { if (o.proto === 6) { const t = Buffer.alloc(20); t.writeUInt16BE(o.sport, 0); t.writeUInt16BE(o.dport, 2); t[12] = 0x50; t[13] = o.flags || 0; return t; } const u = Buffer.alloc(8); u.writeUInt16BE(o.sport, 0); u.writeUInt16BE(o.dport, 2); return u; }
function ethIPv4(o) {
  const p = l4(o), h = Buffer.alloc(20); h[0] = 0x45; h[1] = o.tos || 0; h.writeUInt16BE(20 + p.length, 2); h[8] = 64; h[9] = o.proto; ip(o.src).copy(h, 12); ip(o.dst).copy(h, 16);
  const eth = Buffer.alloc(12, 0x02); const tag = o.vlan ? Buffer.concat([u16(0x8100), u16(o.vlan)]) : Buffer.alloc(0);
  return Buffer.concat([eth, tag, u16(0x0800), h, p]);
}
function ethIPv6(o) {
  const p = l4(o), h = Buffer.alloc(40); h.writeUInt32BE(0x60000000, 0); h.writeUInt16BE(p.length, 4); h[6] = o.proto; h[7] = 64; ip6(o.src).copy(h, 8); ip6(o.dst).copy(h, 24);
  return Buffer.concat([Buffer.alloc(12, 0x02), u16(0x86dd), h, p]);
}
const rec = (fmt, body) => { const b = pad4(body); return Buffer.concat([u32(fmt), u32(b.length), b]); };
const sflowRawHeader = (proto, frame, hdr) => rec(1, Buffer.concat([u32(proto), u32(frame), u32(4), u32(hdr.length), pad4(hdr)]));
const sflowIPv4 = (o) => rec(3, Buffer.concat([u32(o.len), u32(o.proto), ip(o.src), ip(o.dst), u32(o.sport), u32(o.dport), u32(o.flags || 0), u32(o.tos || 0)]));
function sflowFlow(o) {
  const head = o.expanded ? [u32(1), u32(0), u32(3), u32(o.rate), u32(1000), u32(0), u32(0), u32(o.ifIn || 0), u32(0), u32(o.ifOut || 0)]
    : [u32(1), u32(3), u32(o.rate), u32(1000), u32(0), u32(o.ifIn || 0), u32(o.ifOut || 0)];
  return rec(o.expanded ? 3 : 1, Buffer.concat(head.concat([u32(o.records.length)], o.records)));
}
const sflowCounters = () => rec(2, Buffer.concat([u32(1), u32(3), u32(1), rec(1, Buffer.alloc(88))]));
function sflow(agent, samples) { return Buffer.concat([u32(5), u32(1), ip(agent), u32(0), u32(1), u32(1000), u32(samples.length)].concat(samples)); }

module.exports = { u8, u16, u32, u64, ip, ip6, varlen, v5, v9, v9Template, v9OptionsTemplate, v9Data, ipfix, ipfixTemplate, ipfixData, ethIPv4, ethIPv6, sflow, sflowFlow, sflowRawHeader, sflowIPv4, sflowCounters };
