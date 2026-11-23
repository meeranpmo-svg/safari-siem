// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Flow export decoders (engine/collect/flow-collector-decode.js) on SYNTHETIC datagrams built here (documentation address
// ranges only): NetFlow v5, v9 (templates per exporter + source id, expiry, options-data sampling), IPFIX (variable-length
// and enterprise fields, withdrawal, message length), sFlow v5 (raw Ethernet / VLAN / IPv6 headers, counter samples). Then
// the untrusted-input cases: every truncation and thousands of bit flips and random datagrams either decode to valid
// records or throw a FlowDecodeError - never another error, never an impossible record.
const test = require('node:test');
const assert = require('node:assert/strict');
const D = require('./helpers/flow-packets');
const { decode, createTemplateCache, FlowDecodeError } = require('../engine/collect/flow-collector-decode');

const EXP = '192.0.2.1';
const ctx = (now) => ({ exporter: EXP, cache: createTemplateCache({ ttlMs: 60000, maxPerExporter: 4, now: now || Date.now }) });

test('NetFlow v5: records, sampling interval from the header, malformed headers refused', () => {
  const b = D.v5([{ src: '10.1.1.5', dst: '198.51.100.7', sport: 51000, dport: 443, proto: 6, bytes: 1500, packets: 3, if_in: 2, if_out: 7, tos: 0xb8, flags: 0x18 }, { src: '10.1.1.6', dst: '203.0.113.9', sport: 53, dport: 40000, proto: 17, bytes: 90, packets: 1 }], { sampling: 0x4000 | 100 });
  const r = decode(b, ctx());
  assert.equal(r.version, 5); assert.equal(r.sampling, 100); assert.equal(r.records.length, 2);
  assert.deepEqual(r.records[0], { src: '10.1.1.5', dst: '198.51.100.7', if_in: 2, if_out: 7, packets: 3, bytes: 1500, sport: 51000, dport: 443, tcp_flags: 0x18, proto: 6, tos: 0xb8, sampling: 100 });
  const big = Buffer.from(b); big.writeUInt16BE(31, 2);
  assert.throws(() => decode(big, ctx()), /record count 31/);
  assert.throws(() => decode(b.subarray(0, 24 + 48), ctx()), /2 records announced, 1 present/);
  assert.throws(() => decode(b.subarray(0, 10), ctx()), FlowDecodeError);
  assert.throws(() => decode(Buffer.from([0, 7, 0, 0]), ctx()), /unknown export version 7/);
});

test('NetFlow v9: template then data, data before its template dropped, expiry, options sampling, per-exporter cap', () => {
  let t = 1000; const c = ctx(() => t);
  const tpl = D.v9Template(256, [[8, 4], [12, 4], [7, 2], [11, 2], [4, 1], [1, 4], [2, 4], [10, 2], [14, 2], [5, 1], [95, 4]]);
  const rec = D.v9Data(256, [[D.ip('10.0.0.5'), D.ip('198.51.100.20'), D.u16(50123), D.u16(22), D.u8(6), D.u32(4000), D.u32(10), D.u16(3), D.u16(4), D.u8(0), Buffer.from([13, 0, 0, 7])]]);
  let r = decode(D.v9(7, [rec]), c);
  assert.equal(r.no_template, 1, 'data before its template is counted and dropped'); assert.equal(r.records.length, 0);
  r = decode(D.v9(7, [tpl, rec]), c);
  assert.equal(r.templates, 1); assert.equal(r.records.length, 1);
  assert.deepEqual(r.records[0], { src: '10.0.0.5', dst: '198.51.100.20', bytes: 4000, packets: 10, proto: 6, tos: 0, tcp_flags: 0, sport: 50123, dport: 22, if_in: 3, if_out: 4, app_id: '13:7' });
  assert.equal(decode(D.v9(8, [rec]), c).no_template, 1, 'templates are per source id');
  // options template: scope = system (1, 4), option = SAMPLING_INTERVAL (34, 4); then options data → sampling for the domain
  const opt = D.v9OptionsTemplate(300, [[1, 4]], [[34, 4], [95, 4], [96, 16]]);
  const optData = D.v9Data(300, [[D.u32(0), D.u32(512), Buffer.from([13, 0, 0, 7]), Buffer.from('ms-office-365\0\0\0')]]);
  r = decode(D.v9(7, [opt, optData, rec]), c);
  assert.equal(r.records[0].sampling, 512, 'the announced sampling rate applies to later records'); assert.equal(r.records[0].app_name, 'ms-office-365', 'NBAR id resolved by the exporter\'s own options data');
  t += 61000;
  assert.equal(decode(D.v9(7, [rec]), c).no_template, 1, 'template expired after its TTL');
  // cap: 4 templates per exporter, the fifth refused
  r = decode(D.v9(9, [D.v9Template(256, [[8, 4]]), D.v9Template(257, [[8, 4]]), D.v9Template(258, [[8, 4]]), D.v9Template(259, [[8, 4]]), D.v9Template(260, [[8, 4]])]), c);
  assert.ok(r.templates_refused >= 1, 'templates beyond the per-exporter cap are refused');
  assert.throws(() => decode(D.v9(7, [D.v9Template(12, [[8, 4]])]), c), /template id 12 below 256/);
  assert.throws(() => decode(D.v9(7, [D.v9Template(400, [[8, 0]])]), c), /length 0/);
  assert.throws(() => decode(D.v9(7, [D.v9Template(401, Array.from({ length: 200 }, () => [8, 4]))]), c), /fields/);
  const wide = D.v9Template(402, [[8, 4], [12, 4], [7, 4]]);
  r = decode(D.v9(7, [wide, D.v9Data(402, [[D.ip('10.0.0.1'), D.ip('10.0.0.2'), D.u32(70000)]])]), ctx());
  assert.equal(r.records.length, 0); assert.equal(r.invalid, 1, 'a port above 65535 from a wide field is dropped');
});

test('IPFIX: variable-length + enterprise fields skipped safely, IPv6, DSCP, withdrawal, message length checked', () => {
  const c = ctx();
  const tpl = D.ipfixTemplate(256, [[27, 16], [28, 16], [7, 2], [11, 2], [4, 1], [1, 8], [2, 8], [195, 1], { id: 100, len: 65535, ent: 9 }, [96, 65535], { id: 5, len: 4, ent: 29305 }]);
  const data = D.ipfixData(256, [[D.ip6('2001:db8::5'), D.ip6('2001:db8:0:1::9'), D.u16(40000), D.u16(443), D.u8(17), D.u64(123456789012), D.u64(99), D.u8(46), D.varlen(Buffer.alloc(300, 0x41)), D.varlen(Buffer.from('quic-video')), D.u32(1)]]);
  const r = decode(D.ipfix(42, [tpl, data]), c);
  assert.equal(r.version, 10); assert.equal(r.records.length, 1);
  const x = r.records[0];
  assert.equal(x.src, '2001:db8::5'); assert.equal(x.dst, '2001:db8:0:1::9'); assert.equal(x.bytes, 123456789012); assert.equal(x.tos, 46 << 2); assert.equal(x.app_name, 'quic-video');
  assert.equal(decode(D.ipfix(43, [data]), c).no_template, 1, 'templates are per observation domain');
  assert.equal(decode(D.ipfix(42, [D.ipfixTemplate(256, [])]), c).withdrawn, 1);
  assert.equal(decode(D.ipfix(42, [data]), c).no_template, 1, 'withdrawn template no longer decodes');
  const m = D.ipfix(42, [tpl]); m.writeUInt16BE(m.length + 10, 2);
  assert.throws(() => decode(m, c), /message length/);
  const trunc = D.ipfix(42, [tpl, D.ipfixData(256, [[D.ip6('2001:db8::5'), D.ip6('2001:db8::6'), D.u16(1), D.u16(2), D.u8(6), D.u64(1), D.u64(1), D.u8(0), Buffer.from([255, 0xff, 0xff]), Buffer.alloc(8)]])]);
  const rt = decode(trunc, c);
  assert.equal(rt.records.length, 0); assert.equal(rt.truncated, 1, 'a variable length past the set is a truncated record, not a read past the buffer');
});

test('sFlow v5: raw Ethernet / VLAN / IPv6 headers to 5-tuples, sampled IPv4 record, counter samples ignored, rate kept', () => {
  const syn = D.ethIPv4({ src: '10.2.0.8', dst: '198.51.100.30', proto: 6, sport: 49152, dport: 3389, flags: 0x02, vlan: 20, tos: 0x28 });
  const udp6 = D.ethIPv6({ src: '2001:db8::a', dst: '2001:db8::b', proto: 17, sport: 5353, dport: 53 });
  const s = D.sflow('192.0.2.50', [D.sflowFlow({ rate: 2048, ifIn: 5, ifOut: 9, records: [D.sflowRawHeader(1, 1514, syn)] }), D.sflowCounters(),
    D.sflowFlow({ rate: 2048, expanded: true, ifIn: 6, ifOut: 7, records: [D.sflowRawHeader(1, 120, udp6), D.sflowIPv4({ src: '10.9.9.9', dst: '203.0.113.200', proto: 6, sport: 1234, dport: 80, len: 900 })] })]);
  const r = decode(s, ctx());
  assert.equal(r.version, 'sflow5'); assert.equal(r.agent, '192.0.2.50'); assert.equal(r.counters, 1); assert.equal(r.sampling, 2048);
  assert.equal(r.records.length, 3);
  assert.deepEqual([r.records[0].src, r.records[0].dst, r.records[0].sport, r.records[0].dport, r.records[0].proto, r.records[0].tcp_flags, r.records[0].tos, r.records[0].bytes, r.records[0].if_in, r.records[0].if_out, r.records[0].sampling],
    ['10.2.0.8', '198.51.100.30', 49152, 3389, 6, 2, 0x28, 1514, 5, 9, 2048], 'VLAN tag skipped, SYN flag read');
  assert.deepEqual([r.records[1].src, r.records[1].dport, r.records[1].proto, r.records[1].if_in], ['2001:db8::a', 53, 17, 6]);
  assert.deepEqual([r.records[2].src, r.records[2].dst, r.records[2].bytes, r.records[2].dport], ['10.9.9.9', '203.0.113.200', 900, 80]);
  const bad = Buffer.from(s); bad.writeUInt32BE(100000, 24);
  assert.throws(() => decode(bad, ctx()), /samples announced/);
});

// deterministic PRNG (mulberry32) so a failure can be replayed
function rng(seed) { return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function checkRecords(r) {
  for (const x of r.records) {
    assert.ok(typeof x.src === 'string' && x.src && typeof x.dst === 'string' && x.dst, 'addresses present');
    assert.ok(x.sport <= 65535 && x.dport <= 65535 && x.proto <= 255 && x.tos <= 255, 'ranges');
    assert.ok(Number.isFinite(x.bytes) && x.bytes >= 0 && x.bytes <= 1e13 && Number.isFinite(x.packets) && x.packets >= 0, 'counters');
  }
  assert.ok(r.records.length <= 4096);
}
function survive(buf, c) {
  try { checkRecords(decode(buf, c)); } catch (e) { if (!(e instanceof FlowDecodeError)) throw new Error('not a FlowDecodeError for ' + buf.toString('hex').slice(0, 120) + ': ' + (e && e.stack)); }
}

test('fuzz: truncations, bit flips and random datagrams never crash the decoder or produce impossible records', () => {
  const R = rng(20261113), c = ctx();
  const v9t = D.v9Template(256, [[8, 4], [12, 4], [7, 2], [11, 2], [4, 1], [1, 4], [2, 4]]);
  const v9d = D.v9Data(256, [[D.ip('10.0.0.1'), D.ip('10.0.0.2'), D.u16(1), D.u16(2), D.u8(6), D.u32(10), D.u32(1)]]);
  const ipt = D.ipfixTemplate(256, [[8, 4], [12, 4], [96, 65535], { id: 1, len: 65535, ent: 9 }]);
  const ipd = D.ipfixData(256, [[D.ip('10.0.0.1'), D.ip('10.0.0.2'), D.varlen(Buffer.from('x')), D.varlen(Buffer.alloc(3))]]);
  const seeds = [
    D.v5([{ src: '10.0.0.1', dst: '10.0.0.2', bytes: 1, packets: 1 }]), D.v9(1, [v9t, v9d]), D.ipfix(1, [ipt, ipd]),
    D.sflow('192.0.2.9', [D.sflowFlow({ rate: 10, records: [D.sflowRawHeader(1, 64, D.ethIPv4({ src: '10.0.0.1', dst: '10.0.0.2', proto: 6, sport: 1, dport: 2 }))] }), D.sflowCounters()]),
  ];
  for (const s of seeds) for (let n = 0; n <= s.length; n++) survive(s.subarray(0, n), c);   // every truncation
  for (let i = 0; i < 6000; i++) {   // bit flips and overwritten length fields
    const s = Buffer.from(seeds[i % seeds.length]), k = 1 + Math.floor(R() * 4);
    for (let j = 0; j < k; j++) { const p = Math.floor(R() * s.length); s[p] = R() < 0.5 ? s[p] ^ (1 << Math.floor(R() * 8)) : Math.floor(R() * 256); }
    survive(s, c);
  }
  for (let i = 0; i < 3000; i++) {   // random bodies behind each version header
    const len = 4 + Math.floor(R() * 1500), s = Buffer.alloc(len); for (let j = 0; j < len; j++) s[j] = Math.floor(R() * 256);
    const v = [5, 9, 10, 0][i % 4]; s.writeUInt16BE(v, 0); if (v === 0) s.writeUInt32BE(5, 0); if (v === 10 && len >= 4) s.writeUInt16BE(Math.min(len, 16 + Math.floor(R() * len)), 2);
    survive(s, c);
  }
  survive(Buffer.alloc(0), c); survive(Buffer.alloc(70000), c);
  assert.throws(() => decode('not a buffer', c), FlowDecodeError);
  assert.ok(c.cache.size() <= 4, 'the template cache stayed within its per-exporter cap');
});
