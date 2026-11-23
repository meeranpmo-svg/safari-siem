// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Flow collector (engine/collect/flow-collector.js) with SYNTHETIC datagrams: the exporter allow-list (others counted and
// dropped), sampling (the administrator's rate first, then the announced one), one-minute rollups with the client port
// folded away, interface / per-address / raw rows, the overflow row when max_keys is reached, a malformed datagram counted
// and logged once a minute (log.every) without stopping the collector, a failed ClickHouse insert dropped and counted,
// observers and the minute summary, and a real UDP listener on 127.0.0.1 started, fed and stopped.
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const D = require('./helpers/flow-packets');
const { createFlowCollector } = require('../engine/collect/flow-collector');
const { createAppMapper } = require('../engine/collect/flow-collector-apps');

const T0 = Date.UTC(2026, 10, 13, 8, 0, 5);
function harness(over = {}) {
  let t = T0; const inserts = [], logs = [], seen = [], minutes = [];
  const settings = Object.assign({ enabled: false, host: '127.0.0.1', ports: {}, raw_per_minute: 2, template_ttl_s: 1800, max_keys: 1000,
    exporters: [{ ip: '192.0.2.1', name: 'rtr-hq' }, { ip: '192.0.2.2', name: 'sw-core', sampling: 10 }] }, over.settings || {});
  const ch = { insertRows: async (table, rows) => { if (over.failInsert) throw new Error('ClickHouse: Code: 241 memory limit'); inserts.push({ table, rows }); } };
  const log = { info() {}, warn() {}, error() {}, debug() {}, every: (k, ms, lvl, msg, f) => logs.push({ k, lvl, msg, f }) };
  const C = createFlowCollector({ ch, log, now: () => t, getSettings: () => settings, mapper: () => createAppMapper(over.apps || []), billable: (ip) => ip === '203.0.113.50',
    observers: [(f) => { seen.push(f); if (over.observerThrows) throw new Error('boom'); }], onMinute: (s) => minutes.push(s), config: { clickhouse: { database: 'siem' } } });
  return { C, inserts, logs, seen, minutes, settings, at: (ms) => { t = ms; }, rows: (tb) => inserts.filter((x) => x.table === 'siem.' + tb).flatMap((x) => x.rows) };
}

test('allow-list: a sender that is not configured is counted and dropped, never decoded', () => {
  const h = harness();
  const r = h.C.handle(D.v5([{ src: '10.0.0.1', dst: '10.0.0.2', bytes: 100, packets: 1 }]), '::ffff:198.51.100.66');
  assert.equal(r.accepted, false); assert.match(r.reason, /allow-list/);
  const st = h.C.stats();
  assert.equal(st.counters.rejected_unknown, 1); assert.equal(st.counters.records, 0); assert.equal(st.unknown[0].ip, '198.51.100.66', 'IPv4-mapped sender normalised');
  assert.ok(h.logs.some((l) => l.k === 'netflow-unknown-198.51.100.66' && l.lvl === 'warn'), 'logged through log.every (rate-limited per sender)');
  assert.equal(h.seen.length, 0);
});

test('rollups: sampling applied, client port folded away, interfaces, private / group addresses per hour, raw sample capped', async () => {
  const h = harness();
  const flows = [{ src: '10.1.1.5', dst: '198.51.100.7', sport: 51000, dport: 443, proto: 6, bytes: 1000, packets: 2, if_in: 3, if_out: 9 },
    { src: '10.1.1.5', dst: '198.51.100.7', sport: 51001, dport: 443, proto: 6, bytes: 500, packets: 1, if_in: 3, if_out: 9 },
    { src: '198.51.100.7', dst: '10.1.1.5', sport: 443, dport: 51000, proto: 6, bytes: 9000, packets: 6, if_in: 9, if_out: 3 }];
  assert.equal(h.C.handle(D.v5(flows, { sampling: 0x4000 | 100 }), '192.0.2.1').records, 3);
  h.C.handle(D.v5([{ src: '10.1.1.9', dst: '203.0.113.50', sport: 40000, dport: 8443, proto: 6, bytes: 10, packets: 1, if_in: 1, if_out: 2 }], { sampling: 0x4000 | 100 }), '192.0.2.2');
  h.at(T0 + 60000);
  const f = await h.C.flush();
  assert.equal(f.minutes, 1);
  const m = h.rows('flow_minute');
  const out = m.find((r) => r.src_ip === '10.1.1.5' && r.dst_port === 443);
  assert.deepEqual([out.src_port, out.flows, out.bytes, out.packets, out.app, out.minute], [0, 2, 150000, 300, 'HTTPS', Math.floor(T0 / 60000) * 60], 'two client ports, one row; bytes x100 (announced sampling)');
  const back = m.find((r) => r.src_ip === '198.51.100.7');
  assert.deepEqual([back.src_port, back.dst_port], [443, 0], 'the reply keeps the service port, not the client port');
  const sw = m.find((r) => r.exporter === '192.0.2.2');
  assert.equal(sw.bytes, 100, 'the administrator\'s sampling (10) wins over the announced 100');
  const ifs = h.rows('flow_if_minute');
  assert.equal(ifs.find((r) => r.exporter === '192.0.2.1' && r.if_index === 3 && r.dir === 'in').bytes, 150000);
  assert.equal(ifs.find((r) => r.exporter === '192.0.2.1' && r.if_index === 3 && r.dir === 'out').bytes, 900000);
  const ips = h.rows('flow_ip_hour');
  assert.ok(ips.every((r) => r.ip !== '198.51.100.7'), 'public addresses are not kept per address');
  assert.ok(ips.some((r) => r.ip === '203.0.113.50' && r.dir === 'dst'), 'an address inside an IP group is kept (billing)');
  assert.equal(ips[0].hour, Math.floor(T0 / 3600000) * 3600);
  assert.equal(h.rows('flow_raw').length, 3, 'raw sample: at most raw_per_minute (2) per exporter');
  assert.equal(h.C.stats().counters.raw_dropped, 1);
  assert.equal(h.minutes.length, 1); assert.equal(h.minutes[0].apps[0].app, 'HTTPS'); assert.ok(h.minutes[0].ips.length > 0);
  assert.equal(h.seen.length, 4); assert.equal(h.seen[0].bytes, 100000, 'observers see scaled bytes');
  assert.equal(h.C.live().length, 1); assert.equal(h.C.live()[0].flows, 4);
  const ex = h.C.stats().exporters.find((e) => e.ip === '192.0.2.1');
  assert.deepEqual([ex.records, ex.sampling, ex.versions[5]], [3, 100, 1]);
});

test('bounded: overflow row past max_keys keeps the bytes; at most 3 open minutes', async () => {
  const h = harness({ settings: { max_keys: 5 } });
  for (let i = 0; i < 4; i++) h.C.handle(D.v5(Array.from({ length: 3 }, (_, j) => ({ src: '10.0.0.' + (i * 3 + j + 1), dst: '10.9.0.1', dport: 80, sport: 40000, proto: 6, bytes: 10, packets: 1 }))), '192.0.2.1');
  h.at(T0 + 60000); await h.C.flush();
  const m = h.rows('flow_minute');
  assert.equal(m.length, 6, '5 rows + 1 overflow row'); assert.equal(m.find((r) => r.app === '(overflow)').flows, 7);
  assert.equal(m.reduce((a, r) => a + r.bytes, 0), 120, 'no byte lost');
  assert.equal(h.C.stats().counters.overflow_records, 7);
  const g = harness();
  for (let k = 0; k < 6; k++) { g.at(T0 + k * 60000); g.C.handle(D.v5([{ src: '10.0.0.1', dst: '10.0.0.2', bytes: 1, packets: 1 }]), '192.0.2.1'); }
  assert.ok(g.C.stats().counters.minutes_forced >= 3, 'older minutes closed when the flush is late');
});

test('malformed datagram: counted per exporter, logged once a minute, collector keeps going; insert failure dropped and counted', async () => {
  const h = harness({ failInsert: true, observerThrows: true });
  const r = h.C.handle(Buffer.from([0, 9, 0, 1, 0, 0]), '192.0.2.1');
  assert.equal(r.accepted, false);
  const st = h.C.stats(); assert.equal(st.counters.malformed, 1); assert.match(st.exporters.find((e) => e.ip === '192.0.2.1').last_error, /truncated/);
  assert.ok(h.logs.some((l) => l.k === 'netflow-decode-192.0.2.1'));
  assert.equal(h.C.handle(D.v5([{ src: '10.0.0.1', dst: '10.0.0.2', bytes: 5, packets: 1 }]), '192.0.2.1').accepted, true, 'the next datagram is decoded');
  assert.equal(h.C.stats().counters.observer_errors, 1, 'a failing observer is counted, the flow still counts');
  h.at(T0 + 60000);
  await h.C.flush();   // must not throw
  const c = h.C.stats().counters;
  assert.ok(c.insert_errors >= 1 && c.rows_dropped >= 1); assert.ok(h.logs.some((l) => l.k === 'netflow-insert-flow_minute' && l.lvl === 'error'));
  assert.ok(!JSON.stringify(h.logs).match(/password|token|secret/i));
});

test('UDP listener: binds, decodes what an allowed exporter sends, stop() flushes the open minute', async () => {
  const probe = dgram.createSocket('udp4'); await new Promise((r) => probe.bind(0, '127.0.0.1', r)); const port = probe.address().port; await new Promise((r) => probe.close(r));
  let t = Date.now(); const inserts = [];
  const C = createFlowCollector({ ch: { insertRows: async (tb, rows) => inserts.push({ tb, rows }) }, now: () => t, mapper: () => createAppMapper([]),
    getSettings: () => ({ enabled: true, host: '127.0.0.1', ports: { netflow: port }, raw_per_minute: 0, template_ttl_s: 60, max_keys: 1000, exporters: [{ ip: '127.0.0.1', name: 'lo' }] }) });
  await C.start();
  assert.equal(C.stats().listeners.netflow.port, port); assert.equal(C.running, true);
  const s = dgram.createSocket('udp4');
  await new Promise((r) => s.send(D.v5([{ src: '10.0.0.1', dst: '10.0.0.2', dport: 53, sport: 5353, proto: 17, bytes: 70, packets: 1 }]), port, '127.0.0.1', r));
  await new Promise((r) => s.send(Buffer.from('garbage'), port, '127.0.0.1', r));
  s.close();
  for (let i = 0; i < 50 && C.stats().counters.datagrams < 2; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(C.stats().counters.accepted, 1); assert.equal(C.stats().counters.malformed, 1);
  await C.stop();
  assert.equal(C.running, false); assert.deepEqual(C.stats().listeners, {});
  assert.equal(inserts.find((x) => x.tb === 'siem.flow_minute').rows[0].app, 'DNS', 'the open minute was flushed at stop');
  const off = createFlowCollector({ getSettings: () => ({ enabled: false, ports: { netflow: port }, exporters: [], template_ttl_s: 60, max_keys: 10, raw_per_minute: 0 }) });
  await off.start(); assert.equal(off.running, false, 'disabled: no listener'); await off.stop();
});
