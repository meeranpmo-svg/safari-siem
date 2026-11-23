// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// WAN Optimization (engine/netops/wanopt.js + the read-only statistics in collectors.js edgeconnect) over a SYNTHETIC Orchestrator:
// statistics read by pattern from either response shape (packet counters and pre-FEC loss ignored, the keys used kept); reduction
// only where both LAN and WAN bytes are reported (a missing side is "not reported", never zero); tunnels against the thresholds;
// alarms by severity; the learned per-appliance baseline flags a drop; ranked actions; the thresholds (admin, validated, audited);
// a failed statistics call is noted and never fatal; nothing configured says what to do; viewer reads.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const C = require('../engine/netops/collectors');
const W = require('../engine/netops/wanopt');

test('statistics parsed by pattern from both shapes; packets and pre-FEC loss ignored; keys kept', () => {
  const a = C.ecStatRows({ '1.NE': { hostName: 'EC-RUH', LAN_TX_BYTES: 600, LAN_RX_BYTES: 400, WAN_TX_BYTES: 250, WAN_RX_BYTES: 50, LAN_TX_PKTS: 99 } });
  assert.deepEqual(a.rows[0], { name: 'EC-RUH', appliance: 'EC-RUH', lan_tx: 600, lan_rx: 400, wan_tx: 250, wan_rx: 50 });
  assert.ok(!a.keys.includes('LAN_TX_PKTS'));
  const b = C.ecStatRows([{ appName: 'SMB', lanTxBytes: '800', wanTxBytes: '200' }]); assert.equal(b.rows[0].name, 'SMB'); assert.equal(b.rows[0].lan_tx, 800);
  const t = C.ecTunnelRows({ '1.NE': { 'to-DC': { tunnelName: 'to-DC', LOSS_PCT: 1.5, PRE_FEC_LOSS_PCT: 9, LATENCY: 42, JITTER: 3 } } });
  assert.equal(t.rows[0].loss_pct, 1.5, 'post-FEC loss, not the pre-FEC figure'); assert.deepEqual(t.keys.sort(), ['JITTER', 'LATENCY', 'LOSS_PCT']);
  assert.equal(C.ecStatRows({ x: { foo: 'bar' } }).rows.length, 0, 'nothing invented from a row without byte counters');
});

const snap = (o) => Object.assign({ at: 1, ok: true, sources: ['api'], errors: [] }, o);
const orch = (wanopt, appliances, alarms) => [{ id: 'orc', name: 'ORCH-SYN', snapshot: snap({ sdwan: { appliances, alarms: alarms || [] }, wanopt }) }];
const APPL = [{ name: 'EC-RUH', site: 'Riyadh', up: true, state: 'normal' }, { name: 'EC-JED', site: 'Jeddah', up: true, state: 'normal' }, { name: 'EC-DMM', site: 'Dammam', up: false, state: 'unreachable' }];
const WO = { at: 1, window_s: 3600, errors: ['applications: HTTP 403'],
  appliances: [{ name: 'EC-RUH', lan_tx: 6e9, lan_rx: 4e9, wan_tx: 2.5e9, wan_rx: 0.5e9 }, { name: 'EC-JED', lan_tx: 2e9, lan_rx: null, wan_tx: null, wan_rx: null }],
  applications: [], tunnels: [{ name: 'RUH-JED', appliance: 'EC-RUH', loss_pct: 12, latency_ms: 40, jitter_ms: 2 }, { name: 'RUH-DMM', appliance: 'EC-RUH', loss_pct: 0.1, latency_ms: 180, jitter_ms: 5 }, { name: 'RUH-DR', appliance: 'EC-RUH', loss_pct: 0, latency_ms: 20 }],
  keys: { appliances: ['LAN_TX_BYTES', 'WAN_TX_BYTES'] } };

test('analysis: reduction only where both sides are reported, tunnels against thresholds, alarms, learning, actions', () => {
  const v = W.analyse({ orchestrators: orch(WO, APPL, [{ severity: 'critical', appliance: 'EC-DMM', text: 'Appliance unreachable' }, { severity: 'MINOR', appliance: 'EC-RUH', text: 'x' }]) });
  const A = Object.fromEntries(v.appliances.map((a) => [a.name, a]));
  assert.equal(A['EC-RUH'].reduction, 70); assert.equal(A['EC-RUH'].saved_bytes, 7e9);
  assert.equal(A['EC-JED'].reduction, null, 'WAN side not reported: no reduction claimed'); assert.equal(A['EC-JED'].wan_bytes, null);
  assert.equal(v.appliances[0].name, 'EC-DMM', 'down appliance first');
  assert.equal(v.kpis.reduction, 70); assert.equal(v.kpis.measured, 1); assert.equal(v.kpis.down, 1);
  const T = Object.fromEntries(v.tunnels.map((t) => [t.name, t]));
  assert.equal(T['RUH-JED'].level, 'critical'); assert.match(T['RUH-JED'].why, /loss 12%/); assert.equal(T['RUH-DMM'].level, 'warning'); assert.equal(T['RUH-DR'].level, 'ok');
  assert.equal(v.alarm_counts.critical, 1); assert.equal(v.alarm_counts.minor, 1);
  assert.deepEqual(v.actions.map((a) => a.filter).slice(0, 3), ['appliances', 'tunnels', 'alarms']);
  assert.ok(v.actions.some((a) => /not read from the Orchestrator/.test(a.title)), 'a failed statistics call is surfaced');
  // learning: 10 days around 70 %, today 30 % -> dropped
  const hist = { 'EC-RUH': Array.from({ length: 10 }, (_, i) => ({ day: 'd' + i, red: 68 + (i % 3) })) };
  const low = JSON.parse(JSON.stringify(WO)); low.appliances[0].wan_tx = 6e9; low.appliances[0].wan_rx = 1e9;
  const v2 = W.analyse({ orchestrators: orch(low, APPL), hist });
  const r = v2.appliances.find((a) => a.name === 'EC-RUH'); assert.equal(r.reduction, 30); assert.equal(r.dropped, true); assert.equal(r.usual, 69);
  assert.ok(v2.actions.some((a) => /Optimisation dropped/.test(a.title)));
  assert.match(W.analyse({ orchestrators: orch(WO, APPL), hist: { 'EC-RUH': [{ red: 70 }] } }).appliances.find((a) => a.name === 'EC-RUH').learning, /needs 7 days/);
  const none = W.analyse({ orchestrators: [] }); assert.equal(none.configured, false); assert.match(none.reason, /Network Onboarding/);
});

test('routes: any role reads; thresholds admin only, validated, audited; the daily sample', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-wo-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const snaps = { orc: snap({ sdwan: { appliances: APPL, alarms: [] }, wanopt: WO }) };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  N.inventory.put({ id: 'orc', name: 'ORCH-SYN', vendor: 'edgeconnect', ip: '10.0.0.9', role: 'sdwan-orchestrator' }, 'test');
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, { role = 'viewer', user = 'nora.syn', body } = {}) => {
    const out = {}; const ctx = { role, user, body, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { out.status = c; out.error = msg; } };
    try { const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.code || e.status || 500; out.error = e.message; }
    return out;
  };
  const v = (await call('GET', '/wanopt')).body; assert.equal(v.configured, true); assert.equal(v.kpis.reduction, 70);
  assert.equal((await call('POST', '/wanopt/config', { role: 'operator', body: { loss_warn: 1 } })).status, 403);
  let r = await call('POST', '/wanopt/config', { role: 'admin', body: { loss_warn: 'x' } }); assert.equal(r.status, 400); assert.match(r.error, /loss_warn must be a number/);
  r = await call('POST', '/wanopt/config', { role: 'admin', body: { lat_warn: 500, lat_crit: 400 } }); assert.equal(r.status, 400); assert.match(r.error, /lat_warn must be below lat_crit/);
  r = await call('POST', '/wanopt/config', { role: 'admin', user: 'syed', body: { loss_crit: 5, extra: 1 } }); assert.equal(r.status, 200); assert.equal(r.body.thresholds.loss_crit, 5); assert.equal(r.body.thresholds.extra, undefined);
  assert.equal(audits.filter((a) => a.a === 'netops.wanopt.config').length, 1);
  assert.equal(N.wanopt.record(), 1, 'one appliance has a measured reduction'); assert.equal(state.collection('wanopt_daily').get('EC-RUH').d[0].red, 70);
});
