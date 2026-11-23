// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// UPS / power (engine/netops/ups.js + the read-only UPS-MIB reader in collectors.js) over SYNTHETIC SNMP answers: the RFC 1628 values
// decoded (status codes, alarm OIDs, per-line walks); a value the card does not give stays null, never zero; a device that does not
// answer the UPS-MIB is an error, not an empty UPS; the state from what the UPS reports (on battery, low, bypass, fault, online, not
// answering, not polled); short runtime, failed self-test and battery ageing against the UPS's own daily history; ranked actions;
// the poller reads the MIB only for role "ups"; nothing configured says what to do; any role reads; the daily sample.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const C = require('../engine/netops/collectors');
const U = require('../engine/netops/ups');
const { ROLES } = require('../engine/netops/inventory');

const O = C.UPS_OID, B = '1.3.6.1.2.1.33.1';
const scal = (o) => { const g = {}; for (const [k, v] of Object.entries(o)) g[O[k]] = v; return g; };

test('UPS-MIB decoded: status codes, alarms, walks; unreported stays null; role "ups" exists', () => {
  const g = scal({ mfr: 'SYN-Power', model: 'SYN-10K', battStatus: 2, onBattS: 0, minLeft: 42, charge: 100, temp: 27, outSource: 3, alarmsPresent: 1, testResult: 1 });
  const u = C.upsParse(g, { inVoltage: [[B + '.3.3.1.3.1', 228], [B + '.3.3.1.3.2', 231]], outLoad: [[B + '.4.4.1.5.1', 35], [B + '.4.4.1.5.2', 20]], alarmDescr: [[B + '.6.2.1.2.1', B + '.6.3.2']] });
  assert.equal(u.battery, 'normal'); assert.equal(u.output_source, 'normal'); assert.equal(u.minutes_left, 42); assert.equal(u.charge_pct, 100);
  assert.equal(u.load_pct, 35, 'the highest-loaded output line'); assert.deepEqual(u.alarms, ['on battery']); assert.equal(u.last_test, 'passed');
  const bare = C.upsParse(scal({ battStatus: 2 }), {});
  assert.equal(bare.minutes_left, null); assert.equal(bare.load_pct, null); assert.equal(bare.temp_c, null, 'not reported is null, never 0');
  assert.ok(ROLES.includes('ups'));
});

test('a device that does not answer the UPS-MIB is an error, not an empty UPS', async () => {
  let closed = 0; const mk = (g) => () => ({ get: async () => g, walk: async () => { throw new Error('noSuchObject'); }, close() { closed++; } });
  await assert.rejects(C.upsCollect({ ip: '10.9.9.9' }, { version: '2c', community: 'syn' }, mk({})), /UPS-MIB/);
  const r = await C.upsCollect({ ip: '10.9.9.9' }, { version: '2c', community: 'syn' }, mk(scal({ battStatus: 3, charge: 20 })));
  assert.equal(r.battery, 'low'); assert.equal(r.load_pct, null, 'a table the card lacks stays null'); assert.equal(closed, 2, 'the session is always closed');
});

const dev = (id, o) => Object.assign({ id, name: id.toUpperCase(), ip: '10.0.9.' + id.length, role: 'ups', site: 'Riyadh', poll: { snmp: true } }, o);
const snap = (ups, errors) => ({ at: 1, ok: true, ups, errors: errors || [] });
const OK = { battery: 'normal', output_source: 'normal', minutes_left: 40, charge_pct: 100, load_pct: 30, alarms: [], last_test: 'passed' };

test('state, runtime, self-test, ageing and ranked actions from what the UPS reports', () => {
  const devices = [dev('ok'), dev('batt'), dev('low'), dev('byp'), dev('flt'), dev('short'), dev('test'), dev('dead'), dev('off', { poll: { snmp: false } }), { id: 'sw', role: 'access', poll: { snmp: true } }];
  const S = { ok: snap(OK), batt: snap(Object.assign({}, OK, { output_source: 'battery', seconds_on_battery: 120, minutes_left: 18 })), low: snap(Object.assign({}, OK, { battery: 'low' })),
    byp: snap(Object.assign({}, OK, { output_source: 'bypass' })), flt: snap(Object.assign({}, OK, { alarms: ['output overload'] })), short: snap(Object.assign({}, OK, { minutes_left: 8 })),
    test: snap(Object.assign({}, OK, { last_test: 'failed' })), dead: snap(null, ['ups-mib: timeout']) };
  const v = U.analyse({ devices, snapshot: (id) => S[id] || null });
  const by = Object.fromEntries(v.ups.map((u) => [u.id, u]));
  assert.equal(v.ups.length, 9, 'only role ups'); assert.equal(v.ups[0].id, 'batt', 'on battery first');
  assert.equal(by.ok.state, 'online'); assert.equal(by.batt.state, 'on-battery'); assert.equal(by.low.state, 'low'); assert.equal(by.byp.state, 'bypass');
  assert.equal(by.flt.state, 'fault'); assert.match(by.flt.why, /overload/); assert.equal(by.dead.state, 'not-answering'); assert.match(by.dead.why, /timeout/); assert.equal(by.off.state, 'not-polled');
  assert.equal(by.short.short_runtime, true); assert.equal(by.ok.short_runtime, false);
  assert.equal(by.dead.minutes_left, null, 'nothing invented for a UPS that did not answer');
  assert.equal(v.kpis.on_battery, 1); assert.equal(v.kpis.low, 1); assert.equal(v.kpis.fault, 2); assert.equal(v.kpis.not_answering, 2); assert.equal(v.kpis.test_failed, 1); assert.equal(v.kpis.min_runtime, 8);
  assert.match(v.actions[0].title, /on battery now/); assert.ok(v.actions.some((a) => /self-test failed/.test(a.title)));
  // ageing: 10 days ~40 min at ~30 % load, today 25 min at 32 % -> flagged; a different load is not compared
  const hist = { ok: Array.from({ length: 10 }, (_, i) => ({ day: 'd' + i, runtime: 39 + (i % 3), load: 28 + (i % 4) })) };
  const S2 = { ok: snap(Object.assign({}, OK, { minutes_left: 25, load_pct: 32 })) };
  const a = U.analyse({ devices: [dev('ok')], snapshot: (id) => S2[id], hist }).ups[0];
  assert.equal(a.ageing.flag, true); assert.equal(a.ageing.usual, 40); assert.match(a.ageing.why, /usually 40 min/);
  const S3 = { ok: snap(Object.assign({}, OK, { minutes_left: 10, load_pct: 80 })) };
  assert.match(U.analyse({ devices: [dev('ok')], snapshot: (id) => S3[id], hist }).ups[0].ageing.learning, /similar load - has 0/);
  const none = U.analyse({ devices: [] }); assert.equal(none.configured, false); assert.match(none.reason, /role "ups"/);
});

test('routes: any role reads; the daily sample keeps only full-charge mains readings', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ups-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const snaps = { u1: snap(OK), u2: snap(Object.assign({}, OK, { output_source: 'battery' })), u3: snap(Object.assign({}, OK, { charge_pct: 60 })) };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  for (const id of ['u1', 'u2', 'u3']) N.inventory.put({ id, name: 'UPS-' + id, vendor: 'other', ip: '10.0.8.' + id.slice(1), role: 'ups', poll: { snmp: true } }, 'test');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const ctx = { role: 'viewer', user: 'vera.syn', params: {}, query: {}, need: () => true, audit() {}, fail() {} };
  const v = await R['GET /api/soc/netops/ups'](ctx);
  assert.equal(v.configured, true); assert.equal(v.kpis.ups, 3); assert.equal(v.kpis.on_battery, 1);
  assert.equal(N.ups.record(), 1, 'on battery and part-charged readings are not a baseline');
  assert.deepEqual(state.collection('ups_daily').get('u1').d[0].runtime, 40);
});
