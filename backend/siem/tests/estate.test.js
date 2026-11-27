// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Estate & Licensing (engine/netops/estate.js) over a SYNTHETIC FortiManager fleet and switch poller: firewalls with an
// explainable risk score (each point with its reason); switches with ports up / with errors / hot; every FortiCare / FortiGuard
// licence with its days left, expired / due 30 / due 90, the 12-month renewal calendar and the co-term months; devices without
// support; firmware compliance per model; what the AI noticed with figures; suggested change plans (never executed); the route
// is a read for any signed-in user; nothing connected says what to connect.
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../engine/netops/estate');

const T0 = Date.parse('2026-11-27T08:00:00Z'), day = (d) => new Date(T0 + d * 86400000).toISOString().slice(0, 10);
const FW = (name, o) => Object.assign({ name, serial: 'FG' + name, site: 'Riyadh', model: 'FortiGate-60F', firmware: '7.2.8', health: 'ok', conn: 'up', conf: 'in-sync', ha_mode: 'standalone', ha_members: [], links: [], findings: [], z: {}, res: { cpu: 20, mem: 40 },
  licences: [{ name: 'forticare', expires: day(200) }, { name: 'antivirus', expires: day(200) }] }, o || {});
function fakeFmg(devs) { return { status: () => ({ configured: true, last_poll_at: new Date(T0).toISOString() }), fleet: () => ({ status: {}, kpis: { tunnels: { up: 5, down: 1 } }, changes_open: 2, devices: devs,
  models: [{ model: 'FortiGate-60F', devices: 3, target: '7.2.8', newest: '7.4.4', versions: { '7.2.8': 1, '7.0.12': 2 } }] }) }; }
function fakeNet(sw) { return { inventory: { list: () => sw.map((x) => x.d) }, poller: { snapshot: (id) => (sw.find((x) => x.d.id === id) || {}).s || null } }; }

test('estate: firewalls risk with reasons, licences with the calendar, switches, firmware, noticed, suggestions', () => {
  const fmg = fakeFmg([
    FW('FW-SYN-DOWN', { conn: 'down', health: 'down', licences: [{ name: 'forticare', expires: day(-10) }, { name: 'ips', expires: day(20) }] }),
    FW('FW-SYN-SYNC', { conf: 'modified', firmware: '7.0.12', findings: [{ code: 'firmware', severity: 'medium' }], z: { cpu: 4.2 }, licences: [{ name: 'forticare', expires: day(60) }, { name: 'web_filtering', expires: day(60) }] }),
    FW('FW-SYN-OK', { firmware: '7.0.12', findings: [{ code: 'firmware', severity: 'medium' }] })]);
  const net = fakeNet([
    { d: { id: 's1', name: 'SW-SYN-CORE', vendor: 'h3c-comware', role: 'core', site: 'Riyadh', ip: '10.0.0.2' }, s: { ok: true, at: 'x', system: { model: 'S6520', version: '7.1', cpu_pct: 30, mem_pct: 50 },
      interfaces: [{ name: 'GE1/0/1', oper: 'up', util_in: 92 }, { name: 'GE1/0/2', oper: 'up', err_per_min: 3 }, { name: 'GE1/0/3', oper: 'down' }, { name: 'Vlan-interface1', oper: 'up', util_in: 99 }] } },
    { d: { id: 's2', name: 'SW-SYN-ACC', vendor: 'h3c-comware', role: 'access', site: 'Jeddah', ip: '10.1.0.2' }, s: { ok: false, reach: { loss_pct: 100 }, at: 'x', interfaces: [] } },
    { d: { id: 'f9', name: 'FW-STANDALONE', vendor: 'fortigate', role: 'firewall', site: 'Dammam', ip: '10.2.0.1' }, s: { ok: true, licenses: { serial: 'FGSA', items: [{ name: 'FortiCare Premium', kind: 'support', expires: day(5) }] } } }]);
  const v = E.createEstate({ fmgApi: fmg, netopsInstance: net, now: () => T0 }).build();
  assert.equal(v.kpis.firewalls, 3); assert.equal(v.kpis.fw_down, 1); assert.equal(v.kpis.out_of_sync, 1); assert.equal(v.kpis.switches, 2); assert.equal(v.kpis.sw_down, 1); assert.equal(v.kpis.changes_open, 2);
  const down = v.firewalls.find((d) => d.name === 'FW-SYN-DOWN');
  assert.equal(down.risk, 65, 'down 40 + licence expired 25'); assert.equal(v.risk[0].name, 'FW-SYN-DOWN'); assert.ok(v.risk[0].why.some((w) => /not connected/.test(w.reason)) && v.risk[0].why.some((w) => /expired/.test(w.reason)));
  const sync = v.risk.find((r) => r.name === 'FW-SYN-SYNC'); assert.ok(sync.why.some((w) => /out of sync/.test(w.reason)) && sync.why.some((w) => /firmware behind/.test(w.reason)) && sync.why.some((w) => /CPU unusual/.test(w.reason)));
  // switches: physical ports only, errors and hot ports, a switch not answering
  const core = v.switches.find((s) => s.name === 'SW-SYN-CORE'); assert.equal(core.ports, 3); assert.equal(core.ports_up, 2); assert.equal(core.err_ports, 1); assert.equal(core.hot_ports, 1);
  assert.equal(v.switches.find((s) => s.name === 'SW-SYN-ACC').up, false); assert.ok(!v.switches.some((s) => s.name === 'FW-STANDALONE'), 'a firewall is not a switch');
  // licences: names, kinds, days, counts, calendar, standalone FortiGate included, devices without support
  const L = v.licences;
  assert.ok(L.items.some((l) => l.device === 'FW-SYN-DOWN' && l.name === 'FortiCare support' && l.kind === 'support' && l.days === -10));
  assert.ok(L.items.some((l) => l.device === 'FW-SYN-SYNC' && l.name === 'Web filtering' && l.kind === 'security'));
  assert.ok(L.items.some((l) => l.device === 'FW-STANDALONE' && l.days === 5), 'standalone FortiGate licences from the poller');
  assert.equal(L.expired, 1); assert.equal(L.due30, 2); assert.equal(L.due90, 2);
  assert.equal(L.calendar.length, 12); assert.equal(L.calendar.reduce((a, c) => a + c.support + c.security, 0), 7, 'every dated licence within 12 months, the expired one excluded');
  assert.deepEqual(L.devices_without_support, ['FW-SYN-DOWN']);
  assert.equal(v.models[0].on_target, 1);
  const N = v.noticed.map((x) => x.text).join(' | ');
  assert.match(N, /1 FortiGates are not connected/); assert.match(N, /1 switches are not answering/); assert.match(N, /1 FortiCare \/ FortiGuard licences have expired/); assert.match(N, /2 licences end within 30 days; 2 more within 90/);
  assert.match(N, /2 FortiGates are not on their model's target firmware/); assert.match(N, /unusual for their own baseline: FW-SYN-SYNC/); assert.match(N, /1 switch ports are logging errors/); assert.match(N, /Highest risk: FW-SYN-DOWN/);
  assert.ok(v.suggestions.some((s) => s.kind === 'firmware' && /Upgrade 2 FortiGate-60F to 7\.2\.8/.test(s.title) && /second administrator approves/.test(s.note)));
  assert.ok(v.suggestions.some((s) => s.kind === 'renewal' && /Renew 3/.test(s.title)));
});

test('estate: nothing connected says what to connect; a FortiManager error is not fatal', () => {
  let v = E.createEstate({ now: () => T0 }).build();
  assert.equal(v.kpis.firewalls, 0); assert.match(v.note, /connect FortiManager/); assert.equal(v.fortimanager.connected, false);
  const warned = []; v = E.createEstate({ now: () => T0, log: { warn: (m) => warned.push(m) }, fmgApi: { status: () => ({ configured: true }), fleet: () => { throw new Error('poll failed'); } } }).build();
  assert.equal(v.fortimanager.connected, false); assert.equal(warned.length, 1, 'the failure is logged, not swallowed');
});

test('estate: the route is a read for any signed-in user', async () => {
  const R = []; E.register({ route: (m, p, h) => R.push({ m, p, h }) }, { now: () => T0, prefix: '/api/soc', state: {} });
  assert.equal(R.length, 1); assert.equal(R[0].m, 'GET'); assert.equal(R[0].p, '/api/soc/netops/estate');
  assert.equal(E.lname('web_filtering'), 'Web filtering'); assert.equal(E.lname('some_new_service'), 'Some new service');
});
