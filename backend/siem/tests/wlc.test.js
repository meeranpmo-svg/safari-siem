// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Wireless LAN controllers (engine/netops/wlc.js) over SYNTHETIC SNMP answers in the AIRESPACE-WIRELESS-MIB layout: APs keyed by
// MAC, radios per slot (band, channel, oper status, clients), channel utilisation, SSIDs with client counts; a value the controller
// does not give stays null, never 0; a controller that does not answer the MIB is an error, not an empty controller; Aruba is
// recognised and refused (not verified); the poller reads it only for role "wlc"; an AP that drops out of the table shows as
// "not joined"; the inventory has the roles wlc and fc_switch. No client MAC / name is ever read (counts only).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const W = require('../engine/netops/wlc');
const { createPoller } = require('../engine/netops/poller');
const { ROLES } = require('../engine/netops/inventory');
const { createState } = require('../engine/soc/state');

const C = W.CISCO;
const AP1 = '0.17.34.51.68.85', AP2 = '0.17.34.51.68.86';   // 00:11:22:33:44:55 / :56
const walks = () => ({
  apName: [[C.apName + '.' + AP1, Buffer.from('AP-RYD-01')], [C.apName + '.' + AP2, Buffer.from('AP-RYD-02')]],
  apLocation: [[C.apLocation + '.' + AP1, Buffer.from('Riyadh HQ floor 3')]],
  apOper: [[C.apOper + '.' + AP1, 1], [C.apOper + '.' + AP2, 3]],
  apModel: [[C.apModel + '.' + AP1, Buffer.from('AIR-SYN-1')]], apSerial: [], apIp: [[C.apIp + '.' + AP1, '10.50.0.11']],
  ifType: [[C.ifType + '.' + AP1 + '.0', 1], [C.ifType + '.' + AP1 + '.1', 2], [C.ifType + '.' + AP2 + '.0', 1]],
  ifChannel: [[C.ifChannel + '.' + AP1 + '.0', 6], [C.ifChannel + '.' + AP1 + '.1', 36], [C.ifChannel + '.' + AP2 + '.0', 6]],
  ifOper: [[C.ifOper + '.' + AP1 + '.0', 2], [C.ifOper + '.' + AP1 + '.1', 2], [C.ifOper + '.' + AP2 + '.0', 1]],
  ifUsers: [[C.ifUsers + '.' + AP1 + '.0', 7], [C.ifUsers + '.' + AP1 + '.1', 12]],
  chUtil: [[C.chUtil + '.' + AP1 + '.0', 81], [C.chUtil + '.' + AP1 + '.1', 22]],
  essSsid: [[C.essSsid + '.1', Buffer.from('SYN-Corp')], [C.essSsid + '.2', Buffer.from('SYN-Guest')]], essAdmin: [[C.essAdmin + '.1', 1], [C.essAdmin + '.2', 2]], essClients: [[C.essClients + '.1', 15], [C.essClients + '.2', 4]],
});

test('AIRESPACE tables decoded: APs, radios, channels, utilisation, SSIDs; unreported stays null; roles wlc + fc_switch', () => {
  const r = W.parseCisco(walks());
  assert.equal(r.aps.length, 2);
  const a = r.aps[0]; assert.equal(a.name, 'AP-RYD-01'); assert.equal(a.mac, '00:11:22:33:44:55'); assert.equal(a.status, 'up'); assert.equal(a.ip, '10.50.0.11'); assert.equal(a.clients, 19);
  assert.deepEqual(a.radios.map((x) => [x.band, x.channel, x.oper, x.clients, x.ch_util_pct]), [['2.4 GHz', 6, 'up', 7, 81], ['5 GHz', 36, 'up', 12, 22]]);
  const b = r.aps[1]; assert.equal(b.status, 'downloading'); assert.equal(b.radios[0].clients, null, 'not reported is null, never 0'); assert.equal(b.radios[0].ch_util_pct, null); assert.equal(b.model, '');
  assert.deepEqual(r.ssids, [{ wlan_id: 1, ssid: 'SYN-Corp', enabled: true, clients: 15 }, { wlan_id: 2, ssid: 'SYN-Guest', enabled: false, clients: 4 }]);
  assert.deepEqual([r.summary.aps, r.summary.aps_up, r.summary.aps_down, r.summary.clients, r.summary.radios_down, r.summary.max_ch_util_pct, r.summary.busy_radios, r.summary.ssid_clients], [2, 1, 1, 19, 1, 81, 1, 19]);
  assert.deepEqual(r.summary.channels, { '2.4 GHz ch 6': 1, '5 GHz ch 36': 1 }, 'a radio that is down is not counted on its channel');
  assert.ok(!JSON.stringify(r).match(/mobile|station/i), 'no client table is read');
  assert.ok(ROLES.includes('wlc') && ROLES.includes('fc_switch'));
});

test('collect: Cisco by sysObjectID, a controller without the MIB is an error, Aruba refused, session always closed', async () => {
  let closed = 0;
  const mk = (sysOid, tables) => () => ({ get: async () => ({ '1.3.6.1.2.1.1.2.0': sysOid, '1.3.6.1.2.1.1.1.0': Buffer.from('SYN controller') }),
    walk: async (o) => { const k = Object.keys(C).find((x) => C[x] === o); if (!tables || !tables[k]) throw new Error('noSuchObject'); return tables[k]; }, close() { closed++; } });
  const r = await W.collect({ ip: '10.9.9.9' }, { version: '2c', community: 'syn' }, mk('1.3.6.1.4.1.14179.1.1.4.3', walks()));
  assert.equal(r.vendor, 'cisco'); assert.equal(r.aps.length, 2); assert.equal(r.sys_object_id, '1.3.6.1.4.1.14179.1.1.4.3');
  await assert.rejects(W.collect({ ip: '10.9.9.9' }, { version: '2c', community: 'syn' }, mk('1.3.6.1.4.1.9.1.2391', null)), /does not answer the AIRESPACE-WIRELESS-MIB/);
  await assert.rejects(W.collect({ ip: '10.9.9.9' }, { version: '2c', community: 'syn' }, mk('1.3.6.1.4.1.14823.1.1.32', walks())), /Aruba .* not supported yet/);
  assert.equal(closed, 3);
  assert.equal(W.vendorFor('1.3.6.1.4.1.9.1.2391', ''), 'cisco'); assert.equal(W.vendorFor('1.3.6.1.4.1.99.1', 'x'), null);
});

test('poller: the WLC MIB is read only for role wlc with SNMP credentials; history rows; other devices unchanged', async () => {
  const devs = { w1: { id: 'w1', name: 'WLC-1', vendor: 'other', ip: '10.0.5.1', role: 'wlc', site: 'Riyadh', poll: { ping: false, snmp: true } }, s1: { id: 's1', name: 'SW-1', vendor: 'cisco-ios', ip: '10.0.5.2', role: 'access', site: 'Riyadh', poll: { ping: false, snmp: true } } };
  const inventory = { get: (id) => devs[id], list: () => Object.values(devs), credentials: () => ({ snmp: { version: '2c', community: 'syn' } }) };
  const calls = [], rows = [];
  const collectors = { ping: async () => ({}), snmpCollect: async () => ({ system: { name: 'x' } }), wlcCollect: async (d) => { calls.push(d.id); return Object.assign(W.parseCisco(walks()), { at: 1 }); }, security: async () => ({ at: 1, findings: [] }) };
  const p = createPoller({ inventory, config: { netops: { security: false } }, collectors, ch: { insertRows: async (t, r) => { rows.push(...r); } } });
  const a = await p.pollDevice('w1'), b = await p.pollDevice('s1');
  assert.deepEqual(calls, ['w1']); assert.equal(a.wlc.summary.aps, 2); assert.equal(b.wlc, undefined);
  await new Promise((r) => setImmediate(r));
  assert.ok(rows.some((r) => r.metric === 'wlc_clients' && r.value === 19 && r.device === 'w1')); assert.ok(rows.some((r) => r.metric === 'wlc_ssid_clients' && r.key === 'SYN-Corp' && r.value === 15));
  const failing = createPoller({ inventory, config: { netops: { security: false } }, collectors: Object.assign({}, collectors, { wlcCollect: async () => { throw new Error('timeout'); } }) });
  assert.deepEqual((await failing.pollDevice('w1')).errors, ['wlc: timeout']);
  const injected = createPoller({ inventory, config: { netops: { security: false } }, collectors: { ping: collectors.ping, snmpCollect: collectors.snmpCollect, security: collectors.security } });
  assert.equal((await injected.pollDevice('w1')).wlc, undefined, 'injected collectors without wlcCollect skip it');
});

test('view: controllers, "not joined" APs from what the controller listed before, nothing configured says what to do', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-wlc-')) });
  let t = 1000000, snap = null;
  const devs = [{ id: 'w1', name: 'WLC-1', ip: '10.0.5.1', site: 'Riyadh', role: 'wlc', poll: { snmp: true } }, { id: 'w2', name: 'WLC-2', ip: '10.0.5.2', site: 'Jeddah', role: 'wlc', poll: { snmp: false } }];
  const view = W.createWlcView({ inventory: { list: () => devs, credentialSummary: () => ({ snmp: 'v2c' }) }, poller: { snapshot: (id) => (id === 'w1' ? snap : null) }, state, now: () => t }).view;
  let v = view(); assert.equal(v.controllers[0].state, 'waiting'); assert.equal(v.controllers[1].state, 'not-polled'); assert.equal(v.summary.reporting, 0);
  snap = { at: t, errors: [], wlc: Object.assign(W.parseCisco(walks()), { at: t }) };
  v = view(); assert.equal(v.summary.aps, 2); assert.equal(v.summary.clients, 19); assert.equal(v.ssids[0].ssid, 'SYN-Corp');
  const w2 = walks(); w2.apName = w2.apName.slice(0, 1); t += 120000;
  snap = { at: t, errors: [], wlc: Object.assign(W.parseCisco(w2), { at: t }) };
  v = view(); const miss = v.controllers[0].aps.find((a) => a.name === 'AP-RYD-02');
  assert.equal(miss.status, 'not-joined'); assert.equal(v.summary.not_joined, 1); assert.equal(v.summary.aps_down, 1);
  t += 8 * 86400000; snap = { at: t, errors: [], wlc: Object.assign(W.parseCisco(w2), { at: t }) };
  assert.equal(view().summary.not_joined, 0, 'forgotten after 7 days');
  const none = W.createWlcView({ inventory: { list: () => [] }, poller: { snapshot: () => null }, state }).view();
  assert.equal(none.configured, false); assert.match(none.reason, /role "wlc"/);
});
