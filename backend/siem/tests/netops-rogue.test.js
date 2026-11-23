// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Advanced Rogue Detection (engine/netops/rogue.js): devices joined by MAC from the switch port map (ports, switch ARP, VLAN names,
// OUI vendor), FortiGate DHCP / ARP and Genian NAC; itemised risk (NAC refused / never seen, maker board, randomised MAC, unmanaged
// switch behind a port, server VLAN, new, moves, no host name) and the classes; Trusted / Guest (expiry) / Suspect / clear labels
// (operator, validated, audited; a label never hides the points); block = a port shut-down proposal on the device's port, refused
// when the device is on no read port; viewers see counts only; the FortiGate collector's DHCP / ARP parsing. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const RG = require('../engine/netops/rogue');

const DAY = 86400000, H = 3600000, NOW = Date.parse('2026-11-14T08:00:00Z');
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-rg-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const oui = path.join(dir, 'oui.csv'); fs.writeFileSync(oui, 'MA-L,B827EB,"Raspberry Pi Foundation (synthetic)",x\nMA-L,3C5282,"Synthetic HP Inc.",y\nMA-L,0026B9,"Synthetic Dell Inc.",z\n');
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, portmap: { oui_file: oui } } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  let clock = NOW;
  const snaps = {
    'fw-syn': { at: NOW, ok: true, dhcp: [{ ip: '10.10.0.50', mac: 'b8:27:eb:00:00:01', host: '', vci: 'udhcp 1.30' }, { ip: '10.10.0.21', mac: '3c:52:82:aa:00:01', host: 'PC-FIN-01' }],
      arp: [{ ip: '10.10.0.77', mac: '7a:11:22:33:44:55', iface: 'guest-wifi' }, { ip: '10.0.9.9', mac: '00:26:b9:00:00:09', iface: 'lan' }] },
    'nac-syn': { at: NOW, ok: true, nac: { items: [{ mac: '3C:52:82:AA:00:01', ip: '10.10.0.21', host: 'PC-FIN-01', status: 'Authorized' }, { mac: 'b8:27:eb:00:00:01', ip: '10.10.0.50', host: '', status: 'Unauthorized' }] } },
  };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, now: () => clock });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body } = {}) {
    const o = {}; const ctx = { role, user, body, params: {}, query: {}, path: p, need(r) { if (RANK[role] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { o.status = c; o.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.status) { o.status = 200; o.body = rv; } return o;
  }
  N.inventory.put({ id: 'fw-syn', name: 'FW-SYN', vendor: 'fortigate', ip: '10.0.0.1', role: 'firewall' }, 'test');
  N.inventory.put({ id: 'nac-syn', name: 'GENIAN-SYN', vendor: 'genian', ip: '10.0.5.9', role: 'nac' }, 'test');
  N.inventory.put({ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  // the port map: the Raspberry Pi on Gi1/0/9 in the server VLAN, three MACs behind Gi1/0/4, the HP PC on Gi1/0/1
  state.collection('portmap_reads').put({ id: 'acc-syn', at: NOW - H, ports: [], trunks: ['te1/1/1'], vlans: { 10: 'USERS', 30: 'SERVERS' }, errors: [], neighbours: [],
    macs: [{ vlan: 30, mac: 'b827eb000001', port: 'Gi1/0/9' }, { vlan: 10, mac: '3c5282aa0001', port: 'Gi1/0/1' }, { vlan: 10, mac: '0026b9000004', port: 'Gi1/0/4' }, { vlan: 10, mac: '0026b9000005', port: 'Gi1/0/4' }, { vlan: 10, mac: '0026b9000006', port: 'Gi1/0/4' }, { vlan: 10, mac: 'aaaa00000001', port: 'Te1/1/1' }],
    arp: [{ ip: '10.30.0.5', mac: 'b827eb000001' }] });
  const pm = state.collection('portmap_macs');
  pm.put({ id: 'b827eb000001', device: 'acc-syn', port: 'gi1/0/9', first: NOW - 2 * H, last: NOW - H, moves: [] });
  pm.put({ id: '3c5282aa0001', device: 'acc-syn', port: 'gi1/0/1', first: NOW - 90 * DAY, last: NOW - H, moves: [] });
  for (const m of ['0026b9000004', '0026b9000005', '0026b9000006']) pm.put({ id: m, device: 'acc-syn', port: 'gi1/0/4', first: NOW - 30 * DAY, last: NOW - H, moves: m.endsWith('6') ? [{ at: NOW - 3 * H }, { at: NOW - 2 * H }] : [] });
  return { N, call, audits, at: (t) => { clock = t; } };
}

test('devices joined by MAC across sources, itemised risk and classes, sources counted', async () => {
  const { call } = await setup();
  const r = await call('GET', '/rogue', { role: 'analyst' }); assert.equal(r.status, 200, r.error);
  const V = r.body, by = Object.fromEntries(V.devices.map((d) => [d.mac, d]));
  const pi = by['b8:27:eb:00:00:01'];
  assert.equal(pi.class, 'rogue'); assert.deepEqual(pi.seen_by.sort(), ['NAC', 'firewall DHCP', 'switch port'].sort());
  assert.match(pi.vendor, /Raspberry Pi/); assert.equal(pi.port.port, 'gi1/0/9'); assert.equal(pi.vlan_name, 'SERVERS'); assert.ok(pi.ips.includes('10.10.0.50') && pi.ips.includes('10.30.0.5'));
  const why = pi.why.map((w) => w.why).join(' | ');
  assert.match(why, /NAC refused/); assert.match(why, /maker board/); assert.match(why, /SERVERS/); assert.match(why, /first seen in the last 24 hours/); assert.match(why, /no host name/);
  assert.equal(pi.risk, 100, 'capped at 100');
  assert.equal(by['3c:52:82:aa:00:01'].class, 'trusted'); assert.equal(by['3c:52:82:aa:00:01'].trusted_by, 'NAC');
  const behind = by['00:26:b9:00:00:06']; assert.match(behind.why.map((w) => w.why).join(' '), /3 MACs behind ACC-SYN gi1\/0\/4/); assert.match(behind.why.map((w) => w.why).join(' '), /moved ports 2 times/);
  assert.equal(by['7a:11:22:33:44:55'].randomised, true); assert.deepEqual(by['7a:11:22:33:44:55'].seen_by, ['firewall ARP']); assert.equal(by['7a:11:22:33:44:55'].can_block, false);
  assert.ok(!by['aa:aa:00:00:00:01'], 'MACs learned on a trunk are not endpoints');
  assert.equal(V.kpis.unmanaged_ports, 1); assert.equal(V.nac_connected, true); assert.equal(V.oui_loaded, true);
  assert.ok(V.sources.firewall_dhcp === 2 && V.sources.firewall_arp === 2 && V.sources.nac === 2 && V.sources.switch_ports === 5);
  assert.equal(V.devices[0].mac, 'b8:27:eb:00:00:01', 'riskiest first');
});

test('labels: operator only, validated, audited; guest expires back; a label never hides the points', async () => {
  const { call, audits, at } = await setup();
  const mac = '7a:11:22:33:44:55';
  assert.equal((await call('POST', '/rogue/label', { role: 'analyst', body: { macs: [mac], label: 'guest', days: 3 } })).status, 403);
  let r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: [mac], label: 'guest' } }); assert.equal(r.status, 400); assert.match(r.error, /days is required/);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: [mac], label: 'trusted' } }); assert.equal(r.status, 400); assert.match(r.error, /note is required to trust/);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: [mac], label: 'friend' } }); assert.equal(r.status, 400); assert.match(r.error, /label must be one of/);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: ['de:ad:be:ef:00:00'], label: 'suspect' } }); assert.equal(r.status, 404);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: ['not-a-mac'], label: 'suspect' } }); assert.equal(r.status, 400);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: [mac], label: 'guest', days: 3, note: 'synthetic visitor' } }); assert.equal(r.status, 200);
  assert.ok(audits.some((a) => a.a === 'netops.rogue.label' && a.d.label === 'guest' && a.d.days === 3 && a.user === 'nora.syn'));
  let d = (await call('GET', '/rogue', { role: 'analyst' })).body.devices.find((x) => x.mac === mac);
  assert.equal(d.class, 'guest'); assert.equal(d.label.by, 'nora.syn'); assert.ok(d.why.length > 0, 'the points are still shown');
  at(NOW + 4 * DAY); d = (await call('GET', '/rogue', { role: 'analyst' })).body.devices.find((x) => x.mac === mac);
  assert.notEqual(d.class, 'guest'); assert.match(d.note, /guest access expired/);
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: ['00:26:b9:00:00:04', '00:26:b9:00:00:05'], label: 'trusted', note: 'synthetic lab switch, asset SYN-77' } });
  assert.equal(r.body.changed.length, 2); assert.ok(audits.some((a) => a.a === 'netops.rogue.label' && a.t === '2 devices'));
  r = await call('POST', '/rogue/label', { role: 'operator', body: { macs: ['00:26:b9:00:00:04'], label: 'clear' } }); assert.equal(r.body.changed[0].from, 'trusted');
});

test('block: a four-eyes port shut-down proposal on the device port; refused off a read port; validated', async () => {
  const calls = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-rg2-')), state = await createState({ dir });
  state.collection('portmap_macs').put({ id: 'b827eb000001', device: 'acc-syn', port: 'gi1/0/9', first: NOW - H, last: NOW, moves: [] });
  const portmap = { vendor: () => 'Raspberry Pi Foundation (synthetic)', ouiLoaded: () => true, propose: (b, who, via) => { calls.push({ b, who, via }); return { plan: 'NCHG-000009', title: 'Shut ' + b.port, status: 'proposed', risk: 'medium' }; } };
  const inv = { list: () => [{ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios' }] };
  const fwSnap = { arp: [{ ip: '10.0.0.66', mac: '02:00:00:00:00:66' }] };
  const R0 = RG.createRogue({ inventory: { list: () => inv.list().concat([{ id: 'fw', vendor: 'fortigate' }]) }, poller: { snapshot: (id) => (id === 'fw' ? fwSnap : null) }, state, portmap, now: () => NOW });
  const r = R0.block('b8:27:eb:00:00:01', 'unknown board in the server VLAN', { user: 'nora.syn' });
  assert.deepEqual([r.plan, r.switch, r.port, r.status], ['NCHG-000009', 'ACC-SYN', 'gi1/0/9', 'proposed']);
  assert.deepEqual([calls[0].b.type, calls[0].b.device, calls[0].via], ['port-shutdown', 'acc-syn', 'user']); assert.match(calls[0].b.reason, /\[rogue detection\] b8:27:eb:00:00:01/);
  assert.throws(() => R0.block('02:00:00:00:00:66', 'x', { user: 'n' }), (e) => e.status === 409 && /block it in Genian NAC/.test(e.message));
  const { call } = await setup();
  let x = await call('POST', '/rogue/block', { role: 'analyst', body: { mac: 'b8:27:eb:00:00:01', reason: 'unknown board' } }); assert.equal(x.status, 403);
  x = await call('POST', '/rogue/block', { role: 'operator', body: { mac: 'b8:27:eb:00:00:01' } }); assert.equal(x.status, 400); assert.match(x.error, /reason is required/);
});

test('viewer: counts only; NAC states; the FortiGate collector reads DHCP and ARP', async () => {
  const { call } = await setup();
  const V = (await call('GET', '/rogue')).body; assert.equal(V.private, true); assert.deepEqual(V.devices, []); assert.ok(V.kpis.devices >= 5);
  assert.equal(RG.NAC_STATE('Unauthorized'), 'unauthorised'); assert.equal(RG.NAC_STATE('Quarantined'), 'quarantined'); assert.equal(RG.NAC_STATE('Authorized'), 'authorised');
  const C = require('../engine/netops/collectors'); const src = fs.readFileSync(require.resolve('../engine/netops/collectors'), 'utf8');
  assert.ok(/\/api\/v2\/monitor\/system\/dhcp/.test(src) && /\/api\/v2\/monitor\/network\/arp/.test(src) && typeof C.fortigate === 'function');
});
