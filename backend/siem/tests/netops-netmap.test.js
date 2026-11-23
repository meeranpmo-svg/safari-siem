// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Intelligent Network Map (engine/netops/netmap.js): topology from the port map's CDP / LLDP reads joined on IP or exact host
// name (never a similar name), live state from the poll, layers from roles, single points of failure, blast radius of a down
// device and a down link, unmanaged switches, one-sided links, stale / empty neighbour tables, devices not placed, path,
// changes since the last snapshot, layout; roles (viewer sees no IP, analyst for impact / path, operator for writes), validation
// errors that name the field, and the audit record. SYNTHETIC devices only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const NMOD = require('../engine/netops/netmap');

const DAY = 86400000;
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-nm-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  let clock = Date.parse('2026-11-14T07:00:00Z');
  const snaps = {};
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, now: () => clock });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, params = {}, query = {} } = {}) {
    const o = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { o.status = c; o.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.status) { o.status = 200; o.body = rv; } return o;
  }
  const put = (d) => N.inventory.put(d, 'test');
  put({ id: 'fw-syn', name: 'FW-SYN', vendor: 'paloalto', ip: '10.0.0.1', site: 'Riyadh HQ', role: 'firewall' });
  put({ id: 'core-syn', name: 'CORE-SYN', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core' });
  put({ id: 'acc-a', name: 'ACC-A-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' });
  put({ id: 'acc-b', name: 'ACC-B-SYN', vendor: 'cisco-ios', ip: '10.0.5.3', site: 'Riyadh HQ', role: 'access' });
  put({ id: 'lonely', name: 'LONELY-SYN', vendor: 'fortigate', ip: '10.9.9.9', site: 'Jeddah', role: 'branch-router' });
  const nb = (local, name, ip, caps, remote_port, via = 'cdp') => ({ local, name, ip, caps, remote_port, platform: '', via });
  const reads = state.collection('portmap_reads');
  // core: names the firewall by IP, ACC-A by exact host name with a domain, ACC-B by IP
  reads.put({ id: 'core-syn', at: clock - 3600000, ports: [], trunks: [], macs: [], errors: [], neighbours: [nb('Gi1/0/1', 'fw-syn', '10.0.0.1', ['Router'], 'ethernet1/3', 'lldp'), nb('Te1/1/1', 'ACC-A-SYN.as.local', '', ['Switch', 'IGMP'], 'Te1/1/1'), nb('Te1/1/2', 'whatever', '10.0.5.3', ['Switch'], 'Te1/1/1')] });
  // ACC-A: reports the core back (confirmed), an unmanaged switch, a phone; a similar-but-not-equal name is NOT joined
  reads.put({ id: 'acc-a', at: clock - 3600000, ports: [], trunks: ['te1/1/1'], macs: [{ port: 'Gi1/0/1', mac: 'a' }, { port: 'Gi1/0/2', mac: 'b' }, { port: 'Te1/1/1', mac: 'c' }], errors: [],
    neighbours: [nb('Te1/1/1', 'CORE-SYN', '10.0.0.2', ['Router', 'Switch'], 'Te1/1/1'), nb('Gi1/0/8', 'SW-HIDDEN.as.local', '10.0.9.9', ['Switch', 'IGMP'], 'Gi0/1'), nb('Gi1/0/2', 'SEP001122334455', '10.20.0.5', ['Host', 'Phone'], 'Port 1'), nb('Gi1/0/9', 'CORE-SYN-2', '', ['Switch'], 'Gi1/0/9')] });
  // ACC-B: read 10 days ago, reports nothing (CDP off) -> the core's link to it is one-sided
  reads.put({ id: 'acc-b', at: clock - 10 * DAY, ports: [], trunks: [], macs: [], errors: [], neighbours: [] });
  snaps['fw-syn'] = { at: clock, ok: true, sources: ['ping'], reach: { sent: 3, received: 3, rtt_avg_ms: 1 } };
  snaps['core-syn'] = { at: clock, ok: true, sources: ['ping', 'snmp'], reach: { sent: 3, received: 3 }, interfaces: [{ name: 'TenGigabitEthernet1/1/1', oper: 'up', util_in: 12, util_out: 30 }, { name: 'TenGigabitEthernet1/1/2', oper: 'down' }] };
  snaps['acc-a'] = { at: clock, ok: true, sources: ['ping'], reach: { sent: 3, received: 3 } };
  snaps['acc-b'] = { at: clock, ok: false, sources: ['ping'], reach: { sent: 3, received: 0 } };
  return { N, call, audits, state, reads, snaps, at: (t) => { clock = t; }, now: () => clock };
}

test('kindOf: phones and hosts are endpoints; switches, routers and APs are nodes', () => {
  assert.equal(NMOD.kindOf({ caps: ['Host', 'Phone'] }), 'phone');
  assert.equal(NMOD.kindOf({ caps: ['Trans-Bridge'], platform: 'cisco AIR-AP2802I' }), 'ap');
  assert.equal(NMOD.kindOf({ caps: ['Router'] }), 'router');
  assert.equal(NMOD.kindOf({ caps: ['Router', 'Switch'] }), 'switch');
  assert.equal(NMOD.kindOf({ caps: ['Station'] }), 'host');
});

test('map: joins on IP or exact name, states, layers, SPOF, blast radius, unmanaged, one-sided, stale, not placed', async () => {
  const { call } = await setup();
  const r = await call('GET', '/netmap', { role: 'analyst' }); assert.equal(r.status, 200, r.error);
  const V = r.body, node = (id) => V.nodes.find((n) => n.id === id), link = (a, b) => V.links.find((l) => (l.a === a && l.b === b) || (l.a === b && l.b === a));
  // nodes: 5 managed + the unmanaged switch; the phone is counted, not drawn; "CORE-SYN-2" is not joined to CORE-SYN
  assert.ok(node('nb:sw-hidden') && node('nb:sw-hidden').managed === false && node('nb:sw-hidden').role === 'switch');
  assert.ok(node('nb:core-syn-2'), 'a similar name is a different device, never joined');
  assert.ok(!V.nodes.some((n) => /SEP0011/.test(n.name)), 'phone not drawn');
  assert.equal(node('acc-a').endpoints.phones, 1); assert.equal(node('acc-a').read.macs, 2, 'MACs on trunks are not endpoints');
  // links
  const ca = link('core-syn', 'acc-a'); assert.ok(ca.confirmed, 'seen from both ends'); assert.equal(ca.state, 'up'); assert.equal(ca.util_pct, 30);
  const cb = link('core-syn', 'acc-b'); assert.ok(cb.one_sided && !cb.confirmed); assert.equal(cb.state, 'down', 'the core\'s interface is down');
  const fc = link('fw-syn', 'core-syn'); assert.equal(fc.state, 'not measured', 'no interface data -> never shown as up');
  assert.equal(V.links.filter((l) => (l.a === 'core-syn' && l.b === 'acc-a') || (l.a === 'acc-a' && l.b === 'core-syn')).length, 1, 'one link, not one per end');
  // states and layers
  assert.equal(node('acc-b').state, 'down'); assert.equal(node('fw-syn').layer, 0); assert.equal(node('core-syn').layer, 1); assert.equal(node('acc-a').layer, 3);
  assert.equal(V.roots.basis, 'edge devices'); assert.deepEqual(V.roots.ids, ['fw-syn']);
  // findings
  const f = (k) => V.findings.filter((x) => x.kind === k);
  const sp = f('single-point').find((x) => x.node === 'core-syn'); assert.ok(sp && sp.severity === 'high' && sp.cut_off.includes('ACC-A-SYN') && sp.cut_off.includes('ACC-B-SYN'));
  assert.ok(f('single-point').some((x) => x.node === 'acc-a'), 'ACC-A alone carries SW-HIDDEN');
  assert.equal(node('core-syn').spof, true); assert.equal(node('acc-b').spof, false, 'a leaf is not a single point of failure');
  assert.ok(f('device-down').some((x) => x.node === 'acc-b'));
  assert.ok(f('link-down').some((x) => x.link === cb.id));
  assert.ok(f('unmanaged').some((x) => x.node === 'nb:sw-hidden' && /ACC-A-SYN Gi1\/0\/8/.test(x.why)));
  assert.ok(f('one-sided').some((x) => x.link === cb.id));
  assert.ok(f('stale').some((x) => x.node === 'acc-b' && /10 days/.test(x.title)));
  assert.ok(f('no-neighbours').some((x) => x.node === 'acc-b'));
  assert.equal(V.findings[0].severity, 'high', 'sorted worst first');
  assert.deepEqual(V.not_placed.map((x) => x.id), ['lonely']); assert.match(V.not_placed[0].why, /reads Cisco IOS switches/);
  assert.equal(V.summary.devices, 5); assert.equal(V.summary.switches_read, 3); assert.equal(V.summary.down, 1);
});

test('impact, path, roles, privacy, validation errors name the field', async () => {
  const { call } = await setup();
  // viewer: map without IPs; impact and path need analyst
  const v = await call('GET', '/netmap'); assert.equal(v.status, 200); assert.ok(v.body.private); assert.ok(v.body.nodes.every((n) => n.ip === ''));
  assert.equal((await call('GET', '/netmap/impact/:id', { params: { id: 'core-syn' } })).status, 403);
  assert.equal((await call('GET', '/netmap/path', { query: { from: 'fw-syn', to: 'acc-a' } })).status, 403);
  let r = await call('GET', '/netmap/impact/:id', { role: 'analyst', params: { id: 'core-syn' } }); assert.equal(r.status, 200);
  assert.deepEqual(r.body.cut_off.map((x) => x.id).sort(), ['acc-a', 'acc-b', 'nb:core-syn-2', 'nb:sw-hidden']);
  r = await call('GET', '/netmap/impact/:id', { role: 'analyst', params: { id: 'BAD ID' } }); assert.equal(r.status, 400); assert.match(r.error, /id must be a device id/);
  r = await call('GET', '/netmap/impact/:id', { role: 'analyst', params: { id: 'nope' } }); assert.equal(r.status, 404);
  r = await call('GET', '/netmap/path', { role: 'analyst', query: { from: 'fw-syn', to: 'nb:sw-hidden' } }); assert.equal(r.status, 200);
  assert.deepEqual(r.body.hops.map((h) => h.to), ['CORE-SYN', 'ACC-A-SYN', 'SW-HIDDEN.as.local']); assert.equal(r.body.hops[1].from_port, 'Te1/1/1'); assert.equal(r.body.healthy, true);
  r = await call('GET', '/netmap/path', { role: 'analyst', query: { from: 'fw-syn', to: 'acc-b' } }); assert.equal(r.body.healthy, false); assert.ok(r.body.problems.some((p) => /down/.test(p)));
  r = await call('GET', '/netmap/path', { role: 'analyst', query: { from: 'fw-syn', to: 'lonely' } }); assert.equal(r.body.found, false);
  r = await call('GET', '/netmap/path', { role: 'analyst', query: { from: 'fw-syn' } }); assert.equal(r.status, 400); assert.match(r.error, /to is required/);
});

test('layout and snapshot: operator only, validated, audited; changes since the last snapshot', async () => {
  const { call, audits, reads, at, now } = await setup();
  assert.equal((await call('POST', '/netmap/layout', { role: 'analyst', body: { positions: [{ id: 'core-syn', x: 10, y: 10 }] } })).status, 403);
  let r = await call('POST', '/netmap/layout', { role: 'operator', body: { positions: [{ id: 'core-syn', x: -5, y: 10 }] } }); assert.equal(r.status, 400); assert.match(r.error, /positions\[0\]\.x/);
  r = await call('POST', '/netmap/layout', { role: 'operator', body: { positions: [{ id: 'ghost', x: 5, y: 10 }] } }); assert.equal(r.status, 400); assert.match(r.error, /ghost is not on the map/);
  r = await call('POST', '/netmap/layout', { role: 'operator', body: {} }); assert.equal(r.status, 400); assert.match(r.error, /positions is required/);
  r = await call('POST', '/netmap/layout', { role: 'operator', body: { positions: [{ id: 'core-syn', x: 400.4, y: 120 }], admin: true } }); assert.equal(r.status, 200); assert.equal(r.body.saved, 1);
  assert.deepEqual((await call('GET', '/netmap')).body.nodes.find((n) => n.id === 'core-syn').pos, { x: 400, y: 120 });
  assert.ok(audits.some((a) => a.a === 'netops.netmap.layout' && a.user === 'nora.syn' && a.d.moved[0] === 'core-syn'));
  r = await call('POST', '/netmap/layout/reset', { role: 'operator' }); assert.equal(r.body.cleared, 1); assert.ok(audits.some((a) => a.a === 'netops.netmap.layout_reset'));
  // changes
  assert.equal((await call('POST', '/netmap/snapshot', { role: 'analyst' })).status, 403);
  r = await call('POST', '/netmap/snapshot', { role: 'operator' }); assert.equal(r.status, 200); assert.ok(r.body.links >= 4);
  assert.ok(audits.some((a) => a.a === 'netops.netmap.snapshot' && a.d.links === r.body.links));
  assert.deepEqual((await call('GET', '/netmap')).body.changes.items, [], 'nothing changed since the snapshot');
  at(now() + 3600000);
  const a = reads.get('acc-a'); reads.put(Object.assign({}, a, { neighbours: a.neighbours.filter((n) => !/SW-HIDDEN/.test(n.name)) }));
  const ch = (await call('GET', '/netmap')).body.changes.items;
  assert.ok(ch.some((c) => c.kind === 'link-removed' && /SW-HIDDEN|sw-hidden/.test(c.what)) && ch.some((c) => c.kind === 'device-gone'));
});

test('an empty network: no reads, no links - honest, nothing invented', async () => {
  const { call, reads } = await setup();
  for (const id of ['core-syn', 'acc-a', 'acc-b']) reads.remove(id);
  const V = (await call('GET', '/netmap', { role: 'analyst' })).body;
  assert.equal(V.links.length, 0); assert.equal(V.summary.placed, 0); assert.equal(V.roots.basis, 'none');
  assert.equal(V.not_placed.length, 5); assert.ok(V.not_placed.some((x) => /not read yet on the Switch Port Map/.test(x.why)));
  assert.ok(!V.findings.some((f) => f.kind === 'single-point'));
  const r = await call('GET', '/netmap/impact/:id', { role: 'analyst', params: { id: 'core-syn' } }); assert.match(r.body.note, /no link on the map yet/);
});
