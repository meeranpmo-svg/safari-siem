// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IP Address Management (engine/ipam.js) over the REAL asset register and discovery collections with SYNTHETIC addresses: subnets
// validated (CIDR, gateway / DHCP inside, no overlap), utilisation without double counting, next free address skips gateway /
// DHCP / reserved / used, findings (conflict, duplicate, stale, unknown, unplanned network, nearly full, reservation taken), the
// growth forecast from daily snapshots, reservations refused when used / in DHCP / outside the plan, roles, validation, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parseCidr } = require('../engine/ipam');

const DAY = 86400000, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:net', role: 'operator' };
async function setup(t, now) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  const st = e.app.store, seen = new Date(Date.now() - DAY).toISOString(), old = new Date(Date.now() - 60 * DAY).toISOString();
  st.collection('assets').put({ id: 'A1', name: 'core-sw-syn', type: 'switch', status: 'active', mgmt_ip: '10.20.5.2' });
  st.collection('assets').put({ id: 'A2', name: 'printer-syn', type: 'printer', status: 'active', mgmt_ip: '10.20.5.9' });
  st.collection('assets').put({ id: 'A3', name: 'old-ups-syn', type: 'ups', status: 'active', mgmt_ip: '10.20.5.10' });
  st.collection('assets').put({ id: 'A4', name: 'twin-syn', type: 'server', status: 'active', mgmt_ip: '10.20.5.10' });
  st.collection('disc_devices').put({ id: 'd1', status: 'new', ips: ['10.20.5.2'], macs: ['aa:aa:aa:aa:aa:01'], hostname: 'core-sw-syn', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd2', status: 'new', ips: ['10.20.5.20'], macs: ['aa:aa:aa:aa:aa:02'], hostname: 'pc-a', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd3', status: 'new', ips: ['10.20.5.20'], macs: ['aa:aa:aa:aa:aa:03'], hostname: 'pc-b', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd4', status: 'new', ips: ['10.20.5.10'], macs: ['aa:aa:aa:aa:aa:04'], hostname: 'old-ups-syn', last_seen: old });
  st.collection('disc_devices').put({ id: 'd5', status: 'new', ips: ['10.99.1.7', '10.99.1.8'], macs: ['aa:aa:aa:aa:aa:05'], hostname: 'cam-syn', last_seen: seen });
  const post = (p, b, who = OP) => e.req('POST', p, Object.assign({ body: b }, who));
  return { e, post };
}

test('parseCidr: normalised network, usable size, refused shapes', () => {
  assert.deepEqual([parseCidr('10.20.5.77/24').cidr, parseCidr('10.20.5.0/24').usable], ['10.20.5.0/24', 254]);
  for (const bad of ['10.20.5.0', '10.20.5.0/31', '300.1.1.0/24', '10.0.0.0/7', 'x']) assert.equal(parseCidr(bad), null, bad);
});

test('subnets validated; utilisation, next free, findings, proposals; roles; audit', async (t) => {
  const { e, post } = await setup(t);
  let r = await post('/ipam/subnets', { cidr: '10.20.5.0/24', name: 'HQ floor 5 (synthetic)', site: 'HQ', vlan: 105, gateway: '10.20.5.1', dhcp_start: '10.20.5.100', dhcp_end: '10.20.5.199' });
  assert.equal(r.status, 200, r.raw); const SN = r.json.id;
  for (const [b, re] of [[{ cidr: '10.20.5.0/31', name: 'x' }, /cidr/], [{ cidr: '10.21.0.0/24', name: 'x', gateway: '10.22.0.1' }, /gateway must be an address inside/],
    [{ cidr: '10.21.0.0/24', name: 'x', dhcp_start: '10.21.0.10' }, /go together/], [{ cidr: '10.21.0.0/24', name: 'x', gateway: '10.21.0.50', dhcp_start: '10.21.0.10', dhcp_end: '10.21.0.90' }, /outside the DHCP range/],
    [{ name: 'x' }, /cidr/]]) { const x = await post('/ipam/subnets', b); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.json.error, re); }
  r = await post('/ipam/subnets', { cidr: '10.20.4.0/23', name: 'overlap' }); assert.equal(r.status, 409); assert.match(r.json.error, /overlaps 10.20.5.0\/24/);
  const v = (await e.req('GET', '/ipam', OP)).json, s = v.subnets.find((x) => x.id === SN);
  assert.equal(s.usable, 254); assert.equal(s.used, 5, 'gateway + .2 .9 .10 .20 - .10 counted once though two assets and a device use it');
  assert.equal(s.next_free, '10.20.5.3', 'skips network, gateway, .2'); assert.equal(s.dhcp_size, 100);
  const kinds = v.findings.map((f) => f.kind);
  assert.ok(v.findings.some((f) => f.kind === 'conflict' && /10\.20\.5\.20 is used by 2 devices/.test(f.title)), 'conflict');
  assert.ok(v.findings.some((f) => f.kind === 'duplicate' && /10\.20\.5\.10/.test(f.title)), 'two assets on one address');
  assert.ok(v.findings.some((f) => f.kind === 'stale' && /printer-syn/.test(f.title) && /never saw it/.test(f.title)), 'asset never seen by discovery');
  assert.ok(v.findings.some((f) => f.kind === 'stale' && /not seen for 60 days/.test(f.title)), 'asset not seen for 60 days');
  assert.ok(kinds.includes('unknown') && kinds.includes('unplanned'), kinds.join(','));
  assert.deepEqual(v.proposals.map((p) => [p.cidr, p.addresses]), [['10.99.1.0/24', 2]]);
  assert.equal(v.findings[0].severity, 'high', 'ranked by severity');
  const vv = (await e.req('GET', '/ipam', VIEW)).json; assert.equal(vv.addresses, undefined, 'a viewer sees counts, not addresses'); assert.equal(vv.kpis.conflicts, 1);
  assert.equal((await post('/ipam/subnets', { cidr: '10.30.0.0/24', name: 'x' }, VIEW)).status, 403);
  assert.equal((await post('/ipam/subnets', { cidr: '10.30.0.0/24', name: 'x' }, BOT)).status, 403, 'an AI identity cannot change the plan');
  assert.equal((await post('/ipam/ask', { question: 'what first?' }, VIEW)).status, 403);
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'ipam.subnet.add' && x.by === OP.user));
});

test('reservations: free address only, not DHCP / gateway / used / outside the plan; release needs a reason', async (t) => {
  const { e, post } = await setup(t);
  const SN = (await post('/ipam/subnets', { cidr: '10.20.5.0/24', name: 'HQ (synthetic)', gateway: '10.20.5.1', dhcp_start: '10.20.5.100', dhcp_end: '10.20.5.199' })).json.id;
  for (const [ip, re] of [['10.20.5.1', /gateway/], ['10.20.5.150', /DHCP range/], ['10.20.5.20', /in use/], ['10.77.0.5', /no registered subnet/], ['10.20.5', /IPv4/]]) {
    const r = await post('/ipam/reserve', { ip, name: 'x' }); assert.ok([400, 409].includes(r.status), ip); assert.match(r.json.error, re);
  }
  let r = await post('/ipam/reserve', { ip: '10.20.5.3', name: 'new-printer-syn', purpose: 'Floor 5 printer', until: '2026-01-31' }); assert.equal(r.status, 200, r.raw);
  const id = r.json.id;
  assert.equal((await post('/ipam/reserve', { ip: '10.20.5.3', name: 'again' })).status, 409, 'already reserved');
  let v = (await e.req('GET', '/ipam', OP)).json; assert.equal(v.subnets.find((x) => x.id === SN).next_free, '10.20.5.4', 'a reservation is not offered again');
  assert.ok(v.findings.some((f) => f.kind === 'expired' && /10\.20\.5\.3/.test(f.title)), 'reservation past its date');
  e.app.store.collection('disc_devices').put({ id: 'd9', status: 'new', ips: ['10.20.5.3'], macs: ['aa:aa:aa:aa:aa:09'], hostname: 'someone-else', last_seen: new Date().toISOString() });
  v = (await e.req('GET', '/ipam', OP)).json; assert.ok(v.findings.some((f) => f.kind === 'reservation' && /reserved for new-printer-syn but seen as someone-else/.test(f.title)));
  assert.equal((await post('/ipam/reservations/' + id + '/release', {})).status, 400, 'a reason is required');
  assert.equal((await post('/ipam/reservations/' + id + '/release', { reason: 'printer moved (synthetic)' })).status, 200);
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'ipam.release' && x.detail.reason));
});

test('learning: growth per subnet and days until full from daily snapshots', async (t) => {
  let clock = Date.now() - 10 * DAY;
  const { e, post } = await setup(t, () => clock);
  const SN = (await post('/ipam/subnets', { cidr: '10.20.5.0/24', name: 'HQ (synthetic)' })).json.id;
  const D = e.app.store.collection('disc_devices');
  for (let d = 0; d < 8; d++) { for (let k = 0; k < 4; k++) D.put({ id: 'g' + d + k, status: 'new', ips: ['10.20.5.' + (30 + d * 4 + k)], macs: ['bb:00:00:00:' + d + ':' + k], last_seen: new Date(clock).toISOString() }); assert.ok(await e.app.addons.ipam.snapshot()); clock += DAY; }
  const s = (await e.req('GET', '/ipam', OP)).json.subnets.find((x) => x.id === SN);
  assert.ok(Math.abs(s.learning.growth_per_day - 4) < 0.5, 'four new addresses a day: ' + s.learning.growth_per_day);
  assert.ok(s.learning.days_to_full > 40 && s.learning.days_to_full < 60, 'about ' + s.learning.days_to_full + ' days');
});
