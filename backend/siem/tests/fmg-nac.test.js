// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NAC from FortiGate device detection: learning before judging, new endpoint, identity change, two sites within 30 min (clone),
// rare at site, unauthorised after 7 days, random MAC said not scored; four-eyes authorise / quarantine (proposer never approves,
// an AI identity never approves, a quarantine is carried out by a person and marked done); roles, validation, audit.
// MACs, sites and people are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const NAC = require('../engine/netops/fmg-nac');

const NOW = Date.parse('2026-11-25T12:00:00Z'), H = 3600000, D = 24 * H, iso = (t) => new Date(t).toISOString();
const ep = (mac, o) => Object.assign({ id: mac, mac, ip: '10.7.0.1', host: 'PC', os: 'Windows', site: 'Site 7', fortigate: 'FGT-SITE-07', first_seen: iso(NOW - 30 * D), last_seen: iso(NOW - H), idents: ['Windows|PC'], sightings: [{ fortigate: 'FGT-SITE-07', site: 'Site 7', at: iso(NOW - H) }] }, o);

test('assessment: each reason itemised, learning first', () => {
  const site = Array.from({ length: 40 }, (_, i) => ep('aa:00:00:00:00:' + String(i).padStart(2, '0')));
  const list = site.concat([
    ep('aa:00:00:00:01:01', { first_seen: iso(NOW - 3 * H) }),
    ep('aa:00:00:00:01:02', { idents: ['Windows|PC-1', 'Linux|kali'] }),
    ep('aa:00:00:00:01:03', { sightings: [{ fortigate: 'FGT-SITE-07', at: iso(NOW - H) }, { fortigate: 'FGT-SITE-08', at: iso(NOW - H + 10 * 60000) }] }),
    ep('aa:00:00:00:01:04', { os: 'Linux' }),
    ep('a6:00:00:00:01:05', {})]);
  const r = NAC.assess(list, [{ mac: 'aa:00:00:00:00:00', action: 'authorise', status: 'approved' }], NOW), by = Object.fromEntries(r.map((e) => [e.mac, e]));
  const codes = (m) => by[m].reasons.map((x) => x.code).sort();
  assert.deepEqual(codes('aa:00:00:00:01:01'), ['new']);
  assert.deepEqual(codes('aa:00:00:00:01:02'), ['identity', 'unauthorised']);
  assert.deepEqual(codes('aa:00:00:00:01:03'), ['two-sites', 'unauthorised']);
  assert.deepEqual(codes('aa:00:00:00:01:04'), ['rare', 'unauthorised']);
  assert.deepEqual(codes('aa:00:00:00:00:00'), [], 'authorised');
  assert.ok(by['a6:00:00:00:01:05'].notes[0].includes('random') && by['a6:00:00:00:01:05'].risk === 10, 'random MAC said, not scored');
  assert.equal(r[0].risk, 45, 'ranked by risk');
  // learning: a fleet with under 7 days of history does not call anything new
  const young = NAC.assess([ep('bb:00:00:00:00:01', { first_seen: iso(NOW - 2 * D) }), ep('bb:00:00:00:00:02', { first_seen: iso(NOW - 2 * H) })], [], NOW);
  assert.ok(young.every((e) => !e.reasons.some((x) => x.code === 'new')));
});

test('routes: roles and the refused case, validation, four-eyes decisions, quarantine done by a person, audit', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nac-')) });
  state.collection('fmg_endpoints').put(ep('aa:00:00:00:01:02', { idents: ['Windows|PC-1', 'Linux|kali'] }));
  const R = {}, audits = [], RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  NAC.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, state, log: { error() {} }, now: () => NOW, fmgApi: {} });
  const call = async (m, p, b, role = 'operator', user) => {
    const o = {}, u = user || role + '.syn', params = {}; let key = '/api/soc' + p; const mm = p.match(/^\/nac\/decisions\/([^/]+)\/(\w+)$/); if (mm) { params.id = mm[1]; key = '/api/soc/nac/decisions/:id/' + mm[2]; }
    const ctx = { role, user: u, body: b, params, audit: (a, t, d) => audits.push({ a, t, d, by: u }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' ' + key](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  assert.equal((await call('GET', '/nac/endpoints', undefined, 'viewer')).s, 403, 'it names devices and users');
  const v = (await call('GET', '/nac/endpoints', undefined, 'analyst')).b; assert.equal(v.total, 1); assert.equal(v.endpoints[0].risk, 40); assert.equal(v.connected, true);
  assert.equal((await call('POST', '/nac/decisions', { mac: 'aa:00:00:00:01:02', action: 'quarantine', reason: 'identity change seen (synthetic)' }, 'analyst')).s, 403);
  let r = await call('POST', '/nac/decisions', { mac: 'zz', action: 'quarantine', reason: 'identity change seen' }); assert.equal(r.s, 400); assert.match(r.e, /mac/);
  r = await call('POST', '/nac/decisions', { mac: 'aa:00:00:00:09:09', action: 'quarantine', reason: 'identity change seen' }); assert.equal(r.s, 404);
  r = await call('POST', '/nac/decisions', { mac: 'aa:00:00:00:01:02', action: 'authorise', reason: 'the site printer (synthetic)' }); assert.equal(r.s, 400); assert.match(r.e, /owner/);
  r = await call('POST', '/nac/decisions', { mac: 'AA:00:00:00:01:02', action: 'quarantine', reason: 'identity change seen (synthetic)' }, 'operator', 'op.syn'); assert.equal(r.s, 200, r.e); const id = r.b.id;
  assert.equal((await call('POST', '/nac/decisions', { mac: 'aa:00:00:00:01:02', action: 'quarantine', reason: 'identity change seen (synthetic)' }, 'operator', 'op.syn')).s, 409, 'one waiting at a time');
  assert.equal((await call('POST', `/nac/decisions/${id}/done`, { note: 'x' }, 'operator')).s, 409, 'not before approval');
  assert.equal((await call('POST', `/nac/decisions/${id}/decide`, { decision: 'approved' }, 'admin', 'op.syn')).s, 403, 'proposer');
  r = await call('POST', `/nac/decisions/${id}/decide`, { decision: 'approved' }, 'admin', 'ai:network'); assert.equal(r.s, 403); assert.match(r.e, /only a person/);
  assert.equal((await call('POST', `/nac/decisions/${id}/decide`, { decision: 'approved' }, 'operator', 'op2.syn')).s, 403, 'no firewall approver scope');
  assert.equal((await call('POST', `/nac/decisions/${id}/decide`, { decision: 'approved' }, 'admin', 'sec.syn')).s, 200);
  assert.equal((await call('POST', `/nac/decisions/${id}/done`, { note: 'MAC added to the quarantine group in FortiManager (synthetic)' }, 'operator', 'op.syn')).s, 200);
  assert.equal((await call('GET', '/nac/endpoints', undefined, 'analyst')).b.endpoints[0].quarantine, 'done');
  for (const a of ['nac.decision.propose', 'nac.decision.approve', 'nac.decision.done']) assert.ok(audits.some((x) => x.a === a && x.t === id), 'audited: ' + a);
});

test('switch side: port map MACs join the FortiGate endpoints, shared port, flapping, switch-only devices, H3C quarantine steps', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nacsw-')) });
  state.collection('fmg_endpoints').put(ep('aa:00:00:00:02:01', { host: 'PC-RECEPTION' }));
  state.collection('portmap_reads').put({ id: 'sw-2f', at: NOW - H, vendor: 'h3c-comware', ports: [{ port: 'GE1/0/1', vlan: '10', name: 'PC-RECEPTION' }, { port: 'GE1/0/4', vlan: '20', name: 'PRINTER' }], trunks: ['xge1/0/49'], arp: [{ ip: '10.7.20.30', mac: 'aa0000000204' }] });
  const M = (id, port, o) => state.collection('portmap_macs').put(Object.assign({ id, device: 'sw-2f', port, first: NOW - 20 * D, last: NOW - H, moves: [] }, o));
  M('aa0000000201', 'ge1/0/1'); M('aa0000000202', 'ge1/0/1');                                    // two MACs on one access port
  M('aa0000000204', 'ge1/0/4', { moves: [{ at: NOW - 3 * H }, { at: NOW - 2 * H }, { at: NOW - H }] });  // flapping
  M('aa0000000209', 'xge1/0/49');                                                                 // trunk: not an endpoint
  const R = {};
  NAC.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: { netops: { nac: { quarantine_vlan: 999 } } }, state, log: { error() {} }, now: () => NOW, netopsInstance: { inventory: { get: (id) => (id === 'sw-2f' ? { name: 'SW-2F-SYN' } : null) } } });
  const o = {}; const ctx = { role: 'analyst', user: 'ana.syn', params: {}, ok(x) { o.b = x; }, fail(c, m) { o.s = c; o.e = m; }, need: () => true, audit() {} };
  const v = (await R['GET /api/soc/nac/endpoints'](ctx)) || o.b;
  assert.deepEqual(v.sources, { fortigate: 1, switch_ports: 4, switches: 1 }); assert.equal(v.connected, true);
  const by = Object.fromEntries(v.endpoints.map((e) => [e.mac, e]));
  assert.ok(!by['aa:00:00:00:02:09'], 'a MAC on the trunk is not an endpoint');
  const pc = by['aa:00:00:00:02:01']; assert.equal(pc.host, 'PC-RECEPTION'); assert.deepEqual([pc.sw.switch, pc.sw.port, pc.sw.vlan, pc.sw.shared], ['SW-2F-SYN', 'GE1/0/1', '10', 2], 'joined with its switch port');
  assert.ok(pc.reasons.some((r) => r.code === 'shared-port'));
  const silent = by['aa:00:00:00:02:02']; assert.ok(silent && silent.notes.some((n) => /never seen by a FortiGate/.test(n)), 'a device only the switch sees is listed and said');
  const pr = by['aa:00:00:00:02:04']; assert.equal(pr.ip, '10.7.20.30', 'IP from the switch ARP table'); assert.ok(pr.reasons.some((r) => r.code === 'flapping'));
  assert.deepEqual(pr.quarantine_steps.lines, ['system-view', 'interface GE1/0/4', 'port access vlan 999', 'quit', 'save']); assert.equal(pr.quarantine_steps.vendor, 'H3C Comware');
});
