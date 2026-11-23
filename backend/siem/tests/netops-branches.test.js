// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Branch Connectivity (engine/netops/branchnet.js) over the real route map and a SYNTHETIC network (DC, DR, three branches):
// health per site (ok / backup / down / partial / not measured), path to the DC and the DR site, resilience design gaps
// (single path, one ISP, one edge device, no DR route), 5-minute history -> availability, outages, MTTR, failovers, the ISP
// scorecard against the SLA target, ranked actions, the ISP ticket draft (analyst, audited, nothing sent), the SLA setting
// (admin, validated, audited), the site detail, and the empty map saying what to do.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const B = require('../engine/netops/branchnet');

const DEVS = [
  { id: 'pa-dc', name: 'PA-DC-SYN', vendor: 'paloalto', ip: '10.0.0.1', site: 'DC', role: 'firewall' },
  { id: 'fw-dr', name: 'FW-DR-SYN', vendor: 'fortigate', ip: '10.9.0.1', site: 'DR', role: 'firewall' },
  { id: 'fgt-jed', name: 'FGT-JED-SYN', vendor: 'fortigate', ip: '10.2.0.1', site: 'Jeddah', role: 'firewall' },
  { id: 'fgt-dmm', name: 'FGT-DMM-SYN', vendor: 'fortigate', ip: '10.3.0.1', site: 'Dammam', role: 'firewall' },
  { id: 'fgt-abh', name: 'FGT-ABH-SYN', vendor: 'fortigate', ip: '10.4.0.1', site: 'Abha', role: 'firewall' },
];
const MAP = {
  sites: [{ id: 'dc', name: 'Riyadh DC', kind: 'dc' }, { id: 'dr', name: 'DR Site', kind: 'dr' }, { id: 'jed', name: 'Jeddah Branch', kind: 'branch', city: 'Jeddah' },
    { id: 'dmm', name: 'Dammam Branch', kind: 'branch' }, { id: 'abh', name: 'Abha Branch', kind: 'branch' }],
  nodes: [{ id: 'pa', label: 'PA-DC', kind: 'edge-firewall', site: 'dc', device: 'pa-dc' }, { id: 'drfw', label: 'FW-DR', kind: 'firewall', site: 'dr', device: 'fw-dr' },
    { id: 'fjed', label: 'FGT-JED', kind: 'firewall', site: 'jed', device: 'fgt-jed' }, { id: 'fdmm', label: 'FGT-DMM', kind: 'firewall', site: 'dmm', device: 'fgt-dmm' },
    { id: 'fabh', label: 'FGT-ABH', kind: 'firewall', site: 'abh', device: 'fgt-abh' }],
  links: [{ id: 'dc-dr', a: 'drfw', b: 'pa', kind: 'ipsec', tunnel: 'to-dc' },
    { id: 'jed-a', a: 'fjed', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'STC (synthetic)', circuit: 'CIR-SYN-J1', capacity_mbps: 50 },
    { id: 'jed-b', a: 'fjed', b: 'pa', kind: 'ipsec', tunnel: 'dc-b', isp: 'Mobily (synthetic)', circuit: 'CIR-SYN-J2' },
    { id: 'jed-dr', a: 'fjed', b: 'drfw', kind: 'ipsec', tunnel: 'dr' },
    { id: 'dmm-a', a: 'fdmm', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'STC (synthetic)', circuit: 'CIR-SYN-D1' },
    { id: 'dmm-b', a: 'fdmm', b: 'pa', kind: 'ipsec', tunnel: 'dc-b', isp: 'STC (synthetic)', circuit: 'CIR-SYN-D2' },
    { id: 'dmm-dr', a: 'fdmm', b: 'drfw', kind: 'ipsec', tunnel: 'dr' },
    { id: 'abh-a', a: 'fabh', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'Zain (synthetic)', circuit: 'CIR-SYN-A1' }],
};
const up = (tunnels) => ({ at: 1, ok: true, sources: ['ping', 'api'], errors: [], reach: { sent: 5, received: 5, rtt_avg_ms: 4 }, system: { cpu_pct: 20, mem_pct: 40 }, tunnels: (tunnels || []).map(([name, status]) => ({ name, status: status || 'up' })) });
const down = () => ({ at: 1, ok: false, sources: ['ping'], errors: [], reach: { sent: 5, received: 0 } });
const healthy = () => ({ 'pa-dc': up(), 'fw-dr': up([['to-dc']]), 'fgt-jed': up([['dc-a'], ['dc-b'], ['dr']]), 'fgt-dmm': up([['dc-a'], ['dc-b'], ['dr']]), 'fgt-abh': up([['dc-a']]) });

async function setup() {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-br-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const snaps = {}; let clock = Date.parse('2026-11-05T07:00:00Z');
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, now: () => clock });
  for (const d of DEVS) N.inventory.put(d, 'test');
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, params = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query: {}, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { out.status = c; out.error = msg; } };
    try { const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.code || e.status || 500; out.error = e.message; }
    return out;
  }
  return { N, BR: N.branches, RM: N.routemap, snaps, audits, call, tick: (ms) => { clock += ms; }, now: () => clock };
}
const site = (v, id) => v.branches.find((b) => b.id === id);

test('health, path to DC / DR and resilience design over the live route map', async () => {
  const { RM, snaps, call } = await setup();
  let v = (await call('GET', '/branches')).body;
  assert.equal(v.configured, false); assert.match(v.reason, /WAN \/ LAN Route Map/, 'an empty map says what to do');
  RM.save(MAP, 'admin.syn'); Object.assign(snaps, healthy());
  v = (await call('GET', '/branches')).body;
  assert.equal(v.configured, true); assert.deepEqual(v.dc_sites, ['Riyadh DC']); assert.deepEqual(v.dr_sites, ['DR Site']);
  const jed = site(v, 'jed');
  assert.equal(jed.health, 'ok', jed.why); assert.equal(jed.dc, 'yes'); assert.equal(jed.dr, 'yes'); assert.equal(jed.wan_total, 3); assert.equal(jed.wan_up, 3);
  assert.deepEqual(jed.design.map((d) => d.kind), ['single-edge'], 'two ISPs, but every path ends on one firewall');
  assert.deepEqual(site(v, 'dmm').design.map((d) => d.kind).sort(), ['same-isp', 'single-edge']);
  const abh = site(v, 'abh');
  assert.equal(abh.health, 'partial', 'reaches the DC, not the DR site'); assert.equal(abh.dr, 'no');
  assert.deepEqual(abh.design.map((d) => d.kind).sort(), ['no-dr-route', 'single-path']);
  assert.equal(site(v, 'dc').dc, 'self');
  assert.equal(v.actions[0].filter, 'partial');
  assert.ok(v.actions.some((a) => a.filter === 'design'));

  // Jeddah loses its STC tunnel: still in through Mobily = backup; Dammam's firewall dies = down
  snaps['fgt-jed'] = up([['dc-a', 'down'], ['dc-b'], ['dr']]); snaps['fgt-dmm'] = down();
  v = (await call('GET', '/branches')).body;
  assert.equal(site(v, 'jed').health, 'backup'); assert.match(site(v, 'jed').why, /STC \(synthetic\) ipsec to PA-DC \(CIR-SYN-J1\) down/);
  const dmm = site(v, 'dmm'); assert.equal(dmm.health, 'down'); assert.equal(dmm.dc, 'no'); assert.match(dmm.why, /cannot reach the data centre/);
  assert.equal(v.branches[0].id, 'dmm', 'worst site first');
  assert.deepEqual(v.actions.slice(0, 3).map((a) => a.filter), ['down', 'partial', 'backup']);
  assert.equal(v.kpis.down, 1); assert.equal(v.kpis.backup, 1); assert.equal(v.kpis.partial, 1);
  assert.ok(dmm.incidents.some((x) => x.kind === 'node-down'), 'the route-map incident is on the site');

  // a link nobody measures is never "up"
  snaps['fgt-abh'] = up([]); v = (await call('GET', '/branches')).body;
  assert.notEqual(site(v, 'abh').health, 'ok'); assert.equal(site(v, 'abh').wan[0].state, 'unmeasured');
});

test('history: availability, outages, MTTR, failovers, ISP scorecard against the SLA target, the site detail', async () => {
  const { BR, RM, snaps, call, tick } = await setup();
  RM.save(MAP, 'admin.syn');
  for (let i = 0; i < 20; i++) {
    Object.assign(snaps, healthy());
    if (i >= 10 && i < 13) snaps['fgt-dmm'] = down();                          // Dammam dark for 15 minutes
    if (i >= 5 && i < 8) snaps['fgt-jed'] = up([['dc-a', 'down'], ['dc-b'], ['dr']]);   // Jeddah on Mobily for 15 minutes
    BR.record(); tick(300000);
  }
  assert.equal(BR.record(), 0 + BR.view().branches.length, 'records every site');
  const v = (await call('GET', '/branches')).body, dmm = site(v, 'dmm').reliability, jed = site(v, 'jed').reliability;
  assert.equal(dmm.outages, 1); assert.equal(dmm.mttr_min, 15); assert.equal(dmm.availability, 85.7, '18 of 21 samples reached the DC');
  assert.equal(jed.outages, 0); assert.equal(jed.failovers, 1); assert.ok(jed.backup_pct > 0);
  const stc = v.isps.find((x) => x.isp === 'STC (synthetic)');
  assert.equal(stc.links, 3); assert.equal(stc.outages, 3, 'Jeddah STC once, both Dammam circuits once'); assert.equal(stc.below_sla, true);
  assert.equal(v.isps[0].isp, 'STC (synthetic)', 'the ISP below the target first');
  assert.equal(v.isps.find((x) => x.isp === 'Zain (synthetic)').below_sla, false);
  assert.ok(v.actions.some((a) => a.filter === 'isp'));
  const d = (await call('GET', '/branches/:id', { params: { id: 'dmm' } })).body;
  assert.ok(d.strip.length >= 1 && d.strip.some((h) => h.worst === 'down')); assert.equal(d.isps[0].isp, 'STC (synthetic)');
  assert.equal((await call('GET', '/branches/:id', { params: { id: 'nowhere' } })).status, 404);
  assert.equal((await call('GET', '/branches/:id', { params: { id: '../x' } })).status, 400);
  // reliability helpers on their own
  assert.equal(B.reliability([{ t: 0, h: 'ok', dc: 1 }]).availability, null, 'fewer than 12 samples: no availability claimed');
  const fl = Array.from({ length: 24 }, (_, i) => ({ t: i, h: i % 2 ? 'backup' : 'ok', dc: 1 }));
  assert.equal(B.reliability(fl).flapping, true);
  assert.equal(B.latencyAnomaly(Array.from({ length: 40 }, (_, i) => ({ lat: 20 + (i % 3) })), 80).unusual, true);
  assert.match(B.latencyAnomaly([{ lat: 20 }], 80).learning, /needs 36 samples/);
});

test('ISP ticket draft (analyst, audited, nothing sent) and the SLA target (admin, validated, audited)', async () => {
  const { RM, snaps, call, audits } = await setup();
  RM.save(MAP, 'admin.syn'); Object.assign(snaps, healthy()); snaps['fgt-jed'] = up([['dc-a', 'down'], ['dc-b'], ['dr']]);
  assert.equal((await call('POST', '/branches/isp-draft', { body: { link: 'jed-a' } })).status, 403, 'viewer refused');
  let r = await call('POST', '/branches/isp-draft', { role: 'analyst', body: {} }); assert.equal(r.status, 400); assert.match(r.error, /link is required/);
  r = await call('POST', '/branches/isp-draft', { role: 'analyst', body: { link: 'Bad Id!' } }); assert.equal(r.status, 400); assert.match(r.error, /link is not a link id/);
  r = await call('POST', '/branches/isp-draft', { role: 'analyst', body: { link: 'ghost' } }); assert.equal(r.status, 404);
  r = await call('POST', '/branches/isp-draft', { role: 'analyst', user: 'ali.syn', body: { link: 'jed-a', extra: 'dropped' } });
  assert.equal(r.status, 200); assert.match(r.body.text, /To: STC \(synthetic\)/); assert.match(r.body.text, /Circuit: CIR-SYN-J1 · ipsec · 50 Mb\/s contracted/);
  assert.match(r.body.text, /State now: down/); assert.match(r.body.text, /Raised by ali\.syn/); assert.match(r.body.note, /nothing was sent/);
  assert.deepEqual(audits.filter((a) => a.a === 'netops.branches.isp_draft').map((a) => [a.t, a.user, a.d.site]), [['jed-a', 'ali.syn', 'Jeddah Branch']]);

  assert.equal((await call('POST', '/branches/config', { role: 'operator', body: { sla_target_pct: 99 } })).status, 403);
  r = await call('POST', '/branches/config', { role: 'admin', body: { sla_target_pct: 101 } }); assert.equal(r.status, 400); assert.match(r.error, /sla_target_pct must be at most 100/);
  r = await call('POST', '/branches/config', { role: 'admin', body: {} }); assert.equal(r.status, 400); assert.match(r.error, /sla_target_pct is required/);
  r = await call('POST', '/branches/config', { role: 'admin', user: 'admin.syn', body: { sla_target_pct: 99, other: 1 } });
  assert.equal(r.status, 200); assert.equal(r.body.sla_target_pct, 99); assert.equal(r.body.other, undefined);
  assert.equal((await call('GET', '/branches')).body.sla_target_pct, 99);
  assert.deepEqual(audits.filter((a) => a.a === 'netops.branches.config').map((a) => a.d), [{ from: 99.5, to: 99 }]);
});
