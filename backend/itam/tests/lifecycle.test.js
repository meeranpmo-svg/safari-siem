// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// End of life detection (OS builds, server OS, firmware) and isolation with second-person (CISO) approval.
const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, compile, createLifecycle } = require('../engine/lifecycle');

const NOW = Date.parse('2026-10-11T00:00:00Z'), R = compile();
const ev = (t) => evaluate(t, R, NOW);

test('lifecycle rules: Windows builds and editions, servers, Linux, ESXi, firmware', () => {
  assert.equal(ev('Windows 11 Pro 10.0 (22631)').status, 'eol');
  assert.equal(ev('Windows 11 Enterprise 10.0 (22631)').status, 'soon');
  assert.equal(ev('Windows 11 Pro 10.0 (26100)').status, 'soon');
  assert.equal(ev('Windows 11 Pro 10.0 (26200)').status, 'supported');
  assert.equal(ev('Windows 11 Pro 10.0 (26300)').status, 'unknown');
  assert.deepEqual([ev('Windows 10 Pro 10.0 (19045)').status, ev('Windows 10 Pro 10.0 (19045)').eol], ['eol', '2025-10-14']);
  assert.equal(ev('Windows 10 Enterprise LTSC 10.0 (17763)').status, 'supported');
  assert.equal(ev('Windows Server 2012 R2 Standard').product, 'Windows Server 2012 / 2012 R2');
  assert.equal(ev('Windows Server 2016 Datacenter').status, 'soon');
  assert.equal(ev('Windows Server 2022').status, 'supported');
  assert.equal(ev('CentOS Linux release 7.9.2009').status, 'eol');
  assert.equal(ev('VMware ESXi 7.0.3').status, 'eol');
  assert.equal(ev('FortiGate-100F v6.2.15,build1378').product, 'FortiOS 6.2');
  assert.equal(ev('Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE12').status, 'eol');
  assert.equal(ev('').status, 'unknown');
  const custom = compile([{ pattern: 'aruba.*16\\.0[0-8]', product: 'ArubaOS-Switch 16.08 or older', eol: '2024-01-01' }]);
  assert.equal(evaluate('Aruba JL256A 2930F ArubaOS 16.05', custom, NOW).status, 'eol');
});

function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; },
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })()) };
}
const store = () => fakeStore({ assets: [{ id: 'a1', name: 'OLD-SRV', type: 'server', os: 'Windows Server 2012 R2', mgmt_ip: '10.0.0.5', status: 'in_use' }, { id: 'a2', name: 'NEW', type: 'server', os: 'Windows Server 2022', mgmt_ip: '10.0.0.6', status: 'in_use' }],
  disc_devices: [{ id: 'd1', hostname: 'sw-old', type: 'switch', sys_descr: 'Cisco IOS Software, Version 12.2(55)SE', ip: '10.0.1.2', status: 'new' }] });
const adm = { user: 'siva', role: 'admin' }, ciso = { user: 'ciso', role: 'admin' };

test('isolation: request, requester cannot approve, CISO approves, FortiGate quarantine, release', async () => {
  const calls = [], audits = [];
  const L = createLifecycle({ store: store(), audit: (e) => audits.push(e), config: { discovery: { isolation: { approvers: ['CISO'], fortigate: { base_url: 'https://fw', token_file: '/x' } } } } }, { now: () => NOW, fortigate: async (p, b) => { calls.push([p, b]); return { status: 'success' }; } });
  const v = L.view({}); assert.deepEqual([v.summary.eol, v.summary.servers, v.items.length], [2, 1, 2]); assert.equal(v.isolation.method, 'fortigate');
  assert.throws(() => L.isolate({ key: 'asset:a1' }, adm), /reason/);
  const r = L.isolate({ key: 'asset:a1', reason: 'Windows Server 2012 R2 out of support' }, adm);
  assert.equal(r.state, 'pending'); assert.throws(() => L.isolate({ key: 'asset:a1', reason: 'again' }, adm), /already pending/);
  await assert.rejects(L.decide(r.id, { decision: 'approved' }, adm), /cannot approve/);
  await assert.rejects(L.decide(r.id, { decision: 'approved' }, { user: 'siburahim', role: 'admin' }), /only ciso/);
  const d = await L.decide(r.id, { decision: 'approved', comment: 'ok' }, ciso);
  assert.equal(d.state, 'isolated'); assert.deepEqual(calls[0], ['/api/v2/monitor/user/banned/add_users', { ip_addresses: ['10.0.0.5'], expiry: 0 }]);
  assert.equal(L.view({}).items.find((i) => i.key === 'asset:a1').isolation.state, 'isolated');
  const rel = await L.release(r.id, { reason: 'migrated to 2022' }, adm); assert.equal(rel.state, 'released'); assert.equal(calls[1][0], '/api/v2/monitor/user/banned/clear_users');
  assert.ok(audits.some((a) => a.action === 'lifecycle.isolate.approved'));
});

test('isolation: manual method shows steps and waits for "applied"; rejection; FortiGate failure', async () => {
  const L = createLifecycle({ store: store(), config: { discovery: {} } }, { now: () => NOW });
  const r = L.isolate({ key: 'disc:d1', reason: 'IOS 12.2' }, adm);
  const d = await L.decide(r.id, { decision: 'approved' }, ciso);
  assert.equal(d.state, 'approved'); assert.match(d.steps[0], /banned-ip add src4 10\.0\.1\.2/);
  assert.equal(L.applied(r.id, {}, adm).state, 'isolated');
  const r2 = L.isolate({ key: 'asset:a1', reason: 'x' }, adm); assert.equal((await L.decide(r2.id, { decision: 'rejected' }, ciso)).state, 'rejected');
  const F = createLifecycle({ store: store(), config: { discovery: { isolation: { fortigate: { base_url: 'https://fw', token_file: '/x' } } } } }, { now: () => NOW, fortigate: async () => { throw new Error('FortiGate HTTP 403'); } });
  const r3 = F.isolate({ key: 'asset:a1', reason: 'x' }, adm); const d3 = await F.decide(r3.id, { decision: 'approved' }, ciso);
  assert.equal(d3.state, 'failed'); assert.match(d3.error, /403/);
});

test('approvers set from the page override config; empty = any other admin; audited', async () => {
  const audits = [];
  const L = createLifecycle({ store: store(), audit: (e) => audits.push(e), config: { discovery: { isolation: { approvers: ['old'] } } } }, { now: () => NOW });
  assert.deepEqual(L.view({}).isolation.approvers, ['old']);
  assert.throws(() => L.setApprovers({ approvers: 'bad name!' }, adm), /user names/);
  assert.deepEqual(L.setApprovers({ approvers: 'CISO, deputy' }, adm).isolation.approvers, ['ciso', 'deputy']);
  const r = L.isolate({ key: 'asset:a1', reason: 'x' }, adm);
  await assert.rejects(L.decide(r.id, { decision: 'approved' }, { user: 'old', role: 'admin' }), /only ciso, deputy/);
  assert.equal((await L.decide(r.id, { decision: 'approved' }, { user: 'deputy', role: 'operator' })).state, 'approved');
  assert.deepEqual(L.setApprovers({ approvers: [] }, adm).isolation.approvers, ['any other administrator']);
  assert.ok(audits.some((a) => a.action === 'lifecycle.approvers'));
});

test('lifecycle covers everything with serial numbers: inventory, discovery, virtualization hosts, storage; isolation required', () => {
  const st = fakeStore({
    assets: [{ id: 'a1', name: 'OLD-SRV', type: 'server', os: 'Windows Server 2012 R2', mgmt_ip: '10.0.0.5', serial: 'cz1234', vendor: 'HPE', model: 'DL380 Gen9', status: 'in_use' },
      { id: 'a3', name: 'esx01', type: 'server', os: 'VMware ESXi 6.7.0', serial: 'SVC-TAG-01', status: 'in_use' }],
    disc_devices: [{ id: 'd1', hostname: 'sw-old', type: 'switch', sys_descr: 'Cisco IOS Software, Version 12.2(55)SE', ip: '10.0.1.2', serial: 'FOC1234X', status: 'new' }],
    virt_capacity: [{ id: 'vp_1', label: 'VC-RUH', hosts: [{ id: 'host-11', name: 'esx01', version: 'VMware ESXi 6.7.0 build-1', serial: 'SVC-TAG-01', model: 'PowerEdge R740', ip: '10.0.2.11' }, { id: 'host-12', name: 'esx02', version: 'VMware ESXi 6.7.0 build-1', serial: 'SVC-TAG-02', model: 'PowerEdge R740' }] }],
    storage_snapshots: [{ id: 'st1', system: { name: 'MSA-HQ', model: 'MSA 2060', version: 'IN210P003', serial: 'MSA-SN-9' }, controllers: [{ name: 'A', serial: 'CTRL-A-1', model: 'MSA 2060 SAS' }] }],
  });
  const L = createLifecycle({ store: st, config: { discovery: { lifecycle: { rules: [{ pattern: 'msa 2060', product: 'HPE MSA 2060 (test rule)', eol: null }] } } } }, { now: () => NOW });
  const v = L.view({}), by = (k) => v.items.find((i) => i.key === k);
  assert.equal(by('asset:a1').serial, 'CZ1234'); assert.equal(by('asset:a1').model, 'DL380 Gen9');
  assert.equal(by('asset:a1').isolation_required, true); assert.match(by('asset:a1').action, /isolate until upgraded/);
  assert.equal(by('disc:d1').serial, 'FOC1234X'); assert.equal(by('disc:d1').isolation_required, true);
  assert.ok(!v.items.some((i) => i.key === 'virt:vp_1:host-11'), 'the same serial as an inventory asset is listed once');
  const h2 = by('virt:vp_1:host-12'); assert.equal(h2.serial, 'SVC-TAG-02'); assert.equal(h2.status, 'eol');
  assert.equal(h2.isolation_required, false, 'a hypervisor is upgraded, not isolated'); assert.match(h2.action, /upgrade or replace/);
  assert.equal(by('storage:st1').serial, 'MSA-SN-9'); assert.equal(by('storage:st1:A').serial, 'CTRL-A-1');
  assert.equal(v.summary.isolation_required, 2, 'OLD-SRV and sw-old; esx01 runs ESXi: upgrade, not isolate'); assert.match(by('asset:a3').action, /upgrade or replace/);
});

test('risk exception: reasoned, owned, compensated, time-boxed, second person; replaces isolation required until it expires', () => {
  let t = NOW;
  const st = fakeStore({ assets: [{ id: 'a1', name: 'OLD-SRV', type: 'server', os: 'Windows Server 2012 R2', mgmt_ip: '10.0.0.5', serial: 'CZ1', status: 'in_use' }] });
  const audits = [], L = createLifecycle({ store: st, audit: (e) => audits.push(e), config: { discovery: { isolation: { approvers: ['ciso'] } } } }, { now: () => t });
  const base = { key: 'asset:a1', reason: 'runs the legacy payroll until March', compensating: 'own VLAN, only the app server may reach it, EDR on', owner: 'Head of Applications', expires: '2027-03-31' };
  assert.throws(() => L.requestException(Object.assign({}, base, { compensating: '' }), adm), /compensating/);
  assert.throws(() => L.requestException(Object.assign({}, base, { expires: '2028-01-01' }), adm), /one year/);
  const x = L.requestException(base, adm);
  assert.throws(() => L.requestException(base, adm), /already pending/);
  assert.equal(L.view({}).items[0].isolation_required, true, 'pending changes nothing');
  assert.throws(() => L.decideException(x.id, { decision: 'approved' }, adm), /cannot approve/);
  assert.throws(() => L.decideException(x.id, { decision: 'approved' }, { user: 'other', role: 'admin' }), /only ciso/);
  L.decideException(x.id, { decision: 'approved', comment: 'ok until migration' }, ciso);
  let i = L.view({}).items[0];
  assert.equal(i.isolation_required, false); assert.match(i.action, /risk exception until 2027-03-31/); assert.equal(L.view({}).summary.exceptions, 1);
  t = Date.parse('2027-04-02T00:00:00Z');   // expired → required again, nothing renewed silently
  i = L.view({}).items[0]; assert.equal(i.isolation_required, true); assert.equal(i.exception.state, 'expired');
  assert.equal(L.view({}).exceptions[0].state, 'expired');
  assert.ok(audits.some((a) => a.action === 'lifecycle.exception.approved'));
});
