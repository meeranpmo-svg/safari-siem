// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DFIR engine (engine/dfir/dfir.js): forensic lane classification, the entity super-timeline (ordering + lane counts),
// the triage rollup (processes / logons / network / dns / detections / accounts), the overview (open cases, pending
// approvals, collection queue), and the triage-collection request/decide path (records only — never executes).
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDfir, laneOf, isInternalIp } = require('../engine/dfir/dfir');

function memState() { const cols = {}; return { collection(n) { return cols[n] || (cols[n] = { m: new Map(), get(id) { return this.m.get(id); }, put(o) { this.m.set(o.id, o); return o; }, all() { return [...this.m.values()]; }, remove(id) { this.m.delete(id); } }); } }; }
const CASES = {
  list: () => ({ items: [ { id: 'CASE-1', title: 'Ransomware on PC1', severity: 4, status: 'investigating', owner: 'ali', created: 1 }, { id: 'CASE-2', title: 'old', severity: 2, status: 'closed' } ] }),
  approvals: { list: () => ({ items: [ { id: 'APR-1', status: 'pending', title: 'Isolate PC1' } ] }) },
  get: (id) => (id === 'CASE-1' ? { id: 'CASE-1' } : null ),
};
const ROWS = [
  { ts: '2026-10-15 09:00:00.000', category: 'process', action: 'process-start', process: 'powershell.exe', parent_process: 'winword.exe', cmdline: '-enc ZQB2AGk...', host: 'PC1', severity: 1 },
  { ts: '2026-10-15 08:55:00.000', category: 'authentication', action: 'logon', outcome: 'success', target_user: 'ahmed', src_ip: '10.0.0.5', fields: { logon_type: '10' } },
  { ts: '2026-10-15 08:56:00.000', category: 'authentication', action: 'logon-failed', outcome: 'failure', target_user: 'ahmed', src_ip: '203.0.113.9', fields: { logon_type: '3' } },
  { ts: '2026-10-15 09:05:00.000', category: 'malware', action: 'av-detection', severity: 4, process: 'evil.exe', hash: 'abcdef0123456789', message: 'Trojan:Win32 found', src_type: 'edr-cef' },
  { ts: '2026-10-15 09:02:00.000', category: 'network', action: 'connection', dst_ip: '203.0.113.50', dst_port: '443', proto: 'tcp' },
  { ts: '2026-10-15 09:03:00.000', category: 'dns', action: 'dns-query', dns_query: 'evil.example.com', dst_ip: '8.8.8.8' },
  { ts: '2026-10-15 09:06:00.000', category: 'system', action: 'service-installed', message: 'New service: updater' },
  { ts: '2026-10-15 09:07:00.000', category: 'system', action: 'audit-log-cleared', message: 'Security log cleared' },
  { ts: '2026-10-15 09:08:00.000', category: 'iam', action: 'group-member-added', target_user: 'svc_bak', user: 'administrator' },
  { ts: '2026-10-15 09:01:00.000', category: 'network', action: 'connection', dst_ip: '10.0.0.9', dst_port: '445', proto: 'tcp' },
];
const search = async () => ({ rows: ROWS.map((r) => Object.assign({}, r)), total_estimate: ROWS.length, took_ms: 3 });
function mk() { return createDfir({ search, state: memState(), cases: CASES, log: { info() {}, warn() {} }, now: () => Date.parse('2026-10-15T10:00:00Z') }); }

test('dfir: lane classification maps category/action to forensic lanes', () => {
  assert.equal(laneOf({ category: 'malware', action: 'av-detection', severity: 4 }), 'detection');
  assert.equal(laneOf({ category: 'authentication', action: 'logon' }), 'auth');
  assert.equal(laneOf({ category: 'process', action: 'process-start' }), 'execution');
  assert.equal(laneOf({ category: 'system', action: 'service-installed' }), 'persistence');
  assert.equal(laneOf({ category: 'system', action: 'audit-log-cleared' }), 'evasion');
  assert.equal(laneOf({ category: 'iam', action: 'group-member-added' }), 'account');
  assert.equal(laneOf({ category: 'dns', action: 'dns-query' }), 'dns');
  assert.equal(laneOf({ category: 'network', action: 'connection' }), 'network');
  assert.equal(laneOf({ category: 'other', action: 'log', severity: 3 }), 'detection', 'severity>=3 escalates to detection');
  assert.equal(isInternalIp('10.0.0.9'), true); assert.equal(isInternalIp('203.0.113.50'), false);
});

test('dfir: entityType detects ip / user / host', () => {
  const d = mk();
  assert.equal(d.entityType('10.0.0.5'), 'ip');
  assert.equal(d.entityType('ahmed@corp.sa'), 'user');
  assert.equal(d.entityType('CORP\\\\ahmed'), 'user');
  assert.equal(d.entityType('PC1'), 'host');
});

test('dfir: timeline is chronological with lane counts and human titles', async () => {
  const d = mk();
  const t = await d.timeline({ entity: 'PC1', type: 'host', hours: 24 });
  assert.equal(t.rows.length, ROWS.length);
  assert.equal(t.rows[0].ts, '2026-10-15 08:55:00.000', 'sorted ascending by time');
  assert.ok(t.rows[t.rows.length - 1].ts >= t.rows[0].ts);
  const lanes = Object.fromEntries(t.lanes.map((l) => [l.lane, l.count]));
  assert.equal(lanes.detection, 1); assert.equal(lanes.execution, 1); assert.equal(lanes.persistence, 1); assert.equal(lanes.evasion, 1);
  const ps = t.rows.find((r) => r.process === 'powershell.exe'); assert.ok(ps.title.includes('winword.exe') && ps.title.includes('powershell.exe'));
  assert.equal(t.truncated, false);
});

test('dfir: triage rolls up processes, logons, network, dns, detections, accounts', async () => {
  const d = mk();
  const r = await d.triage({ entity: 'PC1', type: 'host', hours: 24 });
  assert.equal(r.summary.max_severity, 4);
  // evil.exe is a detection (sev 4), so only powershell is an execution process
  assert.equal(r.processes.length, 1); assert.equal(r.processes[0].process, 'powershell.exe'); assert.deepEqual(r.processes[0].parents, ['winword.exe']); assert.ok(r.processes[0].cmdline);
  // two logon groups for ahmed; the external one is a failure
  const extFail = r.logons.find((l) => l.src_ip === '203.0.113.9'); assert.equal(extFail.fail, 1); assert.equal(extFail.user, 'ahmed');
  const net = Object.fromEntries(r.network.map((n) => [n.dst_ip, n])); assert.equal(net['203.0.113.50'].internal, false); assert.equal(net['10.0.0.9'].internal, true);
  assert.equal(r.dns[0].query, 'evil.example.com');
  assert.equal(r.detections[0].action, 'av-detection'); assert.equal(r.detections[0].sev, 4);
  assert.equal(r.accounts[0].action, 'group-member-added'); assert.equal(r.accounts[0].target, 'svc_bak');
});

test('dfir: overview summarises cases, pending approvals and the collection queue', async () => {
  const d = mk();
  const o = d.overview();
  assert.equal(o.cases.total, 2); assert.equal(o.cases.open, 1); assert.equal(o.cases.by_status.investigating, 1); assert.equal(o.cases.by_status.closed, 1);
  assert.equal(o.cases.items.length, 1); assert.equal(o.cases.items[0].id, 'CASE-1');
  assert.equal(o.approvals.pending, 1);
  d.requestCollection({ entity: 'PC1', items: ['processes'], rationale: 'ransomware triage' }, { user: 'syed' });
  assert.equal(d.overview().collections.requested, 1);
});

test('dfir: requestCollection validates and records a request but never executes', async () => {
  const d = mk();
  assert.throws(() => d.requestCollection({ items: ['processes'], rationale: 'x' }), /entity is required/);
  assert.throws(() => d.requestCollection({ entity: 'PC1', items: [], rationale: 'x' }), /at least one collection item/);
  assert.throws(() => d.requestCollection({ entity: 'PC1', items: ['processes'] }), /rationale is required/);
  assert.throws(() => d.requestCollection({ entity: 'PC1', items: ['processes'], rationale: 'x', case_id: 'NOPE' }), /case not found/);
  const rec = d.requestCollection({ entity: 'PC1', type: 'host', items: ['processes', 'memory', 'not-a-real-item'], rationale: 'ransomware triage on PC1', case_id: 'CASE-1' }, { user: 'syed' });
  assert.match(rec.id, /^DFC-\d{6}$/);
  assert.deepEqual(rec.items, ['processes', 'memory'], 'invalid catalogue items dropped');
  assert.equal(rec.case_id, 'CASE-1'); assert.equal(rec.status, 'requested'); assert.equal(rec.requested_by, 'syed');
  assert.match(rec.execution, /not-executed-by-engine/);
  // decide
  assert.throws(() => d.decideCollection(rec.id, 'rejected', { user: 'faisal' }), /reason is required/);
  assert.throws(() => d.decideCollection(rec.id, 'frobnicate', { user: 'faisal' }), /decision must be/);
  const dec = d.decideCollection(rec.id, 'approved', { user: 'faisal' });
  assert.equal(dec.status, 'approved'); assert.equal(dec.decided_by, 'faisal');
  assert.equal(d.collections({ status: 'approved' }).items.length, 1);
});

test('dfir: collection decisions follow the state machine; the requester may only cancel; service identities are refused', () => {
  const mk = (d) => d.requestCollection({ entity: 'PC1', type: 'host', items: ['processes'], rationale: 'synthetic triage' }, { user: 'Rasheed' });
  const fresh = () => createDfir({ state: { collection: (() => { const m = new Map(); return () => ({ get: (k) => m.get(k), put: (r) => m.set(r.id, r), all: () => [...m.values()] }); })() }, cases: null, log: { info() {}, warn() {} } });
  const d = fresh(), a = mk(d), code = (c, re) => (e) => e.code === c && e.status === c && re.test(e.message);
  // the requester may only cancel
  assert.throws(() => d.decideCollection(a.id, 'rejected', { user: 'rasheed' }, 'no'), code(403, /four-eyes/));
  assert.throws(() => d.decideCollection(a.id, 'collected', { user: 'RASHEED' }), code(403, /four-eyes/));
  assert.throws(() => d.decideCollection(a.id, 'collected', { user: 'faisal' }), code(409, /requested and cannot become collected/), 'collected only after approved');
  assert.equal(d.decideCollection(a.id, 'approved', { user: 'faisal' }).status, 'approved');
  assert.throws(() => d.decideCollection(a.id, 'collected', { user: 'Rasheed' }), code(403, /cannot mark it collected/), 'the requester cannot mark their own request collected');
  assert.throws(() => d.decideCollection(a.id, 'rejected', { user: 'faisal' }, 'late'), code(409, /approved and cannot become rejected/));
  assert.throws(() => d.decideCollection(a.id, 'collected', { user: 'svc-collector' }), code(403, /not a service/));
  assert.throws(() => d.decideCollection(a.id, 'collected', { user: 'ai:desk' }), code(403, /not a service/));
  assert.equal(d.decideCollection(a.id, 'collected', { user: 'faisal' }).status, 'collected');
  assert.throws(() => d.decideCollection(a.id, 'cancelled', { user: 'Rasheed' }), code(409, /collected and cannot become cancelled/), 'collected is final');
  // rejected is final
  const r = mk(d); d.decideCollection(r.id, 'rejected', { user: 'faisal' }, 'not justified');
  assert.throws(() => d.decideCollection(r.id, 'approved', { user: 'omar' }), code(409, /rejected and cannot become approved/));
  // cancel: the requester may, from requested or approved
  const c = mk(d); assert.equal(d.decideCollection(c.id, 'cancelled', { user: 'rasheed' }).status, 'cancelled');
  assert.throws(() => d.decideCollection(c.id, 'approved', { user: 'faisal' }), code(409, /cancelled and cannot become approved/));
  const s = mk(d); assert.throws(() => d.decideCollection(s.id, 'approved', { user: 'svc-bot' }), code(403, /not a service/));
  assert.equal(d.collections({ status: 'requested' }).items.length, 1, 'the refused decisions changed nothing');
});
