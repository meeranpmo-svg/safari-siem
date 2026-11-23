// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI IT Auditor + AI Cyber Security Auditor (engine/auditors.js) on the duty desk: tests pass only on evidence, a source
// not connected is "not tested" (never passed) and keeps its earlier findings open; four-eyes breaches (requester approves,
// service identity approves, approved without an approver) are found; the re-test resolves a fixed finding; the cyber
// programme reads end of life, the testing schedule, the SIEM (approvals, log flow, duty) and the credential evidence;
// routes: viewer reads without evidence, operator runs (audited), viewer refused, validation names the field; readiness.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin', ip: '' };
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const iso = (h) => new Date(clock - h * 3600000).toISOString();

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  return { e, D, AU: e.app.addons.auditors };
}
const testOf = (r, id) => r.tests.find((x) => x.id === id);

test('IT auditor: four-eyes breaches found, a clean approval passes, missing serials, backup; nothing invented when not connected', async (t) => {
  const { e, AU } = await setup(t);
  let r = await AU.run('itaudit');
  assert.equal(testOf(r, 'IT-02').state, 'not_tested', 'no approvals yet: not tested, not passed');
  assert.equal(testOf(r, 'IT-05').state, 'not_tested'); assert.match(testOf(r, 'IT-05').detail, /not installed|connect|no /i);
  assert.equal(testOf(r, 'IT-04').state, 'not_tested', 'empty register');

  const P = e.app.store.collection('desk_patch');
  P.put({ id: 'PR-1', resource_id: 'r1', name: 'PC-SYN-1', state: 'deploying', requested_by: 'omar.syn', approved_by: 'omar.syn', approved_at: iso(5) });     // requester approved
  P.put({ id: 'PR-2', resource_id: 'r2', name: 'PC-SYN-2', state: 'deploying', requested_by: 'omar.syn', approved_by: 'svc:installer', approved_at: iso(5) }); // service identity
  P.put({ id: 'PR-3', resource_id: 'r3', name: 'PC-SYN-3', state: 'deploying', requested_by: 'system:desk-support', approved_by: 'system:desk-support', auto_approved: true, approved_at: iso(5) }); // armed auto-approval
  P.put({ id: 'PR-4', resource_id: 'r4', name: 'PC-SYN-4', state: 'deploying', requested_by: 'omar.syn', approved_by: 'syed', approved_at: iso(5) });            // correct
  const V = e.app.store.collection('virt_changes');
  V.put({ id: 'VC-1', state: 'approved', requested_by: 'duty:virt', decided_by: 'duty:virt' });
  V.put({ id: 'VC-2', state: 'applied', requested_by: 'ali.syn', decided_by: '' });
  V.put({ id: 'VC-3', state: 'approved', requested_by: 'duty:virt', decided_by: 'syed' });
  e.app.assets.create({ name: 'ESX-SYN-01', type: 'server', status: 'in_use' }, ADM);
  e.app.assets.create({ name: 'SW-SYN-01', type: 'network', status: 'in_use', serial: 'FOC123SYN' }, ADM);
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam', label: 'Veeam SYN', kind: 'veeam', last_sync: { at: '2026-10-20T07:00:00Z', ok: true, objects: 2 } }], settings: { target_hours: 26 },
    summary: { assets: 3, protected: 1, stale: 0, failed: 1, none: 1, exempt: 0, objects: 3 },
    assets: [{ name: 'SRV-SYN-A', mgmt_ip: '10.9.0.1', site: 'HQ', os: 'Windows', type: 'server', status: 'protected', last_success: iso(3), platforms: ['Veeam'], jobs: ['Daily'] },
      { name: 'SRV-SYN-B', mgmt_ip: '10.9.0.2', site: 'HQ', os: 'Linux', type: 'vm', status: 'failed', last_attempt: iso(2), last_result: 'failed', platforms: ['Veeam'], jobs: ['Daily'] },
      { name: '=SRV-SYN-C', mgmt_ip: '10.9.0.3', site: 'DR', os: 'Windows', type: 'server', status: 'none', platforms: [], jobs: [] }],
    unmatched: [{ name: 'srv-syn-c-old', vm_name: 'SRVSYNC', platform: 'Veeam SYN', job: 'Weekly' }] }) };

  r = await AU.run('itaudit');
  const sod = testOf(r, 'IT-02');
  assert.equal(sod.state, 'fail');
  const keys = sod.findings.map((f) => f.key).sort();
  assert.deepEqual(keys, ['IT-02:patch:PR-1', 'IT-02:patch:PR-2', 'IT-02:virt:VC-1', 'IT-02:virt:VC-2'], 'PR-3 (armed auto-approval), PR-4 and VC-3 are fine');
  assert.ok(sod.findings.every((f) => f.severity === 'high' && f.recommendation && f.site === 'IT & Cyber Security Audit'));
  assert.ok(testOf(r, 'IT-02').refs.some((x) => /A\.5\.3 Segregation of duties/.test(x)));
  const reg = testOf(r, 'IT-04'); assert.equal(reg.state, 'fail'); assert.match(reg.findings[0].title, /1 server/); assert.match(reg.findings[0].evidence[0], /ESX-SYN-01/);
  const bk = testOf(r, 'IT-05'); assert.equal(bk.state, 'fail'); assert.deepEqual(bk.findings.map((f) => f.key).sort(), ['IT-05:failed', 'IT-05:none']);
  // the evidence behind the count: every server named, the source and when it was read, the method, the unmatched backups
  const none = bk.findings.find((f) => f.key === 'IT-05:none');
  assert.deepEqual(none.items.map((row) => row[0]), ['=SRV-SYN-C'], 'the server with no backup is named'); assert.equal(none.columns[0], 'Server');
  assert.match(none.basis.join(' '), /Veeam SYN \(veeam; last sync 2026-10-20T07:00:00Z, ok, 2 objects\)/); assert.match(none.basis.join(' '), /within 26 hours/);
  assert.match(none.basis.join(' '), /1 matched no server in the register \(for example: SRVSYNC\)/);
  assert.equal(none.counter.items[0][0], 'srv-syn-c-old'); assert.match(none.evidence_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(bk.findings.find((f) => f.key === 'IT-05:failed').items[0][0], 'SRV-SYN-B');
});

test('duty desk: findings become work items, the re-test resolves a fix, a test that cannot run keeps its findings open', async (t) => {
  const { e, D } = await setup(t);
  e.app.store.collection('desk_patch').put({ id: 'PR-9', resource_id: 'r9', name: 'PC-SYN-9', state: 'deploying', requested_by: 'omar.syn', approved_by: 'omar.syn', approved_at: iso(2) });
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], summary: { assets: 2, protected: 1, stale: 0, failed: 1, none: 0, exempt: 0 } }) };
  e.app.assets.create({ name: 'APP-SYN-1', type: 'vm', status: 'in_use' }, ADM);
  const p1 = await D.patrol('itaudit'); assert.ok(p1.opened >= 2, JSON.stringify(p1));
  const items = D.list({ engineer: 'itaudit', status: 'open' }).items;
  const sod = items.find((x) => x.key === 'IT-02:patch:PR-9'), bk = items.find((x) => x.key === 'IT-05:failed');
  assert.ok(sod && bk); assert.equal(sod.engineer_name, 'AI IT Auditor');
  assert.match(D.get(sod.id).investigation.checks[1].detail, /ISO\/IEC 27001/);
  // the patch record is corrected (retrospective approval by another person); the backup module goes away
  e.app.store.collection('desk_patch').put({ id: 'PR-9', resource_id: 'r9', name: 'PC-SYN-9', state: 'deploying', requested_by: 'omar.syn', approved_by: 'syed', approved_at: iso(1) });
  delete e.app.addons.backup;
  clock += 600000; await D.patrol('itaudit');
  assert.equal(D.get(sod.id).status, 'resolved', 'the re-test passes: resolved');
  assert.notEqual(D.get(bk.id).status, 'resolved', 'backup could not be tested: the finding stays open (silence is not a clean audit)');
  assert.ok(D.get(bk.id).evidence.some((x) => /not re-tested/.test(x)));
});

test('cyber auditor: end of life, testing schedule, SIEM approvals / log flow / duty, credential custody', async (t) => {
  const { e, AU } = await setup(t);
  let r = await AU.run('cyberaudit');
  for (const id of ['CY-01', 'CY-02', 'CY-05', 'CY-06']) assert.equal(testOf(r, id).state, 'not_tested', id + ' with no source');
  e.app.addons.lifecycle = { view: () => ({ summary: { eol: 2 }, items: [{ id: 'a1', name: 'SRV-SYN-OLD', type: 'server', product: 'Windows Server 2008 R2', status: 'eol', eol: '2020-01-14', isolation_required: true }, { id: 'a2', name: 'SW-SYN-OLD', type: 'network', status: 'eol', isolation_required: false }] }) };
  e.app.addons.pentest = { cadence: { schedule: () => ({ rows: [{ asset: 'CORE-SYN', tier: 'critical', worst: 'never' }, { asset: 'WEB-SYN', tier: 'standard', worst: 'overdue' }, { asset: 'OK-SYN', tier: 'standard', worst: 'ok' }] }) } };
  e.app.addons.credPosture = { build: () => ({ summary: { stored: 10, sealed: 9 }, findings: [{ sev: 'high', area: 'Stores', text: '1 credential stored in clear text', fix: 'Re-save it' }, { sev: 'low', area: 'Info', text: 'note' }] }) };
  e.app.addons.ciso = { collect: async () => ({
    approvals: { state: 'live', data: [{ id: 'APR-000001', case_id: 'C-1', action: 'isolate', requested_by: 'system', requested_at: clock - 30 * 3600000 }, { id: 'APR-000002', requested_at: clock - 3600000 }] },
    logflow: { state: 'live', data: { summary: { required: 10, covered: 7, silent: 2, 'not-onboarded': 1, coverage_pct: 70 }, collector: { quiet: false } } },
    siem_duty: { state: 'live', data: { engineers: [{ id: 'network', name: 'AI Network Engineer', on_duty: false }, { id: 'security', name: 'AI Security Engineer', on_duty: true, last_patrol: clock }], items: [{ id: 'DW-000009', engineer: 'network', engineer_name: 'AI Network Engineer', severity: 'critical', status: 'needs-human', title: 'Core switch down', detected_at: clock - 10 * 86400000 }] } },
  }) };
  r = await AU.run('cyberaudit');
  const eol = testOf(r, 'CY-01'); assert.equal(eol.state, 'fail'); assert.equal(eol.findings.length, 1); assert.equal(eol.findings[0].severity, 'high'); assert.match(eol.findings[0].title, /SRV-SYN-OLD/);
  const sch = testOf(r, 'CY-02'); assert.deepEqual(sch.findings.map((f) => [f.key, f.severity]), [['CY-02:critical:never', 'high'], ['CY-02:standard:overdue', 'medium']]);
  const sla = testOf(r, 'CY-03'); assert.ok(sla.findings.some((f) => /Core switch down/.test(f.title) && /SIEM/.test(f.evidence[0])), 'a SIEM critical open 10 days (SLA 24 h × 7)');
  const ap = testOf(r, 'CY-04'); assert.deepEqual(ap.findings.map((f) => f.key), ['CY-04:soc:APR-000001'], 'only the one waiting > 24 h');
  const lf = testOf(r, 'CY-05'); assert.deepEqual(lf.findings.map((f) => f.key).sort(), ['CY-05:not-onboarded', 'CY-05:silent']);
  const cr = testOf(r, 'CY-06'); assert.equal(cr.findings.length, 1, 'low items are not audit findings'); assert.match(cr.findings[0].recommendation, /Re-save/);
  const od = testOf(r, 'CY-07'); assert.ok(od.findings.some((f) => /AI Network Engineer: off duty/.test(f.title)));
  assert.ok(!od.findings.some((f) => /Auditor/.test(f.title)), 'the auditors do not audit themselves as off duty');
});

test('routes: viewer reads the programme without evidence, operator runs it (audited), viewer refused, validation names the field', async (t) => {
  const { e } = await setup(t);
  e.app.store.collection('desk_patch').put({ id: 'PR-5', resource_id: 'r5', name: 'PC-SYN-5', state: 'deploying', requested_by: 'omar.syn', approved_by: 'omar.syn', approved_at: iso(1) });
  assert.equal((await e.req('POST', '/audit-programme/run', { role: 'viewer', body: {} })).status, 403);
  const bad = await e.req('POST', '/audit-programme/run', { role: 'operator', body: { auditor: 'payroll' } });
  assert.equal(bad.status, 400); assert.match(bad.json.error, /auditor/);
  const run = await e.req('POST', '/audit-programme/run', { user: 'aud.syn', role: 'operator', body: { auditor: 'itaudit' } });
  assert.equal(run.status, 200); assert.equal(run.json.auditors[0].id, 'itaudit');
  const sod = run.json.auditors[0].tests.find((x) => x.id === 'IT-02'); assert.equal(sod.state, 'fail'); assert.ok(sod.items[0].evidence.length);
  const tail = e.app.store.auditTail(20).find((x) => x.action === 'audit.programme.run');
  assert.ok(tail && tail.by === 'aud.syn' && tail.role === 'operator'); assert.equal(tail.target, 'itaudit');
  const v = await e.req('GET', '/audit-programme', { role: 'viewer' });
  assert.equal(v.status, 200); assert.equal(v.json.auditors.length, 2);
  const vt = v.json.auditors[0].tests.find((x) => x.id === 'IT-02'); assert.equal(vt.state, 'fail'); assert.equal(vt.findings, 1); assert.equal(vt.items, undefined, 'viewer: counts, no evidence');
  assert.equal(v.json.auditors[1].tests[0].state, 'not_run'); assert.equal(v.json.auditors[1].pass_pct, null, 'nothing tested: no percentage');
  const rd = await e.req('GET', '/duty/readiness', { role: 'viewer' });
  const ia = rd.json.engineers.find((x) => x.id === 'itaudit'); assert.ok(ia && ia.checks.some((c) => c.name === 'Independence'));
  const en = await e.req('GET', '/duty/engineers', { role: 'viewer' });
  assert.ok(['itaudit', 'cyberaudit'].every((id) => en.json.engineers.some((x) => x.id === id)), 'on the AI Engineering Team like every engineer');
});

test('wider IT programme: policies, DR drills, Oracle licences, reconciliation, leavers, warranty, storage', async (t) => {
  const { e, AU } = await setup(t);
  let r = await AU.run('itaudit');
  assert.equal(r.tests.length, 19);
  for (const id of ["IT-15", "IT-16", "IT-17", "IT-18", "IT-19"]) assert.equal(testOf(r, id).state, "not_tested", id + ": no SIEM link - not tested, never passed");
  for (const id of ['IT-10', 'IT-11', 'IT-12', 'IT-14']) assert.equal(testOf(r, id).state, 'not_tested', id + ' with no source');
  e.app.addons.grc = { summary: () => ({ total: 40, reviews: { overdue: 7, soon: 2 } }), drillSummary: () => ({ systems: { total: 5, tested: 3, overdue: 2 }, by_result: { fail: 1 }, awaiting_signoff: 1, rto: { pct: 50 }, rpo: { pct: null } }) };
  e.app.addons.oracleLicences = { compliance: () => ({ verdict_label: 'OVER-UTILISED', matrix: [{ product: 'db', edition: 'ee', name: 'Oracle Database EE', metric: 'Processor', owned: 4, required: 6, utilisation_pct: 150, level: 'over' }, { product: 'rac', name: 'RAC', owned: 4, required: 2, level: 'compliant' }] }) };
  e.app.addons.reconcile = { view: () => ({ report: { issues: [{ kind: 'retired_alive', name: 'OLD-SYN' }, { kind: 'not_in_inventory', name: '10.9.9.9' }, { kind: 'not_in_inventory', name: 'X', accepted: true }, { kind: 'missing_os', name: 'Y' }] } }) };
  e.app.addons.handover = { list: () => [{ id: 'HO-1', state: 'open', leaver: 'left.syn', leaver_name: 'Left Syn', last_day: '2026-10-01', progress: 40, blockers: 2, team: 'infra', manager: 'boss.syn' }, { id: 'HO-2', state: 'signed-off', last_day: '2026-09-01' }] };
  e.app.addons.storage = { view: () => ({ arrays: [{ at: '2026-10-20T05:00:00Z', platform: { label: 'NAS-SYN' }, capacity: { used_pct: 96, size_bytes: 1e13 }, disks: { failed: 1 }, worst: 'high' }], summary: { arrays: 1, read: 1, used_pct: 96, failed_disks: 1 } }) };
  e.app.assets.create({ name: 'SW-SYN-W', type: 'network', status: 'in_use', serial: 'S1', warranty: { end: '2025-01-01' } }, ADM);
  r = await AU.run('itaudit');
  assert.equal(testOf(r, 'IT-08').findings[0].severity, 'high'); assert.match(testOf(r, 'IT-08').findings[0].title, /7 of 40/);
  assert.deepEqual(testOf(r, 'IT-09').findings.map((f) => f.key).sort(), ['IT-09:failed', 'IT-09:overdue', 'IT-09:signoff']);
  const lic = testOf(r, 'IT-10'); assert.equal(lic.findings.length, 1); assert.equal(lic.findings[0].severity, 'high'); assert.match(lic.findings[0].title, /needs 6, owns 4/);
  assert.deepEqual(testOf(r, 'IT-11').findings.map((f) => [f.key, f.severity]), [['IT-11:retired_alive', 'high'], ['IT-11:not_in_inventory', 'medium']], 'accepted items and info kinds are not findings');
  const ho = testOf(r, 'IT-12'); assert.equal(ho.findings.length, 1); assert.equal(ho.findings[0].severity, 'high'); assert.match(ho.findings[0].title, /Left Syn left on 2026-10-01/);
  assert.equal(testOf(r, 'IT-13').state, 'fail');
  assert.deepEqual(testOf(r, 'IT-14').findings.map((f) => [f.key, f.severity]), [['IT-14:disks', 'high'], ['IT-14:full', 'high']]);
});

test('wider cyber programme: SAMA gaps, incident SLA, internet exposure, unknown senders, trusted identities, secret leaks, domains, endpoints', async (t) => {
  const { e, AU } = await setup(t);
  e.app.addons.ciso = { collect: async () => ({
    sama: { state: 'live', data: { summary: { coverage_pct: 72 }, controls: [{ id: '3.3.5', title: 'Identity and access management', status: 'gap' }, { id: '3.3.6', status: 'covered' }] } },
    soc: { state: 'live', data: { open_by_severity: { 4: 2, 3: 5 }, sla: { breaching_now: [{ id: 'C-9' }] } } },
    logflow: { state: 'live', data: { summary: { required: 1, covered: 1 }, unknown_senders: 3, collector: {} } } }) };
  e.app.addons.pentest = { assessment: () => ({ summary: { assets: 4, internet_facing: 1 }, findings: [{ id: 'f1', asset: 'EDGE-SYN', title: 'RDP open', severity: 'critical', internet: true, evidence: '3389/tcp' }, { id: 'f2', asset: 'IN-SYN', title: 'SMB', severity: 'high', internet: false }] }) };
  e.app.addons.credPosture = { build: () => ({ summary: { stored: 1, sealed: 1 }, findings: [], transport: { trust: { ssh: { trusted: 3, pending: 1, changed: 1 }, tls: { trusted: 2, pending: 0, changed: 0 } } }, last_scan: { at: new Date(clock - 40 * 86400000).toISOString(), secrets_checked: 5, files: 20, hits: [{ file: '/var/lib/x.log', secret: 'SIEM link · token' }] } }) };
  e.app.addons.domains = { view: () => ({ summary: { domains: 3, hosts: 4, expired: 0, certs_30: 1, expiring_90: 1, outside_ksa: 1 } }) };
  e.app.addons.deskSupport = { desktops: () => ({ items: [{ name: 'PC1', live: 'down' }, { name: 'PC2', live: 'up' }, { name: 'PC3', live: 'up' }] }) };
  const r = await AU.run('cyberaudit');
  assert.equal(r.tests.length, 26);
  for (const id of ["CY-16", "CY-17", "CY-18", "CY-19", "CY-20", "CY-21", "CY-22", "CY-23", "CY-24", "CY-25", "CY-26"]) assert.equal(testOf(r, id).state, "not_tested", id + ": no SIEM link - not tested, never passed");
  assert.equal(testOf(r, 'CY-08').findings[0].key, 'CY-08:3.3.5');
  assert.deepEqual(testOf(r, 'CY-09').findings.map((f) => f.key), ['CY-09:sla', 'CY-09:critical']);
  assert.deepEqual(testOf(r, 'CY-10').findings.map((f) => f.key), ['CY-10:f1'], 'only internet-facing critical / high');
  assert.match(testOf(r, 'CY-11').findings[0].title, /3 device/);
  assert.deepEqual(testOf(r, 'CY-12').findings.map((f) => [f.key, f.severity]), [['CY-12:changed', 'high'], ['CY-12:pending', 'low']]);
  assert.deepEqual(testOf(r, 'CY-13').findings.map((f) => [f.key, f.severity]), [['CY-13:hits', 'critical'], ['CY-13:stale', 'low']]);
  assert.deepEqual(testOf(r, 'CY-14').findings.map((f) => f.key).sort(), ['CY-14:certs', 'CY-14:expiring', 'CY-14:outside']);
  assert.equal(testOf(r, 'CY-15').findings[0].severity, 'high', '33% silent');
});

test('audit report: opinion from the findings, every finding with criteria / effect / owner / status, limitations listed; operator only, audited', async (t) => {
  const { e, D, AU } = await setup(t);
  let rep = AU.report('itaudit');
  assert.equal(rep.sections[0].opinion.rating, 'Unable to conclude', 'nothing run: no opinion');
  e.app.store.collection('desk_patch').put({ id: 'PR-7', resource_id: 'r7', name: 'PC-SYN-7', state: 'deploying', requested_by: 'omar.syn', approved_by: 'omar.syn', approved_at: iso(1) });
  e.app.addons.grc = { summary: () => ({ total: 10, reviews: { overdue: 0 } }), drillSummary: () => ({ systems: { total: 2, tested: 2, overdue: 0 }, by_result: {}, awaiting_signoff: 0, rto: {}, rpo: {} }) };
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'v' }], summary: { assets: 1, protected: 1, stale: 0, failed: 0, none: 0, exempt: 0 } }) };
  e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'PC', missing: 0, critical: 0 }] }) };
  e.app.addons.supportContracts = { view: () => ({ contracts: [], summary: { contracts: 1 } }) };
  e.app.assets.create({ name: 'SRV-SYN', type: 'server', status: 'in_use', serial: 'S9', warranty: { end: '2030-01-01' } }, ADM);
  await D.patrol('itaudit');
  rep = AU.report('itaudit');
  const sec = rep.sections[0];
  assert.equal(sec.opinion.rating, 'Needs improvement', JSON.stringify(sec.opinion));
  const f = sec.findings.find((x) => x.test === 'IT-02');
  assert.ok(f && f.ref.startsWith('ITA-') && f.criteria.some((c) => /A\.5\.3/.test(c)) && f.effect && f.owner === 'IT & Cyber Security Audit' && f.work_item && f.condition.length);
  assert.ok(sec.limitations.some((l) => l.id === 'IT-10'), 'what could not be tested is listed');
  assert.match(rep.digest, /^sha256:[0-9a-f]{64}$/); assert.equal(rep.signoff.reviewed_by, null);
  assert.equal(AU.report('all').sections.length, 2);
  // routes
  assert.equal((await e.req('GET', '/audit-programme/report', { role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/audit-programme/report?auditor=hr', { role: 'operator' })).status, 400);
  const ok = await e.req('GET', '/audit-programme/report?auditor=itaudit', { user: 'aud.syn', role: 'operator' });
  assert.equal(ok.status, 200); assert.equal(ok.json.sections[0].auditor, 'itaudit');
  const a = e.app.store.auditTail(20).find((x) => x.action === 'audit.report.generate');
  assert.ok(a && a.by === 'aud.syn' && a.target === 'itaudit' && /^sha256:/.test(a.detail.digest));
});

test('evidence of a finding: the rows behind the count in the report and the evidence route (operator, audited, validated)', async (t) => {
  const { e, AU } = await setup(t);
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'v', label: 'Nutanix SYN', kind: 'nutanix', last_sync: { at: '2026-10-20T06:00:00Z', ok: true, objects: 1 } }], settings: { target_hours: 24 },
    summary: { assets: 2, protected: 1, stale: 0, failed: 0, none: 1, exempt: 0, objects: 1 }, unmatched: [],
    assets: [{ name: 'SRV-SYN-OK', status: 'protected', platforms: ['Nutanix'], jobs: [] }, { name: 'SRV-SYN-NONE', mgmt_ip: '10.8.0.9', site: 'HQ', status: 'none', platforms: [], jobs: [] }] }) };
  await AU.run('itaudit');
  const rep = await e.req('GET', '/audit-programme/report?auditor=itaudit', { user: 'aud.syn', role: 'operator' });
  const f = rep.json.sections[0].findings.find((x) => x.key === 'IT-05:none');
  assert.ok(f && f.evidence && f.evidence.count === 1 && f.evidence.rows[0][0] === 'SRV-SYN-NONE' && f.basis.length >= 4, 'report carries the evidence rows and basis');
  assert.equal((await e.req('GET', '/audit-programme/evidence?key=IT-05:none', { role: 'viewer' })).status, 403);
  assert.match((await e.req('GET', '/audit-programme/evidence?key=bad%20key', { role: 'operator' })).json.error, /key/);
  assert.equal((await e.req('GET', '/audit-programme/evidence?key=IT-05:nothing', { role: 'operator' })).status, 404);
  const ev = await e.req('GET', '/audit-programme/evidence?key=IT-05:none', { user: 'aud.syn', role: 'operator' });
  assert.equal(ev.status, 200); assert.equal(ev.json.rows.length, 1); assert.equal(ev.json.columns[1], 'Management IP'); assert.equal(ev.json.rows[0][1], '10.8.0.9');
  assert.match(ev.json.digest, /^sha256:/); assert.equal(ev.json.digest, f.evidence.digest, 'the same evidence in the report and the route');
  const a = e.app.store.auditTail(5).find((x) => x.action === 'audit.evidence.view');
  assert.ok(a && a.by === 'aud.syn' && a.target === 'IT-05:none' && a.detail.rows === 1);
  // the duty desk keeps a short evidence, never the full annex
  const D = e.app.duty; await D.patrol('itaudit');
  const it = D.list({ engineer: 'itaudit', status: 'open', limit: 50 }).items.find((x) => x.key === 'IT-05:none');
  assert.ok(it && !it.items && !it.basis, 'no annex on the work item'); assert.ok(it.evidence.some((x) => /evidence annex/.test(x)));
});
