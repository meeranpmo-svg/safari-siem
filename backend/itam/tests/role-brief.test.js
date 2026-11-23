// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Role briefs for My Workspace (engine/role-brief.js) through the real route on SYNTHETIC sources: the CISO's priorities (a domain
// below 70, critical / high security risks, decisions waiting, SOC SLA breaches, an IT appetite metric outside appetite, the person's
// overdue GRC action) and the IT Manager's (failed / missing backups, critical patches, end of life, failed disks, expired contracts),
// ranked with their points; a source not installed is named and adds nothing; roles (viewer refused); unknown kind 404.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, CISO = { user: 'rashid.syn', role: 'operator' }, ITM = { user: 'sami.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || CISO));
  return { e, call };
}
const CISO_OV = { posture: { overall: 64, grade: 'weak', domains: [{ id: 'detection', name: 'Detection & response', score: 48, measured: true }, { id: 'governance', name: 'Governance', score: 82, measured: true }, { id: 'exposure', name: 'Exposure', score: null, measured: false }] },
  risks: [{ ref: 'duty:SYN-1', severity: 'critical', title: 'Ransomware indicators on a file server (synthetic)', source: 'AI security engineer', domain: 'detection', age_h: 100 },
    { ref: 'drill:SYN-2', severity: 'high', title: 'DR drill overdue for the core system (synthetic)', source: 'DR drills', domain: 'resilience', age_h: 10 }, { ref: 'x:3', severity: 'low', title: 'low item', source: 'x', domain: 'operations' }],
  decisions: [{ ref: 'appr:SYN-9', kind: 'change plan', severity: 'high', title: 'Firewall change plan awaiting approval (synthetic)' }],
  soc: { open_by_severity: { critical: 2, high: 5 }, sla: { breaching_now: 3 } }, compliance: { sama: { coverage_pct: 71 } }, sources: [{ name: 'SIEM', state: 'live' }, { name: 'Pentest', state: 'error', error: 'not connected' }] };

test('CISO brief: ranked security priorities, appetite, GRC actions, roles', async (t) => {
  const { e, call } = await setup(t);
  e.app.addons.ciso = { overview: async () => CISO_OV };
  // an IT metric outside appetite (Business Risk) and an overdue GRC action owned by the CISO
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  assert.equal((await call('POST', '/brisk/ras/RAS-02.01/actuals', { period: '2026-10', value: '82%', note: 'core system outage (synthetic)' })).status, 200);
  const R = e.app.addons.grcRegisters; R.actionCreate({ title: 'Close the synthetic pentest findings', source: 'manual', owner: 'rashid.syn', priority: 'high', due: '2026-10-01' }, ADM);
  assert.equal((await call('GET', '/role-brief/ciso', undefined, VIEW)).status, 403, 'names owners: no viewers');
  assert.equal((await call('GET', '/role-brief/cfo')).status, 404);
  const b = (await call('GET', '/role-brief/ciso')).json;
  assert.equal(b.kpis.posture, 64); assert.equal(b.kpis.critical_alerts, 2); assert.equal(b.kpis.sla_breaching, 3); assert.equal(b.kpis.security_risks, 2); assert.equal(b.kpis.sama_coverage, 71); assert.equal(b.kpis.my_overdue, 1); assert.equal(b.kpis.appetite_outside, 1);
  const refs = b.priorities.map((p) => p.ref);
  for (const r of ['duty:SYN-1', 'drill:SYN-2', 'appr:SYN-9', 'soc:sla', 'domain:detection', 'RAS-02.01']) assert.ok(refs.includes(r), r + ' is a priority');
  assert.ok(!refs.includes('domain:governance') && !refs.includes('domain:exposure') && !refs.includes('x:3'), 'a healthy or unmeasured domain and a low risk are not priorities');
  assert.ok(b.priorities.every((p, i) => i === 0 || b.priorities[i - 1].score >= p.score), 'ranked by score');
  assert.equal(b.priorities[0].ref.startsWith('ACT-') || b.priorities[0].ref === 'duty:SYN-1', true, 'the overdue action or the critical risk first');
  assert.ok(b.priorities.find((p) => p.ref === 'duty:SYN-1').why.some((w) => /open 4 days \+10/.test(w)), 'each priority shows its points');
  assert.ok(b.notes.some((n) => /Pentest: not connected/.test(n)), 'a source not read is named');
  assert.match(b.brief[0], /64 \/ 100/); assert.ok(b.brief.some((l) => /IT \/ cyber appetite metric/.test(l)));
});

test('IT Manager brief: infrastructure priorities; nothing installed is said, never zero', async (t) => {
  const { e, call } = await setup(t);
  // nothing connected: every section named in notes, no number invented
  let b = (await call('GET', '/role-brief/itm', undefined, ITM)).json;
  assert.equal(b.kpis.backup_pct, null); assert.equal(b.kpis.patch_pct, null); assert.ok(b.notes.some((n) => /backup:/.test(n))); assert.ok(b.brief.some((l) => /Backups: not measured/.test(l)));
  assert.ok(b.notes.some((n) => /AI CISO is not installed|AI CISO/.test(n)) || !e.app.addons.ciso);
  e.app.addons.infraOverview = { view: () => ({ register: { available: true, servers: { total: 40 }, network: { total: 12 }, warranty: { expired: 2 } },
    backup: { available: true, protected_pct: 85, failed: 2, none: 3, stale: 1 }, patch: { available: true, compliant_pct: 70, critical_missing: 6 },
    lifecycle: { available: true, eol: 4, soon: 2, isolation_required: 1 }, storage: { available: true, used_pct: 91, failed_disks: 1 }, contracts: { available: true, expired: 1, expiring: 3 } }) };
  e.app.addons.ciso = { overview: async () => CISO_OV };
  b = (await call('GET', '/role-brief/itm', undefined, ITM)).json;
  assert.deepEqual([b.kpis.servers, b.kpis.backup_pct, b.kpis.patch_pct, b.kpis.eol, b.kpis.storage_pct, b.kpis.contracts_due], [40, 85, 70, 4, 91, 4]);
  const refs = b.priorities.map((p) => p.ref);
  for (const r of ['backup:failed', 'backup:none', 'patch:critical', 'eol', 'storage:disks', 'storage:capacity', 'contracts:expired', 'warranty', 'drill:SYN-2']) assert.ok(refs.includes(r), r + ' is a priority');
  assert.ok(!refs.includes('duty:SYN-1'), 'a detection risk belongs to the CISO, not the IT Manager');
  assert.ok(b.priorities.find((p) => p.ref === 'eol').why.some((w) => /isolation required \+10/.test(w)));
  assert.match(b.brief.join(' '), /85 % of servers protected, 2 failed/);
});

test('IT Manager brief: AD Management - what waits for this person, never their own request; off and not connected are said', async (t) => {
  const { e, call } = await setup(t);
  // the real module is installed but the directory is not connected
  let b = (await call('GET', '/role-brief/itm', undefined, ITM)).json;
  assert.equal(b.ad.connected, false); assert.equal(b.kpis.ad_waiting, null); assert.ok(b.brief.some((l) => /AD Management: the directory is not connected/.test(l)));
  assert.ok(b.links.some((l) => l[0] === 'ad-manage.html'));
  const R = (o) => Object.assign({ id: 'adr_' + Math.random().toString(16).slice(2, 18).padEnd(16, '0'), at: new Date(T0 - 3600000).toISOString(), reason: 'synthetic' }, o);
  const reqs = [R({ status: 'pending', by: 'huda.syn', action: 'disable', summary: 'disable alia.syn' }), R({ status: 'pending', by: 'huda.syn', action: 'delete', summary: 'DELETE coral.syn' }),
    R({ status: 'pending', by: 'sami.syn', action: 'enable', summary: 'enable dina.syn' }), R({ status: 'done', by: 'huda.syn', action: 'disable', summary: 'disable eisa.syn', review: 'pending', emergency: true }),
    R({ status: 'done', by: 'sami.syn', action: 'disable', summary: 'disable farah.syn', review: 'pending', emergency: true }), R({ status: 'done', by: 'sami.syn', action: 'reset_password', summary: 'reset the password of alia.syn', password_ready: true }),
    R({ status: 'failed', by: 'huda.syn', action: 'move', summary: 'move alia.syn to OU=Leavers', error: 'the directory refused: INSUFF_ACCESS_RIGHTS', decided_at: new Date(T0 - 86400000).toISOString() }),
    R({ status: 'failed', by: 'huda.syn', action: 'move', summary: 'move old.syn', error: 'old', decided_at: new Date(T0 - 30 * 86400000).toISOString() })];
  const seen = [];
  e.app.addons.adManage = { view: (who) => { seen.push(who.user); return { connection: { ok: true, base_dn: 'DC=synthetic,DC=test' }, settings: { enabled: true, delete_enabled: true }, requests: reqs }; } };
  b = (await call('GET', '/role-brief/itm', undefined, ITM)).json;
  assert.equal(seen.pop(), 'sami.syn', 'read as this person (their temporary passwords)');
  assert.deepEqual([b.ad.waiting_for_you, b.ad.reviews, b.ad.passwords, b.ad.my_pending, b.ad.failed_7d], [2, 1, 1, 1, 1], 'their own request and their own emergency are not theirs to decide; a 30-day-old failure is not counted');
  assert.equal(b.kpis.ad_waiting, 3);
  const P = b.priorities.filter((p) => /^AD /.test(p.kind)), txt = P.map((p) => p.text).join(' | ');
  assert.ok(/DELETE coral\.syn - requested by huda\.syn/.test(txt) && /disable eisa\.syn - by huda\.syn/.test(txt) && /reset the password of alia\.syn/.test(txt) && /INSUFF_ACCESS_RIGHTS/.test(txt), txt);
  assert.ok(!/enable dina\.syn|farah\.syn/.test(txt), 'never the person\'s own request');
  const del = P.find((p) => /DELETE/.test(p.text)), emg = P.find((p) => p.kind === 'AD emergency');
  assert.equal(del.score, 55); assert.ok(del.why.some((w) => /permanent delete \+10/.test(w))); assert.equal(emg.score, 50); assert.ok(P.every((p) => p.page === 'ad-manage.html'));
  assert.ok(b.brief.some((l) => /AD Management: 2 change\(s\) waiting for your approval, 1 emergency disable\(s\) to review, 1 temporary password\(s\) to hand over; 1 of your own request\(s\) waiting/.test(l)));
  assert.equal(b.ad.recent.length, 6);
  e.app.addons.adManage = { view: () => ({ connection: { ok: true }, settings: { enabled: false }, requests: [] }) };
  b = (await call('GET', '/role-brief/itm', undefined, ITM)).json; assert.ok(b.brief.some((l) => /AD Management: switched off/.test(l))); assert.equal(b.kpis.ad_waiting, null);
  e.app.addons.adManage = { view: () => { throw new Error('synthetic failure'); } };
  b = (await call('GET', '/role-brief/itm', undefined, ITM)).json; assert.ok(b.notes.includes('AD Management could not be read')); assert.equal(b.ad, null);
});

test('IT Manager brief: Workflow Automation read as the person - approvals (never their own), overdue in their teams, results to accept', async (t) => {
  const { e, call } = await setup(t);
  const W = e.app.addons.workflow, A = { user: 'adam.syn', role: 'admin', ip: '' }, me = Object.assign({ ip: '' }, ITM);
  W.settingsSave({ version: 0, teams: { dba: ['dba.syn'], servers: ['srv.syn'], identity: ['idm.syn'] }, leads: { identity: ['sami.syn'], dba: ['sami.syn'] } }, A);
  const leaver = W.create({ type: 'leaver-disable', from: 'hr', title: 'Leaver: badr.syn', details: 'last day', priority: 'urgent' }, { user: 'hr.syn', role: 'viewer', ip: '' });
  W.create({ type: 'db-new', from: 'admin', title: 'Schema for the claims app', details: 'new schema' }, me);
  const late = W.create({ type: 'db-user-review', from: 'audit', title: 'Q4 DB accounts', details: 'all DBA accounts' }, { user: 'aud.syn', role: 'viewer', ip: '' });
  const col = e.app.store.collection('wf_requests'), lr = col.get(late.id); lr.due = new Date(T0 - 3600000).toISOString(); lr.escalated_at = new Date(T0).toISOString(); col.put(lr);
  const kpi = W.create({ type: 'kpi-pack', from: 'governance', title: 'October KPI pack', details: 'monthly' }, me);
  W.act(kpi.id, 'start', {}, { user: 'srv.syn', role: 'operator', ip: '' }); W.act(kpi.id, 'fulfil', { response: 'attached' }, { user: 'srv.syn', role: 'operator', ip: '' });
  const b = (await call('GET', '/role-brief/itm', undefined, ITM)).json;
  assert.deepEqual([b.wf.approvals, b.wf.overdue, b.wf.to_accept, b.wf.queue_open], [1, 1, 1, 1], JSON.stringify(b.wf));
  assert.equal(b.kpis.wf_attention, 3);
  const P = b.priorities.filter((p) => /^Request /.test(p.kind)), txt = P.map((p) => p.text).join(' | ');
  assert.ok(/Leaver: badr\.syn - New joiner|Leaver: badr\.syn - Leaver/.test(txt) && /Q4 DB accounts - Database team/.test(txt) && /October KPI pack - fulfilled by srv\.syn/.test(txt), txt);
  assert.ok(!P.some((p) => p.kind === 'Request approval' && /Schema for the claims app/.test(p.text)), 'never their own request to approve');
  const ap = P.find((p) => p.ref === leaver.id), ov = P.find((p) => p.ref === late.id);
  assert.equal(ap.score, 55); assert.ok(ap.why.some((w) => /urgent priority \+10/.test(w))); assert.equal(ov.score, 50); assert.ok(ov.why.some((w) => /escalated \+10/.test(w)));
  assert.equal(ap.page, 'workflow-automation.html#req=' + leaver.id);
  assert.ok(b.brief.some((l) => /Workflow Automation: 1 request\(s\) waiting for your approval, 1 open in your team queue \(1 overdue\), 1 result\(s\) waiting for your acceptance; 1 overdue across the IT teams\./.test(l)), b.brief.join(' / '));
  assert.ok(b.links.some((l) => l[0] === 'workflow-automation.html') && b.wf.items.length >= 2 && b.wf.teams.some((x) => x.team === 'dba'));
  e.app.addons.workflow = { attention: () => { throw new Error('synthetic failure'); } };
  const b2 = (await call('GET', '/role-brief/itm', undefined, ITM)).json; assert.ok(b2.notes.includes('Workflow Automation could not be read')); assert.equal(b2.wf, null); assert.equal(b2.kpis.wf_attention, null);
});

test('CISO brief: Workflow Automation - what the CISO office asked the IT teams for that is late, results to accept, never their own approval', async (t) => {
  const { e, call } = await setup(t);
  e.app.addons.ciso = { overview: async () => CISO_OV };
  const W = e.app.addons.workflow, A = { user: 'adam.syn', role: 'admin', ip: '' }, me = Object.assign({ ip: '' }, CISO), col = e.app.store.collection('wf_requests');
  W.settingsSave({ version: 0, functions: { ciso: ['rashid.syn', 'deputy.syn'] }, teams: { security: ['sec.syn'], network: ['net.syn'] }, leads: { network: ['rashid.syn'] } }, A);
  const late = W.create({ type: 'vuln-remediation', from: 'ciso', title: 'Criticals on the DMZ', details: 'status', priority: 'high' }, { user: 'deputy.syn', role: 'viewer', ip: '' });
  const lr = col.get(late.id); lr.due = new Date(T0 - 7200000).toISOString(); col.put(lr);
  const done = W.create({ type: 'cert-status', from: 'ciso', title: 'Certificates expiring in Q1', details: 'list' }, me);
  W.act(done.id, 'start', {}, { user: 'sec.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'sec.syn', role: 'operator', ip: '' });
  const own = W.create({ type: 'net-change', from: 'ciso', title: 'Block outbound SMB', details: 'at the edge' }, me);
  const other = W.create({ type: 'net-change', from: 'admin', title: 'Open 443 for the portal', details: 'new portal' }, { user: 'adam.syn', role: 'admin', ip: '' });
  const b = (await call('GET', '/role-brief/ciso', undefined, CISO)).json;
  assert.deepEqual([b.wf.raised_late, b.wf.to_accept, b.wf.approvals, b.wf.raised_open], [1, 1, 1, 2], JSON.stringify(b.wf));
  assert.equal(b.kpis.wf_attention, 3);
  const P = b.priorities.filter((p) => /^Request /.test(p.kind)), byRef = (id) => P.find((p) => p.ref === id);
  assert.equal(byRef(late.id).kind, 'Request late', 'raised by a colleague in the CISO office, late with the security team'); assert.equal(byRef(late.id).score, 45); assert.match(byRef(late.id).text, /Security engineering/);
  assert.equal(byRef(done.id).kind, 'Request to accept'); assert.equal(byRef(other.id).kind, 'Request approval');
  assert.ok(!P.some((p) => p.ref === own.id && p.kind === 'Request approval'), 'never their own request to approve');
  assert.ok(b.brief.some((l) => /Workflow Automation: 2 request\(s\) from you and the CISO office open with the IT teams, 1 late, 1 result\(s\) waiting for your acceptance, 1 request\(s\) waiting for your approval; 1 overdue across the IT teams\./.test(l)), b.brief.join(' / '));
  assert.ok(b.links.some((l) => l[0] === 'workflow-automation.html'));
});
