// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit and PDPL Automation Flows (engine/automation-flow.js) through the real ITAM routes with SYNTHETIC records: modules not installed
// read "not installed" (never zeros); installed modules with no records say what to connect; seeded use-case runs, control monitoring,
// proposals and findings moved through the Cyber Security Audit Team's own engine (draft -> issued -> responded -> implemented ->
// closed) are counted per stage, the stuck items listed oldest first with age and owner, the median cycle time from the records'
// timestamps, the bottleneck named; re-tests read defensively ("re-test not yet recorded" until audit_auto_retests holds one); PDPL:
// the 30-day request clock and the 72-hour breach clock, Privacy Office tasks, verified closed; roles (viewer refused), validation
// errors naming the field, the audit record of each view, and nothing written by a view.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createAutomationFlow, registerAutomationFlow } = require('../engine/automation-flow');

const ADM = { user: 'adam.syn', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' };
const AUD2 = { user: 'adel.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000, T0 = Date.parse('2027-03-01T08:00:00Z');

async function setup(t, { duty = true } = {}) {
  let clock = T0;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  if (duty) registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  if (!e.app.addons || !e.app.addons.automationFlow || !duty) registerAutomationFlow(e.app.srv, e.app, createAutomationFlow(e.app, { now: () => clock, consentTimeoutMs: 3000 }));
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who), tick: (d) => { clock += d * DAY; }, at: () => clock, col: (n) => e.app.store.collection(n) };
}
const st = (v, id) => v.stages.find((x) => x.id === id) || v.lanes.find((x) => x.id === id);
const iso = (t) => new Date(t).toISOString();

test('a module that is not installed reads "not installed" - never zeros', async (t) => {
  const s = await setup(t, { duty: false });
  for (const p of ['/audit-flow', '/pdpl-flow']) {
    const r = await s.get(p); assert.equal(r.status, 200, r.text);
    for (const x of r.json.stages.concat(r.json.lanes)) { assert.equal(x.status, 'missing', p + ' ' + x.id); assert.equal(x.count, null); assert.deepEqual(x.lines, ['not installed']); assert.equal(x.installed, false); }
    assert.equal(r.json.bottleneck.stage, null); assert.equal(r.json.kpis.working, 0);
  }
});

test('installed with no records: every stage says what to connect, nothing is lit as working', async (t) => {
  const s = await setup(t);
  const a = (await s.get('/audit-flow')).json;
  assert.ok(a.stages.length >= 9 && a.lanes.length === 3);
  for (const x of a.stages.concat(a.lanes)) { assert.equal(x.installed, true, x.id); assert.equal(x.status, 'off', x.id + ' ' + x.status); assert.ok(x.gap && x.gap.length > 10, x.id + ' says what to connect'); assert.equal(x.stuck, 0); }
  assert.match(st(a, 'tests').gap, /no use-case run yet/); assert.match(st(a, 'engaged').gap, /engagement/);
  const p = (await s.get('/pdpl-flow')).json;
  for (const x of p.stages) { assert.equal(x.installed, true, x.id); assert.equal(x.status, 'off', x.id); assert.ok(x.gap, x.id); }
  assert.match(st(p, 'requests').gap, /data subject request/); assert.match(st(p, 'consent').gap, /consent purpose/);
});

test('audit: stages counted from the records, stuck items oldest first with owner, cycle times, the bottleneck, re-tests read defensively', async (t) => {
  const s = await setup(t);
  // synthetic use-case runs: UC-01 fails in the last two runs (streak from day -10), UC-06 failed then went clean (a 4-day cycle)
  const run = (d, res) => s.col('audit_auto_runs').put({ id: iso(T0 - d * DAY), at: iso(T0 - d * DAY), by: 'laila.syn', results: res });
  run(20, { 'UC-06': { n: 4, ex: 1, status: 'exceptions' }, 'UC-01': { n: 10, ex: 0, status: 'effective' } });
  run(16, { 'UC-06': { n: 4, ex: 0, status: 'effective' }, 'UC-01': { n: 10, ex: 0, status: 'effective' } });
  run(10, { 'UC-06': { n: 4, ex: 0, status: 'effective' }, 'UC-01': { n: 10, ex: 2, status: 'exceptions' } });
  run(1, { 'UC-06': { n: 4, ex: 0, status: 'effective' }, 'UC-01': { n: 10, ex: 2, status: 'exceptions' } });
  s.col('audit_auto_proposals').put({ id: 'AP-001', uc: 'UC-01', team: 'cyber', team_name: 'Cyber Security Audit Team', state: 'proposed', at: iso(T0 - 9 * DAY), by: 'laila.syn', title: 'Leavers disabled late (synthetic) <img src=x onerror=alert(1)>' });
  s.col('audit_auto_proposals').put({ id: 'AP-002', uc: 'UC-02', team: 'cyber', team_name: 'Cyber Security Audit Team', state: 'dismissed', at: iso(T0 - 12 * DAY), decided_at: iso(T0 - 10 * DAY), by: 'laila.syn', title: 'synthetic' });
  // the Cyber Security Audit Team: one engagement in fieldwork, findings moved through its own engine
  assert.equal((await s.post('/csa/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 4 }, ADM)).status, 200);
  const eg = await s.post('/csa/engagements', { title: 'Identity lifecycle (synthetic)', area: 'iam', auditee_dept: 'IT', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user],
    objectives: ['Leavers lose access on their last day'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: '2027-01-10', fieldwork_end: '2027-04-30', report_due: '2027-05-15' }, LEAD);
  assert.equal(eg.status, 200, eg.text); assert.equal((await (await s.post('/csa/engagements/' + eg.json.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post('/csa/engagements/' + eg.json.id + '/advance', { to: 'fieldwork' }, LEAD))).status, 200);
  s.tick(-30);   // findings raised 30 days ago
  const mk = async (title) => { const f = await s.post('/csa/engagements/' + eg.json.id + '/findings', { title, condition: 'c (synthetic)', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: OWNER.user }, LEAD); assert.equal(f.status, 200, f.text); return f.json.id; };
  const act = async (id, a, b, who) => { const r = await s.post('/csa/findings/' + id + '/' + a, b, who); assert.equal(r.status, 200, a + ' ' + r.text); };
  const fDraft = await mk('Draft finding (synthetic)'), fIssued = await mk('Issued finding (synthetic)'), fResp = await mk('Responded finding (synthetic)'), fImpl = await mk('Implemented finding (synthetic)'), fClosed = await mk('Closed finding (synthetic)');
  s.tick(2); for (const id of [fIssued, fResp, fImpl, fClosed]) await act(id, 'issue', {}, LEAD);
  s.tick(3); for (const id of [fResp, fImpl, fClosed]) await act(id, 'respond', { response: 'agreed (synthetic)', action_plan: 'fix (synthetic)', due: '2027-02-20' }, OWNER);
  s.tick(5); for (const id of [fImpl, fClosed]) await act(id, 'implemented', { evidence: 'ticket SYN-1' }, OWNER);
  s.tick(4); await act(fClosed, 'retest', { result: 'closed', note: 'clean re-test (synthetic)' }, LEAD);
  s.tick(16);   // back to T0
  assert.equal(s.at(), T0);
  const before = s.e.app.store.auditTail(2000).length;
  const r = await s.get('/audit-flow'); assert.equal(r.status, 200, r.text); const v = r.json;
  // sources and use-case tests
  assert.match(st(v, 'sources').lines.join(' '), /2\/\d+ sources with records/); assert.ok(st(v, 'sources').gaps.some((g) => /^connect /.test(g)));
  const tests = st(v, 'tests'); assert.equal(tests.count, 2); assert.equal(tests.status, 'part'); assert.match(tests.lines.join(' '), /4 run\(s\)/);
  assert.equal(tests.items[0].id, 'UC-01'); assert.equal(tests.items[0].age_days, 10, 'stuck since the first run of the failing streak'); assert.equal(tests.items[0].owner, 'Cyber Security Audit Team');
  assert.equal(tests.cycle.median_days, 4); assert.equal(tests.cycle.n, 1);
  // proposed findings
  const pr = st(v, 'proposed'); assert.equal(pr.count, 1); assert.equal(pr.items[0].id, 'AP-001'); assert.equal(pr.items[0].age_days, 9); assert.match(pr.items[0].title, /<img src=x/, 'record text returned as data (the page escapes it)'); assert.equal(pr.cycle.median_days, 2);
  // the findings, stage by stage
  const en = st(v, 'engaged'); assert.equal(en.count, 5); assert.equal(en.items.length, 1); assert.equal(en.items[0].id, fDraft); assert.equal(en.items[0].owner, LEAD.user); assert.equal(en.items[0].age_days, 30);
  assert.match(en.lines.join(' '), /1 engagement\(s\) in fieldwork/); assert.match(en.lines.join(' '), /Cyber 5/); assert.equal(en.cycle.median_days, 2); assert.equal(en.cycle.n, 4);
  const ow = st(v, 'owners'); assert.equal(ow.count, 2); assert.deepEqual(ow.items.map((x) => x.id), [fIssued, fResp], 'oldest first'); assert.equal(ow.items[0].age_days, 28); assert.equal(ow.items[0].owner, OWNER.user);
  assert.ok(ow.items[1].overdue, 'past its due date'); assert.match(ow.lines.join(' '), /1 overdue/); assert.equal(ow.cycle.median_days, 8);
  const rt = st(v, 'retest'); assert.equal(rt.count, 1); assert.equal(rt.items[0].id, fImpl); assert.match(rt.lines.join(' '), /re-test not yet recorded/); assert.match(rt.items[0].waiting_for, /re-test not yet recorded/);
  assert.equal(rt.cycle.median_days, 4);
  const cl = st(v, 'closed'); assert.equal(cl.count, 1); assert.equal(cl.status, 'ok'); assert.equal(cl.cycle.median_days, 14);
  // the bottleneck: owners holds the most stuck days (28 + 25)
  assert.equal(v.bottleneck.stage, 'owners'); assert.match(v.bottleneck.why, /2 item\(s\) stuck/);
  // nothing written by the view except its audit record (who read it)
  const tail = s.e.app.store.auditTail(2000); assert.equal(tail.length, before + 1);
  const a = tail[0]; assert.equal(a.action, 'automation-flow.view'); assert.equal(a.by, LEAD.user); assert.equal(a.role, 'operator'); assert.equal(a.target, 'audit'); assert.equal(a.detail.bottleneck, 'owners');
  // the stuck threshold is the caller's: 30 days leaves only the 30-day draft
  const w = (await s.get('/audit-flow?stuck_days=30')).json; assert.equal(st(w, 'owners').stuck, 1, 'overdue stays stuck'); assert.equal(st(w, 'engaged').stuck, 1); assert.equal(st(w, 'proposed').stuck, 0); assert.equal(w.stuck_days, 30);
  // an automatic re-test recorded by audit-auto (audit_auto_retests) is read when present
  s.col('audit_auto_retests').put({ id: 'RT-1', finding: fImpl, result: 'waiting', at: iso(T0 - DAY) });
  const v2 = (await s.get('/audit-flow')).json; assert.match(st(v2, 'retest').lines.join(' '), /automatic: 0 clean · 0 failed/); assert.match(st(v2, 'retest').items[0].waiting_for, /waiting for records after the implementation date/);
  // escalations beside the flow
  s.col('audit_auto_followups').put({ id: 'finding:' + fResp, kind: 'finding', ref: fResp, title: 'Responded finding (synthetic)', owner: OWNER.user, days: 9, page: 'cyber-audit-team.html', source: 'Cyber Security Audit Team', open: true, escalated: iso(T0), first_at: iso(T0 - 9 * DAY) });
  const esc = st((await s.get('/audit-flow')).json, 'escalations'); assert.equal(esc.count, 1); assert.equal(esc.items[0].owner, OWNER.user); assert.match(esc.items[0].waiting_for, /escalated/);
});

test('audit: control monitoring and analytics waiting items, oldest first', async (t) => {
  const s = await setup(t);
  const ex = (id, at) => ({ id, test: 'CT-01', at, by: 'someone.syn', why: 'synthetic' });
  s.col('ccm_runs').put({ id: 'CCM-2027-02-25', day: '2027-02-25', at: iso(T0 - 4 * DAY), records: 50, summary: { effective: 6, exceptions: 1, not_testable: 1 }, tests: [{ id: 'CT-01', name: 'Segregation of duties', exceptions: [ex('CT-01.a', '2027-02-24'), ex('CT-01.c', '2027-02-24')] }] });
  s.col('ccm_runs').put({ id: 'CCM-2027-03-01', day: '2027-03-01', at: iso(T0), records: 60, summary: { effective: 6, exceptions: 1, not_testable: 1 }, tests: [{ id: 'CT-01', name: 'Segregation of duties', exceptions: [ex('CT-01.a', '2027-02-24'), ex('CT-01.b', '2027-02-28'), ex('CT-01.c', '2027-02-28')] }] });
  s.col('ccm_dispositions').put({ id: 'CT-01.c', test: 'CT-01', decision: 'explained', note: 'synthetic note', by: 'adel.syn', at: iso(T0 - 0.5 * DAY) });
  s.col('aa_runs').put({ id: 'AAR-1', test: 'duplicates', dataset: 'DS-1', dataset_name: 'Payments SYN', by: 'adel.syn', at: iso(T0 - 8 * DAY), result: { exceptions_total: 3 }, dispositions: {} });
  s.col('aa_runs').put({ id: 'AAR-2', test: 'gaps', dataset: 'DS-1', dataset_name: 'Payments SYN', by: 'adel.syn', at: iso(T0 - 6 * DAY), result: { exceptions_total: 1 }, review: { by: 'laila.syn', at: iso(T0 - 4 * DAY) } });
  const v = (await s.get('/audit-flow?stuck_days=3')).json, c = st(v, 'ccm'), an = st(v, 'analytics');
  assert.equal(c.count, 60); assert.equal(c.waiting, 2, 'two open exceptions (one has a disposition)'); assert.deepEqual(c.items.map((x) => x.id), ['CT-01.a'], 'only the one first seen 4 days ago is stuck at 3 days');
  assert.equal(c.items[0].age_days, 4); assert.match(c.lines.join(' '), /2 open exception/);
  assert.equal(c.cycle.median_days, 3.5); assert.ok(c.items.every((x) => !/someone\.syn/.test(JSON.stringify(x))), 'the person an exception is about is not named as its owner');
  assert.equal(an.count, 2); assert.equal(an.items[0].id, 'AAR-1'); assert.equal(an.items[0].age_days, 8); assert.equal(an.items[0].owner, 'adel.syn'); assert.equal(an.cycle.median_days, 2);
});

test('pdpl: requests on the 30-day clock, breaches on the 72-hour clock, office tasks, verified closed', async (t) => {
  const s = await setup(t);
  const rec = async (b) => { const r = await s.post('/pdpl/records', b, LEAD); assert.equal(r.status, 200, r.text); return r.json.id; };
  const d1 = await rec({ kind: 'dsr', ref: 'SYN-REQ-1', type: 'access', received: '2027-01-20' });    // 40 days: past 30
  const d2 = await rec({ kind: 'dsr', ref: 'SYN-REQ-2', type: 'copy', received: '2027-02-27' });      // 2 days
  await rec({ kind: 'dsr', ref: 'SYN-REQ-3', type: 'correction', received: '2027-01-01', responded: '2027-01-11' });
  const b1 = await rec({ kind: 'breach', ref: 'SYN-BR-1', aware_at: iso(T0 - 80 * 3600000).slice(0, 16) });
  await rec({ kind: 'breach', ref: 'SYN-BR-2', aware_at: '2027-01-02T08:00', sdaia_notified_at: '2027-01-03T04:00' });
  const ro = await rec({ kind: 'ropa', name: 'Motor claims (synthetic)', purpose: 'claims', legal_basis: 'contract' });
  await rec({ kind: 'dpia', ropa_id: ro }); await rec({ kind: 'transfer', name: 'Reinsurer SYN', country: 'Synthland' }); await rec({ kind: 'processor', name: 'TPA SYN' });
  s.col('pdpl_office_tasks').put({ id: 'PO-00001', key: 'f:syn-1', status: 'open', title: 'Synthetic task <script>x</script>', assignee: 'dpo.syn', first_seen: iso(T0 - 20 * DAY), due: iso(T0 - 6 * DAY), overdue: true, escalation: 1, escalated_to: 'dpo.syn' });
  s.col('pdpl_office_tasks').put({ id: 'PO-00002', key: 'f:syn-2', status: 'closed', title: 'Synthetic done', assignee: 'dpo.syn', first_seen: iso(T0 - 30 * DAY), closed_at: iso(T0 - 18 * DAY) });
  s.col('pdpl_mon_runs').put({ id: 'RUN-1', at: iso(T0 - 3 * DAY), states: { 'S-claims:M01': 'fail', 'S-claims:M02': 'pass' }, drift: [], fixed: [], score: 50, pass: 1, fail: 1, not_measured: 0 });
  s.col('pdpl_mon_runs').put({ id: 'RUN-2', at: iso(T0 - DAY), states: { 'S-claims:M01': 'fail', 'S-claims:M02': 'pass' }, drift: [], fixed: [], score: 50, pass: 1, fail: 1, not_measured: 0 });
  s.col('pdpl_discovery').put({ id: 'db-syn', db: 'db-syn', engine: 'oracle', label: 'claims-db.syn', at: iso(T0 - 9 * DAY), ok: false, error: 'login_denied: synthetic', columns: [] });
  const r = await s.get('/pdpl-flow'); assert.equal(r.status, 200, r.text); const v = r.json;
  const q = st(v, 'requests'); assert.equal(q.count, 3, '2 open requests + 1 open breach');
  assert.equal(q.items[0].id, d1, 'oldest first'); assert.ok(q.items[0].overdue); assert.match(q.items[0].waiting_for, /30-day clock ended/);
  const br = q.items.find((x) => x.id === b1); assert.ok(br && br.overdue); assert.match(br.waiting_for, /72 hours passed 8 h ago/);
  assert.ok(!q.items.some((x) => x.id === d2), 'a 2-day-old request with 28 days left is not stuck'); assert.equal(q.waiting, 3);
  assert.equal(q.cycle.median_days, 10); assert.match(q.lines.join(' '), /notified in a median 20 h/);
  assert.ok(!JSON.stringify(q).includes('SYN-REQ'), 'the request reference is not shown on the flow');
  const as = st(v, 'assess'); assert.equal(as.count, 3); assert.equal(as.waiting, 3); assert.match(as.lines.join(' '), /0\/1 DPIA signed/);
  const of = st(v, 'office'); assert.equal(of.count, 1); assert.equal(of.items[0].owner, 'dpo.syn'); assert.equal(of.items[0].age_days, 20); assert.equal(of.cycle.median_days, 12);
  assert.equal(st(v, 'closed').count, 1); assert.match(st(v, 'closed').lines.join(' '), /1 request\(s\) answered · 1 breach\(es\) notified/);
  const mo = st(v, 'monitor'); assert.equal(mo.waiting, 1); assert.equal(mo.items.length, 0, 'failing 3 days: waiting, not yet stuck at 7'); assert.match(mo.lines.join(' '), /score 50 %/);
  assert.equal(st(v, 'discovery').items[0].age_days, 9); assert.match(st(v, 'discovery').items[0].waiting_for, /login_denied\)/); assert.ok(!/synthetic\)/.test(st(v, 'discovery').items[0].waiting_for), 'only the error class is shown');
  assert.equal(st(v, 'escalations').count, 1);
  assert.ok(v.bottleneck.stage, 'a bottleneck is named'); assert.equal(v.kind, 'pdpl');
  assert.equal(st(v, 'consent').status, 'off'); assert.match(st(v, 'consent').gap, /consent purpose/);
});

test('roles and validation: operators read, viewers are refused, stuck_days validated and named', async (t) => {
  const s = await setup(t);
  for (const p of ['/audit-flow', '/pdpl-flow']) {
    assert.equal((await s.get(p, VIEW)).status, 403, p + ': a viewer is refused (the flow names people)');
    assert.equal((await s.get(p, LEAD)).status, 200); assert.equal((await s.get(p, ADM)).status, 200);
    let r = await s.get(p + '?stuck_days=0'); assert.equal(r.status, 400); assert.match(r.json.error, /stuck_days must be at least 1/);
    r = await s.get(p + '?stuck_days=abc'); assert.equal(r.status, 400); assert.match(r.json.error, /stuck_days must be a whole number/);
    r = await s.get(p + '?stuck_days=999'); assert.equal(r.status, 400); assert.match(r.json.error, /stuck_days must be at most 365/);
    r = await s.get(p + '?stuck_days=14&evil=1'); assert.equal(r.status, 200); assert.equal(r.json.stuck_days, 14);
  }
  const views = s.e.app.store.auditTail(2000).filter((x) => x.action === 'automation-flow.view');
  assert.ok(views.some((x) => x.by === ADM.user && x.role === 'admin' && x.target === 'pdpl'));
  assert.ok(!views.some((x) => x.by === VIEW.user), 'a refused view writes no view record');
});
