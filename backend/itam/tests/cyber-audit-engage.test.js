// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The Cyber Security Audit Team (engine/audit-engage.js, kind "cyber", routes /csa/*) through the real routes: its own
// records, Head of Audit and ids, kept apart from the IT Audit Team; the cyber universe (NCA ECC / SAMA CSF areas) with
// itemised scores; cyber sample populations (access review decisions, end-of-life exceptions, service accounts) with
// suggested attribute tests; four eyes on the plan, workpapers and report; the finding lifecycle; the brief and the duty
// desk; roles (viewer refused, admin-only profile), validation errors naming the field and the audit records. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'basma.syn', role: 'operator' }, LEAD = { user: 'tariq.syn', role: 'operator' };
const AUD2 = { user: 'reem.syn', role: 'operator' }, OWNER = { user: 'yasir.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, ITHEAD = { user: 'hana.syn', role: 'operator' };
const DAY = 86400000;

async function setup(t) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who), tick: (d) => { clock += d * DAY; }, store: (n) => e.app.store.collection(n) };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
async function profile(s) { const r = await s.post('/csa/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 6 }, ADM); assert.equal(r.status, 200, r.raw); }

test('a separate team: own profile, own records, own ids; viewers refused', async (t) => {
  const s = await setup(t); await profile(s);
  await s.post('/ia/profile', { head_of_audit: ITHEAD.user, auditors: [LEAD.user] }, ADM);
  assert.equal((await s.get('/csa/profile')).json.head_of_audit, HEAD.user);
  assert.equal((await s.get('/ia/profile')).json.head_of_audit, ITHEAD.user, 'the IT team keeps its own Head of Audit');
  assert.equal((await s.post('/csa/profile', { head_of_audit: HEAD.user }, LEAD)).status, 403);
  for (const p of ['/csa/profile', '/csa/plans', '/csa/engagements', '/csa/findings', '/csa/brief', '/csa/areas', '/csa/populations']) assert.equal((await s.get(p, VIEW)).status, 403, p);
  const areas = (await s.get('/csa/areas')).json.map((a) => a.id);
  assert.ok(['iam', 'privileged', 'nhi', 'monitoring', 'incident', 'email', 'thirdparty'].every((a) => areas.includes(a)), 'the cyber universe');
  const pops = (await s.get('/csa/populations')).json.map((p) => p.id);
  assert.deepEqual(pops.sort(), ['access_reviews', 'changes', 'exceptions', 'isolations', 'leavers', 'nhi', 'privileged']);
  const r = await s.post('/csa/engagements', { title: 'PAM 2026 (synthetic)', area: 'privileged', auditee_dept: 'IT Operations', auditee_owner: OWNER.user, lead: LEAD.user, start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD);
  assert.equal(r.status, 200, r.raw); assert.match(r.json.id, /^CSE-2027-\d{3}$/);
  const bad = await s.post('/csa/engagements', { title: 'x', area: 'joiners', auditee_dept: 'HR', auditee_owner: OWNER.user, lead: LEAD.user, start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD);
  assert.equal(bad.status, 400); assert.match(bad.json.error, /area/, 'an IT-only area is not in the cyber universe');
  assert.equal((await s.get('/ia/engagements')).json.length, 0, 'the IT team does not see cyber engagements');
  assert.equal(auditOf(s.e, 'csa.engagement.create').length, 1); assert.equal(auditOf(s.e, 'ia.engagement.create').length, 0);
});

test('cyber plan: ECC-mapped areas scored from the risk register; the Head of Audit approves, not the preparer', async (t) => {
  const s = await setup(t); await profile(s);
  s.store('grc_risks').put({ id: 'RSK-0007', status: 'open', description: 'Privileged accounts without PAM vaulting (synthetic)', category: 'Cyber', likelihood: 5, impact: 5, owner: OWNER.user });
  const p = await s.post('/csa/plans/propose', { year: 2027 }, LEAD); assert.equal(p.status, 200, p.raw);
  assert.equal(p.json.id, 'CSPLAN-2027');
  const pr = p.json.items.find((x) => x.area === 'privileged');
  assert.ok(pr.why.some((w) => w.source === 'risk register' && w.refs.includes('RSK-0007') && w.points === 30));
  assert.equal(pr.score, pr.why.reduce((n, w) => n + w.points, 0));
  assert.equal(p.json.items.filter((x) => x.include).length, 6);
  await s.post('/csa/plans/CSPLAN-2027/submit', {}, LEAD);
  assert.equal((await s.post('/csa/plans/CSPLAN-2027/decide', { decision: 'approve' }, ITHEAD)).status, 403, 'the IT Head of Audit is not this team\'s approver');
  assert.equal((await s.post('/csa/plans/CSPLAN-2027/decide', { decision: 'approve' }, HEAD)).status, 200);
  assert.equal(auditOf(s.e, 'csa.plan.approve')[0].by, HEAD.user);
  const e = await s.post('/csa/engagements', { title: 'PAM (synthetic)', area: 'privileged', auditee_dept: 'IT Operations', auditee_owner: OWNER.user, lead: LEAD.user, start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15', plan_item: 'PLAN-2027:privileged' }, LEAD);
  assert.equal(e.status, 400); assert.match(e.json.error, /plan_item.*CSPLAN-<year>/);
  assert.equal((await s.post('/csa/engagements', { title: 'PAM (synthetic)', area: 'privileged', auditee_dept: 'IT Operations', auditee_owner: OWNER.user, lead: LEAD.user, start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15', plan_item: 'CSPLAN-2027:privileged' }, LEAD)).status, 200);
});

test('cyber sampling: access review decisions and end-of-life exceptions with suggested tests; the finding lifecycle and the report', async (t) => {
  const s = await setup(t); await profile(s);
  const ar = s.store('access_review_items');
  ar.put({ id: 'ARI-1', campaign: 'AR-1', group: 'GG-Finance', user: 'a.syn', reviewer: 'mgr.syn', decision: 'keep', decided_by: 'mgr.syn', decided_at: '2026-11-01T10:00:00Z', state: 'decided' });
  ar.put({ id: 'ARI-2', campaign: 'AR-1', group: 'Domain Admins', user: 'b.syn', reviewer: 'mgr.syn', decision: 'remove', reason: 'left the team', decided_by: 'mgr.syn', decided_at: '2026-11-01T10:00:00Z', removal: { decision: 'approve', by: 'mgr.syn' }, state: 'removal_approved' });
  ar.put({ id: 'ARI-3', campaign: 'AR-1', group: 'GG-HR', user: 'c.syn', reviewer: 'mgr.syn', decision: 'keep', decided_by: 'someone.else', decided_at: '2026-11-02T10:00:00Z', state: 'decided' });
  const ex = s.store('lifecycle_exceptions');
  ex.put({ id: 'EXC-1', key: 'sw-old-01', state: 'approved', requested_by: 'net.syn', decided_by: 'net.syn', compensating: '', expires: '2026-12-01', created_at: '2025-06-01T08:00:00Z' });
  const e = (await s.post('/csa/engagements', { title: 'Access governance (synthetic)', area: 'iam', auditee_dept: 'IT Operations', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user], objectives: ['Access reviews are decided and enforced'], scope: '2026 campaigns', start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD)).json, E = '/csa/engagements/' + e.id;
  await (await s.post(E + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post(E + '/advance', { to: 'fieldwork' }, LEAD));
  let r = await s.post(E + '/samples', { population: 'payroll', size: 2, method: 'random' }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /population/);
  r = await s.post(E + '/samples', { population: 'access_reviews', size: 3, method: 'random', seed: 99 }, LEAD); assert.equal(r.status, 200, r.raw);
  const smp = r.json; assert.match(smp.id, /^CSS-\d{3}$/); assert.equal(smp.population_size, 3);
  const sug = (ref, t0) => smp.items.find((i) => i.ref === ref).suggested.find((x) => x.test.startsWith(t0)).ok;
  assert.equal(sug('ARI-1', 'Decided by the assigned'), true);
  assert.equal(sug('ARI-3', 'Decided by the assigned'), false, 'decided by someone who was not the reviewer');
  assert.equal(sug('ARI-2', 'Removal approved by someone other'), false, 'the reviewer approved their own removal');
  assert.equal(sug('ARI-2', 'An approved removal was carried out'), false, 'approved but never removed');
  const x = (await s.post(E + '/samples', { population: 'exceptions', size: 1, method: 'judgemental', refs: ['EXC-1'] }, AUD2)).json;
  const xs = (t0) => x.items[0].suggested.find((y) => y.test.startsWith(t0)).ok;
  assert.equal(xs('Approved by someone other'), false); assert.equal(xs('A compensating control'), false); assert.equal(xs('Expiry within one year'), false); assert.equal(xs('Not expired'), false);
  for (const it of smp.items) await s.post('/csa/samples/' + smp.id + '/items/' + it.ref, it.ref === 'ARI-1' ? { result: 'pass' } : { result: 'exception', note: 'confirmed in the campaign record (synthetic)' }, LEAD);
  await s.post('/csa/samples/' + x.id + '/items/EXC-1', { result: 'exception', note: 'self-approved, no compensating control (synthetic)' }, AUD2);
  const w = (await s.post(E + '/workpapers', { title: 'Access review enforcement', objective: 'Removals are approved by a second person and carried out', procedure: 'Inspect sampled decisions', sample: smp.id }, LEAD)).json;
  assert.match(w.id, /^CWP-\d{3}$/);
  await s.post('/csa/workpapers/' + w.id + '/conclude', { conclusion: 'ineffective', summary: 'Two of three decisions failed (synthetic)' }, LEAD);
  assert.equal((await s.post('/csa/workpapers/' + w.id + '/review', { decision: 'accept' }, LEAD)).status, 403, 'the preparer cannot review');
  assert.equal((await s.post('/csa/workpapers/' + w.id + '/review', { decision: 'accept' }, HEAD)).status, 200);
  r = await s.post(E + '/findings', { title: 'Access review removals not enforced', condition: 'c', criteria: 'NCA ECC 2-2-3', cause: 'ca', effect: 'ef', recommendation: 're', rating: 'high', owner: OWNER.user, samples: [smp.id + '/ARI-2'] }, LEAD);
  assert.equal(r.status, 200, r.raw); const f = r.json; assert.match(f.id, /^CSF-\d{3}$/);
  await s.post('/csa/findings/' + f.id + '/issue', {}, LEAD);
  assert.equal((await s.post('/csa/findings/' + f.id + '/respond', { response: 'Agreed', action_plan: 'Enforce removals', due: '2027-02-01' }, LEAD)).status, 403, 'only the owner responds');
  assert.equal((await s.post('/csa/findings/' + f.id + '/respond', { response: 'Agreed', action_plan: 'Enforce removals automatically', due: '2027-02-01' }, OWNER)).status, 200);
  await s.post(E + '/advance', { to: 'draft_report' }, LEAD);
  await s.post(E + '/report/summary', { summary: 'Access review removals are not enforced; one high finding (synthetic).' }, LEAD);
  assert.equal((await s.post(E + '/report/sign', {}, LEAD)).status, 200);
  assert.equal((await s.post(E + '/report/approve', {}, ITHEAD)).status, 403, 'the IT Head of Audit cannot approve a cyber report');
  r = await s.post(E + '/report/approve', {}, HEAD); assert.equal(r.status, 200, r.raw); assert.equal(r.json.opinion, 'Unsatisfactory'); assert.match(r.json.hash, /^[0-9a-f]{64}$/);
  // overdue: brief and duty desk
  s.tick(30);
  assert.ok((await s.get('/csa/brief')).json.items.some((y) => y.kind === 'finding-overdue' && y.ref === f.id));
  await s.post('/duty/patrol', { engineer: 'csa' }, ADM);
  const items = (await s.get('/duty/items?engineer=csa')).json; assert.ok((items.items || items).some((y) => y.key === 'csa:finding-overdue:' + f.id));
  for (const a of ['csa.sample.draw', 'csa.sample.conclude', 'csa.workpaper.reviewed', 'csa.finding.raise', 'csa.finding.respond', 'csa.report.sign', 'csa.report.approve']) assert.ok(auditOf(s.e, a).length, a);
});
