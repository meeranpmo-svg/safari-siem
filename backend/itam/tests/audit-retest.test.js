// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Automatic re-testing in the Audit Command Center (engine/audit-auto.js) through the real ITAM routes with SYNTHETIC records:
// a finding raised from a use case and marked implemented is re-tested with the SAME use case over the records dated after the
// implementation date; no such records = waiting (never clean); clean -> a closure proposal an auditor of the owning team confirms
// (not the owner, never a service / AI identity) and the finding closes through the team's own engine; exceptions -> reopened
// for the owner, signalled to Notification & Escalation and escalated after escalate_days; a finding with no use case is a manual
// re-test until an auditor links one; the rule auto_retest is an admin setting; roles, validation and audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' };
const AUD2 = { user: 'adel.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' }, OUT = { user: 'zaid.syn', role: 'operator' };
const VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:itaudit', role: 'operator' };
const DAY = 86400000;

async function setup(t) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who), tick: (d) => { clock += d * DAY; }, col: (n) => e.app.store.collection(n) };
}
const auditOf = (e, action) => e.app.store.auditTail(1500).filter((x) => x.action === action);
const leaver = (s, id, last, o = {}) => s.col('offboarding').put(Object.assign({ id, username: id.toLowerCase() + '.syn', last_day: last, requested_by: 'hr.syn', status: 'completed', disable: { approved_by: 'mgr.syn' }, disabled: { at: last + 'T10:00:00Z' } }, o));
function seed(s) {   // 10 leavers before the fix: two disabled late / never (UC-01), one disable approved by the requester (UC-02)
  for (let i = 1; i <= 10; i++) { const last = '2026-12-' + String(10 + i).padStart(2, '0');
    leaver(s, 'OFF-' + i, last, { disable: { approved_by: i === 4 ? 'hr.syn' : 'mgr.syn' }, disabled: i === 2 ? null : { at: (i === 6 ? '2027-01-05' : last) + 'T10:00:00Z' } }); }
}
async function engagement(s) {
  assert.equal((await s.post('/csa/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 4 }, ADM)).status, 200);
  const r = await s.post('/csa/engagements', { title: 'Identity lifecycle 2027 (synthetic)', area: 'iam', auditee_dept: 'IT', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user],
    objectives: ['Leavers lose access on their last day'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD);
  assert.equal(r.status, 200, r.raw); assert.equal((await (await s.post('/csa/engagements/' + r.json.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post('/csa/engagements/' + r.json.id + '/advance', { to: 'fieldwork' }, LEAD))).status, 200); return r.json.id;
}
// raise from the proposals of UC-01 and UC-02, issue, respond, mark implemented (the owner)
async function implemented(s) {
  seed(s); const E = await engagement(s);
  assert.equal((await s.post('/audit-auto/run', {}, LEAD)).status, 200);
  const v = (await s.get('/audit-auto')).json, ids = {};
  for (const uc of ['UC-01', 'UC-02']) {
    const p = v.proposals.find((x) => x.uc === uc && x.state === 'proposed'); assert.ok(p, uc);
    const a = await s.post('/audit-auto/proposals/' + p.id + '/accept', { engagement: E, owner: OWNER.user }, LEAD); assert.equal(a.status, 200, a.raw);
    const id = a.json.finding.id; ids[uc] = id;
    assert.equal((await s.post('/csa/findings/' + id + '/issue', {}, LEAD)).status, 200);
    assert.equal((await s.post('/csa/findings/' + id + '/respond', { response: 'agreed', action_plan: 'fix the leaver process', due: '2027-01-31' }, OWNER)).status, 200);
    assert.equal((await s.post('/csa/findings/' + id + '/implemented', { evidence: 'same-day disable job (synthetic)' }, OWNER)).status, 200);
  }
  return { E, ids };
}
const item = async (s, id, who = LEAD) => (await s.get('/audit-auto', who)).json.retest.find((x) => x.id === id);
const finding = async (s, id) => (await s.get('/csa/findings')).json.find((f) => f.id === id);

test('clean re-test: waiting until records exist, then a closure proposal an auditor of the team confirms; the team engine closes it', async (t) => {
  const s = await setup(t); const { ids } = await implemented(s); const F = ids['UC-01'];
  let it = await item(s, F); assert.equal(it.mode, 'automatic'); assert.equal(it.uc, 'UC-01'); assert.equal(it.retest_state, 'pending'); assert.match(it.how, /raised from proposal AP-/);
  // no leavers dated after the implementation yet: waiting, never clean
  s.tick(1); let r = await s.post('/audit-auto/run', {}, LEAD); assert.equal(r.status, 200, r.raw); assert.ok(r.json.did.retested >= 2); assert.equal(r.json.did.retest_clean, 0);
  it = await item(s, F); assert.equal(it.retest_state, 'waiting'); assert.match(it.why, /no records dated from 2027-01-11/); assert.equal(it.closure, null);
  // clean leavers after the fix
  leaver(s, 'OFF-11', '2027-01-11'); leaver(s, 'OFF-12', '2027-01-12');
  s.tick(2); r = await s.post('/audit-auto/run', {}, LEAD); assert.equal(r.json.did.retest_clean, 2);
  it = await item(s, F); assert.equal(it.retest_state, 'proposed'); assert.equal(it.closure.n, 2); assert.equal(it.closure.ex, 0); assert.match(it.closure.id, /^RT-\d{5}$/); assert.equal(it.closure.from, '2027-01-11');
  assert.equal(it.can_decide, true); assert.equal((await item(s, F, OWNER)).can_decide, false, 'the owner gets no buttons'); assert.equal((await item(s, F, OUT)).can_decide, false);
  assert.equal((await finding(s, F)).state, 'implemented', 'a proposal changes nothing');
  assert.ok(auditOf(s.e, 'audit-auto.retest.propose_close').some((x) => x.target === F && x.detail.population === 2));
  // who may confirm
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', {}, OWNER)).status, 403, 'the owner never confirms their own remediation');
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', {}, BOT)).status, 403, 'an AI identity never confirms');
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', {}, OUT)).status, 403, 'not an auditor of the owning team');
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', {}, VIEW)).status, 403, 'viewers are refused');
  assert.equal((await s.post('/audit-auto/retests/bad_id/confirm', {}, AUD2)).status, 400);
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', { note: 'x'.repeat(1200) }, AUD2)).status, 400);
  const c = await s.post('/audit-auto/retests/' + F + '/confirm', { note: 'checked the job log (synthetic)' }, AUD2); assert.equal(c.status, 200, c.raw);
  assert.equal(c.json.finding.state, 'closed');
  const f = await finding(s, F); assert.equal(f.state, 'closed'); assert.equal(f.retested_by, AUD2.user); assert.match(f.retest_note, /automatic re-test RT-\d{5}.*2 .*record\(s\) dated from 2027-01-11, 0 exceptions/);
  assert.ok(auditOf(s.e, 'csa.finding.retest').some((x) => x.target === F && x.by === AUD2.user), 'closed through the team engine');
  const au = auditOf(s.e, 'audit-auto.retest.confirm').find((x) => x.target === F); assert.equal(au.by, AUD2.user); assert.equal(au.detail.exceptions, 0);
  assert.equal((await s.post('/audit-auto/retests/' + F + '/confirm', {}, AUD2)).status, 409, 'nothing left to confirm');
  const d = await s.get('/audit-auto/retests/' + F); assert.equal(d.status, 200); assert.ok(d.json.record.history.length >= 2); assert.deepEqual(d.json.record.history.map((h) => h.result), ['not_testable', 'clean']);
  assert.equal((await s.get('/audit-auto/retests/' + F, VIEW)).status, 403);
  assert.equal((await s.get('/audit-auto/retests/CSF-999')).status, 404);
});

test('failed re-test: reopened for the owner with the new exceptions, signalled, escalated after escalate_days; a stale proposal is not confirmed', async (t) => {
  const s = await setup(t); const { ids } = await implemented(s); const F1 = ids['UC-01'], F2 = ids['UC-02'];
  leaver(s, 'OFF-11', '2027-01-11'); leaver(s, 'OFF-12', '2027-01-12', { disable: { approved_by: 'hr.syn' } });   // the requester approved their own disable again
  s.tick(3);
  assert.equal((await s.post('/audit-auto/retests/' + F2 + '/run', {}, VIEW)).status, 403);
  assert.equal((await s.post('/audit-auto/retests/' + F2 + '/run', {}, BOT)).status, 403, 'a person asks for a re-test');
  const r = await s.post('/audit-auto/retests/' + F2 + '/run', {}, LEAD); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'exceptions');
  assert.deepEqual(r.json.retest.exceptions.map((x) => x.id), ['OFF-12']); assert.equal(r.json.retest.n, 2);
  const f = await finding(s, F2); assert.equal(f.state, 'responded', 'back with the owner'); assert.match(f.retest_note, /1 of 2 record\(s\) dated from 2027-01-11 failed - first: OFF-12/);
  assert.ok(auditOf(s.e, 'csa.finding.auto-reopen').some((x) => x.target === F2 && x.by === 'system:audit-auto'));
  assert.ok(auditOf(s.e, 'audit-auto.retest.reopen').some((x) => x.target === F2 && x.by === LEAD.user && x.detail.exceptions === 1));
  const it = await item(s, F2); assert.equal(it.retest_state, 'reopened'); assert.deepEqual(it.exceptions.map((x) => x.id), ['OFF-12']);
  assert.equal((await s.post('/audit-auto/retests/' + F2 + '/run', {}, LEAD)).status, 409, 'not implemented any more');
  let sig = s.e.app.addons.auditAuto.signals().find((x) => x.ref === F2);
  assert.ok(sig && sig.source === 'audit' && sig.severity === 2 && /failed its automatic re-test - reopened for omar\.syn/.test(sig.title), JSON.stringify(sig));
  // F1 was proposed for closing; a failure that appears before an auditor confirms reopens it instead
  await s.post('/audit-auto/run', {}, LEAD); assert.equal((await item(s, F1)).retest_state, 'proposed');
  leaver(s, 'OFF-13', '2027-01-13', { disabled: null });
  const c = await s.post('/audit-auto/retests/' + F1 + '/confirm', {}, AUD2); assert.equal(c.status, 409); assert.match(c.json.error, /reopened/);
  assert.equal((await finding(s, F1)).state, 'responded');
  // escalation through the follow-ups after escalate_days (30)
  s.tick(31); await s.post('/audit-auto/run', {}, LEAD);
  sig = s.e.app.addons.auditAuto.signals().find((x) => x.ref === F2); assert.ok(sig && sig.severity === 3 && /escalated/.test(sig.title), JSON.stringify(sig));
  assert.ok(auditOf(s.e, 'audit-auto.escalate').some((x) => x.target === 'retest:' + F2));
  // the owner implements again: a new cycle, the failure signal clears
  assert.equal((await s.post('/csa/findings/' + F2 + '/implemented', { evidence: 'four-eyes enforced in the form (synthetic)' }, OWNER)).status, 200);
  await s.post('/audit-auto/run', {}, LEAD);
  assert.ok(!s.e.app.addons.auditAuto.signals().some((x) => x.ref === F2 && /re-test/.test(x.title)));
  assert.notEqual((await item(s, F2)).retest_state, 'reopened');
  assert.ok((await s.get('/audit-auto/retests/' + F2)).json.record.history.length >= 2, 'the history is kept across cycles');
});

test('reject a closure proposal; manual re-test for a finding with no use case until an auditor links one; settings auto_retest', async (t) => {
  const s = await setup(t); const { E, ids } = await implemented(s); const F1 = ids['UC-01'];
  leaver(s, 'OFF-11', '2027-01-11'); s.tick(2); await s.post('/audit-auto/run', {}, LEAD);
  assert.equal((await s.post('/audit-auto/retests/' + F1 + '/reject', { reason: 'short' }, AUD2)).status, 400);
  assert.equal((await s.post('/audit-auto/retests/' + F1 + '/reject', { reason: 'one record is too few to conclude (synthetic)' }, OWNER)).status, 403);
  const rj = await s.post('/audit-auto/retests/' + F1 + '/reject', { reason: 'one record is too few to conclude (synthetic)' }, AUD2); assert.equal(rj.status, 200, rj.raw);
  assert.equal(rj.json.state, 'rejected'); assert.equal((await finding(s, F1)).state, 'implemented');
  assert.ok(auditOf(s.e, 'audit-auto.retest.reject').some((x) => x.target === F1 && x.by === AUD2.user));
  await s.post('/audit-auto/run', {}, LEAD); assert.equal((await item(s, F1)).retest_state, 'rejected', 'not proposed again for the same implementation');
  // a finding raised by hand: manual
  const m = await s.post('/csa/engagements/' + E + '/findings', { title: 'Service accounts without a named owner (synthetic)', condition: 'c', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: OWNER.user }, LEAD);
  const M = m.json.id; await s.post('/csa/findings/' + M + '/issue', {}, LEAD);
  await s.post('/csa/findings/' + M + '/respond', { response: 'agreed', action_plan: 'name owners', due: '2027-01-31' }, OWNER);
  await s.post('/csa/findings/' + M + '/implemented', { evidence: 'owners named (synthetic)' }, OWNER);
  let it = await item(s, M); assert.equal(it.mode, 'manual'); assert.match(it.why, /Manual re-test.*corrected records/);
  assert.equal((await s.post('/audit-auto/retests/' + M + '/run', {}, LEAD)).status, 409, 'nothing to re-test with');
  assert.equal((await s.post('/audit-auto/retests/' + M + '/link', { uc: 'UC-99' }, LEAD)).status, 400);
  assert.equal((await s.post('/audit-auto/retests/' + M + '/link', { uc: 'UC-13' }, OWNER)).status, 403, 'the owner does not choose the test');
  assert.equal((await s.post('/audit-auto/retests/' + F1 + '/link', { uc: 'UC-13' }, LEAD)).status, 409, 'raised from a proposal: already linked');
  const lk = await s.post('/audit-auto/retests/' + M + '/link', { uc: 'UC-13' }, LEAD); assert.equal(lk.status, 200, lk.raw); assert.equal(lk.json.link.uc, 'UC-13');
  assert.ok(auditOf(s.e, 'audit-auto.retest.link').some((x) => x.target === M && x.detail.uc === 'UC-13'));
  it = await item(s, M); assert.equal(it.mode, 'automatic');
  const rn = await s.post('/audit-auto/retests/' + M + '/run', {}, LEAD); assert.equal(rn.status, 200, rn.raw); assert.equal(rn.json.result, 'not_testable', 'no service accounts recorded: waiting, never clean');
  // settings: auto_retest is named and admin-only; off -> the daily run does not re-test
  const base = { draft_findings: true, follow_up: true, escalate: true, retest_due: true, period_days: 90, escalate_days: 30, version: 0 };
  let r = await s.post('/audit-auto/settings', base, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /auto_retest/);
  assert.equal((await s.post('/audit-auto/settings', Object.assign({}, base, { auto_retest: false }), LEAD)).status, 403);
  r = await s.post('/audit-auto/settings', Object.assign({}, base, { auto_retest: false }), ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.rules.auto_retest, false);
  assert.equal((await s.post('/audit-auto/run', {}, LEAD)).json.did.retested, 0);
  assert.equal((await item(s, M)).mode, 'off');
  assert.ok(auditOf(s.e, 'audit-auto.settings').some((x) => x.detail.rules.auto_retest === false));
});
