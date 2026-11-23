// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL self-assessment (engine/pdpl-assessment.js, pyengine/pdpl_assessment.py): one open assessment per cycle; every answer
// carries evidence (yes / partial) or a note (no / n.a.); the registers' gap is a suggestion and a contradicting answer is
// flagged; an incomplete assessment cannot be submitted; approval is four-eyes by the DPO or an administrator (not the
// submitter, never a service identity); approval writes each requirement's roll-up as its confirmation and turns every
// no / partial into a GRC remediation action once. Viewer sees only the approved score. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const now = () => Date.parse('2026-10-26T08:00:00Z');
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' };
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
const get = (e, p, who = OP) => e.req('GET', p, who);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  assert.equal((await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' }, ADM)).status, 200);
  return e;
}
async function answerAll(e, id, special = {}) {
  const r = (await get(e, '/pdpl/assessment?id=' + id)).json.assessment;
  for (const q of r.questions) {
    const a = special[q.id] || { answer: 'yes', evidence: 'synthetic evidence ' + q.id };
    const x = await post(e, '/pdpl/assessment/' + id + '/answer', Object.assign({ qid: q.id }, a));
    assert.equal(x.status, 200, q.id + ' ' + x.text);
  }
}

test('assessment: start, answers validated, suggestions from the registers, roles', async (t) => {
  const e = await setup(t);
  assert.equal((await get(e, '/pdpl/assessment', VW)).status, 403, 'viewer may not read answers');
  let r = await get(e, '/pdpl/assessment'); assert.equal(r.json.assessment, null); assert.equal(r.json.questions, 40);
  assert.equal((await post(e, '/pdpl/assessment', { cycle: 'x' })).status, 400);
  assert.equal((await post(e, '/pdpl/assessment', { cycle: '2026 annual' }, VW)).status, 403);
  r = await post(e, '/pdpl/assessment', { cycle: '2026 annual' }); assert.equal(r.status, 200, r.text);
  const id = r.json.id; assert.match(id, /^PA-2026-001$/); assert.equal(r.json.progress.total, 40); assert.equal(r.json.score, 0, 'nothing answered = gaps, not a pass');
  assert.equal((await post(e, '/pdpl/assessment', { cycle: 'second' })).status, 409, 'one open assessment at a time');
  // the registers show no published privacy policy: P-03 suggests "no"; no processing activity yet: P-04 cannot tell
  const p03 = r.json.questions.find((q) => q.id === 'P03-1'); assert.equal(p03.suggestion.answer, 'no'); assert.match(p03.suggestion.why, /registers show a gap/);
  const p04 = r.json.questions.find((q) => q.id === 'P04-1'); assert.equal(p04.suggestion.answer, null); assert.match(p04.suggestion.why, /cannot tell yet/);
  let x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P01-1', answer: 'yes' }); assert.equal(x.status, 400); assert.match(x.json.error, /evidence is required/);
  x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P01-1', answer: 'no' }); assert.equal(x.status, 400); assert.match(x.json.error, /note is required/);
  x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P99-1', answer: 'na', note: 'x' }); assert.equal(x.status, 400); assert.match(x.json.error, /no question/);
  x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P01-1', answer: 'maybe' }); assert.equal(x.status, 400); assert.match(x.json.error, /answer/);
  x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P03-1', answer: 'yes', evidence: 'policy on the website', extra: 1 }); assert.equal(x.status, 200);
  assert.ok(x.json.conflicts.some((c) => c.id === 'P03-1'), 'yes against a register gap is flagged');
  assert.equal(x.json.questions.find((q) => q.id === 'P03-1').extra, undefined);
  x = await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P01-1', answer: 'yes', evidence: 'DPO letter 2026-01' }, VW); assert.equal(x.status, 403);
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'pdpl.assessment.answer' && a.detail.qid === 'P03-1'));
  x = await post(e, '/pdpl/assessment/' + id + '/submit', {}); assert.equal(x.status, 400); assert.match(x.json.error, /not answered yet/);
});

test('submit and four-eyes approval: confirmations written back, gaps become GRC actions once; reject needs a note', async (t) => {
  const e = await setup(t);
  const id = (await post(e, '/pdpl/assessment', { cycle: '2026 Q4' })).json.id;
  await answerAll(e, id, { 'P09-1': { answer: 'no', note: 'no 72-hour procedure yet' }, 'P23-1': { answer: 'partial', evidence: 'IT trained, claims not yet' }, 'P22-1': { answer: 'na', note: 'no research use' } });
  let x = await post(e, '/pdpl/assessment/' + id + '/submit', {}); assert.equal(x.status, 200, x.text);
  assert.equal(x.json.status, 'submitted'); assert.ok(x.json.score > 80 && x.json.score < 100);
  assert.equal((await post(e, '/pdpl/assessment/' + id + '/answer', { qid: 'P01-1', answer: 'no', note: 'x' })).status, 409, 'answers frozen once submitted');
  assert.equal((await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'approve' }, OP)).status, 403, 'the submitter cannot decide');
  assert.equal((await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'approve' }, OP2)).status, 403, 'an operator who is not the DPO cannot approve');
  assert.equal((await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'approve' }, { user: 'system:pdpl', role: 'admin' })).status, 403, 'never a service identity');
  x = await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'reject' }, DPO); assert.equal(x.status, 400); assert.match(x.json.error, /note is required/);
  x = await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'reject', note: 'evidence for P13 too thin' }, DPO); assert.equal(x.status, 200); assert.equal(x.json.status, 'draft');
  x = await post(e, '/pdpl/assessment/' + id + '/submit', {}); assert.equal(x.status, 200);
  x = await post(e, '/pdpl/assessment/' + id + '/decide', { decision: 'approve', note: 'reviewed with Legal' }, DPO); assert.equal(x.status, 200, x.text);
  assert.equal(x.json.status, 'approved'); assert.equal(x.json.result.confirm_failed.length, 0, x.json.result.confirm_failed.join(' | '));
  assert.equal(x.json.result.confirmed.length, 24);
  const reqs = Object.fromEntries((await get(e, '/pdpl')).json.requirements.map((r) => [r.id, r]));
  assert.equal(reqs['P-09'].confirmation.status, 'non_compliant'); assert.equal(reqs['P-09'].confirmation.by, 'huda.syn');
  assert.equal(reqs['P-23'].confirmation.status, 'partial'); assert.equal(reqs['P-22'].confirmation.status, 'not_applicable');
  const A = (await get(e, '/grc/actions')).json; const items = A.items || A.actions || A;
  const mine = items.filter((a) => a.source === 'pdpl');
  assert.equal(mine.length, 2, 'P09-1 and P23-1 become actions');
  const p09 = mine.find((a) => a.ref === id + ':P09-1'); assert.equal(p09.priority, 'high'); assert.equal(p09.framework, 'PDPL');
  const log = e.app.store.auditTail(200).map((a) => a.action);
  assert.ok(['pdpl.assessment.submit', 'pdpl.assessment.reject', 'pdpl.assessment.approve', 'pdpl.confirm', 'grc.action.create'].every((k) => log.includes(k)));
  // viewer: the approved score only
  const s = await get(e, '/pdpl/assessment/summary', VW); assert.equal(s.status, 200); assert.equal(s.json.approved.id, id); assert.ok(s.json.approved.chapters.length === 20);
  assert.equal(s.json.approved.answers, undefined);
  // a new cycle can start; its gaps do not duplicate the open actions of the old one (different reference)
  assert.equal((await post(e, '/pdpl/assessment', { cycle: '2027 Q1' })).status, 200);
});
