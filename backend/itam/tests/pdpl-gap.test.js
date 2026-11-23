// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL implementation gap assessment (engine/pdpl-gap.js) end to end with SYNTHETIC data: open the engagement (validated, one at a
// time), kick-off with evidence requests per department, evidence received / accepted / returned (reference or note required), the
// register baseline, the self-assessment started and linked, answered and approved by the DPO (four eyes), every gap rated, the
// remediation plan written onto the GRC actions (owner, due), the summary, the lead's signature and the DPO's approval (never the
// signer, never a service identity); roles (viewer refused, a non-team operator refused); every step audited; the report (white,
// logo, disclaimer) and CSV.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const now = () => Date.parse('2026-11-01T08:00:00Z');
const LEAD = { user: 'lina.syn', role: 'operator' }, ASR = { user: 'amir.syn', role: 'operator' }, OUT = { user: 'omar.syn', role: 'operator' }, DPO = { user: 'huda.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' }, BOT = { user: 'ai:pdpl', role: 'admin' };
const LOGO = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

test('PDPL gap assessment: team to approved report', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' }, ADM)).status, 200);
  let r = await get('/pdpl/gap'); assert.equal(r.status, 200, r.text); assert.equal(r.json.current, null); assert.equal(r.json.steps.length, 7); assert.equal(r.json.approver, 'huda.syn');
  assert.equal((await get('/pdpl/gap', VW)).status, 403, 'viewer refused');
  // 1 team & scope - validated
  const S = { name: 'PDPL gap 2026', lead: 'lina.syn', assessors: ['amir.syn'], sponsor: 'syed', departments: ['Claims', 'HR'], systems: ['Core insurance'], start: '2026-11-01', target: '2026-12-15' };
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { departments: [] }))).status, 400, 'a department is required');
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { target: '2026-10-01' }))).status, 400, 'target after start');
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { lead: 'x y' }))).status, 400, 'lead is a user name');
  assert.equal((await post('/pdpl/gap', S, VW)).status, 403); assert.equal((await post('/pdpl/gap', S, BOT)).status, 403, 'a service identity does not open one');
  r = await post('/pdpl/gap', S); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(id, 'PGA-2026-001'); assert.equal(r.json.current_step, 2);
  assert.equal((await post('/pdpl/gap', S)).status, 409, 'one open engagement at a time');
  assert.equal((await post('/pdpl/gap/' + id + '/scope', { scope_note: 'all personal data in Claims and HR' }, OUT)).status, 403, 'not on the team');
  r = await post('/pdpl/gap/' + id + '/scope', { scope_note: 'all personal data in Claims and HR' }, ASR); assert.equal(r.status, 200, r.text);
  // 2 kick-off: 14 standard requests x 2 departments
  assert.equal((await post('/pdpl/gap/' + id + '/baseline', {})).status, 409, 'baseline after kick-off');
  assert.equal((await post('/pdpl/gap/' + id + '/kickoff', { due: '2026-10-01' })).status, 400, 'due in the past');
  r = await post('/pdpl/gap/' + id + '/kickoff', { due: '2026-11-20' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.evidence.length, 28); assert.equal(r.json.evidence_status.requested, 28); assert.ok(r.json.evidence.every((x) => x.ref && x.what));
  assert.equal((await post('/pdpl/gap/' + id + '/scope', { scope_note: 'changed' })).status, 409, 'scope fixed after kick-off');
  const ev = r.json.evidence;
  assert.equal((await post('/pdpl/gap/' + id + '/evidence/' + ev[0].id, { status: 'received' })).status, 400, 'reference required');
  assert.equal((await post('/pdpl/gap/' + id + '/evidence/' + ev[1].id, { status: 'returned' })).status, 400, 'note required');
  r = await post('/pdpl/gap/' + id + '/evidence/' + ev[0].id, { status: 'received', reference: 'DPO letter 2026-01 (synthetic)' }); assert.equal(r.status, 200, r.text);
  r = await post('/pdpl/gap/' + id + '/evidence/' + ev[0].id, { status: 'accepted' }, ASR); assert.equal(r.json.evidence_status.accepted, 1);
  r = await post('/pdpl/gap/' + id + '/evidence/' + ev[1].id, { status: 'returned', note: 'policy not published yet' }); assert.equal(r.json.evidence_status.returned, 1);
  assert.equal((await post('/pdpl/gap/' + id + '/evidence/EV999', { status: 'na', note: 'n/a here' })).status, 404);
  // 3 baseline
  assert.equal((await post('/pdpl/gap/' + id + '/review', {})).status, 409, 'baseline before the questionnaire');
  r = await post('/pdpl/gap/' + id + '/baseline', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.baseline.counts.ropa, 0); assert.ok(r.json.baseline.empty.includes('ropa'), 'an empty register reads as empty');
  // 4 questionnaire: started and linked
  r = await post('/pdpl/gap/' + id + '/review', {}); assert.equal(r.status, 200, r.text); const aid = r.json.review.id; assert.match(aid, /^PA-2026-/); assert.equal(r.json.status, 'fieldwork');
  assert.match(r.json.steps[3].block, /answer every question/);
  const qs = (await get('/pdpl/assessment?id=' + aid)).json.assessment.questions; const NO = qs[0].id, PART = qs[1].id;
  for (const q of qs) { const a = q.id === NO ? { answer: 'no', note: 'no privacy notice (synthetic)' } : q.id === PART ? { answer: 'partial', evidence: 'draft RoPA (synthetic)' } : { answer: 'yes', evidence: 'synthetic evidence ' + q.id };
    const x = await post('/pdpl/assessment/' + aid + '/answer', Object.assign({ qid: q.id }, a), ASR); assert.equal(x.status, 200, x.text); }
  assert.equal((await post('/pdpl/assessment/' + aid + '/submit', {}, ASR)).status, 200);
  assert.equal((await post('/pdpl/gap/' + id + '/gaps/' + NO, { likelihood: 4, impact: 5, root_cause: 'no owner', recommendation: 'publish the privacy notice', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'rate after DPO approval');
  r = await post('/pdpl/assessment/' + aid + '/decide', { decision: 'approve' }, DPO); assert.equal(r.status, 200, r.text);
  r = await get('/pdpl/gap/' + id); assert.equal(r.json.steps[3].done, true); assert.equal(r.json.gaps.length, 2); assert.equal(r.json.current_step, 5);
  // 5 gap rating
  assert.equal((await post('/pdpl/gap/' + id + '/plan', {})).status, 400, 'every gap rated first');
  assert.equal((await post('/pdpl/gap/' + id + '/gaps/' + NO, { likelihood: 6, impact: 5, root_cause: 'no owner', recommendation: 'publish the privacy notice', owner: 'amir.syn', target: '2026-12-31' })).status, 400, 'likelihood 1-5');
  assert.equal((await post('/pdpl/gap/' + id + '/gaps/P99-9', { likelihood: 2, impact: 2, root_cause: 'none here', recommendation: 'nothing to do here', owner: 'amir.syn', target: '2026-12-31' })).status, 404);
  r = await post('/pdpl/gap/' + id + '/gaps/' + NO, { likelihood: 4, impact: 5, root_cause: 'no owner for the notice', recommendation: 'publish the privacy notice on the website and app', owner: 'amir.syn', target: '2026-12-31' }); assert.equal(r.status, 200, r.text);
  r = await post('/pdpl/gap/' + id + '/gaps/' + PART, { likelihood: 2, impact: 3, root_cause: 'RoPA incomplete for HR', recommendation: 'complete the HR RoPA through a campaign', owner: 'lina.syn', target: '2027-01-31' }, ASR);
  assert.equal(r.json.gaps[0].id, NO, 'sorted by risk'); assert.equal(r.json.gaps[0].risk.level, 'critical'); assert.equal(r.json.gap_levels.medium, 1);
  // 6 plan -> GRC actions carry owner and due
  r = await post('/pdpl/gap/' + id + '/plan', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.plan.actions.length, 2); assert.equal(r.json.status, 'plan');
  const acts = (await get('/grc/actions?source=pdpl', ADM)).json.items; const a1 = acts.find((x) => x.ref === aid + ':' + NO);
  assert.equal(a1.owner, 'amir.syn'); assert.equal(a1.due, '2026-12-31'); assert.equal(a1.priority, 'high'); assert.match(a1.description, /root cause/);
  assert.equal((await post('/pdpl/gap/' + id + '/gaps/' + NO, { likelihood: 1, impact: 1, root_cause: 'changed mind', recommendation: 'nothing at all to do', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'fixed after publishing');
  // 7 report
  assert.equal((await post('/pdpl/gap/' + id + '/report/sign', {})).status, 409, 'summary first');
  assert.equal((await post('/pdpl/gap/' + id + '/report/summary', { summary: 'short' })).status, 400);
  assert.equal((await post('/pdpl/gap/' + id + '/report/summary', { summary: 'Two gaps found; the privacy notice is the critical one.' }, ASR)).status, 403, 'the lead writes it');
  r = await post('/pdpl/gap/' + id + '/report/summary', { summary: 'Two gaps found; the privacy notice is the critical one.' }); assert.equal(r.status, 200, r.text);
  r = await post('/pdpl/gap/' + id + '/report/sign', {}); assert.equal(r.json.signed_by, 'lina.syn');
  assert.equal((await post('/pdpl/gap/' + id + '/report/approve', {}, ASR)).status, 403, 'not the DPO');
  assert.equal((await post('/pdpl/gap/' + id + '/report/approve', {}, BOT)).status, 403, 'never a service identity');
  assert.equal((await post('/pdpl/gap/' + id + '/report/approve', {}, { user: 'lina.syn', role: 'admin' })).status, 403, 'never the signer');
  r = await post('/pdpl/gap/' + id + '/report/approve', {}, DPO); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'closed'); assert.ok(r.json.steps.every((s) => s.done));
  assert.equal((await post('/pdpl/gap/' + id + '/evidence/' + ev[2].id, { status: 'na', note: 'n/a' })).status, 409, 'closed');
  for (const a of ['create', 'kickoff', 'evidence', 'baseline', 'review', 'rate', 'plan', 'summary', 'sign', 'approve']) assert.ok(audits.some((x) => x.action === 'pdpl.gap.' + a && x.target === id), 'audited: ' + a);
  // report
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: 'Synthetic Finance Co', letterhead: LOGO } });
  r = await get('/pdpl/gap/' + id + '/report?format=html'); assert.equal(r.status, 200, r.text);
  assert.match(r.json.html, /background:#fff/); assert.match(r.json.html, /<img class="logo"/); assert.match(r.json.html, /Synthetic Finance Co/); assert.match(r.json.html, /not an SDAIA certificate/); assert.match(r.json.html, /approved by huda\.syn/);
  r = await get('/pdpl/gap/' + id + '/report?format=csv'); assert.match(r.json.csv, /critical \(20\)/);
  assert.equal((await get('/pdpl/gap/' + id + '/report?format=doc')).status, 400);
  assert.ok(audits.some((x) => x.action === 'pdpl.gap.report'));
  // a new one can open now
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { name: 'PDPL gap 2027' }))).status, 200);
});
