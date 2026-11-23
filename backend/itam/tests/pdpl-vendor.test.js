// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Vendor risk (engine/pdpl-vendor.js + pyengine/pdpl_vendor.py): the inherent tier from the processing activities that name a
// vendor (itemised, never assumed when no activity names it), the questionnaire CSV (formula-safe), importing the vendor's
// file (unknown rows refused, formula prefixes stripped), typed answers need evidence, every answer reviewed (a challenge needs
// a note and scores as not met), submit only when complete, four-eyes approval by the DPO / an administrator, gaps to GRC
// once, the Processors due-diligence checks set from the answers, the schedule and the findings; roles and audit. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' };

async function setup(t) {
  clock = Date.parse('2026-10-20T08:00:00Z');   // each test starts on the same day
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' }, ADM);
  const tpa = (await post('/pdpl/records', { kind: 'processor', name: '=HYPERLINK("http://x") TPA Synthetic', service: 'medical claims administration', outside_ksa: true })).json;
  const print = (await post('/pdpl/records', { kind: 'processor', name: 'Print House Synthetic', service: 'statement printing' })).json;
  const lone = (await post('/pdpl/records', { kind: 'processor', name: 'Unlinked Vendor Synthetic' })).json;
  await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', legal_basis: 'contract', data_categories: ['identity', 'health'], volume: 150000, processor_ids: [tpa.id] });
  await post('/pdpl/records', { kind: 'ropa', name: 'Statements (synthetic)', legal_basis: 'contract', data_categories: ['contact'], volume: 900, processor_ids: [print.id] });
  return { e, post, get, tpa, print, lone };
}
function filled(csv, over = {}) {
  return csv.split('\r\n').map((l) => { const m = /^([A-Z]{3}-\d),/.exec(l); if (!m) return l; const a = over[m[1]] || ['yes', 'ref ' + m[1]]; const cells = l.match(/("([^"]|"")*"|[^,]*)(,|$)/g).map((c) => c.replace(/,$/, '')); cells[3] = a[0]; cells[4] = a[1] || ''; return cells.join(','); }).join('\r\n');
}

test('tiers: from the activities that name the vendor, itemised; an unlinked vendor is not rated and cannot be assessed', async (t) => {
  const { get, post, tpa, print, lone } = await setup(t);
  assert.equal((await get('/pdpl/vendors', VW)).status, 403);
  const v = (await get('/pdpl/vendors')).json;
  const T = (id) => v.vendors.find((x) => x.id === id);
  assert.equal(T(tpa.id).tier, 'critical'); assert.ok(T(tpa.id).tier_why.some((w) => /sensitive data: health/.test(w)) && T(tpa.id).tier_why.some((w) => /outside the Kingdom/.test(w)));
  assert.equal(T(tpa.id).cadence_months, 12); assert.equal(T(print.id).tier, 'low'); assert.equal(T(print.id).cadence_months, 36);
  assert.equal(T(lone.id).tier, null);
  assert.ok(v.findings.some((f) => f.key === 'vendor:' + lone.id + ':unrated') && v.findings.some((f) => f.key === 'vendor:' + tpa.id + ':due' && f.severity === 'high'));
  const r = await post('/pdpl/vendors/' + lone.id + '/assessments', {}); assert.equal(r.status, 409); assert.match(r.json.error, /not rated/);
  assert.equal((await post('/pdpl/vendors/PD-X-1/assessments', {})).status, 400);
});

test('the full assessment: questionnaire, vendor file, review, submit, four-eyes approval, GRC actions, schedule', async (t) => {
  const { e, get, post, tpa } = await setup(t);
  assert.equal((await post('/pdpl/vendors/' + tpa.id + '/assessments', {}, VW)).status, 403);
  assert.equal((await post('/pdpl/vendors/' + tpa.id + '/assessments', {}, { user: 'ai:pdpl', role: 'operator' })).status, 403);
  let a = (await post('/pdpl/vendors/' + tpa.id + '/assessments', { return_by: '2026-11-10' })).json; const id = a.assessment.id;
  assert.equal(a.assessment.status, 'draft'); assert.equal(a.tier, 'critical');
  assert.equal((await post('/pdpl/vendors/' + tpa.id + '/assessments', {})).status, 409, 'one open assessment per vendor');
  // the questionnaire
  const q = (await get('/pdpl/vendors/assessments/' + id + '/questionnaire')).json;
  assert.match(q.filename, /^vendor-questionnaire-VRA-001\.csv$/); assert.ok(q.csv.includes('CER-1,') && q.csv.includes('id,domain,question,answer'));
  assert.ok(!/(^|,|")=HYPERLINK/.test(q.csv), 'the vendor name cannot start a formula');
  assert.equal((await get('/pdpl/vendors/assessments/' + id)).json.assessment.status, 'sent');
  // the vendor's file: two gaps, one unknown row, one bad answer, a formula in the evidence
  let csv = filled(q.csv, { 'LOC-1': ['no', 'hosted in Frankfurt'], 'BRE-1': ['partial', '72 hours in the contract'], 'ENC-1': ['yes', '=cmd|calc'] }) + '\r\nZZZ-9,x,x,yes,,\r\n';
  csv = csv.replace(/^(AUD-1,[^\r\n]*?),yes,/m, '$1,maybe,');
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/answers', { csv: 'nonsense' })).status, 400);
  let r = await post('/pdpl/vendors/assessments/' + id + '/answers', { csv }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.imported.answered, 19); assert.ok(r.json.imported.errors.some((x) => /unknown question id ZZZ-9/.test(x)) && r.json.imported.errors.some((x) => /AUD-1 answer must be/.test(x)));
  assert.equal(r.json.questions.find((x) => x.id === 'ENC-1').evidence_given, 'cmd|calc', 'formula prefix stripped');
  // typed answer needs evidence
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/answer', { qid: 'AUD-1', answer: 'yes' })).status, 400);
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/answer', { qid: 'AUD-1', answer: 'yes', evidence: 'annual SOC 2 report' })).status, 200);
  // submit blocked until every answer is reviewed
  r = await post('/pdpl/vendors/assessments/' + id + '/submit', {}); assert.equal(r.status, 409); assert.match(r.json.error, /not reviewed/);
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/review', { qid: 'CER-1', verdict: 'challenged' })).status, 400, 'a challenge needs a note');
  for (const x of r.json ? (await get('/pdpl/vendors/assessments/' + id)).json.questions : []) {
    const verdict = x.id === 'CER-1' ? 'challenged' : 'accepted';
    assert.equal((await post('/pdpl/vendors/assessments/' + id + '/review', { qid: x.id, verdict, note: verdict === 'challenged' ? 'certificate expired in 2025 (synthetic)' : undefined })).status, 200);
  }
  a = (await get('/pdpl/vendors/assessments/' + id)).json;
  assert.ok(a.gaps.some((g) => g.id === 'CER-1' && g.challenged) && a.gaps.some((g) => g.id === 'LOC-1' && g.priority === 'high'));
  assert.ok(a.score < 85 && ['high', 'critical'].includes(a.residual), 'critical vendor with gaps: high residual (' + a.score + ', ' + a.residual + ')');
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/submit', {}, DPO)).status, 200);
  // approval: not an ordinary operator, not the submitter
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/decide', { decision: 'approve' }, OP2)).status, 403);
  r = await post('/pdpl/vendors/assessments/' + id + '/decide', { decision: 'approve' }, DPO); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/decide', { decision: 'reject' }, ADM)).status, 400, 'sending back needs a note');
  r = await post('/pdpl/vendors/assessments/' + id + '/decide', { decision: 'approve', note: 'accepted with actions (synthetic)' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.assessment.status, 'approved'); assert.equal(r.json.result.actions.length, a.gaps.length);
  const acts = e.app.store.collection('grc_actions').all((x) => x.source === 'pdpl' && x.ref.startsWith(id + ':'));
  assert.equal(acts.length, a.gaps.length); assert.ok(acts.some((x) => x.ref === id + ':LOC-1' && x.priority === 'high'));
  // the Processors page follows the approved answers
  const p = (await get('/pdpl/processors')).json.processors.find((x) => x.id === tpa.id);
  assert.equal(p.checks.find((c) => c.key === 'data_in_ksa').ok, false); assert.equal(p.checks.find((c) => c.key === 'iso27001').ok, true, 'answered yes (the challenge lowers the score, the declared check stays)');
  const v = (await get('/pdpl/vendors')).json.vendors.find((x) => x.id === tpa.id);
  assert.equal(v.next_due, '2027-10-20'); assert.equal(v.overdue, false); assert.equal(v.score, a.score);
  assert.ok((await get('/pdpl/vendors')).json.findings.some((f) => f.key === 'vendor:' + tpa.id + ':residual'));
  const au = e.app.store.auditTail(200).map((x) => x.action);
  for (const k of ['pdpl.vendor.start', 'pdpl.vendor.questionnaire', 'pdpl.vendor.answers', 'pdpl.vendor.answer', 'pdpl.vendor.review', 'pdpl.vendor.submit', 'pdpl.vendor.approve']) assert.ok(au.includes(k), k);
  // a year later: due again
  clock += 366 * 86400000;
  assert.ok((await get('/pdpl/vendors')).json.findings.some((f) => f.key === 'vendor:' + tpa.id + ':due' && /due since 2027-10-20/.test(f.title)));
});

test('send back, late questionnaire, cancel; validation names the field', async (t) => {
  const { get, post, print } = await setup(t);
  const id = (await post('/pdpl/vendors/' + print.id + '/assessments', { return_by: '2026-10-25' })).json.assessment.id;
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/answer', { qid: 'CER-1', answer: 'yes', evidence: 'x' })).status, 409, 'not sent yet');
  await get('/pdpl/vendors/assessments/' + id + '/questionnaire');
  clock = Date.parse('2026-10-28T08:00:00Z');
  assert.ok((await get('/pdpl/vendors')).json.findings.some((f) => f.key === 'vendor:' + print.id + ':late'));
  for (const [b, re] of [[{ qid: 'cer-1', answer: 'yes' }, /qid/], [{ qid: 'CER-1', answer: 'maybe' }, /answer/]]) { const r = await post('/pdpl/vendors/assessments/' + id + '/answer', b); assert.equal(r.status, 400); assert.match(r.json.error, re); }
  assert.equal((await post('/pdpl/vendors/assessments/VRA-999/submit', {})).status, 404);
  assert.equal((await post('/pdpl/vendors/assessments/bad/submit', {})).status, 400);
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/cancel', {})).status, 400);
  assert.equal((await post('/pdpl/vendors/assessments/' + id + '/cancel', { note: 'vendor replaced (synthetic)' })).status, 200);
  assert.equal((await post('/pdpl/vendors/' + print.id + '/assessments', {})).status, 200, 'a new one may start after cancelling');
});
