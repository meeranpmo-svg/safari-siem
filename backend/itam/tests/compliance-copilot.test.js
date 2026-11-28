// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance AI Assistant (engine/compliance-copilot.js, engine/policy-templates.js), SYNTHETIC registers: the company register
// (from the company setting, created / renamed by an administrator, validated, never an AI identity, audited); the realistic
// position (not measured counts as not met) next to the recorded one; priorities weighed by what the company does, with why in
// English and Arabic; themes and the 90-day plan; remediation actions (raise → submit evidence → verify by another person, return
// with a reason); control activities (done with an evidence reference → verified by another person → next due); bilingual policy
// drafts to GRC (approval by someone other than the author); local answers in Arabic and English; roles and the refused cases.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const PT = require('../engine/policy-templates');

const ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, OP = { user: 'op.syn', role: 'operator' }, OWN = { user: 'owner.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'admin' };
const REGS = () => ({
  nca: { installed: true, rows: [{ id: '2-2-1', title: 'Identity and access management requirements are defined', result: 'gap', severity: 'high' }, { id: '2-12-1', title: 'Event logs and monitoring', result: 'compliant' },
    { id: '4-1-1', title: 'Third-party cybersecurity requirements in contracts', result: 'not_measured' }, { id: '2-14-1', title: 'Physical security of premises', result: 'partial' }] },
  iso27001: { installed: true, rows: [{ id: 'A.5.34', title: 'Privacy and protection of personal identifiable information', result: 'gap' }, { id: 'A.8.13', title: 'Information backup', result: 'compliant' }, { id: 'A.5.9', title: 'Inventory of information', result: 'not_applicable' }] },
  pdpl: { installed: true, rows: [{ id: 'P-03', title: 'A privacy policy is published before personal data is collected', result: 'compliant' }, { id: 'P-04', title: 'Records of processing activities are kept', result: 'not_assessed' }, { id: 'P-05', title: 'Consent is recorded', result: 'not_assessed' }] },
  ndmo: { installed: true, rows: [] }, aramco: { installed: true, rows: [] } });
async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, Object.assign({ noTimer: true, copilotAiOff: true, copilotRegisters: async () => REGS() }, o));
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}
const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

test('companies: from the company setting, created and renamed by an administrator, validated, audited', async (t) => {
  const { e, call } = await setup(t);
  let v = (await call('GET', '/org/companies', undefined, VIEW)).json; assert.equal(v.companies.length, 1); assert.match(v.companies[0].name, /Safari/); assert.ok(v.companies[0].frameworks.includes('pdpl'));
  const B = { name: 'Safari Facility Services (synthetic)', name_ar: 'سفاري للخدمات (اصطناعي)', frameworks: ['pdpl', 'iso27001'], lines: ['facility', 'manpower'], parent: 'main' };
  assert.equal((await call('PUT', '/org/companies/sfs', B, OP)).status, 403); assert.equal((await call('PUT', '/org/companies/sfs', B, BOT)).status, 403, 'never an AI identity');
  let r = await call('PUT', '/org/companies/Bad!', B, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /id/);
  r = await call('PUT', '/org/companies/sfs', Object.assign({}, B, { frameworks: ['sama'] }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /frameworks/);
  r = await call('PUT', '/org/companies/sfs', Object.assign({}, B, { parent: 'nope' }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /parent/);
  r = await call('PUT', '/org/companies/sfs', Object.assign({}, B, { extra: 'dropped' }), ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.companies.length, 2); assert.equal(r.json.companies.find((c) => c.id === 'sfs').extra, undefined);
  r = await call('PUT', '/org/companies/sfs', Object.assign({}, B, { name: 'Safari Services Co. (synthetic)' }), ADM); assert.equal(r.status, 200);
  assert.equal((await call('PUT', '/org/companies/dup', Object.assign({}, B, { name: 'safari services co. (synthetic)' }), ADM)).status, 409, 'names are unique');
  const au = e.app.store.auditTail(50).filter((x) => /^copilot\.company\./.test(x.action)); assert.ok(au.some((x) => x.action === 'copilot.company.create') && au.some((x) => x.detail.renamed_from === 'Safari Facility Services (synthetic)'));
  assert.equal(e.app.addons.companies.list().length, 2, 'the audit and compliance reports read the register');
});

test('realistic position, priorities by business, why in English and Arabic, themes, plan; viewer sees no action owners', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/copilot/overview', undefined, VIEW)).json;
  const nca = v.frameworks.find((f) => f.id === 'nca'), pd = v.frameworks.find((f) => f.id === 'pdpl');
  assert.equal(nca.applicable, 4); assert.equal(nca.recorded, 50, '(1 + 0.5) / 3 assessed'); assert.equal(nca.realistic, 38, '(1 + 0.5) / 4 - not measured counts as not met');
  assert.equal(pd.recorded, 100); assert.equal(pd.realistic, 33); assert.equal(v.frameworks.find((f) => f.id === 'iso27001').applicable, 2, 'not applicable left out');
  assert.match(v.frameworks.find((f) => f.id === 'ndmo').note, /register empty/);
  assert.ok(v.insights.some((i) => /PDPL: 100% as recorded, 33% realistic/.test(i.title)), JSON.stringify(v.insights));
  const p = v.priorities[0]; assert.ok(p.state === 'gap' && /privacy|iam/.test(p.topic), JSON.stringify(p)); assert.match(p.why, /Matters for Safari because/); assert.match(p.why_ar, /أهميته لـ/);
  assert.ok(v.priorities.find((x) => x.id === '2-2-1').policy === 'access' && v.priorities.find((x) => x.id === '4-1-1').topic === 'third_party');
  assert.ok(v.themes.length && v.plan.length === 3 && v.plan[0].work.length, 'themes and a 90-day plan');
  assert.ok(v.duties.length >= 15 && v.duties.every((d) => d.status === 'never done'), 'the control activities that apply');
  assert.ok(v.policies.templates.length >= 14);
});

test('remediation workflow: raise, submit evidence, verify by another person, return with a reason; roles; audit', async (t) => {
  const { e, call } = await setup(t);
  const A = { company: 'main', fw: 'nca', req_id: '2-2-1', title: 'Define and approve the IAM standard (synthetic)', owner: 'owner.syn', due: day(30) };
  assert.equal((await call('POST', '/copilot/actions', A, VIEW)).status, 403);
  assert.equal((await call('POST', '/copilot/actions', A, { user: 'ai:grc', role: 'operator' })).status, 403, 'an AI never raises');
  let r = await call('POST', '/copilot/actions', Object.assign({}, A, { fw: 'sama' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /^fw/);
  r = await call('POST', '/copilot/actions', Object.assign({}, A, { due: '2020-01-01' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  r = await call('POST', '/copilot/actions', Object.assign({}, A, { owner: 'bad owner!' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /owner/);
  r = await call('POST', '/copilot/actions', A, OP); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(r.json.state, 'open');
  assert.equal((await call('POST', '/copilot/actions', A, OP)).status, 409, 'one open action per requirement');
  assert.equal((await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'accept' }, ADM)).status, 409, 'evidence first');
  assert.equal((await call('POST', '/copilot/actions/' + id + '/submit', { evidence_ref: 'GRC DRAFT-0001 v1.0 (synthetic)' }, { user: 'other.syn', role: 'operator' })).status, 403, 'only the owner submits');
  r = await call('POST', '/copilot/actions/' + id + '/submit', { evidence_ref: 'GRC DRAFT-0001 v1.0 (synthetic)' }, OWN); assert.equal(r.status, 200, r.text); assert.equal(r.json.state, 'submitted');
  assert.equal((await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'accept' }, OP)).status, 403, 'an operator does not verify');
  assert.equal((await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'accept' }, { user: 'owner.syn', role: 'admin' })).status, 403, 'four-eyes: the owner never verifies');
  assert.equal((await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'return' }, ADM)).status, 400, 'a return says what is missing');
  r = await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'return', note: 'the standard is not signed (synthetic)' }, ADM); assert.equal(r.json.state, 'returned');
  await call('POST', '/copilot/actions/' + id + '/submit', { evidence_ref: 'GRC DRAFT-0001 v1.0 signed (synthetic)' }, OWN);
  r = await call('POST', '/copilot/actions/' + id + '/verify', { decision: 'accept', note: 'ok' }, ADM); assert.equal(r.json.state, 'closed'); assert.equal(r.json.verified_by, 'admin.syn');
  const v = (await call('GET', '/copilot/overview', undefined, VIEW)).json; assert.equal(v.actions[0].owner, undefined, 'a viewer sees no owners');
  const au = e.app.store.auditTail(100).map((x) => x.action); for (const a of ['copilot.action.raise', 'copilot.action.submit', 'copilot.action.return', 'copilot.action.close']) assert.ok(au.includes(a), a);
});

test('control activities: done with an evidence reference, verified by another person, next due; administrator adjusts', async (t) => {
  const { e, call } = await setup(t);
  const id = 'main__restore_test';
  let r = await call('POST', '/copilot/duties/' + id + '/done', { evidence_ref: 'Veeam restore report Q4 (synthetic)', done_on: day(3) }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /future/);
  assert.equal((await call('POST', '/copilot/duties/main__nope/done', { evidence_ref: 'x report' }, OP)).status, 404);
  assert.equal((await call('POST', '/copilot/duties/' + id + '/done', { evidence_ref: 'x' }, OP)).status, 400, 'an evidence reference is needed');
  r = await call('POST', '/copilot/duties/' + id + '/done', { evidence_ref: 'Veeam restore report Q4 (synthetic)', done_on: day(0) }, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'awaiting verification');
  assert.equal((await call('POST', '/copilot/duties/' + id + '/done', { evidence_ref: 'again report' }, OP)).status, 409);
  assert.equal((await call('POST', '/copilot/duties/' + id + '/verify', { decision: 'accept' }, { user: 'op.syn', role: 'admin' })).status, 403, 'four-eyes');
  r = await call('POST', '/copilot/duties/' + id + '/verify', { decision: 'accept' }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'on track'); assert.equal(r.json.next_due, day(90));
  r = await call('PUT', '/copilot/duties/' + id, { every_days: 60 }, OP); assert.equal(r.status, 403);
  r = await call('PUT', '/copilot/duties/' + id, { every_days: 2 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /every_days/);
  r = await call('PUT', '/copilot/duties/' + id, { every_days: 60, owner_dept: 'it' }, ADM); assert.equal(r.json.every_days, 60);
  r = await call('PUT', '/copilot/duties/' + id, { every_days: 60, next_due: day(500) }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.next_due, day(90), 'next_due is only set by verification, never by a direct edit');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'copilot.duty.verify' && x.by === 'admin.syn'));
});

test('policies: bilingual templates filled with the company values, sent to GRC, approved only by someone else', async (t) => {
  const { e, call } = await setup(t);
  for (const T of PT.TEMPLATES) { const d = PT.render(T.id, { company: 'Co', company_ar: 'شركة' }); assert.ok(!/\{\w+\}/.test(d.text_en + d.text_ar), T.id + ': every placeholder filled'); assert.ok(/[؀-ۿ]/.test(d.text_ar) && d.sections.every((s) => s.ar && s.en), T.id + ': both languages'); }
  assert.equal((await call('POST', '/copilot/policies/preview', { template: 'access' }, VIEW)).status, 403);
  let r = await call('POST', '/copilot/policies/preview', { template: 'nope' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /template/);
  r = await call('POST', '/copilot/policies/preview', { template: 'access', options: { pw_min: 4 } }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /pw_min/);
  r = await call('POST', '/copilot/policies/preview', { template: 'access', options: { pw_min: 14, access_review_months: 3 } }, OP); assert.equal(r.status, 200, r.text);
  assert.match(r.json.text_en, /at least 14 characters/); assert.match(r.json.text_ar, /14 حرفاً/); assert.match(r.json.text_ar, /شركة سفاري المحدودة/); assert.deepEqual(r.json.refs.nca, ['2-2']);
  r = await call('POST', '/copilot/policies/draft', { template: 'pdpl', options: { breach_hours: 72 } }, OP); assert.equal(r.status, 200, r.text); const g = r.json.grc_draft;
  const d = e.app.store.collection('grc_drafts').get(g); assert.match(d.body, /Personal Data Protection Policy/); assert.match(d.body, /النسخة العربية/); assert.match(d.frameworks, /PDPL Art\. 4/);
  const grc = e.app.addons.grc || require('../engine/grc').createGrc(e.app);
  assert.throws(() => grc.draftStatus(g, 'approved', OP), /four eyes/, 'the author never approves');
  grc.draftStatus(g, 'approved', ADM2);
  const L = (await call('GET', '/copilot/policies?company=main', undefined, VIEW)).json; assert.equal(L.drafts[0].status, 'approved'); assert.equal(L.drafts[0].approved_by, 'admin2.syn');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'copilot.policy.draft'));
});

test('ask without external AI: answers from the registers in Arabic and English, says it is an indicator', async (t) => {
  const { call } = await setup(t);
  let r = await call('POST', '/copilot/ask', { question: 'ما هي أولويات نظام حماية البيانات الشخصية؟' }, VIEW); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ai, false); assert.match(r.json.answer, /النسبة الواقعية 33%/); assert.match(r.json.answer, /P-04/); assert.match(r.json.answer, /ليست رأي تدقيق/);
  r = await call('POST', '/copilot/ask', { question: 'Which policies should we write first?' }, VIEW); assert.match(r.json.answer, /Policies to draft first/);
  r = await call('POST', '/copilot/ask', { question: 'what is overdue?' }, VIEW); assert.match(r.json.answer, /never done/);
  assert.equal((await call('POST', '/copilot/ask', { question: '' }, VIEW)).status, 400);
});
