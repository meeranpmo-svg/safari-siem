// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Reports (engine/audit-report.js) through the real routes and the real audit team engines: the deterministic skeleton
// from an engagement's own records (procedures, samples, findings with management response, the overall rating by the stated
// rule), versions kept on every edit with optimistic concurrency, the optional AI proposal through app.provider (and the report
// working without AI), the lead signs, an administrator outside the team approves for issue (four eyes, never a service / AI
// identity), the issued report frozen with a SHA-256 fingerprint, roles (viewer refused, operator, admin), validation errors
// naming the field, and the audit records. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createAuditReport, registerAuditReport, overall, canon } = require('../engine/audit-report');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'nadia.syn', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' };
const AUD2 = { user: 'adel.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' }, OTHER = { user: 'otto.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };

async function setup(t, o = {}) {
  const e = await startApp(o.noAi ? { noAi: true } : {}); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  let X = e.app.addons.auditReport;
  if (!X) { X = createAuditReport(e.app); e.app.addons.auditReport = X; registerAuditReport(e.app.srv, e.app, X); }
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, X, A: e.app.addons.auditEngage, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(1000).filter((x) => x.action === action);

// a synthetic engagement taken to draft report through the IT Audit Team's own engine: a sample with one exception, a reviewed
// workpaper, one issued medium finding with management's response
function engagement(s, o = {}) {
  const A = s.A, off = s.e.app.store.collection('offboarding');
  for (let i = 1; i <= 4; i++) off.put({ id: 'OFF-000' + i, username: 'leaver' + i + '.syn', last_day: '2026-0' + i + '-15', requested_by: 'hr.syn', status: 'completed', disable: { approved_by: i === 2 ? 'hr.syn' : 'mgr.syn' }, disabled: { at: '2026-0' + i + '-15T20:00:00Z' } });
  A.putProfile({ head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user] }, ADM);
  const today = new Date().toISOString().slice(0, 10), later = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const eng = A.createEngagement({ title: 'Leavers access removal (synthetic)', area: 'joiners', auditee_dept: 'Human Resources', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user],
    objectives: ['Leavers lose access on their last day'], scope: 'All 2026 leavers (synthetic)', criteria: 'NCA ECC 1-9, ISO 27001 A.6.5', start: today, fieldwork_end: later, report_due: later }, LEAD);
  A.priorNone(eng.id, { note: 'first audit of this area (synthetic)' }, LEAD); A.advance(eng.id, { to: 'fieldwork' }, LEAD);
  const smp = A.sample(eng.id, { population: 'leavers', size: 2, method: 'judgemental', refs: ['OFF-0002', 'OFF-0004'] }, LEAD);
  A.concludeItem(smp.id, 'OFF-0002', { result: 'exception', note: 'approved by the requester (synthetic)' }, LEAD);
  A.concludeItem(smp.id, 'OFF-0004', { result: 'pass' }, LEAD);
  const wp = A.addWorkpaper(eng.id, { title: 'Leaver approvals', objective: 'Approved by a second person', procedure: 'Inspect each sampled leaver', sample: smp.id }, LEAD);
  A.concludeWp(wp.id, { conclusion: 'partially_effective', summary: 'One of two leavers self-approved (synthetic)' }, LEAD);
  A.reviewWp(wp.id, { decision: 'accept' }, HEAD);
  const f = A.addFinding(eng.id, Object.assign({ title: 'Self-approved leaver disable', condition: '1 of 2 sampled leavers was approved by the requester', criteria: 'Four eyes on account disables', cause: 'No system check',
    effect: 'One person can keep an account active', recommendation: 'Block self-approval in HR Offboarding', rating: 'medium', owner: OWNER.user, samples: [smp.id + '/OFF-0002'] }, o.finding || {}), LEAD);
  A.findingAct(f.id, 'issue', {}, LEAD);
  A.findingAct(f.id, 'respond', { response: 'Agreed (synthetic)', action_plan: 'Add a second-approver rule', due: later }, OWNER);
  if (o.stop !== 'fieldwork') A.advance(eng.id, { to: 'draft_report' }, LEAD);
  return { eng, smp, wp, f };
}

test('the rating rule: stated, and computed from the findings\' ratings only', () => {
  const r = (h, m, l) => overall([].concat(Array(h).fill({ rating: 'high' }), Array(m).fill({ rating: 'medium' }), Array(l).fill({ rating: 'low' }))).value;
  assert.equal(r(0, 0, 0), 'Satisfactory'); assert.equal(r(0, 0, 2), 'Satisfactory'); assert.equal(r(0, 0, 3), 'Needs improvement');
  assert.equal(r(0, 1, 0), 'Needs improvement'); assert.equal(r(0, 2, 5), 'Needs improvement'); assert.equal(r(0, 3, 0), 'Unsatisfactory'); assert.equal(r(1, 0, 0), 'Unsatisfactory');
  assert.match(overall([]).rule, /Unsatisfactory - at least one high-rated finding/);
  assert.equal(canon({ b: 1, a: [{ d: 2, c: 1 }] }), canon({ a: [{ c: 1, d: 2 }], b: 1 }), 'the fingerprint does not depend on key order');
});

test('draft: the skeleton comes from the engagement\'s records; roles, validation and the audit record', async (t) => {
  const s = await setup(t); const { eng, smp, wp, f } = engagement(s);
  for (const p of ['/audit-reports', '/audit-reports/AR-' + eng.id]) assert.equal((await s.get(p, VIEW)).status, 403, p + ' refuses a viewer (reports name people)');
  assert.equal((await s.post('/audit-reports', { team: 'it', engagement: eng.id }, VIEW)).status, 403);
  let r = await s.post('/audit-reports', { team: 'finance', engagement: eng.id }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /team must be one of/);
  r = await s.post('/audit-reports', { team: 'it' }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /engagement is required/);
  r = await s.post('/audit-reports', { team: 'it', engagement: 'ENG-9999-999' }, LEAD); assert.equal(r.status, 404);
  r = await s.post('/audit-reports', { team: 'it', engagement: eng.id }, OTHER); assert.equal(r.status, 403, 'an operator outside the audit team cannot draft it'); assert.match(r.json.error, /audit team/);
  r = await s.post('/audit-reports', { team: 'it', engagement: eng.id }, { user: 'ai:itaudit', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /named person/);
  const list0 = await s.get('/audit-reports'); assert.equal(list0.status, 200);
  assert.ok(list0.json.engagements.some((x) => x.id === eng.id && x.report === null), 'the engagement is offered for a report');
  r = await s.post('/audit-reports', { team: 'it', engagement: eng.id, state: 'issued', fingerprint: 'forged' }, AUD2); assert.equal(r.status, 200, r.text);
  const rep = r.json; assert.equal(rep.id, 'AR-' + eng.id); assert.equal(rep.state, 'draft', 'undeclared fields are dropped'); assert.equal(rep.fingerprint, null);
  const sk = rep.skeleton;
  assert.equal(sk.scope, 'All 2026 leavers (synthetic)'); assert.deepEqual(sk.objectives, ['Leavers lose access on their last day']); assert.equal(sk.period.start, eng.start);
  assert.equal(sk.procedures[0].id, wp.id); assert.equal(sk.procedures[0].conclusion, 'partially_effective'); assert.equal(sk.procedures[0].reviewed_by, HEAD.user);
  assert.equal(sk.samples[0].id, smp.id); assert.deepEqual(sk.samples[0].results, { pass: 1, exception: 1, na: 0, open: 0 }); assert.equal(sk.samples[0].population_size, 4);
  const sf = sk.findings[0]; assert.equal(sf.id, f.id);
  for (const k of ['condition', 'criteria', 'cause', 'effect', 'recommendation', 'owner', 'due', 'rating']) assert.ok(sf[k], 'the finding carries ' + k);
  assert.equal(sf.management_response, 'Agreed (synthetic)'); assert.equal(sf.action_plan, 'Add a second-approver rule');
  assert.equal(sk.rating.value, 'Needs improvement'); assert.match(sk.rating.why, /1 medium/); assert.match(sk.records_hash, /^[0-9a-f]{64}$/);
  assert.equal(rep.content.executive_summary, ''); assert.equal(rep.versions.length, 1); assert.match(rep.ai_note, /not drafted/);
  assert.equal((await s.post('/audit-reports', { team: 'it', engagement: eng.id }, LEAD)).status, 409, 'one report per engagement');
  const a = auditOf(s.e, 'audit-report.draft')[0]; assert.equal(a.by, AUD2.user); assert.equal(a.role, 'operator'); assert.equal(a.target, rep.id); assert.equal(a.detail.rating, 'Needs improvement');
  assert.equal((await s.get('/audit-reports/' + rep.id, LEAD)).json.stale, false);
});

test('edit: every save is a version; concurrency, validation and the signature cleared by an edit', async (t) => {
  const s = await setup(t); const { eng, f } = engagement(s);
  const rep = (await s.post('/audit-reports', { team: 'it', engagement: eng.id }, LEAD)).json, P = '/audit-reports/' + rep.id;
  let r = await s.post(P + '/edit', { version: 1, executive_summary: 'Leaver access removal needs improvement (synthetic summary).', finding_notes: [{ id: f.id, text: 'Restated (synthetic)' }], note: 'first pass' }, LEAD);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.version, 2); assert.deepEqual(r.json.versions[1].changed, ['executive_summary', 'finding_notes.' + f.id]);
  assert.equal(r.json.content.finding_notes[f.id], 'Restated (synthetic)'); assert.equal(r.json.versions[0].content.executive_summary, '', 'the earlier version is kept as it was');
  r = await s.post(P + '/edit', { version: 1, title: 'stale' }, AUD2); assert.equal(r.status, 409, 'an edit on an old version is refused'); assert.match(r.json.error, /reload/);
  r = await s.post(P + '/edit', { version: 2, finding_notes: [{ id: 'IAF-999', text: 'x' }] }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /finding_notes\[0\]\.id/);
  r = await s.post(P + '/edit', { version: 2, finding_notes: ['text'] }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /finding_notes\[0\]/);
  r = await s.post(P + '/edit', { version: 2, executive_summary: 'x'.repeat(8001) }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /executive_summary is longer/);
  r = await s.post(P + '/edit', { version: 'two' }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /version must be a whole number/);
  r = await s.post(P + '/edit', { version: 2, title: 'x' }, OTHER); assert.equal(r.status, 403);
  r = await s.post(P + '/edit', { version: 2, title: 'x' }, VIEW); assert.equal(r.status, 403);
  r = await s.post(P + '/edit', { version: 2, executive_summary: 'Leaver access removal needs improvement (synthetic summary).' }, LEAD); assert.equal(r.json.unchanged, true); assert.equal(r.json.version, 2, 'nothing changed: no version');
  r = await s.post(P + '/sign', { version: 2 }, LEAD); assert.equal(r.status, 200, r.text); assert.equal(r.json.state, 'signed');
  r = await s.post(P + '/edit', { version: 2, background: 'Background added after signing (synthetic)' }, HEAD); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'draft', 'an edit after signing clears the signature'); assert.equal(r.json.signed_by, null);
  const ed = auditOf(s.e, 'audit-report.edit'); assert.equal(ed.length, 2); assert.equal(ed[0].detail.signature_cleared, true); assert.equal(ed[0].by, HEAD.user);
  assert.ok(!JSON.stringify(ed).includes('Background added'), 'the audit record says what changed, not the text');
});

test('without AI the skeleton works and says the summary is not drafted; signing and issue still work', async (t) => {
  const s = await setup(t, { noAi: true }); const { eng } = engagement(s);
  const l = await s.get('/audit-reports'); assert.equal(l.json.ai.ready, false); assert.match(l.json.ai.message, /works without it/);
  const rep = (await s.post('/audit-reports', { team: 'it', engagement: eng.id }, LEAD)).json, P = '/audit-reports/' + rep.id;
  const r = await s.post(P + '/ai-draft', {}, LEAD); assert.equal(r.status, 409); assert.match(r.json.error, /not ready|no AI provider/); assert.match(r.json.error, /yourself/);
  assert.equal((await s.post(P + '/edit', { version: 1, executive_summary: 'Written by the lead auditor without AI (synthetic).' }, LEAD)).status, 200);
  assert.equal((await s.post(P + '/sign', { version: 2 }, LEAD)).json.state, 'signed');
  const ok = await s.post(P + '/approve', { version: 2 }, ADM); assert.equal(ok.status, 200, ok.text); assert.equal(ok.json.state, 'issued');
});

test('sign and approve for issue: the lead signs, an administrator outside the team approves; frozen with a fingerprint', async (t) => {
  const s = await setup(t); const { eng, f } = engagement(s, { stop: 'fieldwork' });
  const rep = (await s.post('/audit-reports', { team: 'it', engagement: eng.id }, LEAD)).json, P = '/audit-reports/' + rep.id;
  assert.ok(rep.skeleton.warnings.length === 0 || rep.skeleton.warnings.every((w) => typeof w === 'string'));
  let r = await s.post(P + '/sign', { version: 1 }, LEAD); assert.equal(r.status, 409); assert.match(r.json.error, /draft report/, 'the engagement must reach draft report');
  s.A.advance(eng.id, { to: 'draft_report' }, LEAD);
  r = await s.post(P + '/sign', { version: 1 }, LEAD); assert.equal(r.status, 409); assert.match(r.json.error, /executive_summary/);
  await s.post(P + '/edit', { version: 1, executive_summary: 'The leaver control needs improvement (synthetic summary).' }, LEAD);
  r = await s.post(P + '/sign', { version: 2 }, AUD2); assert.equal(r.status, 403, 'only the lead signs'); assert.match(r.json.error, /engagement lead/);
  r = await s.post(P + '/sign', { version: 2 }, { user: 'ai:itaudit', role: 'operator' }); assert.equal(r.status, 403);
  // the records change after the skeleton: signing is refused until the report is refreshed
  s.A.addFinding(eng.id, { title: 'Low: offboarding checklist wording', condition: 'Checklist wording unclear (synthetic)', criteria: 'Policy', cause: 'Old template', effect: 'Confusion', recommendation: 'Update the template', rating: 'low', owner: OWNER.user }, LEAD);
  assert.equal((await s.get(P)).json.stale, true, 'the page shows the draft is stale');
  r = await s.post(P + '/sign', { version: 2 }, LEAD); assert.equal(r.status, 409); assert.match(r.json.error, /refresh/);
  r = await s.post(P + '/refresh', { version: 2 }, LEAD); assert.equal(r.status, 200, r.text); assert.equal(r.json.skeleton.findings.length, 2);
  r = await s.post(P + '/sign', { version: 3 }, LEAD); assert.equal(r.status, 409); assert.match(r.json.error, /draft finding/, 'a draft finding blocks signing');
  const low = s.e.app.store.collection('ia_findings').all((x) => x.state === 'draft')[0]; s.A.findingAct(low.id, 'withdraw', { note: 'covered by ' + f.id }, LEAD);
  await s.post(P + '/refresh', { version: 3 }, LEAD);
  r = await s.post(P + '/sign', { version: 4 }, LEAD); assert.equal(r.status, 200, r.text); assert.equal(r.json.signed_by, LEAD.user);
  // approval: admin route; a person; not the signer; not on the audit team
  r = await s.post(P + '/approve', { version: 4 }, HEAD); assert.equal(r.status, 403, 'an operator (even the Head of Audit) cannot approve for issue'); assert.match(r.json.error, /requires role admin/);
  r = await s.post(P + '/approve', { version: 4 }, { user: 'adel.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await s.post(P + '/approve', { version: 4 }, { user: 'svc:approver', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /named person/);
  r = await s.post(P + '/approve', { version: 3 }, ADM); assert.equal(r.status, 409);
  r = await s.post(P + '/return', { version: 4 }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await s.post(P + '/return', { version: 4, note: 'Add the background section' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.state, 'draft'); assert.equal(r.json.returned.by, ADM2.user);
  await s.post(P + '/edit', { version: 4, background: 'Requested by the Board Audit Committee (synthetic).' }, LEAD);
  await s.post(P + '/sign', { version: 5 }, LEAD);
  r = await s.post(P + '/approve', { version: 5, note: 'Approved for issue' }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'issued'); assert.equal(r.json.approved_by, ADM.user); assert.match(r.json.fingerprint, /^[0-9a-f]{64}$/);
  // frozen: nothing changes an issued report
  for (const [p, b] of [['/edit', { version: 5, title: 'changed' }], ['/refresh', { version: 5 }], ['/sign', { version: 5 }], ['/ai-draft', {}]]) { const x = await s.post(P + p, b, LEAD); assert.equal(x.status, 409, p + ' refused on an issued report'); assert.match(x.json.error, /frozen/); }
  assert.equal((await s.post(P + '/approve', { version: 5 }, ADM2)).status, 409);
  let v = await s.get(P + '/verify'); assert.equal(v.json.ok, true); assert.equal(v.json.computed, r.json.fingerprint);
  const raw = s.e.app.store.collection('audit_reports').get(rep.id); raw.frozen.content.executive_summary = 'tampered'; s.e.app.store.collection('audit_reports').put(raw);
  v = await s.get(P + '/verify'); assert.equal(v.json.ok, false, 'a change to the stored issued report is detected');
  assert.equal((await s.get(P + '/verify', VIEW)).status, 403);
  const iss = auditOf(s.e, 'audit-report.issue')[0]; assert.equal(iss.by, ADM.user); assert.equal(iss.role, 'admin'); assert.equal(iss.detail.fingerprint, r.json.fingerprint); assert.equal(iss.detail.signed_by, LEAD.user);
  assert.equal(auditOf(s.e, 'audit-report.sign').length, 2); assert.equal(auditOf(s.e, 'audit-report.return').length, 1); assert.equal(auditOf(s.e, 'audit-report.refresh').length, 2);
  const l = await s.get('/audit-reports'); assert.equal(l.json.reports[0].state, 'issued'); assert.equal(l.json.engagements.find((x) => x.id === eng.id).report, rep.id);
});

test('the AI proposal: through app.provider, kept as a proposal until a person saves it; audited without its content', async (t) => {
  const s = await setup(t); const { eng, f } = engagement(s);
  const rep = (await s.post('/audit-reports', { team: 'it', engagement: eng.id }, LEAD)).json, P = '/audit-reports/' + rep.id;
  const reply = { executive_summary: 'Leaver access removal needs improvement: one medium finding (synthetic AI text).', conclusion: 'Management agreed an action plan (synthetic).', finding_narratives: [{ id: f.id, text: 'Polished narrative (synthetic).' }] };
  s.e.fake.override = () => ({ ok: true, text: '```json\n' + JSON.stringify(reply) + '\n```', model: 'synthetic-model-1', usage: { input: 50, output: 20 } });
  let r = await s.post(P + '/ai-draft', {}, AUD2); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ai.executive_summary, reply.executive_summary); assert.equal(r.json.ai.finding_narratives[f.id], 'Polished narrative (synthetic).');
  assert.equal(r.json.ai.by, 'ai:audit-report'); assert.equal(r.json.ai.requested_by, AUD2.user);
  assert.equal(r.json.content.executive_summary, '', 'not in the report until a person saves it'); assert.equal(r.json.version, 1);
  const sent = s.e.fake.requests[s.e.fake.requests.length - 1].body;
  assert.match(sent.system, /SECURITY RULES/); assert.match(sent.prompt, /<untrusted source="audit-report:/);
  assert.equal((await s.post(P + '/ai-draft', {}, OTHER)).status, 403);
  assert.equal((await s.post(P + '/ai-draft', {}, VIEW)).status, 403);
  r = await s.post(P + '/edit', { version: 1, executive_summary: reply.executive_summary, conclusion: 'Rewritten by the lead (synthetic).' }, LEAD);
  assert.deepEqual(r.json.versions[1].adopted_ai, ['executive_summary'], 'the adopted AI words are marked');
  const a = auditOf(s.e, 'audit-report.ai.draft')[0]; assert.equal(a.by, AUD2.user); assert.equal(a.detail.model, 'synthetic-model-1');
  assert.ok(!JSON.stringify(a).includes('synthetic AI text'), 'the AI call is audited without its content');
});
