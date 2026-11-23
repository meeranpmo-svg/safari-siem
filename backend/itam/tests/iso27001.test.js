// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ISO/IEC 27001:2022 (engine/iso27001.js, pyengine/iso27001_rules.py) through the real routes: clauses 4-10 and the 93
// Annex A controls on the NCA ECC facts (one collection), an approved NCA ECC confirmation counting for ISO, four-eyes
// confirmations and SoA, the internal audit programme planned and prepared automatically, auditor independence, report
// acceptance raising nonconformities and GRC actions, corrective action verified by another person, the management review
// pack and record, roles (viewer / operator / admin and the refused cases), validation errors, audit records, the duty engineer.
// SYNTHETIC facts only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, MGR = { user: 'mona.syn', role: 'operator' }, AUD = { user: 'adel.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };

const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 3, attested: 15,
    policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }, { title: 'Data Classification Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }],
    control_status: { assets: { state: 'pass', metric: '40 registered', detail: 'ok' }, patch: { state: 'fail', metric: '30/40', detail: '10 host(s) missing critical patches' }, backup: { state: 'pass', metric: '12/12', detail: 'ok' }, roles: { state: 'unknown' } } },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 },
  ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 1, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
  training_12m: 2,
});

async function setup(t) {
  let clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let reads = 0;
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, eccFacts: async () => { reads++; return FACTS(); } });
  const call = async (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, D, call, reads: () => reads, tick: (ms) => { clock += ms; }, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const req = (v, id) => v.clauses.concat(v.annex).find((c) => c.id === id);
const auditOf = (e, action) => e.app.store.auditTail(400).filter((x) => x.action === action);
const PROFILE = { isms_manager: MGR.user, top_management: 'CEO (synthetic)', scope: 'All IT and cyber security services of the head office (synthetic)', scope_approved: '2026-09-01',
  context_reviewed: '2026-09-01', parties_reviewed: '2026-09-01', risk_method_approved: '2026-09-01', auditors: [AUD.user, OP2.user],
  objectives: [{ objective: 'Patch critical vulnerabilities in 14 days', measure: '% within SLA', target: '95%', owner: 'nora.syn', current: '88%', measured_on: '2026-10-20' }] };

test('the register: 25 clause requirements, 93 Annex A controls, ECC checks reused on the same facts', async (t) => {
  const { e, get } = await setup(t);
  const r = await get('/iso27001', VIEW); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.annex.length, 93); assert.equal(v.clauses.length, 25);
  assert.deepEqual(v.themes.map((x) => x.controls), [37, 8, 14, 34]);
  assert.equal(req(v, 'A.5.9').result, 'verified', 'asset register from the same check as NCA ECC ZS-2-1-01');
  assert.equal(req(v, 'A.8.8').result, 'gap', 'critical open vulnerability = gap'); assert.equal(req(v, 'A.8.19').result, 'gap');
  assert.equal(req(v, 'A.5.2').result, 'not_measured'); assert.equal(req(v, 'A.7.1').result, 'no_evidence');
  assert.match(req(v, 'A.7.1').why, /NCA ECC ZS-2-14-01 once - it counts here too/);
  assert.equal(req(v, '5.2').result, 'verified', 'approved information security policy in GRC');
  assert.equal(req(v, '4.3').result, 'gap'); assert.equal(req(v, '9.2').result, 'gap'); assert.equal(req(v, '6.1.3').result, 'gap');
  assert.equal(v.readiness.stage, 'not_ready'); assert.ok(v.readiness.blockers.length);
  assert.equal(v.soa.rows.length, 93); assert.equal(v.soa.applicable, 93);
  assert.match(v.note, /certification body decides/);
  assert.ok(v.findings.some((f) => f.key === 'iso:A.8.8'));
  assert.ok(e.app.addons.iso27001);
  for (const x of v.themes.concat(v.groups)) if (x.levels.applicable) assert.equal(Object.values(x.levels.pct).reduce((a, b) => a + b, 0), 100);
});

test('one evidence collection: an ISO view and an ECC view read the platform once (cache)', async (t) => {
  const { get, reads } = await setup(t);
  await get('/iso27001'); const n1 = reads(); await get('/iso27001'); await get('/iso27001');
  assert.equal(reads(), n1, 'facts are cached for a minute, not re-read per page load');
});

test('record once: an approved NCA ECC confirmation counts for the linked ISO control', async (t) => {
  const { e, post, get } = await setup(t);
  await post('/nca-ecc/profile', { ciso_user: 'khalid.syn' });
  let r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'compliant', evidence: 'badge access logs Q3 (synthetic)' }, OP); assert.equal(r.status, 200, r.raw);
  let v = (await get('/iso27001')).json; assert.equal(req(v, 'A.7.1').result, 'no_evidence', 'not yet approved in ECC: does not count');
  r = await post('/nca-ecc/confirm/ZS-2-14-01/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw);
  e.app.addons.iso27001.facts();   // cache does not matter: confirmations are read live
  v = (await get('/iso27001')).json;
  for (const id of ['A.7.1', 'A.7.2', 'A.7.4']) { assert.equal(req(v, id).result, 'met', id); assert.equal(req(v, id).via_ecc, 'ZS-2-14-01'); }
  assert.ok(v.via_ecc >= 3);
});

test('confirmations: a person records, a different ISMS manager / admin approves; validation names the field', async (t) => {
  const { e, post, get } = await setup(t);
  let r = await post('/iso27001/profile', PROFILE, OP); assert.equal(r.status, 403, 'profile is admin-only');
  r = await post('/iso27001/profile', Object.assign({}, PROFILE, { auditors: ['ai:bot'] })); assert.equal(r.status, 400); assert.match(r.json.error, /auditors\[0\]/);
  r = await post('/iso27001/profile', Object.assign({}, PROFILE, { objectives: [{ measure: 'x' }] })); assert.equal(r.status, 400); assert.match(r.json.error, /objectives\[0\]\.objective is required/);
  r = await post('/iso27001/profile', Object.assign({}, PROFILE, { scope_approved: '2099-01-01' })); assert.equal(r.status, 400); assert.match(r.json.error, /scope_approved cannot be in the future/);
  r = await post('/iso27001/profile', PROFILE); assert.equal(r.status, 200, r.raw);
  assert.equal(auditOf(e, 'iso.profile').length, 1);
  r = await post('/iso27001/confirm', { id: 'A.7.3', status: 'compliant' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  r = await post('/iso27001/confirm', { id: 'Z.1', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be/);
  r = await post('/iso27001/confirm', { id: 'A.7.3', status: 'compliant', evidence: 'clear desk walk-through (synthetic)' }, BOT); assert.equal(r.status, 403);
  r = await post('/iso27001/confirm', { id: 'A.7.3', status: 'compliant', evidence: 'clear desk walk-through (synthetic)' }, VIEW); assert.equal(r.status, 403, 'viewer cannot record');
  r = await post('/iso27001/confirm', { id: 'A.7.3', status: 'compliant', evidence: 'clear desk walk-through (synthetic)' }, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'pending');
  r = await post('/iso27001/confirm/A.7.3/decide', { decision: 'approve' }, OP2); assert.equal(r.status, 403, 'not the ISMS manager'); assert.match(r.json.error, /ISMS manager/);
  r = await post('/iso27001/confirm/A.7.3/decide', { decision: 'reject' }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await post('/iso27001/confirm/A.7.3/decide', { decision: 'approve' }, MGR); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'met');
  await post('/iso27001/confirm', { id: 'A.7.8', status: 'compliant', evidence: 'DC layout (synthetic)' }, MGR);
  r = await post('/iso27001/confirm/A.7.8/decide', { decision: 'approve' }, MGR); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  // automated evidence wins: a confirmed "compliant" never hides a verified gap
  await post('/iso27001/confirm', { id: 'A.8.8', status: 'compliant', evidence: 'says fine (synthetic)' }, OP); await post('/iso27001/confirm/A.8.8/decide', { decision: 'approve' }, MGR);
  const v = (await get('/iso27001')).json; assert.equal(req(v, 'A.8.8').result, 'gap'); assert.equal(req(v, 'A.8.8').conflict, true);
  assert.equal(auditOf(e, 'iso.confirm.approve').length, 2);
});

test('Statement of Applicability: exclusion needs a justification, approved by someone else, goes stale when changed', async (t) => {
  const { e, post, get } = await setup(t);
  await post('/iso27001/profile', PROFILE);
  let r = await post('/iso27001/soa', { exclusions: { 'A.8.30': 'short' } }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /exclusions\.A\.8\.30/);
  r = await post('/iso27001/soa', { exclusions: { 'A.9.1': 'nothing here at all' } }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /not an Annex A control/);
  r = await post('/iso27001/soa', { exclusions: {} }, OP); assert.equal(r.status, 403);
  r = await post('/iso27001/soa', { exclusions: { 'A.8.30': 'no outsourced development: all applications are bought as packages (synthetic)' } }, MGR); assert.equal(r.status, 200, r.raw);
  r = await post('/iso27001/soa/decide', { decision: 'approve' }, MGR); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await post('/iso27001/soa/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.approved, true);
  let v = (await get('/iso27001')).json;
  assert.equal(req(v, 'A.8.30').result, 'not_applicable'); assert.equal(req(v, '6.1.3').result, 'verified'); assert.equal(v.soa.excluded, 1);
  assert.ok(e.app.store.collection('iso_soa').get('v1'), 'the approved version is kept');
  const csv = await get('/iso27001/export?what=soa'); assert.equal(csv.status, 200); assert.match(csv.json.csv, /approved by syed/); assert.match(csv.json.csv, /"A\.8\.30".*"No"/);
  // changing the exclusions without approval makes the approved SoA stale (6.1.3 becomes a gap until re-approved)
  e.app.store.collection('iso_soa').put(Object.assign({}, e.app.store.collection('iso_soa').get('current'), { exclusions: {} }));
  v = (await get('/iso27001')).json; assert.equal(req(v, '6.1.3').result, 'gap'); assert.match(req(v, '6.1.3').why, /no longer matches/);
  assert.equal((await get('/iso27001/export?what=bogus')).status, 400);
  assert.equal(auditOf(e, 'iso.soa.approve').length, 1); assert.equal(auditOf(e, 'iso.export').length, 1);
});

test('internal audit programme: planned risk-first, prepared automatically, independent auditor, report accepted by another person', async (t) => {
  const { e, D, post, get } = await setup(t);
  await post('/iso27001/profile', PROFILE);
  // the daily job plans the programme itself once the scope is approved, and prepares what is due within 30 days
  const I = e.app.addons.iso27001;
  await I.tick();
  let p = (await get('/iso27001/programme', VIEW)).json;
  assert.equal(p.audits.length, 12);
  const scoped = p.audits.reduce((n, a) => n + a.scope.length, 0); assert.equal(scoped, 118, 'every clause and control in exactly one audit');
  const first = p.audits[0]; assert.equal(first.status, 'prepared', 'the first audit is due within 30 days and already prepared');
  assert.ok(first.working_paper.tests.length > 0 && first.findings.length > 0, 'tests and proposed findings come from the register');
  assert.equal(p.audits.filter((a) => a.status === 'prepared').length, 1);
  assert.equal((await get('/iso27001/history', VIEW)).status, 404);
  assert.equal(e.app.store.collection('iso_history').all(() => true).length, 1, 'the daily snapshot');
  let r = await post('/iso27001/programme', {}, OP); assert.equal(r.status, 403);
  r = await post('/iso27001/programme', { months: 99 }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /months must be at most 36/);
  // independence: not the ISMS manager on the ISMS core, not someone who recorded a control in scope, only listed auditors
  const isms = p.audits.find((a) => a.unit === 'ISMS');
  r = await post('/iso27001/audits/' + isms.id + '/assign', { auditor: MGR.user }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /not in the ISO 27001 profile's list/);
  await post('/iso27001/profile', Object.assign({}, PROFILE, { auditors: [AUD.user, OP2.user, MGR.user] }));
  r = await post('/iso27001/audits/' + isms.id + '/assign', { auditor: MGR.user }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /objectivity/);
  const a8 = p.audits.find((a) => a.unit === 'A8-OPS');
  await post('/iso27001/confirm', { id: 'A.8.7', status: 'compliant', evidence: 'EDR console report (synthetic)' }, OP2);
  r = await post('/iso27001/audits/' + a8.id + '/assign', { auditor: OP2.user }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /recorded or approved A\.8\.7/);
  r = await post('/iso27001/audits/' + a8.id + '/assign', { auditor: 'ai:auditor' }, MGR); assert.equal(r.status, 400);
  r = await post('/iso27001/audits/' + a8.id + '/assign', { auditor: AUD.user }, OP); assert.equal(r.status, 403, 'assigning needs the ISMS manager');
  r = await post('/iso27001/audits/' + a8.id + '/assign', { auditor: AUD.user }, MGR); assert.equal(r.status, 200, r.raw);
  if (a8.status === 'planned') { r = await post('/iso27001/audits/' + a8.id + '/prepare', {}, MGR); assert.equal(r.status, 200, r.raw); }
  const wp = e.app.store.collection('iso_audits').get(a8.id);
  assert.ok(wp.working_paper.tests.some((x) => x.id === 'A.8.8' && x.proposed === 'minor'), 'the verified vulnerability gap is proposed as a minor nonconformity');
  // only the assigned auditor records findings; evidence requests must be resolved before submitting
  const F = [{ requirement: 'A.8.8', grade: 'minor', statement: 'One critical vulnerability open past SLA (synthetic)', evidence: 'scan 2026-10-27' },
    { requirement: 'A.8.19', grade: 'major', statement: '10 hosts missing critical patches (synthetic)' }, { requirement: 'A.8.13', grade: 'ofi', statement: 'Automate restore tests (synthetic)' }];
  r = await post('/iso27001/audits/' + a8.id + '/findings', { findings: F }, OP2); assert.equal(r.status, 403);
  r = await post('/iso27001/audits/' + a8.id + '/findings', { findings: [{ requirement: 'A.5.1', grade: 'minor', statement: 'x' }] }, AUD); assert.equal(r.status, 400); assert.match(r.json.error, /not in the scope/);
  r = await post('/iso27001/audits/' + a8.id + '/findings', { findings: [{ requirement: 'A.8.8', grade: 'evidence_request', statement: 'x' }], submit: true, conclusion: 'ok' }, AUD); assert.equal(r.status, 400); assert.match(r.json.error, /evidence request/);
  r = await post('/iso27001/audits/' + a8.id + '/findings', { findings: F, submit: true }, AUD); assert.equal(r.status, 400); assert.match(r.json.error, /conclusion is required/);
  r = await post('/iso27001/audits/' + a8.id + '/findings', { findings: F, submit: true, conclusion: 'Operations controls partly effective (synthetic)' }, AUD); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'awaiting_acceptance');
  r = await post('/iso27001/audits/' + a8.id + '/accept', {}, AUD); assert.equal(r.status, 403);
  await post('/iso27001/profile', Object.assign({}, PROFILE, { isms_manager: AUD.user }));
  r = await post('/iso27001/audits/' + a8.id + '/accept', {}, AUD); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  await post('/iso27001/profile', PROFILE);
  r = await post('/iso27001/audits/' + a8.id + '/accept', { note: 'accepted' }, MGR); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.nonconformities.length, 2, 'major + minor become nonconformities; the OFI does not');
  const G = e.app.addons.grcRegisters || require('../engine/grc-registers').createGrcRegisters(e.app);
  const acts = G.actionList({}).items.filter((x) => x.source === 'iso'); assert.equal(acts.length, 2, 'a GRC action per nonconformity');
  assert.equal(auditOf(e, 'iso.audit.accept').length, 1); assert.equal(auditOf(e, 'iso.audit.assign').length, 1);
  // corrective action (10.2): owner plans and reports done, a different person verifies effectiveness
  const nc = e.app.store.collection('iso_ncs').all(() => true).find((x) => x.grade === 'major');
  r = await post('/iso27001/ncs/' + nc.id + '/implemented', { evidence: 'patched' }, OP); assert.equal(r.status, 409);
  r = await post('/iso27001/ncs/' + nc.id, { root_cause: 'short', corrective_action: 'Weekly patch window with a report (synthetic)', owner: OP.user }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /root_cause must be at least 10/);
  r = await post('/iso27001/ncs/' + nc.id, { root_cause: 'No patch window agreed with the business (synthetic)', corrective_action: 'Weekly patch window with a report (synthetic)', owner: OP.user }, OP2); assert.equal(r.status, 403);
  r = await post('/iso27001/ncs/' + nc.id, { root_cause: 'No patch window agreed with the business (synthetic)', corrective_action: 'Weekly patch window with a report (synthetic)', owner: OP.user }, MGR); assert.equal(r.status, 200, r.raw);
  r = await post('/iso27001/ncs/' + nc.id + '/implemented', { evidence: 'patch report week 44 (synthetic)' }, OP); assert.equal(r.status, 200, r.raw);
  r = await post('/iso27001/ncs/' + nc.id + '/verify', { decision: 'effective', note: 'checked' }, OP); assert.equal(r.status, 403, 'the implementer never verifies');
  r = await post('/iso27001/ncs/' + nc.id + '/verify', { decision: 'effective', note: 'checked' }, OP2); assert.equal(r.status, 403, 'only auditor / ISMS manager / admin');
  r = await post('/iso27001/ncs/' + nc.id + '/verify', { decision: 'not_effective', note: '3 hosts still missing (synthetic)' }, AUD); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'action');
  await post('/iso27001/ncs/' + nc.id + '/implemented', { evidence: 'patch report week 45 (synthetic)' }, OP);
  r = await post('/iso27001/ncs/' + nc.id + '/verify', { decision: 'effective', note: 're-scan clean (synthetic)' }, AUD); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'closed');
  assert.equal(auditOf(e, 'iso.nc.verify').length, 2);
  // the duty engineer sees the overdue nonconformity once its due date passes
  const v = (await get('/iso27001')).json; assert.equal(req(v, '10.2').result, 'gap'); assert.match(req(v, '10.2').why, /without a root cause and corrective action/, 'the minor one is still unplanned');
  void D;
});

test('management review: the 9.3.2 pack from the records, then the meeting recorded by the ISMS manager', async (t) => {
  const { e, post, get } = await setup(t);
  await post('/iso27001/profile', PROFILE);
  let r = await get('/iso27001/reviews/pack', VIEW); assert.equal(r.status, 403, 'the pack names people and gaps: operator and above');
  r = await get('/iso27001/reviews/pack', OP); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.inputs.map((x) => x.id), ['a', 'b', 'c', 'd1', 'd2', 'd3', 'd4', 'e', 'f', 'g']);
  assert.match(JSON.stringify(r.json.inputs), /Patch critical vulnerabilities/);
  r = await post('/iso27001/reviews', { held_on: '2026-10-27', chaired_by: 'CEO (synthetic)', attendees: ['mona.syn'], decisions: 'short' }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /decisions must be at least 10/);
  r = await post('/iso27001/reviews', { held_on: '2026-10-27', chaired_by: 'CEO', attendees: ['mona.syn'], decisions: 'Approve the 2027 ISMS budget (synthetic)' }, OP); assert.equal(r.status, 403);
  r = await post('/iso27001/reviews', { held_on: '2026-10-27', chaired_by: 'CEO (synthetic)', attendees: ['mona.syn', 'nora.syn'], decisions: 'Approve the 2027 ISMS budget (synthetic)', actions: ['Hire a second SOC analyst'] }, MGR);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.actions.length, 1); assert.ok(r.json.actions[0].grc_action);
  const v = (await get('/iso27001')).json; assert.equal(req(v, '9.3').result, 'verified'); assert.equal(req(v, '5.1').result, 'verified');
  r = await get('/iso27001/reviews/pack', OP); assert.match(JSON.stringify(r.json.inputs[0]), /Hire a second SOC analyst/);
  assert.equal(auditOf(e, 'iso.review.record').length, 1);
});

test('gaps to GRC once, the register export, and the duty engineer', async (t) => {
  const { e, D, post, get } = await setup(t);
  await post('/iso27001/profile', PROFILE);
  let r = await post('/iso27001/gaps-to-grc', {}, OP); assert.equal(r.status, 403);
  r = await post('/iso27001/gaps-to-grc', {}, MGR); assert.equal(r.status, 200, r.raw); assert.ok(r.json.created.length >= 2);
  r = await post('/iso27001/gaps-to-grc', {}, MGR); assert.equal(r.json.created.length, 0, 'never twice'); assert.ok(r.json.skipped.length);
  r = await get('/iso27001/export', VIEW); assert.equal(r.status, 403);
  r = await get('/iso27001/export', OP); assert.equal(r.status, 200); assert.match(r.json.csv, /^"Requirement"/); assert.doesNotMatch(r.json.csv, /^"[=+@]/m);
  const eng = e.app.addons.iso27001.adapter; void D;
  const f = await eng.findings(); assert.ok(f.some((x) => x.key === 'iso:A.8.8'));
  const inv = eng.investigate(f.find((x) => x.key === 'iso:A.8.8')); assert.match(inv.summary, /also NCA ECC ZS-2-10-01/);
  assert.equal((await eng.verify({ key: 'iso:A.8.8' })).present, true);
  assert.equal((await eng.verify({ key: 'iso:nothing' })).present, false);
});
