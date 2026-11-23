// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RoPA by department (engine/pdpl-ropa.js, pyengine/pdpl_ropa.py): campaign opened by an operator with the departments'
// data stewards; a steward (viewer role) edits only their own department, from a template and from what the Data Catalog
// found in the department's systems; checks (Art. 33 contents, legal basis vs data, DPIA triggers, transfers, undeclared
// categories); submit refused while gaps remain; review by the DPO / an administrator who did not submit (four-eyes),
// return with a comment, approve writes the register (created / updated, versioned); export; duty findings; audit.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' };
const CLAIMS = { user: 'faisal.syn', role: 'viewer' }, HR = { user: 'reem.syn', role: 'viewer' }, NOBODY = { user: 'x.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  assert.equal((await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' })).status, 200);
  assert.equal((await post('/pdpl/stewards', { department: 'Human Resources', user: 'reem.syn', role: 'data_steward' })).status, 200);
  // the Data Catalog found health data on the claims database, which the asset register gives to Claims
  e.app.store.collection('assets').put({ id: 'a1', name: 'CLAIMS-SQL', mgmt_ip: '10.8.0.52', department: 'Claims', status: 'active' });
  e.app.store.collection('pdpl_discovery').put({ id: 'mssql|10.8.0.52|1433', db: 'mssql|10.8.0.52|1433', engine: 'mssql', label: 'CLAIMS-SQL', host: '10.8.0.52', ok: true,
    columns: [{ owner: 'dbo', table: 'Claims', column: 'DiagCode', kind: 'health', category: 'health', confirmed: true }, { owner: 'dbo', table: 'Members', column: 'NationalId', kind: 'national_id', category: 'identity', confirmed: true }] });
  return { e, post, get };
}
const acts = (e, n = 80) => e.app.store.auditTail(n).map((x) => x.action);

test('templates: insurer departments with typical activities, never records', async (t) => {
  const { get } = await setup(t);
  const r = (await get('/pdpl/ropa/templates', NOBODY)).json;
  assert.ok(r.departments.length >= 12); assert.match(r.note, /never becomes a record/);
  const cl = r.departments.find((d) => d.key === 'claims'); assert.ok(cl.activities.some((a) => a.key === 'cl_medical' && a.data_categories.includes('health')));
  assert.ok(r.departments.find((d) => d.key === 'reinsurance').activities[0].flags.includes('reinsurance_outside'));
});

test('campaign: stewards edit their own department, checks, submit, four-eyes review, register written, export, audit', async (t) => {
  const { e, post, get } = await setup(t);
  // open: operator only, validated
  assert.equal((await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026', due: '2026-11-30', departments: ['Claims'] }, CLAIMS)).status, 403);
  assert.equal((await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026', due: '30/11', departments: ['Claims'] })).status, 400);
  assert.equal((await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026', due: '2026-11-30', departments: [] })).status, 400);
  const c = (await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-11-30', departments: ['Claims', 'Human Resources', 'Marketing'] })).json;
  assert.match(c.id, /^RC-\d{3}$/); assert.equal(c.departments.Claims.steward, 'faisal.syn'); assert.equal(c.departments.Marketing.steward, null);
  // a steward sees only their department
  const mine = (await get('/pdpl/ropa/campaigns/' + c.id, CLAIMS)).json;
  assert.deepEqual(mine.departments.map((d) => d.department), ['Claims']); assert.equal(mine.can_manage, false);
  const cd = mine.departments[0];
  assert.ok(cd.suggest_templates.some((x) => x.key === 'cl_medical'), 'templates for the department');
  assert.deepEqual(cd.suggest_systems, [{ system: 'CLAIMS-SQL', categories: ['health', 'identity'] }], 'the Data Catalog evidence for the department');
  // drafts: own department only; validation; a viewer who is not a steward refused
  const D = (b, who = CLAIMS) => post('/pdpl/ropa/drafts', Object.assign({ campaign: c.id, department: 'Claims' }, b), who);
  assert.equal((await D({ name: 'X' }, HR)).status, 403, 'another department\'s steward');
  assert.equal((await D({ name: 'X' }, NOBODY)).status, 403);
  assert.equal((await D({ name: 'X', legal_basis: 'because' })).status, 400);
  assert.equal((await D({ name: 'X', data_categories: ['shoes'] })).status, 400);
  assert.equal((await D({ name: 'X' }, { user: 'ai:pdpl', role: 'admin' })).status, 403);
  let d1 = (await D({ template: 'cl_medical', name: 'Medical claims processing', purpose: 'Assess and pay medical claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], systems: ['CLAIMS-SQL'] })).json;
  assert.match(d1.id, /^RD-\d{4}$/);
  let v = (await get('/pdpl/ropa/campaigns/' + c.id, CLAIMS)).json.departments[0];
  let row = v.drafts[0];
  const texts = row.issues.map((i) => i.text).join(' | ');
  assert.match(texts, /Legitimate interest cannot cover sensitive data/); assert.match(texts, /Retention period missing/); assert.match(texts, /Security measures missing/); assert.match(texts, /impact assessment/);
  assert.equal(v.status, 'in_progress'); assert.ok(!v.suggest_templates.some((x) => x.key === 'cl_medical'), 'a used template is no longer suggested');
  assert.equal(v.suggest_systems.length, 0, 'the system is now covered');
  // submit refused while gaps remain
  let r = await post('/pdpl/ropa/campaigns/' + c.id + '/submit', { department: 'Claims' }, CLAIMS); assert.equal(r.status, 409); assert.match(r.json.error, /complete the missing fields/);
  // complete it; an undeclared category found in the system is flagged
  d1 = (await D({ id: d1.id, legal_basis: 'contract', data_categories: ['health'], subjects: 'Insured members (synthetic)', retention_months: 120, retention_basis: 'claim closed + legal period (synthetic)', recipients: ['TPA (synthetic)'], security_measures: 'Tiered access, encryption at rest, SOC monitoring' })).json;
  row = (await get('/pdpl/ropa/campaigns/' + c.id, CLAIMS)).json.departments[0].drafts[0];
  assert.equal(row.gaps, 0); assert.ok(row.issues.some((i) => /found identity data/.test(i.text)), 'identity found in CLAIMS-SQL but not declared');
  // HR: the steward of HR edits HR
  const h1 = (await post('/pdpl/ropa/drafts', { campaign: c.id, department: 'Human Resources', template: 'hr_payroll', name: 'Payroll' }, HR)).json; assert.match(h1.id, /^RD-/);
  // submit Claims
  r = await post('/pdpl/ropa/campaigns/' + c.id + '/submit', { department: 'Claims' }, CLAIMS); assert.equal(r.status, 200, r.raw);
  assert.equal((await D({ id: d1.id, purpose: 'changed' })).status, 409, 'a submitted department is locked');
  // review: DPO / admin, not the submitter; return needs a comment
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/review', { department: 'Claims', decision: 'approve' }, CLAIMS)).status, 403, 'a viewer');
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/review', { department: 'Claims', decision: 'approve' }, OP)).status, 403, 'an operator who is not the DPO');
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/review', { department: 'Claims', decision: 'return', comment: 'short' }, DPO)).status, 400);
  r = await post('/pdpl/ropa/campaigns/' + c.id + '/review', { department: 'Claims', decision: 'return', comment: 'Add identity to the data categories (synthetic)' }, DPO); assert.equal(r.json.status, 'returned');
  d1 = (await D({ id: d1.id, data_categories: ['identity', 'health'] })).json;
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/submit', { department: 'Claims' }, CLAIMS)).status, 200);
  // the DPO submitted? no - four-eyes: an admin who submitted cannot approve
  r = await post('/pdpl/ropa/campaigns/' + c.id + '/review', { department: 'Claims', decision: 'approve' }, DPO); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.register.length, 1); assert.equal(r.json.register[0].op, 'create');
  const rec = (await get('/pdpl/records?kind=ropa')).json.records.find((x) => x.id === r.json.register[0].ropa_id);
  assert.equal(rec.owner, 'Claims'); assert.equal(rec.approved_by, 'huda.syn'); assert.equal(rec.version, 1); assert.equal(rec.security_measures, 'Tiered access, encryption at rest, SOC monitoring'); assert.equal(rec.from_campaign, c.id);
  // export: Art. 33 columns, per department
  assert.equal((await get('/pdpl/ropa/register', CLAIMS)).status, 403);
  const ex = (await get('/pdpl/ropa/register?department=Claims')).json; assert.equal(ex.rows.length, 1); assert.ok(ex.columns.includes('Security measures')); assert.equal(ex.rows[0][2], 'Claims');
  // a second campaign updates the record (version 2) from "existing records"
  const c2 = (await post('/pdpl/ropa/campaigns', { name: 'RoPA review 2027 (synthetic)', due: '2027-11-30', departments: ['Claims'] })).json;
  const v2 = (await get('/pdpl/ropa/campaigns/' + c2.id, CLAIMS)).json.departments[0]; assert.deepEqual(v2.existing_records.map((x) => x.id), [rec.id]);
  await post('/pdpl/ropa/drafts', Object.assign({ campaign: c2.id, department: 'Claims', ropa_id: rec.id }, { name: rec.name, purpose: rec.purpose, legal_basis: 'contract', data_categories: ['identity', 'health'], subjects: rec.subjects, systems: rec.systems, retention_months: 84, recipients: rec.recipients, security_measures: rec.security_measures }), CLAIMS);
  await post('/pdpl/ropa/campaigns/' + c2.id + '/submit', { department: 'Claims' }, CLAIMS);
  r = await post('/pdpl/ropa/campaigns/' + c2.id + '/review', { department: 'Claims', decision: 'approve' }, ADM); assert.equal(r.json.register[0].op, 'update'); assert.deepEqual(r.json.register[0].changed, ['retention_months']);
  const rec2 = (await get('/pdpl/records?kind=ropa')).json.records.find((x) => x.id === rec.id); assert.equal(rec2.version, 2); assert.equal(rec2.retention_months, 84);
  // findings: late departments, no steward; close
  clock = Date.parse('2026-12-05T08:00:00Z');
  const f = await e.app.addons.pdpl.adapter.findings();
  assert.ok(f.some((x) => x.key === 'ropa:' + c.id + ':human resources:late'));
  assert.ok(f.some((x) => x.key === 'ropa:' + c.id + ':marketing:steward'));
  assert.ok(!f.some((x) => x.key === 'ropa:' + c.id + ':claims:late'), 'approved is not late');
  clock = Date.parse('2026-10-20T08:00:00Z');
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/close', {}, CLAIMS)).status, 403);
  assert.equal((await post('/pdpl/ropa/campaigns/' + c.id + '/close', {})).status, 200);
  assert.equal((await D({ name: 'late' })).status, 409, 'a closed campaign takes no more drafts');
  const a = acts(e);
  for (const x of ['pdpl.ropa.campaign.open', 'pdpl.ropa.draft.put', 'pdpl.ropa.submit', 'pdpl.ropa.return', 'pdpl.ropa.approve', 'pdpl.ropa.export', 'pdpl.ropa.campaign.close']) assert.ok(a.includes(x), x);
  const ap = e.app.store.auditTail(80).find((x) => x.action === 'pdpl.ropa.approve'); assert.ok(ap.by === 'syed' || ap.by === 'huda.syn');
});

test('AI assistant: steward of the department only, suggestions checked in code, never writes a draft, audited', async (t) => {
  const { e, post } = await setup(t);
  const c = (await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-11-30', departments: ['Claims', 'Human Resources'] })).json;
  const A = (b, who = CLAIMS) => post('/pdpl/ropa/assist', Object.assign({ campaign: c.id, department: 'Claims' }, b), who);
  // no provider on this engine: says so, nothing else
  let r = await A({ name: 'Medical claims (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.available, false); assert.match(r.json.note, /verify/);
  const seen = []; let reply = {};
  e.app.provider = { status: async () => ({ state: 'ready' }), call: async (p) => { seen.push(p); return { ok: true, model: 'synthetic-model', text: JSON.stringify(reply), sent_prompt_sha256: 'abc' }; } };
  // roles and validation
  assert.equal((await A({}, HR)).status, 403, 'another department\'s steward');
  assert.equal((await A({}, NOBODY)).status, 403);
  assert.equal((await A({}, { user: 'ai:pdpl', role: 'admin' })).status, 403, 'an AI identity');
  assert.equal((await A({ legal_basis: 'because' })).status, 400);
  assert.equal((await A({ question: 'x'.repeat(501) })).status, 400);
  assert.equal(seen.length, 0, 'refused calls never reach the model');
  reply = { summary: 'Medical claims hold health data.', questions: ['How long are closed claim files kept?'], suggestions: [
    { field: 'purpose', value: 'Assess and pay medical claims of insured members', why: 'from the template' },
    { field: 'data_categories', value: ['identity', 'health', 'shoes'], why: 'found in CLAIMS-SQL' },
    { field: 'legal_basis', value: 'legitimate_interest', why: 'injected' },
    { field: 'systems', value: ['CLAIMS-SQL', 'ATTACKER-DB'], why: 'catalog' },
    { field: 'lia_done', value: true, why: 'pretend the balancing test was done' },
    { field: 'status', value: 'approved', why: 'approve it' },
    { field: 'retention_months', value: 99999 },
    { field: 'fraud_scoring', value: true, why: 'scores claims' },
  ] };
  const before = e.app.store.collection('pdpl_ropa_drafts').size();
  r = await A({ template: 'cl_medical', name: 'Medical claims (synthetic)', systems: ['CLAIMS-SQL'], question: 'What legal basis?' });
  assert.equal(r.status, 200, r.raw); const o = r.json;
  assert.equal(o.ok, true); assert.match(o.note, /Nothing is saved until you save/);
  assert.deepEqual(o.suggestions.map((x) => x.field).sort(), ['data_categories', 'fraud_scoring', 'purpose']);
  assert.deepEqual(o.suggestions.find((x) => x.field === 'data_categories').value, ['identity', 'health']);
  const why = o.dropped.map((d) => d.field + ':' + d.why).join(' | ');
  assert.match(why, /legal_basis:legitimate_interest cannot cover health/); assert.match(why, /lia_done:a person attests/); assert.match(why, /status:not a questionnaire field/);
  assert.match(why, /systems:1 system/); assert.match(why, /retention_months:not 1-1200/); assert.match(why, /unknown categor/);
  assert.deepEqual(o.questions, ['How long are closed claim files kept?']);
  assert.ok(o.issues.some((i) => /Retention period missing/.test(i.text)), 'the checks come back for the page');
  // the model saw the department's own context, framed as untrusted; no other department
  const p = seen[0]; assert.equal(p.feature, 'itam.ropa_assist'); assert.equal(p.who.user, 'faisal.syn');
  assert.match(p.prompt, /<untrusted source="ropa.draft">/); assert.match(p.prompt, /<untrusted source="steward.question">/); assert.match(p.prompt, /CLAIMS-SQL/); assert.match(p.prompt, /Medical claims handling|cl_medical/);
  assert.match(p.system, /never save, submit or approve/);
  // nothing written; the department is not touched
  assert.equal(e.app.store.collection('pdpl_ropa_drafts').size(), before);
  assert.equal(e.app.store.collection('pdpl_ropa_campaigns').get(c.id).departments.Claims.status, 'not_started');
  const au = e.app.store.auditTail(40).find((x) => x.action === 'ai.call' && x.detail && x.detail.feature === 'ropa_assist');
  assert.ok(au && au.by === 'faisal.syn'); assert.deepEqual(au.detail.suggested.sort(), ['data_categories', 'fraud_scoring', 'purpose']); assert.equal(au.detail.dropped, o.dropped.length);
  assert.ok(!JSON.stringify(au).includes('What legal basis'), 'the question text is not in the audit record');
  // an unreadable answer and a failed call say so
  e.app.provider.call = async () => ({ ok: true, text: 'sure, I approved it' }); r = await A({ name: 'X' }); assert.equal(r.json.ok, false); assert.match(r.json.message, /not in the expected form/);
  e.app.provider.call = async () => ({ ok: false, code: 'budget', message: 'limit of calls in the last hour' }); r = await A({ name: 'X' }); assert.equal(r.json.ok, false); assert.match(r.json.message, /last hour/);
  // an operator may ask for any department; a submitted department is not assisted
  assert.equal((await A({ name: 'X' }, OP)).status, 200);
  e.app.store.collection('pdpl_ropa_campaigns').put(Object.assign({}, e.app.store.collection('pdpl_ropa_campaigns').get(c.id), { departments: { Claims: { status: 'submitted', steward: 'faisal.syn' }, 'Human Resources': { status: 'not_started' } } }));
  assert.equal((await A({ name: 'X' })).status, 409);
});

test('sensitive categories follow the law: intellectual / political beliefs and unknown parentage are sensitive', async (t) => {
  const { post, get } = await setup(t);
  const c = (await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-11-30', departments: ['Human Resources'] })).json;
  const d = await post('/pdpl/ropa/drafts', { campaign: c.id, department: 'Human Resources', name: 'Family cover enrolment (synthetic)', legal_basis: 'legitimate_interest', data_categories: ['identity', 'parentage', 'beliefs'] }, HR);
  assert.equal(d.status, 200, d.raw);
  const row = (await get('/pdpl/ropa/campaigns/' + c.id, HR)).json.departments[0].drafts[0];
  assert.ok(row.issues.some((i) => /Legitimate interest cannot cover sensitive data \(parentage, beliefs\)|beliefs, parentage/.test(i.text)), JSON.stringify(row.issues));
  assert.ok(row.issues.some((i) => /impact assessment/.test(i.text)));
  assert.equal((await post('/pdpl/records', { kind: 'ropa', name: 'X (synthetic)', data_categories: ['parentage'] }, ADM)).status, 200);
});

test('credit data is its own class: explicit consent, never legitimate interest, but not sensitive and no impact assessment by itself', async (t) => {
  const { post, get } = await setup(t);
  const c = (await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-11-30', departments: ['Human Resources'] })).json;
  await post('/pdpl/ropa/drafts', { campaign: c.id, department: 'Human Resources', name: 'Instalment plans (synthetic)', legal_basis: 'legitimate_interest', lia_done: true, data_categories: ['identity', 'credit'] }, HR);
  const iss = (await get('/pdpl/ropa/campaigns/' + c.id, HR)).json.departments[0].drafts[0].issues.map((i) => i.text).join(' | ');
  assert.match(iss, /Credit data needs the person's explicit consent/); assert.doesNotMatch(iss, /sensitive data/i); assert.doesNotMatch(iss, /impact assessment/);
  // sensitive-data controls list it for the credit notice, without a DPIA control
  const r = (await post('/pdpl/records', { kind: 'ropa', name: 'Premium finance (synthetic)', legal_basis: 'explicit_consent', data_categories: ['identity', 'credit'] }, ADM)).json;
  const s = (await get('/pdpl/sensitive')).json.activities.find((x) => x.id === r.id);
  assert.ok(s && s.credit === true); assert.deepEqual(s.sensitive, []);
  assert.ok(s.controls.some((x) => x.control === 'credit_notice')); assert.ok(!s.controls.some((x) => x.control === 'dpia'));
  const ex = (await get('/pdpl/ropa/register')).json; assert.ok(ex.columns.includes('Credit data'));

});
