// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// The PDPL operating pages (engine/pdpl-workflows.js, pyengine/pdpl_workflows.py): records of processing with completeness
// and export, sensitive data controls, the data subject request workflow (identity, systems, one extension, refusal by the
// DPO, letters), transfer impact assessment signed four-eyes, breach playbook, processor due diligence and sub-processor
// approval, the programme (stewards, playbooks, training, maturity, obligations, penalties). Roles, validation, audit.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  return e;
}
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' };
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
const get = (e, p, who = OP) => e.req('GET', p, who);
const acts = (e, n = 60) => e.app.store.auditTail(n).map((x) => x.action);
async function base(e) {
  assert.equal((await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' }, ADM)).status, 200);
  const a = await post(e, '/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', purpose: 'settle health claims', legal_basis: 'contract', data_categories: ['identity', 'health'], subjects: 'insured members',
    systems: ['CLAIMS-DB', 'CRM'], retention_months: 120, owner: 'Claims', reviewed: '2026-06-01', sources: 2 });
  assert.equal(a.status, 200, a.raw);
  return a.json.id;
}

test('records of processing: completeness, links, export audited; viewer refused', async (t) => {
  const e = await setup(t); const id = await base(e);
  await post(e, '/pdpl/records', { kind: 'ropa', name: 'Marketing list (synthetic)' });
  assert.equal((await get(e, '/pdpl/ropa', VW)).status, 403);
  const r = (await get(e, '/pdpl/ropa')).json;
  assert.equal(r.total, 2); assert.equal(r.complete, 1);
  const m = r.activities.find((x) => x.id === id);
  assert.equal(m.completeness, 100); assert.equal(m.dpia, 'missing'); assert.ok(m.dpia_needed_for.some((w) => /sensitive/.test(w)));
  assert.deepEqual(m.sensitive, ['health']); assert.equal(m.sensitive_controls, false);
  const x = (await get(e, '/pdpl/ropa/export')).json;
  assert.equal(x.columns.length, x.rows[0].length); assert.ok(acts(e).includes('pdpl.ropa.export'));
});

test('sensitive controls: gaps become findings, health control required, recorded and re-scored', async (t) => {
  const e = await setup(t); const id = await base(e);
  let s = (await get(e, '/pdpl/sensitive')).json;
  assert.equal(s.activities.length, 1); assert.ok(s.activities[0].controls.some((c) => c.control === 'health_chi'));
  assert.ok(s.activities[0].controls.every((c) => c.control !== 'credit_notice'));
  assert.equal(s.findings[0].requirement, 'P-14'); assert.equal(s.findings[0].severity, 'high');
  assert.equal((await post(e, '/pdpl/sensitive/' + id, { encryption_at_rest: 'yes' })).status, 400, 'booleans only');
  assert.equal((await post(e, '/pdpl/sensitive/PD-ROPA-999', { encryption_at_rest: true })).status, 404);
  assert.equal((await post(e, '/pdpl/sensitive/' + id, { access_review: '2099-01-01' })).status, 400, 'a review in the future');
  const r = await post(e, '/pdpl/sensitive/' + id, { lawful_basis: true, encryption_at_rest: true, masking_nonprod: true, access_logged: true, health_chi: true, access_tiers: ['claims-adjuster', 'medical-reviewer'], access_review: '2026-09-01' });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.gaps, 1, 'only the DPIA is still missing');
  assert.equal((await post(e, '/pdpl/sensitive/' + id, { evidence: 'updated' })).json.gaps, 1, 'updated in place, not a second record');
  assert.equal((await get(e, '/pdpl/records?kind=sensitive_control')).json.records.length, 1);
  assert.equal((await post(e, '/pdpl/records', { kind: 'sensitive_control', ropa_id: id })).status, 400, 'not through the generic register');
  assert.ok(acts(e).includes('pdpl.sensitive.controls'));
});

test('data subject request: identity, systems, respond only when unblocked, one extension, letter', async (t) => {
  const e = await setup(t); await base(e);
  assert.equal((await post(e, '/pdpl/dsar', { ref: 'REQ-1', type: 'access', channel: 'branch' })).status, 400, 'received is required');
  assert.equal((await post(e, '/pdpl/dsar', { ref: 'REQ 1;', type: 'access', channel: 'branch', received: '2026-10-01' })).status, 400, 'ref format');
  assert.equal((await post(e, '/pdpl/dsar', { ref: 'REQ-1', type: 'access', channel: 'branch', received: '2026-10-01' }, VW)).status, 403);
  const n = await post(e, '/pdpl/dsar', { ref: 'REQ-1', type: 'access', channel: 'branch', received: '2026-10-01', systems: ['CLAIMS-DB', 'CRM'] });
  assert.equal(n.status, 200, n.raw); const id = n.json.id;
  assert.equal(n.json.due, '2026-10-31'); assert.equal(n.json.days_left, 10, 'whole days left');
  assert.equal((await post(e, '/pdpl/dsar', { ref: 'req-1', type: 'copy', channel: 'email', received: '2026-10-02' })).status, 409, 'same reference twice');
  let r = await post(e, '/pdpl/dsar/' + id + '/respond', { outcome: 'fulfilled' });
  assert.equal(r.status, 409); assert.match(r.json.error, /identity not verified/);
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/verify', { method: 'by phone' })).status, 400);
  r = await post(e, '/pdpl/dsar/' + id + '/verify', { method: 'national_id_in_branch' }); assert.equal(r.json.stage, 'in_progress');
  await post(e, '/pdpl/dsar/' + id + '/task', { system: 'CLAIMS-DB', status: 'done' });
  assert.match((await post(e, '/pdpl/dsar/' + id + '/respond', { outcome: 'fulfilled' })).json.error, /open in: CRM/);
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/extend', { reason: 'short' })).status, 400);
  r = await post(e, '/pdpl/dsar/' + id + '/extend', { reason: 'the CRM archive must be restored from tape' });
  assert.equal(r.status, 200); assert.equal(r.json.due, '2026-11-30');
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/extend', { reason: 'the CRM archive must be restored again' })).status, 409, 'only once');
  const L = (await get(e, '/pdpl/dsar/' + id + '/letter')).json; assert.match(L.en, /further 30 days/); assert.match(L.ar, /ثلاثين يوماً/);
  await post(e, '/pdpl/dsar/' + id + '/task', { system: 'CRM', status: 'not_found' });
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/respond', { outcome: 'partially' })).status, 400, 'partial needs a note');
  r = await post(e, '/pdpl/dsar/' + id + '/respond', { outcome: 'fulfilled' });
  assert.equal(r.status, 200); assert.equal(r.json.stage, 'responded'); assert.equal(r.json.overdue, false);
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/task', { system: 'CRM', status: 'open' })).status, 409, 'closed');
  assert.match((await get(e, '/pdpl/dsar/' + id + '/letter')).json.en, /enclosed/);
  const a = acts(e); for (const k of ['pdpl.dsar.new', 'pdpl.dsar.verify', 'pdpl.dsar.task', 'pdpl.dsar.extend', 'pdpl.dsar.respond', 'pdpl.dsar.letter']) assert.ok(a.includes(k), k);
});

test('data subject request: refusal by the DPO only, with a ground; late extension refused', async (t) => {
  const e = await setup(t); await base(e);
  const id = (await post(e, '/pdpl/dsar', { ref: 'REQ-2', type: 'destruction', channel: 'email', received: '2026-09-01' })).json.id;
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/extend', { reason: 'too late to ask for more time' })).status, 409);
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/refuse', { ground: 'legal', note: 'claims records kept 10 years' })).status, 403, 'not the DPO');
  assert.equal((await post(e, '/pdpl/dsar/' + id + '/refuse', { ground: 'because', note: 'x' }, DPO)).status, 400);
  const r = await post(e, '/pdpl/dsar/' + id + '/refuse', { ground: 'legal', note: 'claims records kept 10 years' }, DPO);
  assert.equal(r.json.stage, 'refused'); assert.equal(r.json.overdue, true, 'answered after 30 days is still late');
  assert.match((await get(e, '/pdpl/dsar/' + id + '/letter')).json.en, /another law requires/);
  const v = (await get(e, '/pdpl/dsar')).json; assert.equal(v.open, 0);
});

test('transfer impact assessment: scored in Python, signed by the DPO who did not prepare it', async (t) => {
  const e = await setup(t); await base(e);
  const tr = (await post(e, '/pdpl/records', { kind: 'transfer', name: 'Reinsurer (synthetic)', country: 'Germany', basis: 'scc', sensitive: true })).json.id;
  let v = (await get(e, '/pdpl/transfers')).json;
  assert.ok(v.transfers[0].gaps.some((g) => /not signed/.test(g)));
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: { purpose: 'central_operations' } })).status, 400, 'every question');
  const ans = { purpose: 'contract_with_subject', recipient_law: 'yes', gov_access: 'no', sensitive: 'yes', scale: 'regular', minimised: 'yes', encryption: 'yes, keys in the Kingdom', onward: 'allowed with our approval', national_security: 'no', necessity: 'no' };
  const s = await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: ans }, DPO);
  assert.equal(s.status, 200, s.raw); assert.equal(s.json.level, 'medium'); assert.ok(s.json.required.some((x) => /sensitive/.test(x)));
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, DPO)).status, 403, 'four-eyes');
  await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: ans }, OP);
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, ADM)).status, 403, 'only the DPO');
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, DPO)).status, 200);
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, DPO)).status, 409, 'already signed');
  v = (await get(e, '/pdpl/transfers')).json; assert.deepEqual(v.transfers[0].gaps, []);
  const bad = await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: Object.assign({}, ans, { purpose: 'none of these' }) });
  assert.equal(bad.json.outcome, 'not_permitted');
  assert.equal((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, DPO)).status, 409, 'no permitted purpose');
  assert.ok(acts(e).includes('pdpl.transfer.tia.sign'));
  // PDPL Art. 29: the three conditions, the safeguards that replace two of them, and the Art. 29(3) necessity case
  const cond = (r, id) => r.json.conditions.find((c) => c.id === id);
  let r = await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: ans });
  assert.equal(cond(r, 'adequacy').state, 'safeguards', 'SCC replace the adequacy condition'); assert.equal(cond(r, 'minimum').state, 'safeguards'); assert.equal(cond(r, 'security').state, 'met');
  r = await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: Object.assign({}, ans, { national_security: 'yes' }) });
  assert.equal(r.json.outcome, 'not_permitted', 'national security always applies'); assert.ok(r.json.required.some((x) => /national security/.test(x)));
  assert.match((await post(e, '/pdpl/transfers/' + tr + '/tia/sign', {}, DPO)).json.error, /does not meet PDPL Art\. 29.*national security/);
  r = await post(e, '/pdpl/transfers/' + tr + '/tia', { answers: Object.assign({}, ans, { national_security: 'unclear' }) }); assert.equal(r.json.outcome, 'stop');
  const tr2 = (await post(e, '/pdpl/records', { kind: 'transfer', name: 'Group IT (synthetic)', country: 'Bahrain', basis: 'adequacy' })).json.id;
  r = await post(e, '/pdpl/transfers/' + tr2 + '/tia', { answers: Object.assign({}, ans, { recipient_law: 'yes', minimised: 'partly' }) });
  assert.equal(cond(r, 'adequacy').state, 'met', 'basis adequacy recorded'); assert.equal(cond(r, 'minimum').state, 'not_met'); assert.equal(r.json.outcome, 'not_permitted', 'more than the minimum fails Art. 29(2)');
  const tr3 = (await post(e, '/pdpl/records', { kind: 'transfer', name: 'Cloud (synthetic)', country: 'Ireland' })).json.id;
  r = await post(e, '/pdpl/transfers/' + tr3 + '/tia', { answers: Object.assign({}, ans, { recipient_law: 'yes', minimised: 'yes' }) });
  assert.equal(r.json.outcome, 'not_permitted', 'a local law is not an SDAIA adequacy finding'); assert.match(cond(r, 'adequacy').why, /SDAIA/);
  r = await post(e, '/pdpl/transfers/' + tr3 + '/tia', { answers: Object.assign({}, ans, { recipient_law: 'no / unknown', minimised: 'no', necessity: 'yes' }) });
  assert.equal(cond(r, 'adequacy').state, 'disapplied'); assert.equal(cond(r, 'minimum').state, 'disapplied'); assert.notEqual(r.json.outcome, 'not_permitted');
});

test('breach playbook: assess before notifying, remediate before lessons, the clock', async (t) => {
  const e = await setup(t); await base(e);
  const b = (await post(e, '/pdpl/records', { kind: 'breach', ref: 'BR-1', aware_at: '2026-10-19T08:00Z' })).json.id;
  let v = (await get(e, '/pdpl/breaches')).json.breaches[0];
  assert.equal(v.hours_left, 48); assert.match(v.next, /Contain/);
  assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: 'notify_sdaia' })).status, 409);
  assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: 'brag' })).status, 400);
  assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: 'contain', at: '2027-01-01T00:00Z' })).status, 400, 'future');
  for (const s of ['contain', 'assess', 'notify_sdaia']) assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: s, note: 'synthetic' })).status, 200, s);
  assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: 'contain' })).status, 409, 'once');
  assert.equal((await post(e, '/pdpl/breach/' + b + '/step', { step: 'lessons' })).status, 409);
  v = (await get(e, '/pdpl/breaches')).json.breaches[0];
  assert.equal(v.late, false); assert.equal(v.hours_left, null);
  assert.ok((await get(e, '/pdpl/records?kind=breach')).json.records[0].sdaia_notified_at);
  assert.ok(acts(e).includes('pdpl.breach.step'));
});

test('processors: due diligence score, sub-processor approved by the DPO, not the proposer', async (t) => {
  const e = await setup(t); await base(e);
  const p = (await post(e, '/pdpl/records', { kind: 'processor', name: 'TPA (synthetic)', agreement: '2026-01-01' })).json.id;
  let r = await post(e, '/pdpl/processors/' + p + '/assessment', { iso27001: true, breach_24h: false });
  assert.equal(r.json.score, 17); assert.equal((await get(e, '/pdpl/processors')).json.findings.length, 1);
  assert.equal((await post(e, '/pdpl/processors/' + p + '/assessment', { iso27001: 1 })).status, 400);
  r = await post(e, '/pdpl/processors/' + p + '/subprocessor', { name: 'Cloud host (synthetic)', country: 'KSA' }, DPO);
  assert.equal(r.json.pending_subprocessors, 1);
  assert.equal((await post(e, '/pdpl/processors/' + p + '/subprocessor/1', { decision: 'approve' }, OP)).status, 403, 'not the DPO');
  assert.equal((await post(e, '/pdpl/processors/' + p + '/subprocessor/1', { decision: 'approve' }, DPO)).status, 403, 'proposer');
  assert.equal((await post(e, '/pdpl/processors/' + p + '/subprocessor/1', { decision: 'reject' }, ADM)).status, 400, 'reject needs a note');
  r = await post(e, '/pdpl/processors/' + p + '/subprocessor/1', { decision: 'approve' }, ADM);
  assert.equal(r.json.subprocessors[0].status, 'approved');
  assert.equal((await post(e, '/pdpl/processors/' + p + '/subprocessor/1', { decision: 'approve' }, ADM)).status, 409);
  assert.equal((await post(e, '/pdpl/processors/' + p + '/subprocessor/9', { decision: 'approve' }, ADM)).status, 404);
  assert.ok(acts(e).includes('pdpl.processor.sub.approve'));
});

test('programme: stewards, playbooks, training, maturity, obligations with penalties; DPIA view', async (t) => {
  const e = await setup(t); await base(e);
  let g = (await get(e, '/pdpl/programme')).json;
  assert.equal(g.departments[0].department, 'claims'); assert.equal(g.departments[0].gap, true);
  assert.ok(g.obligations.find((o) => o.id === 'register').state === 'gap');
  assert.ok(g.obligations.find((o) => o.id === 'sensitive').criminal);
  assert.match(g.penalties.fine, /5,000,000/);
  assert.equal((await post(e, '/pdpl/stewards', { department: 'Claims', user: 'bad user', role: 'data_steward' })).status, 400);
  assert.equal((await post(e, '/pdpl/stewards', { department: 'Claims', user: 'omar.syn', role: 'data_steward' }, VW)).status, 403);
  const st = await post(e, '/pdpl/stewards', { department: 'Claims', user: 'omar.syn', role: 'data_steward' }); assert.equal(st.status, 200);
  assert.equal((await post(e, '/pdpl/playbooks', { team: 'Claims', title: 'Deleting a member on request', topic: 'deletion', steps: ['find', 'check legal hold', 'delete', 'record'] })).status, 200);
  assert.equal((await post(e, '/pdpl/training', { team: 'Claims', topic: 'PDPL basics', date: '2026-09-15', attendees: 22 })).status, 200);
  assert.equal((await post(e, '/pdpl/maturity', { answers: { 'mapping.map': 'yes' } })).status, 400);
  const ans = {}; for (const [c, q] of Object.entries(g.questions)) for (const x of q.questions) ans[x.id] = c === 'audit' ? 'no' : 'yes';
  const m = await post(e, '/pdpl/maturity', { answers: ans }); assert.equal(m.status, 200); assert.equal(m.json.score.overall, 75); assert.equal(m.json.score.level, 'Managed');
  g = (await get(e, '/pdpl/programme')).json;
  assert.equal(g.departments[0].gap, false); assert.equal(g.departments[0].playbooks.length, 1);
  assert.equal(g.measured.activities_with_steward_pct, 100); assert.equal(g.obligations.find((o) => o.id === 'training').state, 'met');
  assert.equal(g.maturity.score.overall, 75);
  assert.equal((await post(e, '/pdpl/records', { kind: 'steward', id: st.json.id, status: 'archived' })).status, 200, 'archiving through the register');
  const d = (await get(e, '/pdpl/dpia/view')).json; assert.equal(d.missing, 1);
  const a = acts(e); for (const k of ['pdpl.steward.put', 'pdpl.playbook.put', 'pdpl.training.put', 'pdpl.maturity']) assert.ok(a.includes(k), k);
});

test('service identities never write; the patrol picks up sensitive and processor gaps', async (t) => {
  const e = await setup(t); const id = await base(e);
  assert.equal((await post(e, '/pdpl/sensitive/' + id, { lawful_basis: true }, { user: 'system:x', role: 'operator' })).status, 403);
  assert.equal((await post(e, '/pdpl/dsar', { ref: 'R-9', type: 'access', channel: 'web', received: '2026-10-01' }, { user: 'ai:pdpl', role: 'operator' })).status, 403);
  const f = await e.app.addons.pdpl.adapter.findings();
  assert.ok(f.some((x) => x.key === 'sens:' + id));
});

test('policy set: missing / draft / approved from the GRC register and drafts; draft started once, four-eyes approval stays in GRC', async (t) => {
  const e = await setup(t); await base(e);
  let v = await get(e, '/pdpl/policies', VW); assert.equal(v.status, 200, 'policy titles are readable by viewers');
  v = v.json; assert.equal(v.total, 16); assert.equal(v.counts.missing, 16, 'the approved register holds no PDPL policy');
  const dsr = v.policies.find((p) => p.id === 'PP-05'); assert.match(dsr.in_practice, /1 requests? recorded|0 requests recorded/); assert.ok(dsr.covers.some((c) => /30 days/.test(c)));
  assert.equal((await post(e, '/pdpl/policies/PP-05/draft', {}, VW)).status, 403);
  assert.equal((await post(e, '/pdpl/policies/XX-05/draft', {})).status, 400);
  assert.equal((await post(e, '/pdpl/policies/PP-99/draft', {})).status, 404);
  assert.equal((await post(e, '/pdpl/policies/PP-05/draft', {}, { user: 'ai:pdpl', role: 'operator' })).status, 403, 'not a service identity');
  const r = await post(e, '/pdpl/policies/PP-05/draft', {}); assert.equal(r.status, 200, r.raw); assert.equal(r.json.state, 'draft');
  assert.equal((await post(e, '/pdpl/policies/PP-05/draft', {})).status, 409, 'only one draft');
  const d = (await get(e, '/grc/drafts')).json.items.find((x) => x.id === r.json.doc);
  assert.equal(d.title, 'Data Subject Rights Procedure'); assert.match(d.requirements[0], /to be completed by the DPO/); assert.match(d.frameworks, /PDPL/);
  assert.equal((await post(e, '/grc/drafts/' + d.id + '/status', { status: 'approved' }, { user: 'nora.syn', role: 'admin' })).status, 403, 'the author cannot approve');
  assert.equal((await post(e, '/grc/drafts/' + d.id + '/status', { status: 'approved' }, ADM)).status, 200);
  v = (await get(e, '/pdpl/policies')).json; assert.equal(v.policies.find((p) => p.id === 'PP-05').state, 'approved'); assert.equal(v.counts.approved, 1);
  assert.ok(acts(e).includes('pdpl.policy.draft'));
  // PP-01 / PP-02 have full first drafts: the GRC draft opens with every section written, still unapproved, still four-eyes
  v = (await get(e, '/pdpl/policies')).json; assert.equal(v.policies.find((p) => p.id === 'PP-01').full_draft, true); assert.equal(v.policies.find((p) => p.id === 'PP-03').full_draft, false);
  const r1 = await post(e, '/pdpl/policies/PP-01/draft', {}); assert.equal(r1.status, 200, r1.raw); assert.equal(r1.json.state, 'draft', 'a full text is still only a draft');
  const d1 = (await get(e, '/grc/drafts')).json.items.find((x) => x.id === r1.json.doc);
  assert.match(d1.body, /## 7\. Data subject rights/); assert.match(d1.body, /\[name to be confirmed\]/, 'open questions stay visible');
  assert.equal(d1.requirements[0], '1. Document control'); assert.equal(d1.requirements.length, 13);
  const r2 = await post(e, '/pdpl/policies/PP-02/draft', {}); assert.equal(r2.status, 200, r2.raw);
  assert.match((await get(e, '/grc/drafts')).json.items.find((x) => x.id === r2.json.doc).body, /Saudi Data and Artificial Intelligence Authority/);
});

test('governance: DPO line, named owner per function, quarterly committee, obligations follow', async (t) => {
  const e = await setup(t); await base(e);
  let g = (await get(e, '/pdpl/governance')).json;
  assert.equal(g.dpo.ok, false); assert.equal(g.functions_gap.length, 6); assert.equal(g.committee.overdue, true); assert.equal((await get(e, '/pdpl/governance', VW)).status, 403);
  assert.equal((await post(e, '/pdpl/records', { kind: 'profile', dpo_reports_to: 'CEO', dpo_can_stop: true }, ADM)).status, 200);
  assert.equal((await post(e, '/pdpl/accountability', { function: 'requests', user: 'nora.syn' })).status, 403, 'naming owners is for administrators');
  assert.equal((await post(e, '/pdpl/accountability', { function: 'payroll', user: 'nora.syn' }, ADM)).status, 400);
  assert.equal((await post(e, '/pdpl/accountability', { function: 'requests', user: 'nora.syn' }, ADM)).json.user, 'nora.syn');
  assert.equal((await post(e, '/pdpl/accountability', { function: 'requests', user: 'omar.syn', deputy: 'nora.syn' }, ADM)).json.user, 'omar.syn', 'replaced, not duplicated');
  assert.equal((await get(e, '/pdpl/records?kind=accountability')).json.records.length, 1);
  assert.equal((await post(e, '/pdpl/committee', { date: '2026-10-01', departments: ['legal'], actions: [{ action: 'x' }] })).status, 400, 'action needs owner and due');
  assert.equal((await post(e, '/pdpl/committee', { date: '2027-10-01', departments: ['legal'] })).status, 400, 'future date');
  assert.equal((await post(e, '/pdpl/committee', { date: '2026-10-01', departments: ['legal', 'it', 'hr'], attendees: ['huda.syn'], decisions: 'synthetic', actions: [{ action: 'map HR data', owner: 'omar.syn', due: '2026-12-01' }] })).status, 200);
  g = (await get(e, '/pdpl/governance')).json;
  assert.equal(g.dpo.ok, true); assert.equal(g.functions_gap.length, 5); assert.equal(g.committee.overdue, false); assert.deepEqual(g.committee.missing_departments, ['operations']);
  assert.deepEqual(g.untrained_departments, ['claims']);
  const o = (await get(e, '/pdpl/programme')).json.obligations;
  assert.equal(o.find((x) => x.id === 'dpo_line').state, 'met'); assert.equal(o.find((x) => x.id === 'committee').state, 'met'); assert.equal(o.find((x) => x.id === 'accountability').state, 'partly');
  const a = acts(e); assert.ok(a.includes('pdpl.accountability') && a.includes('pdpl.committee.meeting'));
});

test('privacy by design: assessed in Python, decided by the DPO not the requester, DPIA required first', async (t) => {
  const e = await setup(t); const ropa = await base(e);
  const ans = { personal: 'yes', sensitive: 'yes', new_tech: 'no', sources: 'no', outside: 'no', processor: 'yes', minimised: 'partly', controls: 'yes', retention: 'yes', notice: 'yes' };
  assert.equal((await post(e, '/pdpl/pbd', { name: 'Claims app v2', type: 'new_system', answers: { personal: 'yes' } })).status, 400, 'every question');
  const r = await post(e, '/pdpl/pbd', { name: 'Claims app v2', type: 'new_system', go_live: '2026-12-01', answers: ans });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.score.dpia_required, true); assert.ok(r.json.score.required.some((x) => /processor agreement/.test(x)));
  assert.equal((await post(e, '/pdpl/pbd/' + r.json.id + '/decide', { decision: 'approve' }, OP)).status, 403, 'not the DPO');
  assert.equal((await post(e, '/pdpl/pbd/' + r.json.id + '/decide', { decision: 'approve' }, DPO)).status, 409, 'DPIA first');
  assert.equal((await post(e, '/pdpl/pbd/' + r.json.id + '/decide', { decision: 'reject' }, DPO)).status, 400, 'reject needs a note');
  const own = (await post(e, '/pdpl/pbd', { name: 'DPO tool', type: 'change', ropa_id: ropa, answers: Object.assign({}, ans, { sensitive: 'no' }) }, DPO)).json;
  assert.equal(own.score.dpia_required, false);
  assert.equal((await post(e, '/pdpl/pbd/' + own.id + '/decide', { decision: 'approve' }, DPO)).status, 403, 'four-eyes');
  assert.equal((await post(e, '/pdpl/pbd/' + own.id + '/decide', { decision: 'approve' }, ADM)).json.state, 'approved');
  assert.equal((await post(e, '/pdpl/pbd/' + own.id + '/decide', { decision: 'approve' }, ADM)).status, 409, 'decided once');
  assert.equal((await post(e, '/pdpl/pbd/' + r.json.id + '/decide', { decision: 'reject', note: 'sign the DPIA and the TPA agreement first' }, DPO)).json.state, 'rejected');
  assert.ok(acts(e).includes('pdpl.pbd.approve') && acts(e).includes('pdpl.pbd.reject'));
});

test('programme review: five checks, issues need actions, actions closed with evidence; RoPA recipients, joint controllers, training audience', async (t) => {
  const e = await setup(t); const ropa = await base(e);
  const checks = { followed: { result: 'ok' }, changes: { result: 'issues', note: 'new claims portal' }, guidance: { result: 'ok' }, processors: { result: 'ok' }, incidents: { result: 'ok' } };
  assert.equal((await post(e, '/pdpl/reviews', { date: '2026-10-15', checks: { followed: { result: 'ok' } } })).status, 400, 'all five checks');
  assert.equal((await post(e, '/pdpl/reviews', { date: '2026-10-15', checks })).status, 400, 'issues without actions');
  const r = await post(e, '/pdpl/reviews', { date: '2026-10-15', checks, summary: 'synthetic', actions: [{ action: 'add the portal to the RoPA', owner: 'omar.syn', due: '2026-10-18' }] });
  assert.equal(r.status, 200, r.raw);
  let g = (await get(e, '/pdpl/governance')).json; assert.equal(g.review_overdue, false); assert.equal(g.open_actions, 1); assert.equal(g.overdue_actions, 1);
  assert.equal((await post(e, '/pdpl/reviews/' + r.json.id + '/action/1', { status: 'done' })).status, 400, 'evidence needed');
  assert.equal((await post(e, '/pdpl/reviews/' + r.json.id + '/action/2', { status: 'done', note: 'x' })).status, 404);
  assert.equal((await post(e, '/pdpl/reviews/' + r.json.id + '/action/1', { status: 'done', note: 'PD-ROPA-002 created' })).json.status, 'done');
  g = (await get(e, '/pdpl/governance')).json; assert.equal(g.open_actions, 0);
  const p = (await post(e, '/pdpl/records', { kind: 'processor', name: 'Reinsurer (synthetic)', role: 'joint_controller' })).json;
  assert.equal((await post(e, '/pdpl/records', { kind: 'ropa', id: ropa, volume: 120000, recipients: ['CCHI'], processor_ids: ['bad'] })).status, 400);
  assert.equal((await post(e, '/pdpl/records', { kind: 'ropa', id: ropa, volume: 120000, recipients: ['CCHI'], processor_ids: [p.id] })).status, 200);
  const x = (await get(e, '/pdpl/ropa/export')).json; assert.ok(x.columns.includes('Recipients and processors')); assert.match(x.rows[0].join('|'), /CCHI, Reinsurer/);
  assert.equal((await get(e, '/pdpl/processors')).json.processors[0].role, 'joint_controller');
  assert.equal((await post(e, '/pdpl/training', { team: 'Claims', topic: 'Requests', date: '2026-10-01', attendees: 9, audience: 'customer_facing', onboarding: true })).status, 200);
  assert.equal((await post(e, '/pdpl/training', { team: 'Claims', topic: 'x', date: '2026-10-01', attendees: 1, audience: 'everyone' })).status, 400);
  assert.equal((await get(e, '/pdpl/programme')).json.training[0].audience, 'customer_facing');
  assert.ok(acts(e).includes('pdpl.review') && acts(e).includes('pdpl.review.action'));
});

test(('policy upload: the owner uploads the policy ' + ZYB_ORG.short + ' has (content-checked), submits it, another admin approves; refusals'), async (t) => {
  const e = await setup(t); await base(e);
  const pdf = Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << >>\n%%EOF\n'), b64 = pdf.toString('base64');
  const up = (id, b, who) => post(e, '/pdpl/policies/' + id + '/upload', b, who);
  assert.equal((await up('PP-02', { filename: 'privacy.pdf', content_b64: b64 }, VW)).status, 403, 'a viewer cannot upload');
  assert.equal((await up('PP-02', { filename: 'privacy.pdf', content_b64: b64 }, { user: 'ai:pdpl', role: 'operator' })).status, 403, 'not a service identity');
  let r = await up('PP-02', { filename: 'privacy.exe', content_b64: b64 }); assert.equal(r.status, 400); assert.match(r.json.error, /not accepted/);
  r = await up('PP-02', { filename: 'privacy.pdf', content_b64: Buffer.from('MZ not a pdf').toString('base64') }); assert.equal(r.status, 400); assert.match(r.json.error, /not a real \.pdf/, 'checked by content, not by name');
  r = await up('PP-02', { content_b64: b64 }); assert.equal(r.status, 400); assert.match(r.json.error, /filename/);
  // missing -> a draft with the document, sent for approval at once
  r = await up('PP-02', { filename: 'Privacy Notice v3.pdf', content_b64: b64, owner: 'DPO', submit: true, sha256: 'ignored' }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.state, 'in_review'); assert.equal(r.json.owner, 'DPO');
  const d = (await get(e, '/grc/drafts')).json.items.find((x) => x.id === r.json.doc);
  assert.equal(d.title, 'Privacy Notice'); assert.equal(d.document.filename, 'Privacy Notice v3.pdf');
  assert.equal(d.document.sha256, require('node:crypto').createHash('sha256').update(pdf).digest('hex'), 'the hash is computed on the server');
  const doc = await get(e, '/grc/drafts/' + d.id + '/document'); assert.equal(Buffer.from(doc.json.content_b64, 'base64').equals(pdf), true, 'the approver downloads exactly what was submitted');
  const a = e.audits ? e.audits() : null; void a;
  // decide: admin only, never the uploader, a reason to reject
  assert.equal((await post(e, '/pdpl/policies/PP-02/decide', { decision: 'approve' })).status, 403, 'an operator does not approve');
  assert.equal((await post(e, '/pdpl/policies/PP-02/decide', { decision: 'approve' }, { user: 'nora.syn', role: 'admin' })).status, 403, 'four-eyes: the uploader cannot approve');
  r = await post(e, '/pdpl/policies/PP-02/decide', { decision: 'maybe' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /decision/);
  r = await post(e, '/pdpl/policies/PP-02/decide', { decision: 'reject', note: 'no' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /why it is rejected/);
  r = await post(e, '/pdpl/policies/PP-02/decide', { decision: 'reject', note: 'Retention periods missing in section 4' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.state, 'missing', 'rejected: back to the owner');
  // the owner uploads a fixed version (a new draft), submits separately, another admin approves
  r = await up('PP-02', { filename: 'Privacy Notice v4.pdf', content_b64: b64 }); assert.equal(r.status, 200); assert.equal(r.json.state, 'draft');
  assert.equal((await post(e, '/pdpl/policies/PP-02/decide', { decision: 'approve' }, ADM)).status, 409, 'not in review yet');
  r = await post(e, '/pdpl/policies/PP-02/submit', {}); assert.equal(r.status, 200); assert.equal(r.json.state, 'in_review');
  assert.equal((await post(e, '/pdpl/policies/PP-02/submit', {})).status, 409, 'already in review');
  r = await post(e, '/pdpl/policies/PP-02/decide', { decision: 'approve', note: 'Reviewed with Legal' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.state, 'approved');
  // an approved policy: a new version is a revision draft; the approved one stays in force
  r = await up('PP-02', { filename: 'Privacy Notice v5.docx', content_b64: Buffer.from('PK\u0003\u0004[Content_Types].xml word/document.xml').toString('base64') }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.state, 'approved', 'the approved version stays in force'); assert.equal(r.json.revision.state, 'draft');
  const again = await up('PP-02', { filename: 'Privacy Notice v5.1.pdf', content_b64: b64, submit: true }); assert.equal(again.json.revision.doc, r.json.revision.doc, 'the same revision draft, not a new one');
  assert.equal(again.json.revision.state, 'in_review');
  assert.equal((await post(e, '/pdpl/policies/PP-02/decide', { decision: 'approve' }, ADM)).status, 200, 'the revision is approved by another admin');
  const rev = (await get(e, '/grc/drafts')).json.items.find((x) => x.id === r.json.revision.doc);
  assert.match(rev.purpose || '', /Revision of/); assert.equal(rev.document.filename, 'Privacy Notice v5.1.pdf'); assert.equal(rev.status, 'approved');
  // a draft with neither a document nor text cannot be submitted
  await post(e, '/pdpl/policies/PP-03/draft', {});
  r = await post(e, '/pdpl/policies/PP-03/submit', {}); assert.equal(r.status, 409); assert.match(r.json.error, /upload the policy document/);
  const L = acts(e); for (const x of ['pdpl.policy.upload', 'pdpl.policy.submit', 'pdpl.policy.reject', 'pdpl.policy.approve']) assert.ok(L.includes(x), 'audited: ' + x);
});
