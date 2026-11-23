// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Legal holds (engine/pdpl.js, pyengine/pdpl_rules.py) and the breach regulator track (engine/pdpl-workflows.js,
// pyengine/pdpl_workflows.py):
//  - a hold covering a system stops a destruction at plan, approval and recording (a hold placed later still stops it),
//    unless the run names the hold and says how its records are excluded; categories narrow a hold; release is four-eyes
//    by the DPO / an administrator; review overdue is a P-12 finding; a hold cannot be archived through the registers
//  - every breach carries a decision per regulator (IA, SAMA, NCA, CHI, other); deadlines only from the profile; a
//    notification is fixed once recorded; overdue and undecided are findings
// Roles, validation and audit records throughout. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'fahad.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  const ropa = (await post('/pdpl/records', { kind: 'ropa', name: 'Motor claims (synthetic)', purpose: 'settle claims', legal_basis: 'contract', data_categories: ['identity', 'financial'], owner: 'Claims', retention_months: 60, systems: ['CLAIMS-SYN', 'DMS-SYN'] })).json;
  const rule = (await post('/pdpl/records', { kind: 'retention', name: 'Closed motor claims', ropa_id: ropa.id, systems: ['CLAIMS-SYN', 'DMS-SYN'], data_categories: ['identity', 'financial'], period_months: 60, trigger: 'claim_closed', action: 'destroy', legal_ref: 'synthetic', review_months: 12 })).json;
  return { e, post, get, rule };
}
const acts = (e, n = 80) => e.app.store.auditTail(n).map((x) => x.action);

test('legal hold: place (validated, roles), blocks plan / approval / recording, exclusion, release four-eyes, audit', async (t) => {
  const { e, post, get, rule } = await setup(t);
  // validation and roles
  let r = await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'claim', systems: ['CLAIMS-SYN'], scope: 'all records of claim CL-SYN-0042' }, VW); assert.equal(r.status, 403);
  r = await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'gossip', systems: ['CLAIMS-SYN'], scope: 'all records of claim CL-SYN-0042' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'claim', scope: 'all records of claim CL-SYN-0042' }); assert.equal(r.status, 400); assert.match(r.json.error, /systems/);
  r = await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'claim', systems: ['CLAIMS-SYN'], scope: 'short' }); assert.equal(r.status, 400); assert.match(r.json.error, /scope/);
  r = await post('/pdpl/holds', { ref: '<script>', reason: 'claim', systems: ['CLAIMS-SYN'], scope: 'all records of claim CL-SYN-0042' }); assert.equal(r.status, 400); assert.match(r.json.error, /ref/);
  r = await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'claim', systems: ['CLAIMS-SYN'], scope: 'all records of claim CL-SYN-0042' }, { user: 'system:bot', role: 'admin' }); assert.equal(r.status, 403);
  r = await post('/pdpl/records', { kind: 'legal_hold', ref: 'X' }); assert.equal(r.status, 400); assert.match(r.json.error, /legal-hold workflow/);
  const hold = (await post('/pdpl/holds', { ref: 'CL-SYN-0042', reason: 'litigation', systems: ['claims-syn'], scope: 'all records of claim CL-SYN-0042 (court case synthetic)', review_months: 3, unknown: 'dropped' })).json;
  assert.match(hold.id, /^PD-LEGAL_HOLD-\d{3}$/); assert.equal(hold.status, 'active'); assert.equal(hold.placed_by, 'nora.syn'); assert.equal(hold.unknown, undefined);
  // archiving a hold through the registers would end it without four-eyes: refused
  r = await post('/pdpl/records', { kind: 'legal_hold', id: hold.id, status: 'archived' }); assert.equal(r.status, 400);

  // the hold covers CLAIMS-SYN (case-insensitive): planning refused, naming the hold
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CLAIMS-SYN', cutoff: '2020-12-31' }); assert.equal(r.status, 409); assert.match(r.json.error, new RegExp(hold.id + '.*CL-SYN-0042.*planning refused'));
  // a different system is not covered
  const dms = (await post('/pdpl/destruction', { retention_id: rule.id, system: 'DMS-SYN', cutoff: '2020-12-31' })).json; assert.equal(dms.status, 'planned');
  // exclusion: must name an active hold that covers the system and say how
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CLAIMS-SYN', cutoff: '2020-12-31', exclude_holds: [hold.id] }); assert.equal(r.status, 400); assert.match(r.json.error, /exclusion/);
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CLAIMS-SYN', cutoff: '2020-12-31', exclude_holds: ['PD-LEGAL_HOLD-999'], exclusion: 'claim number filter in the purge script' }); assert.equal(r.status, 400);
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'DMS-SYN', cutoff: '2020-12-31', exclude_holds: [hold.id], exclusion: 'claim number filter in the purge script' }); assert.equal(r.status, 400); assert.match(r.json.error, /does not cover/);
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CLAIMS-SYN', cutoff: '2020-12-31', exclude_holds: ['bad'], exclusion: 'claim number filter in the purge script' }); assert.equal(r.status, 400); assert.match(r.json.error, /legal hold ids/);
  const ex = (await post('/pdpl/destruction', { retention_id: rule.id, system: 'CLAIMS-SYN', cutoff: '2020-12-31', exclude_holds: [hold.id], exclusion: 'purge script filters out claim CL-SYN-0042 by claim number' })).json;
  assert.equal(ex.status, 'planned'); assert.deepEqual(ex.holds_excluded.map((h) => h.id), [hold.id]);
  assert.equal((await post('/pdpl/destruction/' + ex.id + '/approve', {}, DPO)).status, 200, 'an excluded hold does not stop the approval');

  // a hold placed AFTER planning stops the approval, and after approval stops the recording
  const h2 = (await post('/pdpl/holds', { ref: 'CMP-SYN-7', reason: 'complaint', systems: ['DMS-SYN'], scope: 'documents of complaint CMP-SYN-7 (Insurance Authority)' }, OP2)).json;
  r = await post('/pdpl/destruction/' + dms.id + '/approve', {}, DPO); assert.equal(r.status, 409); assert.match(r.json.error, /approval refused/);
  const h3 = (await post('/pdpl/holds', { ref: 'AUD-SYN-1', reason: 'audit', all_systems: true, data_categories: ['financial'], scope: 'financial records under the external audit (synthetic)' }, OP2)).json;
  assert.deepEqual(h3.systems, []);
  r = await post('/pdpl/destruction/' + ex.id + '/done', { count: 10, method: 'deleted', evidence: 'CHG-SYN-1', executed_at: new Date(clock).toISOString().slice(0, 16) }); assert.equal(r.status, 409); assert.match(r.json.error, new RegExp(h3.id + '.*recording refused'));

  // holds view: what each covers, the blocked runs
  assert.equal((await get('/pdpl/holds', VW)).status, 403);
  let hv = (await get('/pdpl/holds')).json;
  assert.equal(hv.active, 3); assert.match(hv.note, /released by the DPO or an administrator who did not place it/);
  const v2 = hv.holds.find((x) => x.id === h2.id); assert.deepEqual(v2.rules, [rule.id]); assert.equal(v2.runs[0].id, dms.id); assert.equal(v2.runs[0].excluded, false);
  assert.equal(hv.holds.find((x) => x.id === hold.id).runs.find((x) => x.id === ex.id).excluded, true);
  const rv = (await get('/pdpl/retention')).json; assert.equal(rv.active_holds, 3); assert.ok(rv.rules[0].holds.length >= 2);

  // release: the DPO or an administrator, not the placer, a person, with a note
  r = await post('/pdpl/holds/' + h3.id + '/release', { note: 'external audit closed (synthetic)' }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /DPO/);
  r = await post('/pdpl/holds/' + h3.id + '/release', { note: 'external audit closed (synthetic)' }, { user: 'fahad.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  r = await post('/pdpl/holds/' + h3.id + '/release', { note: 'short' }, DPO); assert.equal(r.status, 400);
  r = await post('/pdpl/holds/bad/release', { note: 'external audit closed (synthetic)' }, DPO); assert.equal(r.status, 400);
  r = await post('/pdpl/holds/' + h3.id + '/release', { note: 'external audit closed (synthetic)' }, DPO); assert.equal(r.status, 200); assert.equal(r.json.status, 'released'); assert.equal(r.json.released_by, 'huda.syn');
  assert.equal((await post('/pdpl/holds/' + h3.id + '/release', { note: 'external audit closed (synthetic)' }, DPO)).status, 409);
  assert.equal((await post('/pdpl/holds/' + h3.id + '/review', { note: 'still needed' })).status, 409);
  r = await post('/pdpl/destruction/' + ex.id + '/done', { count: 10, method: 'deleted', evidence: 'CHG-SYN-1', executed_at: new Date(clock).toISOString().slice(0, 16) }); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'executed');

  // review overdue becomes a P-12 finding; recording a review clears it
  clock += 100 * 86400000;
  let pd = (await get('/pdpl')).json; const key = 'P-12:retention:hold:' + hold.id + ':review';
  assert.ok(pd.findings.some((f) => f.key === key), 'a hold past its review is a gap');
  r = await post('/pdpl/holds/' + hold.id + '/review', { note: 'court case still open (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.history.length, 2);
  pd = (await get('/pdpl')).json; assert.ok(!pd.findings.some((f) => f.key === key));
  clock -= 100 * 86400000;

  const a = acts(e); for (const x of ['pdpl.hold.place', 'pdpl.hold.review', 'pdpl.hold.release', 'pdpl.destruction.plan']) assert.ok(a.includes(x), x);
  const rec = e.app.store.auditTail(80).find((x) => x.action === 'pdpl.hold.release');
  assert.equal(rec.by, 'huda.syn'); assert.equal(rec.role, 'operator'); assert.equal(rec.target, h3.id);
});

test('legal hold: data categories narrow what a hold covers', async (t) => {
  const { post } = await setup(t);
  const rule2 = (await post('/pdpl/records', { kind: 'retention', name: 'Marketing contacts', systems: ['CLAIMS-SYN'], data_categories: ['contact'], period_months: 24, trigger: 'last_contact', action: 'anonymise' })).json;
  await post('/pdpl/holds', { ref: 'FR-SYN-3', reason: 'fraud_investigation', systems: ['CLAIMS-SYN'], data_categories: ['financial'], scope: 'payment records in fraud case FR-SYN-3' });
  assert.equal((await post('/pdpl/destruction', { retention_id: rule2.id, system: 'CLAIMS-SYN', cutoff: '2023-01-01' })).status, 200, 'contact data is not under a financial-records hold');
});

test('breach regulators: decision per regulator, deadlines only from the profile, notification fixed, findings, audit', async (t) => {
  const { e, post, get } = await setup(t);
  const b = (await post('/pdpl/records', { kind: 'breach', ref: 'BR-SYN-9', aware_at: '2026-10-19T08:00Z' })).json.id;
  let v = (await get('/pdpl/breaches')).json;
  let x = v.breaches[0];
  assert.deepEqual(x.regulators.map((r) => r.key), ['ia', 'sama', 'nca', 'chi']); assert.ok(x.regulators.every((r) => r.status === 'to decide' && r.hours == null));
  assert.equal(x.closed, false); assert.match(v.regulator_note, /assumes none/);
  // profile hours are admin only
  assert.equal((await post('/pdpl/records', { kind: 'profile', notify_hours_ia: 24 })).status, 403);
  assert.equal((await post('/pdpl/records', { kind: 'profile', notify_hours_ia: 0 }, ADM)).status, 400);
  assert.equal((await post('/pdpl/records', { kind: 'profile', notify_hours_ia: 24, notify_hours_sama: 4 }, ADM)).status, 200);
  // validation and roles
  const reg = (body, who) => post('/pdpl/breach/' + b + '/regulator', body, who);
  assert.equal((await reg({ regulator: 'ia', required: true }, VW)).status, 403);
  assert.equal((await reg({ regulator: 'cia', required: true })).status, 400);
  assert.equal((await reg({ regulator: 'ia' })).status, 400, 'required must be decided');
  assert.equal((await reg({ regulator: 'nca', required: false })).status, 400, 'not required needs a reason');
  assert.equal((await reg({ regulator: 'nca', required: false, reason: 'n/a', notified_at: '2026-10-19T10:00Z' })).status, 400);
  assert.equal((await reg({ regulator: 'other', required: true })).status, 400, 'another authority needs a name');
  assert.equal((await reg({ regulator: 'ia', required: true }, { user: 'ai:pdpl', role: 'operator' })).status, 403);
  // decisions
  assert.equal((await reg({ regulator: 'ia', required: true })).status, 200);
  assert.equal((await reg({ regulator: 'nca', required: false, reason: 'no critical national infrastructure system involved (synthetic)' })).status, 200);
  assert.equal((await reg({ regulator: 'sama', required: true })).status, 200);
  x = (await get('/pdpl/breaches')).json.breaches[0];
  const ia = x.regulators.find((r) => r.key === 'ia'), sama = x.regulators.find((r) => r.key === 'sama');
  assert.equal(ia.hours, 24); assert.equal(ia.deadline, '2026-10-20T08:00:00Z'); assert.equal(ia.status, 'due'); assert.equal(ia.hours_left, 0);
  assert.equal(sama.status, 'overdue'); assert.equal(sama.late, true);
  assert.equal(x.regulators.find((r) => r.key === 'nca').status, 'not required');
  // notification: assessment first, a reference, not before awareness, not in the future
  assert.equal((await reg({ regulator: 'sama', required: true, notified_at: '2026-10-19T20:00Z', ref: 'SAMA-SYN-1' })).status, 409, 'assess first');
  assert.equal((await post('/pdpl/breach/' + b + '/step', { step: 'assess', note: 'synthetic' })).status, 200);
  assert.equal((await reg({ regulator: 'sama', required: true, notified_at: '2026-10-19T20:00Z' })).status, 400, 'needs a reference');
  assert.equal((await reg({ regulator: 'sama', required: true, notified_at: '2026-10-18T20:00Z', ref: 'SAMA-SYN-1' })).status, 400, 'before awareness');
  assert.equal((await reg({ regulator: 'sama', required: true, notified_at: '2026-10-21T20:00Z', ref: 'SAMA-SYN-1' })).status, 400, 'future');
  // findings before: SAMA overdue (high); undecided after 72 h (chi)
  clock = Date.parse('2026-10-23T09:00:00Z');
  let pd = { findings: await e.app.addons.pdpl.adapter.findings() };   // the duty engineer's patrol
  assert.ok(pd.findings.some((f) => f.key === 'breach:' + b + ':reg:sama' && f.severity === 'high'));
  assert.ok(pd.findings.some((f) => f.key === 'breach:' + b + ':reg:undecided' && /Council of Health Insurance/.test(f.title)));
  clock = Date.parse('2026-10-20T08:00:00Z');
  assert.equal((await reg({ regulator: 'sama', required: true, notified_at: '2026-10-19T20:00Z', ref: 'SAMA-SYN-1' })).status, 200);
  x = (await get('/pdpl/breaches')).json.breaches[0];
  assert.equal(x.regulators.find((r) => r.key === 'sama').status, 'notified late');
  let r = await reg({ regulator: 'sama', required: false, reason: 'changed my mind about this one' }); assert.equal(r.status, 409); assert.match(r.json.error, /evidence/);
  assert.equal((await reg({ regulator: 'chi', required: false, reason: 'no health data involved (synthetic)' })).status, 200);
  assert.equal((await reg({ regulator: 'ia', required: true, notified_at: '2026-10-20T07:00Z', ref: 'IA-SYN-5' })).status, 200);
  assert.equal((await reg({ regulator: 'other', required: true, name: 'Capital Market Authority (synthetic)', hours: 48 })).status, 200);
  x = (await get('/pdpl/breaches')).json.breaches[0];
  assert.equal(x.regulators.find((r) => r.key === 'other').label, 'Capital Market Authority (synthetic)');
  assert.equal(x.regulators.find((r) => r.key === 'ia').status, 'notified');
  assert.equal(x.regulators_open, 1);
  clock = Date.parse('2026-10-23T09:00:00Z');
  pd = { findings: await e.app.addons.pdpl.adapter.findings() };
  assert.ok(!pd.findings.some((f) => f.key === 'breach:' + b + ':reg:sama'));
  assert.ok(!pd.findings.some((f) => f.key === 'breach:' + b + ':reg:undecided'));
  clock = Date.parse('2026-10-20T08:00:00Z');
  const rec = e.app.store.auditTail(80).filter((a) => a.action === 'pdpl.breach.regulator');
  assert.ok(rec.length >= 6); assert.equal(rec[rec.length - 1].by, 'nora.syn'); assert.equal(rec[rec.length - 1].target, b);
});
