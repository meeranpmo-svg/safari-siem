// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Risk Governance & Models (engine/erm-governance.js) through the real routes with SYNTHETIC records (people end in .syn):
// 1 models: inventory, due dates by tier, independence of the validator, findings closed with a note, a not-fit model flagged,
//   a high-tier model in use changed only through a change request a different administrator approves;
// 2 committees: charter approval four-eyes (and back to draft when it changes), quorum computed, actions tracked and overdue,
//   delegated authorities never granted by their holder, expired / expiring;
// 3 people: key functions and succession, fit-and-proper (not by the person attested, default 12 months, expired), key risk takers
//   (no amounts kept), survey change against the previous period;
// 4 the summary and the signals; roles (viewer reads, operator / admin writes, refused cases), an AI identity refused, the audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createErmGovernance, registerErmGovernance } = require('../engine/erm-governance');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' };
const AI = { user: 'ai:risk-officer', role: 'admin' };
const DAY = 86400000, T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const clock = { t: T0 }, X = createErmGovernance(e.app, { now: () => clock.t });
  registerErmGovernance(e.app.srv, e.app, X);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP, { headers: { 'X-Real-IP': '10.9.9.9' } }));
  const audits = () => e.app.store.auditTail(800).filter((a) => /^erm-governance\./.test(a.action));
  const acts = () => audits().map((a) => a.action);
  const get = async (who) => (await call('GET', '/erm-gov', undefined, who || VIEW)).json;
  return { e, X, clock, call, audits, acts, get };
}
const MODEL = { name: 'Synthetic IBNR reserving model', purpose: 'Synthetic: estimates IBNR reserves for motor and medical', kind: 'reserving', owner: 'olga.syn', department: 'Synthetic Actuarial', tier: 'high', status: 'in_use', source: 'in_house' };

test('1 models: inventory, due dates, independent validation, findings, four-eyes change of a high-tier model in use', async (t) => {
  const { call, acts, audits, get, X } = await setup(t);
  // validation at the boundary, naming the field
  let r = await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { tier: 'critical' })); assert.equal(r.status, 400); assert.match(r.json.error, /^tier must be one of: high, medium, low/);
  r = await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { owner: 'Olga <b>' })); assert.equal(r.status, 400); assert.match(r.json.error, /^owner must be a sign-in name/);
  r = await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { name: undefined })); assert.equal(r.status, 400); assert.match(r.json.error, /^name is required/);
  r = await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { last_validated: '2027-01-01' })); assert.equal(r.status, 400); assert.match(r.json.error, /^last_validated cannot be in the future/);
  r = await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { source: 'vendor' })); assert.equal(r.status, 400); assert.match(r.json.error, /vendor is required/);
  // roles: a viewer and an AI identity cannot record
  assert.equal((await call('POST', '/erm-gov/models', MODEL, VIEW)).status, 403);
  r = await call('POST', '/erm-gov/models', MODEL, AI); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI identity/);
  // a high-tier model in use, never validated: overdue at once; undeclared fields are dropped
  r = await call('POST', '/erm-gov/models', Object.assign({ approved: true, by: 'someone' }, MODEL)); assert.equal(r.status, 200);
  const M1 = r.json; assert.equal(M1.id, 'MDL-0001'); assert.equal(M1.frequency_months, 12); assert.equal(M1.frequency_default, true); assert.equal(M1.next_due, null); assert.equal(M1.overdue, true);
  assert.equal(M1.approved, undefined, 'an undeclared field never reaches the record'); assert.deepEqual(M1.flags, ['in use and never validated']);
  assert.equal((await call('POST', '/erm-gov/models', MODEL)).status, 409, 'the same name twice');
  // default frequency by tier
  const M2 = (await call('POST', '/erm-gov/models', { name: 'Synthetic motor pricing GLM', purpose: 'Synthetic pricing', kind: 'pricing', owner: 'paul.syn', department: 'Synthetic Pricing', tier: 'medium', status: 'in_use', source: 'vendor', vendor: 'Synthetic Vendor SYN', last_validated: '2025-06-30' })).json;
  assert.equal(M2.frequency_months, 24); assert.equal(M2.next_due, '2027-06-30'); assert.equal(M2.overdue, false);
  const M3 = (await call('POST', '/erm-gov/models', { name: 'Synthetic cat model', purpose: 'Synthetic flood PML', kind: 'catastrophe', owner: 'cara.syn', department: 'Synthetic Reinsurance', tier: 'low', status: 'development', source: 'in_house', last_validated: '2023-08-31' })).json;
  assert.equal(M3.next_due, '2026-08-31', '36 months for low'); assert.equal(M3.overdue, true, 'past its due date even in development');
  assert.equal(X.addMonths('2026-01-31', 1), '2026-02-28', 'end of month is kept in the shorter month');
  // validation: the owner is never the validator
  const V = { date: '2026-10-15', validator: 'olga.syn', independent: true, outcome: 'fit_with_findings', report_ref: 'SYN-VAL-2026-01', findings: [{ text: 'Synthetic: tail factor not documented', severity: 'medium', due: '2026-11-01', owner: 'olga.syn' }] };
  r = await call('POST', '/erm-gov/models/' + M1.id + '/validations', V); assert.equal(r.status, 403); assert.match(r.json.error, /independence: olga\.syn owns MDL-0001/);
  r = await call('POST', '/erm-gov/models/' + M1.id + '/validations', Object.assign({}, V, { validator: 'val.syn', findings: [] })); assert.equal(r.status, 400); assert.match(r.json.error, /^findings: fit_with_findings needs at least one finding/);
  r = await call('POST', '/erm-gov/models/' + M1.id + '/validations', Object.assign({}, V, { validator: 'val.syn', findings: [{ text: 'x', severity: 'medium', due: '1 Nov', owner: 'olga.syn' }] })); assert.equal(r.status, 400); assert.match(r.json.error, /^findings\[0\]\.due must be a date/);
  r = await call('POST', '/erm-gov/models/' + M1.id + '/validations', Object.assign({}, V, { validator: 'val.syn', independent: 'yes' })); assert.equal(r.status, 400); assert.match(r.json.error, /^independent must be true or false/);
  assert.equal((await call('POST', '/erm-gov/models/' + M1.id + '/validations', Object.assign({}, V, { validator: 'val.syn' }), VIEW)).status, 403);
  r = await call('POST', '/erm-gov/models/' + M1.id + '/validations', Object.assign({}, V, { validator: 'val.syn' })); assert.equal(r.status, 200);
  assert.equal(r.json.model.last_validated, '2026-10-15'); assert.equal(r.json.model.next_due, '2027-10-15'); assert.equal(r.json.model.overdue, false);
  assert.equal(r.json.model.open_findings, 1); assert.equal(r.json.model.overdue_findings, 1, 'the finding was due 2026-11-01'); assert.match(r.json.model.flags.join(' '), /1 validation finding\(s\) past their due date/);
  const fid = r.json.validation.findings[0];
  r = await call('POST', '/erm-gov/findings/' + fid + '/close', {}); assert.equal(r.status, 400); assert.match(r.json.error, /^note is required/);
  assert.equal((await call('POST', '/erm-gov/findings/' + fid + '/close', { note: 'synthetic: documented' }, VIEW)).status, 403);
  r = await call('POST', '/erm-gov/findings/' + fid + '/close', { note: 'synthetic: tail factor documented' }, OP2); assert.equal(r.status, 200); assert.equal(r.json.closed.by, 'omar.syn');
  assert.equal((await call('POST', '/erm-gov/findings/' + fid + '/close', { note: 'synthetic again' })).status, 409);
  // a not-fit model is flagged; a non-independent validation too
  r = await call('POST', '/erm-gov/models/' + M2.id + '/validations', { date: '2026-11-01', validator: 'val.syn', independent: false, outcome: 'not_fit', report_ref: 'SYN-VAL-2026-02' }); assert.equal(r.status, 200);
  assert.equal(r.json.model.not_fit, true); assert.ok(r.json.model.flags.includes('the last validation found it not fit for use') && r.json.model.flags.includes('the last validation was not independent'));
  // a change to a high-tier model in use: a change request, approved by a different administrator
  r = await call('POST', '/erm-gov/models/' + M1.id, { owner: 'otto.syn' }); assert.equal(r.status, 400); assert.match(r.json.error, /^change is required/);
  r = await call('POST', '/erm-gov/models/' + M1.id, { owner: 'olga.syn', change: 'synthetic no-op' }); assert.equal(r.status, 400); assert.match(r.json.error, /nothing to change/);
  r = await call('POST', '/erm-gov/models/' + M1.id, { owner: 'otto.syn', frequency_months: 6, change: 'synthetic: new owner and a semi-annual cycle' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.pending, true);
  const CH = r.json.change; assert.equal(CH.state, 'pending'); assert.deepEqual(CH.set, { owner: 'otto.syn', frequency_months: 6 }); assert.equal(r.json.model.owner, 'olga.syn', 'nothing changes before the approval');
  assert.equal((await call('POST', '/erm-gov/models/' + M1.id, { purpose: 'synthetic other', change: 'synthetic second change' })).status, 409, 'one change at a time');
  assert.equal((await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'approve' }, OP)).status, 403, 'admin only');
  r = await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes: adam\.syn asked/);
  r = await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'approve' }, AI); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI identity/, 'an AI identity never approves, whatever its role');
  r = await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'reject' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^note is required to reject/);
  r = await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'maybe' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^decision must be one of/);
  r = await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'approve', note: 'synthetic committee' }, ADM2); assert.equal(r.status, 200);
  assert.equal(r.json.change.state, 'approved'); assert.equal(r.json.model.owner, 'otto.syn'); assert.equal(r.json.model.frequency_months, 6); assert.equal(r.json.model.next_due, '2027-04-15');
  assert.equal((await call('POST', '/erm-gov/model-changes/' + CH.id + '/decision', { decision: 'approve' }, ADM2)).status, 409);
  // a medium model changes directly
  r = await call('POST', '/erm-gov/models/' + M2.id, { status: 'retired' }); assert.equal(r.status, 200); assert.equal(r.json.pending, false); assert.equal(r.json.model.status, 'retired'); assert.deepEqual(r.json.model.flags, [], 'a retired model is not flagged');
  assert.equal((await call('POST', '/erm-gov/models/' + M2.id + '/validations', { date: '2026-11-02', validator: 'val.syn', independent: true, outcome: 'fit_for_use', report_ref: 'SYN' })).status, 409);
  const D = await get(); assert.equal(D.models.length, 3); assert.equal(D.findings[0].status, 'closed'); assert.equal(D.changes.length, 1); assert.equal(D.validations.length, 2);
  for (const x of ['model.create', 'model.validation', 'model.finding.close', 'model.change.request', 'model.change.approve', 'model.update']) assert.ok(acts().includes('erm-governance.' + x), 'audited: ' + x);
  const ap = audits().find((a) => a.action === 'erm-governance.model.change.approve');
  assert.equal(ap.by, 'aisha.syn'); assert.equal(ap.role, 'admin'); assert.equal(ap.ip, '10.9.9.9'); assert.equal(ap.target, CH.id); assert.equal(ap.detail.requested_by, 'adam.syn'); assert.deepEqual(ap.detail.fields, ['owner', 'frequency_months']);
  const up = audits().find((a) => a.action === 'erm-governance.model.update'); assert.deepEqual(up.detail.from, { status: 'in_use' }); assert.deepEqual(up.detail.to, { status: 'retired' });
});

test('2 committees: charter four-eyes, quorum, actions, delegated authority', async (t) => {
  const { call, acts, audits, get, clock } = await setup(t);
  const BRC = { name: 'Synthetic Board Risk Committee', mandate: 'Synthetic: oversees the risk appetite and the ERM framework', members: ['ali.syn', 'bea.syn', 'cem.syn'], chair: 'ali.syn', quorum: 2, frequency: 'quarterly', charter_review_due: '2027-06-30' };
  let r = await call('POST', '/erm-gov/committees', Object.assign({}, BRC, { chair: 'zed.syn' })); assert.equal(r.status, 400); assert.match(r.json.error, /^chair must be one of the members/);
  r = await call('POST', '/erm-gov/committees', Object.assign({}, BRC, { quorum: 4 })); assert.equal(r.status, 400); assert.match(r.json.error, /^quorum \(4\) cannot be more than the members/);
  r = await call('POST', '/erm-gov/committees', Object.assign({}, BRC, { frequency: 'weekly' })); assert.equal(r.status, 400); assert.match(r.json.error, /^frequency must be one of/);
  r = await call('POST', '/erm-gov/committees', Object.assign({}, BRC, { members: 'ali.syn' })); assert.equal(r.status, 400); assert.match(r.json.error, /^members must be a list/);
  assert.equal((await call('POST', '/erm-gov/committees', BRC, VIEW)).status, 403);
  r = await call('POST', '/erm-gov/committees', BRC); assert.equal(r.status, 200); const C1 = r.json;
  assert.equal(C1.charter_state, 'draft'); assert.ok(C1.flags.includes('the charter is not approved') && C1.flags.includes('no meeting recorded (meets quarterly)'));
  // charter approval: asked by one, approved by a different administrator
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter', {}); assert.equal(r.status, 400); assert.match(r.json.error, /^note is required/);
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter', { note: 'synthetic: charter for approval' }); assert.equal(r.status, 200); assert.equal(r.json.charter_state, 'pending');
  r = await call('POST', '/erm-gov/committees/' + C1.id, { quorum: 3 }); assert.equal(r.status, 409, 'the charter is frozen while it waits');
  assert.equal((await call('POST', '/erm-gov/committees/' + C1.id + '/charter/decision', { decision: 'approve' }, OP2)).status, 403, 'admin only');
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter/decision', { decision: 'approve' }, { user: 'nora.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter/decision', { decision: 'approve' }, AI); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI identity/);
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter/decision', { decision: 'approve', ref: 'SYN-BOARD-2026/9' }, ADM); assert.equal(r.status, 200);
  assert.equal(r.json.charter_state, 'approved'); assert.equal(r.json.approved.version, 1); assert.equal(r.json.approved.approved_by, 'adam.syn'); assert.equal(r.json.approved.requested_by, 'nora.syn');
  // a changed charter goes back to draft; a changed name does not
  r = await call('POST', '/erm-gov/committees/' + C1.id, { name: 'Synthetic BRC' }); assert.equal(r.json.charter_state, 'approved');
  r = await call('POST', '/erm-gov/committees/' + C1.id, { members: ['ali.syn', 'bea.syn', 'cem.syn', 'dia.syn'] }); assert.equal(r.json.charter_state, 'draft'); assert.match(r.json.flags.join(' '), /changed since it was approved/);
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter', { note: 'synthetic: new member' }, OP2);
  r = await call('POST', '/erm-gov/committees/' + C1.id + '/charter/decision', { decision: 'reject', note: 'synthetic: wait for the AGM' }, ADM2); assert.equal(r.json.charter_state, 'draft');
  // meetings: quorum computed from the members
  r = await call('POST', '/erm-gov/meetings', { committee: 'CM-9999', date: '2026-10-20', attendees: ['ali.syn'] }); assert.equal(r.status, 400); assert.match(r.json.error, /^committee: no committee/);
  r = await call('POST', '/erm-gov/meetings', { committee: C1.id, date: '2026-12-20', attendees: ['ali.syn'] }); assert.equal(r.status, 400); assert.match(r.json.error, /^date cannot be in the future/);
  r = await call('POST', '/erm-gov/meetings', { committee: C1.id, date: '2026-10-20', attendees: ['ali.syn'], actions: [{ text: 'synthetic', due: '2026-11-01' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /^actions\[0\]\.owner is required/);
  r = await call('POST', '/erm-gov/meetings', { committee: C1.id, date: '2026-10-20', attendees: ['ali.syn', 'guest.syn'], decisions: [{ text: 'Synthetic: approve the RAS' }] }); assert.equal(r.status, 200);
  assert.equal(r.json.quorum_met, false); assert.equal(r.json.members_present, 1); assert.match(r.json.flags[0], /quorum not met.*ratifying/);
  r = await call('POST', '/erm-gov/meetings', { committee: C1.id, date: '2026-11-05', attendees: ['ALI.syn', 'bea.syn', 'cem.syn'], minutes_ref: 'SYN-MIN-11', decisions: [{ text: 'Synthetic: ratify' }],
    actions: [{ text: 'Synthetic: update the cat limits', owner: 'bea.syn', due: '2026-11-10' }, { text: 'Synthetic: review the ORSA', owner: 'cem.syn', due: '2026-12-31' }] });
  assert.equal(r.status, 200); assert.equal(r.json.quorum_met, true); assert.equal(r.json.members_present, 3); assert.equal(r.json.actions.length, 2);
  let D = await get(); const late = D.actions.find((a) => a.owner === 'bea.syn'); assert.equal(late.overdue, true); assert.equal(D.actions.find((a) => a.owner === 'cem.syn').overdue, false);
  assert.equal(D.committees[0].overdue_actions, 1); assert.equal(D.committees[0].last_meeting, '2026-11-05');
  r = await call('POST', '/erm-gov/actions/' + late.id + '/close', { note: 'x' }); assert.equal(r.status, 400); assert.match(r.json.error, /^note must be at least 5/);
  r = await call('POST', '/erm-gov/actions/' + late.id + '/close', { note: 'synthetic: limits updated' }, OP2); assert.equal(r.status, 200); assert.equal(r.json.status, 'closed'); assert.equal(r.json.overdue, false);
  // delegated authorities
  const DA = { holder: 'uma.syn', authority: 'underwriting', limit: 5000000, currency: 'SAR', granted_by: 'ceo.syn', granted_on: '2026-01-01', expires: '2026-12-01' };
  r = await call('POST', '/erm-gov/authorities', Object.assign({}, DA, { limit: -1 })); assert.equal(r.status, 400); assert.match(r.json.error, /^limit must be at least 0/);
  r = await call('POST', '/erm-gov/authorities', Object.assign({}, DA, { currency: 'riyal' })); assert.equal(r.status, 400); assert.match(r.json.error, /^currency must be a three-letter code/);
  r = await call('POST', '/erm-gov/authorities', Object.assign({}, DA, { expires: '2025-12-01' })); assert.equal(r.status, 400); assert.match(r.json.error, /^expires must be after granted_on/);
  r = await call('POST', '/erm-gov/authorities', Object.assign({}, DA, { granted_by: 'UMA.syn' })); assert.equal(r.status, 403); assert.match(r.json.error, /granted by someone other than its holder/);
  r = await call('POST', '/erm-gov/authorities', Object.assign({}, DA, { holder: 'nora.syn' })); assert.equal(r.status, 403); assert.match(r.json.error, /holds this authority and cannot record it/);
  assert.equal((await call('POST', '/erm-gov/authorities', DA, VIEW)).status, 403);
  r = await call('POST', '/erm-gov/authorities', DA); assert.equal(r.status, 200); const A1 = r.json; assert.equal(A1.state, 'expiring', 'expires within 30 days');
  const A2 = (await call('POST', '/erm-gov/authorities', { holder: 'cla.syn', authority: 'claims_settlement', limit: 250000, granted_by: 'ceo.syn', expires: '2027-11-30' })).json; assert.equal(A2.state, 'active'); assert.equal(A2.currency, 'SAR', 'SAR by default');
  clock.t = Date.parse('2026-12-02T08:00:00Z');
  D = await get(); assert.equal(D.authorities.find((a) => a.id === A1.id).state, 'expired'); assert.equal(D.summary.areas.committees.counts.authorities_expired, 1);
  r = await call('POST', '/erm-gov/authorities/' + A1.id + '/revoke', { note: 'synthetic: replaced by a new grant' }); assert.equal(r.json.state, 'revoked');
  assert.equal((await call('POST', '/erm-gov/authorities/' + A1.id + '/revoke', { note: 'synthetic again' })).status, 409);
  for (const x of ['committee.create', 'committee.update', 'committee.charter.request', 'committee.charter.approve', 'committee.charter.reject', 'meeting.record', 'action.close', 'authority.create', 'authority.revoke']) assert.ok(acts().includes('erm-governance.' + x), 'audited: ' + x);
  const ca = audits().find((a) => a.action === 'erm-governance.committee.charter.approve'); assert.equal(ca.by, 'adam.syn'); assert.equal(ca.role, 'admin'); assert.equal(ca.ip, '10.9.9.9'); assert.equal(ca.detail.requested_by, 'nora.syn');
});

test('3 people: succession, fit and proper, key risk takers, risk culture', async (t) => {
  const { call, acts, audits, get, clock } = await setup(t);
  let r = await call('POST', '/erm-gov/functions', { function: 'chief_risk', title: 'Synthetic CRO', holder: 'rita.syn' }); assert.equal(r.status, 400); assert.match(r.json.error, /^function must be one of/);
  r = await call('POST', '/erm-gov/functions', { function: 'cro', title: 'Synthetic CRO', holder: 'rita.syn', successors: [{ name: 'sam.syn', readiness: 'soon' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /^successors\[0\]\.readiness must be one of/);
  r = await call('POST', '/erm-gov/functions', { function: 'cro', title: 'Synthetic CRO', holder: 'rita.syn', successors: [{ name: 'rita.syn', readiness: 'ready_now' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /own successor/);
  assert.equal((await call('POST', '/erm-gov/functions', { function: 'cro', title: 'Synthetic CRO', holder: 'rita.syn' }, VIEW)).status, 403);
  r = await call('POST', '/erm-gov/functions', { function: 'cro', title: 'Synthetic CRO', holder: 'rita.syn', successors: [{ name: 'sam.syn', readiness: '1_2_years' }] }); assert.equal(r.status, 200); const CRO = r.json;
  assert.equal(CRO.ready_successor, false); assert.ok(CRO.flags.includes('no ready-now successor and no emergency cover') && CRO.flags.includes('the holder rita.syn has no fit-and-proper attestation'));
  const ACT = (await call('POST', '/erm-gov/functions', { function: 'actuarial', title: 'Synthetic Appointed Actuary', holder: 'alan.syn', emergency_cover: 'ext.actuary.syn' })).json; assert.equal(ACT.flags.includes('no successor and no emergency cover'), false, 'emergency cover is enough');
  assert.equal((await call('POST', '/erm-gov/functions', { function: 'cro', title: 'Synthetic CRO', holder: 'x.syn' })).status, 409, 'one function per title');
  // fit and proper: an administrator who is not the person; 12 months by default
  r = await call('POST', '/erm-gov/attestations', { function: CRO.id, person: 'rita.syn', attested_on: '2025-11-01' }, OP); assert.equal(r.status, 403, 'admin only');
  r = await call('POST', '/erm-gov/attestations', { function: CRO.id, person: 'adam.syn', attested_on: '2025-11-01' }, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /own fitness/);
  r = await call('POST', '/erm-gov/attestations', { function: CRO.id, person: 'rita.syn', attested_on: '2025-11-01' }, AI); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI identity/);
  r = await call('POST', '/erm-gov/attestations', { function: 'KF-9999', person: 'rita.syn', attested_on: '2025-11-01' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^function: no key function/);
  r = await call('POST', '/erm-gov/attestations', { function: CRO.id, person: 'rita.syn', attested_on: '2025-11-01', valid_until: '2025-10-01' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^valid_until must be after attested_on/);
  r = await call('POST', '/erm-gov/attestations', { function: CRO.id, person: 'rita.syn', attested_on: '2025-11-01' }, ADM); assert.equal(r.status, 200);
  assert.equal(r.json.valid_until, '2026-11-01'); assert.equal(r.json.valid_default, true); assert.equal(r.json.expired, true, 'expired on 2026-11-01, today is 2026-11-11');
  let D = await get(); assert.match(D.functions.find((f) => f.id === CRO.id).flags.join(' '), /attestation of rita\.syn expired on 2026-11-01/);
  r = await call('POST', '/erm-gov/attestations', { function: ACT.id, person: 'alan.syn', attested_on: '2026-11-01' }, ADM2); assert.equal(r.json.state, 'valid');
  // succession improves: a ready-now successor
  r = await call('POST', '/erm-gov/functions/' + CRO.id, { successors: [{ name: 'sam.syn', readiness: 'ready_now' }], note: 'synthetic: sam ready' }); assert.equal(r.status, 200); assert.equal(r.json.ready_successor, true);
  assert.ok(!r.json.flags.some((f) => /successor/.test(f)));
  assert.equal((await call('POST', '/erm-gov/functions/' + CRO.id, { successors: [{ name: 'sam.syn', readiness: 'ready_now' }] })).status, 400, 'nothing to change');
  // key risk takers: a yes / no and a date, never an amount
  r = await call('POST', '/erm-gov/krt', { name: 'kim.syn', role_title: 'Synthetic Head of Investments', department: 'Synthetic Investments', remuneration_reviewed: true }); assert.equal(r.status, 400); assert.match(r.json.error, /^review_date is required/);
  r = await call('POST', '/erm-gov/krt', { name: 'kim.syn', role_title: 'Synthetic Head of Investments', department: 'Synthetic Investments', remuneration_reviewed: true, review_date: '2025-06-01', bonus: 900000, salary: 1 }); assert.equal(r.status, 200);
  assert.equal(r.json.bonus, undefined); assert.equal(r.json.salary, undefined, 'no amounts are kept'); assert.match(r.json.flags[0], /over 12 months ago/);
  const K2 = (await call('POST', '/erm-gov/krt', { name: 'ken.syn', role_title: 'Synthetic Chief Underwriter', department: 'Synthetic UW', remuneration_reviewed: false })).json; assert.deepEqual(K2.flags, ['remuneration review not recorded']);
  r = await call('POST', '/erm-gov/krt/' + K2.id, { remuneration_reviewed: true, review_date: '2026-10-01' }); assert.deepEqual(r.json.flags, []);
  // risk culture: change against the previous period
  r = await call('POST', '/erm-gov/surveys', { period: '2025', response_rate: 60, tone_at_the_top: 70, speak_up: 55, accountability: 65, risk_awareness: 120 }); assert.equal(r.status, 400); assert.match(r.json.error, /^risk_awareness must be at most 100/);
  r = await call('POST', '/erm-gov/surveys', { period: '25-H1', response_rate: 60, tone_at_the_top: 70, speak_up: 55, accountability: 65, risk_awareness: 60 }); assert.equal(r.status, 400); assert.match(r.json.error, /^period must be/);
  r = await call('POST', '/erm-gov/surveys', { period: '2025', response_rate: 60, tone_at_the_top: 70, speak_up: 55, accountability: 65 }); assert.equal(r.status, 400); assert.match(r.json.error, /^risk_awareness is required/);
  r = await call('POST', '/erm-gov/surveys', { period: '2025', response_rate: 60, tone_at_the_top: 70, speak_up: 55, accountability: 65, risk_awareness: 60 }); assert.equal(r.status, 200); assert.equal(r.json.change, null, 'the first period has nothing to compare');
  r = await call('POST', '/erm-gov/surveys', { period: '2026', response_rate: 72.5, tone_at_the_top: 74, speak_up: 51, accountability: 65, risk_awareness: 66.4 }); assert.equal(r.status, 200);
  assert.equal(r.json.previous, '2025'); assert.deepEqual(r.json.change, { tone_at_the_top: 4, speak_up: -4, accountability: 0, risk_awareness: 6.4, response_rate: 12.5 });
  assert.equal((await call('POST', '/erm-gov/surveys', { period: '2026', response_rate: 1, tone_at_the_top: 1, speak_up: 1, accountability: 1, risk_awareness: 1 })).status, 409);
  assert.equal((await call('POST', '/erm-gov/surveys', { period: '2027', response_rate: 1, tone_at_the_top: 1, speak_up: 1, accountability: 1, risk_awareness: 1 }, VIEW)).status, 403);
  D = await get(); assert.equal(D.surveys[0].period, '2026', 'newest first');
  // a valid attestation expires as time passes
  clock.t = Date.parse('2027-11-02T08:00:00Z'); D = await get(); assert.equal(D.attestations.find((a) => a.person === 'alan.syn').expired, true);
  for (const x of ['function.create', 'function.update', 'attestation.record', 'krt.create', 'krt.update', 'survey.record']) assert.ok(acts().includes('erm-governance.' + x), 'audited: ' + x);
  const at = audits().find((a) => a.action === 'erm-governance.attestation.record'); assert.equal(at.role, 'admin'); assert.equal(at.ip, '10.9.9.9'); assert.ok(['adam.syn', 'aisha.syn'].includes(at.by));
});

test('4 summary and signals: counts and flags per area, each saying why; empty without records', async (t) => {
  const { call } = await setup(t);
  let S = (await call('GET', '/erm-gov/summary', undefined, VIEW)).json;
  assert.equal(S.flags_total, 0); assert.equal(S.areas.models.counts.models, 0); assert.deepEqual((await call('GET', '/erm-gov/signals', undefined, VIEW)).json.signals, [], 'nothing invented on an empty platform');
  await call('POST', '/erm-gov/models', MODEL);
  await call('POST', '/erm-gov/models', Object.assign({}, MODEL, { name: 'Synthetic fraud score', kind: 'fraud_claims', tier: 'medium', last_validated: '2024-01-01' }));
  const C1 = (await call('POST', '/erm-gov/committees', { name: 'Synthetic ERM Committee', mandate: 'Synthetic', members: ['ali.syn', 'bea.syn'], chair: 'ali.syn', quorum: 2, frequency: 'monthly', charter_review_due: '2026-01-01' })).json;
  await call('POST', '/erm-gov/meetings', { committee: C1.id, date: '2026-11-01', attendees: ['ali.syn', 'bea.syn'], actions: [{ text: 'Synthetic overdue action', owner: 'bea.syn', due: '2026-11-05' }] });
  const CEO = (await call('POST', '/erm-gov/functions', { function: 'ceo', title: 'Synthetic CEO', holder: 'cy.syn' })).json;
  await call('POST', '/erm-gov/attestations', { function: CEO.id, person: 'cy.syn', attested_on: '2025-01-15' }, ADM);
  S = (await call('GET', '/erm-gov/summary', undefined, VIEW)).json;
  assert.equal(S.areas.models.counts.overdue, 2); assert.equal(S.areas.models.counts.never_validated, 1);
  assert.ok(S.areas.models.flags.some((f) => f.ref === 'MDL-0002' && /validation overdue: due 2026-01-01/.test(f.why)));
  assert.ok(S.areas.committees.flags.some((f) => /charter review was due on 2026-01-01/.test(f.why)) && S.areas.committees.flags.some((f) => /overdue since 2026-11-05/.test(f.why)));
  assert.equal(S.areas.people.counts.without_ready_successor, 1); assert.equal(S.areas.people.counts.attestations_expired, 1);
  assert.ok(S.flags_total >= 6 && [S.areas.models, S.areas.committees, S.areas.people].every((a) => a.flags.every((f) => f.ref && f.why)), 'every flag names its record and why');
  const G = (await call('GET', '/erm-gov/signals', undefined, VIEW)).json.signals;
  assert.ok(G.every((g) => g.source === 'platform' && g.condition === true && [2, 3].includes(g.severity) && /^erm-governance:/.test(g.fp) && g.ref && g.title && g.text));
  const kinds = G.map((g) => g.fp.split(':')[1]).sort();
  assert.deepEqual([...new Set(kinds)], ['committee-action', 'fit-proper', 'model-validation', 'succession']);
  assert.equal(G.find((g) => g.ref === 'MDL-0001').severity, 3, 'a high-tier model'); assert.equal(G.find((g) => g.ref === 'MDL-0002').severity, 2);
  assert.equal(G.find((g) => g.fp.includes('succession')).severity, 3, 'the CEO');
  // reads: viewer; no identity, no read
  assert.equal((await call('GET', '/erm-gov', undefined, VIEW)).status, 200);
  assert.equal((await call('GET', '/erm-gov', undefined, { user: 'x.syn', role: 'guest' })).status, 401);
  assert.equal((await call('POST', '/erm-gov/models/bad$id', { name: 'x' })).status, 400, 'the id in the path is checked');
  assert.equal((await call('POST', '/erm-gov/models/MDL-0404', { name: 'Synthetic x' })).status, 404);
});
