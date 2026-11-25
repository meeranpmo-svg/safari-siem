// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Saudi Aramco CCC lifecycle (engine/aramco-ccc.js) with SYNTHETIC contracts and a SYNTHETIC control list (no SACS-002 text):
// the eight stages from scope to renewal, each saying what is missing; applicability from the contracts' service types; the
// control import (header, ids, applies_to checked, errors name the row); "not applicable" is a proposal a DIFFERENT person
// accepts; actions, evidence references, audit findings (a major blocks closing the audit), the certificate (coverage, expiry,
// renewal 90 days before); the readiness trend projected against the planned audit; roles, the refused case, audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parseCsv } = require('../engine/aramco-ccc');

const DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, OWNER = { user: 'omar.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const CSV = 'id,domain,title,requirement,applies_to\n'
  + 'SYN-1,Governance,"Policy, approved",A synthetic requirement,all\n'
  + 'SYN-2,Access,MFA for remote access,"Synthetic ""quoted"" text",network-connectivity\n'
  + 'SYN-3,Data,Encrypt data at rest,Synthetic,critical-data|cloud\n'
  + 'SYN-4,Software,Secure SDLC,Synthetic,custom-software\n';
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, tick: (ms) => { clock += ms; }, post: (p, b, who = OWNER) => call('POST', p, b, who), put: (p, b, who = ADM) => call('PUT', p, b, who), get: (p, who = VIEW) => call('GET', p, undefined, who),
    audit: (a) => e.app.store.auditTail(1000).filter((x) => x.action === a), X: e.app.addons.aramcoCcc };
}
const stage = (v, id) => v.stages.find((x) => x.id === id);

test('CSV parsing: quotes, commas and doubled quotes inside a field', () => {
  const r = parseCsv(CSV);
  assert.equal(r.length, 5); assert.deepEqual(r[1].slice(0, 3), ['SYN-1', 'Governance', 'Policy, approved']); assert.equal(r[2][3], 'Synthetic "quoted" text');
});

test('start to end: scope, controls, assessment with four-eyes N/A, remediation, evidence, audit, certificate, renewal', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/aramco-ccc')).json;
  assert.equal(v.current, 'scope'); assert.match(stage(v, 'scope').next, /Name the CCC owner/); assert.equal(v.score, null);
  // profile: admin only, a person as owner
  assert.equal((await s.put('/aramco-ccc/profile', { ccc_owner: 'omar.syn' }, OP)).status, 403);
  assert.equal((await s.put('/aramco-ccc/profile', { ccc_owner: 'ai:grc' })).status, 400);
  assert.equal((await s.put('/aramco-ccc/profile', { ccc_owner: 'omar.syn', vendor_no: 'V-SYN-1', planned_audit: '2027-02-01' })).status, 200);
  // contracts: only the CCC owner / admin; validation names the field
  let r = await s.post('/aramco-ccc/contracts', { contract_no: 'C-SYN-1', title: 'Synthetic O&M', services: ['network-connectivity'] }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /CCC owner/);
  r = await s.post('/aramco-ccc/contracts', { contract_no: 'C-SYN-1', title: 'Synthetic O&M', services: ['hacking'] }); assert.equal(r.status, 400); assert.match(r.json.error, /services/);
  r = await s.post('/aramco-ccc/contracts', { contract_no: 'C-SYN-1', title: 'Synthetic O&M', services: ['network-connectivity', 'critical-data'], ccc_needed_by: '2027-03-01', end: '2028-12-31' }); assert.equal(r.status, 200, r.text);
  const conId = r.json.id;
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'scope').done, true); assert.equal(v.current, 'controls');
  // import: errors name the row; applicability follows the service types (SYN-4 custom-software does not apply)
  r = await s.post('/aramco-ccc/controls/import', { csv: 'id,title\nX,Y' }); assert.equal(r.status, 400); assert.match(r.json.error, /applies_to/);
  r = await s.post('/aramco-ccc/controls/import', { csv: 'id,title,applies_to\nSYN-1,T,everything' }); assert.equal(r.status, 400); assert.match(r.json.error, /row 2/);
  assert.equal((await s.post('/aramco-ccc/controls/import', { csv: CSV }, OP)).status, 403);
  r = await s.post('/aramco-ccc/controls/import', { csv: CSV }); assert.equal(r.status, 200, r.text); assert.equal(r.json.added, 4);
  v = (await s.get('/aramco-ccc')).json; assert.equal(v.applicable, 3); assert.equal(v.controls_total, 4); assert.ok(!v.controls.some((c) => c.id === 'SYN-4'));
  assert.equal(v.current, 'assessment');
  // assessment: viewer refused; AI identity refused; N/A needs a justification and a second person
  assert.equal((await s.post('/aramco-ccc/controls/SYN-1/assess', { status: 'implemented' }, VIEW)).status, 403);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-1/assess', { status: 'implemented' }, BOT)).status, 403);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-1/assess', { status: 'done' }, OP)).status, 400);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-3/assess', { status: 'not-applicable', justification: 'short' }, OP)).status, 400);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-1/assess', { status: 'implemented' }, OP)).status, 200);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-2/assess', { status: 'not-implemented', owner: 'it.syn' }, OP)).status, 200);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-3/assess', { status: 'not-applicable', justification: 'no Aramco data is stored at rest by us (synthetic)' }, OWNER)).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.deepEqual(v.na_pending, ['SYN-3']); assert.equal(stage(v, 'assessment').done, false);
  r = await s.post('/aramco-ccc/controls/SYN-3/na', { decision: 'accepted' }, OWNER); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-3/na', { decision: 'accepted' }, OP)).status, 403, 'an operator who is not the CCC owner');
  assert.equal((await s.post('/aramco-ccc/controls/SYN-3/na', { decision: 'accepted' }, ADM)).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'assessment').done, true); assert.equal(v.score, 50, 'SYN-1 implemented, SYN-2 not; SYN-3 accepted N/A is not counted');
  assert.equal(v.current, 'remediation'); assert.match(stage(v, 'remediation').why, /1 gap\(s\) without an action/);
  // remediation
  r = await s.post('/aramco-ccc/actions', { control: 'SYN-2', title: 'Enforce MFA on the VPN', owner: 'it.syn', due: '2026-11-20' }, OP); assert.equal(r.status, 200); const act = r.json.id;
  assert.equal((await s.post('/aramco-ccc/actions', { control: 'NOPE', title: 'x', owner: 'y', due: '2026-12-01' }, OP)).status, 404);
  s.tick(20 * DAY); v = (await s.get('/aramco-ccc')).json; assert.equal(v.overdue, 1);
  assert.equal((await s.post('/aramco-ccc/actions/' + act, { status: 'done' }, OP)).status, 400, 'done needs a note');
  assert.equal((await s.post('/aramco-ccc/actions/' + act, { status: 'done', note: 'MFA enforced on the VPN portal' }, OP)).status, 200);
  assert.equal((await s.post('/aramco-ccc/controls/SYN-2/assess', { status: 'implemented' }, OP)).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'remediation').done, true); assert.equal(v.score, 100); assert.equal(v.current, 'evidence'); assert.deepEqual(v.evidence_missing, ['SYN-1', 'SYN-2']);
  // evidence references
  assert.equal((await s.post('/aramco-ccc/controls/SYN-1/evidence', { title: 'Policy', location: 'DMS/ISMS/policy.pdf', collected: '2099-01-01' }, OP)).status, 400);
  for (const c of ['SYN-1', 'SYN-2']) assert.equal((await s.post('/aramco-ccc/controls/' + c + '/evidence', { title: 'Evidence ' + c, location: 'DMS/CCC/' + c, collected: '2026-11-21' }, OP)).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'evidence').done, true); assert.equal(v.current, 'audit');
  // audit: a major finding blocks closing
  assert.equal((await s.post('/aramco-ccc/audit', { firm: 'Synthetic Audit Co', planned: '2027-01-15', status: 'fieldwork' })).status, 200);
  r = await s.post('/aramco-ccc/findings', { control: 'SYN-2', severity: 'major', title: 'MFA not on the admin portal' }); assert.equal(r.status, 200); const fnd = r.json.id;
  r = await s.post('/aramco-ccc/audit', { firm: 'Synthetic Audit Co', planned: '2027-01-15', status: 'closed' }); assert.equal(r.status, 409); assert.match(r.json.error, /major finding/);
  assert.equal((await s.post('/aramco-ccc/findings', { id: fnd, severity: 'major', title: 'MFA not on the admin portal', status: 'closed' })).status, 200);
  assert.equal((await s.post('/aramco-ccc/audit', { firm: 'Synthetic Audit Co', planned: '2027-01-15', status: 'closed' })).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'audit').done, true); assert.equal(v.current, 'certificate');
  // certificate: coverage of the contract's service types; renewal 90 days before expiry
  assert.equal((await s.post('/aramco-ccc/certificate', { number: 'CCC-SYN-1', issued: '2026-11-22', expires: '2026-11-01', firm: 'Synthetic Audit Co', services: ['general'] })).status, 400);
  assert.equal((await s.post('/aramco-ccc/certificate', { number: 'CCC-SYN-1', issued: '2026-11-22', expires: '2027-11-21', firm: 'Synthetic Audit Co', services: ['general', 'network-connectivity'] })).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.deepEqual(v.uncovered, ['C-SYN-1'], 'critical-data is not on the certificate'); assert.equal(stage(v, 'certificate').done, false);
  assert.equal((await s.post('/aramco-ccc/certificate', { number: 'CCC-SYN-2', issued: '2026-11-22', expires: '2027-11-21', firm: 'Synthetic Audit Co', services: ['general', 'network-connectivity', 'critical-data'] })).status, 200);
  v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'certificate').done, true); assert.equal(stage(v, 'renewal').done, true); assert.equal(v.current, null, 'every stage done');
  s.tick(300 * DAY); v = (await s.get('/aramco-ccc')).json; assert.equal(stage(v, 'renewal').done, false); assert.equal(v.current, 'renewal');
  s.tick(80 * DAY); v = (await s.get('/aramco-ccc')).json; assert.match(stage(v, 'certificate').why, /EXPIRED/);
  assert.equal((await s.post('/aramco-ccc/contracts/' + conId + '/remove', {}, OP)).status, 403);
  // audit records with who
  for (const a of ['aramco-ccc.profile', 'aramco-ccc.contract.add', 'aramco-ccc.controls.import', 'aramco-ccc.control.assess', 'aramco-ccc.control.na.accepted', 'aramco-ccc.action.add', 'aramco-ccc.action.done', 'aramco-ccc.control.evidence', 'aramco-ccc.audit', 'aramco-ccc.finding', 'aramco-ccc.certificate'])
    assert.ok(s.audit(a).length && s.audit(a).every((x) => x.by && x.role), 'audited: ' + a);
});

test('readiness trend: three daily snapshots project to 100 % against the planned audit', async (t) => {
  const s = await setup(t);
  await s.put('/aramco-ccc/profile', { ccc_owner: 'omar.syn', planned_audit: '2026-11-07' });
  await s.post('/aramco-ccc/contracts', { contract_no: 'C-SYN-1', title: 'Synthetic', services: ['network-connectivity'] });
  await s.post('/aramco-ccc/controls/import', { csv: 'id,title,applies_to\n' + Array.from({ length: 10 }, (_, i) => 'T-' + i + ',Control ' + i + ',all').join('\n') });
  for (const c of Array.from({ length: 10 }, (_, i) => 'T-' + i)) await s.post('/aramco-ccc/controls/' + c + '/assess', { status: 'not-implemented' }, OP);
  for (let d = 0; d < 4; d++) { await s.post('/aramco-ccc/controls/T-' + d + '/assess', { status: 'implemented' }, OP); s.X.snapshot(); s.tick(DAY); }
  const v = (await s.get('/aramco-ccc')).json;
  assert.equal(v.snapshots, 4); assert.ok(v.projection && v.projection.per_week > 0, JSON.stringify(v.projection));
  assert.equal(v.projection.on_track, false); assert.match(v.projection.why, /AFTER the planned audit/);
});
