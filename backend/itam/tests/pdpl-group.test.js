// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL across the group (engine/pdpl-group.js) with SYNTHETIC group companies: the register (DPO / admin only, validation naming
// the field, duplicates refused), the data processing agreement (terms checked, expiry, four-eyes acceptance), RoPA activities
// linked only when they exist, breach notices (late against the agreed hours, open past the limit said), roles, audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HOUR = 3600000, DAY = 24 * HOUR;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, BOT = { user: 'ai:pdpl', role: 'operator' };
async function setup(t) {
  let clock = Date.parse('2026-11-20T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const post = (p, b, who = DPO) => e.req('POST', p, Object.assign({ body: b }, who)), get = (p, who = DPO) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  return { e, post, get, tick: (ms) => { clock += ms; }, audit: (a) => e.app.store.auditTail(1000).filter((x) => x.action === a) };
}

test('group companies, agreements with four-eyes acceptance, activities, breach notices', async (t) => {
  const s = await setup(t);
  assert.equal((await s.get('/pdpl/group', VIEW)).status, 403, 'it names people: not for viewers');
  let v = (await s.get('/pdpl/group')).json; assert.equal(v.dpo, 'huda.syn'); assert.equal(v.kpis.companies, 0);
  // the register
  let r = await s.post('/pdpl/group/companies', { name: 'Synthetic Trading Co', services: ['hr-payroll'] }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /DPO/);
  assert.equal((await s.post('/pdpl/group/companies', { name: 'Synthetic Trading Co', services: ['hr-payroll'] }, BOT)).status, 403);
  r = await s.post('/pdpl/group/companies', { name: 'Synthetic Trading Co', services: ['payroll-ish'] }); assert.equal(r.status, 400); assert.match(r.json.error, /services/);
  r = await s.post('/pdpl/group/companies', { name: 'Synthetic Trading Co', services: ['hr-payroll'], cr_no: 'ABC' }); assert.equal(r.status, 400); assert.match(r.json.error, /cr_no/);
  r = await s.post('/pdpl/group/companies', { name: 'Synthetic Trading Co', cr_no: '1010000001', services: ['hr-payroll', 'it-services'], contact: 'privacy.syn', contact_email: 'privacy@trading.example' }); assert.equal(r.status, 200, r.text);
  const id = r.json.id;
  assert.equal((await s.post('/pdpl/group/companies', { name: 'synthetic trading co', services: ['fleet'] })).status, 409, 'duplicate name');
  v = (await s.get('/pdpl/group')).json; const c0 = v.companies[0];
  assert.equal(c0.status, 'no agreement'); assert.ok(c0.findings.some((f) => /No data processing agreement/.test(f.text)) && c0.findings.some((f) => /No RoPA activity/.test(f.text)));
  // the agreement: validated, terms checked, accepted by a different person
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa', { signed: '2027-01-01', ref: 'DPA-1' })).status, 400, 'signed in the future');
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa', { signed: '2026-01-01', expires: '2025-12-31', ref: 'DPA-1' })).status, 400);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa', { signed: '2026-01-01', ref: 'DPA-1', terms: ['magic'] })).status, 400);
  r = await s.post('/pdpl/group/companies/' + id + '/dpa', { signed: '2026-01-01', expires: '2026-12-31', ref: 'DPA-SYN-1', terms: ['instructions', 'confidentiality', 'security', 'breach'], breach_hours: 24 }); assert.equal(r.status, 200, r.text);
  v = (await s.get('/pdpl/group')).json; let fs = v.companies[0].findings.map((f) => f.text).join(' | ');
  assert.match(fs, /5 term\(s\) not covered/); assert.match(fs, /not accepted by the DPO/); assert.match(fs, /expires on 2026-12-31/);
  r = await s.post('/pdpl/group/companies/' + id + '/dpa/accept', {}); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa/accept', {}, OP)).status, 403);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa/accept', {}, ADM)).status, 200);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/dpa/accept', {}, ADM)).status, 409);
  // activities: only RoPA ids that exist
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/activities', { ropa_ids: ['nope-1'] })).status, 400);
  const ro = await s.post('/pdpl/records', { kind: 'ropa', name: 'Payroll for Synthetic Trading (synthetic)', purpose: 'Run payroll for the group company', legal_basis: 'contract', data_categories: ['identity', 'financial'], subjects: 'Employees', owner: 'hr.syn' }, ADM);
  assert.equal(ro.status, 200, ro.text);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/activities', { ropa_ids: [ro.json.id] })).status, 200);
  // breach notices: late against the agreed 24 h; an open one past the limit is said
  r = await s.post('/pdpl/group/notices', { company: id, incident_ref: 'INC-SYN-1', detected: '2026-11-20T06:00', summary: 'Synthetic: payroll export sent to a wrong address' }, OP); assert.equal(r.status, 200, r.text); const nid = r.json.id;
  assert.equal((await s.post('/pdpl/group/notices', { company: id, incident_ref: 'INC-SYN-2', detected: '2027-01-01T00:00', summary: 'future' }, OP)).status, 400);
  s.tick(30 * HOUR); v = (await s.get('/pdpl/group')).json; assert.match(v.companies[0].findings.map((f) => f.text).join(' | '), /not yet told, 32 h after detection \(agreed 24 h\)/);
  assert.equal((await s.post('/pdpl/group/notices/' + nid + '/notified', { notified_at: '2026-11-20T05:00', how: 'e-mail' }, OP)).status, 400, 'before detection');
  r = await s.post('/pdpl/group/notices/' + nid + '/notified', { notified_at: '2026-11-21T12:00', how: 'e-mail to the privacy contact' }, OP); assert.equal(r.status, 200); assert.equal(r.json.late, true); assert.equal(r.json.hours, 30);
  v = (await s.get('/pdpl/group')).json; assert.equal(v.companies[0].status, 'attention'); assert.match(v.companies[0].findings[0].text, /sent late/);
  for (const a of ['pdpl.group.company.add', 'pdpl.group.dpa.record', 'pdpl.group.dpa.accept', 'pdpl.group.activities', 'pdpl.group.notice.add', 'pdpl.group.notice.notified'])
    assert.ok(s.audit(a).length && s.audit(a).every((x) => x.by && x.role), 'audited: ' + a);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/remove', {}, OP)).status, 403);
  assert.equal((await s.post('/pdpl/group/companies/' + id + '/remove', {})).status, 200);
});
