// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NDMO data management register (engine/ndmo.js, pyengine/ndmo_rules.py) through the real routes: roles (viewer / operator /
// admin and the refused cases), validation errors naming the field, four-eyes approval by a person, the registers winning
// over a confirmation, the Personal Data Protection domain read from the PDPL register, the official list import and its
// mapping, gaps to GRC once, the audit trail and the duty engineer. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, CDO = { user: 'huda.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };

async function setup(t) {
  const clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, ndmoCatalogFiles: false });
  const call = async (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, D, call, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const ctl = (v, id) => v.controls.find((c) => c.id === id);
const auditOf = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('the register: 15 domains, insurer controls, maturity, the PDPL domain from the PDPL register', async (t) => {
  const { e, post, get } = await setup(t);
  let r = await get('/ndmo', VIEW);
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.domains.length, 15); assert.equal(v.maturity.length, 15);
  assert.ok(v.controls.length >= 50 && v.controls.every((c) => /^ZS-[A-Z]{2,3}-\d{2}$/.test(c.id)), 'register controls carry the platform\'s own ids, not official codes');
  assert.ok(v.domains.filter((d) => d.decide).map((d) => d.code).join() === 'OD,FOI', 'open data and FOI wait for the CDO\'s applicability decision');
  assert.match(v.note, /not NDMO's own assessment/);
  assert.equal(ctl(v, 'ZS-DG-01').result, 'gap', 'no Chief Data Officer = a gap');
  // the PDPL register drives the Personal Data Protection domain
  await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' });
  await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], systems: ['CLAIMS-SQL'] });
  r = await get('/ndmo', VIEW);
  assert.equal(r.json.pdpl.available, true);
  assert.equal(ctl(r.json, 'ZS-PDP-01').result, 'gap', 'PDPL non-compliance is an NDMO gap');
  assert.match(ctl(r.json, 'ZS-PDP-01').why, /PDPL compliance \d+%; non-compliant: /);
  assert.equal(ctl(r.json, 'ZS-PDP-07').result, 'auto_pass', 'a DPO on the PDPL profile shows in NDMO');
  assert.ok(ctl(r.json, 'ZS-DG-04').why.includes('Claims'), 'a department owning data with no steward is named');
  assert.ok(e.app.addons.ndmo, 'installed as an add-on');
});

test('roles and validation: viewer refused, fields named, the profile is administrator-only', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'compliant', evidence: 'x' }, VIEW)).status, 403, 'a viewer cannot record');
  assert.equal((await post('/ndmo/profile', { cdo_user: 'huda.syn' }, OP)).status, 403, 'the profile is admin only');
  assert.equal((await post('/ndmo/official', { rows: [{ code: 'DG.1.1', domain: 'DG', title: 't' }] }, OP)).status, 403, 'the official list is admin only');
  assert.equal((await post('/ndmo/mapping', { code: 'DG.1.1', control: 'ZS-DG-02' }, OP)).status, 403);
  assert.equal((await get('/ndmo/suggest', VIEW)).status, 403); assert.equal((await get('/ndmo/export', VIEW)).status, 403);
  let r = await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'compliant' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  r = await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'non_compliant' }, OP); assert.match(r.json.error, /note is required/);
  r = await post('/ndmo/confirm', { id: 'DG.1.1', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be a register control/);
  r = await post('/ndmo/confirm', { id: 'ZS-ZZ-99', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 404);
  r = await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'great', evidence: 'x' }, OP); assert.match(r.json.error, /^status must be one of/);
  r = await post('/ndmo/profile', { strategy_approved: '2026-13-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /strategy_approved must be a date/);
  r = await post('/ndmo/profile', { committee_last_met: '2030-01-01' }); assert.match(r.json.error, /cannot be in the future/);
  r = await post('/ndmo/profile', { applicability: { OD: 'not_applicable' } }); assert.equal(r.status, 400); assert.match(r.json.error, /applicability_note.OD is required/);
  r = await post('/ndmo/profile', { applicability: { DQ: 'applies' } }); assert.match(r.json.error, /not a domain that needs a decision/);
  r = await post('/ndmo/profile', { cdo_user: 'huda.syn', dmo_established: '2026-03-01', unknown_field: 'dropped' }); assert.equal(r.status, 200);
  assert.equal(r.json.unknown_field, undefined, 'undeclared fields are dropped');
});

test('four eyes: a person records, a different person (CDO / administrator) approves; the registers win', async (t) => {
  const { e, post, get } = await setup(t);
  await post('/ndmo/profile', { cdo_user: 'huda.syn', dmo_established: '2026-03-01' });
  assert.equal((await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'compliant', evidence: 'DQ rules v1 (synthetic)' }, BOT)).status, 403, 'an AI identity never records');
  let r = await post('/ndmo/confirm', { id: 'ZS-DQ-01', status: 'compliant', evidence: 'DQ rules v1 (synthetic)' }, OP);
  assert.equal(r.status, 200); assert.equal(r.json.result, 'pending', 'recorded, waiting for the second person');
  assert.equal(auditOf(e, 'ndmo.confirm')[0].by, 'nora.syn');
  assert.equal((await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'approve' }, OP)).status, 403, 'four eyes: not the recorder');
  assert.equal((await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'approve' }, OP2)).status, 403, 'an operator who is not the CDO cannot approve');
  assert.equal((await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'approve' }, { user: 'system:x', role: 'admin' })).status, 403, 'a service never approves');
  assert.match((await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'reject' }, CDO)).json.error, /note is required/);
  r = await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'approve' }, CDO);
  assert.equal(r.status, 200); assert.equal(r.json.result, 'met');
  assert.equal(r.json.confirmation.approved_by, 'huda.syn');
  assert.equal(auditOf(e, 'ndmo.confirm.approve')[0].detail.recorded_by, 'nora.syn');
  assert.equal((await post('/ndmo/confirm/ZS-DQ-01/decide', { decision: 'approve' }, ADM)).status, 409, 'approved once');
  // the registers win: no strategy recorded = a gap, whatever a person says
  await post('/ndmo/confirm', { id: 'ZS-DG-02', status: 'compliant', evidence: 'strategy (synthetic)' }, OP);
  r = await post('/ndmo/confirm/ZS-DG-02/decide', { decision: 'approve' }, ADM);
  assert.equal(r.json.result, 'gap'); assert.equal(r.json.conflict, true);
  // a rejection removes the record and says why in the audit trail
  await post('/ndmo/confirm', { id: 'ZS-DQ-02', status: 'partial', evidence: 'monthly report (synthetic)' }, OP);
  r = await post('/ndmo/confirm/ZS-DQ-02/decide', { decision: 'reject', note: 'report not signed off' }, CDO);
  assert.equal(r.json.result, 'no_evidence'); assert.equal(auditOf(e, 'ndmo.confirm.reject')[0].detail.note, 'report not signed off');
  const v = (await get('/ndmo', VIEW)).json;
  assert.ok(v.maturity.find((m) => m.domain === 'DQ').score > 0, 'an approved control raises the domain score');
});

test('official list: import checked row by row, suggestions accepted by an administrator, coverage shown', async (t) => {
  const { e, post, get } = await setup(t);
  let r = await post('/ndmo/official', { rows: [{ code: 'DG.1.1', domain: 'Data Governance', title: 'Data management strategy (synthetic)' }, { code: 'bad code!', domain: 'DG', title: 'x' },
    { code: 'DQ.2.1', domain: 'quality', title: 'Data quality rules for critical data (synthetic)' }, { code: 'XX.1.1', domain: 'Astrology', title: 'x' }] });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.imported, 2); assert.equal(r.json.error_count, 2);
  assert.ok(r.json.errors.some((x) => /not a control code/.test(x)) && r.json.errors.some((x) => /not one of the 15 NDMO domains/.test(x)));
  assert.match((await post('/ndmo/official', { rows: [{ code: 'DG.1.1', domain: 'DG' }] })).json.error, /^rows\[0\]\.title is required/, 'a row field is named');
  assert.match((await post('/ndmo/official', { rows: 'x' })).json.error, /rows must be a list/);
  assert.equal(auditOf(e, 'ndmo.official.import')[0].detail.imported, 2);
  const s = (await get('/ndmo/suggest')).json.suggestions;
  assert.equal(s.length, 2); assert.equal(s.find((x) => x.code === 'DQ.2.1').control, 'ZS-DQ-01');
  r = await post('/ndmo/mapping', { accept: ['DQ.2.1'] }); assert.equal(r.json.accepted, 1);
  r = await post('/ndmo/mapping', { code: 'DG.1.1', control: 'ZS-ZZ-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /control: no register control/);
  r = await post('/ndmo/mapping', { code: 'NO.9.9', control: 'ZS-DG-02' }); assert.equal(r.status, 404);
  r = await post('/ndmo/mapping', { code: 'DG.1.1', control: 'ZS-DG-02' }); assert.equal(r.status, 200);
  const v = (await get('/ndmo', VIEW)).json;
  assert.equal(v.coverage.total, 2); assert.equal(v.coverage.mapped, 2);
  assert.deepEqual(ctl(v, 'ZS-DG-02').official, ['DG.1.1']);
  // replacing the list drops mappings whose code is gone
  await post('/ndmo/official', { rows: [{ code: 'DQ.2.1', domain: 'DQ', title: 'Data quality rules (synthetic)' }] });
  assert.deepEqual(ctl((await get('/ndmo', VIEW)).json, 'ZS-DG-02').official, []);
});

test('gaps to GRC once, CSV export without formula injection, the duty engineer patrols the register', async (t) => {
  const { e, D, post, get } = await setup(t);
  await post('/ndmo/profile', { cdo_user: 'huda.syn', dmo_established: '2026-03-01' });
  assert.equal((await post('/ndmo/gaps-to-grc', {}, OP2)).status, 403, 'only the CDO or an administrator');
  let r = await post('/ndmo/gaps-to-grc', {}, CDO);
  assert.equal(r.status, 200, r.raw); assert.ok(r.json.created.length >= 5, r.json.created.length + ' actions');
  const acts = e.app.store.collection('grc_actions').all((a) => a.source === 'ndmo');
  assert.equal(acts.length, r.json.created.length); assert.ok(acts.every((a) => /^NDMO ZS-/.test(a.title) && a.framework === 'NDMO'));
  r = await post('/ndmo/gaps-to-grc', {}, CDO);
  assert.equal(r.json.created.length, 0, 'never twice for the same open gap');
  // export: a value starting with = is neutralised
  await post('/ndmo/confirm', { id: 'ZS-DQ-03', status: 'compliant', evidence: '=HYPERLINK("http://x")' }, OP);
  await post('/ndmo/confirm/ZS-DQ-03/decide', { decision: 'approve' }, CDO);
  r = await get('/ndmo/export');
  assert.equal(r.status, 200); assert.match(r.json.filename, /^ndmo-register-\d{4}-\d{2}-\d{2}\.csv$/);
  assert.ok(r.json.csv.includes('=HYPERLINK') && !/(^|,)"[=+@-]/m.test(r.json.csv), 'no cell starts with a formula character');
  assert.equal(auditOf(e, 'ndmo.export').length, 1);
  // the duty engineer: gaps become work items, low items for controls with no evidence and for the OD / FOI decision
  await D.patrol('ndmo');
  const items = D.list({ engineer: 'ndmo', status: 'open', limit: 200 }).items;
  assert.ok(items.some((x) => x.key === 'ndmo:ZS-DG-02'), 'the missing strategy is a work item');
  assert.ok(items.some((x) => x.key === 'ndmo:decide:OD') && items.some((x) => /^ndmo:evidence:/.test(x.key)));
  assert.ok(!items.some((x) => x.key === 'ndmo:ZS-DG-01'), 'the CDO is named: no item');
  // readiness names what is missing
  const rd = (await get('/duty/readiness', ADM)).json;
  const nd = (rd.engineers || rd).find((x) => x.id === 'ndmo');
  assert.ok(nd && nd.checks.some((c) => c.name === 'Official NDMO control list' && c.ok === false));
});
