// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Implementation Roadmap (engine/impl-roadmap.js) with SYNTHETIC records: PDPL and NDMO tasks measured from the modules' own
// records (DPO profile, processing activities, impact assessments, the signed statement, the NDMO profile and controls); a task
// the platform cannot measure set by a person with evidence; a person marking a measured task done while the records show nothing
// reads "claimed"; roles (viewer reads, operator updates, admin sets the target; a service identity never), validation errors
// (done needs evidence, not applicable needs a reason, dates), undeclared fields dropped; next actions, blocked tasks, the critical
// path; the forecast from daily snapshots (withheld below 2 weeks); the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'dpo.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:pdpl', role: 'admin' };
const DAY = 86400000;

test('PDPL, NDMO, ISO 27001, NCA ECC and SAMA CSF roadmaps: measured, manual, claimed, roles, validation, next actions, forecast, audit', async (t) => {
  let T = Date.parse('2026-11-21T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const c = (n) => e.app.store.collection(n), task = (v, id) => v.tasks.find((x) => x.id === id);
  // empty: nothing invented
  let r = await call('GET', '/impl/pdpl', undefined, VIEW); assert.equal(r.status, 200, r.text);
  let v = r.json; assert.equal(v.done, 0); assert.equal(task(v, 'p-dpo').status, 'not_started'); assert.equal(task(v, 'p-dpo').source, 'measured'); assert.match(task(v, 'p-dpo').evidence, /no DPO named/);
  assert.equal(task(v, 'p-xfer').source, 'manual', 'no transfer recorded: a person says whether any exists');
  assert.equal(v.next[0].id, 'p-dpo', 'the DPO is first - most tasks wait for it'); assert.ok(v.next[0].unlocks >= 5);
  assert.ok(v.critical_path.length >= 4 && v.critical_path[0] === 'p-dpo', 'critical path starts at the DPO: ' + v.critical_path.join(' > '));
  assert.ok(v.blocked > 0); assert.match(v.forecast.why, /needs 2 weeks/);
  assert.equal((await call('GET', '/impl/cobit', undefined, VIEW)).status, 404);
  // the records decide
  c('pdpl_records').put({ id: 'profile', kind: 'profile', dpo_user: 'dpo.syn', sdaia_ref: 'SDAIA-SYN-1', privacy_policy_published: true });
  c('pdpl_discovery').put({ id: 'db1', label: 'CLAIMS-SYN' }); c('pdpl_records').put({ id: 'r1', kind: 'ropa', name: 'Claims (synthetic)' });
  c('pdpl_records').put({ id: 'd1', kind: 'dpia', completed: '2026-11-01' }); c('pdpl_records').put({ id: 'd2', kind: 'dpia' });
  v = (await call('GET', '/impl/pdpl', undefined, VIEW)).json;
  assert.equal(task(v, 'p-dpo').status, 'done'); assert.match(task(v, 'p-sdaia').evidence, /SDAIA-SYN-1/); assert.equal(task(v, 'p-ropa').status, 'done');
  assert.equal(task(v, 'p-dpia').status, 'in_progress'); assert.equal(task(v, 'p-dpia').progress, 50); assert.match(task(v, 'p-dpia').evidence, /1 of 2/);
  // roles
  assert.equal((await call('POST', '/impl/pdpl/task/p-xfer', { status: 'in_progress' }, VIEW)).status, 403, 'a viewer reads only');
  assert.equal((await call('POST', '/impl/pdpl/task/p-xfer', { status: 'in_progress' }, BOT)).status, 403, 'a service identity never updates');
  assert.equal((await call('POST', '/impl/pdpl/target', { target: '2027-03-31' }, OP)).status, 403, 'the target is an administrator decision');
  // validation
  r = await call('POST', '/impl/pdpl/task/p-xfer', { status: 'done' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  r = await call('POST', '/impl/pdpl/task/p-xfer', { status: 'not_applicable' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await call('POST', '/impl/pdpl/task/p-xfer', { due: '31/03/2027' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /due must be a date/);
  r = await call('POST', '/impl/pdpl/task/p-nope', { status: 'in_progress' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/impl/pdpl/task/p-xfer', { status: 'maybe' }, OP); assert.equal(r.status, 400);
  // a person sets what cannot be measured
  r = await call('POST', '/impl/pdpl/task/p-xfer', { status: 'not_applicable', note: 'all processing inside the Kingdom (synthetic)', owner: 'dpo.syn', due: '2026-12-01', hacked: 'x' }, OP); assert.equal(r.status, 200, r.text);
  assert.equal(task(r.json, 'p-xfer').status, 'not_applicable'); assert.equal(task(r.json, 'p-xfer').owner, 'dpo.syn');
  assert.equal(e.app.store.collection('impl_roadmap').get('pdpl').tasks['p-xfer'].hacked, undefined, 'undeclared fields are dropped');
  // claimed: a measured task cannot be marked done by a person
  r = await call('POST', '/impl/pdpl/task/p-train', { status: 'done', evidence: 'slides sent (synthetic)' }, OP);
  assert.equal(task(r.json, 'p-train').status, 'not_started', 'the records win'); assert.equal(task(r.json, 'p-train').claimed, true); assert.ok(r.json.claimed.includes('p-train'));
  // overdue
  r = await call('POST', '/impl/pdpl/task/p-proc', { due: '2026-11-01', owner: 'proc.syn' }, OP); assert.ok(task(r.json, 'p-proc').overdue); assert.ok(r.json.overdue.includes('p-proc'));
  assert.equal(r.json.next[0].id, 'p-proc', 'an overdue, unblocked task comes first');
  // target and forecast from snapshots
  r = await call('POST', '/impl/pdpl/target', { target: '2026-12-15', start: '2026-10-01' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.target, '2026-12-15');
  const R = e.app.addons.implRoadmap; R.snapshot(); T += 21 * DAY;
  c('pdpl_records').put({ id: 'tr1', kind: 'training' }); c('pdpl_records').put({ id: 'pb1', kind: 'playbook' }); c('pdpl_records').put({ id: 'p1', kind: 'processor' });
  R.snapshot(); v = (await call('GET', '/impl/pdpl', undefined, VIEW)).json;
  assert.ok(v.forecast.per_week > 0, v.forecast.why); assert.match(v.forecast.finish, /^\d{4}-\d\d-\d\d$/); assert.ok(typeof v.late_days === 'number');
  assert.ok(v.history.length >= 2); assert.equal(task(v, 'p-train').claimed, false, 'training recorded: no longer a claim');
  // NDMO
  c('ndmo_profile').put({ id: 'profile', cdo_user: 'cdo.syn', dmo_established: '2026-09-01', committee_last_met: '2026-05-01', applicability: { OD: 'applicable', FOI: 'not_applicable' } });
  c('ndmo_official').put({ id: 'DG.1', code: 'DG.1' }); c('ndmo_official').put({ id: 'DG.2', code: 'DG.2' }); c('ndmo_mapping').put({ id: 'DG.1', control: 'c1' });
  v = (await call('GET', '/impl/ndmo', undefined, VIEW)).json;
  assert.equal(task(v, 'n-cdo').status, 'done'); assert.equal(task(v, 'n-comm').status, 'in_progress', 'committee met more than 120 days ago'); assert.equal(task(v, 'n-map').progress, 50);
  assert.equal(task(v, 'n-quality').source, 'manual'); assert.equal(task(v, 'n-strat').status, 'not_started');
  // ISO/IEC 27001:2022 - profile, clauses, SoA, audits, nonconformities, certification
  v = (await call('GET', '/impl/iso', undefined, VIEW)).json;
  assert.equal(v.done, 0); assert.equal(v.next[0].id, 'i-lead'); assert.match(task(v, 'i-scope').evidence, /no scope statement/); assert.equal(task(v, 'i-nc').source, 'manual', 'no audit yet: nothing to say');
  c('iso_profile').put({ id: 'profile', top_management: 'CEO (synthetic)', isms_manager: 'isms.syn', scope: 'Head office IT (synthetic)', objectives: [{ objective: 'Patch criticals', measure: 'days', target: '14', current: '9', measured_on: '2026-11-01' }, { objective: 'Awareness' }] });
  c('iso_confirm').put({ id: '5.2', status: 'compliant', approved_by: 'ciso.syn' }); c('iso_confirm').put({ id: 'A.5.1', status: 'compliant', approved_by: null });
  c('iso_soa').put({ id: 'current', version: 1, proposed_by: 'isms.syn', approved_by: null });
  c('iso_audits').put({ id: 'IA-1', status: 'accepted' }); c('iso_audits').put({ id: 'IA-2', status: 'planned' });
  c('iso_ncs').put({ id: 'NC-1', status: 'closed' }); c('iso_ncs').put({ id: 'NC-2', status: 'action' });
  c('iso_lc_cert').put({ id: 'CB-001', event: 'stage1', result: 'minor', date: '2026-10-01', body: 'CB (synthetic)' });
  v = (await call('GET', '/impl/iso', undefined, VIEW)).json;
  assert.equal(task(v, 'i-lead').status, 'done'); assert.equal(task(v, 'i-scope').progress, 50, 'written, not approved');
  assert.equal(task(v, 'i-pol').progress, 85, 'one approved, one awaiting the second person'); assert.equal(task(v, 'i-soa').progress, 50);
  assert.equal(task(v, 'i-obj').progress, 50); assert.equal(task(v, 'i-mon').progress, 50); assert.equal(task(v, 'i-audit').progress, 50); assert.equal(task(v, 'i-nc').progress, 50);
  assert.equal(task(v, 'i-cert').progress, 50); assert.match(task(v, 'i-cert').evidence, /Stage 1 recorded/); assert.match(task(v, 'i-annex').evidence, /1 of 93/);
  // NCA ECC
  c('ecc_profile').put({ id: 'profile', ciso_user: 'ciso.syn', function_established: '2026-01-10', strategy_approved: '2026-02-01', committee_last_met: '2026-11-01', applicability: { '4-2': 'applies' } });
  c('ecc_official').put({ id: '1-1-1', code: '1-1-1' }); c('ecc_official').put({ id: '1-1-2', code: '1-1-2' }); c('ecc_mapping').put({ id: '1-1-1', control: 'ZS-1-1-01' }); c('ecc_mapping').put({ id: '1-1-2', control: 'ZS-1-1-02' });
  c('ecc_confirm').put({ id: 'ZS-1-1-01', status: 'compliant', approved_by: 'syed' });
  c('grc_actions').put({ id: 'ACT-0001', framework: 'NCA ECC', status: 'closed' }); c('grc_actions').put({ id: 'ACT-0002', framework: 'NCA ECC', status: 'open' });
  v = (await call('GET', '/impl/nca', undefined, VIEW)).json;
  assert.equal(v.name, 'NCA ECC-2:2024'); assert.equal(task(v, 'e-head').status, 'done'); assert.equal(task(v, 'e-func').progress, 50, 'reports_to missing'); assert.match(task(v, 'e-func').evidence, /reports to/);
  assert.equal(task(v, 'e-comm').status, 'done'); assert.equal(task(v, 'e-appl').progress, 50); assert.equal(task(v, 'e-record').progress, 50); assert.equal(task(v, 'e-approve').status, 'done');
  assert.equal(task(v, 'e-close').progress, 50); assert.equal(task(v, 'e-aware').source, 'manual'); assert.equal(task(v, 'e-bcm').status, 'not_started');
  // SAMA CSF - shares the CISO / committee with ECC; its own requirements and runs
  c('sama_confirm').put({ id: 'SA-3.3.8-01', status: 'partial', approved_by: null }); c('sama_runs').put({ id: '2026-11-20', score: 62, at_target: 9 });
  c('grc_drills').put({ id: 'DR-0001', status: 'completed', executed: '2026-06-01' });
  v = (await call('GET', '/impl/sama', undefined, VIEW)).json;
  assert.equal(task(v, 's-ciso').status, 'done'); assert.equal(task(v, 's-approve').progress, 0); assert.equal(task(v, 's-run').status, 'done');
  assert.equal(task(v, 's-level3').progress, 62); assert.match(task(v, 's-level3').evidence, /9 subdomain/); assert.equal(task(v, 's-monthly').status, 'done'); assert.equal(task(v, 's-bcm').status, 'done');
  assert.equal(task(v, 's-gaps').status, 'not_started', 'NCA actions are not SAMA actions');
  r = await call('POST', '/impl/sama/task/s-aware', { status: 'done', evidence: 'Awareness plan AW-2026 (synthetic)' }, OP); assert.equal(r.status, 200, r.text);
  assert.equal(task(r.json, 's-aware').status, 'done');
  // audit
  const au = e.app.store.auditTail(200).filter((a) => /^impl\./.test(a.action));
  assert.ok(au.some((a) => a.action === 'impl.task' && a.by === 'dpo.syn' && a.target === 'pdpl:p-xfer')); assert.ok(au.some((a) => a.target === 'sama:s-aware')); assert.ok(au.some((a) => a.action === 'impl.target' && a.by === 'syed'));
});
