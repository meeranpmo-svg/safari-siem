// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL retention enforcement (engine/pdpl-retention.js): a person maps a retention rule to a Data Catalog table and its date
// column; the scan asks for ONE fixed COUNT per table (stubbed runner); a table past retention is a task for its data owner;
// the owner records the disposal, the DPO (another person) accepts, the next scan verifies the count fell; holds are
// four-eyes; signals for Notification & Escalation; roles (viewer / operator / admin / DPO, refused cases); validation (an
// unsafe table / column name refused); the audit record; the Python count against a fake connection (only the dictionary
// lookup and the COUNT are sent, the date bound) and, where PostgreSQL is installed, against a real database.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { startPg } = require('./_pg');
const R = require('../engine/pdpl-retention');

const PY = process.env.PYTHON || 'python3';
const HELPER = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
const DPO = { user: 'dpo.syn', role: 'operator' }, OWNER = { user: 'owner.syn', role: 'viewer' }, AI = { user: 'ai:pdpl-consultant', role: 'operator' };
const SQL = 'mssql|10.8.0.52|1433', PG = 'postgres|10.8.0.53|5432';

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-10-20T08:00:00Z');
  const S = e.app.store, recs = S.collection('pdpl_records');
  recs.put({ id: 'profile', kind: 'profile', dpo_user: 'dpo.syn', status: 'active' });
  recs.put({ id: 'PD-RETENTION-001', kind: 'retention', status: 'active', name: 'Closed motor claims (synthetic)', period_months: 120, trigger: 'claim_closed', action: 'destroy', systems: ['CLAIMS-SQL'] });
  recs.put({ id: 'PD-RETENTION-002', kind: 'retention', status: 'archived', name: 'Old rule (synthetic)', period_months: 12, trigger: 'collection', action: 'destroy' });
  recs.put({ id: 'PD-ROPA-001', kind: 'ropa', status: 'active', name: 'Customer onboarding (synthetic)', retention_months: 84, systems: ['CRM-PG'] });
  recs.put({ id: 'PD-ROPA-002', kind: 'ropa', status: 'active', name: 'No period (synthetic)' });
  const disc = S.collection('pdpl_discovery');
  disc.put({ id: SQL, db: SQL, engine: 'mssql', label: 'CLAIMS-SQL', host: '10.8.0.52', port: 1433, cred_id: 'c2', ok: true, columns: [
    { owner: 'dbo', table: 'Claims', column: 'ClaimantNationalId', type: 'varchar', rows: 9000, kind: 'national_id', category: 'identity', confirmed: true },
    { owner: 'dbo', table: 'Claims', column: 'DateOfBirth', type: 'date', rows: 9000, kind: 'birth_date', category: 'identity', confirmed: null },
    { owner: 'dbo', table: 'Members', column: 'IqamaNo', type: 'varchar', rows: 300, kind: 'iqama', category: 'identity', confirmed: true },
    { owner: 'dbo', table: 'Bad"T', column: 'Email', type: 'nvarchar', rows: 2, kind: 'email', category: 'contact' }] });
  disc.put({ id: PG, db: PG, engine: 'postgres', label: 'CRM-PG', host: '10.8.0.53', port: 5432, cred_id: null, ok: true, columns: [{ owner: 'crm', table: 'customers', column: 'mobile_no', type: 'character varying', rows: 5200, kind: 'mobile', category: 'contact' }] });
  disc.put({ id: '_last', at: '2026-10-19T00:00:00Z' });
  S.collection('pdpl_office_cfg').put({ id: 'cfg', owners: [{ system: 'CLAIMS-SQL', user: 'owner.syn' }] });
  const COUNT = { Claims: 1200, Members: 40 }, calls = [];
  const runQuery = 'runQuery' in o ? o.runQuery : (async (q) => { calls.push(q); return { ok: true, count: COUNT[q.table], oldest: '2011-02-03' }; });
  const X = R.createPdplRetention(e.app, { now: () => clock, noTimer: true, runQuery, runHelper: o.runHelper });
  R.registerPdplRetention(e.app.srv, e.app, X);
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  const audits = (a) => S.auditTail(500).filter((x) => x.action === a);
  const map = (b, who) => post('/pdpl/retention/maps', Object.assign({ rule_id: 'PD-RETENTION-001', db: SQL, schema: 'dbo', table: 'Claims', date_column: 'ClosedDate' }, b), who);
  return { e, X, S, post, get, audits, map, calls, COUNT, tick: (ms) => { clock += ms; }, now: () => clock };
}

test('roles: the view is for operators, a data owner with the viewer role sees their own tasks; viewers and AI identities cannot write', async (t) => {
  const { post, get, map } = await setup(t);
  assert.equal((await get('/pdpl/retention/enforcement', VW)).status, 403);
  const v = await get('/pdpl/retention/enforcement'); assert.equal(v.status, 200, v.raw);
  assert.equal(v.json.dpo, 'dpo.syn'); assert.equal(v.json.is_dpo, false); assert.equal(v.json.can_approve, false);
  assert.equal((await get('/pdpl/retention/enforcement', DPO)).json.can_approve, true);
  assert.equal((await get('/pdpl/retention/enforcement', ADM)).json.can_approve, true);
  assert.deepEqual(v.json.rules.map((r) => r.id).sort(), ['PD-RETENTION-001', 'PD-ROPA-001'], 'archived rules and activities without a period are not offered');
  assert.equal((await get('/pdpl/retention/enforcement/mine', VW)).status, 200);
  assert.equal((await map({}, VW)).status, 403);
  assert.equal((await map({}, AI)).status, 403, 'an AI identity does not map');
  assert.equal((await post('/pdpl/retention/scan', {}, VW)).status, 403);
  assert.equal((await post('/pdpl/retention/settings', { every_days: 30 }, VW)).status, 403);
  assert.equal((await post('/pdpl/retention/settings', { every_days: 30 })).status, 403, 'an operator who is not the DPO does not set the scan');
  assert.equal((await post('/pdpl/retention/holds', { map_id: 'RM-00001', reason: 'synthetic claim dispute', until: '2027-01-01' }, VW)).status, 403);
});

test('mapping: validated at the boundary, the table must be in the Data Catalog, an unsafe name is refused, catalog date columns suggested', async (t) => {
  const { map, get, audits, S } = await setup(t);
  let r = await map({ rule_id: undefined }); assert.equal(r.status, 400); assert.match(r.json.error, /rule_id is required/);
  r = await map({ rule_id: 'PD-DSR-001' }); assert.equal(r.status, 400); assert.match(r.json.error, /rule_id must be/);
  r = await map({ table: 'Bad"T' }); assert.equal(r.status, 400); assert.match(r.json.error, /^table must be a database name/);
  r = await map({ date_column: 'ClosedDate; drop table dbo.Claims --' }); assert.equal(r.status, 400); assert.match(r.json.error, /^date_column must be a database name/);
  r = await map({ schema: 'dbo]' }); assert.equal(r.status, 400); assert.match(r.json.error, /^schema/);
  r = await map({ db: 'x y' }); assert.equal(r.status, 400); assert.match(r.json.error, /^db must be/);
  r = await map({ owner: 'not a user!' }); assert.equal(r.status, 400); assert.match(r.json.error, /^owner/);
  r = await map({ owner: 'svc.batch' }); assert.equal(r.status, 400); assert.match(r.json.error, /a person/);
  r = await map({ table: 'Policies' }); assert.equal(r.status, 404); assert.match(r.json.error, /not in the Data Catalog/);
  r = await map({ db: 'oracle|10.0.0.9|1521' }); assert.equal(r.status, 404); assert.match(r.json.error, /no Data Catalog source/);
  r = await map({ rule_id: 'PD-RETENTION-002' }); assert.equal(r.status, 404, 'an archived rule');
  r = await map({ rule_id: 'PD-ROPA-002' }); assert.equal(r.status, 404, 'no period: not a rule');
  r = await map({ date_column: 'ClaimantNationalId' }); assert.equal(r.status, 409); assert.match(r.json.error, /not a date/);
  const v = (await get('/pdpl/retention/enforcement')).json;
  const claims = v.catalog.find((x) => x.table === 'Claims'); assert.deepEqual(claims.date_columns.map((c) => c.column), ['DateOfBirth']); assert.match(claims.date_columns[0].note, /birth date/);
  assert.deepEqual(claims.rules, ['PD-RETENTION-001'], 'the rule naming the system is suggested');
  assert.equal(v.catalog.find((x) => x.table === 'Bad"T').safe, false, 'a hostile catalog name is marked, never queried');
  r = await map({ status: 'retired', last: { ok: true, count: 0 }, by: 'someone.else', system: 'Claims (synthetic)', note: 'closed claims, settled date' });
  assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'active'); assert.equal(r.json.last, null); assert.equal(r.json.by, 'nora.syn', 'undeclared fields dropped (no mass assignment)');
  assert.equal(r.json.column_from, 'typed'); assert.equal(r.json.system, 'Claims (synthetic)');
  assert.equal((await map({})).status, 409, 'the same table and rule twice');
  const a = audits('pdpl.retention.map.add'); assert.equal(a.length, 1); assert.equal(a[0].by, 'nora.syn'); assert.equal(a[0].role, 'operator'); assert.equal(a[0].detail.table, 'dbo.Claims'); assert.equal(a[0].detail.date_column, 'ClosedDate');
  assert.equal((await map({ table: 'Members', date_column: 'LeftOn' })).status, 200);
  assert.equal(S.collection('pdpl_retention_maps').size(), 2);
});

test('scan: one fixed COUNT per mapped table with validated identifiers and the cut-off; failures say why with no number; tasks for the data owner', async (t) => {
  const { post, map, calls, audits, get, S, e } = await setup(t);
  assert.equal((await post('/pdpl/retention/scan', {})).status, 409, 'nothing mapped yet');
  assert.equal((await map({ system: 'CLAIMS-SQL' })).status, 200);
  assert.equal((await map({ table: 'Members', date_column: 'LeftOn', owner: 'steward.syn' })).status, 200);
  assert.equal((await map({ rule_id: 'PD-ROPA-001', db: PG, schema: 'crm', table: 'customers', date_column: 'last_contact' })).status, 200);
  const r = await post('/pdpl/retention/scan', {}); assert.equal(r.status, 200, r.raw);
  // only COUNTs are ever requested: the spec has the op, identifiers and the cut-off - no SQL, no other operation
  assert.equal(calls.length, 2, 'the source without a read-only login is not queried');
  for (const c of calls) {
    assert.equal(c.op, 'retention_count');
    assert.deepEqual(Object.keys(c).sort(), ['column', 'cred_id', 'cutoff', 'engine', 'host', 'key', 'op', 'port', 'schema', 'service', 'table']);
    assert.ok(!Object.values(c).some((v) => /select|delete|update|insert|drop/i.test(String(v))), 'no SQL text in the request');
  }
  assert.deepEqual(calls.map((c) => [c.engine, c.schema, c.table, c.column, c.cutoff]), [['mssql', 'dbo', 'Claims', 'ClosedDate', '2016-10-20'], ['mssql', 'dbo', 'Members', 'LeftOn', '2016-10-20']], '120 calendar months back from the Riyadh day');
  assert.equal(r.json.mapped, 3); assert.equal(r.json.ok, 2); assert.equal(r.json.failed, 1); assert.equal(r.json.rows, 1240);
  const v = (await get('/pdpl/retention/enforcement')).json;
  const pg = v.maps.find((m) => m.table === 'customers');
  assert.equal(pg.last.ok, false); assert.equal(pg.last.count, null, 'a failure is never a guessed number'); assert.equal(pg.last.error_class, 'no_login'); assert.match(pg.last.error, /no read-only login/);
  assert.equal(pg.last.cutoff, '2019-10-20', 'the activity\'s retention_months (84)');
  const claims = v.maps.find((m) => m.table === 'Claims'); assert.equal(claims.last.count, 1200); assert.equal(claims.last.oldest, '2011-02-03');
  assert.equal(v.totals.tables_past, 2); assert.equal(v.totals.rows_past, 1240); assert.equal(v.totals.failed, 1); assert.equal(v.totals.open, 2);
  const tc = v.tasks.find((x) => x.table === 'dbo.Claims'); assert.equal(tc.owner, 'owner.syn', 'the Privacy Office\'s data owner of the system');
  assert.equal(v.tasks.find((x) => x.table === 'dbo.Members').owner, 'steward.syn', 'the owner named in the mapping');
  // a second scan does not open a second task for the same table
  await post('/pdpl/retention/scan', {}); assert.equal(S.collection('pdpl_retention_tasks').size(), 2);
  const sa = audits('pdpl.retention.scan'); assert.equal(sa.length, 2); assert.equal(sa[0].by, 'nora.syn'); assert.equal(sa[0].detail.rows_past, 1240);
  assert.equal(audits('pdpl.retention.task.open').length, 2);
  // the owner (viewer role) sees their task; counts only
  const mine = (await get('/pdpl/retention/enforcement/mine', OWNER)).json; assert.equal(mine.tasks.length, 1); assert.equal(mine.tasks[0].count, 1200);
  // helper failures: words, never a number
  const s2 = await setup(t, { runQuery: async (q) => (q.table === 'Claims' ? { ok: false, error_class: 'denied', error: 'SELECT permission was denied' } : { ok: true, count: -3 }) });
  await s2.map({}); await s2.map({ table: 'Members', date_column: 'LeftOn' });
  await s2.post('/pdpl/retention/scan', {});
  const v2 = (await s2.get('/pdpl/retention/enforcement')).json;
  const c2 = v2.maps.find((m) => m.table === 'Claims').last; assert.equal(c2.ok, false); assert.equal(c2.count, null); assert.match(c2.error, /no SELECT grant/); assert.equal(c2.detail, 'SELECT permission was denied');
  assert.equal(v2.maps.find((m) => m.table === 'Members').last.error_class, 'bad_answer', 'a nonsense count is refused, not shown');
  assert.equal(v2.tasks.length, 0, 'no task from a failed count');
  // a hostile name that reached the store some other way is still never sent
  const s3 = await setup(t);
  await s3.map({});
  s3.S.collection('pdpl_retention_maps').patch('RM-00001', (m) => { m.table = 'Claims"; delete from x; --'; });
  s3.S.collection('pdpl_discovery').patch(SQL, (d) => { d.columns.push({ owner: 'dbo', table: 'Claims"; delete from x; --', column: 'a', type: 'date' }); });
  await s3.post('/pdpl/retention/scan', {});
  assert.equal(s3.calls.length, 0, 'not queried'); assert.equal((await s3.get('/pdpl/retention/enforcement')).json.maps[0].last.error_class, 'name');
  assert.ok(e);
});

test('disposal: the owner attests, the DPO (another person) accepts, the next scan verifies - or does not; four-eyes; audit; signals', async (t) => {
  const { post, map, get, audits, COUNT, tick, S, X } = await setup(t);
  await map({}); await map({ table: 'Members', date_column: 'LeftOn' });
  await post('/pdpl/retention/scan', {});
  const tasks = (await get('/pdpl/retention/enforcement')).json.tasks, tc = tasks.find((x) => x.table === 'dbo.Claims'), tm = tasks.find((x) => x.table === 'dbo.Members');
  const att = (id, b, who) => post('/pdpl/retention/tasks/' + id + '/attest', Object.assign({ method: 'deletion', date: '2026-10-19', reference: 'CHG-SYN-101', note: 'purged closed claims older than 10 years (synthetic)' }, b), who);
  // validation
  assert.equal((await att(tc.id, { method: 'shredded' }, OWNER)).status, 400);
  assert.equal((await att(tc.id, { date: '2026-13-01' }, OWNER)).status, 400);
  assert.equal((await att(tc.id, { date: '2026-11-01' }, OWNER)).status, 400, 'a disposal in the future');
  assert.equal((await att(tc.id, { note: 'short' }, OWNER)).status, 400);
  assert.equal((await att('RT-1', {}, OWNER)).status, 400, 'a malformed id');
  assert.equal((await att('RT-09999', {}, OWNER)).status, 404);
  // only the owner, or an operator; a person
  assert.equal((await att(tc.id, {}, VW)).status, 403, 'a viewer who is not the owner');
  assert.equal((await att(tc.id, {}, { user: 'ai:retention', role: 'admin' })).status, 403, 'an AI identity never attests');
  let r = await att(tc.id, {}, OWNER); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'attested'); assert.equal(r.json.attestation.by, 'owner.syn');
  assert.equal((await att(tc.id, {}, OWNER)).status, 409, 'already recorded');
  // acceptance: the DPO or an administrator, never the attester, never a service
  const acc = (id, who, b) => post('/pdpl/retention/tasks/' + id + '/accept', b || {}, who);
  assert.equal((await acc(tc.id, OP)).status, 403, 'an operator who is not the DPO');
  assert.equal((await acc(tc.id, OWNER)).status, 403, 'the viewer route refuses the owner');
  assert.equal((await acc(tc.id, { user: 'system:x', role: 'admin' })).status, 403);
  r = await att(tm.id, { method: 'anonymisation', reference: 'CHG-SYN-102' }, DPO); assert.equal(r.status, 200, 'the DPO may record a disposal as an operator');
  r = await acc(tm.id, DPO); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  r = await acc(tc.id, DPO, { note: 'change record checked (synthetic)' }); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'accepted'); assert.equal(r.json.baseline, 1200);
  r = await acc(tm.id, ADM); assert.equal(r.status, 200);
  assert.equal((await acc(tc.id, ADM)).status, 409, 'already accepted');
  // the next scan: Claims fell (verified), Members did not (not verified -> signal)
  COUNT.Claims = 0; COUNT.Members = 40; tick(3600000);
  await post('/pdpl/retention/scan', {});
  let v = (await get('/pdpl/retention/enforcement')).json;
  const vc = v.tasks.find((x) => x.id === tc.id), vm = v.tasks.find((x) => x.id === tm.id);
  assert.equal(vc.status, 'verified'); assert.deepEqual([vc.verification.before, vc.verification.after, vc.verification.verified], [1200, 0, true]);
  assert.equal(vm.status, 'not_verified'); assert.deepEqual([vm.verification.before, vm.verification.after], [40, 40]);
  assert.equal(v.totals.verified, 1); assert.equal(v.totals.not_verified, 1);
  let sig = X.signals(); assert.equal(sig.length, 1); assert.equal(sig[0].fp, 'pdpl:retention:unverified:' + tm.id); assert.equal(sig[0].source, 'pdpl'); assert.equal(sig[0].ref, tm.id); assert.equal(sig[0].condition, true); assert.equal(sig[0].severity, 3);
  for (const a of ['task.attest', 'task.accept', 'task.verified', 'task.not_verified']) { const x = audits('pdpl.retention.' + a); assert.ok(x.length, a); }
  const au = audits('pdpl.retention.task.accept').find((x) => x.target === tc.id); assert.equal(au.by, 'dpo.syn'); assert.equal(au.detail.attested_by, 'owner.syn');
  // re-attest after not verified; the DPO returns it (needs a note), then it is open again
  r = await att(tm.id, { reference: 'CHG-SYN-103' }, OWNER); assert.equal(r.status, 200, 'the owner of the system records it again');
  assert.equal((await post('/pdpl/retention/tasks/' + tm.id + '/return', {}, DPO)).status, 400);
  r = await post('/pdpl/retention/tasks/' + tm.id + '/return', { note: 'no change record attached (synthetic)' }, DPO); assert.equal(r.status, 200); assert.equal(r.json.status, 'open');
  assert.ok(audits('pdpl.retention.task.return').length);
  // rows past retention with no attestation after N days -> signal
  COUNT.Claims = 7; tick(3600000); await post('/pdpl/retention/scan', {});
  v = (await get('/pdpl/retention/enforcement')).json;
  const fresh = v.tasks.find((x) => x.table === 'dbo.Claims' && x.status === 'open'); assert.ok(fresh, 'newly aged rows open a new task'); assert.equal(fresh.count_at_open, 7);
  assert.equal(X.signals().filter((x) => /overdue/.test(x.fp)).length, 0, 'not yet overdue');
  tick(31 * DAY);
  sig = X.signals().filter((x) => /overdue/.test(x.fp)); assert.equal(sig.length, 2);
  assert.match(sig.find((x) => x.ref === fresh.id).title, /no disposal recorded after 31 days/); assert.match(sig[0].text, /data owner/);
  assert.ok(S);
});

test('holds: requested by one person, approved by the DPO or an administrator who is another; a held table raises no signal; expires', async (t) => {
  const { post, map, get, audits, X, tick, S } = await setup(t);
  await map({}); await post('/pdpl/retention/scan', {});
  tick(40 * DAY); assert.equal(X.signals().length, 1);
  const req = (b, who) => post('/pdpl/retention/holds', Object.assign({ map_id: 'RM-00001', reason: 'claim dispute CL-SYN-9 in court (synthetic)', until: '2027-06-30' }, b), who);
  assert.equal((await req({ until: '2026-01-01' })).status, 400, 'in the past');
  assert.equal((await req({ until: '2031-01-01' })).status, 400, 'more than 3 years');
  assert.equal((await req({ reason: 'short' })).status, 400);
  assert.equal((await req({ map_id: 'RM-00099' })).status, 404);
  assert.equal((await req({}, AI)).status, 403);
  let r = await req({}, DPO); assert.equal(r.status, 200, r.raw); const hid = r.json.id; assert.equal(r.json.status, 'requested');
  assert.equal((await req({})).status, 409, 'one hold per table at a time');
  assert.equal((await post('/pdpl/retention/holds/' + hid + '/approve', {}, DPO)).status, 403, 'four-eyes: the requester (the DPO) does not approve');
  assert.equal((await post('/pdpl/retention/holds/' + hid + '/approve', {}, OP)).status, 403, 'not the DPO, not an administrator');
  assert.equal((await post('/pdpl/retention/holds/' + hid + '/approve', {}, { user: 'svc:auto', role: 'admin' })).status, 403);
  r = await post('/pdpl/retention/holds/' + hid + '/approve', { note: 'court order seen (synthetic)' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.status, 'active'); assert.equal(r.json.approved_by, 'syed');
  assert.equal(X.signals().length, 0, 'a held table raises no signal');
  const v = (await get('/pdpl/retention/enforcement')).json; assert.equal(v.maps[0].hold.id, hid); assert.equal(v.tasks[0].hold.id, hid);
  // while held only an archive under legal hold is recorded
  r = await post('/pdpl/retention/tasks/' + v.tasks[0].id + '/attest', { method: 'deletion', date: '2026-11-20', reference: 'CHG-SYN-1', note: 'deleted while held (synthetic)' }, OWNER); assert.equal(r.status, 409);
  // expires on its own
  tick(300 * DAY); assert.equal((await get('/pdpl/retention/enforcement')).json.holds[0].status, 'expired');
  assert.equal(X.signals().length, 1);
  // reject / end
  r = await req({ until: '2028-01-01' }, OP); const h2 = r.json.id; assert.equal(r.status, 200);
  assert.equal((await post('/pdpl/retention/holds/' + h2 + '/reject', {}, DPO)).status, 400, 'a note is required');
  assert.equal((await post('/pdpl/retention/holds/' + h2 + '/reject', { note: 'no case reference (synthetic)' }, DPO)).status, 200);
  r = await req({ until: '2028-01-01' }, OP); const h3 = r.json.id;
  await post('/pdpl/retention/holds/' + h3 + '/approve', {}, DPO);
  assert.equal((await post('/pdpl/retention/holds/' + h3 + '/end', { note: 'case closed (synthetic)' }, OP)).status, 403);
  assert.equal((await post('/pdpl/retention/holds/' + h3 + '/end', { note: 'case closed (synthetic)' }, DPO)).status, 200);
  for (const a of ['hold.request', 'hold.approve', 'hold.reject', 'hold.end']) assert.ok(audits('pdpl.retention.' + a).length, a);
  // a PDPL legal hold covering the system suspends the table's task too
  S.collection('pdpl_records').put({ id: 'PD-LEGAL_HOLD-001', kind: 'legal_hold', status: 'active', ref: 'CASE-SYN-1', reason: 'litigation', systems: ['claims-sql'] });
  assert.equal(X.signals().length, 0); assert.equal((await get('/pdpl/retention/enforcement')).json.maps[0].legal_hold.id, 'PD-LEGAL_HOLD-001');
});

test('settings and the monthly job: the DPO or an administrator; the scan runs when due, as the system, through guardOf', async (t) => {
  const { post, map, tick, X, audits, calls } = await setup(t);
  assert.equal((await post('/pdpl/retention/settings', { every_days: 3 }, DPO)).status, 400);
  assert.equal((await post('/pdpl/retention/settings', { enabled: 'yes' }, DPO)).status, 400);
  let r = await post('/pdpl/retention/settings', { every_days: 14, attest_days: 10 }, DPO); assert.equal(r.status, 200); assert.equal(r.json.every_days, 14);
  assert.equal(audits('pdpl.retention.settings')[0].detail.previous.every_days, 30);
  await X.tick(); assert.equal(calls.length, 0, 'nothing mapped: nothing to scan');
  await map({});
  await X.tick(); assert.equal(calls.length, 1, 'never scanned: due');
  await X.tick(); assert.equal(calls.length, 1, 'not due again');
  tick(14 * DAY); await X.tick(); assert.equal(calls.length, 2);
  assert.equal(audits('pdpl.retention.scan')[0].by, 'system:pdpl-retention');
  r = await post('/pdpl/retention/settings', { enabled: false }, ADM); assert.equal(r.status, 200);
  tick(30 * DAY); await X.tick(); assert.equal(calls.length, 2, 'switched off');
  assert.equal(typeof X.start(), 'function', 'noTimer: start() returns a stop function and arms nothing');
  const src = fs.readFileSync(path.join(__dirname, '..', 'engine', 'pdpl-retention.js'), 'utf8');
  assert.match(src, /guardOf\(app, 'pdpl\.retention\.scan', tick\)/);
  // retire: open tasks close
  await post('/pdpl/retention/settings', { enabled: true }, ADM); await post('/pdpl/retention/scan', {});
  assert.equal((await post('/pdpl/retention/maps/RM-00001/retire', { reason: 'no' })).status, 400);
  r = await post('/pdpl/retention/maps/RM-00001/retire', { reason: 'table replaced by ClaimsArchive (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'retired');
  assert.equal(audits('pdpl.retention.map.retire')[0].detail.tasks_closed.length, 1);
  assert.equal((await post('/pdpl/retention/maps/RM-00001/retire', { reason: 'again (synthetic)' })).status, 409);
});

test('the vault path: the read-only login goes to the helper (stdin), never into the store or the audit', async (t) => {
  const seen = [];
  const { e, post, map, S } = await setup(t, { runQuery: null, runHelper: async (req) => { seen.push(req); return { ok: true, engine: 'mssql', count: 5, oldest: '2014-01-01' }; } });
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { open: (id) => { if (id !== 'c2') throw new Error('no such credential'); return { target: { database: 'claims' }, secret: { username: 'ro_syn', password: 'Synthetic-Pass-77' }, release() { seen.push('released'); } }; } } });
  await map({}); await post('/pdpl/retention/scan', {});
  assert.equal(seen[0].username, 'ro_syn'); assert.equal(seen[0].password, 'Synthetic-Pass-77'); assert.equal(seen[0].database, 'claims'); assert.equal(seen[0].op, 'retention_count'); assert.equal(seen[1], 'released');
  const dir = S.dir; for (const f of fs.readdirSync(dir)) { const p = path.join(dir, f); if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, 'utf8').includes('Synthetic-Pass-77'), 'password in ' + f); }
  assert.ok(!JSON.stringify(S.auditTail(200)).includes('Synthetic-Pass-77'));
});

// ---- the Python count against a fake connection: what is sent to the database
const FAKE = (lib) => `
import json, sys, importlib.machinery, importlib.util
spec = importlib.util.spec_from_loader("invh", importlib.machinery.SourceFileLoader("invh", sys.argv[1]))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
exec(${JSON.stringify(lib)})
LOG = []; ST = {"unsafe": False, "dtype": "datetime2", "deny": False, "missing": False}
class Cur:
    def __init__(s): s.res = []
    def execute(s, q, p=None):
        LOG.append({"q": q, "p": [str(x) for x in (p or [])]}); ql = q.lower()
        if "rolsuper" in ql or "is_srvrolemember" in ql: s.res = [(1 if ST["unsafe"] else 0, 0)]
        elif "information_schema.columns" in ql or "all_tab_columns" in ql: s.res = [] if ST["missing"] else [(ST["dtype"],)]
        elif ql.startswith("select count(*)"):
            if ST["deny"]: raise Exception("SELECT permission was denied on the object 'Claims'")
            import datetime; s.res = [(1234, datetime.datetime(2011, 2, 3, 10, 0))]
        else: s.res = []
    def fetchone(s): return s.res[0] if s.res else None
    def fetchall(s): return s.res
class Conn:
    def cursor(s): return Cur()
    def rollback(s): LOG.append({"rollback": 1})
    def close(s): LOG.append({"close": 1})
m.connect_db = lambda r: Conn()
REQ = {"engine": "mssql", "host": "10.8.0.52", "port": 1433, "username": "ro_syn", "password": "Synthetic-Pass-1", "schema": "dbo", "table": "Claims", "column": "ClosedDate", "cutoff": "2016-10-20"}
def run(**kw):
    del LOG[:]; r = dict(REQ); r.update(kw.pop("req", {})); ST.update(kw); out = retention_count(m, r); ST.update({"unsafe": False, "dtype": "datetime2", "deny": False, "missing": False}); return {"r": out, "log": list(LOG)}
print(json.dumps({"ok": run(), "pg": run(req={"engine": "postgres", "schema": "crm", "table": "claims", "column": "closed_on"}, dtype="date"), "unsafe": run(unsafe=True), "notdate": run(dtype="varchar"), "missing": run(missing=True), "deny": run(deny=True),
    "hostile": run(req={"table": 'Claims"; delete from dbo.Claims; --'}), "badcut": run(req={"cutoff": "2016-10-20' or 1=1"}), "mysql": run(req={"engine": "mysql"})}))
`;

test('Python count: privileges checked first, the column checked in the dictionary, then ONE count with the date bound; nothing else is sent', () => {
  const p = spawnSync(PY, ['-I', '-c', FAKE(R.COUNT_PY_LIB), HELPER], { encoding: 'utf8' });
  assert.equal(p.status, 0, p.stderr);
  const r = JSON.parse(p.stdout);
  const q = (x) => x.log.filter((l) => l.q);
  assert.deepEqual(r.ok.r, { ok: true, engine: 'mssql', count: 1234, oldest: '2011-02-03', data_type: 'datetime2' });
  assert.match(q(r.ok)[0].q, /is_srvrolemember/, 'read-only login checked before anything is read');
  assert.match(q(r.ok)[1].q, /^select data_type from information_schema\.columns where table_schema = %s and table_name = %s and column_name = %s$/);
  assert.deepEqual(q(r.ok)[1].p, ['dbo', 'Claims', 'ClosedDate'], 'the names are parameters in the dictionary lookup');
  assert.equal(q(r.ok)[2].q, 'select count(*), min([ClosedDate]) from [dbo].[Claims] where [ClosedDate] < %s');
  assert.deepEqual(q(r.ok)[2].p, ['2016-10-20'], 'the cut-off is a bound parameter');
  assert.equal(q(r.ok).length, 3, 'nothing else');
  assert.equal(r.ok.log[r.ok.log.length - 1].close, 1);
  for (const k of Object.keys(r)) for (const l of q(r[k])) assert.match(l.q.trim(), /^(select |set (session characteristics as transaction read only|statement_timeout))/i, k + ' only reads: ' + l.q.slice(0, 60));
  for (const k of Object.keys(r)) for (const l of q(r[k]).filter((x) => /^select/i.test(x.q) && !/rolsuper|is_srvrolemember|data_type/.test(x.q))) assert.match(l.q, /^select count\(\*\), min\(/, k + ': only the count reaches a table');
  assert.ok(q(r.pg).some((l) => /set session characteristics as transaction read only/.test(l.q)), 'PostgreSQL: a read-only transaction');
  assert.equal(q(r.pg).find((l) => /^select count\(\*\), min/.test(l.q)).q, 'select count(*), min("closed_on") from "crm"."claims" where "closed_on" < %s');
  assert.equal(r.unsafe.r.error_class, 'unsafe'); assert.equal(q(r.unsafe).length, 1, 'nothing read after the refusal');
  assert.equal(r.notdate.r.error_class, 'not_date'); assert.ok(!q(r.notdate).some((l) => /^select count\(\*\), min/.test(l.q)));
  assert.equal(r.missing.r.error_class, 'no_column'); assert.ok(!q(r.missing).some((l) => /^select count\(\*\), min/.test(l.q)));
  assert.equal(r.deny.r.error_class, 'denied'); assert.equal(r.deny.r.error, 'SELECT permission was denied'); assert.equal(r.deny.r.count, undefined);
  assert.equal(r.hostile.r.error_class, 'name'); assert.equal(r.hostile.log.length, 0, 'a hostile name never reaches a connection');
  assert.equal(r.badcut.r.error_class, 'config'); assert.equal(r.badcut.log.length, 0);
  assert.equal(r.mysql.r.error_class, 'config');
  assert.ok(!p.stdout.includes('Synthetic-Pass-1'), 'the password does not come back');
});

test('real PostgreSQL (skipped when not installed): the count through the real helper, a read-only login, a login that can write refused', async (t) => {
  const chk = spawnSync(PY, ['-I', '-c', 'import pg8000'], { encoding: 'utf8' });
  if (chk.status !== 0) { t.skip('pg8000 not installed for ' + PY); return; }
  const pg = startPg(); if (pg.skip) { t.skip(pg.skip); return; }
  t.after(() => pg.stop());
  const sql = (q) => { const r = spawnSync('psql', ['-h', '127.0.0.1', '-p', String(pg.port), '-U', 'zybsu', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-q', '-c', q], { encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stderr); };
  for (const q of ['create schema claims', 'create table claims.closed (id int, closed_on date, holder text)',
    "insert into claims.closed select g, date '2010-01-01' + g, 'SYNTHETIC' from generate_series(1, 3000) g",   // 2010-01-02 .. 2018-03-20
    'create table claims.noread (id int, closed_on date)',
    "create role zyb_ro login password 'Ro-Synthetic-1'", 'grant usage on schema claims to zyb_ro', 'grant select on claims.closed to zyb_ro',
    "create role zyb_rw login password 'Rw-Synthetic-1'", 'grant usage on schema claims to zyb_rw', 'grant select, delete on claims.closed to zyb_rw']) sql(q);
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const S = e.app.store;
  S.collection('pdpl_records').put({ id: 'PD-RETENTION-001', kind: 'retention', status: 'active', name: 'Closed claims (synthetic)', period_months: 120, trigger: 'claim_closed', action: 'destroy' });
  const key = 'postgres|127.0.0.1|' + pg.port;
  S.collection('pdpl_discovery').put({ id: key, db: key, engine: 'postgres', label: 'PG-SYN', host: '127.0.0.1', port: pg.port, cred_id: 'ro', columns: [
    { owner: 'claims', table: 'closed', column: 'holder', type: 'text', kind: 'name', category: 'identity' }, { owner: 'claims', table: 'noread', column: 'holder', type: 'text', kind: 'name', category: 'identity' }] });
  let login = 'ro';
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { open: () => ({ target: { database: 'postgres' }, secret: login === 'ro' ? { username: 'zyb_ro', password: 'Ro-Synthetic-1' } : { username: 'zyb_rw', password: 'Rw-Synthetic-1' }, release() {} }) } });
  const X = R.registerPdplRetention(e.app.srv, e.app, R.createPdplRetention(e.app, { now: () => Date.parse('2026-10-20T08:00:00Z'), noTimer: true, python: PY }));
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  assert.equal((await post('/pdpl/retention/maps', { rule_id: 'PD-RETENTION-001', db: key, schema: 'claims', table: 'closed', date_column: 'closed_on' })).status, 200);
  assert.equal((await post('/pdpl/retention/maps', { rule_id: 'PD-RETENTION-001', db: key, schema: 'claims', table: 'noread', date_column: 'closed_on' })).status, 200);
  assert.equal((await post('/pdpl/retention/maps', { rule_id: 'PD-RETENTION-001', db: key, schema: 'claims', table: 'closed', date_column: 'holder' }, DPO)).status, 409, 'same table and rule');
  const r = await post('/pdpl/retention/scan', {}); assert.equal(r.status, 200, r.raw);
  const v = X.view(OP), closed = v.maps.find((m) => m.table === 'closed').last, noread = v.maps.find((m) => m.table === 'noread').last;
  // rows with closed_on < 2016-10-20: 2010-01-02 + (g-1) days < 2016-10-20  ->  g <= 2483
  assert.equal(closed.ok, true, JSON.stringify(closed)); assert.equal(closed.count, 2483); assert.equal(closed.oldest, '2010-01-02');
  assert.equal(noread.ok, false); assert.equal(noread.count, null); assert.ok(['no_column', 'denied'].includes(noread.error_class), noread.error_class);
  assert.equal(Number(spawnSync('psql', ['-h', '127.0.0.1', '-p', String(pg.port), '-U', 'zybsu', '-d', 'postgres', '-tAc', 'select count(*) from claims.closed'], { encoding: 'utf8' }).stdout.trim()), 3000, 'nothing was deleted');
  login = 'rw'; await post('/pdpl/retention/scan', {});
  const rw = X.view(OP).maps.find((m) => m.table === 'closed').last; assert.equal(rw.ok, false); assert.equal(rw.error_class, 'unsafe'); assert.match(rw.error, /can write/);
});
