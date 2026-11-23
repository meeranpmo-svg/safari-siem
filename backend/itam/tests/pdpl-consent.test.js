// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Consent ledger (engine/pdpl-consent.js) and retention schedule (engine/pdpl.js) of the AI PDPL Consultant:
//  - consent keys (admin, shown once, hash only, revocable); grants need the current notice version and explicit:true
//    for an explicit purpose; a withdrawal is always accepted; check before processing; identifiers never stored in
//    clear (one-way reference); append-only hash chain detects an edit; counts feed P-05 / P-20; stale-version finding
//  - retention rules, destruction plan → approve (DPO / admin, not the planner) → done with evidence; refusals; P-12
// Roles, validation and audit records throughout. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { CHANNELS } = require('../engine/pdpl-consent');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM);
  const ropa = (await post('/pdpl/records', { kind: 'ropa', name: 'Marketing (synthetic)', purpose: 'offers', legal_basis: 'consent', data_categories: ['contact'], owner: 'Marketing', retention_months: 24, systems: ['CRM-SYN'] })).json;
  return { e, post, ropa };
}
const agent = (e, p, bearer, body, method = 'POST') => e.req(method, '/agent' + p, { body, bearer, user: '', role: '' });

test('consent ledger: keys, grant / withdraw / check, version and explicit rules, one-way reference, integrity', async (t) => {
  const { e, post, ropa } = await setup(t);
  assert.ok(CHANNELS.includes('web'));
  assert.equal((await post('/pdpl/records', { kind: 'consent_purpose', title: 'Marketing offers' })).status, 403, 'purposes are set by an administrator');
  const pur = (await post('/pdpl/records', { kind: 'consent_purpose', title: 'Marketing offers', ropa_id: ropa.id, marketing: true, explicit: true, version: 1 }, ADM)).json;
  assert.match(pur.id, /^PD-CONSENT_PURPOSE-\d{3}$/);
  // keys
  assert.equal((await post('/pdpl/consent/keys', { name: 'Portal' })).status, 403);
  const k = (await post('/pdpl/consent/keys', { name: 'Customer portal (synthetic)', purposes: [pur.id] }, ADM)).json;
  assert.match(k.key, /^ck_[0-9a-f]{48}$/); assert.match(k.note, /once/);
  const list = (await e.req('GET', '/pdpl/consent', OP)).json;
  assert.ok(!JSON.stringify(list).includes(k.key), 'the key is never shown again'); assert.equal(list.keys[0].name, 'Customer portal (synthetic)');
  // machine API
  assert.equal((await agent(e, '/consent/events', 'ck_' + '0'.repeat(48), { subject: '1012345678', purpose: pur.id, action: 'grant', channel: 'web', version: 1, explicit: true })).status, 401);
  let r = await agent(e, '/consent/events', k.key, { subject: '1012345678', purpose: pur.id, action: 'grant', channel: 'web', version: 1 });
  assert.equal(r.status, 400); assert.match(r.json.error, /explicit/);
  r = await agent(e, '/consent/events', k.key, { subject: '1012345678', purpose: pur.id, action: 'grant', channel: 'web', explicit: true });
  assert.equal(r.status, 409); assert.match(r.json.error, /notice version 1/);
  r = await agent(e, '/consent/events', k.key, { subject: '1012345678', purpose: pur.id, action: 'grant', channel: 'fax', version: 1, explicit: true }); assert.equal(r.status, 400); assert.match(r.json.error, /channel/);
  r = await agent(e, '/consent/events', k.key, { subject: '<script>', purpose: pur.id, action: 'grant', channel: 'web', version: 1, explicit: true }); assert.equal(r.status, 400); assert.match(r.json.error, /subject/);
  r = await agent(e, '/consent/events', k.key, { subject: '1012345678', purpose: pur.id, action: 'grant', channel: 'web', version: 1, explicit: true, evidence_ref: 'FORM-SYN-1' });
  assert.equal(r.status, 200); assert.equal(r.json.consented, true); assert.match(r.json.receipt, /^CE-1$/);
  await agent(e, '/consent/events', k.key, { subject: '1098765432', purpose: pur.id, action: 'grant', channel: 'app', version: 1, explicit: true });
  let c = await agent(e, '/consent/check?subject=1012345678&purpose=' + pur.id, k.key, undefined, 'GET');
  assert.equal(c.json.consented, true);
  // withdrawal: any channel, always accepted
  r = await agent(e, '/consent/events', k.key, { subject: ' 1012345678 ', purpose: pur.id, action: 'withdraw', channel: 'call_centre' });
  assert.equal(r.status, 200); assert.equal(r.json.consented, false);
  c = await agent(e, '/consent/check?subject=1012345678&purpose=' + pur.id, k.key, undefined, 'GET');
  assert.equal(c.json.consented, false); assert.equal(c.json.why, 'withdrawn');
  // the identifier never reaches the disk in clear
  const dir = e.app.store.dir, files = fs.readdirSync(dir);
  for (const f of files) { const p = path.join(dir, f); if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, 'utf8').includes('1012345678'), 'identifier found in ' + f); }
  assert.ok(files.some((f) => /^consent-\d{6}\.jsonl$/.test(f)));
  // operator lookup for a data subject request (audited), viewer refused
  assert.equal((await e.req('GET', '/pdpl/consent/lookup?subject=1012345678', { user: 'v', role: 'viewer' })).status, 403);
  const lk = (await e.req('GET', '/pdpl/consent/lookup?subject=1012345678', OP)).json;
  assert.deepEqual(lk.history.map((h) => h.action), ['grant', 'withdraw']); assert.equal(lk.current[0].status, 'withdrawn'); assert.equal(lk.history[0].evidence_ref, 'FORM-SYN-1');
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'pdpl.consent.lookup' && !JSON.stringify(a).includes('1012345678')));
  // counts and P-05 / P-20
  let v = (await e.req('GET', '/pdpl/consent', OP)).json;
  const pv = v.purposes[0]; assert.deepEqual([pv.active, pv.withdrawn, pv.stale_version], [1, 1, 0]); assert.equal(v.chain.ok, true); assert.equal(v.chain.length, 3);
  const pd = (await e.req('GET', '/pdpl', OP)).json;
  assert.notEqual(pd.requirements.find((x) => x.id === 'P-20').result, 'non_compliant');
  assert.ok(!pd.findings.some((f) => /:records$/.test(f.key)), 'the ledger counts as consent records for P-05');
  // a new notice version: the remaining consent is stale; a grant under v1 is refused
  await post('/pdpl/records', { kind: 'consent_purpose', id: pur.id, version: 2 }, ADM);
  v = (await e.req('GET', '/pdpl/consent', OP)).json;
  assert.equal(v.purposes[0].stale_version, 1); assert.ok(v.findings.some((f) => /:stale$/.test(f.key)));
  c = await agent(e, '/consent/check?subject=1098765432&purpose=' + pur.id, k.key, undefined, 'GET'); assert.equal(c.json.consented, false); assert.match(c.json.why, /older notice/);
  // revoke
  await post('/pdpl/consent/keys/' + k.id + '/revoke', {}, ADM);
  assert.equal((await agent(e, '/consent/check?subject=1&purpose=' + pur.id, k.key, undefined, 'GET')).status, 401);
  // tamper: edit a line → integrity fails, critical finding
  const lf = path.join(dir, files.find((f) => /^consent-/.test(f))), lines = fs.readFileSync(lf, 'utf8').split('\n');
  lines[2] = lines[2].replace('"withdraw"', '"grant"'); fs.writeFileSync(lf, lines.join('\n'));
  v = (await e.req('GET', '/pdpl/consent', OP)).json;
  assert.equal(v.chain.ok, false); assert.equal(v.findings.find((f) => /consent:chain$/.test(f.key)).severity, 'critical');
  const acts = e.app.store.auditTail(60).map((a) => a.action);
  for (const x of ['pdpl.consent.key.issue', 'pdpl.consent.key.revoke']) assert.ok(acts.includes(x), x);
});

test('retention schedule: rule, destruction plan → approve (not the planner) → done with evidence; P-12', async (t) => {
  const { e, post, ropa } = await setup(t);
  let pd = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(pd.findings.some((f) => f.key === 'P-12:retention:' + ropa.id + ':schedule'), 'an activity with a period but no rule is a gap');
  let r = await post('/pdpl/records', { kind: 'retention', name: 'Marketing contacts' }); assert.equal(r.status, 400); assert.match(r.json.error, /period_months/);
  r = await post('/pdpl/records', { kind: 'destruction', retention_id: 'PD-RETENTION-001' }); assert.equal(r.status, 400); assert.match(r.json.error, /workflow/);
  const rule = (await post('/pdpl/records', { kind: 'retention', name: 'Marketing contacts', ropa_id: ropa.id, systems: ['CRM-SYN'], period_months: 24, trigger: 'last_contact', action: 'anonymise', legal_ref: 'PDPL Art. 18', review_months: 6 })).json;
  pd = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(!pd.findings.some((f) => /^P-12:retention:.*:schedule$/.test(f.key)));
  // plan: validation, not inside the retention period
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CRM-SYN', cutoff: '2026-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /inside the retention period/);
  r = await post('/pdpl/destruction', { retention_id: rule.id, system: 'CRM-SYN', cutoff: 'last year' }); assert.equal(r.status, 400);
  assert.equal((await post('/pdpl/destruction', { retention_id: rule.id, system: 'CRM-SYN', cutoff: '2024-06-30' }, { user: 'v', role: 'viewer' })).status, 403);
  const run = (await post('/pdpl/destruction', { retention_id: rule.id, system: 'CRM-SYN', cutoff: '2024-06-30', note: 'contacts with no activity since mid-2024' })).json;
  assert.equal(run.status, 'planned'); assert.match(run.id, /^PD-DESTRUCTION-\d{3}$/);
  // done before approval refused; approval: not an ordinary operator, not the planner
  r = await post('/pdpl/destruction/' + run.id + '/done', { count: 10, method: 'anonymised', evidence: 'x', executed_at: '2026-10-20' }); assert.equal(r.status, 409);
  r = await post('/pdpl/destruction/' + run.id + '/approve', {}, { user: 'other.syn', role: 'operator' }); assert.equal(r.status, 403); assert.match(r.json.error, /DPO/);
  r = await post('/pdpl/destruction/' + run.id + '/approve', {}, { user: 'nora.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  r = await post('/pdpl/destruction/' + run.id + '/approve', {}, { user: 'system:bot', role: 'admin' }); assert.equal(r.status, 403);
  r = await post('/pdpl/destruction/' + run.id + '/approve', {}, DPO); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
  r = await post('/pdpl/destruction/' + run.id + '/done', { count: 1840, method: 'anonymised', evidence: 'CHG-SYN-77 / script log', executed_at: '2026-10-21' }); assert.equal(r.status, 400, 'not in the future');
  r = await post('/pdpl/destruction/' + run.id + '/done', { count: 1840, method: 'shredded', evidence: 'x', executed_at: '2026-10-20' }); assert.equal(r.status, 400);
  r = await post('/pdpl/destruction/' + run.id + '/done', { count: 1840, method: 'anonymised', evidence: 'CHG-SYN-77 / script log', executed_at: '2026-10-20T07:00Z' });
  assert.equal(r.status, 400, 'before the approval');
  r = await post('/pdpl/destruction/' + run.id + '/done', { count: 1840, method: 'anonymised', evidence: 'CHG-SYN-77 / script log', executed_at: new Date(clock).toISOString().slice(0, 16) });
  assert.equal(r.status, 200); assert.equal(r.json.status, 'executed');
  let rv = (await e.req('GET', '/pdpl/retention', OP)).json;
  assert.equal(rv.rules[0].due.overdue, false); assert.equal(rv.rules[0].runs[0].count, 1840); assert.match(rv.note, /never deletes/);
  // reject needs a note
  const run2 = (await post('/pdpl/destruction', { retention_id: rule.id, system: 'CRM-SYN', cutoff: '2024-09-30' })).json;
  assert.equal((await post('/pdpl/destruction/' + run2.id + '/reject', {}, DPO)).status, 400);
  assert.equal((await post('/pdpl/destruction/' + run2.id + '/reject', { note: 'legal hold on these contacts' }, DPO)).json.status, 'rejected');
  // 7 months later nothing new: the rule is overdue (review every 6 months)
  clock += 210 * 86400000;
  rv = (await e.req('GET', '/pdpl/retention', OP)).json; assert.equal(rv.rules[0].due.overdue, true); assert.equal(rv.overdue, 1);
  pd = (await e.req('GET', '/pdpl', OP)).json; assert.ok(pd.findings.some((f) => f.key === 'P-12:retention:' + rule.id + ':overdue'));
  clock -= 210 * 86400000;
  const acts = e.app.store.auditTail(60).map((a) => a.action);
  for (const x of ['pdpl.destruction.plan', 'pdpl.destruction.approve', 'pdpl.destruction.done', 'pdpl.destruction.reject']) assert.ok(acts.includes(x), x);
});

test('consent state lives in SQLite: not in the store; a failed database write is replayed from the journal; old state migrated', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { createConsent } = require('../engine/pdpl-consent');
  const { createPyEngine } = require('../engine/pyengine');
  const real = createPyEngine({ python: PY, timeoutMs: 30000 });
  let failApply = 0;
  const py = { call: (op, b) => (op === 'consent.apply' && failApply-- > 0 ? Promise.resolve({ ok: false, error_class: 'protocol', error: 'synthetic failure' }) : real.call(op, b)) };
  const purposes = [{ id: 'PD-CONSENT_PURPOSE-001', title: 'Offers', version: 1, explicit: false }];
  const dir = e.app.store.dir;
  // an install from before the database: old state files and counter rows in the store, journal already written
  fs.writeFileSync(path.join(dir, 'pdpl_consent_state.jsonl'), JSON.stringify({ op: 'put', o: { id: 'x|PD-CONSENT_PURPOSE-001', s: 'g', v: 1, t: 1 } }) + '\n');
  e.app.store.collection('pdpl_consent_meta').put({ id: 'c:PD-CONSENT_PURPOSE-001', events: 99 });
  const C1 = createConsent(e.app, { now, purposes: () => purposes, py });
  const k = C1.issueKey({ name: 'Portal (synthetic)' }, { user: 'syed', role: 'admin' });
  const key = C1.authenticate(k.key);
  failApply = 1;   // the database refuses the first write: the journal still holds the event
  const r1 = await C1.event(key, { subject: 'CUST-0001', purpose: purposes[0].id, action: 'grant', channel: 'web', version: 1 });
  assert.equal(r1.receipt, 'CE-1');
  await C1.event(key, { subject: 'CUST-0002', purpose: purposes[0].id, action: 'grant', channel: 'app', version: 1 });
  await C1.event(key, { subject: 'CUST-0001', purpose: purposes[0].id, action: 'withdraw', channel: 'call_centre' });
  const st = (await C1.stats())[purposes[0].id];
  assert.deepEqual([st.active, st.withdrawn, st.grants, st.withdrawals, st.events], [1, 1, 2, 1, 3], 'the failed write was replayed: ' + JSON.stringify(st));
  assert.equal((await C1.check(key, { subject: 'CUST-0001', purpose: purposes[0].id })).why, 'withdrawn');
  // nothing about the people in the store: the state collection is not used and the old files were renamed
  assert.ok(!fs.existsSync(path.join(dir, 'pdpl_consent_state.jsonl')), 'old state file renamed');
  assert.ok(fs.readdirSync(dir).some((f) => /^pdpl_consent_state\.jsonl\.migrated-/.test(f)));
  assert.equal(e.app.store.collection('pdpl_consent_meta').get('c:' + purposes[0].id), null, 'old counter rows removed');
  assert.ok(fs.existsSync(C1.dbPath)); assert.equal((fs.statSync(C1.dbPath).mode & 0o777).toString(8), '600');
  // a fresh engine (new process) on an EMPTY database rebuilds everything from the journal
  fs.rmSync(C1.dbPath); for (const f of fs.readdirSync(dir).filter((x) => /^pdpl-consent\.sqlite-/.test(x))) fs.rmSync(path.join(dir, f));
  const C2 = createConsent(e.app, { now, purposes: () => purposes, py: createPyEngine({ python: PY, timeoutMs: 30000, resident: false }) });
  const s2 = (await C2.stats())[purposes[0].id];
  assert.deepEqual([s2.active, s2.withdrawn, s2.events], [1, 1, 3], 'rebuilt from the journal');
  assert.equal((await C2.lookup('CUST-0002', { user: 'nora.syn', role: 'operator' })).current[0].status, 'given');
});

test('consent_db.py: replaying an applied sequence changes nothing', () => {
  const { spawnSync } = require('node:child_process'), os = require('node:os');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-')), db = path.join(d, 'c.sqlite');
  const call = (op, b) => JSON.parse(spawnSync(PY, ['-I', path.join(__dirname, '..', 'pyengine', 'run.py')], { input: JSON.stringify(Object.assign({ op, db }, b)), encoding: 'utf8' }).stdout);
  const ev = [{ seq: 1, t: Date.parse('2026-10-01T00:00:00Z'), subject_ref: 'a'.repeat(40), purpose: 'P1', action: 'grant', version: 1, channel: 'web' }, { seq: 2, t: Date.parse('2026-10-02T00:00:00Z'), subject_ref: 'a'.repeat(40), purpose: 'P1', action: 'withdraw', version: 1, channel: 'web' }];
  assert.deepEqual(call('consent.apply', { events: ev }).applied, 2);
  assert.deepEqual(call('consent.apply', { events: ev }).applied, 0, 'idempotent');
  const s = call('consent.stats', { purposes: { P1: 1 }, since_day: '2026-09-25' }).stats.P1;
  assert.deepEqual([s.active, s.withdrawn, s.events, s.events_30d], [0, 1, 2, 2]);
  assert.equal(call('consent.apply', { db: path.join(d, 'x.txt'), events: [] }).ok, false, 'only a .sqlite path');
  fs.rmSync(d, { recursive: true, force: true });
});
