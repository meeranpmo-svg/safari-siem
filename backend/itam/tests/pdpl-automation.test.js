// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// AI PDPL Consultant automation (engine/pdpl.js, pyengine/pdpl_rules.py, inv-helper op oracle_pii_scan):
//  - personal-data discovery: read-only dictionary scan, values tested inside the helper and only COUNTS returned, an
//    over-privileged login refused; findings against the records of processing; "adopt" pre-fills an activity
//  - breach workflow: a SIEM incident becomes a breach record with the 72-hour clock; SDAIA and data-subject drafts
//  - DPIA wizard: scoring, refusal of unanswered questions, DPO-only four-eyes signature closing P-07
// Roles, validation and audit records throughout. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const HELPER = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
const FAKE = `
import json, os
LOG = os.environ["FAKE_LOG"]
def _log(x):
    with open(LOG, "a") as f: f.write(json.dumps(x) + "\\n")
COLS = [("CLAIMS", "INSURED", "NATIONAL_ID", "VARCHAR2", 120000, None), ("CLAIMS", "INSURED", "MOBILE_NO", "VARCHAR2", 120000, None),
        ("CLAIMS", "INSURED", "REMARKS", "VARCHAR2", 120000, None), ("CLAIMS", "CLAIM", "DIAG_CODE", "VARCHAR2", 900000, "ICD-10 diagnosis of the claim"),
        ("CLAIMS", "CLAIM", "AMOUNT", "NUMBER", 900000, None), ("HR", "EMP", "IBAN", "VARCHAR2", 300, None), ("HR", "EMP", "EMAIL", "VARCHAR2", 300, None)]
SAMPLES = {"NATIONAL_ID": ["1012345678", "1098765432", "1055555555"], "MOBILE_NO": ["0551234567", "+966501234567", "n/a"], "EMAIL": ["not an email", "x", "y"]}
class Cur:
    def __init__(s, c): s.c = c; s.res = []
    def execute(s, q, *a):
        _log({"sql": q})
        ql = q.lower()
        if "session_privs" in ql: s.res = [(p,) for p in json.loads(os.environ.get("FAKE_PRIVS", '["CREATE SESSION", "SELECT ANY DICTIONARY"]'))]
        elif "oracle_maintained" in ql: s.res = [("SYS",)]
        elif "dba_tab_columns" in ql: s.res = COLS
        elif ql.startswith('select "'):
            col = q.split('"')[1]
            if '"HR"' in q and col == "IBAN": raise Exception("ORA-00942: table or view does not exist")
            s.res = [(v,) for v in SAMPLES.get(col, [])]
        else: s.res = []
    def fetchall(s): return s.res
class Conn:
    call_timeout = 0; module = None; action = None; client_identifier = None
    def cursor(s): return Cur(s)
    def rollback(s): _log({"rollback": True})
    def close(s): _log({"close": True})
def makedsn(h, p, service_name=None): return "%s:%s/%s" % (h, p, service_name)
def connect(**k): return Conn()
`;
function scan(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'piifake-')), log = path.join(dir, 'log.jsonl');
  fs.writeFileSync(path.join(dir, 'oracledb.py'), FAKE); fs.writeFileSync(log, '');
  const r = spawnSync(PY, [HELPER], { input: JSON.stringify({ op: 'oracle_pii_scan', host: '10.0.0.5', port: 1521, username: 'monitor', password: 'pw', service: 'CORE' }), env: Object.assign({}, process.env, { PYTHONPATH: dir, FAKE_LOG: log }, env), encoding: 'utf8' });
  const sql = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((c) => c.sql).map((c) => c.sql);
  fs.rmSync(dir, { recursive: true, force: true });
  return { out: JSON.parse(r.stdout || '{}'), raw: r.stdout, sql };
}

test('helper: dictionary scan, values tested inside, only counts out; over-privileged login refused', () => {
  const { out, raw, sql } = scan();
  assert.equal(out.ok, true, raw);
  assert.match(sql[0], /session_privs/, 'privileges checked first');
  for (const q of sql) assert.match(q.trim(), /^(select|set transaction read only)/i, q);
  const by = (c) => out.columns.find((x) => x.column === c);
  assert.deepEqual(out.columns.map((c) => c.column).sort(), ['DIAG_CODE', 'EMAIL', 'IBAN', 'MOBILE_NO', 'NATIONAL_ID'], 'REMARKS / AMOUNT are not personal-data names');
  assert.deepEqual([by('NATIONAL_ID').category, by('NATIONAL_ID').matched, by('NATIONAL_ID').sampled, by('NATIONAL_ID').confirmed], ['identity', 3, 3, true]);
  assert.deepEqual([by('MOBILE_NO').matched, by('MOBILE_NO').confirmed], [2, true]);
  assert.equal(by('EMAIL').confirmed, false, 'values that do not look like e-mail: not confirmed');
  assert.equal(by('DIAG_CODE').category, 'health'); assert.equal(by('DIAG_CODE').by, 'comment');
  assert.equal(by('IBAN').confirmed, null, 'no read access: not confirmed, never guessed'); assert.equal(out.probe_denied, 1);
  for (const v of ['1012345678', '0551234567', '+966501234567', 'not an email']) assert.ok(!raw.includes(v), 'value left the helper: ' + v);
  const bad = scan({ FAKE_PRIVS: '["CREATE SESSION","SELECT ANY TABLE"]' });
  assert.equal(bad.out.ok, false); assert.equal(bad.out.error_class, 'unsafe'); assert.equal(bad.sql.length, 1, 'nothing runs after the refusal');
});

let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.addons = e.app.addons || {};
  const out = scan().out;
  e.app.addons.dbHealth = { targets: () => ({ list: [{ key: 'reg:core', ip: '10.0.0.5', host: 'CORE-DB', service: 'CORE', port: 1521, cred_id: 'c1' }] }), piiScan: async () => out };
  e.app.discovery = Object.assign(e.app.discovery || {}, { siem: { call: async (m, p, who) => (p === '/cases/CASE-000042' ? { status: 200, json: { id: 'CASE-000042', title: 'Mass export of insured records', description: 'synthetic', severity: 'high', created: clock - 3 * 3600000, who } } : { status: 404, json: { error: 'case not found' } }) } });
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  return e;
}
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' };
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));

test('discovery: admin runs it, findings against the records of processing, adopt pre-fills an activity', async (t) => {
  const e = await setup(t);
  assert.equal((await post(e, '/pdpl/discovery/run', {}, OP)).status, 403, 'an operator cannot start a scan');
  const r = await post(e, '/pdpl/discovery/run', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.databases[0].columns, 5);
  assert.equal((await e.req('GET', '/pdpl/discovery', { role: 'viewer' })).status, 403);
  let d = (await e.req('GET', '/pdpl/discovery', OP)).json;
  assert.match(d.note, /No personal data value is stored/);
  const db = d.databases[0]; assert.deepEqual(db.categories.map((c) => c.category), ['contact', 'financial', 'health', 'identity'], 'e-mail not confirmed: contact comes from the mobile column only');
  assert.deepEqual(d.findings.map((f) => f.key.split(':').pop()).sort(), ['dpia', 'unmapped']);
  assert.equal(d.findings.find((f) => /unmapped/.test(f.key)).severity, 'high');
  assert.ok(!JSON.stringify(d).includes('1012345678'));
  // adopt → an activity naming the system, categories from the scan; validation
  assert.equal((await post(e, '/pdpl/discovery/adopt', { db: 'x y' })).status, 400);
  assert.equal((await post(e, '/pdpl/discovery/adopt', { db: 'reg:none' })).status, 404);
  const a = await post(e, '/pdpl/discovery/adopt', { db: 'reg:core' }); assert.equal(a.status, 200);
  assert.deepEqual(a.json.systems, ['CORE-DB']); assert.deepEqual(a.json.data_categories.sort(), ['contact', 'financial', 'health', 'identity']); assert.match(a.json.id, /^PD-ROPA-/);
  d = (await e.req('GET', '/pdpl/discovery', OP)).json;
  assert.deepEqual(d.findings.map((f) => f.key.split(':').pop()), ['dpia'], 'mapped now; the sensitive data still needs a DPIA');
  const acts = e.app.store.auditTail(30).map((x) => x.action);
  for (const x of ['pdpl.discovery.run', 'pdpl.discovery.adopt']) assert.ok(acts.includes(x), x);
});

test('breach from a SIEM incident: 72-hour clock, SDAIA draft, Arabic / English notice, missing fields', async (t) => {
  const e = await setup(t);
  assert.equal((await post(e, '/pdpl/breach/from-incident', { case_id: 'x' })).status, 400);
  assert.equal((await post(e, '/pdpl/breach/from-incident', { case_id: 'CASE-000099' })).status, 404);
  assert.equal((await post(e, '/pdpl/breach/from-incident', { case_id: 'CASE-000042' }, { user: 'system:bot', role: 'operator' })).status, 403);
  assert.equal((await post(e, '/pdpl/breach/from-incident', { case_id: 'CASE-000042' }, { user: 'v', role: 'viewer' })).status, 403);
  const b = await post(e, '/pdpl/breach/from-incident', { case_id: 'CASE-000042', aware_at: '2026-10-20T06:00Z' }); assert.equal(b.status, 200);
  assert.equal(b.json.source_case, 'CASE-000042'); assert.match(b.json.description, /Mass export/);
  assert.equal((await post(e, '/pdpl/breach/from-incident', { case_id: 'CASE-000042' })).status, 409, 'one breach record per incident');
  let dr = (await e.req('GET', '/pdpl/breach/' + b.json.id + '/draft', OP)).json;
  assert.equal(dr.hours_left, 70); assert.equal(dr.deadline, '2026-10-23T06:00:00.000Z'); assert.equal(dr.late, false);
  assert.ok(dr.missing.includes('categories of personal data') && dr.missing.includes('DPO contact (Personal data profile)'));
  assert.ok(dr.sdaia.some((r) => r[0] === 'Approximate number of data subjects')); assert.match(dr.subject_notice.ar, new RegExp(ZYB_ORG.short_ar)); assert.match(dr.note, /does not send/);
  await post(e, '/pdpl/records', { kind: 'breach', id: b.json.id, categories: ['identity', 'health'], subjects_count: 1200, risks: 'fraud', measures: 'account disabled', harm_likely: true });
  clock += 80 * 3600000;
  dr = (await e.req('GET', '/pdpl/breach/' + b.json.id + '/draft', OP)).json;
  assert.equal(dr.late, true); assert.match(dr.sdaia.find((r) => /delay/.test(r[0]))[1], /REQUIRED/); assert.equal(dr.sdaia.find((r) => /Sensitive/.test(r[0]))[1], 'yes');
  clock -= 80 * 3600000;
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'pdpl.breach.draft'));
});

test('DPIA wizard: every question answered, scored with reasons; only the DPO signs, not the preparer; P-07 closes', async (t) => {
  const e = await setup(t);
  await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM);
  const ro = (await post(e, '/pdpl/records', { kind: 'ropa', name: 'Medical claims', purpose: 'claims', legal_basis: 'contract', data_categories: ['identity', 'health'], sources: 2 })).json;
  const q = (await e.req('GET', '/pdpl/dpia/questions', OP)).json; assert.ok(q.questions.length >= 10 && q.measures.length >= 10);
  let r = await post(e, '/pdpl/dpia/assess', { ropa_id: ro.id, answers: { sensitive: 'yes' } }); assert.equal(r.status, 400); assert.match(r.json.error, /answer every question/);
  r = await post(e, '/pdpl/dpia/assess', { ropa_id: ro.id, answers: 'all good' }); assert.equal(r.status, 400);
  r = await post(e, '/pdpl/dpia/assess', { ropa_id: 'PD-ROPA-999', answers: {} }); assert.equal(r.status, 404);
  const A = { sensitive: 'yes', scale: 'over 100,000', sources: 'yes', automated: 'solely automated', monitoring: 'no', vulnerable: 'no', new_tech: 'yes', transfer: 'no', processors: 'yes, with agreements', necessity: 'mostly' };
  r = await post(e, '/pdpl/dpia/assess', { ropa_id: ro.id, answers: A, measures: [] });
  assert.equal(r.status, 200); assert.equal(r.json.score.level, 'high'); assert.equal(r.json.outcome, 'not_acceptable');
  assert.ok(r.json.score.required.some((x) => /human review/.test(x))); assert.ok(r.json.score.why.some((x) => /sensitive: yes/.test(x)));
  r = await post(e, '/pdpl/dpia/assess', { id: r.json.id, ropa_id: ro.id, answers: A, measures: ['encryption', 'access', 'logging', 'minimisation', 'human_review', 'consent', 'retention', 'rights', 'contracts', 'training'] });
  assert.equal(r.json.score.level, 'low'); assert.equal(r.json.outcome, 'acceptable'); const id = r.json.id;
  assert.equal((await post(e, '/pdpl/dpia/' + id + '/sign', {}, OP)).status, 403, 'not the DPO');
  const self = await post(e, '/pdpl/dpia/assess', { ropa_id: ro.id, answers: A, measures: ['encryption'] }, DPO);
  const s1 = await post(e, '/pdpl/dpia/' + self.json.id + '/sign', {}, DPO); assert.equal(s1.status, 403); assert.match(s1.json.error, /four-eyes/);
  const s2 = await post(e, '/pdpl/dpia/' + id + '/sign', {}, DPO); assert.equal(s2.status, 200); assert.equal(s2.json.approved_by, 'huda.syn'); assert.equal(s2.json.completed, '2026-10-20');
  assert.equal((await post(e, '/pdpl/dpia/' + id + '/sign', {}, DPO)).status, 409);
  assert.equal((await post(e, '/pdpl/dpia/assess', { id, ropa_id: ro.id, answers: A, measures: [] })).status, 409, 'a signed assessment is not edited');
  const v = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(!v.findings.some((f) => /^P-07:/.test(f.key) && f.target && f.target.id === ro.id), 'P-07 no longer flags the activity');
  const acts = e.app.store.auditTail(40).map((x) => x.action);
  for (const x of ['pdpl.dpia.assess', 'pdpl.dpia.sign']) assert.ok(acts.includes(x), x);
});
