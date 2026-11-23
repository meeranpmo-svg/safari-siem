// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// inv-helper.py op "oracle_health" against a fake python-oracledb driver: the account's privileges are checked before any
// health query and an over-privileged account is refused (no query runs); every call carries the server-side call timeout
// and the session is labelled for the DBAs; the dictionary scans are skipped when the engine asks (heavy=false); a locked
// account is a login error (never retried); the transaction is read-only and rolled back.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawnSync } = require('node:child_process');

const HELPER = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
const PY = ['python3', 'python'].find((p) => spawnSync(p, ['-c', 'pass']).status === 0);
const FAKE = `
import json, os
LOG = os.environ["FAKE_LOG"]
def _log(x):
    with open(LOG, "a") as f: f.write(json.dumps(x) + "\\n")
class Cur:
    def __init__(s, c): s.c = c; s.res = []
    def execute(s, q, *a):
        _log({"sql": q, "call_timeout": s.c.call_timeout, "module": s.c.module, "client_identifier": s.c.client_identifier})
        ql = q.lower()
        if os.environ.get("FAKE_DENY") and os.environ["FAKE_DENY"] in ql: raise Exception("ORA-00942: table or view does not exist")
        if "session_privs" in ql: s.res = [(p,) for p in json.loads(os.environ.get("FAKE_PRIVS", '["CREATE SESSION"]'))]
        elif "from v$instance" in ql: s.res = [("PROD", "db01", "19.0.0.0", "OPEN", "ACTIVE", "READ WRITE", "PRIMARY", "ARCHIVELOG", "PRODDB", "PRODDB", 100, "2026-10-01T00:00:00", "STARTED", "ALLOWED")]
        elif "from v$sysmetric" in ql: s.res = [("Average Active Sessions", 6.5, 6000, "2026-10-19T09:00:00"), ("Host CPU Utilization (%)", 91.25, 6000, "2026-10-19T09:00:00"), ("CPU Usage Per Sec", 380, 6000, "2026-10-19T09:00:00"), ("Buffer Cache Hit Ratio", 98.7, 6000, "2026-10-19T09:00:00"), ("Unrelated Metric", 1, 6000, "2026-10-19T09:00:00")]
        elif "name = 'cpu_count'" in ql: s.res = [("4",)]
        elif "from v$waitclassmetric" in ql: s.res = [("User I/O", 300, 1500, 6000, 55.5, 2.1), ("Commit", 20, 400, 6000, 3.2, 0.1)]
        elif "from v$session where status = 'active'" in ql: s.res = [] if os.environ.get("FAKE_IDLE") else [("CPU", "ON CPU", 3), ("User I/O", "db file sequential read", 2), ("User I/O", "direct path read", 1)]
        elif "from v$osstat" in ql: s.res = [("NUM_CPUS", 4), ("PHYSICAL_MEMORY_BYTES", 68719476736), ("FREE_MEMORY_BYTES", 4294967296)]
        else: s.res = []
    def fetchall(s): return s.res
class Conn:
    call_timeout = 0; module = None; action = None; client_identifier = None
    def cursor(s): return Cur(s)
    def rollback(s): _log({"rollback": True})
    def close(s): _log({"close": True})
def makedsn(h, p, service_name=None): return "%s:%s/%s" % (h, p, service_name)
def connect(**k):
    if os.environ.get("FAKE_CONNECT_ERR"): raise Exception(os.environ["FAKE_CONNECT_ERR"])
    return Conn()
`;

function run(req, env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orafake-')), log = path.join(dir, 'log.jsonl');
  fs.writeFileSync(path.join(dir, 'oracledb.py'), FAKE); fs.writeFileSync(log, '');
  const r = spawnSync(PY, [HELPER], { input: JSON.stringify(Object.assign({ op: 'oracle_health', host: '10.0.0.5', port: 1521, username: 'monitor', password: 'pw', service: 'PROD' }, req)),
    env: Object.assign({}, process.env, { PYTHONPATH: dir, FAKE_LOG: log }, env), encoding: 'utf8' });
  const calls = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  fs.rmSync(dir, { recursive: true, force: true });
  return { out: JSON.parse(r.stdout || '{}'), calls, sql: calls.filter((c) => c.sql).map((c) => c.sql) };
}

test('oracle helper: read-only account - labelled session, call timeout, privileges checked first, rolled back', { skip: !PY && 'no python' }, () => {
  const { out, calls, sql } = run({});
  assert.equal(out.ok, true); assert.equal(out.heavy, true);
  assert.match(sql[0], /session_privs/, 'the privilege check is the very first statement');
  for (const c of calls.filter((x) => x.sql)) { assert.equal(c.call_timeout, 10000); assert.equal(c.module, 'ZYBERON-MONITOR'); assert.equal(c.client_identifier, 'zyberon-itam'); }
  for (const q of sql) assert.match(q.trim(), /^(select|set transaction read only)/i, 'nothing but SELECTs and a read-only transaction: ' + q);
  assert.ok(sql.some((q) => /dba_objects/.test(q)) && sql.some((q) => /rman_backup/.test(q)), 'heavy pass reads backup + invalid objects');
  assert.ok(calls.some((c) => c.rollback) && calls.some((c) => c.close));
});

test('oracle helper: an over-privileged account is refused before any health query', { skip: !PY && 'no python' }, () => {
  for (const privs of [['CREATE SESSION', 'ALTER SYSTEM'], ['CREATE SESSION', 'SELECT ANY TABLE'], ['CREATE SESSION', 'DROP ANY TABLE', 'SYSDBA']]) {
    const { out, sql, calls } = run({}, { FAKE_PRIVS: JSON.stringify(privs) });
    assert.equal(out.ok, false); assert.equal(out.error_class, 'unsafe'); assert.match(out.error, new RegExp(privs[1]));
    assert.deepEqual(sql.length, 1, 'only the privilege check ran: ' + sql.join(' | '));
    assert.ok(calls.some((c) => c.close), 'logged out');
  }
  const ok = run({}, { FAKE_PRIVS: JSON.stringify(['CREATE SESSION', 'SELECT ANY DICTIONARY', 'SET CONTAINER']) });
  assert.equal(ok.out.ok, true, 'the read-only dictionary privileges are accepted');
});

test('oracle helper: heavy=false skips the dictionary scans; locked / expired accounts are login errors', { skip: !PY && 'no python' }, () => {
  const { out, sql } = run({ heavy: false });
  assert.equal(out.ok, true); assert.equal(out.heavy, false);
  assert.ok(!sql.some((q) => /dba_objects|rman_backup/.test(q)), 'no dba_objects / backup history scan');
  assert.ok(!out.records.some((r) => r.kind === 'backup'), 'no invented "no backup" record when backup was not read');
  for (const m of ['ORA-28000: The account is locked.', 'ORA-28001: the password has expired', 'ORA-01017: invalid username/password']) {
    const r = run({}, { FAKE_CONNECT_ERR: m });
    assert.equal(r.out.error_class, 'auth', m);
  }
});

test('oracle helper: performance readings in the SIEM collector\'s shape (load, efficiency, wait classes, active sessions, host)', { skip: !PY && 'no python' }, () => {
  const { out, sql } = run({});
  assert.equal(out.ok, true);
  const by = (k) => out.records.filter((r) => r.kind === k);
  const lp = by('load_profile')[0];
  assert.deepEqual([lp.aas, lp.host_cpu_pct, lp.db_cpu_s, lp.cpu_count, lp.interval_s, lp.scope], [6.5, 91.25, 3.8, 4, 60, 'instance'], 'per-second CPU is centiseconds / 100, as in collect-perf.sql');
  assert.equal(by('efficiency')[0].buffer_cache_hit_pct, 98.7);
  assert.deepEqual(by('wait_classes').map((w) => [w.class, w.time_s, w.waits_s, w.avg_ms, w.dbtime_pct]), [['User I/O', 0.05, 25, 2, 55.5], ['Commit', 0.0033, 6.67, 0.5, 3.2]]);
  const a = by('active_sessions')[0];
  assert.deepEqual([a.aas, a.aas_cpu, a.aas_user_i_o, a.top_event], [6, 3, 3, 'ON CPU']);
  assert.deepEqual([by('host')[0].num_cpus, by('host')[0].mem_total_mb], [4, 65536]);
  assert.ok(!Object.keys(lp).some((k) => /unrelated/i.test(k)), 'only the metrics the SIEM reads');
  for (const q of sql) assert.match(q.trim(), /^(select|set transaction read only)/i);
  assert.ok(!sql.some((q) => /active_session_history|dba_hist/i.test(q)), 'no Diagnostics Pack views (ASH / AWR)');
  // no active session right now = a zero record; a view that cannot be read = no record and the query is named
  assert.equal(run({}, { FAKE_IDLE: '1' }).out.records.find((r) => r.kind === 'active_sessions').aas, 0);
  const d = run({}, { FAKE_DENY: 'v$waitclassmetric' }).out;
  assert.ok(!d.records.some((r) => r.kind === 'wait_classes')); assert.ok(d.errors.some((e) => e.query === 'wait_classes' && e.error === 'denied'));
  assert.ok(!run({ perf: false }).out.records.some((r) => r.kind === 'load_profile'), 'perf=false reads health only');
});

test('oracle helper: long sessions on an account missing a grant name the view and the GRANT that fixes it', { skip: !PY && 'no python' }, () => {
  // only TEMP per session missing: the sessions are still read, TEMP is null and a note gives the grant on the real object
  let { out, sql } = run({ op: 'oracle_long', min_s: 60 }, { FAKE_DENY: 'gv$tempseg_usage' });
  assert.equal(out.ok, true, JSON.stringify(out)); assert.equal(out.notes.length, 1);
  assert.match(out.notes[0], /GRANT SELECT ON sys\.gv_\$sort_usage TO MONITOR;/, 'GV$TEMPSEG_USAGE is a synonym: the grant names gv_$sort_usage');
  assert.ok(sql.some((q) => /from gv\$session s/i.test(q) && !/tempseg/i.test(q)), 'read again without the TEMP column');
  // a view the read cannot do without: refused with the exact grants
  ({ out } = run({ op: 'oracle_long', min_s: 60 }, { FAKE_DENY: 'gv$sesstat' }));
  assert.equal(out.ok, false); assert.equal(out.error_class, 'grant');
  assert.match(out.error, /cannot read gv\$sesstat\./); assert.match(out.error, /GRANT SELECT ON sys\.gv_\$sesstat TO MONITOR;/);
  assert.doesNotMatch(out.error, /gv\$session[,.]/, 'only the missing view is named');
  const ok = run({ op: 'oracle_long', min_s: 60 });
  assert.equal(ok.out.ok, true, JSON.stringify(ok.out)); assert.deepEqual(ok.out.notes, []);
});
