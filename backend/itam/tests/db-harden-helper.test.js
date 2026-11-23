// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// inv-helper.py op "db_harden": a fixed list of read-only SELECTs per engine (Oracle, SQL Server, PostgreSQL), run one by one
// against a fake connection; a query the login may not run is recorded as an error code and the next one still runs (PostgreSQL
// gets a rollback first); no statement writes; an unknown engine is refused; the connection is closed. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const HELPER = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
const PY = ['python3', 'python'].find((p) => spawnSync(p, ['-c', 'pass']).status === 0);
const RUN = `
import json, sys, importlib.machinery, importlib.util
spec = importlib.util.spec_from_loader("invh", importlib.machinery.SourceFileLoader("invh", sys.argv[1]))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
LOG = []
class Cur:
    def execute(s, q): LOG.append(q); s.q = q.lower()
    def fetchmany(s, n):
        if "pg_hba_file_rules" in s.q: raise Exception('ERROR:  permission denied for view pg_hba_file_rules')
        if "current_setting" in s.q or "pg_settings" in s.q: return [("ssl", "off"), ("password_encryption", "md5")]
        return [(1, None, "x" * 400)]
    def close(s): pass
class Conn:
    def cursor(s): return Cur()
    def rollback(s): LOG.append("ROLLBACK")
    def close(s): LOG.append("CLOSE")
m.connect_db = lambda r: Conn()
res = {}
for eng in ("oracle", "mssql", "postgres", "mysql"):
    del LOG[:]
    res[eng] = {"out": m.op_db_harden({"engine": eng, "host": "10.0.0.1", "port": 1, "username": "u", "password": "p"}), "log": list(LOG)}
print(json.dumps(res))
`;

test('db_harden: fixed SELECTs only, one failure does not stop the rest, values capped, connection closed, other engines refused', { skip: !PY && 'no python' }, () => {
  const p = spawnSync(PY, ['-I', '-c', RUN, HELPER], { encoding: 'utf8' });
  assert.equal(p.status, 0, p.stderr);
  const r = JSON.parse(p.stdout);
  for (const eng of ['oracle', 'mssql', 'postgres']) {
    const x = r[eng];
    assert.equal(x.out.ok, true, eng);
    assert.equal(x.log[x.log.length - 1], 'CLOSE', eng + ' connection closed');
    for (const q of x.log.filter((l) => l !== 'ROLLBACK' && l !== 'CLOSE')) {
      assert.match(q.trim(), /^(SELECT|WITH)\b/i, eng + ' runs only queries: ' + q.slice(0, 60));
      assert.doesNotMatch(q, /\b(INSERT|UPDATE|DELETE|ALTER|DROP|GRANT|REVOKE|CREATE|EXEC|TRUNCATE|MERGE)\b\s/i, eng + ' writes nothing: ' + q.slice(0, 60));
    }
    assert.ok(Object.values(x.out.results).some((v) => Array.isArray(v) && v.length), eng + ' read something');
  }
  const pg = r.postgres.out;
  assert.equal(pg.results.hba, null); assert.equal(pg.errors.hba, 'permission denied');
  assert.ok(r.postgres.log.includes('ROLLBACK'), 'a failed PostgreSQL statement is rolled back before the next');
  assert.ok(Object.keys(pg.results).indexOf('hba') < Object.keys(pg.results).length - 1, 'the queries after the failed one still ran');
  assert.ok(r.oracle.out.results.params[0][2].length <= 300, 'long values are capped');
  assert.equal(r.mysql.out.ok, false); assert.equal(r.mysql.out.error_class, 'config');
});
