// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// db_repl.py: the pure checks (SQL_REDO parser, statements per target, hashing across engines, keyset, which logs to mine,
// transactions by XID across windows, LogMiner windows against a fake Oracle cursor) and, when PostgreSQL is installed,
// the helper ops on a real cluster (Verify with planted differences, apply with the checkpoint in the same transaction,
// conflict stop / log with savepoints, over-privileged accounts refused). Scripts: tests/py/repl_*_check.py.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startPg } = require('./_pg');
const PY = spawnSync('python3', ['-c', '1']).status === 0;
const run = (args) => { const r = spawnSync('python3', args, { encoding: 'utf8', timeout: 240000 }); assert.equal(r.status, 0, r.stderr.slice(-1500)); const o = JSON.parse(r.stdout.trim().split('\n').pop()); return Object.keys(o).filter((k) => !o[k]); };

test('db_repl.py pure checks', { skip: !PY && 'python3 missing' }, () => {
  assert.deepEqual(run([path.join(__dirname, 'py/repl_core_check.py'), path.join(__dirname, '../engine/discovery/db_repl.py')]), []);
});
test('helper engine ops on a real PostgreSQL', { skip: !PY && 'python3 missing' }, (tt) => {
  if (spawnSync('python3', ['-c', 'import pg8000']).status !== 0) { tt.skip('pg8000 not installed'); return; }
  const pg = startPg(); if (pg.skip) { tt.skip(pg.skip); return; }
  try { assert.deepEqual(run([path.join(__dirname, 'py/repl_pg_check.py'), path.join(__dirname, '../engine/discovery/inv-helper.py'), String(pg.port)]), []); }
  finally { pg.stop(); }
});
