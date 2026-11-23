// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// An Oracle instance is "down" only on an explicit instance-down reading. When readings arrive but no instance status
// does (seen live: a missing grant on V$INSTANCE), the database is "status unknown" - never counted as Down, and the AI
// Oracle DBA raises "status unknown", not "instance not open".
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOracleSummary } = require('../engine/db-audit');
const health = require('../engine/db-audit/oracle-health');

const NOW = Date.UTC(2026, 9, 20, 11, 0);
const rec = (o) => Object.assign({ collector: 'sentra-oracle-itam', host: 'eskauat', instance: 'ESS', db_name: 'ESS', t: new Date(NOW - 60000).toISOString() }, o);

test('no instance status reading = status unknown, not down; an explicit OPEN/down reading decides', async () => {
  const S = createOracleSummary({ now: () => NOW });
  const parse = (o) => [].concat(health.parse(JSON.stringify(rec(o)), {}) || []);
  for (const e of parse({ kind: 'tablespace', name: 'USERS', used_pct: 40, used_mb: 400, max_mb: 1000 })) S.stage(Object.assign({ ts: NOW - 60000, src_type: 'oracle-health' }, e));
  let v = await S.summary({});
  assert.equal(v.instances.length, 1);
  assert.equal(v.instances[0].state, 'unknown'); assert.equal(v.totals.down, 0, 'not counted as down'); assert.equal(v.totals.unknown, 1);
  for (const e of parse({ kind: 'instance', status: 'OPEN', version: '19.21.0.0.0', open_mode: 'READ WRITE' })) S.stage(Object.assign({ ts: NOW - 30000, src_type: 'oracle-health' }, e));
  v = await S.summary({});
  assert.equal(v.instances[0].state, 'up'); assert.equal(v.instances[0].up, true); assert.equal(v.totals.down, 0);
  for (const e of parse({ kind: 'instance', status: 'SHUTDOWN' })) S.stage(Object.assign({ ts: NOW - 10000, src_type: 'oracle-health' }, e));
  v = await S.summary({});
  assert.equal(v.instances[0].state, 'down'); assert.equal(v.totals.down, 1);
});
