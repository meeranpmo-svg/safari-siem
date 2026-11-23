// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Removing an unknown / unused Oracle instance: hidden from the database pages and counted, needs a reason, the DBA approver
// or an administrator may do it, it reappears flagged when it sends a NEW reading, and it can be restored.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createOracleSummary } = require('../engine/db-audit');
const health = require('../engine/db-audit/oracle-health');
const { createState } = require('../engine/soc/state');
const { tmpDir, quietLog } = require('./soc-fakes');

test('remove / reappear / restore', async () => {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog });
  let now = Date.UTC(2026, 9, 21, 9, 0);
  const S = createOracleSummary({ now: () => now, state });
  const feed = (host, inst, at) => { for (const e of [].concat(health.parse(JSON.stringify({ kind: 'instance', status: 'OPEN', host, instance: inst, db_name: inst, t: new Date(at).toISOString(), collector: 'sentra-oracle-itam' }), {}) || [])) S.stage(Object.assign({ ts: at, src_type: 'oracle-health' }, e)); };
  try {
    feed('eskauat', 'ESS', now - 60000); feed('10.100.12.50', 'ESS', now - 3600000); feed('testdb', 'ORCL', now - 7200000);
    let v = await S.summary({}); assert.equal(v.instances.length, 3);
    assert.throws(() => S.forget('10.100.12.50|ESS', 'ahmed', ''), /say why/);
    assert.throws(() => S.forget('nonsense', 'ahmed', 'x y z'), /host\|INSTANCE/);
    S.forget('10.100.12.50|ESS', 'ahmed', 'same database as eskauat, read by IP');
    S.forget('testdb|ORCL', 'ahmed', 'old test database');
    v = await S.summary({});
    assert.deepEqual(v.instances.map((i) => i.key), ['eskauat|ESS']); assert.equal(v.totals.removed, 2);
    assert.equal((await S.summary({ include_removed: '1' })).instances.length, 3);
    now += 5 * 60000; feed('testdb', 'ORCL', now - 1000);   // it reports again
    v = await S.summary({});
    const back = v.instances.find((i) => i.key === 'testdb|ORCL');
    assert.ok(back && back.returned && back.returned.reason === 'old test database', 'a removed instance that reports again comes back, flagged');
    S.unforget('10.100.12.50|ESS');
    assert.equal((await S.summary({})).instances.length, 3);
    assert.equal(S.forgotten().length, 1);
  } finally { state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
