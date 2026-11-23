// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM pipeline canary (engine/ops/canary.js) end to end through the REAL parser, pipeline, detector (with the built-in rule pack,
// incl. SENTRA-OPS-900) and alert store, with an in-memory event store: a healthy run (parse, pipeline, alert, store - each timed), its
// alert closed as benign by system:canary and left out of the analyst queue; a detector that is not in the pipeline (alert stage
// FAILED, named), an event store that does not answer (store stage FAILED), a canary that stopped (stale), degraded after a failure,
// the routes' roles (viewer reads, operator runs, admin settings), validation naming the field, the audit records. SYNTHETIC only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const K = require('../engine/ops/canary');
const { createParser } = require('../engine/parse');
const { createPipeline } = require('../engine/pipeline');
const { createDetector } = require('../engine/detect/engine');
const { loadBuiltinRules } = require('../engine/detect/ruleset');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const quiet = Object.assign({ every() {} }, quietLog);
async function world(o = {}) {
  const dir = tmpDir('sentra-canary-'), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog });
  const parser = createParser({ log: quiet, config: {} }), pipeline = createPipeline({ log: quiet });
  const detector = await createDetector({ rules: loadBuiltinRules(path.join(__dirname, '..', 'engine', 'detect', 'rules')), now: Date.now, onAlert: (a) => alerts.raise(a), log: quiet });
  const stored = [];
  if (!o.noDetect) pipeline.use((ev) => detector.onEvent(ev), 'detect');
  pipeline.use((ev) => { if (!o.storeBroken) stored.push(ev); }, 'store');
  const search = { search: async (q) => { if (o.storeDown) throw new Error('ClickHouse connection refused'); const id = (q.q.match(/"(CNY-[^"]+)"/) || [])[1]; return { rows: stored.filter((e) => e.fields && e.fields.canary_run === id).slice(0, 1) }; } };
  let T = Date.now();
  const deps = { state, alerts, parser, pipeline, search, config: { canary: { alert_within_s: 60 } }, log: quiet, noTimers: true, pollMs: 1, sleep: async () => { T += 5000; }, now: () => T };
  const api = fakeApi({ realRanks: true }); K.register(api, deps);
  return { api, deps, alerts, state, stored, at: (x) => { T = x; }, now: () => T, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('canary: a healthy run passes every stage, closes its alert and stays out of the analyst queue', async () => {
  const w = await world(); try {
    const r = await w.deps.canary.run('syn.test');
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.deepEqual(r.stages.map((s) => [s.stage, s.ok]), [['parse', true], ['pipeline', true], ['alert', true], ['store', true]]);
    const a = w.alerts.all((x) => x.rule_id === 'SENTRA-OPS-900');
    assert.equal(a.length, 1); assert.equal(a[0].status, 'closed-benign'); assert.ok((a[0].history || []).some((h) => h.by === 'system:canary'));
    const { createAnalyst } = require('../engine/soc/analyst');
    const an = createAnalyst({ state: w.state, alerts: w.alerts, log: quietLog });
    assert.equal(an.queue({ status: 'all' }).items.filter((x) => x.rule_id === 'SENTRA-OPS-900').length, 0, 'never in the analyst views');
    const v = w.deps.canary.view();
    assert.equal(v.status, 'healthy'); assert.equal(v.day.success_pct, 100); assert.ok(v.latency.alert_p50_ms != null); assert.ok(v.intake.stages.some((s) => s.name === 'detect'));
  } finally { w.done(); }
});

test('canary: a detector not in the pipeline and a broken event store are named; degraded, then stale', async () => {
  let w = await world({ noDetect: true }); try {
    const r = await w.deps.canary.run();
    assert.equal(r.ok, false); assert.equal(r.failed_stage, 'alert'); assert.match(r.why, /rule SENTRA-OPS-900 raised no alert within 60 s/);
    assert.equal(w.deps.canary.view().status, 'failing');
  } finally { w.done(); }
  w = await world({ storeDown: true }); try {
    const r = await w.deps.canary.run();
    assert.equal(r.failed_stage, 'store'); assert.match(r.why, /writer or the event store is not working \(ClickHouse connection refused\)/);
  } finally { w.done(); }
  w = await world(); try {
    w.deps.state.collection('siem_canary_runs').put({ id: 'CNY-OLD', at: w.now() - 3600e3, ok: false, stages: [], failed_stage: 'alert', why: 'synthetic' });
    await w.deps.canary.run();
    assert.equal(w.deps.canary.view().status, 'degraded', 'a failure in 24 h, the latest passed');
    w.at(w.now() + 3 * 3600e3);
    const v = w.deps.canary.view(); assert.equal(v.status, 'stale'); assert.match(v.why, /the canary itself is not running/);
  } finally { w.done(); }
});

test('canary: two runs at the same instant never pass on each other\'s alert', async () => {
  const w = await world(); try {
    const r1 = await w.deps.canary.run();                    // passes; the synthetic clock has not moved
    w.deps.pipeline.use((ev) => { ev.host = 'not-the-canary'; }, 'break-detection-after-store');   // later events: the rule cannot match
    const T0 = w.now(); const r2 = await w.deps.canary.run(); w.at(T0);
    assert.equal(r1.ok, true); assert.notEqual(r1.id, r2.id, 'distinct run ids at the same instant');
  } finally { w.done(); }
  const v = await world({ noDetect: true }); try {
    const a = await v.deps.canary.run(), b = await v.deps.canary.run();
    assert.notEqual(a.id, b.id); assert.equal(b.ok, false, 'no detector: it fails, never passes on an earlier alert');
  } finally { v.done(); }
});

test('routes: viewer reads, operator runs (audited), admin settings validated', async () => {
  const w = await world(); try {
    let r = await w.api.call('GET', '/api/soc/ops/pipeline', { role: 'viewer' }); assert.equal(r.status, 200); assert.equal(r.body.status, 'waiting');
    r = await w.api.call('POST', '/api/soc/ops/pipeline/run', { role: 'viewer', body: {} }); assert.equal(r.status, 403);
    r = await w.api.call('POST', '/api/soc/ops/pipeline/run', { role: 'operator', user: 'syn.ops', body: {} }); assert.equal(r.status, 200); assert.equal(r.body.ok, true);
    assert.ok(w.api.audits.some((a) => a.action === 'ops.canary.run' && a.user === 'syn.ops'));
    r = await w.api.call('PUT', '/api/soc/ops/pipeline/settings', { role: 'operator', body: { every_min: 10 } }); assert.equal(r.status, 403);
    r = await w.api.call('PUT', '/api/soc/ops/pipeline/settings', { role: 'admin', body: { every_min: 2 } }); assert.equal(r.status, 400); assert.match(r.body.error, /every_min/);
    r = await w.api.call('PUT', '/api/soc/ops/pipeline/settings', { role: 'admin', user: 'syed', body: { every_min: 10 } }); assert.equal(r.status, 200); assert.equal(r.body.settings.every_min, 10);
    assert.ok(w.api.audits.some((a) => a.action === 'ops.canary.settings'));
  } finally { w.done(); }
});
