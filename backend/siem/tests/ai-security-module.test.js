// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Security (engine/soc/ai-security.js, ai-security-routes.js): the usage ledger fed by ai-guard's listener (calls,
// tokens, refusals, injection flags - never the text), quality from what people did with the AI's work, unusual use per
// person (robust statistics), the inventory, the red team (passes on the real registries; catches a planted containment
// tool), roles and the audit record. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const G = require('../engine/util/ai-guard');
const routes = require('../engine/soc/ai-security-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const DAY = 864e5;
function world(now) {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const deps = { state, log: quietLog, noTimers: true, now: now || Date.now, config: { ai_limits: { per_user_hour: 1000, per_user_day: 10000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi({ realRanks: true }); routes.register(api, deps);
  return { state, api, A: deps.aiSecurity, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('ledger: every call, refusal and injection flag of every AI feature is recorded per day and feature - never the text', async () => {
  const w = world(); try {
    const b = G.sharedBudget({});   // the same shared budget the AI features use
    b.admit('nora.syn', 'soc.copilot', 10); b.record('nora.syn', 'soc.copilot', { input_tokens: 100, output_tokens: 20 }, []);
    b.admit('nora.syn', 'soc.triage', 10); b.record('nora.syn', 'soc.triage', { input_tokens: 50, output_tokens: 5 }, [1, 3]);
    try { b.admit('omar.syn', 'soc.copilot', 1e9); } catch (e) { /* refused for size: recorded as a refusal */ }
    let r = await w.api.call('GET', '/api/soc/soc/ai-security/overview', { role: 'analyst' }); assert.equal(r.status, 403, 'the page names people: operator and above');
    r = await w.api.call('GET', '/api/soc/soc/ai-security/overview', { role: 'operator' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const cp = r.body.by_feature.find((f) => f.feature === 'soc.copilot'), tr = r.body.by_feature.find((f) => f.feature === 'soc.triage');
    assert.equal(cp.calls, 1); assert.equal(cp.tokens, 120); assert.equal(cp.refused, 1); assert.equal(tr.flagged, 1);
    assert.equal(r.body.today.calls, 2); assert.equal(r.body.flags[0].user, 'nora.syn'); assert.deepEqual(r.body.flags[0].signals, [1, 3]);
    assert.ok(!JSON.stringify(r.body.flags).includes('prompt'), 'no prompt text is kept');
    assert.ok(r.body.inventory.some((f) => f.id === 'soc.copilot' && f.proposes.length >= 5), 'inventory lists the copilot and its proposal tools');
    assert.match(r.body.note, /mitigated, not solved/);
  } finally { w.cleanup(); }
});

test('unusual AI use: a person far above their own usual and the peers is flagged with the reason', async () => {
  const T = Date.now(), w = world(() => T); try {
    const d = (k) => new Date(T - k * DAY).toISOString();
    for (let k = 1; k <= 6; k++) for (let i = 0; i < 4; i++) { w.A.onEntry({ at: d(k), user: 'eve.syn', feature: 'soc.copilot', tokens: 10 }); w.A.onEntry({ at: d(k), user: 'nora.syn', feature: 'soc.copilot', tokens: 10 }); }
    for (let i = 0; i < 120; i++) w.A.onEntry({ at: new Date(T).toISOString(), user: 'eve.syn', feature: 'soc.copilot', tokens: 10 });
    for (let i = 0; i < 4; i++) w.A.onEntry({ at: new Date(T).toISOString(), user: 'nora.syn', feature: 'soc.copilot', tokens: 10 });
    const o = w.A.overview();
    assert.deepEqual(o.anomalies.map((a) => a.user), ['eve.syn'], 'only eve is unusual');
    assert.equal(o.anomalies[0].usual, 4); assert.ok(o.anomalies[0].why.some((x) => /robust z/.test(x)));
  } finally { w.cleanup(); }
});

test('quality: acceptance withheld below 3 decisions, then measured', () => {
  const w = world(); try {
    const t = w.state.collection('soc_ai_triage');
    t.put({ id: 'A1', state: 'accepted' }); t.put({ id: 'A2', state: 'rejected' });
    assert.equal(w.A.overview().quality.find((q) => q.feature === 'soc.triage').acceptance_pct, null);
    t.put({ id: 'A3', state: 'accepted' }); t.put({ id: 'A4', state: 'draft' });
    const q = w.A.overview().quality.find((x) => x.feature === 'soc.triage');
    assert.equal(q.acceptance_pct, 67); assert.equal(q.waiting, 1);
  } finally { w.cleanup(); }
});

test('red team: every guard rail passes on the real registries; a planted containment tool is caught; admin only, audited', async () => {
  const w = world(); try {
    let r = await w.api.call('POST', '/api/soc/soc/ai-security/redteam', { role: 'operator' }); assert.equal(r.status, 403);
    r = await w.api.call('POST', '/api/soc/soc/ai-security/redteam', { role: 'admin', user: 'syed' }); assert.equal(r.status, 200);
    assert.equal(r.body.passed, r.body.total, JSON.stringify(r.body.results.filter((x) => !x.pass)));
    assert.ok(w.api.audits.some((a) => a.action === 'soc.ai.redteam' && a.detail.passed === r.body.total));
    const A = require('../engine/soc/analyst');
    A.TOOLS.push({ name: 'isolate_host', description: 'planted', input_schema: { type: 'object', additionalProperties: false, properties: {} } });
    try { const run = w.A.redteam('test'); const nw = run.results.find((x) => x.id === 'no-write'); assert.equal(nw.pass, false); assert.match(nw.detail, /soc\.triage:isolate_host/); }
    finally { A.TOOLS.pop(); }
    assert.equal(w.A.overview().redteam.by, 'test', 'the latest run is on the page');
  } finally { w.cleanup(); }
});
