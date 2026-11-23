// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA coverage intelligence (engine/compliance/sama-intel.js, sama-intel-routes.js) over a SYNTHETIC coverage engine: leverage groups
// open checks across controls and counts only controls whose every open check is in the group (gain from the framework's own weights,
// capped controls never move); quick wins one check away; one snapshot a day, none while the evidence store is unreadable; reliability
// (Beta(1,1)), a regression when a control covered earlier is not now, flapping; forecast after 3 snapshots against the target; settings
// admin-only, versioned, validation naming the field; any signed-in role reads, operator asks; the advisor (off without a key, refs checked).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/compliance/sama-intel-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const T0 = Date.parse('2026-11-02T08:00:00Z'), DAY = 86400000, P = '/api/soc/compliance/sama-intel';
const OP = { role: 'operator', user: 'nora.syn' }, VIEW = { role: 'viewer', user: 'vera.syn' }, ADM = { role: 'admin', user: 'syed' };
const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
const ck = (id, result, reason) => ({ id, title: 'Check ' + id + ' (synthetic)', result, value: null, reason: reason || (result === 'pass' ? 'ok' : 'not met (synthetic)') });
function fakeSama() {
  const C = [
    { id: '3.3.14', title: 'Security event management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'gap', checks: [ck('retention', 'pass'), ck('src_ad', 'fail')], actions: [{ check: 'src_ad', action: 'Onboard the domain controllers' }] },
    { id: '3.3.5', title: 'Identity and access management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'partial', checks: [ck('src_ad', 'fail')], actions: [{ check: 'src_ad', action: 'Onboard the domain controllers' }] },
    { id: '3.3.3', title: 'Operations (synthetic)', domain: '3.3', siem_evidenced: true, status: 'gap', checks: [ck('src_ad', 'fail'), ck('rules', 'fail')], actions: [] },
    { id: '3.3.7', title: 'Malware protection (synthetic)', domain: '3.3', siem_evidenced: true, status: 'partial', checks: [ck('edr', 'unknown', 'evidence unavailable')], actions: [{ check: 'edr', action: 'Connect the EDR' }] },
    { id: '3.3.8', title: 'Patch management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'covered', checks: [ck('patch', 'pass')], actions: [] },
    { id: '3.3.9', title: 'Capped control (synthetic)', domain: '3.3', siem_evidenced: true, status: 'partial', capped: true, checks: [ck('x', 'pass')], actions: [] },
    { id: '3.1.1', title: 'Governance (synthetic)', domain: '3.1', siem_evidenced: false, status: 'n/a', checks: [], actions: [] },
  ];
  const ch = { ok: true };
  return { C, ch, async summary() {
    const ev = C.filter((c) => c.siem_evidenced), counts = { covered: 0, partial: 0, gap: 0, 'n/a': 0 }; for (const c of C) counts[c.status]++;
    const pct = Math.round(((counts.covered + counts.partial * 0.5) / ev.length) * 1000) / 10;
    return { clickhouse: ch, summary: { coverage_pct: pct, evidenced: ev.length, total: C.length, counts, by_domain: {}, scoring: { covered: 1, partial: 0.5, gap: 0 } }, controls: JSON.parse(JSON.stringify(C)).map((c) => Object.assign({ reasons: ['synthetic reason'], capped: false }, c)) };
  } };
}
function world({ script = [], key = true, sama = fakeSama() } = {}) {
  let clock = T0;
  const dir = tmpDir(); const state = createState({ dir, log: quietLog }), calls = [];
  class FakeAnthropic { constructor() { this.messages = { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const config = { soc_analyst: {}, secrets: { netops: { anthropic_api_key: key ? 'sk-ant-synthetic-for-tests' : '' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } };
  const deps = { state, config, log: quietLog, sdk: FakeAnthropic, now: () => clock, noTimers: true, samaCoverage: sama };
  const api = fakeApi({ realRanks: true }); routes.register(api, deps);
  return { api, deps, sama, calls, tick: (ms) => { clock += ms; }, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('leverage counts only controls a fix would move; quick wins; capped and n/a never move', async () => {
  const w = world();
  try {
    const r = await w.api.call('GET', P, VIEW); assert.equal(r.status, 200, JSON.stringify(r.body)); const v = r.body;
    const ad = v.leverage.find((g) => g.check === 'src_ad');
    assert.deepEqual(ad.controls.sort(), ['3.3.14', '3.3.3', '3.3.5']); assert.deepEqual(ad.moves.sort(), ['3.3.14', '3.3.5'], '3.3.3 also fails its rules check');
    assert.equal(ad.gain_pts, 25, 'gap→covered 1/6 + partial→covered 0.5/6 of the evidenced controls'); assert.equal(v.leverage[0].check, 'src_ad');
    assert.ok(ad.actions.includes('Onboard the domain controllers'));
    assert.deepEqual(v.quick_wins.map((q) => q.id), ['3.3.14', '3.3.5', '3.3.7'], 'ranked by gain');
    assert.ok(!v.quick_wins.some((q) => q.id === '3.3.9'), 'a capped control is not a quick win');
    assert.equal(v.kpis.coverage_pct, 41.7); assert.equal(v.kpis.quick_wins, 3); assert.equal(v.kpis.na, 1);
    assert.match(v.learning.forecast.why, /needs 3 daily snapshots/); assert.match(v.intel_note, /official SAMA assessment/);
    let q = await w.api.call('GET', P + '?days=999', VIEW); assert.equal(q.status, 400); assert.match(JSON.stringify(q.body), /days/);
    const w2 = world({ sama: null }); try { const x = (await w2.api.call('GET', P, VIEW)).body; assert.equal(x.installed, false); assert.match(x.reason, /not installed/); } finally { w2.cleanup(); }
  } finally { w.cleanup(); }
});

test('history: one snapshot a day, none while evidence is unreadable; regression, reliability, flapping, forecast; settings', async () => {
  const w = world(); const X = w.deps.samaIntel;
  try {
    w.sama.ch.ok = false; assert.equal(await X.snapshot(), null, 'no snapshot while the evidence store is unreadable'); w.sama.ch.ok = true;
    const c7 = w.sama.C.find((c) => c.id === '3.3.7');
    for (let d = 0; d < 4; d++) { if (d === 2) { c7.status = 'covered'; c7.checks = [ck('edr', 'pass')]; } assert.ok(await X.snapshot()); assert.equal(await X.snapshot(), null, 'one a day'); w.tick(DAY); }
    const c8 = w.sama.C.find((c) => c.id === '3.3.8'); c8.status = 'gap'; c8.checks = [ck('patch', 'fail')];
    let v = (await w.api.call('GET', P, VIEW)).body;
    assert.equal(v.learning.snapshots, 4); assert.equal(v.regressions.length, 1); assert.equal(v.regressions[0].id, '3.3.8'); assert.equal(v.regressions[0].regression.last_covered, '2026-11-05');
    assert.equal(v.per.find((p) => p.id === '3.3.8').reliability, 83, '(4+1)/(4+2)'); assert.equal(v.per.find((p) => p.id === '3.3.5').reliability, 17, '(0+1)/(4+2)');
    assert.ok(v.learning.forecast.why.length && v.learning.trend.length === 4);
    // flapping: alternate a control for a week
    const c5 = w.sama.C.find((c) => c.id === '3.3.5');
    for (let d = 0; d < 5; d++) { c5.status = d % 2 ? 'covered' : 'partial'; assert.ok(await X.snapshot()); w.tick(DAY); }
    v = (await w.api.call('GET', P, VIEW)).body; assert.ok(v.flapping.some((f) => f.id === '3.3.5'), 'flapping after 3+ changes');
    // settings
    assert.equal((await w.api.call('POST', P + '/settings', Object.assign({ body: { target_pct: 90, version: 0 } }, OP))).status, 403);
    let r = await w.api.call('POST', P + '/settings', Object.assign({ body: { target_pct: 5, version: 0 } }, ADM)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /target_pct/);
    r = await w.api.call('POST', P + '/settings', Object.assign({ body: { target_pct: 90, target_date: '2026-01-01', version: 0 } }, ADM)); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /past/);
    r = await w.api.call('POST', P + '/settings', Object.assign({ body: { target_pct: 90, target_date: '2027-06-30', version: 0 } }, ADM)); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.version, 1);
    assert.equal((await w.api.call('POST', P + '/settings', Object.assign({ body: { target_pct: 85, version: 0 } }, ADM))).status, 409);
    v = (await w.api.call('GET', P, VIEW)).body; assert.equal(v.settings.target_pct, 90); assert.ok(['on_track', 'at_risk'].includes(v.learning.forecast.target.status));
    assert.ok(w.api.audits.some((a) => a.action === 'compliance.sama-intel.settings'));
  } finally { w.cleanup(); }
});

test('the advisor: operator only, off without a key, refs checked, audited', async () => {
  const sub = { type: 'tool_use', id: 's', name: 'submit_advice', input: { summary: 'SIEM coverage 41.7 % (synthetic)', priorities: [{ ref: 'src_ad', action: 'Onboard the DCs', why: 'moves two controls' }, { ref: '9.9.9', action: 'x', why: 'invented' }] } };
  const w = world({ script: [turn([{ type: 'tool_use', id: 'a', name: 'leverage', input: {} }]), turn([sub])] });
  try {
    assert.equal((await w.api.call('POST', P + '/ask', Object.assign({ body: {} }, VIEW))).status, 403);
    assert.equal((await w.api.call('POST', P + '/ask', Object.assign({ body: {} }, { role: 'operator', user: 'ai:grc' }))).status, 403);
    const r = await w.api.call('POST', P + '/ask', Object.assign({ body: { question: 'what first?' } }, OP)); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.unverified, 1); assert.equal(r.body.priorities[0].verified, true); assert.equal(r.body.priorities[1].verified, false);
    assert.ok(w.api.audits.some((a) => a.action === 'compliance.sama-intel.ask'));
    const w2 = world({ key: false }); try { assert.equal((await w2.api.call('POST', P + '/ask', Object.assign({ body: {} }, OP))).status, 503); } finally { w2.cleanup(); }
  } finally { w.cleanup(); }
});
