// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Business Risk quantification (engine/brisk-quant.js through engine/business-risk.js): PERT and Poisson draws, the seeded Monte Carlo
// (same inputs -> same figures; a changed input changes them), percentiles ordered and against a closed-form check, the chance of
// exceeding the loss appetite, the drivers; residual exposure per quarter from the assessment history (never back-filled); Pearson
// correlation between RAS series over the periods both reported; the routes: operator enters a loss range (validated, audited, logged
// on the risk), admin sets the appetite, viewer reads; a risk with no range is listed as not quantified. SYNTHETIC register.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const Q = require('../engine/brisk-quant');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

test('draws: PERT stays in its range around the most likely value; Poisson has the right mean', () => {
  const R = Q.rng(42); let s = 0, lo = Infinity, hi = -Infinity; const N = 20000;
  for (let i = 0; i < N; i++) { const v = Q.pert(R, 100, 200, 600); s += v; lo = Math.min(lo, v); hi = Math.max(hi, v); }
  assert.ok(lo >= 100 && hi <= 600); assert.ok(Math.abs(s / N - (100 + 4 * 200 + 600) / 6) < 5, 'PERT mean = (a + 4m + b) / 6');
  let p = 0; for (let i = 0; i < N; i++) p += Q.poisson(R, 2.5); assert.ok(Math.abs(p / N - 2.5) < 0.05);
  assert.equal(Q.poisson(R, 0), 0); assert.equal(Q.pert(R, 50, 50, 50), 50);
});

test('simulate: seeded and repeatable, ordered percentiles, expected mean, appetite and drivers', () => {
  const items = [{ id: 'BR-1', title: 'Synthetic outage', loss_min: 100000, loss_likely: 300000, loss_max: 1500000, frequency: 2 }, { id: 'BR-2', title: 'Synthetic fraud', loss_min: 50000, loss_likely: 80000, loss_max: 200000, frequency: 0.5 }];
  const a = Q.simulate(items, { appetite: 1000000 }), b = Q.simulate(items, { appetite: 1000000 });
  assert.deepEqual(a.percentiles, b.percentiles, 'same register, same figures');
  const c = Q.simulate([Object.assign({}, items[0], { frequency: 3 }), items[1]]); assert.notDeepEqual(c.percentiles, a.percentiles, 'a changed input changes them');
  const P = a.percentiles; assert.ok(P.p50 <= P.p90 && P.p90 <= P.p95 && P.p95 <= P.p99);
  const expected = 2 * (100000 + 4 * 300000 + 1500000) / 6 + 0.5 * (50000 + 4 * 80000 + 200000) / 6;
  assert.ok(Math.abs(a.mean - expected) / expected < 0.03, 'mean = sum of frequency x PERT mean');
  assert.ok(a.appetite.p_exceed > 0 && a.appetite.p_exceed < 1);
  assert.equal(a.drivers[0].id, 'BR-1'); assert.ok(Math.abs(a.drivers.reduce((s, d) => s + d.share, 0) - 1) < 1e-9);
  assert.equal(a.histogram.length, 30); assert.equal(a.cdf[a.cdf.length - 1].p > 0.99, true); assert.match(a.independence, /independent/);
});

test('quarterly: the rating in force at each quarter end, from the history only', () => {
  const now = Date.parse('2026-11-11T00:00:00Z');
  const risks = [
    { id: 'A', history: [{ at: '2025-02-10T00:00:00Z', inherent: 16, class: 'Class III' }, { at: '2026-05-01T00:00:00Z', inherent: 6, class: 'Class I' }] },
    { id: 'B', history: [{ at: '2026-08-15T00:00:00Z', inherent: 20, class: 'Class IV' }] },
    { id: 'C', history: [] },
  ];
  const Rr = Q.quarterly(risks, now); assert.equal(Rr.length, 8); assert.equal(Rr[7].quarter, '2026-Q4'); assert.equal(Rr[7].partial, true);
  const by = Object.fromEntries(Rr.map((r) => [r.quarter, r]));
  assert.deepEqual([by['2026-Q1'].risks, by['2026-Q1'].classes.III], [1, 1], 'A was Class III then; B not yet assessed');
  assert.deepEqual([by['2026-Q2'].inherent_sum, by['2026-Q2'].classes.I], [6, 1], 'A re-assessed in Q2');
  assert.deepEqual([by['2026-Q3'].risks, by['2026-Q3'].classes.IV], [2, 1]);
  assert.equal(by['2025-Q1'].risks, 1); assert.equal(Rr[0].quarter, '2025-Q1');
});

test('correlate: pairs over the periods both reported, strongest first, 6 periods minimum', () => {
  const per = (n) => Array.from({ length: n }, (_, i) => '2026-' + String(i + 1).padStart(2, '0'));
  const M = [
    { id: 'm1', component: 'Synthetic claims ratio', unit: '%', series: per(8).map((p, i) => ({ period: p, value: 50 + i })) },
    { id: 'm2', component: 'Synthetic expense ratio', unit: '%', series: per(8).map((p, i) => ({ period: p, value: 30 + 2 * i })) },
    { id: 'm3', component: 'Synthetic outages', unit: 'hours', series: per(8).map((p, i) => ({ period: p, value: [3, 1, 4, 1, 5, 9, 2, 6][i] })) },
    { id: 'm4', component: 'Synthetic too short', series: per(4).map((p) => ({ period: p, value: 1 })) },
  ];
  const C = Q.correlate(M); assert.equal(C.metrics_with_history, 3);
  assert.deepEqual([C.pairs[0].a, C.pairs[0].b, C.pairs[0].r, C.pairs[0].strength, C.pairs[0].n], ['m1', 'm2', 1, 'strong', 8]);
  assert.equal(C.pairs[0].points.length, 8); assert.ok(!C.pairs.some((p) => p.a === 'm4' || p.b === 'm4'));
});

test('routes: loss ranges (operator, validated, audited, logged), appetite (admin), view (viewer), not quantified listed', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  assert.equal((await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM)).status, 200);
  let v = (await call('GET', '/brisk/quant', undefined, VIEW)).json;
  assert.equal(v.simulation, null, 'nothing quantified: no simulation, no assumed figures'); assert.equal(v.coverage.quantified, 0); assert.ok(v.coverage.missing.length > 0);
  assert.ok(v.coverage.missing[0].residual >= v.coverage.missing[v.coverage.missing.length - 1].residual, 'the most serious unquantified risks first');
  const id = v.coverage.missing[0].id, good = { loss_min: 200000, loss_likely: 500000, loss_max: 2500000, frequency: 1.5, basis: 'two synthetic incidents in 2025 and the synthetic BIA' };
  assert.equal((await call('POST', '/brisk/risks/' + id + '/quant', good, VIEW)).status, 403);
  let r = await call('POST', '/brisk/risks/' + id + '/quant', Object.assign({}, good, { loss_likely: 3000000 })); assert.equal(r.status, 400); assert.match(r.text, /loss_likely must lie between/);
  r = await call('POST', '/brisk/risks/' + id + '/quant', Object.assign({}, good, { frequency: 0 })); assert.equal(r.status, 400); assert.match(r.text, /frequency must be at least/);
  r = await call('POST', '/brisk/risks/' + id + '/quant', Object.assign({}, good, { basis: '' })); assert.equal(r.status, 400); assert.match(r.text, /basis/);
  r = await call('POST', '/brisk/risks/' + id + '/quant', Object.assign({}, good, { loss_max: 'lots' })); assert.equal(r.status, 400); assert.match(r.text, /loss_max must be a number/);
  r = await call('POST', '/brisk/risks/BR-9999/quant', good); assert.equal(r.status, 404);
  r = await call('POST', '/brisk/risks/' + id + '/quant', Object.assign({ owner: 'ignored' }, good)); assert.equal(r.status, 200); assert.equal(r.json.quant.by, 'nora.syn');
  const one = (await call('GET', '/brisk/risks/' + id, undefined, VIEW)).json; assert.ok(one.changelog.some((c) => c.what === 'quantified' && c.by === 'nora.syn'));
  assert.equal(one.owner === 'ignored', false, 'undeclared fields are dropped');
  // appetite
  assert.equal((await call('POST', '/brisk/quant/settings', { appetite_sar: 3000000, basis: 'synthetic board RAS' }, OP)).status, 403);
  r = await call('POST', '/brisk/quant/settings', { appetite_sar: -1, basis: 'x' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /appetite_sar/);
  r = await call('POST', '/brisk/quant/settings', { appetite_sar: 3000000, basis: 'synthetic board RAS' }, ADM); assert.equal(r.status, 200);
  v = (await call('GET', '/brisk/quant', undefined, VIEW)).json;
  assert.equal(v.coverage.quantified, 1); assert.equal(v.simulation.risks, 1); assert.equal(v.simulation.appetite.value, 3000000); assert.ok(v.simulation.appetite.p_exceed >= 0);
  assert.equal(v.settings.by, 'adam.syn'); assert.equal(v.inputs[0].quant.basis, good.basis); assert.equal(v.quarterly.length, 8);
  assert.ok(Array.isArray(v.correlation.pairs));
  const aud = e.app.store.auditTail(200);
  assert.ok(aud.some((a) => a.action === 'brisk.risk.quant' && a.target === id && a.by === 'nora.syn' && a.detail.loss_max === 2500000));
  assert.ok(aud.some((a) => a.action === 'brisk.risk.quant.settings' && a.by === 'adam.syn' && a.detail.to === 3000000));
});
