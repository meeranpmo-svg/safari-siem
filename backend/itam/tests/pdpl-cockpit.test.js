// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Cockpit (engine/pdpl-cockpit.js): the models on their own (Kaplan-Meier with censoring, Holt's forecast and band, the
// explainable activity score) and the route over the real PDPL registers with SYNTHETIC records: every clock in one list with the
// breach's 72 hours first, a missing impact assessment, the request deadline risk (the stated rule below 8 answered requests), the
// activity score with every point named, the heat map, the sources that answered, operator only (a viewer is refused).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { km, holt, activityRisk } = require('../engine/pdpl-cockpit');

test('the models: Kaplan-Meier with censored requests, Holt with a band, the explainable score', () => {
  // 4 answered at 10, 20, 20, 30 days; one still open at 25 (censored)
  const S = km([{ t: 10, event: true }, { t: 20, event: true }, { t: 20, event: true }, { t: 25, event: false }, { t: 30, event: true }]);
  assert.equal(S(5), 1); assert.equal(S(10), 0.8); assert.ok(Math.abs(S(20) - 0.8 * (2 / 4)) < 1e-12, 'two of the four at risk answered at 20 days');
  assert.ok(Math.abs(S(30) - 0) < 1e-12, 'the last one at risk answered at 30 (the censored one left at 25)');
  const f = holt([2, 4, 6, 8, 10, 12], 3); assert.ok(f[0].value > 12 && f[2].value > f[0].value, 'a rising series keeps rising'); assert.ok(f[0].low <= f[0].value && f[0].high >= f[0].value);
  assert.equal(holt([5], 3), null);
  const r = activityRisk({ sensitive: ['health'], data_categories: ['health'], dpia: 'missing', dpia_needed_for: ['sensitive data (health)'], completeness: 56, steward: null, review_due: true }, { transfers: [{ signed: false }], sensitiveGaps: 8 });
  assert.equal(r.score, 100); assert.equal(r.band, 'high');
  assert.ok(r.why.some((w) => /^\+25 sensitive data: health/.test(w)) && r.why.some((w) => /^\+15 sensitive-data control/.test(w) || /^\+15 transfer/.test(w)), r.why.join(' | '));
  assert.equal(activityRisk({ sensitive: [], dpia: 'ok', completeness: 100, steward: 'x' }).score, 0, 'nothing to name, nothing scored');
});

test('route: every clock, the request risk, the activity score; operator only', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-16T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const OP = { user: 'nora.syn', role: 'operator' }, c = (m, p, b, w) => e.req(m, p, Object.assign(b ? { body: b } : {}, w || OP));
  assert.equal((await c('POST', '/pdpl/records', { kind: 'ropa', name: 'Claims handling (synthetic)', purpose: 'claims', legal_basis: 'contract', data_categories: ['health', 'identity'], systems: ['Core'] })).status, 200);
  assert.equal((await c('POST', '/pdpl/records', { kind: 'breach', ref: 'SYN-B1', aware_at: '2026-11-15T08:00Z', description: 'synthetic', subjects_count: 12 })).status, 200);
  assert.equal((await c('POST', '/pdpl/dsar', { ref: 'SYN-R1', type: 'access', channel: 'email', received: '2026-11-01', systems: ['Core'] })).status, 200);
  assert.equal((await c('POST', '/pdpl/dsar', { ref: 'SYN-R2', type: 'destruction', channel: 'email', received: '2026-10-20', systems: ['Core'] })).status, 200);
  assert.equal((await c('GET', '/pdpl/cockpit', null, { user: 'vera.syn', role: 'viewer' })).status, 403, 'a viewer is refused');
  const r = await c('GET', '/pdpl/cockpit'); assert.equal(r.status, 200, r.text); const v = r.json;
  assert.ok(v.sources.filter((s) => s.ok).length >= 6, JSON.stringify(v.sources));
  assert.equal(v.clocks[0].kind, 'dpia', 'a missing impact assessment is already late');
  const b = v.clocks.find((x) => x.kind === 'breach'); assert.ok(b && /notify SDAIA \(72 h\)/.test(b.title) && b.hours_left > 0);
  const order = v.clocks.map((x) => x.kind); assert.ok(order.indexOf('breach') < order.indexOf('request'), 'the breach (hours left) comes before the requests (days left): ' + order.join(','));
  assert.equal(v.kpis.requests_open, 2); assert.match(v.requests.method, /rule \(only 0 answered/);
  assert.equal(v.requests.risk[0].ref, 'SYN-R2', 'the older request is the riskier'); assert.ok(v.requests.risk[0].p_miss > v.requests.risk[1].p_miss);
  assert.match(v.requests.forecast_note, /needs 6 months/);
  const a = v.activities[0]; assert.equal(a.name, 'Claims handling (synthetic)'); assert.equal(a.band, 'high'); assert.ok(a.why.some((w) => /impact assessment required/.test(w)));
  assert.equal(v.heat.health.high, 1);
});
