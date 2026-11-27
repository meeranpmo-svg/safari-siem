// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Vulnerability & Testing Dashboard (engine/vuln-dashboard.js). Unit part with SYNTHETIC sources: every pillar scored with itemised
// deductions (criticals, internet-facing, SLA, reopened, untested critical assets, app tests never done, failing release gates, secrets);
// a source that fails, or has nothing to measure, is not available and left out of the index (never counted as good); the open-findings
// matrix and the pipeline; days to clear at the fix rate; a viewer sees no hosts or findings. Learning: trend needs 3 snapshots, an unusual
// change needs 8 and is flagged. Route part through the real ITAM: a viewer reads, nothing measurable on an empty platform, the advisor
// is for operators and off until allowed, validation names the field.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createVulnDashboard, lsq } = require('../engine/vuln-dashboard');

const DAY = 86400000, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
function fake(o = {}) {
  const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
  const st = { crit: o.crit == null ? 2 : o.crit };
  const finding = (i, sev, ext) => ({ title: 'Synthetic weakness ' + i, host: '10.0.0.' + i, severity: sev, cvss: 9, priority: 80, exposure: ext ? 'external' : 'internal', sources: ['greenbone'], status: 'open', sla_state: i === 1 ? 'breached' : 'ok', owner: 'omar.syn', why: [{ text: 'synthetic' }] });
  const addons = {
    vaptCenter: o.vcFails ? { view: () => { throw new Error('python unavailable (synthetic)'); } } : { view: () => { const f = []; for (let i = 1; i <= st.crit; i++) f.push(finding(i, 'critical', i === 1)); f.push(finding(9, 'high', false));
      return { findings: f, counts: { critical: st.crit, high: 1, medium: 0, low: 0 }, open: f.length, sla: { breached: 1, due_14d: 2, forecast_breaches_14d: 1, fix_rate_per_day: 0.5 }, delta: { reopened: [{}], new: [], fixed: [] }, paths: [], duplicates_merged: 1, sources: {} }; } },
    vulnscan: { view: () => ({ last_scan: { id: 'S1' }, waiting_approval: 1, scans: [{ state: 'running' }], pending_risk: 1 }) },
    apppt: o.noApps ? { view: () => ({ kpis: { apps: 0 }, engagements: [], findings: [], attention: [] }) } : { view: () => ({ kpis: { apps: 3, tests_overdue: 2, never_tested: 1, open: 4, critical: 1, high: 2, overdue: 1, retest_waiting: 1, regressions: 1, accept_waiting: 0 },
      engagements: [{ state: 'scope_requested' }, { state: 'testing' }], findings: [{ severity: 'critical', status: 'open' }, { severity: 'high', status: 'open' }, { severity: 'high', status: 'verified' }],
      attention: [{ level: 'bad', text: 'Claims portal: 1 open critical finding(s)' }] }) },
    appsec: { view: () => ({ kpis: { apps: 2, open: 5, critical: 1, high: 2, secrets: 1, overdue: 0, gates_failing: 1, never_scanned: 0, accept_waiting: 1 }, apps: [{ open: { critical: 1, high: 2, medium: 2, low: 0 } }], attention: [{ level: 'bad', text: 'Mobile BFF: 1 secret(s) in source - rotate and remove' }] }) },
  };
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const app = { store: { collection: col }, addons, settings: { get: () => ({}) }, audit() {}, log: { every() {}, warn() {}, info() {} } };
  return { D: createVulnDashboard(app, { now: () => clock, noTimer: true }), st, tick: (ms) => { clock += ms; } };
}

test('pillars: itemised deductions; a failing or empty source is left out of the index; matrix, pipeline, days to clear', async () => {
  const v = await fake().D.view(OP);
  const ex = v.pillars.exposure; assert.ok(ex.available && ex.deductions.some((d) => /2 critical vulnerability/.test(d.what)) && ex.deductions.some((d) => /internet-facing/.test(d.what)) && ex.deductions.some((d) => /reopened/.test(d.what)));
  assert.equal(v.pillars.coverage.available, false, 'no asset in the testing scope: not available'); assert.match(v.pillars.coverage.reason, /no asset in the testing scope/);
  assert.ok(v.pillars.applications.deductions.some((d) => /1 application\(s\) never tested/.test(d.what)));
  assert.ok(v.pillars.code.deductions.some((d) => /1 release gate/.test(d.what)) && v.pillars.code.deductions.some((d) => /secret/.test(d.what)));
  assert.ok(v.pillars.remediation.deductions.some((d) => /past their SLA/.test(d.what)));
  const meas = Object.values(v.pillars).filter((p) => p.available);
  assert.equal(v.index, Math.round(meas.reduce((t, p) => t + p.score, 0) / meas.length)); assert.match(v.index_why, /Testing coverage not available and left out/);
  assert.deepEqual(v.matrix.map((m) => m.counts.critical), [2, 1, 1]);
  assert.equal(v.pipeline.find((p) => /waiting for approval/.test(p.label)).n, 1); assert.equal(v.pipeline.find((p) => /Risk acceptances/.test(p.label)).n, 2);
  assert.equal(v.learning.clear.days, 6, '3 critical/high at 0.5 a day'); assert.equal(v.attention[0].level, 'bad');
  const vw = await fake().D.view(VIEW); assert.equal(vw.attention.length, 0); assert.equal(vw.infra.top.length, 0); assert.match(vw.details_note, /operators/);
  assert.ok(!JSON.stringify(vw).includes('10.0.0.1'), 'a viewer sees no host');
  const bad = await fake({ vcFails: true, noApps: true }).D.view(OP);
  assert.equal(bad.pillars.exposure.available, false); assert.match(bad.pillars.exposure.reason, /could not be read/); assert.equal(bad.pillars.applications.available, false);
  assert.ok(bad.index !== null && bad.pillars.code.available, 'the other sources still show');
});

test('learning: trend needs 3 snapshots, an unusual change needs 8 and is flagged; one snapshot a day', async () => {
  const f = fake(); let v = await f.D.view(OP);
  assert.match(v.learning.trend.index.why, /needs 3 daily snapshots/);
  for (let d = 0; d < 9; d++) { if (d === 8) f.st.crit = 9; await f.D.snapshot(); assert.equal(await f.D.snapshot(), null); f.tick(DAY); }
  v = await f.D.view(OP);
  assert.equal(v.learning.trend.critical.direction, 'worsening');
  assert.ok(v.learning.unusual.some((u) => u.key === 'critical' && u.change === 7), JSON.stringify(v.learning.unusual));
  assert.equal(lsq([[0, 1], [1, 2], [2, 3]]), 1); assert.equal(lsq([[0, 1]]), null);
});

test('routes: a viewer reads; nothing measurable on an empty platform; the advisor is for operators and off until allowed', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const v = await e.req('GET', '/vuln-dashboard', VIEW); assert.equal(v.status, 200, v.raw);
  assert.ok(['exposure', 'coverage', 'applications', 'code', 'remediation'].every((k) => v.json.pillars[k] && v.json.pillars[k].available === false), 'an empty platform is not a good score');
  assert.equal(v.json.index, null); assert.match(v.json.pillars.exposure.reason, /no scan results yet/);
  assert.equal((await e.req('POST', '/vuln-dashboard/ask', { body: { question: 'what first?' }, ...VIEW })).status, 403);
  const r = await e.req('POST', '/vuln-dashboard/ask', { body: { question: 'x' }, ...OP }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await e.req('POST', '/vuln-dashboard/ask', { body: { question: 'what should we fix first?' }, ...OP })).status, 424);
});

test('charts: daily history and a 14-day projection of the index and the open criticals (3+ snapshots)', async () => {
  const f = fake(), DAY = 864e5;
  let v = await f.D.view(OP); assert.equal(v.forecast.index, null, 'nothing to project before 3 snapshots'); assert.deepEqual(v.history, []);
  for (let d = 0; d < 6; d++) { f.st.crit = 1 + d; await f.D.snapshot(); f.tick(DAY); }   // criticals rise by one a day
  v = await f.D.view(OP);
  assert.equal(v.history.length, 6); assert.deepEqual(v.history.map((h) => h.critical), [1, 2, 3, 4, 5, 6]); assert.ok(typeof v.history[0].pillars === 'object');
  assert.equal(v.forecast.critical.length, 14); assert.equal(v.forecast.critical[0].value, 7, 'the next day on the same line'); assert.equal(v.forecast.critical[13].value, 20);
  assert.ok(v.forecast.index.every((p) => p.value >= 0 && p.value <= 100), 'the index stays within 0-100'); assert.match(v.forecast.note, /not a promise/);
  const vv = await f.D.view({ user: 'vera.syn', role: 'viewer' }); assert.equal(vv.history.length, 6, 'counts only - a viewer sees the history too');
});
