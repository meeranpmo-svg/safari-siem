// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC Dashboard (engine/grc-dashboard.js). Unit part with SYNTHETIC registers: every pillar scored with itemised deductions (roles not
// named, overdue reviews, risks over appetite, expired exceptions, overdue actions, unowned gaps, control exceptions); a source that
// fails is not available and left out of the index (never counted as good); the attention list most urgent first; learning - trend
// needs 3 snapshots, an unusual change needs 7 and is flagged past 2.5 standard deviations, movers over 7 days. Route part through
// the real ITAM (roles; viewer reads, AI refused for a viewer / off until allowed, audit of the question).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createGrcDashboard, lsq } = require('../engine/grc-dashboard');

const DAY = 86400000, OP = { user: 'nora.syn', role: 'operator' };
function fake(o = {}) {
  const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
  if (o.ciso) col('ecc_profile').put({ id: 'profile', ciso_user: 'khalid.syn' });
  const st = { over: o.over == null ? 2 : o.over, overdueActions: 3, ccmExc: 1 };
  const addons = {
    grc: { summary: () => ({ total: 40, attested: 30, reviews: { overdue: 4, soon: 6 }, frameworks: [{ framework: 'SAMA', policies: 35 }] }) },
    riskStudio: { view: () => ({ summary: { open: 9, high: 3, over_appetite: st.over, deteriorating: 1, candidates: 5, model: 'taxonomy (synthetic)' }, heat: { inherent: { '4x4': 2 }, residual: { '3x3': 2 } }, appetite: { default: 12 } }) },
    grcRegisters: { workspace: () => ({ actions: { open: 10, overdue: st.overdueActions, due_soon: 2, awaiting_verification: 1, closed_30d: 4 }, exceptions: { active: 2, expired: 1 } }) },
    crosswalk: o.noCrosswalk ? undefined : { gaps: async () => ({ frameworks: { ecc: { name: 'NCA ECC', available: true, pct_fully: 40 }, sama: { name: 'SAMA CSF / IA', available: true, pct_fully: 60 }, iso: { name: 'ISO 27001:2022', available: false, reason: 'not installed', pct_fully: null } }, kpis: { unowned: 7, overdue: 1, multi_framework: 4 }, forecast: {}, settings: { target_pct: 80 }, items: [{ key: 'ECC:ZS-1-1-01', title: 'Strategy', priority: 90, frameworks: ['ecc', 'sama'] }] }) },
    auditCcm: o.ccmFails ? { summary: () => { throw new Error('store locked (synthetic)'); } } : { summary: () => ({ at: '2026-11-01T00:00:00Z', effective: 7, exceptions: st.ccmExc, not_testable: 2, open: [{ id: 'x', name: 'person names stay in control monitoring' }] }) },
  };
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const app = { store: { collection: col }, addons, settings: { get: () => ({}) }, audit() {}, log: { every() {}, warn() {}, info() {} } };
  return { D: createGrcDashboard(app, { now: () => clock, noTimer: true }), st, tick: (ms) => { clock += ms; } };
}

test('pillars: itemised deductions, roles not named, sources that fail left out of the index', async () => {
  const { D } = fake({ ccmFails: true }), v = await D.view(OP);
  const g = v.pillars.governance; assert.ok(g.deductions.some((d) => /CISO \(NCA ECC profile\) not named/.test(d.what)) && g.deductions.some((d) => /4 policy review\(s\) overdue/.test(d.what)));
  assert.ok(v.pillars.risk.deductions.some((d) => /2 risk\(s\) over appetite/.test(d.what)) && v.pillars.risk.deductions.some((d) => /expired/.test(d.what)));
  assert.ok(v.pillars.compliance.deductions.some((d) => /average share fully compliant 50 % across 2 framework/.test(d.what)), 'unavailable ISO not averaged in');
  assert.ok(v.attention.some((a) => /ISO 27001:2022 register not available/.test(a.text)));
  assert.ok(v.pillars.remediation.deductions.some((d) => /7 gap work item\(s\) without an owner/.test(d.what)));
  assert.equal(v.pillars.assurance.available, false); assert.match(v.pillars.assurance.reason, /could not be read/);
  const meas = Object.values(v.pillars).filter((p) => p.available);
  assert.equal(v.index, Math.round(meas.reduce((t, p) => t + p.score, 0) / meas.length)); assert.match(v.index_why, /Assurance not available and left out/);
  assert.equal(v.attention[0].level, 'bad', 'most urgent first');
  const named = await fake({ ciso: true, ccmFails: true }).D.view(OP); assert.ok(named.pillars.governance.score > g.score, 'naming the CISO raises governance');
  const ok = await fake().D.view(OP); assert.ok(ok.pillars.assurance.available && /1 of 8 control test/.test(ok.pillars.assurance.deductions[0].what));
  assert.ok(!JSON.stringify(ok.pillars.assurance).includes('person names'), 'control-monitoring names stay on their page');
  const nx = await fake({ noCrosswalk: true }).D.view(OP); assert.equal(nx.pillars.compliance.available, false);
});

test('learning: trend needs 3 snapshots, unusual change needs 7 and is flagged, movers over 7 days', async () => {
  const f = fake(); let v = await f.D.view(OP);
  assert.match(v.learning.trend.index.why, /needs 3 daily snapshots/);
  for (let d = 0; d < 8; d++) { if (d === 7) { f.st.over = 9; f.st.overdueActions = 9; } await f.D.snapshot(); assert.equal(await f.D.snapshot(), null, 'one snapshot a day'); f.tick(DAY); }
  v = await f.D.view(OP);
  assert.ok(typeof v.learning.trend.index.per_week === 'number' && v.learning.trend.risk.direction === 'worsening');
  assert.ok(v.learning.unusual.some((u) => u.key === 'risk' && u.change < 0 && /drop/.test(u.why)), 'the sudden risk drop is unusual: ' + JSON.stringify(v.learning.unusual));
  assert.ok(v.learning.movers.some((m) => m.key === 'risk' && m.change < 0));
  assert.equal(lsq([[0, 1], [1, 2], [2, 3]]), 1); assert.equal(lsq([[0, 1]]), null);
});

test('routes: a viewer reads, the advisor is for operators and off until allowed', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const v = await e.req('GET', '/grc-dashboard', { user: 'vera.syn', role: 'viewer' });
  assert.equal(v.status, 200); assert.ok(['governance', 'risk', 'compliance', 'remediation', 'assurance'].every((k) => v.json.pillars[k]));
  assert.equal(v.json.pillars.assurance.available, false, 'no control-monitoring run yet: not available, not good');
  assert.equal(v.json.pillars.risk.available, false, 'an empty risk register is not a good score'); assert.match(v.json.pillars.risk.reason, /no risk rated yet/);
  assert.equal((await e.req('POST', '/grc-dashboard/ask', { body: { question: 'how are we doing?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  const r = await e.req('POST', '/grc-dashboard/ask', { body: { question: 'x' }, user: 'nora.syn', role: 'operator' }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await e.req('POST', '/grc-dashboard/ask', { body: { question: 'how are we doing?' }, user: 'nora.syn', role: 'operator' })).status, 424);
});
