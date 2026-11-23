// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Automated Risk Assessment (engine/risk-assess.js) over a SYNTHETIC AI CISO overview (signals + posture) and the REAL GRC risk register:
// signals linked to scenarios by word-bounded patterns (unmatched ones listed); likelihood itemised; residual after the measured control
// domains, no credit when a domain is not measured; a scenario with nothing measured is NOT ASSESSED (never low); register coverage and
// calibration; proposing to the register by a person (named owner, once); settings admin-only, versioned, validation naming the field;
// one snapshot a day, an unusual jump after a steady week, the exposure trend; roles, the audit record, the assessor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'operator' };
function fakeCiso() {
  const F = {
    risks: [
      { ref: 'duty:SYN-1', severity: 'critical', domain: 'detection', title: 'Kaspersky endpoint protection disabled on 12 hosts (synthetic)', source: 'AI security engineer', age_h: 5 },
      { ref: 'duty:SYN-2', severity: 'high', domain: 'exposure', title: 'CVE-2024-3400 exploitable on the Palo Alto edge (synthetic)', source: 'AI pentest engineer', age_h: null },
      { ref: 'sama:3.3.5', severity: 'high', domain: 'compliance', title: 'SAMA CSF 3.3.5 Identity and access management - gap', source: 'SAMA CSF coverage', age_h: null },
      { ref: 'drill-system:Core (synthetic)', severity: 'critical', domain: 'resilience', title: 'Core (synthetic): recovery test never performed', source: 'DR & BCM drills', age_h: null },
      { ref: 'duty:SYN-9', severity: 'high', domain: 'operations', title: 'Something odd happened (synthetic)', source: 'misc', age_h: null },
    ],
    // the AI CISO's real shape (engine/ciso.js): an object with its domains - a bare list once made every load fail (posture.map)
    posture: { overall: 57, grade: 'weak', measured: 3, of: 6, domains: [{ id: 'detection', name: 'Detection & response', measured: true, score: 40 }, { id: 'exposure', name: 'Exposure & vulnerabilities', measured: true, score: 50 },
      { id: 'governance', name: 'Governance & policy', measured: true, score: 80 }, { id: 'compliance', name: 'SAMA CSF compliance', measured: false, score: null, not_measured_why: 'SAMA coverage not connected' },
      { id: 'resilience', name: 'Resilience (DR / BCM)', measured: false, score: null, not_measured_why: 'no drills recorded' }, { id: 'operations', name: 'Security operations hygiene', measured: false, score: null }] },
    sources: [{ id: 'grc', name: 'GRC', state: 'live' }, { id: 'soc', name: 'SIEM metrics', state: 'unreachable', error: 'synthetic: SIEM link not configured' }],
  };
  return { F, overview: async () => JSON.parse(JSON.stringify(F)) };
}
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const C = fakeCiso();
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', raCiso: C });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, C, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const sc = (v, id) => v.scenarios.find((x) => x.id === id);

test('scenarios from live signals: itemised likelihood, residual after measured controls, not assessed is never low, coverage and calibration', async (t) => {
  const s = await setup(t);
  const G = require('../engine/grc-registers').createGrcRegisters(s.e.app);
  G.riskCreate({ title: 'Ransomware on endpoints (synthetic)', category: 'Malware & ransomware', owner: 'omar.syn', likelihood: 1, impact: 2 }, ADM);
  const r = await s.get('/risk-assess', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const rw = sc(v, 'ransomware');
  assert.deepEqual([rw.likelihood, rw.impact, rw.inherent, rw.control_strength, rw.residual], [3, 5, 15, 45, 11], '1 + critical 1.5 + fresh 0.5 = 3; 15 x (1 - 0.6 x 0.45)');
  assert.ok(rw.likelihood_why.some((p) => /critical/.test(p.what)) && rw.likelihood_why.some((p) => /72 h/.test(p.what)));
  assert.equal(rw.covered_by.length, 1); assert.equal(rw.calibration.length, 1, 'the register rates it 2 against an assessed 11');
  const out = sc(v, 'outage'); assert.equal(out.residual, out.inherent, 'resilience not measured: no control credit'); assert.match(out.controls_note, /no credit/);
  assert.equal(out.residual, 12); assert.equal(out.uncovered, true, 'at the appetite and nothing in the register');
  assert.ok(sc(v, 'vuln').signals.some((x) => x.ref === 'duty:SYN-2') && sc(v, 'network').signals.some((x) => x.ref === 'duty:SYN-2'), 'one signal can bear on two scenarios');
  assert.ok(sc(v, 'regulatory').signals.length && sc(v, 'account').signals.length, 'the SAMA identity gap is regulatory and access');
  const data = sc(v, 'data'); assert.equal(data.assessed, false); assert.equal(data.band, 'not assessed'); assert.equal(data.residual, null);
  assert.equal(v.unmapped_total, 1); assert.equal(v.unmapped[0].ref, 'duty:SYN-9');
  assert.ok(v.exposure != null && v.kpis.assessed >= 3 && v.kpis.not_assessed >= 1 && v.kpis.uncovered >= 1);
  assert.ok(v.notes.some((n) => /SIEM metrics: unreachable/.test(n)), 'a source that could not be read is said');
  for (let i = 1; i < v.scenarios.length; i++) assert.ok((v.scenarios[i - 1].residual || -1) >= (v.scenarios[i].residual || -1), 'sorted by residual');
  assert.match(v.note, /not a substitute/);
});

test('proposing to the register, settings, history and roles', async (t) => {
  const s = await setup(t);
  // propose
  assert.equal((await s.post('/risk-assess/scenarios/outage/register', { owner: 'nora.syn' }, VIEW)).status, 403);
  assert.equal((await s.post('/risk-assess/scenarios/outage/register', { owner: 'nora.syn' }, BOT)).status, 403, 'a service identity never records a risk');
  let r = await s.post('/risk-assess/scenarios/outage/register', {}); assert.equal(r.status, 400); assert.match(r.json.error, /owner/);
  r = await s.post('/risk-assess/scenarios/nope/register', { owner: 'nora.syn' }); assert.equal(r.status, 400); assert.match(r.json.error, /id/);
  r = await s.post('/risk-assess/scenarios/data/register', { owner: 'nora.syn' }); assert.equal(r.status, 409); assert.match(r.json.error, /not assessed/);
  r = await s.post('/risk-assess/scenarios/outage/register', { owner: 'nora.syn', note: 'synthetic' }); assert.equal(r.status, 200, r.raw);
  const risk = r.json.risk; assert.equal(risk.likelihood, 3); assert.equal(risk.impact, 4); assert.equal(risk.source_ref, 'risk-assess:outage'); assert.match(risk.description, /drill-system:Core/);
  assert.equal((await s.post('/risk-assess/scenarios/outage/register', { owner: 'nora.syn' })).status, 409, 'once only');
  let v = (await s.get('/risk-assess')).json; assert.equal(sc(v, 'outage').uncovered, false); assert.equal(sc(v, 'outage').covered_by[0].id, risk.id);
  assert.equal(s.audit('risk-assess.register').length, 1); assert.equal(s.audit('grc.risk.create').length, 1);
  // settings
  assert.equal((await s.post('/risk-assess/settings', { appetite: 10, version: 0 })).status, 403);
  r = await s.post('/risk-assess/settings', { impact: { outage: 9 }, version: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /impact\.outage/);
  r = await s.post('/risk-assess/settings', { appetite: 2, version: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /appetite/);
  r = await s.post('/risk-assess/settings', { appetite: 10, impact: { ransomware: 4 }, version: 0 }, ADM); assert.equal(r.status, 200); assert.equal(r.json.version, 1);
  assert.equal((await s.post('/risk-assess/settings', { appetite: 9, version: 0 }, ADM)).status, 409, 'stale version');
  v = (await s.get('/risk-assess')).json; assert.equal(sc(v, 'ransomware').impact, 4); assert.equal(sc(v, 'ransomware').impact_set, true); assert.equal(v.settings.appetite, 10);
  assert.equal(s.audit('risk-assess.settings').length, 1);
  // history: one a day, a steady week, then a jump
  const X = s.e.app.addons.riskAssess;
  assert.match(v.learning.trend.why, /needs 3 daily snapshots/);
  for (let d = 0; d < 8; d++) { assert.ok(await X.snapshot()); assert.equal(await X.snapshot(), null, 'one a day'); s.tick(DAY); }
  s.C.F.risks.push({ ref: 'duty:SYN-3', severity: 'critical', domain: 'detection', title: 'Ransomware beacon seen on a file server (synthetic)', source: 'AI security engineer', age_h: 2 },
    { ref: 'duty:SYN-4', severity: 'critical', domain: 'detection', title: 'Malware spreading over SMB (synthetic)', source: 'AI security engineer', age_h: 1 });
  v = (await s.get('/risk-assess')).json;
  assert.equal(v.learning.snapshots, 8); assert.ok(v.learning.unusual.some((u) => u.id === 'ransomware' && /never moved before/.test(u.why)), 'a jump after a steady week');
  assert.ok(['flat', 'rising', 'falling'].includes(v.learning.trend.direction)); assert.ok(v.learning.moves.find((m) => m.id === 'ransomware').d7 > 0);
  // assessor
  assert.equal((await s.post('/risk-assess/ask', { question: 'what should we act on?' }, VIEW)).status, 403);
  r = await s.post('/risk-assess/ask', { question: 'x' }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/risk-assess/ask', { question: 'what should we act on first?' })).status, 424, 'off until external AI is allowed');
});

test('no AI CISO: every scenario not assessed, exposure withheld, the page says what to connect', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const M = require('../engine/risk-assess'), X = M.createRiskAssess(e.app, { noTimer: true });
  const v = await X.view();
  assert.ok(v.scenarios.every((x) => !x.assessed && x.band === 'not assessed')); assert.equal(v.exposure, null); assert.match(v.exposure_why, /withheld/);
  assert.ok(v.notes.some((n) => /AI CISO is not installed/.test(n)));
});
