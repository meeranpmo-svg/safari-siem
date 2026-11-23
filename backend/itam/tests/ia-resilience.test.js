// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IA Cyber & Operational Resilience (engine/ia-resilience.js) through the real ITAM: the SAMA CSF + IA register over SYNTHETIC facts,
// real DR drills recorded through the GRC register, backup not connected. Areas scored with their reason or "not measured" (never
// resilient); the IA-specific items; the critical-system matrix (never drilled = bad, RTO missed, no stream / no backup = unknown,
// weakest link); the chance the next drill passes needs 2 drills and is Beta-smoothed; daily snapshot once a day and the trend needs
// 3; roles (viewer reads, export for operators and audited, advisor off until allowed / refused for a viewer).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: {} }, hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 } });
test('IA resilience: areas, matrix, drill learning, snapshots, roles', async (t) => {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', samaFacts: async () => FACTS(), eccFacts: async () => FACTS() });
  const G = e.app.addons.grc, who = { user: 'nora.syn', role: 'operator' };
  // core banking: two passed drills, RTO met; claims portal: a failed drill that missed the RTO; HR: planned, never drilled
  for (const [res, rto] of [['pass', 60], ['pass', 90]]) { const d = G.drillPut({ title: 'Failover core (synthetic)', system: 'CoreBanking', rto_target_min: 120, rpo_target_min: 15, frequency_months: 12 }, who); G.drillResult(d.id, { result: res, rto_actual_min: rto, rpo_actual_min: 5, executed: '2026-10-0' + (res === 'pass' && rto === 60 ? 1 : 2) }, who); }
  const c = G.drillPut({ title: 'Claims restore (synthetic)', system: 'ClaimsPortal', rto_target_min: 60, frequency_months: 12 }, who); G.drillResult(c.id, { result: 'fail', rto_actual_min: 240, executed: '2026-10-05' }, who);
  G.drillPut({ title: 'HR tabletop (synthetic)', system: 'HRSystem', type: 'tabletop' }, who);
  const v = (await e.req('GET', '/ia-resilience', VIEW)).json;
  assert.ok(v.pillars.cyber.available && typeof v.pillars.cyber.score === 'number' && /assessed/.test(v.pillars.cyber.why), 'cyber baseline scored with its reason');
  assert.equal(v.pillars.backup.available, false); assert.match(v.pillars.backup.reason, /no backup platform connected/);
  assert.ok(v.pillars.recover.available && /2 of 3 system\(s\) drilled within cadence/.test(v.pillars.recover.why) && /1 of 2 last drill\(s\) met the RTO/.test(v.pillars.recover.why), 'recoverability: ' + v.pillars.recover.why);
  assert.match(v.index_why, /Backup not measured and left out/);
  assert.ok(v.ia && /277/.test(v.ia.circular) && v.ia.items.length >= 1, 'IA-specific items listed');
  const m = (s) => v.matrix.find((x) => x.system === s);
  assert.equal(m('HRSystem').cells.drill.s, 'bad'); assert.equal(m('HRSystem').weakest.what, 'drill');
  assert.equal(m('ClaimsPortal').cells.rto.s, 'bad'); assert.equal(m('CoreBanking').cells.rto.s, 'ok'); assert.equal(m('CoreBanking').cells.backup.s, 'unknown', 'no backup matched is unknown, never ok');
  assert.equal(m('CoreBanking').p_pass.p, 0.75, 'two passes: Beta(1,1) gives 3/4'); assert.match(m('ClaimsPortal').p_pass.why, /needs 2 completed drills/);
  assert.ok(v.attention.some((a) => /HRSystem: never drilled/.test(a.text)));
  assert.match(v.learning.trend.why, /needs 3 daily snapshots/);
  const R = e.app.addons.iaResilience; for (let i = 0; i < 3; i++) { assert.ok(await R.snapshot()); assert.equal(await R.snapshot(), null, 'one snapshot a day'); clock += DAY; }
  assert.ok(['improving', 'worsening', 'flat'].includes((await e.req('GET', '/ia-resilience', VIEW)).json.learning.trend.direction));
  assert.equal((await e.req('GET', '/ia-resilience/export', VIEW)).status, 403);
  const x = (await e.req('GET', '/ia-resilience/export', OP)).json; assert.ok(x.rows.some((r) => r[1] === 'CoreBanking') && x.rows.some((r) => /^requirement/.test(r[0])));
  assert.ok(e.app.store.auditTail(300).some((a) => a.action === 'ia-resilience.export'));
  assert.equal((await e.req('POST', '/ia-resilience/ask', Object.assign({ body: { question: 'are we ready for IA?' } }, VIEW))).status, 403);
  assert.equal((await e.req('POST', '/ia-resilience/ask', Object.assign({ body: { question: 'are we ready for IA?' } }, OP))).status, 424);
});
