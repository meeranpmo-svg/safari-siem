// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Executive Dashboard (engine/exec-dashboard.js): five pillars from the Reporting Center, AI CISO and Risk Studio (SYNTHETIC
// sources), a pillar with no data is NOT MEASURED (never assumed) and the index is withheld below 3 pillars; the daily history
// (one row a day), least-squares trend and 30-day forecast after 7 days, "unusual today", pillar change against 7 days ago; the
// ranked "needs the executive" list (decisions, high / over-appetite risks, worsening KPIs, gaps); a failing source says so; roles
// (viewer reads, admin records, operator asks for the brief, the refused cases), validation, audit; the AI brief goes through the
// Reporting Center's analyst with the executive report.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const X = require('../engine/exec-dashboard');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const D = 86400000, T0 = Date.parse('2026-11-01T07:00:00Z');
const K = (key, label, value, unit) => ({ key, label, value, unit: unit || '', good: 'up' });
function report() {
  return { id: 'executive', sections: [
    { id: 'compliance', title: 'Compliance posture', state: 'ok', kpis: [K('compliance.sama', 'SAMA CSF + IA score', 70, '%'), K('compliance.nca', 'NCA ECC score', 80, '%'), K('compliance.pdpl', 'PDPL score', null, '%'), K('compliance.sama_gaps', 'gaps', 12)] },
    { id: 'resilience', title: 'DR & backup', state: 'ok', kpis: [K('dr.readiness', 'DR readiness', 90, '%'), K('backup.coverage', 'Backup coverage', 70, '%')] },
    { id: 'security', title: 'Vulnerabilities', state: 'not_installed', note: 'Connect VAPT Studio', kpis: [] },
    { id: 'soc', title: 'SOC', state: 'ok', kpis: [K('soc.alerts_open', 'Alerts still open', 7)] },
    { id: 'assets', title: 'Asset register', state: 'ok', kpis: [K('assets.health', 'Register health', 84, '%'), K('cmdb.quality', 'CMDB quality', 76, '%')] },
    { id: 'platform', title: 'Platform health', state: 'ok', kpis: [K('platform.pages_working', 'Checked pages working', 95), K('platform.pages_down', 'Pages not working', 5)] }] };
}
const ciso = () => ({ posture: { overall: 72, grade: 'adequate', domains: [{ name: 'Detection & response', score: 65, measured: true }, { name: 'Exposure', score: null, measured: false }] },
  decisions: [{ severity: 'high', title: 'Approve firewall change FW-SYN-1', who: 'admin (not the requester)', from: 'AI network engineer', link: 'network-engineer.html' }], last_brief: { id: 'B1', headline: 'Posture adequate' } });
const risk = () => ({ summary: { open: 9, high: 2, over_appetite: 1 }, risks: [{ title: 'Ransomware on claims servers', band: 'high', over_appetite: true, owner: 'cio.syn' }, { title: 'Minor', band: 'low' }] });
const insights = () => ({ ok: true, days: 10, kpis: [{ key: 'dr.readiness', label: 'DR readiness', verdict: 'worsening', change: { delta: -6 }, forecast: 80 }], notable: [{ key: 'dr.readiness', label: 'DR readiness', why: 'worse than last week', text: '96 → 90' }, { key: 'assets.health', label: 'Register health', why: 'better than last week' }] });

test('pillars: measured only, weighted index, withheld below 3, itemised', () => {
  const p = X.pillars({ report: report(), ciso: ciso(), riskSum: risk().summary });
  const by = Object.fromEntries(p.pillars.map((x) => [x.id, x]));
  assert.equal(by.cyber.score, 72); assert.equal(by.compliance.score, 75, 'mean of the measured frameworks; PDPL not measured is left out');
  assert.equal(by.resilience.score, 80); assert.equal(by.operations.score, Math.round((95 + 84 + 76) / 3)); assert.equal(by.risk.score, 100 - 24 - 8);
  assert.equal(p.index, Math.round((72 * 30 + 75 * 25 + 80 * 20 + by.operations.score * 15 + 68 * 10) / 100)); assert.equal(p.grade, 'adequate');
  const few = X.pillars({ report: { sections: [] }, ciso: null, riskSum: risk().summary });
  assert.equal(few.index, null); assert.match(few.withheld_why, /only 1 of 5 pillars measured/); assert.equal(few.pillars.find((x) => x.id === 'cyber').measured, false);
});

test('learn: trend and forecast after 7 days, unusual today, pillar change against a week ago', () => {
  const h = []; for (let i = 20; i >= 1; i--) h.push({ day: new Date(T0 - i * D).toISOString().slice(0, 10), index: 60 + (20 - i) * 0.5 + (i % 2 ? 0.2 : -0.2), pillars: { cyber: 60 + (20 - i) } });
  const m = X.learn(h, 50);
  assert.equal(m.trend.verdict, 'improving'); assert.ok(m.trend.per_week > 3 && m.trend.per_week < 4, String(m.trend.per_week)); assert.ok(m.forecast_30d >= 80 && m.forecast_30d <= 100);
  assert.ok(m.unusual && m.unusual.direction === 'down', 'today well below the last two weeks');
  assert.equal(m.pillar_change.cyber, 7);
  assert.equal(X.learn(h.slice(-5), 70).trend, null, 'fewer than 7 days: no trend');
});

test('attention: decisions and risks first, worsening KPIs, gaps last; nothing improving is listed', () => {
  const p = X.pillars({ report: report(), ciso: ciso(), riskSum: risk().summary });
  const a = X.attention({ ciso: ciso(), risks: risk().risks, insights: insights(), pillarsOut: p.pillars });
  assert.deepEqual(a.slice(0, 2).map((x) => x.kind).sort(), ['decision', 'risk'], 'a high decision and a high, over-appetite risk lead');
  assert.match(a.find((x) => x.kind === 'risk').why, /above the risk appetite/);
  assert.ok(a.some((x) => x.kind === 'decision' && /FW-SYN-1/.test(x.title)));
  assert.ok(a.some((x) => x.kind === 'trend' && /DR readiness/.test(x.title))); assert.ok(!a.some((x) => /Register health/.test(x.title)), 'an improving KPI is not a problem');
  assert.ok(!a.some((x) => /Minor/.test(x.title)), 'a low risk is not escalated');
});

async function setup(t, src) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = T0; registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now });
  const asked = [];
  e.app.addons.reportCenter = { build: async (id) => { if (src.fail) throw new Error('report store down'); return report(); }, insights: async () => insights(),
    aiStatus: () => ({ enabled: true, model: 'm' }), ask: async (b, who) => { asked.push({ b, who }); return { answer: 'Headline: adequate.', steps: [{ tool: 'report' }] }; } };
  e.app.addons.ciso = { overview: async () => ciso() }; e.app.addons.riskStudio = { view: () => risk() };
  return { e, asked, at: (x) => { now = x; } };
}

test('routes: viewer reads (records today once), failing source said, admin snapshot audited, brief via the Reporting Center (operator), refused cases, validation', async (t) => {
  const s = await setup(t, {});
  const v = (await s.e.req('GET', '/exec-dashboard', VW)).json;
  assert.ok(v.index > 0); assert.equal(v.pillars.length, 5); assert.equal(v.decisions_waiting, 1); assert.equal(v.risks.high, 2); assert.equal(v.can_snapshot, false); assert.equal(v.ai.for_role, false);
  assert.equal(v.history.length, 1, 'today recorded once'); await s.e.req('GET', '/exec-dashboard', VW); assert.equal(s.e.app.store.collection('exec_hist').all().length, 1);
  assert.ok(v.sections.some((x) => x.id === 'security' && x.state === 'not_installed'));
  assert.equal((await s.e.req('POST', '/exec-dashboard/snapshot', OP)).status, 403);
  const sn = await s.e.req('POST', '/exec-dashboard/snapshot', ADM); assert.equal(sn.status, 200); assert.equal(sn.json.index, v.index);
  assert.ok(s.e.app.store.auditTail(50).some((a) => a.action === 'exec.snapshot' && a.by === 'syed' && a.role === 'admin'));
  assert.equal((await s.e.req('POST', '/exec-dashboard/brief', VW)).status, 403);
  const bad = await s.e.req('POST', '/exec-dashboard/brief', { body: { question: 'x' }, ...OP }); assert.equal(bad.status, 400); assert.match(bad.text, /question/);
  const b = await s.e.req('POST', '/exec-dashboard/brief', OP); assert.equal(b.status, 200); assert.match(b.json.answer, /Headline/);
  assert.equal(s.asked[0].b.report, 'executive'); assert.equal(s.asked[0].who.user, 'nora.syn', 'asked as the operator, not as a service');
  assert.ok(s.e.app.store.auditTail(50).some((a) => a.action === 'exec.brief' && a.by === 'nora.syn'));
});

test('a failing source is reported, not zeroed; with too little the index is withheld and snapshot refuses', async (t) => {
  const s = await setup(t, { fail: true });
  s.e.app.addons.ciso = { overview: async () => { throw new Error('ciso timeout'); } };
  const v = (await s.e.req('GET', '/exec-dashboard', VW)).json;
  assert.equal(v.index, null); assert.match(v.withheld_why, /pillars measured/);
  assert.ok(v.sources.some((x) => x.name === 'Reporting Center' && x.state === 'error' && /report store down/.test(x.error)));
  assert.ok(v.attention.some((x) => x.kind === 'gap'));
  const sn = await s.e.req('POST', '/exec-dashboard/snapshot', ADM); assert.equal(sn.status, 409); assert.match(sn.text, /withheld/);
});
