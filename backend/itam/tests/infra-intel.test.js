// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Infrastructure Automation intelligence (engine/infra-intel.js) over SYNTHETIC sentra-infra reads: disk / connection forecasts (fit gate),
// recurring and flapping findings, noisy self-clearing rules, MTTA / MTTR now vs before, an unusual day, coverage gaps, itemised risk per
// target and fleet index, ranked actions; the route through a stubbed link (viewer reads, the advisor refused to a viewer, a service
// identity cannot ask), not connected is said; the link's get refuses a bad path.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const I = require('../engine/infra-intel');

const NOW = Date.parse('2026-11-19T09:00:00Z'), H = 3600000, D = 86400000, iso = (t) => new Date(t).toISOString();
function src() {
  const targets = [
    { id: 't1', kind: 'host', name: 'app-syn-01', site: 'Riyadh', status: 'ok', enabled: true, last_seen: iso(NOW - 600000), credential_ref: 'c1', credential_set: true, credential_delivered: true },
    { id: 't2', kind: 'host', name: 'web-syn-02', status: 'ok', enabled: true, last_seen: iso(NOW - 5 * H) },
    { id: 't3', kind: 'device', name: 'sw-syn-03', status: 'never', enabled: true, last_seen: null, credential_ref: 'c3', credential_set: false },
    { id: 't4', kind: 'db', name: 'pg-syn-04', status: 'ok', enabled: true, last_seen: iso(NOW - 300000) },
    { id: 't5', kind: 'host', name: 'old-syn-05', enabled: false }];
  // disk on t1 rises 2 % a day from 70; t4 noisy (no fit)
  const hist = []; for (let h = 72; h >= 0; h -= 6) hist.push({ at: iso(NOW - h * H), disk_max_pct: 70 + (72 - h) / 24 * 2 });
  const noisy = []; for (let h = 72; h >= 0; h -= 6) noisy.push({ at: iso(NOW - h * H), conn_pct: h % 12 ? 20 : 80 });
  const findings = [];
  for (let k = 0; k < 6; k++) findings.push({ id: 'f' + k, target_id: 't2', rule: 'load_high', subject: '', severity: 'warning', title: 'Load high', status: k === 5 ? 'open' : 'cleared', first_seen: iso(NOW - k * D) });
  for (let k = 0; k < 3; k++) findings.push({ id: 'g' + k, target_id: 't1', rule: 'svc_failed', subject: 'nginx', severity: 'critical', title: 'Service failed', status: k === 0 ? 'open' : 'cleared', first_seen: iso(NOW - (k * 9 + 1) * D) });
  const incidents = [];
  for (let k = 0; k < 6; k++) incidents.push({ id: 'n' + k, target_id: 't2', title: 'Load high', severity: 'warning', status: 'resolved', resolution: 'auto', opened_at: iso(NOW - k * D - 2 * H), resolved_at: iso(NOW - k * D - 2 * H + 10 * 60000) });
  incidents.push({ id: 'c1', target_id: 't1', title: 'Service failed', severity: 'critical', status: 'resolved', resolution: 'manual', opened_at: iso(NOW - 5 * D), acked_at: iso(NOW - 5 * D + 10 * 60000), resolved_at: iso(NOW - 5 * D + 90 * 60000) });
  incidents.push({ id: 'c0', target_id: 't1', title: 'Service failed', severity: 'critical', status: 'resolved', resolution: 'manual', opened_at: iso(NOW - 40 * D), acked_at: iso(NOW - 40 * D + 5 * 60000), resolved_at: iso(NOW - 40 * D + 30 * 60000) });
  for (let k = 0; k < 6; k++) incidents.push({ id: 'x' + k, target_id: 't4', title: 'Connections high', severity: 'warning', status: 'open', opened_at: iso(NOW - H - k * 60000) });
  return { summary: { targets: { by_kind: { device: 1 } }, configs: { devices_with_baseline: 0 }, fingerprints_pending: 1 }, targets, findings, incidents, histories: { t1: { points: hist }, t4: { points: noisy } }, probes: [{ id: 'p1', name: 'probe-syn', online: false }] };
}

test('forecast, recurrence, noise, response, coverage, risk and index - each with its reason', () => {
  const v = I.analyse(Object.assign(src(), { now: NOW }));
  assert.equal(v.forecast.length, 1, 'the noisy connection series is not projected'); const f = v.forecast[0];
  assert.equal(f.target, 'app-syn-01'); assert.equal(f.slope_per_day, 2); assert.equal(f.current, 76); assert.equal(f.at90.days, 7); assert.equal(f.at100.days, 12); assert.ok(f.r2 > 0.99);
  const lr = v.recurring.find((g) => g.rule === 'load_high'); assert.ok(lr.flapping && lr.n7 === 6); assert.match(lr.why, /flapping/);
  const sv = v.recurring.find((g) => g.rule === 'svc_failed'); assert.ok(!sv.flapping && sv.n30 === 3 && sv.severity === 'critical');
  assert.equal(v.noise.length, 1); assert.equal(v.noise[0].title, 'Load high'); assert.equal(v.noise[0].share_pct, 100);
  assert.equal(v.response.now.critical.mtta_min, 10); assert.equal(v.response.now.critical.mttr_min, 90); assert.equal(v.response.before.critical.mttr_min, 30);
  assert.equal(v.response.now.warning.mttr_min, null, 'auto-resolved is not a person\'s MTTR');
  assert.ok(v.unusual && v.unusual.today >= 6, 'unusual day');
  const kinds = v.coverage.map((c) => c.kind).sort(); assert.deepEqual(kinds, ['baseline', 'fingerprint', 'never', 'probe', 'stale']);
  assert.match(v.coverage.find((c) => c.kind === 'never').fix, /credential/);
  const r1 = v.risk.find((r) => r.id === 't1'); assert.ok(r1.items.some((i) => /critical finding/.test(i.label)) && r1.items.some((i) => /fullest disk reaches 100 % in about 12/.test(i.label)));
  assert.equal(v.risk.find((r) => r.id === 't5'), undefined, 'disabled targets are not scored'); assert.equal(v.risk[0].id, 't1');
  assert.ok(v.index.score < 100 && v.index.items.some((i) => /not fully monitored/.test(i.label)));
  assert.match(v.actions[0].what, /app-syn-01/); assert.ok(v.actions.some((a) => /Tune the rule "Load high"/.test(a.what)));
  assert.equal(I.analyse({ now: NOW }).index.score, null, 'no target = not measured');
});

test('route: through the link, viewer reads; not connected says so; the advisor; the link refuses a bad path', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  I.registerInfraIntel(e.app.srv, e.app, { now: () => NOW, noTimer: true });
  let r = await e.req('GET', '/infra-intel', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ring.value, null); assert.match(r.json.sections[0].text, /not installed/);
  const S = src(), calls = [];
  e.app.addons.infraSync = { get: async (p, who) => { calls.push([p, who.user]); if (p === '/summary') return S.summary; if (p === '/targets') return { targets: S.targets }; if (p.startsWith('/findings')) return { findings: S.findings }; if (p.startsWith('/incidents')) return { incidents: S.incidents }; if (p === '/probes') return { probes: S.probes }; const m = p.match(/^\/(hosts|db)\/(.+)$/); return { history: S.histories[m[2]] || { points: [] } }; } };
  r = await e.req('GET', '/infra-intel', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.ring.value < 100); assert.ok(calls.every((c) => c[1] === 'vera.syn'), 'read as the asking person');
  assert.ok(calls.some((c) => c[0] === '/hosts/t1') && !calls.some((c) => c[0] === '/hosts/t5'), 'history of enabled hosts only');
  const sec = (id) => r.json.sections.find((s) => s.id === id);
  assert.equal(sec('forecast').rows[0].title, 'app-syn-01'); assert.match(sec('forecast').caption, /not a promise/);
  assert.equal(sec('risk').items[0].id, 't1'); assert.ok(sec('noise').items.length === 1);
  assert.equal((await e.req('POST', '/infra-intel/ask', { user: 'vera.syn', role: 'viewer', body: { question: 'what needs attention?' } })).status, 403);
  assert.equal((await e.req('POST', '/infra-intel/ask', { user: 'ai:infra', role: 'operator', body: { question: 'what needs attention?' } })).status, 403);
  r = await e.req('POST', '/infra-intel/ask', { user: 'nora.syn', role: 'operator', body: { question: 'hi' } }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  r = await e.req('POST', '/infra-intel/ask', { user: 'nora.syn', role: 'operator', body: { question: 'what needs attention?' } }); assert.equal(r.status, 424, 'AI off until allowed');
  // the real link: GET only, and a bad path is refused before any request
  const { createInfraSync } = require('../engine/infra-sync'); let req = 0;
  const N = createInfraSync(e.app, { request: async () => { req++; return { status: 200, body: '{}', headers: {} }; }, readFile: () => 'x'.repeat(32) });
  await assert.rejects(N.get('/../../etc/passwd\n', { user: 'nora.syn' }), (er) => er.status === 400); assert.equal(req, 0);
});
