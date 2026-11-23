// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Platform Map (engine/platform-map.js): each source's state comes from what the platform holds - not connected when nothing is
// there, connected when data arrived, error with the reason when a read failed or nothing new came for a week; outcomes carry
// live counts (assets, open vulnerabilities); the AI mode comes from the AI Engine; viewer may read. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, ADM = { user: 'syed', role: 'admin' };
const T = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;

test('empty platform: every source not connected, with what to connect; nothing invented', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/platform-map', VIEW); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.sources.length, 14);
  for (const s of r.json.sources.filter((x) => x.id !== 'siem')) assert.equal(s.state, 'not_connected', s.id + ': ' + s.detail);
  assert.equal(r.json.outcomes.find((o) => o.id === 'assets').value, 0);
  assert.equal(r.json.stages.length, 5); assert.match(r.json.stages[4].label, /person approves/);
  assert.notEqual((await e.req('GET', '/platform-map', { user: '', role: '' })).status, 200, 'needs a signed-in user');
});

test('sources: connected from real data, error with the reason, stale data flagged; live outcome counts; AI mode', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const c = (n) => e.app.store.collection(n), iso = (d) => new Date(T - d * DAY).toISOString();
  c('virt_platforms').put({ id: 'v1', label: 'vCenter SYN', last_sync: { at: iso(0), ok: true } });
  c('virt_platforms').put({ id: 'v2', label: 'Prism SYN', last_sync: { at: iso(0), ok: false, error: 'HTTP 401 (synthetic)' } });
  c('storage_platforms').put({ id: 's1', label: 'NetApp SYN', last_sync: { at: iso(0), ok: false, error: 'certificate not trusted (synthetic)' } });
  c('vulnscan_results').put({ id: 'r1', hosts: ['10.0.0.1'], at: iso(2) });
  c('vulnscan_findings').put({ id: 'f1', status: 'open' }); c('vulnscan_findings').put({ id: 'f2', status: 'fixed' });
  c('me_ec_computers').put({ id: 'ec1', name: 'PC-SYN-1', seen_at: iso(20) });
  e.app.assets.create({ name: 'SRV-SYN-1', type: 'server', status: 'in_use' }, ADM);
  const v = (await e.req('GET', '/platform-map', VIEW)).json, S = (id) => v.sources.find((s) => s.id === id);
  assert.equal(S('virt').state, 'error'); assert.match(S('virt').detail, /1 of 2 read, 1 failing/);
  assert.equal(S('storage').state, 'error'); assert.match(S('storage').detail, /certificate not trusted/);
  assert.equal(S('vuln').state, 'connected'); assert.match(S('vuln').detail, /Greenbone/);
  assert.equal(S('endpoint').state, 'error', 'nothing new from Endpoint Central for 20 days'); assert.match(S('endpoint').detail, /more than 7 days/);
  assert.equal(v.outcomes.find((o) => o.id === 'assets').value, 1); assert.equal(v.outcomes.find((o) => o.id === 'vulns').value, 1, 'a fixed finding is not open');
  assert.equal(v.summary.connected + v.summary.error + v.summary.not_connected, 14);
  assert.ok(['anthropic', 'local', 'off'].includes(v.ai.mode));
});

test('ML: itemised readiness, outcome confidence with missing sources, next actions, daily history, regressions, flapping, trend', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let NOW = T - 20 * DAY; registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const c = (n) => e.app.store.collection(n), M = e.app.addons.platformMap;
  // empty: readiness counts only what is there; the trend is withheld with the reason
  let v = (await e.req('GET', '/platform-map', VIEW)).json;
  assert.equal(v.readiness.items.length, 14); assert.equal(v.readiness.items.reduce((a, i) => a + i.weight, 0), 100, 'weights sum to 100');
  assert.ok(v.readiness.insights.some((i) => /Trend withheld: 1 day/.test(i.text)));
  assert.equal(v.outcomes.find((o) => o.id === 'vulns').confidence, 0); assert.deepEqual(v.outcomes.find((o) => o.id === 'vulns').missing.map((m) => m.id), ['vuln']);
  assert.equal(v.readiness.next[0].id, 'vuln', 'the source carrying most output ranks first'); assert.ok(v.readiness.next[0].outcomes.includes('Unified vulnerabilities'));
  // 14 daily snapshots: virtualization delivers all the time, storage flaps, Greenbone connects on day 10 (readiness rises)
  const iso = () => new Date(NOW).toISOString();
  for (let d = 0; d < 14; d++) {
    NOW = T - (14 - d) * DAY;
    c('virt_platforms').put({ id: 'v1', label: 'vCenter SYN', last_sync: { at: iso(), ok: true } });
    c('storage_platforms').put({ id: 's1', label: 'NetApp SYN', last_sync: { at: iso(), ok: d % 2 === 0, error: 'HTTP 401 (synthetic)' } });
    if (d >= 10) c('vulnscan_results').put({ id: 'r' + d, hosts: ['10.0.0.1'], at: iso() });
    const snap = M.snapshot(); assert.equal(snap.day, iso().slice(0, 10));
  }
  NOW = T; c('virt_platforms').put({ id: 'v1', label: 'vCenter SYN', last_sync: { at: new Date(T).toISOString(), ok: false, error: 'HTTP 503 (synthetic)' } });
  v = (await e.req('GET', '/platform-map', VIEW)).json;
  const S = (id) => v.sources.find((s) => s.id === id), I = v.readiness.insights.map((i) => i.text).join(' | ');
  assert.equal(S('virt').history.length, 30); assert.equal(S('virt').days_delivering, 14, 'days delivering counted from the snapshots');
  assert.equal(S('virt').weight, 5); assert.ok(S('virt').feeds.includes('assets'));
  assert.match(I, /Virtualization regressed since/, I); assert.match(I, /Storage is unstable: its state changed \d+ times in 14 days/);
  assert.match(I, /Readiness is improving by about/, 'Greenbone connected: readiness rose'); assert.match(I, /reaches 80 around \d{4}-\d\d-\d\d/);
  assert.match(I, /Unified vulnerabilities runs on|Security coverage gaps runs on \d+% of its sources - missing:/);
  const it = v.readiness.items.find((x) => x.id === 'vuln'); assert.equal(it.points, 14); assert.match(it.why, /delivering \(\+14\)/);
  assert.equal(v.readiness.items.find((x) => x.id === 'virt').points, 2.5, 'needs attention counts half');
  assert.equal(v.outcomes.find((o) => o.id === 'vulns').confidence, 100);
  assert.ok(!v.readiness.next.some((n) => n.id === 'vuln'), 'a delivering source is not proposed');
  assert.equal(v.readiness.next.find((n) => n.id === 'virt').action, 'fix');
  // 90 days kept
  NOW = T + 100 * DAY; M.snapshot(); assert.ok(c('platform_map_hist').all().every((r) => r.day >= new Date(T + 10 * DAY).toISOString().slice(0, 10)), 'snapshots older than 90 days are dropped');
});
