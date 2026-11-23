// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Applications Manager insights (engine/integrations/apm-insights.js) over a SYNTHETIC APM snapshot and 5-minute samples: reliability
// (availability, outage episodes, MTTR, MTBF, flapping); problems scored with every point named; two monitors down on one host grouped
// under the host as the probable cause; alarm episodes - noisy (5+ in 7 days) and long open (critical 24 h+); stale polling; unmanaged
// with no maintenance request; the daily trend with an unusual day; not installed / not connected say what to do; the route is open to
// every signed-in role and keeps one sample a day.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const X = require('../engine/integrations/apm-insights');

const T = Date.parse('2026-11-04T08:00:00Z'), SLOT = 300000, D = 86400000;
const series = (n, fn) => Array.from({ length: n }, (_, i) => ({ t: T - (n - i) * SLOT, up: fn(i) ? 1 : 0, h: fn(i) ? 0 : 2 }));
const MON = [
  { id: '101', name: 'ERP web', type: 'URL Monitor', host: 'app01.syn', availability: 'down', health: 'critical', managed: true, last_polled: String(T - 60000), db: false },
  { id: '102', name: 'ERP Tomcat', type: 'Tomcat', host: 'app01.syn', availability: 'down', health: 'critical', managed: true, last_polled: String(T - 60000), db: false },
  { id: '201', name: 'Claims DB', type: 'Oracle DB', host: 'db01.syn', availability: 'up', health: 'critical', managed: true, last_polled: String(T - 3 * 3600000), db: true },
  { id: '301', name: 'Portal API', type: 'REST API', host: 'api01.syn', availability: 'up', health: 'clear', managed: true, last_polled: String(T - 60000), db: false },
  { id: '401', name: 'Old intranet', type: 'URL Monitor', host: 'old.syn', availability: 'up', health: 'clear', managed: false, last_polled: '', db: false },
];
const ALARMS = [{ resource_id: '201', name: 'Claims DB', severity: 'critical', attribute: 'Tablespace', message: 'USERS 97 %', time: String(T - 30 * 3600000) }];
const fakeApm = (o = {}) => ({ status: () => Object.assign({ configured: true, last_sync: T - 60000 }, o.status), settings: () => ({ poll_min: 5 }), monitors: () => o.monitors || MON, alarms: () => o.alarms || ALARMS, actions: () => o.actions || [] });

test('reliability: availability, episodes, MTTR, MTBF, flapping', () => {
  const r = X.reliability(series(48, (i) => !(i >= 10 && i < 14) && !(i >= 30 && i < 32)));
  assert.equal(r.samples, 48); assert.equal(r.episodes, 2); assert.equal(r.mttr_min, 15); assert.equal(r.availability, 87.5); assert.equal(r.mtbf_h, 2);
  assert.equal(X.reliability(series(24, (i) => i % 2 === 0)).flapping, true);
  assert.equal(X.reliability(series(5, () => true)).availability, null, 'fewer than 12 samples: no availability claimed');
});

test('problems ranked, host as probable cause, noisy and long-open alarms, hygiene, trend, actions', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'apmx-')) });
  const S = state.collection('webtier_samples');
  S.put({ id: '101', s: series(48, (i) => i < 46) }); S.put({ id: '102', s: series(48, (i) => i < 46) });
  S.put({ id: '301', s: series(48, (i) => i % 2 === 0) });
  // the Claims DB tablespace alarm opened and cleared 6 times this week
  state.collection('apm_alarm_hist').put({ id: '201|Tablespace', resource_id: '201', name: 'Claims DB', attribute: 'Tablespace', episodes: Array.from({ length: 6 }, (_, i) => ({ from: T - (i + 1) * D, to: T - (i + 1) * D + 1800000, severity: 'warning' })), open: null });
  // 20 quiet days, then today
  for (let i = 1; i <= 20; i++) state.collection('apm_daily').put({ id: 'd' + i, day: new Date(T - i * D + 3 * 3600000).toISOString().slice(0, 10), at: T - i * D, bad: 0, availability: 99.9 });
  const I = X.createApmInsights({ state, apm: fakeApm(), now: () => T });
  assert.equal(I.record(), 1, 'the open tablespace alarm starts an episode');
  const v = I.view();
  assert.equal(v.configured, true);
  assert.deepEqual(v.hosts.map((h) => h.host), ['app01.syn']); assert.equal(v.hosts[0].monitors.length, 2);
  assert.ok(v.problems.every((p, i) => !i || v.problems[i - 1].score >= p.score), 'ranked by score'); const top = v.problems.find((p) => p.id === '101'); assert.equal(top.cause_host, 'app01.syn'); assert.equal(top.score, Math.min(100, top.why.reduce((s, w) => s + w.points, 0)));
  assert.ok(top.why.some((w) => /^down$/.test(w.text)) && top.why.some((w) => /probably the host/.test(w.text)));
  const db = v.problems.find((p) => p.id === '201'); assert.ok(db.why.some((w) => /a database/.test(w.text)) && db.why.some((w) => /open for/.test(w.text)), JSON.stringify(db.why));
  assert.equal(v.noisy[0].attribute, 'Tablespace'); assert.equal(v.noisy[0].episodes_7d, 6);
  assert.equal(v.long_open[0].hours, 30, 'critical 30 h');
  assert.deepEqual(v.stale.map((s) => s.id), ['201']); assert.deepEqual(v.unmanaged.map((u) => [u.id, u.maintenance_request]), [['401', false]]);
  assert.equal(v.reliability.find((r) => r.id === '301').flapping, true);
  assert.equal(v.kpis.down, 2); assert.equal(v.kpis.cause_hosts, 1); assert.equal(v.trend.today_bad, 3, 'each monitor once even when down and critical (2 down + critical, 1 critical)'); assert.equal(v.trend.unusual, true);
  assert.equal(v.actions[0].filter, 'hosts');
  for (const f of ['long', 'trend', 'flapping', 'noisy', 'stale', 'unmanaged']) assert.ok(v.actions.some((a) => a.filter === f), f);
  assert.equal(state.collection('apm_daily').all().length, 21, 'one sample today');
  // the alarm clears: its episode closes
  const I2 = X.createApmInsights({ state, apm: fakeApm({ alarms: [] }), now: () => T + 600000 }); I2.record();
  const h = state.collection('apm_alarm_hist').get('201|Tablespace'); assert.equal(h.open, null); assert.equal(h.episodes.length, 7);
  // a maintenance request in flight is not "left unmanaged"
  const I3 = X.createApmInsights({ state, apm: fakeApm({ actions: [{ resource_id: '401', action: 'unmanage', status: 'pending' }] }), now: () => T });
  assert.equal(I3.view().unmanaged[0].maintenance_request, true);
});

test('not installed / not connected say what to do; the route is open to every role', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'apmx2-')) });
  assert.match(X.createApmInsights({ state, apm: null, now: () => T }).view().reason, /not installed/);
  assert.match(X.createApmInsights({ state, apm: fakeApm({ status: { configured: false } }), now: () => T }).view().reason, /not connected/);
  const R = {}; X.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, meApm: fakeApm(), noTimers: true, config: {}, log: { info() {}, warn() {}, error() {} } });
  const ctx = { role: 'viewer', user: 'vera.syn', body: {}, params: {}, query: {}, need: () => true, audit() {}, fail() {}, ok: (x) => x };
  const v = await R['GET /api/soc/integrations/apm/insights'](ctx); assert.equal(v.configured, true); assert.ok(v.problems.length);
});
