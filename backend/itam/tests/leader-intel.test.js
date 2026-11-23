// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leadership intelligence (engine/leader-intel.js) over SYNTHETIC register records and add-ons: the infrastructure health index
// (each area itemised; not measured is left out and the overall withheld below 3 areas); daily snapshots give trends, the storage
// forecast (date it reaches 85 %) and an unusual drop; the worklist is ranked; the renewal wave by month (overdue in month 1,
// unpriced counted, peak named); the CIO "this week" list; roles (viewer refused, operator reads), validation; the advisor
// refuses a viewer and a service identity.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const LI = require('../engine/leader-intel');

const ADM = { user: 'syed', role: 'admin', ip: '' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000;

test('health index: itemised, not measured left out, withheld below 3 areas', () => {
  const reg = { available: true, servers: { total: 8 }, network: { total: 2 }, storage: { total: 0 } };
  let h = LI.areaScores({ register: reg, backup: { available: true, protected: 6, failed: 1, stale: 0, none: 1, protected_pct: 75 }, patch: { available: false, why: 'ManageEngine is not installed' } }, reg);
  assert.equal(h.overall, null); assert.match(h.withheld_why, /3 measured areas \(1 so far\)/);
  assert.equal(h.areas.find((a) => a.id === 'patch').why, 'ManageEngine is not installed');
  h = LI.areaScores({ register: reg, backup: { available: true, protected: 6, failed: 1, stale: 0, none: 1, protected_pct: 75 },
    patch: { available: true, reported: 10, compliant: 8, critical_missing: 1, compliant_pct: 80 }, lifecycle: { available: true, eol: 1, soon: 2, isolation_required: 0 },
    storage: { available: true, used_pct: 82, read: 1, failed_disks: 0 } }, reg);
  assert.equal(h.measured, 4); assert.ok(h.overall > 0 && h.overall < 100);
  const st = h.areas.find((a) => a.id === 'storage'); assert.equal(st.score, 60); assert.match(st.items[0].label, /82% used/);
  assert.equal(h.areas.find((a) => a.id === 'patch').score, 76, '80 compliant less 4 for one critical in ten');
});

test('renewal wave: months, overdue in the first month, unpriced counted, peak named', () => {
  const w = LI.renewalWave([{ product: 'M365 E3 SYN', expiry: '2026-12-15', cost: 900000 }, { product: 'Old SYN', expiry: '2026-10-01', cost: 1000 }, { product: 'Unpriced SYN', expiry: '2027-02-01' }],
    [{ vendor: 'Cisco', product: 'SmartNet SYN', end: '2027-03-10', cost: 120000 }, { vendor: 'X', product: 'far', end: '2028-05-01', cost: 5 }], '2026-11-19');
  assert.equal(w.months.length, 12); assert.equal(w.months[0].month, '2026-11');
  assert.equal(w.months[0].amount, 1000); assert.equal(w.months[0].list[0].overdue, true);
  assert.equal(w.unpriced, 1); assert.equal(w.items, 4, 'beyond 12 months left out');
  assert.equal(w.peak.month, '2026-12'); assert.equal(w.total, 1021000); assert.equal(w.peak.share_pct, 88);
});

test('routes: trends, storage forecast, unusual drop, worklist and the CIO week; roles and validation', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let T = Date.parse('2026-11-19T06:00:00Z');
  const A = e.app.assets; for (let i = 0; i < 8; i++) A.create({ name: 'SRV-SYN-' + i, type: 'server', status: 'in_use' }, ADM);
  let used = 70, prot = 6;
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], summary: { assets: 8, protected: prot, stale: 0, failed: 8 - prot, none: 0, exempt: 0 } }) };
  e.app.addons.storage = { view: () => ({ arrays: [], summary: { arrays: 1, read: 1, used_pct: used, failed_disks: 0 } }) };
  e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'SRV-SYN-1', missing: 0 }, { name: 'SRV-SYN-2', missing: 3, critical: 1 }] }) };
  e.app.store.collection('licences').put({ id: 'lic-syn', product: 'M365 E3 SYN', expiry: '2026-12-01', cost: 500000, status: 'active' });
  const X = LI.registerLeaderIntel(e.app.srv, e.app, { now: () => T, noTimer: true });
  const snaps = e.app.store.collection('leader_intel_snaps');
  for (let d = 12; d >= 1; d--) { const id = new Date(T - d * DAY).toISOString().slice(0, 10); snaps.put({ id, at: id, overall: 80, backup: 75, patch: 50, storage: 100 - (82 - d) , storage_used: 70 - d * 0.5 }); }
  prot = 3;   // backup protection falls sharply today
  let r = await e.req('GET', '/leader-intel/infra', VW); assert.equal(r.status, 403);
  r = await e.req('GET', '/leader-intel/infra', Object.assign({ query: { x: '1' } }, OP)); assert.equal(r.status, 200, r.text);
  const v = r.json;
  assert.ok(v.health.overall != null); const bk = v.health.areas.find((a) => a.id === 'backup'); assert.equal(bk.score, 38);
  assert.ok(v.storage_forecast.measured && v.storage_forecast.at85.date, JSON.stringify(v.storage_forecast)); assert.match(v.storage_forecast.at85.why, /projection from past pace/);
  assert.ok(v.unusual.some((u) => u.id === 'backup' && u.change < 0), JSON.stringify(v.unusual) + JSON.stringify(v.history.map((h) => [h.day, h.backup])));
  assert.equal(v.worklist[0].title, '5 server backup(s) failing'); assert.ok(v.worklist.some((w) => /dropped unusually/.test(w.title)));
  assert.equal(snaps.get('2026-11-19').backup, 38, 'today snapshotted once');
  r = await e.req('GET', '/leader-intel/cio', OP); assert.equal(r.status, 200);
  const c = r.json; assert.equal(c.renewals.months[0].month, '2026-11'); assert.equal(c.renewals.total, 500000);
  assert.ok(c.this_week.some((x) => /Renewal in 12 days: M365 E3 SYN/.test(x.title)), JSON.stringify(c.this_week));
  assert.equal(c.infra.overall, v.health.overall, 'the CIO sees the same index');
  r = await e.req('POST', '/leader-intel/ask', Object.assign({ body: { question: 'What should we fix first?' } }, VW)); assert.equal(r.status, 403);
  await assert.rejects(X.ask({ question: 'What should we fix first?' }, { user: 'ai:leader', role: 'operator' }), /service or AI identity/);
  X.stop();
});
