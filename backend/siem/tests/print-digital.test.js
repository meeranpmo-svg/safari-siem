// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Print to Digital (engine/printers/digital.js) over a SYNTHETIC printer fleet: pages per department from the printers' own counters,
// then from imported usage reports (colour share, cost); the idea that replaces printing for each kind of department with its estimated
// saving; paper in reams and kg (5 g a sheet); printers to consolidate and sites to right-size; trend and progress against a
// baseline and target; placeholder prices said; the route is a read for any signed-in user, settings are admin, validated and audited;
// no person's printing is shown.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createState } = require('../engine/soc/state');
const PD = require('../engine/printers/digital');

const P = (id, dept, site, p30, o) => Object.assign({ id, name: 'PRN-' + id, department: dept, site, pages_30d: p30, pages_by_day: [{ day: '2026-11-01', pages: Math.round(p30 / 2) }, { day: '2026-11-02', pages: Math.round(p30 / 2) }], snapshot: { ok: true } }, o || {});
function fakePrinters(items, periods) { return { view: async () => ({ items }), usage: () => ({ periods: periods || [] }) }; }

test('from the counters: departments, ideas, paper, fleet, insights', async () => {
  const items = [P('1', 'Finance', 'Riyadh Head Office', 9000), P('2', 'Human Resources', 'Riyadh Head Office', 4000), P('3', 'Projects and Site Workforce', 'Jubail Project Site', 6000), P('4', 'Finance', 'Riyadh Head Office', 120)];
  for (let i = 0; i < 6; i++) items.push(P('s' + i, 'Operations and Maintenance', 'Yanbu Project Site', 400));
  const st = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'pd-')) }), X = PD.createPrintDigital({ printers: fakePrinters(items), state: st });
  const v = await X.view();
  assert.match(v.source, /page counters/); assert.equal(v.kpis.pages_month, 9000 + 4000 + 6000 + 120 + 2400);
  const fin = v.departments.find((d) => d.name === 'Finance'); assert.equal(fin.pages, 9120); assert.equal(fin.printers, 2); assert.match(fin.idea, /Oracle Fusion/); assert.equal(fin.can_save_pct, 55);
  assert.match(v.departments.find((d) => d.name === 'Human Resources').idea, /e-signature/); assert.match(v.departments.find((d) => /Projects/.test(d.name)).idea, /tablets/);
  assert.equal(v.kpis.paper_kg_year, Math.round(v.kpis.pages_month * 12 * 5 / 1000)); assert.equal(v.kpis.reams_year, Math.round(v.kpis.pages_month * 12 / 500));
  assert.ok(v.fleet.some((f) => f.printer === 'PRN-4' && f.kind === 'consolidate')); assert.ok(v.fleet.some((f) => f.site === 'Yanbu Project Site' && f.kind === 'right-size'));
  assert.ok(v.insights.some((i) => /Finance prints the most/.test(i.title)) && v.insights.some((i) => /placeholder prices/.test(i.title)));
  assert.equal(v.roadmap.length, 3);
});

test('from usage reports: colour share, cost, trend, progress against target; settings validated; route roles and audit', async () => {
  const dept = (name, pages, color, cost) => ({ name, pages, color, mono: pages - color, cost, jobs: 10 });
  const periods = [['2026-06', 30000], ['2026-07', 29000], ['2026-08', 28000], ['2026-09', 26000], ['2026-10', 24000], ['2026-11', 21000]].map(([period, pages], i) => ({ id: 'u' + i, period, totals: { pages, color: Math.round(pages * 0.3), mono: 0, cost: 0 },
    by_department: [dept('Finance', Math.round(pages * 0.5), Math.round(pages * 0.2), 0), dept('Procurement', Math.round(pages * 0.3), Math.round(pages * 0.05), 0), dept('Legal', Math.round(pages * 0.2), Math.round(pages * 0.05), 0)], by_user: [{ name: 'a.person' }] }));
  const st = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'pd-')) }), X = PD.createPrintDigital({ printers: fakePrinters([P('1', 'Finance', 'Riyadh', 100)], periods), state: st });
  let v = await X.view();
  assert.match(v.source, /usage report 2026-11/); assert.equal(v.kpis.pages_month, 21000); assert.equal(v.kpis.colour_pct, 30); assert.ok(v.trend_per_period === undefined && v.kpis.trend_per_period < 0, 'falling');
  assert.equal(v.kpis.baseline, 29000, 'the first three months'); assert.equal(v.kpis.progress_pct, 28); assert.ok(v.insights.some((i) => /28% below the baseline \(target 30%\)/.test(i.title)) && v.insights.some((i) => /colour/.test(i.title)));
  assert.ok(!JSON.stringify(v).includes('a.person'), 'no person\'s printing');
  assert.throws(() => X.setSettings({ cost_mono: -1 }, 'adm'), /cost_mono/); assert.throws(() => X.setSettings({ currency: 'riyal' }, 'adm'), /currency/);
  X.setSettings({ cost_mono: 0.08, cost_colour: 0.5, target_pct: 25, extra: 1 }, 'adm'); v = await X.view(); assert.equal(v.settings.cost_mono, 0.08); assert.equal(v.settings.extra, undefined); assert.ok(!v.insights.some((i) => /placeholder/.test(i.title)));
  // routes
  const R = {}, audits = [], RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  PD.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state: st, log: { error() {} } }, fakePrinters([P('1', 'Finance', 'Riyadh', 100)]));
  const call = async (m, p, b, role) => { const o = {}; const ctx = { role, user: role + '.syn', body: b, params: {}, audit: (a, t, d) => audits.push(a), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' /api/soc' + p](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('GET', '/printers/digital', undefined, 'viewer')).s, 200);
  assert.equal((await call('PUT', '/printers/digital/settings', { target_pct: 40 }, 'operator')).s, 403);
  assert.equal((await call('PUT', '/printers/digital/settings', { target_pct: 400 }, 'admin')).s, 400);
  assert.equal((await call('PUT', '/printers/digital/settings', { target_pct: 40 }, 'admin')).s, 200); assert.ok(audits.includes('printers.digital.settings'));
});
