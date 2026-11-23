// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Business Continuity & DR Matrix (bcm-matrix.html) against the REAL ITAM engines (DR & BCM drills, engine/bcm-intel.js) with SYNTHETIC
// drills and a SYNTHETIC DR Studio: ring and KPIs; matrix cards with state chips; a system's readiness item by item; untested though
// replicated; a test action raised by an operator; a hostile system name stays text; a viewer has no action; the advisor off until
// allowed; menu entry, installer, the portal's bcm redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node bcm-matrix.test.js
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
require('./intel-harness')({ file: 'bcm-matrix.html', view: 'bcm',
  seed: (e, col) => { const put = (id, o) => col('grc_drills').put(Object.assign({ id, status: 'completed', type: 'failover', frequency_months: 12, result: 'pass', history: [], signoff: { by: 'syed', at: Date.now() } }, o));
    put('DR-0001', { system: 'Core insurance (synthetic)', executed: ago(60), rto_target_min: 240, rto_actual_min: 120, rpo_target_min: 60, rpo_actual_min: 20 });
    put('DR-0002', { system: '<img src=x onerror="window.__xss=1"> email', executed: ago(30), result: 'fail', rto_target_min: 60, rto_actual_min: 200 }); },
  after: async (e) => { e.app.addons.drStudio = { view: async () => ({ streams: [{ key: 'dg:hr', system: 'HR database (synthetic)', tech: 'Data Guard standby', lag_s: 120, rpo_s: 900 }] }) }; } },
async (h) => {
  let p = await h.page();
  h.ok(/DR readiness/.test(await h.text(p, '#zi-hero')) && /Untested/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-matrix .zi-it', (x) => x.length === 3), 'three systems');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-matrix').textContent)), 'a hostile name stays text');
  await p.click('[data-chip="matrix|untested"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-matrix .zi-it').length === 1 && /HR database/.test(document.getElementById('sec-matrix').textContent)), 'untested though replicated');
  await p.click('[data-chip="matrix|all"]');
  h.ok(await h.openCard(p, 'matrix', 'Core insurance (synthetic)'), 'system detail'); h.ok(/Readiness, item by item/.test(await h.text(p, '#zi-dlgb')) && /RTO met/.test(await h.text(p, '#zi-dlgb')), 'readiness itemised'); await h.closeDlg(p);
  await h.openCard(p, 'matrix', 'HR database (synthetic)'); await p.fill('#zi-dlgb [name=owner]', 'nora.syn'); await p.click('#zi-dlgb button[type=submit]');
  h.ok(await h.toast(p, 'ACT-\\d+ raised for HR database'), 'a test action raised');
  h.ok(await p.$$eval('#sec-readiness .zi-bar', (x) => x.length >= 2), 'readiness bars');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); await h.openCard(p, 'matrix', 'Core insurance (synthetic)'); h.ok(!(await p.$('#zi-dlgb form')), 'a viewer has no action');
});
