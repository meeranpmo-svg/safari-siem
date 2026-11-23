// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Continuous Compliance & Auto-Remediation (continuous-compliance.html) against the REAL ITAM engine (engine/contcomp-intel.js) over a
// SYNTHETIC gap analysis with a day of history: ring and KPIs; frameworks with yesterday's value; drift chips (new / resolved / open);
// a gap raised as a GRC action by an operator; the administrator switches auto-remediation on, an operator cannot; a hostile title
// stays text; a viewer has no action; the advisor off until allowed; menu entry, installer, the portal's contcomp redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node continuous-compliance.test.js
const gap = (key, sev, title) => ({ key, title: title || 'Synthetic gap ' + key, severity: sev, frameworks: ['ecc'], refs: [{ fw: 'ecc', id: key.split(':')[1], level: 'not', why: '' }], priority: 50 });
const S = { items: [gap('ECC:2-2-1', 'high'), gap('ECC:2-3-1', 'medium')], pct: 60 };
require('./intel-harness')({ file: 'continuous-compliance.html', view: 'contcomp', clockStart: Date.now() - 86400000,
  after: async (e, col, tick) => {
    e.app.addons.crosswalk = { gaps: async () => ({ items: JSON.parse(JSON.stringify(S.items)), frameworks: { ecc: { available: true, pct_fully: S.pct, gaps: S.items.length } }, names: { ecc: 'NCA ECC' }, forecast: {} }) };
    await e.app.addons.contcompIntel.snapshot(); tick(86400000);
    S.items = [gap('ECC:2-3-1', 'medium'), gap('ECC:2-9-9', 'high', '<img src=x onerror="window.__xss=1"> new gap')]; S.pct = 50; } },
async (h) => {
  let p = await h.page();
  h.ok(/new drift today/.test(await h.text(p, '#zi-hero')) && /Auto-remediation/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(/down from 60/.test(await h.text(p, '#sec-frameworks')), 'framework against yesterday');
  await p.click('[data-chip="drift|new"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-drift .zi-it').length === 1), 'new drift chip');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-drift').textContent)), 'a hostile title stays text');
  await p.click('[data-chip="drift|resolved"]'); h.ok(await h.wait(p, () => /ECC:2-2-1/.test(document.getElementById('sec-drift').textContent)), 'resolved chip');
  await p.click('[data-chip="drift|all"]');
  h.ok(await h.openCard(p, 'drift', 'ECC:2-3-1'), 'gap detail'); await p.click('#zi-dlgb button[type=submit]'); h.ok(await h.toast(p, 'ACT-\\d+ raised for ECC:2-3-1'), 'raised by an operator');
  h.ok(/administrators set it/.test(await h.text(p, '#zi-set')) && !(await p.$('#zi-sform')), 'an operator cannot switch auto-remediation');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('syed', 'admin'); p = await h.page();
  await p.selectOption('#zi-sform [name=auto_raise]', 'high'); await p.click('#zi-sform button[type=submit]');
  h.ok(await h.toast(p, 'Settings saved'), 'the administrator switches it on'); h.ok(await h.wait(p, () => /on · high/.test(document.getElementById('zi-hero').textContent)), 'the KPI follows');
  h.who('vera.syn', 'viewer'); p = await h.page(); await h.openCard(p, 'drift', 'ECC:2-9-9'); h.ok(!(await p.$('#zi-dlgb form')), 'a viewer has no action');
});
