// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security Controls -> Compliance (security-controls.html) against the REAL ITAM engines (GRC control monitoring + engine/controls-intel.js)
// with SYNTHETIC records: ring and KPIs; control cards with state chips and search; not connected said; a control's detail with the
// requirements it evidences; a failing control raised as a GRC action by an operator; a hostile asset name stays text; a viewer has no
// action; the advisor off until allowed; menu entry, installer, the portal's controls redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node security-controls.test.js
require('./intel-harness')({ file: 'security-controls.html', view: 'controls',
  seed: (e, col) => { col('assets').put({ id: 'A-1', name: 'srv01.syn', type: 'server', status: 'active' }); for (let i = 0; i < 10; i++) col('me_ec_computers').put({ id: 'PC-' + i, name: 'pc' + i + '.syn', critical: i < 5 ? 3 : 0 });
    col('disc_devices').put({ id: 'D-1', ip: '10.0.0.9', hostname: '<img src=x onerror="window.__xss=1">' }); } },
async (h) => {
  let p = await h.page();
  // every tile opens what it counts, named by the engine: the controls (all / failing / partial / regressed), the leverage
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    h.ok(zs.join() === 'controls|all,controls|fail,controls|partial,controls|regressed,leverage', 'each tile opens its list: ' + zs.join(' '));
    await p.click('#zi-hero .zi-kpi[data-zchip="fail"]');
    h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="controls|fail"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-controls').classList.contains('zi-flash'); }), 'Failing: the controls filtered to failing, highlighted');
    await p.click('[data-chip="controls|all"]'); }
  h.ok(/controls effective/.test(await h.text(p, '#zi-hero')) && /Requirements weakened/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-controls .zi-it', (x) => x.length >= 5), 'control cards');
  await p.click('[data-chip="controls|unknown"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-controls .zi-it')].every((c) => c.classList.contains('na')) && document.querySelectorAll('#sec-controls .zi-it').length > 0), 'not connected chip');
  await p.click('[data-chip="controls|fail"]'); h.ok(await h.wait(p, () => /Critical patches/.test(document.getElementById('sec-controls').textContent)), 'failing chip');
  await p.click('[data-chip="controls|all"]'); await p.fill('[data-q="controls"]', 'backup'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-controls .zi-it').length === 1), 'search');
  await p.fill('[data-q="controls"]', '');
  h.ok(/Critical patches/.test(await h.text(p, '#sec-leverage')), 'leverage lists the failing control');
  h.ok(await h.openCard(p, 'controls', 'patch'), 'control detail'); const d = await h.text(p, '#zi-dlgb');
  h.ok(/Requirements it evidences/.test(d) && /SAMA CSF/.test(d), 'the requirements it evidences');
  await p.fill('#zi-dlgb [name=owner]', 'nora.syn'); await p.click('#zi-dlgb button[type=submit]');
  h.ok(await h.toast(p, 'ACT-\\d+ raised'), 'a GRC action raised'); h.ok(await h.wait(p, () => /GRC action open/.test(document.getElementById('sec-controls').textContent)), 'the card says so');
  await h.openCard(p, 'controls', 'assets'); h.ok(await p.evaluate(() => !window.__xss) && /discovered/.test(await h.text(p, '#zi-dlgb')), 'a hostile record stays text'); await h.closeDlg(p);
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  await h.openCard(p, 'controls', 'patch'); h.ok(!(await p.$('#zi-dlgb form')) && /operators and administrators/.test(await h.text(p, '#zi-ai')), 'a viewer reads without actions');
});
