// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NDMO Studio (ndmo-studio.html) against the REAL ITAM engines (NDMO register with its Python rules, engine/ndmo-intel.js): ring and KPIs;
// score by domain; the biggest gains; domain cards with chips and detail; every control with chips, search and its next action; the
// learning lists; official list coverage; "turn gaps into GRC actions" run by an administrator through the register's own route; a
// viewer reads but has no action; the advisor off until allowed; menu entry, installer, portal view.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ndmo-studio.test.js
require('./intel-harness')({ file: 'ndmo-studio.html', view: 'ndmostudio' },
async (h) => {
  h.who('syed.syn', 'admin'); let p = await h.page();
  // every tile opens what it counts: its filter in the controls list, or the trend
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    h.ok(zs.join() === 'controls|gap,controls|pending,controls|no_evidence,controls|regressed,controls|conflict,trend', 'each tile opens its filter: ' + zs.join(' '));
    await p.click('#zi-hero .zi-kpi[data-zchip="no_evidence"]');
    h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="controls|no_evidence"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-controls').classList.contains('zi-flash'); }), 'No evidence: the controls filtered to those without evidence, highlighted'); }
  h.ok(/NDMO score/.test(await h.text(p, '#zi-hero')) && /Gaps/.test(await h.text(p, '#zi-hero')) && /(Awaiting|Waiting for) approval/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-domains .zi-bar', (x) => x.length === 15), 'score by domain');
  h.ok(await p.$$eval('#sec-gains .zi-it, #sec-gains li, #sec-gains [data-open]', (x) => x.length > 0), 'biggest gains');
  h.ok(await p.$$eval('#sec-domaincards .zi-it', (x) => x.length === 15), 'domain cards');
  h.ok(await h.openCard(p, 'domaincards', 'DQ'), 'domain detail'); h.ok(/Indicative maturity/.test(await h.text(p, '#zi-dlgb')), 'maturity in the detail'); await h.closeDlg(p);
  h.ok(await p.$$eval('#sec-controls tbody tr', (x) => x.length >= 40), 'every control');
  await p.click('[data-chip="controls|no_evidence"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-controls tbody tr')].every((r) => /no evidence/.test(r.textContent)) && document.querySelectorAll('#sec-controls tbody tr').length > 0), 'no-evidence chip');
  await p.click('[data-chip="controls|all"]'); await p.fill('[data-q="controls"]', 'ZS-DG-01'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-controls tbody tr').length === 1), 'search');
  await p.fill('[data-q="controls"]', '');
  h.ok(await h.openCard(p, 'controls', 'ZS-DG-01'), 'control detail'); h.ok(/Next action/.test(await h.text(p, '#zi-dlgb')) && /Score points if met/.test(await h.text(p, '#zi-dlgb')), 'next action and its score points'); await h.closeDlg(p);
  h.ok(/Not enough history|No control/.test(await h.text(p, '#sec-learning')), 'learning says when there is too little history');
  h.ok(/official/.test(await h.text(p, '#sec-official')), 'official list coverage');
  p.on('dialog', (d) => d.accept());
  await p.click('[data-gact="0"] button[type=submit]'); h.ok(await h.toast(p, 'Gaps sent to the GRC register|created|GRC'), 'gaps to GRC through the register route');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  h.ok(await p.$$eval('#sec-controls tbody tr', (x) => x.length >= 40), 'a viewer reads the register');
  h.ok(!(await p.$('[data-gact]')), 'a viewer has no action');
});
