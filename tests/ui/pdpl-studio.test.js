// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL Studio (pdpl-studio.html) against the REAL ITAM engines (PDPL register with its Python rules, engine/pdpl-studio-intel.js): ring and
// KPIs; compliance by area; the biggest gains; area cards with chips and detail; every requirement with chips, search and its next action;
// lapsing confirmations and learning say when there is nothing yet; the statement and the SDAIA note; a viewer reads; the advisor off
// until allowed; menu entry, installer, portal views (pdpl -> PDPL Studio).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-studio.test.js
require('./intel-harness')({ file: 'pdpl-studio.html', view: 'pdpl' },
async (h) => {
  h.who('syed.syn', 'admin'); let p = await h.page();
  // every tile opens what it counts: the area cards or the requirements filtered, the readiness statement, the trend
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    h.ok(zs.join() === 'areacards|gaps,areacards|confirm,requirements|not_assessed,requirements|regressed,requirements|expiring,requirements|conflict,readiness,trend', 'each tile opens its filter: ' + zs.join(' '));
    await p.click('#zi-hero .zi-kpi[data-zchip="not_assessed"]');
    h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="requirements|not_assessed"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-requirements').classList.contains('zi-flash'); }), 'Not assessed: the requirements filtered to those not assessed, highlighted');
    await p.click('[data-chip="requirements|all"]'); }
  const hero = await h.text(p, '#zi-hero');
  h.ok(/PDPL compliance/.test(hero) && /Not compliant/.test(hero) && /DPO to confirm/.test(hero) && /Statement/.test(hero), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-areas .zi-bar', (x) => x.length >= 10), 'compliance by area');
  h.ok(await p.$$eval('#sec-gains .zi-it, #sec-gains li, #sec-gains [data-open]', (x) => x.length > 0), 'biggest gains');
  h.ok(await p.$$eval('#sec-areacards .zi-it', (x) => x.length >= 10), 'area cards');
  h.ok(await h.openCard(p, 'areacards', 'a-Governance'), 'area detail'); h.ok(/P-01/.test(await h.text(p, '#zi-dlgb')), 'its requirements in the detail'); await h.closeDlg(p);
  h.ok(await p.$$eval('#sec-requirements tbody tr', (x) => x.length === 24), 'every requirement');
  await p.click('[data-chip="requirements|not_assessed"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-requirements tbody tr')].every((r) => /not assessed|DPO/.test(r.textContent))), 'not-assessed chip');
  await p.click('[data-chip="requirements|all"]'); await p.fill('[data-q="requirements"]', 'P-09'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-requirements tbody tr').length === 1), 'search');
  await p.fill('[data-q="requirements"]', '');
  h.ok(await h.openCard(p, 'requirements', 'P-09'), 'requirement detail'); h.ok(/Next action/.test(await h.text(p, '#zi-dlgb')) && /Points if confirmed compliant/.test(await h.text(p, '#zi-dlgb')), 'next action and its points'); await h.closeDlg(p);
  h.ok(/No confirmation lapses/.test(await h.text(p, '#sec-expiring')), 'lapsing says when there is none');
  h.ok(/Not enough history|No compliant/.test(await h.text(p, '#sec-learning')), 'learning says when there is too little history');
  h.ok(/not an SDAIA certificate/.test(await h.text(p, '#sec-basis')), 'not an SDAIA certificate');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  h.ok(await p.$$eval('#sec-requirements tbody tr', (x) => x.length === 24), 'a viewer reads the register');
});
