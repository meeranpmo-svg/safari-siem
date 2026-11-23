// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Regulatory Framework Library (framework-library.html) against the REAL ITAM engines (crosswalk + NCA ECC with SYNTHETIC facts, ISO 27001,
// NDMO, SAMA, engine/fwlib-intel.js): ring and KPIs; framework cards and detail; the requirement table with framework chips and search;
// a mapping suggestion confirmed by an administrator, not offered to an operator; a viewer reads; the librarian off until allowed;
// menu entry, installer, the portal's fwlib redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node framework-library.test.js
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 18, policies: [], control_status: {} }, risk: { available: true, total: 8 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });
require('./intel-harness')({ file: 'framework-library.html', view: 'fwlib', duty: { eccFacts: async () => FACTS() } },
async (h) => {
  let p = await h.page();
  h.ok(/mapped to the hub/.test(await h.text(p, '#zi-hero')) && /Frameworks held/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  // every tile opens what it counts (named by the engine): the frameworks, the requirements, the not-mapped filter, the suggestions
  const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
  h.ok(zs.join() === 'frameworks,requirements|all,requirements|unmapped,suggestions', 'each tile names its section: ' + zs.join(' '));
  await p.click('#zi-hero .zi-kpi[data-zchip="unmapped"]');
  h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="requirements|unmapped"]'); return c && (c.getAttribute('aria-pressed') === 'true' || c.classList.contains('on')) && document.getElementById('sec-requirements').classList.contains('zi-flash'); }), 'Not mapped: the requirements table filtered to the unmapped ones, highlighted');
  h.ok(await p.$$eval('#sec-frameworks .zi-it', (x) => x.length === 7), 'seven frameworks (NCA ECC, SAMA, ISO 27001, NDMO, PDPL, SOC 2, ISO/IEC 42001)');
  h.ok(await h.openCard(p, 'frameworks', 'iso'), 'framework detail'); h.ok(/Mapped to NCA ECC/.test(await h.text(p, '#zi-dlgb')), 'mapping counts'); await h.closeDlg(p);
  h.ok(await p.$$eval('#sec-requirements tbody tr', (x) => x.length > 50), 'requirement table');
  await p.click('[data-chip="requirements|ndmo"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-requirements tbody tr')].every((r) => /NDMO/.test(r.textContent))), 'framework chip');
  await p.click('[data-chip="requirements|all"]'); await p.fill('[data-q="requirements"]', 'A.5.15'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-requirements tbody tr').length >= 1 && document.querySelectorAll('#sec-requirements tbody tr').length < 5), 'search');
  await p.fill('[data-q="requirements"]', '');
  h.ok(await p.$$eval('#sec-suggestions .zi-li', (x) => x.length > 0), 'mapping suggestions');
  await p.click('#sec-suggestions .zi-li'); h.ok(await h.wait(p, () => !document.getElementById('zi-dlg').hidden) && !(await p.$('#zi-dlgb form')), 'an operator cannot confirm'); await h.closeDlg(p);
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'librarian off until allowed');
  h.who('syed', 'admin'); p = await h.page(); const before = await p.$$eval('#sec-suggestions .zi-li', (x) => x.length);
  await p.click('#sec-suggestions .zi-li'); await p.click('#zi-dlgb button[type=submit]'); h.ok(await h.toast(p, 'Mapping confirmed'), 'the administrator confirms a mapping');
  h.ok(await h.wait(p, (n) => document.querySelectorAll('#sec-suggestions .zi-li').length === n - 1, before), 'it leaves the suggestions');
  h.who('vera.syn', 'viewer'); p = await h.page(); h.ok(/mapped to the hub/.test(await h.text(p, '#zi-hero')), 'a viewer reads');
});
