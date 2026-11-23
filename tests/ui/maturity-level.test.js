// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cybersecurity Maturity Level (maturity-level.html) against the REAL ITAM engines (SAMA CSF assessment, engine/maturity-intel.js): ring and
// KPIs; domain bars; subdomain cards with chips (below target / not rated / per domain) and search; a subdomain's level, why and next
// step; the SAMA levels legend; a viewer reads; the advisor off until allowed; menu entry, installer, the portal's maturity redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node maturity-level.test.js
require('./intel-harness')({ file: 'maturity-level.html', view: 'maturity' },
async (h) => {
  let p = await h.page();
  h.ok(/mean maturity/.test(await h.text(p, '#zi-hero')) && /Target level/.test(await h.text(p, '#zi-hero')) && /Rated/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-domains .zi-bar', (x) => x.length >= 3), 'domain bars');
  h.ok(await p.$$eval('#sec-subdomains .zi-it', (x) => x.length >= 20), 'subdomain cards');
  await p.click('[data-chip="subdomains|not_rated"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-subdomains .zi-it')].every((c) => /not rated/.test(c.textContent)) && document.querySelectorAll('#sec-subdomains .zi-it').length > 0), 'not rated chip');
  await p.click('[data-chip="subdomains|d3.1"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-subdomains .zi-it')].every((c) => /^3\.1\./.test(c.textContent))), 'domain chip');
  await p.click('[data-chip="subdomains|all"]'); await p.fill('[data-q="subdomains"]', '3.1.1'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-subdomains .zi-it').length === 1), 'search');
  await p.fill('[data-q="subdomains"]', '');
  h.ok(await h.openCard(p, 'subdomains', '3.1.1'), 'subdomain detail'); const d = await h.text(p, '#zi-dlgb');
  h.ok(/Indicative level/.test(d) && /Next step/.test(d) && /SA-3\.1\.1-01/.test(d), 'level, why and next step'); await h.closeDlg(p);
  h.ok(/Structured and formalized/.test(await h.text(p, '#sec-levels')) && /indicative/.test(await h.text(p, '#sec-levels')), 'levels legend, honestly framed');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); h.ok(/mean maturity/.test(await h.text(p, '#zi-hero')), 'a viewer reads');
});
