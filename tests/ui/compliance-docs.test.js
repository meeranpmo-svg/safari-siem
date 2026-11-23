// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Documents & Evidence (compliance-docs.html) against the REAL ITAM engines (evidence + policy registers, engine/docs-intel.js)
// with SYNTHETIC evidence: ring and KPIs; evidence cards with freshness chips and search; an item's file, hash and renewal risk; a
// renewal action raised by an operator; the renewal wave, coverage and the policy list; a hostile title stays text; a viewer has no
// action; the advisor off until allowed; menu entry, installer, the portal's docs redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-docs.test.js
const d = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
require('./intel-harness')({ file: 'compliance-docs.html', view: 'docs',
  seed: (e, col) => { const put = (id, o) => col('grc_evidence').put(Object.assign({ id, framework: 'SAMA CSF', control: '3.3.5', title: 'Synthetic evidence ' + id, kind: 'document', owner: 'nora.syn', valid_days: 365, status: 'active', file: { filename: id + '.pdf', sha256: 'c'.repeat(60) + id.slice(-4) }, created_by: 'seed', created_at: d(-400) }, o));
    put('EVD-0001', { collected: d(-100), next_due: d(265) }); put('EVD-0002', { control: '3.3.14', collected: d(-380), next_due: d(-15), title: '<img src=x onerror="window.__xss=1"> log review' }); put('EVD-0003', { control: '3.3.8', collected: d(-350), next_due: d(15) }); } },
async (h) => {
  let p = await h.page();
  h.ok(/evidence current/.test(await h.text(p, '#zi-hero')) && /Policies overdue/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-evidence .zi-it', (x) => x.length === 3), 'evidence cards');
  await p.click('[data-chip="evidence|stale"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-evidence .zi-it').length === 1), 'stale chip');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-evidence').textContent)), 'a hostile title stays text');
  await p.click('[data-chip="evidence|all"]'); await p.fill('[data-q="evidence"]', 'EVD-0003'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-evidence .zi-it').length === 1), 'search');
  await p.fill('[data-q="evidence"]', '');
  h.ok(await h.openCard(p, 'evidence', 'EVD-0002'), 'evidence detail'); const t = await h.text(p, '#zi-dlgb');
  h.ok(/SHA-256/.test(t) && /cccc/.test(t) && /Renewal risk/.test(t), 'file, hash, renewal risk');
  await p.click('#zi-dlgb button[type=submit]'); h.ok(await h.toast(p, 'ACT-\\d+ raised to renew EVD-0002'), 'renewal action raised');
  h.ok(await h.wait(p, () => /renewal action open/.test(document.getElementById('sec-evidence').textContent)), 'the card says so');
  h.ok(await p.$$eval('#sec-wave .zi-bar', (x) => x.length === 6) && /SAMA CSF/.test(await h.text(p, '#sec-coverage')), 'renewal wave and coverage');
  h.ok(await p.$$eval('#sec-policies .zi-li', (x) => x.length > 3), 'policies listed');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  await h.openCard(p, 'evidence', 'EVD-0003'); h.ok(!(await p.$('#zi-dlgb form')), 'a viewer has no action');
});
