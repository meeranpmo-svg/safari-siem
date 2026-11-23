// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Overview (compliance-overview.html) against the REAL ITAM engines (crosswalk over the NCA ECC register with SYNTHETIC facts,
// risk assessment, validation, continuous compliance, engine/overview-intel.js): ring and KPIs; framework cards and their detail; the top
// ten priorities with what they close; the overdue chip; risk and delivery; a hostile action title stays text; a viewer reads; the
// advisor off until allowed; menu entry, installer, the portal's grc redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-overview.test.js
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 3, attested: 18, policies: [], control_status: {} }, risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });
require('./intel-harness')({ file: 'compliance-overview.html', view: 'grc', duty: { eccFacts: async () => FACTS() },
  seed: (e, col) => col('grc_actions').put({ id: 'ACT-9001', title: '<img src=x onerror="window.__xss=1"> overdue', source: 'manual', ref: '', priority: 'high', status: 'open', owner: 'nora.syn', due: '2026-01-01', evidence: [], history: [], created_at: '2025-12-01T00:00:00Z' }) },
async (h) => {
  { // Workflow Automation (the real engine): GRC's audit-trail evidence late with the DBA team, a backup evidence result to accept
    const W = h.e.app.addons.workflow, wc = h.col('wf_requests');
    W.settingsSave({ version: 0, functions: { grc: ['nora.syn'] }, teams: { dba: ['dba.syn'], backup: ['bk.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-audit-trail', from: 'grc', title: 'Audit trail evidence for NCA ECC <img src=x onerror=window.__wfx=1>', details: 'production databases', priority: 'high' }, { user: 'nora.syn', role: 'operator', ip: '' });
    const lr = wc.get(late.id); lr.due = new Date(Date.now() - 2 * 3600000).toISOString(); wc.put(lr);
    const done = W.create({ type: 'backup-evidence', from: 'grc', title: 'Backup success evidence, October', details: 'monthly' }, { user: 'nora.syn', role: 'operator', ip: '' });
    W.act(done.id, 'evidence', { kind: 'note', text: 'report attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); }
  let p = await h.page();
  { h.ok(await h.wait(p, () => !document.getElementById('wfcard').hidden && /Backup success evidence/.test(document.getElementById('wf').textContent)), 'the Workflow Automation card is shown');
    const w = await h.text(p, '#wfcard');
    h.ok(/1\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*results for you to accept/.test(w) && /100 %\s*IT teams on time \(1 of 1\)/.test(w), 'Workflow: open, late, to accept, on time - from the real engine: ' + w.replace(/\s+/g, ' ').slice(0, 240));
    h.ok(w.indexOf('Audit trail evidence') < w.indexOf('Backup success evidence') && /Audit trail evidence for NCA ECC <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /late with the IT team \+35, high priority \+10/.test(w), 'Workflow: ranked by points with reasons; a hostile title stays text'); }
  h.ok(/frameworks fully met/.test(await h.text(p, '#zi-hero')) && /Overdue actions/.test(await h.text(p, '#zi-hero')) && /Risk exposure/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  // every tile opens what it counts (they were plain boxes: "tiles click not working")
  const tl = await p.evaluate(() => [...document.querySelectorAll('#zi-hero a.zi-kpi')].map((a) => a.querySelector('.l').textContent + '=' + a.getAttribute('href')));
  h.ok(tl.length === 7 && tl.includes('Overdue actions=grc-workspace.html') && tl.includes('Frameworks measured=gap-analysis.html') && tl.includes('Contradictions=control-validation.html'), 'every KPI tile links to the page behind it: ' + tl.join(' '));
  await Promise.all([p.waitForURL(/grc-workspace\.html/, { timeout: 10000 }).catch(() => null), p.click('#zi-hero a.zi-kpi[href="grc-workspace.html"]')]); h.ok(/grc-workspace\.html/.test(p.url()), 'clicking Overdue actions opens the GRC workspace');
  p = await h.page();
  // the cockpit: radar, stacked shares per framework, shared work matrix, assessment backlog
  h.ok(await h.wait(p, () => !!document.querySelector('#cp-radar svg polygon')), 'the readiness radar');
  h.ok(await p.$$eval('#cp-fw .fwr[data-fw] .stk', (x) => x.length >= 3) && /NCA ECC/.test(await h.text(p, '#cp-fw')), 'stacked shares per framework');
  h.ok(await p.$$eval('#cp-mx tbody tr', (x) => x.length >= 3) && /open work items close requirements in two or more frameworks|No open work item/.test(await h.text(p, '#cp-mxw')), 'the shared work matrix');
  h.ok(/unknown/.test(await h.text(p, '#cp-bkw')) || /Every item/.test(await h.text(p, '#cp-bk')), 'the assessment backlog');
  // the shared intel graphics: a ring for each framework card's share, a long word value sized to fit, rows and tiles carry their tone
  const gx = await p.evaluate(() => ({ rings: document.querySelectorAll('#sec-frameworks .zi-it .rw svg').length, wide: [...document.querySelectorAll('#zi-hero .zi-kpi .n.w')].map((x) => x.textContent), rows: document.querySelectorAll('.zi-li[class*="t-"]').length,
    acc: getComputedStyle(document.querySelector('#zi-hero .zi-kpi'), '::after').height }));
  h.ok(gx.rings >= 5 && gx.wide.includes('not assessed') && gx.rows >= 1 && gx.acc === '3px', 'graphics: framework rings, a long value sized to fit, rows and tiles with their tone: ' + JSON.stringify(gx));
  if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
  h.ok(await p.$$eval('#sec-frameworks .zi-it', (x) => x.length >= 3) && /NCA ECC/.test(await h.text(p, '#sec-frameworks')), 'framework cards');
  h.ok(await h.openCard(p, 'frameworks', 'ecc'), 'framework detail'); h.ok(/Projection/.test(await h.text(p, '#zi-dlgb')) && /Source/.test(await h.text(p, '#zi-dlgb')), 'projection and source'); await h.closeDlg(p);
  h.ok(await p.$$eval('#sec-priorities .zi-li', (x) => x.length > 0 && x.length <= 10), 'top ten priorities');
  await p.click('#sec-priorities .zi-li'); h.ok(await h.wait(p, () => /Requirements it closes/.test(document.getElementById('zi-dlgb').textContent)), 'what a priority closes'); await h.closeDlg(p);
  await p.click('[data-chip="priorities|unowned"]'); h.ok(await h.wait(p, () => document.querySelector('[data-chip="priorities|unowned"]').getAttribute('aria-pressed') === 'true'), 'priority chip');
  h.ok(/1 overdue/.test(await h.text(p, '#sec-delivery')) && await p.evaluate(() => !window.__xss), 'delivery; nothing executed');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); h.ok(/frameworks fully met/.test(await h.text(p, '#zi-hero')) && /operators and administrators/.test(await h.text(p, '#zi-ai')), 'a viewer reads');
});
