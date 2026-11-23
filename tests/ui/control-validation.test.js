// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Control Validation (control-validation.html) against the REAL ITAM engines (engine/validation-intel.js, policy register, control
// monitoring) with a SYNTHETIC crosswalk: ring and KPIs; finding cards with kind chips; a disagreement's two sides; a claim-vs-measurement
// contradiction; a GRC action raised by an operator; trust per framework; unassessed lines; a hostile title stays text; a viewer has no
// action; the advisor off until allowed; menu entry, installer, the portal's validation redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node control-validation.test.js
const it = (fw, id, level) => ({ fw, id, title: fw + ' ' + id, level, why: '' });
require('./intel-harness')({ file: 'control-validation.html', view: 'validation',
  after: async (e) => {
    e.app.addons.crosswalk = { crosswalk: async () => ({ names: { ecc: 'NCA ECC', sama: 'SAMA CSF', iso: 'ISO 27001' }, lines: [
      { ecc_id: '2-2-1', title: '<img src=x onerror="window.__xss=1"> identity', severity: 'high', frameworks: ['ecc', 'sama'], state: 'disagree', items: [it('ecc', '2-2-1', 'fully'), it('sama', '3.3.5', 'not')] },
      { ecc_id: '2-3-1', title: 'Malware (synthetic)', severity: 'medium', frameworks: ['ecc', 'sama'], state: 'met', items: [it('ecc', '2-3-1', 'fully'), it('sama', '3.3.7', 'fully')] },
      { ecc_id: '2-5-1', title: 'Network (synthetic)', severity: 'low', frameworks: ['ecc'], state: 'na', items: [it('ecc', '2-5-1', 'na')] }] }) };
    for (let i = 0; i < 10; i++) e.app.store.collection('me_ec_computers').put({ id: 'PC-' + i, name: 'pc' + i, critical: i < 5 ? 2 : 0 });
    require('../../backend/itam/engine/grc').createGrc(e.app).attest('IT-OPS-004', { note: 'followed (synthetic)' }, { user: 'omar.syn', role: 'operator' }); } },
async (h) => {
  let p = await h.page();
  h.ok(/assessments consistent/.test(await h.text(p, '#zi-hero')) && /Claim vs measurement/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-findings .zi-it', (x) => x.length >= 2), 'finding cards');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-findings').textContent)), 'a hostile title stays text');
  await p.click('[data-chip="findings|contradiction"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-findings .zi-it').length === 1 && /attested as followed/.test(document.getElementById('sec-findings').textContent)), 'claim vs measurement chip');
  await p.click('[data-chip="findings|all"]');
  h.ok(await h.openCard(p, 'findings', 'X-2-2-1'), 'finding detail'); const d = await h.text(p, '#zi-dlgb');
  h.ok(/Says fully met/.test(d) && /NCA ECC 2-2-1/.test(d) && /SAMA CSF 3.3.5/.test(d), 'both sides shown');
  await p.fill('#zi-dlgb [name=owner]', 'nora.syn'); await p.click('#zi-dlgb button[type=submit]'); h.ok(await h.toast(p, 'ACT-\\d+ raised to resolve X-2-2-1'), 'resolution action raised');
  h.ok(/ISO|SAMA|NCA/.test(await h.text(p, '#sec-trust')) && /2-5-1/.test(await h.text(p, '#sec-unassessed')), 'trust and unassessed');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); await h.openCard(p, 'findings', 'X-2-2-1'); h.ok(!(await p.$('#zi-dlgb form')), 'a viewer has no action');
});
