// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Governance (ai-governance.html) against the REAL ITAM engines (every installed AI advisor, engine/aigov-intel.js) with SYNTHETIC usage
// records: ring and KPIs; the discovered register with chips and search; an AI system's tools and review; usage per feature with an
// unusual day; the administrator records a review, an operator cannot; a hostile feature name stays text; the advisor off until allowed;
// menu entry, installer, the portal's aigov redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-governance.test.js
require('./intel-harness')({ file: 'ai-governance.html', view: 'aigov',
  after: async (e) => { const A = e.app.addons.aigovIntel, at = (d) => new Date(Date.now() - d * 86400000).toISOString();
    for (let d = 9; d >= 1; d--) A.onEntry({ at: at(d), user: 'nora.syn', feature: 'itam.synthetic-advisor', tokens: 100 });
    for (let i = 0; i < 9; i++) A.onEntry({ at: new Date().toISOString(), user: 'omar.syn', feature: 'itam.synthetic-advisor', tokens: 50, injection_signals: i < 2 ? [1] : undefined });
    A.onEntry({ at: new Date().toISOString(), user: 'omar.syn', feature: '<img src=x onerror="window.__xss=1">', tokens: 5 });
    const AS = e.app.store.collection('assets'); AS.put({ id: 'A-SYN-1', status: 'in_use', software: [{ name: 'Ollama' }] }); AS.put({ id: 'A-SYN-2', status: 'in_use', software: [{ name: 'ChatGPT <b>x</b>', publisher: 'OpenAI' }] }); } },
async (h) => {
  let p = await h.page();
  h.ok(/AI systems governed/.test(await h.text(p, '#zi-hero')) && /Write-capable/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-systems .zi-it', (x) => x.length >= 10), 'the discovered register');
  await p.click('[data-chip="systems|write"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-systems .zi-it').length === 0), 'no installed advisor is write-capable');
  await p.click('[data-chip="systems|all"]'); await p.fill('[data-q="systems"]', 'roadmap'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-systems .zi-it').length === 1), 'search');
  await p.fill('[data-q="systems"]', '');
  h.ok(/itam\.synthetic-advisor/.test(await h.text(p, '#sec-usage')) && /unusual/.test(await h.text(p, '#sec-usage')), 'usage with an unusual day');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-usage').textContent)), 'a hostile feature name stays text');
  h.ok(/mitigated, not solved/.test(await h.text(p, '#sec-controls')), 'controls stated honestly');
  await h.openCard(p, 'systems', 'roadmap'); h.ok(!(await p.$('#zi-dlgb form')) && /Tools/.test(await h.text(p, '#zi-dlgb')), 'an operator sees tools, cannot record a review'); await h.closeDlg(p);
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('syed', 'admin'); p = await h.page(); await h.openCard(p, 'systems', 'roadmap');
  await p.fill('#zi-dlgb [name=note]', 'tools, data and results reviewed (synthetic)'); await p.click('#zi-dlgb form:has([name=note]) button[type=submit]');
  h.ok(await h.toast(p, 'Review of roadmap recorded'), 'the administrator records the review');
  h.ok(await h.wait(p, () => /reviewed 20\d\d-/.test(document.querySelector('#sec-systems [data-open="systems:roadmap"]').textContent)), 'the card shows the review');
  // agent commander: risk per agent, shadow AI, framework checks, pause and the four-eyes resume
  h.ok(await p.$$eval('#sec-posture .zi-bar', (x) => x.length >= 10), 'risk per agent');
  const sh = await h.text(p, '#sec-shadow'); h.ok(/Ollama/.test(sh) && /local model runner/.test(sh) && /not sanctioned/.test(sh), 'shadow AI from the software inventory');
  h.ok(await p.evaluate(() => !document.querySelector('#sec-shadow b b') && /<b>x<\/b>/.test(document.getElementById('sec-shadow').textContent)), 'a product name stays text');
  const ck = await h.text(p, '#sec-checks'); h.ok(/SDAIA principle/i.test(ck) && /Fairness/.test(ck) && /not measured/.test(ck), 'framework checks say what is not measured');
  h.ok(/No AI feature is paused/.test(await h.text(p, '#sec-control')), 'nothing paused');
  await p.click('#sec-usage [data-open="usage:itam.synthetic-advisor"]'); await p.waitForSelector('#zi-dlgb form');
  await p.fill('#zi-dlgb [name=reason]', 'synthetic incident drill'); await p.click('#zi-dlgb form:has([name=reason]) button[type=submit]');
  h.ok(await h.toast(p, 'paused'), 'the administrator pauses a feature');
  h.ok(await h.wait(p, () => /itam\.synthetic-advisor/.test(document.getElementById('sec-control').textContent)), 'it is listed as paused');
  await p.click('#sec-control .zi-li'); await p.waitForSelector('#zi-dlgb form'); await p.fill('#zi-dlgb [name=reason]', 'drill over, tools reviewed'); await p.click('#zi-dlgb form button[type=submit]');
  h.ok(await h.toast(p, 'Resume requested'), 'resume requested');
  h.ok(await h.wait(p, () => /resume requested by syed/.test(document.getElementById('sec-control').textContent)), 'waiting for a second administrator');
  await p.click('#sec-control .zi-li'); await p.waitForSelector('#zi-dlgb form'); await p.click('#zi-dlgb form button[type=submit]');
  h.ok(await h.toast(p, 'four-eyes'), 'the requester cannot approve');
  h.who('huda.syn', 'admin'); p = await h.page(); await p.click('#sec-control .zi-li'); await p.waitForSelector('#zi-dlgb form'); await p.click('#zi-dlgb form button[type=submit]');
  h.ok(await h.toast(p, 'resumed'), 'a second administrator approves');
  h.ok(await h.wait(p, () => /No AI feature is paused/.test(document.getElementById('sec-control').textContent)), 'running again');
});
