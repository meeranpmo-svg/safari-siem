// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NCA IT Audit (nca-it-audit.html) against the REAL ITAM engines (audit teams, NCA ECC verification, engine/nca-itaudit-intel.js) with
// SYNTHETIC audit records: ring and KPIs; the TeamMate-style panels (plan by phase, procedure status, document requests, action plans by
// priority); NCA ECC coverage with the "audit next" chip and a subdomain's detail; engagement cards with the slip forecast; action plans
// with the late chance; NCA ECC full-population tests (2-1 owner, 2-3 EDR, ...) with their exceptions; a hostile title stays text; a viewer sees counts and coverage
// but no engagement, finding or exception; the advisor off until allowed; menu entry, installer, portal view.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nca-it-audit.test.js
const T = Date.parse('2026-10-20T08:00:00Z');
const E = (id, o) => Object.assign({ id, title: 'Synthetic engagement ' + id, area: 'network', auditee_dept: 'IT', auditee_owner: 'owner.syn', lead: 'lead.syn', team: ['aud.syn'], objectives: ['o'], scope: 's', criteria: 'c', history: [] }, o);
require('./intel-harness')({ file: 'nca-it-audit.html', view: 'ncaaudit', clockStart: T, after: (e) => {
  const c = (n) => e.app.store.collection(n);
  for (const [id, due, fin] of [['ENG-1', '2026-02-15', '2026-02-20'], ['ENG-2', '2026-04-30', '2026-04-20'], ['ENG-3', '2026-06-15', '2026-06-25']]) {
    const s = Date.parse(fin) - 50 * 86400000, at = (d) => new Date(s + d * 86400000).toISOString();
    c('ia_engagements').put(E(id, { state: 'final', start: at(0).slice(0, 10), fieldwork_end: due, report_due: due, created_at: at(0), fieldwork_at: at(9), draft_report_at: at(31), final_at: fin + 'T10:00:00Z', criteria: id === 'ENG-1' ? 'NCA ECC 2-3' : 'c' }));
  }
  c('ia_engagements').put(E('ENG-4', { title: 'Network security <img src=x onerror=alert(1)>', state: 'fieldwork', start: '2026-10-01', fieldwork_end: '2026-10-28', report_due: '2026-10-30', created_at: '2026-10-01T08:00:00Z', fieldwork_at: '2026-10-05T08:00:00Z', criteria: 'NCA ECC 2-5' }));
  c('ia_workpapers').put({ id: 'WP-1', engagement: 'ENG-4', title: 'w', state: 'reviewed', prepared_by: 'aud.syn', concluded_by: 'aud.syn', reviewed_by: 'aud.syn' });
  for (const [id, due, impl] of [['IAF-1', '2026-03-01', '2026-03-20'], ['IAF-2', '2026-05-01', '2026-05-15'], ['IAF-3', '2026-07-01', '2026-06-20']])
    c('ia_findings').put({ id, engagement: 'ENG-1', title: 'Synthetic finding ' + id, rating: 'medium', owner: 'net.owner', state: 'implemented', due, implemented_at: impl + 'T09:00:00Z', condition: 'x' });
  c('ia_findings').put({ id: 'IAF-4', engagement: 'ENG-4', title: 'Firewall rules not reviewed', rating: 'high', owner: 'net.owner', state: 'responded', due: '2026-10-01', issued_at: '2026-09-01T08:00:00Z', condition: 'x', action_plan: 'review quarterly' });
  for (let i = 0; i < 2; i++) c('assets').put({ id: 'A' + i, name: 'SYN-' + i, hostname: 'SYN-' + i, type: 'server', status: 'in_use', mgmt_ip: '10.60.0.' + (i + 1), owner: i ? 'infra.syn' : null, software: [{ name: 'Notepad++' }] });
} },
async (h) => {
  let p = await h.page();
  // every tile opens what it counts, named by the engine (the word matching had sent two of them to the action plans)
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    h.ok(zs.join() === 'engagements|all,engagements|risk,procedures,findings|all,findings|overdue,requests', 'each tile names its section: ' + zs.join(' '));
    await p.click('#zi-hero .zi-kpi[data-zchip="risk"]');
    h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="engagements|risk"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-engagements').classList.contains('zi-flash'); }), 'Late or at risk: the engagements filtered, highlighted');
    await p.click('#zi-hero .zi-kpi[data-zsec="requests"]'); h.ok(await h.wait(p, () => document.getElementById('sec-requests').classList.contains('zi-flash')), 'NCA requests overdue: the outstanding document requests'); }
  h.ok(/NCA ECC audit coverage/.test(await h.text(p, '#zi-hero')) && /Engagements active/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(/Planning/.test(await h.text(p, '#sec-plan')) && /Fieldwork/.test(await h.text(p, '#sec-plan')) && /Final/.test(await h.text(p, '#sec-plan')), 'audit plan summary by phase');
  h.ok(/awaiting review/.test(await h.text(p, '#sec-procedures')), 'procedure status');
  h.ok(await p.$('#sec-requests') !== null, 'document requests panel');
  h.ok(/High/.test(await h.text(p, '#sec-actions')) && /1 overdue/.test(await h.text(p, '#sec-actions')), 'action plans by priority');
  await p.click('[data-chip="coverage|next"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-coverage tbody tr').length === 5), 'audit next: the top five');
  await p.click('[data-chip="coverage|all"]'); await p.fill('[data-q="coverage"]', '2-5'); h.ok(await h.wait(p, () => /in an engagement now/.test(document.getElementById('sec-coverage').textContent)), 'coverage: 2-5 in an engagement now');
  await p.fill('[data-q="coverage"]', '');
  h.ok(await h.openCard(p, 'engagements', 'ENG-4'), 'engagement detail'); let d = await h.text(p, '#zi-dlgb');
  h.ok(/Slip forecast/.test(d) && /at risk/.test(d) && /past engagement/.test(d), 'slip forecast learned from past engagements'); h.ok(!(await p.$('#zi-dlgb img')), 'a hostile title stays text'); await h.closeDlg(p);
  await p.click('[data-chip="findings|overdue"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-findings .zi-it').length === 1 && /late chance/.test(document.getElementById('sec-findings').textContent)), 'overdue action plan with the late chance');
  h.ok(await h.openCard(p, 'analytics', 'ecc-2-1-owner'), 'analytics detail'); d = await h.text(p, '#zi-dlgb');
  h.ok(/SYN-0/.test(d) && /owner field/.test(d) && /NCA ECC 2-1/.test(d), 'ECC 2-1: the asset without an owner, the method and the control'); await h.closeDlg(p);
  const an = await h.text(p, '#sec-analytics');
  h.ok(/ECC 2-3/.test(an) && /ECC 2-9/.test(an) && /ECC 2-10/.test(an) && /ECC 2-12/.test(an) && !/Benford|serial|Segregation/i.test(an), 'every test is an NCA ECC control; no general data tests');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  h.ok(await p.$$eval('#sec-coverage tbody tr', (x) => x.length > 10), 'a viewer reads the coverage');
  h.ok((await p.$$eval('#sec-engagements .zi-it', (x) => x.length)) === 0 && /operators and administrators/.test(await h.text(p, '#sec-engagements')), 'no engagements for a viewer');
  h.ok(!/ENG-4|IAF-4|SYN-0/.test(await p.textContent('body')), 'no record identifier on a viewer\'s page');
});
