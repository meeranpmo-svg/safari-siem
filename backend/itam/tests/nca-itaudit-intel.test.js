// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NCA IT Audit (engine/nca-itaudit-intel.js) over the REAL audit teams (engine/audit-engage.js), the REAL NCA ECC verification and
// SYNTHETIC audit records: plan by phase; the slip forecast learned from past engagements (late now / at risk / on track); procedures;
// action plans with the late-implementation chance learned from the owner's past findings; NCA ECC coverage from the subdomain ids
// named in engagements, ranked for "audit next"; NCA ECC full-population tests (2-1 owner, 2-3 EDR, 2-9 backup, 2-10 scan, 2-12 logs and the audit-trail chain,
// segregation of duties in the audit work); a viewer sees counts and coverage, not records; the daily snapshot; the advisor off.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const T = Date.parse('2026-10-20T08:00:00Z'), VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const E = (id, o) => Object.assign({ id, title: 'Synthetic engagement ' + id, area: 'network', auditee_dept: 'IT', auditee_owner: 'owner.syn', lead: 'lead.syn', team: ['aud.syn'], objectives: ['o'], scope: 's', criteria: 'c', history: [] }, o);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const c = (n) => e.app.store.collection(n);
  // three finished engagements: two finished after the report due date; phase durations 9 / 22 / 19 days
  for (const [id, due, fin] of [['ENG-1', '2026-02-15', '2026-02-20'], ['ENG-2', '2026-04-30', '2026-04-20'], ['ENG-3', '2026-06-15', '2026-06-25']]) {
    const s = Date.parse(fin) - 50 * 86400000, at = (d) => new Date(s + d * 86400000).toISOString();
    c('ia_engagements').put(E(id, { state: 'final', start: at(0).slice(0, 10), fieldwork_end: due, report_due: due, created_at: at(0), fieldwork_at: at(9), draft_report_at: at(31), final_at: fin + 'T10:00:00Z', criteria: id === 'ENG-1' ? 'NCA ECC 2-3 information system protection' : 'c' }));
  }
  // an active engagement in fieldwork, 10 days to the report: the remaining phases took 22 + 19 days -> at risk
  c('ia_engagements').put(E('ENG-4', { state: 'fieldwork', start: '2026-10-01', fieldwork_end: '2026-10-28', report_due: '2026-10-30', created_at: '2026-10-01T08:00:00Z', fieldwork_at: '2026-10-05T08:00:00Z', criteria: 'NCA ECC 2-5 networks security management' }));
  c('csa_engagements').put(E('CSE-1', { state: 'planning', start: '2026-12-01', fieldwork_end: '2026-12-20', report_due: '2027-01-15', created_at: '2026-10-10T08:00:00Z' }));
  c('ia_workpapers').put({ id: 'WP-1', engagement: 'ENG-4', title: 'w', state: 'reviewed', prepared_by: 'aud.syn', concluded_by: 'aud.syn', reviewed_by: 'aud.syn' });
  c('ia_workpapers').put({ id: 'WP-2', engagement: 'ENG-4', title: 'w', state: 'concluded', prepared_by: 'aud.syn', concluded_by: 'aud.syn' });
  // the owner implemented two past findings late and one on time
  for (const [id, due, impl] of [['IAF-1', '2026-03-01', '2026-03-20'], ['IAF-2', '2026-05-01', '2026-05-15'], ['IAF-3', '2026-07-01', '2026-06-20']])
    c('ia_findings').put({ id, engagement: 'ENG-1', title: 'Synthetic finding ' + id, rating: 'medium', owner: 'net.owner', state: 'implemented', due, implemented_at: impl + 'T09:00:00Z', implemented_by: 'net.owner', condition: 'x' });
  c('ia_findings').put({ id: 'IAF-4', engagement: 'ENG-4', title: 'Firewall rules not reviewed', rating: 'high', owner: 'net.owner', state: 'responded', due: '2026-10-01', issued_at: '2026-09-01T08:00:00Z', condition: 'x', action_plan: 'review quarterly' });
  c('ia_findings').put({ id: 'IAF-5', engagement: 'ENG-2', title: 'r', rating: 'low', owner: 'x.owner', state: 'closed', due: '2026-05-01', implemented_by: 'x.owner', retested_by: 'x.owner', condition: 'x' });
  // assets: 4 in-use servers - SYN-0 with an owner and Kaspersky, SYN-1 owner but no EDR, SYN-2 no owner, SYN-3 no software inventory
  for (let i = 0; i < 4; i++) c('assets').put({ id: 'A' + i, name: 'SYN-' + i, hostname: 'SYN-' + i, type: 'server', status: 'in_use', mgmt_ip: '10.60.0.' + (i + 1), owner: i < 2 ? 'infra.syn' : null,
    software: i === 3 ? [] : [{ name: i === 0 ? 'Kaspersky Endpoint Security for Windows' : 'Notepad++', version: '12' }], sources: [{ source: 'agent', last_seen: new Date(T).toISOString() }] });
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3',
    acovLogCoverage: async () => ({ ok: true, assets: [{ asset_id: 'A0', status: 'covered' }, { asset_id: 'A1', status: 'absent' }] }), acovAvail: async () => ({ ok: false, error: 'synthetic' }) });
  return { e, get: (who = OP) => e.req('GET', '/nca-itaudit-intel', who), post: (p, b, who) => e.req('POST', p, Object.assign({ body: b }, who)) };
}
const sec = (v, id) => v.sections.find((s) => s.id === id);

test('plan, slip forecast, procedures and action plans from the audit teams\' records', async (t) => {
  const s = await setup(t);
  const r = await s.get(); assert.equal(r.status, 200, r.text); const v = r.json;
  const plan = Object.fromEntries(sec(v, 'plan').items.map((i) => [i.id, i.value])); assert.deepEqual([plan.planning, plan.fieldwork, plan.final], [1, 1, 3]);
  const e4 = sec(v, 'engagements').items.find((i) => i.id === 'ENG-4');
  assert.ok(e4.tags.includes('risk') && /at risk/.test(e4.badges[1].text), 'at risk: 10 days left, the remaining phases took 41 at the median');
  assert.match(e4.detail.rows.find((x) => x[0] === 'Slip forecast')[1], /2 of 3 past engagement\(s\) finished late/);
  assert.equal(sec(v, 'procedures').items.find((i) => i.id === 'concluded').value, 1);
  const f4 = sec(v, 'findings').items.find((i) => i.id === 'IAF-4');
  assert.ok(f4.tags.includes('overdue')); assert.ok(f4.badges.some((b) => /late chance 60 %/.test(b.text)), 'Beta(1,1): (2+1)/(3+2) = 60 %');
  assert.equal(v.kpis.find((k) => k.label === 'Overdue').value, 1);
});

test('NCA ECC coverage: subdomains named in engagements, ranked for audit next', async (t) => {
  const s = await setup(t); const v = (await s.get()).json, cov = sec(v, 'coverage');
  assert.ok(cov.rows.length >= 20, 'every applicable ECC subdomain');
  const r25 = cov.rows.find((r) => r.id === '2-5'); assert.equal(r25.cells[2], 'in an engagement now'); assert.ok(r25.tags.includes('covered'));
  const r23 = cov.rows.find((r) => r.id === '2-3'); assert.match(r23.cells[2], /^2026-02-20 \(8 mo\)$/);
  assert.match(r23.detail.rows.find((x) => x[0] === 'Last audited')[1], /^2026-02-20 by the IT Audit Team/, 'the team name, not its members');
  const never = cov.rows.find((r) => r.cells[2] === 'never'); assert.ok(never.tags.includes('uncovered'));
  assert.ok(cov.rows.slice(0, 5).every((r) => r.tags.includes('next')));
  assert.ok(cov.rows.every((r, i) => i === 0 || Number(cov.rows[i - 1].cells[3].text) >= Number(r.cells[3].text)), 'ranked by priority');
  assert.match(v.ring.why, /of \d+ applicable subdomains/);
});

test('NCA ECC full-population tests: each answers one control, exceptions named, a source not connected = not run', async (t) => {
  const s = await setup(t); const a = sec((await s.get()).json, 'analytics').items, by = Object.fromEntries(a.map((x) => [x.id, x]));
  assert.deepEqual(a.map((x) => x.id), ['ecc-2-1-owner', 'ecc-2-3-edr', 'ecc-2-9-backup', 'ecc-2-10-scan', 'ecc-2-12-logs', 'ecc-2-12-chain']);
  assert.ok(a.every((x) => /^ECC 2-\d+ /.test(x.title) && /NCA ECC 2-/.test(x.detail.rows[1][1])), 'every test names its NCA ECC control');
  assert.equal(by['ecc-2-1-owner'].metrics[0].value, 4); assert.equal(by['ecc-2-1-owner'].metrics[1].value, 2); assert.ok(by['ecc-2-1-owner'].detail.lists[0].items.some((x) => /SYN-2/.test(x)));
  assert.equal(by['ecc-2-3-edr'].metrics[0].value, 3, 'no software inventory = not checked, out of the population'); assert.equal(by['ecc-2-3-edr'].metrics[1].value, 2);
  assert.match(by['ecc-2-3-edr'].detail.rows[2][1], /1 not checked/);
  assert.equal(by['ecc-2-9-backup'].metrics[1].value, '—', 'no backup platform: not run'); assert.match(by['ecc-2-9-backup'].detail.rows[2][1], /not run: no backup platform/);
  assert.equal(by['ecc-2-12-logs'].metrics[1].value, 1); assert.ok(by['ecc-2-12-logs'].detail.lists[0].items.some((x) => /SYN-1: missing/.test(x)));
  assert.equal(by['ecc-2-12-chain'].metrics[1].value, 0);
  assert.ok(!a.some((x) => /benford|serial|segregation/i.test(x.title)), 'general data tests are not on the NCA page');
});

test('a viewer sees counts, coverage and analytics totals - no engagement, finding or exception', async (t) => {
  const s = await setup(t); const v = (await s.get(VIEW)).json;
  assert.equal(sec(v, 'engagements').items.length, 0); assert.equal(sec(v, 'findings').items.length, 0);
  assert.ok(sec(v, 'coverage').rows.length > 0);
  assert.ok(sec(v, 'analytics').items.every((i) => /operators and administrators/.test(i.detail.lists[0].items[0])));
  assert.ok(!/ENG-4|IAF-4|SN-SYN-DUP|aud\.syn/i.test(JSON.stringify(v)), 'no record identifier reaches a viewer');
});

test('daily snapshot and the advisor', async (t) => {
  const s = await setup(t);
  assert.ok(await s.e.app.addons.ncaItauditIntel.snapshot());
  assert.equal(sec((await s.get()).json, 'trend').points.length, 1);
  assert.equal((await s.post('/nca-itaudit-intel/ask', { question: 'what needs attention first?' }, VIEW)).status, 403);
  assert.equal((await s.post('/nca-itaudit-intel/ask', { question: 'what needs attention first?' }, OP)).status, 424);
});
