// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The auditor's dashboard (engine/audit-dashboard.js) through the real routes: every framework (PDPL, NCA ECC, NDMO, SAMA CSF,
// IA) and the three audit teams on one page; "not assessed" is never a score; a source that fails shows as not available
// while the others still show; overdue audit findings reach the attention list; roles (viewer refused, operator reads);
// the CSV export is audited and safe to open in Excel. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
// an internal audit area of the organisation's sector (brand setting)
const AREA = /^(insurer|insurance)$/i.test(String(require('../engine/brand').sector || '')) ? 'claims' : 'projects';

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const HEAD = { user: 'noura.syn', role: 'operator' }, LEAD = { user: 'faris.syn', role: 'operator' }, OWNER = { user: 'majed.syn', role: 'operator' };

async function setup(t, all = true) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  if (all) e.app.config.audit_dashboard = Object.assign({}, e.app.config.audit_dashboard, { all_frameworks: true });   // the product's every-framework view; the sector filter has its own test
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), tick: (d) => { clock += d * 86400000; } };
}

test('every framework on one page; nothing assessed is never a score; roles', async (t) => {
  const s = await setup(t);
  assert.equal((await s.get('/audit-dashboard', VIEW)).status, 403, 'viewers are refused (PDPL)');
  assert.equal((await s.get('/audit-dashboard/export', VIEW)).status, 403);
  const r = await s.get('/audit-dashboard'); assert.equal(r.status, 200, r.raw);
  const v = r.json, fw = (id) => v.frameworks.find((f) => f.id === id);
  assert.deepEqual(v.frameworks.map((f) => f.id), ['pdpl', 'nca-ecc', 'ndmo', 'sama', 'ia', 'iso27001', 'aramco']);
  assert.equal(fw('aramco').page, 'aramco-ccc.html'); assert.equal(fw('aramco').score, null, 'Aramco CCC: no score before controls are imported and assessed'); assert.match(fw('aramco').extra, /no control list imported/);
  assert.equal(fw('iso27001').page, 'iso27001.html', 'ISO 27001 sits beside the regulators'); assert.match(fw('iso27001').extra, /readiness/);
  for (const id of ['pdpl', 'sama', 'ia']) { assert.equal(fw(id).status, 'not_assessed', id); assert.equal(fw(id).score, null, id + ' has no score until assessed'); }
  assert.ok(fw('nca-ecc').available && fw('ndmo').available);
  assert.equal(fw('pdpl').owner, 'no DPO named'); assert.equal(fw('nca-ecc').owner, 'no CISO named');
  assert.match(v.note, /not the regulator's assessment/);
  assert.equal(v.teams.list.length, 3); assert.deepEqual(v.teams.list.map((x) => x.id), ['internal', 'it', 'cyber']);
  assert.equal(v.programmes.list.length, 2);
});

test('an assessed checklist gets its score; overdue audit findings and evidence requests reach the attention list', async (t) => {
  const s = await setup(t);
  const a = await s.post('/audit-checklist/assess', { id: 'AC-01', status: 'non_compliant', note: 'no evidence of review (synthetic)' }, OP);
  assert.equal(a.status, 200, a.raw);
  // an Internal Audit finding past its due date
  await s.post('/iad/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user] }, ADM);
  const e = (await s.post('/iad/engagements', { title: 'Audit (synthetic)', area: AREA, auditee_dept: 'Operations', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['o'], scope: 's', start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD)).json;
  await (await s.post('/iad/engagements/' + e.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post('/iad/engagements/' + e.id + '/advance', { to: 'fieldwork' }, LEAD));
  const f = (await s.post('/iad/engagements/' + e.id + '/findings', { title: 'Claims paid above authority', condition: 'c', criteria: 'cr', cause: 'ca', effect: 'ef', recommendation: 'r', rating: 'high', owner: OWNER.user }, LEAD)).json;
  await s.post('/iad/findings/' + f.id + '/issue', {}, LEAD);
  await s.post('/iad/findings/' + f.id + '/respond', { response: 'ok', action_plan: 'second approval', due: '2027-01-20' }, OWNER);
  s.tick(20);
  const v = (await s.get('/audit-dashboard')).json, sama = v.frameworks.find((x) => x.id === 'sama');
  assert.notEqual(sama.status, 'not_assessed'); assert.equal(typeof sama.score, 'number'); assert.ok(sama.counts.gaps >= 1);
  assert.ok(sama.top.some((x) => x.id === 'AC-01'));
  const team = v.teams.list.find((x) => x.id === 'internal');
  assert.equal(team.head_of_audit, HEAD.user); assert.equal(team.findings.overdue, 1); assert.equal(team.findings.high, 1);
  const top = v.attention[0]; assert.equal(top.ref, f.id); assert.equal(top.severity, 'high'); assert.equal(top.page, 'internal-audit-team.html');
  assert.equal(v.summary.overdue_findings, 1);
});

test('a source that fails shows as not available; the others still show', async (t) => {
  const s = await setup(t);
  s.e.app.addons.ndmo = { view: async () => { throw new Error('synthetic failure'); } };
  delete s.e.app.addons.pdpl;
  const v = (await s.get('/audit-dashboard')).json, fw = (id) => v.frameworks.find((x) => x.id === id);
  assert.equal(fw('ndmo').available, false); assert.match(fw('ndmo').reason, /synthetic failure/);
  assert.equal(fw('pdpl').available, false); assert.match(fw('pdpl').reason, /not installed/);
  assert.ok(fw('nca-ecc').available && fw('sama').available, 'the others still show');
});

test('CSV export: audited, and a cell that starts like a formula cannot run in Excel', async (t) => {
  const s = await setup(t);
  await s.post('/audit-checklist/assess', { id: 'AC-01', status: 'non_compliant', note: '=HYPERLINK("http://x") synthetic' }, OP);
  const r = await s.get('/audit-dashboard/export'); assert.equal(r.status, 200, r.raw);
  assert.match(r.json.filename, /^audit-dashboard-2027-01-10\.csv$/);
  const lines = r.json.csv.split('\r\n'); assert.match(lines[0], /^"Section","Item"/);
  assert.ok(lines.some((l) => l.startsWith('"Framework","PDPL (SDAIA)","not_assessed"')));
  assert.ok(!/(^|,)"=/.test(r.json.csv), 'no cell starts with =');
  const au = s.e.app.store.auditTail(50).find((x) => x.action === 'audit-dashboard.export'); assert.ok(au); assert.equal(au.by, OP.user); assert.ok(au.detail.rows > 5);
});

test('control monitoring and PDPL deadlines reach the dashboard: open exceptions and at-risk deadlines on the attention list; never a run started from here', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/audit-dashboard')).json;
  assert.equal(v.ccm.run, null, 'no run yet - the dashboard does not start one'); assert.match(v.ccm.note, /not run yet/);
  assert.equal(s.e.app.store.collection('ccm_runs').all(() => true).length, 0);
  assert.equal(v.summary.control_exceptions_open, null);
  s.e.app.store.audit({ at: '2027-01-09T08:00:00Z', by: 'kamal.syn', role: 'admin', ip: '', action: 'roles.assign', target: 'kamal.syn', detail: { to: 'admin' } });
  s.e.app.addons.auditCcm.runScheduled();
  s.e.app.addons.pdpl.putRecord({ kind: 'breach', ref: 'BR-SYN-9', aware_at: '2027-01-07T16:00Z', description: 'synthetic' }, ADM);   // 64 h before the clock
  v = (await s.get('/audit-dashboard')).json;
  assert.equal(v.ccm.page, 'audit-ccm.html'); assert.ok(v.ccm.open_total >= 1); assert.equal(v.summary.control_exceptions_open, v.ccm.open_total);
  const c = v.attention.find((a) => /Control monitoring - CT-07/.test(a.source)); assert.ok(c, 'the self-granted role is on the attention list'); assert.equal(c.page, 'audit-ccm.html'); assert.equal(c.severity, 'high');
  const b = v.attention.find((a) => a.ref === 'BR-SYN-9'); assert.ok(b && /hour\(s\) left to notify SDAIA/.test(b.text)); assert.equal(v.deadlines.counts.breaches_at_risk, 1);
  assert.ok(v.summary.pdpl_deadlines_at_risk >= 1);
});

test('insight: the index is withheld until two frameworks are assessed, then itemised; history, regression, projection, priority, delivery, advisor', async (t) => {
  const s = await setup(t);
  for (const k of ['ncaEcc', 'ndmo', 'iso27001']) delete s.e.app.addons[k];
  let v = (await s.get('/audit-dashboard')).json;
  assert.equal(v.insight.index.value, null); assert.match(v.insight.index.why, /withheld until two frameworks/);
  const S = { ecc: 50, ndmo: 40 };
  s.e.app.addons.ncaEcc = { view: async () => ({ counts: { verified: 5, gap: 1 }, controls: [], score: S.ecc, profile: {}, nca: null, subdomains: [] }) };
  s.e.app.addons.ndmo = { view: async () => ({ counts: { met: 3, gap: 1 }, controls: [], score: S.ndmo, profile: {}, levels: null, maturity: [] }) };
  s.e.app.store.collection('audit_dashboard_snaps').all(() => true).forEach((x) => s.e.app.store.collection('audit_dashboard_snaps').remove(x.id));
  const D = s.e.app.addons.auditDashboard;
  for (let d = 0; d < 40; d++) { S.ecc = 50 + d; S.ndmo = d < 36 ? 40 + d : 40; await D.snapshot(); s.tick(1); }
  v = (await s.get('/audit-dashboard')).json; const I = v.insight;
  const notAssessed = v.frameworks.filter((f) => f.score == null).length;
  assert.equal(I.index.items[0].points, (S.ecc + S.ndmo) / 2, 'the base is the mean of the assessed scores');
  assert.ok(I.index.items.some((x) => /frameworks not assessed/.test(x.label) && x.points === -Math.min(10, notAssessed * 2)), 'each point itemised');
  assert.equal(I.index.value, Math.round((S.ecc + S.ndmo) / 2 - Math.min(10, notAssessed * 2)));
  assert.ok(I.snapshots >= 40 && I.series.length >= 40);
  const ndmo = I.frameworks.find((f) => f.id === 'ndmo'), ecc = I.frameworks.find((f) => f.id === 'nca-ecc');
  assert.ok(ndmo.regressed && ndmo.move_30d < 0, 'NDMO fell back: a regression'); assert.ok(I.regressions.some((r) => r.id === 'ndmo'));
  assert.ok(ecc.move_30d > 0 && ecc.projection.direction === 'rising');
  assert.ok(ecc.projection.reached || /^\d{4}-\d{2}-\d{2}$/.test(ecc.projection.date), 'a projection to 80 %: ' + ecc.projection.why);
  assert.deepEqual(Object.keys(ecc.dist), ['ok', 'partial', 'gap', 'open']); assert.equal(ecc.dist.ok, 5); assert.equal(ecc.dist.gap, 1);
  assert.equal(I.delivery.length, 3); assert.ok(I.delivery.every((d) => d.on_track === 50 && /prior, not a measurement/.test(d.why)), 'nothing open: the prior, said as such');
  assert.equal(v.analytics.available, true); assert.equal(v.analytics.page, 'audit-analytics.html');
  // the AI advisor: a viewer refused, an operator told it is off until allowed
  assert.equal((await s.post('/audit-dashboard/ask', { question: 'what should the committee see first?' }, VIEW)).status, 403);
  assert.equal((await s.post('/audit-dashboard/ask', { question: 'what should the committee see first?' }, OP)).status, 424);
  assert.equal((await s.get('/audit-dashboard/ai/status', VIEW)).status, 403);
  assert.deepEqual(D.TOOLS.map((x) => x.name), ['dashboard', 'gaps']);
});

test('priority: severity, days overdue and a running legal clock, itemised', async () => {
  const { createAuditDashboard } = require('../engine/audit-dashboard');
  assert.ok(createAuditDashboard);
  const e = await startApp({ noAi: true });
  try {
    registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
    e.app.addons.pdplIntel = { dsarRisk: () => [], breachRisk: () => [{ id: 'B1', ref: 'BR-SYN-1', deadline: '2027-01-01', hours_left: 5, risk: 'high' }] };
    const v = (await e.req('GET', '/audit-dashboard', OP)).json, b = v.attention.find((a) => a.ref === 'BR-SYN-1');
    assert.ok(b.priority >= 75 && b.priority_why.some((w) => /legal clock/.test(w)), 'a running PDPL clock ranks up: ' + b.priority_why.join(', '));
    assert.equal(v.attention[0].ref, 'BR-SYN-1');
  } finally { await e.close(); }
});

test('the organisation\'s frameworks only: SAMA / IA switched off in the brand setting are not listed', async (t) => {
  const off = require('../engine/brand').modules_off || [];
  const s = await setup(t, false);
  const ids = (await s.get('/audit-dashboard')).json.frameworks.map((f) => f.id);
  assert.equal(ids.includes('sama'), !off.includes('fw-sama')); assert.equal(ids.includes('ia'), !off.includes('fw-ia'));
  assert.ok(ids.includes('nca-ecc') && ids.includes('pdpl'));
});
