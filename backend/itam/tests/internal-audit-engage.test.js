// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The Internal Audit Team (engine/audit-engage.js, kind "internal", routes /iad/*) through the real routes: its own records,
// Head of Audit and ids, apart from the IT and Cyber Security Audit Teams; an insurer's business-process universe with
// itemised scores; business populations (data subject requests, personal data breaches, vendor contracts) with suggested
// attribute tests; four eyes on the plan, workpapers and report; the finding lifecycle; the brief and the duty desk; roles
// (viewer refused, admin-only profile), validation errors naming the field and the audit records. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const INSURER = /^(insurer|insurance)$/i.test(String(require('../engine/brand').sector || ''));

const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'noura.syn', role: 'operator' }, LEAD = { user: 'faris.syn', role: 'operator' };
const AUD2 = { user: 'lina.syn', role: 'operator' }, OWNER = { user: 'majed.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, CSHEAD = { user: 'basma.syn', role: 'operator' };
const DAY = 86400000;

async function setup(t) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who), tick: (d) => { clock += d * DAY; }, store: (n) => e.app.store.collection(n) };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const base = { auditee_owner: OWNER.user, lead: LEAD.user, start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' };
async function profile(s) { const r = await s.post('/iad/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 5 }, ADM); assert.equal(r.status, 200, r.raw); }

test('a separate team over the business: own profile, records and ids; the insurer universe; viewers refused', async (t) => {
  const s = await setup(t); await profile(s);
  await s.post('/csa/profile', { head_of_audit: CSHEAD.user, auditors: [LEAD.user] }, ADM);
  assert.equal((await s.get('/iad/profile')).json.head_of_audit, HEAD.user); assert.equal((await s.get('/csa/profile')).json.head_of_audit, CSHEAD.user);
  assert.equal((await s.post('/iad/profile', { head_of_audit: HEAD.user }, LEAD)).status, 403);
  const bad = await s.post('/iad/profile', { head_of_audit: 'ai:internal' }, ADM); assert.equal(bad.status, 400); assert.match(bad.json.error, /head_of_audit/);
  for (const p of ['/iad/profile', '/iad/plans', '/iad/engagements', '/iad/findings', '/iad/brief', '/iad/areas', '/iad/populations']) assert.equal((await s.get(p, VIEW)).status, 403, p);
  const areas = (await s.get('/iad/areas')).json.map((a) => a.id);
  // the universe follows the organisation's sector (brand setting): an insurer's processes, or an operations & maintenance group's
  const UNIVERSE = INSURER ? ['underwriting', 'claims', 'reinsurance', 'actuarial', 'finance', 'procurement', 'aml', 'fraud', 'conduct', 'compliance', 'itcyber']
    : ['service', 'projects', 'subcontractors', 'hse', 'stores', 'fleet', 'procurement', 'finance', 'hr', 'group', 'clients', 'fraud', 'compliance', 'itcyber'];
  assert.ok(UNIVERSE.every((a) => areas.includes(a)), 'the universe of the sector: ' + areas.join(','));
  if (!INSURER) assert.ok(!areas.includes('underwriting') && !areas.includes('reinsurance'), 'no insurer areas');
  assert.deepEqual((await s.get('/iad/populations')).json.map((p) => p.id).sort(), ['actions', 'breaches', 'contracts', 'dsr', 'joiners', 'leavers', 'risks']);
  const r = await s.post('/iad/engagements', Object.assign(INSURER ? { title: 'Claims settlement (synthetic)', area: 'claims', auditee_dept: 'Claims' } : { title: 'Project variations (synthetic)', area: 'projects', auditee_dept: 'Projects' }, base), LEAD);
  assert.equal(r.status, 200, r.raw); assert.match(r.json.id, /^INE-2027-\d{3}$/);
  const wrong = await s.post('/iad/engagements', Object.assign({ title: 'x', area: 'monitoring', auditee_dept: 'IT' }, base), LEAD);
  assert.equal(wrong.status, 400); assert.match(wrong.json.error, /area/, 'a cyber-only area is not in the internal audit universe');
  assert.equal((await s.get('/csa/engagements')).json.length, 0); assert.equal((await s.get('/ia/engagements')).json.length, 0);
  assert.equal(auditOf(s.e, 'iad.engagement.create').length, 1);
});

test('internal plan: risks of the business scored with their source; the team\'s Head of Audit approves, not the preparer', async (t) => {
  const s = await setup(t); await profile(s);
  s.store('grc_risks').put({ id: 'RSK-0012', status: 'open', description: INSURER ? 'Claims paid without second approval above authority limits (synthetic)' : 'Project variations billed without client sign-off (synthetic)', category: 'Operational', likelihood: 4, impact: 5, owner: OWNER.user });
  const p = await s.post('/iad/plans/propose', { year: 2027 }, LEAD); assert.equal(p.status, 200, p.raw); assert.equal(p.json.id, 'INPLAN-2027');
  const c = p.json.items.find((x) => x.area === (INSURER ? 'claims' : 'projects'));
  assert.ok(c.why.some((w) => w.source === 'risk register' && w.refs.includes('RSK-0012') && w.points === 24));
  assert.equal(c.score, c.why.reduce((n, w) => n + w.points, 0));
  assert.equal(p.json.items.filter((x) => x.include).length, 5);
  await s.post('/iad/plans/INPLAN-2027/submit', {}, LEAD);
  assert.equal((await s.post('/iad/plans/INPLAN-2027/decide', { decision: 'approve' }, CSHEAD)).status, 403, 'another team\'s Head of Audit');
  assert.equal((await s.post('/iad/plans/INPLAN-2027/decide', { decision: 'approve' }, HEAD)).status, 200);
  assert.equal(auditOf(s.e, 'iad.plan.approve')[0].by, HEAD.user);
});

test('business sampling: data subject requests, breaches and contracts with suggested tests; the finding lifecycle and the report', async (t) => {
  const s = await setup(t); await profile(s);
  const pr = s.store('pdpl_records');
  pr.put({ id: 'DSR-1', kind: 'dsr', ref: 'REQ-1', type: 'access', received: '2026-10-01', responded: '2026-10-20' });
  pr.put({ id: 'DSR-2', kind: 'dsr', ref: 'REQ-2', type: 'copy', received: '2026-10-01', responded: '2026-11-20' });
  pr.put({ id: 'DSR-3', kind: 'dsr', ref: 'REQ-3', type: 'destruction', received: '2026-10-01', responded: '2026-11-20', extended: true, outcome: 'refused' });
  pr.put({ id: 'BR-1', kind: 'breach', ref: 'CASE-000100', aware_at: '2026-09-01T08:00Z', sdaia_notified_at: '2026-09-05T08:00Z', harm_likely: true });
  pr.put({ id: 'ROPA-1', kind: 'ropa', ref: 'not a request' });
  s.store('support_contracts').put({ id: 'SC-1', vendor: 'Synthetic Vendor', contract_number: 'C-1', start: '2025-01-01', end: '2026-12-31', owner: '', cost: null });
  const e = (await s.post('/iad/engagements', Object.assign({ title: 'PDPL rights handling (synthetic)', area: 'privacy', auditee_dept: 'Compliance', team: [AUD2.user], objectives: ['Requests answered on time'], scope: 'Q4 2026' }, base), LEAD)).json, E = '/iad/engagements/' + e.id;
  await (await s.post(E + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post(E + '/advance', { to: 'fieldwork' }, LEAD));
  let r = await s.post(E + '/samples', { population: 'dsr', size: 5, method: 'random', seed: 7 }, LEAD); assert.equal(r.status, 200, r.raw);
  const smp = r.json; assert.match(smp.id, /^INS-\d{3}$/); assert.equal(smp.population_size, 3, 'only requests - not the other PDPL records');
  const sug = (ref, t0) => smp.items.find((i) => i.ref === ref).suggested.find((x) => x.test.startsWith(t0)).ok;
  assert.equal(sug('DSR-1', 'Answered within'), true); assert.equal(sug('DSR-2', 'Answered within'), false, '50 days');
  assert.equal(sug('DSR-3', 'Answered within'), true, '50 days with an extension'); assert.equal(sug('DSR-3', 'The requester was told'), false); assert.equal(sug('DSR-3', 'A refusal gives'), false);
  const b = (await s.post(E + '/samples', { population: 'breaches', size: 1, method: 'judgemental', refs: ['BR-1'] }, AUD2)).json;
  assert.deepEqual(b.items[0].suggested.map((x) => x.ok), [false, false, false], '96 hours, subjects not told, no prevention');
  const k = (await s.post(E + '/samples', { population: 'contracts', size: 1, method: 'random' }, AUD2)).json;
  assert.deepEqual(k.items[0].suggested.map((x) => x.ok), [false, true, false, false], 'no owner, end recorded, no cost, expired');
  for (const it of smp.items) await s.post('/iad/samples/' + smp.id + '/items/' + it.ref, it.ref === 'DSR-1' ? { result: 'pass' } : { result: 'exception', note: 'checked against the request file (synthetic)' }, LEAD);
  for (const x of [b, k]) await s.post('/iad/samples/' + x.id + '/items/' + x.items[0].ref, { result: 'exception', note: 'confirmed (synthetic)' }, AUD2);
  const w = (await s.post(E + '/workpapers', { title: 'DSR timeliness', objective: 'Requests answered within the legal period', procedure: 'Compare received and responded dates', sample: smp.id }, LEAD)).json;
  assert.match(w.id, /^INW-\d{3}$/);
  await s.post('/iad/workpapers/' + w.id + '/conclude', { conclusion: 'ineffective', summary: 'Two of three late or incomplete (synthetic)' }, LEAD);
  assert.equal((await s.post('/iad/workpapers/' + w.id + '/review', { decision: 'accept' }, CSHEAD)).status, 403, 'another team\'s head cannot review');
  assert.equal((await s.post('/iad/workpapers/' + w.id + '/review', { decision: 'accept' }, HEAD)).status, 200);
  r = await s.post(E + '/findings', { title: 'Data subject requests answered late', condition: 'c', criteria: 'PDPL Art. 4 / IR 30 days', cause: 'ca', effect: 'ef', recommendation: 're', rating: 'high', owner: OWNER.user, samples: [smp.id + '/DSR-2'] }, LEAD);
  assert.equal(r.status, 200, r.raw); const f = r.json; assert.match(f.id, /^INF-\d{3}$/);
  await s.post('/iad/findings/' + f.id + '/issue', {}, LEAD);
  assert.equal((await s.post('/iad/findings/' + f.id + '/respond', { response: 'Agreed', action_plan: 'Track the due date', due: '2027-02-01' }, OWNER)).status, 200);
  await s.post(E + '/advance', { to: 'draft_report' }, LEAD);
  await s.post(E + '/report/summary', { summary: 'Data subject requests are not answered within the legal period (synthetic).' }, LEAD);
  assert.equal((await s.post(E + '/report/sign', {}, LEAD)).status, 200);
  r = await s.post(E + '/report/approve', {}, HEAD); assert.equal(r.status, 200, r.raw); assert.equal(r.json.opinion, 'Unsatisfactory');
  s.tick(30);
  assert.ok((await s.get('/iad/brief')).json.items.some((y) => y.kind === 'finding-overdue' && y.ref === f.id));
  await s.post('/duty/patrol', { engineer: 'iad' }, ADM);
  const items = (await s.get('/duty/items?engineer=iad')).json; assert.ok((items.items || items).some((y) => y.key === 'iad:finding-overdue:' + f.id));
  for (const a of ['iad.sample.draw', 'iad.workpaper.reviewed', 'iad.finding.raise', 'iad.finding.respond', 'iad.report.sign', 'iad.report.approve']) assert.ok(auditOf(s.e, a).length, a);
});
