// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// SAMA CSF + IA automated assessment (engine/sama-ia.js, pyengine/sama_ia_rules.py) through the real routes over SYNTHETIC
// facts: each pillar verified / gap / not measured from its own source; a manual requirement confirmed and approved by the
// CISO (four eyes, never a service identity), and an approved NCA ECC confirmation counting here too; applicability with a
// reason; indicative maturity and its rule; the daily history feeding the chance-of-gap model, regressions and the forecast;
// gaps to GRC; the rule report and the AI Assessor (tools filtered by role, schema-checked answer, approval by someone else);
// the export (audited, formula-safe); roles (viewer sees no names, refused writes).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, CISO = { user: 'khalid.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const DAY = 86400000;

const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Cryptography Standard (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  cadence: { available: true, assets: 12, out_of_policy: 3 },
  siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial', '3.3.16': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
});

async function setup(t, o = {}) {
  let clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  if (o.allowAi) e.app.settings.update({ external_ai_allowed: true }, ADM);
  const seen = [];
  const sdk = o.turns ? class { constructor() { this.messages = { create: async (p) => { seen.push(JSON.parse(JSON.stringify(p))); const f = o.turns.shift(); return Object.assign({ usage: { input_tokens: 10, output_tokens: 5 } }, f(p)); } }; } } : undefined;
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, samaFacts: async () => (o.facts || FACTS)(), eccFacts: async () => (o.facts || FACTS)(), samaSdk: sdk, samaKey: () => (o.turns ? 'sk-ant-test' : '') });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, seen, tick: (ms) => { clock += ms; }, call, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const req = (v, id) => v.requirements.concat(v.ia.requirements).find((r) => r.id === id);
const auditOf = (e, action) => e.app.store.auditTail(400).filter((x) => x.action === action);

test('every requirement is verified against its own pillar: GRC, Hardening, Pentest / VAPT, SIEM logs', async (t) => {
  const { get } = await setup(t);
  const r = await get('/sama-ia'); assert.equal(r.status, 200, r.raw); const v = r.json;
  assert.equal(v.subdomains.length, 32, 'all 32 SAMA subdomains');
  assert.equal(v.domains.length, 4);
  assert.equal(req(v, 'SA-3.3.8-01').result, 'gap', 'hardening: critical failures make the baseline a gap'); assert.match(req(v, 'SA-3.3.8-02').why, /2 critical hardening failure/);
  assert.equal(req(v, 'SA-3.2.3-01').result, 'verified', 'hardening coverage 95 % >= 90 %');
  assert.equal(req(v, 'SA-3.3.17-01').result, 'verified', 'VAPT: no critical / high finding');
  assert.equal(req(v, 'SA-3.3.17-02').result, 'gap', 'pentest cadence: 3 assets out of policy');
  assert.equal(req(v, 'SA-3.3.14-01').result, 'verified', 'SIEM log flow: every required source reporting');
  assert.equal(req(v, 'SA-3.3.14-03').result, 'verified', 'SIEM retention 400 days');
  assert.equal(req(v, 'SA-3.3.15-01').result, 'gap', 'SIEM: incident management only partial');
  assert.equal(req(v, 'SA-3.3.3-01').result, 'not_measured', 'a source not connected is not measured, never a pass');
  assert.equal(req(v, 'SA-3.1.5-01').result, 'no_evidence', 'a manual requirement waits for a person');
  const pil = Object.fromEntries(v.pillars.map((p) => [p.id, p]));
  assert.ok(pil.hardening.gaps >= 2 && pil.siem.ok >= 3 && pil.pentest.gaps >= 1, JSON.stringify(v.pillars));
  assert.equal(v.ia.circular, 'UTC/277/202401'); assert.ok(req(v, 'IA-277-01'), 'the IA requirement is in the IA view');
  const s14 = v.subdomains.find((x) => x.id === '3.3.14');
  assert.equal(s14.maturity.level, 3, '3.3.14: every requirement met'); assert.match(s14.maturity.why, /met/);
  assert.equal(v.subdomains.find((x) => x.id === '3.3.8').below_target, true);
  assert.match(v.note, /Indicative/);
  assert.deepEqual(v.decide, ['3.3.12', '3.3.13'], 'payment systems and e-banking wait for the CISO\'s applicability decision');
});

test('a manual requirement: recorded, approved by the CISO (four eyes), never by a service identity; NCA ECC approval counts', async (t) => {
  const { e, post, get } = await setup(t);
  assert.equal((await post('/nca-ecc/profile', { ciso_user: CISO.user })).status, 200);
  let r = await post('/sama-ia/confirm', { id: 'SA-3.1.5-01', status: 'compliant' }, OP);
  assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  r = await post('/sama-ia/confirm', { id: 'SA-9.9.9-01', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be a SAMA requirement/);
  r = await post('/sama-ia/confirm', { id: 'SA-3.1.5-01', status: 'compliant', evidence: 'Project security review PSR-2026-04 (synthetic)', approved_by: 'syed' }, OP);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'pending', 'waiting for a second person'); assert.equal(r.json.confirmation.approved_by, null, 'approved_by in the body is dropped');
  assert.equal((await post('/sama-ia/confirm', { id: 'SA-3.1.7-01', status: 'compliant', evidence: 'x' }, BOT)).status, 403, 'an AI identity records nothing');
  assert.equal((await post('/sama-ia/confirm/SA-3.1.5-01/decide', { decision: 'approve' }, OP2)).status, 403, 'an operator who is not the CISO cannot approve');
  assert.equal((await post('/sama-ia/confirm', { id: 'SA-3.3.1-01', status: 'compliant', evidence: 'HR procedure (synthetic)' }, CISO)).status, 200);
  r = await post('/sama-ia/confirm/SA-3.3.1-01/decide', { decision: 'approve' }, CISO); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await post('/sama-ia/confirm/SA-3.1.5-01/decide', { decision: 'approve' }, CISO); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'met');
  assert.equal(auditOf(e, 'sama.confirm.approve').length, 1);
  // the same evidence recorded once in NCA ECC counts here (SA-3.1.7-01 <- ZS-1-10-02)
  assert.equal((await post('/nca-ecc/confirm', { id: 'ZS-1-10-02', status: 'compliant', evidence: 'Specialist training records (synthetic)' }, OP)).status, 200);
  assert.equal((await post('/nca-ecc/confirm/ZS-1-10-02/decide', { decision: 'approve' }, CISO)).status, 200);
  const v = (await get('/sama-ia')).json; const x = req(v, 'SA-3.1.7-01');
  assert.equal(x.result, 'met'); assert.equal(x.via_ecc, 'ZS-1-10-02'); assert.match(x.why, /NCA ECC register/);
  // an automated gap is never hidden by a confirmation, and the conflict is shown
  await post('/sama-ia/confirm', { id: 'SA-3.3.17-02', status: 'compliant', evidence: 'says so' }, OP);
  const g = req((await get('/sama-ia')).json, 'SA-3.3.17-02'); assert.equal(g.result, 'gap'); assert.equal(g.conflict, true);
});

test('applicability: an administrator decides with a reason; viewers see results but no names; writes refused', async (t) => {
  const { e, post, get } = await setup(t);
  let r = await post('/sama-ia/profile', { applicability: { '3.3.12': 'not_applicable' } });
  assert.equal(r.status, 400); assert.match(r.json.error, /applicability_note\.3\.3\.12 is required/);
  assert.equal((await post('/sama-ia/profile', { applicability: { '3.1.1': 'not_applicable' } })).status, 400);
  assert.equal((await post('/sama-ia/profile', { applicability: { '3.3.12': 'not_applicable' }, applicability_note: { '3.3.12': (ZYB_ORG.short + ' runs no payment system (synthetic)') } }, OP)).status, 403);
  r = await post('/sama-ia/profile', { applicability: { '3.3.12': 'not_applicable', '3.3.13': 'applies' }, applicability_note: { '3.3.12': (ZYB_ORG.short + ' runs no payment system (synthetic)') } });
  assert.equal(r.status, 200, r.raw); assert.equal(auditOf(e, 'sama.profile').length, 1);
  await post('/nca-ecc/profile', { ciso_user: CISO.user });
  await post('/sama-ia/confirm', { id: 'SA-3.1.5-01', status: 'compliant', evidence: 'PSR (synthetic)' }, OP);
  await post('/sama-ia/confirm/SA-3.1.5-01/decide', { decision: 'approve' }, CISO);
  const v = (await get('/sama-ia', VIEW)).json;
  assert.equal(req(v, 'SA-3.3.12-01').result, 'not_applicable'); assert.deepEqual(v.decide, []);
  const x = req(v, 'SA-3.1.5-01'); assert.equal(x.result, 'met'); assert.ok(!JSON.stringify(v).includes(OP.user) && !JSON.stringify(v).includes(CISO.user), 'a viewer sees no names');
  for (const [p, b] of [['/sama-ia/confirm', { id: 'SA-3.1.5-01', status: 'compliant', evidence: 'x' }], ['/sama-ia/run', {}], ['/sama-ia/report', {}], ['/sama-ia/gaps-to-grc', {}]]) assert.equal((await post(p, b, VIEW)).status, 403, p);
  assert.equal((await get('/sama-ia/export', VIEW)).status, 403);
});

test('learning from history: chance of a gap, regressions and the 30-day forecast from the daily runs', async (t) => {
  let facts = FACTS();
  const { e, post, get, tick } = await setup(t, { facts: () => facts });
  let v = (await get('/sama-ia')).json; assert.equal(v.trend.forecast_30d, null, 'no forecast without 3 runs'); assert.match(v.trend.note, /3 daily runs/);
  for (let i = 0; i < 4; i++) { assert.equal((await post('/sama-ia/run', {}, OP)).status, 200); tick(DAY); }
  assert.equal(auditOf(e, 'sama.run').length, 4);
  facts = Object.assign(FACTS(), { pentest: Object.assign(FACTS().pentest, { by_severity: { critical: 2, high: 1 } }) });   // a new critical finding
  v = (await get('/sama-ia')).json;
  const x = req(v, 'SA-3.3.17-01'); assert.equal(x.result, 'gap');
  assert.equal(x.history.regression, true, 'met at the last run, a gap now'); assert.ok(v.regressions.includes('SA-3.3.17-01'));
  assert.equal(x.history.runs, 4); assert.equal(x.history.p_gap, Number((1 / 6).toFixed(3)), 'Beta(1,1) posterior mean with 0 gaps in 4 runs');
  const p = v.priorities.find((y) => y.id === 'SA-3.3.17-01'); assert.ok(p && p.why.some((w) => /regression/.test(w)), 'the regression raises its priority, and says so');
  assert.ok(v.priorities[0].score >= v.priorities[v.priorities.length - 1].score);
  assert.equal(v.trend.runs, 4); assert.equal(typeof v.trend.forecast_30d, 'number');
  assert.equal(v.history.length, 4);
});

test('gaps to GRC: the CISO / an administrator only, each gap once', async (t) => {
  const { e, post } = await setup(t);
  assert.equal((await post('/sama-ia/gaps-to-grc', {}, OP)).status, 403);
  const r = await post('/sama-ia/gaps-to-grc', {}); assert.equal(r.status, 200, r.raw);
  assert.ok(r.json.created.length >= 4, JSON.stringify(r.json));
  const again = await post('/sama-ia/gaps-to-grc', {}); assert.equal(again.json.created.length, 0, 'no duplicate action'); assert.ok(again.json.skipped.length >= 4);
  assert.equal(auditOf(e, 'sama.gaps_to_grc').length, 2);
});

test('the report: drafted by the rules when AI is off, approved by the CISO who did not request it', async (t) => {
  const { e, post, get } = await setup(t);
  await post('/nca-ecc/profile', { ciso_user: CISO.user });
  assert.equal((await get('/sama-ia/ai/status')).json.enabled, false);
  assert.equal((await post('/sama-ia/report', { use_ai: true }, OP)).status, 503, 'AI off: refused, the reason in the status');
  const r = await post('/sama-ia/report', {}, CISO); assert.equal(r.status, 200, r.raw);
  const d = r.json; assert.equal(d.source, 'rules'); assert.equal(d.state, 'draft'); assert.match(d.executive_summary, /Indicative/);
  assert.ok(d.key_gaps.length && d.roadmap.every((x) => ['30 days', '90 days', '180 days'].includes(x.horizon)));
  let x = await post('/sama-ia/reports/' + d.id + '/decide', { decision: 'approve' }, CISO); assert.equal(x.status, 403); assert.match(x.json.error, /four eyes/);
  x = await post('/sama-ia/reports/' + d.id + '/decide', { decision: 'approve' }, OP2); assert.equal(x.status, 403, 'not the CISO');
  x = await post('/sama-ia/reports/' + d.id + '/decide', { decision: 'reject' }, ADM); assert.equal(x.status, 400); assert.match(x.json.error, /^note is required/);
  x = await post('/sama-ia/reports/' + d.id + '/decide', { decision: 'approve' }, ADM); assert.equal(x.status, 200); assert.equal(x.json.state, 'approved');
  assert.equal(auditOf(e, 'sama.report.approved').length, 1);
  assert.equal((await get('/sama-ia/reports')).json.length, 1);
});

test('the AI Assessor: read-only tools by role, figures from the rules, unknown ids dropped', async (t) => {
  const turns = [
    () => ({ stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'tu1', name: 'get_requirement', input: { id: 'SA-3.3.8-02' } }, { type: 'tool_use', id: 'tu2', name: 'approve_requirement', input: { id: 'SA-3.3.8-02' } }] }),
    () => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ executive_summary: 'Hardening and penetration testing need attention (synthetic).', score: 100, strengths: ['SIEM logs'],
      key_gaps: [{ id: 'SA-3.3.8-02', gap: '2 critical hardening failures', recommendation: 'Fix them' }, { id: 'SA-9.9.9-99', gap: 'invented', recommendation: 'x' }],
      roadmap: [{ horizon: '30 days', action: 'Close the critical hardening failures', requirement: 'SA-3.3.8-02' }, { horizon: 'tomorrow', action: 'x' }], regulator_note: 'IA keeps insurers on the SAMA CSF.' }) }] }),
  ];
  const { e, seen, post } = await setup(t, { allowAi: true, turns });
  const r = await post('/sama-ia/report', { use_ai: true }, OP); assert.equal(r.status, 200, r.raw);
  const d = r.json; assert.equal(d.source, 'ai'); assert.equal(d.tool_calls, 2);
  assert.deepEqual(d.key_gaps.map((g) => g.id), ['SA-3.3.8-02'], 'a gap naming an unknown requirement is dropped');
  assert.equal(d.roadmap.length, 1, 'an unknown horizon is dropped'); assert.ok(d.flags.some((f) => /unknown requirement/.test(f)));
  assert.notEqual(d.figures.score, 100, 'the score is the rules\', never the model\'s'); assert.equal(d.score, undefined, 'undeclared fields are dropped');
  assert.deepEqual(seen[0].tools.map((x) => x.name).sort(), ['get_requirement', 'get_subdomain', 'list_requirements'], 'read-only tools only');
  assert.match(seen[0].system, /untrusted/i); assert.match(seen[0].messages[0].content, /untrusted/i);
  const results = seen[1].messages[2].content; assert.match(results[0].content, /critical hardening/); assert.match(results[1].content, /tool not available/, 'a tool the role does not have is refused at the call');
  assert.equal(auditOf(e, 'sama.report.draft')[0].detail.source, 'ai');
});

test('the export is audited, formula-safe, and refused to viewers', async (t) => {
  const { e, get } = await setup(t);
  const r = await get('/sama-ia/export', OP); assert.equal(r.status, 200, r.raw);
  assert.match(r.json.csv, /SA-3\.3\.8-01/); assert.match(r.json.filename, /^sama-ia-assessment-/);
  for (const line of r.json.csv.split('\r\n')) for (const c of line.split('","')) assert.ok(!/^"?[=+@]/.test(c), c);
  assert.equal(auditOf(e, 'sama.export').length, 1);
});

test('infrastructure controls: leavers, access reviews, privileged access, service accounts, internal scans and end-of-life systems are read from their own modules', async (t) => {
  const { e, get } = await setup(t);
  let v = (await get('/sama-ia')).json;
  for (const id of ['SA-3.3.1-01', 'SA-3.3.5-04', 'SA-3.3.5-05', 'SA-3.3.10-01', 'SA-3.3.17-04']) assert.equal(req(v, id).result, 'not_measured', id + ': a module not in use is not measured, never a pass');
  assert.equal(req(v, 'SA-3.3.5-06').result, 'not_measured');
  // a leaver past the last day whose account is still enabled
  e.app.store.collection('offboarding').put({ id: 'OFF-1', status: 'approved', user: 'leaver.syn', last_day: '2026-10-20', next: 'disabled' });
  e.app.store.collection('mdm_cfg').put({ id: 'cfg', provider: 'manageengine', base_url: 'https://mdm.corp.syn', token_enc: 'sealed' });
  v = (await get('/sama-ia')).json;
  const off = req(v, 'SA-3.3.1-01');
  assert.equal(off.result, 'gap', off.why); assert.match(off.why, /not disabled/);
  assert.equal(req(v, 'SA-3.3.10-01').result, 'verified', 'MDM connected');
  assert.ok(v.value.automated >= 45 && v.value.automated_pct >= 75, JSON.stringify(v.value));
  assert.ok(v.value.recommendations.some((r) => r.id === 'SA-3.3.2-01' && /badge-access/.test(r.recommend)), 'a requirement with no automated source carries a recommendation');
  assert.match(req(v, 'SA-3.3.11-01').recommend, /disposal certificate/);
});
