// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// SAMA CSF Audit (engine/sama-audit.js) on the real SAMA CSF assessment (engine/sama-ia.js + pyengine/sama_ia_rules.py) over
// SYNTHETIC facts: implementation by domain from the assessment only; the gap tracker (owner, default due date by severity,
// plan, validation naming the field, a met requirement refused); closure with evidence confirmed by the CISO / an administrator
// who did not request it (four eyes; service identity refused); closed-not-verified and regressed-after-closure; reopen; the
// closure forecast and due-date risk (ML, with the history they need and what they say without it); the rule memo and the AI
// memo (tools filtered by role, re-checked, unknown ids dropped, untrusted framing, four-eyes approval); the export (audited,
// formula-safe); roles (viewer sees no names, refused writes) and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { lsq, missChance } = require('../engine/sama-audit');

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
  return { e, seen, tick: (ms) => { clock += ms; }, now: () => clock, call, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(400).filter((x) => x.action === action);

test('ML helpers: least-squares line and the Beta-smoothed chance of missing a due date', () => {
  const f = lsq([[0, 10], [1, 8], [2, 6], [3, 4]]); assert.equal(Math.round(f.slope), -2);
  assert.equal(lsq([[0, 1], [1, 2]]), null, 'fewer than 3 points: no line');
  assert.equal(missChance([10, 20], 5, 10).p, null); assert.match(missChance([10, 20], 5, 10).why, /needs 5 closed gaps/);
  const m = missChance([10, 20, 30, 40, 50, 60], 25, 10);   // still open at 25 days: 30,40,50,60 → longer than 35: 40,50,60
  assert.equal(m.p, Math.round((3 + 1) / (4 + 2) * 100) / 100); assert.match(m.why, /3 of 4 closed gap/);
});

test('audit view: implementation by domain from the assessment, gaps tracked, viewer sees no names', async (t) => {
  const { get, post, e } = await setup(t);
  const r = await get('/sama-audit', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  assert.deepEqual(v.domains.map((d) => d.id), ['3.1', '3.2', '3.3', '3.4', 'IA']);
  const d = v.domains.reduce((a, x) => a + x.implemented + x.not_implemented + x.not_applicable, 0);
  assert.equal(d, v.domains.reduce((a, x) => a + x.requirements, 0), 'every requirement counted once');
  assert.ok(v.kpis.gaps > 0 && v.kpis.open === v.kpis.gaps, 'every gap starts open');
  assert.ok(v.gaps.every((g) => !['verified', 'met', 'not_applicable'].includes(g.result)), 'only what the assessment does not show met');
  const hard = v.gaps.find((g) => g.result === 'gap'); assert.ok(hard, 'the synthetic critical hardening failures give a gap');
  assert.ok(hard.priority_why.length && typeof hard.priority === 'number', 'priority with its reasons');
  assert.match(v.forecast.note, /needs 3 daily counts/);
  assert.equal(v.subdomains.length, 32, 'every SAMA subdomain with its indicative maturity');
  assert.ok(v.subdomains.every((x) => 'level' in x && x.why !== undefined && typeof x.open_gaps === 'number'));
  assert.equal(v.kpis.below_target, v.subdomains.filter((x) => x.below_target).length); assert.equal(v.kpis.not_assessed, v.subdomains.filter((x) => x.level == null).length);
  assert.ok(v.subdomains.find((x) => x.id === hard.subdomain).open_gaps >= 1, 'the gap counts on its subdomain');
  await post('/sama-audit/gaps/' + hard.id, { owner: 'nora.syn' });
  const vv = (await get('/sama-audit', VIEW)).json.gaps.find((g) => g.id === hard.id); assert.equal(vv.owner, 'assigned', 'viewer: no names (PDPL)');
  assert.equal((await get('/sama-audit', OP)).json.gaps.find((g) => g.id === hard.id).owner, 'nora.syn');
  const sv = (await get('/sama-audit', VIEW)).json.subdomains.find((x) => x.id === hard.subdomain); assert.deepEqual(sv.owners, ['assigned'], 'viewer: no owner names');
  assert.deepEqual((await get('/sama-audit', OP)).json.subdomains.find((x) => x.id === hard.subdomain).owners, ['nora.syn']);
  assert.equal((await post('/sama-audit/gaps/' + hard.id, { owner: 'x' }, VIEW)).status, 403, 'viewer cannot write');
  assert.equal(auditOf(e, 'sama_audit.gap.update').length, 1);
});

test('gap tracker: validation names the field, default due by severity, a met requirement is refused', async (t) => {
  const { get, post, e } = await setup(t);
  const v = (await get('/sama-audit')).json, g = v.gaps[0];
  let r = await post('/sama-audit/gaps/' + g.id, { due: '2026-13-40' }); assert.equal(r.status, 400); assert.match(r.json.error, /due must be a date/);
  r = await post('/sama-audit/gaps/' + g.id, { status: 'closed' }); assert.equal(r.status, 400); assert.match(r.json.error, /status must be one of: open, in_progress/);
  r = await post('/sama-audit/gaps/' + g.id, {}); assert.equal(r.status, 400); assert.match(r.json.error, /nothing to change/);
  r = await post('/sama-audit/gaps/NOT-AN-ID', { owner: 'x' }); assert.equal(r.status, 400);
  r = await post('/sama-audit/gaps/SA-3.1.1-99', { owner: 'x' }); assert.equal(r.status, 404);
  r = await post('/sama-audit/gaps/' + g.id, { status: 'in_progress', plan: 'Remediate the critical baseline failures (synthetic)', note: 'kick-off' });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'in_progress'); assert.ok(/^\d{4}-\d{2}-\d{2}$/.test(r.json.due), 'a default due date');
  const days = { high: 30, medium: 90, low: 180 }[g.severity]; assert.equal(r.json.due, new Date(Date.parse('2026-10-28T08:00:00Z') + 3 * 3600000 + days * DAY).toISOString().slice(0, 10));
  const sa = (await get('/sama-ia')).json, met = sa.requirements.find((x) => x.result === 'verified');
  assert.ok(met, 'something is verified by the synthetic facts');
  r = await post('/sama-audit/gaps/' + met.id, { owner: 'x' }); assert.equal(r.status, 409); assert.match(r.json.error, /met by the assessment/);
  const a = auditOf(e, 'sama_audit.gap.update')[0]; assert.equal(a.by, OP.user); assert.equal(a.role, 'operator'); assert.equal(a.detail.status, 'in_progress');
});

test('closure: evidence required, confirmed by the CISO / an administrator who did not request it, closed-not-verified, reopen', async (t) => {
  const { get, post, e } = await setup(t);
  await post('/nca-ecc/profile', { ciso_user: CISO.user }, ADM);
  const g = (await get('/sama-audit')).json.gaps.find((x) => x.result === 'gap');
  let r = await post('/sama-audit/gaps/' + g.id + '/close', {}); assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  assert.equal((await post('/sama-audit/gaps/' + g.id + '/close', { evidence: 'Change CHG-SYN-1 baseline fix' }, BOT)).status, 403, 'a service / AI identity cannot request');
  r = await post('/sama-audit/gaps/' + g.id + '/close', { evidence: 'Change CHG-SYN-1 baseline fix' }, CISO); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'closure_requested');
  assert.equal((await post('/sama-audit/gaps/' + g.id + '/close', { evidence: 'again' }, OP)).status, 409);
  assert.equal((await post('/sama-audit/gaps/' + g.id + '/decide', { decision: 'approve' }, OP2)).status, 403, 'an operator who is not the CISO cannot confirm');
  r = await post('/sama-audit/gaps/' + g.id + '/decide', { decision: 'approve' }, CISO); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await post('/sama-audit/gaps/' + g.id + '/decide', { decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await post('/sama-audit/gaps/' + g.id + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'closed'); assert.equal(r.json.verification, 'closed_not_verified', 'the assessment still shows it as a gap');
  const v = (await get('/sama-audit')).json;
  assert.equal(v.kpis.closed, 1); assert.equal(v.kpis.closed_not_verified, 1);
  assert.equal(v.domains.find((d) => d.id === g.domain).closed_not_verified, 1, 'shown beside the rate, not counted as implemented');
  assert.ok(v.attention.some((x) => x.id === g.id && /closed, but the assessment does not show it met/.test(x.text)));
  assert.equal((await post('/sama-audit/gaps/' + g.id, { owner: 'x' })).status, 409, 'closed gaps are reopened first');
  r = await post('/sama-audit/gaps/' + g.id + '/reopen', { reason: 'no' }); assert.equal(r.status, 400);
  r = await post('/sama-audit/gaps/' + g.id + '/reopen', { reason: 'the assessment still fails the baseline (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'in_progress');
  const ap = auditOf(e, 'sama_audit.gap.close_approve')[0]; assert.equal(ap.by, ADM.user); assert.equal(ap.detail.requested_by, CISO.user); assert.equal(ap.detail.verified, false);
  assert.equal(auditOf(e, 'sama_audit.gap.reopen').length, 1);
});

test('closure forecast and due-date risk learn from the tracker history', async (t) => {
  const { get, post, e, now } = await setup(t);
  const store = e.app.store;
  for (let i = 0; i < 5; i++) store.collection('sama_audit_daily').put({ id: 'd' + i, at: now() - (5 - i) * DAY, open: 20 - 2 * i, closed: 2 * i });
  for (let i = 0; i < 6; i++) store.collection('sama_audit_gaps').put({ id: 'SA-3.1.7-0' + (i + 1) + 'x', status: 'closed', opened_at: new Date(now() - 100 * DAY).toISOString(), closed_at: new Date(now() - 100 * DAY + (10 + 20 * i) * DAY).toISOString() });
  const g = (await get('/sama-audit')).json.gaps.find((x) => x.result === 'gap');
  await post('/sama-audit/gaps/' + g.id, { due: new Date(now() + 5 * DAY).toISOString().slice(0, 10) });
  const v = (await get('/sama-audit')).json;
  assert.equal(v.forecast.days, 6, 'five kept days + today, written by the update'); assert.ok(v.forecast.closed_per_week > 0); assert.match(v.forecast.all_closed_by, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(v.learn.closed_durations, 6);
  const x = v.gaps.find((y) => y.id === g.id); assert.ok(x.miss.p > 0 && x.miss.p < 1, JSON.stringify(x.miss)); assert.match(x.miss.why, /closed gap\(s\) still open at/);
});

test('audit memo: rules, AI with role-filtered read-only tools, unknown ids dropped, approval by someone else; export audited and formula-safe', async (t) => {
  const turns = [
    (p) => ({ stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 't1', name: 'list_gaps', input: {} }, { type: 'tool_use', id: 't2', name: 'close_gap', input: { id: 'x' } }] }),
    (p) => { const ids = JSON.parse(p.messages[2].content[0].content.replace(/^[\s\S]*?(\[[\s\S]*\])[\s\S]*$/, '$1')).map((g) => g.id);
      return { stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ summary: 'Synthetic memo.', findings: [{ id: ids[0], finding: 'f', risk: 'high', recommendation: 'r' }, { id: 'SA-3.9.9-99', finding: 'invented', risk: 'high', recommendation: 'r' }], management_actions: [{ id: ids[0], action: 'a', horizon: '30 days' }, { id: ids[0], action: 'b', horizon: 'tomorrow' }] }) }] }; },
  ];
  const { post, get, seen, e } = await setup(t, { allowAi: true, turns });
  let r = await post('/sama-audit/memo', {}); assert.equal(r.status, 200, r.raw); assert.equal(r.json.source, 'rules'); assert.match(r.json.summary, new RegExp('Internal audit of ' + ZYB_ORG.short));
  assert.equal((await post('/sama-audit/memo', {}, VIEW)).status, 403);
  r = await post('/sama-audit/memo', { use_ai: true }, OP2); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.source, 'ai'); assert.equal(r.json.findings.length, 1, 'the invented requirement is dropped'); assert.equal(r.json.management_actions.length, 1, 'unknown horizon dropped');
  assert.ok(r.json.flags.some((f) => /unknown requirement/.test(f)));
  assert.deepEqual(seen[0].tools.map((x) => x.name), ['list_gaps', 'get_gap'], 'read-only tools only');
  assert.match(seen[0].system, /untrusted/i);
  assert.match(seen[1].messages[2].content[1].content, /tool not available/, 'an injected tool call is refused');
  assert.match(seen[1].messages[2].content[0].content, /untrusted/i, 'tool output framed as data');
  assert.equal((await post('/sama-audit/memos/' + r.json.id + '/decide', { decision: 'approve' }, OP2)).status, 403);
  assert.equal((await post('/sama-audit/memos/' + r.json.id + '/decide', { decision: 'approve' }, ADM)).status, 200);
  assert.equal((await get('/sama-audit/memos')).json.items.length, 2);
  // export
  e.app.store.collection('sama_audit_gaps').put({ id: (await get('/sama-audit')).json.gaps[0].id, status: 'in_progress', owner: '=HYPERLINK("x")', plan: '', history: [], opened_at: new Date().toISOString() });
  r = await get('/sama-audit/export'); assert.equal(r.status, 200, r.raw);
  const rows = r.json.sheets[0].rows; assert.ok(rows.length > 10); assert.ok(rows.some((x) => x[9] === "'=HYPERLINK(\"x\")"), 'formula-safe');
  assert.equal((await get('/sama-audit/export', VIEW)).status, 403);
  assert.equal(auditOf(e, 'sama_audit.export').length, 1); assert.equal(auditOf(e, 'sama_audit.memo.draft').length, 2);
});
