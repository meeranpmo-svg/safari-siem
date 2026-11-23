// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Command Center (engine/audit-auto.js) through the real ITAM routes with SYNTHETIC records: the use cases test the whole
// population (leavers, privileged access), a use case with no records is "not testable" (never effective); a run proposes a finding
// for the right team, an auditor accepts it into an engagement in fieldwork (raised through the team's own engine) or dismisses it
// with a reason; a service identity cannot decide; overdue findings are followed up and escalated to Notification & Escalation;
// learning (deteriorating needs 7 runs; slip forecast from the owner's history; repeat findings); settings admin-only with a version;
// roles (viewer refused), validation errors naming the field, the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { jaccard, robustZ, USE_CASES } = require('../engine/audit-auto');

const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' };
const AUD2 = { user: 'adel.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:itaudit', role: 'operator' };
const DAY = 86400000;

async function setup(t) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = LEAD) => call('GET', p, undefined, who), tick: (d) => { clock += d * DAY; }, col: (n) => e.app.store.collection(n) };
}
const auditOf = (e, action) => e.app.store.auditTail(800).filter((x) => x.action === action);
function seed(s) {
  // 10 leavers in the period, two disabled late / not at all (UC-01), one disable approved by the requester (UC-02)
  for (let i = 1; i <= 10; i++) { const last = '2026-12-' + String(10 + i).padStart(2, '0');
    s.col('offboarding').put({ id: 'OFF-' + i, username: 'leaver' + i + '.syn', last_day: last, requested_by: 'hr.syn', status: 'completed',
      disable: { approved_by: i === 4 ? 'hr.syn' : 'mgr.syn' }, disabled: i === 2 ? null : { at: (i === 6 ? '2027-01-05' : last) + 'T10:00:00Z' } }); }
  // privileged access: all approved independently and time-boxed (UC-06/07 effective)
  for (let i = 1; i <= 4; i++) s.col('pam_requests').put({ id: 'PAM-' + i, requester: 'eng' + i + '.syn', group: 'Domain Admins', requested_at: '2026-12-20T09:00:00Z', decision: { decision: 'approve', by: 'ciso.syn' }, expires_at: '2026-12-21T09:00:00Z' });
}
async function cyberEngagement(s) {
  assert.equal((await s.post('/csa/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 4 }, ADM)).status, 200);
  const r = await s.post('/csa/engagements', { title: 'Identity lifecycle 2026 (synthetic)', area: 'iam', auditee_dept: 'IT', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user],
    objectives: ['Leavers lose access on their last day'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD);
  assert.equal(r.status, 200, r.raw); assert.equal((await (await s.post('/csa/engagements/' + r.json.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post('/csa/engagements/' + r.json.id + '/advance', { to: 'fieldwork' }, LEAD))).status, 200); return r.json.id;
}

test('use cases test the whole population; no records is not testable, never effective', async (t) => {
  const s = await setup(t); seed(s);
  const v = await s.get('/audit-auto'); assert.equal(v.status, 200, v.raw);
  assert.ok(v.json.use_cases.length >= 20 && USE_CASES.every((u) => u.refs.length && u.objective));
  const u = (id) => v.json.use_cases.find((x) => x.id === id);
  assert.equal(u('UC-01').status, 'exceptions'); assert.equal(u('UC-01').n, 10); assert.equal(u('UC-01').ex, 2); assert.equal(u('UC-01').rate, 20);
  assert.equal(u('UC-02').ex, 1, 'the requester approved their own disable');
  assert.equal(u('UC-06').status, 'effective'); assert.equal(u('UC-07').status, 'effective');
  assert.equal(u('UC-19').status, 'not_testable'); assert.match(u('UC-19').why, /connect or use PDPL data subject requests/);
  assert.equal(v.json.kpis.tested, v.json.use_cases.filter((x) => x.n).length); assert.ok(v.json.kpis.readiness < 100);
  assert.match(u('UC-01').learning.why, /needs 7 earlier runs/);
  const d = await s.get('/audit-auto/use-cases/UC-01'); assert.deepEqual(d.json.exceptions.map((x) => x.id).sort(), ['OFF-2', 'OFF-6']);
  assert.equal((await s.get('/audit-auto/use-cases/UC-99')).status, 404);
  assert.equal((await s.get('/audit-auto', VIEW)).status, 403, 'audit records name people: no viewers');
});

test('a run proposes findings; an auditor accepts into fieldwork or dismisses with a reason; a service identity cannot decide', async (t) => {
  const s = await setup(t); seed(s); const E = await cyberEngagement(s);
  const r = await s.post('/audit-auto/run', {}, LEAD); assert.equal(r.status, 200, r.raw); assert.ok(r.json.did.proposed >= 2);
  assert.equal((await s.post('/audit-auto/run', {}, LEAD)).json.did.proposed, 0, 'one open proposal per use case');
  assert.equal(auditOf(s.e, 'audit-auto.run').length, 2); assert.ok(auditOf(s.e, 'audit-auto.propose').some((x) => x.detail.uc === 'UC-01'));
  const v = await s.get('/audit-auto'), p1 = v.json.proposals.find((p) => p.uc === 'UC-01'), p2 = v.json.proposals.find((p) => p.uc === 'UC-02');
  assert.equal(p1.team, 'cyber'); assert.match(p1.condition, /2 of 10 Leavers/); assert.match(p1.condition, /OFF-2/); assert.match(p1.criteria, /NCA ECC 2-2/);
  let x = await s.post('/audit-auto/proposals/' + p1.id + '/accept', { engagement: E }, LEAD); assert.equal(x.status, 400); assert.match(x.json.error, /owner/);
  x = await s.post('/audit-auto/proposals/' + p1.id + '/accept', { engagement: E, owner: OWNER.user }, BOT); assert.equal(x.status, 403, 'an AI identity cannot accept');
  x = await s.post('/audit-auto/proposals/' + p1.id + '/accept', { engagement: E, owner: LEAD.user }, LEAD); assert.equal(x.status, 400, 'the team engine refuses an auditor as owner'); assert.match(x.json.error, /owner/);
  x = await s.post('/audit-auto/proposals/' + p1.id + '/accept', { engagement: E, owner: OWNER.user }, LEAD); assert.equal(x.status, 200, x.raw);
  assert.equal(x.json.finding.state, 'draft'); assert.ok((await s.get('/csa/findings')).json.some((f) => f.id === x.json.finding.id && /Leavers disabled/.test(f.title)));
  assert.equal((await s.post('/audit-auto/proposals/' + p1.id + '/accept', { engagement: E, owner: OWNER.user }, LEAD)).status, 409);
  x = await s.post('/audit-auto/proposals/' + p2.id + '/dismiss', { reason: 'short' }, LEAD); assert.equal(x.status, 400); assert.match(x.json.error, /reason/);
  x = await s.post('/audit-auto/proposals/' + p2.id + '/dismiss', { reason: 'covered by the finding just raised (synthetic)' }, LEAD); assert.equal(x.status, 200);
  assert.ok(auditOf(s.e, 'audit-auto.proposal.accept').length === 1 && auditOf(s.e, 'audit-auto.proposal.dismiss').length === 1);
  s.tick(1); await s.post('/audit-auto/run', {}, LEAD);
  assert.equal((await s.get('/audit-auto')).json.proposals.filter((p) => p.uc === 'UC-01' && p.state === 'proposed').length, 0, 'an open finding already covers the use case');
});

test('overdue findings are followed up and escalated to Notification & Escalation; slip forecast and repeats', async (t) => {
  const s = await setup(t); const E = await cyberEngagement(s);
  const mk = async (title) => { const f = await s.post('/csa/engagements/' + E + '/findings', { title, condition: 'c (synthetic)', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: OWNER.user }, LEAD); assert.equal(f.status, 200, f.raw); return f.json.id; };
  const a = await mk('Service accounts without a named owner in the register'), b = await mk('Firewall rule review not performed');
  for (const id of [a, b]) assert.equal((await s.post('/csa/findings/' + id + '/issue', {}, LEAD)).status, 200);
  assert.equal((await s.post('/csa/findings/' + a + '/respond', { response: 'agreed', action_plan: 'name owners', due: '2027-01-20' }, OWNER)).status, 200);
  assert.equal((await s.post('/csa/findings/' + b + '/respond', { response: 'agreed', action_plan: 'review', due: '2027-03-01' }, OWNER)).status, 200);
  // the first is closed late, then a new finding repeats it
  s.tick(15); assert.equal((await s.post('/csa/findings/' + a + '/implemented', { evidence: 'owners named (synthetic)' }, OWNER)).status, 200);
  assert.equal((await s.post('/csa/findings/' + a + '/retest', { result: 'closed', note: 'checked (synthetic)' }, AUD2)).status, 200);
  const c = await mk('Service accounts without named owner in the register again'); await s.post('/csa/findings/' + c + '/issue', {}, LEAD);
  await s.post('/csa/findings/' + c + '/respond', { response: 'agreed', action_plan: 'again', due: '2027-01-30' }, OWNER);
  let v = (await s.get('/audit-auto')).json;
  const fb = v.forecast.find((f) => f.id === b); assert.ok(fb && fb.p_late > 0.5 && /owner omar\.syn: 1 earlier finding/.test(fb.why[0]), JSON.stringify(v.forecast));
  assert.ok(v.repeats.some((r) => r.id === c && r.similar_to === a), 'the new finding repeats a closed one');
  s.tick(40); await s.post('/audit-auto/run', {}, LEAD); v = (await s.get('/audit-auto')).json;
  const fu = v.followups.find((x) => x.ref === c); assert.ok(fu && fu.escalated && fu.count === 1, JSON.stringify(v.followups));
  assert.ok(auditOf(s.e, 'audit-auto.escalate').some((x) => x.target === 'finding:' + c));
  const sig = s.e.app.addons.auditAuto.signals(); assert.ok(sig.some((x) => x.source === 'audit' && x.ref === c && x.severity === 3));
  s.tick(1); await s.post('/audit-auto/run', {}, LEAD); assert.equal((await s.get('/audit-auto')).json.followups.find((x) => x.ref === c).count, 1, 'one follow-up a week');
});

test('settings: administrator only, a version against races, every rule named; rules switched off do nothing', async (t) => {
  const s = await setup(t); seed(s);
  const base = { draft_findings: false, follow_up: true, escalate: true, retest_due: true, auto_retest: true, period_days: 90, escalate_days: 30, version: 0 };
  assert.equal((await s.post('/audit-auto/settings', base, LEAD)).status, 403);
  let r = await s.post('/audit-auto/settings', Object.assign({}, base, { escalate: 'yes' }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /escalate/);
  r = await s.post('/audit-auto/settings', Object.assign({}, base, { period_days: 3 }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /period_days/);
  r = await s.post('/audit-auto/settings', base, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.version, 1);
  assert.equal((await s.post('/audit-auto/settings', base, ADM)).status, 409, 'stale version');
  assert.equal((await s.post('/audit-auto/run', {}, LEAD)).json.did.proposed, 0, 'draft_findings off');
  assert.ok(auditOf(s.e, 'audit-auto.settings').length === 1);
  assert.equal((await s.post('/audit-auto/ask', { question: 'what first?' }, VIEW)).status, 403);
  r = await s.post('/audit-auto/ask', { question: 'x' }, LEAD); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/audit-auto/ask', { question: 'what should we do first?' }, LEAD)).status, 424, 'off until external AI is allowed');
});

test('learning helpers: Jaccard on words, robust z needs 7 values', () => {
  assert.ok(jaccard('Service accounts without an owner', 'service accounts without owner') > 0.6);
  assert.equal(jaccard('', 'x y z'), 0);
  assert.equal(robustZ([1, 2, 3], 9), null);
  assert.ok(robustZ([10, 11, 9, 10, 12, 10, 11], 40) > 2.5);
});
