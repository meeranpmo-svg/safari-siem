// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Office (engine/pdpl-office.js, pyengine/pdpl_office.py): PDPL findings become tasks routed to named people (the
// department's data steward, the function owner, the DPO), deadlines by severity, escalation to the DPO then the committee
// chair, "done" is a claim the registers must confirm, risk acceptance by a committee member who is not the assignee,
// recurring duties, the route map, roles (viewer / operator / admin / DPO / service refused), validation, audit. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' };
const ST = { user: 'faisal.syn', role: 'viewer' }, OTHER = { user: 'x.syn', role: 'viewer' }, BOT = { user: 'ai:pdpl', role: 'admin' };

async function setup(t) {
  let clock = Date.parse('2026-10-20T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' });
  await post('/pdpl/accountability', { function: 'requests', user: 'mona.syn' }, ADM);
  const r = (await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', data_categories: ['health'], legal_basis: 'legitimate_interest' }, ADM)).json;
  return { e, post, get, ropa: r, tick: (d) => { clock += d * DAY; } };
}
const acts = (e) => e.app.store.auditTail(300).map((x) => x.action);

test('routing: each finding to a named person; roles; my tasks; route map and gaps', async (t) => {
  const { e, post, get } = await setup(t);
  assert.equal((await post('/pdpl/office/run', {}, ST)).status, 403, 'a viewer cannot run the office');
  assert.equal((await post('/pdpl/office/run', {})).status, 200);
  assert.equal((await get('/pdpl/office', ST)).status, 403, 'the whole office is operator-only');
  const v = (await get('/pdpl/office')).json;
  const k = (s) => v.tasks.find((x) => x.key.includes(s));
  assert.equal(k('P-07:dpia').assignee, 'faisal.syn'); assert.match(k('P-07:dpia').why, /data steward of Claims/);
  assert.equal(k('sens:').assignee, 'faisal.syn', 'a finding naming the activity only in its key reaches its department');
  assert.equal(k('P-01:dpo').assignee, 'huda.syn', 'nobody owns SDAIA liaison: the DPO');
  assert.ok(v.tasks.every((x) => /^PO-\d{5}$/.test(x.id) && x.due));
  assert.ok(k('duty:committee'), 'a committee never held is a duty due now');
  assert.ok(v.gaps.some((g) => /no privacy champion/.test(g)) && v.gaps.some((g) => /No privacy committee chair/.test(g)));
  assert.equal(v.roadmap.phases.length, 8); assert.ok(v.roadmap.steps.find((s) => s.id === 'dpo').state !== 'todo');
  assert.equal(v.roadmap.steps.find((s) => s.id === 'processors').state, 'todo');
  assert.ok(v.org.departments.some((d) => d.department === 'Claims' && d.data_steward === 'faisal.syn'));
  // the steward (viewer) sees only their own tasks
  const m = (await get('/pdpl/office/mine', ST)).json;
  assert.ok(m.tasks.length >= 3 && m.tasks.every((x) => x.assignee === 'faisal.syn')); assert.ok(m.roles.includes('data steward - Claims'));
  assert.equal((await get('/pdpl/office/mine', OTHER)).json.tasks.length, 0);
  // a second run does not duplicate
  const n = v.tasks.length; await post('/pdpl/office/run', {}); assert.equal((await get('/pdpl/office')).json.tasks.length, n);
  assert.ok(acts(e).includes('pdpl.office.raised') && acts(e).includes('pdpl.office.run'));
});

test('work a task: claim stays open until the registers confirm; reassign by the DPO; risk acceptance four-eyes; escalation; close', async (t) => {
  const { e, post, get, ropa, tick } = await setup(t);
  await post('/pdpl/office/run', {});
  const tasks = () => get('/pdpl/office').then((r) => r.json.tasks);
  const ret = (await tasks()).find((x) => x.key.includes('P-12:retention'));
  const inc = (await tasks()).find((x) => x.key.includes('ropa:' + ropa.id + ':incomplete'));
  // claim: assignee only (or DPO / operator); a note; never a service
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/done', { note: 'filled every field (synthetic)' }, OTHER)).status, 403);
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/done', { note: 'short' }, ST)).status, 400);
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/done', { note: 'filled every field (synthetic)' }, BOT)).status, 403);
  assert.equal((await post('/pdpl/office/tasks/bad/done', { note: 'filled every field (synthetic)' }, ST)).status, 400);
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/ack', {}, ST)).json.status, 'acknowledged');
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/done', { note: 'filled every field (synthetic)' }, ST)).json.status, 'claimed');
  await post('/pdpl/office/run', {});
  assert.equal((await tasks()).find((x) => x.id === inc.id).status, 'claimed', 'the finding is still there: the claim is not a close');
  // reassign: the DPO or an admin, with a reason
  assert.equal((await post('/pdpl/office/tasks/' + ret.id + '/reassign', { user: 'omar.syn', reason: 'records manager' }, OP)).status, 403, 'an operator who is not the DPO');
  assert.equal((await post('/pdpl/office/tasks/' + ret.id + '/reassign', { user: 'ai:x', reason: 'records manager' }, DPO)).status, 400);
  const ra = await post('/pdpl/office/tasks/' + ret.id + '/reassign', { user: 'omar.syn', reason: 'records manager owns retention', due: '2026-12-31' }, DPO);
  assert.equal(ra.status, 200, ra.raw); assert.equal(ra.json.assignee, 'omar.syn');
  await post('/pdpl/office/run', {}); const r2 = (await tasks()).find((x) => x.id === ret.id);
  assert.equal(r2.assignee, 'omar.syn', 'a person\'s reassignment stands over the routing rules'); assert.match(r2.due, /^2026-12-31/);
  // configure: admin or the DPO only; validated
  assert.equal((await post('/pdpl/office/config', { committee: { chair: 'syed', members: ['faisal.syn'] } }, OP)).status, 403);
  assert.equal((await post('/pdpl/office/config', { committee: { chair: 'syed', members: ['faisal.syn'] }, sla_days: { high: 0 } }, DPO)).status, 400);
  assert.equal((await post('/pdpl/office/config', { committee: { chair: 'svc-bot', members: [] } }, DPO)).status, 400);
  assert.equal((await post('/pdpl/office/config', { owners: [{ system: 'CLAIMS-SQL' }] }, DPO)).status, 400);
  assert.equal((await post('/pdpl/office/config', { committee: { chair: 'syed', members: ['faisal.syn', 'reem.syn'] }, escalate_days: 5, verify_days: 30 }, DPO)).status, 200);
  // risk: a committee member who is not the assignee; reason; end within 12 months; never a critical finding
  const dp = (await tasks()).find((x) => x.key.includes('P-07:dpia'));
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/accept-risk', { reason: 'DPIA scheduled with the medical team next quarter', until: '2027-01-31' }, OTHER)).status, 403, 'not on the committee');
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/accept-risk', { reason: 'DPIA scheduled with the medical team next quarter', until: '2027-01-31' }, ST)).status, 403, 'the assignee');
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/accept-risk', { reason: 'DPIA scheduled with the medical team next quarter', until: '2028-06-30' }, ADM)).status, 400, 'over 12 months');
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/accept-risk', { reason: 'too short', until: '2027-01-31' }, ADM)).status, 400);
  const crit = (await tasks()).find((x) => x.severity === 'critical');
  assert.equal((await post('/pdpl/office/tasks/' + crit.id + '/accept-risk', { reason: 'we accept the legitimate interest risk for now', until: '2027-01-31' }, ADM)).status, 409, 'critical is fixed, not accepted');
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/accept-risk', { reason: 'DPIA scheduled with the medical team next quarter', until: '2027-01-31' }, ADM)).json.status, 'risk_accepted');
  // escalation: overdue -> the DPO; overdue + 5 days -> the chair; an accepted risk does not escalate
  tick(8); await post('/pdpl/office/run', {});
  let all = await tasks(); const sens = all.find((x) => x.key.includes('P-06:lia') && x.key.endsWith(':assessment'));
  assert.equal(sens.escalation, 1); assert.equal(sens.escalated_to, 'huda.syn'); assert.equal(all.find((x) => x.id === dp.id).escalation, 0);
  tick(6); await post('/pdpl/office/run', {});
  all = await tasks(); assert.equal(all.find((x) => x.id === sens.id).escalation, 2); assert.equal(all.find((x) => x.id === sens.id).escalated_to, 'syed');
  assert.ok((await get('/pdpl/office/mine', ADM)).json.tasks.some((x) => x.id === sens.id), 'the chair sees what was escalated to them');
  // fix the register: complete the activity -> the incompleteness task closes, confirming the claim
  const fx = await post('/pdpl/records', { kind: 'ropa', id: ropa.id, name: ropa.name, owner: 'Claims', data_categories: ['health'], purpose: 'Assess and pay medical claims', subjects: 'Insured members (synthetic)', systems: ['CLAIMS-SQL'], retention_months: 120, recipients: ['TPA (synthetic)'], security_measures: 'Tiered access, encryption, SOC monitoring', legal_basis: 'contract' }, ADM);
  assert.equal(fx.status, 200, fx.raw);
  await post('/pdpl/office/run', {});
  const closed = (await tasks()).find((x) => x.id === inc.id);
  assert.equal(closed.status, 'closed'); assert.match(closed.history.slice(-1)[0].what, /registers no longer show it.*confirms the claim by faisal\.syn/);
  assert.equal((await post('/pdpl/office/tasks/' + inc.id + '/ack', {}, ST)).status, 409, 'a closed task takes no action');
  const a = acts(e);
  for (const x of ['pdpl.office.claim', 'pdpl.office.ack', 'pdpl.office.reassign', 'pdpl.office.config', 'pdpl.office.accept_risk', 'pdpl.office.escalated', 'pdpl.office.closed']) assert.ok(a.includes(x), x);
  const au = e.app.store.auditTail(300).find((x) => x.action === 'pdpl.office.accept_risk'); assert.equal(au.by, 'syed'); assert.equal(au.detail.until, '2027-01-31');
});
