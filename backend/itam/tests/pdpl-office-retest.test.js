// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Office re-testing (engine/pdpl-office.js): a task marked done is re-checked against the registers on every routing run;
// gone -> closed "verified by re-test" with the evidence (which check, when, how many re-checks); still shown verify_days after the
// claim (default 3) -> reopened, the assignee told, escalated to the DPO; verify_days set by the DPO / an admin and validated;
// the verification state on the task; the audit records. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, DPO = { user: 'huda.syn', role: 'operator' }, ST = { user: 'faisal.syn', role: 'viewer' };

async function setup(t) {
  let clock = Date.parse('2026-10-20T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' });
  const ropa = (await post('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', data_categories: ['health'], legal_basis: 'legitimate_interest' }, ADM)).json;
  // what the office would send: captured, never delivered
  const sent = [], N = e.app.addons.privacyOffice.notifier; if (N) N.sendPlatform = async (b) => { sent.push(b); return { status: 'queued' }; };
  assert.equal((await post('/pdpl/office/run', {})).status, 200);
  const tasks = async () => (await get('/pdpl/office')).json.tasks;
  return { e, post, get, ropa, tasks, sent, tick: (d) => { clock += d * DAY; } };
}
const acts = (e, a) => e.app.store.auditTail(500).filter((x) => x.action === a);

test('a claim the registers confirm closes "verified by re-test" with the evidence', async (t) => {
  const { e, post, ropa, tasks, tick } = await setup(t);
  const inc = (await tasks()).find((x) => x.key.includes('ropa:' + ropa.id + ':incomplete'));
  const c = await post('/pdpl/office/tasks/' + inc.id + '/done', { note: 'filled every field (synthetic)' }, ST); assert.equal(c.status, 200, c.raw);
  assert.equal(c.json.verification.state, 'checking'); assert.equal(c.json.verification.days, 3); assert.equal(c.json.verification.runs, 0);
  tick(1); await post('/pdpl/office/run', {});
  let x = (await tasks()).find((y) => y.id === inc.id); assert.equal(x.status, 'claimed'); assert.equal(x.verification.state, 'checking'); assert.equal(x.verification.runs, 1);
  assert.match(x.verification.check, /PDPL register check P-04:ropa:.*:incomplete \(P-04\) on pdpl "Medical claims/); assert.equal(x.verification.last_result, 'the registers still show it');
  const fx = await post('/pdpl/records', { kind: 'ropa', id: ropa.id, name: ropa.name, owner: 'Claims', data_categories: ['health'], purpose: 'Assess and pay medical claims', subjects: 'Insured members (synthetic)', systems: ['CLAIMS-SQL'], retention_months: 120, recipients: ['TPA (synthetic)'], security_measures: 'Tiered access, encryption, SOC monitoring', legal_basis: 'contract' }, ADM);
  assert.equal(fx.status, 200, fx.raw);
  await post('/pdpl/office/run', {});
  x = (await tasks()).find((y) => y.id === inc.id);
  assert.equal(x.status, 'closed'); assert.equal(x.closed_reason, 'verified by re-test'); assert.equal(x.verification.state, 'verified'); assert.equal(x.verification.runs, 2);
  assert.match(x.verification.evidence, /verified by re-test: PDPL register check P-04:ropa:.*no longer raised by the PDPL registers at 2026-10-21T08:00/);
  assert.match(x.history.slice(-1)[0].what, /confirms the claim by faisal\.syn.*verified by re-test/);
  const v = (await (await e.req('GET', '/pdpl/office', OP)).json); assert.ok(v.totals.verified >= 1); assert.equal(v.verify_days, 3);
  const au = acts(e, 'pdpl.office.verified').find((y) => y.target === inc.id); assert.ok(au, 'audited'); assert.equal(au.detail.claimed_by, 'faisal.syn'); assert.equal(au.by, OP.user);
});

test('a claim still shown after verify_days is reopened, the assignee told, escalated to the DPO; verify_days is validated', async (t) => {
  const { e, post, get, tasks, sent, tick } = await setup(t);
  const dp = (await tasks()).find((x) => x.key.includes('P-07:dpia')); assert.equal(dp.assignee, 'faisal.syn');
  assert.equal((await post('/pdpl/office/config', { verify_days: 0 }, DPO)).status, 400);
  const bad = await post('/pdpl/office/config', { verify_days: 31 }, DPO); assert.equal(bad.status, 400); assert.match(bad.json.error, /verify_days/);
  assert.equal((await post('/pdpl/office/config', { verify_days: 2 }, OP)).status, 403, 'an operator who is not the DPO');
  assert.equal((await post('/pdpl/office/config', { verify_days: 2 }, DPO)).status, 200);
  assert.ok(acts(e, 'pdpl.office.config').some((x) => x.detail.verify_days === 2));
  assert.equal((await post('/pdpl/office/tasks/' + dp.id + '/done', { note: 'DPIA drafted with the medical team (synthetic)' }, ST)).json.verification.days, 2);
  tick(1); await post('/pdpl/office/run', {});
  assert.equal((await tasks()).find((x) => x.id === dp.id).status, 'claimed', 'inside verify_days: still checking');
  tick(1.1); await post('/pdpl/office/run', {});
  const x = (await tasks()).find((y) => y.id === dp.id);
  assert.equal(x.status, 'open'); assert.equal(x.verification.state, 'failed'); assert.equal(x.verification.runs, 2);
  assert.equal(x.escalation, 1); assert.equal(x.escalated_to, 'huda.syn');
  assert.ok(x.history.some((h) => /verification failed: the registers still show it 2 day\(s\) after faisal\.syn marked it done/.test(h.what)));
  assert.ok(acts(e, 'pdpl.office.verify_failed').some((y) => y.target === dp.id && y.detail.claimed_by === 'faisal.syn'));
  assert.ok(acts(e, 'pdpl.office.escalated').some((y) => y.target === dp.id && y.detail.why === 'verification failed'));
  assert.ok(sent.some((m) => m.users.includes('faisal.syn') && /PO-\d+ is open again/.test(m.subject)), 'the assignee is told');
  const n = sent.length; await post('/pdpl/office/run', {}); assert.equal(sent.length, n, 'told once per claim');
  assert.ok((await get('/pdpl/office/mine', ST)).json.tasks.some((y) => y.id === dp.id && y.verification.state === 'failed'), 'the assignee sees it on My tasks');
  assert.equal((await get('/pdpl/office')).json.totals.verify_failed, 1);
});

test('reassigning a claimed task withdraws its re-check', async (t) => {
  const { post, tasks } = await setup(t);
  const dp = (await tasks()).find((x) => x.key.includes('P-07:dpia'));
  await post('/pdpl/office/tasks/' + dp.id + '/done', { note: 'DPIA drafted with the medical team (synthetic)' }, ST);
  const r = await post('/pdpl/office/tasks/' + dp.id + '/reassign', { user: 'omar.syn', reason: 'records manager owns it' }, DPO);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'open'); assert.equal(r.json.verification.state, 'withdrawn');
});
