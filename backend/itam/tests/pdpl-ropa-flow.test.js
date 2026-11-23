// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RoPA workflow automation (engine/pdpl-ropa-flow.js, pyengine/ropa_flow_rules.py) over the real campaign (engine/pdpl-ropa.js):
// proposed drafts from the Data Catalog accepted by the steward through the campaign's own rules (a service identity refused, another
// department's steward refused, an unknown system refused), risk + DPIA per activity, duplicates across departments, the completion
// forecast, reminders to stewards through the SIEM relay (e-mail from the steward record, never in the audit), late departments as
// Notification & Escalation signals, settings validated and operator-only. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const CLAIMS = { user: 'faisal.syn', role: 'viewer' }, HR = { user: 'reem.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-10-20T08:00:00Z'); const sent = [];
  const siem = async (m, p, b, user) => { sent.push({ p, b, user }); return { ok: true }; };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, ropaSiem: siem });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  assert.equal((await post('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' }, ADM)).status, 200);
  assert.equal((await post('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward', email: 'Faisal.Syn@corpgroup.test' })).status, 200);
  assert.equal((await post('/pdpl/stewards', { department: 'Human Resources', user: 'reem.syn', role: 'data_steward' })).status, 200);
  assert.equal((await post('/pdpl/stewards', { department: 'Finance', user: 'fin.syn', role: 'data_steward', email: 'not-mail' })).status, 400, 'a steward e-mail is validated');
  e.app.store.collection('assets').put({ id: 'a1', name: 'CLAIMS-SQL', mgmt_ip: '10.8.0.52', department: 'Claims', status: 'active' });
  e.app.store.collection('pdpl_discovery').put({ id: 'mssql|10.8.0.52|1433', db: 'mssql|10.8.0.52|1433', engine: 'mssql', label: 'CLAIMS-SQL', host: '10.8.0.52', ok: true,
    columns: [{ owner: 'dbo', table: 'Claims', column: 'DiagCode', kind: 'health', category: 'health', confirmed: true }, { owner: 'dbo', table: 'Members', column: 'NationalId', kind: 'national_id', category: 'identity', confirmed: true }] });
  const c = (await post('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-11-05', departments: ['Claims', 'Human Resources'] })).json;
  return { e, post, get, c, sent, at: (t2) => { clock = t2; }, now: () => clock };
}

test('proposed drafts from the Data Catalog: accepted by the steward through the campaign rules; risk, DPIA, refusals, audit', async (t) => {
  const { e, post, get, c } = await setup(t);
  let f = (await get('/pdpl/ropa-flow/' + c.id, CLAIMS)).json;
  assert.ok(f.ml && f.ml.ok, JSON.stringify(f.ml).slice(0, 200));
  const prop = f.ml.autodraft.Claims; assert.ok(prop && prop[0].system === 'CLAIMS-SQL', 'the claims database is proposed as a draft');
  assert.deepEqual(f.departments.map((d) => d.department), ['Claims'], 'a steward sees only their department');
  assert.equal(f.settings, undefined, 'settings are for operators');
  // refusals
  let r = await post('/pdpl/ropa-flow/' + c.id + '/accept', { department: 'Claims', items: [{ system: 'CLAIMS-SQL' }] }, { user: 'ai:helper', role: 'operator' }); assert.equal(r.status, 403);
  r = await post('/pdpl/ropa-flow/' + c.id + '/accept', { department: 'Claims', items: [{ system: 'CLAIMS-SQL' }] }, HR); assert.ok([403, 404].includes(r.status), 'another department\'s steward');
  r = await post('/pdpl/ropa-flow/' + c.id + '/accept', { department: 'Claims', items: [{ system: 'NOT-PROPOSED' }] }, CLAIMS); assert.equal(r.status, 400); assert.match(r.json.error, /not a proposed system/);
  r = await post('/pdpl/ropa-flow/' + c.id + '/accept', { department: 'Claims', items: 'x' }, CLAIMS); assert.equal(r.status, 400);
  // the steward accepts: an ordinary draft, made by the campaign's own rules
  r = await post('/pdpl/ropa-flow/' + c.id + '/accept', { department: 'Claims', items: [{ system: 'CLAIMS-SQL' }] }, CLAIMS);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.created, 1);
  f = (await get('/pdpl/ropa-flow/' + c.id, CLAIMS)).json;
  const d = f.departments[0].drafts[0]; assert.deepEqual(d.fields.systems, ['CLAIMS-SQL']); assert.ok(d.fields.data_categories.includes('health'));
  assert.ok(!(f.ml.autodraft.Claims || []).length, 'no longer proposed once a draft covers it');
  const rk = f.ml.risk[d.id]; assert.equal(rk.dpia_required, true); assert.ok(rk.why.some((w) => /sensitive data \(health\)/.test(w)));
  const au = e.app.store.auditTail(30);
  assert.ok(au.some((x) => x.action === 'pdpl.ropa.flow.accept' && x.by === 'faisal.syn' && x.detail.drafts === 1));
  assert.ok(au.some((x) => /ropa/.test(x.action) && x.by === 'faisal.syn' && x.action !== 'pdpl.ropa.flow.accept'), 'the campaign\'s own draft audit too');
  // duplicates across departments: HR describes the same system and data
  assert.equal((await post('/pdpl/ropa/drafts', { campaign: c.id, department: 'Human Resources', name: 'Claims data for HR (synthetic)', purpose: 'claims health identity', data_categories: ['health', 'identity'], systems: ['CLAIMS-SQL'] }, HR)).status, 200);
  f = (await get('/pdpl/ropa-flow/' + c.id, OP)).json;
  assert.ok(f.ml.duplicates.length >= 1 && f.ml.duplicates[0].a.department !== f.ml.duplicates[0].b.department, 'the same processing in two departments is a question for the DPO');
});

test('forecast, reminders through the relay (no address in the audit), late departments for Notification & Escalation, settings', async (t) => {
  const { e, post, get, c, sent, at } = await setup(t);
  // settings: operator only, validated
  assert.equal((await post('/pdpl/ropa-flow/' + c.id + '/settings', { before_days: [3] }, CLAIMS)).status, 403);
  let r = await post('/pdpl/ropa-flow/' + c.id + '/settings', { before_days: [0] }); assert.equal(r.status, 400); assert.match(r.json.error, /before_days/);
  r = await post('/pdpl/ropa-flow/' + c.id + '/settings', { dpo_email: 'nope' }); assert.equal(r.status, 400);
  r = await post('/pdpl/ropa-flow/' + c.id + '/settings', { before_days: [7, 3, 1], late_every_days: 2, dpo_email: 'dpo.syn@corpgroup.test' }); assert.equal(r.status, 200);
  // 3 days before the due date at 09:00 Riyadh: reminders go to the stewards with an e-mail; HR has none -> recorded as not sent
  at(Date.parse('2026-11-02T06:00:00Z'));
  await e.app.addons.ropaFlow.tick();
  const rel = sent.filter((x) => x.p === '/reports/deliver'); assert.equal(rel.length, 1); assert.deepEqual(rel[0].b.recipients, ['faisal.syn@corpgroup.test']); assert.equal(rel[0].user, 'system:itam-notify');
  assert.match(rel[0].b.subject, /RoPA for Claims: 3 day\(s\) to the due date/);
  let f = (await get('/pdpl/ropa-flow/' + c.id, OP)).json;
  assert.ok(f.reminders.some((x) => x.department === 'Human Resources' && x.status === 'failed' && /no e-mail address/.test(x.error)), 'a steward without an address is named');
  await e.app.addons.ropaFlow.tick(); assert.equal(sent.filter((x) => x.p === '/reports/deliver').length, 1, 'once a day');
  // remind-now: operator only, audited
  assert.equal((await post('/pdpl/ropa-flow/' + c.id + '/remind-now', {}, CLAIMS)).status, 403);
  assert.equal((await post('/pdpl/ropa-flow/' + c.id + '/remind-now', {})).status, 200);
  assert.ok(e.app.store.auditTail(40).some((x) => x.action === 'pdpl.ropa.flow.remind-now' && x.by === 'nora.syn'));
  assert.ok(!JSON.stringify(e.app.store.auditTail(80)).includes('faisal.syn@'), 'addresses never in the audit');
  // past the due date: late -> a signal for Notification & Escalation, and a late reminder every 2 days
  at(Date.parse('2026-11-07T07:00:00Z'));
  const sig = e.app.addons.ropaFlow.signals(); assert.equal(sig.length, 2); assert.equal(sig[0].source, 'pdpl'); assert.match(sig[0].title, /RoPA of Claims is late/);
  await e.app.addons.ropaFlow.tick(); assert.ok(sent.filter((x) => x.p === '/reports/deliver').some((x) => /past the due date/.test(x.b.subject)));
  f = (await get('/pdpl/ropa-flow/' + c.id, OP)).json;
  assert.equal(f.ml.forecast.Claims.verdict, 'late'); assert.equal(f.ml.forecast['Human Resources'].verdict, 'late');
  // and the notification centre routes it like any other condition
  const N = e.app.addons.notifyCenter; e.app.addons.updateHealth.view = () => ({ pages: [] });
  N.saveTeams({ teams: [{ id: 'dpo', name: 'DPO office', members: [{ name: 'Huda Syn', email: 'huda.syn@corpgroup.test' }] }] }, ADM);
  N.savePolicies({ policies: [{ id: 'pdpl', name: 'PDPL deadlines', sources: ['pdpl'], min_severity: 2, team: 'dpo', steps: [{ after_min: 0, to: 'oncall' }] }] }, ADM);
  await N.tick(null);
  const incs = N.view({ role: 'operator' }).incidents.filter((i) => i.source === 'pdpl');
  assert.equal(incs.length, 2); assert.equal(incs[0].policy, 'pdpl');
});
