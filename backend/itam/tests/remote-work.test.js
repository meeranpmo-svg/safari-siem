// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Work From Home (engine/remote-work.js), SYNTHETIC people: an employee asks for days (weekends not counted, past days, too long,
// overlapping and a department that may not refused; over-policy and no laptop marked for the approver); only a named approver of
// the department or an administrator decides - never the person who asked, never an AI identity, a rejection needs a reason; the
// person cancels their own; the board (operators) shows today, the next working days, readiness (laptop on record, VPN logon
// through the SIEM as the read-only role); the VPN-without-approval indicators only for administrators; policy admin-only and
// validated; every change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const EMP = { user: 'sara.syn', role: 'viewer' }, EMP2 = { user: 'omar.syn', role: 'viewer' }, MGR = { user: 'fahad.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' },
  ADM = { user: 'admin.syn', role: 'admin' }, BOT = { user: 'ai:assistant', role: 'admin' };

test('work from home: request, four-eyes approval, policy, board, VPN indicators, roles, validation, audit', async (t) => {
  let clock = Date.parse('2026-11-29T06:00:00Z');   // Sunday 29 Nov 2026, 09:00 Riyadh
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const aud = (a) => e.app.store.auditTail(500).filter((x) => x.action === 'remote-work.' + a);
  // policy: admin only, validated
  assert.equal((await call('PUT', '/remote-work/policy', { max_days_month: 4, notice_days: 1 }, OP)).status, 403);
  let r = await call('PUT', '/remote-work/policy', { max_days_month: 40, notice_days: 1 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /max_days_month/);
  r = await call('PUT', '/remote-work/policy', { max_days_month: 4, notice_days: 1, departments: { nowhere: { allowed: true } } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /departments\.nowhere/);
  r = await call('PUT', '/remote-work/policy', { max_days_month: 2, notice_days: 1, departments: { finance: { allowed: true, approvers: ['fahad.syn'] }, site_security: { allowed: false } } }, ADM);
  assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.departments.finance.approvers, ['fahad.syn']); assert.equal(aud('policy').length, 1);
  // requests: validation
  const ask = (b, who = EMP) => call('POST', '/remote-work/requests', b, who);
  r = await ask({ from: '2026-11-25', to: '2026-11-26', reason: 'synthetic', department: 'finance' }); assert.equal(r.status, 400); assert.match(r.json.error, /from: a day that has passed/);
  r = await ask({ from: '2026-12-03', to: '2026-12-01', reason: 'synthetic', department: 'finance' }); assert.equal(r.status, 400); assert.match(r.json.error, /^to:/);
  r = await ask({ from: '2026-12-01', to: '2027-01-15', reason: 'synthetic', department: 'finance' }); assert.equal(r.status, 400); assert.match(r.json.error, /at most 31 days/);
  r = await ask({ from: '2026-12-04', to: '2026-12-05', reason: 'synthetic', department: 'finance' }); assert.equal(r.status, 400); assert.match(r.json.error, /weekend/);
  r = await ask({ from: '2026-12-01', to: '2026-12-01', reason: 'x', department: 'finance' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await ask({ from: '2026-12-01', to: '2026-12-01', reason: 'synthetic reason', department: 'nowhere' }); assert.equal(r.status, 400); assert.match(r.json.error, /department/);
  r = await ask({ from: '2026-12-01', to: '2026-12-01', reason: 'synthetic reason', department: 'site_security' }); assert.equal(r.status, 403); assert.match(r.json.error, /does not work from home/);
  assert.equal((await ask({ from: '2026-12-01', to: '2026-12-01', reason: 'synthetic reason', department: 'finance' }, BOT)).status, 403, 'not an AI identity');
  // Sunday 29 Nov .. Thursday 3 Dec: 5 working days (Fri / Sat not counted) - today with less than 1 day notice, over the 2 allowed, no laptop
  r = await ask({ from: '2026-11-29', to: '2026-12-05', reason: 'Family matter (synthetic)', department: 'finance', status: 'approved', user: 'someone.else' });
  assert.equal(r.status, 200, r.text); const A = r.json;
  assert.equal(A.user, 'sara.syn', 'always the person signed in'); assert.equal(A.status, 'pending', 'undeclared fields dropped'); assert.equal(A.days.length, 5);
  assert.ok(A.notes.some((n) => /notice/.test(n)) && A.notes.some((n) => /over the 2 allowed/.test(n)) && A.notes.some((n) => /no company laptop/.test(n)), JSON.stringify(A.notes));
  assert.equal((await ask({ from: '2026-12-01', to: '2026-12-01', reason: 'synthetic again', department: 'finance' })).status, 409, 'overlap refused');
  // deciding: not the person, not an approver of another department, not an AI; a rejection needs a reason
  const dec = (id, b, who) => call('POST', '/remote-work/requests/' + id + '/decide', b, who);
  assert.equal((await dec(A.id, { decision: 'approved' }, EMP)).status, 403, 'not your own');
  assert.equal((await dec(A.id, { decision: 'approved' }, EMP2)).status, 403, 'not someone who is not an approver');
  assert.equal((await dec(A.id, { decision: 'approved' }, BOT)).status, 403, 'not an AI');
  assert.equal((await dec(A.id, { decision: 'rejected' }, MGR)).status, 400, 'a rejection needs a reason');
  assert.equal((await dec(A.id, { decision: 'maybe' }, MGR)).status, 400);
  const mine = (await call('GET', '/remote-work/me', undefined, MGR)).json; assert.deepEqual(mine.waiting_for_me.map((x) => x.id), [A.id], 'waits for the department approver');
  r = await dec(A.id, { decision: 'approved', comment: 'ok' }, MGR); assert.equal(r.status, 200, r.text); assert.equal(r.json.decided_by, 'fahad.syn');
  assert.equal((await dec(A.id, { decision: 'rejected', comment: 'x' }, ADM)).status, 409, 'decided once');
  // another person, decided by an administrator
  const B = (await ask({ from: '2026-11-29', to: '2026-11-29', reason: 'Waiting for a delivery (synthetic)', department: 'it' }, EMP2)).json;
  assert.equal((await dec(B.id, { decision: 'approved' }, ADM)).status, 200);
  // a laptop on record for omar; VPN logons today: sara (approved), omar (approved), khalid.syn (no approval)
  e.app.assets.all = ((orig) => () => orig().concat([{ id: 'syn-lap-1', name: 'LT-SYN-0042', type: 'laptop', owner: 'SAFARI\\omar.syn', status: 'active' }]))(e.app.assets.all.bind(e.app.assets));
  const calls = [];
  e.app.discovery = { siem: { call: async (m, p, who, b) => { calls.push([m, p, who.role, b && b.q]); return { status: 200, json: { values: [{ v: 'sara.syn', n: 3 }, { v: 'omar.syn@safari.com.sa', n: 1 }, { v: 'khalid.syn', n: 2 }] } }; } } };
  assert.equal((await call('GET', '/remote-work/board', undefined, EMP)).status, 403, 'a viewer does not see the board');
  let bd = (await call('GET', '/remote-work/board', undefined, OP)).json;
  assert.equal(bd.kpis.home_today, 2); assert.equal(bd.kpis.no_laptop, 1); assert.equal(bd.kpis.no_vpn, 0);
  const sara = bd.today_list.find((x) => x.user === 'sara.syn'), omar = bd.today_list.find((x) => x.user === 'omar.syn');
  assert.equal(sara.laptop, null); assert.equal(sara.vpn, true); assert.equal(omar.laptop, 'LT-SYN-0042'); assert.equal(omar.vpn, true);
  assert.equal(bd.next_days.length, 14); assert.ok(!bd.next_days.some((d) => [5, 6].includes(new Date(d.day + 'T00:00:00Z').getUTCDay())), 'working days only');
  assert.equal(bd.next_days[0].approved, 2);
  assert.equal(bd.indicators, undefined, 'indicators are for administrators only');
  assert.deepEqual(calls[0].slice(0, 4), ['POST', '/top', 'analyst', 'tags:vpn AND action:logon'], 'read-only, as the auditing role');
  bd = (await call('GET', '/remote-work/board', undefined, ADM)).json;
  assert.deepEqual(bd.indicators.vpn_without_approval, ['khalid.syn']); assert.match(bd.indicators.note, /not proof/);
  // no SIEM link: readiness says so, never "no VPN"
  e.app.discovery = null; bd = (await call('GET', '/remote-work/board', undefined, OP)).json;
  assert.equal(bd.vpn.connected, false); assert.equal(bd.kpis.no_vpn, null); assert.equal(bd.today_list[0].vpn, null);
  // cancel: only the person, only before the days have passed
  assert.equal((await call('POST', '/remote-work/requests/' + A.id + '/cancel', {}, EMP2)).status, 403);
  assert.equal((await call('POST', '/remote-work/requests/' + A.id + '/cancel', {}, EMP)).status, 200);
  assert.equal((await call('POST', '/remote-work/requests/bad%20id/cancel', {}, EMP)).status, 400);
  clock = Date.parse('2026-12-02T06:00:00Z'); assert.equal((await call('POST', '/remote-work/requests/' + B.id + '/cancel', {}, EMP2)).status, 409, 'past days stay as they were');
  // audit: who, role, what - no reason text in the audit detail
  const ra = aud('request'); assert.equal(ra.length, 2); assert.deepEqual(ra.map((x) => x.by).sort(), ['omar.syn', 'sara.syn']); assert.ok(ra.every((x) => x.role === 'viewer')); assert.ok(!JSON.stringify(ra).includes('Family matter'));
  assert.equal(aud('decide').length, 2); assert.equal(aud('cancel').length, 1);
});
