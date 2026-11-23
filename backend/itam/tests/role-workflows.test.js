// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Role workflows (engine/role-workflows.js) with SYNTHETIC assets, duty items and GRC records: the live status of a step comes from
// the platform's records (not seen, end of life, AI engineers' items, overdue GRC actions) and says "nothing recorded" or "confirm"
// rather than ok when it cannot measure; sign-off by a person who is a member of the role, with a note when the step needs attention
// or is an issue / not applicable; no future period; handover summarises the period and is acknowledged by someone else; settings are
// admin-only and versioned; viewers read, cannot sign; every write is audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { periodOf } = require('../engine/role-workflows');

const ADM = { user: 'syed', role: 'admin' }, WIN = { user: 'win.syn', role: 'operator' }, WIN2 = { user: 'win2.syn', role: 'operator' }, NET = { user: 'net.syn', role: 'operator' };
const VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'operator' };
const DAY = 86400000;

async function setup(t) {
  const T = Date.parse('2026-11-21T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const A = e.app.store.collection('assets'), iso = (d) => new Date(T + d * DAY).toISOString();
  A.put({ id: 'w1', name: 'WIN-SYN-1', type: 'server', os: 'Windows Server 2019', status: 'in_use', last_seen: iso(-0.2), eol: '2029-01-09' });
  A.put({ id: 'w2', name: 'WIN-SYN-2 <img src=x>', type: 'server', os: 'Windows Server 2012 R2', status: 'in_use', last_seen: iso(-5), eol: '2023-10-10', warranty: { end: '2024-01-01' } });
  A.put({ id: 'w3', name: 'WIN-SYN-3', type: 'vm', os: 'Windows Server 2022', status: 'in_repair', last_seen: iso(-0.1) });
  e.app.store.collection('grc_actions').put({ id: 'ACT-0001', title: 'Close audit gap (synthetic)', status: 'open', due: '2026-11-01', owner: 'grc.syn' });
  e.app.store.collection('duty_items').put({ id: 'DW-000001', engineer: 'virt', severity: 'critical', status: 'open', title: 'Datastore 95% full (synthetic)' });
  return { e, call, T, audits: (a) => e.app.store.auditTail(500).filter((x) => x.action === 'role-workflow.' + a) };
}

test('periods: daily (Riyadh), ISO week, month', () => {
  assert.equal(periodOf('daily', Date.parse('2026-11-21T22:30:00Z')), '2026-11-22', 'Riyadh is UTC+3');
  assert.equal(periodOf('weekly', Date.parse('2026-11-21T08:00:00Z')), '2026-W47');
  assert.equal(periodOf('weekly', Date.parse('2027-01-01T08:00:00Z')), '2026-W53');
  assert.equal(periodOf('monthly', Date.parse('2026-11-21T08:00:00Z')), '2026-11');
});

test('live status comes from the records; unmeasured steps say confirm; nothing recorded is not ok', async (t) => {
  const s = await setup(t);
  const L = (await s.call('GET', '/role-workflows', undefined, VIEW)).json; assert.equal(L.roles.length, 10);
  assert.deepEqual(L.roles.map((r) => r.id).sort(), ['desktop', 'exchange', 'grc', 'network', 'pentest', 'security', 'siem', 'soc', 'virt', 'windows']);
  const w = (await s.call('GET', '/role-workflows/windows?cadence=daily', undefined, VIEW)).json;
  const seen = w.steps.find((x) => x.id === 'seen'); assert.equal(seen.status.state, 'attention'); assert.equal(seen.status.n, 1); assert.equal(seen.status.items[0].id, 'w2');
  assert.equal(w.steps.find((x) => x.id === 'events').status.state, 'confirm', 'not measured by the platform: confirm, never ok');
  assert.equal(w.steps.find((x) => x.id === 'repair').status.n, 1);
  const wm = (await s.call('GET', '/role-workflows/windows?cadence=monthly', undefined, VIEW)).json;
  assert.match(wm.steps.find((x) => x.id === 'eol').status.text, /1 Windows servers past end of life/);
  assert.equal(wm.steps.find((x) => x.id === 'warranty').status.n, 1);
  const n = (await s.call('GET', '/role-workflows/network?cadence=daily', undefined, VIEW)).json;
  assert.equal(n.steps.find((x) => x.id === 'seen').status.state, 'none', 'no network devices: said, not ok');
  const v = (await s.call('GET', '/role-workflows/virt?cadence=daily', undefined, VIEW)).json;
  assert.equal(v.steps.find((x) => x.id === 'duty').status.n, 1, 'the AI Virtualization Administrator\'s critical item');
  const g = (await s.call('GET', '/role-workflows/grc?cadence=daily', undefined, VIEW)).json;
  assert.equal(g.steps.find((x) => x.id === 'actions').status.items[0].id, 'ACT-0001');
  assert.equal((await s.call('GET', '/role-workflows/nope', undefined, VIEW)).status, 404);
  assert.equal(w.period, '2026-11-21'); assert.equal(w.periods.weekly, '2026-W47');
});

test('sign-off: a person, a member, notes when needed, no future period; audited', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: { windows: ['win.syn', 'win2.syn'] } })).status, 200);
  const P = '/role-workflows/windows/signoff';
  assert.equal((await s.call('POST', P, { step: 'seen', period: '2026-11-21', outcome: 'done' }, VIEW)).status, 403, 'viewer');
  assert.equal((await s.call('POST', P, { step: 'seen', period: '2026-11-21', outcome: 'done' }, BOT)).status, 403, 'AI identity');
  assert.equal((await s.call('POST', P, { step: 'seen', period: '2026-11-21', outcome: 'done' }, NET)).status, 403, 'not a member of the role');
  let r = await s.call('POST', P, { step: 'seen', period: '2026-11-21', outcome: 'done' }, WIN); assert.equal(r.status, 400); assert.match(r.json.error, /note: the platform shows/, 'attention needs a note');
  r = await s.call('POST', P, { step: 'events', period: '2026-11-21', outcome: 'na' }, WIN); assert.equal(r.status, 400); assert.match(r.json.error, /why it does not apply/);
  r = await s.call('POST', P, { step: 'seen', period: '2026-11-22', outcome: 'done', note: 'x' }, WIN); assert.equal(r.status, 400); assert.match(r.json.error, /future/);
  r = await s.call('POST', P, { step: 'eol', period: '2026-11-21', outcome: 'done', note: 'x' }, WIN); assert.equal(r.status, 400); assert.match(r.json.error, /monthly period/);
  r = await s.call('POST', P, { step: 'nope', period: '2026-11-21', outcome: 'done' }, WIN); assert.equal(r.status, 400); assert.match(r.json.error, /step/);
  r = await s.call('POST', P, { step: 'seen', period: '2026-11-21', outcome: 'done', note: 'WIN-SYN-2 back online after a reboot (synthetic)', by: 'someone' }, WIN);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.by, 'win.syn', 'undeclared field dropped'); assert.equal(r.json.measured.state, 'attention');
  assert.equal((await s.call('POST', P, { step: 'events', period: '2026-11-21', outcome: 'done' }, WIN)).status, 200, 'a confirm step done without a note');
  const v = (await s.call('GET', '/role-workflows/windows?cadence=daily', undefined, VIEW)).json; assert.equal(v.counts.signed, 2);
  assert.equal(s.audits('signoff').length, 2); assert.equal(s.audits('signoff')[0].by, 'win.syn');
});

test('handover: summary of the period, acknowledged by someone else; settings admin-only and versioned', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: { windows: ['win.syn'] } }, WIN)).status, 403);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: { nope: ['a.syn'] } })).status, 400);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: { windows: ['bad name!'] } })).status, 400);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: { windows: ['win.syn', 'win2.syn'] } })).status, 200);
  assert.equal((await s.call('POST', '/role-workflows/settings', { version: 0, members: {} })).status, 409, 'stale version');
  assert.equal((await s.call('POST', '/role-workflows/windows/handover', { cadence: 'daily', period: '2026-11-21' }, WIN)).status, 400, 'notes required');
  const h = await s.call('POST', '/role-workflows/windows/handover', { cadence: 'daily', period: '2026-11-21', notes: 'WIN-SYN-2 needs a replacement plan (synthetic)' }, WIN);
  assert.equal(h.status, 200, h.text); assert.ok(h.json.summary.open.length >= 3); assert.ok(h.json.summary.attention.some((x) => /not seen/.test(x)));
  assert.equal((await s.call('POST', '/role-workflows/handovers/' + h.json.id + '/ack', {}, WIN)).status, 403, 'the author does not acknowledge');
  const a = await s.call('POST', '/role-workflows/handovers/' + h.json.id + '/ack', { note: 'taken over' }, WIN2); assert.equal(a.status, 200); assert.equal(a.json.ack.by, 'win2.syn');
  assert.equal((await s.call('POST', '/role-workflows/handovers/' + h.json.id + '/ack', {}, ADM)).status, 409, 'once');
  assert.ok(s.audits('handover').length && s.audits('handover.ack').length && s.audits('settings').length);
});
