// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI engineers' duty desk (engine/duty): the duty cycle end to end with fake engineers - open, investigate, AI root cause
// that proposes a change, change approved → applied → verified, cleared, re-opened, snooze, close codes + suppression,
// "not connected" never resolves anything, AI daily cap, shift report, tickets - and the SIEM adapters over fake netops /
// sysadmin instances (firewalls split from the network engineer), routes and roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createDuty } = require('../engine/duty/duty-core');
const routes = require('../engine/duty/routes');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-duty-'));
const store = async () => createState({ dir: path.join(tmp(), 'state') });

function fakeEngineer() {
  const E = { list: [], changes: {}, present: true, aiOn: true, aiCalls: 0, propose: true };
  E.adapter = {
    id: 'network', name: 'AI Network Engineer',
    findings: () => E.list,
    investigate: (it) => ({ summary: 'WAN link down on ' + it.target.name, checks: [{ name: 'reachability', status: 'fail', detail: 'no reply' }], causes: [{ cause: 'ISP circuit down', confidence: 'high', fix: 'call ISP' }] }),
    aiStatus: () => ({ enabled: E.aiOn, reason: E.aiOn ? '' : 'no key' }),
    aiInvestigate: async (it, { onChange }) => { E.aiCalls++; if (E.propose) { const id = 'NCHG-' + String(E.aiCalls).padStart(6, '0'); E.changes[id] = { status: 'proposed' }; onChange({ id }); } return { answer: 'Root cause: ISP. Next steps…', steps: [{}, {}], model: 'claude-x' }; },
    changeStatus: (id) => E.changes[id] || null,
    verify: async () => ({ present: E.present, note: E.present ? 'still there' : 'gone' }),
  };
  return E;
}
const F = (over) => Object.assign({ key: 'r1:wan-down', severity: 'critical', kind: 'wan-down', title: 'Riyadh branch WAN down', evidence: ['ge-0/0/1 down'], recommendation: 'Check the circuit', target: { type: 'device', id: 'r1', name: 'RUH-RTR-01' }, site: 'Riyadh' }, over || {});

test('duty: open → investigate → AI proposes a change → approved → applied → verified fixed', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(), st = await store();
  const D = createDuty({ store: st, engineers: [E.adapter], now: () => t });
  E.list = [F()];
  let r = await D.patrol('network');
  assert.equal(r.opened, 1); assert.equal(r.investigated, 1); assert.equal(r.ai, 1);
  let it = D.list({ engineer: 'network' }).items[0];
  assert.match(it.id, /^DW-\d{6}$/);
  assert.equal(it.status, 'awaiting-approval', 'the AI proposed a plan: waiting for an administrator');
  assert.deepEqual(it.changes, ['NCHG-000001']);
  assert.match(D.get(it.id).investigation.summary, /WAN link down/);
  assert.match(D.get(it.id).ai.answer, /Root cause/);
  // the same finding next patrol: one work item, counted, no second AI call
  t += 600000; r = await D.patrol('network'); assert.equal(r.opened, 0); assert.equal(r.updated, 1); assert.equal(E.aiCalls, 1);
  E.changes['NCHG-000001'].status = 'approved'; t += 600000; await D.patrol('network');
  assert.equal(D.get(it.id).status, 'approved');
  E.changes['NCHG-000001'].status = 'applied'; E.present = false; t += 600000; r = await D.patrol('network');
  it = D.get(it.id);
  assert.equal(it.status, 'resolved'); assert.equal(it.resolution, 'verified-fixed', 'a fresh re-check no longer shows it');
  assert.ok(it.history.some((h) => h.action === 'fix-proposed') && it.history.some((h) => h.action === 'verified-fixed'));
});

test('duty: still present after the fix (twice) goes back to a person; rejected plan → needs-human', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(), D = createDuty({ store: await store(), engineers: [E.adapter], now: () => t });
  E.list = [F()]; await D.patrol('network');
  const id = D.list().items[0].id;
  E.changes['NCHG-000001'].status = 'applied'; E.present = true;
  t += 20 * 60000; await D.patrol('network'); assert.equal(D.get(id).status, 'fix-applied');
  t += 20 * 60000; await D.patrol('network'); assert.equal(D.get(id).status, 'needs-human');
  assert.ok(D.get(id).history.some((h) => h.action === 'still-present'));
  // a second item whose plan is rejected
  E.list = [F(), F({ key: 'r2:cpu', title: 'Core switch CPU 95%', target: { type: 'device', id: 'r2', name: 'CORE-01' } })];
  t += 600000; await D.patrol('network');
  const id2 = D.list().items.find((x) => x.key === 'r2:cpu').id, cid = D.get(id2).changes[0];
  E.changes[cid] = { status: 'rejected', comment: 'not in a change window' }; t += 600000; await D.patrol('network');
  assert.equal(D.get(id2).status, 'needs-human'); assert.match(D.get(id2).history.slice(-1)[0].note, /rejected: not in a change window/);
});

test('duty: cleared on its own, re-opened when it comes back; not connected resolves nothing', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(); E.aiOn = false; const D = createDuty({ store: await store(), engineers: [E.adapter], now: () => t });
  E.list = [F({ severity: 'medium' })]; await D.patrol('network');
  const id = D.list().items[0].id; assert.equal(D.get(id).status, 'diagnosed');
  E.list = null; t += 600000; const r0 = await D.patrol('network');           // source not connected
  assert.equal(r0.not_connected, true); assert.equal(D.get(id).status, 'diagnosed', 'silence is not health');
  E.list = []; t += 600000; await D.patrol('network');
  assert.equal(D.get(id).status, 'resolved'); assert.equal(D.get(id).resolution, 'cleared');
  E.list = [F({ severity: 'medium' })]; t += 3600000; const r = await D.patrol('network');
  assert.equal(r.reopened, 1); assert.equal(D.list().total, 1, 'the same work item, re-opened');
  assert.equal(D.get(id).reopened, 1); assert.equal(D.get(id).status, 'diagnosed');
  // a finding that throws is an error, not a clearance
  E.adapter.findings = () => { throw new Error('poller down'); }; t += 600000; const r2 = await D.patrol('network');
  assert.match(r2.errors[0], /poller down/); assert.equal(D.get(id).status, 'diagnosed');
  assert.equal(D.engineers()[0].last_error.includes('poller down'), true);
});

test('duty: snooze needs a reason and ends; close codes - accepted risk is suppressed 30 days, fixed re-opens', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(); E.aiOn = false; const D = createDuty({ store: await store(), engineers: [E.adapter], now: () => t });
  E.list = [F({ severity: 'low' }), F({ key: 'k2', severity: 'low', title: 'other' })]; await D.patrol('network');
  const [a, b] = D.list().items.map((x) => x.id).sort();
  assert.throws(() => D.snooze(a, 4, '', 'ali'), /reason/);
  assert.throws(() => D.snooze(a, 0, 'x', 'ali'), /1-720/);
  D.snooze(a, 4, 'waiting for the ISP window', 'ali'); assert.equal(D.get(a).status, 'snoozed');
  t += 5 * 3600000; await D.patrol('network'); assert.equal(D.get(a).status, 'diagnosed', 'snooze ended');
  assert.throws(() => D.close(a, 'whatever', 'x', 'ali'), /close code/);
  assert.throws(() => D.close(a, 'fixed', '', 'ali'), /reason/);
  D.close(a, 'accepted-risk', 'legacy site, replacement in Q1', 'syed');
  D.close(b, 'fixed', 'replaced the cable', 'ali');
  t += 600000; const r = await D.patrol('network');
  assert.equal(D.get(a).status, 'closed', 'accepted risk: not raised again'); assert.equal(D.get(a).suppressed_seen, 1);
  assert.equal(r.reopened, 1); assert.notEqual(D.get(b).status, 'closed', 'a fix that did not hold re-opens');
  D.assign(b, '', 'ali'); assert.equal(D.get(b).owner, 'ali');
  D.note(b, 'called the site', 'ali'); assert.equal(D.get(b).history.slice(-1)[0].action, 'note');
});

test('duty: AI daily cap and AI off; manual investigate; shift report; tickets', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(); E.propose = false;
  const created = [];
  const ticketer = { create: async (id, by) => { created.push([id, by]); return { ticket: { request_id: '5' + created.length, url: 'https://sdp/' + created.length } }; } };
  const D = createDuty({ store: await store(), engineers: [E.adapter], now: () => t, ticketer });
  D.setPolicy({ ai_daily_cap: 2, ticket_min_severity: 'high' }, 'syed');
  assert.throws(() => D.setPolicy({ ai_min_severity: 'loud' }, 'syed'), /must be off/);
  E.list = [1, 2, 3, 4].map((n) => F({ key: 'k' + n, title: 'problem ' + n }));
  await D.patrol('network');
  assert.equal(E.aiCalls, 2, 'capped at 2 AI investigations a day');
  assert.equal(D.list().items.filter((x) => x.status === 'needs-human').length, 2, 'AI done, no change plan → a person');
  assert.equal(created.length, 4, 'tickets for high/critical'); assert.equal(D.get(D.list().items[0].id).ticket.request_id.startsWith('5'), true);
  E.aiOn = false; const id = D.list().items.find((x) => x.status === 'diagnosed').id;
  await assert.rejects(() => D.aiInvestigate(id, 'ali'), /no key/);
  const again = await D.investigate(id, 'ali', { ai: false }); assert.equal(again.status, 'diagnosed');
  const rep = D.makeReport('network');
  assert.equal(rep.counts.opened, 4); assert.equal(rep.counts.open, 4); assert.equal(rep.needs_human.length, 4);
  assert.match(rep.summary, /shift handover/); assert.match(rep.summary, /Open now: 4/);
  // daily report at the report hour (07:00 Riyadh = 04:00 UTC), once
  t = Date.UTC(2026, 9, 16, 4, 30); await D.tick(); await D.tick();
  assert.equal(D.listReports('network').length, 1);
});

test('duty adapters: firewalls go to the security engineer, others to network; servers by role; verify re-polls', async () => {
  const devices = { r1: { id: 'r1', vendor: 'cisco-ios', name: 'RUH-RTR-01' }, f1: { id: 'f1', vendor: 'fortigate', name: 'FW-HQ' } };
  let fnd = [{ id: 'r1:down', device: 'r1', device_name: 'RUH-RTR-01', site: 'Riyadh', severity: 'critical', kind: 'down', title: 'RUH-RTR-01 down', evidence: [], recommendation: 'x' },
    { id: 'f1:licence', device: 'f1', device_name: 'FW-HQ', site: 'HQ', severity: 'high', kind: 'licence', title: 'FortiGuard expired', evidence: [], recommendation: 'renew' }];
  const polled = [];
  const N = { inventory: { list: () => Object.values(devices), get: (id) => devices[id] }, findings: () => fnd, diagnose: async () => ({ summary: 's', checks: [], causes: [] }),
    ai: { status: () => ({ enabled: false, reason: 'no key' }) }, changes: { get: () => null }, poller: { pollDevice: async (id) => { polled.push(id); } } };
  const [net, sec] = routes.netAdapters(N);
  assert.deepEqual(net.findings().map((f) => f.key), ['r1:down']);
  assert.deepEqual(sec.findings().map((f) => f.key), ['f1:licence']);
  fnd = fnd.slice(1); const v = await net.verify({ key: 'r1:down', target: { id: 'r1', name: 'RUH-RTR-01' } });
  assert.deepEqual(polled, ['r1']); assert.equal(v.present, false);
  assert.equal(routes.netAdapters({ inventory: { list: () => [], get: () => null }, findings: () => [] })[0].findings(), null, 'nothing onboarded = not connected');
  // servers: the finding key ignores numbers in the title (3 % free and 2 % free are one problem)
  let hf = [{ server: 's1', server_name: 'FS01', site: 'HQ', severity: 'critical', kind: 'disk', title: 'FS01 C: almost full: 3 % free', evidence: [], recommendation: 'clean' }];
  const S = { targets: { list: (role) => (role === 'exchange' ? [] : [{ id: 's1' }]) }, health: { findings: () => hf, snapshot: () => null, pollServer: async () => {} }, ai: { status: () => ({ enabled: false }) }, changes: { get: () => null } };
  const [win, exch] = routes.sysAdapters(S);
  const k1 = win.findings()[0].key; hf = [Object.assign({}, hf[0], { title: 'FS01 C: almost full: 2 % free' })];
  assert.equal(win.findings()[0].key, k1);
  assert.equal(exch.findings(), null, 'no Exchange server onboarded');
});

test('duty routes: reads open, actions need operator, policy needs admin; ServiceDesk ticket kind registered', async () => {
  const st = await store(), R = {}, kinds = {};
  const me = { registerKind: (k, def) => { kinds[k] = def; }, createTicket: async ({ kind, id }) => ({ ticket: { request_id: '77', url: 'u' }, kind, id }) };
  const devices = { r1: { id: 'r1', vendor: 'cisco-ios', name: 'R1' } };
  const N = { inventory: { list: () => Object.values(devices), get: (id) => devices[id] }, findings: () => [{ id: 'r1:down', device: 'r1', device_name: 'R1', site: 'HQ', severity: 'high', kind: 'down', title: 'R1 down', evidence: [], recommendation: 'x' }],
    diagnose: async () => ({ summary: 'down', checks: [], causes: [] }), ai: { status: () => ({ enabled: false }) }, changes: { get: () => null }, poller: { pollDevice: async () => {} } };
  const deps = { state: st, config: { duty: { enabled: false } }, log: { info() {}, warn() {}, error() {} }, netopsInstance: N, integrations: { manageengine: me } };
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, deps);
  assert.ok(kinds.duty, 'work items can become ServiceDesk Plus requests');
  const ctx = (role, b, params, query) => { const c = { role, user: 'u-' + role, body: b || {}, params: params || {}, query: query || {}, out: null, code: 200,
    need(r) { const RK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (RK[role] < RK[r]) { c.code = 403; return false; } return true; }, audit() {}, ok(x) { return x; }, fail(code, msg) { c.code = code; c.msg = msg; return { error: msg }; } }; return c; };
  const call = async (k, c) => { const r = await R[k](c); return { r, c }; };
  await call('POST /api/soc/duty/patrol', ctx('operator', { engineer: 'network' }));
  const list = (await call('GET /api/soc/duty/items', ctx('viewer', {}, {}, { status: 'open' }))).r;
  assert.equal(list.total, 1); const id = list.items[0].id;
  const ids = (await call('GET /api/soc/duty/engineers', ctx('viewer'))).r.engineers.map((e) => e.id), offE = require('../engine/util/brand').engineers_off || [];
  assert.deepEqual(ids.filter((x) => !['fortigate', 'nac', 'ndr', 'mimecast'].includes(x)), ['network', 'security'], 'no server administrators onboarded in this test');
  assert.deepEqual(ids.filter((x) => ['fortigate', 'nac', 'ndr', 'mimecast'].includes(x)), ['fortigate', 'nac', 'ndr', 'mimecast'].filter((x) => !offE.includes(x)), 'the organisation\'s own estate engineers');
  let x = await call('POST /api/soc/duty/items/:id/snooze', ctx('viewer', { hours: 2, reason: 'x' }, { id })); assert.equal(x.c.code, 403);
  x = await call('POST /api/soc/duty/items/:id/snooze', ctx('operator', { hours: 2 }, { id })); assert.equal(x.c.code, 400);
  x = await call('POST /api/soc/duty/items/:id/ticket', ctx('operator', {}, { id })); assert.equal(x.r.ticket.request_id, '77');
  assert.equal(deps.dutyInstance.get(id).ticket.request_id, '77');
  assert.match(kinds.duty.description(deps.dutyInstance.get(id)), /Nothing was changed automatically/);
  x = await call('PUT /api/soc/duty/policy', ctx('operator', { patrol_min: 5 })); assert.equal(x.c.code, 403);
  x = await call('PUT /api/soc/duty/policy', ctx('admin', { patrol_min: 5 })); assert.equal(x.r.patrol_min, 5);
  x = await call('GET /api/soc/duty/items/:id', ctx('viewer', {}, { id: 'DW-999999' })); assert.equal(x.c.code, 404);
});

test('duty: rule-based propose (no AI) puts the item in approval; a deploy in progress is not counted as a failed fix', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const reqs = {}; let present = true, verifyCalls = 0;
  const A = { id: 'desktop', name: 'AI Desktop Support Engineer', findings: () => [F({ key: 'pc1:patch', severity: 'high', title: 'PC1: 3 critical patches missing' })],
    propose: (it, { onChange }) => { reqs.dp_1 = { state: 'requested' }; onChange({ id: 'dp_1' }); return { note: 'patch install requested' }; },
    changeStatus: (id) => (reqs[id] ? { status: reqs[id].state === 'requested' ? 'proposed' : reqs[id].state === 'deploying' ? 'applied' : 'rejected' } : null),
    verify: async () => { verifyCalls++; return { present: present ? null : false, note: 'waiting for Endpoint Central' }; } };
  const D = createDuty({ store: await store(), engineers: [A], now: () => t });
  await D.patrol('desktop');
  const it = D.list().items[0]; assert.equal(it.status, 'awaiting-approval'); assert.deepEqual(it.changes, ['dp_1']);
  reqs.dp_1.state = 'deploying';
  for (let i = 0; i < 4; i++) { t += 20 * 60000; await D.patrol('desktop'); }
  assert.equal(D.get(it.id).status, 'fix-applied', 'unknown (still deploying) is not a failure'); assert.ok(verifyCalls >= 3);
  present = false; t += 20 * 60000; await D.patrol('desktop');
  assert.equal(D.get(it.id).resolution, 'verified-fixed');
});

test('duty KPIs: measured from the work items; nothing to measure = not measured; targets per engineer; adapter measures', async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = fakeEngineer(), st = await store();
  E.adapter.kpis = (open) => [{ label: 'WAN links down', value: require('../engine/duty/duty-core').kindCount(open, ['wan-down'], true), target: 0 }];
  const D = createDuty({ store: st, engineers: [E.adapter], now: () => t });
  let k = D.kpis('network');
  assert.equal(k.score, null, 'nothing has happened: no score, not a perfect one');
  assert.ok(k.kpis.filter((x) => x.id !== 'open_serious' && x.id !== 'patrol_pct').every((x) => x.status === 'na' && x.value === null));
  E.list = [F()];
  await D.patrol('network');                                  // opened, diagnosed, AI proposed a change → awaiting approval
  t += 2 * 3600000; E.changes['NCHG-000001'].status = 'approved'; await D.patrol('network');   // a person approved after 2 h
  t += 3600000; E.changes['NCHG-000001'].status = 'applied'; E.present = false; await D.patrol('network');   // applied → verified
  k = D.kpis('network');
  const g = (id) => k.kpis.find((x) => x.id === id);
  assert.equal(g('approval_h').value, 2); assert.equal(g('approval_h').status, 'ok');
  assert.equal(g('fix_h').value, 3); assert.equal(g('sla_pct').value, 100); assert.equal(g('fix_success_pct').value, 100);
  assert.equal(g('open_serious').value, 0); assert.equal(g('human_h').value, null, 'nobody named touched it: not measured');
  assert.deepEqual(k.domain, [{ label: 'WAN links down', value: 0, unit: '', target: 0, dir: 'max', status: 'ok' }]);
  assert.equal(k.counts.verified_fixed, 1);
  // stricter approval target for this engineer → 2 h now misses it
  D.setPolicy({ kpi_targets: { network: { approval_h: 1 } } }, 'admin');
  assert.equal(D.kpis('network').kpis.find((x) => x.id === 'approval_h').status, 'bad');
  assert.throws(() => D.setPolicy({ kpi_targets: { network: { nope: 1 } } }, 'admin'), /unknown KPI/);
  assert.throws(() => D.setPolicy({ kpi_targets: { ghost: { sla_pct: 1 } } }, 'admin'), /unknown engineer/);
  // an open critical past its 24 h SLA counts against the SLA
  E.list = [F({ key: 'r2:wan-down', target: { type: 'device', id: 'r2', name: 'JED-RTR-01' } })]; E.propose = false; E.aiOn = false;
  await D.patrol('network'); t += 30 * 3600000; await D.patrol('network');
  k = D.kpis('network');
  assert.equal(k.kpis.find((x) => x.id === 'sla_pct').value, 50); assert.equal(k.kpis.find((x) => x.id === 'open_serious').status, 'bad');
  assert.equal(k.domain[0].value, 1);
});
