// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Desktop Support Engineer (engine/desksupport.js): triage derivation (priority/group/technician), scan in suggest
// and auto modes against a mock ServiceDesk Plus, desktop health from the synced Endpoint Central computers, patch
// request/approve four-eyes, and route roles. Reuses ManageEngine's sealed creds (mocked here).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDeskSupport } = require('../engine/desksupport');

const ADM = { user: 'syed', role: 'admin', ip: '' }, ADM2 = { user: 'faisal', role: 'admin', ip: '' }, OP = { user: 'ali', role: 'operator', ip: '' };
const NOW = Date.parse('2026-10-15T12:00:00Z');
const fakeSealer = { available: () => true, seal: (p, k) => 'enc:' + k, unseal: (p, e) => String(e).slice(4), unavailableReason: () => '' };

function seedMe(app) {
  app.store.collection('me_config').put({ id: 'cfg', sdp: { base_url: 'https://sdp.local', enc: 'enc:SDPKEY' }, ec: { base_url: 'https://ec.local', enc: 'enc:ECKEY' } });
}
function seedComputers(app) {
  const c = app.store.collection('me_ec_computers');
  c.put({ id: 'r1', resource_id: 'r1', name: 'PC-RUH-01', user: 'ahmed', os: 'Windows 11', live: 'live', last_contact: NOW - 3600000, critical: 4, missing: 12, health: 'highly vulnerable' });
  c.put({ id: 'r2', resource_id: 'r2', name: 'PC-RUH-02', user: 'sara', os: 'Windows 10', live: 'down', last_contact: NOW - 10 * 86400000, critical: 0, missing: 2, health: 'vulnerable' });
  c.put({ id: 'r3', resource_id: 'r3', name: 'PC-JED-01', user: 'omar', os: 'Windows 11', live: 'live', last_contact: NOW - 7200000, critical: 0, missing: 0, health: 'healthy' });
}

test('desk support: triage derivation — priority, group, technician round-robin', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = createDeskSupport(e.app, { now: () => NOW, sealer: fakeSealer });
  assert.equal(D.derivePriority('Production server is down, all users affected', '', '', require('../engine/desksupport').DEF_PRIORITY), 'Urgent');
  assert.equal(D.derivePriority('Outlook not working, cannot access email', '', '', require('../engine/desksupport').DEF_PRIORITY), 'High');
  assert.equal(D.derivePriority('How to install Teams', '', '', require('../engine/desksupport').DEF_PRIORITY), 'Low');
  assert.equal(D.derivePriority('printer jam', '', '', require('../engine/desksupport').DEF_PRIORITY), 'Medium');
  assert.equal(D.deriveGroup('VPN keeps dropping', require('../engine/desksupport').DEF_GROUPS), 'Network');
  assert.equal(D.deriveGroup('reset my password', require('../engine/desksupport').DEF_GROUPS), 'Identity & Access');
  const techs = [{ name: 'T1', email: 't1@x', skills: ['network'] }, { name: 'T2', email: 't2@x', skills: ['printer'] }];
  assert.equal(D.pickTech('vpn down', techs, 0).tech.name, 'T1', 'skill match wins');
  assert.equal(D.pickTech('general issue', techs, 0).tech.name, 'T1', 'round robin first');
  assert.equal(D.pickTech('general issue', techs, 1).tech.name, 'T2', 'round robin advances');
});

test('desk support: scan proposes in suggest mode and applies in auto mode (mock ServiceDesk Plus)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  seedMe(e.app);
  const calls = [];
  const request = async (url, o) => {
    calls.push({ method: o.method, url });
    if (o.method === 'GET' && /\/requests\?/.test(url)) return { status: 200, json: { requests: [
      { id: '101', subject: 'VPN is down, cannot access email', description: 'since this morning', status: { name: 'Open' }, priority: {}, technician: {}, requester: { name: 'ahmed' } },
      { id: '102', subject: 'How to install Teams', status: { name: 'Open' }, priority: {}, technician: {}, requester: { name: 'sara' } },
      { id: '103', subject: 'Already assigned', status: { name: 'Open' }, priority: { name: 'Medium' }, technician: { name: 'someone' }, requester: { name: 'x' } } ] } };
    return { status: 200, json: { response_status: { status: 'success' } } };
  };
  const techs = [{ name: 'Net Tech', email: 'net@x', skills: ['vpn', 'network'] }, { name: 'Desk Tech', email: 'desk@x', skills: [] }];

  // suggest mode: proposals recorded, nothing written
  let D = createDeskSupport(e.app, { now: () => NOW, sealer: fakeSealer, request });
  D.setConfig({ mode: 'suggest', technicians: techs }, ADM);
  let r = await D.scan(ADM);
  assert.equal(r.mode, 'suggest'); assert.equal(r.proposed, 2, 'two untriaged tickets proposed, the assigned one skipped');
  assert.ok(!calls.some((c) => c.method === 'PUT'), 'suggest writes nothing');
  const p101 = r.items.find((x) => x.request_id === '101');
  assert.equal(p101.proposed.priority, 'Urgent'); assert.equal(p101.proposed.group, 'Network'); assert.equal(p101.proposed.technician, 'Net Tech');
  assert.equal(e.app.store.collection('desk_triage').all().filter((x) => x.state === 'proposed').length, 2);

  // apply a proposed triage (operator) → PUT + note
  calls.length = 0;
  await D.applyProposed('101', {}, OP);
  assert.ok(calls.some((c) => c.method === 'PUT' && /\/requests\/101$/.test(c.url)), 'ticket updated');
  assert.ok(calls.some((c) => c.method === 'POST' && /\/requests\/101\/notes$/.test(c.url)), 'first-response note added');

  // auto mode: applies directly
  calls.length = 0;
  D.setConfig({ mode: 'auto', technicians: techs }, ADM);
  r = await D.scan(ADM);
  assert.equal(r.mode, 'auto'); assert.ok(r.triaged >= 1);
  assert.ok(calls.some((c) => c.method === 'PUT'), 'auto writes the ticket');
  const aud = e.app.store.auditTail(300, (x) => /^desk\./.test(x.action || '')).map((x) => x.action);
  for (const a of ['desk.config', 'desk.scan', 'desk.triage.apply']) assert.ok(aud.includes(a), a);
});

test('desk support: desktop health from synced computers; patch request needs four-eyes approval', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  seedMe(e.app); seedComputers(e.app);
  const ecCalls = [];
  const request = async (url, o) => { ecCalls.push(url); return { status: 200, json: { status: 'success' } }; };
  const D = createDeskSupport(e.app, { now: () => NOW, sealer: fakeSealer, request });
  const d = D.desktops();
  assert.equal(d.summary.total, 3); assert.equal(d.summary.needs_patch, 1); assert.equal(d.summary.offline, 1); assert.equal(d.summary.healthy, 1);
  assert.equal(d.items[0].name, 'PC-RUH-01'); assert.ok(d.items[0].issues.some((x) => /critical/.test(x)) && d.items[0].worst === 'high');

  const pr = D.requestPatch('r1', OP);
  assert.equal(pr.state, 'requested'); assert.equal(pr.critical, 4);
  await assert.rejects(D.approvePatch(pr.id, OP), /four eyes/); // same person
  const done = await D.approvePatch(pr.id, ADM);
  assert.equal(done.state, 'deploying');
  assert.ok(ecCalls.some((u) => /installpatch/.test(u)), 'Endpoint Central install called only after approval');
  assert.throws(() => D.requestPatch('nope', OP), /not found/);
});

test('desk support: route roles — viewer refused, operator reads, admin configures', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/desksupport').registerDeskSupport(e.app.srv, e.app);
  assert.equal((await e.req('GET', '/me/desk', { role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/me/desk', { role: 'operator' })).status, 200);
  assert.equal((await e.req('POST', '/me/desk/config', { role: 'operator', body: { mode: 'auto' } })).status, 403);
  assert.equal((await e.req('POST', '/me/desk/config', { role: 'admin', body: { mode: 'suggest' } })).status, 200);
  // security review: a pattern that can backtrack catastrophically on ticket text is refused with the reason (both writers)
  const rd = await e.req('POST', '/me/desk/config', { role: 'admin', body: { priority_rules: [['Urgent', '(\\w+\\s?)+$']] } });
  assert.equal(rd.status, 400); assert.match(rd.json.error, /nested quantifiers/);
});

test('patch requests raised by the AI engineer: a person takes over first, then a DIFFERENT administrator approves', async (t) => {
  const { startApp } = require('./helpers');
  const { createDeskSupport } = require('../engine/desksupport');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.store.collection('me_ec_computers').put({ id: 'r9', resource_id: 'r9', name: 'PC-9', critical: 3, missing: 5 });
  const D = createDeskSupport(e.app);
  const rec = D.requestPatch('r9', { user: 'duty:desktop', role: 'operator', ip: '' });
  await assert.rejects(D.approvePatch(rec.id, { user: 'syed', role: 'admin' }), /take it over first/, 'one admin alone cannot approve an engineer-raised request');
  D.endorsePatch(rec.id, { user: 'ali', role: 'operator' });
  await assert.rejects(D.approvePatch(rec.id, { user: 'ALI', role: 'admin' }), /four eyes/, 'case does not hide the same person');
  assert.throws(() => D.endorsePatch(rec.id, { user: 'x', role: 'operator' }), /nothing to take over/);
});

test('desk support: automated patching - requests on its own, auto-approves only when armed, inside the Riyadh window, within the limit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  seedMe(e.app); seedComputers(e.app);
  e.app.store.collection('me_ec_computers').put({ id: 'r4', resource_id: 'r4', name: 'PC-DMM-01', live: 'live', last_contact: NOW, critical: 2, missing: 3, health: 'vulnerable' });
  const installs = [];
  const request = async (url, o) => { if (/installpatch/.test(url)) installs.push(JSON.parse(o.body || '{}')); return { status: 200, json: { response_status: { status: 'success' } } }; };
  let clock = Date.parse('2026-10-15T12:00:00Z');                          // 15:00 Riyadh: outside 20:00-06:00
  const D = createDeskSupport(e.app, { now: () => clock, sealer: fakeSealer, request });
  // off: nothing happens
  assert.equal((await D.autoPatch()).skipped, 'patch mode off');
  // suggest: one request per computer missing critical patches, none approved
  D.setConfig({ patch: { mode: 'suggest' } }, ADM);
  let r = await D.autoPatch();
  assert.equal(r.requested, 2, 'PC-RUH-01 and PC-DMM-01'); assert.equal(installs.length, 0);
  assert.equal((await D.autoPatch()).requested, 0, 'no duplicate requests');
  // auto without the auto-approve switch: still waits
  D.setConfig({ patch: { mode: 'auto' } }, ADM);
  assert.match((await D.autoPatch()).skipped, /not armed/);
  // armed, but outside the window
  D.setConfig({ patch: { mode: 'auto', auto_approve: true, max_per_run: 1 } }, ADM);
  assert.equal(D.config().patch.armed_by, 'syed');
  assert.match((await D.autoPatch()).skipped, /outside the maintenance window/); assert.equal(installs.length, 0);
  // 23:00 Riyadh: inside; the limit of 1 per 12 h holds
  clock = Date.parse('2026-10-15T20:00:00Z');
  r = await D.autoPatch();
  assert.equal(r.approved, 1); assert.equal(installs.length, 1); assert.match(r.skipped, /limit of 1/);
  const done = D.patchProposals().find((x) => x.state === 'deploying');
  assert.equal(done.approved_by, 'system:desk-support'); assert.equal(done.auto_approved, true); assert.match(done.history.slice(-1)[0].what, /armed by syed/);
  // a computer patched meanwhile is not installed
  const left = D.patchProposals().find((x) => x.state === 'requested');
  e.app.store.collection('me_ec_computers').patch(left.resource_id, (c) => { c.critical = 0; return c; });
  clock = Date.parse('2026-10-16T19:30:00Z');
  r = await D.autoPatch(); assert.equal(r.approved, 0); assert.equal(installs.length, 1);
  const audit = (await e.req('GET', '/audit?limit=200', { role: 'admin' })).json.audit;
  assert.ok(audit.some((x) => x.action === 'desk.patch.auto-approve'));
  assert.equal(D.inWindow({ window_start: '20:00', window_end: '06:00' }, Date.parse('2026-10-15T02:30:00Z')), true, '05:30 Riyadh');
  assert.equal(D.inWindow({ window_start: '20:00', window_end: '06:00' }, Date.parse('2026-10-15T03:30:00Z')), false, '06:30 Riyadh');
});

test('desk support: every desktop in the asset register is covered - agentless ones listed with the gap, with or without Endpoint Central', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.store.collection('assets');
  A.put({ id: 'a1', type: 'laptop', name: 'LT-FIN-07', custodian: 'mona.syn', site: 'Riyadh HQ', os: 'Windows 11 Pro', status: 'in_use' });          // no agent
  A.put({ id: 'a2', type: 'other', name: 'VDI-HR-03', os: 'Windows 10 Enterprise', status: 'in_use' });                                             // a client OS on an "other" asset
  A.put({ id: 'a3', type: 'server', name: 'SRV-APP-01', os: 'Windows Server 2022', status: 'in_use' });                                            // a server: not desktop support
  A.put({ id: 'a4', type: 'workstation', name: 'PC-OLD-99', status: 'retired' });                                                                   // retired: not listed
  A.put({ id: 'a5', type: 'workstation', name: 'PC-RUH-01', status: 'in_use' });                                                                    // the same machine Endpoint Central reports
  // without Endpoint Central: the register's desktops are still listed, said as not connected
  let D = createDeskSupport(e.app, { now: () => NOW, sealer: fakeSealer });
  let v = D.view();
  assert.equal(v.desktops.not_connected, true);
  assert.deepEqual(v.desktops.items.map((i) => i.name).sort(), ['LT-FIN-07', 'PC-RUH-01', 'VDI-HR-03']);
  assert.ok(v.desktops.items.every((i) => i.source === 'asset register' && /no Endpoint Central agent/.test(i.issues[0])));
  assert.equal(v.desktops.summary.from_assets, 3);
  // with Endpoint Central: its computers plus the agentless register desktops, the joined one not listed twice
  seedMe(e.app); seedComputers(e.app);
  D = createDeskSupport(e.app, { now: () => NOW, sealer: fakeSealer });
  v = D.view(); const names = v.desktops.items.map((i) => i.name);
  assert.ok(!v.desktops.not_connected);
  assert.equal(names.filter((n) => n === 'PC-RUH-01').length, 1, 'matched by name: not listed twice');
  assert.ok(names.includes('LT-FIN-07') && names.includes('VDI-HR-03') && !names.includes('SRV-APP-01') && !names.includes('PC-OLD-99'));
  const lt = v.desktops.items.find((i) => i.name === 'LT-FIN-07');
  assert.deepEqual([lt.source, lt.asset_id, lt.user, lt.branch, lt.live, lt.worst], ['asset register', 'a1', 'mona.syn', 'Riyadh HQ', 'no agent', 'medium']);
  assert.equal(v.desktops.summary.total, 5); assert.equal(v.desktops.summary.no_agent, 2);
  assert.throws(() => D.requestPatch('a1', OP), /computer not found/, 'no agent: a patch install cannot be requested through Endpoint Central');
});

test('desksupport.js installs on its own: it never requires desktops.js, and its desktop rule matches User Desktops case by case', () => {
  // add-desksupport.sh copies desksupport.js alone; a require of './desktops' stopped sentra-itam starting (update rolled back, 2026-11-14)
  const src = require('fs').readFileSync(require.resolve('../engine/desksupport'), 'utf8');
  assert.ok(!/require\(['"]\.\/desktops['"]\)/.test(src), 'desksupport.js must not require ./desktops');
  const DS = require('../engine/desksupport'), DT = require('../engine/desktops');
  const cases = [{ type: 'laptop', status: 'in_use' }, { type: 'workstation', status: 'retired' }, { type: 'thin_client' }, { type: 'other', os: 'Windows 11 Pro' }, { type: 'vm', os: 'Windows 10 Enterprise' },
    { type: 'vm', os: 'Windows Server 2022' }, { type: 'other', os: 'Ubuntu 22.04' }, { type: 'other', discovery: { os: 'macOS 14' } }, { type: 'server', os: 'Windows 11' }, { type: 'unknown', os: 'ChromeOS' }, { type: 'printer' }, null];
  for (const c of cases) assert.equal(DS.isDesktopAsset(c), DT.isDesktopAsset(c), 'same answer for ' + JSON.stringify(c));
  for (const os of ['Windows Server 2019', 'VMware ESXi 8', 'Red Hat Linux', 'Windows 11', '']) assert.equal(DS.isServerOs(os), DT.isServerOs(os), os);
});
