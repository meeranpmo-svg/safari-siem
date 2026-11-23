// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC registers fed by the platform (engine/grc-registers.js liveSync): SAMA gaps, failing controls, overdue drills and
// asset ownership become remediation actions with their reference, unassigned, due by priority; never twice; a gap the
// source stops reporting is flagged on the action (never closed by the platform - four eyes still apply); a source that
// could not be read changes nothing; operational findings are risk candidates only, and drop out once rated as a risk;
// roles and audit. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const NOW = Date.parse('2026-10-24T08:00:00Z');
const live = (data) => ({ state: 'live', data });
function feed() {
  return {
    sama: live({ controls: [{ id: '3.3.5', title: 'Identity and access management', status: 'gap', owner: 'huda.syn' }, { id: '3.3.6', title: 'Application security', status: 'gap' }, { id: '3.1.1', title: 'Governance', status: 'covered' }] }),
    grc: live({ control_status: { 'patch-30d': { state: 'fail', detail: '12 servers past 30 days' }, 'backup-daily': { state: 'pass' } } }),
    drills: live({ systems: [{ system: 'IIRIS-SYN', overdue: true, last_result: 'fail', last: { executed: '2025-09-01' } }, { system: 'CRM-SYN', overdue: false }] }),
    ownership: live({ assets: 40, missing_business: 6, missing_it: 0, business_pct: 85 }),
    siem_duty: live({ items: [] }), soc: { state: 'error', error: 'SIEM link down' },
  };
}
async function setup(t, S) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.now = () => NOW;
  const state = { S };
  e.app.addons.ciso = { collect: async () => state.S, risks: () => [
    { ref: 'duty:DW-000101', severity: 'critical', domain: 'operations', title: 'CORE-SW-SYN down', source: 'AI network engineer', link: 'network-engineer.html' },
    { ref: 'case:C-77', severity: 'high', domain: 'detection', title: 'Case C-77 breaching SLA', source: 'SOC cases' },
    { ref: 'x:low', severity: 'medium', title: 'minor' }] };
  return { e, state };
}

test('the platform\'s gaps become remediation actions once, unassigned, due by priority, with their reference', async (t) => {
  const { e } = await setup(t, feed());
  const r = await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.created.length, 5, 'two SAMA gaps, one failing control, one drill, ownership');
  const A = (await e.req('GET', '/grc/actions', { role: 'viewer' })).json.items;
  const sama = A.find((a) => a.source === 'sama' && a.ref === '3.3.5');
  assert.equal(sama.owner, 'huda.syn', 'the control owner from the source'); assert.equal(sama.priority, 'high'); assert.equal(sama.due, '2026-11-23', 'high: 30 days');
  assert.equal(sama.framework, 'SAMA CSF'); assert.equal(sama.created_by, 'system:grc-live'); assert.ok(sama.live);
  assert.ok(A.find((a) => a.source === 'control' && a.ref === 'patch-30d' && /12 servers/.test(a.description)));
  assert.ok(A.find((a) => a.source === 'drill' && a.ref === 'IIRIS-SYN' && /failed - repeat it/.test(a.title)));
  const own = A.find((a) => a.ref === 'ownership:coverage'); assert.equal(own.priority, 'medium'); assert.equal(own.due, '2026-12-23', 'medium: 60 days'); assert.equal(own.owner, '');
  const again = await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' });
  assert.equal(again.json.created.length, 0, 'never twice');
  const ws = (await e.req('GET', '/grc/workspace', { role: 'viewer' })).json;
  assert.equal(ws.actions.open, 5); assert.equal(ws.live.from_platform, 5); assert.equal(ws.live.gaps, 5);
  assert.ok(e.app.store.auditTail(50, (x) => x.action === 'grc.action.create' && x.by === 'system:grc-live').length === 5, 'each creation audited');
  assert.ok(e.app.store.auditTail(50, (x) => x.action === 'grc.live.sync' && x.by === 'siva').length === 1);
});

test('a cleared gap is flagged, never closed by the platform; a source that was not read changes nothing; a returning gap is noted', async (t) => {
  const { e, state } = await setup(t, feed());
  await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' });
  const S2 = feed(); S2.sama.data.controls[0].status = 'covered'; S2.drills = { state: 'error', error: 'drills unreadable' };
  state.S = S2;
  const r = (await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' })).json;
  const A = () => e.app.store.collection('grc_actions').all();
  const sama = A().find((a) => a.ref === '3.3.5'), drill = A().find((a) => a.ref === 'IIRIS-SYN');
  assert.deepEqual(r.cleared, [sama.id]);
  assert.equal(sama.status, 'open', 'still open: a person verifies, another closes'); assert.ok(sama.live_cleared_at);
  assert.match(sama.history.slice(-1)[0].what, /no longer reports this gap/);
  assert.ok(!drill.live_cleared_at, 'drills could not be read: not called cleared');
  state.S = feed();
  const r3 = (await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' })).json;
  assert.deepEqual(r3.back, [sama.id]); assert.equal(A().find((a) => a.ref === '3.3.5').live_cleared_at, null);
  // four eyes still hold for platform-created actions
  await e.req('POST', '/grc/actions/' + sama.id + '/status', { user: 'siva', role: 'operator', body: { status: 'done', note: 'MFA enforced' } });
  assert.equal((await e.req('POST', '/grc/actions/' + sama.id + '/status', { user: 'siva', role: 'operator', body: { status: 'closed', note: 'ok' } })).status, 403);
  assert.equal((await e.req('POST', '/grc/actions/' + sama.id + '/status', { user: 'rasheed', role: 'operator', body: { status: 'closed', note: 'checked' } })).status, 200);
  // closed and the gap returns: a NEW action, the closed one stays closed
  state.S = feed(); const r4 = (await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' })).json;
  assert.equal(r4.created.length, 1);
});

test('risk candidates: critical / high operational findings, gone once rated as a risk; nothing to read -> said so', async (t) => {
  const { e } = await setup(t, feed());
  await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' });
  let L = (await e.req('GET', '/grc/live', { role: 'viewer' })).json;
  assert.deepEqual(L.candidates.map((c) => c.ref), ['duty:DW-000101', 'case:C-77'], 'medium is not offered');
  assert.equal(L.sources.soc, 'error');
  const rk = await e.req('POST', '/grc/risks', { user: 'siva', role: 'operator', body: { title: 'Core switch single point of failure', likelihood: 3, impact: 5, source_ref: 'duty:DW-000101' } });
  assert.equal(rk.status, 200, rk.text); assert.equal(rk.json.source_ref, 'duty:DW-000101');
  L = (await e.req('GET', '/grc/live', { role: 'viewer' })).json;
  assert.deepEqual(L.candidates.map((c) => c.ref), ['case:C-77'], 'rated -> no longer a candidate');
  delete e.app.addons.ciso;
  const r = (await e.req('POST', '/grc/live/sync', { user: 'siva', role: 'operator' })).json;
  assert.equal(r.ok, false); assert.match(r.error, /AI CISO is not installed/);
});

test('roles: a viewer reads the live state but cannot sync', async (t) => {
  const { e } = await setup(t, feed());
  assert.equal((await e.req('POST', '/grc/live/sync', { user: 'guest', role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/grc/live', { user: 'guest', role: 'viewer' })).status, 200);
});
