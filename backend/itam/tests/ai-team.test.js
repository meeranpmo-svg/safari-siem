// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The AI Engineering Team of the organisation's own estate (brand setting): the Voice, Hyper-V and Aramco CCC engineers are on
// the duty desk and in readiness; engineers for systems it does not run (engineers_off) are not; an engineer whose module is not
// set up answers "not connected" (no work item); a Hyper-V finding becomes a work item on patrol and clears when it is gone.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' };
const report = (hb) => ({ collected_at: '2026-11-25T06:00:00Z', host: { name: 'HV-SYN-01', ip: '10.20.8.10', logical_processors: 8, mem_total_mb: 65536, mem_free_mb: 30000, volumes: [] },
  vms: [{ name: 'DB-SYN-01', vm_id: 'a-2', state: 'Running', vcpus: 4, heartbeat: hb }] });

test('the team: own engineers on the desk and in readiness, switched-off ones gone, a finding worked on patrol', async (t) => {
  const e = await startApp({ noAi: true, config: { duty: { all_engineers: false } } }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-25T07:00:00Z'), python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const off = require('../engine/brand').engineers_off || [];
  const eng = (await call('GET', '/duty/engineers', undefined, OP)).json.engineers.map((x) => x.id);
  for (const id of ['voice', 'hyperv', 'aramco']) assert.ok(eng.includes(id), id + ' on the desk: ' + eng.join(','));
  for (const id of off) assert.ok(!eng.includes(id), id + ' is switched off for this organisation');
  const rd = (await call('GET', '/duty/readiness?fresh=1', undefined, OP)).json;
  const rids = rd.engineers.map((x) => x.id);
  for (const id of ['voice', 'hyperv', 'aramco']) assert.ok(rids.includes(id), id + ' in readiness');
  for (const id of off) assert.ok(!rids.includes(id), id + ' not in readiness');
  const hv = rd.engineers.find((x) => x.id === 'hyperv'); assert.ok(hv.status && hv.checks.some((c) => c.name === 'Hosts reporting' && c.ok === false), 'says what is missing');
  // not set up: no work item; then a host reports a lost heartbeat → a work item; it clears when the heartbeat is back
  await call('POST', '/duty/patrol', { engineer: 'hyperv' }, OP);
  assert.equal((await call('GET', '/duty/items?engineer=hyperv', undefined, OP)).json.items.length, 0);
  const sc = (await call('POST', '/discovery/scopes', { name: 'HV', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ADM)).json.scope;
  assert.equal((await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: report('LostCommunication') }, ADM)).status, 200);
  await call('POST', '/duty/patrol', { engineer: 'hyperv' }, OP);
  const items = (await call('GET', '/duty/items?engineer=hyperv', undefined, OP)).json.items;
  const hb = items.find((i) => /heartbeat/.test(i.title)); assert.ok(hb, 'work item opened: ' + JSON.stringify(items.map((i) => i.title)));
  assert.equal(hb.severity, 'high');
  await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: report('OkApplicationsHealthy') }, ADM);
  await call('POST', '/duty/patrol', { engineer: 'hyperv' }, OP);
  const after = (await call('GET', '/duty/items/' + encodeURIComponent(hb.id), undefined, OP)).json;
  assert.ok(/cleared|resolved|verified/.test(JSON.stringify(after.status || after.item && after.item.status)), 'cleared when the heartbeat is back: ' + JSON.stringify(after.status || after));
});
