// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI engineers' duty desk in IT Asset Management (engine/duty.js + engine/duty-core.js): the penetration-testing and
// desktop-support engineers patrol real module data, open work items, the desktop engineer REQUESTS a patch install
// (a different person approves), deployments in progress are not failed fixes, cleared items resolve, routes + roles,
// and the shared core is byte-for-byte the SIEM's.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin', ip: '' };
let clock = Date.parse('2026-10-15T08:00:00Z');
const now = () => clock;

test('duty core + Python rules: identical to the SIEM copies (one duty cycle, two engines)', (t) => {
  const siem = path.join(__dirname, '..', '..', 'siem', 'engine', 'duty', 'duty-core.js');
  if (!fs.existsSync(siem)) { t.skip('sentra-siem checkout not next to shield'); return; }
  assert.equal(fs.readFileSync(path.join(__dirname, '..', 'engine', 'duty-core.js'), 'utf8'), fs.readFileSync(siem, 'utf8'), 'edit engine/duty/duty-core.js in sentra-siem and copy it here');
  assert.equal(fs.readFileSync(path.join(__dirname, '..', 'engine', 'duty_rules.py'), 'utf8'), fs.readFileSync(path.join(path.dirname(siem), 'duty_rules.py'), 'utf8'), 'edit engine/duty/duty_rules.py in sentra-siem and copy it here');
});

test('duty pentest: exposures become work items, an internet-facing RDP is critical, closing the port clears it', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  const r0 = await D.patrol('pentest'); assert.equal(r0.not_connected, true, 'nothing discovered: not connected, not "secure"');
  const edge = e.app.assets.create({ name: 'EDGE01', type: 'server', status: 'in_use', os: 'Windows Server 2022', mgmt_ip: '129.1.2.3' }, ADM).asset.id;
  e.app.store.collection('disc_devices').put({ id: 'dd1', asset_id: edge, ip: '129.1.2.3', open_ports: [3389, 445], status: 'approved' });
  const r = await D.patrol('pentest');
  assert.ok(r.opened >= 2 && r.investigated >= 2);
  const rdp = D.list({ engineer: 'pentest' }).items.find((x) => /3389/.test(x.title));
  assert.equal(rdp.severity, 'critical'); assert.equal(rdp.status, 'diagnosed'); assert.equal(rdp.target.name, 'EDGE01');
  assert.match(D.get(rdp.id).investigation.checks[0].name, /authorised engagement only/, 'it never tests on its own');
  e.app.store.collection('disc_devices').put({ id: 'dd1', asset_id: edge, ip: '129.1.2.3', open_ports: [445], status: 'approved' });
  clock += 600000; await D.patrol('pentest');
  assert.equal(D.get(rdp.id).status, 'resolved'); assert.equal(D.get(rdp.id).resolution, 'cleared');
});

test('duty desktop: missing critical patches → the engineer requests the install; approved deploy is verified', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  assert.equal((await D.patrol('desktop')).not_connected, true, 'Endpoint Central not synced: nothing opened, nothing closed');
  const c = e.app.store.collection('me_ec_computers');
  c.put({ id: 'r1', resource_id: 'r1', name: 'PC-RUH-01', user: 'ahmed', os: 'Windows 11', live: 'live', last_contact: clock - 3600000, critical: 4, missing: 12, health: 'highly vulnerable' });
  c.put({ id: 'r2', resource_id: 'r2', name: 'PC-RUH-02', user: 'sara', os: 'Windows 10', live: 'down', last_contact: clock - 10 * 86400000, critical: 0, missing: 2, health: 'healthy' });
  await D.patrol('desktop');
  const items = D.list({ engineer: 'desktop' }).items;
  const patch = items.find((x) => x.key === 'r1:patch'), off = items.find((x) => x.key === 'r2:offline');
  assert.ok(patch && off);
  assert.equal(patch.status, 'awaiting-approval'); assert.match(patch.changes[0], /^dp_/);
  const req = e.app.store.collection('desk_patch').get(patch.changes[0]);
  assert.equal(req.state, 'requested'); assert.equal(req.requested_by, 'duty:desktop', 'requested by the engineer, so any administrator can approve');
  assert.equal(off.status, 'diagnosed', 'an offline agent needs a person');
  // a second patrol does not request twice
  clock += 600000; await D.patrol('desktop');
  assert.equal(e.app.store.collection('desk_patch').all().length, 1);
  // an administrator approved: Endpoint Central is deploying (simulated - the real approval calls EC)
  e.app.store.collection('desk_patch').patch(req.id, (x) => { x.state = 'deploying'; x.approved_by = 'syed'; x.approved_at = new Date(clock).toISOString(); });
  for (let i = 0; i < 3; i++) { clock += 20 * 60000; await D.patrol('desktop'); }
  assert.equal(D.get(patch.id).status, 'fix-applied', 'deploying for less than a day is not a failed fix');
  c.put({ id: 'r1', resource_id: 'r1', name: 'PC-RUH-01', user: 'ahmed', os: 'Windows 11', live: 'live', last_contact: clock, critical: 0, missing: 0, health: 'healthy' });
  clock += 20 * 60000; await D.patrol('desktop');
  assert.equal(D.get(patch.id).status, 'resolved'); assert.equal(D.get(patch.id).resolution, 'verified-fixed');
});

test('duty routes: reads open, actions need operator, policy admin', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now });
  e.app.store.collection('me_ec_computers').put({ id: 'r2', resource_id: 'r2', name: 'PC-2', live: 'down', last_contact: clock - 10 * 86400000, critical: 0, missing: 0 });
  assert.equal((await e.req('POST', '/duty/patrol', { role: 'viewer', body: { engineer: 'desktop' } })).status, 403);
  assert.equal((await e.req('POST', '/duty/patrol', { role: 'operator', body: { engineer: 'desktop' } })).status, 200);
  const l = await e.req('GET', '/duty/items?status=open', { role: 'viewer' });
  assert.equal(l.status, 200); assert.equal(l.json.total, 1);
  const id = l.json.items[0].id;
  assert.equal((await e.req('GET', '/duty/engineers', { role: 'viewer' })).json.engineers.length, 17, 'pentest, desktop, GRC consultant, virtualization administrator, IT auditor, cyber security auditor, PDPL consultant, data governance officer (NDMO), cybersecurity compliance officer (NCA ECC), IT auditor (engagements), cyber security auditor (engagements), internal auditor (engagements), identity security engineer (NHI), PKI engineer, ISO 27001 lead implementer, database administrator (SQL Server / PostgreSQL / MySQL), AI Risk Officer');
  assert.equal((await e.req('POST', `/duty/items/${id}/close`, { role: 'operator', body: { code: 'fixed' } })).status, 400, 'a reason is required');
  assert.equal((await e.req('POST', `/duty/items/${id}/close`, { role: 'operator', body: { code: 'fixed', reason: 'agent re-installed' } })).status, 200);
  assert.equal((await e.req('PUT', '/duty/policy', { role: 'operator', body: { patrol_min: 5 } })).status, 403);
  assert.equal((await e.req('PUT', '/duty/policy', { role: 'admin', body: { patrol_min: 5 } })).json.patrol_min, 5);
  assert.equal((await e.req('GET', '/duty/items/DW-999999', { role: 'viewer' })).status, 404);
});

test('duty readiness: each engineer says ready / partial / blocked with the exact fix', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const r = await e.as('viewer.v', 'viewer')('GET', '/duty/readiness');
  assert.equal(r.status, 200);
  const pt = r.json.engineers.find((x) => x.id === 'pentest'), dk = r.json.engineers.find((x) => x.id === 'desktop');
  assert.equal(pt.status, 'blocked', 'no assets yet: blocked'); assert.match(pt.to_fix[0].fix, /Asset Discovery/);
  assert.equal(dk.status, 'blocked'); assert.ok(dk.to_fix.some((f) => /Endpoint Central/.test(f.fix)));
  assert.equal(r.json.of, 16);
  const sq = r.json.engineers.find((x) => x.id === 'sqldba'); assert.equal(sq.status, 'blocked', 'no database login yet'); assert.ok(sq.to_fix.some((f) => /Add database/.test(f.fix)), 'says where to add the read-only login');
  const ia = r.json.engineers.find((x) => x.id === 'ia'); assert.ok(ia.to_fix.some((f) => /Head of Audit/.test(f.fix)), 'no Head of Audit named yet');
  const ec = r.json.engineers.find((x) => x.id === 'nca-ecc'); assert.notEqual(ec.status, 'ready', 'no CISO yet'); assert.ok(ec.to_fix.some((f) => /name the CISO/.test(f.fix)));
  const nd = r.json.engineers.find((x) => x.id === 'ndmo'); assert.notEqual(nd.status, 'ready', 'no Chief Data Officer yet'); assert.ok(nd.to_fix.some((f) => /Chief Data Officer/.test(f.fix)));
  const pd = r.json.engineers.find((x) => x.id === 'pdpl'); assert.equal(pd.status, 'blocked', 'no PDPL profile yet'); assert.ok(pd.to_fix.some((f) => /Profile/.test(f.fix)));
  e.app.assets.create({ name: 'SRV1', type: 'server', status: 'in_use', mgmt_ip: '10.0.0.5' }, ADM);
  const r2 = await e.req('GET', '/duty/readiness');
  assert.notEqual(r2.json.engineers.find((x) => x.id === 'pentest').status, 'blocked', 'with an asset the pentest engineer can work');
});

test('duty readiness answers within its budget when a source is slow (the update check waits 8 s): computing, then the kept result', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, readinessMs: 150, readinessCisoMs: 5000 });
  const real = e.app.addons.ciso; e.app.addons.ciso = { overview: () => new Promise((r) => setTimeout(() => r(null), 700)), status: () => (real ? real.status() : { running: false }) };
  let t0 = Date.now(), r = await e.req('GET', '/duty/readiness', { role: 'viewer' });
  assert.equal(r.status, 200); assert.ok(Date.now() - t0 < 600, 'answered within the budget, not after the slow source'); assert.equal(r.json.computing, true); assert.deepEqual(r.json.engineers, []);
  let worst = 0; for (let i = 0; i < 60 && r.json.computing; i++) { await new Promise((x) => setTimeout(x, 250)); t0 = Date.now(); r = await e.req('GET', '/duty/readiness', { role: 'viewer' }); worst = Math.max(worst, Date.now() - t0); }
  assert.equal(r.status, 200); assert.ok(worst < 600, 'every answer within the budget: ' + worst + ' ms'); assert.ok(r.json.engineers.length > 5, 'the finished result was kept'); if (r.json.stale) assert.match(r.json.note, /fresh one is being computed/); else assert.ok(r.json.generated, 'a fresh result that finished inside the budget');   // which one arrives first is timing: both are correct
  await new Promise((x) => setTimeout(x, 900));
});

test('duty items: viewers see state, not evidence / investigation / notes (PDPL); operators see everything', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  e.app.store.collection('me_ec_computers').put({ id: 'r7', resource_id: 'r7', name: 'PC-7', user: 'fatima', os: 'Windows 11', ip: '10.2.3.4', live: 'down', last_contact: clock - 10 * 86400000, critical: 0, missing: 1, health: 'healthy' });
  await D.patrol('desktop');
  const id = D.list({ engineer: 'desktop' }).items[0].id;
  const v = (await e.req('GET', '/duty/items/' + id, { role: 'viewer' })).json, o = (await e.req('GET', '/duty/items/' + id, { role: 'operator' })).json;
  assert.deepEqual(v.evidence, []); assert.equal(v.investigation, null); assert.ok(v.history.every((h) => h.note === undefined));
  assert.ok(o.evidence.some((x) => /fatima/.test(x)), 'operators see the evidence');
  assert.ok(!JSON.stringify((await e.req('GET', '/duty/items', { role: 'viewer' })).json).includes('fatima'));
  assert.equal((await e.req('GET', '/duty/items', { role: 'constructor' })).status, 401, 'a prototype name is not a role');
});
