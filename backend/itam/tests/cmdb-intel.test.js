// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CMDB Studio insights (engine/cmdb-intel.js) through the real routes on SYNTHETIC CIs: importance (PageRank) ranks what the estate stands
// on and flags a criticality mismatch; service groups from confirmed relationships with the unmapped-service flag; coverage by type
// and site; calibration learned from people's confirms and dismissals (kind recorded on dismiss); health snapshots with the trend
// withheld below 3 days, then a slope and projection; bulk confirm by a person (validation, roles, AI identity refused, audited).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:cmdb-analyst', role: 'admin' };
const DAY = 86400000;

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = Date.parse('2026-11-01T08:00:00Z'); const clock = { set: (d) => { now = Date.parse(d + 'T08:00:00Z'); } };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now, python: process.env.PYTHON || 'python3' });
  const mk = (x) => { const cr = x.criticality; delete x.criticality; const id0 = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
    if (cr) e.app.store.collection('assets').put(Object.assign({}, e.app.store.collection('assets').get(id0), { criticality: cr })); return id0; };
  const id = {
    esx: mk({ name: 'ESX-SYN-1', mgmt_ip: '10.80.1.2', serial: 'S1', owner: 'infra', criticality: 'medium' }),   // everything runs on it, rated medium
    a1: mk({ name: 'APP-SYN-1', type: 'vm', mgmt_ip: '10.80.1.11', owner: 'apps', criticality: 'high' }),
    a2: mk({ name: 'APP-SYN-2', type: 'vm', mgmt_ip: '10.80.1.12', owner: 'apps', criticality: 'high' }),
    a3: mk({ name: 'APP-SYN-3', type: 'vm', mgmt_ip: '10.80.1.13' }),
    sw: mk({ name: 'SW-SYN-CORE', type: 'network', mgmt_ip: '10.80.1.1' }),
    b1: mk({ name: 'BKP-SYN-1', site: 'DR', mgmt_ip: '10.90.1.5' }), b2: mk({ name: 'BKP-SYN-2', site: 'DR', mgmt_ip: '10.90.1.6' }), b3: mk({ name: 'BKP-SYN-3', site: 'DR', mgmt_ip: '10.90.1.7' }),
    lonely: mk({ name: 'SRV-SYN-LONELY', site: 'DR' }),
  };
  const rel = (from, to, type) => e.app.assets.addRelationship({ from, to, type }, ADM, { source: 'manual', autoConfirm: true });
  rel(id.a1, id.esx, 'runs_on'); rel(id.a2, id.esx, 'runs_on'); rel(id.a1, id.sw, 'connected_to'); rel(id.a2, id.sw, 'connected_to');
  rel(id.b1, id.b2, 'depends_on'); rel(id.b2, id.b3, 'depends_on');
  e.app.store.collection('app_route').put({ id: 'profile', apps: [{ id: 'claims', name: 'Claims', machines: ['APP-SYN-1', 'APP-SYN-2'] }] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call, clock };
}

test('importance, mismatch, service groups, coverage', async (t) => {
  const { call, id } = await setup(t);
  const r = await call('GET', '/cmdb/studio/insights', undefined, VIEW); assert.equal(r.status, 200, r.text); const v = r.json;
  assert.equal(v.importance[0].id, id.esx, 'what the estate stands on ranks first'); assert.equal(v.importance[0].score, 100); assert.equal(v.importance[0].dependents, 2);
  const mm = v.mismatches.find((x) => x.id === id.esx); assert.ok(mm && /rated medium but 2 CI/.test(mm.mismatch), 'rated medium while two CIs stand on it');
  assert.ok(!v.mismatches.some((x) => x.id === id.lonely), 'an isolated CI is not a mismatch');
  const g1 = v.groups.find((g) => g.members.some((m) => m.id === id.esx)), g2 = v.groups.find((g) => g.members.some((m) => m.id === id.b1));
  assert.ok(g1 && g1.apps.includes('Claims') && !g1.unmapped, 'the Claims servers form a group mapped to Claims');
  assert.ok(g2 && g2.unmapped && g2.size === 3 && /BKP group · DR/.test(g2.name), 'three backup servers no application touches: unmapped service');
  assert.ok(!v.groups.some((g) => g.members.some((m) => m.id === id.lonely)), 'a CI with no relationship is in no group');
  const hq = v.coverage.by_site.find((s) => s.key === 'HQ'); assert.equal(hq.cis, 5); assert.equal(hq.linked, 80, '4 of 5 HQ CIs have a relationship');
  assert.ok(v.coverage.by_type.some((x) => x.key === 'vm' && x.owner === 67));
  assert.equal(v.health.quality.enough, false); assert.match(v.health.quality.note, /withheld/);
});

test('calibration learns from people: dismissals record the kind and lower the calibrated confidence', async (t) => {
  const { call } = await setup(t);
  let v = (await call('GET', '/cmdb/studio/insights', undefined, VIEW)).json;
  const p = v.proposals[0]; assert.ok(p, 'there is a proposal to decide'); assert.equal(p.calibrated, p.confidence, 'no decisions yet: confidence unchanged');
  const r = await call('POST', '/cmdb/studio/dismiss', { key: p.key, reason: 'not on this host' }, OP); assert.equal(r.status, 200, r.text);
  v = (await call('GET', '/cmdb/studio/insights', undefined, VIEW)).json;
  const c = v.calibration.find((x) => x.kind === p.kind); assert.equal(c.rejected, 1); assert.equal(c.rate, 0.33);
  const other = v.proposals.find((x) => x.kind === p.kind); if (other) assert.ok(other.calibrated < other.confidence, 'the same kind now carries less confidence');
});

test('health snapshots: trend withheld below 3 days, then slope and projection; operator only; audited', async (t) => {
  const { call, clock, e } = await setup(t);
  assert.equal((await call('POST', '/cmdb/studio/snapshot', undefined, VIEW)).status, 403, 'viewers cannot take a snapshot');
  for (const d of ['2026-11-01', '2026-11-02']) { clock.set(d); assert.equal((await call('POST', '/cmdb/studio/snapshot', undefined, OP)).status, 200); }
  let v = (await call('GET', '/cmdb/studio/insights', undefined, VIEW)).json; assert.equal(v.health.history.length, 2); assert.equal(v.health.quality.enough, false);
  // quality improves: owners filled in on day 3
  for (const a of e.app.store.collection('assets').all((x) => !x.owner)) e.app.store.collection('assets').put(Object.assign({}, a, { owner: 'synthetic team', os: 'Linux', vendor: 'Dell', model: 'R1', serial: 'X' + a.id }));
  clock.set('2026-11-03'); await call('POST', '/cmdb/studio/snapshot', undefined, OP);
  v = (await call('GET', '/cmdb/studio/insights', undefined, VIEW)).json;
  assert.equal(v.health.quality.enough, true); assert.ok(v.health.quality.per_week > 0, 'quality is improving'); assert.ok(v.health.quality.projected_30d >= v.health.quality.latest);
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'cmdb.studio.snapshot' && x.by === 'nora.syn'));
});

test('bulk confirm: a person, validated, each recorded, audited; refused for viewers and AI identities', async (t) => {
  const { call, e } = await setup(t);
  const v = (await call('GET', '/cmdb/studio/insights', undefined, VIEW)).json, keys = v.proposals.slice(0, 2).map((p) => p.key);
  assert.ok(keys.length >= 1);
  assert.equal((await call('POST', '/cmdb/studio/accept-bulk', { keys, note: 'checked in vCenter' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/cmdb/studio/accept-bulk', { keys, note: 'checked in vCenter' }, BOT)).status, 403, 'an AI identity never confirms');
  let r = await call('POST', '/cmdb/studio/accept-bulk', { keys: ['nope'], note: 'checked in vCenter' }, OP); assert.equal(r.status, 400); assert.match(r.text, /keys\[0\]/);
  r = await call('POST', '/cmdb/studio/accept-bulk', { keys }, OP); assert.equal(r.status, 400); assert.match(r.text, /note/);
  r = await call('POST', '/cmdb/studio/accept-bulk', { keys: [], note: 'checked in vCenter' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/cmdb/studio/accept-bulk', { keys: keys.concat(['runs_on|ghost1|ghost2']), note: 'checked in vCenter' }, OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.confirmed.length, keys.length); assert.equal(r.json.skipped.length, 1, 'a key that is not a current proposal is skipped, not invented');
  const a = e.app.store.auditTail(80); assert.ok(a.some((x) => x.action === 'cmdb.studio.accept-bulk' && x.by === 'nora.syn' && x.detail.note === 'checked in vCenter'));
  assert.equal(a.filter((x) => x.action === 'cmdb.studio.accept' && x.by === 'nora.syn').length, keys.length, 'each relationship audited on its own');
});
