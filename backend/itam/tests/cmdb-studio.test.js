// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CMDB Studio (engine/cmdb-studio.js, pyengine/cmdb_rules.py) through the real routes on SYNTHETIC CIs and relationships:
// data quality, duplicate candidates, learned relationship proposals, discovery neighbour proposals, blast radius and
// single points of failure, orphans, an impossible relationship, the CI neighbourhood; accepting a proposal confirms it,
// dismissing needs a reason and is remembered, a sensor / AI proposal is confirmed or rejected by a person who did not
// propose it (four eyes), service identities never decide; roles, validation errors and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:cmdb-analyst', role: 'admin' };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
  const id = {
    esx: mk({ name: 'ESX-SYN-1', mgmt_ip: '10.80.1.2', serial: 'SYNSER1', owner: 'infra', os: 'ESXi 8', vendor: 'Dell', model: 'R750' }),
    a1: mk({ name: 'APP-SYN-1', type: 'vm', mgmt_ip: '10.80.1.11', owner: 'apps', os: 'Windows' }),
    a2: mk({ name: 'APP-SYN-2', type: 'vm', mgmt_ip: '10.80.1.12', owner: 'apps', os: 'Windows' }),
    a3: mk({ name: 'APP-SYN-3', type: 'vm', mgmt_ip: '10.80.1.13' }),
    sw: mk({ name: 'SW-SYN-CORE', type: 'network', mgmt_ip: '10.80.1.1' }),
    lonely: mk({ name: 'SRV-SYN-LONELY', mgmt_ip: '10.81.0.5' }),
    dup: mk({ name: 'ESX-SYN-1-OLD', serial: 'SYNSER1' }),
    prn: mk({ name: 'PRN-SYN-1', type: 'printer', mgmt_ip: '10.80.1.40' }),
  };
  const rel = (from, to, type) => e.app.assets.addRelationship({ from, to, type }, ADM, { source: 'manual', autoConfirm: true });
  rel(id.a1, id.esx, 'runs_on'); rel(id.a2, id.esx, 'runs_on'); rel(id.a1, id.sw, 'connected_to'); rel(id.a2, id.sw, 'connected_to');
  rel(id.a3, id.prn, 'runs_on');                                                     // a VM cannot run on a printer
  e.app.store.collection('disc_devices').put({ id: 'dd_sw', asset_id: id.sw, ip: '10.80.1.1', neighbours: [{ via: 'lldp', local_port: 'Gi1/0/7', remote_name: 'ESX-SYN-1', remote_ip: '10.80.1.2' }] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call };
}
const auditOf = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('quality, duplicates, learned and neighbour proposals, blast radius, orphans, anomalies, CI neighbourhood', async (t) => {
  const { call, id } = await setup(t);
  let r = await call('GET', '/cmdb/studio', undefined, VIEW);
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.summary.cis, 8); assert.equal(v.summary.confirmed, 5);
  assert.ok(v.duplicates.some((d) => [d.a.id, d.b.id].includes(id.dup) && /serial/i.test(d.why)), 'same serial is a duplicate candidate');
  const learned = v.proposals.find((p) => p.from === id.a3 && p.to === id.esx && p.type === 'runs_on');
  assert.ok(learned && learned.kind === 'learned' && learned.confidence >= 0.6, 'APP-SYN-3 likely runs on ESX-SYN-1 like its subnet peers');
  assert.ok(v.proposals.some((p) => p.kind === 'neighbours' && [p.from, p.to].includes(id.esx) && [p.from, p.to].includes(id.sw)), 'the LLDP neighbour becomes a proposal');
  assert.ok(v.spof.some((x) => x.id === id.esx && x.impacted >= 2), 'ESX-SYN-1 is a single point of failure');
  assert.ok(v.orphans.some((x) => x.id === id.lonely));
  assert.ok(v.anomalies.some((x) => /printer/i.test(x.text)), 'runs_on a printer is impossible');
  assert.ok(v.quality.find((q) => q.id === id.a3).missing.length > 0);
  assert.equal(v.ai.enabled, false);
  r = await call('GET', '/cmdb/studio/ci/' + id.esx, undefined, VIEW);
  assert.equal(r.status, 200, r.raw);
  assert.ok(r.json.graph.nodes.some((n) => n.id === id.a1) && r.json.graph.edges.length >= 2);
  assert.ok(r.json.impact.layers.flat().length >= 2, 'blast radius layers');
  r = await call('GET', '/cmdb/studio/ci/bad$id', undefined, VIEW); assert.equal(r.status, 400);
  r = await call('GET', '/cmdb/studio/ci/ast_none', undefined, VIEW); assert.equal(r.status, 404);
});

test('accept confirms, dismiss needs a reason and is remembered; four eyes on sensor / AI proposals; roles; audit', async (t) => {
  const { e, call, id } = await setup(t);
  const key = 'runs_on|' + id.a3 + '|' + id.esx;
  let r = await call('POST', '/cmdb/studio/accept', { key }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/cmdb/studio/accept', { key }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /a person does/);
  r = await call('POST', '/cmdb/studio/accept', { key: 'nonsense' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /key is not a relationship proposal key/);
  r = await call('POST', '/cmdb/studio/accept', { key: 'runs_on|' + id.a3 + '|' + id.lonely }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/cmdb/studio/accept', { key, extra: 'dropped' }, OP); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.relationship.status, 'confirmed');
  assert.equal(auditOf(e, 'cmdb.studio.accept')[0].by, 'nora.syn');
  r = await call('GET', '/cmdb/studio', undefined, OP);
  assert.ok(!r.json.proposals.some((p) => p.key === key), 'no longer proposed');
  const nk = r.json.proposals.find((p) => p.kind === 'neighbours').key;
  r = await call('POST', '/cmdb/studio/dismiss', { key: nk }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/cmdb/studio/dismiss', { key: nk, reason: 'out-of-band management link (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('GET', '/cmdb/studio', undefined, OP);
  assert.ok(!r.json.proposals.some((p) => p.key === nk), 'a dismissed proposal is not raised again');
  assert.equal(auditOf(e, 'cmdb.studio.dismiss')[0].detail.reason, 'out-of-band management link (synthetic)');
  // a sensor proposal by nora: nora cannot decide it, syed can; reject needs a note and blocks the key
  const p1 = e.app.assets.addRelationship({ from: id.lonely, to: id.sw, type: 'connected_to' }, OP, { source: 'sensor', autoConfirm: false });
  const p2 = e.app.assets.addRelationship({ from: id.lonely, to: id.esx, type: 'depends_on' }, OP, { source: 'sensor', autoConfirm: false });
  r = await call('GET', '/cmdb/studio', undefined, OP); assert.equal(r.json.pending.length, 2);
  r = await call('POST', '/cmdb/studio/relationships/' + p1.id + '/decide', { decision: 'confirm' }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await call('POST', '/cmdb/studio/relationships/' + p1.id + '/decide', { decision: 'maybe' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /decision must be one of/);
  r = await call('POST', '/cmdb/studio/relationships/' + p1.id + '/decide', { decision: 'confirm' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/cmdb/studio/relationships/' + p1.id + '/decide', { decision: 'confirm' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(e.app.store.collection('relationships').get(p1.id).status, 'confirmed');
  r = await call('POST', '/cmdb/studio/relationships/' + p1.id + '/decide', { decision: 'confirm' }, ADM); assert.equal(r.status, 409);
  r = await call('POST', '/cmdb/studio/relationships/' + p2.id + '/decide', { decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await call('POST', '/cmdb/studio/relationships/' + p2.id + '/decide', { decision: 'reject', note: 'no such dependency (synthetic)' }, ADM); assert.equal(r.status, 200);
  assert.equal(e.app.store.collection('relationships').get(p2.id), null);
  assert.ok(e.app.store.collection('cmdb_decisions').get('depends_on|' + id.lonely + '|' + id.esx), 'the rejected key is remembered');
  const d = auditOf(e, 'cmdb.studio.reject')[0]; assert.equal(d.by, 'syed'); assert.equal(d.detail.proposed_by, 'nora.syn');
  r = await call('POST', '/cmdb/studio/ai/ask', { question: 'what is missing?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/cmdb/studio/ai/ask', { question: 'what is missing?' }, OP); assert.equal(r.status, 503, 'AI not allowed yet');
});
