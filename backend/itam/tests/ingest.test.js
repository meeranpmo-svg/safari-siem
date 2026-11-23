// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, netopsFetch, vcenterFetch } = require('./helpers');

const admin = { user: 'adm', role: 'admin' };

test('netops ingest: devices become assets + LLDP connected_to relationship (auto-adopt)', async (t) => {
  const h = await startApp({ noAi: true, netopsFetch: netopsFetch() });
  t.after(() => h.close());
  await h.req('POST', '/settings', { body: { sources: { netops: true }, auto_adopt: true }, ...admin });
  const run = (await h.req('POST', '/discovery/run?source=netops', { ...admin })).json;
  assert.equal(run.ok, true); assert.equal(run.created, 2); assert.equal(run.relationships, 1);
  const list = (await h.req('GET', '/assets?type=network', { role: 'viewer' })).json;
  assert.equal(list.total, 2);
  // relationship present
  const sw = list.assets.find((a) => a.name === 'core-sw-01');
  const graph = (await h.req('GET', `/cmdb?asset=${sw.id}`, { role: 'viewer' })).json.graph;
  assert.ok(graph.edges.some((e) => e.type === 'connected_to'));
});

test('netops ingest is idempotent: second run matches, does not duplicate', async (t) => {
  const h = await startApp({ noAi: true, netopsFetch: netopsFetch() });
  t.after(() => h.close());
  await h.req('POST', '/settings', { body: { sources: { netops: true }, auto_adopt: true }, ...admin });
  await h.req('POST', '/discovery/run?source=netops', { ...admin });
  const run2 = (await h.req('POST', '/discovery/run?source=netops', { ...admin })).json;
  assert.equal(run2.created, 0); assert.equal(run2.matched, 2);
  assert.equal((await h.req('GET', '/assets', { role: 'viewer' })).json.total, 2);
});

test('vcenter ingest: host + vm assets with runs_on; staged when auto_adopt off', async (t) => {
  const h = await startApp({ noAi: true, vcenterFetch: vcenterFetch() });
  t.after(() => h.close());
  // vcenter disabled by default
  assert.equal((await h.req('POST', '/discovery/run?source=vcenter', { ...admin })).json.ok, false);
  // enable but keep auto_adopt off → staged for adoption
  await h.req('POST', '/settings', { body: { sources: { vcenter: true } }, ...admin });
  const staged = (await h.req('POST', '/discovery/run?source=vcenter', { ...admin })).json;
  assert.equal(staged.staged, 2); assert.equal(staged.created, 0);
  const unmatched = (await h.req('GET', '/discovery', { role: 'viewer' })).json.unmatched;
  assert.equal(unmatched.length, 2);
  // adopt one
  const adopt = (await h.req('POST', `/discovery/${encodeURIComponent(unmatched[0].id)}/adopt`, {})).json;
  assert.ok(adopt.assetId);
  // now enable auto_adopt and rerun → the rest adopted + runs_on relationship
  await h.req('POST', '/settings', { body: { auto_adopt: true }, ...admin });
  const run = (await h.req('POST', '/discovery/run?source=vcenter', { ...admin })).json;
  assert.ok(run.relationships >= 1);
});

test('de-dup across sources: agent report matching a manual asset is held for review, merges once an admin binds it (one record)', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  // manual asset with a serial
  const created = (await h.req('POST', '/assets', { body: { name: 'LAP-1', type: 'laptop', serial: 'DELLSN9', owner: 'Sara' } })).json.asset;
  // enrol an agent and report the same serial
  const tok = (await h.req('POST', '/settings/agent-tokens', { body: {}, ...admin })).json.token;
  const enr = (await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'LAP-1', platform: 'windows' } })).json;
  const rep = await h.req('POST', '/agent/report', { user: '', role: '', bearer: enr.agent_key, body: { seq: 1, ts: new Date().toISOString(), nonce: 'n1', host: { hostname: 'LAP-1', serial: 'DELLSN9', os: 'Windows 11', cpu: 'i7', mem_gb: 16 }, software: [{ name: 'Chrome', publisher: 'Google', version: '120' }] } });
  assert.equal(rep.status, 200);
  assert.equal(rep.json.review, true, 'serial match to a record the agent did not create → review, not merge');
  assert.equal(rep.json.asset_id, null);
  const staged = (await h.req('GET', '/discovery', { role: 'viewer' })).json.unmatched.find((d) => d.source === 'agent');
  assert.ok(staged, 'staged for adoption');
  // admin adopts → merges into the manual record and binds the agent
  const ad = (await h.req('POST', `/discovery/${encodeURIComponent(staged.id)}/adopt`, {})).json;
  assert.equal(ad.assetId, created.id);
  const rep2 = await h.req('POST', '/agent/report', { user: '', role: '', bearer: enr.agent_key, body: { seq: 2, ts: new Date().toISOString(), nonce: 'n2', host: { hostname: 'LAP-1', serial: 'DELLSN9', os: 'Windows 11', cpu: 'i7', mem_gb: 16 }, software: [{ name: 'Chrome', publisher: 'Google', version: '120' }] } });
  assert.equal(rep2.json.asset_id, created.id, 'bound agent merges into the manual record');
  const detail = (await h.req('GET', `/assets/${created.id}`, { role: 'viewer' })).json;
  assert.equal(detail.asset.owner, 'Sara', 'human-entered owner preserved');
  assert.equal(detail.asset.os, 'Windows 11', 'agent filled OS');
  assert.equal(detail.software.length, 1);
  assert.equal(detail.seen_by.length, 2, 'seen by manual + agent');
});

// ---- ZS-11: agent reports are untrusted ------------------------------------------------------------------------------
async function enrolA(h, name) {
  const tok = (await h.req('POST', '/settings/agent-tokens', { body: {}, ...admin })).json.token;
  return (await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: name, platform: 'linux' } })).json;
}
const rpt = (h, key, seq, host) => h.req('POST', '/agent/report', { user: '', role: '', bearer: key, body: { seq, ts: new Date().toISOString(), nonce: `n${seq}`, host, software: [] } });

test('ZS-11 agent cannot hijack another asset by claiming its serial/tag/MAC/hostname (review, not merge)', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const victim = (await h.req('POST', '/assets', { body: { name: 'DC01', type: 'server', serial: 'VICTIMSN1', asset_tag: 'TAG-1', mac: 'aa:bb:cc:dd:ee:01' } })).json.asset;
  const a1 = await enrolA(h, 'evil');
  for (const [i, host] of [{ serial: 'VICTIMSN1', os: 'pwned' }, { asset_tag: 'TAG-1', os: 'pwned' }, { mac: 'aa:bb:cc:dd:ee:01', os: 'pwned' }, { hostname: 'DC01', os: 'pwned' }].entries()) {
    const r = await rpt(h, a1.agent_key, i + 1, host);
    assert.equal(r.status, 200);
    assert.equal(r.json.review, true, `claim ${JSON.stringify(host)} goes to review`);
    assert.equal(r.json.asset_id, null);
  }
  const d = (await h.req('GET', `/assets/${victim.id}`, { role: 'viewer' })).json;
  assert.notEqual(d.asset.os, 'pwned', 'victim untouched');
  assert.equal(d.seen_by.length, 1);
  // a second agent cannot merge into the first agent's own asset either
  const own = await enrolA(h, 'pc9');
  const created = (await rpt(h, own.agent_key, 1, { hostname: 'PC9', serial: 'OWNSN9' })).json;
  assert.ok(created.asset_id && !created.review, 'unmatched → created + bound to that agent');
  assert.equal((await rpt(h, own.agent_key, 2, { hostname: 'PC9', serial: 'OWNSN9', os: 'Ubuntu' })).json.asset_id, created.asset_id, 'its own asset merges');
  const other = await enrolA(h, 'x');
  assert.equal((await rpt(h, other.agent_key, 1, { serial: 'OWNSN9' })).json.review, true);
  // explicit admin binding allows the merge
  assert.equal((await h.req('POST', `/agents/${a1.agent_id}/bind`, { body: { asset_id: victim.id } })).status, 403, 'operator cannot bind');
  assert.equal((await h.req('POST', `/agents/${a1.agent_id}/bind`, { body: { asset_id: victim.id }, ...admin })).status, 200);
  assert.equal((await rpt(h, a1.agent_key, 9, { serial: 'VICTIMSN1', os: 'Win2022' })).json.asset_id, victim.id);
});

test('ZS-11 agent facts are normalised and capped on create and merge (lengths, macs[] size)', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const a = await enrolA(h, 'big');
  const macs = Array.from({ length: 500 }, (_, i) => `02:00:00:00:${String((i >> 8) & 255).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`);
  const huge = 'X'.repeat(100000);
  const r = (await rpt(h, a.agent_key, 1, { hostname: huge, serial: 'CAPSN1', os: huge, cpu: { evil: 1 }, macs, mac: huge })).json;
  assert.ok(r.asset_id);
  let raw = h.app.assets.raw(r.asset_id);
  assert.ok(raw.name.length <= 300 && raw.os.length <= 300, 'create path capped');
  assert.equal(raw.cpu, null, 'non-string cpu dropped');
  assert.ok(raw.mac.length <= 40);
  assert.ok(raw.sources.every((sg) => (sg.keys || []).length <= 20));
  const r2 = (await rpt(h, a.agent_key, 2, { hostname: 'ok', serial: 'CAPSN1', os: huge + 'Y', model: huge, macs })).json;
  raw = h.app.assets.raw(r2.asset_id);
  assert.ok(raw.os.length <= 300 && raw.model.length <= 300, 'merge path capped');
  assert.ok(JSON.stringify(raw).length < 20000, 'record stays small');
  // pure merge path normalises too
  const merge = require('../engine/model/merge');
  const out = merge.mergeInto({ id: 'x', prov: {}, sources: [] }, { name: huge, macs }, 'agent', { source_id: 's' }).asset;
  assert.equal(out.name.length, 300);
  const rawFacts = h.app.agentgw.acceptReport(h.app.agentgw.getAgent(a.agent_id), { seq: 3, ts: new Date().toISOString(), host: { macs, hostname: huge } }).facts;
  assert.ok(rawFacts.macs.length <= 16 && rawFacts.name.length <= 300, 'gateway facts capped');
});
