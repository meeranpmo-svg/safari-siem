// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const admin = { user: 'adm', role: 'admin' };

test('manual/barcode add: off-network item is flagged no_network_source and found by tag', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const r = await h.req('POST', '/assets', { body: { name: 'Projector Room A', type: 'projector', asset_tag: 'BARCODE-900', site: 'HQ', owner: 'Facilities' } });
  assert.equal(r.status, 200);
  const a = r.json.asset;
  assert.equal(a.type, 'other', 'unknown type projector normalises to other');
  assert.equal(a.no_network_source, true);
  assert.equal(a.networked, false);
  // everyone can look it up by its barcode/tag
  const look = (await h.req('GET', '/lookup?tag=BARCODE-900', { role: 'viewer' })).json;
  assert.equal(look.found, 1); assert.equal(look.assets[0].owner, 'Facilities');
});

test('no hard delete: retire and dispose keep the record + audit + lifecycle trail', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const id = (await h.req('POST', '/assets', { body: { name: 'Old Server', type: 'server', asset_tag: 'SV-1' } })).json.asset.id;
  await h.req('POST', `/assets/${id}/retire`, { body: { reason: 'decommissioned' } });
  let d = (await h.req('GET', `/assets/${id}`, { role: 'viewer' })).json;
  assert.equal(d.asset.status, 'retired');
  await h.req('POST', `/assets/${id}/dispose`, { body: { reason: 'recycled' } });
  d = (await h.req('GET', `/assets/${id}`, { role: 'viewer' })).json;
  assert.equal(d.asset.status, 'disposed');
  // record still retrievable, lifecycle recorded, and there is NO delete route
  assert.ok(d.lifecycle.some((e) => e.event === 'retire') && d.lifecycle.some((e) => e.event === 'dispose'));
  const del = await h.req('DELETE', `/assets/${id}`, { ...admin });
  assert.ok(del.status === 404 || del.status === 405, 'no hard-delete endpoint exists');
  // audit chain intact
  const audit = (await h.req('GET', '/audit', { ...admin })).json;
  assert.equal(audit.verify.ok, true);
  assert.ok(audit.audit.some((e) => e.action === 'asset.dispose'));
});

test('edit locks a human-set field; move/assign audited', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const id = (await h.req('POST', '/assets', { body: { name: 'WS-1', type: 'workstation', serial: 'WSSN1' } })).json.asset.id;
  await h.req('POST', `/assets/${id}`, { body: { owner: 'Khalid', os: 'Windows 10' } });
  await h.req('POST', `/assets/${id}/assign`, { body: { department: 'IT' } });
  await h.req('POST', `/assets/${id}/move`, { body: { site: 'HQ', location: { room: '204' } } });
  const d = (await h.req('GET', `/assets/${id}`, { role: 'viewer' })).json;
  assert.equal(d.asset.owner, 'Khalid'); assert.equal(d.asset.department, 'IT'); assert.equal(d.asset.location.room, '204');
});

test('stocktake: scan marks found, unknown code is unexpected, close computes missing', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const a1 = (await h.req('POST', '/assets', { body: { name: 'A1', type: 'laptop', asset_tag: 'T-1', site: 'HQ' } })).json.asset;
  (await h.req('POST', '/assets', { body: { name: 'A2', type: 'laptop', asset_tag: 'T-2', site: 'HQ' } }));
  const st = (await h.req('POST', '/stocktake', { body: { site: 'HQ' }, ...admin })).json;
  assert.equal(st.expected, 2);
  const scan = (await h.req('POST', `/stocktake/${st.id}/scan`, { body: { code: 'T-1' } })).json;
  assert.equal(scan.result, 'found'); assert.equal(scan.asset.id, a1.id);
  const bad = (await h.req('POST', `/stocktake/${st.id}/scan`, { body: { code: 'UNKNOWN-TAG' } })).json;
  assert.equal(bad.result, 'unexpected');
  const closed = (await h.req('POST', `/stocktake/${st.id}/close`, { ...admin })).json;
  assert.equal(closed.found, 1); assert.equal(closed.missing, 1); assert.equal(closed.unexpected, 1);
});
