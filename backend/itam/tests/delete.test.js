// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Admin delete: role gate, reason required, record + relationships removed, audit keeps a snapshot, discovery results
// go back to review (or stay ignored on re-discovery), agent binding cleared, bulk delete, SIEM stop / force path.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const ADM = { user: 'adm.sara', role: 'admin' };

test('delete: admin only, reason required, removes the record and its relationships, audit keeps a snapshot', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const a = (await h.req('POST', '/assets', { body: { name: 'TEST-DUP-PC', type: 'laptop', serial: 'SER-DEL-1', asset_tag: 'TAG-DEL-1' } })).json.asset;
  const b = (await h.req('POST', '/assets', { body: { name: 'TEST-OTHER', type: 'server', serial: 'SER-DEL-2' } })).json.asset;
  assert.equal((await h.req('POST', '/cmdb', { body: { from: a.id, to: b.id, type: 'depends_on', confirm: true } })).status, 200);
  // operator and viewer are refused
  assert.equal((await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'duplicate' } })).status, 403);
  assert.equal((await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'duplicate' }, role: 'viewer' })).status, 403);
  // reason required
  assert.equal((await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: ' x ' }, ...ADM })).status, 400);
  // unknown id
  assert.equal((await h.req('POST', '/assets/as_000000000000/delete', { body: { reason: 'duplicate' }, ...ADM })).status, 404);
  const r = await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'duplicate record' }, ...ADM });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.deleted, a.id); assert.equal(r.json.relationships_removed, 1); assert.equal(r.json.asset.serial, 'SER-DEL-1');
  assert.equal((await h.req('GET', `/assets/${a.id}`)).status, 404);
  assert.equal((await h.req('GET', '/assets')).json.assets.some((x) => x.id === a.id), false);
  assert.equal((await h.req('GET', `/assets/${b.id}`)).json.relationships.length, 0);
  const audit = (await h.req('GET', '/audit?limit=200', ADM)).json;
  const rows = audit.audit || audit.entries || audit;
  const del = rows.find((x) => x.action === 'asset.delete');
  assert.ok(del, 'asset.delete audited');
  assert.equal(del.by, 'adm.sara'); assert.equal(del.target, a.id);
  assert.equal(del.detail.reason, 'duplicate record'); assert.equal(del.detail.deleted.asset_tag, 'TAG-DEL-1');
  // a second delete of the same id is a 404, not a crash
  assert.equal((await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'duplicate record' }, ...ADM })).status, 404);
});

test('delete: discovery results go back to review, or are ignored so a re-discovery stays out; agent binding cleared', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const D = h.app.discovery;
  D.devices.observe({ method: 'arp', ip: '10.30.0.5', mac: '02:dd:00:00:00:05', hostname: 'TEST-DEL-REVIEW', type: 'server' }, { scope_id: 'sc_del', site: 'Riyadh HQ' });
  D.devices.observe({ method: 'arp', ip: '10.30.0.6', mac: '02:dd:00:00:00:06', hostname: 'TEST-DEL-IGNORE', type: 'server' }, { scope_id: 'sc_del', site: 'Riyadh HQ' });
  const [d1, d2] = ['test-del-review', 'test-del-ignore'].map((n) => D.devices.list((d) => d.hostname === n)[0]);
  const a1 = (await h.req('POST', `/discovery/results/${d1.id}/approve`, { body: {}, ...ADM })).json.asset_id;
  const a2 = (await h.req('POST', `/discovery/results/${d2.id}/approve`, { body: {}, ...ADM })).json.asset_id;
  assert.ok(a1 && a2);
  h.app.store.collection('agents').put({ id: 'ag_test', status: 'active', asset_id: a1 });

  const r1 = await h.req('POST', `/assets/${a1}/delete`, { body: { reason: 'test entry' }, ...ADM });
  assert.equal(r1.status, 200, r1.text); assert.equal(r1.json.discovery_results, 1); assert.equal(r1.json.discovery_mode, 'review');
  assert.equal(D.devices.get(d1.id).status, 'new'); assert.equal(D.devices.get(d1.id).asset_id, null);
  assert.equal(h.app.store.collection('agents').get('ag_test').asset_id, null);

  const r2 = await h.req('POST', `/assets/${a2}/delete`, { body: { reason: 'not ours', discovery: 'ignore' }, ...ADM });
  assert.equal(r2.status, 200, r2.text);
  assert.equal(D.devices.get(d2.id).status, 'ignored');
  // seen again by the next run: stays ignored, no asset re-created
  D.devices.observe({ method: 'arp', ip: '10.30.0.6', mac: '02:dd:00:00:00:06', hostname: 'TEST-DEL-IGNORE', type: 'server' }, { scope_id: 'sc_del', site: 'Riyadh HQ' });
  assert.equal(D.devices.get(d2.id).status, 'ignored');
  assert.equal(h.app.assets.all().some((x) => x.mac === '02:dd:00:00:00:06'), false);
  // the review one can be approved again into a fresh asset
  const again = await h.req('POST', `/discovery/results/${d1.id}/approve`, { body: {}, ...ADM });
  assert.equal(again.status, 200, again.text); assert.notEqual(again.json.asset_id, a1);
});

test('bulk delete: admin only, reason required, per-item results, one summary audit line', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const ids = [];
  for (let i = 0; i < 3; i++) ids.push((await h.req('POST', '/assets', { body: { name: `TEST-BULK-DEL-${i}`, type: 'other', serial: `SER-BD-${i}` } })).json.asset.id);
  assert.equal((await h.req('POST', '/bulk/assets/delete', { body: { ids, reason: 'cleanup' } })).status, 403);
  assert.equal((await h.req('POST', '/bulk/assets/delete', { body: { ids, reason: '' }, ...ADM })).status, 400);
  assert.equal((await h.req('POST', '/bulk/assets/delete', { body: { ids: [], reason: 'cleanup' }, ...ADM })).status, 400);
  const r = await h.req('POST', '/bulk/assets/delete', { body: { ids: ids.concat(['as_000000000000']), reason: 'cleanup' }, ...ADM });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ok, 3); assert.equal(r.json.failed, 1); assert.equal(r.json.results[3].status, 404);
  for (const id of ids) assert.equal((await h.req('GET', `/assets/${id}`)).status, 404);
  const rows = (await h.req('GET', '/audit?limit=200', ADM)).json;
  const list = rows.audit || rows.entries || rows;
  assert.equal(list.filter((x) => x.action === 'asset.bulk-delete').length, 1);
  assert.equal(list.filter((x) => x.action === 'asset.delete').length, 3);
});

test('delete: a SIEM-connected asset has its log source stopped first; SIEM down → 409 unless force', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const a = (await h.req('POST', '/assets', { body: { name: 'TEST-SIEM-FW', type: 'firewall', serial: 'SER-SIEM-1', mgmt_ip: '10.40.0.1' } })).json.asset;
  h.app.store.collection('assets').patch(a.id, (x) => { x.siem = { source_id: 'itam-test-fw', kind: 'fortigate' }; });
  const M = h.app.membership; const realStop = M.stop; const calls = [];
  t.after(() => { M.stop = realStop; });
  M.stop = async () => { calls.push('down'); throw Object.assign(new Error('SIEM not reachable'), { status: 502 }); };
  const r1 = await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'decommissioned' }, ...ADM });
  assert.equal(r1.status, 409); assert.match(r1.json.error, /could not be stopped/); assert.equal(r1.json.code, 'siem_stop_failed');
  assert.equal((await h.req('GET', `/assets/${a.id}`)).status, 200, 'not deleted while the SIEM source is still live');
  M.stop = async (id, who, opts) => { calls.push(['stop', id, opts.confirm]); return { source_id: 'itam-test-fw', removed: true }; };
  const r2 = await h.req('POST', `/assets/${a.id}/delete`, { body: { reason: 'decommissioned' }, ...ADM });
  assert.equal(r2.status, 200, r2.text); assert.deepEqual(r2.json.siem, { stopped: true, source_id: 'itam-test-fw' });
  assert.deepEqual(calls[1], ['stop', a.id, true]);
  // force path
  const b = (await h.req('POST', '/assets', { body: { name: 'TEST-SIEM-SW', type: 'switch', serial: 'SER-SIEM-2' } })).json.asset;
  h.app.store.collection('assets').patch(b.id, (x) => { x.siem = { source_id: 'itam-test-sw', kind: 'cisco' }; });
  M.stop = async () => { throw Object.assign(new Error('SIEM not reachable'), { status: 502 }); };
  const r3 = await h.req('POST', `/assets/${b.id}/delete`, { body: { reason: 'decommissioned', force: true }, ...ADM });
  assert.equal(r3.status, 200, r3.text); assert.equal(r3.json.siem.stopped, false);
});
