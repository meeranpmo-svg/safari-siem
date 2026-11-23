// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IT Infrastructure Manager overview (engine/infra-overview.js): figures come from the register and the add-ons that own
// them; an add-on not installed or not reporting is { available:false, why } - never 0 %; percentages only with something
// to divide by; the real End of Life add-on is read; operator only (viewer refused); one broken add-on does not stop the
// answer. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerInfraOverview } = require('../engine/infra-overview');

const ADM = { user: 'syed', role: 'admin', ip: '' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  mk({ name: 'ESX-SYN-01', type: 'server', os: 'VMware ESXi 7.0', mgmt_ip: '10.5.0.1', warranty: { end: new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10) } });   // ends in two weeks, whenever the test runs
  mk({ name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2019', mgmt_ip: '10.5.0.10' });
  mk({ name: 'DB-SYN-01', type: 'vm', os: 'Oracle Linux 8', mgmt_ip: '10.5.0.11' });
  mk({ name: 'OLD-SYN-01', type: 'server', status: 'retired' });
  mk({ name: 'SW-SYN-01', type: 'network', vendor: 'Cisco', model: 'C2960X', os: 'Cisco IOS 12.2(55)SE', mgmt_ip: '10.5.1.1', warranty: { end: '2025-01-31' } });
  mk({ name: 'NAS-SYN-01', type: 'storage', vendor: 'Synology' });
  return e;
}

test('nothing connected: the register is counted, every other section says what to connect - never 0 %', async (t) => {
  const e = await setup(t);
  registerInfraOverview(e.app.srv, e.app);
  const r = await e.req('GET', '/infra-overview', { role: 'operator' });
  assert.equal(r.status, 200);
  const v = r.json;
  assert.deepEqual([v.register.servers.total, v.register.servers.physical, v.register.servers.virtual, v.register.network.total, v.register.storage.total], [3, 1, 2, 1, 1], 'retired servers are not counted');
  assert.deepEqual(v.register.servers.by_os, { ESXi: 1, Windows: 1, Linux: 1 });
  assert.equal(v.register.warranty.expired, 1); assert.ok(v.register.warranty.items.some((x) => x.name === 'SW-SYN-01'));
  for (const k of ['backup', 'patch', 'storage', 'contracts', 'databases']) {
    assert.equal(v[k].available, false, k); assert.match(v[k].why, /not installed|install\/|connect|no |not reported/i, k);
    assert.ok(!('protected_pct' in v[k]) && !('compliant_pct' in v[k]), k + ': no percentage without a source');
  }
});

test('connected add-ons: backup, Endpoint Central patches, storage, contracts and the real End of Life page', async (t) => {
  const e = await setup(t);
  require('../engine/lifecycle').registerLifecycle(e.app.srv, e.app);
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], summary: { assets: 3, protected: 1, stale: 0, failed: 1, none: 0, exempt: 1 } }) };
  e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'APP-SYN-01', missing: 0, critical: 0 }, { name: 'DB-SYN-01', asset_name: 'DB-SYN-01', missing: 7, critical: 2, health: 'highly vulnerable' }, { name: 'PC-SYN-9', missing: null }] }) };
  e.app.addons.storage = { view: () => ({ arrays: [{ at: '2026-10-24T05:00:00Z', platform: { id: 'nas1', label: 'NAS-SYN-01' }, capacity: { used_pct: 71.5, size_bytes: 1e13 }, disks: { failed: 1 }, worst: 'high' }], summary: { arrays: 1, read: 1, used_pct: 71.5, size_bytes: 1e13, used_bytes: 7.15e12, failed_disks: 1, critical: 0, high: 1 } }) };
  e.app.addons.supportContracts = { view: (role) => ({ contracts: [{ vendor: 'Cisco', product: 'SmartNet', end: '2026-11-01', days_left: 8, state: 'expiring' }, { vendor: 'Dell', product: 'ProSupport', end: '2027-06-01', days_left: 220, state: 'active' }], summary: { contracts: 2, expired: 0, expiring: 1, uncovered_assets: 3, role } }) };
  e.app.addons.dbHealth = { databases: () => ({ databases: [{ id: 'd1' }, { id: 'd2' }] }) };
  registerInfraOverview(e.app.srv, e.app);
  const v = (await e.req('GET', '/infra-overview', { role: 'operator' })).json;
  assert.deepEqual([v.backup.protected, v.backup.failed, v.backup.protected_pct], [1, 1, 50], 'exempt servers are out of scope: 1 of 2');
  assert.deepEqual([v.patch.computers, v.patch.reported, v.patch.compliant, v.patch.critical_missing, v.patch.compliant_pct], [3, 2, 1, 1, 50], 'a computer with no patch status is not counted either way');
  assert.equal(v.patch.worst[0].name, 'DB-SYN-01');
  assert.deepEqual([v.storage.used_pct, v.storage.failed_disks, v.storage.list[0].name], [71.5, 1, 'NAS-SYN-01']);
  assert.deepEqual([v.contracts.expiring, v.contracts.renewing.length, v.contracts.renewing[0].vendor], [1, 1, 'Cisco']);
  assert.equal(v.databases.registered, 2);
  assert.equal(v.lifecycle.available, true, 'the real End of Life add-on is read');
  assert.ok(typeof v.lifecycle.eol === 'number' && Array.isArray(v.lifecycle.items));
});

test('a backup add-on with no platform connected is not "100 % protected"; one failing add-on does not stop the answer', async (t) => {
  const e = await setup(t);
  e.app.addons.backup = { view: () => ({ platforms: [], summary: { assets: 3, protected: 0, stale: 0, failed: 0, none: 3, exempt: 0 } }) };
  e.app.addons.storage = { view: () => { throw new Error('array snapshot unreadable'); } };
  e.app.addons.manageengine = { computers: () => ({ computers: [] }) };
  registerInfraOverview(e.app.srv, e.app);
  const v = (await e.req('GET', '/infra-overview', { role: 'operator' })).json;
  assert.equal(v.backup.available, false); assert.match(v.backup.why, /no backup platform is connected/);
  assert.equal(v.storage.available, false); assert.match(v.storage.why, /could not be read: array snapshot unreadable/);
  assert.equal(v.patch.available, false); assert.match(v.patch.why, /Endpoint Central has not reported/);
  assert.equal(v.register.available, true);
});

test('roles: operator and admin read it, a viewer is refused (names servers, devices and contracts)', async (t) => {
  const e = await setup(t);
  registerInfraOverview(e.app.srv, e.app);
  assert.equal((await e.req('GET', '/infra-overview', { role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/infra-overview', { role: 'operator' })).status, 200);
  assert.equal((await e.req('GET', '/infra-overview', { role: 'admin' })).status, 200);
});
