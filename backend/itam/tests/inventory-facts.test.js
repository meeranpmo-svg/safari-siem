// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Inventory columns: IP (management IP, else discovery's addresses), the host a VM runs on (runs_on, else the name the
// hypervisor reported), the VM name and its power state from the newest vCenter / Nutanix sighting.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerInventoryFacts, normPower } = require('../engine/inventory-facts');

const ADM = { user: 'syed', role: 'admin' };

test('normPower: vCenter and Prism spellings', () => {
  assert.equal(normPower('POWERED_ON'), 'on'); assert.equal(normPower('poweredOff'), 'off'); assert.equal(normPower('ON'), 'on');
  assert.equal(normPower('OFF'), 'off'); assert.equal(normPower('SUSPENDED'), 'suspended'); assert.equal(normPower(''), null); assert.equal(normPower('weird'), 'unknown');
});

test('inventory facts: IP, host, VM name and power state per asset', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  registerInventoryFacts(e.app.srv, e.app);
  const A = e.app.assets;
  const host = A.create({ name: 'ESX01', type: 'server', status: 'in_use', mgmt_ip: '10.20.0.11' }, ADM).asset.id;
  const vm = A.create({ name: 'erp-app', type: 'vm', status: 'in_use' }, ADM).asset.id;
  const vm2 = A.create({ name: 'ntx-db', type: 'vm', status: 'in_use' }, ADM).asset.id;
  const sw = A.create({ name: 'core-sw1', type: 'network', status: 'in_use', mgmt_ip: '10.10.1.2' }, ADM).asset.id;
  const gone = A.create({ name: 'old', type: 'server', status: 'in_use' }, ADM).asset.id;
  e.app.store.collection('assets').patch(gone, (a) => { a.status = 'disposed'; return a; });
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'dd1', asset_id: vm, ips: ['10.30.0.5', '10.30.0.6'], methods: { vcenter: { last_seen: '2026-10-14T08:00:00.000Z' } }, extra: { vcenter: { kind: 'vm', name: 'ERP-APP-PROD (vm-101)', host: ('esx01.' + 'corp-hq.com'), power_state: 'POWERED_ON', platform: 'HQ vCenter' } } });
  devs.put({ id: 'dd1b', asset_id: vm, ips: [], methods: { vcenter: { last_seen: '2026-10-01T08:00:00.000Z' } }, extra: { vcenter: { kind: 'vm', name: 'old-name', power_state: 'POWERED_OFF' } } });
  devs.put({ id: 'dd2', asset_id: vm2, ips: ['10.40.0.9'], methods: { nutanix: { last_seen: '2026-10-14T09:00:00.000Z' } }, extra: { nutanix: { kind: 'vm', name: 'NTX-DB01', host: 'NTNX-A', power_state: 'OFF', platform: 'Prism' } } });
  A.addRelationship({ from: vm, to: host, type: 'runs_on' }, ADM, { source: 'vcenter', autoConfirm: true });

  const r = await e.as('v', 'viewer')('GET', '/inventory-facts');
  assert.equal(r.status, 200, r.text);
  const f = r.json.assets;
  assert.deepEqual([f[vm].ip, f[vm].vm_name, f[vm].host_name, f[vm].host_id, f[vm].power, f[vm].source], ['10.30.0.5', 'ERP-APP-PROD (vm-101)', 'ESX01', host, 'on', 'vcenter'], 'newest sighting wins; runs_on names the host asset');
  assert.deepEqual([f[vm2].ip, f[vm2].vm_name, f[vm2].host_name, f[vm2].host_id, f[vm2].power], ['10.40.0.9', 'NTX-DB01', 'NTNX-A', null, 'off'], 'no relationship: the hypervisor-reported host name');
  assert.deepEqual([f[sw].ip, f[sw].vm_name, f[sw].power], ['10.10.1.2', null, null]);
  assert.equal(f[host].ip, '10.20.0.11');
  assert.ok(!(gone in f), 'disposed assets are left out');
});
