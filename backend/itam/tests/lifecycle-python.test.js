// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 6d (docs/PYTHON-MIGRATION.md): pyengine/lifecycle_rules.py must answer exactly like view() in
// engine/lifecycle.js (the End of Life page) - the same rows, in the same order, with the same status, isolation
// requirement, exception and action - for devices from the inventory, Asset Discovery, virtualization hosts and storage
// arrays (duplicates by serial listed once), every rule family (Windows 11 builds, Windows 10 LTSC / ESU, servers, Linux,
// Solaris, ESXi, FortiOS, Cisco, PAN-OS, extra rules from config incl. an invalid one), many ties in the end-of-life date
// (the page's sort never answers "equal"), isolation requests and risk exceptions (pending, approved, expired).
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createLifecycle } = require('../engine/lifecycle');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');
const ADM = { user: 'syed', role: 'admin', ip: '' };

const OSES = ['Microsoft Windows Server 2012 R2 Standard', 'Windows Server 2012 R2 Datacenter', 'Windows Server 2016 Standard', 'Windows Server 2008 R2', 'Windows Server 2019',
  'Microsoft Windows 11 Pro 10.0.22631', 'Windows 11 Enterprise (22621)', 'Windows 11 Pro build 26100', 'Windows 10 Enterprise LTSC 10.0.17763', 'Windows 10 Pro', 'Windows 7 Professional',
  'CentOS Linux release 7.9.2009', 'CentOS 7', 'Red Hat Enterprise Linux Server release 6.10', 'Ubuntu 20.04.6 LTS', 'Debian GNU/Linux 11 (bullseye)', 'Oracle Solaris 11.3',
  'SunOS 5.10 Generic', 'FortiOS v6.2.15', 'Cisco IOS Software, C2960 Software, Version 12.2(55)SE12', 'PAN-OS 9.1.4', 'ACME-OS 3.1 (internal)', 'Linux 6.1', ''];

async function world(t) {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  e.app.config.discovery = Object.assign({}, e.app.config.discovery, { lifecycle: { rules: [{ pattern: 'acme-os\\s*3\\.', product: 'ACME OS 3', eol: '2026-12-31' }, { pattern: '([', product: 'broken' }, { pattern: 'linux 6\\.1', eol: '2026-10-01T00:00' }] } });
  const ids = OSES.map((os, i) => e.app.assets.create({ name: 'DEV-' + String(i).padStart(2, '0'), type: i % 5 === 0 ? 'network' : i % 3 ? 'server' : 'vm', status: i === 7 ? 'retired' : 'in_use', os,
    mgmt_ip: i % 4 ? '10.0.0.' + i : '', serial: i % 6 === 1 ? 'dup-1' : i % 2 ? 'SN' + i : '', site: 'RUH', vendor: 'Vendor\u0001X', model: 'M' + i }, ADM).asset.id);
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'dv1', status: 'new', hostname: 'sw-old', ip: '10.1.0.1', type: 'network', sys_descr: 'Cisco IOS Software, Version 15.0(2)SE', macs: ['aa:bb:cc:00:00:01'], extra: { serial: 'fox111' } });
  devs.put({ id: 'dv2', status: 'ignored', hostname: 'ign', os: 'Windows XP' });
  devs.put({ id: 'dv3', status: 'approved', asset_id: ids[0], os: 'Windows Server 2003' });
  devs.put({ id: 'dv4', status: 'new', ip: '10.1.0.4', os: 'Windows Server 2012', serial: 'DUP-1' });
  devs.put({ id: 'dv5', status: 'new', os: 'esxi 6.7.0', firmware: 'U3' });
  e.app.store.collection('virt_capacity').put({ id: 'vp_v', label: 'VC', site: 'JED', hosts: [{ id: 'host-1', name: 'esx01', version: 'VMware ESXi 6.7.0 build-17700523', serial: 'svc-tag-1', vendor: 'Dell', model: 'R740' }, { id: 'host-2', version: 'VMware ESXi 7.0.3', model: 'R750' }, { id: 'host-3', version: 'VMware ESXi 8.0' }] });
  e.app.store.collection('storage_snapshots').put({ id: 'st1', system: { name: 'MSA-1', serial: 'msa-9', model: 'MSA 2040', version: 'ESXi 5.5 tools' }, controllers: [{ name: 'A', serial: 'CA', model: 'C1' }, { name: 'B' }] });
  e.app.store.collection('storage_snapshots').put({ id: 'st2', system: {} });
  const reqs = e.app.store.collection('isolation_requests'), exc = e.app.store.collection('lifecycle_exceptions');
  reqs.put({ id: 'r1', key: 'asset:' + ids[0], state: 'pending', created_at: '2026-10-01T00:00:00Z' });
  reqs.put({ id: 'r2', key: 'asset:' + ids[3], state: 'isolated', created_at: '2026-09-01T00:00:00Z' });
  reqs.put({ id: 'r3', key: 'asset:' + ids[4], state: 'released', created_at: '2026-09-01T00:00:00Z' });
  exc.put({ id: 'x1', key: 'asset:' + ids[1], state: 'approved', expires: '2027-03-31', owner: 'CIO', created_at: '2026-08-01T00:00:00Z' });
  exc.put({ id: 'x2', key: 'asset:' + ids[11], state: 'approved', expires: '2026-10-01', created_at: '2026-07-01T00:00:00Z' });
  exc.put({ id: 'x3', key: 'asset:' + ids[11], state: 'pending', expires: '2027-01-01', created_at: '2026-10-10T00:00:00Z' });
  exc.put({ id: 'x4', key: 'asset:' + ids[12], state: 'rejected', created_at: '2026-10-11T00:00:00Z' });
  e.app.store.collection('lifecycle_settings').put({ id: 'isolation', approvers: ['Rasheed', 'siva'] });
  return { e };
}

test('Python End of Life view answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const py = createPyEngine({ python: PY });
  const { e } = await world(t);
  const L = createLifecycle(e.app, { now: () => NOW });
  for (const q of [{}, { all: '1' }]) {
    const n = JSON.parse(JSON.stringify(L.view(q)));
    const p = await py.call('rules.lifecycle', JSON.parse(JSON.stringify(L.inputs(q))));
    assert.deepEqual(p, n, 'identical view ' + JSON.stringify(q));
    if (!q.all) {
      assert.ok(n.items.length >= 15, 'rows: ' + n.items.length);
      assert.ok(n.summary.isolation_required > 0 && n.summary.exceptions === 1 && n.summary.exceptions_pending === 1);
      assert.ok(n.items.some((i) => i.source === 'virtualization') && n.items.some((i) => i.source === 'storage') && n.items.some((i) => i.source === 'discovery'));
      assert.equal(n.items.filter((i) => i.serial === 'DUP-1').length, 1, 'one row per serial');
    }
  }
  // the clock moves: an approved exception expires, "soon" turns into "eol"
  const later = createLifecycle(e.app, { now: () => NOW + 200 * 86400000 });
  const n2 = JSON.parse(JSON.stringify(later.view({ all: '1' })));
  assert.deepEqual(await py.call('rules.lifecycle', JSON.parse(JSON.stringify(later.inputs({ all: '1' })))), n2, 'identical view 200 days later');
});
