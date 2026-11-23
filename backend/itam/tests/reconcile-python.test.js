// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 6a (docs/PYTHON-MIGRATION.md): pyengine/reconcile_rules.py must answer exactly like compareCore() in
// engine/reconcile.js, given the same inputs - and through the same field projection the engine sends (slimA / slimD),
// so the projection cannot drop something a rule reads. The inventory below trips every rule: IP / OS / name mismatch,
// AD disabled / stale, retired but alive (discovery and availability), unlinked and not-in-inventory devices, duplicates,
// missing IP / OS, stale, not monitored, Windows / Exchange vs the AI Server Administrators, not synced and why, orphans,
// network devices vs the AI Network Engineer, accepted differences (same and changed values), and names that sort
// differently under localeCompare than by code point. Then the SIEM answers fail one by one.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { compareCore, slimA, slimD } = require('../engine/reconcile');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z'), DAY = 86400000;
const ago = (d) => new Date(NOW - d * DAY).toISOString();

function world() {
  const A = [], D = [];
  const a = (o) => { A.push(Object.assign({ status: 'in_use', type: 'server', lifecycle: [{ event: 'created', at: ago(400) }] }, o)); return o.id; };
  const d = (o) => { D.push(Object.assign({ status: 'approved', last_seen: ago(1), methods: { ad: {} } }, o)); };
  // 1. linked device disagrees
  a({ id: 'a1', name: 'DC-HQA', mgmt_ip: '10.0.0.1', os: 'Windows Server 2019 Standard', locked: { mgmt_ip: true }, prov: { os: 'agent' }, software: [{ name: 'Microsoft Exchange Server 2019' }] });
  d({ id: 'd1', asset_id: 'a1', ip: '10.0.0.99', ips: ['10.0.0.99'], os: 'Windows Server 2022', hostname: ('asdc-hqb.' + 'corp-hq.com'), methods: { ad: {}, vcenter: {}, hyperv: { untrusted: true } }, extra: { ad: { enabled: false, ou: 'Servers' } } });
  a({ id: 'a2', name: 'oradb01', mgmt_ip: '10.0.0.2', ips: ['10.0.0.22'], os: 'Oracle Linux 8', sources: [{ last_seen: ago(3) }] });
  d({ id: 'd2', asset_id: 'a2', ip: '10.0.0.22', os: 'Red Hat Enterprise Linux 8', hostname: 'OraDB01', extra: { ad: { enabled: true, last_logon: ago(200) } } });
  d({ id: 'd2old', asset_id: 'a2', ip: '10.9.9.9', last_seen: ago(40) });
  a({ id: 'a3', name: 'esx01', mgmt_ip: '10.0.1.1', os: 'VMware ESXi 7.0.3', discovery: { device_id: 'd3' } });
  d({ id: 'd3', ip: '10.0.1.1', os: 'ESXi', hostname: 'esx01', last_seen: ago(2), methods: { vcenter: {} } });
  // 2. retired but alive
  a({ id: 'a4', name: 'old-app', status: 'retired', mgmt_ip: '10.0.2.4' });
  d({ id: 'd4', asset_id: 'a4', last_seen: ago(2), methods: { sweep: {} } });
  a({ id: 'a5', name: 'old-db', status: 'disposed', mgmt_ip: '10.0.2.5', type: 'vm' });
  // 3. unlinked / not in inventory
  a({ id: 'a6', name: 'web01', mgmt_ip: '10.0.3.6', macs: ['AA:BB:CC:00:00:06'], serial: 'SN-6', os: 'Ubuntu 22.04' });
  d({ id: 'd6', status: 'new', type: 'server', hostname: 'web01', ip: '10.0.3.60', macs: ['aa:bb:cc:00:00:06'], methods: { sweep: {} } });
  d({ id: 'd7', status: 'new', type: 'vm', hostname: ('WEB01.' + 'corp-hq.com'), ip: '10.0.3.6', methods: { vcenter: {} } });
  d({ id: 'd8', status: 'new', type: 'hypervisor', hostname: 'ntnx-a', ip: '10.0.4.8', os: 'AHV', methods: { nutanix: {} } });
  d({ id: 'd9', status: 'new', type: 'server', ip: '10.0.4.9', methods: { sweep: {} } });
  d({ id: 'd10', status: 'new', type: 'server', ip: '10.0.4.10', methods: { hyperv: { untrusted: true } } });
  d({ id: 'd11', status: 'new', type: 'vm', ip: '10.0.4.11', serial: 'sn-6', extra: { vcenter: { uuid: 'U-1' } }, methods: { vcenter: {} } });
  // 4. duplicates, missing, stale; names that sort differently under ICU
  a({ id: 'a12', name: 'abc', mgmt_ip: '10.0.5.1' }); a({ id: 'a13', name: 'ABD', mgmt_ip: '10.0.5.1', type: 'vm' });
  a({ id: 'a14', name: 'Abc' }); a({ id: 'a15', name: 'abc_1', os: '' }); a({ id: 'a16', name: 'abc-1', type: 'storage' }); a({ id: 'a17', name: 'abc.1' });
  a({ id: 'a18', name: 'abc1', last_seen: ago(90) }); a({ id: 'a19', name: 'ab c', last_seen: ago(5) }); a({ id: 'a20', name: 'خادم-المالية' }); a({ id: 'a21' });
  // 5. Windows / Exchange / server admins
  a({ id: 'a22', name: 'EXCH01', mgmt_ip: '10.0.6.22', os: 'Windows Server 2016' });
  a({ id: 'a23', name: 'MAIL02', mgmt_ip: '10.0.6.23', os: 'Windows Server 2019' });
  a({ id: 'a24', name: 'fs01', mgmt_ip: '10.0.6.24', os: 'Windows Server 2019', tags: ['Exchange'] });
  a({ id: 'a25', name: 'pc-77', type: 'workstation', mgmt_ip: '10.0.6.25', os: 'Windows 11' });
  a({ id: 'a26', name: 'winnoip', os: 'Microsoft Windows Server 2022' });
  d({ id: 'd26', asset_id: 'a26', ip: '10.0.6.26', last_seen: ago(1) });
  a({ id: 'a27', name: 'appsrv', type: 'workstation', notes: 'old Exchange box' });
  // 6. network devices
  a({ id: 'a30', name: 'core-sw1', type: 'network', mgmt_ip: '10.0.7.1', model: 'C9500-24Y4C', vendor: 'Cisco' });
  a({ id: 'a31', name: 'acc-sw7', type: 'network', mgmt_ip: '10.0.7.7', model: 'WS-C2960X' });
  a({ id: 'a32', name: 'fw-edge', type: 'server', model: 'FG-200F', vendor: 'Fortinet', mgmt_ip: '10.0.7.32' });
  a({ id: 'a33', name: 'sw-noip', type: 'network', tags: ['switch'] });
  a({ id: 'a34', name: 'printer-sw', type: 'network', mgmt_ip: '10.0.7.34', discovery: { class: 'printer' } });
  return { A, D };
}
const SIEM = {
  avail: { ok: true, data: { hosts: { '10.0.0.1': { s: 'online' }, '10.0.0.22': { s: 'offline' }, '10.0.2.5': { s: 'online' }, '10.0.6.22': {} } } },
  targets: { ok: true, data: { items: [{ ip: '10.0.0.1', name: 'DC-HQA', roles: ['ad'] }, { ip: '10.0.6.24', roles: ['exchange'] }, { ip: '10.0.6.23', roles: ['windows'] }, { ip: '10.9.0.1', name: 'ghost', roles: ['windows', 'exchange'] }] } },
  netdevs: { ok: true, data: { items: [{ ip: '10.0.7.1' }] } },
};

function run(inp, py) {
  const n = JSON.parse(JSON.stringify(compareCore(inp)));
  const pin = Object.assign({}, inp, { assets: inp.assets.map(slimA), devices: inp.devices.map(slimD) });
  return py.call('rules.reconcile', JSON.parse(JSON.stringify(pin))).then((p) => ({ n, p }));
}

test('Python reconciliation rules answer exactly like the Node.js ones', { skip: !hasPy && 'python3 not available' }, async () => {
  const py = createPyEngine({ python: PY });
  const { A, D } = world();
  const settings = { stale_days: 30, alive_days: 7, ad_logon_days: 90 };
  const first = await run({ assets: A, devices: D, accepted: [], settings, now: NOW, avail: SIEM.avail, targets: SIEM.targets, netdevs: SIEM.netdevs }, py);
  assert.deepEqual(first.p, first.n, 'identical report');
  const kinds = Object.keys(first.n.counts).sort();
  for (const k of ['ip_mismatch', 'os_mismatch', 'name_mismatch', 'ad_disabled', 'ad_stale', 'retired_alive', 'unlinked', 'not_in_inventory', 'duplicate', 'missing_ip', 'missing_os', 'stale',
    'not_monitored', 'not_in_server_admin', 'exchange_mismatch', 'server_admin_not_synced', 'admin_not_in_inventory', 'not_in_network_engineer', 'network_not_synced']) assert.ok(kinds.includes(k), 'covers ' + k);
  // accepted: one still the same (hidden), one whose values changed (back again)
  const ip = first.n.issues.find((i) => i.kind === 'ip_mismatch'), os = first.n.issues.find((i) => i.kind === 'os_mismatch');
  const accepted = [{ id: ip.id, sig: ip.sig, by: 'syed', at: ago(1), reason: 'DR address' }, { id: os.id, sig: 'old|values', by: 'syed', at: ago(9), reason: 'was fine' }];
  const second = await run({ assets: A, devices: D, accepted, settings, now: NOW, avail: SIEM.avail, targets: SIEM.targets, netdevs: SIEM.netdevs }, py);
  assert.deepEqual(second.p, second.n, 'identical report with accepted differences');
  assert.equal(second.n.issues[second.n.issues.length - 1].id, ip.id, 'an accepted difference sorts last');
  // each SIEM source not readable: NOT CHECKED, never "no differences"
  for (const k of ['avail', 'targets', 'netdevs']) {
    const s = Object.assign({}, SIEM, { [k]: { ok: false, error: 'SIEM answered HTTP 502' } });
    const r = await run({ assets: A, devices: D, accepted: [], settings: { stale_days: 10, alive_days: 3, ad_logon_days: 30 }, now: NOW, avail: s.avail, targets: s.targets, netdevs: s.netdevs }, py);
    assert.deepEqual(r.p, r.n, k + ' unreadable: identical report');
  }
  const empty = await run({ assets: [], devices: [], accepted: [], settings, now: NOW, avail: { ok: true, data: {} }, targets: { ok: true, data: null }, netdevs: { ok: true, data: { items: [] } } }, py);
  assert.deepEqual(empty.p, empty.n, 'empty inventory');
});
