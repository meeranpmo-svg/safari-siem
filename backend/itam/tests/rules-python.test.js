// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 6b / 6c (docs/PYTHON-MIGRATION.md): pyengine/asset_rules.py must answer exactly like
//   findingsCore() in engine/findings.js                         (not seen, shadow IT, missing data, warranty, EOL, licences)
//   syncFacts() in engine/licence-sync.js                        (what is filled, kept as typed by hand, skipped - and the
//                                                                 core-licence fact records written)
//   the unlicensed-products list of licence-sync.js
// over the same inventory, built through the real engine (assets, licence register, discovery logins, hand-typed facts).
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { findingsCore } = require('../engine/findings');
const { createLicenceSync } = require('../engine/licence-sync');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z'), DAY = 86400000;
const ago = (d) => new Date(NOW - d * DAY).toISOString(), ahead = (d) => new Date(NOW + d * DAY).toISOString().slice(0, 10);
const ADM = { user: 'syed', role: 'admin', ip: '' };
const plain = (v) => JSON.parse(JSON.stringify(v));

async function inventory(t) {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    win: mk({ name: 'DC-HQA', type: 'server', os: 'Microsoft Windows Server 2019 Datacenter', mgmt_ip: '10.0.0.1', owner: 'it', site: 'RUH', warranty: { end: ahead(20) }, eol: ahead(-30),
      software: [{ name: 'Microsoft SQL Server 2019', publisher: 'Microsoft Corporation', version: '15.0' }, { name: 'Adobe Acrobat Reader DC', publisher: 'Adobe' }, { name: 'Microsoft Visual C++ 2015 Redistributable', publisher: 'Microsoft' }] }),
    std: mk({ name: 'fs02', type: 'server', os: 'Windows Server 2022 Standard', mgmt_ip: '10.0.0.2', warranty: { end: ahead(-400) }, software: ['Microsoft SQL Server 2019 15.0.2000', { name: 'Oracle Database 19c', publisher: 'Oracle' }] }),
    ora: mk({ name: 'oradb01', type: 'server', os: 'Oracle Linux 8', mgmt_ip: '10.0.0.3', warranty: { end: ahead(80) }, eol: ahead(60), software: [{ name: 'Oracle Database 19c', publisher: 'Oracle', licence_id: 'lic_ora' }] }),
    sparc: mk({ name: 'sun-m5', type: 'server', os: 'Oracle Solaris 11.4', mgmt_ip: '10.0.0.4' }),
    old: mk({ name: 'lnx-old', type: 'server', os: 'CentOS 7', mgmt_ip: '10.0.0.5' }),
    vm: mk({ name: 'app-vm', type: 'vm', os: 'Windows Server 2019 Datacenter', mgmt_ip: '10.0.0.6', software: [{ name: 'TeamViewer 15', publisher: 'TeamViewer GmbH' }] }),
    esx: mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 7.0', tags: ['esxi-host'], mgmt_ip: '10.0.0.7' }),
    ntx: mk({ name: 'ntnx-a', type: 'server', os: 'CentOS', mgmt_ip: '10.0.0.8' }),
    pc: mk({ name: 'PC-77', type: 'workstation', networked: true, mgmt_ip: '10.0.1.77', last_seen: ago(200), software: [{ name: 'Microsoft Office Professional Plus 2019', publisher: 'Microsoft' }, { name: 'AutoCAD 2024', publisher: 'Autodesk' }] }),
    pc2: mk({ name: 'PC-78', type: 'laptop', last_seen: ago(40), software: [{ name: 'Microsoft Office Professional Plus 2019', publisher: 'Microsoft' }] }),
    ret: mk({ name: 'old-srv', type: 'server', status: 'retired', os: 'Windows Server 2012 Standard', software: [{ name: 'Adobe Photoshop', publisher: 'Adobe' }] }),
  };
  // the Python twin reads these too: the sensor-only source (shadow IT) and a missing tag
  e.app.store.collection('assets').patch(ids.pc, (a) => { a.sources = [{ source: 'sensor', last_seen: ago(200) }]; delete a.owner; a.last_seen = ago(200); });
  e.app.store.collection('assets').patch(ids.pc2, (a) => { a.last_seen = ago(40); });
  e.app.store.collection('assets').patch(ids.ntx, (a) => { a.asset_tag = 'AT-0099'; });
  const L = e.app.licences;
  L.upsert({ id: 'lic_sql', product: 'SQL Server', seats: 1, expiry: ahead(10), product_key_match: 'sql server' }, ADM);
  L.upsert({ id: 'lic_office', product: 'Microsoft Office', seats: 10, expiry: ahead(-5) }, ADM);
  L.upsert({ id: 'lic_ora', product: 'Oracle Database Enterprise', seats: null }, ADM);
  L.upsert({ id: 'lic_x', product: 'Nothing installed', seats: 3 }, ADM);
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'd1', asset_id: ids.ora, ip: '10.0.0.3', last_seen: ago(1), extra: { unix_login: { at: ago(1), os: 'Linux', sockets: '2', cpus: 32, cores_per_socket: 8, sockets_v: 2 }, db_login: { oracle: { edition: 'Oracle Database 19c Enterprise Edition' } } } });
  devs.put({ id: 'd1b', asset_id: ids.ora, ip: '10.0.0.3', last_seen: ago(5), extra: { db_login: { oracle: { edition: 'Standard Edition 2' } } } });
  devs.put({ id: 'd2', ip: '10.0.0.4', last_seen: ago(2), extra: { unix_login: { at: ago(2), os: 'SunOS 5.11', platform: 'sun4v', sockets: 1, cores_per_socket: '16 cores' } } });
  devs.put({ id: 'd3', ip: '10.0.0.5', last_seen: ago(3), extra: { unix_login: { at: ago(3), sockets: 32, cpus: 32, cores_per_socket: 1 } } });
  devs.put({ id: 'd3err', ip: '10.0.0.5', last_seen: ago(1), extra: { unix_login: { at: ago(1), error: 'auth failed', sockets: 4 } } });
  devs.put({ id: 'd4', ip: '10.0.0.6', last_seen: ago(1), extra: { unix_login: { at: ago(1), sockets: 2, cpus: 8 } } });
  devs.put({ id: 'd5', ip: '10.0.0.8', last_seen: ago(1), extra: { unix_login: { at: ago(1), sockets: 2, cpus: 64, sockets_v: '2', cores_per_socket: 16 }, db_login: { oracle: { edition: 'Personal' } } } });
  devs.put({ id: 'd6', asset_id: 'gone', ip: '10.0.0.2', last_seen: ago(1), extra: { db_login: { oracle: { edition: 'Express Edition' } } } });
  const facts = e.app.store.collection('core_lic_facts');
  facts.put({ id: ids.win, windows: 'std', updated_by: 'syed' });                                  // typed by hand: kept
  facts.put({ id: ids.ora, sockets: 2, auto: { sockets: { v: 2, from: 'SSH login', at: ago(30) } } });   // auto, same value
  facts.put({ id: ids.ntx, source: 'nutanix', sockets: 1, cores_per_socket: 8 });                    // Prism owns sockets / cores
  facts.put({ id: ids.sparc, cores_per_socket: '' });
  return { e, ids };
}

test('Python findings, licence facts and unlicensed products answer exactly like the Node.js rules', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const py = createPyEngine({ python: PY });
  const { e } = await inventory(t);
  // findings
  for (const settings of [{ not_seen_days: 30, expiry_window_days: 90 }, { not_seen_days: 7, expiry_window_days: 365 }, { not_seen_days: 365, expiry_window_days: 0 }]) {
    const inp = { assets: e.app.assets.all ? e.app.assets.all() : e.app.store.collection('assets').all(), licences: e.app.licences.active(), settings, now: NOW };
    const n = plain(findingsCore(inp));
    const p = await py.call('rules.findings', plain(inp));
    assert.deepEqual(p.findings, n, 'findings ' + JSON.stringify(settings));
    if (settings.not_seen_days === 30) for (const k of ['not_seen', 'shadow_it', 'missing_owner', 'missing_location', 'missing_warranty', 'warranty_expired', 'warranty_expiring', 'eol_passed', 'eol_expiring', 'licence_over', 'licence_under', 'licence_expiring'])
      assert.ok(n.some((f) => f.kind === k), 'covers ' + k);
  }
  // licence facts: Python decides from the state before, Node.js decides and writes - the results must match
  const factsCol = e.app.store.collection('core_lic_facts');
  const before = {}; for (const f of factsCol.all()) before[f.id] = plain(f);
  const pin = { assets: e.app.store.collection('assets').all(), devices: e.app.store.collection('disc_devices').all((x) => x.extra && (x.extra.unix_login || x.extra.db_login)), facts: before, now: NOW };
  const p = await py.call('rules.licence_facts', plain(pin));
  const LS = createLicenceSync(e.app, { siemCall: async () => ({ status: 404 }), now: () => NOW });
  const out = { filled: [], kept: [], skipped: [] };
  LS.syncFacts(out);
  assert.deepEqual(p.filled, plain(out.filled), 'filled'); assert.deepEqual(p.kept, plain(out.kept), 'kept as typed by hand'); assert.deepEqual(p.skipped, plain(out.skipped), 'skipped');
  const after = Object.assign({}, before); for (const f of p.puts) after[f.id] = f;
  const nodeAfter = {}; for (const f of factsCol.all()) nodeAfter[f.id] = plain(f);
  assert.deepEqual(after, nodeAfter, 'the same core-licence fact records');
  assert.ok(out.filled.length >= 5 && out.kept.length >= 1 && out.skipped.length >= 2, JSON.stringify({ f: out.filled.length, k: out.kept.length, s: out.skipped.length }));
  // a second run changes nothing in either engine
  const again = {}; for (const f of factsCol.all()) again[f.id] = plain(f);
  const p2 = await py.call('rules.licence_facts', plain(Object.assign({}, pin, { facts: again })));
  const out2 = { filled: [], kept: [], skipped: [] }; LS.syncFacts(out2);
  assert.deepEqual(p2.puts, []); assert.deepEqual(p2.filled, plain(out2.filled)); assert.deepEqual(p2.kept, plain(out2.kept));
  // unlicensed commercial products
  const un = await py.call('rules.unlicensed', plain({ assets: e.app.store.collection('assets').all((a) => a.status !== 'retired' && a.status !== 'disposed'), licences: e.app.licences.active() }));
  assert.deepEqual(un.unlicensed, plain(LS.status().unlicensed), 'unlicensed products');
  assert.ok(un.unlicensed.some((x) => /AutoCAD/.test(x.product)) && !un.unlicensed.some((x) => /Redistributable|Photoshop/.test(x.product)));
});
