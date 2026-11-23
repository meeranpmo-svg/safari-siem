// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Licence details pulled from the assets: sockets / cores from SSH logins, Oracle edition from database logins, Windows
// edition from the OS, Microsoft 365 subscriptions into the register - and nothing typed by hand is ever overwritten.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createLicenceSync, registerLicenceSync } = require('../engine/licence-sync');
const { createCoreLicensing } = require('../engine/core-licensing');

const ADM = { user: 'siva', role: 'admin' };
const M365 = { configured: true, updated: '2026-10-14T06:00:00Z', licenses: [
  { sku: 'SPE_E3', total: 850, consumed: 812, free: false, renews: '2027-06-30', days: 259 },
  { sku: 'POWER_BI_STANDARD', total: 1000000, consumed: 40, free: true },
  { sku: 'CONTOSO_ADDON', total: 25, consumed: 30, free: false },
] };

test('licence sync: facts from logins and OS, hand-entered values kept, Microsoft 365 into the register', async () => {
  const t = await startApp({ noAi: true });
  try {
    const { app } = t;
    const mk = (b) => app.assets.create(Object.assign({ status: 'in_use' }, b), ADM).asset.id;
    const ora = mk({ name: 'ORADB01', type: 'server', os: 'Oracle Linux 8', mgmt_ip: '10.1.1.10' });
    const old = mk({ name: 'APP02', type: 'server', os: 'Red Hat Enterprise Linux 8', mgmt_ip: '10.1.1.11' });
    const win = mk({ name: 'FS01', type: 'server', os: 'Microsoft Windows Server 2022 Datacenter' });
    const hand = mk({ name: 'DB09', type: 'server', os: 'Oracle Linux 9', mgmt_ip: '10.1.1.12' });
    const vmx = mk({ name: 'ORAVM', type: 'vm', os: 'Oracle Linux 8', mgmt_ip: '10.1.1.13' });
    const sol = mk({ name: 'SOL01', type: 'server', os: 'Oracle Solaris 11.4 SPARC', mgmt_ip: '192.168.9.30' });
    const esx = mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 8.0', tags: ['esxi-host'], mgmt_ip: '10.1.1.14' });
    const devs = app.store.collection('disc_devices');
    const unix = (u) => Object.assign({ os: 'Oracle Linux 8', at: '2026-10-14T05:00:00Z' }, u);
    devs.put({ id: 'd1', ip: '10.1.1.10', asset_id: ora, extra: { unix_login: unix({ sockets: 2, cpus: 64, cores_per_socket: 16, sockets_v: 2 }), db_login: { oracle: { engine: 'oracle', edition: 'Enterprise Edition' } } } });
    devs.put({ id: 'd2', ip: '10.1.1.11', extra: { unix_login: unix({ sockets: 48, cpus: 48 }) } });            // old collector: logical CPUs
    devs.put({ id: 'd3', ip: '10.1.1.12', extra: { unix_login: unix({ sockets: 2, cpus: 32, cores_per_socket: 8, sockets_v: 2 }) } });
    devs.put({ id: 'd4', ip: '10.1.1.13', extra: { unix_login: unix({ sockets: 1, cpus: 4, sockets_v: 2 }), db_login: { oracle: { edition: 'Standard Edition' } } } });
    devs.put({ id: 'd6', ip: '192.168.9.30', extra: { unix_login: { os: 'Oracle Solaris 11.4 SPARC', model: 'SPARC T8-1', sockets: 1, cpus: 256, cores_per_socket: 32, sockets_v: 2, at: '2026-10-14T05:00:00Z' } } });
    devs.put({ id: 'd5', ip: '10.1.1.14', extra: { unix_login: unix({ sockets: 2, cpus: 8, sockets_v: 2 }) } });
    // someone typed DB09's sockets by hand earlier
    const C = createCoreLicensing(app);
    C.putFacts({ items: [{ id: hand, sockets: 4 }] }, ADM);
    app.licences.upsert({ id: 'lic_m365_spe_e3', product: 'M365 E3 (contract 2025-114)', seats: 800, cost: 2400000 }, ADM);

    let graph = { status: 200, json: M365 };
    const L = createLicenceSync(app, { siemCall: async () => graph });
    const r = await L.run(ADM);

    const f = (id) => app.store.collection('core_lic_facts').get(id) || {};
    assert.deepEqual([f(ora).sockets, f(ora).cores_per_socket, f(ora).oracle], [2, 16, 'ee']);
    assert.equal(f(ora).auto.oracle.from, 'database login (Enterprise Edition)');
    assert.equal(f(old).sockets, undefined, 'a socket count that is really the logical CPU count is not used');
    assert.ok(r.skipped.some((x) => x.asset === 'APP02' && x.field === 'sockets'));
    assert.equal(f(win).windows, 'dc');
    assert.deepEqual([f(hand).sockets, f(hand).cores_per_socket], [4, 8], 'hand-entered sockets kept, empty cores filled');
    assert.ok(r.kept.some((x) => x.asset === 'DB09' && x.field === 'sockets' && x.entered === 4 && x.found === 2));
    assert.equal(f(vmx).sockets, undefined, 'VM sockets are not physical');
    assert.equal(f(vmx).oracle, 'se2');
    assert.equal(f(esx).sockets, undefined, 'ESXi hosts come from vCenter / Nutanix');
    assert.deepEqual([f(sol).sockets, f(sol).cores_per_socket, f(sol).cpu_vendor], [1, 32, 'sparc'], 'Solaris SPARC: socket, cores and vendor from the SSH login');
    assert.equal(f(ora).cpu_vendor, undefined, 'x86 vendor is never guessed');

    // the licence audit now has the numbers: Oracle EE on ORADB01 = 32 cores x 0.5
    const v = C.view();
    assert.deepEqual(v.products.oracle_ee.hosts.map((h) => [h.host, h.licences]), [['ORADB01', 16]]);
    assert.equal(v.hosts.find((h) => h.name === 'FS01').windows_edition, 'dc');

    // Microsoft 365: existing record keeps its name and cost, seats + expiry follow Microsoft; free SKU skipped
    const lic = app.store.collection('licences');
    const e3 = lic.get('lic_m365_spe_e3');
    assert.deepEqual([e3.product, e3.cost, e3.seats, String(e3.expiry).slice(0, 10), e3.source, e3.m365.consumed], ['M365 E3 (contract 2025-114)', 2400000, 850, '2027-06-30', 'm365', 812]);
    const addon = lic.get('lic_m365_contoso_addon');
    assert.equal(addon.product, 'Microsoft 365 subscription CONTOSO_ADDON'); assert.equal(addon.publisher, 'Microsoft');
    assert.ok(!lic.get('lic_m365_power_bi_standard'));
    assert.deepEqual([r.m365.created, r.m365.updated_records, r.m365.skipped_free], [1, 1, 1]);
    // register "used" = assigned in Microsoft 365
    const cv = app.licences.complianceView();
    const row = (id) => cv.find((x) => x.id === id);
    assert.deepEqual([row('lic_m365_spe_e3').used, row('lic_m365_spe_e3').compliance], [812, 'under']);
    assert.deepEqual([row('lic_m365_contoso_addon').used, row('lic_m365_contoso_addon').compliance], [30, 'over']);

    // a value typed over an auto-filled one is the person's from then on; an auto value follows the source
    C.putFacts({ items: [{ id: ora, oracle: 'se2' }] }, ADM);
    devs.patch('d1', (x) => { x.extra.unix_login.cores_per_socket = 24; return x; });
    const r2 = await L.run(ADM);
    assert.deepEqual([f(ora).oracle, f(ora).cores_per_socket], ['se2', 24]);
    assert.ok(r2.kept.some((x) => x.asset === 'ORADB01' && x.field === 'oracle'));
    assert.equal(r2.m365.unchanged, 2);

    // a retired licence is not revived; SIEM errors are reported, not thrown
    app.licences.retire('lic_m365_contoso_addon', ADM, 'cancelled');
    graph = { status: 200, json: Object.assign({}, M365, { licenses: [{ sku: 'CONTOSO_ADDON', total: 30, consumed: 30 }] }) };
    assert.equal((await L.run(ADM)).m365.retired_kept, 1);
    assert.equal(lic.get('lic_m365_contoso_addon').status, 'inactive');
    graph = { status: 200, json: { configured: false, reason: 'first sync pending' } };
    assert.match((await L.run(ADM)).m365.error, /not connected/);
    const L2 = createLicenceSync(app, { siemCall: async () => { throw new Error('SIEM not reachable (ECONNREFUSED)'); } });
    assert.match((await L2.run(ADM)).m365.error, /not reachable/);
  } finally { await t.close(); }
});

test('licence sync routes: operator reads and runs, viewer refused; unlicensed commercial products listed', async () => {
  const t = await startApp({ noAi: true });
  try {
    const { app } = t;
    app.assets.create({ name: 'PC1', type: 'workstation', status: 'in_use', software: [{ name: 'Adobe Acrobat Pro', publisher: 'Adobe' }, { name: 'Microsoft Visual C++ 2015 Redistributable', publisher: 'Microsoft Corporation' }, { name: '7-Zip', publisher: 'Igor Pavlov' }, { name: 'Microsoft Project Professional 2021', publisher: 'Microsoft Corporation' }] }, ADM);
    app.licences.upsert({ id: 'lic_proj', product: 'Project', product_key_match: 'project professional', seats: 5 }, ADM);
    registerLicenceSync(app.srv, app);
    assert.equal((await t.req('GET', '/licence-sync', { role: 'viewer' })).status, 403);
    const g = await t.req('GET', '/licence-sync');
    assert.equal(g.status, 200);
    assert.deepEqual(g.json.unlicensed.map((p) => p.product), ['Adobe Acrobat Pro']);
    const p = await t.req('POST', '/licence-sync/run');
    assert.equal(p.status, 200);
    assert.ok(p.json.last && p.json.last.m365 && p.json.last.m365.ok === false, 'no SIEM link in the test app - reported, not thrown');
  } finally { await t.close(); }
});
