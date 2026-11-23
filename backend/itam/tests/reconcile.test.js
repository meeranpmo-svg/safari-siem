// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Server & asset reconciliation: approved devices keep feeding their asset (locked fields respected), differences are
// listed with the source that reports them, a source that cannot be read is NOT CHECKED (no invented "all fine"), fixes
// and accepted differences are explicit and audited, and Sync all runs the registered sources then recomputes.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createReconcile, osDiffers } = require('../engine/reconcile');
const { startApp } = require('./helpers');

const ADMIN = { user: 'siva', role: 'admin', ip: '127.0.0.1' };
// the shape runner.js gives an AD computer (classification reads extra.ad.os)
const AD = (hostname, ip, os, extra) => ({ method: 'ad', hostname, ip, os, uid: 'ad:cn=' + hostname, extra: { ad: Object.assign({ os: os || 'Windows Server 2019 Standard', enabled: true }, extra || {}) } });
const kinds = (rep) => rep.issues.filter((i) => !i.accepted).map((i) => `${i.kind}:${i.name}`).sort();

function siem({ down = false, hosts = {}, items = [] } = {}) {
  return async (url) => {
    if (down) { const e = new Error('connect ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; }
    if (url.endsWith('/netops/avail/map')) return { status: 200, json: { hosts } };
    if (url.endsWith('/sysadmin/targets')) return { status: 200, json: { items } };
    return { status: 404, json: {} };
  };
}

test('reconcile: os comparison ignores wording and generic families, catches real version differences', () => {
  assert.equal(osDiffers('Microsoft Windows Server 2019 (64-bit)', 'Windows Server 2019 Standard 10.0 (17763)'), false);
  assert.equal(osDiffers('Windows', 'Windows Server 2022 Datacenter'), false);
  assert.equal(osDiffers('Linux', 'Red Hat Enterprise Linux 9'), false);
  assert.equal(osDiffers('Windows Server 2016 Standard', 'Windows Server 2019 Standard'), true);
  assert.equal(osDiffers('Red Hat Enterprise Linux 8', 'Microsoft Windows Server 2022'), true);
  assert.equal(osDiffers('Windows Server 2012', 'Windows Server 2012 R2'), false);
});

test('reconcile: refresh, differences with their source, fixes, accept, SIEM not checked when unreachable', async () => {
  const t = await startApp({ noAi: true, config: { discovery: { siem: { secret_file: '/nonexistent/siem.secret' } } } });
  try {
    const { app } = t, dev = app.discovery.devices, at = (m) => new Date(Date.now() - m * 60000).toISOString();
    // 1. approved from AD, then AD reports a new IP: refresh moves the asset to it
    const d1 = dev.observe(AD('fs01', '10.0.1.10', 'Windows Server 2019 Standard'), { at: at(60) });
    const a1 = app.discovery.approve(d1.id, ADMIN).asset_id;
    dev.observe(AD('fs01', '10.0.1.11', 'Windows Server 2019 Standard'), { at: at(1) });
    // 2. a hand-made record (locked) merged with vCenter, which reports another OS
    const m1 = app.assets.create({ name: 'APP7', type: 'vm', mgmt_ip: '10.0.1.30', os: 'Red Hat Enterprise Linux 8', status: 'in_use' }, ADMIN).asset.id;
    const d2 = dev.observe({ method: 'vcenter', hostname: 'app7', ips: ['10.0.1.30'], macs: ['00:50:56:00:00:30'], os: 'Microsoft Windows Server 2022 (64-bit)', uid: 'vc:4230-app7', extra: { vcenter: { kind: 'vm', uuid: '4230-app7' } } }, { at: at(2) });
    app.discovery.merge(d2.id, m1, ADMIN);
    // 3. AD knows a server the inventory does not
    dev.observe(AD('newsrv', '10.0.1.50', 'Windows Server 2022 Standard'), { at: at(3) });
    // 4. retired but still answering
    const d4 = dev.observe(AD('oldsrv', '10.0.1.60', 'Windows Server 2012 R2'), { at: at(90) });
    const r1 = app.discovery.approve(d4.id, ADMIN).asset_id;
    app.assets.transition(r1, 'retire', ADMIN, 'replaced');
    dev.observe(AD('oldsrv', '10.0.1.60', 'Windows Server 2012 R2'), { at: at(5) });
    // 5. two records with one IP; one server without an IP
    app.assets.create({ name: 'DB1', type: 'server', mgmt_ip: '10.0.1.70', os: 'Oracle Linux 8', status: 'in_use' }, ADMIN);
    app.assets.create({ name: 'DB1-old', type: 'server', mgmt_ip: '10.0.1.70', os: 'Oracle Linux 8', status: 'in_use' }, ADMIN);
    app.assets.create({ name: 'NOIP', type: 'server', os: 'Windows Server 2019', status: 'in_use' }, ADMIN);

    // SIEM unreachable: inventory differences still listed, SIEM-side checks NOT CHECKED (never "no differences")
    const off = createReconcile(app, { request: siem({ down: true }), readFile: () => 'y'.repeat(32) });
    const rep0 = await off.run(ADMIN);
    assert.equal(rep0.refresh.assets_updated >= 1, true);
    assert.equal(app.assets.raw(a1).mgmt_ip, '10.0.1.11', 'approved asset follows the new IP from AD');
    assert.equal(app.assets.raw(m1).os, 'Red Hat Enterprise Linux 8', 'a hand-edited field is never overwritten by refresh');
    assert.equal(rep0.sources.availability.ok, false); assert.match(rep0.sources.availability.error, /not reachable/);
    assert.ok(!rep0.issues.some((i) => i.kind === 'not_monitored' || i.kind === 'not_in_server_admin'), 'nothing claimed about sources not read');
    // config has no SIEM link → also not checked, with the reason
    const nolink = await createReconcile(Object.assign({}, app, { config: {} }), { request: siem() }).run(ADMIN);
    assert.match(nolink.sources.server_admins.error, /SIEM link not configured/);

    const R = createReconcile(app, { request: siem({ hosts: { '10.0.1.11': { s: 'online' }, '10.0.1.60': { s: 'online' } }, items: [{ id: 'fs01', ip: '10.0.1.11', roles: ['windows', 'exchange'] }, { id: 'ghost', name: 'GHOST', ip: '10.0.9.9', roles: ['windows'] }] }), readFile: () => 'y'.repeat(32) });
    const rep = await R.run(ADMIN);
    const k = kinds(rep);
    for (const want of ['os_mismatch:APP7', 'not_in_inventory:newsrv', 'retired_alive:oldsrv', 'missing_ip:NOIP', 'exchange_mismatch:fs01', 'admin_not_in_inventory:GHOST', 'not_monitored:APP7', 'not_in_server_admin:NOIP'].filter((x) => !x.endsWith('NOIP') || x.startsWith('missing'))) assert.ok(k.includes(want), `${want} in ${k.join(', ')}`);
    assert.ok(k.some((x) => x.startsWith('duplicate:')), 'two records sharing 10.0.1.70');
    assert.ok(!k.includes('not_monitored:fs01'), 'monitored on its refreshed IP');
    assert.ok(!k.some((x) => x.startsWith('ip_mismatch')), 'IP already brought in line by refresh');
    const os = rep.issues.find((i) => i.kind === 'os_mismatch');
    assert.deepEqual([os.have, os.found, os.source, os.held_by, os.fix], ['Red Hat Enterprise Linux 8', 'Microsoft Windows Server 2022 (64-bit)', 'vcenter', 'manual edit (locked)', 'apply']);
    assert.equal(rep.issues.find((i) => i.kind === 'retired_alive').sev, 'high');

    // fixes: apply the source value, approve the unknown server; both audited
    await R.fix(os.id, ADMIN);
    assert.equal(app.assets.raw(m1).os, 'Microsoft Windows Server 2022 (64-bit)');
    const nw = R.view().report.issues.find((i) => i.kind === 'not_in_inventory');
    await R.fix(nw.id, ADMIN);
    const after = kinds(R.view().report);
    assert.ok(!after.includes('os_mismatch:APP7') && !after.includes('not_in_inventory:newsrv'), after.join(', '));
    await assert.rejects(R.fix(os.id, ADMIN), /no longer there/);
    const ghost = R.view().report.issues.find((i) => i.kind === 'admin_not_in_inventory');
    await assert.rejects(R.fix(ghost.id, ADMIN), /no automatic fix/);

    // accept needs a reason; hidden while the values stay the same
    await assert.rejects(R.accept({ id: ghost.id, reason: '' }, ADMIN), /reason/);
    const rep2 = await R.accept({ id: ghost.id, reason: 'lab server, not an asset' }, ADMIN);
    assert.equal(rep2.issues.find((i) => i.id === ghost.id).accepted.by, 'siva');
    assert.ok(!kinds(rep2).includes('admin_not_in_inventory:GHOST'));
    const audit = app.store.auditTail(200).map((e) => e.action);
    for (const a of ['reconcile.fix', 'reconcile.accept', 'reconcile.refresh']) assert.ok(audit.includes(a), a);
  } finally { await t.close(); }
});

test('reconcile: HTTP routes - operator reads, admin fixes and syncs; Sync all reports every source', async () => {
  const t = await startApp({ noAi: true });
  try {
    const R = t.app.addons && t.app.addons.reconcile;
    assert.ok(!R, 'not registered by the stock main.js (install/add-reconcile.sh adds it)');
    require('../engine/reconcile').registerReconcile(t.app.srv, t.app);
    const g = await t.req('GET', '/reconcile');
    assert.equal(g.status, 200, g.text); assert.ok(g.json.report && Array.isArray(g.json.report.issues));
    assert.equal((await t.as('v', 'viewer')('GET', '/reconcile')).status, 403);
    assert.equal((await t.req('POST', '/reconcile/sync-all', { body: {} })).status, 403, 'operator cannot sync all');
    let calls = 0;
    t.app.addons.sysadminSync = { run: async () => { calls++; return { ok: true, added: [1, 2] }; } };
    t.app.addons.virt = { sync: async () => { calls++; return { ok: false, error: 'vCenter refused the login' }; } };
    t.app.store.collection('virt_platforms').put({ id: 'vc1', label: 'RUH vCenter', enc: 'x' });
    const s = await t.as('siva', 'admin')('POST', '/reconcile/sync-all', { body: {} });
    assert.equal(s.status, 200, s.text);
    let j;
    for (let n = 0; n < 200; n++) { j = (await t.req('GET', '/reconcile')).json.job; if (j.state === 'done') break; await new Promise((r) => setTimeout(r, 20)); }
    assert.equal(j.state, 'done');
    const by = Object.fromEntries(j.steps.map((x) => [x.name, [x.state, x.detail || '']]));
    assert.deepEqual(by['AI Server Administrators'], ['done', 'added 2']);
    assert.deepEqual(by['Virtualization: RUH vCenter'], ['failed', 'failed: vCenter refused the login']);
    assert.equal(by.Storage[0], 'not installed');
    assert.equal(calls, 2);
    assert.equal((await t.as('siva', 'admin')('PUT', '/reconcile/settings', { body: { stale_days: 0 } })).status, 400);
  } finally { await t.close(); }
});

test('reconcile: network devices missing from the AI Network Engineer (fix sends them), and the ones not sent say why', async () => {
  const t = await startApp({ noAi: true, config: { discovery: { siem: { secret_file: '/nonexistent/siem.secret' } } } });
  try {
    const { app } = t, netdevs = [{ id: 'core-sw1', ip: '10.9.0.1' }];
    const req = async (url, o) => {
      if (url.endsWith('/netops/devices') && o.method === 'POST') { netdevs.push(JSON.parse(o.body)); return { status: 200, json: {} }; }
      if (url.endsWith('/netops/devices')) return { status: 200, json: { items: netdevs } };
      if (url.endsWith('/netops/avail/map')) return { status: 200, json: { hosts: {} } };
      if (url.endsWith('/sysadmin/targets')) return { status: 200, json: { items: [] } };
      return { status: 404, json: {} };
    };
    app.assets.create({ name: 'CORE-SW1', type: 'network', vendor: 'Cisco', mgmt_ip: '10.9.0.1', status: 'in_use' }, ADMIN);
    app.assets.create({ name: 'ACC-SW9', type: 'network', vendor: 'Cisco', model: 'C9200L-48P', mgmt_ip: '10.9.0.9', status: 'in_use' }, ADMIN);
    app.assets.create({ name: 'ISR-JED', type: 'other', vendor: 'Cisco', model: 'ISR4331/K9', mgmt_ip: '10.9.0.20', status: 'in_use' }, ADMIN);
    const ns = require('../engine/netops-sync').createNetopsSync(app, { request: req, readFile: () => 'y'.repeat(32) });
    (app.addons = app.addons || {}).netopsSync = ns;
    const R = createReconcile(app, { request: req, readFile: () => 'y'.repeat(32) });
    const rep = await R.run(ADMIN);
    assert.equal(rep.sources.network_engineer.ok, true);
    const k = kinds(rep).filter((x) => /network/.test(x));
    assert.deepEqual(k, ['network_not_synced:ISR-JED', 'not_in_network_engineer:ACC-SW9']);
    assert.match(rep.issues.find((i) => i.kind === 'network_not_synced').found, /type is "other"/);
    const fx = await R.fix('nonet:' + rep.issues.find((i) => i.kind === 'not_in_network_engineer').asset_id, ADMIN);
    assert.equal(fx.kind, 'not_in_network_engineer');
    assert.ok(netdevs.some((d) => d.ip === '10.9.0.9'), 'sent to the AI Network Engineer');
    assert.ok(!kinds(await R.run(ADMIN)).includes('not_in_network_engineer:ACC-SW9'));
  } finally { t.close(); }
});

test('reconcile: Sync all covers every CMDB source, runs on its own schedule, and the last run survives a restart', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const app = e.app; let clock = Date.parse('2026-10-19T02:00:00Z');
  const calls = [];
  app.addons = Object.assign(app.addons || {}, {
    manageengine: { syncEc: async () => { calls.push('ec'); return { ok: true, computers: 42, added: 3 }; } },
    virtCapacity: { run: async () => { calls.push('cap'); return [{ label: 'VC-RUH', ok: true, hosts: 4, vms: 60 }]; } },
    licenceSync: { run: async () => { calls.push('lic'); return { filled: 7 }; } },
  });
  app.store.collection('me_config').put({ id: 'cfg', ec: { base_url: 'https://ec.local', enc: 'x', last_sync: { at: '2026-10-19T01:30:00Z', ok: true } } });
  const R = createReconcile(app, { now: () => clock, request: async () => ({ status: 503, json: {} }), readFile: () => 'y'.repeat(32) });
  // no Sync all yet → the scheduled tick starts one
  R.tick();
  for (let i = 0; i < 50 && !(R.view().job && R.view().job.state === 'done'); i++) await new Promise((r) => setTimeout(r, 20));
  const j = R.view().job;
  assert.equal(j.state, 'done'); assert.equal(j.trigger, 'schedule');
  assert.deepEqual(calls.sort(), ['cap', 'ec', 'lic']);
  const step = (n) => j.steps.find((s) => s.name === n);
  assert.match(step('Endpoint Central').detail, /computers 42/); assert.match(step('vCenter / Nutanix capacity facts').detail, /hosts 4 · vms 60/); assert.match(step('Licence facts').detail, /filled 7/);
  // within the interval nothing new starts; after it, the next tick runs again
  calls.length = 0; clock += 3600000; R.tick(); await new Promise((r) => setTimeout(r, 30)); assert.equal(calls.length, 0);
  // the last run is kept: a fresh instance (a restart) still shows it
  const R2 = createReconcile(app, { now: () => clock, request: async () => ({ status: 503, json: {} }), readFile: () => 'y'.repeat(32) });
  assert.equal(R2.view().job.state, 'done'); assert.equal(R2.view().job.trigger, 'schedule');
  // freshness: Endpoint Central fresh (30 min old at the run, 1.5 h now)
  const f = R2.view().freshness.find((x) => x.source === 'Endpoint Central'); assert.equal(f.stale, false); assert.equal(f.age_h, 2);
  // switched off: no automatic run
  R2.putSettings({ auto_sync_hours: 0 }, { user: 'syed', role: 'admin', ip: '' });
  clock += 48 * 3600000; calls.length = 0; R2.tick(); await new Promise((r) => setTimeout(r, 30)); assert.equal(calls.length, 0);
});
