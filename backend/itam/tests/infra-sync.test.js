// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IT Asset Management <-> Infrastructure Automation (engine/infra-sync.js) against a fake sentra-infra API: which assets are
// offered (and why others are not), targets created on the probe without any credential, no duplicates, name / site /
// owner follow, a target removed there is not re-sent, sentra-infra-only targets land in the register, the link refused /
// missing is reported, roles and validation, audit. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createInfraSync, registerInfraSync, deviceProfile } = require('../engine/infra-sync');

const ADM = { user: 'syed', role: 'admin', ip: '' };
const SECRET = 's'.repeat(32);
function fakeInfra(state) {
  return async (url, o) => {
    state.calls.push([o.method, url.replace(/^https?:\/\/[^/]+/, ''), o.headers['X-Sentra-Proxy-Secret'], o.body ? JSON.parse(o.body) : null]);
    if (o.headers['X-Sentra-Proxy-Secret'] !== SECRET) return { status: 401, json: { error: 'unauthorised' } };
    const p = url.replace(/^https?:\/\/[^/]+\/api\/infra/, '');
    if (o.method === 'GET' && p === '/probes') return { status: 200, json: { probes: state.probes } };
    if (o.method === 'GET' && p === '/targets') return { status: 200, json: { targets: JSON.parse(JSON.stringify(state.targets)) } };   // a snapshot, as over HTTP
    if (o.method === 'POST' && p === '/targets') { const t = Object.assign({ id: 't_' + (state.targets.length + 1) }, JSON.parse(o.body)); state.targets.push(t); return { status: 200, json: { target: t } }; }
    const m = /^\/targets\/([^/]+)$/.exec(p);
    if (o.method === 'POST' && m) { const t = state.targets.find((x) => x.id === decodeURIComponent(m[1])); Object.assign(t, JSON.parse(o.body)); return { status: 200, json: { target: t } }; }
    return { status: 404, json: { error: 'not found' } };
  };
}
async function setup(t, st) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.assets, id = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    cat: id({ name: 'SW-SYN-1', type: 'network', vendor: 'Cisco', model: 'C9300-48P', mgmt_ip: '10.1.0.2', site: 'Riyadh HQ', owner: 'omar.syn' }),
    nex: id({ name: 'DC-SYN-N9K', type: 'network', vendor: 'Cisco', model: 'N9K-C93180YC', mgmt_ip: '10.1.0.3' }),
    fgt: id({ name: 'FW-SYN-1', type: 'network', vendor: 'Fortinet', model: 'FortiGate 100F', mgmt_ip: '10.1.0.1' }),
    jun: id({ name: 'RT-SYN-J', type: 'network', vendor: 'Juniper', model: 'MX204', mgmt_ip: '10.1.0.9' }),
    noip: id({ name: 'SW-SYN-NOIP', type: 'network', vendor: 'Cisco' }),
    lin: id({ name: 'APP-SYN-LNX', type: 'server', os: 'Ubuntu 22.04 LTS', mgmt_ip: '10.2.0.5' }),
    win: id({ name: 'APP-SYN-WIN', type: 'server', os: 'Windows Server 2022', mgmt_ip: '10.2.0.6' }),
  };
  e.app.addons = e.app.addons || {};
  e.app.addons.serviceMap = { view: () => ({ servers: [
    { ip: '10.2.0.5', host: 'APP-SYN-LNX', os: 'Ubuntu 22.04', asset: { id: ids.lin, owner: 'huda.syn' }, services: [{ id: 'postgres', confidence: 'confirmed' }, { id: 'mysql', confidence: 'possible' }] },
    { ip: '10.2.0.7', host: 'db-syn-2', os: 'Oracle Linux 8', asset: null, services: [{ id: 'mysql', confidence: 'confirmed' }] }] }) };
  const S = createInfraSync(e.app, { request: fakeInfra(st), readFile: () => SECRET });
  return { e, S, ids };
}

test('profiles: vendor / model / OS wording to the read-only profile', () => {
  assert.equal(deviceProfile({ vendor: 'Cisco Systems', model: 'C9300' }), 'cisco-ios');
  assert.equal(deviceProfile({ vendor: 'Cisco', model: 'N9K-C93180YC' }), 'cisco-nxos');
  assert.equal(deviceProfile({ discovery: { vendor: 'cisco-ios' } }), 'cisco-ios');
  assert.equal(deviceProfile({ vendor: 'Fortinet' }), 'fortigate'); assert.equal(deviceProfile({ vendor: 'HPE Aruba' }), 'aruba');
  assert.equal(deviceProfile({ vendor: 'Cisco', model: 'ASA5516' }), null, 'ASA has no read-only profile there');
  assert.equal(deviceProfile({ vendor: 'Juniper' }), null);
});

test('the register goes to Infrastructure Automation: devices, Linux hosts and confirmed databases, no credentials, no duplicates', async (t) => {
  const st = { calls: [], probes: [{ id: 'relay-1' }], targets: [{ id: 't_old', kind: 'device', profile: 'cisco-ios', name: 'old name', address: '10.1.0.2', site: '', owner: '' }] };
  const { e, S, ids } = await setup(t, st);
  const v = S.view();
  assert.deepEqual(v.pending.map((x) => x.key).sort(), ['db:10.2.0.5:postgres', 'db:10.2.0.7:mysql', 'device:10.1.0.1', 'device:10.1.0.2', 'device:10.1.0.3', 'host:10.2.0.5'].sort());
  assert.ok(v.skipped.some((x) => x.asset_id === ids.jun && /no read-only profile for Juniper/.test(x.why)));
  assert.ok(v.skipped.some((x) => x.asset_id === ids.noip && /no IP address/.test(x.why)));
  assert.ok(!v.pending.some((x) => x.asset_id === ids.win), 'Windows has no agentless Linux profile');
  const r = await S.run(ADM);
  assert.equal(r.ok, true, r.error);
  assert.equal(r.added.length, 5); assert.equal(r.already, 1);
  const posts = st.calls.filter((c) => c[0] === 'POST' && c[1] === '/api/infra/targets').map((c) => c[3]);
  assert.ok(posts.every((b) => b.probe_id === 'relay-1' && !('credential_ref' in b) && b.enabled === true), 'on the only probe, never a credential');
  assert.deepEqual(posts.find((b) => b.kind === 'db' && b.address === '10.2.0.5'), { kind: 'db', profile: 'postgres', name: 'APP-SYN-LNX PostgreSQL', address: '10.2.0.5', site: '', owner: 'huda.syn', probe_id: 'relay-1', enabled: true });
  // the existing target follows name / site / owner from the register
  assert.deepEqual([st.targets[0].name, st.targets[0].site, st.targets[0].owner], ['SW-SYN-1', 'Riyadh HQ', 'omar.syn']);
  assert.deepEqual(r.updated.map((u) => u.changed.sort()), [['name', 'owner', 'site']]);
  // second run: nothing new; a target removed in sentra-infra on purpose is not sent again
  st.targets = st.targets.filter((x) => x.address !== '10.1.0.3');
  const r2 = await S.run(ADM); assert.equal(r2.added.length, 0); assert.equal(r2.skipped_removed, 1);
  assert.equal(e.app.store.auditTail(50, (x) => x.action === 'infra_sync.run').length, 2);
});

test('Infrastructure Automation goes to the register: targets only there are added, same IP is linked', async (t) => {
  const st = { calls: [], probes: [{ id: 'relay-1' }], targets: [
    { id: 't_a', kind: 'host', profile: 'linux', name: 'jump-syn-01', address: '10.3.0.10', site: 'DR' },
    { id: 't_b', kind: 'device', profile: 'fortigate', name: 'fw-syn-dr', address: '10.3.0.1' },
    { id: 't_c', kind: 'host', profile: 'linux', name: 'APP-SYN-LNX', address: '10.2.0.5' },
    { id: 't_d', kind: 'db', profile: 'postgres', name: 'pg', address: '10.3.0.10' }] };
  const { e, S, ids } = await setup(t, st);
  const r = await S.run(ADM);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual([r.pulled.seen, r.pulled.added, r.pulled.linked], [3, 2, 1], JSON.stringify(r.pulled));
  const A = e.app.store.collection('assets');
  assert.ok(A.all((a) => a.mgmt_ip === '10.3.0.10' || (a.name || '').toLowerCase() === 'jump-syn-01').length === 1, 'jump host added to the register');
  const d = e.app.store.collection('disc_devices').all((x) => (x.uids || []).includes('infra:t_c'))[0];
  assert.equal(d.asset_id, ids.lin, 'linked to the asset with the same IP');
});

test('link problems are reported, never silent; several probes need a choice; roles and validation', async (t) => {
  const st = { calls: [], probes: [{ id: 'relay-1' }, { id: 'relay-2' }], targets: [] };
  const { e } = await setup(t, st);
  const bad = createInfraSync(e.app, { request: fakeInfra(st), readFile: () => { throw Object.assign(new Error('x'), { code: 'ENOENT' }); } });
  const r0 = await bad.run(ADM); assert.equal(r0.ok, false); assert.match(r0.error, /link not set up.*add-infra-sync\.sh/);
  const wrong = createInfraSync(e.app, { request: fakeInfra(st), readFile: () => 'w'.repeat(32) });
  assert.match((await wrong.run(ADM)).error, /refused the platform credentials/);
  const N = registerInfraSync(e.app.srv, e.app, { request: fakeInfra(st), readFile: () => SECRET, noTimer: true, installed: true });
  assert.match((await N.run(ADM)).error, /2 probes are configured - choose/);
  assert.equal((await e.req('GET', '/infra-sync', { role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/infra-sync', { role: 'operator' })).status, 200);
  assert.equal((await e.req('PUT', '/infra-sync/settings', { role: 'operator', body: { probe_id: 'relay-2' } })).status, 403, 'settings are admin-only');
  assert.match((await e.req('PUT', '/infra-sync/settings', { role: 'admin', body: { probe_id: 'relay 2;' } })).json.error, /probe_id/);
  assert.match((await e.req('PUT', '/infra-sync/settings', { role: 'admin', body: { include: 'all' } })).json.error, /include must be an object/);
  const ok = await e.req('PUT', '/infra-sync/settings', { user: 'syed', role: 'admin', body: { probe_id: 'relay-2', include: { db: false }, bogus: 1 } });
  assert.equal(ok.status, 200); assert.equal(ok.json.settings.probe_id, 'relay-2'); assert.equal(ok.json.settings.include.db, false); assert.equal(ok.json.settings.bogus, undefined);
  const r = await e.req('POST', '/infra-sync/run', { user: 'ali.syn', role: 'operator' });
  assert.equal(r.status, 200); assert.equal(r.json.ok, true, r.json.error); assert.ok(r.json.added.every((x) => x.kind !== 'db'), 'databases switched off');
  assert.ok(st.calls.filter((c) => c[1] === '/api/infra/targets' && c[0] === 'POST').every((c) => c[3].probe_id === 'relay-2'));
});

// an installation without Infrastructure Automation (the Safari platform): no timer, no add-on (so "Sync all now" and asset
// propagation list it as not installed instead of failing every 10 minutes), the page is told plainly; roles still apply;
// installed is detected from the link secret, the service's settings folder or a configured address
test('not installed: nothing runs or fails, the page says it is not part of this installation; detection', () => {
  const { infraInstalled } = require('../engine/infra-sync');
  // a separate tiny server holding only these routes, so the engine's own registration does not interfere
  const routes = []; const srv = { route: (m, p, fn) => routes.push({ m, p, fn }) };
  const app = { config: {}, addons: {} };
  assert.equal(registerInfraSync(srv, app, { exists: () => false }), null);
  assert.equal(app.addons.infraSync, undefined, 'no add-on: Sync all now shows "not installed"');
  const ctx = (role) => ({ need: (r) => { const R = { viewer: 0, operator: 2, admin: 3 }; if (R[role] < R[r]) throw Object.assign(new Error('forbidden'), { status: 403 }); }, who: { user: 'u', role } });
  const get = routes.find((r) => r.m === 'GET').fn, run = routes.find((r) => r.m === 'POST').fn, put = routes.find((r) => r.m === 'PUT').fn;
  const v = get(ctx('operator')); assert.equal(v.installed, false); assert.match(v.note, /not part of this installation/);
  assert.throws(() => get(ctx('viewer')), (x) => x.status === 403, 'a viewer is refused');
  assert.throws(() => run(ctx('operator')), (x) => x.status === 409 && /not part of this installation/.test(x.message));
  assert.throws(() => put(ctx('operator')), (x) => x.status === 403, 'settings stay admin-only');
  assert.throws(() => put(ctx('admin')), (x) => x.status === 409);
  // detection
  assert.equal(infraInstalled({ config: {} }, { exists: () => false }), false);
  assert.equal(infraInstalled({ config: {} }, { exists: (p) => p === '/etc/sentra-itam/infra-proxy-secret' }), true, 'the link secret was copied');
  assert.equal(infraInstalled({ config: {} }, { exists: (p) => p === '/etc/sentra-infra' }), true, 'the service is on this server');
  assert.equal(infraInstalled({ config: { infra: { base_url: 'http://10.0.0.9:9160' } } }, { exists: () => false }), true, 'an address is configured');
  assert.equal(infraInstalled({ config: {} }, { installed: true }), true);
});
