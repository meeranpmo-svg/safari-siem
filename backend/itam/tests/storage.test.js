// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Storage: NetApp ONTAP and HPE MSA read-only clients (mock arrays), the read-only guard, findings (capacity, failed disks,
// controllers, health, events), inventory link, sealed credentials never returned.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const S = require('../engine/storage-sources');
const { createStorage } = require('../engine/storage');

const NOW = Date.parse('2026-10-13T12:00:00Z');
function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id),
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })()) };
}
const TB = 1e12;
function ontapFake(calls) {
  return async (url, o) => {
    calls.push([o.method, url, o.headers.Authorization]);
    if (o.headers.Authorization !== 'Basic ' + Buffer.from('monitor:Pw-1').toString('base64')) return { status: 401, json: {} };
    const p = new URL(url).pathname;
    const J = (x) => ({ status: 200, json: x });
    if (p === '/api/cluster') return J({ name: 'NTAP-HQ', version: { full: 'NetApp Release 9.13.1P5' } });
    if (p === '/api/cluster/nodes') return J({ records: [{ name: 'NTAP-HQ-01', model: 'AFF-A250', serial_number: '9520001', state: 'up' }, { name: 'NTAP-HQ-02', model: 'AFF-A250', serial_number: '9520002', state: 'down' }] });
    if (p === '/api/storage/aggregates') return J({ records: [{ name: 'aggr1', state: 'online', node: { name: 'NTAP-HQ-01' }, space: { block_storage: { size: 10 * TB, used: 9.7 * TB, available: 0.3 * TB } } }, { name: 'aggr2', state: 'online', space: { block_storage: { size: 10 * TB, used: 5 * TB, available: 5 * TB } } }] });
    if (p === '/api/storage/volumes') return J({ records: [{ name: 'vol_sql', svm: { name: 'svm1' }, state: 'online', space: { size: 1e12, used: 0.95e12 } }, { name: 'vol_fs', svm: { name: 'svm1' }, state: 'online', space: { size: 2e12, used: 0.5e12 } }] });
    if (p === '/api/storage/disks') return J({ records: [{ name: '1.0.1', state: 'present', container_type: 'aggregate' }, { name: '1.0.7', state: 'broken', container_type: 'broken', model: 'X371', serial_number: 'S3X' }, { name: '1.0.9', state: 'spare', container_type: 'spare' }] });
    if (p === '/api/support/ems/events') return J({ records: [{ time: '2026-10-13T09:00:00Z', log_message: 'disk.failed: disk 1.0.7 failed', message: { severity: 'error' }, node: { name: 'NTAP-HQ-01' } }] });
    return { status: 404, json: {} };
  };
}
function msaFake(calls, { basic = true, md5 = false } = {}) {
  const key = 'abcdef0123456789';
  const hash = crypto.createHash(md5 ? 'md5' : 'sha256').update('mon_Pw-2').digest('hex');
  return async (url, o) => {
    calls.push([o.method, new URL(url).pathname, o.headers.sessionKey || '', o.headers.datatype]);
    const p = new URL(url).pathname;
    const J = (x) => ({ status: 200, json: x });
    if (p === '/api/login') return basic && o.headers.Authorization === 'Basic ' + Buffer.from('mon:Pw-2').toString('base64') ? J({ status: [{ response: key, 'return-code': 1 }] }) : { status: 401, json: {} };
    if (p === '/api/login/' + hash) return J({ status: [{ response: key, 'return-code': 1 }] });
    if (/^\/api\/login\//.test(p)) return J({ status: [{ response: 'Authentication Unsuccessful', 'return-code': 2 }] });
    if (o.headers.sessionKey !== key) return J({ status: [{ response: 'Invalid sessionkey', 'return-code': -10027 }] });
    if (p === '/api/show/system') return J({ system: [{ 'system-name': 'MSA-DR', 'product-id': 'MSA 2060 SAN', 'midplane-serial-number': 'MXQ123', health: 'Degraded' }] });
    if (p === '/api/show/controllers') return J({ controllers: [{ 'controller-id': 'A', status: 'Operational', health: 'OK', 'serial-number': 'CA1', 'sc-fw': 'IN110R004' }, { 'controller-id': 'B', status: 'Operational', health: 'OK' }] });
    if (p === '/api/show/pools') return J({ pools: [{ name: 'A', health: 'OK', 'total-size-numeric': String(2 * TB / 512), 'total-avail-numeric': String(0.2 * TB / 512) }] });
    if (p === '/api/show/disks') return J({ drives: [{ location: '0.1', health: 'OK', usage: 'VIRTUAL POOL' }, { location: '0.5', health: 'Fault', usage: 'FAILED', 'serial-number': 'ZZ9', model: 'ST1200' }, { location: '0.12', health: 'OK', usage: 'GLOBAL SPARE' }] });
    if (p === '/api/show/volumes') return J({ volumes: [{ 'volume-name': 'esx-ds1', 'storage-pool-name': 'A', health: 'OK', 'size-numeric': String(1 * TB / 512), 'allocated-size-numeric': String(0.5 * TB / 512) }] });
    if (p === '/api/show/events/last/50') return J({ events: [{ 'time-stamp': '2026-10-13 10:00:00', severity: 'CRITICAL', message: 'Disk 0.5 failed' }, { 'time-stamp': '2026-10-13 10:01:00', severity: 'INFORMATIONAL', message: 'ok' }] });
    if (p === '/api/exit') return J({ status: [{ 'return-code': 1 }] });
    return { status: 404, json: {} };
  };
}

test('ONTAP: Basic auth, GET only, cluster / nodes / aggregates / volumes / disks / EMS events normalised', async () => {
  const calls = [];
  const r = await S.ontap({ target: { base_url: 'https://ntap-hq.corp.local' }, secret: { username: 'monitor', password: 'Pw-1' } }, { request: ontapFake(calls) });
  assert.equal(r.ok, true, r.error);
  assert.ok(calls.every((c) => c[0] === 'GET' && c[1].startsWith('https://ntap-hq.corp.local/api/')));
  assert.deepEqual([r.system.name, r.system.model, r.system.version, r.system.health], ['NTAP-HQ', 'AFF-A250', 'NetApp Release 9.13.1P5', 'degraded']);
  assert.equal(r.pools[0].used_pct, 97); assert.equal(r.volumes[0].used_pct, 95);
  assert.deepEqual([r.disks.total, r.disks.spares, r.disks.failed.length, r.disks.failed[0].name], [3, 1, 1, '1.0.7']);
  assert.equal(r.events[0].severity, 'error');
  const bad = await S.ontap({ target: { base_url: 'https://ntap-hq.corp.local' }, secret: { username: 'monitor', password: 'wrong' } }, { request: ontapFake([]) });
  assert.equal(bad.ok, false); assert.equal(bad.error_class, 'auth');
  assert.match(bad.error, /security login show/, 'the 401 says what to check on the cluster');
});

test('MSA 2040 / P2000 G3: MD5 sign-in after Basic and SHA-256 are refused', async () => {
  const calls = [];
  const r = await S.msa({ target: { base_url: 'https://10.1.9.21' }, secret: { username: 'mon', password: 'Pw-2' } }, { request: msaFake(calls, { basic: false, md5: true }) });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(calls.slice(0, 3).map((c) => c[1].replace(/[0-9a-f]{64}$/, '<sha256>').replace(/[0-9a-f]{32}$/, '<md5>')), ['/api/login', '/api/login/<sha256>', '/api/login/<md5>']);
  const bad = await S.msa({ target: { base_url: 'https://10.1.9.21' }, secret: { username: 'mon', password: 'nope' } }, { request: msaFake([], { basic: false, md5: true }) });
  assert.equal(bad.ok, false); assert.equal(bad.error_class, 'auth');
});

test('MSA 2060: Basic login, older firmware SHA-256 login, sessionKey + datatype json, sizes from 512-byte blocks, logout', async () => {
  for (const basic of [true, false]) {
    const calls = [];
    const r = await S.msa({ target: { base_url: 'https://10.1.9.20' }, secret: { username: 'mon', password: 'Pw-2' } }, { request: msaFake(calls, { basic }) });
    assert.equal(r.ok, true, r.error);
    assert.ok(calls.every((c) => c[0] === 'GET' && c[3] === 'json'));
    if (!basic) assert.match(calls[1][1], /^\/api\/login\/[0-9a-f]{64}$/);
    assert.equal(calls[calls.length - 1][1], '/api/exit', 'session closed');
    assert.deepEqual([r.system.name, r.system.model, r.system.serial, r.system.health], ['MSA-DR', 'MSA 2060 SAN', 'MXQ123', 'degraded']);
    assert.equal(r.pools[0].used_pct, 90); assert.equal(r.pools[0].size_bytes, 2 * TB);
    assert.equal(r.volumes[0].used_pct, 50);
    assert.deepEqual([r.disks.total, r.disks.spares, r.disks.failed[0].name], [3, 1, '0.5']);
    assert.deepEqual(r.events.map((e) => e.severity), ['critical']);
  }
});

test('read-only guard refuses anything but the listed GETs', () => {
  assert.throws(() => S.guard('ontap', 'PATCH', '/api/storage/volumes/x'), /read-only/);
  assert.throws(() => S.guard('ontap', 'GET', '/api/private/cli/system'), /read-only/);
  assert.throws(() => S.guard('msa', 'GET', '/api/delete/volumes/x'), /read-only/);
  assert.throws(() => S.guard('msa', 'GET', '/api/set/user'), /read-only/);
  assert.doesNotThrow(() => S.guard('msa', 'GET', '/api/show/pools'));
});

test('storage module: sealed credentials, findings, inventory link, settings', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'itam-stor-'));
  const st = fakeStore({ assets: [{ id: 'A1', name: 'NTAP-HQ', type: 'storage', status: 'in_use', serial: '9520001' }] });
  const sources = { baseOf: S.baseOf, ontap: (c, o) => S.ontap(c, Object.assign({ request: ontapFake([]) }, o)), msa: (c, o) => S.msa(c, Object.assign({ request: msaFake([]) }, o)), test: async () => ({ ok: true, message: 'ok' }) };
  const M = createStorage({ store: st, config: { discovery: { vault_key_file: path.join(dir, 'k') } } }, { sources, now: () => NOW });
  const adm = { user: 'admin1', role: 'admin', ip: '' };
  assert.throws(() => M.save({ kind: 'ontap', base_url: 'https://ntap-hq.corp.local' }, adm), /read-only \(monitor\) account/);
  assert.throws(() => M.save({ kind: 'emc', base_url: 'https://x' }, adm), /ontap, msa or synology/);
  const a = M.save({ kind: 'ontap', label: 'NetApp HQ', base_url: 'https://ntap-hq.corp.local', username: 'monitor', password: 'Pw-1' }, adm).platform;
  const b = M.save({ kind: 'msa', label: 'MSA DR', base_url: 'https://10.1.9.20', username: 'mon', password: 'Pw-2' }, adm).platform;
  assert.ok(!JSON.stringify(M.view()).includes('Pw-1') && !JSON.stringify(st.collection('storage_platforms').all()).includes('Pw-1'), 'password sealed, never returned');
  assert.equal((await M.sync(a.id, adm)).ok, true); assert.equal((await M.sync(b.id, adm)).ok, true);
  const v = M.view();
  const kinds = v.findings.map((f) => `${f.array}:${f.kind}:${f.severity}`);
  for (const k of ['NetApp HQ:disk:critical', 'NetApp HQ:capacity:critical', 'NetApp HQ:controller:high', 'NetApp HQ:volume:medium', 'MSA DR:disk:critical', 'MSA DR:capacity:medium', 'MSA DR:health:high', 'MSA DR:events:medium', 'MSA DR:inventory:low']) assert.ok(kinds.includes(k), 'missing ' + k + ' in ' + kinds.join(', '));
  assert.ok(!kinds.includes('NetApp HQ:inventory:low'), 'linked by serial');
  assert.equal(v.arrays.find((x) => x.platform.id === a.id).asset.id, 'A1');
  assert.equal(v.summary.failed_disks, 2); assert.equal(v.summary.not_in_inventory, 1);
  assert.equal(v.findings[0].severity, 'critical');
  assert.equal(M.detail(a.id).data.volumes.length, 2);
  M.putSettings({ pool_warn_pct: 80, pool_crit_pct: 99 }, adm);
  assert.ok(M.view().findings.some((f) => f.array === 'NetApp HQ' && f.kind === 'capacity' && f.severity === 'medium'));
  assert.throws(() => M.putSettings({ pool_warn_pct: 99, pool_crit_pct: 90 }, adm), /below/);
  const fail = await createStorage({ store: st, config: { discovery: { vault_key_file: path.join(dir, 'k') } } }, { sources: Object.assign({}, sources, { msa: async () => ({ ok: false, error_class: 'auth', error: 'MSA: sign-in refused' }) }), now: () => NOW }).sync(b.id, adm);
  assert.equal(fail.ok, false); assert.match(fail.error, /^auth:/);
});

test('Synology SA3600: POST form sign-in (no password in the URL), system + storage, health, logout, read-only allow-list, DSM errors', async () => {
  const GB = 1e9, calls = [];
  const fake = (mode = 'ok') => async (url, o) => {
    const u = new URL(url), f = Object.fromEntries(new URLSearchParams(o.body || ''));
    calls.push({ path: u.pathname, search: u.search, method: o.method, api: f.api, m: f.method, sid: f._sid || '' });
    const J = (x) => ({ status: 200, json: x });
    if (f.api === 'SYNO.API.Auth' && f.method === 'login') return mode === '2fa' ? J({ success: false, error: { code: 403 } }) : f.account === 'zyb-mon' && f.passwd === 'S3cret!' ? J({ success: true, data: { sid: 'SID1' } }) : J({ success: false, error: { code: 400 } });
    if (f._sid !== 'SID1') return J({ success: false, error: { code: 119 } });
    if (f.api === 'SYNO.API.Auth' && f.method === 'logout') return J({ success: true });
    if (f.api === 'SYNO.Core.System') return J({ success: true, data: { model: 'SA3600', serial: '2150SBRXX1', firmware_ver: 'DSM 7.2.1-69057', hostname: 'NAS-HQ', up_time: '12:03:44', temperature_warn: false } });
    if (f.api === 'SYNO.Storage.CGI.Storage') return mode === 'noadmin' ? J({ success: false, error: { code: 105 } }) : J({ success: true, data: {
      storagePools: [{ id: 'reuse_1', desc: 'Pool 1', status: 'degraded', raidType: 'RAID 6', size: { total: String(100 * GB), used: String(80 * GB) } }],
      volumes: [{ id: 'volume_1', display_name: 'Volume 1', vol_path: '/volume1', pool_path: 'reuse_1', status: 'normal', fs_type: 'btrfs', size: { total: String(90 * GB), used: String(45 * GB) } }],
      disks: [{ id: 'sata1', name: 'Drive 1', status: 'normal', model: 'HAT5300', serial: 'A1' }, { id: 'sata2', name: 'Drive 2', status: 'crashed', model: 'HAT5300', serial: 'A2', longName: 'Drive 2 (SA3600)' }],
      hotSpares: [{ id: 'sata12' }] } });
    return J({ success: false, error: { code: 102 } });
  };
  const cred = { target: { base_url: 'https://10.1.9.30:5001' }, secret: { username: 'zyb-mon', password: 'S3cret!' } };
  const r = await S.synology(cred, { request: fake() });
  assert.equal(r.ok, true, r.error);
  assert.ok(calls.every((c) => c.path === '/webapi/entry.cgi' && c.method === 'POST' && !/S3cret/.test(c.search)), 'POST form only, password never in the URL');
  assert.deepEqual(calls.map((c) => c.api + '.' + c.m), ['SYNO.API.Auth.login', 'SYNO.Core.System.info', 'SYNO.Storage.CGI.Storage.load_info', 'SYNO.API.Auth.logout']);
  assert.deepEqual([r.system.model, r.system.serial, r.system.name, r.system.health], ['SA3600', '2150SBRXX1', 'NAS-HQ', 'fault']);
  assert.deepEqual([r.pools[0].name, r.pools[0].health, r.pools[0].used_pct, r.pools[0].owner], ['Pool 1', 'degraded', 80, 'RAID 6']);
  assert.deepEqual([r.volumes[0].name, r.volumes[0].state, r.volumes[0].used_pct], ['Volume 1', 'online', 50]);
  assert.deepEqual([r.disks.total, r.disks.spares, r.disks.failed.length, r.disks.failed[0].name, r.disks.failed[0].location], [2, 1, 1, 'Drive 2', 'Drive 2 (SA3600)']);
  // errors say what to do
  const w = await S.synology({ target: cred.target, secret: { username: 'zyb-mon', password: 'x' } }, { request: fake() });
  assert.equal(w.error_class, 'auth'); assert.match(w.error, /wrong user name or password/);
  const tfa = await S.synology(cred, { request: fake('2fa') });
  assert.equal(tfa.error_class, 'auth'); assert.match(tfa.error, /two-factor/);
  const na = await S.synology(cred, { request: fake('noadmin') });
  assert.equal(na.error_class, 'authz'); assert.match(na.error, /administrators group/);
  // the allow-list: only sign-in, system info and storage info - nothing that changes DSM
  assert.deepEqual(S.SYN_ALLOW, { 'SYNO.API.Auth': ['login', 'logout'], 'SYNO.Core.System': ['info'], 'SYNO.Storage.CGI.Storage': ['load_info'] });
  const t = await S.test('synology', cred, { request: fake() });
  assert.equal(t.ok, true); assert.match(t.message, /Connected: NAS-HQ - 1 pool\(s\), 1 volume\(s\), 2 disk\(s\)/);
});

test('Synology through the Python bridge falls back to Node.js (collect and test)', async () => {
  const { createStorageSourcesPy } = require('../engine/storage-sources-py');
  const P = createStorageSourcesPy({ python: '/nonexistent/python3' });
  assert.equal(typeof P.synology, 'function');
  const r = await P.synology({ target: { base_url: 'https://10.1.9.30:5001' }, secret: {} }, {});
  assert.equal(r.ok, false); assert.equal(r.error_class, 'config'); assert.equal(r.engine, 'node');
});
