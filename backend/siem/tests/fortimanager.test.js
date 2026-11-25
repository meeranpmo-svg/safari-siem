// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// FortiGate fleet through FortiManager: JSON-RPC normalising, the batched proxy reads, the assessment (offline, drift,
// conserve mode, tunnels, SD-WAN SLA, licences, firmware target / newest, the device's own baseline), the four-eyes changes
// (proposer never approves, a service identity never approves, only install-package runs here and only with the write key),
// the routes (roles and the refused case, validation, write-only keys, audit). Devices, serials, keys are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const M = require('../engine/netops/fmg');

const NOW = Date.parse('2026-11-25T10:00:00Z');
const DEVS = [
  { name: 'FGT-HQ-01', sn: 'FGT60FTK00000001', ip: '10.0.1.1', platform_str: 'FortiGate-60F', os_ver: '7.0', mr: 2, patch: 10, build: 1600, conn_status: 1, conf_status: 1, ha_mode: 1, ha_slave: [{ name: 'FGT-HQ-01', sn: 'FGT60FTK00000001', role: 1, status: 1 }, { name: 'FGT-HQ-01b', sn: 'FGT60FTK00000009', role: 0, status: 0 }], desc: 'HQ' },
  { name: 'FGT-SITE-07', sn: 'FGT40FTK00000007', ip: '10.7.0.1', platform_str: 'FortiGate-40F', os_ver: '7.0', mr: 2, patch: 4, build: 1400, conn_status: 1, conf_status: 2, ha_mode: 0, desc: 'Project site 7' },
  { name: 'FGT-SITE-08', sn: 'FGT40FTK00000008', ip: '10.8.0.1', platform_str: 'FortiGate-40F', os_ver: '7.0', mr: 2, patch: 8, build: 1500, conn_status: 1, conf_status: 1, ha_mode: 0, desc: 'Project site 8' },
  { name: 'FGT-SITE-09', sn: 'FGT40FTK00000010', ip: '10.9.0.1', platform_str: 'FortiGate-40F', os_ver: '7.0', mr: 2, patch: 8, build: 1500, conn_status: 2, conf_status: 1, ha_mode: 0, desc: 'Project site 9' },
];
function fakeFmg({ mem = { 'FGT-HQ-01': 40, 'FGT-SITE-07': 91, 'FGT-SITE-08': 30 } } = {}) {
  const calls = [];
  const res = (data, code = 0) => ({ id: 1, result: [{ status: { code, message: code ? 'synthetic error' : 'OK' }, data }] });
  const transport = async (b, o) => {
    calls.push({ method: b.method, url: b.params[0].url, write: o.write, data: b.params[0].data });
    const u = b.params[0].url;
    if (u === '/sys/status') return res({ Version: 'v7.4.5-build2600', Hostname: 'FMG-SYN' });
    if (u === '/dvmdb/adom') return res([{ name: 'root' }, { name: 'FortiAnalyzer' }, { name: 'Sites' }]);
    if (u === '/dvmdb/adom/root/device') return res(DEVS.slice(0, 1));
    if (u === '/dvmdb/adom/Sites/device') return res(DEVS.slice(1));
    if (u === '/sys/proxy/json') {
      const r = b.params[0].data.resource;
      return res(b.params[0].data.target.map((t) => {
        const n = t.split('/').pop();
        if (r.startsWith('/api/v2/monitor/system/resource')) return { target: t, status: { code: 0 }, response: { results: { cpu: [{ current: 12 }], mem: [{ current: mem[n] }], session: [{ current: 1000 }] } } };
        if (r.startsWith('/api/v2/monitor/vpn/ipsec')) return { target: t, status: { code: 0 }, response: { results: n === 'FGT-HQ-01' ? [{ name: 'to-site7', rgwy: '198.51.100.7', proxyid: [{ status: 'down' }] }, { name: 'to-site8', proxyid: [{ status: 'up' }] }] : [{ name: 'to-hq', proxyid: [{ status: 'up' }] }] } };
        if (r.startsWith('/api/v2/monitor/virtual-wan')) return { target: t, status: { code: 0 }, response: { results: n === 'FGT-SITE-08' ? { 'hc-internet': { wan1: { status: 'up', latency: 180.4, jitter: 20, packet_loss: 6, sla_targets_met: [] }, wan2: { status: 'down' } } } : { 'hc-internet': { wan1: { status: 'up', latency: 12, jitter: 1, packet_loss: 0, sla_targets_met: [1] } } } } };
        if (r.startsWith('/api/v2/monitor/user/device')) return { target: t, status: { code: 0 }, response: { results: n === 'FGT-SITE-07' ? [{ mac: 'AA:BB:CC:00:00:07', ipv4_address: '10.7.0.50', hostname: 'PC-SITE7', os_name: 'Windows', hardware_vendor: 'Dell', detected_interface: 'internal' }, { mac: 'bad' }] : n === 'FGT-SITE-08' ? [{ mac: 'aa:bb:cc:00:00:07', ipv4_address: '10.8.0.50', hostname: 'PC-SITE7', os_name: 'Linux' }] : [] } };
        if (r.startsWith('/api/v2/monitor/license')) return { target: t, status: { code: 0 }, response: { results: { forticare: { status: 'licensed', expires: Math.floor((NOW + (n === 'FGT-SITE-08' ? 10 : 400) * 86400000) / 1000) } } } };
        return { target: t, status: { code: -3, message: 'unknown' } };
      }));
    }
    if (u === '/securityconsole/install/package') return res({ task: 4242 });
    if (u === '/task/task/4242') return res({ percent: 100, num_err: 0, state: 'done' });
    return res(null, -6);
  };
  return { transport, calls };
}
function mk(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fmg-')), state = createState({ dir });
  const config = { fortimanager: Object.assign({ enabled: true, base_url: 'https://fmg.corp.example', firmware_targets: ['FortiGate-60F=7.2.10'] }, extra.cfg || {}) };
  const secrets = { fortimanager: Object.assign({ api_key: 'fmg-read-syn' }, extra.sec || {}) };
  const fk = fakeFmg(extra.fake);
  let t = NOW; const F = M.createFmg({ config, secrets, state, transport: fk.transport, now: () => t });
  return { F, fk, state, config, secrets, setNow: (v) => { t = v; }, dir };
}

test('normalising FortiManager and FortiOS answers', () => {
  const d = M.normDevice(DEVS[0], 'root');
  assert.deepEqual([d.serial, d.model, d.firmware, d.conn, d.conf, d.ha_mode, d.ha_members.length, d.ha_members[1].status], ['FGT60FTK00000001', 'FortiGate-60F', '7.2.10', 'up', 'in-sync', 'a-p', 2, 'down']);
  assert.equal(M.normDevice(DEVS[1], 'Sites').conf, 'modified');
  assert.equal(M.normDevice({ name: 'x', conn_status: 'down', version: 'v7.4.3 build2573' }, 'root').firmware, '7.4.3');
  assert.deepEqual(M.normRes({ results: { cpu: [{ current: 5 }], mem: [{ current: 50 }], session: [{ current: 9 }] } }), { cpu: 5, mem: 50, sessions: 9, setup_rate: null });
  assert.deepEqual(M.normSdwan({ results: { hc: { wan1: { status: 'up', latency: 3, sla_targets_met: [] } } } })[0].sla_ok, false);
  assert.ok(M.verCmp('7.2.10', '7.2.9') > 0 && M.verCmp('7.0.12', '7.2.1') < 0);
  assert.equal(M.robustZ([1, 2, 3], 9), null, 'no baseline before enough history');
  assert.ok(M.robustZ(Array.from({ length: 30 }, (_, i) => 40 + (i % 5)), 90) > 10);
});

test('poll: ADOMs (system ones skipped), devices, batched proxy reads, assessment and fleet KPIs', async () => {
  const { F, fk, state } = mk();
  const s = await F.poll();
  assert.equal(s.devices, 4); assert.equal(s.last_error, '');
  assert.ok(!fk.calls.some((c) => c.url === '/dvmdb/adom/FortiAnalyzer/device'), 'system ADOMs are skipped');
  const prox = fk.calls.filter((c) => c.url === '/sys/proxy/json');
  assert.equal(prox.length, 5, 'one batched proxy call per reading, not one per device'); assert.ok(prox.every((c) => c.data.target.length === 3 && !c.write), 'the offline device is not queried');
  const fl = F.fleet();
  assert.equal(fl.kpis.devices, 4); assert.equal(fl.kpis.down, 1); assert.equal(fl.kpis.out_of_sync, 1); assert.equal(fl.kpis.links_down, 1); assert.equal(fl.kpis.links_out_of_sla, 1); assert.deepEqual(fl.kpis.tunnels, { up: 3, down: 1 });
  const by = Object.fromEntries(fl.devices.map((d) => [d.name, d]));
  const codes = (n) => by[n].findings.map((f) => f.code);
  assert.equal(by['FGT-SITE-09'].health, 'down'); assert.ok(codes('FGT-SITE-09').includes('offline'));
  assert.ok(codes('FGT-SITE-07').includes('drift') && codes('FGT-SITE-07').includes('conserve') && codes('FGT-SITE-07').includes('firmware'), 'site 7: drift, conserve mode, behind the newest 40F build: ' + codes('FGT-SITE-07'));
  assert.ok(codes('FGT-HQ-01').includes('ha') && codes('FGT-HQ-01').includes('vpn') && !codes('FGT-HQ-01').includes('firmware'), 'HQ: HA member down, a tunnel down, on its target: ' + codes('FGT-HQ-01'));
  assert.ok(codes('FGT-SITE-08').includes('link-down') && codes('FGT-SITE-08').includes('link-sla') && codes('FGT-SITE-08').includes('licence'));
  assert.equal(fl.models.find((m) => m.model === 'FortiGate-40F').newest, '7.2.8');
  assert.ok(!('history' in fl.devices[0]), 'the raw history stays on the server');
  assert.equal(F.device('FGT40FTK00000007').name, 'FGT-SITE-07');
  assert.throws(() => F.device('nope'), /not found/);
  const ep = state.collection('fmg_endpoints').get('aa:bb:cc:00:00:07');
  assert.ok(ep && ep.sightings.length === 2 && ep.idents.length === 2, 'one MAC seen on two FortiGates as two identities: ' + JSON.stringify(ep));
  assert.equal(state.collection('fmg_endpoints').size(), 1, 'a malformed MAC is not kept');
});

test('baseline per device: an unusual reading is flagged only against the device\'s own history', async () => {
  const mem = { 'FGT-HQ-01': 40, 'FGT-SITE-07': 30, 'FGT-SITE-08': 30 };
  const { F, setNow } = mk({ fake: { mem } });
  for (let i = 0; i < 30; i++) { mem['FGT-HQ-01'] = 40 + (i % 3); setNow(NOW + i * 600000); await F.poll(); }
  assert.ok(!F.device('FGT-HQ-01').findings.some((f) => f.code === 'unusual-mem'));
  mem['FGT-HQ-01'] = 79; setNow(NOW + 31 * 600000); await F.poll();
  const f = F.device('FGT-HQ-01').findings.find((x) => x.code === 'unusual-mem');
  assert.ok(f && /baseline: 41/.test(f.title), 'flagged with its own baseline: ' + JSON.stringify(F.device('FGT-HQ-01').findings));
});

test('changes: four-eyes, fixed operations, validated names, install runs only with the write key', async () => {
  const { F, fk, config, secrets } = mk();
  await F.poll();
  assert.throws(() => F.propose({ type: 'shell', devices: ['FGT-SITE-07'], reason: 'synthetic reason' }, 'op.syn'), /type/);
  assert.throws(() => F.propose({ type: 'install-package', devices: ['FGT-NOT-THERE'], package: 'sites', reason: 'synthetic reason' }, 'op.syn'), /not managed/);
  assert.throws(() => F.propose({ type: 'install-package', devices: ['FGT-HQ-01', 'FGT-SITE-07'], package: 'sites', reason: 'synthetic reason' }, 'op.syn'), /one ADOM/);
  assert.throws(() => F.propose({ type: 'install-package', devices: ['FGT-SITE-07'], package: 'x;rm -rf', reason: 'synthetic reason' }, 'op.syn'), /package/);
  assert.throws(() => F.propose({ type: 'firmware-upgrade', devices: ['FGT-SITE-07', 'FGT-HQ-01'], version: '7.2.10', reason: 'synthetic reason' }, 'op.syn'), /one model/);
  assert.throws(() => F.propose({ type: 'firmware-upgrade', devices: ['FGT-SITE-08'], version: '7.0.1', reason: 'synthetic reason' }, 'op.syn'), /already runs/);
  assert.throws(() => F.propose({ type: 'install-package', devices: ['FGT-SITE-07'], package: 'sites', reason: 'short' }, 'op.syn'), /reason/);
  const c = F.propose({ type: 'install-package', devices: ['FGT-SITE-07', 'FGT-SITE-08'], package: 'sites-std', reason: 'undo the change made on the device (synthetic)' }, 'op.syn');
  assert.equal(c.id, 'FGCH-000001'); assert.equal(c.adom, 'Sites'); assert.equal(c.executed_here, true);
  await assert.rejects(F.run(c.id, 'op2.syn'), /only once approved/);
  assert.throws(() => F.decide(c.id, 'approved', 'OP.SYN'), /four-eyes/);
  assert.throws(() => F.decide(c.id, 'rejected', 'sec.syn', ''), /comment/);
  F.decide(c.id, 'approved', 'sec.syn', 'ok');
  await assert.rejects(F.run(c.id, 'op.syn'), /switched off/, 'no write key, no run');
  config.fortimanager.write_enabled = true; secrets.fortimanager.write_key = 'fmg-write-syn';
  const r = await F.run(c.id, 'op.syn');
  assert.equal(r.status, 'running'); assert.equal(r.task, 4242);
  const inst = fk.calls.find((x) => x.url === '/securityconsole/install/package');
  assert.equal(inst.write, true, 'the install uses the write key'); assert.deepEqual(inst.data, { adom: 'Sites', pkg: 'sites-std', scope: [{ name: 'FGT-SITE-07', vdom: 'root' }, { name: 'FGT-SITE-08', vdom: 'root' }], flags: ['none'] });
  assert.ok(fk.calls.filter((x) => x.url !== '/securityconsole/install/package').every((x) => !x.write), 'every other call uses the read key');
  assert.equal((await F.refreshTask(c.id)).status, 'done');
  const fw = F.propose({ type: 'firmware-upgrade', devices: ['FGT-SITE-07'], version: '7.2.8', window: '2026-11-28T02:00', reason: 'bring site 7 to the fleet build (synthetic)' }, 'op.syn');
  assert.equal(fw.executed_here, false); assert.deepEqual(fw.from, ['7.2.4']);
  F.decide(fw.id, 'approved', 'sec.syn');
  await assert.rejects(F.run(fw.id, 'op.syn'), /carried out in FortiManager by a person/);
  assert.equal(F.markDone(fw.id, 'op.syn', 'scheduled in FortiManager for the window').status, 'done');
});

test('routes: roles and the refused case, validation, write-only keys, separate write key, audit', async () => {
  const { state, fk } = mk(), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fmgr-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{}'); fs.writeFileSync(secFile, '{}');
  const config = {}; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const R = {}; require('../engine/netops/fmg-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config, state, log: { error() {}, info() {}, warn() {} }, fmgTransport: fk.transport, noTimer: true, now: () => NOW });
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 }, audits = [];
  const call = async (m, p, b, role = 'admin', user) => {
    const o = {}, u = user || role + '.syn', params = {}; const mm = p.match(/^\/fortimanager\/(changes|devices)\/([^/]+)(\/\w+)?$/); let key = '/api/soc' + p; if (mm) { params.id = mm[2]; key = '/api/soc/fortimanager/' + mm[1] + '/:id' + (mm[3] || ''); }
    const ctx = { role, user: u, body: b, params, audit: (a, t, d) => audits.push({ a, t, d, by: u }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const h = R[m + ' ' + key]; assert.ok(h, 'route ' + m + ' ' + key);
    const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  for (const role of ['viewer', 'operator']) { assert.equal((await call('GET', '/fortimanager/settings', undefined, role)).s, 403); assert.equal((await call('PUT', '/fortimanager/settings', {}, role)).s, 403); assert.equal((await call('POST', '/fortimanager/test', {}, role)).s, 403); }
  assert.equal((await call('POST', '/fortimanager/poll', {}, 'viewer')).s, 403);
  let r = await call('PUT', '/fortimanager/settings', { enabled: true }); assert.equal(r.s, 400); assert.match(r.e, /base_url/);
  r = await call('PUT', '/fortimanager/settings', { base_url: 'https://fmg.corp.example/jsonrpc' }); assert.equal(r.s, 400); assert.match(r.e, /base_url/);
  r = await call('PUT', '/fortimanager/settings', { tls_fingerprint: 'AA:BB' }); assert.equal(r.s, 400); assert.match(r.e, /tls_fingerprint/);
  r = await call('PUT', '/fortimanager/settings', { firmware_targets: ['FortiGate-60F 7.2'] }); assert.equal(r.s, 400); assert.match(r.e, /firmware_targets/);
  r = await call('PUT', '/fortimanager/settings', { base_url: 'https://fmg.corp.example', api_key: 'same-key-syn', write_key: 'same-key-syn', write_enabled: true }); assert.equal(r.s, 400); assert.match(r.e, /separate/);
  r = await call('PUT', '/fortimanager/settings', { enabled: true, base_url: 'https://fmg.corp.example', adoms: ['Sites', 'root'], api_key: 'fmg-read-syn', write_key: 'fmg-write-syn', write_enabled: true, firmware_targets: ['FortiGate-40F=7.2.8'], extra: 1 });
  assert.equal(r.s, 200, r.e); assert.equal(r.b.api_key_set, true); assert.equal(r.b.write_key_set, true);
  assert.ok(!JSON.stringify(r.b).includes('fmg-read-syn') && !JSON.stringify(r.b).includes('fmg-write-syn'), 'keys are write-only');
  assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('fmg-') && JSON.parse(fs.readFileSync(secFile, 'utf8')).fortimanager.write_key === 'fmg-write-syn' && !('extra' in JSON.parse(fs.readFileSync(cfgFile, 'utf8')).fortimanager));
  const a = audits.find((x) => x.a === 'netops.fortimanager.config'); assert.ok(a && a.d.api_key_changed && !JSON.stringify(a).includes('fmg-read-syn'));
  assert.equal((await call('POST', '/fortimanager/test', {})).b.ok, true);
  assert.equal((await call('POST', '/fortimanager/poll', {}, 'operator')).b.devices, 4);
  assert.equal((await call('GET', '/fortimanager/fleet', undefined, 'viewer')).b.kpis.devices, 4);
  assert.equal((await call('GET', '/fortimanager/devices/FGT-SITE-07', undefined, 'viewer')).b.serial, 'FGT40FTK00000007');
  // changes: viewer cannot propose; the proposer cannot approve; an AI identity never approves; another person approves
  assert.equal((await call('POST', '/fortimanager/changes', { type: 'install-package', devices: ['FGT-SITE-07'], package: 'sites', reason: 'synthetic reason here' }, 'viewer')).s, 403);
  r = await call('POST', '/fortimanager/changes', { type: 'install-package', devices: ['FGT-SITE-07'], package: 'sites', reason: 'synthetic reason here' }, 'operator', 'op.syn'); assert.equal(r.s, 200, r.e);
  const cid = r.b.id;
  assert.equal((await call('POST', `/fortimanager/changes/${cid}/decide`, { decision: 'approved' }, 'admin', 'op.syn')).s, 403);
  r = await call('POST', `/fortimanager/changes/${cid}/decide`, { decision: 'approved' }, 'admin', 'ai:network'); assert.equal(r.s, 403); assert.match(r.e, /only a person/);
  assert.equal((await call('POST', `/fortimanager/changes/${cid}/decide`, { decision: 'approved' }, 'operator', 'op2.syn')).s, 403, 'an operator without the firewall approver scope');
  assert.equal((await call('POST', `/fortimanager/changes/${cid}/decide`, { decision: 'maybe' }, 'admin', 'sec.syn')).s, 400);
  assert.equal((await call('POST', `/fortimanager/changes/${cid}/decide`, { decision: 'approved' }, 'admin', 'sec.syn')).s, 200);
  r = await call('POST', `/fortimanager/changes/${cid}/run`, {}, 'operator', 'op.syn'); assert.equal(r.s, 200, r.e); assert.equal(r.b.status, 'running');
  assert.equal((await call('POST', `/fortimanager/changes/${cid}/refresh`, {}, 'operator')).b.status, 'done');
  assert.equal((await call('POST', '/fortimanager/changes/bad id!/run', {}, 'operator')).s, 400);
  for (const act of ['netops.fortimanager.change.propose', 'netops.fortimanager.change.approve', 'netops.fortimanager.change.run', 'netops.fortimanager.change.result']) assert.ok(audits.some((x) => x.a === act && x.t === cid), 'audited: ' + act);
});

test('standalone FortiGates (not in FortiManager, reached by DDNS): settings, pin required, poll, FortiManager-only changes refused', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fgd-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{}'); fs.writeFileSync(secFile, '{}');
  const state = createState({ dir: path.join(dir, 'st') }), config = {}; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const seen = [];
  const fortigateTransport = async (d, p, key) => { seen.push([d.host, p, key]); if (key !== 'fg-key-syn') throw new Error('the FortiGate refused the API key (HTTP 401)');
    if (p.startsWith('/api/v2/monitor/system/status')) return { serial: 'FGT40FTK00000077', version: 'v7.2.6', build: 1575, results: { hostname: 'SITE-77', model_name: 'FortiGate', model_number: '40F' } };
    if (p.startsWith('/api/v2/monitor/system/resource')) return { results: { cpu: [{ current: 7 }], mem: [{ current: 92 }], session: [{ current: 300 }] } };
    if (p.startsWith('/api/v2/monitor/vpn/ipsec')) return { results: [{ name: 'to-hq', proxyid: [{ status: 'down' }] }] };
    if (p.startsWith('/api/v2/monitor/virtual-wan')) return { results: {} };
    if (p.startsWith('/api/v2/monitor/license')) return { results: {} };
    return { results: [] }; };
  const R = {}, audits = [], RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  require('../engine/netops/fmg-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config, state, log: { error() {}, info() {}, warn() {} }, fortigateTransport, noTimer: true, now: () => NOW });
  const call = async (m, p, b, role = 'admin', user) => {
    const o = {}, u = user || role + '.syn', params = {}; let key = '/api/soc' + p; const mm = p.match(/^\/fortimanager\/direct\/([^/]+)(\/remove)?$/); if (mm) { params.name = mm[1]; key = '/api/soc/fortimanager/direct/:name' + (mm[2] || ''); }
    const mc = p.match(/^\/fortimanager\/changes$/); if (mc) key = '/api/soc/fortimanager/changes';
    const ctx = { role, user: u, body: b, params, audit: (a, t, d) => audits.push({ a, t, d }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' ' + key](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  const FPX = Array.from({ length: 32 }, () => 'AB').join(':');
  assert.equal((await call('PUT', '/fortimanager/direct/SITE-77', { host: 'site77.ddns.example', tls_fingerprint: FPX, api_key: 'fg-key-syn' }, 'operator')).s, 403);
  let r = await call('PUT', '/fortimanager/direct/SITE-77', { host: 'https://site77.ddns.example/x', tls_fingerprint: FPX, api_key: 'fg-key-syn' }); assert.equal(r.s, 400); assert.match(r.e, /host/);
  r = await call('PUT', '/fortimanager/direct/SITE-77', { host: 'site77.ddns.example', api_key: 'fg-key-syn' }); assert.equal(r.s, 400); assert.match(r.e, /tls_fingerprint/);
  r = await call('PUT', '/fortimanager/direct/SITE-77', { host: 'site77.ddns.example', tls_fingerprint: FPX }); assert.equal(r.s, 400); assert.match(r.e, /api_key/);
  r = await call('PUT', '/fortimanager/direct/SITE-77', { host: 'Site77.DDNS.example', port: 10443, site: 'Project site 77', tls_fingerprint: FPX.toLowerCase(), api_key: 'fg-key-syn' }); assert.equal(r.s, 200, r.e);
  assert.ok(r.b.devices[0].api_key_set && !JSON.stringify(r.b).includes('fg-key-syn') && r.b.devices[0].host === 'site77.ddns.example');
  assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('fg-key-syn') && JSON.parse(fs.readFileSync(secFile, 'utf8')).fortimanager.direct['SITE-77'] === 'fg-key-syn');
  r = await call('POST', '/fortimanager/poll', {}, 'operator'); assert.equal(r.s, 200, r.e); assert.equal(r.b.devices, 1); assert.equal(r.b.standalone, 1);
  assert.ok(seen.every((x) => x[0] === 'site77.ddns.example' && x[2] === 'fg-key-syn'), 'read by the DDNS name with its own key');
  const fl = (await call('GET', '/fortimanager/fleet', undefined, 'viewer')).b, d = fl.devices[0];
  assert.deepEqual([d.name, d.via, d.model, d.firmware, d.conf, d.site], ['SITE-77', 'direct', 'FortiGate-40F', '7.2.6', 'not managed', 'Project site 77']);
  assert.ok(d.findings.some((f) => f.code === 'conserve') && d.findings.some((f) => f.code === 'vpn') && !d.findings.some((f) => f.code === 'drift'));
  r = await call('POST', '/fortimanager/changes', { type: 'install-package', devices: ['SITE-77'], package: 'std', reason: 'synthetic reason text' }, 'operator'); assert.equal(r.s, 400); assert.match(r.e, /standalone/);
  r = await call('POST', '/fortimanager/changes', { type: 'firmware-upgrade', devices: ['SITE-77'], version: '7.2.10', reason: 'synthetic reason text' }, 'operator'); assert.equal(r.s, 200, r.e);
  assert.equal((await call('POST', '/fortimanager/direct/SITE-77/remove', {})).s, 200);
  assert.ok(audits.some((a) => a.a === 'netops.fortigate.direct.save' && a.d.api_key_changed) && audits.some((a) => a.a === 'netops.fortigate.direct.remove'));
});
