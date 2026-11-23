// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Switch port map (engine/netops/portmap.js): parsers for the read-only show commands, one SSH session per read, endpoints
// (MAC, IP from ARP, Genian NAC state, OUI vendor, randomised address), endpoint type by rules then naive Bayes on people's
// confirmations, findings (err-disabled, half duplex, unmanaged switch, switch on an access port, PoE budget, NAC, errors,
// description, unused, MAC flapping, device swapped), capacity forecast, "where is it plugged in", proposals as four-eyes
// tasks (a trunk is never shut), thresholds admin-only and validated, viewers see no MAC / IP / host names, roles and audit.
// SYNTHETIC switch and endpoints.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const PM = require('../engine/netops/portmap');

const row = (a, b, c, d, e, f, g) => a.padEnd(10) + b.padEnd(19) + c.padEnd(13) + d.padEnd(11) + e.padEnd(8) + f.padEnd(7) + g;
const STATUS = [row('Port', 'Name', 'Status', 'Vlan', 'Duplex', 'Speed', 'Type'),
  row('Gi1/0/1', 'PC-FIN-01', 'connected', '10', 'a-full', 'a-1000', '10/100/1000BaseTX'),
  row('Gi1/0/2', 'Phone desk 12', 'connected', '10', 'a-full', 'a-1000', '10/100/1000BaseTX'),
  row('Gi1/0/3', '', 'connected', '10', 'a-half', 'a-100', '10/100/1000BaseTX'),
  row('Gi1/0/4', 'Meeting room', 'connected', '10', 'a-full', 'a-1000', '10/100/1000BaseTX'),
  row('Gi1/0/5', '', 'err-disabled', '10', 'auto', 'auto', '10/100/1000BaseTX'),
  row('Gi1/0/6', '', 'notconnect', '10', 'auto', 'auto', '10/100/1000BaseTX'),
  row('Gi1/0/7', 'Printer-2F', 'connected', '20', 'a-full', 'a-1000', '10/100/1000BaseTX'),
  row('Gi1/0/8', 'old-ap', 'connected', '10', 'a-full', 'a-1000', '10/100/1000BaseTX'),
  row('Te1/1/1', 'Uplink CORE-SYN', 'connected', 'trunk', 'full', '10G', 'SFP-10GBase-SR')].join('\n');
const mac = (v, m, p) => '  ' + String(v).padEnd(6) + m + '    DYNAMIC     ' + p;
let MACS = ['          Mac Address Table', '-------------------------------------------', 'Vlan    Mac Address       Type        Ports', '----    -----------       --------    -----',
  ' All    0100.0ccc.cccc    STATIC      CPU', mac(10, '3c52.82aa.0001', 'Gi1/0/1'), mac(10, '0011.2233.4455', 'Gi1/0/2'), mac(10, '3c52.82aa.0002', 'Gi1/0/2'), mac(10, '3c52.82aa.0003', 'Gi1/0/3'),
  mac(10, '3c52.82aa.0101', 'Gi1/0/4'), mac(10, '3c52.82aa.0102', 'Gi1/0/4'), mac(10, '3c52.82aa.0103', 'Gi1/0/4'), mac(10, '3c52.82aa.0104', 'Gi1/0/4'), mac(10, '3e52.82aa.0105', 'Gi1/0/4'),
  mac(20, '0026.73bb.0007', 'Gi1/0/7'), mac(10, '00aa.bbcc.0008', 'Gi1/0/8'), mac(10, 'aaaa.0000.0001', 'Te1/1/1'), mac(10, 'aaaa.0000.0002', 'Te1/1/1'), mac(10, 'aaaa.0000.0003', 'Te1/1/1'), mac(10, 'aaaa.0000.0004', 'Te1/1/1')];
const CDP = `-------------------------
Device ID: SEP001122334455
Entry address(es):
  IP address: 10.20.0.5
Platform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): Port 1
Holdtime : 150 sec

Version :
SIP88xx.14-1-1

-------------------------
Device ID: SW-HIDDEN.as.local
Entry address(es):
  IP address: 10.0.9.9
Platform: cisco WS-C2960-8TC-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/8,  Port ID (outgoing port): GigabitEthernet0/1
-------------------------
Device ID: CORE-SYN.as.local
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco C9500-24Y4C,  Capabilities: Router Switch IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TwentyFiveGigE1/0/24
`;
const POE = `Module   Available     Used     Remaining
          (Watts)     (Watts)    (Watts)
------   ---------   --------   ---------
1          100.0        90.0        10.0
Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/2   auto   on         6.3     IP Phone 8845       2     30.0
Gi1/0/6   auto   off        0.0     n/a                 n/a   30.0`;
const TRUNK = 'Port        Mode             Encapsulation  Status        Native vlan\nTe1/1/1     on               802.1q         trunking      1\n\nPort        Vlans allowed on trunk\nTe1/1/1     1-4094';
const ARP = 'Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.10.0.21              3   3c52.82aa.0001  ARPA   Vlan10';
const VLANS = 'VLAN Name                             Status    Ports\n---- -------------------------------- --------- -----\n1    default                          active\n10   USERS                            active    Gi1/0/1\n20   PRINTERS                         active    Gi1/0/7';
function out(c) {
  return { 'show interfaces status': STATUS, 'show mac address-table': MACS.join('\n'), 'show cdp neighbors detail': CDP, 'show lldp neighbors detail': '% LLDP is not enabled', 'show power inline': POE, 'show interfaces trunk': TRUNK, 'show ip arp': ARP, 'show vlan brief': VLANS }[c] || '';
}
function fakeRunner() {
  const calls = [];
  const fn = async (req) => { calls.push(req.op === 'run' ? { op: 'run', commands: req.commands } : { op: req.op });
    if (req.op === 'version') return { ok: true, netmiko: '4.8.0', paramiko: '5.0.0', python: '3.11' };
    if (req.op === 'hostkey') return { ok: true, type: 'ssh-rsa', key: 'AAAAKEY1', fingerprint: 'SHA256:abc' };
    if (req.op === 'run') return { ok: true, prompt: 'ACC-SYN#', results: req.commands.map((c) => ({ command: c, output: out(c) })) };
    return { ok: false, kind: 'input', error: 'bad op' }; };
  fn.calls = calls; return fn;
}
async function setup(sdk) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-pm-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const ouiFile = path.join(dir, 'oui.csv');
  fs.writeFileSync(ouiFile, 'Registry,Assignment,Organization Name,Organization Address\nMA-L,3C5282,"Synthetic HP Inc.",x\nMA-L,002673,RICOH COMPANY (synthetic),y\n');
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, portmap: { oui_file: ouiFile } } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = {}; let clock = Date.parse('2026-10-31T07:00:00Z');
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const runner = fakeRunner();
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, cliRunner: runner, now: () => clock, anthropicSdk: sdk });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, params = {}, query = {} } = {}) {
    const o = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { o.status = c; o.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.status) { o.status = 200; o.body = rv; } return o;
  }
  // a synthetic access switch with a read-only login and a trusted host key, and Genian NAC
  N.inventory.put({ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  N.inventory.put({ id: 'nac', name: 'GENIAN-SYN', vendor: 'genian', ip: '10.0.5.9', role: 'nac' }, 'test');
  assert.equal((await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'acc-syn' }, body: { ssh: { username: 'ro', password: 'Pw-ro-123' } } })).status, 200);
  await call('POST', '/devices/:id/ssh/hostkey', { role: 'admin', params: { id: 'acc-syn' } });
  assert.equal((await call('POST', '/devices/:id/ssh/trust', { role: 'admin', user: 'syed', params: { id: 'acc-syn' }, body: { fingerprint: 'SHA256:abc' } })).status, 200);
  snaps['acc-syn'] = { at: clock, ok: true, interfaces: [{ name: 'GigabitEthernet1/0/3', oper: 'up', util_in: 4, util_out: 2, err_per_min: 42 }] };
  snaps.nac = { at: clock, ok: true, nac: { items: [{ mac: '3C:52:82:AA:00:03', ip: '10.10.0.33', host: 'LT-GUEST', status: 'unauthorized' }, { mac: '3c52.82aa.0001', ip: '10.10.0.21', host: 'PC-FIN-01', status: 'authorized' }] } };
  return { N, call, audits, runner, state, snaps, at: (t) => { clock = t; }, now: () => clock };
}
const allPorts = (m) => [].concat(...m.members.map((x) => x.ports), m.other);
const portOf = (m, p) => allPorts(m).find((x) => x.port === p);

test('parsers: interface names, status columns, MAC table (CPU skipped), CDP, PoE, trunk, ARP, VLANs; forecast', () => {
  assert.equal(PM.shortIf('GigabitEthernet1/0/12'), 'Gi1/0/12'); assert.equal(PM.shortIf('TwentyFiveGigE1/0/1'), 'Twe1/0/1'); assert.equal(PM.longIf('Te1/1/1'), 'TenGigabitEthernet1/1/1');
  assert.deepEqual(PM.slot('Gi2/0/7'), { prefix: 'Gi', member: 2, module: 0, index: 7 });
  const st = PM.parseStatus(STATUS); assert.equal(st.length, 9); assert.deepEqual([st[2].status, st[2].duplex, st[4].status, st[8].vlan], ['connected', 'a-half', 'err-disabled', 'trunk']); assert.equal(st[1].name, 'Phone desk 12');
  const mt = PM.parseMac(MACS.join('\n')); assert.ok(!mt.some((x) => /cpu/i.test(x.port))); assert.equal(mt.filter((x) => x.port === 'Gi1/0/4').length, 5);
  const cdp = PM.parseCdp(CDP); assert.equal(cdp.length, 3); assert.deepEqual([cdp[0].local, cdp[0].ip, cdp[0].caps.includes('Phone')], ['Gi1/0/2', '10.20.0.5', true]); assert.equal(cdp[2].local, 'Te1/1/1');
  const poe = PM.parsePoe(POE); assert.deepEqual(poe.modules[0], { module: 1, available: 100, used: 90 }); assert.equal(poe.ports['gi1/0/2'].watts, 6.3);
  assert.ok(PM.parseTrunk(TRUNK).has('te1/1/1')); assert.deepEqual(PM.parseArp(ARP)[0], { ip: '10.10.0.21', mac: '3c5282aa0001' }); assert.equal(PM.parseVlans(VLANS)['20'], 'PRINTERS');
  const d0 = Date.parse('2026-10-01T00:00:00Z'), f = PM.forecast(Array.from({ length: 10 }, (_, i) => ({ t: d0 + i * 86400000, used: 30 + i })), 48);
  assert.equal(f.days_to_full, 9); assert.equal(PM.forecast([{ t: 1, used: 1 }], 48), null, 'needs a week of samples');
  assert.equal(PM.trainNB([{ type: 'pc', f: ['a'] }]), null, 'naive Bayes needs 8 confirmations');
});

test('read, endpoints, types, findings, privacy, find, labels, proposals (four-eyes, no trunk shutdown), thresholds, roles, audit', async () => {
  const { N, call, audits, runner } = await setup();
  assert.equal((await call('POST', '/portmap/switch/:id/read', { role: 'analyst', params: { id: 'acc-syn' } })).status, 403);
  let r = await call('POST', '/portmap/switch/:id/read', { role: 'operator', params: { id: 'acc-syn' } }); assert.equal(r.status, 200, r.error);
  assert.deepEqual(runner.calls.filter((c) => c.op === 'run')[0].commands, PM.CMDS, 'one session, the read-only commands');
  assert.equal(r.body.ports, 9); assert.ok(r.body.errors.some((e) => /lldp/i.test(e)), 'LLDP off is reported, not fatal');
  // analyst view
  let m = (await call('GET', '/portmap/switch/:id', { role: 'analyst', params: { id: 'acc-syn' } })).body;
  assert.equal(m.counts.connected, 7); assert.equal(m.counts.err, 1); assert.equal(m.counts.trunks, 1);
  const p1 = portOf(m, 'Gi1/0/1'); assert.equal(p1.macs[0].ip, '10.10.0.21'); assert.equal(p1.macs[0].vendor, 'Synthetic HP Inc.'); assert.equal(p1.macs[0].type.type, 'pc'); assert.equal(p1.macs[0].host, 'PC-FIN-01');
  const p2 = portOf(m, 'Gi1/0/2'); assert.equal(p2.neighbour.name, 'SEP001122334455'); assert.equal(p2.macs.find((x) => x.mac === '0011.2233.4455').type.type, 'phone', 'the CDP phone (SEP<mac>)'); assert.equal(p2.macs.find((x) => x.mac === '3c52.82aa.0002').type.type, 'pc', 'the PC behind the phone is not a phone'); assert.equal(p2.poe.watts, 6.3);
  assert.equal(portOf(m, 'Gi1/0/7').macs[0].type.type, 'printer'); assert.equal(portOf(m, 'Gi1/0/4').macs.find((x) => x.mac === '3e52.82aa.0105').vendor, 'private (randomised) address');
  assert.equal(portOf(m, 'Te1/1/1').kind, 'uplink'); assert.equal(portOf(m, 'Te1/1/1').macs.length, 4);
  const kinds = m.findings.map((f) => f.kind + ' ' + f.port);
  for (const k of ['err-disabled Gi1/0/5', 'half-duplex Gi1/0/3', 'many-macs Gi1/0/4', 'switch-on-access Gi1/0/8', 'poe-budget poe1', 'nac-unauth Gi1/0/3', 'errors Gi1/0/3', 'description Gi1/0/8']) assert.ok(kinds.includes(k), k);
  assert.ok(!kinds.some((k) => /many-macs Te1\/1\/1/.test(k)), 'a trunk carries many MACs - not a finding');
  assert.ok(!kinds.some((k) => /description Te1\/1\/1/.test(k)), 'the uplink description names its neighbour');
  assert.equal(m.findings[0].severity, 'high'); assert.equal(m.ml.oui.loaded, true);
  // viewer: states, no MAC / IP / names
  const v = (await call('GET', '/portmap/switch/:id', { params: { id: 'acc-syn' } })).body;
  assert.equal(v.named, false); assert.ok(allPorts(v).every((p) => p.macs.length === 0)); assert.equal(portOf(v, 'Gi1/0/2').neighbour.name, ''); assert.ok(!JSON.stringify(v).includes('10.10.0.21') && !JSON.stringify(v).includes('LT-GUEST') && !JSON.stringify(v).includes('3c52.82aa'));
  const s = (await call('GET', '/portmap')).body; assert.equal(s.totals.read, 1); assert.equal(s.switches[0].counts.endpoints, m.counts.endpoints);
  // where is it plugged in
  assert.equal((await call('GET', '/portmap/find', { query: { q: '10.10.0.21' } })).status, 403);
  r = await call('GET', '/portmap/find', { role: 'analyst', query: { q: '10.10.0.21' } }); assert.equal(r.body.results[0].port, 'Gi1/0/1');
  r = await call('GET', '/portmap/find', { role: 'analyst', query: { q: 'lt-guest' } }); assert.equal(r.body.results[0].port, 'Gi1/0/3');
  r = await call('GET', '/portmap/find', { role: 'analyst', query: { q: 'SW-HIDDEN' } }); assert.equal(r.body.results[0].port, 'Gi1/0/8');
  assert.equal((await call('GET', '/portmap/find', { role: 'analyst', query: { q: 'ab' } })).status, 400);
  // a person confirms a type
  assert.equal((await call('POST', '/portmap/labels', { role: 'analyst', body: { mac: '3c52.82aa.0003', type: 'pc' } })).status, 403);
  r = await call('POST', '/portmap/labels', { role: 'operator', body: { mac: '3c52.82aa.0003', type: 'toaster' } }); assert.equal(r.status, 400); assert.match(r.error, /type must be one of/);
  assert.equal((await call('POST', '/portmap/labels', { role: 'operator', body: { mac: 'dead.beef.0000', type: 'pc' } })).status, 404);
  assert.equal((await call('POST', '/portmap/labels', { role: 'operator', body: { mac: '3c52.82aa.0003', type: 'camera' } })).status, 200);
  m = (await call('GET', '/portmap/switch/:id', { role: 'analyst', params: { id: 'acc-syn' } })).body;
  assert.deepEqual([portOf(m, 'Gi1/0/3').macs[0].type.type, portOf(m, 'Gi1/0/3').macs[0].type.confidence], ['camera', 100], 'a confirmation wins');
  // proposals: four-eyes tasks
  assert.equal((await call('POST', '/portmap/proposals', { role: 'analyst', body: { device: 'acc-syn', port: 'Gi1/0/6', type: 'port-shutdown', reason: 'unused port' } })).status, 403);
  r = await call('POST', '/portmap/proposals', { role: 'operator', body: { device: 'acc-syn', port: 'Gi1/0/6', type: 'port-shutdown' } }); assert.equal(r.status, 400); assert.match(r.error, /reason is required/);
  r = await call('POST', '/portmap/proposals', { role: 'operator', body: { device: 'acc-syn', port: 'Te1/1/1', type: 'port-shutdown', reason: 'test the guard' } }); assert.equal(r.status, 409); assert.match(r.error, /trunk/);
  r = await call('POST', '/portmap/proposals', { role: 'operator', body: { device: 'acc-syn', port: 'Gi1/0/9', type: 'port-enable', reason: 'not there' } }); assert.equal(r.status, 404);
  r = await call('POST', '/portmap/proposals', { role: 'operator', user: 'nora.syn', body: { device: 'acc-syn', port: 'Gi1/0/8', type: 'port-description', description: 'SW-HIDDEN', reason: 'name what is plugged in' } }); assert.equal(r.status, 200, r.error);
  const plan = N.changes.get(r.body.plan); assert.equal(plan.status, 'proposed'); assert.deepEqual(plan.task, { type: 'port-description', params: { interface: 'GigabitEthernet1/0/8', description: 'SW-HIDDEN' } });
  assert.throws(() => N.changes.decide(plan.id, 'approved', 'nora.syn'), /someone other than its author/);
  // thresholds
  assert.equal((await call('POST', '/portmap/config', { role: 'operator', body: { max_macs_access: 6 } })).status, 403);
  r = await call('POST', '/portmap/config', { role: 'admin', body: { max_macs_access: 1 } }); assert.equal(r.status, 400); assert.match(r.error, /max_macs_access/);
  assert.equal((await call('POST', '/portmap/config', { role: 'admin', body: { max_macs_access: 6 } })).status, 200);
  m = (await call('GET', '/portmap/switch/:id', { role: 'analyst', params: { id: 'acc-syn' } })).body; assert.ok(!m.findings.some((f) => f.kind === 'many-macs'), 'threshold applied');
  const acts = audits.map((a) => a.a);
  for (const a of ['netops.portmap.read', 'netops.portmap.find', 'netops.portmap.label', 'netops.portmap.propose', 'netops.portmap.config']) assert.ok(acts.includes(a), a);
  assert.ok(!JSON.stringify(audits).includes('Pw-ro-123'), 'no password in the audit');
});

test('history: MAC flapping, device swapped after a stable week, unused ports, capacity forecast, the schedule reads once per period', async () => {
  const E = await setup(); const { call, N, at, now } = E;
  const t0 = now(), keep = MACS.slice();
  await call('POST', '/portmap/switch/:id/read', { role: 'operator', params: { id: 'acc-syn' } });
  // the PC on Gi1/0/1 jumps between Gi1/0/1 and Gi1/0/6 three times in an hour
  for (let i = 1; i <= 3; i++) { at(t0 + i * 600000); MACS = keep.map((l) => (/3c52\.82aa\.0001/.test(l) ? l.replace('Gi1/0/1', i % 2 ? 'Gi1/0/6' : 'Gi1/0/1') : l)); await N.portmap.read('acc-syn', 'test'); }
  let m = N.portmap.model('acc-syn', 'analyst'); assert.ok(m.findings.some((f) => f.kind === 'mac-flap'), 'flapping');
  // a week later the PC on Gi1/0/7 is a different one
  MACS = keep.slice(); at(t0 + 8 * 86400000); await N.portmap.read('acc-syn', 'test');
  MACS = keep.map((l) => l.replace('0026.73bb.0007', '0026.73bb.0099')); at(t0 + 8 * 86400000 + 3600000); await N.portmap.read('acc-syn', 'test');
  m = N.portmap.model('acc-syn', 'analyst'); assert.ok(m.findings.some((f) => f.kind === 'device-swapped' && f.port === 'Gi1/0/7'));
  // 31 days with Gi1/0/6 down: unused
  MACS = keep.filter((l) => !/Gi1\/0\/6/.test(l)); at(t0 + 40 * 86400000); await N.portmap.read('acc-syn', 'test');
  m = N.portmap.model('acc-syn', 'analyst'); const un = m.findings.find((f) => f.kind === 'unused' && f.port === 'Gi1/0/6'); assert.ok(un, 'unused'); assert.equal(un.fix.type, 'port-shutdown');
  // forecast from daily samples
  for (let i = 0; i < 10; i++) E.state.collection('portmap_daily').put({ id: 'acc-syn@2026-12-' + String(i + 1).padStart(2, '0'), device: 'acc-syn', day: '2026-12-' + String(i + 1).padStart(2, '0'), t: t0 + (50 + i) * 86400000, used: 3 + i, total: 9 });
  m = N.portmap.model('acc-syn', 'analyst'); assert.ok(m.forecast && m.forecast.days_to_full >= 0 && m.forecast.per_month > 0);
  // the schedule: read now, then skipped within the period
  at(t0 + 100 * 86400000); let c = await N.portmap.cycle(); assert.equal(c.read, 1);
  c = await N.portmap.cycle(); assert.equal(c.read, 0, 'not read twice within every_h');
  assert.equal(N.portmap.summary('viewer').job.last.read, 0);
});
