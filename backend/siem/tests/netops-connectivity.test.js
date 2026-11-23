// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connectivity troubleshooter (netops/connectivity.js) and the firewall facts reader (netops/fwfacts.js): users behind a
// FortiGate reaching servers behind a Palo Alto. Facts: fixed xpaths / REST paths, read-only "show" ops, a section the key
// may not read is unread (never a pass), no secret kept. Diagnosis: asymmetric routing from one-way sessions + non-SYN drops,
// idle time-outs from the session end reason and the configured time-outs, policy denies with the rule and App-ID, SSL
// inspection for Outlook, MSS on tunnels, the server probe; each cause with evidence and per-device fix + rollback. Route:
// analyst runs it, operator for a live re-read, viewer refused, validation errors name the field, the run is audited.
// SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const FACTS = require('../engine/netops/fwfacts');
const { diagnose, ttlFor } = require('../engine/netops/connectivity');
const routes = require('../engine/netops/routes');
const { createState } = require('../engine/soc/state');

const PA_XML = {
  '/config/devices/entry/deviceconfig/system': '<system><login-banner>Authorised use only</login-banner><ntp-servers><primary-ntp-server><ntp-server-address>10.0.0.5</ntp-server-address></primary-ntp-server></ntp-servers><permitted-ip><entry name="10.50.0.0/24"/></permitted-ip><service><disable-telnet>yes</disable-telnet><disable-http>yes</disable-http></service><snmp-setting><access-setting><version><v2c><snmp-community-string>SynthCommunity99</snmp-community-string></v2c></version></access-setting></snmp-setting><update-schedule><threats><recurring><daily><at>01:00</at><action>download-only</action></daily></recurring></threats><anti-virus><recurring><hourly><action>download-and-install</action></hourly></recurring></anti-virus></update-schedule></system>',
  '/config/devices/entry/deviceconfig/setting/management': '<management><idle-timeout>60</idle-timeout></management>',
  '/config/devices/entry/deviceconfig/setting/session': '<session/>',
  '/config/devices/entry/deviceconfig/setting/tcp': '<tcp/>',
  '/config/mgt-config/password-complexity': '<password-complexity><enabled>yes</enabled><minimum-length>8</minimum-length></password-complexity>',
  '/config/mgt-config/users': '<users><entry name="admin"><phash>$1$SyntheticHash</phash></entry><entry name="ali.syn"/></users>',
  '/config/shared/log-settings/syslog': '<syslog><entry name="SIEM"/></syslog>',
  '/config/devices/entry/vsys/entry/zone': '<zone><entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="users"><network><layer3><member>ethernet1/2</member></layer3><zone-protection-profile>ZP-users</zone-protection-profile></network></entry></zone>',
  '/config/devices/entry/network/profiles/zone-protection-profile': '<zone-protection-profile><entry name="ZP-users"><flood/></entry></zone-protection-profile>',
  '/config/devices/entry/network/interface/ethernet': '<ethernet><entry name="ethernet1/1"><layer3><adjust-tcp-mss><enable>yes</enable></adjust-tcp-mss></layer3></entry><entry name="ethernet1/2"><layer3/></entry></ethernet>',
  '/config/devices/entry/network/interface/tunnel': '<tunnel><units><entry name="tunnel.1"/></units></tunnel>',
  '/config/devices/entry/vsys/entry/rulebase/security/rules': '<rules><entry name="users-to-dc"><from><member>users</member></from><to><member>dc</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>ms-rdp</member></application><service><member>application-default</member></service><action>allow</action></entry><entry name="any-any"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action><log-end>no</log-end></entry></rules>',
  '/config/devices/entry/vsys/entry/rulebase/decryption/rules': '<rules><entry name="decrypt-users"><destination><member>any</member></destination><action>decrypt</action></entry></rules>',
};
const PA_OP = {
  info: '<response status="success"><result><system><sw-version>10.1.9</sw-version><model>PA-3220</model><hostname>PA-DC-SYN</hostname></system></result></response>',
  counters: '<response status="success"><result><global><counters><entry><name>flow_tcp_non_syn_drop</name><value>4812</value></entry><entry><name>flow_fwd_mtu_exceeded</name><value>0</value></entry><entry><name>pkt_recv</name><value>99</value></entry></counters></global></result></response>',
};
function paGet(deny = []) {
  const calls = [];
  const get = async (url) => {
    const u = new URL(url), type = u.searchParams.get('type'); calls.push(u.search);
    if (type === 'op') { const cmd = u.searchParams.get('cmd'); return { status: 200, text: /counter/.test(cmd) ? PA_OP.counters : PA_OP.info }; }
    const xp = u.searchParams.get('xpath');
    if (deny.includes(xp)) return { status: 403, text: '' };
    if (u.searchParams.get('action') !== 'show') return { status: 400, text: '' };
    return { status: 200, text: '<response status="success"><result>' + (PA_XML[xp] || '') + '</result></response>' };
  };
  return { get, calls };
}
const FG_JSON = {
  '/api/v2/cmdb/system/settings': { asymroute: 'disable' },
  '/api/v2/cmdb/system/global': { 'admin-lockout-threshold': 3, admintimeout: 5 },
  '/api/v2/cmdb/system/session-ttl': { default: 3600, port: [{ id: 1, protocol: 6, 'start-port': 3389, 'end-port': 3389, timeout: 900 }] },
  '/api/v2/cmdb/firewall/policy': [{ policyid: 12, name: 'users-to-dc', status: 'enable', action: 'accept', srcintf: [{ name: 'port2' }], dstintf: [{ name: 'port1' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], 'ssl-ssh-profile': { name: 'deep-inspection' }, 'session-ttl': 0 }],
  '/api/v2/cmdb/system/interface': [{ name: 'port1', type: 'physical' }, { name: 'to-DC', type: 'tunnel', 'tcp-mss': 0 }],
  '/api/v2/cmdb/firewall/ssl-ssh-profile': [{ name: 'deep-inspection', https: { status: 'deep-inspection' } }],
  '/api/v2/cmdb/firewall.service/custom': [], '/api/v2/cmdb/system/session-helper': [],   // read for the one-way audio troubleshooter (netops-voice.test.js)
};
const fgGet = async (url) => { const p = new URL(url).pathname; return p in FG_JSON ? { status: 200, json: { results: FG_JSON[p] }, text: '' } : { status: 404, json: null, text: '' }; };
const PA_DEV = { id: 'pa-dc', name: 'PA-DC-SYN', vendor: 'paloalto', ip: '10.0.0.1' }, FG_DEV = { id: 'fg-users', name: 'FG-USERS-SYN', vendor: 'fortigate', ip: '10.20.0.1' };

test('facts: Palo Alto running configuration on fixed xpaths, show ops only, secrets not kept, a refused section is unread', async () => {
  const { get, calls } = paGet(['/config/mgt-config/users']);
  const f = await FACTS.paloalto(PA_DEV, { token: 'synthetic-key' }, { get });
  assert.equal(f.info.version, '10.1.9');
  assert.deepEqual([f.system.banner, f.system.telnet_off, f.system.http_off, f.system.snmp, f.system.permitted_ip], [true, true, true, 'v2c', 1]);
  assert.deepEqual(f.system.updates.threats, { every: 'daily', action: 'download-only' });
  assert.deepEqual([f.session.reject_non_syn, f.session.asymmetric_path, f.session.timeout_tcp], ['yes', 'drop', 3600], 'nothing configured = the PAN-OS defaults');
  assert.equal(f.admins, null); assert.match(f.unread[0].section, /admins/); assert.match(f.unread[0].reason, /Configuration read/);
  assert.equal(f.counters.flow_tcp_non_syn_drop, 4812); assert.equal(f.counters.pkt_recv, undefined, 'only the counters the checks use');
  assert.deepEqual(f.zones.map((z) => [z.name, z.zpp]), [['untrust', ''], ['users', 'ZP-users']]);
  assert.deepEqual(f.interfaces.map((i) => [i.name, i.mss]), [['ethernet1/1', true], ['ethernet1/2', false], ['tunnel.1', false]]);
  assert.deepEqual(f.rules.items.map((r) => [r.name, r.profile, r.log_end]), [['users-to-dc', false, true], ['any-any', false, false]]);
  assert.equal(f.decryption.decrypting.length, 1);
  assert.doesNotMatch(JSON.stringify(f), /SynthCommunity99|SyntheticHash|synthetic-key/, 'no community, hash or key in the facts');
  assert.ok(calls.every((q) => /type=op/.test(q) ? /cmd=%3Cshow%3E/.test(q) : /action=show/.test(q)), 'only show ops and config show');
});

test('facts: FortiGate REST GET paths; time-outs per port, deep inspection, tunnels', async () => {
  const f = await FACTS.fortigate(FG_DEV, { token: 'synthetic' }, { get: fgGet });
  assert.equal(f.settings.asymroute, 'disable'); assert.equal(ttlFor(f, 3389), 900); assert.equal(ttlFor(f, 22), 3600);
  assert.equal(f.policies[0].ssl_ssh_profile, 'deep-inspection'); assert.equal(f.interfaces[1].type, 'tunnel');
  assert.deepEqual(f.unread, []);
});

async function facts() { return { [PA_DEV.id]: await FACTS.paloalto(PA_DEV, { token: 'k' }, { get: paGet().get }), [FG_DEV.id]: await FACTS.fortigate(FG_DEV, { token: 'k' }, { get: fgGet }) }; }
function deps(F, rows, apps, opts = {}) {
  const asked = [];
  return { asked, inventory: { list: () => [FG_DEV, PA_DEV] }, poller: { snapshot: (id) => ({ security: { facts: F[id] }, system: opts.system && opts.system[id] }) },
    evidence: { sessions: async (q) => { asked.push(q); return rows; }, sessionApps: async () => apps, deviceEvents: async () => opts.events || [] },
    probe: async () => opts.open !== false };
}

test('RDP: asymmetric return path and idle time-outs found from the session logs and the settings, with fixes and rollback per device', async () => {
  const F = await facts();
  const rows = [
    { vendor: 'fortigate', firewall: 'FG-USERS-SYN', firewall_ip: '10.20.0.1', reason: 'timeout', port: 3389, sessions: 40, oneway: 22, p50_s: 900, p90_s: 900, max_s: 901, sample: '10.20.5.7 → 10.0.10.21:3389' },
    { vendor: 'fortigate', firewall: 'FG-USERS-SYN', firewall_ip: '10.20.0.1', reason: 'close', port: 3389, sessions: 20, oneway: 0, p50_s: 300 },
    { vendor: 'paloalto', firewall: 'PA-DC-SYN', firewall_ip: '10.0.0.1', reason: 'aged-out', port: 3389, sessions: 15, oneway: 15, p50_s: 3600 }];
  const d = deps(F, rows, []);
  const r = await diagnose(d, { service: 'rdp', users: '10.20.0.0/16', server: '10.0.10.21', minutes: 120 });
  assert.deepEqual(d.asked[0], { src: '10.20.0.0/16', dst: '10.0.10.21', ports: [3389], minutes: 120 });
  const ids = r.causes.map((c) => c.id);
  assert.equal(ids[0], 'asymmetric', 'the top cause: ' + ids.join(','));
  assert.ok(ids.includes('idle-timeout'));
  const asym = r.causes[0];
  assert.equal(asym.confidence, 'high'); assert.ok(asym.evidence.some((e) => /4812 non-SYN/.test(e))); assert.ok(asym.evidence.some((e) => /asymroute disable/.test(e)));
  const route = asym.steps.find((s) => s.vendor === 'routing'); assert.match(route.commands.join('\n'), /static-route SENTRA-USERS-RETURN destination 10\.20\.0\.0\/16/); assert.match(route.rollback.join('\n'), /delete network virtual-router/);
  assert.ok(asym.steps.filter((s) => /Interim/.test(s.title)).every((s) => s.risk === 'high'), 'weakening inspection is marked high risk');
  const idle = r.causes.find((c) => c.id === 'idle-timeout');
  assert.match(idle.title, /15 min/); assert.ok(idle.evidence.some((e) => /TCP 3389 idle time-out 15 min/.test(e)));
  assert.ok(idle.steps.some((s) => s.vendor === 'client' && /KeepAliveInterval/.test(s.commands.join(' '))));
  assert.match(idle.steps.find((s) => s.vendor === 'fortigate').commands.join('\n'), /set start-port 3389[\s\S]*set timeout 28800/);
  assert.match(idle.steps.find((s) => s.vendor === 'paloalto').commands.join(' '), /override application ms-rdp tcp-timeout 28800/);
  assert.ok(r.checks.find((c) => /Server 10\.0\.10\.21/.test(c.name)).status === 'ok', 'the server answers from the data centre');
  assert.match(r.summary, /Asymmetric routing/);
});

test('Outlook: a Palo Alto rule denying part of the applications, deep inspection on both firewalls, MSS on tunnels', async () => {
  const F = await facts();
  const rows = [{ vendor: 'paloalto', firewall: 'PA-DC-SYN', firewall_ip: '10.0.0.1', reason: 'policy-deny', port: 443, sessions: 30, oneway: 0, p50_s: 0, sample: '10.20.5.7 → 10.0.10.30:443' },
    { vendor: 'fortigate', firewall: 'FG-USERS-SYN', firewall_ip: '10.20.0.1', reason: 'close', port: 443, sessions: 200, oneway: 2, p50_s: 40 }];
  const apps = [{ firewall: 'PA-DC-SYN', firewall_ip: '10.0.0.1', app: 'mapi-over-http', rule: 'interzone-default', action: 'deny', reason: 'policy-deny', sessions: 30 }];
  const r = await diagnose(deps(F, rows, apps), { service: 'outlook', server: '10.0.10.30' });
  const deny = r.causes.find((c) => c.id === 'policy-deny');
  assert.equal(deny.rank, 1); assert.deepEqual(deny.devices, ['pa-dc']); assert.match(deny.explanation, /mapi-over-http/);
  assert.match(deny.steps[0].commands[0], /application \[ ms-exchange mapi-over-http rpc-over-http/); assert.match(deny.steps[0].commands[1], /before <deny-rule>/, 'never "before interzone-default"');
  const ssl = r.causes.find((c) => c.id === 'ssl-inspection');
  assert.match(ssl.title, /decrypted twice/); assert.deepEqual(ssl.steps.map((s) => s.vendor), ['fortigate', 'paloalto']);
  assert.match(ssl.steps[0].commands.join('\n'), /set subnet 10\.0\.10\.30 255\.255\.255\.255[\s\S]*config ssl-exempt/);
  assert.ok(r.causes.some((c) => c.id === 'mss'), 'tunnels without MSS on the Outlook path');
  assert.ok(!r.causes.some((c) => c.id === 'idle-timeout'), 'Outlook is not judged on idle time-outs');
});

test('no logs, a hot FortiGate, a closed server port and an HA failover are each reported', async () => {
  const F = await facts();
  const r = await diagnose(deps(F, [], [], { open: false, system: { 'fg-users': { cpu_pct: 40, mem_pct: 91 } }, events: [{ ts: '2026-10-27 08:00:00', message: 'HA failover: member 2 became primary' }] }), { service: 'ssh', server: '10.0.10.40' });
  const ids = r.causes.map((c) => c.id);
  for (const id of ['no-logs', 'resources', 'server-down', 'ha-failover']) assert.ok(ids.includes(id), id + ' in ' + ids.join(','));
  assert.match(r.causes.find((c) => c.id === 'resources').explanation, /conserve mode/);
  const none = await diagnose({ inventory: { list: () => [] }, poller: { snapshot: () => null }, evidence: null }, { service: 'rdp' });
  assert.match(none.summary, /Add the FortiGate and the Palo Alto/);
});

test('route: analyst runs it, a live re-read needs operator, viewer refused, validation names the field, audited', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-conn-'));
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const F = await facts();
  const poller = { snapshot: (id) => ({ security: { facts: F[id] } }), snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} };
  let liveReads = 0;
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, connProbe: async () => true, factsFor: async (d) => { liveReads++; return F[d.id]; } });
  for (const d of [FG_DEV, PA_DEV]) N.inventory.put(Object.assign({ site: 'Riyadh HQ', poll: {} }, d), 'syed');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(role, body) {
    const out = {}; const ctx = { role, user: 'omar.syn', body, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push(typeof a === 'object' ? a : { action: a, target: t, detail: d }), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R['POST /api/soc/netops/connectivity'](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  assert.equal((await call('viewer', { service: 'rdp' })).status, 403);
  let r = await call('analyst', { service: 'rdp', users: '10.20.0.0/16', server: '10.0.10.21' });
  assert.equal(r.status, 200, r.error); assert.equal(r.body.scope.firewalls.length, 2); assert.equal(liveReads, 0);
  assert.ok(r.body.checks.some((c) => /Traffic logs/.test(c.name) && c.status === 'skip'), 'no log database here: said, not hidden');
  assert.equal((await call('analyst', { service: 'rdp', refresh: true })).status, 403, 'a live re-read needs operator');
  assert.equal((await call('operator', { service: 'rdp', refresh: true })).status, 200); assert.equal(liveReads, 2);
  for (const [b, re] of [[{ service: 'telnet' }, /service/], [{ service: 'custom' }, /port/], [{ service: 'rdp', users: '10.20.0.0/40' }, /users/], [{ service: 'rdp', server: 'srv01; rm' }, /server/], [{ service: 'rdp', minutes: 5 }, /minutes/]]) {
    const x = await call('analyst', b); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.error || '', re);
  }
  const a = audits.filter((x) => JSON.stringify(x).includes('netops.connectivity.diagnose'));
  assert.ok(a.length >= 2, 'every run audited');
});
