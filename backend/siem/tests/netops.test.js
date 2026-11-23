// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Network Engineer (engine/netops): SNMP/BER + USM keys, PAN-OS XML, FortiGate/PAN-OS collectors against a mock
// HTTPS device (certificate pinning), counter-rate maths, findings/sites/forecast, the troubleshooter, the AI tool loop
// (fake SDK), inventory/credentials (secrets.json, never returned) and route permissions.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { execFileSync } = require('node:child_process');
const snmp = require('../engine/netops/snmp');
const X = require('../engine/netops/xml');
const C = require('../engine/netops/collectors');
const { withRates } = require('../engine/netops/poller');
const A = require('../engine/netops/analyze');
const { diagnose } = require('../engine/netops/troubleshoot');
const { createAI, check } = require('../engine/netops/ai');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-netops-'));

test('BER integers/OIDs round-trip and RFC 3414 key localisation vectors', () => {
  const B = snmp._ber;
  for (const v of [0, 1, 127, 128, 255, 256, -1, -128, -129, 2147483647, -2147483648]) assert.equal(Number(B.decInt(B.readTlv(B.encInt(v), 0).content)), v);
  for (const o of ['1.3.6.1.2.1.1.1.0', '1.3.6.1.4.1.9.9.109.1.1.1.1.8.1', '1.3.6.1.4.1.12356.101.4.1.3.0']) assert.equal(B.decOid(B.readTlv(B.encOid(o), 0).content), o);
  const ku = snmp.passwordToKey('maplesyrup', 'sha1');
  assert.equal(ku.toString('hex'), '9fb5cc0381497b3793528939ff788d5d79145211');
  assert.equal(snmp.localizeKey(ku, Buffer.from('000000000000000000000002', 'hex'), 'sha1').toString('hex'), '6695febc9288e36282235fc7151f128497b38f3f');
  assert.throws(() => snmp.passwordToKey('short', 'sha1'), /8 characters/);
  assert.throws(() => snmp.createSnmp({ host: 'router.example' }), /IP address/);
  const pdu = B.encPdu(B.T.GET, 42, ['1.3.6.1.2.1.1.5.0']); const d = B.decPdu(pdu, B.readTlv(pdu, 0));
  assert.equal(d.reqId, 42); assert.equal(d.vbs[0].oid, '1.3.6.1.2.1.1.5.0');
});

test('PAN-OS XML reader: entities, attributes, repeated entries, no DTD expansion', () => {
  const doc = X.parse('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><response status="success"><result><system><hostname>PA-DC&amp;1</hostname></system><entries><entry name="a"><s>up</s></entry><entry name="b"><s>&e;</s></entry></entries></result></response>');
  assert.equal(doc.attrs.status, 'success'); assert.equal(X.txt(doc, 'result/system/hostname'), 'PA-DC&1');
  const e = X.all(doc, 'result/entries/entry'); assert.equal(e.length, 2); assert.equal(e[1].attrs.name, 'b'); assert.equal(X.txt(e[1], 's'), '&e;');
});

function haveOpenssl() { try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch (e) { return false; } }
async function mockDevice(handler) {
  const dir = tmp(); execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=fw', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'c.pem')), key = fs.readFileSync(path.join(dir, 'k.pem'));
  const fp = new (require('node:crypto').X509Certificate)(cert).fingerprint256;
  const srv = https.createServer({ key, cert }, handler); await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { port: srv.address().port, fp, close: () => srv.close() };
}

test('FortiGate collector: REST monitor endpoints, pinned certificate, wrong pin refused', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const seen = [];
  const dev = await mockDevice((req, res) => {
    seen.push(req.method + ' ' + req.url.split('?')[0]); assert.equal(req.headers.authorization, 'Bearer tok123');
    const J = (o) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
    const p = req.url.split('?')[0];
    if (p.endsWith('/system/status')) return J({ version: 'v7.2.8', serial: 'FGT60F000', results: { hostname: 'FGT-HQ', model_name: 'FortiGate', model_number: '100F' } });
    if (p.endsWith('/resource/usage')) return J({ results: { cpu: [{ current: 37 }], mem: [{ current: 61 }], session: [{ current: 12000 }] } });
    if (p.endsWith('/system/interface')) return J({ results: { wan1: { name: 'wan1', alias: 'STC ISP', link: true, speed: 1000, rx_bytes: 1e9, tx_bytes: 2e9, rx_errors: 0, tx_errors: 0 }, port5: { name: 'port5', link: false, speed: 1000, rx_bytes: 0, tx_bytes: 0 } } });
    if (p.endsWith('/vpn/ipsec')) return J({ results: [{ name: 'to-JED', rgwy: '10.2.0.1', incoming_bytes: 5, outgoing_bytes: 6, proxyid: [{ status: 'down' }] }] });
    if (p.endsWith('/ha-peer')) return J({ results: [{ hostname: 'FGT-HQ-A' }, { hostname: 'FGT-HQ-B' }] });
    if (p.endsWith('/ha-checksums')) return J({ results: [{ checksum: { all: 'aa' } }, { checksum: { all: 'bb' } }] });
    if (p.endsWith('/health-check')) return J({ results: { ERP: { wan1: { status: 'up', latency: 12.5, jitter: 1.1, packet_loss: 0 }, wan2: { status: 'down' } } } });
    if (p.endsWith('/user/firewall')) return J({ results: [{ username: 'syn.user1', ipaddr: '10.2.5.10', usergroup: 'Staff', method: 'FSSO', traffic_vol_bytes: 123456, duration: 600 }, { ipaddr: '' }] });
    if (p.endsWith('/bgp/neighbors')) return J({ results: [{ neighbor_ip: '10.255.0.2', remote_as: 65010, state: 'Established' }, { neighbor_ip: '10.255.0.6', remote_as: 65020, state: 'Active' }] });
    if (p.endsWith('/system/dhcp')) return J({ results: [{ ip: '10.2.5.50', mac: 'b8:27:eb:00:00:01', hostname: 'pi-syn', interface: 'lan', vci: 'udhcp', expire_time: 1767225600 }, { ip: '10.2.5.51' }] });
    if (p.endsWith('/network/arp')) return J({ results: [{ ip: '10.2.5.77', mac: '7a:11:22:33:44:55', interface: 'guest', age: 30 }, { ip: '10.2.5.1', mac: '00:00:00:00:00:00' }] });
    res.statusCode = 404; res.end('{}');
  });
  try {
    const r = await C.fortigate({ ip: '127.0.0.1' }, { token: 'tok123', port: dev.port, tls: { fingerprint256: dev.fp } });
    assert.deepEqual(r.errors, []);
    assert.equal(r.system.name, 'FGT-HQ'); assert.equal(r.system.cpu_pct, 37); assert.equal(r.system.sessions, 12000);
    assert.deepEqual(r.dhcp, [{ ip: '10.2.5.50', mac: 'b8:27:eb:00:00:01', host: 'pi-syn', iface: 'lan', vci: 'udhcp', expires: 1767225600, reserved: false }], 'DHCP leases (rogue detection); a lease with no MAC dropped');
    assert.deepEqual(r.arp.map((x) => x.mac), ['7a:11:22:33:44:55'], 'ARP; the all-zero MAC dropped');
    assert.equal(r.interfaces.find((i) => i.name === 'port5').oper, 'down');
    assert.equal(r.tunnels[0].status, 'down'); assert.equal(r.ha.in_sync, false);
    assert.equal(r.paths.find((p) => p.member === 'wan2').status, 'down');
    assert.deepEqual(r.neighbors.map((n) => n.up), [true, false]);
    assert.deepEqual(r.users, [{ user: 'syn.user1', ip: '10.2.5.10', group: 'Staff', method: 'FSSO', bytes: 123456, duration_s: 600 }], 'signed-in firewall users (an empty row dropped)');
    assert.ok(seen.every((s) => s.startsWith('GET ')), 'read-only');
    await assert.rejects(C.fortigate({ ip: '127.0.0.1' }, { token: 'tok123', port: dev.port, tls: { fingerprint256: 'AA'.repeat(32) } }), /unreachable|fingerprint/);
    await assert.rejects(C.fortigate({ ip: '127.0.0.1' }, { token: 'tok123', port: dev.port, tls: {} }), /unreachable|certificate|self-signed/);
  } finally { dev.close(); }
});

test('Palo Alto collector: only <show> operational commands, parsed results', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const cmds = [];
  const dev = await mockDevice((req, res) => {
    const u = new URL(req.url, 'https://x'); assert.equal(u.searchParams.get('type'), 'op'); assert.equal(req.headers['x-pan-key'], 'key1');
    const cmd = u.searchParams.get('cmd'); cmds.push(cmd); const ok = (r) => res.end(`<response status="success"><result>${r}</result></response>`);
    if (cmd.includes('<system><info>')) return ok('<system><hostname>PA-DC</hostname><model>PA-3220</model><sw-version>10.2.7</sw-version><serial>0123</serial><uptime>12 days, 3:04:05</uptime></system>');
    if (cmd.includes('<resources>')) return ok('top - 10:00\n%Cpu(s): 20.0 us,  5.0 sy,  0.0 ni, 75.0 id\nMiB Mem :  16000.0 total,   4000.0 free,  12000.0 used');
    if (cmd.includes('<session>')) return ok('<num-active>53210</num-active>');
    if (cmd.includes('<counter>')) return ok('<ifnet><ifnet><entry><name>ethernet1/1</name><ibytes>100</ibytes><obytes>200</obytes><ierrors>3</ierrors><idrops>1</idrops></entry></ifnet></ifnet>');
    if (cmd.includes('<interface>all')) return ok('<hw><entry><name>ethernet1/1</name><state>up</state><speed>10000</speed></entry><entry><name>ethernet1/2</name><state>down</state><speed>[n/a]</speed></entry></hw>');
    if (cmd.includes('<vpn>')) return ok('<IPSec><entry><name>to-DMM</name><state>active</state><peerip>10.3.0.1</peerip></entry></IPSec>');
    if (cmd.includes('high-availability')) return ok('<enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state></local-info><peer-info><state>passive</state></peer-info><running-sync>synchronized</running-sync></group>');
    if (cmd.includes('<bgp>')) return ok('<entry peer="isp1"><status>Established</status><peer-address>192.0.2.1:179</peer-address><remote-as>39386</remote-as></entry>');
    res.end('<response status="error"><msg><line>bad</line></msg></response>');
  });
  try {
    const r = await C.paloalto({ ip: '127.0.0.1' }, { token: 'key1', port: dev.port, tls: { fingerprint256: dev.fp } });
    assert.deepEqual(r.errors, []);
    assert.equal(r.system.name, 'PA-DC'); assert.equal(r.system.uptime_s, 12 * 86400 + 3 * 3600 + 4 * 60 + 5); assert.equal(r.system.cpu_pct, 25); assert.equal(r.system.mem_pct, 75); assert.equal(r.system.sessions, 53210);
    assert.equal(r.interfaces[0].in_octets, '100'); assert.equal(r.interfaces[1].speed_mbps, null);
    assert.equal(r.ha.in_sync, true); assert.equal(r.tunnels[0].status, 'up'); assert.equal(r.neighbors[0].peer, '192.0.2.1');
    assert.ok(cmds.every((c) => c.startsWith('<show>')));
  } finally { dev.close(); }
});

test('counter rates: bps, utilisation, errors/min, counter reset gives no sample, state changes', () => {
  const prev = { at: 0, interfaces: [{ name: 'wan1', oper: 'up', in_octets: '1000000000', out_octets: '0', in_errors: 0, out_errors: 0 }], tunnels: [{ name: 't1', status: 'up' }] };
  const cur = { at: 60000, interfaces: [{ name: 'wan1', oper: 'down', speed_mbps: 100, in_octets: '1600000000', out_octets: '5', in_errors: 30, out_errors: 0 }], tunnels: [{ name: 't1', status: 'down' }] };
  withRates(cur, prev); const i = cur.interfaces[0];
  assert.equal(i.in_bps, 80e6); assert.equal(i.util_in, 80); assert.equal(i.err_per_min, 30); assert.equal(i.changed, 'up→down'); assert.equal(cur.tunnels[0].changed, 'up→down');
  const reset = { at: 120000, interfaces: [{ name: 'wan1', speed_mbps: 100, in_octets: '10', out_octets: '5' }] }; withRates(reset, cur); assert.equal(reset.interfaces[0].in_bps, null);
  const big = { at: 0, interfaces: [{ name: 'x', in_octets: '18446744073709551000', out_octets: '0' }] }, big2 = { at: 10000, interfaces: [{ name: 'x', speed_mbps: 10000, in_octets: '18446744073709551600', out_octets: '0' }] };
  withRates(big2, big); assert.equal(big2.interfaces[0].in_bps, 480);
});

const DEVS = [
  { id: 'jed-edge', name: 'JED-EDGE', vendor: 'fortigate', ip: '10.2.0.1', site: 'Jeddah Branch', role: 'wan-edge', criticality: 3 },
  { id: 'jed-sw1', name: 'JED-SW1', vendor: 'cisco-ios', ip: '10.2.0.10', site: 'Jeddah Branch', role: 'access', criticality: 2 },
  { id: 'hq-fw', name: 'HQ-FW', vendor: 'paloalto', ip: '10.0.0.1', site: 'Riyadh HQ', role: 'firewall', criticality: 3 },
];
function snaps(now) {
  return {
    'jed-edge': { at: now, ok: true, sources: ['ping', 'api'], errors: [], reach: { sent: 5, received: 5, loss_pct: 0, rtt_avg_ms: 38, jitter_ms: 4 }, system: { cpu_pct: 41 },
      interfaces: [{ name: 'wan1', alias: 'STC MPLS', admin: 'up', oper: 'up', speed_mbps: 100, in_bps: 97e6, out_bps: 20e6, util_in: 97, util_out: 20 }], paths: [{ name: 'ERP', member: 'wan2', status: 'up', loss_pct: 6, latency_ms: 90, jitter_ms: 12 }], tunnels: [{ name: 'to-HQ', status: 'up' }] },
    'jed-sw1': { at: now, ok: true, sources: ['ping'], errors: [], reach: { sent: 5, received: 5, loss_pct: 0, rtt_avg_ms: 40 } },
    'hq-fw': { at: now, ok: true, sources: ['ping', 'api'], errors: [], reach: { sent: 5, received: 5, loss_pct: 0, rtt_avg_ms: 1 }, ha: { enabled: true, in_sync: false }, neighbors: [{ proto: 'bgp', peer: '192.0.2.1', state: 'active', up: false }], tunnels: [{ name: 'to-JED', peer: '10.2.0.1', status: 'down' }] },
  };
}

test('findings, site roll-up, daily report and capacity forecast', () => {
  const now = Date.now(), S = snaps(now), f = A.findings(DEVS, S, { now });
  const kinds = f.map((x) => x.kind);
  for (const k of ['utilization', 'path-quality', 'ha-sync', 'neighbor-down', 'tunnel-down']) assert.ok(kinds.includes(k), k);
  assert.equal(f[0].severity, 'high');
  const u = f.find((x) => x.kind === 'utilization'); assert.match(u.title, /97 %/); assert.ok(u.recommendation);
  const st = A.sites(DEVS, S, f); assert.equal(st.find((s) => s.site === 'Jeddah Branch').status, 'degraded');
  const down = A.findings(DEVS, Object.assign({}, S, { 'jed-sw1': { at: now, sources: ['ping'], errors: [], reach: { sent: 5, received: 0, loss_pct: 100 } } }), { now });
  assert.ok(down.find((x) => x.kind === 'unreachable' && x.device === 'jed-sw1'));
  const rep = A.dailyReport({ devices: DEVS, snapshots: S, findings: f, sitesList: st, now }); assert.match(rep.text, /Network health report/); assert.equal(rep.busiest[0].util_pct, 97);
  const day = 86400000; const fc = A.forecast([0, 1, 2, 3, 4, 5].map((d) => [d * day, 60 + d * 2]), 90); assert.equal(fc.days_to_full, 10);
  assert.equal(A.forecast([[0, 50]]), null);
});

test('troubleshooter ranks congestion, path quality, firewall blocks and recent changes', async () => {
  const now = Date.now(), S = snaps(now);
  const inventory = { list: () => DEVS }, poller = { snapshot: (id) => S[id] };
  const evidence = {
    deviceEvents: async () => [], configChanges: async ({ ip }) => (ip === '10.2.0.1' ? [{ ts: '2026-10-11 07:10', user: 'netadmin', message: 'Edit firewall.policy 12' }] : []),
    blocked: async () => [{ src_ip: '10.2.5.20', dst_ip: '10.0.10.5', dst_port: 443, proto: 'tcp', hits: 140, firewall: 'HQ-FW' }],
  };
  const r = await diagnose({ inventory, poller, evidence, findingsFn: () => A.findings(DEVS, S, { now }) }, { site: 'jeddah', target_ip: '10.0.10.5', symptom: 'ERP slow' });
  assert.equal(r.scope.site, 'jeddah'); assert.deepEqual(r.scope.devices.map((d) => d.id), ['jed-edge', 'jed-sw1']);
  assert.match(r.causes[0].cause, /blocking traffic to 10\.0\.10\.5/);
  assert.ok(r.causes.some((c) => /congestion/.test(c.cause)) && r.causes.some((c) => /configuration change/.test(c.cause)) && r.causes.some((c) => /SD-WAN path quality/.test(c.cause)));
  assert.equal(r.checks.find((c) => c.name.startsWith('Firewall blocks')).status, 'fail');
  const none = await diagnose({ inventory, poller, evidence }, { site: 'Makkah' }); assert.match(none.summary, /No devices found/);
});

test('AI loop: parallel tool results in one message, schema check, change proposal, refusal, per-user conversations', async () => {
  const state = await createState({ dir: tmp() });
  const calls = [];
  const now = Date.now(), S = snaps(now);
  const proposals = [];
  const tools = { inventory: { list: () => DEVS }, poller: { snapshot: (id) => S[id] }, findings: () => A.findings(DEVS, S, { now }), sites: () => A.sites(DEVS, S, []),
    diagnose: async (i) => ({ summary: 'diag ' + i.site }), evidence: {}, ping: async (ip) => ({ sent: 5, received: 5, loss_pct: 0, rtt_avg_ms: 2 }),
    changes: { propose: (p, by) => { proposals.push({ p, by }); return { id: 'NCHG-000001', status: 'proposed' }; } } };
  let script = [];
  class FakeAnthropic { constructor(o) { assert.equal(o.apiKey, 'sk-test'); this.beta = { messages: { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); return script.shift(); } } }; this.messages = this.beta.messages; } }
  const ai = createAI({ config: { netops: { ai: {} }, secrets: { netops: { anthropic_api_key: 'sk-test' } } }, state, tools, sdk: FakeAnthropic });
  assert.equal(ai.status().enabled, true);
  script = [
    { stop_reason: 'tool_use', model: 'claude-opus-5-5', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'thinking', thinking: '', signature: 's' }, { type: 'tool_use', id: 't1', name: 'diagnose', input: { site: 'Jeddah Branch' } }, { type: 'tool_use', id: 't2', name: 'device_status', input: { device: 'JED-EDGE' } }, { type: 'tool_use', id: 't3', name: 'ping', input: { target: '8.8.8.8' } }, { type: 'tool_use', id: 't4', name: 'findings', input: { min_severity: 'urgent' } }] },
    { stop_reason: 'tool_use', model: 'claude-opus-5-5', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'tool_use', id: 't5', name: 'propose_change', input: { device: 'jed-edge', title: 'QoS for ERP', reason: 'wan1 saturated', commands: ['config firewall shaping-policy', 'end'], rollback: ['delete 5'] } }] },
    { stop_reason: 'end_turn', model: 'claude-opus-5-5', usage: { input_tokens: 10, output_tokens: 50 }, content: [{ type: 'text', text: 'Summary: wan1 on JED-EDGE is saturated.' }] },
  ];
  const r = await ai.ask({ question: 'Why is the Jeddah branch slow?', user: 'alice', role: 'operator' });
  assert.equal(r.answer, 'Summary: wan1 on JED-EDGE is saturated.');
  assert.equal(calls[0].model, 'claude-opus-5-5'); assert.deepEqual(calls[0].thinking, { type: 'adaptive' }); assert.equal(calls[0].fallbacks, 'default'); assert.deepEqual(calls[0].betas, ['server-side-fallback-2026-07-01']);
  const second = calls[1].messages; const toolMsg = second[second.length - 1];
  assert.equal(toolMsg.role, 'user'); assert.equal(toolMsg.content.length, 4, 'all results in one user message');
  assert.equal(second[1].content[0].type, 'thinking', 'assistant content appended unchanged');
  const byId = Object.fromEntries(toolMsg.content.map((c) => [c.tool_use_id, c]));
  assert.match(byId.t1.content, /diag Jeddah Branch/); assert.match(byId.t2.content, /JED-EDGE/);
  assert.equal(byId.t3.is_error, true); assert.match(byId.t3.content, /private IP/);
  assert.equal(byId.t4.is_error, true); assert.match(byId.t4.content, /must be one of/);
  assert.equal(proposals[0].p.source, 'ai'); assert.equal(proposals[0].p.device, 'jed-edge'); assert.match(proposals[0].by, /asked by alice/);
  assert.equal(r.steps.length, 5);
  script = [{ stop_reason: 'end_turn', model: 'claude-opus-5-5', usage: {}, content: [{ type: 'text', text: 'follow-up' }] }];
  const r2 = await ai.ask({ question: 'and Dammam?', user: 'alice', conversation: r.conversation });
  assert.equal(r2.conversation, r.conversation); assert.ok(calls[calls.length - 1].messages.length > 4, 'history replayed');
  script = [{ stop_reason: 'end_turn', model: 'claude-opus-5-5', usage: {}, content: [{ type: 'text', text: 'x' }] }];
  const r3 = await ai.ask({ question: 'steal', user: 'mallory', conversation: r.conversation }); assert.notEqual(r3.conversation, r.conversation);
  script = [{ stop_reason: 'refusal', model: 'claude-opus-5-5', usage: {}, content: [] }];
  assert.match((await ai.ask({ question: 'x', user: 'alice' })).answer, /declined/);
  // an analyst's question cannot run device CLI or file a change plan through the AI (same roles as the API routes)
  script = [{ stop_reason: 'tool_use', model: 'claude-opus-5-5', usage: {}, content: [{ type: 'tool_use', id: 'a1', name: 'propose_change', input: { device: 'jed-edge', title: 't', reason: 'r', commands: ['x'], rollback: ['y'] } }, { type: 'tool_use', id: 'a2', name: 'show_commands', input: { device: 'jed-sw1', commands: ['show running-config'] } }] },
    { stop_reason: 'end_turn', model: 'claude-opus-5-5', usage: {}, content: [{ type: 'text', text: 'ok' }] }];
  const before = proposals.length, nCalls = calls.length;
  await ai.ask({ question: 'fix it', user: 'ana', role: 'analyst' });
  assert.equal(proposals.length, before, 'no plan filed for an analyst');
  assert.ok(!calls[nCalls].tools.some((t) => t.name === 'propose_change' || t.name === 'show_commands'), 'tools not offered to an analyst');
  const refused = calls[nCalls + 1].messages[calls[nCalls + 1].messages.length - 1].content;
  assert.ok(refused.every((c) => c.is_error && /operator role/.test(c.content)));
  assert.equal(check({ type: 'object', properties: { a: { type: 'integer', minimum: 1 } }, additionalProperties: false }, { a: 0 }), 'input.a must be at least 1');
  const off = createAI({ config: { netops: { ai: {} }, secrets: {} }, state, tools, sdk: FakeAnthropic });
  const saved = process.env.ANTHROPIC_API_KEY; delete process.env.ANTHROPIC_API_KEY;
  assert.equal(off.status().enabled, false); await assert.rejects(off.ask({ question: 'x', user: 'a' }), /API key/);
  if (saved) process.env.ANTHROPIC_API_KEY = saved;
});

test('routes: roles, credentials are write-only (secrets.json, mode 600), device CRUD, change approval rules', async () => {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, JSON.stringify({ clickhouse: { password: 'x' } }), { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false }, sources: [{ id: 'fgt-jed', type: 'fortigate', match_ip: '10.2.0.1', site: 'Jeddah Branch' }] };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const fakePoller = { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {}, pollDevice: async (id) => ({ device_id: id, ok: true }) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a) => audits.push(a), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  assert.equal((await call('POST', '/devices', { role: 'operator', body: { id: 'x1', vendor: 'cisco-ios', ip: '10.1.1.1' } })).status, 403);
  assert.equal((await call('POST', '/devices', { role: 'admin', body: { id: 'x1', vendor: 'junos', ip: '10.1.1.1' } })).status, 400);
  assert.equal((await call('POST', '/devices', { role: 'admin', body: { id: 'core-sw1', name: 'CORE-SW1', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core', poll: { snmp: true } } })).status, 200);
  assert.equal((await call('POST', '/devices/seed', { role: 'admin' })).body.added[0], 'fgt-jed');
  assert.equal((await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'core-sw1' }, body: { snmp: { version: '3', user: 'mon', authProto: 'md5', authKey: 'authpass1' } } })).status, 400);
  const cr = await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'core-sw1' }, body: { snmp: { version: '3', user: 'mon', authProto: 'sha256', authKey: 'authpass1', privKey: 'privpass1' } } });
  assert.equal(cr.status, 200); assert.equal(cr.body.credentials.snmp, 'v3 authPriv');
  const onDisk = JSON.parse(fs.readFileSync(secrets, 'utf8')); assert.equal(onDisk.netops.devices['core-sw1'].snmp.privKey, 'privpass1'); assert.equal(onDisk.clickhouse.password, 'x');
  assert.equal(fs.statSync(secrets).mode & 0o777, 0o600);
  const list = await call('GET', '/devices'); assert.equal(list.status, 200); assert.ok(!JSON.stringify(list.body).includes('privpass1') && !JSON.stringify(list.body).includes('authpass1'));
  const one = await call('GET', '/devices/:id', { params: { id: 'core-sw1' } }); assert.ok(!JSON.stringify(one.body).includes('privpass1'));
  assert.equal((await call('POST', '/ask', { role: 'viewer', body: { question: 'x' } })).status, 403);
  assert.equal((await call('POST', '/ask', { role: 'analyst', body: { question: 'x' } })).status, 503);
  assert.equal((await call('POST', '/devices/:id/poll', { role: 'operator', params: { id: 'core-sw1' } })).body.ok, true);
  const p = await call('POST', '/changes', { role: 'operator', user: 'eng1', body: { device: 'core-sw1', title: 'Shut unused port', commands: ['interface Gi1/0/24', 'shutdown'], rollback: ['no shutdown'] } });
  assert.equal(p.body.status, 'proposed');
  assert.equal((await call('POST', '/changes/:id/decide', { role: 'operator', params: { id: p.body.id }, body: { decision: 'approved' } })).status, 403);
  assert.equal((await call('POST', '/changes/:id/decide', { role: 'admin', user: 'eng1', params: { id: p.body.id }, body: { decision: 'approved' } })).status, 403, 'author cannot approve');
  assert.equal((await call('POST', '/changes/:id/decide', { role: 'admin', user: 'boss', params: { id: p.body.id }, body: { decision: 'approved' } })).body.status, 'approved');
  const ap = await call('POST', '/changes/:id/applied', { role: 'operator', params: { id: p.body.id }, body: { note: 'done 22:00' } });
  assert.equal(ap.body.status, 'validated');
  assert.equal((await call('DELETE', '/devices/:id', { role: 'admin', params: { id: 'core-sw1' } })).status, 200);
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).netops.devices['core-sw1'], undefined, 'credentials removed with the device');
  assert.ok(audits.includes('netops.device.credentials') && audits.includes('netops.change.approved'));
});

test('a blocked config write explains itself instead of "internal error"', () => {
  const store = require('../engine/onboard/store'), real = fs.writeFileSync;
  fs.writeFileSync = () => { throw Object.assign(new Error('read-only file system'), { code: 'EROFS' }); };
  try { assert.throws(() => store.writeJsonAtomic(path.join(tmp(), 'config.json'), { a: 1 }), (e) => e.code === 500 && /cannot write .*EROFS.*fix-config-write/.test(e.message)); }
  finally { fs.writeFileSync = real; }
});

test('security checks: FortiGate config risks, PAN-OS rules, open Telnet/HTTP, certificate expiry, SNMP hygiene', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const sec = require('../engine/netops/security');
  const net = require('node:net'), http = require('node:http');
  // Telnet-like listener + HTTP server that does NOT redirect to HTTPS
  const tel = net.createServer((s) => s.end()); await new Promise((r) => tel.listen(0, '127.0.0.1', r));
  const web = http.createServer((q, r) => r.end('login')); await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const fg = await mockDevice((req, res) => {
    const p = req.url.split('?')[0], J = (o) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
    assert.equal(req.method, 'GET');
    if (p.endsWith('/cmdb/system/interface')) return J({ results: [{ name: 'wan1', role: 'wan', allowaccess: 'ping https ssh' }, { name: 'port3', role: 'lan', allowaccess: 'ping https http telnet' }] });
    if (p.endsWith('/cmdb/firewall/policy')) return J({ results: [
      { policyid: 7, name: 'temp-any', status: 'enable', action: 'accept', srcintf: [{ name: 'port3' }], dstintf: [{ name: 'wan1' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], logtraffic: 'disable' },
      { policyid: 9, name: 'pub-web', status: 'enable', action: 'accept', srcintf: [{ name: 'wan1' }], dstintf: [{ name: 'dmz' }], srcaddr: [{ name: 'g-partners' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], logtraffic: 'all' },
      { policyid: 11, status: 'enable', action: 'accept', srcintf: [{ name: 'port3' }], srcaddr: [{ name: 'lan' }], dstaddr: [{ name: 'srv' }], service: [{ name: 'HTTPS' }], logtraffic: 'all' },
      { policyid: 12, status: 'disable', action: 'accept', srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }] }] });
    if (p.endsWith('/cmdb/system/admin')) return J({ results: [{ name: 'admin', accprofile: 'super_admin', trusthost1: '0.0.0.0 0.0.0.0' }, { name: 'noc', accprofile: 'ro', trusthost1: '10.1.0.0 255.255.255.0' }] });
    res.statusCode = 404; res.end('{}');
  });
  try {
    const dev = { id: 'fw', name: 'FGT-HQ', vendor: 'fortigate', ip: '127.0.0.1', poll: { ping: true, api: true } };
    const r = await sec.check(dev, { api: { token: 't', port: fg.port, tls: { fingerprint256: fg.fp } }, snmp: { version: '2c', community: 'public' } }, { ports: { telnet: tel.address().port, http: web.address().port }, now: Date.now(), facts: false });   // facts: netops-connectivity.test.js
    const k = r.items.map((i) => i.kind + ':' + i.key);
    for (const want of ['telnet-open:telnet', 'http-open:http', 'cert-expiring:cert', 'snmp-v2c:snmp', 'mgmt-telnet:port3', 'mgmt-http:port3', 'mgmt-wan:wan1', 'fw-any-any:7', 'fw-nolog:7', 'fw-internet-any:9', 'fw-admin-anywhere:admin', 'fw-default-admin:admin']) assert.ok(k.includes(want), 'missing ' + want + ' in ' + k.join(' '));
    assert.ok(!k.some((x) => /:1[12]$/.test(x)), 'specific and disabled policies are not flagged');
    assert.ok(!k.includes('fw-admin-anywhere:noc'));
    assert.equal(r.items.find((i) => i.kind === 'fw-any-any').severity, 'high');
    assert.deepEqual(r.errors, []);
    const later = await sec.check(dev, { api: { token: 't', port: fg.port, tls: { fingerprint256: 'AB'.repeat(32) } } }, { ports: { telnet: 1, http: 1 }, now: Date.now() + 5 * 86400000, facts: false });
    assert.ok(later.items.some((i) => i.kind === 'cert-expired') && later.items.some((i) => i.kind === 'cert-changed'));
    const f = A.findings([dev], { fw: { at: Date.now(), ok: true, sources: ['api'], errors: [], security: r } }, {});
    assert.ok(f.some((x) => x.kind === 'sec-fw-any-any' && x.recommendation));
  } finally { fg.close(); tel.close(); web.close(); }
  const pa = await mockDevice((req, res) => {
    const u = new URL(req.url, 'https://x'); assert.equal(u.searchParams.get('type'), 'config'); assert.equal(u.searchParams.get('action'), 'get');
    const x = u.searchParams.get('xpath');
    if (x.endsWith('/rules')) return res.end('<response status="success"><result><rules><entry name="allow-all"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action><log-end>no</log-end></entry><entry name="web"><source><member>10.0.0.0/8</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><action>allow</action></entry></rules></result></response>');
    return res.end('<response status="success"><result><interface-management-profile><entry name="mgmt-lan"><https>yes</https><http>yes</http><telnet>no</telnet></entry></interface-management-profile></result></response>');
  });
  try {
    const r = await sec.check({ id: 'pa', name: 'PA-DC', vendor: 'paloalto', ip: '127.0.0.1', poll: { ping: false, api: true } }, { api: { token: 'k', port: pa.port, tls: { fingerprint256: pa.fp } } }, { facts: false });
    const k = r.items.map((i) => i.kind + ':' + i.key);
    assert.ok(k.includes('pa-any-any:allow-all') && k.includes('pa-nolog:allow-all') && k.includes('pa-mgmt-http:mgmt-lanhttp'), k.join(' '));
    assert.ok(!k.some((x) => x.includes(':web')));
  } finally { pa.close(); }
  const denied = await mockDevice((req, res) => { res.statusCode = 403; res.end('<response status="error"><msg>Unauthorized</msg></response>'); });
  try {
    const r = await sec.check({ id: 'pa2', name: 'PA2', vendor: 'paloalto', ip: '127.0.0.1', poll: { ping: false, api: true } }, { api: { token: 'k', port: denied.port, tls: { fingerprint256: denied.fp } } }, {});
    assert.match(r.errors[0], /configuration read not allowed/);
  } finally { denied.close(); }
});

test('availability: status durations, 2-failure rule, HA / single point of failure / DR, restarts from logs, import, roles', async () => {
  const av = require('../engine/netops/availability');
  assert.equal(av.stem(('irisdbnp2.' + 'corp-hq.com')), 'irisdbnp'); assert.equal(av.stem('app-a'), 'app'); assert.equal(av.stem('erp-dr'), 'erp'); assert.equal(av.stem('as-datac'), 'as-datac'); assert.equal(av.stem('as-sme-aggdb'), 'as-sme-aggdb');
  assert.ok(av.nonProd('360f-uat') && av.nonProd(('irisdbnp2.' + 'corp-hq.com')) && av.nonProd('erp-test1') && !av.nonProd('as-sme-aggdb') && !av.nonProd('asvcenterhp'));
  assert.ok(av.inCidr('10.10.10.191', '10.10.10.0/24') && !av.inCidr('192.168.11.5', '10.10.10.0/24'));
  const state = await createState({ dir: tmp() });
  let t = Date.parse('2026-10-11T08:00:00Z'); const up = { };
  const inserted = [];
  const ch = { insertRows: async (tb, rows) => { inserted.push(...rows); }, query: async (sql) => {
    if (/host_up/.test(sql)) return [{ device: 'h-db1', d1: 99.31, d7: 99.9, d30: 99.97 }];
    if (/agent-heartbeat/.test(sql)) return [{ host_ip: '', h: 'asiirisdb2', at: new Date(t - 120000).toISOString().replace('T', ' ').slice(0, 19), cpu: '95', mem: '61.5', mem_gb: '16', disk: '92', disks: 'C:|100|8;D:|500|400' }];
    return [{ host_ip: '192.168.11.174', h: ('asiirisdb2.' + 'corp-hq.com'), boot_evt: '2026-08-01 02:00:00', up_s: String(5 * 86400), up_ts: '2026-10-10 00:00:00', unexpected: 2, shutdown_evt: '2026-08-01 01:58:00' }]; } };
  const A1 = av.createAvailability({ state, config: { clickhouse: { database: 'siem' } }, ch, probe: async (h) => ({ up: !!up[h.ip], method: 'tcp/3389' }), now: () => t });
  const hs = [['h-db1', ('asiirisdb1.' + 'corp-hq.com'), '192.168.11.173', 'windows'], ['h-db2', ('asiirisdb2.' + 'corp-hq.com'), '192.168.11.174', 'windows'], ['h-dr', 'asiirisdb-dr', '10.10.10.174', 'windows'], ['h-solo', ('asvcenterhp.' + 'corp-hq.com'), '192.168.11.88', 'linux']];
  for (const [id, name, ip, os] of hs) A1.put({ id, name, ip, os }, 'admin');
  A1.setSettings({ subnets: [{ cidr: '10.10.10.0/24', site: 'DR site', dr: true }, { cidr: '192.168.11.0/24', site: 'Riyadh DC' }], reboot_max_days: 30 }, 'admin');
  Object.assign(up, { '192.168.11.173': 1, '192.168.11.174': 1, '10.10.10.174': 1, '192.168.11.88': 1 });
  await A1.scan(); t += 60000; up['192.168.11.173'] = 0; await A1.scan();
  let v = await A1.view(); assert.equal(v.items.find((i) => i.id === 'h-db1').status, 'online', 'one failed check is not yet offline');
  t += 60000; await A1.scan(); t += 3600000; await A1.scan();
  v = await A1.view(); const db1 = v.items.find((i) => i.id === 'h-db1');
  assert.equal(db1.status, 'offline'); assert.equal(db1.since, Date.parse('2026-10-11T08:00:00Z'), 'offline since the last successful check');
  assert.equal(db1.duration_s, 3600 + 120); assert.deepEqual(db1.availability, { d1: 99.31, d7: 99.9, d30: 99.97 });
  const grp = v.groups.find((g) => g.name === 'asiirisdb'); assert.equal(grp.production, 2); assert.equal(grp.dr, 1); assert.equal(grp.status, 'degraded'); assert.ok(grp.issues.includes('no-redundancy-now') && !grp.issues.includes('no-dr'));
  const solo = v.items.find((i) => i.id === 'h-solo'); assert.ok(solo.flags.includes('single-server') && solo.flags.includes('no-dr'));
  const db2 = v.items.find((i) => i.id === 'h-db2'); assert.equal(db2.site, 'Riyadh DC'); assert.equal(db2.last_boot, Date.parse('2026-10-05T00:00:00Z'), 'uptime event (6013) newer than boot event'); assert.equal(db2.days_since_boot, 6); assert.equal(db2.unexpected_shutdowns_30d, 2); assert.ok(db2.flags.includes('unexpected-shutdowns'));
  assert.equal(db2.resources.cpu_pct, 95); assert.equal(db2.resources.mem_pct, 61.5); assert.deepEqual(db2.resources.disks[0], { dev: 'C:', size_gb: 100, free_gb: 8, used_pct: 92 });
  assert.ok(db2.flags.includes('cpu-high') && db2.flags.includes('disk-full') && !db2.flags.includes('memory-high'), 'resource flags from the agent heartbeat (matched by short name)');
  assert.equal(v.summary.offline, 1); assert.equal(v.summary.spof, 1);
  assert.ok(inserted.some((r) => r.metric === 'host_up' && r.device === 'h-db1' && r.value === 0));
  up['192.168.11.173'] = 1; t += 60000; await A1.scan();
  const d = await A1.detail('h-db1'); assert.equal(d.host.status, 'online'); assert.deepEqual(d.events.map((e) => e.to), ['online', 'offline']);
  assert.equal(d.group.member_hosts.length, 3);
  const A2 = av.createAvailability({ state, config: {}, probe: async () => ({ up: true }), now: () => t }); A2.restore();
  assert.equal(A2.ipMap()['192.168.11.173'].s, 'online', 'state survives an engine restart');
  const imp = A1.importHosts([{ ip: '192.168.11.81', hostname: '360f-uat', os: 'linux', class: 'Virtual machine' }, { ip: '192.168.11.88', hostname: 'x' }, { ip: 'bad' }], 'admin');
  assert.deepEqual([imp.added, imp.updated, imp.skipped], [1, 1, 1]);
  const offAll = av.evaluate([{ id: 'x', name: 'erp-uat', ip: '10.10.10.5' }], { x: { status: 'offline' } }, { subnets: [{ cidr: '10.10.10.0/24', dr: true }] })[0];
  assert.equal(offAll.status, 'down', 'all members offline = down, even non-production / DR-only');
  const uat = (await A1.view()).groups.find((g) => g.name === '360f-uat'); assert.equal(uat.required, false); assert.ok(!uat.issues.includes('single-server') && !uat.issues.includes('no-dr'));
  A1.put({ id: imp.added && A1.list().find((h) => h.ip === '192.168.11.81').id, requires_ha: true }, 'admin');
  assert.ok((await A1.view()).groups.find((g) => g.name === '360f-uat').issues.includes('single-server'), 'administrator override');
  assert.throws(() => A1.setSettings({ subnets: [{ cidr: '10.0.0.0/99' }] }), /invalid CIDR/);
  // routes: roles
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false });
  const fakePoller = { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller, availability: A1 });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, role, b, params = {}) => { const o = {}; const ctx = { role, user: 'u', body: b, params, query: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('GET', '/avail', 'viewer')).b.summary.total, 5);
  assert.equal((await call('POST', '/avail/hosts', 'operator', { ip: '10.0.0.9' })).s, 403);
  assert.equal((await call('POST', '/avail/hosts', 'admin', { id: 'h-solo', service: 'vCenter', role: 'primary', critical: true })).b.service, 'vCenter');
  assert.equal((await call('POST', '/avail/hosts/:id/check', 'operator', null, { id: 'h-solo' })).b.status, 'online');
  assert.equal((await call('POST', '/avail/import', 'admin', { source: 'discovery' })).s, 503);
  // Fetch now: every monitored server checked at once - operator, not viewer; the fresh view comes back
  assert.equal((await call('POST', '/avail/scan', 'viewer')).s, 403);
  const sc = await call('POST', '/avail/scan', 'operator'); assert.ok(sc.b && sc.b.summary && sc.b.summary.total >= 5, JSON.stringify(sc).slice(0, 200));
  assert.equal(Object.keys((await call('GET', '/avail/map', 'viewer')).b.hosts).length >= 4, true);
});

test('availability: inventory sync adds servers / VMs with an IP, keeps manual hosts, removes retired or deleted ones', async () => {
  const av = require('../engine/netops/availability');
  const state = await createState({ dir: tmp() });
  let inv = [
    { id: 'as_vc1', name: ('asvcenter01.' + 'corp-hq.com'), type: 'vm', status: 'in_use', mgmt_ip: '192.168.11.20', os: 'VMware Photon' },
    { id: 'as_vc2', name: ('asvcenter02.' + 'corp-hq.com'), type: 'server', status: 'in_use', mgmt_ip: '192.168.11.21' },
    { id: 'as_vc3', name: ('asvcenter03.' + 'corp-hq.com'), type: 'vm', status: 'in_use', mgmt_ip: '' },
    { id: 'as_az', name: 'az-app01', type: 'other', status: 'in_use', mgmt_ip: '10.50.0.4', tags: ['cloud'] },
    { id: 'as_lap', name: 'laptop-1', type: 'laptop', status: 'in_use', mgmt_ip: '192.168.20.5' },
    { id: 'as_old', name: 'old-srv', type: 'server', status: 'retired', mgmt_ip: '192.168.11.99' }];
  const calls = [];
  const discovery = { assets: async (q, who) => { calls.push([q, who.role]); return { assets: inv, total: inv.length }; } };
  const A = av.createAvailability({ state, config: {}, discovery, probe: async () => ({ up: true }), now: () => Date.now() });
  A.put({ ip: '192.168.11.21', name: 'vc2-manual', service: 'vCenter' }, 'admin');
  const r = await A.importFromInventory();
  assert.deepEqual(calls[0], [{ limit: 5000 }, 'viewer'], 'read-only call to the inventory');
  assert.equal(r.fetched, 6); assert.equal(r.eligible, 3); assert.equal(r.added, 2); assert.equal(r.updated, 1); assert.deepEqual(r.skipped_no_ip, [('asvcenter03.' + 'corp-hq.com')]); assert.equal(r.skipped_type, 1);
  const ips = A.list().map((h) => h.ip).sort(); assert.deepEqual(ips, ['10.50.0.4', '192.168.11.20', '192.168.11.21']);
  const manual = A.list().find((h) => h.ip === '192.168.11.21'); assert.equal(manual.name, 'vc2-manual'); assert.notEqual(manual.source, 'inventory'); assert.equal(manual.asset_id, 'as_vc2');
  // asset 1 retired, asset 2 deleted, asset 3 gets an IP
  inv = inv.filter((a) => a.id !== 'as_vc2').map((a) => (a.id === 'as_vc1' ? Object.assign({}, a, { status: 'retired' }) : a.id === 'as_vc3' ? Object.assign({}, a, { mgmt_ip: '192.168.11.22' }) : a));
  const r2 = await A.importFromInventory();
  assert.equal(r2.removed, 1, 'only the synced host of the retired asset is removed');
  assert.deepEqual(A.list().map((h) => h.ip).sort(), ['10.50.0.4', '192.168.11.21', '192.168.11.22'], 'manual host stays even though its asset is gone');
  await assert.rejects(av.createAvailability({ state, config: {} }).importFromInventory(), /not linked/);
  assert.equal(A.setSettings({ sync_inventory: false }).sync_inventory, false);
});

test('availability: a failed inventory sync (IT Asset Management restarting) is retried after 1 minute', async (t) => {
  const av = require('../engine/netops/availability');
  const state = await createState({ dir: tmp() });
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  let calls = 0; const logs = [];
  const discovery = { assets: async () => { calls++; if (calls === 1) throw new Error('discovery not reachable (ECONNREFUSED)'); return { assets: [{ id: 'as1', name: 'srv1', type: 'server', mgmt_ip: '10.0.0.5', status: 'in_use' }] }; } };
  const A = av.createAvailability({ state, config: {}, discovery, probe: async () => ({ up: true }), now: () => Date.now(), log: { info: (m) => logs.push(['info', m]), warn: (m, f) => logs.push(['warn', m, f]) } });
  A.start();
  const flush = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };
  t.mock.timers.tick(30000); await flush();
  assert.equal(calls, 1); assert.match(A.stats().last_sync_error, /not reachable/);
  assert.deepEqual(logs.find((l) => l[1] === 'inventory sync failed')[2].retry_in_s, 60);
  t.mock.timers.tick(60000); await flush();
  assert.equal(calls, 2); assert.equal(A.stats().last_sync_error, ''); assert.equal(A.stats().last_sync.eligible, 1);
  assert.ok(logs.some((l) => l[1] === 'inventory sync recovered'));
  assert.equal(A.list().length, 1);
  A.stop();
});

test('EdgeConnect Orchestrator: API key, source=menu_rest_apis_id on every call, retry with Accept */* after HTTP 406', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const seen = [];
  const dev = await mockDevice((req, res) => {
    seen.push([req.url, req.headers.accept]);
    if (req.headers['x-auth-token'] !== 'key-1') { res.statusCode = 401; return res.end(); }
    if (!/[?&]source=menu_rest_apis_id/.test(req.url)) { res.statusCode = 400; return res.end('missing source'); }
    if (/application\/json/.test(req.headers.accept || '')) { res.statusCode = 406; return res.end(); }   // an Orchestrator that rejects the first Accept
    res.setHeader('content-type', 'application/json');
    if (req.url.startsWith('/gms/rest/appliance?')) return res.end(JSON.stringify([{ hostName: 'EC-RUH-1', site: 'Riyadh', IP: '10.9.0.1', state: 1, softwareVersion: '9.4.1' }]));
    if (req.url.startsWith('/gms/rest/alarm/appliance?view=active&source=')) return res.end(JSON.stringify([{ severity: 'MAJOR', hostName: 'EC-RUH-1', description: 'Tunnel down' }]));
    res.statusCode = 404; res.end();
  });
  try {
    const r = await C.edgeconnect({ ip: '127.0.0.1' }, { token: 'key-1', port: dev.port, tls: { fingerprint256: dev.fp } });
    assert.equal(r.sdwan.appliances[0].name, 'EC-RUH-1'); assert.equal(r.sdwan.appliances[0].up, true);
    assert.equal(r.sdwan.alarms[0].text, 'Tunnel down'); assert.deepEqual(r.errors, []);
    assert.ok(seen.every(([u]) => /source=menu_rest_apis_id/.test(u)));
    assert.ok(seen.some(([, a]) => a === '*/*'), 'retried with Accept */*');
  } finally { dev.close(); }
});

test('support and subscriptions as FortiGate / PAN-OS report them → findings → SIEM alerts (with the register\'s contracts)', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10), sec = (n) => Math.floor((Date.now() + n * 86400000) / 1000);
  const fgt = await mockDevice((req, res) => {
    assert.equal(req.method, 'GET'); res.setHeader('content-type', 'application/json');
    if (req.url.startsWith('/api/v2/monitor/license/status')) return res.end(JSON.stringify({ serial: 'FGT100F01', results: {
      forticare: { status: 'registered', support: { hardware: { level: 'advanced', status: 'licensed', expires: sec(20) }, enhanced: { level: '24x7', status: 'licensed', expires: sec(300) } } },
      antivirus: { type: 'licensed', status: 'expired', expires: sec(-3) }, ips: { status: 'licensed', expires: sec(200) }, sandbox: { status: 'unlicensed' } } }));
    res.statusCode = 404; res.end('{}');
  });
  const cmds = [];
  const pan = await mockDevice((req, res) => {
    const cmd = new URL(req.url, 'https://x').searchParams.get('cmd'); cmds.push(cmd);
    if (cmd === C.PAN_LICENSE_INFO) return res.end(`<response status="success"><result><licenses><entry><feature>PAN-DB URL Filtering</feature><serial>0123</serial><expires>${new Date(Date.now() + 40 * 86400000).toUTCString().slice(5, 16)}</expires><expired>no</expired></entry><entry><feature>Premium</feature><description>24 x 7 phone support</description><serial>0123</serial><expires>${new Date(Date.now() - 10 * 86400000).toUTCString().slice(5, 16)}</expires><expired>yes</expired></entry><entry><feature>PA-VM</feature><serial>0123</serial><expires>Never</expires><expired>no</expired></entry></licenses></result></response>`);
    res.end('<response status="error"><msg><line>bad</line></msg></response>');
  });
  try {
    const f = await C.licenses({ ip: '127.0.0.1', vendor: 'fortigate' }, { token: 't', port: fgt.port, tls: { fingerprint256: fgt.fp } });
    const byName = Object.fromEntries(f.items.map((i) => [i.name, i]));
    assert.equal(byName['FortiCare hardware'].kind, 'support'); assert.equal(byName['FortiCare hardware'].expires, day(20));
    assert.equal(byName.antivirus.expired, true); assert.equal(byName.sandbox, undefined, 'a service never bought is not "expired"');
    const p = await C.licenses({ ip: '127.0.0.1', vendor: 'paloalto' }, { token: 'k', port: pan.port, tls: { fingerprint256: pan.fp } });
    assert.deepEqual(cmds, [C.PAN_LICENSE_INFO]); assert.equal(p.serial, '0123');
    assert.equal(p.items.find((i) => i.name === 'Premium').expired, true); assert.equal(p.items.find((i) => i.name === 'Premium').kind, 'support');
    assert.equal(p.items.find((i) => i.name === 'PA-VM').expires, null);

    const DEVS2 = [{ id: 'fgt', name: 'FGT-HQ', vendor: 'fortigate', ip: '10.0.0.1', site: 'HQ', role: 'firewall' }, { id: 'pa', name: 'PA-DC', vendor: 'paloalto', ip: '10.0.0.2', site: 'DC', role: 'firewall' }];
    const now = Date.now(), S = { fgt: { at: now, ok: true, sources: ['api'], errors: [], licenses: f }, pa: { at: now, ok: true, sources: ['api'], errors: [], licenses: p } };
    const fs2 = A.findings(DEVS2, S, { now });
    const k = fs2.filter((x) => /support|license/.test(x.kind)).map((x) => `${x.kind}:${x.severity}:${x.device}`).sort();
    assert.deepEqual(k, ['license-expired:high:fgt', 'license-expiring:medium:pa', 'support-expired:high:pa', 'support-expiring:high:fgt']);

    const { createNetopsAlerts } = require('../engine/netops/alerts-bridge');
    const { createAlerts } = require('../engine/soc/alerts');
    const state = await createState({ dir: tmp() }); const alerts = createAlerts({ state });
    const contracts = async () => ({ contracts: [{ id: 'sc_1', vendor: 'Microsoft', product: 'Unified Support', contract_number: 'MS-1', end: day(10), days_left: 10, state: 'expiring', covered_count: 40, issues: [] },
      { id: 'sc_2', vendor: 'Oracle', product: 'Database', end: day(200), days_left: 200, state: 'active', covered_count: 2, issues: [] }, { id: 'sc_3', vendor: 'Nutanix', product: 'AOS', end: day(-1), days_left: -1, state: 'expired', covered_count: 4, issues: [] }] });
    const B = createNetopsAlerts({ alerts, findings: () => fs2.concat([{ id: 'x:unreachable', kind: 'unreachable', severity: 'critical', device: 'fgt', device_name: 'FGT-HQ', title: 'FGT-HQ is not reachable' }, { id: 'y:utilization', kind: 'utilization', severity: 'high', device: 'pa', title: 'busy' }]), contracts, config: {} });
    assert.deepEqual(B.tick(), { raised: 5, merged: 0 }, '4 support/licence findings + the critical unreachable; utilisation is not an alert by default');
    assert.deepEqual(B.tick(), { raised: 0, merged: 5 }, 'the same conditions merge into the open alerts');
    assert.deepEqual(await B.contractsTick(), { raised: 2, merged: 0 }, 'expiring within 30 days + expired; the one with 200 days left is not');
    const list = alerts.list({}).items;
    const lic = list.find((a) => a.rule_id === 'netops-license-expired'); assert.equal(lic.severity, 3); assert.equal(lic.source, 'netops'); assert.match(lic.summary, /antivirus subscription expired/);
    assert.ok(list.some((a) => a.rule_id === 'support-contract-expired' && /Nutanix AOS/.test(a.summary)));
    const off = createNetopsAlerts({ alerts, findings: () => fs2, config: { netops: { alerts: { enabled: false } } } }); assert.deepEqual(off.tick(), { raised: 0, merged: 0 });
  } finally { fgt.close(); pan.close(); }
});

test('routes: NPM summary — nodes by vendor + status, health counts, hot interfaces (from poller snapshots)', async () => {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  // snapshots: core switch healthy with a hot interface, a firewall with an error (critical), a device never polled
  const snaps = {
    'sw1': { at: 1, ok: true, errors: [], sources: ['snmp'], reach: { rtt_avg_ms: 2.4, received: 3 }, system: { model: 'C9500', cpu_pct: 45, mem_pct: 70 }, interfaces: [
      { name: 'Po1', oper: 'up', util_in: 91, util_out: 60, err_per_min: 0 }, { name: 'Gi1/0/1', oper: 'up', util_in: 12, util_out: 8 }] },
    'fw1': { at: 1, ok: false, errors: ['snmp: timeout'], sources: [], system: null, interfaces: [] },
  };
  const fakePoller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({ polls: 2 }), forget() {}, start() {}, pollDevice: async () => ({}) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller });
  N.inventory.put({ id: 'sw1', name: 'CORE-SW1', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core', poll: { snmp: true } }, 'syed');
  N.inventory.put({ id: 'fw1', name: 'FW-HQ', vendor: 'fortigate', ip: '10.0.0.1', site: 'Riyadh HQ', poll: { snmp: true } }, 'syed');
  N.inventory.put({ id: 'ap1', name: 'AP-01', vendor: 'other', ip: '10.0.0.9', site: 'Riyadh HQ' }, 'syed'); // no poll → unpolled
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const ctx = { role: 'viewer', user: 'u', params: {}, query: {}, need: () => true, ok: (b) => b };
  const v = await R['GET /api/soc/netops/npm'](ctx);
  assert.equal(v.total, 3);
  assert.deepEqual([v.counts.up, v.counts.critical, v.counts.unknown], [1, 1, 1]);
  const cisco = v.vendors.find((x) => x.vendor === 'Cisco IOS'); assert.equal(cisco.nodes[0].name, 'CORE-SW1'); assert.equal(cisco.nodes[0].state, 'up'); assert.equal(cisco.nodes[0].response_ms, 2);
  assert.equal(cisco.nodes[0].cpu, 45); assert.equal(cisco.nodes[0].mem, 70); // CPU/memory carried for the NOC overview tiles
  assert.equal(v.interfaces[0].node, 'CORE-SW1'); assert.equal(v.interfaces[0].util, 91); // sorted by utilisation, hottest first
  assert.equal(v.high_interfaces, 1);
  // every coloured dot says why
  const fw = v.vendors.find((x) => x.vendor === 'Fortinet').nodes[0], ap = v.vendors.find((x) => x.vendor === 'Other').nodes[0];
  assert.equal(fw.reason, 'snmp: timeout'); assert.equal(cisco.nodes[0].reason, '');
  assert.match(ap.reason, /not polled yet/);
});

test('routes: NPM no-reply reason, and POST /netops/poll — operator starts one cycle, never two at once, viewer refused, audited', async () => {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = { sw9: { at: 1, ok: false, errors: [], sources: ['ping'], reach: { sent: 3, received: 0, loss_pct: 100 } } };
  let cycles = 0, running = false, finish;
  const fakePoller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({ running }), forget() {}, start() {}, pollDevice: async () => ({}),
    cycle: () => { cycles++; running = true; return new Promise((r) => { finish = () => { running = false; r(); }; }); } };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller });
  N.inventory.put({ id: 'sw9', name: 'SW-SYN-9', vendor: 'cisco-ios', ip: '10.9.9.9', site: 'Riyadh', poll: { ping: true } }, 'syed');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  const call = async (m, p, role) => { const o = {}; const ctx = { role, user: 'op1', body: {}, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit: (a) => audits.push(a), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  const v = (await call('GET', '/npm', 'viewer')).b;
  assert.match(v.vendors[0].nodes[0].reason, /no reply to ping from the engine server \(3 sent\)/);
  assert.equal((await call('POST', '/poll', 'viewer')).s, 403, 'a viewer cannot start polling');
  assert.equal(cycles, 0);
  const a = await call('POST', '/poll', 'operator');
  assert.equal(a.s, 200); assert.equal(a.b.started, true); assert.equal(a.b.devices, 1); assert.equal(cycles, 1);
  const b = await call('POST', '/poll', 'operator');
  assert.equal(b.b.started, false, 'a cycle already running is not started twice'); assert.equal(cycles, 1);
  finish(); await new Promise((r) => setImmediate(r));
  assert.equal((await call('POST', '/poll', 'admin')).b.started, true); assert.equal(cycles, 2); finish();
  assert.equal(audits.filter((x) => x === 'netops.poll.all').length, 3);
});

test('routes: SD-WAN — control, site health, transport distribution, edge inventory, tunnel table (from paths)', async () => {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = {
    // Riyadh edge: both tunnels alive, two transports (one <10, one 100-500) → normal / full site
    'e1': { at: 1, ok: true, errors: [], reach: { rtt_avg_ms: 8, received: 3, loss_pct: 0 }, interfaces: [{ name: 'wan1', oper: 'up', speed_mbps: 1000 }, { name: 'wan2', oper: 'up', speed_mbps: 5 }],
      paths: [{ name: 'INET', member: 'wan1', status: 'alive', latency_ms: 10, jitter_ms: 1, loss_pct: 0 }, { name: 'MPLS', member: 'wan2', status: 'alive', latency_ms: 20, jitter_ms: 2, loss_pct: 0 }] },
    // Jeddah edge: one tunnel dead → warning / partial site
    'e2': { at: 1, ok: true, errors: [], reach: { rtt_avg_ms: 30, received: 3, loss_pct: 0 }, interfaces: [{ name: 'wan1', oper: 'up', speed_mbps: 200 }],
      paths: [{ name: 'INET', member: 'wan1', status: 'alive', latency_ms: 25, jitter_ms: 3, loss_pct: 0 }, { name: 'LTE', member: 'wwan', status: 'dead', latency_ms: 210, jitter_ms: 40, loss_pct: 100 }] },
  };
  const fakePoller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({ polls: 2 }), forget() {}, start() {}, pollDevice: async () => ({}) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller });
  N.inventory.put({ id: 'e1', name: 'SDW-RUH-01', vendor: 'edgeconnect', ip: '10.0.1.1', site: 'Riyadh HQ', role: 'sdwan-appliance', poll: { api: true } }, 'syed');
  N.inventory.put({ id: 'e2', name: 'SDW-JED-01', vendor: 'fortigate', ip: '10.0.2.1', site: 'Jeddah Branch', role: 'wan-edge', poll: { snmp: true } }, 'syed');
  N.inventory.put({ id: 'e3', name: 'SDW-DMM-01', vendor: 'edgeconnect', ip: '10.0.3.1', site: 'Dammam', role: 'sdwan-appliance' }, 'syed'); // never polled → staging / unknown
  N.inventory.put({ id: 'sw', name: 'CORE', vendor: 'cisco-ios', ip: '10.0.0.2', role: 'core' }, 'syed'); // NOT sd-wan — excluded
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const ctx = { role: 'viewer', user: 'u', params: {}, query: {}, need: () => true, ok: (b) => b };
  const v = await R['GET /api/soc/netops/sdwan'](ctx);
  assert.equal(v.inventory.total, 3, 'only the three SD-WAN edges, core switch excluded');
  assert.equal(v.inventory.deployed, 2); assert.equal(v.inventory.staging, 1);
  assert.deepEqual([v.control.up, v.control.partial, v.control.down, v.control.unknown], [1, 1, 0, 1]); // e1 up, e2 partial, e3 never polled → unknown (not miscounted as down)
  assert.deepEqual([v.health.normal, v.health.warning, v.health.error, v.health.unknown], [1, 1, 0, 1]);
  assert.equal(v.siteHealth.full, 1); assert.equal(v.siteHealth.partial, 1); // Riyadh full, Jeddah partial
  assert.equal(v.transportDist['>500'], 1); assert.equal(v.transportDist['<10'], 1); assert.equal(v.transportDist['100-500'], 1);
  assert.equal(v.tunnels[0].name, 'LTE'); assert.equal(v.tunnels[0].loss_pct, 100); // worst tunnel first
  assert.equal(v.tunnels.length, 4);
  const e1 = v.edges.find((e) => e.id === 'e1'); assert.equal(e1.paths_up, 2); assert.equal(e1.state, 'normal');
});

// regression: a "pinned" client used to send its headers (the API key) and body BEFORE comparing the pin, so a device
// impersonator on the management network received the credential and only then was refused. Nothing may arrive now.
test('pinned clients send no header and no body to a device whose certificate does not match the pin', { skip: !haveOpenssl() && 'openssl not available' }, async () => {
  const seen = [];
  const dev = await mockDevice((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { seen.push({ auth: req.headers.authorization || req.headers['x-pan-key'] || '', body: b }); res.end('{}'); }); });
  const wrong = 'AA'.repeat(32);
  try {
    await assert.rejects(require('../engine/netops/http').getRaw('https://127.0.0.1:' + dev.port + '/api', { headers: { Authorization: 'Bearer SYNTH-NETOPS' }, tls: { fingerprint256: wrong } }), /pinned/);
    await assert.rejects(require('../engine/secops/https').request({ url: 'https://127.0.0.1:' + dev.port + '/api', method: 'POST', headers: { Authorization: 'Bearer SYNTH-SECOPS' }, body: { password: 'SYNTH-PW' }, tls: { fingerprint256: wrong } }), /pinned/);
    await new Promise((r) => setTimeout(r, 200));
    assert.deepEqual(seen, [], 'the impersonating device received nothing');
    // the right pin still works
    const ok = await require('../engine/secops/https').request({ url: 'https://127.0.0.1:' + dev.port + '/api', method: 'POST', headers: { Authorization: 'Bearer SYNTH-SECOPS' }, body: { a: 1 }, tls: { fingerprint256: dev.fp } });
    assert.equal(ok.status, 200); assert.equal(seen.length, 1); assert.equal(seen[0].auth, 'Bearer SYNTH-SECOPS');
  } finally { dev.close(); }
});
