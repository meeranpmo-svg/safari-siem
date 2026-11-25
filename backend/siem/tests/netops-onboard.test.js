// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network onboarding + architecture (engine/netops/onboard.js), the Cisco UCS collector (collectors.ucs) and the two IOS
// management-hardening tasks (tasks.js vty-ssh-only / http-server-off): one form per vendor with every field validated and
// named, credentials stored write-only, verification (reach, read, least privilege - UCS privileges and Cisco "show privilege",
// an over-privileged account refused and its polling switched off -, SSH host key pending until trusted, facts, baseline,
// route map), placement in the route map (admin, versioned), the architecture layers and links (route map + CDP neighbours),
// the configuration matrix (pass / fail / not measured / n/a), fixes as change plans (FortiGate allowaccess with its rollback;
// Cisco IOS as approved tasks), four-eyes, roles and audit. SYNTHETIC devices.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const C = require('../engine/netops/collectors');
const T = require('../engine/netops/tasks');

test('Cisco UCS collector: read-only login recorded, admin login flagged, faults filtered, logout always', async () => {
  const sent = [];
  const mk = (priv, failClass) => async (body) => { sent.push(body);
    if (/aaaLogin/.test(body)) return { status: 200, text: `<aaaLogin cookie="" response="yes" outCookie="1700/abc" outPriv="${priv}" />` };
    if (/aaaLogout/.test(body)) return { status: 200, text: '<aaaLogout response="yes" outStatus="success" />' };
    const cls = /classId="(\w+)"/.exec(body)[1];
    if (cls === failClass) return { status: 200, text: `<configResolveClass errorCode="552" errorDescr="Authorization required" />` };
    const R = { topSystem: '<topSystem name="UCS-SYN" address="10.0.7.1" systemUpTime="10:00" mode="cluster" />', equipmentChassis: '<equipmentChassis dn="sys/chassis-1" model="UCSB-5108-AC2" serial="FOX0000SYN" operState="operable" />',
      computeBlade: '<computeBlade dn="sys/chassis-1/blade-1" model="UCSB-B200-M5" serial="FLM0001SYN" operState="ok" operPower="on" numOfCpus="2" totalMemory="393216" />',
      computeRackUnit: '', firmwareRunning: '<firmwareRunning dn="sys/mgmt/fw-system" version="4.2(3h)" type="system" /><firmwareRunning dn="sys/chassis-1/blade-1/mgmt/fw-system" version="4.2(3h)" />',
      faultInst: '<faultInst severity="major" code="F0283" descr="Fan &quot;1&quot; inoperable" dn="sys/chassis-1/fan-module-1-1/fan-1/fault-F0283" created="2026-10-30" ack="no" /><faultInst severity="cleared" code="F1" descr="old" dn="x" /><faultInst severity="info" code="F2" descr="info" dn="y" />' };
    return { status: 200, text: `<configResolveClass cookie="1700/abc" response="yes" classId="${cls}"><outConfigs>${R[cls] || ''}</outConfigs></configResolveClass>` }; };
  let r = await C.ucs({ ip: '10.0.7.1' }, { username: 'sentra-ro', password: 'Pw<&"x' }, { post: mk('read-only') });
  assert.equal(r.ucs.read_only, true); assert.deepEqual(r.ucs.privileges, ['read-only']);
  assert.equal(r.system.name, 'UCS-SYN'); assert.equal(r.system.version, 'UCS Manager 4.2(3h)'); assert.equal(r.system.model, 'UCSB-5108-AC2');
  assert.equal(r.ucs.blades[0].mem_mb, 393216); assert.equal(r.ucs.faults.length, 1, 'cleared and info faults dropped'); assert.equal(r.ucs.faults[0].descr, 'Fan "1" inoperable');
  assert.match(sent[0], /inPassword="Pw&lt;&amp;&quot;x"/, 'the password is XML-escaped'); assert.match(sent[sent.length - 1], /aaaLogout inCookie="1700\/abc"/);
  sent.length = 0; r = await C.ucs({ ip: '10.0.7.1' }, { username: 'a', password: 'b' }, { post: mk('admin,read-only', 'faultInst') });
  assert.equal(r.ucs.read_only, false, 'admin is over-privileged'); assert.ok(r.errors.some((e) => /faultInst: Authorization required/.test(e))); assert.match(sent[sent.length - 1], /aaaLogout/, 'logout even after a failed read');
  await assert.rejects(C.ucs({ ip: '1.1.1.1' }, { username: 'a', password: 'b' }, { post: async () => ({ status: 200, text: '<aaaLogin response="yes" errorCode="551" errorDescr="Authentication failed" />' }) }), /login failed: Authentication failed/);
});

test('IOS hardening tasks: SSH-only refuses when SSH is off or already done, plans every VTY block with its rollback; HTTP off', () => {
  const V = T.TEMPLATES['vty-ssh-only'], Hh = T.TEMPLATES['http-server-off'];
  const cfg = 'line vty 0 4\n transport input telnet ssh\nline vty 5 15\n exec-timeout 5 0\n';
  assert.throws(() => V.plan({}, ['SSH Disabled - version 1.99', cfg]), /SSH is not enabled/);
  const p = V.plan({}, ['SSH Enabled - version 2.0', cfg]);
  assert.deepEqual(p.commands, ['line vty 0 4', ' transport input ssh', 'line vty 5 15', ' transport input ssh']);
  assert.deepEqual(p.rollback, ['line vty 0 4', ' transport input telnet ssh', 'line vty 5 15', ' default transport input']);
  assert.throws(() => V.plan({}, ['SSH Enabled', 'line vty 0 15\n transport input ssh\n']), /already allows SSH only/);
  assert.equal(V.check({}, ['line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh\n']).ok, true);
  assert.equal(V.check({}, [cfg]).ok, false);
  assert.deepEqual(Hh.plan({}, ['ip http server\nip http secure-server\n']), { commands: ['no ip http server'], rollback: ['ip http server'] });
  assert.throws(() => Hh.plan({}, ['ip http secure-server\n']), /already off/);
});

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ob-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, syslog_target: '10.0.0.50' } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const now = Date.now(), snaps = {}, SNAP = {};
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {}, pollDevice: async (id) => { snaps[id] = Object.assign({ device_id: id, at: Date.now(), ok: true, errors: [], sources: ['ping'] }, SNAP[id] || {}); return snaps[id]; } };
  const W = { priv: 15 };
  const runner = async (q) => (q.op === 'version' ? { ok: true, netmiko: '4.8.0' } : q.op === 'hostkey' ? { ok: true, type: 'ssh-rsa', key: 'AAAAKEY1', fingerprint: 'SHA256:corekey' }
    : q.op === 'run' ? { ok: true, prompt: 'CORE#', results: q.commands.map((c) => ({ command: c, output: c === 'show privilege' ? 'Current privilege level is ' + W.priv : '' })) } : { ok: false, error: 'bad op' });
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, cliRunner: runner });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, params = {}, query = {} } = {}) {
    const o = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { o.status = c; o.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.status) { o.status = 200; o.body = rv; } return o;
  }
  return { N, call, audits, SNAP, snaps, W, secrets, now, state };
}
const ADMIN = { role: 'admin', user: 'syed' };
const step = (r, k) => r.steps.find((s) => s.key === k);

test('onboarding: validation, credentials write-only, verification per vendor, over-privileged refused, host key, route map, architecture, fixes, roles, audit', async () => {
  const { N, call, audits, SNAP, W, secrets, state } = await setup();
  const cat = (await call('GET', '/onboard/catalogue')).body;
  assert.deepEqual(cat.vendors.map((v) => v.vendor).sort(), ['cisco-asa', 'cisco-ios', 'cisco-ucs', 'fortigate', 'genian', 'h3c-comware', 'other', 'paloalto']);
  assert.match(cat.vendors.find((v) => v.vendor === 'other').label, /UPS-MIB/); assert.deepEqual(cat.vendors.find((v) => v.vendor === 'other').roles, ['ups']);
  assert.ok(cat.vendors.find((v) => v.vendor === 'cisco-ucs').account.includes('create role read-only')); assert.ok(cat.vendors.find((v) => v.vendor === 'fortigate').logs.join(' ').includes('10.0.0.50'));
  // validation and roles
  const FG = { vendor: 'fortigate', name: 'FGT-JED-SYN', ip: '10.2.0.1', site: 'Jeddah Branch', credentials: { api: { token: 'fg-secret-token-123' } } };
  assert.equal((await call('POST', '/onboard', { role: 'operator', body: FG })).status, 403);
  let r = await call('POST', '/onboard', Object.assign({ body: Object.assign({}, FG, { vendor: 'juniper' }) }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /vendor must be one of/);
  r = await call('POST', '/onboard', Object.assign({ body: Object.assign({}, FG, { credentials: {} }) }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /credentials\.api\.token/);
  r = await call('POST', '/onboard', Object.assign({ body: Object.assign({}, FG, { role: 'core' }) }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /role: a Fortinet FortiGate is one of/);
  r = await call('POST', '/onboard', Object.assign({ body: { vendor: 'cisco-ios', name: 'SW-X', ip: '10.0.5.9', role: 'access', credentials: { snmp: { version: '2c', community: 'public' } } } }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /use SNMPv3/);
  r = await call('POST', '/onboard', Object.assign({ body: { vendor: 'other', name: 'UPS-X', ip: '10.0.5.8', role: 'core', credentials: { snmp: { version: '3', user: 'sentra-snmp' } } } }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /role: a UPS .* is one of ups/);
  r = await call('POST', '/onboard', Object.assign({ body: { vendor: 'other', name: 'UPS-X', ip: '10.0.5.8', credentials: {} } }, ADMIN)); assert.equal(r.status, 400); assert.match(r.error, /SNMPv3 user/);
  // FortiGate: reachable, read, privilege manual, baseline with a high finding, not in the map yet
  SNAP['fgt-jed-syn'] = { reach: { sent: 3, received: 3, rtt_avg_ms: 12 }, sources: ['ping', 'api'], system: { model: 'FortiGate-100F', version: 'v7.4.3' }, interfaces: [], security: { at: Date.now(), items: [{ kind: 'mgmt-telnet', severity: 'high', key: 'port1', title: 'Telnet administration enabled on port1', evidence: ['allowaccess: ping https ssh telnet'], rec: 'Remove telnet' }, { kind: 'fw-nolog', severity: 'medium', key: '7', title: 'Policy 7 accepts traffic without logging', evidence: [] }], facts: { fg: true } } };
  r = await call('POST', '/onboard', Object.assign({ body: FG }, ADMIN)); assert.equal(r.status, 200, r.error);
  assert.deepEqual(['reach', 'read', 'privilege', 'facts', 'baseline', 'routemap'].map((k) => step(r.body, k).state), ['ok', 'ok', 'manual', 'ok', 'fail', 'pending']);
  assert.equal(r.body.status, 'in progress'); assert.equal(N.inventory.get('fgt-jed-syn').poll.api, true);
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).netops.devices['fgt-jed-syn'].api.token, 'fg-secret-token-123');
  assert.ok(!JSON.stringify((await call('GET', '/onboard')).body).includes('fg-secret-token-123'), 'credentials are never returned');
  // UCS with an admin account: refused, polling off
  SNAP['ucs-syn'] = { reach: { sent: 3, received: 3 }, sources: ['ping', 'api'], system: { model: 'UCSB-5108-AC2', version: 'UCS Manager 4.2(3h)' }, ucs: { read_only: false, privileges: ['admin'], faults: [{ severity: 'major', descr: 'Fan 1 inoperable' }] } };
  r = await call('POST', '/onboard', Object.assign({ body: { vendor: 'cisco-ucs', name: 'UCS-SYN', ip: '10.0.7.1', site: 'Riyadh DC', credentials: { api: { username: 'admin', password: 'Pw-ucs-1' } } } }, ADMIN));
  assert.equal(r.status, 200, r.error); assert.equal(r.body.status, 'blocked'); assert.equal(step(r.body, 'privilege').state, 'fail'); assert.match(step(r.body, 'privilege').fix, /read-only/);
  assert.equal(N.inventory.get('ucs-syn').poll.api, false, 'polling with the over-privileged account stopped'); assert.match(r.body.note, /over-privileged/);
  SNAP['ucs-syn'].ucs = { read_only: true, privileges: ['read-only'], faults: [{ severity: 'major', descr: 'Fan 1 inoperable' }] };
  r = await call('POST', '/onboard', Object.assign({ body: { vendor: 'cisco-ucs', name: 'UCS-SYN', ip: '10.0.7.1', site: 'Riyadh DC', credentials: { api: { username: 'sentra-ro', password: 'Pw-ucs-2' } } } }, ADMIN));
  assert.equal(step(r.body, 'privilege').state, 'ok'); assert.equal(N.inventory.get('ucs-syn').poll.api, true);
  // Cisco core switch: host key pending, then privilege 15 refused, then privilege 1 accepted
  SNAP['core-dc-syn'] = { reach: { sent: 3, received: 3 }, sources: ['ping', 'snmp'], system: { model: 'C9500-24Y4C', version: '17.9.4' }, security: { at: Date.now(), items: [{ kind: 'telnet-open', severity: 'high', key: 'telnet', title: 'Telnet is open on CORE-DC-SYN', evidence: [] }] } };
  const CORE = { vendor: 'cisco-ios', name: 'CORE-DC-SYN', ip: '10.0.0.2', site: 'Riyadh DC', role: 'core', credentials: { snmp: { version: '3', user: 'sentra-snmp', authProto: 'sha', authKey: 'auth-pass-1', privKey: 'priv-pass-1' }, ssh: { username: 'sentra-ro', password: 'Pw-ssh-1' } } };
  r = await call('POST', '/onboard', Object.assign({ body: CORE }, ADMIN));
  assert.equal(step(r.body, 'hostkey').state, 'pending'); assert.match(step(r.body, 'hostkey').detail, /SHA256:corekey/);
  await call('POST', '/devices/:id/ssh/trust', Object.assign({ params: { id: 'core-dc-syn' }, body: { fingerprint: 'SHA256:corekey' } }, ADMIN));
  r = await call('POST', '/onboard/:id/verify', { role: 'operator', params: { id: 'core-dc-syn' } });
  assert.equal(step(r.body, 'privilege').state, 'fail'); assert.equal(r.body.status, 'blocked'); assert.equal(N.inventory.get('core-dc-syn').poll.snmp, false);
  W.priv = 1; await call('POST', '/onboard', Object.assign({ body: CORE }, ADMIN));
  r = await call('POST', '/onboard/:id/verify', { role: 'operator', params: { id: 'core-dc-syn' } }); assert.equal(step(r.body, 'privilege').state, 'ok'); assert.equal(step(r.body, 'hostkey').state, 'ok');
  // route map placement
  assert.equal((await call('POST', '/onboard/:id/route-map', { role: 'operator', params: { id: 'fgt-jed-syn' }, body: {} })).status, 403);
  const plan = (await call('GET', '/onboard/:id/route-map', { role: 'analyst', params: { id: 'core-dc-syn' } })).body; assert.equal(plan.node.kind, 'core');
  r = await call('POST', '/onboard/:id/route-map', Object.assign({ params: { id: 'core-dc-syn' }, body: { baseVersion: plan.version } }, ADMIN)); assert.equal(r.status, 200, r.error);
  r = await call('POST', '/onboard/:id/route-map', Object.assign({ params: { id: 'ucs-syn' }, body: { baseVersion: 0 } }, ADMIN)); assert.equal(r.status, 409, 'a stale version is refused'); assert.match(r.error, /changed/);
  r = await call('POST', '/onboard/:id/route-map', Object.assign({ params: { id: 'ucs-syn' }, body: {} }, ADMIN)); assert.equal(r.status, 200, r.error);
  const m = N.routemap.map(); assert.ok(m.nodes.some((n) => n.device === 'ucs-syn' && n.kind === 'compute'));
  const nid = (d) => m.nodes.find((n) => n.device === d).id; assert.ok(m.links.some((l) => [l.a, l.b].sort().join('|') === [nid('core-dc-syn'), nid('ucs-syn')].sort().join('|')), 'compute below the core');
  assert.equal(m.nodes.filter((n) => n.device === 'core-dc-syn').length, 1, 'the core is not added twice');
  // the port map read CDP on the core switch: the FortiGate is its neighbour
  state.collection('portmap_reads').put({ id: 'core-dc-syn', at: Date.now(), ports: [], macs: [], neighbours: [{ local: 'Te1/1/1', name: 'FGT-JED-SYN.as.local', ip: '', via: 'cdp' }], poe: { modules: [], ports: {} }, trunks: [], arp: [], vlans: {} });
  // architecture
  const arch = (await call('GET', '/architecture')).body;
  assert.ok(arch.links.some((l) => [l.a, l.b].sort().join('|') === 'core-dc-syn|fgt-jed-syn' && /cdp neighbour \(Te1\/1\/1\)/.test(l.via)), 'a CDP neighbour becomes a link');
  assert.deepEqual(arch.layers.map((l) => l.id), ['firewall', 'core', 'compute']);
  const row = (id) => arch.matrix.find((x) => x.device === id), ctl = (id, c) => row(id).controls.find((x) => x.control === c);
  assert.equal(ctl('fgt-jed-syn', 'MGMT').state, 'fail'); assert.equal(ctl('fgt-jed-syn', 'FW-LOG').state, 'fail'); assert.equal(ctl('fgt-jed-syn', 'DOCUMENTED').state, 'fail');
  assert.equal(ctl('fgt-jed-syn', 'CONFIG-AUDIT').state, 'pass'); assert.equal(ctl('fgt-jed-syn', 'HW-FAULTS').state, 'n/a');
  assert.equal(ctl('ucs-syn', 'HW-FAULTS').state, 'fail'); assert.equal(ctl('ucs-syn', 'FW-POLICY').state, 'n/a'); assert.equal(ctl('ucs-syn', 'DOCUMENTED').state, 'pass'); assert.equal(ctl('ucs-syn', 'LEAST-PRIV').state, 'pass');
  assert.equal(ctl('core-dc-syn', 'CONFIG-AUDIT').state, 'fail'); assert.equal(ctl('core-dc-syn', 'MGMT').state, 'fail');
  assert.ok(arch.links.some((l) => [l.a, l.b].sort().join('|') === 'core-dc-syn|ucs-syn'), 'route-map link drawn');
  assert.ok(arch.summary.compliance_pct > 0 && arch.summary.compliance_pct < 100);
  // fixes
  assert.equal((await call('POST', '/architecture/fix', { role: 'analyst', body: { device: 'fgt-jed-syn', control: 'MGMT' } })).status, 403);
  r = await call('POST', '/architecture/fix', { role: 'operator', body: { device: 'fgt-jed-syn', control: 'NOPE' } }); assert.equal(r.status, 400);
  r = await call('POST', '/architecture/fix', { role: 'operator', body: { device: 'fgt-jed-syn', control: 'CONFIG-AUDIT' } }); assert.equal(r.status, 409, 'a passing control has nothing to fix');
  r = await call('POST', '/architecture/fix', { role: 'operator', user: 'nora.syn', body: { device: 'fgt-jed-syn', control: 'MGMT' } }); assert.equal(r.status, 200, r.error);
  assert.equal(r.body.automatic, false); assert.ok(r.body.commands.includes('    set allowaccess ping https ssh')); assert.ok(r.body.rollback.includes('    set allowaccess ping https ssh telnet'));
  assert.throws(() => N.changes.decide(r.body.plans[0].id, 'approved', 'nora.syn'), /someone other than its author/);
  r = await call('POST', '/architecture/fix', { role: 'operator', body: { device: 'core-dc-syn', control: 'MGMT' } }); assert.equal(r.status, 200, r.error);
  assert.equal(r.body.automatic, true); assert.deepEqual(N.changes.get(r.body.plans[0].id).task, { type: 'vty-ssh-only', params: {} });
  const acts = audits.map((a) => a.a);
  for (const a of ['netops.onboard', 'netops.onboard.verify', 'netops.onboard.routemap', 'netops.architecture.fix']) assert.ok(acts.includes(a), a);
  assert.ok(!/Pw-ssh-1|Pw-ucs|fg-secret|auth-pass/.test(JSON.stringify(audits)), 'no secret in the audit');
});
