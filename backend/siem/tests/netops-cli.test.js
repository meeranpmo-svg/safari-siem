// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only device CLI (engine/netops/cli.js + cli-helper.py): the show-command allowlist, redaction of secrets, SSH
// credentials write-only, host key trust (no login before an administrator trusts the key), roles, the run log, the
// AI tool, and - when Python with Netmiko is available - a real SSH session to a fake Cisco switch.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { check, redact, createCli } = require('../engine/netops/cli');
const { createAI } = require('../engine/netops/ai');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-netcli-'));

test('allowlist: read-only show commands pass, anything else is refused with the reason', () => {
  for (const c of ['show version', 'SHOW  VERSION', 'show interfaces status', 'show interfaces Gi1/0/24', 'show interfaces GigabitEthernet1/0/24', 'show interfaces Te1/1/1 transceiver',
    'show mac address-table address 001a.2b3c.4d5e', 'show mac address-table interface Gi1/0/5', 'show ip arp 10.1.2.3', 'show running-config interface Gi1/0/3',
    'show running-config | include snmp', 'show logging | include LINK-3', 'show vlan brief', 'show cdp neighbors detail', 'show spanning-tree vlan 20', 'show interfaces Po1'])
    assert.ok(check('cisco-ios', c), c);
  for (const c of ['configure terminal', 'conf t', 'reload', 'write memory', 'copy run start', 'clear counters', 'debug all', 'show run', 'sh ver', 'show version ; reload',
    'show version\nreload', 'show tech-support', 'show running-config | redirect tftp://1.2.3.4/x', 'show running-config | append flash:x', 'show interfaces Gi1/0/1 ; conf t', 'show mac address-table address $(id)', 'terminal monitor', ''])
    assert.throws(() => check('cisco-ios', c), (e) => e.code === 400, JSON.stringify(c));
  assert.ok(check('cisco-asa', 'show failover'));
  assert.throws(() => check('cisco-asa', 'show vlan brief'), /not on the read-only list/);
  assert.throws(() => check('fortigate', 'get system status'), /Cisco IOS/);
});

test('redaction: passwords, secrets, keys and SNMP communities never leave the engine', () => {
  const cfg = ['hostname SW1', 'enable secret 9 $9$abcdefg', 'username admin privilege 15 secret 9 $9$zzz', 'username ro password 7 0822455D0A16', 'snmp-server community S3cr3tComm RO 10',
    'snmp-server user mon grp v3 auth sha AuthPass1 priv aes 128 PrivPass1', 'tacacs-server key 7 0822455D0A16', ' key 7 06120A3258', ' ip ospf message-digest-key 1 md5 OspfKey', ' standby 1 authentication md5 key-string HsrpKey',
    'crypto isakmp key IkeKey address 1.2.3.4', 'ntp authentication-key 1 md5 NtpKey 7', 'radius server ISE', ' key IseKey', 'key chain EIGRP', 'crypto key generate rsa modulus 2048', '! password in a comment stays', 'interface Gi1/0/1', ' description uplink'].join('\n');
  const r = redact(cfg);
  for (const s of ['$9$abcdefg', '$9$zzz', '0822455D0A16', 'S3cr3tComm', 'AuthPass1', 'PrivPass1', '06120A3258', 'OspfKey', 'HsrpKey', 'IkeKey', 'NtpKey', 'IseKey']) assert.ok(!r.includes(s), s + ' leaked');
  assert.match(r, /snmp-server community <removed> RO 10/, 'access level kept for the security review');
  assert.match(r, /enable secret 9 <removed>/, "hash type kept for the audit, the hash removed"); assert.match(r, /key chain EIGRP/); assert.match(r, /crypto key generate rsa modulus 2048/); assert.match(r, /description uplink/);
});

async function setup(runner, extraCfg) {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: Object.assign({ enabled: false }, extraCfg || {}) };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const fakePoller = { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {}, pollDevice: async (id) => ({ device_id: id, ok: true }) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller, cliRunner: runner });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push([a, d]), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  return { N, call, audits, secrets, state };
}

function fakeRunner(o = {}) {
  const calls = [];
  const fn = async (req) => {
    calls.push(JSON.parse(JSON.stringify(req)));
    if (req.op === 'version') return o.missing ? { ok: false, kind: 'missing', error: 'Netmiko is not installed (run install/netops-cli-setup.sh)' } : { ok: true, netmiko: '4.8.0', paramiko: '5.0.0', python: '3.11' };
    if (req.op === 'hostkey') return { ok: true, type: 'ssh-rsa', key: o.key || 'AAAAKEY1', fingerprint: o.fp || 'SHA256:abc' };
    if (req.op === 'run') {
      if (o.fail) return o.fail;
      return { ok: true, prompt: 'SW1#', results: req.commands.map((c) => ({ command: c, output: c === 'show running-config' ? 'hostname SW1\nenable secret 9 $9$abc\nsnmp-server community TopSecret RO' : 'out of ' + c,
        parsed: req.textfsm ? (c === 'show version' ? [{ hostname: 'SW1', version: '15.2(7)E8', hardware: ['WS-C2960X-48FPD-L'], serial: ['FOC1234X0AB'], uptime: '12 weeks' }] : [{ name: '1', pid: 'WS-C2960X-48FPD-L', sn: 'FOC1234X0AB' }]) : undefined })) };
    }
    return { ok: false, kind: 'input', error: 'bad op' };
  };
  fn.calls = calls; return fn;
}

test('routes: SSH login write-only, host key must be trusted before any login, roles, redaction, run log, facts', async () => {
  const runner = fakeRunner();
  const { call, audits, secrets, N } = await setup(runner);
  assert.equal((await call('POST', '/devices', { role: 'admin', body: { id: 'acc-sw1', name: 'ACC-SW1', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' } })).status, 200);
  assert.equal((await call('POST', '/devices', { role: 'admin', body: { id: 'fgt1', vendor: 'fortigate', ip: '10.0.0.1' } })).status, 200);
  const st = await call('GET', '/cli'); assert.equal(st.body.status.available, true); assert.ok(st.body.catalogue['cisco-ios'].length > 30);

  // no login yet
  let r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'acc-sw1' }, body: { commands: ['show version'] } });
  assert.equal(r.status, 409); assert.match(r.error, /no SSH login/);
  assert.equal((await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'acc-sw1' }, body: { ssh: { username: 'ro' } } })).status, 400);
  assert.equal((await call('PUT', '/devices/:id/credentials', { role: 'operator', params: { id: 'acc-sw1' }, body: { ssh: { username: 'ro', password: 'pw' } } })).status, 403);
  const cr = await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'acc-sw1' }, body: { ssh: { username: 'ro', password: 'Pw-ro-123', secret: 'En-123' } } });
  assert.equal(cr.body.credentials.ssh, 'user ro + enable');
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).netops.devices['acc-sw1'].ssh.password, 'Pw-ro-123');
  const list = await call('GET', '/devices'); assert.ok(!JSON.stringify(list.body).includes('Pw-ro-123') && !JSON.stringify(list.body).includes('En-123'));

  // host key not trusted → no session is started (password never sent)
  r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'acc-sw1' }, body: { commands: ['show version'] } });
  assert.equal(r.status, 409); assert.match(r.error, /host key .* not trusted/);
  assert.ok(!runner.calls.some((c) => c.op === 'run'));
  assert.equal((await call('POST', '/devices/:id/ssh/hostkey', { role: 'operator', params: { id: 'acc-sw1' } })).status, 403);
  assert.equal((await call('POST', '/devices/:id/ssh/trust', { role: 'admin', params: { id: 'acc-sw1' }, body: { fingerprint: 'SHA256:abc' } })).status, 409, 'must read first');
  const hk = await call('POST', '/devices/:id/ssh/hostkey', { role: 'admin', params: { id: 'acc-sw1' } });
  assert.equal(hk.body.fingerprint, 'SHA256:abc'); assert.equal(hk.body.pinned, null);
  const hkReq = runner.calls.find((c) => c.op === 'hostkey'); assert.equal(hkReq.username, undefined); assert.equal(hkReq.password, undefined, 'no credentials sent to read the key');
  assert.equal((await call('POST', '/devices/:id/ssh/trust', { role: 'admin', params: { id: 'acc-sw1' }, body: { fingerprint: 'SHA256:other' } })).status, 409);
  assert.equal((await call('POST', '/devices/:id/ssh/trust', { role: 'admin', user: 'boss', params: { id: 'acc-sw1' }, body: { fingerprint: 'SHA256:abc' } })).body.by, 'boss');
  assert.equal((await call('GET', '/devices/:id/ssh', { params: { id: 'acc-sw1' } })).body.hostkey.fingerprint, 'SHA256:abc');

  // roles + allowlist
  assert.equal((await call('POST', '/devices/:id/cli', { role: 'analyst', params: { id: 'acc-sw1' }, body: { commands: ['show version'] } })).status, 403);
  r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'acc-sw1' }, body: { commands: ['show version', 'conf t'] } });
  assert.equal(r.status, 400); assert.equal(runner.calls.filter((c) => c.op === 'run').length, 0, 'nothing sent when any command is refused');
  r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'fgt1' }, body: { commands: ['show version'] } }); assert.equal(r.status, 400);

  r = await call('POST', '/devices/:id/cli', { role: 'operator', user: 'eng1', params: { id: 'acc-sw1' }, body: { commands: ['show running-config', 'show  vlan brief'] } });
  assert.equal(r.status, 200); assert.equal(r.body.prompt, 'SW1#');
  assert.ok(!JSON.stringify(r.body).includes('$9$abc') && !JSON.stringify(r.body).includes('TopSecret'));
  const run = runner.calls.find((c) => c.op === 'run');
  assert.deepEqual(run.commands, ['show running-config', 'show vlan brief']); assert.equal(run.device_type, 'cisco_ios'); assert.equal(run.password, 'Pw-ro-123'); assert.equal(run.secret, 'En-123');
  assert.deepEqual(run.known_host, { type: 'ssh-rsa', key: 'AAAAKEY1' });
  const lg = await call('GET', '/cli/log', { role: 'operator' }); assert.equal(lg.body.items[0].by, 'eng1'); assert.equal(lg.body.items[0].via, 'portal');
  assert.equal((await call('GET', '/cli/log', { role: 'analyst' })).status, 403);
  assert.ok(audits.some(([a, d]) => a === 'netops.cli.run' && d.ok === true) && audits.some(([a]) => a === 'netops.ssh.hostkey.trust'));

  const f = await call('POST', '/devices/:id/cli/facts', { role: 'operator', params: { id: 'acc-sw1' } });
  assert.equal(f.body.model, 'WS-C2960X-48FPD-L'); assert.deepEqual(f.body.serials, ['FOC1234X0AB']); assert.equal(f.body.version, '15.2(7)E8');
  assert.equal(N.inventory.get('acc-sw1').cli_facts.model, 'WS-C2960X-48FPD-L');

  // removing the device forgets the trusted key
  assert.equal((await call('DELETE', '/devices/:id', { role: 'admin', params: { id: 'acc-sw1' } })).status, 200);
  assert.equal(N.cli.hostKey('acc-sw1'), null);
});

test('helper failures are explained: Netmiko missing, wrong password, changed host key', async () => {
  for (const [o, code, re] of [[{ missing: true }, 503, /Netmiko is not installed/], [{ fail: { ok: false, kind: 'auth', error: 'login refused: wrong username / password' } }, 409, /login refused/],
    [{ fail: { ok: false, kind: 'hostkey-changed', error: 'the device presented a DIFFERENT SSH host key' } }, 409, /DIFFERENT/]]) {
    const { call } = await setup(fakeRunner(o));
    await call('POST', '/devices', { role: 'admin', body: { id: 'sw', vendor: 'cisco-ios', ip: '10.0.5.9' } });
    await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'sw' }, body: { ssh: { username: 'ro', password: 'pw-12345' } } });
    await call('POST', '/devices/:id/ssh/hostkey', { role: 'admin', params: { id: 'sw' } });
    await call('POST', '/devices/:id/ssh/trust', { role: 'admin', params: { id: 'sw' }, body: { fingerprint: 'SHA256:abc' } });
    const r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'sw' }, body: { commands: ['show version'] } });
    assert.equal(r.status, code); assert.match(r.error, re);
  }
  const { call } = await setup(fakeRunner(), { cli: { enabled: false } });
  assert.equal((await call('GET', '/cli')).body.status.available, false);
});

test('AI tool show_commands: runs through the same allowlist and log, recorded as the AI on behalf of the user', async () => {
  const runner = fakeRunner();
  const { N } = await setup(runner);
  N.inventory.put({ id: 'acc-sw1', name: 'ACC-SW1', vendor: 'cisco-ios', ip: '10.0.5.2' }, 'admin');
  N.inventory.setCredentials('acc-sw1', { ssh: { username: 'ro', password: 'pw-12345' } }, 'admin');
  await N.cli.fetchHostKey('acc-sw1'); N.cli.trustHostKey('acc-sw1', 'SHA256:abc', 'admin');
  let script = [];
  class FakeAnthropic { constructor() { this.beta = { messages: { create: async () => script.shift() } }; this.messages = this.beta.messages; } }
  const state = await createState({ dir: tmp() });
  const ai = createAI({ config: { netops: { ai: {} }, secrets: { netops: { anthropic_api_key: 'sk-test' } } }, state, sdk: FakeAnthropic,
    tools: { inventory: N.inventory, poller: { snapshot: () => null }, findings: () => [], sites: () => [], evidence: {}, changes: {}, cli: N.cli } });
  script = [
    { stop_reason: 'tool_use', model: 'm', usage: {}, content: [{ type: 'tool_use', id: 't1', name: 'show_commands', input: { device: 'ACC-SW1', commands: ['show mac address-table address 001a.2b3c.4d5e', 'show running-config'] } },
      { type: 'tool_use', id: 't2', name: 'show_commands', input: { device: 'acc-sw1', commands: ['configure terminal'] } }, { type: 'tool_use', id: 't3', name: 'list_devices', input: {} }] },
    { stop_reason: 'end_turn', model: 'm', usage: {}, content: [{ type: 'text', text: 'Port Gi1/0/5.' }] },
  ];
  const r = await ai.ask({ question: 'Where is 001a.2b3c.4d5e?', user: 'alice', role: 'operator' });   // show_commands needs operator, like POST /devices/:id/cli
  assert.equal(r.answer, 'Port Gi1/0/5.');
  assert.deepEqual(r.steps.map((s) => [s.tool, s.ok]), [['show_commands', true], ['show_commands', false], ['list_devices', true]]);
  assert.match(r.steps[1].error, /not on the read-only list/);
  const log = N.cli.log(); assert.equal(log.length, 1); assert.equal(log[0].via, 'ai'); assert.match(log[0].by, /asked by alice/);
  const conv = state.collection('netops_chats').all()[0]; const txt = JSON.stringify(conv.messages);
  assert.ok(!txt.includes('TopSecret') && !txt.includes('$9$abc'), 'no secrets sent to the AI');
  assert.match(txt, /\\"ssh_ready\\":true/);
});

// ---- real SSH: cli-helper.py + Netmiko against a fake Cisco switch (skipped when Netmiko is not installed)
function findPython() {
  for (const p of [process.env.SENTRA_TEST_NETMIKO_PY, '/opt/sentra-siem/pyenv/bin/python3', 'python3'].filter(Boolean)) {
    const r = spawnSync(p, ['-c', 'import netmiko'], { stdio: 'ignore' }); if (r.status === 0) return p;
  }
  return null;
}
const PY = findPython();

test('real SSH session through cli-helper.py: host key read without login, pinned key enforced, enable, redaction', { skip: !PY && 'Python with Netmiko not installed (set SENTRA_TEST_NETMIKO_PY)', timeout: 120000 }, async () => {
  const srv = spawn(PY, [path.join(__dirname, 'helpers', 'fake-cisco-ssh.py')], { stdio: ['ignore', 'pipe', 'inherit'] });
  try {
    const port = await new Promise((ok, bad) => { srv.stdout.once('data', (d) => ok(Number(String(d).trim()))); srv.once('exit', () => bad(new Error('fake switch did not start'))); });
    const { call, N } = await setup(undefined, { cli: { python: PY } });
    await call('POST', '/devices', { role: 'admin', body: { id: 'lab-sw', name: 'LAB-SW', vendor: 'cisco-ios', ip: '127.0.0.1' } });
    await call('PUT', '/devices/:id/credentials', { role: 'admin', params: { id: 'lab-sw' }, body: { ssh: { username: 'ro', password: 'pw-ro', secret: 'en-secret', port } } });
    assert.equal((await call('GET', '/cli')).body.status.available, true);
    const hk = await call('POST', '/devices/:id/ssh/hostkey', { role: 'admin', params: { id: 'lab-sw' } });
    assert.equal(hk.status, 200, hk.error); assert.match(hk.body.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
    await call('POST', '/devices/:id/ssh/trust', { role: 'admin', params: { id: 'lab-sw' }, body: { fingerprint: hk.body.fingerprint } });
    const r = await call('POST', '/devices/:id/cli', { role: 'operator', params: { id: 'lab-sw' }, body: { commands: ['show version', 'show running-config'] } });
    assert.equal(r.status, 200, r.error); assert.equal(r.body.prompt, 'SW1#');
    assert.match(r.body.results[0].output, /WS-C2960X-48FPD-L/);
    assert.match(r.body.results[1].output, /hostname SW1/); assert.ok(!r.body.results[1].output.includes('S3cr3tComm') && !r.body.results[1].output.includes('$9$'));
    const f = await call('POST', '/devices/:id/cli/facts', { role: 'operator', params: { id: 'lab-sw' } });
    assert.equal(f.status, 200, f.error); assert.equal(f.body.model, 'WS-C2960X-48FPD-L'); assert.deepEqual(f.body.serials, ['FOC1234X0AB']);
    // a different pinned key (device replaced / someone in the middle): the helper refuses before authenticating
    const st2 = await createState({ dir: tmp() }); st2.collection('netops_ssh_hostkeys').put({ id: 'lab-sw', type: 'ssh-rsa', key: 'AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7' + 'A'.repeat(168), fingerprint: 'SHA256:x' });
    const forged = createCli({ inventory: N.inventory, state: st2, config: { netops: { cli: { python: PY } } } });
    await assert.rejects(forged.run('lab-sw', ['show version']), (e) => e.code === 409 && /hostkey-changed/.test(e.kind));
    // wrong password
    N.inventory.setCredentials('lab-sw', { ssh: { username: 'ro', password: 'wrong-pass', port } }, 'admin');
    await assert.rejects(N.cli.run('lab-sw', ['show version']), (e) => e.code === 409 && e.kind === 'auth');
  } finally { srv.kill(); }
});

test('H3C / HPE Comware: display commands only, Comware secrets removed with the storage mode kept, the helper refuses show on Comware', () => {
  const { check, redact, CATALOGUE, DEVICE_TYPE } = require('../engine/netops/cli');
  assert.equal(DEVICE_TYPE['h3c-comware'], 'hp_comware');
  assert.ok(CATALOGUE['h3c-comware'].every(([c]) => /^display /.test(c)), 'every Comware command is a display command');
  assert.equal(check('h3c-comware', 'display interface brief'), 'display interface brief');
  assert.equal(check('h3c-comware', 'display interface Ten-GigabitEthernet1/0/49'), 'display interface Ten-GigabitEthernet1/0/49');
  assert.equal(check('h3c-comware', 'display mac-address 0011-2233-4455'), 'display mac-address 0011-2233-4455');
  assert.equal(check('h3c-comware', 'display current-configuration | include sysname'), 'display current-configuration | include sysname');
  for (const bad of ['system-view', 'undo shutdown', 'save force', 'reboot', 'display interface brief; reboot', 'show version', 'display current-configuration\nsave'])
    assert.throws(() => check('h3c-comware', bad), /read-only list|invalid command/, bad);
  const cfg = [
    'local-user admin class manage', ' password hash $h$6$SyntheticHash==', ' service-type ssh',
    'local-user old class manage', ' password simple SyntheticClear1',
    'snmp-agent community read cipher $c$3$SyntheticCipher==', 'snmp-agent community write simple synthetic-rw',
    'snmp-agent usm-user v3 sentra-snmp SENTRA-RO cipher authentication-mode sha $c$3$AuthSyn== privacy-mode aes128 $c$3$PrivSyn==',
    'radius scheme rad', ' key authentication cipher $c$3$RadSyn==', 'ike keychain k1', ' pre-shared-key address 10.0.0.1 255.255.255.255 key cipher $c$3$PskSyn==',
    'sysname test-sw-01', 'interface GigabitEthernet1/0/1', ' description uplink'].join('\n');
  const out = redact(cfg);
  for (const secret of ['SyntheticHash', 'SyntheticClear1', 'SyntheticCipher', 'synthetic-rw', 'AuthSyn', 'PrivSyn', 'RadSyn', 'PskSyn']) assert.ok(!out.includes(secret), 'removed: ' + secret);
  assert.match(out, /password hash <removed>/); assert.match(out, /password simple <removed>/, 'a clear-text password is still visible as "simple" to the auditor');
  assert.match(out, /community read cipher <removed>/); assert.match(out, /authentication-mode sha <removed> privacy-mode aes128 <removed>/);
  assert.match(out, /sysname test-sw-01/); assert.match(out, / description uplink/);
  // the helper's own check: on hp_comware only display, elsewhere only show / get
  const { spawnSync } = require('node:child_process'), path = require('node:path');
  const helper = path.join(__dirname, '../engine/netops/cli-helper.py');
  const ask = (req) => { const r = spawnSync('python3', ['-I', helper], { input: JSON.stringify(req), encoding: 'utf8' }); try { return JSON.parse(r.stdout); } catch { return { raw: r.stdout + r.stderr }; } };
  const base = { op: 'run', host: '192.0.2.10', port: 22, username: 'u', password: 'p', known_host: { type: 'ssh-ed25519', key: 'AAAA' } };
  const a = ask(Object.assign({}, base, { device_type: 'hp_comware', commands: ['show version'] }));
  const b = ask(Object.assign({}, base, { device_type: 'cisco_ios', commands: ['display version'] }));
  const c = ask(Object.assign({}, base, { device_type: 'hp_comware', commands: ['display version; reboot'] }));
  if (a.kind === 'missing') return;   // Netmiko not installed here: the import check runs first, the Node-side checks above still hold
  assert.equal(a.kind, 'input', JSON.stringify(a)); assert.equal(b.kind, 'input', JSON.stringify(b)); assert.equal(c.kind, 'input', JSON.stringify(c));
});
