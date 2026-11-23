// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Baseline Hardening (engine/hardening.js + pyengine/hardening_rules.py): every asset in the register classified and scanned
// against its CIS benchmark from READ-ONLY sources - the SIEM Windows agent snapshot (matched by host name or IP), the
// platform's SSH read for Oracle Linux / Solaris, the SIEM's captured Cisco running-config and the firewall poller findings.
// An asset without a source is NOT SCANNED with what to connect (never compliant), an unreadable setting NOT CHECKED, the SIEM
// down says so. Roles: viewer sees scores only, operator the checks and the fix script; scan and script audited; validation.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createHardening, registerHardeningRoutes, classify } = require('../engine/hardening');

const ADM = { user: 'syed', role: 'admin' }, OPR = { user: 'omar.syn', role: 'operator' }, VWR = { user: 'v.syn', role: 'viewer' };
const NOW = Date.parse('2026-10-26T06:00:00Z');
const call = (e, m, p, who, b) => e.req(m, p, { user: who.user, role: who.role, body: b });
const WIN = { os: { caption: 'Microsoft Windows Server 2022 Standard', product_type: 3 }, secpol: { MinimumPasswordLength: '8', PasswordComplexity: '1', LockoutBadCount: '0' },
  reg: { LmCompatibilityLevel: 5, RdpDeny: 1 }, smb: { smb1: true, signing_required: true }, firewall: [{ name: 'Domain', enabled: true, inbound: 'Block' }], last_hotfix: '2026-10-10' };
const W11 = { os: { caption: 'Microsoft Windows 11 Enterprise', product_type: 1 }, secpol: { MinimumPasswordLength: '14' }, reg: {}, bitlocker: [{ drive: 'C:', protection: 0 }] };
const IOS = 'hostname SW-SYN\nservice password-encryption\nenable secret 9 <removed>\nip ssh version 2\nline vty 0 4\n transport input telnet ssh\n';
const FW = { id: 'fw1', name: 'FW-SYN', vendor: 'fortigate', ip: '10.9.0.1', monitoring: { api: true }, security_at: NOW - 3600000, security: [{ kind: 'fw-any-any', key: 'policy 12', title: 'any-any allow' }] };

async function setup(t, siemDown) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (r) => { audits.push(r); if (orig) orig.call(e.app, r); };
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const ids = {
    win: mk({ name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2022', mgmt_ip: '10.8.0.11' }).id,
    w11: mk({ name: 'LAPTOP-SYN', type: 'laptop', os: 'Windows 11 Enterprise' }).id,
    win2: mk({ name: 'NOAGENT-SYN', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.12' }).id,
    ol: mk({ name: 'OL-SYN-APP', type: 'vm', os: 'Oracle Linux Server 8.9', mgmt_ip: '10.8.0.22' }).id,
    sol: mk({ name: 'SOL-SYN-DB', type: 'server', os: 'Oracle Solaris 11.4', mgmt_ip: '10.8.0.21' }).id,
    sw: mk({ name: 'SW-SYN', type: 'network', vendor: 'Cisco', os: 'IOS 15.2', mgmt_ip: '10.9.0.2' }).id,
    fw: mk({ name: 'FW-SYN', type: 'network', vendor: 'Fortinet', model: 'FortiGate 200F', mgmt_ip: '10.9.0.1' }).id,
    esx: mk({ name: 'ESX-SYN', type: 'server', os: 'VMware ESXi 7.0', mgmt_ip: '10.8.0.31' }).id,
    esx2: mk({ name: 'ESX-NOREAD', type: 'server', os: 'VMware ESXi 8.0', mgmt_ip: '10.8.0.32' }).id,
    ntx: mk({ name: 'NTX-N1', type: 'server', vendor: 'Nutanix', os: 'Nutanix AHV', mgmt_ip: '10.9.9.11' }).id,
  };
  mk({ name: 'PRINTER-SYN', type: 'printer' });   // not in scope
  e.app.store.collection('server_os_health').put({ id: ids.ol, at: new Date(NOW - 3600000).toISOString(), server: { os: 'Oracle Linux 8.9', harden: { sshd: 'PermitRootLogin yes\n', selinux: 'Enforcing', uid0: 'root\n', updates: 'na' } } });
  const reads = [];
  const siem = async (path) => {
    reads.push(path);
    if (siemDown) return { _down: 'the SIEM did not answer' };
    if (path === '/hardening/snapshots') return { available: true, hosts: [{ host: 'app-syn-01.corp.test', at: new Date(NOW - 7200000).toISOString(), settings: WIN }, { host: 'laptop-syn', at: new Date(NOW).toISOString(), settings: W11 }] };
    if (path === '/audit/evidence/network') return { available: true, devices: [FW, { id: 'sw1', name: 'SW-SYN', vendor: 'cisco-ios', ip: '10.9.0.2', config: { sha256: 'a'.repeat(64) } }] };
    if (path === '/audit/evidence/network/config/sw1') return { id: 'sw1', at: new Date(NOW).toISOString(), text: IOS };
    return { _down: 'unexpected ' + path };
  };
  // ESXi and Nutanix facts as virt-capacity.js hardeningRead keeps them (one vCenter that read ESX-SYN, one Prism)
  const virtFacts = () => [{ id: 'vp_vc1', kind: 'esxi', label: 'VC-SYN', at: new Date(NOW - 3600000).toISOString(), error: null,
      hosts: [{ id: 'host-11', name: 'esx-syn.corp.test', version: '7.0.3', build: '1', read: {}, services: { 'TSM-SSH': { running: true, policy: 'on' }, slpd: { running: false, policy: 'off' } }, options: { 'Syslog.global.logHost': '', 'Security.AccountLockFailures': '5' }, ntp: ['10.0.0.1'], firewall: { incoming_blocked: true, rulesets: [] }, vswitches: [], portgroups: [], lockdown: 'lockdownNormal' }] },
    { id: 'vp_vc2', kind: 'esxi', label: 'VC-DOWN', at: null, error_at: new Date(NOW).toISOString(), error: 'authz: not authorised', hosts: [{ id: 'host-99', name: 'esx-noread', read: {} }] },
    { id: 'vp_ntx', kind: 'nutanix', label: 'PRISM-SYN', at: new Date(NOW - 3600000).toISOString(), error: null, cluster: { name: 'NTX-SYN', scma: { schedule: 'HOURLY', aide: true, high_strength_password: true, banner: true, snmpv3_only: false }, hv_scma: null, lockdown: false, password_remote_login: true, ntp: ['a', 'b'], dns: ['c'] }, auth: { directories: 0 }, syslog: { servers: 1 },
      hosts: [{ id: 'h1', name: 'NTX-N1', ip: '10.9.9.11', version: 'AHV 20230302' }] }];
  let virtReads = 0;
  const H = createHardening(e.app, { now: () => NOW, siem, virtFacts, virtRead: async () => { virtReads++; return [{ label: 'VC-SYN', ok: true, hosts: 1 }]; } });
  H.virtReads = () => virtReads;
  registerHardeningRoutes(e.app.srv, e.app, H);
  return { e, audits, ids, reads, H };
}

test('classify: the benchmark follows the register (Windows server / client, Oracle Linux, Solaris, Cisco, FortiGate, hypervisor), others out of scope', () => {
  assert.deepEqual(classify({ type: 'laptop', os: 'Windows 11' }), { kind: 'windows', platform: 'windows_client' });
  assert.deepEqual(classify({ type: 'server', os: 'Windows Server 2022' }), { kind: 'windows', platform: 'windows_server' });
  assert.deepEqual(classify({ type: 'vm', os: 'Oracle Linux Server 8.9' }), { kind: 'unix', platform: 'oracle_linux' });
  assert.deepEqual(classify({ type: 'server', os: 'SunOS 5.11' }), { kind: 'unix', platform: 'solaris' });
  assert.deepEqual(classify({ type: 'network', vendor: 'Palo Alto Networks' }), { kind: 'firewall', platform: 'paloalto' });
  assert.deepEqual(classify({ type: 'network', vendor: 'Cisco', os: 'IOS-XE' }), { kind: 'ios', platform: 'cisco' });
  assert.equal(classify({ type: 'printer' }), null);
  assert.deepEqual(classify({ type: 'server', os: 'VMware ESXi 8' }), { kind: 'esxi', platform: 'esxi' });
  assert.deepEqual(classify({ type: 'server', vendor: 'Nutanix', os: '' }), { kind: 'nutanix', platform: 'nutanix' });
  assert.equal(classify({ type: 'vm', os: 'VMware Photon OS' }).kind, 'unknown', 'a VM guest is not an ESXi host');
  assert.deepEqual(classify({ type: 'server', os: 'Proxmox VE 8' }), { kind: 'proxmox', platform: 'proxmox' });
  assert.deepEqual(classify({ type: 'server', os: 'Microsoft Hyper-V Server 2019' }), { kind: 'windows', platform: 'hyperv' });
  assert.equal(classify({ type: 'server', os: 'XCP-ng 8.2' }).kind, 'unsupported');
});

test('scan: every asset scanned from its source or NOT SCANNED with what to connect; failures with evidence; viewer sees scores only', async (t) => {
  const { e, ids } = await setup(t);
  let r = await call(e, 'GET', '/hardening', VWR); assert.equal(r.status, 200, r.text);
  const by = Object.fromEntries(r.json.assets.map((a) => [a.id, a]));
  assert.equal(r.json.assets.length, 10, 'printer out of scope');
  assert.equal(by[ids.win].state, 'scanned', 'Windows matched by short host name'); assert.ok(by[ids.win].counts.fail >= 3);
  assert.equal(by[ids.w11].platform, 'windows_client');
  assert.equal(by[ids.win2].state, 'not_scanned'); assert.match(by[ids.win2].why, /Windows agent - install or update the agent \(1\.2 or later\)/);
  assert.equal(by[ids.ol].state, 'scanned'); assert.equal(by[ids.sol].state, 'not_scanned'); assert.match(by[ids.sol].why, /read-only SSH login/);
  assert.equal(by[ids.sw].state, 'scanned'); assert.equal(by[ids.fw].state, 'scanned'); assert.equal(by[ids.fw].platform, 'fortigate');
  assert.equal(by[ids.esx].state, 'scanned', 'ESXi matched to its vCenter read by host name'); assert.equal(by[ids.esx].platform, 'esxi');
  assert.equal(by[ids.esx2].state, 'not_scanned'); assert.match(by[ids.esx2].why, /read through VC-DOWN failed: authz/);
  assert.equal(by[ids.ntx].state, 'scanned', 'Nutanix host matched by its address');
  assert.equal(r.json.summary.scanned, 7); assert.equal(r.json.summary.coverage_pct, 70);
  assert.equal(by[ids.win].checks, undefined, 'no settings in the summary');
  r = await call(e, 'GET', '/hardening/assets/' + ids.win, VWR); assert.equal(r.status, 403, 'viewer may not read how a machine is defended');
  r = await call(e, 'GET', '/hardening/assets/' + ids.win, OPR); assert.equal(r.status, 200);
  const c = Object.fromEntries(r.json.checks.map((x) => [x.id, x]));
  assert.equal(c['WIN-PW-LEN'].state, 'fail'); assert.match(c['WIN-PW-LEN'].evidence, /= 8/); assert.match(c['WIN-PW-LEN'].fix, /minpwlen:14/); assert.ok(c['WIN-PW-LEN'].rollback);
  assert.ok(c['WIN-PW-LEN'].refs.some((x) => /SAMA CSF 3\.3\.8/.test(x)) && c['WIN-PW-LEN'].refs.some((x) => /NCA ECC 2-2/.test(x)));
  assert.equal(c['WIN-SMB1'].state, 'fail'); assert.equal(c['WIN-RDP-NLA'].state, 'pass', 'RDP off');
  assert.equal(c['WIN-AUDIT'].state, 'not_checked', 'auditpol not read: not checked, never pass');
  assert.equal(c['WIN-BITLOCKER'], undefined, 'BitLocker is the workstation baseline');
  r = await call(e, 'GET', '/hardening/assets/' + ids.w11, OPR); assert.equal(r.json.checks.find((x) => x.id === 'WIN-BITLOCKER').state, 'fail');
  r = await call(e, 'GET', '/hardening/assets/' + ids.ol, OPR);
  const u = Object.fromEntries(r.json.checks.map((x) => [x.id, x]));
  assert.equal(u['UX-SSH-ROOT'].state, 'fail'); assert.equal(u['UX-SELINUX'].state, 'pass'); assert.equal(u['UX-UPDATES'].state, 'not_checked');
  r = await call(e, 'GET', '/hardening/assets/' + ids.sw, OPR); assert.equal(r.json.checks.find((x) => x.id === 'IOS-VTY-TELNET').state, 'fail');
  r = await call(e, 'GET', '/hardening/assets/' + ids.fw, OPR); assert.equal(r.json.checks.find((x) => x.id === 'FW-ANY-ANY').state, 'fail'); assert.equal(r.json.checks.find((x) => x.id === 'FW-NO-LOG').state, 'pass');
  r = await call(e, 'GET', '/hardening/assets/' + ids.esx, OPR);
  const x = Object.fromEntries(r.json.checks.map((c) => [c.id, c]));
  assert.equal(x['ESX-SSH'].state, 'fail'); assert.match(x['ESX-SSH'].fix, /Get-VMHost esx-syn\.corp\.test/); assert.equal(x['ESX-SLP'].state, 'pass');
  assert.equal(x['ESX-SYSLOG'].state, 'fail'); assert.equal(x['ESX-LOCKOUT'].state, 'pass'); assert.equal(x['ESX-LOCKDOWN'].state, 'pass');
  assert.equal(x['ESX-PWQ'].state, 'not_checked', 'a setting not on this release is not checked, never assumed');
  assert.match(x['ESX-SSH'].cis, /CIS VMware ESXi/); assert.ok(x['ESX-SSH'].refs.some((y) => /SAMA CSF 3\.3\.8/.test(y)));
  r = await call(e, 'GET', '/hardening/assets/' + ids.ntx, OPR);
  const n = Object.fromEntries(r.json.checks.map((c) => [c.id, c]));
  assert.equal(n['NTX-LOCKDOWN'].state, 'fail'); assert.equal(n['NTX-AUTH'].state, 'fail'); assert.equal(n['NTX-SCMA-SCHED'].state, 'pass');
  assert.equal(n['NTX-SCMA-AHV-AIDE'].state, 'not_checked'); assert.match(n['NTX-LOCKDOWN'].cis, /Nutanix STIG/);
  r = await call(e, 'GET', '/hardening/assets/nope', OPR); assert.equal(r.status, 404);
  r = await call(e, 'GET', '/hardening/assets/bad%20id!', OPR); assert.equal(r.status, 400);
});

test('scan now and fix script: operator only, audited, validated; only failed checks go into the script', async (t) => {
  const { e, audits, ids } = await setup(t);
  let r = await call(e, 'POST', '/hardening/scan', VWR); assert.equal(r.status, 403);
  r = await call(e, 'POST', '/hardening/scan', OPR); assert.equal(r.status, 200);
  assert.deepEqual(r.json.virtualization, [{ label: 'VC-SYN', ok: true, hosts: 1, error: null }], 'Scan now reads the ESXi / Nutanix connections first');
  assert.ok(audits.some((a) => a.action === 'hardening.scan' && a.by === OPR.user && a.role === 'operator'));
  assert.equal(e.app.store.collection('hardening_history').all(() => true).length, 1, 'the day is kept for the trend');
  r = await call(e, 'POST', '/hardening/script', VWR, { asset_id: ids.win, checks: ['WIN-PW-LEN'] }); assert.equal(r.status, 403);
  r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.win }); assert.equal(r.status, 400); assert.match(r.json.error, /checks/);
  r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.win, checks: ['rm -rf /'] }); assert.equal(r.status, 400); assert.match(r.json.error, /not a check id/);
  r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.win, checks: ['WIN-RDP-NLA'] }); assert.equal(r.status, 400, 'a passing check has nothing to fix');
  r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.win, checks: ['WIN-PW-LEN', 'WIN-SMB1', 'WIN-RDP-NLA'], extra: 'x' }); assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.checks, ['WIN-PW-LEN', 'WIN-SMB1']);
  assert.match(r.json.script, /REVIEW BEFORE RUNNING/); assert.match(r.json.script, /Set-SmbServerConfiguration -EnableSMB1Protocol \$false/); assert.match(r.json.script, /ROLLBACK/);
  assert.ok(audits.some((a) => a.action === 'hardening.script' && a.target === ids.win && a.detail.checks.length === 2));
});

test('SIEM down: Windows and network assets NOT SCANNED naming the SIEM, Unix still scanned from the SSH read', async (t) => {
  const { e, ids } = await setup(t, true);
  const r = await call(e, 'GET', '/hardening', ADM);
  const by = Object.fromEntries(r.json.assets.map((a) => [a.id, a]));
  assert.match(by[ids.win].why, /^SIEM: the SIEM did not answer/); assert.match(by[ids.fw].why, /^SIEM:/);
  assert.equal(by[ids.ol].state, 'scanned'); assert.equal(r.json.sources.windows, 'the SIEM did not answer');
});
