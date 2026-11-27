// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Firewall & Security Device Audit (engine/netops/fw-audit.js), SYNTHETIC configurations: a weak and a hardened FortiGate (rule
// base: any-any, internet inbound, no logging, no security profile, shadowed / conflicting, unused by hits, disabled; admin
// access; crypto; logging; SNMP; HA; lifecycle from the fleet), sections that cannot be read are NOT CHECKED (never a pass);
// H3C Comware and Cisco IOS switch configuration text; the score and coverage; FortiManager's audit read removes secrets; the
// routes: roles (viewer refused, analyst reads, operator runs, an AI / the runner refused for sign-off), validation, risk
// acceptance limits, sign-off four-eyes and evidence hash, CSV export, audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createState } = require('../engine/soc/state');
const FA = require('../engine/netops/fw-audit');
const FMG = require('../engine/netops/fmg');

const NOW = Date.parse('2026-11-27T08:00:00Z'), D = 86400000;
const pol = (id, o) => Object.assign({ policyid: id, name: 'r' + id, status: 'enable', action: 'accept', srcintf: [{ name: 'internal' }], dstintf: [{ name: 'wan1' }], srcaddr: [{ name: 'LAN-SYN' }], dstaddr: [{ name: 'all' }], service: [{ name: 'HTTPS' }], schedule: 'always', logtraffic: 'all', 'utm-status': 'enable', 'ips-sensor': 'default' }, o || {});
const WEAK = {
  global: { admintimeout: 480, 'admin-lockout-threshold': 0, 'strong-crypto': 'disable', 'admin-https-ssl-versions': 'tlsv1-1 tlsv1-2', 'pre-login-banner': 'disable', 'admin-maintainer': 'enable', 'auto-install-config': 'enable' },
  admins: [{ name: 'admin', accprofile: 'super_admin', trusthost1: '0.0.0.0 0.0.0.0', 'two-factor': 'disable' }, { name: 'net.syn', accprofile: 'super_admin', trusthost1: '10.10.0.0 255.255.255.0', 'two-factor': 'fortitoken' }],
  password_policy: { status: 'disable' },
  interfaces: [{ name: 'wan1', role: 'wan', allowaccess: 'ping https ssh' }, { name: 'internal', role: 'lan', allowaccess: 'ping https http telnet' }],
  policies: [pol(1, { srcintf: [{ name: 'any' }], dstintf: [{ name: 'any' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], name: '' }),
    pol(2, { srcintf: [{ name: 'wan1' }], dstintf: [{ name: 'internal' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'SRV-SYN' }], service: [{ name: 'ALL' }], 'utm-status': 'disable', 'ips-sensor': '' }),
    pol(3, { logtraffic: 'disable' }), pol(4, { action: 'deny', srcaddr: [{ name: 'LAN-SYN' }], service: [{ name: 'HTTPS' }] }), pol(5, { status: 'disable' }), pol(6, { srcaddr: [{ name: 'GUEST-SYN' }], service: [{ name: 'SSH' }] })],
  hits: [{ policyid: 1, hit_count: 900 }, { policyid: 2, hit_count: 5 }, { policyid: 3, hit_count: 50 }, { policyid: 4, hit_count: 0 }, { policyid: 6, hit_count: 0 }],
  ntp: { ntpsync: 'disable' }, log_setting: { 'fwpolicy-implicit-log': 'disable' }, syslog: { status: 'disable' }, faz: { status: 'disable' },
  snmp_community: [{ id: 1, status: 'enable', 'query-v1-status': 'disable', 'query-v2c-status': 'enable', hosts: 2 }], snmp_user: [],
  ha: { mode: 'standalone' }, autoupdate: { status: 'disable' }, phase1: [{ name: 'to-site-syn', proposal: '3des-sha1 aes128-sha256', dhgrp: '2 14', mode: 'aggressive', 'ike-version': '1' }], sslvpn: { 'source-interface': [{ name: 'wan1' }], 'ssl-min-proto-ver': 'tls1-0' } };
const GOOD = {
  global: { admintimeout: 5, 'admin-lockout-threshold': 3, 'admin-lockout-duration': 900, 'strong-crypto': 'enable', 'admin-https-ssl-versions': 'tlsv1-2 tlsv1-3', 'pre-login-banner': 'enable', 'admin-maintainer': 'disable' },
  admins: [{ name: 'net.syn', accprofile: 'super_admin', trusthost1: '10.10.0.0 255.255.255.0', 'two-factor': 'fortitoken' }],
  password_policy: { status: 'enable', 'minimum-length': 14, 'min-number': 1, 'min-non-alphanumeric': 1, 'expire-status': 'enable' },
  interfaces: [{ name: 'wan1', role: 'wan', allowaccess: 'ping fgfm' }, { name: 'mgmt', role: 'lan', allowaccess: 'https ssh' }],
  policies: [pol(10), pol(11, { action: 'deny', srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], name: 'deny-all', 'utm-status': 'disable' })],
  hits: [{ policyid: 10, hit_count: 4000, last_used: (NOW - D) / 1000 }, { policyid: 11, hit_count: 12 }],
  ntp: { ntpsync: 'enable', type: 'custom', ntpserver: [{ server: '10.0.0.5' }] }, log_setting: { 'fwpolicy-implicit-log': 'enable' }, syslog: { status: 'enable', server: '10.0.0.9' }, faz: { status: 'disable' },
  snmp_community: [], snmp_user: [{ name: 'mon', 'security-level': 'auth-priv' }], ha: { mode: 'a-p' }, autoupdate: { status: 'enable', frequency: 'automatic' },
  phase1: [{ name: 'to-dc-syn', proposal: 'aes256gcm-prfsha384', dhgrp: '20', 'ike-version': '2' }], sslvpn: { status: 'disable' } };
const fleet = (o) => Object.assign({ name: 'x', model: 'FortiGate-200F', firmware: '7.2.8', conf: 'insync', findings: [], licences: [{ name: 'forticare', expires: '2027-06-01' }] }, o || {});
const byId = (d) => Object.fromEntries(d.tests.map((t) => [t.id, t]));

test('FortiGate: a weak and a hardened configuration, every test with its evidence', () => {
  const w = FA.auditFortigate({ dev: { id: 'FG-WEAK', name: 'FW-SYN-WEAK', model: 'FortiGate-200F' }, sections: WEAK, unread: {}, fleet: fleet({ firmware: '7.0.12', conf: 'modified', findings: [{ code: 'firmware' }], licences: [{ name: 'ips', expires: '2026-10-01' }] }) }, NOW);
  const T = byId(w);
  for (const id of ['FW-01', 'FW-02', 'FW-03', 'FW-04', 'FW-05', 'FW-06', 'FW-07', 'FW-10', 'FW-11', 'FW-12', 'FW-13', 'FW-14', 'FW-15', 'FW-16', 'FW-17', 'FW-18', 'FW-19', 'FW-20', 'FW-21', 'FW-22', 'FW-30', 'FW-31', 'FW-32', 'FW-33', 'FW-40', 'FW-41', 'FW-50', 'FW-51', 'FW-52'])
    assert.equal(T[id].result, 'fail', id + ' should fail: ' + JSON.stringify(T[id]));
  assert.match(T['FW-01'].evidence[0], /policy 1/); assert.match(T['FW-02'].evidence[0], /policy 2: from wan1/);
  assert.ok(T['FW-03'].evidence.some((e) => /policy 3/.test(e))); assert.ok(T['FW-04'].evidence.some((e) => /policy 2/.test(e)));
  assert.ok(T['FW-05'].evidence.some((e) => /policy 4 never matches: policy 1 .* OPPOSITE/.test(e)), T['FW-05'].evidence.join('|'));
  assert.ok(T['FW-06'].evidence.some((e) => /policy 6/.test(e)) && !T['FW-06'].evidence.some((e) => /policy 4/.test(e)), 'unused: accept rules only');
  assert.match(T['FW-10'].evidence.join(), /"admin"/); assert.ok(!T['FW-10'].evidence.join().includes('net.syn'));
  assert.match(T['FW-16'].evidence.join(), /internal: .*http telnet/); assert.match(T['FW-17'].evidence.join(), /wan1 \(internet\)/);
  assert.match(T['FW-21'].evidence.join(), /3des-sha1.*DH group 2 14.*aggressive/); assert.match(T['FW-33'].evidence.join(), /v1\/v2c/);
  assert.ok(T['FW-03'].fix.includes('set logtraffic all') && T['FW-03'].refs.nca === '2-12-1' && T['FW-03'].refs.iso === '8.15');
  assert.equal(w.score, 0); assert.equal(w.coverage, 100); assert.equal(w.rulebase.total, 6); assert.equal(w.rulebase.any_any, 1); assert.equal(w.rulebase.disabled, 1);
  const g = FA.auditFortigate({ dev: { id: 'FG-GOOD', name: 'FW-SYN-GOOD', model: 'FortiGate-200F' }, sections: GOOD, unread: {}, fleet: fleet() }, NOW);
  const fails = g.tests.filter((t) => t.result === 'fail').map((t) => t.id); assert.deepEqual(fails, [], 'a hardened FortiGate passes: ' + fails);
  assert.equal(byId(g)['FW-22'].result, 'na'); assert.equal(g.score, 100);
  // a small branch unit: HA not expected
  assert.equal(byId(FA.auditFortigate({ dev: { name: 'FW-SYN-BR', model: 'FortiGate-60F' }, sections: GOOD, unread: {}, fleet: fleet({ model: 'FortiGate-60F' }) }, NOW))['FW-40'].result, 'pass');
  assert.equal(byId(FA.auditFortigate({ dev: { name: 'FW-SYN-BR', model: 'FortiGate-60F' }, sections: Object.assign({}, GOOD, { ha: { mode: 'standalone' } }), unread: {}, fleet: null }, NOW))['FW-40'].result, 'na');
});

test('FortiGate: what cannot be read is NOT CHECKED, never passed; coverage says so', () => {
  const S = Object.assign({}, GOOD); delete S.admins; delete S.hits; delete S.faz;
  const a = FA.auditFortigate({ dev: { name: 'FW-SYN-PART' }, sections: S, unread: { admins: 'no permission (synthetic)', hits: 'no permission' }, fleet: null }, NOW), T = byId(a);
  assert.equal(T['FW-10'].result, 'not_checked'); assert.match(T['FW-10'].evidence[0], /admins \(no permission/); assert.equal(T['FW-06'].result, 'not_checked');
  assert.equal(T['FW-30'].result, 'pass', 'syslog alone is enough'); assert.equal(T['FW-50'].result, 'not_checked');
  assert.ok(a.coverage < 100); assert.equal(a.score, 100, 'the score is over what was checked');
});

test('switches: H3C Comware and Cisco IOS configuration text', () => {
  const WCW = ['sysname SW-SYN-ACC', 'telnet server enable', 'snmp-agent community read cipher $c$3$xx', 'snmp-agent sys-info version v2c v3', 'local-user admin class manage', ' password simple ******', 'line vty 0 63', ' idle-timeout 0 0'].join('\n');
  const GCW = ['sysname SW-SYN-CORE', 'ssh server enable', 'snmp-agent sys-info version v3', 'info-center loghost 10.0.0.9 facility local7', 'ntp-service enable', 'ntp-service unicast-server 10.0.0.5', 'hwtacacs scheme tac-syn',
    'local-user admin class manage', ' password hash $h$6$xx', 'line vty 0 63', ' idle-timeout 10 0', 'undo password-recovery enable', 'header login % Authorised use only %'].join('\n');
  const w = byId(FA.auditSwitch({ id: 's1', name: 'SW-SYN-ACC', vendor: 'h3c-comware', text: WCW }));
  for (const id of ['SW-01', 'SW-02', 'SW-03', 'SW-04', 'SW-05', 'SW-06', 'SW-07', 'SW-08', 'SW-09']) assert.equal(w[id].result, 'fail', id);
  assert.match(w['SW-01'].fix, /undo telnet server enable/); assert.match(w['SW-02'].evidence.join(), /1 community line/);
  const g = FA.auditSwitch({ id: 's2', name: 'SW-SYN-CORE', vendor: 'h3c-comware', text: GCW }); assert.deepEqual(g.tests.filter((t) => t.result === 'fail').map((t) => t.id), []); assert.equal(g.score, 100);
  const n = FA.auditSwitch({ id: 's3', name: 'SW-SYN-NEW', vendor: 'h3c-comware', error: 'no SSH login or trusted host key - configuration not read' }); assert.ok(n.tests.every((t) => t.result === 'not_checked')); assert.equal(n.score, null); assert.equal(n.coverage, 0);
  const ios = byId(FA.auditSwitch({ id: 's4', name: 'SW-SYN-IOS', vendor: 'cisco-ios', text: 'line vty 0 4\n transport input telnet\nsnmp-server community public RO\nenable password x' }));
  assert.equal(ios['SW-01'].result, 'fail'); assert.equal(ios['SW-05'].result, 'fail'); assert.equal(ios['SW-08'].result, 'na');
});

test('FortiManager audit read: secrets removed before anything is kept', () => {
  const x = FMG.scrubAudit('admins', [{ name: 'a', password: 'ENC xx', 'reuse-password': 'enable', trusthost1: '1.1.1.1 255.255.255.255', 'ssh-public-key1': 'k' }]);
  assert.deepEqual(x, [{ name: 'a', 'reuse-password': 'enable', trusthost1: '1.1.1.1 255.255.255.255' }]);
  assert.deepEqual(FMG.scrubAudit('phase1', [{ name: 't', psksecret: 's', 'psksecret-remote': 's', proposal: 'aes' }]), [{ name: 't', proposal: 'aes' }]);
  assert.deepEqual(FMG.scrubAudit('snmp_community', [{ id: 1, name: 'public-syn', status: 'enable', hosts: [{ ip: '1.2.3.4' }] }])[0].name, undefined, 'the community string is its name');
  assert.ok(Object.values(FMG.AUDIT_PATHS).every((p) => /^\/api\/v2\/(cmdb|monitor)\//.test(p)), 'GET paths only');
});

test('routes: roles, validation, run, accept with limits, four-eyes sign-off with the evidence hash, CSV, audit', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'fwa-')) });
  const R = {}, audits = [], RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  const fmgApi = { readAudit: async () => [{ dev: { id: 'FG1', name: 'FW-SYN-WEAK', model: 'FortiGate-200F', conn: 'up' }, sections: WEAK, unread: {} }, { dev: { id: 'FG2', name: 'FW-SYN-GOOD', model: 'FortiGate-200F' }, sections: GOOD, unread: {} }],
    fleet: () => ({ devices: [fleet({ name: 'FW-SYN-WEAK' }), fleet({ name: 'FW-SYN-GOOD' })] }) };
  const configAudit = { list: () => [{ id: 's1', name: 'SW-SYN-ACC', vendor: 'h3c-comware', site: 'Jubail', text: 'telnet server enable', at: new Date(NOW).toISOString() }, { id: 'p1', name: 'PRN', vendor: 'other' }] };
  let t = NOW;
  FA.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, state, log: { error() {} }, now: () => t, fmgApi, netopsInstance: { configAudit }, noTimers: true });
  const call = async (m, p, b, role = 'operator', user) => {
    const o = {}, u = user || role + '.syn';
    const ctx = { role, user: u, body: b, params: {}, audit: (a, tg, d) => audits.push({ a, t: tg, d, by: u }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' /api/soc' + p](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  assert.equal((await call('GET', '/netops/fw-audit', undefined, 'viewer')).s, 403, 'the rule base is for analysts and above');
  let v = (await call('GET', '/netops/fw-audit', undefined, 'analyst')).b; assert.equal(v.last, null); assert.match(v.note, /No audit run yet/);
  assert.equal((await call('POST', '/netops/fw-audit/run', {}, 'analyst')).s, 403);
  let r = await call('POST', '/netops/fw-audit/run', {}, 'operator', 'op.syn'); assert.equal(r.s, 200, r.e); v = r.b;
  assert.equal(v.last.kpis.devices, 3); assert.equal(v.last.kpis.firewalls, 2); assert.equal(v.last.kpis.switches, 1, 'H3C included, other vendors not');
  assert.ok(v.last.kpis.critical >= 5 && v.last.findings[0].severity === 'critical'); assert.equal(v.last.kpis.any_any, 1); assert.match(v.last.sha256, /^[0-9a-f]{64}$/);
  assert.ok(v.last.insights.some((i) => /critical finding/.test(i.title))); assert.ok(v.last.by_area.some((a) => a.area === 'Rule base' && a.fail > 0));
  assert.ok(!JSON.stringify(v).includes('ENC '), 'no secret in the view');
  const run = v.last.id;
  // accept a finding: validation and limits
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-1', reason: 'replacement planned Q1 (synthetic)', until: '2027-01-31' }, 'admin', 'sec.syn'); assert.equal(r.s, 400); assert.match(r.e, /^test/);
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-01', reason: 'short', until: '2027-01-31' }, 'admin', 'sec.syn'); assert.equal(r.s, 400); assert.match(r.e, /reason/);
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-01', reason: 'replacement planned Q1 (synthetic)', until: '2027-09-30' }, 'admin', 'sec.syn'); assert.equal(r.s, 400); assert.match(r.e, /three months/);
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG2', test: 'FW-01', reason: 'replacement planned Q1 (synthetic)', until: '2027-01-31' }, 'admin', 'sec.syn'); assert.equal(r.s, 409, 'it did not fail');
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-18', reason: 'banner text with legal (synthetic)', until: '2027-01-31' }, 'operator', 'op.syn'); assert.equal(r.s, 403, 'an operator without the firewall approval scope');
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-18', reason: 'banner text with legal (synthetic)', until: '2027-01-31' }, 'admin', 'ai:network'); assert.equal(r.s, 403, 'never an AI identity');
  r = await call('POST', '/netops/fw-audit/accept', { device: 'FG1', test: 'FW-18', reason: 'banner text with legal (synthetic)', until: '2027-01-31', extra: 1 }, 'admin', 'sec.syn'); assert.equal(r.s, 200, r.e);
  const f18 = r.b.last.findings.find((f) => f.test === 'FW-18' && f.device === 'FW-SYN-WEAK'); assert.equal(f18.accepted.by, 'sec.syn'); assert.equal(r.b.last.kpis.accepted, 1);
  // sign-off: four-eyes, the evidence hash
  r = await call('POST', '/netops/fw-audit/signoff', { run }, 'admin', 'op.syn'); assert.equal(r.s, 403); assert.match(r.e, /four-eyes/);
  r = await call('POST', '/netops/fw-audit/signoff', { run: 'bad' }, 'admin', 'sec.syn'); assert.equal(r.s, 400);
  const orig = state.collection('netops_fw_audit_runs').get(run).devices[0].score; state.collection('netops_fw_audit_runs').patch(run, (o) => { o.devices[0].score = 99; return o; });
  r = await call('POST', '/netops/fw-audit/signoff', { run }, 'admin', 'sec.syn'); assert.equal(r.s, 409); assert.match(r.e, /changed after/);
  state.collection('netops_fw_audit_runs').patch(run, (o) => { o.devices[0].score = orig; return o; });
  r = await call('POST', '/netops/fw-audit/signoff', { run, note: 'reviewed (synthetic)' }, 'admin', 'sec.syn'); assert.equal(r.s, 200, r.e); assert.equal(r.b.runs[0].signed_by, 'sec.syn');
  assert.equal((await call('POST', '/netops/fw-audit/signoff', { run }, 'admin', 'sec2.syn')).s, 409, 'signed once');
  // export
  r = await call('GET', '/netops/fw-audit/export', undefined, 'analyst'); assert.match(r.b.csv, /^"run","device"/); assert.match(r.b.csv, /FW-SYN-WEAK","","FW-01","critical"/); assert.match(r.b.csv, /sec\.syn/);
  // the acceptance expires
  t = NOW + 70 * D; v = (await call('GET', '/netops/fw-audit', undefined, 'analyst')).b; assert.equal(v.last.kpis.accepted, 0, 'expired acceptance is a finding again');
  const acts = audits.map((x) => x.a); for (const a of ['netops.fw_audit.run', 'netops.fw_audit.accept', 'netops.fw_audit.signoff', 'netops.fw_audit.export']) assert.ok(acts.includes(a), a);
  assert.equal(audits.find((x) => x.a === 'netops.fw_audit.signoff').by, 'sec.syn');
});
