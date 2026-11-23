// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI auditors' infrastructure tests (engine/auditors.js IT-15, IT-16, CY-16..CY-20; rules in pyengine/infra_audit_rules.py):
// Active Directory (privileged access, accounts / Kerberos, domain password policy), Cisco IOS hardening (CIS level 1),
// firewall rule bases (FortiGate / Palo Alto / ASA), database and application audits. Each test fails only on evidence,
// names the rows it comes from (basis + columns + items + digest), passes a clean set, and is NOT TESTED when the SIEM
// evidence is missing. The SIEM is read as system:itam-auditor with role analyst. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createAuditors } = require('../engine/auditors');
const R = require('child_process').spawnSync('python3', ['-c', 'import sys; sys.path.insert(0, "pyengine"); import infra_audit_rules as m; print(len(m.OPS))'], { cwd: require('path').join(__dirname, '..'), encoding: 'utf8' });

const T = Date.parse('2026-10-20T08:00:00Z'), DAY = 86400000;
const iso = (d) => new Date(T - d * DAY).toISOString();
const testOf = (r, id) => r.tests.find((x) => x.id === id);
const keys = (t) => t.findings.map((f) => f.key.split(':').slice(1).join(':')).sort();

const U = (sam, o = {}) => Object.assign({ sam, name: 'Synthetic ' + sam, disabled: false, privileged: false, privileged_groups: [], service_account: false, dormant: false, expired: false, admin_orphan: false,
  pwd_never_expires: false, pwd_not_required: false, no_preauth: false, delegation: false, last_logon: iso(1), pwd_last_set: iso(30), created: iso(400) }, o);
const GOOD_POLICY = { min_length: 14, history: 24, max_age_days: 90, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 5, lockout_minutes: 30, lockout_window_minutes: 30 };
function adBad() {
  const da = ['adm-a', 'adm-b', 'adm-c', 'adm-d', 'adm-e', 'adm-f'].map((x) => U(x, { privileged: true, privileged_groups: ['Domain Admins'] }));
  da[0].pwd_never_expires = true; da[1].dormant = true; da[1].last_logon = iso(200); da[2].pwd_last_set = iso(500);
  return { available: true, synced: iso(0), domain: 'example.test', server: 'ldaps://dc.example.test', dormant_days: 90, policy: { min_length: 7, history: 24, max_age_days: 0, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 0, lockout_minutes: 30, lockout_window_minutes: 30 },
    users: da.concat([
      U('svc-sql', { privileged: true, privileged_groups: ['Administrators'], service_account: true }),
      U('ent-1', { privileged: true, privileged_groups: ['Enterprise Admins'] }),
      U('old-admin', { privileged: true, disabled: true, privileged_groups: ['Domain Admins'] }),
      U('user-roast', { no_preauth: true }), U('user-np', { pwd_not_required: true }), U('user-deleg', { delegation: true }),
      U('user-dormant', { dormant: true, last_logon: iso(150) }), U('user-new', { last_logon: null, created: iso(60) }), U('user-nx', { pwd_never_expires: true }),
      U('krbtgt', { disabled: true, pwd_last_set: iso(900), last_logon: null }),
    ]),
    groups: [{ name: 'Domain Admins', members: da.map((u) => ({ sam: u.sam })).concat([{ sam: 'old-admin' }]) }, { name: 'Enterprise Admins', members: [{ sam: 'ent-1' }] }, { name: 'Schema Admins', members: [] }, { name: 'Administrators', members: [{ sam: 'svc-sql' }] }] };
}
function adGood() {
  return { available: true, synced: iso(0), domain: 'example.test', dormant_days: 90, policy: GOOD_POLICY,
    users: [U('adm-a', { privileged: true, privileged_groups: ['Domain Admins'] }), U('user-1'), U('krbtgt', { disabled: true, pwd_last_set: iso(60), last_logon: null })],
    groups: [{ name: 'Domain Admins', members: [{ sam: 'adm-a' }] }, { name: 'Enterprise Admins', members: [] }, { name: 'Schema Admins', members: [] }] };
}
const IOS_BAD = ['hostname SW-SYN-1', 'enable password 7 <removed>', 'username netadmin privilege 15 password 7 <removed>', 'snmp-server community <removed> RW', 'snmp-server community <removed> RO', 'ip http server',
  'line con 0', ' exec-timeout 0 0', 'line vty 0 4', ' transport input telnet ssh', ' exec-timeout 30 0', 'end'].join('\n');
const IOS_GOOD = ['hostname SW-SYN-2', 'service timestamps log datetime msec show-timezone', 'service password-encryption', 'enable secret 9 <removed>', 'username break-glass privilege 15 secret 9 <removed>',
  'aaa new-model', 'aaa authentication login default group tacacs+ local', 'ip ssh version 2', 'no ip http server', 'no ip source-route', 'snmp-server community <removed> RO 10', 'logging host 192.0.2.50', 'ntp server 192.0.2.1',
  'banner login ^C Authorised use only ^C', 'line con 0', ' exec-timeout 10 0', 'line vty 0 4', ' access-class 10 in', ' exec-timeout 10 0', ' transport input ssh', 'end'].join('\n');
const dev = (id, vendor, o = {}) => Object.assign({ id, name: id.toUpperCase(), vendor, role: vendor === 'cisco-ios' ? 'access' : 'firewall', site: 'HQ', ip: '192.0.2.' + (10 + id.length), criticality: 2,
  monitoring: { snmp: 'v3 authPriv', api: vendor === 'cisco-ios' ? null : 'token set, certificate pinned', ssh: 'set' }, polled_at: iso(0), security_at: iso(0), security_errors: [], security: [], licenses: [], config: null }, o);
function network(bad) {
  return { available: true, devices: [
    dev('sw-syn-1', 'cisco-ios', { config: { sha256: 'a'.repeat(64), at: iso(0) }, security: bad ? [{ kind: 'telnet-open', severity: 'high', key: 'telnet', title: 'Telnet is open on SW-SYN-1', evidence: ['TCP 23'], rec: 'Disable Telnet' }] : [] }),
    dev('sw-syn-2', 'cisco-ios', { config: { sha256: 'b'.repeat(64), at: iso(0) } }),
    dev('sw-syn-3', 'cisco-ios', bad ? { config: { error: 'no SSH login or trusted host key - configuration not read' } } : { config: { sha256: 'c'.repeat(64), at: iso(0) } }),
    dev('pa-edge', 'paloalto', { security: bad ? [{ kind: 'pa-any-any', severity: 'high', key: 'allow-all', title: 'Security rule "allow-all" allows any', evidence: ['from trust to untrust'], rec: '' }, { kind: 'pa-nolog', severity: 'medium', key: 'r2', title: 'rule r2 no log', evidence: [], rec: '' }] : [],
      licenses: bad ? [{ name: 'Threat Prevention', expires: iso(10) }] : [{ name: 'Threat Prevention', expires: new Date(T + 100 * DAY).toISOString() }] }),
    dev('fg-users', 'fortigate', bad ? { monitoring: { snmp: 'v2c', api: null, ssh: null }, security: [{ kind: 'snmp-v2c', severity: 'medium', key: 'snmp', title: 'SNMP v2c', evidence: [], rec: '' }], security_at: iso(5) } : {}),
  ] };
}
const configs = (bad) => ({ 'sw-syn-1': bad ? IOS_BAD : IOS_GOOD, 'sw-syn-2': IOS_GOOD, 'sw-syn-3': IOS_GOOD });
const dbReport = (bad) => ({ available: true, total: bad ? 120 : 40, posture: [{ instance: 'ORCLSYN' }], coverage: [{ instance: 'ORCLSYN', events: 40 }], summary: { events: bad ? 120 : 40, databases: 1 },
  findings: bad ? [{ severity: 'critical', area: 'Audit tampering', title: 'NOAUDIT on ORCLSYN by dba-syn', recommendation: 'x', evidence: ['2026-10-19T22:00:00Z NOAUDIT'] },
    { severity: 'high', area: 'Audit configuration', title: 'ORCLSYN: ORA_LOGON_FAILURES not enabled', recommendation: 'y', evidence: [] },
    { severity: 'medium', area: 'Privileged use', title: '4 privileged action(s) by dba-syn on ORCLSYN outside working hours', recommendation: 'z', evidence: [] }] : [] });
const appReport = (bad) => ({ available: true, hours: 720, total: 2, read: 2, applications: [
  { application: { key: 'core-syn', name: 'Core Insurance (synthetic)', critical: true }, findings: bad ? [{ severity: 'high', area: 'Resilience', title: 'Core Insurance (synthetic): runs on a single server', recommendation: 'r', evidence: [] },
    { severity: 'high', area: 'Changes', title: 'SCHG-9 approved by its own author', recommendation: 'r', evidence: [] }] : [] },
  { application: { key: 'intranet-syn', name: 'Intranet (synthetic)', critical: false }, findings: bad ? [{ severity: 'high', area: 'Resilience', title: 'Intranet (synthetic): runs on a single server', recommendation: 'r', evidence: [] }] : [] }] });

async function setup(t, src) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  const siemEvidence = async (p) => { calls.push(p); return src(p); };
  return { e, calls, AU: createAuditors(e.app, { now: () => T, siemEvidence }) };
}
function source(bad) {
  return (p) => {
    if (p === '/audit/evidence/ad') return bad ? adBad() : adGood();
    if (p === '/audit/evidence/network') return network(bad);
    const m = /^\/audit\/evidence\/network\/config\/(.+)$/.exec(p); if (m) return { text: configs(bad)[decodeURIComponent(m[1])] };
    if (p.startsWith('/audit/evidence/database')) return dbReport(bad);
    if (p.startsWith('/audit/evidence/applications')) return appReport(bad);
    return null;
  };
}

test('python rules module loads', () => { assert.equal(R.status, 0, R.stderr); assert.equal(R.stdout.trim(), '15'); });

test('Active Directory: privileged access, accounts and Kerberos, domain policy - findings name the accounts', async (t) => {
  const { AU, calls } = await setup(t, source(true));
  const r = await AU.run('cyberaudit');
  const c16 = testOf(r, 'CY-16'), c17 = testOf(r, 'CY-17'), c18 = testOf(r, 'CY-18');
  assert.equal(c16.state, 'fail');
  assert.deepEqual(keys(c16), ['group:domain-admins', 'group:enterprise-admins', 'priv:disabled-member', 'priv:dormant', 'priv:old-password', 'priv:pwd-never-expires', 'priv:service']);
  const ea = c16.findings.find((f) => f.key === 'CY-16:group:enterprise-admins');
  assert.equal(ea.severity, 'high'); assert.deepEqual(ea.items.map((x) => x[0]), ['ent-1']); assert.equal(ea.columns[0], 'Account');
  assert.match(ea.basis[0], /AD identity sync of example\.test/); assert.ok(ea.basis.some((b) => /Enterprise Admins empty/.test(b))); assert.match(ea.evidence_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(c16.findings.find((f) => f.key === 'CY-16:group:domain-admins').items.length, 6, 'the disabled member is not counted toward the limit');
  assert.equal(c17.state, 'fail');
  assert.deepEqual(keys(c17), ['acct:delegation', 'acct:dormant', 'acct:krbtgt', 'acct:never-logon', 'acct:no-preauth', 'acct:pwd-never-expires', 'acct:pwd-not-required']);
  assert.deepEqual(c17.findings.find((f) => f.key === 'CY-17:acct:no-preauth').items.map((x) => x[0]), ['user-roast']);
  assert.match(c17.findings.find((f) => f.key === 'CY-17:acct:krbtgt').title, /900 days/);
  assert.equal(c18.state, 'fail');
  const p = c18.findings[0]; assert.equal(p.severity, 'high');
  assert.deepEqual(p.items.filter((x) => x[3] === 'does not meet').map((x) => x[0]), ['Minimum password length', 'Maximum password age (days)', 'Account lockout threshold']);
  assert.ok(calls.includes('/audit/evidence/ad'));
  // the evidence annex carries the rows
  const ev = AU.evidence('CY-16:priv:service'); assert.deepEqual(ev.rows.map((x) => x[0]), ['svc-sql']); assert.equal(ev.digest, c16.findings.find((f) => f.key === 'CY-16:priv:service').evidence_digest);
});

test('Cisco switches (CIS IOS L1) and firewalls: every failing check names the device and the line', async (t) => {
  const { AU, calls } = await setup(t, source(true));
  const r = await AU.run('cyberaudit');
  const sw = testOf(r, 'CY-19'), fw = testOf(r, 'CY-20');
  assert.equal(sw.state, 'fail');
  const k = keys(sw);
  for (const x of ['ios:enable-password', 'ios:enable-secret', 'ios:local-user-weak', 'ios:aaa', 'ios:ssh-v2', 'ios:vty-telnet', 'ios:vty-acl', 'ios:vty-timeout', 'ios:con-timeout', 'ios:http-server', 'ios:snmp-rw', 'ios:snmp-acl', 'ios:logging', 'ios:ntp', 'ios:banner', 'ios:password-encryption', 'ios:probe-telnet-open', 'ios:not-read'])
    assert.ok(k.includes(x), 'missing ' + x + ' in ' + k.join(','));
  const vt = sw.findings.find((f) => f.key === 'CY-19:ios:vty-telnet'); assert.equal(vt.severity, 'high'); assert.deepEqual(vt.items.map((x) => x[0]), ['SW-SYN-1']);
  assert.ok(!sw.findings.some((f) => f.items && f.items.some((x) => x[0] === 'SW-SYN-2') && f.key !== 'CY-19:ios:not-read'), 'the hardened switch raises nothing');
  assert.deepEqual(sw.findings.find((f) => f.key === 'CY-19:ios:not-read').items.map((x) => x[0]), ['SW-SYN-3']);
  assert.ok(!calls.includes('/audit/evidence/network/config/sw-syn-3'), 'a device without a capture is not fetched');
  assert.equal(fw.state, 'fail');
  assert.deepEqual(keys(fw), ['fw:any-any', 'fw:checks-stale', 'fw:no-log', 'fw:not-reviewed', 'fw:snmp', 'fw:subscription']);
  const aa = fw.findings.find((f) => f.key === 'CY-20:fw:any-any'); assert.equal(aa.severity, 'high'); assert.equal(aa.items[0][0], 'PA-EDGE'); assert.equal(aa.items[0][5], 'allow-all');
  assert.deepEqual(fw.findings.find((f) => f.key === 'CY-20:fw:not-reviewed').items.map((x) => x[0]), ['FG-USERS']);
  assert.ok(aa.basis.some((b) => /Palo Alto: edge/.test(b)));
});

test('databases and applications: grouped by area, critical application keeps high, non-critical single server is medium', async (t) => {
  const { AU } = await setup(t, source(true));
  const r = await AU.run('itaudit');
  const db = testOf(r, 'IT-15'), ap = testOf(r, 'IT-16');
  assert.equal(db.state, 'fail');
  assert.deepEqual(keys(db), ['db:audit-configuration', 'db:audit-tampering', 'db:privileged-use']);
  assert.equal(db.findings.find((f) => f.key === 'IT-15:db:audit-tampering').severity, 'critical');
  assert.equal(ap.state, 'fail');
  const res = ap.findings.find((f) => f.key === 'IT-16:app:resilience');
  assert.equal(res.severity, 'high'); assert.deepEqual(res.items.map((x) => [x[0], x[2]]), [['Core Insurance (synthetic)', 'high'], ['Intranet (synthetic)', 'medium']]);
  assert.ok(ap.findings.some((f) => f.key === 'IT-16:app:changes'));
});

test('a clean estate passes every infrastructure test', async (t) => {
  const { AU } = await setup(t, source(false));
  const c = await AU.run('cyberaudit'), i = await AU.run('itaudit');
  for (const id of ['CY-16', 'CY-17', 'CY-18', 'CY-19', 'CY-20']) assert.equal(testOf(c, id).state, 'pass', id + ': ' + testOf(c, id).detail + ' ' + JSON.stringify(testOf(c, id).findings.map((f) => f.key)));
  for (const id of ['IT-15', 'IT-16']) assert.equal(testOf(i, id).state, 'pass', id + ': ' + testOf(i, id).detail);
  assert.match(testOf(c, 'CY-19').detail, /3 Cisco switch/);
});

test('missing evidence is NOT TESTED, never passed - and says why', async (t) => {
  const { AU } = await setup(t, (p) => {
    if (p === '/audit/evidence/ad') return { available: true, synced: iso(0), users: [], groups: [], policy: null };
    if (p === '/audit/evidence/network') return { available: true, devices: [dev('sw-x', 'cisco-ios', { config: { error: 'no SSH login or trusted host key - configuration not read' } })] };
    if (p.startsWith('/audit/evidence/database')) return { available: false, reason: 'the event store (ClickHouse) is not available' };
    return null;   // older SIEM without the route
  });
  const c = await AU.run('cyberaudit'), i = await AU.run('itaudit');
  assert.equal(testOf(c, 'CY-18').state, 'not_tested'); assert.match(testOf(c, 'CY-18').detail, /password policy was not read/);
  assert.equal(testOf(c, 'CY-19').state, 'not_tested'); assert.match(testOf(c, 'CY-19').detail, /SSH login and a trusted host key/);
  assert.equal(testOf(c, 'CY-20').state, 'not_tested'); assert.match(testOf(c, 'CY-20').detail, /no firewall/);
  assert.equal(testOf(i, 'IT-15').state, 'not_tested'); assert.match(testOf(i, 'IT-15').detail, /ClickHouse/);
  assert.equal(testOf(i, 'IT-16').state, 'not_tested'); assert.match(testOf(i, 'IT-16').detail, /audit-evidence route is not reachable/);
});

test('the real SIEM link is called as the auditor with role analyst, and an error is a reason, not a pass', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const seen = [];
  e.app.discovery = Object.assign(e.app.discovery || {}, { siem: { call: async (m, p, who) => { seen.push([m, p, who.user, who.role]); return p === '/audit/evidence/ad' ? { status: 403, json: { error: 'requires analyst role' } } : { status: 404, json: null }; } } });
  const AU = createAuditors(e.app, { now: () => T });
  const c = await AU.run('cyberaudit');
  assert.deepEqual(seen.find((x) => x[1] === '/audit/evidence/ad'), ['GET', '/audit/evidence/ad', 'system:itam-auditor', 'analyst']);
  assert.equal(testOf(c, 'CY-16').state, 'not_tested'); assert.match(testOf(c, 'CY-16').detail, /HTTP 403 requires analyst role/);
  assert.equal(testOf(c, 'CY-19').state, 'not_tested'); assert.match(testOf(c, 'CY-19').detail, /not reachable/);
});
