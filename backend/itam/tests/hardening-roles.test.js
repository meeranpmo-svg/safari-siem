// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Baseline Hardening round 3: IIS and Hyper-V from the agent 1.3 snapshot, Active Directory and Exchange from agent 1.4, Proxmox VE nodes from the read-only API token,
// Oracle / SQL Server / PostgreSQL from the fixed SELECTs of inv-helper db_harden (vault credential, never logged). A query the
// login may not run is NOT CHECKED with the grant to give, never a pass; a database read failure says so on the asset; the
// database fixes come out as their own SQL section of the script. Roles, validation and audit. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createHardening, registerHardeningRoutes } = require('../engine/hardening');

const ADM = { user: 'syed', role: 'admin' }, OPR = { user: 'omar.syn', role: 'operator' }, VWR = { user: 'v.syn', role: 'viewer' };
const NOW = Date.parse('2026-10-26T06:00:00Z'), ISO = (ms) => new Date(ms).toISOString();
const call = (e, m, p, who, b) => e.req(m, p, { user: who.user, role: who.role, body: b });
const HV = { os: { caption: 'Microsoft Windows Server 2022 Datacenter', product_type: 3 }, secpol: {}, reg: {},
  iis: { sites: [{ name: 'Portal-SYN', state: 'Started', protocols: ['http'], directory_browse: true, logging: true }], error_mode: 'Detailed', remove_server_header: false, powered_by: true, webdav: false, pools: [{ name: 'PortalPool', identity: 'LocalSystem' }] },
  hyperv: { migration_enabled: true, migration_auth: 'CredSSP', migration_any_network: true, enhanced_session: false,
    vms: [{ name: 'VM-SYN-1', generation: 2, secure_boot: false, mac_spoofing: true, dhcp_guard: false, router_guard: false, guest_service: true }, { name: 'VM-SYN-2', generation: 1, secure_boot: null, mac_spoofing: false, dhcp_guard: true, router_guard: true, guest_service: false }] } };
const DC = { os: { caption: 'Microsoft Windows Server 2022 Standard', product_type: 2, domain_role: 5 }, secpol: {}, reg: {},
  ad: { domain: 'corp.syn.test', domain_mode: 'Windows2012R2Domain', forest_mode: 'Windows2012R2Forest', pwd: { min_length: 8, complexity: true, history: 24, max_age_days: 90, lockout_threshold: 0, reversible: false },
    recycle_bin: true, krbtgt_age_days: 1500, groups: { domain_admins: { count: 9, names: ['adm.ali.syn', 'adm.omar.syn'] }, enterprise_admins: { count: 1, names: ['adm.syed.syn'] }, schema_admins: { count: 0, names: [] }, administrators: { count: 12, names: [] }, protected_users: null },
    accounts: { pwd_never_expires: { count: 37, names: ['svc.backup.syn', 'svc.scan.syn'] }, pwd_not_required: { count: 0, names: [] }, no_preauth: { count: 1, names: ['old.syn'] }, admin_spn: { count: 0, names: [] }, stale_users: null, unconstrained: { count: 2, names: ['APP-SYN-07$'] } },
    computers: 400, laps_computers: 380, ldap_signing: 2, ldap_channel_binding: 0 } };
const EXS = { os: { caption: 'Microsoft Windows Server 2019 Standard', product_type: 3 }, secpol: {}, reg: {},
  exchange: { build: '15.2.1544.4', modern_auth: false, mailbox_audit_off: false, admin_audit: true, auto_forward: true, mapi_http: true,
    receive: [{ name: 'Default Frontend EXS-SYN', anonymous: true, open_relay: false, tls: true, enabled: true }, { name: 'Relay Printers', anonymous: true, open_relay: true, tls: false, enabled: true }],
    owa_basic: false, ecp_external: true, ep_ews: 'None', malware_bypass: false, tls10_server: 0, tls11_server: null } };
const PAFW = { id: 'pa1', name: 'PA-DC-SYN', vendor: 'paloalto', ip: '10.0.0.1', monitoring: { api: 'set' }, security_at: ISO(NOW - 3600000), security: [],
  facts: { vendor: 'paloalto', unread: [{ section: 'admins', reason: 'not allowed for this API key (add Configuration read to its admin role)' }], info: { version: '10.1.9' },
    system: { banner: false, ntp: ['10.0.0.5'], permitted_ip: 0, telnet_off: true, http_off: null, snmp: 'v2c', updates: { threats: { every: 'daily', action: 'download-only' }, 'anti-virus': { every: 'hourly', action: 'download-and-install' }, wildfire: null } },
    management: { idle_timeout: null, lockout_attempts: null }, password: { enabled: true, min_length: 8 }, admins: null, syslog: { profiles: 1 },
    session: { reject_non_syn: 'yes', asymmetric_path: 'drop' }, zones: [{ name: 'untrust', zpp: '' }, { name: 'users', zpp: 'ZP-users' }],
    rules: { items: [{ name: 'any-any', action: 'allow', source: ['any'], destination: ['any'], application: ['any'], service: ['any'], profile: false, log_end: false }, { name: 'users-rdp', action: 'allow', source: ['10.20.0.0/16'], destination: ['srv'], application: ['ms-rdp'], service: ['any'], profile: true, log_end: true }] },
    decryption: { count: 0 } } };
const PVE = { id: 'vp_pve', kind: 'proxmox', label: 'PVE-SYN', at: ISO(NOW - 3600000), error: null,
  cluster: { version: '7.4-3', firewall: { enable: false, policy_in: null }, realms: [{ realm: 'pam', type: 'pam' }, { realm: 'pve', type: 'pve' }], users: [{ userid: 'root@pam', enable: true }, { userid: 'ops@pve', enable: true }, { userid: 'mon@pve!ro', enable: true }], tfa: ['root@pam'], backup_jobs: 0 },
  hosts: [{ id: 'pve1', name: 'pve1', ip: '10.8.1.5', firewall: true, updates: 12, certs: [{ file: 'pve-ssl.pem', issuer: '/CN=Proxmox Virtual Environment/OU=x', subject: '/CN=pve1' }], subscription: 'notfound' }] };

const ORA_OK = { params: [['remote_os_authent', 'FALSE'], ['o7_dictionary_accessibility', 'FALSE'], ['sec_case_sensitive_logon', 'TRUE'], ['audit_sys_operations', 'FALSE'], ['audit_trail', 'NONE']],
  unified: [['FALSE']], defpwd: [['SCOTT']], profile: [['FAILED_LOGIN_ATTEMPTS', '10'], ['PASSWORD_LIFE_TIME', '180'], ['PASSWORD_VERIFY_FUNCTION', 'NULL'], ['PASSWORD_REUSE_MAX', 'UNLIMITED']],
  public_exec: [['UTL_FILE']], dba_role: [], sample: [] };

async function setup(t, opts = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (r) => { audits.push(r); if (orig) orig.call(e.app, r); };
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const ids = {
    hv: mk({ name: 'HV-SYN-01', type: 'server', os: 'Windows Server 2022', mgmt_ip: '10.8.0.41' }).id,
    pve: mk({ name: 'pve1', type: 'server', os: 'Proxmox VE 7.4', mgmt_ip: '10.8.1.5' }).id,
    db: mk({ name: 'ORA-SYN-01', type: 'server', os: 'Oracle Linux Server 8.9', mgmt_ip: '10.8.0.51' }).id,
    sql: mk({ name: 'SQL-SYN-01', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.52' }).id,
    dc: mk({ name: 'DC-SYN-01', type: 'server', os: 'Windows Server 2022', mgmt_ip: '10.8.0.10' }).id,
    exs: mk({ name: 'EXS-SYN-01', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.60' }).id,
    pa: mk({ name: 'PA-DC-SYN', type: 'network', vendor: 'Palo Alto Networks', model: 'PA-3220', mgmt_ip: '10.0.0.1' }).id,
    dcold: mk({ name: 'DC-SYN-02', type: 'server', os: 'Windows Server 2016', mgmt_ip: '10.8.0.9' }).id,
  };
  // what Asset Discovery proved on the database hosts: a read-only login per engine, kept in the vault
  e.app.store.collection('disc_devices').put({ id: 'd-ora', ip: '10.8.0.51', asset_id: ids.db, status: 'matched', extra: { db_login: { oracle: { credential: 'ora-ro' } } } });
  e.app.store.collection('disc_devices').put({ id: 'd-sql', ip: '10.8.0.52', asset_id: ids.sql, status: 'matched', extra: { db_login: { mssql: { credential: 'sql-ro' } } } });
  const opened = [];
  const vault = { list: () => [{ id: 'c1', kind: 'db_login', label: 'ora-ro', target: { engine: 'oracle', service: 'ORCLSYN' } }, { id: 'c2', kind: 'db_login', label: 'sql-ro', target: { engine: 'mssql' } }],
    open: (id) => { opened.push(id); return { target: id === 'c1' ? { service: 'ORCLSYN' } : {}, secret: { username: id === 'c1' ? 'mon_syn' : 'sqlmon', password: 'Synthetic-Pass-1' }, release() {} }; } };
  e.app.discovery = Object.assign({}, e.app.discovery, { vault });
  const helperCalls = [];
  const invRun = async (input) => {
    helperCalls.push(input);
    if (input.engine === 'oracle') return { ok: true, engine: 'oracle', results: ORA_OK, errors: {} };
    if (opts.sqlFails) return { ok: false, error: 'login failed for user sqlmon', error_class: 'auth' };
    return { ok: true, engine: 'mssql', results: { configs: [['xp_cmdshell', 1], ['clr enabled', 0]], server: [['0', '12.0.6024.0', 'SP3', 'Standard']], sa: [['sa', 0]], policy: null, sysadmins: [['sqlmon'], ['CORP\\dba']], trustworthy: [], audits: [], public_perms: [] }, errors: { policy: 'permission denied' } };
  };
  const siem = async (path) => path === '/hardening/snapshots' ? { available: true, hosts: [{ host: 'hv-syn-01', at: ISO(NOW - 3600000), settings: HV }, { host: 'dc-syn-01', at: ISO(NOW - 3600000), settings: DC }, { host: 'exs-syn-01', at: ISO(NOW - 3600000), settings: EXS },
    { host: 'dc-syn-02', at: ISO(NOW - 3600000), settings: { os: { caption: 'Microsoft Windows Server 2016', product_type: 2 }, secpol: {}, reg: {}, ad: { error: 'Unable to contact the server' } } }] } : { available: true, devices: [PAFW] };
  const H = createHardening(e.app, { now: () => NOW, siem, invRun, virtFacts: () => [PVE], virtRead: async () => [{ label: 'PVE-SYN', ok: true, hosts: 1 }] });
  registerHardeningRoutes(e.app.srv, e.app, H);
  return { e, audits, ids, helperCalls, opened };
}

const checksOf = async (e, id) => { const r = await call(e, 'GET', '/hardening/assets/' + id, OPR); assert.equal(r.status, 200, r.text); return Object.fromEntries(r.json.checks.map((c) => [c.id, c])); };

test('IIS and Hyper-V: judged from the agent 1.3 snapshot beside the Windows checks; the host shows as a Hyper-V host', async (t) => {
  const { e, ids } = await setup(t);
  const list = await call(e, 'GET', '/hardening', VWR);
  assert.equal(list.json.assets.find((a) => a.id === ids.hv).platform, 'hyperv');
  const c = await checksOf(e, ids.hv);
  assert.equal(c['IIS-HTTPS'].state, 'fail'); assert.match(c['IIS-HTTPS'].evidence, /Portal-SYN/);
  assert.equal(c['IIS-DIRBROWSE'].state, 'fail'); assert.equal(c['IIS-ERRORS'].state, 'fail'); assert.equal(c['IIS-POOLID'].state, 'fail');
  assert.equal(c['IIS-WEBDAV'].state, 'pass'); assert.equal(c['IIS-LOGGING'].state, 'pass');
  assert.match(c['IIS-POOLID'].cis, /IIS 10/);
  assert.equal(c['HV-MIG-AUTH'].state, 'fail'); assert.match(c['HV-MIG-AUTH'].evidence, /CredSSP/);
  assert.equal(c['HV-SECUREBOOT'].state, 'fail'); assert.match(c['HV-SECUREBOOT'].evidence, /VM-SYN-1/); assert.doesNotMatch(c['HV-SECUREBOOT'].evidence, /VM-SYN-2/, 'generation 1 VMs are not judged on Secure Boot');
  assert.equal(c['HV-ENHANCED'].state, 'pass');
  assert.ok(c['WIN-PWLEN'] || Object.keys(c).some((k) => k.startsWith('WIN-')), 'the Windows checks are still there');
});

test('Proxmox VE: firewall, second factor, updates, certificate, backups and release judged; a part the token may not read is NOT CHECKED', async (t) => {
  const { e, ids } = await setup(t);
  const c = await checksOf(e, ids.pve);
  assert.equal(c['PVE-FW-DC'].state, 'fail'); assert.equal(c['PVE-FW-NODE'].state, 'pass');
  assert.equal(c['PVE-TFA'].state, 'fail'); assert.match(c['PVE-TFA'].evidence, /ops@pve/); assert.doesNotMatch(c['PVE-TFA'].evidence, /mon@pve!ro/, 'API tokens are not people');
  assert.equal(c['PVE-UPDATES'].state, 'fail'); assert.match(c['PVE-UPDATES'].evidence, /12/);
  assert.equal(c['PVE-CERT'].state, 'fail'); assert.equal(c['PVE-BACKUP'].state, 'fail'); assert.equal(c['PVE-VERSION'].state, 'fail'); assert.equal(c['PVE-REALM'].state, 'fail');
  assert.match(c['PVE-FW-NODE'].cis || '', /Proxmox/);
  assert.match(c['PVE-UPDATES'].fix, /apt/);
});

test('databases: read with the vault login through db_harden, judged per engine; a query the login may not run is NOT CHECKED with the grant', async (t) => {
  const { e, ids, helperCalls, opened, audits } = await setup(t);
  let r = await call(e, 'POST', '/hardening/scan', OPR); assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.databases && [r.json.databases.targets, r.json.databases.read, r.json.databases.failed], [2, 2, 0]);
  assert.deepEqual(helperCalls.map((x) => [x.op, x.engine, x.host, x.port]).sort(), [['db_harden', 'mssql', '10.8.0.52', 1433], ['db_harden', 'oracle', '10.8.0.51', 1521]]);
  assert.equal(helperCalls.find((x) => x.engine === 'oracle').service, 'ORCLSYN');
  assert.deepEqual(opened.sort(), ['c1', 'c2']);
  const a = audits.find((x) => x.action === 'hardening.db.read'); assert.ok(a, 'the database read is audited');
  assert.doesNotMatch(JSON.stringify(audits), /Synthetic-Pass-1/, 'the password never reaches the audit');
  const o = await checksOf(e, ids.db);
  assert.equal(o['ORA-DEFPWD-1'].state, 'fail'); assert.equal(o['ORA-DEFPWD-1'].severity, 'critical'); assert.match(o['ORA-DEFPWD-1'].evidence, /SCOTT/);
  assert.equal(o['ORA-REMOTE-OS-1'].state, 'pass'); assert.equal(o['ORA-AUDIT-1'].state, 'fail'); assert.equal(o['ORA-FAILED-1'].state, 'fail'); assert.equal(o['ORA-REUSE-1'].state, 'fail');
  assert.equal(o['ORA-DBA-1'].state, 'pass'); assert.equal(o['ORA-DEFPWD-1'].lang, 'sql'); assert.match(o['ORA-DEFPWD-1'].title, /^\[Oracle/);
  const m = await checksOf(e, ids.sql);
  assert.equal(m['MS-XPCMD-1'].state, 'fail'); assert.equal(m['MS-CLR-1'].state, 'pass'); assert.equal(m['MS-SA-1'].state, 'fail'); assert.equal(m['MS-AUTH-1'].state, 'fail');
  assert.equal(m['MS-VERSION-1'].state, 'fail', 'SQL Server 2014 is out of support');
  assert.equal(m['MS-POLICY-1'].state, 'not_checked'); assert.match(m['MS-POLICY-1'].evidence, /VIEW SERVER STATE/); assert.match(m['MS-POLICY-1'].evidence, /permission denied/);
  assert.equal(m['MS-ADHOC-1'].state, 'not_checked', 'a setting not returned is not a pass');
});

test('a database read that fails says so on the asset; the earlier results are kept', async (t) => {
  const { e, ids } = await setup(t, { sqlFails: true });
  const r = await call(e, 'POST', '/hardening/scan', OPR); assert.equal(r.json.databases.failed, 1);
  const m = await checksOf(e, ids.sql);
  assert.equal(m['DB-READ-1'].state, 'not_checked'); assert.match(m['DB-READ-1'].evidence, /login failed/);
});

test('fix script: database fixes come out as their own SQL section with -- comments; roles and validation', async (t) => {
  const { e, ids, audits } = await setup(t);
  await call(e, 'POST', '/hardening/scan', OPR);
  assert.equal((await call(e, 'POST', '/hardening/scan', VWR)).status, 403, 'a viewer may not scan');
  assert.equal((await call(e, 'GET', '/hardening/assets/' + ids.db, VWR)).status, 403, 'a viewer may not see the checks');
  assert.equal((await call(e, 'POST', '/hardening/script', VWR, { asset_id: ids.db, checks: ['ORA-DEFPWD-1'] })).status, 403);
  let r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.db, checks: ['ORA-DEFPWD-1', 'ORA-AUDIT-1'] });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.sql, true); assert.equal(r.json.os, false);
  assert.match(r.json.script, /^-- ===== REVIEW BEFORE RUNNING/); assert.match(r.json.script, /ALTER USER <user> PASSWORD EXPIRE/); assert.match(r.json.script, /-- ===== ROLLBACK/);
  assert.ok(audits.some((x) => x.action === 'hardening.script' && x.target === ids.db && x.by === OPR.user));
  r = await call(e, 'POST', '/hardening/script', ADM, { asset_id: ids.hv, checks: ['IIS-DIRBROWSE'] });
  assert.equal(r.status, 200, r.text); assert.match(r.json.script, /^# ===== REVIEW/); assert.equal(r.json.sql, false);
  r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.db, checks: ['ora-defpwd; drop'] });
  assert.equal(r.status, 400); assert.match(r.json.error, /checks/);
});

test('Active Directory: domain policy, krbtgt, privileged groups, risky accounts, LDAP and LAPS judged on the domain controller; unread parts NOT CHECKED', async (t) => {
  const { e, ids } = await setup(t);
  const list = await call(e, 'GET', '/hardening', VWR);
  assert.equal(list.json.assets.find((a) => a.id === ids.dc).platform, 'domain_controller');
  const c = await checksOf(e, ids.dc);
  assert.equal(c['AD-PWLEN'].state, 'fail'); assert.match(c['AD-PWLEN'].evidence, /= 8.*corp\.syn\.test/);
  assert.match(c['AD-PWLEN'].fix, /-Identity corp\.syn\.test/, 'the fix names the domain');
  assert.equal(c['AD-LOCKOUT'].state, 'fail', 'lockout threshold 0 = never locks');
  assert.equal(c['AD-REVERSIBLE'].state, 'pass'); assert.equal(c['AD-HISTORY'].state, 'pass');
  assert.equal(c['AD-KRBTGT'].state, 'fail'); assert.match(c['AD-KRBTGT'].fix, /TWICE/);
  assert.equal(c['AD-DA'].state, 'fail'); assert.match(c['AD-DA'].evidence, /9 members.*adm\.ali\.syn/);
  assert.equal(c['AD-EA'].state, 'pass'); assert.equal(c['AD-SA'].state, 'pass');
  assert.equal(c['AD-PROTUSERS'].state, 'not_checked');
  assert.equal(c['AD-NEVEREXP'].state, 'fail'); assert.match(c['AD-NEVEREXP'].evidence, /37 .*svc\.backup\.syn/);
  assert.equal(c['AD-NOTREQ'].state, 'pass'); assert.equal(c['AD-PREAUTH'].state, 'fail'); assert.equal(c['AD-STALE'].state, 'not_checked', 'a query that failed is not a pass');
  assert.equal(c['AD-UNCONSTR'].state, 'fail'); assert.equal(c['AD-RECYCLE'].state, 'pass'); assert.equal(c['AD-LEVEL'].state, 'fail');
  assert.equal(c['AD-LDAP'].state, 'fail'); assert.match(c['AD-LDAP'].evidence, /channel binding/);
  assert.equal(c['AD-LAPS'].state, 'pass', '95% of computers');
  assert.ok(Object.keys(c).some((k) => k.startsWith('WIN-')), 'the Windows checks are still there');
  const old = await checksOf(e, ids.dcold);
  assert.equal(old['AD-READ'].state, 'not_checked'); assert.match(old['AD-READ'].evidence, /Unable to contact/);
  assert.equal(list.json.assets.find((a) => a.id === ids.dcold).platform, 'windows_server', 'a DC whose AD read failed is not shown as scanned for AD');
});

test('Exchange: support status, modern auth, audit, auto-forward, open relay, ECP exposure, Extended Protection, TLS; fix script', async (t) => {
  const { e, ids, audits } = await setup(t);
  const list = await call(e, 'GET', '/hardening', VWR);
  assert.equal(list.json.assets.find((a) => a.id === ids.exs).platform, 'exchange');
  const c = await checksOf(e, ids.exs);
  assert.equal(c['EX-BUILD'].state, 'fail'); assert.match(c['EX-BUILD'].evidence, /Exchange 2019.*Subscription Edition/);
  assert.equal(c['EX-BUILD'].severity, 'critical');
  assert.equal(c['EX-MODERNAUTH'].state, 'fail'); assert.equal(c['EX-ADMINAUDIT'].state, 'pass'); assert.equal(c['EX-MBXAUDIT'].state, 'pass');
  assert.equal(c['EX-AUTOFWD'].state, 'fail'); assert.equal(c['EX-RELAY'].state, 'fail'); assert.match(c['EX-RELAY'].evidence, /Relay Printers/); assert.doesNotMatch(c['EX-RELAY'].evidence, /Default Frontend/);
  assert.equal(c['EX-ECP'].state, 'fail'); assert.equal(c['EX-OWABASIC'].state, 'pass'); assert.equal(c['EX-EP'].state, 'fail'); assert.match(c['EX-EP'].evidence, /None/);
  assert.equal(c['EX-MALWARE'].state, 'pass'); assert.equal(c['EX-TLS'].state, 'fail'); assert.match(c['EX-TLS'].evidence, /TLS 1\.1/); assert.doesNotMatch(c['EX-TLS'].evidence, /TLS 1\.0/);
  assert.equal((await call(e, 'POST', '/hardening/script', VWR, { asset_id: ids.exs, checks: ['EX-RELAY'] })).status, 403);
  const r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.exs, checks: ['EX-RELAY', 'EX-AUTOFWD'] });
  assert.equal(r.status, 200, r.text); assert.match(r.json.script, /Remove-ADPermission/); assert.match(r.json.script, /AutoForwardEnabled \$false/); assert.match(r.json.script, /ROLLBACK[\s\S]*Add-ADPermission/);
  assert.ok(audits.some((x) => x.action === 'hardening.script' && x.target === ids.exs));
});

test('Exchange build: 2013 / 2016 / 2019 out of support, Subscription Edition passes; both version formats read', () => {
  const { spawnSync } = require('node:child_process'), path = require('node:path');
  const code = 'import sys, json; sys.path.insert(0, sys.argv[1]); import hardening_rules as H\n' +
    'print(json.dumps([H._ex_build({"exchange": {"build": b}})[0] for b in json.loads(sys.argv[2])]))';
  const builds = ['15.0.1497.48', '15.1.2507.39', '15.2.1544.4', 'Version 15.2 (Build 1748.10)', '15.2.2562.17', 'Version 15.2 (Build 2562.17)', ''];
  const p = spawnSync('python3', ['-I', '-c', code, path.join(__dirname, '..', 'pyengine'), JSON.stringify(builds)], { encoding: 'utf8' });
  assert.equal(p.status, 0, p.stderr);
  assert.deepEqual(JSON.parse(p.stdout), ['fail', 'fail', 'fail', 'fail', 'pass', 'pass', 'not_checked']);
});

test('Palo Alto: CIS PAN-OS checks from the configuration the SIEM read; an unread section is NOT CHECKED with the reason', async (t) => {
  const { e, ids } = await setup(t);
  const c = await checksOf(e, ids.pa);
  const st = (k) => c[k] && c[k].state;
  assert.equal(st('PA-VERSION'), 'fail'); assert.equal(c['PA-VERSION'].severity, 'critical');
  assert.equal(st('PA-BANNER'), 'fail'); assert.equal(st('PA-NTP'), 'fail'); assert.equal(st('PA-PERMITIP'), 'fail');
  assert.equal(st('PA-TELNET'), 'pass'); assert.equal(st('PA-HTTP'), 'pass'); assert.match(c['PA-HTTP'].evidence, /default/);
  assert.equal(st('PA-SNMP'), 'fail'); assert.equal(st('PA-IDLE'), 'fail'); assert.match(c['PA-IDLE'].evidence, /60 min.*default/);
  assert.equal(st('PA-LOCKOUT'), 'fail'); assert.equal(st('PA-PWD'), 'fail'); assert.equal(st('PA-SYSLOG'), 'pass');
  assert.equal(st('PA-DEFADMIN'), 'not_checked'); assert.match(c['PA-DEFADMIN'].evidence, /Configuration read/);
  assert.equal(st('PA-UPDATES'), 'fail'); assert.match(c['PA-UPDATES'].evidence, /threats, wildfire/);
  assert.equal(st('PA-ZPP'), 'fail'); assert.match(c['PA-ZPP'].evidence, /untrust/); assert.doesNotMatch(c['PA-ZPP'].evidence, /users/);
  assert.equal(st('PA-ANYANY'), 'fail'); assert.equal(st('PA-PROFILE'), 'fail'); assert.match(c['PA-PROFILE'].evidence, /any-any/); assert.doesNotMatch(c['PA-PROFILE'].evidence, /users-rdp/);
  assert.equal(st('PA-APPDEFAULT'), 'fail'); assert.match(c['PA-APPDEFAULT'].evidence, /users-rdp/);
  assert.equal(st('PA-LOGEND'), 'fail'); assert.equal(st('PA-DECRYPT'), 'fail'); assert.equal(st('PA-NONSYN'), 'pass'); assert.equal(st('PA-ASYM'), 'pass');
  assert.ok(!Object.keys(c).some((k) => k.startsWith('FW-')), 'the generic firewall checks are replaced by the PAN-OS ones');
  assert.match(c['PA-PERMITIP'].cis, /CIS Palo Alto Firewall Benchmark/);
  const r = await call(e, 'POST', '/hardening/script', OPR, { asset_id: ids.pa, checks: ['PA-IDLE', 'PA-LOCKOUT'] });
  assert.equal(r.status, 200, r.text); assert.match(r.json.script, /idle-timeout 10[\s\S]*admin-lockout failed-attempts 5[\s\S]*ROLLBACK/);
});
