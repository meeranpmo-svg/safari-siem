// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Business Services (engine/service-map.js + inv-helper.py op ssh_services): what runs on each server, recognised from
// Asset Discovery results, the installed-software list, database logins, SSH (trusted host key only) and the network probe
// (only inside a scope whose safety checklist is complete); "possible" from a port alone, "confirmed" from a banner,
// process, service, product or login; business-critical PROPOSED, decided by an administrator (asset tagged, audited);
// a server nobody could read says NOT CHECKED. All names and addresses are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const SM = require('../engine/service-map');
const scopes = require('../engine/discovery/scopes');

const PS = [
  'oracle ora_pmon_ERPPRD ora_pmon_ERPPRD', 'oracle ora_pmon_HRPRD ora_pmon_HRPRD', 'grid asm_pmon_+ASM asm_pmon_+ASM',
  'oracle tnslsnr /u01/app/oracle/product/19c/bin/tnslsnr LISTENER -inherit', 'root sshd /usr/sbin/sshd -D',
  'tomcat java /usr/bin/java -Dcatalina.base=/opt/tomcat org.apache.catalina.startup.Bootstrap start', 'nginx nginx nginx: worker process',
].join('\n');
const LISTEN = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 [::]:1521 [::]:*\nLISTEN 0 100 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*';

test('parsers: ps, ss / netstat / Solaris netstat, systemctl, oratab, SQL Browser answer, HTTP headers', () => {
  assert.equal(SM.parsePs(PS).length, 7);
  assert.deepEqual(SM.parseListen(LISTEN), [22, 443, 1521, 8080]);
  assert.deepEqual(SM.parseListen('tcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN\ntcp6 0 0 :::5432 :::* LISTEN\nudp 0 0 0.0.0.0:161 0.0.0.0:*'), [3306, 5432]);
  assert.deepEqual(SM.parseListen('      *.1521               *.*                0      0 128000      0 LISTEN'), [1521]);
  assert.deepEqual(SM.parseUnits('  nginx.service loaded active running nginx\n● tomcat9.service loaded active running Tomcat\nfoo.socket x'), ['nginx.service', 'tomcat9.service']);
  assert.deepEqual(SM.parseOratab('ERPPRD:/u01/19c:Y\n# c\n+ASM:/u01/grid:N'), [{ sid: 'ERPPRD', home: '/u01/19c', autostart: true }, { sid: '+ASM', home: '/u01/grid', autostart: false }]);
  const b = Buffer.concat([Buffer.from([5, 0, 0]), Buffer.from('ServerName;SQLAPP01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;ServerName;SQLAPP01;InstanceName;FINANCE;IsClustered;Yes;Version;16.0.1000.6;tcp;51433;;')]);
  assert.deepEqual(SM.parseSqlBrowser(b).map((x) => [x.instance, x.version, x.tcp, x.clustered]), [['MSSQLSERVER', '15.0.2000.5', 1433, false], ['FINANCE', '16.0.1000.6', 51433, true]]);
  assert.deepEqual(SM.parseSqlBrowser(Buffer.from('garbage')), []);
  const h = SM.parseHttpHead('HTTP/1.1 302 Found\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\nX-OWA-Version: 15.2.1258.12\r\nLocation: /owa/\r\n\r\n');
  assert.equal(h.server, 'Microsoft-IIS/10.0'); assert.ok(h.owa); assert.match(h.powered, /ASP\.NET/);
});

test('recognise: confirmed vs possible, instances, the word-bounded patterns', () => {
  const r = SM.recognise({ ports: [3389, 5432, 1433], procs: SM.parsePs(PS), listen: SM.parseListen(LISTEN), oratab: SM.parseOratab('ERPPRD:/u01:Y\nFINDEV:/u01:N'),
    software: [{ name: 'Microsoft SQL Server 2019 (64-bit)', version: '15.0.2000.5' }, { name: 'Microsoft SQL Server Management Studio - 19.1' }, { name: 'Oracle VM VirtualBox' }],
    http: [{ port: 80, server: 'Microsoft-IIS/10.0', powered: 'ASP.NET' }, { port: 8443, tls: true, server: 'Apache-Coyote/1.1' }], sql: [{ instance: 'FINANCE', version: '16.0.1000.6', tcp: 51433 }] });
  const by = Object.fromEntries(r.map((x) => [x.id, x]));
  assert.equal(by.oracle.confidence, 'confirmed'); assert.deepEqual(by.oracle.instances.sort(), ['ERPPRD', 'FINDEV', 'HRPRD']);   // +ASM is not a database
  assert.equal(by.mssql.confidence, 'confirmed'); assert.deepEqual(by.mssql.instances, ['FINANCE']); assert.ok(by.mssql.versions.includes('15.0.2000.5'));
  assert.equal(by.iis.confidence, 'confirmed'); assert.equal(by.tomcat.confidence, 'confirmed'); assert.equal(by.nginx.confidence, 'confirmed');
  assert.equal(by.postgres.confidence, 'possible');   // a port alone
  assert.equal(by.apache, undefined, 'Apache-Coyote is Tomcat, not Apache HTTP Server');
  assert.ok(!by.rdp.critical && by.oracle.critical && by.iis.critical);
  assert.equal(SM.recognise({ software: [{ name: 'Microsoft SQL Server Management Studio - 19.1' }, { name: 'Microsoft SQL Server 2019 Setup (English)' }] }).length, 0, 'tools are not a database server');
  assert.equal(SM.recognise({ procs: SM.parsePs('root dbus-daemon /usr/bin/dbus-daemon\nroot mongodbx x') }).length, 0, 'no bare-substring matches');
  assert.equal(SM.recognise({ ports: [88, 389, 445] }).find((x) => x.id === 'ad').confidence, 'possible');
  assert.equal(SM.recognise({ is_dc: true }).find((x) => x.id === 'ad').confidence, 'confirmed');
});

function setup(e, o = {}) {
  const st = e.app.store, NOW = Date.UTC(2026, 9, 22, 9, 0);
  st.collection('assets').put({ id: 'as_erp', type: 'server', name: 'ERPDB01', asset_tag: 'SENTRA-SRV-0101', status: 'in_use', mgmt_ip: '10.20.0.11', tags: ['dc-riyadh'] });
  st.collection('assets').put({ id: 'as_web', type: 'vm', name: 'WEBAPP01', status: 'in_use', mgmt_ip: '10.20.0.21', software: [{ name: 'Microsoft SQL Server 2019 (64-bit)' }] });
  st.collection('assets').put({ id: 'as_old', type: 'server', name: 'OLD', status: 'disposed', mgmt_ip: '10.20.0.99' });
  st.collection('disc_devices').put({ id: 'd1', ip: '10.20.0.11', type: 'server', hostname: 'erpdb01', asset_id: 'as_erp', open_ports: [22, 1521], extra: { db: [{ engine: 'oracle', port: 1521 }], unix_login: { credential: 'linux-ro' } } });
  st.collection('disc_devices').put({ id: 'd2', ip: '10.20.0.31', type: 'workstation', hostname: 'pc31', extra: {} });
  st.collection('disc_devices').put({ id: 'd3', ip: '10.20.0.41', type: 'server', hostname: 'quiet41', extra: {} });
  st.collection('disc_trust').put({ id: 'ssh:10.20.0.11:22', kind: 'ssh', ip: '10.20.0.11', port: 22, fp: 'b'.repeat(64), state: 'trusted' });
  const sc = { id: 'sc1', name: 'Servers VLAN', targets: ['10.20.0.0/24'], exclusions: ['10.20.0.41'], allow_public: false };
  if (o.gate !== false) sc.checklist = { completed_at: '2026-10-01T00:00:00Z', targets_fp: scopes.targetsFingerprint(sc) };
  st.collection('disc_scopes').put(sc);
  const creds = [{ id: 'ssh1', kind: 'ssh', label: 'linux-ro', target: { port: 22 }, _s: { username: 'zybread', password: 'Synthetic-1' } }];
  const vault = { list: () => creds, open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  const calls = [], probed = [];
  const helper = o.helper || (async () => ({ ok: true, facts: { hostname: 'erpdb01', os: 'Linux 5.4 x86_64\nPRETTY_NAME="Oracle Linux Server 8.8"', ps: PS, listen: LISTEN, units: '', oratab: 'ERPPRD:/u01/19c:Y' } }));
  const probe = {
    tcp: async (ip, p) => { probed.push(ip + ':' + p); return ip === '10.20.0.21' ? [80, 443, 1433, 445, 3389, 5985].includes(p) : false; },
    http: async (ip, p, t) => (ip === '10.20.0.21' ? { status: 200, server: 'Microsoft-IIS/10.0', powered: 'ASP.NET', port: p, tls: t, cn: 'webapp01.example.test' } : null),
    sql: async (ip) => (ip === '10.20.0.21' ? [{ instance: 'APPS', version: '15.0.4000.1', tcp: 1433 }] : []),
  };
  const dbHealth = { targets: () => ({ list: [{ ip: '10.20.0.11', host: 'erpdb01', instance: 'ERPPRD', engine: 'oracle' }] }) };
  const S = SM.createServiceMap(e.app, { discovery: { vault, trust: { see() {} } }, dbHealth, invRun: async (r) => { calls.push(r); return helper(r); }, probe, now: () => NOW });
  return { S, calls, probed };
}

test('pass + view: every server, each source with its reason, findings, nothing guessed', async () => {
  const e = await startApp({ noAi: true });
  try {
    const { S, calls, probed } = setup(e);
    const run = await S.pass();
    assert.equal(run.servers, 3); assert.equal(run.ssh_read, 1); assert.equal(run.probed, 2);   // .41 is excluded from the scope
    assert.equal(calls.length, 1); assert.equal(calls[0].op, 'ssh_services'); assert.equal(calls[0].fp, 'b'.repeat(64)); assert.equal(calls[0].username, 'zybread');
    assert.ok(!probed.some((p) => p.startsWith('10.20.0.41:')), 'an excluded address is never probed');
    const v = S.view('admin');
    assert.deepEqual(v.servers.map((s) => s.ip), ['10.20.0.11', '10.20.0.21', '10.20.0.41']);   // the workstation and the disposed asset are not servers
    const erp = v.servers[0], web = v.servers[1], quiet = v.servers[2];
    assert.equal(erp.asset.asset_tag, 'SENTRA-SRV-0101'); assert.match(erp.os, /Oracle Linux/);
    const ora = erp.services.find((x) => x.id === 'oracle');
    assert.equal(ora.confidence, 'confirmed'); assert.deepEqual(ora.sources, ['dblogin', 'discovery', 'ssh']); assert.ok(ora.instances.includes('ERPPRD') && ora.instances.includes('HRPRD'));
    assert.ok(erp.business.includes('oracle') && erp.business.includes('tomcat')); assert.equal(erp.state, 'proposed');
    assert.ok(web.services.find((x) => x.id === 'iis' && x.confidence === 'confirmed'));
    assert.deepEqual(web.services.find((x) => x.id === 'mssql').instances, ['APPS']);
    assert.ok(web.services.find((x) => x.id === 'rdp').confidence === 'possible' && !web.business.includes('rdp'));
    const cov = Object.fromEntries(web.coverage.map((c) => [c.source, c]));
    assert.equal(cov.network.ok, true); assert.equal(cov.software.ok, true); assert.equal(cov.ssh.ok, false); assert.match(cov.ssh.why, /no SSH login/);
    assert.equal(quiet.checked, true, 'Asset Discovery saw it'); assert.equal(quiet.services.length, 0);
    assert.match(quiet.coverage.find((c) => c.source === 'network').why, /safety checklist/);
    const kinds = v.findings.map((f) => f.kind + ':' + f.ip);
    assert.ok(kinds.includes('unmonitored-db:10.20.0.21'), 'SQL Server with no database login'); assert.ok(!kinds.includes('unmonitored-db:10.20.0.11'), 'the Oracle there is monitored');
    assert.ok(kinds.includes('decide:10.20.0.11') && kinds.includes('decide:10.20.0.21'));
    assert.equal(v.summary.by_product.oracle, 1); assert.equal(v.summary.proposed, 2);
    assert.deepEqual(S.view('viewer').ssh_logins, [], 'logins are listed to administrators only');
  } finally { await e.close(); }
});

test('no gate, no probe; untrusted host key, no login; a failed read says why', async () => {
  const e = await startApp({ noAi: true });
  try {
    e.app.store.collection('disc_trust').put({ id: 'ssh:10.20.0.11:22', kind: 'ssh', ip: '10.20.0.11', port: 22, fp: 'b'.repeat(64), state: 'pending' });
    const { S, calls, probed } = setup(e, { gate: false });
    e.app.store.collection('disc_trust').put({ id: 'ssh:10.20.0.11:22', kind: 'ssh', ip: '10.20.0.11', port: 22, fp: 'b'.repeat(64), state: 'pending' });
    await S.pass();
    assert.equal(calls.length, 0, 'no login without a trusted host key'); assert.equal(probed.length, 0, 'no probe without a completed safety checklist');
    const erp = S.view('admin').servers[0];
    assert.match(erp.coverage.find((c) => c.source === 'ssh').why, /host key not trusted/);
    assert.equal(erp.services.find((x) => x.id === 'oracle').confidence, 'confirmed', 'the database login still confirms it');
  } finally { await e.close(); }
  const e2 = await startApp({ noAi: true });
  try {
    const { S } = setup(e2, { helper: async () => ({ ok: false, error_class: 'auth', error: 'Authentication failed' }) });
    await S.pass();
    assert.match(S.view('admin').servers[0].coverage.find((c) => c.source === 'ssh').why, /failed: Authentication failed/);
  } finally { await e2.close(); }
});

test('decide: confirm tags the asset (audited), not-critical needs a reason, a new service is flagged', async () => {
  const e = await startApp({ noAi: true });
  try {
    const { S } = setup(e);
    await S.pass();
    const admin = { user: 'syed', role: 'admin', ip: '127.0.0.1' };
    assert.throws(() => S.decide({ ip: '10.20.0.21', decision: 'not_critical', reason: 'x' }, admin), /reason/);
    assert.throws(() => S.decide({ ip: '10.9.9.9', decision: 'critical' }, admin), /not a known server/);
    const row = S.decide({ ip: '10.20.0.11', decision: 'critical' }, admin);
    assert.equal(row.state, 'confirmed');
    const a = e.app.store.collection('assets').get('as_erp');
    assert.ok(a.tags.includes('business-critical') && a.tags.includes('svc:oracle') && a.tags.includes('svc:tomcat') && a.tags.includes('dc-riyadh'));
    const r2 = S.decide({ ip: '10.20.0.21', decision: 'not_critical', reason: 'Test web server, no production data' }, admin);
    assert.equal(r2.state, 'not_critical'); assert.equal(r2.decision.reason, 'Test web server, no production data');
    // a service found after the decision
    e.app.store.collection('disc_devices').patch('d1', (d) => { d.extra.db.push({ engine: 'mysql', port: 3306, version: 'MySQL 8.0.36' }); });
    const v = S.view('admin'), erp = v.servers.find((s) => s.ip === '10.20.0.11');
    assert.deepEqual(erp.new_since, ['mysql']); assert.ok(v.findings.some((f) => f.kind === 'changed' && f.ip === '10.20.0.11'));
    // un-confirming removes the tags again
    S.decide({ ip: '10.20.0.11', decision: 'not_critical', reason: 'Moved to the DR site, read-only copy' }, admin);
    const a2 = e.app.store.collection('assets').get('as_erp');
    assert.ok(!a2.tags.includes('business-critical') && !a2.tags.some((t) => t.startsWith('svc:')) && a2.tags.includes('dc-riyadh'));
  } finally { await e.close(); }
});

test('routes: viewer reads, operator runs, admin decides', async () => {
  const e = await startApp({ noAi: true });
  try {
    const st = e.app.store;
    st.collection('assets').put({ id: 'as_x', type: 'server', name: 'X', status: 'in_use', mgmt_ip: '10.30.0.5' });
    SM.registerServiceMap(e.app.srv, e.app, { noTimer: true, probe: { tcp: async () => false, http: async () => null, sql: async () => [] }, invRun: async () => ({ ok: false }) });
    const g = await e.req('GET', '/service-map', { role: 'viewer' }); assert.equal(g.status, 200); assert.equal(g.json.servers.length, 1);
    assert.equal((await e.req('POST', '/service-map/run', { body: {}, role: 'viewer' })).status, 403);
    assert.equal((await e.req('POST', '/service-map/run', { body: {}, role: 'operator' })).status, 200);
    assert.equal((await e.req('POST', '/service-map/decide', { body: { ip: '10.30.0.5', decision: 'critical', reason: 'Payroll batch server' }, role: 'operator' })).status, 403);
    const d = await e.req('POST', '/service-map/decide', { body: { ip: '10.30.0.5', decision: 'critical', reason: 'Payroll batch server' }, role: 'admin' });
    assert.equal(d.status, 200); assert.equal(d.json.state, 'confirmed');
  } finally { await e.close(); }
});
