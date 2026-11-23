// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database servers (engine/db-servers.js + inv-helper.py op ssh_health): the hosts of the monitored databases, aligned with
// the asset register (administrator link > Asset Discovery device > management IP; a host-name match is only a suggestion),
// read over SSH only with a TRUSTED host key and a proven / chosen SSH login, findings (Oracle file system full, instance in
// oratab not running, no listener, NTP, swap, THP), never "healthy" when not read, readings sent to the SIEM per instance,
// and the admin-only link / login routes.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createDbServers, registerDbServers } = require('../engine/db-servers');

const HELPER = path.join(__dirname, '../engine/discovery/inv-helper.py');
const RAW = {
  os: 'Linux 5.4.17-2136.el8uek.x86_64 x86_64\nPRETTY_NAME="Oracle Linux Server 8.8"\nVERSION_ID="8.8"\n',
  uptime_s: '3456000.12 100.0\n', uptime: '', load: '22.10 20.50 18.00 3/900 1234\n', ncpu: '8\n',
  mem: 'MemTotal:       65808000 kB\nMemFree:          900000 kB\nMemAvailable:    2600000 kB\nSwapTotal:       8388604 kB\nSwapFree:        2000000 kB\nHugePages_Total:       0\nHugePages_Free:        0\nHugepagesize:       2048 kB\n',
  thp: 'always madvise [never]\n'.replace('[never]', 'never').replace('always', '[always]'),
  df: 'Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/mapper/ol-root 52403200 20000000 32403200 39% /\n/dev/sdb1     1048576000 1006632960 41943040 97% /u02\n/dev/sdc1      209715200 188743680 20971520 91% /arch\n',
  dfi: 'Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/mapper/ol-root 26214400 200000 26014400 1% /\n/dev/sdc1 1000000 950000 50000 95% /arch\n',
  oracle: 'oracle ora_pmon_ESS\noracle ora_pmon_HR\ngrid asm_pmon_+ASM\n',
  oratab: 'ESS:/u01/app/oracle/product/19c:Y\nHR:/u01/app/oracle/product/19c:Y\nFIN:/u01/app/oracle/product/19c:Y\n+ASM:/u01/app/grid:N\n',
  ntp: 'Reference ID    : 0A000001\nLeap status     : Not synchronised\n', patch: 'kernel-uek-5.4.17 Mon 06 Mar 2023 10:01:02 AM +03\n',
  top: '%CPU %MEM USER COMMAND\n 95.0 12.0 oracle oracle\n 30.0 1.0 root rman\n',
};

test('inv-helper parse_ssh_health: real command output -> the server reading; a missing value is None, not 0', { skip: spawnSync('python3', ['-c', '1']).status !== 0 && 'python3 missing' }, () => {
  const r = spawnSync('python3', ['-c', `
import importlib.util,json,sys
s=importlib.util.spec_from_file_location('h', ${JSON.stringify(HELPER)}); h=importlib.util.module_from_spec(s); s.loader.exec_module(h)
raw=json.loads(sys.stdin.read()); print(json.dumps({"full": h.parse_ssh_health(raw), "empty": h.parse_ssh_health({})}))`], { input: JSON.stringify(RAW) });
  assert.equal(r.status, 0, r.stderr.toString());
  const { full: v, empty } = JSON.parse(r.stdout.toString());
  assert.equal(v.os, 'Oracle Linux Server 8.8'); assert.equal(v.ncpu, 8); assert.equal(v.load5, 20.5); assert.equal(v.uptime_s, 3456000);
  assert.equal(v.mem_total_mb, 64266); assert.equal(v.mem_avail_mb, 2539); assert.equal(v.swap_used_mb, 6239); assert.equal(v.hugepages_total, 0); assert.equal(v.thp, 'always');
  assert.deepEqual(v.filesystems.map((f) => [f.mount, f.used_pct]), [['/', 39], ['/u02', 97], ['/arch', 91]]);
  assert.deepEqual(v.inodes.find((i) => i.mount === '/arch').used_pct, 95);
  assert.deepEqual(v.oracle.pmon, ['ESS', 'HR']); assert.deepEqual(v.oracle.asm, ['+ASM']); assert.deepEqual(v.oracle.listeners, []);
  assert.equal(v.oratab.length, 4); assert.equal(v.ntp_synced, false); assert.equal(v.last_patch, '2023-03-06'); assert.equal(v.top[0].command, 'oracle');
  assert.equal(empty.ncpu, null); assert.equal(empty.mem_total_mb, null); assert.equal(empty.ntp_synced, null); assert.deepEqual(empty.filesystems, []);
});

function setup(e, opts = {}) {
  const st = e.app.store, NOW = Date.UTC(2026, 9, 20, 12, 0);
  st.collection('assets').put({ id: 'as_ess', type: 'server', name: 'ESKAUAT', asset_tag: 'SENTRA-SRV-0042', status: 'in_use', owner: 'DBA team', mgmt_ip: '192.168.9.30', warranty: { end: '2025-12-31' } });
  st.collection('assets').put({ id: 'as_hr', type: 'server', name: 'hrdb01', status: 'in_use' });
  st.collection('disc_devices').put({ id: 'dev1', ip: '192.168.9.30', hostname: 'eskauat', extra: { unix_login: { credential: 'linux-ro' } } });
  st.collection('disc_trust').put({ id: 'ssh:192.168.9.30:22', kind: 'ssh', ip: '192.168.9.30', port: 22, fp: 'a'.repeat(64), state: 'trusted' });
  const creds = [{ id: 'ssh1', kind: 'ssh', label: 'linux-ro', target: { port: 22 }, _s: { username: 'zybread', password: 'Synthetic-1' } }, { id: 'ssh2', kind: 'ssh', label: 'other', target: {}, _s: { username: 'x', password: 'y' } }];
  const vault = { list: () => creds, get: (id) => creds.find((c) => c.id === id), open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  const T = [{ ip: '192.168.9.30', host: 'eskauat', instance: 'ESS', device_id: 'dev1', cred_label: 'oracle-ESS' }, { ip: '192.168.9.30', host: 'eskauat', instance: 'HR' }, { ip: '10.0.0.9', host: 'hrdb01', instance: 'HRP', reg_id: 'odb_1' }];
  const pushed = [], calls = [];
  const dbHealth = { targets: () => ({ list: T }), push: async (recs) => { pushed.push(...recs); return recs.length; } };
  const helper = opts.helper || (async () => ({ ok: true, server: opts.server }));
  const S = createDbServers(e.app, { discovery: { vault }, dbHealth, invRun: async (r) => { calls.push(r); return helper(r); }, now: () => NOW });
  return { S, pushed, calls };
}

test('asset alignment, trust rule, findings, SIEM records, routes', async (tt) => {
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const py = spawnSync('python3', ['-c', `
import importlib.util,json,sys
s=importlib.util.spec_from_file_location('h', ${JSON.stringify(HELPER)}); h=importlib.util.module_from_spec(s); s.loader.exec_module(h)
print(json.dumps(h.parse_ssh_health(json.loads(sys.stdin.read()))))`], { input: JSON.stringify(RAW) });
  const server = JSON.parse(py.stdout.toString());
  const { S, pushed, calls } = setup(e, { server });

  let v = S.view();
  assert.equal(v.servers.length, 2, 'two hosts (two databases on one)');
  const ess = v.servers.find((x) => x.ip === '192.168.9.30'), hr = v.servers.find((x) => x.ip === '10.0.0.9');
  assert.equal(ess.databases.length, 2);
  assert.equal(ess.asset.id, 'as_ess'); assert.equal(ess.asset.how, 'management IP');
  assert.equal(hr.asset, null, 'a host-name match never links on its own'); assert.equal(hr.asset_suggestion.id, 'as_hr');
  assert.ok(v.findings.some((f) => f.ip === '10.0.0.9' && f.kind === 'asset'), 'not in the asset register is a finding');
  assert.ok(v.findings.some((f) => f.ip === '10.0.0.9' && f.kind === 'not-read' && /no SSH login/.test(f.recommendation)), 'not read says why, never healthy');
  assert.equal(ess.ssh.credential, 'linux-ro'); assert.equal(ess.ssh.via, 'proven by Asset Discovery'); assert.equal(ess.ssh.host_key, 'trusted');

  const res = await S.pass();
  assert.equal(res.read, 1); assert.equal(res.skipped, 1, 'the host with no login / key is skipped, not tried');
  assert.equal(calls.length, 1); assert.equal(calls[0].op, 'ssh_health'); assert.equal(calls[0].fp, 'a'.repeat(64)); assert.equal(calls[0].username, 'zybread');
  v = S.view();
  const k = v.findings.filter((f) => f.ip === '192.168.9.30').map((f) => f.kind + ':' + f.severity);
  for (const want of ['filesystem:critical', 'filesystem:high', 'inodes:high', 'instance-down:critical', 'listener:high', 'ntp:medium', 'swap:medium', 'load:high', 'thp:low', 'hugepages:low', 'patch:medium', 'warranty:low', 'memory:high']) assert.ok(k.includes(want), 'missing ' + want + ' in ' + k.join(' '));
  assert.ok(v.findings.find((f) => f.kind === 'instance-down').title.includes('FIN'), 'FIN is in oratab with Y and has no pmon');
  assert.ok(/Oracle file system/.test(v.findings.find((f) => f.kind === 'filesystem' && f.severity === 'critical').title));
  // SIEM: one db_server + file systems per instance on that host
  assert.equal(pushed.filter((x) => x.kind === 'db_server').map((x) => x.instance).sort().join(','), 'ESS,HR');
  assert.equal(pushed.find((x) => x.kind === 'db_server').oratab_down, 'FIN');
  assert.ok(pushed.some((x) => x.kind === 'db_server_fs' && x.mount === '/u02' && x.used_pct === 97 && x.oracle_fs === true));

  // a changed host key: not logged in, and the key goes to the trust list for an administrator
  e.app.store.collection('disc_trust').put({ id: 'ssh:192.168.9.30:22', kind: 'ssh', ip: '192.168.9.30', port: 22, fp: 'a'.repeat(64), state: 'changed' });
  calls.length = 0; await S.pass(); assert.equal(calls.length, 0, 'never logs in while the host key is not trusted');

  // routes: link + login are admin only; link a server to its asset; refuse an unknown asset
  const R = (m, p, body, role) => e.req(m, p, { body, user: role === 'admin' ? 'syed' : 'siva', role });
  registerDbServers(e.app.srv, e.app, { dbHealth: { targets: () => ({ list: [{ ip: '10.0.0.9', host: 'hrdb01', instance: 'HRP' }] }) }, discovery: { vault: { list: () => [] } }, noTimer: true });
  assert.equal((await R('POST', '/db-servers/link', { ip: '10.0.0.9', asset_id: 'as_hr' }, 'operator')).status, 403);
  assert.equal((await R('POST', '/db-servers/link', { ip: '10.0.0.9', asset_id: 'nope' }, 'admin')).status, 404);
  const ok = await R('POST', '/db-servers/link', { ip: '10.0.0.9', asset_id: 'as_hr' }, 'admin');
  assert.equal(ok.status, 200); assert.equal(ok.json.asset.id, 'as_hr'); assert.match(ok.json.asset.how, /linked by syed/);
  assert.ok(e.app.store.auditTail(20, (x) => x.action === 'db.servers.link').length === 1);
  assert.equal((await R('GET', '/db-servers', null, 'viewer')).status, 403);
});
