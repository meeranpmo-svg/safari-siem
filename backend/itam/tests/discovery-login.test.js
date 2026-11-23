// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only scope logins: Solaris / Linux fact parsing, database answer parsing, the trust rules (a key is never
// accepted silently; a changed key is never used), and the REAL inv-helper.py against a fake SSH server (paramiko):
// the host key is read without logging in, a wrong pinned key stops BEFORE any password is sent, and only the fixed
// command list runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const L = require('../engine/discovery/methods/login');

test('parseUnix: Solaris (smbios, psrinfo, prtconf) and Linux (os-release, dmi, meminfo)', () => {
  assert.deepEqual(L.parseUnix({ uname: 'SunOS sol01 5.11 11.4 sun4v sparc', hostname: 'SOL01', release: '   Oracle Solaris 11.4 SPARC', sockets: '2', cpus: '128', memory: 'Memory size: 131072 Megabytes', smbios: '  Manufacturer: Oracle Corporation\n  Product: SPARC T8-1\n  Serial Number: AK001' }),
    { os: 'Oracle Solaris 11.4 SPARC', hostname: 'sol01', vendor: 'Oracle Corporation', model: 'SPARC T8-1', serial: 'AK001', sockets: 2, cpus: 128, cores_per_socket: null, sockets_v: 2, mem_gb: 128 });
  const lin = L.parseUnix({ uname: 'Linux app7 5.14.0 x86_64', hostname: 'app7.corp.local', os_release: 'NAME="Red Hat"\nPRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\n', sockets: '2', cpus: '\n16', memory: 'MemTotal:       65536000 kB', dmi: 'HPE\nProLiant DL380 Gen10\nCZ1234TEST' });
  assert.deepEqual([lin.os, lin.hostname, lin.vendor, lin.model, lin.serial, lin.cpus, lin.mem_gb], ['Red Hat Enterprise Linux 9.4 (Plow)', 'app7.corp.local', 'HPE', 'ProLiant DL380 Gen10', 'CZ1234TEST', 16, 63]);
  assert.equal(L.parseUnix({ cores: 'cpu cores\t: 16' }).cores_per_socket, 16);
  assert.equal(L.parseUnix({ cores: 'The physical processor has 8 cores and 64 virtual processors (0-63)' }).cores_per_socket, 8);
  assert.equal(L.parseUnix({ dmi: 'QEMU\nStandard PC\nNot Specified' }).serial, null, 'placeholder serials are not serials');
  assert.equal(L.parseUnix({ uname: 'SunOS x 5.10 Generic sun4u' }).os, 'Oracle Solaris 10');
});

test('parseDb: edition, instance and host per engine; system schemas dropped; partial reads named', () => {
  const ms = L.parseDb({ engine: 'mssql', version: 'Microsoft SQL Server 2019 (RTM-CU22)', instance: 'SQLPRD01|FINANCE|15.0.4322.2|Enterprise Edition (64-bit)', databases: ['master', 'Finance', 'HR'] });
  assert.deepEqual([ms.edition, ms.instance, ms.host_name, ms.databases.join()], ['Enterprise Edition (64-bit)', 'FINANCE', 'sqlprd01', 'master,Finance,HR']);
  const my = L.parseDb({ engine: 'mysql', version: '8.0.36 MySQL Community Server', instance: 'web01|3306', databases: ['information_schema', 'mysql', 'shop'], databases_error: undefined, instance_error: 'denied' });
  assert.deepEqual([my.host_name, my.databases.join(), my.partial.join()], ['web01', 'shop', 'instance: denied']);
});

test('trust: first key pending, same key kept, a different key after trust is CHANGED until an admin trusts it again', () => {
  const m = new Map(), audits = [];
  const store = { collection: () => ({ get: (k) => m.get(k), put: (o) => m.set(o.id, JSON.parse(JSON.stringify(o))), patch: (k, f) => { const o = m.get(k); f(o); m.set(k, o); }, remove: (k) => m.delete(k), all: (f) => [...m.values()].filter((x) => !f || f(x)) }) };
  const T = L.createTrust(store, (e) => audits.push(e));
  assert.equal(T.see('ssh', '10.0.0.5', 22, 'a'.repeat(64)).state, 'pending');
  assert.equal(T.see('ssh', '10.0.0.5', 22, 'b'.repeat(64)).fp, 'b'.repeat(64), 'still pending: newest key shown');
  T.decide(['ssh:10.0.0.5:22'], 'trust', { user: 'siva', role: 'admin' });
  assert.equal(T.get('ssh', '10.0.0.5', 22).state, 'trusted');
  const ch = T.see('ssh', '10.0.0.5', 22, 'c'.repeat(64));
  assert.deepEqual([ch.state, ch.fp, ch.new_fp], ['changed', 'b'.repeat(64), 'c'.repeat(64)], 'the trusted key is kept, the new one is not used');
  T.decide(['ssh:10.0.0.5:22'], 'trust', { user: 'siva', role: 'admin' });
  assert.deepEqual([T.get('ssh', '10.0.0.5', 22).state, T.get('ssh', '10.0.0.5', 22).fp, T.get('ssh', '10.0.0.5', 22).prev_fp], ['trusted', 'c'.repeat(64), 'b'.repeat(64)]);
  T.decide(['ssh:10.0.0.5:22'], 'forget', { user: 'siva', role: 'admin' });
  assert.equal(T.get('ssh', '10.0.0.5', 22), null);
  assert.deepEqual(audits.map((a) => a.action), ['discovery.trust.trust', 'discovery.trust.trust', 'discovery.trust.forget']);
});

function findPy() {
  for (const p of [process.env.SENTRA_TEST_PARAMIKO_PY, '/opt/sentra-siem/pyenv/bin/python3', 'python3'].filter(Boolean)) {
    const r = spawnSync(p, ['-c', 'import paramiko'], { stdio: 'ignore' });
    if (r.status === 0) return p;
  }
  return null;
}
const PY = findPy();

test('real inv-helper.py over SSH: key read without login, wrong pin stops before the password, fixed commands only', { skip: !PY && 'Python with paramiko not installed (set SENTRA_TEST_PARAMIKO_PY)', timeout: 60000 }, async () => {
  const srv = spawn(PY, [path.join(__dirname, 'helpers', 'fake-unix-ssh.py')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = [];
  try {
    const head = await new Promise((ok, bad) => { let b = ''; srv.stdout.on('data', (d) => { b += d; const ls = b.split('\n'); b = ls.pop(); for (const l of ls) { lines.push(l); if (l.startsWith('PORT ')) ok(l); } }); srv.on('exit', () => bad(new Error('fake server exited'))); });
    const [, port, , fp] = head.split(' ');
    const run = L.realRunner(PY, 30000);
    const hk = await run({ op: 'hostkey', host: '127.0.0.1', port: Number(port) });
    assert.deepEqual([hk.ok, hk.fp], [true, fp]);
    assert.ok(!lines.some((l) => l.startsWith('AUTH')), 'reading the key sent no login');
    const wrong = await run({ op: 'ssh_facts', host: '127.0.0.1', port: Number(port), username: 'itamro', password: 'Synthetic-Ssh-9', fp: 'f'.repeat(64) });
    assert.deepEqual([wrong.ok, wrong.error_class, wrong.fp], [false, 'hostkey_changed', fp]);
    assert.ok(!lines.some((l) => l.startsWith('AUTH')), 'no password went to a server with the wrong key');
    const bad = await run({ op: 'ssh_facts', host: '127.0.0.1', port: Number(port), username: 'itamro', password: 'nope', fp });
    assert.deepEqual([bad.ok, bad.error_class], [false, 'auth']);
    const good = await run({ op: 'ssh_facts', host: '127.0.0.1', port: Number(port), username: 'itamro', password: 'Synthetic-Ssh-9', fp });
    assert.equal(good.ok, true, JSON.stringify(good));
    const u = L.parseUnix(good.facts);
    assert.deepEqual([u.os, u.hostname, u.model, u.serial], ['Oracle Solaris 11.4 SPARC', 'sol02', 'SPARC S7-2', 'AK00FAKE02']);
    const execs = lines.filter((l) => l.startsWith('EXEC ')).map((l) => l.slice(5));
    const allowed = require('node:fs').readFileSync(L.HELPER, 'utf8');
    assert.ok(execs.length >= 8 && execs.every((c) => allowed.includes(JSON.stringify(c).slice(1, -1))), 'only commands from the fixed list ran');
    const unk = await run({ op: 'exec', cmd: 'rm -rf /' });
    assert.equal(unk.error_class, 'config', 'there is no free-form command operation');
    const nodb = await run({ op: 'db', engine: 'oracle', host: '127.0.0.1', port: 1, username: 'u', password: 'p' });
    assert.ok(['missing_module', 'refused', 'unreachable', 'error', 'timeout'].includes(nodb.error_class), JSON.stringify(nodb));
  } finally { srv.kill(); }
});
