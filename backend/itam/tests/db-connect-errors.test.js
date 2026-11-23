// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Why a database connection failed (engine/discovery/inv-helper.py classify + engine/db-health.js hints). python-oracledb
// wraps every network failure in DPY-6005, which was read as a TLS problem: a database added by a host name the platform
// server cannot resolve ("[Errno -3] Temporary failure in name resolution") was reported as "tls". Now: dns / service /
// busy / refused / timeout each get their class and a fix the DBA can act on, a real TLS failure is still "tls", and a
// busy or unresolvable database is never paused (only a refused login or an over-privileged account is).
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createDbHealth } = require('../engine/db-health');
const { createSealer } = require('../engine/discovery/vault');

const PY = ['python3', 'python'].find((p) => spawnSync(p, ['-c', 'pass']).status === 0);
const HELPER = path.join(__dirname, '../engine/discovery/inv-helper.py');
function classify(msgs) {
  const code = 'import importlib.util,json,sys\ns=importlib.util.spec_from_file_location("h",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
    + 'class OperationalError(Exception): pass\nprint(json.dumps([m.classify(OperationalError(x)) for x in json.loads(sys.stdin.read())]))';
  const r = spawnSync(PY, ['-I', '-c', code, HELPER], { input: JSON.stringify(msgs), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); return JSON.parse(r.stdout);
}

test('classify: DPY-6005 is the wrapper, the cause decides - DNS, service, busy, refused, timeout, TLS, login', { skip: !PY && 'python missing' }, () => {
  const got = classify([
    'DPY-6005: cannot connect to database (CONNECTION_ID=abc). [Errno -3] Temporary failure in name resolution',
    'DPY-6005: cannot connect to database. [Errno -2] Name or service not known',
    'DPY-6005: cannot connect to database. ORA-12514: Cannot connect to database. Service IRISLIVE is not registered with the listener',
    'ORA-12528: TNS:listener: all appropriate instances are blocking new connections',
    'ORA-12516: TNS:listener could not find available handler with matching protocol stack',
    'DPY-6005: cannot connect to database. [Errno 111] Connection refused',
    'DPY-6005: cannot connect to database. timed out',
    'DPY-6005: cannot connect to database. [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed',
    'ORA-01017: invalid username/password; logon denied',
  ]);
  assert.deepEqual(got, ['dns', 'dns', 'service', 'busy', 'busy', 'refused', 'timeout', 'tls', 'auth']);
});

test('db-health: a database added by a name the server cannot resolve says so and how to fix it; it is not paused', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const creds = [];
  const vault = {
    available: () => true, list: () => creds.slice(), get: (id) => creds.find((c) => c.id === id) || null,
    create: (b) => { const c = { id: 'cr' + (creds.length + 1), kind: b.kind, label: b.label, target: b.target }; c._secret = b.secret; creds.push(c); return c; },
    open: (id) => { const c = creds.find((x) => x.id === id); return { secret: Object.assign({}, c._secret), release() {} }; },
  };
  let answer = { ok: false, error_class: 'dns', error: 'DPY-6005: cannot connect to database. [Errno -3] Temporary failure in name resolution' };
  const H = createDbHealth(e.app, {
    discovery: { vault, siem: { call: async () => ({ status: 200, json: { source: { id: 'oracle-health' }, token: 't1' } }) } },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: async (r) => (r.op === 'oracle_audit' ? { ok: true, rows: [] } : answer),
    request: async () => ({ status: 200 }),
  });
  const ADM = { user: 'syed', role: 'admin', ip: '' };
  const d = await H.addDb({ label: 'IRISLIVE SYN', host: 'irislive-syn', service: 'IRISLIVE', username: 'zyb_monitor', password: 'Syn-pw-1' }, ADM);
  assert.equal(d.last_test.ok, false); assert.equal(d.last_test.cls, 'dns');
  assert.match(d.last_test.error, /Temporary failure in name resolution/, 'the driver text is kept');
  assert.match(d.last_test.error, /cannot resolve "irislive-syn" in DNS.*IP address instead/, 'and the fix is named: ' + d.last_test.error);
  assert.equal(d.paused, null, 'a DNS problem is not a login problem: not paused');
  assert.ok(!d.last_test.error.includes('Syn-pw-1'));
  answer = { ok: false, error_class: 'service', error: 'ORA-12514: service ESKA is not registered with the listener' };
  const s = await H.testDb(d.id, ADM);
  assert.match(s.last_test.error, /does not know the service "IRISLIVE".*lsnrctl status/);
  answer = { ok: false, error_class: 'busy', error: 'ORA-12528: all appropriate instances are blocking new connections' };
  const b = await H.testDb(d.id, ADM);
  assert.match(b.last_test.error, /tried again on the next pass/); assert.equal(b.paused, null);
  const p = await H.pass(); assert.equal(p.failed, 1, 'still read on the next pass');
});
