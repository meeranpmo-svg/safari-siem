// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database logins over TLS (engine/discovery/inv-helper.py connect_db): with tls "require"/"verify" a server that will not
// do TLS gets no login packet at all - the user name and password never leave in clear - and the failure is classed
// "tls"; with tls "off" (legacy) the same server does receive the login in clear, which is why the credential evidence
// report lists such logins as "not encrypted in transit". Real PyMySQL / pg8000 against fake servers on 127.0.0.1.
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');

const PY = process.env.SENTRA_TEST_DB_PY || 'python3';
const HELPER = path.join(__dirname, '../engine/discovery/inv-helper.py');
const has = (m) => spawnSync(PY, ['-c', 'import ' + m]).status === 0;

function fakeServer(onConn) {
  const got = [];
  const srv = net.createServer((s) => { s.on('data', (d) => got.push(d)); s.on('error', () => {}); onConn(s); });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port, bytes: () => Buffer.concat(got) })));
}
function helper(req) {
  return new Promise((resolve) => {
    const p = spawn(PY, [HELPER], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = ''; p.stdout.on('data', (d) => { out += d; });
    p.on('close', () => { try { resolve(JSON.parse(out)); } catch { resolve({ raw: out }); } });
    p.stdin.end(JSON.stringify(req));
  });
}
const USER = 'zyb_monitor_user', PASS = 'S3cret-Pass-Never-Clear';

test('postgres: tls require + a server that refuses TLS → nothing sent, class tls; tls off → login in clear', { skip: !has('pg8000') && 'pg8000 not installed' }, async () => {
  const f = await fakeServer((s) => s.once('data', (d) => { if (d.length === 8 && d.readUInt32BE(4) === 80877103) s.write('N'); else s.end(); }));
  const r = await helper({ op: 'db', engine: 'postgres', host: '127.0.0.1', port: f.port, username: USER, password: PASS, tls: 'require' });
  assert.equal(r.ok, false); assert.equal(r.error_class, 'tls', JSON.stringify(r));
  const b = f.bytes().toString('latin1'); assert.ok(!b.includes(USER) && !b.includes(PASS), 'no login packet when TLS was refused');
  f.srv.close();
  const g = await fakeServer((s) => setTimeout(() => s.end(), 300));
  await helper({ op: 'db', engine: 'postgres', host: '127.0.0.1', port: g.port, username: USER, password: PASS, tls: 'off' });
  assert.ok(g.bytes().toString('latin1').includes(USER), 'legacy tls off: the login goes out in clear (reported as such)');
  g.srv.close();
});

test('mysql: tls require + a server not offering TLS → refused before the login packet, class tls', { skip: !has('pymysql') && 'PyMySQL not installed' }, async () => {
  // handshake v10 without CLIENT_SSL (0x0800)
  const body = Buffer.concat([Buffer.from([10]), Buffer.from('8.0.36\0'), Buffer.from([1, 0, 0, 0]), Buffer.from('abcdefgh'), Buffer.from([0]),
    Buffer.from([0x01 | 0x00, 0x82]), Buffer.from([0x21]), Buffer.from([2, 0]), Buffer.from([0x08, 0x00]), Buffer.from([21]), Buffer.alloc(10), Buffer.from('ijklmnopqrst\0'), Buffer.from('mysql_native_password\0')]);
  const pkt = Buffer.concat([Buffer.from([body.length & 255, (body.length >> 8) & 255, 0, 0]), body]);
  const f = await fakeServer((s) => { s.write(pkt); setTimeout(() => s.end(), 1500); });
  const r = await helper({ op: 'db', engine: 'mysql', host: '127.0.0.1', port: f.port, username: USER, password: PASS, tls: 'require' });
  assert.equal(r.ok, false); assert.equal(r.error_class, 'tls', JSON.stringify(r));
  assert.ok(!f.bytes().toString('latin1').includes(USER), 'no login packet');
  f.srv.close();
});

test('sql server: TLS needs the CA file - a config error, never a plaintext login', async () => {
  const r = await helper({ op: 'db', engine: 'mssql', host: '127.0.0.1', port: 1, username: USER, password: PASS, tls: 'require' });
  assert.equal(r.ok, false);
  assert.ok(r.error_class === 'config' || r.error_class === 'missing_module', JSON.stringify(r));
});
