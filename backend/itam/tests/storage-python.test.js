// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The first module moved to Python (docs/PYTHON-MIGRATION.md): pyengine/storage_sources.py must answer exactly like
// engine/storage-sources.js. Both read the same simulated NetApp ONTAP and HPE MSA arrays over real HTTP on loopback;
// the answers are compared field for field. Plus the Python read-only guard, the bridge's fallback to Node.js when
// Python is missing, and credentials only on stdin.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const S = require('../engine/storage-sources');
const { createStorageSourcesPy } = require('../engine/storage-sources-py');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const TB = 1e12;

function ontapApi(p, h) {
  if (h.authorization !== 'Basic ' + Buffer.from('monitor:Pw-1').toString('base64')) return [401, {}];
  const R = (x) => [200, x];
  if (p === '/api/cluster') return R({ name: 'NTAP-HQ', version: { full: 'NetApp Release 9.13.1P5' } });
  if (p === '/api/cluster/nodes') return R({ records: [{ name: 'NTAP-HQ-01', model: 'AFF-A250', serial_number: '9520001', state: 'up', ha: { partners: [{ name: 'NTAP-HQ-02' }] } }, { name: 'NTAP-HQ-02', model: 'AFF-A250', serial_number: '9520002', state: 'down' }] });
  if (p === '/api/storage/aggregates') return R({ records: [{ name: 'aggr1', state: 'online', node: { name: 'NTAP-HQ-01' }, space: { block_storage: { size: 10 * TB, used: 9.7 * TB, available: 0.3 * TB } } }, { name: 'aggr2', state: 'offline', space: { block_storage: { size: 10 * TB, used: 5 * TB, available: 5 * TB } } }, { name: 'aggr3' }] });
  if (p === '/api/storage/volumes') return R({ records: [{ name: 'vol_sql', svm: { name: 'svm1' }, state: 'online', type: 'rw', aggregates: [{ name: 'aggr1' }], space: { size: 1e12, used: 0.95e12 } }, { name: 'vol_fs', svm: { name: 'svm1' }, state: 'online', space: { size: 2e12, used: 0.5e12 } }, { name: 'vol_empty' }] });
  if (p === '/api/storage/disks') return R({ records: [{ name: '1.0.1', state: 'present', container_type: 'aggregate' }, { name: '1.0.7', state: 'broken', container_type: 'broken', model: 'X371', serial_number: 'S3X', node: { name: 'NTAP-HQ-01' }, bay: 7 }, { name: '1.0.9', state: 'spare', container_type: 'spare' }] });
  if (p === '/api/support/ems/events') return R({ records: [{ time: '2026-10-13T09:00:00Z', log_message: 'disk.failed: disk 1.0.7 failed', message: { severity: 'ERROR' }, node: { name: 'NTAP-HQ-01' } }, { time: '2026-10-13T12:00:00+03:00', log_message: 'x'.repeat(400), message: { severity: 'alert' } }] });
  return [404, {}];
}
function msaApi(basic, md5) {
  const key = 'abcdef0123456789', hash = crypto.createHash(md5 ? 'md5' : 'sha256').update('mon_Pw-2').digest('hex');
  return (p, h) => {
    const R = (x) => [200, x];
    if (p === '/api/login') return basic && h.authorization === 'Basic ' + Buffer.from('mon:Pw-2').toString('base64') ? R({ status: [{ response: key, 'return-code': 1 }] }) : [401, {}];
    if (p === '/api/login/' + hash) return R({ status: [{ response: key, 'return-code': 1 }] });
    if (h.sessionkey !== key || h.datatype !== 'json') return R({ status: [{ response: 'Invalid sessionkey', 'return-code': -10027 }] });
    if (p === '/api/show/system') return R({ system: [{ 'system-name': 'MSA-DR', 'product-id': 'MSA 2060 SAN', 'midplane-serial-number': 'MXQ123', health: 'Degraded' }] });
    if (p === '/api/show/controllers') return R({ controllers: [{ 'controller-id': 'A', status: 'Operational', health: 'OK', 'serial-number': 'CA1', 'sc-fw': 'IN110R004' }, { 'durable-id': 'controller_b', status: 'Operational', 'health-numeric': 1 }] });
    if (p === '/api/show/pools') return R({ pools: [{ name: 'A', health: 'OK', 'total-size-numeric': String(2 * TB / 512), 'total-avail-numeric': String(0.2 * TB / 512) }, { name: 'B', 'health-numeric': 2, 'total-size': '1.2TB', 'total-avail': '600.5GB' }] });
    if (p === '/api/show/disks') return R({ drives: [{ location: '0.1', health: 'OK', usage: 'VIRTUAL POOL' }, { location: '0.5', health: 'Fault', usage: 'FAILED', 'serial-number': 'ZZ9', model: 'ST1200' }, { location: '0.12', health: 'OK', usage: 'GLOBAL SPARE' }, { 'durable-id': 'disk_0.13', health: 'Degraded' }] });
    if (p === '/api/show/volumes') return R({ volumes: [{ 'volume-name': 'esx-ds1', 'storage-pool-name': 'A', health: 'OK', 'size-numeric': String(1 * TB / 512), 'allocated-size-numeric': String(0.5 * TB / 512) }, { name: 'vol2', 'virtual-disk-name': 'vd1', health: 'Fault', size: '500GB' }] });
    if (p === '/api/show/events/last/50') return R({ events: [{ 'time-stamp': '2026-10-13 10:00:00', severity: 'CRITICAL', message: 'Disk 0.5 failed', controller: 'A' }, { 'time-stamp': '2026-10-13 10:01:00', severity: 'INFORMATIONAL', message: 'ok' }, { severity: 'WARNING', message: 'no time' }] });
    if (p === '/api/exit') return R({ status: [{ 'return-code': 1 }] });
    return [404, {}];
  };
}
async function serve(api, calls) {
  const srv = http.createServer((q, r) => { const u = new URL(q.url, 'http://x'); calls.push([q.method, u.pathname]); const [st, body] = api(u.pathname, q.headers); r.writeHead(st, { 'content-type': 'application/json' }); r.end(JSON.stringify(body)); });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { base: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((ok) => srv.close(ok)) };
}
const strip = (r) => { const o = JSON.parse(JSON.stringify(r)); delete o.ms; delete o.engine; return o; };

test('Python storage reader answers exactly like the Node.js one (ONTAP, MSA basic + older firmware, wrong password)', { skip: !hasPy && 'python3 not available' }, async () => {
  const P = createStorageSourcesPy({ python: PY });
  for (const [kind, api, user, pw] of [['ontap', ontapApi, 'monitor', 'Pw-1'], ['msa', msaApi(true), 'mon', 'Pw-2'], ['msa', msaApi(false), 'mon', 'Pw-2'], ['msa', msaApi(false, true), 'mon', 'Pw-2'], ['ontap', ontapApi, 'monitor', 'wrong']]) {
    const nc = [], pc = [], s1 = await serve(api, nc), s2 = await serve(api, pc);
    try {
      const n = await S[kind]({ target: { base_url: s1.base }, secret: { username: user, password: pw } }, {});
      const p = await P[kind]({ target: { base_url: s2.base }, secret: { username: user, password: pw } }, {});
      assert.equal(p.engine, 'python');
      assert.deepEqual(strip(p), strip(n), `${kind} ${pw}: identical answers`);
      assert.deepEqual(pc, nc, `${kind}: the same requests, in the same order`);
      assert.ok(pc.every((c) => c[0] === 'GET'), 'GET only');
      if (pw === 'wrong') assert.equal(p.error_class, 'auth'); else assert.equal(p.ok, true);
    } finally { await s1.close(); await s2.close(); }
  }
  const s3 = await serve(msaApi(true), []);
  try {
    const t = await P.test('msa', { target: { base_url: s3.base }, secret: { username: 'mon', password: 'Pw-2' } }, {});
    assert.match(t.message || '', /^Connected: MSA-DR - 2 pool\(s\), 2 volume\(s\), 4 disk\(s\)\.$/);
  } finally { await s3.close(); }
});

test('Python: read-only guard, https-only address, unreachable classified', { skip: !hasPy && 'python3 not available' }, async () => {
  const r = spawnSync(PY, ['-I', '-c', `
import sys; sys.path.insert(0, ${JSON.stringify(require('node:path').join(__dirname, '..', 'pyengine'))})
import storage_sources as s
bad = 0
for k, m, p in [('ontap','PATCH','/api/storage/volumes/x'), ('ontap','GET','/api/private/cli/system'), ('msa','GET','/api/delete/volumes/x'), ('msa','GET','/api/set/user')]:
    try: s.guard(k, m, p); bad += 1
    except s.StorageError as e: assert 'read-only' in str(e)
s.guard('msa', 'GET', '/api/show/pools')
for u in ['http://10.1.1.1', 'ftp://x', 'https://bad host']:
    try: s.base_of(u); bad += 1
    except s.StorageError: pass
assert s.base_of('https://NTAP.local:443/') == 'https://ntap.local'
r = s.ontap({'target': {'base_url': 'http://127.0.0.1:9'}, 'secret': {'username': 'u', 'password': 'p'}})
assert r['ok'] is False and r['error_class'] == 'unreachable', r
print('ok' if bad == 0 else 'FAIL %d' % bad)`], { encoding: 'utf8' });
  assert.equal(r.stdout.trim(), 'ok', r.stderr);
});

test('bridge: Python missing → the Node.js reader answers and says so; the password only travels on stdin', async () => {
  const nc = [], s1 = await serve(ontapApi, nc);
  try {
    const P = createStorageSourcesPy({ python: '/nonexistent/python3' });
    const r = await P.ontap({ target: { base_url: s1.base }, secret: { username: 'monitor', password: 'Pw-1' } }, {});
    assert.equal(r.ok, true); assert.match(r.engine, /^node \(python unavailable/);
  } finally { await s1.close(); }
  const src = require('node:fs').readFileSync(require.resolve('../engine/pyengine'), 'utf8');
  assert.match(src, /spawn\(python, \['-I', RUN\]/, 'no request data on the command line');
  assert.ok(hasPy ? (await createPyEngine({ python: PY }).ping()).ok : true);
});

test('Python TLS: pinned self-signed certificate works; a wrong pin sends nothing; Test captures the certificate for Trust & pin', { skip: !hasPy && 'python3 not available' }, async () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), https = require('node:https');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pytls-'));
  const g = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(d, 'k.pem'), '-out', path.join(d, 'c.pem'), '-days', '2', '-subj', '/CN=msa-dr.test'], { encoding: 'utf8' });
  if (g.status !== 0) return;   // no openssl here
  const der = crypto.createPublicKey(fs.readFileSync(path.join(d, 'c.pem'))) && new crypto.X509Certificate(fs.readFileSync(path.join(d, 'c.pem'))).raw;
  const fp = crypto.createHash('sha256').update(der).digest('hex');
  const calls = [], api = msaApi(true);
  const srv = https.createServer({ key: fs.readFileSync(path.join(d, 'k.pem')), cert: fs.readFileSync(path.join(d, 'c.pem')) }, (q, r) => { const u = new URL(q.url, 'https://x'); calls.push(u.pathname); const [st, body] = api(u.pathname, q.headers); r.writeHead(st, { 'content-type': 'application/json' }); r.end(JSON.stringify(body)); });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  try {
    const P = createStorageSourcesPy({ python: PY }), base = `https://127.0.0.1:${srv.address().port}`, secret = { username: 'mon', password: 'Pw-2' };
    const t = await P.test('msa', { target: { base_url: base }, secret }, {});
    assert.equal(t.ok, false); assert.equal(t.error_class, 'tls'); assert.equal(t.presented.fingerprint256, fp, 'the presented certificate is captured');
    assert.equal(t.presented.subject, 'CN=msa-dr.test');
    assert.equal(calls.length, 0, 'nothing was sent to an untrusted array');
    const w = await P.msa({ target: { base_url: base, tls_fingerprint: 'ab'.repeat(32) }, secret }, {});
    assert.equal(w.error_class, 'tls'); assert.equal(calls.length, 0, 'a wrong pin sends nothing');
    const r = await P.msa({ target: { base_url: base, tls_fingerprint: fp }, secret }, {});
    assert.equal(r.ok, true, r.error); assert.equal(r.system.name, 'MSA-DR');
  } finally { await new Promise((ok) => srv.close(ok)); }
});
