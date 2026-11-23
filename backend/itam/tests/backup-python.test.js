// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 2 (docs/PYTHON-MIGRATION.md): pyengine/backup_sources.py must answer exactly like engine/backup-sources.js.
// Both read the same simulated NetBackup, Veeam and Cohesity servers over real HTTP on loopback (paging, partial / failed
// runs, running jobs, missing fields, a wrong key); answers and the requests they made are compared field for field.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const S = require('../engine/backup-sources');
const { createBackupSourcesPy } = require('../engine/backup-sources-py');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-12T12:00:00Z'), H = 3600000;
const at = (h) => new Date(NOW - h * H).toISOString();

function nbApi(u, q, h) {
  if (h.authorization !== 'A1b2-key') return [401, {}];
  if (!/version=14\.0/.test(h.accept || '')) return [406, {}];
  if (u.pathname === '/netbackup/admin/jobs') {
    const off = Number(u.searchParams.get('page[offset]'));
    if (off === 0) return [200, { data: [
      { id: '1', attributes: { jobId: 1, policyName: 'WIN-DAILY', clientName: ('DC-HQA.' + 'corp-hq.com'), status: 0, state: 'DONE', startTime: at(10), endTime: at(9), kilobytesTransferred: 1024 } },
      { id: '2', attributes: { jobId: 2, policyName: 'ORA-RMAN', clientName: 'oradb01', status: 13, state: 'DONE', startTime: at(5), endTime: at(5) } },
      { id: '4', attributes: { jobId: 4, policyName: 'ORA-RMAN', clientName: 'OraDB01', status: 1, state: 'DONE', startTime: at(2), endTime: at(1.5), kilobytesTransferred: '2048' } },
      { id: '5', attributes: { jobId: 5, policyName: 'FILE', clientName: 'fs02', state: 'ACTIVE', startTime: at(0.5) } },
      { id: '6', attributes: { policyName: 'X', status: null, state: 'DONE' } }], meta: { pagination: { next: 5 } } }];
    return [200, { data: [{ id: '3', attributes: { jobId: 3, policyName: 'ORA-RMAN', clientName: 'oradb01', status: 0, state: 'DONE', startTime: at(60), endTime: at(59) } }], meta: { pagination: { offset: 5, last: 5 } } }];
  }
  if (u.pathname === '/netbackup/catalog/images') return [200, { data: [{ attributes: { clientName: 'legacy-ftp', backupTime: at(3), policyName: 'MISC', kilobytes: 2048 } }, { attributes: { clientName: 'fs02', backupTime: at(20) } }, { attributes: {} }], meta: { pagination: {} } }];
  return [404, {}];
}
function veeamApi(u, q, h, body) {
  if (u.pathname === '/api/oauth2/token') return /grant_type=password&username=svc-ro&password=Ve%23am%2B%20x/.test(body) || body === 'grant_type=password&username=svc-ro&password=Ve%23am%2B+x' ? [200, { access_token: 'T1' }] : [401, {}];
  if (h.authorization !== 'Bearer T1') return [401, {}];
  if (u.pathname === '/api/oauth2/logout') return [200, {}];
  if (u.pathname === '/api/v1/sessions') return [200, { data: [
    { id: 's1', name: 'VM-Daily', state: 'Stopped', result: { result: 'Failed', message: 'datastore full' }, creationTime: at(2), endTime: at(1) },
    { id: 's2', name: 'VM-Daily', state: 'Stopped', result: { result: 'Success' }, creationTime: at(26), endTime: at(25) },
    { id: 's3', name: 'SQL', state: 'Working', result: { result: 'None' }, creationTime: at(0.2) },
    { id: 's4', name: 'Files', state: 'Stopped', result: 'Warning', creationTime: '2026-10-12T08:00:00.1234567+03:00', endTime: '2026-10-12 06:00:00' }], pagination: { total: 4 } }];
  if (u.pathname === '/api/v1/restorePoints') return [200, { data: [{ name: 'WIN-APP1', platformName: 'VMware', creationTime: at(30) }, { name: 'win-app1', platformName: 'VMware', creationTime: at(6) }, { name: 'NAS', platformName: 'Windows', creationTime: at(8) }, { platformName: 'x' }], pagination: { total: 4 } }];
  return [404, {}];
}
function cohApi(u, q, h, body) {
  if (u.pathname === '/irisservices/api/v1/public/accessTokens') return body.includes('"password":"Co-1"') ? [200, { accessToken: 'TK', tokenType: 'Bearer' }] : [401, {}];
  if (h.authorization !== 'Bearer TK' && h.apikey !== 'coh-key') return [401, {}];
  if (u.pathname === '/irisservices/api/v1/public/protectionRuns') return [200, [
    { jobName: 'NAS-Daily', jobId: 7, backupRun: { status: 'kSuccess', jobRunId: 1, stats: { startTimeUsecs: (NOW - 4 * H) * 1000 + 499, endTimeUsecs: (NOW - 3 * H) * 1000 + 500 }, sourceBackupStatus: [{ source: { name: 'FS01' }, status: 'kSuccess', stats: { endTimeUsecs: (NOW - 3 * H) * 1000, totalLogicalBackupSizeBytes: 5e9 } }, { source: { displayName: 'ERP-DB' }, status: 'kFailure', error: 'quiesce failed' }, { source: {}, status: 'kSuccess' }] } },
    { jobName: 'NAS-Daily', jobId: 7, backupRun: { status: 'kCanceled', jobRunId: 2, stats: { startTimeUsecs: (NOW - 1 * H) * 1000 }, sourceBackupStatus: [{ source: { name: 'fs01' }, status: 'kRunning' }] } },
    { jobName: 'VM', backupRun: { status: 'kWarning', error: '', stats: {} } }]];
  return [404, {}];
}
async function serve(api, calls) {
  const srv = http.createServer((q, r) => { let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => { const u = new URL(q.url, 'http://x'); calls.push([q.method, u.pathname + u.search]); const [st, body] = api(u, q, q.headers, b); r.writeHead(st, { 'content-type': 'application/json' }); r.end(JSON.stringify(body)); }); });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { base: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((ok) => srv.close(ok)) };
}
const strip = (r) => { const o = JSON.parse(JSON.stringify(r)); delete o.ms; delete o.engine; return o; };

test('Python backup readers answer exactly like the Node.js ones (NetBackup, Veeam, Cohesity; good and wrong credentials)', { skip: !hasPy && 'python3 not available' }, async () => {
  const P = createBackupSourcesPy({ python: PY });
  const cases = [
    ['netbackup', nbApi, { api_key: 'A1b2-key' }, {}], ['netbackup', nbApi, { api_key: 'wrong' }, {}], ['netbackup', nbApi, { api_key: 'A1b2-key' }, { api_version: '13.0' }],
    ['veeam', veeamApi, { username: 'svc-ro', password: 'Ve#am+ x' }, {}], ['veeam', veeamApi, { username: 'svc-ro', password: 'no' }, {}],
    ['cohesity', cohApi, { api_key: 'coh-key' }, {}], ['cohesity', cohApi, { username: 'admin', password: 'Co-1' }, { domain: 'CORP' }], ['cohesity', cohApi, {}, {}],
  ];
  for (const [kind, api, secret, extra] of cases) {
    const nc = [], pc = [], s1 = await serve(api, nc), s2 = await serve(api, pc);
    try {
      const n = await S[kind]({ target: Object.assign({ base_url: s1.base }, extra), secret }, { now: NOW });
      const p = await P[kind]({ target: Object.assign({ base_url: s2.base }, extra), secret }, { now: NOW });
      const label = `${kind} ${JSON.stringify(secret)} ${JSON.stringify(extra)}`;
      assert.equal(p.engine, 'python', label);
      assert.deepEqual(strip(p), strip(n), label + ': identical answers');
      assert.deepEqual(pc, nc, label + ': the same requests, in the same order');
    } finally { await s1.close(); await s2.close(); }
  }
  // the system saved as Cohesity is really a NetBackup primary (address = its /webui console): both readers say so
  const nb404 = () => [404, { errorMessage: 'not found' }], w1 = await serve(nb404, []), w2 = await serve(nb404, []);
  try {
    const n = await S.cohesity({ target: { base_url: w1.base + '/webui' }, secret: { username: 'admin', password: 'x' } }, { now: NOW });
    const p = await P.cohesity({ target: { base_url: w2.base + '/webui' }, secret: { username: 'admin', password: 'x' } }, { now: NOW });
    assert.equal(n.ok, false); assert.match(n.error, /answered HTTP 404(: [^-]*)? - this address is the NetBackup web console \(\/webui\).*choose the type NetBackup/);
    assert.deepEqual(strip(p), strip(n), 'wrong type: identical answers');
  } finally { await w1.close(); await w2.close(); }
  const s3 = await serve(veeamApi, []);
  try {
    const t = await P.test('veeam', { target: { base_url: s3.base }, secret: { username: 'svc-ro', password: 'Ve#am+ x' } }, { now: NOW });
    const tn = await S.test('veeam', { target: { base_url: s3.base }, secret: { username: 'svc-ro', password: 'Ve#am+ x' } }, { now: NOW });
    assert.equal(t.message, tn.message); assert.match(t.message, /^Connected: \d+ backup runs/);
  } finally { await s3.close(); }
});

test('Python backup: read-only guard; Python missing → Node.js answers and says so', async () => {
  if (hasPy) {
    const r = spawnSync(PY, ['-I', '-c', `
import sys; sys.path.insert(0, ${JSON.stringify(require('node:path').join(__dirname, '..', 'pyengine'))})
import backup_sources as b
bad = 0
for k, m, p in [('netbackup','DELETE','/netbackup/admin/jobs/1'), ('netbackup','POST','/netbackup/admin/jobs/1/cancel'), ('veeam','POST','/api/v1/jobs/x/start'), ('cohesity','POST','/irisservices/api/v1/public/protectionJobs/run/1')]:
    try: b.guard(k, m, p); bad += 1
    except b.BackupError as e: assert 'read-only' in str(e)
assert b.base_of('https://nbu', 1556) == 'https://nbu:1556' and b.base_of('https://vbr:9420/', 9419) == 'https://vbr:9420'
print('ok' if bad == 0 else 'FAIL')`], { encoding: 'utf8' });
    assert.equal(r.stdout.trim(), 'ok', r.stderr);
  }
  const s1 = await serve(nbApi, []);
  try {
    const r = await createBackupSourcesPy({ python: '/nonexistent/python3' }).netbackup({ target: { base_url: s1.base }, secret: { api_key: 'A1b2-key' } }, { now: NOW });
    assert.equal(r.ok, true); assert.match(r.engine, /^node \(python unavailable/);
  } finally { await s1.close(); }
});
