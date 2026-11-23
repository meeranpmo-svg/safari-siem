// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9a (docs/PYTHON-MIGRATION.md): the resident Python service (pyengine/serve.py) keeps the store in memory
// and reads only what the Node.js engine appended. It must never answer from stale data: after every kind of write the
// engine makes - new records, edits, deletes, a compaction, a line still being written, records written during a
// compaction - its answer must equal a fresh read of the files. It must refuse the operations that are not store reads
// (the device readers carry credentials and keep a process per call), live behind a private 0700 folder, and when it
// dies the caller must still get the right answer (one process per call) while it is restarted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { createStore } = require('../engine/store');
const { createPyEngine, residentFor } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;

test('resident service: always current, refuses non-read operations, private, falls back when it dies', { skip: !hasPy && 'python3 not available' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-res-'));
  const S = createStore({ dir }), A = S.collection('assets'), R = S.collection('relationships');
  const py = createPyEngine({ python: PY }), once = (op, b) => py.callOnce(op, b);
  const same = async (what) => {
    for (const [op, b] of [['assets.list', { query: { limit: '5000' } }], ['assets.cmdb', { query: {} }], ['assets.detail', { id: 'a3' }], ['assets.lookup', { tag: 'TAG-7' }]]) {
      const live = await py.call(op, Object.assign({ dir }, b)), fresh = await once(op, Object.assign({ dir }, b));
      assert.deepEqual(live, fresh, what + ': ' + op);
    }
  };
  for (let i = 0; i < 50; i++) A.put({ id: 'a' + i, name: 'Asset ' + i, asset_tag: 'TAG-' + i, type: 'server', status: 'in_use', prov: { x: 1 } });
  R.put({ id: 'r1', from: 'a1', to: 'a2', type: 'runs_on', key: 'k' });
  await same('first read');
  const r = residentFor(PY);
  assert.ok(r.child, 'the resident service is running');
  assert.equal(fs.statSync(path.dirname(r.sock)).mode & 0o777, 0o700, 'its socket lives in a private folder');
  A.put({ id: 'a50', name: 'New one', type: 'vm', status: 'in_use' }); await same('a new record');
  A.patch('a3', (x) => { x.name = 'Renamed'; x.asset_tag = 'TAG-7'; }); await same('an edit');
  A.remove('a10'); R.remove('r1'); await same('deletes');
  S.snapshot(); await same('after a compaction');
  A.put({ id: 'a51', name: 'After compaction' }); A.remove('a11'); await same('writes after a compaction');
  fs.appendFileSync(path.join(dir, 'assets.jsonl'), '{"op":"put","o":{"id":"half","name":"being wri');
  await same('a line still being written');
  fs.appendFileSync(path.join(dir, 'assets.jsonl'), 'tten"}}\n');
  assert.ok((await py.call('assets.list', { dir, query: {} })).assets.some((a) => a.id === 'half'), 'the line once complete');
  for (let k = 0; k < 5; k++) { for (let i = 0; i < 30; i++) A.put({ id: 'b' + k + '_' + i, n: i }); S.snapshot(); A.put({ id: 'c' + k }); await same('compaction round ' + k); }
  // only store reads: a device reader is refused by the service (and so runs in its own process, as before)
  const refused = await new Promise((resolve) => {
    const body = JSON.stringify({ op: 'discovery.collect', method: 'vcenter', cred: {} });
    const q = http.request({ socketPath: r.sock, method: 'POST', path: '/call', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { let t = ''; res.on('data', (d) => { t += d; }); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(t) })); });
    q.end(body);
  });
  assert.equal(refused.status, 400); assert.match(refused.body.error, /not a resident operation/);
  // the two allow-lists are the same, and no credential-carrying reader is on them
  const pyList = JSON.parse(spawnSync(PY, ['-I', '-c', 'import sys,json; sys.path.insert(0, sys.argv[1]); import serve; print(json.dumps(serve.READ_OPS))', path.join(__dirname, '..', 'pyengine')], { stdio: ['ignore', 'pipe', 'pipe'] }).stdout.toString());
  const jsSrc = fs.readFileSync(path.join(__dirname, '..', 'engine', 'pyengine.js'), 'utf8'), jsList = JSON.parse('[' + /RESIDENT_OPS = new Set\(\[([^\]]+)\]/.exec(jsSrc)[1].replace(/'/g, '"') + ']');
  assert.deepEqual(jsList.sort(), pyList.slice().sort(), 'the same allow-list in Node.js and Python');
  for (const op of pyList) assert.ok(!/^(storage|backup|cisco|virt|discovery)\./.test(op), op + ' carries no credentials');
  // it dies: the next calls still answer correctly (one process per call), nothing is lost
  r.child.kill('SIGKILL'); await new Promise((res) => setTimeout(res, 200));
  A.put({ id: 'after-crash', name: 'after-crash' });
  const a = await py.call('assets.list', { dir, query: { q: 'after-crash' } });
  assert.equal(a.total, 1, 'answered without the resident service');
  S.close();
});
