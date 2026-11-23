// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 8a (docs/PYTHON-MIGRATION.md): pyengine/store.py must write the store exactly like engine/store.js - the
// same journal lines, snapshots and hash-chained audit records, byte for byte, including the values where JSON.stringify
// and Python disagree by default (integer-like keys first, -0, 1e21, 1.5e-7, lone surrogates, control characters,
// U+2028) - and each must read and verify the other's files. Then the read-only side that runs on the live server next to
// the Node.js writer: it refuses to write, ignores a last line still being written, never loses a journal entry while
// the writer compacts, and the audit chain check reports tampering at the same line as Node.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createStore } = require('../engine/store');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const DRIVER = path.join(__dirname, 'helpers', 'store-driver.py');
const PYENGINE = path.join(__dirname, '..', 'pyengine');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-store-'));
const py = (code, input) => { const r = spawnSync(PY, ['-I', '-c', `import sys; sys.path.insert(0, ${JSON.stringify(PYENGINE)})\n${code}`], { input: input || '' }); if (r.status) throw new Error(r.stderr.toString()); return JSON.parse(r.stdout.toString()); };
const files = (d) => fs.readdirSync(d).filter((f) => !f.endsWith('.tmp')).sort();

const ODD = { 10: 'ten', b: 'bee', 2: 'two', '01': 'not an index', '-1': 'nor this', 4294967295: 'too big for an index', a: [1, 'x', null, true, false],
  floats: [0.1 + 0.2, 1e21, 1.5e-7, 123456789.123, -0, 2 ** 53, 5e-324, 1.7976931348623157e308, 100, -2.5e-6, 1e-6],
  text: 'tab\tnl\ncr\rbs\\q"\u0001\u001f\u007f   é 中 😀 lone \ud800 and \udfff', nested: { z: { 3: [], 1: {} } } };

function ops() {
  const o = [];
  for (let i = 0; i < 40; i++) o.push({ c: 'assets', op: 'put', o: { id: 'a' + i, name: 'Asset ' + i, n: i * 1.5, odd: i % 7 ? null : ODD } });
  o.push({ c: 'assets', op: 'put', o: { id: 7, numeric: 'id' } }, { c: 'assets', op: 'patch', id: 'a3', set: { name: 'renamed', 5: 'five' } }, { c: 'assets', op: 'remove', id: 'a4' },
    { c: 'assets', op: 'patch', id: 'missing', set: { x: 1 } }, { c: 'assets', op: 'remove', id: 'missing' }, { c: 'assets', op: 'snapshot' },
    { c: 'assets', op: 'put', o: { id: 'a5', after: 'snapshot' } }, { c: 'roles', op: 'put', o: { id: 'r', odd: ODD } });
  for (let i = 0; i < 12; i++) o.push({ op: 'audit', entry: { at: `2026-${i < 6 ? '09' : '10'}-1${i % 9}T08:00:0${i % 10}.123Z`, by: 'syed', action: 'x.' + i, target: 't' + i, detail: i % 3 ? { k: i } : ODD, ...(i === 5 ? { hash: 'ignored', seq: 99 } : {}) } });
  return o;
}
function nodeApply(dir, list) {
  const s = createStore({ dir });
  for (const op of list) {
    const c = op.c ? s.collection(op.c) : null;
    if (op.op === 'put') c.put(op.o); else if (op.op === 'patch') c.patch(op.id, (x) => { Object.assign(x, op.set); }); else if (op.op === 'remove') c.remove(op.id);
    else if (op.op === 'audit') s.audit(op.entry); else if (op.op === 'snapshot') s.snapshot();
  }
  return s;
}

test('store: Python writes the same bytes as Node.js and each reads and verifies the other', { skip: !hasPy && 'python3 not available' }, () => {
  const list = ops(), dn = tmp(), dp = tmp();
  const N = nodeApply(dn, list);
  const r = spawnSync(PY, ['-I', DRIVER, dp], { input: JSON.stringify(list) });
  assert.equal(r.status, 0, r.stderr.toString());
  assert.deepEqual(files(dp), files(dn), 'the same files');
  for (const f of files(dn)) {
    if (f.endsWith('.snap.json')) {
      const a = JSON.parse(fs.readFileSync(path.join(dn, f), 'utf8')), b = JSON.parse(fs.readFileSync(path.join(dp, f), 'utf8'));
      assert.deepEqual(b.items, a.items, f);
      assert.equal(fs.readFileSync(path.join(dp, f), 'utf8').replace(/^\{"at":\d+,/, ''), fs.readFileSync(path.join(dn, f), 'utf8').replace(/^\{"at":\d+,/, ''), f + ' bytes');
    } else assert.equal(fs.readFileSync(path.join(dp, f), 'utf8'), fs.readFileSync(path.join(dn, f), 'utf8'), f + ' bytes');
  }
  // Node.js reads what Python wrote
  const P = createStore({ dir: dp });
  for (const c of ['assets', 'roles']) assert.deepEqual(P.collection(c).all(), N.collection(c).all(), c + ' read back by Node.js');
  assert.deepEqual(P.verifyAudit(), N.verifyAudit(), 'Node.js verifies the Python chain');
  assert.equal(P.verifyAudit().ok, true); assert.equal(P.verifyAudit().checked, 12);
  // Python reads what Node.js wrote
  const got = py('from store import Store; import json\ns = Store(sys.argv[1] if len(sys.argv) > 1 else ' + JSON.stringify(dn) + ', readonly=True)\nprint(json.dumps({"assets": s.collection("assets").all(), "roles": s.collection("roles").all(), "verify": s.verify_audit(), "tail": s.audit_tail(3)}))');
  assert.deepEqual(got.assets, JSON.parse(JSON.stringify(N.collection('assets').all())), 'assets read by Python');
  assert.deepEqual(got.roles, JSON.parse(JSON.stringify(N.collection('roles').all())));
  assert.deepEqual(got.verify, N.verifyAudit(), 'Python verifies the Node.js chain');
  assert.deepEqual(got.tail, JSON.parse(JSON.stringify(N.auditTail(3))), 'the audit tail');
  N.close(); P.close();
});

test('store: tampering is reported at the same line by both', { skip: !hasPy && 'python3 not available' }, () => {
  const d = tmp(); const N = nodeApply(d, ops()); N.close();
  const f = path.join(d, 'audit-202610.jsonl'), lines = fs.readFileSync(f, 'utf8').split('\n');
  for (const [what, edit] of [['edited', (l) => { l[2] = l[2].replace('"syed"', '"eve"'); }], ['deleted', (l) => { l.splice(1, 1); }], ['garbage', (l) => { l[3] = '{not json'; }]]) {
    const l = lines.slice(); edit(l); fs.writeFileSync(f, l.join('\n'));
    const n = createStore({ dir: d }).verifyAudit();
    assert.equal(n.ok, false, what);
    assert.deepEqual(py(`from store import Store; import json\nprint(json.dumps(Store(${JSON.stringify(d)}, readonly=True).verify_audit()))`), n, what + ': the same answer');
  }
  fs.writeFileSync(f, lines.join('\n'));
});

test('store: read-only next to a live writer - refuses writes, skips a half-written line, loses nothing during compaction', { skip: !hasPy && 'python3 not available' }, async () => {
  const d = tmp(); const N = createStore({ dir: d });
  N.collection('items').put({ id: 'x0', n: 0 }); N.audit({ at: '2026-10-19T08:00:00.000Z', by: 'syed', action: 'a' });
  const ro = py(`from store import Store, ReadOnly; import json\ns = Store(${JSON.stringify(d)}, readonly=True)\nout = []\nfor f in (lambda: s.collection("items").put({"id": "y"}), lambda: s.audit({"action": "x"})):\n    try:\n        f(); out.append("wrote")\n    except ReadOnly:\n        out.append("refused")\nprint(json.dumps(out))`);
  assert.deepEqual(ro, ['refused', 'refused']);
  // the writer is half-way through a line
  fs.appendFileSync(path.join(d, 'items.jsonl'), '{"op":"put","o":{"id":"x1","n":');
  fs.appendFileSync(path.join(d, 'audit-202610.jsonl'), '{"seq":2,"at":"2026-10-19T08:00:01');
  const half = py(`from store import Store; import json\ns = Store(${JSON.stringify(d)}, readonly=True)\nc = s.collection("items")\nprint(json.dumps({"ids": sorted(c.items), "bad": c.bad, "verify": s.verify_audit()}))`);
  assert.deepEqual(half.ids, ['x0']); assert.equal(half.bad, 0, 'not counted as damage'); assert.equal(half.verify.ok, true); assert.equal(half.verify.checked, 1);
  N.close();
  // compaction while Python reads: every read must hold x0..xk with no gap (a lost journal entry would leave one)
  const d2 = tmp(); const W = createStore({ dir: d2 }); const col = W.collection('items'); col.put({ id: 0 });
  const reader = spawn(PY, ['-I', '-c', `import sys, json, time; sys.path.insert(0, ${JSON.stringify(PYENGINE)})\nfrom store import Store\nres = []\nt = time.time()\nwhile time.time() - t < 2.5:\n    ids = sorted(Store(${JSON.stringify(d2)}, readonly=True).collection("items").items)\n    res.append([len(ids), ids == list(range(len(ids)))])\nprint(json.dumps(res))`]);
  let out = "", errs = ""; reader.stdout.on("data", (b) => { out += b; }); reader.stderr.on("data", (b) => { errs += b; });
  const done = new Promise((r) => reader.on('close', r));
  let i = 1, snaps = 0, lastSnap = Date.now(); const until = Date.now() + 2300;   // a compaction every ~50 ms (the server: every 5000 writes or 6 h)
  while (Date.now() < until) { for (let k = 0; k < 20; k++) col.put({ id: i++, pad: 'x'.repeat(200) }); if (Date.now() - lastSnap > 50) { W.snapshot(); snaps++; lastSnap = Date.now(); } await new Promise((r) => setTimeout(r, 4)); }
  await done; W.close();
  assert.ok(out, "reader failed: " + errs.slice(-800));
  const reads = JSON.parse(out);
  assert.ok(reads.length > 5, 'reads: ' + reads.length);
  assert.ok(reads.every((x) => x[1]), 'every read is a complete prefix: ' + JSON.stringify(reads.filter((x) => !x[1]).slice(0, 3)));
  for (let k = 1; k < reads.length; k++) assert.ok(reads[k][0] >= reads[k - 1][0], 'never goes back');
  assert.ok(reads[reads.length - 1][0] > 100, 'it saw the writer progress');
  assert.ok(snaps > 10, 'compactions during the reads: ' + snaps);
});
