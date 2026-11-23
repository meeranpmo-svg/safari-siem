// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The audit hash-chain check on a worker thread (engine/audit-verify.js): the same answer as store.verifyAudit() -
// intact, edited, deleted line, garbage - while the engine's own thread keeps running (it used to stop for the whole
// read), and a line the engine is still writing is neither read nor reported as damage.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../engine/store');
const { verifyInWorker } = require('../engine/audit-verify');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-auditw-'));

test('audit check on a worker thread: same answers, the engine keeps running', async () => {
  const dir = tmp(); const s = createStore({ dir });
  for (let i = 0; i < 30000; i++) s.audit({ at: new Date(Date.UTC(2026, 8, 1) + i * 60000).toISOString(), by: 'syed', action: 'asset.edit', target: 'ast_' + i, detail: { i, t: 'é 中 😀', n: i % 7 ? null : { 10: 'x', b: [1.5, -0, 1e21] } } });
  const want = s.verifyAudit();
  assert.equal(want.ok, true); assert.equal(want.checked, 30000);
  // the engine thread keeps ticking while the worker reads
  let ticks = 0; const iv = setInterval(() => { ticks++; }, 5);
  const t0 = Date.now(); const got = await verifyInWorker(dir); const ms = Date.now() - t0;
  clearInterval(iv);
  assert.deepEqual(got, want, 'intact chain: the same answer');
  assert.ok(ticks >= Math.floor(ms / 5) * 0.5, `the engine thread ran ${ticks} timers in ${ms} ms`);
  // a line still being written (no newline yet) is not damage
  const files = fs.readdirSync(dir).filter((f) => /^audit-/.test(f)).sort(), last = path.join(dir, files[files.length - 1]);
  fs.appendFileSync(last, '{"seq":30001,"at":"2026-10');
  const half = await verifyInWorker(dir);
  assert.equal(half.ok, true); assert.equal(half.checked, 30000);
  // tampering: the same line and reason as the engine's own check
  const first = path.join(dir, files[0]), L = fs.readFileSync(first, 'utf8').split('\n');
  for (const [what, edit] of [['edited', (l) => { l[5] = l[5].replace('"syed"', '"eve"'); }], ['deleted', (l) => { l.splice(2, 1); }], ['garbage', (l) => { l[7] = '{not json'; }]]) {
    const l = L.slice(); edit(l); fs.writeFileSync(first, l.join('\n'));
    assert.deepEqual(await verifyInWorker(dir), s.verifyAudit(), what);
  }
  fs.writeFileSync(first, L.join('\n'));
  s.close();
});
