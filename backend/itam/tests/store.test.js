// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createStore } = require('../engine/store');
const { tmpDir } = require('./helpers');

test('collection: put/patch/get/all persist across reopen', () => {
  const dir = tmpDir();
  let s = createStore({ dir });
  const c = s.collection('things');
  c.put({ id: '1', v: 1 }); c.put({ id: '2', v: 2 });
  c.patch('1', (o) => { o.v = 10; });
  s.close();
  s = createStore({ dir });
  const c2 = s.collection('things');
  assert.equal(c2.get('1').v, 10);
  assert.equal(c2.all().length, 2);
  s.close();
});

test('audit: hash chain verifies, and tampering is detected', () => {
  const dir = tmpDir();
  let s = createStore({ dir });
  for (let i = 0; i < 5; i++) s.audit({ by: 'u', action: 'test', target: `t${i}`, detail: { i } });
  assert.equal(s.verifyAudit().ok, true);
  assert.equal(s.verifyAudit().checked, 5);
  s.close();
  // tamper: edit a line in the audit journal
  const f = fs.readdirSync(dir).find((x) => /^audit-\d{6}\.jsonl$/.test(x));
  const p = path.join(dir, f);
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
  const rec = JSON.parse(lines[2]); rec.detail = { i: 999 };
  lines[2] = JSON.stringify(rec);
  fs.writeFileSync(p, lines.join('\n') + '\n');
  s = createStore({ dir });
  const v = s.verifyAudit();
  assert.equal(v.ok, false);
  assert.match(v.reason, /hash chain/);
  s.close();
});
