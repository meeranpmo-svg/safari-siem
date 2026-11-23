// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* The vendored third-party bundles (install/vendor): checksums match, the Python wheel bundle never ships a version below the
 * patched minimums in python-constraints.txt (each closes a published advisory), and the installer applies the constraints on
 * every install path. tools/build-python-wheels.sh checks the bundle against PyPI's advisories when it is rebuilt. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const V = path.join(__dirname, '..', 'install', 'vendor');
const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };
const norm = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

test('vendored bundles match their recorded SHA-256', () => {
  for (const f of fs.readdirSync(V).filter((x) => x.endsWith('.sha256'))) {
    const [want, name] = fs.readFileSync(path.join(V, f), 'utf8').trim().split(/\s+/);
    const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(V, name))).digest('hex');
    assert.equal(got, want, name);
  }
});

test('python wheel bundle: every wheel meets the patched minimum, the constraints ship inside it', () => {
  const mins = {};
  for (const line of fs.readFileSync(path.join(V, 'python-constraints.txt'), 'utf8').split('\n')) {
    const m = /^([A-Za-z0-9_.-]+)\s*>=\s*([0-9.]+)/.exec(line.replace(/#.*/, '').trim());
    if (m) mins[norm(m[1])] = m[2];
  }
  for (const p of ['cryptography', 'urllib3', 'requests', 'certifi', 'pynacl', 'pg8000', 'paramiko']) assert.ok(mins[p], 'minimum declared for ' + p);
  const list = fs.readFileSync(path.join(V, 'python-wheels-linux-x86_64.txt'), 'utf8').split('\n').filter(Boolean);
  assert.ok(list.includes('constraints.txt'), 'constraints.txt is inside the bundle (the offline install uses it)');
  let checked = 0;
  for (const w of list.filter((x) => x.endsWith('.whl'))) {
    const [name, ver] = w.split('-'); const min = mins[norm(name)];
    if (!min) continue;
    assert.ok(cmp(ver.replace(/[^0-9.].*$/, ''), min) >= 0, `${w} is below the patched minimum ${min}`);
    checked++;
  }
  assert.ok(checked >= 7, 'the constrained packages are in the bundle');
  assert.ok(!list.some((x) => /-cp3(8|9)-cp3/.test(x)), 'no wheels built only for Python 3.8 / 3.9 (they cannot get the fixed releases; abi3 wheels serve 3.10+)');
});

test('installer applies the constraints on the bundled, offline and PyPI paths and upgrades an older venv', () => {
  const s = fs.readFileSync(path.join(__dirname, '..', 'install', 'netops-cli-setup.sh'), 'utf8');
  assert.match(s, /--upgrade --upgrade-strategy eager/);
  assert.ok((s.match(/-c "\$CONS"/g) || []).length >= 4, 'offline and PyPI installs use python-constraints.txt');
  assert.match(s, /-c "\$BTMP\/constraints.txt"/);
  assert.match(s, /\[ "\$v" -ge 310 \]/, 'Python 3.10 or newer');
});
