// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A fresh server runs install.sh only - no add-on installer - so every module an install/add-*.sh used to register must already
// be registered in engine/main.js. Without that, Platform Map, Staff Handover, the Audit / PDPL automation flows, Business
// Services and the rest answered 404 ("not installed - run the update") on a new server.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.join(__dirname, '..');

test('every add-on registration line is in main.js, once, and its module exists', () => {
  const main = fs.readFileSync(path.join(ROOT, 'engine/main.js'), 'utf8');
  const lines = fs.readdirSync(path.join(ROOT, 'install')).filter((f) => /^add-.*\.sh$/.test(f)).map((f) => {
    const m = fs.readFileSync(path.join(ROOT, 'install', f), 'utf8').match(/^LINE="\s*require\('\.\/([a-z0-9-]+)'\)\.(register[A-Za-z]+)\(srv, app\);/m);
    return m && { file: f, mod: m[1], fn: m[2] };
  }).filter(Boolean);
  assert.ok(lines.length >= 30, 'the add-on installers were found: ' + lines.length);
  const missing = lines.filter((l) => !main.includes(`require('./${l.mod}').${l.fn}(srv, app);`));
  assert.match(main, /createApp\(\{ config: cfg\.config, secrets: cfg\.secrets, log, addons: true \}\)/, 'the service turns the add-ons on');
  assert.deepEqual(missing.map((l) => l.file), [], 'registered in main.js');
  for (const l of lines) {
    assert.equal(main.split(`.${l.fn}(srv, app);`).length - 1, 1, l.fn + ' registered once');
    assert.equal(typeof require(path.join(ROOT, 'engine', l.mod))[l.fn], 'function', l.mod + ' exports ' + l.fn);
  }
});

test('a fresh engine serves the add-on pages (Platform Map, handover, automation flows, duty desk)', async () => {
  const { createApp } = require('../engine/main');
  const os = require('node:os'), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'itam-fresh-'));
  const log = { info() {}, warn() {}, error() {}, debug() {}, every() {} };
  const app = createApp({ config: { api: { host: '127.0.0.1', port: 0 }, data_dir: dir }, secrets: { proxy_secret: 'syn-proxy-secret-0123456789' }, log, noTimer: true, addons: true });
  await app.start();
  try {
    const port = app.port || (app.server && app.server.address && app.server.address().port) || (app.srv && app.srv.address && app.srv.address().port);
    assert.ok(port, 'listening');
    const H = { 'x-sentra-proxy-secret': 'syn-proxy-secret-0123456789', 'x-auth-user': 'admin.syn', 'x-auth-role': 'admin' };
    for (const p of ['/platform-map', '/handover', '/audit-flow', '/pdpl-flow', '/duty/kpis', '/service-map', '/infra-overview', '/ownership', '/budget', '/nca-ecc-intel', '/impl/nca', '/impl/pdpl', '/impl/iso', '/impl/ndmo', '/iso-lifecycle']) {
      const r = await fetch(`http://127.0.0.1:${port}/api/itam${p}`, { headers: H });
      assert.notEqual(r.status, 404, p + ' is served');
    }
  } finally { await app.stop(); }
});

test('install.sh copies the Python rules (pyengine) - without them ISO 27001, NCA ECC, PDPL and the rest say "Python did not answer"', () => {
  const sh = fs.readFileSync(path.join(ROOT, 'install/install.sh'), 'utf8');
  assert.match(sh, /find "\$SRC_ROOT\/pyengine" -maxdepth 1 -type f -name '\*\.py' -exec install -m 644 \{\} "\$APP\/pyengine\/"/, 'every pyengine/*.py is installed');
  assert.match(sh, /rm -rf -- "\$\{APP:\?\}\/pyengine"/, 'the old copy is replaced, never with an empty APP');
  assert.ok(fs.readdirSync(path.join(ROOT, 'pyengine')).includes('run.py'), 'the entry point the engine runs is there');
  assert.ok(fs.readFileSync(path.join(ROOT, 'engine/pyengine.js'), 'utf8').includes("path.join(__dirname, '..', 'pyengine', 'run.py')"), 'the engine looks for it beside engine/');
});

test('the Python launcher uses the system python3 when the SIEM venv is not there, and says why the rules did not answer', () => {
  const PE = require('../engine/pyengine');
  assert.equal(PE.pick('/opt/sentra-siem/pyenv/bin/python3'), fs.existsSync('/opt/sentra-siem/pyenv/bin/python3') ? '/opt/sentra-siem/pyenv/bin/python3' : 'python3', 'the default venv falls back to the system python3 when it is not there');
  assert.equal(PE.pick('/nonexistent/python3'), '/nonexistent/python3', 'a configured Python is used as given');
  assert.equal(PE.pick('python3.12'), 'python3.12', 'a name on PATH is kept');
  assert.equal(PE.pick(undefined), fs.existsSync('/opt/sentra-siem/pyenv/bin/python3') ? '/opt/sentra-siem/pyenv/bin/python3' : 'python3');
  assert.match(PE.why({ ok: false, error_class: 'missing_python', error: 'Python not found (python3)' }), /Python not found .* apt-get install -y python3/);
  assert.match(PE.why({ ok: false, error_class: 'protocol', error: 'the Python module failed (exit 1): ValueError: x' }), /\(the Python module failed \(exit 1\): ValueError: x\)/);
  assert.match(PE.why(null), /run the update/);
});
