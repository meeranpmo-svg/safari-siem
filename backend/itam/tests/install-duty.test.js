// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// install/add-duty.sh installs every module engine/duty.js loads with optional('./x'). Bug fixed: CMDB Studio, Scope Studio,
// the Compliance Assistant, the AI SQL DBA and the database inventory were in duty.js but not on the installer's fixed list,
// so they were never copied to the server, optional() skipped them and their pages said "not installed" after every update.
// The test runs the installer's own discovery line against duty.js and checks each module it names exists in the package.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..'), SH = fs.readFileSync(path.join(ROOT, 'install/add-duty.sh'), 'utf8');

test('add-duty.sh installs every optional() module of duty.js, read from duty.js itself', () => {
  const line = SH.split('\n').filter((l) => l.startsWith('OPT=')).join('\n');
  assert.ok(line, 'the installer derives the module list from duty.js');
  const out = execFileSync('bash', ['-c', line + '\necho "$OPT"'], { env: { SRC: path.join(ROOT, 'engine/duty.js'), PATH: process.env.PATH } }).toString().trim().split(/\s+/);
  const src = fs.readFileSync(path.join(ROOT, 'engine/duty.js'), 'utf8');
  const want = [...new Set([...src.matchAll(/optional\('\.\/([a-z0-9-]+)'\)/g)].map((m) => m[1]).concat(require('../engine/duty').INTEL_MODULES.map((x) => x[0].slice(2))))].sort();
  assert.deepEqual([...new Set(out)].sort(), want, 'every optional() module, including two on one line, and every INTEL_MODULES entry');
  for (const m of ['maturity-intel', 'fwlib-intel', 'netcfg-intel']) assert.ok(out.includes(m), m + ' (an intel-kit page) is installed');
  for (const m of ['cmdb-studio', 'discovery-advisor', 'compliance-assist', 'sqldba', 'db-inventory']) assert.ok(out.includes(m), m + ' is installed');
  for (const m of want) assert.ok(fs.existsSync(path.join(ROOT, 'engine', m + '.js')), m + '.js exists in the package');
  assert.match(SH, /for m in \$OPT; do[\s\S]*?engine-all\/\$m\.js[\s\S]*?install -m 644/, 'falls back to engine-all (the package stages every engine file there)');
});

// Bug fixed: the fixed list (intel-kit, *-intel ...) was copied only from the package's engine/, which holds hand-picked files; the intel
// modules were only in engine-all/, so they were never installed and their pages said "This platform does not have this page yet".
test('the fixed module list falls back to engine-all, where the package stages every engine file', () => {
  const os = require('node:os'), D = fs.mkdtempSync(path.join(os.tmpdir(), 'duty-')), pkg = path.join(D, 'pkg');
  for (const d of ['engine', 'engine-all', 'install']) fs.mkdirSync(path.join(pkg, d), { recursive: true });
  fs.mkdirSync(path.join(D, 'app', 'engine'), { recursive: true }); fs.mkdirSync(path.join(D, 'bk'));
  for (const m of ['intel-kit', 'netcfg-intel', 'maturity-intel']) fs.writeFileSync(path.join(pkg, 'engine-all', m + '.js'), '// ' + m);
  const lines = SH.split('\n'), i = lines.findIndex((l) => l.startsWith('for m in virt-net-read auditors')), j = lines.indexOf('done', i);
  const loop = lines.slice(i, j + 1).join('\n').replace(/install -m 644 -o root -g root/g, 'cp');
  execFileSync('bash', ['-c', loop + '\ntrue'], { env: { HERE: path.join(pkg, 'install'), APP: path.join(D, 'app'), BK: path.join(D, 'bk'), PATH: process.env.PATH } });
  for (const m of ['intel-kit', 'netcfg-intel', 'maturity-intel']) assert.ok(fs.existsSync(path.join(D, 'app', 'engine', m + '.js')), m + '.js installed from engine-all');
  fs.rmSync(D, { recursive: true, force: true });
});

// Bug fixed: xlsx-read.js was require()d by audit-analytics.js and audit-repo.js but on no list, so it was never copied to the
// server, both modules failed to load and the update reported "itam-duty". The installer now follows every installed module's
// require('./x') until nothing new is needed; the test runs that loop on a temporary install.
test('every engine file an installed module requires is installed too, and a missing one is named', () => {
  const os = require('node:os'), D = fs.mkdtempSync(path.join(os.tmpdir(), 'duty-dep-')), pkg = path.join(D, 'pkg');
  for (const d of ['engine', 'engine-all', 'install']) fs.mkdirSync(path.join(pkg, d), { recursive: true });
  fs.mkdirSync(path.join(D, 'app', 'engine'), { recursive: true }); fs.mkdirSync(path.join(D, 'bk'));
  fs.writeFileSync(path.join(D, 'app', 'engine', 'audit-repo.js'), "const { readXlsx } = require('./xlsx-read'); const x = require('./not-in-package'); require('./discovery');");
  fs.mkdirSync(path.join(D, 'app', 'engine', 'discovery')); fs.writeFileSync(path.join(D, 'app', 'engine', 'discovery', 'index.js'), '// a directory module');
  fs.writeFileSync(path.join(pkg, 'engine', 'xlsx-read.js'), "require('./zip-helper');");
  fs.writeFileSync(path.join(pkg, 'engine-all', 'zip-helper.js'), '// helper');
  const lines = SH.split('\n'), i = lines.findIndex((l) => l.startsWith('for pass in')), j = lines.indexOf('done', lines.indexOf('  [ "$NEW" = 1 ] || break', i));
  assert.ok(i > 0 && j > i, 'the installer follows require() dependencies');
  const loop = lines.slice(i, j + 1).join('\n').replace(/install -m 644 -o root -g root/g, 'cp');
  const out = execFileSync('bash', ['-c', 'restore() { echo "RESTORE $1"; exit 1; }\n' + loop], { env: { HERE: path.join(pkg, 'install'), APP: path.join(D, 'app'), BK: path.join(D, 'bk'), NODE: process.execPath, PATH: process.env.PATH } }).toString();
  assert.ok(fs.existsSync(path.join(D, 'app', 'engine', 'xlsx-read.js')), 'xlsx-read.js installed');
  assert.ok(fs.existsSync(path.join(D, 'app', 'engine', 'zip-helper.js')), 'a dependency of a dependency is installed (from engine-all)');
  assert.match(out, /needs not-in-package\.js, which this package does not have/); assert.doesNotMatch(out, /RESTORE/); assert.doesNotMatch(out, /needs discovery/, 'a directory module is not reported missing');
  fs.rmSync(D, { recursive: true, force: true });
});

test('every require(\'./x\') in the engine resolves to a file the package ships', () => {
  const E = path.join(ROOT, 'engine'), miss = [];
  for (const f of fs.readdirSync(E).filter((x) => x.endsWith('.js'))) for (const m of fs.readFileSync(path.join(E, f), 'utf8').matchAll(/require\('\.\/([a-z0-9-]+)'\)/g)) if (!fs.existsSync(path.join(E, m[1] + '.js')) && !fs.existsSync(path.join(E, m[1], 'index.js'))) miss.push(f + ' -> ' + m[1]);
  assert.deepEqual(miss, []);
});

// Bug fixed: a dependency already on the server was never updated. Business Risk was installed with its new importer but kept the
// old xlsx-read.js (no sheet / header-row choice), so importing the department's risk register said 'xlsx: the sheet has no "Risk
// Code" column'. A dependency that differs from the package is now replaced, this run's copy kept, and put back on a failure.
test('a dependency already on the server is updated when the package carries a different copy, and restored on a failure', () => {
  const os = require('node:os'), D = fs.mkdtempSync(path.join(os.tmpdir(), 'duty-upd-')), pkg = path.join(D, 'pkg'), app = path.join(D, 'app', 'engine');
  for (const d of ['engine', 'engine-all', 'install']) fs.mkdirSync(path.join(pkg, d), { recursive: true });
  fs.mkdirSync(app, { recursive: true }); fs.mkdirSync(path.join(D, 'bk'));
  fs.writeFileSync(path.join(app, 'business-risk.js'), "require('./xlsx-read'); require('./check');");
  fs.writeFileSync(path.join(app, 'xlsx-read.js'), '// old reader: first sheet, first row');
  fs.writeFileSync(path.join(app, 'check.js'), '// same');
  fs.writeFileSync(path.join(pkg, 'engine-all', 'xlsx-read.js'), "// new reader: o.sheet, o.header\nrequire('./zip-helper');");
  fs.writeFileSync(path.join(pkg, 'engine-all', 'zip-helper.js'), '// helper');
  fs.writeFileSync(path.join(pkg, 'engine-all', 'check.js'), '// same');
  const t0 = fs.statSync(path.join(app, 'check.js')).mtimeMs;
  const lines = SH.split('\n'), i = lines.findIndex((l) => l.startsWith('DEPS_UPDATED=')), j = lines.indexOf('done', lines.indexOf('  [ "$NEW" = 1 ] || break', i));
  const loop = lines.slice(i, j + 1).join('\n').replace(/install -m 644 -o root -g root/g, 'cp');
  const back = /for d in \$\{DEPS_UPDATED:-\}; do [^;]*; done/.exec(SH);
  assert.ok(back, 'restore() puts back the dependencies this run replaced');
  const env = { HERE: path.join(pkg, 'install'), APP: path.join(D, 'app'), BK: path.join(D, 'bk'), NODE: process.execPath, PATH: process.env.PATH };
  const out = execFileSync('bash', ['-c', 'restore() { echo "RESTORE $1"; exit 1; }\n' + loop + '\necho "UPDATED:$DEPS_UPDATED"'], { env }).toString();
  assert.match(fs.readFileSync(path.join(app, 'xlsx-read.js'), 'utf8'), /new reader/, 'the old xlsx-read.js is replaced');
  assert.ok(fs.existsSync(path.join(app, 'zip-helper.js')), 'and what the new copy requires is installed');
  assert.match(fs.readFileSync(path.join(D, 'bk', 'run-xlsx-read.js'), 'utf8'), /old reader/, 'this run\'s copy is kept');
  assert.match(out, /~ xlsx-read\.js updated \(needed by business-risk\.js\)/); assert.match(out, /UPDATED: xlsx-read$/m, 'only the file that differed');
  assert.equal(fs.statSync(path.join(app, 'check.js')).mtimeMs, t0, 'an identical dependency is left alone'); assert.doesNotMatch(out, /RESTORE/);
  // a failure later in the update puts the replaced dependency back
  execFileSync('bash', ['-c', 'DEPS_UPDATED=" xlsx-read"\n' + back[0]], { env });
  assert.match(fs.readFileSync(path.join(app, 'xlsx-read.js'), 'utf8'), /old reader/, 'restored');
  // a second run with nothing new changes nothing
  fs.copyFileSync(path.join(pkg, 'engine-all', 'xlsx-read.js'), path.join(app, 'xlsx-read.js'));
  const again = execFileSync('bash', ['-c', 'restore() { echo "RESTORE $1"; exit 1; }\n' + loop + '\necho "UPDATED:$DEPS_UPDATED"'], { env }).toString();
  assert.match(again, /UPDATED:$/m); assert.doesNotMatch(again, /updated \(needed/);
  fs.rmSync(D, { recursive: true, force: true });
});

// Bug fixed: the dependency update replaced patched core files too (main.js requires http.js, routes.js, findings.js,
// monitoring-membership.js), so the server's own copies - patched, owned by core_upgrade - were overwritten and the update reported
// itam-pages. Core files are now never replaced by it, and a core file an earlier run replaced is put back from that run's copy.
test('core files are never replaced by the dependency update, and one an earlier run replaced is put back', () => {
  const os = require('node:os'), D = fs.mkdtempSync(path.join(os.tmpdir(), 'duty-core-')), pkg = path.join(D, 'pkg'), app = path.join(D, 'app', 'engine'), bk = path.join(D, 'bk');
  for (const d of ['engine', 'engine-all', 'install/patches']) fs.mkdirSync(path.join(pkg, d), { recursive: true });
  fs.mkdirSync(app, { recursive: true }); fs.mkdirSync(bk);
  fs.writeFileSync(path.join(pkg, 'install', 'patches', 'http-roles.patch'), '--- a/engine/http.js\n+++ b/engine/http.js\t2026-10-19\n@@ -1 +1 @@\n');
  fs.writeFileSync(path.join(pkg, 'install', 'core-known.txt'), '# synthetic\n' + 'a'.repeat(64) + '  engine/routes.js\n');
  fs.writeFileSync(path.join(app, 'main.js'), "require('./http'); require('./routes'); require('./xlsx-read'); // + the server's add-on lines");
  fs.writeFileSync(path.join(app, 'http.js'), '// the server\'s patched http.js');
  fs.writeFileSync(path.join(app, 'routes.js'), '// package routes.js');   // what the earlier, faulty run left
  fs.writeFileSync(path.join(bk, 'run-routes.js'), '// the server\'s own routes.js');
  fs.writeFileSync(path.join(app, 'xlsx-read.js'), '// old reader');
  for (const [f, t] of [['http.js', '// package http.js'], ['routes.js', '// package routes.js'], ['xlsx-read.js', '// new reader'], ['main.js', '// package main.js']]) fs.writeFileSync(path.join(pkg, 'engine-all', f), t);
  const lines = SH.split('\n'), i = lines.findIndex((l) => l.startsWith('DEPS_UPDATED=')), j = lines.indexOf('done', lines.indexOf('  [ "$NEW" = 1 ] || break', i));
  const loop = lines.slice(i, j + 1).join('\n').replace(/install -m 644 -o root -g root/g, 'cp');
  const out = execFileSync('bash', ['-c', 'restore() { echo "RESTORE $1"; exit 1; }\n' + loop + '\necho "UPDATED:$DEPS_UPDATED PROTECT:$PROTECT"'], { env: { HERE: path.join(pkg, 'install'), APP: path.join(D, 'app'), BK: bk, NODE: process.execPath, PATH: process.env.PATH } }).toString();
  assert.match(fs.readFileSync(path.join(app, 'http.js'), 'utf8'), /server's patched/, 'a patched core file is left alone');
  assert.match(fs.readFileSync(path.join(app, 'main.js'), 'utf8'), /add-on lines/, 'main.js is left alone');
  assert.match(fs.readFileSync(path.join(app, 'routes.js'), 'utf8'), /server's own routes/, 'a core file an earlier run replaced is put back');
  assert.ok(!fs.existsSync(path.join(bk, 'run-routes.js')) && fs.existsSync(path.join(bk, 'run-routes.js.restored')), 'the run copy is used once');
  assert.match(fs.readFileSync(path.join(app, 'xlsx-read.js'), 'utf8'), /new reader/, 'an ordinary dependency is still updated');
  assert.match(out, /UPDATED: xlsx-read PROTECT:/); assert.match(out, /PROTECT: main .*http.*routes/); assert.match(out, /routes\.js: the server's own copy is put back/); assert.doesNotMatch(out, /RESTORE/);
  fs.rmSync(D, { recursive: true, force: true });
});
