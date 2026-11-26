// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// deploy/install-fresh-server.sh: while another installer (Ubuntu's automatic updates) holds the dpkg lock, "dpkg --configure -a"
// is retried instead of stopping the install at once; any other dpkg error still stops; the lock file is never removed; apt waits
// for the lock too. A stand-in dpkg on PATH (no root, nothing installed); sleep is a no-op.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), { spawnSync } = require('child_process');
const F = path.resolve(__dirname, '../../../deploy/install-fresh-server.sh'), S = fs.readFileSync(F, 'utf8');
const fn = S.slice(S.indexOf('dpkg_configure() {'), S.indexOf('\n}\n', S.indexOf('dpkg_configure() {')) + 3);

function run(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpkg-'));
  fs.writeFileSync(path.join(dir, 'dpkg'), '#!/bin/bash\n' + script, { mode: 0o755 });
  const r = spawnSync('bash', ['-c', 'warn() { echo "!! $*" >&2; }; sleep() { :; }; export N=' + dir + '/n; ' + fn + '\ndpkg_configure; echo "rc=$?"'], { encoding: 'utf8', env: Object.assign({}, process.env, { PATH: dir + ':' + process.env.PATH }) });
  fs.rmSync(dir, { recursive: true, force: true });
  return r;
}

test('the dpkg lock held by another installer is waited for, then the step runs', () => {
  const r = run('c=$(cat "$N" 2>/dev/null || echo 0); echo $((c+1)) > "$N"; if [ "$c" -lt 2 ]; then echo "dpkg: error: dpkg frontend lock was locked by /usr/bin/python3.14 process with pid 303129" >&2; exit 2; fi; echo configured; exit 0');
  assert.match(r.stdout, /configured/); assert.match(r.stdout, /rc=0/);
  assert.match(r.stderr, /another package installer is running/); assert.match(r.stderr, /locked by \/usr\/bin\/python3\.14 process with pid 303129/);
});

test('another dpkg error still stops at once', () => {
  const r = run('echo "dpkg: error processing package foo (--configure): broken" >&2; exit 1');
  assert.match(r.stdout, /rc=1/); assert.match(r.stderr, /error processing package foo/); assert.doesNotMatch(r.stderr, /waiting/);
});

test('the lock is never removed; apt waits for it as well', () => {
  assert.doesNotMatch(S, /rm[^\n]*\/var\/lib\/dpkg\/lock/); assert.doesNotMatch(S, /rm[^\n]*lock-frontend/);
  assert.match(S, /DPkg::Lock::Timeout=1200/);
  assert.match(S, /dpkg --audit[^\n]*dpkg_configure \|\| die/);
});

// the installer WAITS for another package operation (it printed "waiting" and then failed at once on a real server): a fake ps
// shows a dpkg for two checks, then nothing - the step continues; a dpkg stuck in state D for the whole 20 minutes is named as the
// VM's storage stalling, and the step stops (never removing the lock)
const fnW = S.slice(S.indexOf('pkg_busy() {'), S.indexOf('\n}\n', S.indexOf('wait_pkg_idle() {')) + 3);
function runW(psScript) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-'));
  fs.writeFileSync(path.join(dir, 'ps'), '#!/bin/bash\n' + psScript, { mode: 0o755 });
  const r = spawnSync('bash', ['-c', 'warn() { echo "!! $*" >&2; }; sleep() { :; }; export N=' + dir + '/n; ' + fnW + '\nwait_pkg_idle; echo "rc=$?"'], { encoding: 'utf8', env: Object.assign({}, process.env, { PATH: dir + ':' + process.env.PATH }) });
  fs.rmSync(dir, { recursive: true, force: true });
  return r;
}
test('another package operation is waited for, then the install continues', () => {
  const r = runW('c=$(cat "$N" 2>/dev/null || echo 0); echo $((c+1)) > "$N"; [ "$c" -lt 2 ] && echo " 8652 Ds+ 06:28 /usr/bin/dpkg --status-fd 40 --no-triggers --unpack --auto-deconfigure"; exit 0');
  assert.match(r.stdout, /rc=0/); assert.match(r.stderr, /waiting for it to finish/); assert.match(r.stderr, /8652/);
});
test('a package process stuck on the disk for 20 minutes is named, and the step stops', () => {
  const r = runW('echo " 8652 Ds+ 26:28 /usr/bin/dpkg --status-fd 40 --unpack"; exit 0');
  assert.match(r.stdout, /rc=1/); assert.match(r.stderr, /stuck waiting on the disk \(state D\)/); assert.match(r.stderr, /Hyper-V host/);
  assert.match(S, /wait_pkg_idle \|\| die "another package operation is still running after 20 minutes/);
});

