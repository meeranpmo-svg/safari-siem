// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The update's final page check (scripts/update-server.sh) after a restart of sentra-itam. Bug fixed: update-server.sh restarted
// sentra-itam (newer engine files, supplied dependencies) and waited only for "systemctl is-active", which is true the moment the
// process starts, long before it listens; the final check then asked its FIRST page, /mail-route, got "connection refused"
// twice in milliseconds (itam_code prints 0 for that too) and reported "/mail-route (HTTP 0, no answer in 30 s)" after every
// such update - whatever /mail-route did. Now every restart there waits for the port, the check waits for it before it starts,
// an instant 0 waits for the port and asks again, and a refused connection is named as such.
const test = require('node:test'), assert = require('node:assert'), fs = require('fs'), path = require('path'), net = require('net'), { spawnSync } = require('child_process');
const ROOT = path.join(__dirname, '..'), US = fs.readFileSync(path.join(ROOT, '../../deploy/server/update-server.sh'), 'utf8');

test('every restart of sentra-itam in update-server.sh waits until it listens', () => {
  const lines = US.split('\n'), bad = [];
  lines.forEach((l, i) => { if (/systemctl restart sentra-itam/.test(l) && !/itam_listen|itam_up/.test(l + '\n' + (lines[i + 1] || ''))) bad.push(i + 1 + ': ' + l.trim()); });
  assert.deepStrictEqual(bad, [], 'a restart not followed by a wait for the port');
  assert.ok(!/seq 1 45\); do systemctl is-active --quiet sentra-itam && break/.test(US), 'the wait for "is-active" alone is gone');
  assert.match(US, /itam_listen\(\) \{[^\n]*lib-itam\.sh"; itam_up/, 'itam_listen uses lib-itam.sh itam_up');
});

test('the final check waits for the port, asks a refused page again and names a refused connection', () => {
  const i = US.indexOf('BAD=""; for p in /mail-route'), pre = US.slice(US.lastIndexOf('lib-itam.sh"', i), i), loop = US.slice(i, US.indexOf('done', US.indexOf('BAD="$BAD', i)));
  assert.match(pre, /itam_up 90/, 'waits for the port before the first page');
  assert.match(loop, /SECONDS - t0\)\) -lt 5 \]; then itam_up 90; c="\$\(itam_code "\$p" 30000\)"/, 'an instant 0 waits for the port and asks again');
  assert.match(loop, /connection refused - sentra-itam is not listening/, 'a refused connection is named');
  assert.match(loop, /no answer in 30 s/, 'a page that is really slow is still named as slow');
  const r = spawnSync('bash', ['-n', path.join(ROOT, '../../deploy/server/update-server.sh')]); assert.strictEqual(r.status, 0, String(r.stderr));
});

test('itam_code answers 0 at once for a refused connection - why "no answer in 30 s" could be printed in milliseconds', async () => {
  const s = net.createServer(); await new Promise((r) => s.listen(0, '127.0.0.1', r)); const port = s.address().port; await new Promise((r) => s.close(r));   // a port nothing listens on
  const lib = path.join(ROOT, 'install', 'lib-itam.sh');
  const body = fs.readFileSync(lib, 'utf8').match(/itam_code\(\) \{[\s\S]*?\n\}/)[0].replace('a.port||9150', String(port)).replace('a.host||"127.0.0.1"', '"127.0.0.1"');
  const t0 = Date.now(), r = spawnSync('bash', ['-c', body + '\nitam_code /mail-route 30000'], { env: Object.assign({}, process.env, { NODE: process.execPath }), encoding: 'utf8' });
  assert.strictEqual(r.stdout.trim(), '0'); assert.ok(Date.now() - t0 < 5000, 'refused is instant, not 30 s: ' + (Date.now() - t0) + ' ms');
});

test('itam_serves (the installers\' page check) waits for the port and asks again after a refused connection', () => {
  const L = fs.readFileSync(path.join(ROOT, 'install', 'lib-itam.sh'), 'utf8'), f = L.slice(L.indexOf('itam_serves() {'), L.indexOf('\n}', L.indexOf('itam_serves() {')));
  assert.match(f, /SECONDS - t0\)\) -lt 5 \]; then itam_up 90 >\/dev\/null; code="\$\(itam_code "\$1" 30000\)"/, 'an instant 0 waits for the port and asks again');
  assert.match(f, /connection refused/, 'a refused connection is named');
  const r = spawnSync('bash', ['-n', path.join(ROOT, 'install', 'lib-itam.sh')]); assert.strictEqual(r.status, 0, String(r.stderr));
});

test('the update summary repeats the "!!" lines of every failed IT Asset Management step, and a stop is recorded', () => {
  const fn = US.slice(US.indexOf('itam_step() {'), US.indexOf('\n', US.indexOf('itam_step() {')));
  assert.ok(US.indexOf('itam_step() {') < US.indexOf('itam_step itam-'), 'defined before the first step uses it');
  assert.ok(!/bash "\$HERE\/sentra-itam\/install\/[a-z0-9-]+\.sh"[^|;\n]*\|\| FAILED=/.test(US), 'every installer runs through itam_step');
  assert.match(US, /itam_step itam-duty "\$HERE\/sentra-itam\/install\/add-duty\.sh"/);
  // run the wrapper and the summary on a fake failing step
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'steps-')), step = path.join(dir, 'step.sh');
  fs.writeFileSync(step, 'echo "==> working"\necho "!! the engine is running, but these pages do not answer yet: /x"\necho "   /x: connection refused"\nexit 3\n');
  const sum = US.slice(US.indexOf('  for t in $FAILED; do'), US.indexOf('  echo "   the full messages are above'));
  const r = spawnSync('bash', ['-c', 'STEPLOG=' + dir + '; FAILED=""\n' + fn + '\nitam_step itam-duty ' + step + ' >/dev/null\necho "FAILED=$FAILED"\n' + sum], { encoding: 'utf8' });
  assert.match(r.stdout, /FAILED= itam-duty/); assert.match(r.stdout, /itam-duty said:\n\s+!! the engine is running, but these pages do not answer yet: \/x\n\s+\/x: connection refused/);
  const D = fs.readFileSync(path.join(ROOT, 'install', 'add-duty.sh'), 'utf8'); assert.match(D, /die\(\) \{[^\n]*itam_report duty failed/, 'add-duty records a stop');
  assert.match(fs.readFileSync(path.join(ROOT, 'install', 'update-doctor.js'), 'utf8'), /v\.reason \? ': ' \+ v\.reason/, 'the summary prints a roll-back reason');
});

test('a step that stopped without a "!!" line still shows why: the installer names the failing command, the summary its last lines', () => {
  const D = fs.readFileSync(path.join(ROOT, 'install', 'add-duty.sh'), 'utf8');
  assert.match(D, /set -E; trap 'die "add-duty stopped at line \$LINENO \(exit \$\?\): \$BASH_COMMAND"' ERR/, 'set -e no longer stops it silently');
  assert.ok(D.indexOf('trap \'die') > D.indexOf('die() {'), 'the trap is set after die() exists');
  // the trap itself: a script in the same shape stops at a failing command and says which
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'trap-')), sh = path.join(dir, 's.sh');
  fs.writeFileSync(sh, 'set -euo pipefail\ndie() { echo "!! $*"; exit 1; }\nset -E; trap \'die "add-duty stopped at line $LINENO (exit $?): $BASH_COMMAND"\' ERR\necho start\nfalse_cmd() { return 7; }\nfalse_cmd\necho never\n');
  const r = spawnSync('bash', [sh], { encoding: 'utf8' });
  assert.strictEqual(r.status, 1); assert.match(r.stdout, /!! add-duty stopped at line \d+ \(exit 7\): (false_cmd|return 7)/); assert.doesNotMatch(r.stdout, /never/);
  // the summary falls back to the last lines when there is no "!!" line
  const fn = US.slice(US.indexOf('itam_step() {'), US.indexOf('\n', US.indexOf('itam_step() {'))), sum = US.slice(US.indexOf('  for t in $FAILED; do'), US.indexOf('  echo "   the full messages are above'));
  const st = path.join(dir, 'quiet.sh'); fs.writeFileSync(st, 'echo "==> working"\necho "something went wrong in node: EACCES"\nexit 2\n');
  const o = spawnSync('bash', ['-c', 'STEPLOG=' + dir + '; FAILED=""\n' + fn + '\nitam_step itam-duty ' + st + ' >/dev/null\n' + sum], { encoding: 'utf8' });
  assert.match(o.stdout, /itam-duty said:\n\s+==> working\n\s+something went wrong in node: EACCES/);
});

test('add-duty: the protected-file list does not stop the installer when nothing matches (the server\'s "line 102" stop)', () => {
  const D = fs.readFileSync(path.join(ROOT, 'install', 'add-duty.sh'), 'utf8'), line = D.split('\n').find((l) => l.startsWith('PROTECT=" main '));
  assert.ok(line, 'the PROTECT line');
  const run = (setup) => { const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'prot-')); setup(dir);
    return spawnSync('bash', ['-c', 'set -euo pipefail\nHERE=' + JSON.stringify(dir) + '\n' + line + '\necho "[$PROTECT]"'], { encoding: 'utf8' }); };
  let r = run(() => {}); assert.strictEqual(r.status, 0, 'no patches/, no core-known.txt: ' + r.stderr); assert.match(r.stdout, /^\[ main \s*\]$/m);
  r = run((d) => { fs.mkdirSync(path.join(d, 'patches')); fs.writeFileSync(path.join(d, 'patches', 'a.patch'), '--- a/README\n+++ b/README\n'); fs.writeFileSync(path.join(d, 'core-known.txt'), '# only comments\n'); });
  assert.strictEqual(r.status, 0, 'a patch and core-known.txt without engine files: ' + r.stderr);
  r = run((d) => { fs.mkdirSync(path.join(d, 'patches')); fs.writeFileSync(path.join(d, 'patches', 'a.patch'), '+++ b/engine/http.js\n'); fs.writeFileSync(path.join(d, 'core-known.txt'), 'abc engine/routes.js\n'); });
  assert.strictEqual(r.status, 0); assert.match(r.stdout, /main http\s+routes/, 'the files are still protected: ' + r.stdout);
  // the same shape for the module lists
  for (const l of D.split('\n').filter((x) => /^OPT="/.test(x))) assert.match(l, /\{ grep -o [^}]*\|\| true; \}/, 'module list tolerates no match: ' + l.slice(0, 60));
});
