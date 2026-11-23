// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Core-file upgrade (install/update-discovery.sh core_upgrade + install/core-known.txt): a patched core file that a patch no
// longer fits is replaced whole by the current one ONLY when it is an unmodified version the platform shipped (its hash is in
// core-known.txt); a file changed on the server is left alone; the current file reads "already installed"; a CRLF copy counts
// as the same version. core-known.txt must be current with git history and the patches (gen-core-known.js --check).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
const ROOT = path.resolve(__dirname, '..');
const hasGit = (() => { try { cp.execFileSync('git', ['rev-parse', '--git-dir'], { cwd: ROOT, stdio: 'ignore' }); return true; } catch (e) { return false; } })();

test('core-known.txt is current with git history and the patches', { skip: !hasGit && 'no git history here (clean tree)' }, () => {
  const r = cp.spawnSync(process.execPath, [path.join(ROOT, 'install/gen-core-known.js'), '--check'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr + r.stdout);
});

test('core_upgrade: an unmodified older version is replaced (backup kept), a changed file is left alone', { skip: (!hasGit && 'no git history') || (process.getuid && process.getuid() !== 0 && 'needs root (install -o root)') }, () => {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'core-up-')), APP = path.join(T, 'app'), HERE = path.join(T, 'bundle', 'install');
  fs.mkdirSync(path.join(APP, 'engine'), { recursive: true }); fs.mkdirSync(path.join(T, 'bundle', 'engine-all'), { recursive: true }); fs.mkdirSync(HERE, { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'install/core-known.txt'), path.join(HERE, 'core-known.txt'));
  for (const f of ['routes.js', 'http.js']) fs.copyFileSync(path.join(ROOT, 'engine', f), path.join(T, 'bundle', 'engine-all', f));
  // the oldest shipped http.js, with CRLF line ends (a Windows checkout); a hand-edited routes.js
  const first = cp.execFileSync('git', ['log', '--format=%H', '--reverse', '--', 'engine/http.js'], { cwd: ROOT, encoding: 'utf8' }).split('\n')[0];
  const old = cp.execFileSync('git', ['show', first + ':./engine/http.js'], { cwd: ROOT, encoding: 'utf8' });
  fs.writeFileSync(path.join(APP, 'engine/http.js'), old.replace(/\r?\n/g, '\r\n'));
  fs.writeFileSync(path.join(APP, 'engine/routes.js'), fs.readFileSync(path.join(ROOT, 'engine/routes.js'), 'utf8') + '\n// changed on this server\n');
  const fn = fs.readFileSync(path.join(ROOT, 'install/update-discovery.sh'), 'utf8').match(/^core_upgrade\(\) \{[\s\S]*?^\}$/m)[0];
  const sh = `set -u; say() { echo "==> $*"; }; HERE='${HERE}'; APP='${APP}'; BK='${T}/bk'; TMPD='${T}'; NODE='${process.execPath}'; KNOWN="$HERE/core-known.txt"\n${fn}\n`
    + 'core_upgrade engine/http.js http-roles; echo "rc1=$?"; core_upgrade engine/http.js http-roles; echo "rc2=$?"; core_upgrade engine/routes.js assets-write; echo "rc3=$?"';
  const r = cp.spawnSync('bash', ['-c', sh], { encoding: 'utf8' });
  assert.match(r.stdout, /http-roles: engine\/http\.js was an unmodified earlier platform version - replaced/, r.stdout + r.stderr);
  assert.match(r.stdout, /rc1=0/); assert.match(r.stdout, /http-roles: already installed .*rc2=0/s, 'second run: already the current version');
  assert.equal(fs.readFileSync(path.join(APP, 'engine/http.js'), 'utf8'), fs.readFileSync(path.join(ROOT, 'engine/http.js'), 'utf8'), 'the current file installed');
  assert.ok(fs.readdirSync(path.join(T, 'bk')).some((f) => /^http\.js\.pre-upgrade-/.test(f)), 'the previous file is backed up');
  assert.match(r.stdout, /rc3=1/, 'a file changed on the server is not a shipped version: not replaced');
  assert.match(fs.readFileSync(path.join(APP, 'engine/routes.js'), 'utf8'), /changed on this server/, 'left exactly as it was');
});
