// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Update doctor (install/update-doctor.js), the duty installer's check policy (install/add-duty.sh) and Update Health
// (engine/update-health.js). Bug fixed: when ONE checked page did not answer after an update, add-duty.sh restored the whole
// previous engine - the Email Route Map and every new page then said "not installed" although their files had shipped. Now the
// running engine is kept, the pages that do not answer are named with the cause the log shows, and the result is recorded.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const D = require('../install/update-doctor');

const ROOT = path.join(__dirname, '..'), SH = fs.readFileSync(path.join(ROOT, 'install/add-duty.sh'), 'utf8'), LIB = fs.readFileSync(path.join(ROOT, 'install/lib-itam.sh'), 'utf8');

test('diagnose: each failure the log shows gets its cause and fix; unknown lines are not guessed', () => {
  const log = [
    "Error: Cannot find module './discovery/diag'",
    'duty: module not installed - re-run the update {"module":"./mail-reputation"}',
    "Error: EACCES: permission denied, open '/etc/sentra-itam/secrets.json'",
    'SyntaxError: Unexpected end of input',
    'Error: listen EADDRINUSE: address already in use 127.0.0.1:9150',
    "ModuleNotFoundError: No module named 'vapt_rules'",
    'credential vault unavailable: key file not readable',
    'something perfectly normal happened',
    "Error: Cannot find module './discovery/diag'",
  ].join('\n');
  const f = D.diagnose(log).findings, by = (r) => f.find((x) => x.rule === r);
  assert.equal(f.length, 7, 'one finding per distinct cause, the repeated line counted once, the normal line ignored');
  assert.match(by('missing-module').fix, /diag\.js was not installed/);
  assert.match(by('duty-module-missing').cause, /mail-reputation is not on the server/);
  assert.match(by('permission').fix, /chown root:sentra-itam \/etc\/sentra-itam\/secrets\.json/);
  assert.match(by('port-in-use').fix, /:9150/);
  assert.match(by('python-import').cause, /vapt_rules/);
  assert.ok(by('syntax') && by('vault-key'));
});

test('preflight: a module needing a file nobody installed gets it from the package before the restart; what cannot be fixed is named', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-pf-')), app = path.join(tmp, 'app'), pkg = path.join(tmp, 'pkg');
  fs.mkdirSync(path.join(app, 'discovery'), { recursive: true }); fs.mkdirSync(path.join(pkg, 'discovery'), { recursive: true });
  fs.writeFileSync(path.join(app, 'main.js'), 'throw new Error("main.js must never be loaded by the preflight")');
  fs.writeFileSync(path.join(app, 'good.js'), 'module.exports = require("./discovery/diag");');
  fs.writeFileSync(path.join(pkg, 'discovery', 'diag.js'), 'module.exports = { ok: true };');
  fs.writeFileSync(path.join(app, 'broken.js'), 'require("./not-in-the-package-either");');
  const r = D.preflight(app, pkg);
  assert.equal(r.checked, 2); assert.deepEqual(r.supplied, ['discovery/diag.js']); assert.ok(fs.existsSync(path.join(app, 'discovery', 'diag.js')));
  assert.equal(r.errors.length, 1); assert.equal(r.errors[0].module, 'broken.js'); assert.equal(r.ok, false);
  const rep = path.join(tmp, 'update-report.json');
  D.report(rep, 'duty', 'partial', JSON.stringify({ missing: '/mail-route' })); D.report(rep, 'ciso', 'ok', '');
  const doc = JSON.parse(fs.readFileSync(rep, 'utf8'));
  assert.equal(doc.installers.duty.status, 'partial'); assert.equal(doc.installers.duty.missing, '/mail-route'); assert.equal(doc.installers.ciso.status, 'ok'); assert.ok(doc.updated_at);
});

test('add-duty.sh: one page not answering no longer rolls back the rest; it is named, diagnosed and recorded; preflight runs before every restart', () => {
  assert.doesNotMatch(SH, /itam_serves "\$p" \|\| restore/, 'no whole-engine restore for one page');
  assert.match(SH, /MISS="\$MISS \$p"/); assert.match(SH, /itam_doctor/); assert.match(SH, /itam_report duty partial/); assert.match(SH, /exit 3/);
  assert.match(SH, /itam_report duty ok/);
  for (const p of ['/mail-route', '/dr-studio', '/vsphere-studio', '/vapt-studio', '/discovery-studio', '/platform/update-health']) assert.ok(SH.includes(' ' + p + ' ') || SH.includes(' ' + p + '"'), p + ' is checked after an update');
  assert.match(SH, /404\) restore "the duty desk did not register"/, 'a duty desk that does not register at all is still restored');
  assert.match(LIB, /itam_on_restore\(\) \{[\s\S]*itam_doctor[\s\S]*itam_report "\$name" rolled-back/, 'every rollback is diagnosed and recorded');
  const fs0 = require('node:fs'), dir = path.join(__dirname, '..', 'install');
  for (const f of fs0.readdirSync(dir).filter((x) => /^add-.*\.sh$/.test(x))) { const s = fs0.readFileSync(path.join(dir, f), 'utf8'); if (/restore\(\) \{/.test(s)) assert.match(s, /restore\(\) \{ itam_on_restore "\$1";/, f + ': its rollback is reported'); }
  const RC = fs0.readFileSync(path.join(dir, 'add-remote-console.sh'), 'utf8');
  assert.doesNotMatch(RC, /itam_serves \/console \|\| restore/, 'a /console 404 with a running engine does not roll back');
  assert.match(RC, /itam_report remote-console partial/);
  // the package the PC builds must carry every file lib-itam.sh uses, or the doctor and the report silently do nothing on the server
  const MAP = fs0.readFileSync(path.join(__dirname, '..', '..', '..', 'deploy', 'stage-map.txt'), 'utf8');   // the package layout of this tree
  for (const f of ['lib-itam.sh', 'update-doctor.js', 'add-duty.sh', 'add-remote-console.sh']) assert.ok(MAP.includes('backend/itam/install/' + f + ' '), f + ' is copied into the update package');
  assert.match(LIB, /itam_restart_if_changed\(\) \{\n  itam_supply_deps\n  itam_preflight/, 'the preflight runs before every installer restart');
});

test('Update Health: pages served vs expected, modules not loaded, installer results and findings; admin only', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-uh-')), rep = path.join(tmp, 'update-report.json');
  D.report(rep, 'duty', 'partial', JSON.stringify({ missing: '/mail-route', findings: D.diagnose("Error: Cannot find module './mail-reputation'") }));
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', updateReportFile: rep });
  e.app.dutyMissing = ['remote-console'];
  let r = await e.req('GET', '/platform/update-health', { user: 'nora.syn', role: 'operator' }); assert.equal(r.status, 403);
  r = await e.req('GET', '/platform/update-health', { user: 'syed', role: 'admin' }); assert.equal(r.status, 200, r.raw);
  const v = r.json, pg = (n) => v.pages.find((p) => p.name === n);
  assert.equal(pg('Email Route Map').ok, true, 'registered in this engine'); assert.equal(pg('Discovery Studio').ok, true);
  assert.equal(pg('Remote Console').ok, false); assert.match(pg('Remote Console').why, /remote-console\.js is not on the server/);
  assert.equal(v.summary.state, 'ATTENTION'); assert.deepEqual(v.missing_modules, ['remote-console']);
  assert.equal(v.installers[0].installer, 'duty'); assert.equal(v.installers[0].status, 'partial');
  assert.match(v.findings[0].fix, /mail-reputation\.js was not installed/);
  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  for (const r0 of ['/ciso/insights', '/ciso/overview']) e2.app.srv.route('GET', r0, () => ({}));   // main.js registers AI CISO on a server
  registerDuty(e2.app.srv, e2.app, { noTimer: true, python: process.env.PYTHON || 'python3', updateReportFile: path.join(tmp, 'none.json') });
  const n = (await e2.req('GET', '/platform/update-health', { user: 'syed', role: 'admin' })).json;
  assert.equal(n.summary.state, 'NO REPORT YET'); assert.equal(n.installers.length, 0);
});

test('readiness answers when the AI CISO overview hangs (the server update saw /duty/readiness HTTP 0)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', readinessCisoMs: 200, readinessMs: 60000 });   // this test is about the CISO bound; the overall budget has its own test (duty.test.js)
  e.app.addons.ciso = { overview: () => new Promise(() => {}), status: () => ({ running: false, brief_hour: 7 }) };   // never answers
  const t0 = Date.now(), r = await e.req('GET', '/duty/readiness', { user: 'vera.syn', role: 'viewer' });
  assert.equal(r.status, 200, r.raw); assert.ok(Date.now() - t0 < 9000, 'answers within the bound, not when the CISO sources do');
  const c = r.json.engineers.find((x) => x.id === 'ciso'); assert.ok(c, 'the AI CISO is listed'); assert.match(c.checks[0].detail, /not read yet/);
});

test('a page slow on its first request is retried with 30 s before it counts as missing; the update summary names each failed step', () => {
  const { execFileSync } = require('node:child_process');
  const run = (codes) => execFileSync('bash', ['-c', `
    HERE=${JSON.stringify(path.join(ROOT, 'install'))}; APP=/nonexistent; SVC=sentra-itam-test; set +e
    . "$HERE/lib-itam.sh" >/dev/null 2>&1
    CNT=$(mktemp); echo 0 > "$CNT"; CODES=(${codes}); itam_code() { local n; n=$(cat "$CNT"); echo $((n+1)) > "$CNT"; echo "\${CODES[$n]}"; }; itam_restart() { :; }; itam_up() { :; }
    itam_serves /slow-page && echo SERVED || echo MISSING`], { encoding: 'utf8' });
  let out = run('0 200'); assert.match(out, /answered only on a second try \(HTTP 200\)/); assert.match(out, /SERVED/);
  out = run('0 0 0'); assert.match(out, /MISSING/, 'no answer in 30 s either, nor after waiting for the port: missing'); assert.match(out, /connection refused/);
  out = run('0 0 200'); assert.match(out, /SERVED/, 'refused while restarting, answers once it listens');
  out = run('0 404'); assert.match(out, /MISSING/);
  out = run('403'); assert.match(out, /SERVED/, 'a refusal means the route exists');
  // summary of the update report
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sum-')), 'update-report.json');
  D.report(f, 'duty', 'partial', JSON.stringify({ missing: '/audit-repo', findings: [{ title: 'module failed to load', message: "Cannot find module './xlsx-read'", fix: 're-run the update' }] }));
  D.report(f, 'final-check', 'ok', '{}');
  const s = D.summary(f);
  assert.match(s, /duty \(partial/); assert.match(s, /pages not answering: \/audit-repo/); assert.match(s, /xlsx-read.*fix: re-run the update/); assert.ok(!/final-check/.test(s), 'ok steps are not listed');
  assert.match(fs.readFileSync(path.join(ROOT, '../../deploy/server/update-server.sh'), 'utf8'), /update-doctor\.js" summary \/opt\/sentra-itam\/update-report\.json/, 'the update prints it');
});
