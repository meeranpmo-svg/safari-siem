// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 8d (docs/PYTHON-MIGRATION.md): the GRC read routes (policy drafts, DR drills: list, one, per-system
// coverage, summary) from pyengine/grc_read.py and the audit hash-chain check from pyengine/store.py must answer exactly
// like the Node.js routes. A Python-backed engine and a Node.js-only engine (grc.engine / audit.engine = "node") run on
// identical copies of one data folder and are asked the same over HTTP: drafts with and without documents, drills of
// every status / result with RTO / RPO met, not met, not measured, typed as text, overdue and never tested systems,
// upcoming drills; a drill date that is not ISO (Python must hand the answer to Node.js); the audit chain intact and
// tampered. Plus the fixed "Roles & responsibilities" control (it read an empty collection and said "no roles defined").
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp, tmpDir } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z'), DAY = 86400000;
const iso = (d) => new Date(NOW + d * DAY).toISOString().slice(0, 10);
function copyDir(a, b) { fs.mkdirSync(b, { recursive: true }); for (const f of fs.readdirSync(a)) { const s = path.join(a, f); if (fs.statSync(s).isDirectory()) copyDir(s, path.join(b, f)); else fs.copyFileSync(s, path.join(b, f)); } }

async function build(dir, odd) {
  const e = await startApp({ noAi: true, dir });
  const dr = e.app.store.collection('grc_drafts'), dl = e.app.store.collection('grc_drills');
  dr.put({ id: 'DRF-1', title: 'Cloud policy', status: 'draft', updated: NOW - 5 * DAY, document: { filename: 'cloud.docx', sha256: 'ab', content_b64: 'UEsDBA==' } });
  dr.put({ id: 'DRF-2', title: 'AI policy', status: 'in-review', updated: NOW - DAY });
  dr.put({ id: 'DRF-3', title: 'No date', status: 'draft' });
  const D = (o) => dl.put(Object.assign({ status: 'planned', result: null, executed: null, history: [], findings: [], actions: [], rto_target_min: null, rto_actual_min: null, rpo_target_min: null, rpo_actual_min: null, frequency_months: 12 }, o));
  D({ id: 'DR-1', title: 'Core banking failover', system: 'Core Banking', type: 'failover', status: 'completed', result: 'pass', executed: iso(-400), rto_target_min: 60, rto_actual_min: 45, rpo_target_min: 15, rpo_actual_min: 20, signoff: { by: 'rasheed', at: NOW }, executed_by: 'siva', evidence: { filename: 'r.pdf', content_b64: 'JVBERi0=', sha256: 'x' }, updated: NOW - 400 * DAY });
  D({ id: 'DR-2', title: 'Core banking restore', system: 'core banking', type: 'restore', status: 'completed', result: 'partial', executed: iso(-30), rto_target_min: '120', rto_actual_min: '90', frequency_months: 6, updated: NOW - 30 * DAY });
  D({ id: 'DR-3', title: 'Email DR', system: 'Exchange', type: 'full-dr', status: 'planned', scheduled: iso(20), updated: NOW - 2 * DAY });
  D({ id: 'DR-4', title: 'Old plan', system: 'Exchange', type: 'tabletop', status: 'planned', scheduled: iso(-10), updated: NOW - 50 * DAY });
  D({ id: 'DR-5', title: 'Backups', system: 'Backup', type: 'backup-restore', status: 'completed', result: 'fail', executed: iso(-5) + 'T08:30:00Z', rpo_target_min: 0, rpo_actual_min: '', updated: NOW - 5 * DAY });
  D({ id: 'DR-6', title: 'Cancelled', system: 'Exchange', status: 'cancelled', scheduled: iso(5) });
  D({ id: 'DR-7', title: 'No system yet', system: '', status: 'in-progress', scheduled: iso(3), frequency_months: 0 });
  for (let i = 0; i < 6; i++) D({ id: 'DR-1' + i, title: 'Upcoming ' + i, system: 'Sys ' + (i % 3), status: 'planned', scheduled: iso(1 + i) });
  if (odd) D({ id: 'DR-99', title: 'Typed by hand', system: 'Core Banking', status: 'completed', result: 'pass', executed: '10/01/2026' });
  for (let i = 0; i < 25; i++) e.app.store.audit({ at: new Date(NOW - (25 - i) * 3600000).toISOString(), by: 'syed', role: 'admin', action: 'test.' + i, target: 't' + i, detail: { i, text: 'é 中 😀' } });
  const assign = e.app.store.collection('role_assignments');
  if (e.app.roles) e.app.roles.setUser({ user: 'siva', role_id: 'server-admin' }, { user: 'syed', role: 'admin', ip: '' }); else assign.put({ id: 'siva', user: 'siva', role_id: 'server-admin' });
  await e.close();
}

async function pair(t, odd) {
  const d0 = tmpDir(); await build(d0, odd);
  const dn = tmpDir(), dp = tmpDir(); copyDir(d0, dn); copyDir(d0, dp);
  const N = await startApp({ noAi: true, dir: dn, config: { grc: { engine: 'node' }, audit: { engine: 'node' } } });
  const P = await startApp({ noAi: true, dir: dp, config: { discovery: { python_bin: PY } } });
  for (const e of [N, P]) e.app.now = () => NOW;
  t.after(async () => { await N.close(); await P.close(); });
  return { N, P, dn, dp };
}
async function same(N, P, p, role = 'operator') {
  const [a, b] = await Promise.all([N.req('GET', p, { role }), P.req('GET', p, { role })]);
  assert.equal(b.status, a.status, p + ' status'); assert.deepEqual(b.json, a.json, p); return a.json;
}

test('Python GRC drafts and drills answer exactly like Node.js', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const { N, P } = await pair(t, false);
  for (const p of ['/grc/drafts', '/grc/drafts?status=draft', '/grc/drafts/DRF-1', '/grc/drafts/nope', '/grc/drills', '/grc/drills?status=completed', '/grc/drills?system=CORE%20BANKING', '/grc/drills?result=fail', '/grc/drills?type=tabletop',
    '/grc/drills/DR-1', '/grc/drills/DR-5', '/grc/drills/nope', '/grc/drills/systems', '/grc/drills/summary']) await same(N, P, p);
  const s = await same(N, P, '/grc/drills/summary');
  assert.ok(s.systems.overdue > 0 && s.upcoming.length === 5 && s.rto.measured === 2, JSON.stringify(s.systems));
  const one = (await P.req('GET', '/grc/drafts/DRF-1')).json;
  assert.ok(one.document && !('content_b64' in one.document), 'the document bytes are never sent with the draft');
  // it really was Python: the Python operations themselves give Node.js's answers
  const run = (body) => JSON.parse(spawnSync(PY, ['-I', path.join(__dirname, '..', 'pyengine', 'run.py')], { input: JSON.stringify(Object.assign({ dir: P.app.store.dir, now: NOW }, body)) }).stdout.toString());
  assert.deepEqual(run({ op: 'grc.drills', query: {} }), (await N.req('GET', '/grc/drills')).json, 'Python grc.drills');
  assert.deepEqual(run({ op: 'grc.drill_summary' }), (await N.req('GET', '/grc/drills/summary')).json, 'Python grc.drill_summary');
  assert.deepEqual(run({ op: 'grc.drafts', query: { status: 'draft' } }), (await N.req('GET', '/grc/drafts?status=draft')).json, 'Python grc.drafts');
  assert.deepEqual(run({ op: 'store.verify_audit' }), (await N.req('GET', '/audit', { role: 'admin' })).json.verify, 'Python audit check');
});

test('a drill date that is not ISO: Node.js answers, the same as before', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const { N, P, dp } = await pair(t, true);
  for (const p of ['/grc/drills', '/grc/drills/systems', '/grc/drills/summary', '/grc/drills/DR-99']) await same(N, P, p);
  const r = spawnSync(PY, ['-I', path.join(__dirname, '..', 'pyengine', 'run.py')], { input: JSON.stringify({ op: 'grc.drill_summary', dir: path.join(dp, 'state'), now: NOW }) });
  assert.deepEqual(JSON.parse(r.stdout.toString()), { node: true }, 'Python hands the answer to Node.js rather than guess the date');
});

test('the audit chain check in Python answers like Node.js, intact and tampered; the roles control counts the real roles', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const { N, P, dn, dp } = await pair(t, false);
  const a = await same(N, P, '/audit', 'admin');
  assert.equal(a.verify.ok, true); assert.ok(a.verify.checked >= 25);
  for (const d of [dn, dp]) { const st = path.join(d, 'state'); const f = fs.readdirSync(st).filter((x) => /^audit-/.test(x)).sort()[0]; const L = fs.readFileSync(path.join(st, f), 'utf8').split('\n'); L[3] = L[3].replace('"syed"', '"eve"'); fs.writeFileSync(path.join(st, f), L.join('\n')); }
  const b = await same(N, P, '/audit', 'admin');
  assert.equal(b.verify.ok, false); assert.equal(b.verify.reason, 'hash chain broken');
  const cs = (await P.req('GET', '/grc/control-status')).json.status.roles;
  assert.equal(cs.state, 'pass', JSON.stringify(cs)); assert.match(cs.metric, /^\d+ role\(s\)$/); assert.ok(!/no roles defined/.test(cs.detail));
});
