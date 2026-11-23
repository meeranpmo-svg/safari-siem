// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// UAT sign-off checklist for the AI Windows Server Administrator (engine/sysadmin/uat.js): tests on the UAT site's servers,
// platform evidence beside each test (never a result), roles, validation, four-eyes sign-off, new rounds and the audit trail.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/sysadmin/routes');
const { TESTS } = require('../engine/sysadmin/uat');

async function setup(execFail) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-uat-')), secrets = path.join(dir, 'secrets.json');
  fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = {};
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const exec = async (req) => (req.op === 'version' ? { ok: true } : req.op === 'run' ? (execFail || { ok: true, data: req.check === 'disks' ? [{ drive: 'C:', size_gb: 100, free_gb: 3, free_pct: 3 }] : [], errors: [] }) : { ok: false, kind: 'input', error: 'bad op' });
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: exec });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d, user, role]), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R[m + ' /api/soc/sysadmin' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  await call('POST', '/targets', { role: 'admin', body: { id: 'uat-app01', name: 'UAT-APP01', ip: '10.9.0.11', site: 'UAT' } });
  await call('POST', '/targets', { role: 'admin', body: { id: 'prod-fs01', name: 'PROD-FS01', ip: '10.1.0.10', site: 'HQ' } });
  return { S, call, audits };
}

test('the round lists the UAT servers only, every test not run, and no evidence before anything happened', async () => {
  const { call } = await setup();
  const v = (await call('GET', '/uat')).body;
  assert.equal(v.site, 'UAT'); assert.deepEqual(v.servers.map((s) => s.id), ['uat-app01']);
  assert.equal(v.items.length, TESTS.length); assert.ok(v.items.every((i) => i.result === 'not_run' && i.evidence === null));
  assert.equal(v.ready_to_sign, false); assert.equal(v.summary.required, TESTS.filter((t) => t.required).length);
});

test('evidence comes from the UAT servers only: checks, problems, a refused login', async () => {
  const { S, call } = await setup();
  S.targets.setProfile('windows', { username: 'CORP\\svc-ai-winread', password: 'Synthetic-1' }, 'admin1');
  await S.health.pollServer('uat-app01', {}); await S.health.pollServer('prod-fs01', {});
  let v = (await call('GET', '/uat')).body, ev = Object.fromEntries(v.items.map((i) => [i.id, i.evidence]));
  assert.match(ev.connection, /1 of 1 UAT server\(s\) checked/);
  assert.match(ev.finding, /problem\(s\) open on UAT servers/);
  assert.equal(ev.badlogin, null);
  const bad = await setup({ ok: false, kind: 'auth', error: 'login refused' });
  bad.S.targets.setProfile('windows', { username: 'CORP\\svc-ai-winread', password: 'Wrong-1' }, 'admin1');
  await bad.S.health.pollServer('uat-app01', {});
  v = (await bad.call('GET', '/uat')).body; ev = Object.fromEntries(v.items.map((i) => [i.id, i.evidence]));
  assert.match(ev.badlogin, /UAT-APP01/); assert.match(ev.unreachable, /could not run/);
  assert.ok(!JSON.stringify(v).includes('Wrong-1'), 'no password in the view');
});

test('recording results: roles, validation, a fail needs a note, audit with who and what', async () => {
  const { call, audits } = await setup();
  assert.equal((await call('POST', '/uat/items/:id', { role: 'viewer', params: { id: 'connection' }, body: { result: 'pass' } })).status, 403);
  assert.equal((await call('POST', '/uat/items/:id', { role: 'analyst', params: { id: 'connection' }, body: { result: 'pass' } })).status, 403);
  let r = await call('POST', '/uat/items/:id', { role: 'operator', params: { id: 'connection' }, body: { result: 'maybe' } });
  assert.equal(r.status, 400); assert.match(r.error, /result/);
  r = await call('POST', '/uat/items/:id', { role: 'operator', params: { id: 'finding' }, body: { result: 'fail' } });
  assert.equal(r.status, 400); assert.match(r.error, /note is required/);
  assert.equal((await call('POST', '/uat/items/:id', { role: 'operator', params: { id: 'nope' }, body: { result: 'pass' } })).status, 404);
  r = await call('POST', '/uat/items/:id', { role: 'operator', params: { id: 'connection' }, body: { result: 'pass', server: 'prod-fs01' } });
  assert.equal(r.status, 400); assert.match(r.error, /not a UAT server/);
  r = await call('POST', '/uat/items/:id', { role: 'operator', user: 'tester1', params: { id: 'connection' }, body: { result: 'pass', server: 'uat-app01', note: 'all checks answered', extra: 'dropped' } });
  assert.equal(r.status, 200);
  const it = r.body.items.find((i) => i.id === 'connection');
  assert.equal(it.result, 'pass'); assert.equal(it.by, 'tester1'); assert.equal(it.server, 'uat-app01'); assert.equal(it.extra, undefined);
  const a = audits.find((x) => x[0] === 'sysadmin.uat.result');
  assert.deepEqual([a[1], a[2].from, a[2].to, a[3], a[4]], ['connection', 'not_run', 'pass', 'tester1', 'operator']);
});

test('sign-off: every required test passed, by an admin who recorded none of the results; then the round is closed', async () => {
  const { call, audits } = await setup();
  assert.equal((await call('POST', '/uat/signoff', { role: 'admin', user: 'boss' })).status, 409);
  for (const t of TESTS.filter((x) => x.required)) await call('POST', '/uat/items/:id', { role: 'operator', user: 'tester1', params: { id: t.id }, body: { result: 'pass' } });
  await call('POST', '/uat/items/:id', { role: 'admin', user: 'admin2', params: { id: 'roles' }, body: { result: 'pass', note: 're-tested' } });
  assert.equal((await call('GET', '/uat')).body.ready_to_sign, true);
  assert.equal((await call('POST', '/uat/signoff', { role: 'operator', user: 'op9' })).status, 403);
  const own = await call('POST', '/uat/signoff', { role: 'admin', user: 'admin2' });
  assert.equal(own.status, 403); assert.match(own.error, /four eyes/);
  const ok = await call('POST', '/uat/signoff', { role: 'admin', user: 'boss', body: { note: 'UAT accepted' } });
  assert.equal(ok.status, 200); assert.equal(ok.body.signoff.by, 'boss'); assert.equal(ok.body.ready_to_sign, false);
  assert.ok(audits.some((x) => x[0] === 'sysadmin.uat.signoff' && x[3] === 'boss'));
  assert.equal((await call('POST', '/uat/items/:id', { role: 'operator', params: { id: 'ai' }, body: { result: 'fail', note: 'x' } })).status, 409);
  assert.equal((await call('POST', '/uat/signoff', { role: 'admin', user: 'boss2' })).status, 409);
});

test('a new round: admin only, archives the old one, can move to another site name', async () => {
  const { call, audits } = await setup();
  await call('POST', '/uat/items/:id', { role: 'operator', user: 'tester1', params: { id: 'connection' }, body: { result: 'pass' } });
  assert.equal((await call('POST', '/uat/reset', { role: 'operator' })).status, 403);
  assert.equal((await call('POST', '/uat/reset', { role: 'admin', body: { site: '<script>' } })).status, 400);
  const r = await call('POST', '/uat/reset', { role: 'admin', user: 'boss', body: { site: 'HQ', note: 'second round' } });
  assert.equal(r.status, 200); assert.equal(r.body.round, 2); assert.equal(r.body.site, 'HQ');
  assert.deepEqual(r.body.servers.map((s) => s.id), ['prod-fs01']);
  assert.ok(r.body.items.every((i) => i.result === 'not_run'));
  assert.equal(r.body.past.length, 1); assert.equal(r.body.past[0].round, 1); assert.equal(r.body.past[0].closed_by, 'boss');
  assert.ok(audits.some((x) => x[0] === 'sysadmin.uat.reset' && x[2].site === 'HQ'));
});
