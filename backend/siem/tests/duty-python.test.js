// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 7 (sentra-itam docs/PYTHON-MIGRATION.md): engine/duty/duty_rules.py must decide exactly like duty-core.js.
// Two duty desks run in lockstep over separate stores - one Node.js only, one with Python - through the same patrols
// (new, unchanged, escalated, gone, back inside / outside the re-open window, closed as accepted risk / false positive /
// duplicate / fixed, snoozes that run out, a source that is not connected, findings with odd fields) and the same actions
// by people; after every step every work item, the counter and the patrol result must be identical, and so must the
// list / engineers / KPI / shift handover views. Then: a person's change made WHILE Python is deciding is never lost,
// and a missing interpreter falls back to Node.js. The copy in sentra-itam must be byte-for-byte this one.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createState } = require('../engine/soc/state');
const { createDuty, planPatrol, kpisCore, listCore, reportCore, RULES_PY } = require('../engine/duty/duty-core');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-dutypy-'));
const store = () => createState({ dir: path.join(tmp(), 'state') });
const plain = (v) => JSON.parse(JSON.stringify(v));
const H = 3600000, DAY = 86400000;
const py = (op, body) => { const r = spawnSync(PY, ['-I', RULES_PY], { input: JSON.stringify(Object.assign({ op }, body)) }); return JSON.parse(r.stdout.toString()); };

function engineer(id, E) {
  return {
    id, name: 'AI ' + id + ' Engineer',
    findings: () => (E.down ? null : E.list.map((f) => Object.assign({}, f))),
    investigate: (it) => (it.key === 'boom' ? Promise.reject(new Error('probe failed')) : { summary: 'checked ' + it.title, checks: [{ name: 'reach', status: 'fail', detail: 'x' }], causes: [] }),
    aiStatus: () => ({ enabled: false, reason: 'no key' }),
    kpis: id === 'network' ? (open) => [{ label: 'Links down', value: open.length, unit: '', target: 0, dir: 'max' }] : undefined,
  };
}
const F = (key, over) => Object.assign({ key, severity: 'high', kind: 'wan-down', title: 'Down: ' + key, evidence: ['ge-0/0/1 down'], recommendation: 'Check ' + key, target: { type: 'device', id: key, name: String(key).toUpperCase() }, site: 'Riyadh' }, over || {});

test('duty rules: Python decides exactly like Node.js, step by step', { skip: !hasPy && 'python3 not available' }, async () => {
  let t = Date.UTC(2026, 9, 15, 6, 0);
  const E = { network: { list: [] }, windows: { list: [] } };
  const mk = (python) => createDuty({ store: store(), now: () => t, python, engineers: [engineer('network', E.network), engineer('windows', E.windows)], policyDefaults: { ai_min_severity: 'off' } });
  const N = mk(null), P = mk(PY);
  const both = async (fn) => { const a = await fn(N), b = await fn(P); return [a, b]; };
  const same = async (what) => {
    for (const x of ['network', 'windows']) {
      const a = N.list({ engineer: x, limit: 1000 }).items.map((i) => plain(Object.assign({}, N.get(i.id))));
      const b = P.list({ engineer: x, limit: 1000 }).items.map((i) => plain(Object.assign({}, P.get(i.id))));
      assert.deepEqual(b, a, what + ': ' + x + ' items');
    }
  };
  const patrol = async (what, ids = ['network', 'windows']) => {
    for (const id of ids) {
      const [a, b] = await both((D) => D.patrol(id));
      assert.equal(b.engine, 'python', what + ': answered by Python (' + b.engine + ')'); delete b.engine;
      assert.deepEqual(plain(b), plain(a), what + ': patrol result ' + id);
    }
    await same(what);
  };
  const tick = (h) => { t += h * H; };

  E.network.list = [F('r1', { severity: 'critical' }), F('r2'), F('r3', { severity: 'low', evidence: [{ port: 1, up: false, x: null }, null, 42, 'ok', ['a', 'b']] }), F('boom'),
    F('r4', { severity: 'weird', title: 'x'.repeat(239) + '😀 tail', kind: 'k\u0001ind', target: 0 }), F('r2', { title: 'duplicate key, later wins' }), { key: '' }, null,
    F(17, { severity: ['high'], evidence: 'one string', target: 'str', recommendation: '' })];
  E.windows.list = [F('w1', { severity: 'medium', site: undefined }), F('w2', { severity: 'low' })];
  await patrol('first patrol');
  tick(1); E.network.list[1] = F('r2', { severity: 'critical', evidence: ['worse'] }); E.network.list.splice(5, 1); await patrol('escalated + unchanged');
  // people act on both desks the same way
  const ids = N.list({ engineer: 'network' }).items.map((x) => x.id).sort();
  for (const D of [N, P]) {
    D.assign(ids[0], 'siva', 'rasheed'); D.note(ids[1], 'looked at it', 'siva');
    D.close(ids[2], 'false-positive', 'lab box', 'rasheed'); D.close(ids[3], 'duplicate', 'same as INC-1', 'siva');
    D.snooze(ids[4], 2, 'maintenance tonight', 'siva');
    D.close(N.list({ engineer: 'windows' }).items.find((x) => x.key === 'w2').id, 'fixed', 'patched by hand', 'siva');
  }
  await same('after people acted');
  tick(1); E.network.list = E.network.list.filter((f) => !f || f.key !== 'r1'); E.windows.list = [F('w1', { severity: 'medium' })]; await patrol('r1 gone, w2 gone');
  tick(3); await patrol('snooze ran out');
  tick(2); E.network.list.push(F('r1', { severity: 'high' })); E.windows.list.push(F('w2')); await patrol('back inside the re-open window');
  E.network.down = true; tick(1); await patrol('network not connected: nothing opened or resolved');
  E.network.down = false; E.network.list = [F('r9')]; tick(24 * 8); await patrol('everything else gone');
  E.network.list = [F('r1'), F('r2'), F('r3'), F('boom')]; tick(1); await patrol('back after the window, suppressed, duplicate');
  tick(24 * 31); E.network.list = [F('r3', { severity: 'critical' })]; await patrol('suppression over');
  // the views
  for (const f of [{}, { engineer: 'network' }, { status: 'open' }, { status: 'resolved', limit: '2' }, { since: String(t - 30 * DAY) }, { since: 'x' }, { limit: '-3' }, { limit: 'all' }])
    assert.deepEqual(plain(await P.listAuto(f)), plain(N.list(f)), 'list ' + JSON.stringify(f));
  assert.deepEqual(plain(await P.engineersAuto()), plain(N.engineers()), 'engineers');
  for (const id of ['network', 'windows']) for (const days of [undefined, '7', '0', '365', 'x', '2.5']) assert.deepEqual(plain(await P.kpisAuto(id, { days })), plain(N.kpis(id, { days })), 'kpis ' + id + ' ' + days);
  for (const id of ['network', 'windows']) for (const since of [undefined, t - 40 * DAY]) assert.deepEqual(plain(await P.makeReportAuto(id, since)), plain(N.makeReport(id, since)), 'report ' + id);
  assert.equal(P.engine(), 'python');
});

test('duty rules: the pure functions, odd inputs', { skip: !hasPy && 'python3 not available' }, () => {
  const now = Date.UTC(2026, 9, 19, 9, 0);
  const items = [
    { id: 'DW-000001', engineer: 'e', key: 'a', status: 'resolved', resolved_at: now - 2 * DAY, severity: 'high', detected_at: now - 5 * DAY, resolution: 'verified-fixed', history: [{ at: now - 5 * DAY + 60000, by: 'duty', action: 'diagnosed' }, { at: now - 4 * DAY, by: 'syed', action: 'note' }, { at: now - 4 * DAY, by: 'duty', action: 'fix-proposed' }, { at: now - 3 * DAY, by: 'duty', action: 'approved' }, { at: now - 2 * DAY, by: 'duty', action: 'reopened' }] },
    { id: 'DW-000002', engineer: 'e', key: 'a', status: 'closed', close_code: 'accepted-risk', resolved_at: now - DAY, suppress_until: now + DAY, severity: 'critical' },
    { id: 'DW-000003', engineer: 'e', key: 'b', status: 'awaiting-approval', severity: 'critical', detected_at: now - 3 * DAY, first_seen: now - 3 * DAY, history: [{ at: now - 2 * DAY, by: 'core:x', action: 'fix-proposed' }], owner: '', ai: { at: now - DAY, answer: 'long', model: 'm', proposed: ['C1'], steps: 2 } },
    { id: 'DW-000004', engineer: 'e', key: 'c', status: 'snoozed', snooze_until: now - 1, investigation: { summary: 's' }, severity: 'low', target: null },
    { id: 'DW-000005', engineer: 'e', key: 'd', status: 'snoozed', snooze_until: now + H, severity: 'medium', target: { type: 't' } },
    { id: 'DW-000006', engineer: 'e', status: 'open', severity: 'high', kind: 'x', detected_at: now - 10 * H },
    { id: 'DW-000007', engineer: 'e', key: 'f', status: 'fix-applied', severity: 'high', detected_at: now - 2 * DAY, changes: ['C2'] },
  ];
  for (const findings of [null, [], [{ key: 'a' }, { key: 'b', severity: 'low' }, { key: 'c' }, { key: 'zz', title: '😀'.repeat(130), evidence: { nested: [1, { k: 'v' }] } }]]) {
    const inp = { engineer: 'e', engineer_name: 'E', findings, items: plain(items), policy: { reopen_window_days: 7 }, now, counter: 7 };
    assert.deepEqual(py('duty.plan', plain(inp)), plain(planPatrol(plain(inp))), 'plan ' + JSON.stringify(findings && findings.length));
  }
  const st = { patrols: 10, errors: 3, last_patrol: now - 2 * H, last_result: { not_connected: false }, last_error: 'x' };
  for (const policy of [{ enabled: true, patrol_min: 10 }, { enabled: false, patrol_min: 10 }, { enabled: true, patrol_min: 60 }]) {
    const k = { engineer: 'e', name: 'E', now, days: '30', policy, targets: { open_serious: 0, sla_pct: 90, human_h: 4, approval_h: 24, fix_h: 72, fix_success_pct: 90, reopen_pct: 10, patrol_pct: 95, diag_min: 30 }, st, items: plain(items), domain: null };
    assert.deepEqual(py('duty.kpis', plain(k)), plain(kpisCore(plain(k))), 'kpis ' + JSON.stringify(policy));
  }
  assert.deepEqual(py('duty.report', { engineer: 'e', name: 'E', now, since: 0, items: plain(items), st }), plain(reportCore({ engineer: 'e', name: 'E', now, since: 0, items: plain(items), st })));
  assert.deepEqual(py('duty.list', { filter: { status: 'open' }, items: plain(items) }), plain(listCore({ filter: { status: 'open' }, items: plain(items) })));
  assert.equal(py('duty.nothing', {}).ok, false, 'an unknown operation is refused, not guessed');
});

test('duty rules: a person\'s change while Python decides is never written over; no interpreter = Node.js', { skip: !hasPy && 'python3 not available' }, async () => {
  const dir = tmp(), slow = path.join(dir, 'slow-python');
  fs.writeFileSync(slow, `#!/bin/sh\nsleep 0.6\nexec ${PY} "$@"\n`, { mode: 0o755 });
  let t = Date.UTC(2026, 9, 15, 6, 0); const E = { list: [F('r1'), F('r2')] };
  const D = createDuty({ store: store(), now: () => t, python: slow, engineers: [engineer('network', E)], policyDefaults: { ai_min_severity: 'off' } });
  await D.patrol('network');
  const id = D.list({}).items.find((x) => x.key === 'r1').id;
  t += H; E.list = [F('r2')];
  const run = D.patrol('network');
  await new Promise((r) => setTimeout(r, 200));
  D.assign(id, 'siva', 'rasheed');   // while Python is still deciding
  const r = await run;
  assert.equal(r.engine, 'node (items changed during the Python call)');
  const it = D.get(id);
  assert.equal(it.owner, 'siva', 'the assignment survived'); assert.equal(it.status, 'resolved', 'and the patrol still resolved it');
  const M = createDuty({ store: store(), now: () => t, python: path.join(dir, 'no-such-python'), engineers: [engineer('network', E)] });
  const r2 = await M.patrol('network');
  assert.equal(r2.opened, 1); assert.match(r2.engine, /^node/);
  assert.ok(Array.isArray((await M.listAuto({})).items));
});

test('duty rules: the sentra-itam copies are identical', (t) => {
  const itam = path.join(__dirname, '..', '..', 'itam', 'engine');
  if (!fs.existsSync(itam)) { t.skip('shield checkout not next to sentra-siem'); return; }
  for (const [a, b] of [['duty_rules.py', 'duty_rules.py'], ['duty-core.js', 'duty-core.js']])
    assert.equal(fs.readFileSync(path.join(itam, b), 'utf8'), fs.readFileSync(path.join(__dirname, '..', 'engine', 'duty', a), 'utf8'), a + ': edit the sentra-siem copy and copy it to sentra-itam');
});
