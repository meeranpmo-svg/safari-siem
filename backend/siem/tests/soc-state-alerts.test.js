// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { tmpDir, fakeCH, quietLog } = require('./soc-fakes');

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);

test('state: put/get/patch/remove/all, persistence via journal and snapshot, torn line tolerated', () => {
  const dir = tmpDir('sentra-state-');
  try {
    let st = createState({ dir, log: quietLog });
    const c = st.collection('things');
    c.put({ id: 'a', v: 1, nested: { x: [1] } });
    c.put({ id: 'b', v: 2 });
    const p = c.patch('a', (o) => { o.v = 10; o.nested.x.push(2); });
    assert.equal(p.v, 10);
    assert.equal(c.patch('zzz', () => {}), null);
    assert.ok(c.remove('b'));
    assert.ok(!c.remove('b'));
    assert.equal(c.all().length, 1);
    assert.equal(c.all((o) => o.v > 100).length, 0);
    assert.throws(() => c.put({ v: 1 }), /needs obj.id/);
    assert.throws(() => st.collection('../evil'), /invalid collection name/);
    st.audit({ user: 'u1', action: 'test.write', target: 'a' });
    assert.equal(st.auditTail(5)[0].action, 'test.write');
    st.close();

    // reopen: journal replay
    st = createState({ dir, log: quietLog });
    assert.deepEqual(st.collection('things').get('a'), { id: 'a', v: 10, nested: { x: [1, 2] } });
    assert.equal(st.collection('things').get('b'), null);
    // snapshot compacts the journal; more writes after it are replayed on top
    st.collection('things').put({ id: 'c', v: 3 });
    st.snapshot();
    assert.equal(fs.readFileSync(path.join(dir, 'things.jsonl'), 'utf8'), '');
    st.collection('things').put({ id: 'd', v: 4 });
    st.close();
    fs.appendFileSync(path.join(dir, 'things.jsonl'), '{"op":"put","o":{"id":"torn"'); // crash mid-write
    st = createState({ dir, log: quietLog });
    assert.deepEqual(st.collection('things').all().map((o) => o.id).sort(), ['a', 'c', 'd']);
    const auditFiles = fs.readdirSync(dir).filter((f) => f.startsWith('audit-'));
    assert.equal(auditFiles.length, 1);
    assert.match(fs.readFileSync(path.join(dir, auditFiles[0]), 'utf8'), /test\.write/);
    st.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('state: automatic snapshot after snapshotEvery writes', () => {
  const dir = tmpDir('sentra-state-');
  try {
    const st = createState({ dir, snapshotEvery: 10, log: quietLog });
    const c = st.collection('x');
    for (let i = 0; i < 25; i++) c.put({ id: `k${i}`, i });
    const lines = fs.readFileSync(path.join(dir, 'x.jsonl'), 'utf8').split('\n').filter(Boolean);
    assert.equal(lines.length, 5);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'x.snap.json'), 'utf8')).items.length, 20);
    st.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

function setup(extra) {
  const dir = tmpDir('sentra-alerts-');
  const state = createState({ dir, log: quietLog });
  const ch = fakeCH();
  let now = T0;
  const changes = [];
  const alerts = createAlerts(Object.assign({ state, ch, log: quietLog, now: () => now, onChange: (a, k) => changes.push(k) }, extra || {}));
  return { dir, state, ch, alerts, changes, setNow: (t) => { now = t; }, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const partial = (o) => Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force', severity: 3, mitre: ['T1110.001'], group: { user: 'alice' }, group_key: 'alice',
  count: 10, ts_first: T0 - 60000, ts_last: T0 - 1000, sample_event_ids: ['e1', 'e2'], summary: 'Brute force — user=alice (10 events)', suppress_s: 3600, source: 'engine', src_type: 'windows', src_id: 'dc01', host: 'dc01' }, o);

test('alerts: raise creates ARCH-shaped alert; dedupe merges into open alert within window', () => {
  const s = setup();
  try {
    const r1 = s.alerts.raise(partial());
    assert.ok(r1.created);
    const a = r1.alert;
    assert.match(a.id, /^ALR-\d{7}$/);
    for (const k of ['id', 'rule_id', 'rule_name', 'severity', 'mitre', 'ts_first', 'ts_last', 'count', 'group', 'sample_event_ids', 'summary', 'status', 'assignee', 'case_id', 'notes', 'history']) assert.ok(k in a, k);
    assert.equal(a.status, 'new');
    assert.equal(a.history[0].action, 'created');
    const r2 = s.alerts.raise(partial({ count: 5, ts_first: T0, ts_last: T0 + 5000, sample_event_ids: ['e2', 'e3'], severity: 4 }));
    assert.ok(!r2.created);
    assert.equal(r2.alert.id, a.id);
    assert.equal(r2.alert.count, 15);
    assert.equal(r2.alert.ts_first, T0 - 60000);
    assert.equal(r2.alert.ts_last, T0 + 5000);
    assert.deepEqual(r2.alert.sample_event_ids, ['e1', 'e2', 'e3']);
    assert.equal(r2.alert.severity, 4, 'severity escalates');
    // outside the suppress window → new alert
    const r3 = s.alerts.raise(partial({ ts_first: T0 + 2 * 3600000, ts_last: T0 + 2 * 3600000 }));
    assert.ok(r3.created);
    // update partials always merge into the open alert
    const r4 = s.alerts.raise(partial({ update: true, count: 7, ts_first: T0 + 9 * 3600000, ts_last: T0 + 9 * 3600000 }));
    assert.equal(r4.alert.id, r3.alert.id);
    assert.equal(r4.alert.count, 17);
    // other group → separate alert
    assert.ok(s.alerts.raise(partial({ group: { user: 'bob' }, group_key: 'bob' })).created);
    // closed alerts are not merged into
    s.alerts.close(r3.alert.id, 'benign', 'ana');
    assert.ok(s.alerts.raise(partial({ ts_first: T0 + 9 * 3600000 + 1, ts_last: T0 + 9 * 3600000 + 1 })).created);
    assert.deepEqual(s.alerts.stats().created, 4);
    assert.ok(s.changes.includes('created') && s.changes.includes('merged'));
  } finally { s.done(); }
});

test('alerts: workflow transitions, ack auto-assigns, notes, close reasons, reopen, history', () => {
  const s = setup();
  try {
    const { alert } = s.alerts.raise(partial());
    const acked = s.alerts.ack(alert.id, 'ana');
    assert.equal(acked.status, 'acknowledged');
    assert.equal(acked.assignee, 'ana');
    assert.equal(acked.ack_at, T0);
    assert.throws(() => s.alerts.setStatus(alert.id, 'new', 'ana'), (e) => e.code === 409);
    assert.throws(() => s.alerts.setStatus(alert.id, 'bogus', 'ana'), (e) => e.code === 400);
    s.alerts.setStatus(alert.id, 'in-progress', 'ana');
    s.alerts.note(alert.id, 'checked source IP — internal scanner', 'ana');
    assert.throws(() => s.alerts.note(alert.id, '   ', 'ana'), (e) => e.code === 400);
    assert.throws(() => s.alerts.close(alert.id, 'maybe', 'ana'), (e) => e.code === 400);
    s.setNow(T0 + 3600000);
    const closed = s.alerts.close(alert.id, 'false-positive', 'ana', 'scanner allow-listed');
    assert.equal(closed.status, 'closed-false-positive');
    assert.equal(closed.closure_reason, 'false-positive');
    assert.equal(closed.closed_at, T0 + 3600000);
    assert.equal(closed.notes.length, 2);
    assert.throws(() => s.alerts.ack(alert.id + 'x', 'ana'), (e) => e.code === 404);
    const re = s.alerts.reopen(alert.id, 'lead');
    assert.equal(re.status, 'in-progress');
    assert.equal(re.closed_at, 0);
    const actions = re.history.map((h) => h.action);
    assert.deepEqual(actions, ['created', 'status', 'assign', 'status', 'note', 'note', 'status', 'status']);
  } finally { s.done(); }
});

test('alerts: bulk ops and list filters (portal parameters)', () => {
  const s = setup();
  try {
    const ids = [];
    for (let i = 0; i < 6; i++) ids.push(s.alerts.raise(partial({ group: { user: `u${i}` }, group_key: `u${i}`, severity: i % 5, ts_first: T0 + i * 1000, ts_last: T0 + i * 1000, rule_id: i < 3 ? 'R-A' : 'R-B' })).alert.id);
    s.alerts.raise(partial({ source: 'logrhythm', group_key: 'lr:1', rule_id: 'LR-1' }));
    const b = s.alerts.bulk(ids.slice(0, 3), 'assign', { assignee: 'ana' }, 'lead');
    assert.equal(b.ok, 3);
    const c = s.alerts.bulk([ids[3], 'ALR-9999999'], 'close', { reason: 'true-positive', note: 'confirmed' }, 'lead');
    assert.equal(c.ok, 1);
    assert.equal(c.failed, 1);
    assert.throws(() => s.alerts.bulk(ids, 'explode', {}, 'x'), (e) => e.code === 400);
    assert.equal(s.alerts.list({}).total, 6, 'LogRhythm alerts hidden by default');
    assert.equal(s.alerts.list({ source: 'logrhythm' }).total, 1);
    assert.equal(s.alerts.list({ status: 'open' }).total, 5);
    assert.equal(s.alerts.list({ status: 'closed' }).total, 1);
    assert.equal(s.alerts.list({ status: 'all' }).total, 6);
    assert.equal(s.alerts.list({ status: 'new,closed-true-positive' }).total, 6);
    assert.equal(s.alerts.list({ min_severity: '3' }).total, 2);
    assert.equal(s.alerts.list({ rule_id: 'R-A' }).total, 3);
    assert.equal(s.alerts.list({ assignee: 'ana' }).total, 3);
    assert.equal(s.alerts.list({ unassigned: '1' }).total, 3);
    assert.equal(s.alerts.list({ from: new Date(T0 + 3500).toISOString() }).total, 2);
    assert.equal(s.alerts.list({ q: 'u5' }).total, 1);
    const page = s.alerts.list({ limit: 2, offset: 1, sort: 'ts_first' });
    assert.equal(page.items.length, 2);
    assert.equal(page.items[0].ts_first, T0 + 1000);
    assert.throws(() => s.alerts.list({ from: 'yesterday-ish' }), (e) => e.code === 400);
  } finally { s.done(); }
});

test('alerts: ClickHouse mirror (core siem.alerts columns), retry on failure; state survives restart', async () => {
  const s = setup({ mirrorMs: 3600000 });
  try {
    const { alert } = s.alerts.raise(partial());
    s.alerts.ack(alert.id, 'ana');
    s.ch.setFailing(true);
    assert.equal(await s.alerts.flushMirror(), 0);
    assert.equal(s.alerts.stats().mirror_queue, 1);
    s.ch.setFailing(false);
    assert.equal(await s.alerts.flushMirror(), 1);
    const row = s.ch.inserts[0].rows[0];
    assert.equal(s.ch.inserts[0].table, 'siem.alerts');
    assert.deepEqual(Object.keys(row).sort(), ['assignee', 'group_json', 'id', 'mitre', 'rule_id', 'rule_name', 'severity', 'status', 'summary', 'ts_first', 'ts_last', 'updated'].sort());
    assert.equal(row.status, 'acknowledged');
    assert.match(row.ts_first, /^2026-09-29 09:59:00\.000$/);
    assert.deepEqual(JSON.parse(row.group_json), { user: 'alice' });
    // restart: open-alert index rebuilt, ids continue
    s.alerts.stop();
    const again = createAlerts({ state: s.state, log: quietLog, now: () => T0 + 1000 });
    const r = again.raise(partial({ ts_first: T0 + 500, ts_last: T0 + 600 }));
    assert.equal(r.created, false);
    assert.equal(r.alert.id, alert.id);
    assert.ok(again.raise(partial({ group_key: 'new', group: { user: 'new' } })).alert.id > alert.id);
    again.stop();
  } finally { s.done(); }
});

test('state: auditSince reads the monthly journals, survives a restart, filters and reports capping', () => {
  const dir = tmpDir('sentra-audit-');
  try {
    const now = Date.now(), lastMonth = now - 40 * 864e5;
    let st = createState({ dir, log: quietLog });
    st.audit({ at: lastMonth, by: 'a', action: 'netops.device.put' });
    st.audit({ at: now - 1000, by: 'b', action: 'access.denied' });
    st.audit({ at: now - 500, by: 'c', action: 'netops.change.approved' });
    st.close();
    st = createState({ dir, log: quietLog });            // restart: the in-memory ring is empty
    assert.equal(st.auditTail(10).length, 0);
    let r = st.auditSince(now - 50 * 864e5);
    assert.deepEqual(r.items.map((e) => e.by), ['c', 'b', 'a'], 'newest first, across month files');
    assert.equal(r.capped, false);
    assert.deepEqual(st.auditSince(now - 864e5).items.map((e) => e.by), ['c', 'b'], 'period respected');
    assert.deepEqual(st.auditSince(0, 10, (e) => e.action.startsWith('netops')).items.map((e) => e.by), ['c', 'a'], 'filter');
    r = st.auditSince(0, 2); assert.equal(r.items.length, 2); assert.equal(r.capped, true, 'capped is reported');
    st.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
