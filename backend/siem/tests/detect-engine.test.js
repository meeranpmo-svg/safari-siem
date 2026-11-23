// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDetector, compileRule, compileMatch, indexKeyOf } = require('../engine/detect/engine');
const { parseIP, createCidrSet, isPrivate } = require('../engine/detect/ip');

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);
let n = 0;
const ev = (o) => Object.assign({ id: `e${++n}`, ts: T0, src_type: 'windows', action: '', user: '', src_ip: '', fields: {}, tags: [] }, o);
const m = (match, e) => compileMatch(match, { intel: null, tzOffsetMin: 180 })(e);

function det(rules, extra) {
  const alerts = [];
  let wall = T0;
  const d = createDetector(Object.assign({ rules, onAlert: (a) => alerts.push(a), now: () => wall }, extra || {}));
  return { d, alerts, setNow: (t) => { wall = t; }, fresh: () => alerts.filter((a) => !a.update) };
}

test('ip helpers: IPv4, IPv6, mapped, CIDR sets, private ranges', () => {
  assert.deepEqual(parseIP('10.1.2.3'), { v: 4, n: 167838211 });
  assert.equal(parseIP('256.1.1.1'), null);
  assert.equal(parseIP('1.2.3'), null);
  assert.equal(parseIP('::ffff:10.0.0.1').v, 4);
  assert.equal(parseIP('2001:db8::1').v, 6);
  assert.equal(parseIP('[2001:db8::1]').v, 6);
  assert.equal(parseIP('fe80::1%eth0').v, 6);
  assert.equal(parseIP('2001:db8::1::2'), null);
  assert.equal(parseIP('not-an-ip'), null);
  const s = createCidrSet(['10.0.0.0/8', '192.168.1.0/24', '2001:db8::/32', '203.0.113.7']);
  assert.ok(s.has('10.255.1.1'));
  assert.ok(s.has('192.168.1.200'));
  assert.ok(!s.has('192.168.2.1'));
  assert.ok(s.has('2001:db8:abcd::5'));
  assert.ok(!s.has('2001:db9::5'));
  assert.ok(s.has('203.0.113.7'));
  assert.ok(!s.has('203.0.113.8'));
  assert.ok(s.has('::ffff:10.9.9.9'));
  assert.throws(() => createCidrSet(['10.0.0.0/33']));
  assert.ok(isPrivate('172.20.1.1') && isPrivate('fd00::1') && !isPrivate('8.8.8.8'));
});

test('ops: eq/neq/in case-insensitive, numbers, arrays, missing fields', () => {
  const e = ev({ action: 'Logon-Failed', user: 'Alice', http_status: 404, tags: ['admin', 'rdp'] });
  assert.ok(m({ field: 'action', op: 'eq', value: 'logon-failed' }, e));
  assert.ok(m({ field: 'user', op: 'in', value: ['bob', 'ALICE'] }, e));
  assert.ok(m({ field: 'http_status', op: 'eq', value: '404' }, e));
  assert.ok(m({ field: 'http_status', op: 'eq', value: 404 }, e));
  assert.ok(m({ field: 'user', op: 'neq', value: 'bob' }, e));
  assert.ok(!m({ field: 'user', op: 'neq', value: 'alice' }, e));
  assert.ok(m({ field: 'tags', op: 'eq', value: 'rdp' }, e), 'array field matches any element');
  assert.ok(m({ field: 'missing', op: 'eq', value: '' }, e));
  assert.ok(m({ field: 'missing', op: 'neq', value: 'x' }, e));
});

test('ops: contains/startswith/endswith/re (compiled once, case-insensitive)', () => {
  const e = ev({ cmdline: 'C:\\Windows\\System32\\CMD.exe /c whoami' });
  assert.ok(m({ field: 'cmdline', op: 'contains', value: 'cmd.EXE' }, e));
  assert.ok(m({ field: 'cmdline', op: 'contains', value: ['nope', 'WHOAMI'] }, e));
  assert.ok(m({ field: 'cmdline', op: 'startswith', value: 'c:\\windows' }, e));
  assert.ok(m({ field: 'cmdline', op: 'endswith', value: 'WHOAMI' }, e));
  assert.ok(m({ field: 'cmdline', op: 're', value: 'cmd\\.exe\\s+/c' }, e));
  assert.ok(!m({ field: 'cmdline', op: 're', value: '^powershell' }, e));
  assert.throws(() => compileRule({ id: 'X-1', name: 'x', match: { all: [{ field: 'cmdline', op: 're', value: '(' }] } }), /invalid regex/);
});

test('ops: exists / gt / gte / lt / lte / fields.<key> / Map fields', () => {
  const e = ev({ dst_port: 0, src_port: 443, fields: { sentbyte: '2048', 'status.errorCode': '500121' } });
  assert.ok(m({ field: 'src_port', op: 'exists', value: true }, e));
  assert.ok(m({ field: 'dst_port', op: 'exists', value: false }, e), '0 counts as absent');
  assert.ok(m({ field: 'fields.sentbyte', op: 'gt', value: 1024 }, e));
  assert.ok(m({ field: 'fields.sentbyte', op: 'gte', value: 2048 }, e));
  assert.ok(!m({ field: 'fields.sentbyte', op: 'lt', value: 2048 }, e));
  assert.ok(m({ field: 'fields.sentbyte', op: 'lte', value: 2048 }, e));
  assert.ok(!m({ field: 'fields.nothing', op: 'gt', value: -1 }, e), 'missing never compares');
  assert.ok(m({ field: 'fields.status.errorCode', op: 'eq', value: '500121' }, e), 'dotted keys inside fields');
  const em = ev({ fields: new Map([['k', 'v']]) });
  assert.ok(m({ field: 'fields.k', op: 'eq', value: 'v' }, em));
  assert.throws(() => compileRule({ id: 'X-2', name: 'x', match: { all: [{ field: 'a.b', op: 'eq', value: 1 }] } }), /invalid field path/);
  assert.throws(() => compileRule({ id: 'X-3', name: 'x', match: { all: [{ field: 'a', op: 'gt', value: 'abc' }] } }), /numeric/);
  assert.throws(() => compileRule({ id: 'X-4', name: 'x', match: { all: [{ field: 'a', op: 'like', value: 'abc' }] } }), /unknown op/);
});

test('ops: cidr (v4 + v6) and intel', () => {
  const r = { field: 'src_ip', op: 'cidr', value: ['10.0.0.0/8', 'fc00::/7'] };
  assert.ok(m(r, ev({ src_ip: '10.4.5.6' })));
  assert.ok(m(r, ev({ src_ip: 'fd12::1' })));
  assert.ok(!m(r, ev({ src_ip: '11.0.0.1' })));
  assert.ok(!m(r, ev({ src_ip: '' })));
  const intel = { match: (list, v) => list === 'ip' && v === '6.6.6.6' };
  const f = compileMatch({ field: 'dst_ip', op: 'intel', value: 'ip' }, { intel, tzOffsetMin: 180 });
  assert.ok(f(ev({ dst_ip: '6.6.6.6' })));
  assert.ok(!f(ev({ dst_ip: '7.7.7.7' })));
  assert.ok(!compileMatch({ field: 'dst_ip', op: 'intel', value: 'ip' }, { intel: null })(ev({ dst_ip: '6.6.6.6' })));
});

test('ops: hour_between / weekday_in (Asia/Riyadh default), wrap-around', () => {
  const night = ev({ ts: Date.UTC(2026, 8, 29, 20, 0) });   // 23:00 Riyadh Tue
  const day = ev({ ts: Date.UTC(2026, 8, 29, 10, 0) });     // 13:00 Riyadh Tue
  const fri = ev({ ts: Date.UTC(2026, 9, 2, 10, 0) });      // Fri
  const off = { field: 'ts', op: 'hour_between', value: [19, 7] };
  assert.ok(m(off, night));
  assert.ok(!m(off, day));
  assert.ok(m({ op: 'hour_between', value: [9, 17] }, day), 'field defaults to ts');
  assert.ok(m({ op: 'hour_between', value: [10, 11], tz_offset_min: 0 }, day), 'explicit UTC');
  assert.ok(m({ op: 'weekday_in', value: [5, 6] }, fri));
  assert.ok(!m({ op: 'weekday_in', value: [5, 6] }, day));
  assert.throws(() => compileRule({ id: 'X-5', name: 'x', match: { all: [{ op: 'hour_between', value: [25, 3] }] } }));
});

test('match groups: all/any/none, nesting, not', () => {
  const e = ev({ action: 'logon', outcome: 'success', user: 'bob' });
  assert.ok(m({ all: [{ field: 'action', op: 'eq', value: 'logon' }], any: [{ field: 'user', op: 'eq', value: 'x' }, { field: 'user', op: 'eq', value: 'bob' }], none: [{ field: 'outcome', op: 'eq', value: 'failure' }] }, e));
  assert.ok(!m({ all: [{ field: 'action', op: 'eq', value: 'logon' }], none: [{ field: 'user', op: 'eq', value: 'bob' }] }, e));
  assert.ok(m({ all: [{ any: [{ all: [{ field: 'user', op: 'eq', value: 'bob' }, { field: 'outcome', op: 'eq', value: 'success' }] }, { field: 'user', op: 'eq', value: 'z' }] }] }, e));
  assert.ok(m({ field: 'user', op: 'eq', value: 'alice', not: true }, e));
  assert.throws(() => compileMatch({ all: [], any: [] }, {}), /empty match/);
  assert.throws(() => compileMatch({ foo: [] }, {}), /unknown match key/);
});

test('index key extraction picks the best mandatory eq/in condition', () => {
  assert.deepEqual(indexKeyOf({ all: [{ field: 'src_type', op: 'eq', value: 'windows' }, { field: 'event_code', op: 'in', value: ['4624', 4625] }] }), { field: 'event_code', values: ['4624', '4625'] });
  assert.equal(indexKeyOf({ any: [{ field: 'action', op: 'eq', value: 'x' }] }), null);
  assert.equal(indexKeyOf({ all: [{ field: 'action', op: 'eq', value: 'x', not: true }] }), null);
  assert.deepEqual(indexKeyOf({ all: [{ all: [{ field: 'action', op: 'eq', value: 'X' }] }] }), { field: 'action', values: ['x'] });
});

test('single rule: alert partial shape, fields_in_alert, summary, suppression per group', () => {
  const rule = { id: 'T-1', name: 'Audit log cleared', severity: 4, mitre: ['T1685.005'], type: 'single', match: { all: [{ field: 'event_code', op: 'eq', value: '1102' }] }, group_by: ['host'], suppress_s: 600, fields_in_alert: ['host', 'user'] };
  const { d, alerts, fresh } = det([rule]);
  d.onEvent(ev({ event_code: '1102', host: 'dc01', user: 'mallory' }));
  d.onEvent(ev({ event_code: '1102', host: 'dc01', user: 'mallory', ts: T0 + 1000 }));
  d.onEvent(ev({ event_code: '1102', host: 'dc02', user: 'x', ts: T0 + 2000 }));
  d.onEvent(ev({ event_code: '1102', host: 'dc01', ts: T0 + 700000 }));
  const a = fresh();
  assert.equal(a.length, 3);
  assert.equal(a[0].rule_id, 'T-1');
  assert.equal(a[0].severity, 4);
  assert.deepEqual(a[0].mitre, ['T1685.005']);
  assert.deepEqual(a[0].group, { host: 'dc01' });
  assert.deepEqual(a[0].fields, { host: 'dc01', user: 'mallory' });
  assert.equal(a[0].count, 1);
  assert.match(a[0].summary, /^Audit log cleared — host=dc01 \(1 event\)$/);
  // the suppressed second event is reported as an update partial before the post-expiry alert
  const upd = alerts.filter((x) => x.update);
  assert.equal(upd.length, 1);
  assert.equal(upd[0].count, 1);
  assert.equal(d.stats().rules[0].suppressed, 1);
});

test('suppressed detections are flushed as one update partial on tick()/flush()', () => {
  const rule = { id: 'T-2', name: 'x', type: 'single', match: { all: [{ field: 'action', op: 'eq', value: 'ips-detection' }] }, group_by: ['src_ip'], suppress_s: 60 };
  const { d, alerts, setNow } = det([rule]);
  for (let i = 0; i < 50; i++) d.onEvent(ev({ action: 'ips-detection', src_ip: '1.2.3.4', ts: T0 + i * 100 }));
  assert.equal(alerts.length, 1);
  setNow(T0 + 30000); d.tick(T0 + 30000);
  assert.equal(alerts.length, 1, 'not yet expired');
  setNow(T0 + 61000); d.tick(T0 + 61000);
  assert.equal(alerts.length, 2);
  assert.equal(alerts[1].update, true);
  assert.equal(alerts[1].count, 49);
  assert.ok(alerts[1].sample_event_ids.length <= 20);
  d.flush();
  assert.equal(alerts.length, 2, 'nothing pending');
});

test('threshold: sliding window per group, resets after firing, skip empty group', () => {
  const rule = { id: 'T-3', name: 'Brute', type: 'threshold', match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }] }, group_by: ['user'], window_s: 60, count: 5, suppress_s: 0 };
  const { d, fresh } = det([rule]);
  for (let i = 0; i < 4; i++) d.onEvent(ev({ action: 'logon-failed', user: 'a', ts: T0 + i * 20000 })); // spread over 60 s: never 5 in window
  d.onEvent(ev({ action: 'logon-failed', user: 'a', ts: T0 + 100000 }));
  assert.equal(fresh().length, 0);
  for (let i = 0; i < 5; i++) d.onEvent(ev({ action: 'logon-failed', user: 'b', ts: T0 + i * 1000 }));
  assert.equal(fresh().length, 1);
  const a = fresh()[0];
  assert.equal(a.count, 5);
  assert.equal(a.ts_first, T0);
  assert.equal(a.ts_last, T0 + 4000);
  assert.equal(a.sample_event_ids.length, 5);
  assert.match(a.summary, /within 1m/);
  for (let i = 0; i < 4; i++) d.onEvent(ev({ action: 'logon-failed', user: 'b', ts: T0 + 5000 + i }));
  assert.equal(fresh().length, 1, 'state reset after firing');
  for (let i = 0; i < 10; i++) d.onEvent(ev({ action: 'logon-failed', user: '', ts: T0 + i }));
  assert.equal(fresh().length, 1, 'empty group values are not aggregated');
});

test('threshold with sum_field / sum_gt (bucketed)', () => {
  const rule = { id: 'T-4', name: 'Exfil', type: 'threshold', match: { all: [{ field: 'category', op: 'eq', value: 'network' }] }, group_by: ['src_ip', 'dst_ip'], window_s: 3600, sum_field: 'fields.sentbyte', sum_gt: 1000, suppress_s: 0 };
  const { d, fresh } = det([rule]);
  d.onEvent(ev({ category: 'network', src_ip: '10.0.0.1', dst_ip: '8.8.8.8', fields: { sentbyte: '600' } }));
  d.onEvent(ev({ category: 'network', src_ip: '10.0.0.1', dst_ip: '8.8.4.4', fields: { sentbyte: '600' }, ts: T0 + 1 }));
  assert.equal(fresh().length, 0);
  d.onEvent(ev({ category: 'network', src_ip: '10.0.0.1', dst_ip: '8.8.8.8', fields: { sentbyte: '500' }, ts: T0 + 60000 }));
  assert.equal(fresh().length, 1);
  assert.equal(fresh()[0].sum, 1100);
  assert.equal(fresh()[0].count, 2);
  // old volume slides out of the window
  d.onEvent(ev({ category: 'network', src_ip: '10.0.0.2', dst_ip: '8.8.8.8', fields: { sentbyte: '900' }, ts: T0 }));
  d.onEvent(ev({ category: 'network', src_ip: '10.0.0.2', dst_ip: '8.8.8.8', fields: { sentbyte: '900' }, ts: T0 + 2 * 3600000 }));
  assert.equal(fresh().length, 1);
  assert.throws(() => compileRule({ id: 'T-4b', name: 'x', type: 'threshold', match: { all: [{ field: 'a', op: 'exists', value: true }] }, sum_field: 'fields.x' }), /sum_gt/);
});

test('distinct: many values of a field per group within window', () => {
  const rule = { id: 'T-5', name: 'Spray', type: 'distinct', match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }] }, group_by: ['src_ip'], distinct_field: 'user', distinct_count: 3, window_s: 60, suppress_s: 0 };
  const { d, fresh } = det([rule]);
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'a' }));
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'A' }));   // same value (case-insensitive)
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'b', ts: T0 + 1000 }));
  assert.equal(fresh().length, 0);
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'c', ts: T0 + 120000 })); // 'a','b' expired
  assert.equal(fresh().length, 0);
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'd', ts: T0 + 121000 }));
  d.onEvent(ev({ action: 'logon-failed', src_ip: '1.1.1.1', user: 'e', ts: T0 + 122000 }));
  assert.equal(fresh().length, 1);
  assert.deepEqual(fresh()[0].distinct_values.sort(), ['c', 'd', 'e']);
  assert.equal(fresh()[0].count, 3);
});

test('sequence: ordered steps with counts, same by-key, window expiry', () => {
  const rule = {
    id: 'T-6', name: 'Fail then success', type: 'sequence', by: ['user'], window_s: 300, suppress_s: 0,
    steps: [{ match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }] }, count: 3 }, { match: { all: [{ field: 'action', op: 'eq', value: 'logon' }] } }],
  };
  const { d, fresh } = det([rule]);
  d.onEvent(ev({ action: 'logon', user: 'x' }));                                   // success first: nothing
  for (let i = 0; i < 3; i++) d.onEvent(ev({ action: 'logon-failed', user: 'x', ts: T0 + i * 1000 }));
  d.onEvent(ev({ action: 'logon', user: 'y', ts: T0 + 5000 }));                     // different user
  assert.equal(fresh().length, 0);
  d.onEvent(ev({ action: 'logon', user: 'x', ts: T0 + 6000 }));
  assert.equal(fresh().length, 1);
  assert.equal(fresh()[0].count, 4);
  assert.equal(fresh()[0].ts_first, T0);
  assert.equal(fresh()[0].steps, 2);
  // window expiry: failures, then success too late
  for (let i = 0; i < 3; i++) d.onEvent(ev({ action: 'logon-failed', user: 'z', ts: T0 + i * 1000 }));
  d.onEvent(ev({ action: 'logon', user: 'z', ts: T0 + 400000 }));
  assert.equal(fresh().length, 1);
  assert.throws(() => compileRule({ id: 'T-6b', name: 'x', type: 'sequence', steps: [{ match: { all: [{ field: 'a', op: 'eq', value: 1 }] } }] }), /at least 2 steps/);
});

test('new_value: learns during learn_s, then alerts once per new value; state export/import', () => {
  const rule = { id: 'T-7', name: 'New admin source', type: 'new_value', match: { all: [{ field: 'action', op: 'eq', value: 'logon' }] }, group_by: ['user'], new_field: 'src_ip', learn_s: 3600, suppress_s: 0 };
  const { d, fresh } = det([rule]);
  d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.1' }));
  d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.2', ts: T0 + 60000 }));  // still learning
  d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.1', ts: T0 + 7200000 }));
  assert.equal(fresh().length, 0);
  d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.3', ts: T0 + 7300000 }));
  d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.3', ts: T0 + 7400000 }));
  assert.equal(fresh().length, 1);
  assert.equal(fresh()[0].new_value, '10.0.0.3');
  const snap = JSON.parse(JSON.stringify(d.exportState()));
  const b = det([rule]);
  assert.equal(b.d.importState(snap), 1);
  b.d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.2', ts: T0 + 8000000 }));
  b.d.onEvent(ev({ action: 'logon', user: 'adm', src_ip: '10.0.0.9', ts: T0 + 8000001 }));
  assert.equal(b.fresh().length, 1, 'baseline restored, only the new value alerts');
});

test('memory bound: max groups per rule with LRU eviction; tick() expires idle state', () => {
  const rule = { id: 'T-8', name: 'x', type: 'threshold', match: { all: [{ field: 'action', op: 'eq', value: 'a' }] }, group_by: ['user'], window_s: 60, count: 1000 };
  const { d, setNow } = det([rule], { maxGroups: 100 });
  for (let i = 0; i < 1000; i++) d.onEvent(ev({ action: 'a', user: `u${i}` }));
  let s = d.stats().rules[0];
  assert.equal(s.groups, 100);
  assert.equal(s.evicted, 900);
  setNow(T0 + 5 * 60000);
  const r = d.tick(T0 + 5 * 60000);
  assert.equal(r.expired, 100);
  s = d.stats().rules[0];
  assert.equal(s.groups, 0);
});

test('stats per rule, errors isolated, disabled/scheduled/invalid rules on load', () => {
  const rules = [
    { id: 'T-9', name: 'ok', match: { all: [{ field: 'action', op: 'eq', value: 'x' }] } },
    { id: 'T-10', name: 'bad', match: { all: [{ field: 'action', op: 'nope', value: 'x' }] } },
    { id: 'T-11', name: 'off', enabled: false, match: { all: [{ field: 'action', op: 'eq', value: 'x' }] } },
    { id: 'T-12', name: 'sched', type: 'scheduled', query: 'a:b' },
    { id: 'T-13', name: 'throws', match: { all: [{ field: 'action', op: 'eq', value: 'x' }] }, group_by: ['boom'] },
  ];
  const { d, alerts } = det(rules, { timingSample: 1 });
  const s0 = d.stats();
  assert.equal(s0.rules_loaded, 2);
  assert.equal(s0.load_errors.length, 1);
  assert.match(s0.load_errors[0].error, /unknown op/);
  const bad = ev({ action: 'x' });
  Object.defineProperty(bad, 'boom', { get() { throw new Error('boom'); } });
  d.onEvent(bad);
  d.onEvent(ev({ action: 'x', host: 'h' }));
  d.onEvent(ev({ action: 'y' }));
  const st = d.stats();
  const r9 = st.rules.find((r) => r.id === 'T-9');
  const r13 = st.rules.find((r) => r.id === 'T-13');
  assert.equal(r9.evaluations, 2, 'indexed: only events with action x are evaluated');
  assert.equal(r9.matches, 2);
  assert.equal(r9.alerts, 1);
  assert.ok(r9.avg_us >= 0);
  assert.equal(r9.indexed, 'action');
  assert.equal(r13.errors, 1);
  assert.equal(st.errors, 1);
  assert.equal(st.events, 3);
  assert.ok(alerts.length >= 2);
});

test('load() keeps in-flight state for unchanged rules and resets changed ones', () => {
  const rule = { id: 'T-14', name: 'x', type: 'threshold', match: { all: [{ field: 'action', op: 'eq', value: 'a' }] }, group_by: ['user'], window_s: 60, count: 3, suppress_s: 0 };
  const { d, fresh } = det([rule]);
  d.onEvent(ev({ action: 'a', user: 'u' }));
  d.onEvent(ev({ action: 'a', user: 'u' }));
  d.load([JSON.parse(JSON.stringify(rule))]);
  d.onEvent(ev({ action: 'a', user: 'u' }));
  assert.equal(fresh().length, 1);
  d.onEvent(ev({ action: 'a', user: 'u' }));
  d.onEvent(ev({ action: 'a', user: 'u' }));
  d.load([Object.assign({}, rule, { count: 4 })]);
  d.onEvent(ev({ action: 'a', user: 'u' }));
  assert.equal(fresh().length, 1, 'changed rule restarted its state');
});

test('onAlert exceptions do not break detection; events without ts use rts / now', () => {
  let calls = 0;
  const d = createDetector({ rules: [{ id: 'T-15', name: 'x', suppress_s: 0, match: { all: [{ field: 'action', op: 'eq', value: 'a' }] } }], onAlert: () => { calls++; throw new Error('sink down'); }, now: () => T0 });
  d.onEvent({ id: '1', action: 'a' });
  d.onEvent({ id: '2', action: 'a', rts: T0 });
  d.onEvent(null);
  assert.equal(calls, 2);
  assert.equal(d.stats().errors, 2);
});

test('indexed and unindexed evaluation give identical results', () => {
  const idx = { id: 'T-16', name: 'i', suppress_s: 0, match: { all: [{ field: 'event_code', op: 'in', value: ['4625', '4771'] }, { field: 'user', op: 'startswith', value: 'a' }] } };
  const unidx = { id: 'T-17', name: 'u', suppress_s: 0, match: { all: [{ field: 'user', op: 'startswith', value: 'a' }, { any: [{ field: 'event_code', op: 'eq', value: '4625' }, { field: 'event_code', op: 'eq', value: '4771' }] }] } };
  const { d, fresh } = det([idx, unidx]);
  const codes = ['4625', '4771', '4624', 4625, ''];
  for (let i = 0; i < 200; i++) d.onEvent(ev({ event_code: codes[i % 5], user: i % 3 ? 'alice' : 'bob' }));
  const a = fresh();
  assert.equal(a.filter((x) => x.rule_id === 'T-16').length, a.filter((x) => x.rule_id === 'T-17').length);
  assert.ok(a.length > 0);
});

test('unsafe regexes are refused in rules and Sigma; long fields are capped', () => {
  const { checkRegex } = require('../engine/detect/saferegex');
  for (const bad of ['(a+)+$', '(\\w+\\s?)*$', '(.*a){3,}', '(x|y)\\1', 'a'.repeat(600)]) assert.throws(() => checkRegex(bad), Error, bad);
  // shapes the first check missed (security review): overlapping repeated alternatives, exact-count nesting, wildcard pile-ups
  for (const bad of ['^(a|a)*$', '(.*a){12}$', '.*.*.*.*.*x$', '(\\w|\\d)*$', '(a|ab)*$', '(a|)*$', '(\\w+){3}']) assert.throws(() => checkRegex(bad), Error, bad);
  for (const ok of ['(\\s|\\+|%20)*select', '.*foo.*bar', 'a.*b|c.*d|e.*f', '\\S+@\\S+\\.com$']) assert.doesNotThrow(() => checkRegex(ok), ok);
  // every built-in rule still loads
  const fsx = require('fs'), px = require('path'), D = px.join(__dirname, '../engine/detect/rules');
  const visit = (o) => { if (Array.isArray(o)) return o.forEach(visit); if (o && typeof o === 'object') { if (o.op === 're' && o.value !== undefined) for (const x of [].concat(o.value)) assert.doesNotThrow(() => checkRegex(x), x); for (const k in o) visit(o[k]); } };
  for (const f of fsx.readdirSync(D)) if (f.endsWith('.json')) visit(JSON.parse(fsx.readFileSync(px.join(D, f), 'utf8')));
  for (const ok of ['^cmd\\.exe$', '(?:powershell|pwsh)(\\.exe)?\\s+-enc', '[a-z]+@[a-z]+\\.com', '(ab)+', '(\\S*/)?bash']) assert.doesNotThrow(() => checkRegex(ok), ok);
  const { createDetector } = require('../engine/detect/engine');
  const refused = createDetector({ rules: [{ id: 'R1', name: 'r', type: 'single', match: { field: 'raw', op: 're', value: '(a+)+$' } }], onAlert() {}, log: { warn() {}, error() {}, info() {}, debug() {} } }).stats();
  assert.equal(refused.rules_loaded, 0);
  assert.match(refused.load_errors[0].error, /unsafe regex/);
  const { convertSigmaAll } = require('../engine/detect/sigma');
  const res = convertSigmaAll('title: t\nlogsource:\n  product: linux\ndetection:\n  sel:\n    CommandLine|re: \'(a+)+$\'\n  condition: sel\n')[0];
  assert.equal(res.ok, false);
  assert.match(res.errors.join(' '), /refused/);
  // a safe pattern on a huge attacker-controlled field returns quickly
  const hits = [];
  const det = createDetector({ rules: [{ id: 'R2', name: 'r', type: 'single', match: { field: 'raw', op: 're', value: 'x[a-z]*y$' } }], onAlert: (a) => hits.push(a) });
  const t0 = Date.now();
  det.onEvent({ ts: Date.now(), raw: 'x' + 'a'.repeat(5 * 1024 * 1024), fields: {} });
  assert.ok(Date.now() - t0 < 1000);
});
