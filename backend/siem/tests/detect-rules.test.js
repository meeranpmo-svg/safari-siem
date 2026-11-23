// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Built-in rule pack: every real-time rule has a synthetic positive fixture that fires and a negative that does not.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDetector, compileRule } = require('../engine/detect/engine');
const { createIntel } = require('../engine/detect/intel');
const { loadBuiltinRules } = require('../engine/detect/ruleset');
const { FIXTURES, INTEL, T0 } = require('./detect-fixtures');

const rules = loadBuiltinRules();
const realtime = rules.filter((r) => r.type !== 'scheduled');

function intel() {
  const i = createIntel({ watch: false });
  i.add('test-domains', INTEL.domains);
  i.add('test-ips', INTEL.ips);
  i.add('test-hashes', INTEL.hashes);
  for (const [name, values] of Object.entries(INTEL.lists || {})) i.add(name, values);
  return i;
}

function run(rule, events) {
  const alerts = [];
  const det = createDetector({ rules: [rule], onAlert: (a) => alerts.push(a), intel: intel(), now: () => T0 });
  for (const e of events) det.onEvent(e);
  const st = det.stats();
  assert.equal(st.errors, 0, `${rule.id}: evaluation errors`);
  return alerts.filter((a) => !a.update);
}

test('rule pack: ~40+ rules, unique ids, required metadata, all compile', () => {
  assert.ok(realtime.length >= 40, `expected >= 40 real-time rules, got ${realtime.length}`);
  const ids = new Set();
  for (const r of rules) {
    assert.ok(!ids.has(r.id), `duplicate id ${r.id}`); ids.add(r.id);
    assert.match(r.id, /^SENTRA-[A-Z0-9]+-\d{3}$/);
    assert.ok(r.name && r.description && r.description.length > 10, `${r.id}: name/description`);
    assert.ok(Array.isArray(r.mitre) && r.mitre.length && r.mitre.every((m) => /^T\d{4}(\.\d{3})?$/.test(m)), `${r.id}: mitre ids`);
    assert.ok(r.tactic, `${r.id}: tactic`);
    assert.ok(r.severity >= 0 && r.severity <= 4, `${r.id}: severity`);
    if (r.type !== 'scheduled') compileRule(r);
  }
});

// rules whose fixtures are still to be written (tests/fixtures-pending.json): listed explicitly, never silently skipped
const PENDING = new Set(require('./fixtures-pending.json').rules);

test('every real-time rule has fixtures (or is listed in fixtures-pending.json)', () => {
  const missing = realtime.filter((r) => !FIXTURES[r.id]).map((r) => r.id);
  assert.deepEqual(missing.sort(), [...PENDING].sort(), 'fixtures-pending.json must list exactly the rules without fixtures');
  const extra = Object.keys(FIXTURES).filter((id) => !realtime.some((r) => r.id === id));
  assert.deepEqual(extra, []);
});

for (const rule of realtime) {
  test(`${rule.id} ${rule.name}: fires on positive, silent on negative`, { skip: PENDING.has(rule.id) && 'fixture pending (tests/fixtures-pending.json)' }, () => {
    const fx = FIXTURES[rule.id];
    assert.ok(fx, 'fixture missing');
    const pos = run(rule, fx.pos);
    assert.ok(pos.length >= 1, `${rule.id} did not fire on its positive fixture`);
    for (const a of pos) {
      assert.equal(a.rule_id, rule.id);
      assert.ok(a.summary.startsWith(rule.name));
      assert.ok(a.sample_event_ids.length >= 1 && a.sample_event_ids.length <= 20);
      assert.ok(a.ts_first <= a.ts_last);
    }
    const neg = run(rule, fx.neg);
    assert.equal(neg.length, 0, `${rule.id} fired on its negative fixture: ${neg.map((a) => a.summary).join(' | ')}`);
  });
}

test('whole pack over all fixtures: no evaluation errors, every rule fires somewhere', () => {
  const alerts = [];
  const det = createDetector({ rules, onAlert: (a) => alerts.push(a), intel: intel(), now: () => T0 });
  const all = Object.values(FIXTURES).flatMap((f) => f.pos.concat(f.neg)).sort((a, b) => a.ts - b.ts);
  for (const e of all) det.onEvent(e);
  const st = det.stats();
  assert.equal(st.errors, 0);
  assert.equal(st.rules_loaded, realtime.filter((r) => r.enabled !== false).length);
  const fired = new Set(alerts.map((a) => a.rule_id));
  const silent = realtime.filter((r) => !fired.has(r.id) && !PENDING.has(r.id)).map((r) => r.id);
  assert.deepEqual(silent, []);
});
