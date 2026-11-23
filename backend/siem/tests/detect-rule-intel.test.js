// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Alarm Rules Studio (engine/detect/rule-intel.js + GET /rules/intel, GET /rules/intel/:id, POST /rules/assist):
// false-positive rate withheld below 3 closures and benign never counted as a false positive, a proposed exclusion only when
// one entity is ≥ 60 % of the false positives, bursts against the rule's own history, silent / broken / noisy health,
// overlaps, ATT&CK gaps from the catalogue; roles (viewer reads, assist = operator and a person, refused for a viewer and a
// service identity), validation errors naming the field, the audit record, and the AI draft checked by the engine's compiler,
// always disabled, never stored. SYNTHETIC alerts and users only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createDetector } = require('../engine/detect/engine');
const detectRoutes = require('../engine/detect/routes');
const { createRuleIntel, robustZ } = require('../engine/detect/rule-intel');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

function setup(extra) {
  const dir = tmpDir('sentra-ruleintel-');
  const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const detector = createDetector({ rules: [], onAlert: (p) => alerts.raise(p), log: quietLog });
  const api = fakeApi(), audits = [];
  detectRoutes.register(api, Object.assign({ state, alerts, detector, config: { noisy_alerts_per_day: 2 }, log: quietLog, audit: (e) => audits.push(e) }, extra || {}));
  return { api, state, alerts, audits, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
function raiseClose(alerts, rule, user, reason, i) {
  const a = alerts.raise({ rule_id: rule, rule_name: rule, group: { user }, group_key: 'u=' + user + i, ts_first: Date.now(), ts_last: Date.now() });
  const id = a.id || (a.alert && a.alert.id);
  if (reason) alerts.close(id, reason, 'omar.syn');
  return id;
}

test('robustZ: withheld with too little history; a jump against a flat history is a burst', () => {
  assert.equal(robustZ([1, 2, 3], 9), null);
  assert.ok(robustZ([2, 2, 3, 2, 2, 3, 2, 2], 20) >= 4);
  assert.ok(Math.abs(robustZ([2, 2, 3, 2, 2, 3, 2, 2], 2)) < 1);
});

test('false-positive rate is withheld below 3 closures; benign never counts as a false positive; exclusion proposed at ≥ 60 %', async () => {
  const s = setup();
  try {
    raiseClose(s.alerts, 'SENTRA-AUTH-002', 'svc.syn', 'false-positive', 1); raiseClose(s.alerts, 'SENTRA-AUTH-002', 'svc.syn', 'false-positive', 2);
    let r = await s.api.call('GET', '/api/soc/rules/intel', { role: 'viewer' });
    assert.equal(r.status, 200);
    let x = r.body.items.find((i) => i.id === 'SENTRA-AUTH-002');
    assert.equal(x.fp_rate, null, 'two closures: no rate'); assert.equal(x.exclusion, null);
    for (let i = 0; i < 3; i++) raiseClose(s.alerts, 'SENTRA-AUTH-002', 'svc.syn', 'false-positive', 10 + i);
    raiseClose(s.alerts, 'SENTRA-AUTH-002', 'ali.syn', 'benign', 20); raiseClose(s.alerts, 'SENTRA-AUTH-002', 'ali.syn', 'true-positive', 21);
    r = await s.api.call('GET', '/api/soc/rules/intel', { role: 'viewer' });
    x = r.body.items.find((i) => i.id === 'SENTRA-AUTH-002');
    assert.deepEqual(x.closures, { tp: 1, fp: 5, benign: 1, open: 0, closed: 7 });
    assert.equal(x.fp_rate, 71, '5 false positives of 7 closures - the benign one is not a false positive');
    assert.equal(x.health, 'fp-heavy');
    assert.deepEqual([x.exclusion.field, x.exclusion.value, x.exclusion.pct], ['user', 'svc.syn', 100]);
    assert.ok(r.body.next.some((n) => n.kind === 'exclude' && n.rule === 'SENTRA-AUTH-002'), 'the exclusion is a next step');
    assert.match(r.body.note, /proposals - nothing here changes a rule/);
    // spread false positives: no single entity → no exclusion, a tune step instead
    for (let i = 0; i < 4; i++) raiseClose(s.alerts, 'SENTRA-AUTH-001', 'user' + i + '.syn', 'false-positive', 30 + i);
    r = await s.api.call('GET', '/api/soc/rules/intel', { role: 'viewer' });
    x = r.body.items.find((i) => i.id === 'SENTRA-AUTH-001');
    assert.equal(x.exclusion, null); assert.ok(r.body.next.some((n) => n.kind === 'tune' && n.rule === 'SENTRA-AUTH-001'));
  } finally { s.done(); }
});

test('health: silent, disabled and noisy rules; coverage is the catalogue (gap = nothing enabled); LogRhythm alerts are not this engine\'s', async () => {
  const s = setup();
  try {
    for (let i = 0; i < 20; i++) raiseClose(s.alerts, 'SENTRA-AUTH-001', 'u' + i + '.syn', null, i);
    s.alerts.raise({ rule_id: 'SENTRA-AUTH-002', rule_name: 'x', group_key: 'lr', source: 'logrhythm', ts_first: Date.now(), ts_last: Date.now() });
    const r = await s.api.call('GET', '/api/soc/rules/intel', { role: 'viewer' });
    const a1 = r.body.items.find((i) => i.id === 'SENTRA-AUTH-001'), a2 = r.body.items.find((i) => i.id === 'SENTRA-AUTH-002');
    assert.ok(a1.flags.includes('noisy') && a1.health === 'noisy'); assert.equal(a1.fires_7d, 20); assert.equal(a1.series.length, 30); assert.equal(a1.series[29], 20);
    assert.equal(a2.health, 'silent', 'the LogRhythm-imported alert does not count as this rule firing');
    assert.ok(r.body.counts.silent > 50); assert.equal(r.body.counts.total, r.body.items.length);
    const lat = r.body.coverage.find((c) => c.tactic === 'lateral-movement');
    assert.equal(lat.state, 'gap'); assert.ok(r.body.next.some((n) => n.kind === 'gap' && n.name === 'lateral-movement'));
    assert.equal(r.body.coverage.find((c) => c.tactic === 'credential-access').state, 'covered');
    assert.equal(r.body.items[0].id, 'SENTRA-AUTH-001', 'ranked by tuning priority');
    // disable a rule: it reads disabled and no longer covers its tactic count
    assert.equal((await s.api.call('POST', '/api/soc/rules/SENTRA-AUTH-002/disable', { role: 'admin', user: 'syed.syn', body: {} })).status, 200);
    const r2 = await s.api.call('GET', '/api/soc/rules/intel', { role: 'viewer' });
    assert.equal(r2.body.items.find((i) => i.id === 'SENTRA-AUTH-002').health, 'disabled');
    assert.equal(r2.body.coverage.find((c) => c.tactic === 'credential-access').rules, r.body.coverage.find((c) => c.tactic === 'credential-access').rules - 1);
  } finally { s.done(); }
});

test('overlap: two rules hitting the same entity in the same hour are listed as a merge candidate', () => {
  const t = Date.UTC(2026, 10, 6, 9, 0, 0), list = [];
  for (let i = 0; i < 4; i++) for (const rule of ['R-A', 'R-B']) list.push({ id: rule + i, rule_id: rule, created: t - i * 3600000, ts_first: t - i * 3600000, status: 'new', group: { user: 'u' + i + '.syn' } });
  const RI = createRuleIntel({ rules: () => [{ id: 'R-A', name: 'A', type: 'single', match: {} }, { id: 'R-B', name: 'B', type: 'single', match: {} }], alerts: { all: (f) => list.filter(f) }, config: {}, log: quietLog, now: () => t });
  const v = RI.view();
  assert.equal(v.overlaps.length, 1); assert.equal(v.overlaps[0].pct, 100);
  assert.ok(v.next.some((n) => n.kind === 'overlap'));
  assert.throws(() => RI.ruleView('NOPE'), /not found/);
});

test('GET /rules/intel/:id: one rule with its recent alerts; an unknown or malformed id is refused', async () => {
  const s = setup();
  try {
    raiseClose(s.alerts, 'SENTRA-AUTH-001', 'a.syn', null, 1);
    const r = await s.api.call('GET', '/api/soc/rules/intel/SENTRA-AUTH-001', { role: 'viewer' });
    assert.equal(r.status, 200); assert.equal(r.body.recent.length, 1); assert.equal(r.body.recent[0].group.user, 'a.syn');
    assert.equal((await s.api.call('GET', '/api/soc/rules/intel/NOPE-1', { role: 'viewer' })).status, 404);
    const bad = await s.api.call('GET', '/api/soc/rules/intel/' + encodeURIComponent('x y'), { role: 'viewer' });
    assert.ok([400, 404].includes(bad.status));
  } finally { s.done(); }
});

test('POST /rules/assist: viewer refused; validation names the field; AI off is said; nothing audited when nothing was asked', async () => {
  const s = setup();
  try {
    assert.equal((await s.api.call('POST', '/api/soc/rules/assist', { role: 'viewer', user: 'vera.syn', body: { mode: 'draft', text: 'x' } })).status, 403);
    let r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'rewrite' } });
    assert.equal(r.status, 400); assert.match(r.body.error, /mode/);
    r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'draft' } });
    assert.equal(r.status, 400); assert.match(r.body.error, /^text/);
    r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'tune' } });
    assert.equal(r.status, 400); assert.match(r.body.error, /^rule_id/);
    r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'tune', rule_id: 'NOPE-1' } });
    assert.equal(r.status, 404);
    r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'draft', text: 'logons from two countries' } });
    assert.equal(r.status, 503, 'AI not configured: said so'); assert.match(r.body.error, /SDK|key|switched off/i);
  } finally { s.done(); }
});

const AICFG = { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000 }, noisy_alerts_per_day: 2 };
function fakeSdk(script, seen) { return class Fake { constructor() { this.messages = { create: async (p) => { if (seen) seen.push(JSON.parse(JSON.stringify(p))); return script.shift(); } }; } }; }

test('assist: a person gets a DISABLED draft checked by the compiler; a service identity is refused; audited; nothing stored', async () => {
  const good = { id: 'AI-LOGON-GEO', name: 'Logon from two countries', type: 'distinct', severity: 3, tactic: 'initial-access', enabled: true,
    match: { all: [{ field: 'action', op: 'eq', value: 'logon-success' }] }, group_by: ['user'], distinct_field: 'src_country', distinct_count: 2, window_s: 3600 };
  const script = [{ content: [{ type: 'tool_use', id: 'a', name: 'catalogue', input: {} }], stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 } },
    { content: [{ type: 'tool_use', id: 'b', name: 'submit_rule', input: { rule_json: JSON.stringify(good), why: 'impossible travel', noise_risk: 'VPN egress' } }], stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 } }];
  const s = setup({ sdk: fakeSdk(script), config: AICFG });
  try {
    let r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'system:rules', body: { mode: 'draft', text: 'x' } });
    assert.equal(r.status, 403); assert.match(r.body.error, /service or AI identity/);
    r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', ip: '10.0.0.9', body: { mode: 'draft', text: 'logons from two countries within an hour' } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.ok, true); assert.equal(r.body.compile_error, null);
    assert.equal(r.body.rule.enabled, false, 'an AI draft always arrives disabled'); assert.match(r.body.rule.author, /reviewed by omar\.syn/);
    assert.match(r.body.label, /administrator saves it/);
    assert.ok(!s.state.collection('rules').get('AI-LOGON-GEO'), 'nothing stored by the assistant');
    const au = s.api.audits.find((a) => a.action === 'rule.assist');
    assert.ok(au, 'audited: ' + JSON.stringify(s.api.audits)); assert.equal(au.by || au.user, 'omar.syn');
    // saving is the ordinary admin route: an operator is refused, an admin stores it (still disabled)
    assert.equal((await s.api.call('POST', '/api/soc/rules', { role: 'operator', user: 'omar.syn', body: { rule: r.body.rule } })).status, 403);
    const saved = await s.api.call('POST', '/api/soc/rules', { role: 'admin', user: 'syed.syn', body: { rule: r.body.rule } });
    assert.equal(saved.status, 200); assert.equal(saved.body.rule.enabled, false);
  } finally { s.done(); }
});

test('assist: a draft that does not compile is returned as not ok with the reason; tune keeps the rule id', async () => {
  const bad = { id: 'SENTRA-AUTH-001', name: 'x', type: 'threshold', match: { all: [{ field: 'action', op: 'explode', value: 'x' }] }, group_by: ['user'], window_s: 60, count: 3 };
  const script = [{ content: [{ type: 'tool_use', id: 'b', name: 'submit_rule', input: { rule_json: JSON.stringify(Object.assign({}, bad, { id: 'SOMETHING-ELSE' })), why: 'x' } }], stop_reason: 'tool_use', usage: {} }];
  const s = setup({ sdk: fakeSdk(script), config: AICFG });
  try {
    const r = await s.api.call('POST', '/api/soc/rules/assist', { role: 'operator', user: 'omar.syn', body: { mode: 'tune', rule_id: 'SENTRA-AUTH-001', text: 'too noisy for svc accounts' } });
    assert.equal(r.status, 200); assert.equal(r.body.ok, false); assert.ok(r.body.compile_error);
    assert.equal(r.body.rule.id, 'SENTRA-AUTH-001', 'tune cannot retarget another rule'); assert.equal(r.body.rule.enabled, false);
  } finally { s.done(); }
});
