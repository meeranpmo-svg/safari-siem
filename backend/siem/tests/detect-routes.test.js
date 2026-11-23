// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Rules API against a fake createApi: list decoration, create/update, enable, Sigma (dry run / save), delete/reset,
// replay test through deps.search (paged), roles and audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createDetector } = require('../engine/detect/engine');
const { createScheduled } = require('../engine/detect/scheduled');
const detectRoutes = require('../engine/detect/routes');
const { effectiveRules } = require('../engine/detect/ruleset');
const { fakeApi, fakeSearch, tmpDir, quietLog } = require('./soc-fakes');

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);

function setup(events) {
  const dir = tmpDir('sentra-rulesapi-');
  const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const detector = createDetector({ rules: [], onAlert: (p) => alerts.raise(p), log: quietLog });
  const search = fakeSearch(events || [], { asCH: true });
  const scheduled = createScheduled({ rules: [], search, onAlert: (p) => alerts.raise(p), log: quietLog });
  const api = fakeApi();
  const ctl = detectRoutes.register(api, { state, alerts, detector, scheduled, search, config: { noisy_alerts_per_day: 2 }, log: quietLog });
  return { api, state, alerts, detector, scheduled, search, ctl, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

const SIGMA = `
title: Net user add
id: 11111111-2222-4333-8444-555555555555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'net'
            - ' user '
            - '/add'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1136.001
`;

test('register loads effective rules into the detector and scheduler', () => {
  const s = setup();
  try {
    const st = s.detector.stats();
    assert.ok(st.rules_loaded >= 40);
    assert.equal(st.load_errors.length, 0);
    assert.equal(s.scheduled.stats().length, 1, 'SENTRA-SCH-001 enabled, SENTRA-SCH-002 disabled template');
  } finally { s.done(); }
});

test('GET /rules decorates with origin, alerts_24h, noisy, stats; GET /rules/:id', async () => {
  const s = setup();
  try {
    for (let i = 0; i < 3; i++) s.alerts.raise({ rule_id: 'SENTRA-AUTH-001', rule_name: 'x', group_key: `g${i}`, ts_first: Date.now(), ts_last: Date.now() });
    let r = await s.api.call('GET', '/api/soc/rules', { role: 'viewer' });
    assert.equal(r.status, 200);
    const a1 = r.body.items.find((x) => x.id === 'SENTRA-AUTH-001');
    assert.equal(a1.origin, 'builtin');
    assert.equal(a1.alerts_24h, 3);
    assert.equal(a1.noisy, true);
    assert.ok(a1.stats && a1.stats.indexed === 'action');
    assert.equal(r.body.items.find((x) => x.id === 'SENTRA-AUTH-002').noisy, false);
    r = await s.api.call('GET', '/api/soc/rules?type=scheduled');
    assert.equal(r.body.total, 2);
    r = await s.api.call('GET', '/api/soc/rules/SENTRA-WEB-001');
    assert.equal(r.body.prefilter_query, 'category:"web"');
    r = await s.api.call('GET', '/api/soc/rules/NOPE');
    assert.equal(r.status, 404);
  } finally { s.done(); }
});

test('POST /rules (admin): validate, create, update (version bump), override built-in, enable {enabled}, delete/reset', async () => {
  const s = setup();
  try {
    const rule = { id: 'CUST-001', name: 'Custom login from TOR test range', severity: 3, mitre: ['T1078'], type: 'single',
      match: { all: [{ field: 'action', op: 'eq', value: 'logon' }, { field: 'src_ip', op: 'cidr', value: '198.18.0.0/15' }] }, group_by: ['user'] };
    let r = await s.api.call('POST', '/api/soc/rules', { role: 'operator', body: { rule } });
    assert.equal(r.status, 403, 'rule changes need admin');
    r = await s.api.call('POST', '/api/soc/rules', { role: 'admin', body: { rule: Object.assign({}, rule, { match: { all: [{ field: 'x', op: 'bogus', value: 1 }] } }) } });
    assert.equal(r.status, 400);
    assert.match(r.body.errors[0], /unknown op/);
    r = await s.api.call('POST', '/api/soc/rules', { role: 'admin', body: { rule: Object.assign({}, rule, { id: 'bad id!' }) } });
    assert.equal(r.status, 400);
    r = await s.api.call('POST', '/api/soc/rules', { role: 'admin', body: { rule } });
    assert.equal(r.status, 200);
    assert.equal(r.body.rule.origin, 'custom');
    assert.equal(r.body.rule.version, 1);
    assert.ok(s.detector.stats().rules.some((x) => x.id === 'CUST-001'));
    r = await s.api.call('POST', '/api/soc/rules', { role: 'admin', body: { rule: Object.assign({}, rule, { severity: 4 }) } });
    assert.equal(r.body.rule.version, 2);
    // built-in override + enable {enabled:false}
    r = await s.api.call('POST', '/api/soc/rules/SENTRA-AUTH-001/enable', { role: 'admin', body: { enabled: false } });
    assert.equal(r.body.rule.enabled, false);
    assert.equal(r.body.rule.origin, 'builtin');
    assert.ok(!s.detector.stats().rules.some((x) => x.id === 'SENTRA-AUTH-001'));
    r = await s.api.call('POST', '/api/soc/rules/SENTRA-AUTH-001/enable', { role: 'admin', body: {} });
    assert.equal(r.body.rule.enabled, true);
    // reset built-in / delete custom
    r = await s.api.call('DELETE', '/api/soc/rules/SENTRA-AUTH-001', { role: 'admin' });
    assert.equal(r.body.reset_to_builtin, true);
    r = await s.api.call('POST', '/api/soc/rules/SENTRA-AUTH-002/delete', { role: 'admin' });
    assert.equal(r.status, 409, 'unchanged built-in cannot be deleted');
    r = await s.api.call('POST', '/api/soc/rules/CUST-001/delete', { role: 'admin' });
    assert.equal(r.body.deleted, true);
    assert.ok(!effectiveRules(s.state).some((x) => x.id === 'CUST-001'));
    const acts = s.api.audits.map((x) => x.action);
    assert.deepEqual(acts, ['rule.upsert', 'rule.upsert', 'rule.disable', 'rule.enable', 'rule.reset', 'rule.delete']);
  } finally { s.done(); }
});

test('POST /rules/sigma: dry_run (operator) returns the converted rule; save needs admin; errors → 400 {errors}', async () => {
  const s = setup();
  try {
    let r = await s.api.call('POST', '/api/soc/rules/sigma', { role: 'operator', body: { yaml: SIGMA, dry_run: true } });
    assert.equal(r.status, 200);
    assert.equal(r.body.stored, false);
    assert.equal(r.body.rule.id, 'SIGMA-11111111');
    assert.deepEqual(r.body.rule.mitre, ['T1136.001']);
    assert.ok(Array.isArray(r.body.warnings));
    assert.ok(!effectiveRules(s.state).some((x) => x.id === 'SIGMA-11111111'));
    r = await s.api.call('POST', '/api/soc/rules/sigma', { role: 'operator', body: { yaml: SIGMA, dry_run: false } });
    assert.equal(r.status, 403);
    r = await s.api.call('POST', '/api/soc/rules/sigma', { role: 'admin', body: { yaml: SIGMA, dry_run: false } });
    assert.equal(r.body.stored, true);
    assert.equal(r.body.rule.origin, 'sigma');
    const list = await s.api.call('GET', '/api/soc/rules?origin=sigma');
    assert.equal(list.body.total, 1);
    r = await s.api.call('POST', '/api/soc/rules/sigma', { role: 'admin', body: { yaml: SIGMA.replace("- '/add'", "- '/add'\n    condition2: x").replace('condition: selection', 'condition: selection near other') } });
    assert.equal(r.status, 400);
    assert.ok(r.body.errors.some((e) => /near/.test(e)));
    r = await s.api.call('POST', '/api/soc/rules/import-sigma', { role: 'admin', body: { yaml: SIGMA.replace('11111111', '99999999') + '\n---\n' + SIGMA.replace('11111111', '88888888'), dry_run: false } });
    assert.deepEqual(r.body.stored.sort(), ['SIGMA-88888888', 'SIGMA-99999999']);
    assert.equal(effectiveRules(s.state).find((x) => x.id === 'SIGMA-88888888').enabled, false, 'bulk import defaults to disabled');
  } finally { s.done(); }
});

test('POST /rules/test replays a past time range through a fresh detector (paged search, CH-style rows)', async () => {
  const events = [];
  for (let i = 0; i < 2600; i++) events.push({ id: `r${i}`, ts: T0 + i * 1000, src_type: 'linux', action: i % 2 ? 'logon-failed' : 'logon', process: 'sshd', src_ip: i < 1300 ? '198.51.100.7' : '198.51.100.8', user: 'root', fields: { service: 'ssh' } });
  const s = setup(events);
  try {
    const alertsBefore = s.alerts.list({ status: 'all' }).total;
    let r = await s.api.call('POST', '/api/soc/rules/test', { role: 'operator', body: { rule_id: 'SENTRA-LNX-001', from: new Date(T0 - 1000).toISOString(), to: new Date(T0 + 3000 * 1000).toISOString() } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.events_scanned, 2600);
    assert.equal(r.body.truncated, false);
    assert.ok(r.body.took_ms >= 0);
    assert.equal(r.body.query, 'action:"logon-failed"');
    assert.ok(r.body.alerts.length >= 2, 'one per source IP at least');
    assert.ok(r.body.alerts.every((a) => a.rule_id === 'SENTRA-LNX-001'));
    assert.equal(s.search.calls.length, 3, 'pages of 1000');
    assert.equal(s.alerts.list({ status: 'all' }).total, alertsBefore, 'test does not raise real alerts');
    // ad-hoc rule object + max_events truncation
    r = await s.api.call('POST', '/api/soc/rules/test', { role: 'operator', body: {
      rule: { id: 'ADHOC', name: 'adhoc', type: 'threshold', window_s: 60, count: 30, group_by: ['src_ip'], match: { all: [{ field: 'action', op: 'eq', value: 'logon' }] } },
      from: T0, to: T0 + 3000 * 1000, max_events: 1000 } });
    assert.equal(r.body.truncated, true);
    assert.equal(r.body.events_scanned, 1000);
    r = await s.api.call('POST', '/api/soc/rules/test', { role: 'viewer', body: { rule_id: 'SENTRA-LNX-001' } });
    assert.equal(r.status, 403);
    r = await s.api.call('POST', '/api/soc/rules/test', { role: 'operator', body: { rule_id: 'SENTRA-LNX-001', from: T0 + 10, to: T0 } });
    assert.equal(r.status, 400);
    r = await s.api.call('POST', '/api/soc/rules/test', { role: 'operator', body: { sigma: SIGMA, from: T0, to: T0 + 1000 } });
    assert.equal(r.status, 200);
    assert.ok(s.api.audits.some((a) => a.action === 'rule.test'));
  } finally { s.done(); }
});
