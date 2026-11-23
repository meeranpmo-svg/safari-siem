// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// After-hours mode: real state, alerts, cases, playbooks and business-hours calendar; a fake SMTP relay and a fake clock.
// Riyadh = UTC+3, working days Sun-Thu 08:00-17:00 (05:00-14:00 UTC). 2026-10-21 is a Wednesday.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const playbooks = require('../engine/soc/playbooks');
const { createBusinessHoursStore } = require('../engine/util/business-hours');
const { createAfterHoursMode } = require('../engine/afterhours/mode');
const routes = require('../engine/afterhours/routes');
const { tmpDir, quietLog, fakeApi } = require('./soc-fakes');

const U = (s) => Date.parse(s);
function setup() {
  const dir = tmpDir();
  const state = createState({ dir, log: quietLog });
  let now = U('2026-10-21T10:00:00Z');                       // Wednesday 13:00 Riyadh: working hours
  const clock = () => now;
  const alerts = createAlerts({ state, log: quietLog, now: clock });
  const cases = createCases({ state, alerts, log: quietLog, now: clock });
  const bh = createBusinessHoursStore({ state, log: quietLog, now: clock });
  const mails = []; let fail = null;
  const mail = async (m) => { if (fail) { const e = fail; fail = null; throw e; } mails.push(m); return { accepted: m.to, rejected: [] }; };
  const mode = createAfterHoursMode({ state, alerts, cases, playbooks, calendar: () => bh.calendar(), mail, mailProblems: () => [], log: quietLog, now: clock, portalUrl: 'https://soc.example/dashboards' });
  const raise = (p) => alerts.raise(Object.assign({ rule_name: p.rule_id, ts_first: now, ts_last: now, count: 1 }, p)).alert;
  return { state, alerts, cases, bh, mode, mails, raise, setNow: (t) => { now = t; }, failNext: (e) => { fail = e; },
    done: () => { mode.stop(); alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('pages out-of-hours alerts once, prepares containment as approval requests, never the backlog', async () => {
  const t = setup();
  try {
    const old = t.raise({ rule_id: 'SENTRA-AUTH-001', severity: 4, group: { user: 'old' }, summary: 'raised before the mode was on' });
    t.setNow(U('2026-10-21T10:05:00Z'));
    assert.throws(() => t.mode.save({ enabled: true }, 'syed'), /at least one page recipient/);
    let c = t.mode.save({ enabled: true, page: { to: ['soc@as.example'], quiet_rules: ['SENTRA-NOISY-001'] }, prepare: { mode: 'prepare' }, brief: { enabled: false } }, 'syed');
    assert.equal(c.version, 1); assert.ok(c.enabled_at);
    assert.throws(() => t.mode.save({ page: { min_severity: 2 } }, 'syed', 0), (e) => e.code === 409);
    assert.throws(() => t.mode.save({ page: { to: ['not-an-address'] } }, 'syed'), /not an e-mail address/);
    assert.throws(() => t.mode.save({ shell: 'x' }, 'syed'), /unknown setting/);

    t.setNow(U('2026-10-21T10:30:00Z'));                    // working hours
    t.raise({ rule_id: 'SENTRA-AUTH-001', severity: 4, group: { user: 'day' }, summary: 'raised in working hours' });
    await t.mode.tick();
    assert.equal(t.mails.length, 0, 'working-hours and backlog alerts are not paged');
    assert.equal(t.mode.runs().length, 0);

    t.setNow(U('2026-10-21T18:00:00Z'));                    // 21:00 Riyadh
    const bf = t.raise({ rule_id: 'SENTRA-AUTH-001', severity: 3, mitre: ['T1110'], group: { user: 'fahad' }, summary: 'Brute force against fahad' });
    t.raise({ rule_id: 'SENTRA-X-LOW', severity: 2, group: { host: 'pc1' }, summary: 'medium, below the bar' });
    t.raise({ rule_id: 'SENTRA-NOISY-001', severity: 4, group: { host: 'pc2' }, summary: 'quiet rule' });
    await t.mode.tick();
    assert.equal(t.mails.length, 1, 'one page for the one alert at or above high');
    const m = t.mails[0];
    assert.deepEqual(m.to, ['soc@as.example']);
    assert.match(m.subject, /^\[After hours\]\[HIGH\] Brute force against fahad/);
    assert.match(m.text, /approval/); assert.match(m.text, /Nothing has been executed/);
    assert.match(m.text, new RegExp(`soc-intel\\.html\\?alert=${bf.id}#mode`));
    const R = Object.fromEntries(t.mode.runs().map((r) => [r.rule_id, r]));
    assert.equal(R['SENTRA-AUTH-001'].status, 'PAGED');
    assert.equal(R['SENTRA-AUTH-001'].reason, 'after-hours');
    assert.equal(R['SENTRA-NOISY-001'].status, 'QUIET');
    assert.ok(!R['SENTRA-X-LOW'], 'below min severity: no run, but it is in the brief');
    const cs = t.cases.get(R['SENTRA-AUTH-001'].case_id);
    assert.equal(cs.playbook_id, 'PB-BRUTE-FORCE');
    const apr = t.cases.approvals.list({}).filter((a) => a.case_id === cs.id);
    assert.ok(apr.length >= 2 && apr.every((a) => a.status === 'pending'), 'containment waits as pending approvals');
    assert.ok(!t.mode.runs().some((r) => r.alert_id === old.id), 'the alert from before switching on is never handled');

    await t.mode.tick();
    assert.equal(t.mails.length, 1, 'paged once, not every tick');
    t.alerts.ack(bf.id, 'rasheed');                          // in-progress (our case) → ack is a no-op; the portal also assigns
    t.alerts.assign(bf.id, 'rasheed', 'rasheed');
    await t.mode.tick();
    const r2 = t.mode.runs().find((r) => r.alert_id === bf.id);
    assert.equal(r2.status, 'ACKED'); assert.equal(r2.acked_by, 'rasheed');
  } finally { t.done(); }
});

test('escalation, retry after a relay failure, storm guard, shadow mode', async () => {
  const t = setup();
  try {
    t.mode.save({ enabled: true, page: { to: ['a@as.example'], escalate_to: ['ciso@as.example'], escalate_after_min: 30, max_per_hour: 2 },
      oncall: [{ name: 'Wednesday night', days: [3], to: ['oncall@as.example'] }], prepare: { mode: 'shadow' } }, 'syed');
    t.setNow(U('2026-10-21T20:00:00Z'));                    // 23:00 Wednesday
    const e = Object.assign(new Error('connection refused'), { stage: 'connect', transient: true });
    t.failNext(e);
    const a1 = t.raise({ rule_id: 'SENTRA-AUTH-001', severity: 4, mitre: ['T1110'], group: { user: 'u1' }, summary: 'one' });
    await t.mode.tick();
    let r = t.mode.runs().find((x) => x.alert_id === a1.id);
    assert.equal(r.status, 'RETRY', JSON.stringify(r.history)); assert.match(r.error, /connect: connection refused/);
    assert.ok(r.shadow && !r.case_id, 'shadow records the playbook, opens nothing');
    assert.equal(t.cases.list({}).items.length, 0);
    await t.mode.tick();
    assert.equal(t.mode.runs().find((x) => x.alert_id === a1.id).status, 'RETRY', 'no retry before its back-off');
    t.setNow(U('2026-10-21T20:01:30Z'));
    await t.mode.tick();
    r = t.mode.runs().find((x) => x.alert_id === a1.id);
    assert.equal(r.status, 'PAGED');
    assert.equal(t.mode.brief('2026-10-21').sent.status, 'missed', 'engine "started" at 23:00: the day\'s brief is recorded as missed, not mailed');
    assert.deepEqual(t.mails[0].to.sort(), ['a@as.example', 'oncall@as.example'], 'page.to + tonight\'s rota');
    assert.deepEqual(r.rota, ['Wednesday night']);

    t.setNow(U('2026-10-21T20:32:00Z'));
    await t.mode.tick();
    r = t.mode.runs().find((x) => x.alert_id === a1.id);
    assert.equal(r.status, 'ESCALATED');
    assert.deepEqual(t.mails[1].to, ['ciso@as.example']); assert.match(t.mails[1].subject, /\[ESCALATION\]/);
    assert.match(t.mails[1].text, /Nobody has acknowledged/);

    t.raise({ rule_id: 'SENTRA-AUTH-002', severity: 3, group: { user: 'u2' }, summary: 'two' });
    t.raise({ rule_id: 'SENTRA-AUTH-003', severity: 3, group: { user: 'u3' }, summary: 'three' });
    await t.mode.tick();
    const st = t.mode.runs().map((x) => x.status).sort();
    assert.ok(st.includes('HELD'), 'third page in the hour is held, not dropped');
    assert.equal(t.mode.status().tonight.held, 1);

    // morning brief: Thursday 07:40 Riyadh, window from Wednesday 17:00
    t.setNow(U('2026-10-22T04:40:00Z'));
    const briefs = () => t.mails.filter((x) => /^After-hours brief/.test(x.subject));
    await t.mode.tick();
    const b = t.mode.brief('2026-10-22');
    assert.ok(b, 'brief stored');
    assert.equal(b.window.from, U('2026-10-21T14:00:00Z'));
    assert.equal(b.counts.alerts, 3); assert.equal(b.counts.held, 1); assert.equal(b.counts.shadow, 3, 'all three match the brute-force playbook');
    assert.ok(b.need.some((x) => /unacknowledged/.test(x)));
    assert.ok(b.need.some((x) => /storm guard/.test(x)));
    assert.equal(b.sent.status, 'ok');
    assert.equal(briefs().length, 1); assert.match(briefs()[0].subject, /^After-hours brief 2026-10-22/);
    assert.doesNotMatch(briefs()[0].html, /<script/i);
    assert.ok(t.mails.some((x) => /\[ESCALATION\]\[HIGH\] two/.test(x.subject)), 'the unacknowledged overnight page escalated too');
    await t.mode.tick();
    assert.equal(briefs().length, 1, 'one brief per day');

    // Friday is not a working day: no brief; Sunday's covers the weekend from Thursday 17:00
    t.setNow(U('2026-10-23T05:00:00Z')); await t.mode.tick();
    assert.equal(t.mode.brief('2026-10-23'), null);
    t.setNow(U('2026-10-25T04:45:00Z')); await t.mode.tick();
    assert.equal(t.mode.brief('2026-10-25').window.from, U('2026-10-22T14:00:00Z'));
  } finally { t.done(); }
});

test('routes: viewer sees status only, operator reads, only an administrator changes settings', async () => {
  const dir = tmpDir();
  const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const bh = createBusinessHoursStore({ state, log: quietLog });
  const mails = [];
  const api = fakeApi();
  const deps = { state, alerts, cases: null, config: { afterhours: { scheduler: false } }, log: quietLog,
    reports: { businessHours: bh, schedules: { mail: async (m) => { mails.push(m); return { accepted: m.to }; }, mailProblems: () => [] } } };
  try {
    routes.register(api, deps);
    let r = await api.call('GET', '/api/soc/after-hours/mode/status', { role: 'viewer' });
    assert.equal(r.status, 200); assert.equal(r.body.enabled, false); assert.equal(r.body.mail.ok, true);
    r = await api.call('GET', '/api/soc/after-hours/mode/runs', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await api.call('GET', '/api/soc/after-hours/mode/config', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await api.call('GET', '/api/soc/after-hours/mode/config', { role: 'operator' }); assert.equal(r.status, 200);
    r = await api.call('POST', '/api/soc/after-hours/mode/config', { role: 'operator', body: { enabled: true } }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/after-hours/mode/config', { role: 'admin', body: { enabled: true, page: { to: ['soc@as.example'] }, base_version: 0 } });
    assert.equal(r.status, 200); assert.equal(r.body.version, 1);
    assert.ok(api.audits.some((a) => a.action === 'after-hours.mode.save'));
    r = await api.call('POST', '/api/soc/after-hours/mode/config', { role: 'admin', body: { brief: { at: '07:00' }, base_version: 0 } });
    assert.equal(r.status, 409);
    r = await api.call('POST', '/api/soc/after-hours/mode/test-page', { role: 'admin', user: 'syed' });
    assert.equal(r.status, 200); assert.equal(mails.length, 1); assert.match(mails[0].text, /sent by syed/);
    r = await api.call('POST', '/api/soc/after-hours/mode/brief-now', { role: 'admin', body: {} });
    assert.equal(r.status, 200); assert.ok(r.body.text); assert.equal(mails.length, 1, 'preview sends nothing');
    r = await api.call('GET', '/api/soc/after-hours/mode/briefs/2020-01-01', { role: 'operator' }); assert.equal(r.status, 404);
  } finally { deps.afterHoursMode.stop(); alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
