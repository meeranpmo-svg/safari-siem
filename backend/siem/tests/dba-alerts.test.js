// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DBA alert center: thresholds (defaults, per-instance / per-tablespace overrides, validation), conditions from the latest
// readings, stale readings kept open, collector silence, ORA- error findings (de-duplicated, catalogued, ignore list),
// notifications (critical at once in one mail, warnings to the digest, sustain against flapping, ack, re-notify, snooze,
// maintenance, recovery), the daily digest, and route roles (the DBA approver may change thresholds, a plain operator may not).
// ClickHouse is a fake answering by the /* sentra:dba-… */ tag; readings are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createDbaAlerts, valueOf, oraLines } = require('../engine/db-audit/dba-alerts');
const routes = require('../engine/db-audit/dba-routes');
const { createState } = require('../engine/soc/state');
const { createBusinessHoursStore } = require('../engine/util/business-hours');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const U = (s) => Date.parse(s);
function world(t0) {
  let now = t0;
  const R = { latest: [], seen: [], alerts: [] };
  const row = (inst, act, k, f, agoMin = 2, h = 'db1') => ({ h, inst, act, k, f, last_ms: now - agoMin * 60000 });
  const ch = { async query(sql) { const m = /sentra:(dba-[a-z]+)/.exec(sql); if (!m) throw new Error('untagged'); return { 'dba-latest': R.latest, 'dba-seen': R.seen, 'dba-alertlog': R.alerts }[m[1]]; } };
  return { R, row, ch, clock: () => now, set: (t) => { now = t; }, get now() { return now; } };
}
function setup(t0 = U('2026-10-21T08:00:00Z')) {   // Wednesday 11:00 Riyadh
  const dir = tmpDir(); const state = createState({ dir, log: quietLog });
  const W = world(t0); const bh = createBusinessHoursStore({ state, log: quietLog, now: W.clock });
  const mails = [];
  const D = createDbaAlerts({ ch: W.ch, state, log: quietLog, now: W.clock, calendar: () => bh.calendar(), mail: async (m) => { mails.push(m); return { accepted: m.to }; }, mailProblems: () => [], portalUrl: 'https://soc.example/dashboards' });
  const base = () => {
    W.R.seen = [{ h: 'db1', inst: 'ORCLPRD', last_ms: W.now - 120000, db: 'ORCLPRD' }, { h: 'db2', inst: 'HRDB', last_ms: W.now - 120000, db: 'HRDB' }];
    W.R.latest = [
      W.row('ORCLPRD', 'health-sample', '', { status: 'OPEN', role: 'PRIMARY', version: '19.21' }),
      W.row('ORCLPRD', 'tablespace-usage', 'USERS', { used_pct: '96', contents: 'PERMANENT' }),
      W.row('ORCLPRD', 'tablespace-usage', 'SYSTEM', { used_pct: '87', contents: 'PERMANENT' }),
      W.row('ORCLPRD', 'tablespace-usage', 'TEMP', { used_pct: '99', contents: 'TEMPORARY' }),
      W.row('ORCLPRD', 'tablespace-growth', 'USERS', { days_to_full: '5.5' }, 60),
      W.row('ORCLPRD', 'fra-usage', '', { used_pct: '92' }),
      W.row('ORCLPRD', 'backup-status', '', { status: 'COMPLETED', age_h: '30' }, 30),
      W.row('ORCLPRD', 'dataguard-lag', 'PRIMARY', { apply_lag_s: '2000', transport_lag_s: '10' }),
      W.row('ORCLPRD', 'listener-down', 'LISTENER', { status: 'DOWN' }),
      W.row('HRDB', 'instance-down', '', { status: 'MOUNTED' }, 3, 'db2'),
      W.row('HRDB', 'health-sample', '', { status: 'OPEN' }, 50, 'db2'),
    ];
    W.R.alerts = [];
  };
  base();
  return { W, D, mails, state, bh, base, done: () => { D.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const byMetric = (D) => Object.fromEntries(D.conditions({ status: 'open' }).map((c) => [`${c.metric}|${c.instance}|${c.key}`, c]));

test('value extraction and ORA- line parsing', () => {
  assert.equal(valueOf('ts_used_pct', { act: 'tablespace-usage', f: { used_pct: '91', contents: 'PERMANENT' } }), 91);
  assert.equal(valueOf('ts_used_pct', { act: 'tablespace-usage', f: { used_pct: '99', contents: 'UNDO' } }), null, 'UNDO / TEMP have their own metrics');
  assert.equal(valueOf('sessions_pct', { act: 'session-count', f: { total: '450', max_sessions: '500' } }), 90);
  assert.equal(valueOf('backup_failed', { act: 'backup-status', f: { status: 'FAILED' } }), 1);
  assert.equal(valueOf('backup_failed', { act: 'backup-status', f: { status: 'NONE' } }), 1, 'no backup on record is a problem');
  assert.equal(valueOf('dg_lag_s', { act: 'dg-lag', k: 'apply lag', f: { value_s: '700' } }), 700);
  // a destination a DBA DEFERRED keeps Oracle's last error text: not an "archive destination error" (seen on ESX-AGGREGATOR)
  assert.equal(valueOf('archive_dest', { act: 'archive-dest', f: { status: 'DEFERRED', error: 'ORA-19504: failed to create file' } }), 0);
  assert.equal(valueOf('archive_dest', { act: 'archive-dest', f: { status: 'DISABLED', error: 'ORA-12541' } }), 0);
  assert.equal(valueOf('archive_dest', { act: 'archive-dest', f: { status: 'ERROR', error: 'ORA-12541: TNS:no listener' } }), 1);
  assert.equal(valueOf('archive_dest', { act: 'archive-dest', f: { status: 'VALID', error: 'ORA-16191' } }), 1, 'an enabled destination with an error is still one');
  assert.deepEqual(oraLines('ok line\n2026-10-21T07:00:00Z ORA-00600: internal error [kdsgrp1]\nORA-01653 and ORA-01110').map((x) => x.codes), [['ORA-00600'], ['ORA-01653', 'ORA-01110']]);
});

test('default thresholds, overrides by scope, validation', async () => {
  const t = setup();
  try {
    await t.D.evaluate();
    let C = byMetric(t.D);
    assert.equal(C['ts_used_pct|ORCLPRD|USERS'].level, 'crit');
    assert.equal(C['ts_used_pct|ORCLPRD|SYSTEM'].level, 'warn');
    assert.ok(!C['ts_used_pct|ORCLPRD|TEMP'], 'TEMP tablespace is not judged by the permanent-tablespace threshold');
    assert.equal(C['ts_days_to_full|ORCLPRD|USERS'].level, 'crit', '5.5 days to full ≤ 7');
    assert.equal(C['fra_pct|ORCLPRD|'].level, 'crit');
    assert.equal(C['backup_age_h|ORCLPRD|'].level, 'warn');
    assert.equal(C['dg_lag_s|ORCLPRD|PRIMARY'].level, 'crit');
    assert.equal(C['listener_down|ORCLPRD|LISTENER'].level, 'crit');
    assert.equal(C['instance_down|HRDB|'].level, 'crit', 'the newer instance-down reading wins over an older OPEN sample');
    const S = t.D.status();
    assert.equal(S.instances.length, 2); assert.equal(S.instances[0].level, 'crit');
    assert.deepEqual(S.instances.find((i) => i.instance === 'ORCLPRD').max_ts, { key: 'USERS', value: 96 });

    assert.throws(() => t.D.savePolicy({ metrics: { ts_used_pct: { warn: 90, crit: 80 } }, reason: 'test' }, 'ahmed'), /critical must be at or above warning/);
    assert.throws(() => t.D.savePolicy({ metrics: { fra_pct: { crit: 120 } }, reason: 'test' }, 'ahmed'), /at most 100/);
    assert.throws(() => t.D.savePolicy({ metrics: { fra_pct: { crit: 95 } } }, 'ahmed'), /say why/);
    assert.throws(() => t.D.savePolicy({ overrides: [{ metric: 'fra_pct', scope: 'ORCLPRD/USERS', crit: 95 }], reason: 'x y' }, 'ahmed'), /set per instance/);
    t.D.savePolicy({ overrides: [{ metric: 'ts_used_pct', scope: 'ORCLPRD/USERS', warn: 97, crit: 99 }, { metric: 'ts_used_pct', scope: '*/SYSTEM', warn: 90, crit: 98 }], reason: 'USERS is pre-allocated; SYSTEM is stable', base_version: 0 }, 'ahmed');
    assert.throws(() => t.D.savePolicy({ metrics: {}, reason: 'race', base_version: 0 }, 'ali'), (e) => e.code === 409);
    assert.equal(t.D.thresholdFor('ts_used_pct', 'ORCLPRD', 'USERS').scope, 'ORCLPRD/USERS');
    assert.equal(t.D.thresholdFor('ts_used_pct', 'HRDB', 'SYSTEM').scope, '*/SYSTEM');
    await t.D.evaluate();
    C = byMetric(t.D);
    assert.ok(!C['ts_used_pct|ORCLPRD|USERS'] && !C['ts_used_pct|ORCLPRD|SYSTEM'], 'both cleared under their overrides');
    assert.equal(t.D.conditions({ status: 'cleared' }).filter((c) => c.metric === 'ts_used_pct').length, 2);
  } finally { t.done(); }
});

test('stale readings stay open; a silent database is critical', async () => {
  const t = setup();
  try {
    await t.D.evaluate();
    assert.ok(byMetric(t.D)['fra_pct|ORCLPRD|']);
    t.W.set(t.W.now + 3 * 3600000);   // FRA freshness is 120 min: the reading is now stale
    t.W.R.latest = t.W.R.latest.map((r) => (r.act === 'fra-usage' ? r : Object.assign({}, r, { last_ms: t.W.now - 60000 })));
    t.W.R.seen = [{ h: 'db1', inst: 'ORCLPRD', last_ms: t.W.now - 60000 }, { h: 'db2', inst: 'HRDB', last_ms: t.W.now - 40 * 60000 }];
    await t.D.evaluate();
    const C = byMetric(t.D);
    assert.ok(C['fra_pct|ORCLPRD|'] && C['fra_pct|ORCLPRD|'].stale, 'no fresh reading: kept open, marked stale - never a silent clear');
    assert.equal(C['collector_silent|HRDB|'].level, 'crit', '40 minutes without a reading');
  } finally { t.done(); }
});

test('ORA- error findings: catalogued, de-duplicated, ignore list, unknown codes kept', async () => {
  const t = setup();
  try {
    const tail = '2026-10-21T07:10:00Z ORA-00600: internal error code, arguments: [kdsgrp1]\n2026-10-21T07:12:00Z ORA-01653: unable to extend table APP.CLAIMS by 128 in tablespace USERS\n2026-10-21T07:20:00Z ORA-01017: invalid username/password\n2026-10-21T07:30:00Z ORA-29999 something new';
    t.W.R.alerts = [{ h: 'db1', inst: 'ORCLPRD', t: t.W.now - 3600000, tail, path: 'V$DIAG_ALERT_EXT' }, { h: 'db1', inst: 'ORCLPRD', t: t.W.now - 600000, tail, path: 'V$DIAG_ALERT_EXT' }];
    await t.D.evaluate();
    const E = t.D.errors().items; const by = Object.fromEntries(E.map((e) => [e.code, e]));
    assert.equal(by['ORA-00600'].count, 1, 'the same line read twice (overlapping hourly windows) counts once');
    assert.equal(by['ORA-00600'].level, 'crit'); assert.match(by['ORA-00600'].what, /adrci/);
    assert.equal(by['ORA-01653'].level, 'crit'); assert.match(by['ORA-01653'].samples[0], /APP\.CLAIMS/);
    assert.equal(by['ORA-29999'].known, false); assert.equal(by['ORA-29999'].title, 'Other ORA- error');
    const C = byMetric(t.D);
    assert.ok(C['ora:ORA-00600|ORCLPRD|'] && !C['ora:ORA-01017|ORCLPRD|'], 'info-level codes are listed, not raised');
    t.D.savePolicy({ errors: { ignore: ['ORA-29999'] }, reason: 'known application noise' }, 'ahmed');
    await t.D.evaluate();
    assert.ok(!t.D.errors().items.some((e) => e.code === 'ORA-29999'));
  } finally { t.done(); }
});

test('notifications: critical at once (one mail), warnings to the digest, sustain, ack, re-notify, snooze, maintenance, recovery', async () => {
  const t = setup();
  try {
    t.D.saveNotify({ recipients: ['dba@as.example'], digest: { enabled: false } }, 'ahmed');
    await t.D.tick();
    assert.equal(t.mails.length, 1, 'all new critical problems in one e-mail');
    assert.match(t.mails[0].subject, /^\[DB\]\[CRITICAL\] \d+ problem\(s\) on /);
    assert.match(t.mails[0].text, /ORCLPRD · USERS - Tablespace used: 96 %/);
    assert.match(t.mails[0].text, /SYSTEM - Tablespace used: 87 %/, 'a tablespace at 87 % is a warning the DBA hears about at once (mailWarn)');
    assert.doesNotMatch(t.mails[0].text, /Hours since the last good backup/, 'other warnings (backup 30 h) wait for the digest');
    assert.match(t.mails[0].text, /db-dashboard\.html/);

    // sustain: sessions at 90 % mails only after 10 minutes
    t.W.R.latest.push(t.W.row('ORCLPRD', 'session-count', '', { total: '480', max_sessions: '500' }));
    t.W.set(t.W.now + 60000); t.W.R.latest = t.W.R.latest.map((r) => Object.assign({}, r, { last_ms: t.W.now - 60000 }));
    await t.D.tick();
    assert.equal(t.mails.length, 1, 'a 1-minute spike does not page');
    t.W.set(t.W.now + 11 * 60000); t.W.R.latest = t.W.R.latest.map((r) => Object.assign({}, r, { last_ms: t.W.now - 60000 }));
    await t.D.tick();
    assert.equal(t.mails.length, 2); assert.match(t.mails[1].text, /Sessions of the limit: 96 %/);

    // ack stops reminders; re-notify after 4 h for the rest; snooze and maintenance hold
    const users = t.D.conditions().find((c) => c.metric === 'ts_used_pct' && c.key === 'USERS');
    t.D.ack(users.id, 'ahmed', 'adding a data file tonight');
    const fra = t.D.conditions().find((c) => c.metric === 'fra_pct');
    t.D.snooze(fra.id, 24, 'ahmed', 'RMAN delete obsolete scheduled');
    assert.throws(() => t.D.snooze(fra.id, 24, 'ahmed', ''), /say why/);
    t.D.maintenance('HRDB', 8, 'ahmed', 'patching to 19.22');
    t.W.set(t.W.now + 4.2 * 3600000); t.W.R.latest = t.W.R.latest.map((r) => Object.assign({}, r, { last_ms: t.W.now - 60000 }));
    t.W.R.seen = t.W.R.seen.map((s) => Object.assign({}, s, { last_ms: t.W.now - 60000 }));
    await t.D.tick();
    const rem = t.mails[t.mails.length - 1];
    assert.match(rem.text, /Still open and not acknowledged|reported before/);
    assert.doesNotMatch(rem.text, /USERS - Tablespace used/, 'acknowledged: no reminder');
    assert.doesNotMatch(rem.text, /Recovery area/, 'snoozed: no reminder');
    assert.doesNotMatch(rem.text, /HRDB/, 'in maintenance: no mail');
    assert.ok(t.D.status().instances.find((i) => i.instance === 'HRDB').maintenance);

    // recovery
    t.W.R.latest = t.W.R.latest.filter((r) => r.act !== 'listener-down').concat([t.W.row('ORCLPRD', 'listener-status', 'LISTENER', { status: 'READY' })]);
    const n = t.mails.length;
    await t.D.tick();
    assert.ok(t.mails.slice(n).some((m) => /^\[DB\]\[RECOVERED\]/.test(m.subject) && /Listener down/.test(m.text)), 'recovery mail when a critical clears');
  } finally { t.done(); }
});

test('daily digest: once per working day at the set time, with errors and open problems', async () => {
  const t = setup(U('2026-10-21T04:40:00Z'));   // 07:40 Riyadh, digest at 07:45
  try {
    t.D.saveNotify({ recipients: ['dba@as.example'], digest: { enabled: true, at: '07:45' } }, 'ahmed');
    t.W.R.alerts = [{ h: 'db1', inst: 'ORCLPRD', t: t.W.now - 600000, tail: 'ORA-00257: archiver error' }];
    await t.D.tick();
    assert.ok(!t.mails.some((m) => /^Database digest/.test(m.subject)), 'not before 07:45');
    t.W.set(U('2026-10-21T04:50:00Z')); t.W.R.latest = t.W.R.latest.map((r) => Object.assign({}, r, { last_ms: t.W.now - 60000 }));
    await t.D.tick(); await t.D.tick();
    const dg = t.mails.filter((m) => /^Database digest 2026-10-21/.test(m.subject));
    assert.equal(dg.length, 1, 'once');
    assert.match(dg[0].html, /ORCLPRD/); assert.match(dg[0].html, /ORA-00257 Archiver stuck/); assert.match(dg[0].html, /nothing was changed on any database/);
    assert.doesNotMatch(dg[0].html, /<script/i);
    t.W.set(U('2026-10-23T05:00:00Z')); await t.D.tick();   // Friday
    assert.ok(!t.mails.some((m) => /^Database digest 2026-10-23/.test(m.subject)), 'no digest on a weekend day');
  } finally { t.done(); }
});

test('routes: anyone reads, the DBA approver changes thresholds, an operator acknowledges', async () => {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog });
  state.collection('approvers').put({ id: 'map', scopes: { 'eng:dba': ['ahmed'] } });
  const W = world(U('2026-10-21T08:00:00Z'));
  W.R.seen = [{ h: 'db1', inst: 'ORCLPRD', last_ms: W.now - 60000 }];
  W.R.latest = [W.row('ORCLPRD', 'health-sample', '', { status: 'OPEN' }), W.row('ORCLPRD', 'tablespace-usage', 'USERS', { used_pct: '96', contents: 'PERMANENT' })];
  const bh = createBusinessHoursStore({ state, log: quietLog });
  const api = fakeApi(); const mails = [];
  const deps = { state, ch: W.ch, now: W.clock, config: { dba: { scheduler: false } }, log: quietLog, reports: { businessHours: bh, schedules: { mail: async (m) => { mails.push(m); return {}; }, mailProblems: () => [] } } };
  try {
    routes.register(api, deps);
    let r = await api.call('POST', '/api/soc/db/dba/evaluate', { role: 'operator' }); assert.equal(r.status, 200); assert.equal(r.body.opened, 1);
    r = await api.call('GET', '/api/soc/db/dba/status', { role: 'viewer' }); assert.equal(r.status, 200); assert.equal(r.body.instances[0].instance, 'ORCLPRD');
    r = await api.call('GET', '/api/soc/db/dba/thresholds', { role: 'viewer' }); assert.equal(r.body.metrics.find((m) => m.id === 'ts_used_pct').crit, 95);
    const body = { metrics: { ts_used_pct: { warn: 88 } }, reason: 'agreed with the DBA team', base_version: 0 };
    r = await api.call('POST', '/api/soc/db/dba/thresholds', { role: 'operator', user: 'ali', body }); assert.equal(r.status, 403, 'a plain operator cannot change thresholds');
    r = await api.call('POST', '/api/soc/db/dba/thresholds', { role: 'operator', user: 'ahmed', body }); assert.equal(r.status, 200, 'the named DBA can'); assert.equal(r.body.metrics.find((m) => m.id === 'ts_used_pct').warn, 88);
    const a = api.audits.find((x) => x.action === 'dba.thresholds.save');
    assert.deepEqual(a.detail.changed, [{ metric: 'ts_used_pct', from: { warn: 87, crit: 95, enabled: true }, to: { warn: 88, crit: 95, enabled: true } }]);
    r = await api.call('POST', '/api/soc/db/dba/thresholds', { role: 'admin', user: 'svc-ai', body: Object.assign({}, body, { base_version: 1 }) });
    r = await api.call('POST', '/api/soc/db/dba/thresholds', { role: 'admin', user: 'system:ai-dba', body: Object.assign({}, body, { base_version: 1 }) }); assert.equal(r.status, 403, 'an AI / service identity never changes thresholds');
    const cid = (await api.call('GET', '/api/soc/db/dba/conditions')).body.items[0].id;
    r = await api.call('POST', '/api/soc/db/dba/conditions/ack', { role: 'viewer', body: { id: cid } }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/db/dba/conditions/ack', { role: 'operator', user: 'ali', body: { id: cid, note: 'on it' } }); assert.equal(r.status, 200); assert.equal(r.body.ack.by, 'ali');
    r = await api.call('POST', '/api/soc/db/dba/test-mail', { role: 'operator', user: 'ahmed' }); assert.equal(r.status, 400, 'no recipients yet: says so');
    r = await api.call('POST', '/api/soc/db/dba/notify', { role: 'operator', user: 'ahmed', body: { recipients: ['dba@as.example'] } }); assert.equal(r.status, 200);
    r = await api.call('POST', '/api/soc/db/dba/test-mail', { role: 'operator', user: 'ahmed' }); assert.equal(r.status, 200); assert.equal(mails.length, 1);
    // the morning health check report from IT Asset Management: only its service identity sends it, subject forced to [DB]
    r = await api.call('POST', '/api/soc/db/dba/morning-report', { role: 'admin', user: 'syed', body: { subject: 'x', html: '<p>x</p>' } }); assert.equal(r.status, 403, 'a person cannot send arbitrary mail to the DBAs through this');
    r = await api.call('POST', '/api/soc/db/dba/morning-report', { role: 'admin', user: 'system:itam-db-health', body: { id: 'MHC-1', day: '2026-10-21', subject: 'Morning health check 2026-10-21: 2 FAIL\nBcc: x', text: 't', html: '<p>h</p>' } });
    assert.equal(r.status, 200); assert.equal(mails.length, 2); assert.equal(mails[1].subject, '[DB] Morning health check 2026-10-21: 2 FAIL Bcc: x', 'no header injection'); assert.deepEqual(mails[1].to, ['dba@as.example']);
    assert.ok(api.audits.some((x) => x.action === 'dba.morning-report'));
    // the Oracle licence report: its own identity, audience dba+managers adds the infrastructure managers (never other addresses)
    r = await api.call('POST', '/api/soc/db/dba/notify', { role: 'operator', user: 'ahmed', body: { managers: ['not-an-address'] } }); assert.equal(r.status, 400);
    r = await api.call('POST', '/api/soc/db/dba/notify', { role: 'operator', user: 'ahmed', body: { managers: ['Infra.Manager@as.example', 'dba@as.example'] } }); assert.equal(r.status, 200);
    r = await api.call('POST', '/api/soc/db/dba/morning-report', { role: 'admin', user: 'system:itam-oracle-licences', body: { id: 'OLR-1', subject: 'Oracle licence compliance: OVER-UTILISED', html: '<p>r</p>', audience: 'dba+managers', to: ['attacker@evil.example'] } });
    assert.equal(r.status, 200); assert.deepEqual(mails[2].to, ['dba@as.example', 'infra.manager@as.example'], 'DBAs + managers, de-duplicated; a "to" in the body is ignored'); assert.equal(r.body.recipients, 2);
    r = await api.call('POST', '/api/soc/db/dba/morning-report', { role: 'admin', user: 'system:itam-db-health', body: { id: 'MHC-2', subject: 'x', text: 't' } });
    assert.deepEqual(mails[3].to, ['dba@as.example'], 'without the audience only the DBAs');
    r = await api.call('POST', '/api/soc/db/dba/morning-report', { role: 'admin', user: 'system:itam-other', body: { subject: 'x', text: 't' } }); assert.equal(r.status, 403);
  } finally { deps.dbaAlerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// The DBA's own list (Oct 2026): ASM / FRA 80 %, tablespace 87 %, deadlocks, long queries, scheduler jobs over 20 min, bulk
// deletes and truncates, code changes by anyone but SYS / SYSDBA / Oracle's users, RAC node down, DR link failing. Warnings of
// these are e-mailed at once (not held for the digest), each naming who / what.
test('DBA list: ASM, FRA, deadlocks, long query, long job, bulk delete, truncate, code change (SYS excluded), RAC node, DR link', async () => {
  const t = setup();
  try {
    const W = t.W, r = W.row;
    W.R.latest = [
      r('ORCLPRD', 'health-sample', '', { status: 'OPEN', role: 'PRIMARY' }),
      r('ORCLPRD', 'asm-diskgroup', 'DATA', { used_pct: '82' }), r('ORCLPRD', 'asm-diskgroup', 'RECO', { free_pct: '35' }),
      r('ORCLPRD', 'fra-usage', '', { used_pct: '81' }),
      r('ORCLPRD', 'long-query', '412,77', { elapsed_s: '2000', sql_id: 'a1b2c3d4e5f6g', user: 'APPUSER', module: 'claims-api', event: 'db file sequential read' }),
      r('ORCLPRD', 'sched-job', 'APP.NIGHTLY_LOAD', { owner: 'APP', job_name: 'NIGHTLY_LOAD', elapsed_s: '1500', session_id: '88' }),
      r('ORCLPRD', 'sched-job', 'APP.QUICK', { owner: 'APP', job_name: 'QUICK', elapsed_s: '300' }),
      r('ORCLPRD', 'bulk-delete', '9xyz123abc456', { rows_deleted: '15000', table: 'APP.CLAIMS', db_user: 'APPUSER', sql_id: '9xyz123abc456', executions: '1' }),
      r('ORCLPRD', 'code-change', 'APP.PKG_CLAIMS (PACKAGE BODY)', { owner: 'APP', name: 'PKG_CLAIMS', type: 'PACKAGE BODY', ddl_time: '2026-10-21T10:40:00', created: 'N', status: 'VALID' }),
      r('ORCLPRD', 'code-change-by', 'APP.PKG_CLAIMS|ALI.SYN|X', { owner: 'APP', name: 'PKG_CLAIMS', user: 'ALI.SYN', os_user: 'ali', client_host: 'pc-17', action: 'ALTER PACKAGE BODY', excluded: 'N', ok: 'Y', at: '2026-10-21T07:40:00Z' }),
      r('ORCLPRD', 'code-change', 'APP.TRG_AUDIT (TRIGGER)', { owner: 'APP', name: 'TRG_AUDIT', type: 'TRIGGER', ddl_time: '2026-10-21T10:41:00', status: 'VALID' }),
      r('ORCLPRD', 'code-change-by', 'APP.TRG_AUDIT|SYS|X', { owner: 'APP', name: 'TRG_AUDIT', user: 'SYS', sysdba: 'Y', action: 'ALTER TRIGGER', excluded: 'Y', at: '2026-10-21T07:41:00Z' }),
      r('ORCLPRD', 'code-change', 'APP.FN_RATE (FUNCTION)', { owner: 'APP', name: 'FN_RATE', type: 'FUNCTION', ddl_time: '2026-10-21T10:42:00', created: 'Y', status: 'INVALID' }),
      r('ORCLPRD', 'code-change-by', 'APP.CLAIMS_TMP|BATCH.SYN|X', { owner: 'APP', name: 'CLAIMS_TMP', user: 'BATCH.SYN', action: 'TRUNCATE TABLE', excluded: 'N', ok: 'Y', at: '2026-10-21T07:43:00Z' }),
      r('ORCLPRD', 'code-change-by', 'APP.OLD_PROC|ALI.SYN|X', { owner: 'APP', name: 'OLD_PROC', user: 'ALI.SYN', action: 'DROP PROCEDURE', excluded: 'N', ok: 'Y', at: '2026-10-21T07:44:00Z' }),
      r('ORCLPRD', 'rac-node', '2', { thread: '2', instance_name: 'ORCLPRD2', host_name: 'db1b', status: 'NOT RUNNING' }),
      r('ORCLPRD', 'rac-node', '1', { thread: '1', instance_name: 'ORCLPRD1', host_name: 'db1', status: 'OPEN' }),
      r('ORCLPRD', 'dg-transport', 'ORCL_DR', { status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'IDLE' }),
    ];
    W.R.alerts = [{ h: 'db1', inst: 'ORCLPRD', t: W.now - 10 * 60000, tail: '2026-10-21T07:50:01Z ORA-00060: Deadlock detected. See Note 60.1 at My Oracle Support for Troubleshooting ORA-60 Errors. More info in file /u01/trace/orcl_ora_4411.trc.\n2026-10-21T07:51:09Z ORA-00060: Deadlock detected. More info in file /u01/trace/orcl_ora_4412.trc.' },
      { h: 'db1', inst: 'ORCLPRD', t: W.now - 3 * 3600000, tail: '2026-10-21T05:00:00Z ORA-00060: Deadlock detected. old one' }];
    t.D.saveNotify({ recipients: ['dba@as.example'], digest: { enabled: false } }, 'ahmed');
    await t.D.tick();
    const C = byMetric(t.D);
    assert.equal(C['asm_used_pct|ORCLPRD|DATA'].level, 'warn'); assert.ok(!C['asm_used_pct|ORCLPRD|RECO'], 'RECO 65 % used (from free %) is fine');
    assert.ok(!Object.keys(C).some((k) => k.startsWith('asm_free_pct')), 'the old free % rule is off by default');
    assert.equal(C['fra_pct|ORCLPRD|'].level, 'warn');
    assert.equal(C['long_query_s|ORCLPRD|412,77'].level, 'warn'); assert.match(C['long_query_s|ORCLPRD|412,77'].detail, /user APPUSER · SQL a1b2c3d4e5f6g · claims-api/);
    assert.equal(C['job_run_min|ORCLPRD|APP.NIGHTLY_LOAD'].level, 'warn'); assert.ok(!C['job_run_min|ORCLPRD|APP.QUICK'], 'a 5-minute job is fine');
    assert.equal(C['deadlocks|ORCLPRD|'].value, 2, 'two deadlock lines in the last hour, the older one not counted'); assert.match(C['deadlocks|ORCLPRD|'].detail, /orcl_ora_4411\.trc/);
    assert.equal(C['bulk_delete_rows|ORCLPRD|9xyz123abc456'].level, 'warn'); assert.match(C['bulk_delete_rows|ORCLPRD|9xyz123abc456'].detail, /table APP\.CLAIMS · by APPUSER/);
    const pkg = C['code_change|ORCLPRD|APP.PKG_CLAIMS (PACKAGE BODY)']; assert.ok(pkg); assert.match(pkg.detail, /PACKAGE BODY changed .* by ALI\.SYN \(ali@pc-17\)/);
    assert.ok(!C['code_change|ORCLPRD|APP.TRG_AUDIT (TRIGGER)'], 'a change made by SYS AS SYSDBA is left out');
    assert.match(C['code_change|ORCLPRD|APP.FN_RATE (FUNCTION)'].detail, /created .* now INVALID · by not recorded \(no audit policy/);
    assert.match(C['table_truncate|ORCLPRD|APP.CLAIMS_TMP'].detail, /TRUNCATE TABLE .* by BATCH\.SYN/);
    assert.match(C['code_change|ORCLPRD|APP.OLD_PROC (PROCEDURE)'].detail, /DROP PROCEDURE .* by ALI\.SYN/);
    assert.equal(C['rac_node_down|ORCLPRD|2'].level, 'crit'); assert.match(C['rac_node_down|ORCLPRD|2'].detail, /node ORCLPRD2 · on db1b/); assert.ok(!C['rac_node_down|ORCLPRD|1']);
    assert.equal(C['dr_link|ORCLPRD|ORCL_DR'].level, 'crit'); assert.match(C['dr_link|ORCLPRD|ORCL_DR'].detail, /apply IDLE/);
    // one e-mail: the critical ones and these warnings together, each line with its detail
    assert.equal(t.mails.length, 1); const m = t.mails[0].text;
    for (const rx of [/ASM disk group used: 82 %/, /Long-running query.*user APPUSER/, /Scheduler job running long: 25 min.*APP\.NIGHTLY_LOAD/, /Deadlocks: 2/, /Bulk delete: 15000.*APP\.CLAIMS/,
      /Code changed.*ALI\.SYN/, /Table truncated - TRUNCATE TABLE/, /RAC node down - node ORCLPRD2/, /DR \(Data Guard\) link failing/]) assert.match(m, rx);
    assert.doesNotMatch(m, /TRG_AUDIT/, 'SYS change not mailed');
    // thresholds: the event rules are on / off only; the catalogue says which warnings are mailed at once
    const P = t.D.policy(), tc = P.metrics.find((x) => x.id === 'code_change');
    assert.equal(tc.kind, 'event'); assert.equal(tc.mail_warn, true); assert.equal(P.metrics.find((x) => x.id === 'ts_used_pct').warn, 87);
    assert.throws(() => t.D.savePolicy({ reason: 'test', metrics: { asm_used_pct: { warn: 95, crit: 90 } } }, 'ahmed'), /critical must be at or above warning/);
    // an hour later nothing new: the deadlock and code-change events clear
    W.set(W.now + 70 * 60000); W.R.latest = W.R.latest.filter((x) => !/^code-change/.test(x.act)).map((x) => Object.assign({}, x, { last_ms: W.now - 60000 }));
    await t.D.tick();
    const C2 = byMetric(t.D);
    assert.ok(!C2['deadlocks|ORCLPRD|'], 'no deadlock in the last hour: cleared');
    assert.ok(!C2['code_change|ORCLPRD|APP.PKG_CLAIMS (PACKAGE BODY)'], 'a code change is an event: it ages out of its window');
    const old = t.D.conditions({ status: 'cleared' }).find((c) => c.metric === 'code_change' && /PKG_CLAIMS/.test(c.key));
    assert.ok(old && old.history.some((h) => /event older than its window/.test(h.what)) && old.notified, 'kept in the history, after it was mailed');
    assert.ok(C2['rac_node_down|ORCLPRD|2'], 'a node still down stays open');
  } finally { t.done(); }
});

test('parser: scheduler job, bulk delete, code change and who (SYS / SYSDBA excluded)', () => {
  const H = require('../engine/db-audit/oracle-health');
  const p = (o) => H.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'db1', instance: 'ORCLPRD', t: '2026-10-21T08:00:00Z' }, o)));
  const j = p({ kind: 'sched_job', owner: 'app', job_name: 'nightly', elapsed_s: 1500 }); assert.equal(j.action, 'sched-job'); assert.equal(j.fields.key, 'APP.NIGHTLY'); assert.equal(j.severity, 2);
  const b = p({ kind: 'bulk_delete', sql_id: '9xyz123abc456', rows_deleted: 15000, table: 'APP.CLAIMS', user: 'APPUSER', sql_text: 'delete from app.claims where id < :1', period_s: 300 });
  assert.equal(b.action, 'bulk-delete'); assert.equal(b.severity, 3); assert.equal(b.fields.db_user, 'APPUSER'); assert.match(b.message, /15000 row\(s\) deleted on ORCLPRD from APP\.CLAIMS by APPUSER/);
  const c = p({ kind: 'code_change', owner: 'APP', name: 'PKG', type: 'PACKAGE BODY', ddl_time: '2026-10-21T10:40:00', status: 'INVALID' }); assert.equal(c.action, 'code-change'); assert.match(c.message, /now INVALID/);
  const w1 = p({ kind: 'code_change_by', owner: 'APP', name: 'PKG', user: 'ALI.SYN', action: 'ALTER PACKAGE BODY', at: '2026-10-21T07:40:00Z', sysdba: 'N', oracle_user: 'N' });
  assert.equal(w1.fields.excluded, 'N'); assert.equal(w1.severity, 2);
  for (const o of [{ user: 'SYS' }, { user: 'DBA1', sysdba: 'Y' }, { user: 'MDSYS', oracle_user: 'Y' }]) assert.equal(p(Object.assign({ kind: 'code_change_by', owner: 'APP', name: 'PKG', action: 'ALTER PACKAGE', at: 'x' }, o)).fields.excluded, 'Y', JSON.stringify(o));
});

test('Thursday digest: before the weekend - tablespaces forecast to fill, FRA / ASM near the threshold, unacknowledged problems', async () => {
  const t = setup(U('2026-10-22T05:00:00Z'));   // Thursday 08:00 Riyadh - Friday and Saturday are the weekend
  try {
    const r = t.W.row;
    t.W.R.latest = [r('ORCLPRD', 'health-sample', '', { status: 'OPEN' }), r('ORCLPRD', 'tablespace-growth', 'USERS', { days_to_full: '2.5' }, 60), r('ORCLPRD', 'tablespace-growth', 'INDX', { days_to_full: '40' }, 60),
      r('ORCLPRD', 'fra-usage', '', { used_pct: '74' }), r('ORCLPRD', 'asm-diskgroup', 'DATA', { used_pct: '83' })];
    await t.D.evaluate();
    const d = t.D.digest(t.W.now);
    assert.ok(d.before_weekend, 'Thursday carries the before-the-weekend list'); assert.equal(d.before_weekend.next, '2026-10-25'); assert.equal(d.before_weekend.days, 3);
    const w = d.before_weekend.items.map((x) => x.what).join(' | ');
    assert.match(w, /USERS tablespace forecast full in 2\.5 day/); assert.doesNotMatch(w, /INDX/); assert.match(w, /FRA\) 74 % used/); assert.match(w, /ASM DATA 83 % used/);
    assert.match(d.html, /Before the weekend - next working day 2026-10-25/); assert.match(d.subject, /before the weekend$/); assert.match(d.text, /Before the weekend/);
    const wed = t.D.digest(U('2026-10-21T05:00:00Z'));
    assert.equal(wed.before_weekend, null, 'Wednesday has no weekend list');
  } finally { t.done(); }
});

test('connections: an application that dropped off and listener refusals are mailed with the meaning and fix', async () => {
  const t = setup();
  try {
    const W = t.W, r = W.row;
    W.R.latest = [r('ORCLPRD', 'health-sample', '', { status: 'OPEN' }),
      r('ORCLPRD', 'app-session', 'CLAIMS|app01|JDBC|CLAIMS_APP', { service: 'CLAIMS', machine: 'app01', program: 'JDBC', db_user: 'CLAIMS_APP', sessions: '40' }, 2),
      r('ORCLPRD', 'app-session', 'HR|hrapp|w3wp.exe|HR_APP', { service: 'HR', machine: 'hrapp', program: 'w3wp.exe', db_user: 'HR_APP', sessions: '12' }, 95),
      r('ORCLPRD', 'app-session', 'BATCH|b1|sqlplus|ETL', { service: 'BATCH', machine: 'b1', program: 'sqlplus', db_user: 'ETL', sessions: '1' }, 300),
      r('ORCLPRD', 'lsnr-conn', 'CLAIMS|10.20.1.15|JDBC|12519', { service: 'CLAIMS', client_host: '10.20.1.15', program: 'JDBC', code: '12519', n: '25' }, 20),
      r('ORCLPRD', 'lsnr-conn', 'CLAIMS|10.20.1.15|JDBC|0', { service: 'CLAIMS', client_host: '10.20.1.15', code: '0', n: '300' }, 20)];
    t.D.saveNotify({ recipients: ['dba@as.example'], digest: { enabled: false } }, 'ahmed');
    await t.D.tick();
    const C = byMetric(t.D);
    const d = C['app_disconnected|ORCLPRD|HR|hrapp|w3wp.exe|HR_APP']; assert.ok(d); assert.equal(d.level, 'warn'); assert.match(d.detail, /w3wp\.exe on hrapp as HR_APP \(service HR\) had 12 session\(s\) at .* none now/);
    assert.ok(!C['app_disconnected|ORCLPRD|BATCH|b1|sqlplus|ETL'], 'a one-session batch job coming and going is not an outage');
    assert.ok(!Object.keys(C).some((k) => k.startsWith('app_disconnected') && k.includes('app01')), 'still connected');
    const l = C['listener_refused|ORCLPRD|CLAIMS|10.20.1.15|JDBC|12519']; assert.equal(l.level, 'warn'); assert.match(l.detail, /TNS-12519 no appropriate service handler found · from 10\.20\.1\.15 · JDBC · service CLAIMS · The database has reached its processes limit/);
    assert.ok(!Object.keys(C).some((k) => k.startsWith('listener_refused') && k.endsWith('|0')), 'successful connects are not a problem');
    assert.match(t.mails[0].text, /Application disconnected: 12 sessions \(threshold 3\) - w3wp\.exe on hrapp/); assert.match(t.mails[0].text, /Listener refused connections: 25/);
    // the application reconnects: cleared
    W.R.latest = W.R.latest.map((x) => (x.act === 'app-session' && x.k.startsWith('HR') ? Object.assign({}, x, { last_ms: W.now - 60000 }) : x));
    await t.D.tick();
    assert.ok(!byMetric(t.D)['app_disconnected|ORCLPRD|HR|hrapp|w3wp.exe|HR_APP'], 'reconnected: cleared');
  } finally { t.done(); }
});

test('parser: app sessions, listener lines, DB links, user write rights', () => {
  const H = require('../engine/db-audit/oracle-health');
  const p = (o) => H.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'db1', instance: 'ORCLPRD', t: '2026-10-21T08:00:00Z' }, o)));
  const a = p({ kind: 'app_session', service: 'CLAIMS', machine: 'app01', program: 'JDBC', db_user: 'CLAIMS_APP', sessions: 40, active: 3 });
  assert.equal(a.action, 'app-session'); assert.equal(a.fields.key, 'CLAIMS|app01|JDBC|CLAIMS_APP');
  const l = p({ kind: 'lsnr_conn', service: 'CLAIMS', client_host: '10.20.1.15', program: 'JDBC', code: '12514', n: 8 }); assert.equal(l.severity, 3); assert.match(l.message, /REFUSED connection\(s\) \(TNS-12514\)/);
  assert.equal(p({ kind: 'lsnr_conn', service: 'X', client_host: 'h', code: '0', n: 2 }).severity, 0);
  const k = p({ kind: 'db_link', owner: 'app', link: 'to_fin', remote_user: 'FIN_RO', host: 'FINPRD' }); assert.equal(k.action, 'db-link'); assert.equal(k.fields.key, 'APP.TO_FIN');
  const w = p({ kind: 'user_write', db_user: 'finowner', dba: 'DBA', own_tables: 220 }); assert.equal(w.action, 'user-write'); assert.equal(w.fields.key, 'FINOWNER'); assert.match(w.message, /roles DBA/);
});
