// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DLP analysis and reports: SQL shape (ClickHouse alias rule, bound filters), itemised person risk, viewer without names,
// CSV with the filter written in and formula-safe cells, report HTML escaped, schedule + send-now through the SMTP relay.
// ClickHouse is a fake that answers by the /* sentra:dlp-… */ tag; rows are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createDlp, riskOf } = require('../engine/reports/dlp');
const routes = require('../engine/reports/dlp-routes');
const { aliasViolations } = require('../engine/reports/common');
const { createState } = require('../engine/soc/state');
const { createBusinessHoursStore } = require('../engine/util/business-hours');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const NOW = Date.parse('2026-10-21T09:00:00Z');
const ROWS = {
  'dlp-totals': [{ n: 42, n_left: 6, n_blocked: 30, n_enc: 2, n_unreported: 4, n_users: 5, n_hosts: 6, n_high: 9, n_ah: 7, n_matches: 1200 }],
  'dlp-channels': [{ c: 'USB', n: 20, n_left: 2, n_blocked: 18 }, { c: 'removable media', n: 5, n_left: 0, n_blocked: 5 }, { c: 'web upload', n: 10, n_left: 4, n_blocked: 6 }, { c: '', n: 7, n_left: 0, n_blocked: 1 }],
  'dlp-policies': [{ p: 'Confidential-USB', n: 25, n_left: 2, n_blocked: 23, people: 3 }],
  'dlp-classes': [{ k: 'National ID', n: 12, n_left: 3 }, { k: 'Project code', n: 4, n_left: 0 }],
  'dlp-actions': [{ a: 'blocked', n: 30 }, { a: '', n: 4 }],
  'dlp-sources': [{ v: 'somansa', pr: 'Privacy-i', s: 'somansa-hq', n: 42, last_ms: NOW - 6e5 }],
  'dlp-trend': [],
  'dlp-users': [
    { u: 'fahad', n: 15, n_left: 5, n_blocked: 10, n_high: 6, n_ah: 6, n_matches: 800, n_chan: 3, chans: ['usb', 'web upload', 'print'], classes: ['National ID', 'IBAN'], hosts: ['fin-pc07'], last_ms: NOW - 36e5 },
    { u: 'sara', n: 2, n_left: 0, n_blocked: 2, n_high: 0, n_ah: 0, n_matches: 3, n_chan: 1, chans: ['usb'], classes: ['Project code'], hosts: ['hr-pc02'], last_ms: NOW - 72e5 },
    { u: '=cmd|calc', n: 1, n_left: 1, n_blocked: 0, n_high: 0, n_ah: 0, n_matches: 1, n_chan: 1, chans: ['web'], classes: [], hosts: [], last_ms: NOW }],
  'dlp-hosts': [{ h: 'fin-pc07', n: 15, n_left: 5, people: 1, last_ms: NOW }],
  'dlp-dests': [{ d: 'https://files.example/upload', n: 3, people: 1 }],
  'dlp-tamper': [{ t: NOW - 5e6, user: 'fahad', host: 'fin-pc07', pr: 'Privacy-i', message: 'agent stopped <script>' }],
  'dlp-events': [{ t: NOW - 1e6, user: 'fahad', host: 'fin-pc07', src_id: 'somansa-hq', severity: 3, act: 'permitted', chan: 'usb', pol: 'Confidential-USB', cls: 'National ID', vendor: 'somansa', product: 'Privacy-i', dest: 'E:\\', file: '=HYPERLINK("x")', incident_id: '100245', dsev: 'High', matches: 37, ah: 1, message: 'm' }],
};
function fakeCh() {
  const calls = [];
  return { calls, async query(sql, params) { calls.push({ sql, params }); const m = /\/\* sentra:([a-z-]+) \*\//.exec(sql); if (!m) throw new Error('untagged query'); return ROWS[m[1]] || []; } };
}

test('SQL: every query is tagged, passes the ClickHouse alias rule, and binds filters as parameters', async () => {
  const d = createDlp({ ch: fakeCh(), now: () => NOW, calendar: () => null });
  const S = d.SQL(null);
  for (const [k, v] of Object.entries(S)) {
    if (k === 'params') continue;
    const q = typeof v === 'function' ? v({ user: 'x', host: 'y', policy: 'p', channel: 'c', cls: 'k', left: true }) : v;
    assert.match(q, /\/\* sentra:dlp-/, `${k} tagged`);
    assert.deepEqual(aliasViolations(q), [], `${k}: alias rule`);
  }
  const ch = fakeCh(); const d2 = createDlp({ ch, now: () => NOW, calendar: () => null });
  await d2.events({ user: "o'brien", policy: "x' OR 1=1 --", limit: 99999 });
  const c = ch.calls[0];
  assert.doesNotMatch(c.sql, /o'brien|OR 1=1/, 'values are never pasted into the SQL');
  assert.equal(c.params.f_user.value, "o'brien"); assert.equal(c.params.f_lim.value, 5000, 'limit capped');
});

test('risk is an itemised weighted sum; viewer gets no names', async () => {
  const r = riskOf(ROWS['dlp-users'][0], new Map([['fahad', 1]]));
  assert.equal(r.score, 100);
  const reasons = r.why.map((w) => w.reason).join(' | ');
  assert.match(reasons, /5 incident\(s\) where the DLP product let the data go/);
  assert.match(reasons, /National ID .*Bank account \/ IBAN|sensitive data class/);
  assert.match(reasons, /DLP agent or protection disabled 1 time/);
  assert.equal(r.why.reduce((s, w) => s + w.points, 0) >= 100, true);
  assert.equal(riskOf(ROWS['dlp-users'][1], new Map()).score, 0, 'two blocked USB copies of a project file: no score');

  const d = createDlp({ ch: fakeCh(), now: () => NOW, calendar: () => null });
  const op = await d.summary({ period: '30d' }, { names: true });
  assert.equal(op.available, true); assert.equal(op.totals.left, 6); assert.equal(op.totals.tamper, 1);
  assert.equal(op.users[0].user, 'fahad'); assert.equal(op.users[0].tamper, 1);
  const usb = op.channels.find((c) => c.channel === 'usb');
  assert.equal(usb.incidents, 25, 'USB and removable media are one channel');
  assert.ok(op.channels.some((c) => c.channel === 'not reported'), 'a missing channel is "not reported", never guessed');
  assert.equal(op.classes[0].sensitive, 'National ID / Iqama / passport');
  const ch = fakeCh(); const dv = createDlp({ ch, now: () => NOW, calendar: () => null });
  const vw = await dv.summary({ period: '7d' }, { names: false });
  assert.equal(vw.users, null); assert.equal(vw.hosts, null); assert.equal(vw.destinations, null); assert.equal(vw.tamper_events, null);
  assert.ok(!ch.calls.some((c) => /sentra:dlp-(users|hosts|dests)/.test(c.sql)), 'the per-person queries are not even run for a viewer');
  assert.equal(vw.totals.tamper, 1, 'the count is still there');
});

test('a failed panel is null with its error, never zero', async () => {
  const ch = { async query(sql) { if (/dlp-policies/.test(sql)) throw new Error('timeout'); return ROWS[/sentra:([a-z-]+)/.exec(sql)[1]] || []; } };
  const s = await createDlp({ ch, now: () => NOW, calendar: () => null }).summary({}, { names: true });
  assert.equal(s.policies, null); assert.equal(s.clickhouse.ok, false); assert.equal(s.clickhouse.errors[0].panel, 'policies');
  const r = await createDlp({ ch, now: () => NOW, calendar: () => null }).report({}, {});
  assert.match(r.html, /Some figures could not be read/);
});

test('routes: roles, CSV, report, schedule and send-now', async () => {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog });
  const bh = createBusinessHoursStore({ state, log: quietLog });
  const mails = []; let mailOk = true;
  const api = fakeApi();
  const deps = { state, ch: fakeCh(), config: { dlp: { scheduler: false } }, log: quietLog, now: () => NOW,
    reports: { businessHours: bh, schedules: { mail: async (m) => { if (!mailOk) throw Object.assign(new Error('relay refused'), { stage: 'connect' }); mails.push(m); return { accepted: m.to }; }, mailProblems: () => [] } } };
  try {
    routes.register(api, deps);
    let r = await api.call('GET', '/api/soc/dlp/summary?period=30d', { role: 'viewer' });
    assert.equal(r.status, 200); assert.equal(r.body.users, null); assert.equal(r.body.names, false);
    r = await api.call('GET', '/api/soc/dlp/summary?period=30d', { role: 'operator' }); assert.equal(r.body.users[0].user, 'fahad');
    for (const u of ['/api/soc/dlp/events', '/api/soc/dlp/events.csv', '/api/soc/dlp/report.html']) { r = await api.call('GET', u, { role: 'viewer' }); assert.equal(r.status, 403, `${u} refused to a viewer`); }
    r = await api.call('GET', '/api/soc/dlp/events.csv?user=fahad&left=1', { role: 'operator' });
    assert.equal(r.status, 200);
    assert.match(r.body.csv, /^# DLP incidents .* filter: user=fahad left=1; rows: 1/);
    assert.match(r.body.csv, /,"'=HYPERLINK\(""x""\)",/, 'formula cells are neutralised');
    assert.ok(api.audits.some((a) => a.action === 'dlp.events.export' && a.detail.rows === 1));
    r = await api.call('GET', '/api/soc/dlp/report.html?period=30d', { role: 'operator', user: 'rasheed' });
    assert.match(r.body.html, /Data Loss Prevention report/); assert.match(r.body.html, /by rasheed/);
    assert.doesNotMatch(r.body.html, /<script>/, 'collector text is escaped in the report');
    assert.match(r.body.html, /not proof of wrongdoing/);
    assert.ok(api.audits.some((a) => a.action === 'dlp.report.download'));

    r = await api.call('POST', '/api/soc/dlp/schedule', { role: 'operator', body: {} }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/dlp/schedule', { role: 'admin', body: { enabled: true, period: 'daily', at: '07:00', recipients: ['ciso@as.example'] } }); assert.equal(r.status, 400);
    r = await api.call('POST', '/api/soc/dlp/schedule', { role: 'admin', body: { enabled: true, period: 'monthly', at: '07:00', day_of_month: 1, recipients: [] } }); assert.equal(r.status, 400, 'enabled needs a recipient');
    r = await api.call('POST', '/api/soc/dlp/schedule', { role: 'admin', body: { enabled: true, period: 'monthly', at: '07:00', day_of_month: 1, recipients: ['ciso@as.example'] } });
    assert.equal(r.status, 200); assert.ok(r.body.next_at > NOW);
    r = await api.call('POST', '/api/soc/dlp/send-now', { role: 'admin', user: 'syed', body: { period: '30d' } });
    assert.equal(r.status, 200); assert.equal(mails.length, 1);
    assert.deepEqual(mails[0].to, ['ciso@as.example']); assert.match(mails[0].subject, /DLP report/); assert.equal(mails[0].attachments[0].contentType, 'text/html; charset=utf-8');
    mailOk = false;
    r = await api.call('POST', '/api/soc/dlp/send-now', { role: 'admin', body: {} }); assert.equal(r.status, 502); assert.match(r.body.error, /connect: relay refused/);
    r = await api.call('GET', '/api/soc/dlp/schedule', { role: 'admin' }); assert.equal(r.body.last.status, 'failed');
  } finally { deps.dlp.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
