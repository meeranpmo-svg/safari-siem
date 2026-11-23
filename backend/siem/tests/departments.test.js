// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Threats by department (engine/soc/departments.js): attribution account → AD department, enrichment, host → last
// logon user, machine accounts, "Not attributed" reasons, risk per 100 users, no names for viewers, analyst drill-down.
const test = require('node:test');
const assert = require('node:assert/strict');
const D = require('../engine/soc/departments');

const NOW = Date.parse('2026-10-13T10:00:00Z'), H = 3600000;
const USERS = [{ sam: 'ahmed', dept: 'Finance' }, { sam: 'sara', dept: 'Finance' }, { sam: 'omar', dept: 'IT' }, { sam: 'nodept', dept: '' }, { sam: 'old', dept: 'Finance', disabled: true }];
const identity = {
  lookup: (n) => USERS.find((u) => u.sam === String(n).toLowerCase().replace(/^.*\\/, '').replace(/@.*$/, '')) || null,
  size: () => USERS.length, snapshot: () => ({ users: USERS }), meta: () => ({ synced: NOW - H }),
};
const AL = [
  { id: 'A1', rule_name: 'Brute force', severity: 3, status: 'new', ts_last: NOW - H, group: { user: 'CORP\\ahmed' }, tactic: 'credential-access' },
  { id: 'A2', rule_name: 'Malware', severity: 4, status: 'closed-true-positive', ts_last: NOW - 2 * H, group: { host: 'fin-pc-07' } },
  { id: 'A3', rule_name: 'Admin group change', severity: 2, status: 'new', ts_last: NOW - 3 * H, group: { target_user: 'omar' } },
  { id: 'A4', rule_name: 'Port scan', severity: 1, status: 'new', ts_last: NOW - H, group: { src_ip: '203.0.113.9' } },
  { id: 'A5', rule_name: 'Odd logon', severity: 2, status: 'new', ts_last: NOW - H, group: { user: 'stranger' } },
  { id: 'A6', rule_name: 'Odd logon', severity: 2, status: 'new', ts_last: NOW - H, group: { user: 'nodept' } },
  { id: 'A7', rule_name: 'Kerberoast', severity: 3, status: 'new', ts_last: NOW - H, group: { user: 'FIN-PC-07$' } },
  { id: 'A8', rule_name: 'Old', severity: 4, status: 'new', ts_last: NOW - 30 * 24 * H, group: { user: 'ahmed' } },
  { id: 'A9', rule_name: 'DLP', severity: 2, status: 'new', ts_last: NOW - H, group: {}, fields: { user_dept: 'HR' } },
  { id: 'A10', rule_name: 'LR copy', severity: 4, status: 'new', ts_last: NOW - H, group: { user: 'ahmed' }, source: 'logrhythm' },
  { id: 'A11', rule_name: 'Unknown host', severity: 1, status: 'new', ts_last: NOW - H, group: { host: 'lab-9' } },
];
const alerts = { all: (fn) => AL.filter(fn), list: () => { throw new Error('paged list must not be used'); } };
const queries = [];
const ch = { query: async (sql, params) => { queries.push({ sql, params }); return [{ h: 'fin-pc-07', u: 'sara' }]; } };

test('attribution, reasons, risk, trend', async () => {
  const b = await D.build({ alerts, identity, ch, db: 'siem', days: 7, minSev: 0, now: NOW });
  const by = Object.fromEntries(b.items.map((x) => [x.a.id, x]));
  assert.deepEqual([by.A1.dept, by.A1.via, by.A1.user], ['Finance', 'account', 'ahmed']);
  assert.deepEqual([by.A2.dept, by.A2.via, by.A2.user], ['Finance', 'host last logon', 'sara']);
  assert.deepEqual([by.A3.dept, by.A3.via], ['IT', 'target account']);
  assert.deepEqual([by.A4.dept, by.A4.reason], [D.NONE, 'no user or host on the alert']);
  assert.equal(by.A5.reason, 'account not in AD'); assert.equal(by.A6.reason, 'AD account has no department');
  assert.deepEqual([by.A7.dept, by.A7.host], ['Finance', 'fin-pc-07'], 'machine account treated as its host');
  assert.equal(by.A8, undefined, 'outside the window'); assert.equal(by.A10, undefined, 'LogRhythm copies left out');
  assert.deepEqual([by.A9.dept, by.A9.via], ['HR', 'AD enrichment']); assert.equal(by.A11.reason, 'host with no recorded logon');
  assert.equal(queries.length, 1, 'one host lookup for all hosts'); assert.deepEqual(queries[0].params.names.sort(), ['fin-pc-07', 'lab-9']);
  assert.match(queries[0].sql, /logon_type'\] IN \('2','10','11'\)/);
  const s = D.summarise(b, { days: 7, withNames: true });
  const fin = s.departments[0];
  assert.equal(fin.department, 'Finance'); assert.equal(fin.alerts, 3); assert.equal(fin.risk, 7 + 15 + 7);
  assert.equal(fin.users_in_ad, 2, 'disabled accounts not counted'); assert.equal(fin.risk_per_100_users, 1450);
  assert.equal(fin.open, 2); assert.deepEqual(fin.severity, { info: 0, low: 0, medium: 0, high: 2, critical: 1 });
  assert.deepEqual(fin.top_users.sort(), ['ahmed', 'sara']); assert.equal(fin.trend.length, 7); assert.equal(fin.trend[6], 3);
  assert.equal(s.departments[s.departments.length - 1].department, D.NONE, '"Not attributed" listed last');
  assert.equal(s.total_alerts, 9); assert.equal(s.not_attributed, 4);
  assert.deepEqual(s.departments.find((d) => d.department === D.NONE).not_attributed_reasons, { 'no user or host on the alert': 1, 'account not in AD': 1, 'AD account has no department': 1, 'host with no recorded logon': 1 });
  assert.equal(D.summarise(b, { days: 7, withNames: false }).departments[0].top_users, undefined, 'viewers get no names');
});

test('no AD sync: everything is "Not attributed" with that reason; min severity filter', async () => {
  const b = await D.build({ alerts, identity: null, ch: null, db: 'siem', days: 7, minSev: 3, now: NOW });
  assert.ok(b.items.every((x) => x.dept === D.NONE || x.via === 'AD enrichment'));
  assert.ok(b.items.every((x) => x.a.severity >= 3));
  assert.equal(b.items.find((x) => x.a.id === 'A1').reason, 'no AD sync');
});

test('routes: viewer sees totals without names, drill-down needs analyst and is audited', async () => {
  const R = {}, audits = [];
  D.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { alerts, identity, ch, config: {}, log: { error() {} }, now: () => NOW });   // fixed clock: the fixtures are dated
  const call = async (p, role, params = {}) => { const out = {}; await R['GET /api/soc' + p]({ role, user: 'u', query: { days: '7' }, params, need: () => true, audit: (a, t) => audits.push([a, t]), ok(b) { out.status = 200; out.body = b; }, fail(c, m) { out.status = c; out.error = m; } }); return out; };
  const v = await call('/threats/departments', 'viewer');
  assert.equal(v.status, 200); assert.ok(!JSON.stringify(v.body).includes('ahmed') && !JSON.stringify(v.body).includes('sara'));
  assert.equal((await call('/threats/departments/:name', 'viewer', { name: 'Finance' })).status, 403);
  const d = await call('/threats/departments/:name', 'analyst', { name: 'Finance' });
  assert.equal(d.status, 200); assert.equal(d.body.items.length, 3); assert.equal(d.body.items[0].severity, 'critical');
  assert.deepEqual(audits[0], ['threats.department.view', 'Finance']);
});
