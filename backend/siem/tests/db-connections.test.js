// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Connections (engine/db-audit/connections.js): applications per database from the latest pass, dropped ones,
// listener connects / refusals per client with meaning and fix, timeouts the database recorded per client, DB links and
// whether their remote user can change data on a monitored remote database; validation, operator only. Synthetic data.
const test = require('node:test');
const assert = require('node:assert/strict');
const cn = require('../engine/db-audit/connections');

const NOW = Date.UTC(2026, 9, 26, 10, 0);
const row = (inst, k, f, agoMin) => ({ inst, k, f, last_ms: NOW - agoMin * 60000 });
const DATA = {
  cn_app_session: [
    row('ORCLPRD', 'CLAIMS|app01|JDBC Thin Client|CLAIMS_APP', { service: 'CLAIMS', machine: 'app01', program: 'JDBC Thin Client', db_user: 'CLAIMS_APP', module: 'claims-api', sessions: '42', active: '3', max_idle_s: '900', oldest_logon: '2026-10-26T06:00:00', instances: '2' }, 2),
    row('ORCLPRD', 'CLAIMS|app02|JDBC Thin Client|CLAIMS_APP', { service: 'CLAIMS', machine: 'app02', program: 'JDBC Thin Client', db_user: 'CLAIMS_APP', sessions: '40', active: '1' }, 3),
    row('ORCLPRD', 'HR|hrapp|w3wp.exe|HR_APP', { service: 'HR', machine: 'hrapp', program: 'w3wp.exe', db_user: 'HR_APP', sessions: '12' }, 95),
  ],
  cn_lsnr_conn: [
    row('ORCLPRD', 'CLAIMS|10.20.1.15|JDBC|0', { service: 'CLAIMS', client_host: '10.20.1.15', program: 'JDBC', code: '0', n: '300', last: '2026-10-26T09:50:00Z' }, 10),
    row('ORCLPRD', 'CLAIMS|10.20.1.15|JDBC|12519', { service: 'CLAIMS', client_host: '10.20.1.15', program: 'JDBC', code: '12519', n: '25', last: '2026-10-26T09:51:00Z' }, 10),
    row('ORCLPRD', 'CLAIMSX|10.20.1.16|?|12514', { service: 'CLAIMSX', client_host: '10.20.1.16', code: '12514', n: '8' }, 10),
  ],
  cn_alert: [{ t: NOW - 3600000, tail: 'Fatal NI connect error 12170.\n  TNS-12535: TNS:operation timed out\n  Client address: (ADDRESS=(PROTOCOL=tcp)(HOST=10.20.1.15)(PORT=51234))\nsomething else\n  Client address: (ADDRESS=(PROTOCOL=tcp)(HOST=10.9.9.9)(PORT=1))' }],
  cn_db_link: [
    row('ORCLPRD', 'APP.TO_FIN', { owner: 'APP', link: 'TO_FIN', remote_user: 'FIN_RO', host: '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.6.5)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FINPRD.corpgroup.local)))' }, 60),
    row('ORCLPRD', 'PUBLIC.TO_FIN_ADMIN', { owner: 'PUBLIC', link: 'TO_FIN_ADMIN', remote_user: 'FINOWNER', host: 'FINPRD' }, 60),
    row('ORCLPRD', 'APP.TO_HR', { owner: 'APP', link: 'TO_HR', remote_user: 'HRREAD', host: 'hrdb:1521/HRPRD' }, 60),
    row('ORCLPRD', 'APP.TO_LEGACY', { owner: 'APP', link: 'TO_LEGACY', remote_user: 'X', host: 'LEGACYDB' }, 60),
    row('ORCLPRD', 'APP.CU', { owner: 'APP', link: 'CU', remote_user: '', host: 'FINPRD' }, 60),
  ],
  cn_user_write: [
    row('FINPRD', 'FIN_RO', { db_user: 'FIN_RO', own_tables: '0', obj_write: '0' }, 60),
    row('FINPRD', 'FINOWNER', { db_user: 'FINOWNER', dba: 'DBA', any_dml: 'DELETE ANY TABLE', own_tables: '220', obj_write: '0' }, 60),
    row('HRPRD', 'HRREAD', { db_user: 'HRREAD', own_tables: '0', obj_write: '14' }, 60),
  ],
};
function harness() {
  const routes = {}, calls = [];
  const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, p }); return (DATA[tag] || []).map((r) => Object.assign({}, r)); } };
  cn.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  const call = async (q, role = 'operator') => { let out = null; const ctx = { query: q, role, user: 'dba.syn', ok: (x) => { out = { status: 200, body: x }; return out; }, fail: (s, m) => { out = { status: s, error: m }; return out; },
    need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out = { status: 403, error: 'requires ' + r }; return false; } return true; } };
    await routes['GET /api/soc/db/oracle/connections'](ctx); return out; };
  return { call, calls };
}

test('applications connected and dropped, listener refusals with meaning and fix, client timeouts', async () => {
  const h = harness();
  const r = await h.call({ instance: 'orclprd' }); assert.equal(r.status, 200); const v = r.body;
  assert.equal(v.summary.applications, 2); assert.equal(v.summary.sessions, 82); assert.equal(v.summary.dropped, 1);
  const hr = v.applications.find((a) => a.machine === 'hrapp'); assert.equal(hr.state, 'dropped'); assert.equal(hr.last_sessions, 12); assert.equal(hr.sessions, 0);
  assert.equal(v.applications[0].state, 'dropped', 'dropped applications first');
  const a1 = v.applications.find((a) => a.machine === 'app01'); assert.equal(a1.state, 'connected'); assert.equal(a1.sessions, 42); assert.equal(a1.instances, 2);
  const c = v.listener.find((x) => x.client_host === '10.20.1.15'); assert.equal(c.ok, 300); assert.equal(c.refused, 25);
  assert.match(c.reasons[0].meaning, /no appropriate service handler/); assert.match(c.reasons[0].fix, /processes limit/);
  assert.match(v.listener.find((x) => x.service === 'CLAIMSX').reasons[0].meaning, /service not known/);
  assert.equal(v.summary.refused, 33);
  assert.deepEqual(v.timeouts.map((x) => [x.client_host, x.n]), [['10.20.1.15', 1]], 'only an address that follows a network error counts');
  const q = h.calls.find((x) => x.tag === 'cn_app_session'); assert.equal(q.p.inst.value, 'ORCLPRD'); assert.ok(!q.sql.includes('ORCLPRD'), 'parameters only');
});

test('DB links: write rights of the remote user judged on the monitored remote database', async () => {
  const v = (await harness().call({ instance: 'ORCLPRD' })).body;
  const L = Object.fromEntries(v.links.map((l) => [l.link, l]));
  assert.equal(L.TO_FIN.remote_db, 'FINPRD', 'SERVICE_NAME with a domain matched'); assert.equal(L.TO_FIN.verdict, 'read_only');
  assert.equal(L.TO_FIN_ADMIN.verdict, 'write_all'); assert.ok(L.TO_FIN_ADMIN.why.includes('role DBA') && L.TO_FIN_ADMIN.why.includes('DELETE ANY TABLE')); assert.match(L.TO_FIN_ADMIN.fix, /least-privileged user on FINPRD/);
  assert.equal(L.TO_HR.remote_db, 'HRPRD', 'EZConnect host:port/service'); assert.equal(L.TO_HR.verdict, 'write_some'); assert.match(L.TO_HR.why.join(' '), /14 table\(s\) of other schemas/);
  assert.equal(L.TO_LEGACY.verdict, 'not_monitored'); assert.equal(L.CU.verdict, 'current_user');
  assert.equal(v.links[0].verdict, 'write_all', 'worst first'); assert.equal(v.summary.links_write, 2);
});

test('validation and roles', async () => {
  const h = harness();
  assert.equal((await h.call({ instance: "x' or 1=1" })).status, 400);
  assert.equal((await h.call({})).status, 400);
  assert.equal((await h.call({ instance: 'ORCLPRD' }, 'viewer')).status, 403, 'viewer refused: machines, programs and users');
  assert.equal(cn.createConnections({}).remoteOf('(DESCRIPTION=(CONNECT_DATA=(SID=HRPRD)))', ['HRPRD']), 'HRPRD');
});
