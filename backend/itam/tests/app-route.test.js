// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Route Map (engine/app-route.js + pyengine/app_route.py): the register of applications kept by an administrator
// (validated, versioned - a stale version is refused, every change audited with what changed), and the judgement of each hop
// from facts the page read in the SIEM: an APM monitor down / unmanaged, a client machine that dropped off, listener
// refusals with their TNS fix, a RAC database with one instance down (degraded, not down), a database not monitored, no
// session reading (not checked, never "working"), client machines no application claims offered as discovered.
// Roles: viewer reads and judges, only an administrator changes the register. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerAppRouteRoutes, cleanFacts } = require('../engine/app-route');

const ADM = { user: 'syed', role: 'admin' }, OPR = { user: 'omar.syn', role: 'operator' }, VWR = { user: 'v.syn', role: 'viewer' };
const call = (e, m, p, who, b) => e.req(m, p, { user: who.user, role: who.role, body: b });
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (r) => { audits.push(r); if (orig) orig.call(e.app, r); };
  registerAppRouteRoutes(e.app.srv, e.app, {});
  return { e, audits };
}
const FACTS = {
  apm: { connected: true },
  monitors: [{ id: '101', name: 'Claims portal URL', type: 'URL', host: 'claims.corpgroup.test', availability: 'up', health: 'clear' },
    { id: '102', name: 'Claims API', type: 'REST API', availability: 'down', health: 'critical', message: 'HTTP 503 <img src=x>' },
    { id: '103', name: 'Policy API', type: 'REST API', availability: 'up', health: 'clear', managed: false },
    { id: '200', name: 'HR portal', type: 'URL', availability: 'up', health: 'clear' }],
  databases: [{ database: 'ESP', instances: [{ instance: 'ESP1', host: 'db1', level: 'ok', status: 'OPEN' }, { instance: 'ESP2', host: 'db2', level: 'ok', status: 'MOUNTED' }] },
    { database: 'ODS', instances: [{ instance: 'ODS', host: 'db3', level: 'crit', crit: 2, status: 'OPEN' }] }],
  sessions: { ESP: { reported: true, apps: [{ machine: 'APPSRV1.corpgroup.test', program: 'w3wp.exe', service: 'CLAIMS', sessions: 40, state: 'connected' },
    { machine: 'appsrv2', program: 'java', service: 'CLAIMS', sessions: 0, state: 'dropped' }, { machine: 'BATCH9', program: 'sqlplus', service: 'ESP', sessions: 2, state: 'connected' }] } },
  listener: { ESP: [{ client_host: 'appsrv2', service: 'CLAIMS', refused: 7, reasons: [{ code: '12514', meaning: 'service not known to the listener', fix: 'Check the service name.', n: 7 }] }] },
};
const CLAIMS = { name: 'Claims', url: 'https://claims.corpgroup.test', front_monitor: '101', api_monitors: ['102', '103'], machines: ['appsrv1', 'appsrv2'], database: 'esp', services: ['claims'] };

test('app route: register by an administrator only - validated, versioned, audited with what changed; viewer and operator refused', async (t) => {
  const { e, audits } = await setup(t);
  let r = await call(e, 'POST', '/app-route/apps', OPR, Object.assign({ baseVersion: 0 }, CLAIMS)); assert.equal(r.status, 403, 'operator refused');
  r = await call(e, 'POST', '/app-route/apps', VWR, CLAIMS); assert.equal(r.status, 403, 'viewer refused');
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({}, CLAIMS, { machines: ['bad host!'] })); assert.equal(r.status, 400); assert.match(r.json.error, /machines must be host names/);
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({}, CLAIMS, { database: "ESP' OR 1=1" })); assert.equal(r.status, 400); assert.match(r.json.error, /database must be/);
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({}, CLAIMS, { url: 'javascript:alert(1)' })); assert.equal(r.status, 400); assert.match(r.json.error, /url must start/);
  r = await call(e, 'POST', '/app-route/apps', ADM, { url: 'https://x.test' }); assert.equal(r.status, 400); assert.match(r.json.error, /name/);
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({ baseVersion: 0, owner_password: 'x' }, CLAIMS)); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.app.id, 'claims'); assert.equal(r.json.app.database, 'ESP'); assert.deepEqual(r.json.app.services, ['CLAIMS']); assert.equal(r.json.app.owner_password, undefined, 'undeclared field dropped');
  const a = audits.find((x) => x.action === 'app_route.app.create'); assert.ok(a && a.by === 'syed' && a.role === 'admin' && a.target === 'claims' && a.detail.version === 1);
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({ baseVersion: 0 }, CLAIMS, { id: 'claims', machines: ['appsrv1'] })); assert.equal(r.status, 409, 'stale version refused'); assert.match(r.json.error, /changed since you opened it/);
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({ baseVersion: 1 }, CLAIMS, { id: 'claims', machines: ['appsrv1', 'appsrv2', 'appsrv3'] })); assert.equal(r.status, 200, r.text);
  assert.deepEqual(audits.find((x) => x.action === 'app_route.app.update').detail.changed, ['machines'], 'the audit says what changed');
  r = await call(e, 'POST', '/app-route/apps', ADM, Object.assign({}, CLAIMS)); assert.equal(r.status, 409, 'same name twice refused');
  r = await call(e, 'GET', '/app-route/profile', VWR); assert.equal(r.status, 200); assert.equal(r.json.version, 2); assert.equal(r.json.apps.length, 1);
  r = await call(e, 'DELETE', '/app-route/apps/claims', OPR); assert.equal(r.status, 403);
  r = await call(e, 'DELETE', '/app-route/apps/claims', ADM); assert.equal(r.status, 400); assert.match(r.json.error, /baseVersion/);
  r = await call(e, 'DELETE', '/app-route/apps/claims?baseVersion=2', ADM); assert.equal(r.status, 200);
  assert.ok(audits.some((x) => x.action === 'app_route.app.delete' && x.target === 'claims'));
});

test('app route: each hop judged from the facts - monitor down, unmanaged, dropped machine + refusals, RAC degraded, discovered', async (t) => {
  const { e } = await setup(t);
  await call(e, 'POST', '/app-route/apps', ADM, Object.assign({ baseVersion: 0 }, CLAIMS));
  await call(e, 'POST', '/app-route/apps', ADM, { name: 'Data warehouse', database: 'ODS', machines: ['etl1'], baseVersion: 1 });
  await call(e, 'POST', '/app-route/apps', ADM, { name: 'Unlinked app', baseVersion: 2 });
  const r = await call(e, 'POST', '/app-route', VWR, { facts: FACTS }); assert.equal(r.status, 200, r.text);
  const by = Object.fromEntries(r.json.apps.map((a) => [a.name, a]));
  const c = by.Claims;
  assert.equal(c.front.state, 'ok'); assert.equal(c.apis[0].state, 'down'); assert.equal(c.apis[1].state, 'not_checked', 'unmanaged monitor: nothing checks it');
  assert.equal(c.servers[0].state, 'ok', 'appsrv1 matched by short name'); assert.equal(c.servers[0].sessions, 40);
  assert.equal(c.servers[1].state, 'bad', 'appsrv2 dropped off and refused');
  assert.ok(c.issues.some((i) => /refused 7 connection/.test(i.title) && i.evidence.some((x) => /TNS-12514/.test(x)) && i.fix.includes('Check the service name.')));
  assert.equal(c.service.state, 'bad', 'service with refusals');
  assert.equal(c.db.state, 'warn', 'RAC with one instance not open is degraded, not down'); assert.match(c.db.issues[0].title, /ESP2 not open/);
  assert.equal(c.state, 'down', 'the route is as bad as its worst hop');
  assert.equal(by['Data warehouse'].db.state, 'bad'); assert.ok(by['Data warehouse'].issues.some((i) => /2 critical/.test(i.title)));
  assert.equal(by['Data warehouse'].servers[0].state, 'not_checked', 'no session reading for ODS: not checked, never working');
  assert.equal(by['Unlinked app'].state, 'not_connected'); assert.ok(by['Unlinked app'].issues.some((i) => /No database linked/.test(i.title)));
  assert.deepEqual(r.json.discovered.map((d) => d.machine), ['BATCH9'], 'a client machine no application claims is offered');
  assert.deepEqual(r.json.unlinked_monitors.map((m) => m.id), ['200'], 'monitors nobody linked');
  assert.equal(r.json.summary.down, 1);
  const v = await call(e, 'POST', '/app-route', VWR, { facts: Object.assign({}, FACTS, { sessions: null }) });
  assert.equal(v.json.apps.find((a) => a.name === 'Claims').servers[0].state, 'not_checked', 'a role that cannot see sessions: not checked');
  assert.equal(v.json.summary.sessions_visible, false);
  const n = await call(e, 'POST', '/app-route', VWR, { facts: Object.assign({}, FACTS, { apm: { connected: false } }) });
  assert.equal(n.json.apps.find((a) => a.name === 'Claims').front.state, 'not_connected', 'APM not connected: says so');
  const bad = await call(e, 'POST', '/app-route', VWR, { facts: [1] }); assert.equal(bad.status, 400); assert.match(bad.json.error, /facts must be an object/);
});

test('app route: the facts are cleaned - unknown fields dropped, strings clipped, bad database names ignored', () => {
  const f = cleanFacts({ monitors: [{ id: 1, name: 'x'.repeat(500), password: 'p' }], databases: [{ database: 'A; DROP', instances: [] }, { database: 'esp', instances: [{ instance: 'esp1', level: 'ok', secret: 's' }] }],
    sessions: { "x'y": { reported: true, apps: [] }, esp: { reported: true, apps: [{ machine: 'm', sessions: -5, db_user: 'SCOTT' }] } }, extra: 1 });
  assert.equal(f.monitors[0].name.length, 160); assert.equal(f.monitors[0].password, undefined);
  assert.deepEqual(f.databases.map((d) => d.database), ['ESP']); assert.equal(f.databases[0].instances[0].secret, undefined);
  assert.deepEqual(Object.keys(f.sessions), ['ESP']); assert.equal(f.sessions.ESP.apps[0].sessions, 0); assert.equal(f.sessions.ESP.apps[0].db_user, undefined, 'database users never reach the rules (PDPL)');
  assert.equal(f.extra, undefined); assert.equal(cleanFacts({}).sessions, null);
});
