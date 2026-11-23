// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ManageEngine Applications Manager integration: settings and write-only key, only the six documented calls, monitors / alarms
// normalised from nested replies, failures named (refused key, not JSON, APM error code) with the key scrubbed, coverage against
// the Database Dashboard, Poll now at once, Unmanage / Manage only after a DIFFERENT person in the right scope approves.
// APM is a fake transport; replies are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/integrations/apm-routes');
const { createMeApm, records } = require('../engine/integrations/me-apm');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const KEY = 'a1b2c3d4e5f6a7b8c9d0';
const MON = { 'response-code': '4000', response: { result: [{ Monitorinfo: [
  { RESOURCEID: '10001', DISPLAYNAME: 'ORCLPRD', TYPE: 'Oracle-DB-server', HEALTHSTATUS: 'critical', AVAILABILITYSTATUS: 'up', HOSTNAME: 'db1' },
  { RESOURCEID: '10002', DISPLAYNAME: 'Claims portal', TYPE: 'UrlMonitor', HEALTHSTATUS: 'clear', AVAILABILITYSTATUS: 'up', HOSTNAME: 'portal' },
  { RESOURCEID: '10003', DISPLAYNAME: 'FINDB', TYPE: 'MSSQL-DB-server', HEALTHSTATUS: 'warning', AVAILABILITYSTATUS: 'down', HOSTNAME: 'sql1', MANAGED: 'false' }] }] } };
const ALM = { 'response-code': '4000', response: { result: [{ Alarm: [
  { RESOURCEID: '10001', DISPLAYNAME: 'ORCLPRD', SEVERITY: 'critical', ATTRIBUTE: 'Tablespace USERS', MESSAGE: 'Tablespace USERS 96% used', MODTIME: '2026-10-21 10:00' },
  { RESOURCEID: '10002', DISPLAYNAME: 'Claims portal', SEVERITY: 'clear', MESSAGE: 'ok' }] }] } };

function fakeTransport(calls, mode) {
  return async (o) => {
    const u = new URL(o.url); calls.push({ path: u.pathname, q: Object.fromEntries(u.searchParams) });
    if (mode.refuse) return { status: 401, text: 'no' };
    if (mode.html) return { status: 200, text: '<html>login</html>' };
    if (mode.down) throw new Error(`connect ECONNREFUSED ${o.url}`);
    const api = u.pathname.split('/').pop();
    if (api === 'ListMonitor') return { status: 200, json: MON };
    if (api === 'ListAlarms') return { status: 200, json: ALM };
    if (api === 'GetMonitorData') return { status: 200, json: { 'response-code': '4000', response: { result: [{ RESOURCEID: '10001', Attribute: [{ DISPLAYNAME: 'Tablespace USERS used', VALUE: '96', UNITS: '%', STATUS: 'critical' }] }] } } };
    if (mode.actFail) return { status: 200, json: { 'response-code': '4004', response: { message: `Invalid resource ${KEY}` } } };
    return { status: 200, json: { 'response-code': '4000', response: { result: [{ message: 'ok' }] } } };
  };
}

test('nested replies are found and normalised', () => {
  assert.equal(records(MON).length, 3);
});

test('settings, write-only key, sync, failures named with the key scrubbed', async () => {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog }); const calls = []; const mode = {};
  const A = createMeApm({ state, config: { me_apm_scheduler: false }, log: quietLog, transport: fakeTransport(calls, mode), dbInstances: () => [{ instance: 'ORCLPRD', host: 'db1' }, { instance: 'HRDB', host: 'db2' }] });
  try {
    assert.throws(() => A.setSettings({ base_url: 'http://apm:9090' }), /https/);
    assert.throws(() => A.setSettings({ base_url: 'https://apm:8443/x?apikey=1' }), /no path parameters/);
    assert.throws(() => A.setSettings({ enabled: true }), /base_url before/);
    A.setSettings({ base_url: 'https://apm.as.local:8443/AppManager' }, 'syed');
    assert.equal(A.settings().base_url, 'https://apm.as.local:8443');
    await assert.rejects(A.test(), /no Applications Manager API key/);
    assert.throws(() => A.setKey('short'), /REST API key/);
    const ks = A.setKey(KEY, 'syed');
    assert.equal(ks.api_key_set, true); assert.equal(JSON.stringify(A.settings()).includes(KEY), false);
    const s = await A.sync();
    assert.equal(s.ok, true); assert.equal(s.monitors, 3); assert.equal(s.db_monitors, 2); assert.equal(s.down, 1); assert.equal(s.unmanaged, 1);
    assert.deepEqual(s.alarms, { critical: 1, warning: 0, db: 1 });
    assert.ok(calls.every((c) => /^\/AppManager\/json\/(ListMonitor|ListAlarms)$/.test(c.path) && c.q.apikey === KEY && c.q.type === 'all'));
    assert.equal(A.alarms({ db: '1' })[0].message, 'Tablespace USERS 96% used');
    const d = await A.monitorData('10001'); assert.equal(d.attributes[0].name, 'Tablespace USERS used'); assert.equal(d.attributes[0].status, 'critical');
    await assert.rejects(A.monitorData('1; drop'), /number/);
    const cov = A.coverage();
    assert.deepEqual(cov.both.map((x) => x.instance), ['ORCLPRD']); assert.deepEqual(cov.apm_only.map((x) => x.name), ['FINDB']); assert.deepEqual(cov.siem_only.map((x) => x.instance), ['HRDB']);
    await assert.rejects(A._call('DeleteMonitor', { resourceid: '1' }), /not an allowed/);

    mode.refuse = true; await A.sync(); assert.match(A.status().error, /refused the key/); mode.refuse = false;
    mode.html = true; await A.sync(); assert.match(A.status().error, /did not answer JSON/); mode.html = false;
    mode.down = true; await A.sync(); assert.match(A.status().error, /unreachable/); assert.ok(!A.status().error.includes(KEY), 'the key never appears in an error'); mode.down = false;
    assert.equal(A.status().monitors, 3, 'a failed sync keeps the last good read');
  } finally { state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('routes: poll now at once; unmanage / manage need a different approver in the right scope', async () => {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog }); const calls = []; const mode = {};
  state.collection('approvers').put({ id: 'map', scopes: { 'eng:dba': ['ahmed'], infra: ['siva'], security: ['rasheed'] } });
  const api = fakeApi();
  const deps = { state, config: { me_apm_scheduler: false }, log: quietLog, apmTransport: fakeTransport(calls, mode) };
  try {
    routes.register(api, deps);
    let r = await api.call('POST', '/api/soc/integrations/apm/settings', { role: 'operator', body: { base_url: 'https://apm:8443' } }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/integrations/apm/settings', { role: 'admin', body: { base_url: 'https://apm:8443' } }); assert.equal(r.status, 200);
    r = await api.call('POST', '/api/soc/integrations/apm/key', { role: 'admin', body: { api_key: KEY } }); assert.equal(r.status, 200); assert.ok(!JSON.stringify(r.body).includes(KEY));
    r = await api.call('GET', '/api/soc/integrations/apm/settings', { role: 'admin' }); assert.ok(!JSON.stringify(r.body).includes(KEY), 'the key is never returned');
    r = await api.call('POST', '/api/soc/integrations/apm/sync', { role: 'operator' }); assert.equal(r.body.monitors, 3);
    r = await api.call('GET', '/api/soc/integrations/apm/monitors?db=1', { role: 'viewer' }); assert.deepEqual(r.body.items.map((m) => m.name), ['ORCLPRD', 'FINDB']);

    r = await api.call('POST', '/api/soc/integrations/apm/actions', { role: 'operator', user: 'ali', body: { action: 'poll', resource_id: '10001' } });
    assert.equal(r.body.status, 'executed'); assert.equal(calls[calls.length - 1].path, '/AppManager/json/PollNow');
    r = await api.call('POST', '/api/soc/integrations/apm/actions', { role: 'operator', user: 'ali', body: { action: 'unmanage', resource_id: '10001', hours: 4 } }); assert.equal(r.status, 400, 'a reason is required');
    r = await api.call('POST', '/api/soc/integrations/apm/actions', { role: 'operator', user: 'ali', body: { action: 'unmanage', resource_id: '10001', hours: 4, reason: 'patching ORCLPRD to 19.22' } });
    const id = r.body.id; assert.equal(r.body.status, 'pending'); assert.equal(r.body.suppress, 'alerts', 'default: keep monitoring, suppress alerts');
    const before = calls.length;
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${id}/decide`, { role: 'operator', user: 'rasheed', body: { decision: 'approve' } }); assert.equal(r.status, 403, 'a security approver may not decide a database monitor (eng:dba, covered by its infra group)');
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${id}/decide`, { role: 'admin', user: 'ali', body: { decision: 'approve' } }); assert.equal(r.status, 403, 'the requester never decides, even as admin');
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${id}/decide`, { role: 'admin', user: 'system:ai-dba', body: { decision: 'approve' } }); assert.equal(r.status, 403, 'an AI / service identity never decides');
    assert.equal(calls.length, before, 'nothing reached Applications Manager before approval');
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${id}/decide`, { role: 'operator', user: 'ahmed', body: { decision: 'approve', comment: 'ok for tonight' } });
    assert.equal(r.status, 200); assert.equal(r.body.status, 'executed'); assert.equal(r.body.decided_by, 'ahmed');
    const un = calls.find((c) => c.path === '/AppManager/json/UnmanageMonitor');
    assert.equal(un.q.resourceid, '10001'); assert.equal(un.q.suppresstype, 'alerts'); assert.ok(Number(un.q.time) > Date.now() + 3.9 * 3600000);
    assert.ok(api.audits.some((a) => a.action === 'apm.settings') && api.audits.some((a) => a.action === 'apm.key.set'));

    // non-database monitor: infra approver; a failure from APM is recorded, the key scrubbed
    r = await api.call('POST', '/api/soc/integrations/apm/actions', { role: 'operator', user: 'ali', body: { action: 'manage', resource_id: '10002', reason: 'portal release done' } });
    mode.actFail = true;
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${r.body.id}/decide`, { role: 'operator', user: 'siva', body: { decision: 'approve' } });
    assert.equal(r.body.status, 'failed'); assert.match(r.body.result, /answered 4004/); assert.ok(!r.body.result.includes(KEY));
    mode.actFail = false;
    r = await api.call('POST', '/api/soc/integrations/apm/actions', { role: 'operator', user: 'ali', body: { action: 'manage', resource_id: '10003', reason: 'back from maintenance' } });
    r = await api.call('POST', `/api/soc/integrations/apm/actions/${r.body.id}/decide`, { role: 'operator', user: 'ahmed', body: { decision: 'reject' } }); assert.equal(r.status, 400, 'a rejection needs a reason');
    r = await api.call('GET', '/api/soc/integrations/apm/actions', { role: 'operator' }); assert.equal(r.body.items.length, 4);
  } finally { deps.meApm.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
