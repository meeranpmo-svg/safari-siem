// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Door access (engine/facilities: zkbio.js + doors.js + routes.js) against an in-process fake ZKBioSecurity (SYNTHETIC controllers,
// doors and events): only GET and only the saved paths; lists read from the different envelopes ZKBio releases use; online only
// from a field that says so (anything else "not reported"); PDPL - an event keeps type, door and time, never the person, card or pin;
// alarms classified (duress, forced, tamper, held open, denied) and ranked; offline controllers; a stale server reads "not reported";
// token sealed, write-only, never returned or logged; admin-only settings validated (400 names the field) and audited; operators read
// now; viewers read the view; a refused token / 404 path / non-JSON answer is a named error; nothing connected says what to do.
const test = require('node:test');
const crypto = require('node:crypto');
const KEYDIR = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'sentra-zk-key-'));
process.env.SENTRA_SIEM_SECRETS_KEY = require('node:path').join(KEYDIR, 'secrets.key');
require('node:fs').writeFileSync(process.env.SENTRA_SIEM_SECRETS_KEY, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/facilities/routes');
const Z = require('../engine/facilities/zkbio');
const { analyse } = require('../engine/facilities/doors');

const TOKEN = 'zk-syn-token-0123456789';
function fakeZk() {
  const st = { calls: [], mode: 'ok' };
  const srv = http.createServer((q, r) => {
    const u = new URL(q.url, 'http://x'); st.calls.push(q.method + ' ' + u.pathname);
    const j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (q.method !== 'GET') return j(405, {});
    if (u.searchParams.get('access_token') !== TOKEN || st.mode === 'badtoken') return j(200, { code: 401, message: 'invalid access_token' });
    if (u.pathname === '/api/device/list') return j(200, { code: 0, data: { data: [
      { devName: 'CTRL-RUH-LOBBY', sn: 'SYN0001', ipAddress: '10.1.5.10', connectState: 1, areaName: 'Riyadh HQ' },
      { devName: 'CTRL-JED-01', sn: 'SYN0002', ipAddress: '10.2.5.10', connectState: 0, areaName: 'Jeddah' },
      { devName: 'CTRL-DMM-01', sn: 'SYN0003', ipAddress: '10.3.5.10', connectState: 7 }] } });
    if (u.pathname === '/api/door/list') return j(200, { code: 0, data: [{ doorName: 'Lobby-1', devName: 'CTRL-RUH-LOBBY', enabled: true }, { doorName: 'Server Room', devName: 'CTRL-RUH-LOBBY', enabled: true }, { doorName: 'Jeddah Main', devName: 'CTRL-JED-01' }] });
    if (u.pathname === '/api/transaction/list') {
      if (st.mode === 'noevents') return j(404, {});
      const now = Date.now(), t = (m) => new Date(now - m * 60000 + 3 * 3600000).toISOString().replace('T', ' ').slice(0, 19);
      const ev = [{ eventName: 'Duress Password Open', eventPointName: 'Server Room', eventTime: t(5), pin: '1001', name: 'Synthetic Person', cardNo: '99887766' },
        { eventName: 'Door Forced Open', eventPointName: 'Server Room', eventTime: t(30), pin: '', name: '' },
        { eventName: 'Door Opened Too Long', eventPointName: 'Lobby-1', eventTime: t(60) },
        { eventName: 'Normal Verify Open', eventPointName: 'Lobby-1', eventTime: t(2), pin: '1002', name: 'Synthetic Two' }];
      for (let i = 0; i < 11; i++) ev.push({ eventName: 'Card Expired', eventPointName: 'Lobby-1', eventTime: t(10 + i), pin: '1003', name: 'Synthetic Three', cardNo: '1234' });
      return j(200, { code: 0, data: { rows: ev } });
    }
    return j(404, {});
  });
  return { srv, st };
}

test('parsing: envelopes, online only from a field that says so, PDPL drops the person, alarm kinds', () => {
  assert.equal(Z.rows({ code: 0, data: { data: [1, 2] } }).length, 2); assert.equal(Z.rows({ data: { rows: [1] } }).length, 1); assert.equal(Z.rows([1, 2, 3]).length, 3); assert.equal(Z.rows({ x: 1 }), null);
  assert.equal(Z.device({ connectState: 1 }).online, true); assert.equal(Z.device({ status: 'offline' }).online, false);
  assert.equal(Z.device({ connectState: 7 }).online, null, 'an unknown code is not read as up or down'); assert.equal(Z.device({}).online, null);
  const e = Z.event({ eventName: 'Duress Password Open', eventPointName: 'Server Room', eventTime: '2026-11-05 09:00:00', pin: '1001', name: 'Synthetic Person', cardNo: '9988' });
  assert.equal(e.kind, 'duress'); assert.equal(e.door, 'Server Room'); assert.equal(e.at, Date.parse('2026-11-05T09:00:00+03:00'), 'ZKBio local time is Riyadh');
  assert.ok(!JSON.stringify(e).match(/1001|Synthetic|9988/), 'no pin, name or card is kept');
  assert.deepEqual(['Door Forced Open', 'Tamper Alarm', 'Door Opened Too Long', 'Card Expired', 'Anti-Passback', 'Normal Verify Open'].map(Z.eventKind), ['forced', 'tamper', 'held-open', 'denied', 'alarm', 'normal']);
  assert.equal(Z.okPath('/api/door/list'), true); assert.equal(Z.okPath('/api/../admin'), false); assert.equal(Z.okPath('/door/list'), false);
  const none = analyse({ servers: [] }); assert.equal(none.configured, false); assert.match(none.reason, /API Authorization/);
});

async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-zk-')), secFile = path.join(dir, 'secrets.json');
  const state = await createState({ dir });
  const config = {}; Object.defineProperty(config, '_paths', { value: { secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const F = fakeZk(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const logs = [], log = { info: (...a) => logs.push(JSON.stringify(a)), warn: (...a) => logs.push(JSON.stringify(a)), error: (...a) => logs.push(JSON.stringify(a)) };
  const D = routes.createDoors({ state, config, log, allowHttp: true });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log, doors: D });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, { role = 'viewer', user = 'nora.syn', body, params = {} } = {}) => {
    const out = {}; const ctx = { role, user, body, params, query: {}, ip: '10.9.9.9', need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, tg, d) => audits.push({ a, tg, d, user }), fail(c, msg) { out.status = c; out.error = msg; } };
    try { const rv = await R[m + ' /api/soc/facilities/doors' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code || 500; out.error = e.message; }
    return out;
  };
  return { D, F, call, audits, logs, secFile, port: F.srv.address().port };
}

test('routes: admin settings validated and audited, token sealed and never returned, read, analysis, roles', async (t) => {
  const { F, call, audits, logs, secFile, port } = await setup(t);
  const SRV = { id: 'zk-hq', label: 'ZKBio HQ', site: 'Riyadh HQ', host: '127.0.0.1', port };
  assert.equal((await call('POST', '/servers', { role: 'operator', body: SRV })).status, 403, 'settings are admin only');
  let r = await call('POST', '/servers', { role: 'admin', body: Object.assign({}, SRV, { host: 'bad host!' }) }); assert.equal(r.status, 400); assert.match(r.error, /host must be a host name/);
  r = await call('POST', '/servers', { role: 'admin', body: Object.assign({}, SRV, { path_events: '/api/../x' }) }); assert.equal(r.status, 400); assert.match(r.error, /path_events/);
  r = await call('POST', '/servers', { role: 'admin', body: Object.assign({}, SRV, { port: 70000 }) }); assert.equal(r.status, 400); assert.match(r.error, /port/);
  r = await call('POST', '/servers', { role: 'admin', user: 'syed', body: Object.assign({}, SRV, { extra: 'x' }) }); assert.equal(r.status, 200, r.error); assert.equal(r.body.extra, undefined, 'undeclared field dropped');
  assert.equal(r.body.token, null);
  r = await call('PUT', '/servers/:id/token', { role: 'operator', params: { id: 'zk-hq' }, body: { token: TOKEN } }); assert.equal(r.status, 403);
  r = await call('PUT', '/servers/:id/token', { role: 'admin', params: { id: 'zk-hq' }, body: {} }); assert.equal(r.status, 400); assert.match(r.error, /token is required/);
  r = await call('PUT', '/servers/:id/token', { role: 'admin', user: 'syed', params: { id: 'zk-hq' }, body: { token: TOKEN } }); assert.equal(r.status, 200); assert.equal(r.body.token, 'token set');
  assert.ok(!fs.readFileSync(secFile, 'utf8').includes(TOKEN), 'the token is sealed at rest');
  assert.ok(!JSON.stringify((await call('GET', '/servers')).body).includes(TOKEN), 'never returned');
  assert.equal((await call('POST', '/servers/:id/sync', { role: 'viewer', params: { id: 'zk-hq' } })).status, 403, 'a viewer does not trigger a read');
  r = await call('POST', '/servers/:id/sync', { role: 'operator', params: { id: 'zk-hq' } }); assert.equal(r.status, 200); assert.equal(r.body.ok, true); assert.equal(r.body.devices, 3);
  assert.ok(F.st.calls.every((c) => c.startsWith('GET ')), 'GET only'); assert.deepEqual([...new Set(F.st.calls.map((c) => c.slice(4)))].sort(), ['/api/device/list', '/api/door/list', '/api/transaction/list']);
  const v = (await call('GET', '')).body;
  assert.equal(v.configured, true); assert.equal(v.kpis.controllers, 3); assert.equal(v.kpis.online, 1); assert.equal(v.kpis.offline, 1); assert.equal(v.kpis.not_reported, 1);
  assert.equal(v.controllers[0].name, 'CTRL-JED-01', 'offline first'); assert.equal(v.kpis.doors, 3);
  assert.equal(v.kpis.duress, 1); assert.equal(v.kpis.forced, 1); assert.equal(v.kpis.held_open, 1); assert.equal(v.kpis.denied, 11);
  assert.match(v.actions[0].title, /duress/); assert.ok(v.actions.some((a) => /10\+ denied attempts/.test(a.title) && /Lobby-1 ×11/.test(a.detail)));
  assert.ok(!JSON.stringify(v).match(/Synthetic|1001|99887766/), 'no person in the view (PDPL)');
  assert.ok(!logs.join(' ').includes(TOKEN), 'the token is never logged');
  assert.deepEqual(audits.map((a) => a.a), ['facilities.zkbio.put', 'facilities.zkbio.token', 'facilities.zkbio.sync']); assert.equal(audits[1].user, 'syed');
  assert.ok(!JSON.stringify(audits).includes(TOKEN));
  // a path this release lacks: named, the rest still read
  F.st.mode = 'noevents'; r = await call('POST', '/servers/:id/sync', { role: 'operator', params: { id: 'zk-hq' } });
  assert.equal(r.body.ok, true); assert.match(r.body.errors.join(' '), /404 - this ZKBio release has no \/api\/transaction\/list/);
  // a refused token: named, the view says the server is not read, controllers not reported
  F.st.mode = 'badtoken'; r = await call('POST', '/servers/:id/sync', { role: 'operator', params: { id: 'zk-hq' } });
  assert.equal(r.body.ok, false); assert.match(r.body.error, /ZKBio refused \(code 401/);
  const v2 = (await call('GET', '')).body; assert.equal(v2.kpis.unread, 1); assert.equal(v2.kpis.controllers, 0, 'nothing invented from a failed read');
  assert.equal((await call('DELETE', '/servers/:id', { role: 'admin', params: { id: 'nope' } })).status, 404);
});

test('a server not read for three polls: its controllers read "not reported", never online', () => {
  const snap = { at: 0, devices: [{ name: 'C1', online: true }], doors: [], events: [], errors: [] };
  const v = analyse({ servers: [{ id: 's', label: 'S', enabled: true }], snapshot: () => snap, pollMin: 10, now: 31 * 60000 });
  assert.equal(v.controllers[0].online, null); assert.equal(v.kpis.online, 0); assert.equal(v.kpis.unread, 1);
});
