// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CCTV / NVR (engine/facilities: isapi.js + cctv.js + routes.js) against an in-process fake Hikvision NVR that demands HTTP Digest
// (SYNTHETIC channels and disks): only GET and only the four ISAPI paths; the digest handshake; channels joined to their status;
// online only from the recorder's field; disks and a failed disk; a recorder not read for 3 polls reads "not reported"; ML over
// the poll history - 7-day availability, flapping, a group outage (3+ cameras down within 10 minutes = one shared cause);
// credentials sealed, write-only, admin refused as a user, never returned or logged; admin-only settings validated and audited;
// operators read now; viewers read the view; wrong password is a named error; nothing connected says what to do.
const test = require('node:test');
const crypto = require('node:crypto');
const KEYDIR = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'sentra-cctv-key-'));
process.env.SENTRA_SIEM_SECRETS_KEY = require('node:path').join(KEYDIR, 'secrets.key');
require('node:fs').writeFileSync(process.env.SENTRA_SIEM_SECRETS_KEY, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/facilities/routes');
const I = require('../engine/facilities/isapi');
const { analyse } = require('../engine/facilities/cctv');

const USER = 'viewer-syn', PASS = 'Syn-Passw0rd!', REALM = 'DS-SYN', NONCE = 'abc123nonce';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
function fakeNvr() {
  const st = { calls: [], online: { 1: true, 2: true, 3: true, 4: true, 5: false }, disk: 'ok' };
  const srv = http.createServer((q, r) => {
    st.calls.push(q.method + ' ' + q.url);
    if (q.method !== 'GET') { r.writeHead(405); return r.end(); }
    const a = q.headers.authorization || '';
    const p = {}; a.replace(/(\w+)="?([^",]*)"?/g, (m0, k, v) => { p[k] = v; return m0; });
    const ok = /^Digest /.test(a) && p.username === USER && p.response === md5(md5(USER + ':' + REALM + ':' + PASS) + ':' + NONCE + ':' + p.nc + ':' + p.cnonce + ':auth:' + md5('GET:' + q.url));
    if (!ok) { r.writeHead(401, { 'WWW-Authenticate': 'Digest qop="auth", realm="' + REALM + '", nonce="' + NONCE + '"' }); return r.end(); }
    const x = (b) => { r.writeHead(200, { 'Content-Type': 'application/xml' }); r.end('<?xml version="1.0"?>' + b); };
    if (q.url === I.PATHS.info) return x('<DeviceInfo><deviceName>NVR-SYN-HQ</deviceName><model>DS-SYN-7716</model><serialNumber>SYN0001</serialNumber><firmwareVersion>V4.SYN</firmwareVersion></DeviceInfo>');
    const ch = [1, 2, 3, 4, 5];
    if (q.url === I.PATHS.channels) return x('<InputProxyChannelList>' + ch.map((i) => '<InputProxyChannel><id>' + i + '</id><name>Cam-' + i + (i === 1 ? ' &lt;b&gt;' : '') + '</name><sourceInputPortDescriptor><ipAddress>10.10.20.' + i + '</ipAddress></sourceInputPortDescriptor></InputProxyChannel>').join('') + '</InputProxyChannelList>');
    if (q.url === I.PATHS.status) return x('<InputProxyChannelStatusList>' + ch.map((i) => '<InputProxyChannelStatus><id>' + i + '</id><online>' + st.online[i] + '</online></InputProxyChannelStatus>').join('') + '</InputProxyChannelStatusList>');
    if (q.url === I.PATHS.storage) return x('<storage><hddList><hdd><id>1</id><hddName>hdd1</hddName><capacity>3815447</capacity><freeSpace>512000</freeSpace><status>' + st.disk + '</status></hdd></hddList></storage>');
    r.writeHead(404); r.end();
  });
  return { srv, st };
}

test('parsers, digest, and the analysis (availability, flapping, group outage, stale)', () => {
  assert.deepEqual(I.parseInfo('<DeviceInfo><model>M1</model><serialNumber>S1</serialNumber></DeviceInfo>').model, 'M1');
  assert.equal(I.parseStatus('<InputProxyChannelStatus><id>2</id><online>maybe</online></InputProxyChannelStatus>')[0].online, null, 'not read as up or down');
  const h = I.digestHeader('Digest realm="r", nonce="n", qop="auth"', { user: 'u', pass: 'p', method: 'GET', uri: '/x', cnonce: 'c' });
  assert.match(h, new RegExp('response="' + md5(md5('u:r:p') + ':n:00000001:c:auth:' + md5('GET:/x')) + '"'));
  const now = Date.parse('2026-11-06T10:00:00Z'), M = 60000;
  const snap = { at: now, channels: [1, 2, 3, 4, 5].map((i) => ({ id: String(i), name: 'Cam-' + i })), status: [1, 2, 3, 4, 5].map((i) => ({ id: String(i), online: i > 3 })), disks: [{ id: '1', capacity_gb: 4000, free_gb: 0, status: 'error' }] };
  const H = { 1: [], 2: [], 3: [], 4: [], 5: [] };
  for (let k = 0; k < 288; k++) { const t = now - (287 - k) * 5 * M; H[1].push([t, k < 280 ? 1 : 0]); H[2].push([t, k < 281 ? 1 : 0]); H[3].push([t, k < 282 ? 1 : 0]); H[4].push([t, k % 20 < 10 ? 1 : 0]); H[5].push([t, 1]); }
  const v = analyse({ recorders: [{ id: 'nvr1', label: 'NVR HQ', site: 'HQ', enabled: true }], snapshot: () => snap, history: () => H, pollMin: 5, now });
  assert.equal(v.kpis.offline, 3); assert.equal(v.kpis.disks_failed, 1);
  assert.equal(v.outages.length, 1, 'cams 1-3 went down within 10 minutes'); assert.equal(v.outages[0].cameras.length, 3); assert.match(v.outages[0].why, /shared cause/);
  assert.ok(v.cameras.find((c) => c.channel === '4').flapping, 'camera 4 goes on and off');
  assert.equal(v.cameras.find((c) => c.channel === '5').availability_7d, 100);
  assert.equal(v.actions[0].priority, 100, 'a failed disk ranks first'); assert.ok(v.actions.some((a) => /down together/.test(a.title)));
  const stale = analyse({ recorders: [{ id: 'nvr1', label: 'NVR HQ', enabled: true }], snapshot: () => Object.assign({}, snap, { at: now - 60 * M }), pollMin: 5, now });
  assert.ok(stale.cameras.every((c) => c.online === null), 'stale recorder: cameras not reported'); assert.equal(stale.kpis.unreachable, 1);
  const none = analyse({ recorders: [] }); assert.equal(none.configured, false); assert.match(none.reason, /read-only user/);
});

async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cctv-')), secFile = path.join(dir, 'secrets.json');
  const state = await createState({ dir });
  const config = {}; Object.defineProperty(config, '_paths', { value: { secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const F = fakeNvr(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const logs = [], log = { info: (...a) => logs.push(JSON.stringify(a)), warn: (...a) => logs.push(JSON.stringify(a)), error: (...a) => logs.push(JSON.stringify(a)) };
  const C = require('../engine/facilities/cctv').createCctv({ state, config, log });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log, cctv: C, doors: { view() {}, list() { return []; }, get() {} } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (m, p, { role = 'viewer', user = 'nora.syn', body, params = {} } = {}) => {
    const out = {}; const ctx = { role, user, body, params, query: {}, ip: '10.9.9.9', need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, tg, d) => audits.push({ a, tg, d, user }), fail(c, msg) { out.status = c; out.error = msg; } };
    const key = m + ' /api/soc/facilities/cctv' + p.replace('/nvr-hq', '/:id'); try { const rv = await R[key](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code || 500; out.error = e.message; }
    return out;
  };
  return { C, F, call, audits, logs, secFile, port: F.srv.address().port };
}

test('routes: admin settings, sealed credential, digest read, viewer view, operator sync, refusals', async (t) => {
  const { F, call, audits, logs, secFile, port } = await setup(t);
  let r = await call('GET', ''); assert.equal(r.status, 200); assert.equal(r.body.configured, false);
  assert.equal((await call('POST', '/recorders', { role: 'operator', body: { id: 'nvr-hq', host: '127.0.0.1' } })).status, 403);
  r = await call('POST', '/recorders', { role: 'admin', body: { id: 'NVR HQ!', host: '127.0.0.1' } }); assert.equal(r.status, 400); assert.match(r.error, /id/);
  r = await call('POST', '/recorders', { role: 'admin', body: { id: 'nvr-hq', host: '127.0.0.1', vendor: 'dahua' } }); assert.equal(r.status, 400); assert.match(r.error, /vendor/);
  r = await call('POST', '/recorders', { role: 'admin', body: { id: 'nvr-hq', label: 'NVR HQ', site: 'Riyadh HQ', host: '127.0.0.1', port, https: false } }); assert.equal(r.status, 200); assert.match(r.body.credential || 'none', /none/);
  r = await call('POST', '/recorders/nvr-hq/sync', { role: 'operator', params: { id: 'nvr-hq' } }); assert.equal(r.body.ok, false); assert.match(r.body.error, /user and password not set/);
  assert.equal((await call('PUT', '/recorders/nvr-hq/credential', { role: 'admin', params: { id: 'nvr-hq' }, body: { user: 'admin', password: 'x' } })).status, 400, 'admin account refused');
  r = await call('PUT', '/recorders/nvr-hq/credential', { role: 'admin', params: { id: 'nvr-hq' }, body: { user: USER, password: 'wrong' } }); assert.equal(r.status, 200);
  r = await call('POST', '/recorders/nvr-hq/sync', { role: 'operator', params: { id: 'nvr-hq' } }); assert.equal(r.body.ok, false); assert.match(r.body.error, /login refused/);
  r = await call('PUT', '/recorders/nvr-hq/credential', { role: 'admin', params: { id: 'nvr-hq' }, body: { user: USER, password: PASS } }); assert.match(r.body.credential, /password set\) · HTTP, not encrypted/);
  assert.ok(!JSON.stringify(r.body).includes(PASS), 'password never returned');
  assert.ok(!fs.readFileSync(secFile, 'utf8').includes(PASS), 'password sealed in secrets.json');
  r = await call('POST', '/recorders/nvr-hq/sync', { role: 'operator', params: { id: 'nvr-hq' } }); assert.equal(r.body.ok, true, JSON.stringify(r.body)); assert.equal(r.body.cameras, 5); assert.equal(r.body.disks, 1);
  assert.ok(F.st.calls.every((c) => c.startsWith('GET /ISAPI/')), 'only GET, only ISAPI paths');
  assert.deepEqual([...new Set(F.st.calls.map((c) => c.slice(4)))].sort(), Object.values(I.PATHS).sort(), 'only the four paths');
  const v = (await call('GET', '')).body;
  assert.equal(v.kpis.cameras, 5); assert.equal(v.kpis.online, 4); assert.equal(v.kpis.offline, 1); assert.equal(v.recorders[0].info.model, 'DS-SYN-7716');
  assert.ok(!/[<>]/.test(v.cameras.find((c) => c.channel === '1').name), 'markup stripped from a camera name');
  assert.equal(v.disks[0].used_pct, Math.round(100 * (3726 - 500) / 3726));
  F.st.disk = 'error'; await call('POST', '/recorders/nvr-hq/sync', { role: 'operator', params: { id: 'nvr-hq' } });
  assert.equal((await call('GET', '')).body.actions[0].priority, 100, 'failed disk ranks first');
  assert.ok(!logs.join('\n').includes(PASS), 'password never logged');
  for (const a of ['facilities.cctv.put', 'facilities.cctv.credential', 'facilities.cctv.sync']) assert.ok(audits.some((x) => x.a === a), 'audited ' + a);
  assert.equal((await call('DELETE', '/recorders/nvr-hq', { role: 'operator', params: { id: 'nvr-hq' } })).status, 403);
  assert.equal((await call('DELETE', '/recorders/nvr-hq', { role: 'admin', params: { id: 'nvr-hq' } })).status, 200);
  assert.equal((await call('GET', '')).body.configured, false);
});
