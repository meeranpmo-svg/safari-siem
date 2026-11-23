// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Libraesva ESG read-only API (engine/libraesva.js): config admin-only, password sealed and never returned / logged, login
// with X-ESG-Auth-Token and X-Switch-User, catalogue read from the appliance (OpenAPI at /api/v2/ or linked from its page),
// endpoint mapping only to GET paths in that catalogue, reads (status for viewers; quarantine / messages for operators,
// audited), GET-only, errors the admin can act on. The gateway is a stub; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const sealer = { seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, e) => Buffer.from(String(e).slice(7), 'base64').toString() };
const SPEC = { openapi: '3.0.0', paths: { '/api/v2/login': { post: {} }, '/api/v2/system/status': { get: { summary: 'System status' } }, '/api/v2/quarantine': { get: { summary: 'Quarantined messages' }, delete: {} },
  '/api/v2/messages': { get: { summary: 'Message log' } }, '/api/v2/quarantine/{id}/release': { post: {} } } };
function gateway(state) {
  return async (url, o) => {
    state.calls.push({ url, method: o.method, headers: o.headers || {}, body: o.body });
    const u = new URL(url);
    if (state.down) { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); }
    if (u.pathname === '/api/v2/login') { const b = JSON.parse(o.body); return b.password === 'Synthetic-Pass1' ? { status: 200, json: { token: 'tok-123' } } : { status: 401, json: { error: 'bad' } }; }
    if (o.headers['X-ESG-Auth-Token'] !== 'tok-123') return { status: 401, json: {} };
    if (!o.headers['X-Switch-User']) return { status: 403, json: {} };
    if (u.pathname === '/api/v2/') return state.html ? { status: 200, text: '<html><script>SwaggerUIBundle({ url: "/api/v2/doc.json" })</script></html>', json: null } : { status: 200, json: SPEC };
    if (u.pathname === '/api/v2/doc.json') return { status: 200, json: SPEC };
    if (u.pathname === '/api/v2/system/status') return { status: 200, json: { version: '5.6.2', cluster: { nodes: 2, ok: true }, queue: 12 } };
    if (u.pathname === '/api/v2/quarantine') return { status: 200, json: { data: [{ id: 'q1', from: 'spam@ext.test', to: 'user@corpgroup.test', subject: 'Invoice', score: 9.8, reason: 'Spam' }] } };
    return { status: 404, json: {} };
  };
}
async function setup(t, st) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: gateway(st), esgSealer: sealer });
  return e;
}
const post = (e, p, body, user, role) => e.req('POST', p, { body, user, role });
const ADM = ['syed', 'admin'], OP = ['nora.syn', 'operator'], VW = ['v.syn', 'viewer'];

test('connection: admin only, https, password sealed and never returned or logged; test logs in and reads the catalogue', async (t) => {
  const st = { calls: [] }, e = await setup(t, st);
  assert.equal((await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1' }, ...OP)).status, 403);
  assert.equal((await post(e, '/esg/config', { base_url: 'http://esg.corpgroup.test', username: 'api', password: 'x' }, ...ADM)).status, 400);
  assert.equal((await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api' }, ...ADM)).status, 400, 'password needed the first time');
  const c = await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test/', username: 'api', password: 'Synthetic-Pass1', switch_user: 'readonly@corpgroup.test' }, ...ADM);
  assert.equal(c.status, 200); assert.equal(c.json.password_set, true); assert.ok(!JSON.stringify(c.json).includes('Synthetic-Pass1'));
  assert.ok(!JSON.stringify(e.app.store.auditTail(20)).includes('Synthetic-Pass1'), 'not in the audit trail');
  assert.ok(String(e.app.store.collection('esg').get('cfg').enc).startsWith('SEALED:'), 'stored sealed');
  assert.equal((await post(e, '/esg/test', {}, ...VW)).status, 403);
  const r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.status, 200);
  assert.equal(r.json.last_test.ok, true); assert.equal(r.json.catalogue.length, 5); assert.equal(r.json.catalogue_source, '/api/v2/');
  const login = st.calls.find((x) => x.url.endsWith('/api/v2/login')); assert.equal(login.method, 'POST');
  const g = st.calls.find((x) => x.url.endsWith('/api/v2/')); assert.equal(g.headers['X-ESG-Auth-Token'], 'tok-123'); assert.equal(g.headers['X-Switch-User'], 'readonly@corpgroup.test');
  assert.ok(st.calls.every((x) => x.method === 'GET' || x.url.endsWith('/api/v2/login')), 'GET only, apart from the login');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'esg.test' && x.detail.ok));
});

test('catalogue linked from the documentation page; mapping only to GET endpoints in it; reads by role, personal data audited', async (t) => {
  const st = { calls: [], html: true }, e = await setup(t, st);
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
  const r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.json.catalogue_source, '/api/v2/doc.json');
  assert.equal((await post(e, '/esg/endpoints', { status: '/api/v2/system/status' }, ...OP)).status, 403);
  assert.match((await post(e, '/esg/endpoints', { quarantine: '/api/v2/quarantine/{id}/release' }, ...ADM)).json.error, /no \{placeholders\}/);
  assert.match((await post(e, '/esg/endpoints', { quarantine: '/api/v2/not-there' }, ...ADM)).json.error, /not a GET endpoint in the appliance catalogue/);
  assert.equal((await post(e, '/esg/endpoints', { status: '/api/v2/system/status', quarantine: '/api/v2/quarantine' }, ...ADM)).status, 200);
  const s = await e.req('GET', '/esg/read/status', { user: 'v.syn', role: 'viewer' }); assert.equal(s.status, 200);
  assert.equal(s.json.rows[0].version, '5.6.2'); assert.equal(s.json.rows[0].cluster, '{"nodes":2,"ok":true}');
  assert.equal((await e.req('GET', '/esg/read/quarantine', { user: 'v.syn', role: 'viewer' })).status, 403, 'quarantine names people: operators only');
  const q = await e.req('GET', '/esg/read/quarantine?status=spam', { user: 'nora.syn', role: 'operator' });
  assert.equal(q.status, 200); assert.equal(q.json.rows[0].from, 'spam@ext.test'); assert.ok(st.calls.some((x) => /\/api\/v2\/quarantine\?status=spam$/.test(x.url)));
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'esg.read.quarantine' && x.by === 'nora.syn'));
  assert.equal((await e.req('GET', '/esg/read/messages', { user: 'nora.syn', role: 'operator' })).status, 409, 'not mapped: says so');
  assert.equal((await e.req('GET', '/esg/read/other', { user: 'syed', role: 'admin' })).status, 400);
  assert.equal((await e.req('GET', '/esg/read/status?a%20b=1', { user: 'syed', role: 'admin' })).status, 400);
});

test('errors the admin can act on: wrong password, missing act-as user, gateway down', async (t) => {
  const st = { calls: [] }, e = await setup(t, st);
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'wrong' }, ...ADM);
  let r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.json.last_test.ok, false); assert.match(r.json.last_test.message, /login refused .* check the API user and password/);
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1' }, ...ADM);
  r = await post(e, '/esg/test', {}, ...OP); assert.match(r.json.last_test.message, /set "act as user"/);
  st.down = true; r = await post(e, '/esg/test', {}, ...OP); assert.match(r.json.last_test.message, /refused the connection \(ECONNREFUSED\)/);
});

test('remove the connection (Connections & Setup): admin only, a person, sealed password and mapping gone, audited', async (t) => {
  const st = { calls: [] }, e = await setup(t, st);
  const del = (u, r) => e.req('DELETE', '/esg/config', { user: u, role: r });
  assert.equal((await del(...ADM)).status, 404, 'nothing to remove yet');
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
  await post(e, '/esg/test', {}, ...OP);
  assert.equal((await del(...OP)).status, 403); assert.equal((await del(...VW)).status, 403);
  assert.equal((await del('system:itam', 'admin')).status, 403, 'a service identity never removes it');
  const r = await del(...ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.configured, false); assert.equal(r.json.password_set, false); assert.equal(r.json.catalogue.length, 0);
  assert.equal(e.app.store.collection('esg').get('cfg'), null, 'the sealed password is gone');
  const a = e.app.store.auditTail(20).find((x) => x.action === 'esg.config.remove'); assert.ok(a); assert.equal(a.by, 'syed'); assert.equal(a.detail.base_url, 'https://esg.corpgroup.test');
  assert.equal((await post(e, '/esg/test', {}, ...OP)).status, 409, 'test after removal says it is not set');
});

test('login: the act-as user goes with the login; a refused login shows the gateway\'s reason and what to fix', async (t) => {
  // a release that refuses an API user's login (HTTP 400) unless it names the ESG user it acts as
  const st = { calls: [] }, base = gateway(st);
  const strict = async (url, o) => {
    if (new URL(url).pathname === '/api/v2/login' && !(o.headers || {})['X-Switch-User']) { st.calls.push({ url, headers: o.headers || {} }); return { status: 400, json: { code: 400, message: 'API user must specify X-Switch-User' } }; }
    if (new URL(url).pathname === '/api/v2/login' && o.headers['X-Switch-User'] === 'nobody') { st.calls.push({ url, headers: o.headers }); return { status: 400, text: 'User nobody not found', json: null }; }
    return base(url, o);
  };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: strict, esgSealer: sealer });
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'Zyberon', password: 'Synthetic-Pass1' }, ...ADM);
  let r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, false);
  assert.match(r.json.last_test.message, /HTTP 400\): "API user must specify X-Switch-User" - an ESG API user must act as an ESG user: fill in "Act as ESG user"/);
  assert.doesNotMatch(r.json.last_test.message, /Synthetic-Pass1/);
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'Zyberon', switch_user: 'nobody' }, ...ADM);
  r = await post(e, '/esg/test', {}, ...OP); assert.match(r.json.last_test.message, /"User nobody not found" - check that "Act as ESG user" is an existing ESG user/);
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'Zyberon', switch_user: 'readonly.esg' }, ...ADM);
  r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, true, r.json.last_test.message);
  assert.equal(st.calls.filter((c) => /\/login$/.test(c.url)).pop().headers['X-Switch-User'], 'readonly.esg', 'the act-as user is sent with the login');
});

// the integration doctor: each step in order, the first failure named with its fix; read-only; operators only; audited
async function diag(t, st, cfg, lookup) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: gateway(st), esgSealer: sealer, esgLookup: lookup || (async () => ({ address: '10.20.0.25' })) });
  if (cfg) await post(e, '/esg/config', Object.assign({ base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, cfg), ...ADM);
  return e;
}
const stepOf = (r, name) => r.json.steps.find((x) => x.step === name);

test('diagnose: a healthy connection passes every step; the mapping and syslog are named as next steps; roles; audited', async (t) => {
  const st = { calls: [] }, e = await diag(t, st, {});
  assert.equal((await post(e, '/esg/diagnose', {}, ...VW)).status, 403, 'viewers cannot run it');
  const r = await post(e, '/esg/diagnose', {}, ...OP); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.steps.map((x) => x.status), ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'warn', 'info']);
  assert.match(stepOf(r, 'Address (DNS)').detail, /10\.20\.0\.25/);
  assert.match(stepOf(r, 'Endpoint mapping').detail, /status, queue, quarantine, messages/); assert.match(stepOf(r, 'Endpoint mapping').fix, /Libraesva page/);
  assert.match(stepOf(r, 'Mail log to the SIEM (syslog)').fix, /514/);
  assert.equal(r.json.ok, true);
  assert.ok(st.calls.every((x) => x.method === 'GET' || x.url.endsWith('/api/v2/login')), 'read-only');
  assert.ok(!JSON.stringify(r.json).includes('Synthetic-Pass1'));
  const a = e.app.store.auditTail(20).find((x) => x.action === 'esg.diagnose'); assert.equal(a.by, OP[0]); assert.equal(a.detail.ok, true);
  await post(e, '/esg/endpoints', { status: '/api/v2/system/status' }, ...ADM);
  const r2 = await post(e, '/esg/diagnose', {}, ...OP); assert.equal(stepOf(r2, 'Sample read').status, 'ok');
});

test('diagnose: each failure stops at its step with the fix (not set, DNS, certificate, firewall, password, act-as user)', async (t) => {
  let r = await post(await diag(t, { calls: [] }), '/esg/diagnose', {}, ...OP);
  assert.equal(r.json.ok, false); assert.equal(r.json.steps[0].status, 'fail'); assert.match(r.json.steps[0].fix, /Connections & Setup/);
  r = await post(await diag(t, { calls: [] }, {}, async () => { throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); }), '/esg/diagnose', {}, ...OP);
  assert.equal(stepOf(r, 'Address (DNS)').status, 'fail'); assert.match(stepOf(r, 'Address (DNS)').fix, /IP address/); assert.equal(r.json.steps.length, 2, 'stops at the failing step');
  // a self-signed certificate: the unauthenticated probe is refused with the certificate's fingerprint
  const certSt = { calls: [] }, certGw = gateway(certSt);
  const e3 = await startApp({ noAi: true }); t.after(() => e3.close());
  registerDuty(e3.app.srv, e3.app, { noTimer: true, esgSealer: sealer, esgLookup: async () => ({ address: '10.20.0.25' }), esgRequest: async (url, o) => { if (url.endsWith('/api/v2/') && !o.headers['X-ESG-Auth-Token']) throw Object.assign(new Error('self signed'), { cert: { fingerprint256: 'AA:BB:CC' } }); return certGw(url, o); } });
  await post(e3, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
  r = await post(e3, '/esg/diagnose', {}, ...OP);
  assert.equal(stepOf(r, 'HTTPS and certificate').status, 'fail'); assert.match(stepOf(r, 'HTTPS and certificate').detail, /AA:BB:CC/); assert.match(stepOf(r, 'HTTPS and certificate').fix, /Certificate pin/);
  const e4 = await startApp({ noAi: true }); t.after(() => e4.close());
  registerDuty(e4.app.srv, e4.app, { noTimer: true, esgSealer: sealer, esgLookup: async () => ({ address: '10.20.0.25' }), esgRequest: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }); } });
  await post(e4, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1' }, ...ADM);
  r = await post(e4, '/esg/diagnose', {}, ...OP); assert.match(stepOf(r, 'HTTPS and certificate').fix, /allow TCP 443/);
  r = await post(await diag(t, { calls: [] }, { password: 'Wrong-Pass9' }), '/esg/diagnose', {}, ...OP);
  assert.equal(stepOf(r, 'Login').status, 'fail'); assert.match(stepOf(r, 'Login').fix, /user name and password/);
  // an API user without "act as": the stub refuses the reads with 403 after login - the catalogue warns, the fix names "act as"
  const e6 = await diag(t, { calls: [] }, { switch_user: '' });
  await post(e6, '/esg/endpoints', {}, ...ADM);
  e6.app.store.collection('esg').put(Object.assign(e6.app.store.collection('esg').get('cfg'), { endpoints: { status: '/api/v2/system/status' } }));
  r = await post(e6, '/esg/diagnose', {}, ...OP);
  assert.equal(stepOf(r, 'Sample read').status, 'fail'); assert.match(stepOf(r, 'Sample read').detail, /act as user/);
});

test('login HTTP 400 with no reason: says what came back and the documented cases, never assumes an API user', async (t) => {
  const st = { calls: [] }, base = gateway(st);
  let MODE = 'empty';
  const req = async (url, o) => {
    if (new URL(url).pathname === '/api/v2/login') { st.calls.push({ url, headers: o.headers || {} }); return MODE === 'html' ? { status: 400, headers: { 'content-type': 'text/html; charset=utf-8' }, text: '<html><body>Bad Request</body></html>', json: null } : { status: 400, headers: { 'content-type': 'application/json' }, text: '{}', json: {} }; }
    return base(url, o);
  };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '192.0.2.25' }) });
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'readonly.admin', password: 'Synthetic-Pass1' }, ...ADM);
  let r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, false);
  assert.match(r.json.last_test.message, /gave no reason \(answer type application\/json\)/);
  assert.match(r.json.last_test.message, /A normal ESG user \(User Management → Users\) .* needs no "Act as ESG user"/);
  assert.doesNotMatch(r.json.last_test.message, /an ESG API user must act as/, 'a read-only admin is not told it is an API user');
  MODE = 'html'; r = await post(e, '/esg/test', {}, ...OP);
  assert.match(r.json.last_test.message, /answered with a web page \(text\/html\): check the address is the ESG appliance itself/);
  assert.doesNotMatch(r.json.last_test.message, /Synthetic-Pass1/);
  const d = await post(e, '/esg/diagnose', {}, ...OP); const login = (d.json.steps || []).find((s) => s.step === 'Login');
  assert.ok(login, 'the diagnosis has a Login step: ' + JSON.stringify(d.json).slice(0, 600)); assert.match(login.fix, /web console with the same user name and password/);
});

test('login HTTP 400 with "Act as" filled and no reason: a normal user is told to clear it; an API user to use the exact name', async (t) => {
  const st = { calls: [] }, base = gateway(st);
  const req = async (url, o) => { if (new URL(url).pathname === '/api/v2/login') { st.calls.push({ url, headers: o.headers || {} }); return { status: 400, headers: { 'content-type': 'application/json' }, text: '{}', json: {} }; } return base(url, o); };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '192.0.2.25' }) });
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'readonly.admin', password: 'Synthetic-Pass1', switch_user: 'readonly.admin' }, ...ADM);
  const r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, false);
  assert.match(r.json.last_test.message, /If "readonly\.admin" is a normal ESG user .* clear "Act as ESG user"/);
  assert.equal(st.calls[0].headers['X-Switch-User'], 'readonly.admin', 'the header was sent as configured');
  const d = await post(e, '/esg/diagnose', {}, ...OP); const login = (d.json.steps || []).find((x) => x.step === 'Login');
  assert.ok(login); assert.match(login.fix, /empty "Act as ESG user", save and test again/);
});

test('reached by IP, the appliance refuses with an HTML 400: the page is quoted, the fix names the certificate host, and "Host name" fixes it', async (t) => {
  const st = { calls: [] }, base = gateway(st);
  const req = async (url, o) => {
    const u = new URL(url), h = o.headers || {};
    if (u.hostname === '10.10.10.63' && u.pathname === '/' && o.captureUntrusted && !o.pin) throw Object.assign(new Error('TLS certificate not trusted'), { code: 'tls', cert: { subject: 'CN=esg.corpgroup.test, O=Libraesva', fingerprint256: 'ab'.repeat(32) } });
    if (h.Host !== 'esg.corpgroup.test') { st.calls.push({ url, headers: h }); return { status: 400, headers: { 'content-type': 'text/html' }, text: '<html><head><title>400 Bad Request</title></head><body><h1>Untrusted Host "10.10.10.63"</h1></body></html>', json: null }; }
    if (o.servername !== 'esg.corpgroup.test') return { status: 500, json: {} };
    return base(url.replace('10.10.10.63', 'esg.corpgroup.test'), o);
  };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.10.10.63' }) });
  await post(e, '/esg/config', { base_url: 'https://10.10.10.63', username: 'zyberon-esg', password: 'Synthetic-Pass1' }, ...ADM);
  let r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, false);
  assert.match(r.json.last_test.message, /HTTP 400\): "400 Bad Request - Untrusted Host/, 'the error page is quoted');
  assert.match(r.json.last_test.message, /reached by its IP address .* enter that name .* in "Host name"/);
  assert.doesNotMatch(r.json.last_test.message, /Act as ESG user" is an existing/, 'a page title is not read as an act-as refusal');
  const d = await post(e, '/esg/diagnose', {}, ...OP); const login = (d.json.steps || []).find((s) => s.step === 'Login');
  assert.match(login.fix, /certificate is issued to esg\.corpgroup\.test\. Enter esg\.corpgroup\.test in "Host name"/);
  // validation: a name in the URL needs no host_name; a bad name is refused
  assert.equal((await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'u', host_name: 'esg.corpgroup.test' }, ...ADM)).status, 400);
  r = await post(e, '/esg/config', { base_url: 'https://10.10.10.63', username: 'zyberon-esg', host_name: 'not a host!' }, ...ADM); assert.equal(r.status, 400); assert.match(r.json.error, /host_name/);
  r = await post(e, '/esg/config', { base_url: 'https://10.10.10.63', username: 'zyberon-esg', host_name: 'ESG.corpgroup.test', switch_user: 'readonly@corpgroup.test' }, ...ADM);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.host_name, 'esg.corpgroup.test');
  r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.json.last_test.ok, true, JSON.stringify(r.json.last_test));
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'esg.config' && x.detail.host_name === 'esg.corpgroup.test'));
});

test('reached by IP, the appliance answers 404 at /api/v2/login (its default site): the error says to enter the host name; with it the login works', async (t) => {
  const st = { calls: [] }, base = gateway(st);
  const req = async (url, o) => { const h = o.headers || {}; if (h.Host !== 'esg.corpgroup.test') return { status: 404, headers: { 'content-type': 'text/html' }, text: '<html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>', json: null }; return base(url.replace('10.10.10.63', 'esg.corpgroup.test'), o); };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.10.10.63' }) });
  await post(e, '/esg/config', { base_url: 'https://10.10.10.63', username: 'zyberon-esg', password: 'Synthetic-Pass1' }, ...ADM);
  let r = await post(e, '/esg/test', {}, ...OP);
  assert.equal(r.json.last_test.ok, false);
  assert.match(r.json.last_test.message, /HTTP 404\): "Not Found" - the gateway was reached by its IP address .* Enter the ESG host name .* in "Host name"/);
  r = await post(e, '/esg/config', { base_url: 'https://10.10.10.63', username: 'zyberon-esg', host_name: 'esg.corpgroup.test', switch_user: 'readonly@corpgroup.test' }, ...ADM); assert.equal(r.status, 200, r.raw);
  r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.json.last_test.ok, true, JSON.stringify(r.json.last_test));
});

test('a host name that does not serve the API (404): the error names it and points to the management interface and Diagnose', async (t) => {
  const req = async () => ({ status: 404, headers: { 'content-type': 'text/html' }, text: '<html><title>Not Found</title></html>', json: null });
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.10.10.64' }) });
  await post(e, '/esg/config', { base_url: 'https://quarantine.corpgroup.test', username: 'zyberon-esg', password: 'Synthetic-Pass1' }, ...ADM);
  const r = await post(e, '/esg/test', {}, ...OP);
  assert.match(r.json.last_test.message, /HTTP 404\).*ESG management interface .* not a load balancer, the user quarantine portal .* "Diagnose" checks each step/);
});

test('no HTTP answer: the OS cause is named with what to change (DNS, reset on the TLS name, no route) - never a bare "unreachable"', async (t) => {
  // what engine/discovery/httpc.js throws: code "unreachable", the OS code in sys
  const net = (sys) => async () => { throw Object.assign(new Error(`connection failed (${sys})`), { code: 'unreachable', sys }); };
  const run = async (sys, cfg) => {
    const e = await startApp({ noAi: true }); t.after(() => e.close());
    registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: net(sys), esgSealer: sealer, esgLookup: async () => ({ address: '10.20.0.25' }) });
    await post(e, '/esg/config', Object.assign({ base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1' }, cfg || {}), ...ADM);
    return { test: (await post(e, '/esg/test', {}, ...OP)).json.last_test.message, diag: stepOf(await post(e, '/esg/diagnose', {}, ...OP), 'HTTPS and certificate') };
  };
  let r = await run('ENOTFOUND');
  assert.match(r.test, /does not resolve on the platform server \(ENOTFOUND\)/); assert.match(r.test, /Host name/); assert.doesNotMatch(r.test, /\(unreachable\)/);
  r = await run('ECONNRESET', { base_url: 'https://10.20.0.25', host_name: 'esg.corpgroup.test' });
  assert.match(r.test, /closed the connection during the TLS handshake \(ECONNRESET\)/); assert.match(r.test, /esg\.corpgroup\.test/);
  assert.equal(r.diag.status, 'fail'); assert.match(r.diag.fix, /clear it, save and test again/);
  r = await run('ECONNRESET');
  assert.match(r.test, /firewall or proxy/); assert.doesNotMatch(r.test, /Host name/);
  r = await run('EHOSTUNREACH'); assert.match(r.test, /no route from the platform server/); assert.match(r.diag.fix, /allow TCP 443/);
});

test('diagnose: ESG 5.5 with no /api/v2/ index page passes on the login endpoint; both missing at an IP names "Host name"', async (t) => {
  const run = async (loginGet, cfg) => {
    const st = { calls: [] }, gw = gateway(st), e = await startApp({ noAi: true }); t.after(() => e.close());
    const req = async (url, o) => {
      const p = new URL(url).pathname;
      if (p === '/api/v2/' && !(o.headers || {})['X-ESG-Auth-Token']) return { status: 404, text: '<html><title>404 Not Found</title></html>', json: null };
      if (p === '/api/v2/login' && o.method === 'GET') return loginGet;
      return gw(url, o);
    };
    registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.20.0.25' }) });
    await post(e, '/esg/config', Object.assign({ base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, cfg || {}), ...ADM);
    return post(e, '/esg/diagnose', {}, ...OP);
  };
  let r = await run({ status: 405, text: '', json: null });
  assert.equal(stepOf(r, 'REST API v2').status, 'ok'); assert.match(stepOf(r, 'REST API v2').detail, /login answers \(HTTP 405\)/);
  assert.equal(stepOf(r, 'Login').status, 'ok', 'the diagnosis goes on to the login');
  const nf = { status: 404, text: '<html><title>404 Not Found</title></html>', json: null };
  r = await run(nf, { base_url: 'https://10.20.0.25' });
  assert.equal(stepOf(r, 'REST API v2').status, 'fail'); assert.match(stepOf(r, 'REST API v2').detail, /404 Not Found/); assert.match(stepOf(r, 'REST API v2').fix, /"Host name"/);
  r = await run(nf);
  assert.equal(stepOf(r, 'REST API v2').status, 'fail'); assert.doesNotMatch(stepOf(r, 'REST API v2').fix, /"Host name"/); assert.match(stepOf(r, 'REST API v2').fix, /management interface/);
});

test('catalogue: found at a usual OpenAPI place when /api/v2/ is not published; none found names the places tried and the test still passes', async (t) => {
  const run = async (specAt) => {
    const st = { calls: [] }, gw = gateway(st), e = await startApp({ noAi: true }); t.after(() => e.close());
    const req = async (url, o) => { const p = new URL(url).pathname;
      if (p === '/api/v2/' || p === '/api/v2/doc.json') return { status: 404, text: 'Not Found', json: null };
      if (specAt && p === specAt && o.headers['X-ESG-Auth-Token'] === 'tok-123') return { status: 200, json: SPEC };
      if (/\/api\/v2\/(docs\.json|openapi\.json|swagger\.json|doc|docs)$/.test(p)) return { status: 404, text: 'Not Found', json: null };
      return gw(url, o); };
    registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer });
    await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
    return (await post(e, '/esg/test', {}, ...OP)).json.last_test;
  };
  let r = await run('/api/v2/openapi.json');
  assert.equal(r.ok, true); assert.equal(r.endpoints, 5); assert.match(r.message, /openapi\.json/);
  r = await run(null);
  assert.equal(r.ok, true, 'a missing catalogue is not a failed connection'); assert.match(r.message, /no machine-readable catalogue at .*\/api\/v2\/, .*\/api\/v2\/ \(page\).*swagger\.json/); assert.match(r.message, /Endpoints/);
});

// bug fix (ESG 5.x, API Platform): the OpenAPI document is only embedded in the /api/v2/ documentation page (<script id="swagger-data">),
// is several MB (more than the 2 MB a normal read allows) and lists hundreds of paths - "quarantine" and "messages" sort after the
// 400th. The catalogue was reported as "not published" and the four reads could not be mapped.
test('catalogue: the ESG 5.x documentation page with the spec embedded, over 2 MB and hundreds of paths', async (t) => {
  const big = { openapi: '3.1.0', paths: {} };
  for (let i = 0; i < 700; i++) { const n = 'account-takeover-protection/res-' + String(i).padStart(3, '0'); big.paths['/api/v2/' + n] = { get: { summary: 'Retrieves the collection of resources. ' + 'x'.repeat(3500) }, post: {} }; big.paths['/api/v2/' + n + '/{id}'] = { get: {}, put: {}, delete: {}, patch: {} }; }
  Object.assign(big.paths, SPEC.paths);
  const page = '<!DOCTYPE html><html><head><title>Libraesva ESG API</title></head><body><div id="swagger-ui"></div><script id="swagger-data" type="application/json">' + JSON.stringify({ url: '/api/v2/docs.jsonopenapi', spec: big }) + '</script></body></html>';
  assert.ok(page.length > 2 * 1024 * 1024, 'the fixture is larger than a normal read');
  const st = { calls: [] }, gw = gateway(st), e = await startApp({ noAi: true }); t.after(() => e.close());
  const req = async (url, o) => { const p = new URL(url).pathname;
    if (/^\/api\/v2\/(docs(\.json|\.jsonopenapi)?|doc(\.json)?|openapi\.json|swagger\.json)?$/.test(p) && o.headers['X-ESG-Auth-Token'] === 'tok-123') {
      if (p === '/api/v2/' && /text\/html/.test(o.headers.Accept)) { if ((o.maxBytes || 16 * 1024 * 1024) < page.length) throw Object.assign(new Error('response too large'), { code: 'ETOOBIG' }); return { status: 200, text: page, json: null }; }
      if (p === '/api/v2/') return { status: 200, json: { '@context': '/api/v2/contexts/Entrypoint', '@id': '/api/v2' }, text: '{}' };   // the Hydra entrypoint: no paths
      return { status: 404, text: 'Not Found', json: null }; }
    return gw(url, o); };
  registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.10.10.63' }) });
  await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
  const r = await post(e, '/esg/test', {}, ...OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.last_test.ok, true); assert.match(r.json.catalogue_source, /embedded in the documentation page/);
  assert.ok(r.json.catalogue.length > 1400, 'every path kept: ' + r.json.catalogue.length);
  assert.ok(r.json.catalogue.some((x) => x.path === '/api/v2/quarantine') && r.json.catalogue.some((x) => x.path === '/api/v2/messages'), 'quarantine and messages are there to map');
  assert.equal((await post(e, '/esg/endpoints', { quarantine: '/api/v2/quarantine', messages: '/api/v2/messages', status: '/api/v2/system/status' }, ...ADM)).status, 200);
  assert.ok(st.calls.every((x) => x.method === 'GET' || x.url.endsWith('/api/v2/login')), 'GET only');
  const d = await post(e, '/esg/diagnose', {}, ...OP); const cs = d.json.steps.find((x) => x.step === 'API catalogue') || {}; assert.equal(cs.status, 'ok', JSON.stringify(d.json.steps.map((x) => [x.step, x.status, x.detail]))); assert.match(cs.detail, /embedded/);
});

// bug fix: ESG 5.x answers /api/v2/ with HTTP 302 (to its documentation page, or to the console login). A redirect was a failure,
// so the catalogue was never read. A redirect inside /api/v2/ on the same gateway is followed once; anywhere else is named.
test('catalogue: /api/v2/ redirects (302) to the documentation page; a redirect to the console login is named, not followed', async (t) => {
  const page = '<html><body><script id="swagger-data" type="application/json">' + JSON.stringify({ spec: SPEC }) + '</script></body></html>';
  const run = async (target) => {
    const st = { calls: [] }, gw = gateway(st), e = await startApp({ noAi: true }); t.after(() => e.close());
    const req = async (url, o) => { const p = new URL(url).pathname;
      if (/^\/api\/v2\/(docs(\.json|\.jsonopenapi)?|doc(\.json)?|openapi\.json|swagger\.json)?$/.test(p) && o.headers['X-ESG-Auth-Token'] === 'tok-123') {
        if (p === '/api/v2/') return { status: 302, headers: { location: target }, text: '', json: null };
        if (p === '/api/v2/docs' && /text\/html/.test(o.headers.Accept) && target === '/api/v2/docs') return { status: 200, text: page, json: null };
        if (p === '/api/v2/docs') return { status: 302, headers: { location: target }, text: '', json: null };
        return { status: 404, text: 'Not Found', json: null }; }
      return gw(url, o); };
    registerDuty(e.app.srv, e.app, { noTimer: true, esgRequest: req, esgSealer: sealer, esgLookup: async () => ({ address: '10.10.10.63' }) });
    await post(e, '/esg/config', { base_url: 'https://esg.corpgroup.test', username: 'api', password: 'Synthetic-Pass1', switch_user: 'ro' }, ...ADM);
    return { r: await post(e, '/esg/test', {}, ...OP), d: await post(e, '/esg/diagnose', {}, ...OP), st };
  };
  let { r, d, st } = await run('/api/v2/docs');
  assert.equal(r.json.catalogue.length, 5, JSON.stringify(r.json.last_test)); assert.match(r.json.catalogue_source, /embedded/);
  assert.ok(st.calls.every((x) => x.method === 'GET' || x.url.endsWith('/api/v2/login')), 'GET only');
  ({ r, d, st } = await run('https://esg.corpgroup.test/login'));
  assert.equal(r.json.catalogue.length, 0); assert.equal(r.json.last_test.ok, true, 'still a working connection');
  const cs = d.json.steps.find((x) => x.step === 'API catalogue'); assert.equal(cs.status, 'warn'); assert.match(cs.detail, /\/api\/v2\/: HTTP 302 for \/api\/v2\/ \(redirect to \/login\)/);
  assert.ok(!st.calls.some((x) => /\/login$/.test(new URL(x.url).pathname) && !x.url.endsWith('/api/v2/login')), 'a redirect outside /api/v2/ is never followed');
});
