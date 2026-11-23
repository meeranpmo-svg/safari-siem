// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security sweep of the SIEM's request layer (SAMA CSF 3.3.5 identity and access management, 3.3.6 application security) on the REAL
// api server (engine/api/server.js) and the REAL role wrapper (engine/soc/routeutil.js wrap), one route of every kind - a read, an
// operator write, an admin write, a four-eyes approval, a write open to every role, a handler that throws:
//   S1 no proxy secret -> 401 · S2 no identity / forged role -> 401 or 403 · S3 below the role -> 403 · S4 malformed JSON -> 400 before
//   the handler · S5 too large -> 413 from the header · S7 a throwing handler -> 500 "internal error", no stack, no path · S8 __proto__ /
//   constructor keys refused · S9 a service / AI identity never approves · and every route's role is declared (tests/contract.test.js).
// The route modules need a live log store to register, so the per-route declaration is enforced statically by contract.test.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { createApi } = require('../engine/api/server');
const { wrap } = require('../engine/soc/routeutil');

const SECRET = 'synthetic-proxy-secret-0123456789';
const LEAK = /\n\s+at \S+ \(|\/home\/|\/opt\/sentra-siem|node_modules|\b(TypeError|ReferenceError|SyntaxError|RangeError)\b/;
test('SIEM request layer: secret, identity, roles, bad JSON, size, internal errors, proto keys, approvals by a person', async (t) => {
  const deps = { log: { info() {}, warn() {}, error() {} }, state: null }, ran = [];
  const api = createApi({ port: 0, audit: () => {}, proxySecret: SECRET });
  api.route('GET', '/api/soc/syn/read', wrap(deps, null, () => ({ ok: 1 })));
  api.route('POST', '/api/soc/syn/op', wrap(deps, 'operator', (ctx) => { ran.push('op'); return { ok: 1, body: ctx.body }; }));
  api.route('POST', '/api/soc/syn/admin', wrap(deps, 'admin', () => { ran.push('admin'); return { ok: 1 }; }));
  api.route('POST', '/api/soc/syn/approve', wrap(deps, 'approve:security', () => { ran.push('approve'); return { ok: 1 }; }));
  api.route('POST', '/api/soc/syn/open', wrap(deps, null, () => ({ ok: 1 })), { anyRole: 'synthetic: any person may send it' });
  api.route('POST', '/api/soc/syn/small', wrap(deps, 'operator', () => ({ ok: 1 })), { maxBody: 1024 });
  api.route('GET', '/api/soc/syn/boom', wrap(deps, null, () => { throw new TypeError('secret detail at /opt/sentra-siem/engine/x.js:12'); }));
  const { port } = await api.start(); t.after(() => api.stop());
  const call = (method, path, { user = 'syn.op', role = 'operator', secret = SECRET, body } = {}) => new Promise((ok) => {
    const h = Object.assign({}, secret ? { 'X-Sentra-Proxy-Secret': secret } : {}, user ? { 'X-Auth-User': user } : {}, role ? { 'X-Auth-Role': role } : {}, body != null ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {});
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: h }, (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => ok({ s: res.statusCode, t: Buffer.concat(c).toString() })); });
    if (body != null) r.write(body); r.end();
  });
  const big = (path, len) => new Promise((ok) => { const s = net.connect(port, '127.0.0.1', () => s.write('POST ' + path + ' HTTP/1.1\r\nHost: x\r\nX-Sentra-Proxy-Secret: ' + SECRET + '\r\nX-Auth-User: syn.op\r\nX-Auth-Role: operator\r\nContent-Type: application/json\r\nContent-Length: ' + len + '\r\n\r\n'));
    let b = ''; s.on('data', (d) => { b += d; const m = /^HTTP\/1\.1 (\d{3})/.exec(b); if (m) { s.destroy(); ok(Number(m[1])); } }); });
  const W = ['/api/soc/syn/op', '/api/soc/syn/admin', '/api/soc/syn/approve'];
  for (const p of W.concat(['/api/soc/syn/read'])) {
    const m = p.endsWith('read') ? 'GET' : 'POST', b = m === 'POST' ? '{}' : null;
    assert.equal((await call(m, p, { secret: null, role: 'admin', body: b })).s, 401, 'S1 ' + p);
    assert.equal((await call(m, p, { secret: SECRET + 'x', role: 'admin', body: b })).s, 401, 'S1 wrong secret ' + p);
    assert.ok([401, 403].includes((await call(m, p, { user: '', role: '', body: b })).s), 'S2 no identity ' + p);
    if (m === 'POST') assert.ok([401, 403].includes((await call(m, p, { user: 'syn.forge', role: 'superuser', body: b })).s), 'S2 forged role ' + p);
  }
  assert.equal((await call('POST', '/api/soc/syn/op', { role: 'viewer', body: '{}' })).s, 403, 'S3 viewer on an operator write');
  assert.equal((await call('POST', '/api/soc/syn/admin', { role: 'operator', body: '{}' })).s, 403, 'S3 operator on an admin write');
  assert.equal((await call('POST', '/api/soc/syn/open', { role: 'viewer', body: '{}' })).s, 200, 'a write declared open to every role');
  let r = await call('POST', '/api/soc/syn/op', { body: '{"a":' }); assert.equal(r.s, 400, 'S4 malformed JSON');
  assert.equal(await big('/api/soc/syn/small', 4096), 413, 'S5 over the route limit'); assert.equal(await big('/api/soc/syn/op', 50 * 1024 * 1024), 413, 'S5 over the server limit');
  r = await call('GET', '/api/soc/syn/boom'); assert.equal(r.s, 500); assert.ok(!LEAK.test(r.t) && /internal error/.test(r.t), 'S7 nothing leaks: ' + r.t);
  for (const k of ['__proto__', 'constructor', 'prototype']) { r = await call('POST', '/api/soc/syn/op', { body: '{"' + k + '":{"admin":true}}' }); assert.equal(r.s, 400, 'S8 ' + k); }
  r = await call('POST', '/api/soc/syn/op', { body: '{"\\u005f_proto__":{"x":1}}' }); assert.equal(r.s, 400, 'S8 escaped key');
  r = await call('POST', '/api/soc/syn/approve', { user: 'ai:security-engineer', role: 'admin', body: '{}' }); assert.equal(r.s, 403, 'S9 an AI identity never approves'); assert.match(r.t, /only a person approves/);
  r = await call('POST', '/api/soc/syn/approve', { user: 'svc:collector', role: 'admin', body: '{}' }); assert.equal(r.s, 403, 'S9 a service identity never approves');
  assert.ok(!ran.includes('approve'), 'no refused approval reached its handler'); assert.equal(ran.filter((x) => x === 'admin').length, 0, 'no refused admin write reached its handler');
  r = await call('POST', '/api/soc/syn/approve', { user: 'syn.admin', role: 'admin', body: '{}' }); assert.equal(r.s, 200, 'a person who is admin approves');
});
