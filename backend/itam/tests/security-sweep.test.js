// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security sweep (SAMA CSF 3.3.5 identity and access management, 3.3.6 application security): EVERY route IT Asset Management
// registers - the core app and every duty module - is called the way an attacker would, and must refuse correctly:
//   S1 no proxy secret (a request that did not come through nginx)          -> 401, every route
//   S2 no signed-in identity, and a forged role name ("superuser")          -> 401, except the PUBLIC list below
//   S3 a viewer on a write route                                            -> 401/403, unless the route declares anyRole with a reason
//   S4 malformed JSON on a write route                                      -> 400 before any logic (DELETE without a body is exempt)
//   S5 a body larger than the route allows                                  -> 413 before it is read
//   S6 a viewer on every read route with made-up ids                        -> never 500, never hangs
//   S7 no answer carries a stack trace, a file path or an exception name    (errors are 4xx with a message, or 500 "internal error")
// Synthetic identities only; nothing leaves the test process.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { startApp, SECRET } = require('./helpers');

const PUBLIC = new Set(['GET /api/itam/health']);   // the load balancer's liveness check - names no data
const LEAK = /\n\s+at \S+ \(|\/home\/|\/opt\/sentra-itam|node_modules|\b(TypeError|ReferenceError|SyntaxError|RangeError)\b/;

test('security sweep: every route refuses a missing secret, a missing or forged identity, a viewer write, bad JSON, a huge body; no 500 or leak', { timeout: 900000 }, async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const L = e.app.srv.list().filter((r) => r.path.startsWith('/api/itam') && ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(r.method));
  assert.ok(L.length > 1000, 'the sweep sees the whole route table (' + L.length + ')');
  const raw = (method, path, headers, body) => new Promise((ok) => {
    const h = Object.assign({}, headers); if (body != null) { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(body); }
    const r = http.request({ host: '127.0.0.1', port: e.port, method, path, headers: h, timeout: 20000 }, (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => ok({ s: res.statusCode, t: Buffer.concat(c).toString() })); });
    r.on('timeout', () => { r.destroy(); ok({ s: 'timeout', t: '' }); }); r.on('error', () => ok({ s: 'error', t: '' }));
    if (body != null) r.write(body); r.end();
  });
  // S5 over a raw socket: Node's HTTP client only surfaces a response once its own request has finished, so a declared-but-unsent
  // body would read as a slow server; the server answers 413 from the Content-Length header before reading anything
  const tooBig = (method, path, headers, len) => new Promise((ok) => {
    const s = net.connect(e.port, '127.0.0.1', () => s.write(method + ' ' + path + ' HTTP/1.1\r\nHost: x\r\n' + Object.entries(headers).map(([k, v]) => k + ': ' + v + '\r\n').join('') + 'Content-Type: application/json\r\nContent-Length: ' + len + '\r\n\r\n'));
    let buf = ''; const done = (v) => { clearTimeout(tm); s.destroy(); ok(v); }, tm = setTimeout(() => done('timeout'), 10000);
    s.on('data', (d) => { buf += d; const m = /^HTTP\/1\.1 (\d{3})/.exec(buf); if (m) done(Number(m[1])); }); s.on('error', () => done('error'));
  });
  const fill = (p) => p.replace(/:[A-Za-z_]+/g, 'syn-x');
  const H = (u, role) => Object.assign({ 'X-Sentra-Proxy-Secret': SECRET }, u ? { 'X-Auth-User': u } : {}, role ? { 'X-Auth-Role': role } : {});
  const bad = { S1: [], S2: [], S3: [], S4: [], S5: [], S6: [], S7: [] };
  const leak = (k, x) => { if (LEAK.test(x.t) || (x.s === 500 && !/^\{"error":"internal error"/.test(x.t))) bad.S7.push(k + ' -> ' + x.s + ' ' + x.t.slice(0, 120)); };
  async function one(r) {
    const k = r.method + ' ' + r.path, p = fill(r.path), w = r.method !== 'GET', b = w ? '{}' : null, open = !!(r.opts && r.opts.anyRole);
    let x = await raw(r.method, p, { 'X-Auth-User': 'syn.admin', 'X-Auth-Role': 'admin' }, b); if (x.s !== 401) bad.S1.push(k + ' -> ' + x.s); leak(k, x);
    for (const h of [H(null, null), H('syn.forge', 'superuser')]) { x = await raw(r.method, p, h, b); if (x.s !== 401 && !PUBLIC.has(k)) bad.S2.push(k + ' -> ' + x.s); leak(k, x); }
    if (w) {
      x = await raw(r.method, p, H('vera.syn', 'viewer'), '{}'); if (![401, 403].includes(x.s) && !open) bad.S3.push(k + ' -> ' + x.s); leak(k, x);
      x = await raw(r.method, p, H('adm.syn', 'admin'), '{"a":'); if (x.s !== 400 && !(r.method === 'DELETE' && [200, 204, 404].includes(x.s))) bad.S4.push(k + ' -> ' + x.s); leak(k, x);
      const lim = (r.opts && r.opts.maxBody) || 1024 * 1024; const big = await tooBig(r.method, p, H('adm.syn', 'admin'), lim + 1); if (big !== 413 && r.method !== 'DELETE') bad.S5.push(k + ' -> ' + big);
    } else { x = await raw('GET', p, H('vera.syn', 'viewer')); if (x.s === 500 || x.s === 'timeout' || x.s === 'error') bad.S6.push(k + ' -> ' + x.s); leak(k, x); }
  }
  const Q = L.slice(); await Promise.all(Array.from({ length: 12 }, async () => { while (Q.length) await one(Q.shift()); }));
  for (const [rule, list] of Object.entries(bad)) assert.deepEqual(list, [], rule + ' failed on ' + list.length + ' route(s):\n' + list.slice(0, 25).join('\n'));
});

// S8 / S9 in IT Asset Management: prototype keys are refused before any logic, and a service or AI identity cannot do what only a person
// may do (record a review, pause an AI feature, approve) even with the admin role
test('security sweep: __proto__ / constructor keys refused; a service or AI identity cannot act as a person', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const raw = (path, body, user, role) => new Promise((ok) => { const r = http.request({ host: '127.0.0.1', port: e.port, method: 'POST', path, headers: { 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': user, 'X-Auth-Role': role, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => ok({ s: res.statusCode, t: Buffer.concat(c).toString() })); }); r.write(body); r.end(); });
  for (const b of ['{"__proto__":{"role":"admin"}}', '{"constructor":{"prototype":{"x":1}}}', '{"note":"x","\\u005f_proto__":{}}']) {
    const x = await raw('/api/itam/aigov-intel/roadmap/review', b, 'syn.admin', 'admin'); assert.equal(x.s, 400, 'S8 ' + b); assert.match(x.t, /may not contain the key|invalid JSON/);
  }
  assert.equal({}.role, undefined, 'the prototype was not polluted');
  for (const who of ['ai:grc-consultant', 'system:itam', 'svc:collector']) {
    const x = await raw('/api/itam/aigov-intel/roadmap/review', '{"note":"tools and results reviewed (synthetic)"}', who, 'admin'); assert.equal(x.s, 403, 'S9 ' + who); assert.match(x.t, /a person does/);
  }
});
