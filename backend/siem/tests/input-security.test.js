// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM API boundary: prototype keys refused, malformed / oversized bodies refused, a double submission runs once while two
// people are never merged and a later repeat is a new request. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApi } = require('../engine/api/server');

const SECRET = 'synthetic-proxy-secret-0123456789';
function call(port, method, path, body, user = 'syed') {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body || {}));
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: { 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': user, 'X-Auth-Role': 'admin', 'Content-Type': 'application/json', 'Content-Length': data.length } }, (res) => {
      let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(t); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json: j }); });
    });
    r.on('error', reject); r.end(data);
  });
}

test('SIEM API: hostile bodies, double submissions', async (t) => {
  const api = createApi({ port: 0, proxySecret: SECRET, maxBody: 64 * 1024 });
  let runs = 0;
  api.route('POST', '/api/soc/test/slow', async (ctx) => { const n = ++runs; await new Promise((r) => setTimeout(r, 120)); return { run: n, echo: Object.keys(ctx.body) }; });
  api.route('POST', '/api/soc/test/ok', (ctx) => { ctx.ok({ via: 'ctx.ok', n: ++runs }); });
  await api.start(); t.after(() => api.stop());
  const port = api.address().port;
  const p = await call(port, 'POST', '/api/soc/test/slow', '{"a":1,"__proto__":{"isAdmin":true}}');
  assert.equal(p.status, 400); assert.equal(({}).isAdmin, undefined);
  assert.equal((await call(port, 'POST', '/api/soc/test/slow', '{"a":')).status, 400, 'broken JSON');
  assert.equal((await call(port, 'POST', '/api/soc/test/slow', JSON.stringify({ x: 'A'.repeat(70000) }))).status, 413, 'over the body limit');
  runs = 0;
  const [a, b] = await Promise.all([call(port, 'POST', '/api/soc/test/slow', { a: 1 }), call(port, 'POST', '/api/soc/test/slow', { a: 1 })]);
  assert.equal(runs, 1, 'ran once'); assert.equal(a.json.run, b.json.run);
  const [c, d] = await Promise.all([call(port, 'POST', '/api/soc/test/slow', { a: 1 }, 'ali'), call(port, 'POST', '/api/soc/test/slow', { a: 1 }, 'sara')]);
  assert.notEqual(c.json.run, d.json.run, 'two people are never merged');
  await call(port, 'POST', '/api/soc/test/slow', { a: 1 });
  assert.equal(runs, 4, 'a later repeat is a new request');
  const [e1, e2] = await Promise.all([call(port, 'POST', '/api/soc/test/ok', { k: 1 }), call(port, 'POST', '/api/soc/test/ok', { k: 1 })]);
  assert.equal(e1.status, 200); assert.equal(e2.status, 200);
});

/* review regressions (2026-10-22): each failed before its fix */
test('review: a duplicate of a FAILED request gets the same failure and never runs; query strings stay apart; wrap() 5xx reach the register', async (t) => {
  const { wrap } = require('../engine/soc/routeutil');
  const seen = [];
  const api = createApi({ port: 0, proxySecret: SECRET, onError: (x) => seen.push(x) });
  let runs = 0;
  api.route('POST', '/api/soc/test/conflict', wrap({}, 'operator', async () => { runs++; await new Promise((r) => setTimeout(r, 100)); const e = new Error('already exists'); e.code = 409; throw e; }));
  api.route('POST', '/api/soc/test/poll', async (ctx) => { await new Promise((r) => setTimeout(r, 100)); return { security: ctx.query.security === '1' }; });
  api.route('POST', '/api/soc/test/boom', wrap({ log: { error() {} } }, 'operator', () => { throw new Error('clickhouse said: table missing'); }));
  await api.start(); t.after(() => api.stop());
  const port = api.address().port;
  const four = await Promise.all([1, 2, 3, 4].map(() => call(port, 'POST', '/api/soc/test/conflict', { k: 1 })));
  assert.equal(runs, 1, 'the handler ran once'); assert.deepEqual(four.map((r) => r.status), [409, 409, 409, 409]);
  const [p1, p2] = await Promise.all([call(port, 'POST', '/api/soc/test/poll', {}), call(port, 'POST', '/api/soc/test/poll?security=1', {})]);
  assert.deepEqual([p1.json.security, p2.json.security], [false, true], 'a different query string is a different request');
  assert.equal((await call(port, 'POST', '/api/soc/test/boom', {})).status, 500);
  assert.ok(seen.some((x) => x.path === '/api/soc/test/boom' && /table missing/.test(x.err.message)), 'a 500 answered by wrap() reaches Platform Health with its cause');
  assert.equal((await call(port, 'POST', '/api/soc/test/poll', '{"\\u005f_proto__":{"x":1}}')).status, 400, 'an escaped __proto__ key is refused too');
});
