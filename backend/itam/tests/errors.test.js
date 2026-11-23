// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// engine/errors.js: a failing background job (throw or rejected promise) is caught, counted and shown, never reaches the
// process; a 5xx answer is recorded with its detail while the caller only gets "internal error"; pages report their errors
// (rate-limited, no query string kept); the process safety net; roles on the routes. Names are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { startApp } = require('./helpers');
const { createErrors, guardOf } = require('../engine/errors');

const quiet = { error() {}, warn() {}, every() {} };

test('guard: sync throw, async rejection, success, consecutive failures', async () => {
  const E = createErrors({ log: quiet });
  const boom = E.guard('sync.job', () => { throw new Error('disk full'); });
  assert.equal(boom(), undefined, 'a throw does not escape');
  const rej = E.guard('async.job', async () => { throw new Error('timeout to 10.0.0.9'); });
  assert.equal(await rej(), undefined, 'a rejection does not escape');
  await rej(); await rej();
  const good = E.guard('good.job', async (x) => x * 2);
  assert.equal(await good(21), 42, 'the value still comes back');
  const v = E.view();
  const j = (n) => v.jobs.find((x) => x.name === n);
  assert.equal(j('sync.job').failures, 1); assert.match(j('sync.job').last_error, /disk full/);
  assert.equal(j('async.job').consecutive, 3); assert.equal(j('async.job').state, 'failing');
  assert.equal(j('good.job').state, 'ok'); assert.equal(v.failing, 2);
  assert.equal(v.jobs[0].name, 'async.job', 'the most broken job first');
  const bare = guardOf({ log: quiet }, 'x', () => { throw new Error('no register'); });
  assert.equal(bare(), undefined, 'without a register a throw is still caught (logged), never thrown');
  assert.equal(await guardOf({ log: quiet }, 'y', async () => { throw new Error('x'); })(), undefined, 'and a rejection is still caught');
});

test('page errors: kept without query strings, rate-limited per user', () => {
  const E = createErrors({ log: quiet });
  const r = E.recordClient({ kind: 'http', page: '/dashboards/db-morning.html?user=ahmed', message: 'HTTP 502', status: 502, url: '/api/itam/db-morning?q=secret', ref: 'E-1' }, { user: 'syed', role: 'admin' });
  assert.equal(r.ok, true);
  const c = E.view().client[0];
  assert.equal(c.page, '/dashboards/db-morning.html'); assert.equal(c.url, '/api/itam/db-morning'); assert.equal(c.status, 502);
  assert.equal(E.recordClient({ kind: '<script>' }, { user: 'syed' }).ok, true); assert.equal(E.view().client[0].kind, 'error', 'unknown kinds are normalised');
  for (let i = 0; i < 40; i++) E.recordClient({ message: 'loop' }, { user: 'loop.user' });
  assert.equal(E.view().client.filter((x) => x.user === 'loop.user').length, 30, 'at most 30 a minute per user');
});

test('process safety net: rejection kept, uncaught exception saves state then exits 1', async () => {
  const E = createErrors({ log: quiet });
  const p = new EventEmitter(); let code = null, saved = 0; p.exit = (c) => { code = c; };
  E.processHandlers(p, () => { saved++; });
  p.emit('unhandledRejection', new Error('lost promise'));
  assert.equal(E.view().process.unhandled, 1); assert.equal(code, null, 'a rejection does not stop the engine');
  p.emit('uncaughtException', new Error('bad state'));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(saved, 1); assert.equal(code, 1);
});

test('routes: 5xx detail recorded, caller sees "internal error"; roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.srv.route('GET', '/test/explode', () => { throw new Error('secret detail: password=x'); });
  const r = await e.req('GET', '/test/explode');
  assert.equal(r.status, 500); assert.equal(r.json.error, 'internal error', 'no detail leaks to the browser');
  assert.equal((await e.req('GET', '/platform/errors', { role: 'operator' })).status, 403);
  const v = await e.req('GET', '/platform/errors', { user: 'syed', role: 'admin' });
  assert.equal(v.status, 200); assert.equal(v.json.server[0].path, '/api/itam/test/explode'); assert.match(v.json.server[0].error, /secret detail/);
  const c = await e.req('POST', '/platform/client-errors', { role: 'viewer', body: { kind: 'error', page: '/dashboards/x.html', message: 'TypeError: a is undefined' } });
  assert.equal(c.status, 200);
  assert.equal((await e.req('GET', '/platform/errors', { user: 'syed', role: 'admin' })).json.client[0].message, 'TypeError: a is undefined');
});

test('an older main.js without the register: the first guarded job brings it and its routes', () => {
  const routes = [], app = { srv: { route: (m, p) => routes.push(m + ' ' + p) }, log: quiet };
  guardOf(app, 'addon.tick', () => { throw new Error('first failure'); })();
  guardOf(app, 'addon.other', () => 1)();
  assert.deepEqual(routes, ['GET /platform/errors', 'GET /platform/ai-usage', 'POST /platform/client-errors'], 'routes registered once');
  assert.equal(app.errors.view().jobs.find((j) => j.name === 'addon.tick').failures, 1);
});
