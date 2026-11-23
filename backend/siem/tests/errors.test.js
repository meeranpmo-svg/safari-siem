// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// util/errors.js in the SIEM: a failing job is caught and counted (never reaches the process), a 5xx answer is recorded with
// its detail while the caller sees "internal error", and a collector keeps its schedule after a poll that throws.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApi } = require('../engine/api/server');
const { createErrors, shared, guard } = require('../engine/util/errors');

const SECRET = 'synthetic-proxy-secret-0123456789';
function get(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p, headers: { 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'syed', 'X-Auth-Role': 'admin' } }, (res) => {
      let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(t || 'null') }));
    }).on('error', reject);
  });
}

test('shared register: one per process, jobs from any module land in it', async () => {
  const j = guard('collect.test.poll', async () => { throw new Error('ECONNREFUSED 10.1.1.1:443'); });
  assert.equal(await j(), undefined);
  assert.equal(shared(), shared());
  const row = shared().view().jobs.find((x) => x.name === 'collect.test.poll');
  assert.equal(row.failures, 1); assert.match(row.last_error, /ECONNREFUSED/);
});

test('API: a handler that throws answers "internal error" and the detail is recorded', async (t) => {
  const E = createErrors({ log: { error() {}, warn() {}, every() {} } });
  const api = createApi({ port: 0, proxySecret: SECRET, onError: E.recordServer });
  api.route('GET', '/api/soc/test/explode', () => { throw new Error('clickhouse said: table missing'); });
  api.route('GET', '/api/soc/platform/errors', (ctx) => { ctx.need('admin'); return E.view(); });
  await api.start(); t.after(() => api.stop());
  const port = api.address().port;
  const r = await get(port, '/api/soc/test/explode');
  assert.equal(r.status, 500); assert.equal(r.json.error, 'internal error');
  const v = await get(port, '/api/soc/platform/errors');
  assert.equal(v.json.server[0].path, '/api/soc/test/explode'); assert.match(v.json.server[0].error, /table missing/);
});

test('collector: a Graph sync that throws does not stop the schedule', async () => {
  const { createGraph } = require('../engine/collect/m365-graph');
  // credentials that cannot be read make enabled() throw inside the timer; before, that ended the schedule for good
  const real = global.setTimeout, queued = [];
  global.setTimeout = (fn, ms) => { queued.push({ fn, ms }); return { unref() {} }; };
  let g;
  try {
    g = createGraph({ config: { get m365() { throw new Error('config unreadable'); } }, log: { info() {}, warn() {}, error() {}, every() {} } });
    g.start();
    assert.equal(queued.length, 1, 'the first sync is scheduled');
    await queued[0].fn();
    assert.equal(queued.length, 2, 'after a failed sync the next one is still scheduled');
    assert.equal(queued[1].ms, 900000, 'with the default interval when the setting cannot be read');
    await queued[1].fn();
    assert.equal(queued.length, 3, 'and again');
  } finally { global.setTimeout = real; if (g) g.stop(); }
  assert.ok(shared().view().jobs.find((x) => x.name === 'collect.m365-graph.sync').failures >= 2, 'each failure is counted');
});
