// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The duty desk with a newer engineer's file missing on the server (an update that did not copy it): the engine keeps
// running without that engineer and readiness names the file and the fix. Own file = own process, so the modules are
// not already in Node's require cache. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module'), orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  if (req === './pdpl' || req === './audit-checklist') { const e = new Error("Cannot find module '" + req + "'"); e.code = 'MODULE_NOT_FOUND'; throw e; }
  return orig.call(this, req, ...rest);
};
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
test('a newer engineer\'s file missing on the server leaves it out - the engine keeps running (was HTTP 502 on every page)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const en = await e.req('GET', '/duty/engineers', { role: 'viewer' });
  assert.equal(en.status, 200); assert.ok(!en.json.engineers.some((x) => x.id === 'pdpl'), 'PDPL consultant left out');
  assert.ok(en.json.engineers.some((x) => x.id === 'itaudit'), 'the others still work');
  assert.equal((await e.req('GET', '/pdpl', { role: 'viewer' })).status, 404);
  const rd = (await e.req('GET', '/duty/readiness', { role: 'viewer' })).json;
  const m = rd.engineers.find((x) => x.id === 'modules');
  assert.ok(m && /pdpl\.js/.test(m.checks[0].detail) && /audit-checklist\.js/.test(m.checks[0].detail) && /update/.test(m.to_fix[0].fix), 'readiness names the missing files and the fix');
});
