// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engineering Team intelligence in the SIEM (engine/duty/duty-intel.js, identical to IT Asset Management's engine/duty-intel.js):
// GET /api/soc/duty/intel after a patrol (any signed-in role reads, as the other duty reads) with SYNTHETIC findings; the logic itself
// is tested in sentra-itam tests/duty-intel.test.js against the same file.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/duty/routes');
const DI = require('../engine/duty/duty-intel');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dutyintel-'));

test('duty intel route after a patrol; pure analysis on an empty desk says not measured', async () => {
  const st = await createState({ dir: path.join(tmp(), 'state') }), R = {};
  const devices = { r1: { id: 'r1', vendor: 'cisco-ios', name: 'R1-syn' } };
  const N = { inventory: { list: () => Object.values(devices), get: (id) => devices[id] }, findings: () => [{ id: 'r1:down', device: 'r1', device_name: 'R1-syn', site: 'HQ', severity: 'critical', kind: 'down', title: 'R1-syn down', evidence: [], recommendation: 'x' }],
    diagnose: async () => ({ summary: 'down', checks: [], causes: [] }), ai: { status: () => ({ enabled: false }) }, changes: { get: () => null }, poller: { pollDevice: async () => {} } };
  const deps = { state: st, config: { duty: { enabled: false } }, log: { info() {}, warn() {}, error() {} }, netopsInstance: N };
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, deps);
  const ctx = (role, b) => { const c = { role, user: 'u-' + role, body: b || {}, params: {}, query: {}, code: 200, need(r) { const RK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (RK[role] < RK[r]) { c.code = 403; return false; } return true; }, audit() {}, ok(x) { return x; }, fail(code, msg) { c.code = code; return { error: msg }; } }; return c; };
  await R['POST /api/soc/duty/patrol'](ctx('operator', { engineer: 'network' }));
  const c = ctx('viewer'), v = await R['GET /api/soc/duty/intel'](c);
  assert.equal(c.code, 200); assert.equal(v.source, 'siem');
  const net = v.engineers.find((e) => e.id === 'network'); assert.equal(net.open, 1); assert.equal(net.precision, null, 'withheld below 3 closures');
  assert.equal(v.team.engineers, v.engineers.length);
  const e0 = DI.analyse({ items: [], engineers: [{ id: 'x', name: 'X' }], now: Date.now() }); assert.equal(e0.engineers[0].trust, null); assert.match(e0.engineers[0].why, /not measured/);
});
