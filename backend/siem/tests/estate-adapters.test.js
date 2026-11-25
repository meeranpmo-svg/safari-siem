// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The organisation's own AI engineers on the SIEM duty desk (duty/estate-adapters.js): a module that is missing or not set up
// answers null (no work item opened or closed); FortiGate fleet findings, NAC endpoints at risk, NDR detections and a failing
// Mimecast collector become work items with a stable key, evidence and the fix; verify re-reads the module. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { estateAdapters } = require('../engine/duty/estate-adapters');

test('not set up → null; set up → work items; verify follows the module', async () => {
  const deps = { config: {}, state: { collection: () => ({ get: () => null }) } };
  const A = Object.fromEntries(estateAdapters(deps).map((a) => [a.id, a]));
  assert.deepEqual(Object.keys(A), ['fortigate', 'nac', 'ndr', 'mimecast']);
  for (const a of Object.values(A)) assert.equal(await a.findings(), null, a.id + ': not connected');
  let present = true;
  deps.fmgApi = { status: () => ({ configured: true, last_poll_at: '2026-11-25T08:00:00Z' }), fleet: () => ({ findings: present ? [{ device: 'FGT-SITE-07', serial: 'FGT40F07', code: 'conserve', severity: 'critical', title: 'Memory 91 %', fix: 'Find the growth' }] : [] }) };
  deps.nacApi = { view: () => ({ connected: true, total: 2, learning: false, endpoints: [{ mac: 'aa:00:00:00:00:01', host: 'PC-1', risk: 65, reasons: [{ points: 35, why: 'two sites' }], site: 'S7' }, { mac: 'aa:00:00:00:00:02', risk: 10, reasons: [] }] }) };
  deps.state = { collection: (n) => ({ get: () => (n === 'ndr_run' ? { at: '2026-11-25T09:00:00Z', detections: [{ kind: 'beacon', host: '10.1.1.5', dst: '203.0.113.9:443', severity: 'high', why: 'every 300 s' }, { kind: 'country', host: '10.1.1.5', dst: 'X', severity: 'low', why: 'new' }] } : null) }) };
  deps.config.mimecast = { enabled: true }; deps.mimecastStats = () => ({ last_error: 'Mimecast refused the client ID / secret', last_poll_at: '2026-11-25T09:00:00Z' }); deps.now = () => Date.parse('2026-11-25T09:30:00Z');
  const fw = await A.fortigate.findings(); assert.equal(fw.length, 1); assert.deepEqual([fw[0].key, fw[0].severity, fw[0].target.name], ['fgt:FGT40F07:conserve', 'critical', 'FGT-SITE-07']); assert.match(fw[0].recommendation, /growth/);
  const nac = await A.nac.findings(); assert.equal(nac.length, 1, 'only endpoints at risk'); assert.equal(nac[0].severity, 'high'); assert.match(nac[0].evidence[0], /two sites/);
  const ndr = await A.ndr.findings(); assert.equal(ndr.length, 1, 'low detections are not work items'); assert.equal(ndr[0].key, 'ndr:beacon:10.1.1.5:203.0.113.9:443');
  const mc = await A.mimecast.findings(); assert.equal(mc[0].key, 'mimecast:error');
  assert.equal((await A.fortigate.verify(fw[0])).present, true); present = false; assert.equal((await A.fortigate.verify(fw[0])).present, false, 'cleared when the fleet no longer shows it');
  assert.equal(A.fortigate.investigate(fw[0]).causes[0].fix, fw[0].recommendation);
});

test('the readiness route leaves out engineers the organisation does not run', async () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), { createState } = require('../engine/soc/state');
  const R = {}; require('../engine/duty/routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state: createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'est-')) }), config: { duty: { enabled: false } }, log: { info() {}, warn() {}, error() {} }, noTimer: true });
  const o = {}; const v = await R['GET /api/soc/duty/readiness']({ role: 'viewer', user: 'v.syn', ok(x) { o.b = x; }, fail(c, m) { o.e = m; }, need: () => true, audit() {} });
  const ids = (v || o.b).engineers.map((e) => e.id), off = require('../engine/util/brand').engineers_off || [];
  for (const id of off) assert.ok(!ids.includes(id), id + ' left out'); for (const id of ['fortigate', 'nac', 'ndr', 'mimecast']) if (!off.includes(id)) assert.ok(ids.includes(id), id + ' listed');
  assert.equal((v || o.b).of, ids.length);
});
