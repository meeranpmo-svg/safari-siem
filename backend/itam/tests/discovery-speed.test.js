// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Active probing speed: per host, the TCP ports and the SNMP probe run at the same time, so a silent address costs one
// timeout instead of the sum of all of them; progress (phase, done / total, alive) is reported while it runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../engine/discovery/runner');

test('silent hosts cost one timeout, not the sum of the ports; progress is reported', async () => {
  const DELAY = 120, PORTS = [22, 80, 135, 443, 445, 3389, 5985];
  const connect = (host, port) => new Promise((r) => setTimeout(() => r(host === '10.9.0.5' && port === 443 ? 'open' : 'timeout'), DELAY));
  const run = { id: 'dr_t', stats: {}, progress: {}, seen: new Set() };
  const seenProgress = [];
  const ctx = {
    vault: { open: () => ({ release() {} }) }, devices: { observe: (o) => ({ id: 'd' + o.ip }), list: () => [] },
    deps: { connect }, settings: () => ({ icmp_mode: 'ping' }), log: { info() {}, warn() {} }, config: { discovery: { tcp_timeout_ms: DELAY, snmp_timeout_ms: DELAY, max_hosts_per_scope: 4096 } },
    isCancelled: () => false, onProgress: () => seenProgress.push(Object.assign({}, run.progress)), stopWindow() {},
  };
  const scope = { id: 's1', site: 'Riyadh HQ', targets: ['10.9.0.1-10.9.0.16'], exclusions: [], window: null, rate: { max_hosts_per_sec: 500, concurrency: 8 },
    methods: { sweep: { enabled: true, icmp: false, tcp_ports: PORTS }, snmp: { enabled: false, credential_ids: [] } } };
  const t0 = Date.now();
  await runner.execute({ run, scope, allowed: ['sweep'], ctx });
  const ms = Date.now() - t0;
  // sequential would be 16 hosts / 8 workers * 7 ports * 120 ms = 1680 ms; parallel ≈ 2 * 120 ms
  assert.ok(ms < 900, `took ${ms} ms`);
  assert.equal(run.progress.hosts_done, 16); assert.equal(run.progress.hosts_total, 16); assert.equal(run.progress.alive, 1);
  assert.ok(seenProgress.some((p) => p.phase === 'probe'));
});
