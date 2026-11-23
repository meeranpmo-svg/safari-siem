// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scope Studio (engine/discovery-advisor.js, pyengine/scope_rules.py) through the real routes and the real Asset Discovery
// engine on SYNTHETIC scopes, runs, devices and assets: coverage per /24, a gap with assets becomes a proposal with methods
// chosen from what the subnet holds, scope health with every point explained, an anomaly in the devices a run saw, an idle
// method, a port calling for a method that is off, the learned run-time model, accepting a proposal creates the scope with a
// manual schedule and its safety gate closed, dismissing needs a reason and is remembered, roles (viewer refused, operator
// reads, admin decides, a service identity never accepts), validation errors and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:discovery', role: 'admin' };
const NOW = Date.parse('2026-10-30T09:00:00Z');
const iso = (ms) => new Date(ms).toISOString();

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const D = e.app.discovery, site = D.sites()[0];
  const core = D.createScope({ name: 'HQ servers (synthetic)', site, targets: ['10.20.1.0/24'], methods: { sweep: { enabled: true }, arp: { enabled: true } }, schedule: { type: 'manual' } }, ADM);
  // 7 finished runs: ~40 devices each, the last one only 8 (a firewall change?)
  const runs = e.app.store.collection('disc_runs');
  const seen = [40, 41, 39, 40, 42, 40, 8];
  seen.forEach((n, i) => {
    const st = NOW - (8 - i) * 86400000;
    runs.put({ id: 'dr_s' + i, scope_id: core.id, scope_name: core.name, status: 'finished', started_at: iso(st), finished_at: iso(st + (300 + i) * 1000), devices_seen: n, devices_new: i === 6 ? 0 : 1, methods_run: ['sweep', 'arp'], progress: { hosts_total: 254, alive: n } });
  });
  // what the scans found in 10.20.1.0/24: servers answering SSH and SQL Server, nothing found by SNMP
  const devs = e.app.store.collection('disc_devices');
  for (let i = 1; i <= 6; i++) devs.put({ id: 'dd_' + i, ip: '10.20.1.' + (10 + i), type: 'server', open_ports: i <= 4 ? [22, 1433] : [22], methods: { sweep: {} }, scope_id: core.id, site, status: 'new' });
  // the asset register knows two subnets no scope covers
  for (let i = 1; i <= 5; i++) e.app.assets.create({ name: 'SW-SYN-' + i, type: 'network', status: 'in_use', mgmt_ip: '10.30.5.' + i, site }, ADM);
  e.app.assets.create({ name: 'SRV-SYN-9', type: 'server', status: 'in_use', mgmt_ip: '10.40.7.9', site }, ADM);
  e.app.assets.create({ name: 'SRV-SYN-1', type: 'server', status: 'in_use', mgmt_ip: '10.20.1.11', site }, ADM);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, D, core, site, call };
}
const auditOf = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('coverage, gaps as proposals, scope health with reasons, anomaly, tuning, learned run time', async (t) => {
  const { call, core } = await setup(t);
  const r = await call('GET', '/discovery/advisor', undefined, OP);
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.summary.subnets, 3); assert.equal(v.summary.covered, 1); assert.equal(v.summary.uncovered, 2);
  assert.equal(v.summary.assets_with_ip, 7); assert.equal(v.summary.assets_covered, 1); assert.equal(v.summary.coverage_pct, 14);
  const p = v.proposals.find((x) => x.subnet === '10.30.5.0/24');
  assert.ok(p, 'the switches subnet is proposed first');
  assert.equal(v.proposals[0].subnet, '10.30.5.0/24', 'most assets first');
  assert.ok(p.methods.includes('sweep') && p.methods.includes('snmp'), 'network gear: sweep + SNMP proposed');
  assert.match(p.why[0], /5 asset\(s\) in the register/);
  assert.ok(p.estimate, 'expected run time from the learned model');
  const h = v.scopes.find((x) => x.id === core.id);
  assert.ok(h.health < 80, 'gate closed + anomaly lower the score: ' + h.health);
  assert.ok(h.why.some((w) => /safety gate closed/.test(w.why)) && h.why.some((w) => /usually 40/.test(w.why)), 'every point explained');
  assert.equal(h.anomaly.seen, 8); assert.ok(h.anomaly.z <= -3.5);
  const recs = h.recommendations.map((x) => x.text).join(' | ');
  assert.match(recs, /ARP cache ran 7 times and found nothing/);
  assert.match(recs, /Enable Unix \/ SSH: 6 host\(s\) answer SSH/);
  assert.match(recs, /Enable Database listeners: 4 database listener/);
  assert.deepEqual(h.trend, [40, 41, 39, 40, 42, 40, 8]);
  assert.equal(v.learned.duration_model.n, 7); assert.ok(v.learned.duration_model.r2 >= 0);
  assert.equal(v.ai.enabled, false); assert.match(v.ai.reason, /external AI is not allowed/);
});

test('accept creates the scope with a manual schedule and the gate closed; dismiss needs a reason and is remembered; roles; audit', async (t) => {
  const { e, call, site } = await setup(t);
  let r = await call('GET', '/discovery/advisor', undefined, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/discovery/advisor/accept', { key: 'new:10.30.5.0/24' }, OP); assert.equal(r.status, 403, 'operators do not create scopes');
  r = await call('POST', '/discovery/advisor/accept', { key: 'new:10.30.5.0/24' }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /a person does/);
  r = await call('POST', '/discovery/advisor/accept', { key: 'bogus' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /key is not a proposal key/);
  r = await call('POST', '/discovery/advisor/accept', { key: 'new:10.99.9.0/24' }, ADM); assert.equal(r.status, 404);
  r = await call('POST', '/discovery/advisor/accept', { key: 'new:10.30.5.0/24', name: 'HQ switches (synthetic)', extra: 'dropped' }, ADM);
  assert.equal(r.status, 200, r.raw);
  const sc = r.json.scope;
  assert.equal(sc.name, 'HQ switches (synthetic)'); assert.deepEqual(sc.targets, ['10.30.5.0/24']); assert.equal(sc.site, site);
  assert.equal(sc.schedule.type, 'manual'); assert.equal(sc.gate.open, false, 'active methods blocked until the checklist');
  assert.ok(sc.blocked_methods.some((b) => b.method === 'sweep'));
  assert.match(r.json.note, /pre-scan checklist/);
  assert.ok(!sc.methods.snmp.enabled && r.json.left_off.some((x) => x.method === 'snmp' && /no snmp_v2c \/ snmp_v3 credential saved/.test(x.reason)), 'SNMP left off without a credential, and said');
  const a = auditOf(e, 'discovery.advisor.accept'); assert.equal(a.length, 1); assert.equal(a[0].by, 'syed'); assert.equal(a[0].detail.scope_id, sc.id);
  assert.equal(auditOf(e, 'discovery.scope.create').length, 2, 'the scope itself is audited by Asset Discovery too');
  r = await call('GET', '/discovery/advisor', undefined, OP);
  assert.ok(!r.json.proposals.some((x) => x.subnet === '10.30.5.0/24'), 'now covered: no longer proposed');
  r = await call('POST', '/discovery/advisor/dismiss', { key: 'new:10.40.7.0/24' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/discovery/advisor/dismiss', { key: 'new:10.40.7.0/24', reason: 'lab network, not ours (synthetic)' }, ADM); assert.equal(r.status, 200);
  r = await call('GET', '/discovery/advisor', undefined, OP);
  assert.ok(!r.json.proposals.some((x) => x.subnet === '10.40.7.0/24'), 'a dismissed proposal is not raised again');
  assert.equal(r.json.decided.find((x) => x.key === 'new:10.40.7.0/24').reason, 'lab network, not ours (synthetic)');
  assert.equal(auditOf(e, 'discovery.advisor.dismiss')[0].detail.reason, 'lab network, not ours (synthetic)');
  r = await call('POST', '/discovery/advisor/ai/ask', { question: 'what is missing?' }, OP); assert.equal(r.status, 403, 'the AI advisor is for System Admins');
  r = await call('POST', '/discovery/advisor/ai/ask', { question: 'what is missing?' }, ADM); assert.equal(r.status, 503, 'AI not allowed yet');
});
