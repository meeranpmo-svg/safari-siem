// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Change Log & NOC <-> SOC correlation (engine/netops/changecorr.js): carried-out change plans from the network / server / Kaspersky
// desks (proposed and approved-not-applied plans are not changes), NCM configuration changes authorised or not, changes recorded by a
// person; the SIEM alerts on the same system (host, device name, IP - exact) inside the window after the change, never before it and
// never on a similar name; the device's NOC state; KPIs; off-hours in Riyadh time; viewers get counts without alert text or IPs; the
// record route is operator only, validated (fields named, no future change), audited. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const CC = require('../engine/netops/changecorr');

const MIN = 60000, H = 3600000, NOW = Date.parse('2026-11-12T09:00:00Z');   // Thursday 12:00 Riyadh
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cl-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = { 'sw-a': { at: NOW, ok: false, sources: ['ping'], reach: { sent: 3, received: 0 } }, 'core-syn': { at: NOW, ok: true, sources: ['ping'], reach: { sent: 3, received: 3 } } };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const AL = [];
  const alerts = { raise() {}, all: (fn) => AL.filter(fn), list: () => ({ items: AL }) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, alerts, now: () => NOW });
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, query = {} } = {}) {
    const o = {}; const ctx = { role, user, body, params: {}, query, path: p, need(r) { if (RANK[role] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { o.status = c; o.error = msg; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !o.status) { o.status = 200; o.body = rv; } return o;
  }
  N.inventory.put({ id: 'core-syn', name: 'CORE-SYN', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core' }, 'test');
  N.inventory.put({ id: 'sw-a', name: 'SW-A-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  const plan = (col, o) => state.collection(col).put(Object.assign({ risk: 'medium', proposed_by: 'nora.syn', proposed_at: NOW - 10 * H, history: [] }, o));
  plan('netops_changes', { id: 'NCHG-000001', device: 'core-syn', title: 'Raise OSPF cost on uplink', status: 'validated', decided_by: 'adam.syn', applied_by: 'nora.syn', applied_at: NOW - 3 * H, risk: 'high', rollback: ['ip ospf cost 10'] });
  plan('netops_changes', { id: 'NCHG-000002', device: 'sw-a', title: 'Shut unused ports', status: 'execution-failed', decided_by: 'adam.syn', run: { started: NOW - 2 * H, finished: NOW - 2 * H + 5 * MIN } });
  plan('netops_changes', { id: 'NCHG-000003', device: 'sw-a', title: 'Only proposed', status: 'proposed' });
  plan('netops_changes', { id: 'NCHG-000004', device: 'sw-a', title: 'Approved, not applied', status: 'approved', decided_at: NOW - H });
  plan('sysadmin_changes', { id: 'SCHG-000001', device: 'app-syn-01', title: 'Patch IIS', status: 'applied', applied_by: 'omar.syn', applied_at: NOW - 40 * H });
  const A = (id, host, t, sev, extra) => AL.push(Object.assign({ id, rule_name: 'Synthetic rule ' + id, severity: sev, status: 'new', host, ts_first: t, ts_last: t, created: t, summary: 'synthetic alert on ' + host }, extra || {}));
  A('ALR-1', 'CORE-SYN.as.local', NOW - 3 * H + 30 * MIN, 3);                                        // 30 min after NCHG-1, host with a domain
  A('ALR-2', 'core-syn-2', NOW - 3 * H + 40 * MIN, 4);                                               // a similar name: never joined
  A('ALR-3', 'other', NOW - 3 * H + 50 * MIN, 2, { group: { src_ip: '10.0.0.2' } });                 // by the device's IP in the group
  A('ALR-4', 'CORE-SYN', NOW - 4 * H, 4);                                                            // before the change: not after it
  A('ALR-5', 'SW-A-SYN', NOW - 2 * H + 10 * MIN, 2);                                                 // after the failed change
  A('ALR-6', 'app-syn-01', NOW - 40 * H + 30 * H, 2);                                                // 30 h after: outside a 24 h window
  return { N, call, audits, AL, state };
}

test('register: carried-out plans only, failed and high risk, alerts after on the same system, NOC state, KPIs', async () => {
  const { call } = await setup();
  const r = await call('GET', '/changelog', { role: 'analyst' }); assert.equal(r.status, 200, r.error);
  const V = r.body, by = Object.fromEntries(V.changes.map((c) => [c.id, c]));
  assert.deepEqual(Object.keys(by).sort(), ['NCHG-000001', 'NCHG-000002', 'SCHG-000001'], 'proposed and approved-not-applied plans are not changes');
  const c1 = by['NCHG-000001'];
  assert.deepEqual(c1.soc.items.map((a) => a.id), ['ALR-1', 'ALR-3'], 'same host (domain dropped) and same IP; not the similar name, not before');
  assert.equal(c1.soc.first_after_min, 30); assert.equal(c1.soc.worst, 3); assert.equal(c1.ip, '10.0.0.2'); assert.match(c1.rollback, /ip ospf cost 10/);
  assert.equal(c1.noc.state, 'up'); assert.equal(by['NCHG-000002'].noc.state, 'down'); assert.equal(by['NCHG-000002'].failed, true);
  assert.equal(by['SCHG-000001'].soc.alerts, 0, '30 h later is outside the 24 h window'); assert.equal(by['SCHG-000001'].source, 'server');
  assert.deepEqual(V.kpis, { changes: 3, with_alerts: 2, with_alerts_pct: 67, unauthorised: 0, failed: 1, high_risk: 1, off_hours: 1, noc_down_now: 1 });
  assert.match(V.note, /not proof/);
  const w = await call('GET', '/changelog', { role: 'analyst', query: { window_h: '48' } });
  assert.equal(w.body.changes.find((c) => c.id === 'SCHG-000001').soc.alerts, 1, 'a 48 h window reaches it');
});

test('viewer: counts only - no alert text, no IP, no roll-back', async () => {
  const { call } = await setup();
  const V = (await call('GET', '/changelog')).body; const c1 = V.changes.find((c) => c.id === 'NCHG-000001');
  assert.equal(V.private, true); assert.equal(c1.soc.alerts, 2); assert.deepEqual(c1.soc.items, []); assert.equal(c1.ip, ''); assert.equal(c1.rollback, '');
});

test('record a change: operator only, validated, audited, then correlated like the rest', async () => {
  const { call, audits, AL } = await setup();
  const good = { what: 'Firmware upgrade on the core', target: 'CORE-SYN', category: 'network', risk: 'high', at: new Date(NOW - H).toISOString(), ticket: 'SYN-123', rollback: 'boot the previous image' };
  assert.equal((await call('POST', '/changelog', { role: 'analyst', body: good })).status, 403);
  let r = await call('POST', '/changelog', { role: 'operator', body: Object.assign({}, good, { category: 'magic' }) }); assert.equal(r.status, 400); assert.match(r.error, /category must be one of/);
  r = await call('POST', '/changelog', { role: 'operator', body: Object.assign({}, good, { what: '' }) }); assert.equal(r.status, 400); assert.match(r.error, /what is required/);
  r = await call('POST', '/changelog', { role: 'operator', body: Object.assign({}, good, { at: 'soon' }) }); assert.equal(r.status, 400); assert.match(r.error, /at must be a time/);
  r = await call('POST', '/changelog', { role: 'operator', body: Object.assign({}, good, { at: new Date(NOW + 2 * H).toISOString() }) }); assert.equal(r.status, 400); assert.match(r.error, /not in the future/);
  r = await call('POST', '/changelog', { role: 'operator', body: Object.assign({ by: 'someone.else' }, good) }); assert.equal(r.status, 200); assert.equal(r.body.id, 'CHG-000001'); assert.equal(r.body.by, 'nora.syn', 'who is the caller, never the body');
  assert.ok(audits.some((a) => a.a === 'netops.changelog.record' && a.t === 'CHG-000001' && a.user === 'nora.syn' && a.d.risk === 'high'));
  AL.push({ id: 'ALR-9', rule_name: 'Synthetic', severity: 4, status: 'new', host: 'core-syn', ts_first: NOW - H + 5 * MIN, ts_last: NOW, created: NOW - H + 5 * MIN });
  const c = (await call('GET', '/changelog', { role: 'analyst' })).body.changes.find((x) => x.id === 'CHG-000001');
  assert.equal(c.source, 'recorded'); assert.equal(c.soc.first_after_min, 5); assert.equal(c.soc.worst, 4); assert.equal(c.ticket, 'SYN-123');
  r = await call('GET', '/changelog', { role: 'analyst', query: { days: '0' } }); assert.equal(r.status, 400); assert.match(r.error, /days/);
});

test('configuration changes from NCM: unauthorised ones are high risk and counted; off-hours in Riyadh time', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cl2-')), state = await createState({ dir });
  const inv = { get: (id) => ({ 'core-syn': { id: 'core-syn', name: 'CORE-SYN', ip: '10.0.0.2' } })[id] || null, list: () => [] };
  const ncm = { view: () => ({ recent: [{ device: 'core-syn', name: 'CORE-SYN', sha256: 'a'.repeat(64), first_seen: NOW - 5 * H, kind: 'unauthorised', plan: null }, { device: 'core-syn', name: 'CORE-SYN', sha256: 'b'.repeat(64), first_seen: NOW - 50 * 86400000, kind: 'authorised', plan: { id: 'NCHG-1' } }] }) };
  const C = CC.createChangeCorr({ state, inventory: inv, ncm, now: () => NOW });
  const V = C.view({ days: 30, window_h: 24 }, 'analyst');
  assert.equal(V.changes.length, 1, 'outside the 30 days is not listed'); assert.equal(V.changes[0].authorised, false); assert.equal(V.changes[0].risk, 'high'); assert.equal(V.kpis.unauthorised, 1);
  assert.equal(V.sources.alerts, 'not available', 'no alert store: said, not shown as zero alerts silently');
  assert.equal(CC.offHours(Date.parse('2026-11-12T09:00:00Z')), false, 'Thursday 12:00 Riyadh');
  assert.equal(CC.offHours(Date.parse('2026-11-13T09:00:00Z')), true, 'Friday');
  assert.equal(CC.offHours(Date.parse('2026-11-12T16:00:00Z')), true, 'Thursday 19:00 Riyadh');
  const broken = CC.createChangeCorr({ state, inventory: inv, ncm: { view() { throw new Error('config store locked'); } }, now: () => NOW }).view({}, 'analyst');
  assert.match(broken.sources.ncm, /not available: config store locked/);
});
