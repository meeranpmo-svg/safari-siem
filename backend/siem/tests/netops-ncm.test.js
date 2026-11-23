// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Configuration Management (engine/netops/ncm.js) over the read-only configuration capture with SYNTHETIC Cisco configs:
// a version kept per real change; the first copy is the baseline; a change inside an applied change plan's window is authorised,
// any other is unauthorised; off-hours flagged (Riyadh Sun-Thu 07-18); line diff; golden baseline and drift; backup states; risk
// itemised; roles (viewer counts only, analyst diffs, operator downloads / golden / backup now; an AI identity cannot set golden),
// validation names the field, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const { lineDiff, offHours } = require('../engine/netops/ncm');

const H = 3600000, DAY = 24 * H;
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const CFG1 = 'hostname SW-JED-SYN\ninterface Gi1/0/24\n switchport access vlan 20\nlogging host 10.0.0.9\nntp server 10.0.0.5';
const CFG2 = 'hostname SW-JED-SYN\ninterface Gi1/0/24\n switchport access vlan 45\n spanning-tree portfast\nlogging host 10.0.0.9\nntp server 10.0.0.5';
const CFG3 = CFG2 + '\nusername backdoor privilege 15 secret <removed>';

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ncm-'));
  const state = await createState({ dir });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  let clock = Date.parse('2026-10-27T08:00:00Z');   // Tuesday 11:00 Riyadh
  const poller = { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, alerts: { raise: () => ({}) }, now: () => clock });
  N.inventory.put({ id: 'sw-jed', name: 'SW-JED-SYN', vendor: 'cisco-ios', ip: '10.2.0.2', site: 'Jeddah Branch', role: 'access' }, 'test');
  N.inventory.put({ id: 'sw-hq', name: 'SW-HQ-SYN', vendor: 'cisco-ios', ip: '10.1.0.2', site: 'HQ', role: 'access' }, 'test');
  const R = {}, audits = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'nora.syn', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, user }), fail(c, msg) { out.status = c; out.error = msg; }, ok(x) { return x; } };
    const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  const C = state.collection('netops_config_audit'), hist = { 'sw-jed': [] };
  // a capture of a device at time t (what config-audit.js stores)
  function read(id, text, t) {
    const s = sha(text), prev = C.get(id), h = (prev && prev.history) || [];
    if (!prev || prev.sha256 !== s) h.push({ sha256: s, first_seen: t, previous_read: prev ? prev.at : null });
    C.put({ id, name: id === 'sw-jed' ? 'SW-JED-SYN' : 'SW-HQ-SYN', vendor: 'cisco-ios', site: '', at: t, checked: t, error: '', sha256: s, history: h, text });
    N.ncm.capture();
  }
  return { N, call, audits, read, at: (t) => { clock = t; }, now: () => clock, C, state };
}

test('lineDiff and working hours', () => {
  const d = lineDiff(CFG1, CFG2);
  assert.ok(d.exact); assert.deepEqual(d.lines.filter((l) => l.op !== ' ').map((l) => l.op + l.t), ['- switchport access vlan 20', '+ switchport access vlan 45', '+ spanning-tree portfast']);
  assert.equal(offHours(Date.parse('2026-10-27T08:00:00Z')), false, 'Tuesday 11:00 Riyadh'); assert.equal(offHours(Date.parse('2026-10-27T20:00:00Z')), true, '23:00');
  assert.equal(offHours(Date.parse('2026-10-30T08:00:00Z')), true, 'Friday');
});

test('versions, baseline, authorised and unauthorised changes, off-hours, golden and drift, risk; roles; audit', async () => {
  const { N, call, audits, read, at, now, state } = await setup();
  const t0 = now(); read('sw-jed', CFG1, t0 - 10 * DAY); read('sw-jed', CFG1, t0 - 9 * DAY);
  // an approved plan, applied, then the config moves: authorised
  const plan = N.changes.propose({ device: 'sw-jed', title: 'Move Gi1/0/24 to VLAN 45 (synthetic)', reason: 'claims floor', commands: ['interface Gi1/0/24', 'switchport access vlan 45'], rollback: ['switchport access vlan 20'], risk: 'low' }, 'omar.syn');
  N.changes.decide(plan.id, 'approved', 'syed', 'ok'); N.changes.markApplied(plan.id, 'omar.syn', 'done');
  { const col = state.collection('netops_changes'), p = col.get(plan.id); p.applied_at = t0 - 8 * DAY - H; col.put(p); }   // changes.js stamps the real clock
  read('sw-jed', CFG2, t0 - 8 * DAY);
  // a line appears overnight with no plan: unauthorised and off-hours
  at(t0); read('sw-jed', CFG3, Date.parse('2026-10-26T21:00:00Z'));
  read('sw-hq', CFG1, t0 - 2 * DAY);   // read 2 days ago: stale backup
  let v = (await call('GET', '/ncm', { role: 'analyst' })).body;
  const jed = v.devices.find((d) => d.id === 'sw-jed'), hq = v.devices.find((d) => d.id === 'sw-hq');
  assert.equal(jed.versions, 3, 'one version per real change'); assert.equal(jed.changes_30d, 2); assert.equal(jed.unauthorised_30d, 1);
  assert.equal(hq.backup, 'stale');
  const kinds = v.recent.filter((r) => r.device === 'sw-jed').map((r) => r.kind + (r.off_hours ? '+off' : ''));
  assert.deepEqual(kinds, ['unauthorised+off', 'authorised'], kinds.join());
  assert.equal(v.recent.find((r) => r.kind === 'authorised').plan.id, plan.id, 'the plan is named');
  assert.equal(jed.risk, jed.risk_why.reduce((s, x) => s + x.points, 0)); assert.ok(jed.risk_why.some((x) => /no approved change plan/.test(x.label)));
  assert.equal(v.kpis.unauthorised_30d, 1); assert.equal(v.kpis.no_golden, 2);
  // diff: latest against the previous
  let d = (await call('GET', '/ncm/:id/diff', { role: 'analyst', params: { id: 'sw-jed' } })).body;
  assert.equal(d.added, 1); assert.match(d.lines.find((l) => l.op === '+').t, /username backdoor/);
  // golden: an operator marks the authorised version; drift = the unauthorised line
  assert.equal((await call('POST', '/ncm/:id/golden', { role: 'analyst', params: { id: 'sw-jed' }, body: { sha256: sha(CFG2) } })).status, 403);
  assert.equal((await call('POST', '/ncm/:id/golden', { role: 'operator', user: 'ai:net', params: { id: 'sw-jed' }, body: { sha256: sha(CFG2) } })).status, 403, 'an AI identity cannot set it');
  let r = await call('POST', '/ncm/:id/golden', { role: 'operator', params: { id: 'sw-jed' }, body: { sha256: 'xyz' } }); assert.equal(r.status, 400); assert.match(r.error, /sha256/);
  r = await call('POST', '/ncm/:id/golden', { role: 'operator', params: { id: 'sw-jed' }, body: { sha256: sha(CFG2) } }); assert.equal(r.status, 200, r.error);
  v = (await call('GET', '/ncm', { role: 'analyst' })).body;
  assert.deepEqual(v.devices.find((x) => x.id === 'sw-jed').drift, { added: 1, removed: 0 });
  d = (await call('GET', '/ncm/:id/diff', { role: 'analyst', params: { id: 'sw-jed' } })).body; assert.equal(d.from.sha256, sha(CFG2), 'compares against the golden baseline by default');
  // versions, text download
  const vs = (await call('GET', '/ncm/:id/versions', { role: 'analyst', params: { id: 'sw-jed' } })).body.versions;
  assert.deepEqual(vs.map((x) => x.kind), ['unauthorised', 'authorised', 'baseline']); assert.ok(vs[1].golden);
  assert.equal((await call('GET', '/ncm/:id/text', { role: 'analyst', params: { id: 'sw-jed' }, query: { sha: sha(CFG1) } })).status, 403, 'downloading a configuration is operator');
  r = await call('GET', '/ncm/:id/text', { role: 'operator', params: { id: 'sw-jed' }, query: { sha: sha(CFG1) } }); assert.equal(r.body.text, CFG1);
  // a viewer sees counts only
  const vv = (await call('GET', '/ncm', { role: 'viewer' })).body; assert.ok(vv.limited); assert.equal(vv.devices[0].name, undefined); assert.equal(vv.recent.length, 0);
  assert.equal((await call('GET', '/ncm/:id/diff', { role: 'viewer', params: { id: 'sw-jed' } })).status, 403);
  assert.equal((await call('GET', '/ncm/:id/diff', { role: 'analyst', params: { id: 'bad id!' } })).status, 400);
  assert.ok(audits.some((a) => a.a === 'netops.ncm.golden') && audits.some((a) => a.a === 'netops.ncm.download') && audits.some((a) => a.a === 'netops.ncm.diff'));
});

test('back up now: forces a read, keeps a version, operator only, audited', async () => {
  const { N, call, audits } = await setup();
  let n = 0; N.configAudit.list = () => [];   // the capture would SSH; count the forced runs instead
  const orig = N.configAudit.run; let forced = null;
  N.configAudit.run = async (o) => { forced = o; n++; return { read: 0, failed: 0, skipped: 0 }; };
  assert.equal((await call('POST', '/ncm/backup', { role: 'analyst', body: {} })).status, 403);
  const r = await call('POST', '/ncm/backup', { role: 'operator', body: {} }); assert.equal(r.status, 200, r.error);
  assert.deepEqual(forced, { force: true }); assert.equal(n, 1); assert.ok(audits.some((a) => a.a === 'netops.ncm.backup'));
  N.configAudit.run = orig;
});
