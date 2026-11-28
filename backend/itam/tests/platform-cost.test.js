// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cost Optimisation platform scenarios (engine/platform-cost.js) over a SYNTHETIC collected estate: consolidation from MEASURED
// CPU / memory (a cluster without usage is not computed and says so); non-production VMs by word-bounded names (not "devops" /
// "contest"); AHV only where Nutanix runs; powered-off VMs; backup platforms and SPARC from the register; a recorded VMware licence
// wins over the planning figure; assumptions admin-only, validated, versioned (409), audited; business cases four-eyes (the
// proposer cannot decide, a service identity cannot, a reason is required); viewers refused (costs); nothing connected = honest.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { NONPROD } = require('../engine/platform-cost');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'huda.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const host = (name, cluster, used) => ({ platform: 'vc-syn', cluster, name, sockets: 2, cores: 32, cpu_ghz: 2.5, cpu_used_pct: used ? used[0] : null, mem_gb: 512, mem_used_pct: used ? used[1] : null });
async function setup(t, estate = true) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  if (estate) {
    const hosts = [1, 2, 3, 4, 5, 6].map((i) => host('esx' + i, 'PROD', [12, 20])).concat([host('esx7', 'DMZ', null), host('esx8', 'DMZ', null)]).concat([{ platform: 'prism-syn', cluster: 'NTX', name: 'ntx1', sockets: 2, cores: 24, cpu_ghz: 2.4, cpu_used_pct: 30, mem_gb: 384, mem_used_pct: 40 }]);
    const vms = ['app-prod-01', 'uat-crm-01', 'dev-api', 'test_portal', 'devops-runner', 'contest-web', 'sql-qa-02'].map((n) => ({ name: n, platform: 'vc-syn', cluster: 'PROD', power: 'on', disk_gb: 100 })).concat([{ name: 'old-ftp', platform: 'vc-syn', cluster: 'PROD', power: 'off', disk_gb: 400 }]);
    e.app.addons.virtCapacity = { report: () => ({ platforms: [{ label: 'vc-syn', kind: 'vcenter', at: Date.now() }, { label: 'prism-syn', kind: 'nutanix', at: Date.now() }], hosts, vms }) };
    const A = e.app.store.collection('assets'), now = new Date().toISOString();
    A.put({ id: 'bk1', name: 'BKP-SYN-1', type: 'server', status: 'in_use', software: [{ name: 'Veeam Backup & Replication' }], updated_at: now });
    A.put({ id: 'bk2', name: 'BKP-SYN-2', type: 'server', status: 'in_use', software: [{ name: 'Commvault Simpana' }], updated_at: now });
    A.put({ id: 'sp1', name: 'SPARC-SYN-1', type: 'server', status: 'in_use', os: 'Oracle Solaris 11.4', model: 'SPARC T8-1', updated_at: now });
  }
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('non-production names are word-bounded', () => {
  for (const n of ['uat-crm-01', 'dev-api', 'test_portal', 'sql-qa-02', 'SRV-STAGING']) assert.ok(NONPROD.test(n), n);
  for (const n of ['devops-runner', 'contest-web', 'latest-app', 'quality']) assert.ok(!NONPROD.test(n), n);
});

test('scenarios from the measured estate: consolidation, non-prod, AHV, reclaim, backup, SPARC', async (t) => {
  const { call } = await setup(t);
  assert.equal((await call('GET', '/platform-cost', undefined, VW)).status, 403, 'costs are not shown to viewers');
  const v = (await call('GET', '/platform-cost', undefined, OP)).json, R = Object.fromEntries(v.recs.map((r) => [r.id, r]));
  assert.equal(v.facts.vmware_hosts, 8); assert.equal(v.facts.nutanix_nodes, 1);
  const prod = R.R1.clusters.find((c) => c.cluster === 'vc-syn / PROD'), dmz = R.R1.clusters.find((c) => c.cluster === 'vc-syn / DMZ');
  assert.equal(prod.measured, true); assert.equal(prod.need, 3, '6 hosts at 12 % CPU / 20 % memory need 2 at the 70 % / 80 % ceilings, + N+1'); assert.equal(prod.freed, 3);
  assert.equal(dmz.measured, false); assert.match(R.R1.evidence, /Not computed for vc-syn \/ DMZ/);
  assert.ok(R.R1.saving.low > 0 && R.R1.saving.high >= R.R1.saving.low);
  assert.equal(v.facts.nonprod_vms, 4, 'uat, dev, test, qa - not devops / contest'); assert.ok(R.R2);
  assert.ok(R.R3 && /Nutanix AHV/.test(R.R3.title)); assert.ok(R.R4 && /400 GB/.test(R.R4.title)); assert.ok(R.R5 && /Veeam, Commvault/.test(R.R5.evidence)); assert.ok(R.R6 && /SPARC-SYN-1/.test(R.R6.evidence));
  assert.match(v.per_host.vmware_src, /^assumption/);
  assert.equal(v.totals.low, v.recs.reduce((n, r) => n + (r.saving ? r.saving.low : 0), 0));
});

test('a recorded VMware licence wins over the planning figure; assumptions admin-only, validated, versioned, audited', async (t) => {
  const { e, call } = await setup(t);
  e.app.store.collection('licences').put({ id: 'lic-vmw', vendor: 'VMware', product: 'vSphere Foundation', annual_cost: 400000, status: 'active' });
  let v = (await call('GET', '/platform-cost', undefined, OP)).json;
  assert.match(v.per_host.vmware_src, /^recorded: 1 VMware licence/); assert.equal(v.per_host.vmware, 50000, '400 000 over 8 hosts');
  assert.equal((await call('POST', '/platform-cost/assumptions', { host_run_sar: 1 }, OP)).status, 403);
  assert.equal((await call('POST', '/platform-cost/assumptions', { host_run_sar: 1 }, { user: 'system:bot', role: 'admin' })).status, 403);
  let r = await call('POST', '/platform-cost/assumptions', { cpu_target_pct: 120 }, ADM); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /cpu_target_pct/);
  r = await call('POST', '/platform-cost/assumptions', { host_run_sar: 'x' }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/platform-cost/assumptions', { host_run_sar: 12000, baseVersion: 0, extra: 5 }, ADM); assert.equal(r.status, 200); assert.equal(r.json.version, 1);
  assert.equal((await call('POST', '/platform-cost/assumptions', { host_run_sar: 13000, baseVersion: 0 }, ADM2)).status, 409, 'stale version refused');
  v = (await call('GET', '/platform-cost', undefined, OP)).json; assert.equal(v.assumptions.values.host_run_sar, 12000); assert.deepEqual(v.assumptions.changed, ['host_run_sar']); assert.equal(v.assumptions.by, ADM.user);
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'platform_cost.assumptions' && a.detail.changes.host_run_sar.to === 12000));
  r = await call('POST', '/platform-cost/assumptions', { reset: true }, ADM); assert.equal(r.status, 200);
  v = (await call('GET', '/platform-cost', undefined, OP)).json; assert.equal(v.assumptions.values.host_run_sar, 9000);
});

test('business cases are four-eyes and audited', async (t) => {
  const { e, call } = await setup(t);
  assert.equal((await call('POST', '/platform-cost/cases', { rec: 'R1' }, VW)).status, 403);
  assert.equal((await call('POST', '/platform-cost/cases', { rec: 'R9' }, OP)).status, 400);
  let r = await call('POST', '/platform-cost/cases', { rec: 'R1', note: 'synthetic' }, OP); assert.equal(r.status, 200, JSON.stringify(r.json)); const id = r.json.case.id;
  assert.equal((await call('POST', '/platform-cost/cases', { rec: 'R1' }, OP)).status, 409, 'one open case per scenario');
  assert.equal((await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'approve', reason: 'ok' }, OP)).status, 403, 'operators do not decide');
  { const x = await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'approve', reason: 'ok' }, { user: 'Nora.Syn', role: 'admin' }); assert.equal(x.status, 403); assert.match(x.json.error, /four-eyes/, 'the proposer under another spelling of their name'); }
  assert.equal((await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'approve' }, ADM)).status, 400, 'a reason is required');
  assert.equal((await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'approve', reason: 'ok' }, { user: 'system:ai', role: 'admin' })).status, 403);
  // the proposer cannot decide: an admin proposes, the same admin is refused
  const id2 = (await call('POST', '/platform-cost/cases', { rec: 'R4' }, ADM)).json.case.id;
  r = await call('POST', '/platform-cost/cases/' + id2 + '/decide', { decision: 'approve', reason: 'mine' }, ADM); assert.equal(r.status, 403); assert.match(JSON.stringify(r.json), /four-eyes/);
  r = await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'approve', reason: 'measured, N+1 kept (synthetic)' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.case.status, 'approved'); assert.equal(r.json.case.decided_by, ADM.user);
  assert.equal((await call('POST', '/platform-cost/cases/' + id + '/decide', { decision: 'reject', reason: 'x' }, ADM2)).status, 409, 'decided once');
  assert.equal((await call('POST', '/platform-cost/cases/pcc_nope/decide', { decision: 'reject', reason: 'x' }, ADM2)).status, 404);
  const v = (await call('GET', '/platform-cost', undefined, OP)).json; assert.equal(v.recs.find((x) => x.id === 'R1').case.status, 'approved');
  const au = e.app.store.auditTail(40); assert.ok(au.some((a) => a.action === 'platform_cost.case.propose' && a.by === OP.user)); assert.ok(au.some((a) => a.action === 'platform_cost.case.approved' && a.by === ADM.user && a.detail.proposed_by === OP.user));
});

test('nothing collected: no scenario invented', async (t) => {
  const { call } = await setup(t, false);
  const v = (await call('GET', '/platform-cost', undefined, OP)).json;
  assert.equal(v.connected, false); assert.deepEqual(v.recs, []); assert.equal(v.totals.low, 0);
});
