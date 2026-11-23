// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Virtualization Administrator (engine/virt-admin.js on the duty desk): from the read-only capacity collection
// (fake vCenter) it opens work items for a red host, HA off, a cluster that cannot survive one host failure, old
// snapshots, disks to consolidate, Tools not running and powered-off VMs; writes the PowerCLI change plan; four-eyes
// approval (operators cannot approve, a reject needs a reason, "applied" only after approval and with a note); verifies
// with a collection taken AFTER the change; nothing connected = not connected; readiness says what is missing.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createVirtCapacity } = require('../engine/virt-capacity');
const { createSealer } = require('../engine/discovery/vault');
const { fakeVc, HEALTH } = require('./fixtures-vcenter-soap');

const ADM = { user: 'syed', role: 'admin', ip: '' };

async function setup(t, withPlatform = true) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-08-01T08:00:00Z');
  const now = () => clock;
  const dc = e.app.config.discovery;
  const sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  if (withPlatform) e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', site: 'Riyadh HQ', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  const C = createVirtCapacity(e.app, { request: fakeVc([]), now, sealer });
  e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C;
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  return { e, C, D, tick: (ms) => { clock += ms; }, now };
}

test('virt admin: health → work items; snapshot change plan; four-eyes; verified only by a later collection', async (t) => {
  const { e, C, D, tick } = await setup(t);
  await C.run(ADM);
  await D.patrol('virt');
  const items = D.list({ engineer: 'virt' }).items, by = (k) => items.filter((x) => x.kind === k);
  assert.equal(by('host-health')[0].severity, 'high'); assert.match(by('host-health')[0].title, /esx02/);
  assert.equal(by('ha-off').length, 1, 'HA off on RUH-PROD');
  assert.equal(by('n1-memory').length, 1, '840 GB in use, 768 GB left after one host');
  const snap = by('snapshot-old')[0];
  assert.equal(snap.severity, 'high', '60 days old'); assert.match(snap.title, /APP-1: 2 snapshots, oldest 60 days/);
  assert.equal(by('consolidation-needed').length, 1); assert.equal(by('tools-not-running')[0].severity, 'low'); assert.equal(by('reclaim').length, 1);
  assert.equal(by('cores-unknown').length, 0, 'cores read from vCenter');
  // the engineer wrote the plan on its own; nothing executed
  assert.equal(D.get(snap.id).status, 'awaiting-approval');
  const plan = (await e.req('GET', '/virt/changes/' + D.get(snap.id).changes[0], { role: 'viewer' })).json;
  assert.equal(plan.state, 'proposed'); assert.equal(plan.irreversible, true); assert.equal(plan.requested_by, 'duty:virt');
  assert.match(plan.commands[0].text, /Get-VM -Id 'VirtualMachine-vm-101' \| Get-Snapshot \| Where-Object \{ \$_\.Created -lt \(Get-Date\)\.AddDays\(-3\) \} \| Remove-Snapshot/, 'addressed by ID, never by name');
  assert.ok(plan.prechecks.some((x) => /backup job/.test(x)));
  // four-eyes
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/approve`, { role: 'operator', body: {} })).status, 403, 'operators cannot approve');
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/applied`, { role: 'operator', body: { note: 'x' } })).status, 409, 'not before approval');
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/approve`, { user: 'syed', role: 'admin', body: { comment: 'owner confirmed' } })).status, 200);
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/applied`, { role: 'operator', body: {} })).status, 400, 'a note is required');
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/applied`, { user: 'ali', role: 'operator', body: { note: 'deleted 2 snapshots in vCenter' } })).status, 200);
  // an operator's own request cannot be decided by that operator
  const ha = by('ha-off')[0], hp = D.get(ha.id).changes[0];
  const own = await e.req('POST', '/virt/changes', { user: 'ali', role: 'operator', body: { item_id: by('host-health')[0].id } });
  assert.equal(own.status, 409, 'a red host has no plan: it needs a person');
  assert.equal((await e.req('POST', `/virt/changes/${hp}/reject`, { role: 'admin', body: {} })).status, 400, 'reject needs a reason');
  // after "applied": the collection taken BEFORE the change proves nothing
  tick(20 * 60000); await D.patrol('virt');
  assert.equal(D.get(snap.id).status, 'fix-applied');
  // the snapshots are gone in vCenter; a fresh read-only collection confirms it
  const saved = HEALTH.VirtualMachine; HEALTH.VirtualMachine = saved.filter((x) => !/vm-101/.test(x));
  try {
    tick(60000); await C.run(ADM);
    tick(20 * 60000); await D.patrol('virt');
    assert.equal(D.get(snap.id).status, 'resolved', JSON.stringify(D.get(snap.id).history.slice(-3)));
  } finally { HEALTH.VirtualMachine = saved; }
  const audit = (await e.req('GET', '/audit?limit=300', { role: 'admin' })).json.audit;
  for (const a of ['virt.change.propose', 'virt.change.approve', 'virt.change.applied']) assert.ok(audit.some((x) => x.action === a), a);
  const ov = (await e.req('GET', '/virt/admin', { role: 'viewer' })).json;
  assert.equal(ov.installed, true); assert.ok(ov.hosts.every((h) => h.cores_per_socket === 24)); assert.equal(ov.clusters[0].ha, false);
});

test('virt admin: nothing connected = not connected; readiness names the fix; policy is admin-only and validated', async (t) => {
  const { e, D } = await setup(t, false);
  assert.equal((await D.patrol('virt')).not_connected, true);
  const r = (await e.req('GET', '/duty/readiness', { role: 'viewer' })).json.engineers.find((x) => x.id === 'virt');
  assert.equal(r.status, 'blocked'); assert.ok(r.to_fix.some((f) => /Virtualization → add each vCenter/.test(f.fix)));
  assert.equal((await e.req('PUT', '/virt/admin/policy', { role: 'operator', body: {} })).status, 403);
  assert.equal((await e.req('PUT', '/virt/admin/policy', { role: 'admin', body: { snapshot_warn_days: 10, snapshot_high_days: 5 } })).status, 400);
  assert.equal((await e.req('PUT', '/virt/admin/policy', { role: 'admin', body: { snapshot_warn_days: 7 } })).json.snapshot_warn_days, 7);
});

test('virt admin: commands never carry platform names (IDs only, quotes doubled); the approver cannot also record "applied"', async (t) => {
  const { e, C, D } = await setup(t);
  await C.run(ADM);
  // a VM renamed in vCenter to something hostile: the plan addresses it by ID, the name appears only in display text
  e.app.store.collection('virt_capacity').patch('vp_1', (m) => { const v = m.vms.find((x) => x.id === 'vm-101'); v.name = "x'; Remove-VM * -Confirm:$false ‘"; return m; });
  await D.patrol('virt');
  const snap = D.list({ engineer: 'virt' }).items.find((x) => x.kind === 'snapshot-old');
  const plan = (await e.req('GET', '/virt/changes/' + D.get(snap.id).changes[0], { role: 'viewer' })).json;
  assert.ok(plan.commands.every((c) => !/Remove-VM/.test(c.text)), 'no platform name inside a command');
  assert.match(plan.commands[0].text, /-Id 'VirtualMachine-vm-101'/);
  const { createVirtAdmin } = require('../engine/virt-admin');
  const V = createVirtAdmin(e.app);
  assert.equal(V.planFor({ key: 'x', kind: 'snapshot-old', target: { type: 'vm', id: "vp_1:vm-1'; rm", name: 'x', kind: 'vcenter' }, data: {} }), null, 'an ID of an unexpected shape gives no plan');
  // four-eyes on apply
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/approve`, { user: 'syed', role: 'admin', body: {} })).status, 200);
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/applied`, { user: 'SYED ', role: 'admin', body: { note: 'done' } })).status, 403, 'same person (any case / spaces) cannot approve and apply');
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/applied`, { user: 'ali', role: 'operator', body: { note: 'done in vCenter' } })).status, 200);
});
