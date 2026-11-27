// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V VMs into the inventory automatically (discovery/index.js ingestHyperv + scope methods.hyperv.auto_register), SYNTHETIC hosts
// and VMs: off by default (VMs wait in Discovery); an administrator switches it on for the scope (an operator is refused); the next
// report registers each new VM as a VM asset with its guest OS and DNS name; a VM that looks like an existing record is left for a
// person; a second report adds nothing twice; audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const ADM = { user: 'admin.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' };
const report = (extra = []) => ({ collected_at: new Date().toISOString(), host: { name: 'HV-SYN-01', ip: '10.20.8.10', os: 'Windows Server 2022 Datacenter' },
  vms: [{ name: 'APP-SYN-01', vm_id: 'aaaaaaaa-0000-0000-0000-000000000001', state: 'Running', os: 'Windows Server 2022 Standard (10.0.20348)', fqdn: 'app-syn-01.corp.example', ips: ['10.20.8.21'], macs: ['00155D010201'] },
    { name: 'WEB-SYN-01', vm_id: 'aaaaaaaa-0000-0000-0000-000000000002', state: 'Off', ips: [], macs: ['00155D010202'] }].concat(extra) });

test('VMs into the inventory: off by default, switched on by an administrator, look-alikes held for a person', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const assets = () => e.app.store.collection('assets').all();
  let r = await call('POST', '/discovery/scopes', { name: 'HQ Hyper-V', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ADM); assert.equal(r.status, 200, r.text);
  const sid = r.json.scope.id;
  r = await call('POST', '/discovery/hyperv/import', { scope_id: sid, report: report() }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.registered, 0);
  assert.ok(!assets().some((a) => String(a.name).toUpperCase() === 'APP-SYN-01'), 'off by default: the VM waits in Discovery');
  assert.equal((await call('POST', '/discovery/scopes/' + sid, { methods: { hyperv: { enabled: true, auto_register: true } } }, OP)).status, 403);
  r = await call('POST', '/discovery/scopes/' + sid, { methods: { hyperv: { enabled: true, auto_register: 'yes' } } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /auto_register/);
  r = await call('POST', '/discovery/scopes/' + sid, { methods: { hyperv: { enabled: true, auto_register: true } } }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.scope.methods.hyperv.auto_register, true);
  assert.equal((await call('GET', '/discovery/hyperv/hosts', undefined, ADM)).json.scopes[0].auto_register, true);
  // a record that already exists for a third VM: the look-alike is held
  await call('POST', '/assets', { name: 'DB-SYN-01', type: 'server', mac: '00:15:5d:01:02:03' }, OP);
  r = await call('POST', '/discovery/hyperv/import', { scope_id: sid, report: report([{ name: 'DB-SYN-01', vm_id: 'aaaaaaaa-0000-0000-0000-000000000003', state: 'Running', macs: ['00155D010203'] }]) }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.registered, 2); assert.equal(r.json.left_for_review, 1);
  const A = assets().find((a) => String(a.name).toUpperCase() === 'APP-SYN-01'); assert.ok(A, 'registered: ' + JSON.stringify(assets().map((a) => [a.name, a.type, a.os]))); assert.equal(A.type, 'vm'); assert.match(A.os || '', /Windows Server 2022 Standard/);
  assert.ok(assets().some((a) => String(a.name).toUpperCase() === 'WEB-SYN-01' && a.type === 'vm'), 'an off VM is registered too');
  assert.equal(assets().filter((a) => /DB-SYN-01/i.test(a.name)).length, 1, 'the look-alike is not duplicated');
  r = await call('POST', '/discovery/hyperv/import', { scope_id: sid, report: report() }, ADM); assert.equal(r.json.registered, 0, 'nothing twice');
  assert.equal(assets().filter((a) => String(a.name).toUpperCase() === 'APP-SYN-01').length, 1);
  assert.ok(e.app.store.auditTail(300).some((x) => x.action === 'discovery.hyperv.auto_register' && x.detail && x.detail.registered === 2));
});
