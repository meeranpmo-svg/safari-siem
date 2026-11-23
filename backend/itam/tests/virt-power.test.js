// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Power control (engine/virt-power.js): restart / shut down / start of ESXi hosts, VMware VMs, Nutanix AHV hosts and VMs as
// change plans. Roles (viewer reads, operator asks, approver decides, admin sets controllers), validation (fields named,
// undeclared fields dropped), the safety checks (cluster room, standalone host, DRS, one Nutanix node at a time, Tools),
// commands built from IDs only (never names), four-eyes (requester, approver, service identities), 24 h approval expiry,
// verification by a later collection, and the audit trail. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerVirtPower } = require('../engine/virt-power');

const GB = 1073741824, T0 = Date.parse('2026-10-22T08:00:00Z');
function fixture(store, at, over = {}) {
  store.collection('virt_platforms').put({ id: 'vp_v', kind: 'vcenter', label: 'VC-SYN' });
  store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE-SYN' });
  store.collection('virt_capacity').put(Object.assign({ id: 'vp_v', kind: 'vcenter', label: 'VC-SYN', at: new Date(at).toISOString(),
    clusters: [{ id: 'domain-c1', name: 'SYN-PROD', drs: false, ha: true }],
    hosts: [
      { id: 'host-11', name: 'esx-syn-01', cluster_id: 'domain-c1', cluster: 'SYN-PROD', state: 'connected', maintenance: false, mem_bytes: 512 * GB, mem_used_bytes: 200 * GB },
      { id: 'host-12', name: 'esx-syn-02', cluster_id: 'domain-c1', cluster: 'SYN-PROD', state: 'connected', maintenance: false, mem_bytes: 512 * GB, mem_used_bytes: 450 * GB },
      { id: 'host-13', name: 'esx-syn-03', cluster_id: null, cluster: 'Standalone hosts', state: 'connected', maintenance: false, mem_bytes: 256 * GB, mem_used_bytes: 10 * GB },
      { id: 'host-14', name: 'esx-syn-04', cluster_id: null, cluster: 'Standalone hosts', state: 'notResponding', maintenance: false },
      { id: '12345', name: 'odd-id-host', cluster_id: null, cluster: 'Standalone hosts', state: 'connected', maintenance: false }],
    vms: [
      { id: 'vm-101', name: 'APP-SYN-1', host_id: 'host-11', power: 'on', mem_mb: 65536, tools: 'running' },
      { id: 'vm-102', name: 'DB-SYN-1; Stop-VMHost', host_id: 'host-11', power: 'on', mem_mb: 131072, tools: 'not-running' },
      { id: 'vm-103', name: 'OFF-SYN-1', host_id: 'host-12', power: 'off', mem_mb: 4096, tools: null },
      { id: 'vm-104', name: 'vcsa-syn', host_id: 'host-12', power: 'on', mem_mb: 16384, tools: 'running' },
      { id: 'vm-105', name: 'STANDALONE-SYN', host_id: 'host-13', power: 'on', mem_mb: 8192, tools: 'running' }] }, over.v || {}));
  const U = (n) => `0000000${n}-aaaa-bbbb-cccc-00000000000${n}`;
  store.collection('virt_capacity').put(Object.assign({ id: 'vp_n', kind: 'nutanix', label: 'PE-SYN', at: new Date(at).toISOString(),
    clusters: [{ id: 'c1', name: 'NTX-SYN' }],
    hosts: [1, 2, 3].map((n) => ({ id: U(n), name: 'NTNX-SYN-' + n, cluster_id: 'c1', cluster: 'NTX-SYN', state: 'connected', maintenance: n === 3 && !over.allUp, mem_bytes: 768 * GB, mem_used_bytes: 100 * GB, ip: '10.99.0.1' + n, cvm_ip: '10.99.0.2' + n, bmc_ip: '10.99.9.1' + n })),
    vms: [{ id: U(7), name: 'NTX-APP-SYN', host_id: U(1), power: 'on', mem_mb: 32768 }] }, over.n || {}));
  return U;
}
async function setup(t, over) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = T0; const now = () => clock;
  const U = fixture(e.app.store, T0 - 10 * 60000, over);
  const V = registerVirtPower(e.app.srv, e.app, { noTimer: true, now });
  return { e, V, U, now, tick: (ms) => { clock += ms; } };
}
const ask = (e, user, b) => e.req('POST', '/virt/power/requests', { user, role: 'operator', body: b });
const audits = (e, re) => e.app.store.auditTail(200, (x) => re.test(x.action || '')).reverse();   // oldest first

test('roles and validation: viewer reads, operator asks, fields named, undeclared fields dropped', async (t) => {
  const { e } = await setup(t);
  const g = await e.req('GET', '/virt/power', { role: 'viewer' });
  assert.equal(g.status, 200); assert.equal(g.json.hosts.length, 8); assert.equal(g.json.vms.length, 6);
  assert.equal(g.json.hosts.find((h) => h.id === 'host-11').vms_on, 2);
  const ntx = g.json.hosts.find((h) => h.name === 'NTNX-SYN-1'); assert.equal(ntx.bmc.address, '10.99.9.11'); assert.equal(ntx.bmc.source, 'read from Prism');
  assert.equal((await e.req('POST', '/virt/power/requests', { role: 'viewer', body: { platform_id: 'vp_v', target_id: 'vm-101', action: 'restart', reason: 'patching window' } })).status, 403, 'viewer cannot ask');
  const miss = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'restart' });
  assert.equal(miss.status, 400); assert.match(miss.json.error, /reason is required/);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'restart', reason: 'short' })).json.error, /reason must be at least 10/);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101;rm', action: 'restart', reason: 'patching window tonight' })).json.error, /target_id is not a valid id/);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'destroy', reason: 'patching window tonight' })).json.error, /action must be one of: start, shutdown, restart, power-off, reset/);
  assert.equal((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-999', action: 'start', reason: 'patching window tonight' })).status, 404);
  // a client cannot make its own request approved or name another requester
  const r = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'restart', reason: 'monthly patching, owner informed', state: 'approved', requested_by: 'someone', decided_by: 'boss' });
  assert.equal(r.status, 200); assert.equal(r.json.state, 'proposed'); assert.equal(r.json.requested_by, 'ali'); assert.equal(r.json.decided_by, undefined);
  assert.equal((await ask(e, 'omar', { platform_id: 'vp_v', target_id: 'vm-101', action: 'shutdown', reason: 'second request same VM' })).status, 409, 'one open plan per target');
  assert.equal((await e.req('GET', '/virt/power/requests?state=bogus', { role: 'viewer' })).status, 400);
});

test('VM plans: state must fit, a guest operation needs Tools, commands address the VM by id only', async (t) => {
  const { e } = await setup(t);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'start', reason: 'start it again please' })).json.error, /already running/);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-103', action: 'shutdown', reason: 'shut it down please' })).json.error, /not running/);
  const nt = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-102', action: 'shutdown', reason: 'DB maintenance tonight' });
  assert.equal(nt.status, 409); assert.match(nt.json.error, /Tools are not-running .* hard power-off/);
  const off = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-102', action: 'power-off', reason: 'hung guest, owner agreed' });
  assert.equal(off.status, 200); assert.equal(off.json.risk, 'high');
  assert.ok(off.json.checks.some((c) => c.name === 'Hard power operation' && c.status === 'warn'));
  const cmd = off.json.commands.map((c) => c.text).join('\n');
  assert.match(cmd, /Get-VM -Id 'VirtualMachine-vm-102'/); assert.match(cmd, /Stop-VM -VM \$vm -Confirm:\$false/);
  assert.ok(!cmd.includes('DB-SYN-1'), 'the VM name (attacker-controlled) never reaches a command');
  const st = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-103', action: 'start', reason: 'needed for month end' });
  assert.match(st.json.commands[0].text, /Start-VM -VM \$vm/);
  const mg = await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-104', action: 'restart', reason: 'vCenter patch applied' });
  assert.ok(mg.json.checks.some((c) => c.name === 'Management VM' && c.status === 'warn'));
  const nv = await ask(e, 'ali', { platform_id: 'vp_n', target_id: '00000007-aaaa-bbbb-cccc-000000000007', action: 'shutdown', reason: 'app retired this week' });
  assert.equal(nv.status, 200); assert.match(nv.json.commands[0].text, /acli vm\.shutdown 00000007-aaaa-bbbb-cccc-000000000007/);
});

test('ESXi host restart: cluster room, DRS off moves VMs by id, standalone host, four-eyes, accepted risk, audit', async (t) => {
  const { e } = await setup(t);
  const r = (await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'host-11', action: 'restart', reason: 'ESXi patch 8.0U3 install' })).json;
  const c = (n) => r.checks.find((x) => x.name === n);
  assert.equal(c('Running VMs on this host').status, 'info'); assert.match(c('Running VMs on this host').detail, /2 running \(192 GB\)/);
  assert.equal(c('The rest of the cluster can carry them').status, 'fail', '62 GB free on esx-syn-02, 192 GB needed');
  assert.equal(c('DRS moves the VMs').status, 'warn'); assert.equal(r.blocked, true);
  const cmd = r.commands.map((x) => x.text).join('\n');
  assert.match(cmd, /Move-VM -VM \(Get-VM -Id 'VirtualMachine-vm-102'\) -Destination \(Get-VMHost -Id 'HostSystem-host-12'\)/);
  assert.match(cmd, /Set-VMHost -VMHost \$h -State Maintenance -Evacuate:\$true/); assert.match(cmd, /Restart-VMHost -VMHost \$h -Confirm:\$false/);
  assert.match(cmd, /-State Connected/); assert.ok(!/esx-syn|DB-SYN/.test(cmd), 'names never in commands');
  // a standalone host cannot hand its VMs to other standalone hosts
  const sa = (await ask(e, 'omar', { platform_id: 'vp_v', target_id: 'host-13', action: 'shutdown', reason: 'decommission spare host' })).json;
  assert.equal(sa.checks.find((x) => x.name === 'Somewhere to move them').status, 'fail');
  // four-eyes
  const id = r.id, ap = (user, role, b) => e.req('POST', `/virt/power/requests/${id}/approve`, { user, role, body: b || {} });
  assert.equal((await ap('omar', 'operator')).status, 403, 'operators cannot approve');
  assert.equal((await ap('ali', 'admin')).status, 403, 'the requester cannot approve, whatever their role');
  assert.equal((await ap('ALI ', 'admin')).status, 403, 'names compared trimmed and case-insensitive');
  assert.equal((await ap('duty:virt', 'admin')).status, 403, 'a service identity never approves');
  const blocked = await ap('syed', 'admin', { comment: 'ok' });
  assert.equal(blocked.status, 409); assert.match(blocked.json.error, /1 check\(s\) failed: The rest of the cluster can carry them/);
  assert.equal((await ap('syed', 'admin', { accept_risk: 'short' })).status, 400, 'an accepted risk is a sentence');
  const ok = await ap('syed', 'admin', { comment: 'CAB-SYN-101', accept_risk: 'two test VMs on it will be shut down first by the owner' });
  assert.equal(ok.status, 200); assert.equal(ok.json.state, 'approved'); assert.match(ok.json.accepted_risk, /shut down first/);
  assert.equal(ok.json.expires_at, new Date(T0 + 24 * 3600000).toISOString());
  assert.equal((await e.req('POST', `/virt/power/requests/${id}/reject`, { user: 'sara', role: 'admin', body: { reason: 'late' } })).status, 409, 'decided once');
  // applied: not the approver, a note, then waits for a collection
  const apl = (user, b) => e.req('POST', `/virt/power/requests/${id}/applied`, { user, role: 'operator', body: b });
  assert.equal((await apl('syed', { note: 'done' })).status, 403, 'the approver does not record it');
  assert.equal((await apl('omar', {})).status, 400, 'a note is required');
  assert.equal((await apl('omar', { note: 'ran the plan 22:10, host back 22:31' })).json.state, 'applied');
  const trail = audits(e, /^virt\.power\./).map((x) => [x.action, x.by]);
  assert.deepEqual(trail.filter((x) => x[0] !== 'virt.power.request'), [['virt.power.approve', 'syed'], ['virt.power.applied', 'omar']]);
  const appr = audits(e, /^virt\.power\.approve$/)[0];
  assert.deepEqual(appr.detail.failed_checks, ['The rest of the cluster can carry them']); assert.equal(appr.role, 'admin');
});

test('Nutanix host: one node at a time, the documented CVM sequence, addresses validated', async (t) => {
  const { e, U } = await setup(t);
  const r = (await ask(e, 'ali', { platform_id: 'vp_n', target_id: U(1), action: 'restart', reason: 'AOS / AHV upgrade prep' })).json;
  assert.equal(r.checks.find((x) => x.name === 'One Nutanix node at a time').status, 'fail', 'NTNX-SYN-3 is in maintenance');
  const cmd = r.commands.map((x) => x.text).join('\n');
  assert.match(cmd, /ncli cluster get-domain-fault-tolerance-status type=node/);
  assert.match(cmd, new RegExp(`acli host\\.enter_maintenance_mode ${U(1)} wait=true`));
  assert.match(cmd, /on the CVM of this host \(10\.99\.0\.21\)[\s\S]*cvm_shutdown -P now/); assert.match(cmd, /AHV host \(10\.99\.0\.11\)[\s\S]*\nreboot/);
  assert.match(cmd, new RegExp(`acli host\\.exit_maintenance_mode ${U(1)}`));
  assert.equal((await e.req('POST', `/virt/power/requests/${r.id}/approve`, { user: 'syed', role: 'admin', body: {} })).status, 409);
});

test('Nutanix: a second node is refused while the first plan is open; a malformed address gives no plan', async (t) => {
  const { e, U } = await setup(t, { allUp: true });
  const a = (await ask(e, 'ali', { platform_id: 'vp_n', target_id: U(1), action: 'shutdown', reason: 'move to the new rack' })).json;
  assert.equal(a.checks.find((x) => x.name === 'One Nutanix node at a time').status, 'ok');
  const b = (await ask(e, 'omar', { platform_id: 'vp_n', target_id: U(2), action: 'restart', reason: 'BIOS update on node 2' })).json;
  assert.match(b.checks.find((x) => x.name === 'One Nutanix node at a time').detail, new RegExp(`power plan ${a.id} is still open`));
  // an ID outside the expected shape (data read from the platform): no command is built from it
  const odd = await ask(e, 'ali', { platform_id: 'vp_v', target_id: '12345', action: 'restart', reason: 'restart the odd host' });
  assert.equal(odd.status, 409); assert.match(odd.json.error, /unexpected format - no plan is written/);
});

test('host start: out-of-band controller (admin-only setting), password never on a command line; state rules', async (t) => {
  const { e } = await setup(t);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'host-11', action: 'start', reason: 'start the host' })).json.error, /already running/);
  assert.match((await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'host-14', action: 'restart', reason: 'restart the hung host' })).json.error, /cannot be put into maintenance mode - use "Power on" or "Power-cycle"/);
  const noBmc = (await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'host-14', action: 'power-cycle', reason: 'host hung after PSOD' })).json;
  assert.equal(noBmc.checks.find((x) => x.name === 'Out-of-band controller').status, 'warn'); assert.match(noBmc.commands[0].text, /open its iDRAC \/ iLO \/ IPMI console/);
  await e.req('POST', `/virt/power/requests/${noBmc.id}/cancel`, { user: 'ali', role: 'operator', body: { reason: 'will add the controller first' } });
  const put = (role, b) => e.req('PUT', '/virt/power/bmc/vp_v:host-14', { user: 'syed', role, body: b });
  assert.equal((await put('operator', { address: '10.9.9.14', kind: 'idrac' })).status, 403, 'controllers are an admin setting');
  assert.match((await put('admin', { address: '10.9.9.14; reboot', kind: 'idrac' })).json.error, /address must be a host name or IP address/);
  assert.match((await put('admin', { address: '10.9.9.14', kind: 'telnet' })).json.error, /kind must be one of/);
  assert.equal((await put('admin', { address: 'idrac-esx04.syn.local', kind: 'idrac' })).status, 200);
  const pc = (await ask(e, 'omar', { platform_id: 'vp_v', target_id: 'host-14', action: 'power-cycle', reason: 'host hung after PSOD' })).json;
  const txt = pc.commands[0].text;
  assert.match(txt, /curl --cacert \.\/bmc-idrac-esx04\.syn\.local\.pem -u '<your-bmc-login>' -X POST https:\/\/idrac-esx04\.syn\.local\/redfish\/v1\/Systems\/System\.Embedded\.1\/Actions\/ComputerSystem\.Reset/);
  assert.match(txt, /"ResetType":"ForceRestart"/); assert.ok(!/ -k |--insecure|password/i.test(txt.replace(/asks for the password/, '')), 'no password, TLS checking stays on');
  assert.equal((await e.req('DELETE', '/virt/power/bmc/vp_v:host-14', { user: 'syed', role: 'operator' })).status, 403);
  assert.equal((await e.req('DELETE', '/virt/power/bmc/vp_v:host-14', { user: 'syed', role: 'admin' })).status, 200);
  assert.deepEqual(audits(e, /^virt\.power\.bmc/).map((x) => x.action), ['virt.power.bmc.set', 'virt.power.bmc.delete']);
});

test('cancel, approval expiry, verification by a later collection (verified / not verified)', async (t) => {
  const { e, V, tick, now } = await setup(t, { allUp: true });
  const r = (await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'restart', reason: 'apply OS patches tonight' })).json;
  assert.equal((await e.req('POST', `/virt/power/requests/${r.id}/cancel`, { user: 'omar', role: 'operator', body: { reason: 'not mine' } })).status, 403);
  // expiry: approved, run 25 h later = refused
  await e.req('POST', `/virt/power/requests/${r.id}/approve`, { user: 'syed', role: 'admin', body: {} });
  tick(25 * 3600000);
  const late = await e.req('POST', `/virt/power/requests/${r.id}/applied`, { user: 'omar', role: 'operator', body: { note: 'ran it' } });
  assert.equal(late.status, 409); assert.match(late.json.error, /approval expired/);
  assert.equal((await e.req('POST', `/virt/power/requests/${r.id}/cancel`, { user: 'ali', role: 'operator', body: { reason: 'expired, asking again' } })).json.state, 'cancelled');
  // a fresh request, run, verified once a collection AFTER the run shows the VM off
  const s = (await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-105', action: 'shutdown', reason: 'standalone host retirement' })).json;
  await e.req('POST', `/virt/power/requests/${s.id}/approve`, { user: 'syed', role: 'admin', body: {} });
  await e.req('POST', `/virt/power/requests/${s.id}/applied`, { user: 'omar', role: 'operator', body: { note: 'shut down 09:05' } });
  V.verifyTick(); assert.equal(V.get(s.id).state, 'applied', 'no collection since: still waiting');
  const cap = e.app.store.collection('virt_capacity');
  tick(5 * 60000); cap.patch('vp_v', (x) => { x.at = new Date(now()).toISOString(); x.vms.find((v) => v.id === 'vm-105').power = 'off'; return x; });
  V.verifyTick(); assert.equal(V.get(s.id).state, 'verified'); assert.match(V.get(s.id).verify_note, /is off/);
  // a VM that is still on two hours after its shutdown was recorded: not verified, and said so
  const o = (await ask(e, 'ali', { platform_id: 'vp_v', target_id: 'vm-101', action: 'shutdown', reason: 'retire the app server' })).json;
  await e.req('POST', `/virt/power/requests/${o.id}/approve`, { user: 'syed', role: 'admin', body: {} });
  await e.req('POST', `/virt/power/requests/${o.id}/applied`, { user: 'omar', role: 'operator', body: { note: 'clicked shut down' } });
  tick(10 * 60000); cap.patch('vp_v', (x) => { x.at = new Date(now()).toISOString(); return x; });
  V.verifyTick(); assert.equal(V.get(o.id).state, 'applied'); assert.match(V.get(o.id).verify_note, /is on, expected off/);
  tick(2 * 3600000); cap.patch('vp_v', (x) => { x.at = new Date(now()).toISOString(); return x; });
  V.verifyTick(); assert.equal(V.get(o.id).state, 'not-verified');
  assert.deepEqual(audits(e, /^virt\.power\.(verified|not-verified)$/).map((x) => [x.action, x.by]), [['virt.power.verified', 'system:virt-power'], ['virt.power.not-verified', 'system:virt-power']]);
});

test('power on while the platform is shut down: a failing or stale collection cannot say a host is still on', async (t) => {
  const { e, U, tick } = await setup(t, { allUp: true });
  // fresh, successful collection: a connected host is known to be running
  assert.match((await ask(e, 'ali', { platform_id: 'vp_n', target_id: U(1), action: 'start', reason: 'power on after the downtime' })).json.error, /already running/);
  let g = (await e.req('GET', '/virt/power', { role: 'viewer' })).json;
  assert.equal(g.hosts.find((h) => h.id === U(1)).known_up, true);
  // the cluster is shut down: Prism cannot be read, the last good collection still shows every node connected
  e.app.store.collection('virt_capacity').patch('vp_n', (x) => { x.last_error = 'connect ETIMEDOUT 10.99.0.20:9440'; x.last_error_at = new Date(T0).toISOString(); return x; });
  g = (await e.req('GET', '/virt/power', { role: 'viewer' })).json;
  assert.equal(g.hosts.find((h) => h.id === U(1)).known_up, false); assert.equal(g.platforms.find((p) => p.id === 'vp_n').stale, true);
  const on = await ask(e, 'ali', { platform_id: 'vp_n', target_id: U(1), action: 'start', reason: 'power on after the downtime' });
  assert.equal(on.status, 200, JSON.stringify(on.json)); assert.equal(on.json.title.startsWith('Power on: NTNX-SYN-1'), true);
  assert.equal(on.json.checks.find((c) => c.name === 'Is it really off?').status, 'warn');
  assert.match(on.json.commands[0].text, /https:\/\/10\.99\.9\.11\/redfish\/v1\/Systems\/1\/Actions\/ComputerSystem\.Reset[\s\S]*"ResetType":"On"/);
  assert.match(on.json.commands.map((c) => c.text).join('\n'), new RegExp(`acli host\\.exit_maintenance_mode ${U(1)}`));
  // vCenter not collected for more than 2 h: the same
  tick(3 * 3600000);
  const esx = await ask(e, 'omar', { platform_id: 'vp_v', target_id: 'host-12', action: 'start', reason: 'power on after the downtime' });
  assert.equal(esx.status, 200); assert.ok(esx.json.checks.some((c) => c.name === 'Data is current' && c.status === 'warn'));
});
