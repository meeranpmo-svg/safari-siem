// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Approved network tasks (engine/netops/tasks.js + pam.js): a task template → change plan → approval by another admin →
// Run → prechecks, backup, push, verify, write memory; a failed verification is rolled back; the device must be in the
// state the task expects (no access VLAN on a trunk); with PAM the write account is checked out for the run only and
// checked in after, and a stored write password is never used; a free-text plan can never be turned into a task.
// The switch is simulated (VLAN database + interfaces) behind the cli-helper.py request shape.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/netops/routes');
const { createPam } = require('../engine/netops/pam');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-nettask-'));

function fakeSwitch(o = {}) {
  const vl = { 1: 'default', 10: 'DATA' };
  const ifs = { 'Gi1/0/1': { mode: 'access', vlan: 10, desc: '' }, 'Gi1/0/2': { mode: null, vlan: null, desc: 'old desc' }, 'Gi1/0/48': { mode: 'trunk', allowed: '1,10' } };
  const calls = [];
  const runCfg = (i) => `Building configuration...\n!\ninterface ${i}\n` + (ifs[i].desc ? ` description ${ifs[i].desc}\n` : '') + (ifs[i].mode === 'trunk' ? ` switchport trunk allowed vlan ${ifs[i].allowed}\n switchport mode trunk\n` : (ifs[i].vlan ? ` switchport access vlan ${ifs[i].vlan}\n` : '') + (ifs[i].mode === 'access' ? ' switchport mode access\n' : '')) + (ifs[i].shut ? ' shutdown\n' : '') + 'end';
  const show = (c) => {
    let m;
    if ((m = /^show vlan id (\d+)$/.exec(c))) return vl[m[1]] ? `VLAN Name   Status\n${m[1]}   ${vl[m[1]]}   active` : `VLAN id ${m[1]} not found in current VLAN database`;
    if (c === 'show vlan brief') return Object.keys(vl).map((n) => `${n}    ${vl[n]}    active    `).join('\n');
    if ((m = /^show running-config interface (\S+)$/.exec(c))) return ifs[m[1]] ? runCfg(m[1]) : '% Invalid input detected';
    if ((m = /^show interfaces (\S+) switchport$/.exec(c))) { const x = ifs[m[1]]; return `Administrative Mode: ${x.mode === 'trunk' ? 'trunk' : x.mode === 'access' ? 'static access' : 'dynamic auto'}\nAccess Mode VLAN: ${x.vlan || 1} (x)`; }
    if (c === 'show running-config') return 'hostname SW1\nenable secret 9 $9$abcdef\nusername admin privilege 15 secret 9 $9$zz';
    return '';
  };
  const fn = async (req) => {
    calls.push(JSON.parse(JSON.stringify(req)));
    if (req.op === 'version') return { ok: true, netmiko: '4', paramiko: '3', python: '3' };
    if (req.op === 'hostkey') return { ok: true, type: 'ssh-rsa', key: 'AAAA', fingerprint: 'SHA256:abc' };
    if (req.op === 'run') return { ok: true, prompt: 'SW1#', results: req.commands.map((c) => ({ command: c, output: show(c) })) };
    if (req.op === 'save') return { ok: true };
    if (req.op === 'config') {
      let curV = null, curI = null;
      for (const l of req.lines) {
        let m;
        if ((m = /^vlan (\d+)$/.exec(l))) { curV = m[1]; vl[curV] = vl[curV] || 'VLAN' + String(curV).padStart(4, '0'); curI = null; }
        else if ((m = /^ name (\S+)$/.exec(l)) && curV) vl[curV] = m[1];
        else if ((m = /^no vlan (\d+)$/.exec(l))) delete vl[m[1]];
        else if ((m = /^interface (\S+)$/.exec(l))) { curI = m[1]; curV = null; }
        else if (curI && / switchport mode access/.test(l)) ifs[curI].mode = 'access';
        else if (curI && / no switchport mode/.test(l)) ifs[curI].mode = null;
        else if (curI && (m = / switchport access vlan (\d+)/.exec(l))) { if (!o.ignoreAccessVlan) ifs[curI].vlan = +m[1]; }
        else if (curI && / no switchport access vlan/.test(l)) ifs[curI].vlan = null;
        else if (curI && (m = / description (.+)$/.exec(l))) ifs[curI].desc = m[1];
        else if (curI && / no description/.test(l)) ifs[curI].desc = '';
        else if (curI && (m = / switchport trunk allowed vlan add (\S+)/.exec(l))) ifs[curI].allowed += ',' + m[1];
      }
      return { ok: true, output: 'SW1(config)#' };
    }
    return { ok: false, kind: 'input', error: 'unknown op' };
  };
  return { fn, calls, vl, ifs };
}

async function setup(sw, netopsCfg, pam) {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: Object.assign({ enabled: false }, netopsCfg || {}) };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const fakePoller = { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {}, pollDevice: async (id) => ({ device_id: id, ok: true }) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: fakePoller, cliRunner: sw.fn, pam });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit() {}, ok(b) { out.status = 200; out.body = b; }, fail(s, e) { out.status = s; out.error = e; } };
    try { const rv = await R[m + ' /api/soc/netops' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } }
    catch (e) { out.status = e.code || e.status || 500; out.error = e.message; }
    return out;
  }
  N.inventory.put({ id: 'acc-sw1', name: 'ACC-SW1', vendor: 'cisco-ios', ip: '10.0.5.2' }, 'admin');
  await N.cli.fetchHostKey('acc-sw1'); N.cli.trustHostKey('acc-sw1', 'SHA256:abc', 'admin');
  return { N, call, state };
}
async function approved(call, body) {
  const p = await call('POST', '/tasks', { role: 'operator', user: 'ali', body });
  assert.equal(p.status, 200, p.error);
  const d = await call('POST', '/changes/:id/decide', { role: 'admin', user: 'syed', params: { id: p.body.id }, body: { decision: 'approved' } });
  assert.equal(d.status, 200, d.error);
  return p.body;
}

test('tasks: VLAN create → approve → Run: prechecks, backup without secrets, push, verify, write memory', async () => {
  const sw = fakeSwitch(); const { N, call } = await setup(sw);
  const p = await approved(call, { device: 'acc-sw1', type: 'vlan-create', params: { vlan: 120, name: 'USERS_HQ' }, reason: 'new floor' });
  assert.equal(p.task.type, 'vlan-create'); assert.match(p.execution, /automated after approval/);
  // no write login yet: refused with the reason
  let r = await call('POST', '/changes/:id/execute', { role: 'operator', user: 'omar', params: { id: p.id } });
  assert.equal(r.status, 409); assert.match(r.error, /no write login/);
  N.inventory.setCredentials('acc-sw1', { ssh_write: { username: 'netadmin', password: 'Wr1te-pw' } }, 'admin');
  r = await call('POST', '/changes/:id/execute', { role: 'operator', user: 'omar', params: { id: p.id } });
  assert.equal(r.status, 200, r.error); assert.equal(r.body.status, 'validated', JSON.stringify(r.body.run.steps));
  assert.equal(sw.vl[120], 'USERS_HQ');
  const cfg = sw.calls.filter((c) => c.op === 'config'); assert.deepEqual(cfg[0].lines, ['vlan 120', ' name USERS_HQ']);
  assert.ok(sw.calls.some((c) => c.op === 'save')); assert.equal(cfg[0].username, 'netadmin', 'the write login, not the read-only one');
  const backup = r.body.run.steps.find((s) => s.name === 'backup'); assert.ok(backup.output.includes('hostname SW1') && !backup.output.includes('$9$'));
  assert.match(r.body.applied_by, /omar via the SIEM/);
  // the same plan cannot run twice
  assert.equal((await call('POST', '/changes/:id/execute', { role: 'operator', params: { id: p.id } })).status, 409);
});

test('tasks: refused when the device is not in the expected state; verify failure is rolled back', async () => {
  const sw = fakeSwitch({ ignoreAccessVlan: true }); const { N, call } = await setup(sw);
  N.inventory.setCredentials('acc-sw1', { ssh_write: { username: 'netadmin', password: 'Wr1te-pw' } }, 'admin');
  // a trunk (uplink) is never turned into an access port
  let p = await approved(call, { device: 'acc-sw1', type: 'port-access-vlan', params: { vlan: 10, interfaces: ['Gi1/0/48'] } });
  let r = await call('POST', '/changes/:id/execute', { role: 'operator', params: { id: p.id } });
  assert.equal(r.body.status, 'execution-failed'); assert.match(JSON.stringify(r.body.run.steps), /is a trunk/);
  assert.equal(sw.calls.filter((c) => c.op === 'config').length, 0, 'nothing pushed');
  // the switch does not take the VLAN: verification fails → the previous port config is restored
  p = await approved(call, { device: 'acc-sw1', type: 'port-access-vlan', params: { vlan: 10, interfaces: ['Gi1/0/2'], description: 'Printer 2F' } });
  r = await call('POST', '/changes/:id/execute', { role: 'operator', params: { id: p.id } });
  assert.equal(r.body.status, 'execution-failed'); assert.equal(r.body.run.status, 'rolled-back');
  const rb = sw.calls.filter((c) => c.op === 'config').pop().lines;
  assert.deepEqual(rb, ['interface Gi1/0/2', ' no switchport access vlan', ' no switchport mode', ' description old desc']);
  assert.ok(!sw.calls.filter((c) => c.op === 'save').length, 'nothing saved after a failed change');
  // bad parameters never reach the device
  for (const params of [{ vlan: 1, name: 'x' }, { vlan: 1003 }, { vlan: 50, name: 'a b' }]) assert.equal((await call('POST', '/tasks', { role: 'operator', body: { device: 'acc-sw1', type: 'vlan-create', params } })).status, 400);
  assert.equal((await call('POST', '/tasks', { role: 'operator', body: { device: 'acc-sw1', type: 'port-access-vlan', params: { vlan: 10, interfaces: ['Vlan1'] } } })).status, 400);
  assert.equal((await call('POST', '/tasks', { role: 'operator', body: { device: 'acc-sw1', type: 'ios-stage', params: { image: 'x.bin', url: 'tftp://u:p@1.2.3.4/x.bin', md5: 'a'.repeat(32) } } })).status, 400);
  // a free-text plan cannot smuggle in a task
  const f = await call('POST', '/changes', { role: 'operator', body: { device: 'acc-sw1', title: 'manual', commands: ['conf t'], task: { type: 'vlan-create', params: { vlan: 77 } } } });
  assert.equal(f.body.task, undefined);
  // an unapproved plan does not run
  const u = await call('POST', '/tasks', { role: 'operator', body: { device: 'acc-sw1', type: 'vlan-create', params: { vlan: 300 } } });
  assert.match((await call('POST', '/changes/:id/execute', { role: 'operator', params: { id: u.body.id } })).error, /not approved/);
});

test('tasks with PAM: checked out for the run only, checked in after, stored write passwords not used', async () => {
  const sw = fakeSwitch(), log = [];
  const pam = { status: () => ({ enabled: true, ready: true, required: true }), checkout: async (r) => { log.push(['out', r]); return { username: 'pam-net', password: 'PamOneTime-1', secret: '', lease: 'L-77' }; }, checkin: async (r) => { log.push(['in', r]); return { ok: true }; } };
  const { N, call, state } = await setup(sw, {}, pam);
  N.inventory.setCredentials('acc-sw1', { ssh_write: { username: 'netadmin', password: 'Stored-pw' } }, 'admin');
  const cat = (await call('GET', '/tasks/catalogue', { query: { device: 'acc-sw1' } })).body;
  assert.equal(cat.status.enabled, false, 'PAM required: the stored password is not used'); assert.match(cat.status.reason, /no PAM account/);
  N.inventory.setCredentials('acc-sw1', { ssh_write: { pam: 'NETWORK/acc-sw1-admin' } }, 'admin');
  assert.match(N.inventory.credentialSummary('acc-sw1').ssh_write, /from PAM: NETWORK\/acc-sw1-admin/);
  const p = await approved(call, { device: 'acc-sw1', type: 'vlan-create', params: { vlan: 130, name: 'VOICE' } });
  const r = await call('POST', '/changes/:id/execute', { role: 'operator', user: 'omar', params: { id: p.id } });
  assert.equal(r.body.status, 'validated', JSON.stringify(r.body.run.steps));
  assert.equal(log[0][0], 'out'); assert.equal(log[0][1].account, 'NETWORK/acc-sw1-admin'); assert.equal(log[0][1].approved_by, 'syed'); assert.equal(log[0][1].plan, p.id);
  assert.equal(log[1][0], 'in'); assert.equal(log[1][1].lease, 'L-77'); assert.equal(log[1][1].outcome, 'done');
  assert.ok(sw.calls.filter((c) => c.op === 'config').every((c) => c.username === 'pam-net'));
  const saved = JSON.stringify(state.collection('netops_changes').all());
  assert.ok(!saved.includes('PamOneTime-1') && !saved.includes('Stored-pw'), 'no password in the plan');
  assert.ok(r.body.run.steps.some((s) => s.name === 'PAM checkout') && r.body.run.steps.some((s) => s.name === 'PAM check-in' && s.ok));
});

test('pam.js: programs must be root-owned and not writable by others; JSON in, JSON out; checkout errors named', async () => {
  const mk = (stat) => createPam({ config: { netops: { pam: { enabled: true, checkout: '/usr/local/sbin/zyb-pam-checkout', checkin: '/usr/local/sbin/zyb-pam-checkin' } } }, statImpl: () => stat,
    spawnImpl: () => { const { EventEmitter } = require('node:events'); const c = new EventEmitter(); c.stdout = new EventEmitter(); c.stderr = new EventEmitter(); let input = '';
      c.stdin = { end: (s) => { input = s; setImmediate(() => { const j = JSON.parse(input); if (j.action === 'checkout') c.stdout.emit('data', JSON.stringify(j.account === 'nope' ? {} : { username: 'u', password: 'p', lease: 'x' })); c.emit('close', j.account === 'fail' ? 3 : 0); }); } }; c.kill = () => {}; return c; } });
  const file = { isFile: () => true, uid: 0, mode: 0o100755 };
  assert.match(mk(Object.assign({}, file, { uid: 1001 })).status().reason, /owned by root/);
  assert.match(mk(Object.assign({}, file, { mode: 0o100777 })).status().reason, /not be writable/);
  const P = mk(file); assert.equal(P.status().ready, true);
  assert.deepEqual(await P.checkout({ account: 'NET/a' }), { username: 'u', password: 'p', secret: '', lease: 'x' });
  await assert.rejects(() => P.checkout({ account: 'nope' }), /without a username and password/);
  await assert.rejects(() => P.checkout({ account: 'fail' }), /checkout of "fail" failed/);
  assert.equal((await P.checkin({ account: 'NET/a', lease: 'x' })).ok, true);
});
