// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Proxmox VE reader (engine/discovery/methods/proxmox.js): GET only on the allow-listed paths, the API token only in the
// Authorization header; nodes and guests collected; the hardening read keeps a part the token may not read as null (NOT
// CHECKED on Baseline Hardening, never a pass); API tokens are not counted as people. Fake HTTP, SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const pve = require('../engine/discovery/methods/proxmox');

const CRED = { target: { base_url: 'https://pve.syn.test:8006/' }, secret: { username: 'mon@pve!ro', password: 'synthetic-token-secret' } };
const DATA = {
  '/api2/json/version': { version: '8.2.4' },
  '/api2/json/nodes': [{ node: 'pve1', status: 'online' }, { node: 'pve2', status: 'offline' }],
  '/api2/json/cluster/status': [{ type: 'cluster', name: 'c' }, { type: 'node', name: 'pve1', ip: '10.8.1.5' }, { type: 'node', name: 'pve2', ip: 'not-an-ip' }],
  '/api2/json/cluster/resources?type=vm': [{ vmid: 101, name: 'app-syn', node: 'pve1', status: 'running', type: 'qemu', maxcpu: 4, maxmem: 8589934592 }, { vmid: 900, template: 1 }, { vmid: 102, node: 'pve2', status: 'stopped', type: 'lxc' }],
  '/api2/json/cluster/firewall/options': { enable: 1, policy_in: 'DROP' },
  '/api2/json/access/domains': [{ realm: 'pam', type: 'pam' }, { realm: 'corp', type: 'ad' }],
  '/api2/json/access/users?full=1': [{ userid: 'root@pam', enable: 1 }, { userid: 'ali@corp', enable: 1 }, { userid: 'old@pve', enable: 0 }],
  '/api2/json/access/tfa': [{ userid: 'root@pam', entries: [{ type: 'totp', enable: 1 }] }, { userid: 'ali@corp', entries: [{ type: 'totp', enable: 0 }] }],
  '/api2/json/nodes/pve1/firewall/options': { enable: 0 },
  '/api2/json/nodes/pve1/apt/update': [{ Package: 'pve-manager' }],
  '/api2/json/nodes/pve1/certificates/info': [{ filename: 'pveproxy-ssl.pem', issuer: '/CN=Corp CA', subject: '/CN=pve1.syn.test', notafter: 1900000000 }],
  '/api2/json/nodes/pve1/subscription': { status: 'active' },
};
function fake(deny = []) {
  const calls = [];
  const request = async (url, o) => {
    const p = url.replace('https://pve.syn.test:8006', '');
    calls.push({ p, method: o.method, auth: o.headers.Authorization, body: o.body });
    if (deny.some((d) => p.includes(d))) return { status: 403, json: null };
    return p in DATA ? { status: 200, json: { data: DATA[p] } } : { status: 404, json: null };
  };
  return { request, calls };
}

test('guard: GET on allow-listed paths only - writes and other paths refused before any request', () => {
  assert.doesNotThrow(() => pve.guard('GET', '/api2/json/nodes/pve-1.local/apt/update'));
  for (const [m, p] of [['POST', '/api2/json/nodes'], ['PUT', '/api2/json/cluster/firewall/options'], ['GET', '/api2/json/nodes/pve1/qemu/101/status/stop'], ['GET', '/api2/json/access/ticket'], ['GET', '/api2/json/nodes/../access/users?full=1'], ['DELETE', '/api2/json/version']]) {
    assert.throws(() => pve.guard(m, p), /read-only/, m + ' ' + p);
  }
});

test('collect: nodes with their cluster address, guests without templates; the token goes only in the Authorization header', async () => {
  const f = fake();
  const r = await pve.collect(CRED, { request: f.request });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.hosts.map((h) => [h.name, h.ip, h.state]), [['pve1', '10.8.1.5', 'connected'], ['pve2', null, 'offline']]);
  assert.deepEqual(r.vms.map((v) => [v.id, v.kind, v.power_state, v.memory_mb]), [['101', 'vm', 'on', 8192], ['102', 'container', 'off', null]]);
  assert.ok(f.calls.every((c) => c.method === 'GET' && c.body === null));
  assert.ok(f.calls.every((c) => c.auth === 'PVEAPIToken=mon@pve!ro=synthetic-token-secret'));
  assert.ok(f.calls.every((c) => !c.p.includes('synthetic-token-secret')), 'the secret never goes in the URL');
});

test('hardening read: firewall, realms, people and second factors, backups, per-node updates / certificates; unreadable parts are null', async () => {
  const f = fake(['/access/tfa', '/cluster/backup', '/nodes/pve2/']);
  const h = await pve.hardening(CRED, { request: f.request });
  assert.equal(h.version, '8.2.4');
  assert.deepEqual(h.cluster_firewall, { enable: true, policy_in: 'DROP' });
  assert.deepEqual(h.realms.map((x) => x.type), ['pam', 'ad']);
  assert.deepEqual(h.users.find((u) => u.userid === 'old@pve'), { userid: 'old@pve', enable: false });
  assert.equal(h.tfa, null, 'a 403 is "not readable", never "nobody has a second factor"');
  assert.equal(h.backup_jobs, null);
  const n1 = h.nodes.find((n) => n.name === 'pve1'), n2 = h.nodes.find((n) => n.name === 'pve2');
  assert.deepEqual([n1.firewall, n1.updates, n1.subscription, n1.certs[0].issuer], [false, 1, 'active', '/CN=Corp CA']);
  assert.deepEqual([n2.firewall, n2.updates, n2.certs, n2.subscription], [null, null, null, null]);
  const ok = await pve.hardening(CRED, { request: fake().request });
  assert.deepEqual(ok.tfa, ['root@pam'], 'a disabled second factor does not count');
});

test('a rejected token is an auth error, not an empty cluster', async () => {
  const r = await pve.collect(CRED, { request: async () => ({ status: 401, json: null }) });
  assert.equal(r.ok, false); assert.equal(r.error_class, 'auth');
});

test('virt: a Proxmox VE connection saves sealed (admin only), syncs nodes as servers and guests as VMs, audited', async (t) => {
  const { startApp } = require('./helpers'), { createVirt } = require('../engine/virt');
  const s = await startApp({ noAi: true }); t.after(() => s.close());
  const audits = []; const orig = s.app.audit; s.app.audit = (r) => { audits.push(r); if (orig) orig.call(s.app, r); };
  const f = fake();
  const V = createVirt(s.app, { methods: { proxmox: { collect: (c) => pve.collect(c, { request: f.request }), test: async () => ({ ok: true }) } } });
  const adm = { user: 'syed', role: 'admin' };
  const p = V.save({ kind: 'proxmox', label: 'PVE-SYN', base_url: 'https://pve.syn.test:8006', username: 'mon@pve!ro', password: 'synthetic-token-secret', site: 'Riyadh HQ' }, adm).platform;
  assert.doesNotMatch(JSON.stringify(V.list()), /synthetic-token-secret/, 'the token secret is never listed');
  assert.equal((await s.req('POST', '/virt', { role: 'operator', user: 'omar.syn', body: { kind: 'proxmox', base_url: 'https://x', username: 'a', password: 'b' } })).status, 403, 'only an admin saves a connection');
  const r = await V.sync(p.id, adm);
  assert.equal(r.ok, true, r.error); assert.deepEqual([r.hosts, r.vms], [2, 2]);
  const devs = s.app.store.collection('disc_devices').all();
  const node = devs.find((d) => (d.uids || [d.uid]).includes('pve-node:' + p.id + ':pve1'));
  assert.ok(node, 'the node keeps its Proxmox id so Baseline Hardening can match it'); assert.equal(node.type, 'server'); assert.match(node.os || '', /Proxmox/);
  assert.ok(devs.some((d) => (d.uids || [d.uid]).includes('pve:' + p.id + ':101')), 'guest observed');
  assert.ok(audits.some((a) => /virt/.test(a.action) && a.by === 'syed'), 'save / sync audited');
  assert.doesNotMatch(JSON.stringify(audits), /synthetic-token-secret/);
});
