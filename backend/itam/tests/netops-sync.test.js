// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Approved network devices → AI Network Engineer: vendor / role mapping, ids, dedupe by IP, removed devices not re-sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createNetopsSync, isNetDevice } = require('../engine/netops-sync');

function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id) }; })()) };
}
function fakeSiem(devs, calls) {
  return async (url, o) => {
    calls.push([o.method, url.replace(/^.*\/api\/soc/, ''), o.headers['X-Sentra-Proxy-Secret'], o.body && JSON.parse(o.body)]);
    if (o.method === 'GET') return { status: 200, json: { items: devs } };
    const b = JSON.parse(o.body); if (b.ip === '10.0.0.99') return { status: 400, json: { error: 'vendor must be one of …' } };
    devs.push(b); return { status: 200, json: b };
  };
}
const SECRET = 'x'.repeat(32);
const net = (id, name, ip, extra) => Object.assign({ id, name, type: 'network', mgmt_ip: ip, status: 'in_use' }, extra || {});

test('netops sync: approved switches / firewalls go to the AI Network Engineer once', async () => {
  const st = fakeStore({ assets: [
    net('a1', 'dc-rack2-sw1.asi.local', '10.110.10.33', { vendor: 'Cisco', discovery: { class: 'switch', os: 'Cisco IOS Software [Dublin]' }, site: 'Riyadh HQ' }),
    net('a2', 'FW-HQ', '10.110.0.1', { vendor: 'Fortinet', tags: ['firewall'] }),
    net('a3', 'ASA-DMZ', '10.110.0.2', { vendor: 'Cisco', model: 'ASA5516', tags: ['firewall'] }),
    net('a4', 'already', '10.110.10.2', { vendor: 'Cisco' }),
    net('a5', 'core1', '10.110.10.1', { vendor: 'Cisco', tags: ['switch', 'core'] }),
    net('a6', 'bad', '10.0.0.99'), net('a7', 'noip', ''), { id: 'a8', name: 'PC', type: 'workstation', mgmt_ip: '10.1.1.1', status: 'in_use' },
    net('a9', 'old', '10.110.10.9', { status: 'retired' }),
  ] });
  const devs = [{ id: 'f0-c1-sw1', ip: '10.110.10.2' }, { id: 'dc-rack2-sw1', ip: '10.9.9.9' }], calls = [];
  const N = createNetopsSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } } }, { request: fakeSiem(devs, calls), readFile: () => SECRET });
  assert.equal(isNetDevice({ type: 'network', mgmt_ip: '1.1.1.1', status: 'in_use' }), true);
  const r = await N.run({ user: 'siva', role: 'admin' });
  assert.equal(r.ok, true);
  const by = Object.fromEntries(r.added.map((x) => [x.name, [x.device_id, x.vendor, x.role]]));
  assert.deepEqual(by, { 'dc-rack2-sw1.asi.local': ['dc-rack2-sw1-2', 'cisco-ios', 'other'], 'FW-HQ': ['fw-hq', 'fortigate', 'firewall'], 'ASA-DMZ': ['asa-dmz', 'cisco-asa', 'firewall'], core1: ['core1', 'cisco-ios', 'core'] });
  assert.equal(r.already, 1); assert.equal(r.failed.length, 1); assert.equal(r.failed[0].ip, '10.0.0.99');
  assert.ok(calls.every((c) => c[2] === SECRET));
  const posted = calls.filter((c) => c[0] === 'POST' && c[3].ip).map((c) => c[3]);   // adds (an update carries only id + name / site)
  assert.ok(posted.every((b) => b.poll.ping === true && b.poll.snmp === false && !('snmp' in b) && !('credentials' in b)));   // never credentials
  // removed in the AI Network Engineer → not sent again; a second run adds nothing new
  devs.splice(devs.findIndex((d) => d.id === 'fw-hq'), 1);
  const r2 = await N.run();
  assert.equal(r2.added.length, 0); assert.equal(r2.skipped_removed, 1);
  assert.equal(N.view().pending.length, 1);   // only the failing one
});

test('netops sync: auto off stops the timer runs; SIEM link missing is reported, not thrown', async () => {
  const st = fakeStore({ assets: [net('a1', 'sw', '10.1.1.1', { vendor: 'Cisco' })] }), calls = [];
  const N = createNetopsSync({ store: st, config: {} }, { request: fakeSiem([], calls) });
  const r = await N.run(); assert.equal(r.ok, false); assert.match(r.error, /secret_file/);
  N.putSettings({ auto: false }, { user: 'siva', role: 'admin' }); assert.equal(N.view().settings.auto, false);
  N.tick(); assert.equal(calls.length, 0);
});

test('netops sync: class unknown and a discovery IP still sync, name / site edits are sent, skipped devices say why', async () => {
  const st = fakeStore({
    assets: [
      net('b1', 'C9300-ACC-3', '', { vendor: 'Cisco', model: 'C9300-48P', discovery: { class: 'unknown' }, site: 'Jeddah' }),
      net('b2', 'CORE-SW1-NEW', '10.2.0.1', { vendor: 'Cisco', site: 'Riyadh HQ' }),
      { id: 'b3', name: 'C9200 in a box', type: 'other', model: 'C9200L-24T', status: 'in_use', mgmt_ip: '10.2.0.50' },
      net('b4', 'Cisco phone?', '10.2.0.60', { vendor: 'Cisco', discovery: { class: 'phone' } }),
      net('b5', 'no address', '', { vendor: 'Cisco' }),
    ],
    disc_devices: [{ id: 'd1', asset_id: 'b1', ip: '10.2.0.33' }],
  });
  const devs = [{ id: 'core-sw1', ip: '10.2.0.1', name: 'CORE-SW1', site: 'Unassigned', vendor: 'cisco-ios', role: 'core' }], calls = [];
  const N = createNetopsSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } } }, { request: fakeSiem(devs, calls), readFile: () => SECRET });
  const r = await N.run({ user: 'siva', role: 'admin' });
  assert.deepEqual(r.added.map((x) => [x.name, x.ip]), [['C9300-ACC-3', '10.2.0.33']], 'class unknown + discovery IP');
  assert.deepEqual(r.updated, [{ asset_id: 'b2', device_id: 'core-sw1', changed: { name: 'CORE-SW1-NEW', site: 'Riyadh HQ' } }]);
  const upd = calls.find((c) => c[0] === 'POST' && c[3].id === 'core-sw1')[3];
  assert.deepEqual(Object.keys(upd).sort(), ['id', 'name', 'site'], 'vendor, role, polling and credentials are not touched');
  const why = Object.fromEntries(N.view().skipped.map((x) => [x.asset_id, x.why]));
  assert.match(why.b3, /type is "other"/); assert.match(why.b4, /classed it as phone/); assert.match(why.b5, /no IP address/);
  assert.equal((await N.run()).updated.length, 0, 'nothing to update the second time');
});

test('netops sync, the other way: devices of the AI Network Engineer fill asset facts, link by IP, or wait for approval', async (t) => {
  const { startApp } = require('./helpers');
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const ADM = { user: 'siva', role: 'admin', ip: '' }, A = e.app.assets;
  const core = A.create({ name: 'CORE-SW1', type: 'network', vendor: 'Cisco', mgmt_ip: '10.0.0.2', status: 'in_use' }, ADM).asset.id;
  const locked = A.create({ name: 'ACC-SW2', type: 'network', mgmt_ip: '10.0.0.3', serial: 'HAND-TYPED', status: 'in_use' }, ADM).asset.id;
  const devs = [
    { id: 'core-sw1', name: 'CORE-SW1', vendor: 'cisco-ios', ip: '10.0.0.2', role: 'core', site: 'Riyadh HQ', cli_facts: { hostname: 'core-sw1', model: 'C9500-24Y4C', version: '17.9.4a', serials: ['FDO1111AAAA'], at: Date.now() } },
    { id: 'acc-sw2', name: 'ACC-SW2', vendor: 'cisco-ios', ip: '10.0.0.3', role: 'access', cli_facts: { model: 'C9200L-48P', version: '17.6.5', serials: ['JAE2222BBBB'] } },
    { id: 'fgt-hq', name: 'FGT-HQ', vendor: 'fortigate', ip: '10.0.0.1', role: 'firewall', last: { system: { name: 'FGT-HQ', model: 'FortiGate 100F', version: 'v7.2.8', serial: 'FG100FTK1' } } },
  ], calls = [];
  e.app.config.discovery.siem = { secret_file: '/x' };
  const N2 = require('../engine/netops-sync').createNetopsSync(e.app, { request: fakeSiem(devs, calls), readFile: () => SECRET });
  N2.putSettings({ auto_add: false }, ADM);   // an administrator chose approval: devices wait in Asset Discovery
  const r = await N2.run(ADM);
  assert.equal(r.ok, true, r.error);
  assert.deepEqual([r.pulled.seen, r.pulled.linked, r.pulled.waiting], [3, 2, 1], JSON.stringify(r.pulled));
  let a = A.get(core); assert.deepEqual([a.model, a.serial, a.os], ['C9500-24Y4C', 'FDO1111AAAA', 'Cisco IOS 17.9.4a']);
  assert.equal(A.get(locked).serial, 'HAND-TYPED', 'a value typed by hand is not overwritten');
  const waiting = e.app.store.collection('disc_devices').all((d) => (d.uids || []).includes('netops:fgt-hq'))[0];
  assert.equal(waiting.status, 'new'); assert.equal(waiting.type, 'firewall'); assert.equal(waiting.serial, 'FG100FTK1');
  // later: the switch reports a new IOS version → the linked asset follows
  devs[0].cli_facts.version = '17.12.3';
  const r2 = await N2.run(ADM); assert.equal(r2.pulled.facts_updated >= 1, true);
  a = A.get(core); assert.equal(a.os, 'Cisco IOS 17.12.3');
  // auto_add puts devices only the network engineer knows straight into the inventory
  N2.putSettings({ auto_add: true }, ADM);
  const r3 = await N2.run(ADM); assert.equal(r3.pulled.added, 1);
  assert.ok(e.app.store.collection('assets').all((x) => x.mgmt_ip === '10.0.0.1').length === 1, 'FortiGate added to IT Asset Management');
});

test('auto_add is on by default: a device the network team registered goes straight into the register; only an explicit choice turns it off', async (t) => {
  const { startApp } = require('./helpers'), ADM = { user: 'syed', role: 'admin', ip: '' };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.config.discovery.siem = { secret_file: '/x' };
  const devs = [{ id: 'acc-sw-syn', name: 'ACC-SW-SYN', vendor: 'cisco-ios', ip: '10.7.0.3', role: 'access', cli_facts: { model: 'C9200L-48P', serials: ['JAE7777SYN'] } }];
  // an older settings record written by a save before this change: auto_add false, nobody chose it
  e.app.store.collection('netops_sync_settings').put({ id: 'settings', values: { auto: true, pull: true, auto_add: false } });
  const N = require('../engine/netops-sync').createNetopsSync(e.app, { request: fakeSiem(devs, []), readFile: () => SECRET });
  assert.equal(N.view().settings.auto_add, true, 'the old stored default does not count as a choice');
  const r = await N.run(ADM); assert.equal(r.pulled.added, 1, JSON.stringify(r.pulled));
  const a = e.app.store.collection('assets').all((x) => x.mgmt_ip === '10.7.0.3')[0];
  assert.ok(a, 'in the asset register'); assert.equal(a.serial, 'JAE7777SYN');
  N.putSettings({ auto_add: false }, ADM);
  assert.equal(N.view().settings.auto_add, false); assert.equal(N.view().settings.auto_add_by, 'syed');
});
