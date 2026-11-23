// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Windows / Exchange servers → AI Server Administrators: which assets qualify, how Exchange is recognised (and why),
// dedupe by IP, a server the sync added gains the Exchange role later, removed servers are not re-sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSysadminSync, isWindows, exchangeWhy } = require('../engine/sysadmin-sync');

function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id) }; })()) };
}
const srv = (id, name, ip, extra) => Object.assign({ id, name, type: 'server', mgmt_ip: ip, status: 'in_use', os: 'Microsoft Windows Server 2019 Standard' }, extra || {});

test('sysadmin sync: Windows servers and VMs go to the list once, Exchange recognised with a reason', async () => {
  const st = fakeStore({ assets: [
    srv('a1', 'FS01.corp.local', '10.0.1.10', { site: 'Riyadh HQ' }),
    srv('a2', 'EXCH01', '10.0.1.20'),
    srv('a3', 'MAILSRV', '10.0.1.21', { software: [{ name: 'Microsoft Exchange Server 2019 Cumulative Update 14' }] }),
    srv('a4', 'APP7', '10.0.1.30', { type: 'vm', os: 'Microsoft Windows Server 2022 (64-bit)' }),
    srv('a5', 'LNX1', '10.0.1.40', { os: 'Red Hat Enterprise Linux 9' }),
    srv('a6', 'PC-01', '10.0.5.5', { type: 'workstation', os: 'Windows 11' }),
    srv('a7', 'NOIP', ''), srv('a8', 'OLD', '10.0.1.50', { status: 'retired' }),
    srv('a9', 'ALREADY', '10.0.1.60'), srv('a10', 'EXCH02', '10.0.1.70'),
    srv('a11', 'removed', '10.0.1.80'),
  ], sysadmin_sync: [{ id: 'a11', server_id: 'removed', ip: '10.0.1.80', state: 'sent' }] });
  const list = [{ id: 'already', ip: '10.0.1.60', source: 'manual', roles: ['windows'] }, { id: 'exch02', ip: '10.0.1.70', source: 'itam', roles: ['windows'] }], calls = [];
  const request = async (url, o) => { if (/\/top$/.test(url)) return { status: 200, json: { values: [] } }; calls.push([o.method, url.replace(/^.*\/api\/soc/, ''), o.body && JSON.parse(o.body)]); if (o.method === 'GET') return { status: 200, json: { items: list } };
    const b = JSON.parse(o.body), ex = list.find((t) => t.id === b.id); if (ex) Object.assign(ex, b); else list.push(b); return { status: 200, json: b }; };
  assert.equal(isWindows({ type: 'vm', mgmt_ip: '1.1.1.1', os: 'Windows Server 2016', status: 'in_use' }), true);
  assert.equal(exchangeWhy({ name: 'srv-mbx2' }), 'host name srv-mbx2'); assert.equal(exchangeWhy({ name: 'EXPORT01' }), ''); assert.equal(exchangeWhy({ name: 'executive-pc' }), '');
  const S = createSysadminSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } } }, { request, readFile: () => 'y'.repeat(32) });
  const r = await S.run({ user: 'siva', role: 'admin' });
  assert.equal(r.ok, true, r.error);
  const by = Object.fromEntries(r.added.map((x) => [x.name, [x.server_id, x.roles.join('+'), x.why]]));
  assert.deepEqual(Object.keys(by).sort(), ['APP7', 'EXCH01', 'FS01.corp.local', 'MAILSRV']);
  assert.deepEqual(by.EXCH01, ['exch01', 'windows+exchange', 'host name EXCH01']);
  assert.deepEqual(by.MAILSRV.slice(1), ['windows+exchange', 'software: Microsoft Exchange Server 2019 Cumulative Update 14']);
  assert.deepEqual(by['FS01.corp.local'].slice(0, 2), ['fs01', 'windows']);
  const post = calls.find((c) => c[0] === 'POST' && c[2].id === 'fs01')[2];
  assert.equal(post.source, 'itam'); assert.equal(post.asset_id, 'a1'); assert.equal(post.site, 'Riyadh HQ'); assert.ok(!('password' in post) && !('logins' in post));
  assert.equal(r.already, 2); assert.equal(r.skipped_removed, 1);
  assert.deepEqual(r.upgraded.map((u) => u.server_id), ['exch02'], 'an itam-added server gains the Exchange role');
  assert.ok(!calls.some((c) => c[0] === 'POST' && c[2].id === 'already'), 'a manually added server is left alone');
  calls.length = 0; const r2 = await S.run();
  assert.equal(r2.added.length, 0); assert.equal(calls.filter((c) => c[0] === 'POST').length, 0, 'nothing sent twice');
  assert.equal(S.view().pending.length, 0);
});

test('sysadmin sync: Exchange without an OS still goes, a hand-added server gains the Exchange role once, discovery IP used, skipped ones say why', async () => {
  const st = fakeStore({
    assets: [
      { id: 'b1', name: 'EXCH01', type: 'server', mgmt_ip: '10.2.0.20', status: 'in_use' },                                  // no OS at all
      { id: 'b2', name: 'MBX02', type: 'vm', status: 'in_use', tags: ['exchange'] },                                          // IP only from discovery
      { id: 'b3', name: 'EXCH03', type: 'server', mgmt_ip: '10.2.0.40', status: 'in_use', os: 'Windows Server 2019' },        // added by hand in the SIEM
      { id: 'b4', name: 'EXCH04', type: 'other', mgmt_ip: '10.2.0.50', status: 'in_use', tags: ['exchange'] },                // wrong type
      { id: 'b5', name: 'EX2019-5', type: 'server', status: 'in_use' },                                                       // no IP anywhere
    ],
    disc_devices: [{ id: 'd2', asset_id: 'b2', ip: '10.2.0.30' }],
  });
  const list = [{ id: 'exch03', ip: '10.2.0.40', source: 'manual', roles: ['windows'] }], calls = [];
  const request = async (url, o) => { if (/\/top$/.test(url)) return { status: 200, json: { values: [] } }; calls.push([o.method, o.body && JSON.parse(o.body)]); if (o.method === 'GET') return { status: 200, json: { items: list } };
    const b = JSON.parse(o.body), ex = list.find((t) => t.id === b.id); if (ex) Object.assign(ex, b); else list.push(b); return { status: 200, json: b }; };
  const S = createSysadminSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } } }, { request, readFile: () => 'y'.repeat(32) });
  const r = await S.run({ user: 'siva', role: 'admin' });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.added.map((x) => [x.name, x.ip, x.roles.join('+')]).sort(), [['EXCH01', '10.2.0.20', 'windows+exchange'], ['MBX02', '10.2.0.30', 'windows+exchange']]);
  assert.deepEqual(r.upgraded.map((x) => x.server_id), ['exch03']); assert.deepEqual(list.find((t) => t.id === 'exch03').roles, ['windows', 'exchange']);
  const why = Object.fromEntries(S.view().skipped.map((x) => [x.asset_id, x.why]));
  assert.match(why.b4, /type is "other"/); assert.match(why.b5, /no IP address/);
  // an administrator takes the Exchange role away again: the sync does not put it back
  list.find((t) => t.id === 'exch03').roles = ['windows'];
  const r2 = await S.run({ user: 'siva', role: 'admin' });
  assert.equal(r2.upgraded.length, 0); assert.deepEqual(list.find((t) => t.id === 'exch03').roles, ['windows']);
});

test('sysadmin sync: a Windows server named *MAIL* is Exchange, a Linux one is not', () => {
  const { exchangeWhy } = require('../engine/sysadmin-sync');
  assert.match(exchangeWhy({ name: 'CORP-MAIL01', os: 'Windows Server 2019' }), /Windows mail server/);
  assert.match(exchangeWhy({ name: 'mail02.corp.local', os: 'Microsoft Windows Server 2016 Standard' }), /Windows mail server/);
  assert.equal(exchangeWhy({ name: 'mail-relay', os: 'Ubuntu 22.04' }), '');
  assert.equal(exchangeWhy({ name: 'gmailsync', os: 'Windows Server 2019' }), '');
});

test('sysadmin sync: Exchange also from the Email Route Map register and Business Services (the Exchange page agrees)', async () => {
  const st = fakeStore({ assets: [srv('b1', 'SRV-SYN-77', '10.0.2.77'), srv('b2', 'SRV-SYN-78', '10.0.2.78', { os: '' }), srv('b3', 'FILE-SYN', '10.0.2.79')],
    mailrep: [{ id: 'route_profile', servers: [{ name: 'SRV-SYN-77', role: 'exchange', private_ip: '10.0.2.77', public_ips: [] }, { name: 'GW-SYN', role: 'gateway', private_ip: '10.0.2.79' }] }] });
  const list = [], request = async (url, o) => { if (/\/top$/.test(url)) return { status: 200, json: { values: [] } }; if (o.method === 'GET') return { status: 200, json: { items: list } }; const b = JSON.parse(o.body); list.push(b); return { status: 200, json: b }; };
  const app = { store: st, config: { discovery: { siem: { secret_file: '/x' } } },
    addons: { serviceMap: { view: () => ({ servers: [{ ip: '10.0.2.78', host: 'SRV-SYN-78', services: [{ id: 'exchange', confidence: 'confirmed', evidence: [{ detail: 'HTTPS 443: Outlook on the web 15.2.1544' }] }] }] }) } } };
  const r = await createSysadminSync(app, { request, readFile: () => 'y'.repeat(32) }).run({ user: 'siva', role: 'admin' });
  const by = Object.fromEntries(r.added.map((x) => [x.name, [x.roles.join('+'), x.why]]));
  assert.deepEqual(by['SRV-SYN-77'], ['windows+exchange', 'Email Route Map register: role exchange']);
  assert.deepEqual(by['SRV-SYN-78'], ['windows+exchange', 'Business Services: HTTPS 443: Outlook on the web 15.2.1544'], 'Exchange with no OS recorded still counts (Exchange runs on Windows)');
  assert.deepEqual(by['FILE-SYN'][0], 'windows', 'a gateway in the register is not Exchange');
});

test('sysadmin sync: servers that send Exchange message-tracking logs to the SIEM are Exchange - the Exchange page agrees', async () => {
  const st = fakeStore({ assets: [srv('c1', 'SENTRA-MAILHQ-SYN', '10.0.3.10'), srv('c2', 'APP-SYN-9', '10.0.3.11'), srv('c3', 'DAG-NODE-SYN', '10.0.3.12', { os: '' })] });
  const list = [], tops = [];
  const request = async (url, o) => {
    if (/\/top$/.test(url)) { const b = JSON.parse(o.body); tops.push(b); if (b.q !== 'src_type:exchange') return { status: 200, json: { values: [] } }; return { status: 200, json: { values: b.field === 'host' ? [{ v: 'sentra-mailhq-syn.corp.local', n: 9000 }] : [{ v: '10.0.3.12', n: 4000 }] } }; }
    if (o.method === 'GET') return { status: 200, json: { items: list } }; const b = JSON.parse(o.body); list.push(b); return { status: 200, json: b };
  };
  const app = { store: st, config: { discovery: { siem: { secret_file: '/x' } } } };
  const r = await createSysadminSync(app, { request, readFile: () => 'y'.repeat(32) }).run({ user: 'siva', role: 'admin' });
  const mt = tops.filter((b) => b.q === 'src_type:exchange');
  assert.ok(mt.length === 2 && mt.every((b) => b.from === 'now-7d' && b.limit === 100), 'asks the SIEM which hosts sent Exchange logs');
  assert.ok(tops.some((b) => b.q === 'action:exchange-cmdlet' && b.from === 'now-30d'), 'and which hosts write the Exchange cmdlet log');
  const by = Object.fromEntries(r.added.map((x) => [x.name, [x.roles.join('+'), x.why]]));
  assert.deepEqual(by['SENTRA-MAILHQ-SYN'], ['windows+exchange', 'SIEM: sends Exchange message-tracking logs'], 'matched by host name');
  assert.deepEqual(by['DAG-NODE-SYN'], ['windows+exchange', 'SIEM: sends Exchange message-tracking logs'], 'matched by IP, no OS recorded');
  assert.deepEqual(by['APP-SYN-9'][0], 'windows');
  assert.equal(st.collection('exchange_seen').get('siem').names[0], 'sentra-mailhq-syn.corp.local', 'kept for the Exchange server page');
  assert.equal(r.exchange_log_senders, 1);
});

test('sysadmin sync: the servers the SIEM admin already has with the Exchange role are kept for the Servers pages', async () => {
  const st = fakeStore({ assets: [] });
  const list = [{ id: 'win-x1', name: 'MBX-SYN-1', ip: '10.0.4.1', roles: ['windows', 'exchange'], asset_id: 'a-x1' }, { id: 'win-x2', name: 'FS-SYN', ip: '10.0.4.2', roles: ['windows'] }];
  const request = async (url, o) => { if (/\/top$/.test(url)) return { status: 200, json: { values: [] } }; return { status: 200, json: { items: list } }; };
  const r = await createSysadminSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } }, addons: {} }, { request, readFile: () => 'y'.repeat(32) }).run({ user: 'siva', role: 'admin' });
  assert.equal(r.exchange_servers, 1);
  const s = st.collection('exchange_seen').get('siem-admin');
  assert.deepEqual([s.names, s.ips, s.assets], [['MBX-SYN-1'], ['10.0.4.1'], ['a-x1']], 'only the Exchange one');
});

test('sysadmin sync: the Exchange servers Active Directory lists and the hosts writing the Exchange cmdlet log get the Exchange role', async () => {
  const st = fakeStore({ assets: [srv('d1', 'SYNMSG01', '10.0.5.10'), srv('d2', 'SYNMSG02', '10.0.5.11'), srv('d3', 'FILE-SYN', '10.0.5.12')] });
  const list = [], paths = [];
  const request = async (url, o) => {
    paths.push(url.replace(/^.*\/api\/soc/, ''));
    if (/\/top$/.test(url)) { const b = JSON.parse(o.body); return { status: 200, json: { values: b.q === 'action:exchange-cmdlet' && b.field === 'host_ip' ? [{ v: '10.0.5.11', n: 50 }] : [] } }; }
    if (/\/identity\/exchange-servers$/.test(url)) return { status: 200, json: { available: true, items: [{ name: 'SYNMSG01', fqdn: 'synmsg01.corp-hq.test', version: 'Version 15.2 (Build 1544.4)', roles: ['mailbox'] }] } };
    if (o.method === 'GET') return { status: 200, json: { items: list } }; const b = JSON.parse(o.body); list.push(b); return { status: 200, json: b };
  };
  const r = await createSysadminSync({ store: st, config: { discovery: { siem: { secret_file: '/x' } } } }, { request, readFile: () => 'y'.repeat(32) }).run({ user: 'siva', role: 'admin' });
  assert.ok(paths.includes('/identity/exchange-servers'));
  assert.equal(r.exchange_in_ad, 1);
  const by = Object.fromEntries(r.added.map((x) => [x.name, [x.roles.join('+'), x.why]]));
  assert.deepEqual(by.SYNMSG01[0], 'windows+exchange'); assert.match(by.SYNMSG01[1], /Active Directory: Exchange server object \(Version 15\.2/);
  assert.deepEqual(by.SYNMSG02[0], 'windows+exchange'); assert.match(by.SYNMSG02[1], /cmdlet log/);
  assert.equal(by['FILE-SYN'][0], 'windows');
});
