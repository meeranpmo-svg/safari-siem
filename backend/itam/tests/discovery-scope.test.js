// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Discovery scopes: validation (RFC 1918 by default, public only with a flag), exclusions, expansion, schedule math in
// Riyadh time (UTC+3), scan windows, and the SAFETY GATE that blocks active methods until the checklist is complete.
const test = require('node:test');
const assert = require('node:assert/strict');
const ip4 = require('../engine/discovery/ipv4');
const sched = require('../engine/discovery/schedule');
const S = require('../engine/discovery/scopes');

const SITES = ['Riyadh HQ', 'Jeddah DR', 'Riyadh Olaya', 'Alkhobar'];
const base = (o) => Object.assign({ name: 'HQ servers', site: 'Riyadh HQ', targets: ['10.20.0.0/24'] }, o);
const err = (fn, re) => assert.throws(fn, (e) => e.status === 400 && re.test(e.message));

test('targets: CIDR / range / single IP parsing and RFC 1918 enforcement', () => {
  assert.deepEqual(ip4.parseTarget('10.20.0.0/24'), { kind: 'cidr', first: ip4.parseIp('10.20.0.0'), last: ip4.parseIp('10.20.0.255'), bits: 24, text: '10.20.0.0/24', count: 256 });
  assert.equal(ip4.parseTarget('192.168.1.10-192.168.1.20').count, 11);
  assert.equal(ip4.parseTarget('192.168.1.10-20').text, '192.168.1.10-192.168.1.20');
  assert.equal(ip4.parseTarget('172.16.5.4').kind, 'ip');
  assert.throws(() => ip4.parseTarget('10.20.0.1/24'), /not a network address/);
  assert.throws(() => ip4.parseTarget('10.0.0.300'), /not an IPv4/);
  assert.throws(() => ip4.parseTarget('010.0.0.1'), /not an IPv4/); // octal-looking octets refused
  assert.throws(() => ip4.parseTarget('10.0.0.9-10.0.0.1'), /ends before/);
  assert.ok(ip4.isPrivate('10.1.2.3') && ip4.isPrivate('172.31.255.1') && ip4.isPrivate('192.168.0.1'));
  assert.ok(!ip4.isPrivate('172.32.0.1') && !ip4.isPrivate('8.8.8.8'));

  const ok = S.normScope(base({}), { sites: SITES });
  assert.equal(ok.host_count, 256);
  err(() => S.normScope(base({ targets: ['203.0.113.0/28'] }), { sites: SITES }), /not private \(RFC 1918\)/);
  err(() => S.normScope(base({ targets: ['10.255.255.0-11.0.0.5'] }), { sites: SITES }), /not private/); // straddles a block
  const pub = S.normScope(base({ targets: ['203.0.113.0/28'], allow_public: true }), { sites: SITES });
  assert.equal(pub.allow_public, true);
  err(() => S.normScope(base({ targets: ['127.0.0.0/8'], allow_public: true }), { sites: SITES }), /loopback/);
  err(() => S.normScope(base({ targets: ['169.254.0.0/16'], allow_public: true }), { sites: SITES }), /link-local/);
  err(() => S.normScope(base({ site: 'Dammam' }), { sites: SITES }), /site must be one of/);
  err(() => S.normScope(base({ targets: ['10.0.0.0/16'] }), { sites: SITES, maxHosts: 4096 }), /limit per scope is 4096/);
  err(() => S.normScope(base({ vlan: 5000 }), { sites: SITES }), /vlan must be an integer 1-4094/);
  err(() => S.normScope(base({ rate: { max_hosts_per_sec: 0 } }), { sites: SITES }), /max_hosts_per_sec/);
  err(() => S.normScope(base({ methods: { telnet: true } }), { sites: SITES }), /unknown method "telnet"/);
  err(() => S.normScope(base({ methods: { sweep: { enabled: true, tcp_ports: [22, 161] } } }), { sites: SITES }), /UDP 161 is not a TCP port/);
  err(() => S.normScope(base({ methods: { snmp: { enabled: true } } }), { sites: SITES }), /choose a credential/);
  const withVlan = S.normScope(base({ vlan: 120, label: 'Server VLAN', rate: { max_hosts_per_sec: 50, concurrency: 16 } }), { sites: SITES });
  assert.deepEqual([withVlan.vlan, withVlan.rate.max_hosts_per_sec, withVlan.rate.concurrency], [120, 50, 16]);
  assert.deepEqual(withVlan.methods.sweep.tcp_ports, [22, 25, 80, 135, 443, 444, 445, 2525, 3389, 5985]);
});

test('credential references are checked for existence and kind', () => {
  const creds = { cr_a: { kind: 'snmp_v2c' }, cr_b: { kind: 'ldap' } };
  const lookup = (id) => creds[id] || null;
  const ok = S.normScope(base({ methods: { snmp: { enabled: true, credential_ids: ['cr_a'] }, ad: { enabled: true, credential_id: 'cr_b' } } }), { sites: SITES, credentials: lookup });
  assert.deepEqual(ok.methods.snmp.credential_ids, ['cr_a']);
  err(() => S.normScope(base({ methods: { snmp: { enabled: true, credential_ids: ['cr_b'] } } }), { sites: SITES, credentials: lookup }), /is ldap, expected snmp_v2c or snmp_v3/);
  err(() => S.normScope(base({ methods: { ad: { enabled: true, credential_id: 'cr_zz' } } }), { sites: SITES, credentials: lookup }), /not found/);
});

test('exclusions are removed on expansion; network/broadcast and reserved addresses skipped', () => {
  const hosts = ip4.expand(['10.20.0.0/29', '10.20.0.100-10.20.0.102'], ['10.20.0.3', '10.20.0.101']).map(ip4.ipStr);
  assert.deepEqual(hosts, ['10.20.0.1', '10.20.0.2', '10.20.0.4', '10.20.0.5', '10.20.0.6', '10.20.0.100', '10.20.0.102']);
  assert.deepEqual(ip4.expand(['10.0.0.0/31']).map(ip4.ipStr), ['10.0.0.0', '10.0.0.1']); // /31: both usable
  assert.throws(() => ip4.expand(['10.0.0.0/20'], [], { max: 1000 }), /more than 1000/);
  assert.ok(ip4.contains(['10.20.0.0/24'], '10.20.0.77'));
  assert.ok(!ip4.contains(['10.20.0.0/24'], '10.20.1.1'));
});

test('schedule math is in Riyadh time (UTC+3, no DST)', () => {
  const from = Date.UTC(2026, 9, 7, 20, 0); // 2026-10-07 23:00 Riyadh (Wednesday)
  const daily = sched.normSchedule({ type: 'daily', time: '02:00' });
  assert.equal(new Date(sched.nextRun(daily, from)).toISOString(), '2026-10-07T23:00:00.000Z'); // 02:00 Thu Riyadh
  const weekly = sched.normSchedule({ type: 'weekly', day: 'fri', time: '01:30' });
  assert.equal(weekly.day, 5);
  assert.equal(new Date(sched.nextRun(weekly, from)).toISOString(), '2026-10-08T22:30:00.000Z'); // Fri 01:30 Riyadh
  const weekly2 = sched.normSchedule({ type: 'weekly', day: 3, time: '23:30' }); // Wednesday, later the same evening
  assert.equal(new Date(sched.nextRun(weekly2, from)).toISOString(), '2026-10-07T20:30:00.000Z');
  assert.equal(new Date(sched.nextRun(weekly2, Date.UTC(2026, 9, 7, 20, 30))).toISOString(), '2026-10-14T20:30:00.000Z'); // strictly after
  const once = sched.normSchedule({ type: 'once', at: '2026-10-10T03:15' });
  assert.equal(new Date(sched.nextRun(once, from)).toISOString(), '2026-10-10T00:15:00.000Z');
  assert.equal(sched.nextRun(once, Date.UTC(2026, 9, 11)), null, 'a past one-off never runs again');
  assert.equal(sched.nextRun({ type: 'manual' }, from), null);
  assert.throws(() => sched.normSchedule({ type: 'daily', time: '25:00' }), /HH:MM/);
  assert.throws(() => sched.normSchedule({ type: 'once', at: '2026-02-30T01:00' }), /not a valid date/);
  assert.throws(() => sched.normSchedule({ type: 'hourly' }), /manual, once, daily or weekly/);
  // window crossing midnight: 22:00-05:00 Riyadh
  const win = sched.normWindow({ start: '22:00', end: '05:00' });
  assert.equal(sched.inWindow(win, Date.UTC(2026, 9, 7, 20, 0)), true);  // 23:00
  assert.equal(sched.inWindow(win, Date.UTC(2026, 9, 7, 1, 0)), true);   // 04:00
  assert.equal(sched.inWindow(win, Date.UTC(2026, 9, 7, 9, 0)), false);  // 12:00
  assert.equal(sched.label(weekly), 'weekly fri 01:30 (Riyadh)');
});

test('SAFETY GATE: active methods blocked until the checklist is complete; changing targets re-closes it', () => {
  const lookup = () => ({ kind: 'snmp_v2c' });
  const f = S.normScope(base({ methods: { sweep: { enabled: true }, snmp: { enabled: true, credential_ids: ['cr_x'] }, arp: { enabled: true }, ad: { enabled: true, credential_id: 'cr_l' } } }), { sites: SITES, credentials: (id) => (id === 'cr_l' ? { kind: 'ldap' } : lookup()) });
  const scope = Object.assign({ id: 'sc_1' }, f);
  let am = S.allowedMethods(scope, {});
  assert.deepEqual(am.run.sort(), ['ad', 'arp']);
  assert.deepEqual(am.blocked.map((b) => b.method).sort(), ['snmp', 'sweep']);
  assert.match(am.blocked[0].reason, /safety gate/);
  // checklist validation: every part is mandatory
  const good = { firewall: { snmp_161: true, ssh_22: true, winrm_5985_5986: true, icmp: true }, soc_notified_name: 'SOC duty lead', soc_notified_date: '2026-10-06', approved_by: 'IT Infrastructure Manager' };
  assert.throws(() => S.normChecklist(Object.assign({}, good, { firewall: { snmp_161: true, ssh_22: true, icmp: true } })), /winrm/);
  assert.throws(() => S.normChecklist(Object.assign({}, good, { soc_notified_name: '' })), /SOC contact/);
  assert.throws(() => S.normChecklist(Object.assign({}, good, { soc_notified_date: '06/10/2026' })), /YYYY-MM-DD/);
  assert.throws(() => S.normChecklist(Object.assign({}, good, { approved_by: ' ' })), /approved_by/);
  const c = S.normChecklist(good);
  scope.checklist = Object.assign(c, { completed_at: new Date().toISOString(), targets_fp: S.targetsFingerprint(scope) });
  am = S.allowedMethods(scope, {});
  assert.deepEqual(am.run.sort(), ['ad', 'arp', 'snmp', 'sweep']);
  // global toggle still wins
  am = S.allowedMethods(scope, { snmp: false });
  assert.deepEqual(am.blocked, [{ method: 'snmp', reason: 'disabled globally' }]);
  // targets change → gate closed again
  const changed = Object.assign({}, scope, { targets: ['10.20.0.0/23'] });
  assert.equal(S.gateOpen(changed), false);
  assert.deepEqual(S.allowedMethods(changed, {}).run.sort(), ['ad', 'arp']);
  const excl = Object.assign({}, scope, { exclusions: ['10.20.0.9'] });
  assert.equal(S.gateOpen(excl), false, 'exclusions are part of the approved target set');
});
