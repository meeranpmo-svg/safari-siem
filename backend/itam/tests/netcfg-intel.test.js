// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Configuration Audit (engine/netcfg-intel.js) over the REAL AI auditors (CY-19 Cisco IOS, CY-20 firewalls, CY-23 change control)
// and SYNTHETIC SIEM network evidence: before the first run everything reads "not run yet"; after a run every check has its result and
// every device is passing, failing (with the lines that failed) or NOT TESTED - a device whose configuration cannot be read is never
// counted as passing; a clean estate reads 100 %; no SIEM evidence = nothing tested; roles (a viewer sees counts, not devices; running
// needs an operator and a person), the audit record, one run at a time, the daily snapshot, the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const T = Date.parse('2026-10-20T08:00:00Z'), DAY = 86400000;
const iso = (d) => new Date(T - d * DAY).toISOString();
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed.syn', role: 'admin' }, BOT = { user: 'ai:netops', role: 'admin' };
const IOS_BAD = ['hostname SW-SYN-1', 'enable password 7 <removed>', 'snmp-server community <removed> RW', 'ip http server', 'line con 0', ' exec-timeout 0 0', 'line vty 0 4', ' transport input telnet ssh', ' exec-timeout 30 0', 'end'].join('\n');
const IOS_GOOD = ['hostname SW-SYN-2', 'service timestamps log datetime msec show-timezone', 'service password-encryption', 'enable secret 9 <removed>', 'aaa new-model', 'aaa authentication login default group tacacs+ local', 'ip ssh version 2',
  'no ip http server', 'no ip source-route', 'snmp-server community <removed> RO 10', 'logging host 192.0.2.50', 'ntp server 192.0.2.1', 'banner login ^C Authorised use only ^C', 'line con 0', ' exec-timeout 10 0', 'line vty 0 4', ' access-class 10 in', ' exec-timeout 10 0', ' transport input ssh', 'end'].join('\n');
const dev = (id, vendor, o = {}) => Object.assign({ id, name: id.toUpperCase(), vendor, role: vendor === 'cisco-ios' ? 'access' : 'firewall', site: 'HQ', ip: '192.0.2.' + (10 + id.length), criticality: 2,
  monitoring: { snmp: 'v3 authPriv', api: vendor === 'cisco-ios' ? null : 'token set, certificate pinned', ssh: 'set' }, polled_at: iso(0), security_at: iso(0), security_errors: [], security: [], licenses: [], config: null }, o);
function network(bad) {
  return { available: true, devices: [
    dev('sw-syn-1', 'cisco-ios', { config: { sha256: 'a'.repeat(64), at: iso(0) } }), dev('sw-syn-2', 'cisco-ios', { config: { sha256: 'b'.repeat(64), at: iso(0) } }),
    dev('sw-syn-3', 'cisco-ios', bad ? { config: { error: 'no SSH login or trusted host key - configuration not read' } } : { config: { sha256: 'c'.repeat(64), at: iso(0) } }),
    dev('pa-edge', 'paloalto', { security: bad ? [{ kind: 'pa-any-any', severity: 'high', key: 'allow-all', title: 'Security rule "allow-all" allows any', evidence: ['from trust to untrust'], rec: '' }] : [],
      licenses: bad ? [{ name: 'Threat Prevention', expires: iso(10) }] : [{ name: 'Threat Prevention', expires: new Date(T + 100 * DAY).toISOString() }] }),
    dev('fg-users', 'fortigate', bad ? { monitoring: { snmp: 'v2c', api: null, ssh: null }, security_at: iso(5) } : {}),
  ] };
}
const configs = (bad) => ({ 'sw-syn-1': bad ? IOS_BAD : IOS_GOOD, 'sw-syn-2': IOS_GOOD, 'sw-syn-3': IOS_GOOD });
const source = (bad) => (p) => { if (p === '/audit/evidence/network') return network(bad); const m = /^\/audit\/evidence\/network\/config\/(.+)$/.exec(p); return m ? { text: configs(bad)[decodeURIComponent(m[1])] } : null; };
// clean estate: every switch hardened (sw-syn-1 too)
const sourceClean = () => (p) => { if (p === '/audit/evidence/network') return network(false); const m = /^\/audit\/evidence\/network\/config\/(.+)$/.exec(p); return m ? { text: IOS_GOOD } : null; };

async function setup(t, src) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = T;
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', siemEvidence: async (p) => src(p) });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const check = (v, label) => v.sections[0].rows.find((r) => r.cells[0] === label);
const dev0 = (v, name) => v.sections[2].items.find((i) => i.title.startsWith(name + ' ·'));

test('before the first run: everything reads "not run yet", nothing is passing', async (t) => {
  const s = await setup(t, source(true));
  const r = await s.get('/netcfg-intel'); assert.equal(r.status, 200, r.text); const v = r.json;
  assert.equal(v.ring.value, null); assert.match(v.ring.why, /not run yet/);
  assert.ok(v.sections[0].rows.length >= 16 && v.sections[0].rows.every((x) => x.cells[3].text === 'not run yet'), 'no check is shown as passing before it ran');
  assert.ok(v.sections[2].items.length === 5 && v.sections[2].items.every((i) => i.tags.includes('not_run')), 'every device in the inventory, none passing');
  assert.equal(v.kpis.find((k) => k.label === 'Last run').value, 'not run yet');
});

test('after a run: checks, devices with their failing lines, unread devices NOT TESTED, never passing', async (t) => {
  const s = await setup(t, source(true));
  const run = await s.post('/netcfg-intel/run', {}); assert.equal(run.status, 200, run.raw); assert.match(run.json.message, /CY-19 fail/);
  const v = (await s.get('/netcfg-intel')).json;
  assert.equal(check(v, 'SSH version 2, no Telnet').cells[3].text, 'fails'); assert.equal(check(v, 'No SNMP read-write community').cells[3].text, 'fails');
  assert.equal(check(v, 'HTTP server off').cells[3].text, 'fails'); assert.equal(check(v, 'Configuration could be read').cells[3].text, 'fails');
  assert.equal(check(v, 'Rule base: no any-any, no internet-to-any, logging on').cells[3].text, 'fails'); assert.equal(check(v, 'Security subscriptions and support current').cells[3].text, 'fails');
  assert.equal(check(v, 'Rule base can be reviewed').cells[3].text, 'fails');
  assert.notEqual(check(v, 'Changes only through an approved change').cells[3].text, 'passes', 'change control needs two captures - not run / not tested, never passes');
  const sw1 = dev0(v, 'SW-SYN-1'); assert.ok(sw1.tags.includes('fail') && sw1.tone === 'bad');
  const lines = sw1.detail.lists[0].items.join('\n'); assert.match(lines, /SSH version 2, no Telnet/); assert.match(lines, /No SNMP read-write community/); assert.match(lines, /HTTP server off/);
  assert.ok(dev0(v, 'SW-SYN-2').tags.includes('pass'), 'the hardened switch passes');
  const sw3 = dev0(v, 'SW-SYN-3'); assert.ok(sw3.tags.includes('not_tested') && !sw3.tags.includes('pass')); assert.match(sw3.detail.text, /not counted as passing/); assert.match(sw3.detail.rows.find((x) => x[0] === 'How it is read')[1], /configuration not read/);
  assert.ok(dev0(v, 'PA-EDGE').tags.includes('fail')); assert.ok(dev0(v, 'FG-USERS').tags.includes('not_tested'), 'a firewall whose rule base cannot be read is not tested');
  assert.equal(v.ring.value, 33, 'one of the three audited devices has no finding; the two unread ones are outside the percentage'); assert.match(v.ring.why, /2 not tested/);
  assert.equal(v.kpis.find((k) => k.label === 'Not tested').value, 2); assert.ok(v.kpis.find((k) => k.label === 'High / critical').value >= 3);
  const a = s.audit('netcfg-intel.run'); assert.equal(a.length, 1); assert.equal(a[0].by, OP.user); assert.equal(a[0].role, 'operator'); assert.ok(a[0].detail.tests.some((x) => x.id === 'CY-19' && x.state === 'fail'));
});

test('a clean estate reads 100 % and every check passes', async (t) => {
  const s = await setup(t, sourceClean());
  assert.equal((await s.post('/netcfg-intel/run', {}, ADM)).status, 200);
  const v = (await s.get('/netcfg-intel')).json;
  assert.equal(v.ring.value, 100, v.ring.why);
  for (const label of ['Central AAA (TACACS+ / RADIUS)', 'SSH version 2, no Telnet', 'Enable secret and password encryption', 'No SNMP read-write community', 'HTTP server off', 'Syslog to the SIEM, NTP, time stamps, banner', 'Security subscriptions and support current'])
    assert.equal(check(v, label).cells[3].text, 'passes', label);
  assert.ok(v.sections[2].items.filter((i) => i.tags.includes('cisco')).every((i) => i.tags.includes('pass')));
});

test('no SIEM evidence: nothing is tested and nothing passes', async (t) => {
  const s = await setup(t, () => null);
  assert.equal((await s.post('/netcfg-intel/run', {})).status, 200);
  const v = (await s.get('/netcfg-intel')).json;
  assert.equal(v.ring.value, null); assert.ok(v.sections[0].rows.filter((r) => r.tags.includes('CY-19') || r.tags.includes('CY-20')).every((r) => r.cells[3].text === 'not tested'));
  assert.equal(v.sections[2].items.length, 0); assert.match(v.sections[2].empty, /not available/);
});

test('roles: a viewer sees counts and checks but no device; running needs an operator and a person; validation; one run at a time', async (t) => {
  const s = await setup(t, source(true));
  assert.equal((await s.post('/netcfg-intel/run', {}, VIEW)).status, 403, 'a viewer cannot run it');
  assert.equal((await s.post('/netcfg-intel/run', {}, BOT)).status, 403, 'a service or AI identity cannot run it');
  assert.equal((await s.audit('netcfg-intel.run')).length, 0, 'a refused run leaves no audit record of a run');
  assert.equal((await s.post('/netcfg-intel/run', { junk: 'x'.repeat(10) })).status, 200, 'undeclared fields are dropped, not applied');
  const X = s.e.app.addons.netcfgIntel, r = await Promise.allSettled([X.run({}, OP), X.run({}, OP)]);
  assert.deepEqual(r.map((x) => x.status === 'fulfilled' ? 200 : x.reason.status).sort(), [200, 409], 'one run at a time');
  const v = (await s.get('/netcfg-intel', VIEW)).json;
  assert.equal(v.sections[2].items.length, 0, 'device names are for operators and administrators'); assert.match(v.sections[2].caption, /operators and administrators/);
  assert.ok(v.sections[0].rows.some((r) => r.cells[3].text === 'fails'), 'a viewer still reads the checks');
  assert.ok(!/SW-SYN|PA-EDGE|FG-USERS|192\.0\.2\./i.test(JSON.stringify(v)), 'no device name or address reaches a viewer');
});

test('daily snapshot and the advisor', async (t) => {
  const s = await setup(t, source(true));
  await s.post('/netcfg-intel/run', {});
  const v = (await s.get('/netcfg-intel')).json; assert.ok(v.sections[3].points.length >= 1 && v.sections[3].points[0].value === 33, 'the run recorded the day\'s snapshot');
  assert.equal((await s.post('/netcfg-intel/ask', { question: 'what should we fix first?' }, VIEW)).status, 403);
  assert.equal((await s.post('/netcfg-intel/ask', { question: 'what should we fix first?' }, OP)).status, 424, 'off until external AI is allowed');
  assert.equal((await s.post('/netcfg-intel/ask', { question: 'x' }, OP)).status, 400, 'validation names the field');
});
