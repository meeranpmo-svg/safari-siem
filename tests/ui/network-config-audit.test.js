// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Configuration Audit (network-config-audit.html) against the REAL ITAM engines (AI auditors CY-19 / CY-20 / CY-23, engine/netcfg-intel.js)
// and SYNTHETIC SIEM network evidence: before the first run nothing passes; "Run the audit now" (operator) runs the three tests; the checks table
// with its filters and a check's detail; device cards with their failing lines; a device that cannot be read is NOT TESTED, never passing; a
// viewer sees the checks but no device and has no run button; a hostile finding stays text; the advisor off until allowed; menu entry, installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-config-audit.test.js
const T = Date.parse('2026-10-20T08:00:00Z'), DAY = 86400000, iso = (d) => new Date(T - d * DAY).toISOString();
const IOS_BAD = ['hostname SW-SYN-1', 'enable password 7 <removed>', 'snmp-server community <removed> RW', 'ip http server', 'line vty 0 4', ' transport input telnet ssh', 'end'].join('\n');
const IOS_GOOD = ['hostname SW-SYN-2', 'service timestamps log datetime msec', 'service password-encryption', 'enable secret 9 <removed>', 'aaa new-model', 'aaa authentication login default group tacacs+ local', 'ip ssh version 2', 'no ip http server', 'no ip source-route',
  'snmp-server community <removed> RO 10', 'logging host 192.0.2.50', 'ntp server 192.0.2.1', 'banner login ^C Authorised use only ^C', 'line vty 0 4', ' access-class 10 in', ' exec-timeout 10 0', ' transport input ssh', 'end'].join('\n');
const dev = (id, vendor, o = {}) => Object.assign({ id, name: id.toUpperCase(), vendor, role: vendor === 'cisco-ios' ? 'access' : 'firewall', site: 'HQ', ip: '192.0.2.' + (10 + id.length), criticality: 2,
  monitoring: { snmp: 'v3 authPriv', api: vendor === 'cisco-ios' ? null : 'token set', ssh: 'set' }, polled_at: iso(0), security_at: iso(0), security_errors: [], security: [], licenses: [], config: null }, o);
const NET = { available: true, devices: [dev('sw-syn-1', 'cisco-ios', { config: { sha256: 'a'.repeat(64), at: iso(0) } }), dev('sw-syn-2', 'cisco-ios', { config: { sha256: 'b'.repeat(64), at: iso(0) } }),
  dev('sw-syn-3', 'cisco-ios', { config: { error: 'no SSH login or trusted host key - configuration not read' } }),
  dev('pa-edge', 'paloalto', { security: [{ kind: 'pa-any-any', severity: 'high', key: 'allow-all', title: 'Security rule <img src=x onerror=alert(1)> allows any', evidence: ['from trust to untrust'], rec: '' }], licenses: [{ name: 'Threat Prevention', expires: iso(10) }] })] };
const CFG = { 'sw-syn-1': IOS_BAD, 'sw-syn-2': IOS_GOOD };
const siemEvidence = async (p) => { if (p === '/audit/evidence/network') return NET; const m = /^\/audit\/evidence\/network\/config\/(.+)$/.exec(p); return m ? { text: CFG[decodeURIComponent(m[1])] } : null; };
require('./intel-harness')({ file: 'network-config-audit.html', view: 'netcfg', clockStart: T, duty: { siemEvidence } },
async (h) => {
  let p = await h.page();
  // every tile opens what it counts, named by the engine: the devices (all / not tested), the failing checks, the audit programme
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    if (zs.length) { h.ok(zs.join() === 'devices|all,devices|all,devices|not_tested,checks|fail,checks|fail,programme', 'each tile opens its list: ' + zs.join(' '));
      await p.click('#zi-hero .zi-kpi[data-zchip="not_tested"]');
      h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="devices|not_tested"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-devices').classList.contains('zi-flash'); }), 'Not tested: the devices not tested, highlighted');
      await p.click('[data-chip="devices|all"]'); } }
  h.ok(/devices meeting the standard/.test(await h.text(p, '#zi-hero')) && /Devices in scope/.test(await h.text(p, '#zi-hero')) && /not run yet/.test(await h.text(p, '#zi-hero')), 'ring and KPIs before the first run');
  h.ok(await p.$$eval('#sec-checks tbody tr', (x) => x.length >= 16 && x.every((r) => /not run yet/.test(r.textContent))), 'every check reads not run yet - none passes');
  h.ok(await p.$$eval('#sec-devices .zi-it', (x) => x.length === 4 && x.every((c) => /not run yet/.test(c.textContent))), 'devices listed, none passing');
  p.on('dialog', (d) => d.accept());
  await p.click('[data-gact="0"] button[type=submit]'); h.ok(await h.toast(p, 'Audit re-run|CY-19'), 'run the audit now');
  h.ok(await h.wait(p, () => !/not run yet/.test(document.getElementById('zi-hero').textContent)), 'KPIs refreshed after the run');
  const rows = await p.$$eval('#sec-checks tbody tr', (x) => x.map((r) => r.textContent));
  h.ok(rows.some((r) => /SSH version 2, no Telnet/.test(r) && /fails/.test(r)) && rows.some((r) => /Rule base: no any-any/.test(r) && /fails/.test(r)) && rows.some((r) => /HTTP server off/.test(r) && /fails/.test(r)), 'failing checks named');
  await p.click('[data-chip="checks|firewalls"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-checks tbody tr')].every((r) => /Firewalls/.test(r.textContent)) && document.querySelectorAll('#sec-checks tbody tr').length > 0), 'firewalls chip');
  await p.click('[data-chip="checks|fail"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-checks tbody tr')].every((r) => /fails/.test(r.textContent))), 'failing chip');
  await p.click('[data-chip="checks|all"]');
  h.ok(await h.openCard(p, 'devices', 'sw-syn-1'), 'device detail'); let d = await h.text(p, '#zi-dlgb');
  h.ok(/Findings on this device/.test(d) && /SSH version 2, no Telnet/.test(d) && /No SNMP read-write community/.test(d), 'the lines that failed'); await h.closeDlg(p);
  h.ok(await h.openCard(p, 'devices', 'sw-syn-3'), 'unread device'); d = await h.text(p, '#zi-dlgb');
  h.ok(/not counted as passing/.test(d) && /configuration not read/.test(d), 'a device that cannot be read is NOT TESTED, never passing'); await h.closeDlg(p);
  await p.click('#sec-devices [data-chip="devices|not_tested"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-devices .zi-it').length === 1 && /SW-SYN-3/.test(document.getElementById('sec-devices').textContent)), 'not tested chip');
  await p.click('#sec-devices [data-chip="devices|all"]');
  h.ok(await p.$$eval('#sec-programme .zi-it', (x) => x.length === 3), 'the three audit tests');
  h.ok(await h.openCard(p, 'devices', 'pa-edge'), 'firewall detail'); d = await h.text(p, '#zi-dlgb');
  h.ok(/Security rule/.test(d) && !(await p.$('#zi-dlgb img')), 'a hostile finding title stays text'); await h.closeDlg(p);
  h.ok(/How to read this page/.test(await h.text(p, '#sec-basis')) && /never counted as passing/.test(await h.text(p, '#sec-basis')), 'honest framing');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  h.ok(await p.$$eval('#sec-checks tbody tr', (x) => x.some((r) => /fails/.test(r.textContent))), 'a viewer reads the checks');
  h.ok((await p.$$eval('#sec-devices .zi-it', (x) => x.length)) === 0 && /operators and administrators/.test(await h.text(p, '#sec-devices')), 'a viewer sees no device');
  h.ok(!(await p.$('[data-gact]')), 'a viewer has no run button');
});
