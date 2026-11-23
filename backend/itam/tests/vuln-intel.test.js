// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Vulnerabilities + Risk Prioritization (engine/vuln-intel.js) through the real routes on SYNTHETIC records: one row per
// vulnerability across adapters (Greenbone + Tenable), primary vs max score and the primary-order setting, severity / software / OS
// charts (a host not in the register is counted as such), roles (viewer charts only, operator rows, admin settings and profiles,
// refused cases), validation errors naming the field, the audit records, the explained device risk with its factors, profiles
// (match, deactivate, catch-all protected) and the daily trend withheld below 3 days.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const col = e.app.store.collection('assets');
  const mk = (x, sw) => { const id = e.app.assets.create(Object.assign({ status: 'in_use', site: 'HQ' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), x.extra || {}, { software: sw })); return id; };
  const ids = {
    w1: mk({ name: 'SRV-SYN-1', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.1.0.1', extra: { internet_facing: true, eol: '2026-01-01', classification: 'secret' } }, [{ name: 'Mozilla Firefox 115.0', version: '115.0' }]),
    l1: mk({ name: 'SRV-SYN-2', type: 'server', os: 'Red Hat Enterprise Linux 9', mgmt_ip: '10.1.0.2' }, [{ name: 'Notepad++' }]),
    p1: mk({ name: 'PC-SYN-3', type: 'workstation', os: 'Windows 11 Enterprise', mgmt_ip: '10.1.0.3' }, [{ name: 'Mozilla Firefox 115.0' }])
  };
  const gb = e.app.store.collection('vulnscan_findings'), fc = e.app.store.collection('fc_findings');
  gb.put({ id: 'g1', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.2', cves: ['CVE-2024-6387'], score: 8.1 });
  gb.put({ id: 'g2', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.1', cves: ['CVE-2024-6387'], score: 8.1 });
  gb.put({ id: 'g3', status: 'open', name: 'Mozilla Firefox < 130 Multiple Vulnerabilities (synthetic)', severity: 'medium', host: '10.1.0.3', cves: ['CVE-2024-9392'], score: 6.1 });
  gb.put({ id: 'g4', status: 'open', name: 'TLS 1.0 enabled (synthetic)', severity: 'low', host: '10.9.9.9', cves: [] });
  gb.put({ id: 'g5', status: 'fixed', name: 'old (synthetic)', severity: 'critical', host: '10.1.0.2', cves: ['CVE-2020-0001'] });
  fc.put({ id: 'tn:0123456789abcdef0123', vendor: 'tenable', asset: '10.1.0.2', host: '10.1.0.2', title: 'OpenSSH regreSSHion (synthetic)', severity: 'critical', cvss: 9.8, cves: ['CVE-2024-6387'], status_src: 'open', first_seen: '2026-10-01' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, ids };
}

test('vulnerabilities: one row per vulnerability across adapters, primary vs max score, charts', async (t) => {
  const { call } = await setup(t);
  const r = await call('GET', '/vuln-inventory', undefined, OP); assert.equal(r.status, 200, r.text);
  const v = r.json, ssh = v.inventory.find((x) => x.cve === 'CVE-2024-6387');
  assert.deepEqual(ssh.adapters, ['tenable', 'greenbone'], 'Greenbone and Tenable reporting the same CVE are one row');
  assert.equal(ssh.devices, 2); assert.equal(ssh.severity, 'critical', 'the worst severity wins');
  assert.equal(ssh.primary_adapter, 'tenable'); assert.equal(ssh.primary_score, 9.8); assert.equal(ssh.max_score, 9.8);
  assert.ok(!v.inventory.some((x) => x.cve === 'CVE-2020-0001'), 'a fixed finding is not in the inventory');
  const ff = v.inventory.find((x) => x.cve === 'CVE-2024-9392'); assert.equal(ff.product_from, 'installed software'); assert.match(ff.product, /Mozilla Firefox/);
  assert.equal(v.by_software.find((x) => x.key === 'OpenSSH').from, 'finding title');
  assert.ok(v.by_os.some((x) => x.key === 'unregistered' && x.devices === 1), 'a host not in the register is counted as such, never guessed');
  const sev = Object.fromEntries(v.by_severity.map((x) => [x.key, x.count])); assert.equal(sev.critical, 1); assert.ok(sev.medium >= 1, 'Firefox (+ any pentest engineer finding)'); assert.equal(sev.low, 1);
  assert.equal(v.totals.multi_adapter, 1);
  const f = await call('GET', '/vuln-inventory?sev=critical', undefined, OP); assert.equal(f.json.inventory.length, 1);
  assert.equal((await call('GET', '/vuln-inventory?sev=urgent', undefined, OP)).status, 400);
  const it = await call('GET', '/vuln-inventory/item?key=CVE-2024-6387', undefined, OP); assert.equal(it.status, 200); assert.equal(it.json.devices_list.length, 2);
  assert.equal((await call('GET', '/vuln-inventory/item?key=CVE-1999-0000', undefined, OP)).status, 404);
});

test('vulnerabilities: roles, primary order setting, export audited', async (t) => {
  const { call, e } = await setup(t);
  const v = (await call('GET', '/vuln-inventory', undefined, VIEW)).json;
  assert.equal(v.inventory, undefined, 'a viewer sees charts and counts, not rows'); assert.ok(v.by_severity.length);
  assert.equal((await call('GET', '/vuln-inventory/item?key=CVE-2024-6387', undefined, VIEW)).status, 403);
  assert.equal((await call('GET', '/vuln-inventory/export', undefined, VIEW)).status, 403);
  const x = await call('GET', '/vuln-inventory/export', undefined, OP); assert.equal(x.status, 200); assert.match(x.json.csv, /CVE-2024-6387/);
  assert.equal((await call('PUT', '/vuln-inventory/settings', { primary_order: ['greenbone'] }, OP)).status, 403);
  let r = await call('PUT', '/vuln-inventory/settings', { primary_order: ['nessus'] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /primary_order/);
  r = await call('PUT', '/vuln-inventory/settings', { primary_order: ['greenbone'] }, ADM); assert.equal(r.status, 200); assert.equal(r.json.primary_order[0], 'greenbone');
  const ssh = (await call('GET', '/vuln-inventory', undefined, OP)).json.inventory.find((y) => y.cve === 'CVE-2024-6387');
  assert.equal(ssh.primary_adapter, 'greenbone'); assert.equal(ssh.primary_score, 8.1); assert.equal(ssh.max_score, 9.8, 'max is across adapters');
  const a = e.app.store.auditTail(40);
  assert.ok(a.some((y) => y.action === 'vuln.inventory.export' && y.by === 'nora.syn'));
  assert.ok(a.some((y) => y.action === 'vuln.inventory.settings' && y.by === 'syed' && y.role === 'admin'));
});

test('risk prioritization: explained device score, bands, factors, profiles', async (t) => {
  const { call, ids } = await setup(t);
  const r = await call('GET', '/risk-prioritization', undefined, OP); assert.equal(r.status, 200, r.text);
  const v = r.json, w1 = v.fix_first.find((d) => d.id === ids.w1);
  assert.equal(w1.profile, 'p-winsrv');
  const why = w1.why.map((x) => x.text).join(' | ');
  for (const k of ['internet-facing', 'past end of support', 'sensitive data', 'worst open vulnerability']) assert.match(why, new RegExp(k));
  assert.equal(w1.score, Math.min(100, w1.why.reduce((s, x) => s + x.points, 0)), 'the score is the sum of its itemised points');
  assert.equal(w1.band, 'critical');
  assert.equal(v.scored, 3); assert.equal(v.bands.reduce((s, b) => s + b.devices, 0), 3);
  const fx = Object.fromEntries(v.factors.map((x) => [x.key, x])); assert.equal(fx.internet.devices, 1); assert.equal(fx.eol.devices, 1); assert.equal(fx.sensitive.devices, 1);
  const p = Object.fromEntries(v.profiles.map((x) => [x.id, x])); assert.equal(p['p-winsrv'].devices, 1); assert.equal(p['p-linsrv'].devices, 1); assert.equal(p['p-winws'].devices, 1);
  assert.match(v.learning.note, /withheld/);
  const vv = (await call('GET', '/risk-prioritization', undefined, VIEW)).json; assert.equal(vv.fix_first, undefined, 'a viewer does not see devices'); assert.equal(vv.can_edit, false);
});

test('risk profiles: admin only, validation naming the field, deactivate, catch-all protected, audited; trend after 3 days', async (t) => {
  const { call, e } = await setup(t);
  assert.equal((await call('POST', '/risk-prioritization/profiles', { name: 'DMZ', types: ['server'], severity: 'high' }, OP)).status, 403);
  let r = await call('POST', '/risk-prioritization/profiles', { name: 'DMZ', types: ['mainframe'], severity: 'high' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /types/);
  r = await call('POST', '/risk-prioritization/profiles', { name: 'DMZ', severity: 'high' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /types or os/);
  r = await call('POST', '/risk-prioritization/profiles', { name: 'DMZ', severity: 'urgent', os: ['linux'] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /severity/);
  r = await call('POST', '/risk-prioritization/profiles', { name: 'Linux everything', os: ['linux'], severity: 'high' }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal((await call('PUT', '/risk-prioritization/profiles/p-linsrv', { active: false }, ADM)).status, 200);
  const v = (await call('GET', '/risk-prioritization', undefined, ADM)).json;
  assert.equal(v.scored, 2); assert.equal(v.inactive, 1, 'an inactive profile is not scored into the overall picture');
  assert.equal((await call('POST', '/risk-prioritization/profiles/p-other/delete', undefined, ADM)).status, 409);
  assert.equal((await call('PUT', '/risk-prioritization/profiles/p-other', { os: ['linux'] }, ADM)).status, 400);
  assert.equal((await call('PUT', '/risk-prioritization/profiles/bad!', { active: true }, ADM)).status, 400);
  assert.equal((await call('POST', '/risk-prioritization/profiles/' + r.json.profile.id + '/delete', undefined, ADM)).status, 200);
  const a = e.app.store.auditTail(40).map((x) => x.action); for (const k of ['risk.profile.create', 'risk.profile.update', 'risk.profile.delete']) assert.ok(a.includes(k), k);
  const H = e.app.store.collection('rp_hist');
  for (let i = 4; i >= 1; i--) { const d = new Date(T0 + 3 * 3600000 - i * DAY).toISOString().slice(0, 10); H.put({ id: d, day: d, at: T0 - i * DAY, total: 3, critical: 4 - i, medium: 1, low: 0 }); }
  const w = (await call('GET', '/risk-prioritization', undefined, ADM)).json; assert.equal(w.learning.days, 5); assert.equal(w.learning.note, null); assert.equal(typeof w.learning.per_week.critical, 'number');
});
