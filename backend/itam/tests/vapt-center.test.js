// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// VAPT Center (engine/vapt-center.js, pyengine/vapt_center_rules.py): every source read (Greenbone, FireCompass / Tenable, pentest),
// the same CVE on the same host merged, priority with its reasons, SLA + breach forecast, a lateral-movement path, the register's
// criticality / owner / department, daily snapshots -> new / fixed / REOPENED, the scan wizard filing ONE request through Vulnerability
// Scans (a person only, IPv4 only), nine reports (HTML escaped, CSV formula-safe), SLA settings admin-only, roles, audit. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000, T0 = Date.parse('2026-10-31T08:00:00Z');
const XSS = '<img src=x onerror="window.__x=1">';
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = T0; const requests = [];
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY });
  const d = (n) => new Date(T0 - n * DAY).toISOString().slice(0, 10);
  const gb = [{ id: 'g1', host: '10.1.1.5', hostname: 'core-sql', name: 'OpenSSH regreSSHion remote code execution', severity: 'high', score: 8.1, cves: ['CVE-2024-6387'], status: 'open', first_seen: d(40), last_seen: d(35) },
    { id: 'g2', host: '10.1.1.9', name: '=cmd|calc ' + XSS, severity: 'medium', score: 5, cves: [], status: 'open', first_seen: d(5), last_seen: d(1) },
    { id: 'g3', host: '10.1.1.12', name: 'Old TLS', severity: 'low', score: 3, cves: [], status: 'fixed', first_seen: d(60), fixed_at: new Date(T0 - 3 * DAY).toISOString() }];
  const fc = [{ id: 't1', vendor: 'tenable', host: '10.1.1.5', title: 'OpenSSH < 9.8 (regreSSHion)', severity: 'critical', cvss: 8.1, cves: ['CVE-2024-6387'], status: 'open', first_seen: d(10) },
    { id: 'f1', vendor: 'firecompass', host: '203.0.113.7', title: 'Exposed RDP with weak TLS', severity: 'high', cves: [], status: 'open', first_seen: d(20), exposure: 'external' }];
  e.app.addons.vulnscan = { findings: () => ({ items: gb }), view: () => ({ scope: { allowed: ['10.0.0.0/8'], exclude: [] } }), request: async (b, who) => { requests.push({ b, who }); return { id: 'SCAN-001', status: 'waiting_approval' }; } };
  e.app.addons.vaptStudio = { view: async () => ({ findings: fc }) };
  e.app.addons.pentest = { view: () => ({ findings: [{ id: 'p1', asset: 'WEB-01', ip: '203.0.113.8', title: 'Directory listing', severity: 'medium', status: 'open', internet: true, at: d(3) }] }),
    cadence: { schedule: () => [{ asset: 'CORE-DB', ip: '10.1.1.20', worst: 'overdue', tier: 'critical' }, { asset: 'PRINTER', ip: '10.9.9.9', worst: 'ok' }] } };
  e.app.store.collection('assets').put({ id: 'a1', name: 'CORE-SQL', mgmt_ip: '10.1.1.5', owner: 'DBA team', department: 'IT', tags: ['business-critical'], status: 'active' });
  e.app.store.collection('assets').put({ id: 'a2', name: 'DMZ-DB', mgmt_ip: '203.0.113.20', tags: ['crown-jewel'], status: 'active' });
  return { e, requests, at: (t2) => { clock = t2; }, gb };
}

test('analysis: merged sources, priority with reasons, SLA, lateral path, register enrichment, roles', async (t) => {
  const { e } = await setup(t);
  assert.equal((await e.req('GET', '/vapt-center', VW)).status, 403, 'vulnerability details name internal hosts: operators only');
  const v = (await e.req('GET', '/vapt-center', OP)).json;
  assert.ok(v.ok, JSON.stringify(v).slice(0, 300));
  const ssh = v.findings.find((f) => f.key === '10.1.1.5|CVE-2024-6387');
  assert.deepEqual(ssh.sources, ['greenbone', 'tenable'], 'the same CVE on the same host from two sources is ONE row');
  assert.equal(ssh.severity, 'critical'); assert.equal(ssh.criticality, 'critical'); assert.equal(ssh.owner, 'DBA team'); assert.equal(ssh.department, 'IT');
  assert.ok(ssh.why.some((w) => /known-exploited|remote code execution/.test(w.text)) && ssh.why.some((w) => /confirmed by 2 sources/.test(w.text)) && ssh.why.some((w) => /past its 15-day SLA/.test(w.text)));
  assert.equal(v.findings[0].key, ssh.key, 'highest priority first');
  assert.equal(v.duplicates_merged, 1); assert.equal(v.open, 4, 'ssh (merged), the medium, RDP, the pentest finding'); assert.equal(v.counts.critical, 1);
  assert.ok(v.sla.breached >= 1);
  assert.ok(v.paths.some((p) => p.from === '203.0.113.7' && p.to === 'DMZ-DB'), 'internet-facing vulnerable host next to a business-critical asset');
  assert.deepEqual(Object.keys(v.sources).sort(), ['greenbone', 'pentest', 'vapt']); assert.ok(Object.values(v.sources).every((x) => x.ok));
  // scan suggestions: cadence overdue + retest of a high finding not rescanned for 30 days
  assert.ok(v.suggestions.items.some((x) => x.target === '10.1.1.20' && /overdue/.test(x.why)));
  assert.ok(v.suggestions.items.some((x) => x.target === '10.1.1.5' && /retest/.test(x.why)));
  assert.ok(!v.suggestions.items.some((x) => x.target === '10.9.9.9'), 'an asset tested on time is not proposed');
});

test('snapshots: new / fixed / reopened (a regression) since the previous day', async (t) => {
  const { e, at, gb } = await setup(t);
  assert.equal((await e.req('POST', '/vapt-center/snapshot', Object.assign({ body: {} }, OP))).status, 403);
  // day 1: the low TLS finding is open; day 2: it is fixed; day 3: it is back
  gb[2].status = 'open'; delete gb[2].fixed_at; at(T0 - 2 * DAY);
  assert.equal((await e.req('POST', '/vapt-center/snapshot', Object.assign({ body: {} }, ADM))).status, 200);
  gb[2].status = 'fixed'; gb[2].fixed_at = new Date(T0 - DAY).toISOString(); at(T0 - DAY);
  await e.req('POST', '/vapt-center/snapshot', Object.assign({ body: {} }, ADM));
  gb[2].status = 'open'; delete gb[2].fixed_at; at(T0);
  const v = (await e.req('GET', '/vapt-center', OP)).json;
  assert.ok(v.delta.reopened.includes('10.1.1.12|old tls'), 'fixed yesterday, open again today = a regression');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'vapt.center.snapshot' && x.by === 'syed'));
});

test('scan wizard: one request through Vulnerability Scans, a person only, IPv4 only; SLA admin-only and ordered', async (t) => {
  const { e, requests } = await setup(t);
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who));
  assert.equal((await post('/vapt-center/scan', { targets: ['10.1.1.20'] }, VW)).status, 403);
  assert.equal((await post('/vapt-center/scan', { targets: ['10.1.1.20'] }, { user: 'svc:bot', role: 'operator' })).status, 403);
  let r = await post('/vapt-center/scan', { targets: ['core-db.local'] }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /not an IPv4 address/);
  r = await post('/vapt-center/scan', { targets: ['10.1.1.20', '10.1.1.5'], profile: 'full', hours: 3, reason: 'quarterly retest (synthetic)' }, OP);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.request.status, 'waiting_approval'); assert.match(r.json.note, /different named person approves/);
  assert.equal(requests.length, 1); assert.deepEqual(requests[0].b.targets, ['10.1.1.20', '10.1.1.5']); assert.equal(requests[0].who.user, 'nora.syn');
  assert.equal(Date.parse(requests[0].b.window_end) - Date.parse(requests[0].b.window_start), 3 * 3600000);
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'vapt.center.scan' && x.by === 'nora.syn' && x.detail.targets === 2));
  assert.equal((await post('/vapt-center/sla', { critical: 7 }, OP)).status, 403);
  r = await post('/vapt-center/sla', { critical: 60, high: 30 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /must not shorten/);
  r = await post('/vapt-center/sla', { critical: 7 }, ADM); assert.equal(r.status, 200); assert.equal(r.json.days.critical, 7);
});

test('reports: nine kinds, HTML escaped, CSV formula-safe, compliance mapping, audited', async (t) => {
  const { e } = await setup(t);
  const get = (k, f) => e.req('GET', '/vapt-center/reports/' + k + '?format=' + f, OP);
  for (const k of ['executive', 'technical', 'asset', 'owner', 'department', 'compliance', 'sla', 'delta', 'retest']) {
    const h = await get(k, 'html'); assert.equal(h.status, 200, k + ' ' + h.raw); assert.ok(h.json.html.startsWith('<!doctype html>'), k);
    const c = await get(k, 'csv'); assert.equal(c.status, 200, k); assert.match(c.json.filename, new RegExp('^vapt-' + k + '-\\d{4}-\\d{2}-\\d{2}\\.csv$'));
  }
  const tech = (await get('technical', 'html')).json.html; assert.ok(!tech.includes('<img src=x') && tech.includes('&lt;img src=x'), 'a hostile title is escaped');
  assert.ok((await get('technical', 'csv')).json.csv.includes('"\'=cmd|calc'), 'a cell starting with = is neutralised');
  const comp = (await get('compliance', 'html')).json.html; assert.match(comp, /NCA ECC/); assert.match(comp, /2-10 Vulnerabilities Management/); assert.match(comp, /gap/);
  assert.equal((await get('everything', 'html')).status, 404); assert.equal((await get('technical', 'pdf')).status, 400);
  assert.equal((await e.req('GET', '/vapt-center/reports/technical?format=html', VW)).status, 403);
  assert.ok(e.app.store.auditTail(60).filter((x) => x.action === 'vapt.center.report').length >= 18);
});
