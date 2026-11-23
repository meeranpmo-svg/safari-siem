// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scanned Assets (engine/scanned-assets.js) through the real routes on SYNTHETIC records (hosts / findings ending .syn / SYN):
// one asset per register record a scanner reported, matched by asset id / IP / name (and saying how); the same vulnerability from
// Greenbone and Tenable on one asset is one finding; the stated risk rule (severity / CVSS, known-exploited, criticality);
// oldest age, overdue by the VAPT Center SLA, fixed in 30 days, scanners and last scan; coverage (in the approved scope and never /
// stale scanned, unknown hosts); roles (viewer refused, operator reads and exports, admin settings, a service identity refused),
// validation errors naming the field, the audit records; and the empty / not-installed states (nothing fabricated).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const SA = require('../engine/scanned-assets');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000, D = (n) => new Date(T0 - n * DAY).toISOString();
const HOSTILE = '<img src=x onerror=alert(1)>.syn';

async function setup(t, { seed = true } = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  if (!e.app.addons.scannedAssets) SA.registerScannedAssets(e.app.srv, e.app, SA.createScannedAssets(e.app, { now: () => T0 }));
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const ids = {};
  if (seed) {
    const col = e.app.store.collection('assets');
    const mk = (x, extra) => { const id = e.app.assets.create(Object.assign({ status: 'in_use' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), extra || {})); return id; };
    ids.s1 = mk({ name: 'SRV-SYN-1', type: 'server', mgmt_ip: '10.20.0.1', site: 'HQ-SYN', owner: 'owner.syn', department: 'Finance SYN' }, { tags: ['business-critical'] });
    ids.s2 = mk({ name: 'SRV-SYN-2', type: 'server', mgmt_ip: '10.20.0.2', site: 'DR-SYN', owner: 'other.syn' }, { criticality: 'low' });
    ids.p3 = mk({ name: 'PC-SYN-3', type: 'workstation', mgmt_ip: '10.20.0.3', site: 'HQ-SYN' });
    ids.p4 = mk({ name: 'PC-SYN-4', type: 'workstation', mgmt_ip: '10.20.0.4', site: 'HQ-SYN' });
    ids.d5 = mk({ name: 'DMZ-SYN-5', type: 'server', site: 'HQ-SYN' });
    e.app.store.collection('vulnscan').put({ id: 'scope', allowed: ['10.20.0.0/24'], exclude: [] });
    const res = e.app.store.collection('vulnscan_results');
    res.put({ id: 'scan-syn-1', hosts: ['10.20.0.1', '10.20.0.2', '10.20.0.99'], findings: [], at: D(2) });
    res.put({ id: 'scan-syn-0', hosts: ['10.20.0.4'], findings: [], at: D(60) });
    const gb = e.app.store.collection('vulnscan_findings');
    gb.put({ id: 'g1', status: 'open', name: 'Example Server Overflow (synthetic)', severity: 'critical', host: '10.20.0.1', hostname: 'srv-syn-1', cves: ['CVE-2099-0001'], score: 9.8, first_seen: D(40), last_seen: D(2) });
    gb.put({ id: 'g2', status: 'open', name: 'Example Daemon remote code execution (synthetic)', severity: 'high', host: '10.20.0.1', cves: [], score: 7.5, first_seen: D(5), last_seen: D(2) });
    gb.put({ id: 'g3', status: 'fixed', name: 'Old Library Flaw (synthetic)', severity: 'medium', host: '10.20.0.2', cves: ['CVE-2099-0002'], score: 5, first_seen: D(50), last_seen: D(10), fixed_at: D(3) });
    gb.put({ id: 'g4', status: 'open', name: 'TLS 1.0 enabled (synthetic)', severity: 'low', host: '10.20.0.2', cves: [], score: 2.6, first_seen: D(10), last_seen: D(2) });
    gb.put({ id: 'g5', status: 'open', name: 'Unknown Host Weakness (synthetic)', severity: 'high', host: '10.20.0.99', hostname: HOSTILE, cves: ['CVE-2099-0005'], score: 8, first_seen: D(3), last_seen: D(2) });
    const fc = e.app.store.collection('fc_findings');
    fc.put({ id: 'tn:0123456789abcdef0001', vendor: 'tenable', asset: '10.20.0.1', host: '10.20.0.1', title: 'Example Server Overflow (synthetic)', severity: 'critical', cvss: 9.8, cves: ['CVE-2099-0001'], status_src: 'open', first_seen: '2026-10-01' });
    fc.put({ id: 'tn:0123456789abcdef0003', vendor: 'tenable', asset: 'dmz-syn-5.corp.syn', host: 'dmz-syn-5.corp.syn', title: 'Example Web Server Disclosure (synthetic)', severity: 'medium', cvss: 5.3, cves: ['CVE-2099-0003'], status_src: 'open', first_seen: '2026-11-01' });
  }
  return { e, call, ids };
}
const byName = (v, n) => v.assets.find((a) => a.asset && a.asset.name === n);

test('scanned assets: matched to the register, deduplicated findings, the stated risk rule, SLA, coverage', async (t) => {
  const { call, ids } = await setup(t);
  const r = await call('GET', '/scanned-assets', undefined, OP); assert.equal(r.status, 200, r.text);
  const v = r.json;
  assert.match(v.risk_rule, /critical 10, high 5, medium 2, low 0\.5/); assert.match(v.risk_rule, /EPSS is not/); assert.match(v.match_rule, /asset id.*IP.*name/);
  const s1 = byName(v, 'SRV-SYN-1');
  assert.equal(s1.match.by, 'IP'); assert.equal(s1.asset.owner, 'owner.syn'); assert.equal(s1.asset.site, 'HQ-SYN'); assert.equal(s1.criticality, 'critical', 'critical tag = critical');
  assert.ok(s1.open.critical >= 1 && s1.open.high >= 1);
  const one = (await call('GET', '/scanned-assets/' + s1.id, undefined, OP)).json;
  const ov = one.findings.filter((f) => f.key === 'CVE-2099-0001');
  assert.equal(ov.length, 1, 'Greenbone and Tenable reporting the same CVE on one asset are ONE finding');
  assert.deepEqual(ov[0].scanners.sort(), ['Greenbone', 'Tenable']);
  assert.equal(ov[0].sla_state, 'overdue', '40 days open against the 15-day critical SLA'); assert.equal(ov[0].sla_days, 15);
  const rce = one.findings.find((f) => /remote code execution/.test(f.title)); assert.equal(rce.known_exploited, true); assert.equal(rce.points, 7.5, 'high 5 x 1.5 known-exploited / RCE');
  assert.equal(rce.sla_state, 'within');
  const synPts = one.findings.filter((f) => f.status === 'open').reduce((x, f) => x + f.points, 0);
  assert.equal(s1.risk, Math.round(synPts * 2 * 10) / 10, 'risk = sum of finding points x criticality 2');
  assert.ok(s1.oldest_open_days >= 40); assert.ok(s1.overdue >= 1); assert.equal(s1.last_scan, D(2)); assert.ok(s1.scanners.includes('Greenbone') && s1.scanners.includes('Tenable'));
  assert.equal(v.assets[0].id, s1.id, 'the riskiest asset first'); assert.equal(v.riskiest[0].id, s1.id);
  const s2 = byName(v, 'SRV-SYN-2'); assert.equal(s2.fixed_30d, 1, 'fixed 3 days ago'); assert.equal(s2.criticality, 'low'); assert.equal(s2.risk_multiplier, 0.75);
  const d5 = byName(v, 'DMZ-SYN-5'); assert.equal(d5.match.by, 'name', 'matched by its short name (dmz-syn-5.corp.syn)'); assert.ok(d5.open.medium >= 1, 'the Tenable finding (+ the pentest engineer\'s own)');
  const d5f = (await call('GET', '/scanned-assets/' + d5.id, undefined, OP)).json.findings;
  assert.ok(d5f.some((f) => f.key === 'CVE-2099-0003'));
  const nofs = d5f.find((f) => f.status === 'open' && !f.first_seen); if (nofs) assert.equal(nofs.sla_state, 'not judged', 'no first-seen date: overdue not judged');
  // unknown host: listed, hostile name kept as data
  const unk = v.assets.find((a) => !a.registered && a.ip === '10.20.0.99'); assert.ok(unk); assert.equal(unk.match, null); assert.ok(unk.names.includes(HOSTILE));
  assert.ok(v.coverage.unknown.some((u) => u.ip === '10.20.0.99'));
  // coverage: in the approved scope, never scanned (PC-SYN-3) / stale (PC-SYN-4, 60 days > 30)
  assert.ok(v.coverage.never.some((x) => x.asset_id === ids.p3)); assert.ok(!v.coverage.never.some((x) => x.asset_id === ids.s1));
  const st = v.coverage.stale.find((x) => x.asset_id === ids.p4); assert.ok(st); assert.equal(st.days, 60);
  assert.ok(!v.coverage.never.some((x) => x.asset_id === ids.d5), 'no address in the scope: not judged');
  assert.equal(v.sla.days.critical, 15); assert.match(v.sla.from, /VAPT Center/);
  assert.equal(v.totals.never_scanned, v.coverage.never.length);
  // filters
  assert.ok((await call('GET', '/scanned-assets?site=DR-SYN', undefined, OP)).json.assets.every((a) => a.asset && a.asset.site === 'DR-SYN'));
  assert.ok((await call('GET', '/scanned-assets?sev=critical', undefined, OP)).json.assets.every((a) => a.open.critical > 0));
  assert.ok((await call('GET', '/scanned-assets?scanner=tenable', undefined, OP)).json.assets.every((a) => a.scanners.includes('Tenable')));
  assert.deepEqual((await call('GET', '/scanned-assets?criticality=low', undefined, OP)).json.assets.map((a) => a.asset.name), ['SRV-SYN-2']);
  assert.deepEqual((await call('GET', '/scanned-assets?owner=owner.syn', undefined, OP)).json.assets.map((a) => a.asset.name), ['SRV-SYN-1']);
  assert.ok((await call('GET', '/scanned-assets?q=CVE-2099-0003', undefined, OP)).json.assets.some((a) => a.id === d5.id));
  // stale_days moves the stale line
  assert.equal((await call('POST', '/scanned-assets/settings', { stale_days: 90 }, ADM)).status, 200);
  assert.ok(!(await call('GET', '/scanned-assets', undefined, OP)).json.coverage.stale.some((x) => x.asset_id === ids.p4), '60 days is not stale at 90');
});

test('scanned assets: roles, validation, audit', async (t) => {
  const { call, e } = await setup(t);
  for (const p of ['/scanned-assets', '/scanned-assets/export', '/scanned-assets/h.0123456789abcdef']) assert.equal((await call('GET', p, undefined, VIEW)).status, 403, 'a viewer is refused ' + p);
  let r = await call('GET', '/scanned-assets?sev=urgent', undefined, OP); assert.equal(r.status, 400); assert.match(r.text, /sev/);
  r = await call('GET', '/scanned-assets?criticality=extreme', undefined, OP); assert.equal(r.status, 400); assert.match(r.text, /criticality/);
  r = await call('GET', '/scanned-assets?scanner=nessus', undefined, OP); assert.equal(r.status, 400); assert.match(r.text, /scanner/);
  r = await call('GET', '/scanned-assets?q=' + 'x'.repeat(200), undefined, OP); assert.equal(r.status, 400); assert.match(r.text, /q is longer/);
  assert.equal((await call('GET', '/scanned-assets/bad%20id', undefined, OP)).status, 400);
  assert.equal((await call('GET', '/scanned-assets/x.123', undefined, OP)).status, 400);
  assert.equal((await call('GET', '/scanned-assets/h.0123456789abcdef', undefined, OP)).status, 404);
  const x = await call('GET', '/scanned-assets/export?site=HQ-SYN', undefined, OP); assert.equal(x.status, 200, x.text);
  assert.match(x.json.filename, /^scanned-assets-2026-11-08\.xlsx$/); assert.ok(x.json.assets.length >= 1); assert.ok(x.json.findings.some((f) => f[3] === 'CVE-2099-0001'));
  assert.match(x.json.filter, /site=HQ-SYN/);
  assert.equal((await call('POST', '/scanned-assets/settings', { stale_days: 10 }, OP)).status, 403, 'an operator cannot change the setting');
  r = await call('POST', '/scanned-assets/settings', { stale_days: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.text, /stale_days/);
  r = await call('POST', '/scanned-assets/settings', { stale_days: 'soon' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /stale_days/);
  r = await call('POST', '/scanned-assets/settings', {}, ADM); assert.equal(r.status, 400); assert.match(r.text, /stale_days is required/);
  r = await call('POST', '/scanned-assets/settings', { stale_days: 45 }, { user: 'svc:bot', role: 'admin' }); assert.equal(r.status, 403, 'a service identity does not change settings');
  r = await call('POST', '/scanned-assets/settings', { stale_days: 45, by: 'someone.else', evil: 1 }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.stale_days, 45); assert.equal(r.json.by, 'syed', 'undeclared fields are dropped');
  assert.equal((await call('GET', '/scanned-assets', undefined, OP)).json.settings.stale_days, 45);
  const a = e.app.store.auditTail(60);
  const ex = a.find((y) => y.action === 'scanned.assets.export'); assert.ok(ex); assert.equal(ex.by, 'nora.syn'); assert.equal(ex.role, 'operator'); assert.match(ex.detail.filter, /site=HQ-SYN/);
  const st = a.find((y) => y.action === 'scanned.assets.settings'); assert.ok(st); assert.equal(st.by, 'syed'); assert.equal(st.role, 'admin'); assert.deepEqual([st.detail.from, st.detail.to], [30, 45]);
});

test('scanned assets: asset-id match, not-installed and empty states say what to connect', async (t) => {
  const { e } = await setup(t, { seed: false });
  const id = e.app.assets.create({ name: 'APP-SYN-7', type: 'server', status: 'in_use' }, ADM).asset.id;
  // a stub VAPT Center (the pentest engineer carries the register id) - SYNTHETIC
  const stub = { store: e.app.store, audit: e.app.audit, addons: { vaptCenter: { gather: async () => ({ status: { pentest: { ok: true } }, findings: [{ src: 'pentest', asset_id: id, host: 'app-syn-7-other.syn', asset: 'App label', title: 'Weak admin panel (synthetic)', severity: 'high', cves: [], status: 'open', first_seen: D(1) }] }), slaDays: () => ({ critical: 15, high: 30, medium: 90, low: 180 }) } } };
  const S = SA.createScannedAssets(stub, { now: () => T0 });
  let v = await S.view(OP);
  assert.equal(v.assets.length, 1); assert.equal(v.assets[0].match.by, 'asset id'); assert.equal(v.assets[0].asset.name, 'APP-SYN-7');
  assert.equal(v.coverage.note.includes('no approved scan scope'), true, 'no scope: never / stale is not judged and says so');
  // a gather that fails is reported, not hidden
  stub.addons.vaptCenter.gather = async () => { throw new Error('synthetic failure'); };
  v = await S.view(OP); assert.equal(v.sources.vapt_center.ok, false); assert.match(v.empty, /connect Greenbone/);
  // no VAPT Center at all: overdue is not judged, and the source says what to install
  const S2 = SA.createScannedAssets({ store: e.app.store, addons: {} }, { now: () => T0 });
  v = await S2.view(OP);
  assert.equal(v.sla.days, null); assert.match(v.sla.note, /not judged/); assert.equal(v.totals.overdue, null);
  assert.match(v.sources.vapt_center.error, /not installed/); assert.equal(v.assets.length, 0); assert.match(v.empty, /No scan results yet/);
});
