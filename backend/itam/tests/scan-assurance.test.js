// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scan Coverage Assurance (engine/scan-assurance.js) with SYNTHETIC assets and scans: every connected asset gets one status and,
// when not scanned, one reason with its fix (no IP, no scanner, out of scope, rejected, failed / expired, cut short, blocked by a
// firewall vs offline, stale, never scanned); fragile and excluded devices are "left out on purpose", never failures; a device that
// did not answer is never counted as scanned; persistent failures; the rescan batches are filed in Vulnerability Scans by a person
// (a service identity is refused) and then show as pending; the coverage report (escaped, audited); the VAPT targets view; roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'net.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:scanner', role: 'admin' };
const DAY = 86400000, XSS = '<img src=x onerror=alert(1)>';

test('Scan Coverage Assurance: status, reason and fix per connected asset; rescan prepared and filed', async (t) => {
  let T = Date.parse('2026-11-22T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const c = (n) => e.app.store.collection(n), iso = (d) => new Date(T - d * DAY).toISOString();
  const A = (id, name, ip, extra) => c('assets').put(Object.assign({ id, name, type: 'server', status: 'active', mgmt_ip: ip }, extra || {}));
  A('ok', 'srv-ok ' + XSS, '10.0.5.10'); A('noip', 'srv-noip', null); A('out', 'srv-out', '10.9.0.5'); A('rej', 'srv-rej', '10.0.5.20'); A('fail', 'srv-fail', '10.0.5.30');
  A('cut', 'srv-cut', '10.0.5.40'); A('blk', 'srv-blk', '10.0.5.50'); A('off', 'srv-off', '10.0.5.60'); A('old', 'srv-old', '10.0.5.70'); A('new', 'srv-new', '10.0.5.80');
  A('prn', 'Floor MFP', '10.0.5.90', { type: 'printer' }); A('exc', 'srv-excluded', '10.0.5.99');
  // no Greenbone connection yet: everything assessable reads "no scanner"
  let v = (await call('GET', '/scan-assurance', undefined, OP)).json;
  assert.equal(v.assets.find((r) => r.asset_id === 'new').reason, 'no_scanner'); assert.equal(v.assets.find((r) => r.asset_id === 'noip').reason, 'no_ip');
  assert.equal(v.assets.find((r) => r.asset_id === 'prn').status, 'excluded', 'a fragile device is left out on purpose, not a failure');
  c('vulnscan').put({ id: 'cfg', socket: '/run/syn.sock', username: 'syn' });
  assert.equal((await call('PUT', '/vulnscan/scope', { allowed: ['10.0.5.0/24'], exclude: ['10.0.5.99'] }, ADM)).status, 200);
  const S = (id, state, targets, extra) => c('vulnscan_scans').put(Object.assign({ id, name: id, targets, exclude: [], state, requested_at: iso(5), finished_at: ['done', 'stopped'].includes(state) ? iso(4) : null }, extra || {}));
  S('VS-1', 'done', ['10.0.5.10', '10.0.5.50', '10.0.5.60']); c('vulnscan_results').put({ id: 'VS-1', hosts: ['10.0.5.10'], at: iso(4) });
  S('VS-2', 'rejected', ['10.0.5.20'], { decision_note: 'not in the change window' });
  S('VS-3', 'failed', ['10.0.5.30'], { error: 'gvmd: scanner unavailable' });
  S('VS-4', 'stopped', ['10.0.5.40'], { partial: true, stop_reason: 'the approved window ended' }); c('vulnscan_results').put({ id: 'VS-4', hosts: [], at: iso(4) });
  S('VS-0', 'done', ['10.0.5.70'], { finished_at: iso(60) }); c('vulnscan_results').put({ id: 'VS-0', hosts: ['10.0.5.70'], at: iso(60) });
  c('disc_devices').put({ id: 'D1', ips: ['10.0.5.50'], last_seen: iso(3), status: 'approved' });   // answered discovery, not the scanner
  // the first daily snapshot, then evaluate
  e.app.addons.scanAssurance.snapshot(); T += DAY;
  let r = await call('GET', '/scan-assurance', undefined, OP); assert.equal(r.status, 200, r.text); v = r.json;
  const st = (id) => v.assets.find((x) => x.asset_id === id);
  assert.equal(st('ok').status, 'scanned'); assert.equal(st('ok').tool, 'Greenbone VS-1');
  const want = { noip: 'no_ip', out: 'out_of_scope', rej: 'rejected', fail: 'scan_failed', cut: 'cut_short', blk: 'blocked', off: 'offline', old: 'stale', new: 'never_scanned' };
  for (const [id, reason] of Object.entries(want)) { assert.equal(st(id).status, 'failed', id); assert.equal(st(id).reason, reason, id + ': ' + st(id).reason); assert.ok(st(id).fix.length > 10, id + ' has a fix'); }
  assert.match(st('rej').detail, /change window/); assert.match(st('fail').detail, /scanner unavailable/); assert.match(st('blk').fix, /firewall/); assert.match(st('out').fix, /scan scope/);
  assert.equal(st('exc').status, 'excluded'); assert.equal(st('prn').status, 'excluded');
  assert.ok(st('new').persistent, 'failed in the previous snapshot too: persistent'); assert.equal(v.assets[0].persistent, true, 'persistent failures listed first');
  assert.equal(v.kpis.connected, 12); assert.equal(v.kpis.scanned, 1); assert.equal(v.kpis.excluded, 2); assert.equal(v.kpis.coverage, 10, '1 scanned of 10 assessable');
  assert.deepEqual(v.scope_proposal, ['10.9.0.0/24']);
  assert.deepEqual(v.rescan.batches[0].targets, ['10.0.5.30', '10.0.5.40', '10.0.5.50', '10.0.5.70', '10.0.5.80'], 'only what a rescan fixes: failed, cut short, blocked, stale, never');
  // roles and validation
  assert.equal((await call('GET', '/scan-assurance', undefined, VIEW)).status, 403);
  assert.equal((await call('POST', '/scan-assurance/rescan', {}, BOT)).status, 403, 'a service identity never files a scan');
  assert.equal((await call('POST', '/scan-assurance/settings', { stale_days: 3 }, ADM)).status, 400);
  assert.equal((await call('POST', '/scan-assurance/settings', { stale_days: 30 }, OP)).status, 403);
  // a person files the rescan: it lands in Vulnerability Scans as a request and the assets show as pending
  r = await call('POST', '/scan-assurance/rescan', { hours: 4 }, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.filed.length, 1); assert.match(r.json.filed[0].scan, /^VS-/);
  const req = c('vulnscan_scans').get(r.json.filed[0].scan); assert.equal(req.state, 'requested'); assert.equal(req.requested_by, 'net.syn'); assert.match(req.reason, /Scan Coverage Assurance/);
  v = (await call('GET', '/scan-assurance', undefined, OP)).json; assert.equal(v.assets.find((x) => x.asset_id === 'new').status, 'pending');
  assert.equal((await call('POST', '/scan-assurance/rescan', {}, OP)).status, 409, 'nothing left to rescan');
  // report: escaped, audited
  r = await call('GET', '/scan-assurance/report?format=html', undefined, OP); assert.equal(r.status, 200);
  assert.ok(!r.json.html.includes(XSS) && r.json.html.includes('&lt;img'), 'escaped'); assert.match(r.json.html, /Why assets were not scanned/); assert.match(r.json.html, /Outside the internal scan scope/);
  r = await call('GET', '/scan-assurance/report?format=csv', undefined, OP); assert.match(r.json.csv, /srv-out/);
  assert.equal((await call('GET', '/scan-assurance/report?format=pdf', undefined, OP)).status, 400);
  const au = e.app.store.auditTail(100).filter((a) => /^scanassure\./.test(a.action));
  assert.ok(au.some((a) => a.action === 'scanassure.rescan' && a.by === 'net.syn')); assert.ok(au.some((a) => a.action === 'scanassure.report'));
  // VAPT Workflow: coverage of an engagement's targets
  const cov = e.app.addons.scanAssurance.forTargets(['10.0.5.0/24', 'portal.syn.local']);
  assert.equal(cov.assets, 10); assert.equal(cov.scanned, 1); assert.ok(cov.rows.some((x) => /rejected/.test(x.why) || x.status === 'pending'));
});
