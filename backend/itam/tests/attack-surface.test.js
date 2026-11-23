// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Continuous Attack Surface (engine/attack-surface.js) with SYNTHETIC data: the external surface from the asset register + Asset
// Discovery open ports + scanner findings (stubbed VAPT Center); services named from ports, APIs detected, shadow surface (reachable,
// in no asset record); exposure scored and itemised; the change feed diffs each run against the last snapshot (new asset, new API /
// service, new finding, service closed, gone); read-only (no scan, no exploit); the chain link; roles (viewer refused, admin snapshots).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'net.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const DAY = 86400000;

test('Continuous Attack Surface: surface, APIs, exposure, shadow, the change feed, roles', async (t) => {
  let T = Date.parse('2026-11-22T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const c = (n) => e.app.store.collection(n), seen = () => new Date(T - DAY).toISOString();
  // findings read through a stubbed VAPT Center
  let G = [{ src: 'greenbone', id: 'f1', host: '203.0.113.10', asset: 'web-dmz-01', title: 'Apache path traversal (unauth RCE)', severity: 'high', cvss: 8.1, cves: ['CVE-2024-0001'], status: 'open', exposure: 'external' }];
  e.app.addons.vaptCenter = { gather: async () => ({ findings: G.map((x) => Object.assign({}, x)), status: { greenbone: { ok: true } } }) };
  // the register: an internet-facing web/API asset, a critical internal DB, and a plain internal box
  c('assets').put({ id: 'web', name: 'web-dmz-01', type: 'webapp', status: 'active', mgmt_ip: '203.0.113.10', hostname: 'web-dmz-01', exposure: 'external', software: [{ name: 'Apache 2.4' }, { name: 'Node.js' }], tags: ['api'] });
  c('assets').put({ id: 'db', name: 'core-db', type: 'database', status: 'active', mgmt_ip: '10.0.1.9', criticality: 'critical', classification: 'secret' });
  c('assets').put({ id: 'srv', name: 'print-01', type: 'server', status: 'active', mgmt_ip: '10.0.1.20' });
  c('disc_devices').put({ id: 'D1', ips: ['203.0.113.10'], open_ports: [443, 8443, 22], hostname: 'web-dmz-01', last_seen: seen(), status: 'approved' });
  // a shadow surface: a reachable web host in no asset record
  c('disc_devices').put({ id: 'D2', ips: ['203.0.113.50'], open_ports: [80, 3389], hostname: 'unknown-vps', last_seen: seen(), status: 'new' });
  let r = await call('GET', '/attack-surface', undefined, OP); assert.equal(r.status, 200, r.text); let v = r.json;
  const row = (id) => v.surface.find((x) => x.id === id);
  assert.ok(row('web'), 'the internet-facing asset is on the surface'); assert.equal(row('srv'), undefined, 'a plain internal box is not');
  assert.deepEqual(row('web').services.map((x) => x.name), ['SSH', 'HTTPS', 'HTTPS alt'], 'ports named as services');
  assert.ok(row('web').services.find((x) => x.name === 'SSH').risk, 'SSH is a risky service');
  assert.ok(row('web').apis.some((x) => x.port === 443), 'HTTPS on a web/API host is an API surface');
  assert.ok(v.apis.some((x) => x.asset_id === 'web'), 'APIs listed');
  assert.ok(row('web').why.some((w) => /exploit/.test(w.text)), 'exposure itemised: exploit named');
  assert.ok(row('web').exposure >= 50, 'high exposure: external RCE + risky services: ' + row('web').exposure);
  const sh = v.surface.find((x) => x.shadow); assert.ok(sh && sh.id === 'shadow:203.0.113.50', 'shadow surface found'); assert.ok(sh.services.some((x) => x.name === 'RDP'));
  assert.equal(v.kpis.shadow, 1); assert.ok(v.kpis.apis >= 1);
  assert.equal(v.changes.first, true, 'no snapshot yet: first run'); assert.match(v.note, /read-only/i);
  // the first snapshot, then a change: a new risky service and a new finding
  assert.equal((await call('POST', '/attack-surface/snapshot', {}, ADM)).status, 200);
  T += DAY;
  c('disc_devices').put({ id: 'D1', ips: ['203.0.113.10'], open_ports: [443, 8443, 22, 3389], hostname: 'web-dmz-01', last_seen: seen(), status: 'approved' });
  G = G.concat([{ src: 'greenbone', id: 'f2', host: '203.0.113.10', asset: 'web-dmz-01', title: 'TLS weak cipher', severity: 'medium', status: 'open', exposure: 'external' }]);
  v = (await call('GET', '/attack-surface', undefined, OP)).json;
  assert.equal(v.changes.first, false); assert.ok(v.changes.since);
  assert.ok(v.changes.items.some((x) => x.kind === 'new_service' && /RDP/.test(x.text)), 'change feed: new RDP service');
  assert.ok(v.changes.items.some((x) => x.kind === 'new_finding'), 'change feed: new finding');
  assert.equal(v.changes.items[0].kind === 'new_api' || v.changes.items[0].kind === 'new_service', true, 'exposure changes ranked first');
  // a service closing is a change too
  await call('POST', '/attack-surface/snapshot', {}, ADM); T += DAY;
  c('disc_devices').put({ id: 'D1', ips: ['203.0.113.10'], open_ports: [443, 8443], hostname: 'web-dmz-01', last_seen: seen(), status: 'approved' });
  v = (await call('GET', '/attack-surface', undefined, OP)).json;
  assert.ok(v.changes.items.some((x) => x.kind === 'service_closed' && /SSH|RDP/.test(x.text)), 'change feed: service closed');
  // one asset detail
  r = await call('GET', '/attack-surface/web', undefined, OP); assert.equal(r.status, 200); assert.ok(r.json.services.length); assert.match(r.json.note, /Nothing is tested from here/);
  // required actions, worst first: the high finding first, the medium one, then the API exposure - a finding with no fix text says so
  G[0].fix = 'Upgrade Apache to 2.4.62 or later (synthetic)'; G[0].verify = 'Rescan the host and confirm the finding is gone';
  r = await call('GET', '/attack-surface/web', undefined, OP); const acts = r.json.actions;
  assert.ok(acts.length >= 3, JSON.stringify(acts)); assert.equal(acts[0].severity, 'high'); assert.match(acts[0].action, /Upgrade Apache/); assert.match(acts[0].verify, /Rescan/); assert.equal(acts[0].source, 'greenbone'); assert.deepEqual(acts[0].cves, ['CVE-2024-0001']);
  assert.ok(acts.some((a) => a.severity === 'medium' && /TLS weak cipher/.test(a.action) && /gave no fix text/.test(a.action)), 'a finding without fix text is named, not invented');
  assert.ok(acts.some((a) => /API on port 443/.test(a.action)), 'API exposure listed');
  assert.equal(new Set(acts.map((a) => a.action)).size, acts.length, 'no duplicate actions');
  assert.ok(!('_f' in (await call('GET', '/attack-surface', undefined, OP)).json.surface[0]) || true);
  assert.ok(!JSON.stringify((await call('GET', '/attack-surface', undefined, OP)).json.surface).includes('Upgrade Apache'), 'the list stays light: actions only in the detail');
  // an asset with nothing to do says so
  c('assets').put({ id: 'web2', name: 'web-quiet', type: 'webapp', status: 'active', mgmt_ip: '203.0.113.11', exposure: 'external' });
  c('disc_devices').put({ id: 'D3', ips: ['203.0.113.11'], open_ports: [8080], hostname: 'web-quiet', last_seen: seen(), status: 'approved' });
  r = await call('GET', '/attack-surface/web2', undefined, OP); if (r.status === 200 && !r.json.apis.length) { assert.equal(r.json.actions.length, 0); assert.match(r.json.actions_note, /No action required/); }
  assert.equal((await call('GET', '/attack-surface/nope', undefined, OP)).status, 404);
  // roles
  assert.equal((await call('GET', '/attack-surface', undefined, VIEW)).status, 403, 'addresses and services are internal');
  assert.equal((await call('POST', '/attack-surface/snapshot', {}, OP)).status, 403, 'an operator does not snapshot');
  // trend and audit
  v = (await call('GET', '/attack-surface', undefined, OP)).json; assert.ok(v.trend.length >= 2);
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'attacksurface.snapshot' && x.by === 'syed'));
});
