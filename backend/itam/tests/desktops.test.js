// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// User Desktops (engine/desktops.js): desktops from Endpoint Central (servers left out) + register desktops without an agent,
// branch filter incl. the engineer's own branches, branch compliance; patch catalogue and one computer's patches; deploy /
// scan become Endpoint Central action requests (four eyes in manageengine.js), split per 200; remote support needs a reason,
// is logged and audited, offers only the configured methods, is closed by its engineer or an admin. Roles and validation.
// Endpoint Central client: patch reads are allow-listed GETs. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { ecClient, ecPatchRow } = require('../engine/manageengine');

const ADM = { user: 'syed', role: 'admin' }, OPR = { user: 'faisal.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, VWR = { user: 'v.syn', role: 'viewer' };
const call = (e, m, p, who, b) => e.req(m, p, { user: who.user, role: who.role, body: b });

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (r) => { audits.push(r); if (orig) orig.call(e.app, r); };
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const a1 = mk({ name: 'RUH-PC-001', type: 'desktop', site: 'Riyadh HQ' }), noAgent = mk({ name: 'JED-LT-009', type: 'laptop', site: 'Jeddah Branch', custodian: 'sara.syn' });
  mk({ name: 'OLD-PC', type: 'desktop', status: 'retired' });
  mk({ name: 'RUH-VDI-07', type: 'vm', os: 'Windows 11 Enterprise multi-session', site: 'Riyadh HQ' }); mk({ name: 'MKT-PC-3', type: 'other', os: 'Windows 10 Pro', site: 'Jeddah Branch' });
  mk({ name: 'WEB-VM', type: 'vm', os: 'Windows Server 2022' }); mk({ name: 'NAS-1', type: 'other', os: 'Linux' });
  const ec = e.app.store.collection('me_ec_computers');
  ec.put({ id: '301', name: 'RUH-PC-001', ip: '10.20.1.11', fqdn: 'ruh-pc-001.corp-hq.test', os: 'Windows 11 Enterprise', branch: 'Riyadh HQ', user: 'ali.syn', live: 'live', health: 'highly vulnerable', missing: 14, critical: 3, asset_id: a1.id });
  ec.put({ id: '302', name: 'RUH-PC-002', ip: '10.20.1.12', os: 'Windows 10 Pro', branch: 'Riyadh HQ', user: 'noura.syn', live: 'down', health: 'healthy', missing: 0, critical: 0 });
  ec.put({ id: '303', name: 'DMM-PC-001', ip: '10.40.1.5', os: 'Windows 11 Pro', branch: 'Dammam Branch', user: 'khalid.syn', live: 'live', health: 'vulnerable', missing: 4, critical: 0 });
  ec.put({ id: '399', name: 'APP-SRV-01', os: 'Windows Server 2019', branch: 'Riyadh HQ', live: 'live' });
  for (let i = 0; i < 230; i++) ec.put({ id: String(1000 + i), name: 'BULK-PC-' + i, os: 'Windows 11', branch: 'Bulk Branch', live: 'live', critical: 1 });
  const requests = [];
  e.app.addons.manageengine = {
    status: () => ({ ec: { base_url: 'https://ec.syn.test', last_sync: { at: '2026-10-27T05:00:00Z', ok: true } } }),
    patches: () => [{ id: '9001', patch_id: '9001', name: 'KB5044284 Cumulative Update', severity: 'critical', missing: 40, installed: 200 }, { id: '9002', patch_id: '9002', name: 'Adobe Reader 24.003', severity: 'moderate', missing: 0, installed: 240 }],
    systemPatches: async (rid) => { assert.equal(rid, '301'); return [{ patch_id: '9001', name: 'KB5044284', severity: 'critical', status: 'missing' }, { patch_id: '9002', name: 'Adobe', severity: 'moderate', status: 'installed' }]; },
    requestA: (b, who) => { const a = { id: 'ma_' + requests.length, label: b.action === 'ec-install-patches' ? 'Install patches' : 'Patch scan', resource_ids: b.resource_ids, status: 'pending' }; requests.push({ b, who: who.user }); return { action: a }; },
  };
  return { e, audits, requests, a1, noAgent };
}

test('desktops: Endpoint Central computers without servers, register desktops without an agent, branch summary; viewer sees counts only', async (t) => {
  const { e, noAgent } = await setup(t);
  let r = await call(e, 'GET', '/desktops?branch=Riyadh%20HQ', OPR); assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.desktops.map((d) => d.name), ['RUH-PC-001', 'RUH-PC-002', 'RUH-VDI-07'], 'the server and other branches are not listed');
  const p1 = r.json.desktops[0]; assert.equal(p1.user, 'ali.syn'); assert.equal(p1.patch.critical, 3); assert.equal(p1.agent, 'live');
  const ruh = r.json.branches.find((b) => b.branch === 'Riyadh HQ'); assert.deepEqual([ruh.desktops, ruh.agent_offline, ruh.agent_missing, ruh.critical_missing, ruh.compliance_pct], [3, 1, 1, 1, 50]);
  r = await call(e, 'GET', '/desktops?state=no_agent', OPR);
  assert.deepEqual(r.json.desktops.map((d) => [d.name, d.agent, d.branch]), [['JED-LT-009', 'missing', 'Jeddah Branch'], ['MKT-PC-3', 'missing', 'Jeddah Branch'], ['RUH-VDI-07', 'missing', 'Riyadh HQ']], 'register desktops by type or client OS (VDI too); servers and appliances are not desktops');
  assert.equal(r.json.desktops[0].id, noAgent.id); assert.equal(r.json.desktops[0].user, 'sara.syn');
  r = await call(e, 'GET', '/desktops?q=khalid', OPR); assert.deepEqual(r.json.desktops.map((d) => d.name), ['DMM-PC-001']);
  assert.ok(!r.json.desktops.some((d) => d.name === 'OLD-PC'));
  assert.equal((await call(e, 'GET', '/desktops', VWR)).status, 403, 'names of users are not for viewers');
  const sm = await call(e, 'GET', '/desktops/summary', VWR); assert.equal(sm.status, 200); assert.doesNotMatch(sm.text, /ali\.syn|RUH-PC/);
  assert.equal((await call(e, 'GET', '/desktops?state=bogus', OPR)).status, 400);
});

test('branches: an administrator assigns branches; the engineer opens on "mine"; settings validated and audited', async (t) => {
  const { e, audits } = await setup(t);
  assert.equal((await call(e, 'POST', '/desktops/settings', OPR, { engineers: [] })).status, 403);
  let r = await call(e, 'POST', '/desktops/settings', ADM, { remote: { ec_url: 'http://ec.syn.test/x' } }); assert.equal(r.status, 400); assert.match(r.json.error, /ec_url/);
  r = await call(e, 'POST', '/desktops/settings', ADM, { engineers: [{ user: 'faisal.syn', branches: [] }] }); assert.equal(r.status, 400); assert.match(r.json.error, /engineers\[0\]\.branches/);
  r = await call(e, 'POST', '/desktops/settings', ADM, { remote: { ec_url: 'https://ec.syn.test:8383/webclient#/uems/tools/remote-control?resourceId={resource_id}', msra: true, rdp: false }, engineers: [{ user: 'Faisal.Syn', branches: ['Riyadh HQ', 'Dammam Branch'] }] });
  assert.equal(r.status, 200, r.text);
  assert.ok(audits.some((a) => a.action === 'desktops.settings' && a.by === 'syed'));
  r = await call(e, 'GET', '/desktops?branch=mine', OPR);
  assert.deepEqual(r.json.my_branches, ['Riyadh HQ', 'Dammam Branch']); assert.deepEqual(r.json.desktops.map((d) => d.branch).filter((v, i, a) => a.indexOf(v) === i), ['Dammam Branch', 'Riyadh HQ']);
});

test('patches: catalogue, one desktop\'s patches; deploy / scan become approval requests split per 200; validation and audit', async (t) => {
  const { e, audits, requests, a1, noAgent } = await setup(t);
  let r = await call(e, 'GET', '/desktops/patches', OPR); assert.equal(r.status, 200);
  assert.deepEqual(r.json.counts, { patches: 2, missing: 1, critical_missing: 1, important_missing: 0 });
  r = await call(e, 'GET', '/desktops/' + a1.id + '/patches', OPR); assert.equal(r.status, 200, r.text); assert.equal(r.json.missing, 1);
  r = await call(e, 'GET', '/desktops/' + noAgent.id + '/patches', OPR); assert.equal(r.status, 409); assert.match(r.json.error, /agent/);
  assert.equal((await call(e, 'POST', '/desktops/patches/deploy', VWR, { patch_ids: ['9001'], branch: 'Riyadh HQ', reason: 'October critical' })).status, 403);
  for (const [b, re] of [[{ branch: 'Riyadh HQ', reason: 'October critical' }, /patch_ids/], [{ patch_ids: ['KB5044284'], branch: 'Riyadh HQ', reason: 'October critical' }, /patch_ids/], [{ patch_ids: ['9001'], branch: 'Riyadh HQ', reason: 'x' }, /reason/], [{ patch_ids: ['9001'], reason: 'October critical' }, /branch or desktops/], [{ patch_ids: ['9001'], branch: 'Nowhere', reason: 'October critical' }, /branch/]]) {
    const x = await call(e, 'POST', '/desktops/patches/deploy', OPR, b); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.json.error, re);
  }
  r = await call(e, 'POST', '/desktops/patches/deploy', OPR, { patch_ids: ['9001'], branch: 'Bulk Branch', reason: 'October critical updates' });
  assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.requests.map((x) => x.computers), [200, 30], 'split per 200 computers');
  assert.match(r.json.approval, /different person approves/);
  assert.ok(requests.every((q) => q.b.action === 'ec-install-patches' && q.who === 'faisal.syn' && /October critical updates \[User Desktops: branch Bulk Branch\]/.test(q.b.reason)));
  r = await call(e, 'POST', '/desktops/patches/scan', OPR, { desktop_ids: [a1.id, noAgent.id], reason: 'check after reboot' });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.computers, 1); assert.equal(r.json.without_agent, 1);
  assert.ok(audits.some((a) => a.action === 'desktops.patch.deploy_request' && a.detail.computers === 230));
  assert.ok(audits.some((a) => a.action === 'desktops.patch.scan_request'));
});

test('remote support: reason required, session logged and audited, configured methods only, closed by its engineer or an admin', async (t) => {
  const { e, audits, a1 } = await setup(t);
  let r = await call(e, 'POST', '/desktops/' + a1.id + '/remote', OPR, { reason: 'Outlook keeps asking for password' });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.commands.map((c) => c.command), ['msra /offerra ruh-pc-001.corp-hq.test', 'mstsc /v:ruh-pc-001.corp-hq.test']);
  assert.equal(r.json.links.length, 0, 'no Endpoint Central link until an administrator sets it');
  await call(e, 'POST', '/desktops/settings', ADM, { remote: { ec_url: 'https://ec.syn.test/rc?resourceId={resource_id}', msra: true, rdp: false } });
  r = await call(e, 'POST', '/desktops/' + a1.id + '/remote', OPR, { reason: 'Outlook keeps asking for password', ticket: 'SDP-4412' });
  assert.deepEqual(r.json.links.map((l) => l.url), ['https://ec.syn.test/rc?resourceId=301']); assert.deepEqual(r.json.commands.map((c) => c.kind), ['msra']);
  const sid = r.json.session.id; assert.equal(r.json.session.end_user, 'ali.syn'); assert.match(r.json.consent, /PDPL/);
  assert.ok(audits.some((a) => a.action === 'desktops.remote.start' && a.detail.ticket === 'SDP-4412' && a.by === 'faisal.syn'));
  assert.equal((await call(e, 'POST', '/desktops/' + a1.id + '/remote', OPR, { reason: 'no' })).status, 400);
  assert.equal((await call(e, 'POST', '/desktops/' + a1.id + '/remote', VWR, { reason: 'Outlook keeps asking' })).status, 403);
  assert.equal((await call(e, 'POST', '/desktops/remote/' + sid + '/end', OP2, { outcome: 'resolved' })).status, 403, 'another engineer cannot close it');
  assert.equal((await call(e, 'POST', '/desktops/remote/' + sid + '/end', OPR, { outcome: 'fixed' })).status, 400);
  r = await call(e, 'POST', '/desktops/remote/' + sid + '/end', OPR, { outcome: 'resolved', note: 'cleared cached credentials' }); assert.equal(r.status, 200, r.text);
  assert.equal((await call(e, 'POST', '/desktops/remote/' + sid + '/end', ADM, { outcome: 'resolved' })).status, 409);
  r = await call(e, 'GET', '/desktops/remote/sessions?mine=1', OPR); assert.equal(r.json.sessions.length, 2);
  assert.equal((await call(e, 'GET', '/desktops/remote/sessions?mine=1', OP2)).json.sessions.length, 0);
  assert.ok(audits.some((a) => a.action === 'desktops.remote.end' && a.detail.outcome === 'resolved'));
  await call(e, 'POST', '/desktops/settings', ADM, { remote: { ec_url: '', msra: false, rdp: false } });
  assert.equal((await call(e, 'POST', '/desktops/' + a1.id + '/remote', OPR, { reason: 'Outlook keeps asking' })).status, 409);
});

test('Endpoint Central client: patch catalogue and one computer\'s report are allow-listed GETs; patch rows read defensively', async () => {
  const urls = [];
  const request = async (url) => { urls.push(url); return { status: 200, json: { message_response: { systemreport: [{ patch_id: 9001, patch_name: 'KB5044284', severity: 4, patch_status: 'Missing' }], total: 1 } } }; };
  const c = ecClient({ base_url: 'https://ec.syn.test:8383' }, 'k', { request });
  const rows = (await c.pages('patch/systemreport?resid=301')).map(ecPatchRow);
  assert.equal(urls[0], 'https://ec.syn.test:8383/api/1.4/patch/systemreport?resid=301&page=1&pagelimit=1000');
  assert.deepEqual([rows[0].patch_id, rows[0].severity, rows[0].status], ['9001', 'critical', 'missing']);
  await assert.rejects(c.call('GET', '/api/1.4/patch/systemreport?resid=../x&page=1&pagelimit=1'), /refusing/);
  await assert.rejects(c.call('POST', '/api/1.4/patch/installpatch', {}), /refusing/, 'no write without the write client');
});
