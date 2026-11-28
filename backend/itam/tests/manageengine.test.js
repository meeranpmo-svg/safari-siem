// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ManageEngine Endpoint Central (read + approved actions) and ServiceDesk Plus (tickets): sealed keys, read-only guard,
// computers into Asset Discovery / the inventory, rules opening tickets automatically or after approval, no duplicates,
// four eyes, status sync from the desk, action results noted on the ticket.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createManageEngine, ecClient, ecComputer, ecPatch } = require('../engine/manageengine');

const EC_KEY = 'EC-API-KEY-1234567890', SDP_KEY = 'SDP-TECH-KEY-0987654321';
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'faisal', role: 'admin' }, OP = { user: 'ali', role: 'operator' };
const DAY = 86400000;

function fakes(calls, t0) {
  let nextId = 5000; const sdpReq = {};
  return async (url, o) => {
    calls.push({ url, method: o.method, headers: o.headers, body: o.body });
    const u = new URL(url);
    if (u.host === 'ec01.corp.local:8383') {
      if (o.headers.Authorization !== EC_KEY) return { status: 200, json: { status: 'error', error_code: '10002', error_description: 'Invalid API key' } };
      if (u.pathname === '/api/1.4/som/computers') return { status: 200, json: { status: 'success', message_response: { total: 3, computers: [
        { resource_id: 301, resource_name: 'HQ-PC-014', fqdn_name: ('hq-pc-014.' + 'corp-hq.com'), ip_address: '10.50.1.14', mac_address: '00:1a:2b:3c:4d:14', os_name: 'Windows 11 Enterprise', agent_last_contact_time: t0 - 2 * 3600000, computer_live_status: 1, domain_netbios_name: 'ASIC' },
        { resource_id: 302, resource_name: 'ERP-APP01', ip_address: '10.20.5.10, 169.254.1.1', mac_address: '00:1a:2b:3c:4d:15', os_name: 'Windows Server 2022 Standard', agent_last_contact_time: t0 - 12 * DAY, computer_live_status: 2 },
        { resource_id: 303, resource_name: 'HQ-LT-077', ip_address: '10.50.2.77', os_name: 'Windows 10 Pro', agent_last_contact_time: t0 - DAY, computer_live_status: 1 }] } } };
      if (u.pathname === '/api/1.4/patch/allsystems') return { status: 200, json: { status: 'success', message_response: { allsystems: [
        { resource_id: 301, health_status: 1, missing_patches: 0 }, { resource_id: 302, health_status: 3, missing_patches: 14, critical_missing_patches: 4 }, { resource_id: 303, health_status: 2, missing_patches: 3, critical_missing_patches: 0 }] } } };
      if (o.method === 'POST' && /^\/api\/1\.4\/(patch|inventory)\//.test(u.pathname)) return { status: 200, json: { status: 'success', message_response: { status: 'Scan initiated' } } };
      return { status: 404, json: null, text: 'not found' };
    }
    if (u.host === 'sdp.corp.local:8443') {
      if (o.headers.authtoken !== SDP_KEY) return { status: 401, json: { response_status: { status_code: 4000, status: 'failed', messages: [{ message: 'Invalid technician key' }] } } };
      if (o.method === 'GET' && u.pathname === '/api/v3/requests') return { status: 200, json: { response_status: [{ status_code: 2000, status: 'success' }], requests: [] } };
      if (o.method === 'POST' && u.pathname === '/api/v3/requests') {
        const input = JSON.parse(decodeURIComponent(String(o.body).replace(/^input_data=/, '')));
        const rid = String(nextId++); sdpReq[rid] = { input, status: 'Open', notes: [] };
        return { status: 201, json: { response_status: { status_code: 2000, status: 'success' }, request: { id: rid, status: { name: 'Open' } } } };
      }
      let m;
      if (o.method === 'GET' && (m = /^\/api\/v3\/requests\/(\d+)$/.exec(u.pathname))) return { status: 200, json: { response_status: { status_code: 2000, status: 'success' }, request: { id: m[1], status: { name: sdpReq[m[1]].status } } } };
      if (o.method === 'POST' && (m = /^\/api\/v3\/requests\/(\d+)\/notes$/.exec(u.pathname))) { sdpReq[m[1]].notes.push(JSON.parse(decodeURIComponent(String(o.body).replace(/^input_data=/, ''))).note.description); return { status: 201, json: { response_status: { status_code: 2000, status: 'success' }, note: { id: '1' } } }; }
      return { status: 404, json: null };
    }
    throw Object.assign(new Error('connection failed (ENOTFOUND)'), { code: 'unreachable' });
  };
}

test('parsers: Endpoint Central computer and patch rows', () => {
  const c = ecComputer({ resource_id: 7, resource_name: 'PC1', ip_address: '169.254.0.1,10.1.1.5', mac_address: '00:11:22:33:44:55', computer_live_status: 2, agent_last_contact_time: 1760000000000 });
  assert.deepEqual([c.resource_id, c.ip, c.ips.join(), c.macs.join(), c.live, c.last_contact], ['7', '169.254.0.1', '169.254.0.1,10.1.1.5', '00:11:22:33:44:55', 'down', 1760000000000]);
  assert.deepEqual(ecPatch({ resource_id: 7, health_status: 3, missing_patches: 9, critical_missing_patches: 2 }), { resource_id: '7', health: 'highly vulnerable', missing: 9, critical: 2, installed: null });
});

test('Endpoint Central client is read-only unless an approved action asks', async () => {
  const cl = ecClient({ base_url: 'https://ec01.corp.local:8383' }, EC_KEY, { request: async () => ({ status: 200, json: { status: 'success' } }) });
  await assert.rejects(cl.call('POST', '/api/1.4/patch/installpatch', {}), /refusing/);
  await assert.rejects(cl.call('GET', '/api/1.4/sdp/delete?x=1'), /refusing/);
  await assert.rejects(cl.call('DELETE', '/api/1.4/som/computers?page=1&pagelimit=1'), /refusing/);
});

test('ManageEngine: sync, rules, approvals, ServiceDesk Plus tickets, four-eyes actions', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const t0 = Date.parse('2026-10-14T09:00:00Z'), calls = [];
  const M = createManageEngine(e.app, { request: fakes(calls, t0), now: () => t0 });

  assert.throws(() => M.saveConfig({ ec: { base_url: 'http://ec01.corp.local:8383', api_key: EC_KEY } }, ADM), /https/);
  assert.throws(() => M.saveConfig({ ec: { base_url: 'https://ec01.corp.local:8383', api_key: 'short' } }, ADM), /key/);
  M.saveConfig({ ec: { base_url: 'https://ec01.corp.local:8383', api_key: EC_KEY, site: 'Riyadh HQ' }, sdp: { base_url: 'https://sdp.corp.local:8443', technician_key: SDP_KEY, requester: ('itam-bot@' + 'corp-hq.com') },
    rules: { ec_vulnerable: { enabled: true, mode: 'auto', group: 'Desktop Support' }, ec_silent: { enabled: true, mode: 'approve', param: 7 }, warranty: { enabled: true, mode: 'approve', param: 60 } } }, ADM);
  const st = JSON.stringify(M.status());
  assert.ok(!st.includes(EC_KEY) && !st.includes(SDP_KEY), 'keys never returned');
  assert.equal(M.status().ec.key_set, true);
  assert.throws(() => M.saveConfig({ ec: { base_url: 'https://other.corp.local:8383' } }, ADM), /enter the key again/);

  // connection tests
  assert.match((await M.test('ec', ADM)).result.message, /3 computers/);
  assert.equal((await M.test('sdp', ADM)).result.ok, true);

  // sync: computers into discovery and the inventory, patch health merged
  const s1 = await M.syncEc(ADM);
  assert.equal(s1.ok, true, JSON.stringify(s1)); assert.equal(s1.computers, 3); assert.equal(s1.added, 3); assert.equal(s1.patch_rows, 3);
  const comps = M.computers().computers;
  const erp = comps.find((c) => c.name === 'ERP-APP01');
  assert.deepEqual([erp.health, erp.critical, erp.live, erp.ip], ['highly vulnerable', 4, 'down', '10.20.5.10']);
  const erpAsset = e.app.store.collection('assets').get(erp.asset_id);
  assert.equal(erpAsset.type, 'server'); assert.equal(e.app.store.collection('assets').get(comps.find((c) => c.name === 'HQ-PC-014').asset_id).type, 'workstation');
  assert.ok(calls.filter((c) => /ec01/.test(c.url)).every((c) => c.method === 'GET'), 'sync only reads');
  // a second sync does not add twice
  assert.equal((await M.syncEc(ADM)).added, 0);

  // a warranty ending in 20 days on a hand-made asset
  const lap = e.app.assets.create({ name: 'CEO-LAPTOP', type: 'laptop', status: 'in_use', warranty: { end: '2026-11-03', provider: 'Dell ProSupport' } }, ADM).asset.id;

  // rules: ec_vulnerable opens automatically, ec_silent and warranty wait for approval
  const r1 = M.evalRules(ADM); await M.flush();
  assert.deepEqual(r1.by_rule, { warranty: 1, ec_silent: 1, ec_vulnerable: 1 });
  let T = M.listT({}).tickets;
  const vuln = T.find((x) => x.rule === 'ec_vulnerable'), silent = T.find((x) => x.rule === 'ec_silent'), war = T.find((x) => x.rule === 'warranty');
  assert.equal(vuln.status, 'open'); assert.equal(vuln.sdp_id, '5000'); assert.match(vuln.sdp_url, /WorkOrder\.do\?woMode=viewWO&woID=5000$/);
  assert.equal(silent.status, 'pending'); assert.equal(war.status, 'pending'); assert.equal(war.asset_id, lap);
  const post = calls.find((c) => c.method === 'POST' && /sdp\.corp\.local:8443\/api\/v3\/requests$/.test(c.url));
  assert.equal(post.headers.authtoken, SDP_KEY); assert.equal(post.headers['Content-Type'], 'application/x-www-form-urlencoded');
  const input = JSON.parse(decodeURIComponent(post.body.replace(/^input_data=/, ''))).request;
  assert.match(input.subject, /Missing patches on ERP-APP01: 4 critical/);
  assert.deepEqual([input.priority.name, input.group.name, input.requester.email_id], ['High', 'Desktop Support', ('itam-bot@' + 'corp-hq.com')]);
  assert.match(input.description, /highly vulnerable/);
  // no duplicates on the next run
  assert.equal(M.evalRules(ADM).raised, 0);

  // approvals: reason required to reject; approve sends it
  assert.throws(() => M.rejectT(war.id, {}, OP), /reason/);
  assert.equal(M.rejectT(war.id, { reason: 'renewal already ordered (PO 4471)' }, OP).ticket.status, 'rejected');
  assert.equal(M.evalRules(ADM).raised, 0, 'a rejected condition stays quiet');
  const ap = await M.approveT(silent.id, OP);
  assert.equal(ap.ticket.status, 'open'); assert.equal(ap.ticket.approved_by, 'ali');
  await assert.rejects(M.approveT(silent.id, OP), /not waiting/);

  // hand-made ticket: a second person approves
  const man = M.manual({ title: 'Replace UPS battery in rack 4', description: 'Battery test failed', asset_id: lap }, OP).ticket;
  assert.equal(man.status, 'pending');
  await assert.rejects(M.approveT(man.id, OP), /second person/);
  await assert.rejects(M.approveT(man.id, { user: ' ALI ', role: 'operator' }), /second person/);
  assert.equal((await M.approveT(man.id, ADM)).ticket.status, 'open');

  // desk status comes back; closed tickets are closed here
  const sdpCalls = () => calls.filter((c) => c.method === 'GET' && /\/api\/v3\/requests\/5000$/.test(c.url)).length;
  const reqs = calls.filter((c) => /\/api\/v3\/requests$/.test(c.url) && c.method === 'POST').length;
  assert.equal(reqs, 3);
  const before = sdpCalls();
  await M.pollSdp();
  assert.ok(sdpCalls() > before, 'open tickets are re-read from the desk');

  // actions: request by an operator, four eyes, sent to Endpoint Central, noted on the ticket
  assert.throws(() => M.requestA({ action: 'ec-reboot', resource_ids: ['302'], reason: 'x' }, OP), /action must be/);
  assert.throws(() => M.requestA({ action: 'ec-install-patches', resource_ids: ['302'], reason: 'patch it' }, OP), /patch IDs/);
  assert.throws(() => M.requestA({ action: 'ec-patch-scan', resource_ids: ['999'], reason: 'scan' }, OP), /not in the Endpoint Central list/);
  const a1 = M.requestA({ action: 'ec-install-patches', resource_ids: ['302'], patch_ids: '104821, 104822', reason: 'critical patches', ticket_id: vuln.id }, ADM).action;
  await assert.rejects(M.approveA(a1.id, ADM), /four eyes/);
  const done = (await M.approveA(a1.id, ADM2)).action;
  assert.equal(done.status, 'done', done.result);
  const ecPost = calls.filter((c) => c.method === 'POST' && /ec01/.test(c.url)).pop();
  assert.match(ecPost.url, /\/api\/1\.4\/patch\/installpatch$/);
  assert.deepEqual(JSON.parse(ecPost.body), { PatchIDs: [104821, 104822], ResourceIDs: [302], actionToPerform: 'Deploy' });
  assert.ok(calls.some((c) => c.method === 'POST' && /\/api\/v3\/requests\/5000\/notes$/.test(c.url) && /approved by faisal/.test(decodeURIComponent(c.body))), 'result noted on the ticket');
  const a2 = M.requestA({ action: 'ec-patch-scan', resource_ids: ['301', '303'], reason: 'after patch Tuesday' }, OP).action;
  assert.equal(M.rejectA(a2.id, { reason: 'wait for the window' }, ADM).action.status, 'rejected');

  // audit: decisions recorded, keys never
  const aud = e.app.store.auditTail(500, (x) => /^me\./.test(x.action || ''));
  for (const k of ['me.config', 'me.test', 'me.ec.sync', 'me.ticket.raise', 'me.ticket.approve', 'me.ticket.reject', 'me.ticket.send', 'me.action.request', 'me.action.approve', 'me.action.result', 'me.action.reject']) assert.ok(aud.some((x) => x.action === k), k);
  assert.ok(!JSON.stringify(aud).includes(EC_KEY) && !JSON.stringify(aud).includes(SDP_KEY));
});

test('ServiceDesk Plus: a closed request closes the ticket; the condition may re-open after the re-arm time', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  let clock = Date.parse('2026-10-14T09:00:00Z'), deskStatus = 'Open';
  const calls = [];
  const base = fakes(calls, clock);
  const request = async (url, o) => {
    if (o.method === 'GET' && /\/api\/v3\/requests\/\d+$/.test(url)) return { status: 200, json: { response_status: { status_code: 2000, status: 'success' }, request: { id: '5000', status: { name: deskStatus } } } };
    return base(url, o);
  };
  const M = createManageEngine(e.app, { request, now: () => clock });
  M.saveConfig({ sdp: { base_url: 'https://sdp.corp.local:8443', technician_key: SDP_KEY }, rules: { warranty: { enabled: true, mode: 'auto', param: 30 } } }, ADM);
  e.app.assets.create({ name: 'SRV-OLD', type: 'server', status: 'in_use', warranty: { end: '2026-10-20' } }, ADM);
  M.evalRules(); await M.flush();
  assert.equal(M.listT({}).tickets[0].status, 'open');
  deskStatus = 'Resolved'; await M.pollSdp();
  const tk = M.listT({}).tickets[0];
  assert.deepEqual([tk.status, tk.sdp_status], ['closed', 'Resolved']);
  assert.equal(M.evalRules().raised, 0, 'not again straight away');
  clock += 8 * DAY;
  assert.equal(M.evalRules().raised, 1, 'after the re-arm time the open condition raises a new ticket');
});

test('manageengine: /me/status tells the page the role the portal sent (not whoami.json)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/manageengine').registerManageEngine(e.app.srv, e.app);
  const a = await e.req('GET', '/me/status', { role: 'admin', user: 'syed' });
  assert.equal(a.status, 200); assert.deepEqual(a.json.you, { user: 'syed', role: 'admin' });
  assert.equal((await e.req('GET', '/me/status', { role: 'operator', user: 'ali' })).json.you.role, 'operator');
});

test('a connection that never got an answer says why and what to fix (EAI_AGAIN on the platform server: DNS)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let sys = 'EAI_AGAIN';
  const request = async () => { throw Object.assign(new Error('connection failed (' + sys + ')'), { code: sys === 'ETIMEDOUT' ? 'timeout' : 'unreachable', sys }); };
  const M = createManageEngine(e.app, { request, now: () => Date.parse('2026-11-12T08:00:00Z') });
  M.saveConfig({ ec: { base_url: 'https://mepc.synthetic.test:8383', api_key: EC_KEY } }, ADM);
  let r = (await M.test('ec', ADM)).result;
  assert.equal(r.ok, false); assert.equal(r.error_class, 'EAI_AGAIN');
  assert.match(r.message, /mepc\.synthetic\.test does not resolve on the platform server \(EAI_AGAIN, DNS did not answer\)/);
  assert.match(r.message, /getent hosts mepc\.synthetic\.test/); assert.match(r.message, /\/etc\/hosts/); assert.match(r.message, /Keep the name in the address/);
  sys = 'ECONNREFUSED'; assert.match((await M.test('ec', ADM)).result.message, /mepc\.synthetic\.test:8383 refused the connection/);
  sys = 'ETIMEDOUT'; assert.match((await M.test('ec', ADM)).result.message, /allow TCP 8383 from the platform server/);
  assert.equal(M.status().ec.last_test.ok, false, 'the last test is recorded');
});
