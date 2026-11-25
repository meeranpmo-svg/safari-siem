// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mimecast actions: the held queue, the fixed actions built from validated values, four-eyes (the proposer never approves,
// an AI identity never approves, an operator without the security scope does not approve), actions off until switched on,
// a separate management application (never the read-only log application), Mimecast "fail" answers said in words, audit.
// Addresses, ids and secrets are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');

const NOW = Date.parse('2026-11-25T10:00:00Z');
const res = (status, j) => ({ status, ok: status >= 200 && status < 300, json: async () => j });
function fake({ failOn } = {}) {
  const calls = [];
  const f = async (url, o = {}) => {
    calls.push({ url, auth: (o.headers || {}).Authorization || '', body: o.body ? String(o.body) : '' });
    if (url.endsWith('/oauth/token')) return /client_id=mng-id-syn/.test(String(o.body)) ? res(200, { access_token: 'mng-tok', expires_in: 1800 }) : res(401, {});
    if (url.endsWith('/api/gateway/get-hold-message-list')) return res(200, { meta: { status: 200 }, data: [{ id: 'eNoVzs1OgzAAAOBX', dateReceived: '2026-11-25T08:00:00+0000', fromHeader: { emailAddress: 'x@partner.example' }, to: { emailAddress: 'a@corp.example' }, subject: 'Invoice <b>', reason: 'Attachment', hasAttachments: true }], fail: [] });
    if (failOn && url.endsWith(failOn)) return res(200, { meta: { status: 200 }, data: [], fail: [{ errors: [{ message: 'synthetic: sender already exists' }] }] });
    return res(200, { meta: { status: 200 }, data: [{ ok: true }], fail: [] });
  };
  return { f, calls };
}
function mk(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcm-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{}'); fs.writeFileSync(secFile, '{}');
  const config = { mimecast: { enabled: false } }; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: { mimecast: { client_id: 'log-id-syn', client_secret: 'log-secret-syn' } }, writable: true });
  config.brand_domain = 'corp.example';
  const fk = fake(opts), state = createState({ dir: path.join(dir, 'state') }), R = {};
  const deps = { config, state, log: { error() {}, info() {}, warn() {} }, mimecastFetch: fk.f, now: () => NOW };
  const api = { route: (m, p, h) => { R[m + ' ' + p] = h; } };
  require('../engine/collect/mimecast-manage').register(api, deps); require('../engine/collect/mimecast-routes').register(api, deps);
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 }, audits = [];
  const call = async (m, p, b, role = 'admin', user) => {
    const o = {}, u = user || role + '.syn', params = {}; let key = '/api/soc' + p; const mm = p.match(/^\/cloud\/mimecast\/actions\/([^/]+)(\/\w+)$/); if (mm) { params.id = mm[1]; key = '/api/soc/cloud/mimecast/actions/:id' + mm[2]; }
    const ctx = { role, user: u, body: b, params, audit: (a, t, d) => audits.push({ a, t, d, by: u }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const h = R[m + ' ' + key]; assert.ok(h, 'route ' + m + ' ' + key); const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  return { call, audits, fk, config, secFile };
}

test('settings: a separate management application, write-only, actions off until switched on', async () => {
  const { call, secFile, audits } = mk();
  let r = await call('PUT', '/cloud/mimecast', { manage_enabled: true }); assert.equal(r.s, 400); assert.match(r.e, /manage_client_secret/);
  r = await call('PUT', '/cloud/mimecast', { manage_client_id: 'log-id-syn', manage_client_secret: 'x-syn' }); assert.equal(r.s, 400); assert.match(r.e, /separate Mimecast application/);
  assert.equal((await call('PUT', '/cloud/mimecast', { manage_enabled: true, manage_client_id: 'mng-id-syn', manage_client_secret: 'mng-secret-syn' }, 'operator')).s, 403);
  r = await call('PUT', '/cloud/mimecast', { manage_enabled: true, manage_client_id: 'mng-id-syn', manage_client_secret: 'mng-secret-syn' });
  assert.equal(r.s, 200, r.e); assert.equal(r.b.manage_app_set, true); assert.equal(r.b.manage_enabled, true);
  assert.ok(!JSON.stringify(r.b).includes('mng-secret-syn') && JSON.parse(fs.readFileSync(secFile, 'utf8')).mimecast.manage_client_secret === 'mng-secret-syn');
  assert.ok(audits.some((a) => a.a === 'cloud.mimecast.config' && a.d.manage_app_changed === true && !JSON.stringify(a).includes('mng-secret-syn')));
});

test('held queue and actions: validation, four-eyes, run with the management app, Mimecast refusals in words, audit', async () => {
  const { call, audits, fk, config } = mk({ failOn: '/api/ttp/url/create-managed-url' });
  await call('PUT', '/cloud/mimecast', { manage_client_id: 'mng-id-syn', manage_client_secret: 'mng-secret-syn' });
  assert.equal((await call('GET', '/cloud/mimecast/held', undefined, 'viewer')).s, 403);
  const h = await call('GET', '/cloud/mimecast/held', undefined, 'operator'); assert.equal(h.s, 200, h.e);
  assert.deepEqual([h.b.held[0].from, h.b.held[0].to, h.b.held[0].attachments], ['x@partner.example', 'a@corp.example', true]);
  assert.ok(fk.calls.filter((c) => !c.url.endsWith('/oauth/token')).every((c) => c.auth === 'Bearer mng-tok'), 'actions and the held queue use the management app');
  assert.ok(fk.calls.some((c) => /client_id=mng-id-syn/.test(c.body)) && !fk.calls.some((c) => /client_id=log-id-syn/.test(c.body)));
  // validation names the field
  const bad = async (b, field) => { const r = await call('POST', '/cloud/mimecast/actions', Object.assign({ reason: 'synthetic reason text' }, b), 'operator', 'op.syn'); assert.equal(r.s, 400, JSON.stringify(b)); assert.match(r.e, new RegExp(field)); };
  await bad({ kind: 'delete-mailbox' }, 'kind'); await bad({ kind: 'block-sender', sender: 'not an address', to: 'a@corp.example' }, 'sender');
  await bad({ kind: 'block-sender', sender: 'evil.example', to: 'everyone' }, 'to'); await bad({ kind: 'permit-sender', sender: 'ceo@corp.example', to: 'a@corp.example' }, 'own domain');
  await bad({ kind: 'release-held', id: 'x' }, 'id'); await bad({ kind: 'block-url', url: 'javascript:alert(1)' }, 'url');
  await bad({ kind: 'block-sender', sender: 'evil.example', to: 'a@corp.example', reason: 'short' }, 'reason');
  assert.equal((await call('POST', '/cloud/mimecast/actions', { kind: 'block-sender', sender: 'evil.example', to: 'a@corp.example', reason: 'synthetic reason text' }, 'viewer')).s, 403);
  let r = await call('POST', '/cloud/mimecast/actions', { kind: 'block-sender', sender: 'Bad@Evil.example', to: 'a@corp.example', reason: 'phishing campaign seen today (synthetic)', extra: 'x' }, 'operator', 'op.syn');
  assert.equal(r.s, 200, r.e); const id = r.b.id; assert.equal(r.b.sender, 'bad@evil.example'); assert.ok(!('extra' in r.b));
  assert.equal((await call('POST', `/cloud/mimecast/actions/${id}/run`, {}, 'operator', 'op.syn')).s, 409, 'not before approval');
  assert.equal((await call('POST', `/cloud/mimecast/actions/${id}/decide`, { decision: 'approved' }, 'admin', 'op.syn')).s, 403, 'the proposer does not approve');
  r = await call('POST', `/cloud/mimecast/actions/${id}/decide`, { decision: 'approved' }, 'admin', 'ai:soc'); assert.equal(r.s, 403); assert.match(r.e, /only a person/);
  assert.equal((await call('POST', `/cloud/mimecast/actions/${id}/decide`, { decision: 'approved' }, 'operator', 'op2.syn')).s, 403, 'no security approver scope');
  assert.equal((await call('POST', `/cloud/mimecast/actions/${id}/decide`, { decision: 'approved' }, 'admin', 'sec.syn')).s, 200);
  r = await call('POST', `/cloud/mimecast/actions/${id}/run`, {}, 'operator', 'op.syn'); assert.equal(r.s, 409); assert.match(r.e, /switched off/);
  config.mimecast.manage_enabled = true;
  r = await call('POST', `/cloud/mimecast/actions/${id}/run`, {}, 'operator', 'op.syn'); assert.equal(r.s, 200, r.e); assert.equal(r.b.status, 'done');
  const sent = fk.calls.find((c) => c.url.endsWith('/api/managedsender/permit-or-block-sender'));
  assert.deepEqual(JSON.parse(sent.body), { data: [{ sender: 'bad@evil.example', to: 'a@corp.example', action: 'block' }] });
  // a Mimecast refusal is the action's failure, in words, and audited
  r = await call('POST', '/cloud/mimecast/actions', { kind: 'block-url', url: 'https://evil.example/login', match: 'domain', reason: 'credential phishing page (synthetic)' }, 'operator', 'op.syn');
  const uid = r.b.id; await call('POST', `/cloud/mimecast/actions/${uid}/decide`, { decision: 'approved' }, 'admin', 'sec.syn');
  r = await call('POST', `/cloud/mimecast/actions/${uid}/run`, {}, 'operator', 'op.syn'); assert.equal(r.s, 502); assert.match(r.e, /sender already exists/);
  const list = (await call('GET', '/cloud/mimecast/actions', undefined, 'operator')).b; assert.equal(list.actions.find((a) => a.id === uid).status, 'failed'); assert.equal(list.enabled, true);
  // rejected needs a reason
  r = await call('POST', '/cloud/mimecast/actions', { kind: 'release-held', id: 'eNoVzs1OgzAAAOBX', reason: 'the vendor confirmed the invoice (synthetic)' }, 'operator', 'op.syn');
  assert.equal((await call('POST', `/cloud/mimecast/actions/${r.b.id}/decide`, { decision: 'rejected' }, 'admin', 'sec.syn')).s, 400);
  for (const a of ['cloud.mimecast.action.propose', 'cloud.mimecast.action.approve', 'cloud.mimecast.action.run']) assert.ok(audits.some((x) => x.a === a && x.t === id), 'audited: ' + a);
  assert.ok(audits.some((x) => x.a === 'cloud.mimecast.action.run' && x.d.status === 'failed'));
});
