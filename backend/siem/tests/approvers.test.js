// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Approvers in the SIEM: IT Asset Management pushes {scope: [user]} (admin, validated); wrap(deps, 'approve:<scope>')
// lets an administrator through, or an operator on that scope's list - never a viewer, never another scope's approver;
// forensic collections now refuse the requester's own approval (four-eyes).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createState } = require('../engine/soc/state');
const { wrap } = require('../engine/soc/routeutil');
const approvers = require('../engine/approvers/routes');

function ctxOf(user, role, b) {
  const out = { status: 200, body: null };
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  return { user, role, body: b, out,
    need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out.status = 403; return false; } return true; },
    ok: (j) => { out.body = j; return j; }, fail: (code, msg) => { out.status = code; out.body = { error: msg }; return out.body; }, audit: () => {} };
}

test('approver list: pushed by IT Asset Management, validated; the approve guard follows it per scope', async () => {
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-appr-')), 'state') });
  const deps = { state, config: {}, log: { error() {} } }, routes = {};
  approvers.register({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, deps);
  const post = routes['POST /api/soc/approvers'], get = routes['GET /api/soc/approvers'];
  let c = ctxOf('system:itam-roles', 'operator', { scopes: { infra: ['siva'] } }); await post(c); assert.equal(c.out.status, 403, 'only an administrator (IT Asset Management as system) may set it');
  c = ctxOf('system:itam-roles', 'admin', { scopes: { root: ['x'] } }); await post(c); assert.equal(c.out.status, 400);
  c = ctxOf('system:itam-roles', 'admin', { scopes: { infra: ['bad user!'] } }); await post(c); assert.equal(c.out.status, 400);
  c = ctxOf('system:itam-roles', 'admin', { scopes: { infra: ['Siva'], security: ['rasheed'] } }); await post(c); assert.equal(c.out.status, 200);
  c = ctxOf('ali', 'operator'); await get(c); assert.deepEqual(c.out.body.approvers, { infra: ['siva'], security: ['rasheed'] });

  let ran = 0; const h = wrap(deps, 'approve:infra', (ctx) => { ran++; return ctx.ok({ ok: true }); });
  for (const [u, r, want] of [['syed', 'admin', 200], ['siva', 'operator', 200], ['SIVA', 'operator', 200], ['rasheed', 'operator', 403], ['ali', 'operator', 403], ['siva', 'viewer', 403]]) {
    c = ctxOf(u, r); await h(c); assert.equal(c.out.status, want, `${u} (${r}) on infra`);
  }
  assert.equal(ran, 3, 'the handler ran only for the administrator and the infra approver');
  const hs = wrap(deps, 'approve:security', (ctx) => ctx.ok({ ok: true }));
  c = ctxOf('rasheed', 'operator'); await hs(c); assert.equal(c.out.status, 200);
  c = ctxOf('siva', 'operator'); await hs(c); assert.equal(c.out.status, 403); assert.match(c.out.body.error, /human approver for Security/);
  // the list is replaced, not merged: Siva removed → refused at once
  c = ctxOf('system:itam-roles', 'admin', { scopes: { infra: [], security: ['rasheed'] } }); await post(c);
  c = ctxOf('siva', 'operator'); await h(c); assert.equal(c.out.status, 403);
  // no state = administrators only
  const h0 = wrap({ config: {}, log: { error() {} } }, 'approve:infra', (ctx) => ctx.ok({ ok: true }));
  c = ctxOf('siva', 'operator'); await h0(c); assert.equal(c.out.status, 403);
});

test('per AI engineer approvers: an engineer scope covers that engineer only, the group covers all of its engineers; only people approve', async () => {
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-appr-')), 'state') });
  const deps = { state, config: {}, log: { error() {} } }, routes = {};
  approvers.register({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, deps);
  let c = ctxOf('system:itam-roles', 'admin', { scopes: { infra: ['siva'], 'eng:network': ['omar'], 'eng:windows': ['fahad'] } }); await routes['POST /api/soc/approvers'](c); assert.equal(c.out.status, 200);
  const net = wrap(deps, 'approve:eng:network', (ctx) => ctx.ok({ ok: true })), win = wrap(deps, (ctx) => 'approve:eng:windows|eng:exchange', (ctx) => ctx.ok({ ok: true }));
  for (const [h, u, want, what] of [[net, 'omar', 200, 'network approver → network'], [net, 'siva', 200, 'infra group → network'], [net, 'fahad', 403, 'windows approver → not network'],
    [win, 'fahad', 200, 'windows approver → a Windows/Exchange server'], [win, 'omar', 403, 'network approver → not Windows']]) { c = ctxOf(u, 'operator'); await h(c); assert.equal(c.out.status, want, what); }
  for (const u of ['duty:network', 'system:itam-roles', 'core:after-hours', 'ai:assistant']) { c = ctxOf(u, 'admin'); await net(c); assert.equal(c.out.status, 403, u + ' is not a person'); assert.match(c.out.body.error, /only a person approves/); }
  c = ctxOf('syed', 'admin'); await net(c); assert.equal(c.out.status, 200, 'an administrator still approves');
});

test('forensic collections: the requester cannot approve their own request (may still cancel it)', () => {
  const { createDfir, COLLECT } = require('../engine/dfir/dfir');
  const state = createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-dfir-')), 'state') });
  const D = createDfir({ state, search: async () => ({ events: [] }) });
  const item = (Array.isArray(COLLECT) ? COLLECT[0] : Object.values(COLLECT)[0]); const itemId = item.id || item;
  const mk = () => D.requestCollection({ entity: 'PC-0042', items: [itemId], rationale: 'case of suspected exfiltration' }, { user: 'rasheed' });
  const a = mk();
  assert.throws(() => D.decideCollection(a.id, 'approved', { user: 'Rasheed' }), (e) => e.code === 403 && /four-eyes/.test(e.message));
  assert.equal(D.decideCollection(a.id, 'approved', { user: 'syed' }).status, 'approved', 'a second person approves');
  const b = mk(); assert.equal(D.decideCollection(b.id, 'cancelled', { user: 'rasheed' }).status, 'cancelled', 'cancelling your own request is fine');
});
