// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Portal menu preferences (engine/ui/menuprefs.js): admin-only shared order, per-user favorites, input validation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const menu = require('../engine/ui/menuprefs');

const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
async function setup() {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-menu-')) });
  const routes = {}, audits = [];
  menu.register({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, { state, log: { error() {} } });
  async function call(m, p, { user = 'alice', role = 'viewer', body } = {}) {
    const out = {};
    const ctx = { user, role, body, path: p,
      need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; },
      audit(a, t, d) { audits.push({ by: user, a, t, d }); },
      ok(b) { out.status = 200; out.body = b; return b; },
      fail(c, msg) { out.status = c; out.error = msg; } };
    await routes[m + ' ' + p](ctx);
    return out;
  }
  return { call, audits };
}

test('favorites are per user', async () => {
  const { call } = await setup();
  assert.equal((await call('PUT', '/api/soc/ui/menu/favorites', { user: 'alice', body: { items: ['ciodash', 'link:/dashboards/head-of-it.html', 'ciodash'] } })).status, 200);
  assert.deepEqual((await call('GET', '/api/soc/ui/menu', { user: 'alice' })).body.favorites, ['ciodash', 'link:/dashboards/head-of-it.html']);
  assert.deepEqual((await call('GET', '/api/soc/ui/menu', { user: 'bob' })).body.favorites, []);
});

test('only an admin can change the shared order; everyone sees it', async () => {
  const { call, audits } = await setup();
  const order = { groups: [{ name: 'Command Center', items: ['home', 'ciodash'] }, { name: 'Dashboards', items: ['link:/dashboards/network-flows.html'] }] };
  assert.equal((await call('PUT', '/api/soc/ui/menu/order', { role: 'operator', body: order })).status, 403);
  const r = await call('PUT', '/api/soc/ui/menu/order', { user: 'admin1', role: 'admin', body: order });
  assert.equal(r.status, 200);
  const seen = (await call('GET', '/api/soc/ui/menu', { user: 'carol' })).body;
  assert.deepEqual(seen.order.groups, order.groups);
  assert.equal(seen.order.updated_by, 'admin1');
  assert.equal(seen.can_edit_order, false);
  assert.equal((await call('GET', '/api/soc/ui/menu', { role: 'admin' })).body.can_edit_order, true);
  assert.equal((await call('DELETE', '/api/soc/ui/menu/order', { role: 'viewer' })).status, 403);
  assert.equal((await call('DELETE', '/api/soc/ui/menu/order', { role: 'admin' })).status, 200);
  assert.equal((await call('GET', '/api/soc/ui/menu')).body.order, null);
  assert.ok(audits.some((a) => a.a === 'ui.menu.order' && a.by === 'admin1'));
});

test('input is validated: no markup, bounded sizes, signed-in user required', async () => {
  const { call } = await setup();
  assert.equal((await call('PUT', '/api/soc/ui/menu/favorites', { body: { items: ['<img src=x onerror=alert(1)>'] } })).status, 400);
  assert.equal((await call('PUT', '/api/soc/ui/menu/favorites', { body: { items: Array.from({ length: 31 }, (_, i) => 'v' + i) } })).status, 400);
  assert.equal((await call('PUT', '/api/soc/ui/menu/favorites', { body: { items: 'home' } })).status, 400);
  assert.equal((await call('PUT', '/api/soc/ui/menu/order', { role: 'admin', body: { groups: [{ name: '<b>x</b>', items: ['home'] }] } })).body.groups[0].name, 'bx/b');
  assert.equal((await call('PUT', '/api/soc/ui/menu/order', { role: 'admin', body: { groups: [] } })).status, 400);
  assert.equal((await call('GET', '/api/soc/ui/menu', { user: '' })).status, 401);
});

test('order format v: stored and returned (workspace placements "area:<id>"), old orders read as v1, bad v refused', async () => {
  const { call } = await setup();
  const order = { groups: [{ name: 'Command Center', items: ['home'] }, { name: 'area:db', items: ['infra-db'] }], v: 2 };
  assert.equal((await call('PUT', '/api/soc/ui/menu/order', { role: 'admin', body: order })).body.v, 2);
  const seen = (await call('GET', '/api/soc/ui/menu')).body.order;
  assert.equal(seen.v, 2); assert.deepEqual(seen.groups, order.groups);
  await call('PUT', '/api/soc/ui/menu/order', { role: 'admin', body: { groups: order.groups } });
  assert.equal((await call('GET', '/api/soc/ui/menu')).body.order.v, 1);
  for (const v of [0, 10, 1.5, 'x']) assert.equal((await call('PUT', '/api/soc/ui/menu/order', { role: 'admin', body: { groups: order.groups, v } })).status, 400);
});
