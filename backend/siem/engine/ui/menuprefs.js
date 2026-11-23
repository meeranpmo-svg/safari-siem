// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Portal menu preferences — the admin's menu order (shared by everyone) and each user's favorites.
 * Used by the portal menu add-on (dashboards/vendor/zyb-menu.js in the shield repository). Identity and role come
 * from the portal login (nginx auth_request → X-Auth-User / X-Auth-Role, see api/server.js), never from the body.
 *
 *   GET    {P}/ui/menu            any signed-in user → { order: {groups:[{name, items:[key]}], updated, updated_by} | null,
 *                                                       favorites: [key], user, can_edit_order }
 *   PUT    {P}/ui/menu/order      admin  { groups:[{name, items:[key]}], v? } → the stored order (replaces it). A group
 *                                       named "area:<id>" places pages inside a Dashboards workspace; v (1-9) is the
 *                                       client's order format, returned as given so it knows its defaults were overridden
 *   DELETE {P}/ui/menu/order      admin  → back to the portal's own order
 *   PUT    {P}/ui/menu/favorites  any    { items:[key] }  → the caller's favorites (max 30)
 *
 * A key is the menu item's view id (data-view) or "link:<path>" for plain links. Keys and group names are validated
 * (length, characters, counts) so the store never holds markup. Writes are audited (ui.menu.order / ui.menu.favorites).
 * Stored in the state collection "ui_prefs": id "menu-order" and "fav:<user>".
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

const KEY_RE = /^(link:\/[A-Za-z0-9._~\/-]{1,200}|[A-Za-z0-9._-]{1,80})$/;
const MAX_GROUPS = 60, MAX_ITEMS = 300, MAX_FAV = 30, MAX_NAME = 120;

function cleanKeys(list, max, what) {
  if (!Array.isArray(list)) throw new HttpError(400, `${what} must be a list`);
  if (list.length > max) throw new HttpError(400, `at most ${max} ${what}`);
  const out = [], seen = new Set();
  for (const k of list) {
    if (typeof k !== 'string' || !KEY_RE.test(k)) throw new HttpError(400, `invalid menu item key in ${what}`);
    if (!seen.has(k)) { seen.add(k); out.push(k); }
  }
  return out;
}

function cleanGroups(groups) {
  if (!Array.isArray(groups) || !groups.length) throw new HttpError(400, 'groups must be a non-empty list');
  if (groups.length > MAX_GROUPS) throw new HttpError(400, `at most ${MAX_GROUPS} groups`);
  let total = 0;
  return groups.map((g) => {
    if (!g || typeof g !== 'object') throw new HttpError(400, 'each group needs a name and items');
    const name = typeof g.name === 'string' ? g.name.replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, MAX_NAME) : '';
    if (!name) throw new HttpError(400, 'each group needs a name');
    const items = cleanKeys(g.items || [], MAX_ITEMS, 'items');
    total += items.length;
    if (total > MAX_ITEMS) throw new HttpError(400, `at most ${MAX_ITEMS} items in total`);
    return { name, items };
  });
}

function register(api, deps) {
  const state = deps.state;
  if (!state) throw new Error('ui/menuprefs needs deps.state');
  const P = prefixOf(deps);
  const col = state.collection('ui_prefs');
  const favId = (user) => 'fav:' + String(user || '').toLowerCase().slice(0, 200);
  const signedIn = (ctx) => { if (!ctx.user) throw new HttpError(401, 'sign in required'); return ctx.user; };

  api.route('GET', `${P}/ui/menu`, wrap(deps, null, (ctx) => {
    const user = signedIn(ctx);
    const o = col.get('menu-order');
    const f = col.get(favId(user));
    return ctx.ok({ order: o ? { groups: o.groups, v: o.v || 1, updated: o.updated, updated_by: o.updated_by } : null,
      favorites: f ? f.items : [], user, can_edit_order: ctx.role === 'admin' });
  }));

  api.route('PUT', `${P}/ui/menu/order`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx), groups = cleanGroups(b.groups);
    const v = b.v == null ? 1 : Number(b.v);
    if (!Number.isInteger(v) || v < 1 || v > 9) throw new HttpError(400, 'v must be a whole number from 1 to 9');
    const doc = { id: 'menu-order', groups, v, updated: Date.now(), updated_by: ctx.user || '' };
    col.put(doc);
    audit(ctx, 'ui.menu.order', 'menu-order', { groups: groups.length, items: groups.reduce((n, g) => n + g.items.length, 0) });
    return ctx.ok({ groups: doc.groups, v: doc.v, updated: doc.updated, updated_by: doc.updated_by });
  }));

  api.route('DELETE', `${P}/ui/menu/order`, wrap(deps, 'admin', (ctx) => {
    col.remove('menu-order');
    audit(ctx, 'ui.menu.order.reset', 'menu-order', {});
    return ctx.ok({ order: null });
  }));

  api.route('PUT', `${P}/ui/menu/favorites`, wrap(deps, null, (ctx) => {
    const user = signedIn(ctx);
    const items = cleanKeys(body(ctx).items, MAX_FAV, 'favorites');
    col.put({ id: favId(user), user, items, updated: Date.now() });
    audit(ctx, 'ui.menu.favorites', user, { count: items.length });
    return ctx.ok({ favorites: items });
  }), { anyRole: 'each person saves only their own menu favorites' });
}

module.exports = { register, cleanKeys, cleanGroups };
