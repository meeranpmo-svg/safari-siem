// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared list of locations (sites) for the IT Asset Register and the inventory: add a location before any asset is
// there, edit its name / city / kind, and rename it on every inventory asset that uses it.
//   GET  /locations                      {locations[]}  saved locations + every site used by an inventory asset  operator
//   POST /locations                      {name, city?, kind?: main|dr|branch|cloud|other, address?, notes?}      admin
//   POST /locations/:id                  same fields; a new name renames the site on the inventory assets      admin
//   POST /locations/:id/delete           only when no inventory asset uses it                                  admin
// (The IT Asset Register's own records live in the portal's /api/db - the portal add-on renames them there.)
// Self-contained (stored collections), added to an existing install with one registration line (install/add-locations.sh).
const crypto = require('node:crypto');

const KINDS = ['main', 'dr', 'branch', 'cloud', 'other'];
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max || 120);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const key = (n) => s(n).toLowerCase();

function createLocations(app, opts = {}) {
  const { store } = app;
  const col = store.collection('locations'), assets = store.collection('assets');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;

  function list() {
    const used = {};
    for (const a of assets.all()) { const k = key(a.site); if (k) { used[k] = used[k] || { name: s(a.site), count: 0 }; used[k].count++; } }
    const out = col.all().map((l) => Object.assign({}, l, { assets: (used[key(l.name)] || {}).count || 0, saved: true }));
    const have = new Set(out.map((l) => key(l.name)));
    for (const k of Object.keys(used)) if (!have.has(k)) out.push({ id: null, name: used[k].name, city: '', kind: '', assets: used[k].count, saved: false });
    return { locations: out.sort((a, b) => a.name.localeCompare(b.name)), kinds: KINDS };
  }
  function fields(b, cur) {
    const o = Object.assign({}, cur || {});
    if (!cur || 'name' in b) { o.name = s(b.name); if (!o.name) throw bad('a location name is required'); }
    if ('city' in b) o.city = s(b.city, 80);
    if ('kind' in b) { const k = s(b.kind, 20).toLowerCase(); if (k && !KINDS.includes(k)) throw bad('kind must be one of ' + KINDS.join(', ')); o.kind = k; }
    if ('address' in b) o.address = s(b.address, 300);
    if ('notes' in b) o.notes = s(b.notes, 500);
    return o;
  }
  function clash(name, id) { const k = key(name); return col.all((l) => key(l.name) === k && l.id !== id)[0]; }
  function create(b, who) {
    const o = fields(b || {});
    if (clash(o.name)) throw bad(`location "${o.name}" already exists`, 409);
    o.id = 'loc_' + crypto.randomBytes(5).toString('hex'); o.created_by = who.user; o.created_at = new Date(now()).toISOString();
    col.put(o);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'location.create', target: o.id, detail: { name: o.name, city: o.city, kind: o.kind } });
    return Object.assign(list(), { location: o });
  }
  // an inventory site that was never saved can be edited too: it is saved first (id "site:<name>")
  function edit(id, b, who) {
    let cur = col.get(String(id || ''));
    if (!cur && /^site:/.test(String(id))) { const nm = String(id).slice(5); cur = { id: 'loc_' + crypto.randomBytes(5).toString('hex'), name: s(nm), created_by: who.user, created_at: new Date(now()).toISOString() }; col.put(cur); }
    if (!cur) throw bad('location not found', 404);
    const o = fields(b || {}, cur), from = cur.name;
    if (key(o.name) !== key(from) && clash(o.name, cur.id)) throw bad(`location "${o.name}" already exists`, 409);
    o.updated_by = who.user; o.updated_at = new Date(now()).toISOString();
    col.put(o);
    let renamed = 0;
    if (o.name !== from) for (const a of assets.all((x) => key(x.site) === key(from))) { assets.patch(a.id, (x) => { x.site = o.name; x.updated_at = o.updated_at; }); renamed++; }
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'location.edit', target: o.id, detail: { from, to: o.name, city: o.city, kind: o.kind, assets_renamed: renamed } });
    return Object.assign(list(), { location: o, renamed });
  }
  function remove(id, who) {
    const cur = col.get(String(id || '')); if (!cur) throw bad('location not found', 404);
    const n = assets.all((x) => key(x.site) === key(cur.name)).length;
    if (n) throw bad(`${n} inventory assets are at "${cur.name}" - move them first`, 409);
    col.remove(cur.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'location.delete', target: cur.id, detail: { name: cur.name } });
    return list();
  }
  return { list, create, edit, remove };
}

// the writes decided in Python (pyengine/addons_write.py, migration step 9f) and committed by engine/py-writer.js; the
// answer (the list after the write) is built here. locations.engine = "node", or a missing Python bridge, keeps Node.js
function registerLocations(srv, app) {
  const L = createLocations(app);
  const W = (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.locations) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const w = (op, spec, who, node) => (W ? W.write(op, Object.assign({ own: ['locations', 'assets'], reads: ['locations', 'assets'], newId: () => 'loc_' + crypto.randomBytes(5).toString('hex') }, spec), who, node) : node());
  app.locationsWriteStats = () => (W ? W.stats() : null);
  srv.route('GET', '/locations', (ctx) => { ctx.need('operator'); return L.list(); });
  srv.route('POST', '/locations', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; return w('locations.create', { extra: { body: b }, after: (r) => Object.assign(L.list(), r) }, ctx.who, () => L.create(b, ctx.who)); });
  srv.route('POST', '/locations/:id/delete', (ctx) => { ctx.need('admin'); return w('locations.delete', { extra: { id: ctx.params.id }, after: () => L.list() }, ctx.who, () => L.remove(ctx.params.id, ctx.who)); });
  srv.route('POST', '/locations/:id', (ctx) => { ctx.need('admin'); const id = decodeURIComponent(ctx.params.id), b = ctx.body || {}; return w('locations.edit', { extra: { id, body: b }, after: (r) => Object.assign(L.list(), r) }, ctx.who, () => L.edit(id, b, ctx.who)); });
  return L;
}

module.exports = { createLocations, registerLocations, KINDS };
