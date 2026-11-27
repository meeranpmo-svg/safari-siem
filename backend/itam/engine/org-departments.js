// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Departments - the organisation's own department register, customised by an administrator, used by HR onboarding, Work From
 * Home and the asset register. It starts from the company setting (brand departments) and becomes the register on the first save.
 *   department  {id, name, name_ar, code, company, parent, head (platform user), cost_center, branches[], active,
 *                template: {laptop_profile, mailbox, vpn, m365, groups[], licences[]}}   - the joiner template: what a new joiner
 *                of this department normally gets, prefilled in HR onboarding (the person still decides, the four-eyes stay)
 *   suggestions department names found in the data (assets, onboarding requests) that the register does not have - learned, for
 *                an administrator to add or merge
 *   rename / merge   an administrator renames a department or merges one into another: the asset register's records follow
 *                (the department field), counted and audited; a merged department is kept inactive with its "merged into"
 *   GET  /org/departments                  viewer   the register (+ suggestions for operators)
 *   PUT  /org/departments/:id              admin    create or update (validated, audited)
 *   POST /org/departments/:id/merge        admin    {into, reason}  records follow, audited
 *   GET  /org/departments/:id/template     operator the joiner template (HR onboarding)
 */
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const ID = /^[a-z][a-z0-9_-]{1,39}$/;
const PROFILES = ['standard', 'power', 'executive'];
const PRIVILEGED = /domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|group policy creator/i;
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();

function createDepartments(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const col = () => app.store.collection('org_departments');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'org.department.' + action, target, detail }); };
  const seed = () => (Array.isArray(ZYB_ORG.departments) ? ZYB_ORG.departments : []).map((d) => (typeof d === 'string' ? { id: d.toLowerCase().replace(/[^a-z0-9]+/g, '_'), name: d } : { id: String(d.id), name: String(d.name || d.id) }))
    .map((d) => ({ id: d.id, name: d.name, name_ar: '', code: '', company: ZYB_ORG.name || '', parent: '', head: '', cost_center: '', branches: [], active: true, template: { laptop_profile: 'standard', mailbox: true, vpn: false, m365: true, groups: [], licences: [] }, from: 'company setting' }));
  const stored = () => col().all();
  function list(includeInactive) { const S = stored(), L = S.length ? S : seed(); return L.filter((d) => includeInactive || d.active !== false).sort((a, b) => a.name.localeCompare(b.name)); }
  function find(nameOrId) { const k = low(nameOrId); return list(true).find((d) => d.id === k || low(d.name) === k || (d.name_ar && d.name_ar === String(nameOrId).trim())) || null; }
  function materialise(who) { if (stored().length) return; for (const d of seed()) col().put(Object.assign({}, d, { from: 'company setting', created_by: who.user, created_at: iso() })); }

  function suggestions() {   // department names in the data the register does not know
    const known = new Set(list(true).flatMap((d) => [low(d.name), d.id, low(d.name_ar)])), seen = new Map();
    const add = (v, where) => { const k = low(v); if (!k || known.has(k)) return; const x = seen.get(k) || { name: String(v).trim(), assets: 0, onboarding: 0 }; x[where]++; seen.set(k, x); };
    for (const a of app.store.collection('assets').all((x) => x.status !== 'deleted')) add(a.department, 'assets');
    for (const r of app.store.collection('onboarding').all()) add(r.department, 'onboarding');
    return [...seen.values()].sort((a, b) => (b.assets + b.onboarding) - (a.assets + a.onboarding)).slice(0, 50);
  }
  function usage() { const u = {}; for (const a of app.store.collection('assets').all((x) => x.status !== 'deleted')) { const d = a.department && find(a.department); if (d) u[d.id] = (u[d.id] || 0) + 1; } return u; }

  function view(role) {
    const op = ['operator', 'admin'].includes(role), U = usage();
    return { departments: list(true).map((d) => Object.assign({}, d, { assets: U[d.id] || 0 })), from_company_setting: !stored().length, enforced: stored().length > 0, profiles: PROFILES,
      companies: [...new Set(list(true).map((d) => d.company).filter(Boolean))].sort(), suggestions: op ? suggestions() : [] };
  }

  function put(id0, b0, who) {
    if (!isHuman(who.user)) throw bad('a person changes the department register', 403);
    const id = param(id0, 'id'); if (!ID.test(id)) throw bad('id: 2-40 lower-case letters, digits, _ or - starting with a letter');
    const b = body(b0 || {}).str('name', { required: true, min: 2, max: 120 }).str('name_ar', { max: 120 }).str('code', { max: 20, re: /^[A-Za-z0-9._-]*$/, msg: 'code: letters, digits, . _ -' })
      .str('company', { max: 120 }).str('parent', { max: 40 }).str('head', { max: 64, re: /^[A-Za-z0-9._@-]*$/, msg: 'head: a platform user name' }).str('cost_center', { max: 40 })
      .list('branches', { max: 50, item: 'str', itemMax: 120, unique: true, def: [] }).bool('active', { def: true }).done();
    const t0 = (b0 && b0.template) || {};
    if (t0 && (typeof t0 !== 'object' || Array.isArray(t0))) throw bad('template must be an object');
    const t = body(t0).oneOf('laptop_profile', PROFILES, { def: 'standard' }).bool('mailbox', { def: true }).bool('vpn', { def: false }).bool('m365', { def: true })
      .list('groups', { max: 30, item: 'str', itemMax: 120, unique: true, def: [] }).list('licences', { max: 10, item: 'str', itemMax: 80, unique: true, def: [] }).done();
    const priv = t.groups.filter((g) => PRIVILEGED.test(g)); if (priv.length) throw bad('template.groups: ' + priv.join(', ') + ' is privileged - a joiner never gets it through onboarding');
    if (b.parent && (b.parent === id || !find(b.parent))) throw bad('parent: an existing department other than itself');
    materialise(who);
    const clash = list(true).find((d) => d.id !== id && low(d.name) === low(b.name)); if (clash) throw bad('name: "' + b.name + '" is already department ' + clash.id, 409);
    const prev = col().get(id), rec = Object.assign({}, prev || {}, b, { id, template: t, updated_by: who.user, updated_at: iso() }, prev ? {} : { created_by: who.user, created_at: iso() });
    let moved = 0;
    if (prev && low(prev.name) !== low(b.name)) moved = follow(prev.name, b.name, who);   // a rename: the asset records follow
    col().put(rec);
    audit(who, prev ? 'update' : 'create', id, { name: b.name, company: b.company || null, head: b.head || null, active: b.active, template: { profile: t.laptop_profile, groups: t.groups.length, licences: t.licences.length }, renamed_from: prev && low(prev.name) !== low(b.name) ? prev.name : undefined, records_moved: moved || undefined });
    return Object.assign(view(who.role), { saved: id, records_moved: moved });
  }
  function follow(from, to, who) {   // asset records with the old department name take the new one
    let n = 0; for (const a of app.store.collection('assets').all((x) => x.status !== 'deleted' && low(x.department) === low(from))) {
      if (app.assets && typeof app.assets.assign === 'function') app.assets.assign(a.id, { department: to }, who); else app.store.collection('assets').patch(a.id, (o) => { o.department = to; return o; }); n++; }
    return n;
  }
  function merge(id0, b0, who) {
    if (!isHuman(who.user)) throw bad('a person merges departments', 403);
    const id = param(id0, 'id'), b = body(b0 || {}).str('into', { required: true, max: 40 }).str('reason', { required: true, min: 5, max: 300 }).done();
    materialise(who);
    const from = col().get(id), into = col().get(b.into); if (!from) throw bad('department ' + id + ' not found', 404); if (!into || into.id === id) throw bad('into: another existing department');
    const moved = follow(from.name, into.name, who);
    // free-text names found in the data can be merged too: the suggestion's name follows
    col().patch(id, (o) => { o.active = false; o.merged_into = into.id; o.merged_at = iso(); o.merged_by = who.user; return o; });
    audit(who, 'merge', id, { into: into.id, records_moved: moved, reason: b.reason });
    return Object.assign(view(who.role), { merged: id, into: into.id, records_moved: moved });
  }
  function mergeName(b0, who) {   // a department name found in the data (a suggestion) into a register department
    if (!isHuman(who.user)) throw bad('a person merges departments', 403);
    const b = body(b0 || {}).str('name', { required: true, max: 120 }).str('into', { required: true, max: 40 }).done(), into = find(b.into);
    if (!into) throw bad('into: an existing department'); const moved = follow(b.name, into.name, who);
    audit(who, 'merge_name', into.id, { name: b.name, records_moved: moved }); return Object.assign(view(who.role), { records_moved: moved });
  }
  function template(nameOrId) { const d = find(nameOrId); if (!d) throw bad('department not in the register: ' + String(nameOrId).slice(0, 80), 404); return { department: d.name, id: d.id, head: d.head || null, branches: d.branches || [], template: d.template || {} }; }
  // the register is enforced once an administrator has saved it (before that, the company setting only suggests names)
  const enforced = () => stored().length > 0;
  return { list, find, view, put, merge, mergeName, template, suggestions, enforced, PROFILES };
}

function registerDepartments(srv, app, X) {
  srv.route('GET', '/org/departments', (ctx) => { ctx.need('viewer'); return X.view(ctx.who.role); });
  srv.route('PUT', '/org/departments/:id', (ctx) => { ctx.need('admin'); return X.put(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/org/departments/:id/merge', (ctx) => { ctx.need('admin'); return X.merge(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/org/departments-merge-name', (ctx) => { ctx.need('admin'); return X.mergeName(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/org/departments/:id/template', (ctx) => { ctx.need('operator'); return X.template(param(ctx.params.id, 'id')); });
  (app.addons = app.addons || {}).departments = X;
  return X;
}

module.exports = { createDepartments, registerDepartments };
