// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Approvers: who besides an administrator may approve which kind of change. The list is OWNED by IT Asset Management
 * (Roles & Functions: a job role carries approval scopes) and pushed here on every change and every 10 minutes; this
 * module only stores it so the SIEM's own approval routes can enforce the same rule (soc/routeutil.js wrap(deps,
 * 'approve:<scope>')). Base level is untouched: an approver is an operator - no users, no settings. Four-eyes stays in
 * each approval itself.
 *   POST {P}/approvers  {scopes: {infra: [user…], security: [user…]}, access?: {user: [function…]}}   admin (IT Asset Management, as system)
 *   GET  {P}/approvers                                                  operator
 * access: the people whose job role is an engineer role (Roles & Functions) and the engineer functions they are limited to.
 * Their requests here are refused unless the route is one of theirs (approvers/access.js, the same file as IT Asset
 * Management's engine/access-scopes.js) - the server-side half of the menu the pages already narrow. A push without
 * `access` (an older IT Asset Management) leaves the stored list as it was.
 */
const { HttpError, wrap, audit, body, prefixOf, APPROVE_SCOPES } = require('../soc/routeutil');

const AC = require('./access');

const USER_RE = /^[A-Za-z0-9._@\\-]{1,100}$/;

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), col = deps.state.collection('approvers');
  api.route('GET', `${P}/approvers`, wrap(deps, 'operator', (ctx) => { const m = col.get('map'); return ctx.ok({ scopes: APPROVE_SCOPES, approvers: (m && m.scopes) || {}, updated_at: m ? m.updated_at : null, by: m ? m.by : null }); }));
  api.route('POST', `${P}/approvers`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx), sc = b.scopes;
    if (!sc || typeof sc !== 'object' || Array.isArray(sc)) throw new HttpError(400, 'scopes must be an object {scope: [user, …]}');
    const out = {};
    for (const [k, v] of Object.entries(sc)) {
      if (!Object.prototype.hasOwnProperty.call(APPROVE_SCOPES, k)) throw new HttpError(400, `unknown approval scope "${String(k).slice(0, 30)}"`);
      if (!Array.isArray(v) || v.length > 200) throw new HttpError(400, `${k}: a list of up to 200 user names`);
      out[k] = [...new Set(v.map((u) => String(u).trim().toLowerCase()))].filter((u) => { if (!USER_RE.test(u)) throw new HttpError(400, `${k}: invalid user name`); return true; }).sort();
    }
    let access = null;
    if (b.access !== undefined) {
      if (!b.access || typeof b.access !== 'object' || Array.isArray(b.access)) throw new HttpError(400, 'access must be an object {user: [function, …]}');
      const ent = Object.entries(b.access); if (ent.length > 2000) throw new HttpError(400, 'access: at most 2000 people');
      access = {};
      for (const [u0, fns] of ent) {
        const u = String(u0).trim().toLowerCase(); if (!USER_RE.test(u)) throw new HttpError(400, 'access: invalid user name');
        if (!Array.isArray(fns) || !fns.length || fns.length > AC.ENGINEER_FNS.length) throw new HttpError(400, `access.${u}: a list of engineer functions`);
        for (const f of fns) if (!AC.ENGINEER_FNS.includes(f)) throw new HttpError(400, `access.${u}: unknown engineer function "${String(f).slice(0, 30)}" (${AC.ENGINEER_FNS.join(', ')})`);
        access[u] = [...new Set(fns)].sort();
      }
    }
    const prev = col.get('map'), changed = JSON.stringify((prev && prev.scopes) || {}) !== JSON.stringify(out);
    col.put({ id: 'map', scopes: out, updated_at: new Date().toISOString(), by: ctx.user });
    if (changed) audit(ctx, 'approvers.update', 'approvers', { scopes: out });
    let accessChanged = false;
    if (access) {
      const pa = col.get('access'); accessChanged = JSON.stringify((pa && pa.users) || {}) !== JSON.stringify(access);
      col.put({ id: 'access', users: access, updated_at: new Date().toISOString(), by: ctx.user });
      if (accessChanged) audit(ctx, 'access.update', 'engineer access', { users: access });
    }
    return ctx.ok({ ok: true, changed, access_changed: accessChanged });
  }));

  // the server-side boundary for engineer job roles: a restricted person's request outside their routes is refused before
  // any route runs. Refusals are audited at most once per person and route group every 10 minutes (a page that polls a
  // refused route must not flood the audit trail).
  if (typeof api.gate === 'function') {
    const refused = new Map();
    api.gate((ctx) => {
      const u = String(ctx.user || '').trim().toLowerCase(); if (!u || String(ctx.role || '').toLowerCase() === 'admin') return null;
      const a = col.get('access'), fns = a && a.users && Object.prototype.hasOwnProperty.call(a.users, u) ? a.users[u] : null;
      if (!Array.isArray(fns) || !fns.length) return null;
      const rel = ctx.path.startsWith(P) ? ctx.path.slice(P.length) : ctx.path;
      if (AC.allows('soc', fns, rel)) return null;
      const seg = rel.split('/')[1] || '', key = u + '|' + seg, t = Date.now();
      if (!refused.has(key) || t - refused.get(key) > 600000) { refused.set(key, t); if (refused.size > 5000) refused.clear(); audit(ctx, 'access.refused', ctx.method + ' ' + P + '/' + seg, { functions: fns, reason: 'outside the job role' }); }
      return 'not part of your job role - an administrator can change it in Roles & Functions';
    });
  }
}

module.exports = { register };
