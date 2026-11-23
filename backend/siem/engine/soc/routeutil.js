// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared helpers for engine/detect/routes.js and engine/soc/routes.js (ARCH "Internal interfaces" → createApi ctx).

class HttpError extends Error {
  constructor(code, msg, errors) { super(msg); this.code = code; this.errors = errors || [msg]; }
}

// approval scopes (owned by IT Asset Management's Roles & Functions, pushed to approvers/routes.js)
// group scopes (infra / security) and one scope per AI engineer (eng:<id>) - approvers/scopes.js
const SC = require('../approvers/scopes');
const APPROVE_SCOPES = SC.SCOPES;
// scope: one scope or a list (any of them); an engineer scope is also covered by its group
function approverAllows(deps, user, scope) {
  try {
    if (!SC.isHuman(user)) return false;
    const m = deps && deps.state && deps.state.collection('approvers').get('map'), u = String(user || '').trim().toLowerCase();
    const held = Object.entries((m && m.scopes) || {}).filter(([, l]) => Array.isArray(l) && l.includes(u)).map(([k]) => k);
    return SC.allows(held, scope);
  } catch (e) { return false; }
}

function prefixOf(deps) {
  const p = (deps && deps.config && deps.config.api_prefix) || '/api/soc';
  return p.replace(/\/+$/, '');
}

/**
 * wrap(deps, role, fn) → handler(ctx)
 *   role: null (any authenticated user — nginx already enforced the session), 'operator', 'admin', or 'approve:<scope>'
 *         (an administrator, or an operator on the approver list for that scope - approvers/routes.js), or a function
 *         (ctx) → 'approve:<scope>[|<scope>…]' when the scope depends on the request (which AI engineer proposed it).
 *         Only a person approves: a service / AI identity is refused even as admin.
 *   ctx.need(role) is called first; if it returns false (or throws) the handler stops — the core server is expected to
 *   have answered 403 already; the core server's ctx.need throws an error with .status 403, which is passed on unchanged).
 *   Errors with a numeric .code (HttpError / WorkflowError) or .status become ctx.fail(code, message, errors[]) —
 *   the core server replies 4xx as {error, errors:[…]} (the portal lists `errors`).
 */
function wrap(deps, role, fn) {
  const log = (deps && deps.log) || { error() {} };
  return async (ctx) => {
    let r = role;
    if (typeof r === 'function') { try { r = r(ctx); } catch (e) { r = 'approve:infra|security'; } }
    if (r && r.startsWith('approve:')) {
      const scopes = r.slice(8).split('|').filter(Boolean), base = String(ctx.role || '').toLowerCase();
      if (!SC.isHuman(ctx.user)) return ctx.fail(403, 'only a person approves: ' + String(ctx.user || 'this identity') + ' is a service / AI identity');
      if (base !== 'admin') {
        if (typeof ctx.need === 'function' && ctx.need('operator') === false) return undefined;
        if (!approverAllows(deps, ctx.user, scopes)) return ctx.fail(403, `approving this needs an administrator, or a human approver for ${scopes.map(SC.label).join(' / ')} (Roles & Functions)`);
      }
    } else if (r && typeof ctx.need === 'function' && ctx.need(r) === false) return undefined;
    try {
      return await fn(ctx);
    } catch (e) {
      const code = e && Number.isInteger(e.code) ? e.code : e && Number.isInteger(e.status) ? e.status : 0;
      if (code >= 400 && code < 600) return ctx.fail(code, e.message, Array.isArray(e.errors) && e.errors.length ? e.errors.map(String) : [e.message]);
      log.error('soc api handler failed', { path: ctx.path, err: e && e.message });
      ctx._err = e;   // the server reports it to the error register (Platform Health) with the real cause
      return ctx.fail(500, 'internal error');
    }
  };
}

function audit(ctx, action, target, detail) {
  if (typeof ctx.audit === 'function') ctx.audit(action, target, detail === undefined ? {} : detail);
}

function body(ctx) {
  const b = ctx.body;
  return b && typeof b === 'object' && !Array.isArray(b) ? b : {};
}

function timeParam(v, dflt) {
  if (v === undefined || v === null || v === '') return dflt;
  const n = Number(v);
  if (Number.isFinite(n)) return n < 1e11 ? n * 1000 : n; // seconds or ms
  const t = Date.parse(v);
  if (!Number.isFinite(t)) throw new HttpError(400, `invalid time "${v}"`);
  return t;
}

module.exports = { HttpError, wrap, audit, body, timeParam, prefixOf, APPROVE_SCOPES, approverAllows };
