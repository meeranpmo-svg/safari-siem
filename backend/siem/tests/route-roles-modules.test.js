// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The five route modules that had no test of their own (tests/contract-baseline.json): engine/ksc/routes, engine/zscaler/routes,
// engine/integrations/routes, engine/compliance/routes, engine/onboard/bulk. For EVERY route each one registers, the role it
// declares in its source (wrap(deps, '<role>' | 'approve:<scope>' | null)) is the role it enforces: a viewer is refused every
// change, an operator every admin / approval route, and the handler never runs when refused; a write by an administrator is
// audited (who, role, what). The modules' engines are stand-ins (no Kaspersky, Zscaler, ManageEngine or ClickHouse here).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');

const MODULES = [
  { file: 'engine/ksc/routes.js', load: () => require('../engine/ksc/routes'), deps: (s) => ({ ksc: s, config: { ksc: { enabled: false } } }), write: ['POST', '/api/soc/ksc/servers', 'ksc.server.put'] },
  { file: 'engine/zscaler/routes.js', load: () => require('../engine/zscaler/routes'), deps: (s) => ({ zscaler: s, config: { zscaler: { enabled: false } } }), write: ['POST', '/api/soc/zscaler/tenants', 'zscaler.tenant.put'] },
  { file: 'engine/integrations/routes.js', load: () => require('../engine/integrations/routes'), deps: (s) => ({ integrations: { manageengine: s }, config: {} }), write: ['POST', '/api/soc/integrations/manageengine/queue/purge', 'integrations.manageengine.queue.purge'] },
  { file: 'engine/compliance/routes.js', load: () => require('../engine/compliance/routes'), deps: (s) => ({ compliance: { sama: s, grcPush: s }, config: {} }), write: null },
  { file: 'engine/onboard/bulk.js', load: () => require('../engine/onboard/bulk'), deps: () => ({ config: {} }), bulk: true, write: null },
];
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const quiet = { info() {}, warn() {}, error() {}, debug() {}, every() {}, child() { return quiet; } };

// a stand-in engine: every property is a function that records the call and answers an object (never a network call)
function standIn(calls) {
  const fn = (name) => (...a) => { calls.push(name); return name === 'findings' ? [] : name === 'list' ? [] : {}; };
  return new Proxy({}, { get: (_, k) => (k === 'then' ? undefined : k === 'changes' ? standIn(calls) : k === 'DEFAULTS' ? {} : fn(String(k))) });
}
// the role each route declares, read from the module's own source
function declared(file) {
  const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), out = [];
  const re = /api\.route\(\s*'(GET|POST|PUT|DELETE)'\s*,\s*(`[^`]+`|'[^']+'|\w+)\s*,\s*wrap\(\s*deps\s*,\s*(null|'[^']+')/g;
  let m; while ((m = re.exec(src))) out.push({ method: m[1], role: m[3] === 'null' ? null : m[3].slice(1, -1) });
  return out;
}
function ctxFor(role, user, routeParams) {
  const o = { s: 200 };
  return { o, ctx: { role, user, ip: '10.0.0.9', body: {}, params: Object.assign({ id: 'x1', control: '3.3.14' }, routeParams || {}), query: {}, res: null,
    need(r) { if ((RANK[role] || 0) < RANK[r]) { o.s = 403; return false; } return true; },
    ok(b) { o.b = b; return b; }, fail(c, msg) { o.s = c; o.b = { error: msg }; return o.b; }, audit(a, t, d) { (o.audits = o.audits || []).push({ a, t, d, by: user, role }); } } };
}

for (const M of MODULES) {
  test(M.file + ': every route enforces the role it declares; a refused call never runs; an admin write is audited', async () => {
    const calls = [], routes = [], api = { route: (method, p, h) => routes.push({ method, p, h }) };
    const deps = Object.assign({ state: { collection: () => ({ get: () => null, put: (o) => o, all: () => [], remove() {} }) }, log: quiet }, M.deps(standIn(calls)));
    const mod = M.load();
    if (M.bulk) mod.register(api, deps, { B: '/api/soc/onboard', store: standIn(calls) }); else mod.register(api, deps);
    const decl = declared(M.file);
    assert.ok(routes.length >= decl.length && decl.length > 0, M.file + ': routes registered ' + routes.length + ', declared ' + decl.length);
    for (const r of routes) {
      const d = decl.find((x, i) => x.method === r.method && !x.used && (x.used = true));
      if (!d) continue;   // a route built by a helper (its own tests cover it)
      const needs = d.role === null ? null : d.role.startsWith('approve:') ? 'approve' : d.role;
      if (needs) {   // a viewer never passes a declared role
        const n0 = calls.length, { o, ctx } = ctxFor('viewer', 'vera.syn'); await r.h(ctx);
        assert.equal(o.s, 403, `${r.method} ${r.p}: a viewer is refused (declared ${d.role})`); assert.equal(calls.length, n0, `${r.method} ${r.p}: the refused call did not run`);
      }
      if (needs === 'admin' || needs === 'approve') {   // an operator who is not an approver is refused admin and approval routes
        const n0 = calls.length, { o, ctx } = ctxFor('operator', 'omar.syn'); await r.h(ctx);
        assert.equal(o.s, 403, `${r.method} ${r.p}: an operator is refused (declared ${d.role})`); assert.equal(calls.length, n0);
      }
      if (r.method === 'GET' && needs === null) { const { o, ctx } = ctxFor('viewer', 'vera.syn'); await r.h(ctx); assert.notEqual(o.s, 403, `${r.method} ${r.p}: a signed-in viewer may read`); }
    }
    if (M.write) {
      const r = routes.find((x) => x.method === M.write[0] && x.p === M.write[1]); assert.ok(r, 'write route ' + M.write[1]);
      const { o, ctx } = ctxFor('admin', 'syed.syn'); ctx.body = { host: 'ksc.syn.local', name: 'synthetic' }; await r.h(ctx);
      assert.notEqual(o.s, 403); assert.ok((o.audits || []).some((a) => a.a === M.write[2] && a.by === 'syed.syn' && a.role === 'admin'), M.write[1] + ': audited with who and role: ' + JSON.stringify(o.audits));
    }
  });
}
