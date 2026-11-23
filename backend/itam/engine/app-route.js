// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
/*
 * Application Route Map (Databases -> Application Route Map, {P} = /api/itam): every business application as a route from
 * its users to its database - front end, APIs / services, application servers, database service, database (RAC instances) -
 * the same design as the Email Route Map. The state of each hop is judged in Python (pyengine/app_route.py) from facts the
 * page reads from the SIEM as the signed-in person (Applications Manager monitors, the DBA Alert Center, Application
 * Connections); this module keeps the register of applications and passes the facts through.
 *
 * Register (store app_route / id 'profile', versioned): apps[{id, name, url, front_monitor, api_monitors[], machines[],
 * database, services[]}]. An administrator keeps it - it decides what the map calls an application. Every change is
 * audited with what changed; a stale baseVersion is refused (409) so two administrators cannot overwrite each other.
 *
 * Routes: GET  /app-route/profile                  viewer  (application names, monitor ids, host names - no personal data)
 *         POST /app-route {facts}                   viewer  (read-only: judges the facts the page read; nothing is stored)
 *         POST /app-route/apps {...app, baseVersion} admin   (add or change one application)
 *         DELETE /app-route/apps/:id?baseVersion=n  admin
 */
const MAX_APPS = 200;
const ID = /^[a-z0-9][a-z0-9-]{0,40}$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DBN = /^[A-Za-z0-9_$#.-]{1,64}$/;
const s = (v, n) => String(v == null ? '' : v).slice(0, n);
const n0 = (v) => { const x = Number(v); return Number.isFinite(x) && x >= 0 ? Math.min(x, 1e9) : 0; };
const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

// the facts the page posts: only these fields are kept, each clipped (no field the rules do not read reaches Python)
function cleanFacts(f) {
  f = f && typeof f === 'object' ? f : {};
  const mon = (m) => ({ id: s(m.id, 40), name: s(m.name, 160), type: s(m.type, 80), host: s(m.host, 160), health: s(m.health, 20), availability: s(m.availability, 20), managed: m.managed !== false, message: s(m.message, 300) });
  const inst = (i) => ({ instance: s(i.instance, 64).toUpperCase(), host: s(i.host, 128), level: s(i.level, 10), status: s(i.status, 30), role: s(i.role, 30), crit: n0(i.crit), warn: n0(i.warn) });
  const sess = (x) => ({ machine: s(x.machine, 128), program: s(x.program, 120), service: s(x.service, 120), sessions: n0(x.sessions), state: x.state === 'dropped' ? 'dropped' : 'connected' });
  const lsn = (x) => ({ client_host: s(x.client_host, 128), service: s(x.service, 120), refused: n0(x.refused), reasons: arr(x.reasons, 10).map((c) => ({ code: s(c.code, 8), meaning: s(c.meaning, 160), fix: s(c.fix, 400), n: n0(c.n) })) });
  const map = (o, fn, maxKeys) => { const out = {}; for (const k of Object.keys(o && typeof o === 'object' ? o : {}).slice(0, maxKeys)) if (DBN.test(k)) out[k.toUpperCase()] = fn(o[k]); return out; };
  return {
    apm: { connected: !!(f.apm && f.apm.connected) },
    monitors: arr(f.monitors, 3000).filter((m) => m && m.id != null).map(mon),
    databases: arr(f.databases, 300).filter((d) => d && DBN.test(String(d.database || ''))).map((d) => ({ database: s(d.database, 64).toUpperCase(), instances: arr(d.instances, 16).map(inst) })),
    sessions: f.sessions === null || f.sessions === undefined ? null : map(f.sessions, (x) => ({ reported: !!(x && x.reported), apps: arr(x && x.apps, 2000).map(sess) }), 300),
    listener: map(f.listener, (l) => arr(l, 500).map(lsn), 300),
  };
}

function createAppRoute(app, opts = {}) {
  const col = app.store.collection('app_route'), now = opts.now || Date.now;
  const py = opts.py || require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false });
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const profile = () => col.get('profile') || { id: 'profile', version: 0, apps: [] };
  function checkVersion(b) { const p = profile(); if (b !== undefined && b !== p.version) throw bad('the register changed since you opened it (version ' + p.version + ') - reload and try again', 409); return p; }
  function saveApp(input, who) {
    const v = body(input || {}).str('id', { max: 41, re: ID, msg: 'id must be lower-case letters, digits and -' }).str('name', { required: true, max: 120 })
      .str('url', { max: 300, re: /^https?:\/\/[^\s<>"']+$/, msg: 'url must start with http:// or https://' })
      .str('front_monitor', { max: 40, re: /^[A-Za-z0-9_-]+$/, msg: 'front_monitor must be an Applications Manager monitor id' })
      .list('api_monitors', { item: 'str', itemMax: 40, max: 30, unique: true }).list('machines', { item: 'str', itemMax: 128, max: 40, unique: true })
      .str('database', { max: 64, re: DBN, msg: 'database must be an Oracle database name' }).list('services', { item: 'str', itemMax: 120, max: 20, unique: true })
      .int('baseVersion', { min: 0 })
      .rule((o) => ((o.api_monitors || []).some((x) => !/^[A-Za-z0-9_-]+$/.test(x)) ? 'api_monitors must be Applications Manager monitor ids' : null))
      .rule((o) => ((o.machines || []).some((x) => !HOST.test(x)) ? 'machines must be host names' : null))
      .rule((o) => ((o.services || []).some((x) => !DBN.test(x)) ? 'services must be database service names' : null)).done();
    const p = checkVersion(v.baseVersion);
    const id = v.id || (s(v.name, 40).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'app');
    const cur = p.apps.find((a) => a.id === id);
    if (!v.id && cur) throw bad('an application with this name exists already (' + id + ') - open it to change it', 409);
    if (!cur && p.apps.length >= MAX_APPS) throw bad('the register holds at most ' + MAX_APPS + ' applications');
    if (p.apps.some((a) => a.id !== id && a.name.toLowerCase() === v.name.toLowerCase())) throw bad('another application is already called ' + v.name, 409);
    const rec = { id, name: v.name, url: v.url || '', front_monitor: v.front_monitor || '', api_monitors: v.api_monitors || [], machines: v.machines || [],
      database: v.database ? v.database.toUpperCase() : '', services: (v.services || []).map((x) => x.toUpperCase()), updated_at: new Date(now()).toISOString(), updated_by: who.user };
    const changed = cur ? Object.keys(rec).filter((k) => !/^updated_/.test(k) && JSON.stringify(cur[k]) !== JSON.stringify(rec[k])) : Object.keys(rec).filter((k) => !/^updated_/.test(k));
    const next = { id: 'profile', version: p.version + 1, apps: cur ? p.apps.map((a) => (a.id === id ? rec : a)) : p.apps.concat([rec]) };
    col.put(next);
    audit(who, cur ? 'app_route.app.update' : 'app_route.app.create', id, { name: rec.name, changed, database: rec.database, machines: rec.machines.length, monitors: (rec.front_monitor ? 1 : 0) + rec.api_monitors.length, version: next.version });
    return { app: rec, version: next.version };
  }
  function removeApp(id, baseVersion, who) {
    if (!ID.test(String(id || ''))) throw bad('id must be an application id');
    const p = checkVersion(baseVersion), cur = p.apps.find((a) => a.id === id);
    if (!cur) throw bad('no application ' + id, 404);
    const next = { id: 'profile', version: p.version + 1, apps: p.apps.filter((a) => a.id !== id) };
    col.put(next);
    audit(who, 'app_route.app.delete', id, { name: cur.name, version: next.version });
    return { ok: true, version: next.version };
  }
  async function assess(facts) {
    const r = await py.call('approute.assess', { profile: profile(), facts: cleanFacts(facts) });
    if (!r || r.ok === false || !Array.isArray(r.apps)) {
      if (app.log && app.log.every) app.log.every('app-route:py', 300000, 'warn', 'app-route: the route rules (Python) did not answer', { cls: r && r.error_class, err: s(r && r.error, 200) });
      throw bad('The route rules run in Python and Python did not answer (' + ((r && r.error_class) || 'error') + ') - run the update so pyengine is installed', 409);
    }
    return Object.assign(r, { version: profile().version, generated_at: new Date(now()).toISOString() });
  }
  return { profile, saveApp, removeApp, assess, cleanFacts };
}

function registerAppRouteRoutes(srv, app, A) {
  if (!A || typeof A.assess !== 'function') A = createAppRoute(app, A || {});
  srv.route('GET', '/app-route/profile', (ctx) => { ctx.need('viewer'); return A.profile(); });
  srv.route('POST', '/app-route', async (ctx) => {
    ctx.need('viewer');   // read-only: the facts are what this person could read in the SIEM; nothing is stored
    const b = ctx.body && typeof ctx.body === 'object' ? ctx.body : {};
    if (b.facts !== undefined && (typeof b.facts !== 'object' || Array.isArray(b.facts) || b.facts === null)) throw Object.assign(new Error('facts must be an object'), { status: 400 });
    return A.assess(b.facts || {});
  }, { anyRole: 'a read-only assessment of facts the person already read; nothing is stored' });
  srv.route('POST', '/app-route/apps', (ctx) => { ctx.need('admin'); return A.saveApp(ctx.body, ctx.who); });
  srv.route('DELETE', '/app-route/apps/:id', (ctx) => {
    ctx.need('admin');
    const q = body(ctx.query || {}).str('baseVersion', { required: true, max: 9, re: /^\d+$/, msg: 'baseVersion must be the register version you saw' }).done();
    return A.removeApp(param(ctx.params.id, 'id'), Number(q.baseVersion), ctx.who);
  });
  (app.addons = app.addons || {}).appRoute = A;
  return A;
}

module.exports = { createAppRoute, registerAppRouteRoutes, cleanFacts };
