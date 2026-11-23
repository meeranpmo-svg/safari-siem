// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Facilities - door access (ZKTeco ZKBioSecurity, read only; prefix {P} = /api/soc).
 *   GET    {P}/facilities/doors                         any role   controllers, doors, 24 h door alarms (no person), actions
 *   GET    {P}/facilities/doors/servers                 any role   connection records (never the token)
 *   POST   {P}/facilities/doors/servers                 admin      add / update a ZKBio server (validated, audited)
 *   DELETE {P}/facilities/doors/servers/:id             admin
 *   PUT    {P}/facilities/doors/servers/:id/token       admin      { token, fingerprint256?, insecure? } -> secrets.json (sealed)
 *   POST   {P}/facilities/doors/servers/:id/sync        operator   read now (the answer is the counts, not the data)
 * CCTV / NVR (cctv.js, Hikvision ISAPI read only):
 *   GET    {P}/facilities/cctv                          any role   recorders, disks, cameras, 7-day availability, group outages, actions
 *   POST   {P}/facilities/cctv/recorders                admin      add / update a recorder (validated, audited)
 *   DELETE {P}/facilities/cctv/recorders/:id            admin
 *   PUT    {P}/facilities/cctv/recorders/:id/credential admin      { user, password, fingerprint256?, insecure? } -> secrets.json (sealed)
 *   POST   {P}/facilities/cctv/recorders/:id/sync       operator   read now
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { createDoors } = require('./doors');
const { createCctv } = require('./cctv');

function register(api, deps) {
  if (!deps.state) throw new Error('facilities needs deps.state');
  const P = prefixOf(deps), D = deps.doors || createDoors(deps);
  deps.doorsInstance = D;
  if (!deps.doors && !deps.noTimers && !(deps.config && deps.config.facilities && deps.config.facilities.enabled === false)) D.start();
  api.route('GET', `${P}/facilities/doors`, wrap(deps, null, () => D.view()));
  api.route('GET', `${P}/facilities/doors/servers`, wrap(deps, null, () => ({ items: D.list() })));
  api.route('POST', `${P}/facilities/doors/servers`, wrap(deps, 'admin', (ctx) => { const s = D.put(body(ctx), ctx.user); audit(ctx, 'facilities.zkbio.put', s.id, { host: s.host, port: s.port, enabled: s.enabled, paths: s.paths }); return s; }));
  api.route('DELETE', `${P}/facilities/doors/servers/:id`, wrap(deps, 'admin', (ctx) => { const r = D.remove(ctx.params.id, ctx.user); audit(ctx, 'facilities.zkbio.remove', ctx.params.id); return r; }));
  api.route('PUT', `${P}/facilities/doors/servers/:id/token`, wrap(deps, 'admin', (ctx) => { const b = body(ctx); const r = D.setToken(ctx.params.id, b, ctx.user); audit(ctx, 'facilities.zkbio.token', ctx.params.id, { set: true, pinned: !!b.fingerprint256, insecure: !!b.insecure }); return r; }));
  api.route('POST', `${P}/facilities/doors/servers/:id/sync`, wrap(deps, 'operator', async (ctx) => {
    if (!D.get(ctx.params.id)) throw new HttpError(404, 'server not found');
    const s = await D.sync(ctx.params.id);
    audit(ctx, 'facilities.zkbio.sync', ctx.params.id, { ok: !s.error, errors: (s.errors || []).length });
    return { ok: !s.error, error: s.error || null, errors: s.errors || [], devices: s.devices ? s.devices.length : null, doors: s.doors ? s.doors.length : null, alarms: s.events ? s.events.length : null };
  }));

  const C = deps.cctv || createCctv(deps);
  deps.cctvInstance = C;
  if (!deps.cctv && !deps.noTimers && !(deps.config && deps.config.facilities && deps.config.facilities.enabled === false)) C.start();
  api.route('GET', `${P}/facilities/cctv`, wrap(deps, null, () => C.view()));
  api.route('POST', `${P}/facilities/cctv/recorders`, wrap(deps, 'admin', (ctx) => { const r = C.put(body(ctx), ctx.user); audit(ctx, 'facilities.cctv.put', r.id, { host: r.host, port: r.port, https: r.https, enabled: r.enabled }); return r; }));
  api.route('DELETE', `${P}/facilities/cctv/recorders/:id`, wrap(deps, 'admin', (ctx) => { const r = C.remove(ctx.params.id, ctx.user); audit(ctx, 'facilities.cctv.remove', ctx.params.id); return r; }));
  api.route('PUT', `${P}/facilities/cctv/recorders/:id/credential`, wrap(deps, 'admin', (ctx) => { const b = body(ctx); const r = C.setCredential(ctx.params.id, b, ctx.user); audit(ctx, 'facilities.cctv.credential', ctx.params.id, { set: true, pinned: !!b.fingerprint256, insecure: !!b.insecure }); return r; }));
  api.route('POST', `${P}/facilities/cctv/recorders/:id/sync`, wrap(deps, 'operator', async (ctx) => {
    if (!C.get(ctx.params.id)) throw new HttpError(404, 'recorder not found');
    const s = await C.sync(ctx.params.id);
    audit(ctx, 'facilities.cctv.sync', ctx.params.id, { ok: !s.error, errors: (s.errors || []).length });
    return { ok: !s.error, error: s.error || null, errors: s.errors || [], cameras: s.status ? s.status.length : null, disks: s.disks ? s.disks.length : null };
  }));
}

module.exports = { register, createDoors };
