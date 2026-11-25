// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * FortiGate fleet through FortiManager (netops/fmg.js):
 *   GET  {P}/fortimanager/settings           settings; keys only as set / not set; poll status                        admin
 *   PUT  {P}/fortimanager/settings           {enabled, base_url, adoms[], poll_min, tls_fingerprint, firmware_targets[],
 *                                             write_enabled, api_key?, write_key?}                                      admin
 *   POST {P}/fortimanager/test               sign in, list ADOMs and devices (read key)                                admin
 *   POST {P}/fortimanager/poll               poll now                                                                 operator
 *   GET  {P}/fortimanager/fleet              KPIs, devices with health + findings, models / firmware, SD-WAN links     viewer
 *   GET  {P}/fortimanager/devices/:id        one FortiGate                                                            viewer
 *   GET  {P}/fortimanager/changes            change plans                                                             viewer
 *   POST {P}/fortimanager/changes            propose {type, devices[], package?, version?, window?, reason}          operator
 *   POST {P}/fortimanager/changes/:id/decide {decision, comment}  a different PERSON with the firewall scope  approve:eng:security
 *   POST {P}/fortimanager/changes/:id/run    install-package only, with the write key                                operator
 *   POST {P}/fortimanager/changes/:id/refresh follow the FortiManager task                                           operator
 *   POST {P}/fortimanager/changes/:id/done   {note}  a plan carried out in FortiManager by a person                   operator
 * Keys: secrets.json "fortimanager.api_key / write_key" (sealed at rest, write-only, never logged, never audited).
 */
const fs = require('node:fs');
const SF = require('../secretfile');
const { body, param } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { guard } = require('../util/errors');
const { createFmg, NAME } = require('./fmg');

const FP = /^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$/;
function register(api, deps) {
  const P = prefixOf(deps), cfg = deps.config, writeJson = require('../onboard/store').writeJsonAtomic, log = deps.log || { info() {}, warn() {}, error() {} };
  if (!deps.state) throw new Error('fortimanager needs deps.state');
  const secretsObj = () => { if (!cfg.secrets) Object.defineProperty(cfg, 'secrets', { value: {}, writable: true, configurable: true }); return cfg.secrets; };
  const F = deps.fmg || createFmg({ config: cfg, secrets: secretsObj(), state: deps.state, log, transport: deps.fmgTransport, now: deps.now });
  const sec = () => secretsObj().fortimanager || {};
  const read = (p) => { try { if (SF.isSecretsPath(p)) return SF.read(p) || {}; return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw new HttpError(500, `cannot read ${p}`); } };
  const view = () => { const c = cfg.fortimanager || {}; return { enabled: !!c.enabled, base_url: c.base_url || '', adoms: c.adoms || [], poll_min: c.poll_min || 10, tls_fingerprint: c.tls_fingerprint || '', firmware_targets: c.firmware_targets || [],
    write_enabled: !!c.write_enabled, api_key_set: !!sec().api_key, write_key_set: !!sec().write_key, status: F.status() }; };

  // the poll: every poll_min while enabled; reschedules in finally so one failure never stops it
  let timer = null, stopped = false;
  const loop = guard('netops.fortimanager.poll', async () => { if ((cfg.fortimanager || {}).enabled && sec().api_key) await F.poll(); });
  function schedule(ms) { if (stopped || deps.noTimer) return; timer = setTimeout(async () => { try { await loop(); } finally { schedule(Math.max(5, (cfg.fortimanager || {}).poll_min || 10) * 60000); } }, ms); if (timer.unref) timer.unref(); }
  schedule(60000);
  if (deps.onShutdown) deps.onShutdown(() => { stopped = true; if (timer) clearTimeout(timer); });

  api.route('GET', `${P}/fortimanager/settings`, wrap(deps, 'admin', () => view()));
  api.route('PUT', `${P}/fortimanager/settings`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx.body).bool('enabled').str('base_url', { max: 200 }).list('adoms', { max: 40, item: 'str', itemMax: 63 }).int('poll_min', { min: 5, max: 240 })
      .str('tls_fingerprint', { max: 100 }).list('firmware_targets', { max: 80, item: 'str', itemMax: 80 }).bool('write_enabled').str('api_key', { max: 300 }).str('write_key', { max: 300 }).done();
    const paths = cfg._paths || {}; if (!paths.config || !paths.secrets) throw new HttpError(409, 'config / secrets files not available');
    const c = Object.assign({}, cfg.fortimanager || {});
    if (b.base_url !== undefined) { const u = b.base_url.replace(/\/+$/, ''); if (u && !/^https:\/\/[A-Za-z0-9.-]+(?::\d{2,5})?$/.test(u)) throw new HttpError(400, 'base_url: https://<fortimanager address>[:port], nothing after it'); c.base_url = u; }
    if (b.adoms !== undefined) { const bad = b.adoms.filter((a) => !NAME.test(a)); if (bad.length) throw new HttpError(400, 'adoms: not an ADOM name: ' + bad.slice(0, 3).join(', ')); c.adoms = b.adoms; }
    if (b.poll_min !== undefined) c.poll_min = b.poll_min;
    if (b.tls_fingerprint !== undefined) { if (b.tls_fingerprint && !FP.test(b.tls_fingerprint)) throw new HttpError(400, 'tls_fingerprint: the SHA-256 fingerprint of the FortiManager certificate, AA:BB:… (32 pairs)'); c.tls_fingerprint = b.tls_fingerprint.toUpperCase(); }
    if (b.firmware_targets !== undefined) { const bad = b.firmware_targets.filter((t) => !/^[A-Za-z0-9 ._-]{2,40}=\d{1,2}\.\d{1,2}\.\d{1,3}$/.test(t)); if (bad.length) throw new HttpError(400, 'firmware_targets: model=version, for example FortiGate-60F=7.2.10: ' + bad.slice(0, 3).join(', ')); c.firmware_targets = b.firmware_targets; }
    for (const k of ['api_key', 'write_key']) if (b[k] !== undefined && /\s/.test(b[k])) throw new HttpError(400, k + ': no spaces');
    if (b.enabled !== undefined) c.enabled = b.enabled;
    if (b.write_enabled !== undefined) c.write_enabled = b.write_enabled;
    if (c.enabled && !c.base_url) throw new HttpError(400, 'base_url: needed to switch the FortiManager poll on');
    if (c.enabled && !(b.api_key || sec().api_key)) throw new HttpError(400, 'api_key: needed to switch the FortiManager poll on');
    if (c.write_enabled && !(b.write_key || sec().write_key)) throw new HttpError(400, 'write_key: needed to run approved changes');
    if (b.api_key && b.write_key && b.api_key === b.write_key) throw new HttpError(400, 'write_key: use a separate FortiManager API admin for changes, not the read key');
    const file = read(paths.config); file.fortimanager = Object.assign({}, file.fortimanager || {}, c); writeJson(paths.config, file); cfg.fortimanager = Object.assign(cfg.fortimanager || {}, c);
    if (b.api_key || b.write_key) { const s = read(paths.secrets), m = Object.assign({}, s.fortimanager || {}); if (b.api_key) m.api_key = b.api_key; if (b.write_key) m.write_key = b.write_key; s.fortimanager = m; writeJson(paths.secrets, s); secretsObj().fortimanager = Object.assign(secretsObj().fortimanager || {}, m); }
    audit(ctx, 'netops.fortimanager.config', c.base_url ? new URL(c.base_url).hostname : '', { enabled: !!c.enabled, adoms: (c.adoms || []).length, poll_min: c.poll_min || 10, pinned: !!c.tls_fingerprint, targets: (c.firmware_targets || []).length, write_enabled: !!c.write_enabled, api_key_changed: !!b.api_key, write_key_changed: !!b.write_key });
    return view();
  }));
  api.route('POST', `${P}/fortimanager/test`, wrap(deps, 'admin', async (ctx) => { body(ctx.body).done(); const r = await F.testConnection(); audit(ctx, 'netops.fortimanager.test', '', { ok: r.ok }); return r; }));
  api.route('POST', `${P}/fortimanager/poll`, wrap(deps, 'operator', async (ctx) => {
    body(ctx.body).done(); if (!sec().api_key || !(cfg.fortimanager || {}).base_url) throw new HttpError(409, 'FortiManager is not connected - an administrator adds it in the Integration Hub');
    const s = await F.poll(); audit(ctx, 'netops.fortimanager.poll', '', { devices: s.devices, error: s.last_error ? 'yes' : 'no' }); return s;
  }));
  api.route('GET', `${P}/fortimanager/fleet`, wrap(deps, null, () => F.fleet()));
  api.route('GET', `${P}/fortimanager/devices/:id`, wrap(deps, null, (ctx) => { const id = String(ctx.params.id || ''); if (!/^[A-Za-z0-9 ._()-]{1,63}$/.test(id)) throw new HttpError(400, 'id: a FortiGate serial or name'); return F.device(id); }));
  api.route('GET', `${P}/fortimanager/changes`, wrap(deps, null, () => ({ changes: F.changes(), types: F.TYPES, write_enabled: F.status().write_enabled })));
  api.route('POST', `${P}/fortimanager/changes`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).oneOf('type', Object.keys(F.TYPES), { required: true }).list('devices', { required: true, max: 100, item: 'str', itemMax: 63 }).str('package', { max: 63 }).str('version', { max: 12 }).str('window', { max: 16 }).str('reason', { required: true, max: 600 }).done();
    const c = F.propose(b, ctx.user);
    audit(ctx, 'netops.fortimanager.change.propose', c.id, { type: c.type, devices: c.devices.length, adom: c.adom, package: c.package || null, version: c.version || null });
    return c;
  }));
  const id = (ctx) => param(String(ctx.params.id || ''), 'id');
  api.route('POST', `${P}/fortimanager/changes/:id/decide`, wrap(deps, 'approve:eng:security', async (ctx) => {
    const b = body(ctx.body).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    const c = F.decide(id(ctx), b.decision, ctx.user, b.comment);
    audit(ctx, 'netops.fortimanager.change.' + (b.decision === 'approved' ? 'approve' : 'reject'), c.id, { type: c.type, devices: c.devices.length, proposed_by: c.proposed_by });
    return c;
  }));
  api.route('POST', `${P}/fortimanager/changes/:id/run`, wrap(deps, 'operator', async (ctx) => {
    body(ctx.body).done();
    const c = await F.run(id(ctx), ctx.user);
    audit(ctx, 'netops.fortimanager.change.run', c.id, { type: c.type, devices: c.devices.length, status: c.status, task: c.task == null ? null : c.task });
    if (c.status === 'failed') log.warn('fortimanager: change failed', { id: c.id, err: c.error });
    return c;
  }));
  api.route('POST', `${P}/fortimanager/changes/:id/refresh`, wrap(deps, 'operator', async (ctx) => { body(ctx.body).done(); const before = F.get(id(ctx)); const c = await F.refreshTask(id(ctx)); if (before && before.status !== c.status) audit(ctx, 'netops.fortimanager.change.result', c.id, { status: c.status, task: c.task }); return c; }));
  api.route('POST', `${P}/fortimanager/changes/:id/done`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).str('note', { required: true, max: 400 }).done(); const c = F.markDone(id(ctx), ctx.user, b.note);
    audit(ctx, 'netops.fortimanager.change.done', c.id, { type: c.type, devices: c.devices.length });
    return c;
  }));
  return F;
}

module.exports = { register };
