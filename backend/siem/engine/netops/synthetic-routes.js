// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Synthetic Monitoring & Apdex, wireless controllers and infrastructure health by device type (prefix {P} = /api/soc).
 * Registered after netops/routes.js (uses its inventory, poller and server availability: deps.netopsInstance).
 *   GET    {P}/netops/synthetic                  viewer   checks, Apdex / uptime 24 h · 7 d · 30 d, certificates, per application
 *                                                         (+ the allow-list settings for an administrator)
 *   GET    {P}/netops/synthetic/checks/:id       viewer   one check: hourly (48 h) and daily (30 d) Apdex, response time, recent runs
 *   POST   {P}/netops/synthetic/checks           admin    add / update a check (GET / HEAD only, steps follow links)       audited
 *   DELETE {P}/netops/synthetic/checks/:id       admin                                                                     audited
 *   POST   {P}/netops/synthetic/checks/:id/run   operator run now                                                          audited
 *   PUT    {P}/netops/synthetic/settings         admin    {allow[], allow_private, default_t_ms}  the SSRF allow-list       audited
 *   GET    {P}/netops/apdex/portal?hours&t_ms&site viewer Apdex from the web server access logs (Portal Traffic data)
 *   GET    {P}/netops/health/types               viewer   up / down by device type: servers, domain controllers, storage,
 *                                                         WLCs, FC switches, firewalls, switches, routers, UPS
 *   GET    {P}/netops/wlc                         viewer   wireless controllers: APs, radios, channels, SSIDs, client counts
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { body, param } = require('../util/check');
const { createSynthetic } = require('./synthetic');
const { createWlcView } = require('./wlc');

const DC_RE = /(^|[^a-z])(a|as|ad)?dc\d*([^a-z]|$)|domain controller|active directory/i;   // dc01, adc2, asdc01, addc1
const NET_TYPES = { wlc: 'wlcs', fc_switch: 'fc_switches', firewall: 'firewalls', core: 'switches', distribution: 'switches', access: 'switches', 'wan-edge': 'routers', 'branch-router': 'routers', router: 'routers', 'sdwan-appliance': 'routers', ups: 'ups' };
const LABEL = { servers: 'Servers', domain_controllers: 'Domain controllers', storage: 'Storage', wlcs: 'Wireless LAN controllers', fc_switches: 'FC switches', firewalls: 'Firewalls', switches: 'Switches', routers: 'Routers / WAN', ups: 'UPS', other_network: 'Other network devices' };
const ALWAYS = ['servers', 'domain_controllers', 'wlcs', 'fc_switches'];

/* pure: up / down / unknown per device type, from server availability (hosts + live status) and the netops poll */
function healthByType({ hosts = [], hostStatus = {}, devices = [], snapshot = () => null }) {
  const T = {};
  const add = (type, state, item) => { const t = T[type] || (T[type] = { type, label: LABEL[type], total: 0, up: 0, down: 0, unknown: 0, unmonitored: 0, down_items: [] }); t.total++; t[state]++; if (state === 'down' && t.down_items.length < 10) t.down_items.push(item); };
  for (const h of hosts) {
    const kind = String(h.kind || '').toLowerCase();
    const type = kind === 'dc' || DC_RE.test(String(h.name || '')) || DC_RE.test(String(h.service || '')) ? 'domain_controllers' : kind === 'storage' ? 'storage' : 'servers';
    const s = hostStatus[h.ip] || {};
    const state = h.monitor === false ? 'unmonitored' : s.s === 'online' ? 'up' : s.s === 'offline' ? 'down' : 'unknown';
    add(type, state, { name: h.name, ip: h.ip, since: s.since || null });
  }
  for (const d of devices) {
    const type = NET_TYPES[d.role] || 'other_network', snap = snapshot(d.id), polled = d.poll && (d.poll.ping !== false || d.poll.snmp || d.poll.api);
    const state = !polled ? 'unmonitored' : !snap ? 'unknown' : snap.ok ? 'up' : 'down';
    add(type, state, { name: d.name, ip: d.ip, since: snap ? snap.at : null, why: snap && (snap.errors || [])[0] ? String(snap.errors[0]).slice(0, 160) : '' });
  }
  for (const k of ALWAYS) if (!T[k]) T[k] = { type: k, label: LABEL[k], total: 0, up: 0, down: 0, unknown: 0, unmonitored: 0, down_items: [] };
  const order = Object.keys(LABEL);
  return { types: Object.values(T).sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type)),
    note: 'Servers, domain controllers and storage from Server Availability (ping / TCP); domain controllers recognised by name or service (dc, adc, asdc, "domain controller"). Network devices from the AI Network Engineer poll, by inventory role.' };
}

function register(api, deps) {
  if (!deps.state) throw new Error('synthetic needs deps.state');
  const P = prefixOf(deps), N = deps.netopsInstance || deps.netops || null;
  const S = deps.synthetic || createSynthetic({ state: deps.state, config: deps.config, log: deps.log, ch: deps.ch, now: deps.now, resolve: deps.syntheticResolve });
  deps.syntheticInstance = S;
  if (deps.config && deps.config.netops && deps.config.netops.enabled !== false && !deps.synthetic) S.start();
  const WV = N ? createWlcView({ inventory: N.inventory, poller: N.poller, state: deps.state, now: deps.now }) : null;

  api.route('GET', `${P}/netops/synthetic`, wrap(deps, null, (ctx) => Object.assign(S.view(), { role: ctx.role || 'viewer' }, ctx.role === 'admin' ? { settings: S.settings() } : {})));
  api.route('GET', `${P}/netops/synthetic/checks/:id`, wrap(deps, null, (ctx) => S.detail(param(ctx.params.id))));
  api.route('POST', `${P}/netops/synthetic/checks`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx.body)
      .str('id', { max: 40, re: /^[a-z0-9][a-z0-9-]{1,39}$/, msg: 'id: 2-40 lowercase letters, digits and dashes' })
      .str('name', { max: 120 }).str('app', { max: 80 }).str('url', { max: 1000 })
      .oneOf('method', ['GET', 'HEAD']).list('expect_status', { max: 10 }).str('expect_text', { max: 200 })
      .int('timeout_ms', { min: 1000, max: 60000 }).int('interval_s', { min: 30, max: 86400 }).int('apdex_t_ms', { min: 50, max: 60000 })
      .int('max_redirects', { min: 0, max: 10 }).int('cert_warn_days', { min: 1, max: 365 })
      .bool('follow_redirects').bool('tls_verify').bool('enabled').list('steps', { max: 10 })
      .rule((o) => (!o.id && (!o.name || !o.url) ? 'name and url are required for a new check' : null))
      .done();
    if (b.id && !S.get(b.id) && (!b.name || !b.url)) throw new HttpError(400, 'name and url are required for a new check');
    const r = S.put(b, ctx.user), c = r.check;
    audit(ctx, r.before ? 'netops.synthetic.check.update' : 'netops.synthetic.check.create', c.id, { name: c.name, url: c.url, method: c.method, steps: c.steps.length, interval_s: c.interval_s, apdex_t_ms: c.apdex_t_ms, tls_verify: c.tls_verify, enabled: c.enabled,
      changed: r.before ? Object.keys(b).filter((k) => k !== 'id' && JSON.stringify(b[k]) !== JSON.stringify(r.before[k])) : undefined });
    return c;
  }));
  api.route('DELETE', `${P}/netops/synthetic/checks/:id`, wrap(deps, 'admin', (ctx) => { const id = param(ctx.params.id), c = S.get(id); const r = S.remove(id); audit(ctx, 'netops.synthetic.check.delete', id, { name: c && c.name, url: c && c.url }); return r; }));
  api.route('POST', `${P}/netops/synthetic/checks/:id/run`, wrap(deps, 'operator', async (ctx) => {
    const id = param(ctx.params.id); audit(ctx, 'netops.synthetic.run', id, {});
    const r = await S.runNow(id); return r;
  }));
  api.route('PUT', `${P}/netops/synthetic/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx.body).list('allow', { max: 200, item: 'str', itemMax: 260 }).bool('allow_private').int('default_t_ms', { min: 50, max: 60000 }).done();
    const r = S.setSettings(b, ctx.user);
    audit(ctx, 'netops.synthetic.settings', 'allow-list', { from: r.before, to: { allow: r.settings.allow, allow_private: r.settings.allow_private, default_t_ms: r.settings.default_t_ms } });
    return r.settings;
  }));
  api.route('GET', `${P}/netops/apdex/portal`, wrap(deps, null, (ctx) => {
    const q = body(ctx.query || {}).oneOf('hours', ['1', '24', '168', '720'], { def: '24' }).int('t_ms', { min: 50, max: 60000, def: 500 }).str('site', { max: 200, re: /^[A-Za-z0-9._:-]+$/, msg: 'site must be a host name' }).done();
    return S.portalApdex({ hours: Number(q.hours), t_ms: q.t_ms, site: q.site || '' });
  }));
  api.route('GET', `${P}/netops/health/types`, wrap(deps, null, () => {
    if (!N) throw new HttpError(503, 'network operations are not running in the SIEM engine');
    const av = N.availability;
    return healthByType({ hosts: av ? av.list() : [], hostStatus: av ? av.ipMap() : {}, devices: N.inventory.list(), snapshot: (id) => N.poller.snapshot(id) });
  }));
  api.route('GET', `${P}/netops/wlc`, wrap(deps, null, () => {
    if (!WV) throw new HttpError(503, 'network operations are not running in the SIEM engine');
    return WV.view();
  }));
}

module.exports = { register, healthByType };
