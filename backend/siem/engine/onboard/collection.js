// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Log collection for the asset inventory ({P} = /api/soc): the SIEM side of IT Asset Management's per-asset "Log
 * collection" (sentra-itam engine/monitoring-membership.js) and of log-flow assurance (onboard/assurance.js).
 * A source created here is an ordinary Connect & Onboard source (onboard/store.js, same template + validation), carrying
 * the asset it belongs to (asset_id, origin 'inventory'). Nothing here touches a device: the device still has to be
 * configured to send (the setup returned says exactly how), and until it does the source is "never-seen".
 *   GET  {P}/collection/health                     viewer  { sources[{src_id, kind, site, asset_id, state: receiving|silent|
 *                                                           never-seen|paused, last_seen, eps_1m, lag_p50_s, lag_p95_s,
 *                                                           parse_error_rate_1h, sla_min, sla_class, auto_onboarded, paused}] }
 *   POST {P}/collection/sources/ensure             admin   {asset{asset_id, name, mgmt_ip, type, vendor, os, class, is_dc,
 *                                                           hostname, site, kind?}} → {created, source_id, kind, site, setup,
 *                                                           token? (once, token connectors only)} - idempotent per asset / IP
 *   GET  {P}/collection/sources/:id/setup          viewer  { source_id, setup }  (the device-side configuration)
 *   POST {P}/collection/sources/:id/pause|resume   admin   paused = kept and still accepted, but out of flow assurance
 *   POST {P}/collection/sources/:id/stop           admin   removed; while it still sent events in the last 24 h it is paused
 *                                                           instead (stop the sender first) → {removed, paused, reason}
 *   GET  {P}/collection/assurance                  viewer  log-flow assurance model (onboard/assurance.js)
 *   GET  {P}/collection/policy · PUT (admin)               which assets must log, silence thresholds per class
 * "Silent" is per class (SLA_DEFAULT): a firewall quiet for 15 minutes is a problem, an iLO quiet for a day is not.
 * Lag = receive time (rts) - event time (ts), p50 / p95 over the last 15 minutes; a device clock that is wrong shows here
 * as lag too, and the page says so.
 */
const net = require('node:net');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const catalog = require('./catalog');
const { collectAgg } = require('./state');
const { StoreError, isPrivate } = require('./store');

// minutes without an event before a source of this class counts as silent
const SLA_DEFAULT = { firewall: 15, dc: 15, server: 60, network: 240, hypervisor: 60, oob: 1440, endpoint: 60, cloud: 120, app: 120, other: 120 };
const FW_KINDS = new Set(['fortigate', 'palo-alto', 'cisco-asa-ftd', 'check-point', 'sophos-firewall', 'sonicwall', 'f5-afm', 'silver-peak', 'zscaler-zia', 'zscaler-zpa', 'vpn-forcepoint']);
function slaClassOf(kind) {
  const k = String(kind || '');
  if (FW_KINDS.has(k)) return 'firewall';
  if (k === 'dc') return 'dc';
  if (['windows', 'linux', 'exchange-on-prem', 'oracle-health', 'oracle-audit', 'mssql-audit', 'iis', 'radius-nps'].includes(k)) return 'server';
  if (['vmware-esxi-hosts', 'nutanix-prism-syslog', 'cisco-ucs'].includes(k)) return 'hypervisor';
  if (['dell-idrac', 'hpe-ilo'].includes(k)) return 'oob';
  if (['cisco', 'syslog'].includes(k)) return 'network';
  if (['kaspersky', 'crowdstrike-falcon', 'sentinelone', 'trend-micro-apex', 'sophos-central'].includes(k)) return 'endpoint';
  if (k === 'm365') return 'cloud';
  return 'other';
}

// asset → connector kind (first match wins); sentra-itam discovery/siem.js KIND_TABLE plus firewalls recognised by OS / name
const KIND_TABLE = [
  ['dc', (c) => c.windows && c.dc], ['windows', (c) => c.windows], ['vmware-esxi-hosts', (c) => /esxi/.test(c.os)],
  ['fortigate', (c) => c.cls === 'firewall' && /forti/.test(c.vendor + c.os)], ['palo-alto', (c) => c.cls === 'firewall' && /palo alto|pan-os/.test(c.vendor + c.os)],
  ['cisco-asa-ftd', (c) => c.cls === 'firewall' && /cisco/.test(c.vendor)], ['check-point', (c) => c.cls === 'firewall' && /check ?point/.test(c.vendor)],
  ['sophos-firewall', (c) => c.cls === 'firewall' && /sophos/.test(c.vendor)], ['sonicwall', (c) => c.cls === 'firewall' && /sonicwall/.test(c.vendor)],
  // firewalls recognised by their OS / name even when discovery did not classify them (manually added assets)
  ['fortigate', (c) => /fortigate|fortios|\bfgt/.test(c.os + ' ' + c.name)], ['palo-alto', (c) => /pan-os/.test(c.os)],
  ['f5-bigip', (c) => /\bf5\b/.test(c.vendor)], ['cisco', (c) => ['switch', 'router', 'ap'].includes(c.cls) && /cisco/.test(c.vendor)],
  ['dell-idrac', (c) => /idrac/.test(c.os + ' ' + c.name)], ['hpe-ilo', (c) => /\bilo\b/.test(c.os + ' ' + c.name)],
  ['syslog', (c) => /solaris|sunos|\baix\b|hp-ux/.test(c.os)], ['linux', (c) => /linux|ubuntu|red hat|rhel|centos|debian|suse|unix/.test(c.os)],
  ['syslog', (c) => ['switch', 'router', 'ap', 'firewall'].includes(c.cls)],
];
const NOT_APPLICABLE = { printer: 'printers are monitored by the print module', phone: 'IP phones log through CUCM', cloud: 'cloud instances use the cloud connectors' };
function kindForAsset(a) {
  const cls = String(a.class || '') || ({ network: 'switch', server: 'server', workstation: 'workstation', laptop: 'workstation', vm: 'vm', printer: 'printer', phone: 'phone' }[a.type] || 'unknown');
  const c = { cls, vendor: String(a.vendor || '').toLowerCase(), os: String(a.os || '').toLowerCase(), name: String(a.name || '').toLowerCase() };
  c.windows = /windows/.test(c.os); c.dc = !!a.is_dc;
  if (NOT_APPLICABLE[cls]) return { kind: null, reason: NOT_APPLICABLE[cls] };
  const hit = KIND_TABLE.find((r) => r[1](c));
  return hit ? { kind: hit[0], reason: '' } : { kind: null, reason: 'no automatic connector for this asset (vendor / OS not recognised) - onboard it in Connect & Onboard' };
}
const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

function register(api, deps) {
  const P = prefixOf(deps), cfg = deps.config || {}, log = deps.log || { info() {}, warn() {}, error() {} };
  const store = deps.onboard && deps.onboard.store;
  if (!store) { log.warn('collection: onboard store not available - routes not registered'); return; }
  const db = (cfg.clickhouse && cfg.clickhouse.database) || 'siem';
  const clock = typeof deps.now === 'function' ? deps.now : Date.now;
  const C = `${P}/collection`;
  const sites = () => (Array.isArray((cfg.onboard || {}).sites) ? cfg.onboard.sites : []);

  // policy: config.collection (defaults) overlaid by the admin's saved policy (state)
  const polCol = deps.state ? deps.state.collection('collection_policy') : null;
  function policy() {
    const base = Object.assign({ required_types: ['server', 'network', 'firewall', 'storage', 'vm'], require_workstations: false, unknown_min_events: 20, waiting_grace_h: 24, lag_warn_s: 300, parse_error_warn: 0.2 }, cfg.collection || {});
    const saved = polCol ? polCol.get('policy') : null;
    const p = Object.assign({}, base, saved || {});
    p.sla_min = Object.assign({}, SLA_DEFAULT, base.sla_min || {}, (saved && saved.sla_min) || {});
    return p;
  }

  let lagCache = null;
  async function lagBySrc() {
    if (lagCache && clock() - lagCache.at < 60000) return lagCache.v;
    const out = new Map();
    if (deps.ch && typeof deps.ch.query === 'function') {
      try {
        const rows = await deps.ch.query(`SELECT src_id, quantile(0.5)(greatest(0, dateDiff('second', ts, rts))) AS p50, quantile(0.95)(greatest(0, dateDiff('second', ts, rts))) AS p95
          FROM ${db}.events WHERE rts >= now() - INTERVAL 15 MINUTE GROUP BY src_id`, {}, { readonly: true, timeout_ms: 8000, settings: { max_execution_time: 8 } });
        for (const r of rows || []) out.set(r.src_id, { p50: Math.round(Number(r.p50) || 0), p95: Math.round(Number(r.p95) || 0) });
      } catch (e) { /* lag is optional - shown as not measured */ }
    }
    lagCache = { at: clock(), v: out };
    return out;
  }

  async function health() {
    const pol = policy(), now = clock();
    const live = new Map(deps.tracker && typeof deps.tracker.summary === 'function' ? deps.tracker.summary().map((s) => [s.src_id, s]) : []);
    const { agg, ok } = await collectAgg(deps.ch, db, now);
    const lag = await lagBySrc();
    const rows = (cfg.sources || []).filter((s) => s && s.id).map((s) => {
      const l = live.get(s.id), a = agg.get(s.id), cls = s.sla_class || slaClassOf(s.kind);
      const sla = Number(s.sla_min) || pol.sla_min[cls] || 120;
      const last = Math.max((l && l.last_seen) || 0, (a && a.last_ms) || 0) || null;
      const ever = !!last || !!(l && l.events_since_start) || !!(a && (a.events_24h || a.ever));
      const state = s.paused ? 'paused' : last && now - last <= sla * 60000 ? 'receiving' : ever ? 'silent' : 'never-seen';
      const lg = lag.get(s.id);
      return { src_id: s.id, kind: s.kind || '', type: s.type || '', label: s.label || '', site: s.site || '', asset_id: s.asset_id || null, origin: s.origin || 'onboard',
        match_ip: (s.match && (s.match.ip || s.match.cidr)) || null, state, last_seen: last, events_24h: a ? a.events_24h : (l ? l.events_since_start : 0),
        eps_1m: l ? l.eps_1m : 0, eps_1h: l ? l.eps_1h : 0, parse_error_rate_1h: l ? l.parse_error_rate_1h : null, hosts: (a && a.hosts && a.hosts.length ? a.hosts : (l && l.hosts) || []).slice(0, 10),
        lag_p50_s: lg ? lg.p50 : null, lag_p95_s: lg ? lg.p95 : null, sla_min: sla, sla_class: cls, auto_onboarded: !!s.auto_onboarded, paused: !!s.paused,
        paused_reason: s.paused_reason || null, created_at: s.created_at || null };
    });
    // events arriving under an id that is not a configured source = the collectors' catch-all (unidentified senders)
    const unconfigured = [...live.values()].filter((l) => !(cfg.sources || []).some((s) => s && s.id === l.src_id)).map((l) => ({ src_id: l.src_id, collector: l.collector || '', last_seen: l.last_seen, eps_1h: l.eps_1h, events_since_start: l.events_since_start, hosts: l.hosts || [] }));
    return { sources: rows, unconfigured, stats_available: ok, generated_at: new Date(now).toISOString() };
  }

  function siteFor(want) {
    const w = String(want || '').trim().toLowerCase(), list = sites();
    const hit = list.find((x) => x.id === w) || list.find((x) => String(x.name || '').toLowerCase() === w) || list.find((x) => w && String(x.name || '').toLowerCase().includes(w));
    if (hit) return { site: hit.id, note: '' };
    const main = list.find((x) => x.kind === 'main') || list[0];
    if (!main) throw new HttpError(400, 'no sites are configured in the SIEM (Connect & Onboard → Sites)');
    return { site: main.id, note: `site "${want || '-'}" is not a SIEM site - registered under ${main.name}; correct it in Connect & Onboard if needed` };
  }
  function setupFor(src, token) {
    const conn = catalog.byKind(src.kind);
    if (!conn) return null;
    const vars = catalog.siteVars(cfg, { source_id: src.id, device_ip: (src.match && (src.match.ip || src.match.cidr)) || '<device-ip>', token: token || '<token: shown once at creation - rotate it in Connect & Onboard to install the agent>' });
    let d; try { d = catalog.describe(conn, vars); } catch (e) { return { mode: conn.mode, error: e.message }; }
    const tls = !!(cfg.syslog && cfg.syslog.tls && cfg.syslog.tls.enabled);
    return { mode: conn.mode, kind: conn.kind, title: conn.title, syslog_target: conn.mode === 'syslog' ? `${vars.siem_ip}:${vars.syslog_port}/${(d.network && d.network.proto) || 'tcp'}` : null,
      tls_target: conn.mode === 'syslog' && tls ? `${vars.siem_ip}:${vars.tls_port}/tcp` : null, kit_url: conn.mode === 'token' ? vars.kit_url : null,
      snippet: (d.instructions[0] || {}).body || '', instructions: d.instructions, network: d.network, steps: d.steps, prerequisites: d.prerequisites,
      summary: { en: conn.mode === 'syslog' ? `Point the device's syslog at ${vars.siem_ip}:${vars.syslog_port} (${(d.network && d.network.proto) || 'tcp'}) - ${conn.title.en}` : `Install the SIEM agent (${vars.kit_url}) with this source's token - ${conn.title.en}`, ar: conn.title.ar } };
  }
  function srcOrFail(id) { const s = store.get(String(id || '')); if (!s) throw new HttpError(404, `source "${id}" not found`); return s; }
  const storeErr = (e) => { if (e instanceof StoreError) return new HttpError(e.code, e.message, e.errors); return e; };

  function ensure(a, by) {
    if (!a || typeof a !== 'object') throw new HttpError(400, 'asset required');
    const assetId = String(a.asset_id || '').slice(0, 80), ip = String(a.mgmt_ip || '').trim();
    if (!assetId) throw new HttpError(400, 'asset.asset_id required');
    const list = cfg.sources || [];
    const prior = list.find((s) => s && s.asset_id === assetId) || (ip ? list.find((s) => s && s.match && s.match.ip === ip) : null);
    if (prior) return { created: false, source_id: prior.id, kind: prior.kind, site: prior.site || '', setup: setupFor(prior) };
    let kind = a.kind && catalog.byKind(String(a.kind)) ? String(a.kind) : null, reason = '';
    if (!kind) { const k = kindForAsset(a); kind = k.kind; reason = k.reason; }
    if (!kind) throw new HttpError(400, reason);
    const conn = catalog.byKind(kind);
    if (!conn || conn.mode === 'link' || conn.mode === 'future' || conn.mode === 'cloud') throw new HttpError(400, `connector ${kind} cannot be created from the inventory`);
    const needsIp = conn.mode === 'syslog';
    if (needsIp && !net.isIPv4(ip)) throw new HttpError(400, `${a.name || assetId}: a management IPv4 address is needed for a syslog source`);
    if (ip && net.isIPv4(ip) && !isPrivate(ip)) throw new HttpError(400, `${ip} is not a private address - onboard internet-facing senders in Connect & Onboard`);
    const st = siteFor(a.site);
    let base = slug(conn.id_prefix + (slug(a.name || a.hostname) || ip.replace(/\./g, '-') || assetId)).slice(0, 36).replace(/-+$/, '');
    if (base.length < 3) base = slug(conn.id_prefix + assetId).slice(0, 36);
    let id = base, n = 2; while (store.get(id)) id = `${base}-${n++}`;
    let r;
    try {
      r = store.create({ id, kind, type: conn.type, match_ip: ip && net.isIPv4(ip) ? ip : undefined, label: String(a.name || a.hostname || ip).slice(0, 120), site: st.site, by,
        needs_ip: needsIp, mints_token: conn.mode === 'token', extra: { asset_id: assetId, origin: 'inventory', auto_onboarded: /^system:/.test(String(by || '')), sla_class: a.is_dc ? 'dc' : slaClassOf(kind) } });
    } catch (e) { throw storeErr(e); }
    return { created: true, source_id: r.source.id, kind, site: st.site, site_note: st.note || undefined, token: r.token || undefined, token_shown_once: !!r.token, setup: setupFor(r.source, r.token) };
  }

  api.route('GET', `${C}/health`, wrap(deps, null, async (ctx) => ctx.ok(await health())));
  api.route('POST', `${C}/sources/ensure`, wrap(deps, 'admin', (ctx) => {
    const r = ensure(body(ctx).asset, ctx.user);
    audit(ctx, r.created ? 'collection.source.create' : 'collection.source.ensure', r.source_id, { asset_id: (body(ctx).asset || {}).asset_id, kind: r.kind, created: r.created });
    return ctx.ok(r);
  }));
  api.route('GET', `${C}/sources/:id/setup`, wrap(deps, null, (ctx) => { const s = srcOrFail(ctx.params.id); return ctx.ok({ source_id: s.id, setup: setupFor(s) }); }));
  for (const act of ['pause', 'resume']) {
    api.route('POST', `${C}/sources/:id/${act}`, wrap(deps, 'admin', (ctx) => {
      srcOrFail(ctx.params.id);
      const reason = String(body(ctx).reason || '').slice(0, 300);
      let r; try { r = store.update(ctx.params.id, act === 'pause' ? { paused: true, paused_at: new Date(clock()).toISOString(), paused_by: ctx.user, paused_reason: reason || 'paused' } : { paused: null, paused_at: null, paused_by: null, paused_reason: null }, ctx.user); } catch (e) { throw storeErr(e); }
      audit(ctx, `collection.source.${act}`, ctx.params.id, { reason });
      return ctx.ok({ id: r.source.id, paused: act === 'pause' });
    }));
  }
  api.route('POST', `${C}/sources/:id/stop`, wrap(deps, 'admin', async (ctx) => {
    const s = srcOrFail(ctx.params.id);
    const h = (await health()).sources.find((x) => x.src_id === s.id);
    if (h && (h.events_24h > 0 || (h.last_seen && clock() - h.last_seen < 86400000))) {
      try { store.update(s.id, { paused: true, paused_at: new Date(clock()).toISOString(), paused_by: ctx.user, paused_reason: 'stop requested while still sending' }, ctx.user); } catch (e) { throw storeErr(e); }
      audit(ctx, 'collection.source.stop', s.id, { removed: false, paused: true });
      return ctx.ok({ id: s.id, removed: false, paused: true, reason: `the source received ${h.events_24h} events in the last 24 h - paused; stop the sender, then remove it after 24 h` });
    }
    try { store.remove(s.id, ctx.user); } catch (e) { throw storeErr(e); }
    audit(ctx, 'collection.source.stop', s.id, { removed: true });
    return ctx.ok({ id: s.id, removed: true, paused: false });
  }));
  api.route('GET', `${C}/policy`, wrap(deps, null, (ctx) => ctx.ok(policy())));
  api.route('PUT', `${C}/policy`, wrap(deps, 'admin', (ctx) => {
    if (!polCol) throw new HttpError(503, 'state store not available');
    const b = body(ctx), cur = polCol.get('policy') || { id: 'policy' }, errs = [];
    const TYPES = ['server', 'network', 'firewall', 'storage', 'vm', 'workstation', 'laptop', 'appliance', 'other'];
    if (b.required_types !== undefined) { if (!Array.isArray(b.required_types) || !b.required_types.every((t) => TYPES.includes(t))) errs.push(`required_types: any of ${TYPES.join(', ')}`); else cur.required_types = b.required_types; }
    if (b.require_workstations !== undefined) cur.require_workstations = b.require_workstations === true;
    if (b.sla_min !== undefined) { const o = {}; for (const [k, v] of Object.entries(b.sla_min || {})) { if (!SLA_DEFAULT[k] || !(Number(v) >= 5 && Number(v) <= 10080)) errs.push(`sla_min.${k}: 5-10080 minutes for a known class`); else o[k] = Math.round(Number(v)); } cur.sla_min = o; }
    for (const [k, lo, hi] of [['unknown_min_events', 1, 100000], ['waiting_grace_h', 1, 720], ['lag_warn_s', 30, 86400], ['parse_error_warn', 0.01, 1]]) if (b[k] !== undefined) { if (!(Number(b[k]) >= lo && Number(b[k]) <= hi)) errs.push(`${k}: ${lo}-${hi}`); else cur[k] = Number(b[k]); }
    if (errs.length) throw new HttpError(400, 'invalid policy', errs);
    cur.updated_by = ctx.user; cur.updated_at = new Date(clock()).toISOString();
    polCol.put(cur);
    audit(ctx, 'collection.policy', 'policy', cur);
    return ctx.ok(policy());
  }));

  const C2 = { health, ensure, setupFor, policy, kindForAsset, slaClassOf };
  deps.collection = C2;
  // log-flow assurance (inventory × sources × logs) and its route
  try {
    const A = require('./assurance').createAssurance(deps, C2);
    deps.collectionAssurance = A;
    api.route('GET', `${C}/assurance`, wrap(deps, null, async (ctx) => ctx.ok(await A.model({ fresh: (ctx.query || {}).fresh === '1' }))));
    // device configuration by type, with real counts, setup guides, learned time to first log (onboard/devconfig.js)
    require('./devconfig').register(api, deps, C2, A, C);
    // live status of every feed: learned rhythm, volume against the same hour, health, AI analyst (onboard/livestatus.js)
    require('./livestatus').register(api, deps, A, C);
  } catch (e) { log.error('collection: assurance not available', { err: e.message }); }
  return C2;
}

module.exports = { register, kindForAsset, slaClassOf, SLA_DEFAULT };
