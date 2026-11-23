// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Connect & Onboard API — register(api, deps), deps = { config, log, ch, tracker, ingest, syslog, state }.
 * {P} = config.api_prefix || '/api/soc'. Same proxy-secret + portal session auth as every SOC route.
 * Reads: any signed-in role. test / firewall-check: operator. create / rotate / revoke / remove / m365: admin.
 * Every write is audited (ctx.audit → onboard.*). Tokens are returned exactly once (create, rotate) and never logged.
 *
 *   GET  {P}/onboard/catalog                 → { version, siem: {host, ip, kit_url, syslog_port, tls_port, tls_enabled},
 *                                               categories[], ports[], connectors[] (templates keep {{placeholders}}) }
 *   GET  {P}/onboard/sources                 → { sources[{id,type,kind,label,site,match_ip,state,last_seen,events_24h,hosts,
 *                                               token_set,created_at,created_by,relay?}], summary{receiving,silent,waiting,total},
 *                                               stats_available, window_min, generated_at }
 *   POST {P}/onboard/sources                 admin {id, kind, match_ip?, label?, site?, allow_public?} → { source, token (once),
 *                                               instructions[{title,lang,body}], network, steps, kit_url } 409 duplicate, 400 invalid
 *   POST {P}/onboard/sources/:id/rotate-token admin → { source, token (once) }
 *   POST {P}/onboard/sources/:id/revoke       admin → { source }
 *   DELETE {P}/onboard/sources/:id            admin → { removed } 409 when the source had events in the last 24 h (hint)
 *   POST {P}/onboard/sources/:id/test         operator → { id, state, last_seen, events_24h, hosts[], last_events[≤3] }
 *   POST {P}/onboard/firewall-check {ip}      operator → { ip, private, siem_ip, ports[{port,proto,service,listener_enabled,bind,
 *                                               reachable_by_config,note}], host_firewall_note }   (NOT a firewall change)
 *   GET  {P}/onboard/sites                    → { sites[{id,name,kind}] }   (config.json onboard.sites; seeded with the customer's sites)
 *   POST {P}/onboard/sites                    admin {sites[{id,name,kind:main|dr|branch}]} → { sites } (replaces the list; sites in use cannot be dropped)
 *   GET  {P}/onboard/m365                     → { enabled, tenant, client_id, secret_set, src_id, restart_required }
 *   POST {P}/onboard/m365                     admin {tenant, client_id, client_secret} → same shape (secret write-only)
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const net = require('node:net');
const fs = require('node:fs');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const catalog = require('./catalog');
const { createOnboardStore, validateId, isPrivate, writeJsonAtomic, StoreError } = require('./store');
const { sourceState, summarize, collectAgg, lastEvents } = require('./state');

function register(api, deps) {
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const log = deps.log || { info() {}, warn() {}, error() {} };
  const ob = cfg.onboard || {};
  const windowMs = Math.max(60000, (ob.receiving_window_min || 15) * 60000);
  const db = (cfg.clickhouse && cfg.clickhouse.database) || 'siem';
  const clock = typeof deps.now === 'function' ? deps.now : Date.now; // injectable for tests
  const store = deps.onboardStore || createOnboardStore({
    config: cfg, log, paths: deps.onboardPaths,
    onReload: (what) => {
      try { if (deps.ingest && typeof deps.ingest.reload === 'function') deps.ingest.reload(); } catch (e) { log.error('onboard: ingest reload failed', { err: e.message }); }
      try { if (deps.syslog && typeof deps.syslog.reloadSources === 'function') deps.syslog.reloadSources(); } catch (e) { log.error('onboard: syslog reload failed', { err: e.message }); }
      log.info('onboard: sources reloaded in process', { what });
    },
  });
  const B = `${P}/onboard`;

  function siteVars(extra) { return catalog.siteVars(cfg, extra); }
  const SITE_ID_RE = /^[a-z0-9-]{2,32}$/;
  const SITE_KINDS = new Set(['main', 'dr', 'branch']);
  function sites() { return Array.isArray(ob.sites) ? ob.sites.filter((x) => x && SITE_ID_RE.test(String(x.id || ''))) : []; }
  function siteOf(id) { return sites().find((x) => x.id === id) || null; }
  function normSites(list) {
    if (!Array.isArray(list) || !list.length) throw new HttpError(400, 'sites must be a non-empty list');
    const errs = []; const ids = new Set(); const out = [];
    list.forEach((x, i) => {
      const id = String((x && x.id) || '').trim().toLowerCase(); const name = String((x && x.name) || '').trim().slice(0, 80); const kind = String((x && x.kind) || 'branch').trim().toLowerCase();
      if (!SITE_ID_RE.test(id)) errs.push(`sites[${i}].id must be 2-32 lowercase letters, digits or dashes`);
      else if (ids.has(id)) errs.push(`sites[${i}].id duplicate "${id}"`);
      if (!name) errs.push(`sites[${i}].name required`);
      if (!SITE_KINDS.has(kind)) errs.push(`sites[${i}].kind must be main, dr or branch`);
      ids.add(id); out.push({ id, name, kind });
    });
    if (errs.length) throw new HttpError(400, 'invalid sites', errs);
    return out;
  }
  function tlsEnabled() { return !!(cfg.syslog && cfg.syslog.tls && cfg.syslog.tls.enabled); }

  async function liveRows() {
    const live = new Map(deps.tracker && typeof deps.tracker.summary === 'function' ? deps.tracker.summary().map((s) => [s.src_id, s]) : []);
    const { agg, ok } = await collectAgg(deps.ch, db, clock());
    const relays = new Map();
    if (deps.ingest && typeof deps.ingest.relayStats === 'function') { try { for (const r of deps.ingest.relayStats()) relays.set(r.relay_id, r); } catch { /* ignore */ } }
    const now = clock();
    const rows = (cfg.sources || []).filter((s) => s && s.id).map((s) => {
      const row = sourceState({ cfg: s, live: live.get(s.id), agg: agg.get(s.id), relay: s.type === 'relay' ? relays.get(s.id) : null, now, windowMs, tokenSet: store.tokenSet(s.id) });
      if (s.type === 'relay' && relays.get(s.id)) row.relay = { batches: relays.get(s.id).batches, peers_seen: relays.get(s.id).peers_seen, rejected: relays.get(s.id).rejected };
      return row;
    });
    rows.sort((a, b) => ({ waiting: 0, silent: 1, receiving: 2 }[a.state] - { waiting: 0, silent: 1, receiving: 2 }[b.state]) || a.id.localeCompare(b.id));
    return { rows, stats_available: ok, agg, live, relays };
  }

  api.route('GET', `${B}/catalog`, wrap(deps, null, (ctx) => {
    const cat = catalog.loadCatalog();
    const v = siteVars();
    return ctx.ok({
      version: cat.version, verify_note: cat.verify_note,
      siem: { host: v.siem_host, ip: v.siem_ip, kit_url: v.kit_url, syslog_port: v.syslog_port, tls_port: v.tls_port, tls_enabled: tlsEnabled(), udp_enabled: !!(cfg.syslog && cfg.syslog.udp && cfg.syslog.udp.enabled !== false) },
      categories: cat.categories, ports: cat.ports, placeholders: cat.placeholders,
      connectors: cat.connectors.map((c) => Object.assign({}, c, { needs_ip: c.mode === 'syslog' || c.type === 'relay', mints_token: c.mode === 'token' })),
    });
  }));

  api.route('GET', `${B}/sources`, wrap(deps, null, async (ctx) => {
    const { rows, stats_available } = await liveRows();
    const bySite = {};
    for (const st of sites()) bySite[st.id] = { id: st.id, name: st.name, kind: st.kind, receiving: 0, silent: 0, waiting: 0, total: 0 };
    for (const r of rows) { const k = r.site && bySite[r.site] ? r.site : ''; if (!bySite[k]) bySite[k] = { id: '', name: '', kind: '', receiving: 0, silent: 0, waiting: 0, total: 0 }; bySite[k][r.state]++; bySite[k].total++; }
    if (bySite[''] && !bySite[''].total) delete bySite[''];
    return ctx.ok({ sources: rows, summary: summarize(rows), by_site: Object.values(bySite), sites: sites(), stats_available, window_min: Math.round(windowMs / 60000), generated_at: new Date().toISOString() });
  }));

  api.route('POST', `${B}/sources`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const conn = catalog.byKind(String(b.kind || ''));
    if (!conn) throw new HttpError(400, 'unknown connector kind');
    if (conn.mode === 'link') throw new HttpError(400, `connector ${conn.kind} is configured in another module`);
    if (conn.mode === 'future') throw new HttpError(400, `connector ${conn.kind} is not available yet`);
    if (conn.mode === 'cloud') throw new HttpError(400, `connector ${conn.kind} is configured through ${B}/m365`);
    const site = String(b.site || '').trim().toLowerCase();
    if (!site) throw new HttpError(400, 'site required — pick the site this device or server belongs to', ['site required']);
    if (!siteOf(site)) throw new HttpError(400, `unknown site "${site}" (configured sites: ${sites().map((x) => x.id).join(', ') || 'none'})`);
    let r;
    try {
      r = store.create({ id: b.id, kind: conn.kind, type: conn.type, match_ip: b.match_ip, label: b.label, site, allow_public: b.allow_public === true, by: ctx.user, needs_ip: conn.mode === 'syslog' || conn.type === 'relay', mints_token: conn.mode === 'token', extra: b.extra });
    } catch (e) { if (e instanceof StoreError) throw new HttpError(e.code, e.message, e.errors); throw e; }
    const vars = siteVars({ source_id: r.source.id, device_ip: (r.source.match && (r.source.match.ip || r.source.match.cidr)) || (r.source.allowed_peers || [])[0] || '<device-ip>', token: r.token || '<token>' });
    const d = catalog.describe(conn, vars);
    audit(ctx, 'onboard.source.create', r.source.id, { kind: conn.kind, type: conn.type, match_ip: r.source.match || r.source.allowed_peers || null, label: r.source.label || '', site: r.source.site || '', token_minted: !!r.token });
    return ctx.ok({ source: r.source, token: r.token, token_shown_once: !!r.token, instructions: d.instructions, network: d.network, steps: d.steps, prerequisites: d.prerequisites, kit_url: vars.kit_url, siem: { host: vars.siem_host, ip: vars.siem_ip, syslog_port: vars.syslog_port, tls_port: vars.tls_port } });
  }));

  api.route('POST', `${B}/sources/:id/rotate-token`, wrap(deps, 'admin', (ctx) => {
    let r;
    try { r = store.rotate(ctx.params.id, ctx.user); } catch (e) { if (e instanceof StoreError) throw new HttpError(e.code, e.message, e.errors); throw e; }
    const conn = catalog.byKind(r.source.kind || '') || null;
    if (conn && conn.mode !== 'token') { /* token added to a syslog source: allowed (HTTP posting of raw lines) */ }
    audit(ctx, 'onboard.source.rotate-token', r.source.id, { kind: r.source.kind });
    const vars = siteVars({ source_id: r.source.id, device_ip: (r.source.match && (r.source.match.ip || r.source.match.cidr)) || (r.source.allowed_peers || [])[0] || '<device-ip>', token: r.token });
    return ctx.ok({ source: r.source, token: r.token, token_shown_once: true, instructions: conn && conn.mode === 'token' ? catalog.instructionsFor(conn, vars) : [] });
  }));

  api.route('POST', `${B}/sources/:id/revoke`, wrap(deps, 'admin', (ctx) => {
    let r;
    try { r = store.revoke(ctx.params.id, ctx.user); } catch (e) { if (e instanceof StoreError) throw new HttpError(e.code, e.message, e.errors); throw e; }
    audit(ctx, 'onboard.source.revoke', r.source.id, {});
    return ctx.ok({ source: r.source, token_set: false });
  }));

  api.route('DELETE', `${B}/sources/:id`, wrap(deps, 'admin', async (ctx) => {
    let sid;
    try { sid = validateId(ctx.params.id); } catch (e) { throw new HttpError(400, e.message); }
    if (!store.get(sid)) throw new HttpError(404, `source "${sid}" not found`);
    const { rows } = await liveRows();
    const row = rows.find((r) => r.id === sid);
    if (row && (row.events_24h > 0 || (row.last_seen && clock() - row.last_seen < 86400000))) {
      throw new HttpError(409, `source "${sid}" received ${row.events_24h} events in the last 24 h — stop the sender first (or revoke its token), then remove it after 24 h`);
    }
    let r;
    try { r = store.remove(sid, ctx.user); } catch (e) { if (e instanceof StoreError) throw new HttpError(e.code, e.message, e.errors); throw e; }
    audit(ctx, 'onboard.source.remove', sid, {});
    return ctx.ok(r);
  }));

  api.route('POST', `${B}/sources/:id/test`, wrap(deps, 'operator', async (ctx) => {
    let sid;
    try { sid = validateId(ctx.params.id); } catch (e) { throw new HttpError(400, e.message); }
    const s = store.get(sid);
    if (!s) throw new HttpError(404, `source "${sid}" not found`);
    const { rows, stats_available } = await liveRows();
    const row = rows.find((r) => r.id === sid);
    const events = await lastEvents(deps.ch, db, sid, 3);
    audit(ctx, 'onboard.source.test', sid, { state: row.state });
    return ctx.ok({ id: sid, state: row.state, last_seen: row.last_seen, events_24h: row.events_24h, hosts: row.hosts, token_set: row.token_set, last_events: events, stats_available, checked_at: new Date().toISOString() });
  }));

  api.route('POST', `${B}/firewall-check`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const ip = String(b.ip || '').trim();
    if (!net.isIPv4(ip)) throw new HttpError(400, 'ip must be an IPv4 address');
    const sl = cfg.syslog || {};
    const v = siteVars();
    const bind = sl.host || '127.0.0.1';
    const lanBound = bind === '0.0.0.0' || bind === '::' || bind === v.siem_ip || (bind !== '127.0.0.1' && bind !== '::1' && bind !== 'localhost');
    const bindNote = lanBound ? null : 'the SIEM syslog listener is bound to loopback only; the platform operator must set syslog.host to the LAN IP before devices can reach it';
    const ports = [
      { port: 443, proto: 'tcp', service: 'https (agents, relays)', listener_enabled: true, bind: v.siem_host, reachable_by_config: true, note: 'served by nginx on the portal host; TLS with the portal certificate' },
      { port: (sl.tcp && sl.tcp.port) || 5514, proto: 'tcp', service: 'syslog', listener_enabled: !!(sl.tcp && sl.tcp.enabled !== false), bind, reachable_by_config: !!(sl.tcp && sl.tcp.enabled !== false) && lanBound, note: bindNote },
      { port: (sl.udp && sl.udp.port) || 5514, proto: 'udp', service: 'syslog', listener_enabled: !!(sl.udp && sl.udp.enabled !== false), bind, reachable_by_config: !!(sl.udp && sl.udp.enabled !== false) && lanBound, note: bindNote },
      { port: (sl.tls && sl.tls.port) || 6514, proto: 'tcp', service: 'syslog-tls', listener_enabled: tlsEnabled(), bind, reachable_by_config: tlsEnabled() && lanBound, note: tlsEnabled() ? bindNote : 'TLS listener disabled in the SIEM config (syslog.tls.enabled) — plain TCP 5514 is available; ask the platform operator to enable TLS' },
    ];
    audit(ctx, 'onboard.firewall-check', ip, {});
    return ctx.ok({
      ip, private: isPrivate(ip), siem_ip: v.siem_ip, siem_host: v.siem_host, ports, checked_at: new Date().toISOString(),
      is_firewall_change: false,
      host_firewall_note: `This check reads the SIEM configuration only. The host firewall allow-list on ${v.siem_ip} (ufw) is managed by the platform operator — request that ${ip} (or its range) be allowed for the ports above.`,
    });
  }));

  // --- sites (config.json onboard.sites): the customer's locations; every device source is registered under one
  api.route('GET', `${B}/sites`, wrap(deps, null, (ctx) => ctx.ok({ sites: sites() })));
  api.route('POST', `${B}/sites`, wrap(deps, 'admin', (ctx) => {
    const list = normSites(body(ctx).sites);
    const keep = new Set(list.map((x) => x.id));
    const inUse = [...new Set((cfg.sources || []).map((s) => s && s.site).filter((x) => x && !keep.has(x)))];
    if (inUse.length) throw new HttpError(409, `sites still used by sources cannot be removed: ${inUse.join(', ')}`);
    const cfgFile = (() => { try { return JSON.parse(fs.readFileSync(store.paths.config, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } })();
    cfgFile.onboard = Object.assign({}, cfgFile.onboard || {}, { sites: list });
    writeJsonAtomic(store.paths.config, cfgFile);
    if (!cfg.onboard) cfg.onboard = {};
    cfg.onboard.sites = list; ob.sites = list;
    audit(ctx, 'onboard.sites', 'sites', { sites: list.map((x) => x.id) });
    return ctx.ok({ sites: list });
  }));

  // --- Microsoft 365: admin write-only settings (secrets.json "m365" + config.json m365.enabled). The collector reads
  // them at start, so a restart by the platform operator is still needed (reported as restart_required).
  function m365View() {
    const sec = (cfg.secrets && cfg.secrets.m365) || {};
    const mc = cfg.m365 || {};
    return { enabled: !!mc.enabled, tenant: sec.tenant || '', client_id: sec.client_id || '', secret_set: !!(sec.client_secret || sec.cert_file), auth: sec.cert_file ? 'certificate' : (sec.client_secret ? 'client_secret' : ''), src_id: mc.src_id || 'm365', content_types: mc.content_types || [], restart_required: !!m365Dirty };
  }
  let m365Dirty = false;
  api.route('GET', `${B}/m365`, wrap(deps, null, (ctx) => ctx.ok(m365View())));
  api.route('POST', `${B}/m365`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const errs = [];
    const tenant = String(b.tenant || '').trim();
    const clientId = String(b.client_id || '').trim();
    const secret = typeof b.client_secret === 'string' ? b.client_secret.trim() : '';
    if (!/^[0-9a-f-]{36}$/i.test(tenant) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tenant)) errs.push('tenant must be the tenant GUID (or verified domain)');
    if (!/^[0-9a-f-]{36}$/i.test(clientId)) errs.push('client_id must be the application (client) GUID');
    const existing = (cfg.secrets && cfg.secrets.m365) || {};
    if (!secret && !existing.client_secret && !existing.cert_file) errs.push('client_secret required');
    if (errs.length) throw new HttpError(400, 'invalid Microsoft 365 settings', errs);
    const paths = store.paths;
    const secFile = (() => { try { return SF.read(paths.secrets) || {}; } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } })();
    secFile.m365 = Object.assign({}, secFile.m365 || {}, { tenant, client_id: clientId });
    if (secret) { secFile.m365.client_secret = secret; delete secFile.m365.cert_file; delete secFile.m365.key_file; delete secFile.m365.key_passphrase; }
    writeJsonAtomic(paths.secrets, secFile);
    const cfgFile = (() => { try { return JSON.parse(require('node:fs').readFileSync(paths.config, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } })();
    cfgFile.m365 = Object.assign({}, cfgFile.m365 || {}, { enabled: true, publisher_id: /^[0-9a-f-]{36}$/i.test(tenant) ? tenant : (cfgFile.m365 && cfgFile.m365.publisher_id) || '' });
    writeJsonAtomic(paths.config, cfgFile);
    if (!cfg.secrets) Object.defineProperty(cfg, 'secrets', { value: {}, enumerable: false, writable: true });
    cfg.secrets.m365 = Object.assign({}, secFile.m365);
    cfg.m365 = Object.assign({}, cfg.m365 || {}, { enabled: true, publisher_id: cfgFile.m365.publisher_id });
    m365Dirty = true;
    audit(ctx, 'onboard.m365.settings', 'm365', { tenant, client_id: clientId, secret_changed: !!secret });
    return ctx.ok(m365View());
  }));

  deps.onboard = { store };

  // Add-Devices BULK hub (CSV / templates / range-discovery → the SAME source-creation path). Wire a default HTTP
  // discovery client (method B) only when configured; tests inject deps.discoveryClient directly.
  if (!deps.discoveryClient) {
    const dcfg = (cfg.onboard && cfg.onboard.discovery) || null;
    if (dcfg && dcfg.base_url && dcfg.secret_file) {
      try { deps.discoveryClient = require('./discovery-client').createDiscoveryClient({ config: cfg, log }); } catch (e) { log.warn('onboard: discovery client not wired', { err: e.message }); }
    }
  }
  try { require('./bulk').register(api, deps, { B, store }); } catch (e) { log.error('onboard: bulk hub registration failed', { err: e.message }); }

  return { store };
}

module.exports = { register };
