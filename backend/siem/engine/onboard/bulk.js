// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Add-Devices BULK onboarding — bolt-on to the Connect & Onboard hub (engine/onboard/routes.js calls register()).
 * Bulk-register network + security devices (switches, routers, firewalls, WLC, load balancers, NAC, proxies, EDR/DLP
 * appliances) into the SIEM in one shot, by three methods that all funnel through ONE preview/commit path:
 *   (A) CSV / pasted lines  →  POST {P}/onboard/bulk/preview | /commit  {csv:"ip,name,type,vendor,site", defaults}
 *   (C) type templates      →  the same, with {devices:[{ip,name,type,vendor,site,port?}], defaults}
 *   (B) range auto-discovery → POST {P}/onboard/bulk/discover {scope_id, run?, adopt?}  (calls the sentra-itam discovery
 *                               engine through an injectable client — reuses its scopes + pre-scan GATE + results;
 *                               never reimplements scanning — then maps discovered devices through the SAME commit path)
 *
 * Every device resolves a device-TYPE TEMPLATE (device-templates.json → a real catalog.json connector kind), then the
 * SAME store.create() the single-device wizard uses mints the SIEM source (+ ingest token for token kinds) — nothing
 * about source creation or token issuance is forked. Idempotent: an existing source with the same ip + kind is skipped
 * (so a re-run is a no-op). Capped (BULK_MAX). Admin-only. One audit summary (onboard.bulk.*) plus a per-item audit.
 * Each committed device comes back with the syslog target to configure on it ({siem_ip}:{port}/{proto}).
 *
 *   GET  {P}/onboard/bulk/templates  any   → { version, templates[{type,label,vendor,category,kind,parser,planned_parser?,
 *                                               proto,port,snmp,source_kind,sama[]}], siem{host,ip,syslog_port,tls_port,
 *                                               tls_enabled}, csv_header, sites[] }
 *   POST {P}/onboard/bulk/preview    admin { devices?|csv?, defaults{site?,vendor?,allow_public?} } → { rows[], summary }   (no writes)
 *   POST {P}/onboard/bulk/commit     admin same body → { rows[], summary }  (tokens returned ONCE, per row)
 *   POST {P}/onboard/bulk/discover   admin { scope_id, run?, adopt?, defaults } → { scope, gate, devices[], rows?, summary? }
 */
const { HttpError, wrap, audit, body } = require('../soc/routeutil');
const { StoreError, ID_RE } = require('./store');
const catalog = require('./catalog');

const BULK_MAX = 500;
const TPL = require('./device-templates.json');

// ---- template resolution: map each device template to its real catalog connector, cross-check it never drifts -------
function resolveTemplates() {
  const cat = catalog.loadCatalog();
  const byType = new Map();
  const list = [];
  for (const t of TPL.templates) {
    const conn = cat.connectors.find((c) => c.kind === t.kind);
    if (!conn) throw new Error(`device-templates: "${t.type}" maps to unknown connector kind "${t.kind}"`);
    if (conn.mode !== 'syslog' && conn.mode !== 'token') throw new Error(`device-templates: "${t.type}" kind "${t.kind}" is mode ${conn.mode} (not onboardable in bulk)`);
    // in-sync checks against the catalogue (the single source of truth for parsers / SAMA / source kind)
    if (t.parser !== conn.type) throw new Error(`device-templates: "${t.type}" parser "${t.parser}" != catalog type "${conn.type}" for kind ${t.kind}`);
    if (t.source_kind !== conn.mode) throw new Error(`device-templates: "${t.type}" source_kind "${t.source_kind}" != catalog mode "${conn.mode}"`);
    const want = (conn.sama || []).slice().sort().join(',');
    const have = (t.sama || []).slice().sort().join(',');
    if (want !== have) throw new Error(`device-templates: "${t.type}" sama [${have}] != catalog [${want}] for kind ${t.kind}`);
    if (conn.dedicated_parser && t.planned_parser && t.planned_parser !== conn.dedicated_parser) throw new Error(`device-templates: "${t.type}" planned_parser "${t.planned_parser}" != catalog dedicated_parser "${conn.dedicated_parser}"`);
    const rec = Object.assign({}, t, { connector: conn, id_prefix: conn.id_prefix });
    byType.set(t.type, rec);
    list.push(rec);
  }
  return { byType, list };
}
let TPLS = null;
function templates() { if (!TPLS) TPLS = resolveTemplates(); return TPLS; }
function templateFor(type) { return templates().byType.get(String(type || '').trim().toLowerCase()) || null; }

function slug(s) { return String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }

// ---- tolerant CSV / pasted-lines parser ----------------------------------------------------------------------------
// Accepts an optional header row (any order of ip,name,type,vendor,site,port); otherwise positional ip,name,type,vendor,site.
// Lines starting with # and blank lines are ignored. Comma, semicolon or tab separated.
const CSV_COLS = ['ip', 'name', 'type', 'vendor', 'site', 'port'];
function parseCsv(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  let cols = null;
  let n = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line[0] === '#') continue;
    const cells = line.split(/\s*[,;\t]\s*/).map((c) => c.trim());
    const lower = cells.map((c) => c.toLowerCase());
    if (n === 0 && lower.some((c) => CSV_COLS.includes(c)) && !/^\d/.test(cells[0])) {
      // header row: remember the column order (unknown headers ignored)
      cols = lower.map((c) => (CSV_COLS.includes(c) ? c : null));
      continue;
    }
    n++;
    const row = {};
    if (cols) { cols.forEach((k, i) => { if (k && cells[i] !== undefined && cells[i] !== '') row[k] = cells[i]; }); }
    else { CSV_COLS.forEach((k, i) => { if (cells[i] !== undefined && cells[i] !== '') row[k] = cells[i]; }); }
    row._line = raw;
    out.push(row);
  }
  return out;
}

// ---- resolve one device row to a planned source (pure; no writes) --------------------------------------------------
function resolveRow(input, ctx) {
  const errors = [];
  const ip = String((input && (input.ip || input.host)) || '').trim();
  const typeKey = String((input && input.type) || '').trim().toLowerCase();
  const name = String((input && input.name) || '').trim();
  const site = String((input && input.site) || ctx.defaults.site || '').trim().toLowerCase();
  const vendor = String((input && input.vendor) || ctx.defaults.vendor || '').trim();
  const tpl = typeKey ? templateFor(typeKey) : null;
  if (!typeKey) errors.push('type is required');
  else if (!tpl) errors.push(`unknown device type "${typeKey}"`);
  if (!ip) errors.push('ip is required');
  if (!site) errors.push('site is required (set it per row or in defaults)');
  else if (!ctx.siteOf(site)) errors.push(`unknown site "${site}" (configured: ${ctx.siteIds().join(', ') || 'none'})`);

  const out = { input: { ip, name, type: typeKey, vendor, site, port: input && input.port, line: input && input._line },
    ok: false, action: 'error', errors };
  if (!tpl || errors.length) return out;

  // validate the IP via the store's own rules (private unless allow_public)
  let match;
  try { match = ctx.validateIp(ip, !!ctx.defaults.allow_public); } catch (e) { errors.push(e.message); return out; }
  const matchIp = match.cidr || match.ip;

  // deterministic source id from the connector prefix + a slug of name (fallback ip)
  const prefix = tpl.id_prefix;
  let stem = (prefix + (slug(name) || slug(ip))).replace(/-+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  if (stem.length < 3) stem = (prefix + slug(ip)).slice(0, 40);
  let id = stem;
  let k = 1;
  while (ctx.idTaken(id)) { k++; const suf = '-' + k; id = (stem.slice(0, 40 - suf.length) + suf); if (k > 50) break; }
  if (!ID_RE.test(id)) { errors.push(`could not derive a valid source id from "${name || ip}"`); return out; }

  const proto = tpl.proto;
  const port = proto === 'tls' ? ctx.siem.tls_port : ctx.siem.syslog_port;
  const resolved = {
    id, kind: tpl.kind, type: tpl.parser, template: tpl.type, vendor: vendor || tpl.vendor,
    parser: tpl.parser, planned_parser: tpl.planned_parser || null, category: tpl.category,
    proto, port, snmp: tpl.snmp || 0, source_kind: tpl.source_kind, sama: tpl.sama,
    site, match_ip: matchIp, label: (name || vendor || tpl.vendor + ' ' + tpl.type).slice(0, 120),
    syslog_target: `${ctx.siem.siem_ip}:${port}/${proto}`,
    instruction: `Point this device's syslog at ${ctx.siem.siem_ip}:${port} over ${proto.toUpperCase()}`,
  };

  // idempotency: an existing source with the same kind + match IP is already onboarded → skip
  const existing = ctx.existingByIpKind(matchIp, tpl.kind);
  if (existing) { out.ok = true; out.action = 'skip'; out.reason = `already onboarded as "${existing.id}"`; out.existing_id = existing.id; out.resolved = Object.assign({}, resolved, { id: existing.id }); return out; }

  out.ok = true; out.action = 'create'; out.resolved = resolved;
  return out;
}

// ---- gather + de-dupe the request's device rows --------------------------------------------------------------------
function gather(b) {
  let rows = [];
  if (typeof b.csv === 'string' && b.csv.trim()) rows = parseCsv(b.csv);
  if (Array.isArray(b.devices)) rows = rows.concat(b.devices.map((d) => (d && typeof d === 'object' ? d : {})));
  return rows;
}

function buildCtx(deps, defaults) {
  const cfg = deps.config || {};
  const store = deps.onboard && deps.onboard.store ? deps.onboard.store : deps.onboardStore;
  const { validateIp } = require('./store');
  const ob = cfg.onboard || {};
  const SITE_ID_RE = /^[a-z0-9-]{2,32}$/;
  const sites = () => (Array.isArray(ob.sites) ? ob.sites.filter((x) => x && SITE_ID_RE.test(String(x.id || ''))) : []);
  const siteOf = (id) => sites().find((x) => x.id === id) || null;
  const v = catalog.siteVars(cfg);
  const taken = new Set((store.list() || []).map((s) => s && s.id).filter(Boolean));
  const existing = (store.list() || []).filter((s) => s && s.id);
  return {
    defaults, validateIp, siteOf, siteIds: () => sites().map((x) => x.id),
    siem: { siem_ip: v.siem_ip, siem_host: v.siem_host, syslog_port: v.syslog_port, tls_port: v.tls_port },
    idTaken: (id) => taken.has(id),
    reserve: (id) => taken.add(id),
    existingByIpKind: (ip, kind) => existing.find((s) => s.kind === kind && ((s.match && (s.match.ip === ip || s.match.cidr === ip)) || (Array.isArray(s.allowed_peers) && s.allowed_peers.indexOf(ip) >= 0))) || null,
    store,
  };
}

function previewRows(deps, b) {
  const defaults = (b && b.defaults && typeof b.defaults === 'object') ? b.defaults : {};
  const ctx = buildCtx(deps, defaults);
  const inputs = gather(b);
  if (!inputs.length) throw new HttpError(400, 'no devices — provide csv text or a devices[] list');
  if (inputs.length > BULK_MAX) throw new HttpError(409, `${inputs.length} devices requested; the limit per request is ${BULK_MAX}`);
  const rows = [];
  const seen = new Set(); // in-batch ip+kind de-dupe
  for (const input of inputs) {
    const r = resolveRow(input, ctx);
    if (r.ok && r.resolved) {
      const key = r.resolved.kind + '|' + r.resolved.match_ip;
      if (seen.has(key)) { r.action = 'skip'; r.reason = r.reason || 'duplicate of an earlier row in this batch'; }
      else { seen.add(key); if (r.action === 'create') ctx.reserve(r.resolved.id); }
    }
    rows.push(r);
  }
  return { ctx, rows, summary: summarize(rows) };
}

function summarize(rows) {
  const s = { total: rows.length, create: 0, skip: 0, error: 0, created: 0, updated: 0, skipped: 0, errors: 0 };
  for (const r of rows) {
    if (!r.ok || r.action === 'error') s.error++;
    else if (r.action === 'skip') s.skip++;
    else s.create++;
    if (r.result === 'created') s.created++;
    else if (r.result === 'skipped') s.skipped++;
    else if (r.result === 'error') s.errors++;
  }
  return s;
}

// ---- map a discovered device (sentra-itam results.devices[]) to a bulk device row -------------------------------------
function classifyDiscovered(d) {
  const vendor = String(d.vendor || '').toLowerCase();
  const os = String(d.os || '').toLowerCase();
  const name = String(d.hostname || d.name || '').toLowerCase();
  const cls = String(d.class || d.type || '').toLowerCase();
  const text = vendor + ' ' + os + ' ' + name;
  const fw = cls === 'firewall' || /firewall|ngfw/.test(text);
  if (/forti/.test(text)) return fw ? 'fortigate' : 'fortigate';
  if (/palo alto|pan-os|panorama/.test(text)) return 'palo-alto';
  if (fw && /cisco/.test(vendor)) return 'cisco-asa-ftd';
  if (/zscaler/.test(text)) return 'zscaler';
  if (/esxi|vmware/.test(text)) return 'esxi';
  if (/netscaler|citrix/.test(text)) return 'citrix-netscaler';
  if (/\bf5\b|big-?ip/.test(text)) return 'f5-bigip';
  if (/aruba|hpe|hewlett|procurve/.test(text)) return 'aruba-hpe';
  if (/cisco/.test(vendor) && ['switch', 'router', 'ap', 'network'].includes(cls)) return 'cisco-ios';
  if (['switch', 'router', 'ap', 'network', 'firewall'].includes(cls)) return 'generic-syslog';
  return null; // not an onboardable network/security device (server, printer, phone, workstation…)
}
function discoveredToDevice(d, siteFallback) {
  const type = classifyDiscovered(d);
  if (!type) return null;
  const ip = d.ip || (Array.isArray(d.ips) && d.ips[0]) || '';
  return { ip, name: d.hostname || d.name || '', type, vendor: d.vendor || '', site: d.site || siteFallback || '', _discovered: true };
}

function register(api, deps, ob) {
  const B = ob.B; // "{P}/onboard"
  const log = deps.log || { info() {}, warn() {}, error() {} };
  const discovery = deps.discoveryClient || null; // injectable; HTTP client wired by the caller when configured

  // make sure deps.onboard.store is visible to buildCtx (routes.js sets deps.onboard = {store})
  if (!deps.onboard) deps.onboard = { store: ob.store };

  api.route('GET', `${B}/bulk/templates`, wrap(deps, null, (ctx) => {
    const cfg = deps.config || {};
    const v = catalog.siteVars(cfg);
    const tlsEnabled = !!(cfg.syslog && cfg.syslog.tls && cfg.syslog.tls.enabled);
    const list = templates().list.map((t) => ({
      type: t.type, label: t.label, vendor: t.vendor, category: t.category, kind: t.kind,
      parser: t.parser, planned_parser: t.planned_parser || null, proto: t.proto,
      port: t.proto === 'tls' ? v.tls_port : v.syslog_port, snmp: t.snmp || 0,
      source_kind: t.source_kind, sama: t.sama, id_prefix: t.id_prefix,
    }));
    const sites = Array.isArray((cfg.onboard || {}).sites) ? cfg.onboard.sites : [];
    return ctx.ok({ version: TPL.version, templates: list, csv_header: CSV_COLS.join(','),
      siem: { host: v.siem_host, ip: v.siem_ip, syslog_port: v.syslog_port, tls_port: v.tls_port, tls_enabled: tlsEnabled },
      sites, bulk_max: BULK_MAX });
  }));

  api.route('POST', `${B}/bulk/preview`, wrap(deps, 'admin', (ctx) => {
    const { rows, summary } = previewRows(deps, body(ctx));
    audit(ctx, 'onboard.bulk.preview', 'bulk', { total: summary.total, create: summary.create, skip: summary.skip, error: summary.error });
    return ctx.ok({ rows: rows.map(publicRow), summary, dry_run: true });
  }));

  api.route('POST', `${B}/bulk/commit`, wrap(deps, 'admin', (ctx) => {
    const { ctx: rctx, rows } = previewRows(deps, body(ctx));
    commitRows(rctx, rows, ctx.user);
    const summary = summarize(rows);
    audit(ctx, 'onboard.bulk.commit', 'bulk', { total: summary.total, created: summary.created, skipped: summary.skipped, errors: summary.errors });
    return ctx.ok({ rows: rows.map(publicRow), summary });
  }));

  api.route('POST', `${B}/bulk/discover`, wrap(deps, 'admin', async (ctx) => {
    if (!discovery) throw new HttpError(503, 'range discovery is not configured (set config.onboard.discovery.base_url + secret_file, or inject a discovery client)');
    const b = body(ctx);
    const scopeId = String(b.scope_id || '').trim();
    if (!scopeId) throw new HttpError(400, 'scope_id is required (create the CIDR scope + complete its pre-scan checklist in Asset Discovery first)');
    const who = { user: ctx.user, role: 'admin', ip: ctx.ip };
    let scope;
    try { scope = await discovery.scope(scopeId, who); } catch (e) { throw new HttpError(e.status && e.status < 500 ? e.status : 502, `discovery: ${e.message}`); }
    if (!scope) throw new HttpError(404, `discovery scope "${scopeId}" not found`);
    const gate = scope.gate || { open: false };
    // respect the pre-scan GATE: only trigger an active run when the checklist is complete for these targets
    let run = null;
    if (b.run) {
      if (gate.required && !gate.open) throw new HttpError(409, 'pre-scan checklist not completed for this scope — complete it in Asset Discovery (safety gate) before launching an active scan');
      try { run = await discovery.run(scopeId, who); } catch (e) { throw new HttpError(e.status && e.status < 500 ? e.status : 502, `discovery run: ${e.message}`); }
    }
    let discovered;
    try { discovered = await discovery.results({ scope_id: scopeId }, who); } catch (e) { throw new HttpError(e.status && e.status < 500 ? e.status : 502, `discovery results: ${e.message}`); }
    const devs = (discovered && discovered.devices) || [];
    const siteFallback = (b.defaults && b.defaults.site) || scope.site || '';
    const mapped = [];
    const skipped = [];
    for (const d of devs) { const m = discoveredToDevice(d, siteFallback); if (m) mapped.push(m); else skipped.push({ ip: d.ip || (d.ips || [])[0] || '', reason: 'not an onboardable network/security device' }); }
    const result = { scope: { id: scope.id, name: scope.name, site: scope.site }, gate, run: run ? { id: run.id, status: run.status } : null, discovered: devs.length, onboardable: mapped.length, devices: mapped, not_onboardable: skipped };

    if (b.adopt) {
      const defaults = Object.assign({ site: siteFallback }, (b.defaults && typeof b.defaults === 'object') ? b.defaults : {});
      const { ctx: rctx, rows } = previewRows(deps, { devices: mapped, defaults });
      commitRows(rctx, rows, ctx.user);
      result.rows = rows.map(publicRow);
      result.summary = summarize(rows);
      audit(ctx, 'onboard.bulk.discover-adopt', scopeId, { discovered: devs.length, onboardable: mapped.length, created: result.summary.created, skipped: result.summary.skipped, errors: result.summary.errors, ran: !!run });
    } else {
      audit(ctx, 'onboard.bulk.discover', scopeId, { discovered: devs.length, onboardable: mapped.length, ran: !!run, gate_open: !!gate.open });
    }
    return ctx.ok(result);
  }));
}

// perform the writes for a resolved preview (reuses store.create — nothing forked); fills r.result + r.token (ONCE)
function commitRows(rctx, rows, user) {
  const store = rctx.store;
  for (const r of rows) {
    if (!r.ok || r.action === 'error') { r.result = 'error'; continue; }
    if (r.action === 'skip') { r.result = 'skipped'; continue; }
    const d = r.resolved;
    try {
      const made = store.create({ id: d.id, kind: d.kind, type: d.type, match_ip: d.match_ip, label: d.label, site: d.site, allow_public: !!rctx.defaults.allow_public, by: user, needs_ip: d.source_kind === 'syslog', mints_token: d.source_kind === 'token' });
      r.result = 'created'; r.source = made.source; if (made.token) { r.token = made.token; r.token_shown_once = true; }
    } catch (e) {
      if (e instanceof StoreError && e.code === 409) { r.result = 'skipped'; r.reason = e.message; }
      else { r.result = 'error'; r.ok = false; r.action = 'error'; r.errors = (r.errors || []).concat([(e && e.message) || 'create failed']); }
    }
  }
  return rows;
}

// never leak tokens into logs/audit; token is only on the row returned to the admin once
function publicRow(r) {
  const o = { input: r.input, ok: r.ok, action: r.action };
  if (r.errors && r.errors.length) o.errors = r.errors;
  if (r.reason) o.reason = r.reason;
  if (r.existing_id) o.existing_id = r.existing_id;
  if (r.resolved) o.resolved = r.resolved;
  if (r.result) o.result = r.result;
  if (r.token) { o.token = r.token; o.token_shown_once = true; }
  return o;
}

module.exports = { register, parseCsv, resolveRow, resolveTemplates, templateFor, templates, classifyDiscovered, discoveredToDevice, slug, previewRows, commitRows, summarize, BULK_MAX, CSV_COLS };
