// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * NetFlow traffic analytics over the flow collector's rollups (engine/collect/flow-collector.js → ClickHouse flow_minute,
 * flow_if_minute, flow_ip_hour) and its live last hour. Read-only towards every device: nothing here changes a router.
 *   createFlowAnalytics({ state, ch, config, log, alerts, intel, mail, netops, now })
 *     settings / exporters / groups / applications / alarms / templates / detection: validated, kept in the SIEM state
 *     queries: interfaces, top (app / protocol / DSCP / port / exporter), talkers + conversations, groups, billing,
 *              forecast + capacity, hour-of-week patterns
 *     onMinute(summary)  alarms (utilisation %, Mbps, volume, new top talker) per interface / group / application / total
 *     observe(flow) + the minute close  security detections (port scan, host sweep, unusual outbound volume, known-bad
 *              addresses from the SIEM's threat-intel lists) raised through the alert pipeline (alerts.raise), like the
 *              other detectors
 * Never invented: utilisation needs the interface speed (SNMP poller or the exporter setting); a bill needs a rate per GB
 * an administrator set; a forecast needs MIN_DAYS of daily peaks; a pattern needs two weeks of hours - otherwise the
 * answer says what is missing.
 */
const { body, param } = require('../util/check');
const { HttpError } = require('./routeutil');
const { parseCidr, createCidrSet, isPrivate } = require('../detect/ip');
const { createAppMapper, protoName } = require('../collect/flow-collector-apps');

const MIN_DAYS = 14;
const RANGES = { 15: 15, 60: 60, 360: 72, 1440: 96, 10080: 84, 43200: 60 };   // minutes → chart buckets
const RANGE_KEYS = Object.keys(RANGES);
const PLACEHOLDERS = ['alarm', 'target', 'metric', 'value', 'threshold', 'unit', 'severity', 'state', 'time'];
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const EMAIL = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const escH = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const r1 = (v) => Math.round(v * 10) / 10, r2 = (v) => Math.round(v * 100) / 100;
const mbps = (bytes, seconds) => (seconds > 0 ? bytes * 8 / seconds / 1e6 : 0);
const DEFAULTS = { enabled: false, host: '0.0.0.0', ports: { netflow: 2055, ipfix: 4739, sflow: 6343 }, raw_per_minute: 500, template_ttl_s: 1800, max_keys: 200000, tz_offset_min: 180 };
const DETECT = { enabled: true, scan_ports: 100, sweep_hosts: 50, outbound_mb: 500, outbound_factor: 10, learn_minutes: 120, exclude: [], intel: true };

// ---------------------------------------------------------------------------------------------------- forecasting maths
function linreg(xs, ys) {
  const n = xs.length; if (n < 2) return null;
  let sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (let i = 0; i < n; i++) { sx += xs[i]; sy += ys[i]; sxx += xs[i] * xs[i]; sxy += xs[i] * ys[i]; }
  const d = n * sxx - sx * sx; if (!d) return null;
  const slope = (n * sxy - sx * sy) / d, intercept = (sy - slope * sx) / n, my = sy / n;
  let ssr = 0, sst = 0; for (let i = 0; i < n; i++) { const f = intercept + slope * xs[i]; ssr += (ys[i] - f) ** 2; sst += (ys[i] - my) ** 2; }
  return { slope, intercept, r2: sst ? 1 - ssr / sst : 1 };
}
// Holt's linear (double exponential) smoothing
function holt(ys, alpha = 0.5, beta = 0.3) {
  if (ys.length < 2) return null;
  let level = ys[0], trend = ys[1] - ys[0];
  for (let i = 1; i < ys.length; i++) { const l0 = level; level = alpha * ys[i] + (1 - alpha) * (level + trend); trend = beta * (level - l0) + (1 - beta) * trend; }
  return { level, trend };
}
/* daily peaks [{day, v}] (v = utilisation % when the speed is known, else Mbps) → when 80 % / 100 % are reached */
function forecastSeries(points, opts = {}) {
  const minDays = opts.minDays || MIN_DAYS, util = !!opts.util;
  if (points.length < minDays) return { enough: false, days: points.length, needs: minDays, note: `needs ${minDays} days of daily peaks - ${points.length} so far (${minDays - points.length} more)` };
  const x0 = points[0].day, xs = points.map((p) => (p.day - x0) / 86400000), ys = points.map((p) => p.v), last = xs[xs.length - 1];
  const lr = linreg(xs, ys), h = holt(ys);
  const when = (target) => {
    const out = {};
    if (lr && lr.slope > 0) { const x = (target - lr.intercept) / lr.slope - last; out.linear = x <= 0 ? 0 : Math.ceil(x); } else out.linear = null;
    if (h && h.trend > 0) { const x = (target - h.level) / h.trend; out.holt = x <= 0 ? 0 : Math.ceil(x); } else out.holt = null;
    return out;
  };
  const r = { enough: true, days: points.length, slope_per_day: lr ? r2(lr.slope) : null, intercept: lr ? r2(lr.intercept) : null, r2: lr ? r2(lr.r2) : null, holt_level: h ? r2(h.level) : null, holt_trend: h ? r2(h.trend) : null,
    current_peak: r2(ys[ys.length - 1]), max_peak: r2(Math.max(...ys)), in_30: lr ? r2(lr.intercept + lr.slope * (last + 30)) : null, in_90: lr ? r2(lr.intercept + lr.slope * (last + 90)) : null };
  if (util) { r.to80 = when(80); r.to100 = when(100); r.growing = !!((lr && lr.slope > 0) || (h && h.trend > 0)); }
  return r;
}
/* hour-of-week baseline: [{t (ms, hour start), b (bytes)}] → baseline per slot + deviations of the last 7 days */
function hourOfWeek(rows, now, tzMin, opts = {}) {
  const weekAgo = now - 7 * 86400000, slots = Array.from({ length: 168 }, () => []), cur = [];
  const slot = (t) => { const d = new Date(t + tzMin * 60000); return ((d.getUTCDay() + 6) % 7) * 24 + d.getUTCHours(); };   // Monday 00 = slot 0, local time
  for (const r of rows) { const s = slot(r.t); if (r.t < weekAgo) slots[s].push(r.b); else cur.push({ t: r.t, s, b: r.b }); }
  const base = slots.map((v) => { if (!v.length) return { n: 0, mean: null, sd: null }; const m = v.reduce((a, b) => a + b, 0) / v.length; const sd = Math.sqrt(v.reduce((a, b) => a + (b - m) ** 2, 0) / v.length); return { n: v.length, mean: m, sd }; });
  const ready = base.filter((b) => b.n >= 2).length;
  const out = { slots_ready: ready, enough: ready >= 168 * 0.8, baseline: base.map((b) => (b.mean == null ? null : Math.round(b.mean))) };
  if (!out.enough) { out.note = `needs two weeks of hourly history before the last 7 days - ${ready} of 168 hour-of-week slots have it`; out.deviations = []; return out; }
  const z = opts.z || 3;
  out.deviations = cur.map((c) => { const b = base[c.s]; const sd = Math.max(b.sd, b.mean * 0.1, 1); return { t: c.t, slot: c.s, bytes: c.b, usual: Math.round(b.mean), z: r1((c.b - b.mean) / sd) }; })
    .filter((d) => Math.abs(d.z) >= z).sort((a, b) => Math.abs(b.z) - Math.abs(a.z)).slice(0, 50);
  out.current = cur.map((c) => ({ t: c.t, slot: c.s, bytes: c.b }));
  return out;
}

// ---------------------------------------------------------------------------------------------------- templates
function render(tpl, vars) {
  const has = (k) => Object.prototype.hasOwnProperty.call(vars, k);
  const sub = (s, html) => String(s).replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (m, k) => (has(k) ? (html ? escH(vars[k]) : String(vars[k])) : ''));
  return { subject: sub(tpl.subject, false).replace(/[\r\n]+/g, ' ').slice(0, 200), text: sub(tpl.body, false).slice(0, 10000), html: sub(escH(tpl.body), true).replace(/\r?\n/g, '<br>').slice(0, 40000) };
}
const DEFAULT_TEMPLATE = { id: 'default', name: 'Default', subject: '[NETFLOW] {{alarm}} - {{target}} {{state}}', body: ('Alarm: {{alarm}}\nTarget: {{target}}\nMetric: {{metric}}\nValue: {{value}} {{unit}} (threshold {{threshold}} {{unit}})\nSeverity: {{severity}}\nState: {{state}}\nTime: {{time}}\n\nNetFlow Analytics, ' + ZYB_ORG.short + ' SIEM') };

// ---------------------------------------------------------------------------------------------------- the module
function createFlowAnalytics({ state, ch, config, log, alerts, intel, mail, netops, now } = {}) {
  if (!state) throw new Error('flow analytics needs deps.state');
  const NOW = now || Date.now, L = log || { info() {}, warn() {}, error() {}, every() {} };
  const every = (k, ms, lvl, msg, f) => { if (typeof L.every === 'function') L.every(k, ms, lvl, msg, f); else if (L[lvl]) L[lvl](msg, f); };
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';
  const fileCfg = (config && config.netflow) || {};
  const C = { cfg: state.collection('netflow_cfg'), exp: state.collection('netflow_exporters'), groups: state.collection('netflow_groups'), apps: state.collection('netflow_apps'),
    alarms: state.collection('netflow_alarms'), tpl: state.collection('netflow_templates'), events: state.collection('netflow_alarm_events'), det: state.collection('netflow_detections') };
  const newId = (p) => p + '-' + NOW().toString(36) + Math.random().toString(36).slice(2, 6);
  let onChange = () => {};

  // ------------------------------------------------------------------ settings
  function settings() {
    const s = C.cfg.get('settings') || {};
    const ports = Object.assign({}, DEFAULTS.ports, fileCfg.ports || {}, s.ports || {});
    return { enabled: s.enabled !== undefined ? s.enabled : fileCfg.enabled !== undefined ? !!fileCfg.enabled : DEFAULTS.enabled, host: fileCfg.host || DEFAULTS.host, ports,
      raw_per_minute: s.raw_per_minute != null ? s.raw_per_minute : fileCfg.raw_per_minute != null ? fileCfg.raw_per_minute : DEFAULTS.raw_per_minute,
      template_ttl_s: s.template_ttl_s || fileCfg.template_ttl_s || DEFAULTS.template_ttl_s, max_keys: fileCfg.max_keys || DEFAULTS.max_keys,
      tz_offset_min: fileCfg.tz_offset_min != null ? fileCfg.tz_offset_min : DEFAULTS.tz_offset_min, by: s.by || null, at: s.at || null };
  }
  function exporters() {
    const m = new Map();
    for (const e of fileCfg.exporters || []) if (e && typeof e.ip === 'string') m.set(e.ip.toLowerCase(), { id: 'cfg-' + e.ip.replace(/[^0-9A-Za-z]/g, '-'), ip: e.ip.toLowerCase(), name: String(e.name || '').slice(0, 80), sampling: e.sampling || null, if_speeds: [], from: 'config.json' });
    for (const e of C.exp.all()) m.set(e.ip, Object.assign({ from: 'portal' }, e));
    return [...m.values()].sort((a, b) => a.ip.localeCompare(b.ip));
  }
  function collectorSettings() { return Object.assign(settings(), { exporters: exporters() }); }
  function saveSettings(b, by) {
    const v = body(b).bool('enabled').int('raw_per_minute', { min: 0, max: 5000 }).int('template_ttl_s', { min: 60, max: 86400 }).done();
    if (b && b.ports !== undefined) {
      if (!b.ports || typeof b.ports !== 'object' || Array.isArray(b.ports)) throw new HttpError(400, 'ports must be an object {netflow, ipfix, sflow}');
      const p = body(b.ports).int('netflow', { min: 0, max: 65535 }).int('ipfix', { min: 0, max: 65535 }).int('sflow', { min: 0, max: 65535 }).done();
      for (const [k, port] of Object.entries(p)) if (port && port < 1024) throw new HttpError(400, `ports.${k} must be 0 (off) or 1024-65535 (the engine does not run as root)`);
      v.ports = p;
    }
    const cur = C.cfg.get('settings') || { id: 'settings' };
    const next = Object.assign({}, cur, v, { ports: Object.assign({}, cur.ports || {}, v.ports || {}), id: 'settings', by, at: NOW() });
    C.cfg.put(next);
    const changed = Object.keys(v).filter((k) => JSON.stringify(v[k]) !== JSON.stringify(cur[k]));
    return { settings: settings(), changed };
  }
  function saveExporter(b, by) {
    const v = body(b).str('ip', { required: true, ip: true, max: 39 }).str('name', { max: 80 }).int('sampling', { min: 1, max: 1000000 }).list('if_speeds', { max: 512 }).done();
    v.ip = v.ip.toLowerCase();
    const speeds = (v.if_speeds || []).map((x, i) => {
      if (!x || typeof x !== 'object' || Array.isArray(x)) throw new HttpError(400, `if_speeds[${i}] must be {if_index, mbps}`);
      try { return body(x).int('if_index', { required: true, min: 1, max: 4294967295 }).num('mbps', { required: true, min: 0.001, max: 4000000 }).str('name', { max: 60 }).done(); }
      catch (e) { throw new HttpError(400, `if_speeds[${i}].${e.message}`); }
    });
    const id = 'x-' + v.ip.replace(/[^0-9a-z]/g, '-'), old = C.exp.get(id);
    if (!old && C.exp.all().length >= 500) throw new HttpError(400, 'at most 500 exporters');
    const e = { id, ip: v.ip, name: v.name || '', sampling: v.sampling || null, if_speeds: speeds, by, at: NOW() };
    C.exp.put(e); onChange('exporters');
    return { exporter: e, created: !old };
  }
  function deleteExporter(id) { param(id); const e = C.exp.get(id); if (!e) throw new HttpError(404, 'exporter not found (exporters from config.json are removed there)'); C.exp.remove(id); onChange('exporters'); return e; }

  // ------------------------------------------------------------------ groups (departments, sites) + billing rates
  let groupIndex = null;
  function groups() { return C.groups.all().sort((a, b) => a.name.localeCompare(b.name)); }
  function index() {
    if (!groupIndex) groupIndex = groups().map((g) => ({ g, set: createCidrSet(g.cidrs) }));
    return groupIndex;
  }
  const groupsOf = (ip) => index().filter((x) => x.set.has(ip)).map((x) => x.g);
  const billable = (ip) => index().some((x) => x.set.has(ip));
  function cidrs(list, field) {
    return (list || []).map((c, i) => { try { parseCidr(c); } catch (e) { throw new HttpError(400, `${field}[${i}] "${String(c).slice(0, 50)}" is not an IP address or CIDR range`); } return c.trim(); });
  }
  function saveGroup(b, by) {
    const v = body(b).str('id', { id: true }).str('name', { required: true, max: 80 }).oneOf('kind', ['department', 'site', 'other'], { def: 'department' })
      .list('cidrs', { required: true, max: 64, item: 'str', itemMax: 50, unique: true }).num('rate_per_gb', { min: 0, max: 1000000 })
      .str('currency', { max: 8, re: /^[A-Z]{3}$/, msg: 'currency must be a 3-letter code (SAR)', def: 'SAR' }).done();
    v.cidrs = cidrs(v.cidrs, 'cidrs');
    const old = v.id ? C.groups.get(v.id) : null;
    if (v.id && !old) throw new HttpError(404, 'group not found');
    if (groups().some((g) => g.name.toLowerCase() === v.name.toLowerCase() && g.id !== v.id)) throw new HttpError(400, `name: a group "${v.name}" already exists`);
    if (!old && groups().length >= 300) throw new HttpError(400, 'at most 300 groups');
    const g = { id: v.id || newId('g'), name: v.name, kind: v.kind, cidrs: v.cidrs, rate_per_gb: v.rate_per_gb != null ? v.rate_per_gb : null, currency: v.currency, by, at: NOW() };
    C.groups.put(g); groupIndex = null;
    const detail = { name: g.name, cidrs: g.cidrs.length, rate_per_gb: g.rate_per_gb };
    if (old) { if (old.rate_per_gb !== g.rate_per_gb) detail.rate_from = old.rate_per_gb; if (old.cidrs.join() !== g.cidrs.join()) detail.cidrs_changed = true; }
    return { group: g, created: !old, detail };
  }
  function deleteGroup(id) {
    param(id); const g = C.groups.get(id); if (!g) throw new HttpError(404, 'group not found');
    const used = C.alarms.all().filter((a) => a.scope === 'group' && a.target === id); if (used.length) throw new HttpError(409, `alarm "${used[0].name}" watches this group - delete or change it first`);
    C.groups.remove(id); groupIndex = null; return g;
  }

  // ------------------------------------------------------------------ custom applications
  let mapperCache = null;
  function apps() { return C.apps.all().sort((a, b) => a.name.localeCompare(b.name)); }
  function mapper() { if (!mapperCache) mapperCache = createAppMapper(apps()); return mapperCache; }
  function saveApp(b, by) {
    const v = body(b).str('id', { id: true }).str('name', { required: true, max: 60 }).oneOf('proto', ['tcp', 'udp', 'any'], { def: 'any' })
      .list('ports', { max: 50, item: 'str', itemMax: 11 }).list('cidrs', { max: 32, item: 'str', itemMax: 50, unique: true }).done();
    if (/^\(|^app /i.test(v.name)) throw new HttpError(400, 'name: may not start with "(" or "app "');
    const ports = (v.ports || []).map((p, i) => { const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p); const lo = m && Number(m[1]), hi = m && Number(m[2] || m[1]);
      if (!m || lo < 1 || hi > 65535 || lo > hi) throw new HttpError(400, `ports[${i}] "${String(p).slice(0, 20)}" must be a port (1-65535) or a range (8000-8080)`); return [lo, hi]; });
    const cl = cidrs(v.cidrs, 'cidrs');
    if (!ports.length && !cl.length) throw new HttpError(400, 'ports or cidrs: give at least one port or one address range');
    const old = v.id ? C.apps.get(v.id) : null;
    if (v.id && !old) throw new HttpError(404, 'application not found');
    if (!old && apps().length >= 500) throw new HttpError(400, 'at most 500 custom applications');
    const a = { id: v.id || newId('a'), name: v.name, proto: v.proto, ports, cidrs: cl, by, at: NOW() };
    C.apps.put(a); mapperCache = null; onChange('apps');
    return { app: a, created: !old };
  }
  function deleteApp(id) { param(id); const a = C.apps.get(id); if (!a) throw new HttpError(404, 'application not found'); C.apps.remove(id); mapperCache = null; onChange('apps'); return a; }

  // ------------------------------------------------------------------ interface speeds: exporter setting, else the SNMP poller
  function speeds() {
    const m = new Map();
    try {
      const N = typeof netops === 'function' ? netops() : netops;
      if (N && N.inventory && N.poller) {
        for (const d of N.inventory.list()) {
          const s = d.ip && N.poller.snapshot(d.id); if (!s || !s.interfaces) continue;
          for (const i of s.interfaces) if (i.index && i.speed_mbps) m.set(String(d.ip).toLowerCase() + '#' + i.index, { mbps: Number(i.speed_mbps), name: i.name || '', source: 'SNMP poller (' + (d.name || d.id) + ')' });
        }
      }
    } catch (e) { every('netflow-speeds', 600000, 'warn', 'netflow: interface speeds from the poller not read', { err: String(e.message).slice(0, 200) }); }
    for (const e of exporters()) for (const s of e.if_speeds || []) m.set(e.ip + '#' + s.if_index, { mbps: s.mbps, name: s.name || (m.get(e.ip + '#' + s.if_index) || {}).name || '', source: 'exporter setting' });
    return m;
  }
  const expName = () => new Map(exporters().map((e) => [e.ip, e.name || '']));

  // ------------------------------------------------------------------ ClickHouse
  async function q(tag, sql, params) {
    if (!ch || typeof ch.query !== 'function') throw new HttpError(503, 'ClickHouse is not available to this engine - flow history needs it');
    try { return await ch.query(`/*q:${tag}*/ ` + sql, params || {}, { readonly: true, timeout_ms: 30000 }); } catch (e) {
      if (e && (e.chCode === 60 || /UNKNOWN_TABLE|doesn't exist/.test(String(e.message)))) throw new HttpError(503, 'the NetFlow tables are not in ClickHouse yet - run the SIEM update (it applies engine/store/schema.sql)');
      throw e;
    }
  }
  function opts(query, allowed) {
    const qq = Object.assign({}, query || {}); if (qq.range != null && qq.range !== '') qq.range = String(qq.range);
    const v = body(qq).oneOf('range', allowed || RANGE_KEYS, { def: allowed ? allowed[0] : '60' }).str('exporter', { ip: true, max: 39 }).int('if', { min: 1, max: 4294967295 }).done();
    const range = Number(v.range), to = Math.floor(NOW() / 60000) * 60, from = to - range * 60, step = Math.max(60, Math.ceil((to - from) / RANGES[range] / 60) * 60);
    return { range, from, to, step, buckets: Math.ceil((to - from) / step), exporter: v.exporter ? v.exporter.toLowerCase() : '', if_index: v.if || 0 };
  }
  function where(o, col, extra) {
    const p = { f: { type: 'Int64', value: o.from }, t: { type: 'Int64', value: o.to } };
    let w = `${col || 'minute'} >= toDateTime({f:Int64}) AND ${col || 'minute'} < toDateTime({t:Int64})`;
    if (o.exporter) { w += ' AND exporter = {exp:String}'; p.exp = { type: 'String', value: o.exporter }; }
    if (extra) w += ' AND ' + extra;
    return { w, p };
  }

  async function interfaces(query) {
    const o = opts(query), sp = speeds(), names = expName();
    const ifw = where(o, 'minute', o.if_index ? 'if_index = {ifx:UInt32}' : null); if (o.if_index) ifw.p.ifx = { type: 'UInt32', value: o.if_index };
    const T = db + '.flow_if_minute', M = db + '.flow_minute';
    const [list, series, total] = await Promise.all([
      q('if_list', `SELECT exporter, if_index, dir, sum(b) AS bytes, sum(p) AS packets, max(b) AS peak FROM (SELECT exporter, if_index, dir, minute, sum(bytes) AS b, sum(packets) AS p FROM ${T} WHERE ${ifw.w} GROUP BY exporter, if_index, dir, minute) GROUP BY exporter, if_index, dir ORDER BY bytes DESC LIMIT 400`, ifw.p),
      o.if_index ? q('if_series', `SELECT intDiv(toUnixTimestamp(minute) - {f:Int64}, {st:Int64}) AS k, dir, sum(bytes) AS b FROM ${T} WHERE ${ifw.w} GROUP BY k, dir ORDER BY k`, Object.assign({ st: { type: 'Int64', value: o.step } }, ifw.p)) : null,
      q('if_total', `SELECT intDiv(toUnixTimestamp(minute) - {f:Int64}, {st:Int64}) AS k, sum(bytes) AS b, sum(flows) AS n FROM ${M} WHERE ${where(o).w} GROUP BY k ORDER BY k`, Object.assign({ st: { type: 'Int64', value: o.step } }, where(o).p)),
    ]);
    const secs = o.to - o.from, m = new Map();
    for (const r of list) {
      const k = r.exporter + '#' + r.if_index; let x = m.get(k);
      if (!x) { const s = sp.get(k); x = { exporter: r.exporter, exporter_name: names.get(r.exporter) || '', if_index: num(r.if_index), if_name: s ? s.name : '', speed_mbps: s ? s.mbps : null, speed_source: s ? s.source : null, in_bytes: 0, out_bytes: 0, in_avg_mbps: 0, out_avg_mbps: 0, in_peak_mbps: 0, out_peak_mbps: 0 }; m.set(k, x); }
      const d = r.dir === 'out' ? 'out' : 'in';
      x[d + '_bytes'] = num(r.bytes); x[d + '_avg_mbps'] = r2(mbps(num(r.bytes), secs)); x[d + '_peak_mbps'] = r2(mbps(num(r.peak), 60));
    }
    const rows = [...m.values()].map((x) => Object.assign(x, x.speed_mbps ? { util_in_peak: r1(x.in_peak_mbps / x.speed_mbps * 100), util_out_peak: r1(x.out_peak_mbps / x.speed_mbps * 100), util_in_avg: r1(x.in_avg_mbps / x.speed_mbps * 100), util_out_avg: r1(x.out_avg_mbps / x.speed_mbps * 100) } : { util_in_peak: null, util_out_peak: null, util_in_avg: null, util_out_avg: null }));
    const fill = (rs, pick) => { const by = new Map(rs.map((r) => [num(r.k), r])); return Array.from({ length: o.buckets }, (_, i) => { const r = by.get(i); return r ? pick(r) : 0; }); };
    const t = Array.from({ length: o.buckets }, (_, i) => (o.from + i * o.step) * 1000);
    const out = { range: o.range, from: o.from * 1000, to: o.to * 1000, step_s: o.step, interfaces: rows, times: t,
      total_mbps: fill(total, (r) => r2(mbps(num(r.b), o.step))), total_flows: fill(total, (r) => num(r.n)), has_data: total.length > 0 || rows.length > 0 };
    if (series) {
      const sel = rows.find((x) => x.if_index === o.if_index && (!o.exporter || x.exporter === o.exporter)) || null;
      out.selected = { exporter: o.exporter, if_index: o.if_index, speed_mbps: sel ? sel.speed_mbps : null,
        in_mbps: fill(series.filter((r) => r.dir === 'in'), (r) => r2(mbps(num(r.b), o.step))), out_mbps: fill(series.filter((r) => r.dir === 'out'), (r) => r2(mbps(num(r.b), o.step))) };
    }
    return out;
  }

  const TOP = { app: "if(app = '', concat('unclassified ', multiIf(proto = 6, 'TCP', proto = 17, 'UDP', concat('IP ', toString(proto))), if(dst_port != 0, concat('/', toString(dst_port)), if(src_port != 0, concat('/', toString(src_port)), ''))), app)",
    proto: 'toString(proto)', dscp: 'toString(dscp)', port: "concat(toString(proto), '/', toString(if(dst_port != 0, dst_port, src_port)))", exporter: 'exporter',
    if_in: "concat(exporter, '#', toString(if_in))", if_out: "concat(exporter, '#', toString(if_out))" };
  const DSCP = { 0: 'CS0 / best effort', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13', 16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23', 24: 'CS3', 26: 'AF31', 28: 'AF32', 30: 'AF33', 32: 'CS4', 34: 'AF41', 36: 'AF42', 38: 'AF43', 40: 'CS5', 44: 'VOICE-ADMIT', 46: 'EF (voice)', 48: 'CS6', 56: 'CS7' };
  function filt(o, extra) {
    const w = where(o, 'minute', extra);
    if (o.if_index) { w.w += ' AND (if_in = {ifx:UInt32} OR if_out = {ifx:UInt32})'; w.p.ifx = { type: 'UInt32', value: o.if_index }; }
    return w;
  }
  async function top(query) {
    const by = body(query || {}).oneOf('by', Object.keys(TOP), { def: 'app' }).done().by, o = opts(query), w = filt(o), K = TOP[by], M = db + '.flow_minute';
    const rows = await q('top_' + by, `SELECT ${K} AS k, sum(bytes) AS b, sum(packets) AS p, sum(flows) AS n FROM ${M} WHERE ${w.w} GROUP BY k ORDER BY b DESC LIMIT 50`, w.p);
    const keys = rows.slice(0, 6).map((r) => String(r.k));
    const series = keys.length ? await q('top_series', `SELECT intDiv(toUnixTimestamp(minute) - {f:Int64}, {st:Int64}) AS t, ${K} AS k, sum(bytes) AS b FROM ${M} WHERE ${w.w} AND ${K} IN {keys:Array(String)} GROUP BY t, k ORDER BY t`, Object.assign({ st: { type: 'Int64', value: o.step }, keys: { type: 'Array(String)', value: keys } }, w.p)) : [];
    const total = rows.reduce((a, r) => a + num(r.b), 0), secs = o.to - o.from;
    const label = (k) => (by === 'proto' ? protoName(Number(k)) : by === 'dscp' ? (DSCP[Number(k)] || 'DSCP ' + k) : by === 'port' ? protoName(Number(k.split('/')[0])) + '/' + k.split('/')[1] : k);
    return { by, range: o.range, from: o.from * 1000, to: o.to * 1000, step_s: o.step, total_bytes: total, times: Array.from({ length: o.buckets }, (_, i) => (o.from + i * o.step) * 1000),
      rows: rows.map((r) => ({ key: String(r.k), label: label(String(r.k)), bytes: num(r.b), packets: num(r.p), flows: num(r.n), share: total ? r1(num(r.b) / total * 100) : 0, avg_mbps: r2(mbps(num(r.b), secs)) })),
      series: keys.map((k) => { const by2 = new Map(series.filter((r) => String(r.k) === k).map((r) => [num(r.t), num(r.b)])); return { key: k, label: label(k), mbps: Array.from({ length: o.buckets }, (_, i) => r2(mbps(by2.get(i) || 0, o.step))) }; }) };
  }
  async function talkers(query) {
    const v = body(query || {}).oneOf('by', ['src', 'dst', 'conv'], { def: 'src' }).str('group', { id: true }).done(), o = opts(query);
    let extra = null; const w0 = filt(o);
    if (v.group) { const g = C.groups.get(v.group); if (!g) throw new HttpError(404, 'group not found'); extra = '(' + g.cidrs.map((c, i) => { w0.p['c' + i] = { type: 'String', value: c }; return `isIPAddressInRange(src_ip, {c${i}:String}) OR isIPAddressInRange(dst_ip, {c${i}:String})`; }).join(' OR ') + ')'; w0.w += ' AND ' + extra; }
    const M = db + '.flow_minute';
    const sql = v.by === 'conv'
      ? `SELECT src_ip AS a, dst_ip AS b2, any(app) AS app, any(proto) AS proto, max(if(dst_port != 0, dst_port, src_port)) AS port, sum(bytes) AS b, sum(packets) AS p, sum(flows) AS n FROM ${M} WHERE ${w0.w} AND src_ip != '' GROUP BY a, b2 ORDER BY b DESC LIMIT 100`
      : `SELECT ${v.by === 'src' ? 'src_ip' : 'dst_ip'} AS a, sum(bytes) AS b, sum(packets) AS p, sum(flows) AS n, uniqExact(${v.by === 'src' ? 'dst_ip' : 'src_ip'}) AS peers, topK(3)(app) AS apps FROM ${M} WHERE ${w0.w} AND ${v.by === 'src' ? 'src_ip' : 'dst_ip'} != '' GROUP BY a ORDER BY b DESC LIMIT 100`;
    const rows = await q('talk_' + v.by, sql, w0.p);
    const tag = (ip) => { const g = groupsOf(ip); return g.length ? g.map((x) => x.name).join(', ') : isPrivate(ip) ? 'internal' : 'external'; };
    return { by: v.by, range: o.range, group: v.group || null, rows: rows.map((r) => (v.by === 'conv'
      ? { src: r.a, src_group: tag(r.a), dst: r.b2, dst_group: tag(r.b2), app: r.app || '', proto: protoName(num(r.proto)), port: num(r.port), bytes: num(r.b), packets: num(r.p), flows: num(r.n) }
      : { ip: r.a, group: tag(r.a), bytes: num(r.b), packets: num(r.p), flows: num(r.n), peers: num(r.peers), apps: Array.isArray(r.apps) ? r.apps.filter(Boolean) : [] })) };
  }

  // per group over the hourly address table; an address in two groups counts in both (said in the note)
  async function groupBytes(fromS, toS, exporter, withApps) {
    const o = { from: fromS, to: toS, exporter };
    const w = where(o, 'hour');
    const rows = await q('grp_bytes', `SELECT ip, dir, ${withApps ? 'app, ' : ''}sum(bytes) AS b FROM ${db}.flow_ip_hour WHERE ${w.w} GROUP BY ip, dir${withApps ? ', app' : ''} LIMIT 500000`, w.p);
    const out = new Map(groups().map((g) => [g.id, { in_bytes: 0, out_bytes: 0, apps: new Map(), addresses: new Set() }]));
    let unassigned = 0;
    for (const r of rows) {
      const gs = groupsOf(r.ip), b = num(r.b);
      if (!gs.length) { unassigned += b; continue; }
      for (const g of gs) { const x = out.get(g.id); if (r.dir === 'dst') x.in_bytes += b; else x.out_bytes += b; if (withApps) x.apps.set(r.app || 'unclassified', (x.apps.get(r.app || 'unclassified') || 0) + b); if (x.addresses.size < 100000) x.addresses.add(r.ip); }
    }
    return { out, unassigned, truncated: rows.length >= 500000 };
  }
  async function groupsUsage(query) {
    const o = opts(query, ['1440', '10080', '43200']);
    const r = await groupBytes(Math.floor(o.from / 3600) * 3600, o.to, o.exporter, true);
    return { range: o.range, groups: groups().map((g) => { const x = r.out.get(g.id); return { id: g.id, name: g.name, kind: g.kind, cidrs: g.cidrs, rate_per_gb: g.rate_per_gb, currency: g.currency,
      in_bytes: x.in_bytes, out_bytes: x.out_bytes, addresses: x.addresses.size, apps: [...x.apps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([app, bytes]) => ({ app, bytes })) }; }),
    unassigned_private_bytes: r.unassigned, truncated: r.truncated, note: 'Download = traffic to the group\'s addresses, upload = from them; hourly totals. An address inside two groups counts in both.' };
  }
  async function billing(query) {
    const v = body(query || {}).str('month', { re: /^\d{4}-(0[1-9]|1[0-2])$/, msg: 'month must be YYYY-MM' }).str('exporter', { ip: true, max: 39 }).done();
    const d = new Date(NOW()), month = v.month || `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    const [y, mo] = month.split('-').map(Number), from = Date.UTC(y, mo - 1, 1) / 1000, to = Date.UTC(y, mo, 1) / 1000;
    if (from * 1000 > NOW()) throw new HttpError(400, 'month: that month has not started');
    const r = await groupBytes(from, Math.min(to, Math.ceil(NOW() / 3600000) * 3600), v.exporter ? v.exporter.toLowerCase() : '', false);
    let total = 0; const cur = new Set();
    const lines = groups().map((g) => { const x = r.out.get(g.id), bytes = x.in_bytes + x.out_bytes, gb = bytes / 1e9;
      const amount = g.rate_per_gb == null ? null : r2(gb * g.rate_per_gb); if (amount != null) { total += amount; cur.add(g.currency); }
      return { id: g.id, name: g.name, kind: g.kind, in_bytes: x.in_bytes, out_bytes: x.out_bytes, gb: Math.round(gb * 1000) / 1000, rate_per_gb: g.rate_per_gb, currency: g.currency, amount, note: amount == null ? 'no rate per GB set - not billed' : '' }; });
    return { month, partial: to * 1000 > NOW(), exporter: v.exporter || 'all', lines, total: cur.size === 1 ? r2(total) : null, currency: cur.size === 1 ? [...cur][0] : null,
      mixed_currencies: cur.size > 1, unassigned_private_bytes: r.unassigned, truncated: r.truncated,
      note: 'GB = 10^9 bytes, download + upload, from flow records (scaled by each exporter\'s sampling rate, so an estimate where sampling is on). Each exporter that sees the same traffic counts it again - choose one exporter for a bill when traffic crosses several. An address inside two groups is billed in both.' };
  }
  async function forecast(query) {
    const v = body(query || {}).str('exporter', { ip: true, max: 39 }).int('if', { min: 1, max: 4294967295 }).int('days', { min: 14, max: 400, def: 90 }).done();
    const o = { from: Math.floor(NOW() / 86400000) * 86400 - v.days * 86400, to: Math.floor(NOW() / 86400000) * 86400, exporter: v.exporter ? v.exporter.toLowerCase() : '' };
    const w = where(o, 'minute', v.if ? 'if_index = {ifx:UInt32}' : null); if (v.if) w.p.ifx = { type: 'UInt32', value: v.if };
    const rows = await q('fc_peaks', `SELECT exporter, if_index, dir, toUnixTimestamp(toStartOfDay(m)) AS d, max(b) AS peak FROM (SELECT exporter, if_index, dir, minute AS m, sum(bytes) AS b FROM ${db}.flow_if_minute WHERE ${w.w} GROUP BY exporter, if_index, dir, m) GROUP BY exporter, if_index, dir, d ORDER BY d LIMIT 200000`, w.p);
    const sp = speeds(), names = expName(), series = new Map();
    for (const r of rows) { const k = r.exporter + '#' + r.if_index + '#' + r.dir; let s = series.get(k); if (!s) { if (series.size >= 400) continue; s = { exporter: r.exporter, if_index: num(r.if_index), dir: r.dir, points: [] }; series.set(k, s); } s.points.push({ day: num(r.d) * 1000, mbps: r2(mbps(num(r.peak), 60)) }); }
    const items = [...series.values()].map((s) => {
      const spd = sp.get(s.exporter + '#' + s.if_index), util = !!(spd && spd.mbps);
      const pts = s.points.map((p) => ({ day: p.day, v: util ? r2(p.mbps / spd.mbps * 100) : p.mbps }));
      return { exporter: s.exporter, exporter_name: names.get(s.exporter) || '', if_index: s.if_index, if_name: spd ? spd.name : '', dir: s.dir, speed_mbps: util ? spd.mbps : null, unit: util ? '%' : 'Mbps',
        points: pts, forecast: forecastSeries(pts, { util }), speed_note: util ? spd.source : 'utilisation needs the interface speed: add the device to Network Onboarding with SNMP, or set the speed on the exporter' };
    });
    const soon = (i) => (i.forecast.enough && i.forecast.to80 ? Math.min(...[i.forecast.to80.linear, i.forecast.to80.holt].filter((x) => x != null).concat([1e9])) : 1e9);
    items.sort((a, b) => soon(a) - soon(b) || b.points.length - a.points.length);
    return { days: v.days, min_days: MIN_DAYS, items, note: `Daily peak = the busiest minute of each day. Linear = least-squares trend; Holt = double exponential smoothing. A forecast needs ${MIN_DAYS} days of peaks.` };
  }
  async function patterns(query) {
    const v = body(query || {}).str('exporter', { ip: true, max: 39 }).int('if', { min: 1, max: 4294967295 }).int('weeks', { min: 2, max: 12, def: 4 }).done();
    const t = Math.floor(NOW() / 3600000) * 3600, o = { from: t - (v.weeks + 1) * 7 * 86400, to: t, exporter: v.exporter ? v.exporter.toLowerCase() : '' };
    let rows;
    if (v.if) { const w = where(o, 'minute', 'if_index = {ifx:UInt32}'); w.p.ifx = { type: 'UInt32', value: v.if }; rows = await q('pat_if', `SELECT toUnixTimestamp(toStartOfHour(minute)) AS h, sum(bytes) AS b FROM ${db}.flow_if_minute WHERE ${w.w} GROUP BY h ORDER BY h`, w.p); }
    else { const w = where(o); rows = await q('pat_total', `SELECT toUnixTimestamp(toStartOfHour(minute)) AS h, sum(bytes) AS b FROM ${db}.flow_minute WHERE ${w.w} GROUP BY h ORDER BY h`, w.p); }
    const tz = settings().tz_offset_min, r = hourOfWeek(rows.map((x) => ({ t: num(x.h) * 1000, b: num(x.b) })), NOW(), tz);
    return Object.assign({ weeks: v.weeks, exporter: o.exporter || 'all', if_index: v.if || null, tz_offset_min: tz, note: 'Baseline = the same hour of the same weekday over the earlier weeks (local time); a deviation is |z| >= 3 against it.' }, r);
  }

  // ------------------------------------------------------------------ alarms + notification templates
  const active = new Map();      // alarm id → { since, consecutive, raised }
  const recent = [];             // last 60 minute summaries (volume windows)
  const talkSeen = new Map();    // ip → last time it was a top talker (new top talker)
  let firstMinute = 0;
  function templates() { return [DEFAULT_TEMPLATE].concat(C.tpl.all().sort((a, b) => a.name.localeCompare(b.name))); }
  function saveTemplate(b, by) {
    const v = body(b).str('id', { id: true }).str('name', { required: true, max: 80 }).str('subject', { required: true, max: 200 }).str('body', { required: true, max: 4000 }).done();
    if (/[\r\n]/.test(v.subject)) throw new HttpError(400, 'subject must be one line');
    if (v.id === 'default') throw new HttpError(400, 'the default template cannot be changed - save a copy under another name');
    const unknown = [...(v.subject + ' ' + v.body).matchAll(/\{\{\s*([^}]*?)\s*\}\}/g)].map((m) => m[1]).filter((k) => !PLACEHOLDERS.includes(k));
    if (unknown.length) throw new HttpError(400, `body: unknown placeholder {{${unknown[0].slice(0, 30)}}} - use ${PLACEHOLDERS.map((p) => '{{' + p + '}}').join(' ')}`);
    const old = v.id ? C.tpl.get(v.id) : null;
    if (v.id && !old) throw new HttpError(404, 'template not found');
    if (!old && C.tpl.all().length >= 100) throw new HttpError(400, 'at most 100 templates');
    const t = { id: v.id || newId('t'), name: v.name, subject: v.subject, body: v.body, by, at: NOW() };
    C.tpl.put(t); return { template: t, created: !old };
  }
  function deleteTemplate(id) {
    param(id); const t = C.tpl.get(id); if (!t) throw new HttpError(404, 'template not found');
    const used = C.alarms.all().find((a) => a.template_id === id); if (used) throw new HttpError(409, `alarm "${used.name}" uses this template`);
    C.tpl.remove(id); return t;
  }
  function preview(b) {
    const v = body(b).str('template_id', { id: true }).str('subject', { max: 200 }).str('body', { max: 4000 }).done();
    const t = v.template_id ? templates().find((x) => x.id === v.template_id) : { subject: v.subject || '', body: v.body || '' };
    if (!t) throw new HttpError(404, 'template not found');
    return render(t, { alarm: 'Example alarm', target: 'example-exporter#1', metric: 'util_pct', value: 85.2, threshold: 80, unit: '%', severity: 'high', state: 'raised', time: new Date(NOW()).toISOString() });
  }
  const UNIT = { mbps: 'Mbps', util_pct: '%', volume_mb: 'MB', new_top_talker: '' };
  function alarms() { return C.alarms.all().sort((a, b) => a.name.localeCompare(b.name)); }
  function saveAlarm(b, by) {
    const v = body(b).str('id', { id: true }).str('name', { required: true, max: 80 }).oneOf('scope', ['interface', 'group', 'application', 'total'], { required: true })
      .str('target', { max: 120 }).oneOf('metric', Object.keys(UNIT), { required: true }).oneOf('dir', ['in', 'out', 'both'], { def: 'both' })
      .num('threshold', { required: true, min: 0, max: 1e9 }).int('for_min', { min: 1, max: 60, def: 3 }).oneOf('severity', Object.keys(SEV), { def: 'medium' })
      .str('template_id', { id: true }).list('recipients', { max: 20, item: 'str', itemMax: 254, unique: true }).bool('enabled', { def: true }).done();
    if (v.scope !== 'total' && !v.target) throw new HttpError(400, 'target is required for an interface, group or application alarm');
    if (v.scope === 'interface' && !/^[0-9a-fA-F.:]{2,39}#\d{1,10}$/.test(v.target)) throw new HttpError(400, 'target must be <exporter IP>#<ifIndex> for an interface alarm');
    if (v.scope === 'group' && !C.groups.get(v.target)) throw new HttpError(400, 'target: no such group');
    if (v.metric === 'util_pct' && v.scope !== 'interface') throw new HttpError(400, 'metric: utilisation % is for interfaces (it needs the link speed)');
    if (v.metric === 'util_pct' && v.threshold > 150) throw new HttpError(400, 'threshold: utilisation is at most 150 %');
    if (v.metric === 'new_top_talker' && !['total', 'group'].includes(v.scope)) throw new HttpError(400, 'metric: new top talker is for the total or a group');
    if (v.metric === 'new_top_talker' && !(Number.isInteger(v.threshold) && v.threshold >= 1 && v.threshold <= 20)) throw new HttpError(400, 'threshold: for a new top talker, the top N (1-20)');
    if (v.template_id && !templates().some((t) => t.id === v.template_id)) throw new HttpError(400, 'template_id: no such template');
    const rc = (v.recipients || []).map((x) => x.toLowerCase()); const badR = rc.find((x) => !EMAIL.test(x)); if (badR) throw new HttpError(400, `recipients: "${badR.slice(0, 60)}" is not an e-mail address`);
    const old = v.id ? C.alarms.get(v.id) : null;
    if (v.id && !old) throw new HttpError(404, 'alarm not found');
    if (!old && alarms().length >= 200) throw new HttpError(400, 'at most 200 alarms');
    const a = { id: v.id || newId('al'), name: v.name, scope: v.scope, target: v.scope === 'total' ? '' : v.target, metric: v.metric, dir: v.dir, threshold: v.threshold, for_min: v.for_min,
      severity: v.severity, template_id: v.template_id || 'default', recipients: rc, enabled: v.enabled, by, at: NOW() };
    C.alarms.put(a); active.delete(a.id);
    return { alarm: a, created: !old };
  }
  function deleteAlarm(id) { param(id); const a = C.alarms.get(id); if (!a) throw new HttpError(404, 'alarm not found'); C.alarms.remove(id); active.delete(id); return a; }

  function valueOf(a, s, sp) {
    const bytesFor = (summary) => {
      if (a.scope === 'total') return summary.bytes;
      if (a.scope === 'application') return num((summary.app_totals || {})[a.target]);
      if (a.scope === 'interface') { const [e, i] = a.target.split('#'); const rows = (summary.interfaces || []).filter((x) => x.exporter === e.toLowerCase() && String(x.if_index) === i);
        const by = (d) => rows.filter((x) => x.dir === d).reduce((t, x) => t + x.bytes, 0); return a.dir === 'in' ? by('in') : a.dir === 'out' ? by('out') : Math.max(by('in'), by('out')); }
      if (a.scope === 'group') { const g = C.groups.get(a.target); if (!g) return null; const set = createCidrSet(g.cidrs); const rows = (summary.ips || []).filter((x) => set.has(x.ip));
        const by = (d) => rows.filter((x) => x.dir === d).reduce((t, x) => t + x.bytes, 0); return a.dir === 'in' ? by('dst') : a.dir === 'out' ? by('src') : by('dst') + by('src'); }
      return null;
    };
    if (a.metric === 'volume_mb') { const win = recent.slice(-a.for_min); return { value: r2(win.reduce((t, x) => t + num(bytesFor(x)), 0) / 1e6), window: true }; }
    const b = bytesFor(s); if (b == null) return { value: null, why: 'target not found' };
    const m = mbps(b, 60);
    if (a.metric === 'mbps') return { value: r2(m) };
    if (a.metric === 'util_pct') { const k = a.target.toLowerCase(), spd = sp.get(k); if (!spd) return { value: null, why: 'no interface speed (SNMP poller or exporter setting)' }; return { value: r1(m / spd.mbps * 100) }; }
    return { value: null };
  }
  function notify(a, ev, vars) {
    if (!a.recipients || !a.recipients.length) { ev.notified = 'no recipients set'; return; }
    if (typeof mail !== 'function') { ev.notified = 'e-mail not available (Reports SMTP relay)'; return; }
    const t = templates().find((x) => x.id === a.template_id) || DEFAULT_TEMPLATE, m = render(t, vars);
    ev.notified = 'sending';
    Promise.resolve().then(() => mail({ to: a.recipients, subject: m.subject, text: m.text, html: m.html }))
      .then(() => { C.events.patch(ev.id, (x) => { x.notified = 'sent'; }); })
      .catch((e) => { const msg = String(e && e.message).slice(0, 200); C.events.patch(ev.id, (x) => { x.notified = 'failed: ' + msg; }); every('netflow-alarm-mail', 300000, 'warn', 'netflow: alarm e-mail not sent', { alarm: a.id, err: msg }); });
  }
  function record(a, stateName, value, at, extra) {
    const ev = Object.assign({ id: newId('ev'), alarm_id: a.id, name: a.name, scope: a.scope, target: a.target, metric: a.metric, threshold: a.threshold, value, severity: a.severity, state: stateName, at, notified: '' }, extra || {});
    C.events.put(ev);
    const all = C.events.all(); if (all.length > 1000) for (const old of all.sort((x, y) => x.at - y.at).slice(0, all.length - 1000)) C.events.remove(old.id);
    return ev;
  }
  function onMinute(s) {
    recent.push(s); while (recent.length > 60) recent.shift();
    if (!firstMinute) firstMinute = s.minute;
    const out = { raised: 0, cleared: 0 }, sp = speeds(), at = s.minute + 60000;
    for (const a of alarms()) {
      if (!a.enabled) continue;
      try {
        if (a.metric === 'new_top_talker') { out.raised += newTalkers(a, s, at); continue; }
        const v = valueOf(a, s, sp), st = active.get(a.id) || { consecutive: 0, raised: false };
        if (v.value == null) { st.why = v.why || ''; active.set(a.id, st); continue; }
        st.last = v.value; st.why = '';
        const over = v.value >= a.threshold;
        st.consecutive = over ? (v.window ? a.for_min : st.consecutive + 1) : 0;
        if (over && !st.raised && st.consecutive >= a.for_min) {
          st.raised = true; st.since = at; out.raised++;
          const vars = { alarm: a.name, target: a.target || 'all traffic', metric: a.metric, value: v.value, threshold: a.threshold, unit: UNIT[a.metric], severity: a.severity, state: 'raised', time: new Date(at).toISOString() };
          const ev = record(a, 'raised', v.value, at);
          if (alerts && typeof alerts.raise === 'function') alerts.raise({ rule_id: 'netflow-alarm', rule_name: 'NetFlow alarm: ' + a.name, rule_type: 'netflow', severity: SEV[a.severity], ts_first: at, ts_last: at, count: 1,
            group: { alarm: a.name, target: vars.target }, group_key: a.id, summary: `${a.name}: ${vars.target} ${a.metric} ${v.value} ${vars.unit} >= ${a.threshold} ${vars.unit} for ${a.for_min} min`, source: 'netflow', src_type: 'netflow', src_id: a.target || 'total',
            suppress_s: 3600, fields: { metric: a.metric, value: String(v.value), threshold: String(a.threshold), scope: a.scope } });
          notify(a, ev, vars);
        } else if (!over && st.raised) { st.raised = false; out.cleared++; record(a, 'cleared', v.value, at); }
        active.set(a.id, st);
      } catch (e) { every('netflow-alarm-' + a.id, 300000, 'warn', 'netflow: alarm not evaluated', { alarm: a.id, err: String(e.message).slice(0, 200) }); }
    }
    return Object.assign(out, security(s));
  }
  function newTalkers(a, s, at) {
    const n = Math.round(a.threshold), learnt = s.minute - firstMinute >= 60 * 60000;
    let list = (s.all_talkers || []);
    if (a.scope === 'group') { const g = C.groups.get(a.target); if (!g) return 0; const set = createCidrSet(g.cidrs); list = list.filter((t) => set.has(t.ip)); }
    let raised = 0;
    for (const t of list.slice(0, n)) {
      const key = a.id + '|' + t.ip, last = talkSeen.get(key);
      if (learnt && (!last || at - last > 7 * 86400000)) {
        raised++;
        const vars = { alarm: a.name, target: t.ip, metric: 'new_top_talker', value: r2(mbps(t.bytes, 60)), threshold: 'top ' + n, unit: 'Mbps', severity: a.severity, state: 'raised', time: new Date(at).toISOString() };
        const ev = record(a, 'raised', vars.value, at, { talker: t.ip });
        if (alerts && typeof alerts.raise === 'function') alerts.raise({ rule_id: 'netflow-new-top-talker', rule_name: 'NetFlow: new top talker', rule_type: 'netflow', severity: SEV[a.severity], ts_first: at, ts_last: at, count: 1,
          group: { alarm: a.name, ip: t.ip }, group_key: a.id + ':' + t.ip, summary: `${t.ip} entered the top ${n} talkers (${vars.value} Mbps) - not among them in the last 7 days`, source: 'netflow', src_type: 'netflow', src_id: a.id, suppress_s: 86400, fields: { ip: t.ip, mbps: String(vars.value) } });
        notify(a, ev, vars);
      }
      if (talkSeen.size >= 20000 && !talkSeen.has(key)) talkSeen.delete(talkSeen.keys().next().value);
      talkSeen.set(key, at);
    }
    return raised;
  }

  // ------------------------------------------------------------------ security analytics on flows
  let DC = null;   // read for every flow: cached, rebuilt when an administrator saves
  function detectCfg() { return DC || (DC = Object.assign({}, DETECT, C.cfg.get('detection') || {})); }
  function saveDetection(b, by) {
    const v = body(b).bool('enabled').int('scan_ports', { min: 10, max: 65535 }).int('sweep_hosts', { min: 10, max: 65535 }).num('outbound_mb', { min: 1, max: 1000000 })
      .num('outbound_factor', { min: 2, max: 1000 }).int('learn_minutes', { min: 10, max: 10080 }).list('exclude', { max: 100, item: 'str', itemMax: 50, unique: true }).bool('intel').done();
    if (v.exclude) v.exclude = cidrs(v.exclude, 'exclude');
    const cur = C.cfg.get('detection') || {};
    const next = Object.assign({}, cur, v, { id: 'detection', by, at: NOW() }); C.cfg.put(next); excl = null; DC = null;
    return { detection: detectCfg(), changed: Object.keys(v).filter((k) => JSON.stringify(v[k]) !== JSON.stringify(cur[k])) };
  }
  let win = new Map(), winDropped = 0, excl = null, intelHits = new Map(), intelChecked = new Set();
  const base = new Map();   // internal source → { ewma, n } of outbound bytes per active minute
  const ST = { observed: 0, dropped_sources: 0, detections: 0, intel_checks: 0 };
  const scanning = (f) => (f.proto === 6 ? (f.tcp_flags ? (f.tcp_flags & 0x02) && !(f.tcp_flags & 0x10) : f.dport < 32768) : f.proto === 17 ? f.dport < 32768 : false);
  function observe(f) {
    const d = detectCfg(); if (!d.enabled) return;
    if (!excl) excl = createCidrSet(d.exclude || []);
    if (excl.has(f.src)) return;
    ST.observed++;
    let s = win.get(f.src);
    if (!s) { if (win.size >= 20000) { winDropped++; ST.dropped_sources++; return; } s = { pairs: new Set(), out: 0, exporter: f.exporter, flows: 0 }; win.set(f.src, s); }
    s.flows++;
    if (scanning(f) && s.pairs.size < 4096) s.pairs.add(f.dst + '|' + f.dport);
    const sp = isPrivate(f.src), dp = isPrivate(f.dst);
    if (sp && !dp) s.out += f.bytes;
    if (d.intel !== false && intel && typeof intel.match === 'function' && intelHits.size < 500) {
      for (const [ip, peer, dir] of [[f.dst, f.src, 'to'], [f.src, f.dst, 'from']]) {
        if (isPrivate(ip)) continue;
        const k = ip + '|' + peer; if (intelHits.has(k)) { intelHits.get(k).bytes += f.bytes; continue; }
        if (intelChecked.has(ip)) continue;   // looked up this minute and not listed
        ST.intel_checks++;
        if (intelChecked.size < 50000) intelChecked.add(ip);
        if (intel.match('ip', ip)) intelHits.set(k, { bad: ip, peer, dir, bytes: f.bytes, exporter: f.exporter, port: dir === 'to' ? f.dport : f.sport, lists: typeof intel.lookup === 'function' ? intel.lookup(ip).slice(0, 5) : [] });
      }
    }
  }
  function raiseDet(kind, sev, mitre, tactic, key, summary, fields, at, exporter) {
    const d = { id: newId('d'), kind, at, severity: sev, summary, key, fields, exporter };
    C.det.put(d); ST.detections++;
    const all = C.det.all(); if (all.length > 500) for (const old of all.sort((x, y) => x.at - y.at).slice(0, all.length - 500)) C.det.remove(old.id);
    if (alerts && typeof alerts.raise === 'function') try { alerts.raise({ rule_id: 'netflow-' + kind, rule_name: { 'port-scan': 'Port scan seen in flows', 'host-sweep': 'Host sweep seen in flows', 'outbound-volume': 'Unusual outbound volume in flows', 'intel-ip': 'Traffic with a known-bad address (threat intel)' }[kind],
      rule_type: 'netflow', severity: sev, mitre, tactic, ts_first: at, ts_last: at, count: 1, group: fields.src ? { src_ip: fields.src } : {}, group_key: key, summary, source: 'netflow', src_type: 'netflow', src_id: exporter || '', suppress_s: 3600,
      fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, Array.isArray(v) ? v.slice(0, 20).join(', ') : String(v)])) }); }
    catch (e) { every('netflow-det-raise', 60000, 'error', 'netflow: detection not raised as an alert', { kind, err: String(e.message).slice(0, 200) }); }
    return d;
  }
  function security(s) {
    const d = detectCfg(), at = s.minute + 60000, out = { detections: 0 };
    const w = win, hits = intelHits; win = new Map(); intelHits = new Map(); intelChecked = new Set(); winDropped = 0;
    if (!d.enabled) return out;
    for (const [src, x] of w) {
      if (x.pairs.size >= Math.min(d.scan_ports, d.sweep_hosts)) {
        const byDst = new Map(), byPort = new Map();
        for (const p of x.pairs) { const i = p.lastIndexOf('|'), dst = p.slice(0, i), port = p.slice(i + 1); (byDst.get(dst) || byDst.set(dst, new Set()).get(dst)).add(port); (byPort.get(port) || byPort.set(port, new Set()).get(port)).add(dst); }
        for (const [dst, ports] of byDst) if (ports.size >= d.scan_ports) { out.detections++; raiseDet('port-scan', 3, ['T1046'], 'discovery', src + '>' + dst, `${src} probed ${ports.size} ports on ${dst} within one minute`, { src, dst, ports: ports.size, sample: [...ports].slice(0, 20) }, at, x.exporter); }
        for (const [port, dsts] of byPort) if (dsts.size >= d.sweep_hosts) { out.detections++; raiseDet('host-sweep', 3, ['T1046', 'T1018'], 'discovery', src + ':' + port, `${src} contacted ${dsts.size} hosts on port ${port} within one minute`, { src, port, hosts: dsts.size, sample: [...dsts].slice(0, 20) }, at, x.exporter); }
      }
      if (x.out > 0 && isPrivate(src)) {
        let b = base.get(src);
        if (!b) { if (base.size >= 50000) base.delete(base.keys().next().value); b = { ewma: x.out, n: 0 }; base.set(src, b); }
        if (b.n >= d.learn_minutes && x.out >= d.outbound_mb * 1e6 && x.out >= d.outbound_factor * b.ewma) {
          out.detections++; raiseDet('outbound-volume', 3, ['T1048'], 'exfiltration', src, `${src} sent ${r1(x.out / 1e6)} MB to external addresses in one minute - ${r1(x.out / Math.max(b.ewma, 1))}x its usual`, { src, mb: r1(x.out / 1e6), usual_mb: r2(b.ewma / 1e6) }, at, x.exporter);
        }
        b.ewma = b.n ? b.ewma * 0.95 + x.out * 0.05 : x.out; b.n++;
      }
    }
    for (const h of hits.values()) { out.detections++; raiseDet('intel-ip', 4, ['T1071'], 'command-and-control', h.peer + '|' + h.bad, `${h.peer} ${h.dir === 'to' ? 'sent traffic to' : 'received traffic from'} ${h.bad}, listed in the threat-intel lists${h.lists.length ? ' (' + h.lists.join(', ') + ')' : ''}`, { src: h.peer, bad_ip: h.bad, direction: h.dir, port: h.port, bytes: Math.round(h.bytes), lists: h.lists }, at, h.exporter); }
    return out;
  }
  function detections(query) {
    const v = body(query || {}).oneOf('kind', ['port-scan', 'host-sweep', 'outbound-volume', 'intel-ip']).int('limit', { min: 1, max: 500, def: 200 }).done();
    const list = C.det.all().filter((d) => !v.kind || d.kind === v.kind).sort((a, b) => b.at - a.at);
    const counts = {}; for (const d of C.det.all()) counts[d.kind] = (counts[d.kind] || 0) + 1;
    return { detection: detectCfg(), counts, items: list.slice(0, v.limit), sensor: Object.assign({ tracked_sources: win.size, learnt_sources: [...base.values()].filter((b) => b.n >= detectCfg().learn_minutes).length, intel_loaded: !!(intel && typeof intel.match === 'function') }, ST),
      note: 'Indicators from sampled flow records, not proof: a scan needs SYN-only TCP or low destination ports in one minute; outbound volume is compared with each internal host\'s own usual minute after it has learnt; known-bad addresses come from the SIEM threat-intel lists (Threat Intelligence).' };
  }
  function alarmView() {
    const ev = C.events.all().sort((a, b) => b.at - a.at).slice(0, 200);
    return { alarms: alarms().map((a) => { const s = active.get(a.id) || {}; return Object.assign({}, a, { active: !!s.raised, since: s.since || null, last_value: s.last != null ? s.last : null, why: s.why || '' }); }),
      templates: templates(), placeholders: PLACEHOLDERS, events: ev, metrics: Object.keys(UNIT) };
  }

  return { settings, collectorSettings, saveSettings, exporters, saveExporter, deleteExporter, groups, saveGroup, deleteGroup, billable, groupsOf, apps, saveApp, deleteApp, mapper,
    speeds, interfaces, top, talkers, groupsUsage, billing, forecast, patterns, templates, saveTemplate, deleteTemplate, preview, alarms, saveAlarm, deleteAlarm, alarmView,
    onMinute, observe, security, detections, detectCfg, saveDetection, setOnChange: (fn) => { onChange = fn || (() => {}); } };
}

module.exports = { createFlowAnalytics, forecastSeries, hourOfWeek, linreg, holt, render, PLACEHOLDERS, DEFAULT_TEMPLATE, MIN_DAYS };
