// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Business-hours calendar — ONE definition of "business hours" shared by:
 *   - after-hours activity monitoring (engine/reports/after-hours.js: SQL expression + per-event reason),
 *   - the rule engine op `outside_business_hours` (engine/detect/engine.js; rules SENTRA-AUTH-007, SENTRA-ORA-002),
 *   - SLA-style clocks (addBusinessMinutes: the clock stops outside business hours and rolls over weekends/holidays —
 *     same algorithm as the service-desk SLA clock this was ported from, incl. its test vector).
 *
 * Model (all optional on input; DEFAULTS fill the rest):
 *   { utc_offset_min: 180,                 Asia/Riyadh = UTC+3 all year (no DST) → fixed-offset arithmetic
 *     days: [0,1,2,3,4],                   working days, 0 = Sunday … 6 = Saturday (default Sun–Thu)
 *     start: '08:00', end: '17:00',        local time, end exclusive, end must be after start ('24:00' allowed)
 *     holidays: [{date:'YYYY-MM-DD', name}],  whole local days that are not business days (every site)
 *     sites: { '<site id>': { days?, start?, end?, holidays?[], src_ids?[] } } }   per-site override
 * Site of an event: its src_id listed in a site override's src_ids → that site; else the `site` of its configured source
 * (config.sources[].site, set in the Connect hub) when that site has an override; else the default window.
 *
 *   normalize(input, {siteIds?}) → {config, errors[]}        compile(config, {siteOfSrc?}) → calendar
 *   calendar = { config, parts(ms), window(site), siteOf(ev), isBusiness(ms, site?), isAfterHours(ms, site?),
 *                isAfterHoursEvent(ev), reason(ms, site?) → ''|'weekend'|'holiday'|'before-hours'|'after-hours',
 *                addBusinessMinutes(ms, minutes, site?), sql({ts, src}) → {expr, params}, describe() }
 *   active() / setActive(calendar)   the process-wide calendar the rule engine reads at evaluation time
 *   createBusinessHoursStore({state, config, log, now}) → { get(), set(patch, by), calendar(), defaults(), sites() }
 *     persisted in the state collection `business_hours` (doc "calendar"); every set() re-activates the calendar.
 */

const DAY = 86400000;
const DEFAULTS = Object.freeze({ utc_offset_min: 180, days: [0, 1, 2, 3, 4], start: '08:00', end: '17:00', holidays: [], sites: {} });
const SITE_IDS = ['riyadh-hq', 'jeddah', 'riyadh-olaya', 'alkhobar'];
const SITE_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const SRC_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }
function hm(s) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(String(s === undefined || s === null ? '' : s).trim());
  if (!m) return null;
  const h = Number(m[1]); const mi = Number(m[2]);
  if (mi > 59 || h > 24 || (h === 24 && mi !== 0)) return null;
  return h * 60 + mi;
}
const fmtHm = (min) => `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;
function dayNumOf(date) {
  const m = DATE_RE.exec(String(date || ''));
  if (!m) return null;
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const d = new Date(t);
  if (d.getUTCFullYear() !== Number(m[1]) || d.getUTCMonth() !== Number(m[2]) - 1 || d.getUTCDate() !== Number(m[3])) return null;
  return Math.floor(t / DAY);
}
const dateOfDayNum = (dn) => new Date(dn * DAY).toISOString().slice(0, 10);

function normDays(v, name, errs) {
  if (!Array.isArray(v) || !v.length) { errs.push(`${name} must list at least one working day (0 = Sunday … 6 = Saturday)`); return null; }
  const out = [...new Set(v.map(Number))].sort((a, b) => a - b);
  if (out.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) { errs.push(`${name} must be integers 0-6 (0 = Sunday)`); return null; }
  return out;
}
function normHolidays(v, name, errs) {
  if (v === undefined) return [];
  if (!Array.isArray(v)) { errs.push(`${name} must be an array`); return []; }
  if (v.length > 400) { errs.push(`${name}: at most 400 entries`); return []; }
  const out = []; const seen = new Set();
  for (const h of v) {
    const date = typeof h === 'string' ? h : isObj(h) ? h.date : '';
    const nm = isObj(h) && typeof h.name === 'string' ? h.name.trim().slice(0, 80) : '';
    if (dayNumOf(date) === null) { errs.push(`${name}: invalid date "${String(date).slice(0, 20)}" (YYYY-MM-DD)`); continue; }
    if (seen.has(date)) continue;
    seen.add(date);
    out.push({ date, name: nm });
  }
  return out.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
}
function normWindow(o, base, name, errs) {
  const start = o.start !== undefined ? o.start : base.start;
  const end = o.end !== undefined ? o.end : base.end;
  const s = hm(start); const e = hm(end);
  if (s === null) errs.push(`${name}start must be HH:MM`);
  if (e === null) errs.push(`${name}end must be HH:MM`);
  if (s !== null && e !== null && !(e > s)) errs.push(`${name}end must be after ${name}start`);
  return { start: s === null ? start : fmtHm(s), end: e === null ? end : fmtHm(e) };
}

/** normalize(input, {siteIds}) → {config, errors[]} — never throws. */
function normalize(input, opts = {}) {
  const errs = [];
  const src = isObj(input) ? input : {};
  const known = Array.isArray(opts.siteIds) && opts.siteIds.length ? opts.siteIds : null;
  const off = src.utc_offset_min === undefined ? DEFAULTS.utc_offset_min : Number(src.utc_offset_min);
  if (!Number.isInteger(off) || off < -720 || off > 840) errs.push('utc_offset_min must be an integer between -720 and 840');
  const days = normDays(src.days === undefined ? DEFAULTS.days : src.days, 'days', errs) || DEFAULTS.days.slice();
  const win = normWindow(src, DEFAULTS, '', errs);
  const holidays = normHolidays(src.holidays, 'holidays', errs);
  const sites = {};
  if (src.sites !== undefined && !isObj(src.sites)) errs.push('sites must be an object keyed by site id');
  for (const [id, o] of Object.entries(isObj(src.sites) ? src.sites : {})) {
    if (!SITE_RE.test(id) || (known && !known.includes(id))) { errs.push(`unknown site "${String(id).slice(0, 40)}"${known ? ` (sites: ${known.join(', ')})` : ''}`); continue; }
    if (o === null || o === false) continue; // remove the override
    if (!isObj(o)) { errs.push(`sites.${id} must be an object`); continue; }
    const s = {};
    if (o.days !== undefined) { const d = normDays(o.days, `sites.${id}.days`, errs); if (d) s.days = d; }
    if (o.start !== undefined || o.end !== undefined) Object.assign(s, normWindow(o, win, `sites.${id}.`, errs));
    if (o.holidays !== undefined) s.holidays = normHolidays(o.holidays, `sites.${id}.holidays`, errs);
    if (o.src_ids !== undefined) {
      if (!Array.isArray(o.src_ids) || o.src_ids.length > 500 || o.src_ids.some((x) => !SRC_RE.test(String(x)))) errs.push(`sites.${id}.src_ids must be source ids`);
      else s.src_ids = [...new Set(o.src_ids.map(String))];
    }
    sites[id] = s;
  }
  return { config: { utc_offset_min: Number.isInteger(off) ? off : DEFAULTS.utc_offset_min, days, start: win.start, end: win.end, holidays, sites }, errors: errs };
}

function compile(input, opts = {}) {
  const { config: c, errors } = normalize(input, opts);
  if (errors.length) { const e = new Error(errors[0]); e.code = 400; e.errors = errors; throw e; }
  const off = c.utc_offset_min * 60000;
  const globalHol = c.holidays.map((h) => dayNumOf(h.date));
  const mk = (o) => {
    const days = o.days || c.days;
    return {
      days, daySet: new Set(days), s: hm(o.start || c.start), e: hm(o.end || c.end),
      hol: [...new Set(globalHol.concat((o.holidays || []).map((h) => dayNumOf(h.date))))].sort((a, b) => a - b),
    };
  };
  const W = { default: mk({}) };
  for (const [id, o] of Object.entries(c.sites)) W[id] = mk(o);
  for (const w of Object.values(W)) w.holSet = new Set(w.hol);
  const srcSite = new Map();
  for (const [id, o] of Object.entries(c.sites)) for (const s of o.src_ids || []) if (!srcSite.has(s)) srcSite.set(s, id);
  const siteOfSrc = typeof opts.siteOfSrc === 'function' ? opts.siteOfSrc : () => '';

  function parts(ms) {
    const loc = Number(ms) + off;
    const dn = Math.floor(loc / DAY);
    const mod = Math.floor((loc - dn * DAY) / 60000);
    return { dn, mod, dow: (((dn + 4) % 7) + 7) % 7, date: dateOfDayNum(dn) };
  }
  const windowOf = (site) => W[site] || W.default;
  function siteOf(ev) {
    const id = ev && ev.src_id ? String(ev.src_id) : '';
    if (!id) return 'default';
    if (srcSite.has(id)) return srcSite.get(id);
    const s = siteOfSrc(id);
    return s && W[s] ? s : 'default';
  }
  function reason(ms, site) {
    const t = Number(ms);
    if (!Number.isFinite(t)) return '';
    const w = windowOf(site); const p = parts(t);
    if (w.holSet.has(p.dn)) return 'holiday';
    if (!w.daySet.has(p.dow)) return 'weekend';
    if (p.mod < w.s) return 'before-hours';
    if (p.mod >= w.e) return 'after-hours';
    return '';
  }
  const isBusiness = (ms, site) => Number.isFinite(Number(ms)) && reason(ms, site) === '';
  const isAfterHours = (ms, site) => Number.isFinite(Number(ms)) && reason(ms, site) !== '';
  const isAfterHoursEvent = (ev) => !!ev && isAfterHours(typeof ev.ts === 'number' ? ev.ts : Date.parse(ev.ts), siteOf(ev));

  // SLA clock: add `minutes` of business time to startMs (port of the service-desk h3AddMin, plus holidays).
  function addBusinessMinutes(startMs, minutes, site) {
    const w = windowOf(site);
    let t = Number(startMs) + off; let left = Number(minutes) || 0; let guard = 0;
    while (left > 0 && guard++ < 20000) {
      const day0 = Math.floor(t / DAY) * DAY; const dn = day0 / DAY;
      const open = day0 + w.s * 60000; const close = day0 + w.e * 60000;
      const dow = (((dn + 4) % 7) + 7) % 7;
      if (!w.daySet.has(dow) || w.holSet.has(dn) || t >= close) { t = day0 + DAY + w.s * 60000; continue; }
      if (t < open) t = open;
      const avail = (close - t) / 60000;
      if (left <= avail) { t += left * 60000; left = 0; } else { left -= avail; t = day0 + DAY + w.s * 60000; }
    }
    return t - off;
  }

  // ClickHouse boolean (UInt8) expression: 1 when the row's time is outside business hours of its site.
  // Only integers produced here are inlined; source ids go in as parameters.
  function sql({ ts = 'ts', src = 'src_id' } = {}) {
    const loc = `(toUnixTimestamp64Milli(${ts}) + ${off})`;
    const dn = `intDiv(${loc}, ${DAY})`;
    const mod = `intDiv(${loc} % ${DAY}, 60000)`;
    const dow = `((${dn} + 4) % 7)`;
    const biz = (w) => `(has([${w.days.join(',')}], ${dow})${w.hol.length ? ` AND NOT has([${w.hol.join(',')}], ${dn})` : ''} AND ${mod} >= ${w.s} AND ${mod} < ${w.e})`;
    const ids = Object.keys(W).filter((k) => k !== 'default');
    const params = {};
    if (!ids.length) return { expr: `toUInt8(NOT ${biz(W.default)})`, params };
    const from = []; const to = [];
    for (const [s, site] of srcSite) { from.push(s); to.push(ids.indexOf(site) + 1); }
    if (typeof opts.srcSites === 'function') {
      for (const [s, site] of opts.srcSites()) if (!srcSite.has(s) && ids.includes(site)) { from.push(s); to.push(ids.indexOf(site) + 1); }
    }
    if (!from.length) return { expr: `toUInt8(NOT ${biz(W.default)})`, params }; // no source belongs to an overridden site
    params.bh_src = { type: 'Array(String)', value: from };
    params.bh_site = { type: 'Array(UInt8)', value: to };
    // site index (1-based, 0 = default window): arrayElement(…, 0) is 0 when the source is not mapped
    const siteExpr = `arrayElement({bh_site:Array(UInt8)}, indexOf({bh_src:Array(String)}, toString(${src})))`;
    const arms = ids.map((id, i) => `${siteExpr} = ${i + 1}, ${biz(W[id])}`).join(', ');
    return { expr: `toUInt8(NOT multiIf(${arms}, ${biz(W.default)}))`, params };
  }

  function describe() {
    const one = (w) => ({ days: w.days.slice(), start: fmtHm(w.s), end: fmtHm(w.e), holidays: w.hol.length });
    const sites = {};
    for (const id of Object.keys(W)) if (id !== 'default') sites[id] = one(W[id]);
    return Object.assign(one(W.default), { utc_offset_min: c.utc_offset_min, sites });
  }

  return { config: c, parts, window: windowOf, siteOf, reason, isBusiness, isAfterHours, isAfterHoursEvent, addBusinessMinutes, sql, describe };
}

let ACTIVE = null;
function active() { if (!ACTIVE) ACTIVE = compile(DEFAULTS); return ACTIVE; }
function setActive(cal) { ACTIVE = cal || null; return active(); }

/** Persisted calendar (state collection business_hours, doc id "calendar"); set() validates, stores, re-activates. */
function createBusinessHoursStore({ state, config = {}, log, now = Date.now } = {}) {
  const L = log || { info() {}, warn() {}, error() {} };
  const col = state ? state.collection('business_hours') : null;
  const siteIds = () => {
    const s = (config.onboard && Array.isArray(config.onboard.sites) && config.onboard.sites.length) ? config.onboard.sites.map((x) => String(x.id)) : SITE_IDS;
    return [...new Set(s.concat(SITE_IDS))];
  };
  let cache = { at: 0, map: new Map() };
  function srcMap() {
    if (now() - cache.at < 5000) return cache.map;
    const m = new Map();
    for (const s of Array.isArray(config.sources) ? config.sources : []) if (s && s.id && s.site) m.set(String(s.id), String(s.site));
    cache = { at: now(), map: m };
    return m;
  }
  const opts = () => ({ siteIds: siteIds(), siteOfSrc: (id) => srcMap().get(id) || '', srcSites: () => srcMap() });
  function stored() { const d = col && col.get('calendar'); return d && isObj(d.value) ? d.value : {}; }
  let cal;
  try { cal = compile(stored(), opts()); } catch (e) { L.error('business hours: stored calendar invalid — using defaults', { err: e.message }); cal = compile(DEFAULTS, opts()); }
  setActive(cal);
  function get() { const d = col && col.get('calendar'); return Object.assign({}, cal.config, { updated: (d && d.updated) || 0, updated_by: (d && d.by) || '' }); }
  function set(patch, by) {
    if (!isObj(patch)) throw Object.assign(new Error('business hours must be an object'), { code: 400 });
    const allowed = ['utc_offset_min', 'days', 'start', 'end', 'holidays', 'sites'];
    const unknown = Object.keys(patch).filter((k) => !allowed.includes(k));
    if (unknown.length) throw Object.assign(new Error(`unknown business-hours setting(s): ${unknown.join(', ')}`), { code: 400 });
    const base = cal.config;
    const merged = Object.assign({}, base, patch);
    if (isObj(patch.sites)) { // per-site keys merge; null removes an override
      merged.sites = Object.assign({}, base.sites);
      for (const [k, v] of Object.entries(patch.sites)) { if (v === null || v === false) delete merged.sites[k]; else merged.sites[k] = v; }
    }
    const next = compile(merged, opts()); // throws {code:400, errors}
    if (col) col.put({ id: 'calendar', value: next.config, updated: now(), by: by || '' });
    cal = next;
    setActive(cal);
    L.info('business hours updated', { by: by || '', days: next.config.days.join(','), start: next.config.start, end: next.config.end, holidays: next.config.holidays.length, sites: Object.keys(next.config.sites).length });
    return get();
  }
  return { get, set, calendar: () => cal, defaults: () => JSON.parse(JSON.stringify(DEFAULTS)), sites: siteIds };
}

module.exports = { DEFAULTS, SITE_IDS, normalize, compile, active, setActive, createBusinessHoursStore, hm, dayNumOf };
