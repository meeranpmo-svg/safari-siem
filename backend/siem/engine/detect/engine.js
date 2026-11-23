// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * the organisation SIEM — real-time detection engine.
 *
 *   createDetector({ rules, now, onAlert, log, intel, maxGroups = 20000, timingSample = 16, sweepMs = 10000, tzOffsetMin = 180 })
 *     → { onEvent(ev), tick(nowMs), flush(), load(rules) → {loaded, errors[]}, stats(), rules(), exportState(), importState(s), setIntel(i) }
 *   Dispatch: each rule gets a "gate" (a mandatory eq on event_code/action/category/src_type, or a field that must be
 *   non-empty such as cmdline/url/dns_query/hash) so an event is only evaluated against rules that can match it.
 *
 * Rule format: see ARCH.md "Rule format". Documented extensions (all optional, backwards compatible):
 *
 *   match nesting      Any item inside match.all / match.any / match.none may itself be a group
 *                      { all?, any?, none? } (used by the Sigma converter for and/or/not trees).
 *   "not": true        on a leaf condition negates it.
 *   op "hour_between"  value [startHour, endHour] (0-24, end exclusive, wraps midnight when start > end),
 *                      field defaults to "ts", optional "tz_offset_min" (default 180 = Asia/Riyadh, UTC+3).
 *   op "weekday_in"    value [0..6] (0 = Sunday … 5 = Friday, 6 = Saturday), same field / tz_offset_min rules.
 *   op "outside_business_hours"
 *                      value true (default) | false. True when the time (field defaults to "ts") is outside the
 *                      configured business hours of the event's site — the SAME calendar as the after-hours monitoring
 *                      (engine/util/business-hours.js; admin: POST /api/soc/after-hours/settings): working days,
 *                      start/end, holidays, per-site overrides. Read at evaluation time, so a settings change applies
 *                      immediately without reloading rules. opts.businessHours (calendar or store) overrides the
 *                      process-wide calendar (tests).
 *   threshold "sum_field" + "sum_gt"
 *                      threshold rules may aggregate a numeric field: the group fires when the SUM of
 *                      sum_field over window_s exceeds sum_gt (and, if "count" is also set, at least
 *                      `count` events were seen). Uses 60 time buckets per window (bounded memory).
 *   type "new_value"   fires when `new_field` shows a value never seen for the group (group_by) after the
 *                      learning period `learn_s` (default 7 days of event time from the first event the rule
 *                      sees). Baselines are bounded (max_values per group, default 256) and can be persisted
 *                      with exportState()/importState().
 *   sequence steps     each step may carry "count" (default 1): step N must be seen `count` times.
 *                      "by" is the correlation key (group_by accepted as an alias).
 *   "skip_empty_group" default true: events whose group_by values are all empty are not aggregated.
 *   "suppress_s"       default 300. While a group is suppressed, further detections are aggregated and emitted
 *                      ONCE as an update partial (update: true, count = suppressed events) when the
 *                      suppression expires (tick/flush) or the next detection after expiry — so alert counts stay
 *                      accurate while the emission rate is bounded to ~2 per suppression window per group.
 *
 * String comparisons (eq/neq/in/contains/startswith/endswith) are case-insensitive; `re` is compiled once with
 * the `i` flag. Values may be arrays (any-of). Array-valued event fields (tags) match when any element matches.
 * `exists` treats undefined/null/''/0/[] as absent (ARCH: missing strings '', numbers 0).
 * Windows (threshold/distinct/sequence) are evaluated in EVENT time (ev.ts); state expiry on tick() uses the
 * injected wall clock `now()` so skewed device clocks cannot pin memory.
 */
const { createCidrSet } = require('./ip');
const businessHours = require('../util/business-hours');
const { checkRegex, MAX_REGEX_INPUT } = require('./saferegex');

const LEAF_OPS = new Set(['eq', 'neq', 'in', 'contains', 'startswith', 'endswith', 're', 'exists', 'gt', 'gte', 'lt', 'lte',
  'cidr', 'intel', 'hour_between', 'weekday_in', 'outside_business_hours']);
const TIME_OPS = new Set(['hour_between', 'weekday_in', 'outside_business_hours']);
function calendarOf(ctx) {
  const b = ctx && ctx.businessHours;
  if (b && typeof b.calendar === 'function') return b.calendar();
  if (b && typeof b.isAfterHours === 'function') return b;
  return businessHours.active();
}
const RULE_TYPES = new Set(['single', 'threshold', 'distinct', 'sequence', 'new_value']);
const INDEX_FIELDS = ['event_code', 'action', 'category', 'src_type']; // priority order for the pre-filter index
const MAX_SAMPLES = 20;
const SEP = '\u0001';
const DEFAULT_TZ_MIN = 180;

function toStr(v) {
  if (typeof v === 'string') return v;
  if (v === undefined || v === null) return '';
  return String(v);
}
function lc(v) { return toStr(v).toLowerCase(); }

function makeGetter(path) {
  if (typeof path !== 'string' || !path) throw new Error('condition without field');
  if (path.startsWith('fields.')) {
    const k = path.slice(7);
    if (!k) throw new Error(`invalid field path: ${path}`);
    return (ev) => {
      const f = ev.fields;
      if (!f) return undefined;
      return typeof f.get === 'function' ? f.get(k) : f[k];
    };
  }
  if (path.indexOf('.') >= 0) throw new Error(`invalid field path: ${path} (use a top-level field or fields.<key>)`);
  return (ev) => ev[path];
}

function toMs(v) {
  if (typeof v === 'number') return v;
  if (v instanceof Date) return v.getTime();
  const n = Number(v);
  if (Number.isFinite(n) && toStr(v).trim() !== '') return n;
  return Date.parse(v);
}

function present(v) {
  return !(v === undefined || v === null || v === '' || v === 0 || (Array.isArray(v) && v.length === 0));
}

// ---------------------------------------------------------------- condition compiler
function compileLeaf(c, ctx) {
  const op = c.op;
  if (!LEAF_OPS.has(op)) throw new Error(`unknown op "${op}" on field ${c.field}`);
  const field = c.field || (TIME_OPS.has(op) ? 'ts' : c.field);
  const get = makeGetter(field);
  const raw = c.value;
  const vals = Array.isArray(raw) ? raw : [raw];
  let test = null;
  let fn;

  switch (op) {
    case 'eq': case 'in': case 'neq': {
      if (raw === undefined) throw new Error(`${op} on ${field} needs a value`);
      const set = new Set(vals.map(lc));
      if (set.size === 1) { const one = vals.map(lc)[0]; test = (v) => lc(v) === one; }
      else test = (v) => set.has(lc(v));
      break;
    }
    case 'contains': case 'startswith': case 'endswith': {
      const needles = vals.map(lc);
      if (!needles.length) throw new Error(`${op} on ${field} needs a value`);
      const m = op === 'contains' ? 'includes' : op === 'startswith' ? 'startsWith' : 'endsWith';
      if (needles.length === 1) { const n0 = needles[0]; test = (v) => lc(v)[m](n0); }
      else test = (v) => { const s = lc(v); for (let i = 0; i < needles.length; i++) if (s[m](needles[i])) return true; return false; };
      break;
    }
    case 're': {
      const res = vals.map((p) => {
        try { checkRegex(p); } catch (e) { throw new Error(`unsafe regex on ${field}: ${e.message}`); }
        try { return new RegExp(String(p), 'i'); } catch (e) { throw new Error(`invalid regex on ${field}: ${e.message}`); }
      });
      // inputs are capped so even an acceptable pattern cannot scan an unbounded field
      const cap = (v) => { const s = toStr(v); return s.length > MAX_REGEX_INPUT ? s.slice(0, MAX_REGEX_INPUT) : s; };
      if (res.length === 1) { const r0 = res[0]; test = (v) => r0.test(cap(v)); }
      else test = (v) => { const s = cap(v); for (let i = 0; i < res.length; i++) if (res[i].test(s)) return true; return false; };
      break;
    }
    case 'exists': {
      const want = raw !== false && raw !== 'false';
      fn = (ev) => present(get(ev)) === want;
      break;
    }
    case 'gt': case 'gte': case 'lt': case 'lte': {
      const num = Number(raw);
      if (!Number.isFinite(num)) throw new Error(`${op} on ${field} needs a numeric value`);
      const cmp = op === 'gt' ? (x) => x > num : op === 'gte' ? (x) => x >= num : op === 'lt' ? (x) => x < num : (x) => x <= num;
      test = (v) => {
        if (v === undefined || v === null || v === '') return false;
        const x = typeof v === 'number' ? v : Number(v);
        return x === x && cmp(x); // NaN-safe
      };
      break;
    }
    case 'cidr': {
      const cs = createCidrSet(vals);
      test = (v) => cs.has(v);
      break;
    }
    case 'intel': {
      const lists = vals.map(String);
      test = (v) => {
        const intel = ctx.intel;
        if (!intel || v === undefined || v === null || v === '') return false;
        for (let i = 0; i < lists.length; i++) if (intel.match(lists[i], v)) return true;
        return false;
      };
      break;
    }
    case 'hour_between': case 'weekday_in': {
      const off = (c.tz_offset_min !== undefined ? Number(c.tz_offset_min) : ctx.tzOffsetMin) * 60000;
      if (op === 'hour_between') {
        if (!Array.isArray(raw) || raw.length !== 2) throw new Error('hour_between needs [startHour, endHour]');
        const a = Number(raw[0]), b = Number(raw[1]);
        if (!(a >= 0 && a <= 24 && b >= 0 && b <= 24)) throw new Error('hour_between hours must be 0-24');
        test = (v) => {
          const t = toMs(v); if (!Number.isFinite(t) || t <= 0) return false;
          const h = Math.floor((((t + off) % 86400000) + 86400000) % 86400000 / 3600000);
          return a <= b ? (h >= a && h < b) : (h >= a || h < b);
        };
      } else {
        const days = new Set(vals.map(Number));
        test = (v) => {
          const t = toMs(v); if (!Number.isFinite(t) || t <= 0) return false;
          return days.has(new Date(t + off).getUTCDay());
        };
      }
      break;
    }
    case 'outside_business_hours': {
      if (raw !== undefined && typeof raw !== 'boolean' && raw !== 'true' && raw !== 'false') throw new Error('outside_business_hours value must be true or false');
      const want = !(raw === false || raw === 'false');
      fn = (ev) => {
        const t = toMs(get(ev)); if (!Number.isFinite(t) || t <= 0) return false;
        const cal = calendarOf(ctx);
        return cal.isAfterHours(t, cal.siteOf(ev)) === want;
      };
      break;
    }
    default: throw new Error(`unsupported op ${op}`);
  }

  if (!fn) {
    const t = test;
    fn = (ev) => {
      const v = get(ev);
      if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) if (t(v[i])) return true; return false; }
      return t(v);
    };
    if (op === 'neq') { const eq = fn; fn = (ev) => !eq(ev); }
  }
  if (c.not === true) { const inner = fn; return (ev) => !inner(ev); }
  return fn;
}

function compileMatch(m, ctx) {
  if (m === undefined || m === null) throw new Error('rule has no match');
  if (Array.isArray(m)) return compileMatch({ all: m }, ctx);
  if (typeof m !== 'object') throw new Error('match must be an object');
  if (m.op !== undefined || m.field !== undefined) return compileLeaf(m, ctx);
  for (const k of Object.keys(m)) if (k !== 'all' && k !== 'any' && k !== 'none') throw new Error(`unknown match key "${k}"`);
  const all = (m.all || []).map((x) => compileMatch(x, ctx));
  const any = (m.any || []).map((x) => compileMatch(x, ctx));
  const none = (m.none || []).map((x) => compileMatch(x, ctx));
  if (!all.length && !any.length && !none.length) throw new Error('empty match (needs all/any/none)');
  const nA = all.length, nY = any.length, nN = none.length;
  if (nA === 1 && !nY && !nN) return all[0];
  return (ev) => {
    for (let i = 0; i < nA; i++) if (!all[i](ev)) return false;
    if (nY) {
      let ok = false;
      for (let i = 0; i < nY; i++) if (any[i](ev)) { ok = true; break; }
      if (!ok) return false;
    }
    for (let i = 0; i < nN; i++) if (none[i](ev)) return false;
    return true;
  };
}

/** Finds a mandatory eq/in condition on an index field → {field, values[] (lower-case)} or null. */
function indexKeyOf(m) {
  if (!m || typeof m !== 'object') return null;
  let leaves;
  if (Array.isArray(m)) leaves = m;
  else if (m.field !== undefined) leaves = [m];
  else leaves = m.all || [];
  let best = null;
  for (const c of leaves) {
    if (!c || c.field === undefined || c.not === true) {
      // a nested all-group is still mandatory
      if (c && c.field === undefined && c.all && !c.any && !c.none) {
        const k = indexKeyOf(c);
        if (k && (!best || INDEX_FIELDS.indexOf(k.field) < INDEX_FIELDS.indexOf(best.field))) best = k;
      }
      continue;
    }
    if ((c.op === 'eq' || c.op === 'in') && INDEX_FIELDS.includes(c.field)) {
      const values = (Array.isArray(c.value) ? c.value : [c.value]).map(lc);
      if (!best || INDEX_FIELDS.indexOf(c.field) < INDEX_FIELDS.indexOf(best.field)) best = { field: c.field, values };
    }
  }
  return best;
}

/*
 * Dispatch gates: a gate is a list of alternatives, at least one of which is TRUE for every event the rule can match.
 *   {kind:'eq', field, values[]}  — field (an INDEX_FIELD) equals one of values   → hash lookup per event
 *   {kind:'present', field}       — field is non-empty (0 counts as present)     → one property read per event
 * Rules without any derivable gate are evaluated for every event.
 */
const COMMON_FIELDS = new Set(['src_ip', 'dst_ip', 'user', 'target_user', 'host', 'host_ip', 'src_type', 'src_id', 'category', 'action',
  'outcome', 'ts', 'rts', 'severity', 'tags', 'message', 'raw', 'id', 'collector']);
const EQ_RANK = { event_code: 0, action: 1, category: 3, src_type: 4 };

function leafGate(c) {
  if (!c || c.not === true || typeof c.field !== 'string' || !c.field) return null;
  const vals = Array.isArray(c.value) ? c.value : [c.value];
  const present = [{ kind: 'present', field: c.field }];
  switch (c.op) {
    case 'eq': case 'in':
      if (INDEX_FIELDS.includes(c.field)) return [{ kind: 'eq', field: c.field, values: vals.map(lc) }];
      return vals.length && vals.every((v) => lc(v) !== '') ? present : null;
    case 'contains': case 'startswith': case 'endswith':
      return vals.length && vals.every((v) => lc(v) !== '') ? present : null;
    case 're':
      try { if (!vals.length || vals.some((p) => new RegExp(String(p), 'i').test(''))) return null; } catch { return null; }
      return present;
    case 'intel': case 'cidr': case 'gt': case 'gte': case 'lt': case 'lte':
      return present;
    case 'exists':
      return c.value === false || c.value === 'false' ? null : present;
    default: return null;
  }
}
function gateScore(g) {
  let worst = 0;
  for (const a of g) {
    const s = a.kind === 'eq' ? EQ_RANK[a.field] : (COMMON_FIELDS.has(a.field) ? 6 : 2);
    if (s > worst) worst = s;
  }
  return worst + g.length * 0.01;
}
function gateOf(m) {
  if (!m || typeof m !== 'object') return null;
  if (Array.isArray(m)) return gateOf({ all: m });
  if (m.field !== undefined || m.op !== undefined) return leafGate(m);
  const cands = [];
  for (const c of m.all || []) { const g = gateOf(c); if (g) cands.push(g); }
  if (m.any && m.any.length) {
    const alts = m.any.map(gateOf);
    if (alts.every(Boolean)) cands.push(alts.flat());
  }
  if (!cands.length) return null;
  cands.sort((a, b) => gateScore(a) - gateScore(b));
  return cands[0];
}
function describeGate(g) {
  if (!g) return null;
  return [...new Set(g.map((a) => (a.kind === 'eq' ? a.field : `present:${a.field}`)))].join('|');
}

// ---------------------------------------------------------------- rule compiler
function num(v, dflt) { const n = Number(v); return v === undefined || v === null || v === '' || !Number.isFinite(n) ? dflt : n; }

/**
 * compileRule(def, ctx?) → compiled rule; throws Error with a clear message for invalid rules.
 * Exported for validation in the rules API.
 */
function compileRule(def, ctx) {
  ctx = ctx || { intel: null, tzOffsetMin: DEFAULT_TZ_MIN };
  if (!def || typeof def !== 'object') throw new Error('rule must be an object');
  if (!def.id || typeof def.id !== 'string') throw new Error('rule.id is required');
  if (!def.name) throw new Error(`${def.id}: rule.name is required`);
  const type = def.type || 'single';
  if (!RULE_TYPES.has(type)) throw new Error(`${def.id}: unknown rule type "${type}"`);
  const wrap = (fnc) => { try { return fnc(); } catch (e) { throw new Error(`${def.id}: ${e.message}`); } };

  const cr = {
    def, id: def.id, type,
    severity: Math.max(0, Math.min(4, num(def.severity, 2))),
    windowMs: num(def.window_s, 300) * 1000,
    suppressMs: num(def.suppress_s, 300) * 1000,
    skipEmpty: def.skip_empty_group !== false,
    groupFields: [], groupGet: [],
    alertFields: [], alertGet: [],
    state: new Map(),   // group key → state
    supp: new Map(),    // group key → suppression entry
    firstTs: 0,
    stats: { evaluations: 0, matches: 0, alerts: 0, suppressed: 0, updates: 0, evicted: 0, errors: 0, timedNs: 0, timed: 0 },
  };
  if (cr.windowMs <= 0) throw new Error(`${def.id}: window_s must be > 0`);
  if (cr.suppressMs < 0) throw new Error(`${def.id}: suppress_s must be >= 0`);

  const gb = type === 'sequence' ? (def.by || def.group_by || []) : (def.group_by || []);
  if (!Array.isArray(gb)) throw new Error(`${def.id}: group_by/by must be an array`);
  wrap(() => { for (const f of gb) { cr.groupFields.push(f); cr.groupGet.push(makeGetter(f)); } });
  const fia = Array.isArray(def.fields_in_alert) ? def.fields_in_alert : [];
  wrap(() => { for (const f of fia) { cr.alertFields.push(f); cr.alertGet.push(makeGetter(f)); } });

  if (type === 'sequence') {
    if (!Array.isArray(def.steps) || def.steps.length < 2) throw new Error(`${def.id}: sequence needs at least 2 steps`);
    cr.steps = def.steps.map((s, i) => wrap(() => {
      const c = Math.max(1, Math.floor(num(s.count, 1)));
      return { test: compileMatch(s.match, ctx), count: c, idx: i };
    }));
    // index only when every step is gated on the same field
    const keys = def.steps.map((s) => indexKeyOf(s.match));
    if (keys.every((k) => k && k.field === keys[0].field)) cr.index = { field: keys[0].field, values: [...new Set(keys.flatMap((k) => k.values))] };
    const gates = def.steps.map((s) => gateOf(s.match));
    cr.gate = gates.every(Boolean) ? gates.flat() : null;
  } else {
    cr.test = wrap(() => compileMatch(def.match, ctx));
    cr.index = indexKeyOf(def.match);
    cr.gate = gateOf(def.match);
  }
  cr.stamp = 0;

  if (type === 'threshold') {
    cr.count = Math.floor(num(def.count, def.sum_field ? 1 : NaN));
    if (!(cr.count >= 1)) throw new Error(`${def.id}: threshold needs count >= 1 (or sum_field + sum_gt)`);
    if (def.sum_field) {
      cr.sumGet = wrap(() => makeGetter(def.sum_field));
      cr.sumGt = num(def.sum_gt, NaN);
      if (!Number.isFinite(cr.sumGt)) throw new Error(`${def.id}: sum_field needs numeric sum_gt`);
      cr.bucketMs = Math.max(1000, Math.ceil(cr.windowMs / 60));
    }
  } else if (type === 'distinct') {
    if (!def.distinct_field) throw new Error(`${def.id}: distinct needs distinct_field`);
    cr.distinctGet = wrap(() => makeGetter(def.distinct_field));
    cr.distinctCount = Math.floor(num(def.distinct_count, NaN));
    if (!(cr.distinctCount >= 2)) throw new Error(`${def.id}: distinct needs distinct_count >= 2`);
  } else if (type === 'new_value') {
    const nf = def.new_field || def.distinct_field;
    if (!nf) throw new Error(`${def.id}: new_value needs new_field`);
    cr.newGet = wrap(() => makeGetter(nf));
    cr.learnMs = num(def.learn_s, 7 * 86400) * 1000;
    cr.maxValues = Math.max(1, num(def.max_values, 256));
  }
  return cr;
}

function fmtDur(ms) {
  const s = Math.round(ms / 1000);
  if (s % 86400 === 0) return `${s / 86400}d`;
  if (s % 3600 === 0) return `${s / 3600}h`;
  if (s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

// ---------------------------------------------------------------- detector
function createDetector(opts = {}) {
  const now = opts.now || Date.now;
  const log = opts.log || { info() {}, warn() {}, error() {}, debug() {} };
  const onAlert = opts.onAlert || (() => {});
  const maxGroups = opts.maxGroups || 20000;
  const timingSample = opts.timingSample || 16; // time 1 in N evaluations per rule
  const sweepMs = opts.sweepMs !== undefined ? opts.sweepMs : 10000;
  const ctx = { intel: opts.intel || null, tzOffsetMin: opts.tzOffsetMin !== undefined ? opts.tzOffsetMin : DEFAULT_TZ_MIN, businessHours: opts.businessHours || null };

  let compiled = [];          // all enabled compiled rules
  let unindexed = [];         // rules without a gate: evaluated for every event
  let indexFields = [];       // [[field, Map(value → [rules])]] for eq gates
  let presentGates = [];      // [[getter, [rules]]] for presence gates
  let evSeq = 0;              // per-event stamp so a rule reachable through several gates is evaluated once
  const g = { events: 0, alerts: 0, updates: 0, errors: 0, loadErrors: [], started: now(), epsWin: [], lastEvents: 0 };

  function safeEmit(partial) {
    try { onAlert(partial); } catch (e) { g.errors++; log.error('detector onAlert failed', { rule: partial.rule_id, err: e.message }); }
  }

  function load(rules) {
    const errors = [];
    const next = [];
    const old = new Map(compiled.map((c) => [c.id, c]));
    for (const def of rules || []) {
      if (!def || def.enabled === false || def.type === 'scheduled') continue;
      try {
        const cr = compileRule(def, ctx);
        const prev = old.get(cr.id);
        // keep in-flight state when the rule definition did not change
        if (prev && JSON.stringify(prev.def) === JSON.stringify(def)) {
          cr.state = prev.state; cr.supp = prev.supp; cr.stats = prev.stats; cr.firstTs = prev.firstTs;
        }
        next.push(cr);
      } catch (e) {
        errors.push({ id: def && def.id, error: e.message });
        log.warn('rule rejected', { id: def && def.id, err: e.message });
      }
    }
    const idx = new Map();
    const pres = new Map();
    const un = [];
    const addTo = (arr, cr) => { if (!arr.includes(cr)) arr.push(cr); };
    for (const cr of next) {
      if (!cr.gate) { un.push(cr); continue; }
      for (const alt of cr.gate) {
        if (alt.kind === 'eq') {
          let byVal = idx.get(alt.field);
          if (!byVal) { byVal = new Map(); idx.set(alt.field, byVal); }
          for (const v of alt.values) {
            let arr = byVal.get(v);
            if (!arr) { arr = []; byVal.set(v, arr); }
            addTo(arr, cr);
          }
        } else {
          let arr = pres.get(alt.field);
          if (!arr) { arr = []; pres.set(alt.field, arr); }
          addTo(arr, cr);
        }
      }
    }
    compiled = next; unindexed = un;
    indexFields = INDEX_FIELDS.filter((f) => idx.has(f)).map((f) => [f, idx.get(f)]);
    presentGates = [...pres.entries()].map(([f, arr]) => [makeGetter(f), arr, f]);
    g.loadErrors = errors;
    return { loaded: next.length, errors };
  }

  // -- helpers
  function groupOf(cr, ev) {
    const n = cr.groupGet.length;
    if (!n) return '';
    if (n === 1) return toStr(cr.groupGet[0](ev));
    let k = toStr(cr.groupGet[0](ev));
    for (let i = 1; i < n; i++) k += SEP + toStr(cr.groupGet[i](ev));
    return k;
  }
  function emptyGroup(cr, key) {
    return cr.skipEmpty && cr.groupGet.length > 0 && (key === '' || key.replace(/\u0001/g, '') === '');
  }
  function touch(cr, key, st) {
    const m = cr.state;
    m.delete(key); m.set(key, st);
    if (m.size > maxGroups) { m.delete(m.keys().next().value); cr.stats.evicted++; }
  }
  function pushSample(arr, id) {
    if (!id) return;
    arr.push(id);
    if (arr.length > MAX_SAMPLES) arr.shift();
  }

  function buildPartial(cr, ev, key, count, tsFirst, tsLast, samples, extra) {
    const def = cr.def;
    const group = {};
    const parts = [];
    for (let i = 0; i < cr.groupFields.length; i++) {
      const v = toStr(cr.groupGet[i](ev));
      group[cr.groupFields[i]] = v;
      if (v) parts.push(`${cr.groupFields[i]}=${v}`);
    }
    const fields = {};
    for (let i = 0; i < cr.alertFields.length; i++) {
      const v = cr.alertGet[i](ev);
      if (present(v)) fields[cr.alertFields[i]] = Array.isArray(v) ? v.join(',') : toStr(v);
    }
    let ctxText = parts.join(', ');
    if (!ctxText) ctxText = Object.keys(fields).slice(0, 3).map((k) => `${k}=${fields[k]}`).join(', ');
    const span = cr.type === 'single' || cr.type === 'new_value' ? '' : ` within ${fmtDur(cr.windowMs)}`;
    const summary = `${def.name}${ctxText ? ` — ${ctxText}` : ''} (${count} event${count === 1 ? '' : 's'}${span})`;
    return Object.assign({
      rule_id: cr.id, rule_name: def.name, rule_version: def.version || 1, rule_type: cr.type,
      severity: cr.severity, mitre: Array.isArray(def.mitre) ? def.mitre.slice() : [], tactic: def.tactic || '',
      group, group_key: key, count, ts_first: tsFirst, ts_last: tsLast,
      sample_event_ids: samples.slice(0, MAX_SAMPLES), summary, fields,
      src_type: toStr(ev.src_type), src_id: toStr(ev.src_id), host: toStr(ev.host),
      source: 'engine', suppress_s: cr.suppressMs / 1000, detected_at: now(),
    }, extra || null);
  }

  /** fire honouring suppression (event time). */
  function fire(cr, ev, key, count, tsFirst, tsLast, samples, extra) {
    const s = cr.supp.get(key);
    if (s && tsLast < s.until) {
      cr.stats.suppressed++;
      s.pend += count;
      if (!s.pfirst || tsFirst < s.pfirst) s.pfirst = tsFirst;
      if (tsLast > s.plast) s.plast = tsLast;
      for (const id of samples) { if (s.psamples.length < MAX_SAMPLES) s.psamples.push(id); }
      s.ev = ev;
      return;
    }
    if (s) { flushSupp(cr, key, s); cr.supp.delete(key); }
    const partial = buildPartial(cr, ev, key, count, tsFirst, tsLast, samples, extra);
    cr.stats.alerts++; g.alerts++;
    safeEmit(partial);
    if (cr.suppressMs > 0) {
      cr.supp.set(key, { until: tsLast + cr.suppressMs, wallUntil: now() + cr.suppressMs, pend: 0, pfirst: 0, plast: 0, psamples: [], ev: null });
      if (cr.supp.size > maxGroups) {
        const k0 = cr.supp.keys().next().value;
        flushSupp(cr, k0, cr.supp.get(k0));
        cr.supp.delete(k0);
      }
    }
  }
  function flushSupp(cr, key, s) {
    if (!s || !s.pend || !s.ev) return;
    cr.stats.updates++; g.updates++;
    safeEmit(buildPartial(cr, s.ev, key, s.pend, s.pfirst, s.plast, s.psamples, { update: true }));
    s.pend = 0; s.psamples = []; s.ev = null;
  }

  // -- per-type processing (called after the match test for non-sequence types)
  function procSingle(cr, ev, ts) {
    const key = groupOf(cr, ev);
    fire(cr, ev, key, 1, ts, ts, ev.id ? [ev.id] : []);
  }

  function procThreshold(cr, ev, ts) {
    const key = groupOf(cr, ev);
    if (emptyGroup(cr, key)) return;
    let st = cr.state.get(key);
    const lo = ts - cr.windowMs;
    if (!st) st = { q: [], n: 0, samples: [], b: null, sum: 0, touched: 0 };
    st.touched = now();
    pushSample(st.samples, ev.id);
    if (cr.sumGet) {
      // bucketed sliding sum
      const val = Number(cr.sumGet(ev)) || 0;
      const bt = Math.floor(ts / cr.bucketMs) * cr.bucketMs;
      if (!st.b) st.b = [];
      const b = st.b;
      while (b.length && b[0].t + cr.bucketMs <= lo) { st.sum -= b[0].s; st.n -= b[0].n; b.shift(); }
      const last = b[b.length - 1];
      if (last && last.t === bt) { last.s += val; last.n++; } else if (last && bt < last.t) { last.s += val; last.n++; } else b.push({ t: bt, s: val, n: 1, f: ts });
      st.sum += val; st.n++;
      touch(cr, key, st);
      if (st.sum > cr.sumGt && st.n >= cr.count) {
        const first = b.length ? b[0].f : ts;
        cr.state.delete(key);
        fire(cr, ev, key, st.n, first, ts, st.samples, { sum: st.sum, sum_field: cr.def.sum_field });
      }
      return;
    }
    const q = st.q;
    while (q.length && q[0] < lo) q.shift();
    q.push(ts);
    if (q.length > cr.count) q.shift();
    touch(cr, key, st);
    if (q.length >= cr.count) {
      cr.state.delete(key);
      fire(cr, ev, key, q.length, q[0], ts, st.samples);
    }
  }

  function procDistinct(cr, ev, ts) {
    const key = groupOf(cr, ev);
    if (emptyGroup(cr, key)) return;
    const dv = lc(cr.distinctGet(ev));
    if (!dv) return;
    let st = cr.state.get(key);
    if (!st) st = { vals: new Map(), samples: [], touched: 0 };
    st.touched = now();
    const lo = ts - cr.windowMs;
    const vals = st.vals;
    vals.delete(dv); vals.set(dv, ts);
    for (const [k, t] of vals) { if (t < lo) vals.delete(k); else break; }
    pushSample(st.samples, ev.id);
    touch(cr, key, st);
    if (vals.size >= cr.distinctCount) {
      let first = ts;
      for (const t of vals.values()) if (t < first) first = t;
      const distinct = [...vals.keys()].slice(0, MAX_SAMPLES);
      cr.state.delete(key);
      fire(cr, ev, key, vals.size, first, ts, st.samples, { distinct_field: cr.def.distinct_field, distinct_values: distinct });
    }
  }

  function procNewValue(cr, ev, ts) {
    const key = groupOf(cr, ev);
    if (emptyGroup(cr, key)) return;
    const v = lc(cr.newGet(ev));
    if (!v) return;
    if (!cr.firstTs) cr.firstTs = ts;
    let st = cr.state.get(key);
    if (!st) st = { vals: new Set(), touched: 0 };
    st.touched = now();
    const known = st.vals.has(v);
    if (!known) {
      st.vals.add(v);
      if (st.vals.size > cr.maxValues) st.vals.delete(st.vals.values().next().value);
    }
    touch(cr, key, st);
    if (!known && ts >= cr.firstTs + cr.learnMs) {
      fire(cr, ev, key, 1, ts, ts, ev.id ? [ev.id] : [], { new_field: cr.def.new_field || cr.def.distinct_field, new_value: v });
    }
  }

  function procSequence(cr, ev, ts) {
    const steps = cr.steps;
    let any = false;
    const hit = cr._hit || (cr._hit = new Array(steps.length));
    for (let i = 0; i < steps.length; i++) { hit[i] = steps[i].test(ev); if (hit[i]) any = true; }
    if (!any) return;
    cr.stats.matches++;
    const key = groupOf(cr, ev);
    if (emptyGroup(cr, key)) return;
    let st = cr.state.get(key);
    if (st && st.step > 0 && ts - st.t0 > cr.windowMs) st = null; // expired → restart
    if (!st) {
      if (!hit[0]) return;
      st = { step: 0, q: [], t0: 0, n: 0, samples: [], touched: 0 };
    }
    st.touched = now();
    const cur = st.step;
    if (!hit[cur]) { touch(cr, key, st); return; }
    const step = steps[cur];
    pushSample(st.samples, ev.id);
    st.n++;
    if (cur === 0) {
      const lo = ts - cr.windowMs;
      while (st.q.length && st.q[0] < lo) st.q.shift();
      st.q.push(ts);
      if (st.q.length > step.count) st.q.shift();
      if (st.q.length >= step.count) { st.t0 = st.q[0]; st.step = 1; st.q = []; }
    } else {
      st.q.push(ts);
      if (st.q.length >= step.count) { st.step++; st.q = []; }
    }
    if (st.step >= steps.length) {
      cr.state.delete(key);
      fire(cr, ev, key, st.n, st.t0 || ts, ts, st.samples, { steps: steps.length });
      return;
    }
    touch(cr, key, st);
  }

  function evalRule(cr, ev, ts) {
    const s = cr.stats;
    const timed = (++s.evaluations % timingSample) === 0;
    const t0 = timed ? process.hrtime.bigint() : 0n;
    try {
      switch (cr.type) {
        case 'sequence': procSequence(cr, ev, ts); break;
        default:
          if (cr.test(ev)) {
            s.matches++;
            if (cr.type === 'single') procSingle(cr, ev, ts);
            else if (cr.type === 'threshold') procThreshold(cr, ev, ts);
            else if (cr.type === 'distinct') procDistinct(cr, ev, ts);
            else procNewValue(cr, ev, ts);
          }
      }
    } catch (e) {
      s.errors++; g.errors++;
      if (s.errors <= 5) log.error('rule evaluation failed', { rule: cr.id, err: e.message });
    }
    if (timed) { s.timedNs += Number(process.hrtime.bigint() - t0); s.timed++; }
  }

  function onEvent(ev) {
    if (!ev || typeof ev !== 'object') return ev;
    g.events++;
    let ts = ev.ts;
    if (typeof ts !== 'number') ts = ts ? toMs(ts) : 0;
    if (!(ts > 0)) ts = ev.rts || now();
    const stamp = ++evSeq;
    for (let i = 0; i < unindexed.length; i++) evalRule(unindexed[i], ev, ts);
    for (let f = 0; f < indexFields.length; f++) {
      const v = ev[indexFields[f][0]];
      if (v === undefined || v === null || v === '') continue;
      const arr = indexFields[f][1].get(typeof v === 'string' ? v.toLowerCase() : String(v).toLowerCase());
      if (arr) for (let i = 0; i < arr.length; i++) { const cr = arr[i]; if (cr.stamp !== stamp) { cr.stamp = stamp; evalRule(cr, ev, ts); } }
    }
    for (let p = 0; p < presentGates.length; p++) {
      const v = presentGates[p][0](ev);
      if (v === undefined || v === null || v === '') continue;
      const arr = presentGates[p][1];
      for (let i = 0; i < arr.length; i++) { const cr = arr[i]; if (cr.stamp !== stamp) { cr.stamp = stamp; evalRule(cr, ev, ts); } }
    }
    return ev;
  }

  /**
   * Expire idle state and flush expired suppression aggregates. Cheap to call often (main.js: every second): the full
   * sweep over all groups runs at most every opts.sweepMs (default 10 s) of the given clock.
   */
  function tick(nowMs) {
    const t = nowMs || now();
    let expired = 0;
    const dtE = t - (g.lastTick || g.started);
    if (dtE > 0) { g.eps = Math.round(((g.events - g.lastEvents) * 1000) / dtE); g.lastEvents = g.events; g.lastTick = t; }
    if (g.lastSweep && t - g.lastSweep < sweepMs && t >= g.lastSweep) return { expired: 0, swept: false };
    g.lastSweep = t;
    for (const cr of compiled) {
      if (cr.type !== 'new_value') {
        const idle = cr.windowMs + 60000;
        for (const [k, st] of cr.state) { if (t - st.touched > idle) { cr.state.delete(k); expired++; } }
      }
      for (const [k, s] of cr.supp) {
        if (t >= s.wallUntil) { flushSupp(cr, k, s); cr.supp.delete(k); }
      }
    }
    return { expired, swept: true };
  }

  /** Emit every pending suppression aggregate (e.g. at the end of a replay). */
  function flush() {
    for (const cr of compiled) for (const [k, s] of cr.supp) flushSupp(cr, k, s);
  }

  function stats() {
    const rules = compiled.map((cr) => {
      const s = cr.stats;
      return {
        id: cr.id, name: cr.def.name, type: cr.type, indexed: describeGate(cr.gate),
        evaluations: s.evaluations, matches: s.matches, alerts: s.alerts, suppressed: s.suppressed, updates: s.updates,
        errors: s.errors, groups: cr.state.size, suppressions: cr.supp.size, evicted: s.evicted,
        avg_us: s.timed ? Math.round(s.timedNs / s.timed / 10) / 100 : 0,
      };
    });
    return {
      events: g.events, alerts: g.alerts, updates: g.updates, errors: g.errors, eps: g.eps || 0,
      rules_loaded: compiled.length, rules_unindexed: unindexed.length, load_errors: g.loadErrors, rules,
    };
  }

  /** Persistable state for new_value baselines (other rule state is short-lived and not exported). */
  function exportState() {
    const out = {};
    for (const cr of compiled) {
      if (cr.type !== 'new_value') continue;
      out[cr.id] = { firstTs: cr.firstTs, groups: [...cr.state].map(([k, st]) => [k, [...st.vals]]) };
    }
    return { version: 1, rules: out };
  }
  function importState(s) {
    if (!s || !s.rules) return 0;
    let n = 0;
    for (const cr of compiled) {
      const r = s.rules[cr.id];
      if (!r || cr.type !== 'new_value') continue;
      cr.firstTs = r.firstTs || 0;
      for (const [k, vals] of r.groups || []) { cr.state.set(k, { vals: new Set(vals), touched: now() }); n++; }
    }
    return n;
  }

  load(opts.rules || []);
  return {
    onEvent, tick, flush, load, stats, exportState, importState,
    rules: () => compiled.map((c) => c.def),
    setIntel(intel) { ctx.intel = intel; },
  };
}

module.exports = { createDetector, compileRule, compileMatch, indexKeyOf, gateOf, LEAF_OPS, RULE_TYPES };
