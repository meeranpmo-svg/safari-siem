// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — pipeline & rule model (DATAOPT.md "Pipeline model").
 *
 * A pipeline is an ordered list of rules. Each rule:
 *   { id, name, enabled?, match, action, ...params }
 *   match   — the same predicate language the detection engine uses (engine/detect/engine.js compileMatch):
 *             leaves {field, op, value} with op eq/in/neq/contains/startswith/endswith/re/exists/gt/gte/lt/lte/cidr,
 *             grouped by all / any / none (AND / OR / NOT). "field" may be a top-level event field or "fields.<key>".
 *   action  — one of:
 *     keep                         terminal → hot store (ClickHouse, normal TTL). The implicit default.
 *     route:archive                terminal → cold/cheap archive tier. { stub? } (see drop stub; n/a for route)
 *     route:forward                TEE (non-terminal, fan-out) → external destination. { destination }
 *     sample  { rate }             keep a fraction 0<rate<=1; sampled-out events are dropped (counted). terminal when out.
 *     trim    { drop?[], keep?[], truncate?{field:len} }   transform (pass through): shrink the row.
 *     aggregate { window_s, group_by?[] }   collapse identical events over a window into a count. terminal for collapsed.
 *     drop    { reason, stub? (default true), override? }   discard — needs a reason; keeps a minimal archive stub by default.
 *
 * Evaluation order: rules in order; the first TERMINAL action (keep / route:archive / drop / sample-out / aggregate-collapse)
 * decides the event's disposition. trim / forward / sample-in pass through to later rules. If no rule is terminal the event
 * is kept (hot store).
 *
 * compilePipeline(def, ctx?) → { id, name, version, enabled, rules:[compiled], error? }
 *   compiled rule = { id, name, action, kind, terminal, params, test(ev) }
 *   `test` throws nothing; a rule that fails to compile is reported in `error` and the pipeline is marked invalid.
 */
const { compileMatch } = require('../detect/engine');

const ACTIONS = new Set(['keep', 'route:archive', 'route:forward', 'sample', 'trim', 'aggregate', 'drop']);
const DEFAULT_TZ_MIN = 180;
const FIELD_RE = /^(?:[a-z_][a-z0-9_]*|fields\.[A-Za-z0-9_.-]+)$/;

function normAction(r) {
  // Accept "action": "route:archive" or {action:"route", target:"archive"} or {action:"route", route:"archive"}
  let a = String(r.action || 'keep').trim().toLowerCase();
  if (a === 'route') {
    const t = String(r.target || r.route || r.to || '').toLowerCase();
    a = t === 'archive' ? 'route:archive' : t === 'forward' ? 'route:forward' : 'route:archive';
  }
  if (a === 'archive') a = 'route:archive';
  if (a === 'forward') a = 'route:forward';
  return a;
}

function compileRule(r, ctx) {
  if (!r || typeof r !== 'object') throw new Error('rule must be an object');
  if (!r.id || typeof r.id !== 'string') throw new Error('rule.id is required');
  const action = normAction(r);
  if (!ACTIONS.has(action)) throw new Error(`${r.id}: unknown action "${r.action}"`);
  let test;
  try { test = compileMatch(r.match, ctx); }
  catch (e) { throw new Error(`${r.id}: ${e.message}`); }

  const out = { id: r.id, name: r.name || r.id, action, enabled: r.enabled !== false, raw: r, test, params: {} };
  switch (action) {
    case 'keep': out.kind = 'keep'; out.terminal = true; break;
    case 'route:archive': out.kind = 'archive'; out.terminal = true; out.params.destination = r.destination || ''; break;
    case 'route:forward':
      out.kind = 'forward'; out.terminal = false; // tee / fan-out: forward a copy and keep evaluating
      if (!r.destination) throw new Error(`${r.id}: route:forward needs a destination`);
      out.params.destination = r.destination;
      break;
    case 'sample': {
      const rate = Number(r.rate !== undefined ? r.rate : r.sample);
      if (!(rate > 0 && rate <= 1)) throw new Error(`${r.id}: sample needs rate in (0,1]`);
      out.kind = 'sample'; out.terminal = false; out.params.rate = rate; out.params.stub = r.stub !== false;
      break;
    }
    case 'trim': {
      const drop = Array.isArray(r.drop) ? r.drop.filter((f) => typeof f === 'string') : [];
      const keep = Array.isArray(r.keep) ? r.keep.filter((f) => typeof f === 'string') : null;
      const truncate = r.truncate && typeof r.truncate === 'object' && !Array.isArray(r.truncate) ? r.truncate : {};
      if (!drop.length && !keep && !Object.keys(truncate).length) throw new Error(`${r.id}: trim needs drop[], keep[] or truncate{}`);
      for (const f of [...drop, ...(keep || []), ...Object.keys(truncate)]) if (!FIELD_RE.test(f)) throw new Error(`${r.id}: trim field "${f}" invalid`);
      out.kind = 'trim'; out.terminal = false; out.params = { drop, keep, truncate };
      break;
    }
    case 'aggregate': {
      const windowS = Number(r.window_s || r.window || 60);
      if (!(windowS > 0)) throw new Error(`${r.id}: aggregate needs window_s > 0`);
      const gb = Array.isArray(r.group_by) ? r.group_by.filter((f) => typeof f === 'string') : [];
      for (const f of gb) if (!FIELD_RE.test(f)) throw new Error(`${r.id}: aggregate group_by "${f}" invalid`);
      out.kind = 'aggregate'; out.terminal = true; out.params = { windowS, groupBy: gb.length ? gb : ['src_id', 'src_type', 'action', 'event_code'] };
      break;
    }
    case 'drop': {
      const reason = String(r.reason || '').trim();
      if (!reason) throw new Error(`${r.id}: drop needs a reason`);
      out.kind = 'drop'; out.terminal = true;
      out.params = { reason, stub: r.stub !== false, override: r.override || null };
      break;
    }
    default: throw new Error(`${r.id}: unhandled action ${action}`);
  }
  return out;
}

function compilePipeline(def, ctx) {
  ctx = ctx || { intel: null, tzOffsetMin: DEFAULT_TZ_MIN };
  const out = { id: def && def.id, name: (def && def.name) || (def && def.id) || 'pipeline', version: (def && def.version) || 1, enabled: !!(def && def.enabled), rules: [], error: null };
  if (!def || typeof def !== 'object') { out.error = 'pipeline must be an object'; return out; }
  const list = Array.isArray(def.rules) ? def.rules : [];
  const seen = new Set();
  for (const r of list) {
    if (r && r.id) { if (seen.has(r.id)) { out.error = `duplicate rule id ${r.id}`; return out; } seen.add(r.id); }
    try { out.rules.push(compileRule(r, ctx)); }
    catch (e) { out.error = e.message; return out; }
  }
  return out;
}

/** Validate a pipeline definition; returns { ok, error? }. Does not mutate. */
function validatePipeline(def, ctx) {
  const c = compilePipeline(def, ctx);
  return c.error ? { ok: false, error: c.error } : { ok: true };
}

// ---------------------------------------------------------------- blind-spot guard helpers
// Collect the mandatory eq/in constraints (field → Set(lowercased values)) from the top-level `all` of a match tree.
// Conservative: only mandatory, non-negated leaves count; any/none/nested groups are treated as "unconstrained".
function positiveConstraints(m, acc) {
  acc = acc || new Map();
  if (!m || typeof m !== 'object') return acc;
  const all = Array.isArray(m) ? m : (m.all || []);
  for (const c of all) {
    if (!c || typeof c !== 'object' || c.not === true) continue;
    if (c.field !== undefined && (c.op === 'eq' || c.op === 'in')) {
      const vals = (Array.isArray(c.value) ? c.value : [c.value]).map((v) => String(v).toLowerCase());
      let s = acc.get(c.field); if (!s) { s = new Set(); acc.set(c.field, s); }
      for (const v of vals) s.add(v);
    } else if (c.field === undefined && c.all && !c.any && !c.none) {
      positiveConstraints(c, acc); // a nested all-group is still mandatory
    }
  }
  return acc;
}

// Every field a detection rule reads: match leaves + group_by/by + distinct/new/sum fields + fields_in_alert.
function detectionRuleFields(def) {
  const fields = new Set();
  const walk = (m) => {
    if (!m || typeof m !== 'object') return;
    if (Array.isArray(m)) { for (const x of m) walk(x); return; }
    if (m.field !== undefined) { fields.add(m.field); return; }
    for (const k of ['all', 'any', 'none']) if (Array.isArray(m[k])) for (const x of m[k]) walk(x);
  };
  if (def.type === 'sequence' && Array.isArray(def.steps)) for (const s of def.steps) walk(s.match);
  else walk(def.match);
  for (const f of (def.group_by || def.by || [])) fields.add(f);
  for (const f of (def.fields_in_alert || [])) fields.add(f);
  if (def.distinct_field) fields.add(def.distinct_field);
  if (def.new_field) fields.add(def.new_field);
  if (def.sum_field) fields.add(def.sum_field);
  return fields;
}

// Could a dropping rule and a detection rule match the same event? Disjoint only when they both pin a shared field to
// value-sets that do not intersect; otherwise conservatively "yes".
function constraintsCompatible(dropC, detC) {
  for (const [field, dvals] of dropC) {
    const svals = detC.get(field);
    if (!svals) continue;
    let overlap = false;
    for (const v of dvals) if (svals.has(v)) { overlap = true; break; }
    if (!overlap) return false; // disjoint on this field → cannot match the same event
  }
  return true;
}

/**
 * detectionConflicts(compiledRule, detectionRuleDefs, { uebaFeatures? }) → [{ rule_id, rule_name, reason, fields[] }]
 * A drop / heavy-sample / trim rule that would remove events an active detection rule (or UEBA feature) needs.
 *   - drop / sample(rate<=heavy): conflict with every enabled detection rule whose match is compatible with this rule's.
 *   - trim: conflict with any detection rule that reads a field this rule drops or truncates.
 */
function detectionConflicts(compiled, detectionRules, opts = {}) {
  const out = [];
  const heavySample = opts.heavySampleRate !== undefined ? opts.heavySampleRate : 0.5;
  const rules = (detectionRules || []).filter((d) => d && d.enabled !== false && d.type !== 'scheduled');
  const ueba = opts.uebaFeatures || []; // [{ id, name, fields:[] }]

  if (compiled.kind === 'trim') {
    const removed = new Set([...(compiled.params.drop || []), ...Object.keys(compiled.params.truncate || {})]);
    if (compiled.params.keep) { // keep-list: everything NOT kept is removed — flag conservatively on named detection fields
      // we cannot enumerate all fields, so only named truncate/drop entries are treated as definite removals here
    }
    for (const d of rules) {
      const used = detectionRuleFields(d);
      const hit = [...removed].filter((f) => used.has(f));
      if (hit.length) out.push({ rule_id: d.id, rule_name: d.name || d.id, reason: 'trim removes fields this detection rule reads', fields: hit });
    }
    for (const f of ueba) { const hit = [...removed].filter((x) => (f.fields || []).includes(x)); if (hit.length) out.push({ rule_id: 'ueba:' + f.id, rule_name: f.name || f.id, reason: 'trim removes fields this UEBA feature reads', fields: hit }); }
    return out;
  }

  const isDrop = compiled.kind === 'drop' || compiled.kind === 'aggregate';
  const isHeavySample = compiled.kind === 'sample' && compiled.params.rate <= heavySample;
  if (!isDrop && !isHeavySample) return out;

  const dropC = positiveConstraints(compiled.raw.match);
  for (const d of rules) {
    const detC = positiveConstraints(d.type === 'sequence' && d.steps ? { all: d.steps.flatMap((s) => (s.match && s.match.all) || []) } : d.match);
    if (constraintsCompatible(dropC, detC)) {
      out.push({ rule_id: d.id, rule_name: d.name || d.id, reason: compiled.kind === 'sample' ? 'heavy sampling reduces events this detection rule relies on' : (compiled.kind === 'aggregate' ? 'aggregation collapses events this detection rule relies on' : 'drop removes events this detection rule relies on'), fields: [...detectionRuleFields(d)].slice(0, 12) });
    }
  }
  for (const f of ueba) out.push({ rule_id: 'ueba:' + f.id, rule_name: f.name || f.id, reason: 'reduces events a UEBA feature relies on', fields: (f.fields || []).slice(0, 12) });
  return out;
}

module.exports = {
  compilePipeline, compileRule, validatePipeline, ACTIONS,
  positiveConstraints, detectionRuleFields, detectionConflicts, constraintsCompatible,
};
