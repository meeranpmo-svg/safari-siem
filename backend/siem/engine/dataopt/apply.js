// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — ingest enforcement point (DATAOPT.md "Enforcement").
 * Runs in the normalise→store path, between parse/enrich (+ detect) and the batch writer:
 *   decide(pipeline, ev, opts) → a disposition, applying rules in order, first-terminal-wins.
 *   createRouter({ writer, archive, destinations, counters, log, aggregator }) → { route(ev), flush() }
 *     route(ev): keep → writer.push(ev); route:archive → archive.write(ev); drop → counted (+ optional stub to archive);
 *                route:forward → tee a copy to the destination and keep evaluating (fan-out); trim/sample pass through.
 * Counters are updated per rule (events + bytes) for every non-keep disposition and for trims/forwards.
 */
const crypto = require('node:crypto');

function eventBytes(ev) {
  if (ev && typeof ev.raw === 'string' && ev.raw.length) return Buffer.byteLength(ev.raw);
  try { return Buffer.byteLength(JSON.stringify(ev)); } catch { return 0; }
}

// Deterministic, representative sampler in [0,1): hash of a stable key.
function sampleRoll(ev) {
  const key = (ev && (ev.id || ev.raw)) || '';
  const h = crypto.createHash('sha1').update(String(key)).digest();
  return h.readUInt32BE(0) / 0x100000000;
}

function applyTrim(ev, params) {
  if (!ev || typeof ev !== 'object') return;
  const { drop, keep, truncate } = params;
  if (keep) {
    const allow = new Set(keep);
    // only prune the free-form fields map (never structural schema fields) when a keep-list is given
    if (ev.fields && typeof ev.fields === 'object') {
      for (const k of Object.keys(ev.fields)) if (!allow.has('fields.' + k) && !allow.has(k)) delete ev.fields[k];
    }
  }
  for (const f of drop || []) {
    if (f.startsWith('fields.')) { if (ev.fields) delete ev.fields[f.slice(7)]; }
    else if (f in ev) ev[f] = typeof ev[f] === 'string' ? '' : (Array.isArray(ev[f]) ? [] : (typeof ev[f] === 'number' ? 0 : ''));
  }
  for (const [f, len] of Object.entries(truncate || {})) {
    const n = Number(len) || 0;
    if (f.startsWith('fields.')) { const k = f.slice(7); if (ev.fields && typeof ev.fields[k] === 'string' && ev.fields[k].length > n) ev.fields[k] = ev.fields[k].slice(0, n); }
    else if (typeof ev[f] === 'string' && ev[f].length > n) ev[f] = ev[f].slice(0, n);
  }
}

/**
 * decide(pipeline, ev, opts) → {
 *   disposition: 'keep'|'archive'|'drop', forwards:[destination], stub:bool, reason, rule_id,
 *   trims:[ruleId], trimmedBytes, aggregated:bool, sampledOut:bool, matched:[{id,kind}]
 * }
 * opts: { aggregator?, roll?(ev)->[0,1), now? } — aggregator has collapse(ruleId, params, ev, now) → true when collapsed.
 */
function decide(pipeline, ev, opts = {}) {
  const roll = opts.roll || sampleRoll;
  const res = { disposition: 'keep', forwards: [], stub: false, reason: '', rule_id: '', trims: [], aggregated: false, sampledOut: false, matched: [] };
  if (!pipeline || !pipeline.rules || !pipeline.rules.length) return res;
  res.trimmedBytes = 0;
  for (const r of pipeline.rules) {
    if (r.enabled === false) continue;
    let hit;
    try { hit = r.test(ev); } catch { hit = false; }
    if (!hit) continue;
    res.matched.push({ id: r.id, kind: r.kind });
    switch (r.kind) {
      case 'keep': res.disposition = 'keep'; res.rule_id = r.id; return res;
      case 'archive': res.disposition = 'archive'; res.rule_id = r.id; return res;
      case 'drop':
        res.disposition = 'drop'; res.rule_id = r.id; res.reason = r.params.reason; res.stub = r.params.stub; return res;
      case 'forward':
        res.forwards.push({ rule_id: r.id, destination: r.params.destination }); break; // tee — keep evaluating
      case 'sample':
        if (roll(ev) < r.params.rate) break; // kept in sample → continue
        res.disposition = 'drop'; res.rule_id = r.id; res.reason = 'sampled out'; res.sampledOut = true; res.stub = r.params.stub; return res;
      case 'trim': { const b0 = eventBytes(ev); applyTrim(ev, r.params); res.trims.push(r.id); res.trimmedBytes += Math.max(0, b0 - eventBytes(ev)); break; }
      case 'aggregate': {
        const collapsed = opts.aggregator ? opts.aggregator.collapse(r.id, r.params, ev, opts.now) : false;
        if (collapsed) { res.disposition = 'drop'; res.rule_id = r.id; res.reason = 'aggregated'; res.aggregated = true; res.stub = false; return res; }
        break; // representative event continues
      }
      default: break;
    }
  }
  return res;
}

// Windowed aggregator: the first event of a (rule, group) window passes; later identical events in the window collapse.
function createAggregator({ now = Date.now, maxKeys = 50000 } = {}) {
  const windows = new Map(); // key → expiry ms
  function sig(groupBy, ev) {
    let k = '';
    for (const f of groupBy) {
      const v = f.startsWith('fields.') ? (ev.fields ? ev.fields[f.slice(7)] : '') : ev[f];
      k += '\u0001' + (v == null ? '' : String(v));
    }
    return k;
  }
  function collapse(ruleId, params, ev, t) {
    const tn = t || now();
    const key = ruleId + sig(params.groupBy, ev);
    const exp = windows.get(key);
    if (exp !== undefined && exp > tn) return true; // within an open window → collapse
    windows.set(key, tn + params.windowS * 1000);
    if (ev.fields && typeof ev.fields === 'object') ev.fields.agg_window_s = String(params.windowS);
    if (windows.size > maxKeys) {
      for (const [k, e] of windows) { if (e <= tn) windows.delete(k); if (windows.size <= maxKeys) break; }
      if (windows.size > maxKeys) windows.delete(windows.keys().next().value);
    }
    return false;
  }
  return { collapse, size: () => windows.size };
}

/**
 * createRouter: wires decide() to the real sinks. All sinks are optional (tests pass fakes).
 *   writer.push(ev); archive.write(ev, {stub, rule_id, reason}); destinations.forward(destination, ev);
 *   counters.record(rule_id, kind, events, bytes) — see dataopt counters.
 */
function createRouter({ writer, archive, destinations, counters, log, aggregator, getPipeline, now = Date.now } = {}) {
  const agg = aggregator || createAggregator({ now });
  function route(ev) {
    const pipeline = getPipeline ? getPipeline() : null;
    if (!pipeline || !pipeline.rules || !pipeline.rules.length) { if (writer) writer.push(ev); return { disposition: 'keep' }; }
    const bytes = eventBytes(ev);
    const d = decide(pipeline, ev, { aggregator: agg, now });
    // forwards (tee / fan-out)
    for (const f of d.forwards) {
      try { if (destinations) destinations.forward(f.destination, ev); if (counters) counters.record(f.rule_id, 'forward', 1, bytes, { destination: f.destination, ev }); }
      catch (e) { if (log) log.every('dataopt-forward', 30000, 'warn', 'dataopt: forward failed', { destination: f.destination, err: e.message }); }
    }
    if (counters && d.trims.length) for (const rid of d.trims) counters.record(rid, 'trim', 1, d.trimmedBytes || 0, { ev });
    if (d.disposition === 'keep') { if (writer) writer.push(ev); if (counters) counters.record(d.rule_id, 'keep', 1, eventBytes(ev), { ev }); return d; }
    if (d.disposition === 'archive') {
      try { if (archive) archive.write(ev, { rule_id: d.rule_id, reason: 'route:archive' }); } catch (e) { if (log) log.every('dataopt-archive', 30000, 'error', 'dataopt: archive write failed', { err: e.message }); if (writer) writer.push(ev); }
      if (counters) counters.record(d.rule_id, 'archive', 1, bytes, { ev });
      return d;
    }
    // drop (incl. sampled-out / aggregated)
    const kind = d.sampledOut ? 'sample' : d.aggregated ? 'aggregate' : 'drop';
    if (d.stub && archive) { try { archive.writeStub(ev, { rule_id: d.rule_id, reason: d.reason }); } catch (e) { if (log) log.every('dataopt-stub', 30000, 'warn', 'dataopt: drop-stub write failed', { err: e.message }); } }
    if (counters) counters.record(d.rule_id, kind, 1, bytes, { ev, reason: d.reason });
    return d;
  }
  return { route, aggregator: agg, flush() { /* counters flushed by their own timer */ } };
}

module.exports = { decide, applyTrim, eventBytes, sampleRoll, createAggregator, createRouter };
