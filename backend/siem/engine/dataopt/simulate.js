// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — simulation / dry-run (DATAOPT.md "Simulation & cost"). Evaluate a DRAFT pipeline against the last
 * N hours of REAL events (ClickHouse) and report, per rule, how many events / bytes it would keep / archive / sample /
 * trim / drop, the projected hot-store reduction, and any detection-rule conflicts — BEFORE it is enabled.
 *
 *   createSimulate({ ch, detector, settings, log }) →
 *     { run({ pipeline, window_hours|from|to, detectionRules?, limit? }) → report }
 */
const { compilePipeline, detectionConflicts } = require('./rules');
const { decide, eventBytes, createAggregator } = require('./apply');

const KINDS = ['keep', 'archive', 'drop', 'sample', 'trim', 'aggregate', 'forward'];

function blankTally() { const t = {}; for (const k of KINDS) t[k] = { events: 0, bytes: 0 }; return t; }

function createSimulate({ ch, detector, settings, log } = {}) {
  async function fetchEvents(from, to, limit) {
    if (!ch) return [];
    const rows = await ch.query(
      'SELECT * FROM events WHERE ts >= {from:DateTime64(3)} AND ts <= {to:DateTime64(3)} ORDER BY ts DESC LIMIT {lim:UInt32}',
      { from: { type: 'String', value: fmt(from) }, to: { type: 'String', value: fmt(to) }, lim: { type: 'UInt32', value: limit } },
      { readonly: true, timeout_ms: 30000 });
    return rows;
  }

  function normEv(row) {
    const ev = Object.assign({}, row);
    if (!ev.fields || typeof ev.fields !== 'object' || Array.isArray(ev.fields)) ev.fields = ev.fields && Array.isArray(ev.fields) ? Object.fromEntries(ev.fields) : {};
    if (!Array.isArray(ev.tags)) ev.tags = ev.tags ? [].concat(ev.tags) : [];
    if (typeof ev.severity === 'string') ev.severity = Number(ev.severity) || 0;
    return ev;
  }

  async function run({ pipeline, window_hours, from, to, detectionRules, uebaFeatures, limit = 20000, ctx } = {}) {
    const now = Date.now();
    const toMs = to != null ? to : now;
    const fromMs = from != null ? from : toMs - (Number(window_hours) || 24) * 3600000;
    // 20 000 events at most and a wall-clock budget: a dry run must never hold the engine thread (ingest, detection, API)
    const lim = Math.min(20000, Math.max(1, Number(limit) || 20000));
    const budgetMs = 15000, t0 = Date.now(); let outOfTime = false;
    const compiled = compilePipeline(pipeline, ctx);
    if (compiled.error) { const e = new Error('pipeline invalid: ' + compiled.error); e.code = 400; throw e; }

    const rows = await fetchEvents(fromMs, toMs, lim);
    const perRule = new Map();
    const totals = blankTally();
    const agg = createAggregator({ now });
    let rawBytes = 0, hotBytes = 0, scanned = 0;

    const tally = (rid, kind, bytes) => {
      let t = perRule.get(rid); if (!t) { t = blankTally(); perRule.set(rid, t); }
      t[kind].events++; t[kind].bytes += bytes;
      totals[kind].events++; totals[kind].bytes += bytes;
    };

    for (const row of rows) {
      if ((scanned & 63) === 0 && Date.now() - t0 > budgetMs) { outOfTime = true; break; }
      scanned++;
      const ev = normEv(row);
      const bytes = eventBytes(ev);
      rawBytes += bytes;
      const d = decide(compiled, ev, { aggregator: agg, now });
      for (const f of d.forwards) tally(f.rule_id, 'forward', bytes);
      for (const rid of d.trims) tally(rid, 'trim', d.trimmedBytes || 0);
      if (d.disposition === 'keep') { tally(d.rule_id || '(default)', 'keep', eventBytes(ev)); hotBytes += eventBytes(ev); }
      else if (d.disposition === 'archive') tally(d.rule_id, 'archive', bytes);
      else { const k = d.sampledOut ? 'sample' : d.aggregated ? 'aggregate' : 'drop'; tally(d.rule_id, k, bytes); }
    }

    // detection conflicts per dataopt rule
    const detRules = detectionRules || (detector && typeof detector.rules === 'function' ? detector.rules() : []);
    const heavy = settings ? (settings.get().heavy_sample_rate || 0.5) : 0.5;
    const conflicts = [];
    for (const r of compiled.rules) {
      const c = detectionConflicts(r, detRules, { heavySampleRate: heavy, uebaFeatures: uebaFeatures || [] });
      if (c.length) conflicts.push({ rule_id: r.id, action: r.action, detections: c });
    }

    const per_rule = compiled.rules.map((r) => {
      const t = perRule.get(r.id) || blankTally();
      const o = { rule_id: r.id, name: r.name, action: r.action };
      for (const k of KINDS) if (t[k].events) o[k] = t[k];
      return o;
    });
    // include default keep bucket if events fell through
    if (perRule.has('(default)')) per_rule.push(Object.assign({ rule_id: '(default)', name: 'keep (no rule matched)', action: 'keep' }, { keep: perRule.get('(default)').keep }));

    const reductionBytes = Math.max(0, rawBytes - hotBytes);
    return {
      window: { from: fromMs, to: toMs, hours: Math.round((toMs - fromMs) / 3600000) },
      scanned, sampled_limit: lim, limited: rows.length >= lim || outOfTime, out_of_time: outOfTime,
      per_rule, totals,
      projected: {
        raw_bytes: rawBytes, hot_bytes: hotBytes, archived_bytes: totals.archive.bytes,
        dropped_bytes: totals.drop.bytes + totals.sample.bytes + totals.aggregate.bytes,
        hot_reduction_bytes: reductionBytes, hot_reduction_pct: rawBytes ? Math.round((reductionBytes / rawBytes) * 100) : 0,
      },
      conflicts, has_conflicts: conflicts.length > 0,
    };
  }

  return { run };
}

function fmt(ms) { return new Date(Number.isFinite(ms) ? ms : Date.now()).toISOString().slice(0, 19).replace('T', ' '); }

module.exports = { createSimulate };
