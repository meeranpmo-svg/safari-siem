// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Data Optimizer — per-rule volume counters (DATAOPT.md blind-spot guard: "Dropped/sampled/trimmed volume is always
 * counted per rule (events + bytes, hourly)"). Kept in memory and flushed to ClickHouse:
 *   dataopt_rule_stat (hour, pipeline_id, rule_id, action, events, bytes)  — SummingMergeTree, every action incl. keep
 *   dataopt_drop_log  (hour, pipeline_id, rule_id, src_id, src_type, event_type, action, events, bytes) — the source
 *                      breakdown of what is dropped / sampled / trimmed / aggregated, feeding GET /dataopt/drops.
 * Nothing silently discards: a drop/sample/trim/aggregate always lands here.
 */
const HOUR = 3600000;
const KINDS = ['keep', 'archive', 'drop', 'sample', 'trim', 'aggregate', 'forward'];
const DROP_KINDS = new Set(['drop', 'sample', 'trim', 'aggregate']);

function fmtHour(ms) { return new Date(Math.floor(ms / HOUR) * HOUR).toISOString().slice(0, 19).replace('T', ' '); }

function createCounters({ ch, log, now = Date.now, pipelineId = '', flushMs = 60000, maxDropKeys = 20000 } = {}) {
  let pid = pipelineId;
  // live totals (since process start) for the API: rule_id → { kind → {events, bytes} }
  const live = new Map();
  // pending rows to flush, keyed to the hour bucket: "hour|rule|action" and "hour|rule|src|type|etype|action"
  let pendRule = new Map();
  let pendDrop = new Map();
  const st = { recorded: 0, flushes: 0, flush_errors: 0, last_flush: 0, last_error: '' };

  function liveOf(ruleId) {
    let m = live.get(ruleId);
    if (!m) { m = {}; for (const k of KINDS) m[k] = { events: 0, bytes: 0 }; live.set(ruleId, m); }
    return m;
  }

  function record(ruleId, kind, events, bytes, meta = {}) {
    if (!KINDS.includes(kind)) return;
    const rid = ruleId || '(default)';
    st.recorded++;
    const l = liveOf(rid)[kind];
    l.events += events; l.bytes += bytes;
    const hour = fmtHour(now());
    const rk = `${hour}\u0001${rid}\u0001${kind}`;
    let rr = pendRule.get(rk);
    if (!rr) { rr = { hour, pipeline_id: pid, rule_id: rid, action: kind, events: 0, bytes: 0 }; pendRule.set(rk, rr); }
    rr.events += events; rr.bytes += bytes;
    if (DROP_KINDS.has(kind) && meta.ev) {
      const ev = meta.ev;
      const etype = ev.event_code || ev.action || '';
      const dk = `${hour}\u0001${rid}\u0001${ev.src_id || ''}\u0001${ev.src_type || ''}\u0001${etype}\u0001${kind}`;
      let dr = pendDrop.get(dk);
      if (!dr) {
        if (pendDrop.size >= maxDropKeys) return; // bounded
        dr = { hour, pipeline_id: pid, rule_id: rid, src_id: ev.src_id || '', src_type: ev.src_type || '', event_type: String(etype), action: kind, events: 0, bytes: 0 };
        pendDrop.set(dk, dr);
      }
      dr.events += events; dr.bytes += bytes;
    }
  }

  function snapshot() {
    const by_rule = {};
    for (const [rid, m] of live) {
      const o = {};
      for (const k of KINDS) if (m[k].events) o[k] = { events: m[k].events, bytes: m[k].bytes };
      by_rule[rid] = o;
    }
    return { by_rule, recorded: st.recorded };
  }

  // Aggregated view for GET /dataopt/drops (in-memory, current process): per rule, total + source breakdown.
  function drops() {
    const byRule = new Map();
    for (const dr of pendDrop.values()) {
      let r = byRule.get(dr.rule_id);
      if (!r) { r = { rule_id: dr.rule_id, actions: {}, events: 0, bytes: 0, sources: new Map() }; byRule.set(dr.rule_id, r); }
      r.actions[dr.action] = (r.actions[dr.action] || 0) + dr.events;
      r.events += dr.events; r.bytes += dr.bytes;
      const sk = `${dr.src_id}|${dr.src_type}|${dr.event_type}`;
      let s = r.sources.get(sk);
      if (!s) { s = { src_id: dr.src_id, src_type: dr.src_type, event_type: dr.event_type, events: 0, bytes: 0 }; r.sources.set(sk, s); }
      s.events += dr.events; s.bytes += dr.bytes;
    }
    // fold in live totals so rules whose pending rows were just flushed still show
    for (const [rid, m] of live) {
      let r = byRule.get(rid);
      let tot = 0, tb = 0;
      for (const k of DROP_KINDS) { tot += m[k].events; tb += m[k].bytes; }
      if (!tot) continue;
      if (!r) { r = { rule_id: rid, actions: {}, events: 0, bytes: 0, sources: new Map() }; byRule.set(rid, r); }
      for (const k of DROP_KINDS) if (m[k].events && !r.actions[k]) r.actions[k] = m[k].events;
      if (r.events < tot) { r.events = tot; r.bytes = tb; }
    }
    return [...byRule.values()].map((r) => ({ rule_id: r.rule_id, actions: r.actions, events: r.events, bytes: r.bytes, sources: [...r.sources.values()].sort((a, b) => b.events - a.events).slice(0, 50) }))
      .sort((a, b) => b.events - a.events);
  }

  async function flush() {
    const rule = [...pendRule.values()];
    const drop = [...pendDrop.values()];
    if (!rule.length && !drop.length) return { rule: 0, drop: 0 };
    pendRule = new Map(); pendDrop = new Map();
    if (!ch) return { rule: rule.length, drop: drop.length };
    try {
      if (rule.length) await ch.insertRows('dataopt_rule_stat', rule);
      if (drop.length) await ch.insertRows('dataopt_drop_log', drop);
      st.flushes++; st.last_flush = now();
      return { rule: rule.length, drop: drop.length };
    } catch (e) {
      st.flush_errors++; st.last_error = e.message;
      // merge back (SummingMergeTree-safe) — bounded
      for (const r of rule) { const k = `${r.hour}\u0001${r.rule_id}\u0001${r.action}`; const cur = pendRule.get(k); if (cur) { cur.events += r.events; cur.bytes += r.bytes; } else if (pendRule.size < 50000) pendRule.set(k, r); }
      for (const d of drop) { const k = `${d.hour}\u0001${d.rule_id}\u0001${d.src_id}\u0001${d.src_type}\u0001${d.event_type}\u0001${d.action}`; if (!pendDrop.has(k) && pendDrop.size < maxDropKeys) pendDrop.set(k, d); }
      if (log) log.every('dataopt-counters-flush', 60000, 'warn', 'dataopt: counter flush failed, will retry', { err: e.message });
      return { rule: 0, drop: 0, error: e.message };
    }
  }

  const timer = flushMs ? setInterval(guardJob('dataopt.counters.flush', () => flush()), flushMs) : null;
  if (timer && timer.unref) timer.unref();

  return {
    record, snapshot, drops, flush,
    stats: () => ({ ...st, rules: live.size, pending_rule: pendRule.size, pending_drop: pendDrop.size }),
    setPipelineId(id) { pid = id || ''; },
    async stop() { if (timer) clearInterval(timer); await flush().catch(() => { /* the last flush at shutdown: a failure is logged by flush itself */ }); },
  };
}

module.exports = { createCounters, KINDS, DROP_KINDS, fmtHour };
