// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Scheduled search rules — run a query every N minutes and alert when the count condition is met.
 *
 *   createScheduled({ rules, search, onAlert, log, now, checkMs = 30000 })
 *     → { load(rules), start(), stop(), runDue(nowMs), runRule(id, nowMs), stats() }
 *
 * Rule (native JSON, type "scheduled"):
 *   { "id", "name", "severity", "mitre", "type": "scheduled",
 *     "query": "<query language q>",            // ARCH "Query language"
 *     "every_min": 15, "lookback_min": 15,       // lookback defaults to every_min
 *     "condition": { "op": "gte"|"gt"|"lt"|"lte"|"eq", "value": N },   // alias: "threshold": N  (≡ gte N)
 *     "group_by": ["src_ip"],                    // optional: condition evaluated per group (from returned rows)
 *     "max_rows": 50000,                         // optional cap on rows fetched for group_by counting
 *     "suppress_s": 3600 }
 * `lt`/`lte` enable "absence" rules (e.g. a log source that went silent).
 *
 * deps.search contract (provided by the core/API layer):
 *   search(q, fromMs, toMs, { limit, offset, order: 'asc' }) → Promise<{ rows[], total_estimate? } | rows[]>
 * When total_estimate is a number and there is no group_by, a single call (limit 1000) is made;
 * otherwise rows are paged (limit 1000) until exhausted or max_rows.
 */

const OPS = { gte: (a, b) => a >= b, gt: (a, b) => a > b, lt: (a, b) => a < b, lte: (a, b) => a <= b, eq: (a, b) => a === b };

function normRule(def) {
  if (!def || !def.id) throw new Error('scheduled rule needs id');
  if (!def.name) throw new Error(`${def.id}: scheduled rule needs name`);
  if (typeof def.query !== 'string' || !def.query.trim()) throw new Error(`${def.id}: scheduled rule needs a query`);
  const every = Number(def.every_min || 15);
  if (!(every >= 1)) throw new Error(`${def.id}: every_min must be >= 1`);
  const look = Number(def.lookback_min || every);
  if (!(look >= 1)) throw new Error(`${def.id}: lookback_min must be >= 1`);
  let cond = def.condition;
  if (!cond && def.threshold !== undefined) cond = { op: 'gte', value: Number(def.threshold) };
  if (!cond) cond = { op: 'gte', value: 1 };
  if (!OPS[cond.op]) throw new Error(`${def.id}: unknown condition op ${cond.op}`);
  if (!Number.isFinite(Number(cond.value))) throw new Error(`${def.id}: condition value must be numeric`);
  const gb = Array.isArray(def.group_by) ? def.group_by : [];
  if (gb.length && (cond.op === 'lt' || cond.op === 'lte' || (cond.op === 'eq' && Number(cond.value) === 0)))
    throw new Error(`${def.id}: absence conditions cannot be combined with group_by (groups with 0 rows are invisible)`);
  return { def, id: def.id, everyMs: every * 60000, lookMs: look * 60000, op: cond.op, value: Number(cond.value), groupBy: gb,
    maxRows: Number(def.max_rows || 50000), suppressMs: Number(def.suppress_s !== undefined ? def.suppress_s : 3600) * 1000 };
}

function getPath(row, f) {
  if (f.startsWith('fields.')) { const fl = row.fields || {}; return typeof fl.get === 'function' ? fl.get(f.slice(7)) : fl[f.slice(7)]; }
  return row[f];
}

function createScheduled(opts = {}) {
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const now = opts.now || Date.now;
  const onAlert = opts.onAlert || (() => {});
  const search = opts.search;
  const checkMs = opts.checkMs || 30000;
  let rules = [];
  const lastRun = new Map();
  const supp = new Map();
  const st = new Map();
  let timer = null; let running = false;

  function load(defs) {
    const errors = [];
    const next = [];
    for (const d of defs || []) {
      if (!d || d.type !== 'scheduled' || d.enabled === false) continue;
      try { next.push(normRule(d)); } catch (e) { errors.push({ id: d.id, error: e.message }); }
    }
    rules = next;
    return { loaded: next.length, errors };
  }

  async function fetchAll(r, from, to, needRows) {
    const pageSize = 1000;
    let res = await search(r.def.query, from, to, { limit: pageSize, offset: 0, order: 'asc' });
    let rows = Array.isArray(res) ? res : (res && res.rows) || [];
    const total = !Array.isArray(res) && res && typeof res.total_estimate === 'number' ? res.total_estimate : null;
    if (!needRows && total !== null) return { count: total, rows };
    const all = rows.slice();
    let offset = rows.length;
    while (rows.length === pageSize && all.length < r.maxRows) {
      res = await search(r.def.query, from, to, { limit: pageSize, offset, order: 'asc' });
      rows = Array.isArray(res) ? res : (res && res.rows) || [];
      all.push(...rows);
      offset += rows.length;
    }
    return { count: all.length, rows: all, truncated: all.length >= r.maxRows };
  }

  function emit(r, key, group, count, from, to, rows, extra) {
    const s = supp.get(r.id + '\u0002' + key);
    const t = now();
    if (s && t < s) { stat(r.id).suppressed++; return; }
    if (r.suppressMs > 0) supp.set(r.id + '\u0002' + key, t + r.suppressMs);
    const groupTxt = Object.keys(group).map((k) => `${k}=${group[k]}`).join(', ');
    const partial = Object.assign({
      rule_id: r.id, rule_name: r.def.name, rule_version: r.def.version || 1, rule_type: 'scheduled',
      severity: Math.max(0, Math.min(4, Number(r.def.severity !== undefined ? r.def.severity : 2))),
      mitre: Array.isArray(r.def.mitre) ? r.def.mitre.slice() : [], tactic: r.def.tactic || '',
      group, group_key: key, count, ts_first: from, ts_last: to,
      sample_event_ids: rows.map((x) => x && x.id).filter(Boolean).slice(0, 20),
      summary: `${r.def.name}${groupTxt ? ` — ${groupTxt}` : ''} (${count} ${r.op} ${r.value} in last ${Math.round(r.lookMs / 60000)}m)`,
      fields: { query: r.def.query }, source: 'scheduled', suppress_s: r.suppressMs / 1000, detected_at: t,
    }, extra || null);
    stat(r.id).alerts++;
    try { onAlert(partial); } catch (e) { log.error('scheduled onAlert failed', { rule: r.id, err: e.message }); }
  }

  function stat(id) {
    let s = st.get(id);
    if (!s) { s = { runs: 0, alerts: 0, suppressed: 0, errors: 0, last_run: 0, last_count: null, last_ms: 0, last_error: '' }; st.set(id, s); }
    return s;
  }

  async function runRule(id, nowMs) {
    const r = rules.find((x) => x.id === id);
    if (!r) throw new Error(`scheduled rule ${id} not loaded`);
    if (typeof search !== 'function') throw new Error('scheduled rules need deps.search');
    const to = nowMs || now();
    const from = to - r.lookMs;
    const s = stat(r.id);
    const t0 = Date.now();
    s.runs++; s.last_run = to;
    lastRun.set(r.id, to);
    try {
      const needRows = r.groupBy.length > 0;
      const res = await fetchAll(r, from, to, needRows);
      s.last_count = res.count;
      if (!needRows) {
        if (OPS[r.op](res.count, r.value)) emit(r, '', {}, res.count, from, to, res.rows);
      } else {
        const groups = new Map();
        for (const row of res.rows) {
          const vals = r.groupBy.map((f) => String(getPath(row, f) ?? ''));
          if (vals.every((v) => v === '')) continue;
          const k = vals.join('\u0001');
          let gg = groups.get(k);
          if (!gg) { gg = { vals, n: 0, rows: [] }; groups.set(k, gg); }
          gg.n++;
          if (gg.rows.length < 20) gg.rows.push(row);
        }
        for (const [k, gg] of groups) {
          if (OPS[r.op](gg.n, r.value)) {
            const group = {}; r.groupBy.forEach((f, i) => { group[f] = gg.vals[i]; });
            emit(r, k, group, gg.n, from, to, gg.rows, res.truncated ? { truncated: true } : null);
          }
        }
      }
      s.last_error = '';
      return { count: res.count };
    } catch (e) {
      s.errors++; s.last_error = e.message;
      log.warn('scheduled rule failed', { rule: r.id, err: e.message });
      return { error: e.message };
    } finally {
      s.last_ms = Date.now() - t0;
    }
  }

  async function runDue(nowMs) {
    if (running) return 0;
    running = true;
    const t = nowMs || now();
    let n = 0;
    try {
      for (const r of rules) {
        const last = lastRun.get(r.id) || 0;
        if (t - last >= r.everyMs) { await runRule(r.id, t); n++; }
      }
    } finally { running = false; }
    return n;
  }

  load(opts.rules || []);
  return {
    load, runDue, runRule,
    start() {
      if (timer) return;
      timer = setInterval(() => { runDue().catch((e) => log.error('scheduled loop failed', { err: e.message })); }, checkMs);
      if (timer.unref) timer.unref();
    },
    stop() { if (timer) clearInterval(timer); timer = null; },
    stats: () => rules.map((r) => Object.assign({ id: r.id, name: r.def.name, every_min: r.everyMs / 60000 }, stat(r.id))),
  };
}

module.exports = { createScheduled, normScheduledRule: normRule };
