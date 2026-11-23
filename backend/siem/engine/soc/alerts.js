// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Alerts — raise (with dedupe), status workflow, assignment, notes, bulk operations, ClickHouse mirror.
 *
 *   createAlerts({ state, ch, log, now, onChange, dedupeWindowS = 3600, mirrorMs = 2000 })
 *     → { raise(partial), get(id), list(filter), ack(id, by), assign(id, assignee, by), note(id, text, by),
 *         setStatus(id, status, by, detail), close(id, reason, by, note), reopen(id, by), linkCase(ids, caseId, by),
 *         bulk(ids, op, args, by), flushMirror(), stats(), stop() }
 * Workflow methods throw WorkflowError { code: 400 | 404 | 409, message } for invalid input / transitions.
 *
 * Alert object (ARCH) + bookkeeping fields:
 *   { id: "ALR-0000123", rule_id, rule_name, rule_type, severity, mitre[], tactic, ts_first, ts_last, count,
 *     group: {k:v}, group_key, sample_event_ids[], summary, fields{}, status, assignee, case_id, notes[{at,by,text}],
 *     history[{at,by,action,detail}], source: engine|scheduled|sigma|logrhythm|manual, src_type, src_id, host,
 *     created, updated, ack_at, closed_at, closure_reason, merges }
 *
 * Dedupe: a partial with the same rule_id + group_key as an OPEN alert (status not closed-*) whose ts_last is within
 * the partial's suppress window (partial.suppress_s, default dedupeWindowS) is merged into it: count += partial.count,
 * ts_first/ts_last widened, sample ids appended (max 20). Update partials from the detector (update: true) always merge
 * into the open alert when there is one.
 *
 * ClickHouse mirror (optional, deps.ch.insertRows): every created/changed alert is queued and flushed every mirrorMs as
 * the full current row, matching siem.alerts in engine/store/schema.sql (ReplacingMergeTree(updated) ORDER BY id):
 *   id, rule_id, rule_name, severity, ts_first, ts_last, status, assignee, summary, group_json, mitre, updated
 * With opts.chExtraColumns = true it also sends (add these columns to schema.sql first):
 *   count UInt64, case_id String, source LowCardinality(String), src_type LowCardinality(String), src_id LowCardinality(String),
 *   host String, created DateTime64(3,'UTC'), closed_at Nullable(DateTime64(3,'UTC')), closure_reason String
 */

const STATUSES = ['new', 'acknowledged', 'in-progress', 'closed-true-positive', 'closed-false-positive', 'closed-benign'];
const CLOSE_REASONS = { 'true-positive': 'closed-true-positive', 'false-positive': 'closed-false-positive', benign: 'closed-benign' };
const TRANSITIONS = {
  new: ['acknowledged', 'in-progress', 'closed-true-positive', 'closed-false-positive', 'closed-benign'],
  acknowledged: ['in-progress', 'closed-true-positive', 'closed-false-positive', 'closed-benign'],
  'in-progress': ['acknowledged', 'closed-true-positive', 'closed-false-positive', 'closed-benign'],
  'closed-true-positive': ['in-progress'],
  'closed-false-positive': ['in-progress'],
  'closed-benign': ['in-progress'],
};
const MAX_SAMPLES = 20;
const MAX_HISTORY = 200;
const MAX_NOTES = 500;

const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');

class WorkflowError extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}

function chTime(ms) {
  if (!ms) return null;
  return new Date(ms).toISOString().replace('T', ' ').replace('Z', '');
}

function groupKeyOf(p) {
  if (typeof p.group_key === 'string') return p.group_key;
  const g = p.group || {};
  return Object.keys(g).sort().map((k) => `${k}=${g[k]}`).join('\u0001');
}

function createAlerts(opts = {}) {
  const state = opts.state;
  if (!state) throw new Error('createAlerts needs state');
  const ch = opts.ch || null;
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const now = opts.now || Date.now;
  const onChange = opts.onChange || null;
  const dedupeWindowMs = (opts.dedupeWindowS || 3600) * 1000;
  const table = opts.chTable || 'siem.alerts';
  const col = state.collection('alerts');
  const counters = state.collection('counters');

  // open-alert index: rule_id \u0002 group_key → alert id
  const openIdx = new Map();
  const dkey = (ruleId, gk) => `${ruleId}\u0002${gk}`;
  for (const a of col.all()) {
    if (isClosed(a.status)) continue;
    const k = dkey(a.rule_id, a.group_key || '');
    const cur = openIdx.get(k);
    if (!cur || (col.get(cur).ts_last || 0) < (a.ts_last || 0)) openIdx.set(k, a.id);
  }

  let seq = (counters.get('alert') || {}).n || 0;
  if (!seq) for (const a of col.all()) { const n = Number(String(a.id).replace(/\D/g, '')); if (n > seq) seq = n; }
  function nextId() {
    seq++;
    counters.put({ id: 'alert', n: seq });
    return `ALR-${String(seq).padStart(7, '0')}`;
  }

  const st = { raised: 0, created: 0, merged: 0, mirror_rows: 0, mirror_errors: 0, mirror_queue: 0 };

  // ---- ClickHouse mirror
  const mirrorQ = new Set();
  let mirrorBusy = false;
  // Row shape = columns of siem.alerts in engine/store/schema.sql (core). opts.chExtraColumns adds the optional columns.
  function toRow(a) {
    const row = {
      id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity,
      ts_first: chTime(a.ts_first), ts_last: chTime(a.ts_last), status: a.status, assignee: a.assignee || '',
      summary: a.summary || '', group_json: JSON.stringify(a.group || {}), mitre: a.mitre || [], updated: chTime(a.updated),
    };
    if (opts.chExtraColumns) {
      Object.assign(row, {
        count: a.count, case_id: a.case_id || '', source: a.source || 'engine', src_type: a.src_type || '', src_id: a.src_id || '',
        host: a.host || '', created: chTime(a.created), closed_at: chTime(a.closed_at), closure_reason: a.closure_reason || '',
      });
    }
    return row;
  }
  function queueMirror(id) {
    if (!ch || typeof ch.insertRows !== 'function') return;
    mirrorQ.add(id);
    if (mirrorQ.size > 20000) { const first = mirrorQ.values().next().value; mirrorQ.delete(first); }
  }
  async function flushMirror() {
    if (!ch || typeof ch.insertRows !== 'function' || mirrorBusy || !mirrorQ.size) return 0;
    mirrorBusy = true;
    const ids = [...mirrorQ].slice(0, 5000);
    for (const id of ids) mirrorQ.delete(id);
    const rows = ids.map((id) => col.get(id)).filter(Boolean).map(toRow);
    try {
      await ch.insertRows(table, rows);
      st.mirror_rows += rows.length;
      return rows.length;
    } catch (e) {
      st.mirror_errors++;
      for (const id of ids) mirrorQ.add(id);
      log.warn('alert mirror to ClickHouse failed (will retry)', { err: e.message, rows: rows.length });
      return 0;
    } finally { mirrorBusy = false; }
  }
  const mirrorTimer = setInterval(guardJob('soc.alerts.flushMirror', () => flushMirror()), opts.mirrorMs || 2000);
  if (mirrorTimer.unref) mirrorTimer.unref();

  function changed(a, kind) {
    queueMirror(a.id);
    if (onChange) { try { onChange(a, kind); } catch (e) { log.warn('alert onChange failed', { err: e.message }); } }
    return a;
  }
  function hist(a, by, action, detail) {
    a.history = a.history || [];
    a.history.push({ at: now(), by: by || 'system', action, detail: detail === undefined ? '' : detail });
    if (a.history.length > MAX_HISTORY) a.history.splice(1, a.history.length - MAX_HISTORY); // keep the creation entry
  }

  // ---- raise
  function raise(p) {
    if (!p || !p.rule_id) throw new Error('raise needs a partial with rule_id');
    st.raised++;
    const t = now();
    const gk = groupKeyOf(p);
    const k = dkey(p.rule_id, gk);
    const count = Math.max(1, Number(p.count) || 1);
    const tsFirst = Number(p.ts_first) || t;
    const tsLast = Number(p.ts_last) || tsFirst;
    const openId = openIdx.get(k);
    const open = openId ? col.get(openId) : null;
    const win = p.suppress_s !== undefined && Number(p.suppress_s) > 0 ? Number(p.suppress_s) * 1000 : dedupeWindowMs;
    if (open && !isClosed(open.status) && (p.update === true || tsFirst - (open.ts_last || 0) <= win)) {
      const a = col.patch(open.id, (x) => {
        x.count = (x.count || 0) + count;
        if (tsFirst < x.ts_first) x.ts_first = tsFirst;
        if (tsLast > x.ts_last) x.ts_last = tsLast;
        const s = x.sample_event_ids || (x.sample_event_ids = []);
        for (const id of p.sample_event_ids || []) { if (s.length >= MAX_SAMPLES) break; if (!s.includes(id)) s.push(id); }
        if (p.severity > x.severity) { hist(x, 'system', 'severity', `${x.severity}→${p.severity}`); x.severity = p.severity; }
        x.merges = (x.merges || 0) + 1;
        x.updated = t;
      });
      st.merged++;
      return { alert: changed(a, 'merged'), created: false };
    }
    const a = {
      id: nextId(), rule_id: String(p.rule_id), rule_name: String(p.rule_name || p.rule_id), rule_type: p.rule_type || '',
      severity: Math.max(0, Math.min(4, Number(p.severity) || 0)), mitre: Array.isArray(p.mitre) ? p.mitre.slice() : [],
      tactic: p.tactic || '', ts_first: tsFirst, ts_last: tsLast, count,
      group: Object.assign({}, p.group || {}), group_key: gk,
      sample_event_ids: (p.sample_event_ids || []).slice(0, MAX_SAMPLES), summary: String(p.summary || p.rule_name || p.rule_id),
      fields: Object.assign({}, p.fields || {}),
      status: 'new', assignee: '', case_id: '', notes: [], history: [],
      source: p.source || 'engine', src_type: p.src_type || '', src_id: p.src_id || '', host: p.host || '',
      created: t, updated: t, ack_at: 0, closed_at: 0, closure_reason: '', merges: 0,
    };
    for (const extra of ['distinct_field', 'distinct_values', 'sum', 'sum_field', 'new_field', 'new_value', 'lr_alarm_id', 'lr', 'truncated']) {
      if (p[extra] !== undefined) a[extra] = p[extra];
    }
    hist(a, 'system', 'created', `${a.source}: ${a.count} event(s)`);
    col.put(a);
    openIdx.set(k, a.id);
    st.created++;
    return { alert: changed(col.get(a.id), 'created'), created: true };
  }

  // ---- workflow
  function must(id) {
    const a = col.get(id);
    if (!a) throw new WorkflowError(404, `alert ${id} not found`);
    return a;
  }
  function setStatus(id, status, by, detail) {
    if (!STATUSES.includes(status)) throw new WorkflowError(400, `unknown status ${status}`);
    const cur = must(id);
    if (cur.status === status) return cur;
    if (!TRANSITIONS[cur.status].includes(status)) throw new WorkflowError(409, `cannot move alert from ${cur.status} to ${status}`);
    const t = now();
    const a = col.patch(id, (x) => {
      const from = x.status;
      x.status = status;
      if (!x.ack_at && status !== 'new') x.ack_at = t;
      if (isClosed(status)) { x.closed_at = t; x.closure_reason = status.slice(7); }
      else if (isClosed(from)) { x.closed_at = 0; x.closure_reason = ''; }
      x.updated = t;
      hist(x, by, 'status', `${from}→${status}${detail ? `: ${detail}` : ''}`);
    });
    const k = dkey(a.rule_id, a.group_key || '');
    if (isClosed(status)) { if (openIdx.get(k) === id) openIdx.delete(k); }
    else if (!openIdx.has(k)) openIdx.set(k, id);
    return changed(a, 'status');
  }
  function ack(id, by) {
    const a = must(id);
    if (a.status !== 'new') return a;
    const r = setStatus(id, 'acknowledged', by);
    if (!r.assignee && by) return assign(id, by, by);
    return r;
  }
  function assign(id, assignee, by) {
    must(id);
    const a = col.patch(id, (x) => {
      const from = x.assignee || '';
      x.assignee = String(assignee || '');
      x.updated = now();
      hist(x, by, 'assign', `${from || '-'}→${x.assignee || '-'}`);
    });
    return changed(a, 'assign');
  }
  function note(id, text, by) {
    const tx = String(text || '').trim();
    if (!tx) throw new WorkflowError(400, 'note text is empty');
    if (tx.length > 10000) throw new WorkflowError(400, 'note too long (max 10000 chars)');
    must(id);
    const a = col.patch(id, (x) => {
      x.notes = x.notes || [];
      x.notes.push({ at: now(), by: by || 'system', text: tx });
      if (x.notes.length > MAX_NOTES) x.notes.shift();
      x.updated = now();
      hist(x, by, 'note', '');
    });
    return changed(a, 'note');
  }
  function close(id, reason, by, noteText) {
    const status = CLOSE_REASONS[reason] || (STATUSES.includes(reason) && isClosed(reason) ? reason : null);
    if (!status) throw new WorkflowError(400, `close reason must be one of ${Object.keys(CLOSE_REASONS).join(', ')}`);
    if (noteText) note(id, noteText, by);
    return setStatus(id, status, by, reason);
  }
  function reopen(id, by) { return setStatus(id, 'in-progress', by, 'reopened'); }
  function linkCase(ids, caseId, by) {
    const out = [];
    for (const id of ids) {
      const cur = must(id);
      let a = col.patch(id, (x) => { x.case_id = caseId || ''; x.updated = now(); hist(x, by, 'case', caseId || 'unlinked'); });
      if (caseId && cur.status === 'new') a = setStatus(id, 'in-progress', by, `case ${caseId}`);
      else changed(a, 'case');
      out.push(a);
    }
    return out;
  }

  const BULK_OPS = {
    ack: (id, args, by) => ack(id, by),
    assign: (id, args, by) => assign(id, args.assignee, by),
    note: (id, args, by) => note(id, args.text, by),
    status: (id, args, by) => setStatus(id, args.status, by, args.detail),
    close: (id, args, by) => close(id, args.reason, by, args.note),
    reopen: (id, args, by) => reopen(id, by),
  };
  function bulk(ids, op, args, by) {
    if (!Array.isArray(ids) || !ids.length) throw new WorkflowError(400, 'ids[] required');
    if (ids.length > 1000) throw new WorkflowError(400, 'at most 1000 ids per bulk operation');
    const fn = BULK_OPS[op];
    if (!fn) throw new WorkflowError(400, `unknown bulk op ${op} (${Object.keys(BULK_OPS).join(', ')})`);
    const results = [];
    for (const id of ids) {
      try { fn(id, args || {}, by); results.push({ id, ok: true }); } catch (e) { results.push({ id, ok: false, error: e.message }); }
    }
    return { ok: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, results };
  }

  // ---- queries
  function list(f = {}) {
    let statuses = f.status ? String(f.status).split(',').map((s) => s.trim()).filter(Boolean) : null;
    if (statuses && statuses.includes('all')) statuses = null;
    const sevMinRaw = f.min_severity !== undefined && f.min_severity !== '' ? f.min_severity : f.severity_min;
    const sevMin = sevMinRaw !== undefined && sevMinRaw !== '' && sevMinRaw !== null ? Number(sevMinRaw) : null;
    const unassigned = f.unassigned === true || f.unassigned === '1' || f.unassigned === 'true';
    const sevList = f.severity !== undefined && f.severity !== '' ? String(f.severity).split(',').map(Number) : null;
    const sources = f.source ? String(f.source).split(',') : null;
    const tparse = (v) => { if (!v) return null; const n = Number(v); const t = Number.isFinite(n) ? n : Date.parse(v); if (!Number.isFinite(t)) throw new WorkflowError(400, `invalid time "${v}"`); return t; };
    const from = tparse(f.from);
    const to = tparse(f.to);
    const q = f.q ? String(f.q).toLowerCase() : '';
    const items = col.all((a) => {
      if (statuses) {
        const ok = statuses.some((s) => (s === 'open' ? !isClosed(a.status) : s === 'closed' ? isClosed(a.status) : a.status === s));
        if (!ok) return false;
      }
      if (sources) { if (!sources.includes(a.source)) return false; } else if (a.source === 'logrhythm' && !f.include_lr) return false;
      if (sevMin !== null && a.severity < sevMin) return false;
      if (sevList && !sevList.includes(a.severity)) return false;
      if (f.rule_id && a.rule_id !== f.rule_id) return false;
      if (unassigned && a.assignee) return false;
      if (f.assignee !== undefined && f.assignee !== null && f.assignee !== '' && (a.assignee || '') !== (f.assignee === '-' ? '' : f.assignee)) return false;
      if (f.case_id && a.case_id !== f.case_id) return false;
      if (from && a.ts_last < from) return false;
      if (to && a.ts_first > to) return false;
      if (q) {
        const hay = `${a.id} ${a.rule_id} ${a.rule_name} ${a.summary} ${Object.values(a.group || {}).join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const sort = String(f.sort || '-ts_last');
    const desc = sort.startsWith('-');
    const key = sort.replace(/^[-+]/, '');
    const allowed = ['ts_last', 'ts_first', 'created', 'updated', 'severity', 'count', 'id'];
    const sk = allowed.includes(key) ? key : 'ts_last';
    items.sort((a, b) => {
      const x = a[sk], y = b[sk];
      const c = x < y ? -1 : x > y ? 1 : 0;
      return desc ? -c : c;
    });
    const limit = Math.max(1, Math.min(500, Number(f.limit) || 100));
    const offset = Math.max(0, Number(f.offset) || 0);
    return { total: items.length, items: items.slice(offset, offset + limit) };
  }

  return {
    raise, get: (id) => col.get(id), list, all: (fn) => col.all(fn),
    ack, assign, note, setStatus, close, reopen, linkCase, bulk,
    flushMirror,
    stats: () => Object.assign({}, st, { open: col.all((a) => !isClosed(a.status)).length, total: col.size(), mirror_queue: mirrorQ.size }),
    stop() { clearInterval(mirrorTimer); },
  };
}

module.exports = { createAlerts, WorkflowError, STATUSES, CLOSE_REASONS, TRANSITIONS, isClosed };
