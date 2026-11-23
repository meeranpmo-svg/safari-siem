// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Database audit / health module (Oracle) — docs/ORACLE.md.
 *
 *   registerParsers(parserModule = require('../parse')) → ['oracle-health', 'oracle-audit']
 *     Adds the two source types to the parser router's BY_TYPE table at runtime (no edit of engine/parse/index.js).
 *     Equivalent one-line router edit, if preferred:  BY_TYPE['oracle-health'] = require('../db-audit/oracle-health');
 *     BY_TYPE['oracle-audit'] = require('../db-audit/oracle-audit');  (+ push them on JSON_ORDER / TEXT_ORDER for sniffing).
 *
 *   createOracleSummary({ ch, alerts, log, now, windowH = 24, staleS = 300 })
 *     → { stage(ev), summary({hours}) → Promise<view>, instance(key) → Promise<inst|null>, stats() }
 *     stage()  — pipeline stage: remembers the latest sample per instance / kind / key in memory (fresh data between
 *                ClickHouse flushes and when ClickHouse is down).
 *     summary() — ClickHouse argMax-per-(host, instance, action, key) over the last `hours` (siem.events) merged with the
 *                in-memory latest (newest wins) + failed logons (24 h) + open SENTRA-ORA-* alerts → the view the portal
 *                module ui/as-oracle-module.js renders (shape documented in routes.js).
 */
const health = require('./oracle-health');
const audit = require('./oracle-audit');

const TYPES = ['oracle-health', 'oracle-audit'];
const SINGLE = new Set(['health-sample', 'instance-down', 'session-count', 'redo-status', 'backup-status', 'invalid-objects', 'fra-usage', 'alertlog-tail', 'agent-heartbeat']);
const MULTI = new Set(['tablespace-usage', 'blocked-session', 'wait-class', 'dataguard-lag', 'top-sql', 'listener-status', 'listener-down']);

function registerParsers(parserModule) {
  const pm = parserModule || require('../parse');
  if (!pm || !pm.BY_TYPE) return [];
  pm.BY_TYPE['oracle-health'] = health;
  pm.BY_TYPE['oracle-audit'] = audit;
  if (pm.parsers) { pm.parsers['oracle-health'] = health; pm.parsers['oracle-audit'] = audit; }
  return TYPES.slice();
}

function chTs(v) { if (typeof v === 'number') return v; const t = Date.parse(String(v).replace(' ', 'T') + (/[Zz]|[+-]\d\d:?\d\d$/.test(String(v)) ? '' : 'Z')); return Number.isFinite(t) ? t : 0; }
function num(v) { const n = parseFloat(v); return Number.isFinite(n) ? n : null; }

function createOracleSummary({ ch, alerts, log, now = Date.now, windowH = 24, staleS = 300, table = 'siem.events', state = null } = {}) {
  // removed instances (an old test database, the same database under a second host name): hidden until a NEW reading arrives
  const hidden = state ? state.collection('oracle_hidden') : null;
  const mem = new Map(); // key → { host, instance, db_name, last_seen, single: {action → rec}, multi: {action → Map(key → rec)}, failed: [ts…] }
  const st = { staged: 0, instances: 0, ch_queries: 0, ch_errors: 0, last_ch_error: '' };
  const keyOf = (host, inst) => `${String(host || '').toLowerCase()}|${String(inst || '').toUpperCase()}`;

  function rec(ev) {
    return { action: ev.action, key: (ev.fields && ev.fields.key) || '', ts: ev.ts || now(), outcome: ev.outcome, severity: ev.severity || 0, message: ev.message || '', f: Object.assign({}, ev.fields || {}) };
  }
  function slot(host, inst, db) {
    const k = keyOf(host, inst);
    let s = mem.get(k);
    if (!s) { s = { key: k, host: String(host || ''), instance: String(inst || '').toUpperCase(), db_name: String(db || inst || '').toUpperCase(), last_seen: 0, single: {}, multi: {}, failed: [] }; mem.set(k, s); if (mem.size > 500) mem.delete(mem.keys().next().value); }
    return s;
  }
  function stage(ev) {
    if (!ev || !ev.tags || ev.tags.indexOf('oracle') < 0) return;
    const f = ev.fields || {};
    if (ev.action === 'logon-failed') {
      if (!f.instance && !ev.host) return;
      const s = slot(ev.host, f.instance, f.db_name);
      s.failed.push(ev.ts || now());
      const cut = now() - 86400000;
      while (s.failed.length && s.failed[0] < cut) s.failed.shift();
      if (s.failed.length > 10000) s.failed.splice(0, s.failed.length - 10000);
      s.last_failed = ev.ts || now();
      return;
    }
    if (ev.src_type !== 'oracle-health') return;
    if (ev.tags.indexOf('db-perf') >= 0) return; // performance kinds: kept by perf-api.js (createOraclePerf), not the health view
    st.staged++;
    const s = slot(ev.host, f.instance, f.db_name);
    const r = rec(ev);
    if (r.ts > s.last_seen) s.last_seen = r.ts;
    if (MULTI.has(ev.action)) { const m = s.multi[ev.action] || (s.multi[ev.action] = new Map()); m.set(r.key, r); if (m.size > 200) m.delete(m.keys().next().value); }
    else s.single[ev.action] = r;
    if (ev.action === 'instance-down') delete s.single['health-sample']; else if (ev.action === 'health-sample') delete s.single['instance-down'];
    if (ev.action === 'listener-down' || ev.action === 'listener-status') { const other = ev.action === 'listener-down' ? 'listener-status' : 'listener-down'; if (s.multi[other]) s.multi[other].delete(r.key); }
  }

  async function fromClickHouse(hours) {
    const out = new Map();
    if (!ch || typeof ch.query !== 'function') return { map: out, ok: false, error: 'clickhouse not configured' };
    const h = Math.max(1, Math.min(24 * 30, Number(hours) || windowH));
    try {
      st.ch_queries++;
      const rows = await ch.query(
        `SELECT host, fields['instance'] AS instance, fields['db_name'] AS db_name, action, fields['key'] AS k, max(ts) AS ts_s,
                argMax(fields, ts) AS f, argMax(outcome, ts) AS outcome, argMax(severity, ts) AS severity, argMax(message, ts) AS message
           FROM ${table}
          WHERE src_type = 'oracle-health' AND action != 'logon-failed' AND NOT has(tags, 'db-perf') AND ts >= now() - INTERVAL {h:UInt32} HOUR
          GROUP BY host, instance, db_name, action, k`, { h: { type: 'UInt32', value: h } });
      for (const r of rows || []) {
        const key = keyOf(r.host, r.instance);
        let s = out.get(key);
        if (!s) { s = { key, host: r.host || '', instance: String(r.instance || '').toUpperCase(), db_name: String(r.db_name || r.instance || '').toUpperCase(), last_seen: 0, single: {}, multi: {}, failed: [] }; out.set(key, s); }
        const x = { action: r.action, key: r.k || '', ts: chTs(r.ts_s), outcome: r.outcome, severity: Number(r.severity) || 0, message: r.message || '', f: r.f && typeof r.f === 'object' ? r.f : {} };
        if (x.ts > s.last_seen) s.last_seen = x.ts;
        if (MULTI.has(r.action)) { const m = s.multi[r.action] || (s.multi[r.action] = new Map()); m.set(x.key, x); } else s.single[r.action] = x;
      }
      const fl = await ch.query(
        `SELECT host, fields['instance'] AS instance, count() AS n, max(ts) AS last FROM ${table}
          WHERE action = 'logon-failed' AND has(tags, 'oracle') AND ts >= now() - INTERVAL 24 HOUR GROUP BY host, instance`, {});
      for (const r of fl || []) {
        const key = keyOf(r.host, r.instance);
        const s = out.get(key) || (out.set(key, { key, host: r.host || '', instance: String(r.instance || '').toUpperCase(), db_name: String(r.instance || '').toUpperCase(), last_seen: 0, single: {}, multi: {}, failed: [] }), out.get(key));
        s.failed_ch = Number(r.n) || 0; s.last_failed_ch = chTs(r.last);
      }
      return { map: out, ok: true, error: '' };
    } catch (e) {
      st.ch_errors++; st.last_ch_error = e.message;
      if (log) log.warn('oracle summary: ClickHouse query failed — serving in-memory data only', { err: e.message });
      return { map: out, ok: false, error: e.message };
    }
  }

  function mergeInto(base, s) {
    // in-memory recs win when newer
    const t = base.get(s.key) || (base.set(s.key, { key: s.key, host: s.host, instance: s.instance, db_name: s.db_name, last_seen: 0, single: {}, multi: {}, failed: [] }), base.get(s.key));
    if (s.last_seen > t.last_seen) t.last_seen = s.last_seen;
    for (const [a, r] of Object.entries(s.single)) if (!t.single[a] || r.ts >= t.single[a].ts) t.single[a] = r;
    for (const [a, m] of Object.entries(s.multi)) { const tm = t.multi[a] || (t.multi[a] = new Map()); for (const [k, r] of m) if (!tm.has(k) || r.ts >= tm.get(k).ts) tm.set(k, r); }
    t.failed = s.failed; t.last_failed = s.last_failed;
    if (s.failed_ch !== undefined) { t.failed_ch = s.failed_ch; t.last_failed_ch = s.last_failed_ch; }
  }

  function view(s, t) {
    const latest = (a) => s.single[a] || null;
    const list = (a) => (s.multi[a] ? [...s.multi[a].values()] : []);
    const hs = latest('health-sample'); const down = latest('instance-down');
    const inst = down && (!hs || down.ts >= hs.ts) ? down : hs;
    const f = (inst && inst.f) || {};
    const issues = [];
    const sev = (x) => (x ? Number(x.severity) || 0 : 0);
    let worst = 0;
    const note = (x, text) => { if (x && sev(x) >= 2) { issues.push({ severity: sev(x), text: text || x.message, action: x.action, ts: x.ts }); } worst = Math.max(worst, sev(x)); };
    note(inst);
    const tbs = list('tablespace-usage').map((r) => ({ name: r.key || r.f.name || '', used_pct: num(r.f.used_pct), used_mb: num(r.f.used_mb), max_mb: num(r.f.max_mb), autoextend: r.f.autoextend || '', severity: sev(r), ts: r.ts })).sort((a, b) => (b.used_pct || 0) - (a.used_pct || 0));
    for (const r of list('tablespace-usage')) note(r);
    const sess = latest('session-count'); note(sess);
    const blocked = list('blocked-session').filter((r) => t - r.ts < 3600000).map((r) => ({ sid: r.key, user: r.f.user || '', blocking_sid: r.f.blocking_sid || '', blocking_user: r.f.blocking_user || '', wait_s: num(r.f.wait_s), event: r.f.event || '', sql_id: r.f.sql_id || '', ts: r.ts }));
    const waits = list('wait-class').map((r) => ({ class: r.key, pct: num(r.f.pct), time_waited_s: num(r.f.time_waited_s), rank: num(r.f.rank) })).sort((a, b) => (a.rank || 99) - (b.rank || 99)).slice(0, 5);
    const bk = latest('backup-status'); note(bk);
    const dg = list('dataguard-lag')[0] || null; note(dg);
    const redo = latest('redo-status'); note(redo);
    const fra = latest('fra-usage'); note(fra);
    const inv = latest('invalid-objects'); note(inv);
    const ls = list('listener-down').concat(list('listener-status')).sort((a, b) => b.ts - a.ts)[0] || null; note(ls);
    const al = latest('alertlog-tail'); note(al);
    const hb = latest('agent-heartbeat');
    const failed24 = s.failed_ch !== undefined ? Math.max(s.failed_ch, s.failed.length) : s.failed.length;
    if (failed24 >= 10) { issues.push({ severity: 2, text: `${failed24} failed logons in 24 h`, action: 'logon-failed', ts: s.last_failed || s.last_failed_ch || 0 }); worst = Math.max(worst, 2); }
    const stale = !s.last_seen || t - s.last_seen > staleS * 1000;
    if (stale) { issues.push({ severity: 2, text: s.last_seen ? `no sample for ${Math.round((t - s.last_seen) / 60000)} min` : 'no health sample yet', action: 'stale', ts: s.last_seen }); worst = Math.max(worst, 2); }
    return {
      key: s.key, host: s.host, instance: s.instance, db_name: f.db_name || s.db_name, version: f.version || '', status: inst ? (f.status || (inst.action === 'instance-down' ? 'DOWN' : 'OPEN')) : 'UNKNOWN',
      // up only on a health sample, down only on an explicit instance-down reading; no status reading = unknown, never "down"
      up: !!inst && inst.action === 'health-sample', state: !inst ? 'unknown' : inst.action === 'instance-down' ? 'down' : 'up', open_mode: f.open_mode || '', role: f.role || '', log_mode: f.log_mode || '', uptime_s: num(f.uptime_s), last_seen: s.last_seen, stale,
      tablespaces: tbs,
      sessions: sess ? { total: num(sess.f.total), active: num(sess.f.active), blocked: num(sess.f.blocked), max_sessions: num(sess.f.max_sessions), processes: num(sess.f.processes), max_processes: num(sess.f.max_processes), ts: sess.ts } : null,
      blocked_sessions: blocked, waits,
      backup: bk ? { status: bk.f.status || '', input_type: bk.f.input_type || '', age_h: num(bk.f.age_h), end_time: bk.f.end_time || '', output_mb: num(bk.f.output_mb), outcome: bk.outcome, severity: sev(bk), ts: bk.ts } : null,
      dataguard: dg ? { role: dg.key, apply_lag_s: num(dg.f.apply_lag_s), transport_lag_s: num(dg.f.transport_lag_s), protection_mode: dg.f.protection_mode || '', severity: sev(dg), ts: dg.ts } : null,
      redo: redo ? { log_mode: redo.f.log_mode || '', archive_lag_s: num(redo.f.archive_lag_s), unarchived: num(redo.f.unarchived), switches_1h: num(redo.f.redo_switches_1h), severity: sev(redo) } : null,
      fra: fra ? { used_pct: num(fra.f.used_pct), space_used_mb: num(fra.f.space_used_mb), space_limit_mb: num(fra.f.space_limit_mb), reclaimable_mb: num(fra.f.reclaimable_mb), severity: sev(fra) } : null,
      invalid_objects: inv ? num(inv.f.count) : null,
      listener: ls ? { name: ls.key, status: ls.f.status || '', up: ls.action === 'listener-status', services: num(ls.f.services), ts: ls.ts } : null,
      alertlog: al ? { path: al.f.path || '', ora_errors: num(al.f.ora_errors), tail: (al.f.tail || '').split('\n').slice(-5), ts: al.ts } : null,
      top_sql: list('top-sql').map((r) => ({ sql_id: r.key, elapsed_s: num(r.f.elapsed_s), executions: num(r.f.executions), user: r.f.user || '', sql_text: r.f.sql_text || '' })).sort((a, b) => (b.elapsed_s || 0) - (a.elapsed_s || 0)).slice(0, 10),
      failed_logons_24h: failed24, failed_logons_last: s.last_failed || s.last_failed_ch || 0,
      collector: hb ? { version: hb.f.version || '', last: hb.ts, queries_failed: num(hb.f.queries_failed), last_error: hb.f.last_error || '' } : null,
      worst_severity: worst, issues: issues.sort((a, b) => b.severity - a.severity),
    };
  }

  function openAlerts() {
    if (!alerts || typeof alerts.all !== 'function') return [];
    return alerts.all((a) => /^SENTRA-ORA-/.test(a.rule_id || '') && !/^closed-/.test(a.status || ''))
      .sort((a, b) => (b.severity - a.severity) || ((b.ts_last || 0) - (a.ts_last || 0))).slice(0, 100)
      .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, count: a.count, ts_last: a.ts_last, summary: a.summary, host: a.host || (a.group && a.group.host) || '', instance: (a.group && a.group['fields.instance']) || (a.fields && a.fields.instance) || '' }));
  }

  async function summary(q = {}) {
    const t = now();
    const hours = Math.max(1, Math.min(24 * 30, Number(q.hours) || windowH));
    const chr = await fromClickHouse(hours);
    const base = chr.map;
    for (const s of mem.values()) mergeInto(base, s);
    let removed = 0;
    const instances = [...base.values()].map((s) => view(s, t)).filter((i) => {
      const h = hidden && hidden.get(i.key);
      if (!h) return true;
      if ((i.last_seen || 0) > h.at + 60000) { i.returned = { at: h.at, by: h.by, reason: h.reason }; return true; }   // it reports again: shown, flagged
      removed++; return !!q.include_removed;
    }).sort((a, b) => (b.worst_severity - a.worst_severity) || a.key.localeCompare(b.key));
    const al = openAlerts();
    for (const i of instances) i.open_alerts = al.filter((a) => (a.instance && a.instance === i.instance) || (!a.instance && a.host && a.host.toLowerCase() === i.host.toLowerCase())).length;
    st.instances = instances.length;
    return {
      generated_at: new Date(t).toISOString(), window_h: hours, stale_after_s: staleS,
      clickhouse: { ok: chr.ok, error: chr.error || '' },
      totals: { removed, instances: instances.length, down: instances.filter((i) => i.state === 'down').length, unknown: instances.filter((i) => i.state === 'unknown').length, stale: instances.filter((i) => i.stale).length, with_issues: instances.filter((i) => i.issues.length).length, open_alerts: al.length, failed_logons_24h: instances.reduce((n, i) => n + (i.failed_logons_24h || 0), 0), blocked_sessions: instances.reduce((n, i) => n + i.blocked_sessions.length, 0) },
      instances, alerts: al,
    };
  }
  /** remove an instance from every database page (kept in the audit; reappears flagged if it reports again) */
  function forget(key, by, reason) {
    if (!hidden) throw Object.assign(new Error('needs the engine state store'), { code: 503 });
    const k = String(key || ''); const m = /^([^|]{1,253})\|([A-Za-z0-9_$#.-]{1,64})$/.exec(k);
    if (!m) throw Object.assign(new Error('key must be host|INSTANCE as listed'), { code: 400 });
    if (String(reason || '').trim().length < 3) throw Object.assign(new Error('say why (reason)'), { code: 400 });
    const key2 = `${m[1].toLowerCase()}|${m[2].toUpperCase()}`;
    hidden.put({ id: key2, at: now(), by: by || '', reason: String(reason).trim().slice(0, 200) });
    return hidden.get(key2);
  }
  function unforget(key) { if (hidden) hidden.remove(String(key || '')); return true; }
  function forgotten() { return hidden ? hidden.all().sort((a, b) => b.at - a.at) : []; }
  function isHidden(key, lastSeen) { const h = hidden && hidden.get(key); return !!h && !((lastSeen || 0) > h.at + 60000); }
  async function instance(key, q) { const v = await summary(q); return v.instances.find((i) => i.key === key || i.instance === String(key).toUpperCase()) || null; }

  return { stage, summary, instance, forget, unforget, forgotten, isHidden, stats: () => Object.assign({}, st, { memory_instances: mem.size }), TYPES };
}

// performance monitoring (docs/ORACLE.md section 4): createOraclePerf({ch, alerts, log, now}) → {stage, perf, topsql, sessions, capacity, stats}
const { createOraclePerf } = require('./perf-api');

module.exports = { registerParsers, createOracleSummary, createOraclePerf, parsers: { 'oracle-health': health, 'oracle-audit': audit }, TYPES };
