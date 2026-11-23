// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Parallel-run comparison with LogRhythm.
 *
 * LogRhythm alarm IMPORT SHAPE (what engine/collect/lr.js — or POST /api/soc/lr/alarms — must deliver per alarm):
 *   {
 *     "alarm_id": 1234567,                         // LR AlarmId (required, unique)
 *     "alarm_rule_id": 1000123,                    // LR AIE rule / alarm rule id (optional)
 *     "alarm_rule_name": "AIE: Brute Force Attack",// required
 *     "alarm_date": "2026-09-29T10:15:00Z",        // ISO string or epoch ms (required) — when LR raised the alarm
 *     "first_event": "2026-09-29T10:10:02Z",       // optional: earliest event in the alarm (defaults to alarm_date)
 *     "last_event":  "2026-09-29T10:14:55Z",       // optional
 *     "priority": 75,                              // LR risk/priority 0-100 → severity (≥90:4, ≥70:3, ≥40:2, ≥20:1, else 0)
 *     "status": "New",                             // LR alarm status (kept for reference)
 *     "entity": "the organisation HQ",               // LR entity
 *     "log_source": "FW-HQ-01",                    // LR log source name  → alert.src_id
 *     "log_source_type": "Syslog - Fortinet FortiGate",
 *     "user": "alice", "src_ip": "203.0.113.7", "dst_ip": "", "host": "dc01",   // any known entities (optional)
 *     "event_count": 42,                           // optional
 *     "mitre": ["T1110"]                           // optional
 *   }
 * lrAlarmToPartial(alarm) converts it into an alerts.raise() partial with source 'logrhythm', rule_id 'LR-<rule id|name>',
 * group_key 'lr:<alarm_id>' (every LR alarm stays its own alert; re-import of the same alarm id merges).
 *
 * compare({ ours, lr, from, to, windowS = 900, ruleMap = {}, bucketS = 3600 })
 *   A LogRhythm alarm and one of our alerts are "the same detection" when their time spans (±windowS) overlap AND
 *   (ruleMap maps the LR rule name/id to our rule id  OR  they share an entity value: user / src_ip / dst_ip / host).
 *   ruleMap example (config.lr_rule_map): { "AIE: Brute Force Attack": "SENTRA-AUTH-001", "1000123": ["SENTRA-AUTH-001","SENTRA-LNX-001"] }
 *   → { totals:{ours, lr, both_ours, both_lr, only_ours, only_lr, overlap_pct}, lr_high:{total, matched, unmatched, pct, unmatched_ids[]}, by_rule[], by_lr_rule[], by_source[], by_bucket[],
 *       pairs[], only_ours_ids[], only_lr_ids[] }
 */

function toMs(v) {
  if (typeof v === 'number') return v;
  if (v === undefined || v === null || v === '') return 0;
  const n = Number(v);
  if (Number.isFinite(n)) return n;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : 0;
}

function prioToSeverity(p) {
  const n = Number(p) || 0;
  return n >= 90 ? 4 : n >= 70 ? 3 : n >= 40 ? 2 : n >= 20 ? 1 : 0;
}

function lrAlarmToPartial(al) {
  if (!al || al.alarm_id === undefined || al.alarm_id === null || al.alarm_id === '') throw new Error('LR alarm needs alarm_id');
  if (!al.alarm_rule_name) throw new Error('LR alarm needs alarm_rule_name');
  const at = toMs(al.alarm_date);
  if (!at) throw new Error('LR alarm needs a valid alarm_date');
  const first = toMs(al.first_event) || at;
  const last = toMs(al.last_event) || at;
  const group = {};
  for (const k of ['user', 'src_ip', 'dst_ip', 'host']) if (al[k]) group[k] = k.endsWith('ip') ? String(al[k]).trim() : String(al[k]).trim().toLowerCase();
  const ruleKey = al.alarm_rule_id !== undefined && al.alarm_rule_id !== null && al.alarm_rule_id !== '' ? String(al.alarm_rule_id) : String(al.alarm_rule_name);
  return {
    rule_id: `LR-${ruleKey}`, rule_name: String(al.alarm_rule_name), rule_type: 'logrhythm',
    severity: prioToSeverity(al.priority), mitre: Array.isArray(al.mitre) ? al.mitre.map(String) : [],
    group, group_key: `lr:${al.alarm_id}`, count: Math.max(1, Number(al.event_count) || 1),
    ts_first: Math.min(first, last, at), ts_last: Math.max(first, last),
    sample_event_ids: [], summary: `LogRhythm: ${al.alarm_rule_name}${Object.keys(group).length ? ` — ${Object.entries(group).map(([k, v]) => `${k}=${v}`).join(', ')}` : ''}`,
    fields: { lr_status: String(al.status || ''), lr_entity: String(al.entity || ''), lr_log_source_type: String(al.log_source_type || '') },
    source: 'logrhythm', src_id: String(al.log_source || ''), src_type: 'logrhythm', host: String(al.host || ''),
    lr_alarm_id: String(al.alarm_id), lr: { alarm_rule_id: al.alarm_rule_id !== undefined ? String(al.alarm_rule_id) : '', alarm_date: at, priority: Number(al.priority) || 0 },
    suppress_s: 0,
  };
}

const ENTITY_KEYS = ['user', 'target_user', 'src_ip', 'dst_ip', 'host'];
function entities(a) {
  const s = new Set();
  const bag = Object.assign({}, a.fields || {}, a.group || {});
  if (a.host) bag.host = a.host;
  for (const k of ENTITY_KEYS) { const v = bag[k]; if (v) s.add(`${k === 'target_user' ? 'user' : k}=${String(v).toLowerCase()}`); }
  return s;
}

function compare(o = {}) {
  const win = (o.windowS || 900) * 1000;
  const bucket = (o.bucketS || 3600) * 1000;
  const from = o.from || 0;
  const to = o.to || Date.now();
  const inRange = (a) => a.ts_last >= from && a.ts_first <= to;
  const ours = (o.ours || []).filter((a) => a.source !== 'logrhythm' && inRange(a));
  const lr = (o.lr || []).filter((a) => a.source === 'logrhythm' && inRange(a));
  const ruleMap = o.ruleMap || {};
  const mapped = (a) => {
    const keys = [a.rule_name, a.rule_id, a.rule_id.replace(/^LR-/, ''), a.lr && a.lr.alarm_rule_id].filter(Boolean);
    const out = new Set();
    for (const k of keys) { const m = ruleMap[k]; if (m) for (const r of Array.isArray(m) ? m : [m]) out.add(r); }
    return out;
  };

  const oursEnt = ours.map((a) => ({ a, ent: entities(a) }));
  const matchedOurs = new Set();
  const pairs = [];
  const onlyLr = [];
  for (const l of lr) {
    const lEnt = entities(l);
    const rules = mapped(l);
    let best = null;
    for (const { a, ent } of oursEnt) {
      if (a.ts_first > l.ts_last + win || a.ts_last < l.ts_first - win) continue;
      let via = '';
      if (rules.has(a.rule_id)) via = 'rule-map';
      else { for (const e of lEnt) if (ent.has(e)) { via = `entity:${e.split('=')[0]}`; break; } }
      if (!via) continue;
      const dt = Math.abs(a.ts_first - l.ts_first);
      const score = (via === 'rule-map' ? 0 : 1) * 1e15 + dt;
      if (!best || score < best.score) best = { a, via, dt, score };
    }
    if (best) { matchedOurs.add(best.a.id); pairs.push({ lr_id: l.id, lr_rule: l.rule_name, our_id: best.a.id, our_rule: best.a.rule_id, via: best.via, dt_ms: best.dt, l }); }
    else onlyLr.push(l);
  }
  const onlyOurs = ours.filter((a) => !matchedOurs.has(a.id));

  const byRule = new Map();
  for (const a of ours) {
    const r = byRule.get(a.rule_id) || { rule_id: a.rule_id, rule_name: a.rule_name, total: 0, matched_by_lr: 0, only_ours: 0 };
    r.total++; if (matchedOurs.has(a.id)) r.matched_by_lr++; else r.only_ours++;
    byRule.set(a.rule_id, r);
  }
  const byLrRule = new Map();
  const pairedLr = new Set(pairs.map((p) => p.lr_id));
  for (const l of lr) {
    const r = byLrRule.get(l.rule_name) || { lr_rule: l.rule_name, total: 0, matched_by_ours: 0, only_lr: 0, our_rules: {} };
    r.total++;
    if (pairedLr.has(l.id)) { r.matched_by_ours++; const p = pairs.find((x) => x.lr_id === l.id); r.our_rules[p.our_rule] = (r.our_rules[p.our_rule] || 0) + 1; } else r.only_lr++;
    byLrRule.set(l.rule_name, r);
  }
  const bySrc = new Map();
  const srcRow = (k) => { let r = bySrc.get(k); if (!r) { r = { source: k, ours: 0, lr: 0, both: 0 }; bySrc.set(k, r); } return r; };
  for (const a of ours) { const r = srcRow(a.src_id || a.src_type || 'unknown'); r.ours++; if (matchedOurs.has(a.id)) r.both++; }
  for (const l of lr) srcRow(l.src_id || 'unknown').lr++;
  const byBucket = new Map();
  const bRow = (t) => { const k = Math.floor(t / bucket) * bucket; let r = byBucket.get(k); if (!r) { r = { t: k, ours: 0, lr: 0, both: 0 }; byBucket.set(k, r); } return r; };
  for (const a of ours) { const r = bRow(a.ts_first); r.ours++; if (matchedOurs.has(a.id)) r.both++; }
  for (const l of lr) bRow(l.ts_first).lr++;

  const bothLr = pairs.length;
  // Exit criterion 3 (docs/PARALLEL-RUN.md): LR alarms of priority >= 70 (severity >= 3 when no priority was imported).
  const isHigh = (l) => ((l.lr && Number(l.lr.priority)) ? Number(l.lr.priority) >= 70 : Number(l.severity) >= 3);
  const high = lr.filter(isHigh);
  const highUn = high.filter((l) => !pairedLr.has(l.id));
  return {
    from, to, window_s: win / 1000,
    totals: {
      ours: ours.length, lr: lr.length, both_ours: matchedOurs.size, both_lr: bothLr,
      only_ours: onlyOurs.length, only_lr: onlyLr.length,
      overlap_pct: lr.length ? Math.round((bothLr / lr.length) * 1000) / 10 : null,
    },
    lr_high: {
      total: high.length, matched: high.length - highUn.length, unmatched: highUn.length,
      pct: high.length ? Math.round(((high.length - highUn.length) / high.length) * 1000) / 10 : null,
      unmatched_ids: highUn.slice(0, 1000).map((a) => a.id),
    },
    by_rule: [...byRule.values()].sort((a, b) => b.total - a.total),
    by_lr_rule: [...byLrRule.values()].sort((a, b) => b.total - a.total),
    by_source: [...bySrc.values()].sort((a, b) => b.ours + b.lr - (a.ours + a.lr)),
    by_bucket: [...byBucket.values()].sort((a, b) => a.t - b.t),
    pairs: pairs.slice(0, 500).map(({ l, ...p }) => p),
    only_ours_ids: onlyOurs.slice(0, 200).map((a) => a.id),
    only_lr_ids: onlyLr.slice(0, 1000).map((a) => a.id),
  };
}

/** Idempotent import: alarms already imported (same alarm_id) are skipped. → { imported, skipped, errors[] } */
function importAlarms(alertsApi, alarms) {
  const known = new Set(alertsApi.all((a) => a.source === 'logrhythm').map((a) => String(a.lr_alarm_id)));
  const out = { imported: 0, skipped: 0, errors: [] };
  for (const al of alarms || []) {
    try {
      const p = lrAlarmToPartial(al);
      if (known.has(p.lr_alarm_id)) { out.skipped++; continue; }
      alertsApi.raise(p);
      known.add(p.lr_alarm_id);
      out.imported++;
    } catch (e) { out.errors.push({ alarm_id: al && al.alarm_id, error: e.message }); }
  }
  return out;
}

module.exports = { lrAlarmToPartial, compare, prioToSeverity, importAlarms };
