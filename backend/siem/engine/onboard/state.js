// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Live state of a configured source for the Connect hub — pure functions, tested with fixtures.
//   sourceState({cfg, live, agg, relay, now, windowMs}) → {
//     id, type, kind, label, site, match_ip, state: 'receiving'|'silent'|'waiting', last_seen (ms|null), events_24h,
//     hosts[], token_set?, created_at, created_by }
//   receiving — an event (or relay batch) in the last `windowMs` (default 15 min)
//   silent    — events seen before (tracker since start, or ClickHouse in the last 24 h / ever) but none in the window
//   waiting   — never seen anything
//   live: collect/tracker.js summary row for the id   agg: {events_24h, last_ms, hosts[]} from ClickHouse (optional)
//   relay: api/routes.js relayList() row for relay sources (last_batch, events)
//   summarize(rows) → {receiving, silent, waiting, total}
//   collectAgg(ch, db, ids, now) → Map(src_id → {events_24h, last_ms, hosts}) — bounded read-only ClickHouse queries,
//   returns an empty map (and the error) when ClickHouse is unavailable; never throws.
const DEFAULT_WINDOW = 15 * 60000;
const DAY = 86400000;

function matchOf(cfg) {
  if (!cfg) return '';
  if (cfg.type === 'relay') return [].concat(cfg.allowed_peers || []).join(', ');
  const m = cfg.match || {};
  return [].concat(m.ip || []).concat([].concat(m.cidr || [])).join(', ');
}

function sourceState({ cfg, live, agg, relay, now = Date.now(), windowMs = DEFAULT_WINDOW, tokenSet } = {}) {
  const id = (cfg && cfg.id) || (live && live.src_id) || (agg && agg.src_id) || '';
  let last = 0;
  let everSeen = false;
  if (relay) { if (relay.last_batch) last = Math.max(last, relay.last_batch); if (relay.batches || relay.events) everSeen = true; }
  if (live) { if (live.last_seen) last = Math.max(last, live.last_seen); if (live.events_since_start) everSeen = true; }
  if (agg) { if (agg.last_ms) last = Math.max(last, agg.last_ms); if (agg.events_24h || agg.ever) everSeen = true; }
  if (last) everSeen = true;
  const state = last && now - last <= windowMs ? 'receiving' : everSeen ? 'silent' : 'waiting';
  const hosts = new Set();
  if (live) for (const h of live.hosts || []) if (h) hosts.add(h);
  if (agg) for (const h of agg.hosts || []) if (h) hosts.add(h);
  let events24 = agg && Number.isFinite(Number(agg.events_24h)) ? Number(agg.events_24h) : null;
  if (events24 === null && live) events24 = live.events_since_start || 0;
  if (events24 === null && relay) events24 = relay.events || 0;
  return {
    id, type: (cfg && cfg.type) || (live && live.src_type) || '', kind: (cfg && cfg.kind) || '', label: (cfg && cfg.label) || '', site: (cfg && cfg.site) || '',
    match_ip: matchOf(cfg), configured: !!cfg, state, last_seen: last || null, events_24h: events24 || 0, hosts: [...hosts].slice(0, 20),
    token_set: tokenSet === undefined ? undefined : !!tokenSet, created_at: (cfg && cfg.created_at) || null, created_by: (cfg && cfg.created_by) || null,
  };
}

function summarize(rows) {
  const s = { receiving: 0, silent: 0, waiting: 0, total: rows.length };
  for (const r of rows) s[r.state] = (s[r.state] || 0) + 1;
  return s;
}

async function collectAgg(ch, db, now = Date.now()) {
  const out = new Map();
  if (!ch || typeof ch.query !== 'function') return { agg: out, ok: false, error: 'no store' };
  const d = db || 'siem';
  try {
    const rows = await ch.query(
      `SELECT src_id, sum(events) AS events, max(minute) AS last_minute FROM ${d}.stats_minute WHERE minute >= now() - INTERVAL 24 HOUR GROUP BY src_id`,
      {}, { readonly: true, timeout_ms: 5000 });
    for (const r of rows) out.set(r.src_id, { src_id: r.src_id, events_24h: Number(r.events) || 0, last_ms: r.last_minute ? Date.parse(String(r.last_minute).replace(' ', 'T') + (String(r.last_minute).endsWith('Z') ? '' : 'Z')) || 0 : 0, hosts: [] });
    try {
      const older = await ch.query(`SELECT src_id, max(minute) AS last_minute FROM ${d}.stats_minute WHERE minute < now() - INTERVAL 24 HOUR GROUP BY src_id`, {}, { readonly: true, timeout_ms: 5000 });
      for (const r of older) {
        const cur = out.get(r.src_id) || { src_id: r.src_id, events_24h: 0, last_ms: 0, hosts: [] };
        cur.ever = true;
        if (!cur.last_ms && r.last_minute) cur.last_ms = Date.parse(String(r.last_minute).replace(' ', 'T') + 'Z') || 0;
        out.set(r.src_id, cur);
      }
    } catch { /* optional */ }
    try {
      const hosts = await ch.query(`SELECT src_id, groupUniqArray(10)(host) AS hosts FROM ${d}.events WHERE ts >= now() - INTERVAL 24 HOUR AND host != '' GROUP BY src_id`, {}, { readonly: true, timeout_ms: 8000, settings: { max_execution_time: 8 } });
      for (const r of hosts) { const cur = out.get(r.src_id); if (cur) cur.hosts = Array.isArray(r.hosts) ? r.hosts.slice(0, 10) : []; }
    } catch { /* hosts are optional */ }
    return { agg: out, ok: true, error: null };
  } catch (e) {
    return { agg: out, ok: false, error: e && e.message ? e.message : String(e) };
  }
}

// last N events of one source for POST /:id/test — only display fields, never `raw`, never `fields` (may hold secrets)
async function lastEvents(ch, db, srcId, limit = 3) {
  if (!ch || typeof ch.query !== 'function') return [];
  const d = db || 'siem';
  try {
    const rows = await ch.query(
      `SELECT ts, host, category, action, outcome, severity, event_code, substring(message, 1, 200) AS message FROM ${d}.events WHERE src_id = {src:String} ORDER BY ts DESC LIMIT {lim:UInt8}`,
      { src: { type: 'String', value: srcId }, lim: { type: 'UInt8', value: Math.max(1, Math.min(10, limit)) } }, { readonly: true, timeout_ms: 8000, settings: { max_execution_time: 8 } });
    return rows.map((r) => ({ ts: r.ts, host: r.host || '', category: r.category || '', action: r.action || '', outcome: r.outcome || '', severity: r.severity, event_code: r.event_code || '', message: r.message || '' }));
  } catch { return []; }
}

module.exports = { sourceState, summarize, collectAgg, lastEvents, matchOf, DEFAULT_WINDOW, DAY };
