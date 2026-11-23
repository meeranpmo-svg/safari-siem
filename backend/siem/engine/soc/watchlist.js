// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard } = require('../util/errors');
/*
 * SOC Performance & Operations - watchlists, asset criticality and the SOC's response times.
 *   watchlist    a host, IP, user, domain, file hash or CVE an analyst wants to hear about (with the reason, and an optional end
 *                date). Every 5 minutes the events since the last check are counted for each active entry; an appearance raises
 *                ONE alert per entry (rule soc-watchlist-hit, grouped on the entry, so later appearances merge into it). Open
 *                alerts already naming the entity are listed as its hits. A watched entity adds points to an alert's priority.
 *   criticality  a host or IP rated crown jewel or high (the reason recorded): an alert touching it gets more priority points
 *                (crown jewel +20, high +10), itemised in the priority explanation like every other factor (alert-ml.js).
 *   performance  over the last 30 days, from the alert records themselves: time to detect (first event -> alert raised), to
 *                acknowledge (raised -> first acknowledged) and to resolve (raised -> closed) - median and 90th percentile with the
 *                number of alerts each is computed from, per severity, and week by week. A figure with fewer than 3 alerts is
 *                withheld rather than shown as a trend.
 * Matching is exact and case-insensitive (a host also matches its name with the domain dropped); never a similar name.
 */
const DAY = 86400000, MIN = 60000;
const KINDS = ['host', 'ip', 'user', 'domain', 'hash', 'cve'];
const LEVELS = ['crown_jewel', 'high'];
const POINTS = { crown_jewel: 20, high: 10 };
const low = (s) => String(s == null ? '' : s).trim().toLowerCase();
const hk = (s) => low(s).split('.')[0];
const QF = { host: (v) => 'host:"' + v + '"', ip: (v) => 'ip:' + v, user: (v) => 'user:"' + v + '" OR target_user:"' + v + '"', domain: (v) => 'domain:"' + v + '" OR dns_query:"' + v + '" OR url:"' + v + '"', hash: (v) => 'hash:"' + v + '"', cve: (v) => '"' + v + '"' };

function valuesOf(a) { return [a.host, ...(a.group ? Object.values(a.group) : []), ...(a.fields ? Object.values(a.fields) : [])].filter((v) => v != null && v !== '').map((v) => String(v)); }
function matches(a, kind, value) {
  const v = low(value), vals = valuesOf(a);
  if (kind === 'cve') return vals.some((x) => low(x).includes(v)) || low(a.summary).includes(v);
  return vals.some((x) => low(x) === v || (kind === 'host' && hk(x) === v));
}
function pct(arr, p) { if (!arr.length) return null; const s = arr.slice().sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]; }

function createWatchlist(deps = {}) {
  const { state, alerts } = deps, now = deps.now || Date.now, L = deps.log || { info() {}, warn() {} };
  const W = state.collection('soc_watchlist'), C = state.collection('soc_criticality'), S = state.collection('soc_watch_state');
  let timer = null;
  const active = (w, t) => !w.until || w.until > t;
  const err = (status, msg) => Object.assign(new Error(msg), { status });
  const nextId = (col, p) => p + '-' + String(col.all().reduce((m, x) => { const n = Number(String(x.id).split('-')[1]); return n > m ? n : m; }, 0) + 1).padStart(5, '0');

  // ---- watchlist
  function add(b, who) {
    const t = now(), v = low(b.value);
    if (W.all((w) => w.kind === b.kind && low(w.value) === v && active(w, t)).length) throw err(409, b.kind + ' ' + b.value + ' is already on the watchlist');
    if (W.all((w) => active(w, t)).length >= 200) throw err(409, 'the watchlist holds 200 entries - remove one first');
    const rec = { id: nextId(W, 'WL'), kind: b.kind, value: String(b.value).trim(), reason: b.reason, until: b.days ? t + b.days * DAY : null, by: who.user, at: t };
    W.put(rec); return rec;
  }
  function remove(id, reason, who) { const w = W.get(id); if (!w) throw err(404, 'no watchlist entry ' + id); W.remove(id); return { removed: id, kind: w.kind, value: w.value, by: who.user, reason }; }
  function list() {
    const t = now(), open = alerts.all((a) => !/^closed/.test(String(a.status || '')));
    return W.all().sort((a, b) => b.at - a.at).map((w) => {
      const hits = open.filter((a) => matches(a, w.kind, w.value)).sort((a, b) => (b.ts_last || 0) - (a.ts_last || 0));
      const st = S.get(w.id) || {};
      return Object.assign({}, w, { active: active(w, t), expired: !active(w, t), open_alerts: hits.length, worst: hits.reduce((m, a) => Math.max(m, a.severity || 0), 0),
        hits: hits.slice(0, 10).map((a) => ({ id: a.id, rule_name: a.rule_name, severity: a.severity, ts_last: a.ts_last })), last_check: st.at || null, last_seen_events: st.last_count || 0, last_appearance: st.last_hit || null });
    });
  }
  function watchedFor(entity) { const t = now(), e = low(String(entity).replace(/^(user|host|ip|domain):/, '')); return W.all((w) => active(w, t) && (low(w.value) === e || (w.kind === 'host' && hk(e) === low(w.value)))).map((w) => w.id); }
  // every 5 min: count the events naming each active entry since its last check; an appearance raises one grouped alert
  async function check() {
    if (!deps.search || typeof deps.search.histogram !== 'function') return { checked: 0, note: 'the event store is not available' };
    const t = now(); let checked = 0, raised = 0;
    for (const w of W.all((x) => active(x, t))) {
      const st = S.get(w.id) || { id: w.id }, from = Math.max(st.at || w.at, t - 6 * 3600000);
      try {
        const h = await deps.search.histogram({ q: QF[w.kind](w.value.replace(/"/g, '')), from, to: t, buckets: 1 }), n = h.buckets.reduce((s, b) => s + b.n, 0);
        checked++; st.at = t; st.last_count = n;
        if (n > 0) {
          st.last_hit = t; raised++;
          alerts.raise({ rule_id: 'soc-watchlist-hit', rule_name: 'Watched ' + w.kind + ' seen: ' + w.value, severity: 3, group: { watch: w.kind + ':' + w.value }, fields: { watch_id: w.id, events: String(n) },
            summary: n + ' event(s) naming watched ' + w.kind + ' ' + w.value + ' since ' + new Date(from).toISOString() + ' - on the watchlist because: ' + String(w.reason).slice(0, 200), ts_first: from, ts_last: t, count: n, source: 'engine', suppress_s: 6 * 3600 });
        }
        S.put(st);
      } catch (e) { L.warn('soc watchlist: check failed', { id: w.id, err: e.message }); }
    }
    return { checked, raised };
  }
  function start() { if (timer) return; timer = setInterval(guard('soc.watchlist.check', () => check()), 5 * MIN); if (timer.unref) timer.unref(); }

  // ---- asset criticality
  function rate(b, who) {
    const v = low(b.value), ex = C.all((c) => low(c.value) === v)[0], t = now();
    const rec = { id: ex ? ex.id : nextId(C, 'AC'), value: String(b.value).trim(), level: b.level, reason: b.reason, by: who.user, at: t };
    C.put(rec); return Object.assign({ replaced: ex ? ex.level : null }, rec);
  }
  function unrate(id, who) { const c = C.get(id); if (!c) throw err(404, 'no criticality entry ' + id); C.remove(id); return { removed: id, value: c.value, level: c.level, by: who.user }; }
  function criticality() { return C.all().sort((a, b) => (a.level === b.level ? String(a.value).localeCompare(String(b.value)) : a.level === 'crown_jewel' ? -1 : 1)); }
  function criticalFor(entity) { const e = low(String(entity).replace(/^(user|host|ip|xip):/, '')); const c = C.all((x) => low(x.value) === e || hk(e) === low(x.value))[0]; return c ? { level: c.level, value: c.value, points: POINTS[c.level] } : null; }

  // ---- response times
  function performance() {
    const t = now(), from = t - 30 * DAY, A = alerts.all((a) => (a.created || 0) >= from), mins = (x) => Math.round(x / MIN);
    const stat = (L0) => { const det = L0.filter((a) => a.ts_first && a.created >= a.ts_first).map((a) => a.created - a.ts_first), ack = L0.filter((a) => a.ack_at > 0).map((a) => a.ack_at - a.created), res = L0.filter((a) => a.closed_at > 0).map((a) => a.closed_at - a.created);
      const f = (arr) => (arr.length >= 3 ? { median_min: mins(pct(arr, 0.5)), p90_min: mins(pct(arr, 0.9)), n: arr.length } : { median_min: null, p90_min: null, n: arr.length, withheld: 'fewer than 3 alerts' });
      return { raised: L0.length, detect: f(det), acknowledge: f(ack), resolve: f(res) }; };
    const weeks = []; for (let w = 3; w >= 0; w--) { const a = t - (w + 1) * 7 * DAY, b = t - w * 7 * DAY; weeks.push(Object.assign({ from: a, to: b }, stat(A.filter((x) => x.created > a && x.created <= b)))); }
    const bySev = [4, 3, 2, 1, 0].map((s) => Object.assign({ severity: s }, stat(A.filter((x) => (x.severity || 0) === s))));
    const open = alerts.all((a) => !/^closed/.test(String(a.status || ''))), unacked = open.filter((a) => !(a.ack_at > 0));
    return { at: t, days: 30, overall: stat(A), by_severity: bySev, weeks, open: open.length, unacknowledged: unacked.length, oldest_unacked_min: unacked.length ? mins(t - Math.min(...unacked.map((a) => a.created || t))) : null };
  }
  return { add, remove, list, check, start, rate, unrate, criticality, criticalFor, watchedFor, performance, KINDS, LEVELS };
}

module.exports = { createWatchlist, matches, KINDS, LEVELS, POINTS };
