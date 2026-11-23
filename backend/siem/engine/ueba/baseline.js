// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA baselines — robust per-entity behavioural profiles.
 *
 * Two paths produce the SAME per-entity aggregate:
 *   - production : ClickHouse aggregates events into per-entity-per-day feature rows (engine/ueba/sql.js), the engine
 *                  feeds those rows to computeBaseline().
 *   - tests      : buildAggregates() aggregates synthetic events in Node, then computeBaseline().
 *
 * Robust statistics (median + MAD, p95) so one spike cannot poison a baseline, plus an EWMA so baselines track gradual
 * change. Standard library only; no ClickHouse dependency in this file.
 *
 *   median(a), quantile(a,p), mad(a), robustZ(x, med, mad, floor), ewma(series, alpha)
 *   buildAggregates(events, { identifier, tzOffsetMin }) → Map entityId → aggregate
 *   computeBaseline(aggregate, settings) → baseline object (explainable; arrays, not Sets)
 *   observedWindow(events, { identifier, tzOffsetMin }) → Map entityId → current-window summary
 */

const { geoOf, subnetsOf } = require('./geo');

// actions / signals that count as privileged / admin activity
const PRIV_ACTIONS = new Set([
  'privileges-assigned', 'role-assigned', 'group-member-added', 'group-member-removed', 'user-created', 'user-deleted',
  'user-enabled', 'user-disabled', 'password-reset', 'sudo', 'su', 'audit-log-cleared', 'audit-disabled',
  'service-installed', 'scheduled-task-created', 'mailbox-permission-added', 'sendas-permission-added',
  'transport-rule-created', 'mail-forwarding-set', 'mailbox-export',
]);
const BYTE_FIELDS = ['bytes', 'bytes_out', 'sc_bytes', 'size_bytes', 'total_bytes', 'sent_bytes', 'out_bytes'];
// fields that identify an API / OAuth scope / application an (AI-)agent or service account is exercising
const SCOPE_FIELDS = ['scope', 'scopes', 'operation', 'app_id', 'appid', 'app', 'client_id', 'api', 'permission'];
const DAY_MS = 86400000;

function scopesOf(ev) {
  const f = ev.fields || {};
  const out = [];
  for (const k of SCOPE_FIELDS) { const v = f[k]; if (v) out.push(`${k}=${String(v).toLowerCase()}`); }
  return out;
}

// ---------- robust stats ----------
function sortedNums(a) { return a.filter((x) => Number.isFinite(x)).slice().sort((x, y) => x - y); }
function median(a) {
  const s = sortedNums(a);
  if (!s.length) return 0;
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
function quantile(a, p) {
  const s = sortedNums(a);
  if (!s.length) return 0;
  if (s.length === 1) return s[0];
  const idx = Math.min(s.length - 1, Math.max(0, p * (s.length - 1)));
  const lo = Math.floor(idx), hi = Math.ceil(idx);
  return lo === hi ? s[lo] : s[lo] + (s[hi] - s[lo]) * (idx - lo);
}
function mean(a) { const s = sortedNums(a); return s.length ? s.reduce((x, y) => x + y, 0) / s.length : 0; }
// Median Absolute Deviation, scaled to be a robust sigma estimate (×1.4826).
function mad(a) {
  const s = sortedNums(a);
  if (!s.length) return 0;
  const med = median(s);
  const dev = s.map((x) => Math.abs(x - med));
  return median(dev) * 1.4826;
}
// robust z-score with a floor so a near-zero MAD / tiny baseline cannot explode the score.
function robustZ(x, med, madv, floor = 1) {
  const scale = Math.max(madv, floor);
  return (x - med) / scale;
}
function ewma(series, alpha = 0.3) {
  if (!series.length) return 0;
  let v = series[0];
  for (let i = 1; i < series.length; i++) v = alpha * series[i] + (1 - alpha) * v;
  return v;
}

function localHour(ms, tzOffsetMin) { return Math.floor(((ms + tzOffsetMin * 60000) % DAY_MS) / 3600000 + 24) % 24; }
function localDayKey(ms, tzOffsetMin) { return Math.floor((ms + tzOffsetMin * 60000) / DAY_MS); }

function egressBytes(ev) {
  const f = ev.fields || {};
  let sum = 0;
  for (const k of BYTE_FIELDS) { const n = Number(f[k]); if (Number.isFinite(n) && n > 0) sum += n; }
  return sum;
}
function isPrivileged(ev) {
  if (PRIV_ACTIONS.has(ev.action)) return true;
  if (Array.isArray(ev.tags) && ev.tags.includes('admin')) return true;
  return false;
}
function logonTypeOf(ev) {
  const f = ev.fields || {};
  return String(f.logon_type_name || f.logon_type || '').toLowerCase();
}
function serviceOf(ev) {
  if (ev.dst_port) return `${ev.proto || 'tcp'}/${ev.dst_port}`;
  return '';
}

function addCapped(set, v, cap) { if (v && set.size < cap) set.add(v); }

/** Group events by entity (actor + host) into rich aggregates. */
function buildAggregates(events, { identifier, tzOffsetMin = 180, maxSet = 512 } = {}) {
  const out = new Map();
  for (const ev of events) {
    const ents = identifier.entitiesOf(ev);
    if (!ents.length) continue;
    const g = geoOf(ev);
    const ts = ev.ts || ev.rts || 0;
    const day = localDayKey(ts, tzOffsetMin);
    const hour = localHour(ts, tzOffsetMin);
    const authFail = ev.category === 'authentication' && (ev.outcome === 'failure' || ev.action === 'logon-failed');
    const authSucc = ev.category === 'authentication' && ev.outcome === 'success';
    const bytes = egressBytes(ev);
    const priv = isPrivileged(ev);
    for (const ent of ents) {
      let a = out.get(ent.id);
      if (!a) {
        a = {
          id: ent.id, type: ent.type, name: ent.name, role_host: ent.role === 'host',
          first_seen: ts, last_seen: ts, tags: new Set(),
          days: new Map(), hourHist: new Array(24).fill(0),
          sets: { countries: new Set(), subnets: new Set(), ips: new Set(), hosts: new Set(), services: new Set(), processes: new Set(), logon_types: new Set(), api_scopes: new Set() },
          action_types: new Set(), targets: new Set(), hourBuckets: new Map(),
        };
        out.set(ent.id, a);
      }
      if (ts && ts < a.first_seen) a.first_seen = ts;
      if (ts > a.last_seen) a.last_seen = ts;
      if (Array.isArray(ev.tags)) for (const t of ev.tags) if (t === 'admin') a.tags.add(t);
      a.hourHist[hour]++;
      let d = a.days.get(day);
      if (!d) { d = { events: 0, auth_fail: 0, auth_success: 0, egress_bytes: 0, privileged: 0, hosts: new Set() }; a.days.set(day, d); }
      d.events++;
      if (authFail) d.auth_fail++;
      if (authSucc) d.auth_success++;
      if (bytes) d.egress_bytes += bytes;
      if (priv) d.privileged++;
      if (ev.host && ent.type !== 'host') d.hosts.add(ev.host.toLowerCase());
      // known value sets
      addCapped(a.sets.countries, g.country, maxSet);
      addCapped(a.sets.subnets, g.subnet24, maxSet);
      addCapped(a.sets.ips, g.ip, maxSet);
      if (ev.host && ent.type !== 'host') addCapped(a.sets.hosts, ev.host.toLowerCase(), maxSet);
      addCapped(a.sets.services, serviceOf(ev), maxSet);
      addCapped(a.sets.processes, (ev.process || '').toLowerCase(), maxSet);
      addCapped(a.sets.logon_types, logonTypeOf(ev), maxSet);
      for (const sc of scopesOf(ev)) addCapped(a.sets.api_scopes, sc, maxSet);
      // agent/service profile
      addCapped(a.action_types, ev.action, maxSet);
      addCapped(a.targets, (ev.target_user || ev.dst_ip || '').toLowerCase(), maxSet);
      const hb = Math.floor(ts / 3600000);
      a.hourBuckets.set(hb, (a.hourBuckets.get(hb) || 0) + 1);
    }
  }
  return out;
}

function metricStats(series, alpha) {
  return {
    median: median(series), mad: mad(series), p95: quantile(series, 0.95),
    mean: mean(series), ewma: ewma(series, alpha), max: series.length ? Math.max(...series) : 0, n: series.length,
  };
}

/** computeBaseline(aggregate, settings) → explainable baseline (Sets → sorted arrays). */
function computeBaseline(agg, settings = {}) {
  const alpha = settings.ewma_alpha !== undefined ? settings.ewma_alpha : 0.3;
  const minDays = settings.min_days_established || 7;
  const workHours = settings.work_hours || [7, 19];
  const dayKeys = [...agg.days.keys()].sort((x, y) => x - y);
  const series = { events: [], auth_fail: [], auth_success: [], egress_bytes: [], privileged: [], distinct_hosts: [] };
  for (const k of dayKeys) {
    const d = agg.days.get(k);
    series.events.push(d.events);
    series.auth_fail.push(d.auth_fail);
    series.auth_success.push(d.auth_success);
    series.egress_bytes.push(d.egress_bytes);
    series.privileged.push(d.privileged);
    series.distinct_hosts.push(d.distinct_hosts !== undefined ? d.distinct_hosts : (d.hosts ? d.hosts.size : 0));
  }
  const daysObserved = dayKeys.length;
  const spanDays = daysObserved ? (dayKeys[dayKeys.length - 1] - dayKeys[0] + 1) : 0;
  const totalEvents = agg.hourHist.reduce((a, b) => a + b, 0);
  let work = 0, off = 0;
  for (let h = 0; h < 24; h++) { if (h >= workHours[0] && h < workHours[1]) work += agg.hourHist[h]; else off += agg.hourHist[h]; }
  // per-hour call rate (for ai_agent / service_account)
  const rateSeries = agg.rateSeries || [...(agg.hourBuckets ? agg.hourBuckets.values() : [])];
  const activeHours = [];
  for (let h = 0; h < 24; h++) if (agg.hourHist[h] > 0) activeHours.push(h);

  const metrics = {};
  for (const [k, s] of Object.entries(series)) metrics[k] = metricStats(s, alpha);

  const setArr = (s) => [...s].filter(Boolean).sort();
  return {
    id: agg.id, type: agg.type, name: agg.name,
    first_seen: agg.first_seen, last_seen: agg.last_seen,
    days_observed: daysObserved, span_days: spanDays,
    state: daysObserved >= minDays ? 'established' : 'learning',
    tags: setArr(agg.tags),
    active_hours: {
      histogram: agg.hourHist.slice(), total: totalEvents,
      work_events: work, off_events: off, active: activeHours,
    },
    metrics,
    known: {
      countries: setArr(agg.sets.countries), subnets: setArr(agg.sets.subnets), ips: setArr(agg.sets.ips),
      hosts: setArr(agg.sets.hosts), services: setArr(agg.sets.services), processes: setArr(agg.sets.processes),
      logon_types: setArr(agg.sets.logon_types), api_scopes: setArr(agg.sets.api_scopes),
    },
    action_types: setArr(agg.action_types), targets: setArr(agg.targets),
    rate_per_hour: metricStats(rateSeries, alpha),
    windows: activeHours,
    computed_at: Date.now(),
  };
}

/** Summarise a recent window per entity for the detectors / API "current" view. */
function observedWindow(events, opts) {
  const aggs = buildAggregates(events, opts);
  const out = new Map();
  for (const [id, a] of aggs) {
    const days = [...a.days.values()];
    const sum = (f) => days.reduce((x, d) => x + d[f], 0);
    const hosts = new Set();
    for (const d of days) for (const h of d.hosts) hosts.add(h);
    out.set(id, {
      id, type: a.type, name: a.name, first_seen: a.first_seen, last_seen: a.last_seen,
      events: sum('events'), auth_fail: sum('auth_fail'), auth_success: sum('auth_success'),
      egress_bytes: sum('egress_bytes'), privileged: sum('privileged'), distinct_hosts: hosts.size,
      active_hours: a.hourHist.slice(),
      known: {
        countries: [...a.sets.countries], subnets: [...a.sets.subnets], ips: [...a.sets.ips], hosts: [...a.sets.hosts],
        services: [...a.sets.services], processes: [...a.sets.processes], logon_types: [...a.sets.logon_types],
        api_scopes: [...a.sets.api_scopes],
      },
      action_types: [...a.action_types], targets: [...a.targets],
    });
  }
  return out;
}

/**
 * Fold ClickHouse aggregation rows (engine/ueba/sql.js) into baselines — production path.
 *   numericRows: dailyNumericSQL() rows (per entity_id, day)
 *   valueRows  : knownValuesSQL() rows  (per entity_id)
 * Subnets are derived in Node from the IP array (geo.js), keeping geo logic in one place.
 * Returns Map entityId → baseline (same shape computeBaseline produces).
 */
function baselineFromSql(numericRows, valueRows, settings = {}) {
  const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
  const byId = new Map();
  const ensure = (id, type, name) => {
    let a = byId.get(id);
    if (!a) {
      a = {
        id, type, name, first_seen: 0, last_seen: 0, tags: new Set(), days: new Map(),
        hourHist: new Array(24).fill(0),
        sets: { countries: new Set(), subnets: new Set(), ips: new Set(), hosts: new Set(), services: new Set(), processes: new Set(), logon_types: new Set(), api_scopes: new Set() },
        action_types: new Set(), targets: new Set(), rateSeries: [],
      };
      byId.set(id, a);
    }
    return a;
  };
  for (const r of numericRows || []) {
    const a = ensure(r.entity_id, r.entity_type, r.entity_name);
    a.days.set(num(r.day), {
      events: num(r.events), auth_fail: num(r.auth_fail), auth_success: num(r.auth_success),
      egress_bytes: num(r.egress_bytes), privileged: num(r.privileged), distinct_hosts: num(r.distinct_hosts),
    });
    const ft = num(r.first_ts), lt = num(r.last_ts);
    if (ft && (!a.first_seen || ft < a.first_seen)) a.first_seen = ft;
    if (lt > a.last_seen) a.last_seen = lt;
    // approximate per-hour rate for this day (events spread over its active hours)
    a.rateSeries.push(num(r.events));
  }
  for (const r of valueRows || []) {
    const a = ensure(r.entity_id, r.entity_type, r.entity_name);
    const hist = Array.isArray(r.hour_hist) ? r.hour_hist : [];
    for (let h = 0; h < 24; h++) a.hourHist[h] += num(hist[h]);
    const fill = (set, arr) => { for (const v of arr || []) if (v) set.add(String(v)); };
    fill(a.sets.countries, r.countries); fill(a.sets.ips, r.ips); fill(a.sets.hosts, r.hosts);
    fill(a.sets.services, r.services); fill(a.sets.processes, r.processes); fill(a.sets.logon_types, r.logon_types);
    fill(a.sets.api_scopes, r.api_scopes); fill(a.action_types, r.action_types); fill(a.targets, r.targets);
    for (const ip of r.ips || []) { const { s24 } = subnetsOf(ip); if (s24) a.sets.subnets.add(s24); }
  }
  const out = new Map();
  for (const [id, a] of byId) out.set(id, computeBaseline(a, settings));
  return out;
}

module.exports = {
  median, quantile, mean, mad, robustZ, ewma,
  buildAggregates, computeBaseline, observedWindow, baselineFromSql,
  localHour, localDayKey, egressBytes, isPrivileged, logonTypeOf, serviceOf, scopesOf,
  PRIV_ACTIONS, BYTE_FIELDS, SCOPE_FIELDS,
};
