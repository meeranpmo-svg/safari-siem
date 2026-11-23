// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer — cost model (DATAOPT.md "Cost model"). Advisory only.
 *   events & bytes per source/type/day, projected hot-store GB + monthly cost (configurable SAR/GB + retention),
 *   savings from the current pipeline vs raw, top talkers, and suggestions.
 *   createCost({ ch, settings, log }) → { summary({from,to}) }
 *   Pure helpers (bytesToGB, projectMonthlyCost, buildSuggestions) are exported for tests.
 */
const GB = 1024 * 1024 * 1024;
const bytesToGB = (b) => (Number(b) || 0) / GB;

// Steady-state stored GB = daily GB * retention days; monthly cost = stored GB * SAR/GB-month.
function projectMonthlyCost(bytesInWindow, windowDays, retentionDays, costPerGbMonth) {
  const dailyGb = bytesToGB(bytesInWindow) / Math.max(1, windowDays);
  const storedGb = dailyGb * Math.max(0, retentionDays);
  return { stored_gb: round(storedGb), monthly_cost: round(storedGb * (costPerGbMonth || 0)) };
}
function round(n) { return Math.round((Number(n) || 0) * 100) / 100; }

function buildSuggestions({ bySource, typeBreakdown, totals }, settings) {
  const out = [];
  const totalBytes = totals.raw_bytes || 1;
  for (const s of bySource.slice(0, 10)) {
    const share = s.bytes / totalBytes;
    if (share < 0.15) continue;
    // dominant informational event type for this source?
    const types = (typeBreakdown[s.src_id] || []).slice().sort((a, b) => b.bytes - a.bytes);
    const top = types[0];
    if (top && top.bytes / Math.max(1, s.bytes) > 0.6 && isInformational(top.event_type)) {
      out.push({ severity: 'high', src_id: s.src_id, event_type: top.event_type,
        message: `source ${s.src_id} is ${Math.round(share * 100)}% of volume, ${Math.round((top.bytes / s.bytes) * 100)}% is informational "${top.event_type}" — archive or sample?`,
        action_hint: 'sample', suggested_rate: 0.1 });
    } else if (share > 0.25) {
      out.push({ severity: 'medium', src_id: s.src_id,
        message: `source ${s.src_id} is ${Math.round(share * 100)}% of total volume — consider archiving low-value events`,
        action_hint: 'route:archive' });
    }
  }
  if (!settings.protect_detections) out.push({ severity: 'warning', message: 'protect-detections is OFF — drop/sample rules can create blind spots without an override' });
  return out;
}
const INFORMATIONAL = [/logon-type-3/i, /^4634$/, /^4624$/, /heartbeat/i, /connection$/i, /dns-query/i, /http-request/i, /allowed$/i];
function isInformational(t) { return INFORMATIONAL.some((re) => re.test(String(t || ''))); }

function createCost({ ch, settings, log } = {}) {
  async function volume(from, to) {
    // per source/type volume from stats_minute (raw ingest)
    if (!ch) return { bySource: [], byType: [], total: { events: 0, bytes: 0 } };
    const params = { from: { type: 'String', value: fmt(from) }, to: { type: 'String', value: fmt(to) } };
    const rows = await ch.query(
      'SELECT src_id, src_type, sum(events) AS events, sum(bytes) AS bytes FROM stats_minute WHERE minute >= {from:DateTime} AND minute <= {to:DateTime} GROUP BY src_id, src_type ORDER BY bytes DESC',
      params, { readonly: true, timeout_ms: 20000 });
    const bySource = rows.map((r) => ({ src_id: r.src_id, src_type: r.src_type, events: Number(r.events), bytes: Number(r.bytes) }));
    const byTypeMap = new Map();
    let te = 0, tb = 0;
    for (const r of bySource) {
      te += r.events; tb += r.bytes;
      const t = byTypeMap.get(r.src_type) || { src_type: r.src_type, events: 0, bytes: 0 };
      t.events += r.events; t.bytes += r.bytes; byTypeMap.set(r.src_type, t);
    }
    return { bySource, byType: [...byTypeMap.values()].sort((a, b) => b.bytes - a.bytes), total: { events: te, bytes: tb } };
  }

  async function ruleStats(from, to) {
    if (!ch) return {};
    try {
      const rows = await ch.query(
        'SELECT action, sum(events) AS events, sum(bytes) AS bytes FROM dataopt_rule_stat WHERE hour >= {from:DateTime} AND hour <= {to:DateTime} GROUP BY action',
        { from: { type: 'String', value: fmt(from) }, to: { type: 'String', value: fmt(to) } }, { readonly: true, timeout_ms: 20000 });
      const out = {};
      for (const r of rows) out[r.action] = { events: Number(r.events), bytes: Number(r.bytes) };
      return out;
    } catch { return {}; }
  }

  async function typeBreakdown(from, to, srcIds) {
    if (!ch || !srcIds.length) return {};
    try {
      const rows = await ch.query(
        'SELECT src_id, if(event_code != \'\', event_code, action) AS event_type, count() AS events, sum(length(raw)) AS bytes FROM events WHERE ts >= {from:DateTime64(3)} AND ts <= {to:DateTime64(3)} AND src_id IN {ids:Array(String)} GROUP BY src_id, event_type ORDER BY bytes DESC LIMIT 200',
        { from: { type: 'String', value: fmt(from) }, to: { type: 'String', value: fmt(to) }, ids: { type: 'Array(String)', value: srcIds } }, { readonly: true, timeout_ms: 25000 });
      const out = {};
      for (const r of rows) { (out[r.src_id] = out[r.src_id] || []).push({ event_type: r.event_type, events: Number(r.events), bytes: Number(r.bytes) }); }
      return out;
    } catch { return {}; }
  }

  async function summary({ from, to } = {}) {
    const s = settings ? settings.get() : { currency: 'SAR', cost_per_gb_month: 1.5, archive_cost_per_gb_month: 0.1, hot_retention_days: 365, archive_retention_days: 730, protect_detections: true };
    const windowMs = Math.max(1, to - from);
    const windowDays = windowMs / 86400000;
    const [vol, rs] = await Promise.all([volume(from, to), ruleStats(from, to)]);
    const tb = await typeBreakdown(from, to, vol.bySource.slice(0, 8).map((x) => x.src_id)).catch(() => ({}));

    const rawBytes = vol.total.bytes;
    const keptBytes = (rs.keep && rs.keep.bytes) || 0;
    const archivedBytes = (rs.archive && rs.archive.bytes) || 0;
    const droppedBytes = (rs.drop && rs.drop.bytes || 0) + (rs.sample && rs.sample.bytes || 0) + (rs.aggregate && rs.aggregate.bytes || 0);
    const hotBytes = keptBytes || (rawBytes - archivedBytes - droppedBytes); // fall back when no keep-counter yet
    const enforced = !!(rs.keep || rs.drop || rs.archive || rs.sample);

    const hot = projectMonthlyCost(Math.max(0, hotBytes), windowDays, s.hot_retention_days, s.cost_per_gb_month);
    const raw = projectMonthlyCost(rawBytes, windowDays, s.hot_retention_days, s.cost_per_gb_month);
    const arch = projectMonthlyCost(archivedBytes, windowDays, s.archive_retention_days, s.archive_cost_per_gb_month);
    const savingsMonthly = round(raw.monthly_cost - hot.monthly_cost - arch.monthly_cost);

    const bySource = vol.bySource.map((r) => ({ ...r, gb: round(bytesToGB(r.bytes)), ...projectMonthlyCost(r.bytes, windowDays, s.hot_retention_days, s.cost_per_gb_month) }));
    const totals = {
      events: vol.total.events, raw_bytes: rawBytes, raw_gb: round(bytesToGB(rawBytes)),
      hot_bytes: Math.max(0, hotBytes), hot_gb: hot.stored_gb, archived_bytes: archivedBytes, archived_gb: arch.stored_gb,
      dropped_bytes: droppedBytes,
      hot_monthly_cost: hot.monthly_cost, archive_monthly_cost: arch.monthly_cost, raw_monthly_cost: raw.monthly_cost,
      savings_monthly: savingsMonthly, savings_pct: raw.monthly_cost ? Math.round((savingsMonthly / raw.monthly_cost) * 100) : 0,
    };
    const suggestions = buildSuggestions({ bySource, typeBreakdown: tb, totals }, s);
    return {
      window: { from, to, days: round(windowDays) }, currency: s.currency, cost_per_gb_month: s.cost_per_gb_month,
      enforced, by_source: bySource, by_type: vol.byType.map((r) => ({ ...r, gb: round(bytesToGB(r.bytes)) })),
      top_talkers: bySource.slice(0, 10), rule_actions: rs, totals, suggestions,
    };
  }

  return { summary, volume, ruleStats };
}

function fmt(ms) { return new Date(Number.isFinite(ms) ? ms : Date.now()).toISOString().slice(0, 19).replace('T', ' '); }

module.exports = { createCost, bytesToGB, projectMonthlyCost, buildSuggestions, isInformational };
