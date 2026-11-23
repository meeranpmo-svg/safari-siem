// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SOC metrics (pure functions over alert / case objects).
 *
 *   computeMetrics({ alerts, cases, from, to, now, slaState, tzOffsetMin = 180, noisyPerDay = 20, top = 10 })
 *
 * Definitions
 *   alerts_by_day      alerts first seen (created) per calendar day (Asia/Riyadh by default) split by severity 0-4
 *   MTTD               alert.created − alert.ts_first (first event time → alert first seen), per alert
 *   MTTA               alert.ack_at − alert.created;  case.acked_at − case.created
 *   MTTR (cases)       case.closed − case.created for cases closed in the period;  (alerts) closed_at − created
 *   SLA                cases created in the period: ack / resolve breaches (see cases.js), open cases breaching now
 *   top_rules          most alerts (and summed event counts) per rule
 *   top_sources        alerts per src_id (falls back to src_type / host)
 *   noisy_rules        alerts per day per rule over the period, flagged when ≥ noisyPerDay
 *   fp_rate            per rule: closed-false-positive / all closed alerts of that rule (plus benign share)
 * LogRhythm-imported alerts (source 'logrhythm') are excluded (they are measured by /lr-compare).
 *
 * Result (portal contract first): { open_by_severity:{0..4:n}, alerts_by_day:[{day, s0..s4, total}], mttd_s, mttr_s
 *   (case MTTR, falls back to alert MTTR), sla:{breached, at_risk, cases, ack_breaches, resolve_breaches, *_compliance_pct,
 *   breaching_now[]}, top_rules[], top_sources[], top_hosts[], top_users[], noisy_rules[], mitre:{T1110: n},
 *   + detail: totals, alerts_by_severity, mttd{n,avg_ms,median_ms,p90_ms,max_ms}, mttd_by_severity, mtta, mttr, fp_rate[] }
 * at_risk = open, not yet breached cases with < 25 % of their (unmet) ack or resolve budget left.
 */

function dist(values) {
  const v = values.filter((x) => Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (!v.length) return { n: 0, avg_ms: null, median_ms: null, p90_ms: null, max_ms: null };
  const q = (p) => v[Math.min(v.length - 1, Math.floor(p * (v.length - 1) + 0.5))];
  return { n: v.length, avg_ms: Math.round(v.reduce((a, b) => a + b, 0) / v.length), median_ms: q(0.5), p90_ms: q(0.9), max_ms: v[v.length - 1] };
}

function dayOf(ms, offMin) {
  return new Date(ms + offMin * 60000).toISOString().slice(0, 10);
}

function computeMetrics(o = {}) {
  const now = o.now || Date.now();
  const to = o.to || now;
  const from = o.from || to - 30 * 86400000;
  const off = o.tzOffsetMin !== undefined ? o.tzOffsetMin : 180;
  const noisyPerDay = o.noisyPerDay || 20;
  const top = o.top || 10;
  const days = Math.max(1, (to - from) / 86400000);

  const allAlerts = (o.alerts || []).filter((a) => a.source !== 'logrhythm');
  const alerts = allAlerts.filter((a) => a.created >= from && a.created <= to);
  const cases = o.cases || [];

  // alerts by day / severity
  const byDay = new Map();
  if (days <= 400) for (let t = from; t <= to; t += 86400000) byDay.set(dayOf(t, off), { day: dayOf(t, off), s0: 0, s1: 0, s2: 0, s3: 0, s4: 0, total: 0 });
  const bySev = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
  for (const a of alerts) {
    const d = dayOf(a.created, off);
    let row = byDay.get(d);
    if (!row) { row = { day: d, s0: 0, s1: 0, s2: 0, s3: 0, s4: 0, total: 0 }; byDay.set(d, row); }
    const s = Math.max(0, Math.min(4, a.severity | 0));
    row[`s${s}`]++; row.total++; bySev[s]++;
  }

  // detection / response times
  const mttd = dist(alerts.map((a) => a.created - a.ts_first));
  const mttdBySev = {};
  for (let s = 0; s <= 4; s++) mttdBySev[s] = dist(alerts.filter((a) => (a.severity | 0) === s).map((a) => a.created - a.ts_first));
  const alertMtta = dist(alerts.filter((a) => a.ack_at).map((a) => a.ack_at - a.created));
  const alertMttr = dist(allAlerts.filter((a) => a.closed_at && a.closed_at >= from && a.closed_at <= to).map((a) => a.closed_at - a.created));
  const casesClosed = cases.filter((c) => c.closed && c.closed >= from && c.closed <= to);
  const caseMttr = dist(casesClosed.map((c) => c.closed - c.created));
  const caseMttrBySev = {};
  for (let s = 0; s <= 4; s++) caseMttrBySev[s] = dist(casesClosed.filter((c) => (c.severity | 0) === s).map((c) => c.closed - c.created));
  const casesInRange = cases.filter((c) => c.created >= from && c.created <= to);
  const caseMtta = dist(casesInRange.filter((c) => c.acked_at).map((c) => c.acked_at - c.created));

  // SLA
  const sla = { cases: casesInRange.length, ack_breaches: 0, resolve_breaches: 0, ack_compliance_pct: null, resolve_compliance_pct: null, breaching_now: [] };
  if (typeof o.slaState === 'function') {
    for (const c of casesInRange) {
      const s = o.slaState(c, now);
      if (s.ack_breached) sla.ack_breaches++;
      if (s.resolve_breached) sla.resolve_breaches++;
    }
    for (const c of cases) {
      if (c.status === 'closed') continue;
      const s = o.slaState(c, now);
      if (s.ack_breached || s.resolve_breached) sla.breaching_now.push({ id: c.id, title: c.title, severity: c.severity, ack_breached: s.ack_breached, resolve_breached: s.resolve_breached });
    }
    if (casesInRange.length) {
      sla.ack_compliance_pct = Math.round((1 - sla.ack_breaches / casesInRange.length) * 1000) / 10;
      sla.resolve_compliance_pct = Math.round((1 - sla.resolve_breaches / casesInRange.length) * 1000) / 10;
    }
  }

  // rules
  const rules = new Map();
  const rs = (a) => {
    let r = rules.get(a.rule_id);
    if (!r) { r = { rule_id: a.rule_id, rule_name: a.rule_name, alerts: 0, events: 0, closed: 0, tp: 0, fp: 0, benign: 0 }; rules.set(a.rule_id, r); }
    return r;
  };
  for (const a of alerts) { const r = rs(a); r.alerts++; r.events += a.count || 0; }
  for (const a of allAlerts) {
    if (!a.closed_at || a.closed_at < from || a.closed_at > to) continue;
    const r = rs(a);
    r.closed++;
    if (a.status === 'closed-true-positive') r.tp++;
    else if (a.status === 'closed-false-positive') r.fp++;
    else if (a.status === 'closed-benign') r.benign++;
  }
  const ruleArr = [...rules.values()];
  const topRules = ruleArr.filter((r) => r.alerts).sort((a, b) => b.alerts - a.alerts || b.events - a.events).slice(0, top)
    .map((r) => ({ rule_id: r.rule_id, rule_name: r.rule_name, alerts: r.alerts, events: r.events }));
  const noisy = ruleArr.filter((r) => r.alerts).map((r) => ({ rule_id: r.rule_id, rule_name: r.rule_name, alerts: r.alerts, per_day: Math.round((r.alerts / days) * 10) / 10 }))
    .sort((a, b) => b.per_day - a.per_day).slice(0, top).map((r) => Object.assign(r, { noisy: r.per_day >= noisyPerDay }));
  const fpRate = ruleArr.filter((r) => r.closed).map((r) => ({
    rule_id: r.rule_id, rule_name: r.rule_name, closed: r.closed, true_positive: r.tp, false_positive: r.fp, benign: r.benign,
    fp_rate: Math.round((r.fp / r.closed) * 1000) / 1000, benign_rate: Math.round((r.benign / r.closed) * 1000) / 1000,
  })).sort((a, b) => b.fp_rate - a.fp_rate || b.closed - a.closed);

  // sources
  const src = new Map();
  for (const a of alerts) {
    const k = a.src_id || a.src_type || a.host || 'unknown';
    const s = src.get(k) || { source: k, src_type: a.src_type || '', alerts: 0 };
    s.alerts++; src.set(k, s);
  }
  const topSources = [...src.values()].sort((a, b) => b.alerts - a.alerts).slice(0, top);

  const open = allAlerts.filter((a) => !String(a.status).startsWith('closed-'));
  const openBySev = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
  for (const a of open) openBySev[Math.max(0, Math.min(4, a.severity | 0))]++;

  // entities and MITRE techniques over alerts in the period
  const hosts = new Map(); const users = new Map(); const mitre = {};
  const bump = (m, k) => { if (k) m.set(k, (m.get(k) || 0) + 1); };
  for (const a of alerts) {
    const bag = Object.assign({}, a.fields || {}, a.group || {});
    const hs = new Set([bag.host, a.host].filter(Boolean).map(String));
    for (const h of hs) bump(hosts, h);
    const us = new Set([bag.user, bag.target_user].filter((u) => u && !String(u).endsWith('$')).map(String));
    for (const u of us) bump(users, u);
    for (const t of a.mitre || []) mitre[t] = (mitre[t] || 0) + 1;
  }
  const topOf = (m, key) => [...m.entries()].sort((x, y) => y[1] - x[1]).slice(0, top).map(([k, n]) => ({ [key]: k, alerts: n }));

  // SLA at-risk: open cases with less than 25% of the resolve (or un-met ack) budget left, not yet breached
  if (typeof o.slaState === 'function') {
    let atRisk = 0;
    for (const c of cases) {
      if (c.status === 'closed' || !c.sla) continue;
      const s = o.slaState(c, now);
      if (s.ack_breached || s.resolve_breached) continue;
      const ackLeft = !c.acked_at && s.ack_remaining_ms < 0.25 * (c.sla.ack_due - c.created);
      const resLeft = s.resolve_remaining_ms < 0.25 * (c.sla.resolve_due - c.created);
      if (ackLeft || resLeft) atRisk++;
    }
    sla.breached = sla.breaching_now.length;
    sla.at_risk = atRisk;
  } else { sla.breached = 0; sla.at_risk = 0; }

  return {
    from, to, generated_at: now,
    open_by_severity: openBySev,
    mttd_s: mttd.avg_ms === null ? null : Math.round(mttd.avg_ms / 1000),
    mttr_s: caseMttr.avg_ms !== null ? Math.round(caseMttr.avg_ms / 1000) : (alertMttr.avg_ms !== null ? Math.round(alertMttr.avg_ms / 1000) : null),
    top_hosts: topOf(hosts, 'host'), top_users: topOf(users, 'user'), mitre,
    totals: {
      alerts: alerts.length, events: alerts.reduce((s, a) => s + (a.count || 0), 0), open_alerts: open.length,
      unassigned_open: open.filter((a) => !a.assignee).length,
      cases_created: casesInRange.length, cases_closed: casesClosed.length, cases_open: cases.filter((c) => c.status !== 'closed').length,
    },
    alerts_by_severity: bySev,
    alerts_by_day: [...byDay.values()].sort((a, b) => (a.day < b.day ? -1 : 1)),
    mttd, mttd_by_severity: mttdBySev,
    mtta: { alerts: alertMtta, cases: caseMtta },
    mttr: { cases: caseMttr, cases_by_severity: caseMttrBySev, alerts: alertMttr },
    sla, top_rules: topRules, top_sources: topSources, noisy_rules: noisy, fp_rate: fpRate,
  };
}

module.exports = { computeMetrics, dist };
