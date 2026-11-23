// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Security Operations Overview insights (GET {P}/soc/overview/insights, analyst.js overviewInsights()) - pure statistics over the
 * SIEM's own alerts. No model, no data leaves the platform; every figure says how it was computed and how much history it had.
 *   forecast    alerts raised per Riyadh day for 56 days; the next 7 days = the mean of the same weekday over the last 4 weeks,
 *               scaled by the last 7 days against the 28 before (level); band = 1.28 x MAD of the seasonal residuals. Withheld below
 *               14 days with alerts. A projection from past pace, not a promise.
 *   shifts      each rule's last 24 hours against its previous 14 daily counts (robust z): NEW (never fired in 14 days, 3+ now),
 *               SURGING (|z| >= 3.5 and 5+), SILENT (5+ a day on average for 14 days and nothing in 24 hours - a broken
 *               detection or a source that stopped). Judged from 7 days of history.
 *   efficacy    per rule, 30 days of closures (3+): precision = smoothed true-positive share (Beta(1,1)), median time to close,
 *               open now. "high value" >= 60 %, "noise" <= 20 %; between is said as such.
 *   entities    users / hosts / IPs ranked by the sum of the priorities of their OPEN alerts across rules, with the rules, the
 *               ATT&CK tactics and the highest priority - who is most at risk right now, not who is most noisy.
 *   sla         per week (4 weeks), the share of alerts acknowledged and closed inside the case SLA policy for their severity.
 */
const DAY = 86400000, H = 3600000, OFF = 3 * H;
const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');
const r1 = (x) => Math.round(x * 10) / 10;
const med = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const dayIdx = (ms) => Math.floor(((ms || 0) + OFF) / DAY);
const created = (a) => a.created || a.ts_first || 0;
function rz(vals, x) {
  if (vals.length < 7) return null;
  const m = med(vals), mad = med(vals.map((v) => Math.abs(v - m)));
  if (!mad) return { z: x === m ? 0 : (x > m ? Infinity : -Infinity), usual: m };
  return { z: r1(0.6745 * (x - m) / mad), usual: m };
}

function forecast(all, now) {
  const today = dayIdx(now), d0 = today - 55, counts = new Array(56).fill(0);
  for (const a of all) { const k = dayIdx(created(a)) - d0; if (k >= 0 && k < 56) counts[k]++; }
  const series = counts.map((n, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), raised: n }));
  const active = counts.filter((n) => n > 0).length;
  if (active < 14) return { series: series.slice(-28), forecast: null, why: 'the volume forecast needs 14 days with alerts (' + active + ' so far)' };
  // complete days only (today is partial): the last 28 complete days
  const full = counts.slice(0, 55), last7 = full.slice(-7), firstData = full.findIndex((x) => x > 0);
  const prev28 = full.slice(Math.max(firstData, 55 - 35), 55 - 7);   // only days since the first alert: days before it are not "quiet days"
  const avg = (a) => a.reduce((x, y) => x + y, 0) / Math.max(1, a.length);
  const level = prev28.length >= 7 && avg(prev28) ? avg(last7) / avg(prev28) : 1;
  const seasonal = (dayNo) => { const v = []; for (let w = 1; w <= 4; w++) { const k = dayNo - 7 * w - d0; if (k >= Math.max(0, firstData) && k < 55) v.push(full[k]); } return avg(v); };
  const resid = []; for (let k = Math.max(28, firstData + 7); k < 55; k++) resid.push(full[k] - seasonal(d0 + k));
  const mad = med(resid.map((x) => Math.abs(x - med(resid)))) || 0;
  const out = [];
  for (let i = 1; i <= 7; i++) { const dn = today + i - 1, f = Math.max(0, seasonal(dn) * level), band = 1.28 * 1.4826 * mad;
    out.push({ day: new Date(dn * DAY).toISOString().slice(0, 10), alerts: Math.round(f), low: Math.max(0, Math.round(f - band)), high: Math.round(f + band) }); }
  const total = out.reduce((x, y) => x + y.alerts, 0), lastWeek = last7.reduce((x, y) => x + y, 0);
  return { series: series.slice(-28), forecast: out, level: r1(level), next_7_days: total, last_7_days: lastWeek,
    why: 'about ' + total + ' alerts expected in the next 7 days (last 7: ' + lastWeek + '); same weekday over 4 weeks x the recent level ' + r1(level) + ' - a projection, not a promise' };
}

function shifts(all, now) {
  const by = new Map();
  for (const a of all) { const k = a.rule_id; if (!by.has(k)) by.set(k, { rule_id: k, rule_name: a.rule_name || k, last24: 0, days: new Array(14).fill(0) }); const r = by.get(k), c = created(a);
    if (c > now - DAY) r.last24++; else { const d = Math.floor((now - DAY - c) / DAY); if (d >= 0 && d < 14) r.days[d]++; } }
  const first = Math.min(...all.map(created).filter(Boolean), now), histDays = Math.min(14, Math.floor((now - DAY - first) / DAY));
  if (histDays < 7) return { judged: false, items: [], why: 'rules are compared with their own history from 7 days of alerts (' + Math.max(0, histDays) + ' so far)' };
  const items = [];
  for (const r of by.values()) {
    const hist = r.days.slice(0, histDays), tot = hist.reduce((x, y) => x + y, 0), avg = tot / histDays;
    if (!tot && r.last24 >= 3) { items.push({ kind: 'new', rule_id: r.rule_id, rule_name: r.rule_name, last24: r.last24, usual: 0, why: 'never fired in ' + histDays + ' days, ' + r.last24 + ' in the last 24 hours' }); continue; }
    if (avg >= 5 && !r.last24) { items.push({ kind: 'silent', rule_id: r.rule_id, rule_name: r.rule_name, last24: 0, usual: r1(avg), why: 'about ' + r1(avg) + ' a day for ' + histDays + ' days and none in 24 hours - check the detection and its log source' }); continue; }
    const z = rz(hist, r.last24);
    if (z && z.z >= 3.5 && r.last24 >= 5) items.push({ kind: 'surging', rule_id: r.rule_id, rule_name: r.rule_name, last24: r.last24, usual: z.usual, z: Number.isFinite(z.z) ? z.z : null, why: r.last24 + ' in 24 hours against a usual ' + z.usual + ' a day' });
  }
  const order = { silent: 0, new: 1, surging: 2 };
  return { judged: true, history_days: histDays, items: items.sort((a, b) => order[a.kind] - order[b.kind] || b.last24 - a.last24).slice(0, 15) };
}

function efficacy(all, now) {
  const by = new Map();
  for (const a of all) {
    if (!(isClosed(a.status) && (a.closed_at || 0) >= now - 30 * DAY)) continue;
    const r = by.get(a.rule_id) || by.set(a.rule_id, { rule_id: a.rule_id, rule_name: a.rule_name || a.rule_id, n: 0, tp: 0, ttc: [] }).get(a.rule_id);
    r.n++; if (a.status === 'closed-true-positive') r.tp++; if (created(a)) r.ttc.push(a.closed_at - created(a));
  }
  const open = new Map(); for (const a of all) if (!isClosed(a.status)) open.set(a.rule_id, (open.get(a.rule_id) || 0) + 1);
  const rows = [...by.values()].filter((r) => r.n >= 3).map((r) => { const p = Math.round(100 * (r.tp + 1) / (r.n + 2)), m = med(r.ttc);
    return { rule_id: r.rule_id, rule_name: r.rule_name, closures: r.n, true_positive: r.tp, precision: p, median_close_min: m == null ? null : Math.round(m / 60000), open: open.get(r.rule_id) || 0,
      grade: p >= 60 ? 'high value' : p <= 20 ? 'noise' : 'mixed', why: r.tp + ' of ' + r.n + ' closures true positive in 30 days (smoothed ' + p + '%)' }; });
  return { rules: rows.sort((a, b) => b.precision - a.precision || b.closures - a.closures).slice(0, 20), judged: rows.length, why: rows.length ? null : 'a rule is graded from 3 closures in 30 days' };
}

function entities(openScored) {
  const by = new Map();
  for (const a of openScored) for (const e of new Set(a.entities || [])) {
    const r = by.get(e) || by.set(e, { entity: e, risk: 0, alerts: 0, rules: new Set(), tactics: new Set(), max: 0 }).get(e);
    r.risk += a.priority || 0; r.alerts++; r.rules.add(a.rule_name || a.rule_id); if (a.tactic) r.tactics.add(a.tactic); r.max = Math.max(r.max, a.priority || 0);
  }
  return [...by.values()].sort((a, b) => b.risk - a.risk).slice(0, 10).map((r) => ({ entity: r.entity, risk: r.risk, alerts: r.alerts, max_priority: r.max, rules: [...r.rules].slice(0, 5), tactics: [...r.tactics].slice(0, 6),
    why: r.alerts + ' open alert(s) from ' + r.rules.size + ' rule(s), summed priority ' + r.risk + (r.tactics.size ? ', tactics ' + [...r.tactics].join(', ') : '') }));
}

function sla(all, policy, now) {
  const name = (s) => (s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low'), weeks = [];
  for (let w = 3; w >= 0; w--) {
    const t1 = now - w * 7 * DAY, t0 = t1 - 7 * DAY, L = all.filter((a) => created(a) > t0 && created(a) <= t1);
    let ackN = 0, ackOk = 0, resN = 0, resOk = 0;
    for (const a of L) { const p = (policy || {})[name(a.severity || 0)]; if (!p) continue; const c = created(a);
      const ackDue = c + p.ack_h * H, resDue = c + p.resolve_h * H;
      if (a.ack_at || now > ackDue) { ackN++; if (a.ack_at && a.ack_at <= ackDue) ackOk++; }
      if (isClosed(a.status) || now > resDue) { resN++; if (isClosed(a.status) && a.closed_at && a.closed_at <= resDue) resOk++; } }
    weeks.push({ week_ending: new Date(t1).toISOString().slice(0, 10), alerts: L.length, ack_pct: ackN ? Math.round(100 * ackOk / ackN) : null, resolve_pct: resN ? Math.round(100 * resOk / resN) : null, ack_judged: ackN, resolve_judged: resN });
  }
  return { weeks, why: 'an alert counts once its clock has run out or it was acknowledged / closed; open alerts still inside their time are not judged yet' };
}

module.exports = { forecast, shifts, efficacy, entities, sla };
