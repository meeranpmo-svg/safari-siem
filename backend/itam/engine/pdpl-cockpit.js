// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Privacy Cockpit (Data Privacy): one view over every PDPL register the platform keeps, read from the modules that own them
 * (engine/pdpl.js, pdpl-workflows.js, pdpl-vendor.js, pdpl-retention.js) - nothing re-entered, nothing invented.
 *
 *   clocks      every legal deadline in one list, most urgent first: data subject requests (30 days, extendable), breaches (72 hours
 *               to SDAIA; other regulators' hours as set in the profile), impact assessments missing or outdated, transfers outside
 *               the Kingdom without a signed transfer impact assessment, vendor reviews due, retention tasks overdue.
 *   requests    MACHINE LEARNING on the request history:
 *                 deadline risk  Kaplan-Meier survival of the handling time over every request ever received (open ones censored
 *                                at their age): P(not answered by the due date | still open today). With fewer than 8 answered
 *                                requests it falls back to a stated rule (days left, blockers) and says so.
 *                 volume         requests per month; Holt's linear smoothing for the next 3 months with an 80 % band, only with 6+
 *                                months of history.
 *   activities  an explainable privacy-risk score per processing activity (0-100, every point named): sensitive / health / credit
 *               data, impact assessment missing or outdated, transfer outside the Kingdom without a signed assessment, sensitive-data
 *               controls missing, incomplete record, no steward. A heat map of activities by score band and data type.
 *   sources     which registers answered; a module that is not installed or failed is named, never counted as zero.
 * Read-only, operator and up (the registers it reads are operator-only: PDPL records themselves; no personal data is shown). The AI Privacy Officer (PDPL Studio) reads the same
 * view through a read-only tool to draft the DPO's weekly briefing.
 */
const DAY = 864e5;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

// ---------------------------------------------------------------- the models (pure, tested on their own)
// Kaplan-Meier: durations in days, event=true when answered, false when still open (censored at its age)
function km(items) {
  const T = items.filter((x) => x.t >= 0).sort((a, b) => a.t - b.t), steps = []; let atRisk = T.length, S = 1;
  for (let i = 0; i < T.length;) {
    const t = T[i].t; let d = 0, c = 0;
    while (i < T.length && T[i].t === t) { if (T[i].event) d++; else c++; i++; }
    if (d) { S *= 1 - d / atRisk; steps.push([t, S]); }
    atRisk -= d + c;
  }
  return (t) => { let s = 1; for (const [u, v] of steps) { if (u <= t) s = v; else break; } return s; };
}
// Holt's linear exponential smoothing; returns h-step forecasts with an 80 % band from the one-step errors
function holt(y, h, a = 0.5, b = 0.3) {
  if (y.length < 2) return null;
  let l = y[0], t = y[1] - y[0]; const err = [];
  for (let i = 1; i < y.length; i++) { const f = l + t; err.push(y[i] - f); const nl = a * y[i] + (1 - a) * (l + t); t = b * (nl - l) + (1 - b) * t; l = nl; }
  const sd = Math.sqrt(err.reduce((s, e) => s + e * e, 0) / Math.max(1, err.length));
  return Array.from({ length: h }, (_, k) => { const v = Math.max(0, l + (k + 1) * t), w = 1.28 * sd * Math.sqrt(k + 1); return { value: v, low: Math.max(0, v - w), high: v + w }; });
}
// the explainable score of one processing activity (every point named)
function activityRisk(a, opts = {}) {
  const pts = [], add = (p, why) => { if (p) pts.push([p, why]); };
  const sens = a.sensitive || [];
  if (sens.length) add(25, 'sensitive data: ' + sens.join(', '));
  if (sens.includes('health')) add(10, 'health data (insurer: core activity)');
  if ((a.data_categories || []).some((c) => /credit|financial|bank/i.test(c))) add(5, 'credit / financial data');
  if (a.dpia === 'missing' && (a.dpia_needed_for || []).length) add(20, 'impact assessment required (' + a.dpia_needed_for.join(', ') + ') and missing');
  else if (a.dpia === 'outdated') add(10, 'impact assessment outdated');
  const tr = opts.transfers || [];
  if (tr.some((t) => !t.signed)) add(15, 'transfer outside the Kingdom without a signed transfer impact assessment');
  if (opts.sensitiveGaps) add(Math.min(15, opts.sensitiveGaps * 2), opts.sensitiveGaps + ' sensitive-data control(s) missing');
  if (a.completeness != null && a.completeness < 70) add(10, 'record ' + a.completeness + ' % complete');
  if (!a.steward) add(5, 'no data steward');
  if (a.review_due) add(5, 'yearly review due');
  const score = Math.min(100, pts.reduce((s, p) => s + p[0], 0));
  return { score, band: score >= 60 ? 'high' : score >= 35 ? 'medium' : 'low', why: pts.map(([p, w]) => '+' + p + ' ' + w) };
}

function createPdplCockpit(app, opts = {}) {
  const now = opts.now || Date.now;
  const PD = () => (app.addons || {}).pdpl || null;
  async function read(name, fn) {
    try { const v = await fn(); return v === undefined ? { name, ok: false, reason: 'not installed' } : { name, ok: true, v }; } catch (e) {
      if (app.log && app.log.warn) app.log.warn('pdpl cockpit: a register did not answer', { register: name, message: e.message });
      return { name, ok: false, reason: e.status === 404 ? 'not installed' : String(e.message || e).slice(0, 160) };
    }
  }
  async function view(who) {
    const P = PD(); if (!P) throw httpErr(424, 'the PDPL module is not installed on this server - run the update');
    const W = P.workflows, V = P.vendor, R = (app.addons || {}).pdplRetention;
    const src = await Promise.all([
      read('Data subject requests', () => W ? W.dsar() : undefined), read('Breaches', () => W ? W.breaches() : undefined), read('Impact assessments', () => W ? W.dpia() : undefined),
      read('Transfers', () => W ? W.transfers() : undefined), read('Records of processing', () => W ? W.ropa() : undefined), read('Sensitive data controls', () => W ? W.sensitive() : undefined),
      read('Vendors', () => V ? V.view() : undefined), read('Retention', () => R ? R.view(who) : undefined)]);
    const g = (n) => { const x = src.find((s) => s.name === n); return x && x.ok ? x.v : null; };
    const dsar = g('Data subject requests'), br = g('Breaches'), dp = g('Impact assessments'), tr = g('Transfers'), ro = g('Records of processing'), se = g('Sensitive data controls'), ve = g('Vendors'), re = g('Retention');
    const t0 = now(), today = new Date(t0).toISOString().slice(0, 10);

    // ---- clocks
    const clocks = [];
    for (const r of (dsar && dsar.requests) || []) if (!r.responded && !r.outcome && !['refused', 'withdrawn', 'closed'].includes(r.stage)) clocks.push({ kind: 'request', id: r.id, title: 'Data subject request ' + (r.ref || r.id) + ' (' + r.type + ')', due: r.due, hours_left: r.due ? Math.round((Date.parse(String(r.due).slice(0, 10) + 'T23:59:59Z') - t0) / 36e5) : null, late: !!r.overdue, page: 'pdpl-dsar.html', note: (r.blockers || []).slice(0, 2).join('; ') });
    for (const b of (br && br.breaches) || []) if (!b.closed) {
      clocks.push({ kind: 'breach', id: b.id, title: 'Breach ' + (b.ref || b.id) + ': notify SDAIA (72 h)', due: b.deadline, hours_left: b.hours_left, late: !!b.late, page: 'pdpl-breach.html', note: b.next || '' });
      for (const g2 of b.regulators || []) if (g2.deadline && !g2.notified_at && g2.required !== false) clocks.push({ kind: 'breach', id: b.id + ':' + g2.key, title: 'Breach ' + (b.ref || b.id) + ': notify ' + g2.label, due: g2.deadline, hours_left: g2.hours_left, late: !!g2.late, page: 'pdpl-breach.html', note: '' });
    }
    for (const a of (dp && dp.activities) || []) if (a.state === 'missing' || a.outdated) clocks.push({ kind: 'dpia', id: a.id, title: 'Impact assessment ' + (a.outdated ? 'outdated' : 'missing') + ': ' + a.name, due: null, hours_left: null, late: true, page: 'pdpl-dpia.html', note: (a.needed_for || []).join(', ') });
    for (const t of (tr && tr.transfers) || []) if (!(t.tia && t.tia.signed_by)) clocks.push({ kind: 'transfer', id: t.id, title: 'Transfer to ' + (t.country || '?') + ' without a signed assessment: ' + (t.name || t.id), due: null, hours_left: null, late: true, page: 'pdpl-transfers.html', note: (t.gaps || []).slice(0, 2).join('; ') });
    if (ve && ve.summary && ve.summary.due) clocks.push({ kind: 'vendor', id: 'vendors', title: ve.summary.due + ' vendor review(s) due', due: null, hours_left: null, late: true, page: 'pdpl-processors.html', note: '' });
    if (re && re.totals && re.totals.overdue) clocks.push({ kind: 'retention', id: 'retention', title: re.totals.overdue + ' retention task(s) overdue', due: null, hours_left: null, late: true, page: 'pdpl-retention.html', note: '' });
    const ord = (c) => (c.late ? -1e9 : 0) + (c.hours_left == null ? 1e8 : c.hours_left);
    clocks.sort((a, b) => ord(a) - ord(b));

    // ---- requests: survival model for the deadline risk, Holt for the volume
    const reqs = (dsar && dsar.requests) || [], age = (r) => Math.max(0, Math.round((Date.parse((r.responded || today).slice(0, 10)) - Date.parse(r.received)) / DAY));
    const closed = reqs.filter((r) => r.responded), open = reqs.filter((r) => !r.responded && !r.outcome && !['refused', 'withdrawn', 'closed'].includes(r.stage));
    let risk, method;
    if (closed.length >= 8) {
      const S = km(reqs.filter((r) => r.received).map((r) => ({ t: age(r), event: !!r.responded })));
      method = 'Kaplan-Meier survival of the handling time over ' + reqs.length + ' requests (' + closed.length + ' answered)';
      risk = open.map((r) => { const a = age(r), dueIn = Math.max(0, r.days_left == null ? 0 : r.days_left), sNow = S(a), sDue = S(a + dueIn), p = sNow > 0 ? sDue / sNow : 1;
        return { id: r.id, ref: r.ref, type: r.type, days_left: r.days_left, age: a, p_miss: Math.round(p * 100) / 100, why: 'of requests still open after ' + a + ' days, ' + Math.round(p * 100) + ' % were not answered within ' + dueIn + ' more days' }; });
    } else {
      method = 'rule (only ' + closed.length + ' answered request(s) - the survival model needs 8): days left and blockers';
      risk = open.map((r) => { const bl = (r.blockers || []).length, d = r.days_left == null ? 30 : r.days_left, p = Math.min(0.95, Math.max(0.05, (bl * 0.15) + (d <= 3 ? 0.5 : d <= 7 ? 0.3 : d <= 14 ? 0.15 : 0.05) + (r.identity_verified ? 0 : 0.1)));
        return { id: r.id, ref: r.ref, type: r.type, days_left: r.days_left, age: age(r), p_miss: Math.round(p * 100) / 100, why: d + ' day(s) left, ' + bl + ' blocker(s)' + (r.identity_verified ? '' : ', identity not verified') }; });
    }
    risk.sort((a, b) => b.p_miss - a.p_miss);
    const months = {}; for (const r of reqs) if (r.received) { const m = String(r.received).slice(0, 7); months[m] = (months[m] || 0) + 1; }
    const mk = Object.keys(months).sort(), series = [];
    if (mk.length) { let [y, m] = mk[0].split('-').map(Number); const end = today.slice(0, 7); for (;;) { const k = y + '-' + String(m).padStart(2, '0'); series.push({ month: k, n: months[k] || 0 }); if (k >= end) break; m++; if (m > 12) { m = 1; y++; } if (series.length > 60) break; } }
    const fc = series.length >= 6 ? holt(series.map((s) => s.n), 3) : null;
    const answered = closed.map(age), within = closed.filter((r) => r.due && r.responded.slice(0, 10) <= r.due).length;

    // ---- activities: explainable risk
    const trBy = {}; for (const t of (tr && tr.transfers) || []) if (t.ropa_id) (trBy[t.ropa_id] = trBy[t.ropa_id] || []).push({ signed: !!(t.tia && t.tia.signed_by) });
    const gapsBy = {}; for (const a of (se && se.activities) || []) gapsBy[a.id] = a.gaps || 0;
    const acts = ((ro && ro.activities) || []).map((a) => Object.assign({ id: a.id, name: a.name, owner: a.owner || null, sensitive: a.sensitive || [], dpia: a.dpia, completeness: a.completeness }, activityRisk(a, { transfers: trBy[a.id], sensitiveGaps: gapsBy[a.id] })));
    acts.sort((a, b) => b.score - a.score);
    const kinds = ['health', 'biometric', 'genetic', 'criminal', 'religious', 'ethnic', 'credit'], heat = {};
    for (const a of acts) { const k = a.sensitive.find((s) => kinds.includes(s)) || (a.sensitive.length ? 'other sensitive' : 'not sensitive'); heat[k] = heat[k] || { high: 0, medium: 0, low: 0 }; heat[k][a.band]++; }

    return {
      at: new Date(t0).toISOString(),
      sources: src.map((s) => ({ name: s.name, ok: s.ok, reason: s.ok ? null : s.reason })),
      kpis: { clocks: clocks.length, late: clocks.filter((c) => c.late).length, requests_open: open.length, requests_high_risk: risk.filter((r) => r.p_miss >= 0.5).length,
        breaches_open: ((br && br.breaches) || []).filter((b) => !b.closed).length, activities: acts.length, activities_high: acts.filter((a) => a.band === 'high').length,
        on_time: closed.length ? Math.round(within / closed.length * 100) : null, median_days: answered.length ? answered.slice().sort((a, b) => a - b)[answered.length >> 1] : null },
      clocks: clocks.slice(0, 60),
      requests: { method, risk: risk.slice(0, 40), volume: series.slice(-24), forecast: fc, forecast_note: fc ? null : 'the volume forecast needs 6 months of requests (' + series.length + ' so far)' },
      activities: acts.slice(0, 50), heat,
    };
  }
  async function aiSummary(who) {
    const v = await view(who);
    return { kpis: v.kpis, sources: v.sources.filter((s) => !s.ok), clocks: v.clocks.slice(0, 15).map((c) => ({ kind: c.kind, title: c.title, due: c.due, hours_left: c.hours_left, late: c.late, note: c.note })),
      requests_at_risk: v.requests.risk.slice(0, 10), request_model: v.requests.method, forecast: v.requests.forecast,
      riskiest_activities: v.activities.slice(0, 10).map((a) => ({ name: a.name, score: a.score, band: a.band, why: a.why })) };
  }
  return { view, aiSummary };
}

function registerPdplCockpit(srv, app, C) {
  srv.route('GET', '/pdpl/cockpit', async (ctx) => { ctx.need('operator'); return C.view({ user: ctx.who.user, role: ctx.who.role }); });
}

module.exports = { createPdplCockpit, registerPdplCockpit, km, holt, activityRisk };
