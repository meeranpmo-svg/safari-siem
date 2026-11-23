// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Budget execution (IT Assets -> Budgets (CAPEX / OPEX), {P} = /api/itam). Tracks the APPROVED lines of the IT Budget
 * (engine/budget.js) through their fiscal year with real spend - nothing seeded, nothing estimated as spend:
 *   plan        each approved, priced line; phased by quarter: an administrator's phasing, else the default (OPEX evenly over
 *               the four quarters, CAPEX in the quarter of its due date, or Q2 when it has none) - labelled as the default
 *   committed   purchase orders approved against the line and not yet invoiced (engine/purchasing.js)
 *   actual      purchase orders invoiced against the line, plus invoices recorded here for spend that does not go through a
 *               PO (telecom, colocation, subscriptions paid directly) - each by a person, audited, voidable with a reason
 *   per line, envelope, kind and quarter: plan, plan to date, actual, committed, remaining (plan - actual - committed),
 *   utilisation, variance to date (actual + committed - plan to date)
 *   forecast    year end = actual + committed + plan of the quarters not started; for OPEX also the run rate (actual / elapsed
 *               share of the year) - the higher of the two is used for the overspend warning
 *   warnings    overspend risk (forecast > plan + 5 %), lapse risk (after mid-year, actual + committed < 50 % of plan to date),
 *               spend with no plan (actuals on a line that is not approved), an invoice > 3 x the line's median invoice
 *   GET  /budget-exec                         viewer (same as the IT Budget page)
 *   POST /budget-exec/actuals                 operator, a person   {line_id, date, amount, reference, note}
 *   POST /budget-exec/actuals/:id/void        admin, a person      {reason}
 *   PUT  /budget-exec/lines/:id/phasing       admin, a person      {q1, q2, q3, q4} must add up to the line's plan
 */
const crypto = require('node:crypto');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const r2 = (x) => Math.round(x * 100) / 100;
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };

function createBudgetExec(app, opts = {}) {
  const now = opts.now || Date.now;
  const ACT = app.store.collection('budget_actuals'), PH = app.store.collection('budget_phasing');
  const budget = () => { app.addons = app.addons || {}; if (!app.addons.budget) app.addons.budget = require('./budget').createBudget(app); return app.addons.budget; };
  const POs = () => app.store.collection('purchase_orders');
  const total = (o) => r2((o.lines || []).reduce((n, l) => n + (l.qty || 0) * (l.unit_cost || 0), 0));
  const qOf = (iso) => Math.floor((Number(String(iso).slice(5, 7)) - 1) / 3);   // 0..3, fiscal year = calendar year
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  function view() {
    const B = budget().build(), fy = Number(B.settings && B.settings.fy || B.fy), T = now(), today = new Date(T).toISOString().slice(0, 10);
    const y0 = Date.parse(fy + '-01-01T00:00:00Z'), y1 = Date.parse((fy + 1) + '-01-01T00:00:00Z');
    const elapsed = Math.max(0, Math.min(1, (T - y0) / (y1 - y0))), started = T >= y0, qNow = T < y0 ? -1 : T >= y1 ? 4 : qOf(today);
    const lines = (B.lines || []), byId = new Map(lines.map((l) => [l.id, l]));
    const acts = ACT.all((a) => !a.void && String(a.date).slice(0, 4) === String(fy));
    const pos = POs().all((o) => o.budget_line && !o.cancelled);
    const rows = [], warn = [];
    const plan = lines.filter((l) => l.status === 'approved' && l.priced && l.amount > 0);
    for (const l of plan) {
      const ph = PH.get(l.id); let q, phased;
      if (ph && Math.abs(ph.q.reduce((n, x) => n + x, 0) - l.amount) <= 1) { q = ph.q; phased = 'set by ' + ph.by; }
      else if (l.kind === 'opex') { q = [0, 1, 2, 3].map(() => r2(l.amount / 4)); q[3] = r2(l.amount - q[0] * 3); phased = 'default: evenly over the year'; }
      else { const qi = l.due && String(l.due).slice(0, 4) === String(fy) ? qOf(l.due) : 1; q = [0, 0, 0, 0]; q[qi] = l.amount; phased = 'default: in Q' + (qi + 1) + (l.due ? ' (due ' + String(l.due).slice(0, 10) + ')' : ' (no due date)'); }
      const mine = pos.filter((o) => o.budget_line === l.id), la = acts.filter((a) => a.line_id === l.id);
      const committed = r2(mine.reduce((n, o) => n + (o.dates.invoiced || !o.approved ? 0 : total(o)), 0));
      const poAct = mine.filter((o) => o.dates.invoiced && String(o.dates.invoiced).slice(0, 4) === String(fy)).map((o) => ({ date: String(o.dates.invoiced).slice(0, 10), amount: o.invoice ? o.invoice.amount : total(o), ref: o.po_number || o.id, src: 'po' }));
      const inv = poAct.concat(la.map((a) => ({ date: a.date, amount: a.amount, ref: a.reference, src: 'invoice', id: a.id })));
      const actual = r2(inv.reduce((n, x) => n + x.amount, 0));
      const aq = [0, 1, 2, 3].map((i) => r2(inv.filter((x) => qOf(x.date) === i).reduce((n, x) => n + x.amount, 0)));
      const planToDate = r2(q.reduce((n, x, i) => n + (i < qNow ? x : i === qNow ? x * Math.min(1, ((T - Date.parse(fy + '-' + String(i * 3 + 1).padStart(2, '0') + '-01T00:00:00Z')) / (91.3 * DAY))) : 0), 0));
      const future = r2(q.reduce((n, x, i) => n + (i > qNow ? x : 0), 0));
      const fcPlan = r2(actual + committed + future), fcRun = l.kind === 'opex' && elapsed > 0.1 ? r2(actual / elapsed) : null, fc = Math.max(fcPlan, fcRun || 0);
      const row = { id: l.id, title: l.title, envelope: l.envelope, kind: l.kind, source: l.source, plan: l.amount, q, phasing: phased, actual_q: aq, plan_to_date: planToDate, actual, committed,
        remaining: r2(l.amount - actual - committed), utilisation_pct: Math.round(100 * (actual + committed) / l.amount), variance: r2(actual + committed - planToDate),
        forecast: fc, forecast_basis: fcRun && fcRun > fcPlan ? 'run rate: ' + Math.round(elapsed * 100) + ' % of the year gone, spend so far scaled to 12 months' : 'actual + committed + plan of the quarters not started',
        invoices: inv.sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 50), orders: mine.length, flags: [] };
      if (fc > l.amount * 1.05) row.flags.push({ kind: 'overspend', why: 'forecast ' + Math.round(fc) + ' over the plan ' + Math.round(l.amount) + ' (' + row.forecast_basis + ')' });
      if (started && elapsed > 0.5 && planToDate > 0 && actual + committed < planToDate * 0.5) row.flags.push({ kind: 'lapse', why: 'only ' + Math.round(100 * (actual + committed) / planToDate) + ' % of the plan to date is spent or committed' });
      const md = median(inv.map((x) => x.amount)); if (inv.length >= 4) for (const x of inv) if (x.amount > md * 3) row.flags.push({ kind: 'unusual', why: 'invoice ' + (x.ref || '') + ' of ' + Math.round(x.amount) + ' is over 3 x this line\'s median (' + Math.round(md) + ')' });
      for (const f of row.flags) warn.push(Object.assign({ line_id: l.id, title: l.title }, f));
      rows.push(row);
    }
    // spend on lines that are not approved
    const planned = new Set(plan.map((l) => l.id));
    for (const a of acts) if (!planned.has(a.line_id)) warn.push({ line_id: a.line_id, title: (byId.get(a.line_id) || {}).title || a.line_id, kind: 'unplanned', why: 'invoice ' + (a.reference || a.id) + ' recorded on a line that is not approved' });
    for (const o of pos) if (!planned.has(o.budget_line) && o.approved) warn.push({ line_id: o.budget_line, title: (byId.get(o.budget_line) || {}).title || o.budget_line, kind: 'unplanned', why: 'PO ' + (o.po_number || o.id) + ' approved against a line that is not approved' });
    const sum = (L, k) => r2(L.reduce((n, r) => n + r[k], 0));
    const group = (key, val) => { const L = rows.filter((r) => r[key] === val); return { plan: sum(L, 'plan'), plan_to_date: sum(L, 'plan_to_date'), actual: sum(L, 'actual'), committed: sum(L, 'committed'), remaining: sum(L, 'remaining'), forecast: sum(L, 'forecast'), lines: L.length }; };
    const envelopes = (B.envelopes || []).map((e) => Object.assign({ id: e.id, name: e.name, envelope: e.envelope }, group('envelope', e.id), { capex: sumKind(e.id, 'capex'), opex: sumKind(e.id, 'opex') }));
    function sumKind(env, k) { const L = rows.filter((r) => r.envelope === env && r.kind === k); return { plan: sum(L, 'plan'), actual: sum(L, 'actual'), committed: sum(L, 'committed'), forecast: sum(L, 'forecast') }; }
    const quarters = [0, 1, 2, 3].map((i) => ({ q: 'Q' + (i + 1), plan: r2(rows.reduce((n, r) => n + r.q[i], 0)), actual: r2(rows.reduce((n, r) => n + r.actual_q[i], 0)), state: i < qNow ? 'closed' : i === qNow ? 'current' : 'not started' }));
    const months = []; for (let m = 1; m <= 12; m++) { const k = fy + '-' + String(m).padStart(2, '0'); months.push({ month: k, actual: r2(rows.reduce((n, r) => n + r.invoices.filter((x) => String(x.date).slice(0, 7) === k).reduce((s, x) => s + x.amount, 0), 0)) }); }
    let cum = 0; for (const m of months) { cum += m.actual; m.cumulative = r2(cum); }
    const tot = { plan: sum(rows, 'plan'), plan_to_date: sum(rows, 'plan_to_date'), actual: sum(rows, 'actual'), committed: sum(rows, 'committed'), remaining: sum(rows, 'remaining'), forecast: sum(rows, 'forecast') };
    return { at: new Date(T).toISOString(), fy, currency: (B.settings && B.settings.currency) || 'SAR', started, elapsed_pct: Math.round(elapsed * 100), quarter: qNow >= 0 && qNow < 4 ? 'Q' + (qNow + 1) : null,
      totals: Object.assign(tot, { utilisation_pct: tot.plan ? Math.round(100 * (tot.actual + tot.committed) / tot.plan) : null, variance: r2(tot.actual + tot.committed - tot.plan_to_date) }),
      envelopes, quarters, months, lines: rows.sort((a, b) => b.flags.length - a.flags.length || b.plan - a.plan), warnings: warn,
      not_approved: lines.filter((l) => l.status !== 'approved' && l.status !== 'rejected').length, unpriced_approved: lines.filter((l) => l.status === 'approved' && !l.priced).length,
      line_choices: lines.filter((l) => l.status !== 'rejected').map((l) => ({ id: l.id, title: l.title, envelope: l.envelope, status: l.status })),
      note: 'Plan = the approved lines of the IT Budget. Spend = purchase orders and invoices recorded against them; nothing is estimated as spend. The forecast is a projection, not a commitment.' };
  }
  function addActual(input, who) {
    person(who, 'record spend');
    const b = body(input || {}).str('line_id', { required: true, max: 160 }).date('date', { required: true, notFuture: true, now: now() }).num('amount', { required: true, min: 0.01, max: 1e9 }).str('reference', { required: true, max: 80 }).str('note', { max: 300 }).done();
    const line = (budget().build().lines || []).find((l) => l.id === b.line_id);
    if (!line) throw httpErr(400, 'line_id: no such line in the IT budget');
    if (ACT.all((a) => !a.void && a.line_id === b.line_id && a.reference.toLowerCase() === b.reference.toLowerCase()).length) throw httpErr(409, 'reference: invoice ' + b.reference + ' is already recorded on this line');
    const rec = { id: 'bx_' + crypto.randomBytes(5).toString('hex'), line_id: b.line_id, date: b.date, amount: r2(b.amount), reference: b.reference, note: b.note || null, by: who.user, at: new Date(now()).toISOString(), void: false };
    ACT.put(rec);
    app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.actual.add', target: b.line_id, detail: { id: rec.id, date: rec.date, amount: rec.amount, reference: rec.reference, line_status: line.status } });
    return { ok: true, actual: rec, warning: line.status !== 'approved' ? 'this line is not approved - the spend is shown as unplanned' : null };
  }
  function voidActual(id, input, who) {
    person(who, 'void spend');
    const b = body(input || {}).str('reason', { required: true, max: 300 }).done();
    const a = ACT.get(id); if (!a) throw httpErr(404, 'spend record not found'); if (a.void) throw httpErr(409, 'already void');
    ACT.put(Object.assign({}, a, { void: true, void_by: who.user, void_at: new Date(now()).toISOString(), void_reason: b.reason }));
    app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.actual.void', target: a.line_id, detail: { id, amount: a.amount, reference: a.reference, reason: b.reason } });
    return { ok: true };
  }
  function setPhasing(id, input, who) {
    person(who, 'change the phasing');
    const b = body(input || {}).num('q1', { required: true, min: 0 }).num('q2', { required: true, min: 0 }).num('q3', { required: true, min: 0 }).num('q4', { required: true, min: 0 }).done();
    const line = (budget().build().lines || []).find((l) => l.id === id);
    if (!line) throw httpErr(404, 'no such line in the IT budget');
    if (line.status !== 'approved' || !line.priced) throw httpErr(409, 'only an approved, priced line is phased');
    const q = [b.q1, b.q2, b.q3, b.q4].map(r2), s = r2(q.reduce((n, x) => n + x, 0));
    if (Math.abs(s - line.amount) > 1) throw httpErr(400, 'q1: the quarters add up to ' + s + ', the line is ' + line.amount);
    const prev = PH.get(id);
    PH.put({ id, q, by: who.user, at: new Date(now()).toISOString() });
    app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.phasing', target: id, detail: { from: prev ? prev.q : 'default', to: q } });
    return { ok: true, q };
  }
  return { view, addActual, voidActual, setPhasing };
}

function registerBudgetExec(srv, app, X) {
  srv.route('GET', '/budget-exec', (ctx) => { ctx.need('viewer'); return X.view(); });
  srv.route('POST', '/budget-exec/actuals', (ctx) => { ctx.need('operator'); return X.addActual(ctx.body, ctx.who); });
  srv.route('POST', '/budget-exec/actuals/:id/void', (ctx) => { ctx.need('admin'); return X.voidActual(ctx.params.id, ctx.body, ctx.who); });
  srv.route('PUT', '/budget-exec/lines/:id/phasing', (ctx) => { ctx.need('admin'); return X.setPhasing(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createBudgetExec, registerBudgetExec };
