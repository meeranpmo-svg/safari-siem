// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { createIntelKit, robustZ } = require('./intel-kit');
const { isHuman } = require('./approve-scopes');
/*
 * Budget intelligence ({P} = /api/itam, IT Budget and Budgets (CAPEX / OPEX) pages). Thinks ahead over what the IT Budget
 * (engine/budget.js), Budget execution (engine/budget-exec.js), Purchasing (engine/purchasing.js) and the asset register already
 * record - nothing is invented, every figure says what it stands on, nothing is changed without a person.
 *   forecast   year-end spend per envelope as a distribution, not one number: a Monte Carlo of 2,000 runs (seeded, so it is the same
 *              each time for the same data). Actual and committed spend are certain; each line's plan still to come is scaled by an
 *              execution ratio drawn from this year's own lines ((actual + committed) / plan to date, lines with plan to date), and a
 *              CAPEX line not yet started slips to next year with the share of CAPEX lines already past their quarter with nothing
 *              spent (Beta(1,1)). Fewer than 5 lines to learn from = a stated prior (ratio 0.85-1.15, slip 10 %). P10 / P50 / P90 and
 *              the chance of going over the envelope's approved plan and over its ceiling.
 *   prices     a suggested price for every line marked "price needed", learned from this organisation's own purchases: purchase
 *              order lines and asset purchase costs of the same model, else the same type (licences: the same product words), the
 *              median, the range and the purchases it rests on, inflated to the fiscal year at the budget's own inflation rate.
 *              An administrator (a person) accepts it - it goes through the IT Budget's own decision, audited.
 *   optimise   the set of lines that covers the most within each envelope ceiling - an exact 0/1 knapsack (amounts in steps of
 *              10,000) over value = priority (must 100, should 40, could 10) x urgency (due in the first half +30 %) x kind
 *              (end of life / security +20 %); "must" lines always in. Compared with today's ranking: what it would add and drop,
 *              and the value gained. A proposal only.
 *   anomalies  priced lines whose amount is far from the others of the same source and envelope (robust z of log amount, 8+
 *              lines, |z| >= 3.5) - a typo, a wrong unit, or a line that needs a second look.
 *   signals    to Notification & Escalation: an envelope whose chance of going over its ceiling is 50 %+ (severity 3, 80 %+
 *              severity 4) once a quarter of the year has gone.
 *   ask        the AI budget advisor (operator, a person; engine/intel-kit.js: budget before / record after, redactSecrets,
 *              untrusted() tool output, UNTRUSTED_RULE) - it reads this module's figures and proposes; it changes nothing.
 *   GET  /budget-intel                         operator
 *   POST /budget-intel/prices/:id/accept       admin, a person   {amount?} - the suggested price (or the person's own) as the line's amount  audited
 *   POST /budget-intel/ask                     operator, a person {question}
 */
const PR_W = { must: 100, should: 40, could: 10 }, SIMS = 2000, STEP = 10000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const r0 = (x) => Math.round(x), r2 = (x) => Math.round(x * 100) / 100;
const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const pct = (a, p) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); return b[Math.min(b.length - 1, Math.floor(p * (b.length - 1)))]; };
function rng(seed) { let t = seed >>> 0; return () => { t += 0x6D2B79F5; let x = Math.imul(t ^ (t >>> 15), 1 | t); x ^= x + Math.imul(x ^ (x >>> 7), 61 | x); return ((x ^ (x >>> 14)) >>> 0) / 4294967296; }; }
const words = (s) => new Set(String(s || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').split(/\s+/).filter((w) => w.length > 2 && !/^(renewal|licence|license|seats?|support|replace|for|the|and)$/.test(w)));

/* ---- the forecast (pure: exec = budget-exec view, ceilings = {env: amount}) */
function forecast(exec, ceilings, seed) {
  const rows = exec.lines || exec.rows || [], R = rng(seed || 1);
  const ratios = rows.filter((r) => r.plan_to_date > 0).map((r) => (r.actual + r.committed) / r.plan_to_date).filter((x) => Number.isFinite(x)).map((x) => Math.max(0, Math.min(3, x)));
  const capPast = rows.filter((r) => r.kind === 'capex' && r.plan_to_date >= r.plan * 0.99 && r.plan > 0), slipped = capPast.filter((r) => r.actual + r.committed === 0).length;
  const learned = ratios.length >= 5, pSlip = capPast.length >= 5 ? (slipped + 1) / (capPast.length + 2) : 0.1;
  const draw = () => (learned ? ratios[Math.floor(R() * ratios.length)] : 0.85 + 0.3 * R());
  const envs = [...new Set(rows.map((r) => r.envelope))], out = {};
  for (const env of envs) {
    const L = rows.filter((r) => r.envelope === env), sure = L.reduce((n, r) => n + r.actual + r.committed, 0), plan = L.reduce((n, r) => n + r.plan, 0), sims = [];
    for (let i = 0; i < SIMS; i++) {
      let tot = sure;
      for (const r of L) {
        const rest = Math.max(0, r.plan - r.actual - r.committed); if (!rest) continue;
        if (r.kind === 'capex' && r.actual + r.committed === 0 && R() < pSlip) continue;   // slips to next year
        tot += rest * draw();
      }
      sims.push(tot);
    }
    const cap = Number(ceilings[env]) || 0;
    out[env] = { envelope: env, plan: r0(plan), certain: r0(sure), p10: r0(pct(sims, 0.1)), p50: r0(pct(sims, 0.5)), p90: r0(pct(sims, 0.9)), ceiling: cap,
      p_over_plan: Math.round(100 * sims.filter((x) => x > plan * 1.0001).length / SIMS), p_over_ceiling: cap ? Math.round(100 * sims.filter((x) => x > cap).length / SIMS) : null };
  }
  return { envelopes: out, sims: SIMS, basis: { learned, ratios: ratios.length, median_ratio: ratios.length ? r2(median(ratios)) : null, p_slip: r2(pSlip), capex_judged: capPast.length },
    why: learned ? 'execution ratio learned from ' + ratios.length + ' line(s) of this year (median ' + r2(median(ratios)) + '); CAPEX slip ' + Math.round(pSlip * 100) + '% from ' + capPast.length + ' line(s) past their quarter'
      : 'fewer than 5 lines with spend to learn from: a stated prior (execution 0.85-1.15, CAPEX slip 10 %) - the forecast sharpens as invoices come in' };
}

/* ---- price suggestions (pure) */
function suggestPrices(lines, evidence, opts) {
  const fy = opts.fy, infl = (Number(opts.inflation_pct) || 0) / 100, out = [];
  const inflate = (amt, year) => amt * Math.pow(1 + infl, Math.max(0, fy - (year || fy)));
  for (const l of lines.filter((x) => !x.priced && x.status !== 'rejected')) {
    const model = String(l.model || '').toLowerCase(), type = l.asset_type || null, wl = words(l.title);
    let pool = model ? evidence.filter((e) => e.model && e.model.toLowerCase() === model) : [], how = 'same model ' + l.model;
    if (pool.length < 2 && type) { pool = evidence.filter((e) => e.type === type && e.kind === (l.kind === 'opex' ? 'support' : 'purchase')); how = 'same asset type "' + type + '"'; }
    if (pool.length < 2) { const tl = String(l.title || '').toLowerCase(), types = [...new Set(evidence.map((e) => e.type).filter((t) => t && t !== 'other'))], t = types.find((x) => new RegExp('\\b' + x.replace(/[^a-z0-9]/g, '') + '(e?s)?\\b').test(tl));
      if (t) { pool = evidence.filter((e) => e.type === t); how = 'asset type "' + t + '" named in the title'; } }
    if (pool.length < 2 && l.source === 'licence') { pool = evidence.filter((e) => { const w = words(e.product); let k = 0; for (const x of wl) if (w.has(x)) k++; return k >= 1; }); how = 'purchases of the same product'; }
    if (pool.length < 2) continue;
    const vals = pool.map((e) => inflate(e.amount, e.year)).sort((a, b) => a - b);
    const sug = Math.round(median(vals) / 100) * 100;
    out.push({ line_id: l.id, title: l.title, envelope: l.envelope, suggested: sug, low: r0(pct(vals, 0.25)), high: r0(pct(vals, 0.75)), n: pool.length, how,
      evidence: pool.slice(0, 5).map((e) => ({ ref: e.ref, amount: e.amount, year: e.year })),
      why: 'median of ' + pool.length + ' purchase(s) of the ' + how + (infl ? ', inflated to ' + fy + ' at ' + opts.inflation_pct + '% a year' : '') });
  }
  return out;
}

/* ---- the budget mix (pure, exact 0/1 knapsack per envelope) */
function valueOf(l, fy) {
  let v = PR_W[l.priority] || 10; const why = [l.priority + ' ' + v];
  if (l.due && String(l.due) < fy + '-07-01') { v *= 1.3; why.push('due in the first half +30%'); }
  if (l.source === 'eol' || l.envelope === 'cyber') { v *= 1.2; why.push(l.source === 'eol' ? 'end of life +20%' : 'security +20%'); }
  return { v: r2(v), why };
}
function optimise(lines, ceilings, fy) {
  const out = {};
  for (const env of Object.keys(ceilings)) {
    const L = lines.filter((l) => l.envelope === env && l.priced && l.amount > 0 && l.status !== 'rejected' && l.status !== 'deferred');
    const cap = Math.floor((Number(ceilings[env]) || 0) / STEP), must = L.filter((l) => l.priority === 'must'), rest = L.filter((l) => l.priority !== 'must');
    const mustCost = must.reduce((n, l) => n + Math.ceil(l.amount / STEP), 0), room = Math.max(0, cap - mustCost);
    const items = rest.map((l) => ({ l, w: Math.ceil(l.amount / STEP), val: valueOf(l, fy) }));
    const W = Math.min(room, 20000), n = items.length, best = new Float64Array(W + 1), keep = [];
    for (let i = 0; i < n; i++) { const k = new Uint8Array(W + 1), w = items[i].w, val = items[i].val.v; if (w <= W) for (let c = W; c >= w; c--) if (best[c - w] + val > best[c]) { best[c] = best[c - w] + val; k[c] = 1; } keep.push(k); }
    const chosen = new Set(); let c = W; for (let i = n - 1; i >= 0; i--) if (keep[i][c]) { chosen.add(items[i].l.id); c -= items[i].w; }
    const today = new Set(L.filter((l) => l.fit === 'fits').map((l) => l.id)), opt = new Set([...must.map((l) => l.id), ...chosen]);
    const val = (set) => r2(L.filter((l) => set.has(l.id)).reduce((s, l) => s + valueOf(l, fy).v, 0)), amt = (set) => r0(L.filter((l) => set.has(l.id)).reduce((s, l) => s + l.amount, 0));
    const pick = (l) => ({ id: l.id, title: l.title, amount: l.amount, priority: l.priority, value: valueOf(l, fy).v, why: valueOf(l, fy).why.join(', ') });
    out[env] = { ceiling: Number(ceilings[env]) || 0, must_over_ceiling: mustCost > cap, today: { lines: today.size, amount: amt(today), value: val(today) }, optimal: { lines: opt.size, amount: amt(opt), value: val(opt) },
      add: L.filter((l) => opt.has(l.id) && !today.has(l.id)).map(pick), drop: L.filter((l) => today.has(l.id) && !opt.has(l.id)).map(pick),
      why: mustCost > cap ? 'the "must" lines alone exceed the ceiling - raise the envelope or re-grade a line' : 'the highest-value mix that fits ' + (Number(ceilings[env]) || 0).toLocaleString('en-US') + ': value ' + val(opt) + ' against ' + val(today) + ' for today\'s ranking' };
  }
  return out;
}

function anomalies(lines) {
  const out = [], groups = new Map();
  for (const l of lines.filter((x) => x.priced && x.amount > 0)) { const k = l.source + '|' + l.envelope; (groups.get(k) || groups.set(k, []).get(k)).push(l); }
  for (const L of groups.values()) {
    if (L.length < 8) continue;
    const logs = L.map((l) => Math.log10(l.amount));
    for (const l of L) { const z = robustZ(logs.filter((_, i) => L[i] !== l), Math.log10(l.amount)); if (z && Number.isFinite(z.z) && Math.abs(z.z) >= 3.5) out.push({ line_id: l.id, title: l.title, amount: l.amount, typical: r0(Math.pow(10, z.usual)), z: z.z, why: (z.z > 0 ? 'about ' + Math.round(l.amount / Math.pow(10, z.usual)) + 'x' : 'a fraction of') + ' the typical ' + l.source + ' line in this envelope (' + r0(Math.pow(10, z.usual)).toLocaleString('en-US') + ') - check the amount and its unit' }); }
  }
  return out.sort((a, b) => Math.abs(b.z) - Math.abs(a.z)).slice(0, 20);
}

function createBudgetIntel(app, opts = {}) {
  const now = opts.now || Date.now;
  const budget = () => { app.addons = app.addons || {}; if (!app.addons.budget) app.addons.budget = require('./budget').createBudget(app); return app.addons.budget; };
  const exec = () => { app.addons = app.addons || {}; if (!app.addons.budgetExec) app.addons.budgetExec = require('./budget-exec').createBudgetExec(app); return app.addons.budgetExec; };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  function evidence() {
    const out = [], st = app.store;
    for (const o of st.collection('purchase_orders').all((x) => !x.cancelled)) for (const l of o.lines || []) if (l.unit_cost > 0) out.push({ kind: 'purchase', ref: o.po_number || o.id, product: l.product, model: l.model || '', type: l.type || 'other', amount: l.unit_cost, year: Number(String((o.dates || {}).ordered || (o.dates || {}).approved || o.created || '').slice(0, 4)) || null });
    for (const a of (app.assets ? app.assets.all() : st.collection('assets').all())) if (a.purchase && Number(a.purchase.cost) > 0) out.push({ kind: 'purchase', ref: a.asset_tag || a.name || a.id, product: [a.vendor, a.model].filter(Boolean).join(' '), model: a.model || '', type: a.type, amount: Number(a.purchase.cost), year: Number(String(a.purchase.date || '').slice(0, 4)) || null });
    return out;
  }
  function view() {
    const B = budget().build(), st = B.settings || {}, fy = Number(st.fy || B.fy), ceilings = st.envelopes || {};
    let E = null; try { E = exec().view(); } catch (e) { E = null; }
    const assetById = new Map((app.assets ? app.assets.all() : app.store.collection('assets').all()).map((a) => [a.id, a]));
    const lines = (B.lines || []).map((l) => { const a = l.ref && (l.ref.asset || l.ref.asset_id) ? assetById.get(l.ref.asset || l.ref.asset_id) : (String(l.id).match(/^(eol|sup):([^:]+):/) ? assetById.get(String(l.id).split(':')[1]) : null); return Object.assign({}, l, a ? { model: a.model, asset_type: a.type } : {}); });
    const fc = E && E.started && (E.lines || []).length ? forecast(E, ceilings, fy) : null;
    const prices = suggestPrices(lines, evidence(), { fy, inflation_pct: st.inflation_pct });
    return { generated_at: new Date(now()).toISOString(), fy, currency: st.currency || 'SAR', elapsed_pct: E ? E.elapsed_pct : null,
      forecast: fc || { envelopes: {}, why: E && !E.started ? 'the fiscal year ' + fy + ' has not started - the forecast begins with its first invoices' : 'no approved, priced line is being executed yet' },
      prices, unpriced: lines.filter((l) => !l.priced && l.status !== 'rejected').length, unpriced_lines: lines.filter((l) => !l.priced && l.status !== 'rejected').slice(0, 50).map((l) => ({ id: l.id, title: l.title, envelope: l.envelope, priority: l.priority, source: l.source, suggested: (prices.find((p) => p.line_id === l.id) || {}).suggested || null })), optimise: optimise(lines, ceilings, fy), anomalies: anomalies(lines),
      note: 'Every figure comes from the budget, its execution, purchase orders and the asset register; nothing is changed until a person accepts it.' };
  }
  function signals() {
    const out = []; let v; try { v = view(); } catch (e) { return out; }
    if ((v.elapsed_pct || 0) < 25) return out;
    for (const f of Object.values(v.forecast.envelopes || {})) if (f.p_over_ceiling != null && f.p_over_ceiling >= 50)
      out.push({ fp: 'budget:overspend:' + f.envelope, source: 'budget', title: (f.envelope === 'cyber' ? 'Cyber Security' : 'IT Operations') + ' budget: ' + f.p_over_ceiling + '% chance of going over the ceiling', severity: f.p_over_ceiling >= 80 ? 4 : 3, condition: true,
        text: 'Year-end forecast P50 ' + f.p50.toLocaleString('en-US') + ' (P90 ' + f.p90.toLocaleString('en-US') + ') against a ceiling of ' + f.ceiling.toLocaleString('en-US') + '. ' + v.forecast.why + '. Open IT Assets -> Budgets.' });
    return out;
  }
  function acceptPrice(id, b0, who) {
    const b = body(b0 || {}).num('amount', { min: 1, max: 1e10 }).done();
    if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot price a budget line: a person does');
    const v = view(), p = v.prices.find((x) => x.line_id === id);
    if (!p && b.amount == null) throw httpErr(404, 'no price suggestion for this line - enter the amount on the IT Budget page');
    const amount = b.amount != null ? b.amount : p.suggested;
    budget().decide(id, { amount, note: p ? 'priced from ' + p.n + ' purchase(s): ' + p.why : 'priced by ' + who.user }, who);
    audit(who, 'budget.intel.price.accept', id, { amount, suggested: p ? p.suggested : null, n: p ? p.n : 0 });
    return { ok: true, line_id: id, amount };
  }
  const K = createIntelKit(app, { key: 'budget-intel', feature: 'itam.budget-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the IT budget advisor for ' + ZYB_ORG.name + ' (Saudi Arabia, SAR). Read the budget through the budget_intelligence tool and answer the CIO, the IT finance controller or the CISO: will each envelope (IT Operations, Cyber Security) land within its ceiling and how sure we are, which lines need a price and what the organisation paid before, which lines the best mix would add or drop and why, and unusual amounts. Use only what the tool returns and say what it rests on. You cannot change the budget: an administrator decides.'),
    tools: [{ name: 'budget_intelligence', description: 'The year-end forecast per envelope (P10 / P50 / P90, chance of overspend, what it is learned from), price suggestions with their purchase evidence, the optimal budget mix against today\'s ranking, unusual line amounts.', run: () => { const v = view(); return { fy: v.fy, currency: v.currency, elapsed_pct: v.elapsed_pct, forecast: v.forecast, prices: v.prices.slice(0, 20).map((p) => ({ title: p.title, suggested: p.suggested, low: p.low, high: p.high, n: p.n, why: p.why })), unpriced: v.unpriced, unpriced_lines: v.unpriced_lines.map((l) => ({ title: l.title, envelope: l.envelope, priority: l.priority, suggested: l.suggested })), optimise: v.optimise, anomalies: v.anomalies }; } }] });
  return { view, signals, acceptPrice, ask: K.ask, TOOLS: K.TOOLS };
}

function registerBudgetIntel(srv, app, opts) {
  const X = createBudgetIntel(app, opts || {});
  (app.addons = app.addons || {}).budgetIntel = X;
  srv.route('GET', '/budget-intel', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return X.view(); });
  srv.route('POST', '/budget-intel/prices/:id/accept', (ctx) => { ctx.need('admin'); return X.acceptPrice(param(ctx.params.id.replace(/[^A-Za-z0-9_.:-]/g, ''), 'id'), ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/budget-intel/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
  return X;
}

module.exports = { createBudgetIntel, registerBudgetIntel, forecast, suggestPrices, optimise, anomalies };
