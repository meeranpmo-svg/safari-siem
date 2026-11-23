// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Asset Purchasing (IT Assets -> Asset Purchasing, {P} = /api/itam). Every IT purchase from request to go-live, tracked against
 * the IT budget:
 *   order        PO number, title, vendor (name, contact, e-mail, phone), requester, department, budget line, CAPEX / OPEX,
 *                currency, product lines (product, model, part number, asset type, quantity, unit cost, warranty months)
 *   timeline     requested -> approved (four eyes: never the requester) -> ordered (PO date) -> delivered (partial allowed) ->
 *                installed -> live (go-live) -> invoiced -> paid -> closed; or cancelled. Each step is dated, by a person, audited.
 *   receive      at delivery the items become assets in the register with purchase {date, cost, po, supplier} and warranty
 *                {start = delivery, end = + warranty months}, serials entered at receipt - the Asset Data Autopilot starts from there
 *   budget       per budget line and envelope (IT Operations / Cyber Security): approved budget, COMMITTED (approved, not yet
 *                invoiced), SPENT (invoiced / paid), remaining, utilisation % and an end-of-year forecast at the current burn rate.
 *                An order over its line's remaining budget is flagged before approval.
 * Machine learning (from this register only, the count it learned from is shown; nothing is guessed without data):
 *   lead time    per vendor, median PO -> delivery days (>= 3 deliveries): the expected delivery when none was given, and LATE
 *                when today passes the expected date
 *   go-live lag  per asset type, median delivery -> go-live days: delivered-but-not-live orders past that (x1.5) are STUCK
 *   price        unit cost against the median of the same model / product on earlier orders: >= 25 % above is flagged
 *   vendors      scorecard - orders, on-time %, median lead time, spend
 *   GET  /purchasing                          operator   orders, budget utilisation, vendors, learned, alerts (costs: operator+)
 *   POST /purchasing/orders                   operator   create / update while requested                     audited
 *   POST /purchasing/orders/:id/approve       operator   a person other than the requester                    audited
 *   POST /purchasing/orders/:id/step          operator   {step, date, note?, amount?, invoice_no?}            audited
 *   POST /purchasing/orders/:id/receive       operator   {items:[{line, qty, serials[]}], date}  -> assets      audited
 */
const DAY = 86400000;
const STEPS = ['ordered', 'delivered', 'installed', 'live', 'invoiced', 'paid', 'closed', 'cancelled'];
const ORDER = { requested: 0, approved: 1, ordered: 2, delivered: 3, installed: 4, live: 5, invoiced: 6, paid: 7, closed: 8 };
const TYPES = ['server', 'workstation', 'laptop', 'network', 'storage', 'printer', 'phone', 'ups', 'mobile', 'peripheral', 'software', 'licence', 'other'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const d10 = (v) => (v ? String(v).slice(0, 10) : null);
const ms = (v) => { if (!v) return null; const t = Date.parse(String(v).slice(0, 10) + 'T00:00:00Z'); return Number.isFinite(t) ? t : null; };
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };
const r2 = (n) => Math.round(n * 100) / 100;
const low = (v) => String(v || '').trim().toLowerCase();

function createPurchasing(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const POs = () => store.collection('purchase_orders');
  const budget = () => { app.addons = app.addons || {}; if (app.addons.budget) return app.addons.budget; try { return (app.addons.budget = require('./budget').createBudget(app)); } catch (e) { return null; } };
  const today = () => new Date(now()).toISOString().slice(0, 10);
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const audit = (who, action, target, detail) => app.audit && app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'purchasing.' + action, target, detail });
  const total = (o) => r2((o.lines || []).reduce((n, l) => n + (l.qty || 0) * (l.unit_cost || 0), 0));
  const status = (o) => { if (o.cancelled) return 'cancelled'; let st = o.approved ? 'approved' : 'requested'; for (const k of ['ordered', 'delivered', 'installed', 'live', 'invoiced', 'paid', 'closed']) if (o.dates && o.dates[k]) st = k; return st; };

  function validLines(raw) {
    if (!Array.isArray(raw) || !raw.length) throw httpErr(400, 'lines: at least one product line');
    if (raw.length > 100) throw httpErr(400, 'lines: at most 100 product lines');
    return raw.map((l, i) => { const b = body(l).str('product', { required: true, max: 200 }).str('model', { max: 120 }).str('part_no', { max: 80 }).oneOf('type', TYPES)
      .int('qty', { required: true, min: 1, max: 100000 }).num('unit_cost', { required: true, min: 0, max: 1e10 }).int('warranty_months', { min: 0, max: 120 }).done();
      return Object.assign({ line: i + 1, type: b.type || 'other', received: 0 }, b); });
  }
  function save(input, who) {
    person(who, 'raise a purchase order');
    const src = input || {};
    const b = body(src).str('id', { max: 40 }).str('po_number', { max: 60 }).str('title', { required: true, max: 200 }).str('department', { max: 120 }).str('budget_line', { max: 120 })
      .oneOf('envelope', ['it_ops', 'cyber']).oneOf('kind', ['capex', 'opex'], { required: true }).str('currency', { max: 3, def: 'SAR' })
      .date('requested').date('expected_delivery').date('planned_go_live').str('notes', { max: 2000 }).done();
    if (!src.vendor || typeof src.vendor !== 'object' || Array.isArray(src.vendor)) throw httpErr(400, 'vendor must be an object {name, contact?, email?, phone?}');
    const v = body(src.vendor).str('name', { required: true, max: 200 }).str('contact', { max: 120 }).str('email', { max: 200 }).str('phone', { max: 40 }).str('vat', { max: 40 }).done();
    if (v.email && !/^[^\s@<>"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/.test(v.email)) throw httpErr(400, 'vendor.email is not an e-mail address');
    const lines = validLines(src.lines);
    if (b.budget_line) { const B = budget(); const bl = B && B.build().lines.find((x) => x.id === b.budget_line); if (!bl) throw httpErr(400, 'budget_line: no such line in the IT budget'); if (!b.envelope) b.envelope = bl.envelope; }
    let o = b.id ? POs().get(b.id) : null;
    if (b.id && !o) throw httpErr(404, 'order not found');
    if (o && status(o) !== 'requested') throw httpErr(409, 'an order can be edited only before it is approved (it is ' + status(o) + ')');
    if (b.po_number && POs().all((x) => x.po_number === b.po_number && (!o || x.id !== o.id)).length) throw httpErr(409, 'PO number ' + b.po_number + ' is already used');
    const at = new Date(now()).toISOString();
    if (!o) { const y = today().slice(0, 4), n = POs().all((x) => String(x.id).startsWith('PR-' + y)).length + 1; o = { id: 'PR-' + y + '-' + String(n).padStart(4, '0') + '-' + crypto.randomBytes(2).toString('hex'), requester: who.user, created_at: at, dates: {}, history: [], assets: [] }; }
    Object.assign(o, { po_number: b.po_number || o.po_number || null, title: b.title, department: b.department || null, budget_line: b.budget_line || null, envelope: b.envelope || 'it_ops', kind: b.kind, currency: (b.currency || 'SAR').toUpperCase(),
      vendor: v, lines, expected_delivery: b.expected_delivery || null, planned_go_live: b.planned_go_live || null, notes: b.notes || null, updated_at: at });
    o.dates.requested = b.requested || o.dates.requested || today();
    o.history.push({ at, by: who.user, step: o.history.length ? 'edited' : 'requested' });
    POs().put(o); audit(who, o.history.length > 1 ? 'edit' : 'request', o.id, { title: o.title, vendor: v.name, total: total(o), currency: o.currency, budget_line: o.budget_line });
    return pub(o);
  }
  function approve(id0, input, who) {
    person(who, 'approve a purchase order');
    const id = param(id0), o = POs().get(id); if (!o) throw httpErr(404, 'order not found');
    const b = body(input).str('note', { max: 500 }).bool('override_budget').done();
    if (status(o) !== 'requested') throw httpErr(409, 'already ' + status(o));
    if (o.requester === who.user) throw httpErr(403, 'four eyes: the requester cannot approve their own purchase');
    const util = view().budget.lines.find((x) => x.id === o.budget_line);
    if (util && util.remaining != null && total(o) > util.remaining && !b.override_budget) throw httpErr(409, 'over budget: this order (' + total(o) + ') is more than the remaining ' + util.remaining + ' on "' + util.title + '" - approve with override_budget and a note, or move it to another line');
    if (b.override_budget && !b.note) throw httpErr(400, 'note: say why the budget is overridden');
    o.approved = { by: who.user, at: new Date(now()).toISOString(), note: b.note || null, override_budget: !!b.override_budget };
    o.history.push({ at: o.approved.at, by: who.user, step: 'approved', note: b.note || null }); POs().put(o);
    audit(who, 'approve', o.id, { total: total(o), override_budget: !!b.override_budget, note: b.note || null });
    return pub(o);
  }
  function step(id0, input, who) {
    person(who, 'record a purchase step');
    const id = param(id0), o = POs().get(id); if (!o) throw httpErr(404, 'order not found');
    const b = body(input).oneOf('step', STEPS, { required: true }).date('date').str('note', { max: 500 }).num('amount', { min: 0, max: 1e11 }).str('invoice_no', { max: 60 }).str('po_number', { max: 60 }).done();
    const st = status(o);
    if (st === 'cancelled' || st === 'closed') throw httpErr(409, 'the order is ' + st);
    if (b.step === 'cancelled') { if (!b.note) throw httpErr(400, 'note: say why it is cancelled'); if (ORDER[st] >= ORDER.invoiced) throw httpErr(409, 'an invoiced order cannot be cancelled'); o.cancelled = true; }
    else {
      if (!o.approved) throw httpErr(409, 'approve the order first');
      if (b.step === 'ordered' && !(b.po_number || o.po_number)) throw httpErr(400, 'po_number: the PO number is needed when the order is placed');
      if (b.step === 'invoiced' && b.amount == null) throw httpErr(400, 'amount: the invoiced amount');
      const prevStep = { delivered: 'ordered', installed: 'delivered', live: 'delivered', invoiced: 'ordered', paid: 'invoiced', closed: 'paid' }[b.step];
      if (prevStep && !o.dates[prevStep]) throw httpErr(409, b.step + ' needs ' + prevStep + ' first');
      const d = b.date || today();
      if (d > today()) throw httpErr(400, 'date: a step is recorded when it happened, not in the future');
      if (prevStep && o.dates[prevStep] && d < o.dates[prevStep]) throw httpErr(400, 'date: ' + b.step + ' cannot be before ' + prevStep + ' (' + o.dates[prevStep] + ')');
      o.dates[b.step] = d;
      if (b.po_number) o.po_number = b.po_number;
      if (b.step === 'invoiced') { o.invoice = { amount: b.amount, invoice_no: b.invoice_no || null }; }
    }
    o.history.push({ at: new Date(now()).toISOString(), by: who.user, step: b.step, date: b.date || today(), note: b.note || null }); o.updated_at = new Date(now()).toISOString(); POs().put(o);
    audit(who, 'step', o.id, { step: b.step, date: b.date || today(), amount: b.amount, note: b.note || null });
    return pub(o);
  }
  function receive(id0, input, who) {
    person(who, 'receive purchased items');
    const id = param(id0), o = POs().get(id); if (!o) throw httpErr(404, 'order not found');
    if (!o.dates.ordered) throw httpErr(409, 'the order has not been placed yet');
    const src = input || {}, b = body(src).date('date').done(), d = b.date || today();
    if (d > today()) throw httpErr(400, 'date: not in the future');
    if (!Array.isArray(src.items) || !src.items.length) throw httpErr(400, 'items: what was received [{line, qty, serials[]}]');
    const made = [];
    for (const [i, it0] of src.items.entries()) {
      const it = body(it0).int('line', { required: true, min: 1, max: 100 }).int('qty', { required: true, min: 1, max: 1000 }).list('serials', { max: 1000, item: 'str', itemMax: 60 }).done();
      const l = o.lines.find((x) => x.line === it.line); if (!l) throw httpErr(400, 'items[' + i + '].line: no line ' + it.line);
      if (l.received + it.qty > l.qty) throw httpErr(400, 'items[' + i + '].qty: only ' + (l.qty - l.received) + ' of line ' + l.line + ' are still to come');
      if (it.serials && it.serials.length && it.serials.length !== it.qty) throw httpErr(400, 'items[' + i + '].serials: give one serial per item (' + it.qty + ') or none');
      if (l.type !== 'software' && l.type !== 'licence') {
        for (let k = 0; k < it.qty; k++) {
          const sn = it.serials ? it.serials[k] : null;
          if (sn && store.collection('assets').all((a) => String(a.serial || '').toLowerCase() === sn.toLowerCase()).length) throw httpErr(409, 'serial ' + sn + ' is already in the asset register');
          const w = l.warranty_months ? { start: d, end: (() => { const t = new Date(ms(d)); t.setUTCMonth(t.getUTCMonth() + l.warranty_months); return t.toISOString().slice(0, 10); })(), provider: o.vendor.name } : null;
          const r = app.assets.create({ name: l.product + (sn ? ' ' + sn : ' #' + (l.received + k + 1)), type: l.type, vendor: o.vendor.name, model: l.model || l.product, serial: sn || null, department: o.department || null, status: 'in_stock',
            purchase: { date: d, cost: l.unit_cost, po: o.po_number || o.id, supplier: o.vendor.name }, warranty: w, notes: 'Received on ' + (o.po_number || o.id) + ' line ' + l.line }, who, { source: 'manual' });
          const aid = (r.asset || r).id; made.push(aid); o.assets.push(aid);
        }
      }
      l.received += it.qty;
    }
    if (!o.dates.delivered) o.dates.delivered = d;
    o.fully_received = o.lines.every((l) => l.received >= l.qty);
    o.history.push({ at: new Date(now()).toISOString(), by: who.user, step: 'received', date: d, note: made.length + ' asset(s) created' }); POs().put(o);
    audit(who, 'receive', o.id, { date: d, assets: made.length, fully_received: o.fully_received });
    return Object.assign(pub(o), { created_assets: made });
  }

  function learn(list) {
    const lead = {}, golive = {}, price = {};
    for (const o of list) {
      if (o.dates.ordered && o.dates.delivered) (lead[low(o.vendor.name)] = lead[low(o.vendor.name)] || []).push((ms(o.dates.delivered) - ms(o.dates.ordered)) / DAY);
      if (o.dates.delivered && o.dates.live) { const t = (o.lines[0] || {}).type || 'other'; (golive[t] = golive[t] || []).push((ms(o.dates.live) - ms(o.dates.delivered)) / DAY); }
      for (const l of o.lines) { const k = low(l.model || l.product); (price[k] = price[k] || []).push({ id: o.id, c: l.unit_cost, at: o.dates.requested }); }
    }
    const M = (o, min) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, { n: v.length, days: v.length >= min ? Math.round(median(v)) : null }]));
    return { lead: M(lead, 3), golive: M(golive, 3), price };
  }
  function view() {
    const list = POs().all(), learned = learn(list), t = today(), T = ms(t), alerts = [];
    const orders = list.map((o) => {
      const p = pub(o), st = p.status, lv = learned.lead[low(o.vendor.name)];
      p.expected = o.expected_delivery ? { date: o.expected_delivery, source: 'given' } : o.dates.ordered && lv && lv.days != null ? { date: new Date(ms(o.dates.ordered) + lv.days * DAY).toISOString().slice(0, 10), source: 'learned: ' + o.vendor.name + ' delivers in ' + lv.days + ' days (median of ' + lv.n + ')' } : null;
      p.flags = [];
      if (['ordered'].includes(st) && p.expected && p.expected.date < t) p.flags.push({ kind: 'late', why: 'expected ' + p.expected.date + ' (' + p.expected.source + '), not delivered' });
      const gl = learned.golive[(o.lines[0] || {}).type || 'other'];
      if (['delivered', 'installed'].includes(st) && o.dates.delivered) { const age = (T - ms(o.dates.delivered)) / DAY;
        if (gl && gl.days != null && age > Math.max(14, gl.days * 1.5)) p.flags.push({ kind: 'stuck', why: 'delivered ' + Math.round(age) + ' days ago, not live - usually live in ' + gl.days + ' days (' + gl.n + ' orders)' });
        else if (o.planned_go_live && o.planned_go_live < t) p.flags.push({ kind: 'stuck', why: 'planned go-live ' + o.planned_go_live + ' passed' }); }
      for (const l of o.lines) { const hist = (learned.price[low(l.model || l.product)] || []).filter((x) => x.id !== o.id && String(x.at) < String(o.dates.requested)); if (hist.length >= 2) { const m = median(hist.map((x) => x.c)); if (m > 0 && l.unit_cost >= m * 1.25) p.flags.push({ kind: 'price', why: (l.model || l.product) + ' at ' + l.unit_cost + ' is ' + Math.round((l.unit_cost / m - 1) * 100) + ' % above the median ' + m + ' of ' + hist.length + ' earlier orders' }); } }
      if (o.invoice && Math.abs(o.invoice.amount - p.total) > Math.max(1, p.total * 0.02)) p.flags.push({ kind: 'invoice', why: 'invoiced ' + o.invoice.amount + ' vs order ' + p.total });
      for (const f of p.flags) alerts.push({ id: o.id, title: o.title, kind: f.kind, why: f.why });
      return p;
    }).sort((a, b) => (b.flags.length - a.flags.length) || String(b.dates.requested).localeCompare(String(a.dates.requested)));
    // budget utilisation
    const B = budget(), bv = B ? B.build() : null, fyStart = bv && bv.fy ? String(bv.fy).slice(0, 4) + '-01-01' : t.slice(0, 4) + '-01-01';
    const spentOf = (o) => (o.cancelled ? 0 : o.dates.invoiced ? (o.invoice ? o.invoice.amount : total(o)) : 0);
    const commitOf = (o) => (o.cancelled || o.dates.invoiced || !o.approved ? 0 : total(o));
    const lines = (bv ? bv.lines.filter((l) => l.status !== 'rejected') : []).map((l) => {
      const mine = list.filter((o) => o.budget_line === l.id), committed = r2(mine.reduce((n, o) => n + commitOf(o), 0)), spent = r2(mine.reduce((n, o) => n + spentOf(o), 0));
      const budgetAmt = l.status === 'approved' && l.priced ? l.amount : null;
      return { id: l.id, title: l.title, envelope: l.envelope, kind: l.kind, status: l.status, budget: budgetAmt, committed, spent, orders: mine.length,
        remaining: budgetAmt == null ? null : r2(budgetAmt - committed - spent), utilisation_pct: budgetAmt ? Math.round(100 * (committed + spent) / budgetAmt) : null };
    }).filter((l) => l.orders || l.budget != null);
    const elapsed = Math.max(1, (T - ms(fyStart)) / DAY), yearDays = 365;
    const envelopes = (bv ? bv.envelopes : []).map((e) => {
      const mine = list.filter((o) => (o.envelope || 'it_ops') === e.id), committed = r2(mine.reduce((n, o) => n + commitOf(o), 0)), spent = r2(mine.reduce((n, o) => n + spentOf(o), 0));
      const spentYtd = r2(mine.filter((o) => o.dates.invoiced && o.dates.invoiced >= fyStart).reduce((n, o) => n + spentOf(o), 0));
      const forecast = elapsed >= 30 ? r2(spentYtd / elapsed * yearDays) : null;
      return { id: e.id, name: e.name, envelope: e.envelope, approved: e.approved, committed, spent, remaining: r2(e.envelope - committed - spent), utilisation_pct: e.envelope ? Math.round(100 * (committed + spent) / e.envelope) : null,
        forecast_year: forecast, forecast_note: forecast == null ? 'needs 30 days of this year to forecast' : 'at the burn rate of the ' + Math.round(elapsed) + ' days so far' };
    });
    for (const l of lines) if (l.remaining != null && l.remaining < 0) alerts.push({ id: l.id, title: l.title, kind: 'budget', why: 'committed + spent ' + r2(l.committed + l.spent) + ' is over the approved ' + l.budget });
    // vendors
    const vend = {};
    for (const o of list) { const k = low(o.vendor.name), v = vend[k] = vend[k] || { vendor: o.vendor.name, orders: 0, spend: 0, delivered: 0, on_time: 0 }; v.orders++; v.spend = r2(v.spend + spentOf(o) + commitOf(o));
      if (o.dates.delivered) { v.delivered++; const exp = o.expected_delivery; if (!exp || o.dates.delivered <= exp) v.on_time++; } }
    const vendors = Object.values(vend).map((v) => Object.assign(v, { on_time_pct: v.delivered ? Math.round(100 * v.on_time / v.delivered) : null, lead_days: (learned.lead[low(v.vendor)] || {}).days ?? null })).sort((a, b) => b.spend - a.spend);
    const by = (s) => orders.filter((o) => o.status === s).length;
    return { at: new Date(now()).toISOString(), currency: (bv && bv.currency) || 'SAR', kpis: { orders: orders.length, open: orders.filter((o) => !['closed', 'cancelled', 'paid'].includes(o.status)).length, awaiting_approval: by('requested'), on_order: by('ordered'),
      delivered_not_live: by('delivered') + by('installed'), late: alerts.filter((a) => a.kind === 'late').length, committed: r2(envelopes.reduce((n, e) => n + e.committed, 0)), spent: r2(envelopes.reduce((n, e) => n + e.spent, 0)) },
      orders, budget: { fy: bv ? bv.fy : null, connected: !!bv, envelopes, lines }, vendors, alerts,
      learned: { lead_time: Object.entries(learned.lead).map(([k, v]) => Object.assign({ vendor: k }, v)), go_live: Object.entries(learned.golive).map(([k, v]) => Object.assign({ type: k }, v)) },
      budget_lines: bv ? bv.lines.filter((l) => l.status !== 'rejected').map((l) => ({ id: l.id, title: l.title, envelope: l.envelope, status: l.status })) : [],
      note: 'Spent = invoiced; committed = approved and not yet invoiced. Lead times, go-live lag and price checks are learned from these orders only, with the count shown.' };
  }
  function pub(o) { return Object.assign({}, o, { total: total(o), status: status(o) }); }
  return { view, save, approve, step, receive, status };
}

function registerPurchasing(srv, app, P) {
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/purchasing', (ctx) => { ctx.need('operator'); return P.view(); });
  srv.route('POST', '/purchasing/orders', (ctx) => { ctx.need('operator'); return P.save(ctx.body, who(ctx)); });
  srv.route('POST', '/purchasing/orders/:id/approve', (ctx) => { ctx.need('operator'); return P.approve(ctx.params.id, ctx.body, who(ctx)); });
  srv.route('POST', '/purchasing/orders/:id/step', (ctx) => { ctx.need('operator'); return P.step(ctx.params.id, ctx.body, who(ctx)); });
  srv.route('POST', '/purchasing/orders/:id/receive', (ctx) => { ctx.need('operator'); return P.receive(ctx.params.id, ctx.body, who(ctx)); });
}

module.exports = { createPurchasing, registerPurchasing, STEPS, TYPES };
