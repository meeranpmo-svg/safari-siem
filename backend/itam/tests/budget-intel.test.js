// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Budget intelligence (engine/budget-intel.js) over SYNTHETIC lines, purchase orders and invoices, fixed clock in November:
// the Monte Carlo forecast (same seed = same answer; certain spend never below actual + committed; the prior said when there is
// little to learn from; an envelope far over its ceiling reads near 100 %); price suggestions from purchases of the same model and
// type, inflated, with the evidence; the exact knapsack beats a greedy pick and keeps "must"; unusual amounts; the overspend
// signal to Notification & Escalation; routes: operator reads, viewer refused, admin (a person) accepts a price - through the
// IT Budget's own decision, audited - a service identity refused, validation names the field; the advisor refuses a viewer.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const BI = require('../engine/budget-intel');

const FY = 2026, NOW = Date.parse('2026-11-05T09:00:00Z');
const A1 = { user: 'syed', role: 'admin' }, OP = { user: 'fin.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' }, SVC = { user: 'system:itam', role: 'admin' };

test('forecast: a distribution, reproducible, certain spend is a floor, prior stated when there is little to learn', () => {
  const row = (id, env, kind, plan, ptd, actual, committed) => ({ id, envelope: env, kind, plan, plan_to_date: ptd, actual, committed });
  const E = { rows: [row('a', 'it_ops', 'opex', 120, 100, 100, 0), row('b', 'it_ops', 'capex', 400, 400, 0, 0), row('c', 'cyber', 'opex', 200, 160, 240, 0)] };
  const f1 = BI.forecast(E, { it_ops: 1000, cyber: 210 }, 7), f2 = BI.forecast(E, { it_ops: 1000, cyber: 210 }, 7);
  assert.deepEqual(f1, f2, 'same data, same seed, same answer');
  assert.equal(f1.basis.learned, false); assert.match(f1.why, /stated prior/);
  const it = f1.envelopes.it_ops, cy = f1.envelopes.cyber;
  assert.ok(it.p10 <= it.p50 && it.p50 <= it.p90); assert.ok(it.p10 >= it.certain, 'never below actual + committed');
  assert.equal(cy.p_over_ceiling, 100, 'already spent more than the ceiling'); assert.equal(it.p_over_ceiling, 0);
  const many = { rows: Array.from({ length: 8 }, (_, i) => row('r' + i, 'it_ops', 'opex', 120, 100, 130, 0)) };
  const f3 = BI.forecast(many, { it_ops: 1000 }, 1);
  assert.equal(f3.basis.learned, true); assert.equal(f3.basis.median_ratio, 1.3); assert.match(f3.why, /learned from 8 line/);
  assert.ok(f3.envelopes.it_ops.p50 > 8 * 120, 'running 30 % hot projects over plan'); assert.ok(f3.envelopes.it_ops.p_over_plan > 90);
});

test('prices, the best mix and unusual amounts', () => {
  const lines = [{ id: 'eol:x', title: 'Replace FortiGate 100F (SYN)', priced: false, status: 'proposed', model: 'FortiGate 100F', asset_type: 'firewall', kind: 'capex', envelope: 'cyber', source: 'eol' }];
  const ev = [{ ref: 'PO-1', model: 'FortiGate 100F', type: 'firewall', kind: 'purchase', amount: 40000, year: 2024 }, { ref: 'PO-2', model: 'FortiGate 100F', type: 'firewall', kind: 'purchase', amount: 44000, year: 2026 }, { ref: 'PO-3', model: 'Other', type: 'switch', kind: 'purchase', amount: 9000, year: 2026 }];
  const p = BI.suggestPrices(lines, ev, { fy: 2026, inflation_pct: 5 });
  assert.equal(p.length, 1); assert.equal(p[0].n, 2); assert.match(p[0].how, /same model/); assert.match(p[0].why, /inflated to 2026 at 5%/);
  assert.equal(p[0].suggested, Math.round(((40000 * 1.1025) + 44000) / 2 / 100) * 100);
  assert.deepEqual(BI.suggestPrices(lines, ev.slice(2), { fy: 2026 }), [], 'one unrelated purchase is not evidence');
  // knapsack: ceiling 100k; must 40k; greedy (today) took a 50k should; the optimiser takes two 30k shoulds (more value)
  const L = [
    { id: 'm', envelope: 'it_ops', priced: true, amount: 40000, priority: 'must', status: 'approved', fit: 'fits', source: 'manual' },
    { id: 'big', envelope: 'it_ops', priced: true, amount: 50000, priority: 'should', status: 'proposed', fit: 'fits', source: 'manual' },
    { id: 's1', envelope: 'it_ops', priced: true, amount: 30000, priority: 'should', status: 'proposed', fit: 'over', source: 'manual' },
    { id: 's2', envelope: 'it_ops', priced: true, amount: 30000, priority: 'should', status: 'proposed', fit: 'over', source: 'manual' }];
  const o = BI.optimise(L, { it_ops: 100000 }, 2026).it_ops;
  assert.deepEqual(o.add.map((x) => x.id).sort(), ['s1', 's2']); assert.deepEqual(o.drop.map((x) => x.id), ['big']);
  assert.ok(o.optimal.value > o.today.value && o.optimal.amount <= 100000);
  assert.equal(BI.optimise([Object.assign({}, L[0], { amount: 200000 })], { it_ops: 100000 }, 2026).it_ops.must_over_ceiling, true);
  const typ = Array.from({ length: 9 }, (_, i) => ({ id: 'l' + i, title: 'Licence ' + i, priced: true, amount: 10000 + i * 500, source: 'licence', envelope: 'it_ops' }));
  const an = BI.anomalies(typ.concat({ id: 'odd', title: 'Typo line SYN', priced: true, amount: 10500000, source: 'licence', envelope: 'it_ops' }));
  assert.equal(an.length, 1); assert.equal(an[0].line_id, 'odd'); assert.match(an[0].why, /about \d+x the typical licence line/);
});

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const B = e.app.addons.budget || (e.app.addons.budget = require('../engine/budget').createBudget(e.app));
  B.putSettings({ fy: FY, envelopes: { it_ops: 300000, cyber: 150000 } }, A1);
  const mk = (o, status) => { B.saveLine(Object.assign({ area: o.envelope === 'cyber' ? 'security' : 'infrastructure', priority: 'must' }, o), A1); const id = B.build().lines.find((l) => l.title === o.title).id; if (status) B.decide(id, { status, note: 'synthetic' }, A1); return id; };
  return { e, call, B, mk };
}

test('routes: operator reads, viewer refused; admin person accepts a price (audited); overspend signal; validation', async (t) => {
  const { e, call, B, mk } = await setup(t);
  const edr = mk({ envelope: 'cyber', kind: 'opex', title: 'EDR subscription SYN', amount: 200000 }, 'approved');
  const un = mk({ envelope: 'it_ops', kind: 'capex', title: 'Replace core switch SYN', amount: null }, null);
  for (let m = 1; m <= 10; m++) assert.equal((await call('POST', '/budget-exec/actuals', { line_id: edr, date: FY + '-' + String(m).padStart(2, '0') + '-05', amount: 20000, reference: 'INV-SYN-' + m }, OP)).status, 200);
  let r = await call('GET', '/budget-intel', undefined, VW); assert.equal(r.status, 403);
  r = await call('GET', '/budget-intel', undefined, OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.unpriced, 1); assert.ok(r.json.forecast.envelopes.cyber.p_over_ceiling >= 80, JSON.stringify(r.json.forecast.envelopes.cyber));
  const sig = e.app.addons.budgetIntel.signals();
  assert.ok(sig.some((s) => s.fp === 'budget:overspend:cyber' && s.severity === 4 && /Cyber Security budget/.test(s.title)));
  // no purchase evidence -> no suggestion; the admin can still enter the price through this route
  r = await call('POST', '/budget-intel/prices/' + encodeURIComponent(un) + '/accept', {}, A1); assert.equal(r.status, 404);
  r = await call('POST', '/budget-intel/prices/' + encodeURIComponent(un) + '/accept', { amount: 'lots' }, A1); assert.equal(r.status, 400); assert.match(r.json.error, /amount/);
  r = await call('POST', '/budget-intel/prices/' + encodeURIComponent(un) + '/accept', { amount: 85000 }, OP); assert.equal(r.status, 403);
  r = await call('POST', '/budget-intel/prices/' + encodeURIComponent(un) + '/accept', { amount: 85000 }, SVC); assert.equal(r.status, 403); assert.match(r.json.error, /a person does/);
  r = await call('POST', '/budget-intel/prices/' + encodeURIComponent(un) + '/accept', { amount: 85000 }, A1); assert.equal(r.status, 200, r.text);
  const line = B.build().lines.find((l) => l.id === un); assert.equal(line.amount, 85000); assert.equal(line.priced, true);
  const au = e.app.store.auditTail(50); assert.ok(au.some((a) => a.action === 'budget.intel.price.accept' && a.by === 'syed') && au.some((a) => a.action === 'budget.decide' && a.target === un));
  r = await call('POST', '/budget-intel/ask', { question: 'Will cyber land within its ceiling?' }, VW); assert.equal(r.status, 403);
});
