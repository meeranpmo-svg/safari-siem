// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Budget execution (engine/budget-exec.js) over SYNTHETIC approved lines, purchase orders and invoices, with a fixed clock in
// November of the fiscal year: default phasing (OPEX evenly, CAPEX in its due quarter); an admin's phasing must add up to the
// plan; PO commitments and invoiced POs plus recorded invoices make actual and committed; remaining, variance, year-end forecast
// (plan path and OPEX run rate); warnings for overspend, lapse, an unusual invoice and spend on a line that is not approved;
// recording needs a person and a reference, refuses a duplicate invoice and a future date, voiding needs an admin and a reason;
// every write audited; viewers read; nothing approved = nothing invented.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const FY = 2026, NOW = Date.parse('2026-11-05T09:00:00Z');
const A1 = { user: 'syed', role: 'admin' }, A2 = { user: 'cfo.syn', role: 'admin' }, OP = { user: 'fin.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const B = e.app.addons.budget || (e.app.addons.budget = require('../engine/budget').createBudget(e.app));
  B.putSettings({ fy: FY }, A1);
  const mk = (o, status) => { B.saveLine(Object.assign({ area: o.envelope === 'cyber' ? 'security' : 'infrastructure' }, o), A1); const id = B.build().lines.find((l) => l.title === o.title).id; if (status) B.decide(id, { status, note: 'synthetic' }, A1); return id; };
  const ids = {
    wan: mk({ envelope: 'it_ops', kind: 'opex', title: 'WAN links SYN', amount: 120000 }, 'approved'),
    srv: mk({ envelope: 'it_ops', kind: 'capex', title: 'Server refresh SYN', amount: 400000, due: FY + '-08-15' }, 'approved'),
    edr: mk({ envelope: 'cyber', kind: 'opex', title: 'EDR subscription SYN', amount: 200000 }, 'approved'),
    idea: mk({ envelope: 'it_ops', kind: 'capex', title: 'Unapproved idea SYN', amount: 50000 }, null),
  };
  return { e, call, ids, B };
}
const L = (v, id) => v.lines.find((l) => l.id === id);

test('phasing, POs and invoices, variance, forecast and warnings', async (t) => {
  const { e, call, ids } = await setup(t);
  // a purchase order against the server line: approved (committed) and an invoiced one (actual)
  const POC = e.app.store.collection('purchase_orders');
  POC.put({ id: 'PR-SYN-1', po_number: 'PO-SYN-1', budget_line: ids.srv, approved: { by: 'cfo.syn' }, lines: [{ qty: 2, unit_cost: 100000 }], dates: { requested: '2026-07-01' } });
  POC.put({ id: 'PR-SYN-2', po_number: 'PO-SYN-2', budget_line: ids.srv, approved: { by: 'cfo.syn' }, lines: [{ qty: 1, unit_cost: 150000 }], dates: { requested: '2026-06-01', invoiced: '2026-09-10' }, invoice: { amount: 150000 } });
  // WAN invoices monthly at 10,000 (on plan) ; EDR paid 240,000 already (over its 200,000 plan)
  for (let m = 1; m <= 10; m++) assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: FY + '-' + String(m).padStart(2, '0') + '-05', amount: 10000, reference: 'STC-SYN-' + m }, OP)).status, 200);
  assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: FY + '-10-20', amount: 45000, reference: 'STC-SYN-X' }, OP)).status, 200);
  assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.edr, date: FY + '-02-01', amount: 240000, reference: 'EDR-SYN-1' }, OP)).status, 200);
  const r = await call('POST', '/budget-exec/actuals', { line_id: ids.idea, date: FY + '-03-01', amount: 5000, reference: 'IDEA-1' }, OP);
  assert.equal(r.status, 200); assert.match(r.json.warning, /not approved/);
  const v = (await call('GET', '/budget-exec', undefined, VW)).json;
  assert.equal(v.fy, FY); assert.equal(v.quarter, 'Q4'); assert.ok(v.elapsed_pct > 80 && v.elapsed_pct < 90);
  const w = L(v, ids.wan), s = L(v, ids.srv), d = L(v, ids.edr);
  assert.deepEqual(w.q, [30000, 30000, 30000, 30000]); assert.match(w.phasing, /evenly/);
  assert.deepEqual(s.q, [0, 0, 400000, 0]); assert.match(s.phasing, /Q3/);
  assert.equal(s.committed, 200000); assert.equal(s.actual, 150000); assert.equal(s.remaining, 50000); assert.equal(s.orders, 2);
  assert.equal(w.actual, 145000); assert.equal(w.actual_q[3], 55000);
  assert.ok(w.flags.some((f) => f.kind === 'overspend' && /run rate/.test(f.why)), 'WAN run rate projects past its plan');
  assert.ok(w.flags.some((f) => f.kind === 'unusual' && /STC-SYN-X/.test(f.why)), 'the 45,000 invoice is unusual for this line');
  assert.ok(d.flags.some((f) => f.kind === 'overspend'), 'EDR already over plan');
  assert.ok(v.warnings.some((x) => x.kind === 'unplanned' && x.line_id === ids.idea), 'spend on a line that is not approved');
  assert.ok(!v.lines.some((l) => l.id === ids.idea), 'an unapproved line is not plan');
  const it = v.envelopes.find((x) => x.id === 'it_ops'); assert.equal(it.plan, 520000); assert.equal(it.capex.plan, 400000);
  assert.equal(v.quarters[2].plan, 480000, 'server 400k + WAN 30k + EDR 50k'); assert.equal(v.quarters[3].state, 'current');
  assert.equal(v.months[9].month, FY + '-10'); assert.equal(v.months[11].cumulative, v.totals.actual);
  assert.equal(v.totals.plan, 720000);
});

test('phasing by an admin; recording rules; void; roles; audit', async (t) => {
  const { e, call, ids } = await setup(t);
  assert.equal((await call('PUT', '/budget-exec/lines/' + encodeURIComponent(ids.srv) + '/phasing', { q1: 100000, q2: 100000, q3: 100000, q4: 100000 }, OP)).status, 403);
  let r = await call('PUT', '/budget-exec/lines/' + encodeURIComponent(ids.srv) + '/phasing', { q1: 100000, q2: 100000, q3: 100000, q4: 1 }, A1); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /add up/);
  assert.equal((await call('PUT', '/budget-exec/lines/' + encodeURIComponent(ids.idea) + '/phasing', { q1: 50000, q2: 0, q3: 0, q4: 0 }, A1)).status, 409, 'only an approved line is phased');
  r = await call('PUT', '/budget-exec/lines/' + encodeURIComponent(ids.srv) + '/phasing', { q1: 0, q2: 200000, q3: 200000, q4: 0 }, A1); assert.equal(r.status, 200);
  let v = (await call('GET', '/budget-exec', undefined, VW)).json; assert.deepEqual(L(v, ids.srv).q, [0, 200000, 200000, 0]); assert.match(L(v, ids.srv).phasing, /set by syed/);
  // recording
  assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-01', amount: 1, reference: 'X' }, VW)).status, 403);
  assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-01', amount: 1, reference: 'X' }, { user: 'system:bot', role: 'operator' })).status, 403);
  r = await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-01', amount: 1 }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /reference/);
  r = await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2027-01-01', amount: 1, reference: 'F' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /date/);
  r = await call('POST', '/budget-exec/actuals', { line_id: 'nope', date: '2026-10-01', amount: 1, reference: 'N' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /line_id/);
  r = await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-01', amount: -5, reference: 'N' }, OP); assert.equal(r.status, 400); assert.match(JSON.stringify(r.json), /amount/);
  r = await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-01', amount: 9000, reference: 'INV-SYN-9', extra: 1 }, OP); assert.equal(r.status, 200); const id = r.json.actual.id; assert.equal(r.json.actual.extra, undefined);
  assert.equal((await call('POST', '/budget-exec/actuals', { line_id: ids.wan, date: '2026-10-02', amount: 9000, reference: 'inv-syn-9' }, OP)).status, 409, 'the same invoice twice');
  assert.equal((await call('POST', '/budget-exec/actuals/' + id + '/void', { reason: 'x' }, OP)).status, 403, 'operators do not void');
  assert.equal((await call('POST', '/budget-exec/actuals/' + id + '/void', {}, A2)).status, 400, 'a reason is required');
  assert.equal((await call('POST', '/budget-exec/actuals/' + id + '/void', { reason: 'entered on the wrong line (synthetic)' }, A2)).status, 200);
  assert.equal((await call('POST', '/budget-exec/actuals/' + id + '/void', { reason: 'again' }, A2)).status, 409);
  v = (await call('GET', '/budget-exec', undefined, VW)).json; assert.equal(L(v, ids.wan).actual, 0, 'a void invoice does not count');
  const au = e.app.store.auditTail(50);
  assert.ok(au.some((a) => a.action === 'budget.phasing' && a.by === 'syed'));
  assert.ok(au.some((a) => a.action === 'budget.actual.add' && a.by === OP.user && a.detail.reference === 'INV-SYN-9'));
  assert.ok(au.some((a) => a.action === 'budget.actual.void' && a.by === A2.user && /wrong line/.test(a.detail.reason)));
});

test('nothing approved: an honest empty plan', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW });
  const v = (await e.req('GET', '/budget-exec', VW)).json;
  assert.deepEqual(v.lines, []); assert.equal(v.totals.plan, 0); assert.equal(v.totals.utilisation_pct, null);
});
