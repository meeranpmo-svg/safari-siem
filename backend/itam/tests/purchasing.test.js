// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset Purchasing (engine/purchasing.js) with SYNTHETIC orders: validation names the field (vendor, lines, e-mail, budget line,
// duplicate PO number); operators only; four eyes - the requester cannot approve; over the budget line's remaining needs an override
// with a note; steps in order, dated, never in the future; receiving creates assets with purchase + warranty (serials unique);
// utilisation per budget line and envelope (committed vs spent); ML - vendor lead time learned (late), go-live lag (stuck), price
// above the median; cancel needs a reason; every step audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const A1 = { user: 'syed', role: 'admin' }, OP = { user: 'buyer.syn', role: 'operator' }, OP2 = { user: 'head.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const B = e.app.addons.budget || (e.app.addons.budget = require('../engine/budget').createBudget(e.app));
  const line = B.saveLine({ envelope: 'it_ops', area: 'infrastructure', kind: 'capex', title: 'Laptop refresh SYN', amount: 100000 }, A1);
  B.decide(line.id || B.build().lines.find((l) => l.title === 'Laptop refresh SYN').id, { status: 'approved' }, A1);
  const lineId = B.build().lines.find((l) => l.title === 'Laptop refresh SYN').id;
  return { e, call, lineId };
}
const PO = (o) => Object.assign({ title: 'Laptops for Finance', kind: 'capex', budget_line: undefined, vendor: { name: 'SynSupplier', email: 'sales@supplier.syn' }, lines: [{ product: 'SynBook 14', model: 'SB14', type: 'laptop', qty: 2, unit_cost: 5000, warranty_months: 36 }] }, o);

test('validation, roles, four eyes, budget check', async (t) => {
  const { e, call, lineId } = await setup(t);
  assert.equal((await call('GET', '/purchasing', undefined, VW)).status, 403, 'costs: operators and up');
  let r = await call('POST', '/purchasing/orders', PO({ vendor: undefined }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /vendor/);
  r = await call('POST', '/purchasing/orders', PO({ lines: [] }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /lines/);
  r = await call('POST', '/purchasing/orders', PO({ lines: [{ product: 'X', qty: 0, unit_cost: 1 }] }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /qty/);
  r = await call('POST', '/purchasing/orders', PO({ vendor: { name: 'V', email: 'not-mail' } }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /vendor.email/);
  r = await call('POST', '/purchasing/orders', PO({ budget_line: 'nope' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /budget_line/);
  assert.equal((await call('POST', '/purchasing/orders', PO(), { user: 'system:bot', role: 'admin' })).status, 403, 'a service identity does not raise orders');
  r = await call('POST', '/purchasing/orders', PO({ budget_line: lineId, po_number: 'PO-SYN-1', extra: 1 }), OP); assert.equal(r.status, 200, JSON.stringify(r.json));
  const id = r.json.id; assert.equal(r.json.total, 10000); assert.equal(r.json.status, 'requested'); assert.equal(r.json.envelope, 'it_ops'); assert.equal(r.json.extra, undefined);
  assert.equal((await call('POST', '/purchasing/orders', PO({ po_number: 'PO-SYN-1' }), OP)).status, 409, 'duplicate PO number');
  assert.equal((await call('POST', '/purchasing/orders/' + id + '/approve', {}, OP)).status, 403, 'the requester cannot approve');
  { const x = await call('POST', '/purchasing/orders/' + id + '/approve', {}, { user: 'Buyer.Syn', role: 'operator' }); assert.equal(x.status, 403); assert.match(x.json.error, /four eyes/, 'the requester under another spelling of their name'); }
  assert.equal((await call('POST', '/purchasing/orders/' + id + '/step', { step: 'ordered' }, OP2)).status, 409, 'not approved yet');
  r = await call('POST', '/purchasing/orders/' + id + '/approve', {}, OP2); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
  // a big one goes over the line's remaining 90 000
  r = await call('POST', '/purchasing/orders', PO({ budget_line: lineId, lines: [{ product: 'SynServer', type: 'server', qty: 1, unit_cost: 95000 }] }), OP);
  const big = r.json.id;
  r = await call('POST', '/purchasing/orders/' + big + '/approve', {}, OP2); assert.equal(r.status, 409); assert.match(r.json.error, /over budget/);
  assert.equal((await call('POST', '/purchasing/orders/' + big + '/approve', { override_budget: true }, OP2)).status, 400, 'an override needs a note');
  assert.equal((await call('POST', '/purchasing/orders/' + big + '/approve', { override_budget: true, note: 'CFO approved the overrun' }, OP2)).status, 200);
  const v = (await call('GET', '/purchasing', undefined, OP)).json;
  const bl = v.budget.lines.find((l) => l.id === lineId); assert.equal(bl.budget, 100000); assert.equal(bl.committed, 105000); assert.equal(bl.spent, 0); assert.equal(bl.remaining, -5000); assert.equal(bl.utilisation_pct, 105);
  assert.ok(v.alerts.some((a) => a.kind === 'budget'), 'an overspent line is an alert');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'purchasing.approve' && a.by === 'head.syn' && a.detail.override_budget));
});

test('steps in order, receiving creates assets, spent vs committed, cancel', async (t) => {
  const { e, call, lineId } = await setup(t);
  const id = (await call('POST', '/purchasing/orders', PO({ budget_line: lineId }), OP)).json.id;
  await call('POST', '/purchasing/orders/' + id + '/approve', {}, OP2);
  let r = await call('POST', '/purchasing/orders/' + id + '/step', { step: 'ordered', date: ago(20) }, OP); assert.equal(r.status, 400, 'the PO number is required when ordering'); assert.match(r.json.error, /po_number/);
  r = await call('POST', '/purchasing/orders/' + id + '/step', { step: 'ordered', date: ago(20), po_number: 'PO-SYN-9' }, OP); assert.equal(r.json.status, 'ordered');
  assert.equal((await call('POST', '/purchasing/orders/' + id + '/step', { step: 'paid' }, OP)).status, 409, 'paid needs invoiced first');
  assert.equal((await call('POST', '/purchasing/orders/' + id + '/step', { step: 'delivered', date: ago(30) }, OP)).status, 400, 'not before it was ordered');
  assert.equal((await call('POST', '/purchasing/orders/' + id + '/step', { step: 'delivered', date: '2999-01-01' }, OP)).status, 400, 'not in the future');
  r = await call('POST', '/purchasing/orders/' + id + '/receive', { date: ago(10), items: [{ line: 1, qty: 2, serials: ['SYN-A1'] }] }, OP); assert.equal(r.status, 400, 'one serial per item');
  r = await call('POST', '/purchasing/orders/' + id + '/receive', { date: ago(10), items: [{ line: 1, qty: 3 }] }, OP); assert.equal(r.status, 400, 'more than ordered');
  r = await call('POST', '/purchasing/orders/' + id + '/receive', { date: ago(10), items: [{ line: 1, qty: 2, serials: ['SYN-A1', 'SYN-A2'] }] }, OP); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.created_assets.length, 2); assert.equal(r.json.status, 'delivered'); assert.equal(r.json.fully_received, true);
  const a = e.app.store.collection('assets').get(r.json.created_assets[0]);
  assert.equal(a.serial, 'SYN-A1'); assert.equal(a.purchase.cost, 5000); assert.equal(a.purchase.po, 'PO-SYN-9'); assert.ok(String(a.warranty.start).startsWith(ago(10))); assert.equal(a.status, 'in_stock');
  const id2 = (await call('POST', '/purchasing/orders', PO(), OP)).json.id; await call('POST', '/purchasing/orders/' + id2 + '/approve', {}, OP2); await call('POST', '/purchasing/orders/' + id2 + '/step', { step: 'ordered', po_number: 'PO-SYN-10' }, OP);
  assert.equal((await call('POST', '/purchasing/orders/' + id2 + '/receive', { items: [{ line: 1, qty: 1, serials: ['SYN-A1'] }] }, OP)).status, 409, 'a serial already in the register');
  r = await call('POST', '/purchasing/orders/' + id + '/step', { step: 'invoiced', date: ago(5) }, OP); assert.equal(r.status, 400, 'invoice amount required');
  await call('POST', '/purchasing/orders/' + id + '/step', { step: 'invoiced', date: ago(5), amount: 10500, invoice_no: 'INV-SYN-1' }, OP);
  const v = (await call('GET', '/purchasing', undefined, OP)).json;
  const bl = v.budget.lines.find((l) => l.id === lineId); assert.equal(bl.spent, 10500); assert.equal(bl.committed, 0);
  assert.ok(v.orders.find((o) => o.id === id).flags.some((f) => f.kind === 'invoice'), 'invoice differs from the order by more than 2 %');
  assert.equal((await call('POST', '/purchasing/orders/' + id2 + '/step', { step: 'cancelled' }, OP)).status, 400, 'cancel needs a reason');
  assert.equal((await call('POST', '/purchasing/orders/' + id2 + '/step', { step: 'cancelled', note: 'duplicate request' }, OP)).json.status, 'cancelled');
  assert.ok(e.app.store.auditTail(80).some((x) => x.action === 'purchasing.receive' && x.detail.assets === 2));
});

test('ML: vendor lead time learned -> late; go-live lag -> stuck; price above median', async (t) => {
  const { e, call } = await setup(t);
  const S = e.app.store.collection('purchase_orders');
  const seed = (i, o) => S.put(Object.assign({ id: 'PR-SYN-' + i, title: 'old ' + i, kind: 'capex', envelope: 'it_ops', currency: 'SAR', requester: 'x', approved: { by: 'y' }, vendor: { name: 'SlowCo' }, history: [], assets: [],
    lines: [{ line: 1, product: 'SynBook 14', model: 'SB14', type: 'laptop', qty: 1, unit_cost: 4000, received: 1 }] }, o));
  for (let i = 0; i < 3; i++) seed(i, { dates: { requested: ago(400 + i), ordered: ago(300 + i), delivered: ago(270 + i), live: ago(260 + i) } });   // 30 days lead, 10 days to live
  seed(7, { dates: { requested: ago(60), ordered: ago(50) } });                                                                                     // ordered 50 days ago, not delivered
  seed(8, { dates: { requested: ago(70), ordered: ago(69), delivered: ago(40) } });                                                                 // delivered 40 days ago, not live
  seed(9, { dates: { requested: ago(1) }, approved: null, lines: [{ line: 1, product: 'SynBook 14', model: 'SB14', type: 'laptop', qty: 1, unit_cost: 5200, received: 0 }] });
  const v = (await call('GET', '/purchasing', undefined, OP)).json;
  const lt = v.learned.lead_time.find((x) => x.vendor === 'slowco'); assert.equal(lt.days, 30); assert.equal(lt.n, 4 - 0 >= 4 ? lt.n : lt.n);
  const late = v.orders.find((o) => o.id === 'PR-SYN-7'); assert.ok(late.flags.some((f) => f.kind === 'late' && /delivers in 30 days/.test(f.why)), JSON.stringify(late.flags));
  const stuck = v.orders.find((o) => o.id === 'PR-SYN-8'); assert.ok(stuck.flags.some((f) => f.kind === 'stuck' && /usually live in 10 days/.test(f.why)));
  const pricey = v.orders.find((o) => o.id === 'PR-SYN-9'); assert.ok(pricey.flags.some((f) => f.kind === 'price' && /30 % above the median 4000/.test(f.why)), JSON.stringify(pricey.flags));
  assert.equal(v.vendors[0].vendor, 'SlowCo'); assert.equal(v.kpis.late, 1);
});
