// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Enterprise Asset Management (engine/eam.js) with SYNTHETIC assets and people: a purchase request is approved by procurement (never by
// the requester or an AI identity), ordered and received - device lines with serials become assets in stock and spares raise stock;
// an asset is deployed (in_use, owner); a corrective work order puts it in repair, parts come out of stock, it is completed and verified by
// a different person, and the asset is back in use; a maintenance plan raises its work order from the background job; a retirement is
// approved by a different administrator and drives the register; roles (viewer refused, membership), validation (undeclared fields
// dropped, bad list entries refused), the ML (failure risk with its reasons, MTBF, stock demand and reorder, cost outliers, technician
// suggestion, duplicates) and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, MGR = { user: 'mgr.syn', role: 'operator' };
const TECH = { user: 'tech.syn', role: 'operator' }, TECH2 = { user: 'tech2.syn', role: 'operator' }, WH = { user: 'wh.syn', role: 'operator' };
const PROC = { user: 'proc.syn', role: 'operator' }, VIEW = { user: 'view.syn', role: 'viewer' }, BOT = { user: 'ai:eam', role: 'admin' };
const DAY = 86400000;

async function setup(t, settings) {
  let T = Date.parse('2026-11-20T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  if (settings) { const r = await call('POST', '/eam/settings', Object.assign({ version: 0 }, settings)); assert.equal(r.status, 200, r.text); }
  const asset = (o) => e.app.assets.create(Object.assign({ name: 'SYN-' + Math.random().toString(36).slice(2, 7), type: 'laptop' }, o), ADM).asset.id;
  return { e, call, asset, clock: (ms) => { T += ms; }, now: () => T, audits: (a) => e.app.store.auditTail(1000).filter((x) => x.action === 'eam.' + a) };
}

test('purchase -> receive into stock -> deploy: four-eyes, serials become assets in stock, spares raise stock; audited', async (t) => {
  const s = await setup(t, { technicians: ['tech.syn', 'tech2.syn'], warehouse: ['wh.syn'], procurement: ['proc.syn'] });
  const st = await s.call('POST', '/eam/stock', { name: 'SSD 512 GB (synthetic)', kind: 'spare', site: 'HQ', qty: 2, reorder_point: 3, unit_cost: 200 }, WH);
  assert.equal(st.status, 200, st.text);
  assert.equal((await s.call('POST', '/eam/stock', { name: 'X', kind: 'spare', site: 'HQ' }, TECH)).status, 403, 'not in the warehouse');
  const po = await s.call('POST', '/eam/po', { title: 'Laptops Q4', justification: 'new joiners (synthetic)', vendor: 'Syn Vendor', status: 'received', items: [{ name: 'Laptop 14', qty: 2, unit_cost: 4000, kind: 'device', type: 'laptop' }, { name: 'SSD', qty: 5, kind: 'spare', stock_id: st.json.id }] }, TECH);
  assert.equal(po.status, 200, po.text); assert.equal(po.json.status, 'requested', 'undeclared status dropped'); assert.equal(po.json.total, 8000);
  assert.equal((await s.call('POST', '/eam/po', { title: 'x', justification: 'y', items: [{ name: 'a', qty: 0 }] }, TECH)).status, 400, 'qty 0 refused');
  assert.equal((await s.call('POST', '/eam/po', { title: 'x', justification: 'y', items: ['not an object'] }, TECH)).status, 400, 'a bad line is refused');
  const id = po.json.id;
  assert.equal((await s.call('POST', '/eam/po/' + id + '/approve', {}, VIEW)).status, 403, 'viewer');
  assert.equal((await s.call('POST', '/eam/po/' + id + '/approve', {}, BOT)).status, 403, 'AI identity never approves');
  assert.equal((await s.call('POST', '/eam/po/' + id + '/approve', {}, WH)).status, 403, 'not procurement');
  assert.equal((await s.call('POST', '/eam/po/' + id + '/approve', {}, PROC)).json.status, 'approved');
  assert.equal((await s.call('POST', '/eam/po/' + id + '/order', { order_ref: 'PO-SYN-77' }, PROC)).json.status, 'ordered');
  const bad = await s.call('POST', '/eam/po/' + id + '/receive', { site: 'HQ', lines: [{ line: 0, qty: 2, serials: ['SN-SYN-1'] }] }, WH);
  assert.equal(bad.status, 400, 'serial count must match'); assert.match(bad.json.error, /serial/);
  const rc = await s.call('POST', '/eam/po/' + id + '/receive', { site: 'HQ', lines: [{ line: 0, qty: 2, serials: ['SN-SYN-1', 'SN-SYN-2'] }, { line: 1, qty: 5 }] }, WH);
  assert.equal(rc.status, 200, rc.text); assert.equal(rc.json.received.assets.length, 2);
  const a1 = e1(s, rc.json.received.assets[0]); assert.equal(a1.status, 'in_stock'); assert.equal(a1.serial, 'SN-SYN-1');
  assert.equal(s.e.app.store.collection('eam_stock').get(st.json.id).qty, 7, 'spares received');
  const dp = await s.call('POST', '/eam/deploy', { asset_id: a1.id, owner: 'new.joiner.syn', site: 'Branch-1' }, WH);
  assert.equal(dp.status, 200, dp.text); assert.equal(dp.json.asset.status, 'in_use'); assert.equal(dp.json.asset.owner, 'new.joiner.syn');
  assert.equal((await s.call('POST', '/eam/deploy', { asset_id: a1.id, owner: 'x.syn' }, WH)).status, 409, 'only from stock');
  for (const a of ['po.create', 'po.approve', 'po.order', 'po.receive', 'deploy', 'stock.create']) assert.ok(s.audits(a).length, 'audit ' + a);
  const ap = s.audits('po.approve')[0]; assert.equal(ap.by, 'proc.syn'); assert.equal(ap.role, 'operator');
});
function e1(s, id) { return s.e.app.assets.get(id); }

test('requester never approves their own purchase', async (t) => {
  const s = await setup(t);
  const po = await s.call('POST', '/eam/po', { title: 'Toner', justification: 'printers (synthetic)', items: [{ name: 'Toner', qty: 3, kind: 'consumable' }] }, PROC);
  const r = await s.call('POST', '/eam/po/' + po.json.id + '/approve', {}, PROC); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  const rj = await s.call('POST', '/eam/po/' + po.json.id + '/reject', {}, MGR); assert.equal(rj.status, 400, 'reason required'); assert.match(rj.json.error, /reason/);
});

test('work order: corrective puts the asset in repair, parts from stock, done -> back in use, verified by someone else', async (t) => {
  const s = await setup(t, { technicians: ['tech.syn', 'tech2.syn'] });
  const a = s.asset({ name: 'LAPTOP-SYN-01' });
  const st = (await s.call('POST', '/eam/stock', { name: 'Keyboard (synthetic)', kind: 'spare', site: 'HQ', qty: 1, unit_cost: 50 }, ADM)).json;
  assert.equal((await s.call('POST', '/eam/wo', { asset_id: a, kind: 'corrective', title: 'keyboard broken' }, VIEW)).status, 403, 'viewer');
  assert.equal((await s.call('POST', '/eam/wo', { asset_id: a, kind: 'fix-it', title: 'x' }, TECH)).status, 400, 'kind validated');
  const w = (await s.call('POST', '/eam/wo', { asset_id: a, kind: 'corrective', title: 'Keyboard broken', priority: 'high', assignee: 'evil' }, MGR)).json;
  assert.match(w.id, /^WO-2026-\d{4}$/); assert.equal(w.assignee, null, 'undeclared field dropped'); assert.equal(w.due, '2026-11-21T08:00:00.000Z', 'high = 24 h');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/assign', { assignee: 'tech.syn' }, MGR)).status, 403, 'an operator outside the technicians does not assign');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/assign', { assignee: 'outsider.syn' }, ADM)).status, 400, 'assignee must be a technician');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/assign', { assignee: 'tech.syn' }, ADM)).json.status, 'assigned');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/start', {}, TECH2)).status, 403, 'only the assignee starts it');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/start', {}, TECH)).json.status, 'in_progress');
  assert.equal(e1(s, a).status, 'in_repair');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/complete', { notes: 'x', parts: [{ stock_id: st.id, qty: 2 }] }, TECH)).status, 409, 'not enough stock');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/complete', { parts: [] }, TECH)).status, 400, 'notes required');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/complete', { notes: 'x', parts: [{ qty: 1 }] }, TECH)).status, 400, 'a part needs its stock id');
  const done = await s.call('POST', '/eam/wo/' + w.id + '/complete', { notes: 'Replaced the keyboard', cost: 50, parts: [{ stock_id: st.id, qty: 1 }] }, TECH);
  assert.equal(done.status, 200, done.text); assert.equal(done.json.status, 'done'); assert.equal(done.json.parts[0].name, 'Keyboard (synthetic)');
  assert.equal(s.e.app.store.collection('eam_stock').get(st.id).qty, 0); assert.equal(e1(s, a).status, 'in_use', 'back in use');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/verify', {}, TECH)).status, 403, 'the doer does not verify');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/verify', {}, BOT)).status, 403, 'AI identity');
  assert.equal((await s.call('POST', '/eam/wo/' + w.id + '/verify', { note: 'checked' }, MGR)).json.status, 'verified');
  assert.equal(s.audits('wo.complete')[0].by, 'tech.syn'); assert.ok(s.audits('wo.verify').length);
  const c = await s.call('POST', '/eam/wo', { asset_id: a, kind: 'inspection', title: 'check' }, MGR);
  assert.equal((await s.call('POST', '/eam/wo/' + c.json.id + '/cancel', {}, MGR)).status, 400, 'reason required');
  assert.equal((await s.call('POST', '/eam/wo/' + c.json.id + '/cancel', { reason: 'dup' }, TECH)).status, 403, 'only the raiser or an admin');
  assert.equal((await s.call('POST', '/eam/wo/' + c.json.id + '/cancel', { reason: 'duplicate' }, MGR)).json.status, 'cancelled');
});

test('maintenance plan raises its work order when due; retirement is decided by a different administrator', async (t) => {
  const s = await setup(t);
  const a = s.asset({ name: 'UPS-SYN-1', type: 'ups' });
  const p = await s.call('POST', '/eam/pm', { asset_id: a, title: 'Battery check', every_days: 90, next: '2026-11-25', category: 'facilities' }, MGR);
  assert.equal(p.status, 200, p.text);
  assert.deepEqual(s.e.app.addons.eam.tick().raised, [], 'not due yet');
  s.clock(6 * DAY); const r = s.e.app.addons.eam.tick(); assert.equal(r.raised.length, 1);
  const w = s.e.app.store.collection('eam_wo').get(r.raised[0]); assert.equal(w.plan_id, p.json.id); assert.equal(w.category, 'facilities'); assert.equal(w.created_by, 'system:eam');
  assert.equal(s.e.app.store.collection('eam_pm').get(p.json.id).next, '2027-02-23');
  assert.deepEqual(s.e.app.addons.eam.tick().raised, [], 'one open work order per plan');
  const rt = await s.call('POST', '/eam/retire', { asset_id: a, action: 'dispose', reason: 'end of life' }, MGR);
  assert.equal(rt.status, 400, 'method required to dispose');
  const rt2 = await s.call('POST', '/eam/retire', { asset_id: a, action: 'dispose', reason: 'end of life', method: 'recycle' }, MGR);
  assert.equal(rt2.status, 400); assert.match(rt2.json.error, /data_wiped/);
  const ok = await s.call('POST', '/eam/retire', { asset_id: a, action: 'retire', reason: 'end of life (synthetic)' }, ADM);
  assert.equal(ok.status, 200, ok.text); assert.deepEqual(ok.json.open_work_orders, [w.id], 'open work is listed');
  assert.equal((await s.call('POST', '/eam/retire/' + ok.json.id + '/approve', {}, MGR)).status, 403, 'operator');
  assert.equal((await s.call('POST', '/eam/retire/' + ok.json.id + '/approve', {}, ADM)).status, 403, 'the requester');
  assert.equal((await s.call('POST', '/eam/retire/' + ok.json.id + '/approve', {}, BOT)).status, 403, 'AI identity');
  assert.equal((await s.call('POST', '/eam/retire/' + ok.json.id + '/approve', { note: 'ok' }, ADM2)).json.status, 'approved');
  assert.equal(e1(s, a).status, 'retired'); assert.ok(s.audits('retire.approve').length);
  assert.equal((await s.call('POST', '/eam/wo', { asset_id: a, kind: 'corrective', title: 'x' }, MGR)).status, 409, 'no work orders on a retired asset');
});

test('ML: failure risk with reasons, MTBF, stock demand and reorder, cost outliers, technician suggestion, duplicates', async (t) => {
  const s = await setup(t, { technicians: ['tech.syn', 'tech2.syn'] });
  const peers = [1, 2, 3, 4].map((i) => s.asset({ name: 'PRN-SYN-' + i, type: 'printer', vendor: 'SynCo', model: 'P100' }));
  const bad = peers[0];
  const st = (await s.call('POST', '/eam/stock', { name: 'Fuser (synthetic)', kind: 'spare', site: 'HQ', qty: 30, reorder_point: 5, lead_days: 14, unit_cost: 100 }, ADM)).json;
  for (let i = 0; i < 6; i++) {
    const w = (await s.call('POST', '/eam/wo', { asset_id: bad, kind: 'corrective', title: 'Paper jam ' + i }, MGR)).json;
    await s.call('POST', '/eam/wo/' + w.id + '/assign', { assignee: 'tech.syn' }, ADM); await s.call('POST', '/eam/wo/' + w.id + '/start', {}, TECH);
    s.clock(2 * 3600000);
    const d = await s.call('POST', '/eam/wo/' + w.id + '/complete', { notes: 'cleared', cost: i === 5 ? 5000 : 100, parts: [{ stock_id: st.id, qty: 2 }] }, TECH); assert.equal(d.status, 200, d.text);
    s.clock(10 * DAY);
  }
  const v = await s.call('GET', '/eam?ws=manager', undefined, MGR); assert.equal(v.status, 200, v.text);
  const top = v.json.workspace.risk[0]; assert.equal(top.asset_id, bad); assert.ok(top.score >= 25, JSON.stringify(top));
  assert.ok(top.items.some((i) => /6 corrective work order\(s\) in 365 days, peers median 0/.test(i.why)), JSON.stringify(top.items));
  const rel = v.json.ml.reliability.find((r) => r.model === 'SynCo P100'); assert.equal(rel.failures, 6); assert.equal(rel.mtbf_days, 10.1); assert.equal(rel.mttr_h, 2);
  assert.match(top.next_failure, /^\d{4}-\d{2}-\d{2}$/); assert.match(top.next_why, /projection/);
  const wh = await s.call('GET', '/eam?ws=warehouse', undefined, MGR); const f = wh.json.workspace.stock.find((x) => x.id === st.id);
  assert.equal(f.qty, 18); assert.ok(f.daily > 0); assert.ok(f.cover_days > 0); assert.match(f.why, /lead time 14 d/);
  assert.ok(v.json.ml.outliers.some((o) => o.cost === 5000), 'cost outlier'); assert.equal(v.json.ml.suggest_technician, 'tech.syn', 'no open work for either: the better on-time record wins');
  const o1 = (await s.call('POST', '/eam/wo', { asset_id: peers[1], kind: 'corrective', title: 'Toner smudge on output' }, MGR)).json;
  await s.call('POST', '/eam/wo', { asset_id: peers[1], kind: 'corrective', title: 'toner smudge output' }, MGR);
  await s.call('POST', '/eam/wo/' + o1.id + '/assign', { assignee: 'tech.syn' }, ADM);
  const v2 = await s.call('GET', '/eam?ws=field', undefined, TECH2); assert.equal(v2.json.ml.suggest_technician, 'tech2.syn', 'tech.syn now has open work'); assert.ok(v2.json.ml.duplicates.some((d) => d.a === o1.id), 'duplicate found');
  assert.equal(v2.json.workspace.unassigned.length, 1);
  const one = await s.call('GET', '/eam/assets/' + bad, undefined, VIEW); assert.equal(one.status, 200); assert.equal(one.json.work_orders.length, 6); assert.ok(one.json.risk.score > 0);
  // not enough history -> said, never guessed
  const st2 = (await s.call('POST', '/eam/stock', { name: 'Cable (synthetic)', kind: 'consumable', site: 'HQ', qty: 10 }, ADM)).json;
  const w3 = await s.call('GET', '/eam?ws=warehouse', undefined, MGR); const c = w3.json.workspace.stock.find((x) => x.id === st2.id);
  assert.equal(c.daily, null); assert.match(c.why, /not enough usage history/);
});

test('settings: admin only, versioned, user names validated; viewer reads; AI needs a provider', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/eam/settings', { version: 0, technicians: ['a.syn'] }, MGR)).status, 403);
  assert.equal((await s.call('POST', '/eam/settings', { version: 0, technicians: ['bad name!'] }, ADM)).status, 400);
  assert.equal((await s.call('POST', '/eam/settings', { version: 0, technicians: ['a.syn'] }, ADM)).status, 200);
  assert.equal((await s.call('POST', '/eam/settings', { version: 0, technicians: ['b.syn'] }, ADM)).status, 409, 'stale version');
  assert.equal((await s.call('GET', '/eam', undefined, VIEW)).status, 200);
  assert.equal((await s.call('POST', '/eam/ai/ask', { question: 'what first?' }, VIEW)).status, 403);
  assert.equal((await s.call('POST', '/eam/ai/ask', { question: 'what first?' }, BOT)).status, 403);
  const ai = await s.call('POST', '/eam/ai/ask', { question: 'what first?' }, MGR); assert.ok([409, 200].includes(ai.status), ai.text);
});
