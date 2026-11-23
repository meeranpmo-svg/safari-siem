// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Renewals & Expiry (engine/expiry-hub.js) over SYNTHETIC records in the owning modules: every kind collected (licence, support
// contract, certificate, domain, hosting, app secret + rotation due, warranty, asset support, Cisco); risk itemised (expired, inside
// the lead time, no owner, auto-renew off, critical kind); costs only for operators; tracking by a person, audited, validated;
// "renewed" stays a claim until the source shows a later date, then verified; lead time learned from 3 verified renewals; price
// rise flagged; expiry storms; 12-month forecast.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const OP = { user: 'ren.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const inD = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const C = (n) => e.app.store.collection(n);
  C('licences').put({ id: 'lic1', product: 'SynSuite', expiry: inD(20), cost: 1000, status: 'active' });
  C('support_contracts').put({ id: 'sc1', vendor: 'SynVendor', product: 'ProSupport', contract_number: 'SC-1', end: inD(200), cost: 5000, status: 'active', owner: 'infra.syn' });
  C('cert_endpoints').put({ id: 'ep1', host: 'portal.syn.test', port: 443 }); C('cert_scans').put({ id: 'ep1', scan: { ok: true, subject: 'CN=portal.syn.test', not_after_iso: inD(5) } });
  C('dom_domains').put({ id: 'd1', name: 'syn-example.test', expires: inD(-3), auto_renew: false, cost: 80 });
  C('ren_hosting').put({ id: 'h1', provider: 'SynHost', service: 'VPS', renews: inD(100), auto_renew: true, cost: 300 });
  C('assets').put({ id: 'a1', name: 'SRV-SYN', type: 'server', status: 'in_use', warranty: { end: inD(45), provider: 'SynVendor' }, support: { provider: 'SynVendor', end: inD(300), verified: true } });
  C('cisco_coverage').put({ id: 'FOC123', contract: 'SN-9', end: inD(400) });
  e.app.addons.nhi = { view: async () => ({ policy: { rotation_days: 365, secret_max_days: 730, privileged_rotation_days: 90 }, items: [
    { id: 'app1', kind_name: 'App registration', name: 'SynApp', expires: inD(10), owner: null },
    { id: 'svc1', kind_name: 'Service account', name: 'svc-syn', secret_age_days: 360, privileged: false, owner: 'ops.syn' }] }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, C };
}
const I = (v, k) => v.items.find((x) => x.key === k);

test('every kind collected, risk itemised, costs for operators only', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/expiry', undefined, OP)).json;
  const kinds = new Set(v.items.map((x) => x.kind));
  for (const k of ['licence', 'support', 'certificate', 'domain', 'hosting', 'secret', 'warranty', 'asset_support', 'cisco']) assert.ok(kinds.has(k), 'collected ' + k);
  const dom = I(v, 'domain:d1'); assert.equal(dom.state, 'expired'); assert.ok(dom.why.some((w) => /expired 3 day/.test(w.why)) && dom.why.some((w) => /auto-renew off/.test(w.why)));
  const cert = I(v, 'certificate:ep1'); assert.equal(cert.state, 'due'); assert.ok(cert.why.some((w) => /outage when it lapses/.test(w.why)), 'certificate is a critical kind');
  assert.ok(I(v, 'secret:svc1:rotate') && I(v, 'secret:svc1:rotate').rotation, 'rotation due from the NHI policy');
  assert.equal(I(v, 'support:sc1').state, 'later'); assert.equal(v.items[0].key, 'domain:d1', 'highest risk first');
  assert.equal(I(v, 'licence:lic1').cost, 1000); assert.equal(v.kpis.expired, 1); assert.ok(v.kpis.d30 >= 3);
  assert.equal(v.months.length, 12);
  const vw = (await call('GET', '/expiry', undefined, VW)).json; assert.equal(vw.costs_visible, false); assert.equal(I(vw, 'licence:lic1').cost, undefined); assert.equal(vw.kpis.cost_90, undefined);
});

test('tracking: a person, validated, audited; renewed is a claim until the source moves; price rise', async (t) => {
  const { e, call, C } = await setup(t);
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'owner', owner: 'x' }, VW)).status, 403);
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'owner', owner: 'x' }, { user: 'system:bot', role: 'admin' })).status, 403);
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'owner' }, OP)).status, 400);
  assert.equal((await call('POST', '/expiry/track', { key: 'nope', action: 'owner', owner: 'x' }, OP)).status, 404);
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'renewed' }, OP)).status, 400, 'a reference is required');
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'renewed', reference: 'PO-1', new_expiry: inD(1) }, OP)).status, 400, 'the new date must be later');
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'owner', owner: 'apps.syn' }, OP)).status, 200);
  let v = (await call('GET', '/expiry', undefined, OP)).json; assert.equal(I(v, 'licence:lic1').owner, 'apps.syn'); assert.ok(!I(v, 'licence:lic1').why.some((w) => /no owner/.test(w.why)));
  assert.equal((await call('POST', '/expiry/track', { key: 'licence:lic1', action: 'renewed', reference: 'INV-SYN-1', cost: 1300, new_expiry: inD(385) }, OP)).status, 200);
  v = (await call('GET', '/expiry', undefined, OP)).json; assert.equal(I(v, 'licence:lic1').state, 'claimed', 'not verified by the claim alone');
  assert.equal(I(v, 'licence:lic1').price_change_pct, 30); assert.ok(I(v, 'licence:lic1').why.some((w) => /30 % above/.test(w.why)));
  C('licences').put(Object.assign(C('licences').get('lic1'), { expiry: inD(385) }));
  v = (await call('GET', '/expiry', undefined, OP)).json; assert.equal(I(v, 'licence:lic1').state, 'renewed', 'verified when the licence record shows the new date');
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'expiry.verified' && a.target === 'licence:lic1'));
  assert.ok(e.app.store.auditTail(30).some((a) => a.action === 'expiry.renewed' && a.by === 'ren.syn'));
  assert.equal((await call('POST', '/expiry/track', { key: 'domain:d1', action: 'not_renewing' }, OP)).status, 400, 'a reason');
  assert.equal((await call('POST', '/expiry/track', { key: 'domain:d1', action: 'not_renewing', note: 'brand retired' }, OP)).status, 200);
  v = (await call('GET', '/expiry', undefined, OP)).json; assert.equal(I(v, 'domain:d1').state, 'not renewing'); assert.equal(I(v, 'domain:d1').risk, 0);
});

test('ML: lead time learned from 3 verified renewals; expiry storms', async (t) => {
  const { call, C } = await setup(t);
  const TR = C('expiry_tracking');
  for (let i = 0; i < 3; i++) TR.put({ id: 'certificate:old' + i, kind: 'certificate', old_expiry: inD(-100 - i), renewed: { at: new Date(Date.now() - (110 + i) * 86400000).toISOString() }, verified_at: new Date().toISOString() });
  for (let i = 0; i < 5; i++) C('licences').put({ id: 'storm' + i, product: 'Storm ' + i, expiry: inD(150), status: 'active' });
  const v = (await call('GET', '/expiry', undefined, OP)).json;
  const ck = v.by_kind.find((k) => k.kind === 'certificate'); assert.equal(ck.lead_learned, true); assert.equal(ck.lead_n, 3); assert.ok(ck.lead_days >= 9 && ck.lead_days <= 10, 'renewed about 10 days before expiry: ' + ck.lead_days);
  assert.ok(v.storms.some((s) => s.count >= 5), 'a week with 5+ expiries is a storm: ' + JSON.stringify(v.storms));
});
