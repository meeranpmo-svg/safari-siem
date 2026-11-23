// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Asset Data Autopilot (engine/asset-autofill.js) over SYNTHETIC assets: end of life from the vendor OS table (verified) and from
// hardware life learned from this register's own retirements (estimate) - the earlier one proposed; warranty start from the purchase
// date and end from the term learned from peers; support from a covering support contract; classification from classified peers and
// CIA from record facts; nothing written until a person accepts (a service identity is refused); accept one / all verified, audited;
// a dismissed proposal stays dismissed; serial / MAC gaps say why; settings admin only and validated; auto-fill writes verified
// values into EMPTY fields only as source "autofill", which an import overrides; viewers read.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'asset.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const yrs = (n) => new Date(Date.now() - n * 365.25 * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  require('../engine/support-contracts').registerSupportContracts(e.app.srv, e.app);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const mk = async (o) => { const r = await call('POST', '/assets', o, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); return (r.json.asset || r.json).id; };
  return { e, call, mk };
}
const P = (v, id, f) => v.proposals.find((p) => p.asset_id === id && p.field === f);

test('end of life, warranty, support, classification and CIA proposed with source and reason; nothing written yet', async (t) => {
  const { e, call, mk } = await setup(t);
  // three laptops retired after ~6 years teach the hardware life
  for (let i = 0; i < 3; i++) { const id = await mk({ name: 'LT-OLD-' + i, type: 'laptop', vendor: 'SynVendor', purchase: { date: yrs(6) } }); assert.equal((await call('POST', '/assets/' + id + '/retire', { reason: 'end of life' }, ADM)).status, 200); }
  // three laptops with a 36-month warranty teach the term
  for (let i = 0; i < 3; i++) await mk({ name: 'LT-W-' + i, type: 'laptop', vendor: 'SynVendor', warranty: { start: '2024-01-01', end: '2027-01-01' }, classification: 'restricted', department: 'Finance', cia: { c: 'medium', i: 'medium', a: 'low' } });
  const lt = await mk({ name: 'LT-NEW', type: 'laptop', vendor: 'SynVendor', purchase: { date: '2025-03-01' }, department: 'Finance' });
  const srv = await mk({ name: 'SRV-DB-01', type: 'server', vendor: 'SynVendor', os: 'Windows Server 2012 R2 Standard', purchase: { date: '2020-06-01' }, software: [{ name: 'Microsoft SQL Server 2016' }] });
  assert.equal((await call('POST', '/support-contracts', { vendor: 'SynVendor', family: 'hardware', product: 'ProSupport SYN', contract_number: 'SUP-SYN-1', level: 'NBD', kind: 'support', start: '2025-01-01', end: '2028-01-01', asset_ids: [srv] }, ADM)).status, 200);

  const v = (await call('GET', '/asset-autofill', undefined, VW)).json;
  const ls = v.learned.lifespan.find((x) => x.type === 'laptop'); assert.ok(ls && ls.n === 3 && Math.abs(ls.years - 6) < 0.2, 'laptop life learned from retirements: ' + JSON.stringify(ls));
  const we = P(v, lt, 'warranty'); assert.ok(we, 'warranty proposed'); assert.equal(we.value.start, '2025-03-01'); assert.equal(we.value.end, '2028-03-01'); assert.equal(we.verified, false); assert.match(we.why, /36 months, the term on 3 of 3/);
  const el = P(v, lt, 'eol'); assert.equal(el.source, 'learned hardware life'); assert.match(el.why, /median of 3 retirements/); assert.equal(el.verified, false);
  const es = P(v, srv, 'eol'); assert.equal(es.value, '2023-10-10', 'the vendor OS date is earlier than the hardware life'); assert.equal(es.verified, true); assert.equal(es.candidates.length, 2);
  const su = P(v, srv, 'support'); assert.equal(su.value.contract, 'SUP-SYN-1'); assert.equal(su.value.end, '2028-01-01'); assert.equal(su.verified, false, 'a contract not verified with the vendor is not verified');
  const cl = P(v, lt, 'classification'); assert.equal(cl.value, 'restricted'); assert.match(cl.why, /3 of 3 classified laptop assets in Finance/);
  const ci = P(v, srv, 'cia'); assert.equal(ci.value.c, 'high'); assert.match(ci.why, /runs a database/);
  const ciL = P(v, lt, 'cia'); assert.deepEqual(ciL.value, { c: 'medium', i: 'medium', a: 'low' });
  assert.equal(e.app.store.collection('assets').get(lt).eol, null, 'nothing is written by the analysis');
  assert.ok(v.gaps.some((g) => g.asset_id === lt && g.field === 'serial'), 'a missing serial is a gap with a reason');
  assert.ok(v.coverage.find((c) => c.field === 'eol').after_pct > v.coverage.find((c) => c.field === 'eol').pct);
});

test('a person accepts (one, all verified), dismiss sticks, roles, validation, audit', async (t) => {
  const { e, call, mk } = await setup(t);
  const srv = await mk({ name: 'SRV-OLD', type: 'server', os: 'Windows Server 2012 R2', purchase: { date: '2020-06-01' } });
  const lt = await mk({ name: 'LT-X', type: 'laptop', purchase: { date: '2025-03-01' } });
  let v = (await call('GET', '/asset-autofill', undefined, OP)).json;
  const k = P(v, lt, 'eol').key;
  assert.equal((await call('POST', '/asset-autofill/accept', { keys: [k] }, VW)).status, 403, 'viewers do not accept');
  assert.equal((await call('POST', '/asset-autofill/accept', { keys: [k] }, { user: 'system:bot', role: 'admin' })).status, 403, 'a service identity does not accept');
  assert.equal((await call('POST', '/asset-autofill/accept', {}, OP)).status, 400);
  assert.equal((await call('POST', '/asset-autofill/accept', { verified: true, fields: ['price'] }, OP)).status, 400);
  // all verified: only the vendor-table end of life of the server, not the laptop's estimate
  let r = await call('POST', '/asset-autofill/accept', { verified: true }, OP); assert.equal(r.status, 200); assert.equal(r.json.accepted, 1);
  const A = e.app.store.collection('assets');
  assert.ok(String(A.get(srv).eol).startsWith('2023-10-10')); assert.equal(A.get(lt).eol, null, 'an estimate is not accepted as verified');
  assert.equal(A.get(srv).locked.eol, true, 'accepted = a person decided: locked');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'asset.autofill.accept' && a.by === 'asset.syn' && a.detail.source === 'vendor lifecycle'));
  // dismiss with a reason: gone until the value changes
  assert.equal((await call('POST', '/asset-autofill/dismiss', { key: k }, OP)).status, 400, 'a reason is required');
  assert.equal((await call('POST', '/asset-autofill/dismiss', { key: k, reason: 'laptop is leased - lease end applies' }, OP)).status, 200);
  v = (await call('GET', '/asset-autofill', undefined, OP)).json; assert.equal(P(v, lt, 'eol'), undefined, 'dismissed stays dismissed');
  assert.equal((await call('POST', '/asset-autofill/accept', { keys: [k] }, OP)).status, 409, 'a stale key is refused');
  // settings
  assert.equal((await call('PUT', '/asset-autofill/settings', { lifespan_years: { laptop: 3 } }, OP)).status, 403);
  assert.equal((await call('PUT', '/asset-autofill/settings', { lifespan_years: { laptop: 40 } }, ADM)).status, 400);
  assert.equal((await call('PUT', '/asset-autofill/settings', { lifespan_years: { toaster: 3 } }, ADM)).status, 400);
  r = await call('PUT', '/asset-autofill/settings', { lifespan_years: { laptop: 3 }, auto_fill_verified: true, x: 1 }, ADM); assert.equal(r.status, 200); assert.equal(r.json.lifespan_years.laptop, 3); assert.equal(r.json.x, undefined);
  v = (await call('GET', '/asset-autofill', undefined, OP)).json; assert.match(P(v, lt, 'eol').why, new RegExp('3 years \\(' + ZYB_ORG.short + ' policy\\)'), 'the policy life changes the estimate (new value -> proposed again)');
});

test('auto-fill: verified vendor values into empty fields only, as "autofill", overridden by an import', async (t) => {
  const { e, call, mk } = await setup(t);
  const a1 = await mk({ name: 'SRV-AF', type: 'server', os: 'Windows Server 2012' });
  const a2 = await mk({ name: 'SRV-KEEP', type: 'server', os: 'Windows Server 2012', eol: '2030-01-01' });
  const F = e.app.addons.assetAutofill;
  assert.equal(F.autoFill(), 0, 'off by default');
  await call('PUT', '/asset-autofill/settings', { auto_fill_verified: true }, ADM);
  assert.equal(F.autoFill(), 1);
  const A = e.app.store.collection('assets');
  assert.ok(String(A.get(a1).eol).startsWith('2023-10-10')); assert.equal(A.get(a1).prov.eol, 'autofill'); assert.ok(!(A.get(a1).locked || {}).eol);
  assert.ok(String(A.get(a2).eol).startsWith('2030-01-01'), 'a value a person entered is never replaced automatically');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'asset.autofill.auto' && x.target === a1));
  const merge = require('../engine/model/merge');
  const m = merge.mergeInto(A.get(a1), { eol: '2024-06-30' }, 'import');
  assert.ok(String(m.asset.eol).startsWith('2024-06-30'), 'an import overrides an auto-filled value');
});

test('criticality (availability) for unrated assets: CMDB dependents, name family, role; nothing decides -> stays unrated', async (t) => {
  const { e, call, mk } = await setup(t);
  // a rated family: two VDI desktops rated low by a person
  for (const n of ['as-nagg-vdi2', 'as-nagg-vdi3']) await mk({ name: n, type: 'vm', cia: { a: 'medium' } });
  const fam = await mk({ name: 'as-nagg-vdi4', type: 'vm' });
  const vdi = await mk({ name: '360f-vdi1', type: 'vm' });
  const app = await mk({ name: 'Core Claims (synthetic)', type: 'server', cia: { a: 'high' } });
  const dep = await mk({ name: 'astcs1', type: 'vm' });
  const none = await mk({ name: 'srv-misc', type: 'server' });
  const fw = await mk({ name: 'jed-fw', type: 'network' });
  e.app.store.collection('relationships').put({ id: 'R1', from: app, to: dep, type: 'depends_on', status: 'confirmed' });
  const v = (await call('GET', '/asset-autofill', undefined, OP)).json;
  const a = (id) => { const p = P(v, id, 'cia'); return p ? p.value.a : null; };
  assert.equal(a(dep), 'high'); assert.match(P(v, dep, 'cia').why, /Core Claims .* depends on it/, 'inherits the criticality of what depends on it');
  assert.equal(a(fam), 'medium'); assert.match(P(v, fam, 'cia').why, /2 of 2 rated assets of the same family \(as-nagg-vdi\*\)/, 'family peers decide before the VDI rule');
  assert.equal(a(vdi), 'low'); assert.match(P(v, vdi, 'cia').why, /VDI/);
  assert.equal(a(fw), 'high'); assert.equal(a(none), null, 'no evidence: no proposal, the asset stays unrated');
  // a person accepts: Scanned Assets / VAPT Center then read the rating
  const r = await call('POST', '/asset-autofill/accept', { keys: [P(v, dep, 'cia').key] }, OP); assert.equal(r.status, 200);
  assert.equal(e.app.store.collection('assets').get(dep).cia.a, 'high');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'asset.autofill.accept' && x.target === dep));
});
