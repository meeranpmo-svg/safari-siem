// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC 2 and ISO/IEC 42001 readiness (engine/frameworks-x.js) through the real routes on SYNTHETIC records: status derived from
// stubbed NCA ECC levels (all met -> fully, any gap -> not, none assessed -> not assessed, no mapping -> not assessed), the SOC 2
// scope (optional categories are not applicable until chosen), four-eyes confirmation (evidence required, the submitter cannot
// approve, a reject needs a reason, an AI identity cannot approve), the 12-month expiry, roles, validation, audit, the CSV
// export and the crosswalk feed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t, levels) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = T0;
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now, python: process.env.PYTHON || 'python3' });
  e.app.addons.ncaEcc = { view: async () => ({ controls: Object.entries(levels).map(([id, level]) => ({ id, title: id, subdomain: id.slice(3, 8), level })) }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  const item = async (fw, id, who) => (await call('GET', '/frameworks-x', undefined, who)).json.frameworks.find((f) => f.key === fw).items.find((x) => x.id === id);
  return { e, call, item, setNow: (v) => { now = v; } };
}

test('derived from NCA ECC, scope, four-eyes confirmation, expiry, roles, audit', async (t) => {
  const { e, call, item, setNow } = await setup(t, { 'ZS-2-2-01': 'fully', 'ZS-2-1-01': 'fully', 'ZS-2-3-03': 'not', 'ZS-2-2-02': 'partially', 'ZS-2-12-02': 'not_assessed', 'ZS-1-3-01': 'fully' });
  let r = await call('GET', '/frameworks-x', undefined, VIEW); assert.equal(r.status, 200);
  const soc = r.json.frameworks.find((f) => f.key === 'soc2'), iso = r.json.frameworks.find((f) => f.key === 'iso42001');
  assert.equal(soc.items.length, 61); assert.equal(iso.items.length, 62);
  assert.match(r.json.note, /attested by a licensed CPA firm/);
  const by = Object.fromEntries(soc.items.map((x) => [x.id, x]));
  assert.equal(by['CC6.1'].level, 'fully', 'both mapped controls met'); assert.match(by['CC6.1'].why, /ZS-2-2-01 fully/);
  assert.equal(by['CC6.8'].level, 'not', 'EDR gap');
  assert.equal(by['CC6.3'].level, 'partially');
  assert.equal(by['CC7.3'].level, 'not_assessed', 'mapped control not assessed is never a pass');
  assert.equal(by['CC3.2'].level, 'not_assessed', 'control missing from the register');
  assert.equal(by['A1.2'].level, 'na', 'Availability not in scope yet'); assert.equal(by['A1.2'].in_scope, false);
  assert.equal(iso.items.find((x) => x.id === '4.3').level, 'not_assessed', 'no mapping -> not assessed, never compliant');
  assert.equal(iso.items.find((x) => x.id === 'A.2.2').level, 'fully');
  assert.equal(soc.in_scope, 33, 'security only');

  // scope: admin only, security always kept
  assert.equal((await call('POST', '/frameworks-x/settings', { soc2_scope: ['availability'] }, OP)).status, 403);
  r = await call('POST', '/frameworks-x/settings', { soc2_scope: ['nonsense'] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /soc2_scope/);
  r = await call('POST', '/frameworks-x/settings', { soc2_scope: ['availability', 'privacy'] }, ADM); assert.equal(r.status, 200); assert.deepEqual(r.json.soc2_scope, ['security', 'availability', 'privacy']);
  assert.equal((await item('soc2', 'A1.1')).level, 'not_assessed', 'in scope now, no mapping');
  assert.equal((await item('soc2', 'PI1.1')).level, 'na', 'processing integrity still out');

  // confirm (operator): validation, evidence, unknown items
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'fully' }, VIEW)).status, 403);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'great' }); assert.equal(r.status, 400); assert.match(r.text, /level/);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'fully' }); assert.equal(r.status, 400); assert.match(r.text, /evidence/);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'na' }); assert.equal(r.status, 400); assert.match(r.text, /note/);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/ZZ9/confirm', { level: 'not' })).status, 404);
  assert.equal((await call('POST', '/frameworks-x/nist/items/CC3.2/confirm', { level: 'not' })).status, 404);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'not' }, { user: 'ai:grc', role: 'operator' })).status, 403, 'an AI identity does not confirm');
  r = await call('POST', '/frameworks-x/soc2/items/CC3.2/confirm', { level: 'fully', evidence: 'Risk assessment RA-2026 (synthetic)', extra: 'dropped' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'pending');
  let it = await item('soc2', 'CC3.2'); assert.equal(it.level, 'not_assessed', 'pending changes nothing'); assert.equal(it.pending.by, 'nora.syn');
  assert.deepEqual((await item('soc2', 'CC3.2', VIEW)).pending, { level: 'fully' }, 'a viewer sees no names');

  // decide (admin, four eyes)
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/decide', { decision: 'approve' }, OP)).status, 403);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.2/decide', { decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /note/);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/decide', { decision: 'approve' }, { user: 'svc:sync', role: 'admin' })).status, 403);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.3/confirm', { level: 'partially', evidence: 'fraud register (synthetic)' }, ADM); assert.equal(r.status, 200);
  r = await call('POST', '/frameworks-x/soc2/items/CC3.3/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/decide', { decision: 'approve' }, ADM)).status, 200);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.2/decide', { decision: 'approve' }, ADM2)).status, 409, 'nothing pending any more');
  it = await item('soc2', 'CC3.2'); assert.equal(it.level, 'fully'); assert.equal(it.source, 'confirmed'); assert.match(it.why, /approved by adam\.syn/);
  assert.equal((await call('POST', '/frameworks-x/soc2/items/CC3.3/decide', { decision: 'reject', note: 'the register is a draft' }, ADM2)).status, 200);
  assert.equal((await item('soc2', 'CC3.3')).level, 'not_assessed', 'rejected changes nothing');

  // expiry after 12 months: back to derived
  setNow(T0 + 366 * 86400000);
  it = await item('soc2', 'CC3.2'); assert.equal(it.level, 'not_assessed'); assert.equal(it.expired, true);

  // export (operator) and audit
  assert.equal((await call('GET', '/frameworks-x/soc2/export', undefined, VIEW)).status, 403);
  r = await call('GET', '/frameworks-x/iso42001/export'); assert.equal(r.status, 200); assert.match(r.json.csv, /^"Framework","Item"/); assert.match(r.json.filename, /ISO-42001/);
  const acts = e.app.store.auditTail(200).map((a) => a.action);
  for (const a of ['fx.settings', 'fx.confirm', 'fx.approve', 'fx.reject', 'fx.export']) assert.ok(acts.includes(a), a + ' audited');
  const au = e.app.store.auditTail(200).find((a) => a.action === 'fx.approve'); assert.equal(au.by, 'adam.syn'); assert.equal(au.role, 'admin');
});

test('no NCA ECC: everything not assessed; crosswalk carries both frameworks', async (t) => {
  const { e, call } = await setup(t, {});
  delete e.app.addons.ncaEcc;
  const v = (await call('GET', '/frameworks-x', undefined, VIEW)).json;
  for (const f of v.frameworks) { assert.equal(f.counts.fully, 0); assert.equal(f.pct_fully, 0); assert.equal(f.ecc, 'NCA ECC is not installed'); }
  const X = await e.app.addons.frameworksX.view('soc2');
  assert.ok(X.items.every((x) => x.level === 'not_assessed' || x.level === 'na'));
  assert.ok(X.items.find((x) => x.id === 'CC6.1').ecc.includes('ZS-2-2-01'));
});
