// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Continuous Compliance & Auto-Remediation (engine/contcomp-intel.js) over a SYNTHETIC gap analysis: no drift before the first snapshot;
// a new gap is NEW DRIFT, a disappeared one RESOLVED, a framework that dropped is said; time to fix learned per severity; auto-remediation
// (admin setting, versioned, validated) raises GRC tracking actions for new high drift as system:contcomp, once, audited - never more
// than tracking; a person raises any gap by hand (once, validation naming the field); roles; advisor off.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'operator' };
const gap = (key, sev) => ({ key, title: 'Synthetic gap ' + key, severity: sev, frameworks: ['ecc', 'sama'], refs: [{ fw: 'ecc', id: key.split(':')[1], level: 'not', why: 'synthetic' }], priority: 50 });
function fakeXw() { const S = { items: [gap('ECC:2-2-1', 'high'), gap('ECC:2-3-1', 'medium')], pct: { ecc: 60, sama: 55 } };
  return { S, gaps: async () => ({ items: JSON.parse(JSON.stringify(S.items)), frameworks: { ecc: { available: true, pct_fully: S.pct.ecc, gaps: S.items.length }, sama: { available: true, pct_fully: S.pct.sama, gaps: 1 } }, names: { ecc: 'NCA ECC', sama: 'SAMA CSF' }, forecast: { ecc: { why: 'needs 3 daily snapshots (synthetic)' } } }) }; }
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const X = fakeXw(); e.app.addons.crosswalk = X;
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, X, C: e.app.addons.contcompIntel, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const card = (v, id) => v.sections[1].items.find((i) => i.id === id);

test('drift, resolved, framework drop, time to fix; auto-remediation raises tracking actions only when switched on', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/contcomp-intel', VIEW)).json; assert.match(v.ring.why, /first daily snapshot/); assert.ok(card(v, 'ECC:2-2-1').tags.includes('open'));
  assert.ok(await s.C.snapshot()); s.tick(DAY);
  s.X.S.items = [gap('ECC:2-3-1', 'medium'), gap('ECC:2-9-9', 'high'), gap('ECC:1-1-1', 'low')]; s.X.S.pct.ecc = 50;   // 2-2-1 fixed, two new, ECC down
  assert.ok(await s.C.snapshot(), 'auto-remediation is off: nothing raised');
  assert.equal(s.audit('contcomp-intel.auto-raise').length, 0);
  v = (await s.get('/contcomp-intel')).json;
  assert.ok(card(v, 'ECC:2-9-9').tags.includes('new') && card(v, 'ECC:1-1-1').tags.includes('new') && card(v, 'ECC:2-2-1').tags.includes('resolved'));
  assert.match(v.sections[0].items.find((f) => f.id === 'ecc').label, /down from 60/); assert.match(v.sections[2].text, /high: 1 d median over 1/);
  // switch auto-remediation on (high only) and drift again
  let r = await s.post('/contcomp-intel/settings', { auto_raise: 'high', version: 0 }); assert.equal(r.status, 403, 'administrators only');
  r = await s.post('/contcomp-intel/settings', { auto_raise: 'everything', version: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /auto_raise/);
  r = await s.post('/contcomp-intel/settings', { auto_raise: 'high', version: 0 }, ADM); assert.equal(r.status, 200); assert.equal(r.json.version, 1);
  assert.equal((await s.post('/contcomp-intel/settings', { auto_raise: 'all', version: 0 }, ADM)).status, 409);
  s.tick(DAY); s.X.S.items.push(gap('ECC:3-1-1', 'high'), gap('ECC:3-2-1', 'medium'));
  assert.ok(await s.C.snapshot());
  const ar = s.audit('contcomp-intel.auto-raise'); assert.equal(ar.length, 1, 'only the new high drift'); assert.equal(ar[0].target, 'ECC:3-1-1'); assert.equal(ar[0].by, 'system:contcomp');
  const acts = require('../engine/grc-registers').createGrcRegisters(s.e.app).actionList({ status: 'open' }).items.filter((a) => a.ref === 'contcomp-intel:ECC:3-1-1'); assert.equal(acts.length, 1);
  assert.equal(acts[0].status, 'open', 'a tracking action - nothing was changed on a system');
});

test('a person raises a gap by hand, once; roles; advisor', async (t) => {
  const s = await setup(t);
  assert.equal((await s.post('/contcomp-intel/ECC%3A2-2-1/raise', {}, VIEW)).status, 403);
  assert.equal((await s.post('/contcomp-intel/ECC%3A2-2-1/raise', {}, BOT)).status, 403);
  let r = await s.post('/contcomp-intel/nope/raise', {}); assert.equal(r.status, 400); assert.match(r.json.error, /key/);
  assert.equal((await s.post('/contcomp-intel/ECC%3A9-9-9/raise', {})).status, 404);
  r = await s.post('/contcomp-intel/ECC%3A2-2-1/raise', { owner: 'nora.syn' }); assert.equal(r.status, 200, r.raw);
  assert.equal((await s.post('/contcomp-intel/ECC%3A2-2-1/raise', {})).status, 409);
  assert.equal(s.audit('contcomp-intel.raise').length, 1);
  assert.equal((await s.post('/contcomp-intel/ask', { question: 'what drifted this week?' })).status, 424);
});
