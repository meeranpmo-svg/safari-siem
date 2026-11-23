// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security Controls -> Compliance (engine/controls-intel.js) over the REAL GRC control monitoring with SYNTHETIC platform records: a
// control with no source is "not connected" (no score), measured controls are scored pass / partial / fail; each control lists the
// framework requirements it evidences (SAMA CSF + the crosswalk); one snapshot a day, a REGRESSION when a control that passed fails;
// raising a GRC action (operator, a person, failing or partial only, once, audited, validation naming the field); roles; advisor off.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const col = (c) => e.app.store.collection(c);
  col('assets').put({ id: 'A-1', name: 'srv01.syn', type: 'server', status: 'active' });
  for (let i = 0; i < 10; i++) col('me_ec_computers').put({ id: 'PC-' + i, name: 'pc' + i + '.syn', critical: 0 });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, col, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const card = (v, id) => v.sections[0].items.find((i) => i.id === id);

test('controls scored from the platform, not connected never scored, requirements per control', async (t) => {
  const s = await setup(t);
  const r = await s.get('/controls-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  assert.ok(card(v, 'patch').tags.includes('pass') && card(v, 'assets').tags.includes('pass'));
  const bk = card(v, 'backup'); assert.ok(bk.tags.includes('unknown')); assert.match(bk.detail.text, /Not connected/);
  assert.ok(card(v, 'patch').detail.lists[0].items.some((x) => /SAMA|3\.3\.17/.test(x)), 'the requirements it evidences');
  assert.ok(v.ring.value != null && /measured control/.test(v.ring.why)); assert.match(v.kpis[0].value, /\//);
  assert.match(v.note, /assessor decides/);
});

test('history, regression, raising a GRC action, roles', async (t) => {
  const s = await setup(t);
  const X = s.e.app.addons.controlsIntel;
  for (let d = 0; d < 3; d++) { assert.ok(await X.snapshot()); assert.equal(await X.snapshot(), null, 'one a day'); s.tick(DAY); }
  for (let i = 0; i < 5; i++) s.col('me_ec_computers').put({ id: 'PC-' + i, name: 'pc' + i + '.syn', critical: 2 });   // half the estate missing critical patches
  let v = (await s.get('/controls-intel')).json; const p = card(v, 'patch');
  assert.ok(p.tags.includes('fail') && p.tags.includes('regressed')); assert.ok(p.badges.some((b) => /regressed - passed 2026-11-04/.test(b.text)));
  assert.ok(v.sections[1].items.some((i) => i.id === 'patch'), 'leverage lists the failing control');
  assert.equal((await s.post('/controls-intel/patch/action', {}, VIEW)).status, 403);
  assert.equal((await s.post('/controls-intel/patch/action', {}, BOT)).status, 403, 'a service identity never raises');
  let r = await s.post('/controls-intel/patch/action', { due: '2020-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  r = await s.post('/controls-intel/assets/action', {}); assert.equal(r.status, 409, 'a passing control is not raised');
  r = await s.post('/controls-intel/patch/action', { owner: 'nora.syn', due: '2026-12-31' }); assert.equal(r.status, 200, r.raw); assert.match(r.json.action.id, /^ACT-/);
  assert.equal((await s.post('/controls-intel/patch/action', {})).status, 409, 'once only (an open action already tracks it)');
  v = (await s.get('/controls-intel')).json; assert.ok(card(v, 'patch').badges.some((b) => /GRC action open/.test(b.text))); assert.equal(card(v, 'patch').actions.length, 0);
  assert.equal(s.audit('controls-intel.raise').length, 1);
  assert.equal((await s.post('/controls-intel/ask', { question: 'what first?' }, VIEW)).status, 403);
  r = await s.post('/controls-intel/ask', { question: 'x' }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/controls-intel/ask', { question: 'what should we fix first?' })).status, 424);
});

test('the requirement -> control -> evidence chain for the flow page: state, evidence and every requirement reached', async (t) => {
  const s = await setup(t);
  const v = (await s.get('/controls-intel', VIEW)).json;
  assert.ok(Array.isArray(v.chain) && v.chain.length === v.sections[0].items.length, 'one chain entry per control');
  const p = v.chain.find((c) => c.key === 'patch'), b = v.chain.find((c) => c.key === 'backup');
  assert.equal(p.state, 'pass'); assert.ok(p.requirements.some((r) => r.fw === 'sama'), 'requirements it reaches'); assert.equal(p.requirements_total, p.requirements.length);
  assert.equal(b.state, 'unknown', 'not connected stays not connected - evidences nothing');
  assert.ok(v.framework_names && typeof v.framework_names === 'object');
});
