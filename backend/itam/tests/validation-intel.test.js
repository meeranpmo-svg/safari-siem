// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Control Validation (engine/validation-intel.js) over a SYNTHETIC crosswalk and the REAL policy register / control monitoring: a line
// where one framework says fully met and another not met is a DISAGREEMENT; an attested policy for a SAMA control whose measured control
// fails is a CONTRADICTION; consistent lines score, unassessed lines are listed and never counted; trust per framework (Beta(1,1));
// a finding new since yesterday; a GRC action to resolve it raised by a person (once, audited, validation naming the field); roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const it = (fw, id, level) => ({ fw, id, title: fw + ' ' + id + ' (synthetic)', level, why: level === 'not' ? 'no evidence (synthetic)' : '' });
function fakeXw() {
  const L = [
    { ecc_id: '2-2-1', title: 'Identity and access (synthetic)', severity: 'high', frameworks: ['ecc', 'sama', 'iso'], state: 'disagree', items: [it('ecc', '2-2-1', 'fully'), it('sama', '3.3.5', 'not'), it('iso', 'A.5.15', 'fully')] },
    { ecc_id: '2-3-1', title: 'Malware (synthetic)', severity: 'medium', frameworks: ['ecc', 'sama'], state: 'met', items: [it('ecc', '2-3-1', 'fully'), it('sama', '3.3.7', 'fully')] },
    { ecc_id: '2-4-1', title: 'Email (synthetic)', severity: 'medium', frameworks: ['ecc', 'iso'], state: 'gap', items: [it('ecc', '2-4-1', 'not'), it('iso', 'A.8.23', 'partially')] },
    { ecc_id: '2-5-1', title: 'Network (synthetic)', severity: 'low', frameworks: ['ecc'], state: 'na', items: [it('ecc', '2-5-1', 'na')] },
  ];
  return { L, crosswalk: async () => ({ lines: JSON.parse(JSON.stringify(L)), names: { ecc: 'NCA ECC', sama: 'SAMA CSF', iso: 'ISO 27001' } }) };
}
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const X = fakeXw(); e.app.addons.crosswalk = X;
  for (let i = 0; i < 10; i++) e.app.store.collection('me_ec_computers').put({ id: 'PC-' + i, name: 'pc' + i + '.syn', critical: i < 5 ? 2 : 0 });   // patching fails
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const s = { e, X, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
  assert.equal((await s.post('/grc/policy/IT-OPS-004/attest', { note: 'patching followed (synthetic)' })).status, 200);
  return s;
}
const f = (v, id) => v.sections[0].items.find((i) => i.id === id);

test('disagreement, claim vs measurement, consistency score, trust, unassessed', async (t) => {
  const s = await setup(t);
  const r = await s.get('/validation-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const x = f(v, 'X-2-2-1'); assert.ok(x.tags.includes('disagree')); assert.ok(x.detail.lists[0].items.some((i) => /NCA ECC 2-2-1/.test(i)) && x.detail.lists[1].items.some((i) => /SAMA CSF 3.3.5 \(not met/.test(i)));
  const c = v.sections[0].items.find((i) => i.tags.includes('contradiction')); assert.ok(c, 'an attested policy against a failing measured control'); assert.ok(c.detail.lists[0].items.some((i) => /IT-OPS-004/.test(i)) && c.detail.lists[1].items.some((i) => /patches/i.test(i)));
  assert.equal(v.ring.value, 67, '2 consistent of 3 judged; the unassessed line is not counted');
  assert.ok(v.sections[2].items.some((i) => i.id === '2-5-1'), 'unassessed listed');
  const iso = v.sections[1].items.find((i) => i.id === 'iso'); assert.match(iso.label, /1 of 1 contradicted/);
  assert.match(v.note, /does not decide which side is right/);
});

test('new since yesterday, a resolution action by a person, roles', async (t) => {
  const s = await setup(t), V = s.e.app.addons.validationIntel;
  assert.ok(await V.snapshot()); s.tick(DAY);
  s.X.L[1].state = 'disagree'; s.X.L[1].items[1].level = 'not';
  let v = (await s.get('/validation-intel')).json; assert.ok(f(v, 'X-2-3-1').tags.includes('new')); assert.ok(!f(v, 'X-2-2-1').tags.includes('new'));
  assert.equal((await s.post('/validation-intel/X-2-2-1/resolve', {}, VIEW)).status, 403);
  assert.equal((await s.post('/validation-intel/X-2-2-1/resolve', {}, BOT)).status, 403);
  let r = await s.post('/validation-intel/bad%20id/resolve', {}); assert.equal(r.status, 400);
  r = await s.post('/validation-intel/X-2-2-1/resolve', { due: '2020-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  assert.equal((await s.post('/validation-intel/X-9-9-9/resolve', {})).status, 404);
  r = await s.post('/validation-intel/X-2-2-1/resolve', { owner: 'nora.syn' }); assert.equal(r.status, 200, r.raw);
  assert.equal((await s.post('/validation-intel/X-2-2-1/resolve', {})).status, 409, 'once');
  v = (await s.get('/validation-intel')).json; assert.ok(f(v, 'X-2-2-1').badges.some((b) => /GRC action open/.test(b.text)));
  assert.equal(s.audit('validation-intel.resolve').length, 1);
  assert.equal((await s.post('/validation-intel/ask', { question: 'what would an auditor find?' })).status, 424);
});
