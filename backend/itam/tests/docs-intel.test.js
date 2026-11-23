// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Documents & Evidence (engine/docs-intel.js) over the REAL evidence and policy registers with SYNTHETIC evidence: freshness
// (current / due in 30 days / stale), the renewal wave, coverage per framework, a file reused for two controls, renewals learned per
// owner (a newer item collected after the older one's due date is late), a renewal action raised by a person (stale / due only, once,
// validation naming the field, audited); roles; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const T0 = Date.parse('2026-11-02T08:00:00Z'), d = (n) => new Date(T0 + n * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const ev = e.app.store.collection('grc_evidence');
  const put = (id, o) => ev.put(Object.assign({ id, framework: 'SAMA CSF', control: '3.3.5', title: 'Synthetic evidence ' + id, kind: 'document', owner: 'nora.syn', valid_days: 365, status: 'active', file: { filename: id + '.pdf', sha256: 'a'.repeat(64) + id }, created_by: 'seed', created_at: d(-400) }, o));
  put('EVD-0001', { control: '3.3.5', collected: d(-500), next_due: d(-135), owner: 'omar.syn' });                     // old, renewed late by EVD-0002
  put('EVD-0002', { control: '3.3.5', collected: d(-100), next_due: d(265), owner: 'omar.syn' });                      // current
  put('EVD-0003', { control: '3.3.14', collected: d(-380), next_due: d(-15), title: 'Log review record (synthetic)' }); // stale
  put('EVD-0004', { control: '3.3.8', collected: d(-350), next_due: d(15), file: { filename: 'shared.pdf', sha256: 'b'.repeat(64) } });   // due soon
  put('EVD-0005', { framework: 'NCA ECC', control: '2-3-1', collected: d(-10), next_due: d(355), file: { filename: 'shared.pdf', sha256: 'b'.repeat(64) } });  // same file
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}
const ev = (v, id) => v.sections[0].items.find((i) => i.id === id);

test('freshness, wave, coverage, reuse and renewal risk', async (t) => {
  const s = await setup(t);
  const r = await s.get('/docs-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  assert.ok(ev(v, 'EVD-0003').tags.includes('stale') && ev(v, 'EVD-0004').tags.includes('due_soon') && ev(v, 'EVD-0002').tags.includes('current'));
  assert.ok(ev(v, 'EVD-0004').tags.includes('reused') && ev(v, 'EVD-0005').tags.includes('reused'), 'one file evidencing two controls');
  assert.match(ev(v, 'EVD-0004').detail.rows.find((x) => x[0] === 'Renewal risk')[1], /team: 1 of 1 renewals late/, 'no history of its own: the team rate');
  assert.match(ev(v, 'EVD-0002').detail.rows.find((x) => x[0] === 'Renewal risk')[1], /omar\.syn: 1 of 1 renewals late/, 'the owner\'s own history');
  assert.match(v.sections[4].text, /renewals: 1 of 1 late/);
  assert.equal(v.sections[1].items.length, 6); assert.ok(v.sections[1].items[0].value >= 1, 'the item due in 15 days is in this or next month');
  const sama = v.sections[2].items.find((c) => c.id === 'SAMA CSF'); assert.ok(sama && sama.label === '2 / 3', 'SAMA CSF: 3.3.5 and 3.3.8 current, 3.3.14 stale');
  assert.ok(v.sections[3].items.length > 5, 'the policy register is listed'); assert.ok(v.ring.value > 0 && v.ring.value < 100);
  assert.match(v.note, /auditor decides/);
});

test('a renewal action raised by a person, once; roles; advisor', async (t) => {
  const s = await setup(t);
  assert.equal((await s.post('/docs-intel/EVD-0003/renew', {}, VIEW)).status, 403);
  assert.equal((await s.post('/docs-intel/EVD-0003/renew', {}, BOT)).status, 403);
  let r = await s.post('/docs-intel/nope/renew', {}); assert.equal(r.status, 400); assert.match(r.json.error, /id/);
  r = await s.post('/docs-intel/EVD-0003/renew', { due: '2020-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  assert.equal((await s.post('/docs-intel/EVD-0002/renew', {})).status, 409, 'current evidence is not renewed');
  r = await s.post('/docs-intel/EVD-0003/renew', { owner: 'nora.syn', due: d(20) }); assert.equal(r.status, 200, r.raw); assert.match(r.json.action.id, /^ACT-/);
  const v = (await s.get('/docs-intel')).json; assert.ok(ev(v, 'EVD-0003').badges.some((b) => /renewal action open/.test(b.text))); assert.equal(ev(v, 'EVD-0003').actions.length, 0, 'once');
  assert.equal(s.audit('docs-intel.renew').length, 1);
  assert.equal((await s.post('/docs-intel/ask', { question: 'what to renew?' }, VIEW)).status, 403);
  assert.equal((await s.post('/docs-intel/ask', { question: 'what should we renew first?' })).status, 424);
});
