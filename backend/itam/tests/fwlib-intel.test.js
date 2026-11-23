// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Regulatory Framework Library (engine/fwlib-intel.js) over the REAL crosswalk and framework registers (NCA ECC with SYNTHETIC facts,
// ISO 27001, NDMO, SAMA): every framework held with its requirement / assessed / mapped counts, a framework not installed said, every
// requirement searchable with its level and ECC mapping, mapping suggestions that only an administrator confirms (through the crosswalk
// route, audited there); any signed-in role reads; the advisor's search tool; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 18, policies: [], control_status: {} }, risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

test('frameworks held, requirements, mapping suggestions confirmed only by an administrator', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  const r = await e.req('GET', '/fwlib-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const ecc = v.sections[0].items.find((i) => i.id === 'ecc'); assert.ok(ecc.tags.includes('installed') && ecc.metrics[0].value > 20, 'the NCA ECC register: its controls');
  assert.ok(v.sections[0].items.every((i) => i.tags.includes('installed') || (i.tags.includes('missing') && i.tone === 'na')));
  assert.ok(v.sections[1].rows.length > 100 && v.sections[1].rows.every((x) => x.cells.length === 5), 'every requirement in one table');
  assert.equal(v.kpis.find((k) => k.label === 'Requirements').value, v.sections[1].rows.length);
  const sug = v.sections[2].items; assert.ok(sug.length > 0, 'unmapped requirements get suggestions');
  {
    const a = sug[0].actions[0]; assert.equal(a.role, 'admin'); assert.equal(a.path, '/crosswalk/mappings');
    assert.equal((await e.req('POST', a.path, Object.assign({ body: a.body }, OP))).status, 403, 'an operator cannot confirm a mapping');
    const ok = await e.req('POST', a.path, Object.assign({ body: a.body }, ADM)); assert.equal(ok.status, 200, ok.raw);
    const v2 = (await e.req('GET', '/fwlib-intel', VIEW)).json; assert.ok(!v2.sections[2].items.some((i) => i.id === sug[0].id), 'a confirmed mapping is no longer suggested');
  }
  const X = e.app.addons.fwlibIntel, find = X.TOOLS.find((x) => x.name === 'find_requirements'); assert.ok(find, 'the advisor can search requirements');
  assert.match(v.note, /only an administrator confirms/);
  assert.equal((await e.req('POST', '/fwlib-intel/ask', { body: { question: 'what covers access control?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await e.req('POST', '/fwlib-intel/ask', { body: { question: 'what covers access control?' }, user: 'nora.syn', role: 'operator' })).status, 424);
});
