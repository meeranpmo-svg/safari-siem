// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Overview (engine/overview-intel.js) over the REAL crosswalk (NCA ECC register with SYNTHETIC facts) and the REAL risk
// assessment / validation / continuous compliance modules: frameworks with their measured share and projection, a framework without a
// register said (never counted), the top ten priorities, risk above appetite, remediation delivery (open / overdue actions), the
// overall trend after snapshots; any signed-in role reads; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 3, attested: 18, policies: [], control_status: {} }, risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

test('frameworks, priorities, risk, delivery, trend', async (t) => {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  e.app.store.collection('grc_actions').put({ id: 'ACT-9001', title: 'Synthetic overdue action', source: 'manual', ref: '', priority: 'high', status: 'open', owner: 'nora.syn', due: '2026-10-01', evidence: [], history: [], created_at: '2026-09-01T00:00:00Z' });
  const r = await e.req('GET', '/overview-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const ecc = v.sections[0].items.find((i) => i.id === 'ecc'); assert.ok(ecc && ecc.tags.includes('installed') && /%/.test(ecc.metrics[0].value));
  assert.ok(v.sections[0].items.length >= 3 && v.sections[0].items.every((i) => i.tags.includes('installed') || (i.tags.includes('missing') && i.tone === 'na')), 'every framework is listed with its source state; a missing register is never scored');
  assert.ok(v.sections[1].items.length > 0 && v.sections[1].items.length <= 10, 'top ten priorities');
  assert.ok(v.sections[1].items[0].detail.lists[0].items.length > 0, 'what each priority closes');
  const high = v.sections[3].items.find((i) => i.id === 'high'); assert.match(high.label, /1 overdue/);
  assert.ok(v.kpis.find((k) => k.label === 'Overdue actions').value.startsWith('1 /'));
  assert.ok(v.kpis.find((k) => k.label === 'Risk exposure'), 'the risk assessment is read');
  assert.ok(v.ring.value != null); assert.match(v.note, /regulators/);
  const X = e.app.addons.overviewIntel; for (let d = 0; d < 3; d++) { assert.ok(await X.snapshot()); clock += 86400000; }
  const v2 = (await e.req('GET', '/overview-intel', OP)).json; assert.ok(v2.sections[4].points.length === 3 && /a week over 3 snapshots/.test(v2.sections[4].text));
  assert.equal((await e.req('POST', '/overview-intel/ask', { body: { question: 'where do we stand?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await e.req('POST', '/overview-intel/ask', { body: { question: 'where do we stand?' }, user: 'nora.syn', role: 'operator' })).status, 424);
});

test('visual: shares per framework add up, coverage, overlap matrix is symmetric, backlog ranked, series from snapshots', async (t) => {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  const X = e.app.addons.overviewIntel; for (let d = 0; d < 3; d++) { assert.ok(await X.snapshot()); clock += 86400000; }
  const V = (await e.req('GET', '/overview-intel', VIEW)).json.visual;
  const ecc = V.frameworks.find((f) => f.id === 'ecc'); assert.ok(ecc.available && ecc.items > 0);
  const sum = ecc.shares.fully + ecc.shares.partially + ecc.shares.not + ecc.shares.not_assessed; assert.ok(Math.abs(sum - 100) <= 0.5, 'shares add up to 100: ' + sum);
  assert.equal(ecc.coverage, Math.round((ecc.items - ecc.counts.not_assessed) / ecc.items * 100));
  assert.equal(ecc.series.length, 3, 'one point per daily snapshot');
  const M = V.overlap.matrix; assert.equal(M.length, V.overlap.keys.length);
  for (let i = 0; i < M.length; i++) for (let j = 0; j < M.length; j++) assert.equal(M[i][j], M[j][i], 'symmetric');
  assert.ok(V.overlap.shared_items <= V.overlap.items);
  assert.ok(V.backlog.every((b, i, L) => !i || L[i - 1].unknown >= b.unknown), 'backlog ranked by unknown items');
  const pdpl = V.frameworks.find((f) => f.id === 'pdpl'); assert.ok(pdpl.pct_fully == null, 'nothing assessed is never a score');
  assert.equal(V.overall.series.length, 3);
});
