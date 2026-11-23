// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// One compliance language on the register pages (engine/compliance-levels.js): fully / partially / not compliant / not
// assessed, the share of each in whole percentages adding up to 100, and the group status - for PDPL (by area) and NDMO (by
// domain) through the real routes, as NCA ECC does. "Not assessed" (an automated pass still to confirm, no evidence, waiting)
// is never counted as compliant. The NDMO export opens with the summary. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const CL = require('../engine/compliance-levels');
const { PDPL_LEVEL } = require('../engine/pdpl');

const OP = { user: 'nora.syn', role: 'operator' };
const sum = (n) => Object.values(n.pct).reduce((a, b) => a + b, 0);

test('levels: statuses, shares that add up to 100, not applicable left out', () => {
  const M = { ok: 'fully', half: 'partially', bad: 'not', none: 'not_assessed', na: 'na' };
  const L = (rs) => CL.levels(rs.map((result) => ({ result })), M);
  assert.equal(L(['ok', 'ok']).status, 'fully_compliant');
  assert.equal(L(['ok', 'bad']).status, 'partially_compliant', 'one met, one not: partially, not "gap"');
  assert.equal(L(['half', 'none']).status, 'partially_compliant');
  assert.equal(L(['bad', 'none']).status, 'not_compliant');
  assert.equal(L(['none', 'none']).status, 'not_assessed', 'nothing assessed is never compliant');
  assert.equal(L(['na']).status, 'not_applicable'); assert.equal(L(['na']).applicable, 0);
  const t = L(['ok', 'half', 'bad']); assert.equal(sum(t), 100, 'thirds round to exactly 100'); assert.deepEqual(t.counts, { fully: 1, partially: 1, not: 1, not_assessed: 0 });
  assert.deepEqual(L(['ok', 'bad', 'na']).pct, { fully: 50, partially: 0, not: 50, not_assessed: 0 }, 'n/a is not in the denominator');
  assert.equal(CL.levelOf('mystery', M), 'not_assessed', 'an unknown result is never compliant');
  const g = CL.group([{ a: 'x', result: 'ok' }, { a: 'y', result: 'bad' }], 'a', M, [['y', 'Why'], ['x', 'Ex']]);
  assert.deepEqual(g.map((x) => [x.key, x.name, x.status]), [['y', 'Why', 'not_compliant'], ['x', 'Ex', 'fully_compliant']]);
  assert.equal(PDPL_LEVEL.auto_pass, 'not_assessed', 'PDPL: an automated pass waits for the DPO');
});

test('PDPL and NDMO registers carry the levels overall, by area / domain and per item; the NDMO export opens with them', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
  const p = await e.req('GET', '/pdpl', OP); assert.equal(p.status, 200, p.raw);
  const v = p.json; assert.ok(v.levels && v.levels.applicable > 0); assert.equal(sum(v.levels), 100);
  assert.ok(v.by_area.length > 3 && v.by_area.every((a) => !a.applicable || sum(a) === 100));
  assert.equal(v.requirements.reduce((n, r) => n + (r.level === 'not_applicable' ? 0 : 1), 0), v.levels.applicable);
  assert.ok(v.requirements.every((r) => r.level === CL.levelOf(r.result, PDPL_LEVEL)));
  assert.equal(v.levels.counts.fully, v.counts.compliant, 'only confirmed requirements are fully compliant');
  const n = await e.req('GET', '/ndmo', OP); assert.equal(n.status, 200, n.raw);
  const d = n.json; assert.ok(d.levels.applicable > 0); assert.equal(sum(d.levels), 100);
  assert.equal(d.domain_levels.length, 15); assert.ok(d.domain_levels.every((x) => x.name && (!x.applicable || sum(x) === 100)));
  assert.ok(d.controls.every((c) => typeof c.level === 'string'));
  assert.equal(d.levels.counts.not, d.counts.gap || 0, 'NDMO gaps are not compliant');
  const x = await e.req('GET', '/ndmo/export', OP); assert.equal(x.status, 200, x.raw);
  assert.match(x.json.csv, /^"Level","Code","Name","Status","Fully compliant %"/); assert.match(x.json.csv, /"Overall","NDMO",/); assert.match(x.json.csv, /"Control","Domain","Title","Level"/);
});
