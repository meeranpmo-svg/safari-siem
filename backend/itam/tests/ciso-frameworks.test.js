// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI CISO for an organisation not under SAMA (brand modules_off fw-sama, as for Safari): the compliance domain is scored from
// the NCA ECC register and Aramco CCC readiness, never SAMA; the SIEM is not asked for SAMA coverage; neither assessed = not
// measured (no free pass); one held = that one; both = their mean. Engines stubbed with SYNTHETIC figures.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createCiso } = require('../engine/ciso');

const notConnected = () => Promise.reject(Object.assign(new Error('SIEM link not configured'), { notConnected: true }));

test('compliance domain from NCA ECC and Aramco CCC when SAMA is off for the organisation', async (t) => {
  const off = new Set(require('../engine/brand').modules_off || []);
  assert.ok(off.has('fw-sama'), 'this brand is not under SAMA');
  const e = await startApp({ noAi: true, config: { ciso: { all_frameworks: false } } }); t.after(() => e.close());
  const calls = []; const siem = (m, p) => { calls.push(p); return notConnected(); };
  e.app.addons = e.app.addons || {};
  const C = createCiso(e.app, { siem, noTimer: true });
  assert.match(C.DOMAINS.find((d) => d.id === 'compliance').name, /NCA ECC/);
  let v = await C.overview(true);
  let d = v.posture.domains.find((x) => x.id === 'compliance');
  assert.equal(d.measured, false, 'nothing assessed: not measured'); assert.match(d.not_measured_why, /NCA ECC/);
  assert.ok(!calls.includes('/compliance/sama'), 'the SIEM is not asked for SAMA: ' + calls.join(','));
  assert.ok(!v.sources.some((s) => s.id === 'sama'));
  e.app.addons.aramcoCcc = { view: () => ({ controls_total: 10, score: 60, assessed: 8, applicable: 10, stages: [{ done: true }, { done: false }], days_left: 100 }) };
  v = await C.overview(true); d = v.posture.domains.find((x) => x.id === 'compliance');
  assert.equal(d.score, 60); assert.match(d.items[0].label, /Aramco CCC readiness 60%/);
  e.app.addons.ncaEcc = { view: async () => ({ score: 80, counts: { pass: 8 } }) };
  v = await C.overview(true); d = v.posture.domains.find((x) => x.id === 'compliance');
  assert.equal(d.score, 70, 'the mean of the two'); assert.equal(d.items.length, 2);
  assert.deepEqual(v.compliance.frameworks, ['nca', 'aramco']); assert.equal(v.compliance.nca.score, 80); assert.equal(v.compliance.aramco.stages_done, 1); assert.equal(v.compliance.sama, null);
});

// the register reads this overview's records and the overview reads the register's score: no endless loop (a fresh engine hung on
// /nca-ecc-intel and /iso-lifecycle); the register still gets the overview's other records, the overview still gets the score
test('NCA ECC register and the CISO overview read each other without looping', async (t) => {
  const e = await startApp({ noAi: true, config: { ciso: { all_frameworks: false } } }); t.after(() => e.close());
  e.app.addons = e.app.addons || {};
  const C = createCiso(e.app, { siem: notConnected, noTimer: true }); e.app.addons.ciso = C;
  let views = 0, seen = null;
  e.app.addons.ncaEcc = { view: async () => { views++; if (views > 3) throw new Error('loop'); const S = await C.collect(); seen = Object.keys(S).sort(); return { score: 66, counts: {} }; } };
  const v = await Promise.race([C.overview(true), new Promise((_, bad) => setTimeout(() => bad(new Error('timed out - the two loop')), 5000))]);
  assert.equal(views, 1, 'the register is read once');
  assert.ok(seen.includes('grc') && !seen.includes('nca'), 'inside the register the overview skips the register: ' + seen);
  assert.equal(v.compliance.nca.score, 66);
});

