// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NDMO Studio (engine/ndmo-intel.js) over the REAL NDMO register (engine/ndmo.js, Python rules) and a SYNTHETIC register for the history:
// 15 domains with score and indicative maturity; every control with its result and why; the biggest gains (approvals first); a control
// that regressed against 30 days ago; a control that passes now but failed often is "likely to fail next" (Beta(1,1)); the projection;
// the gaps-to-GRC action points at the register's own route; any signed-in role reads; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const sec = (v, id) => v.sections.find((s) => s.id === id);

test('over the real register: 15 domains, every control with why, gains and the gaps-to-GRC action', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/ndmo-intel', VIEW); assert.equal(r.status, 200, r.text); const v = r.json;
  assert.equal(sec(v, 'domains').items.length, 15); assert.equal(sec(v, 'domaincards').items.length, 15);
  const rows = sec(v, 'controls').rows; assert.ok(rows.length >= 40); assert.ok(rows.every((x) => /^ZS-[A-Z]{2,3}-\d{2}$/.test(x.id)));
  const ne = rows.find((x) => x.tags.includes('no_evidence')); assert.ok(ne && /Next action: record it with/.test(ne.detail.text), 'a control without evidence says what to record');
  assert.ok(sec(v, 'gains').items.length > 0 && /^\+\d/.test(sec(v, 'gains').items[0].badges[0].text));
  assert.equal(v.actions[0].path, '/ndmo/gaps-to-grc', 'the action goes to the register\'s own audited route');
  assert.match(sec(v, 'basis').text, /indicative/);
});

test('learning over a synthetic register: regressed, likely to fail next, movement, approvals first, projection', async (t) => {
  let clock = Date.parse('2026-09-01T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const S = { a: 'met', b: 'gap', score: 40 };
  const ctl = (id, result, o) => Object.assign({ id, domain: 'DQ', domain_name: 'Data Quality', title: 'Synthetic control ' + id, result, why: 'synthetic', severity: 'medium', automated: true, auto_state: result === 'gap' ? false : true, evidence_hint: 'a report' }, o);
  e.app.addons.ndmo = { view: async () => ({ score: S.score, coverage: { total: 10, mapped: 7, unmapped: 3 },
    maturity: [{ domain: 'DQ', name: 'Data Quality', controls: 4, applicable: 4, score: S.score, level: 3, level_name: 'Activated', met: 1, auto: 1, gaps: 1, no_evidence: 1 }],
    controls: [ctl('ZS-DQ-01', S.a), ctl('ZS-DQ-02', S.b), ctl('ZS-DQ-03', 'pending', { severity: 'low', automated: false }), ctl('ZS-DQ-04', 'auto_pass')] }) };
  const X = e.app.addons.ndmoIntel;
  for (let d = 0; d < 40; d++) { S.b = d % 3 === 0 ? 'gap' : 'auto_pass'; S.score = 40 + d; if (d === 36) S.a = 'gap'; assert.ok(await X.snapshot()); clock += DAY; }
  S.b = 'auto_pass';
  const v = (await e.req('GET', '/ndmo-intel', OP)).json;
  assert.ok(sec(v, 'regressed').items.some((i) => i.id === 'rZS-DQ-01'), 'met 30 days ago, a gap now');
  assert.ok(sec(v, 'controls').rows.find((r) => r.id === 'ZS-DQ-01').tags.includes('regressed'));
  const lk = sec(v, 'learning').items.find((i) => i.id === 'lZS-DQ-02'); assert.ok(lk, 'passes now but failed on 14 of 40 days'); assert.match(lk.sub, /failing on 14 of 40 day/);
  assert.equal(sec(v, 'gains').items[0].id, 'gZS-DQ-01', 'the high-weight gap first');
  assert.ok(sec(v, 'gains').items.some((i) => i.id === 'gZS-DQ-03' && /approve the pending record/.test(i.sub)));
  assert.ok(sec(v, 'domaincards').items[0].badges.some((b) => /\+\d+ pts \(30 d\)/.test(b.text)), 'movement against 30 days ago');
  assert.match(v.kpis.find((k) => k.label === 'Projected 80 %').value, /^(\d{4}-\d{2}-\d{2}|reached)$/);
  assert.match(sec(v, 'official').text, /7 of 10 official controls/);
  assert.equal((await e.req('POST', '/ndmo-intel/ask', { body: { question: 'what should we close first?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await e.req('POST', '/ndmo-intel/ask', { body: { question: 'what should we close first?' }, user: 'nora.syn', role: 'operator' })).status, 424);
});

test('without the register the page says so', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  delete e.app.addons.ndmo;
  const v = (await e.req('GET', '/ndmo-intel', OP)).json; assert.equal(v.ring.value, null); assert.ok(v.notes.some((n) => /not installed/.test(n)));
});
