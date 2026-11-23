// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cybersecurity Maturity Level (engine/maturity-intel.js) over the REAL SAMA CSF assessment (engine/sama-ia.js) and a SYNTHETIC one for the
// history: subdomains with their indicative level and why, a subdomain with no evidence NOT RATED (never 0), domain means over rated
// subdomains only, the gap to target and the next step from the assessment's priorities; snapshots, a subdomain that moved up against 30
// days ago, the projection of the mean level; any signed-in role reads; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };

test('over the real assessment: levels, not rated, domain means, next step', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/maturity-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const subs = v.sections[1].items; assert.ok(subs.length >= 20);
  const nr = subs.filter((s) => s.tags.includes('not_rated')); assert.ok(nr.length > 0 && nr.every((s) => s.metrics[0].value === '—'), 'no evidence = not rated, never 0');
  const g = subs.find((s) => s.id === '3.1.1'); assert.ok(g.tags.includes('below')); assert.ok(g.detail.lists[0].items.some((x) => /SA-3\.1\.1-01/.test(x)), 'the next step from the assessment');
  assert.match(v.kpis.find((k) => k.label === 'Rated').value, /^\d+ \/ \d+$/); assert.match(v.note, /indicative/);
});

test('history over a synthetic assessment: moved up, projection', async (t) => {
  let clock = Date.parse('2026-09-01T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const S = { l: 1 }, sub = (id, lv) => ({ id, name: 'Synthetic ' + id, domain: '3.3', maturity: { level: lv, why: 'synthetic', incomplete: false }, status: 'partially', counts: { compliant: 1, partially: 1, not: 1, not_assessed: 0 }, score: 40 });
  e.app.addons.samaIa = { view: async () => ({ target_level: 3, levels: { 0: 'Non-existent', 1: 'Ad-hoc', 2: 'Repeatable', 3: 'Structured', 4: 'Managed', 5: 'Adaptive' }, domains: [{ id: '3.3', name: 'Operations (synthetic)', subdomains: 3 }],
    subdomains: [sub('3.3.1', S.l), sub('3.3.2', 2), Object.assign(sub('3.3.3', 0), { status: 'not_assessed', counts: { compliant: 0, partially: 0, not: 0, not_assessed: 3 } })], priorities: [] }) };
  const X = e.app.addons.maturityIntel;
  for (let d = 0; d < 40; d++) { if (d === 20) S.l = 2; if (d === 35) S.l = 3; assert.ok(await X.snapshot()); clock += DAY; }
  const v = (await e.req('GET', '/maturity-intel', OP)).json, s1 = v.sections[1].items.find((i) => i.id === '3.3.1');
  assert.ok(s1.tags.includes('up') && s1.badges.some((b) => /up from L1/.test(b.text)), 'moved up against 30 days ago');
  assert.ok(v.sections[1].items.find((i) => i.id === '3.3.3').tags.includes('not_rated'));
  assert.equal(v.sections[0].items[0].label, 'L2.5 · 2/3 rated', 'the domain mean over rated subdomains only');
  assert.equal(v.ring.value, 2.5); assert.ok(v.sections[3].points.length >= 40 && /a week over 40 snapshots|projected/.test(v.sections[3].text));
  assert.equal((await e.req('POST', '/maturity-intel/ask', { body: { question: 'where does maturity stand?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await e.req('POST', '/maturity-intel/ask', { body: { question: 'where does maturity stand?' }, user: 'nora.syn', role: 'operator' })).status, 424);
});
