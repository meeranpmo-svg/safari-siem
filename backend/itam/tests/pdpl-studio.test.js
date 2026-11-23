// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL Studio (engine/pdpl-studio-intel.js) over the REAL PDPL register (engine/pdpl.js, Python rules) and a SYNTHETIC register for the
// history: 24 requirements with result, why and evidence; compliance by area; the biggest gains (DPO confirmations first); a requirement
// that regressed; one compliant now but failing often is "likely to fail next" (Beta(1,1)); confirmations lapsing within 60 days; the
// projection; any signed-in role reads; the advisor refused to a viewer and off until allowed; without the register the page says so.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const sec = (v, id) => v.sections.find((s) => s.id === id);

test('over the real register: 24 requirements by area, each with why and a next action', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/pdpl-studio', VIEW); assert.equal(r.status, 200, r.text); const v = r.json;
  const rows = sec(v, 'requirements').rows; assert.equal(rows.length, 24); assert.ok(rows.every((x) => /^P-\d{2}$/.test(x.id)));
  assert.ok(sec(v, 'areas').items.length >= 10 && sec(v, 'areas').items.some((i) => i.title === 'Governance'));
  assert.ok(rows.filter((x) => !x.tags.includes('compliant')).every((x) => /Next action: /.test(x.detail.text)));
  assert.ok(sec(v, 'gains').items.length > 0 && /^\+\d/.test(sec(v, 'gains').items[0].badges[0].text));
  assert.match(sec(v, 'basis').text, /not an SDAIA certificate/);
  assert.ok(v.kpis.some((k) => k.label === 'Statement'));
});

test('learning over a synthetic register: regressed, likely to fail next, lapsing, confirmations first, projection', async (t) => {
  let clock = Date.parse('2026-09-01T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const S = { a: 'compliant', b: 'non_compliant', pct: 40, due: null };
  const rq = (id, area, result, o) => Object.assign({ id, area, title: 'Synthetic requirement ' + id, ref: 'PDPL Art. 0', result, why: 'synthetic', evidence_expected: 'a synthetic report', automated: true, auto: { state: result === 'non_compliant' ? 'fail' : 'pass', detail: 'synthetic', findings: result === 'non_compliant' ? 2 : 0 }, confirmation: null, conflict: false }, o);
  e.app.addons.pdpl = { view: async () => ({ compliance_pct: S.pct, readiness: { ready: false, open: 3 }, statement: { status: 'none' }, requirements: [
    rq('P-91', 'Governance', S.a, S.a === 'compliant' ? { confirmation: { status: 'compliant', by: 'dpo.syn', due: S.due || new Date(clock + 200 * DAY).toISOString(), expired: false } } : {}),
    rq('P-92', 'Records', S.b), rq('P-93', 'Records', 'auto_pass'), rq('P-94', 'Breach', 'not_assessed', { automated: false, auto: null }),
    rq('P-95', 'Breach', 'compliant', { confirmation: { status: 'compliant', by: 'dpo.syn', due: new Date(clock + 20 * DAY).toISOString(), expired: false } })] }) };
  const X = e.app.addons.pdplStudio;
  for (let d = 0; d < 40; d++) { S.b = d % 3 === 0 ? 'non_compliant' : 'compliant'; S.pct = 40 + d; if (d === 36) S.a = 'non_compliant'; assert.ok(await X.snapshot()); clock += DAY; }
  S.b = 'compliant';
  const v = (await e.req('GET', '/pdpl-studio', OP)).json;
  assert.ok(sec(v, 'regressed').items.some((i) => i.id === 'rP-91'), 'compliant 30 days ago, not compliant now');
  assert.ok(sec(v, 'requirements').rows.find((r) => r.id === 'P-91').tags.includes('regressed'));
  const lk = sec(v, 'learning').items.find((i) => i.id === 'lP-92'); assert.ok(lk, 'compliant now but failed on 14 of 40 days'); assert.match(lk.sub, /failing on 14 of 40 day/);
  assert.equal(sec(v, 'gains').items[0].id, 'gP-93', 'the DPO confirmation of an automated pass first - one step');
  assert.ok(sec(v, 'gains').items.some((i) => i.id === 'gP-94' && /PDPL Self-Assessment/.test(i.sub)));
  const ex = sec(v, 'expiring').items; assert.equal(ex.length, 1); assert.equal(ex[0].id, 'eP-95'); assert.match(ex[0].sub, /lapses in \d+ day/);
  assert.match(v.kpis.find((k) => k.label === 'Projected 90 %').value, /^(\d{4}-\d{2}-\d{2}|reached|—)$/);
  assert.equal(v.kpis.find((k) => k.label === 'Statement').value, '3 open');
  assert.equal((await e.req('POST', '/pdpl-studio/ask', { body: { question: 'what should the DPO confirm first?' }, user: 'vera.syn', role: 'viewer' })).status, 403);
  assert.equal((await e.req('POST', '/pdpl-studio/ask', { body: { question: 'what should the DPO confirm first?' }, user: 'nora.syn', role: 'operator' })).status, 424);
  assert.deepEqual(X.TOOLS.map((x) => x.name).sort(), ['pdpl', 'privacy_cockpit', 'requirements']);
});

test('without the register the page says so', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  delete e.app.addons.pdpl;
  const v = (await e.req('GET', '/pdpl-studio', OP)).json; assert.equal(v.ring.value, null); assert.ok(v.notes.some((n) => /not installed/.test(n)));
});
