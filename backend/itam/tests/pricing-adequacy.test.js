// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Pricing Adequacy (engine/pricing-adequacy.js) with SYNTHETIC figures: a review recorded per line (Motor / Medical) with the
// combined-ratio maths (ULR + expense + commission), the adequacy verdict itemised (adequate / watch / inadequate), the required
// rate change to reach target; validation; roles and four-eyes approval (the recorder cannot approve, a service identity never);
// the trend over approved periods (withheld below 3) with a Holt-style early warning; the report (white background, logo, audited).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, ACT = { user: 'act.syn', role: 'operator' }, RISK = { user: 'risk.syn', role: 'admin' }, BOT = { user: 'ai:risk', role: 'admin' };

test('Pricing Adequacy: record, combined ratio, verdict, four eyes, trend, report', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || RISK));
  // empty
  let r = await call('GET', '/pricing-adequacy', undefined, ACT); assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.reviews, []);
  assert.equal(r.json.lines.length, 2); assert.equal(r.json.lines[0].key, 'motor'); assert.match(r.json.lines[0].trend.why, /needs 3/);
  assert.equal((await call('GET', '/pricing-adequacy', undefined, VIEW)).status, 403, 'figures are internal');
  // validation
  assert.equal((await call('POST', '/pricing-adequacy', { period: '2026Q1', line: 'motor', nep: 100, ulr: 70, expense_ratio: 20, target_loss_ratio: 72 }, ACT)).status, 400, 'period format');
  assert.equal((await call('POST', '/pricing-adequacy', { period: '2026-Q1', line: 'air', nep: 100, ulr: 70, expense_ratio: 20, target_loss_ratio: 72 }, ACT)).status, 400, 'unknown line');
  assert.equal((await call('POST', '/pricing-adequacy', { period: '2026-Q1', line: 'motor', sub_line: 'Jets', nep: 100, ulr: 70, expense_ratio: 20, target_loss_ratio: 72 }, ACT)).status, 400, 'unknown sub-line');
  assert.equal((await call('POST', '/pricing-adequacy', { period: '2026-Q1', line: 'motor', nep: 100, ulr: 70, expense_ratio: 20, target_loss_ratio: 72 }, BOT)).status, 403, 'a service identity does not record');
  // an inadequate Motor review: ULR 88 + expense 18 + commission 4 = combined 110
  r = await call('POST', '/pricing-adequacy', { period: '2026-Q1', line: 'motor', nep: 250000, ulr: 88, expense_ratio: 18, commission_ratio: 4, target_loss_ratio: 75, rate_change: 5 }, ACT);
  assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(r.json.combined_ratio, 110); assert.equal(r.json.status, 'inadequate');
  assert.equal(r.json.target_miss, 13); assert.ok(r.json.required_rate_change > 0, 'a rate increase is required'); assert.match(r.json.status_why, /110/);
  assert.equal(r.json.build_up.length, 4);
  // a duplicate is refused; an edit before approval is allowed
  assert.equal((await call('POST', '/pricing-adequacy', { period: '2026-Q1', line: 'motor', nep: 1, ulr: 1, expense_ratio: 1, target_loss_ratio: 50 }, ACT)).status, 409, 'one review per line/period');
  r = await call('POST', '/pricing-adequacy', { id, period: '2026-Q1', line: 'motor', nep: 250000, ulr: 70, expense_ratio: 18, commission_ratio: 4, target_loss_ratio: 75, rate_change: 5 }, ACT);
  assert.equal(r.json.combined_ratio, 92); assert.equal(r.json.status, 'adequate');
  // four eyes
  assert.equal((await call('POST', '/pricing-adequacy/' + id + '/approve', {}, ACT)).status, 403, 'the recorder cannot approve');
  assert.equal((await call('POST', '/pricing-adequacy/' + id + '/approve', {}, BOT)).status, 403);
  r = await call('POST', '/pricing-adequacy/' + id + '/approve', {}, RISK); assert.equal(r.status, 200, r.text); assert.equal(r.json.approved_by, 'risk.syn');
  assert.equal((await call('POST', '/pricing-adequacy', { id, period: '2026-Q1', line: 'motor', nep: 1, ulr: 1, expense_ratio: 1, target_loss_ratio: 50 }, ACT)).status, 409, 'approved is frozen');
  // trend over 3 approved whole-line periods, with a rising combined ratio -> warning
  for (const [p, ulr] of [['2026-Q2', 80], ['2026-Q3', 92]]) { const x = await call('POST', '/pricing-adequacy', { period: p, line: 'motor', nep: 250000, ulr, expense_ratio: 18, commission_ratio: 4, target_loss_ratio: 75 }, ACT); await call('POST', '/pricing-adequacy/' + x.json.id + '/approve', {}, RISK); }
  r = await call('GET', '/pricing-adequacy', undefined, ACT); const mt = r.json.lines.find((l) => l.key === 'motor').trend;
  assert.equal(mt.measured, true); assert.equal(mt.points.length, 3); assert.ok(mt.combined_slope_per_period > 0, 'combined ratio rising');
  assert.ok(mt.forecast_next > 100 && /above 100/.test(mt.warning || ''), 'early warning: ' + JSON.stringify(mt.warning));
  assert.equal(r.json.kpis.approved, 3); assert.ok(r.json.kpis.worst_combined >= 110 || r.json.kpis.worst_combined >= 100);
  // settings and report
  assert.equal((await call('POST', '/pricing-adequacy/settings', { watch: 100, inadequate: 100 }, RISK)).status, 400, 'inadequate must be above watch');
  assert.equal((await call('POST', '/pricing-adequacy/settings', { watch: 100, inadequate: 105 }, ACT)).status, 403, 'settings are admin');
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: (ZYB_ORG.short + ' (synthetic)'), letterhead: 'data:image/png;base64,AAAA' } });
  r = await call('GET', '/pricing-adequacy/report?line=motor&format=html', undefined, ACT); assert.equal(r.status, 200);
  assert.match(r.json.html, /background:#fff/); assert.match(r.json.html, /print-color-adjust:exact/); assert.match(r.json.html, new RegExp(ZYB_ORG.short + ' \\(synthetic\\)|data:image\\/png')); assert.match(r.json.html, /Combined/);
  r = await call('GET', '/pricing-adequacy/report?format=csv', undefined, ACT); assert.match(r.json.csv, /Combined/); assert.ok(!/\n=/.test(r.json.csv));
  // reopen then it is editable again
  r = await call('POST', '/pricing-adequacy/' + id + '/reopen', { reason: 'restated after audit (synthetic)' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.status_rec, 'draft');
  const au = e.app.store.auditTail(100).filter((a) => /^pricing\./.test(a.action));
  for (const a of ['record', 'approve', 'reopen', 'report']) assert.ok(au.some((x) => x.action === 'pricing.' + a), 'audited: ' + a);
});

test('Pricing Adequacy: read figures from an actuarial report PDF - proposals with pages, the person confirms, the draft names its source', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || RISK));
  const pdf = require('./pdf-fixture').pricingReport().toString('base64');
  // roles and validation
  assert.equal((await call('POST', '/pricing-adequacy/extract', { filename: 'pricing.pdf', data_b64: pdf }, VIEW)).status, 403);
  assert.equal((await call('POST', '/pricing-adequacy/extract', { filename: 'pricing.pdf', data_b64: pdf }, BOT)).status, 403, 'a person reads it');
  let r = await call('POST', '/pricing-adequacy/extract', { filename: 'pricing.pdf' }, ACT); assert.equal(r.status, 400); assert.match(r.text, /data_b64/);
  r = await call('POST', '/pricing-adequacy/extract', { filename: 'pricing.docx', data_b64: pdf }, ACT); assert.equal(r.status, 400);
  r = await call('POST', '/pricing-adequacy/extract', { filename: 'pricing.pdf', data_b64: Buffer.from('not a pdf').toString('base64') }, ACT); assert.equal(r.status, 400); assert.match(r.text, /real \.pdf/);
  r = await call('POST', '/pricing-adequacy/extract', { filename: 'locked.pdf', data_b64: require('./pdf-fixture').pricingReport({ encrypt: true }).toString('base64') }, ACT); assert.equal(r.status, 400); assert.match(r.text, /encrypted/);
  // the read: proposals, nothing recorded
  r = await call('POST', '/pricing-adequacy/extract', { filename: 'pricing-2026Q1.pdf', data_b64: pdf }, ACT); assert.equal(r.status, 200, r.text);
  const X = r.json; assert.match(X.id, /^PX-/); assert.equal(X.pages, 2); assert.ok(X.proposals > 20);
  const tpl = X.groups.find((g) => g.period === '2026-Q1' && g.line === 'motor' && g.sub_line === 'Compulsory (TPL)'); assert.equal(tpl.fields.ulr[0].value, 82.1);
  assert.equal((await call('GET', '/pricing-adequacy', undefined, ACT)).json.reviews.length, 0, 'reading records nothing');
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'pricing.extract' && a.by === ACT.user && a.detail.proposals === X.proposals));
  assert.ok(!JSON.stringify(e.app.store.collection('pricing_extracts').all()).includes(pdf.slice(0, 200)), 'the file is not kept');
  // the actuary confirms (here: the proposed figures as they are) - the draft names its source; a bad source id is refused
  const b = { period: '2026-Q1', line: 'motor', sub_line: 'Compulsory (TPL)', nep: tpl.fields.nep[0].value, ulr: tpl.fields.ulr[0].value, expense_ratio: tpl.fields.expense_ratio[0].value,
    commission_ratio: tpl.fields.commission_ratio[0].value, target_loss_ratio: tpl.fields.target_loss_ratio[0].value, rate_change: tpl.fields.rate_change[0].value };
  assert.equal((await call('POST', '/pricing-adequacy', Object.assign({}, b, { source_extract: 'PX-nope' }), ACT)).status, 400);
  r = await call('POST', '/pricing-adequacy', Object.assign({}, b, { source_extract: X.id, source_note: 'Table 1 p.1, rate change Table 2 p.1' }), ACT); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.source.extract, X.id); assert.equal(r.json.source.filename, 'pricing-2026Q1.pdf'); assert.equal(r.json.combined_ratio, 102.6); assert.equal(r.json.status_rec, 'draft');
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'pricing.record' && a.detail.source === X.id));
  assert.equal((await call('POST', '/pricing-adequacy/' + r.json.id + '/approve', {}, ACT)).status, 403, 'four eyes still apply');
});
