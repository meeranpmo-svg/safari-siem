// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RBC Own Funds & Solvency Assessment (engine/rbc-assessment.js) with a SYNTHETIC workbook in the IA template layout: every schedule read
// by its labels, the solvency ratio, MCR cover, headroom, the change split into the own-funds and RBC effects, capital quality, the FAIL
// checks, the projection (combined ratio above 100%, claims trend, loss quarters), the board answers; validation (not xlsx, not the
// template, no period); roles; four-eyes approval (the uploader never, a service identity never); re-upload replaces a draft only; the
// series withheld below 3 periods; the report (white, logo, audited) and CSV.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const F = require('./rbc-fixture');
const { normPeriod } = require('../engine/rbc-assessment');
const VIEW = { user: 'vera.syn', role: 'viewer' }, FIN = { user: 'fin.syn', role: 'operator' }, RISK = { user: 'risk.syn', role: 'admin' }, BOT = { user: 'ai:risk', role: 'admin' };
const LOGO = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

test('normPeriod reads the template headers', () => {
  assert.equal(normPeriod('Q1 2026'), '2026-Q1'); assert.equal(normPeriod('YE 2025'), '2025'); assert.equal(normPeriod('2026 Q2'), '2026-Q2');
  assert.equal(normPeriod('H1 2026'), '2026-H1'); assert.equal(normPeriod('FY2025'), '2025'); assert.equal(normPeriod('current'), null);
});

test('RBC assessment: import, schedules, insights, four eyes, series, report', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || RISK));
  let r = await call('GET', '/brisk/rbc', undefined, FIN); assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.periods, []); assert.match(r.json.note, /No RBC assessment uploaded/);
  assert.equal((await call('GET', '/brisk/rbc', undefined, VIEW)).status, 403, 'capital figures are internal');
  // validation
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.csv', xlsx_b64: F.b64() }, FIN)).status, 400, 'xlsx only');
  r = await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64({ notTemplate: true }) }, FIN); assert.equal(r.status, 400); assert.match(r.json.error, /Own Funds/);
  r = await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64({ period: 'Current' }) }, FIN); assert.equal(r.status, 400); assert.match(r.json.error, /period/);
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64(), period: '26Q1' }, FIN)).status, 400, 'period format');
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: '***' }, FIN)).status, 400, 'not base64');
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64() }, VIEW)).status, 403, 'viewer cannot upload');
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64() }, BOT)).status, 403, 'a service identity does not upload');
  // the 2026 Q1 workbook: own funds 1,300,000 / RBC 500,000 = 260%; prior 1,250,000 / 480,000
  r = await call('POST', '/brisk/rbc/import', { filename: 'RBC Q1 2026.xlsx', xlsx_b64: F.b64() }, FIN); assert.equal(r.status, 200, r.text);
  const d = r.json, id = d.id; assert.equal(d.period, '2026-Q1'); assert.equal(d.status, 'draft'); assert.equal(d.solvency_ratio, 260); assert.equal(d.company, 'Synthetic Insurance Co');
  assert.equal(d.figures.mcr.current, 170000); assert.equal(d.figures.total_assets.current, 5000000); assert.equal(d.figures.tiers[0].total.current, 1520000);
  assert.equal(d.figures.adjustments.find((a) => a.item === 'Goodwill').current, 300000); assert.equal(d.figures.components.length, 2);
  assert.equal(d.checks.length, 5); assert.ok(d.checks.every((c) => c.result === 'PASS')); assert.equal(d.questions.length, 2); assert.deepEqual(d.projection.columns, ['Q1', 'Q2', 'H1', 'Q3', 'Q4', '2026']);
  const ins = Object.fromEntries(d.insights.map((i) => [i.key, i]));
  assert.equal(ins.ratio.level, 'ok'); assert.equal(ins.mcr.value, 764.7); assert.equal(ins.headroom.headroom_100, 800000); assert.equal(ins.headroom.headroom_target, 550000);
  // the change is split exactly: own-funds effect + RBC effect = the movement
  assert.ok(Math.abs(ins.change.own_funds_effect_pts + ins.change.rbc_effect_pts - ins.change.delta_pts) <= 0.2, JSON.stringify(ins.change));
  assert.equal(ins.quality.level, 'watch', 'goodwill + intangibles 23% of Tier 1'); assert.equal(ins.checks.level, 'ok');
  assert.equal(ins.combined.level, 'watch'); assert.deepEqual(ins.combined.quarters_over, ['Q4']); assert.ok(ins.claims.slope_pts > 0); assert.match(ins.loss.text, /Q4/);
  assert.ok(audits.some((a) => a.action === 'rbc.import' && a.by === 'fin.syn' && a.target === id), 'import audited');
  assert.ok(!JSON.stringify(e.app.store.collection('rbc_assessments').get(id)).includes(F.b64().slice(100, 160)), 'the file itself is not kept');
  // re-upload of the draft replaces it (same id); with a FAIL check and a low ratio
  r = await call('POST', '/brisk/rbc/import', { filename: 'RBC Q1 2026 v2.xlsx', xlsx_b64: F.b64({ ownFunds: 450000, fail: true }) }, FIN); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.id, id); assert.equal(r.json.solvency_ratio, 90); const i2 = Object.fromEntries(r.json.insights.map((i) => [i.key, i]));
  assert.equal(i2.ratio.level, 'bad'); assert.match(i2.ratio.text, /BELOW the 100%/); assert.equal(i2.checks.level, 'bad'); assert.equal(i2.checks.fails, 2); assert.equal(i2.headroom.level, 'bad');
  assert.ok(audits.some((a) => a.action === 'rbc.replace'));
  r = await call('POST', '/brisk/rbc/import', { filename: 'RBC Q1 2026.xlsx', xlsx_b64: F.b64() }, FIN); assert.equal(r.json.solvency_ratio, 260);
  // four eyes
  assert.equal((await call('POST', '/brisk/rbc/' + id + '/approve', {}, FIN)).status, 403, 'not an approver');
  assert.equal((await call('POST', '/brisk/rbc/' + id + '/approve', {}, BOT)).status, 403, 'a service identity never approves');
  assert.equal((await call('POST', '/brisk/rbc/' + id + '/approve', {}, { user: 'fin.syn', role: 'admin' })).status, 403, 'the uploader never approves');
  r = await call('POST', '/brisk/rbc/' + id + '/approve', {}, RISK); assert.equal(r.status, 200, r.text); assert.equal(r.json.approved_by, 'risk.syn');
  assert.ok(audits.some((a) => a.action === 'rbc.approve' && a.by === 'risk.syn'));
  assert.equal((await call('POST', '/brisk/rbc/import', { filename: 'x.xlsx', xlsx_b64: F.b64() }, FIN)).status, 409, 'approved period is frozen');
  assert.equal((await call('POST', '/brisk/rbc/' + id + '/reopen', { reason: 'no' }, RISK)).status, 400, 'reason too short');
  r = await call('POST', '/brisk/rbc/' + id + '/reopen', { reason: 'restated after audit' }, RISK); assert.equal(r.json.status, 'draft'); assert.equal(r.json.reopen_reason, 'restated after audit');
  await call('POST', '/brisk/rbc/' + id + '/approve', {}, RISK);
  // the series across approved periods: withheld below 3, then measured
  r = await call('GET', '/brisk/rbc', undefined, FIN); assert.equal(r.json.series.measured, false); assert.match(r.json.series.why, /needs 3/);
  for (const [p, of] of [['YE 2025', 1250000], ['Q2 2026', 1200000]]) { const x = await call('POST', '/brisk/rbc/import', { filename: p + '.xlsx', xlsx_b64: F.b64({ period: p, ownFunds: of }) }, FIN); assert.equal(x.status, 200, x.text); await call('POST', '/brisk/rbc/' + x.json.id + '/approve', {}, RISK); }
  r = await call('GET', '/brisk/rbc', undefined, FIN); assert.equal(r.json.periods.length, 3); assert.equal(r.json.series.measured, true); assert.deepEqual(r.json.series.points.map((p) => p.period), ['2025', '2026-Q1', '2026-Q2']);
  assert.equal(r.json.latest.period, '2026-Q2');
  // settings: admin only, validated, change the verdict
  assert.equal((await call('POST', '/brisk/rbc/settings', { target_ratio: 3 }, FIN)).status, 403);
  assert.equal((await call('POST', '/brisk/rbc/settings', { target_ratio: 9 }, RISK)).status, 400);
  r = await call('POST', '/brisk/rbc/settings', { target_ratio: 3, quality_pct: 30 }, RISK); assert.equal(r.status, 200, r.text);
  r = await call('GET', '/brisk/rbc/' + id, undefined, FIN); assert.equal(r.json.insights.find((i) => i.key === 'ratio').level, 'watch'); assert.equal(r.json.insights.find((i) => i.key === 'quality').level, 'ok');
  // report: white, the brand logo and name, audited; CSV with formula-injection guard
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: 'Synthetic Finance Co', letterhead: LOGO } });
  r = await call('GET', '/brisk/rbc/' + id + '/report?format=html', undefined, FIN); assert.equal(r.status, 200, r.text);
  assert.match(r.json.html, /background:#fff/); assert.match(r.json.html, /<img class="logo" src="data:image\/png/); assert.match(r.json.html, /Synthetic Finance Co/); assert.match(r.json.html, /Insights/); assert.match(r.json.html, /Financial projection/);
  assert.ok(audits.some((a) => a.action === 'rbc.report' && a.detail.format === 'html'));
  r = await call('GET', '/brisk/rbc/' + id + '/report?format=csv', undefined, FIN); assert.match(r.json.csv, /Solvency Ratio %,260/); assert.match(r.json.filename, /2026-Q1\.csv$/);
  assert.equal((await call('GET', '/brisk/rbc/' + id + '/report?format=pdf', undefined, FIN)).status, 400);
  assert.equal((await call('GET', '/brisk/rbc/' + id + '/report', undefined, VIEW)).status, 403);
  assert.equal((await call('GET', '/brisk/rbc/nope', undefined, FIN)).status, 404);
});
