// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Analytics, the period and Excel half (engine/audit-analytics.js, audit-analytics-lib.js compare, engine/xlsx-read.js) over a
// SYNTHETIC payroll: the xlsx reader (shared strings, inline strings, numbers, date styles, blank / repeated headers, a zip bomb and a
// renamed file refused); payroll imported as a workbook into a series by period (the same period twice refused); period-to-period
// compare finds the new, the gone and the changed - a changed IBAN with a pay rise ranks first; an on-import script approved by a
// second person runs by itself when the next month arrives, an unapproved one does not, monthly runs on the 1st (Riyadh); the exception
// list goes to Excel (the page's own zyb-xlsx.js) and comes back with decisions - rows for another run, a re-sorted row, an unknown
// decision or a missing note are refused line by line; viewer and AI identity refused; every step audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const L = require('../engine/audit-analytics-lib');
const { readXlsx } = require('../engine/xlsx-read');

const NOW = Date.parse('2027-02-01T06:00:00Z');   // 09:00 on the 1st in Riyadh
const OP = { user: 'auditor.syn', role: 'operator' }, REV = { user: 'reviewer.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:audit', role: 'operator' };

// the browser's own Excel writer, run in a sandbox: what the page exports is exactly what comes back
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../../ui/vendor/zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const xlsx = async (sheets, meta) => Buffer.from(await XL.build(sheets, meta || { title: 'synthetic' }).arrayBuffer());
const b64 = (b) => b.toString('base64');

// synthetic payroll for two months: E005 joins, E004 leaves, E002 changes IBAN and gets +40 %, E003 a +3 % rise, E001 unchanged
const COLS = [{ h: 'emp_id' }, { h: 'name' }, { h: 'iban' }, { h: 'basic', t: 'n' }, { h: 'dept' }, { h: 'paid_on', t: 'd' }];
const JAN = [['E001', 'Synthetic One', 'SA00 0000 0000 0001', 9000, 'Claims', '2027-01-27'], ['E002', 'Synthetic Two', 'SA00 0000 0000 0002', 10000, 'Finance', '2027-01-27'], ['E003', 'Synthetic Three', 'SA00 0000 0000 0003', 8000, 'IT', '2027-01-27'], ['E004', 'Synthetic Four', 'SA00 0000 0000 0004', 7000, 'IT', '2027-01-27']];
const FEB = [['E001', 'Synthetic One', 'SA00 0000 0000 0001', 9000, 'Claims', '2027-02-24'], ['E002', 'Synthetic Two', 'SA99 9999 9999 9999', 14000, 'Finance', '2027-02-24'], ['E003', 'Synthetic Three', 'SA00 0000 0000 0003', 8240, 'IT', '2027-02-24'], ['E005', 'Synthetic Five', 'SA00 0000 0000 0005', 6000, 'Claims', '2027-02-24']];

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(800).filter((x) => x.action === 'audit-analytics.' + a) };
}

test('xlsx reader: values, dates, headers; damaged, renamed and oversized workbooks refused', async () => {
  const X = readXlsx(await xlsx([{ name: 'Payroll', columns: COLS.concat([{ h: '' }, { h: 'name' }]), rows: [JAN[0].concat(['x', 'dup']), ['=HYPERLINK("http://x")', 'A & B <c>', '', 0.1 + 0.2, '', '2027-01-27T10:30']] }]));
  assert.deepEqual(X.fields, ['emp_id', 'name', 'iban', 'basic', 'dept', 'paid_on', 'G', 'name (2)']);
  assert.equal(X.rows[0].basic, '9000'); assert.equal(X.rows[0].paid_on, '2027-01-27'); assert.equal(X.rows[1].basic, '0.3', 'float noise trimmed');
  assert.equal(X.rows[1].emp_id, '=HYPERLINK("http://x")', 'a formula-looking text is text, never evaluated'); assert.equal(X.rows[1].name, 'A & B <c>'); assert.equal(X.rows[1].paid_on, '2027-01-27T10:30');
  assert.equal(X.sheet, 'sheet1.xml', 'the first sheet, not the Report sheet');
  assert.throws(() => readXlsx(Buffer.from('not a zip at all, just text padding......')), /not a readable workbook/);
  // a part that claims to expand past the cap is refused before it is inflated
  const bomb = await xlsx([{ name: 'S', columns: [{ h: 'a' }], rows: [['1']] }]); for (let c = bomb.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])); c >= 0; c = bomb.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]), c + 4)) bomb.writeUInt32LE(200 * 1024 * 1024, c + 24);
  assert.throws(() => readXlsx(bomb), /too large/);
});

test('compare: new, gone, changed - a changed IBAN with a pay rise first', () => {
  const rows = (D) => D.map((r) => ({ emp_id: r[0], name: r[1], iban: r[2], basic: String(r[3]), dept: r[4] }));
  const R = L.compare(rows(FEB), { key: 'emp_id', amount: 'basic', pct: 10, watch: ['name', 'iban', 'basic', 'dept'] }, rows(JAN));
  assert.deepEqual(R.counts, { new: 1, gone: 1, changed: 2, unchanged: 1, repeated: 0 });
  const top = R.exceptions[0]; assert.equal(top.values.emp_id, 'E002'); assert.match(top.why, /iban changed/); assert.match(top.why, /basic \+40%/); assert.match(top.why, /pay rose in the same period the account changed/);
  assert.equal(top.values['iban (previous)'], 'SA00 0000 0000 0002');
  const e3 = R.exceptions.find((x) => x.values.emp_id === 'E003'); assert.match(e3.why, /basic \+3%/); assert.ok(e3.score < top.score);
  assert.ok(R.exceptions.some((x) => x.kind === 'new' && x.values.emp_id === 'E005') && R.exceptions.some((x) => x.kind === 'gone' && x.values.emp_id === 'E004'));
  assert.deepEqual(R.totals, { before: 34000, after: 37240, change_pct: 9.5 });
  const dup = L.compare(rows(FEB).concat([rows(FEB)[0]]), { key: 'emp_id' }, rows(JAN)); assert.ok(dup.exceptions.some((x) => x.kind === 'repeated' && /appears 2 times/.test(x.why)));
  assert.throws(() => L.compare(rows(FEB), { key: 'staff' }, rows(JAN)), /staff is not a column/);
});

test('series by period, compare through the routes, on-import script after four-eyes, monthly schedule', async (t) => {
  const s = await setup(t);
  const imp = async (D, period, who = OP) => s.post('/audit-analytics/datasets', { name: 'Payroll ' + period + ' (synthetic)', purpose: 'monthly payroll review (synthetic)', xlsx_b64: b64(await xlsx([{ name: 'Payroll', columns: COLS, rows: D }])), filename: 'payroll-' + period + '.xlsx', series: 'Payroll', period }, who);
  let r = await imp(JAN, '2027-01'); assert.equal(r.status, 200, r.text); assert.equal(r.json.format, 'xlsx'); assert.equal(r.json.rows, 4); assert.equal(r.json.series, 'payroll'); assert.match(r.json.hash, /^sha256:[0-9a-f]{64}$/);
  const jan = r.json;
  assert.equal((await s.post('/audit-analytics/datasets', { name: 'x', purpose: 'y', xlsx_b64: b64(Buffer.from('%PDF-1.4 pretend')), filename: 'p.xlsx' })).status, 400, 'a renamed file is refused');
  assert.match((await s.post('/audit-analytics/datasets', { name: 'x', purpose: 'y', csv: 'a\n1\n', series: 'Payroll' })).text, /period \(YYYY-MM\) is required/);
  assert.match((await s.post('/audit-analytics/datasets', { name: 'x', purpose: 'y', csv: 'a\n1\n', series: 'Payroll', period: '2027-13' })).text, /period must be YYYY-MM/);
  assert.match((await s.post('/audit-analytics/datasets', { name: 'x', purpose: 'y' })).text, /csv or xlsx_b64/);
  assert.equal((await s.post('/audit-analytics/datasets', { name: 'x', purpose: 'y', csv: 'emp_id\nE9\n', series: 'payroll', period: '2027-01' })).status, 409, 'the same period twice');
  // a script on the series: refused to run on schedule until a different person approves it
  const sc = (await s.post('/audit-analytics/scripts', { name: 'Monthly payroll comparison', dataset: 'latest:payroll', schedule: 'on_import', steps: [{ test: 'compare', other: 'previous:payroll', params: { key: 'emp_id', amount: 'basic', pct: 10, watch: ['name', 'iban', 'basic', 'dept'] } }, { test: 'duplicates', params: { keys: ['iban'] } }] })).json;
  assert.ok(sc.id, JSON.stringify(sc));
  assert.match((await s.post('/audit-analytics/scripts', { name: 'bad', dataset: jan.id, schedule: 'on_import', steps: [{ test: 'duplicates', params: { keys: ['iban'] } }] })).text, /on_import needs the script to read a series/);
  let ov = (await s.get('/audit-analytics')).json; assert.equal(ov.series[0].series, 'payroll'); assert.equal(ov.series[0].previous, null); assert.ok(ov.schedules.includes('monthly'));
  r = await imp(FEB, '2027-02'); assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.triggered, [], 'not approved: nothing runs');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, OP)).status, 403, 'the author does not approve');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, BOT)).status, 403, 'an AI identity does not approve');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, REV)).status, 200);
  // the compare by hand through the series refs
  r = await s.post('/audit-analytics/run', { dataset: 'latest:payroll', other: 'previous:payroll', test: 'compare', params: { key: 'emp_id', amount: 'basic', watch: ['iban', 'basic'] } });
  assert.equal(r.status, 200, r.text); assert.match(r.json.summary, /^1 new, 1 gone, 2 changed, 1 unchanged/); assert.equal(r.json.result.exceptions[0].values.emp_id, 'E002');
  assert.match((await s.post('/audit-analytics/run', { dataset: 'latest:payroll', other: 'latest:payroll', test: 'compare', params: { key: 'emp_id' } })).text, /compare with a different dataset/);
  assert.match((await s.post('/audit-analytics/run', { dataset: 'latest:claims', other: 'previous:claims', test: 'compare', params: { key: 'emp_id' } })).text, /series claims: no import yet/);
  assert.equal((await s.post('/audit-analytics/run', { dataset: 'latest:payroll', other: 'previous:payroll', test: 'compare', params: { key: 'emp_id' } }, VIEW)).status, 403, 'viewer refused');
  // March arrives: the approved on-import script runs by itself as the scheduler identity
  const MAR = FEB.map((x) => x.slice()); MAR[3][3] = 6100;
  r = await imp(MAR, '2027-03', REV); assert.equal(r.status, 200, r.text); assert.equal(r.json.triggered.length, 1); assert.equal(r.json.triggered[0].runs.length, 2); assert.equal(r.json.triggered[0].errors, 0);
  const auto = (await s.get('/audit-analytics/runs/' + r.json.triggered[0].runs[0])).json; assert.equal(auto.by, 'system:audit-analytics'); assert.match(auto.summary, /0 new, 0 gone, 1 changed, 3 unchanged/);
  assert.ok(s.audit('script.run').some((a) => a.by === 'system:audit-analytics' && a.target === sc.id));
  // monthly: runs on the 1st of the month (Riyadh), once
  const m = (await s.post('/audit-analytics/scripts', { name: 'Monthly duplicates', dataset: 'latest:payroll', schedule: 'monthly', steps: [{ test: 'duplicates', params: { keys: ['iban'] } }] })).json;
  await s.post('/audit-analytics/scripts/' + m.id + '/approve', {}, REV);
  const X = s.e.app.addons.auditAnalytics; X.daily(); X.daily();
  ov = (await s.get('/audit-analytics')).json; assert.equal(ov.scripts.find((x) => x.id === m.id).last_runs.length, 1, 'once on the 1st');
  assert.ok(s.audit('dataset.import').some((a) => a.detail.series === 'payroll' && a.detail.period === '2027-02' && a.detail.format === 'xlsx'));
});

test('Excel round trip of exceptions: export, decisions back, every row checked', async (t) => {
  const s = await setup(t);
  const imp = async (D, period) => (await s.post('/audit-analytics/datasets', { name: 'Payroll ' + period, purpose: 'review (synthetic)', xlsx_b64: b64(await xlsx([{ name: 'P', columns: COLS, rows: D }])), filename: 'p.xlsx', series: 'payroll', period })).json;
  await imp(JAN, '2027-01'); await imp(FEB, '2027-02');
  const run = (await s.post('/audit-analytics/run', { dataset: 'latest:payroll', other: 'previous:payroll', test: 'compare', params: { key: 'emp_id', amount: 'basic', watch: ['name', 'iban', 'basic', 'dept'] } })).json;
  const other = (await s.post('/audit-analytics/run', { dataset: 'latest:payroll', test: 'duplicates', params: { keys: ['dept'] } })).json;
  const x = (await s.get('/audit-analytics/runs/' + run.id + '/export')).json;
  assert.deepEqual(x.xlsx.columns.slice(0, 4).map((c) => c.h), ['run', 'exception', 'row', 'why']); assert.equal(x.xlsx.rows.length, 4); assert.match(x.xlsx.how, /decision/);
  assert.match(x.csv.split('\n')[1], /^"run","exception","row","why"/);
  // the auditee fills the workbook: two good rows, a row from another run, a re-sorted row, an unknown decision, a missing note, a blank
  const di = x.xlsx.columns.findIndex((c) => c.h === 'decision'), ni = x.xlsx.columns.findIndex((c) => c.h === 'note');
  const rows = x.xlsx.rows.map((r) => r.slice()); const fill = (r, d, n) => { r[di] = d; r[ni] = n; return r; };
  fill(rows[0], 'Finding', 'IBAN change not supported by an HR request (synthetic)'); fill(rows[1], 'Explained', 'joiner letter on file (synthetic)');
  const wrongRun = fill(rows[2].slice(), 'explained', 'x'); wrongRun[0] = other.id;
  const moved = fill(rows[3].slice(), 'explained', 'x'); moved[2] = 999;
  const book = await xlsx([{ name: 'Exceptions', columns: x.xlsx.columns, rows: [rows[0], rows[1], wrongRun, moved, fill(rows[2].slice(), 'maybe', 'x'), fill(rows[3].slice(), 'finding', ''), rows[2].map((v, i) => (i === di || i === ni ? '' : v))] }]);
  assert.equal((await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { xlsx_b64: b64(book), filename: 'back.xlsx' }, VIEW)).status, 403);
  assert.equal((await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { xlsx_b64: b64(book), filename: 'back.xlsx' }, BOT)).status, 403);
  let r = await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { xlsx_b64: b64(book), filename: 'back.xlsx' });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.applied, 2); assert.equal(r.json.blank, 1); assert.equal(r.json.errors.length, 4, JSON.stringify(r.json.errors));
  const err = r.json.errors.map((e) => e.error).join(' | ');
  assert.match(err, new RegExp('run is ' + other.id)); assert.match(err, /the rows were changed/); assert.match(err, /decision "maybe"/); assert.match(err, /a note is required/);
  const got = (await s.get('/audit-analytics/runs/' + run.id)).json; assert.equal(got.dispositions[0].decision, 'finding'); assert.equal(got.dispositions[1].decision, 'explained'); assert.match(got.dispositions[0].via, /^file xlsx sha256:/);
  r = await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { xlsx_b64: b64(book), filename: 'back.xlsx' }); assert.equal(r.json.unchanged, 2, 'the same file again changes nothing'); assert.equal(r.json.applied, 0);
  // the CSV round trip works the same (the comment line the export starts with is skipped)
  const csv = x.csv.replace('"' + run.id + '","3",', '"' + run.id + '","3",').split('\n').map((l, i) => (i === 4 ? l.replace(/,"","",""$/, ',"false positive","same person, two IBANs on file (synthetic)",""') : l)).join('\n');
  r = await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { csv }); assert.equal(r.status, 200, r.text + JSON.stringify(csv.slice(0, 300))); assert.equal(r.json.applied, 1);
  assert.match((await s.post('/audit-analytics/runs/' + run.id + '/dispositions', { csv: 'a,b\n1,2\n' })).text, /no .{1,2}run.{1,2} column/);
  assert.ok(s.audit('dispositions.import').length >= 3); assert.ok(s.audit('exception.disposition').some((a) => a.detail.via === 'xlsx'));
});
