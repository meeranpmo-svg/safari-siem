// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IT Budget in Excel and from one year to the next (engine/budget.js), SYNTHETIC figures only:
//  - the round trip: the budget as the page exports it (zyb-xlsx.js, sheet "Budget" with Line IDs) is edited and imported back -
//    preview first (every change, every row error with its row number), then all of it or nothing; a new row adds a requirement
//    once (the same workbook twice does not add it twice); roles (viewer / operator refused, an AI identity cannot apply);
//    validation (not base64, not an .xlsx, no Title column, wrong FY, unknown Line ID, reject without a note, approve unpriced);
//    one audit record per change with the file it came from, and a summary record
//  - last year's budget as an .xlsx workbook (not only CSV) feeds the carry-over
//  - the year-end rollover: nothing before the year ends; on 1 January the year is archived, its approved and deferred lines with
//    the actual spend from Budget execution become last year's budget, planning moves on, it runs once; an administrator's own
//    import for that year is kept; a server that was off catches up year by year; Notification & Escalation shows it until an
//    administrator (a person) marks the carry-over reviewed
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { registerBudget } = require('../engine/budget');

const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../../ui/vendor/zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const b64 = async (sheets) => Buffer.from(await XL.build(sheets, { title: 'synthetic' }).arrayBuffer()).toString('base64');
// the columns the IT Budget page exports (dashboards/server/budget.html xlsxOut)
const COLS = ['Line ID', 'FY', 'Envelope', 'Area', 'Type', 'Title', 'Amount', 'Priority', 'Status', 'Due', 'Note', 'Source', 'Basis', 'Reason', 'Fit', 'Decided by'];
const EN = { it_ops: 'IT Operations', cyber: 'Cyber Security' };
const exportRows = (v) => v.lines.map((l) => [l.id, v.fy, EN[l.envelope], l.area, l.kind.toUpperCase(), l.title, l.priced ? l.amount : '', l.priority, l.status, l.due || '', l.note || '', l.source, l.basis || '', l.reason || '', l.fit || '', l.decided_by || '']);
const book = (rows) => b64([{ name: 'Budget', columns: COLS.map((h) => ({ h, t: h === 'Amount' || h === 'FY' ? 'n' : h === 'Due' ? 'd' : undefined })), rows }]);
const ADM = { user: 'cio.syn', role: 'admin' }, ADM2 = { user: 'cfo.syn', role: 'admin' }, OP = { user: 'fin.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:budget-analyst', role: 'admin' };

async function setup(t, T0) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const clock = { t: T0 };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  const B = registerBudget(e.app.srv, e.app, { noTimer: true, now: () => clock.t });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const audits = (action) => e.app.store.auditTail(500).filter((a) => a.action === action);
  return { e, B, call, clock, audits };
}

test('Excel round trip: preview, all or nothing, new rows once, roles, validation, audit', async (t) => {
  const { B, call, audits } = await setup(t, Date.parse('2026-11-10T08:00:00Z'));
  B.putSettings({ fy: 2027 }, ADM);
  B.saveLine({ title: 'Backup appliance SYN', envelope: 'it_ops', area: 'infrastructure', kind: 'capex', amount: 300000, priority: 'should' }, ADM);
  B.saveLine({ title: 'SOC tooling SYN', envelope: 'cyber', kind: 'opex', priority: 'should' }, ADM);   // no price yet
  B.saveLine({ title: 'Training SYN', envelope: 'it_ops', kind: 'opex', amount: 40000 }, ADM);
  let v = (await call('GET', '/budget', undefined, VW)).json;
  const id = (title) => v.lines.find((l) => l.title === title).id;
  const [bak, soc, trn] = ['Backup appliance SYN', 'SOC tooling SYN', 'Training SYN'].map(id);

  // the export as it is reads back with nothing to change
  let r = await call('POST', '/budget/import', { xlsx_b64: await book(exportRows(v)), filename: 'it-budget-FY2027.xlsx' }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.changes.length, 0); assert.equal(r.json.unchanged, 3); assert.equal(r.json.errors.length, 0);

  // edited in Excel: some rows wrong
  const edit = (fix) => {
    const rows = exportRows(v).map((x) => x.slice());
    const row = (lid) => rows.find((x) => x[0] === lid);
    row(bak)[6] = 320000; row(bak)[8] = 'approved';
    row(soc)[8] = 'approved'; if (fix) row(soc)[6] = 55000;           // approving an unpriced line needs the amount
    row(trn)[8] = 'rejected'; if (fix) row(trn)[10] = 'done in-house this year (synthetic)';   // rejecting needs a note
    rows.push(['', 2027, 'IT Operations', 'Infrastructure', 'CAPEX', 'Network refresh SYN', 900000, 'must', '', '2027-06-30', '', '', '', 'core switches end of support', '', '']);
    if (!fix) { rows.push(['man:nope000000', 2027, 'IT Operations', '', 'OPEX', 'Ghost SYN', 1, 'must', 'proposed', '', '', '', '', '', '', '']); rows.push(['', 2026, 'IT Operations', '', 'OPEX', 'Last year SYN', 5, 'must', '', '', '', '', '', '', '', '']); rows.push(['', 2027, 'Facilities', '', 'OPEX', 'No envelope SYN', 5, 'must', '', '', '', '', '', '', '', '']); }
    return rows;
  };
  const bad = await book(edit(false));
  r = await call('POST', '/budget/import', { xlsx_b64: bad, filename: 'edited.xlsx' }, ADM);
  assert.equal(r.status, 200);
  const msgs = r.json.errors.map((x) => x.row + ': ' + x.msg).join(' | ');
  assert.match(msgs, /approve it/, msgs); assert.match(msgs, /Note with the reason/); assert.match(msgs, /man:nope000000 is not in the FY2027 budget/); assert.match(msgs, /FY 2026 is not the budget being planned/); assert.match(msgs, /Envelope must be IT Operations or Cyber Security/);
  assert.ok(r.json.errors.every((x) => x.row >= 2), 'errors name the Excel row');
  // all or nothing
  r = await call('POST', '/budget/import', { xlsx_b64: bad, filename: 'edited.xlsx', apply: true }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /nothing was changed - \d+ row\(s\) need fixing/);
  assert.equal(B.build().lines.find((l) => l.id === bak).amount, 300000, 'nothing applied');

  const good = await book(edit(true));
  // roles: viewer and operator refused; an AI identity may look but not apply
  assert.equal((await call('POST', '/budget/import', { xlsx_b64: good }, VW)).status, 403);
  assert.equal((await call('POST', '/budget/import', { xlsx_b64: good }, OP)).status, 403);
  assert.equal((await call('POST', '/budget/import', { xlsx_b64: good, apply: true }, BOT)).status, 403);
  r = await call('POST', '/budget/import', { xlsx_b64: good, filename: 'edited.xlsx' }, ADM);
  assert.equal(r.json.errors.length, 0, JSON.stringify(r.json.errors));
  assert.equal(r.json.changes.length, 4);
  assert.deepEqual(r.json.changes.find((c) => c.id === bak).fields, { amount: [300000, 320000], status: ['proposed', 'approved'] });
  assert.ok(r.json.changes.some((c) => c.action === 'add' && c.title === 'Network refresh SYN' && c.fields.kind === 'capex' && c.fields.amount === 900000));
  r = await call('POST', '/budget/import', { xlsx_b64: good, filename: 'edited.xlsx', apply: true }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.applied, true);
  const L = (lid) => r.json.budget.lines.find((l) => l.id === lid);
  assert.equal(L(bak).amount, 320000); assert.equal(L(bak).status, 'approved'); assert.equal(L(bak).decided_by, 'cio.syn');
  assert.equal(L(soc).amount, 55000); assert.equal(L(soc).status, 'approved');
  assert.equal(L(trn).status, 'rejected'); assert.match(L(trn).note, /in-house/);
  const added = r.json.budget.lines.find((l) => l.title === 'Network refresh SYN');
  assert.ok(added && added.source === 'manual' && added.amount === 900000 && added.priority === 'must' && added.due === '2027-06-30' && added.status === 'proposed');
  // the audit: one record per change, with the file, and a summary - who, role, what
  const ch = audits('budget.workbook_change');
  assert.equal(ch.length, 3); assert.ok(ch.every((a) => a.by === 'cio.syn' && a.role === 'admin' && a.detail.file === 'edited.xlsx' && a.detail.sha256));
  assert.ok(audits('budget.line_add').some((a) => a.detail.via === 'workbook' && a.detail.title === 'Network refresh SYN'));
  const sum = audits('budget.import_workbook'); assert.equal(sum.length, 1); assert.deepEqual([sum[0].detail.updated, sum[0].detail.added], [3, 1]);

  // the same workbook again: the new row is not added twice, the rest is already done
  r = await call('POST', '/budget/import', { xlsx_b64: good, filename: 'edited.xlsx' }, ADM2);
  assert.equal(r.json.changes.length, 0); assert.match(r.json.errors.map((x) => x.msg).join(' '), /"Network refresh SYN" is already in the budget \(Line ID man:/);
  assert.equal(B.build().lines.filter((l) => l.title === 'Network refresh SYN').length, 1);
  // nothing to apply is said, not silently accepted
  v = B.build();
  r = await call('POST', '/budget/import', { xlsx_b64: await book(exportRows(v)), apply: true }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /nothing to apply/);

  // validation at the boundary
  assert.match((await call('POST', '/budget/import', {}, ADM)).json.error, /xlsx_b64 is required/);
  assert.match((await call('POST', '/budget/import', { xlsx_b64: 'not base64 !!' }, ADM)).json.error, /not base64/);
  const csv = Buffer.from('title,amount\nSYN,1\n').toString('base64');
  r = await call('POST', '/budget/import', { xlsx_b64: csv, filename: 'budget.xlsx' }, ADM); assert.equal(r.status, 400, 'a CSV renamed .xlsx is refused');
  r = await call('POST', '/budget/import', { xlsx_b64: await b64([{ name: 'Other', columns: [{ h: 'Item' }, { h: 'Cost' }], rows: [['SYN', 1]] }]) }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /no "Title" column/);
  r = await call('POST', '/budget/import', { xlsx_b64: await book([[bak, 2027, 'IT Operations', '', 'CAPEX', 'Backup appliance SYN', 'lots', '', '', '', '', '', '', '', '', '']]) }, ADM);
  assert.match(r.json.errors[0].msg, /Amount "lots" is not a number/);
});

test('last year\'s budget as an Excel workbook feeds the carry-over', async (t) => {
  const { B, call, audits } = await setup(t, Date.parse('2026-11-10T08:00:00Z'));
  B.putSettings({ fy: 2027 }, ADM);
  const wb = await b64([{ name: 'FY2026', columns: ['Item', 'Budget', 'Category', 'Type', 'Approved', 'Spent', 'Status', 'Vendor'].map((h) => ({ h, t: h === 'Approved' || h === 'Spent' ? 'n' : undefined })), rows: [
    ['Core switch replacement SYN', 'IT Operations', 'Infrastructure', 'CAPEX', 1200000, 450000, 'In progress', 'Synthetic Networks'],
    ['EDR renewal SYN', 'Cyber Security', 'Security', 'OPEX', 300000, 300000, 'Completed', 'Synthetic Security'],
  ] }]);
  assert.equal((await call('POST', '/budget/previous', { fy: 2026, xlsx_b64: wb, filename: 'fy2026.xlsx' }, OP)).status, 403);
  assert.equal((await call('POST', '/budget/previous', { fy: 2026, xlsx_b64: 'x y' }, ADM)).status, 400);
  assert.match((await call('POST', '/budget/previous', { xlsx_b64: wb }, ADM)).json.error, /fy is required/);
  const r = await call('POST', '/budget/previous', { fy: 2026, xlsx_b64: wb, filename: 'fy2026.xlsx' }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.imported, 2);
  const carried = r.json.budget.lines.filter((l) => l.source === 'carryover');
  assert.equal(carried.length, 1, 'completed lines do not carry over'); assert.equal(carried[0].amount, 750000); assert.equal(carried[0].kind, 'capex');
  assert.ok(audits('budget.import_previous').some((a) => a.by === 'cio.syn' && a.detail.rows === 2));
});

test('year-end rollover: archived, carried with actual spend, once, admin import kept, catch-up, reviewed by a person', async (t) => {
  const { e, B, call, clock, audits } = await setup(t, Date.parse('2026-11-10T08:00:00Z'));
  B.putSettings({ fy: 2026 }, ADM);
  const mk = (o, status, note) => { B.saveLine(Object.assign({ area: o.envelope === 'cyber' ? 'security' : 'infrastructure' }, o), ADM); const lid = B.build().lines.find((l) => l.title === o.title).id; if (status) B.decide(lid, { status, note: note || 'synthetic' }, ADM); return lid; };
  const srv = mk({ envelope: 'it_ops', kind: 'capex', title: 'Server refresh SYN', amount: 400000 }, 'approved');
  const wan = mk({ envelope: 'it_ops', kind: 'opex', title: 'WAN links SYN', amount: 120000 }, 'approved');
  mk({ envelope: 'cyber', kind: 'opex', title: 'Pen test SYN', amount: 90000 }, 'deferred', 'moved to next year (synthetic)');
  mk({ envelope: 'it_ops', kind: 'capex', title: 'Rejected idea SYN', amount: 10000 }, 'rejected', 'not needed (synthetic)');
  // spend recorded in Budget execution: the WAN line fully spent, the server line partly
  for (const [line_id, amount, ref] of [[wan, 120000, 'STC-SYN-1'], [srv, 150000, 'INV-SYN-1']]) assert.equal((await call('POST', '/budget-exec/actuals', { line_id, date: '2026-09-10', amount, reference: ref }, OP)).status, 200);

  clock.t = Date.parse('2026-12-31T20:00:00Z');
  assert.equal(B.rollover().rolled, false, 'the year has not ended');
  clock.t = Date.parse('2027-01-01T06:00:00Z');
  const ro = B.rollover();
  assert.deepEqual(ro.years.map((y) => [y.closed, y.next]), [[2026, 2027]]);
  assert.equal(B.rollover().rolled, false, 'once');
  const v = (await call('GET', '/budget', undefined, VW)).json;
  assert.equal(v.fy, 2027, 'planning moved to the next year');
  assert.equal(v.previous.fy, 2026); assert.equal(v.previous.auto, true); assert.equal(v.previous.review.pending, true);
  const carried = v.lines.filter((l) => l.source === 'carryover');
  const C = (title) => carried.find((l) => l.title === title);
  assert.equal(C('Server refresh SYN').amount, 250000, 'approved minus the actual spend');
  assert.equal(C('Pen test SYN').amount, 90000, 'deferred work carries over');
  assert.equal(C('WAN links SYN'), undefined, 'fully spent: completed, not carried'); assert.equal(C('Rejected idea SYN'), undefined);
  assert.equal(v.closed_years[0].fy, 2026); assert.equal(v.closed_years[0].approved, 520000);
  const ra = audits('budget.rollover'); assert.equal(ra.length, 1);
  assert.equal(ra[0].by, 'system:budget-rollover'); assert.equal(ra[0].detail.next_fy, 2027); assert.equal(ra[0].detail.spent_from_execution, true); assert.equal(ra[0].detail.carried_rows, 3);

  // Notification & Escalation shows it until a person signs off the carry-over
  assert.equal(B.signals().length, 1); assert.match(B.signals()[0].title, /FY2026 closed - check the carry-over into FY2027/);
  const nc = e.app.addons.notifyCenter; if (nc) assert.ok((await nc.collect()).signals.some((s) => s.source === 'budget'), 'collected as source "budget"');
  assert.equal((await call('POST', '/budget/rollover/reviewed', {}, VW)).status, 403);
  assert.equal((await call('POST', '/budget/rollover/reviewed', {}, OP)).status, 403);
  assert.equal((await call('POST', '/budget/rollover/reviewed', {}, BOT)).status, 403, 'an AI identity does not sign off');
  const rv = await call('POST', '/budget/rollover/reviewed', {}, ADM2);
  assert.equal(rv.status, 200, rv.text); assert.equal(rv.json.previous.review.by, 'cfo.syn'); assert.equal(B.signals().length, 0);
  assert.equal((await call('POST', '/budget/rollover/reviewed', {}, ADM2)).status, 409);
  assert.ok(audits('budget.rollover_reviewed').some((a) => a.by === 'cfo.syn' && a.role === 'admin'));

  // FY2027: finance imported its own FY2027 figures before year end - the rollover keeps them; the server was then off until 2029
  await call('POST', '/budget/previous', { fy: 2027, rows: [{ item: 'Finance figure SYN', budget: 'IT Operations', type: 'OPEX', approved: '1000', spent: '0', status: 'Pending' }] }, ADM);
  clock.t = Date.parse('2029-02-01T06:00:00Z');
  const two = B.rollover();
  assert.deepEqual(two.years.map((y) => y.closed), [2027, 2028], 'one year at a time');
  assert.equal(two.years[0].kept_admin_import, true);
  assert.equal(B.settings().fy, 2029);
  assert.ok(audits('budget.rollover').some((a) => a.target === 'FY2027' && a.detail.kept_admin_import === true));
});
