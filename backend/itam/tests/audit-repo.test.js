// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Repository (engine/audit-repo.js) through the real routes over a SYNTHETIC audit history (SAMA 2024 / 2025 / 2026, an external
// audit): reports validated (year, body, a duplicate, an issue date far from the year); a report file checked by its bytes and hash, a
// renamed file refused, a download audited; a management letter imported from Excel with its own column names (Observation, Risk
// Rating, Target Date ...), one bad line refuses the whole file with every problem named, a dry run imports nothing; repeat findings
// proposed with the score itemised and decided by a person (not an AI identity, not a later year); closing needs evidence; analytics
// per year and body (Beta closure rate), carried-forward regulator findings first in the actions, systemic areas over 3 years, late
// risk; an open finding raised as a GRC action; Excel export; viewer refused, archive admin only; every change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { words } = require('../engine/audit-repo');

const NOW = Date.parse('2026-11-04T08:00:00Z');
const OP = { user: 'auditor.syn', role: 'operator' }, REV = { user: 'reviewer.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:audit', role: 'operator' };
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../../ui/vendor/zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const xlsx = async (columns, rows) => Buffer.from(await XL.build([{ name: 'Management letter', columns: columns.map((h) => ({ h })), rows }], { title: 'synthetic' }).arrayBuffer()).toString('base64');
const PDF = Buffer.from('%PDF-1.4\n% synthetic audit report\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(800).filter((x) => x.action === 'audit-repo.' + a) };
}
const report = (s, year, extra, who) => s.post('/audit-repo/reports', Object.assign({ year, body: 'sama', kind: 'inspection', title: 'SAMA cyber security inspection ' + year + ' (synthetic)', auditor: 'SAMA inspection team (synthetic)', issued: year + '-06-30' }, extra || {}), who);

test('reports: validation, roles, files checked by their bytes, downloads audited', async (t) => {
  const s = await setup(t);
  let r = await report(s, 2024); assert.equal(r.status, 200, r.text); const R = r.json; assert.equal(R.body_name, 'SAMA'); assert.equal(R.status, 'draft');
  assert.equal((await report(s, 2024)).status, 409, 'the same report twice');
  assert.match((await s.post('/audit-repo/reports', { year: 2024, body: 'sama', kind: 'inspection', auditor: 'x' })).text, /title is required/);
  assert.match((await report(s, 2024, { body: 'mars', title: 'other' })).text, /body must be one of/);
  assert.match((await report(s, 2023, { issued: '2020-01-01', title: 'far' })).text, /far from the audit year/);
  assert.match((await report(s, 2031, { title: 'future' })).text, /year/);
  assert.equal((await report(s, 2025, {}, VIEW)).status, 403, 'viewer refused');
  assert.equal((await report(s, 2025, {}, BOT)).status, 403, 'an AI identity does not record');
  assert.equal((await s.get('/audit-repo', VIEW)).status, 403, 'a viewer does not read the register');
  // the report file: bytes checked, hash kept, the same file twice refused, a damaged upload refused
  r = await s.post('/audit-repo/reports/' + R.id + '/files', { filename: 'SAMA-2024.pdf', content_b64: PDF.toString('base64') }); assert.equal(r.status, 200, r.text);
  const f = r.json.files[0]; assert.match(f.sha256, /^[0-9a-f]{64}$/); assert.equal(f.type, 'pdf');
  assert.equal((await s.post('/audit-repo/reports/' + R.id + '/files', { filename: 'again.pdf', content_b64: PDF.toString('base64') })).status, 409);
  assert.match((await s.post('/audit-repo/reports/' + R.id + '/files', { filename: 'report.pdf', content_b64: Buffer.from('MZ\x90\x00 not a pdf').toString('base64') })).text, /not a real \.pdf/);
  assert.match((await s.post('/audit-repo/reports/' + R.id + '/files', { filename: 'x.html', content_b64: Buffer.from('<html>').toString('base64') })).text, /not accepted/);
  assert.match((await s.post('/audit-repo/reports/' + R.id + '/files', { filename: 'b.pdf', content_b64: Buffer.from('%PDF-1.4 other').toString('base64'), sha256: '0'.repeat(64) })).text, /arrived damaged/);
  const d = await s.get('/audit-repo/files/' + f.id); assert.equal(d.status, 200); assert.equal(Buffer.from(d.json.content_b64, 'base64').toString(), PDF.toString());
  assert.equal((await s.get('/audit-repo/files/' + f.id, VIEW)).status, 403);
  assert.ok(s.audit('file.download').some((a) => a.target === f.id && a.by === OP.user));
  // edit, archive (admin only, with a note)
  r = await s.post('/audit-repo/reports/' + R.id, { status: 'final', notes: 'signed copy received (synthetic)' }); assert.equal(r.json.status, 'final');
  assert.equal((await s.post('/audit-repo/reports/' + R.id + '/archive', { note: 'recorded twice by mistake' })).status, 403, 'operator cannot archive');
  assert.match((await s.post('/audit-repo/reports/' + R.id + '/archive', { note: 'x' }, ADM)).text, /note must be at least/);
  assert.ok(s.audit('report.create').length === 1 && s.audit('report.edit').length === 1 && s.audit('file.add').length === 1);
});

test('findings: Excel import with its own headings, all or nothing, repeats proposed and decided by a person, analytics and actions', async (t) => {
  const s = await setup(t);
  const r24 = (await report(s, 2024)).json, r25 = (await report(s, 2025)).json, r26 = (await report(s, 2026, { issued: '2026-06-30' })).json;
  const ext = (await s.post('/audit-repo/reports', { year: 2025, body: 'external', kind: 'external_audit', title: 'External audit management letter 2025 (synthetic)', auditor: 'Synthetic & Co', issued: '2026-03-15' })).json;
  const H = ['Ref', 'Observation', 'Details', 'Domain', 'Risk Rating', 'Owner', 'Target Date', 'Status'];
  // a bad line refuses the file: nothing is imported, every problem is named
  let r = await s.post('/audit-repo/reports/' + r24.id + '/findings/import', { xlsx_b64: await xlsx(H, [['S24-01', 'User access reviews not performed for the core insurance system', 'No periodic review of user access rights was evidenced', 'Access management', 'High', 'it.ops.syn', '2024-12-31', 'Open'], ['S24-02', 'Backups not tested', '', 'Resilience', 'Severe', '', '', 'Open']]), filename: 'ml-2024.xlsx' });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.imported, 0); assert.match(r.json.errors[0].error, /rating "Severe"/); assert.equal(r.json.columns.title, 'Observation'); assert.equal(r.json.columns.rating, 'Risk Rating');
  r = await s.post('/audit-repo/reports/' + r24.id + '/findings/import', { xlsx_b64: await xlsx(H, [['S24-01', 'User access reviews not performed for the core insurance system', 'No periodic review of user access rights was evidenced', 'Access management', 'High', 'it.ops.syn', '2024-12-31', 'Open'], ['S24-02', 'Backups not tested', 'Restore tests not performed', 'Resilience', 'Medium', 'infra.syn', '2025-03-31', 'Closed']]), filename: 'ml-2024.xlsx', dry_run: true });
  assert.equal(r.json.rows, 2); assert.equal(r.json.imported, 0, 'a dry run imports nothing');
  r = await s.post('/audit-repo/reports/' + r24.id + '/findings/import', { xlsx_b64: await xlsx(H, [['S24-01', 'User access reviews not performed for the core insurance system', 'No periodic review of user access rights was evidenced', 'Access management', 'High', 'it.ops.syn', '2024-12-31', 'Open'], ['S24-02', 'Backups not tested', 'Restore tests not performed', 'Resilience', 'Medium', 'infra.syn', '2025-03-31', 'Closed']]), filename: 'ml-2024.xlsx' });
  assert.equal(r.json.imported, 2, r.text);
  assert.equal((await s.post('/audit-repo/reports/' + r24.id + '/findings/import', { csv: 'Ref,Observation,Risk Rating\nS24-01,again,High\n' })).json.errors[0].error.includes('already a finding'), true);
  assert.match((await s.post('/audit-repo/reports/' + r24.id + '/findings/import', { csv: 'a,b\n1,2\n' })).text, /no finding \/ observation \/ title column/);
  // CSV works too
  r = await s.post('/audit-repo/reports/' + r25.id + '/findings/import', { csv: 'Finding No,Finding,Description,Area,Severity,Responsible,Due Date\nS25-01,Periodic user access review for the core insurance system was not performed,User access rights were not reviewed in the period,Access management,High,it.ops.syn,2025-12-31\nS25-02,Privileged accounts not monitored,,Access management,Critical,soc.syn,2026-02-28\n' });
  assert.equal(r.json.imported, 2, r.text);
  await s.post('/audit-repo/reports/' + r26.id + '/findings', { ref: 'S26-01', title: 'Access review of the core insurance system not performed again', area: 'Access management', rating: 'high', owner: 'it.ops.syn', due: '2026-12-31' });
  await s.post('/audit-repo/reports/' + ext.id + '/findings', { ref: 'EXT-1', title: 'Journal entries posted without approval', area: 'Financial reporting', rating: 'medium', owner: 'finance.syn', due: '2026-12-15' });
  assert.match((await s.post('/audit-repo/reports/' + r26.id + '/findings', { title: 'x', rating: 'high' })).text, /title must be at least/);
  assert.match((await s.post('/audit-repo/reports/' + r26.id + '/findings', { title: 'Something new', rating: 'urgent' })).text, /rating must be one of/);
  let v = (await s.get('/audit-repo')).json;
  const f25 = v.findings.find((f) => f.ref === 'S25-01'), f24 = v.findings.find((f) => f.ref === 'S24-01'), f26 = v.findings.find((f) => f.ref === 'S26-01');
  // repeat proposals: the 2025 access-review finding looks like 2024's; the score is itemised
  const p25 = v.proposals.find((p) => p.finding === f25.id); assert.ok(p25, JSON.stringify(v.proposals)); assert.equal(p25.candidates[0].of, f24.id); assert.ok(p25.candidates[0].why.some((w) => /same area/.test(w)));
  assert.ok(!v.proposals.some((p) => p.finding === f24.id), 'the earliest year has nothing to repeat');
  assert.equal((await s.post('/audit-repo/findings/' + f25.id + '/repeat', { of: f24.id, decision: 'confirm', note: 'same control gap (synthetic)' }, BOT)).status, 403, 'an AI identity never confirms');
  assert.match((await s.post('/audit-repo/findings/' + f24.id + '/repeat', { of: f25.id, decision: 'confirm', note: 'backwards' })).text, /earlier year/);
  assert.equal((await s.post('/audit-repo/findings/' + f25.id + '/repeat', { of: f24.id, decision: 'confirm', note: 'same control gap (synthetic)' })).status, 200);
  assert.equal((await s.post('/audit-repo/findings/' + f26.id + '/repeat', { of: f25.id, decision: 'confirm', note: 'third year running (synthetic)' }, REV)).status, 200);
  // closing needs evidence
  assert.match((await s.post('/audit-repo/findings/' + f24.id, { status: 'closed', note: 'done' })).text, /evidence: closing a finding needs/);
  assert.equal((await s.post('/audit-repo/findings/' + f24.id, { status: 'closed', note: 'review performed', evidence: 'access review sign-off 2025-02 (synthetic)' })).json.status, 'closed');
  assert.match((await s.post('/audit-repo/findings/' + f24.id, { note: 'nothing' })).text, /nothing to change/);
  v = (await s.get('/audit-repo')).json;
  assert.equal(v.kpis.findings, 6); assert.equal(v.kpis.repeats, 2); assert.ok(v.kpis.carried >= 2, 'open findings from earlier years carried forward');
  assert.equal(v.actions[0].filter, 'carried'); assert.match(v.actions[0].title, /SAMA \/ Insurance Authority finding\(s\) from earlier years still open/);
  assert.ok(v.actions.some((a) => a.filter === 'repeat'));
  assert.deepEqual(v.systemic.map((x) => x.area), ['Access management'], 'found in 2024, 2025 and 2026');
  const y24 = v.by_year.find((y) => y.year === 2024); assert.equal(y24.findings, 2); assert.equal(y24.closure_rate, 75, 'Beta-smoothed: 2 of 2 closed reads 75, not 100');
  assert.ok(v.matrix.rows.find((x) => x.body === 'sama').cells.every((c) => c && c.findings >= 1));
  const o26 = v.findings.find((f) => f.id === f26.id); assert.ok(o26.late_risk && o26.late_risk.p >= 0 && /earlier finding/.test(o26.late_risk.basis));
  assert.ok(v.findings.find((f) => f.id === f25.id).overdue, 'S25-01 due 2025-12-31 is overdue');
  // an open finding raised as a GRC remediation action
  r = await s.post('/audit-repo/findings/' + f26.id + '/to-action', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.action.source, 'audit'); assert.equal(r.json.action.ref, f26.id);
  assert.equal((await s.post('/audit-repo/findings/' + f26.id + '/to-action', {})).status, 409);
  assert.equal((await s.post('/audit-repo/findings/' + f24.id + '/to-action', {})).status, 409, 'closed findings need no action');
  // Excel export
  const x = (await s.get('/audit-repo/export')).json; assert.deepEqual(x.sheets.map((sh) => sh.name), ['Findings', 'By year', 'Reports']); assert.equal(x.sheets[0].rows.length, 6);
  assert.ok(s.audit('finding.import').length === 2 && s.audit('finding.repeat').length === 2 && s.audit('finding.update').length === 1 && s.audit('finding.action').length === 1 && s.audit('export').length === 1);
  assert.ok(s.audit('finding.repeat').every((a) => a.by !== BOT.user));
});

test('words: stop words dropped, light stemming, Arabic kept', () => {
  assert.deepEqual(words('The reviews of user access were not performed'), ['review', 'user', 'access', 'perform']);
  assert.ok(words('مراجعة صلاحيات المستخدمين').length === 3);
});
