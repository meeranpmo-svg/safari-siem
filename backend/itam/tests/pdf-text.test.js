// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The PDF reader (engine/pdf-text.js) and the pricing-figure reader on top of it (engine/pricing-pdf.js) on SYNTHETIC PDFs
// (tests/pdf-fixture.js): compressed and plain content, TJ kerning, a 2-byte font with ToUnicode, a form XObject, objects in an object
// stream; refused: not a PDF, encrypted; a scanned (text-less) PDF says so. The four table layouts, fractions read as %, SAR million
// converted, a conflict kept as two candidates, a line that is not priced here ignored, a heading about capital not read as premium.
const test = require('node:test');
const assert = require('node:assert/strict');
const { pdfText } = require('../engine/pdf-text');
const { pricingFromPdf, _t } = require('../engine/pricing-pdf');
const F = require('./pdf-fixture');

test('pdf text: lines and cells from every way a PDF stores text', () => {
  for (const o of [{}, { compress: false }, { xobject: true }, { objstm: true }, { unicode: true }]) {
    const d = pdfText(F.pricingReport(o)); assert.equal(d.pages.length, 2, JSON.stringify(o));
    const hdr = d.pages[0].lines.find((l) => /^Line of business/.test(l.text)); assert.ok(hdr, 'heading row ' + JSON.stringify(o));
    assert.deepEqual(hdr.cells.map((c) => c.text), ['Line of business', 'Net earned premium', 'Ultimate loss ratio', 'Expense ratio', 'Commission ratio', 'Target loss ratio']);
    assert.ok(d.pages[0].lines.some((l) => l.cells[0].text === 'Motor Comprehensive'), 'a TJ array with kerning is one word');
    assert.ok(d.pages[1].lines.some((l) => /Motor Comprehensive ultimate loss ratio for 2026 Q1 is 70\.9%/.test(l.text)), 'the 2-byte font decodes through ToUnicode ' + JSON.stringify(o));
  }
  assert.throws(() => pdfText(Buffer.from('not a pdf')), (e) => e.status === 400);
  assert.throws(() => pdfText(F.pricingReport({ encrypt: true })), (e) => e.status === 400 && /encrypted/.test(e.message));
  const sc = pdfText(F.pricingReport({ scanned: true })); assert.ok(sc.warnings.some((w) => /scanned/.test(w)));
});

test('pricing figures: four layouts, units, conflicts, nothing invented', () => {
  const r = pricingFromPdf(pdfText(F.pricingReport()));
  const g = (period, line, sub) => r.groups.find((x) => x.period === period && x.line === line && x.sub_line === sub);
  const tpl = g('2026-Q1', 'motor', 'Compulsory (TPL)'); assert.ok(tpl);
  assert.equal(tpl.fields.nep[0].value, 21300); assert.equal(tpl.fields.ulr[0].value, 82.1); assert.deepEqual(tpl.fields.ulr[0].pages, [1, 2], 'the same figure on two pages is one proposal');
  assert.equal(tpl.fields.target_loss_ratio[0].value, 75); assert.equal(tpl.fields.rate_change[0].how, 'rows'); assert.equal(tpl.fields.rate_change[0].value, 5);
  assert.equal(tpl.fields.ulr[0].pages[0], 1); assert.match(tpl.fields.ulr[0].table, /Table 1/); assert.deepEqual(tpl.missing, []);
  const sme = g('2026-Q1', 'medical', 'SME / Group'); assert.equal(sme.fields.ulr[0].value, 88.4); assert.match(sme.fields.ulr[0].note, /fraction/); assert.ok(sme.conflicts.includes('ulr'), '88.4 in table 1, 90.0 in table 3');
  assert.equal(g('2026-Q1', 'medical', 'Corporate').fields.rate_change[0].value, -1, '(1.0%) is negative');
  const comp = g('2026-Q1', 'motor', 'Comprehensive'); assert.deepEqual(comp.fields.ulr.map((x) => x.how).sort(), ['columns', 'text'], 'prose and table both kept');
  const ind = g('2026-Q1', 'medical', 'Individual'); assert.equal(ind.fields.nep[0].value, 12500); assert.match(ind.fields.nep[0].note, /million/);
  assert.equal(g('2024', 'motor', 'Compulsory (TPL)').fields.ulr[0].value, 79); assert.equal(g('2025', 'medical', 'SME / Group').fields.ulr[0].value, 87.2);
  assert.ok(!g('2024', 'medical', 'Individual'), 'a table does not run on into the next one');
  assert.ok(!JSON.stringify(r.groups).includes('9000'), 'Property is not priced on this page');
  // what is not a pricing measure or line
  assert.equal(_t.fieldOf('Allocation Based on NEP'), null); assert.equal(_t.fieldOf('Sliding Scale Commission'), null); assert.equal(_t.fieldOf('Ultimate loss ratio'), 'ulr');
  assert.equal(_t.lineOf('Health Pandemic', {}), null); assert.deepEqual(_t.lineOf('LOB9', { LOB9: 'Health Insurance' }), { line: 'medical', sub: null }); assert.equal(_t.lineOf('LOB9', {}), null, 'never a guess');
  assert.equal(_t.periodOf('Q1 2026'), '2026-Q1'); assert.equal(_t.periodOf('FY2025'), '2025');
  const none = pricingFromPdf(pdfText(F.build([[{ x: 40, y: 500, t: 'Solvency and Capital Report (synthetic)' }, { x: 40, y: 480, t: 'No pricing tables here' }]])));
  assert.equal(none.proposals, 0); assert.match(none.notes[0], /no pricing figures were recognised/);
});

test('pdf text: a decompression bomb is refused, not expanded', () => {
  const zlib = require('node:zlib'), z = zlib.deflateSync(Buffer.alloc(80 * 1024 * 1024, 0x20));
  const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Filter /FlateDecode /Length ' + z.length + ' >>\nstream\n', 'latin1'), z, Buffer.from('\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n', 'latin1')]);
  assert.throws(() => pdfText(pdf), (e) => e.status === 400 && /64 MB/.test(e.message));
});
