// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A SYNTHETIC workbook in the layout of the Insurance Authority's Solvency and Capital template (SCA.nn): the sheets the platform
// reads, with formulas and their cached values the way Excel saves them. Invented insurer, figures and people - no company record.
// o: { asAt, version, ratio, marketInput, failComment, formulaEdit, extraFail }
const zlib = require('node:zlib');
const { _t } = require('../engine/xlsx-book');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function cellXml(ref, v) {
  if (v && typeof v === 'object' && 'f' in v) {
    const cv = v.v, t = typeof cv === 'string' ? ' t="str"' : typeof cv === 'boolean' ? ' t="b"' : '';
    return '<c r="' + ref + '"' + t + '><f>' + esc(v.f) + '</f><v>' + (typeof cv === 'boolean' ? (cv ? 1 : 0) : esc(cv)) + '</v></c>';
  }
  if (typeof v === 'number') return '<c r="' + ref + '"><v>' + v + '</v></c>';
  if (typeof v === 'boolean') return '<c r="' + ref + '" t="b"><v>' + (v ? 1 : 0) + '</v></c>';
  return '<c r="' + ref + '" t="inlineStr"><is><t>' + esc(v) + '</t></is></c>';
}
function sheetXml(cells) {
  const rows = new Map();
  for (const ref of Object.keys(cells)) { const m = /^([A-Z]+)(\d+)$/.exec(ref); const r = +m[2]; if (!rows.has(r)) rows.set(r, []); rows.get(r).push([m[1], ref]); }
  const ord = (c) => c.length * 100 + c.charCodeAt(0) + (c.length > 1 ? c.charCodeAt(1) : 0);
  let x = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
  for (const r of [...rows.keys()].sort((a, b) => a - b)) x += '<row r="' + r + '">' + rows.get(r).sort((a, b) => ord(a[0]) - ord(b[0])).map(([, ref]) => cellXml(ref, cells[ref])).join('') + '</row>';
  return x + '</sheetData></worksheet>';
}
function zip(files) {
  const chunks = [], cen = []; let off = 0;
  for (const [name, text] of files) {
    const raw = Buffer.from(text, 'utf8'), data = zlib.deflateRawSync(raw), n = Buffer.from(name), crc = _t.crc32(raw), lh = Buffer.alloc(30), ch = Buffer.alloc(46);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(n.length, 26);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    chunks.push(lh, n, data); cen.push(ch, n); off += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(cen), e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(files.length, 8); e.writeUInt16LE(files.length, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat(chunks.concat([cd, e]));
}

function sheets(o = {}) {
  const asAt = o.asAt || '2025-12-31', y = +asAt.slice(0, 4), ratio = o.ratio || 2.25, naa = 900000, req = Math.round(naa / ratio);
  const mkt = o.marketInput === undefined ? 125000 : o.marketInput;
  return [
    ['Instructions', { B2: 'Name of the Insurer', C2: 'Synthetic Cooperative Insurance Co.', B3: o.atLabel || 'Data as at [date]', C3: asAt, B10: 'All amounts should be stated in Thousands.' }],
    ['Version', { C2: 'Version No.', C3: 'SCA.01', C4: o.version || 'SCA.04' }],
    ['Sign-off Record', { A1: 'Synthetic dry run - Record of Sign-off', A2: 'Area', B2: 'Department of the Person Signing-Off', C2: 'Name of the Person Signing-Off', D2: 'Title', E2: 'Expert Judgments Used (if any)', F2: 'Comments (if any)',
      A3: 'Own Funds Results', A4: 'Tiering and Calculation', B4: 'Finance Function', A5: 'Risk-Based Capital Results', A6: 'Market Risk', B6: 'Finance Function', B7: 'Actuarial Function', A8: 'Operational Risk', B8: 'Risk Function' }],
    ['Validations', Object.assign({ B24: 'Reconciliation of Exposures Across Market Sub-modules', C24: 'Checks', D24: 'Comment if fail', B25: 'Bonds (synthetic)', C25: { f: 'IF(Market!C5=Market!D5,"Pass","Fail")', v: 'Fail' },
      B26: 'Equity (synthetic)', C26: { f: 'IF(1=1,"Pass","Fail")', v: 'Pass' }, G24: 'Alignment with SOFP', G25: 'Assets', H25: { f: 'IF(1=1,"Pass","Fail")', v: 'Pass' } },
      o.failComment ? { D25: o.failComment } : {}, o.extraFail ? { B27: 'Property (synthetic)', C27: { f: 'IF(1=2,"Pass","Fail")', v: 'Fail' } } : {})],
    ['Market', Object.assign({ B5: 'Synthetic bonds', C5: mkt, D5: 120000, E5: { f: 'C5*0.05', v: mkt * 0.05 } }, o.formulaEdit ? { E5: { f: 'C5*0.01', v: mkt * 0.01 } } : {})],
    ['Regulatory Solvency', { B5: "All amounts in SR '000", D5: y - 1, E5: y, F5: y + 1, B12: 'Total Admissible Assets', D12: 2000000, E12: 2100000, F12: 2200000, B20: 'Total Liabilities', D20: 1150000, E20: 1200000, F20: 1250000,
      B33: 'Claims Method - Required margin (General and Health Insurance)', E33: req - 100000, B34: 'Premium Method Required margin (General and Health Insurance)', E34: req - 50000, B35: 'Required margin (Protection and Savings Insurance)', E35: 50000,
      B28: 'Total Net Admissible Assets', D28: 850000, E28: naa, F28: 950000, B37: 'Minimum Capital Requirement (1)', D37: 100000, E37: 100000, F37: 100000,
      B38: 'Total Required Minimum Margin (the highest of 2 measures)', D38: 400000, E38: req, F38: 410000, B40: 'Excess (deficiency) of Net Admissible Assets', E40: { f: 'E28-E38', v: naa - req },
      B42: 'Basis for Required Solvency Capital', E42: 'Premium-based', B43: 'Solvency Ratio', D43: 2.125, E43: { f: 'IF(E38=0,"",E28/E38)', v: naa / req }, F43: 2.3 }],
    ['Projected RBC', { C7: (y - 1) + 'YE', D7: y + 'YE', F7: (y + 1) + 'YE', G7: (y + 2) + 'YE', K7: (y + 1) + 'YE', A8: 'RBC', C8: 400000, D8: 420000, F8: 450000, G8: 470000, K8: 0, B9: 'Own Funds', C9: 1100000, D9: 1150000, F9: 1200000, G9: 1260000,
      B10: 'Net RA', D10: 0, B11: 'Net CSM', D11: 0, A12: 'RBC Solvency Ratio', C12: 2.75, D12: { f: 'D9/D8', v: 1150000 / 420000 }, F12: 2.67, G12: 2.68, K12: 0 }],
    ['RBC', { AA5: 'Overall RBC', AB5: 'As % of RBC', AA6: 'Non-Life UW Risk', AB6: 0.5, AA7: 'Market Risk', AB7: 0.45, AA8: 'Credit Risk', AB8: 0.15, AA9: 'Divers. Benefit', AB9: -0.2, AA10: 'Operational Risk', AB10: 0.1, AA11: 'RBC', AB11: 1 }],
    ['Summary of results', { B4: 'Stress/ Scenario Test', C4: 'Undiversified BEFORE', B5: 'Market - Interest Rate', C5: -90000, D5: -90000, F5: -90000, G5: -90000, H5: 2, B6: 'Natural CAT - Pluvial Flood', C6: -1000000, D6: -900000, F6: -20000, G6: -18000, H6: 3,
      B7: 'Non life Underwriting - Premium risk', C7: -250000, D7: -250000, F7: -250000, G7: -250000, H7: 1, B8: 'Undiversified Change in NAV', C8: -1340000, D8: -1240000, F8: -360000, G8: -358000 }],
  ];
}
function build(o) { return bookOf(sheets(o)); }
// any workbook from [[sheetName, {ref: value | {f, v}}], ...] - used by other synthetic templates (tests/rbc-fixture.js)
function bookOf(S) {
  const files = [];
  files.push(['[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    + S.map((s, i) => '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>').join('') + '</Types>']);
  files.push(['_rels/.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>']);
  files.push(['xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
    + S.map((s, i) => '<sheet name="' + esc(s[0]) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>').join('') + '</sheets><calcPr calcId="191029"/></workbook>']);
  files.push(['xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    + S.map((s, i) => '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>').join('') + '</Relationships>']);
  S.forEach((s, i) => files.push(['xl/worksheets/sheet' + (i + 1) + '.xml', sheetXml(s[1])]));
  return zip(files);
}
const b64 = (o) => build(o).toString('base64');
module.exports = { build, b64, bookOf };
