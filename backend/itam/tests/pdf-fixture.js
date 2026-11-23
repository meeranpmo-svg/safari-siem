// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SYNTHETIC PDFs for the PDF reader tests (engine/pdf-text.js, engine/pricing-pdf.js): text placed at given positions, with the
// features real reports use - Flate-compressed content, TJ arrays with kerning, a Type0 font with 2-byte codes and a ToUnicode map,
// a form XObject drawn with Do, objects inside a compressed object stream, an Encrypt entry, a page with no text.
//   build([[{ x, y, t, size?, tj? , u? }]], { compress, xobject, objstm, encrypt }) -> Buffer
const zlib = require('node:zlib');
const lit = (s) => '(' + String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)') + ')';
function build(pages, o = {}) {
  const objs = [], add = (s) => { objs.push(s); return objs.length; };
  const cat = add(null), pagesId = add(null), f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  // a Type0 font: code = character + 0x100, mapped back by its ToUnicode CMap
  const cmap = '/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfrange <0100> <01FF> <0000> endbfrange\nendcmap end end';
  const tu = add('<< /Length ' + cmap.length + ' >>\nstream\n' + cmap + '\nendstream');
  const desc = add('<< /Type /Font /Subtype /CIDFontType2 /BaseFont /SynSans /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 500 >>');
  const f2 = add('<< /Type /Font /Subtype /Type0 /BaseFont /SynSans /Encoding /Identity-H /DescendantFonts [' + desc + ' 0 R] /ToUnicode ' + tu + ' 0 R >>');
  const hex2 = (s) => '<' + [...String(s)].map((c) => (c.charCodeAt(0) + 0x100).toString(16).padStart(4, '0')).join('') + '>';
  const kids = [];
  for (const items of pages) {
    const ops = items.map((it) => { const sz = it.size || 9, f = it.u ? '/F2' : '/F1';
      const show = it.u ? hex2(it.t) + ' Tj' : it.tj ? '[' + it.t.split('|').map(lit).join(' -60 ') + '] TJ' : lit(it.t) + ' Tj';
      return 'BT ' + f + ' ' + sz + ' Tf 1 0 0 1 ' + it.x + ' ' + it.y + ' Tm ' + show + ' ET'; }).join('\n');
    let content = ops, xo = '';
    if (o.xobject) { const form = add('<< /Type /XObject /Subtype /Form /BBox [0 0 800 600] /Matrix [1 0 0 1 0 0] /Resources << /Font << /F1 ' + f1 + ' 0 R /F2 ' + f2 + ' 0 R >> >> /Length ' + ops.length + ' >>\nstream\n' + ops + '\nendstream');
      content = 'q 1 0 0 1 0 0 cm /X1 Do Q'; xo = ' /XObject << /X1 ' + form + ' 0 R >>'; }
    let stream; if (o.compress !== false) { const z = zlib.deflateSync(Buffer.from(content, 'latin1')); stream = { z }; } else stream = { s: content };
    const cid = add(stream);
    kids.push(add('<< /Type /Page /Parent ' + pagesId + ' 0 R /MediaBox [0 0 842 595] /Contents ' + cid + ' 0 R /Resources << /Font << /F1 ' + f1 + ' 0 R /F2 ' + f2 + ' 0 R >>' + xo + ' >> >>'));
  }
  objs[pagesId - 1] = '<< /Type /Pages /Kids [' + kids.map((k) => k + ' 0 R').join(' ') + '] /Count ' + kids.length + ' >>';
  objs[cat - 1] = '<< /Type /Catalog /Pages ' + pagesId + ' 0 R >>';
  // optionally move the catalog and the page tree into a compressed object stream
  let inStm = [];
  if (o.objstm) { inStm = [cat, pagesId]; const body = inStm.map((n) => objs[n - 1]); let head = '', off = 0; const parts = [];
    inStm.forEach((n, k) => { head += n + ' ' + off + ' '; parts.push(body[k]); off += body[k].length + 1; });
    const data = head + parts.join('\n'), z = zlib.deflateSync(Buffer.from(data, 'latin1'));
    add({ z, dict: '/Type /ObjStm /N ' + inStm.length + ' /First ' + head.length }); }
  const chunks = [Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1')], offs = []; let pos = chunks[0].length;
  objs.forEach((v, k) => { const n = k + 1; if (inStm.includes(n)) { offs.push(null); return; } let b;
    if (v && v.z) b = Buffer.concat([Buffer.from(n + ' 0 obj\n<< ' + (v.dict || '') + ' /Filter /FlateDecode /Length ' + v.z.length + ' >>\nstream\n', 'latin1'), v.z, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
    else if (v && v.s != null) b = Buffer.from(n + ' 0 obj\n<< /Length ' + v.s.length + ' >>\nstream\n' + v.s + '\nendstream\nendobj\n', 'latin1');
    else b = Buffer.from(n + ' 0 obj\n' + v + '\nendobj\n', 'latin1');
    offs.push(pos); chunks.push(b); pos += b.length; });
  const xref = 'xref\n0 ' + (objs.length + 1) + '\n0000000000 65535 f \n' + offs.map((x) => (x == null ? '0000000000 00000 f ' : String(x).padStart(10, '0') + ' 00000 n ')).join('\n') + '\n';
  chunks.push(Buffer.from(xref + 'trailer\n<< /Size ' + (objs.length + 1) + ' /Root ' + cat + ' 0 R' + (o.encrypt ? ' /Encrypt << /Filter /Standard /V 2 >>' : '') + ' >>\nstartxref\n' + pos + '\n%%EOF\n', 'latin1'));
  return Buffer.concat(chunks);
}
// a synthetic actuarial pricing report: the four layouts the reader knows, with clearly synthetic figures
function pricingReport(o = {}) {
  const row = (y, cells) => cells.map(([x, t, extra]) => Object.assign({ x, y, t }, extra || {}));
  const p1 = [].concat(
    row(560, [[40, 'Synthetic Insurance Co. - Pricing Adequacy Review 2026 Q1 (synthetic)']]),
    row(530, [[40, "Table 1: Premium adequacy by line (SAR '000)"]]),
    row(510, [[40, 'Line of business'], [220, 'Net earned premium'], [340, 'Ultimate loss ratio'], [460, 'Expense ratio'], [560, 'Commission ratio'], [670, 'Target loss ratio']]),
    row(490, [[40, 'Motor TPL'], [240, '21,300'], [360, '82.1%'], [480, '14.0%'], [580, '6.5%'], [690, '75.0%']]),
    row(475, [[40, 'Motor Comprehensive', { tj: true, t: 'Motor Compre|hensive' }], [240, '18,750'], [360, '71.4%'], [480, '13.0%'], [580, '8.0%'], [690, '72.0%']]),
    row(460, [[40, 'Medical SME'], [240, '33,900'], [360, '0.884'], [480, '11.5%'], [580, '4.0%'], [690, '85.0%']]),
    row(445, [[40, 'Property (not a pricing line here)'], [240, '9,000'], [360, '55.0%'], [480, '20.0%'], [580, '10.0%'], [690, '60.0%']]),
    row(430, [[40, 'Medical Corporate'], [240, '41,200'], [360, '91.0%'], [480, '9.0%'], [580, '3.0%'], [690, '88.0%']]),
    row(380, [[40, 'Table 2: Rate changes and growth'], [520, '(synthetic)']]),
    row(360, [[40, 'Measure'], [240, 'Motor TPL'], [360, 'Medical SME'], [480, 'Medical Corporate']]),
    row(345, [[40, 'Rate change implemented'], [250, '5.0%'], [370, '3.5%'], [490, '(1.0%)']]),
    row(330, [[40, 'Exposure growth'], [250, '2.0%'], [370, '6.0%'], [490, '1.5%']]));
  const p2 = [].concat(
    row(560, [[40, 'Table 3: Ultimate loss ratio by underwriting year (synthetic)']]),
    row(540, [[40, 'Line'], [240, '2024'], [340, '2025'], [440, '2026 Q1']]),
    row(525, [[40, 'Motor TPL'], [250, '79.0%'], [350, '80.5%'], [450, '82.1%']]),
    row(510, [[40, 'Medical SME'], [250, '86.0%'], [350, '87.2%'], [450, '90.0%']]),
    row(470, [[40, 'Motor Comprehensive ultimate loss ratio for 2026 Q1 is 70.9% after the large-loss review (synthetic).', { u: !!o.unicode }]]),
    row(440, [[40, "Table 4: Net earned premium (SAR million)"]]),
    row(425, [[40, 'Line'], [240, 'Net earned premium']]),
    row(410, [[40, 'Medical Individual'], [250, '12.5']]));
  return build(o.scanned ? [[], []] : [p1, p2], o);
}
module.exports = { build, pricingReport };
