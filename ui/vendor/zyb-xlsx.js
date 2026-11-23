// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-xlsx.js - "Export to Excel" for the dashboards: a real .xlsx (Office Open XML), written in the browser with no
 * library and nothing sent anywhere. Bold, frozen header row with filters, column widths, numbers kept as numbers, dates
 * as dates, and a "Report" sheet that says what was exported, by whom, when and with which filter - so a file can never
 * be read as "all records" when the page was filtered. Text cells are inline strings, which Excel never evaluates, so a
 * value that starts with "=" cannot become a formula (the CSV formula-injection problem does not exist here).
 *   zybXlsx.download('end-of-life.xlsx', [{ name: 'End of life', columns: [{ h: 'Device', w: 28 }, { h: 'Days', t: 'n' },
 *     { h: 'EOL date', t: 'd' }], rows: [['srv01', -30, '2026-09-19']] }], { title, filter, by })
 * Column types: 's' text (default), 'n' number (empty / non-numeric = blank, never 0), 'd' date (YYYY-MM-DD[THH:MM]). */
(function () {
  'use strict';
  if (window.zybXlsx) return;
  var CRC = (function () { var t = [], c, n, k; for (n = 0; n < 256; n++) { c = n; for (k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(b) { var c = 0xFFFFFFFF; for (var i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  var enc = new TextEncoder();
  // XML 1.0 allows tab, LF, CR and >= 0x20 (minus lone surrogates and U+FFFE/F); everything else is dropped
  function x(s) {
    s = String(s == null ? '' : s); var o = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) { var d = s.charCodeAt(i + 1); if (d >= 0xDC00 && d <= 0xDFFF) { o += s.charAt(i) + s.charAt(i + 1); i++; } continue; }   // a pair is kept, a lone half dropped
      if (c >= 0xDC00 && c <= 0xDFFF) continue;
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 0xFFFE && c !== 0xFFFF)) o += s.charAt(i);
    }
    return o.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function col(i) { var s = ''; i++; while (i) { var m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; }
  // Excel date serial (days since 1899-12-30, local wall time as written)
  function serial(v) {
    var m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}))?/.exec(String(v || ''));
    if (!m) return null;
    return (Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0)) - Date.UTC(1899, 11, 30)) / 86400000;
  }
  function cell(ref, v, t, style) {
    if (v == null || v === '') return '';
    if (t === 'n') { var n = typeof v === 'number' ? v : Number(String(v).replace(/,/g, '')); if (String(v).trim() === '' || !isFinite(n)) return '<c r="' + ref + '" t="inlineStr"' + (style ? ' s="' + style + '"' : '') + '><is><t>' + x(v) + '</t></is></c>'; return '<c r="' + ref + '"' + (style ? ' s="' + style + '"' : '') + '><v>' + n + '</v></c>'; }
    if (t === 'd') { var d = serial(v); if (d != null) return '<c r="' + ref + '" s="' + (/[T ]\d{2}:\d{2}/.test(String(v)) ? 3 : 2) + '"><v>' + d + '</v></c>'; }
    return '<c r="' + ref + '" t="inlineStr"' + (style ? ' s="' + style + '"' : '') + '><is><t xml:space="preserve">' + x(v) + '</t></is></c>';
  }
  function sheetXml(sh) {
    var cols = sh.columns || [], rows = sh.rows || [], out = [];
    out.push('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">');
    if (sh.header !== false) out.push('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>');
    out.push('<cols>' + cols.map(function (c, i) {
      var w = c.w || Math.min(60, Math.max(10, String(c.h || '').length + 2, rows.slice(0, 200).reduce(function (m, r) { return Math.max(m, String(r[i] == null ? '' : r[i]).length + 1); }, 0)));
      return '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + w + '" customWidth="1"/>';
    }).join('') + '</cols><sheetData>');
    var r0 = 1;
    if (sh.header !== false) { out.push('<row r="1">' + cols.map(function (c, i) { return cell(col(i) + '1', c.h, 's', 1); }).join('') + '</row>'); r0 = 2; }
    rows.forEach(function (r, ri) { var n = ri + r0; out.push('<row r="' + n + '">' + cols.map(function (c, i) { return cell(col(i) + n, r[i], c.t, 0); }).join('') + '</row>'); });
    out.push('</sheetData>');
    if (sh.header !== false && cols.length) out.push('<autoFilter ref="A1:' + col(cols.length - 1) + Math.max(1, rows.length + 1) + '"/>');
    out.push('</worksheet>');
    return out.join('');
  }
  function zip(files) {
    var parts = [], central = [], off = 0;
    files.forEach(function (f) {
      var name = enc.encode(f.name), data = enc.encode(f.data), c = crc32(data);
      var h = new DataView(new ArrayBuffer(30));
      h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, 0, true);
      h.setUint16(10, 0, true); h.setUint16(12, 0x21, true); h.setUint32(14, c, true); h.setUint32(18, data.length, true); h.setUint32(22, data.length, true);
      h.setUint16(26, name.length, true); h.setUint16(28, 0, true);
      parts.push(new Uint8Array(h.buffer), name, data);
      var d = new DataView(new ArrayBuffer(46));
      d.setUint32(0, 0x02014b50, true); d.setUint16(4, 20, true); d.setUint16(6, 20, true); d.setUint16(8, 0x0800, true); d.setUint16(10, 0, true);
      d.setUint16(12, 0, true); d.setUint16(14, 0x21, true); d.setUint32(16, c, true); d.setUint32(20, data.length, true); d.setUint32(24, data.length, true);
      d.setUint16(28, name.length, true); d.setUint32(42, off, true);
      central.push(new Uint8Array(d.buffer), name);
      off += 30 + name.length + data.length;
    });
    var csize = central.reduce(function (n, p) { return n + p.length; }, 0), e = new DataView(new ArrayBuffer(22));
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true); e.setUint32(12, csize, true); e.setUint32(16, off, true);
    return new Blob(parts.concat(central, [new Uint8Array(e.buffer)]), { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }
  function build(sheets, meta) {
    meta = meta || {};
    var info = [['Report', meta.title || ''], ['Exported', new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC'], ['By', meta.by || ''], ['Filter', meta.filter || 'none - every record the page holds']]
      .concat(sheets.map(function (s) { return ['Rows in "' + s.name + '"', (s.rows || []).length]; })).concat(meta.notes ? [['Note', meta.notes]] : []);
    var all = sheets.concat([{ name: 'Report', header: false, columns: [{ h: '', w: 22 }, { h: '', w: 90 }], rows: info }]);
    var seen = {};
    all.forEach(function (s) { var n = String(s.name || 'Sheet').replace(/[\\/?*[\]:]/g, ' ').slice(0, 31) || 'Sheet', k = n, i = 2; while (seen[k.toLowerCase()]) k = n.slice(0, 28) + ' ' + i++; seen[k.toLowerCase()] = 1; s._n = k; });
    var files = [
      { name: '[Content_Types].xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' + all.map(function (s, i) { return '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'; }).join('') + '</Types>' },
      { name: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>' },
      { name: 'xl/workbook.xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + all.map(function (s, i) { return '<sheet name="' + x(s._n) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>'; }).join('') + '</sheets>' + all.map(function (s, i) { return s.header !== false && (s.columns || []).length ? '' : ''; }).join('') + (function () { var d = all.map(function (s, i) { return s.header !== false && (s.columns || []).length ? '<definedName name="_xlnm._FilterDatabase" localSheetId="' + i + '" hidden="1">\'' + x(s._n).replace(/'/g, "''") + '\'!$A$1:$' + col(s.columns.length - 1) + '$' + Math.max(1, (s.rows || []).length + 1) + '</definedName>' : ''; }).join(''); return d ? '<definedNames>' + d + '</definedNames>' : ''; })() + '</workbook>' },
      { name: 'xl/_rels/workbook.xml.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + all.map(function (s, i) { return '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>'; }).join('') + '<Relationship Id="rId' + (all.length + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>' },
      { name: 'xl/styles.xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="2"><numFmt numFmtId="164" formatCode="yyyy-mm-dd"/><numFmt numFmtId="165" formatCode="yyyy-mm-dd hh:mm"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F3A5F"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/><xf numFmtId="165" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>' },
    ];
    all.forEach(function (s, i) { files.push({ name: 'xl/worksheets/sheet' + (i + 1) + '.xml', data: sheetXml(s) }); });
    return zip(files);
  }
  function download(filename, sheets, meta) {
    var blob = build(sheets, meta), url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = /\.xlsx$/i.test(filename) ? filename : filename + '.xlsx';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    return blob;
  }
  // who is signed in (best-effort; the file says "unknown" rather than guessing)
  function who() { return new Promise(function (ok) { var r = new XMLHttpRequest(); r.open('GET', '/api/itam/roles/me'); r.withCredentials = true; r.timeout = 4000; r.onload = function () { try { ok(JSON.parse(r.responseText).user || 'unknown'); } catch (e) { ok('unknown'); } }; r.onerror = r.ontimeout = function () { ok('unknown'); }; r.send(); }); }
  window.zybXlsx = { build: build, download: download, who: who };
})();
