// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Read the first worksheet of an .xlsx (Office Open XML) into { fields, rows } - no library, Node's zlib only. Built for the audit
 * teams' Excel round trip: an auditee's workbook, a payroll extract, a management letter's findings list.
 *   - the zip is walked from its central directory; only the parts a sheet needs are inflated (workbook, its rels, shared strings,
 *     styles, the first sheet), each capped (MAX_PART) and in total (MAX_TOTAL), so a zip bomb is refused, never expanded
 *   - formulas are never evaluated: a cell's cached value is read as it was saved
 *   - a number with a date format (built-in 14-22, 45-47 or a custom code with d / m / y) becomes YYYY-MM-DD[THH:MM]
 *   - the header row is the first row with a value; a blank header becomes its column letter, a repeated one gets " (2)"
 * o.sheet picks a worksheet by name and o.header (a regex) the header row below a title block.
 * Values come back as strings, like parseCsv, so every audit test treats an imported workbook and a CSV the same.
 */
const zlib = require('node:zlib');
const MAX_PART = 64 * 1024 * 1024, MAX_TOTAL = 128 * 1024 * 1024;
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

function entries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw bad('xlsx: not a readable workbook (no zip directory) - save it again from Excel as .xlsx');
  const n = buf.readUInt16LE(eocd + 10), off = buf.readUInt32LE(eocd + 16), E = new Map();
  let p = off;
  for (let k = 0; k < n; k++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw bad('xlsx: the zip directory is damaged');
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24), nl = buf.readUInt16LE(p + 28), el = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), lho = buf.readUInt32LE(p + 42);
    E.set(buf.slice(p + 46, p + 46 + nl).toString('utf8'), { method, csize, usize, lho });
    p += 46 + nl + el + cl;
  }
  let used = 0;
  const read = (name) => {
    const e = E.get(name); if (!e) return null;
    if (e.usize > MAX_PART) throw bad('xlsx: ' + name + ' is too large to read');
    if (e.lho + 30 > buf.length || buf.readUInt32LE(e.lho) !== 0x04034b50) throw bad('xlsx: a part of the workbook is damaged');
    const start = e.lho + 30 + buf.readUInt16LE(e.lho + 26) + buf.readUInt16LE(e.lho + 28), data = buf.slice(start, start + e.csize);
    let out;
    if (e.method === 0) out = data;
    else if (e.method === 8) { try { out = zlib.inflateRawSync(data, { maxOutputLength: Math.min(MAX_PART, MAX_TOTAL - used) + 1 }); } catch (x) { throw bad('xlsx: ' + name + ' could not be decompressed (damaged or too large)'); } }
    else throw bad('xlsx: compression method ' + e.method + ' is not supported - save it again from Excel');
    used += out.length; if (out.length > MAX_PART || used > MAX_TOTAL) throw bad('xlsx: the workbook expands to more than ' + (MAX_TOTAL >> 20) + ' MB');
    return out.toString('utf8');
  };
  return { read, names: [...E.keys()] };
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const unx = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENT[e.toLowerCase()]));
const texts = (xml) => { let o = ''; const re = /<(?:\w+:)?t(?:\s[^>]*)?>([\s\S]*?)<\/(?:\w+:)?t>|<(?:\w+:)?t\s*\/>/g; let m; while ((m = re.exec(xml))) o += m[1] ? unx(m[1]) : ''; return o; };
const attr = (tag, a) => { const m = new RegExp('\\s' + a + '="([^"]*)"').exec(tag); return m ? unx(m[1]) : null; };
const colIx = (ref) => { const m = /^([A-Z]+)/.exec(ref || ''); if (!m) return -1; let n = 0; for (const ch of m[1]) n = n * 26 + ch.charCodeAt(0) - 64; return n - 1; };
const colName = (i) => { let s = ''; i++; while (i) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; };
const DATE_IDS = new Set([14, 15, 16, 17, 18, 19, 20, 21, 22, 45, 46, 47]);

function serialToIso(v) {
  const ms = Math.round((v - 25569) * 86400000); if (!Number.isFinite(ms)) return String(v);
  const d = new Date(ms).toISOString(); return v % 1 ? d.slice(0, 16) : d.slice(0, 10);
}
function numText(v) { const n = Number(v); return Number.isFinite(n) ? String(+n.toPrecision(15)) : String(v); }

function readXlsx(buf, o = {}) {
  const maxRows = o.maxRows || 50000, maxCols = o.maxCols || 60;
  if (!Buffer.isBuffer(buf) || buf.length < 22) throw bad('xlsx: the file is empty');
  const Z = entries(buf);
  // the first sheet in workbook order (or o.sheet, by name), through the workbook's relationships (falls back to sheet1.xml)
  let sheetPath = 'xl/worksheets/sheet1.xml';
  const wb = Z.read('xl/workbook.xml'), rels = Z.read('xl/_rels/workbook.xml.rels');
  if (o.sheet && !(wb && rels)) throw bad('xlsx: the workbook has no sheet list - save it again from Excel');
  if (wb && rels) {
    const all = [...wb.matchAll(/<(?:\w+:)?sheet\s[^>]*>/g)].map((m) => m[0]);
    let first = all[0];
    if (o.sheet) {
      const want = String(o.sheet).trim().toLowerCase(); first = all.find((t) => unx(attr(t, 'name') || '').trim().toLowerCase() === want);
      if (!first) throw bad('xlsx: no worksheet named "' + String(o.sheet).slice(0, 60) + '" - the workbook has: ' + all.map((t) => unx(attr(t, 'name') || '')).join(', ').slice(0, 300));
    }
    const rid = first && (attr(first, 'r:id') || attr(first, 'id'));
    const rel = rid && new RegExp('<Relationship\\s[^>]*Id="' + rid.replace(/[^\w-]/g, '') + '"[^>]*>').exec(rels);
    const tgt = rel && attr(rel[0], 'Target');
    if (tgt) sheetPath = tgt.startsWith('/') ? tgt.slice(1) : 'xl/' + tgt.replace(/^\.\//, '');
  }
  const sheet = Z.read(sheetPath); if (sheet == null) throw bad('xlsx: the workbook has no worksheet');
  const ss = []; const sx = Z.read('xl/sharedStrings.xml'); if (sx) { const re = /<(?:\w+:)?si>([\s\S]*?)<\/(?:\w+:)?si>|<(?:\w+:)?si\s*\/>/g; let m; while ((m = re.exec(sx))) ss.push(m[1] ? texts(m[1]) : ''); }
  const dateStyle = []; const sty = Z.read('xl/styles.xml');
  if (sty) {
    const custom = {}; let m; const nf = /<(?:\w+:)?numFmt\s[^>]*>/g; while ((m = nf.exec(sty))) custom[attr(m[0], 'numFmtId')] = attr(m[0], 'formatCode') || '';
    const xfs = /<(?:\w+:)?cellXfs[^>]*>([\s\S]*?)<\/(?:\w+:)?cellXfs>/.exec(sty);
    if (xfs) { const xf = /<(?:\w+:)?xf\s[^>]*?\/?>/g; while ((m = xf.exec(xfs[1]))) { const id = Number(attr(m[0], 'numFmtId') || 0), code = custom[String(id)]; dateStyle.push(DATE_IDS.has(id) || (code != null && /[dmy]/i.test(code.replace(/"[^"]*"|\[[^\]]*\]|\\./g, '')) && !/^general$/i.test(code))); } }
  }
  const grid = []; let truncatedCols = false;
  const rowRe = /<(?:\w+:)?row\b[^>]*>([\s\S]*?)<\/(?:\w+:)?row>/g; let rm;
  while ((rm = rowRe.exec(sheet))) {
    const cells = []; const cre = /<(?:\w+:)?c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:\w+:)?c>)/g; let cm, seq = 0;
    while ((cm = cre.exec(rm[1]))) {
      const tag = cm[1], inner = cm[2] || '', ref = attr(tag, 'r'), ix = ref ? colIx(ref) : seq; seq = ix + 1;
      if (ix >= maxCols) { truncatedCols = true; continue; }
      const t = attr(tag, 't'), s = Number(attr(tag, 's') || 0), vm = /<(?:\w+:)?v>([\s\S]*?)<\/(?:\w+:)?v>/.exec(inner), v = vm ? unx(vm[1]) : null;
      let val = '';
      if (t === 's') val = v == null ? '' : (ss[Number(v)] == null ? '' : ss[Number(v)]);
      else if (t === 'inlineStr') val = texts(inner);
      else if (t === 'b') val = v === '1' ? 'TRUE' : v === '0' ? 'FALSE' : '';
      else if (t === 'str' || t === 'e') val = v == null ? '' : v;
      else if (v != null && v !== '') val = dateStyle[s] ? serialToIso(Number(v)) : numText(v);
      cells[ix] = val;
    }
    if (cells.some((c) => c != null && String(c).trim() !== '')) grid.push(cells);
    if (grid.length > maxRows + 1) break;
  }
  if (!grid.length) throw bad('xlsx: the first worksheet is empty');
  // o.header: the header is the first row with a cell matching it (a report with a title block above the table)
  if (o.header) { const hi = grid.findIndex((r) => r.some((c) => c != null && o.header.test(String(c).trim()))); if (hi < 0) throw bad('xlsx: no header row found (looked for ' + String(o.header) + ')'); grid.splice(0, hi); }
  const head = grid[0], width = Math.min(maxCols, Math.max(...grid.map((r) => r.length))), seen = {}, fields = [];
  for (let i = 0; i < width; i++) { let h = String(head[i] == null ? '' : head[i]).trim().slice(0, 60) || colName(i); const k = h.toLowerCase(); if (seen[k]) h = h + ' (' + (++seen[k]) + ')'; else seen[k] = 1; fields.push(h); }
  const rows = grid.slice(1, maxRows + 1).map((r) => { const o2 = {}; fields.forEach((f, i) => { o2[f] = r[i] == null ? '' : String(r[i]); }); return o2; });
  return { fields, rows, truncated: grid.length - 1 > maxRows, truncated_cols: truncatedCols, sheet: sheetPath.split('/').pop() };
}

module.exports = { readXlsx, serialToIso };
