// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * A whole .xlsx workbook, read and patched without a library (Node's zlib only) - for regulator templates that must go back in
 * exactly the format they came in (the Insurance Authority's Solvency and Capital template).
 *   readBook(buf)          every sheet: name, and each cell's cached value, type and formula text (formulas are never evaluated)
 *   patchBook(buf, edits)  writes values into chosen cells and leaves every other byte of every part as it was: styles, formulas,
 *                          validations, comments, defined names, hidden sheets. A cell that holds a formula is never overwritten
 *                          (refused). The workbook is flagged to recalculate when Excel opens it.
 * Limits: zip parts are capped (MAX_PART) and in total (MAX_TOTAL), so a zip bomb is refused, never expanded; zip64 is refused.
 */
const zlib = require('node:zlib');
const MAX_PART = 96 * 1024 * 1024, MAX_TOTAL = 256 * 1024 * 1024;
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

function dir(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw bad('xlsx: not a readable workbook (no zip directory) - save it again from Excel as .xlsx');
  const n = buf.readUInt16LE(eocd + 10), off = buf.readUInt32LE(eocd + 16);
  if (n === 0xffff || off === 0xffffffff) throw bad('xlsx: a zip64 workbook is not supported - save it again from Excel');
  const list = []; let p = off;
  for (let k = 0; k < n; k++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw bad('xlsx: the zip directory is damaged');
    const e = { vmade: buf.readUInt16LE(p + 4), vneed: buf.readUInt16LE(p + 6), flags: buf.readUInt16LE(p + 8), method: buf.readUInt16LE(p + 10), time: buf.readUInt16LE(p + 12), date: buf.readUInt16LE(p + 14),
      crc: buf.readUInt32LE(p + 16), csize: buf.readUInt32LE(p + 20), usize: buf.readUInt32LE(p + 24), iattr: buf.readUInt16LE(p + 36), eattr: buf.readUInt32LE(p + 38), lho: buf.readUInt32LE(p + 42) };
    const nl = buf.readUInt16LE(p + 28), el = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32);
    e.name = buf.slice(p + 46, p + 46 + nl).toString('utf8');
    if (e.usize > MAX_PART) throw bad('xlsx: a part of the workbook is too large (' + e.name + ')');
    if (e.method !== 0 && e.method !== 8) throw bad('xlsx: unsupported compression in ' + e.name);
    if (e.lho + 30 > buf.length || buf.readUInt32LE(e.lho) !== 0x04034b50) throw bad('xlsx: the zip is damaged (' + e.name + ')');
    e.data = e.lho + 30 + buf.readUInt16LE(e.lho + 26) + buf.readUInt16LE(e.lho + 28);
    if (e.data + e.csize > buf.length) throw bad('xlsx: the zip is truncated (' + e.name + ')');
    list.push(e); p += 46 + nl + el + cl;
  }
  if (list.reduce((s, e) => s + e.usize, 0) > MAX_TOTAL) throw bad('xlsx: the workbook expands to more than ' + (MAX_TOTAL >> 20) + ' MB');
  return list;
}
function inflate(buf, e) {
  const raw = buf.slice(e.data, e.data + e.csize);
  const out = e.method === 0 ? raw : zlib.inflateRawSync(raw, { maxOutputLength: MAX_PART });
  if (out.length !== e.usize) throw bad('xlsx: a part did not expand to its stated size (' + e.name + ')');
  return out;
}
const xmlDec = (s) => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (m, c) => c[0] === '#' ? String.fromCodePoint(c[1] === 'x' || c[1] === 'X' ? parseInt(c.slice(2), 16) : +c.slice(1)) : { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[c.toLowerCase()]);
const xmlEnc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
const attr = (tag, a) => { const m = new RegExp('\\s' + a + '="([^"]*)"').exec(tag); return m ? xmlDec(m[1]) : null; };
function textOf(si) { let t = ''; const re = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>|<t\s*\/>/g; let m; const s = si.replace(/<rPh\b[\s\S]*?<\/rPh>/g, ''); while ((m = re.exec(s))) t += xmlDec(m[1] || ''); return t; }

function parts(buf) {
  const list = dir(buf), by = new Map(list.map((e) => [e.name, e]));
  const get = (name) => { const e = by.get(name); return e ? inflate(buf, e).toString('utf8') : null; };
  const wb = get('xl/workbook.xml'); if (!wb) throw bad('xlsx: this is not an Excel workbook (no xl/workbook.xml)');
  const rels = get('xl/_rels/workbook.xml.rels') || '', R = {};
  for (const m of rels.matchAll(/<Relationship\b[^>]*>/g)) { const id = attr(m[0], 'Id'), t = attr(m[0], 'Target'); if (id && t) R[id] = t.startsWith('/') ? t.slice(1) : 'xl/' + t.replace(/^\.\//, ''); }
  const sheets = [];
  for (const m of wb.matchAll(/<sheet\b[^>]*\/?>/g)) { const rid = attr(m[0], 'r:id') || attr(m[0], 'id'); sheets.push({ name: attr(m[0], 'name'), state: attr(m[0], 'state') || 'visible', path: R[rid] }); }
  return { list, by, get, wb, sheets };
}
const colNum = (c) => { let n = 0; for (const ch of c) n = n * 26 + ch.charCodeAt(0) - 64; return n; };
const splitRef = (ref) => { const m = /^([A-Z]{1,3})(\d{1,7})$/.exec(ref); if (!m) throw bad('bad cell reference ' + ref); return { col: m[1], row: +m[2], c: colNum(m[1]) }; };

// { sheets: [{ name, state, cells: Map(ref -> { v, t, f }) }] } - v is the cached value: number, string, boolean or null
function readBook(buf, o = {}) {
  const P = parts(buf), sst = [];
  const ss = P.get('xl/sharedStrings.xml'); if (ss) for (const m of ss.matchAll(/<si\b[^>]*>([\s\S]*?)<\/si>|<si\s*\/>/g)) sst.push(textOf(m[1] || ''));
  const want = o.sheets ? new Set(o.sheets) : null, out = [];
  for (const s of P.sheets) {
    const sheet = { name: s.name, state: s.state, cells: new Map() };
    out.push(sheet);
    if ((want && !want.has(s.name)) || !s.path) continue;
    const x = P.get(s.path); if (!x) continue;
    for (const m of x.matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const a = m[1], inner = m[2] || '', ref = attr(a, 'r'); if (!ref) continue;
      const t = attr(a, 't') || 'n', fm = /<f\b[^>]*?(?:\/>|>([\s\S]*?)<\/f>)/.exec(inner), vm = /<v>([\s\S]*?)<\/v>/.exec(inner);
      let v = null;
      if (t === 's' && vm) v = sst[+vm[1]] == null ? null : sst[+vm[1]];
      else if (t === 'inlineStr') v = textOf(inner);
      else if (t === 'b' && vm) v = vm[1] === '1';
      else if ((t === 'str' || t === 'e') && vm) v = xmlDec(vm[1]);
      else if (vm) { const n = Number(vm[1]); v = Number.isFinite(n) ? n : xmlDec(vm[1]); }
      const f = fm ? (fm[1] != null ? xmlDec(fm[1]) : (/\bt="shared"/.test(fm[0]) ? '=shared:' + (attr(fm[0], 'si') || '') : '')) : null;
      if (v === null && f === null) continue;
      sheet.cells.set(ref, { v, t, f });
    }
  }
  return { sheets: out, sheet: (n) => out.find((s) => s.name === n) || null };
}

// ---- writing
let CRC = null;
function crc32(b) { if (!CRC) { CRC = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC[n] = c; } } let c = -1; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ -1) >>> 0; }
function cellXml(ref, style, val) {
  const s = style ? ' s="' + style + '"' : '';
  if (val === null || val === undefined || val === '') return '<c r="' + ref + '"' + s + '/>';
  if (typeof val === 'number') { if (!Number.isFinite(val)) throw bad('not a finite number for ' + ref); return '<c r="' + ref + '"' + s + '><v>' + String(val) + '</v></c>'; }
  if (typeof val === 'boolean') return '<c r="' + ref + '"' + s + ' t="b"><v>' + (val ? 1 : 0) + '</v></c>';
  return '<c r="' + ref + '"' + s + ' t="inlineStr"><is><t xml:space="preserve">' + xmlEnc(val) + '</t></is></c>';
}
function patchSheet(x, edits, sheetName) {
  let out = x;
  for (const ref of Object.keys(edits)) {
    const { row, c } = splitRef(ref), val = edits[ref];
    const cre = new RegExp('<c\\b(?=[^>]*\\sr="' + ref + '")([^>]*?)(?:\\/>|>([\\s\\S]*?)<\\/c>)');
    const cm = cre.exec(out);
    if (cm) {
      if (/<f\b/.test(cm[2] || '')) throw bad(sheetName + '!' + ref + ' holds a formula - the template\'s formulas are never overwritten');
      out = out.slice(0, cm.index) + cellXml(ref, attr(cm[1], 's'), val) + out.slice(cm.index + cm[0].length); continue;
    }
    const rre = new RegExp('<row\\b(?=[^>]*\\sr="' + row + '")[^>]*?(?:\\/>|>([\\s\\S]*?)<\\/row>)'), rm = rre.exec(out);
    const nc = cellXml(ref, null, val);
    if (rm) {
      if (rm[0].endsWith('/>')) { out = out.slice(0, rm.index) + rm[0].slice(0, -2) + '>' + nc + '</row>' + out.slice(rm.index + rm[0].length); continue; }
      const inner = rm[1] || '', start = rm.index + rm[0].indexOf('>') + 1; let pos = inner.length;
      for (const m of inner.matchAll(/<c\b[^>]*\sr="([A-Z]+)\d+"/g)) if (colNum(m[1]) > c) { pos = m.index; break; }
      out = out.slice(0, start + pos) + nc + out.slice(start + pos); continue;
    }
    const sd = /<sheetData\b[^>]*?(\/>|>)/.exec(out); if (!sd) throw bad(sheetName + ': no sheet data');
    if (sd[1] === '/>') { out = out.slice(0, sd.index) + '<sheetData><row r="' + row + '">' + nc + '</row></sheetData>' + out.slice(sd.index + sd[0].length); continue; }
    const body0 = sd.index + sd[0].length, end = out.indexOf('</sheetData>', body0); let pos = end;
    for (const m of out.slice(body0, end).matchAll(/<row\b[^>]*\sr="(\d+)"/g)) if (+m[1] > row) { pos = body0 + m.index; break; }
    out = out.slice(0, pos) + '<row r="' + row + '">' + nc + '</row>' + out.slice(pos);
  }
  return out;
}
// edits: { 'Sheet name': { A1: 'text' | 123 | true | null } }
function patchBook(buf, edits) {
  const P = parts(buf), repl = new Map();
  for (const name of Object.keys(edits || {})) {
    const s = P.sheets.find((x) => x.name === name); if (!s || !s.path) throw bad('the workbook has no sheet "' + name + '"');
    repl.set(s.path, Buffer.from(patchSheet(P.get(s.path), edits[name], name), 'utf8'));
  }
  // recalculate on open, so every formula reflects the values written
  let wb = P.wb;
  if (/<calcPr\b/.test(wb)) wb = wb.replace(/<calcPr\b([^>]*?)(\/?)>/, (m, a, sl) => '<calcPr' + a.replace(/\sfullCalcOnLoad="[^"]*"/, '') + ' fullCalcOnLoad="1"' + sl + '>');
  else wb = wb.replace('</workbook>', '<calcPr fullCalcOnLoad="1"/></workbook>');
  repl.set('xl/workbook.xml', Buffer.from(wb, 'utf8'));
  const chunks = [], central = []; let off = 0;
  for (const e of P.list) {
    let data, crc = e.crc, usize = e.usize, method = e.method;
    if (repl.has(e.name)) { const raw = repl.get(e.name); crc = crc32(raw); usize = raw.length; data = zlib.deflateRawSync(raw, { level: 6 }); method = 8; }
    else data = buf.slice(e.data, e.data + e.csize);
    const name = Buffer.from(e.name, 'utf8'), flags = (e.flags & ~0x0008) | 0x0800, lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(e.vneed, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt16LE(method, 8); lh.writeUInt16LE(e.time, 10); lh.writeUInt16LE(e.date, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(usize, 22); lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(e.vmade, 4); ch.writeUInt16LE(e.vneed, 6); ch.writeUInt16LE(flags, 8); ch.writeUInt16LE(method, 10); ch.writeUInt16LE(e.time, 12); ch.writeUInt16LE(e.date, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(usize, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32); ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(e.iattr, 36); ch.writeUInt32LE(e.eattr, 38); ch.writeUInt32LE(off, 42);
    chunks.push(lh, name, data); central.push(ch, name); off += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(P.list.length, 8); end.writeUInt16LE(P.list.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat(chunks.concat([cd, end]));
}

module.exports = { readBook, patchBook, splitRef, colNum, _t: { crc32, xmlEnc } };
