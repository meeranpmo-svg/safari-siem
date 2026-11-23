// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * One table out of an uploaded spreadsheet (.xlsx or .csv), its columns found by their headings rather than by position:
 *   readTable(buf, ext, HEAD, { need, max, cut })
 *     HEAD   { key: /heading regex/ } - the sheet whose first 15 rows match most headings is used, the heading row is the first of
 *            those rows that matches a `need` key; cells under it become { key: text } rows (empty rows dropped)
 *     need   keys of which at least one must be a column (else 400 naming them)
 *     cut    { key: max length } (default 300); a leading "'" that Excel export put before = + - @ is removed
 * Text only: numbers and dates come back as the text Excel stored. Nothing is evaluated.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
function csvGrid(buf) {
  const t = buf.toString('utf8').replace(/^﻿/, ''), lines = []; let row = [], cur = '', q = false;
  for (let i = 0; i < t.length; i++) { const ch = t[i];
    if (q) { if (ch === '"' && t[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch; }
    else if (ch === '"') q = true; else if (ch === ',') { row.push(cur); cur = ''; } else if (ch === '\n' || ch === '\r') { if (ch === '\r' && t[i + 1] === '\n') i++; row.push(cur); lines.push(row); row = []; cur = ''; } else cur += ch; }
  if (cur || row.length) { row.push(cur); lines.push(row); }
  return [lines.filter((r) => !/^#/.test(r[0] || '') && r.some((x) => String(x).trim()))];
}
function xlsxGrids(buf) {
  const XB = require('./xlsx-book'), B = XB.readBook(buf);
  return B.sheets.map((sh) => { const R = new Map();
    for (const [ref, c] of sh.cells) { const m = /^([A-Z]+)(\d+)$/.exec(ref); if (!m) continue; if (!R.has(+m[2])) R.set(+m[2], []); R.get(+m[2])[XB.colNum(m[1]) - 1] = c && c.v != null ? String(c.v).trim() : ''; }
    return [...R.keys()].sort((a, b) => a - b).map((r) => Array.from(R.get(r), (x) => x || '')); });
}
function readTable(buf, ext, HEAD, o = {}) {
  const need = o.need || Object.keys(HEAD), max = o.max || 5000, cut = o.cut || {};
  const grids = ext === 'csv' ? csvGrid(buf) : xlsxGrids(buf);
  const hits = (r) => r.filter((x) => Object.values(HEAD).some((re) => re.test(String(x).trim()))).length;
  let grid = grids[0] || [], best = -1; for (const g of grids) { const sc = g.slice(0, 15).reduce((m, r) => Math.max(m, hits(r)), 0); if (sc > best) { best = sc; grid = g; } }
  let h = -1; for (let i = 0; i < Math.min(15, grid.length); i++) { const r = grid[i].map((x) => String(x).trim()); if (need.some((k) => r.some((x) => HEAD[k].test(x)))) { h = i; break; } }
  if (h < 0) throw httpErr(400, 'no heading row found - the file needs a column named like ' + need.map((k) => HEAD[k].source.replace(/[\^$()?\\]/g, '').split('|')[0]).join(' or '));
  const hdr = grid[h].map((x) => String(x).trim()), col = {}; for (const k of Object.keys(HEAD)) { const i = hdr.findIndex((x) => HEAD[k].test(x)); if (i >= 0) col[k] = i; }
  const rows = []; for (const r of grid.slice(h + 1)) { const g = {}; for (const k of Object.keys(col)) g[k] = String(r[col[k]] == null ? '' : r[col[k]]).replace(/^'(?=[=+\-@])/, '').trim().slice(0, cut[k] || 300);
    if (need.some((k) => g[k])) rows.push(g); if (rows.length >= max) break; }
  return { rows, columns: Object.keys(col) };
}
module.exports = { readTable };
