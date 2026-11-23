// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Audit analytics - the pure functions behind engine/audit-analytics.js (no I/O, no clock unless passed, no eval). Every test takes
 * rows (plain objects) and declared parameters and returns { summary, exceptions[], chart? }: exceptions carry the row number (#),
 * the values that made them exceptions and why, so an auditor can re-perform them.
 *   csv / types / profile                    parse (RFC 4180 quotes), infer number / date / text per column, field statistics
 *   duplicates · fuzzy · gaps                exact duplicate keys, near-duplicate text (sorted neighbourhood + Levenshtein), missing
 *                                            and repeated numbers in a sequence
 *   benford                                  first-digit test: chi-square (8 df) and Nigrini's mean absolute deviation conformity,
 *                                            z per digit; under 100 values it says the test is not reliable
 *   stratify · age · summarize · outliers    bands, ageing buckets, group totals, robust z (0.6745 (x - median) / MAD >= 3.5)
 *   join · compare · filter                  matched / unmatched on a key; period-to-period (new, gone, changed, by how much);
 *                                            structured conditions (field, op, value)
 *   sampleSize · draw · mus                  attribute sample size (binomial), seeded record sample, monetary-unit sample
 *   suggest                                  which tests fit a dataset's columns (the "what to run" assistant)
 * Statistics are indicators for an auditor to follow up, not proof of wrongdoing.
 */
const LIMIT_EX = 500;

function parseCsv(text, o = {}) {
  const maxRows = o.maxRows || 50000, maxCols = o.maxCols || 60, t = String(text || '').replace(/^﻿/, '');
  const rows = []; let row = [], cell = '', q = false, i = 0;
  const delim = (() => { const first = t.slice(0, t.indexOf('\n') >= 0 ? t.indexOf('\n') : t.length); const c = { ',': 0, ';': 0, '\t': 0, '|': 0 }; for (const ch of first) if (ch in c) c[ch]++; return Object.entries(c).sort((a, b) => b[1] - a[1])[0][1] ? Object.entries(c).sort((a, b) => b[1] - a[1])[0][0] : ','; })();
  for (; i < t.length; i++) {
    const ch = t[i];
    if (q) { if (ch === '"') { if (t[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; continue; }
    if (ch === '"' && cell === '') { q = true; continue; }
    if (ch === delim) { row.push(cell); cell = ''; continue; }
    if (ch === '\r') continue;
    if (ch === '\n') { row.push(cell); cell = ''; if (row.some((x) => x !== '')) rows.push(row); row = []; if (rows.length > maxRows) break; continue; }
    cell += ch;
  }
  if (q) throw Object.assign(new Error('csv: a quoted value is not closed'), { status: 400 });
  if (cell !== '' || row.length) { row.push(cell); if (row.some((x) => x !== '')) rows.push(row); }
  if (rows.length < 2) throw Object.assign(new Error('csv: a header row and at least one data row are needed'), { status: 400 });
  if (rows.length - 1 > maxRows) throw Object.assign(new Error('csv: more than ' + maxRows + ' rows - split the file'), { status: 400 });
  const seen = {}, head = rows[0].map((h, k) => { let n = String(h).trim().replace(/[\u0000-\u001f]/g, '').slice(0, 60) || 'column_' + (k + 1); if (seen[n]) n = n + '_' + (++seen[n]); else seen[n] = 1; return n; });
  if (head.length > maxCols) throw Object.assign(new Error('csv: more than ' + maxCols + ' columns'), { status: 400 });
  return { fields: head, delimiter: delim, rows: rows.slice(1).map((r) => Object.fromEntries(head.map((h, k) => [h, r[k] === undefined ? '' : String(r[k]).slice(0, 2000)]))) };
}

const NUMRE = /^\s*[-+]?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?\s*$/;
const num = (v) => { if (typeof v === 'number') return Number.isFinite(v) ? v : null; if (v == null) return null; const s = String(v).trim(); if (!NUMRE.test(s)) return null; return Number(s.replace(/,/g, '')); };
const DRE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$|^\d{1,2}\/\d{1,2}\/\d{4}$/;
const date = (v) => { if (v == null || v === '') return null; const s = String(v).trim(); if (!DRE.test(s)) return null;
  if (s.includes('/')) { const [d, m, y] = s.split('/').map(Number); const t = Date.UTC(y, m - 1, d); return Number.isFinite(t) && m >= 1 && m <= 12 && d >= 1 && d <= 31 ? t : null; }
  const t = Date.parse(s.length === 10 ? s + 'T00:00:00Z' : s); return Number.isFinite(t) ? t : null; };
const blank = (v) => v == null || String(v).trim() === '';
const norm = (v) => String(v == null ? '' : v).toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/\b(ltd|llc|co|company|est|the|inc|wll)\b/g, '').replace(/[^a-z0-9؀-ۿ]+/g, '');

function types(rows, fields) {
  const out = {};
  for (const f of fields) {
    let n = 0, d = 0, t = 0;
    for (const r of rows) { const v = r[f]; if (blank(v)) continue; t++; if (num(v) !== null) n++; else if (date(v) !== null) d++; if (t >= 2000) break; }
    out[f] = !t ? 'text' : n / t >= 0.95 ? 'number' : d / t >= 0.95 ? 'date' : 'text';
  }
  return out;
}
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const r2 = (x) => x == null || !Number.isFinite(x) ? null : Math.round(x * 100) / 100;

function profile(rows, fields, ty) {
  ty = ty || types(rows, fields);
  return fields.map((f) => {
    const vals = rows.map((r) => r[f]), filled = vals.filter((v) => !blank(v)), distinct = new Map();
    for (const v of filled) { const k = String(v); distinct.set(k, (distinct.get(k) || 0) + 1); }
    const p = { field: f, type: ty[f], count: rows.length, blanks: rows.length - filled.length, distinct: distinct.size, top: [...distinct.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([v, c]) => ({ value: String(v).slice(0, 80), count: c })) };
    if (ty[f] === 'number') { const x = filled.map(num).filter((v) => v !== null); const sum = x.reduce((a, b) => a + b, 0), mean = x.length ? sum / x.length : null;
      Object.assign(p, { min: x.length ? Math.min(...x) : null, max: x.length ? Math.max(...x) : null, sum: r2(sum), mean: r2(mean), median: median(x), stdev: x.length > 1 ? r2(Math.sqrt(x.reduce((a, b) => a + (b - mean) ** 2, 0) / (x.length - 1))) : null, negatives: x.filter((v) => v < 0).length, zeros: x.filter((v) => v === 0).length }); }
    if (ty[f] === 'date') { const x = filled.map(date).filter((v) => v !== null); Object.assign(p, { min: x.length ? new Date(Math.min(...x)).toISOString().slice(0, 10) : null, max: x.length ? new Date(Math.max(...x)).toISOString().slice(0, 10) : null }); }
    return p;
  });
}

const cap = (ex) => ({ exceptions: ex.slice(0, LIMIT_EX), exceptions_total: ex.length, truncated: ex.length > LIMIT_EX });
const pick = (r, fs) => Object.fromEntries(fs.map((f) => [f, r[f]]));
const need = (rows, f) => { if (!rows.length) return; if (!(f in rows[0])) throw Object.assign(new Error('field: ' + f + ' is not a column of this dataset'), { status: 400 }); };

function duplicates(rows, p) {
  for (const f of p.keys) need(rows, f);
  const m = new Map(); rows.forEach((r, i) => { if (p.keys.every((k) => blank(r[k]))) return; const k = p.keys.map((f) => String(r[f]).trim().toLowerCase()).join('\u0001'); (m.get(k) || m.set(k, []).get(k)).push(i); });
  const groups = [...m.values()].filter((g) => g.length > 1), ex = [];
  groups.forEach((g, gi) => g.forEach((i) => ex.push({ '#': i + 1, group: gi + 1, values: pick(rows[i], p.keys), why: 'same ' + p.keys.join(' + ') + ' as ' + (g.length - 1) + ' other row(s)' })));
  return Object.assign({ summary: groups.length + ' duplicate group(s), ' + ex.length + ' row(s), on ' + p.keys.join(' + '), groups: groups.length }, cap(ex));
}

function lev(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) { const cur = [i]; let lo = i; for (let j = 1; j <= b.length; j++) { cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); if (cur[j] < lo) lo = cur[j]; } if (lo > max) return max + 1; prev = cur; }
  return prev[b.length];
}
function fuzzy(rows, p) {
  need(rows, p.field); const th = p.threshold || 0.85, win = 12;
  const items = rows.map((r, i) => ({ i, k: norm(r[p.field]) })).filter((x) => x.k.length >= 3).sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : 0));
  const rev = items.map((x) => ({ i: x.i, k: x.k, r: x.k.split('').reverse().join('') })).sort((a, b) => (a.r < b.r ? -1 : a.r > b.r ? 1 : 0));
  const pairs = new Map();
  for (const list of [items, rev]) for (let a = 0; a < list.length; a++) for (let b = a + 1; b < Math.min(list.length, a + win); b++) {
    const x = list[a], y = list[b]; if (x.k === y.k) continue; const L = Math.max(x.k.length, y.k.length), d = lev(x.k, y.k, Math.floor(L * (1 - th)));
    const sim = 1 - d / L; if (sim >= th) { const key = Math.min(x.i, y.i) + ':' + Math.max(x.i, y.i); if (!pairs.has(key)) pairs.set(key, { a: Math.min(x.i, y.i), b: Math.max(x.i, y.i), sim }); }
  }
  const ex = [...pairs.values()].sort((u, v) => v.sim - u.sim).map((q) => ({ '#': q.a + 1, with: q.b + 1, similarity: Math.round(q.sim * 100), values: { [p.field]: rows[q.a][p.field], ['row ' + (q.b + 1)]: rows[q.b][p.field] }, why: Math.round(q.sim * 100) + ' % similar after normalising (case, accents, punctuation, company suffixes) - not an exact duplicate' }));
  return Object.assign({ summary: ex.length + ' near-duplicate pair(s) on ' + p.field + ' at >= ' + Math.round(th * 100) + ' % similarity' }, cap(ex));
}

function gaps(rows, p) {
  need(rows, p.field); const seen = new Map(); rows.forEach((r, i) => { const v = num(r[p.field]); if (v === null || !Number.isInteger(v)) return; (seen.get(v) || seen.set(v, []).get(v)).push(i); });
  const ks = [...seen.keys()].sort((a, b) => a - b), ex = [], ranges = [];
  if (!ks.length) return { summary: 'no whole numbers in ' + p.field, exceptions: [], exceptions_total: 0 };
  for (let j = 1; j < ks.length; j++) if (ks[j] - ks[j - 1] > 1) { ranges.push([ks[j - 1] + 1, ks[j] - 1]); ex.push({ '#': null, values: { missing_from: ks[j - 1] + 1, missing_to: ks[j] - 1, count: ks[j] - ks[j - 1] - 1 }, why: 'missing in the sequence' }); }
  for (const [v, ix] of seen) if (ix.length > 1) for (const i of ix) ex.push({ '#': i + 1, values: { [p.field]: v }, why: 'number used ' + ix.length + ' times' });
  const missing = ranges.reduce((t, r) => t + r[1] - r[0] + 1, 0);
  return Object.assign({ summary: 'sequence ' + ks[0] + '-' + ks[ks.length - 1] + ': ' + missing + ' missing number(s) in ' + ranges.length + ' gap(s), ' + [...seen.values()].filter((x) => x.length > 1).length + ' repeated', missing, gaps: ranges.length }, cap(ex));
}

function benford(rows, p) {
  need(rows, p.field); const c = Array(10).fill(0), idx = Array.from({ length: 10 }, () => []);
  rows.forEach((r, i) => { const v = num(r[p.field]); if (v === null || Math.abs(v) < 10) return; const d = Number(String(Math.floor(Math.abs(v))).replace(/^0+/, '')[0]); c[d]++; idx[d].push(i); });
  const n = c.slice(1).reduce((a, b) => a + b, 0), digits = [];
  let chi = 0, mad = 0;
  for (let d = 1; d <= 9; d++) { const e = Math.log10(1 + 1 / d), o = n ? c[d] / n : 0; chi += n ? (c[d] - n * e) ** 2 / (n * e) : 0; mad += Math.abs(o - e);
    const z = n ? (Math.abs(o - e) - 1 / (2 * n)) / Math.sqrt(e * (1 - e) / n) : 0; digits.push({ digit: d, count: c[d], actual: Math.round(o * 10000) / 100, expected: Math.round(e * 10000) / 100, z: r2(Math.max(0, z)), flag: z > 1.96 && o > e }); }
  mad /= 9;
  // Nigrini's MAD thresholds are for large populations (1,000+); below that the MAD is noisy and the chi-square decides
  const conf = n >= 1000 ? (mad <= 0.006 ? 'close conformity' : mad <= 0.012 ? 'acceptable conformity' : mad <= 0.015 ? 'marginally acceptable' : 'nonconformity') : (chi > 15.51 ? 'nonconformity' : 'conformity');
  const ex = []; for (const d of digits.filter((x) => x.flag)) for (const i of idx[d.digit]) ex.push({ '#': i + 1, values: { [p.field]: rows[i][p.field] }, why: 'first digit ' + d.digit + ' is over-represented (' + d.actual + ' % against ' + d.expected + ' % expected, z ' + d.z + ')' });
  ex.sort((a, b) => Math.abs(num(b.values[p.field])) - Math.abs(num(a.values[p.field])));
  return Object.assign({ summary: n < 100 ? 'only ' + n + ' value(s) of 10 or more - Benford\'s law needs at least 100 to be reliable; shown for information' : (n >= 1000 ? 'MAD ' + mad.toFixed(4) + ' - ' + conf + ' (Nigrini); chi-square ' + chi.toFixed(1) : conf + ' by chi-square ' + chi.toFixed(1) + (chi > 15.51 ? ' above' : ' within') + ' the 5 % critical value 15.51 (MAD ' + mad.toFixed(4) + ' shown for information - its thresholds need 1,000+ values)'),
    n, mad: Math.round(mad * 10000) / 10000, conformity: conf, chi_square: r2(chi), reliable: n >= 100, chart: { kind: 'benford', digits } }, cap(ex));
}

function stratify(rows, p) {
  need(rows, p.field); const x = rows.map((r, i) => ({ i, v: num(r[p.field]) })).filter((q) => q.v !== null);
  if (!x.length) return { summary: 'no numbers in ' + p.field, exceptions: [], exceptions_total: 0, chart: { kind: 'bars', items: [] } };
  let edges = p.bands && p.bands.length ? p.bands.slice().sort((a, b) => a - b) : null;
  if (!edges) { const lo = Math.min(...x.map((q) => q.v)), hi = Math.max(...x.map((q) => q.v)), k = p.count || 5, w = (hi - lo) / k || 1; edges = Array.from({ length: k - 1 }, (_, j) => r2(lo + w * (j + 1))); }
  const bands = Array.from({ length: edges.length + 1 }, (_, j) => ({ label: j === 0 ? '< ' + edges[0] : j === edges.length ? '>= ' + edges[j - 1] : edges[j - 1] + ' - ' + edges[j], count: 0, sum: 0 }));
  for (const q of x) { let j = 0; while (j < edges.length && q.v >= edges[j]) j++; bands[j].count++; bands[j].sum += q.v; }
  const tot = x.reduce((a, q) => a + q.v, 0);
  for (const b of bands) { b.sum = r2(b.sum); b.pct_count = Math.round(b.count / x.length * 1000) / 10; b.pct_value = tot ? Math.round(b.sum / tot * 1000) / 10 : 0; }
  return { summary: x.length + ' value(s) in ' + bands.length + ' band(s); the top band holds ' + bands[bands.length - 1].pct_value + ' % of the value', bands, exceptions: [], exceptions_total: 0, chart: { kind: 'bars', items: bands.map((b) => ({ label: b.label, value: b.count, sub: b.sum })) } };
}

function age(rows, p, now) {
  need(rows, p.field); const asOf = p.as_of ? date(p.as_of) : now, B = (p.buckets && p.buckets.length ? p.buckets : [30, 60, 90, 180, 365]).slice().sort((a, b) => a - b);
  const bands = B.map((d, j) => ({ label: (j ? B[j - 1] + 1 : 0) + '-' + d + ' days', count: 0, sum: 0 })).concat([{ label: '> ' + B[B.length - 1] + ' days', count: 0, sum: 0 }, { label: 'future dated', count: 0, sum: 0 }]);
  const ex = [];
  rows.forEach((r, i) => { const t = date(r[p.field]); if (t === null) return; const d = Math.floor((asOf - t) / 86400000), amt = p.amount ? num(r[p.amount]) || 0 : 0;
    let j = d < 0 ? bands.length - 1 : B.findIndex((x) => d <= x); if (j < 0) j = bands.length - 2; bands[j].count++; bands[j].sum += amt;
    if (d < 0 || d > B[B.length - 1]) ex.push({ '#': i + 1, values: Object.assign({ [p.field]: r[p.field], days: d }, p.amount ? { [p.amount]: r[p.amount] } : {}), why: d < 0 ? 'dated after ' + new Date(asOf).toISOString().slice(0, 10) : 'older than ' + B[B.length - 1] + ' days' }); });
  for (const b of bands) b.sum = r2(b.sum);
  return Object.assign({ summary: 'aged at ' + new Date(asOf).toISOString().slice(0, 10) + ': ' + bands.map((b) => b.label + ' ' + b.count).join(', '), bands, chart: { kind: 'bars', items: bands.map((b) => ({ label: b.label, value: b.count, sub: b.sum })) } }, cap(ex));
}

function summarize(rows, p) {
  need(rows, p.by); if (p.amount) need(rows, p.amount);
  const m = new Map(); for (const r of rows) { const k = blank(r[p.by]) ? '(blank)' : String(r[p.by]).trim(); const g = m.get(k) || m.set(k, { key: k, count: 0, sum: 0 }).get(k); g.count++; if (p.amount) g.sum += num(r[p.amount]) || 0; }
  const groups = [...m.values()].map((g) => Object.assign(g, { sum: r2(g.sum), avg: p.amount ? r2(g.sum / g.count) : null })).sort((a, b) => (p.amount ? b.sum - a.sum : b.count - a.count));
  return { summary: groups.length + ' group(s) by ' + p.by + (groups[0] ? '; largest ' + groups[0].key + ' (' + (p.amount ? groups[0].sum : groups[0].count) + ')' : ''), groups: groups.slice(0, 200), groups_total: groups.length, exceptions: [], exceptions_total: 0,
    chart: { kind: 'bars', items: groups.slice(0, 15).map((g) => ({ label: g.key, value: p.amount ? g.sum : g.count })) } };
}

function outliers(rows, p) {
  need(rows, p.field); if (p.by) need(rows, p.by); const th = p.z || 3.5, G = new Map();
  rows.forEach((r, i) => { const v = num(r[p.field]); if (v === null) return; const k = p.by ? String(r[p.by] || '(blank)') : '*'; (G.get(k) || G.set(k, []).get(k)).push({ i, v }); });
  const ex = []; let tested = 0;
  for (const [k, list] of G) { if (list.length < 8) continue; tested++; const md = median(list.map((q) => q.v)), mad = median(list.map((q) => Math.abs(q.v - md)));
    if (!mad) continue; for (const q of list) { const z = 0.6745 * (q.v - md) / mad; if (Math.abs(z) >= th) ex.push({ '#': q.i + 1, z: r2(z), values: Object.assign({ [p.field]: rows[q.i][p.field] }, p.by ? { [p.by]: k } : {}), why: 'robust z ' + r2(z) + ' against the median ' + r2(md) + (p.by ? ' of ' + k : '') }); } }
  ex.sort((a, b) => Math.abs(b.z) - Math.abs(a.z));
  return Object.assign({ summary: ex.length + ' outlier(s) at |robust z| >= ' + th + (p.by ? ' within ' + tested + ' group(s) by ' + p.by : '') + (tested ? '' : ' - no group has the 8 values needed') }, cap(ex));
}

function join(rows, p, other) {
  need(rows, p.key); need(other, p.other_key);
  const k = (v) => String(v == null ? '' : v).trim().toLowerCase(), B = new Map(); other.forEach((r, i) => { if (!blank(r[p.other_key])) B.set(k(r[p.other_key]), i); });
  const A = new Set(), ex = []; let matched = 0;
  rows.forEach((r, i) => { if (blank(r[p.key])) return; A.add(k(r[p.key])); if (B.has(k(r[p.key]))) matched++; else if (p.mode !== 'unmatched_other') ex.push({ '#': i + 1, side: 'this', values: { [p.key]: r[p.key] }, why: 'not found in the other dataset' }); });
  if (p.mode !== 'unmatched_this') other.forEach((r, i) => { if (!blank(r[p.other_key]) && !A.has(k(r[p.other_key]))) ex.push({ '#': i + 1, side: 'other', values: { [p.other_key]: r[p.other_key] }, why: 'in the other dataset only' }); });
  return Object.assign({ summary: matched + ' matched; ' + ex.filter((e) => e.side === 'this').length + ' only in this dataset, ' + ex.filter((e) => e.side === 'other').length + ' only in the other', matched }, cap(ex));
}

/* period-to-period comparison (this period = rows, the previous period = other), keyed on one field - the payroll / vendor master /
   claims-list test: who is new, who has gone, what changed and by how much. Each exception is scored so the riskiest come first:
   a changed bank / account / IBAN field is the classic red flag (a salary redirected), worse together with a pay rise; an amount
   change beyond pct %; a key repeated within one period is reported on its own (the comparison cannot be trusted for it). */
const PAYEE = /iban|bank|account|acct|beneficiary|swift|payee/i;
function compare(rows, p, other) {
  const okey = p.other_key || p.key; need(rows, p.key); need(other, okey);
  const k = (v) => String(v == null ? '' : v).trim().toLowerCase(), A = new Map(), B = new Map(), ex = [];
  const index = (list, key, M, side) => list.forEach((r, i) => { if (blank(r[key])) return; const x = k(r[key]); if (M.has(x)) { M.get(x).dup++; return; } M.set(x, { r, i, dup: 1 }); });
  index(rows, p.key, A, 'this'); index(other, okey, B, 'other');
  const common = rows.length && other.length ? Object.keys(rows[0]).filter((f) => f !== p.key && f in other[0]) : [];
  const watch = p.watch && p.watch.length ? p.watch : common; for (const f of watch) { need(rows, f); need(other, f); }
  if (p.amount) { need(rows, p.amount); need(other, p.amount); }
  const pct = p.pct == null ? 10 : p.pct, same = (a, b) => { const na = num(a), nb = num(b); return na !== null && nb !== null ? na === nb : String(a == null ? '' : a).trim() === String(b == null ? '' : b).trim(); };
  let changed = 0, added = 0, gone = 0, unchanged = 0, dups = 0, before = 0, after = 0;
  for (const [x, a] of A) {
    if (a.dup > 1) { dups++; ex.push({ '#': a.i + 1, kind: 'repeated', score: 3, values: { [p.key]: a.r[p.key] }, why: p.key + ' appears ' + a.dup + ' times in this period - compare it by hand' }); }
    const b = B.get(x);
    if (p.amount) { const v = num(a.r[p.amount]); if (v !== null) after += v; }
    if (!b) { added++; ex.push({ '#': a.i + 1, kind: 'new', score: 2 + (p.amount && num(a.r[p.amount]) !== null ? 0 : 0), values: pick(a.r, [p.key].concat(p.amount ? [p.amount] : [], watch.slice(0, 4))), why: 'new in this period - not in the previous one' }); continue; }
    const diff = watch.filter((f) => !same(a.r[f], b.r[f]));
    if (!diff.length) { unchanged++; continue; }
    changed++;
    let score = diff.length, why = [];
    const payee = diff.filter((f) => PAYEE.test(f)); if (payee.length) { score += 4; why.push(payee.join(', ') + ' changed'); }
    if (p.amount && diff.includes(p.amount)) {
      const va = num(a.r[p.amount]), vb = num(b.r[p.amount]);
      if (va !== null && vb !== null && vb !== 0) { const ch = Math.round(((va - vb) / Math.abs(vb)) * 1000) / 10; if (Math.abs(ch) >= pct) { score += 3; why.push(p.amount + ' ' + (ch > 0 ? '+' : '') + ch + '% (' + vb + ' -> ' + va + ')'); } else why.push(p.amount + ' ' + (ch > 0 ? '+' : '') + ch + '%'); }
      else why.push(p.amount + ' ' + b.r[p.amount] + ' -> ' + a.r[p.amount]);
      if (payee.length && va !== null && vb !== null && va > vb) { score += 3; why.push('pay rose in the same period the account changed'); }
    }
    const rest = diff.filter((f) => !PAYEE.test(f) && f !== p.amount); if (rest.length) why.push(rest.slice(0, 6).join(', ') + ' changed');
    const values = { [p.key]: a.r[p.key] }; for (const f of diff.slice(0, 8)) { values[f] = a.r[f]; values[f + ' (previous)'] = b.r[f]; }
    ex.push({ '#': a.i + 1, kind: 'changed', score, values, changes: diff, why: why.join('; ') });
  }
  for (const [x, b] of B) {
    if (b.dup > 1) dups++;
    if (p.amount) { const v = num(b.r[p.amount]); if (v !== null) before += v; }
    if (!A.has(x)) { gone++; ex.push({ '#': b.i + 1, side: 'other', kind: 'gone', score: 1, values: pick(b.r, [okey].concat(p.amount ? [p.amount] : [])), why: 'in the previous period only - left, or missing from this one' }); }
  }
  ex.sort((a, b) => b.score - a.score || a['#'] - b['#']);
  const totals = p.amount ? { before: Math.round(before * 100) / 100, after: Math.round(after * 100) / 100, change_pct: before ? Math.round(((after - before) / Math.abs(before)) * 1000) / 10 : null } : null;
  return Object.assign({ summary: added + ' new, ' + gone + ' gone, ' + changed + ' changed, ' + unchanged + ' unchanged' + (dups ? ', ' + dups + ' key(s) repeated within a period' : '') + (totals ? '; ' + p.amount + ' total ' + totals.before + ' -> ' + totals.after + (totals.change_pct == null ? '' : ' (' + (totals.change_pct > 0 ? '+' : '') + totals.change_pct + '%)') : ''),
    counts: { new: added, gone, changed, unchanged, repeated: dups }, totals, watched: watch.slice(0, 40) }, cap(ex));
}

const OPS = ['eq', 'ne', 'gt', 'ge', 'lt', 'le', 'contains', 'not_contains', 'blank', 'not_blank', 'before', 'after'];
function test1(v, c) {
  const n = num(v), cv = num(c.value), s = String(v == null ? '' : v).toLowerCase(), cs = String(c.value == null ? '' : c.value).toLowerCase();
  switch (c.op) {
    case 'eq': return n !== null && cv !== null ? n === cv : s.trim() === cs.trim();
    case 'ne': return n !== null && cv !== null ? n !== cv : s.trim() !== cs.trim();
    case 'gt': return n !== null && cv !== null && n > cv; case 'ge': return n !== null && cv !== null && n >= cv;
    case 'lt': return n !== null && cv !== null && n < cv; case 'le': return n !== null && cv !== null && n <= cv;
    case 'contains': return s.includes(cs); case 'not_contains': return !s.includes(cs);
    case 'blank': return blank(v); case 'not_blank': return !blank(v);
    case 'before': return date(v) !== null && date(c.value) !== null && date(v) < date(c.value);
    case 'after': return date(v) !== null && date(c.value) !== null && date(v) > date(c.value);
  }
  return false;
}
function filter(rows, p) {
  for (const c of p.conditions) need(rows, c.field);
  const ex = []; rows.forEach((r, i) => { const hit = p.match === 'any' ? p.conditions.some((c) => test1(r[c.field], c)) : p.conditions.every((c) => test1(r[c.field], c)); if (hit) ex.push({ '#': i + 1, values: pick(r, [...new Set(p.conditions.map((c) => c.field))]), why: 'meets ' + (p.match === 'any' ? 'any' : 'all') + ' of: ' + p.conditions.map((c) => c.field + ' ' + c.op + (c.value != null && c.value !== '' ? ' ' + c.value : '')).join(p.match === 'any' ? ' or ' : ' and ') }); });
  return Object.assign({ summary: ex.length + ' of ' + rows.length + ' row(s) meet the condition(s)' }, cap(ex));
}

// attribute sample size: the smallest n for which finding no more than the expected deviations still lets the auditor conclude, at the
// chosen confidence, that the true deviation rate is below the tolerable rate (binomial, AICPA style)
function binomCdf(k, n, p) { let s = 0, t = Math.pow(1 - p, n); for (let i = 0; i <= k; i++) { s += t; t = t * (n - i) / (i + 1) * p / (1 - p); } return s; }
function sampleSize(p) {
  const conf = p.confidence / 100, tol = p.tolerable / 100, exp = (p.expected || 0) / 100;
  if (exp >= tol) throw Object.assign(new Error('expected: the expected deviation rate must be below the tolerable rate'), { status: 400 });
  for (let n = 1; n <= 2000; n++) { const k = exp > 0 ? Math.ceil(n * exp) : 0; if (binomCdf(k, n, tol) <= 1 - conf) return { size: p.population ? Math.min(p.population, n) : n, allowed_deviations: k, why: 'binomial: with ' + n + ' items and at most ' + k + ' deviation(s), the auditor is ' + p.confidence + ' % confident the deviation rate is below ' + p.tolerable + ' %' + (p.population && p.population < n ? ' - the population (' + p.population + ') is smaller, so every item is tested' : '') }; }
  return { size: 2000, allowed_deviations: Math.ceil(2000 * exp), why: 'capped at 2000 - widen the tolerable rate' };
}
function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function draw(n, size, seed) { const r = rng(seed), ix = Array.from({ length: n }, (_, i) => i); const k = Math.min(size, n); for (let i = 0; i < k; i++) { const j = i + Math.floor(r() * (n - i)); [ix[i], ix[j]] = [ix[j], ix[i]]; } return ix.slice(0, k).sort((a, b) => a - b); }
function mus(rows, p, seed) {
  need(rows, p.amount); const x = rows.map((r, i) => ({ i, v: Math.abs(num(r[p.amount]) || 0) })).filter((q) => q.v > 0), tot = x.reduce((a, q) => a + q.v, 0);
  if (!tot) return { summary: 'no amounts in ' + p.amount, picked: [], interval: null };
  const interval = tot / p.size, start = rng(seed)() * interval, picked = []; let cum = 0, next = start;
  for (const q of x) { cum += q.v; if (cum > next) { picked.push({ i: q.i, v: q.v, top: q.v >= interval }); while (next < cum) next += interval; } }
  return { summary: picked.length + ' item(s) selected by monetary-unit sampling; interval ' + r2(interval) + ', random start ' + r2(start) + '; ' + picked.filter((q) => q.top).length + ' item(s) at or above the interval are always selected', picked, interval: r2(interval), start: r2(start), total: r2(tot) };
}

function suggest(fields, ty, prof) {
  const S = [], byName = (re) => fields.filter((f) => re.test(f));
  const amounts = fields.filter((f) => ty[f] === 'number' && /amount|value|cost|price|total|paid|premium|claim|invoice|sum|sar|fee/i.test(f));
  const ids = fields.filter((f) => ty[f] === 'number' && /(^|_|\b)(no|num|number|seq|id|invoice|voucher|cheque|check|receipt|ref)(\b|_|$)/i.test(f));
  const dates = fields.filter((f) => ty[f] === 'date'), names = byName(/name|vendor|supplier|payee|customer|beneficiary|employee|user/i).filter((f) => ty[f] === 'text');
  for (const f of amounts) S.push({ test: 'benford', params: { field: f }, why: f + ' is an amount: Benford\'s first-digit test looks for invented or manipulated figures' }, { test: 'outliers', params: { field: f }, why: 'unusually large or small ' + f }, { test: 'stratify', params: { field: f }, why: 'how ' + f + ' is distributed - where the value sits' });
  for (const f of ids) S.push({ test: 'gaps', params: { field: f }, why: f + ' looks like a sequence number: missing or repeated numbers' });
  for (const f of names) S.push({ test: 'fuzzy', params: { field: f }, why: 'near-duplicate ' + f + ' (the same party entered twice, a ghost vendor)' });
  if (names.length && amounts.length) S.push({ test: 'duplicates', params: { keys: [names[0], amounts[0]].concat(dates[0] ? [dates[0]] : []) }, why: 'the same ' + names[0] + ' and ' + amounts[0] + (dates[0] ? ' on the same ' + dates[0] : '') + ' - a possible double payment' });
  for (const f of dates) S.push({ test: 'age', params: Object.assign({ field: f }, amounts[0] ? { amount: amounts[0] } : {}), why: 'how old the records are by ' + f });
  const cats = fields.filter((f) => ty[f] === 'text' && prof && (prof.find((x) => x.field === f) || {}).distinct > 1 && (prof.find((x) => x.field === f) || {}).distinct <= 50);
  if (cats[0]) S.push({ test: 'summarize', params: Object.assign({ by: cats[0] }, amounts[0] ? { amount: amounts[0] } : {}), why: 'totals by ' + cats[0] });
  if (amounts[0] && cats[0]) S.push({ test: 'outliers', params: { field: amounts[0], by: cats[0] }, why: amounts[0] + ' unusual within its own ' + cats[0] + ' (peer comparison)' });
  return S.slice(0, 14);
}

module.exports = { parseCsv, types, profile, duplicates, fuzzy, gaps, benford, stratify, age, summarize, outliers, join, compare, filter, OPS, sampleSize, draw, mus, suggest, num, date, norm, lev, LIMIT_EX };
