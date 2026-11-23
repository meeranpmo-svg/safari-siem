// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The machine learning behind Business Risk (engine/business-risk.js). Plain JavaScript, no library, deterministic: the same register
 * gives the same answer every time, and every answer carries the evidence it came from - an auditor can re-perform it.
 *   tokens      lower-cased words (Latin and Arabic letters), stop words dropped, a light English stem
 *   tfidf       term frequency x inverse document frequency, L2-normalised sparse vectors; cosine similarity between them
 *   bayes       multinomial naive Bayes with Laplace smoothing, trained on the register itself; leave-one-out scoring so a risk is
 *               never judged by a model that learned from it
 *   holt        Holt's linear exponential smoothing for a KRI series: level + trend, the one-step error spread, forecasts and the
 *               chance (normal approximation) that the next value falls outside a limit - a projection from past values, not a promise
 *   threshold   reads the RAS limits as numbers: 0.7, '<70%', '>=250%', '70% - 90%', '1 days', '30 Min', '25 MN', 'BBB+', '(Yes / No)'
 */
const STOP = new Set(('a an and are as at be been by can could do does due for from has have in into is it its may might more most must no not of on or our over per '
  + 'risk risks such than that the their there these this those through to under was were which while will with within without would lack inadequate ineffective '
  + 'potential possible failure failures related process processes').split(' '));
function stem(w) { if (w.length > 5 && w.endsWith('ies')) return w.slice(0, -3) + 'y'; if (w.length > 5 && w.endsWith('ing')) return w.slice(0, -3); if (w.length > 4 && w.endsWith('ed')) return w.slice(0, -2); if (w.length > 3 && w.endsWith('s') && !w.endsWith('ss')) return w.slice(0, -1); return w; }
function tokens(text) {
  return String(text == null ? '' : text).toLowerCase().split(/[^a-z0-9؀-ۿ]+/).filter((w) => w.length > 2 && !STOP.has(w) && !/^\d+$/.test(w)).map(stem).filter((w) => w.length > 2 && !STOP.has(w));
}

// ---- TF-IDF + cosine
function tfidf(docs) {
  const toks = docs.map(tokens), df = new Map();
  for (const t of toks) for (const w of new Set(t)) df.set(w, (df.get(w) || 0) + 1);
  const N = docs.length || 1, idf = (w) => Math.log((N + 1) / ((df.get(w) || 0) + 1)) + 1;
  const vec = (t) => { const tf = new Map(); for (const w of t) tf.set(w, (tf.get(w) || 0) + 1); let n = 0; const v = new Map(); for (const [w, c] of tf) { const x = (1 + Math.log(c)) * idf(w); v.set(w, x); n += x * x; } n = Math.sqrt(n) || 1; for (const [w, x] of v) v.set(w, x / n); return v; };
  return { vectors: toks.map(vec), embed: (text) => vec(tokens(text)), idf };
}
function cosine(a, b) { if (a.size > b.size) [a, b] = [b, a]; let s = 0; for (const [w, x] of a) { const y = b.get(w); if (y) s += x * y; } return Math.round(s * 1000) / 1000; }
// the words two texts share, heaviest first - the "why" of a similarity
function shared(a, b, n = 5) { const out = []; for (const [w, x] of a) { const y = b.get(w); if (y) out.push([w, x * y]); } return out.sort((p, q) => q[1] - p[1]).slice(0, n).map((p) => p[0]); }
function neighbours(vectors, i, k = 5, min = 0.2) {
  const out = []; for (let j = 0; j < vectors.length; j++) if (j !== i) { const c = cosine(vectors[i], vectors[j]); if (c >= min) out.push({ j, sim: c }); }
  return out.sort((a, b) => b.sim - a.sim || a.j - b.j).slice(0, k);
}

// ---- multinomial naive Bayes
function bayesTrain(docs, labels) {
  const M = { classes: new Map(), vocab: new Set(), n: 0 };
  docs.forEach((d, i) => { const y = labels[i]; if (!y) return; const t = tokens(d); let c = M.classes.get(y); if (!c) M.classes.set(y, (c = { docs: 0, words: new Map(), total: 0 })); c.docs++; M.n++; for (const w of t) { c.words.set(w, (c.words.get(w) || 0) + 1); c.total++; M.vocab.add(w); } });
  return M;
}
// probabilities over the classes; `exclude` = { label, text } removes one training document first (leave-one-out)
function bayesPredict(M, text, exclude) {
  const t = tokens(text), V = M.vocab.size || 1, ex = exclude ? tokens(exclude.text) : null, exCount = new Map();
  if (ex) for (const w of ex) exCount.set(w, (exCount.get(w) || 0) + 1);
  const n = M.n - (exclude ? 1 : 0), scores = [];
  for (const [y, c] of M.classes) {
    const mine = exclude && exclude.label === y, docs = c.docs - (mine ? 1 : 0); if (docs <= 0) continue;
    const total = c.total - (mine ? ex.length : 0);
    let lp = Math.log(docs / n);
    for (const w of t) lp += Math.log(((c.words.get(w) || 0) - (mine ? exCount.get(w) || 0 : 0) + 1) / (total + V));
    scores.push([y, lp]);
  }
  if (!scores.length) return [];
  const mx = Math.max(...scores.map((x) => x[1])), z = scores.reduce((a, x) => a + Math.exp(x[1] - mx), 0);
  return scores.map(([y, lp]) => ({ label: y, p: Math.round((Math.exp(lp - mx) / z) * 1000) / 1000 })).sort((a, b) => b.p - a.p || String(a.label).localeCompare(String(b.label)));
}

// ---- Holt's linear trend
const normCdf = (x) => { const t = 1 / (1 + 0.2316419 * Math.abs(x)), d = 0.3989423 * Math.exp(-x * x / 2), p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274)))); return x > 0 ? 1 - p : p; };
function holt(series, o = {}) {
  const y = series.filter((v) => Number.isFinite(v)), a = o.alpha || 0.5, b = o.beta || 0.3, min = o.min || 4;
  if (y.length < min) return { n: y.length, why: 'needs ' + min + ' reported periods (' + y.length + ' so far)' };
  let L = y[0], T = y[1] - y[0]; const err = [];
  for (let i = 1; i < y.length; i++) { const f = L + T; err.push(y[i] - f); const L2 = a * y[i] + (1 - a) * (L + T); T = b * (L2 - L) + (1 - b) * T; L = L2; }
  const e = err.slice(1), sd = e.length ? Math.sqrt(e.reduce((s, x) => s + x * x, 0) / e.length) : 0, r = (x) => Math.round(x * 10000) / 10000;
  const fc = (h) => L + h * T, sig = (h) => Math.max(sd * Math.sqrt(h), Math.abs(L) * 0.01, 1e-9);
  return { n: y.length, level: r(L), trend: r(T), sd: r(sd), forecast: [1, 2, 3].map((h) => ({ h, value: r(fc(h)), lo: r(fc(h) - 1.28 * sig(h)), hi: r(fc(h) + 1.28 * sig(h)) })),
    // P(the value h periods ahead is above / below a limit)
    pAbove: (lim, h = 1) => Math.round((1 - normCdf((lim - fc(h)) / sig(h))) * 100) / 100, pBelow: (lim, h = 1) => Math.round(normCdf((lim - fc(h)) / sig(h)) * 100) / 100,
    why: 'Holt linear smoothing (alpha ' + a + ', beta ' + b + ') over ' + y.length + ' periods; the band is the 80 % range of past one-step errors - a projection from past values, not a promise' };
}

// ---- RAS thresholds
const RATINGS = ['AAA', 'AA+', 'AA', 'AA-', 'A+', 'A', 'A-', 'BBB+', 'BBB', 'BBB-', 'BB+', 'BB', 'BB-', 'B+', 'B', 'B-', 'CCC+', 'CCC', 'CCC-', 'CC', 'C', 'D'];
// durations are held in hours (a row may mix '30 Min' and '1H'); amounts in SAR million
const UNITS = [[/\b(?:days?)\b/i, 'hours', 24], [/\b(?:hours?|h)\b/i, 'hours', 1], [/\b(?:min(?:ute)?s?)\b/i, 'hours', 1 / 60], [/\bmn\b/i, 'SAR million', 1], [/\bm\b/i, 'SAR million', 1], [/request/i, 'requests', 1]];
// one cell -> { v: number|null, kind: 'number'|'rating'|'boolean'|'text'|'blank', unit, lo, hi, raw }
function parseLimit(raw) {
  const s0 = String(raw == null ? '' : raw).trim(), s = s0.replace(/^'/, '').replace(/–|—/g, '-');
  if (!s || /^[-–]$/.test(s)) return { v: null, kind: 'blank', raw: s0 };
  if (/\(\s*yes\s*\/\s*no\s*\)/i.test(s) || /^all limits are/i.test(s)) return { v: null, kind: 'boolean', raw: s0 };
  const rt = /^(?:[<>]=?\s*)?(AAA|AA[+-]?|A[+-]?|BBB[+-]?|BB[+-]?|B[+-]?|CCC[+-]?|CC|C|D)$/.exec(s.replace(/\s+/g, ''));
  if (rt) return { v: RATINGS.indexOf(rt[1]) + 1, kind: 'rating', raw: s0 };
  const pct = /%/.test(s), first = /-?\d+(?:\.\d+)?/.exec(s);
  if (!first) return { v: null, kind: 'text', raw: s0 };
  let unit = null, f = 1; const words = s.replace(/\d+(?:\.\d+)?/g, ' ');
  for (const [re, u, k] of UNITS) if (re.test(words)) { unit = u; f = k; break; }
  if (/^\d+(?:\.\d+)?\s*h$/i.test(s)) { unit = 'hours'; f = 1; }
  const k = (pct ? 0.01 : 1) * f, num = (x) => Math.round(Number(x) * k * 1e9) / 1e9;
  // "70% - 90%", "-5%-20%", "100 MN - 120 MN": a range (the side decides which end is the limit); otherwise the first number
  const rg = /(-?\d+(?:\.\d+)?)\s*%?\s*[a-z]*\s*-\s*(-?\d+(?:\.\d+)?)/i.exec(s.replace(/^[<>]=?\s*/, ''));
  if (rg) { const a = num(rg[1]), b = num(rg[2]); return { v: null, lo: Math.min(a, b), hi: Math.max(a, b), kind: 'number', unit, raw: s0, pct }; }
  return { v: num(first[0]), lo: null, hi: null, kind: 'number', unit, raw: s0, pct };
}
// the six RAS columns -> the metric's kind and its numeric limits; a column that cannot be read is said, never guessed
function parseLimits(cols) {
  const keys = ['cap_floor', 'tol_floor', 'app_floor', 'app_ceil', 'tol_ceil', 'cap_ceil'], P = {}, issues = [];
  for (const k of keys) P[k] = parseLimit(cols[k]);
  const kinds = new Set(keys.map((k) => P[k].kind).filter((x) => x !== 'blank'));
  if (!kinds.size) return { kind: 'none', limits: {}, issues: ['no limits set - monitored without an appetite'], unit: null };
  if (kinds.has('boolean')) return { kind: 'boolean', limits: {}, issues: [], unit: null, question: String(cols.cap_floor || cols.app_floor || '').trim() };
  if (kinds.has('text')) return { kind: 'manual', limits: {}, issues: ['limits are written as text (' + keys.filter((k) => P[k].kind === 'text').map((k) => P[k].raw.slice(0, 40)).join('; ') + ') - the zone is recorded by a person'], unit: null };
  const rating = kinds.has('rating');
  if (rating && kinds.has('number')) return { kind: 'manual', limits: {}, issues: ['limits mix credit ratings and numbers - the zone is recorded by a person'], unit: null };
  const L = {}; const floorSide = (k) => k.endsWith('floor');
  for (const k of keys) { const p = P[k]; if (p.kind === 'blank') continue; let v = p.v; if (v == null && p.lo != null) v = floorSide(k) ? p.lo : p.hi; if (rating && floorSide(k)) continue; L[k] = v; }
  const units = [...new Set(keys.map((k) => P[k].unit).filter(Boolean))], hasF = ['cap_floor', 'tol_floor', 'app_floor'].some((k) => L[k] != null), hasC = ['app_ceil', 'tol_ceil', 'cap_ceil'].some((k) => L[k] != null);
  const seq = (a) => a.filter((k) => L[k] != null);
  const f = seq(['cap_floor', 'tol_floor', 'app_floor']); for (let i = 1; i < f.length; i++) if (L[f[i]] < L[f[i - 1]]) issues.push('floors out of order: ' + f[i - 1] + ' ' + L[f[i - 1]] + ' > ' + f[i] + ' ' + L[f[i]]);
  const c = seq(['app_ceil', 'tol_ceil', 'cap_ceil']); for (let i = 1; i < c.length; i++) if (L[c[i]] < L[c[i - 1]]) issues.push('ceilings out of order: ' + c[i - 1] + ' ' + L[c[i - 1]] + ' > ' + c[i] + ' ' + L[c[i]]);
  if (L.app_floor != null && L.app_ceil != null && L.app_floor > L.app_ceil) issues.push('the appetite floor ' + L.app_floor + ' is above the appetite ceiling ' + L.app_ceil);
  const vals = Object.values(L), big = vals.filter((v) => Math.abs(v) > 3).length, small = vals.filter((v) => v !== 0 && Math.abs(v) <= 1.5).length;
  if (!rating && !units.length && big && small) issues.push('limits mix scales (' + vals.join(', ') + ') - a percentage may be written as a whole number');
  const ratio = !rating && !units.length && vals.every((v) => Math.abs(v) <= 3) && keys.some((k) => P[k].pct || (P[k].v != null && P[k].v % 1 !== 0));
  return { kind: rating ? 'rating' : hasF && hasC ? 'band' : hasF ? 'floor' : 'ceiling', limits: L, issues, unit: rating ? 'rating' : units[0] || (ratio ? 'ratio' : null) };
}
// zone of a value: within appetite / outside appetite (within tolerance) / outside tolerance (within capacity) / capacity breached
const ZONES = ['within_appetite', 'outside_appetite', 'outside_tolerance', 'capacity_breach'];
function zoneOf(m, v) {
  const L = m.limits || {}; let z = 0, side = null;
  const up = (lim, lvl) => { if (lim != null && v > lim && lvl > z) { z = lvl; side = 'above'; } };
  const dn = (lim, lvl) => { if (lim != null && v < lim && lvl > z) { z = lvl; side = 'below'; } };
  if (m.kind === 'ceiling' || m.kind === 'band' || m.kind === 'rating') { up(L.app_ceil, 1); up(L.tol_ceil, 2); up(L.cap_ceil, 3); }
  if (m.kind === 'floor' || m.kind === 'band') { dn(L.app_floor, 1); dn(L.tol_floor, 2); dn(L.cap_floor, 3); }
  return { zone: ZONES[z], level: z, side };
}
// a reported value -> a number on the metric's scale; "82%" -> 0.82; a whole number on a ratio metric is refused, not divided
function parseValue(m, raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (m.kind === 'boolean') { if (/^(yes|y|true|1|met|compliant)$/i.test(s)) return { v: 1 }; if (/^(no|n|false|0|not met|breach)$/i.test(s)) return { v: 0 }; return { error: 'value: answer yes or no for this metric' }; }
  if (m.kind === 'rating') { const i = RATINGS.indexOf(s.toUpperCase().replace(/\s+/g, '')); return i < 0 ? { error: 'value: a credit rating such as BBB+ or A-' } : { v: i + 1, text: RATINGS[i] }; }
  if (m.unit === 'hours') { const d = /^(\d+(?:\.\d+)?)\s*(days?|d|hours?|h|min(?:ute)?s?|m)?$/i.exec(s); if (!d) return { error: 'value: a duration such as 4 hours, 30 min or 2 days' }; const u = (d[2] || 'h').toLowerCase(); return { v: Math.round(Number(d[1]) * (u[0] === 'd' ? 24 : u[0] === 'm' ? 1 / 60 : 1) * 1e6) / 1e6 }; }
  const x = /^(-?\d+(?:\.\d+)?)\s*(%?)$/.exec(s.replace(/,/g, '')); if (!x) return { error: 'value: a number' + (m.unit === 'ratio' ? ' such as 0.82 or 82%' : '') };
  let v = Number(x[1]); if (x[2]) v /= 100;
  if (m.unit === 'ratio' && !x[2] && Math.abs(v) > 3) return { error: 'value: this metric is a ratio - enter ' + v + '% or ' + (v / 100) };
  return { v: Math.round(v * 1e9) / 1e9 };
}

module.exports = { tokens, tfidf, cosine, shared, neighbours, bayesTrain, bayesPredict, holt, normCdf, parseLimit, parseLimits, parseValue, zoneOf, ZONES, RATINGS };
