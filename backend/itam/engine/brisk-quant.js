// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Business Risk quantification (pure functions; business-risk.js stores the inputs, audits the changes and serves the result).
 *   simulate   Monte Carlo of the annual loss: for each register risk with a loss range the risk owner entered (lowest / most likely /
 *              highest SAR, and how many times a year it could happen), each trial draws the number of events (Poisson) and the
 *              loss of each event (PERT between the three amounts), and adds every risk's losses. 10,000 trials, seeded from the
 *              inputs, so the same register gives the same figures every time and a change in any input changes them.
 *              Out: mean, P50 / P90 / P95 / P99 annual loss, the histogram, the cumulative curve, the chance of exceeding the
 *              loss appetite, and each risk's share of the mean (what drives the total). The risks are added as independent -
 *              the page says so: correlated risks make the tail heavier than shown.
 *   quarterly  residual exposure at the end of each of the last 8 quarters, from each risk's assessment history (the rating in
 *              force at that date): risks by Class I-IV and the sum of inherent scores. A risk with no assessment before a
 *              quarter's end is not counted in that quarter - never back-filled.
 *   correlate  Pearson correlation between the numeric RAS metric series, over the periods both reported (6 or more), with the
 *              points for a scatter plot. A correlation is a co-movement to look into, not a cause.
 */
const QUARTERS = 8, MIN_COMMON = 6;

function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function normal(R) { let u = 0, v = 0; while (u === 0) u = R(); while (v === 0) v = R(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
// Marsaglia-Tsang gamma (shape >= 1 here: PERT shapes are 1-5)
function gamma(R, k) { const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d); for (;;) { let x, v; do { x = normal(R); v = 1 + c * x; } while (v <= 0); v = v * v * v; const u = R(); if (u < 1 - 0.0331 * x * x * x * x || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v; } }
function pert(R, a, m, b) { if (b <= a) return a; const al = 1 + (4 * (m - a)) / (b - a), be = 1 + (4 * (b - m)) / (b - a), x = gamma(R, al), y = gamma(R, be); return a + ((b - a) * x) / (x + y); }
function poisson(R, lam) { if (lam <= 0) return 0; if (lam > 30) return Math.max(0, Math.round(lam + Math.sqrt(lam) * normal(R))); const L = Math.exp(-lam); let k = 0, p = 1; do { k++; p *= R(); } while (p > L); return k - 1; }
const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1))];

// items: [{id, title, loss_min, loss_likely, loss_max, frequency}] (SAR, events per year)
function simulate(items, opts = {}) {
  const trials = opts.trials || 10000, seed = hash(JSON.stringify(items.map((i) => [i.id, i.loss_min, i.loss_likely, i.loss_max, i.frequency]))), R = rng(seed);
  const tot = new Float64Array(trials), per = items.map(() => 0);
  for (let t = 0; t < trials; t++) {
    let s = 0;
    for (let i = 0; i < items.length; i++) { const it = items[i], n = poisson(R, it.frequency); for (let k = 0; k < n; k++) { const l = pert(R, it.loss_min, it.loss_likely, it.loss_max); s += l; per[i] += l; } }
    tot[t] = s;
  }
  const sorted = Array.from(tot).sort((a, b) => a - b), mean = sorted.reduce((a, b) => a + b, 0) / trials;
  const P = { p50: pct(sorted, 0.5), p90: pct(sorted, 0.9), p95: pct(sorted, 0.95), p99: pct(sorted, 0.99) };
  const lo = sorted[0], hi = pct(sorted, 0.995), BINS = 30, w = (hi - lo) / BINS || 1, hist = Array.from({ length: BINS }, (_, i) => ({ from: lo + i * w, to: lo + (i + 1) * w, n: 0 }));
  let over = 0; for (const v of sorted) { if (v > hi) { over++; continue; } hist[Math.min(BINS - 1, Math.floor((v - lo) / w))].n++; }
  const cdf = hist.map((h, i) => ({ x: h.to, p: hist.slice(0, i + 1).reduce((s, x) => s + x.n, 0) / trials }));
  const exceed = (x) => (x == null ? null : sorted.filter((v) => v > x).length / trials);
  const drivers = items.map((it, i) => ({ id: it.id, title: it.title, mean: per[i] / trials, share: mean ? per[i] / trials / mean : 0 })).sort((a, b) => b.mean - a.mean);
  return { trials, seed, risks: items.length, mean, percentiles: P, min: lo, max: sorted[trials - 1], histogram: hist, beyond_chart: over, cdf, appetite: opts.appetite != null ? { value: opts.appetite, p_exceed: exceed(opts.appetite) } : null, drivers,
    independence: 'risks are simulated as independent; risks that tend to happen together make the tail (P95 / P99) heavier than shown' };
}

const qOf = (d) => d.getUTCFullYear() + '-Q' + (Math.floor(d.getUTCMonth() / 3) + 1);
function quarterly(risks, nowMs) {
  const d = new Date(nowMs), out = [];
  for (let k = QUARTERS - 1; k >= 0; k--) {
    const y = d.getUTCFullYear(), q0 = Math.floor(d.getUTCMonth() / 3) - k, yy = y + Math.floor(q0 / 4), qq = ((q0 % 4) + 4) % 4;
    const end = Date.UTC(yy, qq * 3 + 3, 1) - 1, label = yy + '-Q' + (qq + 1), row = { quarter: label, end: new Date(Math.min(end, nowMs)).toISOString(), risks: 0, inherent_sum: 0, classes: { I: 0, II: 0, III: 0, IV: 0 }, partial: end > nowMs };
    for (const r of risks) {
      const h = (r.history || []).filter((x) => Date.parse(x.at) <= end).pop();
      if (!h || h.inherent == null) continue;
      if (r.status === 'solved' && r.solved_at && Date.parse(r.solved_at) <= end) continue;
      row.risks++; row.inherent_sum += h.inherent; const c = /Class (IV|III|II|I)\b/.exec(h.class || ''); if (c) row.classes[c[1]]++;
    }
    out.push(row);
  }
  return out;
}

function pearson(x, y) { const n = x.length, mx = x.reduce((a, b) => a + b, 0) / n, my = y.reduce((a, b) => a + b, 0) / n; let sxy = 0, sxx = 0, syy = 0; for (let i = 0; i < n; i++) { sxy += (x[i] - mx) * (y[i] - my); sxx += (x[i] - mx) ** 2; syy += (y[i] - my) ** 2; } return sxx && syy ? sxy / Math.sqrt(sxx * syy) : null; }
// metrics: [{id, component, unit, series:[{period, value}]}]
function correlate(metrics) {
  const num = metrics.map((m) => ({ id: m.id, name: m.component || m.id, unit: m.unit || '', v: new Map((m.series || []).filter((p) => Number.isFinite(p.value)).map((p) => [p.period, p.value])) })).filter((m) => m.v.size >= MIN_COMMON);
  const pairs = [];
  for (let i = 0; i < num.length; i++) for (let j = i + 1; j < num.length; j++) {
    const A = num[i], B = num[j], per = [...A.v.keys()].filter((p) => B.v.has(p)).sort(); if (per.length < MIN_COMMON) continue;
    const x = per.map((p) => A.v.get(p)), y = per.map((p) => B.v.get(p)), r = pearson(x, y); if (r == null) continue;
    pairs.push({ a: A.id, a_name: A.name, a_unit: A.unit, b: B.id, b_name: B.name, b_unit: B.unit, r: Math.round(r * 100) / 100, n: per.length, strength: Math.abs(r) >= 0.7 ? 'strong' : Math.abs(r) >= 0.4 ? 'moderate' : 'weak', points: per.map((p, k) => ({ period: p, x: x[k], y: y[k] })) });
  }
  pairs.sort((p, q) => Math.abs(q.r) - Math.abs(p.r));
  return { metrics_with_history: num.length, min_common: MIN_COMMON, pairs: pairs.slice(0, 40) };
}

module.exports = { simulate, quarterly, correlate, pert, poisson, rng, qOf };
