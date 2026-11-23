// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Risk Appetite automation for Business Risk (engine/business-risk.js) - pure functions, deterministic, every result names its evidence.
 *
 *   coverage   which register risks a RAS metric watches. A confirmed link is "covered"; otherwise the platform scores every metric
 *              against the risk from four signals and says which ones fired:
 *                text      TF-IDF cosine of the risk (title, description, categories) and the metric (component, description,
 *                          formula, RBS category, section) in one corpus
 *                dept      the department that owns the risk is the one responsible for the metric (+0.15)
 *                family    the risk area and the metric's section / RBS category are the same family of risk (insurance,
 *                          operational, strategic, financial, compliance) (+0.10)
 *                learned   a risk like this one (cosine >= 0.35) was linked to the metric by a person: half that similarity is added -
 *                          the model learns from every confirmation; a suggestion a person rejected is never offered again
 *              score >= 0.45 with some shared text = "strong" (approve in bulk), >= 0.30 = "possible" (look first), below = uncovered.
 *   proposals  corrected limits for metrics whose limits are out of order, on mixed scales or missing: re-ordered, a whole-number
 *              percentage read as a percentage, the limits of the most similar metric, or the spread of the metric's own values. Each
 *              proposal is parsed again and must come out clean; a person requests it and a different administrator approves it.
 *   due        the metrics each responsible department has not reported for the last closed period, with what is needed to report.
 */
const ML = require('./brisk-ml');

const STRONG = 0.45, POSSIBLE = 0.3;
const FAMILIES = [['insurance', /insurance|underwrit|actuar|reinsur/i], ['operational', /operational|oversight|conduct/i], ['strategic', /strateg|project/i],
  ['financial', /financ|credit|market|counterparty|ifrs|liquidity|investment|solvency/i], ['compliance', /legal|regulat|\baml\b|compliance/i]];
const familyOf = (...xs) => { const s = xs.filter(Boolean).join(' ').replace(/_/g, ' '); return new Set(FAMILIES.filter(([, re]) => re.test(s)).map(([k]) => k)); };
const deptKey = (s) => String(s || '').toLowerCase().replace(/&/g, ' and ').replace(/\b(department|dept|division|unit|section|team)\b/g, ' ').replace(/[^a-z0-9؀-ۿ]+/g, ' ').replace(/\s+/g, ' ').trim();
function deptMatch(a, b) {
  const x = deptKey(a), y = deptKey(b); if (!x || !y) return false; if (x === y) return true;
  if (x.length >= 4 && y.length >= 4 && (x.includes(y) || y.includes(x))) return true;
  // word overlap (Jaccard >= 0.5) - short words such as "IT" count, so "X IT" and "X Finance" share one word of three, not one of two
  const A = new Set(x.split(' ').filter((w) => w.length > 1)), B = new Set(y.split(' ').filter((w) => w.length > 1)); if (!A.size || !B.size) return false;
  const inter = [...A].filter((w) => B.has(w)).length; return inter / (A.size + B.size - inter) >= 0.5;
}
const r2 = (x) => Math.round(x * 100) / 100;
const riskDoc = (r) => [r.title, r.description, r.primary_cat, r.secondary_cat].join(' ');
const metricDoc = (m) => [m.component, m.description, m.formula, m.rbs, m.section_title].join(' ');

// risks: enriched register rows (id, code, title, department, area, residual, status, ...); metrics: RAS metric views (id, links, rejected?, ...)
function coverage(risks, metrics) {
  const V = ML.tfidf(risks.map(riskDoc).concat(metrics.map(metricDoc))), vr = V.vectors.slice(0, risks.length), vm = V.vectors.slice(risks.length);
  const ix = new Map(risks.map((r, i) => [r.id, i])), rfam = risks.map((r) => familyOf(r.area, r.primary_cat)), mfam = metrics.map((m) => familyOf(m.section_title, m.rbs));
  const linkedTo = metrics.map((m) => (m.links || []).map((id) => ix.get(id)).filter((i) => i != null));
  const rej = metrics.map((m) => new Set(m.rejected || []));
  const covers = new Map(); metrics.forEach((m) => (m.links || []).forEach((id) => { if (!covers.has(id)) covers.set(id, []); covers.get(id).push(m.id); }));
  const simRR = new Map(), rr = (i, k) => { const key = i < k ? i + ':' + k : k + ':' + i; if (!simRR.has(key)) simRR.set(key, ML.cosine(vr[i], vr[k])); return simRR.get(key); };
  const metricBest = metrics.map(() => null);
  const out = risks.map((r, i) => {
    const cands = [];
    metrics.forEach((m, j) => {
      if ((m.links || []).includes(r.id) || rej[j].has(r.id)) return;
      const text = ML.cosine(vr[i], vm[j]), dept = deptMatch(r.department, m.responsibility), fam = [...rfam[i]].some((f) => mfam[j].has(f));
      let learned = null; for (const k of linkedTo[j]) { if (k === i) continue; const s = rr(i, k); if (s >= 0.35 && (!learned || s > learned.sim)) learned = { risk: risks[k].code || risks[k].id, sim: s }; }
      const score = r2(Math.min(1, text + (dept ? 0.15 : 0) + (fam ? 0.1 : 0) + (learned ? learned.sim / 2 : 0)));
      if (score < POSSIBLE - 0.05) return;
      const c = { metric: m.id, component: m.component, score, text, dept, family: fam, learned, words: ML.shared(vr[i], vm[j], 4) };
      cands.push(c); if (!metricBest[j] || score > metricBest[j].score) metricBest[j] = { risk: r.id, score };
    });
    cands.sort((a, b) => b.score - a.score || a.metric.localeCompare(b.metric));
    const linked = covers.get(r.id) || [], best = cands.slice(0, 3), top = best[0];
    const state = linked.length ? 'covered' : top && top.score >= STRONG && top.text >= 0.08 ? 'strong' : top && top.score >= POSSIBLE ? 'possible' : 'uncovered';
    return { id: r.id, code: r.code, title: r.title, department: r.department, area: r.area || '(none)', owner: r.owner, residual: r.residual, class: r.class, status: r.status, linked, state, suggestions: best };
  });
  const open = out.filter((r) => r.status !== 'solved'), count = (a, s) => a.filter((r) => r.state === s).length;
  const areas = {}; for (const r of open) { const a = areas[r.area] || (areas[r.area] = { area: r.area, risks: 0, covered: 0, strong: 0, possible: 0, uncovered: 0, serious_uncovered: 0 }); a.risks++; a[r.state]++; if (r.residual >= 3 && r.state !== 'covered') a.serious_uncovered++; }
  const mstate = metrics.map((m, j) => ({ id: m.id, component: m.component, section_title: m.section_title, responsibility: m.responsibility, links: (m.links || []).length,
    state: (m.links || []).length ? 'linked' : metricBest[j] && metricBest[j].score >= POSSIBLE ? 'suggested' : 'orphan', best: metricBest[j] }));
  return {
    summary: { open: open.length, covered: count(open, 'covered'), strong: count(open, 'strong'), possible: count(open, 'possible'), uncovered: count(open, 'uncovered'),
      serious_open: open.filter((r) => r.residual >= 3).length, serious_uncovered: open.filter((r) => r.residual >= 3 && r.state !== 'covered').length,
      all: out.length, all_covered: count(out, 'covered'), metrics: metrics.length, metrics_linked: mstate.filter((m) => m.state === 'linked').length, metrics_orphan: mstate.filter((m) => m.state === 'orphan').length },
    risks: out, by_area: Object.values(areas).sort((a, b) => b.risks - a.risks), metrics: mstate,
    method: 'score = text similarity (TF-IDF cosine) + 0.15 same department + 0.10 same family of risk + half the similarity to a risk a person already linked to the metric; strong >= ' + STRONG + ', possible >= ' + POSSIBLE + '. Suggestions a person rejected are not offered again. A person confirms every link.',
  };
}

// ---------- limit proposals
const KEYS = ['cap_floor', 'tol_floor', 'app_floor', 'app_ceil', 'tol_ceil', 'cap_ceil'], FLOORS = KEYS.slice(0, 3), CEILS = KEYS.slice(3);
const LABEL = { cap_floor: 'capacity floor', tol_floor: 'tolerance floor', app_floor: 'appetite floor', app_ceil: 'appetite ceiling', tol_ceil: 'tolerance ceiling', cap_ceil: 'capacity ceiling' };
function fmt(v, unit) {
  if (v == null) return '';
  const n = (x) => String(Math.round(x * 1e6) / 1e6);
  if (unit === 'ratio') return n(v * 100) + '%';
  if (unit === 'hours') return v >= 24 && v % 24 === 0 ? n(v / 24) + ' days' : v < 1 ? n(v * 60) + ' min' : n(v) + ' hours';
  if (unit === 'SAR million') return n(v) + ' MN';
  return n(v);
}
function quantile(xs, q) { const s = xs.slice().sort((a, b) => a - b), p = (s.length - 1) * q, lo = Math.floor(p), hi = Math.ceil(p); return s[lo] + (s[hi] - s[lo]) * (p - lo); }
// metric: a RAS metric (raw, kind, unit, limits, issues); others: all metrics (for "like a similar metric"); values: the metric's reported numbers
function proposeLimits(metric, others, values) {
  const m = metric, why = [], L = Object.assign({}, m.limits || {});
  const clean = (raw, basis, from) => { const P = ML.parseLimits(raw); if (P.issues.length || P.kind === 'none' || P.kind === 'manual') return null; return { id: m.id, component: m.component, basis, from: from || null, current: m.raw, proposed: raw, kind: P.kind, unit: P.unit, limits: P.limits, why }; };
  if (['band', 'floor', 'ceiling'].includes(m.kind) && (m.issues || []).length) {
    let unit = m.unit; const vals = KEYS.filter((k) => L[k] != null).map((k) => L[k]);
    // a whole number among ratios: 70 with 0.6 and 0.8 means 70 %
    if ((!unit || unit === 'ratio') && vals.some((v) => Math.abs(v) > 3) && vals.some((v) => v !== 0 && Math.abs(v) <= 1.5)) {
      for (const k of KEYS) if (L[k] != null && Math.abs(L[k]) > 3 && Math.abs(L[k] / 100) <= 3) { why.push('the ' + LABEL[k] + ' ' + L[k] + ' is read as ' + L[k] + ' % (' + r2(L[k] / 100) + '), like the other limits'); L[k] = L[k] / 100; }
      unit = 'ratio';
    }
    // floors rise capacity -> tolerance -> appetite; ceilings rise appetite -> tolerance -> capacity
    for (const side of [FLOORS, CEILS]) {
      const ks = side.filter((k) => L[k] != null), sorted = ks.map((k) => L[k]).sort((a, b) => a - b);
      if (ks.some((k, i) => L[k] !== sorted[i])) { why.push('the ' + (side === FLOORS ? 'floors' : 'ceilings') + ' are put in order: ' + ks.map((k, i) => LABEL[k] + ' ' + fmt(sorted[i], unit)).join(', ')); ks.forEach((k, i) => { L[k] = sorted[i]; }); }
    }
    if (L.app_floor != null && L.app_ceil != null && L.app_floor > L.app_ceil) { why.push('the appetite floor and ceiling are swapped (' + fmt(L.app_ceil, unit) + ' to ' + fmt(L.app_floor, unit) + ')'); [L.app_floor, L.app_ceil] = [L.app_ceil, L.app_floor]; }
    if (!why.length) return null;
    const raw = {}; for (const k of KEYS) raw[k] = L[k] != null ? fmt(L[k], unit) : ''; return clean(raw, 'correction');
  }
  if (m.kind === 'none') {
    const nums = (values || []).filter(Number.isFinite);
    if (nums.length >= 6) {
      const q = (p) => r2(quantile(nums, p)), unit = nums.every((v) => Math.abs(v) <= 3) && nums.some((v) => v % 1 !== 0) ? 'ratio' : null;
      const raw = { cap_floor: fmt(Math.min(...nums), unit), tol_floor: fmt(q(0.05), unit), app_floor: fmt(q(0.1), unit), app_ceil: fmt(q(0.9), unit), tol_ceil: fmt(q(0.95), unit), cap_ceil: fmt(Math.max(...nums), unit) };
      why.push('from the ' + nums.length + ' values reported for this metric: appetite = the middle 80 % (10th to 90th percentile), tolerance = 5th to 95th, capacity = the lowest and highest seen - the committee sets the real appetite');
      return clean(raw, 'history');
    }
    const pool = others.filter((o) => o.id !== m.id && ['band', 'floor', 'ceiling', 'boolean'].includes(o.kind) && !(o.issues || []).length);
    if (!pool.length) return null;
    const V = ML.tfidf([metricDoc(m)].concat(pool.map(metricDoc))), best = pool.map((o, j) => ({ o, sim: ML.cosine(V.vectors[0], V.vectors[j + 1]), words: ML.shared(V.vectors[0], V.vectors[j + 1], 4) })).sort((a, b) => b.sim - a.sim)[0];
    if (!best || best.sim < 0.35) return null;
    why.push('no limits in the workbook; ' + best.o.id + ' (' + best.o.component + ') reads alike (similarity ' + best.sim + ': ' + best.words.join(', ') + ') - its limits are a starting point to adjust');
    if (best.o.kind === 'boolean') { const raw = Object.fromEntries(KEYS.map((k) => [k, k === 'app_floor' ? (best.o.question || '(Yes / No)') : ''])); const P = ML.parseLimits(raw); return P.kind === 'boolean' ? { id: m.id, component: m.component, basis: 'similar', from: best.o.id, current: m.raw, proposed: raw, kind: 'boolean', unit: null, limits: {}, why } : null; }
    return clean(Object.assign({}, best.o.raw), 'similar', best.o.id);
  }
  return null;
}

// ---------- reporting: what each department still owes for the last closed period
function due(metrics) {
  const by = {};
  for (const m of metrics) {
    if (m.reporting === 'no_limits') continue;
    const d = m.responsibility || '(none)', x = by[d] || (by[d] = { department: d, total: 0, reported: 0, due: [], outside: 0 });
    x.total++; if (m.reporting === 'reported') x.reported++; else x.due.push({ id: m.id, component: m.component, kind: m.kind, unit: m.unit, raw: m.raw, question: m.question, frequency: m.frequency, due_period: m.due_period, last: m.latest ? { period: m.latest.period, value: m.latest.value, text: m.latest.text, zone: m.latest.zone } : null });
    if (m.latest && m.latest.level >= 1) x.outside++;
  }
  return Object.values(by).sort((a, b) => b.due.length - a.due.length || a.department.localeCompare(b.department));
}

module.exports = { coverage, proposeLimits, due, deptMatch, familyOf, fmt, KEYS, STRONG, POSSIBLE };
