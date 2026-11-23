// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared helpers for engine/reports/* (attack summary, after-hours monitoring, scheduled reports).
//   resolvePeriod(query, nowMs, {dflt, maxDays}) → {from, to, label: '24h'|'7d'|'30d'|'custom', bucket: 'hour'|'day', bucket_ms}
//   tparams(period, offMin) → ClickHouse params {t_from, t_to, t_off, t_bucket}      TIME_WHERE  the matching WHERE clause
//   runQueries(ch, {name: [sql, params]}, opts) → {results:{name: rows|null}, errors:[{panel, error}]}  (independent, read-only)
//   fillBuckets(rows, period, offMin) → [{t, …}]   esc(s)   toMs(v)   dist(values)   isPrivateIp(ip)
//   aliasViolations(sql) → [{alias, scope}]  static check: an alias that is also a column used inside an aggregate of the
//     same SELECT scope (e.g. `max(updated) AS updated` next to argMax(x, updated)) — ClickHouse 26.x rejects those.
const { HttpError, timeParam } = require('../soc/routeutil');
const { toMs } = require('../compliance/evidence-ch');

const H = 3600000;
const DAY = 86400000;
const PRESETS = { '24h': DAY, '7d': 7 * DAY, '30d': 30 * DAY };

function resolvePeriod(q = {}, nowMs = Date.now(), { dflt = '7d', maxDays = 400 } = {}) {
  const now = Math.floor(nowMs / 60000) * 60000; // minute-aligned → cacheable
  let from; let to; let label;
  if ((q.from !== undefined && q.from !== '') || (q.to !== undefined && q.to !== '')) {
    to = timeParam(q.to, now);
    from = timeParam(q.from, to - (PRESETS[dflt] || 7 * DAY));
    label = 'custom';
  } else {
    label = q.period === undefined || q.period === '' ? dflt : String(q.period);
    if (!PRESETS[label]) throw new HttpError(400, 'period must be 24h, 7d or 30d (or give from/to)');
    to = now; from = now - PRESETS[label];
  }
  if (!(Number.isFinite(from) && Number.isFinite(to) && from < to)) throw new HttpError(400, 'from must be before to');
  if (to - from > maxDays * DAY) throw new HttpError(400, `period longer than ${maxDays} days`);
  if (to > nowMs + H) throw new HttpError(400, 'to is in the future');
  const bucket = to - from <= 2 * DAY ? 'hour' : 'day';
  return { from, to, label, bucket, bucket_ms: bucket === 'hour' ? H : DAY };
}

const TIME_WHERE = 'ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64})';
function tparams(p, offMin = 180) {
  return {
    t_from: { type: 'Int64', value: Math.floor(p.from) }, t_to: { type: 'Int64', value: Math.floor(p.to) },
    t_off: { type: 'Int64', value: offMin * 60000 }, t_bucket: { type: 'Int64', value: p.bucket_ms },
  };
}

async function runQueries(ch, specs, { timeoutMs = 20000 } = {}) {
  const results = {}; const errors = [];
  if (!ch || typeof ch.query !== 'function') {
    for (const k of Object.keys(specs)) results[k] = null;
    return { results, errors: [{ panel: '*', error: 'ClickHouse client not available' }] };
  }
  await Promise.all(Object.entries(specs).map(async ([name, [sql, params]]) => {
    try { results[name] = await ch.query(sql, params, { readonly: true, timeout_ms: timeoutMs }); } catch (e) { results[name] = null; errors.push({ panel: name, error: String(e && e.message || e).slice(0, 300) }); }
  }));
  return { results, errors };
}

/** Bucket start (epoch ms) of bucket index b (local-time aligned); rows [{b, …}] → every bucket of the period, zeros kept. */
function fillBuckets(rows, p, offMin = 180, fields = ['n']) {
  const off = offMin * 60000; const bms = p.bucket_ms;
  const first = Math.floor((p.from + off) / bms); const last = Math.floor((p.to - 1 + off) / bms);
  const by = new Map((rows || []).map((r) => [Number(r.b), r]));
  const out = [];
  for (let b = first; b <= last && out.length < 2000; b++) {
    const r = by.get(b) || {};
    const pt = { t: b * bms - off };
    for (const f of fields) pt[f] = Number(r[f]) || 0;
    out.push(pt);
  }
  return out;
}

const esc = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function dist(values) {
  const v = values.filter((x) => Number.isFinite(x) && x >= 0).sort((a, b) => a - b);
  if (!v.length) return { n: 0, avg_ms: null, median_ms: null, p90_ms: null };
  const q = (p) => v[Math.min(v.length - 1, Math.floor(p * (v.length - 1) + 0.5))];
  return { n: v.length, avg_ms: Math.round(v.reduce((a, b) => a + b, 0) / v.length), median_ms: q(0.5), p90_ms: q(0.9) };
}

function isPrivateIp(ip) {
  const s = String(ip || '');
  if (/^(10\.|127\.|169\.254\.|192\.168\.)/.test(s)) return true;
  const m = /^172\.(\d+)\./.exec(s); if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(s)) return true; // CGNAT
  return /^(::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(s);
}

// ---------------------------------------------------------------- static SQL check (tests + defensive self-check)
const AGG_RE = /\b(argMax|argMin|max|min|sum|count|countIf|sumIf|avg|avgIf|any|anyIf|anyLast|uniq|uniqIf|uniqExact|uniqExactIf|groupArray|groupArrayIf|groupUniqArray|topK|maxIf|minIf|quantile\w*|median)\s*(\(\s*\d+\s*\))?\s*\(/gi;
const NOT_IDENT = new Set(['if', 'and', 'or', 'not', 'in', 'is', 'null', 'as', 'case', 'when', 'then', 'else', 'end', 'select', 'from', 'where', 'distinct', 'true', 'false', 'like', 'ilike']);

function stripStrings(sql) { return sql.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ').replace(/\{[A-Za-z_][A-Za-z0-9_]*:[^}]*\}/g, '0'); }
function matchParen(s, i) { let d = 0; for (let k = i; k < s.length; k++) { if (s[k] === '(') d++; else if (s[k] === ')') { d--; if (d === 0) return k; } } return s.length - 1; }

/** Split into SELECT scopes: every "(SELECT …)" group is its own scope; nested groups are blanked in the parent. */
function scopes(sql) {
  const s = stripStrings(sql);
  const out = [];
  function walk(text) {
    let own = ''; let i = 0;
    while (i < text.length) {
      if (text[i] === '(' && /^\(\s*SELECT\b/i.test(text.slice(i, i + 12))) {
        const j = matchParen(text, i);
        walk(text.slice(i + 1, j));
        own += ' (_sub_) '; i = j + 1; continue;
      }
      own += text[i]; i++;
    }
    out.push(own);
  }
  walk(s);
  return out;
}

function aliasViolations(sql) {
  const bad = [];
  scopes(sql).forEach((scope, si) => {
    const aliases = new Set(); let m;
    const aRe = /\bAS\s+([A-Za-z_][A-Za-z0-9_]*)/gi;
    while ((m = aRe.exec(scope))) aliases.add(m[1].toLowerCase());
    const inAgg = new Set();
    AGG_RE.lastIndex = 0;
    while ((m = AGG_RE.exec(scope))) {
      const open = AGG_RE.lastIndex - 1;
      const close = matchParen(scope, open);
      const inner = scope.slice(open + 1, close);
      const idRe = /[A-Za-z_][A-Za-z0-9_]*/g; let x;
      while ((x = idRe.exec(inner))) {
        const id = x[0].toLowerCase();
        if (/^\s*\(/.test(inner.slice(x.index + x[0].length))) continue; // a function name
        if (!NOT_IDENT.has(id)) inAgg.add(id);
      }
    }
    for (const a of aliases) if (inAgg.has(a)) bad.push({ alias: a, scope: si });
  });
  return bad;
}

module.exports = { resolvePeriod, TIME_WHERE, tparams, runQueries, fillBuckets, esc, toMs, dist, isPrivateIp, aliasViolations, scopes, PRESETS, DAY, H };
