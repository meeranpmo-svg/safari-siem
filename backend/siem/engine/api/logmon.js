// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body: check } = require('../util/check');
/*
 * Log Monitor & Analysis - what the logs say, not only that they arrive. Built on the search service over siem.events (the same
 * queries the hunt page runs); nothing is stored and nothing is changed.
 *   overview  events in the window, the rate now against the window's own median, the share at warning or above, volume over time
 *             for the busiest sources (stacked), severity mix, top sources / hosts / categories / actions.
 *   patterns  log template mining: each message is reduced to its template (IP, MAC, GUID, e-mail, hex, numbers and variable
 *             key=value values masked) and grouped per source type, so 40,000 lines read as 60 patterns. Each pattern is compared
 *             with the window of the same length before it: NEW (not seen before), SPIKE (3x or more and at least 10), DROPPED
 *             (10 or more before, none now) - with counts, hosts, first / last seen, worst severity and one sample line.
 *             The window is mined from the newest `limit` events (default 20,000); when there are more, the result says it is a
 *             sample and how big, never presented as the whole.
 * Raw lines are personal data (sign-ins and logons of named people, PDPL): analysts and above, every read audited.
 *   POST /api/soc/logmon/overview  {from?, to?, q?}            analyst
 *   POST /api/soc/logmon/patterns  {from?, to?, q?, limit?}    analyst
 */
const HOUR = 3600000;
const SEV = ['info', 'low', 'medium', 'high', 'critical'];

// a message reduced to its template: the variable parts masked, the constant words kept
function template(msg) {
  let t = String(msg == null ? '' : msg).slice(0, 2000);
  t = t.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<guid>')
    .replace(/\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b/g, '<email>')
    .replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b/gi, '<mac>')
    .replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<time>')
    .replace(/\b\d{1,2}:\d{2}(:\d{2})?\b/g, '<time>')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, '<ip>')
    .replace(/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi, '<ip>')
    .replace(/\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b/gi, '<hex>')
    .replace(/([\w.-]+)=("[^"]*"|'[^']*'|\S+)/g, (m, k, v) => (/\d|^["']/.test(v) ? k + '=<*>' : m))
    .replace(/(?<=[A-Za-z])\d+(?=\/)/g, '<n>')   // interface names: Gi1/0/24, Te1/1/1
    .replace(/\b\d+(\.\d+)?\b/g, '<n>')
    .replace(/(<\*>|<n>)([\s,;]+(<\*>|<n>))+/g, '$1')
    .replace(/\s+/g, ' ').trim();
  return t.slice(0, 300) || '(empty message)';
}

function mine(events) {
  const G = new Map();
  for (const e of events) {
    const tpl = template(e.message || e.raw), k = (e.src_type || 'unknown') + '\u0000' + tpl;
    let g = G.get(k);
    if (!g) { g = { src_type: e.src_type || 'unknown', template: tpl, n: 0, hosts: new Set(), first: e.ts, last: e.ts, severity: 0, sample: String(e.message || e.raw || '').slice(0, 400) }; G.set(k, g); }
    g.n++; if (e.host) g.hosts.add(e.host);
    if (e.ts < g.first) g.first = e.ts; if (e.ts > g.last) { g.last = e.ts; g.sample = String(e.message || e.raw || '').slice(0, 400); }
    if ((e.severity || 0) > g.severity) g.severity = e.severity || 0;
  }
  return G;
}

function createLogMonitor({ search, now } = {}) {
  const clock = now || Date.now;
  function range(b) {
    const t = clock(), to = b.to != null ? b.to : t, from = b.from != null ? b.from : to - 24 * HOUR;
    if (!(to > from)) throw Object.assign(new Error('from must be before to'), { status: 400 });
    if (to - from > 31 * 24 * HOUR) throw Object.assign(new Error('the window may be at most 31 days'), { status: 400 });
    return { from, to };
  }
  const and = (q, extra) => (q ? '(' + q + ') AND ' + extra : extra);

  async function overview(b) {
    const { from, to } = range(b), q = b.q || '';
    const [hist, srcs, hosts, sev, cats, acts] = await Promise.all([
      search.histogram({ q, from, to, buckets: 48 }), search.top({ q, from, to, field: 'src_type', limit: 12 }), search.top({ q, from, to, field: 'host', limit: 12 }),
      search.top({ q, from, to, field: 'severity', limit: 5 }), search.top({ q, from, to, field: 'category', limit: 10 }), search.top({ q, from, to, field: 'action', limit: 10 }),
    ]);
    const total = hist.buckets.reduce((s, x) => s + x.n, 0);
    const series = await Promise.all(srcs.values.slice(0, 5).map((s) => search.histogram({ q: and(q, 'src_type:"' + String(s.v).replace(/"/g, '') + '"'), from, to, buckets: 48 }).then((h) => ({ source: s.v, buckets: h.buckets.map((x) => x.n) }))));
    const per = hist.buckets.map((x) => x.n), sorted = per.slice().sort((a, c) => a - c), median = sorted.length ? sorted[Math.floor(sorted.length / 2)] : 0;
    const last = per.length ? per[per.length - 1] : 0, stepMin = hist.step_ms / 60000;
    const sevN = Object.fromEntries(SEV.map((n, i) => [n, (sev.values.find((v) => Number(v.v) === i) || { n: 0 }).n]));
    const warn = sevN.medium + sevN.high + sevN.critical;
    return {
      from, to, q, total, step_ms: hist.step_ms, buckets: hist.buckets, series,
      rate: { last_per_min: stepMin ? Math.round((last / stepMin) * 10) / 10 : 0, median_per_min: stepMin ? Math.round((median / stepMin) * 10) / 10 : 0,
        // the last bucket is still filling when the window ends now: said, not compared as a drop
        partial: to >= clock() - hist.step_ms },
      severity: sevN, warn_share_pct: total ? Math.round((warn / total) * 1000) / 10 : 0,
      top: { sources: srcs.values, hosts: hosts.values, categories: cats.values, actions: acts.values },
    };
  }

  async function patterns(b) {
    const { from, to } = range(b), q = b.q || '', limit = b.limit || 20000, span = to - from;
    const [cur, prev, hist] = await Promise.all([
      search.fetchEvents({ q, from, to, limit, order: 'desc' }), search.fetchEvents({ q, from: from - span, to: from, limit, order: 'desc' }), search.histogram({ q, from, to, buckets: 24 }),
    ]);
    const total = hist.buckets.reduce((s, x) => s + x.n, 0), C = mine(cur), P = mine(prev), out = [];
    // a capped previous window covers less time than the current one: scale its counts to the same span before comparing
    const scale = prev.length >= limit ? span / Math.max(1, from - prev[prev.length - 1].ts) : 1;
    for (const [k, g] of C) {
      const p = P.get(k), before = p ? Math.round(p.n * scale) : 0;
      const status = !p ? 'new' : g.n >= 10 && g.n >= 3 * Math.max(1, before) ? 'spike' : 'steady';
      out.push({ id: Buffer.from(k).toString('base64url').slice(0, 60), src_type: g.src_type, template: g.template, n: g.n, before, status, hosts: g.hosts.size, host_list: [...g.hosts].slice(0, 8), first: g.first, last: g.last, severity: SEV[g.severity] || 'info', sample: g.sample });
    }
    const dropped = [];
    for (const [k, p] of P) if (!C.has(k) && p.n * scale >= 10) dropped.push({ src_type: p.src_type, template: p.template, before: Math.round(p.n * scale), hosts: p.hosts.size, last: p.last, sample: p.sample });
    const ORDER = { new: 0, spike: 1, steady: 2 };
    out.sort((a, c) => ORDER[a.status] - ORDER[c.status] || c.n - a.n);
    return {
      from, to, q, total, mined: cur.length, sampled: cur.length >= limit && total > cur.length,
      note: cur.length >= limit && total > cur.length ? 'patterns mined from the newest ' + cur.length.toLocaleString('en') + ' of ' + total.toLocaleString('en') + ' events in the window' : null,
      previous: { from: from - span, to: from, mined: prev.length },
      summary: { patterns: out.length, new: out.filter((x) => x.status === 'new').length, spike: out.filter((x) => x.status === 'spike').length, dropped: dropped.length, rare: out.filter((x) => x.n === 1).length },
      patterns: out.slice(0, 500), dropped: dropped.sort((a, c) => c.before - a.before).slice(0, 100),
    };
  }
  return { overview, patterns };
}

const T = (v) => (v == null || v === '' ? undefined : typeof v === 'number' ? v : Number.isFinite(Number(v)) ? Number(v) : Date.parse(v));
function args(src, withLimit) {
  let c = check(src || {}).str('q', { max: 4096 }).rule((o) => {
    for (const k of ['from', 'to']) { const v = (src || {})[k]; if (v != null && v !== '' && !Number.isFinite(T(v))) return k + ' must be a time (epoch ms or ISO-8601)'; }
    return null;
  });
  if (withLimit) c = c.int('limit', { min: 100, max: 50000, def: 20000 });
  const b = c.done(); b.from = T((src || {}).from); b.to = T((src || {}).to); return b;
}

function register(api, { search, now } = {}) {
  const L = createLogMonitor({ search, now });
  api.route('POST', '/api/soc/logmon/overview', async (ctx) => { ctx.need('analyst'); return L.overview(args(ctx.body)); }, { auditRead: true });
  api.route('POST', '/api/soc/logmon/patterns', async (ctx) => { ctx.need('analyst'); return L.patterns(args(ctx.body, true)); }, { auditRead: true });
  return L;
}

module.exports = { createLogMonitor, register, template };
