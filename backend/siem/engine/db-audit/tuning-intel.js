// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle Tuning intelligence (prefix {P} = /api/soc) - the "✦ AI / ML" tab of Oracle Tuning: it closes the loop on the tuning
 * the DBAs already do (tuning.js findings and proposals) with the SQL timings the SIEM already holds (perf-api.js Top SQL, 7 days).
 * Read-only: nothing here runs on a database. Every number says what it stands on.
 *   verified    each recommendation marked DONE with a SQL_ID: time per execution in the 7 days before it was run against the
 *               time since (from 1 hour after), weighted by executions, 3+ samples and 10+ executions on each side - IMPROVED
 *               (1.3x or better, with the DB time it saves a day), NO EFFECT, or WORSE (its rollback SQL is named). Otherwise
 *               "not measurable" and why - never assumed to have worked.
 *   learned     the share of verified fixes that worked, per kind of fix (plan baseline, statistics, AI, rule ...), smoothed
 *               Beta(1,1) so one success is not "100 %"; it becomes each new finding's confidence.
 *   next        the findings ranked by expected benefit: severity x the DB time its SQL costs a day (7-day Top SQL) x the
 *               confidence learned for its kind. What to tune first, and why.
 *   candidates  tuning the findings do not raise yet: (a) unstable plans - a SQL_ID with 2+ plans whose time per execution
 *               differs 2x or more (a SQL Plan Management baseline candidate); (b) literal SQL - 3+ SQL_IDs that differ only in
 *               literals (bind variables / cursor sharing); (c) the Pareto line - how much of all SQL time the top 5 take.
 * GET {P}/db/oracle/tuning/intel?instance=    analyst (same as the Tuning page)
 */
const { wrap } = require('../soc/routeutil');
const { body: check } = require('../util/check');

const H = 3600000, DAY = 86400000;
const r1 = (x) => Math.round(x * 10) / 10;
const SEVW = { critical: 4, high: 3, medium: 2, low: 1 };
const tms = (x) => (typeof x === 'number' ? (x < 1e12 ? x * 1000 : x) : Date.parse(x));
const kindOf = (p) => { const k = String(p.finding_key || '').split(':')[0]; return k ? k : p.source === 'ai' ? 'ai' : 'rule'; };
const KIND_NAME = { plan: 'plan baseline / plan fix', stats: 'optimizer statistics', ai: 'AI recommendation', rule: 'rule-based recommendation', long: 'long-running call', wait: 'wait event', temp: 'TEMP / undo', mem: 'memory', dg: 'Data Guard', gg: 'GoldenGate' };

function perExec(points) {
  const P = points.filter((p) => p.executions > 0 && p.ela_ms_exec != null);
  const ex = P.reduce((n, p) => n + p.executions, 0);
  return { n: P.length, executions: ex, ms: ex ? P.reduce((n, p) => n + p.ela_ms_exec * p.executions, 0) / ex : null };
}

function verify(p, detail, now) {
  const base = { id: p.id, title: p.title, sql_id: p.sql_id || null, kind: kindOf(p), done_at: p.done_at, done_by: p.done_by || '' };
  if (!p.sql_id) return Object.assign(base, { verdict: 'not-measurable', why: 'not tied to one SQL_ID - check it with its verification SQL' });
  if (!detail) return Object.assign(base, { verdict: 'not-measurable', why: 'no timings for ' + p.sql_id + ' in the last 7 days (it may not run any more)' });
  const t = tms(p.done_at), pts = [];
  for (const pl of detail.plans || []) for (const x of pl.points || []) pts.push({ t: tms(x.ts), executions: Number(x.executions) || 0, ela_ms_exec: x.ela_ms_exec == null ? null : Number(x.ela_ms_exec) });
  const before = perExec(pts.filter((x) => x.t < t && x.t >= t - 7 * DAY)), after = perExec(pts.filter((x) => x.t >= t + H && x.t <= now));
  if (before.n < 3 || after.n < 3 || before.executions < 10 || after.executions < 10) return Object.assign(base, { verdict: 'not-measurable', why: 'needs 3+ samples and 10+ executions before and after (' + before.n + '/' + after.n + ' samples, ' + before.executions + '/' + after.executions + ' executions)', before_ms: before.ms == null ? null : r1(before.ms), after_ms: after.ms == null ? null : r1(after.ms) });
  const ratio = before.ms / Math.max(0.001, after.ms), days = Math.max(1, (now - t - H) / DAY), perDay = after.executions / days, saves = (before.ms - after.ms) * perDay / 1000;
  const v = ratio >= 1.3 ? 'improved' : ratio <= 1 / 1.3 ? 'worse' : 'no-effect';
  return Object.assign(base, { verdict: v, before_ms: r1(before.ms), after_ms: r1(after.ms), ratio: r1(ratio), saves_s_day: v === 'improved' ? r1(saves) : null,
    why: v === 'improved' ? r1(ratio) + 'x faster per execution (' + r1(before.ms) + ' -> ' + r1(after.ms) + ' ms), about ' + r1(saves) + ' s of DB time saved a day'
      : v === 'worse' ? r1(1 / ratio) + 'x SLOWER since it was run (' + r1(before.ms) + ' -> ' + r1(after.ms) + ' ms) - consider its rollback SQL' + (p.rollback_sql ? '' : ' (none was recorded)')
        : 'no measurable change (' + r1(before.ms) + ' -> ' + r1(after.ms) + ' ms per execution)' });
}

const norm = (t) => String(t || '').toLowerCase().replace(/'(?:[^']|'')*'/g, '?').replace(/\b\d+(\.\d+)?\b/g, '?').replace(/:\w+/g, '?').replace(/\s+/g, ' ').trim();

function analyse({ view, sql7d, details = {}, now = Date.now() }) {
  const P = (view && view.proposals) || [], F = (view && view.findings) || [], SQ = (sql7d && sql7d.sql) || [];
  // verified outcomes
  const verified = P.filter((p) => p.status === 'done').map((p) => verify(p, p.sql_id ? details[p.sql_id] : null, now)).sort((a, b) => String(b.done_at).localeCompare(String(a.done_at)));
  // learned success per kind
  const kinds = {};
  for (const v of verified) { if (v.verdict === 'not-measurable') continue; const k = kinds[v.kind] = kinds[v.kind] || { kind: v.kind, name: KIND_NAME[v.kind] || v.kind, improved: 0, measured: 0 }; k.measured++; if (v.verdict === 'improved') k.improved++; }
  const learned = Object.values(kinds).map((k) => Object.assign(k, { success_pct: Math.round(100 * (k.improved + 1) / (k.measured + 2)), why: k.improved + ' of ' + k.measured + ' verified ' + k.name + ' fixes worked (smoothed)' })).sort((a, b) => b.measured - a.measured);
  const conf = (kind) => { const k = kinds[kind]; return k ? (k.improved + 1) / (k.measured + 2) : 0.5; };
  // what costs DB time
  const bySql = new Map(SQ.map((q) => [q.sql_id, q])), period = (sql7d && sql7d.period_s) || 7 * 86400, dayF = 86400 / period;
  const next = F.map((f) => {
    const k = String(f.key || '').split(':')[0], q = f.sql_id ? bySql.get(f.sql_id) : null, cost = q ? (q.elapsed_s || 0) * dayF : null, c = conf(k);
    const score = (SEVW[f.severity] || 1) * (1 + (cost ? Math.log10(1 + cost) : 0)) * (0.5 + c);
    return { key: f.key, title: f.title, severity: f.severity, area: f.area, sql_id: f.sql_id || null, cost_s_day: cost == null ? null : r1(cost), confidence_pct: Math.round(100 * c), score: r1(score),
      why: (cost != null ? 'its SQL costs ' + r1(cost) + ' s of DB time a day' : 'severity ' + f.severity) + ' · ' + (kinds[k] ? kinds[k].why : 'no verified ' + (KIND_NAME[k] || k) + ' fix yet - 50 % prior') };
  }).sort((a, b) => b.score - a.score);
  // candidates the findings do not raise
  const already = new Set(F.map((f) => f.sql_id).filter(Boolean));
  const unstable = SQ.filter((q) => (q.plans || []).length >= 2 && !already.has(q.sql_id)).map((q) => { const ms = q.plans.map((x) => Number(x.ela_ms_exec)).filter((x) => x > 0); if (ms.length < 2) return null; const best = Math.min(...ms), worst = Math.max(...ms), bp = q.plans.find((x) => Number(x.ela_ms_exec) === best);
    return worst / best >= 2 ? { sql_id: q.sql_id, plans: q.plans.length, best_plan: bp ? bp.plan_hash : null, best_ms: r1(best), worst_ms: r1(worst), ratio: r1(worst / best), cost_s_day: r1((q.elapsed_s || 0) * dayF), why: q.plans.length + ' plans, the slowest ' + r1(worst / best) + 'x the best - a SQL Plan Management baseline on plan ' + (bp ? bp.plan_hash : '?') + ' would pin the good one' } : null; }).filter(Boolean).sort((a, b) => b.cost_s_day - a.cost_s_day);
  const groups = new Map(); for (const q of SQ) { if (!q.sql_text) continue; const k = norm(q.sql_text); if (k.length < 20) continue; const g = groups.get(k) || { signature: k.slice(0, 200), sql_ids: [], elapsed_s: 0, executions: 0, module: q.module || '' }; g.sql_ids.push(q.sql_id); g.elapsed_s += q.elapsed_s || 0; g.executions += q.executions || 0; groups.set(k, g); }
  const literals = [...groups.values()].filter((g) => g.sql_ids.length >= 3).map((g) => Object.assign(g, { elapsed_s: r1(g.elapsed_s), why: g.sql_ids.length + ' SQL_IDs differ only in literal values - bind variables in the application (or CURSOR_SHARING, tested first) would let Oracle reuse one cursor' })).sort((a, b) => b.sql_ids.length - a.sql_ids.length);
  const tot = SQ.reduce((n, q) => n + (q.elapsed_s || 0), 0), top5 = SQ.slice().sort((a, b) => (b.elapsed_s || 0) - (a.elapsed_s || 0)).slice(0, 5);
  const pareto = tot ? { top5_pct: Math.round(100 * top5.reduce((n, q) => n + (q.elapsed_s || 0), 0) / tot), total_s: r1(tot), top: top5.map((q) => ({ sql_id: q.sql_id, pct: Math.round(100 * (q.elapsed_s || 0) / tot), module: q.module || '' })) } : null;
  const counts = { improved: verified.filter((v) => v.verdict === 'improved').length, worse: verified.filter((v) => v.verdict === 'worse').length, no_effect: verified.filter((v) => v.verdict === 'no-effect').length, not_measurable: verified.filter((v) => v.verdict === 'not-measurable').length };
  return { generated_at: new Date(now).toISOString(), counts, saved_s_day: r1(verified.reduce((n, v) => n + (v.saves_s_day || 0), 0)), verified, learned, next: next.slice(0, 20), candidates: { unstable: unstable.slice(0, 15), literals: literals.slice(0, 10), pareto },
    sql_text_visible: !!(sql7d && sql7d.sql_text_visible) };
}

function register(api, deps, P, withRole, tuning) {
  api.route('GET', `${P}/db/oracle/tuning/intel`, wrap(deps, 'analyst', async (ctx) => {
    const q = check(ctx.query || {}).str('instance', { max: 200 }).done(), M = deps.oracle_perf, t = (deps.now || Date.now)();
    const view = await tuning.view(q), inst = (view && view.instance && (view.instance.key || view.instance)) || q.instance;
    const base = Object.assign(withRole(ctx), { instance: inst });
    const sql7d = M ? await M.topsql(Object.assign({}, base, { period: '7d', by: 'elapsed' })).catch(() => null) : null;
    const details = {};
    for (const p of ((view && view.proposals) || []).filter((x) => x.status === 'done' && x.sql_id).slice(0, 15)) {
      try { const d = await M.topsql(Object.assign({}, base, { period: '7d', by: 'elapsed', sql_id: p.sql_id })); if (d && d.detail) details[p.sql_id] = d.detail; } catch (e) { /* one SQL without timings is reported as not measurable, the rest still answers */ }
    }
    return ctx.ok(analyse({ view, sql7d, details, now: t }));
  }));
}

module.exports = { analyse, verify, register, norm };
