// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Investigations & Cases insights (GET {P}/soc/cases/insights, and the per-case parts in the workspace) - pure statistics over the
 * SIEM's own cases, no model, nothing leaves the platform. Every figure says what it was computed from.
 *   forecast   for an open case, how long comparable CLOSED cases (same severity, 90 days; 5+ of them) took: median and 80th
 *              percentile, the expected close date from its age, and the share of comparable cases that took longer than the time
 *              left on its resolve SLA ("breach risk"). Withheld with fewer than 5 comparables.
 *   stalled    an open case with no timeline activity for twice the usual gap between its entries (median gap over closed cases of
 *              the same severity) and at least 24 hours - nobody has touched it.
 *   stages     the median time spent in each status (open, investigating, contained, eradicated, recovered), from the status
 *              changes on the timelines of 90 days of cases - the bottleneck is the longest one.
 *   similar    for a case, the closed cases whose scope looks like it: Jaccard over the entities, the rules and the ATT&CK
 *              techniques of their alerts, 0.3 or more, top 5, with the resolution, the time to close and the closing note.
 *   duplicates open cases whose scopes overlap (2+ shared entities and a Jaccard of 0.3 or more) - candidates to merge; a person
 *              decides, nothing is merged from here.
 *   owners     for an unassigned case, the people who closed comparable cases (same severity and a shared entity or rule) fastest,
 *              less their open load; service / AI identities never suggested.
 */
const H = 3600000, DAY = 24 * H;
const sevName = (s) => (s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low');
const q = (a, p) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); return b[Math.min(b.length - 1, Math.floor(p * (b.length - 1) + 0.5))]; };
const r1 = (x) => Math.round(x * 10) / 10;
const jac = (a, b) => { if (!a.size || !b.size) return 0; let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i); };

// the scope of a case: its alerts' entities, rules and techniques
function scopeOf(c, alertOf, entsOf) {
  const ents = new Set(), rules = new Set(), tech = new Set();
  for (const id of c.alerts || []) { const a = alertOf(id); if (!a) continue; for (const e of entsOf(a)) ents.add(e); rules.add('r:' + a.rule_id); for (const m of a.mitre || []) tech.add('t:' + (typeof m === 'object' ? m.id || m.technique : m)); }
  return { ents, all: new Set([...ents, ...rules, ...tech]) };
}
function stageDurations(c, now) {
  const out = {}, ev = (c.timeline || []).filter((x) => x.kind === 'status').map((x) => ({ at: x.at, to: (String(x.text).match(/→([a-z]+)/) || [])[1] })).filter((x) => x.to);
  let cur = 'open', since = c.created;
  for (const e of ev) { out[cur] = (out[cur] || 0) + Math.max(0, e.at - since); cur = e.to; since = e.at; }
  if (cur !== 'closed') out[cur] = (out[cur] || 0) + Math.max(0, now - since);
  return out;
}

function createCaseInsights({ cases, alertOf, entsOf, policy, now, isHuman }) {
  const t = now(), all = cases.all(() => true), closed = all.filter((c) => c.status === 'closed' && c.closed && c.closed >= t - 90 * DAY), open = all.filter((c) => c.status !== 'closed');
  const scopes = new Map(); const sc = (c) => scopes.get(c.id) || scopes.set(c.id, scopeOf(c, alertOf, entsOf)).get(c.id);
  const bySev = new Map(); for (const c of closed) { const k = sevName(c.severity || 0); (bySev.get(k) || bySev.set(k, []).get(k)).push(c); }
  const gapUsual = new Map();
  for (const [k, L0] of bySev) { const g = []; for (const c of L0) { const ts = (c.timeline || []).map((x) => x.at).sort((a, b) => a - b); for (let i = 1; i < ts.length; i++) g.push(ts[i] - ts[i - 1]); } gapUsual.set(k, q(g, 0.5)); }

  function forecast(c) {
    const comp = bySev.get(sevName(c.severity || 0)) || [];
    if (comp.length < 5) return { judged: false, why: 'needs 5 closed ' + sevName(c.severity || 0) + ' cases in 90 days (' + comp.length + ' so far)' };
    const dur = comp.map((x) => x.closed - x.created), med = q(dur, 0.5), p80 = q(dur, 0.8), age = t - c.created;
    const p = policy[sevName(c.severity || 0)], due = p ? c.created + p.resolve_h * H : null, left = due ? due - t : null;
    const longer = left == null ? null : Math.round(100 * dur.filter((d) => d > age + Math.max(0, left)).length / dur.length);
    const expected = new Date(c.created + Math.max(med, age + H)).toISOString();
    return { judged: true, comparables: comp.length, median_h: r1(med / H), p80_h: r1(p80 / H), expected_close: expected, breach_risk: left != null && left < 0 ? 100 : longer,
      why: comp.length + ' closed ' + sevName(c.severity || 0) + ' cases took a median ' + r1(med / H) + ' h (80% within ' + r1(p80 / H) + ' h)' + (longer != null ? '; ' + (left < 0 ? 'its resolve SLA has already passed' : longer + '% of them took longer than the ' + r1(left / H) + ' h left on its SLA') : '') };
  }
  function stalled(c) {
    const ts = (c.timeline || []).map((x) => x.at), last = ts.length ? Math.max(...ts) : c.created, idle = t - last, usual = gapUsual.get(sevName(c.severity || 0));
    if (usual == null) return null;
    return idle >= Math.max(DAY, 2 * usual) ? { idle_h: r1(idle / H), usual_gap_h: r1(usual / H), why: 'no activity for ' + r1(idle / H) + ' h; comparable cases are touched every ' + r1(usual / H) + ' h' } : null;
  }
  function similar(c, n = 5) {
    const me = sc(c).all; if (!me.size) return [];
    return closed.filter((x) => x.id !== c.id).map((x) => ({ x, j: jac(me, sc(x).all) })).filter((y) => y.j >= 0.3).sort((a, b) => b.j - a.j).slice(0, n)
      .map(({ x, j }) => ({ id: x.id, title: x.title, similarity: Math.round(j * 100), resolution: x.resolution || '', close_h: r1((x.closed - x.created) / H), note: String(x.resolution_note || '').slice(0, 300), owner: x.owner || '', shared: [...sc(c).ents].filter((e) => sc(x).ents.has(e)).slice(0, 5) }));
  }
  function duplicates() {
    const out = [];
    for (let i = 0; i < open.length; i++) for (let k = i + 1; k < open.length; k++) {
      const a = sc(open[i]), b = sc(open[k]), shared = [...a.ents].filter((e) => b.ents.has(e)), j = jac(a.all, b.all);
      if (shared.length >= 2 && j >= 0.3) out.push({ a: open[i].id, a_title: open[i].title, b: open[k].id, b_title: open[k].title, similarity: Math.round(j * 100), shared: shared.slice(0, 6), why: shared.length + ' shared entities (' + shared.slice(0, 3).join(', ') + '), ' + Math.round(j * 100) + '% of their scope' });
    }
    return out.sort((x, y) => y.similarity - x.similarity).slice(0, 15);
  }
  function owners(c) {
    const load = new Map(); for (const o of open) if (o.owner) load.set(o.owner, (load.get(o.owner) || 0) + 1);
    const me = sc(c), cand = new Map();
    for (const x of closed) { if (!x.owner || !isHuman(x.owner) || (x.severity || 0) !== (c.severity || 0)) continue; const s2 = sc(x); if (![...me.all].some((e) => s2.all.has(e))) continue;
      const e = cand.get(x.owner) || cand.set(x.owner, { user: x.owner, n: 0, h: [] }).get(x.owner); e.n++; e.h.push((x.closed - x.created) / H); }
    const L0 = [...cand.values()].map((e) => ({ user: e.user, closed: e.n, median_h: r1(q(e.h, 0.5)), load: load.get(e.user) || 0, score: e.n / (1 + q(e.h, 0.5) / 24) - 0.3 * (load.get(e.user) || 0) })).sort((a, b) => b.score - a.score);
    return L0.length ? Object.assign({}, L0[0], { why: L0[0].user + ' closed ' + L0[0].closed + ' comparable case(s) in a median ' + L0[0].median_h + ' h and holds ' + L0[0].load + ' open', others: L0.slice(1, 3).map((x) => x.user) }) : null;
  }
  function stages() {
    const per = {}; for (const c of all.filter((x) => x.created >= t - 90 * DAY)) for (const [k, v] of Object.entries(stageDurations(c, t))) (per[k] || (per[k] = [])).push(v);
    const rows = ['open', 'investigating', 'contained', 'eradicated', 'recovered'].filter((k) => per[k] && per[k].length).map((k) => ({ status: k, cases: per[k].length, median_h: r1(q(per[k], 0.5) / H), p80_h: r1(q(per[k], 0.8) / H) }));
    const slow = rows.slice().sort((a, b) => b.median_h - a.median_h)[0];
    return { rows, bottleneck: slow ? slow.status : null, why: slow ? 'cases spend the longest in "' + slow.status + '" (median ' + slow.median_h + ' h)' : 'no case history in 90 days' };
  }
  return { forecast, stalled, similar, duplicates, owners, stages, open, closed };
}

module.exports = { createCaseInsights, stageDurations, scopeOf };
