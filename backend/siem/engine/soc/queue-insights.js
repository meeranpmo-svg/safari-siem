// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Alert Queue insights (GET {P}/soc/queue/insights, analyst.js insights()) - pure functions over the scored open alerts and the
 * alert history. Statistics the SOC can explain; no model, no external data:
 *   campaigns   open alerts of DIFFERENT rules joined through a shared entity (host, user, IP) - union-find. An entity on more
 *               than max(10, 20 %) of the open alerts (a domain controller, a proxy, a scanner) would join everything, so it is
 *               left out of the joining and named as a hub. Combined score = 1 - prod(1 - priority/100); ATT&CK tactics in
 *               kill-chain order; 3+ distinct tactics is called a progression. A lead for an analyst, not a verdict.
 *   flow        alerts raised and closed per day (Riyadh days, 30 days); the backlog projected 7 days by least squares on the
 *               last 14 days of net change, with the band; days to clear at the current closing rate. Says how little
 *               history there is instead of projecting from it.
 *   sla         the case SLA policy (cases.js SLA, critical 1 h ack / 24 h resolve ... as configured) applied to each open alert:
 *               acknowledge due (not acknowledged, nobody assigned) and resolve due; breached or under 25 % of the time left.
 *   precedent   how alerts of the same rule on a shared entity were closed before (90 days): Beta(1,1) smoothed shares of true
 *               positive / false positive / benign, given only from 3 closures. Past decisions, not a prediction of this one.
 *   histogram   open alerts per priority band of 10.
 *   owners      a suggested owner for each unassigned open alert: the PEOPLE who closed this rule in 90 days (expertise =
 *               log2(1 + closures)) less their current load (0.15 per open alert they hold); service / AI identities never
 *               suggested. A suggestion - a person assigns.
 *   tuning      rules whose 30-day closures (5+) were false positive / benign at a smoothed rate >= 80 %; when one entity holds
 *               >= 60 % of those closures it is named as the exclusion to consider. Proposed, never applied: the rule is changed
 *               on SIEM Detection Rules by a person.
 *   surge       alerts raised in the last 60 minutes against the same hour on each of the previous 14 days (robust z, 7+ days
 *               of history); |z| >= 3.5 with 5+ alerts is a surge, with the rules driving it.
 *   similar     for each open alert, the closest CLOSED alerts of any rule (90 days): Jaccard over the masked summary words and
 *               the entities; 0.5 or more, top 3, with how each was closed and its note. Past cases to read, not a verdict.
 */
const DAY = 86400000, H = 3600000, OFF = 3 * H;
const KILL = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion',
  'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
const TACTIC_ID = { TA0043: 'reconnaissance', TA0042: 'resource-development', TA0001: 'initial-access', TA0002: 'execution', TA0003: 'persistence', TA0004: 'privilege-escalation',
  TA0005: 'defense-evasion', TA0006: 'credential-access', TA0007: 'discovery', TA0008: 'lateral-movement', TA0009: 'collection', TA0011: 'command-and-control', TA0010: 'exfiltration', TA0040: 'impact' };
const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');
const r1 = (x) => Math.round(x * 10) / 10;
function tacticsOf(a) {
  const out = new Set(), add = (t) => { const k = String(t || '').trim().toLowerCase().replace(/[\s_]+/g, '-').replace(/^command-and-control$/, 'command-and-control'); if (KILL.includes(k)) out.add(k); else if (TACTIC_ID[String(t).toUpperCase()]) out.add(TACTIC_ID[String(t).toUpperCase()]); };
  add(a.tactic); for (const m of a.mitre || []) { if (typeof m === 'object' && m) { add(m.tactic); add(m.tactic_id); } else add(m); }
  return out;
}

function campaigns(open) {
  const n = open.length, hubLimit = Math.max(10, Math.ceil(n * 0.2)), freq = new Map();
  for (const a of open) for (const e of new Set(a.entities || [])) freq.set(e, (freq.get(e) || 0) + 1);
  const hubs = [...freq.entries()].filter(([, c]) => c > hubLimit).map(([e, c]) => ({ entity: e, alerts: c })).sort((a, b) => b.alerts - a.alerts);
  const hub = new Set(hubs.map((h) => h.entity));
  const parent = open.map((_, i) => i), find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  const firstOf = new Map();
  open.forEach((a, i) => { for (const e of new Set(a.entities || [])) { if (hub.has(e)) continue; if (firstOf.has(e)) { const x = find(i), y = find(firstOf.get(e)); if (x !== y) parent[x] = y; } else firstOf.set(e, i); } });
  const groups = new Map(); open.forEach((a, i) => { const r = find(i); (groups.get(r) || groups.set(r, []).get(r)).push(a); });
  const out = [];
  for (const g of groups.values()) {
    const rules = new Set(g.map((a) => a.rule_id)); if (rules.size < 2) continue;
    const ents = new Map(); for (const a of g) for (const e of a.entities || []) if (!hub.has(e)) ents.set(e, (ents.get(e) || 0) + 1);
    const shared = [...ents.entries()].filter(([, c]) => c > 1).sort((a, b) => b[1] - a[1]).map(([e]) => e);
    const tac = new Set(); for (const a of g) for (const t of tacticsOf(a)) tac.add(t);
    const chain = KILL.filter((t) => tac.has(t)), score = Math.round(100 * (1 - g.reduce((p, a) => p * (1 - Math.min(99, a.priority || 0) / 100), 1)));
    const ts = g.map((a) => a.ts_first || a.ts_last || 0).filter(Boolean);
    out.push({ id: 'CMP-' + [...rules].sort().join('+').slice(0, 40) + '-' + (shared[0] || '').slice(0, 30), score, alerts: g.length, rules: [...rules].slice(0, 12),
      rule_names: [...new Set(g.map((a) => a.rule_name || a.rule_id))].slice(0, 8), entities: shared.slice(0, 8), tactics: chain, progression: chain.length >= 3,
      max_priority: Math.max(...g.map((a) => a.priority || 0)), max_severity: Math.max(...g.map((a) => a.severity || 0)), first: ts.length ? Math.min(...ts) : null, last: ts.length ? Math.max(...ts) : null,
      alert_ids: g.sort((a, b) => (b.priority || 0) - (a.priority || 0)).slice(0, 20).map((a) => a.id),
      why: g.length + ' open alerts from ' + rules.size + ' different rules share ' + (shared.length ? shared.slice(0, 3).join(', ') : 'an entity') + (chain.length ? '; tactics ' + chain.join(' -> ') : '') });
  }
  return { items: out.sort((a, b) => b.score - a.score || b.alerts - a.alerts).slice(0, 20), hubs: hubs.slice(0, 10), hub_limit: hubLimit };
}

function flow(all, now) {
  const days = 30, d0 = Math.floor((now + OFF) / DAY) - days + 1;
  const series = Array.from({ length: days }, (_, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), raised: 0, closed: 0 }));
  const slot = (ms) => { const k = Math.floor(((ms || 0) + OFF) / DAY) - d0; return k >= 0 && k < days ? series[k] : null; };
  for (const a of all) { const r = slot(a.created || a.ts_first); if (r) r.raised++; if (isClosed(a.status) && a.closed_at) { const c = slot(a.closed_at); if (c) c.closed++; } }
  const open = all.filter((a) => !isClosed(a.status)).length;
  const active = series.filter((s) => s.raised || s.closed).length, recent = series.slice(-14), net = recent.map((s) => s.raised - s.closed);
  const out = { series, open, days_with_data: active };
  const closeRate = recent.reduce((a, s) => a + s.closed, 0) / 14, raiseRate = recent.reduce((a, s) => a + s.raised, 0) / 14;
  out.raised_per_day = r1(raiseRate); out.closed_per_day = r1(closeRate);
  if (active < 7) { out.forecast = null; out.note = 'the backlog forecast needs 7 days with alerts (' + active + ' so far)'; return out; }
  const n = net.length, mx = (n - 1) / 2, my = net.reduce((a, b) => a + b, 0) / n, sxx = net.reduce((a, _, i) => a + (i - mx) ** 2, 0);
  const b = sxx ? net.reduce((a, y, i) => a + (i - mx) * (y - my), 0) / sxx : 0, a0 = my - b * mx;
  const se = Math.sqrt(net.reduce((s, y, i) => s + (y - (a0 + b * i)) ** 2, 0) / Math.max(1, n - 2));
  let level = open; out.forecast = [];
  for (let k = 1; k <= 7; k++) { level += a0 + b * (n - 1 + k); const band = 1.28 * se * Math.sqrt(k); out.forecast.push({ day: new Date((d0 + days - 1 + k) * DAY).toISOString().slice(0, 10), open: Math.max(0, Math.round(level)), low: Math.max(0, Math.round(level - band)), high: Math.max(0, Math.round(level + band)) }); }
  out.net_per_day = r1(my); out.trend = my > 0.5 ? 'growing' : my < -0.5 ? 'shrinking' : 'steady';
  out.days_to_clear = closeRate > raiseRate && open ? Math.ceil(open / (closeRate - raiseRate)) : null;
  out.note = out.trend === 'growing' ? 'more alerts are raised than closed: the backlog grows by about ' + r1(my) + ' a day' : out.days_to_clear ? 'at the current closing rate the open alerts are cleared in about ' + out.days_to_clear + ' days' : 'raising and closing are about level';
  return out;
}

function sla(open, policy, now) {
  const P = policy || {}, name = (s) => (s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low');
  const items = [];
  for (const a of open) {
    const p = P[name(a.severity || 0)]; if (!p) continue;
    const start = a.created || a.ts_first; if (!start) continue;
    const acked = !!(a.assignee || a.status === 'acknowledged' || a.status === 'investigating' || a.acked_at);
    const clocks = [];
    if (!acked) clocks.push({ kind: 'acknowledge', due: start + p.ack_h * H, len: p.ack_h * H });
    clocks.push({ kind: 'resolve', due: start + p.resolve_h * H, len: p.resolve_h * H });
    for (const c of clocks) { const left = c.due - now, frac = left / c.len; if (left < 0 || frac < 0.25) items.push({ id: a.id, rule: a.rule_name || a.rule_id, severity: a.severity, priority: a.priority, kind: c.kind, due: new Date(c.due).toISOString(), hours_left: r1(left / H), breached: left < 0, assignee: a.assignee || '' }); }
  }
  items.sort((x, y) => x.hours_left - y.hours_left);
  return { breached: items.filter((x) => x.breached).length, at_risk: items.filter((x) => !x.breached).length, items: items.slice(0, 25), policy: Object.fromEntries(Object.entries(P).map(([k, v]) => [k, { ack_h: v.ack_h, resolve_h: v.resolve_h }])) };
}

function precedent(open, closed) {
  const idx = new Map();
  for (const a of closed) { const k = a.rule_id + '|'; for (const e of a.entities || []) { const key = k + e; (idx.get(key) || idx.set(key, []).get(key)).push(a); } }
  const out = {};
  for (const a of open) {
    const seen = new Set(), hit = [];
    for (const e of a.entities || []) for (const c of idx.get(a.rule_id + '|' + e) || []) if (!seen.has(c.id)) { seen.add(c.id); hit.push(c); }
    if (hit.length < 3) continue;
    const cnt = { tp: 0, fp: 0, benign: 0 }; for (const c of hit) { if (c.status === 'closed-true-positive') cnt.tp++; else if (c.status === 'closed-false-positive') cnt.fp++; else cnt.benign++; }
    const nn = hit.length, sh = (k) => Math.round(100 * (cnt[k] + 1) / (nn + 3)), shares = { tp: sh('tp'), fp: sh('fp'), benign: sh('benign') };
    const likely = Object.keys(shares).sort((x, y) => shares[y] - shares[x])[0];
    out[a.id] = { n: nn, counts: cnt, shares, likely, why: 'the same rule on ' + (a.entities || []).slice(0, 2).join(', ') + ' was closed ' + nn + ' times: ' + cnt.tp + ' true positive, ' + cnt.fp + ' false positive, ' + cnt.benign + ' benign' };
  }
  return out;
}

function histogram(open) { const h = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, n: 0 })); for (const a of open) h[Math.min(9, Math.floor((a.priority || 0) / 10))].n++; return h; }

const LOG2 = (x) => Math.log(x) / Math.LN2;
function closerOf(a) {   // the person who closed it and the note they gave, from the alert's own history
  const h = (a.history || []).filter((x) => x.action === 'status' && /→closed-/.test(String(x.detail || ''))).pop();
  if (!h) return null; const d = String(h.detail || ''), i = d.indexOf(': ');
  return { by: h.by || '', at: h.at || a.closed_at || null, note: i >= 0 ? d.slice(i + 2).slice(0, 300) : '' };
}
function owners(open, closed, isHuman) {
  const load = new Map(); for (const a of open) if (a.assignee) load.set(a.assignee, (load.get(a.assignee) || 0) + 1);
  const exp = new Map();
  for (const a of closed) { const c = closerOf(a); if (!c || !isHuman(c.by)) continue; const k = a.rule_id + '|' + c.by; exp.set(k, (exp.get(k) || 0) + 1); }
  const byRule = new Map(); for (const k of exp.keys()) { const [r, u] = [k.slice(0, k.indexOf('|')), k.slice(k.indexOf('|') + 1)]; (byRule.get(r) || byRule.set(r, []).get(r)).push(u); }
  const out = {};
  for (const a of open) {
    if (a.assignee) continue;
    const cand = (byRule.get(a.rule_id) || []).map((u) => { const n = exp.get(a.rule_id + '|' + u), l = load.get(u) || 0; return { user: u, closures: n, load: l, score: Math.round((LOG2(1 + n) - 0.15 * l) * 100) / 100 }; })
      .sort((x, y) => y.score - x.score || x.load - y.load);
    if (!cand.length) continue;
    const c = cand[0]; out[a.id] = { user: c.user, closures: c.closures, load: c.load, why: c.user + ' closed ' + c.closures + ' alert(s) of this rule in 90 days and holds ' + c.load + ' open now', others: cand.slice(1, 3).map((x) => x.user) };
  }
  return out;
}
function tuning(closed, now) {
  const by = new Map();
  for (const a of closed) { if ((a.closed_at || 0) < now - 30 * DAY) continue; (by.get(a.rule_id) || by.set(a.rule_id, []).get(a.rule_id)).push(a); }
  const out = [];
  for (const [rule, L] of by) {
    if (L.length < 5) continue;
    const noise = L.filter((a) => a.status !== 'closed-true-positive'), tp = L.length - noise.length, rate = Math.round(100 * (noise.length + 1) / (L.length + 2));
    if (rate < 80) continue;
    const ent = new Map(); for (const a of noise) for (const e of new Set(a.entities || [])) ent.set(e, (ent.get(e) || 0) + 1);
    const top = [...ent.entries()].sort((x, y) => y[1] - x[1])[0], share = top ? Math.round(100 * top[1] / noise.length) : 0;
    out.push({ rule_id: rule, rule_name: L[0].rule_name || rule, closures: L.length, true_positive: tp, noise_pct: rate, entity: share >= 60 ? top[0] : null, entity_share: share >= 60 ? share : null,
      why: noise.length + ' of ' + L.length + ' closures in 30 days were false positive or benign' + (share >= 60 ? '; ' + share + '% of them on ' + top[0] + ' - consider an exclusion for it' : '; no single entity dominates - review the rule logic') + (tp ? ' (' + tp + ' true positive: keep it on)' : '') });
  }
  return out.sort((a, b) => b.closures - a.closures).slice(0, 10);
}
function surge(all, now) {
  const H = 3600000, cur = all.filter((a) => (a.created || a.ts_first || 0) > now - H);
  const past = []; for (let d = 1; d <= 14; d++) { const t1 = now - d * DAY; past.push(all.filter((a) => { const c = a.created || a.ts_first || 0; return c > t1 - H && c <= t1; }).length); }
  const withData = past.filter((x) => x > 0).length, n = cur.length;
  const rules = new Map(); for (const a of cur) rules.set(a.rule_name || a.rule_id, (rules.get(a.rule_name || a.rule_id) || 0) + 1);
  const top = [...rules.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([k, v]) => ({ rule: k, alerts: v }));
  const sorted = past.slice().sort((x, y) => x - y), md = (sorted[6] + sorted[7]) / 2, mad = (() => { const d = past.map((x) => Math.abs(x - md)).sort((x, y) => x - y); return (d[6] + d[7]) / 2; })();
  if (withData < 7) return { last_hour: n, usual: null, surge: false, top, why: 'the hourly baseline needs 7 days with alerts at this hour (' + withData + ' so far)' };
  const z = mad ? Math.round(0.6745 * (n - md) / mad * 10) / 10 : (n > md ? Infinity : 0), flag = n >= 5 && (z >= 3.5);
  return { last_hour: n, usual: md, z: Number.isFinite(z) ? z : null, surge: flag, top,
    why: flag ? n + ' alerts in the last hour against a usual ' + md + ' at this hour - driven by ' + top.map((x) => x.rule + ' (' + x.alerts + ')').join(', ') : n + ' alerts in the last hour, usual ' + md + ' at this hour' };
}
const words = (a) => { const w = new Set(); for (const t of shapeOf(a.summary || a.rule_name || '').split(/[^a-z<>#_]+/)) if (t.length > 2) w.add(t); for (const e of a.entities || []) w.add('e:' + e); return w; };
function shapeOf(s) { return String(s || '').toLowerCase().replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<ip>').replace(/\b[0-9a-f]{12,}\b/g, '<hex>').replace(/\d+/g, '#'); }
function similar(open, closed, max = 200) {
  const C = closed.map((a) => ({ a, w: words(a) })).filter((x) => x.w.size), out = {};
  for (const o of open.slice(0, max)) {
    const w = words(o); if (!w.size) continue;
    const hits = [];
    for (const c of C) { let inter = 0; for (const t of w) if (c.w.has(t)) inter++; if (!inter) continue; const j = inter / (w.size + c.w.size - inter); if (j >= 0.5) hits.push({ c: c.a, j }); }
    if (!hits.length) continue;
    out[o.id] = hits.sort((x, y) => y.j - x.j).slice(0, 3).map((h) => { const cl = closerOf(h.c) || {}; return { id: h.c.id, rule_name: h.c.rule_name || h.c.rule_id, same_rule: h.c.rule_id === o.rule_id, similarity: Math.round(h.j * 100), status: h.c.status, closed_by: cl.by || '', note: cl.note || '', closed_at: h.c.closed_at || null }; });
  }
  return out;
}

module.exports = { campaigns, flow, sla, precedent, histogram, owners, tuning, surge, similar, closerOf, tacticsOf, KILL };
