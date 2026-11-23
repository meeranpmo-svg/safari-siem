// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Alert scoring the SOC can explain - statistics learned from this SIEM's own alert history, no model, no external data.
 *
 *   learn(alerts[], { now, days = 30 })  → model: per rule volume, closures by reason, false-positive rate; per rule + entity
 *                                           first seen; clusters of near-identical open alerts
 *   score(alert, model, ctx)             → { priority 0-100, label, why[{points, factor, reason}], cluster, noise }
 *       ctx: { entities[] (xdr entitiesOf), ueba(entityKey) → tier|null, intel(alert) → [{value, list}], incident(alert) →
 *              {id, domains}|null }
 *
 * What it learns:
 *   noise       the rule's false-positive + benign share of its CLOSED alerts, Laplace-smoothed, and WITHHELD below
 *               MIN_CLOSURES closures - a rule nobody has closed yet is "not learned", never "noisy"
 *   rarity      the first time this rule fires for this entity in the window (new behaviour), and how rare the rule is
 *               across the estate (inverse frequency)
 *   clusters    open alerts of one rule whose summary is identical once digits / IPs / hex are masked are one cluster:
 *               the queue can collapse 40 copies into one row with "x 40"
 * An input the platform does not hold (UEBA off, no intel, no incident) contributes 0 points and says so - a low score can
 * then mean missing context, and the reason list shows which.
 */
const DAY = 86400000;
const MIN_CLOSURES = 3;
const SEV_POINTS = [0, 8, 18, 30, 40];   // severity 0-4
const TIER_POINTS = { critical: 20, high: 12, elevated: 5 };
const LABELS = [[70, 'act-now'], [45, 'investigate'], [25, 'review'], [0, 'low']];
const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');

// the summary with the parts that change between copies masked: IPs, hex ids, GUIDs, numbers
function shape(s) {
  return String(s || '').toLowerCase()
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '<guid>')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<ip>')
    .replace(/\b[0-9a-f]{12,}\b/g, '<hex>')
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ').trim().slice(0, 200);
}
const clusterKey = (a) => String(a.rule_id || '') + '|' + shape(a.summary || a.rule_name);

function learn(alerts, o = {}) {
  const now = o.now || Date.now(), from = now - (o.days || 30) * DAY;
  const rules = new Map(), firstSeen = new Map(), clusters = new Map();
  let total = 0;
  for (const a of alerts || []) {
    const t = a.ts_first || a.created || 0;
    if (t < from) continue;
    total++;
    const r = rules.get(a.rule_id) || { rule_id: a.rule_id, rule_name: a.rule_name || a.rule_id, n: 0, closed: 0, tp: 0, fp: 0, benign: 0 };
    r.n++;
    if (isClosed(a.status)) { r.closed++; if (a.status === 'closed-true-positive') r.tp++; else if (a.status === 'closed-false-positive') r.fp++; else r.benign++; }
    rules.set(a.rule_id, r);
    for (const e of (o.entitiesOf ? o.entitiesOf(a) : [])) {
      const k = a.rule_id + '\u0001' + e;
      if (!firstSeen.has(k) || firstSeen.get(k) > t) firstSeen.set(k, t);
    }
    if (!isClosed(a.status)) {
      const ck = clusterKey(a), c = clusters.get(ck) || { key: ck, ids: [], count: 0 };
      c.ids.push(a.id); c.count += Math.max(1, a.count || 1); clusters.set(ck, c);
    }
  }
  for (const r of rules.values()) {
    r.per_day = Math.round((r.n / (o.days || 30)) * 10) / 10;
    // smoothed share of closures that were not real (false positive or benign); withheld until enough closures exist
    r.noise = r.closed >= MIN_CLOSURES ? Math.round(((r.fp + r.benign + 0.5) / (r.closed + 1)) * 100) / 100 : null;
  }
  return { at: now, days: o.days || 30, total, rules, firstSeen, clusters };
}

function label(p) { for (const [min, l] of LABELS) if (p >= min) return l; return 'low'; }

function score(a, m, ctx = {}) {
  const why = [], add = (points, factor, reason) => { why.push({ points, factor, reason }); return points; };
  let p = 0;
  const sev = Math.max(0, Math.min(4, Math.floor(Number(a.severity) || 0)));
  p += add(SEV_POINTS[sev], 'severity', 'severity ' + sev + ' of 4');
  const r = m.rules.get(a.rule_id);
  // rarity: this entity has never triggered this rule before this alert (inside the learning window)
  const ents = ctx.entities || [];
  const fresh = ents.filter((e) => { const t = m.firstSeen.get(a.rule_id + '\u0001' + e); return t === undefined || t >= (a.ts_first || a.created || 0); });
  if (ents.length && fresh.length) p += add(15, 'rarity', 'first time this rule fires for ' + fresh.slice(0, 3).join(', ') + ' in ' + m.days + ' days');
  else if (ents.length) add(0, 'rarity', 'seen before for these entities');
  else add(0, 'rarity', 'no entity on the alert to compare');
  if (r && m.total) {
    const share = r.n / m.total;
    const pts = share < 0.01 ? 10 : share < 0.05 ? 5 : 0;
    if (pts) p += add(pts, 'rare rule', r.rule_name + ' is ' + (Math.round(share * 1000) / 10) + '% of alerts in ' + m.days + ' days');
  }
  // UEBA: the riskiest tier among the alert's entities
  if (ctx.ueba) {
    const tiers = ents.map((e) => ({ e, t: ctx.ueba(e) })).filter((x) => x.t);
    const top = tiers.sort((x, y) => (TIER_POINTS[y.t] || 0) - (TIER_POINTS[x.t] || 0))[0];
    if (top && TIER_POINTS[top.t]) p += add(TIER_POINTS[top.t], 'behaviour (UEBA)', top.e + ' is ' + top.t + ' risk in UEBA');
    else add(0, 'behaviour (UEBA)', ents.length ? 'no elevated UEBA risk for the entities' : 'no entity to look up');
  } else add(0, 'behaviour (UEBA)', 'UEBA not available');
  if (ctx.intel) {
    const hits = ctx.intel(a) || [];
    if (hits.length) p += add(15, 'threat intel', hits.slice(0, 3).map((h) => h.value + ' on ' + h.list).join('; '));
    else add(0, 'threat intel', 'no indicator on the intel lists');
  } else add(0, 'threat intel', 'threat intel not available');
  // asset criticality (soc/watchlist.js): the most important rated system the alert touches
  if (ctx.critical) {
    const cs = ents.map((e) => ctx.critical(e)).filter(Boolean).sort((x, y) => y.points - x.points);
    if (cs.length) p += add(cs[0].points, 'asset criticality', cs[0].value + ' is rated ' + (cs[0].level === 'crown_jewel' ? 'a crown jewel' : 'high criticality'));
    else add(0, 'asset criticality', ents.length ? 'no rated asset on the alert' : 'no entity to look up');
  }
  // the watchlist: an analyst asked to hear about one of the alert's entities
  if (ctx.watched) {
    const ws = ents.filter((e) => ctx.watched(e).length);
    if (ws.length) p += add(15, 'watchlist', ws.slice(0, 3).join(', ') + ' is on the watchlist');
  }
  if (ctx.incident) {
    const inc = ctx.incident(a);
    if (inc) p += add((inc.domains || []).length > 1 ? 12 : 6, 'correlation (XDR)', 'part of ' + inc.id + ((inc.domains || []).length > 1 ? ' across ' + inc.domains.join(', ') : ''));
  }
  // learned noise: a rule whose closures are mostly false positive / benign is pushed down (a true positive history pushes up)
  let noise = null;
  if (r && r.noise !== null) {
    noise = r.noise;
    const pts = Math.round(-25 * r.noise + (r.tp / Math.max(1, r.closed)) * 10);
    if (pts) p += add(pts, 'learned from closures', Math.round(r.noise * 100) + '% of ' + r.closed + ' closed ' + r.rule_name + ' alerts were false positive or benign' + (r.tp ? ', ' + r.tp + ' true positive' : ''));
  } else add(0, 'learned from closures', 'not learned yet: fewer than ' + MIN_CLOSURES + ' closures of this rule');
  const c = m.clusters.get(clusterKey(a));
  const priority = Math.max(0, Math.min(100, Math.round(p)));
  return { priority, label: noise !== null && noise >= 0.8 && priority < 45 ? 'likely-noise' : label(priority), why,
    noise, cluster: c ? { key: c.key, size: c.ids.length, events: c.count, lead: c.ids[0] } : null };
}

module.exports = { learn, score, shape, clusterKey, label, MIN_CLOSURES };
