// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * XDR machine learning (GET {P}/xdr/intel, xdr.js intel()) - learned from the SIEM's own correlated incidents over 90 days, nothing
 * else; every figure says how much history it stands on.
 *   next       a first-order Markov chain over the ATT&CK tactics of past incidents, in the order their alerts fired: for an open
 *              incident, the tactics most likely to come next after its latest one (Laplace-smoothed over the tactics seen), with
 *              the number of observed transitions; only tactics observed after it and not already on the incident's path are listed. With fewer than 3 transitions out of that tactic it falls back to the ATT&CK
 *              kill-chain order and says it is a prior, not something learned here.
 *   similar    closed past incidents that look like an open one (Jaccard over rules, domains and tactics, 0.35 or more), with how
 *              their alerts were closed - "the last three like this were false positives" is a lead, not a verdict.
 *   trend      incidents first seen per Riyadh day for 30 days (all / cross-domain), and today against the 29 days before (robust
 *              z, 14+ days with incidents).
 */
const DAY = 86400000, OFF = 3 * 3600000;
const KILL = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
const med = (a) => { if (!a.length) return 0; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const jac = (a, b) => { if (!a.size || !b.size) return 0; let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i); };

// sequences: arrays of tactic keys in firing order (consecutive repeats collapsed)
function learnChain(sequences) {
  const T = new Map(); let total = 0;
  for (const s of sequences) for (let i = 1; i < s.length; i++) { const a = s[i - 1], b = s[i]; if (a === b) continue; const m = T.get(a) || T.set(a, new Map()).get(a); m.set(b, (m.get(b) || 0) + 1); total++; }
  return { T, total, states: new Set([...T.keys(), ...[...T.values()].flatMap((m) => [...m.keys()])]) };
}
function predictNext(chain, last, name, path) {
  const done = new Set(path || [last]), row = chain.T.get(last), seen = row ? [...row.values()].reduce((a, b) => a + b, 0) : 0;
  if (seen >= 3) {
    const S = [...chain.states].filter((s) => s !== last), k = S.length || 1;
    // only tactics actually observed after this one, and not already on the incident's path; Laplace-smoothed shares
    const out = S.filter((s) => (row.get(s) || 0) > 0 && !done.has(s)).map((s) => ({ tactic: s, name: name(s), p: Math.round(100 * ((row.get(s) || 0) + 1) / (seen + k)), observed: row.get(s) })).sort((a, b) => b.p - a.p).slice(0, 3);
    return { learned: true, from: last, transitions: seen, next: out, why: 'after ' + name(last) + ', past incidents here went to ' + out.filter((x) => x.observed).map((x) => name(x.tactic) + ' (' + x.observed + ')').join(', ') + ' - ' + seen + ' observed transition(s)' };
  }
  const i = KILL.indexOf(last), nx = i >= 0 ? KILL.slice(i + 1).filter((t) => !done.has(t)).slice(0, 2) : [];
  return { learned: false, from: last, transitions: seen, next: nx.map((s) => ({ tactic: s, name: name(s), p: null, observed: 0 })), why: nx.length ? 'not enough history after ' + name(last) + ' (' + seen + ' transition(s)): the ATT&CK kill-chain order suggests ' + nx.map(name).join(' then ') + ' - a prior, not learned here' : 'no prediction after ' + name(last) };
}
function similarPast(inc, past, verdictOf) {
  const sig = (i) => new Set([...(i.rules || []).map((r) => 'r:' + r), ...Object.keys(i.domains || {}).map((d) => 'd:' + d), ...(i.tactics || []).map((t) => 't:' + t)]);
  const me = sig(inc);
  return past.filter((p) => p.id !== inc.id).map((p) => ({ p, j: jac(me, sig(p)) })).filter((x) => x.j >= 0.35).sort((a, b) => b.j - a.j).slice(0, 3)
    .map(({ p, j }) => Object.assign({ id: p.id, title: p.title, similarity: Math.round(j * 100), first: p.first, score: p.score }, verdictOf(p)));
}
function trend(incs, now) {
  const days = 30, d0 = Math.floor((now + OFF) / DAY) - days + 1, series = Array.from({ length: days }, (_, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), incidents: 0, cross_domain: 0 }));
  for (const i of incs) { const k = Math.floor(((i.first || 0) + OFF) / DAY) - d0; if (k >= 0 && k < days) { series[k].incidents++; if (i.domain_count > 1) series[k].cross_domain++; } }
  const past = series.slice(0, -1).map((x) => x.incidents), withData = past.filter((x) => x > 0).length, today = series[days - 1].incidents;
  if (withData < 14) return { series, judged: false, why: 'today is compared with the month from 14 days with incidents (' + withData + ' so far)' };
  const m = med(past), mad = med(past.map((x) => Math.abs(x - m))), z = mad ? Math.round(0.6745 * (today - m) / mad * 10) / 10 : (today > m ? Infinity : 0);
  return { series, judged: true, usual: m, today, z: Number.isFinite(z) ? z : null, unusual: today >= 3 && z >= 3.5, why: today + ' incident(s) today against a usual ' + m + ' a day' };
}

module.exports = { learnChain, predictNext, similarPast, trend, KILL };
