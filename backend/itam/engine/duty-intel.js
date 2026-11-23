// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Engineering Team intelligence - learned from the duty desk's own work items (duty-core.js). The SAME file runs in IT Asset
 * Management (engine/duty-intel.js) and the SIEM (engine/duty/duty-intel.js); a test fails if the two copies differ. Pure: no I/O.
 *   per engineer  open / resolved in 30 days; MTTR (median detection -> resolved) now against the 30 days before; VERIFIED-fix rate (of
 *                 the items a change fixed, how many a fresh re-check confirmed); PRECISION = 1 - the Beta(1,1) rate of people closing its
 *                 items as false positives (3+ closures, otherwise withheld); reopen rate; items past their SLA; backlog per day for 30
 *                 days with a least-squares 7-day projection; an unusual day (robust z of items opened, 14 days).
 *   trust         0-100 per engineer, every point itemised: false positives, re-opened fixes, items past SLA, a rising backlog, fixes
 *                 never verified, a patrol that has stopped. It is how far a person can rely on what the engineer raises - not a grade.
 *   needs you     the open items that wait for a person (needs-human, a change waiting approval or to be applied, unowned and old),
 *                 ranked by severity x time over SLA x re-opened, each with its reason.
 *   noisy checks  a kind of finding an engineer raises that people close as false positive 3+ times, or that re-opens 3+ times: tune it.
 *   overlaps      one target worked by two or more engineers at once - one problem, two queues.
 *   recurring     items re-opened twice or more: the fix does not hold.
 * analyse({ items, engineers:[{id,name}], now, source }) -> { engineers[], team, needs[], noisy[], overlaps[], recurring[] }
 */
const DAY = 86400000, H = 3600000;
const SEVW = { critical: 4, high: 3, medium: 2, low: 1 }, SLA_H = { critical: 24, high: 72, medium: 168, low: 720 };
const TERMINAL = { resolved: 1, closed: 1 };
const WAITING = { 'needs-human': 'needs a person', 'change-proposed': 'change waiting approval', 'change-approved': 'approved change waiting to be applied', 'awaiting-approval': 'waiting approval', 'approval-pending': 'waiting approval' };
const r1 = (x) => Math.round(x * 10) / 10;
const median = (a) => { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; };
const beta = (k, n) => (k + 1) / (n + 2);
function robustZ(vals, x) { if (vals.length < 7) return null; const md = median(vals), mad = median(vals.map((v) => Math.abs(v - md))) || 1; return { z: r1(0.6745 * (x - md) / mad), usual: md }; }
function slope(ys) { const n = ys.length; if (n < 7) return null; const mx = (n - 1) / 2, my = ys.reduce((a, b) => a + b, 0) / n, sxx = ys.reduce((a, _, i) => a + (i - mx) ** 2, 0); return ys.reduce((a, y, i) => a + (i - mx) * (y - my), 0) / sxx; }
const ts = (v) => { const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) ? t : null; };
const dayOf = (t) => new Date(t + 3 * H).toISOString().slice(0, 10);   // Riyadh

function analyse({ items = [], engineers = [], now = Date.now(), source = '' }) {
  const names = {}; for (const e of engineers) names[e.id] = e.name || e.id;
  for (const it of items) if (!names[it.engineer]) names[it.engineer] = it.engineer_name || it.engineer;
  const byEng = {}; for (const it of items) (byEng[it.engineer] = byEng[it.engineer] || []).push(it);
  const out = [];
  for (const id of Object.keys(names)) {
    const L = byEng[id] || [], open = L.filter((x) => !TERMINAL[x.status]);
    const det = (x) => ts(x.detected_at) || ts(x.first_seen), res = (x) => ts(x.resolved_at) || (x.status === 'closed' ? ts(x.closed_at) || ts(x.updated) : null);
    const done = (from, to) => L.filter((x) => TERMINAL[x.status] && res(x) != null && res(x) >= from && res(x) < to);
    const d30 = done(now - 30 * DAY, now + 1), dPrev = done(now - 60 * DAY, now - 30 * DAY);
    const mttr = (list) => { const v = list.map((x) => (res(x) - det(x)) / H).filter((h) => h >= 0); return v.length ? r1(median(v)) : null; };
    const closedByPeople = L.filter((x) => x.status === 'closed' && x.close_code), fp = closedByPeople.filter((x) => x.close_code === 'false-positive').length;
    const changed = L.filter((x) => (x.changes || []).length || x.resolution === 'verified-fixed'), verified = changed.filter((x) => x.resolution === 'verified-fixed').length;
    const reopened = L.filter((x) => (x.reopened || 0) > 0).length;
    const overSla = open.filter((x) => det(x) != null && (now - det(x)) / H > (SLA_H[x.severity] || 168));
    // backlog per day: opened on or before the day and not yet resolved at its end
    const backlog = []; for (let d = 29; d >= 0; d--) { const end = now - d * DAY; backlog.push({ date: dayOf(end), value: L.filter((x) => det(x) != null && det(x) <= end && (res(x) == null || res(x) > end) && !(TERMINAL[x.status] && res(x) == null)).length }); }
    const sl = slope(backlog.map((b) => b.value)), proj = sl == null ? null : Math.max(0, Math.round(backlog[backlog.length - 1].value + sl * 7));
    const perDay = {}; for (const x of L) { const t = det(x); if (t != null && now - t <= 15 * DAY) perDay[dayOf(t)] = (perDay[dayOf(t)] || 0) + 1; }
    const earlier = []; for (let d = 1; d <= 14; d++) earlier.push(perDay[dayOf(now - d * DAY)] || 0);
    const z = robustZ(earlier, perDay[dayOf(now)] || 0), unusual = z && z.z >= 3.5 && (perDay[dayOf(now)] || 0) >= 3 ? { today: perDay[dayOf(now)], usual: z.usual } : null;
    const lastSeen = L.reduce((m, x) => Math.max(m, ts(x.last_seen) || 0), 0);
    const precision = closedByPeople.length >= 3 ? Math.round(100 * (1 - beta(fp, closedByPeople.length))) : null;
    const items0 = [], add = (p, l) => { if (p > 0) items0.push({ points: -Math.round(p), label: l }); };
    if (precision != null) add((100 - precision) * 0.4, fp + ' of ' + closedByPeople.length + ' items people closed were false positives (precision ' + precision + ' %)');
    add(L.length ? Math.min(20, 100 * reopened / L.length * 0.5) : 0, reopened + ' item(s) came back after being fixed or cleared');
    add(open.length ? Math.min(20, 100 * overSla.length / open.length * 0.3) : 0, overSla.length + ' of ' + open.length + ' open item(s) past their SLA');
    if (sl != null && sl > 0.3) add(Math.min(10, sl * 5), 'backlog rising ' + r1(sl) + ' a day');
    if (changed.length >= 3 && verified / changed.length < 0.5) add(10, 'only ' + verified + ' of ' + changed.length + ' fixes confirmed by a fresh re-check');
    if (L.length && lastSeen && now - lastSeen > 2 * DAY && open.length) add(15, 'nothing seen for ' + Math.round((now - lastSeen) / DAY) + ' day(s) with work still open - is the patrol running?');
    const trust = L.length ? Math.max(0, 100 + items0.reduce((n, i) => n + i.points, 0)) : null;
    out.push({ id, name: names[id], source, open: open.length, critical_high: open.filter((x) => SEVW[x.severity] >= 3).length, resolved_30d: d30.length, resolved_prev: dPrev.length,
      mttr_h: mttr(d30), mttr_prev_h: mttr(dPrev), precision, fp, closed_by_people: closedByPeople.length, verified, changed: changed.length, verified_pct: changed.length ? Math.round(100 * verified / changed.length) : null,
      reopen_pct: L.length ? Math.round(100 * reopened / L.length) : null, over_sla: overSla.length, backlog, backlog_slope: sl == null ? null : r1(sl), backlog_7d: proj, unusual, trust, trust_items: items0,
      why: trust == null ? 'no work item yet - not measured' : items0.length ? items0.map((i) => i.points + ' ' + i.label).join('; ') : 'nothing lowers it' });
  }
  // needs you
  const needs = items.filter((x) => !TERMINAL[x.status]).map((x) => {
    const age = (now - (ts(x.detected_at) || ts(x.first_seen) || now)) / H, sla = SLA_H[x.severity] || 168, over = Math.max(0, age / sla);
    const wait = WAITING[x.status] || (!x.owner && age > 24 ? 'unowned for ' + Math.round(age / 24) + ' day(s)' : null); if (!wait) return null;
    const score = r1((SEVW[x.severity] || 1) * (1 + Math.min(over, 3)) * (1 + 0.5 * Math.min(x.reopened || 0, 3)));
    return { id: x.id, engineer: x.engineer, engineer_name: names[x.engineer], source, severity: x.severity, title: x.title, status: x.status, target: x.target && x.target.name, age_h: Math.round(age), score,
      why: wait + ' · ' + x.severity + ' · ' + (over >= 1 ? 'past its ' + sla + ' h SLA by ' + Math.round(age - sla) + ' h' : Math.round(age) + ' h of ' + sla + ' h SLA') + ((x.reopened || 0) ? ' · re-opened ' + x.reopened + 'x' : '') };
  }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 40);
  // noisy checks
  const kinds = {}; for (const x of items) { const k = x.engineer + '|' + (x.kind || 'other'); const g = kinds[k] = kinds[k] || { engineer: x.engineer, engineer_name: names[x.engineer], kind: x.kind || 'other', fp: 0, reopened: 0, n: 0 }; g.n++; if (x.close_code === 'false-positive') g.fp++; g.reopened += x.reopened || 0; }
  const noisy = Object.values(kinds).filter((g) => g.fp >= 3 || g.reopened >= 3).map((g) => Object.assign(g, { source, why: (g.fp >= 3 ? g.fp + ' of ' + g.n + ' closed as false positive' : '') + (g.fp >= 3 && g.reopened >= 3 ? '; ' : '') + (g.reopened >= 3 ? 're-opened ' + g.reopened + ' times' : '') + ' - tune the check or its threshold' })).sort((a, b) => b.fp + b.reopened - a.fp - a.reopened);
  // overlaps: one target, two engineers
  const byT = {}; for (const x of items.filter((y) => !TERMINAL[y.status] && y.target && (y.target.id || y.target.name))) { const k = String(x.target.id || x.target.name).toLowerCase(); (byT[k] = byT[k] || []).push(x); }
  const overlaps = Object.values(byT).filter((L) => new Set(L.map((x) => x.engineer)).size >= 2).map((L) => ({ target: L[0].target.name || L[0].target.id, source, engineers: [...new Set(L.map((x) => names[x.engineer]))], items: L.map((x) => ({ id: x.id, engineer: names[x.engineer], title: x.title, severity: x.severity })),
    why: 'worked by ' + [...new Set(L.map((x) => names[x.engineer]))].join(' and ') + ' - one problem may be in two queues; agree one owner' }));
  const recurring = items.filter((x) => (x.reopened || 0) >= 2).map((x) => ({ id: x.id, engineer_name: names[x.engineer], source, title: x.title, severity: x.severity, reopened: x.reopened, status: x.status, why: 're-opened ' + x.reopened + ' times - the fix does not hold; look for the cause' })).sort((a, b) => b.reopened - a.reopened).slice(0, 30);
  const scored = out.filter((e) => e.trust != null);
  const team = { engineers: out.length, open: out.reduce((n, e) => n + e.open, 0), over_sla: out.reduce((n, e) => n + e.over_sla, 0), resolved_30d: out.reduce((n, e) => n + e.resolved_30d, 0), needs_you: needs.length,
    trust: scored.length ? Math.round(scored.reduce((n, e) => n + e.trust * Math.max(1, e.open + e.resolved_30d), 0) / scored.reduce((n, e) => n + Math.max(1, e.open + e.resolved_30d), 0)) : null };
  return { generated_at: new Date(now).toISOString(), source, engineers: out.sort((a, b) => (a.trust == null) - (b.trust == null) || a.trust - b.trust), team, needs, noisy, overlaps, recurring };
}
module.exports = { analyse, SLA_H };
