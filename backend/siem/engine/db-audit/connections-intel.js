// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Application Connections intelligence (prefix {P} = /api/soc) - the "✦ AI / ML" part of Application Connections. It learns from
 * 14 days of the app-session readings the SIEM already holds (one per pass: sessions per service / machine / program / database
 * user) and adds to connections.js what one snapshot cannot say. Read-only; every verdict says what it rests on.
 *   baseline   each application's sessions for each hour of the day (Riyadh) from the earlier days: median and p90 (3+ days at
 *              that hour) - drawn behind its last 24 hours.
 *   verdicts   MISSING - usually connected at this hour (seen at it on 3+ of the earlier days) and absent now: an outage of that
 *              application or its path, more urgent than an app that simply stopped for the day; LEAK - sessions rising through the
 *              last 12 hours (least squares, 6+ hours), above the usual p90, with idle sessions piling up: a pool not returning
 *              connections, heading for the processes limit; SPIKE - over 3x the usual p90 now; NEW - a client (machine + program +
 *              user) never seen before today: confirm it is expected (a new server, or someone else using an application account).
 *   accounts   one database user used from 3+ machines or 3+ programs: a shared account - harder to trace and to rotate.
 *   refusals   the listener's refusal rate per client (refused / attempts), 10+ attempts.
 *   map        the dependency map: client machines -> services -> this database, and its database links to remote databases.
 *   health     0-100 itemised.
 * GET {P}/db/oracle/connections/intel?instance=    operator (machine names, programs and database users - as the page)
 */
const { wrap, HttpError } = require('../soc/routeutil');

const H = 3600000, DAY = 86400000;
const r1 = (x) => Math.round(x * 10) / 10;
const median = (a) => { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; };
const pct = (a, p) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * (s.length - 1)))]; };
const hourOf = (t) => new Date(t + 3 * H).getUTCHours(), dayOf = (t) => new Date(t + 3 * H).toISOString().slice(0, 10);
const keyOf = (a) => [a.service, a.machine, a.program, a.db_user].join('|');

/* pure: the current view (connections.js) + hourly history rows [{k, h (ms, hour start), s (max sessions), idle}] -> intelligence */
function analyse({ view, history = [], now = Date.now() }) {
  const t = now, today = dayOf(t), hr = hourOf(t), apps = (view && view.applications) || [];
  const byKey = new Map(); for (const r of history) { const k = r.k; (byKey.get(k) || byKey.set(k, []).get(k)).push({ t: r.h, s: Number(r.s) || 0, idle: r.idle == null ? null : Number(r.idle) }); }
  const out = [];
  for (const a of apps) {
    const k = keyOf(a), H0 = (byKey.get(k) || []).sort((x, y) => x.t - y.t), earlier = H0.filter((p) => dayOf(p.t) !== today);
    const atHour = earlier.filter((p) => hourOf(p.t) === hr), daysAtHour = new Set(atHour.filter((p) => p.s > 0).map((p) => dayOf(p.t))).size;
    const allDays = new Set(earlier.map((p) => dayOf(p.t))).size;
    const base = atHour.length >= 3 ? { median: r1(median(atHour.map((p) => p.s))), p90: r1(pct(atHour.map((p) => p.s), 0.9)), days: daysAtHour } : null;
    const r = { key: k, service: a.service, machine: a.machine, program: a.program, db_user: a.db_user, state: a.state, sessions: a.sessions, max_idle_s: a.max_idle_s, baseline: base, verdicts: [] };
    const V = (verdict, severity, why) => r.verdicts.push({ verdict, severity, why });
    if (!H0.length || (allDays === 0 && earlier.length === 0)) { if (!H0.some((p) => dayOf(p.t) !== today)) V('new', 'medium', 'never seen in the 14 days before today - confirm this client is expected (a new server, or another program using ' + a.db_user + ')'); }
    if (a.state === 'dropped' && base && daysAtHour >= 3 && base.median > 0) V('missing', 'high', 'usually connected at ' + String(hr).padStart(2, '0') + ':00 (' + daysAtHour + ' days, about ' + base.median + ' sessions) - no session now');
    const last12 = H0.filter((p) => t - p.t <= 12 * H);
    if (a.state === 'connected' && last12.length >= 6) {
      const n = last12.length, mx = (n - 1) / 2, my = last12.reduce((s, p) => s + p.s, 0) / n, sxx = last12.reduce((s, _, i) => s + (i - mx) ** 2, 0), sl = last12.reduce((s, p, i) => s + (i - mx) * (p.s - my), 0) / sxx;
      const rising = last12.slice(1).filter((p, i) => p.s >= last12[i].s).length / (n - 1);
      if (sl >= 1 && rising >= 0.8 && (!base || a.sessions > base.p90) && (a.max_idle_s == null || a.max_idle_s >= 600)) V('leak', 'high', 'sessions rising for ' + n + ' hours (+' + r1(sl) + ' an hour, ' + last12[0].s + ' -> ' + a.sessions + ')' + (a.max_idle_s != null ? ', idle sessions up to ' + Math.round(a.max_idle_s / 60) + ' min' : '') + ' - a pool not returning connections');
    }
    // a spike only when a leak does not already explain the count
    if (!r.verdicts.some((x) => x.verdict === 'leak') && a.state === 'connected' && base && base.p90 > 0 && a.sessions > 3 * base.p90 && a.sessions - base.p90 >= 10) V('spike', 'medium', a.sessions + ' sessions against a usual ' + base.p90 + ' at this hour (p90)');
    r.last24 = H0.filter((p) => t - p.t <= DAY).map((p) => ({ t: p.t, s: p.s }));
    r.band = base ? Array.from({ length: 24 }, (_, h) => { const L = earlier.filter((p) => hourOf(p.t) === h).map((p) => p.s); return L.length >= 3 ? { h, median: r1(median(L)), p90: r1(pct(L, 0.9)) } : { h, median: null, p90: null }; }) : null;
    out.push(r);
  }
  // shared accounts
  const users = new Map(); for (const a of apps.filter((x) => x.state === 'connected')) { const u = users.get(a.db_user) || { db_user: a.db_user, machines: new Set(), programs: new Set(), sessions: 0 }; u.machines.add(a.machine); u.programs.add(a.program); u.sessions += a.sessions; users.set(a.db_user, u); }
  const shared = [...users.values()].filter((u) => u.machines.size >= 3 || u.programs.size >= 3).map((u) => ({ db_user: u.db_user, machines: u.machines.size, programs: u.programs.size, sessions: u.sessions, why: u.db_user + ' is used from ' + u.machines.size + ' machine(s) and ' + u.programs.size + ' program(s) - a shared account is harder to trace and to rotate; give each application its own user' })).sort((a, b) => b.machines + b.programs - a.machines - a.programs);
  // refusal rates
  const refusals = ((view && view.listener) || []).filter((c) => c.ok + c.refused >= 10 && c.refused > 0).map((c) => ({ client_host: c.client_host, service: c.service, attempts: c.ok + c.refused, refused: c.refused, rate_pct: Math.round(100 * c.refused / (c.ok + c.refused)), top: (c.reasons || []).sort((x, y) => y.n - x.n)[0] || null })).sort((a, b) => b.rate_pct - a.rate_pct);
  // dependency map
  const svc = new Map(), mach = new Map();
  for (const a of apps.filter((x) => x.state === 'connected')) { mach.set(a.machine, (mach.get(a.machine) || 0) + a.sessions); const s = svc.get(a.service) || { service: a.service, sessions: 0, from: new Map() }; s.sessions += a.sessions; s.from.set(a.machine, (s.from.get(a.machine) || 0) + a.sessions); svc.set(a.service, s); }
  const map = { database: view && view.instance, machines: [...mach.entries()].map(([m, n]) => ({ machine: m, sessions: n })).sort((a, b) => b.sessions - a.sessions).slice(0, 14),
    services: [...svc.values()].map((s) => ({ service: s.service, sessions: s.sessions, from: [...s.from.entries()].map(([m, n]) => ({ machine: m, sessions: n })) })).sort((a, b) => b.sessions - a.sessions).slice(0, 8),
    links: ((view && view.links) || []).map((l) => ({ link: l.link, remote_db: l.remote_db, verdict: l.verdict })).slice(0, 8) };
  const flagged = out.filter((r) => r.verdicts.length).sort((a, b) => { const w = (x) => Math.max(...x.verdicts.map((v) => (v.severity === 'high' ? 3 : v.severity === 'medium' ? 2 : 1))); return w(b) - w(a); });
  const items = [], add = (p, l) => { if (p) items.push({ points: -Math.round(p), label: l }); };
  const cnt = (v) => out.filter((r) => r.verdicts.some((x) => x.verdict === v)).length;
  add(Math.min(40, cnt('missing') * 20), cnt('missing') + ' application(s) missing at a time they are usually connected');
  add(Math.min(30, cnt('leak') * 15), cnt('leak') + ' connection pool(s) leaking');
  add(Math.min(15, cnt('spike') * 5), cnt('spike') + ' session spike(s)'); add(Math.min(10, cnt('new') * 2), cnt('new') + ' new client(s)');
  add(Math.min(20, refusals.filter((x) => x.rate_pct >= 20).length * 10), refusals.filter((x) => x.rate_pct >= 20).length + ' client(s) refused 20 %+ of the time');
  add(Math.min(10, shared.length * 3), shared.length + ' shared database account(s)');
  return { generated_at: new Date(t).toISOString(), instance: view && view.instance, health: apps.length ? { score: Math.max(0, 100 + items.reduce((n, i) => n + i.points, 0)), items } : { score: null, items: [], why: 'no application session reported - not measured' },
    counts: { missing: cnt('missing'), leak: cnt('leak'), spike: cnt('spike'), new: cnt('new'), shared: shared.length, refusing: refusals.filter((x) => x.rate_pct >= 20).length },
    learning: { days: new Set(history.filter((r) => dayOf(r.h) !== today).map((r) => dayOf(r.h))).size, applications: byKey.size }, flagged: flagged.slice(0, 40), apps: out.slice(0, 120), shared, refusals: refusals.slice(0, 20), map };
}

function register(api, deps, P) {
  const C = deps.dbConnections; if (!C || !deps.ch) return null;
  const db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const hist = (inst) => deps.ch.query(`/*q:cn_hist*/ SELECT fields['key'] AS k, toUnixTimestamp64Milli(toStartOfHour(ts)) AS h, max(toFloat64OrZero(fields['sessions'])) AS s, max(toFloat64OrNull(fields['max_idle_s'])) AS idle
    FROM ${db}.events WHERE ts >= now64(3) - INTERVAL 14 DAY AND has(tags, 'db-health') AND action = 'app-session' AND upper(fields['instance']) = {inst:String} GROUP BY k, h ORDER BY h LIMIT 200000`, { inst: { type: 'String', value: inst } }, { readonly: true, timeout_ms: 30000 });
  api.route('GET', `${P}/db/oracle/connections/intel`, wrap(deps, 'operator', async (ctx) => {
    const inst = String((ctx.query || {}).instance || '').toUpperCase();
    if (!/^[A-Z][A-Z0-9_$#.]{0,63}$/.test(inst)) throw new HttpError(400, 'instance must be an Oracle instance / DB_UNIQUE_NAME');
    const [view, history] = await Promise.all([C.view(inst), hist(inst)]);
    return ctx.ok(analyse({ view, history: (history || []).map((r) => ({ k: r.k, h: Number(r.h), s: Number(r.s), idle: r.idle })), now: (deps.now || Date.now)() }));
  }));
  return true;
}

module.exports = { analyse, register, keyOf };
