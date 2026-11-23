// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Threats by department: the SOC's alerts attributed to the departments in Active Directory.
 *   GET {P}/threats/departments?days=7&min_severity=0      any signed-in role: totals per department (no names for viewers)
 *   GET {P}/threats/departments/:name?days=7               analyst+: the alerts behind one department (users, hosts)
 * How an alert is attributed (first that works, the method is kept on every alert so the page can say it):
 *   1. the alert's user (group / fields: user, else target_user)            → that account's AD department
 *   2. the enricher's AD department on the alert (fields.user_dept / target_dept)
 *   3. the alert's host → the account that last logged on to it interactively (Windows 4624, logon type 2/10/11, last
 *      14 days, from the log store)                                          → that account's department
 * Machine accounts (NAME$) are treated as hosts. Anything left is counted as "Not attributed" with the reason (no user
 * or host on the alert, account not in AD, AD account without a department, host with no recorded logon) - never
 * guessed. Departments come only from the AD sync; with no AD sync every alert is "Not attributed".
 * Risk = sum of severity weights (info 0, low 1, medium 3, high 7, critical 15), and per 100 enabled AD users of the
 * department so a big department does not look worse only because it is big.
 * PDPL: the department totals carry no names; the drill-down (named users) needs analyst and is audited.
 */
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

const W = [0, 1, 3, 7, 15];
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const NONE = 'Not attributed';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const DAY = 86400000;
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

const pick = (o, keys) => { for (const k of keys) { const v = o && o[k]; if (v !== undefined && v !== null && String(v).trim() && String(v).trim() !== '-') return String(v).trim(); } return ''; };
const hostOnly = (h) => String(h || '').trim().toLowerCase().split('.')[0];

function alertSubject(a) {
  const g = a.group || {}, f = a.fields || {};
  let user = pick(g, ['user']) || pick(f, ['user', 'user_name', 'username']);
  let target = pick(g, ['target_user']) || pick(f, ['target_user']);
  let host = pick(g, ['host']) || a.host || pick(f, ['host', 'workstation', 'computer']);
  if (/\$$/.test(user)) { host = host || user.slice(0, -1); user = ''; }
  if (/\$$/.test(target)) target = '';
  return { user: user || target, role: user ? 'user' : target ? 'target' : '', host: hostOnly(host), dept: pick(f, ['user_dept', 'target_dept']) };
}

// host → last interactive logon user (one query for all hosts)
async function hostUsers(ch, db, hosts) {
  const names = [...new Set(hosts)].filter((h) => NAME_RE.test(h)).slice(0, 5000);
  if (!names.length || !ch || typeof ch.query !== 'function') return {};
  const rows = await ch.query(`SELECT lower(fields['workstation']) AS h, argMax(user, ts) AS u FROM ${db}.events
      WHERE ts >= now() - INTERVAL 14 DAY AND src_type = 'windows' AND event_code = '4624' AND fields['logon_type'] IN ('2','10','11')
        AND user != '' AND NOT endsWith(user, '$') AND lower(fields['workstation']) IN {names:Array(String)} GROUP BY h`,
  { names }, { readonly: true, timeout_ms: 30000, settings: { max_execution_time: 30 } }).catch(() => []);
  const m = {}; for (const r of rows || []) if (r.h && r.u) m[r.h] = r.u; return m;
}

async function build({ alerts, identity, ch, db, days, minSev, now }) {
  const t = now || Date.now(), from = t - days * DAY;
  // every alert seen in the window (not the paged list); LogRhythm copies from the parallel run are left out as in the queue
  const items = alerts.all((a) => (a.ts_last || a.created || 0) >= from && (a.severity || 0) >= minSev && a.source !== 'logrhythm');
  const adUsers = identity ? identity.size() : 0;
  const subj = items.map(alertSubject);
  const needHost = subj.filter((s) => !s.user && !s.dept && s.host).map((s) => s.host);
  let hostMap = {}, hostLookup = 'not needed';
  if (needHost.length) { try { hostMap = await hostUsers(ch, db, needHost); hostLookup = 'ok'; } catch (e) { hostLookup = 'failed: ' + e.message; } }
  const deptOf = (u) => { const r = identity && u ? identity.lookup(u) : null; return r ? { dept: r.dept || '', sam: r.sam, found: true } : { dept: '', sam: u, found: false }; };

  const out = [];
  items.forEach((a, i) => {
    const s = subj[i]; let dept = '', via = '', user = '', reason = '';
    if (s.user) { const d = deptOf(s.user); user = d.sam; if (d.dept) { dept = d.dept; via = s.role === 'target' ? 'target account' : 'account'; } else reason = !identity || !adUsers ? 'no AD sync' : d.found ? 'AD account has no department' : 'account not in AD'; }
    if (!dept && s.dept) { dept = s.dept; via = 'AD enrichment'; reason = ''; }
    if (!dept && !s.user && s.host) {
      const u = hostMap[s.host];
      if (u) { const d = deptOf(u); user = d.sam; if (d.dept) { dept = d.dept; via = 'host last logon'; } else reason = d.found ? 'AD account has no department' : 'account not in AD'; }
      else reason = 'host with no recorded logon';
    }
    if (!dept && !reason) reason = 'no user or host on the alert';
    out.push({ a, dept: dept || NONE, via, user, host: s.host, reason });
  });

  // department sizes (enabled accounts) from the AD snapshot
  const sizes = new Map();
  if (identity && identity.snapshot) for (const r of identity.snapshot().users || []) if (r.dept && !r.disabled) sizes.set(r.dept, (sizes.get(r.dept) || 0) + 1);
  return { items: out, sizes, hostLookup, adUsers, adSynced: identity && identity.meta ? identity.meta().synced : 0, from, to: t };
}

function summarise(b, { days, withNames }) {
  const by = new Map();
  const dayKey = (ts) => new Date(ts).toISOString().slice(0, 10);
  const daysList = []; for (let i = days - 1; i >= 0; i--) daysList.push(dayKey(b.to - i * DAY));
  for (const x of b.items) {
    let d = by.get(x.dept);
    if (!d) by.set(x.dept, d = { department: x.dept, users_in_ad: b.sizes.get(x.dept) || null, alerts: 0, open: 0, risk: 0, severity: [0, 0, 0, 0, 0], users: new Map(), hosts: new Set(), rules: new Map(), tactics: new Map(), via: {}, reasons: {}, trend: Object.fromEntries(daysList.map((k) => [k, 0])), last: 0 });
    const a = x.a, sv = Math.max(0, Math.min(4, a.severity || 0));
    d.alerts++; d.severity[sv]++; d.risk += W[sv]; if (!/^closed/.test(a.status || '')) d.open++;
    if (x.user) d.users.set(x.user, (d.users.get(x.user) || 0) + W[sv] + 0.001);
    if (x.host) d.hosts.add(x.host);
    const rk = a.rule_name || a.rule_id || 'alert'; const r = d.rules.get(rk) || { rule: rk, alerts: 0, max_severity: 0 }; r.alerts++; r.max_severity = Math.max(r.max_severity, sv); d.rules.set(rk, r);
    for (const tc of [].concat(a.tactic || []).filter(Boolean)) d.tactics.set(tc, (d.tactics.get(tc) || 0) + 1);
    if (x.via) d.via[x.via] = (d.via[x.via] || 0) + 1;
    if (x.reason) d.reasons[x.reason] = (d.reasons[x.reason] || 0) + 1;
    const k = dayKey(a.ts_last || a.created || b.to); if (k in d.trend) d.trend[k]++;
    d.last = Math.max(d.last, a.ts_last || 0);
  }
  const depts = [...by.values()].map((d) => ({
    department: d.department, users_in_ad: d.users_in_ad, alerts: d.alerts, open: d.open, risk: d.risk,
    risk_per_100_users: d.users_in_ad ? Math.round(d.risk / d.users_in_ad * 1000) / 10 : null,
    severity: Object.fromEntries(SEV.map((s, i) => [s, d.severity[i]])), users_affected: d.users.size, hosts_affected: d.hosts.size,
    top_rules: [...d.rules.values()].sort((x, y) => y.alerts - x.alerts).slice(0, 5).map((r) => Object.assign(r, { max_severity: SEV[r.max_severity] })),
    tactics: [...d.tactics.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6).map(([tactic, n]) => ({ tactic, alerts: n })),
    attributed_via: d.via, not_attributed_reasons: d.department === NONE ? d.reasons : undefined,
    trend: daysList.map((k) => d.trend[k]), last_alert: d.last ? new Date(d.last).toISOString() : null,
    top_users: withNames ? [...d.users.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5).map(([u]) => u) : undefined,
  })).sort((x, y) => (x.department === NONE) - (y.department === NONE) || y.risk - x.risk || y.alerts - x.alerts);
  const total = b.items.length, unattr = (by.get(NONE) || { alerts: 0 }).alerts;
  return { days, from: new Date(b.from).toISOString(), to: new Date(b.to).toISOString(), trend_days: daysList,
    total_alerts: total, attributed: total - unattr, not_attributed: unattr,
    ad: { synced: b.adSynced ? new Date(b.adSynced).toISOString() : null, users: b.adUsers }, host_lookup: b.hostLookup,
    names_included: !!withNames, departments: depts, weights: Object.fromEntries(SEV.map((s, i) => [s, W[i]])) };
}

function register(api, deps) {
  const P = prefixOf(deps), { alerts, identity, ch } = deps;
  if (!alerts) throw new Error('department threats need deps.alerts');
  const db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const opts = (q) => ({ days: Math.max(1, Math.min(90, parseInt(q.days, 10) || 7)), minSev: Math.max(0, Math.min(4, parseInt(q.min_severity, 10) || 0)) });
  api.route('GET', `${P}/threats/departments`, wrap(deps, null, async (ctx) => {
    const o = opts(ctx.query || {});
    const b = await build({ alerts, identity, ch, db, days: o.days, minSev: o.minSev, now: deps.now ? deps.now() : undefined });
    return ctx.ok(summarise(b, { days: o.days, withNames: (RANK[ctx.role] || 0) >= RANK.analyst }));
  }));
  api.route('GET', `${P}/threats/departments/:name`, wrap(deps, null, async (ctx) => {
    if ((RANK[ctx.role] || 0) < RANK.analyst) throw new HttpError(403, 'requires analyst role (the list names employees)');
    const o = opts(ctx.query || {}), name = String(ctx.params.name || '');
    const b = await build({ alerts, identity, ch, db, days: o.days, minSev: o.minSev, now: deps.now ? deps.now() : undefined });
    const rows = b.items.filter((x) => x.dept === name).sort((x, y) => (y.a.severity || 0) - (x.a.severity || 0) || (y.a.ts_last || 0) - (x.a.ts_last || 0)).slice(0, 500);
    audit(ctx, 'threats.department.view', name, { days: o.days, alerts: rows.length });
    return ctx.ok({ department: name, days: o.days, items: rows.map((x) => ({ id: x.a.id, rule: x.a.rule_name || x.a.rule_id, severity: SEV[Math.max(0, Math.min(4, x.a.severity || 0))], status: x.a.status,
      ts_last: x.a.ts_last ? new Date(x.a.ts_last).toISOString() : null, count: x.a.count || 1, user: x.user, host: x.host, via: x.via, reason: x.reason, tactic: x.a.tactic || '', summary: String(x.a.summary || '').slice(0, 240) })) });
  }));
}

module.exports = { register, build, summarise, alertSubject, NONE, W };
