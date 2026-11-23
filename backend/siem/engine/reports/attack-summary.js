// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Attack Summary — what attacked the organisation in a period, built ONLY from live data:
 *   ClickHouse siem.events (events, attack categories, targets, attackers, failed logons, trend) and siem.alerts
 *   (alert mirror, deduplicated with argMax(…, updated) GROUP BY id: severity/status, rules, MITRE, notable alerts),
 *   plus the engine's own workflow state for what ClickHouse does not hold (alert ack/close times → MTTA / MTTC, cases).
 * Nothing is estimated or filled in: a panel whose query failed is null (shown as "not available" with the reason);
 * a panel with no rows is an empty list (shown as "no data in this period").
 *
 *   createAttackSummary({ ch, alerts?, cases?, rules?() , config, log, now, cacheS = 60 })
 *     → { summary(query) → Promise<report>, build(period) → Promise<report>, SQL, CATEGORIES }
 *   query: { period: 24h|7d|30d } or { from, to } (ISO / epoch ms; max 400 days); refresh=1 bypasses the 60 s cache.
 *
 * Report: { kind, generated_at, period{from,to,label,bucket,utc_offset_min}, clickhouse{ok, errors[]},
 *   totals{events, by_severity{0..4}, hosts, sources} | null,
 *   categories[{id, events, blocked, allowed, unknown (null for brute_force / admin_change)}] | null, threat_verdicts{blocked, allowed, unknown} | null,
 *   top_targets[{target, events, high, sources, classes[], last_ms}] | null,
 *   top_attackers[{ip, events, targets, classes[], country, internal, last_ms}] | null,
 *   top_failed_users[{user, failures, sources, hosts, last_ms}] | null,
 *   alerts{total, by_severity{0..4}, by_status{}, open, closed, closed_by_reason{true-positive,false-positive,benign}} | null,
 *   cases{opened, closed, open_now} | null, mitre{tactics[{tactic, alerts, techniques[{id, alerts}]}], techniques[{id, tactic, alerts}]} | null,
 *   trend{bucket, points[{t, events, threats, alerts}]} | null (alerts null-safe), top_rules[{rule_id, rule_name, alerts, max_severity, tactic, sama[]}] | null,
 *   sama[{control, title, alerts, rules[]}] | null, response{mtta, mttc (n, avg_ms, median_ms, p90_ms), source} | null,
 *   notable_alerts[{id, rule_id, rule_name, severity, status, first_ms, last_ms, summary, assignee}] | null,
 *   notable_cases[{id, title, severity, status, created, owner}] | null }
 */
const { resolvePeriod, TIME_WHERE, tparams, runQueries, fillBuckets, toMs, dist, isPrivateIp } = require('./common');
const samaCatalogue = require('../compliance/sama-catalogue');

// ---------------------------------------------------------------- SQL (parameterised; tagged /* sentra:<name> */)
const ADMIN_ACTIONS = ['config-change', 'exchange-cmdlet', 'group-member-added', 'group-member-removed', 'user-created', 'user-deleted',
  'user-modified', 'user-enabled', 'privileges-assigned', 'password-change', 'service-installed', 'audit-log-cleared', 'scheduled-task-created', 'role-assigned'];
const qlist = (a) => a.map((s) => `'${s}'`).join(', '); // constants only (never user input)

// Attack category of an event ('' = not an attack/threat-relevant event). First match wins.
const CLS = `multiIf(
    action IN ('av-detection', 'agent-tamper', 'edr-detection') OR category = 'malware' OR fields['vendor_class'] = 'edr', 'malware',
    action = 'dlp-incident' OR has(tags, 'dlp'), 'dlp',
    action = 'waf-detection' OR has(tags, 'waf') OR (category = 'web' AND action = 'blocked'), 'web',
    action = 'ips-detection', 'ips',
    action IN ('logon-failed', 'account-locked'), 'brute_force',
    category = 'network' AND action = 'blocked', 'firewall',
    category = 'policy' OR (category = 'process' AND action = 'blocked'), 'policy',
    action IN (${qlist(ADMIN_ACTIONS)}) OR category = 'iam', 'admin_change',
    '')`;
// Prevention verdict of a threat event: EDR remediated flag first, then the normalised action/outcome
// (firewall/IPS/AV/WAF/DLP parsers map "blocked" to action blocked or outcome failure; EDR uses fields.remediated).
const VERDICT = `multiIf(
    fields['remediated'] = 'true', 'blocked',
    fields['remediated'] = 'false', 'allowed',
    action = 'blocked', 'blocked',
    fields['dlp_action'] IN ('blocked', 'quarantined'), 'blocked',
    outcome = 'failure', 'blocked',
    outcome = 'success', 'allowed',
    'unknown')`;
const TARGET = `if(category IN ('network', 'web') AND dst_ip != '', dst_ip, host)`;
const COUNTRY = `multiIf(fields['country'] != '', fields['country'], fields['srccountry'] NOT IN ('', 'Reserved'), fields['srccountry'],
    fields['src_country'] != '', fields['src_country'], fields['geo_country'] != '', fields['geo_country'], '')`;
const THREAT = `cls NOT IN ('', 'admin_change')`;
const BASE = `${TIME_WHERE} AND action != 'agent-heartbeat'`;

function sqlFor(db = 'siem') {
  const E = `${db}.events`;
  const DEDUP = `SELECT id, argMax(rule_id, updated) AS a_rule, argMax(rule_name, updated) AS a_name, argMax(severity, updated) AS a_sev,
      argMax(status, updated) AS a_status, argMax(ts_first, updated) AS a_first, argMax(ts_last, updated) AS a_last,
      argMax(mitre, updated) AS a_mitre, argMax(summary, updated) AS a_summary, argMax(assignee, updated) AS a_assignee, max(updated) AS upd_at
    FROM ${db}.alerts WHERE ts_last >= fromUnixTimestamp64Milli({t_from:Int64}) AND rule_id NOT LIKE 'LR-%' GROUP BY id`;
  const IN_PERIOD = 'a_first < fromUnixTimestamp64Milli({t_to:Int64})';
  return {
    totals: `/* sentra:as-totals */ SELECT count() AS n_events, countIf(severity = 0) AS s0, countIf(severity = 1) AS s1, countIf(severity = 2) AS s2,
      countIf(severity = 3) AS s3, countIf(severity = 4) AS s4, uniqExact(host) AS n_hosts, uniqExact(src_id) AS n_sources
      FROM ${E} WHERE ${BASE}`,
    categories: `/* sentra:as-categories */ SELECT cls, verdict, count() AS n FROM (SELECT ${CLS} AS cls, ${VERDICT} AS verdict FROM ${E} WHERE ${BASE})
      WHERE cls != '' GROUP BY cls, verdict`,
    targets: `/* sentra:as-targets */ SELECT target, count() AS n, countIf(severity >= 3) AS n_high, uniqExactIf(src_ip, src_ip != '') AS n_src,
      groupUniqArray(8)(cls) AS classes, toUnixTimestamp64Milli(max(ts)) AS last_ms
      FROM (SELECT ${TARGET} AS target, severity, src_ip, ts, ${CLS} AS cls FROM ${E} WHERE ${BASE})
      WHERE ${THREAT} AND target != '' GROUP BY target ORDER BY n DESC LIMIT 10`,
    attackers: `/* sentra:as-attackers */ SELECT src_ip, count() AS n, uniqExact(target) AS n_targets, groupUniqArray(8)(cls) AS classes,
      anyIf(cty, cty != '') AS country, toUnixTimestamp64Milli(max(ts)) AS last_ms
      FROM (SELECT src_ip, ts, ${TARGET} AS target, ${CLS} AS cls, ${COUNTRY} AS cty FROM ${E} WHERE ${BASE} AND src_ip != '')
      WHERE ${THREAT} GROUP BY src_ip ORDER BY n DESC LIMIT 10`,
    users: `/* sentra:as-users */ SELECT user, count() AS n, uniqExactIf(src_ip, src_ip != '') AS n_src, uniqExact(host) AS n_hosts,
      toUnixTimestamp64Milli(max(ts)) AS last_ms FROM ${E} WHERE ${BASE} AND action = 'logon-failed' AND user != ''
      GROUP BY user ORDER BY n DESC LIMIT 10`,
    trend: `/* sentra:as-trend */ SELECT b, count() AS n, countIf(${THREAT}) AS n_threat
      FROM (SELECT intDiv(toUnixTimestamp64Milli(ts) + {t_off:Int64}, {t_bucket:Int64}) AS b, ${CLS} AS cls FROM ${E} WHERE ${BASE})
      GROUP BY b ORDER BY b`,
    alerts: `/* sentra:as-alerts */ SELECT a_sev, a_status, count() AS n FROM (${DEDUP}) WHERE ${IN_PERIOD} GROUP BY a_sev, a_status`,
    rules: `/* sentra:as-rules */ SELECT a_rule, any(a_name) AS r_name, count() AS n, max(a_sev) AS max_sev FROM (${DEDUP}) WHERE ${IN_PERIOD}
      GROUP BY a_rule ORDER BY n DESC LIMIT 500`,
    mitre: `/* sentra:as-mitre */ SELECT a_rule, tech, count() AS n FROM (${DEDUP}) ARRAY JOIN a_mitre AS tech WHERE ${IN_PERIOD}
      GROUP BY a_rule, tech ORDER BY n DESC LIMIT 2000`,
    alertTrend: `/* sentra:as-alert-trend */ SELECT intDiv(toUnixTimestamp64Milli(a_first) + {t_off:Int64}, {t_bucket:Int64}) AS b, count() AS n
      FROM (${DEDUP}) WHERE ${IN_PERIOD} AND a_first >= fromUnixTimestamp64Milli({t_from:Int64}) GROUP BY b ORDER BY b`,
    notable: `/* sentra:as-notable */ SELECT id, a_rule, a_name, a_sev, a_status, toUnixTimestamp64Milli(a_first) AS first_ms,
      toUnixTimestamp64Milli(a_last) AS last_ms, a_summary, a_assignee FROM (${DEDUP}) WHERE ${IN_PERIOD} AND a_sev >= 3
      ORDER BY a_sev DESC, a_last DESC LIMIT 15`,
  };
}

const CATEGORIES = ['brute_force', 'malware', 'web', 'ips', 'dlp', 'policy', 'firewall', 'admin_change'];
const THREAT_CLASSES = new Set(['malware', 'web', 'ips', 'dlp', 'policy', 'firewall']);
const OPEN = new Set(['new', 'acknowledged', 'in-progress']);
const n = (v) => Number(v) || 0;

function createAttackSummary({ ch, alerts, cases, rules, config = {}, log, now = Date.now, cacheS = 60 } = {}) {
  const L = log || { info() {}, warn() {}, error() {} };
  const db = (config.clickhouse && config.clickhouse.database) || 'siem';
  const offMin = config.tz_offset_min !== undefined ? Number(config.tz_offset_min) : 180;
  const SQL = sqlFor(db);
  const cache = new Map();

  function ruleDefs() {
    try {
      const list = typeof rules === 'function' ? rules() : Array.isArray(rules) ? rules : [];
      return new Map((list || []).filter((r) => r && r.id).map((r) => [r.id, r]));
    } catch (e) { L.warn('attack summary: rule list unavailable', { err: e.message }); return new Map(); }
  }

  function engineState(p) {
    const out = { response: null, cases: null, notable_cases: null };
    if (alerts && typeof alerts.all === 'function') {
      const list = alerts.all((a) => a.source !== 'logrhythm' && a.created >= p.from && a.created < p.to);
      out.response = {
        source: 'engine alert workflow (created in period)',
        alerts: list.length,
        mtta: dist(list.filter((a) => a.ack_at).map((a) => a.ack_at - a.created)),
        mttc: dist(list.filter((a) => a.closed_at).map((a) => a.closed_at - a.created)),
      };
    }
    if (cases && typeof cases.all === 'function') {
      const all = cases.all();
      const closedAt = (c) => toMs(c.closed);
      out.cases = {
        opened: all.filter((c) => toMs(c.created) >= p.from && toMs(c.created) < p.to).length,
        closed: all.filter((c) => closedAt(c) >= p.from && closedAt(c) < p.to).length,
        open_now: all.filter((c) => c.status !== 'closed').length,
      };
      out.notable_cases = all.filter((c) => n(c.severity) >= 3 && ((toMs(c.created) >= p.from && toMs(c.created) < p.to) || c.status !== 'closed'))
        .sort((a, b) => n(b.severity) - n(a.severity) || toMs(b.created) - toMs(a.created)).slice(0, 10)
        .map((c) => ({ id: c.id, title: c.title || '', severity: n(c.severity), status: c.status || '', created: toMs(c.created), owner: c.owner || '' }));
    }
    return out;
  }

  async function build(p) {
    const params = tparams(p, offMin);
    const specs = {};
    for (const [k, sql] of Object.entries(SQL)) specs[k] = [sql, params];
    const { results: R, errors } = await runQueries(ch, specs);
    const defs = ruleDefs();
    const rep = {
      kind: 'attack-summary', generated_at: new Date(now()).toISOString(),
      period: { from: p.from, to: p.to, label: p.label, bucket: p.bucket, utc_offset_min: offMin, timezone: config.timezone || 'Asia/Riyadh' },
      clickhouse: { ok: errors.length === 0, errors },
    };

    const t = R.totals && R.totals[0];
    rep.totals = R.totals ? (t ? { events: n(t.n_events), by_severity: { 0: n(t.s0), 1: n(t.s1), 2: n(t.s2), 3: n(t.s3), 4: n(t.s4) }, hosts: n(t.n_hosts), sources: n(t.n_sources) }
      : { events: 0, by_severity: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }, hosts: 0, sources: 0 }) : null;

    if (R.categories) {
      const by = {};
      const verd = { blocked: 0, allowed: 0, unknown: 0 };
      for (const r of R.categories) {
        const id = String(r.cls); if (!CATEGORIES.includes(id)) continue;
        const c = by[id] || (by[id] = { id, events: 0, blocked: 0, allowed: 0, unknown: 0 });
        const v = ['blocked', 'allowed'].includes(r.verdict) ? r.verdict : 'unknown';
        c.events += n(r.n); c[v] += n(r.n);
        if (THREAT_CLASSES.has(id)) verd[v] += n(r.n);
      }
      // prevention outcome is only meaningful for threat classes (a failed logon or an admin change is not "blocked")
      for (const c of Object.values(by)) if (!THREAT_CLASSES.has(c.id)) { c.blocked = null; c.allowed = null; c.unknown = null; }
      rep.categories = CATEGORIES.filter((id) => by[id]).map((id) => by[id]).sort((a, b) => b.events - a.events);
      rep.threat_verdicts = verd;
    } else { rep.categories = null; rep.threat_verdicts = null; }

    rep.top_targets = R.targets ? R.targets.map((r) => ({ target: String(r.target), events: n(r.n), high: n(r.n_high), sources: n(r.n_src), classes: (r.classes || []).map(String).sort(), last_ms: toMs(r.last_ms) })) : null;
    rep.top_attackers = R.attackers ? R.attackers.map((r) => ({ ip: String(r.src_ip), events: n(r.n), targets: n(r.n_targets), classes: (r.classes || []).map(String).sort(), country: String(r.country || ''), internal: isPrivateIp(r.src_ip), last_ms: toMs(r.last_ms) })) : null;
    rep.top_failed_users = R.users ? R.users.map((r) => ({ user: String(r.user), failures: n(r.n), sources: n(r.n_src), hosts: n(r.n_hosts), last_ms: toMs(r.last_ms) })) : null;

    if (R.alerts) {
      const a = { total: 0, by_severity: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }, by_status: {}, open: 0, closed: 0, open_by_severity: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }, closed_by_reason: { 'true-positive': 0, 'false-positive': 0, benign: 0 } };
      for (const r of R.alerts) {
        const c = n(r.n); const s = Math.max(0, Math.min(4, n(r.a_sev))); const st = String(r.a_status || '');
        a.total += c; a.by_severity[s] += c; a.by_status[st] = (a.by_status[st] || 0) + c;
        if (OPEN.has(st)) { a.open += c; a.open_by_severity[s] += c; } else if (st.startsWith('closed-')) { a.closed += c; const k = st.slice(7); if (k in a.closed_by_reason) a.closed_by_reason[k] += c; }
      }
      rep.alerts = a;
    } else rep.alerts = null;

    if (R.rules) {
      rep.top_rules = R.rules.map((r) => {
        const d = defs.get(String(r.a_rule)) || {};
        return { rule_id: String(r.a_rule), rule_name: String(r.r_name || d.name || ''), alerts: n(r.n), max_severity: n(r.max_sev), tactic: d.tactic || '', sama: Array.isArray(d.sama) ? d.sama.slice() : [] };
      });
      const sm = new Map();
      for (const r of rep.top_rules) for (const c of r.sama) {
        const e = sm.get(c) || { control: c, title: (samaCatalogue.control(c) || {}).title || '', alerts: 0, rules: [] };
        e.alerts += r.alerts; if (!e.rules.includes(r.rule_id)) e.rules.push(r.rule_id);
        sm.set(c, e);
      }
      rep.sama = [...sm.values()].sort((a, b) => b.alerts - a.alerts || samaCatalogue.refNum(a.control) - samaCatalogue.refNum(b.control));
      rep.top_rules = rep.top_rules.slice(0, 15);
    } else { rep.top_rules = null; rep.sama = null; }

    if (R.mitre) {
      const tac = new Map(); const tech = new Map();
      for (const r of R.mitre) {
        const id = String(r.tech || ''); if (!/^T\d{4}(\.\d{3})?$/.test(id)) continue;
        const tactic = (defs.get(String(r.a_rule)) || {}).tactic || 'unmapped';
        const c = n(r.n);
        const te = tech.get(id) || { id, tactic, alerts: 0 }; te.alerts += c; tech.set(id, te);
        const ta = tac.get(tactic) || { tactic, alerts: 0, techniques: new Map() };
        ta.alerts += c; ta.techniques.set(id, (ta.techniques.get(id) || 0) + c); tac.set(tactic, ta);
      }
      rep.mitre = {
        tactics: [...tac.values()].map((x) => ({ tactic: x.tactic, alerts: x.alerts, techniques: [...x.techniques.entries()].map(([id, c]) => ({ id, alerts: c })).sort((a, b) => b.alerts - a.alerts) })).sort((a, b) => b.alerts - a.alerts),
        techniques: [...tech.values()].sort((a, b) => b.alerts - a.alerts).slice(0, 30),
      };
    } else rep.mitre = null;

    if (R.trend) {
      const pts = fillBuckets(R.trend.map((r) => ({ b: r.b, events: r.n, threats: r.n_threat })), p, offMin, ['events', 'threats']);
      const at = R.alertTrend ? new Map(fillBuckets(R.alertTrend.map((r) => ({ b: r.b, alerts: r.n })), p, offMin, ['alerts']).map((x) => [x.t, x.alerts])) : null;
      rep.trend = { bucket: p.bucket, points: pts.map((x) => Object.assign(x, { alerts: at ? at.get(x.t) || 0 : null })) };
    } else rep.trend = null;

    rep.notable_alerts = R.notable ? R.notable.map((r) => ({ id: String(r.id), rule_id: String(r.a_rule), rule_name: String(r.a_name || ''), severity: n(r.a_sev), status: String(r.a_status || ''), first_ms: toMs(r.first_ms), last_ms: toMs(r.last_ms), summary: String(r.a_summary || ''), assignee: String(r.a_assignee || '') })) : null;

    Object.assign(rep, engineState(p));
    if (errors.length) L.warn('attack summary: some panels unavailable', { failed: errors.map((e) => e.panel) });
    return rep;
  }

  async function summary(q = {}) {
    const p = resolvePeriod(q, now());
    const key = `${p.from}|${p.to}|${p.label}`;
    const hit = cache.get(key);
    if (hit && q.refresh !== '1' && now() - hit.at < cacheS * 1000) return hit.rep;
    const rep = await build(p);
    cache.set(key, { at: now(), rep });
    if (cache.size > 50) cache.delete(cache.keys().next().value);
    return rep;
  }

  return { summary, build, SQL, CATEGORIES };
}

module.exports = { createAttackSummary, sqlFor, CATEGORIES, CLS, VERDICT };
