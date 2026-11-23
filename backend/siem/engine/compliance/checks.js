// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA check evaluators — pure functions over the evidence object from evidence.js.
//   KINDS[kind](check, ctx) → { pass: true | false | null, value, reason, details? }
//   ctx = { ctrl (control id), ev (evidence), settings, map }
//   pass null = the evidence needed is not available (ClickHouse down, module not loaded, no inventory …): the control
//   is then reported partial with that reason — missing evidence never counts as passing.
const H = 3600000;
const D = 86400000;
const fmtDur = (s) => (s === null || s === undefined ? 'n/a' : s < 120 ? `${Math.round(s)} s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round((s / 3600) * 10) / 10} h` : `${Math.round((s / 86400) * 10) / 10} d`);
const r = (pass, value, reason, details) => ({ pass, value, reason, details: details || undefined });
const p = (c) => c.params || {};

function enabledTagged(ev, ctrl) { return ev.rules.filter((x) => x.enabled && x.sama.includes(ctrl)); }

function classCheck(name, ev) {
  const c = ev.classes[name];
  if (!c) return r(false, 0, `source class "${name}" is not defined in sama-map.json`);
  if (c.evidence === 'unavailable') return r(null, null, `${c.title}: evidence unavailable (ClickHouse probe failed)`);
  const missing = c.expected_missing || [];
  if (!c.present && c.evidence === 'live-memory') return r(null, null, `${c.title}: not seen since engine start and ClickHouse unavailable — evidence unavailable`);
  if (!c.present) return r(false, 0, `${c.title}: no events in the last ${ev.active_window_h} h`, { expected_missing: missing });
  if (missing.length) return r(false, c.host_count, `${c.title}: ${c.host_count} reporting, but expected host(s) silent: ${missing.join(', ')}`, { hosts: c.hosts, expected_missing: missing });
  return r(true, c.host_count, `${c.title}: reporting (${c.host_count} host(s), ${c.sources.length} source(s))`, { hosts: c.hosts.slice(0, 50), sources: c.sources });
}

function topics(check, ev) {
  const t = p(check).topics || {};
  const enabled = new Set(ev.rules.filter((x) => x.enabled).map((x) => x.id));
  const missing = []; const covered = [];
  for (const [k, v] of Object.entries(t)) {
    const on = (v.rules || []).filter((id) => enabled.has(id));
    if (on.length) covered.push({ topic: k, title: v.title || k, rules: on });
    else missing.push({ topic: k, title: v.title || k, rules: v.rules || [], action: v.action || '' });
  }
  const n = Object.keys(t).length;
  return r(missing.length === 0, `${covered.length}/${n}`, missing.length ? `missing: ${missing.map((m) => m.title).join(', ')}` : `all ${n} topics have an enabled detection`, { covered, missing });
}

const KINDS = {
  sources_active: (c, { ev }) => (!ev.sources.active && ev.hosts.from !== 'clickhouse'
    ? r(null, null, 'no source seen since engine start and ClickHouse unavailable — evidence unavailable')
    : r(ev.sources.active >= (p(c).min || 1), ev.sources.active, `${ev.sources.active} active log source(s) (${ev.sources.configured} configured)`)),
  silent_sources: (c, { ev }) => {
    const s = ev.sources.silent;
    return r(s.length <= (p(c).max || 0), s.length, s.length ? `silent: ${s.map((x) => x.src_id).slice(0, 10).join(', ')}` : 'no configured source is silent', { silent: s.map((x) => ({ src_id: x.src_id, src_type: x.src_type, last_seen: x.last_seen })) });
  },
  hosts_reporting: (c, { ev }) => (!ev.hosts.count && ev.hosts.from !== 'clickhouse'
    ? r(null, null, 'no host seen since engine start and ClickHouse unavailable — evidence unavailable')
    : r(ev.hosts.count >= (p(c).min || 1), ev.hosts.count, `${ev.hosts.count} host(s) sent events in the last ${ev.active_window_h} h (${ev.hosts.from})`)),
  required_source_classes: (c, { ev, settings }) => {
    const req = settings.required_source_classes || [];
    const res = req.map((n) => Object.assign({ class: n }, classCheck(n, ev)));
    const failed = res.filter((x) => x.pass === false); const unknown = res.filter((x) => x.pass === null);
    const pass = failed.length ? false : unknown.length ? null : true;
    return r(pass, `${res.filter((x) => x.pass).length}/${req.length}`, pass ? `all ${req.length} required source classes reporting` : res.filter((x) => x.pass !== true).map((x) => x.reason).join('; '), { classes: res });
  },
  source_class: (c, { ev }) => classCheck(p(c).class, ev),
  retention: (c, { ev, settings }) => {
    const need = Number(settings.required_retention_days) || 365;
    const rt = ev.retention;
    if (!rt.effective_days) return r(null, null, 'retention could not be determined');
    const extra = rt.mismatch ? ` (config says ${rt.configured_days} d; the live ClickHouse TTL is authoritative)` : '';
    return r(rt.effective_days >= need, rt.effective_days, `hot retention ${rt.effective_days} d (${rt.source}) vs required ${need} d${extra}`, { required_days: need, archive_days: rt.archive_days, data_age_days: rt.data_age_days });
  },
  detector_running: (c, { ev }) => {
    const d = ev.detector;
    if (!d.loaded) return r(false, 0, 'real-time detector not loaded');
    if (!d.rules_loaded) return r(false, 0, 'detector loaded without rules');
    return r(d.load_errors === 0, d.rules_loaded, `${d.rules_loaded} rules compiled${d.load_errors ? `, ${d.load_errors} rule(s) failed to compile` : ''}, ${d.scheduled} scheduled`);
  },
  rules_tagged: (c, { ev, ctrl }) => {
    const on = enabledTagged(ev, ctrl); const all = ev.rules.filter((x) => x.sama.includes(ctrl));
    return r(on.length >= (p(c).min || 1), on.length, `${on.length} enabled of ${all.length} rules tagged ${ctrl} (minimum ${p(c).min || 1})`, { disabled: all.filter((x) => !x.enabled).map((x) => x.id) });
  },
  rules_enabled: (c, { ev }) => {
    const want = p(c).rules || []; const byId = new Map(ev.rules.map((x) => [x.id, x]));
    const on = want.filter((id) => byId.get(id) && byId.get(id).enabled);
    const min = p(c).min || want.length;
    const off = want.filter((id) => !on.includes(id));
    return r(on.length >= min, `${on.length}/${want.length}`, `${on.length} of ${want.length} enabled${off.length ? ` (not enabled: ${off.join(', ')})` : ''}`, { enabled: on, not_enabled: off });
  },
  rule_topics: (c, { ev }) => topics(c, ev),
  alert_triage: (c, { ev }) => {
    const a = ev.alerts;
    if (!a.available) return r(null, null, 'alert workflow module not loaded');
    if (!a.total) return r(false, 0, `no alerts in the ${ev.period.days}-day period — monitoring and triage are not evidenced`);
    const minPct = p(c).min_ack_pct || 90; const maxH = p(c).max_mtta_h || 24;
    const okPct = a.ack_pct >= minPct; const okMtta = a.mtta_avg_s === null ? true : a.mtta_avg_s <= maxH * 3600;
    return r(okPct && okMtta, a.ack_pct, `${a.triaged}/${a.total} alerts triaged (${a.ack_pct}%, target ${minPct}%), MTTA ${fmtDur(a.mtta_avg_s)} (target ≤ ${maxH} h), ${a.unassigned_open} open unassigned`);
  },
  cases_handled: (c, { ev }) => {
    const k = ev.cases;
    if (!k.available) return r(null, null, 'case module not loaded');
    const n = k.created + k.closed;
    return r(n >= (p(c).min_cases || 1), n, `${k.created} case(s) opened, ${k.closed} closed in ${ev.period.days} days; MTTR ${fmtDur(k.mttr_avg_s)}; ${k.open} open`);
  },
  case_sla: (c, { ev }) => {
    const k = ev.cases;
    if (!k.available) return r(null, null, 'case module not loaded');
    if (k.sla_resolve_pct === null) return r(null, null, 'no cases in the period to measure SLA compliance');
    const min = p(c).min_resolve_pct || 90;
    return r(k.sla_resolve_pct >= min && !k.breaching_now.length, k.sla_resolve_pct, `resolve SLA compliance ${k.sla_resolve_pct}% (target ${min}%), ack ${k.sla_ack_pct}%; breaching now: ${k.breaching_now.length ? k.breaching_now.join(', ') : 'none'}`);
  },
  playbooks: (c, { ev }) => r(ev.playbooks.count >= (p(c).min || 1), ev.playbooks.count, `${ev.playbooks.count} response playbooks: ${ev.playbooks.ids.join(', ')}`),
  escalation: (c, { ev }) => {
    const a = ev.alerts;
    if (!a.available) return r(null, null, 'alert workflow module not loaded');
    const e = a.escalation[Math.max(1, Math.min(4, p(c).min_severity || 3))];
    if (!e.total) return r(true, null, `no alerts of severity ≥ ${p(c).min_severity || 3} in the period; ${ev.cases.approvals_requested} response approval(s) requested`);
    const pct = Math.round((e.escalated / e.total) * 1000) / 10;
    return r(pct >= (p(c).min_pct || 90), pct, `${e.escalated}/${e.total} high/critical alerts escalated to a case or closed (${pct}%); ${ev.cases.high_severity_cases} high/critical case(s), ${ev.cases.approvals_requested} approval request(s)`, { open_unescalated: e.open_unescalated });
  },
  intel_feed: (c, { ev }) => {
    const i = ev.intel;
    if (!i.enabled) return r(false, 0, 'threat-intel module not loaded');
    return r(i.indicators >= (p(c).min_indicators || 1), i.indicators, `${i.indicators} indicators in ${i.lists} list(s) (ip ${i.ip}, domain ${i.domain}, hash ${i.hash})`);
  },
  intel_fresh: (c, { ev }) => {
    const i = ev.intel;
    if (!i.enabled || !i.newest_file_at) return r(null, null, 'no intel list file found to date the feed');
    const age = (ev.generated_at - i.newest_file_at) / D;
    return r(age <= (p(c).max_age_days || 7), Math.round(age * 10) / 10, `newest IOC list updated ${Math.round(age * 10) / 10} d ago (maximum ${p(c).max_age_days || 7} d)`);
  },
  ioc_matching: (c, { ev }) => {
    const res = KINDS.rules_enabled({ params: { rules: p(c).rules || [], min: 1 } }, { ev });
    return r(res.pass && ev.intel.enabled, ev.intel.ioc_alerts || 0, `${res.reason}; ${ev.intel.ioc_alerts || 0} IOC alert(s) in the period, ${ev.intel.hits_since_start || 0} IOC match(es) since engine start`, res.details);
  },
  ad_sync: (c, { ev }) => {
    const i = ev.identity;
    if (!i.available) return r(false, null, 'AD identity sync module not loaded');
    if (!i.enabled) return r(false, null, 'AD identity sync disabled (config ad.enabled=false)');
    if (!i.last_at) return r(false, null, `AD identity sync has not run yet${i.problems.length ? ': ' + i.problems.join('; ') : ''}`);
    if (!i.last_ok) return r(false, i.age_h, `last AD sync failed: ${i.last_error || 'unknown error'}`);
    const max = p(c).max_age_h || 26;
    return r(i.age_h <= max, i.age_h, `last AD sync ok ${i.age_h} h ago (maximum ${max} h); ${i.users} users, ${i.privileged} privileged`);
  },
  ueba: (c, { ev }) => {
    const u = ev.ueba;
    if (!u.available) return r(false, null, 'UEBA module not loaded');
    if (!u.enabled) return r(false, null, 'UEBA disabled in its settings');
    if (!u.last_detect_run) return r(false, null, 'UEBA detectors have not run yet');
    const max = p(c).max_age_h || 2;
    return r(u.age_h <= max, u.age_h, `UEBA detectors ran ${u.age_h} h ago (maximum ${max} h); ${u.entities} entities, ${u.findings_open} open findings`);
  },
  asset_coverage: (c, { ev }) => {
    const a = ev.assets;
    if (a.inventory === 'none') return r(null, null, `no asset inventory configured (${a.hosts_reporting} hosts reporting)`);
    const min = p(c).min_pct || 90;
    return r(a.pct >= min, a.pct, `${a.reporting_known}/${a.known} known assets reporting (${a.pct}%, target ${min}%)`, { not_reporting: a.not_reporting });
  },
  vendor_accounts: (c, { ev }) => {
    const v = ev.vendor;
    if (!v.patterns.length) return r(false, null, 'no third-party account patterns defined');
    return r(true, v.accounts_matched, `patterns ${v.patterns.join(', ')}${v.accounts_matched === null ? '' : ` match ${v.accounts_matched} directory account(s)`}`);
  },
};

module.exports = { KINDS, fmtDur };
