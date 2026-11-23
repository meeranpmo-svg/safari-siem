// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA evidence collector: live facts from ClickHouse (evidence-ch.js) and the engine's in-memory state.
//   collectEvidence(deps, { map, settings, now }) → Promise<evidence>
//   deps = { ch, config, state, detector, scheduled, alerts, cases, intel, identity, adSync, ueba, tracker, dataopt,
//            rules? (array | () => array; default: built-in pack + admin overrides), playbooks?, probe? (tests) }
// Nothing here writes anywhere. Missing modules simply produce "not available" facts that the evaluator reports.
const fs = require('node:fs');
const path = require('node:path');
const { probeClickHouse } = require('./evidence-ch');
const { computeMetrics } = require('../soc/metrics');

const H = 3600000;
const D = 86400000;
const shortHost = (h) => String(h || '').trim().toLowerCase().replace(/^.*\\/, '').split('.')[0];
function globRe(p) { return new RegExp('^' + String(p).toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'); }
const matchAny = (pats, v) => pats.some((p) => globRe(p).test(String(v || '').toLowerCase()));
const safe = (fn, dflt) => { try { const v = fn(); return v === undefined ? dflt : v; } catch { return dflt; } };

function loadRules(deps) {
  if (Array.isArray(deps.rules)) return deps.rules;
  if (typeof deps.rules === 'function') return deps.rules();
  const rs = require('../detect/ruleset');
  const dir = (deps.config && deps.config.detect && deps.config.detect.rules_dir) || undefined;
  const builtins = rs.loadBuiltinRules(dir);
  const tags = new Map(builtins.map((r) => [r.id, r.sama]));
  // an admin override stored before the rules were tagged has no `sama`: inherit the shipped tags
  return rs.effectiveRules(deps.state || null, builtins).map((r) => (Array.isArray(r.sama) ? r : Object.assign({}, r, { sama: tags.get(r.id) || [] })));
}

function ruleFacts(deps) {
  const errs = new Set(safe(() => deps.detector.stats().load_errors, []).map((e) => e && e.id).filter(Boolean));
  return loadRules(deps).map((r) => ({
    id: r.id, name: r.name || r.id, type: r.type || 'single', severity: r.severity, mitre: r.mitre || [], sama: Array.isArray(r.sama) ? r.sama : [],
    enabled: r.enabled !== false && !errs.has(r.id), load_error: errs.has(r.id), origin: r.builtin ? 'builtin' : (r.origin || 'custom'),
  }));
}

function sourceFacts(deps, chHosts, windowH, now) {
  const cfg = deps.config || {};
  const live = safe(() => deps.tracker.summary(), []);
  const byId = new Map();
  const get = (id) => { if (!byId.has(id)) byId.set(id, { src_id: id, src_type: '', configured: false, last_seen: 0, events_window: 0, hosts: new Set() }); return byId.get(id); };
  for (const s of cfg.sources || []) { if (!s || s.type === 'relay') continue; const x = get(s.id); x.configured = true; x.src_type = x.src_type || s.type || ''; x.silent_after_s = s.silent_after_s || 900; }
  for (const l of live) { const x = get(l.src_id); x.src_type = l.src_type || x.src_type; x.last_seen = Math.max(x.last_seen, l.last_seen || 0); for (const h of l.hosts || []) x.hosts.add(h); }
  for (const r of chHosts || []) { const x = get(r.src_id); x.src_type = x.src_type || r.src_type; x.last_seen = Math.max(x.last_seen, r.last_ms || 0); x.events_window += r.events; if (r.host) x.hosts.add(r.host); }
  const list = [...byId.values()].map((x) => {
    const silentAfter = (x.silent_after_s || 900) * 1000;
    const status = !x.last_seen || now - x.last_seen > silentAfter ? 'silent' : 'ok';
    return { src_id: x.src_id, src_type: x.src_type, configured: x.configured, last_seen: x.last_seen || null, events_window: x.events_window, hosts: [...x.hosts].slice(0, 50), host_count: x.hosts.size, status };
  }).sort((a, b) => (a.src_id < b.src_id ? -1 : 1));
  const active = list.filter((s) => s.status === 'ok' || (s.last_seen && now - s.last_seen <= windowH * H));
  return { list, configured: list.filter((s) => s.configured).length, active: active.length, silent: list.filter((s) => s.configured && s.status === 'silent') };
}

// rows with an empty host (e.g. Microsoft 365 audit records) still prove that a source class is reporting
function hostRows(chHosts, sources, windowH, now) {
  if (chHosts) return chHosts.map((r) => Object.assign({}, r, { short: shortHost(r.host) }));
  const rows = []; // fallback: what the tracker saw since start within the window (no Kerberos counts)
  for (const s of sources.list) {
    if (!s.last_seen || now - s.last_seen > windowH * H) continue;
    const hs = s.hosts.length ? s.hosts : [''];
    for (const h of hs) rows.push({ src_type: s.src_type, src_id: s.src_id, host: h, short: shortHost(h), events: 0, last_ms: s.last_seen, kdc: 0 });
  }
  return rows;
}

function classFacts(map, settings, rows, defender, cfg, fromCH) {
  const defs = map.source_classes || {};
  const out = {};
  const adServers = [].concat((cfg.ad && cfg.ad.servers) || []).map((s) => (typeof s === 'string' ? s : (s && s.url) || ''))
    .map((u) => shortHost(String(u).replace(/^[a-z]+:\/\//i, '').replace(/[:/].*$/, ''))).filter(Boolean);
  const order = Object.keys(defs).sort((a, b) => (defs[a].exclude_classes ? 1 : 0) - (defs[b].exclude_classes ? 1 : 0));
  for (const name of order) {
    const c = defs[name];
    const types = new Set((c.src_types || []).map((t) => String(t).toLowerCase()));
    const idPats = c.src_id_patterns || [];
    let mine = rows.filter((r) => types.has(String(r.src_type).toLowerCase()) || (idPats.length && matchAny(idPats, r.src_id)));
    let expected = [];
    if (c.kdc_event_codes) {
      const pats = [].concat(c.host_patterns || [], name === 'domain_controllers' ? settings.dc_hosts || [] : []);
      if (c.use_ad_servers) expected = adServers.slice();
      for (const p of settings.dc_hosts || []) if (!/[*?]/.test(p)) expected.push(shortHost(p));
      mine = mine.filter((r) => r.kdc > 0 || (pats.length && matchAny(pats, r.short)) || expected.includes(r.short));
    }
    if (c.channel_contains) { const hs = new Set((defender || []).map((d) => shortHost(d.host))); mine = defender ? mine.filter((r) => hs.has(r.short)) : []; }
    for (const ex of c.exclude_classes || []) { const skip = new Set((out[ex] && out[ex].hosts) || []); mine = mine.filter((r) => !skip.has(r.short)); }
    const hosts = [...new Set(mine.map((r) => r.short).filter(Boolean))].sort();
    const missing = [...new Set(expected)].filter((e) => !hosts.includes(e));
    out[name] = { title: c.title || name, present: mine.length > 0, hosts: hosts.slice(0, 200), host_count: hosts.length,
      sources: [...new Set(mine.map((r) => r.src_id))].sort(), events: mine.reduce((s, r) => s + (r.events || 0), 0), expected_missing: missing,
      evidence: c.channel_contains && !defender ? 'unavailable' : fromCH ? 'ok' : 'live-memory' };
  }
  return out;
}

function alertCaseFacts(deps, from, to, now) {
  const all = safe(() => deps.alerts.all(), []).filter((a) => a.source !== 'logrhythm');
  const cases = safe(() => deps.cases.all(), []);
  const m = computeMetrics({ alerts: all, cases, from, to, now, slaState: deps.cases && deps.cases.slaState });
  const inP = all.filter((a) => a.created >= from && a.created <= to);
  const triaged = inP.filter((a) => a.ack_at || a.status !== 'new');
  const high = (min) => inP.filter((a) => (a.severity | 0) >= min);
  const approvals = safe(() => deps.cases.approvals.list({}), []).filter((a) => { const t = Date.parse(a.requested_at) || a.requested_at || 0; return t >= from && t <= to; });
  return {
    _alerts: inP,
    alerts: { available: !!deps.alerts, total: inP.length, triaged: triaged.length, ack_pct: inP.length ? Math.round((triaged.length / inP.length) * 1000) / 10 : null,
      mtta_avg_s: m.mtta.alerts.avg_ms === null ? null : Math.round(m.mtta.alerts.avg_ms / 1000), mtta_n: m.mtta.alerts.n,
      mttd_avg_s: m.mttd_s, open: m.totals.open_alerts, unassigned_open: m.totals.unassigned_open, by_severity: m.alerts_by_severity,
      // escalation by minimum severity: escalated = linked to a case or closed with a reason
      escalation: [1, 2, 3, 4].reduce((o, min) => { const h = high(min); const esc = h.filter((a) => a.case_id || String(a.status).startsWith('closed-')); o[min] = { total: h.length, escalated: esc.length, open_unescalated: h.filter((a) => !esc.includes(a)).map((a) => a.id).slice(0, 20) }; return o; }, {}) },
    cases: { available: !!deps.cases, created: m.totals.cases_created, closed: m.totals.cases_closed, open: m.totals.cases_open,
      mttr_avg_s: m.mttr.cases.avg_ms === null ? null : Math.round(m.mttr.cases.avg_ms / 1000), mtta_avg_s: m.mtta.cases.avg_ms === null ? null : Math.round(m.mtta.cases.avg_ms / 1000),
      sla_resolve_pct: m.sla.resolve_compliance_pct, sla_ack_pct: m.sla.ack_compliance_pct, breaching_now: (m.sla.breaching_now || []).map((c) => c.id).slice(0, 20),
      high_severity_cases: cases.filter((c) => c.created >= from && c.created <= to && (c.severity | 0) >= 3).length, approvals_requested: approvals.length },
  };
}

function intelFacts(deps, from, to, alertsInP) {
  const cfg = deps.config || {};
  if (!deps.intel) return { enabled: false };
  const st = safe(() => deps.intel.stats(), {});
  const dir = (cfg.detect && cfg.detect.intel_dir) || (cfg.data_dir ? path.join(cfg.data_dir, 'intel') : '');
  let newest = null;
  if (deps.intelNewestFileMs !== undefined) newest = deps.intelNewestFileMs;
  else if (dir) { try { for (const f of fs.readdirSync(dir)) if (/\.(txt|csv)$/i.test(f)) newest = Math.max(newest || 0, fs.statSync(path.join(dir, f)).mtimeMs); } catch { /* dir missing */ } }
  const hits = st.hits || {};
  return { enabled: true, indicators: (st.ip || 0) + (st.domain || 0) + (st.hash || 0), ip: st.ip || 0, domain: st.domain || 0, hash: st.hash || 0, lists: st.lists || 0,
    loaded_at: st.loaded_at || null, newest_file_at: newest || null, hits_since_start: Object.values(hits).reduce((s, n) => s + n, 0),
    ioc_alerts: alertsInP.filter((a) => /^SENTRA-INTEL-/.test(a.rule_id || '')).length };
}

function identityFacts(deps, now) {
  const s = deps.adSync ? safe(() => deps.adSync.status(), null) : null;
  const last = s && s.last ? s.last : null;
  const at = last ? Date.parse(last.at) || 0 : 0;
  const sum = deps.identity ? safe(() => deps.identity.summary(), null) : null;
  return { available: !!s, enabled: !!(s && s.enabled), problems: (s && s.problems) || [], last_ok: !!(last && last.ok), last_at: at || null,
    last_error: last && !last.ok ? String(last.error || '').slice(0, 300) : null, age_h: at ? Math.round(((now - at) / H) * 10) / 10 : null,
    users: sum ? sum.counts.users : null, privileged: sum ? sum.counts.privileged : null, dormant_privileged: sum ? sum.counts.dormant_privileged : null };
}

function uebaFacts(deps, now) {
  if (!deps.ueba || typeof deps.ueba.health !== 'function') return { available: false, enabled: false };
  const h = safe(() => deps.ueba.health(), {});
  const last = Number(h.last_detect_run) || 0;
  return { available: true, enabled: h.enabled !== false, last_detect_run: last || null, last_baseline_run: Number(h.last_baseline_run) || null,
    age_h: last ? Math.round(((now - last) / H) * 10) / 10 : null, entities: h.entities || 0, findings_open: h.findings_open || 0 };
}

function assetFacts(cfg, settings, rows) {
  const known = new Set();
  for (const a of (cfg.enrich && cfg.enrich.assets) || []) { const n = shortHost(a && (a.host || a.ip)); if (n) known.add(n); }
  for (const a of settings.known_assets || []) { const n = shortHost(a); if (n) known.add(n); }
  const reporting = new Set(rows.map((r) => r.short).filter(Boolean));
  const ipsReporting = new Set(rows.map((r) => String(r.host || '').toLowerCase()));
  const expected = Number(settings.expected_asset_count) || 0;
  if (known.size) {
    const hit = [...known].filter((k) => reporting.has(k) || ipsReporting.has(k));
    return { inventory: 'list', known: known.size, reporting_known: hit.length, pct: Math.round((hit.length / known.size) * 1000) / 10, not_reporting: [...known].filter((k) => !hit.includes(k)).sort().slice(0, 50), hosts_reporting: reporting.size };
  }
  if (expected > 0) return { inventory: 'count', known: expected, reporting_known: Math.min(reporting.size, expected), pct: Math.min(100, Math.round((reporting.size / expected) * 1000) / 10), not_reporting: [], hosts_reporting: reporting.size };
  return { inventory: 'none', known: null, reporting_known: null, pct: null, not_reporting: [], hosts_reporting: reporting.size };
}

async function collectEvidence(deps, { map, settings, now = Date.now() } = {}) {
  const cfg = deps.config || {};
  const windowH = Number(settings.active_window_h) || 24;
  const to = now;
  const from = to - (Number(settings.period_days) || 30) * D;
  const dcDef = (map.source_classes || {}).domain_controllers || {};
  const defDef = Object.values(map.source_classes || {}).find((c) => c.channel_contains) || {};
  const probe = await (deps.probe || probeClickHouse)(deps.ch, { database: (cfg.clickhouse && cfg.clickhouse.database) || 'siem', windowH, kdcCodes: dcDef.kdc_event_codes || [], channelContains: defDef.channel_contains || '' });
  const sources = sourceFacts(deps, probe.hosts, windowH, now);
  const rows = hostRows(probe.hosts, sources, windowH, now);
  const ac = alertCaseFacts(deps, from, to, now);
  const dsv = deps.dataopt && deps.dataopt.settings ? safe(() => deps.dataopt.settings.get(), null) : null;
  const configured = dsv && Number(dsv.hot_retention_days) ? Number(dsv.hot_retention_days) : Number(cfg.retention_days) || null;
  const ttl = probe.ttl && probe.ttl.events;
  const det = deps.detector ? safe(() => deps.detector.stats(), null) : null;
  const ev = {
    generated_at: now, period: { from, to, days: Number(settings.period_days) || 30 }, active_window_h: windowH,
    clickhouse: { ok: probe.ok, partial: !!probe.partial, error: probe.error },
    sources, hosts: { count: new Set(rows.map((r) => r.short).filter(Boolean)).size, from: probe.hosts ? 'clickhouse' : 'live-memory' },
    classes: classFacts(map, settings, rows, probe.defender, cfg, !!probe.hosts),
    retention: { configured_days: configured, ttl_days: ttl || null, effective_days: ttl || configured, source: ttl ? 'clickhouse-ttl' : 'config',
      mismatch: !!(ttl && configured && ttl !== configured), archive_days: (probe.ttl && probe.ttl.events_archive) || (dsv && dsv.archive_retention_days) || null,
      oldest_event: probe.oldest ? probe.oldest.events : null, data_age_days: probe.oldest && probe.oldest.events ? Math.floor((now - probe.oldest.events) / D) : null },
    detector: { loaded: !!det, rules_loaded: det ? det.rules_loaded : 0, load_errors: det ? (det.load_errors || []).length : 0, events: det ? det.events : 0, scheduled: deps.scheduled ? safe(() => deps.scheduled.stats().length, 0) : 0 },
    rules: ruleFacts(deps),
    alerts: ac.alerts, cases: ac.cases,
    playbooks: (() => { const pl = safe(() => (deps.playbooks || require('../soc/playbooks')).list(), []); return { count: pl.length, ids: pl.map((p) => p.id) }; })(),
    intel: intelFacts(deps, from, to, ac._alerts),
    identity: identityFacts(deps, now), ueba: uebaFacts(deps, now),
    assets: assetFacts(cfg, settings, rows),
    vendor: { patterns: settings.vendor_account_patterns || [], accounts_matched: deps.identity && (settings.vendor_account_patterns || []).length
      ? safe(() => deps.identity.snapshot().users.filter((u) => matchAny(settings.vendor_account_patterns, u.sam)).length, null) : null },
  };
  Object.defineProperty(ev, '_alerts', { value: ac._alerts, enumerable: false });
  return ev;
}

module.exports = { collectEvidence, shortHost, globRe, matchAny };
