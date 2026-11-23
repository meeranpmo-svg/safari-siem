// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA detectors — run each cycle on an entity's recent events vs its baseline.
 *
 *   runDetectors(ctx) → findings[]
 *     ctx = { entity, baseline, recent (events asc), observed, now, windowMs, settings, peers, plans, identifier, tz }
 *   Each finding is explainable: { detector, severity, weight, mitre, observed, baseline, window:{from,to},
 *                                  evidence:[event ids], explanation, dedup_key }.
 *
 * Detectors are config-driven (settings.detectors[name] = {enabled, thresholds…}); every detector has a synthetic test.
 * During an entity's "learning" state only hard first-seen / known-bad detectors fire (needsEstablished=false).
 * Standard library only.
 */
const { geoOf, travelInfeasible } = require('./geo');
const { robustZ, localHour, isPrivileged } = require('./baseline');
const { detectorConfig } = require('./settings');
const { createCidrSet } = require('../detect/ip');

const KNOWN_KEYS = {
  first_seen_country: 'countries', first_seen_subnet: 'subnets', first_seen_host: 'hosts',
  first_seen_service: 'services', first_seen_process: 'processes', first_seen_logon_type: 'logon_types',
};
const KNOWN_LABEL = {
  countries: 'country', subnets: 'source subnet', hosts: 'host', services: 'service',
  processes: 'process', logon_types: 'logon type',
};

function ids(events, n = 20) { const o = []; for (const e of events) { if (e && e.id) o.push(e.id); if (o.length >= n) break; } return o; }
function win(events) {
  let from = Infinity, to = 0;
  for (const e of events) { const t = e.ts || e.rts || 0; if (t && t < from) from = t; if (t > to) to = t; }
  return { from: from === Infinity ? 0 : from, to };
}
function fmtBytes(n) { if (n >= 1e9) return (n / 1e9).toFixed(1) + ' GB'; if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB'; if (n >= 1e3) return (n / 1e3).toFixed(1) + ' KB'; return n + ' B'; }

// ---- first-seen family (generic) ----
function firstSeen(ctx, detector) {
  const key = KNOWN_KEYS[detector];
  const baseKnown = (ctx.baseline && ctx.baseline.known && ctx.baseline.known[key]) || null;
  if (!baseKnown) return []; // no baseline history to compare against
  const baseSet = new Set(baseKnown);
  const seen = (ctx.observed && ctx.observed.known && ctx.observed.known[key]) || [];
  const fresh = seen.filter((v) => v && !baseSet.has(v));
  if (!fresh.length) return [];
  const findings = [];
  for (const value of fresh) {
    const evts = ctx.recent.filter((e) => matchKnown(detector, e, value));
    findings.push({
      detector, observed: { value, field: key },
      baseline: { known_count: baseSet.size, sample: baseKnown.slice(0, 8) },
      window: win(evts.length ? evts : ctx.recent), evidence: ids(evts),
      explanation: `${ctx.entity.type} ${ctx.entity.name}: first time seen ${KNOWN_LABEL[key] || key} "${value}" — not among ${baseSet.size} value(s) in ${ctx.baseline.days_observed} observed day(s)`,
      dedup_key: `${detector}:${value}`,
    });
  }
  return findings;
}
function matchKnown(detector, ev, value) {
  const g = geoOf(ev);
  switch (detector) {
    case 'first_seen_country': return g.country === value;
    case 'first_seen_subnet': return g.subnet24 === value;
    case 'first_seen_host': return (ev.host || '').toLowerCase() === value;
    case 'first_seen_service': return (ev.dst_port ? `${ev.proto || 'tcp'}/${ev.dst_port}` : '') === value;
    case 'first_seen_process': return (ev.process || '').toLowerCase() === value;
    case 'first_seen_logon_type': return String((ev.fields && (ev.fields.logon_type_name || ev.fields.logon_type)) || '').toLowerCase() === value;
    default: return false;
  }
}

// ---- volume_spike ----
function volumeSpike(ctx) {
  const dcfg = ctx.dcfg;
  const b = ctx.baseline;
  if (!b) return [];
  const dayFrac = Math.min(1, Math.max(ctx.windowMs / 86400000, 1 / 48));
  const findings = [];
  const label = { events: 'events', auth_fail: 'auth failures', egress_bytes: 'egress' };
  for (const m of dcfg.metrics || ['events', 'auth_fail', 'egress_bytes']) {
    const bm = b.metrics[m];
    const obs = ctx.observed[m] || 0;
    if (!bm) continue;
    if (obs < (dcfg.min_floor || 20)) continue;
    const expMed = bm.median * dayFrac;
    const scaleFloor = Math.max(1, (dcfg.min_floor || 20) * dayFrac);
    const z = robustZ(obs, expMed, bm.mad * dayFrac, scaleFloor);
    if (z >= (dcfg.z || 3.5)) {
      findings.push({
        detector: 'volume_spike', metric: m,
        observed: { metric: m, value: m === 'egress_bytes' ? fmtBytes(obs) : obs, raw: obs, z: Math.round(z * 10) / 10 },
        baseline: { per_day_median: Math.round(bm.median), per_day_p95: Math.round(bm.p95), expected_for_window: Math.round(expMed) },
        window: win(ctx.recent), evidence: ids(ctx.recent),
        explanation: `${ctx.entity.name}: ${label[m] || m} ${m === 'egress_bytes' ? fmtBytes(obs) : obs} in the window — baseline ~${Math.round(bm.median)}/day (robust z=${z.toFixed(1)})`,
        dedup_key: `volume_spike:${m}`,
      });
    }
  }
  return findings;
}

// ---- off_hours_activity ----
function offHours(ctx) {
  const b = ctx.baseline;
  if (!b || !b.active_hours || !b.active_hours.total) return [];
  const dcfg = ctx.dcfg;
  const hist = b.active_hours.histogram, total = b.active_hours.total;
  const quiet = new Set();
  for (let h = 0; h < 24; h++) if (hist[h] / total < (dcfg.quiet_pct || 0.02)) quiet.add(h);
  const offEvents = ctx.recent.filter((e) => quiet.has(localHour(e.ts || e.rts || 0, ctx.tz)));
  if (!offEvents.length) return [];
  const sensitive = offEvents.filter(isPrivileged);
  const offFloor = dcfg.off_floor || 5;
  if (sensitive.length < (dcfg.min_sensitive || 1) && offEvents.length < offFloor) return [];
  const hours = [...new Set(offEvents.map((e) => localHour(e.ts || e.rts || 0, ctx.tz)))].sort((a, z) => a - z);
  return [{
    detector: 'off_hours_activity',
    observed: { off_hours_events: offEvents.length, sensitive: sensitive.length, hours },
    baseline: { active_hours: b.active_hours.active, quiet_hours: [...quiet] },
    window: win(offEvents), evidence: ids(sensitive.length ? sensitive : offEvents),
    explanation: `${ctx.entity.name}: ${offEvents.length} event(s) (${sensitive.length} privileged) at off-hours ${hours.join(',')} — normally active ${b.active_hours.active.join(',')}`,
    dedup_key: `off_hours_activity:${hours.join('-')}`,
    severityBump: sensitive.length ? 1 : 0,
  }];
}

// ---- impossible_travel ----
function impossibleTravel(ctx) {
  const dcfg = ctx.dcfg;
  const auths = ctx.recent.filter((e) => e.category === 'authentication' && e.outcome !== 'failure' && (e.src_ip || e.host_ip))
    .map((e) => ({ e, g: geoOf(e), t: e.ts || e.rts || 0 }))
    .sort((a, z) => a.t - z.t);
  const findings = [];
  for (let i = 1; i < auths.length; i++) {
    const a = auths[i - 1], b = auths[i];
    if (a.g.ip === b.g.ip) continue;
    const r = travelInfeasible(a.g, b.g, Math.abs(b.t - a.t), dcfg);
    if (r && r.infeasible) {
      findings.push({
        detector: 'impossible_travel',
        observed: { from: a.g.ip, to: b.g.ip, from_country: a.g.country, to_country: b.g.country, detail: r.reason },
        baseline: { known_ips: (ctx.baseline && ctx.baseline.known.ips.length) || 0 },
        window: { from: a.t, to: b.t }, evidence: ids([a.e, b.e]),
        explanation: `${ctx.entity.name}: authentications from ${a.g.ip}${a.g.country ? ` (${a.g.country})` : ''} then ${b.g.ip}${b.g.country ? ` (${b.g.country})` : ''} — ${r.reason}`,
        dedup_key: `impossible_travel:${a.g.ip}:${b.g.ip}`,
      });
    }
  }
  return findings;
}

// ---- brute_force_then_success ----
function bruteThenSuccess(ctx) {
  const dcfg = ctx.dcfg;
  const winMs = (dcfg.window_min || 30) * 60000;
  const auths = ctx.recent.filter((e) => e.category === 'authentication').sort((a, z) => (a.ts || 0) - (z.ts || 0));
  const findings = [];
  for (let i = 0; i < auths.length; i++) {
    const s = auths[i];
    if (!(s.outcome === 'success' || s.action === 'logon' || s.action === 'credential-validated')) continue;
    const st = s.ts || s.rts || 0;
    const fails = auths.filter((e) => (e.outcome === 'failure' || e.action === 'logon-failed') && (e.ts || 0) <= st && st - (e.ts || 0) <= winMs);
    if (fails.length >= (dcfg.fail_min || 8)) {
      findings.push({
        detector: 'brute_force_then_success',
        observed: { failures: fails.length, window_min: dcfg.window_min || 30, success_ip: s.src_ip || s.host_ip || '' },
        baseline: { typical_auth_fail_per_day: Math.round((ctx.baseline && ctx.baseline.metrics.auth_fail.median) || 0) },
        window: { from: fails[0].ts || 0, to: st }, evidence: ids(fails.concat([s])),
        explanation: `${ctx.entity.name}: ${fails.length} failed auths then a success within ${dcfg.window_min || 30} min${s.src_ip ? ` from ${s.src_ip}` : ''}`,
        dedup_key: `brute_force_then_success:${st}`,
      });
      break;
    }
  }
  return findings;
}

// ---- dormant_wakeup ----
function dormantWakeup(ctx) {
  const b = ctx.baseline;
  if (!b || !b.last_seen || !ctx.observed.first_seen) return [];
  const idleMs = (ctx.dcfg.idle_days || 30) * 86400000;
  const gap = ctx.observed.first_seen - b.last_seen;
  if (gap < idleMs) return [];
  return [{
    detector: 'dormant_wakeup',
    observed: { idle_days: Math.floor(gap / 86400000), woke_at: ctx.observed.first_seen },
    baseline: { last_seen: b.last_seen, days_observed: b.days_observed },
    window: win(ctx.recent), evidence: ids(ctx.recent),
    explanation: `${ctx.entity.name}: active again after ${Math.floor(gap / 86400000)} idle day(s) (last seen before today ${new Date(b.last_seen).toISOString().slice(0, 10)})`,
    dedup_key: `dormant_wakeup:${Math.floor(ctx.observed.first_seen / 86400000)}`,
  }];
}

// ---- privilege_escalation / first_admin_action ----
function privEscalation(ctx) {
  const b = ctx.baseline;
  const privEvents = ctx.recent.filter(isPrivileged);
  if (!privEvents.length) return [];
  const everPriv = b && b.metrics.privileged && b.metrics.privileged.max > 0;
  const baseActions = new Set((b && b.action_types) || []);
  const newPrivActions = [...new Set(privEvents.map((e) => e.action))].filter((a) => a && !baseActions.has(a));
  if (everPriv && !newPrivActions.length) return [];
  return [{
    detector: 'privilege_escalation',
    observed: { privileged_events: privEvents.length, new_actions: newPrivActions, first_ever: !everPriv },
    baseline: { ever_privileged: !!everPriv, known_actions: [...baseActions].slice(0, 10) },
    window: win(privEvents), evidence: ids(privEvents),
    explanation: `${ctx.entity.name}: ${!everPriv ? 'first privileged/admin action ever' : `new privileged action(s) ${newPrivActions.join(', ')}`} (${privEvents.length} event(s))`,
    dedup_key: `privilege_escalation:${!everPriv ? 'first' : newPrivActions.join('-')}`,
  }];
}

// ---- lateral_movement ----
function lateralMovement(ctx) {
  const b = ctx.baseline;
  const baseHosts = new Set((b && b.known.hosts) || []);
  const newHosts = ((ctx.observed.known && ctx.observed.known.hosts) || []).filter((h) => h && !baseHosts.has(h));
  if (newHosts.length < (ctx.dcfg.new_hosts || 5)) return [];
  const evts = ctx.recent.filter((e) => e.host && newHosts.includes(e.host.toLowerCase()));
  return [{
    detector: 'lateral_movement',
    observed: { new_hosts: newHosts.length, hosts: newHosts.slice(0, 20) },
    baseline: { known_hosts: baseHosts.size },
    window: win(evts.length ? evts : ctx.recent), evidence: ids(evts),
    explanation: `${ctx.entity.name}: reached ${newHosts.length} new host(s) in the window (baseline knew ${baseHosts.size}) — ${newHosts.slice(0, 6).join(', ')}`,
    dedup_key: `lateral_movement:${Math.floor((win(evts).to || ctx.now) / 3600000)}`,
  }];
}

// ---- peer_group_outlier ----
function peerOutlier(ctx) {
  const b = ctx.baseline;
  if (!b || !ctx.peers) return [];
  const dcfg = ctx.dcfg;
  const findings = [];
  for (const m of dcfg.metrics || ['events', 'distinct_hosts', 'privileged']) {
    const peer = ctx.peers(m);
    if (!peer || peer.n < (dcfg.min_peers || 4)) continue;
    const mine = (b.metrics[m] && b.metrics[m].median) || 0;
    const z = robustZ(mine, peer.median, peer.mad, 1);
    if (z >= (dcfg.z || 3.5)) {
      findings.push({
        detector: 'peer_group_outlier', metric: m,
        observed: { metric: m, value: Math.round(mine), z: Math.round(z * 10) / 10 },
        baseline: { peer_group: ctx.entity.peer_group || '', peer_median: Math.round(peer.median), peer_p95: Math.round(peer.p95), peers: peer.n },
        window: { from: ctx.now - ctx.windowMs, to: ctx.now }, evidence: [],
        explanation: `${ctx.entity.name}: ${m} ~${Math.round(mine)}/day vs peer-group "${ctx.entity.peer_group || 'n/a'}" median ${Math.round(peer.median)} across ${peer.n} peers (z=${z.toFixed(1)})`,
        dedup_key: `peer_group_outlier:${m}`,
      });
    }
  }
  return findings;
}

// ---- data_exfil_pattern ----
function dataExfil(ctx) {
  const b = ctx.baseline;
  if (!b) return [];
  const dcfg = ctx.dcfg;
  const obs = ctx.observed.egress_bytes || 0;
  if (obs < (dcfg.min_bytes || 50000000)) return [];
  const dayFrac = Math.min(1, Math.max(ctx.windowMs / 86400000, 1 / 48));
  const bm = b.metrics.egress_bytes;
  const z = robustZ(obs, bm.median * dayFrac, bm.mad * dayFrac, Math.max(1, (dcfg.min_bytes || 50000000) * dayFrac));
  const baseSub = new Set(b.known.subnets);
  const newDest = ((ctx.observed.known && ctx.observed.known.subnets) || []).filter((s) => s && !baseSub.has(s));
  if (z < (dcfg.z || 3) || !newDest.length) return [];
  const evts = ctx.recent.filter((e) => geoOf(e).subnet24 && newDest.includes(geoOf(e).subnet24));
  return [{
    detector: 'data_exfil_pattern',
    observed: { egress: fmtBytes(obs), raw: obs, z: Math.round(z * 10) / 10, new_destinations: newDest.slice(0, 10) },
    baseline: { per_day_median: fmtBytes(Math.round(bm.median)), known_subnets: baseSub.size },
    window: win(evts.length ? evts : ctx.recent), evidence: ids(evts.length ? evts : ctx.recent),
    explanation: `${ctx.entity.name}: egress ${fmtBytes(obs)} (z=${z.toFixed(1)}) to ${newDest.length} new destination(s) ${newDest.slice(0, 4).join(', ')}`,
    dedup_key: `data_exfil_pattern:${newDest.join('-').slice(0, 64)}`,
  }];
}

// ---- AI-agent / service-account: action_outside_profile ----
function actionOutsideProfile(ctx) {
  if (!isAgent(ctx.entity)) return [];
  const b = ctx.baseline;
  if (!b) return [];
  const baseActions = new Set(b.action_types), baseTargets = new Set(b.targets);
  const newActions = ((ctx.observed.action_types) || []).filter((a) => a && !baseActions.has(a));
  const newTargets = ((ctx.observed.targets) || []).filter((t) => t && !baseTargets.has(t));
  if (!newActions.length && !newTargets.length) return [];
  const evts = ctx.recent.filter((e) => newActions.includes(e.action) || newTargets.includes((e.target_user || e.dst_ip || '').toLowerCase()));
  return [{
    detector: 'action_outside_profile',
    observed: { new_actions: newActions, new_targets: newTargets.slice(0, 10) },
    baseline: { known_actions: [...baseActions].slice(0, 12), known_targets: baseTargets.size },
    window: win(evts.length ? evts : ctx.recent), evidence: ids(evts),
    explanation: `${ctx.entity.type} ${ctx.entity.name}: performed action/target never in its profile — actions [${newActions.join(', ')}]${newTargets.length ? `, targets [${newTargets.slice(0, 4).join(', ')}]` : ''}`,
    dedup_key: `action_outside_profile:${newActions.join('-')}:${newTargets.slice(0, 3).join('-')}`,
  }];
}

// ---- rate_anomaly (agents) ----
function rateAnomaly(ctx) {
  if (!isAgent(ctx.entity)) return [];
  const b = ctx.baseline;
  if (!b || !b.rate_per_hour) return [];
  const dcfg = ctx.dcfg;
  const hours = Math.max(ctx.windowMs / 3600000, 1 / 60);
  const rate = (ctx.observed.events || 0) / hours;
  if ((ctx.observed.events || 0) < (dcfg.min_floor || 50)) return [];
  const rp = b.rate_per_hour;
  const z = robustZ(rate, rp.median, rp.mad, Math.max(1, (dcfg.min_floor || 50) / 24));
  if (z < (dcfg.z || 4)) return [];
  return [{
    detector: 'rate_anomaly',
    observed: { calls_per_hour: Math.round(rate), events: ctx.observed.events, z: Math.round(z * 10) / 10 },
    baseline: { median_per_hour: Math.round(rp.median), p95_per_hour: Math.round(rp.p95) },
    window: win(ctx.recent), evidence: ids(ctx.recent),
    explanation: `${ctx.entity.type} ${ctx.entity.name}: ~${Math.round(rate)} calls/hour vs baseline median ${Math.round(rp.median)}/hour (z=${z.toFixed(1)})`,
    dedup_key: `rate_anomaly:${Math.floor(ctx.now / 3600000)}`,
  }];
}

// ---- out_of_window (agents; cross-checks approved plan windows if reachable) ----
function outOfWindow(ctx) {
  if (!isAgent(ctx.entity)) return [];
  const b = ctx.baseline;
  const normal = new Set((b && b.windows) || []);
  const ident = ctx.identifier.aiIdentity(ctx.entity.name);
  const cfgWindows = (ident && ident.windows) || [];
  for (const w of cfgWindows) for (let h = w[0]; h !== w[1]; h = (h + 1) % 24) normal.add(h);
  if (!normal.size && !cfgWindows.length && !ctx.plans) return [];
  // approved-plan windows (absolute time ranges) take precedence when available
  const planWindows = ctx.plans && typeof ctx.plans.windowsFor === 'function' ? (ctx.plans.windowsFor(ctx.entity) || []) : null;
  const offEvents = ctx.recent.filter((e) => {
    const t = e.ts || e.rts || 0;
    if (planWindows) { if (planWindows.some((pw) => t >= pw.from && t <= pw.to)) return false; }
    return normal.size ? !normal.has(localHour(t, ctx.tz)) : !!planWindows;
  });
  if (!offEvents.length) return [];
  const hours = [...new Set(offEvents.map((e) => localHour(e.ts || e.rts || 0, ctx.tz)))].sort((a, z) => a - z);
  return [{
    detector: 'out_of_window',
    observed: { events: offEvents.length, hours, checked_plan: !!planWindows },
    baseline: { normal_hours: [...normal].sort((a, z) => a - z), approved_plan_windows: planWindows ? planWindows.length : 'n/a' },
    window: win(offEvents), evidence: ids(offEvents),
    explanation: `${ctx.entity.type} ${ctx.entity.name}: ${offEvents.length} action(s) at hour(s) ${hours.join(',')} outside its ${planWindows ? 'approved-plan' : 'normal'} schedule`,
    dedup_key: `out_of_window:${hours.join('-')}`,
  }];
}

// ---- new_api_or_scope (agents / service accounts) ----
function newApiOrScope(ctx) {
  if (!isAgent(ctx.entity)) return [];
  const b = ctx.baseline;
  if (!b || !b.known.api_scopes) return [];
  const base = new Set(b.known.api_scopes);
  const fresh = ((ctx.observed.known && ctx.observed.known.api_scopes) || []).filter((s) => s && !base.has(s));
  if (!fresh.length) return [];
  return [{
    detector: 'new_api_or_scope',
    observed: { new_scopes: fresh.slice(0, 12) },
    baseline: { known_scopes: base.size, sample: [...base].slice(0, 8) },
    window: win(ctx.recent), evidence: ids(ctx.recent),
    explanation: `${ctx.entity.type} ${ctx.entity.name}: used API/scope never seen before — ${fresh.slice(0, 6).join(', ')} (baseline knew ${base.size})`,
    dedup_key: `new_api_or_scope:${fresh.join('-').slice(0, 80)}`,
  }];
}

// ---- identity_misuse (agent identity from an unexpected host/IP) ----
function identityMisuse(ctx) {
  if (ctx.entity.type !== 'ai_agent' && ctx.entity.type !== 'service_account') return [];
  const ident = ctx.identifier.aiIdentity(ctx.entity.name);
  const homeList = (ident && ident.home_ips) || [];
  let homeSet = null;
  if (homeList.length) { try { homeSet = createCidrSet(homeList); } catch { homeSet = null; } }
  // fall back to the established baseline's known IPs as the agent's "home"
  const baseIps = (ctx.baseline && ctx.baseline.known.ips) || [];
  if (!homeSet && !baseIps.length) return [];
  const baseIpSet = new Set(baseIps);
  const bad = ctx.recent.filter((e) => {
    const ip = e.src_ip || e.host_ip;
    if (!ip) return false;
    if (homeSet) return !homeSet.has(ip);
    return !baseIpSet.has(ip);
  });
  if (!bad.length) return [];
  const badIps = [...new Set(bad.map((e) => e.src_ip || e.host_ip))];
  return [{
    detector: 'identity_misuse',
    observed: { from_ips: badIps.slice(0, 10) },
    baseline: { home_ips: homeList.length ? homeList : 'baseline', known_ips: baseIps.length },
    window: win(bad), evidence: ids(bad),
    explanation: `${ctx.entity.type} ${ctx.entity.name}: identity used from unexpected IP(s) ${badIps.slice(0, 5).join(', ')} — expected ${homeList.length ? `platform ${homeList.join(', ')}` : 'its baseline hosts'}`,
    dedup_key: `identity_misuse:${badIps.sort().join('-').slice(0, 64)}`,
  }];
}

function isAgent(entity) { return entity.type === 'ai_agent' || entity.type === 'service_account'; }

// registry: name → { fn, needsEstablished }
const REGISTRY = {
  first_seen_country: { fn: (c) => firstSeen(c, 'first_seen_country'), needsEstablished: false },
  first_seen_subnet: { fn: (c) => firstSeen(c, 'first_seen_subnet'), needsEstablished: false },
  first_seen_host: { fn: (c) => firstSeen(c, 'first_seen_host'), needsEstablished: false },
  first_seen_service: { fn: (c) => firstSeen(c, 'first_seen_service'), needsEstablished: false },
  first_seen_process: { fn: (c) => firstSeen(c, 'first_seen_process'), needsEstablished: false },
  first_seen_logon_type: { fn: (c) => firstSeen(c, 'first_seen_logon_type'), needsEstablished: false },
  volume_spike: { fn: volumeSpike, needsEstablished: true },
  off_hours_activity: { fn: offHours, needsEstablished: true },
  impossible_travel: { fn: impossibleTravel, needsEstablished: false },
  brute_force_then_success: { fn: bruteThenSuccess, needsEstablished: false },
  dormant_wakeup: { fn: dormantWakeup, needsEstablished: true },
  privilege_escalation: { fn: privEscalation, needsEstablished: false },
  lateral_movement: { fn: lateralMovement, needsEstablished: true },
  peer_group_outlier: { fn: peerOutlier, needsEstablished: true },
  data_exfil_pattern: { fn: dataExfil, needsEstablished: true },
  action_outside_profile: { fn: actionOutsideProfile, needsEstablished: true },
  rate_anomaly: { fn: rateAnomaly, needsEstablished: true },
  out_of_window: { fn: outOfWindow, needsEstablished: true },
  new_api_or_scope: { fn: newApiOrScope, needsEstablished: true },
  identity_misuse: { fn: identityMisuse, needsEstablished: false },
};

function runDetectors(ctx) {
  const out = [];
  const established = ctx.entity.state === 'established';
  for (const [name, def] of Object.entries(REGISTRY)) {
    const dcfg = detectorConfig(ctx.settings, name);
    if (dcfg.enabled === false) continue;
    if (def.needsEstablished && !established) continue;
    let findings;
    try { findings = def.fn({ ...ctx, dcfg }) || []; } catch (e) { findings = []; if (ctx.log) ctx.log.warn('ueba detector failed', { detector: name, err: e.message }); }
    for (const f of findings) {
      f.severity = Math.max(0, Math.min(4, (dcfg.severity || 2) + (f.severityBump || 0)));
      f.weight = dcfg.weight || 3;
      f.mitre = dcfg.mitre || [];
      delete f.severityBump;
      out.push(f);
    }
  }
  return out;
}

module.exports = { runDetectors, REGISTRY, KNOWN_KEYS };
