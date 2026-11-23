// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA settings — defaults, deep-merge of admin overrides, and validation.
 *
 *   defaultSettings()                → the full built-in settings object (see DEFAULTS below)
 *   mergeSettings(base, over)        → deep merge (objects merged, scalars/arrays replaced)
 *   validateSettings(s)              → throws Error('ueba settings invalid: …') on bad input, else returns s
 *   detectorConfig(settings, name)   → { enabled, ...thresholds } for one detector (defaults filled)
 *
 * Everything the engine and the detectors read is here so an admin can tune windows, thresholds, detector
 * toggles, sensitivity and the service-account / ai-agent identity lists through GET/POST /api/soc/ueba/settings.
 * Node standard library only; no side effects.
 */

const DAY_MS = 86400000;

// Per-detector defaults. severity is the base severity (0-4) of the finding; weight feeds the risk score.
const DETECTOR_DEFAULTS = {
  first_seen_country:    { enabled: true,  severity: 3, weight: 6,  mitre: ['T1078'] },
  first_seen_subnet:     { enabled: true,  severity: 1, weight: 2,  mitre: ['T1078'] },
  first_seen_host:       { enabled: true,  severity: 1, weight: 2,  mitre: [] },
  first_seen_service:    { enabled: true,  severity: 1, weight: 2,  mitre: [] },
  first_seen_process:    { enabled: true,  severity: 2, weight: 3,  mitre: ['T1059'] },
  first_seen_logon_type: { enabled: true,  severity: 2, weight: 3,  mitre: ['T1078'] },
  volume_spike:          { enabled: true,  severity: 2, weight: 4,  z: 3.5, min_floor: 20, metrics: ['events', 'auth_fail', 'egress_bytes'], mitre: [] },
  off_hours_activity:    { enabled: true,  severity: 2, weight: 3,  min_sensitive: 1, quiet_pct: 0.02, mitre: ['T1078'] },
  impossible_travel:     { enabled: true,  severity: 4, weight: 9,  max_kph: 900, min_km: 500, min_gap_min_diff_country: 60, mitre: ['T1078'] },
  brute_force_then_success: { enabled: true, severity: 4, weight: 9, fail_min: 8, window_min: 30, mitre: ['T1110.001'] },
  dormant_wakeup:        { enabled: true,  severity: 2, weight: 4,  idle_days: 30, mitre: ['T1078'] },
  privilege_escalation:  { enabled: true,  severity: 3, weight: 6,  mitre: ['T1548'] },
  lateral_movement:      { enabled: true,  severity: 3, weight: 6,  new_hosts: 5, window_min: 60, mitre: ['T1021'] },
  peer_group_outlier:    { enabled: true,  severity: 2, weight: 3,  z: 3.5, min_peers: 4, metrics: ['events', 'distinct_hosts', 'privileged'], mitre: [] },
  data_exfil_pattern:    { enabled: true,  severity: 4, weight: 8,  z: 3, min_bytes: 50000000, mitre: ['T1041'] },
  // AI-agent / service-account specific
  action_outside_profile: { enabled: true, severity: 3, weight: 6,  mitre: ['T1098'] },
  rate_anomaly:          { enabled: true,  severity: 3, weight: 5,  z: 4, min_floor: 50, mitre: [] },
  out_of_window:         { enabled: true,  severity: 3, weight: 5,  mitre: ['T1078'] },
  new_api_or_scope:      { enabled: true,  severity: 2, weight: 4,  mitre: ['T1098'] },
  identity_misuse:       { enabled: true,  severity: 4, weight: 9,  mitre: ['T1078.004'] },
};

const DEFAULTS = {
  enabled: true,
  timezone_offset_min: 180,          // Asia/Riyadh (UTC+3) for active-hour histograms / work vs off hours
  learning_window_days: 30,          // how far back baselines look
  min_days_established: 7,           // fewer observed days => entity is "learning"
  detect_lookback_min: 60,           // recent-events window each detector cycle (with overlap)
  baseline_interval_h: 24,           // nightly baseline rebuild cadence (scheduler)
  detect_interval_min: 5,            // detector cadence (scheduler)
  work_hours: [7, 19],               // [start, end) local hours considered "work" (for off-hours weighting)
  ewma_alpha: 0.3,                   // EWMA smoothing for gradual-change tracking
  max_set_size: 512,                 // cap on stored known-value sets (ips/subnets/countries/hosts/…)
  // robust stats floors so a tiny baseline can't make everything look anomalous
  min_baseline_days: 3,
  // risk scoring
  risk: {
    half_life_h: 24,                 // time decay half-life
    window_h: 168,                   // findings older than this drop out of the score (7 days)
    confirm_multiplier: 2.0,         // a confirmed finding weighs this much more
    tiers: { elevated: 15, high: 40, critical: 80 },  // score thresholds; below "elevated" = low
    alert_tier: 'high',              // raise a UEBA-RISK alert when an entity reaches this tier
    alert_min_severity: 3,           // raise a per-finding alert for findings at/above this severity
    max_timeline: 500,               // risk-timeline points kept per entity
  },
  // role / asset sensitivity multipliers applied to the risk score
  sensitivity: { user: 1, host: 1, service_account: 1.2, ai_agent: 1.3, admin_tag: 1.5, by_peer_group: {} },
  // identity classification
  service_accounts: {
    patterns: ['^svc[-_.]', '[-_.]svc$', '^service[-_.]', '\\$$'],  // regexes on the account name
    names: [],                                                      // explicit account names
  },
  ai_agents: {
    // each: { name, match: { user?:[], collector?:[], src_type?:[] }, home_ips?:[cidr], windows?:[[h,h]] }
    identities: [
      { name: 'soar',     match: { user: ['svc-soar', 'soar'], collector: [] }, home_ips: [], windows: [] },
      { name: 'ai-team',  match: { user: ['svc-aiteam', 'ai-team', 'aiteam'] }, home_ips: [], windows: [] },
      { name: 'uc-agent', match: { user: ['svc-uc', 'uc-agent', 'ucagent'] }, home_ips: [], windows: [] },
      { name: 'autopilot', match: { user: ['svc-autopilot', 'autopilot'] }, home_ips: [], windows: [] },
      { name: 'n8n',      match: { user: ['svc-n8n', 'n8n'] }, home_ips: [], windows: [] },
    ],
  },
  // detectors: per-name overrides merged over DETECTOR_DEFAULTS
  detectors: {},
};

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

function deepMerge(base, over) {
  if (!isObj(over)) return base;
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  return out;
}

function defaultSettings() {
  // deep clone so callers can mutate safely
  return JSON.parse(JSON.stringify(DEFAULTS));
}

function mergeSettings(base, over) {
  return deepMerge(base || defaultSettings(), over || {});
}

function detectorConfig(settings, name) {
  const base = DETECTOR_DEFAULTS[name] || { enabled: true, severity: 2, weight: 3, mitre: [] };
  const over = (settings && settings.detectors && settings.detectors[name]) || {};
  return deepMerge(base, over);
}

function detectorNames() { return Object.keys(DETECTOR_DEFAULTS); }

function validateSettings(s) {
  const errs = [];
  const num = (v, name, lo, hi) => { const n = Number(v); if (!Number.isFinite(n) || (lo !== undefined && n < lo) || (hi !== undefined && n > hi)) errs.push(`${name} must be a number${lo !== undefined ? ` >= ${lo}` : ''}`); };
  if (s.learning_window_days !== undefined) num(s.learning_window_days, 'learning_window_days', 1);
  if (s.min_days_established !== undefined) num(s.min_days_established, 'min_days_established', 1);
  if (s.detect_lookback_min !== undefined) num(s.detect_lookback_min, 'detect_lookback_min', 1);
  if (s.timezone_offset_min !== undefined) num(s.timezone_offset_min, 'timezone_offset_min', -720, 840);
  if (s.ewma_alpha !== undefined) num(s.ewma_alpha, 'ewma_alpha', 0, 1);
  if (s.risk) {
    if (s.risk.half_life_h !== undefined) num(s.risk.half_life_h, 'risk.half_life_h', 0.01);
    const t = s.risk.tiers;
    if (t && !(Number(t.elevated) <= Number(t.high) && Number(t.high) <= Number(t.critical))) errs.push('risk.tiers must satisfy elevated <= high <= critical');
    if (s.risk.alert_tier !== undefined && !['elevated', 'high', 'critical'].includes(s.risk.alert_tier)) errs.push('risk.alert_tier must be elevated|high|critical');
  }
  for (const [name, dc] of Object.entries(s.detectors || {})) {
    if (!DETECTOR_DEFAULTS[name]) errs.push(`unknown detector "${name}"`);
    if (dc && dc.severity !== undefined && !(Number(dc.severity) >= 0 && Number(dc.severity) <= 4)) errs.push(`detectors.${name}.severity must be 0-4`);
  }
  for (const a of (s.ai_agents && s.ai_agents.identities) || []) {
    if (!a || typeof a.name !== 'string' || !a.name.trim()) errs.push('ai_agents.identities[].name required');
  }
  if (errs.length) throw new Error('ueba settings invalid: ' + errs.join('; '));
  return s;
}

module.exports = {
  DEFAULTS, DETECTOR_DEFAULTS, DAY_MS,
  defaultSettings, mergeSettings, validateSettings, detectorConfig, detectorNames,
};
