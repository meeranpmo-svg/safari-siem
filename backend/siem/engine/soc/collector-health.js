// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * LogRhythm collector-health flood remediation (parallel-run noise control).
 *
 * During the LogRhythm parallel run the portal Alert Center floods with ~170 HIGH alerts titled, e.g.
 *   "Failed to read log source (<SRC> WinEvtXML - Security): One or more errors occurred. on lr01.the organisation"
 * These are LogRhythm System Monitor's OWN log-source-collection failure DIAGNOSTICS (WinEvtXML = LogRhythm's MS Windows
 * Event Log XML log-source type), imported through the LogRhythm path (engine/api/lr-import.js / engine/soc/lrcompare.js,
 * source 'logrhythm'). Each distinct LR alarm id otherwise becomes its OWN alert (lrcompare group_key 'lr:<alarm_id>'),
 * so hundreds of occurrences of the same failing source become hundreds of separate HIGH security alerts.
 *
 * This module recognises that class of SELF-DIAGNOSTIC collector event and collapses it into a SINGLE aggregated, deduped,
 * low-severity OPERATIONAL "log collection health" signal PER FAILING SOURCE (rule_id LR-COLLECTOR-HEALTH, group_key
 * 'lrhealth:<collector>:<source>', long suppress window) - NOT a HIGH security detection. alerts.raise() then merges every
 * further occurrence of the same failing source into that one alert (count keeps rising, emission stays bounded). N
 * distinct failing sources -> N aggregated alerts, not 170.
 *
 * Operator setting (per the parallel run): mode
 *   'aggregate' (default) - roll up to one low/medium-severity health alert per failing source,
 *   'suppress'            - raise no alert at all, only count it in the health registry (quietest),
 *   'off'                 - original behaviour (one LR alert per diagnostic alarm).
 * A rolled-up health view is ALWAYS kept (state collection 'collector_health') so operators can still SEE which sources
 * are failing and how often, in every mode. Nothing here deletes or hides the underlying LR import.
 */

const DIAG_RULE_ID = 'LR-COLLECTOR-HEALTH';
const DIAG_RULE_NAME = 'LogRhythm log collection health';
const MODES = new Set(['aggregate', 'suppress', 'off']);
const DEFAULT_SEVERITY = 1;         // low / operational (never HIGH)
const DEFAULT_SUPPRESS_S = 86400;   // 24h: keep all occurrences of one source in a single alert during the run

// LogRhythm System Monitor / Data Processor log-collection self-diagnostic classes (NOT security detections).
const DIAG_RE = /failed to read log source|one or more errors occurred|log source .{0,40}(?:error|fail|unreachable|unavailable)|unable to (?:read|collect|connect|open).{0,40}log source|log ?(?:source|collection) (?:failure|failed|error)|winevtxml|system monitor .{0,40}(?:error|fail|unreachable)|data (?:indexer|processor|collector) .{0,40}(?:error|unreachable|fail)|log source is (?:silent|down|unavailable)|(?:collection|collector) (?:failure|failed|error|heartbeat)/i;

const SRC_STR = (v) => (v === undefined || v === null ? '' : String(v)).trim();

/** Is this native LR alarm a collector-health self-diagnostic (vs a real security detection)? */
function isCollectorDiagnostic(al) {
  if (!al || typeof al !== 'object') return false;
  const hay = `${SRC_STR(al.alarm_rule_name)} ${SRC_STR(al.log_source_type)} ${SRC_STR(al.log_source)}`;
  return DIAG_RE.test(hay);
}

/** Best-effort failing-source label: the "(<SRC> WinEvtXML - ...)" inside the title, else log_source, else host. */
function failingSourceOf(al) {
  const name = SRC_STR(al.alarm_rule_name);
  let m = /log source\s*\(\s*([^)]+?)(?:\s+WinEvtXML| -\s|\s*\))/i.exec(name);
  if (m && m[1]) return m[1].trim().slice(0, 200);
  m = /log source[:\s]+"?([^"\n,]{2,100})"?/i.exec(name);
  if (m && m[1] && !/error|fail/i.test(m[1])) return m[1].trim().slice(0, 200);
  return SRC_STR(al.log_source) || SRC_STR(al.host) || 'unknown';
}

/** The collector/host the diagnostic is reported on ("... on lr01.the organisation"). */
function collectorOf(al) {
  const m = /\bon\s+([A-Za-z0-9][A-Za-z0-9._-]{1,120})\s*$/.exec(SRC_STR(al.alarm_rule_name));
  return (m && m[1]) || SRC_STR(al.host) || SRC_STR(al.entity) || 'collector';
}

function toMs(v) {
  if (typeof v === 'number') return v;
  if (v === undefined || v === null || v === '') return 0;
  const n = Number(v);
  if (Number.isFinite(n)) return n;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : 0;
}

/** Aggregated low-severity health partial for alerts.raise() (collapses per failing source). */
function healthPartial(al, opts = {}) {
  const src = failingSourceOf(al);
  const collector = collectorOf(al);
  const at = toMs(al.alarm_date) || Date.now();
  const severity = Math.max(0, Math.min(2, opts.severity === undefined ? DEFAULT_SEVERITY : Number(opts.severity)));
  return {
    rule_id: DIAG_RULE_ID, rule_name: DIAG_RULE_NAME, rule_type: 'logrhythm-health', severity,
    mitre: [], tactic: '', group: { collector, source: src }, group_key: `lrhealth:${collector}:${src}`,
    count: 1, ts_first: at, ts_last: at, sample_event_ids: [],
    summary: `${DIAG_RULE_NAME} — ${src} on ${collector} (collector diagnostic, aggregated)`,
    fields: {
      category: 'operational', signal: 'log-collection-health', lr_class: 'collector-diagnostic',
      failing_source: src, collector_host: collector, log_source_type: SRC_STR(al.log_source_type) || undefined,
      last_error: SRC_STR(al.alarm_rule_name).slice(0, 400) || undefined,
    },
    source: 'logrhythm', src_type: 'logrhythm-health', src_id: SRC_STR(al.log_source), host: collector,
    lr_alarm_id: SRC_STR(al.alarm_id), suppress_s: opts.suppress_s === undefined ? DEFAULT_SUPPRESS_S : Number(opts.suppress_s),
  };
}

/**
 * createCollectorHealth({ state, config }) → operator-facing controller used by the LR import path.
 *   getMode() / setMode(mode, by)  — persisted in state collection 'settings' (doc 'lr_collector_health')
 *   ingest(nativeAlarm)            — { action: 'passthrough' | 'suppress' | 'aggregate', partial? }  (+ records the registry)
 *   view()                         — rolled-up per-failing-source health [{ id, collector, source, count, first, last, last_error }]
 */
function createCollectorHealth({ state, config } = {}) {
  if (!state) throw new Error('createCollectorHealth needs state');
  const settings = state.collection('settings');
  const registry = state.collection('collector_health');
  const SET_ID = 'lr_collector_health';
  const cfgDefault = ((config && config.lr) || {}).collector_health_mode;
  const defaultMode = MODES.has(cfgDefault) ? cfgDefault : 'aggregate';

  function getMode() {
    const d = settings.get(SET_ID);
    return d && MODES.has(d.mode) ? d.mode : defaultMode;
  }
  function setMode(mode, by) {
    if (!MODES.has(mode)) throw Object.assign(new Error(`mode must be one of ${[...MODES].join(', ')}`), { status: 400 });
    settings.put({ id: SET_ID, mode, updated: Date.now(), updated_by: by || 'system' });
    return mode;
  }
  function record(al) {
    const src = failingSourceOf(al), collector = collectorOf(al), at = toMs(al.alarm_date) || Date.now();
    const id = `${collector}|${src}`;
    const cur = registry.get(id);
    registry.put({
      id, collector, source: src, log_source_type: SRC_STR(al.log_source_type),
      count: ((cur && cur.count) || 0) + 1,
      first: cur && cur.first ? Math.min(cur.first, at) : at, last: Math.max((cur && cur.last) || 0, at),
      last_error: SRC_STR(al.alarm_rule_name).slice(0, 400),
    });
  }
  function ingest(al) {
    if (!isCollectorDiagnostic(al)) return { action: 'passthrough' };
    record(al);
    const mode = getMode();
    if (mode === 'off') return { action: 'passthrough' };
    if (mode === 'suppress') return { action: 'suppress' };
    return { action: 'aggregate', partial: healthPartial(al) };
  }
  function view() {
    return registry.all().sort((a, b) => (b.count || 0) - (a.count || 0) || (b.last || 0) - (a.last || 0));
  }
  return { getMode, setMode, ingest, view, MODES: [...MODES] };
}

module.exports = {
  createCollectorHealth, isCollectorDiagnostic, failingSourceOf, collectorOf, healthPartial,
  DIAG_RULE_ID, DIAG_RULE_NAME, MODES: [...MODES],
};
