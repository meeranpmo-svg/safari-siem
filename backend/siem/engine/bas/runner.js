// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * the organisation SIEM — SAFE synthetic test-event injection runner (DEFENSIVE).
 *
 * The runner validates detection coverage WITHOUT touching endpoints or raising real alerts. For each scenario it:
 *   1. parses the scenario's synthetic log lines with a FRESH parser instance (never the live collector parser),
 *   2. tags every resulting event simulation:true + a run_id (tags 'simulation','bas'; fields.simulation / bas_run_id),
 *   3. feeds them through an ISOLATED detector compiled from the SAME effective rules as the live engine, whose
 *      onAlert writes ONLY to the in-memory run record — it is NEVER wired to soc/alerts.js, so a simulated detection
 *      cannot become a live alert/offense, cannot trigger any outbound notification or response/playbook action, and
 *      is not written to ClickHouse or counted in live metrics.
 *   4. records per-technique DETECTED / MISSED, which rule fired, and the processing latency.
 *
 * SAFETY INVARIANTS (enforced here, asserted by tests):
 *   - no network I/O, no endpoint execution, no payloads — only in-memory parse + detect of synthetic strings;
 *   - synthetic events never reach the live pipeline, writer/ClickHouse, live detector, alerts, cases or metrics;
 *   - every event carries simulation:true + the run_id; runs are purgeable by run_id.
 *
 *   createRunner({ rulesProvider, createDetector, createParser, intel?, now?, log?, maxRuns?, maxRunAgeMs? })
 *     → { simulate({scenario_ids?, technique_ids?, by}), getRun(id), listRuns(), purge(id), stats() }
 */
const scenarios = require('./scenarios');

function rid(now) {
  const d = new Date(now);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const stamp = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
  return `BAS-${stamp}-${Math.random().toString(36).slice(2, 7)}`;
}

function createRunner(opts = {}) {
  const rulesProvider = opts.rulesProvider || (() => []);
  const createDetector = opts.createDetector || require('../detect/engine').createDetector;
  const createParser = opts.createParser || require('../parse').createParser;
  const intel = opts.intel || null;
  const now = opts.now || Date.now;
  const log = opts.log || { info() {}, warn() {}, error() {}, debug() {} };
  const maxRuns = opts.maxRuns || 200;
  const maxRunAgeMs = opts.maxRunAgeMs || 7 * 86400000;

  const runs = new Map(); // run_id → run record
  const parser = createParser({ log }); // one fresh parser, isolated from the live collector parser's stats
  const st = { runs: 0, scenarios_run: 0, events_injected: 0, detections: 0, misses: 0, purged: 0 };

  function markSimulation(ev, runId) {
    if (!ev || typeof ev !== 'object') return ev;
    if (!Array.isArray(ev.tags)) ev.tags = ev.tags ? [ev.tags] : [];
    if (ev.tags.indexOf('simulation') < 0) ev.tags.push('simulation');
    if (ev.tags.indexOf('bas') < 0) ev.tags.push('bas');
    if (!ev.fields || typeof ev.fields !== 'object') ev.fields = {};
    ev.fields.simulation = 'true';
    ev.fields.bas_run_id = runId;
    ev.simulation = true;
    ev.bas_run_id = runId;
    return ev;
  }

  /** Run ONE scenario through its own isolated detector; returns the result row. Nothing escapes this function. */
  function runScenario(scn, runId, rules) {
    const fired = [];
    // Isolated detector: onAlert is a local sink. It is NEVER alerts.raise — simulated detections stay in memory.
    const det = createDetector({
      rules, intel, log,
      now: () => now() + 3600000, // wall clock ahead so suppression windows do not re-fire within the run
      onAlert: (p) => { if (!p.update) fired.push({ rule_id: p.rule_id, rule_name: p.rule_name, severity: p.severity, mitre: p.mitre || [], count: p.count }); },
    });
    const built = scn.build({ run_id: runId, now: now() });
    const t0 = Date.now();
    let injected = 0;
    for (const item of built) {
      const ev = parser.parse(item.line, item.meta || { src_type: scn.src_type, src_id: 'bas-sim' });
      markSimulation(ev, runId);
      det.onEvent(ev);
      injected++;
    }
    det.flush();
    const latency = Date.now() - t0;

    // de-duplicate fired rules (keep highest severity / first)
    const byRule = new Map();
    for (const f of fired) if (!byRule.has(f.rule_id)) byRule.set(f.rule_id, f);
    const detectedRules = [...byRule.values()];
    const firedIds = new Set(detectedRules.map((r) => r.rule_id));
    const firedExpected = scn.expect_rule ? firedIds.has(scn.expect_rule) : false;
    // DETECTED only when the expected rule fired. A control scenario has no expected rule, so it is always MISSED
    // (its technique is a genuine coverage gap) — the runner never fabricates a detection.
    const status = firedExpected ? 'detected' : 'missed';
    const unexpected = scn.control ? detectedRules.map((r) => r.rule_id) : [];

    st.scenarios_run++;
    st.events_injected += injected;
    if (status === 'detected') st.detections++; else st.misses++;

    return {
      scenario_id: scn.id, name: scn.name, control: !!scn.control,
      technique: scn.technique, techniques: scn.techniques.slice(),
      source_class: scn.source_class, src_type: scn.src_type,
      expect_rule: scn.expect_rule, fired_expected: firedExpected,
      status, detected_rules: detectedRules, unexpected_rules: unexpected, events_injected: injected, latency_ms: latency,
      note: scn.control ? 'Control scenario: no rule maps to this technique, so MISSED is the expected result (it validates that the runner reports gaps honestly).' : '',
      synthetic: true,
    };
  }

  function sweep() {
    const cutoff = now() - maxRunAgeMs;
    for (const [id, r] of runs) if (r.started_ms < cutoff) runs.delete(id);
    while (runs.size > maxRuns) { const k = runs.keys().next().value; runs.delete(k); }
  }

  function simulate({ scenario_ids, technique_ids, by } = {}) {
    let chosen;
    if (Array.isArray(scenario_ids) && scenario_ids.length) {
      chosen = scenario_ids.map((id) => scenarios.get(id)).filter(Boolean);
      const missing = scenario_ids.filter((id) => !scenarios.get(id));
      if (missing.length) { const e = new Error(`unknown scenario id(s): ${missing.join(', ')}`); e.code = 400; throw e; }
    } else if (Array.isArray(technique_ids) && technique_ids.length) {
      chosen = scenarios.forTechniques(technique_ids);
      if (!chosen.length) { const e = new Error(`no scenario covers the requested technique(s): ${technique_ids.join(', ')}`); e.code = 400; throw e; }
    } else {
      chosen = scenarios.SCENARIOS.slice();
    }

    const runId = rid(now());
    const rules = (rulesProvider() || []).filter((r) => r && r.enabled !== false);
    const startedMs = now();
    const results = [];
    for (const scn of chosen) {
      try { results.push(runScenario(scn, runId, rules)); } catch (e) {
        log.error('bas scenario failed', { scenario: scn.id, err: e.message });
        results.push({ scenario_id: scn.id, name: scn.name, status: 'error', error: e.message, synthetic: true });
      }
    }

    const detected = results.filter((r) => r.status === 'detected');
    const missed = results.filter((r) => r.status === 'missed');
    const techDetected = [...new Set(detected.flatMap((r) => r.techniques || []))].sort();
    const techAll = [...new Set(results.flatMap((r) => r.techniques || []))].sort();
    const techMissed = techAll.filter((t) => techDetected.indexOf(t) < 0);

    const run = {
      run_id: runId, started_at: new Date(startedMs).toISOString(), started_ms: startedMs,
      finished_at: new Date(now()).toISOString(), by: by || 'unknown',
      scenario_ids: chosen.map((s) => s.id), technique_ids_requested: Array.isArray(technique_ids) ? technique_ids.slice() : [],
      results,
      summary: {
        scenarios: results.length, detected: detected.length, missed: missed.length,
        events_injected: results.reduce((a, r) => a + (r.events_injected || 0), 0),
        techniques_validated: techAll, techniques_detected: techDetected, techniques_missed: techMissed,
        detection_pct: results.length ? Math.round((detected.length * 100) / results.length) : 0,
      },
      safety: {
        simulation: true, events_tagged: true, isolated_detector: true,
        raised_to_live_alerts: false, outbound_notifications: false, response_actions: false,
        written_to_store: false, counted_in_live_metrics: false,
        note: 'Synthetic detection test. Events were parsed and run through an isolated copy of the detection rules only; no real attack, scan, payload or endpoint action occurred, and no live alert, notification, response action or stored event was produced.',
      },
      rules_loaded: rules.length,
    };
    runs.set(runId, run);
    st.runs++;
    sweep();
    log.info('bas run complete', { run_id: runId, scenarios: run.summary.scenarios, detected: run.summary.detected, missed: run.summary.missed, by: run.by });
    return run;
  }

  function getRun(id) { return runs.get(id) || null; }
  function listRuns() {
    return [...runs.values()].sort((a, b) => b.started_ms - a.started_ms).map((r) => ({
      run_id: r.run_id, started_at: r.started_at, finished_at: r.finished_at, by: r.by,
      summary: r.summary, scenario_ids: r.scenario_ids, safety: { simulation: true },
    }));
  }
  function purge(id) {
    const r = runs.get(id);
    if (!r) { const e = new Error(`run ${id} not found`); e.code = 404; throw e; }
    runs.delete(id);
    st.purged++;
    return { run_id: id, purged: true, events_purged: r.summary ? r.summary.events_injected : 0 };
  }

  return {
    simulate, getRun, listRuns, purge,
    scenarios: () => scenarios.list(),
    stats: () => Object.assign({}, st, { runs_held: runs.size }),
  };
}

module.exports = { createRunner };
