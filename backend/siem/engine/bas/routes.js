// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Breach-&-Attack-Simulation / detection-validation API (DEFENSIVE) — register(api, deps).
 * deps = { state, config, log, detector, alerts, ch, tracker, intel, search }.
 * {P} = config.api_prefix || '/api/soc'. Reads: any signed-in role (operators included). Writes (simulate / purge): admin.
 *
 *   GET  {P}/bas/coverage                → { tactics, techniques[], summary, unmapped_rules, source_classes, connected_source_classes, sources_summary, generated_at }
 *   GET  {P}/bas/scenarios               → { scenarios[], note }
 *   POST {P}/bas/simulate                admin {scenario_id | scenario_ids[] | technique_ids[]} → run record
 *   GET  {P}/bas/runs                    → { runs[] }
 *   GET  {P}/bas/runs/:id                → run record
 *   POST {P}/bas/runs/:id/purge          admin → { run_id, purged }
 *   GET  {P}/bas/assurance               → detection assurance (bas/assurance.js): score, per-scenario / technique learning, ranked gaps, trend, schedule
 *   POST {P}/bas/assurance/run           admin → run every scenario now (recorded in history)                         audited
 *   POST {P}/bas/assurance/settings      admin {schedule: off|daily|weekly, hour 0-23, version} - a person              audited
 *   POST {P}/bas/assurance/ask           operator {question?} the AI purple-team advisor (read-only, proposes)        audited
 *
 * Isolation: simulation NEVER touches soc/alerts.js, the live detector, the writer/ClickHouse or live metrics — the
 * runner builds its own detector from a snapshot of the effective rules and captures detections in memory only.
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const { createAssurance, SCHEDULES } = require('./assurance');
const { computeCoverage, connectedClassesFrom, SOURCE_CLASSES } = require('./coverage');
const scenarios = require('./scenarios');
const { createRunner } = require('./runner');

let ruleset = null;
function rulesetMod() { if (!ruleset) ruleset = require('../detect/ruleset'); return ruleset; }
let obState = null;
function obStateMod() { if (!obState) obState = require('../onboard/state'); return obState; }
let detectEngine = null;
function detectEngineMod() { if (!detectEngine) detectEngine = require('../detect/engine'); return detectEngine; }
let parseMod = null;
function parseModule() { if (!parseMod) parseMod = require('../parse'); return parseMod; }

function register(api, deps) {
  const P = prefixOf(deps);
  const B = `${P}/bas`;
  const cfg = deps.config || {};
  const log = deps.log || { info() {}, warn() {}, error() {} };
  const db = (cfg.clickhouse && cfg.clickhouse.database) || 'siem';
  const clock = typeof deps.now === 'function' ? deps.now : Date.now;

  const rs = rulesetMod();
  const rulesDir = cfg.detect && cfg.detect.rules_dir;
  let builtins = [];
  try { builtins = rs.loadBuiltinRules(rulesDir || undefined); } catch (e) { log.error('bas: built-in rules failed to load', { err: e.message }); }
  const effective = () => {
    try { return rs.effectiveRules(deps.state, builtins); } catch (e) { log.error('bas: effectiveRules failed', { err: e.message }); return builtins; }
  };

  const runner = deps.basRunner || createRunner({
    rulesProvider: effective,
    createDetector: detectEngineMod().createDetector,
    createParser: parseModule().createParser,
    intel: deps.intel || null,
    now: clock, log,
  });

  // Which log-source classes are currently connected (receiving / silent) — from the onboarding source registry + live tracker + ClickHouse rollup.
  async function connectedClasses() {
    const sources = (cfg.sources || []).filter((s) => s && s.id);
    if (!sources.length) return { set: new Set(), rows: [], stats_available: false };
    const os = obStateMod();
    const live = new Map(deps.tracker && typeof deps.tracker.summary === 'function' ? deps.tracker.summary().map((s) => [s.src_id, s]) : []);
    let agg = new Map(); let ok = false;
    try { const r = await os.collectAgg(deps.ch, db, clock()); agg = r.agg; ok = r.ok; } catch { /* store unavailable → configured sources only */ }
    const windowMs = Math.max(60000, ((cfg.onboard && cfg.onboard.receiving_window_min) || 15) * 60000);
    const rows = sources.map((s) => os.sourceState({ cfg: s, live: live.get(s.id), agg: agg.get(s.id), now: clock(), windowMs }));
    return { set: connectedClassesFrom(rows.map((r) => ({ type: r.type, state: r.state }))), rows, stats_available: ok };
  }

  // ---- coverage (read)
  api.route('GET', `${B}/coverage`, wrap(deps, null, async (ctx) => {
    const { set, rows, stats_available } = await connectedClasses();
    const cov = computeCoverage({ rules: effective(), connectedClasses: set, now: clock });
    const summary = { receiving: 0, silent: 0, waiting: 0, total: rows.length };
    for (const r of rows) summary[r.state] = (summary[r.state] || 0) + 1;
    return ctx.ok(Object.assign({}, cov, {
      connected_source_classes: [...set].sort(),
      sources_summary: summary,
      stats_available,
    }));
  }));

  // ---- scenarios (read)
  api.route('GET', `${B}/scenarios`, wrap(deps, null, (ctx) => ctx.ok({
    scenarios: scenarios.list(), count: scenarios.SCENARIOS.length, label: scenarios.SYN,
    note: 'Synthetic detection-validation scenarios. Running one injects clearly-benign fake log lines into an isolated copy of the detection rules — no real attacks, no endpoints touched.',
  })));

  // ---- simulate (admin)
  api.route('POST', `${B}/simulate`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const scenarioIds = b.scenario_ids || (b.scenario_id ? [b.scenario_id] : null);
    const techIds = Array.isArray(b.technique_ids) ? b.technique_ids : null;
    if (scenarioIds && !Array.isArray(scenarioIds)) throw new HttpError(400, 'scenario_ids must be an array');
    let run;
    try { run = runner.simulate({ scenario_ids: scenarioIds, technique_ids: techIds, by: ctx.user }); }
    catch (e) { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; }
    if (deps.basAssurance) deps.basAssurance.record(run);   // every run is kept for learning
    audit(ctx, 'bas.simulate', run.run_id, { scenarios: run.summary.scenarios, detected: run.summary.detected, missed: run.summary.missed, events: run.summary.events_injected });
    return ctx.ok(run);
  }));

  // ---- runs (read) + purge (admin)
  api.route('GET', `${B}/runs`, wrap(deps, null, (ctx) => ctx.ok({ runs: runner.listRuns(), stats: runner.stats() })));
  api.route('GET', `${B}/runs/:id`, wrap(deps, null, (ctx) => {
    const r = runner.getRun(ctx.params.id);
    if (!r) throw new HttpError(404, 'run not found');
    return ctx.ok(r);
  }));
  api.route('POST', `${B}/runs/:id/purge`, wrap(deps, 'admin', (ctx) => {
    let r;
    try { r = runner.purge(ctx.params.id); } catch (e) { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; }
    audit(ctx, 'bas.purge', ctx.params.id, {});
    return ctx.ok(r);
  }));

  // ---- detection assurance: schedule, history, learning, AI advisor (needs the state store)
  if (deps.state) {
    const coverageLive = async () => { const { set } = await connectedClasses(); return { connected_source_classes: [...set] }; };
    const AS = createAssurance(Object.assign({}, deps, { runner, coverageLive, now: clock }));
    deps.basAssurance = AS;
    api.route('GET', `${B}/assurance`, wrap(deps, null, async (ctx) => ctx.ok(await AS.view())));
    api.route('POST', `${B}/assurance/run`, wrap(deps, 'admin', (ctx) => {
      if (!require('../approvers/scopes').isHuman(ctx.user)) throw new HttpError(403, 'a service or AI identity cannot start a run: a person does');
      const run = AS.runNow({ user: ctx.user });
      audit(ctx, 'bas.assurance.run', run.run_id, { scenarios: run.summary.scenarios, detected: run.summary.detected, missed: run.summary.missed });
      return ctx.ok(run);
    }));
    api.route('POST', `${B}/assurance/settings`, wrap(deps, 'admin', (ctx) => {
      const b = check(ctx.body).oneOf('schedule', SCHEDULES, { required: true }).int('hour', { min: 0, max: 23, required: true }).int('version', { min: 0, required: true }).done();
      let r; try { r = AS.saveSettings(b, { user: ctx.user, role: ctx.role }); } catch (e) { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; }
      audit(ctx, 'bas.assurance.settings', 'schedule', { schedule: b.schedule, hour: b.hour, version: r.version });
      return ctx.ok(r);
    }));
    api.route('POST', `${B}/assurance/ask`, wrap(deps, 'operator', async (ctx) => {
      const b = check(ctx.body || {}).str('question', { max: 1500 }).done();
      if (!require('../approvers/scopes').isHuman(ctx.user)) throw new HttpError(403, 'a service or AI identity cannot ask the advisor: a person does');
      let r; try { r = await AS.advise(b.question || '', { user: ctx.user, role: ctx.role }); } catch (e) { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; }
      audit(ctx, 'bas.assurance.ask', 'advisor', { chars: (b.question || '').length, steps: r.steps.length, unverified: r.unverified });
      return ctx.ok(r);
    }));
    // the schedule: checked every 15 minutes, runs when due; reschedules in finally
    let TIMER = null;
    const tick = guardJob('bas.assurance.schedule', async () => { try { AS.tick(); } finally { TIMER = setTimeout(tick, 15 * 60000); if (TIMER.unref) TIMER.unref(); } });
    if (!deps.noTimers) { TIMER = setTimeout(tick, 5 * 60000); if (TIMER.unref) TIMER.unref(); }
  }

  deps.bas = { runner, coverage: () => computeCoverage({ rules: effective(), connectedClasses: new Set() }), SOURCE_CLASSES, assurance: deps.basAssurance || null };
  return deps.bas;
}

module.exports = { register };
