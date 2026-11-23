// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const G = require('../util/ai-guard');
const SC = require('../approvers/scopes');
const { createModel, runLoop } = require('../soc/ai-loop');
/*
 * Detection assurance (DEFENSIVE) - automation, learning and an AI purple-team advisor over the breach-&-attack simulator
 * (bas/runner.js). The simulator injects clearly synthetic log lines into an ISOLATED copy of the detection rules: no attack, no
 * scan, no endpoint, no live alert. This module only schedules it, keeps its history and learns from it:
 *
 *   automation   an administrator sets a schedule (off / daily / weekly, at an hour); every scheduled run is recorded as
 *                system:bas-schedule. Every run - scheduled or by a person - is kept in history (bas_history, last 400).
 *   learning     per scenario and per ATT&CK technique: detection reliability (Beta(1,1): (detected+1)/(runs+2)); a REGRESSION when
 *                the last run missed what an earlier run detected (a rule was changed or disabled); FLAPPING when the result changed
 *                2+ times in the last 6 runs; detection latency slower than usual (robust z on median / MAD, 7+ runs); the detection
 *                rate trend (least squares, 3+ runs).
 *   gaps         every missed technique classified by WHY: "rule" (its source is connected but no enabled rule caught it - write or
 *                enable a rule), "source" (no connected source feeds it - connect one), "control" (a control scenario with no rule
 *                on purpose). Ranked: regressions first, then rule gaps, then source gaps.
 *   assurance    0-100 = share of non-control scenarios detected in the last run, minus itemised points for regressions and flapping.
 *   AI advisor   read-only tools (the analysis, the gaps); proposes what to tune - a person decides; ids it cites are checked.
 *
 *   createAssurance({ state, runner, coverageLive?, config, log, now?, sdk? }) → { view(), record(run), runNow(who), saveSettings(b, who),
 *     tick(), advise(question, who) }
 */
const DAY = 86400000;
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 2000 });
const median = (a) => { const t = [...a].sort((x, y) => x - y), m = t.length >> 1; return t.length % 2 ? t[m] : (t[m - 1] + t[m]) / 2; };
function lsq(pts) { const n = pts.length; if (n < 3) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n, sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0); return sxx ? pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx : 0; }
const SCHEDULES = ['off', 'daily', 'weekly'];
const SYS = 'system:bas-schedule';

const SYSTEM = `You are the purple-team advisor of ${ZYB_ORG.short}'s SOC. You read the results of SYNTHETIC detection tests (benign fake log lines run
through an isolated copy of the detection rules - nothing was attacked) and advise which detections to fix first.
Read the analysis (assurance_analysis) and the gaps (detection_gaps), then call submit_advice once:
- summary: where detection stands, two or three sentences;
- priorities: up to 6, each {ref (a scenario id or technique id from the tools), action, why} - a regression first, then a rule gap, then a source gap;
- note: anything the tests cannot show (only the bundled scenarios are tested; a detected test is not proof every variant is caught).
You propose; a person decides. Never claim a detection works unless the tools show it detected.`;
const TOOLS = [
  { name: 'assurance_analysis', role: 'operator', description: 'Per scenario and technique: runs, detected, reliability, regression, flapping, latency; the assurance score and its deductions.', input_schema: S({ properties: {} }) },
  { name: 'detection_gaps', role: 'operator', description: 'Missed techniques with the reason (rule / source / control) and what to do.', input_schema: S({ properties: {} }) },
  { name: 'submit_advice', role: 'operator', description: 'Final answer.', input_schema: S({ required: ['summary', 'priorities'], properties: { summary: STR(1500), note: STR(800),
    priorities: { type: 'array', maxItems: 6, items: S({ required: ['ref', 'action', 'why'], properties: { ref: STR(40), action: STR(300), why: STR(500) } }) } } }) },
];

function createAssurance(deps = {}) {
  const state = deps.state; if (!state) throw new Error('createAssurance needs deps.state');
  const runner = deps.runner; if (!runner) throw new Error('createAssurance needs deps.runner');
  const now = deps.now || Date.now, L = deps.log || { info() {}, warn() {}, error() {} };
  const hist = state.collection('bas_history'), conf = state.collection('bas_assurance_cfg');
  const AI = createModel({ config: deps.config || {}, deps, log: L });
  const cfg = () => Object.assign({ schedule: 'off', hour: 2, version: 0 }, conf.get('cfg') || {});

  function record(run) {
    if (!run || !run.run_id || hist.get(run.run_id)) return null;
    const r = { id: run.run_id, at: run.started_at, ms: run.started_ms, by: run.by, summary: run.summary,
      results: (run.results || []).map((x) => ({ scenario_id: x.scenario_id, name: x.name, control: !!x.control, technique: x.technique, techniques: x.techniques || [], source_class: x.source_class, expect_rule: x.expect_rule || null, status: x.status, latency_ms: x.latency_ms == null ? null : x.latency_ms })) };
    hist.put(r);
    const all = hist.all().sort((a, b) => a.ms - b.ms); for (const old of all.slice(0, Math.max(0, all.length - 400))) hist.remove(old.id);
    return r;
  }
  function runNow(who) {
    const run = runner.simulate({ by: who.user });
    record(run); return run;
  }

  async function connected() {
    if (typeof deps.coverageLive !== 'function') return { known: false, set: new Set() };
    try { const c = await deps.coverageLive(); return { known: true, set: new Set(c.connected_source_classes || []) }; }
    catch (e) { L.warn('bas assurance: coverage not read', { err: String(e.message).slice(0, 160) }); return { known: false, set: new Set() }; }
  }
  async function analysis() {
    const runs = hist.all().sort((a, b) => a.ms - b.ms), last = runs[runs.length - 1] || null, con = await connected();
    const by = new Map();
    for (const r of runs) for (const x of r.results) { if (!by.has(x.scenario_id)) by.set(x.scenario_id, { meta: x, seq: [] }); by.get(x.scenario_id).seq.push({ status: x.status, latency: x.latency_ms, at: r.at }); }
    const scen = [...by.values()].map(({ meta, seq }) => {
      const n = seq.length, k = seq.filter((s) => s.status === 'detected').length, lastS = seq[n - 1].status;
      const prev = seq.slice(0, -1);
      const regression = !meta.control && lastS !== 'detected' && prev.some((s) => s.status === 'detected');
      const recent = seq.slice(-6).map((s) => s.status); let flips = 0; for (let i = 1; i < recent.length; i++) if (recent[i] !== recent[i - 1]) flips++;
      const lat = seq.map((s) => s.latency).filter((v) => typeof v === 'number'), lh = lat.slice(0, -1).slice(-30);
      let latency = { last: lat.length ? lat[lat.length - 1] : null, slower: false, why: 'needs 7 earlier runs to learn the usual latency (' + lh.length + ' so far)' };
      if (lh.length >= 7) { const m = median(lh), mad = median(lh.map((v) => Math.abs(v - m))) * 1.4826 || 1, z = (latency.last - m) / mad; latency = { last: latency.last, usual_ms: Math.round(m), z: Math.round(z * 10) / 10, slower: z > 3, why: 'last ' + latency.last + ' ms against a usual ' + Math.round(m) + ' ms' }; }
      return { scenario_id: meta.scenario_id, name: meta.name, control: meta.control, technique: meta.technique, techniques: meta.techniques, source_class: meta.source_class, expect_rule: meta.expect_rule,
        runs: n, detected: k, reliability: Math.round(((k + 1) / (n + 2)) * 100) / 100, last: lastS, regression, flapping: !meta.control && flips >= 2, latency };
    });
    // techniques: a technique is detected in the last run when any of its scenarios was
    const tech = new Map();
    for (const s of scen) for (const t of s.techniques) { const x = tech.get(t) || { technique: t, scenarios: [], detected_last: false, reliability: 0, source_classes: new Set() }; x.scenarios.push(s.scenario_id); x.detected_last = x.detected_last || s.last === 'detected'; x.reliability = Math.max(x.reliability, s.reliability); x.source_classes.add(s.source_class); tech.set(t, x); }
    const techniques = [...tech.values()].map((x) => Object.assign(x, { source_classes: [...x.source_classes] })).sort((a, b) => a.technique.localeCompare(b.technique));
    // gaps, ranked: regressions, rule gaps, source gaps, controls
    const gaps = [];
    for (const s of scen.filter((x) => x.last !== 'detected')) {
      let kind, action;
      if (s.control) { kind = 'control'; action = 'by design: no rule maps to ' + s.technique + ' - decide whether one is needed'; }
      else if (s.regression) { kind = 'regression'; action = 'detected before, missed now - check rule ' + (s.expect_rule || '') + ' (changed, disabled or suppressed?)'; }
      else if (con.known && !con.set.has(s.source_class)) { kind = 'source'; action = 'no connected ' + s.source_class + ' source - connect one so the rule can see this'; }
      else { kind = 'rule'; action = (s.expect_rule ? 'rule ' + s.expect_rule + ' did not fire' : 'no rule fired') + ' - review / enable / tune it'; }
      gaps.push({ ref: s.scenario_id, technique: s.technique, name: s.name, kind, action, source_class: s.source_class, reliability: s.reliability });
    }
    const RANK = { regression: 0, rule: 1, source: 2, control: 3 }; gaps.sort((a, b) => RANK[a.kind] - RANK[b.kind]);
    // assurance
    const real = scen.filter((x) => !x.control), det = real.filter((x) => x.last === 'detected').length;
    const ded = [{ what: scen.filter((x) => x.regression).length + ' regression(s): detected before, missed now', points: Math.min(30, scen.filter((x) => x.regression).length * 10) },
      { what: scen.filter((x) => x.flapping).length + ' flapping detection(s)', points: Math.min(20, scen.filter((x) => x.flapping).length * 5) },
      { what: scen.filter((x) => x.latency.slower).length + ' detection(s) slower than usual', points: Math.min(10, scen.filter((x) => x.latency.slower).length * 3) }].filter((d) => d.points > 0);
    const base = real.length ? Math.round((det / real.length) * 100) : null;
    const score = base === null ? null : Math.max(0, base - ded.reduce((t, d) => t + d.points, 0));
    const pts = runs.slice(-30).map((r, i) => [i, r.summary ? r.summary.detection_pct : 0]), sl = lsq(pts);
    return { runs: runs.length, last_run: last ? { id: last.id, at: last.at, by: last.by, summary: last.summary } : null,
      assurance: { score, base, deductions: ded, why: base === null ? 'no simulation has run yet - run one, or set a schedule' : det + ' of ' + real.length + ' test scenario(s) detected in the last run' + (ded.length ? ', minus ' + ded.map((d) => d.what).join('; ') : '') },
      scenarios: scen, techniques, gaps, sources_known: con.known,
      trend: { points: runs.slice(-30).map((r) => ({ at: r.at, pct: r.summary ? r.summary.detection_pct : null, by: r.by })), per_run: sl === null ? null : Math.round(sl * 10) / 10, why: sl === null ? 'needs 3 runs for a trend (' + runs.length + ' so far)' : 'least squares over the last ' + pts.length + ' run(s)' } };
  }
  async function view() {
    const a = await analysis(), c = cfg();
    return Object.assign(a, { settings: { schedule: c.schedule, hour: c.hour, version: c.version, by: c.by || null, at: c.at || null, last_auto: c.last_auto || null, next: nextDue(c) }, schedules: SCHEDULES, ai: AI.status(),
      note: 'Synthetic detection tests only: benign fake log lines through an isolated copy of the rules - nothing is attacked, no alert is raised, no endpoint is touched. A detected test shows the rule fires on that pattern, not that every variant is caught.' });
  }
  function saveSettings(b, who) {
    if (!SC.isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot change the schedule: a person does');
    const c = cfg(); if (b.version !== c.version) throw httpErr(409, 'the settings were changed by someone else - reload and try again');
    const next = { id: 'cfg', schedule: b.schedule, hour: b.hour, version: c.version + 1, by: who.user, at: new Date(now()).toISOString(), last_auto: c.last_auto || null };
    conf.put(next); return next;
  }
  function nextDue(c) {
    if (c.schedule === 'off') return null;
    const gap = c.schedule === 'daily' ? DAY : 7 * DAY, base = c.last_auto ? Date.parse(c.last_auto) + gap : (c.at ? Date.parse(c.at) : now());   // first run: the first hour after the schedule was set
    const d = new Date(base); d.setUTCHours(c.hour, 0, 0, 0); if (d.getTime() < base) d.setTime(d.getTime() + DAY);
    return d.toISOString();
  }
  function tick() {
    const c = cfg(); if (c.schedule === 'off') return null;
    const due = nextDue(c); if (!due || Date.parse(due) > now()) return null;
    const run = runNow({ user: SYS });
    conf.put(Object.assign({}, c, { last_auto: new Date(now()).toISOString() }));
    L.info('bas assurance: scheduled simulation ran', { run_id: run.run_id, detected: run.summary.detected, missed: run.summary.missed });
    return run;
  }

  async function advise(question, who) {
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const run = async (name) => {
      const a = await analysis();
      if (name === 'assurance_analysis') return { assurance: a.assurance, scenarios: a.scenarios, trend: a.trend };
      if (name === 'detection_gaps') return { gaps: a.gaps, sources_known: a.sources_known };
      throw new Error('unknown tool ' + name);
    };
    const q = G.redactSecrets(String(question || '')).slice(0, 1500);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: SYSTEM, tools: TOOLS, role: who.role || 'operator', user: who.user || 'unknown', feature: 'soc.bas-advisor', config: deps.config, log: L,
      prompt: (q ? 'The analyst asks:\n' + G.untrusted('analyst-question', q) + '\n' : '') + 'Use the tools, then call submit_advice.', run, final: 'submit_advice', maxSteps: 6 });
    if (!r.result) throw httpErr(502, 'the AI did not return advice (' + r.note + ') - try again');
    const a = await analysis(), known = new Set(a.scenarios.map((s) => s.scenario_id).concat(a.techniques.map((t) => t.technique)));
    const pr = (r.result.priorities || []).map((p) => Object.assign({}, p, { verified: known.has(String(p.ref)) }));
    return { summary: r.result.summary, priorities: pr, note: r.result.note || '', unverified: pr.filter((p) => !p.verified).length, steps: r.steps, usage: r.usage, injection_signals: r.flags,
      framing: 'Advice from synthetic tests for a person to review - nothing was changed.' };
  }
  return { view, analysis, record, runNow, saveSettings, tick, advise, cfg, SCHEDULES, TOOLS };
}

module.exports = { createAssurance, SCHEDULES, TOOLS, lsq };
