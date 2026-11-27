// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Agent Workspace (ui/agent-workspace.html): build, govern and run AI-agent workflows in one place - a trigger, then steps from a
 * FIXED catalogue, run one after the other, every run kept with each step's output.
 *   trigger     schedule (every 15 min .. 1 day), new alerts (minimum severity, rule name contains) or manual
 *   alerts      read alerts (window, minimum severity, status, rule contains, or the alerts that triggered the run) - counts, top rules
 *   rules       read the detection rules' own counters - the noisiest (matches, duplicates suppressed) for tuning
 *   condition   go on only when a number from an earlier step passes (>, >=, <, <=, =); otherwise the run stops, nothing more happens
 *   agent       an AI agent (triage, detection tuning, intelligence, incident summary) reads the earlier steps' output and WRITES text.
 *               It has no tools and cannot start, skip or change any step: what happens next is decided by the workflow, never by
 *               the model. Every call goes through util/ai-guard (budget before / record after, secrets redacted, the data framed
 *               as untrusted, UNTRUSTED_RULE). Without AI the step says why and the run goes on.
 *   approval    the run waits for a named person (operator or administrator, as the step says) who is neither the workflow's
 *               author nor the person who started the run - never a service or AI identity
 *   action      create a case from the alerts found, add a note to them, or keep a report. Changing anything (case, note) needs an
 *               approval step earlier in the same workflow - checked when the workflow is saved and again when it runs.
 * Governance: a workflow is a draft until a second administrator publishes it (four-eyes; the author never publishes their own); any
 * edit makes it a draft again. Only published workflows run on their trigger; a draft can be TEST-run, where actions are only
 * described and approvals are passed as "would wait". One run at a time per workflow; the newest 500 runs are kept.
 *   GET  {P}/workspace                               analyst   catalogue, templates, workflows, recent runs, AI status
 *   GET  {P}/workspace/runs/:id                      analyst   one run with every step's output
 *   POST {P}/workspace/workflows                     operator  {name, description, trigger, steps[]} or {template}  → draft   audited
 *   PUT  {P}/workspace/workflows/:id                 operator  same fields → draft again (a new version)                    audited
 *   POST {P}/workspace/workflows/:id/submit          operator  draft → waiting for a second administrator                   audited
 *   POST {P}/workspace/workflows/:id/decide          admin     {decision: publish|reject, comment} - a person, not the author audited
 *   POST {P}/workspace/workflows/:id/disable         admin     {reason}                                                      audited
 *   POST {P}/workspace/workflows/:id/run             operator  {test?} - published, or a test run of any version           audited
 *   POST {P}/workspace/runs/:id/decide               operator  {decision: approve|reject, comment} on a waiting approval    audited
 *   POST {P}/workspace/workflows/:id/delete          admin     a draft or disabled workflow                                  audited
 * The scheduler (guard 'soc.workspace.tick') checks the triggers every minute and reschedules itself in finally.
 */
const path = require('node:path');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');
const { body, param } = require('../util/check');
const { guard } = require('../util/errors');
const G = require('../util/ai-guard');
const SC = require('../approvers/scopes');

const MIN = 60000, H = 36e5, SEV = ['info', 'low', 'medium', 'high', 'critical'];
const EVERY = [15, 60, 360, 720, 1440], MAX_STEPS = 12, MAX_WF = 60, KEEP_RUNS = 500;
const AGENTS = {
  triage: { label: 'Alert triage agent', system: 'You are a SOC triage analyst. From the alerts in the data, say which look real and which look like noise, what to check first and why. Be brief and specific; present indicators, not proof.' },
  tuning: { label: 'Detection and alert tuning agent', system: 'You are a detection engineer. From the rule counters in the data, name the noisiest rules, why they are noisy, and the exact tuning to consider (threshold, grouping, exclusion) with the risk of each. Never suggest switching a rule off without saying what would be missed.' },
  intel: { label: 'Intelligence reports agent', system: 'You are a threat-intelligence analyst. Summarise what the data shows about indicators, campaigns or sources, and what the team should watch next.' },
  summary: { label: 'Incident summariser', system: 'You are a SOC shift lead. Write a short summary of the data for the next shift: what happened, what is open, what needs a person.' },
};
const CATALOGUE = [
  { type: 'alerts', label: 'Read alerts', group: 'Data', desc: 'Alerts in a window, by severity, status or rule - or the alerts that started the run' },
  { type: 'rules', label: 'Read detection rules', group: 'Data', desc: 'The noisiest rules: matches, duplicates suppressed, alerts' },
  { type: 'condition', label: 'Condition', group: 'Flow', desc: 'Go on only when a number from an earlier step passes' },
  { type: 'agent', label: 'AI agent', group: 'Agents', desc: 'Triage, tuning, intelligence or summary - writes text, decides nothing' },
  { type: 'approval', label: 'Person approves', group: 'Governance', desc: 'The run waits for a named person (not the author, not the starter)' },
  { type: 'action', label: 'Action', group: 'Actions', desc: 'Create a case, add a note to the alerts, or keep a report' }];
const ACTIONS = { create_case: 'Create a case from the alerts found', note_alerts: 'Add a note to the alerts found', report: 'Keep the run as a report' };
const CHANGES = new Set(['create_case', 'note_alerts']);
const TEMPLATES = {
  tuning: { name: 'Detection and alert tuning agent report', description: 'Every day: the noisiest rules, an AI tuning proposal, kept as a report for the detection engineer.',
    trigger: { type: 'schedule', every_min: 1440 }, steps: [{ type: 'rules', top: 10 }, { type: 'condition', field: 'count', op: '>', value: 0 }, { type: 'agent', agent: 'tuning', instructions: 'Keep it to the five rules that would save the most analyst time.' }, { type: 'action', action: 'report' }] },
  triage: { name: 'Critical alert triage', description: 'New high or critical alerts: the AI triage agent reads them, a person approves, a case is opened.',
    trigger: { type: 'alert', min_severity: 3 }, steps: [{ type: 'alerts', from_trigger: true }, { type: 'agent', agent: 'triage' }, { type: 'approval', role: 'operator' }, { type: 'action', action: 'create_case' }] },
  shift: { name: 'Shift handover summary', description: 'Every 12 hours: the alerts of the shift, summarised for the next shift.',
    trigger: { type: 'schedule', every_min: 720 }, steps: [{ type: 'alerts', window_h: 12, min_severity: 1 }, { type: 'agent', agent: 'summary' }, { type: 'action', action: 'report' }] },
};
const err = (c, m) => new HttpError(c, m);
const human = (u) => SC.isHuman(u);

// one step, checked against the catalogue; undeclared fields are dropped
function cleanStep(s, i) {
  const n = 'steps[' + i + ']';
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw err(400, n + ' must be an object');
  const t = body({ type: s.type }).oneOf('type', CATALOGUE.map((c) => c.type), { required: true }).done().type, b = body(s);
  const at = (f) => { try { return f(); } catch (e) { throw err(400, n + '.' + e.message); } };
  if (t === 'alerts') return Object.assign({ type: t }, at(() => b.int('window_h', { min: 1, max: 720, def: 24 }).int('min_severity', { min: 0, max: 4, def: 0 }).oneOf('status', ['open', 'any', 'closed-false-positive', 'closed-true-positive'], { def: 'any' }).str('rule', { max: 120 }).bool('from_trigger', { def: false }).done()));
  if (t === 'rules') return Object.assign({ type: t }, at(() => b.int('top', { min: 1, max: 50, def: 10 }).done()));
  if (t === 'condition') return Object.assign({ type: t }, at(() => b.oneOf('field', ['count', 'critical', 'high', 'suppressed', 'matches'], { def: 'count' }).oneOf('op', ['>', '>=', '<', '<=', '='], { def: '>' }).num('value', { min: -1e9, max: 1e9, def: 0 }).done()));
  if (t === 'agent') return Object.assign({ type: t }, at(() => b.oneOf('agent', Object.keys(AGENTS), { required: true }).str('instructions', { max: 1000 }).done()));
  if (t === 'approval') return Object.assign({ type: t }, at(() => b.oneOf('role', ['operator', 'admin'], { def: 'operator' }).str('note', { max: 300 }).done()));
  return Object.assign({ type: t }, at(() => b.oneOf('action', Object.keys(ACTIONS), { required: true }).str('title', { max: 200 }).str('note', { max: 2000 }).int('severity', { min: 0, max: 4 }).done()));
}
function cleanWorkflow(src) {
  const b = body(src).str('name', { required: true, min: 3, max: 120 }).str('description', { max: 600 }).list('steps', { required: true, max: MAX_STEPS }).done();
  const tr = src.trigger; if (!tr || typeof tr !== 'object' || Array.isArray(tr)) throw err(400, 'trigger is required');
  const tt = body(tr).oneOf('type', ['schedule', 'alert', 'manual'], { required: true }).done().type;
  const trigger = tt === 'schedule' ? Object.assign({ type: tt }, body(tr).oneOf('every_min', EVERY, { required: true }).done())
    : tt === 'alert' ? Object.assign({ type: tt }, body(tr).int('min_severity', { min: 0, max: 4, def: 3 }).str('rule', { max: 120 }).done()) : { type: 'manual' };
  const steps = b.steps.map(cleanStep);
  // a change (case, note) only after a person approved it in the same run; a condition / agent reads only what came before it
  steps.forEach((s, i) => {
    if (s.type === 'action' && CHANGES.has(s.action) && !steps.slice(0, i).some((x) => x.type === 'approval')) throw err(400, 'steps[' + i + ']: "' + ACTIONS[s.action] + '" changes the SIEM - put a "Person approves" step before it');
    if (s.type === 'action' && s.action !== 'report' && !steps.slice(0, i).some((x) => x.type === 'alerts')) throw err(400, 'steps[' + i + ']: "' + ACTIONS[s.action] + '" needs a "Read alerts" step before it');
    if ((s.type === 'condition' || s.type === 'agent') && i === 0) throw err(400, 'steps[0]: a ' + s.type + ' needs a data step before it');
    if (s.type === 'alerts' && s.from_trigger && trigger.type !== 'alert') throw err(400, 'steps[' + i + ']: "the alerts that started the run" needs the new-alerts trigger');
  });
  return { name: b.name, description: b.description || '', trigger, steps };
}

function createWorkspace(deps) {
  const { state } = deps, now = deps.now || Date.now, L = deps.log || { info() {}, warn() {}, every() {} };
  const WF = state.collection('ws_workflows'), RUNS = state.collection('ws_runs'), iso = () => new Date(now()).toISOString();
  const nid = (C, p) => { let m = 0; for (const x of C.all()) { const k = Number(String(x.id).split('-')[1]); if (k > m) m = k; } return p + '-' + String(m + 1).padStart(5, '0'); };
  const A = (ctx, action, target, detail) => { if (ctx && typeof ctx.audit === 'function') audit(ctx, action, target, detail); else if (state.audit) state.audit({ at: iso(), user: (ctx && ctx.user) || 'system:workspace', role: 'system', action, target, detail }); };

  // ---- the model: injected in tests, else the Anthropic SDK the other SIEM analysts use (same key and switch)
  const aicfg = (deps.config && deps.config.netops && deps.config.netops.ai) || {};
  let Ctor = null;
  function sdk() { if (deps.anthropicSdk) return deps.anthropicSdk; if (Ctor) return Ctor;
    for (const p of ['@anthropic-ai/sdk', aicfg.sdk_path || '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk')]) {
      try { const m = require(p); Ctor = m.default || m.Anthropic || m; return Ctor; } catch (e) { /* not at this path: the next one is tried */ } }
    return null; }
  const apiKey = () => (deps.config && deps.config.secrets && deps.config.secrets.netops && deps.config.secrets.netops.anthropic_api_key) || process.env.ANTHROPIC_API_KEY || '';
  function aiStatus() {
    if (deps.model) return { enabled: true, model: 'injected' };
    if (aicfg.enabled === false) return { enabled: false, reason: 'AI is switched off in the configuration' };
    if (!sdk()) return { enabled: false, reason: 'the Anthropic SDK is not installed' };
    if (!apiKey()) return { enabled: false, reason: 'no Anthropic API key (secrets.json netops.anthropic_api_key)' };
    return { enabled: true, model: aicfg.model || 'claude-opus-5-5' };
  }
  const budget = G.sharedBudget({ log: L, limits: () => (deps.config && deps.config.ai_limits) || {} });
  async function callModel(user, agent, instructions, data) {
    const st = aiStatus(); if (!st.enabled) return { text: null, why: st.reason };
    const system = AGENTS[agent].system + ' You work inside the SIEM of ' + ((deps.config && deps.config.org) || 'the organisation') + '. You cannot run tools, approve, or change anything; a person decides.\n\n' + G.UNTRUSTED_RULE;
    const prompt = (instructions ? 'Instructions from the workflow (written by its author, approved by a second administrator): ' + G.redactSecrets(instructions) + '\n\n' : '')
      + 'The data from the earlier steps:\n' + G.untrusted('workspace:steps', G.redactSecrets(JSON.stringify(data)).slice(0, 60000));
    const flags = G.injectionSignals(JSON.stringify(data));
    budget.admit(user, 'soc.workspace.agent', prompt.length);
    let usage = { input_tokens: 0, output_tokens: 0 };
    try {
      if (deps.model) { const r = await deps.model({ system, prompt }); usage = r.usage || usage; return { text: String(r.text || '').slice(0, 20000), flags }; }
      const C = sdk(), client = new C({ apiKey: apiKey() });
      const resp = await client.messages.create({ model: aiStatus().model, max_tokens: 3000, system, messages: [{ role: 'user', content: prompt }] });
      usage = resp.usage || usage;
      return { text: (resp.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n').slice(0, 20000), flags };
    } finally { budget.record(user, 'soc.workspace.agent', usage, flags); }
  }

  // ---- the steps
  function readAlerts(s, run) {
    const all = deps.alerts ? deps.alerts.all() : [], from = now() - s.window_h * H;
    const want = s.from_trigger ? new Set(run.trigger.alert_ids || []) : null;
    const L0 = all.filter((a) => (want ? want.has(a.id) : (a.created || 0) >= from && (a.severity || 0) >= s.min_severity
      && (s.status === 'any' || (s.status === 'open' ? !/^closed/.test(String(a.status || '')) : a.status === s.status))
      && (!s.rule || String(a.rule_name || a.rule_id || a.summary || '').toLowerCase().includes(s.rule.toLowerCase()))));
    const by = {}; L0.forEach((a) => { const k = String(a.rule_name || a.rule_id || 'unknown'); by[k] = (by[k] || 0) + 1; });
    return { count: L0.length, critical: L0.filter((a) => a.severity >= 4).length, high: L0.filter((a) => a.severity === 3).length,
      top_rules: Object.entries(by).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([rule, n]) => ({ rule, n })),
      alerts: L0.slice(0, 50).map((a) => ({ id: a.id, severity: SEV[a.severity || 0], rule: a.rule_name || a.rule_id || '', summary: String(a.summary || '').slice(0, 200), status: a.status, at: a.created ? new Date(a.created).toISOString() : null })),
      ids: L0.slice(0, 200).map((a) => a.id) };
  }
  function readRules(s) {
    const st = deps.detector && deps.detector.stats ? deps.detector.stats() : { rules: [] };
    const R = (st.rules || []).filter((r) => r.matches).map((r) => ({ id: r.id, name: r.name || r.id, matches: r.matches, suppressed: r.suppressed || 0, alerts: r.alerts || 0, noise_pct: r.matches ? Math.round(100 * (r.suppressed || 0) / r.matches) : 0 }))
      .sort((a, b) => b.alerts - a.alerts || b.matches - a.matches).slice(0, s.top);
    return { count: R.length, matches: R.reduce((a, r) => a + r.matches, 0), suppressed: R.reduce((a, r) => a + r.suppressed, 0), rules: R };
  }
  const lastNum = (run, field) => { for (let i = run.steps.length - 1; i >= 0; i--) { const o = run.steps[i].out; if (o && typeof o[field] === 'number') return o[field]; } return null; };
  const OPS = { '>': (a, b) => a > b, '>=': (a, b) => a >= b, '<': (a, b) => a < b, '<=': (a, b) => a <= b, '=': (a, b) => a === b };
  const alertIds = (run) => { for (let i = run.steps.length - 1; i >= 0; i--) { const o = run.steps[i].out; if (o && Array.isArray(o.ids)) return o.ids; } return []; };

  async function step(run, wf, s, i, who) {
    const rec = { i, type: s.type, started: iso(), status: 'done', out: null };
    if (s.type === 'alerts') rec.out = readAlerts(s, run);
    else if (s.type === 'rules') rec.out = readRules(s);
    else if (s.type === 'condition') { const v = lastNum(run, s.field), pass = v != null && OPS[s.op](v, s.value); rec.out = { field: s.field, value: v, op: s.op, against: s.value, pass }; if (!pass) rec.status = 'stopped'; }
    else if (s.type === 'agent') {
      const data = run.steps.filter((x) => x.out).map((x) => ({ step: x.i + 1, type: x.type, out: Object.assign({}, x.out, { ids: undefined }) }));
      try { const r = await callModel(run.by_user, s.agent, s.instructions, data); rec.out = r.text != null ? { agent: s.agent, text: r.text, flagged: (r.flags || []).length > 0 } : { agent: s.agent, text: null, why: 'AI not used: ' + r.why }; }
      catch (e) { rec.out = { agent: s.agent, text: null, why: 'AI not used: ' + String(e.message).slice(0, 200) }; if (!e.status) L.every('workspace:agent', 600000, 'warn', 'workspace agent step failed', { wf: wf.id, err: String(e.message).slice(0, 200) }); }
    } else if (s.type === 'approval') {
      if (run.test) rec.out = { would_wait: 'for a ' + s.role + ' who is neither ' + wf.author + ' nor ' + run.by_user };
      else { rec.status = 'waiting'; rec.out = { role: s.role, note: s.note || '', not: [wf.author, run.by_user] }; }
    } else if (s.type === 'action') {
      const ids = alertIds(run), approved = run.steps.some((x) => x.type === 'approval' && x.status === 'done' && x.out && x.out.approved_by);
      if (CHANGES.has(s.action) && !run.test && !approved) throw err(409, 'step ' + (i + 1) + ': no person approved this run - the action is not taken');
      if (s.action === 'report') rec.out = { report: true, steps: run.steps.length };
      else if (!ids.length) rec.out = { skipped: 'no alerts were found by the earlier steps' };
      else if (run.test) rec.out = { would: ACTIONS[s.action] + ' (' + ids.length + ' alert(s))' };
      else if (s.action === 'create_case') {
        if (!deps.cases) throw err(503, 'case management is not running');
        const free = ids.filter((id) => { const a = deps.alerts && deps.alerts.get(id); return a && !a.case_id; });
        if (!free.length) rec.out = { skipped: 'every alert found already belongs to a case' };
        else { const c = deps.cases.create({ title: s.title || ('Agent Workspace: ' + wf.name), severity: s.severity, alert_ids: free.slice(0, 100) }, 'system:workspace');
          rec.out = { case_id: c.id, alerts: free.length, approved_by: run.steps.filter((x) => x.out && x.out.approved_by).map((x) => x.out.approved_by) }; A(null, 'workspace.action.create_case', c.id, { wf: wf.id, run: run.id, alerts: free.length }); }
      } else {
        const text = (s.note || ('Agent Workspace: ' + wf.name)) + ' (run ' + run.id + ')'; let n = 0;
        for (const id of ids.slice(0, 200)) { try { deps.alerts.note(id, text, 'system:workspace'); n++; } catch (e) { L.every('workspace:note', 600000, 'warn', 'workspace: a note could not be added', { alert: id, err: String(e.message).slice(0, 120) }); } }
        rec.out = { noted: n }; A(null, 'workspace.action.note_alerts', wf.id, { run: run.id, alerts: n });
      }
    }
    rec.ended = iso(); return rec;
  }

  // run from step `from` until the end, a stop, a wait or an error; the run is saved after every step
  async function advance(runId, wf) {
    let run = RUNS.get(runId);
    for (let i = run.next; i < wf.steps.length; i++) {
      let rec; try { rec = await step(run, wf, wf.steps[i], i); }
      catch (e) { rec = { i, type: wf.steps[i].type, status: 'failed', error: String(e.message).slice(0, 300), ended: iso() }; if (!e.status) L.every('workspace:step', 600000, 'warn', 'workspace step failed', { wf: wf.id, step: i, err: String(e.message).slice(0, 200) }); }
      run = RUNS.patch(runId, (r) => { r.steps.push(rec); r.next = i + 1; if (rec.status !== 'done') r.status = rec.status; if (rec.status !== 'waiting' && rec.status !== 'done') r.ended = iso(); return r; });
      if (rec.status !== 'done') return run;
    }
    return RUNS.patch(runId, (r) => { r.status = 'done'; r.ended = iso(); return r; });
  }
  async function start(wf, trig, who, test) {
    if (RUNS.all((r) => r.wf === wf.id && !r.test && (r.status === 'running' || r.status === 'waiting')).length && !test) throw err(409, 'a run of ' + wf.name + ' is still running or waiting for a person');
    const run = RUNS.put({ id: nid(RUNS, 'WSR'), wf: wf.id, wf_name: wf.name, version: wf.version, test: !!test, trigger: trig, by_user: who, started: iso(), status: 'running', next: 0, steps: [] });
    for (const o of RUNS.all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(KEEP_RUNS)) RUNS.remove(o.id);
    if (!test) WF.patch(wf.id, (w) => { w.last_run = run.started; return w; });
    return advance(run.id, wf);
  }

  // ---- the routes' logic
  function view() {
    return { catalogue: CATALOGUE, agents: Object.entries(AGENTS).map(([id, a]) => ({ id, label: a.label })), actions: ACTIONS, every: EVERY, templates: Object.entries(TEMPLATES).map(([id, t]) => ({ id, name: t.name, description: t.description })),
      workflows: WF.all().sort((a, b) => String(a.id).localeCompare(String(b.id))), runs: RUNS.all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 60).map((r) => Object.assign({}, r, { steps: r.steps.map((s) => ({ i: s.i, type: s.type, status: s.status })) })),
      ai: aiStatus(), note: 'An AI agent only writes text. What runs next is the workflow\'s, and a change needs a named person\'s approval.' };
  }
  function getWf(id) { param(id, 'workflow'); const w = WF.get(id); if (!w) throw err(404, 'workflow ' + id + ' not found'); return w; }
  function create(b0, ctx) {
    if (!human(ctx.user)) throw err(403, 'a person builds workflows');
    if (WF.size() >= MAX_WF) throw err(409, 'at most ' + MAX_WF + ' workflows');
    const tpl = b0 && b0.template !== undefined ? body(b0).oneOf('template', Object.keys(TEMPLATES), { required: true }).done().template : null;
    const w = cleanWorkflow(tpl ? TEMPLATES[tpl] : b0);
    const rec = WF.put(Object.assign({ id: nid(WF, 'WSW'), status: 'draft', version: 1, author: ctx.user, created: iso(), updated: iso(), last_run: null, last_check: iso() }, w));
    A(ctx, 'workspace.workflow.create', rec.id, { name: rec.name, template: tpl, steps: rec.steps.length }); return rec;
  }
  function update(id, b0, ctx) {
    if (!human(ctx.user)) throw err(403, 'a person edits workflows');
    const cur = getWf(id); if (cur.status === 'pending') throw err(409, 'the workflow is waiting for a second administrator - decide it first');
    const w = cleanWorkflow(b0);
    const rec = WF.patch(id, (o) => Object.assign(o, w, { status: 'draft', version: o.version + 1, updated: iso(), editor: ctx.user, published_by: null }));
    A(ctx, 'workspace.workflow.update', id, { version: rec.version, was: cur.status }); return rec;
  }
  function submit(id, ctx) {
    const cur = getWf(id); if (cur.status !== 'draft') throw err(409, 'only a draft is submitted (this one is ' + cur.status + ')');
    const rec = WF.patch(id, (o) => { o.status = 'pending'; o.submitted_by = ctx.user; o.submitted = iso(); return o; });
    A(ctx, 'workspace.workflow.submit', id, { version: rec.version }); return rec;
  }
  function decide(id, b0, ctx) {
    if (!human(ctx.user)) throw err(403, 'only a person publishes: ' + ctx.user + ' is a service / AI identity');
    const b = body(b0).oneOf('decision', ['publish', 'reject'], { required: true }).str('comment', { max: 400 }).done(), cur = getWf(id);
    if (cur.status !== 'pending') throw err(409, 'only a workflow waiting for a second administrator is decided');
    const me = String(ctx.user).toLowerCase();
    if ([cur.author, cur.editor, cur.submitted_by].filter(Boolean).some((u) => String(u).toLowerCase() === me)) throw err(403, 'four-eyes: who built, edited or submitted this workflow does not publish it');
    if (b.decision === 'reject' && !(b.comment && b.comment.length >= 5)) throw err(400, 'comment: say why it is rejected');
    const rec = WF.patch(id, (o) => { o.status = b.decision === 'publish' ? 'published' : 'draft'; o.decided_by = ctx.user; o.decided = iso(); o.comment = b.comment || ''; if (b.decision === 'publish') { o.published_by = ctx.user; o.last_check = iso(); } return o; });
    A(ctx, 'workspace.workflow.' + b.decision, id, { version: rec.version, author: rec.author }); return rec;
  }
  function disable(id, b0, ctx) {
    const b = body(b0).str('reason', { required: true, min: 5, max: 300 }).done(), cur = getWf(id); if (cur.status === 'disabled') throw err(409, 'already disabled');
    const rec = WF.patch(id, (o) => { o.status = 'disabled'; o.disabled_by = ctx.user; o.disabled_reason = b.reason; return o; });
    A(ctx, 'workspace.workflow.disable', id, { reason: b.reason }); return rec;
  }
  function remove(id, ctx) {
    const cur = getWf(id); if (!['draft', 'disabled'].includes(cur.status)) throw err(409, 'disable the workflow before deleting it');
    WF.remove(id); A(ctx, 'workspace.workflow.delete', id, { name: cur.name }); return { removed: id };
  }
  async function runNow(id, b0, ctx) {
    if (!human(ctx.user)) throw err(403, 'a person starts a run by hand');
    const b = body(b0 || {}).bool('test', { def: false }).done(), wf = getWf(id);
    if (!b.test && wf.status !== 'published') throw err(409, 'only a published workflow runs for real - use a test run for a ' + wf.status + ' workflow');
    if (wf.trigger.type === 'alert' && !b.test) throw err(409, 'this workflow starts on new alerts - use a test run to try it');
    const run = await start(wf, { type: 'manual', by: ctx.user }, ctx.user, b.test);
    A(ctx, 'workspace.run.start', run.id, { wf: id, test: b.test, status: run.status }); return run;
  }
  function getRun(id) { param(id, 'run'); const r = RUNS.get(id); if (!r) throw err(404, 'run ' + id + ' not found'); return r; }
  async function decideRun(id, b0, ctx) {
    if (!human(ctx.user)) throw err(403, 'only a person approves: ' + ctx.user + ' is a service / AI identity');
    const b = body(b0).oneOf('decision', ['approve', 'reject'], { required: true }).str('comment', { max: 400 }).done(), run = getRun(id);
    if (run.status !== 'waiting') throw err(409, 'this run is not waiting for a person');
    const wf = getWf(run.wf), w = run.steps[run.steps.length - 1], me = String(ctx.user).toLowerCase();
    if (w.out.not.some((u) => String(u || '').toLowerCase() === me)) throw err(403, 'four-eyes: the workflow\'s author and the person who started the run do not approve it');
    if (w.out.role === 'admin' && ctx.role !== 'admin') throw err(403, 'this step needs an administrator');
    if (b.decision === 'reject' && !(b.comment && b.comment.length >= 5)) throw err(400, 'comment: say why it is rejected');
    if (wf.version !== run.version) throw err(409, 'the workflow changed since this run started - reject it and start a new one');
    RUNS.patch(id, (r) => { const s = r.steps[r.steps.length - 1]; s.status = b.decision === 'approve' ? 'done' : 'rejected'; s.out = Object.assign({}, s.out, b.decision === 'approve' ? { approved_by: ctx.user } : { rejected_by: ctx.user }, { comment: b.comment || '', decided: iso() });
      if (b.decision === 'reject') { r.status = 'rejected'; r.ended = iso(); } else r.status = 'running'; return r; });
    A(ctx, 'workspace.run.' + b.decision, id, { wf: wf.id, step: w.i + 1 });
    return b.decision === 'approve' ? advance(id, wf) : RUNS.get(id);
  }

  // ---- triggers: schedule and new alerts, checked every minute
  async function tick() {
    for (const wf of WF.all((w) => w.status === 'published')) {
      if (RUNS.all((r) => r.wf === wf.id && !r.test && (r.status === 'running' || r.status === 'waiting')).length) continue;
      if (wf.trigger.type === 'schedule') {
        const last = Date.parse(wf.last_run || wf.decided || 0) || 0;
        if (now() - last >= wf.trigger.every_min * MIN) await start(wf, { type: 'schedule' }, 'system:workspace');
      } else if (wf.trigger.type === 'alert' && deps.alerts) {
        const since = Date.parse(wf.last_check) || now(), tr = wf.trigger;
        const fresh = deps.alerts.all((a) => (a.created || 0) > since && (a.severity || 0) >= tr.min_severity && (!tr.rule || String(a.rule_name || a.rule_id || a.summary || '').toLowerCase().includes(tr.rule.toLowerCase())));
        WF.patch(wf.id, (w) => { w.last_check = iso(); return w; });
        if (fresh.length) await start(wf, { type: 'alert', alert_ids: fresh.slice(0, 200).map((a) => a.id) }, 'system:workspace');
      }
    }
  }
  let timer = null, armed = false;
  const job = guard('soc.workspace.tick', async () => { try { await tick(); } finally { if (armed) { timer = setTimeout(job, MIN); if (timer.unref) timer.unref(); } } });
  function startTimer() { if (armed) return; armed = true; timer = setTimeout(job, MIN); if (timer.unref) timer.unref(); }
  function stop() { armed = false; if (timer) clearTimeout(timer); }
  return { view, create, update, submit, decide, disable, remove, runNow, getRun, decideRun, tick, start: startTimer, stop, aiStatus };
}

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), X = createWorkspace(deps), id = (ctx) => ctx.params.id;
  api.route('GET', `${P}/workspace`, wrap(deps, 'analyst', (ctx) => ctx.ok(X.view())));
  api.route('GET', `${P}/workspace/runs/:id`, wrap(deps, 'analyst', (ctx) => ctx.ok(X.getRun(id(ctx)))));
  api.route('POST', `${P}/workspace/workflows`, wrap(deps, 'operator', (ctx) => ctx.ok(X.create(ctx.body, ctx))));
  api.route('PUT', `${P}/workspace/workflows/:id`, wrap(deps, 'operator', (ctx) => ctx.ok(X.update(id(ctx), ctx.body, ctx))));
  api.route('POST', `${P}/workspace/workflows/:id/submit`, wrap(deps, 'operator', (ctx) => ctx.ok(X.submit(id(ctx), ctx))));
  api.route('POST', `${P}/workspace/workflows/:id/decide`, wrap(deps, 'admin', (ctx) => ctx.ok(X.decide(id(ctx), ctx.body, ctx))));
  api.route('POST', `${P}/workspace/workflows/:id/disable`, wrap(deps, 'admin', (ctx) => ctx.ok(X.disable(id(ctx), ctx.body, ctx))));
  api.route('POST', `${P}/workspace/workflows/:id/delete`, wrap(deps, 'admin', (ctx) => ctx.ok(X.remove(id(ctx), ctx))));
  api.route('POST', `${P}/workspace/workflows/:id/run`, wrap(deps, 'operator', async (ctx) => ctx.ok(await X.runNow(id(ctx), ctx.body, ctx))));
  api.route('POST', `${P}/workspace/runs/:id/decide`, wrap(deps, 'operator', async (ctx) => ctx.ok(await X.decideRun(id(ctx), ctx.body, ctx))));
  if (!(deps.config && deps.config.noTimers) && !deps.noTimer) X.start();
  deps.workspace = X;
}

module.exports = { register, createWorkspace, cleanWorkflow, cleanStep, CATALOGUE, AGENTS, TEMPLATES };
