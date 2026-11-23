// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const crypto = require('node:crypto');
const G = require('../util/ai-guard');
const SC = require('../approvers/scopes');
const playbooks = require('./playbooks');
const { createModel, check, allowed, RANK } = require('./ai-loop');
/*
 * SOC Copilot - one conversational agent beside every Security Operations page. It knows the page and the record the
 * analyst is looking at, chains the platform's READ tools to answer, and when a step is worth doing it records a PROPOSAL
 * that the analyst accepts or rejects in the panel. Nothing changes until a person accepts; the accepted action then runs as
 * that person, with that person's role checked again.
 *
 *   createCopilot({ state, alerts, cases, analyst?, investigate?, behaviour?, intelView?, xdr?, search?, ueba?, intel?, config, log, sdk?, now? })
 *     ask({ question, conversation?, context?{page, kind, id} }, who) → { answer, conversation, steps[], proposals[], usage }
 *     conversations(who) / conversation(id, who)   private to their user
 *     proposals(who, status) / decide(id, {decision, note}, who)
 *
 * Proposal kinds (fixed allow-list; inputs checked when proposed AND again when accepted):
 *   open_case {title, alert_ids[], playbook_id?} · add_case_note {case_id, text} · add_alerts_to_case {case_id, alert_ids[]}
 *   close_alert {alert_id, reason: true-positive|false-positive|benign, note} · assign_alert {alert_id, assignee}
 *   save_hunt {name, q, hours?}
 * Containment (block, isolate, disable) is NOT a copilot action: it stays a playbook approval request that a named approver
 * decides (cases.js). AI rules: tools filtered by the asker's role before the call and re-checked per call, schema-checked
 * input, tool output untrusted + redacted, UNTRUSTED_RULE, budget before / record after (docs/AI-SECURITY.md).
 */
const MAX_STEPS = 12, MAX_RESULT = 20000, H = 3600000;
const PAGES = ['soc-overview', 'soc-alerts', 'soc-cases', 'soc-hunt', 'soc-ueba', 'soc-ti', 'other'];
const KINDS = ['alert', 'case', 'entity', 'indicator', 'query', 'none'];
const PROPOSE = { open_case: 'operator', add_case_note: 'operator', add_alerts_to_case: 'operator', close_alert: 'operator', assign_alert: 'operator', save_hunt: 'analyst' };
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 4000 });
const IDS = { type: 'array', maxItems: 50, items: STR(40) };

const SYSTEM = `You are the SOC Copilot for ${ZYB_ORG.name}'s Security Operations Centre, working beside an analyst inside the SIEM console.
- Answer from tool results only. Never invent alerts, users, hosts, IPs, counts or times; if the data is not there, say what is missing.
- Start from the context you are given (the page and record the analyst is looking at). Chain tools: e.g. an alert -> related alerts -> the user's behaviour -> threat intel -> correlation -> similar closures.
- Cite record ids (ALR-…, CASE-…, user:…, host:…, XDR-…) inline so the analyst can open them.
- When a step is worth doing (open a case, add a note, close or assign an alert, add alerts to a case, save a hunt), call the matching propose_* tool. It is only RECORDED for the analyst to accept or reject; say so. You cannot contain, block, isolate or disable anything - those are playbook approval requests a named approver decides.
- User behaviour is an indicator, never proof; do not judge people (Saudi PDPL).
- Be concise: lead with the answer, then the evidence, then the proposed next step. Reply in the language of the question (Arabic or English).`;

function createCopilot(deps = {}) {
  const { state, alerts, cases } = deps;
  if (!state || !alerts || !cases) throw new Error('createCopilot needs state, alerts and cases');
  const L = deps.log || { info() {}, warn() {} };
  const now = deps.now || Date.now;
  const chats = state.collection('soc_copilot_chats'), props = state.collection('soc_copilot_proposals');
  const AI = createModel({ config: deps.config, deps, log: L });

  // ------------------------------------------------------------------ tools (read)
  const TOOLS = [
    { name: 'soc_overview', description: 'The SOC at a glance: open alerts by priority band and severity, act-now alerts, MTTA/MTTR, top rules and entities, XDR, UEBA.', input_schema: S({ properties: {} }) },
    { name: 'alert_queue', description: 'Open alerts ranked by explainable priority, optionally filtered by text, label (act-now, investigate, review, low, likely-noise) or severity.', input_schema: S({ properties: { q: STR(200), label: { type: 'string', enum: ['act-now', 'investigate', 'review', 'low', 'likely-noise'] }, limit: { type: 'integer', minimum: 1, maximum: 30 } } }) },
    { name: 'get_alert', description: 'One alert with its fields, notes, history, its priority breakdown and its AI triage if any.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'related_alerts', description: 'Alerts in the last N hours sharing a user / host / IP with an alert, or involving an entity key (user:x, host:y, ip:z).', input_schema: S({ properties: { id: STR(40), entity: STR(200), hours: { type: 'integer', minimum: 1, maximum: 720 } } }) },
    { name: 'list_cases', description: 'Cases (active by default) with stage, severity, owner and SLA.', input_schema: S({ properties: { status: { type: 'string', enum: ['active', 'all', 'closed'] }, q: STR(200) } }) },
    { name: 'get_case', description: 'One case workspace: alerts, merged timeline, scope, tasks, evidence, approvals, suggested alerts, AI brief.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'entity_profile', description: 'UEBA behaviour profile of user:<name> or host:<name>: risk, contributions, findings.', role: 'operator', input_schema: S({ properties: { entity: STR(200) }, required: ['entity'] }) },
    { name: 'intel_lookup', description: 'Which threat-intel lists contain an IP, domain or hash.', input_schema: S({ properties: { value: STR(300) }, required: ['value'] }) },
    { name: 'intel_sightings', description: 'Indicators from threat lists seen in alerts in the last 30 days.', input_schema: S({ properties: {} }) },
    { name: 'xdr_incident', description: 'The correlated XDR incident an alert belongs to (domains, ATT&CK chain, score).', input_schema: S({ properties: { alert_id: STR(40) }, required: ['alert_id'] }) },
    { name: 'count_events', description: 'Number of events matching a query (platform query language) in the last N hours.', role: 'analyst', input_schema: S({ properties: { q: STR(1000), hours: { type: 'integer', minimum: 1, maximum: 168 } }, required: ['q'] }) },
    { name: 'top_values', description: 'The 10 most frequent values of a field among events matching a query.', role: 'analyst', input_schema: S({ properties: { q: STR(1000), field: { type: 'string', enum: ['user', 'host', 'src_ip', 'dst_ip', 'domain', 'dns_query', 'process', 'action', 'outcome', 'category', 'src_type', 'event_code'] }, hours: { type: 'integer', minimum: 1, maximum: 168 } }, required: ['q', 'field'] }) },
    { name: 'search_events', description: 'Up to 20 raw events matching a query in the last N hours (newest first, narrow field set).', role: 'analyst', input_schema: S({ properties: { q: STR(1000), hours: { type: 'integer', minimum: 1, maximum: 168 } }, required: ['q'] }) },
    // ---- proposals: recorded for the analyst to accept; never executed by the copilot
    { name: 'propose_open_case', description: 'Propose opening a case for alerts (optionally with a playbook). Recorded for the analyst to accept.', role: 'operator', propose: 'open_case',
      input_schema: S({ properties: { title: STR(300), alert_ids: IDS, playbook_id: { type: 'string', enum: [''].concat(playbooks.PLAYBOOKS.map((p) => p.id)) }, reason: STR(600) }, required: ['title', 'alert_ids', 'reason'] }) },
    { name: 'propose_add_case_note', description: 'Propose adding a note to a case. Recorded for the analyst to accept.', role: 'operator', propose: 'add_case_note', input_schema: S({ properties: { case_id: STR(40), text: STR(4000), reason: STR(600) }, required: ['case_id', 'text', 'reason'] }) },
    { name: 'propose_add_alerts_to_case', description: 'Propose adding alerts to a case. Recorded for the analyst to accept.', role: 'operator', propose: 'add_alerts_to_case', input_schema: S({ properties: { case_id: STR(40), alert_ids: IDS, reason: STR(600) }, required: ['case_id', 'alert_ids', 'reason'] }) },
    { name: 'propose_close_alert', description: 'Propose closing an alert with a reason. Recorded for the analyst to accept.', role: 'operator', propose: 'close_alert',
      input_schema: S({ properties: { alert_id: STR(40), reason: { type: 'string', enum: ['true-positive', 'false-positive', 'benign'] }, note: STR(1000) }, required: ['alert_id', 'reason', 'note'] }) },
    { name: 'propose_assign_alert', description: 'Propose assigning an alert to an analyst. Recorded for the analyst to accept.', role: 'operator', propose: 'assign_alert', input_schema: S({ properties: { alert_id: STR(40), assignee: STR(120), reason: STR(600) }, required: ['alert_id', 'assignee', 'reason'] }) },
    { name: 'propose_save_hunt', description: 'Propose saving a hunt query for the analyst. Recorded for the analyst to accept.', role: 'analyst', propose: 'save_hunt', input_schema: S({ properties: { name: STR(120), q: STR(1000), hours: { type: 'integer', minimum: 1, maximum: 720 }, reason: STR(600) }, required: ['name', 'q', 'reason'] }) },
  ];

  const allAlerts = () => (typeof alerts.all === 'function' ? alerts.all() : state.collection('alerts').all());
  const slim = (a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, assignee: a.assignee, case_id: a.case_id, ts_first: a.ts_first && new Date(a.ts_first).toISOString(),
    ts_last: a.ts_last && new Date(a.ts_last).toISOString(), count: a.count, host: a.host, group: a.group, fields: a.fields, summary: a.summary, mitre: a.mitre, notes: (a.notes || []).slice(-6), history: (a.history || []).slice(-6) });
  async function run(name, i) {
    if (name === 'soc_overview') { if (!deps.analyst) return { note: 'the overview is not available' }; const o = deps.analyst.overview(); return { open: o.open, mtta_min: o.mtta_min, mttr_min: o.mttr_min, act_now: o.act_now, top_rules: o.top_rules, top_entities: o.top_entities, xdr: o.xdr, ueba: o.ueba, noisy_rules: o.noisy_rules }; }
    if (name === 'alert_queue') { if (!deps.analyst) return { note: 'the queue is not available' }; const q = deps.analyst.queue({ q: i.q, label: i.label, limit: i.limit || 15 }); return { total: q.total, bands: q.bands, items: q.items.map((x) => ({ id: x.id, rule_name: x.rule_name, severity: x.severity, priority: x.priority, label: x.label, entities: x.entities, summary: String(x.summary || '').slice(0, 200), triage: x.triage, incident: x.incident && x.incident.id })) }; }
    if (name === 'get_alert') {
      const a = alerts.get(i.id); if (!a) throw new Error('no alert ' + i.id);
      let pr = null; if (deps.analyst) { const q = deps.analyst.queue({ status: 'all', limit: 500 }).items.find((x) => x.id === a.id); if (q) pr = { priority: q.priority, label: q.label, why: q.why, entities: q.entities }; }
      const t = deps.analyst && deps.analyst.getTriage ? deps.analyst.getTriage(a.id) : null;
      return Object.assign(slim(a), { priority: pr, ai_triage: t ? { state: t.state, draft: t.draft } : null });
    }
    if (name === 'related_alerts') {
      const { entitiesOf } = require('../xdr/xdr'); const from = now() - (i.hours || 168) * H;
      let keys;
      if (i.id) { const a = alerts.get(i.id); if (!a) throw new Error('no alert ' + i.id); keys = new Set(entitiesOf(a, new Set()).map((e) => e.replace(/^xip:/, 'ip:'))); }
      else if (i.entity) keys = new Set([String(i.entity).toLowerCase()]); else throw new Error('give an alert id or an entity');
      const rel = allAlerts().filter((x) => x.id !== i.id && (x.ts_last || 0) >= from && entitiesOf(x, new Set()).some((e) => keys.has(e.replace(/^xip:/, 'ip:')))).sort((x, y) => (y.ts_last || 0) - (x.ts_last || 0)).slice(0, 30);
      return { entities: [...keys], total: rel.length, alerts: rel.map((x) => ({ id: x.id, rule_name: x.rule_name, severity: x.severity, status: x.status, case_id: x.case_id, ts_last: new Date(x.ts_last || 0).toISOString(), summary: String(x.summary || '').slice(0, 200) })) };
    }
    if (name === 'list_cases') { const r = cases.list({ status: i.status || 'active', q: i.q, limit: 30 }); return { total: r.total, items: r.items.map((c) => ({ id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner, alerts: (c.alerts || []).length, sla: c.sla_state })) }; }
    if (name === 'get_case') { if (!deps.investigate) { const c = cases.get(i.id); if (!c) throw new Error('no case ' + i.id); return c; } const w = deps.investigate.workspace(i.id); return { case: { id: w.case.id, title: w.case.title, status: w.case.status, owner: w.case.owner, severity: w.case.severity, sla: w.case.sla_state, tasks: w.case.tasks, evidence: w.case.evidence, approvals: w.case.recommended_actions }, alerts: w.alerts, scope: w.scope, timeline: w.timeline.slice(-40), suggested: w.suggested.slice(0, 10), brief: w.brief && w.brief.draft }; }
    if (name === 'entity_profile') { if (!deps.ueba) return { note: 'UEBA is not running' }; const e = deps.ueba.entity(String(i.entity)); if (!e) return { note: 'no UEBA profile for ' + i.entity }; return { entity: e.entity, risk: { score: e.risk.score, tier: e.risk.tier, contributions: (e.risk.contributions || []).slice(0, 8) }, findings: (e.findings || []).slice().sort((x, y) => (y.severity || 0) - (x.severity || 0)).slice(0, 10).map((f) => ({ id: f.id, detector: f.detector, severity: f.severity, status: f.status, explanation: f.explanation })) }; }
    if (name === 'intel_lookup') { if (!deps.intel) return { note: 'threat intelligence is not loaded' }; return { value: i.value, lists: deps.intel.lookup(String(i.value).trim()) }; }
    if (name === 'intel_sightings') { if (!deps.intelView) return { note: 'threat intelligence is not loaded' }; const o = deps.intelView.overview(); return o.enabled ? { sightings: o.sightings.slice(0, 20), total: o.sightings_total, open: o.open_sightings } : { note: o.note }; }
    if (name === 'xdr_incident') { if (!deps.xdr) return { note: 'XDR is not running' }; const m = deps.xdr.byAlert().get(i.alert_id); if (!m) return { incident: null }; const inc = deps.xdr.incident(m.id); return inc ? { id: inc.id, title: inc.title, score: inc.score, why: inc.why, domains: Object.keys(inc.domains || {}), tactics: inc.tactics } : m; }
    if (name === 'count_events') { if (!deps.search) return { note: 'the event store is not available' }; deps.search.parse(i.q); const r = await deps.search.histogram({ q: i.q, from: now() - (i.hours || 24) * H, to: now(), buckets: 24 }); return { q: i.q, count: r.buckets.reduce((s, x) => s + x.n, 0) }; }
    if (name === 'top_values') { if (!deps.search) return { note: 'the event store is not available' }; deps.search.parse(i.q); const r = await deps.search.top({ q: i.q, from: now() - (i.hours || 24) * H, to: now(), field: i.field, limit: 10 }); return { values: r.values }; }
    if (name === 'search_events') { if (!deps.search) return { note: 'the event store is not available' }; deps.search.parse(i.q); const r = await deps.search.search({ q: i.q, from: now() - (i.hours || 24) * H, to: now(), limit: 20, fields: ['host', 'user', 'src_ip', 'dst_ip', 'category', 'action', 'outcome', 'process', 'message'] }); return { rows: (r.rows || []).map((e) => Object.assign({}, e, { message: String(e.message || '').slice(0, 300) })) }; }
    throw new Error('unknown tool ' + name);
  }

  // ------------------------------------------------------------------ proposals
  function validate(kind, x) {
    const mustAlert = (id) => { if (!alerts.get(id)) throw httpErr(404, 'alert ' + id + ' not found'); };
    const mustCase = (id) => { if (!cases.get(id)) throw httpErr(404, 'case ' + id + ' not found'); };
    if (kind === 'open_case') { if (!x.alert_ids.length) throw httpErr(400, 'alert_ids: at least one alert'); x.alert_ids.forEach(mustAlert); }
    if (kind === 'add_case_note') mustCase(x.case_id);
    if (kind === 'add_alerts_to_case') { mustCase(x.case_id); if (!x.alert_ids.length) throw httpErr(400, 'alert_ids: at least one alert'); x.alert_ids.forEach(mustAlert); }
    if (kind === 'close_alert' || kind === 'assign_alert') mustAlert(x.alert_id);
    if (kind === 'assign_alert' && !SC.isHuman(x.assignee)) throw httpErr(400, 'assignee must be a person');
    if (kind === 'save_hunt') { if (!deps.search) throw httpErr(503, 'the event store is not available'); try { deps.search.parse(x.q); } catch (e) { throw httpErr(400, 'q: ' + e.message); } }
  }
  function propose(kind, input, ctx) {
    const x = Object.assign({}, input); delete x.reason;
    validate(kind, x);
    const p = { id: 'CPP-' + now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase(), kind, params: x, reason: String(input.reason || input.note || '').slice(0, 600),
      status: 'pending', requested_by: ctx.user, conversation: ctx.conversation, at: now(), needs_role: PROPOSE[kind] };
    props.put(p); ctx.proposals.push(p);
    return { recorded: p.id, kind, status: 'pending', note: 'Recorded for the analyst to accept or reject in the Copilot panel. Nothing has changed.' };
  }
  function decide(id, b, who) {
    if (!SC.isHuman(who.user)) throw httpErr(403, 'only a person accepts a copilot proposal: ' + String(who.user || 'this identity') + ' is a service / AI identity');
    const p = props.get(id); if (!p) throw httpErr(404, 'proposal not found');
    if (p.status !== 'pending') throw httpErr(409, 'this proposal was already ' + p.status + ' by ' + p.decided_by);
    // a proposal belongs to the conversation that produced it: the analyst who asked decides it (an administrator may clear one)
    if (String(p.requested_by || '').toLowerCase() !== String(who.user || '').toLowerCase() && who.role !== 'admin') throw httpErr(403, 'this proposal was made in ' + p.requested_by + '\'s conversation - they decide it');
    if ((RANK[who.role] || 0) < RANK[p.needs_role]) throw httpErr(403, 'accepting this needs the ' + p.needs_role + ' role - it runs as you');
    let result = null;
    if (b.decision === 'accept') {
      const x = p.params; validate(p.kind, x);   // checked again: the record may have changed since it was proposed
      const by = who.user, note = ' (proposed by the SOC Copilot, accepted by ' + by + ')';
      if (p.kind === 'open_case') { const c = cases.create({ title: x.title, alert_ids: x.alert_ids, playbook_id: x.playbook_id || undefined, auto_playbook: !x.playbook_id, owner: by, description: (p.reason || '') + note }, by); result = { case_id: c.id, approvals: (c.approvals || []).length }; }
      else if (p.kind === 'add_case_note') { cases.note(x.case_id, x.text + note, by); result = { case_id: x.case_id }; }
      else if (p.kind === 'add_alerts_to_case') { cases.addAlerts(x.case_id, x.alert_ids, by); result = { case_id: x.case_id, added: x.alert_ids.length }; }
      else if (p.kind === 'close_alert') { alerts.close(x.alert_id, x.reason, by, x.note + note); result = { alert_id: x.alert_id, closed: x.reason }; }
      else if (p.kind === 'assign_alert') { alerts.assign(x.alert_id, x.assignee, by); result = { alert_id: x.alert_id, assignee: x.assignee }; }
      else if (p.kind === 'save_hunt') { const h = deps.investigate.save({ name: x.name, q: x.q, hours: x.hours || 24, shared: false }, who); result = { hunt_id: h.id }; }
    }
    props.put(Object.assign({}, p, { status: b.decision === 'accept' ? 'accepted' : 'rejected', decided_by: who.user, decided_at: now(), decision_note: b.note || '', result }));
    return props.get(id);
  }
  function proposals(who, status) { return props.all((p) => p.requested_by === who.user && (!status || p.status === status)).sort((a, b) => b.at - a.at).slice(0, 100); }

  // ------------------------------------------------------------------ the conversation loop
  async function exec(block, ctx, steps, flags) {
    const def = TOOLS.find((t) => t.name === block.name), t0 = Date.now();
    if (!def || !ctx.offered.has(block.name) || !allowed(def, ctx.role)) { steps.push({ tool: block.name, ok: false, refused: true }); return { type: 'tool_result', tool_use_id: block.id, content: `not allowed: ${block.name} is not available to the ${ctx.role} role`, is_error: true }; }
    const err = check(def.input_schema, block.input);
    if (err) { steps.push({ tool: block.name, ok: false, error: err }); return { type: 'tool_result', tool_use_id: block.id, content: 'invalid input: ' + err, is_error: true }; }
    try {
      const out = def.propose ? propose(def.propose, block.input, ctx) : await run(block.name, block.input);
      let text = JSON.stringify(out); if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated]';
      const f = G.injectionSignals(text); if (f.length) flags.push(...f);
      steps.push({ tool: block.name, ok: true, ms: Date.now() - t0, proposal: def.propose ? out.recorded : undefined, injection_signals: f.length ? f : undefined });
      return { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool:' + block.name, text) };
    } catch (e) {
      steps.push({ tool: block.name, ok: false, ms: Date.now() - t0, error: String(e.message || e).slice(0, 200) });
      return { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool-error:' + block.name, 'error: ' + String(e.message || e).slice(0, 300)), is_error: true };
    }
  }

  async function ask(b, who) {
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const role = RANK[who.role] !== undefined ? who.role : 'viewer', user = who.user || 'unknown';
    let conv = b.conversation ? chats.get(b.conversation) : null;
    if (b.conversation && (!conv || conv.user !== user)) throw httpErr(404, 'conversation not found');   // private to its user
    if (!conv) conv = { id: 'CPC-' + crypto.randomBytes(6).toString('hex'), user, created: now(), messages: [], title: String(b.question).slice(0, 80) };
    if (conv.messages.length > 120 || JSON.stringify(conv.messages).length > 500000) throw httpErr(409, 'this conversation is too long - start a new one');
    const ctxLine = b.context && b.context.kind && b.context.kind !== 'none' ? `[context: the analyst is on ${b.context.page || 'a SOC page'} looking at ${b.context.kind} ${b.context.id || ''}]` : `[context: the analyst is on ${(b.context && b.context.page) || 'a SOC page'}]`;
    const tools = TOOLS.filter((t) => allowed(t, role)), offered = new Set(tools.map((t) => t.name));
    const budget = G.sharedBudget({ log: L, limits: () => (deps.config && deps.config.ai_limits) || {} }), qflags = G.injectionSignals(b.question);
    budget.admit(user, 'soc.copilot', b.question.length);
    const messages = conv.messages.concat([{ role: 'user', content: ctxLine + '\n' + b.question }]);
    const steps = [], flags = [...qflags], ctx = { user, role, conversation: conv.id, offered, proposals: [] };
    const client = AI.client(); let usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }, answer = null;
    try {
      for (let i = 0; i < MAX_STEPS; i++) {
        const resp = await client.messages.create({ model: AI.model(), max_tokens: 8000, thinking: { type: 'adaptive' }, output_config: { effort: AI.effort() },
          system: SYSTEM + '\n\n' + G.UNTRUSTED_RULE, tools: tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema })), messages, cache_control: { type: 'ephemeral' } });
        for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
        messages.push({ role: 'assistant', content: resp.content });
        if (resp.stop_reason === 'refusal') { answer = 'The Copilot declined this request. Rephrase it as a security operations question.'; break; }
        if (resp.stop_reason === 'pause_turn') continue;
        const uses = resp.content.filter((x) => x.type === 'tool_use');
        if (resp.stop_reason !== 'tool_use' || !uses.length) { answer = resp.content.filter((x) => x.type === 'text').map((x) => x.text).join('\n').trim(); break; }
        const results = [];
        for (const u of uses) results.push(await exec(u, ctx, steps, flags));
        messages.push({ role: 'user', content: results });
      }
    } finally { budget.record(user, 'soc.copilot', usage, [...new Set(flags)]); }
    if (answer === null) answer = 'Stopped after ' + MAX_STEPS + ' steps. The evidence gathered so far is in the steps; ask a narrower follow-up.';
    conv.messages = messages; conv.updated = now(); chats.put(conv);
    L.info('soc copilot', { user, role, steps: steps.length, proposals: ctx.proposals.length, in: usage.input_tokens, out: usage.output_tokens });
    return { answer, conversation: conv.id, steps, proposals: ctx.proposals, usage, injection_signals: [...new Set(flags)], model: AI.model() };
  }
  function conversations(who) { return chats.all((c) => c.user === who.user).sort((a, b) => (b.updated || 0) - (a.updated || 0)).slice(0, 30).map((c) => ({ id: c.id, title: c.title, updated: c.updated })); }
  function conversation(id, who) {
    const c = chats.get(id); if (!c || c.user !== who.user) throw httpErr(404, 'conversation not found');
    // what the analyst saw: their questions and the copilot's answers (tool traffic stays out)
    const turns = [];
    for (const m of c.messages) {
      if (m.role === 'user' && typeof m.content === 'string') turns.push({ role: 'analyst', text: m.content.replace(/^\[context:[^\]]*\]\n/, '') });
      else if (m.role === 'assistant') { const t = (m.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n').trim(); if (t) turns.push({ role: 'copilot', text: t }); }
    }
    return { id: c.id, title: c.title, turns, proposals: props.all((p) => p.conversation === c.id).sort((a, b) => a.at - b.at) };
  }

  return { ask, decide, proposals, conversations, conversation, status: () => AI.status(), TOOLS, PAGES, KINDS };
}

module.exports = { createCopilot, PAGES, KINDS, PROPOSE };
