// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const path = require('node:path');
const G = require('../util/ai-guard');
const SCH = require('../util/ai-schema');
const ML = require('./alert-ml');
const QI = require('./queue-insights');
const OI = require('./overview-insights');
const playbooks = require('./playbooks');
const { entitiesOf } = require('../xdr/xdr');
const SC = require('../approvers/scopes');
/*
 * The SOC's AI analyst and the data behind the Security Operations Overview and Alert Queue.
 *
 *   createAnalyst({ state, alerts, cases, ueba?, intel?, xdr?, config, log, sdk?, now? })
 *     queue(q)          open alerts with the explainable priority (alert-ml.js), entities, intel hits, the XDR incident, the
 *                       AI triage state; sorted by priority; clusters of near-identical alerts collapsible
 *     overview(q)       the SOC at a glance: open by severity / priority band, 14-day raised vs closed (by reason), MTTA / MTTR,
 *                       top rules and entities, ATT&CK tactics, sources, XDR, UEBA, what the AI analyst did and how often
 *                       people agreed with it - every figure computed from the stores, nothing assumed
 *     triage(id, who)   Claude investigates ONE alert with read-only tools and returns a DRAFT: verdict, confidence, summary,
 *                       evidence (each item must cite a record a tool returned - anything else is marked unverified), next
 *                       steps, ATT&CK, and optionally a playbook from the fixed list. It never closes, assigns or contains.
 *     decide(id, b, who) a PERSON accepts or rejects the draft. Accepting may close the alert with the person's reason and/or
 *                       open a case with the proposed playbook - the case raises the playbook's approval requests, which a
 *                       named approver decides (cases.js); nothing is executed by the engine.
 *     settings / putSettings / autoTick   optional auto-triage of new high-severity alerts (off by default; budgeted)
 *
 * AI rules (docs/AI-SECURITY.md): tools are filtered by the asker's role before the model sees them and re-checked per call;
 * every tool input is schema-checked; tool output is DATA (G.untrusted, secrets redacted); UNTRUSTED_RULE is in the system
 * prompt; G.sharedBudget admits before and records after every call. The automatic triage runs as the service identity
 * ai:soc-analyst with the analyst role, which does NOT get the UEBA behavioural profile tool (personal data, PDPL).
 */
const MODEL = 'claude-opus-5-5';
const MAX_STEPS = 10, MAX_RESULT = 20000, DAY = 86400000;
const VERDICTS = ['true_positive', 'false_positive', 'benign', 'needs_more_data'];
const CLOSE_OF = { true_positive: 'true-positive', false_positive: 'false-positive', benign: 'benign' };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const SERVICE = 'ai:soc-analyst';
const isClosed = (s) => typeof s === 'string' && s.startsWith('closed-');
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });

const SYSTEM = `You are the AI SOC Analyst for ${ZYB_ORG.name}'s Security Operations Centre (SIEM alerts from Windows / Active Directory, Microsoft 365, FortiGate and Palo Alto firewalls, Kaspersky EDR, e-mail gateways, Oracle databases, UEBA and threat intelligence).

Your job: triage ONE alert the way a senior analyst would, then call submit_triage exactly once.

How you work:
- Start with get_alert, then look for context in parallel: related_alerts for the same user / host / IP, rule_history (how people closed this rule before), intel_lookup for external IPs, domains and hashes, incident (XDR correlation), and entity_profile (UEBA behaviour) when it is offered to you.
- Base every statement on tool results. Never invent users, hosts, IPs, counts or log lines. If something is missing, say so and choose needs_more_data rather than guess.
- Evidence items must cite a ref that a tool returned (an alert id such as ALR-0000123, an entity key such as user:alice or host:pc-17, an indicator value, or an incident id such as XDR-...).
- Verdicts: true_positive (malicious or policy-violating activity that needs response), false_positive (the detection fired on activity it should not have), benign (the detection was right but the activity is authorised / expected - a benign true positive), needs_more_data.
- A rule's history of false-positive closures is a hint, not proof; a first-time entity, intel hits and cross-domain correlation raise concern.
- You cannot close, assign, contain or change anything. If response is warranted, choose ONE playbook id from the playbook list in submit_triage; a person decides whether to open a case, and every containment step still needs a named approver.
- Keep it tight: the summary is two or three sentences for the analyst on shift. Reply in English unless the alert text is Arabic.`;

const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const TOOLS = [
  { name: 'get_alert', description: 'The alert: rule, severity, ATT&CK, first/last seen, count, group, fields, summary, notes, history, status.', input_schema: S({ properties: { id: { type: 'string' } }, required: ['id'] }) },
  { name: 'related_alerts', description: 'Other alerts in the last N hours that share an entity (user / host / IP) or the rule with the given alert.', input_schema: S({ properties: { id: { type: 'string' }, hours: { type: 'integer', minimum: 1, maximum: 720 } }, required: ['id'] }) },
  { name: 'rule_history', description: 'How this rule has behaved in 30 days: volume per day, how people closed it (true positive / false positive / benign) and the last closure notes.', input_schema: S({ properties: { rule_id: { type: 'string' } }, required: ['rule_id'] }) },
  { name: 'intel_lookup', description: 'Which threat-intelligence lists contain an IP, domain, URL host or file hash.', input_schema: S({ properties: { value: { type: 'string' } }, required: ['value'] }) },
  { name: 'incident', description: 'The XDR correlated incident this alert belongs to (other alerts, domains, ATT&CK chain, score), if any.', input_schema: S({ properties: { alert_id: { type: 'string' } }, required: ['alert_id'] }) },
  { name: 'entity_profile', description: 'UEBA behaviour profile of an entity (user:<name> or host:<name>): risk score and tier with contributions, open findings, peer comparison.', input_schema: S({ properties: { entity: { type: 'string' } }, required: ['entity'] }) },
  { name: 'submit_triage', description: 'Submit the triage draft. Call exactly once, last.', input_schema: S({ properties: {
    verdict: { type: 'string', enum: VERDICTS }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    severity: { type: 'integer', minimum: 0, maximum: 4 }, summary: { type: 'string' }, reasoning: { type: 'string' },
    evidence: { type: 'array', maxItems: 12, items: S({ properties: { ref: { type: 'string' }, fact: { type: 'string' } }, required: ['ref', 'fact'] }) },
    next_steps: { type: 'array', maxItems: 8, items: { type: 'string' } }, mitre: { type: 'array', maxItems: 8, items: { type: 'string' } },
    playbook: { type: 'string', enum: [''].concat(playbooks.PLAYBOOKS.map((p) => p.id)) } }, required: ['verdict', 'confidence', 'summary', 'evidence'] }) },
];
SCH.assertSchemas(TOOLS, 'soc analyst');   // a rule the checker cannot enforce is refused at load, never silently ignored
// minimum role per tool: the UEBA profile is behavioural personal data, as on the UEBA page (operator and above)
const TOOL_ROLE = { entity_profile: 'operator' };
const toolAllowed = (name, role) => !TOOL_ROLE[name] || (RANK[role] || 0) >= RANK[TOOL_ROLE[name]];

// the model's arguments against the tool's schema - the shared checker (util/ai-schema.js, the same file as IT Asset Management's)
const check = (schema, v, at = 'input') => SCH.checkInput(schema, v, at);

function createAnalyst(deps = {}) {
  const { state, alerts, cases } = deps;
  if (!state || !alerts) throw new Error('createAnalyst needs state and alerts');
  const L = deps.log || { info() {}, warn() {}, error() {} };
  const now = deps.now || Date.now;
  const cfg = () => (deps.config && deps.config.soc_analyst) || {};
  const triC = state.collection('soc_ai_triage'), setC = state.collection('soc_ai_settings');
  const internal = () => new Set(((deps.xdr && deps.xdr.settings && deps.xdr.settings().internal_domains) || []).map((d) => String(d).toLowerCase()));
  // the pipeline canary's own alerts (rule SENTRA-OPS-900, engine/ops/canary.js) are a test of the SIEM, never an analyst's work
  const allAlerts = () => (typeof alerts.all === 'function' ? alerts.all() : state.collection('alerts').all()).filter((a) => a.rule_id !== 'SENTRA-OPS-900');

  // ---- the learned model, rebuilt at most once a minute (the queue and the overview share it)
  let mc = null;
  function model() {
    if (mc && now() - mc.at < 60000) return mc.m;
    const ints = internal();
    mc = { at: now(), m: ML.learn(allAlerts(), { now: now(), days: 30, entitiesOf: (a) => entitiesOf(a, ints) }) };
    return mc.m;
  }
  function context() {
    const ints = internal();
    let tiers = null;
    if (deps.ueba && typeof deps.ueba.entities === 'function') {
      try { tiers = new Map(deps.ueba.entities({ limit: 500 }).items.map((e) => [e.id, e.tier])); }
      catch (e) { L.warn('soc analyst: UEBA entities not read', { err: e.message }); }
    }
    let inc = null;
    if (deps.xdr && typeof deps.xdr.byAlert === 'function') { try { inc = deps.xdr.byAlert(); } catch (e) { L.warn('soc analyst: XDR incidents not read', { err: e.message }); } }
    const intelHits = (a) => {
      if (!deps.intel || typeof deps.intel.lookup !== 'function') return [];
      const out = [];
      for (const v of indicators(a)) for (const list of deps.intel.lookup(v)) out.push({ value: v, list });
      return out;
    };
    return { ints, tiers, inc, intelHits };
  }
  function indicators(a) {
    const f = Object.assign({}, a.fields || {}, a.group || {}), out = new Set();
    for (const k of ['src_ip', 'dst_ip', 'remote_ip', 'client_ip', 'domain', 'url_host', 'sender_domain', 'hash', 'sha256', 'md5', 'file_hash']) {
      const v = String(f[k] || '').trim(); if (v && v !== '-' && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(v)) out.add(v.slice(0, 200));
    }
    return [...out].slice(0, 10);
  }
  function scored(a, m, c) {
    const ents = entitiesOf(a, c.ints).map((e) => e.replace(/^xip:/, 'ip:'));
    const s = ML.score(a, m, {
      entities: ents,
      ueba: c.tiers ? (e) => c.tiers.get(e) || null : null,
      intel: deps.intel ? c.intelHits : null,
      incident: c.inc ? (x) => c.inc.get(x.id) || null : null,
      critical: deps.watchlist ? (e) => deps.watchlist.criticalFor(e) : null,
      watched: deps.watchlist ? (e) => deps.watchlist.watchedFor(e) : null,
    });
    const t = triC.get(a.id);
    return Object.assign({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, summary: a.summary, status: a.status, assignee: a.assignee || '',
      ts_first: a.ts_first, ts_last: a.ts_last, count: a.count || 1, host: a.host || '', tactic: a.tactic || '', mitre: a.mitre || [], source: a.source || '', src_type: a.src_type || '',
      case_id: a.case_id || '', entities: ents, incident: c.inc ? c.inc.get(a.id) || null : null,
      triage: t ? { verdict: t.draft && t.draft.verdict, confidence: t.draft && t.draft.confidence, state: t.state, at: t.at } : null }, s);
  }

  function queue(q = {}) {
    const m = model(), c = context();
    const statuses = q.status === 'all' ? null : q.status === 'closed' ? (s) => isClosed(s) : (s) => !isClosed(s);
    let items = allAlerts().filter((a) => a.source !== 'logrhythm' && (!statuses || statuses(a.status))).map((a) => scored(a, m, c));
    if (q.label) items = items.filter((x) => x.label === q.label);
    if (q.min_priority) items = items.filter((x) => x.priority >= Number(q.min_priority));
    if (q.severity) { const sv = String(q.severity).split(',').map(Number); items = items.filter((x) => sv.includes(x.severity)); }
    if (q.triage === 'none') items = items.filter((x) => !x.triage); else if (q.triage) items = items.filter((x) => x.triage && x.triage.state === q.triage);
    if (q.assignee === 'unassigned') items = items.filter((x) => !x.assignee); else if (q.assignee) items = items.filter((x) => x.assignee === q.assignee);
    if (q.q) { const s = String(q.q).toLowerCase(); items = items.filter((x) => `${x.id} ${x.rule_id} ${x.rule_name} ${x.summary} ${x.host} ${x.entities.join(' ')}`.toLowerCase().includes(s)); }
    const bands = { 'act-now': 0, investigate: 0, review: 0, low: 0, 'likely-noise': 0 };
    for (const x of items) bands[x.label]++;
    // collapse a cluster to its highest-priority member, carrying the cluster size
    if (q.collapse === '1' || q.collapse === true) {
      const seen = new Map();
      for (const x of items.sort((a, b) => b.priority - a.priority)) { const k = x.cluster ? x.cluster.key : x.id; if (!seen.has(k)) seen.set(k, x); }
      items = [...seen.values()];
    }
    const sort = q.sort || '-priority';
    const key = { priority: (x) => x.priority, ts: (x) => x.ts_last || 0, severity: (x) => x.severity }[sort.replace(/^-/, '')] || ((x) => x.priority);
    items.sort((a, b) => (sort.startsWith('-') ? key(b) - key(a) : key(a) - key(b)) || (b.ts_last || 0) - (a.ts_last || 0));
    const total = items.length, limit = Math.max(1, Math.min(500, Number(q.limit) || 200)), offset = Math.max(0, Number(q.offset) || 0);
    return { total, bands, items: items.slice(offset, offset + limit), model: { days: m.days, alerts: m.total, rules_learned: [...m.rules.values()].filter((r) => r.noise !== null).length, rules: m.rules.size },
      sources: { ueba: !!c.tiers, intel: !!deps.intel, xdr: !!c.inc, ai: status() }, generated_at: now() };
  }

  // ---- Alert Queue insights (queue-insights.js): campaigns across rules, backlog flow and forecast, SLA risk, precedent
  function insights() {
    const t = now(), all = allAlerts().filter((a) => a.source !== 'logrhythm'), m = model(), c = context();
    const open = all.filter((a) => !isClosed(a.status)).map((a) => Object.assign(scored(a, m, c), { created: a.created, acked_at: a.ack_at }));
    const closed = all.filter((a) => isClosed(a.status) && (a.closed_at || 0) >= t - 90 * DAY)
      .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, summary: a.summary, status: a.status, closed_at: a.closed_at, history: a.history, entities: entitiesOf(a, c.ints).map((e) => e.replace(/^xip:/, 'ip:')) }));
    const policy = (cases && cases.SLA) || require('./cases').DEFAULT_SLA;
    const prec = QI.precedent(open, closed);
    return { generated_at: t, open: open.length, histogram: QI.histogram(open), campaigns: QI.campaigns(open), flow: QI.flow(all, t), sla: QI.sla(open, policy, t),
      precedent: prec, precedent_alerts: Object.keys(prec).length,
      owners: QI.owners(open, closed, SC.isHuman), tuning: QI.tuning(closed, t), surge: QI.surge(all, t),
      similar: QI.similar(open.slice().sort((a, b) => b.priority - a.priority), closed),
      top: open.filter((x) => !x.triage).sort((a, b) => b.priority - a.priority).slice(0, 5).map((x) => x.id) };
  }

  // ---- Security Operations Overview insights (overview-insights.js): volume forecast, rules behaving differently, rule efficacy,
  // entities most at risk now, SLA attainment per week
  function overviewInsights() {
    const t = now(), all = allAlerts().filter((a) => a.source !== 'logrhythm'), m = model(), c = context();
    const open = all.filter((a) => !isClosed(a.status)).map((a) => scored(a, m, c));
    const policy = (cases && cases.SLA) || require('./cases').DEFAULT_SLA;
    return { generated_at: t, forecast: OI.forecast(all, t), shifts: OI.shifts(all, t), efficacy: OI.efficacy(all, t), entities: OI.entities(open), sla: OI.sla(all, policy, t) };
  }

  function overview(q = {}) {
    const t = now(), all = allAlerts().filter((a) => a.source !== 'logrhythm'), m = model(), c = context();
    const open = all.filter((a) => !isClosed(a.status));
    const bySev = [0, 0, 0, 0, 0]; for (const a of open) bySev[Math.max(0, Math.min(4, a.severity || 0))]++;
    const bands = { 'act-now': 0, investigate: 0, review: 0, low: 0, 'likely-noise': 0 };
    const sc = open.map((a) => scored(a, m, c)); for (const x of sc) bands[x.label]++;
    // 14 days: raised per day, closed per day by reason (Riyadh days, UTC+3)
    const days = 14, off = 3 * 3600000, d0 = Math.floor((t + off) / DAY) - days + 1;
    const series = Array.from({ length: days }, (_, i) => ({ day: new Date((d0 + i) * DAY).toISOString().slice(0, 10), raised: 0, tp: 0, fp: 0, benign: 0 }));
    const slot = (ms) => { const k = Math.floor(((ms || 0) + off) / DAY) - d0; return k >= 0 && k < days ? series[k] : null; };
    for (const a of all) {
      const r = slot(a.created || a.ts_first); if (r) r.raised++;
      if (isClosed(a.status) && a.closed_at) { const s = slot(a.closed_at); if (s) s[a.status === 'closed-true-positive' ? 'tp' : a.status === 'closed-false-positive' ? 'fp' : 'benign']++; }
    }
    const since = t - 7 * DAY, recent = all.filter((a) => (a.created || a.ts_first || 0) >= since);
    const top = (fn, n) => { const mm = new Map(); for (const a of recent) for (const k of [].concat(fn(a))) if (k) mm.set(k, (mm.get(k) || 0) + 1); return [...mm.entries()].sort((x, y) => y[1] - x[1]).slice(0, n).map(([k, v]) => ({ key: k, count: v })); };
    const ack = all.filter((a) => a.ack_at && a.created && a.created >= since).map((a) => a.ack_at - a.created);
    const res = all.filter((a) => a.closed_at && a.created && a.closed_at >= since).map((a) => a.closed_at - a.created);
    const med = (L2) => { if (!L2.length) return null; const s = L2.slice().sort((x, y) => x - y); return Math.round(s[Math.floor(s.length / 2)] / 60000); };
    const tri = triC.all();
    const decided = tri.filter((x) => x.state === 'accepted' || x.state === 'rejected');
    const agreed = tri.filter((x) => { const a = alerts.get(x.id); return a && isClosed(a.status) && x.draft && CLOSE_OF[x.draft.verdict] && a.status === 'closed-' + CLOSE_OF[x.draft.verdict]; }).length;
    const closedTriaged = tri.filter((x) => { const a = alerts.get(x.id); return a && isClosed(a.status) && x.draft && CLOSE_OF[x.draft.verdict]; }).length;
    let xdr = null; if (deps.xdr) { try { xdr = deps.xdr.incidents({ scope: 'correlated', limit: 5 }); xdr = { summary: xdr.summary, top: xdr.items.slice(0, 5).map((i) => ({ id: i.id, title: i.title, score: i.score, domains: Object.keys(i.domains), alerts: i.alerts, status: i.status })) }; } catch (e) { L.warn('soc overview: XDR not read', { err: e.message }); xdr = null; } }
    let ueba = null; if (deps.ueba) { try { const u = deps.ueba.summary({ limit: 5 }); ueba = { tiers: u.tiers, top: u.top_risky.map((e) => ({ id: e.id, name: e.name, type: e.type, score: e.risk_score, tier: e.tier })), findings_24h: u.new_findings.length }; } catch (e) { L.warn('soc overview: UEBA not read', { err: e.message }); ueba = null; } }
    const noisy = [...m.rules.values()].filter((r) => r.noise !== null && r.noise >= 0.8).sort((a, b) => b.n - a.n).slice(0, 5).map((r) => ({ rule_id: r.rule_id, rule_name: r.rule_name, per_day: r.per_day, noise: r.noise, closed: r.closed }));
    return {
      generated_at: t,
      open: { total: open.length, by_severity: bySev, unassigned: open.filter((a) => !a.assignee).length, bands, new_24h: all.filter((a) => (a.created || 0) >= t - DAY).length },
      series, mtta_min: med(ack), mttr_min: med(res),
      top_rules: top((a) => a.rule_name || a.rule_id, 8), top_entities: top((a) => entitiesOf(a, c.ints), 8), tactics: top((a) => a.tactic || '', 14), sources: top((a) => a.src_type || a.source || 'other', 8),
      act_now: sc.filter((x) => x.label === 'act-now').sort((a, b) => b.priority - a.priority).slice(0, 6).map((x) => ({ id: x.id, rule_name: x.rule_name, priority: x.priority, severity: x.severity, entities: x.entities.slice(0, 3), summary: x.summary })),
      noisy_rules: noisy, xdr, ueba,
      ai: { status: status(), triaged: tri.length, accepted: tri.filter((x) => x.state === 'accepted').length, rejected: tri.filter((x) => x.state === 'rejected').length,
        drafts: tri.filter((x) => x.state === 'draft').length, agreement_pct: closedTriaged >= 3 ? Math.round((agreed / closedTriaged) * 100) : null, closed_triaged: closedTriaged, decided: decided.length, auto: settings() },
      model: { days: m.days, alerts: m.total, rules: m.rules.size, rules_learned: [...m.rules.values()].filter((r) => r.noise !== null).length },
      sources_connected: { ueba: !!ueba, xdr: !!xdr, intel: !!deps.intel },
    };
  }

  // ---- the model call
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (deps.sdk) return deps.sdk; if (Ctor) return Ctor;
    const c = cfg(), tries = ['@anthropic-ai/sdk', c.sdk_path || '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk'), require('path').join(__dirname, '..', 'util', 'ai-sdk-shim.js')];
    for (const p of tries) { try { const mod = require(p); Ctor = require('../util/ai-backend').wrap(mod.Anthropic || mod.default || mod); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (run install/netops-ai-sdk)' : e.message; } }
    return null;
  }
  function apiKey() { const s = deps.config && deps.config.secrets; return (s && s.netops && s.netops.anthropic_api_key) || process.env.ANTHROPIC_API_KEY || ''; }
  function status() {
    const c = cfg();
    if (c.enabled === false) return { enabled: false, reason: 'the AI SOC analyst is switched off (config soc_analyst.enabled)', model: c.model || MODEL };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model: c.model || MODEL };
    if (!apiKey()) return { enabled: false, reason: 'no Anthropic API key (secrets.json netops.anthropic_api_key)', model: c.model || MODEL };
    return { enabled: true, model: c.model || MODEL };
  }

  const slimAlert = (a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, mitre: a.mitre, tactic: a.tactic, status: a.status, ts_first: a.ts_first && new Date(a.ts_first).toISOString(),
    ts_last: a.ts_last && new Date(a.ts_last).toISOString(), count: a.count, host: a.host, group: a.group, fields: a.fields, summary: a.summary, source: a.source, src_type: a.src_type, assignee: a.assignee, case_id: a.case_id,
    notes: (a.notes || []).slice(-10), history: (a.history || []).slice(-10) });
  function runTool(name, i, seen) {
    const ints = internal();
    if (name === 'get_alert') { const a = alerts.get(i.id); if (!a) throw new Error('no alert ' + i.id); seen.add(a.id); for (const e of entitiesOf(a, ints)) seen.add(e.replace(/^xip:/, 'ip:')); for (const v of indicators(a)) seen.add(v); return slimAlert(a); }
    if (name === 'related_alerts') {
      const a = alerts.get(i.id); if (!a) throw new Error('no alert ' + i.id);
      const from = now() - (i.hours || 168) * 3600000, mine = new Set(entitiesOf(a, ints));
      const rel = allAlerts().filter((x) => x.id !== a.id && (x.ts_last || 0) >= from && (x.rule_id === a.rule_id || entitiesOf(x, ints).some((e) => mine.has(e))))
        .sort((x, y) => (y.ts_last || 0) - (x.ts_last || 0)).slice(0, 40);
      for (const x of rel) seen.add(x.id);
      return { entities: [...mine], total: rel.length, alerts: rel.map((x) => ({ id: x.id, rule_name: x.rule_name, severity: x.severity, status: x.status, ts_last: new Date(x.ts_last || 0).toISOString(), shared: entitiesOf(x, ints).filter((e) => mine.has(e)), summary: String(x.summary || '').slice(0, 300) })) };
    }
    if (name === 'rule_history') {
      const r = model().rules.get(i.rule_id); if (!r) return { rule_id: i.rule_id, note: 'no alert of this rule in 30 days' };
      const notes = allAlerts().filter((x) => x.rule_id === i.rule_id && isClosed(x.status)).sort((x, y) => (y.closed_at || 0) - (x.closed_at || 0)).slice(0, 5)
        .map((x) => ({ id: x.id, closed_as: x.status, note: String(((x.notes || []).slice(-1)[0] || {}).text || '').slice(0, 300) }));
      for (const x of notes) seen.add(x.id);
      return { rule_id: r.rule_id, rule_name: r.rule_name, alerts_30d: r.n, per_day: r.per_day, closed: r.closed, true_positive: r.tp, false_positive: r.fp, benign: r.benign, noise_share: r.noise, last_closures: notes };
    }
    if (name === 'intel_lookup') {
      if (!deps.intel) return { value: i.value, note: 'threat intelligence is not loaded on this SIEM' };
      const lists = deps.intel.lookup(String(i.value).trim()); seen.add(String(i.value).trim());
      return { value: i.value, lists, listed: lists.length > 0 };
    }
    if (name === 'incident') {
      if (!deps.xdr) return { note: 'XDR correlation is not running' };
      const m = deps.xdr.byAlert().get(i.alert_id); if (!m) return { alert_id: i.alert_id, incident: null, note: 'not part of a correlated incident' };
      const inc = deps.xdr.incident(m.id); seen.add(m.id);
      return inc ? { id: inc.id, title: inc.title, score: inc.score, why: inc.why, domains: Object.keys(inc.domains || {}), tactics: inc.tactics, alerts: (inc.timeline || inc.alert_list || []).slice(0, 30) } : { id: m.id, score: m.score, domains: m.domains };
    }
    if (name === 'entity_profile') {
      if (!deps.ueba) return { note: 'UEBA is not running' };
      const e = deps.ueba.entity(String(i.entity)); if (!e) return { entity: i.entity, note: 'UEBA has no profile for this entity' };
      seen.add(e.entity.id);
      return { entity: e.entity, risk: { score: e.risk.score, tier: e.risk.tier, contributions: (e.risk.contributions || []).slice(0, 10) }, open_findings: (e.findings || []).filter((f) => f.status !== 'benign').slice(0, 10).map((f) => ({ id: f.id, detector: f.detector, severity: f.severity, explanation: f.explanation })), peer_comparison: e.peer_comparison };
    }
    throw new Error('unknown tool ' + name);
  }

  async function triage(id, who) {
    const a = alerts.get(id); if (!a) throw httpErr(404, 'alert not found');
    const st = status(); if (!st.enabled) throw httpErr(503, st.reason);
    const role = RANK[who.role] !== undefined ? who.role : 'analyst', user = who.user || SERVICE;
    const tools = TOOLS.filter((t) => toolAllowed(t.name, role));
    const system = SYSTEM + '\n\nPlaybooks you may propose (id - name):\n' + playbooks.PLAYBOOKS.map((p) => `${p.id} - ${p.name}`).join('\n') + '\n\n' + G.UNTRUSTED_RULE;
    const prompt = `Triage alert ${a.id} (${String(a.rule_name || a.rule_id).slice(0, 200)}). Use the tools, then call submit_triage.`;
    const budget = G.sharedBudget({ log: L, limits: () => (deps.config && deps.config.ai_limits) || {} });
    budget.admit(user, 'soc.triage', prompt.length);
    const Anthropic = loadSdk(), c = cfg();
    const client = new Anthropic({ apiKey: apiKey(), timeout: (c.timeout_s || 180) * 1000, maxRetries: 2, baseURL: c.base_url || undefined });
    const messages = [{ role: 'user', content: prompt }], steps = [], flags = [], seen = new Set();
    let usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }, draft = null, invalid = '', model = c.model || MODEL, note = '';
    try {
      for (let s = 0; s < MAX_STEPS && !draft; s++) {
        const params = { model, max_tokens: 8000, thinking: { type: 'adaptive' }, output_config: { effort: c.effort || 'high' }, system, tools, messages, cache_control: { type: 'ephemeral' } };
        const resp = await client.messages.create(params);
        for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
        model = resp.model || model;
        messages.push({ role: 'assistant', content: resp.content });
        if (resp.stop_reason === 'refusal') { note = 'the AI declined to triage this alert'; break; }
        if (resp.stop_reason === 'pause_turn') continue;
        const uses = resp.content.filter((b) => b.type === 'tool_use');
        if (!uses.length) { note = 'the AI answered without submitting a triage'; break; }
        const results = [];
        for (const b of uses) {
          const def = TOOLS.find((t) => t.name === b.name), t0 = Date.now();
          // re-checked per call: a tool the asker's role does not hold is refused even if the model names it
          if (!def || !toolAllowed(b.name, role) || !tools.includes(def)) { results.push({ type: 'tool_result', tool_use_id: b.id, content: `not allowed: ${b.name} is not available to the ${role} role`, is_error: true }); steps.push({ tool: b.name, ok: false, refused: true }); continue; }
          const err = check(def.input_schema, b.input);
          if (err) { results.push({ type: 'tool_result', tool_use_id: b.id, content: 'invalid input: ' + err, is_error: true }); steps.push({ tool: b.name, ok: false, error: err }); if (b.name === 'submit_triage') invalid = err; continue; }
          if (b.name === 'submit_triage') { draft = b.input; results.push({ type: 'tool_result', tool_use_id: b.id, content: 'received' }); steps.push({ tool: b.name, ok: true, ms: 0 }); continue; }
          try {
            let text = JSON.stringify(runTool(b.name, b.input, seen)); if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated]';
            const f = G.injectionSignals(text); if (f.length) flags.push(...f);
            results.push({ type: 'tool_result', tool_use_id: b.id, content: G.untrusted('tool:' + b.name, text) });
            steps.push({ tool: b.name, input: b.input, ok: true, ms: Date.now() - t0, injection_signals: f.length ? f : undefined });
          } catch (e) {
            results.push({ type: 'tool_result', tool_use_id: b.id, content: G.untrusted('tool-error:' + b.name, 'error: ' + String(e.message || e).slice(0, 300)), is_error: true });
            steps.push({ tool: b.name, input: b.input, ok: false, ms: Date.now() - t0, error: String(e.message || e).slice(0, 200) });
          }
        }
        if (draft) break;
        messages.push({ role: 'user', content: results });
      }
    } finally { budget.record(user, 'soc.triage', usage, [...new Set(flags)]); }
    if (!draft) {
      L.warn('soc analyst: no triage returned', { alert: a.id, note: note || invalid || 'step limit' });
      throw httpErr(502, 'the AI analyst did not return a triage for ' + a.id + ' (' + (note || (invalid ? 'invalid draft: ' + invalid : 'it ran out of steps')) + ') - triage it manually or try again');
    }
    // evidence must cite something a tool actually returned; anything else is kept but marked unverified
    const evidence = (draft.evidence || []).map((e) => ({ ref: e.ref, fact: String(e.fact).slice(0, 600), verified: seen.has(String(e.ref).trim()) }));
    const mitre = (draft.mitre || []).filter((x) => /^T\d{4}(\.\d{3})?$/.test(x));
    const rec = { id: a.id, state: 'draft', at: now(), by: model, requested_by: user, role,
      draft: { verdict: draft.verdict, confidence: draft.confidence, severity: Number.isInteger(draft.severity) ? draft.severity : null, summary: String(draft.summary).slice(0, 2000), reasoning: String(draft.reasoning || '').slice(0, 4000),
        evidence, next_steps: (draft.next_steps || []).map((x) => String(x).slice(0, 400)), mitre, playbook: draft.playbook || '' },
      unverified: evidence.filter((e) => !e.verified).length, steps, usage, injection_signals: [...new Set(flags)], runs: ((triC.get(a.id) || {}).runs || 0) + 1 };
    triC.put(rec);
    L.info('soc analyst triage', { alert: a.id, user, verdict: rec.draft.verdict, confidence: rec.draft.confidence, steps: steps.length, unverified: rec.unverified, in: usage.input_tokens, out: usage.output_tokens });
    return rec;
  }

  function getTriage(id) { return triC.get(id) || null; }

  function decide(id, b, who) {
    if (!SC.isHuman(who.user)) throw httpErr(403, 'only a person decides on an AI triage: ' + String(who.user || 'this identity') + ' is a service / AI identity');
    const t = triC.get(id); if (!t) throw httpErr(404, 'no AI triage for ' + id + ' - run the triage first');
    if (t.state !== 'draft') throw httpErr(409, 'this triage was already ' + t.state + ' by ' + t.decided_by);
    const a = alerts.get(id); if (!a) throw httpErr(404, 'alert not found');
    const out = { alert: id, closed: null, case_id: null };
    if (b.decision === 'accept') {
      if (b.close) {
        if (isClosed(a.status)) throw httpErr(409, id + ' is already closed');
        alerts.close(id, b.close, who.user, 'AI triage accepted by ' + who.user + ' (' + t.draft.verdict + ', ' + t.draft.confidence + ' confidence)' + (b.note ? ': ' + b.note : ''));
        out.closed = b.close;
      }
      if (b.open_case) {
        if (!cases) throw httpErr(409, 'case management is not available');
        if (a.case_id) throw httpErr(409, id + ' already belongs to ' + a.case_id);
        const pb = t.draft.playbook && playbooks.get(t.draft.playbook) ? t.draft.playbook : '';
        const cs = cases.create({ title: String(a.summary || a.rule_name).slice(0, 280), alert_ids: [id], playbook_id: pb, auto_playbook: !pb, owner: who.user,
          description: 'Opened by ' + who.user + ' from the AI SOC analyst triage of ' + id + ': ' + t.draft.summary }, who.user);
        out.case_id = cs.id; out.approvals = (cs.approvals || []).length;
      }
      if (!b.close && !b.open_case) alerts.note(id, 'AI triage accepted by ' + who.user + ': ' + t.draft.verdict + (b.note ? ' - ' + b.note : ''), who.user);
    } else alerts.note(id, 'AI triage rejected by ' + who.user + ': ' + b.note, who.user);
    triC.put(Object.assign({}, t, { state: b.decision === 'accept' ? 'accepted' : 'rejected', decided_by: who.user, decided_at: now(), decision_note: b.note || '', outcome: out }));
    return Object.assign(out, { triage: triC.get(id) });
  }

  // ---- optional auto-triage of new high-severity alerts (off by default; every call is budgeted like a person's)
  const DEF = { auto: false, min_severity: 3, max_per_hour: 6 };
  function settings() { return Object.assign({}, DEF, (cfg().auto || {}), setC.get('settings') || {}, { id: undefined }); }
  function putSettings(b, by) {
    const cur = settings(), next = Object.assign({}, cur, b), changed = Object.keys(b).filter((k) => cur[k] !== b[k]);
    setC.put({ id: 'settings', auto: next.auto, min_severity: next.min_severity, max_per_hour: next.max_per_hour, updated_by: by, updated_at: now() });
    return { settings: settings(), changed };
  }
  const autoRuns = [];
  async function autoTick() {
    const s = settings(); if (!s.auto || !status().enabled) return { ran: 0 };
    const t = now(); while (autoRuns.length && t - autoRuns[0] > 3600000) autoRuns.shift();
    const todo = allAlerts().filter((a) => !isClosed(a.status) && (a.severity || 0) >= s.min_severity && !triC.get(a.id) && a.source !== 'logrhythm' && (a.created || 0) >= t - DAY)
      .sort((x, y) => (y.severity - x.severity) || ((y.created || 0) - (x.created || 0)));
    let ran = 0;
    for (const a of todo) {
      if (autoRuns.length >= s.max_per_hour) break;
      autoRuns.push(now());
      try { await triage(a.id, { user: SERVICE, role: 'analyst' }); ran++; }
      catch (e) { L.warn('soc analyst: auto-triage failed', { alert: a.id, err: String(e.message).slice(0, 200) }); if (e.code === 429 || e.code === 503) break; }
    }
    return { ran };
  }

  return { queue, overview, overviewInsights, insights, triage, getTriage, decide, settings, putSettings, autoTick, status, model, TOOLS, SYSTEM, _check: check };
}

module.exports = { createAnalyst, TOOLS, TOOL_ROLE, toolAllowed, VERDICTS, SYSTEM, SERVICE, check };
