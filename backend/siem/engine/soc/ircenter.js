// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const SC = require('../approvers/scopes');
const G = require('../util/ai-guard');
const { createModel, runLoop } = require('./ai-loop');
/*
 * Incident Response Center - one command view over what the SOC is responding to, built on the cases (soc/cases.js), their
 * playbooks and approval requests, the XDR incidents (xdr/xdr.js) and the DFIR regulatory clocks (dfir/forensics.js).
 * It decides nothing on its own: every write (owner, status, playbook, approval) goes through the existing case routes.
 *
 *   createIrCenter({ state, alerts, cases, config, log, sdk?, now?, xdr?: () => x, forensics?: () => f })
 *     board()            open incidents by lifecycle phase (open → investigating → contained → eradicated → recovered),
 *                        KPIs, what needs attention, workload per responder, untriaged XDR incidents, response metrics
 *                        (MTTA / MTTC / MTTR medians, false-positive rate, 8-week opened vs closed, backlog forecast)
 *     incident(id)       one case: phase, SLA, playbook progress and the next steps, approvals, regulatory clocks,
 *                        similar past incidents and what was learned from them
 *     ask(id, mode, who) the AI incident commander: a response plan (mode "plan") or a stakeholder update ("update"), from
 *                        read-only tools; a draft a person adds to the case as their note (decide)
 *
 * Machine learning (explainable, from the organisation's own closed cases - never a vendor benchmark):
 *   breach risk     chance an open case misses its resolve SLA: of the closed cases of the same severity band still open at
 *                   this case's age, how many took longer than the time this one has left (Beta(1,1)-smoothed; 5+ needed,
 *                   pooled across bands below that)
 *   similar cases   Jaccard similarity over rule ids, ATT&CK techniques, entities and playbook against closed cases; the
 *                   resolution they ended with and how long they took; a recommended playbook when the case has none
 *   priority        severity + SLA pressure + breach risk + waiting approvals + an overdue regulatory clock, every point itemised
 *   backlog         least-squares line over the weekly net (opened - closed) → expected open cases in 4 weeks
 */
const H = 3600e3, DAY = 24 * H, WEEK = 7 * DAY;
const PHASES = ['open', 'investigating', 'contained', 'eradicated', 'recovered'];
const SEVN = ['info', 'low', 'medium', 'high', 'critical'];
const band = (s) => (s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low');
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const median = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 4000 });

/* pure: chance of missing the resolve SLA from closed durations (hours) */
function breachChance(durH, ageH, leftH) {
  if (durH.length < 5) return { p: null, why: 'needs 5 closed cases to learn from (' + durH.length + ' so far)' };
  const older = durH.filter((d) => d > ageH), late = older.filter((d) => d > ageH + leftH).length;
  return { p: Math.round(((late + 1) / (older.length + 2)) * 100) / 100, why: late + ' of ' + older.length + ' past case(s) still open at ' + Math.round(ageH) + ' h took longer than the ' + Math.max(0, Math.round(leftH)) + ' h left' };
}
/* pure: Jaccard similarity of two token sets */
function jaccard(a, b) { if (!a.size || !b.size) return 0; let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i); }
function lsq(pts) {
  const n = pts.length; if (n < 3) return null;
  const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n, sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0);
  if (!sxx) return null; const slope = pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx; return { slope, intercept: my - slope * mx };
}

const ASK_SYSTEM = {
  plan: `You are the AI incident commander for ${ZYB_ORG.name}, advising the responder who owns ONE incident case.
Read the case (get_incident), its alerts (case_alerts), what happened in similar past incidents (similar_incidents) and the regulatory clocks (regulatory_clocks). Then call submit_plan once.
- Base every statement on tool results; never invent hosts, users, IPs, times, counts or outcomes. Say what is unknown.
- next_actions are steps for people, in lifecycle order (investigating → contained → eradicated → recovered); mark needs_approval true for anything that changes a system (block, isolate, disable, reset) - those are approval requests a named approver decides. Cite a ref a tool returned.
- Past incidents are indicators of what may work, not proof. Personal data only as needed (PDPL).`,
  update: `You are the AI incident commander for ${ZYB_ORG.name} writing a short stakeholder update for ONE incident (for the CISO and management).
Read the case (get_incident), its alerts (case_alerts) and the regulatory clocks (regulatory_clocks). Then call submit_plan once with the update in stakeholder_update: status, impact known so far, what is being done, what is needed from management, next update time. Neutral, factual, no technical jargon, no names beyond roles. Never invent facts.`,
};

function createIrCenter(deps = {}) {
  const { state, alerts, cases } = deps;
  if (!state || !cases) throw new Error('createIrCenter needs state and cases');
  const L = deps.log || { info() {}, warn() {}, error() {} };
  const now = deps.now || Date.now;
  const aiC = state.collection('soc_ir_ai');
  const AI = createModel({ config: deps.config, deps, log: L });
  const getX = () => { try { return typeof deps.xdr === 'function' ? deps.xdr() : deps.xdr; } catch (e) { return null; } };
  const getF = () => { try { return typeof deps.forensics === 'function' ? deps.forensics() : deps.forensics; } catch (e) { return null; } };
  const all = () => (cases.all ? cases.all(() => true) : (cases.list({ status: 'all', limit: 500 }).items || []));
  const alertOf = (id) => (alerts && alerts.get ? alerts.get(id) : null);

  function tokens(c) {
    const t = new Set();
    for (const aid of c.alerts || []) {
      const a = alertOf(aid); if (!a) continue;
      if (a.rule_id) t.add('rule:' + a.rule_id);
      for (const m of a.mitre || []) t.add('t:' + String(m).split('.')[0]);
      const g = a.group || {}, f = a.fields || {};
      if (g.user) t.add('user:' + String(g.user).toLowerCase()); if (g.host) t.add('host:' + String(g.host).toLowerCase());
      for (const k of ['src_ip', 'dst_ip']) { const v = g[k] || f[k]; if (v) t.add('ip:' + v); }
    }
    if (c.playbook_id) t.add('pb:' + c.playbook_id);
    return t;
  }
  function contained(c) { const e = (c.timeline || []).find((x) => x.kind === 'status' && /→contained/.test(String(x.text || ''))); return e ? e.at : null; }

  function learn(list, t) {
    const closed = list.filter((c) => c.status === 'closed' && c.closed && c.created);
    const dur = {}, pooled = [];
    for (const c of closed) { const h = (c.closed - c.created) / H; pooled.push(h); (dur[band(c.severity)] = dur[band(c.severity)] || []).push(h); }
    const recent = closed.filter((c) => c.closed >= t - 90 * DAY);
    const mtta = median(recent.filter((c) => c.acked_at).map((c) => (c.acked_at - c.created) / H));
    const mttc = median(recent.map((c) => { const x = contained(c); return x ? (x - c.created) / H : null; }).filter((x) => x != null));
    const mttr = median(recent.map((c) => (c.closed - c.created) / H));
    const fp = recent.length ? Math.round(100 * recent.filter((c) => c.resolution === 'false-positive').length / recent.length) : null;
    const weeks = []; for (let i = 7; i >= 0; i--) { const from = t - (i + 1) * WEEK, to = t - i * WEEK; weeks.push({ from, opened: list.filter((c) => c.created >= from && c.created < to).length, closed: closed.filter((c) => c.closed >= from && c.closed < to).length }); }
    const open = list.filter((c) => c.status !== 'closed').length;
    const fit = lsq(weeks.map((w, i) => [i, w.opened - w.closed]));
    let backlog;
    if (closed.length + open < 5 || !fit) backlog = { now: open, in_4_weeks: null, note: 'a backlog forecast needs a few weeks of cases' };
    else { const net = [8, 9, 10, 11].reduce((a, i) => a + Math.max(-open, fit.intercept + fit.slope * i), 0); const f = Math.max(0, Math.round(open + net));
      backlog = { now: open, in_4_weeks: f, note: f > open ? 'more cases are opening than closing - the queue is expected to grow' : f < open ? 'the team is closing faster than cases open - the queue is expected to shrink' : 'opening and closing are balanced' }; }
    return { closed, dur, pooled, metrics: { closed_90d: recent.length, mtta_h: mtta == null ? null : Math.round(mtta * 10) / 10, mttc_h: mttc == null ? null : Math.round(mttc * 10) / 10, mttr_h: mttr == null ? null : Math.round(mttr * 10) / 10, false_positive_pct: fp }, weeks, backlog };
  }

  function similar(c, closed) {
    const me = tokens(c); if (!me.size) return [];
    return closed.filter((x) => x.id !== c.id).map((x) => ({ x, s: jaccard(me, tokens(x)) })).filter((r) => r.s >= 0.2).sort((a, b) => b.s - a.s).slice(0, 5)
      .map((r) => ({ id: r.x.id, title: r.x.title, similarity: Math.round(r.s * 100) / 100, resolution: r.x.resolution, playbook_id: r.x.playbook_id || '', hours_to_close: Math.round((r.x.closed - r.x.created) / H), shared: [...me].filter((k) => tokens(r.x).has(k)).slice(0, 8) }));
  }

  function enrich(c, Lr, clocksById, t) {
    const v = cases.view ? cases.view(c, t) : cases.get(c.id), sla = v.sla_state;
    const ageH = (t - c.created) / H, leftH = sla.resolve_remaining_ms / H;
    const durs = (Lr.dur[band(c.severity)] || []).length >= 5 ? Lr.dur[band(c.severity)] : Lr.pooled;
    const risk = breachChance(durs, ageH, leftH);
    const pend = (v.recommended_actions || []).filter((a) => a.status === 'pending').length;
    const tasks = c.tasks || [], done = tasks.filter((x) => x.done).length;
    const next = tasks.filter((x) => !x.done).slice(0, 3).map((x) => ({ id: x.id, title: x.title, phase: x.phase || '', kind: x.kind || 'manual', action_id: x.action_id || '' }));
    const clocks = clocksById[c.id] || [];
    const reasons = []; const add = (p, why) => { if (p > 0) reasons.push({ points: p, why }); };
    add((c.severity || 0) * 15, SEVN[c.severity || 0] + ' severity');
    if (sla.resolve_breached) add(25, 'resolve SLA breached'); else if (!c.acked_at && sla.ack_breached) add(20, 'not acknowledged within its SLA');
    else if (leftH <= 4) add(10, 'resolve SLA ends within 4 h');
    if (risk.p != null && risk.p >= 0.5 && !sla.resolve_breached) add(Math.round(risk.p * 20), Math.round(risk.p * 100) + ' % chance of missing the SLA (' + risk.why + ')');
    if (pend) add(Math.min(15, 5 * pend), pend + ' response action(s) waiting for an approver');
    const clk = clocks.filter((k) => /breached|due-soon/.test(k.state)); if (clk.length) add(20, clk.map((k) => k.name + ' notification ' + (k.state === 'breached' ? 'overdue' : 'due soon')).join(', '));
    if (!c.owner) add(5, 'no owner');
    return { id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner || '', created: c.created, age_h: Math.round(ageH),
      sla: { ack_breached: sla.ack_breached, resolve_breached: sla.resolve_breached, resolve_due: sla.resolve_due, left_h: Math.round(leftH) }, breach: risk,
      playbook_id: c.playbook_id || '', playbook_name: v.playbook_name || '', tasks: { done, total: tasks.length }, next, approvals_pending: pend, alerts: (c.alerts || []).length,
      clocks, priority: Math.min(100, reasons.reduce((a, r) => a + r.points, 0)), reasons };
  }

  function clocksMap() {
    const out = {}; const F = getF();
    if (F && F.board) { try { for (const r of F.board().cases) out[r.id] = r.clocks; } catch (e) { L.warn('ir center: DFIR clocks not read', { err: e && e.message }); } }
    return out;
  }

  function board() {
    const t = now(), list = all(), Lr = learn(list, t), clk = clocksMap();
    const open = list.filter((c) => c.status !== 'closed').map((c) => enrich(c, Lr, clk, t)).sort((a, b) => b.priority - a.priority);
    const lanes = PHASES.map((p) => ({ phase: p, items: open.filter((c) => c.status === p) }));
    let xdr = { available: false, untriaged: [] };
    const X = getX();
    if (X && X.incidents) { try { const r = X.incidents({ status: 'open' }); const L2 = (r.incidents || r.items || r || []).filter((i) => !(i.cases || []).length);
      xdr = { available: true, untriaged: L2.sort((a, b) => b.score - a.score).slice(0, 15).map((i) => ({ id: i.id, title: i.title, score: i.score, severity: i.severity, alerts: i.alerts, tactics: i.tactics, domains: Object.keys(i.domains || {}) })) }; }
      catch (e) { L.warn('ir center: XDR incidents not read', { err: e && e.message }); xdr = { available: false, untriaged: [], error: String(e.message || e).slice(0, 160) }; } }
    const pendAll = cases.approvals ? cases.approvals.list({ status: 'pending' }) : [];
    const kpis = { open: open.length, critical_high: open.filter((c) => c.severity >= 3).length, unassigned: open.filter((c) => !c.owner).length,
      sla_breached: open.filter((c) => c.sla.resolve_breached || (c.sla.ack_breached && c.status === 'open')).length, likely_breach: open.filter((c) => c.breach.p != null && c.breach.p >= 0.5 && !c.sla.resolve_breached).length,
      approvals_pending: pendAll.length, untriaged_xdr: xdr.untriaged.length, clocks_overdue: open.reduce((a, c) => a + c.clocks.filter((k) => k.state === 'breached').length, 0) };
    const attention = [];
    for (const c of open) {
      if (c.clocks.some((k) => k.state === 'breached')) attention.push({ level: 'bad', id: c.id, text: c.id + ': a regulator notification is overdue (DFIR)' });
      if (c.sla.resolve_breached) attention.push({ level: 'bad', id: c.id, text: c.id + ' is past its resolve SLA' });
      else if (c.status === 'open' && c.sla.ack_breached) attention.push({ level: 'bad', id: c.id, text: c.id + ' has not been acknowledged within its SLA' });
      else if (c.breach.p != null && c.breach.p >= 0.5) attention.push({ level: 'warn', id: c.id, text: c.id + ' will probably miss its SLA (' + Math.round(c.breach.p * 100) + ' %)' });
      if (c.approvals_pending) attention.push({ level: 'warn', id: c.id, text: c.id + ': ' + c.approvals_pending + ' response action(s) wait for an approver' });
      if (!c.playbook_id && c.severity >= 3) attention.push({ level: 'info', id: c.id, text: c.id + ' has no playbook - open it for the recommended one' });
    }
    for (const i of xdr.untriaged.filter((x) => x.score >= 60).slice(0, 5)) attention.push({ level: 'warn', xdr: i.id, text: 'XDR incident ' + i.id + ' (score ' + i.score + ') has no case yet: ' + i.title });
    const rank = { bad: 0, warn: 1, info: 2 }; attention.sort((a, b) => rank[a.level] - rank[b.level]);
    const owners = {}; for (const c of open) { const o = c.owner || '(unassigned)'; const w = owners[o] || (owners[o] = { owner: o, open: 0, critical_high: 0, breached: 0 }); w.open++; if (c.severity >= 3) w.critical_high++; if (c.sla.resolve_breached) w.breached++; }
    return { at: t, kpis, lanes: lanes.map((l) => ({ phase: l.phase, count: l.items.length })), incidents: open, attention: attention.slice(0, 30), workload: Object.values(owners).sort((a, b) => b.open - a.open),
      xdr, metrics: Lr.metrics, weeks: Lr.weeks, backlog: Lr.backlog, learned_from: Lr.closed.length, ai: AI.status(), phases: PHASES };
  }

  function incident(id) {
    const c0 = cases.get(id); if (!c0) throw httpErr(404, 'case not found: ' + id);
    const t = now(), list = all(), Lr = learn(list, t), clk = clocksMap(), raw = list.find((x) => x.id === id) || c0;
    const e = enrich(raw, Lr, clk, t), sim = similar(raw, Lr.closed);
    let recPb = null;
    if (!raw.playbook_id) {
      const votes = {}; for (const s of sim) if (s.playbook_id && s.resolution === 'true-positive') votes[s.playbook_id] = (votes[s.playbook_id] || 0) + s.similarity;
      let pb = Object.entries(votes).sort((a, b) => b[1] - a[1])[0];
      if (pb) recPb = { id: pb[0], why: 'used on similar past incidents that were true positives' };
      else { try { const s = require('./playbooks').suggest((raw.alerts || []).map(alertOf).filter(Boolean)); if (s) recPb = { id: s, why: 'matches the rules and ATT&CK techniques of this case\'s alerts' }; } catch (er) { L.warn('ir center: playbook suggestion failed', { err: er && er.message }); } }
      if (recPb) { try { const p = require('./playbooks').get(recPb.id); recPb.name = p ? p.name : recPb.id; } catch (er) { recPb.name = recPb.id; } }
    }
    const votes = {}; for (const s of sim) votes[s.resolution] = (votes[s.resolution] || 0) + s.similarity;
    const likely = Object.entries(votes).sort((a, b) => b[1] - a[1])[0];
    return Object.assign(e, { description: raw.description || '', timeline: (raw.timeline || []).slice(-40), tasks_all: (raw.tasks || []).map((x) => ({ id: x.id, title: x.title, phase: x.phase || '', done: !!x.done, kind: x.kind || 'manual' })),
      approvals: (cases.view ? cases.view(raw, t) : c0).recommended_actions || [], similar: sim, recommended_playbook: recPb,
      likely_resolution: likely && sim.length >= 2 ? { resolution: likely[0], why: 'the most common outcome of the ' + sim.length + ' most similar past incidents - an indicator, not a verdict' } : null,
      ai: aiC.get(id) || null, ai_status: AI.status() });
  }

  // ---------------------------------------------------------------- AI incident commander
  const TOOLS = [
    { name: 'get_incident', description: 'The incident case: title, severity, phase, owner, SLA, playbook tasks and their state, approval requests, recent timeline.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'case_alerts', description: 'The alerts linked to the case: rule, severity, ATT&CK, first / last seen, entities, summary.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'similar_incidents', description: 'Closed past incidents most similar to this one: resolution, playbook, time to close, what they share.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'regulatory_clocks', description: 'PDPL / SAMA / NCA / IA notification clocks for the case (from DFIR), if any.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'submit_plan', description: 'Submit the plan or update.', input_schema: S({ properties: {
      summary: STR(3000), phase_assessment: STR(1000), stakeholder_update: STR(3000),
      next_actions: { type: 'array', maxItems: 15, items: S({ properties: { action: STR(400), phase: { type: 'string', enum: ['investigating', 'contained', 'eradicated', 'recovered', 'closed'] }, needs_approval: { type: 'boolean' }, ref: STR(200) }, required: ['action', 'phase', 'needs_approval'] }) },
      risks: { type: 'array', maxItems: 10, items: STR(300) } }, required: ['summary'] }) },
  ];
  function runTool(caseId, name, i, seen) {
    if (String(i.id) !== caseId) return { note: 'only the case being asked about can be read: ' + caseId };
    if (name === 'get_incident') {
      const v = incident(caseId); seen.add(caseId); for (const x of v.tasks_all) seen.add(x.id); for (const a of v.approvals) seen.add(a.id);
      return { id: v.id, title: v.title, severity: SEVN[v.severity || 0], phase: v.status, owner: v.owner ? 'assigned' : 'unassigned', sla: v.sla, breach_risk: v.breach, playbook: v.playbook_name,
        tasks: v.tasks_all, approvals: v.approvals.map((a) => ({ id: a.id, title: a.title, status: a.status, targets: a.targets })), timeline: v.timeline.slice(-20).map((x) => ({ at: new Date(x.at).toISOString(), kind: x.kind, text: String(x.text || '').slice(0, 300) })) };
    }
    if (name === 'case_alerts') {
      const c = cases.get(caseId);
      return (c.alerts || []).slice(0, 40).map(alertOf).filter(Boolean).map((a) => { seen.add(a.id); const g = a.group || {}; for (const k of ['user', 'host']) if (g[k]) seen.add(k + ':' + String(g[k]).toLowerCase());
        return { id: a.id, rule: a.rule_name || a.rule_id, severity: SEVN[a.severity || 0], mitre: a.mitre || [], first: a.ts_first ? new Date(a.ts_first).toISOString() : null, last: a.ts_last ? new Date(a.ts_last).toISOString() : null, entities: g, summary: String(a.summary || '').slice(0, 300) }; });
    }
    if (name === 'similar_incidents') { const s = incident(caseId).similar; for (const x of s) seen.add(x.id); return s; }
    if (name === 'regulatory_clocks') { const k = clocksMap()[caseId] || []; return k.length ? k.map((x) => ({ name: x.name, state: x.state, due: x.due ? new Date(x.due).toISOString() : null })) : { note: 'no regulatory clock recorded for this case in DFIR' }; }
    throw new Error('unknown tool ' + name);
  }
  async function ask(caseId, mode, question, who) {
    if (!cases.get(caseId)) throw httpErr(404, 'case not found: ' + caseId);
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const q = G.redactSecrets(String(question || '')).slice(0, 1500);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: ASK_SYSTEM[mode], tools: TOOLS, role: who.role || 'operator', user: who.user || 'unknown', feature: 'soc.ir-commander', config: deps.config, log: L,
      prompt: `Case ${caseId}. ${mode === 'plan' ? 'Draft the response plan.' : 'Draft the stakeholder update.'}${q ? '\nThe responder adds:\n' + G.untrusted('responder-question', q) : ''}\nUse the tools, then call submit_plan.`, run: (n, inp, seen) => runTool(caseId, n, inp, seen), final: 'submit_plan', maxSteps: 10 });
    if (!r.result) throw httpErr(502, 'the AI did not return a ' + (mode === 'plan' ? 'plan' : 'update') + ' (' + r.note + ') - try again');
    const chk = (v) => { const s = String(v || '').trim(); return !s || r.seen.has(s) || r.seen.has(s.toLowerCase()); };
    const d = r.result, acts = (d.next_actions || []).map((a) => Object.assign({}, a, { verified: chk(a.ref) }));
    const rec = { id: caseId, mode, state: 'draft', at: now(), by: AI.model(), asked_by: who.user, role: who.role, summary: d.summary, phase_assessment: d.phase_assessment || '', stakeholder_update: d.stakeholder_update || '',
      next_actions: acts, risks: d.risks || [], unverified: acts.filter((a) => !a.verified).length, steps: r.steps, usage: r.usage, injection_signals: r.flags };
    aiC.put(rec); L.info('ir commander draft', { case: caseId, mode, user: who.user, steps: r.steps.length });
    return rec;
  }
  function decide(caseId, decision, who) {
    if (!SC.isHuman(who.user)) throw httpErr(403, 'only a person adds an AI draft to a case');
    const r = aiC.get(caseId); if (!r) throw httpErr(404, 'no AI draft for ' + caseId);
    if (r.state !== 'draft') throw httpErr(409, 'this draft was already ' + r.state);
    if (decision === 'add') {
      const ok = r.next_actions.filter((a) => a.verified);
      const text = (r.mode === 'plan' ? 'Response plan' : 'Stakeholder update') + ' (AI draft, reviewed and added by ' + who.user + ')\n\n' + r.summary
        + (r.stakeholder_update ? '\n\n' + r.stakeholder_update : '') + (ok.length ? '\n\nNext actions:\n- ' + ok.map((a) => '[' + a.phase + '] ' + a.action + (a.needs_approval ? ' (needs approval)' : '')).join('\n- ') : '')
        + (r.risks.length ? '\n\nRisks:\n- ' + r.risks.join('\n- ') : '') + (r.unverified ? '\n\n(' + r.unverified + ' action(s) cited something no tool returned and were left out.)' : '');
      cases.note(caseId, text.slice(0, 20000), who.user);
    }
    aiC.put(Object.assign({}, r, { state: decision === 'add' ? 'added' : 'discarded', decided_by: who.user, decided_at: now() }));
    return aiC.get(caseId);
  }
  return { board, incident, ask, decide, TOOLS };
}

module.exports = { createIrCenter, breachChance, jaccard, PHASES };
