// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Questions to the teams (IT Infrastructure Manager dashboard). The manager sees the critical problems the platform already raises -
 * database (DBA alert center), servers and Exchange (AI Server Administrators' health checks), network (AI Network Engineer) - and
 * raises a question to the team that owns it, from the problem itself. The team acknowledges, answers; the manager follows up or
 * closes. Every step is a person, kept in the question's thread and in the audit log; the team is told by mail.
 *
 *   issues()          the flagged problems by team: critical (and high, flagged separately), with the open question on each
 *   ask / ack / answer / followUp / close   the workflow: open -> acknowledged -> answered -> closed (a follow-up re-opens)
 *   SLA               answer due in 4 h for a critical problem, 24 h otherwise (config); breach counted, never hidden
 *   ML                per team: answer time learned from answered questions (median, p90); breach risk of an open question from
 *                     that history (share of past answers that took longer, given the time already gone; from 5 answers);
 *                     "asked before": the closest past answered question on the same asset or the most similar words (Jaccard >= 0.35)
 *                     so the manager sees the earlier answer before asking again
 * Who answers: an administrator, or a person the IT Asset Management approver list names for the team's scope (DBA eng:dba,
 * servers eng:windows, Exchange eng:exchange, network eng:network). The person who asked cannot answer their own question.
 */
const crypto = require('node:crypto');
const SC = require('../approvers/scopes');

const TEAMS = { dba: { label: 'Database (DBA)', scope: 'eng:dba' }, server: { label: 'Servers', scope: 'eng:windows' }, exchange: { label: 'Exchange / mail', scope: 'eng:exchange' }, network: { label: 'Network', scope: 'eng:network' } };
const HOUR = 3600e3;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ' ').trim().slice(0, n);
const words = (t) => new Set(String(t || '').toLowerCase().split(/[^a-z0-9_.-]+/).filter((w) => w.length > 2));
const jaccard = (a, b) => { if (!a.size || !b.size) return 0; let i = 0; for (const x of a) if (b.has(x)) i++; return i / (a.size + b.size - i); };
const pct = (arr, p) => { if (!arr.length) return null; const x = arr.slice().sort((a, b) => a - b); return x[Math.min(x.length - 1, Math.floor(p * x.length))]; };
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);

function createQuestions(deps) {
  const now = deps.now || Date.now, L = deps.log || { info() {}, warn() {}, error() {} };
  const Q = deps.state.collection('ops_questions'), CFG = deps.state.collection('ops_questions_cfg');
  const cfg = () => { const c = CFG.get('cfg') || {}; return { version: c.version || 0, sla_h: Object.assign({ critical: 4, other: 24 }, c.sla_h || {}), teams: Object.assign({}, ...Object.keys(TEAMS).map((k) => ({ [k]: { emails: ((c.teams || {})[k] || {}).emails || [] } }))), by: c.by || null }; };
  const person = (who, what) => { if (!SC.isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const sevNorm = (v) => { const x = String(v || '').toLowerCase(); return x === 'critical' || x === 'crit' || x === '4' ? 'critical' : x === 'high' || x === 'warning' || x === 'warn' || x === '3' ? 'high' : x || 'medium'; };

  // the flagged problems, from the modules that raise them (each read on its own: one missing source never hides the others)
  function issues() { const out = [], miss = [];
    const take = (team, source, fn) => { try { const r = fn(); if (r === null) { miss.push({ team, source, why: 'not installed on this SIEM' }); return; } for (const x of r) out.push(Object.assign({ team, source }, x)); } catch (e) { miss.push({ team, source, why: 'could not be read: ' + e.message }); L.warn('questions: a problem source failed', { source, err: e.message }); } };
    take('dba', 'dba-alerts', () => { const D = deps.dbaAlerts; if (!D) return null; return D.conditions({ status: 'open' }).filter((c) => !c.snoozed).map((c) => ({ ref: 'dba:' + c.id, severity: sevNorm(c.level), asset: c.instance, title: c.label || c.metric, detail: [c.value != null ? 'value ' + c.value + (c.unit || '') : '', c.threshold != null ? 'threshold ' + c.threshold : '', c.ack ? 'acknowledged by ' + c.ack.by : ''].filter(Boolean).join(' · '), since: c.since || null })); });
    take('server', 'server-health', () => { const F = deps.sysadminFindings; if (!F) return null; return F('windows').filter((f) => f.scope !== 'exchange').map((f) => ({ ref: 'srv:' + f.server + ':' + f.kind, severity: sevNorm(f.severity), asset: f.server_name || f.server, title: f.title, detail: (f.evidence || []).slice(0, 2).join(' · '), since: null })); });
    take('exchange', 'exchange-health', () => { const F = deps.sysadminFindings; if (!F) return null; return F('exchange').filter((f) => f.scope === 'exchange').map((f) => ({ ref: 'exch:' + f.server + ':' + f.kind, severity: sevNorm(f.severity), asset: f.server_name || f.server, title: f.title, detail: (f.evidence || []).slice(0, 2).join(' · '), since: null })); });
    take('network', 'network', () => { const F = deps.netopsFindings; if (!F) return null; return F().map((f) => ({ ref: 'net:' + (f.id || f.device + ':' + f.kind), severity: sevNorm(f.severity), asset: f.device_name || f.device, title: f.title, detail: (f.evidence || []).slice(0, 2).join(' · ') + (f.site ? ' · site ' + f.site : ''), since: null })); });
    const open = Q.all((q) => q.status !== 'closed'), byRef = new Map(open.filter((q) => q.issue && q.issue.ref).map((q) => [q.issue.ref, q]));
    const flagged = out.filter((x) => x.severity === 'critical' || x.severity === 'high').map((x) => Object.assign(x, { question: byRef.has(x.ref) ? { id: byRef.get(x.ref).id, status: byRef.get(x.ref).status } : null }))
      .sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'critical' ? -1 : 1) || String(a.team).localeCompare(b.team));
    return { items: flagged, missing: miss, by_team: Object.keys(TEAMS).map((t) => ({ team: t, label: TEAMS[t].label, critical: flagged.filter((x) => x.team === t && x.severity === 'critical').length, high: flagged.filter((x) => x.team === t && x.severity === 'high').length, asked: flagged.filter((x) => x.team === t && x.question).length })) }; }

  function learning() { const out = {};
    for (const t of Object.keys(TEAMS)) { const done = Q.all((q) => q.team === t && q.answered_at).map((q) => (q.answered_at - q.asked_at) / HOUR);
      out[t] = { answered: done.length, median_h: r1(pct(done, 0.5)), p90_h: r1(pct(done, 0.9)), hours: done }; }
    return out; }
  function risk(q, Lr) { if (q.status !== 'open' && q.status !== 'acknowledged') return null; const H = Lr[q.team].hours, el = (now() - q.asked_at) / HOUR, due = (q.due_at - q.asked_at) / HOUR;
    if (H.length < 5) return { p: null, why: 'needs 5 answered questions for this team (has ' + H.length + ')' };
    const still = H.filter((h) => h > el); if (!still.length) return { p: 1, why: 'every past answer came sooner than this - it is unusually late' };
    const p = still.filter((h) => h > due).length / still.length; return { p: Math.round(p * 100) / 100, why: Math.round(p * 100) + ' % of past ' + TEAMS[q.team].label + ' answers that took over ' + r1(el) + ' h also took over the ' + r1(due) + ' h due time' }; }
  function similar(q) { const w = words(q.question + ' ' + ((q.issue || {}).title || '')); let best = null;
    for (const x of Q.all((y) => y.id !== q.id && y.team === q.team && y.answered_at)) { const same = q.issue && x.issue && q.issue.asset && x.issue.asset && String(q.issue.asset).toLowerCase() === String(x.issue.asset).toLowerCase(), j = jaccard(w, words(x.question + ' ' + ((x.issue || {}).title || ''))), sc = j + (same ? 0.25 : 0);
      if (sc >= 0.35 && (!best || sc > best.score)) best = { id: x.id, score: Math.round(sc * 100) / 100, question: x.question, answer: (x.thread.filter((m) => m.kind === 'answer').pop() || {}).text || '', by: x.answered_by, at: x.answered_at, same_asset: !!same }; }
    return best; }
  function view(f = {}) { const Lr = learning(), t = now(), C = cfg();
    const list = Q.all((q) => (!f.team || q.team === f.team) && (!f.status || f.status === 'all' || (f.status === 'open' ? q.status !== 'closed' : q.status === f.status)) && (!f.mine || q.asked_by === f.mine))
      .sort((a, b) => (a.status === 'closed') - (b.status === 'closed') || b.asked_at - a.asked_at).slice(0, 300)
      .map((q) => Object.assign({}, q, { team_label: TEAMS[q.team].label, overdue: q.status !== 'closed' && !q.answered_at && t > q.due_at, risk: risk(q, Lr), asked_before: similar(q) }));
    const all = Q.all(() => true), open = all.filter((q) => q.status !== 'closed');
    return { at: new Date(t).toISOString(), teams: Object.entries(TEAMS).map(([k, v]) => ({ id: k, label: v.label, scope: v.scope, open: open.filter((q) => q.team === k).length, overdue: open.filter((q) => q.team === k && !q.answered_at && t > q.due_at).length, answered: Lr[k].answered, median_h: Lr[k].median_h, p90_h: Lr[k].p90_h })),
      kpis: { open: open.length, waiting: open.filter((q) => !q.answered_at || q.status === 'reopened').length, answered: open.filter((q) => q.status === 'answered').length, overdue: open.filter((q) => !q.answered_at && t > q.due_at).length, closed: all.length - open.length },
      items: list, config: { sla_h: C.sla_h, version: C.version, teams: Object.fromEntries(Object.keys(TEAMS).map((k) => [k, { emails: C.teams[k].emails.length ? C.teams[k].emails : null }])) } }; }

  const get = (id) => { const q = Q.get(id); if (!q) throw httpErr(404, 'question not found'); return q; };
  const save = (q, who, kind, text) => { q.thread = (q.thread || []).concat([{ at: now(), by: who.user, kind, text: text || '' }]).slice(-200); q.updated_at = now(); Q.put(q); return q; };
  function notify(q, kind) { const send = deps.mail; if (!send) return; const C = cfg(); let to = C.teams[q.team].emails;
    if (!to.length && q.team === 'dba' && deps.dbaAlerts && deps.dbaAlerts.notifySettings) { try { to = deps.dbaAlerts.notifySettings().recipients || []; } catch (e) { to = []; /* DBA settings unreadable: no fallback list */ } }
    if (kind !== 'ask' && kind !== 'follow_up') to = [q.asked_by_email].filter(Boolean);
    // the mail answers later: record its outcome on the CURRENT question, never on this copy (it may have moved on since)
    const mark = (n) => { const cur = Q.get(q.id); if (cur) { cur.notify = n; Q.put(cur); } };
    if (!to.length) { mark({ sent: false, why: kind === 'answer' ? 'the asker gave no mail address' : 'no mail address for ' + TEAMS[q.team].label + ' (set it on the page)' }); return; }
    const subject = '[Question ' + q.id + '] ' + (kind === 'follow_up' ? 'Follow-up: ' : '') + (q.issue ? q.issue.title + ' on ' + q.issue.asset : 'from the infrastructure manager');
    const text = 'Asked by ' + q.asked_by + ' for ' + TEAMS[q.team].label + '.\n\n' + q.question + '\n\nAnswer due ' + new Date(q.due_at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC. Answer it on the platform: ' + (deps.portalUrl || '') + '/infra-manager.html#questions';
    Promise.resolve().then(() => send({ to, subject, text })).then(() => mark({ sent: true, to: to.length, at: now() }), (e) => { mark({ sent: false, why: 'mail failed: ' + e.message }); L.warn('questions: mail failed', { id: q.id, err: e.message }); }); }

  function ask(b, who) { person(who, 'ask a question'); const C = cfg();
    let issue = null; if (b.ref) { const it = issues().items.find((x) => x.ref === b.ref); if (!it) throw httpErr(409, 'ref: this problem is no longer flagged (cleared or snoozed) - refresh'); if (it.team !== b.team) throw httpErr(400, 'team: this problem belongs to ' + TEAMS[it.team].label);
      if (it.question) throw httpErr(409, 'a question on this problem is already open: ' + it.question.id); issue = { ref: it.ref, source: it.source, severity: it.severity, asset: it.asset, title: it.title, detail: it.detail }; }
    const sev = issue ? issue.severity : b.severity || 'medium', t = now();
    const q = { id: 'Q-' + crypto.randomBytes(3).toString('hex').toUpperCase(), team: b.team, issue, severity: sev, question: s(b.question, 3000), asked_by: who.user, asked_by_email: b.reply_to || null, asked_at: t, due_at: t + (sev === 'critical' ? C.sla_h.critical : C.sla_h.other) * HOUR, status: 'open', thread: [] };
    save(q, who, 'question', q.question); notify(q, 'ask'); return Q.get(q.id); }
  const canAnswer = (q, who) => { if (q.asked_by.toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'you asked this question - ' + TEAMS[q.team].label + ' answers it'); };
  function ack(id, who) { person(who, 'acknowledge'); const q = get(id); canAnswer(q, who); if (q.status !== 'open' && q.status !== 'reopened') throw httpErr(409, 'the question is ' + q.status);
    q.status = 'acknowledged'; q.ack_by = who.user; q.ack_at = now(); return save(q, who, 'acknowledged', ''); }
  function answer(id, text, who) { person(who, 'answer'); const q = get(id); canAnswer(q, who); if (q.status === 'closed') throw httpErr(409, 'the question is closed');
    q.status = 'answered'; q.answered_by = who.user; if (!q.answered_at) q.answered_at = now(); q.last_answer_at = now(); save(q, who, 'answer', s(text, 4000)); notify(q, 'answer'); return Q.get(id); }
  function followUp(id, text, who) { person(who, 'follow up'); const q = get(id); if (q.asked_by.toLowerCase() !== String(who.user).toLowerCase() && who.role !== 'admin') throw httpErr(403, 'only ' + q.asked_by + ' (who asked) or an administrator follows up');
    if (q.status === 'closed') throw httpErr(409, 'the question is closed - ask a new one'); q.status = 'reopened'; save(q, who, 'follow_up', s(text, 3000)); notify(q, 'follow_up'); return Q.get(id); }
  function close(id, note, who) { person(who, 'close'); const q = get(id); if (q.asked_by.toLowerCase() !== String(who.user).toLowerCase() && who.role !== 'admin') throw httpErr(403, 'only ' + q.asked_by + ' (who asked) or an administrator closes it');
    if (q.status === 'closed') throw httpErr(409, 'already closed'); q.status = 'closed'; q.closed_by = who.user; q.closed_at = now(); return save(q, who, 'closed', s(note, 1000)); }
  function putConfig(b, who) { person(who, 'change where questions go'); const cur = cfg(); if (b.baseVersion != null && b.baseVersion !== cur.version) throw httpErr(409, 'baseVersion: changed by someone else - reload');
    const next = { id: 'cfg', version: cur.version + 1, sla_h: Object.assign({}, cur.sla_h, b.sla_h || {}), teams: Object.assign({}, cur.teams, b.teams || {}), by: who.user, at: now() }; CFG.put(next); return { ok: true, version: next.version }; }
  return { TEAMS, issues, view, ask, ack, answer, followUp, close, putConfig, cfg, get };
}

module.exports = { createQuestions, TEAMS, jaccard, words };
