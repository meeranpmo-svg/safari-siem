// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Risk Officer - the enterprise-risk engineer of the AI team. It works ON the department's processes (the register, the Risk
 * Appetite Statement, the GRC actions) instead of waiting to be asked, and it never changes a record by itself.
 *
 * ON DUTY (duty-core.js adapter "riskofficer"): every patrol turns enterprise-risk work into work items, each with its evidence and
 * ONE proposed next step; an item closes only when the register no longer shows the problem.
 *   ras-unreported     a department has not reported its appetite metrics for the last closed period    -> reminder (drafted)
 *   ras-breach         a metric outside its appetite with no GRC action tracking it                       -> raise the action
 *   ras-warning        a metric forecast to leave its appetite (Holt, >= 50 % within 3 periods)          -> re-assess the linked risk
 *   risk-unwatched     an open Class III / IV risk no appetite metric watches                             -> link the best metric
 *   risk-kri           a risk whose linked metric is outside tolerance and was not re-assessed since      -> re-assess (owner)
 *   risk-stale         open risks of a department last assessed more than 12 months ago                  -> re-assess (owner)
 *   ras-limits         a metric whose limits are out of order / on mixed scales, a correction available  -> request the correction
 *   acceptance-stale   a Class III / IV acceptance waiting for a second administrator for over 7 days    -> escalate
 *
 * SUPERVISOR (a second layer, deterministic - not a second model): every proposal is checked when it is made and again when a
 * person decides it: the records it cites exist; the figures it states are still the register's figures; the methodology gives the
 * rating it claims; the step is on the allow-list and is not something a person already refused; it is not a duplicate. A proposal
 * that fails is HELD (not offered for approval) and escalated to the named owner; one with warnings is FLAGGED. Verdicts are stored.
 *
 * DECISIONS (a person, never a service or AI identity; operator+): approve applies the step through the module that owns it - a link
 * (Business Risk), a GRC action (GRC register), a limit change REQUEST (still needs a second administrator), a re-assessment action
 * for the owner, or a reminder drafted for a person to send. Reject needs a reason. Everything audited.
 *
 * LEARNS ON THE JOB: per kind, how often people approve its proposals (Beta(1,1) smoothed) ranks what it raises first; a kind people
 * keep rejecting (>= 5 decisions, < 30 %) is lowered one severity; the coverage-link threshold moves toward the scores people
 * approve and away from those they reject (bounded 0.35 - 0.70). Every adjustment is shown with the decisions it came from.
 *
 * GRADED ON OUTCOMES (scorecard, a snapshot a day): metrics reported for the last period; breaches with an action; breaches the
 * officer warned of before they happened; open risks a metric watches; open risks assessed within 12 months; proposals approved;
 * median days from proposal to decision - each against a target, with its trend.
 *
 * Routes ({P} = /api/itam):  GET /brisk/officer (viewer) - queue, verdicts, learning, scorecard
 *                            POST /brisk/officer/:id/decide (operator, a person) {decision: approve | reject, note}     audited
 */
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');

const DAY = 86400000;
const KINDS = ['ras-unreported', 'ras-breach', 'ras-warning', 'risk-unwatched', 'risk-kri', 'risk-stale', 'ras-limits', 'acceptance-stale'];
const STEPS = { 'ras-unreported': 'reminder', 'ras-breach': 'action', 'ras-warning': 'reassess', 'risk-unwatched': 'link', 'risk-kri': 'reassess', 'risk-stale': 'reassess', 'ras-limits': 'limits', 'acceptance-stale': 'escalate' };
const SEV = ['low', 'medium', 'high', 'critical'];
const TARGETS = { reported: 90, actioned: 100, caught_early: 50, watched: 80, current: 90, approval: 60 };
const ME = { user: 'ai:risk-officer', role: 'operator' };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').slice(0, n || 200);
const pct = (a, b) => (b ? Math.round(a / b * 1000) / 10 : null);
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

function createRiskOfficer(app, opts = {}) {
  const now = opts.now || Date.now, C = (n) => app.store.collection(n), PROP = () => C('ro_proposals'), LEARN = () => C('ro_learn'), SCORE = () => C('ro_scores'), WARN = () => C('ro_warnings');
  const BR = () => (app.addons && app.addons.businessRisk) || null, GR = () => (app.addons && app.addons.grcRegisters) || null;
  const iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'risk-officer.' + action, target, detail }); };
  const openActions = () => { const G = GR(); if (!G || !G.actionList) return null; try { const r = G.actionList({}); return (r.items || r || []).filter((a) => a.source === 'risk' && ['open', 'in_progress', 'awaiting_verification'].includes(a.status)); } catch (e) { return null; /* register unreadable: treated as unknown, never as "no action" */ } };

  // ---------- learning: per kind, approvals and rejections; the coverage-link threshold
  function learning() {
    const L = Object.fromEntries(KINDS.map((k) => [k, Object.assign({ kind: k, approved: 0, rejected: 0 }, LEARN().get(k) || {})]));
    for (const k of KINDS) { const x = L[k], n = x.approved + x.rejected; x.rate = Math.round((x.approved + 1) / (n + 2) * 100) / 100; x.decisions = n; x.lowered = n >= 5 && x.approved / n < 0.3;
      x.why = n ? x.approved + ' approved, ' + x.rejected + ' rejected' + (x.lowered ? ' - raised one severity lower until people approve more of them' : '') : 'no decision yet'; }
    const t = LEARN().get('link-threshold') || { id: 'link-threshold', value: 0.45, from: [] };
    return { kinds: L, link_threshold: { value: t.value, why: t.from.length ? 'moved by ' + t.from.length + ' decision(s) on suggested links: ' + t.from.slice(-5).map((f) => (f.d === 'approve' ? '+' : '-') + f.s).join(' ') : 'the starting threshold - no link decided yet' } };
  }
  function learn(p, decision) {
    const x = Object.assign({ id: p.kind, kind: p.kind, approved: 0, rejected: 0 }, LEARN().get(p.kind) || {}); x[decision === 'approve' ? 'approved' : 'rejected']++; LEARN().put(x);
    if (p.step === 'link' && typeof p.params.score === 'number') {
      const t = LEARN().get('link-threshold') || { id: 'link-threshold', value: 0.45, from: [] }, s = p.params.score;
      // approved: the threshold may come down toward that score; rejected: it goes above it
      t.value = Math.round(Math.max(0.35, Math.min(0.7, decision === 'approve' ? Math.min(t.value, (t.value + s) / 2) : Math.max(t.value, (t.value + s + 0.04) / 2))) * 100) / 100;
      t.from = (t.from || []).concat([{ d: decision, s: Math.round(s * 100) / 100, at: iso() }]).slice(-50); LEARN().put(t);
    }
  }
  const sevOf = (base, kind, L) => (L.kinds[kind] && L.kinds[kind].lowered ? SEV[Math.max(0, SEV.indexOf(base) - 1)] : base);

  // ---------- the patrol: what needs doing, each with its evidence and one proposed step
  async function current() {
    const X = BR(); if (!X) return null;   // Business Risk not loaded: nothing is created or closed
    const L = learning(), out = [], t = now();
    const M = X.rasAll().metrics, R = X.riskList().risks, acts = openActions(), actRefs = new Set((acts || []).map((a) => a.ref));
    const mk = (kind, key, sev, title, evidence, target, params) => out.push({ key: kind + ':' + key, severity: sevOf(sev, kind, L), kind, title: clip(title, 200), evidence: evidence.filter(Boolean).map((e) => clip(e, 300)),
      recommendation: RECO[kind], target, proposal: { step: STEPS[kind], params, rank: L.kinds[kind].rate } });
    // reporting
    const due = {}; for (const m of M) if (m.reporting === 'due') (due[m.responsibility || '(none)'] = due[m.responsibility || '(none)'] || []).push(m);
    for (const [d, ms] of Object.entries(due)) mk('ras-unreported', d, ms.length >= 5 ? 'high' : 'medium', d + ': ' + ms.length + ' appetite metric(s) not reported for ' + ms[0].due_period,
      ['due: ' + ms.slice(0, 12).map((m) => m.id).join(', ') + (ms.length > 12 ? ' …' : '')], { type: 'department', id: d, name: d }, { department: d, metrics: ms.map((m) => m.id), period: ms[0].due_period });
    // breaches without an action (unknown register = not raised: an unreadable register must not create work)
    for (const m of M) if (m.latest && m.latest.level >= 1 && acts && !actRefs.has(m.id + ':' + m.latest.period))
      mk('ras-breach', m.id + ':' + m.latest.period, m.latest.level >= 2 ? 'critical' : 'high', m.id + ' ' + m.component + ': ' + m.latest.zone.replace(/_/g, ' ') + ' in ' + m.latest.period + ', no GRC action tracks it',
        ['value ' + (m.latest.text || m.latest.value) + ' · ' + m.latest.zone, m.latest.note ? 'explanation: ' + m.latest.note : '', 'responsible: ' + (m.responsibility || '-')], { type: 'metric', id: m.id, name: m.component },
        { metric: m.id, period: m.latest.period, value: m.latest.value, level: m.latest.level });
    // early warnings: recorded (for the scorecard's "caught early"), then the linked risks re-assessed
    for (const m of M) if (m.early_warning) {
      const wid = m.id + ':' + m.due_period; if (!WARN().get(wid)) WARN().put({ id: wid, metric: m.id, period: m.due_period, p: m.early_warning.p, at: iso() });
      mk('ras-warning', m.id, m.early_warning.p >= 0.8 ? 'high' : 'medium', m.id + ' ' + m.component + ': ' + Math.round(m.early_warning.p * 100) + ' % chance of leaving the appetite within ' + m.early_warning.periods + ' period(s)',
        [m.early_warning.why, m.links.length ? 'linked risks: ' + m.links.join(', ') : 'no linked risk'], { type: 'metric', id: m.id, name: m.component }, { metric: m.id, risks: m.links, p: m.early_warning.p });
    }
    // coverage: an open Class III / IV risk no metric watches, with the best suggestion above the learned threshold
    let cov = null; try { cov = X.coverageView(); } catch (e) { cov = null; /* coverage unavailable this patrol: nothing raised for it */ }
    if (cov) for (const r of cov.risks) if (r.status !== 'solved' && r.residual >= 3 && r.state !== 'covered') {
      const s = r.suggestions.find((x) => x.score >= L.link_threshold.value);
      mk('risk-unwatched', r.id, r.residual >= 4 ? 'high' : 'medium', (r.code || r.id) + ' ' + r.title + ': ' + r.class + ', no appetite metric watches it',
        [s ? 'best match ' + s.metric + ' (' + s.component + ') score ' + s.score + (s.dept ? ', same department' : '') + (s.family ? ', same family' : '') + (s.words.length ? ', shared: ' + s.words.join(', ') : '') : 'no metric matches above ' + L.link_threshold.value + ' - a metric may be missing from the RAS'],
        { type: 'risk', id: r.id, name: r.code || r.id }, s ? { metric: s.metric, risk: r.id, score: s.score } : { risk: r.id });
    }
    // risks: KRI outside tolerance not re-assessed; stale per department; acceptances waiting
    const stale = {};
    for (const r of R) {
      if (r.status === 'solved') continue;
      const f = (c) => r.flags.find((x) => x.code === c);
      if (f('kri_breach')) mk('risk-kri', r.id, 'high', (r.code || r.id) + ' ' + r.title + ': ' + f('kri_breach').text, ['owner: ' + (r.owner || 'none'), 'rated ' + (r.label || '-') + ' / ' + (r.class || '-')], { type: 'risk', id: r.id, name: r.code || r.id }, { risk: r.id, owner: r.owner, inherent: r.inherent });
      if (f('stale')) (stale[r.department || '(none)'] = stale[r.department || '(none)'] || []).push(r);
      if (r.acceptance && r.acceptance.status === 'pending' && t - Date.parse(r.acceptance.at) > 7 * DAY) mk('acceptance-stale', r.id, 'medium', (r.code || r.id) + ': acceptance of a ' + r.acceptance.class + ' risk waiting since ' + String(r.acceptance.at).slice(0, 10),
        ['requested by ' + r.acceptance.by], { type: 'risk', id: r.id, name: r.code || r.id }, { risk: r.id, requested_by: r.acceptance.by });
    }
    for (const [d, rs] of Object.entries(stale)) mk('risk-stale', d, rs.length >= 5 ? 'high' : 'medium', d + ': ' + rs.length + ' open risk(s) last assessed more than 12 months ago',
      [rs.slice(0, 10).map((r) => r.code || r.id).join(', ')], { type: 'department', id: d, name: d }, { department: d, risks: rs.map((r) => r.id), owners: [...new Set(rs.map((r) => r.owner).filter(Boolean))] });
    // limits a correction is ready for
    let lim = null; try { lim = X.limitsView(); } catch (e) { lim = null; /* limit proposals unavailable this patrol */ }
    if (lim) for (const p of lim.proposals.filter((x) => x.basis === 'correction')) mk('ras-limits', p.id, 'medium', p.id + ' ' + p.component + ': limits ' + p.why.join('; '), [p.why.join(' · ')], { type: 'metric', id: p.id, name: p.component }, { metric: p.id, raw: p.proposed, basis: p.basis });
    snapshot();
    return out;
  }
  const RECO = { 'ras-unreported': 'Remind the department to report its values for the period (a reminder is drafted for a person to send).',
    'ras-breach': 'Raise a GRC action owned by the responsible department so the breach is tracked to closure.',
    'ras-warning': 'Ask the owners of the linked risks to re-assess them before the metric leaves its appetite.',
    'risk-unwatched': 'Link the best-matching appetite metric so the risk is monitored (or add a metric to the RAS).',
    'risk-kri': 'Ask the risk owner to re-assess the risk: its key risk indicator is outside tolerance.',
    'risk-stale': 'Ask the owners to re-assess the risks; the methodology expects at least yearly.',
    'ras-limits': 'Request the corrected limits; a second administrator approves the change.',
    'acceptance-stale': 'Escalate the waiting acceptance to a second administrator.' };

  // ---------- supervisor: the facts behind a proposal, checked against the register now
  function supervise(p) {
    const X = BR(), checks = [], add = (name, ok, detail, hard) => checks.push({ name, ok, detail, hard: !!hard });
    if (!X) return { verdict: 'held', checks: [{ name: 'source', ok: false, detail: 'Business Risk is not loaded', hard: true }] };
    add('step allowed', Object.values(STEPS).includes(p.step), 'the step "' + p.step + '" is ' + (Object.values(STEPS).includes(p.step) ? '' : 'not ') + 'on the allow-list', true);
    const M = new Map(X.rasAll().metrics.map((m) => [m.id, m])), R = new Map(X.riskList().risks.map((r) => [r.id, r])), pr = p.params || {};
    if (pr.metric) add('metric exists', M.has(pr.metric), pr.metric + (M.has(pr.metric) ? ' is in the RAS' : ' is not in the RAS'), true);
    if (pr.risk) add('risk exists', R.has(pr.risk), pr.risk + (R.has(pr.risk) ? ' is in the register' : ' is not in the register'), true);
    for (const r of pr.risks || []) if (!R.has(r)) add('risk exists', false, r + ' is not in the register', true);
    const m = pr.metric && M.get(pr.metric), r = pr.risk && R.get(pr.risk);
    if (p.step === 'action' && m) { const same = m.latest && m.latest.period === pr.period && m.latest.level === pr.level;
      add('figures current', same, same ? m.id + ' is still ' + m.latest.zone.replace(/_/g, ' ') + ' in ' + pr.period : m.id + ' changed since the proposal (now ' + (m.latest ? m.latest.zone + ' in ' + m.latest.period : 'not reported') + ')', true);
      const acts = openActions(); add('not a duplicate', !!acts && !acts.some((a) => a.ref === pr.metric + ':' + pr.period), acts ? 'no open action tracks ' + pr.metric + ':' + pr.period : 'the GRC register could not be read', true); }
    if (p.step === 'link' && m && r) { add('not refused before', !(m.rejected || []).includes(r.id), (m.rejected || []).includes(r.id) ? 'a person rejected this pair before' : 'not rejected before', true);
      add('not already linked', !(m.links || []).includes(r.id), (m.links || []).includes(r.id) ? 'already linked' : 'not yet linked', true);
      add('evidence strong enough', pr.score >= 0.35, 'match score ' + pr.score, false); }
    if (p.step === 'link' && !pr.metric) add('a metric to link', false, 'no metric matches - a person decides whether the RAS needs one', true);
    if ((p.step === 'reassess') && r) { const rt = X.rate(r.likelihood, r.impact, r.exposure); add('methodology', rt.inherent === r.inherent, 'likelihood ' + r.likelihood + ' x impact ' + r.impact + ' = ' + rt.inherent + (rt.inherent === r.inherent ? ', as recorded' : ', the record says ' + r.inherent), false);
      add('owner named', !!r.owner, r.owner ? 'owner ' + r.owner : 'no owner - the action has no one to go to', false); }
    if (p.step === 'reassess' && (pr.risks || []).length === 0 && !pr.risk) add('who to ask', false, 'no linked or named risk to re-assess', false);
    if (p.step === 'limits' && m) add('still needed', (m.issues || []).length > 0 && !(m.limit_change && m.limit_change.status === 'pending'), (m.issues || []).length ? (m.limit_change && m.limit_change.status === 'pending' ? 'a change already waits for approval' : 'the limits still have: ' + m.issues.join('; ')) : 'the limits no longer have an issue', true);
    if (p.step === 'reminder') { const still = (pr.metrics || []).filter((id) => M.get(id) && M.get(id).reporting === 'due'); add('still due', still.length > 0, still.length + ' of ' + (pr.metrics || []).length + ' metric(s) still due', true); }
    const hard = checks.some((c) => !c.ok && c.hard), soft = checks.some((c) => !c.ok && !c.hard);
    return { verdict: hard ? 'held' : soft ? 'flagged' : 'passed', checks, at: iso() };
  }

  // ---------- proposals: one per work item, supervised; held ones go to the named owner, never to the approve button
  function ownerOf(it) { const p = it.proposal.params || {}; const X = BR(); if (!X) return null;
    if (p.risk) { const r = X.riskList().risks.find((x) => x.id === p.risk); return r && r.owner || null; }
    if (p.metric) { const m = X.rasAll().metrics.find((x) => x.id === p.metric); return m && m.responsibility || null; }
    return p.department || null; }
  async function propose(it) {
    if (!it.proposal) return { note: 'nothing to propose' };
    const id = 'RO-' + String(it.key).replace(/[^A-Za-z0-9.:-]/g, '_').slice(0, 77), cur = PROP().get(id);
    if (cur && cur.status === 'proposed') return { note: 'already proposed (' + id + ')' };
    const p = { id, item: it.id, key: it.key, kind: it.kind, severity: it.severity, title: it.title, evidence: it.evidence, step: it.proposal.step, params: it.proposal.params, rank: it.proposal.rank, status: 'proposed', by: ME.user, at: iso() };
    p.supervisor = supervise(p);
    if (p.supervisor.verdict === 'held') { p.status = 'held'; p.escalated_to = ownerOf(it) || 'the Head of Risk Management'; }
    PROP().put(p); audit(ME, 'propose', id, { step: p.step, verdict: p.supervisor.verdict, escalated_to: p.escalated_to });
    return { note: p.status === 'held' ? 'held by the supervisor (' + p.supervisor.checks.filter((c) => !c.ok).map((c) => c.detail).join('; ') + ') - escalated to ' + p.escalated_to : 'proposed: ' + p.step + ' - waiting for a person (' + p.supervisor.verdict + ')' };
  }
  async function decide(id, input, who) {
    if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot decide a proposal: a person does');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required to reject: say why' : null)).done();
    const p = PROP().get(id); if (!p) throw httpErr(404, 'no proposal ' + id);
    if (p.status !== 'proposed') throw httpErr(409, id + ' is ' + p.status + (p.status === 'held' ? ' by the supervisor - it cannot be approved' : ''));
    let result = null;
    if (b.decision === 'approve') {
      const sv = supervise(p); p.supervisor = sv;
      if (sv.verdict === 'held') { p.status = 'held'; PROP().put(p); audit(who, 'held', id, { checks: sv.checks.filter((c) => !c.ok).map((c) => c.name) }); throw httpErr(409, 'the supervisor holds it now: ' + sv.checks.filter((c) => !c.ok).map((c) => c.detail).join('; ')); }
      result = await apply(p, who, b.note);
    }
    Object.assign(p, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '', result });
    PROP().put(p); learn(p, b.decision);
    audit(who, b.decision, id, { step: p.step, kind: p.kind, result });
    return p;
  }
  async function apply(p, who, note) {
    const X = BR(), G = GR(), pr = p.params;
    if (p.step === 'link') { X.linkBulk({ pairs: [{ metric: pr.metric, risk: pr.risk }] }, who); return { linked: pr.metric + ' > ' + pr.risk }; }
    if (p.step === 'action') { const r = X.raiseAction(pr.metric, { period: pr.period }, who); return { action: r.action }; }
    if (p.step === 'limits') { X.limitRequest(pr.metric, { raw: pr.raw, note: note || 'proposed by the AI Risk Officer: ' + p.title, basis: pr.basis }, who); return { limit_request: pr.metric, waits_for: 'a second administrator' }; }
    if (p.step === 'reminder') { const subject = 'RAS reporting due ' + pr.period + ' - ' + pr.department, txt = 'Please report these risk appetite metrics for ' + pr.period + ':\n' + pr.metrics.join('\n');
      return { mailto: 'mailto:?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(txt), sent_by: 'the approver sends it' }; }
    if (p.step === 'reassess' || p.step === 'escalate') {
      if (!G || !G.actionCreate) throw httpErr(424, 'the GRC register is not installed - ask the owner directly');
      const risks = pr.risks || (pr.risk ? [pr.risk] : []), owner = pr.owner || (pr.owners && pr.owners[0]) || '';
      const a = G.actionCreate({ title: clip((p.step === 'escalate' ? 'Decide the waiting risk acceptance: ' : 'Re-assess: ') + p.title, 200), source: 'risk', ref: 'officer:' + p.id, owner, priority: SEV.indexOf(p.severity) >= 2 ? 'high' : 'medium',
        description: clip('Proposed by the AI Risk Officer, approved by ' + who.user + '. ' + (RECO[p.kind] || '') + ' Risks: ' + risks.join(', ') + '. Evidence: ' + p.evidence.join(' | '), 4000) }, who);
      return { action: a.id };
    }
    throw httpErr(400, 'step ' + p.step + ' is not allowed');
  }

  // ---------- graded on outcomes
  function scorecard() {
    const X = BR(); if (!X) return null;
    const M = X.rasAll().metrics, R = X.riskList().risks.filter((r) => r.status !== 'solved'), acts = openActions(), allActs = (() => { const G = GR(); try { return G && G.actionList ? (G.actionList({}).items || []) : []; } catch (e) { return []; /* unreadable: no action counted */ } })();
    const lim = M.filter((m) => m.reporting !== 'no_limits'), breaches = M.filter((m) => m.latest && m.latest.level >= 1);
    const refs = new Set(allActs.filter((a) => a.source === 'risk').map((a) => a.ref)), actioned = breaches.filter((m) => refs.has(m.id + ':' + m.latest.period));
    // caught early: a metric that breached in period p and had an officer warning recorded for an earlier period
    const W = WARN().all(), early = breaches.filter((m) => W.some((w) => w.metric === m.id && w.period < m.latest.period));
    let cov = null; try { cov = X.coverageView().summary; } catch (e) { cov = null; /* coverage unavailable: shown as not measured */ }
    const current = R.filter((r) => !r.flags.some((f) => f.code === 'stale'));
    const P = PROP().all(), dec = P.filter((p) => p.status === 'approved' || p.status === 'rejected'), days = dec.map((p) => (Date.parse(p.decided_at) - Date.parse(p.at)) / DAY);
    const m = (key, label, value, target, why) => ({ key, label, value, target, met: value == null ? null : value >= target, why });
    return [
      m('reported', 'Appetite metrics reported for the last period', pct(lim.filter((x) => x.reporting === 'reported').length, lim.length), TARGETS.reported, lim.filter((x) => x.reporting === 'reported').length + ' of ' + lim.length),
      m('actioned', 'Breaches tracked by a GRC action', breaches.length ? pct(actioned.length, breaches.length) : null, TARGETS.actioned, breaches.length ? actioned.length + ' of ' + breaches.length + ' breach(es)' : 'no breach'),
      m('caught_early', 'Breaches the officer warned of beforehand', breaches.length ? pct(early.length, breaches.length) : null, TARGETS.caught_early, breaches.length ? early.length + ' of ' + breaches.length : 'no breach'),
      m('watched', 'Open risks a metric watches', cov ? pct(cov.covered, cov.open) : null, TARGETS.watched, cov ? cov.covered + ' of ' + cov.open : 'coverage not available'),
      m('current', 'Open risks assessed within 12 months', R.length ? pct(current.length, R.length) : null, TARGETS.current, current.length + ' of ' + R.length),
      m('approval', 'Officer proposals people approved', dec.length ? pct(dec.filter((p) => p.status === 'approved').length, dec.length) : null, TARGETS.approval, dec.length + ' decided'),
      Object.assign(m('decision_days', 'Median days from proposal to decision', median(days) == null ? null : Math.round(median(days) * 10) / 10, 0, dec.length + ' decided'), { met: null, lower_is_better: true }),
    ].map((x) => Object.assign(x, { history: SCORE().all().sort((a, b) => a.id.localeCompare(b.id)).slice(-30).map((s) => ({ date: s.id, value: s.values[x.key] })).filter((h) => h.value != null) }));
  }
  let lastSnap = null;
  function snapshot() { const d = today(); if (lastSnap === d || SCORE().get(d)) { lastSnap = d; return; } const S = scorecard(); if (!S) return; SCORE().put({ id: d, values: Object.fromEntries(S.map((x) => [x.key, x.value])) }); lastSnap = d; }

  function view() {
    const P = PROP().all().sort((a, b) => (a.status === b.status ? SEV.indexOf(b.severity) - SEV.indexOf(a.severity) || (b.rank || 0) - (a.rank || 0) : a.status === 'proposed' ? -1 : b.status === 'proposed' ? 1 : a.status === 'held' ? -1 : 1));
    return { generated_at: iso(), queue: P.filter((p) => p.status === 'proposed').slice(0, 100), held: P.filter((p) => p.status === 'held').slice(0, 50), decided: P.filter((p) => p.status === 'approved' || p.status === 'rejected').sort((a, b) => String(b.decided_at).localeCompare(String(a.decided_at))).slice(0, 30),
      learning: learning(), scorecard: scorecard(), loaded: !!BR(),
      how: 'The officer proposes; a person decides. Every proposal is checked by the supervisor when it is made and again when it is decided; a held one cannot be approved and goes to its owner.' };
  }

  const adapter = {
    id: 'riskofficer', name: 'AI Risk Officer',
    findings: current,
    investigate(it) { return { summary: it.title + '. ' + (it.recommendation || ''), checks: (it.evidence || []).map((e) => ({ name: 'evidence', status: 'warn', detail: e })), causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] }; },
    propose,
    async verify(it) { const f = await current(); const present = !!f && f.some((x) => x.key === it.key); return { present, note: present ? 'the register still shows it' : 'the register no longer shows it' }; },
  };
  // a daily snapshot even on a day the duty desk does not patrol (guarded; the duty patrol also takes it)
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'risk-officer.snapshot', async () => snapshot()), 6 * 3600000); if (tm.unref) tm.unref(); }
  return { adapter, view, decide, supervise, scorecard, learning, current, propose };
}

function registerRiskOfficer(srv, app, O) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  srv.route('GET', '/brisk/officer', (ctx) => { ctx.need('viewer'); return O.view(); });
  srv.route('POST', '/brisk/officer/:id/decide', (ctx) => { ctx.need('operator'); return O.decide(param(ctx.params.id, 'id'), ctx.body, W(ctx)); }, { maxBody: 4096 });
}

module.exports = { createRiskOfficer, registerRiskOfficer, KINDS, STEPS, TARGETS };
