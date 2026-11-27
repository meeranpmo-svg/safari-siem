// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const OFF = new Set(ZYB_ORG.modules_off || []);
/*
 * The auditor's dashboard ({P} = /api/itam): every regulatory framework and every audit team on one page, so an internal or
 * external auditor sees where the organisation stands and goes straight to the evidence. It writes nothing and decides nothing:
 * it reads what the modules already hold, each source on its own (a module that is not installed, or that fails, shows as
 * "not available" with the reason - the others still show):
 *   PDPL           the AI PDPL Consultant's 24 requirements and the approved self-assessment (engine/pdpl.js, pdpl-assessment.js)
 *   NCA ECC        the verification register (engine/nca-ecc.js)
 *   ISO 27001      the ISMS register and readiness (engine/iso27001.js)
 *   NDMO           the data management register and maturity (engine/ndmo.js)
 *   SAMA CSF / IA  the audit checklists and their evidence requests (PBC list) (engine/audit-checklist.js)
 *   AI auditors    the IT and cyber security audit programmes (engine/auditors.js)
 *   audit teams    Internal, IT and Cyber Security Audit Teams: plans, engagements, open and overdue findings (engine/audit-engage.js)
 *   control monitoring  the latest daily run over the audit trail and its open exceptions (engine/audit-ccm.js)
 *   PDPL deadlines requests and breaches at risk of missing their legal deadline (engine/pdpl-intel.js)
 * A framework nobody has assessed reads "not assessed" - never 0 % and never compliant. Scores are each module's own,
 * indicative figures, not a regulator's assessment, and the page says so.
 *
 * Insight (ML, all explainable - every number says where it came from):
 *   assurance index  the mean score of the assessed frameworks, less itemised points for overdue findings, overdue evidence requests,
 *                    open control-monitoring exceptions, PDPL deadlines at risk and frameworks nobody has assessed; withheld until two
 *                    frameworks are assessed (an empty platform must not read 100)
 *   history          one snapshot a day (index, every framework's score, the counts); movement against 30 days ago, regressions
 *                    (a framework down 5 points or more), least-squares pace and a projection to 80 % from 3 snapshots - a
 *                    projection from past pace, not a promise
 *   priority         the attention list ranked by severity, how long it has been overdue (log scale) and a regulatory clock
 *                    (PDPL 72 hours / 30 days), each point itemised
 *   delivery         per audit team, the share of open findings still on track (Beta(1,1): 50 % with nothing open, never 0 / 100)
 *   analytics        the Audit Analytics command log: runs, exceptions not dispositioned, runs awaiting a second person's review
 *   advisor          the read-only AI audit advisor (intel kit: ai-guard budget, redactSecrets, untrusted tool output)
 *
 *   GET  /audit-dashboard           operator  the dashboard (names people and weaknesses: viewers refused, PDPL)
 *   GET  /audit-dashboard/export    operator  the same as CSV (frameworks, attention list, audit teams)          audited
 *   GET  /audit-dashboard/ai/status operator  · POST /audit-dashboard/ask {question} operator  the advisor (kit, audited)
 */
const { createIntelKit, trend, beta } = require('./intel-kit');
const DAY = 86400000;
const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
const s = (v, n = 200) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);

function createAuditDashboard(app, opts = {}) {
  const now = opts.now || Date.now, A = () => app.addons || {};
  const iso = () => new Date(now()).toISOString();
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('auditdash:' + key, 3600000, 'warn', msg, { err: s((err && err.message) || err, 200) }); };
  // one source: its section, or {available:false, reason} - the reason is logged once an hour, never thrown
  async function source(key, fn) {
    try { const v = await fn(); return v || { available: false, reason: 'not installed - run the update' }; }
    catch (e) { warn(key, 'audit dashboard: ' + key + ' could not be read', e); return { available: false, reason: 'could not be read: ' + s(e.message, 160) }; }
  }

  async function pdpl() {
    const P = A().pdpl; if (!P) return null;
    const a = await P.assess(), c = a.counts || {}, assessed = (c.compliant || 0) + (c.partial || 0) + (c.non_compliant || 0) + (c.not_applicable || 0);
    let sa = null; try { sa = A().pdplAssessment ? (await A().pdplAssessment.summary()).approved : null; } catch (e) { warn('pdpl-sa', 'audit dashboard: the PDPL self-assessment summary could not be read', e); }
    const gaps = a.requirements.filter((r) => r.result === 'non_compliant' || r.result === 'partial');
    return { available: true, id: 'pdpl', name: 'PDPL (SDAIA)', page: 'pdpl-dashboard.html', owner: (a.readiness && a.readiness.dpo_user) ? 'DPO ' + a.readiness.dpo_user : 'no DPO named',
      score: assessed ? a.compliance_pct : null, status: assessed ? (c.non_compliant ? 'gaps' : c.partial ? 'partial' : 'compliant') : 'not_assessed',
      counts: { requirements: a.requirements.length, compliant: c.compliant || 0, partial: c.partial || 0, gaps: c.non_compliant || 0, not_assessed: c.not_assessed || 0, auto_pass: c.auto_pass || 0 },
      extra: (() => { const L = require('./compliance-levels').levels(a.requirements, require('./pdpl').PDPL_LEVEL); return (L.applicable ? 'fully compliant ' + L.pct.fully + '%, partially ' + L.pct.partially + '%, not compliant ' + L.pct.not + '%, not assessed ' + L.pct.not_assessed + '%; ' : '') + (sa ? 'self-assessment ' + sa.cycle + ': ' + sa.score + '% approved by ' + sa.approved_by : 'no approved self-assessment'); })(),
      top: gaps.slice(0, 8).map((r) => ({ id: r.id, title: r.title, ref: r.ref, result: r.result, why: s(r.why, 240) })) };
  }
  async function ecc() {
    const N = A().ncaEcc; if (!N) return null;
    const v = await N.view(), c = v.counts || {}, verified = (c.verified || 0) + (c.met || 0) + (c.gap || 0) + (c.partial || 0);
    const gaps = v.controls.filter((x) => x.result === 'gap' || x.result === 'partial').sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
    return { available: true, id: 'nca-ecc', name: 'NCA ECC-1:2018', page: 'nca-ecc.html', owner: v.profile && v.profile.ciso_user ? 'CISO ' + v.profile.ciso_user : 'no CISO named',
      score: verified ? v.score : null, status: verified ? (c.gap ? 'gaps' : 'partial') : 'not_assessed',
      counts: { controls: v.controls.length, verified: (c.verified || 0) + (c.met || 0), gaps: c.gap || 0, partial: c.partial || 0, not_measured: c.not_measured || 0, no_evidence: c.no_evidence || 0 },
      extra: v.nca && v.nca.applicable ? 'NCA: fully compliant ' + v.nca.pct.fully + '%, partially ' + v.nca.pct.partially + '%, not compliant ' + v.nca.pct.not + '%, not assessed ' + v.nca.pct.not_assessed + '%; ' + v.subdomains.filter((x) => x.nca && x.nca.status === 'fully_compliant').length + ' of ' + v.subdomains.length + ' subdomains fully compliant' : '',
      nca: v.nca || null,
      top: gaps.slice(0, 8).map((x) => ({ id: x.id, title: x.title, ref: x.subdomain + ' ' + x.subdomain_name, result: x.result, why: s(x.why, 240), severity: x.severity })) };
  }
  async function iso27001() {
    const I = A().iso27001; if (!I) return null;
    const v = await I.view(), c = v.counts || {}, rows = v.clauses.concat(v.annex), assessed = (c.verified || 0) + (c.met || 0) + (c.gap || 0) + (c.partial || 0);
    const gaps = rows.filter((x) => x.result === 'gap' || x.result === 'partial').sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
    const rd = v.readiness;
    return { available: true, id: 'iso27001', name: 'ISO/IEC 27001:2022', page: 'iso27001.html', owner: v.profile && v.profile.isms_manager ? 'ISMS manager ' + v.profile.isms_manager : 'no ISMS manager named',
      score: assessed ? v.score : null, status: assessed ? (c.gap ? 'gaps' : 'partial') : 'not_assessed',
      counts: { controls: rows.length, verified: (c.verified || 0) + (c.met || 0), gaps: c.gap || 0, partial: c.partial || 0, not_measured: c.not_measured || 0, no_evidence: c.no_evidence || 0 },
      extra: 'readiness ' + rd.stage.replace('_', ' ') + '; Annex A ' + rd.annex_implemented + ' of ' + rd.annex_applicable + ' implemented; ' + (v.via_ecc || 0) + ' counted from NCA ECC',
      top: gaps.slice(0, 8).map((x) => ({ id: x.id, title: x.title, ref: x.group_name, result: x.result, why: s(x.why, 240), severity: x.severity })) };
  }
  async function ndmo() {
    const N = A().ndmo; if (!N) return null;
    const v = await N.view(), c = v.counts || {}, assessed = (c.met || 0) + (c.gap || 0) + (c.partial || 0) + (c.auto_pass || 0) + (c.verified || 0);
    const gaps = v.controls.filter((x) => x.result === 'gap' || x.result === 'partial').sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
    return { available: true, id: 'ndmo', name: 'NDMO data management', page: 'ndmo.html', owner: v.profile && v.profile.cdo_user ? 'CDO ' + v.profile.cdo_user : 'no Chief Data Officer named',
      score: assessed ? v.score : null, status: assessed ? (c.gap ? 'gaps' : 'partial') : 'not_assessed',
      counts: { controls: v.controls.length, met: (c.met || 0) + (c.auto_pass || 0), gaps: c.gap || 0, partial: c.partial || 0, no_evidence: c.no_evidence || 0 },
      extra: (v.levels && v.levels.applicable ? 'fully compliant ' + v.levels.pct.fully + '%, partially ' + v.levels.pct.partially + '%, not compliant ' + v.levels.pct.not + '%, not assessed ' + v.levels.pct.not_assessed + '%; ' : '') + (v.maturity || []).filter((m) => m.level !== null && m.level !== undefined).length + ' of 15 domains with a maturity level',
      top: gaps.slice(0, 8).map((x) => ({ id: x.id, title: x.title, ref: x.domain + ' ' + x.domain_name, result: x.result, why: s(x.why, 240), severity: x.severity })) };
  }
  // Saudi Aramco CCC (engine/aramco-ccc.js): the imported SACS-002 controls that apply to the active Aramco contracts, the
  // self-assessment, the audit firm's findings and the certificate dates
  async function aramco() {
    const X = A().aramcoCcc; if (!X) return null;
    const v = X.view({ user: 'system:audit-dashboard', role: 'viewer' }), st = (c) => c.status || 'not-assessed';
    const rows = v.controls || [], gaps = rows.filter((c) => st(c) === 'not-implemented' || st(c) === 'partial');
    const cert = v.certificate ? 'certificate ' + (v.certificate.number || '') + ' expires ' + String(v.certificate.expires || '').slice(0, 10) + (v.days_left !== null && v.days_left !== undefined ? ' (' + v.days_left + ' days)' : '') : 'no certificate recorded';
    return { available: true, id: 'aramco', name: 'Saudi Aramco CCC (SACS-002)', page: 'aramco-ccc.html', owner: v.profile && v.profile.ccc_owner ? 'CCC owner ' + v.profile.ccc_owner : 'no CCC owner named',
      score: v.assessed ? v.score : null, status: !rows.length ? 'not_assessed' : v.assessed ? (gaps.length ? 'gaps' : 'partial') : 'not_assessed',
      counts: { controls: rows.length, met: rows.filter((c) => st(c) === 'implemented').length, gaps: rows.filter((c) => st(c) === 'not-implemented').length, partial: rows.filter((c) => st(c) === 'partial').length, not_assessed: rows.filter((c) => st(c) === 'not-assessed').length },
      extra: (rows.length ? v.applicable + ' of ' + v.controls_total + ' imported control(s) apply; ' : 'no control list imported - import your copy of SACS-002; ') + cert + (v.overdue ? '; ' + v.overdue + ' action(s) overdue' : '') + ((v.findings || []).filter((f) => f.status !== 'closed').length ? '; ' + (v.findings || []).filter((f) => f.status !== 'closed').length + ' open audit finding(s)' : ''),
      top: gaps.slice(0, 8).map((x) => ({ id: x.id, title: x.title, ref: x.domain || '', result: st(x) === 'partial' ? 'partial' : 'gap', why: s(x.requirement || '', 240), severity: 'high' })) };
  }
  function checklist(fw, name) {
    return async () => {
      const C = A().auditChecklist; if (!C) return null;
      const v = C.view(fw, true), c = v.counts || {}, r = C.requests(fw), assessed = (c.compliant || 0) + (c.partial || 0) + (c.non_compliant || 0) + (c.not_applicable || 0);
      const bad = v.checks.filter((x) => x.result === 'non_compliant' || x.result === 'partial');
      return { available: true, id: fw === 'sama' ? 'sama' : 'ia', name, page: 'ai-auditors.html', owner: 'the compliance team confirms each check',
        score: assessed ? v.compliance_pct : null, status: assessed ? (c.non_compliant ? 'gaps' : c.partial ? 'partial' : 'compliant') : 'not_assessed',
        counts: { checks: v.checks.length, compliant: c.compliant || 0, partial: c.partial || 0, gaps: c.non_compliant || 0, not_assessed: c.not_assessed || 0, auto_pass: c.auto_pass || 0 },
        extra: 'evidence requests: ' + (r.by_state.issued || 0) + ' issued, ' + (r.by_state.provided || 0) + ' provided, ' + (r.by_state.accepted || 0) + ' accepted, ' + (r.by_state.overdue || 0) + ' overdue',
        pbc: { by_state: r.by_state, overdue: r.items.filter((x) => x.overdue).slice(0, 10).map((x) => ({ ref: x.ref, title: x.title, owner: x.owner_name, due: x.due, days_overdue: x.days_overdue })) },
        top: bad.slice(0, 8).map((x) => ({ id: x.id, title: x.title, ref: x.owner_name, result: x.result, why: s(x.why, 240) })) };
    };
  }
  async function programmes() {
    const AU = A().auditors; if (!AU) return null;
    return { available: true, list: ['itaudit', 'cyberaudit'].map((id) => { const p = AU.programme(id);
      return { id, name: p.name, last_run: p.last_run, counts: p.counts, pass_pct: p.pass_pct, failing: p.tests.filter((t) => t.state === 'fail').slice(0, 10).map((t) => ({ id: t.id, title: t.title, owner: t.owner_name, detail: s(t.detail, 200) })) }; }) };
  }
  async function teams() {
    const list = [['internalAuditEngage', 'Internal Audit Team', 'internal-audit-team.html'], ['auditEngage', 'IT Audit Team', 'audit-team.html'], ['cyberAuditEngage', 'Cyber Security Audit Team', 'cyber-audit-team.html']]
      .map(([k, name, page]) => [A()[k], name, page]).filter((x) => x[0]);
    if (!list.length) return null;
    const year = iso().slice(0, 4);
    return { available: true, list: list.map(([T, name, page]) => {
      const pr = T.profile(), plan = T.plans().find((p) => p.year === Number(year)), e = T.listEngagements(), f = T.listFindings();
      const open = f.filter((x) => ['issued', 'responded', 'implemented'].includes(x.state));
      return { id: T.kind, name, page, head_of_audit: pr.head_of_audit || null, plan: plan ? { id: plan.id, state: plan.state, engagements: plan.items.filter((i) => i.include).length } : null,
        engagements: { planning: e.filter((x) => x.state === 'planning').length, fieldwork: e.filter((x) => x.state === 'fieldwork').length, draft_report: e.filter((x) => x.state === 'draft_report').length, final: e.filter((x) => x.state === 'final').length },
        findings: { open: open.length, high: open.filter((x) => x.rating === 'high').length, overdue: open.filter((x) => x.overdue).length, risk_accepted: f.filter((x) => x.state === 'risk_accepted').length, closed: f.filter((x) => x.state === 'closed').length },
        overdue: open.filter((x) => x.overdue).slice(0, 10).map((x) => ({ id: x.id, title: x.title, rating: x.rating, owner: x.owner, due: x.due })) };
    }) };
  }

  // the department framework checklist: how each department keeps up its periodic obligations
  async function departments() {
    const D = A().deptChecklist; if (!D) return null;
    const x = D.attention();
    return { available: true, overall: x.overall, counts: x.counts, items: x.items,
      list: x.departments.map((d) => ({ key: d.key, name: d.name, head: d.head || null, status: d.status, pct: d.pct, counts: d.counts, applicable: d.applicable, overdue: d.overdue, awaiting_review: d.awaiting_review, exceptions: d.exceptions })) };
  }

  // continuous control monitoring (engine/audit-ccm.js): the latest daily run over the whole audit trail
  async function ccm() {
    const C = A().auditCcm; if (!C) return null;
    const x = C.summary();
    if (!x) return { available: true, run: null, tests: [], open: [], note: 'the control tests have not run yet - they run each day, or from Control Monitoring' };
    return Object.assign({ available: true, page: 'audit-ccm.html' }, x, { open_total: x.open.length, open: x.open.slice(0, 10).map((o) => ({ id: o.id, test: o.test, name: o.name, by: o.by, why: s(o.why, 240), score: o.score })) });
  }
  // PDPL deadlines (engine/pdpl-intel.js): requests and breaches at risk of missing their legal deadline
  async function deadlines() {
    const I = A().pdplIntel; if (!I) return null;
    const ds = I.dsarRisk().filter((x) => x.risk === 'high' || x.risk === 'breached'), br = I.breachRisk().filter((x) => x.risk !== 'low');
    return { available: true, page: 'pdpl-intel.html', dsar: ds.slice(0, 10).map((x) => ({ id: x.id, ref: x.ref, type: x.type, due: x.due, days_left: x.days_left, risk: x.risk, p_on_time: x.p_on_time, method: x.method })),
      breaches: br.slice(0, 10).map((x) => ({ id: x.id, ref: x.ref, deadline: x.deadline, hours_left: x.hours_left, risk: x.risk })), counts: { dsar_at_risk: ds.length, breaches_at_risk: br.length } };
  }

  async function view() {
    const [cc, dl] = await Promise.all([source('ccm', ccm), source('deadlines', deadlines)]);
    const [p, e, n, sa, ia, pg, tm, dp, io] = await Promise.all([source('pdpl', pdpl), source('nca-ecc', ecc), source('ndmo', ndmo),
      source('sama', checklist('sama', 'SAMA Cyber Security Framework')), source('ia', checklist('ia', 'Insurance Authority (IA)')), source('programmes', programmes), source('teams', teams), source('departments', departments), source('iso27001', iso27001)]);
    const ac = await source('aramco', aramco);
    const frameworks = [['pdpl', 'PDPL (SDAIA)', p], ['nca-ecc', 'NCA ECC-1:2018', e], ['ndmo', 'NDMO data management', n], ['sama', 'SAMA Cyber Security Framework', sa], ['ia', 'Insurance Authority (IA)', ia], ['iso27001', 'ISO/IEC 27001:2022', io], ['aramco', 'Saudi Aramco CCC (SACS-002)', ac]]
      // a framework the organisation is not under (its module switched off in the brand setting) is not listed at all
      .filter(([id]) => (app.config && app.config.audit_dashboard && app.config.audit_dashboard.all_frameworks) || !((id === 'sama' && OFF.has('fw-sama')) || (id === 'ia' && OFF.has('fw-ia')) || (id === 'aramco' && OFF.has('fw-aramco'))))
      .map(([id, name, x]) => (x.available ? x : { available: false, id, name, reason: x.reason, status: 'not_available', score: null }));
    // what needs an auditor's attention first: overdue audit findings, overdue evidence requests, framework gaps
    const att = [];
    const daysPast = (d) => { const t = Date.parse(String(d || '').slice(0, 10) + 'T00:00:00Z'); return Number.isFinite(t) ? Math.max(0, Math.floor((now() - t) / DAY)) : null; };
    if (tm.available) for (const t of tm.list) for (const f of t.overdue) att.push({ severity: f.rating === 'high' ? 'high' : 'medium', source: t.name, ref: f.id, text: f.title + ' - owner ' + f.owner + ', due ' + f.due, page: t.page, kind: 'finding', days: daysPast(f.due) });
    for (const fw of frameworks) if (fw.available && fw.pbc) for (const r of fw.pbc.overdue) att.push({ severity: r.days_overdue > 30 ? 'high' : 'medium', source: fw.name + ' evidence request', ref: r.ref, text: r.title + ' - ' + r.owner + ', ' + r.days_overdue + ' day(s) overdue', page: fw.page, kind: 'request', days: r.days_overdue });
    for (const fw of frameworks) if (fw.available) for (const g of fw.top.filter((x) => x.result !== 'partial').slice(0, 3)) att.push({ severity: g.severity === 'high' || g.severity === 'critical' || fw.id === 'pdpl' ? 'high' : 'medium', source: fw.name, ref: g.id, text: g.title, page: fw.page });
    if (dp.available) for (const d of dp.items.slice(0, 10)) att.push({ severity: d.result === 'exception' || d.days_overdue > 30 ? 'high' : 'medium', source: 'Department checklist - ' + d.dept, ref: d.id, text: d.title + (d.result === 'overdue' ? ' - ' + d.period + ' not attested, ' + d.days_overdue + ' day(s) overdue' : ' - auditor exception for ' + d.period), page: 'dept-checklist.html' });
    if (cc.available) for (const o of (cc.open || []).slice(0, 5)) att.push({ severity: o.score >= 0.9 ? 'high' : 'medium', source: 'Control monitoring - ' + o.test + ' ' + o.name, ref: o.id, text: o.why, page: 'audit-ccm.html' });
    if (dl.available) for (const b of dl.breaches) att.push({ severity: 'high', kind: 'clock', source: 'PDPL breach - 72 hours to SDAIA', ref: b.ref, text: b.risk === 'breached' ? 'the 72 hours have passed without an SDAIA notification' : b.hours_left + ' hour(s) left to notify SDAIA', page: 'pdpl-intel.html' });
    if (dl.available) for (const d of dl.dsar) att.push({ severity: d.risk === 'breached' ? 'high' : 'medium', kind: 'clock', source: 'PDPL data subject request', ref: d.ref, text: d.type + ' request due ' + d.due + (d.risk === 'breached' ? ' - the deadline has passed' : ' - ' + Math.round(d.p_on_time * 100) + '% chance of answering in time (' + (d.method === 'history' ? 'from history' : 'by the rules') + ')'), page: 'pdpl-intel.html' });
    if (pg.available) for (const pr of pg.list) for (const t of pr.failing.slice(0, 3)) att.push({ severity: 'medium', source: pr.name, ref: t.id, text: t.title + ' - ' + t.owner, page: 'ai-auditors.html' });
    for (const a of att) prioritise(a);
    att.sort((a, b) => SEV[a.severity] - SEV[b.severity] || b.priority - a.priority);
    const avail = frameworks.filter((x) => x.available && x.score !== null);
    const an = await source('analytics', analytics);
    const out = { generated_at: iso(), frameworks, programmes: pg, teams: tm, departments: dp, ccm: cc, deadlines: dl, analytics: an, attention: att.slice(0, 40),
      summary: { assessed: avail.length, of: frameworks.length, gaps: frameworks.reduce((n, x) => n + ((x.counts && x.counts.gaps) || 0), 0),
        overdue_findings: tm.available ? tm.list.reduce((n, t) => n + t.findings.overdue, 0) : null,
        overdue_requests: frameworks.reduce((n, x) => n + ((x.pbc && x.pbc.by_state.overdue) || 0), 0),
        control_exceptions_open: cc.available && cc.run ? cc.open_total : null, pdpl_deadlines_at_risk: dl.available ? dl.counts.dsar_at_risk + dl.counts.breaches_at_risk : null },
      note: 'Each score is the platform module\'s own indicative figure from its register - not the regulator\'s assessment. A framework nobody has assessed reads "not assessed", never compliant.' };
    out.insight = insight(out);
    return out;
  }

  // ---- insight: the assurance index, history, priority, delivery (every number itemised)
  const SEVP = { critical: 70, high: 60, medium: 35, low: 15 };
  function prioritise(a) {
    const why = [['severity ' + a.severity, SEVP[a.severity] || 15]];
    if (a.days) why.push([a.days + ' day(s) overdue', Math.min(25, Math.round(6 * Math.log(1 + a.days)))]);
    if (a.kind === 'clock') why.push(['a legal clock is running (PDPL)', 15]);
    if (a.kind === 'finding') why.push(['an audit finding past its agreed date', 8]);
    a.priority = Math.min(100, why.reduce((t, x) => t + x[1], 0)); a.priority_why = why.map((x) => x[0] + ' +' + x[1]);
    return a;
  }
  async function analytics() {
    const X = A().auditAnalytics; if (!X) return null;
    const o = X.overview();
    return { available: true, page: 'audit-analytics.html', kpis: o.kpis, datasets: o.datasets.filter((d) => !d.archived).length, recent: o.runs.slice(0, 6).map((r) => ({ id: r.id, test: r.test_name, dataset: r.dataset_name, summary: s(r.summary, 200), exceptions: r.exceptions_total, reviewed: !!r.review, at: r.at })) };
  }
  const TARGET = 80;
  function dist(c) {
    c = c || {};
    return { ok: (c.compliant || 0) + (c.verified || 0) + (c.met || 0), partial: c.partial || 0, gap: c.gaps || 0, open: (c.not_assessed || 0) + (c.not_measured || 0) + (c.no_evidence || 0) + (c.auto_pass || 0) };
  }
  function index(v) {
    const sc = v.frameworks.filter((f) => f.available && f.score != null), S = v.summary;
    if (sc.length < 2) return { value: null, why: 'withheld until two frameworks are assessed (' + sc.length + ' so far) - an empty platform must not read as assured', items: [] };
    const base = Math.round(sc.reduce((t, f) => t + Number(f.score), 0) / sc.length * 10) / 10;
    const items = [{ label: 'mean score of ' + sc.length + ' assessed framework(s)', points: base, side: 'base' }];
    const pen = (label, n, each, max) => { if (n > 0) items.push({ label: label + ' (' + n + ' x ' + each + ', at most ' + max + ')', points: -Math.min(max, n * each), side: 'down' }); };
    pen('overdue audit findings', S.overdue_findings || 0, 3, 20); pen('overdue evidence requests', S.overdue_requests || 0, 2, 10);
    pen('open control-monitoring exceptions', S.control_exceptions_open || 0, 1, 10); pen('PDPL deadlines at risk', S.pdpl_deadlines_at_risk || 0, 5, 15);
    pen('frameworks not assessed', v.frameworks.filter((f) => f.score == null).length, 2, 10);
    const value = Math.max(0, Math.min(100, Math.round(items.reduce((t, x) => t + x.points, 0))));
    return { value, why: 'the mean of the assessed framework scores less the points itemised below - indicative, not a regulator\'s rating', items };
  }
  function insight(v) {
    const ix = index(v), ref = K.ago(30), hist = K.history(90);
    const fw = v.frameworks.map((f) => {
      const prev = ref && ref.fw ? ref.fw[f.id] : null, mv = f.score != null && prev != null ? Math.round((f.score - prev) * 10) / 10 : null;
      const tr = f.score != null ? trend(K.pts((h) => (h.fw ? h.fw[f.id] : null)), { target: TARGET, current: f.score, now: now() }) : { why: 'not assessed' };
      return { id: f.id, name: f.name, score: f.score == null ? null : f.score, dist: dist(f.counts), move_30d: mv, regressed: mv != null && mv <= -5, projection: tr,
        series: hist.map((h) => ({ date: h.id, value: h.fw ? (h.fw[f.id] == null ? null : h.fw[f.id]) : null })) };
    });
    const delivery = v.teams.available ? v.teams.list.map((t) => { const open = t.findings.open, on = open - t.findings.overdue;
      return { id: t.id, name: t.name, open, overdue: t.findings.overdue, on_track: Math.round(beta(on, open) * 100), why: open ? on + ' of ' + open + ' open finding(s) not overdue, Beta(1,1)' : 'no open finding - 50 % is the prior, not a measurement' }; }) : [];
    const tr = ix.value == null ? { why: ix.why } : trend(K.pts('index'), { target: TARGET, current: ix.value, now: now() });
    return { index: ix, index_move_30d: ix.value != null && ref && ref.index != null ? ix.value - ref.index : null, projection: tr, target: TARGET,
      series: hist.map((h) => ({ date: h.id, value: h.index })), frameworks: fw, regressions: fw.filter((x) => x.regressed).map((x) => ({ id: x.id, name: x.name, move_30d: x.move_30d })),
      delivery, snapshots: hist.length, ai: K.aiStatus() };
  }
  async function snapshot() {
    return K.snapshot(async () => { const v = await view(); return { index: v.insight.index.value, fw: Object.fromEntries(v.frameworks.filter((f) => f.score != null).map((f) => [f.id, f.score])), s: v.summary }; });
  }
  async function viewAndSnap() { if (!K.history(1).some((h) => h.id === K.today())) { try { await snapshot(); } catch (e) { warn('snapshot', 'audit dashboard: the daily snapshot could not be written', e); } } return view(); }
  const K = createIntelKit(app, { key: 'audit-dashboard', feature: 'itam.audit-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the audit advisor to the internal audit, IT audit and cyber security audit teams and the Audit Committee of ' + ZYB_ORG.name + '. You read the auditor\'s dashboard: every framework (PDPL, NCA ECC, NDMO, SAMA CSF, Insurance Authority, ISO 27001) with its score and movement, the assurance index with its itemised breakdown, overdue findings and evidence requests, control-monitoring exceptions, PDPL deadlines, audit-team delivery and the Audit Analytics log. Base every statement on the tool results and name the framework, finding or request. Scores are the platform\'s indicative figures, not a regulator\'s assessment. You propose priorities; auditors decide, conclude and sign.'),
    tools: [{ name: 'dashboard', description: 'The audit dashboard: frameworks with scores and movement, the assurance index and its breakdown, the ranked attention list, audit teams and delivery, analytics.', run: async () => { const v = await view();
      return { summary: v.summary, index: v.insight.index, projection: v.insight.projection, frameworks: v.frameworks.map((f) => ({ id: f.id, name: f.name, status: f.status, score: f.score, counts: f.counts, reason: f.reason })),
        movement: v.insight.frameworks.map((f) => ({ id: f.id, move_30d: f.move_30d, projection: f.projection.why })), attention: v.attention.slice(0, 20).map((a) => ({ ref: a.ref, source: a.source, severity: a.severity, priority: a.priority, text: s(a.text, 200) })),
        delivery: v.insight.delivery, analytics: v.analytics.available ? v.analytics.kpis : null }; } },
    { name: 'gaps', description: 'The top gaps of one framework (pdpl, nca-ecc, ndmo, sama, ia, iso27001, aramco) with result and why.', input_schema: { type: 'object', properties: { framework: { type: 'string', enum: ['pdpl', 'nca-ecc', 'ndmo', 'sama', 'ia', 'iso27001', 'aramco'] } }, required: ['framework'], additionalProperties: false },
      run: async (inp) => { const v = await view(), f = v.frameworks.find((x) => x.id === inp.framework); if (!f || !f.available) return { error: (f && f.reason) || 'not available' }; return { name: f.name, top: f.top, pbc_overdue: f.pbc ? f.pbc.overdue : [] }; } }] });

  async function exportCsv(who) {
    const v = await view();
    const cell = (x) => { let t = s(x, 1000); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };   // no formula injection in Excel
    const L = [['Section', 'Item', 'Status / result', 'Score %', 'Detail', 'Owner / reference'].map(cell).join(',')];
    for (const f of v.frameworks) {
      L.push(['Framework', f.name, f.available ? f.status : 'not available', f.score === null || f.score === undefined ? '' : f.score, f.available ? JSON.stringify(f.counts) + (f.extra ? ' - ' + f.extra : '') : f.reason, f.owner || ''].map(cell).join(','));
      if (f.available) for (const g of f.top) L.push(['Gap', g.id + ' ' + g.title, g.result, '', g.why, g.ref].map(cell).join(','));
    }
    if (v.departments.available) for (const d of v.departments.list) L.push(['Department', d.name, d.status, '', 'fully ' + d.pct.fully + '%, partially ' + d.pct.partially + '%, not ' + d.pct.not + '%, not assessed ' + d.pct.not_assessed + '%; overdue ' + d.overdue, d.head || 'no head named'].map(cell).join(','));
    if (v.teams.available) for (const t of v.teams.list) L.push(['Audit team', t.name, t.plan ? t.plan.id + ' ' + t.plan.state : 'no plan', '', 'open findings ' + t.findings.open + ', high ' + t.findings.high + ', overdue ' + t.findings.overdue, t.head_of_audit || 'no Head of Audit'].map(cell).join(','));
    for (const a of v.attention) L.push(['Attention', a.ref + ' ' + a.text, a.severity, '', a.source, a.page].map(cell).join(','));
    if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'audit-dashboard.export', target: 'audit-dashboard', detail: { rows: L.length - 1 } });
    return { filename: 'audit-dashboard-' + v.generated_at.slice(0, 10) + '.csv', csv: L.join('\r\n') };
  }
  return { view: viewAndSnap, exportCsv, snapshot, start: () => K.start(snapshot), stop: K.stop, ask: K.ask, aiStatus: K.aiStatus, TOOLS: K.TOOLS };
}

function registerAuditDashboard(srv, app, D) {
  srv.route('GET', '/audit-dashboard', (ctx) => { ctx.need('operator'); return D.view(); });   // names people and weaknesses (PDPL): no viewers
  srv.route('GET', '/audit-dashboard/export', (ctx) => { ctx.need('operator'); return D.exportCsv(ctx.who); });
  srv.route('GET', '/audit-dashboard/ai/status', (ctx) => { ctx.need('operator'); return D.aiStatus(); });
  srv.route('POST', '/audit-dashboard/ask', (ctx) => { ctx.need('operator'); return D.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
}

module.exports = { createAuditDashboard, registerAuditDashboard };
