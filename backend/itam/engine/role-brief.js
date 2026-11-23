// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { param } = require('./check');
/*
 * Role briefs for My Workspace ({P} = /api/itam): the CISO's and the IT Manager's own start page, built the same way as the Head of
 * Risk's (engine/risk-command.js my()). It writes nothing and adds no data source - it reads what the modules already hold, at
 * request time, and ranks it into one list of priorities, each with its points and the reasons behind them.
 *
 *   ciso    security posture by domain (AI CISO, engine/ciso.js), open critical / high security risks and the decisions waiting for a
 *           person, SOC alerts and SLA breaches, SAMA coverage, IT / cyber appetite metrics outside appetite (Business Risk), and the
 *           GRC actions the person owns or that are overdue in the team; and Workflow Automation (wfRead below): what they or the CISO
 *           office asked the IT teams for that is late, results waiting for their acceptance, requests waiting for their approval
 *   itm     the infrastructure position (engine/infra-overview.js): backups failed / stale / missing, endpoints missing critical
 *           patches, end-of-life systems (isolation required), storage capacity and failed disks, support contracts and warranties
 *           expiring, operations / resilience risks from the AI CISO, IT appetite metrics outside appetite, and the GRC actions; and
 *           AD Management (engine/ad-manage.js): directory changes waiting for THIS person's approval (never their own requests),
 *           emergency disables to review, temporary passwords waiting for them, changes that failed in the last 7 days; and
 *           Workflow Automation (engine/workflow-auto.js), read as the person: business requests waiting for their approval (never
 *           their own), requests overdue or likely to miss their SLA in the teams they work or lead, results waiting for their acceptance
 * A source that is not installed or cannot be read is named in `notes` and contributes nothing - never a zero that reads as "fine".
 * The brief is written by rules from the records, not by an AI.
 *   GET /role-brief/:kind    operator   kind ciso | itm (names owners, servers and contracts: no viewers)
 */
const SEVP = { critical: 50, high: 35, medium: 15, low: 5 };
const s = (x, n = 200) => String(x == null ? '' : x).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').slice(0, n);
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createRoleBrief(app, opts = {}) {
  const now = opts.now || Date.now, A = () => app.addons || {}, L = app.log || { every() {} };
  const iso = () => new Date(now()).toISOString();
  let infraO = null;
  const infra = () => A().infraOverview || infraO || (infraO = require('./infra-overview').createInfraOverview(app));
  async function read(name, fn, notes) {
    try { const v = await fn(); if (v == null) notes.push(name + ' is not installed'); return v; }
    catch (e) { if (L.every) L.every('role-brief:' + name, 600000, 'warn', 'role brief: ' + name + ' could not be read', { err: s(e.message, 160) }); notes.push(name + ' could not be read'); return null; }
  }
  // the person's GRC actions and the team's overdue ones
  function actions(who) {
    const R = A().grcRegisters; if (!R) return null;
    const u = String(who.user || '').toLowerCase(), all = R.actionList({ status: 'open' }).items;
    const mine = all.filter((a) => String(a.owner || '').toLowerCase() === u), team = all.filter((a) => a.overdue && String(a.owner || '').toLowerCase() !== u);
    return { mine, team };
  }
  // appetite metrics outside appetite whose responsible department matches
  async function rasOutside(re, notes) {
    const B = A().businessRisk; if (!B) return [];
    const v = await read('Business Risk', () => B.rasAll(), notes); if (!v) return [];
    return v.metrics.filter((m) => m.latest && m.latest.level >= 1 && re.test(m.responsibility || '') || (m.early_warning && re.test(m.responsibility || '')))
      .map((m) => ({ id: m.id, component: m.component, zone: m.latest ? m.latest.zone : 'within_appetite', level: m.latest ? m.latest.level : 0, period: m.latest ? m.latest.period : null, warning: m.early_warning ? m.early_warning.why : null }));
  }
  function ranked(P) { return P.map((p) => Object.assign(p, { score: Math.min(100, p.why.reduce((t, w) => t + w[1], 0)), why: p.why.map((w) => w[0] + ' +' + w[1]) })).sort((a, b) => b.score - a.score || String(a.ref).localeCompare(String(b.ref))).slice(0, 20); }
  function addActions(P, act) {
    if (!act) return;
    for (const a of act.mine) if (a.overdue) P.push({ kind: 'my action', ref: a.id, text: a.title + ' - due ' + a.due, page: 'grc-workspace.html', why: [['your action, overdue', 60]] });
      else if (a.due_soon) P.push({ kind: 'my action', ref: a.id, text: a.title + ' - due ' + a.due, page: 'grc-workspace.html', why: [['your action, due within 14 days', 40]] });
    for (const a of act.team.slice(0, 8)) P.push({ kind: 'team action', ref: a.id, text: a.title + ' - ' + (a.owner || 'no owner') + ', due ' + a.due, page: 'grc-workspace.html', why: [['an overdue action in your area', 30]] });
  }
  function addRas(P, list) {
    for (const m of list) P.push({ kind: 'appetite', ref: m.id, text: m.component + (m.period ? ' (' + m.period + ')' : ''), page: 'risk-appetite.html#' + m.id,
      why: m.level >= 1 ? [['appetite metric ' + m.zone.replace(/_/g, ' '), 30 + 10 * m.level]] : [['early warning: ' + s(m.warning, 120), 30]] });
  }

  // Workflow Automation (engine/workflow-auto.js), read as the person: requests waiting for their approval (never their own), the queue
  // of the teams they work or lead (overdue, likely to miss the SLA), and what they or their function raised (late with the IT teams,
  // results waiting for their acceptance). Shared by the CISO and the IT Manager briefs.
  async function wfRead(who, P, notes) {
    const WF = A().workflow, at = WF ? await read('Workflow Automation', () => WF.attention({ user: who.user, role: who.role }), notes) : null;
    if (!WF) notes.push('Workflow Automation is not installed');
    if (!at) return null;
    for (const p of at.priorities) P.push(p);
    return at.summary;
  }

  async function ciso(who) {
    const notes = [], C = A().ciso;
    const v = C ? await read('AI CISO', () => C.overview(false), notes) : (notes.push('the AI CISO is not installed'), null);
    const act = actions(who); if (!act) notes.push('the GRC register is not installed');
    const ras = await rasOutside(/cyber|security|\bit\b|information technology/i, notes);
    const P = [];
    if (v) {
      for (const d of v.posture.domains || []) if (d.measured && d.score != null && d.score < 70) P.push({ kind: 'posture', ref: 'domain:' + d.id, text: d.name + ' ' + d.score + ' / 100', page: d.page || 'ciso-dashboard.html', why: [['security domain below 70', 20 + Math.round((70 - d.score) / 2)]] });
      for (const r of (v.risks || []).filter((x) => x.severity === 'critical' || x.severity === 'high').slice(0, 10)) P.push({ kind: 'security risk', ref: r.ref, text: r.title + ' (' + r.source + ')', page: 'ciso-dashboard.html', why: [[r.severity + ' security risk', SEVP[r.severity]]].concat(r.age_h > 72 ? [['open ' + Math.round(r.age_h / 24) + ' days', 10]] : []) });
      for (const d of (v.decisions || []).slice(0, 8)) P.push({ kind: 'decision', ref: d.ref, text: d.title, page: 'ciso-dashboard.html', why: [['waiting for a decision (' + d.kind + ')', 30], [d.severity || 'medium', Math.round((SEVP[d.severity] || 15) / 3)]] });
      const br = v.soc && v.soc.sla ? v.soc.sla.breaching_now : 0; if (br) P.push({ kind: 'soc', ref: 'soc:sla', text: br + ' case(s) breaching their SLA now', page: 'soc-cases.html', why: [['SOC cases breaching the SLA', 45]] });
    }
    const wf = await wfRead(who, P, notes);
    addRas(P, ras); addActions(P, act);
    const sev = (v && v.soc && v.soc.open_by_severity) || {}, comp = v && v.compliance;
    const kpis = { posture: v ? v.posture.overall : null, grade: v ? v.posture.grade : null, critical_alerts: v && v.soc ? sev.critical || 0 : null, high_alerts: v && v.soc ? sev.high || 0 : null,
      sla_breaching: v && v.soc && v.soc.sla ? v.soc.sla.breaching_now : null, decisions: v ? (v.decisions || []).length : null, security_risks: v ? (v.risks || []).filter((x) => x.severity === 'critical' || x.severity === 'high').length : null,
      sama_coverage: comp && comp.sama ? comp.sama.coverage_pct : null, my_overdue: act ? act.mine.filter((a) => a.overdue).length : null, appetite_outside: ras.filter((m) => m.level >= 1).length,
      wf_attention: wf ? wf.approvals + wf.raised_late + wf.to_accept : null };
    const pr = ranked(P), lines = [];
    lines.push(kpis.posture != null ? 'Security posture ' + kpis.posture + ' / 100 (' + kpis.grade + ').' : 'The security posture is withheld until three domains are measured' + (v && v.posture.withheld_why ? ': ' + v.posture.withheld_why : '.'));
    if (v) lines.push(kpis.security_risks + ' critical or high security risk(s) open; ' + kpis.decisions + ' decision(s) waiting for a person.');
    if (kpis.critical_alerts != null) lines.push(kpis.critical_alerts + ' critical and ' + kpis.high_alerts + ' high SOC alert(s) open' + (kpis.sla_breaching ? ', ' + kpis.sla_breaching + ' case(s) breaching their SLA' : '') + '.');
    if (kpis.sama_coverage != null) lines.push('SAMA CSF evidence coverage ' + kpis.sama_coverage + ' %.');
    if (ras.length) lines.push(ras.filter((m) => m.level >= 1).length + ' IT / cyber appetite metric(s) outside appetite, ' + ras.filter((m) => m.warning).length + ' with an early warning.');
    if (act) lines.push(act.mine.length ? 'You own ' + act.mine.length + ' open GRC action(s), ' + kpis.my_overdue + ' overdue.' : 'You own no open GRC action.');
    if (wf) lines.push('Workflow Automation: ' + wf.raised_open + ' request(s) from you' + (wf.functions.includes('ciso') ? ' and the CISO office' : '') + ' open with the IT teams' + (wf.raised_late ? ', ' + wf.raised_late + ' late' : '')
      + (wf.to_accept ? ', ' + wf.to_accept + ' result(s) waiting for your acceptance' : '') + (wf.approvals ? ', ' + wf.approvals + ' request(s) waiting for your approval' : '') + '; ' + wf.all_overdue + ' overdue across the IT teams.');
    if (pr[0]) lines.push('First: ' + pr[0].ref + ' - ' + pr[0].text + '.');
    return { kind: 'ciso', generated_at: iso(), user: who.user, brief: lines, kpis, priorities: pr, wf, domains: v ? (v.posture.domains || []).map((d) => ({ id: d.id, name: d.name, score: d.score, measured: d.measured })) : [],
      notes: notes.concat(v ? (v.sources || []).filter((x) => x.state !== 'live').map((x) => x.name + ': ' + (x.error || x.state)) : []),
      links: [['ciso-dashboard.html', 'CISO Dashboard'], ['workflow-automation.html', 'Workflow Automation'], ['soc-overview.html', 'SOC Overview'], ['vuln-dashboard.html', 'Vulnerability & Testing Dashboard'], ['enterprise-risk.html', 'Enterprise Risk Dashboard'], ['compliance-overview.html', 'Compliance Overview'], ['report-center.html', 'Reporting Center']],
      note: 'Ranked from the platform\'s records - each priority shows its points. Written by rules, not by an AI.' };
  }

  async function itm(who) {
    const notes = [], o = await read('Infrastructure overview', () => infra().view(who.role), notes) || {};
    const off = (k) => !o[k] || o[k].available === false;
    for (const k of ['backup', 'patch', 'lifecycle', 'storage', 'contracts']) if (o[k] && o[k].available === false) notes.push(k + ': ' + o[k].why);
    const C = A().ciso, v = C ? await read('AI CISO', () => C.overview(false), notes) : null;
    const act = actions(who); if (!act) notes.push('the GRC register is not installed');
    const ras = await rasOutside(/^\s*it\b|information technology|infrastructure/i, notes);
    const P = [], b = o.backup, p = o.patch, l = o.lifecycle, st = o.storage, c = o.contracts, rg = o.register;
    if (!off('backup')) { if (b.failed) P.push({ kind: 'backup', ref: 'backup:failed', text: b.failed + ' server(s) with a failed backup', page: 'backup.html', why: [['backups failing', 50]] });
      if (b.none) P.push({ kind: 'backup', ref: 'backup:none', text: b.none + ' server(s) with no backup', page: 'backup.html', why: [['servers not backed up', 45]] });
      if (b.stale) P.push({ kind: 'backup', ref: 'backup:stale', text: b.stale + ' server(s) with a stale backup', page: 'backup.html', why: [['backups out of date', 30]] }); }
    if (!off('patch') && p.critical_missing) P.push({ kind: 'patching', ref: 'patch:critical', text: p.critical_missing + ' computer(s) missing critical patches', page: 'desktop-patches.html', why: [['critical patches missing', 45]] });
    if (!off('lifecycle')) { if (l.eol) P.push({ kind: 'end of life', ref: 'eol', text: l.eol + ' system(s) past end of support' + (l.isolation_required ? ', ' + l.isolation_required + ' needing isolation' : ''), page: 'lifecycle.html', why: [['end of support passed', 40]].concat(l.isolation_required ? [['isolation required', 10]] : []) });
      if (l.soon) P.push({ kind: 'end of life', ref: 'eol:soon', text: l.soon + ' system(s) reaching end of support soon', page: 'lifecycle.html', why: [['end of support approaching', 25]] }); }
    if (!off('storage')) { if (st.failed_disks) P.push({ kind: 'storage', ref: 'storage:disks', text: st.failed_disks + ' failed disk(s)', page: 'storage.html', why: [['failed disks', 50]] });
      if (st.used_pct >= 85) P.push({ kind: 'storage', ref: 'storage:capacity', text: 'storage ' + st.used_pct + ' % used', page: 'storage.html', why: [['storage above 85 %', 35]] }); }
    if (!off('contracts')) { if (c.expired) P.push({ kind: 'contracts', ref: 'contracts:expired', text: c.expired + ' support contract(s) expired', page: 'support-contracts.html', why: [['support expired', 40]] });
      if (c.expiring) P.push({ kind: 'contracts', ref: 'contracts:expiring', text: c.expiring + ' support contract(s) expiring', page: 'support-contracts.html', why: [['support expiring', 25]] }); }
    if (rg && rg.warranty && rg.warranty.expired) P.push({ kind: 'warranty', ref: 'warranty', text: rg.warranty.expired + ' device(s) out of warranty', page: 'renewals-expiry.html', why: [['warranty expired', 20]] });
    if (v) for (const r of (v.risks || []).filter((x) => (x.domain === 'operations' || x.domain === 'resilience') && (x.severity === 'critical' || x.severity === 'high')).slice(0, 6))
      P.push({ kind: 'operations risk', ref: r.ref, text: r.title + ' (' + r.source + ')', page: 'ciso-dashboard.html', why: [[r.severity + ' operations / resilience risk', SEVP[r.severity] - 10]] });
    // AD Management: what waits for this person - a request they made is approved and reviewed by someone else, so it is not theirs to act on
    const AM = A().adManage, me = String(who.user || '').toLowerCase();
    const am = AM ? await read('AD Management', () => AM.view({ user: who.user, role: who.role }), notes) : null;
    if (!AM) notes.push('AD Management is not installed');
    let ad = null;
    if (am) {
      const R = am.requests || [], wk = now() - 7 * 86400000, others = (r) => String(r.by || '').toLowerCase() !== me;
      const waiting = R.filter((r) => r.status === 'pending' && others(r)), mine = R.filter((r) => r.status === 'pending' && !others(r)), reviews = R.filter((r) => r.review === 'pending' && others(r));
      const pw = R.filter((r) => r.password_ready), failed = R.filter((r) => r.status === 'failed' && Date.parse(r.decided_at || r.at) >= wk);
      for (const r of waiting.slice(0, 8)) P.push({ kind: 'AD change', ref: r.id, text: s(r.summary, 160) + ' - requested by ' + r.by, page: 'ad-manage.html', why: [['a directory change waiting for your approval', 45]].concat(r.action === 'delete' ? [['permanent delete', 10]] : []) });
      for (const r of reviews.slice(0, 5)) P.push({ kind: 'AD emergency', ref: r.id, text: s(r.summary, 160) + ' - by ' + r.by, page: 'ad-manage.html', why: [['emergency disable waiting for your review', 50]] });
      for (const r of pw.slice(0, 5)) P.push({ kind: 'AD password', ref: r.id, text: s(r.summary, 160), page: 'ad-manage.html', why: [['temporary password to hand over (destroyed after 72 h)', 35]] });
      for (const r of failed.slice(0, 5)) P.push({ kind: 'AD change', ref: r.id, text: s(r.summary, 160) + ' failed: ' + s(r.error, 120), page: 'ad-manage.html', why: [['a directory change failed', 30]] });
      const cn = am.connection || {}, st = am.settings || {};
      ad = { connected: !!cn.ok, enabled: !!(cn.ok && st.enabled), why: cn.ok ? '' : s(cn.why), delete_enabled: !!st.delete_enabled, waiting_for_you: waiting.length, my_pending: mine.length, reviews: reviews.length, passwords: pw.length, failed_7d: failed.length,
        recent: R.slice(0, 6).map((r) => ({ id: r.id, summary: s(r.summary, 160), status: r.status, by: r.by, at: r.at, decided_by: r.decided_by || '', review: r.review || '', emergency: !!r.emergency })) };
    }
    const wf = await wfRead(who, P, notes);
    addRas(P, ras); addActions(P, act);
    const kpis = { servers: rg && rg.available !== false ? rg.servers.total : null, network: rg && rg.available !== false ? rg.network.total : null, backup_pct: off('backup') ? null : b.protected_pct,
      patch_pct: off('patch') ? null : p.compliant_pct, eol: off('lifecycle') ? null : l.eol, storage_pct: off('storage') ? null : st.used_pct, contracts_due: off('contracts') ? null : (c.expired || 0) + (c.expiring || 0),
      my_overdue: act ? act.mine.filter((a) => a.overdue).length : null, appetite_outside: ras.filter((m) => m.level >= 1).length,
      ad_waiting: ad && ad.enabled ? ad.waiting_for_you + ad.reviews : null, wf_attention: wf ? wf.approvals + wf.overdue + wf.to_accept : null };
    const pr = ranked(P), lines = [];
    lines.push(kpis.servers != null ? kpis.servers + ' server(s) and ' + kpis.network + ' network device(s) in the register.' : 'The asset register could not be read.');
    lines.push(kpis.backup_pct != null ? 'Backups: ' + kpis.backup_pct + ' % of servers protected' + (b.failed ? ', ' + b.failed + ' failed' : '') + '.' : 'Backups: not measured - ' + (b ? b.why : 'not installed') + '.');
    lines.push(kpis.patch_pct != null ? 'Patching: ' + kpis.patch_pct + ' % of reporting computers fully patched, ' + p.critical_missing + ' missing a critical patch.' : 'Patching: not measured - ' + (p ? p.why : 'not installed') + '.');
    if (kpis.eol != null) lines.push(kpis.eol + ' system(s) past end of support, ' + l.soon + ' soon.');
    if (kpis.contracts_due != null) lines.push(kpis.contracts_due + ' support contract(s) expired or expiring.');
    if (ras.length) lines.push(ras.filter((m) => m.level >= 1).length + ' IT appetite metric(s) outside appetite, ' + ras.filter((m) => m.warning).length + ' with an early warning.');
    if (act) lines.push(act.mine.length ? 'You own ' + act.mine.length + ' open GRC action(s), ' + kpis.my_overdue + ' overdue.' : 'You own no open GRC action.');
    if (ad) lines.push(!ad.connected ? 'AD Management: the directory is not connected.' : !ad.enabled ? 'AD Management: switched off.'
      : 'AD Management: ' + (ad.waiting_for_you ? ad.waiting_for_you + ' change(s) waiting for your approval' : 'nothing waiting for your approval') + (ad.reviews ? ', ' + ad.reviews + ' emergency disable(s) to review' : '') + (ad.passwords ? ', ' + ad.passwords + ' temporary password(s) to hand over' : '') + (ad.my_pending ? '; ' + ad.my_pending + ' of your own request(s) waiting for another administrator' : '') + '.');
    if (wf) lines.push('Workflow Automation: ' + (wf.approvals ? wf.approvals + ' request(s) waiting for your approval' : 'nothing waiting for your approval') + ', ' + wf.queue_open + ' open in your team queue'
      + (wf.overdue ? ' (' + wf.overdue + ' overdue)' : '') + (wf.at_risk ? ', ' + wf.at_risk + ' likely to miss the SLA' : '') + (wf.to_accept ? ', ' + wf.to_accept + ' result(s) waiting for your acceptance' : '') + '; ' + wf.all_overdue + ' overdue across the IT teams.');
    if (pr[0]) lines.push('First: ' + pr[0].text + '.');
    return { kind: 'itm', generated_at: iso(), user: who.user, brief: lines, kpis, priorities: pr, notes, ad, wf,
      links: [['head-of-it.html', 'Head of IT'], ['ad-manage.html', 'AD Management'], ['workflow-automation.html', 'Workflow Automation'], ['infra-manager.html', 'Infrastructure Manager'], ['servers-dashboard.html', 'Servers'], ['network-dashboard.html', 'Network Dashboard'], ['backup.html', 'Backup'], ['support-contracts.html', 'Support Contracts'], ['enterprise-risk.html', 'Enterprise Risk Dashboard']],
      note: 'Ranked from the platform\'s records - each priority shows its points. A section that is not connected says so and adds nothing.' };
  }
  async function brief(kind, who) { if (kind === 'ciso') return ciso(who); if (kind === 'itm') return itm(who); throw httpErr(404, 'brief: ciso or itm'); }
  return { brief, ciso, itm };
}

function registerRoleBrief(srv, app, X) {
  srv.route('GET', '/role-brief/:kind', (ctx) => { ctx.need('operator'); return X.brief(param(ctx.params.kind, 'kind'), { user: ctx.who.user, role: ctx.who.role }); });
}
module.exports = { createRoleBrief, registerRoleBrief };
