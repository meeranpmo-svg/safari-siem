// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Process Risk Assessment (Business Risk -> Risk Assessments). A STANDALONE deep-dive on a specific process - procurement, the
 * succession plan, pricing, or any process the Risk function names - separate from the risk register and from the scenario risk
 * assessment. When the team notices an issue, they open an assessment here, record what they found, rate it, and extract a report.
 *   assessment   a process (procurement / succession / pricing / outsourcing / underwriting / claims / IT change / other), an owner,
 *                the period, the objective and scope. A set of suggested focus areas per process is offered as guidance (never filled
 *                in as data). Status: draft -> in_review -> approved (a different person, Risk) -> closed. Reopened with a reason.
 *   findings     each: the area, the observation, likelihood 1-5 and impact 1-5 (rating = L x I, band low/medium/high/critical), the
 *                root cause, the recommendation, the owner, the due date, the management response and a status (open / in_progress /
 *                closed). A finding can raise a tracked GRC action (a person; the register keeps its own four-eyes acceptance).
 *   rating       the assessment's residual rating = the highest open finding; "not rated" with no finding - never shown as low.
 *   report       the standalone report auditors ask for: objective, scope, focus areas, findings by rating, the action plan and the
 *                sign-off - HTML (white background, print-safe, company logo) or CSV. Audited.
 *   GET  /process-assessment                 operator  list, KPIs, the process templates
 *   GET  /process-assessment/:id             operator  one assessment with its findings and rating
 *   POST /process-assessment                 operator  create / edit the assessment header (draft)                  audited
 *   POST /process-assessment/:id/findings    operator  add / edit a finding                                         audited
 *   POST /process-assessment/:id/findings/:fid/action   operator  raise a GRC action for the finding               audited
 *   POST /process-assessment/:id/submit      operator  draft -> in_review                                           audited
 *   POST /process-assessment/:id/approve     risk      four eyes, not the author                                    audited
 *   POST /process-assessment/:id/reopen      risk      {reason}                                                     audited
 *   GET  /process-assessment/:id/report      operator  ?format=html|csv                                             audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const PROC = {
  procurement: { name: 'Procurement', areas: ['Vendor selection and competition', 'Conflict of interest and segregation of duties', 'Approval authority and limits', 'Contract terms and SLAs', 'Payment and three-way match', 'Single-source / emergency buys'] },
  succession: { name: 'Succession plan', areas: ['Key-person dependency', 'Identified successors and readiness', 'Knowledge transfer and documentation', 'Development plans', 'Emergency cover', 'Retention risk'] },
  pricing: { name: 'Pricing', areas: ['Rate adequacy vs loss experience', 'Pricing governance and sign-off', 'Model and assumptions review', 'Competitive and regulatory limits', 'Deviation and override controls', 'Monitoring of actual vs expected'] },
  outsourcing: { name: 'Outsourcing', areas: ['Due diligence and approval', 'Contract and exit plan', 'Data protection (PDPL)', 'Service monitoring', 'Concentration risk', 'Regulatory notification'] },
  underwriting: { name: 'Underwriting', areas: ['Authority and limits', 'Risk acceptance criteria', 'Accumulation control', 'Reinsurance adequacy', 'Documentation', 'Peer review'] },
  claims: { name: 'Claims', areas: ['Reserving adequacy', 'Fraud controls', 'Settlement authority', 'Leakage', 'Turnaround and SLAs', 'Litigation management'] },
  it_change: { name: 'IT change', areas: ['Change approval and testing', 'Segregation of duties', 'Rollback', 'Emergency change', 'Documentation', 'Post-implementation review'] },
  other: { name: 'Other process', areas: [] },
};
const STATUS = ['draft', 'in_review', 'approved', 'closed'];
const FSTATUS = ['open', 'in_progress', 'closed'];
const band = (r) => r >= 15 ? 'critical' : r >= 8 ? 'high' : r >= 4 ? 'medium' : 'low';

function createProcessAssessment(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const C = () => store.collection('proc_assessments'), F = () => store.collection('proc_findings');
  const A = () => app.addons || {};
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'procassess.' + action, target, detail }); };
  const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const same = (a, b) => !!a && !!b && String(a).toLowerCase() === String(b).toLowerCase();
  const get = (id0) => { const id = param(id0, 'id'), a = C().get(id); if (!a) throw httpErr(404, 'assessment ' + id + ' not found'); return a; };
  const findsOf = (a) => F().all((f) => f.assessment === a.id);
  const ratingOf = (fnds) => { const open = fnds.filter((f) => f.status !== 'closed'); if (!open.length) return fnds.length ? { rating: 0, band: 'resolved', note: 'all findings closed' } : { rating: null, band: 'not_rated', note: 'no finding recorded' }; const r = Math.max.apply(null, open.map((f) => f.rating)); return { rating: r, band: band(r), note: open.length + ' open finding(s), highest ' + r }; };

  function create(src, who) {
    human(who, 'creates an assessment');
    const b = body(src || {}).str('id', { max: 60, re: /^PA-[a-z0-9]+$/i }).str('title', { required: true, min: 4, max: 200 }).oneOf('process', Object.keys(PROC), { required: true }).str('owner', { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'owner must be a user name' })
      .str('period', { max: 20 }).str('objective', { max: 2000 }).str('scope', { max: 2000 }).done();
    let rec;
    if (b.id) { rec = C().get(b.id); if (!rec) throw httpErr(404, 'assessment not found'); if (rec.status === 'approved' || rec.status === 'closed') throw httpErr(409, 'an approved assessment is not edited - reopen it first'); rec = Object.assign({}, rec, b, { updated_by: who.user, updated_at: iso() }); }
    else rec = Object.assign({ id: 'PA-' + crypto.randomBytes(4).toString('hex'), status: 'draft', by: who.user, created_at: iso(), updated_at: iso(), approved_by: null }, b);
    C().put(rec); audit(who, 'create', rec.id, { process: rec.process, title: rec.title }); return detail(rec.id);
  }
  function putFinding(id0, src, who) {
    human(who, 'records a finding'); const a = get(id0); if (a.status === 'approved' || a.status === 'closed') throw httpErr(409, 'reopen the assessment before changing findings');
    const b = body(src || {}).str('id', { max: 60, re: /^PF-[a-z0-9]+$/i }).str('area', { required: true, max: 200 }).str('observation', { required: true, min: 5, max: 4000 }).int('likelihood', { required: true, min: 1, max: 5 }).int('impact', { required: true, min: 1, max: 5 })
      .str('root_cause', { max: 2000 }).str('recommendation', { required: true, min: 5, max: 2000 }).str('owner', { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'owner must be a user name' }).date('due').str('response', { max: 2000 }).oneOf('status', FSTATUS, { def: 'open' }).done();
    const rating = b.likelihood * b.impact; let rec;
    if (b.id) { rec = F().get(b.id); if (!rec || rec.assessment !== a.id) throw httpErr(404, 'finding not found'); rec = Object.assign({}, rec, b, { rating, band: band(rating), updated_by: who.user, updated_at: iso() }); }
    else rec = Object.assign({ id: 'PF-' + crypto.randomBytes(4).toString('hex'), assessment: a.id, grc_action: null, by: who.user, created_at: iso() }, b, { rating, band: band(rating) });
    F().put(rec); audit(who, 'finding', a.id + ':' + rec.id, { area: rec.area, rating }); return detail(a.id);
  }
  function raiseAction(id0, fid0, who) {
    human(who, 'raises an action'); const a = get(id0), fid = param(fid0, 'fid'), f = F().get(fid); if (!f || f.assessment !== a.id) throw httpErr(404, 'finding not found');
    if (f.grc_action) throw httpErr(409, 'a GRC action already tracks this finding: ' + f.grc_action);
    const GR = A().grcRegisters; if (!GR || !GR.actionCreate) throw httpErr(424, 'the GRC register is not installed');
    const act = GR.actionCreate({ title: ('Risk assessment: ' + a.title + ' - ' + f.area).slice(0, 200), source: 'audit', ref: a.id + ':' + f.id, owner: f.owner || a.owner || '', due: f.due || null, priority: f.band === 'critical' ? 'critical' : f.band === 'high' ? 'high' : 'medium', description: (f.recommendation + '\nFrom process assessment ' + a.id).slice(0, 4000) }, who);
    F().put(Object.assign({}, f, { grc_action: act && act.id })); audit(who, 'action', a.id + ':' + f.id, { action: act && act.id }); return detail(a.id);
  }
  function submit(id0, who) { human(who, 'submits an assessment'); const a = get(id0); if (a.status !== 'draft') throw httpErr(409, 'only a draft is submitted (this is ' + a.status + ')'); if (!findsOf(a).length) throw httpErr(409, 'record at least one finding (or close the assessment with a note of no issues) before review');
    C().put(Object.assign({}, a, { status: 'in_review', submitted_by: who.user, submitted_at: iso() })); audit(who, 'submit', a.id, {}); return detail(a.id); }
  function approve(id0, who) { human(who, 'approves an assessment'); const a = get(id0); if (a.status !== 'in_review') throw httpErr(409, 'submit it for review first (this is ' + a.status + ')'); if (same(who.user, a.by)) throw httpErr(403, 'four eyes: the author cannot approve the assessment');
    C().put(Object.assign({}, a, { status: 'approved', approved_by: who.user, approved_at: iso() })); audit(who, 'approve', a.id, {}); return detail(a.id); }
  function reopen(id0, src, who) { human(who, 'reopens an assessment'); const a = get(id0); if (a.status !== 'approved' && a.status !== 'in_review' && a.status !== 'closed') throw httpErr(409, 'nothing to reopen');
    const b = body(src || {}).str('reason', { required: true, min: 5, max: 500 }).done(); C().put(Object.assign({}, a, { status: 'draft', approved_by: null, reopened_by: who.user, reopened_at: iso(), reopen_reason: b.reason })); audit(who, 'reopen', a.id, { reason: b.reason }); return detail(a.id); }

  function slim(a) { const f = findsOf(a), r = ratingOf(f); return { id: a.id, title: a.title, process: a.process, process_name: (PROC[a.process] || {}).name || a.process, owner: a.owner || '', period: a.period || '', status: a.status, findings: f.length, open_findings: f.filter((x) => x.status !== 'closed').length, rating: r.rating, band: r.band, by: a.by, approved_by: a.approved_by || null, updated_at: a.updated_at }; }
  function view() {
    const rows = C().all().map(slim).sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
    const kpis = { assessments: rows.length, open: rows.filter((r) => r.status !== 'closed').length, in_review: rows.filter((r) => r.status === 'in_review').length, critical: rows.filter((r) => r.band === 'critical').length, open_findings: rows.reduce((a, r) => a + r.open_findings, 0) };
    return { generated_at: iso(), processes: Object.keys(PROC).map((k) => ({ key: k, name: PROC[k].name, areas: PROC[k].areas })), assessments: rows, kpis, statuses: STATUS,
      note: 'Standalone deep-dives on a process, separate from the risk register. A finding can raise a tracked GRC action; a different person in the Risk function approves each assessment (four eyes).' };
  }
  function detail(id0) { const a = get(id0), f = findsOf(a).sort((x, y) => y.rating - x.rating), r = ratingOf(f);
    return { id: a.id, title: a.title, process: a.process, process_name: (PROC[a.process] || {}).name || a.process, areas: (PROC[a.process] || {}).areas || [], owner: a.owner || '', period: a.period || '', objective: a.objective || '', scope: a.scope || '',
      status: a.status, rating: r.rating, band: r.band, rating_note: r.note, findings: f, reopen_reason: a.reopen_reason || null,
      history: { by: a.by, created_at: a.created_at, submitted_by: a.submitted_by || null, approved_by: a.approved_by || null, approved_at: a.approved_at || null }, statuses: STATUS, finding_statuses: FSTATUS,
      note: 'A finding\'s rating is likelihood x impact. Raise a GRC action to track a recommendation; the register keeps its own four-eyes acceptance.' };
  }
  function report(id0, q, who) {
    const a = get(id0), fmt = (q && q.format) || 'html'; if (!['html', 'csv'].includes(fmt)) throw httpErr(400, 'format must be html or csv');
    const d = detail(a.id); audit(who, 'report', a.id, { format: fmt });
    const cols = ['Area', 'Observation', 'Likelihood', 'Impact', 'Rating', 'Band', 'Root cause', 'Recommendation', 'Owner', 'Due', 'Status', 'GRC action'];
    const row = (f) => [f.area, f.observation, f.likelihood, f.impact, f.rating, f.band, f.root_cause || '', f.recommendation, f.owner || '', f.due || '', f.status, f.grc_action || ''];
    if (fmt === 'csv') return { filename: 'risk-assessment-' + a.id + '.csv', csv: ['# ' + a.title + ' (' + d.process_name + ') ' + d.generated_at, cols.join(',')].concat(d.findings.map((f) => row(f).map(csvCell).join(','))).join('\r\n') };
    const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {}, brand = { name: bv.org_name || ZYB_ORG.name, logo_url: bv.letterhead || '' };
    const tbl = (c, rs) => '<table><thead><tr>' + c.map((x) => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>' + (rs.length ? rs.map((r) => '<tr>' + r.map((x) => '<td>' + esc(x) + '</td>').join('') + '</tr>').join('') : '<tr><td colspan="' + c.length + '">None</td></tr>') + '</tbody></table>';
    let h = '<!doctype html><html><head><meta charset="utf-8"><title>' + esc(a.title) + '</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;margin:32px;max-width:1000px}h1{font-size:21px;margin:0}h2{font-size:16px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:22px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef2f7;color:#111}.muted{color:#555}img.logo{max-height:46px}</style></head><body>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center">' + (brand.logo_url ? '<img class="logo" src="' + esc(brand.logo_url) + '" alt="">' : '<b>' + esc(brand.name) + '</b>') + '<span class="muted">Generated ' + esc(iso().slice(0, 16).replace('T', ' ')) + ' UTC by ' + esc(who.user) + '</span></div>';
    h += '<h1>Risk assessment: ' + esc(a.title) + '</h1><div class="muted">' + esc(d.process_name + (a.period ? ' · ' + a.period : '') + ' · status ' + a.status + (a.owner ? ' · owner ' + a.owner : '')) + '</div>';
    h += '<h2>1. Objective and scope</h2><p>' + esc(a.objective || '-') + '</p><p><b>Scope:</b> ' + esc(a.scope || '-') + '</p>' + (d.areas.length ? '<p><b>Focus areas:</b> ' + esc(d.areas.join('; ')) + '</p>' : '');
    h += '<h2>2. Overall rating</h2><p><b>' + esc(d.band === 'not_rated' ? 'Not rated' : d.band) + '</b>' + (d.rating != null ? ' (' + esc(d.rating) + ')' : '') + ' - ' + esc(d.rating_note) + '</p>';
    h += '<h2>3. Findings</h2>' + tbl(cols, d.findings.map(row));
    h += '<h2>4. Action plan</h2>' + tbl(['Recommendation', 'Owner', 'Due', 'Status', 'GRC action'], d.findings.filter((f) => f.status !== 'closed').map((f) => [f.recommendation, f.owner || '', f.due || '', f.status, f.grc_action || '']));
    h += '<h2>5. Sign-off</h2><p>Prepared by ' + esc(d.history.by) + '. ' + (d.history.approved_by ? 'Approved by ' + esc(d.history.approved_by) + ' on ' + esc(String(d.history.approved_at).slice(0, 10)) + '.' : 'Not yet approved.') + '</p>';
    return { filename: 'risk-assessment-' + a.id + '.html', html: h + '</body></html>' };
  }
  return { view, detail, create, putFinding, raiseAction, submit, approve, reopen, report, PROC };
}

function registerProcessAssessment(srv, app, P0) {
  const P = P0 && P0.view ? P0 : createProcessAssessment(app, P0 || {});
  app.addons = app.addons || {}; app.addons.processAssessment = P;
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/process-assessment', (ctx) => { ctx.need('operator'); return P.view(); });
  srv.route('GET', '/process-assessment/:id/report', (ctx) => { ctx.need('operator'); return P.report(ctx.params.id, ctx.query || {}, who(ctx)); });
  srv.route('GET', '/process-assessment/:id', (ctx) => { ctx.need('operator'); return P.detail(ctx.params.id); });
  srv.route('POST', '/process-assessment', (ctx) => { ctx.need('operator'); return P.create(ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('POST', '/process-assessment/:id/findings', (ctx) => { ctx.need('operator'); return P.putFinding(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('POST', '/process-assessment/:id/findings/:fid/action', (ctx) => { ctx.need('operator'); return P.raiseAction(ctx.params.id, ctx.params.fid, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/process-assessment/:id/submit', (ctx) => { ctx.need('operator'); return P.submit(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/process-assessment/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return P.approve(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/process-assessment/:id/reopen', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return P.reopen(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 1024 });
  return P;
}
module.exports = { createProcessAssessment, registerProcessAssessment, PROC };
