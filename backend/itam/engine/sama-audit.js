// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
const G = require('./ai-guard');
/*
 * SAMA CSF Audit ({P} = /api/itam) - the audit workflow on top of the automated SAMA CSF + IA assessment (engine/sama-ia.js).
 * The assessment decides what is met (from GRC, hardening, pentest / VAPT, SIEM and operations evidence, or a confirmation a
 * second person approved); this module tracks closing what is not:
 *
 *   Implementation by domain     implemented / not implemented / not applicable / rate, per SAMA domain and the IA items -
 *                                from the assessment only (a gap closed on paper is shown beside it, never counted as met)
 *   Gap remediation tracker      every requirement the assessment does not show as met: owner, due date, plan, notes, status
 *                                open → in progress → closure requested (with the evidence relied on) → closed by the CISO or
 *                                an administrator who did not request it (four eyes; service and AI identities never close).
 *                                A closed gap the assessment still shows as not met reads "closed - not yet verified"; a gap
 *                                closed while verified that is a gap again reads "regressed after closure".
 *   Machine learning             closure forecast: least-squares line over the daily count of open gaps (3+ days), the day it
 *                                reaches zero if it is falling; due-date risk per open gap: how often the team's own closed gaps
 *                                took longer than this one has left, given its age (needs 5+ closed gaps; Beta(1,1)-smoothed);
 *                                priority = the assessment's priority (severity x distance x chance of a gap) + 1 when overdue.
 *   AI audit memo                the internal-audit memo (findings, risk, recommendation, management actions) drafted by the
 *                                rules, or by Claude with read-only tools over the tracker (role-filtered, re-checked, ids
 *                                validated, untrusted framing, budgeted); the CISO / an administrator who did not request it
 *                                approves it.
 *
 *   GET  /sama-audit                       viewer    the audit view (owners' and approvers' names for operator / admin only)
 *   GET  /sama-audit/export                operator  the official-sheet rows                                       audited
 *   POST /sama-audit/gaps/:id              operator  {owner?, due?, status?: open|in_progress, plan?, note?}           audited
 *   POST /sama-audit/gaps/:id/close        operator  {evidence, note?}  request closure                             audited
 *   POST /sama-audit/gaps/:id/decide       operator  CISO / admin, not the requester: {decision: approve|reject, note?} audited
 *   POST /sama-audit/gaps/:id/reopen       operator  {reason}                                                       audited
 *   POST /sama-audit/memo                  operator  {use_ai?}  draft the audit memo                                  audited
 *   GET  /sama-audit/memos                 operator
 *   POST /sama-audit/memos/:id/decide      operator  CISO / admin, not the requester: {decision, note?}             audited
 */
const RID = /^(?:SA-3\.[1-4]\.\d{1,2}-\d{2}|IA-277-\d{2})$/;
const OK = ['verified', 'met'];
const DOMAINS = { '3.1': 'Leadership and Governance', '3.2': 'Risk Management and Compliance', '3.3': 'Operations and Technology', '3.4': 'Third Party Cyber Security', IA: 'Insurance Authority items' };
const STATES = ['open', 'in_progress', 'closure_requested', 'closed'];
const DUE_DAYS = { high: 30, medium: 90, low: 180 };
const HORIZONS = ['30 days', '90 days', '180 days'];
const DAY = 86400000, MODEL = 'claude-opus-5-5', MAX_TURNS = 6;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();
const s = (x, n) => String(x == null ? '' : x).slice(0, n);

/* pure: least-squares line over [t, y] points → {slope_per_day, zero_at} */
function lsq(pts) {
  const n = pts.length; if (n < 3) return null;
  const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n;
  const sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0); if (!sxx) return null;
  const slope = pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx;
  return { slope, intercept: my - slope * mx };
}
/* pure: chance a gap of `ageDays` with `leftDays` to its due date misses it, from the team's closed durations */
function missChance(durations, ageDays, leftDays) {
  const older = durations.filter((d) => d > ageDays);        // gaps that were still open at this age
  if (durations.length < 5) return { p: null, why: 'needs 5 closed gaps to learn from (' + durations.length + ' so far)' };
  const late = older.filter((d) => d > ageDays + leftDays).length;
  const p = (late + 1) / (older.length + 2);                 // Beta(1,1) posterior mean
  return { p: Math.round(p * 100) / 100, why: late + ' of ' + older.length + ' closed gap(s) still open at ' + Math.round(ageDays) + ' days took longer than the ' + Math.max(0, Math.round(leftDays)) + ' day(s) left' };
}

function createSamaAudit(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, col = (n) => store.collection(n);
  const iso = () => new Date(now()).toISOString();
  const day = (ms) => new Date(ms + 3 * 3600000).toISOString().slice(0, 10);   // Riyadh day
  const gapsC = () => col('sama_audit_gaps'), dailyC = () => col('sama_audit_daily'), memoC = () => col('sama_audit_memos');
  const L = app.log || { every() {}, warn() {}, info() {} };
  const warn = (key, msg, err) => { if (L.every) L.every('sama-audit:' + key, 3600000, 'warn', msg, { err: s((err && err.message) || err, 200) }); };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'sama_audit.' + action, target, detail }); };
  const SA = () => opts.samaIa || (app.addons && app.addons.samaIa);
  const eccProfile = () => { try { return col('ecc_profile').get('profile') || {}; } catch (e) { warn('eccp', 'SAMA audit: the NCA ECC profile was not read', e); return {}; } };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const ciso = (who) => who.role === 'admin' || same(eccProfile().ciso_user, who.user);
  const needCiso = (who, what) => { person(who, what); if (!ciso(who)) throw httpErr(403, what + ' needs the CISO named in the NCA ECC profile or an administrator'); };

  async function assess() {
    const S = SA(); if (!S) throw httpErr(409, 'the SAMA CSF assessment is not installed - run the update');
    return S.assess();
  }
  const domOf = (r) => (r.domain === 'IA' || /^IA-/.test(r.id) ? 'IA' : r.domain || r.subdomain.slice(0, 3));
  const isGap = (r) => !OK.includes(r.result) && r.result !== 'not_applicable';

  function build(v) {
    const t = now(), rows = v.requirements.concat(v.ia.requirements), T = {}; for (const g of gapsC().all(() => true)) T[g.id] = g;
    const pri = {}; for (const p of v.priorities || []) pri[p.id] = p;
    const durations = Object.values(T).filter((g) => g.status === 'closed' && g.closed_at && g.opened_at).map((g) => (Date.parse(g.closed_at) - Date.parse(g.opened_at)) / DAY);
    const gaps = [];
    for (const r of rows) {
      const tr = T[r.id];
      if (!isGap(r) && !tr) continue;   // met by the assessment and never tracked: nothing to remediate
      const g = tr || { id: r.id, status: 'open', owner: '', due: '', plan: '', history: [], opened_at: null };
      const opened = g.opened_at ? Date.parse(g.opened_at) : t, ageDays = (t - opened) / DAY;
      const dueMs = g.due ? Date.parse(g.due + 'T23:59:59+03:00') : null, leftDays = dueMs ? (dueMs - t) / DAY : null;
      let verification = null;
      if (g.status === 'closed') verification = isGap(r) ? (g.verified_at_close ? 'regressed_after_closure' : 'closed_not_verified') : 'verified';
      else if (!isGap(r)) verification = 'met_by_assessment';
      const overdue = g.status !== 'closed' && dueMs != null && t > dueMs;
      const p = pri[r.id];
      const risk = g.status !== 'closed' && dueMs != null ? missChance(durations, ageDays, leftDays) : { p: null, why: dueMs ? '' : 'no due date' };
      const why = (p ? p.why.slice() : [r.severity + ' severity', r.result.replace(/_/g, ' ')]); if (overdue) why.push('overdue');
      gaps.push({ id: r.id, domain: domOf(r), subdomain: r.subdomain, subdomain_name: r.subdomain_name, title: r.title, pillar: r.pillar_name, severity: r.severity,
        result: r.result, why_result: r.why, evidence_hint: r.evidence_hint, recommend: r.recommend || null, automated: r.automated,
        status: g.status, owner: g.owner || '', due: g.due || '', plan: g.plan || '', closure: g.closure || null, closed_by: g.closed_by || '', closed_at: g.closed_at || null,
        history: (g.history || []).slice(-30), opened_at: g.opened_at, tracked: !!tr, age_days: Math.round(ageDays), left_days: leftDays == null ? null : Math.round(leftDays),
        overdue, verification, priority: Math.round(((p ? p.score : 1) + (overdue ? 1 : 0)) * 100) / 100, priority_why: why, miss: risk });
    }
    gaps.sort((a, b) => (a.status === 'closed') - (b.status === 'closed') || b.priority - a.priority);
    // implementation by domain - from the assessment
    const domains = Object.keys(DOMAINS).map((d) => {
      const rs = rows.filter((r) => domOf(r) === d), na = rs.filter((r) => r.result === 'not_applicable').length, impl = rs.filter((r) => OK.includes(r.result)).length;
      const not = rs.length - na - impl, paper = gaps.filter((g) => g.domain === d && g.status === 'closed' && g.verification !== 'verified').length;
      return { id: d, name: DOMAINS[d], requirements: rs.length, implemented: impl, not_implemented: not, not_applicable: na, rate: rs.length - na ? Math.round(100 * impl / (rs.length - na)) : null, closed_not_verified: paper };
    });
    const app_ = rows.filter((r) => r.result !== 'not_applicable'), implN = app_.filter((r) => OK.includes(r.result)).length;
    const open = gaps.filter((g) => g.status !== 'closed');
    const kpis = { rate: app_.length ? Math.round(100 * implN / app_.length) : null, requirements: app_.length, implemented: implN,
      gaps: gaps.length, open: open.filter((g) => g.status === 'open').length, in_progress: open.filter((g) => g.status === 'in_progress').length,
      closure_requested: open.filter((g) => g.status === 'closure_requested').length, closed: gaps.filter((g) => g.status === 'closed').length,
      overdue: open.filter((g) => g.overdue).length, unassigned: open.filter((g) => !g.owner).length,
      closed_not_verified: gaps.filter((g) => g.verification === 'closed_not_verified').length, regressed: gaps.filter((g) => g.verification === 'regressed_after_closure').length,
      high_risk_due: open.filter((g) => g.miss.p != null && g.miss.p >= 0.5).length };
    // closure forecast from the daily open-gap count
    const pts = dailyC().all(() => true).sort((a, b) => a.at - b.at).slice(-60).map((x) => [x.at / DAY, x.open]);
    const fit = lsq(pts);
    let forecast;
    if (!fit) forecast = { days: pts.length, note: 'a forecast needs 3 daily counts or more (' + pts.length + ' so far)' };
    else {
      const perWeek = Math.round(-fit.slope * 7 * 10) / 10, last = pts[pts.length - 1];
      const zero = fit.slope < 0 ? Math.round((last[1] / -fit.slope + last[0]) * DAY) : null;
      forecast = { days: pts.length, closed_per_week: perWeek, all_closed_by: zero ? day(zero) : null,
        note: fit.slope < 0 ? 'open gaps are falling by about ' + perWeek + ' a week; at that pace the last closes around ' + day(zero) : 'open gaps are not falling - at this pace they will not all close' };
    }
    const attention = [];
    for (const g of open) if (g.overdue) attention.push({ level: 'bad', id: g.id, text: g.id + ' is overdue (due ' + g.due + ')' + (g.owner ? '' : ' and has no owner') });
    for (const g of gaps) if (g.verification === 'regressed_after_closure') attention.push({ level: 'bad', id: g.id, text: g.id + ' was closed and verified, and the assessment shows it as a gap again' });
    for (const g of open) if (g.status === 'closure_requested') attention.push({ level: 'warn', id: g.id, text: g.id + ' waits for the CISO / an administrator to confirm its closure' });
    for (const g of open) if (!g.overdue && g.miss.p != null && g.miss.p >= 0.5) attention.push({ level: 'warn', id: g.id, text: g.id + ' will probably miss its due date (' + Math.round(g.miss.p * 100) + ' %): ' + g.miss.why });
    for (const g of gaps) if (g.verification === 'closed_not_verified') attention.push({ level: 'info', id: g.id, text: g.id + ' is closed, but the assessment does not show it met yet - connect the evidence source or record a confirmation in SAMA CSF Assessment' });
    const rank = { bad: 0, warn: 1, info: 2 }; attention.sort((a, b) => rank[a.level] - rank[b.level]);
    // maturity per subdomain (indicative level from the assessment's evidence, against the level-3 minimum) + the open gaps behind it
    const subdomains = (v.subdomains || []).map((x) => {
      const og = gaps.filter((g) => g.subdomain === x.id && g.status !== 'closed');
      return { id: x.id, name: x.name, domain: x.domain, level: x.maturity ? x.maturity.level : null, level_name: x.maturity ? x.maturity.name : '', why: x.maturity ? x.maturity.why : '',
        below_target: !!x.below_target, decide: !!x.decide, score: x.score == null ? null : x.score, open_gaps: og.length, overdue: og.filter((g) => g.overdue).length,
        owners: [...new Set(og.map((g) => g.owner).filter(Boolean))].slice(0, 4) };
    });
    kpis.below_target = subdomains.filter((x) => x.below_target).length; kpis.at_target = subdomains.filter((x) => x.level != null && x.level >= v.target_level).length;
    kpis.not_assessed = subdomains.filter((x) => x.level == null).length;
    return { framework: v.framework, target_level: v.target_level, levels: v.levels || null, subdomains, score: v.overall.score, readiness: v.readiness, trend: v.trend, kpis, domains, gaps, attention: attention.slice(0, 40), forecast,
      learn: { closed_durations: durations.length, median_days_to_close: durations.length ? Math.round(durations.slice().sort((a, b) => a - b)[Math.floor(durations.length / 2)]) : null },
      ia: { name: v.ia.name, circular: v.ia.circular }, generated_at: iso() };
  }
  function forViewer(out) {   // owners, requesters and approvers are names (PDPL): a viewer sees the state, not who
    const strip = (g) => Object.assign({}, g, { owner: g.owner ? 'assigned' : '', closed_by: g.closed_by ? 'a second person' : '', closure: g.closure ? { at: g.closure.at } : null, history: [] });
    return Object.assign({}, out, { gaps: out.gaps.map(strip), subdomains: out.subdomains.map((x) => Object.assign({}, x, { owners: x.owners.length ? ['assigned'] : [] })) });
  }
  async function view(who) { const out = build(await assess()); return who && who.role === 'viewer' ? forViewer(out) : out; }

  // ---- the tracker
  async function gapRow(id) {
    const v = await assess(), r = v.requirements.concat(v.ia.requirements).find((x) => x.id === id);
    if (!r) throw httpErr(404, 'no SAMA requirement ' + id);
    return { v, r };
  }
  function rec(id, r) {
    return gapsC().get(id) || { id, status: 'open', owner: '', due: '', plan: '', history: [], opened_at: iso(), severity: r.severity };
  }
  const idOf = (id0) => { const id = param(id0, 'id'); if (!RID.test(id)) throw httpErr(400, 'id must be a SAMA requirement (e.g. SA-3.3.8-01) or IA-277-01'); return id; };
  function snapshot() {
    try { const all = gapsC().all(() => true); dailyC().put({ id: day(now()), at: now(), open: all.filter((g) => g.status !== 'closed').length, closed: all.filter((g) => g.status === 'closed').length }); }
    catch (e) { warn('daily', 'SAMA audit: the daily count was not kept', e); }
  }
  async function update(id0, input, who) {
    person(who, 'update a SAMA gap');
    const id = idOf(id0);
    const b = body(input || {}).str('owner', { max: 120 }).date('due').oneOf('status', ['open', 'in_progress']).str('plan', { max: 2000 }).str('note', { max: 1000 })
      .rule((o) => (Object.keys(o).length ? null : 'nothing to change: give owner, due, status, plan or note')).done();
    const { r } = await gapRow(id), g = rec(id, r);
    if (g.status === 'closed') throw httpErr(409, id + ' is closed - reopen it first');
    if (g.status === 'closure_requested' && b.status) throw httpErr(409, id + ' waits for its closure to be confirmed - the CISO approves or rejects it');
    if (!isGap(r) && !gapsC().get(id)) throw httpErr(409, id + ' is met by the assessment - there is nothing to remediate');
    const changed = {};
    for (const k of ['owner', 'due', 'status', 'plan']) if (b[k] !== undefined && b[k] !== g[k]) { changed[k] = k === 'plan' ? 'updated' : b[k]; g[k] = b[k]; }
    if (!g.due && !b.due) { g.due = day(now() + (DUE_DAYS[r.severity] || 90) * DAY); changed.due = g.due + ' (default for ' + r.severity + ')'; }
    g.history = (g.history || []).concat([{ at: iso(), by: who.user, what: Object.keys(changed).map((k) => k + ' ' + changed[k]).join(', ') || 'note', note: b.note || '' }]).slice(-100);
    gapsC().put(g); snapshot();
    audit(who, 'gap.update', id, changed);
    return (build((await gapRow(id)).v).gaps.find((x) => x.id === id));
  }
  async function requestClose(id0, input, who) {
    person(who, 'request closing a SAMA gap');
    const id = idOf(id0), b = body(input || {}).str('evidence', { required: true, min: 5, max: 500 }).str('note', { max: 1000 }).done();
    const { r } = await gapRow(id), g = rec(id, r);
    if (g.status === 'closed') throw httpErr(409, id + ' is already closed');
    if (g.status === 'closure_requested') throw httpErr(409, id + ' already waits for its closure to be confirmed');
    g.status = 'closure_requested'; g.closure = { by: who.user, at: iso(), evidence: b.evidence, note: b.note || '', assessment: r.result };
    g.history = (g.history || []).concat([{ at: iso(), by: who.user, what: 'closure requested', note: 'evidence: ' + b.evidence }]).slice(-100);
    gapsC().put(g); snapshot();
    audit(who, 'gap.close_request', id, { evidence: 'given', assessment: r.result });
    return (build((await gapRow(id)).v).gaps.find((x) => x.id === id));
  }
  async function decideClose(id0, input, who) {
    const id = idOf(id0), b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the closure is rejected' : null)).done();
    const g = gapsC().get(id); if (!g || g.status !== 'closure_requested') throw httpErr(409, id + ' has no closure waiting for a decision');
    needCiso(who, 'confirming a SAMA gap closure');
    if (same(g.closure.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested closing ' + id + ' and cannot also confirm it');
    const { r } = await gapRow(id);
    if (b.decision === 'approve') { Object.assign(g, { status: 'closed', closed_by: who.user, closed_at: iso(), verified_at_close: !isGap(r) }); }
    else { g.status = 'in_progress'; }
    g.history = (g.history || []).concat([{ at: iso(), by: who.user, what: 'closure ' + (b.decision === 'approve' ? 'confirmed' : 'rejected'), note: b.note || '' }]).slice(-100);
    gapsC().put(g); snapshot();
    audit(who, 'gap.close_' + b.decision, id, { requested_by: g.closure.by, assessment: r.result, verified: b.decision === 'approve' ? !isGap(r) : undefined });
    return (build((await gapRow(id)).v).gaps.find((x) => x.id === id));
  }
  async function reopen(id0, input, who) {
    person(who, 'reopen a SAMA gap');
    const id = idOf(id0), b = body(input || {}).str('reason', { required: true, min: 5, max: 1000 }).done();
    const g = gapsC().get(id); if (!g || g.status !== 'closed') throw httpErr(409, id + ' is not closed');
    Object.assign(g, { status: 'in_progress', reopened_at: iso(), closed_by: '', closed_at: null, verified_at_close: false });
    g.history = (g.history || []).concat([{ at: iso(), by: who.user, what: 'reopened', note: b.reason }]).slice(-100);
    gapsC().put(g); snapshot();
    audit(who, 'gap.reopen', id, { reason: b.reason });
    return (build((await gapRow(id)).v).gaps.find((x) => x.id === id));
  }
  async function exportRows(who) {
    const v = await assess(), out = build(v), rows = v.requirements.concat(v.ia.requirements), G2 = {}; for (const g of out.gaps) G2[g.id] = g;
    const q = (x) => { const t = String(x == null ? '' : x); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };
    const sheet = [['Ref', 'Domain', 'Subdomain', 'Subdomain name', 'Requirement', 'Severity', 'Assessment', 'Why', 'Gap status', 'Owner', 'Due', 'Plan', 'Closure evidence', 'Closed by', 'Verified by the assessment']];
    for (const r of rows) { const g = G2[r.id] || {}; sheet.push([r.id, DOMAINS[domOf(r)], r.subdomain, r.subdomain_name, r.title, r.severity, r.result, s(r.why, 500), g.status || (r.result === 'not_applicable' ? 'not applicable' : 'implemented'), g.owner || '', g.due || '', s(g.plan, 500), g.closure ? g.closure.evidence : '', g.closed_by || '', g.verification === 'verified' || OK.includes(r.result) ? 'yes' : g.status ? 'no' : ''].map(q)); }
    audit(who, 'export', 'sheet', { rows: sheet.length - 1 });
    return { filename: 'sama-csf-audit-' + iso().slice(0, 10) + '.xlsx', sheets: [{ name: 'SAMA CSF audit', rows: sheet }, { name: 'By domain', rows: [['Domain', 'Requirements', 'Implemented', 'Not implemented', 'Not applicable', 'Rate %', 'Closed, not yet verified']].concat(out.domains.map((d) => [d.id + ' ' + d.name, d.requirements, d.implemented, d.not_implemented, d.not_applicable, d.rate == null ? '' : d.rate, d.closed_not_verified])) }] };
  }
  const tick = guardOf(app, 'sama-audit.daily', async () => { if (!dailyC().get(day(now()))) snapshot(); });
  let timer = null;
  function start() { if (opts.noTimer || app.noTimers || timer) return; timer = setInterval(tick, 3 * 3600000); if (timer.unref) timer.unref(); setTimeout(tick, 150000).unref(); }

  // ---- the audit memo (rules, or Claude with read-only tools)
  const cfg = () => (app.config && app.config.ia_ai) || {};
  const getKey = opts.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file); } catch (e) { warn('key', 'SAMA audit: the API key could not be read', e); return ''; } });
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfg().sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it)' : s(e.message, 200); }
    }
    return null;
  }
  function aiStatus() {
    const model = cfg().model || MODEL;
    let allowed = false; try { allowed = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { allowed = false; /* settings unreadable = not allowed */ }
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine) - the memo is drafted by the rules only', model };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key) - the memo is drafted by the rules only', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model };
    return { enabled: true, model };
  }
  const horizonOf = (sev) => (sev === 'high' ? '30 days' : sev === 'medium' ? '90 days' : '180 days');
  function ruleMemo(out) {
    const k = out.kpis, open = out.gaps.filter((g) => g.status !== 'closed');
    return {
      summary: ('Internal audit of ' + ZYB_ORG.short + ' against the SAMA Cyber Security Framework (with the Insurance Authority items, circular ') + out.ia.circular + ') on ' + iso().slice(0, 10) + ': ' + k.implemented + ' of ' + k.requirements + ' applicable requirements are implemented on the evidence (' + k.rate + ' %). '
        + k.gaps + ' gap(s) are tracked: ' + k.open + ' open, ' + k.in_progress + ' in progress, ' + k.closure_requested + ' awaiting confirmation, ' + k.closed + ' closed' + (k.closed_not_verified ? ' (' + k.closed_not_verified + ' closed but not yet verified by the assessment)' : '') + '. '
        + (k.overdue ? k.overdue + ' are overdue. ' : '') + (out.forecast.all_closed_by ? 'At the current pace the last gap closes around ' + out.forecast.all_closed_by + '. ' : out.forecast.note + '. ') + 'Indicative, from the platform register - not SAMA\'s or the external auditor\'s opinion.',
      findings: open.slice(0, 12).map((g) => ({ id: g.id, finding: g.title + ' - ' + s(g.why_result, 300), risk: g.severity, recommendation: g.recommend || ('Close with: ' + (g.evidence_hint || 'the record') + '.') })),
      management_actions: open.slice(0, 12).map((g) => ({ id: g.id, action: (g.plan || 'Remediate ' + g.id + ': ' + g.title).slice(0, 300), horizon: horizonOf(g.severity), owner: g.owner ? 'assigned' : 'owner to be named' })),
    };
  }
  const TOOLS = [
    { name: 'list_gaps', roles: ['operator', 'admin'], description: 'List tracked SAMA gaps with status, severity, due date and priority, optionally filtered by status or domain.',
      input_schema: { type: 'object', properties: { status: { type: 'string', enum: STATES }, domain: { type: 'string', enum: Object.keys(DOMAINS) } }, additionalProperties: false } },
    { name: 'get_gap', roles: ['operator', 'admin'], description: 'One gap: the requirement, why the assessment does not show it met, the plan, the history, the due-date risk.',
      input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false } },
  ];
  function runTool(out, who, name, input) {
    const t = TOOLS.find((x) => x.name === name);
    if (!t || !t.roles.includes(who.role)) return { error: 'tool not available: ' + s(name, 40) };   // re-checked on every call
    const i = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    if (name === 'list_gaps') {
      if (i.status !== undefined && !STATES.includes(i.status)) return { error: 'status must be one of ' + STATES.join(', ') };
      return out.gaps.filter((g) => (!i.status || g.status === i.status) && (!i.domain || g.domain === i.domain)).slice(0, 60).map((g) => ({ id: g.id, title: g.title, severity: g.severity, status: g.status, result: g.result, due: g.due, overdue: g.overdue, priority: g.priority }));
    }
    if (!RID.test(String(i.id || ''))) return { error: 'id must look like SA-3.3.8-01' };
    const g = out.gaps.find((x) => x.id === i.id); if (!g) return { error: 'no tracked gap ' + i.id };
    return { id: g.id, subdomain: g.subdomain + ' ' + g.subdomain_name, title: g.title, severity: g.severity, result: g.result, why: s(g.why_result, 400), plan: s(g.plan, 600), status: g.status, due: g.due, overdue: g.overdue, miss: g.miss, verification: g.verification };
  }
  const str = (x, n) => (typeof x === 'string' ? x.slice(0, n) : '');
  function checkMemo(o, out, flags) {   // the model's answer is data: keep only the declared fields and requirement ids that exist
    const ids = new Set(out.gaps.map((g) => g.id));
    const keep = (arr, what) => (Array.isArray(arr) ? arr : []).slice(0, 20).filter((x) => (x && ids.has(x.id) ? true : (flags.push('dropped a ' + what + ' naming an unknown requirement'), false)));
    const m = { summary: str(o.summary, 3000),
      findings: keep(o.findings, 'finding').map((x) => ({ id: x.id, finding: str(x.finding, 600), risk: ['high', 'medium', 'low'].includes(x.risk) ? x.risk : 'medium', recommendation: str(x.recommendation, 600) })),
      management_actions: keep(o.management_actions, 'action').filter((x) => (HORIZONS.includes(x.horizon) ? true : (flags.push('dropped an action with an unknown horizon'), false))).map((x) => ({ id: x.id, action: str(x.action, 400), horizon: x.horizon, owner: 'to be confirmed by management' })) };
    if (!m.summary) throw httpErr(502, 'the AI did not return a usable memo - the rule-based memo is still available');
    return m;
  }
  async function aiMemo(out, who) {
    const st = aiStatus(); if (!st.enabled) throw httpErr(503, st.reason);
    const flags = [], tools = TOOLS.filter((t) => t.roles.includes(who.role)).map(({ name, description, input_schema }) => ({ name, description, input_schema }));
    const ctx = JSON.stringify({ kpis: out.kpis, domains: out.domains, forecast: out.forecast, top: out.gaps.filter((g) => g.status !== 'closed').slice(0, 15).map((g) => ({ id: g.id, title: g.title, severity: g.severity, status: g.status, overdue: g.overdue, priority: g.priority })) });
    const sys = ('You are the AI internal auditor of ' + ZYB_ORG.name + ', a Saudi insurer regulated by the Insurance Authority under the SAMA Cyber Security Framework. ')
      + 'You draft the internal-audit memo on the SAMA CSF gap remediation from the platform\'s tracker; the CISO approves it. Use only the tracker and your read-only tools. Never change or invent a figure, a status, a date or a requirement; '
      + 'figures are fixed by the platform. Write findings in audit style (condition, risk, recommendation). Answer with ONE JSON object with exactly the keys summary, findings (array of {id, finding, risk: high|medium|low, recommendation}), '
      + 'management_actions (array of {id, action, horizon: "30 days"|"90 days"|"180 days"}).\n\n' + G.UNTRUSTED_RULE;
    const messages = [{ role: 'user', content: G.redactSecrets('Draft the SAMA CSF internal-audit memo. The tracker summary:\n\n' + G.untrusted('sama-audit:tracker', ctx)) }];
    flags.push(...G.injectionSignals(ctx).map((n) => 'injection-like text in the tracker (signal ' + n + ')'));
    const budget = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfg().timeout_s || 180) * 1000, maxRetries: 2 });
    let text = '', calls = 0;
    for (let turn = 0; turn < MAX_TURNS; turn++) {
      budget.admit(who.user, 'itam.sama-audit-memo', JSON.stringify(messages).length);
      let resp = null, usage = null;
      try { resp = await client.messages.create({ model: st.model, max_tokens: 6000, system: sys, tools, messages }); usage = resp.usage; }
      finally { budget.record(who.user, 'itam.sama-audit-memo', usage, flags); }
      const uses = (resp.content || []).filter((c) => c.type === 'tool_use');
      text = (resp.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
      if (!uses.length || resp.stop_reason !== 'tool_use') break;
      messages.push({ role: 'assistant', content: resp.content });
      messages.push({ role: 'user', content: uses.map((u) => { calls++; const o2 = JSON.stringify(runTool(out, who, u.name, u.input)); flags.push(...G.injectionSignals(o2).map((n) => 'injection-like text in ' + u.name + ' output (signal ' + n + ')')); return { type: 'tool_result', tool_use_id: u.id, content: G.untrusted('sama-audit:' + u.name, G.redactSecrets(o2)) }; }) });
      if (turn === MAX_TURNS - 1) flags.push('stopped after ' + MAX_TURNS + ' turns');
    }
    const m = text.match(/\{[\s\S]*\}/); let o = null; try { o = m ? JSON.parse(m[0]) : null; } catch (e) { o = null; /* not JSON: reported as unusable below */ }
    if (!o || typeof o !== 'object') throw httpErr(502, 'the AI did not return a usable memo - the rule-based memo is still available');
    return { content: checkMemo(o, out, flags), flags, tool_calls: calls };
  }
  async function memo(input, who) {
    person(who, 'draft the SAMA audit memo');
    const b = body(input || {}).bool('use_ai', { def: false }).done();
    const out = build(await assess());
    let content = ruleMemo(out), source = 'rules', flags = [], calls = 0;
    if (b.use_ai) { const a = await aiMemo(out, who); content = a.content; source = 'ai'; flags = a.flags; calls = a.tool_calls; }
    const n = memoC().all(() => true).length + 1;
    const d = Object.assign({ id: 'SAMA-AM-' + String(n).padStart(4, '0'), state: 'draft', source, flags, tool_calls: calls, figures: { kpis: out.kpis, domains: out.domains, forecast: out.forecast }, requested_by: who.user, at: iso() }, content);
    memoC().put(d);
    audit(who, 'memo.draft', d.id, { source, flags: flags.length, tool_calls: calls });
    return d;
  }
  async function decideMemo(id0, input, who) {
    const id = param(id0, 'id'); const d = memoC().get(id); if (!d) throw httpErr(404, 'no memo ' + s(id, 30));
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    if (d.state !== 'draft') throw httpErr(409, d.id + ' is ' + d.state);
    needCiso(who, 'approving the SAMA audit memo');
    if (same(d.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested ' + d.id + ' and cannot also approve it');
    Object.assign(d, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decide_note: b.note || '' });
    memoC().put(d);
    audit(who, 'memo.' + d.state, d.id, { requested_by: d.requested_by, source: d.source });
    return d;
  }
  const memos = () => ({ items: memoC().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 30), ai: aiStatus() });
  return { view, update, requestClose, decideClose, reopen, exportRows, memo, decideMemo, memos, aiStatus, tick, start, snapshot, TOOLS };
}

function registerSamaAudit(srv, app, S) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };
  srv.route('GET', '/sama-audit', (ctx) => { ctx.need('viewer'); return S.view(ctx.who); });
  srv.route('GET', '/sama-audit/export', op((ctx) => S.exportRows(ctx.who)));
  srv.route('POST', '/sama-audit/gaps/:id', op((ctx) => S.update(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/sama-audit/gaps/:id/close', op((ctx) => S.requestClose(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/sama-audit/gaps/:id/decide', op((ctx) => S.decideClose(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/sama-audit/gaps/:id/reopen', op((ctx) => S.reopen(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/sama-audit/memo', op((ctx) => S.memo(ctx.body, ctx.who)));
  srv.route('GET', '/sama-audit/memos', op(() => S.memos()));
  srv.route('POST', '/sama-audit/memos/:id/decide', op((ctx) => S.decideMemo(ctx.params.id, ctx.body, ctx.who)));
}

module.exports = { createSamaAudit, registerSamaAudit, lsq, missChance };
