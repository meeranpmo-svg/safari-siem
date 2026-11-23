// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * SAMA IT Audit ({P} = /api/itam, Audit -> SAMA IT Audit): is the organisation ready for a SAMA IT audit, area by area, from evidence
 * the platform already holds - never from a questionnaire.
 *   areas      information security governance · cyber risk management · data protection and privacy · incident management and
 *              response · business continuity and disaster recovery · the audit process itself (plan, test controls, report,
 *              monitor continuously)
 *   evidence   the IT Audit team (approved plan, engagements, final reports), the asset register (business-critical systems),
 *              Ownership, the Reporting Center (executive report to senior management), the VAPT Center (SLA, critical), the
 *              testing cadence + Greenbone scans, GRC policy reviews, Certificates, Access Reviews, the PDPL self-assessment,
 *              Notification & Escalation (routing, learnt time to acknowledge), the PDPL breach regulator track, DR & BCM Drills,
 *              DR Studio, Backup Status, continuous control monitoring. A check without a source is NOT MEASURED, never a pass.
 *   ML         pyengine/sama_itaudit_rules.py: weighted readiness per area and overall over the measured checks, trend over the daily
 *              history (needs 5 days), the weakest area; every gap becomes a DRAFT audit finding (condition, criteria with the SAMA
 *              reference, cause, effect, recommendation, rating) that a person sends into an IT Audit engagement - where the
 *              engagement's own rules apply (fieldwork, auditee owner, independence, review).
 *   GET  /sama-itaudit                    operator  areas, checks, readiness, trend, draft findings, engagements to send to
 *   GET  /sama-itaudit/pack               operator  ?format=html|csv  the regulator-ready pack                      audited
 *   POST /sama-itaudit/findings/send      operator  {check, engagement, owner}  a person; IT Audit addFinding        audited
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const escH = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createSamaItAudit(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const A = () => app.addons || {};
  const histC = () => store.collection('sama_itaudit_hist');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'sama.itaudit.' + action, target, detail }); };
  const iso = () => new Date(now()).toISOString();
  const day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const tryv = async (fn) => { try { const r = await fn(); return r === undefined ? null : r; } catch (e) { return null; /* a source that cannot be read is "not measured" */ } };

  async function facts() {
    const f = {}, year = new Date(now() + RIYADH).getUTCFullYear(), IA = A().auditEngage;
    if (IA) {
      const P = await tryv(() => IA.plans()) || [];
      f.plan = { year, approved: P.some((p) => p.year === year && p.state === 'approved'), draft: P.some((p) => p.year === year && p.state === 'draft') };
      const E = (await tryv(() => IA.listEngagements())) || [], thisYear = E.filter((e) => String(e.start || '').startsWith(String(year)));
      f.engagements = { total: thisYear.length, active: thisYear.filter((e) => e.state !== 'cancelled').length, fieldwork_done: thisYear.filter((e) => ['draft_report', 'final'].includes(e.state)).length, final: thisYear.filter((e) => e.state === 'final').length };
    }
    f.critical_assets = await tryv(() => { const pol = (store.collection('pentest_settings').get('cadence') || {}).values || {}, ct = (pol.critical_tags || ['business-critical', 'critical', 'crown-jewel']).map((x) => String(x).toLowerCase()), tiers = store.collection('test_tier');
      return store.collection('assets').all((a) => a.status !== 'disposed').filter((a) => { const o = tiers.get(a.id); return o ? o.tier === 'critical' : (a.tags || []).some((t) => ct.includes(String(t).toLowerCase())); }).length; });
    const RC = A().reportCenter;
    if (RC) f.senior_reporting = await tryv(async () => { const h = await RC.home({ role: 'admin', user: 'svc:sama-itaudit' }); const ex = (h.schedules || []).filter((x) => x.enabled && x.report === 'executive');
      const ok = ex.some((x) => x.last && x.last.status === 'ok' && now() - x.last.at <= 35 * DAY);
      return { ok, evidence: ex.length ? ex.length + ' executive schedule(s); last delivered ' + (ex.map((x) => x.last && x.last.status === 'ok' ? day(x.last.at) : null).filter(Boolean).sort().pop() || 'never') : 'no executive report scheduled to senior management' }; });
    const OW = A().ownerStudio; if (OW) f.owners_pct = await tryv(async () => (await OW.view()).summary.both_pct);
    const VC = A().vaptCenter; if (VC) f.vapt = await tryv(async () => { const a = await VC.analysis(); return a && a.ok ? { open: a.open, critical: a.counts.critical, breached: a.sla.breached } : null; });
    const PT = A().pentest;
    if (PT && PT.cadence) f.testing = await tryv(() => { const sc = PT.cadence.schedule(), rows = Array.isArray(sc) ? sc : sc.rows || sc.items || []; let last = null; try { const v = A().vulnscan && A().vulnscan.view(); last = v && v.last_scan ? String(v.last_scan.at || v.last_scan.finished_at || v.last_scan).slice(0, 10) : null; } catch (e) { last = null; /* Greenbone not installed */ } return { overdue: rows.filter((r) => ['never', 'overdue'].includes(r.worst)).length, last_scan: last }; });
    const GR = A().grc; if (GR) f.policy_reviews = await tryv(() => GR.summary().reviews.overdue);
    const CE = A().certs; if (CE) f.certs = await tryv(() => CE.view('admin').counts);
    const AR = A().accessReviews; if (AR) f.access_review = await tryv(() => { const l = AR.list({ user: 'svc:sama-itaudit', role: 'admin' }); const closed = (l.campaigns || []).filter((c) => c.status === 'closed').map((c) => Date.parse(c.due_at || c.started_at)).filter(Number.isFinite).sort((a, b) => b - a); return { days_since: closed.length ? Math.round((now() - closed[0]) / DAY) : null }; });
    const PD = A().pdpl; if (PD) { f.pdpl_pct = await tryv(() => PD.view('admin').compliance_pct);
      f.breach = await tryv(() => { const br = PD.records('breach') || []; return { total: br.length, late: br.filter((b) => Object.values(b.regulators || {}).some((r) => r && r.required && !r.notified_at)).length }; }); }
    const NC = A().notifyCenter; if (NC) f.notify = await tryv(async () => { const v = NC.view({ role: 'admin' }); let med = null; try { const i = await NC.insights(); if (i && i.ok) { const xs = Object.values(i.teams).map((t) => t.median_min).filter((x) => x != null); med = xs.length ? Math.max(...xs) : null; } } catch (e) { med = null; /* not learnt yet */ }
      return { policies: v.policies.filter((p) => p.enabled).length, teams: v.teams.length, enabled: v.enabled, median_ack_min: med }; });
    if (GR && GR.drillList) f.drills = await tryv(() => { const L2 = GR.drillList({}).items || [], yr = L2.filter((d) => { const t = Date.parse(d.executed || ''); return Number.isFinite(t) && now() - t <= 365 * DAY; });
      return { done_12m: yr.length, passed_12m: yr.filter((d) => d.result === 'pass').length, failed_open: yr.filter((d) => d.result === 'fail' && d.status !== 'closed').length }; });
    const DR = A().drStudio; if (DR) f.dr_readiness = await tryv(async () => (await DR.view()).summary.readiness);
    const BK = A().backup; if (BK) f.backup_pct = await tryv(() => BK.view('admin').summary.coverage_pct);
    const CC = A().auditCcm; if (CC) f.ccm = await tryv(() => { const v = CC.view('admin'); const at = Date.parse((v.run && (v.run.at || v.run.finished_at)) || v.at || ''); return { run_days: Number.isFinite(at) ? Math.round((now() - at) / DAY) : null, exceptions: (v.summary && v.summary.exceptions) || 0 }; });
    return f;
  }
  let CACHE = null;
  async function assess(force) {
    if (!force && CACHE && now() - CACHE.at < 60000) return CACHE.r;
    const f = await facts();
    let r;
    try { r = await py().call('sama.itaudit', { facts: f, history: histC().all(() => true).sort((a, b) => a.day.localeCompare(b.day)).slice(-60), now: now() }); }
    catch (e) { r = { ok: false, error: 'the SAMA IT audit rules could not run: ' + s(e.message, 200) }; }
    if (r && r.ok && r.readiness.score != null) { const d = day(now()); histC().put({ id: d, day: d, score: r.readiness.score, areas: Object.fromEntries(r.areas.map((a) => [a.id, a.score])) }); }
    CACHE = { at: now(), r }; return r;
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'sama.itaudit.daily', async () => { if (!histC().get(day(now()))) await assess(true); }), 60 * 60000); if (tm.unref) tm.unref(); }

  async function view() {
    const r = await assess();
    const IA = A().auditEngage;
    const eng = IA ? ((await tryv(() => IA.listEngagements())) || []).filter((e) => ['fieldwork', 'draft_report'].includes(e.state)).map((e) => ({ id: e.id, title: e.title, state: e.state, auditee_owner: e.auditee_owner || null })) : [];
    return Object.assign({}, r, { engagements: eng, audit_installed: !!IA, history: histC().all(() => true).sort((a, b) => a.day.localeCompare(b.day)).slice(-60), generated_at: iso() });
  }
  async function send(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person raises an audit finding, not a service or AI identity');
    const b = body(input).str('check', { required: true, max: 40, re: /^[a-z]+-[a-z]+$/, msg: 'check has an invalid format' }).str('engagement', { required: true, max: 40 }).str('owner', { required: true, max: 80 }).done();
    const IA = A().auditEngage; if (!IA) throw httpErr(424, 'the IT Audit team is not installed on this server');
    const r = await assess(); if (!r.ok) throw httpErr(424, r.error);
    const f = r.findings.find((x) => x.check === b.check); if (!f) throw httpErr(404, 'the check ' + b.check + ' has no gap to raise (it is met or not measured)');
    const created = await IA.addFinding(b.engagement, { title: 'SAMA IT audit: ' + f.title, condition: f.condition, criteria: f.criteria, cause: f.cause, effect: f.effect, recommendation: f.recommendation, rating: f.rating, owner: b.owner }, who);
    audit(who, 'finding.send', b.engagement, { check: b.check, finding: created && created.id });
    return { finding: created };
  }
  async function pack(format, who) {
    if (!['html', 'csv'].includes(format)) throw httpErr(400, 'format must be html or csv');
    const r = await assess(true); if (!r.ok) throw httpErr(424, r.error);
    const stamp = iso().slice(0, 10), name = (a) => (r.areas.find((x) => x.id === a) || {}).name || a;
    audit(who, 'pack', format, { readiness: r.readiness.score, gaps: r.findings.length });
    if (format === 'csv') {
      const cell = (x) => { let t = s(x, 3000); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };
      const L2 = [['SAMA IT audit readiness', r.readiness.text], ['Generated', iso()], [], ['Area', 'Check', 'Reference', 'State', 'Evidence', 'Action']].map((x) => x.map(cell).join(','));
      for (const c of r.checks) L2.push([name(c.area), c.title, c.ref, c.state, c.evidence, c.fix].map(cell).join(','));
      L2.push(''); L2.push(['Draft finding', 'Rating', 'Condition', 'Criteria', 'Cause', 'Effect', 'Recommendation'].map(cell).join(','));
      for (const f of r.findings) L2.push([f.title, f.rating, f.condition, f.criteria, f.cause, f.effect, f.recommendation].map(cell).join(','));
      return { filename: 'sama-it-audit-' + stamp + '.csv', csv: L2.join('\r\n') };
    }
    const col = { met: '#1a7f37', partial: '#b26b00', gap: '#c62828', not_measured: '#5c6577' };
    let h = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SAMA IT audit readiness</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:14px/1.45 Segoe UI,Arial,sans-serif;color:#1b1f27;background:#fff;max-width:1050px;margin:24px auto;padding:0 16px}h1{font-size:22px;margin:0}h2{font-size:15px;margin:20px 0 6px;border-bottom:2px solid #e3e6ec;padding-bottom:4px}.m{color:#5c6577;font-size:12px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #eceef2;vertical-align:top}th{color:#5c6577}.f{border-left:3px solid #c62828;padding:6px 10px;margin:8px 0;background:#fdf3f3;font-size:12.5px}@media print{body{margin:0}}</style></head><body>';
    h += ('<h1>SAMA IT audit readiness</h1><div class="m">' + ZYB_ORG.name + ' · generated ') + escH(iso().replace('T', ' ').slice(0, 16)) + ' UTC · evidence read from the platform\'s own records; a check with no source is "not measured", never a pass</div>';
    h += '<p><b>' + escH(r.readiness.text) + '</b>' + (r.readiness.trend ? ' · ' + escH(r.readiness.trend.text) : '') + (r.readiness.weakest ? ' · weakest area: ' + escH(r.readiness.weakest) : '') + '</p>';
    h += '<table><tr><th>Area</th><th>Score</th><th>Met</th><th>Partial</th><th>Gap</th><th>Not measured</th></tr>' + r.areas.map((a) => '<tr><td>' + escH(a.name) + '</td><td>' + escH(a.score == null ? '-' : a.score + '%') + '</td><td>' + a.met + '</td><td>' + a.partial + '</td><td>' + a.gap + '</td><td>' + a.not_measured + '</td></tr>').join('') + '</table>';
    for (const a of r.areas) { h += '<h2>' + escH(a.name) + '</h2><table><tr><th>Check</th><th>Reference</th><th>State</th><th>Evidence</th><th>Action</th></tr>' + r.checks.filter((c) => c.area === a.id).map((c) => '<tr><td>' + escH(c.title) + '</td><td>' + escH(c.ref) + '</td><td style="color:' + col[c.state] + ';font-weight:700">' + escH(c.state.replace('_', ' ')) + '</td><td>' + escH(c.evidence) + '</td><td>' + escH(c.fix) + '</td></tr>').join('') + '</table>'; }
    h += '<h2>Draft audit findings</h2>' + (r.findings.length ? r.findings.map((f) => '<div class="f"><b>' + escH(f.title) + '</b> · rating ' + escH(f.rating) + '<br><b>Condition</b> ' + escH(f.condition) + '<br><b>Criteria</b> ' + escH(f.criteria) + '<br><b>Cause</b> ' + escH(f.cause) + '<br><b>Effect</b> ' + escH(f.effect) + '<br><b>Recommendation</b> ' + escH(f.recommendation) + '</div>').join('') : '<p class="m">No gap.</p>');
    return { filename: 'sama-it-audit-' + stamp + '.html', html: h + '</body></html>' };
  }
  return { view, assess, send, pack, facts };
}

function registerSamaItAudit(srv, app, S0) {
  const S = S0 && S0.view ? S0 : createSamaItAudit(app, S0 || {});
  app.addons = app.addons || {}; app.addons.samaItAudit = S;
  srv.route('GET', '/sama-itaudit', (ctx) => { ctx.need('operator'); return S.view(); });
  srv.route('GET', '/sama-itaudit/pack', (ctx) => { ctx.need('operator'); return S.pack((ctx.query && ctx.query.format) || 'html', ctx.who); });
  srv.route('POST', '/sama-itaudit/findings/send', (ctx) => { ctx.need('operator'); return S.send(ctx.body, ctx.who); });
  return S;
}

module.exports = { createSamaItAudit, registerSamaItAudit };
