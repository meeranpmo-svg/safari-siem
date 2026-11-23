// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * VAPT & Penetration Testing Workflow ({P} = /api/itam; Pentest & Vulnerability Management -> VAPT Workflow): ONE engagement from the
 * request to the signed report, over the modules the platform already has. Nothing here sends a packet: a scan is FILED in
 * Vulnerability Scans (engine/vulnscan.js), which keeps its own scope and its own four-eyes approval; the findings of the other
 * tools are read through the VAPT Center (gather()); a tester's manual findings are recorded with evidence.
 *
 *   1 scoping        name, kind, approach, tester (internal / third party, certification), lead, targets, out of scope, objectives,
 *                    test window, emergency contact - the rules of engagement
 *   2 authorisation  safety checklist (RoE signed, SOC notified, backups confirmed, emergency contact reachable, change reference) and
 *                    an administrator authorises
 *   3 approval       FOUR EYES: a different named person (not the requester, not the authoriser, never a service / AI identity)
 *   4 testing        inside the window: a Greenbone scan filed for the IPv4 targets, external tool runs and manual findings recorded,
 *                    findings of every scanner on the targets imported; the lead marks testing complete
 *   5 validation     each finding confirmed, informational or a false positive - a false positive needs a reason and a second person
 *   6 remediation    each confirmed finding gets an owner and a due date from the SLA (VAPT Center SLA, else 7 / 30 / 90 / 180 days)
 *                    and, when the GRC register is installed, a tracked GRC action
 *   7 retest         FIXED only when the scanner that found it no longer reports it after the fix was claimed, or a retest by a person
 *                    who is neither the owner nor the claimant passes. Risk acceptance needs a reason, an end date and a second person
 *   8 report         generated from the records: executive summary, scope and RoE, methodology, findings by severity with evidence,
 *                    remediation and retest status, compliance mapping (SAMA CSF, NCA ECC, ISO 27001) - HTML (print / PDF) and CSV,
 *                    versioned with a SHA-256; an administrator issues a version
 *   9 sign-off       a person who did not write the report signs it off; the engagement closes and counts as the asset's test
 *
 *   ML       risk rating 0-100 (severity x exploitability x exposure, itemised); SLA days left and breaches forecast for 14 days;
 *            RECURRING findings (the same CVE / title on the same host in an earlier closed engagement = a regression); cycle time
 *            per stage and a forecast close date from the median of past engagements (withheld below 3 closed engagements)
 *   GET  /vapt-workflow                         viewer    KPIs (+ engagements: operator)
 *   GET  /vapt-workflow/:id                     operator  the engagement, stage, next step, findings, analysis, reports
 *   POST /vapt-workflow                         operator  scoping                                                    audited
 *   POST /vapt-workflow/:id/scope               operator  edit scoping (before approval)                             audited
 *   POST /vapt-workflow/:id/authorise           admin     {checklist}                                                audited
 *   POST /vapt-workflow/:id/approve             approver  four eyes                                                  audited
 *   POST /vapt-workflow/:id/scan                operator  file a Greenbone scan for the IPv4 targets                 audited
 *   POST /vapt-workflow/:id/tool-run            operator  {tool, ran_on, note}  an external tool run recorded        audited
 *   POST /vapt-workflow/:id/import              operator  findings of every scanner on the targets                   audited
 *   POST /vapt-workflow/:id/findings            operator  a manual finding with evidence                             audited
 *   POST /vapt-workflow/:id/testing-done        operator  the lead or an admin                                       audited
 *   POST /vapt-workflow/:id/findings/:fid/validate   operator {result, note?}                                       audited
 *   POST /vapt-workflow/:id/findings/:fid/remediate  operator {owner, due?, action?}                                audited
 *   POST /vapt-workflow/:id/findings/:fid/fixed      operator {note}  a claim                                       audited
 *   POST /vapt-workflow/:id/findings/:fid/retest     operator {result: pass|fail, evidence}  independent             audited
 *   POST /vapt-workflow/:id/findings/:fid/accept     operator {reason, until}  a request                            audited
 *   POST /vapt-workflow/:id/findings/:fid/decide     approver {decision: approve|reject, note?}  not the requester  audited
 *   POST /vapt-workflow/:id/report              operator  {kind: interim|final}  a new version                       audited
 *   GET  /vapt-workflow/:id/report/:ver         operator  ?format=html|csv                                           audited
 *   POST /vapt-workflow/:id/report/:ver/issue   admin                                                                audited
 *   POST /vapt-workflow/:id/signoff             approver  {statement}  not the report's author                       audited
 * Host names and findings are internal: operators and administrators. Evidence is a reference or an excerpt, never a credential.
 */
const DAY = 86400000;
const KINDS = { internal_vapt: 'Internal VAPT', external_vapt: 'External VAPT', web_app: 'Web application test', api: 'API test', pentest_internal: 'Internal penetration test', pentest_external: 'External penetration test', red_team: 'Red team exercise' };
const APPROACH = { black: 'Black box', grey: 'Grey box', white: 'White box' };
const SEV = ['critical', 'high', 'medium', 'low', 'info'], W = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
const SLA_DEF = { critical: 7, high: 30, medium: 90, low: 180, info: 365 };
const STAGES = ['scoping', 'authorisation', 'approval', 'testing', 'validation', 'remediation', 'retest', 'report', 'signoff', 'closed'];
const CHECK = { roe_signed: 'Rules of engagement signed by the asset owners', soc_notified: 'SOC notified of the test window and source addresses', backups_confirmed: 'Backups of the systems in scope confirmed', emergency_contact: 'Emergency contact reachable during the window', change_ref: 'Change request reference' };
const COMPL = [['SAMA CSF', '3.3.10', 'Vulnerability management'], ['SAMA CSF', '3.3.11', 'Penetration testing'], ['NCA ECC', '2-10', 'Vulnerabilities management'], ['NCA ECC', '2-11', 'Penetration testing'], ['ISO 27001', 'A.8.8', 'Management of technical vulnerabilities'], ['ISO 27001', 'A.8.29', 'Security testing in development and acceptance']];
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).slice(0, n || 200);
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const median = (L) => { if (!L.length) return null; const a = L.slice().sort((x, y) => x - y), m = a.length >> 1; return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2; };

function createVaptWorkflow(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const E = () => store.collection('vapt_wf'), F = () => store.collection('vapt_wf_find'), R = () => store.collection('vapt_wf_reports');
  const A = () => app.addons || {};
  const iso = (t) => new Date(t == null ? now() : t).toISOString(), day = (t) => iso(t).slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'vaptwf.' + action, target, detail }); };
  const same = (a, b) => !!a && !!b && String(a).toLowerCase() === String(b).toLowerCase();
  const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const hist = (o, who, what) => { o.history = (o.history || []).concat([{ at: iso(), by: who.user, what }]).slice(-200); };
  const slaDays = () => { try { const V = A().vaptCenter; const d = V && V.slaDays && V.slaDays(); if (d && typeof d === 'object') return Object.assign({}, SLA_DEF, d); } catch (e) { /* VAPT Center absent or its SLA unreadable: the defaults apply and the report says so */ } return SLA_DEF; };

  function getE(id0) { const id = param(id0, 'id'); const e = E().get(id); if (!e) throw httpErr(404, 'engagement ' + id + ' not found'); return e; }
  function getF(e, fid0) { const fid = param(fid0, 'fid'); const f = F().get(fid); if (!f || f.eng !== e.id) throw httpErr(404, 'finding ' + fid + ' not found in ' + e.id); return f; }
  const findsOf = (e) => F().all((f) => f.eng === e.id);
  const isOpenConfirmed = (f) => f.validation === 'confirmed' && !['verified', 'accepted'].includes(f.state);
  function nextId() { const y = day().slice(0, 4), k = E().all((e) => String(e.id).startsWith('VA-' + y + '-')).length + 1; return 'VA-' + y + '-' + String(k).padStart(3, '0'); }

  function scopeFields(src, cur) {
    const b = body(src || {}).str('name', { required: !cur, min: 3, max: 160 }).oneOf('kind', Object.keys(KINDS), { required: !cur }).oneOf('approach', Object.keys(APPROACH), { def: cur ? undefined : 'grey' })
      .oneOf('tester_type', ['internal', 'third_party'], { def: cur ? undefined : 'internal' }).str('tester_org', { max: 120 }).str('tester_cert', { max: 120 }).str('lead', { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'lead must be a user name' })
      .list('targets', { required: !cur, max: 256, item: 'str', itemMax: 200, unique: true }).list('out_of_scope', { max: 256, item: 'str', itemMax: 200, unique: true }).str('objectives', { max: 2000 })
      .date('window_start', { required: !cur }).date('window_end', { required: !cur }).str('emergency_contact', { max: 200 }).done();
    const ws = b.window_start || (cur && cur.window_start), we = b.window_end || (cur && cur.window_end);
    if (ws && we && we < ws) throw httpErr(400, 'window_end must be on or after window_start');
    if (ws && we && Date.parse(we) - Date.parse(ws) > 90 * DAY) throw httpErr(400, 'window_end: a test window is at most 90 days - split the engagement');
    const tt = b.tester_type || (cur && cur.tester_type); if (tt === 'third_party' && !(b.tester_org || (cur && cur.tester_org))) throw httpErr(400, 'tester_org is required for a third-party tester');
    for (const t of (b.targets || [])) if (/[\s<>"']/.test(t)) throw httpErr(400, 'targets: "' + s(t, 60) + '" is not a host, address, range or URL');
    return b;
  }
  function create(src, who) {
    human(who, 'requests an engagement');
    const b = scopeFields(src, null);
    const e = Object.assign({ id: nextId(), approach: 'grey', tester_type: 'internal', tester_org: '', tester_cert: '', lead: who.user, out_of_scope: [], objectives: '', emergency_contact: '' }, b,
      { created_by: who.user, created_at: iso(), checklist: {}, authorised_by: null, approved_by: null, scans: [], tool_runs: [], testing_done_at: null, signed_by: null, closed_at: null, history: [] });
    hist(e, who, 'requested'); E().put(e); audit(who, 'create', e.id, { kind: e.kind, targets: e.targets.length, window: [e.window_start, e.window_end] });
    return detail(e.id);
  }
  function editScope(id, src, who) {
    const e = getE(id); if (e.approved_by) throw httpErr(409, 'the scope is approved - a change of scope needs a new engagement');
    const b = scopeFields(src, e); Object.assign(e, b, { authorised_by: null, authorised_at: null }); hist(e, who, 'scope changed: ' + Object.keys(b).join(', ') + (e.checklist && Object.keys(e.checklist).length ? ' (authorisation reset)' : ''));
    E().put(e); audit(who, 'scope', e.id, { fields: Object.keys(b) }); return detail(e.id);
  }
  function authorise(id, src, who) {
    human(who, 'authorises a test'); const e = getE(id); if (e.approved_by) throw httpErr(409, 'already approved');
    const c = (src && src.checklist) || {}; if (typeof c !== 'object' || Array.isArray(c)) throw httpErr(400, 'checklist must be an object');
    const b = body(c).bool('roe_signed', { def: false }).bool('soc_notified', { def: false }).bool('backups_confirmed', { def: false }).bool('emergency_contact', { def: false }).str('change_ref', { max: 60 }).done();
    const missing = Object.keys(CHECK).filter((k) => !b[k]); if (missing.length) throw httpErr(400, 'checklist: not complete - ' + missing.map((k) => CHECK[k]).join('; '));
    if (!e.emergency_contact) throw httpErr(400, 'emergency_contact: record who to call during the window in the scope first');
    Object.assign(e, { checklist: b, authorised_by: who.user, authorised_at: iso() }); hist(e, who, 'authorised (change ' + b.change_ref + ')'); E().put(e);
    audit(who, 'authorise', e.id, { change_ref: b.change_ref }); return detail(e.id);
  }
  function approve(id, who) {
    human(who, 'approves a test'); const e = getE(id);
    if (!e.authorised_by) throw httpErr(409, 'authorise the engagement (safety checklist) first'); if (e.approved_by) throw httpErr(409, 'already approved');
    if (same(who.user, e.created_by) || same(who.user, e.authorised_by)) throw httpErr(403, 'four eyes: the requester or the authoriser cannot approve - a different person approves');
    Object.assign(e, { approved_by: who.user, approved_at: iso() }); hist(e, who, 'approved (four eyes)'); E().put(e); audit(who, 'approve', e.id, { requested_by: e.created_by, authorised_by: e.authorised_by });
    return detail(e.id);
  }
  function inWindow(e) { const d = day(); if (!e.approved_by) throw httpErr(409, 'the engagement is not approved yet - nothing is tested before four-eyes approval'); if (d < e.window_start || d > e.window_end) throw httpErr(409, 'outside the test window ' + e.window_start + ' to ' + e.window_end); }
  async function scan(id, src, who) {
    human(who, 'requests a scan'); const e = getE(id); inWindow(e);
    const b = body(src || {}).oneOf('profile', ['full', 'discovery'], { def: 'full' }).int('hours', { min: 1, max: 12, def: 4 }).done();
    const V = A().vulnscan; if (!V) throw httpErr(424, 'Vulnerability Scans (Greenbone) is not installed - record the tool run instead');
    const targets = e.targets.filter((t) => IPV4.test(t) || /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(t)); if (!targets.length) throw httpErr(400, 'targets: no IPv4 address or range in the scope to scan with Greenbone - record the tool run instead');
    const st = now() + 10 * 60000, en = Math.min(st + b.hours * 3600000, Date.parse(e.window_end + 'T23:59:59Z'));
    const r = await V.request({ name: e.id + ' ' + s(e.name, 60), targets, exclude: e.out_of_scope.filter((t) => IPV4.test(t)), profile: b.profile, window_start: iso(st), window_end: iso(en), reason: 'Engagement ' + e.id + ' (approved by ' + e.approved_by + ')' }, who);
    e.scans.push({ ref: r && r.id, kind: 'greenbone', targets: targets.length, at: iso(), by: who.user }); hist(e, who, 'Greenbone scan filed: ' + (r && r.id)); E().put(e);
    audit(who, 'scan', e.id, { request: r && r.id, targets: targets.length }); return Object.assign(detail(e.id), { note: 'Filed in Vulnerability Scans: it runs only inside the scan scope and after a different person approves it there.' });
  }
  function toolRun(id, src, who) {
    human(who, 'records a tool run'); const e = getE(id); inWindow(e);
    const b = body(src || {}).str('tool', { required: true, max: 80 }).date('ran_on', { required: true, notFuture: true, now: now() }).str('note', { max: 500 }).done();
    if (b.ran_on < e.window_start || b.ran_on > e.window_end) throw httpErr(400, 'ran_on: outside the test window');
    e.tool_runs.push(Object.assign(b, { by: who.user, at: iso() })); hist(e, who, 'tool run recorded: ' + b.tool); E().put(e); audit(who, 'tool', e.id, { tool: b.tool, ran_on: b.ran_on }); return detail(e.id);
  }
  // a target matches a host when it is the same address / name, or a CIDR range holding the address
  function inScope(e, host) {
    const h = String(host || '').toLowerCase(); if (!h) return false;
    if (e.out_of_scope.some((t) => String(t).toLowerCase() === h)) return false;
    return e.targets.some((t) => { const x = String(t).toLowerCase(); if (x === h || x.replace(/^https?:\/\//, '').split(/[/:]/)[0] === h) return true;
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(x); if (!m || !IPV4.test(h)) return false;
      const n = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0), bits = Number(m[2]), mask = bits ? Math.pow(2, 32) - Math.pow(2, 32 - bits) : 0;
      return (n(h) - (n(h) % Math.pow(2, 32 - bits))) === (n(m[1]) - (n(m[1]) % Math.pow(2, 32 - bits))) && mask >= 0; });
  }
  const sevOf = (v) => { const x = String(v || '').toLowerCase(); return SEV.includes(x) ? x : x === 'log' || x === 'informational' ? 'info' : 'medium'; };
  async function importFindings(id, who) {
    human(who, 'imports findings'); const e = getE(id); if (!e.approved_by) throw httpErr(409, 'the engagement is not approved yet');
    const V = A().vaptCenter; if (!V || !V.gather) throw httpErr(424, 'the VAPT Center is not installed - record the findings by hand');
    const g = await V.gather(), have = new Set(findsOf(e).filter((f) => f.src_id).map((f) => f.src + ':' + f.src_id)); let added = 0, skipped = 0;
    for (const x of g.findings || []) {
      if (!inScope(e, x.host) && !inScope(e, x.asset)) continue; if (x.src === 'wf') continue;
      const k = x.src + ':' + x.id; if (have.has(k)) { skipped++; continue; }
      const f = { id: 'VF-' + crypto.randomBytes(5).toString('hex'), eng: e.id, src: x.src, src_id: x.id, host: s(x.host || x.asset, 200), title: s(x.title, 300), severity: sevOf(x.severity), cvss: typeof x.cvss === 'number' ? x.cvss : null,
        cves: (x.cves || []).slice(0, 20), description: '', evidence: 'reported by ' + x.src, fix: s(x.fix || x.solution, 1000), exposure: x.exposure || '', validation: 'pending', state: 'open', created_by: who.user, created_at: iso(), history: [] };
      hist(f, who, 'imported from ' + x.src); F().put(f); have.add(k); added++;
    }
    hist(e, who, 'imported ' + added + ' finding(s)'); E().put(e); audit(who, 'import', e.id, { added, skipped, sources: Object.keys(g.status || {}) });
    return Object.assign(detail(e.id), { imported: added, already: skipped, sources: g.status || {} });
  }
  function addFinding(id, src, who) {
    human(who, 'records a finding'); const e = getE(id); inWindow(e);
    const b = body(src || {}).str('title', { required: true, min: 4, max: 300 }).oneOf('severity', SEV, { required: true }).num('cvss', { min: 0, max: 10 }).str('host', { required: true, max: 200 })
      .list('cves', { max: 20, item: 'str', itemMax: 20, unique: true }).str('description', { max: 4000 }).str('evidence', { required: true, min: 5, max: 4000 }).str('fix', { max: 2000 }).str('technique', { max: 20, re: /^T\d{4}(\.\d{3})?$/, msg: 'technique must be an ATT&CK id (e.g. T1190)' })
      .oneOf('exposure', ['internet', 'internal', ''], { def: '' }).done();
    if (!inScope(e, b.host)) throw httpErr(400, 'host: ' + s(b.host, 60) + ' is not in the engagement scope');
    for (const c of b.cves || []) if (!/^CVE-\d{4}-\d{4,7}$/i.test(c)) throw httpErr(400, 'cves: "' + s(c, 20) + '" is not a CVE id');
    if (/(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/i.test(b.evidence)) throw httpErr(400, 'evidence: it looks like it holds a credential - record where it was found, never the value');
    const f = Object.assign({ id: 'VF-' + crypto.randomBytes(5).toString('hex'), eng: e.id, src: 'manual', src_id: null, cvss: null, cves: [], description: '', fix: '', technique: '' }, b, { validation: 'pending', state: 'open', created_by: who.user, created_at: iso(), history: [] });
    hist(f, who, 'recorded by the tester'); F().put(f); audit(who, 'finding', e.id, { finding: f.id, severity: f.severity }); return detail(e.id);
  }
  function testingDone(id, who) {
    human(who, 'closes testing'); const e = getE(id); if (!e.approved_by) throw httpErr(409, 'the engagement is not approved yet');
    if (!(same(who.user, e.lead) || who.role === 'admin')) throw httpErr(403, 'the engagement lead (' + e.lead + ') or an administrator marks testing complete');
    if (!e.scans.length && !e.tool_runs.length && !findsOf(e).length) throw httpErr(409, 'nothing was tested: file a scan, record a tool run or a finding first');
    e.testing_done_at = iso(); hist(e, who, 'testing complete'); E().put(e); audit(who, 'testing-done', e.id, { findings: findsOf(e).length }); return detail(e.id);
  }
  function validate(id, fid, src, who) {
    human(who, 'validates a finding'); const e = getE(id), f = getF(e, fid);
    const b = body(src || {}).oneOf('result', ['confirmed', 'informational', 'false_positive'], { required: true }).str('note', { max: 1000 }).done();
    if (b.result === 'false_positive') { if (!b.note || b.note.length < 10) throw httpErr(400, 'note: say why it is a false positive (at least 10 characters)');
      f.request = { kind: 'false_positive', by: who.user, at: iso(), reason: b.note }; f.validation = 'fp_pending'; hist(f, who, 'false positive requested: ' + b.note); }
    else { f.validation = b.result; f.request = null; hist(f, who, b.result + (b.note ? ': ' + b.note : '')); }
    F().put(f); audit(who, 'validate', e.id + ':' + f.id, { result: b.result }); return detail(e.id);
  }
  function remediate(id, fid, src, who) {
    human(who, 'assigns remediation'); const e = getE(id), f = getF(e, fid); if (f.validation !== 'confirmed') throw httpErr(409, 'confirm the finding before assigning its remediation');
    const b = body(src || {}).str('owner', { required: true, max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'owner must be a user name' }).date('due').bool('action', { def: true }).done();
    const due = b.due || day(Date.parse(f.created_at) + slaDays()[f.severity] * DAY);
    Object.assign(f, { owner: b.owner, due, sla_days: slaDays()[f.severity] }); hist(f, who, 'owner ' + b.owner + ', due ' + due);
    if (b.action && !f.grc_action) { const GR = A().grcRegisters; if (GR && GR.actionCreate) {
      try { const a = GR.actionCreate({ title: s('Fix ' + f.severity + ': ' + f.title + ' on ' + f.host, 200), source: 'audit', ref: e.id + ':' + f.id, owner: b.owner, due, priority: f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : 'medium', description: s((f.fix || '') + '\nEngagement ' + e.id, 4000) }, who); f.grc_action = a && a.id; hist(f, who, 'GRC action ' + f.grc_action); }
      catch (x) { if (x.status !== 409) throw x; hist(f, who, 'a GRC action already tracks this finding'); } } }
    F().put(f); audit(who, 'remediate', e.id + ':' + f.id, { owner: b.owner, due, grc_action: f.grc_action || null }); return detail(e.id);
  }
  function fixed(id, fid, src, who) {
    human(who, 'claims a fix'); const e = getE(id), f = getF(e, fid); if (!isOpenConfirmed(f)) throw httpErr(409, 'only an open, confirmed finding can be claimed fixed');
    const b = body(src || {}).str('note', { required: true, min: 5, max: 1000 }).done();
    Object.assign(f, { state: 'fix_claimed', claimed_by: who.user, claimed_at: iso() }); hist(f, who, 'fix claimed: ' + b.note); F().put(f); audit(who, 'fixed', e.id + ':' + f.id, {});
    return detail(e.id);
  }
  function retest(id, fid, src, who) {
    human(who, 'retests'); const e = getE(id), f = getF(e, fid); if (f.state !== 'fix_claimed') throw httpErr(409, 'retest after the fix is claimed');
    if (same(who.user, f.owner) || same(who.user, f.claimed_by)) throw httpErr(403, 'independent retest: the owner or the person who claimed the fix cannot retest it');
    const b = body(src || {}).oneOf('result', ['pass', 'fail'], { required: true }).str('evidence', { required: true, min: 5, max: 2000 }).done();
    if (b.result === 'pass') Object.assign(f, { state: 'verified', verified_by: who.user, verified_at: iso(), verified_how: 'retest' });
    else Object.assign(f, { state: 'open', reopened: (f.reopened || 0) + 1 });
    hist(f, who, 'retest ' + b.result + ': ' + b.evidence); F().put(f); audit(who, 'retest', e.id + ':' + f.id, { result: b.result }); return detail(e.id);
  }
  function accept(id, fid, src, who) {
    human(who, 'requests risk acceptance'); const e = getE(id), f = getF(e, fid); if (!isOpenConfirmed(f)) throw httpErr(409, 'only an open, confirmed finding can be risk-accepted');
    const b = body(src || {}).str('reason', { required: true, min: 10, max: 1000 }).date('until', { required: true }).done();
    if (b.until <= day()) throw httpErr(400, 'until must be in the future'); if (Date.parse(b.until) - now() > 366 * DAY) throw httpErr(400, 'until: a risk acceptance lasts at most a year');
    f.request = { kind: 'risk_accepted', by: who.user, at: iso(), reason: b.reason, until: b.until }; hist(f, who, 'risk acceptance requested until ' + b.until); F().put(f);
    audit(who, 'accept', e.id + ':' + f.id, { until: b.until }); return detail(e.id);
  }
  function decide(id, fid, src, who) {
    human(who, 'decides'); const e = getE(id), f = getF(e, fid); const q = f.request; if (!q) throw httpErr(409, 'nothing is waiting for a decision on this finding');
    if (same(who.user, q.by)) throw httpErr(403, 'four eyes: the requester cannot decide their own request');
    const b = body(src || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).done();
    if (q.kind === 'false_positive') f.validation = b.decision === 'approve' ? 'false_positive' : 'pending';
    else if (b.decision === 'approve') Object.assign(f, { state: 'accepted', accepted_until: q.until });
    f.request = null; hist(f, who, q.kind + ' ' + b.decision + 'd' + (b.note ? ': ' + b.note : '')); F().put(f); audit(who, 'decide', e.id + ':' + f.id, { kind: q.kind, decision: b.decision, requested_by: q.by });
    return detail(e.id);
  }

  // ---- scanner-verified fixes: a finding a scanner reported is FIXED when that scanner no longer reports it after the claim
  async function reconcile(e) {
    const V = A().vaptCenter; if (!V || !V.gather) return;
    const L = findsOf(e).filter((f) => f.src !== 'manual' && f.state === 'fix_claimed'); if (!L.length) return;
    let g; try { g = await V.gather(); } catch (x) { if (app.log && app.log.every) app.log.every('vaptwf.reconcile', 600000, 'warn', 'vapt workflow: scanner findings unreadable', { err: x.message }); return; }
    const by = new Map((g.findings || []).map((x) => [x.src + ':' + x.id, x]));
    for (const f of L) { const x = by.get(f.src + ':' + f.src_id); const fx = x && x.status === 'fixed' && (!x.fixed_at || x.fixed_at >= f.claimed_at);
      if (fx) { Object.assign(f, { state: 'verified', verified_by: 'scan:' + f.src, verified_at: iso(), verified_how: 'rescan' }); hist(f, { user: 'system' }, 'not reported by the next ' + f.src + ' scan - verified fixed'); F().put(f); } }
  }

  // ---- analysis: risk, SLA, recurrence, cycle time
  function analyse(e, L) {
    const live = L.filter((f) => f.validation !== 'false_positive');
    const conf = live.filter((f) => f.validation === 'confirmed'), open = conf.filter((f) => !['verified', 'accepted'].includes(f.state));
    const counts = {}; for (const k of SEV) counts[k] = conf.filter((f) => f.severity === k).length;
    const why = []; let pts = 0;
    for (const f of open) { let p = W[f.severity] || 0; const x = [];
      if (/remote code|rce|exploit|known.exploited|kev/i.test(f.title + ' ' + (f.description || ''))) { p *= 1.5; x.push('exploit named'); }
      if (f.exposure === 'internet' || /external/.test(e.kind)) { p *= 1.25; x.push('internet-facing'); }
      pts += p; if (p >= 6) why.push(f.severity + ' ' + s(f.title, 60) + (x.length ? ' (' + x.join(', ') + ')' : '')); }
    const risk = Math.round(Math.min(100, 100 * (1 - Math.exp(-pts / 25))));
    const today = now(), sla = open.filter((f) => f.due).map((f) => ({ id: f.id, title: f.title, severity: f.severity, due: f.due, days_left: Math.round((Date.parse(f.due) - today) / DAY) }));
    // recurrence: the same CVE / title on the same host in an earlier CLOSED engagement
    const past = E().all((x) => x.id !== e.id && x.closed_at), keys = new Set();
    for (const p of past) for (const f of F().all((y) => y.eng === p.id && y.validation === 'confirmed')) { keys.add(String(f.host).toLowerCase() + '|' + ((f.cves && f.cves[0]) || String(f.title).toLowerCase())); }
    const recurring = conf.filter((f) => keys.has(String(f.host).toLowerCase() + '|' + ((f.cves && f.cves[0]) || String(f.title).toLowerCase()))).map((f) => f.id);
    // cycle time: days from request to close of past engagements, and per stage from their history
    const dur = past.map((p) => (Date.parse(p.closed_at) - Date.parse(p.created_at)) / DAY).filter((d) => d >= 0);
    const m = dur.length >= 3 ? median(dur) : null;
    return { risk, band: risk >= 75 ? 'critical' : risk >= 50 ? 'high' : risk >= 25 ? 'medium' : 'low', risk_why: why.slice(0, 8), counts, total: L.length, confirmed: conf.length, open: open.length,
      false_positive: L.filter((f) => f.validation === 'false_positive').length, pending: L.filter((f) => f.validation === 'pending' || f.validation === 'fp_pending').length,
      verified: conf.filter((f) => f.state === 'verified').length, accepted: conf.filter((f) => f.state === 'accepted').length,
      sla: { breached: sla.filter((x) => x.days_left < 0).length, due_14d: sla.filter((x) => x.days_left >= 0 && x.days_left <= 14).length, items: sla.sort((a, b) => a.days_left - b.days_left).slice(0, 20) },
      recurring, cycle: m == null ? { withheld: true, why: 'needs 3 closed engagements (' + dur.length + ' so far)' } : { median_days: Math.round(m), forecast_close: e.closed_at ? null : day(Date.parse(e.created_at) + m * DAY), from: dur.length } };
  }
  function stageOf(e, L) {
    if (e.closed_at) return 'closed';
    if (!(e.targets.length && e.window_start && e.window_end && e.lead)) return 'scoping';
    if (!e.authorised_by) return 'authorisation'; if (!e.approved_by) return 'approval'; if (!e.testing_done_at) return 'testing';
    const live = L.filter((f) => f.validation !== 'false_positive');
    if (live.some((f) => f.validation === 'pending' || f.validation === 'fp_pending')) return 'validation';
    const conf = live.filter((f) => f.validation === 'confirmed');
    if (conf.some((f) => !f.owner && !['verified', 'accepted'].includes(f.state))) return 'remediation';
    if (conf.some((f) => !['verified', 'accepted'].includes(f.state))) return 'retest';
    if (!R().all((r) => r.eng === e.id && r.status === 'issued' && r.kind === 'final').length) return 'report';
    return 'signoff';
  }
  const NEXT = { scoping: 'Complete the scope: targets, window and lead.', authorisation: 'An administrator completes the safety checklist and authorises.', approval: 'A different person approves (four eyes).',
    testing: 'Inside the window: file the Greenbone scan, record tool runs and manual findings, import the scanners\' findings, then mark testing complete.',
    validation: 'Confirm each finding, mark it informational, or request a false positive (a second person decides).', remediation: 'Give every confirmed finding an owner and a due date (a GRC action is raised).',
    retest: 'Owners claim fixes; a rescan or an independent retest verifies them. A risk acceptance needs a second person.', report: 'Generate the final report and have an administrator issue it.',
    signoff: 'A person who did not write the report signs it off - the engagement closes.', closed: 'Closed. It counts as the assets\' test in the testing cadence.' };
  function slimE(e) { const L = findsOf(e), st = stageOf(e, L), a = analyse(e, L);
    return { id: e.id, name: e.name, kind: KINDS[e.kind] || e.kind, lead: e.lead, window: [e.window_start, e.window_end], stage: st, stage_no: STAGES.indexOf(st) + 1, risk: a.risk, band: a.band, open: a.open, confirmed: a.confirmed, sla_breached: a.sla.breached, created_at: e.created_at, closed_at: e.closed_at }; }
  function detail(id) {
    const e = getE(id), L = findsOf(e).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || String(a.created_at).localeCompare(String(b.created_at))), st = stageOf(e, L);
    return { engagement: Object.assign({}, e, { kind_name: KINDS[e.kind] || e.kind, approach_name: APPROACH[e.approach] || e.approach }), stage: st, stage_no: STAGES.indexOf(st) + 1, stages: STAGES, next: NEXT[st],
      checklist_items: CHECK, findings: L, analysis: analyse(e, L), sla_days: slaDays(), reports: R().all((r) => r.eng === e.id).map((r) => ({ id: r.id, version: r.version, kind: r.kind, status: r.status, sha256: r.sha256, by: r.by, at: r.at, issued_by: r.issued_by || null })).sort((a, b) => a.version - b.version) };
  }
  async function view(who) {
    const all = E().all(), rows = all.map(slimE).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const kpi = { engagements: rows.length, active: rows.filter((r) => r.stage !== 'closed').length, closed: rows.filter((r) => r.stage === 'closed').length, open_findings: rows.reduce((a, r) => a + r.open, 0), sla_breached: rows.reduce((a, r) => a + r.sla_breached, 0),
      by_stage: STAGES.map((x) => ({ stage: x, n: rows.filter((r) => r.stage === x).length })) };
    const ops = ['operator', 'admin'].includes(String(who.role || '').toLowerCase());
    return Object.assign({ kpi, kinds: KINDS, approaches: APPROACH, stages: STAGES, installed: { greenbone: !!A().vulnscan, vapt_center: !!A().vaptCenter, grc: !!A().grcRegisters }, generated_at: iso() }, ops ? { engagements: rows } : { note: 'Engagement names and hosts are internal: operators and administrators see the list.' });
  }
  async function detailFresh(id) { const e = getE(id); await reconcile(e); return detail(id); }

  // ---- the report: generated from the records only
  function buildReport(e, L, kind, who, version) {
    const a = analyse(e, L), conf = L.filter((f) => f.validation === 'confirmed'), sd = slaDays();
    const tbl = (cols, rows) => '<table><thead><tr>' + cols.map((c) => '<th>' + esc(c) + '</th>').join('') + '</tr></thead><tbody>' + (rows.length ? rows.map((r) => '<tr>' + r.map((c) => '<td>' + esc(c) + '</td>').join('') + '</tr>').join('') : '<tr><td colspan="' + cols.length + '">None</td></tr>') + '</tbody></table>';
    const status = (f) => f.state === 'verified' ? 'Fixed - verified by ' + (f.verified_how === 'rescan' ? 'rescan' : 'independent retest') : f.state === 'accepted' ? 'Risk accepted until ' + f.accepted_until : f.state === 'fix_claimed' ? 'Fix claimed - awaiting verification' : 'Open';
    const posture = a.counts.critical ? 'Critical exposure found - immediate remediation required.' : a.counts.high ? 'High-risk findings require prompt remediation.' : conf.length ? 'Medium and low findings to track to closure.' : 'No confirmed finding in the tested scope.';
    let h = '<!doctype html><html><head><meta charset="utf-8"><title>' + esc(e.id + ' - ' + e.name) + '</title><style>body{font:13px/1.5 Arial,sans-serif;color:#111;margin:32px;max-width:1000px}h1{font-size:22px;margin:0}h2{font-size:16px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:26px}table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef2f7}.k{display:inline-block;border:1px solid #bbb;border-radius:6px;padding:6px 10px;margin:3px}.muted{color:#555}.f{border:1px solid #ccc;border-radius:6px;padding:8px 10px;margin:8px 0;page-break-inside:avoid}</style></head><body>';
    h += (() => { const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {}; return bv.letterhead && /^data:image\/(png|jpe?g|webp|svg\+xml);base64,/.test(bv.letterhead) ? '<img src="' + esc(bv.letterhead) + '" alt="" style="max-height:46px;max-width:200px;margin-bottom:8px"><br>' : ''; })();
    h += '<div class="muted">' + esc(((store.collection('pentest_settings').get('report_brand') || {}).values || {}).org_name || ZYB_ORG.name) + ' - ' + esc(kind === 'final' ? 'Final' : 'Interim') + ' report, version ' + version + ' - CONFIDENTIAL</div><h1>' + esc(KINDS[e.kind] || e.kind) + ': ' + esc(e.name) + '</h1><div class="muted">' + esc(e.id + ' · window ' + e.window_start + ' to ' + e.window_end + ' · generated ' + iso().slice(0, 16).replace('T', ' ') + ' UTC by ' + who.user) + '</div>';
    h += '<h2>1. Executive summary</h2><p>' + esc(posture) + '</p><div>' + [['Risk rating', a.risk + '/100 (' + a.band + ')'], ['Confirmed findings', a.confirmed], ['Critical', a.counts.critical], ['High', a.counts.high], ['Medium', a.counts.medium], ['Low', a.counts.low], ['Fixed and verified', a.verified], ['Open', a.open], ['Past SLA', a.sla.breached], ['Recurring', a.recurring.length]].map((k) => '<span class="k"><b>' + esc(k[1]) + '</b> ' + esc(k[0]) + '</span>').join('') + '</div>';
    if (a.risk_why.length) h += '<p class="muted">Rating driven by: ' + esc(a.risk_why.join('; ')) + '. Rating = 100 x (1 - e^(-points/25)); points per open finding: critical 10, high 6, medium 3, low 1, x1.5 when an exploit is named, x1.25 internet-facing.</p>';
    h += '<h2>2. Scope and rules of engagement</h2>' + tbl(['Item', 'Value'], [['Engagement type', KINDS[e.kind] || e.kind], ['Approach', APPROACH[e.approach] || e.approach], ['Tester', e.tester_type === 'third_party' ? e.tester_org + (e.tester_cert ? ' (' + e.tester_cert + ')' : '') : 'Internal' + (e.tester_cert ? ' (' + e.tester_cert + ')' : '')], ['Lead', e.lead], ['Targets', e.targets.join(', ')], ['Out of scope', e.out_of_scope.join(', ') || 'none'], ['Objectives', e.objectives || '-'], ['Window', e.window_start + ' to ' + e.window_end], ['Emergency contact', e.emergency_contact], ['Authorised by', (e.authorised_by || '-') + ' ' + s(e.authorised_at, 10) + ' (change ' + ((e.checklist && e.checklist.change_ref) || '-') + ')'], ['Approved by (four eyes)', (e.approved_by || '-') + ' ' + s(e.approved_at, 10)]]);
    h += '<h2>3. Methodology</h2><p>Scanner findings are read from the platform\'s own scanners (Greenbone, Tenable, FireCompass, the penetration testing engineer) for the hosts in scope; manual findings are recorded by the tester with evidence. Each finding is validated by a person; false positives and risk acceptances are decided by a second person. A fix counts only when a later scan no longer reports it or an independent retest passes.</p>' + tbl(['Activity', 'Detail', 'When', 'By'], e.scans.map((x) => ['Greenbone scan', 'request ' + x.ref + ', ' + x.targets + ' target(s)', s(x.at, 10), x.by]).concat(e.tool_runs.map((x) => ['Tool run', x.tool + (x.note ? ' - ' + x.note : ''), x.ran_on, x.by])));
    h += '<h2>4. Findings summary</h2>' + tbl(['#', 'Severity', 'CVSS', 'Host', 'Finding', 'Owner', 'Due', 'Status'], conf.map((f, i) => [i + 1, f.severity, f.cvss == null ? '-' : f.cvss, f.host, f.title + (a.recurring.includes(f.id) ? ' [RECURRING]' : ''), f.owner || '-', f.due || '-', status(f)]));
    h += '<h2>5. Detailed findings</h2>' + (conf.length ? conf.map((f, i) => '<div class="f"><b>' + (i + 1) + '. [' + esc(f.severity.toUpperCase()) + '] ' + esc(f.title) + '</b><div class="muted">' + esc(f.host + (f.cves && f.cves.length ? ' · ' + f.cves.join(', ') : '') + (f.technique ? ' · ATT&CK ' + f.technique : '') + ' · source ' + f.src) + '</div>' + (f.description ? '<p>' + esc(f.description) + '</p>' : '') + '<p><b>Evidence:</b> ' + esc(f.evidence || '-') + '</p><p><b>Remediation:</b> ' + esc(f.fix || '-') + '</p><p><b>Status:</b> ' + esc(status(f)) + (f.grc_action ? ' · GRC action ' + esc(f.grc_action) : '') + '</p></div>').join('') : '<p>No confirmed finding.</p>');
    h += '<h2>6. Remediation SLA</h2><p class="muted">SLA days: ' + esc(Object.entries(sd).map(([k, d]) => k + ' ' + d).join(', ')) + '.</p>' + tbl(['Finding', 'Severity', 'Due', 'Days left'], a.sla.items.map((x) => [x.title, x.severity, x.due, x.days_left]));
    h += '<h2>7. Compliance mapping</h2>' + tbl(['Framework', 'Control', 'Requirement', 'Evidence in this report'], COMPL.map((c) => [c[0], c[1], c[2], c[2].includes('Penetration') ? 'This engagement: ' + (KINDS[e.kind] || e.kind) + ', ' + e.window_start + ' to ' + e.window_end : a.confirmed + ' confirmed finding(s), ' + a.verified + ' verified fixed, ' + a.open + ' open']));
    // coverage of the targets: every connected asset in scope scanned, or why not and the fix (engine/scan-assurance.js)
    let cov = null; try { cov = A().scanAssurance && A().scanAssurance.forTargets(e.targets); } catch (x) { cov = null; if (app.log && app.log.every) app.log.every('vaptwf.coverage', 600000, 'warn', 'vapt workflow: coverage unreadable', { err: x.message }); }
    h += '<h2>7a. Scan coverage of the targets</h2>' + (cov ? '<p>' + esc(cov.scanned + ' of ' + cov.assets + ' registered asset(s) in the target ranges were scanned within the policy.') + '</p>' + tbl(['Asset', 'Addresses', 'Status', 'Why not scanned', 'Fix'], cov.rows.map((x) => [x.name, x.ips, x.status, x.why, x.fix])) : '<p class="muted">Coverage is measured for IPv4 targets when Scan Coverage Assurance is installed.</p>');
    h += '<h2>8. False positives and accepted risks</h2>' + tbl(['Finding', 'Host', 'Decision'], L.filter((f) => f.validation === 'false_positive' || f.state === 'accepted').map((f) => [f.title, f.host, f.validation === 'false_positive' ? 'False positive' : 'Risk accepted until ' + f.accepted_until]));
    h += '<h2>9. Sign-off</h2><p>Prepared by ' + esc(who.user) + '. Issued and signed-off records are kept with the SHA-256 of this document in the platform.</p></body></html>';
    const cols = ['#', 'Severity', 'CVSS', 'Host', 'Finding', 'CVEs', 'Source', 'Validation', 'Owner', 'Due', 'Status', 'Recurring'];
    const csv = ['# ' + e.id + ' ' + e.name + ' - version ' + version + ' - generated ' + iso(), cols.join(',')].concat(L.map((f, i) => [i + 1, f.severity, f.cvss == null ? '' : f.cvss, f.host, f.title, (f.cves || []).join(' '), f.src, f.validation, f.owner || '', f.due || '', status(f), a.recurring.includes(f.id) ? 'yes' : ''].map(csvCell).join(','))).join('\r\n');
    return { html: h, csv };
  }
  async function report(id, src, who) {
    human(who, 'generates a report'); const e = getE(id); await reconcile(e);
    const b = body(src || {}).oneOf('kind', ['interim', 'final'], { def: 'final' }).done(), L = findsOf(e);
    if (!e.testing_done_at && b.kind === 'final') throw httpErr(409, 'a final report comes after testing is complete - generate an interim report meanwhile');
    if (b.kind === 'final') { const st = stageOf(e, L); if (STAGES.indexOf(st) < STAGES.indexOf('report')) throw httpErr(409, 'a final report needs every finding validated, assigned and verified or risk-accepted - stage now: ' + st); }
    const version = R().all((r) => r.eng === e.id).length + 1, out = buildReport(e, L, b.kind, who, version);
    const r = { id: e.id + '-R' + version, eng: e.id, version, kind: b.kind, status: 'draft', html: out.html, csv: out.csv, sha256: crypto.createHash('sha256').update(out.html).digest('hex'), by: who.user, at: iso() };
    R().put(r); hist(e, who, b.kind + ' report v' + version + ' generated'); E().put(e); audit(who, 'report', e.id, { version, kind: b.kind, sha256: r.sha256 }); return detail(e.id);
  }
  function getReport(id, ver0, fmt, who) {
    const e = getE(id), ver = Number(param(ver0, 'ver')); const r = R().get(e.id + '-R' + ver); if (!r) throw httpErr(404, 'report version ' + ver + ' not found');
    const f = fmt || 'html'; if (!['html', 'csv'].includes(f)) throw httpErr(400, 'format must be html or csv');
    audit(who, 'report.read', r.id, { format: f }); const base = 'vapt-' + e.id + '-v' + ver;
    return f === 'csv' ? { filename: base + '.csv', csv: r.csv, sha256: r.sha256 } : { filename: base + '.html', html: r.html, sha256: r.sha256, status: r.status };
  }
  function issue(id, ver0, who) {
    human(who, 'issues a report'); const e = getE(id), ver = Number(param(ver0, 'ver')); const r = R().get(e.id + '-R' + ver); if (!r) throw httpErr(404, 'report version ' + ver + ' not found');
    if (r.status === 'issued') throw httpErr(409, 'already issued');
    Object.assign(r, { status: 'issued', issued_by: who.user, issued_at: iso() }); R().put(r); hist(e, who, r.kind + ' report v' + ver + ' issued'); E().put(e); audit(who, 'report.issue', r.id, { sha256: r.sha256 }); return detail(e.id);
  }
  function signoff(id, src, who) {
    human(who, 'signs off'); const e = getE(id), L = findsOf(e); if (stageOf(e, L) !== 'signoff') throw httpErr(409, 'sign-off comes after an issued final report - stage now: ' + stageOf(e, L));
    const r = R().all((x) => x.eng === e.id && x.kind === 'final' && x.status === 'issued').sort((a, b) => b.version - a.version)[0];
    if (same(who.user, r.by)) throw httpErr(403, 'four eyes: the report\'s author cannot sign it off');
    const b = body(src || {}).str('statement', { required: true, min: 10, max: 1000 }).done();
    Object.assign(e, { signed_by: who.user, signed_at: iso(), signoff_statement: b.statement, signed_report: r.id, signed_sha256: r.sha256, closed_at: iso() });
    hist(e, who, 'signed off report ' + r.id + ' - closed'); E().put(e); audit(who, 'signoff', e.id, { report: r.id, sha256: r.sha256 }); return detail(e.id);
  }
  return { view, detail: detailFresh, create, editScope, authorise, approve, scan, toolRun, importFindings, addFinding, testingDone, validate, remediate, fixed, retest, accept, decide, report, getReport, issue, signoff, inScope, analyse };
}

function registerVaptWorkflow(srv, app, W0) {
  const W = W0 && W0.view ? W0 : createVaptWorkflow(app, W0 || {});
  app.addons = app.addons || {}; app.addons.vaptWorkflow = W;
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  const P = '/vapt-workflow', FP = P + '/:id/findings/:fid';
  srv.route('GET', P, (ctx) => { ctx.need('viewer'); return W.view(who(ctx)); });
  srv.route('GET', P + '/:id', (ctx) => { ctx.need('operator'); return W.detail(ctx.params.id); });
  srv.route('POST', P, (ctx) => { ctx.need('operator'); return W.create(ctx.body, who(ctx)); }, { maxBody: 65536 });
  srv.route('POST', P + '/:id/scope', (ctx) => { ctx.need('operator'); return W.editScope(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 65536 });
  srv.route('POST', P + '/:id/authorise', (ctx) => { ctx.need('admin'); return W.authorise(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', P + '/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); return W.approve(ctx.params.id, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', P + '/:id/scan', (ctx) => { ctx.need('operator'); return W.scan(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 2048 });
  srv.route('POST', P + '/:id/tool-run', (ctx) => { ctx.need('operator'); return W.toolRun(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', P + '/:id/import', (ctx) => { ctx.need('operator'); return W.importFindings(ctx.params.id, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', P + '/:id/findings', (ctx) => { ctx.need('operator'); return W.addFinding(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 32768 });
  srv.route('POST', P + '/:id/testing-done', (ctx) => { ctx.need('operator'); return W.testingDone(ctx.params.id, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', FP + '/validate', (ctx) => { ctx.need('operator'); return W.validate(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', FP + '/remediate', (ctx) => { ctx.need('operator'); return W.remediate(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', FP + '/fixed', (ctx) => { ctx.need('operator'); return W.fixed(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', FP + '/retest', (ctx) => { ctx.need('operator'); return W.retest(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', FP + '/accept', (ctx) => { ctx.need('operator'); return W.accept(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', FP + '/decide', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); return W.decide(ctx.params.id, ctx.params.fid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', P + '/:id/report', (ctx) => { ctx.need('operator'); return W.report(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 1024 });
  srv.route('GET', P + '/:id/report/:ver', (ctx) => { ctx.need('operator'); return W.getReport(ctx.params.id, ctx.params.ver, ctx.query && ctx.query.format, who(ctx)); });
  srv.route('POST', P + '/:id/report/:ver/issue', (ctx) => { ctx.need('admin'); return W.issue(ctx.params.id, ctx.params.ver, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', P + '/:id/signoff', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); return W.signoff(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 4096 });
  return W;
}
module.exports = { createVaptWorkflow, registerVaptWorkflow, KINDS, STAGES };
