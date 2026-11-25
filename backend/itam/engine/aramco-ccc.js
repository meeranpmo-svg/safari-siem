// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const ORG = require('./brand');
/*
 * Saudi Aramco Cybersecurity Compliance Certificate (CCC) - start to end, for a third party that works for Aramco
 * ({P} = /api/itam). The platform ships NO control text: the CCC owner imports the control list from the organisation's own
 * copy of the Aramco Third Party Cybersecurity Standard (SACS-002) - id, domain, title, requirement, the service types it
 * applies to. Nothing is invented: a stage without its records says what is missing.
 *
 *   1 scope        the Aramco contracts (number, service types as the contract classifies them, the date the CCC is needed by)
 *   2 controls     imported control list; applicable = applies to "all" or to a service type of an active contract
 *   3 assessment   every applicable control: implemented / partial / not implemented / not applicable. "Not applicable" is only a
 *                  proposal until a DIFFERENT person (the CCC owner or an administrator) accepts the justification (four-eyes)
 *   4 remediation  actions for each gap (owner, due); overdue said
 *   5 evidence     references to where the evidence is kept (document, system, date) - the files stay in the organisation's own
 *                  systems (PDPL), never here
 *   6 audit        the engagement with the Aramco-approved audit firm and its findings (major / minor / observation)
 *   7 certificate  number, issue and expiry dates as printed, firm, service types covered; contracts the certificate does not cover
 *                  or that need it after expiry are said
 *   8 renewal      renewal due 90 days before expiry; expired said
 *   learning       a daily readiness snapshot; the readiness trend (least squares over 3+ days) projected to 100 % against the
 *                  planned audit date - on track / at risk, with why
 *
 *   GET  /aramco-ccc                              viewer    the whole lifecycle
 *   PUT  /aramco-ccc/profile                      admin     {vendor_no, ccc_owner, planned_audit, audit_firm}
 *   POST /aramco-ccc/contracts                    manager   {id?, contract_no, title, services[], ccc_needed_by, end, active}
 *   POST /aramco-ccc/contracts/:id/remove         manager
 *   POST /aramco-ccc/controls/import              manager   {csv, replace}
 *   POST /aramco-ccc/controls/:id/assess          operator  {status, justification?, owner?, notes?}
 *   POST /aramco-ccc/controls/:id/na              manager   {decision: accepted | refused, comment}   never the proposer
 *   POST /aramco-ccc/controls/:id/evidence        operator  {title, location, collected}
 *   POST /aramco-ccc/actions                      operator  {control, title, owner, due}
 *   POST /aramco-ccc/actions/:id                  operator  {status: open | done, note?}
 *   POST /aramco-ccc/audit                        manager   {firm, lead_auditor?, planned, status}
 *   POST /aramco-ccc/findings                     manager   {id?, control?, severity, title, due?, status}
 *   POST /aramco-ccc/certificate                  manager   {number, issued, expires, firm, services[]}
 * "manager" = the CCC owner named in the profile, or an administrator; always a person, never a service / AI identity.
 */
const DAY = 86400000;
const SERVICES = {
  general: 'General (every third party)',
  'network-connectivity': 'Network connectivity to Aramco',
  'outsourced-infrastructure': 'Outsourced infrastructure / hosting',
  'critical-data': 'Critical data processing',
  'custom-software': 'Customized software development',
  cloud: 'Cloud computing service',
};
const ASSESS = ['implemented', 'partial', 'not-implemented', 'not-applicable'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (x, n = 300) => String(x == null ? '' : x).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').slice(0, n);
const CID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;

// CSV with quotes ("a, b" and "" inside), first row the header
function parseCsv(text) {
  const rows = [], t = String(text || '').replace(/^﻿/, '');
  let row = [], cur = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"' && t[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(cur); cur = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cur); rows.push(row); row = []; cur = ''; } else cur += c;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}
function lsq(pts) { const n = pts.length; if (n < 3) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; for (const [x, y] of pts) { sx += x; sy += y; sxy += x * y; sxx += x * x; } const d = n * sxx - sx * sx; if (!d) return null; const b = (n * sxy - sx * sy) / d; return { slope: b, icept: (sy - b * sx) / n }; }

function createAramcoCcc(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now, C = (n) => store.collection(n);
  const prof = () => C('accc_profile').get('profile') || { id: 'profile' };
  const iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'aramco-ccc.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const manager = (who) => who.role === 'admin' || (prof().ccc_owner && String(prof().ccc_owner).toLowerCase() === String(who.user).toLowerCase());
  const needMgr = (who, what) => { person(who, what); if (!manager(who)) throw httpErr(403, what + ' needs the CCC owner named in the profile, or an administrator'); };
  const nextId = (col, pfx) => { let m = 0; for (const x of C(col).all()) { const n = Number(String(x.id).slice(pfx.length)); if (n > m) m = n; } return pfx + String(m + 1).padStart(4, '0'); };

  function view(who) {
    const p = prof(), contracts = C('accc_contracts').all().sort((a, b) => String(a.contract_no).localeCompare(String(b.contract_no)));
    const active = contracts.filter((c) => c.active !== false && (!c.end || c.end >= today()));
    const svc = new Set(['general']); for (const c of active) for (const x of c.services || []) svc.add(x);
    const all = C('accc_controls').all().sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
    const applicable = all.filter((c) => (c.applies || []).includes('all') || (c.applies || []).some((x) => svc.has(x)));
    const acts = C('accc_actions').all(), findings = C('accc_findings').all(), cert = C('accc_cert').get('current') || null, aud = C('accc_audit').get('current') || null;
    const st = (c) => c.status || 'not-assessed';
    const counted = applicable.filter((c) => !(st(c) === 'not-applicable' && c.na && c.na.state === 'accepted'));
    const score = counted.length ? Math.round(100 * counted.reduce((a, c) => a + (st(c) === 'implemented' ? 1 : st(c) === 'partial' ? 0.5 : 0), 0) / counted.length) : null;
    const assessed = applicable.filter((c) => st(c) !== 'not-assessed').length;
    const gaps = counted.filter((c) => ['partial', 'not-implemented'].includes(st(c)));
    const openActs = acts.filter((a) => a.status !== 'done'), overdue = openActs.filter((a) => a.due && a.due < today());
    const gapsNoAct = gaps.filter((c) => !acts.some((a) => a.control === c.id));
    const implNoEv = counted.filter((c) => st(c) === 'implemented' && !(c.evidence || []).length);
    const naPending = applicable.filter((c) => st(c) === 'not-applicable' && (!c.na || c.na.state === 'proposed'));
    const openMajor = findings.filter((f) => f.status !== 'closed' && f.severity === 'major'), openFind = findings.filter((f) => f.status !== 'closed');
    const certValid = cert && cert.expires >= today(), daysLeft = cert ? Math.floor((Date.parse(cert.expires) - Date.parse(today())) / DAY) : null;
    const uncovered = active.filter((c) => !cert || !certValid || (c.services || []).some((x) => !(cert.services || []).includes(x)) || (c.end && cert.expires < c.end && c.ccc_needed_by && c.ccc_needed_by > cert.expires));
    const stage = (id, name, done, why, next) => ({ id, name, done: !!done, why, next: done ? '' : next });
    const stages = [
      stage('scope', 'Scope', active.length && p.ccc_owner, active.length ? active.length + ' active Aramco contract(s), service types: ' + [...svc].map((x) => SERVICES[x] || x).join(', ') : 'no active Aramco contract recorded', p.ccc_owner ? 'Add the Aramco contracts and their service types' : 'Name the CCC owner in the profile, then add the contracts'),
      stage('controls', 'Controls', applicable.length, all.length ? applicable.length + ' of ' + all.length + ' imported control(s) apply' : 'no control list imported', 'Import the control list from your copy of SACS-002 (CSV: id, domain, title, requirement, applies_to)'),
      stage('assessment', 'Self-assessment', applicable.length && assessed === applicable.length && !naPending.length, assessed + ' of ' + applicable.length + ' assessed' + (naPending.length ? ' · ' + naPending.length + ' "not applicable" waiting for acceptance' : ''), 'Assess every applicable control; a second person accepts each "not applicable"'),
      stage('remediation', 'Remediation', applicable.length && !gaps.length, gaps.length + ' gap(s), ' + openActs.length + ' open action(s)' + (overdue.length ? ', ' + overdue.length + ' overdue' : '') + (gapsNoAct.length ? ', ' + gapsNoAct.length + ' gap(s) without an action' : ''), 'Give every gap an action with an owner and a due date, and close them'),
      stage('evidence', 'Evidence', applicable.length && assessed && !implNoEv.length, implNoEv.length ? implNoEv.length + ' implemented control(s) without evidence' : 'every implemented control has evidence', 'Record where the evidence for each implemented control is kept'),
      stage('audit', 'Audit', aud && aud.status === 'closed' && !openMajor.length, aud ? aud.firm + ' · ' + aud.status + (openFind.length ? ' · ' + openFind.length + ' open finding(s), ' + openMajor.length + ' major' : '') : 'no audit engagement recorded', aud ? 'Close the findings; the firm closes the audit' : 'Engage an Aramco-approved audit firm and record the engagement'),
      stage('certificate', 'Certificate', certValid && !uncovered.length, cert ? (certValid ? 'CCC ' + cert.number + ' valid until ' + cert.expires : 'CCC ' + cert.number + ' EXPIRED ' + cert.expires) + (uncovered.length ? ' · not covering ' + uncovered.map((c) => c.contract_no).join(', ') : '') : 'no certificate recorded', 'Record the certificate the audit firm issues'),
      stage('renewal', 'Renewal', certValid && daysLeft > 90, cert ? (certValid ? daysLeft + ' day(s) to expiry' : 'expired') : 'no certificate yet', 'Start the renewal: re-assess and book the audit firm 90 days before expiry'),
    ];
    const current = stages.find((x) => !x.done) || null;
    // learning: readiness trend → projected 100 % date against the planned audit
    const snaps = C('accc_snaps').all().sort((a, b) => String(a.id).localeCompare(String(b.id))).slice(-120);
    const fit = lsq(snaps.map((x) => [Date.parse(x.id) / DAY, x.score]));
    let projection = null;
    if (fit && fit.slope > 0 && score != null && score < 100) { const d = new Date((100 - fit.icept) / fit.slope * DAY).toISOString().slice(0, 10); projection = { date: d, per_week: Math.round(fit.slope * 7 * 10) / 10, on_track: p.planned_audit ? d <= p.planned_audit : null, why: p.planned_audit ? (d <= p.planned_audit ? 'at the current pace readiness reaches 100 % on ' + d + ', before the planned audit (' + p.planned_audit + ')' : 'at the current pace readiness reaches 100 % on ' + d + ', AFTER the planned audit (' + p.planned_audit + ')') : 'no planned audit date set' }; }
    else if (snaps.length >= 3 && score != null && score < 100) projection = { date: null, per_week: fit ? Math.round(fit.slope * 7 * 10) / 10 : 0, on_track: false, why: 'readiness is not rising - nothing closes the gaps at the current pace' };
    return { org: ORG.name, profile: p, can_manage: manager(who), services: SERVICES, contracts, controls: applicable, controls_total: all.length, score, assessed, applicable: applicable.length,
      gaps: gaps.length, actions: acts.sort((a, b) => String(a.due || '9').localeCompare(String(b.due || '9'))), overdue: overdue.length, evidence_missing: implNoEv.map((c) => c.id), na_pending: naPending.map((c) => c.id),
      audit: aud, findings: findings.sort((a, b) => String(a.id).localeCompare(String(b.id))), certificate: cert, days_left: daysLeft, uncovered: uncovered.map((c) => c.contract_no), stages, current: current && current.id, projection, snapshots: snaps.length };
  }

  function putProfile(b0, who) {
    person(who, 'change the CCC profile');
    const b = body(b0).str('vendor_no', { max: 40 }).str('ccc_owner', { max: 120 }).date('planned_audit').str('audit_firm', { max: 120 }).done();
    if (b.ccc_owner !== undefined && !isHuman(b.ccc_owner)) throw httpErr(400, 'ccc_owner: a person, not a service or AI identity');
    const p = Object.assign(prof(), b, { id: 'profile', updated_by: who.user, updated_at: iso() }); C('accc_profile').put(p);
    audit(who, 'profile', 'profile', { fields: Object.keys(b) }); return view(who);
  }
  function saveContract(b0, who) {
    needMgr(who, 'record an Aramco contract');
    const b = body(b0).str('id', { id: true }).str('contract_no', { required: true, max: 40 }).str('title', { required: true, max: 160 }).list('services', { required: true, max: 6, item: Object.keys(SERVICES), unique: true })
      .date('ccc_needed_by').date('end').bool('active', { def: true }).done();
    const id = b.id || nextId('accc_contracts', 'CON-'); if (b.id && !C('accc_contracts').get(b.id)) throw httpErr(404, 'contract not found');
    const c = C('accc_contracts').put(Object.assign({}, b, { id, updated_by: who.user, updated_at: iso() }));
    audit(who, b.id ? 'contract.update' : 'contract.add', id, { contract_no: c.contract_no, services: c.services, active: c.active }); return c;
  }
  function removeContract(id, who) { needMgr(who, 'remove an Aramco contract'); param(id); const c = C('accc_contracts').get(id); if (!c) throw httpErr(404, 'contract not found'); C('accc_contracts').remove(id); audit(who, 'contract.remove', id, { contract_no: c.contract_no }); return { removed: id }; }

  function importControls(b0, who) {
    needMgr(who, 'import the control list');
    const b = body(b0).str('csv', { required: true, max: 2000000 }).bool('replace', { def: false }).done();
    const rows = parseCsv(b.csv); if (rows.length < 2) throw httpErr(400, 'csv: a header row and at least one control');
    const h = rows[0].map((x) => x.trim().toLowerCase().replace(/[\s-]+/g, '_')), at = (k) => h.indexOf(k);
    for (const k of ['id', 'title', 'applies_to']) if (at(k) < 0) throw httpErr(400, 'csv: the header needs the columns id, domain, title, requirement, applies_to (missing ' + k + ')');
    const out = [], errs = [], seen = new Set(), okSvc = new Set(['all', ...Object.keys(SERVICES)]);
    rows.slice(1).forEach((r, i) => {
      const id = s(r[at('id')], 40).trim(), applies = s(r[at('applies_to')], 300).split(/[|;]/).map((x) => x.trim().toLowerCase()).filter(Boolean);
      if (!CID.test(id)) { errs.push('row ' + (i + 2) + ': id "' + id + '" is not a control id'); return; }
      if (seen.has(id)) { errs.push('row ' + (i + 2) + ': id ' + id + ' twice'); return; } seen.add(id);
      const badS = applies.filter((x) => !okSvc.has(x)); if (!applies.length || badS.length) { errs.push('row ' + (i + 2) + ': applies_to must be all or ' + Object.keys(SERVICES).join(' | ') + (badS.length ? ' (not ' + badS.join(', ') + ')' : '')); return; }
      out.push({ id, domain: s(at('domain') >= 0 ? r[at('domain')] : '', 120).trim(), title: s(r[at('title')], 300).trim(), requirement: s(at('requirement') >= 0 ? r[at('requirement')] : '', 4000).trim(), applies });
    });
    if (errs.length) throw httpErr(400, 'csv: ' + errs.slice(0, 5).join('; ') + (errs.length > 5 ? ' (+' + (errs.length - 5) + ' more)' : ''));
    if (out.length > 2000) throw httpErr(400, 'csv: more than 2000 controls');
    const col = C('accc_controls');
    if (b.replace) for (const c of col.all()) if (!seen.has(c.id)) col.remove(c.id);
    let added = 0, updated = 0;
    for (const c of out) { const cur = col.get(c.id); if (cur) { updated++; col.put(Object.assign(cur, c)); } else { added++; col.put(Object.assign(c, { status: 'not-assessed', evidence: [] })); } }
    audit(who, 'controls.import', 'controls', { added, updated, replace: b.replace, total: col.size() }); return { added, updated, total: col.size() };
  }
  function must(id) { param(id); const c = C('accc_controls').get(id); if (!c) throw httpErr(404, 'control not found'); return c; }
  function assess(id, b0, who) {
    person(who, 'assess a control');
    const c = must(id), b = body(b0).oneOf('status', ASSESS, { required: true }).str('justification', { max: 1000 }).str('owner', { max: 120 }).str('notes', { max: 2000 }).done();
    if (b.status === 'not-applicable' && !(b.justification && b.justification.length >= 20)) throw httpErr(400, 'justification: say why the control does not apply (at least 20 characters)');
    const next = C('accc_controls').patch(id, (x) => { x.status = b.status; x.owner = b.owner !== undefined ? b.owner : x.owner; x.notes = b.notes !== undefined ? b.notes : x.notes; x.assessed_by = who.user; x.assessed_at = iso();
      x.na = b.status === 'not-applicable' ? { state: 'proposed', by: who.user, at: iso(), justification: b.justification } : null; return x; });
    audit(who, 'control.assess', id, { from: c.status || 'not-assessed', to: b.status }); return next;
  }
  function decideNa(id, b0, who) {
    needMgr(who, 'accept a "not applicable"');
    const c = must(id), b = body(b0).oneOf('decision', ['accepted', 'refused'], { required: true }).str('comment', { max: 600 }).done();
    if (c.status !== 'not-applicable' || !c.na || c.na.state !== 'proposed') throw httpErr(409, 'no "not applicable" is waiting on this control');
    if (String(c.na.by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who proposed "not applicable" does not accept it');
    if (b.decision === 'refused' && !(b.comment && b.comment.length >= 5)) throw httpErr(400, 'comment: say why it is refused');
    const next = C('accc_controls').patch(id, (x) => { x.na = Object.assign(x.na, { state: b.decision, decided_by: who.user, decided_at: iso(), comment: b.comment || '' }); if (b.decision === 'refused') x.status = 'not-assessed'; return x; });
    audit(who, 'control.na.' + b.decision, id, { proposed_by: c.na.by }); return next;
  }
  function addEvidence(id, b0, who) {
    person(who, 'record evidence');
    must(id); const b = body(b0).str('title', { required: true, max: 200 }).str('location', { required: true, max: 300 }).date('collected', { required: true }).done();
    if (b.collected > today()) throw httpErr(400, 'collected: not in the future');
    const next = C('accc_controls').patch(id, (x) => { x.evidence = (x.evidence || []).concat({ title: b.title, location: b.location, collected: b.collected, by: who.user, at: iso() }).slice(-30); return x; });
    audit(who, 'control.evidence', id, { title: b.title }); return next;
  }
  function addAction(b0, who) {
    person(who, 'add an action');
    const b = body(b0).str('control', { required: true, id: true }).str('title', { required: true, max: 200 }).str('owner', { required: true, max: 120 }).date('due', { required: true }).done();
    must(b.control); const a = C('accc_actions').put(Object.assign(b, { id: nextId('accc_actions', 'ACT-'), status: 'open', created_by: who.user, created_at: iso() }));
    audit(who, 'action.add', a.id, { control: a.control, due: a.due }); return a;
  }
  function updateAction(id, b0, who) {
    person(who, 'update an action'); param(id);
    const b = body(b0).oneOf('status', ['open', 'done'], { required: true }).str('note', { max: 600 }).done();
    const a = C('accc_actions').get(id); if (!a) throw httpErr(404, 'action not found');
    if (b.status === 'done' && !(b.note && b.note.length >= 5)) throw httpErr(400, 'note: say what was done');
    const next = C('accc_actions').patch(id, (x) => { x.status = b.status; x.note = b.note || x.note; x.closed_by = b.status === 'done' ? who.user : null; x.closed_at = b.status === 'done' ? iso() : null; return x; });
    audit(who, 'action.' + b.status, id, { control: a.control }); return next;
  }
  function saveAudit(b0, who) {
    needMgr(who, 'record the audit engagement');
    const b = body(b0).str('firm', { required: true, max: 120 }).str('lead_auditor', { max: 120 }).date('planned', { required: true }).oneOf('status', ['planned', 'fieldwork', 'report', 'closed'], { required: true }).done();
    if (b.status === 'closed' && C('accc_findings').all().some((f) => f.status !== 'closed' && f.severity === 'major')) throw httpErr(409, 'status: a major finding is still open - close it before the audit is closed');
    const a = C('accc_audit').put(Object.assign(C('accc_audit').get('current') || {}, b, { id: 'current', updated_by: who.user, updated_at: iso() }));
    audit(who, 'audit', 'current', { firm: a.firm, status: a.status }); return a;
  }
  function saveFinding(b0, who) {
    needMgr(who, 'record an audit finding');
    const b = body(b0).str('id', { id: true }).str('control', { id: true }).oneOf('severity', ['major', 'minor', 'observation'], { required: true }).str('title', { required: true, max: 300 }).date('due').oneOf('status', ['open', 'closed'], { def: 'open' }).done();
    if (b.control) must(b.control); if (b.id && !C('accc_findings').get(b.id)) throw httpErr(404, 'finding not found');
    const f = C('accc_findings').put(Object.assign(b.id ? C('accc_findings').get(b.id) : {}, b, { id: b.id || nextId('accc_findings', 'FND-'), updated_by: who.user, updated_at: iso() }));
    audit(who, 'finding', f.id, { severity: f.severity, status: f.status }); return f;
  }
  function saveCert(b0, who) {
    needMgr(who, 'record the certificate');
    const b = body(b0).str('number', { required: true, max: 60 }).date('issued', { required: true }).date('expires', { required: true }).str('firm', { required: true, max: 120 }).list('services', { required: true, max: 6, item: Object.keys(SERVICES), unique: true }).done();
    if (b.expires <= b.issued) throw httpErr(400, 'expires: after the issue date');
    if (b.issued > today()) throw httpErr(400, 'issued: not in the future');
    const prev = C('accc_cert').get('current'); if (prev) C('accc_cert').put(Object.assign({}, prev, { id: 'prev-' + prev.number.replace(/[^A-Za-z0-9._-]/g, '_') }));
    const c = C('accc_cert').put(Object.assign(b, { id: 'current', recorded_by: who.user, recorded_at: iso() }));
    audit(who, 'certificate', b.number, { issued: b.issued, expires: b.expires, services: b.services }); return c;
  }
  function snapshot() { const v = view({ user: 'system', role: 'viewer' }); if (v.score == null) return null; return C('accc_snaps').put({ id: today(), score: v.score, gaps: v.gaps, assessed: v.assessed, applicable: v.applicable }); }
  let timer = null; const tick = guardOf(app, 'aramco-ccc.daily', async () => { snapshot(); });
  return { view, putProfile, saveContract, removeContract, importControls, assess, decideNa, addEvidence, addAction, updateAction, saveAudit, saveFinding, saveCert, snapshot,
    start() { if (timer || opts.noTimer) return; setTimeout(tick, 190000).unref(); timer = setInterval(tick, 6 * 3600000); timer.unref(); }, stop() { if (timer) clearInterval(timer); timer = null; } };
}

function registerAramcoCcc(srv, app, X) {
  srv.route('GET', '/aramco-ccc', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('PUT', '/aramco-ccc/profile', (ctx) => { ctx.need('admin'); return X.putProfile(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/contracts', (ctx) => { ctx.need('operator'); return X.saveContract(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/contracts/:id/remove', (ctx) => { ctx.need('operator'); return X.removeContract(ctx.params.id, ctx.who); });
  srv.route('POST', '/aramco-ccc/controls/import', (ctx) => { ctx.need('operator'); return X.importControls(ctx.body, ctx.who); }, { maxBody: 2200000 });
  srv.route('POST', '/aramco-ccc/controls/:id/assess', (ctx) => { ctx.need('operator'); return X.assess(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/aramco-ccc/controls/:id/na', (ctx) => { ctx.need('operator'); return X.decideNa(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/controls/:id/evidence', (ctx) => { ctx.need('operator'); return X.addEvidence(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/actions', (ctx) => { ctx.need('operator'); return X.addAction(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/actions/:id', (ctx) => { ctx.need('operator'); return X.updateAction(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/audit', (ctx) => { ctx.need('operator'); return X.saveAudit(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/findings', (ctx) => { ctx.need('operator'); return X.saveFinding(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/aramco-ccc/certificate', (ctx) => { ctx.need('operator'); return X.saveCert(ctx.body, ctx.who); }, { maxBody: 4096 });
}

module.exports = { createAramcoCcc, registerAramcoCcc, parseCsv, SERVICES };
