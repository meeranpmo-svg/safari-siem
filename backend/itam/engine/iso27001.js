// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * ISO/IEC 27001:2022 - the ISMS run by the platform ({P} = /api/itam). Python decides (pyengine/iso27001_rules.py); this file
 * validates at the boundary, gathers the facts, commits and audits.
 *
 * Built to save the audit team's time:
 *   - one evidence collection: the facts are the NCA ECC register's (engine/nca-ecc.js facts(), cached 60 s), checked by the
 *     same rules, so ISO and ECC never disagree and the platform is read once for both;
 *   - record once: a manual control already confirmed and approved in the NCA ECC register counts for the linked ISO control;
 *   - the internal audit programme (9.2) is generated risk-first, and each audit's working paper is PREPARED by the daily job
 *     from the register a month before it is due - tests, evidence and proposed findings; the auditor decides;
 *   - accepted major / minor findings become nonconformities (10.2) and GRC actions without retyping; a nonconformity closes
 *     only when a different person verifies the corrective action worked;
 *   - the management review pack (9.3.2 a-g) and the Statement of Applicability are generated from the records;
 *   - a daily snapshot gives the measurement trend (9.1).
 *
 * People decide: a confirmation is approved by a second person (the ISMS manager or an administrator, never the one who
 * recorded it); the SoA is approved by someone other than who proposed it; an auditor is independent of what is audited and
 * a different person accepts the report; service and AI identities never record, approve, audit or verify.
 *
 *   GET  /iso27001                         viewer    clauses, Annex A, themes, SoA, readiness, findings
 *   GET  /iso27001/export?what=register|soa  operator CSV                                                 audited
 *   POST /iso27001/profile                 admin     scope, ISMS manager, objectives, review dates, auditors   audited
 *   POST /iso27001/confirm                 operator  {id, status, evidence?, note?}                            audited
 *   POST /iso27001/confirm/:id/decide      operator  ISMS manager / admin, four eyes                           audited
 *   POST /iso27001/soa                     operator  ISMS manager / admin: {exclusions{id: why}} -> proposed    audited
 *   POST /iso27001/soa/decide              operator  a different ISMS manager / admin approves or rejects       audited
 *   GET  /iso27001/programme               viewer    audits, nonconformities, management reviews
 *   POST /iso27001/programme               operator  ISMS manager / admin: {start?, months?} (re)plan          audited
 *   POST /iso27001/audits/:id/assign       operator  ISMS manager / admin: {auditor}  independence checked      audited
 *   POST /iso27001/audits/:id/prepare      operator  re-prepare the working paper from the register now         audited
 *   POST /iso27001/audits/:id/findings     operator  the assigned auditor: {findings[], submit?}               audited
 *   POST /iso27001/audits/:id/accept       operator  ISMS manager / admin, not the auditor: report accepted     audited
 *   POST /iso27001/ncs/:id                 operator  {root_cause, correction, corrective_action, owner, due}    audited
 *   POST /iso27001/ncs/:id/implemented     operator  {evidence}                                                 audited
 *   POST /iso27001/ncs/:id/verify          operator  {decision: effective|not_effective, note}  not the implementer audited
 *   GET  /iso27001/reviews/pack            operator  the 9.3.2 inputs from the records
 *   POST /iso27001/reviews                 operator  ISMS manager / admin: {held_on, chaired_by, attendees, decisions, actions[]} audited
 *   POST /iso27001/gaps-to-grc             operator  ISMS manager / admin: every gap becomes a GRC action (once) audited
 *
 * The duty engineer (id iso27001, "AI ISO 27001 Lead Implementer") turns gaps, overdue audits and overdue nonconformities into
 * work items and closes them when the register no longer shows them. It proposes; it never approves and never changes a system.
 */
const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];
const CID = /^(?:A\.[5-8]\.\d{1,2}|(?:4|5|6|7|8|9|10)\.\d(?:\.\d)?)$/;
const ANNEX = /^A\.[5-8]\.\d{1,2}$/;
const GRADES = ['major', 'minor', 'ofi', 'conforming', 'evidence_request'];
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'a user name (letters, digits, . _ - @ \\)' };
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createIso27001(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const day = (ms) => new Date(ms).toISOString().slice(0, 10);
  const col = (n) => store.collection(n);
  const prof = () => col('iso_profile'), conf = () => col('iso_confirm'), soaC = () => col('iso_soa'), aud = () => col('iso_audits'),
    ncC = () => col('iso_ncs'), rev = () => col('iso_reviews'), hist = () => col('iso_history');
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('iso:' + key, 3600000, 'warn', msg, { err: String((err && err.message) || err || '').slice(0, 200) }); };
  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (!r || r.ok === false) {
      warn('py', 'ISO 27001: the rules (Python) did not answer', r && r.error);
      throw httpErr(409, (r && r.error && /unknown audit unit/.test(r.error)) ? r.error : 'The ISO 27001 rules run in Python and Python did not answer - run the update so pyengine is installed');
    }
    return r;
  }
  const profile = () => prof().get('profile') || {};
  const soa = () => soaC().get('current') || { exclusions: {} };
  const byId = (c) => { const o = {}; for (const x of c.all(() => true)) o[x.id] = x; return o; };
  const sortId = (a, b) => String(a.id).localeCompare(String(b.id), 'en', { numeric: true });
  const audits = () => aud().all(() => true).sort((a, b) => String(a.due).localeCompare(String(b.due)));
  const ncs = () => ncC().all(() => true).sort(sortId);
  const reviews = () => rev().all(() => true).sort((a, b) => String(b.held_on).localeCompare(String(a.held_on)));
  const history = () => hist().all(() => true).sort((a, b) => String(a.at).localeCompare(String(b.at)));
  const addon = (k) => app.addons && app.addons[k];
  const manager = (who) => who.role === 'admin' || same(profile().isms_manager, who.user);
  const needManager = (who, what) => {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does');
    if (!manager(who)) throw httpErr(403, what + ' needs the ISMS manager named in the ISO 27001 profile or an administrator');
  };
  const nextId = (prefix, c) => { let n = c.all(() => true).length + 1, id; do { id = prefix + '-' + String(n++).padStart(4, '0'); } while (c.get(id)); return id; };

  // ---- one evidence collection for ISO and NCA ECC, cached briefly so a page load and the patrol do not read it twice
  let factsAt = 0, factsP = null;
  function facts() {
    if (opts.facts) return Promise.resolve(opts.facts());
    if (factsP && now() - factsAt < 60000) return factsP;
    const N = addon('ncaEcc') || (() => { try { return require('./nca-ecc').createNcaEcc(app, { now: opts.now, python: opts.python }); } catch (e) { warn('ecc', 'ISO 27001: the NCA ECC fact reader is not installed', e); return null; } })();
    factsAt = now();
    factsP = N ? N.facts().catch((e) => { factsP = null; warn('facts', 'ISO 27001: the platform facts could not be read', e); return {}; }) : Promise.resolve({});
    return factsP;
  }
  const eccProfile = () => { try { return col('ecc_profile').get('profile') || {}; } catch (e) { warn('eccp', 'ISO 27001: the NCA ECC profile was not read', e); return {}; } };
  const eccConfirms = () => { try { return byId(col('ecc_confirm')); } catch (e) { warn('eccc', 'ISO 27001: the NCA ECC confirmations were not read', e); return {}; } };

  async function input() {
    return { facts: await facts(), profile: profile(), ecc_profile: eccProfile(), confirms: byId(conf()), ecc_confirms: eccConfirms(), soa: soa(),
      audits: audits(), reviews: reviews(), ncs: ncs(), history: history().slice(-400), now: now() };
  }
  async function view() {
    const v = await rules('iso.view', await input());
    const p = profile(), s = soa();
    return Object.assign({}, v, {
      profile: { isms_manager: p.isms_manager || null, scope: p.scope || '', scope_approved: p.scope_approved || null, context_reviewed: p.context_reviewed || null,
        parties_reviewed: p.parties_reviewed || null, risk_method_approved: p.risk_method_approved || null, top_management: p.top_management || null,
        auditors: p.auditors || [], objectives: p.objectives || [], updated_by: p.updated_by || null, updated_at: p.updated_at || null },
      soa_state: { version: s.version || 0, proposed_by: s.proposed_by || null, proposed_at: s.proposed_at || null, approved_by: s.approved_by || null, approved_at: s.approved_at || null, stale: v.soa.stale },
      history: history().slice(-90).map((h) => ({ at: h.at, score: h.score, annex_pct: h.annex_pct })), generated_at: iso() });
  }

  function putProfile(input, who) {
    const d = { notFuture: true, now: now() };
    const src = input || {};
    const b = body(src).str('isms_manager', USER).str('top_management', { max: 120 }).str('scope', { max: 2000 }).date('scope_approved', d).date('context_reviewed', d)
      .date('parties_reviewed', d).date('risk_method_approved', d).list('auditors', { max: 30, item: 'str', itemMax: 80, unique: true }).list('objectives', { max: 30 }).done();
    if (b.auditors) for (const [i, a] of b.auditors.entries()) if (!USER.re.test(a) || isService(a)) throw httpErr(400, 'auditors[' + i + '] must be a person\'s user name');
    if (b.objectives) {
      b.objectives = b.objectives.map((o, i) => {
        if (!o || typeof o !== 'object' || Array.isArray(o)) throw httpErr(400, 'objectives[' + i + '] must be an object {objective, measure, target, owner}');
        try { return body(o).str('objective', { required: true, max: 300 }).str('measure', { max: 300 }).str('target', { max: 120 }).str('owner', { max: 80 }).str('current', { max: 120 }).date('measured_on', d).done(); }
        catch (e) { throw httpErr(400, 'objectives[' + i + '].' + e.message); }
      });
    }
    if (b.scope_approved && !(b.scope || profile().scope)) throw httpErr(400, 'scope is required before scope_approved: write the scope statement');
    const rec = Object.assign({}, profile(), b, { id: 'profile', updated_by: who.user, updated_at: iso() });
    prof().put(rec);
    audit(who, 'iso.profile', 'profile', { fields: Object.keys(b), isms_manager: rec.isms_manager || null });
    return rec;
  }

  async function confirm(input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot record an ISO 27001 control: a person does');
    const b = body(input || {}).str('id', { required: true, re: CID, msg: 'id must be an ISO 27001 clause (e.g. 9.2) or Annex A control (e.g. A.5.15)' }).oneOf('status', STATUSES, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for compliant / partial: name the document, report or record relied on' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    const v = await view();
    if (!v.clauses.concat(v.annex).some((c) => c.id === b.id)) throw httpErr(404, 'no ISO 27001 requirement ' + b.id);
    const prev = conf().get(b.id);
    conf().put({ id: b.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: iso(), approved_by: null, approved_at: null });
    audit(who, 'iso.confirm', b.id, { status: b.status, previous: prev ? prev.status : null, evidence: b.evidence ? 'given' : 'none' });
    const v2 = await view();
    return v2.clauses.concat(v2.annex).find((c) => c.id === b.id);
  }

  async function decide(id, input, who) {
    const cid = param(id);
    if (!CID.test(cid)) throw httpErr(400, 'id must be an ISO 27001 clause or Annex A control');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const c = conf().get(cid); if (!c) throw httpErr(404, 'nothing recorded for ' + cid + ' yet');
    if (c.approved_by) throw httpErr(409, cid + ' was already approved by ' + c.approved_by);
    needManager(who, 'approving an ISO 27001 control');
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' recorded ' + cid + ' and cannot also approve it');
    if (b.decision === 'reject') { conf().remove(cid); audit(who, 'iso.confirm.reject', cid, { recorded_by: c.by, status: c.status, note: b.note }); }
    else { conf().put(Object.assign({}, c, { approved_by: who.user, approved_at: iso(), approve_note: b.note || '' })); audit(who, 'iso.confirm.approve', cid, { recorded_by: c.by, status: c.status }); }
    const v = await view();
    return v.clauses.concat(v.annex).find((x) => x.id === cid);
  }

  // ---- Statement of Applicability: exclusions need a justification; a proposal is approved by someone else
  async function proposeSoa(input, who) {
    needManager(who, 'changing the Statement of Applicability');
    const src = input || {};
    const ex = src.exclusions;
    if (ex === undefined || !ex || typeof ex !== 'object' || Array.isArray(ex)) throw httpErr(400, 'exclusions must be an object {"A.7.x": "why it does not apply"} ({} includes every control)');
    const out = {};
    for (const k of Object.keys(ex)) {
      if (!ANNEX.test(k)) throw httpErr(400, 'exclusions: ' + k + ' is not an Annex A control (A.5.1 - A.8.34)');
      const j = body(ex).str(k, { required: true, max: 500 }).done()[k];
      if (!j || j.length < 10) throw httpErr(400, 'exclusions.' + k + ': give the justification for excluding it (at least 10 characters)');
      out[k] = j;
    }
    const cur = soa();
    const draft = { id: 'current', exclusions: out, version: (cur.version || 0) + 1, proposed_by: who.user, proposed_at: iso(), approved_by: null, approved_at: null, hash: null };
    soaC().put(draft);
    const v = await view();
    soaC().put(Object.assign({}, draft, { proposed_hash: v.soa.hash }));
    audit(who, 'iso.soa.propose', 'v' + draft.version, { excluded: Object.keys(out), previous: cur.version || 0 });
    return { version: draft.version, excluded: Object.keys(out).length, applicable: v.soa.applicable, waiting_for: 'a different ISMS manager / administrator to approve' };
  }
  async function decideSoa(input, who) {
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const s = soa();
    if (!s.proposed_by) throw httpErr(409, 'no Statement of Applicability is waiting for approval - propose one first');
    if (s.approved_by) throw httpErr(409, 'SoA v' + s.version + ' is already approved by ' + s.approved_by);
    needManager(who, 'approving the Statement of Applicability');
    if (same(s.proposed_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' proposed SoA v' + s.version + ' and cannot also approve it');
    const v = await view();
    if (s.proposed_hash && s.proposed_hash !== v.soa.hash) throw httpErr(409, 'the SoA changed since it was proposed - propose it again');
    if (b.decision === 'reject') {
      soaC().put(Object.assign({}, s, { proposed_by: null, proposed_at: null, rejected_by: who.user, rejected_at: iso(), reject_note: b.note }));
      audit(who, 'iso.soa.reject', 'v' + s.version, { proposed_by: s.proposed_by, note: b.note });
      return { version: s.version, approved: false };
    }
    const rec = Object.assign({}, s, { approved_by: who.user, approved_at: iso(), hash: v.soa.hash, approve_note: b.note || '' });
    soaC().put(rec);
    soaC().put(Object.assign({}, rec, { id: 'v' + rec.version, rows: v.soa.rows.map((r) => ({ id: r.id, applicable: r.applicable, justification: r.justification })) }));   // the approved version, kept
    audit(who, 'iso.soa.approve', 'v' + s.version, { proposed_by: s.proposed_by, hash: v.soa.hash.slice(0, 16) });
    return { version: s.version, approved: true, hash: v.soa.hash };
  }

  // ---- internal audit programme (9.2)
  async function planProgramme(input, who, system) {
    if (!system) needManager(who, 'planning the internal audit programme');
    const b = body(input || {}).date('start').int('months', { min: 3, max: 36 }).done();
    const v = await view();
    const p = await rules('iso.plan', { rows: v.clauses.concat(v.annex), start: b.start || day(now()), months: b.months || 12, now: now() });
    const keep = audits().filter((a) => a.status !== 'planned');   // work already prepared, started or reported is never replanned
    for (const a of audits()) if (a.status === 'planned') aud().remove(a.id);
    const busy = new Set(keep.filter((a) => a.status !== 'reported' && a.status !== 'cancelled').map((a) => a.unit));
    const made = [];
    for (const a of p.audits) {
      if (busy.has(a.unit)) continue;
      const id = nextId('IA', aud());
      aud().put({ id, unit: a.unit, name: a.name, due: a.due, risk: a.risk, scope: a.scope, status: 'planned', auditor: null, planned_by: who.user, planned_at: iso(), cycle_months: p.months });
      made.push(id);
    }
    audit(who, 'iso.programme.plan', 'programme', { audits: made.length, months: p.months, kept: keep.length });
    return { planned: made.length, kept: keep.length, months: p.months, audits: audits() };
  }

  const must = (c, id, what) => { const x = c.get(param(id)); if (!x) throw httpErr(404, 'no ' + what + ' ' + id); return x; };

  async function prepareAudit(id, who) {
    const a = must(aud(), id, 'audit');
    if (['reported', 'cancelled', 'awaiting_acceptance'].includes(a.status)) throw httpErr(409, a.id + ' is ' + a.status.replace('_', ' ') + ' - its working paper is final');
    const v = await view();
    const wp = await rules('iso.prepare', { unit: a.unit, rows: v.clauses.concat(v.annex), now: now() });
    const rec = Object.assign({}, a, { status: a.status === 'planned' ? 'prepared' : a.status, working_paper: { tests: wp.tests, proposed: wp.proposed, note: wp.note, prepared_at: iso(), prepared_by: who.user } });
    if (!rec.findings) rec.findings = wp.tests.filter((t) => t.proposed !== 'conforming').map((t) => ({ requirement: t.id, grade: t.proposed, statement: t.title + ': ' + String(t.evidence || '').slice(0, 300), evidence: t.evidence_hint, proposed: true }));
    aud().put(rec);
    audit(who, 'iso.audit.prepare', a.id, { unit: a.unit, tests: wp.tests.length, proposed: wp.proposed });
    return rec;
  }

  async function assignAudit(id, input, who) {
    needManager(who, 'assigning an internal auditor');
    const a = must(aud(), id, 'audit');
    if (['reported', 'cancelled'].includes(a.status)) throw httpErr(409, a.id + ' is ' + a.status);
    const b = body(input || {}).str('auditor', Object.assign({ required: true }, USER)).done();
    if (isService(b.auditor)) throw httpErr(400, 'auditor must be a person, not a service or AI identity');
    const pr = profile();
    if ((pr.auditors || []).length && !(pr.auditors || []).some((x) => same(x, b.auditor))) throw httpErr(400, 'auditor: ' + b.auditor + ' is not in the ISO 27001 profile\'s list of internal auditors');
    // 9.2: auditors do not audit their own work - not the ISMS manager on the ISMS core, not anyone who recorded or approved a control in scope
    if (a.unit === 'ISMS' && same(pr.isms_manager, b.auditor)) throw httpErr(400, 'auditor: the ISMS manager cannot audit the ISMS core (clause 9.2 objectivity)');
    const scope = new Set(a.scope || []);
    const own = conf().all((c) => scope.has(c.id) && (same(c.by, b.auditor) || same(c.approved_by, b.auditor))).map((c) => c.id);
    if (own.length) throw httpErr(400, 'auditor: ' + b.auditor + ' recorded or approved ' + own.slice(0, 5).join(', ') + ' in this audit\'s scope - choose an independent auditor');
    aud().put(Object.assign({}, a, { auditor: b.auditor, assigned_by: who.user, assigned_at: iso() }));
    audit(who, 'iso.audit.assign', a.id, { auditor: b.auditor, previous: a.auditor || null });
    return aud().get(a.id);
  }

  async function auditFindings(id, input, who) {
    const a = must(aud(), id, 'audit');
    if (!a.auditor) throw httpErr(409, a.id + ' has no auditor assigned yet');
    if (!same(a.auditor, who.user)) throw httpErr(403, 'only the assigned auditor (' + a.auditor + ') records findings for ' + a.id);
    if (['reported', 'cancelled', 'awaiting_acceptance'].includes(a.status)) throw httpErr(409, a.id + ' is ' + a.status.replace('_', ' '));
    const b = body(input || {}).list('findings', { required: true, max: 200 }).bool('submit', { def: false }).str('conclusion', { max: 2000 }).done();
    const scope = new Set(a.scope || []);
    const F = b.findings.map((f, i) => {
      if (!f || typeof f !== 'object' || Array.isArray(f)) throw httpErr(400, 'findings[' + i + '] must be an object {requirement, grade, statement}');
      let o; try { o = body(f).str('requirement', { required: true, re: CID, msg: 'requirement must be an ISO 27001 clause or Annex A control' }).oneOf('grade', GRADES, { required: true }).str('statement', { required: true, max: 1000 }).str('evidence', { max: 500 }).done(); }
      catch (e) { throw httpErr(400, 'findings[' + i + '].' + e.message); }
      if (!scope.has(o.requirement)) throw httpErr(400, 'findings[' + i + '].requirement ' + o.requirement + ' is not in the scope of ' + a.id);
      return o;
    });
    if (b.submit && F.some((f) => f.grade === 'evidence_request')) throw httpErr(400, 'findings: resolve every evidence request (conforming, OFI, minor or major) before submitting the report');
    if (b.submit && !b.conclusion) throw httpErr(400, 'conclusion is required to submit the report');
    const summary = {}; for (const f of F) summary[f.grade] = (summary[f.grade] || 0) + 1;
    aud().put(Object.assign({}, a, { findings: F, summary, conclusion: b.conclusion || a.conclusion || '', status: b.submit ? 'awaiting_acceptance' : 'in_progress', submitted_at: b.submit ? iso() : null }));
    audit(who, b.submit ? 'iso.audit.submit' : 'iso.audit.findings', a.id, { summary });
    return aud().get(a.id);
  }

  async function acceptAudit(id, input, who) {
    needManager(who, 'accepting an internal audit report');
    const a = must(aud(), id, 'audit');
    if (a.status !== 'awaiting_acceptance') throw httpErr(409, a.id + ' is ' + String(a.status).replace('_', ' ') + ' - the auditor submits the report first');
    if (same(a.auditor, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' audited ' + a.id + ' and cannot also accept the report');
    const b = body(input || {}).str('note', { max: 1000 }).done();
    const G = addon('grcRegisters') || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'ISO 27001: the GRC registers are not installed', e); return null; } })();
    const made = [];
    for (const f of (a.findings || []).filter((x) => x.grade === 'major' || x.grade === 'minor')) {
      const nid = nextId('NC', ncC());
      const due = day(now() + (f.grade === 'major' ? 30 : 90) * DAY);
      let act = null;
      if (G) {
        try { act = G.actionCreate({ title: 'ISO 27001 ' + nid + ' (' + f.grade + ') ' + f.requirement + ': ' + f.statement.slice(0, 140), source: 'iso', ref: 'iso:' + nid, framework: 'ISO 27001', priority: f.grade === 'major' ? 'high' : 'medium', due, description: f.statement + ' (internal audit ' + a.id + ', auditor ' + a.auditor + ')' }, { user: who.user, role: who.role, ip: who.ip }).id; }
        catch (e) { warn('grc-act', 'ISO 27001: a GRC action was not created for ' + nid, e); }
      }
      ncC().put({ id: nid, audit: a.id, requirement: f.requirement, grade: f.grade, statement: f.statement, evidence: f.evidence || '', status: 'open', due, grc_action: act,
        raised_by: a.auditor, raised_at: iso(), owner: null, root_cause: '', correction: '', corrective_action: '', history: [{ at: iso(), by: who.user, what: 'raised from ' + a.id }] });
      made.push(nid);
    }
    aud().put(Object.assign({}, a, { status: 'reported', reported_at: iso(), accepted_by: who.user, accept_note: b.note || '', ncs: made }));
    audit(who, 'iso.audit.accept', a.id, { auditor: a.auditor, ncs: made, summary: a.summary || {} });
    return { audit: aud().get(a.id), nonconformities: made };
  }

  // ---- nonconformity and corrective action (10.2)
  const ncHist = (x, who, what) => (x.history || []).concat([{ at: iso(), by: who.user, what }]).slice(-50);
  function ncPlan(id, input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot plan a corrective action');
    const x = must(ncC(), id, 'nonconformity');
    if (['closed', 'cancelled'].includes(x.status)) throw httpErr(409, x.id + ' is ' + x.status);
    if (!(manager(who) || same(x.owner, who.user))) throw httpErr(403, 'the nonconformity owner or the ISMS manager plans the corrective action');
    const b = body(input || {}).str('root_cause', { required: true, min: 10, max: 1000 }).str('correction', { max: 1000 }).str('corrective_action', { required: true, min: 10, max: 1000 })
      .str('owner', Object.assign({ required: true }, USER)).date('due').done();
    if (isService(b.owner)) throw httpErr(400, 'owner must be a person');
    if (b.due && Date.parse(b.due) > Date.parse(x.due) + 90 * DAY) throw httpErr(400, 'due: more than 90 days past the original due date ' + x.due + ' - record the reason with the ISMS manager');
    ncC().put(Object.assign({}, x, b, { status: 'action', due: b.due || x.due, planned_by: who.user, history: ncHist(x, who, 'root cause and corrective action recorded, owner ' + b.owner) }));
    audit(who, 'iso.nc.plan', x.id, { owner: b.owner, due: b.due || x.due });
    return ncC().get(x.id);
  }
  function ncImplemented(id, input, who) {
    const x = must(ncC(), id, 'nonconformity');
    if (x.status !== 'action') throw httpErr(409, x.id + ' is ' + x.status + ' - record the root cause and corrective action first');
    if (!(same(x.owner, who.user) || manager(who))) throw httpErr(403, 'the owner (' + x.owner + ') or the ISMS manager reports the action done');
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot report a corrective action done');
    const b = body(input || {}).str('evidence', { required: true, min: 5, max: 1000 }).done();
    ncC().put(Object.assign({}, x, { status: 'verify', implemented_by: who.user, implemented_at: iso(), implementation_evidence: b.evidence, history: ncHist(x, who, 'corrective action reported done') }));
    audit(who, 'iso.nc.implemented', x.id, { evidence: 'given' });
    return ncC().get(x.id);
  }
  function ncVerify(id, input, who) {
    const x = must(ncC(), id, 'nonconformity');
    if (x.status !== 'verify') throw httpErr(409, x.id + ' is ' + x.status + ' - nothing to verify yet');
    if (isService(who.user)) throw httpErr(403, 'only a person verifies effectiveness');
    if (same(x.implemented_by, who.user) || same(x.owner, who.user)) throw httpErr(403, 'four eyes: the owner or the person who did the corrective action cannot verify it');
    if (!(manager(who) || same(x.raised_by, who.user))) throw httpErr(403, 'the auditor who raised it, the ISMS manager or an administrator verifies effectiveness');
    const b = body(input || {}).oneOf('decision', ['effective', 'not_effective'], { required: true }).str('note', { required: true, min: 5, max: 1000 }).done();
    const ok = b.decision === 'effective';
    ncC().put(Object.assign({}, x, { status: ok ? 'closed' : 'action', verified_by: ok ? who.user : null, verified_at: ok ? iso() : null, verify_note: b.note,
      history: ncHist(x, who, ok ? 'verified effective - closed' : 'not effective: ' + b.note) }));
    audit(who, 'iso.nc.verify', x.id, { decision: b.decision });
    return ncC().get(x.id);
  }

  // ---- management review (9.3)
  async function reviewPack() {
    const v = await view();
    const R = reviews().filter((r) => r.status === 'held');
    const G = addon('grcRegisters');
    const withStatus = R.map((r, i) => i === 0 && G ? Object.assign({}, r, { actions_status: (r.actions || []).map((a) => {
      try { const x = G.actionList({}).items.find((y) => y.id === a.grc_action); return { title: a.title, status: x ? x.status : 'not found' }; }
      catch (e) { warn('rv-act', 'ISO 27001: a review action status was not read', e); return { title: a.title, status: 'unknown' }; } }) }) : r);
    return rules('iso.pack', { view: v, reviews: withStatus, ncs: ncs(), audits: audits(), history: history(), profile: profile(), now: now() });
  }
  async function recordReview(input, who) {
    needManager(who, 'recording a management review');
    const b = body(input || {}).date('held_on', { required: true, notFuture: true, now: now() }).str('chaired_by', { required: true, max: 120 }).list('attendees', { required: true, max: 40, item: 'str', itemMax: 120 })
      .str('decisions', { required: true, min: 10, max: 4000 }).list('actions', { max: 30, item: 'str', itemMax: 200 }).done();
    const pack = await reviewPack();
    const G = addon('grcRegisters') || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'ISO 27001: the GRC registers are not installed', e); return null; } })();
    const id = nextId('MR', rev());
    const acts = (b.actions || []).map((t, i) => {
      let act = null;
      if (G) { try { act = G.actionCreate({ title: 'ISO 27001 management review ' + id + ': ' + t, source: 'iso', ref: 'iso:' + id + ':' + (i + 1), framework: 'ISO 27001', priority: 'medium', due: day(now() + 90 * DAY), description: 'Decided at the management review held ' + b.held_on + ' (chaired by ' + b.chaired_by + ').' }, { user: who.user, role: who.role, ip: who.ip }).id; }
      catch (e) { warn('rv-grc', 'ISO 27001: a management review action was not created', e); } }
      return { title: t, grc_action: act };
    });
    rev().put({ id, status: 'held', held_on: b.held_on, chaired_by: b.chaired_by, attendees: b.attendees, decisions: b.decisions, actions: acts, pack: pack.inputs, recorded_by: who.user, recorded_at: iso() });
    audit(who, 'iso.review.record', id, { held_on: b.held_on, attendees: b.attendees.length, actions: acts.length });
    return rev().get(id);
  }

  async function gapsToGrc(who) {
    needManager(who, 'sending ISO 27001 gaps to GRC');
    const G = addon('grcRegisters') || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'ISO 27001: the GRC registers are not installed', e); return null; } })();
    if (!G) throw httpErr(409, 'the GRC registers are not installed - run the update');
    const v = await view(), out = { created: [], skipped: [] }, due = { high: 30, medium: 60, low: 90 };
    for (const c of v.clauses.concat(v.annex).filter((x) => x.result === 'gap')) {
      const pri = due[c.severity] ? c.severity : 'low';
      try {
        out.created.push(G.actionCreate({ title: 'ISO 27001 ' + c.id + ': ' + c.title.slice(0, 150), source: 'iso', ref: 'iso:' + c.id, framework: 'ISO 27001', priority: pri,
          due: day(now() + due[pri] * DAY), description: 'ISO/IEC 27001:2022 ' + c.id + ' gap: ' + String(c.why || '').slice(0, 500) + ' Close it with the evidence: ' + c.evidence_hint + '.' }, { user: who.user, role: who.role, ip: who.ip }).id);
      } catch (e) { out.skipped.push(c.id + ': ' + String(e.message).slice(0, 120)); }
    }
    audit(who, 'iso.gaps_to_grc', 'register', { created: out.created.length, skipped: out.skipped.length });
    return out;
  }

  async function exportCsv(what, who) {
    const w = what === 'soa' ? 'soa' : 'register';
    const v = await view();
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const lines = [];
    if (w === 'soa') {
      const s = v.soa_state;
      lines.push(['Statement of Applicability', 'version ' + s.version, s.approved_by ? 'approved by ' + s.approved_by + ' ' + String(s.approved_at).slice(0, 10) : 'NOT APPROVED', s.stale ? 'CHANGED SINCE APPROVAL' : ''].map(cell).join(','));
      lines.push(['Control', 'Title', 'Applicable', 'Justification', 'Implementation', 'Evidence'].map(cell).join(','));
      for (const r of v.soa.rows) lines.push([r.id, r.title, r.applicable ? 'Yes' : 'No', r.justification, r.implementation, r.evidence].map(cell).join(','));
    } else {
      lines.push(['Requirement', 'Kind', 'Group', 'Title', 'Level', 'Result', 'Why', 'Automated', 'From NCA ECC', 'Recorded by', 'Approved by'].map(cell).join(','));
      for (const c of v.clauses.concat(v.annex)) lines.push([c.id, c.kind, c.group_name, c.title, c.level, c.result, c.why, c.automated ? 'yes' : 'no', c.via_ecc || '', c.confirmation ? c.confirmation.by : '', c.confirmation ? c.confirmation.approved_by : ''].map(cell).join(','));
    }
    audit(who, 'iso.export', w, { rows: lines.length - 1 });
    return { filename: 'iso27001-' + w + '-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  // ---- the daily job: measure, plan when nothing is planned, prepare audits due within 30 days
  const SYS = { user: 'system:iso27001', role: 'system', ip: '' };
  async function tick() {
    const v = await view();
    const d = day(now());
    if (!hist().get(d)) {
      hist().put({ id: d, at: iso(), score: v.score, annex_pct: v.readiness.annex_pct, stage: v.readiness.stage, gaps: (v.counts || {}).gap || 0 });
      const H = history(); for (const h of H.slice(0, Math.max(0, H.length - 400))) hist().remove(h.id);
    }
    if (!audits().length && profile().scope_approved) await planProgramme({}, SYS, true);
    for (const a of audits()) {
      if (a.status === 'planned' && Date.parse(a.due) - now() <= 30 * DAY) {
        try { await prepareAudit(a.id, SYS); } catch (e) { warn('prep:' + a.id, 'ISO 27001: audit ' + a.id + ' could not be prepared', e); }
      }
    }
    return { snapshot: d, audits: audits().length };
  }
  let timer = null;
  function start() { if (opts.noTimer || app.noTimers || timer) return; timer = setInterval(guardOf(app, 'iso27001.daily', tick), opts.everyMs || 6 * 3600000); if (timer.unref) timer.unref(); }
  start();

  let last = null;
  const adapter = {
    id: 'iso27001', name: 'AI ISO 27001 Lead Implementer',
    async findings() { const v = await view(); last = v; return v.findings; },
    investigate(it) {
      const c = last && last.clauses.concat(last.annex).find((x) => 'iso:' + x.id === it.key);
      if (!c) return { summary: 'ISO 27001 item - see the ISO 27001 page for the evidence.', checks: [], causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
      return { summary: c.id + ' ' + c.title + (c.ecc.length ? ' - also NCA ECC ' + c.ecc.join(', ') : ''),
        checks: [{ name: 'Register', status: c.result === 'gap' ? 'fail' : 'warn', detail: c.result + ': ' + (c.why || '') }, { name: 'Evidence expected', status: 'ok', detail: c.evidence_hint }],
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
    },
    async verify(it) {
      let v; try { v = await view(); } catch (e) { return { present: null, note: 'could not re-check: ' + String(e.message).slice(0, 120) }; }
      const present = v.findings.some((f) => f.key === it.key);
      return { present, note: present ? 'the register still shows it' : 'the register no longer shows it' };
    },
  };
  const programme = () => ({ audits: audits(), ncs: ncs(), reviews: reviews().map((r) => Object.assign({}, r, { pack: undefined })), profile: { isms_manager: profile().isms_manager || null, auditors: profile().auditors || [] } });
  return { view, facts, putProfile, confirm, decide, proposeSoa, decideSoa, planProgramme, prepareAudit, assignAudit, auditFindings, acceptAudit,
    ncPlan, ncImplemented, ncVerify, reviewPack, recordReview, gapsToGrc, exportCsv, programme, tick, adapter };
}

function registerIso27001Routes(srv, app, I) {
  srv.route('GET', '/iso27001', (ctx) => { ctx.need('viewer'); return I.view(); });
  srv.route('GET', '/iso27001/export', (ctx) => { ctx.need('operator'); const q = body(ctx.query || {}).oneOf('what', ['register', 'soa'], { def: 'register' }).done(); return I.exportCsv(q.what, ctx.who); });
  srv.route('POST', '/iso27001/profile', (ctx) => { ctx.need('admin'); return I.putProfile(ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/confirm', (ctx) => { ctx.need('operator'); return I.confirm(ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/confirm/:id/decide', (ctx) => { ctx.need('operator'); return I.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/soa', (ctx) => { ctx.need('operator'); return I.proposeSoa(ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/soa/decide', (ctx) => { ctx.need('operator'); return I.decideSoa(ctx.body, ctx.who); });
  srv.route('GET', '/iso27001/programme', (ctx) => { ctx.need('viewer'); return I.programme(); });
  srv.route('POST', '/iso27001/programme', (ctx) => { ctx.need('operator'); return I.planProgramme(ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/audits/:id/assign', (ctx) => { ctx.need('operator'); return I.assignAudit(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/audits/:id/prepare', (ctx) => { ctx.need('operator'); return I.prepareAudit(ctx.params.id, ctx.who); });
  srv.route('POST', '/iso27001/audits/:id/findings', (ctx) => { ctx.need('operator'); return I.auditFindings(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/audits/:id/accept', (ctx) => { ctx.need('operator'); return I.acceptAudit(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/ncs/:id', (ctx) => { ctx.need('operator'); return I.ncPlan(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/ncs/:id/implemented', (ctx) => { ctx.need('operator'); return I.ncImplemented(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/ncs/:id/verify', (ctx) => { ctx.need('operator'); return I.ncVerify(ctx.params.id, ctx.body, ctx.who); });
  srv.route('GET', '/iso27001/reviews/pack', (ctx) => { ctx.need('operator'); return I.reviewPack(); });
  srv.route('POST', '/iso27001/reviews', (ctx) => { ctx.need('operator'); return I.recordReview(ctx.body, ctx.who); });
  srv.route('POST', '/iso27001/gaps-to-grc', (ctx) => { ctx.need('operator'); return I.gapsToGrc(ctx.who); });
}

module.exports = { createIso27001, registerIso27001Routes };
