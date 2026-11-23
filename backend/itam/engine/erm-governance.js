// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Risk Governance & Models - the governance side of the enterprise risk management of an insurer (KPMG ERM framework: 1 risk
 * governance, 2 risk oversight - model validation and governance, 3 target operating model - committees and delegated authority,
 * 6 succession planning). NOTHING HERE IS ESTIMATED: every record is entered by a person; the platform checks the rules, computes the
 * due dates and raises the flags.
 *
 *   MODELS       the model inventory (reserving, pricing, capital / solvency, IFRS 17, investment / ALM, catastrophe, fraud / claims
 *                analytics, other): owner (sign-in name), department, materiality tier, status, vendor or in-house. Validation is
 *                due every frequency_months (default by tier: high 12, medium 24, low 36) after the last one; an in-use model never
 *                validated is overdue. A validation is recorded with its validator - never the model's owner (independence) - its
 *                outcome and its findings, tracked to closure with a note. A change to a HIGH-tier model IN USE is a change
 *                request that a different administrator approves; other models change directly (audited).
 *   COMMITTEES   charters (mandate, members, chair, quorum, meeting frequency, charter review date): a charter is approved by an
 *                administrator who did not ask for the approval, and goes back to draft when it changes. Meetings record the
 *                attendees (quorum computed from the members), decisions and actions; actions are tracked to closure.
 *                Delegated authorities (holder, authority, limit and currency, granted by, expiry) - never granted or recorded by
 *                their own holder - are flagged expired / expiring (30 days).
 *   PEOPLE       key functions (CEO, CFO, CRO, actuarial, compliance, internal audit, key risk takers) with their holder and
 *                succession (successors with readiness, emergency cover) - no ready-now successor and no emergency cover is
 *                flagged; fit-and-proper attestations (valid 12 months by default, recorded by an administrator who is not the
 *                person attested); key risk takers with a remuneration-review flag (yes / no and a date - never an amount);
 *                risk-culture survey results per period with the change against the previous period.
 *
 * Routes ({P} = /api/itam) - reads viewer; writes a person (never a service or AI identity), each audited 'erm-governance.*'
 *   GET  /erm-gov                                  viewer   everything the page shows (summary, models, committees, people)
 *   GET  /erm-gov/summary                          viewer   counts and flags per area, each flag saying why
 *   GET  /erm-gov/signals                          viewer   the signals for Notification & Escalation
 *   POST /erm-gov/models                           operator {name, purpose, kind, owner, department, tier, status, source, vendor?, last_validated?, frequency_months?}
 *   POST /erm-gov/models/:id                       operator {...any of the above, change}     high tier in use: a change request
 *   POST /erm-gov/model-changes/:id/decision       admin    {decision: approve | reject, note}   not the requester
 *   POST /erm-gov/models/:id/validations           operator {date, validator, independent, outcome, findings[], report_ref, note?}   validator is not the owner
 *   POST /erm-gov/findings/:id/close               operator {note}
 *   POST /erm-gov/committees                       operator {name, mandate, members[], chair, quorum, frequency, charter_review_due}
 *   POST /erm-gov/committees/:id                   operator {...any of the above}        a changed charter goes back to draft
 *   POST /erm-gov/committees/:id/charter           operator {note}                        asks for the charter approval
 *   POST /erm-gov/committees/:id/charter/decision  admin    {decision, note, ref?}         not the requester
 *   POST /erm-gov/authorities                      operator {holder, authority, description?, limit, currency?, granted_by, granted_on?, expires}
 *   POST /erm-gov/authorities/:id/revoke           operator {note}
 *   POST /erm-gov/meetings                         operator {committee, date, attendees[], minutes_ref?, decisions[{text}], actions[{text, owner, due}]}
 *   POST /erm-gov/actions/:id/close                operator {note}
 *   POST /erm-gov/functions                        operator {function, title, holder, emergency_cover?, successors[{name, readiness}]}
 *   POST /erm-gov/functions/:id                    operator {...any of the above, note?}
 *   POST /erm-gov/attestations                     admin    {function, person, attested_on, valid_until?, note?}   not the person attested
 *   POST /erm-gov/krt                              operator {name, role_title, department, remuneration_reviewed, review_date?}
 *   POST /erm-gov/krt/:id                          operator {...any of the above}
 *   POST /erm-gov/surveys                          operator {period, response_rate, tone_at_the_top, speak_up, accountability, risk_awareness, note?}
 */
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const KINDS = ['reserving', 'pricing', 'capital_solvency', 'ifrs17', 'investment_alm', 'catastrophe', 'fraud_claims', 'other'];
const TIERS = ['high', 'medium', 'low'], TIER_MONTHS = { high: 12, medium: 24, low: 36 };
const MSTATUS = ['in_use', 'development', 'retired'], SOURCES = ['vendor', 'in_house'];
const OUTCOMES = ['fit_for_use', 'fit_with_findings', 'not_fit'], SEVERITIES = ['high', 'medium', 'low'];
const FREQ = { monthly: 1, quarterly: 3, semiannual: 6, annual: 12, ad_hoc: null };
const AUTHORITIES = ['underwriting', 'claims_settlement', 'investment', 'reinsurance', 'expenditure', 'other'];
const FUNCTIONS = ['ceo', 'cfo', 'cro', 'actuarial', 'compliance', 'internal_audit', 'key_risk_taker', 'other'];
const READINESS = ['ready_now', '1_2_years', '3_plus'];
const DIMS = ['tone_at_the_top', 'speak_up', 'accountability', 'risk_awareness'];
const SIGNIN = /^[A-Za-z0-9_.@\\-]{1,80}$/, SIGNIN_MSG = (k) => k + ' must be a sign-in name (letters, digits and . _ - @ \\)';
const PERIOD = /^\d{4}(-(Q[1-4]|H[12]))?$/;
const SOON_DAYS = 30;

function addMonths(d, n) {
  const [y, m, day] = d.split('-').map(Number), t = new Date(Date.UTC(y, m - 1 + n, 1));
  const last = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate();
  t.setUTCDate(Math.min(day, last)); return t.toISOString().slice(0, 10);
}
const addDays = (d, n) => new Date(Date.parse(d + 'T00:00:00Z') + n * 86400000).toISOString().slice(0, 10);

function createErmGovernance(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10), C = (n) => app.store.collection(n);
  const MOD = () => C('eg_models'), VAL = () => C('eg_validations'), FND = () => C('eg_findings'), CHG = () => C('eg_model_changes');
  const COM = () => C('eg_committees'), AUT = () => C('eg_authorities'), MTG = () => C('eg_meetings'), ACT = () => C('eg_actions');
  const FUN = () => C('eg_functions'), ATT = () => C('eg_attestations'), KRT = () => C('eg_krt'), SUR = () => C('eg_surveys');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'erm-governance.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const same = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
  const seq = (col, prefix) => { let n = 0; for (const x of col.all()) { const m = new RegExp('^' + prefix + '-(\\d+)$').exec(x.id); if (m) n = Math.max(n, Number(m[1])); } return prefix + '-' + String(n + 1).padStart(4, '0'); };
  const notFuture = () => ({ notFuture: true, now: now() });
  const noteBody = (input) => body(input || {}).str('note', { required: true, min: 5, max: 1000 }).done();
  const decisionBody = (input) => body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).str('ref', { max: 200 })
    .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required to reject: say why' : null)).done();
  // a list of objects, each validated with its own fields; the error names the entry: findings[1].due must be a date
  function items(list, name, fields) {
    return (list || []).map((x, i) => {
      if (!x || typeof x !== 'object' || Array.isArray(x)) throw httpErr(400, name + '[' + i + '] must be an object');
      try { return fields(body(x)).done(); } catch (e) { if (e.status === 400) throw httpErr(400, name + '[' + i + '].' + e.message); throw e; }
    });
  }
  const changed = (rec, b, keys) => keys.filter((k) => b[k] !== undefined && JSON.stringify(rec[k]) !== JSON.stringify(b[k]));
  const logTo = (rec, who, what, fields, note) => { rec.log = (rec.log || []).concat([{ at: iso(), by: who.user, what, fields: fields || [], note: note || '' }]).slice(-50); };

  // ---------- MODELS: inventory, validation, findings, change requests
  const MODEL_KEYS = ['name', 'purpose', 'kind', 'owner', 'department', 'tier', 'status', 'source', 'vendor', 'last_validated', 'frequency_months'];
  const modelFields = (b, create) => b.str('name', { required: create, max: 160 }).str('purpose', { required: create, max: 1000 }).oneOf('kind', KINDS, { required: create })
    .str('owner', { required: create, max: 80, re: SIGNIN, msg: SIGNIN_MSG('owner') }).str('department', { required: create, max: 120 }).oneOf('tier', TIERS, { required: create })
    .oneOf('status', MSTATUS, { required: create }).oneOf('source', SOURCES, { required: create }).str('vendor', { max: 120 }).date('last_validated', notFuture()).int('frequency_months', { min: 1, max: 120 });
  function modelView(m) {
    const t = today(), freq = m.frequency_months || TIER_MONTHS[m.tier], next = m.last_validated ? addMonths(m.last_validated, freq) : null, live = m.status !== 'retired';
    const overdue = live && (next ? next < t : m.status === 'in_use');
    const open = FND().all((f) => f.model === m.id && f.status === 'open'), late = open.filter((f) => f.due < t), flags = [];
    if (overdue) flags.push(next ? 'validation overdue: due ' + next + ' (' + freq + '-month cycle, last validated ' + m.last_validated + ')' : 'in use and never validated');
    if (live && m.last_outcome === 'not_fit') flags.push('the last validation found it not fit for use');
    if (live && m.last_independent === false) flags.push('the last validation was not independent');
    if (late.length) flags.push(late.length + ' validation finding(s) past their due date');
    const pending = CHG().all((c) => c.model === m.id && c.state === 'pending')[0] || null;
    return Object.assign({}, m, { frequency_months: freq, frequency_default: !m.frequency_months, next_due: next, overdue, not_fit: live && m.last_outcome === 'not_fit', open_findings: open.length, overdue_findings: late.length, pending_change: pending, needs_approval: m.tier === 'high' && m.status === 'in_use', flags });
  }
  const vendorRule = (m) => { if (m.source === 'vendor' && !m.vendor) throw httpErr(400, 'vendor is required for a vendor model: name the supplier'); };
  function modelCreate(input, who) {
    person(who, 'record a model');
    const b = modelFields(body(input || {}), true).done(); vendorRule(b);
    if (MOD().all((m) => m.status !== 'retired' && same(m.name, b.name)).length) throw httpErr(409, 'name: a model named "' + b.name + '" is already in the inventory');
    const m = Object.assign({ id: seq(MOD(), 'MDL') }, b, { frequency_months: b.frequency_months || null, last_validated: b.last_validated || null, created_by: who.user, created_at: iso() });
    logTo(m, who, 'recorded', Object.keys(b)); MOD().put(m);
    audit(who, 'model.create', m.id, { name: m.name, kind: m.kind, tier: m.tier, status: m.status, owner: m.owner });
    return modelView(m);
  }
  function applyModel(m, set, who, what, note) {
    const fields = Object.keys(set), from = Object.fromEntries(fields.map((k) => [k, m[k] === undefined ? null : m[k]]));
    Object.assign(m, set); vendorRule(m); logTo(m, who, what, fields, note); MOD().put(m); return from;
  }
  function modelUpdate(id, input, who) {
    person(who, 'change a model');
    const b = modelFields(body(input || {}), false).str('change', { max: 1000 }).done();
    const m = MOD().get(id); if (!m) throw httpErr(404, 'no model ' + id);
    const ch = changed(m, b, MODEL_KEYS); if (!ch.length) throw httpErr(400, 'nothing to change: give at least one field with a new value');
    const set = Object.fromEntries(ch.map((k) => [k, b[k]]));
    if (set.name && MOD().all((x) => x.id !== id && x.status !== 'retired' && same(x.name, set.name)).length) throw httpErr(409, 'name: a model named "' + set.name + '" is already in the inventory');
    vendorRule(Object.assign({}, m, set));
    if (m.tier === 'high' && m.status === 'in_use') {
      if (!b.change || b.change.length < 5) throw httpErr(400, 'change is required: say what changes in this high-tier model in use and why (a different administrator approves it)');
      if (CHG().all((c) => c.model === id && c.state === 'pending').length) throw httpErr(409, id + ' already has a change waiting for approval');
      const c = { id: seq(CHG(), 'MC'), model: id, model_name: m.name, set, from: Object.fromEntries(ch.map((k) => [k, m[k] === undefined ? null : m[k]])), change: b.change, state: 'pending', by: who.user, at: iso() };
      CHG().put(c); audit(who, 'model.change.request', c.id, { model: id, fields: ch });
      return { pending: true, change: c, model: modelView(m) };
    }
    const from = applyModel(m, set, who, 'edited', b.change);
    audit(who, 'model.update', id, { fields: ch, from, to: set });
    return { pending: false, model: modelView(m) };
  }
  function changeDecision(id, input, who) {
    person(who, 'approve a model change');
    const b = decisionBody(input);
    const c = CHG().get(id); if (!c) throw httpErr(404, 'no model change ' + id); if (c.state !== 'pending') throw httpErr(409, id + ' is already ' + c.state);
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for ' + id + ' and cannot also approve it');
    const m = MOD().get(c.model); if (!m) throw httpErr(409, 'the model ' + c.model + ' is no longer in the inventory - reject this change');
    if (b.decision === 'approve') applyModel(m, c.set, who, 'change ' + id + ' approved (asked by ' + c.by + ')', c.change);
    Object.assign(c, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decision_note: b.note || '' }); CHG().put(c);
    audit(who, 'model.change.' + b.decision, id, { model: c.model, requested_by: c.by, fields: Object.keys(c.set) });
    return { change: c, model: modelView(m) };
  }
  function validationAdd(id, input, who) {
    person(who, 'record a model validation');
    const b = body(input || {}).date('date', Object.assign({ required: true }, notFuture())).str('validator', { required: true, max: 80, re: SIGNIN, msg: SIGNIN_MSG('validator') })
      .bool('independent', { required: true }).oneOf('outcome', OUTCOMES, { required: true }).str('report_ref', { required: true, max: 200 }).list('findings', { max: 100 }).str('note', { max: 1000 })
      .rule((o) => (o.outcome === 'fit_with_findings' && !(o.findings || []).length ? 'findings: fit_with_findings needs at least one finding' : null)).done();
    const F = items(b.findings, 'findings', (x) => x.str('text', { required: true, max: 1000 }).oneOf('severity', SEVERITIES, { required: true }).date('due', { required: true }).str('owner', { required: true, max: 80, re: SIGNIN, msg: SIGNIN_MSG('owner') }));
    const m = MOD().get(id); if (!m) throw httpErr(404, 'no model ' + id);
    if (m.status === 'retired') throw httpErr(409, id + ' is retired - a retired model is not validated');
    if (same(b.validator, m.owner)) throw httpErr(403, 'independence: ' + b.validator + ' owns ' + id + ' and cannot be its validator');
    const v = { id: seq(VAL(), 'MV'), model: id, date: b.date, validator: b.validator, independent: b.independent, outcome: b.outcome, report_ref: b.report_ref, note: b.note || '', by: who.user, at: iso(), findings: [] };
    for (const f of F) { const r = Object.assign({ id: seq(FND(), 'MF'), model: id, validation: v.id }, f, { status: 'open', created_by: who.user, created_at: iso() }); FND().put(r); v.findings.push(r.id); }
    VAL().put(v);
    if (!m.last_validated || b.date >= m.last_validated) Object.assign(m, { last_validated: b.date, last_outcome: b.outcome, last_independent: b.independent, last_validation: v.id });
    logTo(m, who, 'validated', ['last_validated'], b.outcome + ' by ' + b.validator); MOD().put(m);
    audit(who, 'model.validation', v.id, { model: id, outcome: b.outcome, independent: b.independent, validator: b.validator, findings: F.length });
    return { validation: v, model: modelView(m) };
  }
  function findingClose(id, input, who) {
    person(who, 'close a validation finding');
    const b = noteBody(input, 'close a finding: say how it was resolved');
    const f = FND().get(id); if (!f) throw httpErr(404, 'no finding ' + id); if (f.status !== 'open') throw httpErr(409, id + ' is already closed');
    Object.assign(f, { status: 'closed', closed: { by: who.user, at: iso(), note: b.note } }); FND().put(f);
    audit(who, 'model.finding.close', id, { model: f.model, severity: f.severity, owner: f.owner });
    return f;
  }

  // ---------- COMMITTEES: charters (four-eyes), delegated authorities, meetings and actions
  const CHARTER = ['mandate', 'members', 'chair', 'quorum', 'frequency'];
  const committeeFields = (b, create) => b.str('name', { required: create, max: 160 }).str('mandate', { required: create, max: 4000 }).list('members', { required: create, item: 'str', itemMax: 80, max: 50, unique: true })
    .str('chair', { required: create, max: 80 }).int('quorum', { required: create, min: 1, max: 50 }).oneOf('frequency', Object.keys(FREQ), { required: create }).date('charter_review_due', { required: create });
  const fpOf = (c) => crypto.createHash('sha256').update(JSON.stringify(CHARTER.map((k) => (k === 'members' ? [...c.members].map((x) => x.toLowerCase()).sort() : c[k])))).digest('hex').slice(0, 16);
  function charterRules(c) {
    if (c.members.some((x) => !x)) throw httpErr(400, 'members: a member name is empty');
    if (!c.members.some((x) => same(x, c.chair))) throw httpErr(400, 'chair must be one of the members');
    if (c.quorum > c.members.length) throw httpErr(400, 'quorum (' + c.quorum + ') cannot be more than the members (' + c.members.length + ')');
  }
  function committeeView(c) {
    const t = today(), M = MTG().all((x) => x.committee === c.id).sort((a, b) => b.date.localeCompare(a.date)), last = M[0] || null, months = FREQ[c.frequency], flags = [];
    if (c.charter_state === 'draft') flags.push(c.approved ? 'the charter changed since it was approved on ' + c.approved.at.slice(0, 10) + ' - ask for approval again' : 'the charter is not approved');
    if (c.charter_state === 'pending') flags.push('the charter approval is waiting for an administrator');
    if (c.charter_review_due < t) flags.push('the charter review was due on ' + c.charter_review_due);
    if (months && !last) flags.push('no meeting recorded (meets ' + c.frequency + ')');
    else if (months && addMonths(last.date, months) < t) flags.push('no meeting since ' + last.date + ' (meets ' + c.frequency + ')');
    const open = ACT().all((a) => a.committee === c.id && a.status === 'open');
    return Object.assign({}, c, { fingerprint: fpOf(c), meetings: M.length, last_meeting: last ? last.date : null, open_actions: open.length, overdue_actions: open.filter((a) => a.due < t).length, flags });
  }
  function committeeSave(id, input, who) {
    person(who, id ? 'change a committee' : 'record a committee');
    const b = committeeFields(body(input || {}), !id).done();
    const cur = id ? COM().get(id) : null; if (id && !cur) throw httpErr(404, 'no committee ' + id);
    const nm = b.name || (cur && cur.name);
    if (COM().all((x) => x.id !== id && same(x.name, nm)).length) throw httpErr(409, 'name: a committee named "' + nm + '" already exists');
    const ch = cur ? changed(cur, b, ['name'].concat(CHARTER, ['charter_review_due'])) : Object.keys(b);
    if (cur && !ch.length) throw httpErr(400, 'nothing to change: give at least one field with a new value');
    if (cur && cur.charter_state === 'pending' && ch.some((k) => CHARTER.includes(k))) throw httpErr(409, 'the charter of ' + id + ' is waiting for approval - decide it (or reject it) before changing the charter');
    const c = Object.assign({ id: seq(COM(), 'CM'), charter_state: 'draft', approved: null, created_by: who.user, created_at: iso() }, cur || {}, b);
    charterRules(c);
    if (c.approved) c.charter_state = c.charter_state === 'pending' ? 'pending' : fpOf(c) === c.approved.fingerprint ? 'approved' : 'draft';
    logTo(c, who, cur ? 'edited' : 'recorded', ch); COM().put(c);
    audit(who, cur ? 'committee.update' : 'committee.create', c.id, { name: c.name, fields: ch, charter_state: c.charter_state });
    return committeeView(c);
  }
  function charterRequest(id, input, who) {
    person(who, 'ask for a charter approval');
    const b = noteBody(input, 'ask for the approval: what is being approved');
    const c = COM().get(id); if (!c) throw httpErr(404, 'no committee ' + id);
    if (c.charter_state === 'pending') throw httpErr(409, 'the charter of ' + id + ' is already waiting for approval (asked by ' + c.charter_request.by + ')');
    if (c.charter_state === 'approved') throw httpErr(409, 'the charter of ' + id + ' is approved as it stands - change it first');
    c.charter_request = { by: who.user, at: iso(), note: b.note, fingerprint: fpOf(c), state: 'pending' }; c.charter_state = 'pending';
    logTo(c, who, 'charter approval asked', [], b.note); COM().put(c);
    audit(who, 'committee.charter.request', id, { fingerprint: c.charter_request.fingerprint });
    return committeeView(c);
  }
  function charterDecision(id, input, who) {
    person(who, 'approve a committee charter');
    const b = decisionBody(input);
    const c = COM().get(id); if (!c) throw httpErr(404, 'no committee ' + id);
    const q = c.charter_request; if (c.charter_state !== 'pending' || !q) throw httpErr(409, 'no charter approval is waiting for ' + id);
    if (same(q.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for this charter approval and cannot also approve it');
    if (b.decision === 'approve' && fpOf(c) !== q.fingerprint) throw httpErr(409, 'the charter changed after the approval was asked for - reject it and ask again');
    Object.assign(q, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decision_note: b.note || '' });
    c.charter_history = (c.charter_history || []).concat([Object.assign({}, q)]).slice(-20);
    if (b.decision === 'approve') { c.approved = { version: ((c.approved && c.approved.version) || 0) + 1, fingerprint: q.fingerprint, requested_by: q.by, approved_by: who.user, at: iso(), ref: b.ref || '' }; c.charter_state = 'approved'; }
    else c.charter_state = c.approved && fpOf(c) === c.approved.fingerprint ? 'approved' : 'draft';
    logTo(c, who, 'charter ' + q.state, [], b.note); COM().put(c);
    audit(who, 'committee.charter.' + b.decision, id, { requested_by: q.by, fingerprint: q.fingerprint, version: c.approved ? c.approved.version : null });
    return committeeView(c);
  }
  function authView(a) {
    const t = today(), state = a.revoked ? 'revoked' : a.expires < t ? 'expired' : a.expires <= addDays(t, SOON_DAYS) ? 'expiring' : 'active';
    return Object.assign({}, a, { state, flags: state === 'expired' ? ['expired on ' + a.expires] : state === 'expiring' ? ['expires on ' + a.expires + ' (within ' + SOON_DAYS + ' days)'] : [] });
  }
  function authorityAdd(input, who) {
    person(who, 'record a delegated authority');
    const b = body(input || {}).str('holder', { required: true, max: 120 }).oneOf('authority', AUTHORITIES, { required: true }).str('description', { max: 500 }).num('limit', { required: true, min: 0, max: 1e13 })
      .str('currency', { def: 'SAR', max: 10, re: /^[A-Z]{3}$/, msg: 'currency must be a three-letter code (SAR, USD)' }).str('granted_by', { required: true, max: 120 }).date('granted_on', notFuture()).date('expires', { required: true }).done();
    const granted = b.granted_on || today();
    if (b.expires <= granted) throw httpErr(400, 'expires must be after granted_on (' + granted + ')');
    if (same(b.holder, b.granted_by)) throw httpErr(403, 'four eyes: an authority is granted by someone other than its holder');
    if (same(b.holder, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' holds this authority and cannot record it');
    const a = Object.assign({ id: seq(AUT(), 'DA') }, b, { granted_on: granted, by: who.user, at: iso(), revoked: null }); AUT().put(a);
    audit(who, 'authority.create', a.id, { holder: a.holder, authority: a.authority, limit: a.limit, currency: a.currency, expires: a.expires, granted_by: a.granted_by });
    return authView(a);
  }
  function authorityRevoke(id, input, who) {
    person(who, 'revoke a delegated authority');
    const b = noteBody(input, 'revoke: say why');
    const a = AUT().get(id); if (!a) throw httpErr(404, 'no authority ' + id); if (a.revoked) throw httpErr(409, id + ' is already revoked');
    a.revoked = { by: who.user, at: iso(), note: b.note }; AUT().put(a);
    audit(who, 'authority.revoke', id, { holder: a.holder, authority: a.authority });
    return authView(a);
  }
  function actionView(a) { const overdue = a.status === 'open' && a.due < today(); return Object.assign({}, a, { overdue, flags: overdue ? ['overdue since ' + a.due + ' (owner ' + a.owner + ')'] : [] }); }
  function meetingAdd(input, who) {
    person(who, 'record a committee meeting');
    const b = body(input || {}).str('committee', { required: true, max: 20, id: true }).date('date', Object.assign({ required: true }, notFuture())).list('attendees', { required: true, item: 'str', itemMax: 80, max: 60, unique: true })
      .str('minutes_ref', { max: 200 }).list('decisions', { max: 100 }).list('actions', { max: 100 }).done();
    const D = items(b.decisions, 'decisions', (x) => x.str('text', { required: true, max: 2000 }));
    const A = items(b.actions, 'actions', (x) => x.str('text', { required: true, max: 1000 }).str('owner', { required: true, max: 80 }).date('due', { required: true }));
    const c = COM().get(b.committee); if (!c) throw httpErr(400, 'committee: no committee ' + b.committee);
    const att = b.attendees.filter(Boolean); if (!att.length) throw httpErr(400, 'attendees needs at least one name');
    const present = c.members.filter((mm) => att.some((x) => same(x, mm))).length, quorumMet = present >= c.quorum;
    const m = { id: seq(MTG(), 'MT'), committee: c.id, committee_name: c.name, date: b.date, attendees: att, members_present: present, members: c.members.length, quorum: c.quorum, quorum_met: quorumMet,
      minutes_ref: b.minutes_ref || '', decisions: D, actions: [], by: who.user, at: iso() };
    for (const x of A) { const r = Object.assign({ id: seq(ACT(), 'CA'), meeting: m.id, committee: c.id }, x, { status: 'open', created_by: who.user, created_at: iso() }); ACT().put(r); m.actions.push(r.id); }
    MTG().put(m);
    audit(who, 'meeting.record', m.id, { committee: c.id, date: b.date, attendees: att.length, quorum_met: quorumMet, decisions: D.length, actions: A.length });
    return meetingView(m);
  }
  function meetingView(m) { return Object.assign({}, m, { flags: m.quorum_met ? [] : ['quorum not met: ' + m.members_present + ' of ' + m.members + ' members present, quorum ' + m.quorum + (m.decisions.length ? ' - its decisions need ratifying' : '')] }); }
  function actionClose(id, input, who) {
    person(who, 'close a committee action');
    const b = noteBody(input, 'close an action: say what was done');
    const a = ACT().get(id); if (!a) throw httpErr(404, 'no action ' + id); if (a.status !== 'open') throw httpErr(409, id + ' is already closed');
    Object.assign(a, { status: 'closed', closed: { by: who.user, at: iso(), note: b.note } }); ACT().put(a);
    audit(who, 'action.close', id, { committee: a.committee, owner: a.owner, was_overdue: a.due < today() });
    return actionView(a);
  }

  // ---------- PEOPLE: key functions and succession, fit and proper, key risk takers, risk culture
  const functionFields = (b, create) => b.oneOf('function', FUNCTIONS, { required: create }).str('title', { required: create, max: 160 }).str('holder', { required: create, max: 120 })
    .str('emergency_cover', { max: 120 }).list('successors', { max: 10 });
  const latestAtt = (fid, who) => ATT().all((a) => a.function === fid && same(a.person, who)).sort((a, b) => b.attested_on.localeCompare(a.attested_on) || b.id.localeCompare(a.id))[0] || null;
  function attView(a) { const t = today(), expired = a.valid_until < t, expiring = !expired && a.valid_until <= addDays(t, SOON_DAYS); return Object.assign({}, a, { expired, expiring, state: expired ? 'expired' : expiring ? 'expiring' : 'valid' }); }
  function functionView(f) {
    const ready = (f.successors || []).some((s) => s.readiness === 'ready_now'), flags = [];
    if (!ready && !f.emergency_cover) flags.push((f.successors || []).length ? 'no ready-now successor and no emergency cover' : 'no successor and no emergency cover');
    const a = latestAtt(f.id, f.holder);
    if (!a) flags.push('the holder ' + f.holder + ' has no fit-and-proper attestation');
    else if (a.valid_until < today()) flags.push('the fit-and-proper attestation of ' + f.holder + ' expired on ' + a.valid_until);
    return Object.assign({}, f, { ready_successor: ready, attestation: a ? attView(a) : null, flags });
  }
  function functionSave(id, input, who) {
    person(who, id ? 'change a key function' : 'record a key function');
    const b = functionFields(body(input || {}), !id).str('note', { max: 1000 }).done();
    if (b.successors) b.successors = items(b.successors, 'successors', (x) => x.str('name', { required: true, max: 120 }).oneOf('readiness', READINESS, { required: true }));
    const cur = id ? FUN().get(id) : null; if (id && !cur) throw httpErr(404, 'no key function ' + id);
    const f = Object.assign({ id: seq(FUN(), 'KF'), successors: [], emergency_cover: '', created_by: who.user, created_at: iso() }, cur || {});
    const keys = ['function', 'title', 'holder', 'emergency_cover', 'successors'], ch = cur ? changed(cur, b, keys) : keys.filter((k) => b[k] !== undefined);
    if (cur && !ch.length) throw httpErr(400, 'nothing to change: give at least one field with a new value');
    for (const k of ch) f[k] = b[k];
    if (FUN().all((x) => x.id !== f.id && same(x.title, f.title)).length) throw httpErr(409, 'title: a key function "' + f.title + '" already exists');
    if ((f.successors || []).some((s) => same(s.name, f.holder))) throw httpErr(400, 'successors: the holder cannot be their own successor');
    if (f.emergency_cover && same(f.emergency_cover, f.holder)) throw httpErr(400, 'emergency_cover: the holder cannot be their own emergency cover');
    logTo(f, who, cur ? 'edited' : 'recorded', ch, b.note); FUN().put(f);
    audit(who, cur ? 'function.update' : 'function.create', f.id, { title: f.title, fields: ch, successors: f.successors.length, ready_now: f.successors.filter((s) => s.readiness === 'ready_now').length });
    return functionView(f);
  }
  function attestationAdd(input, who) {
    person(who, 'record a fit-and-proper attestation');
    const b = body(input || {}).str('function', { required: true, max: 20, id: true }).str('person', { required: true, max: 120 }).date('attested_on', Object.assign({ required: true }, notFuture()))
      .date('valid_until').str('note', { max: 1000 }).done();
    const f = FUN().get(b.function); if (!f) throw httpErr(400, 'function: no key function ' + b.function);
    if (same(b.person, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' cannot attest their own fitness and propriety');
    const until = b.valid_until || addMonths(b.attested_on, 12);
    if (until <= b.attested_on) throw httpErr(400, 'valid_until must be after attested_on');
    const a = { id: seq(ATT(), 'FP'), function: f.id, function_title: f.title, person: b.person, attested_on: b.attested_on, valid_until: until, valid_default: !b.valid_until, note: b.note || '', by: who.user, at: iso() };
    ATT().put(a); audit(who, 'attestation.record', a.id, { function: f.id, person: a.person, valid_until: until });
    return attView(a);
  }
  const krtFields = (b, create) => b.str('name', { required: create, max: 120 }).str('role_title', { required: create, max: 160 }).str('department', { required: create, max: 120 })
    .bool('remuneration_reviewed', { required: create }).date('review_date', notFuture());
  function krtView(k) {
    const flags = [];
    if (!k.remuneration_reviewed) flags.push('remuneration review not recorded');
    else if (k.review_date && addMonths(k.review_date, 12) < today()) flags.push('remuneration last reviewed on ' + k.review_date + ' (over 12 months ago)');
    return Object.assign({}, k, { flags });
  }
  function krtSave(id, input, who) {
    person(who, id ? 'change a key risk taker' : 'record a key risk taker');
    const b = krtFields(body(input || {}), !id).done();
    const cur = id ? KRT().get(id) : null; if (id && !cur) throw httpErr(404, 'no key risk taker ' + id);
    const k = Object.assign({ id: seq(KRT(), 'KR'), created_by: who.user, created_at: iso() }, cur || {}, b);
    if (k.remuneration_reviewed && !k.review_date) throw httpErr(400, 'review_date is required when remuneration_reviewed is true');
    if (!k.remuneration_reviewed) k.review_date = null;
    if (KRT().all((x) => x.id !== k.id && same(x.name, k.name)).length) throw httpErr(409, 'name: ' + k.name + ' is already a key risk taker');
    const ch = cur ? changed(cur, b, ['name', 'role_title', 'department', 'remuneration_reviewed', 'review_date']) : Object.keys(b);
    if (cur && !ch.length) throw httpErr(400, 'nothing to change: give at least one field with a new value');
    logTo(k, who, cur ? 'edited' : 'recorded', ch); KRT().put(k);
    audit(who, cur ? 'krt.update' : 'krt.create', k.id, { name: k.name, fields: ch, remuneration_reviewed: k.remuneration_reviewed });
    return krtView(k);
  }
  function surveyAdd(input, who) {
    person(who, 'record risk-culture survey results');
    let v = body(input || {}).str('period', { required: true, max: 7, re: PERIOD, msg: 'period must be YYYY, YYYY-Qn or YYYY-H1 / H2' }).num('response_rate', { required: true, min: 0, max: 100 }).str('note', { max: 1000 });
    for (const d of DIMS) v = v.num(d, { required: true, min: 0, max: 100 });
    const b = v.done();
    if (SUR().get('RS-' + b.period)) throw httpErr(409, 'period: results for ' + b.period + ' are already recorded');
    const s = Object.assign({ id: 'RS-' + b.period }, b, { note: b.note || '', by: who.user, at: iso() }); SUR().put(s);
    audit(who, 'survey.record', s.id, { period: s.period, response_rate: s.response_rate });
    return surveys().find((x) => x.id === s.id);
  }
  function surveys() {
    const L = SUR().all().sort((a, b) => a.period.localeCompare(b.period));
    return L.map((s, i) => { const p = L[i - 1] || null; return Object.assign({}, s, { previous: p ? p.period : null, change: p ? Object.fromEntries(DIMS.concat(['response_rate']).map((d) => [d, Math.round((s[d] - p[d]) * 10) / 10])) : null }); }).reverse();
  }

  // ---------- the summary, the full read and the signals
  function data() {
    const t = today();
    return {
      models: MOD().all().sort((a, b) => a.id.localeCompare(b.id)).map(modelView),
      validations: VAL().all().sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id)).slice(0, 300),
      findings: FND().all().sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || a.due.localeCompare(b.due)).slice(0, 500).map((f) => Object.assign({}, f, { overdue: f.status === 'open' && f.due < t })),
      changes: CHG().all().sort((a, b) => b.at.localeCompare(a.at)).slice(0, 200),
      committees: COM().all().sort((a, b) => a.name.localeCompare(b.name)).map(committeeView),
      meetings: MTG().all().sort((a, b) => b.date.localeCompare(a.date)).slice(0, 300).map(meetingView),
      actions: ACT().all().sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || a.due.localeCompare(b.due)).slice(0, 500).map(actionView),
      authorities: AUT().all().sort((a, b) => a.expires.localeCompare(b.expires)).map(authView),
      functions: FUN().all().sort((a, b) => FUNCTIONS.indexOf(a.function) - FUNCTIONS.indexOf(b.function) || a.title.localeCompare(b.title)).map(functionView),
      attestations: ATT().all().sort((a, b) => b.attested_on.localeCompare(a.attested_on)).slice(0, 500).map(attView),
      krt: KRT().all().sort((a, b) => a.name.localeCompare(b.name)).map(krtView),
      surveys: surveys(),
    };
  }
  function view(who) {
    const D = data(), fl = (list, name) => list.flatMap((x) => (x.flags || []).map((why) => ({ ref: x.id, name: name(x), why })));
    const liveM = D.models.filter((m) => m.status !== 'retired'), openA = D.actions.filter((a) => a.status === 'open');
    const latestAtts = new Map(); for (const a of D.attestations.slice().reverse()) latestAtts.set(a.function + '|' + a.person.toLowerCase(), a);
    const LA = [...latestAtts.values()], S = D.surveys[0] || null;
    const areas = {
      models: { counts: { models: liveM.length, in_use: liveM.filter((m) => m.status === 'in_use').length, high_tier: liveM.filter((m) => m.tier === 'high').length, overdue: liveM.filter((m) => m.overdue).length,
        never_validated: liveM.filter((m) => !m.last_validated).length, not_fit: liveM.filter((m) => m.not_fit).length, open_findings: D.findings.filter((f) => f.status === 'open').length,
        overdue_findings: D.findings.filter((f) => f.overdue).length, pending_changes: D.changes.filter((c) => c.state === 'pending').length }, flags: fl(D.models, (m) => m.name) },
      committees: { counts: { committees: D.committees.length, charters_approved: D.committees.filter((c) => c.charter_state === 'approved').length, charters_pending: D.committees.filter((c) => c.charter_state === 'pending').length,
        meetings: D.meetings.length, quorum_missed: D.meetings.filter((m) => !m.quorum_met).length, open_actions: openA.length, overdue_actions: openA.filter((a) => a.overdue).length,
        authorities_active: D.authorities.filter((a) => a.state === 'active' || a.state === 'expiring').length, authorities_expiring: D.authorities.filter((a) => a.state === 'expiring').length, authorities_expired: D.authorities.filter((a) => a.state === 'expired').length },
        flags: fl(D.committees, (c) => c.name).concat(fl(D.meetings, (m) => m.committee_name + ' ' + m.date), fl(D.actions, (a) => a.text), fl(D.authorities, (a) => a.holder + ' - ' + a.authority.replace(/_/g, ' '))) },
      people: { counts: { key_functions: D.functions.length, without_ready_successor: D.functions.filter((f) => !f.ready_successor && !f.emergency_cover).length, attestations_valid: LA.filter((a) => !a.expired).length,
        attestations_expired: LA.filter((a) => a.expired).length, attestations_expiring: LA.filter((a) => a.expiring).length, key_risk_takers: D.krt.length, krt_review_missing: D.krt.filter((k) => k.flags.length).length,
        survey_periods: D.surveys.length, latest_period: S ? S.period : null },
        flags: fl(D.functions, (f) => f.title).concat(fl(D.krt, (k) => k.name)) },
    };
    const mine = (who && who.user) || '';
    return { generated_at: iso(), you: mine, areas, flags_total: areas.models.flags.length + areas.committees.flags.length + areas.people.flags.length,
      waiting_for_you: { model_changes: D.changes.filter((c) => c.state === 'pending' && !same(c.by, mine)).length, charters: D.committees.filter((c) => c.charter_state === 'pending' && c.charter_request && !same(c.charter_request.by, mine)).length },
      note: 'Every record here is entered by a person; the platform computes the due dates and the flags and never estimates a figure.' };
  }
  function all(who) {
    return Object.assign({ summary: view(who) }, data(), { options: { kinds: KINDS, tiers: TIERS, tier_months: TIER_MONTHS, statuses: MSTATUS, sources: SOURCES, outcomes: OUTCOMES, severities: SEVERITIES,
      frequencies: Object.keys(FREQ), authorities: AUTHORITIES, functions: FUNCTIONS, readiness: READINESS, dimensions: DIMS } });
  }
  function signals() {
    const out = [], D = data(), t = today();
    for (const m of D.models) if (m.overdue) out.push({ fp: 'erm-governance:model-validation:' + m.id, source: 'platform', ref: m.id, title: 'Model validation overdue: ' + m.name, text: 'Risk Governance & Models: ' + (m.next_due ? 'due ' + m.next_due + ' (' + m.tier + ' tier, every ' + m.frequency_months + ' months)' : 'in use and never validated') + ' - owner ' + m.owner, severity: m.tier === 'high' ? 3 : 2, condition: true });
    for (const a of D.actions) if (a.overdue) out.push({ fp: 'erm-governance:committee-action:' + a.id, source: 'platform', ref: a.id, title: 'Committee action overdue: ' + String(a.text).slice(0, 120), text: 'Risk Governance & Models: due ' + a.due + ', owner ' + a.owner + ' (' + a.committee + ')', severity: 2, condition: true });
    for (const f of D.functions) if (!f.ready_successor && !f.emergency_cover) out.push({ fp: 'erm-governance:succession:' + f.id, source: 'platform', ref: f.id, title: 'No ready successor: ' + f.title, text: 'Risk Governance & Models: no ready-now successor and no emergency cover for ' + f.title + ' (held by ' + f.holder + ')', severity: ['ceo', 'cro', 'cfo'].includes(f.function) ? 3 : 2, condition: true });
    for (const f of D.functions) { const a = latestAtt(f.id, f.holder); if (a && a.valid_until < t) out.push({ fp: 'erm-governance:fit-proper:' + a.id, source: 'platform', ref: a.id, title: 'Fit-and-proper attestation expired: ' + f.holder + ' (' + f.title + ')', text: 'Risk Governance & Models: valid until ' + a.valid_until, severity: 3, condition: true }); }
    return out;
  }

  return { view, all, signals, modelCreate, modelUpdate, changeDecision, validationAdd, findingClose, committeeSave, charterRequest, charterDecision, authorityAdd, authorityRevoke, meetingAdd, actionClose,
    functionSave, attestationAdd, krtSave, surveyAdd, addMonths };
}

function registerErmGovernance(srv, app, X) {
  if (!X || typeof X.view !== 'function') X = createErmGovernance(app, X || {});   // registered with options only (contract test): build it here
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || ctx.ip });
  const ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/erm-gov', (ctx) => { ctx.need('viewer'); return X.all(W(ctx)); });
  srv.route('GET', '/erm-gov/summary', (ctx) => { ctx.need('viewer'); return X.view(W(ctx)); });
  srv.route('GET', '/erm-gov/signals', (ctx) => { ctx.need('viewer'); return { signals: X.signals() }; });
  srv.route('POST', '/erm-gov/models', (ctx) => { ctx.need('operator'); return X.modelCreate(ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-gov/models/:id', (ctx) => { ctx.need('operator'); return X.modelUpdate(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-gov/model-changes/:id/decision', (ctx) => { ctx.need('admin'); return X.changeDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/models/:id/validations', (ctx) => { ctx.need('operator'); return X.validationAdd(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 64 * 1024 });
  srv.route('POST', '/erm-gov/findings/:id/close', (ctx) => { ctx.need('operator'); return X.findingClose(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/committees', (ctx) => { ctx.need('operator'); return X.committeeSave(null, ctx.body, W(ctx)); }, { maxBody: 32 * 1024 });
  srv.route('POST', '/erm-gov/committees/:id', (ctx) => { ctx.need('operator'); return X.committeeSave(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 32 * 1024 });
  srv.route('POST', '/erm-gov/committees/:id/charter', (ctx) => { ctx.need('operator'); return X.charterRequest(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/committees/:id/charter/decision', (ctx) => { ctx.need('admin'); return X.charterDecision(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/authorities', (ctx) => { ctx.need('operator'); return X.authorityAdd(ctx.body, W(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/erm-gov/authorities/:id/revoke', (ctx) => { ctx.need('operator'); return X.authorityRevoke(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/meetings', (ctx) => { ctx.need('operator'); return X.meetingAdd(ctx.body, W(ctx)); }, { maxBody: 128 * 1024 });
  srv.route('POST', '/erm-gov/actions/:id/close', (ctx) => { ctx.need('operator'); return X.actionClose(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/functions', (ctx) => { ctx.need('operator'); return X.functionSave(null, ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-gov/functions/:id', (ctx) => { ctx.need('operator'); return X.functionSave(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 16 * 1024 });
  srv.route('POST', '/erm-gov/attestations', (ctx) => { ctx.need('admin'); return X.attestationAdd(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/krt', (ctx) => { ctx.need('operator'); return X.krtSave(null, ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/krt/:id', (ctx) => { ctx.need('operator'); return X.krtSave(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/erm-gov/surveys', (ctx) => { ctx.need('operator'); return X.surveyAdd(ctx.body, W(ctx)); }, { maxBody: 4096 });
}

module.exports = { createErmGovernance, registerErmGovernance, KINDS, TIER_MONTHS, FUNCTIONS, AUTHORITIES };
