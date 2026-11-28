// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * GRC registers ({P} = /api/itam): the working side of GRC - what is being fixed, what could go wrong, what is allowed
 * as an exception, and the evidence an auditor asks for. Everything is entered by people (or created from a real gap
 * with one click on the SAMA, GRC-policy and DR-drill pages); nothing is seeded or guessed.
 *
 *   Remediation actions  grc_actions     ACT-0001  a gap → an owner, a due date, evidence, and FOUR-EYES closure: whoever
 *                                                    marked it done cannot verify it closed
 *   Risks                grc_risks       RSK-0001  likelihood × impact 1-5 (inherent and residual), treatment, owner,
 *                                                    linked controls / assets / actions; accepting a risk needs an
 *                                                    administrator who is not the risk owner
 *   Policy exceptions    grc_exceptions  EXC-0001  against an approved policy, time-bound (max 12 months), compensating
 *                                                    controls; approved by an administrator who is not the requester;
 *                                                    "expired" is computed from the date, never left to someone to set
 *   Evidence             grc_evidence    EVD-0001  per framework control: a file (SHA-256 computed here) or a reference,
 *                                                    collected date and validity → current / due soon / stale; SAMA IT
 *                                                    governance controls with no current evidence are listed as missing
 *   Files                grc_files       the uploaded bytes (max 8 MB each), kept apart from the records
 * Reads: any signed-in role. Writes: operator. Approvals: administrator, a person (never a service / AI identity), never
 * your own request. Every change is in the audit trail and in the record's own history.
 *
 *   GET  /grc/workspace                         KPIs of all four registers + what is overdue / waiting for whom
 *   GET  /grc/actions | POST /grc/actions | POST /grc/actions/:id | POST /grc/actions/:id/status {status, note}
 *   POST /grc/actions/:id/evidence {filename, content_b64 | url, note}
 *   GET  /grc/risks   | POST /grc/risks   | POST /grc/risks/:id   | POST /grc/risks/:id/accept {note} | /close {note}
 *   GET  /grc/exceptions | POST /grc/exceptions | POST /grc/exceptions/:id/decide {decision, note} | /revoke {note}
 *   GET  /grc/evidence | POST /grc/evidence | POST /grc/evidence/:id/retire {note}
 *   GET  /grc/files/:id                         operator: the stored bytes (base64) of an evidence file
 */
const crypto = require('node:crypto');

const DAY = 86400000;
const SOURCES = ['sama', 'control', 'audit', 'drill', 'risk', 'exception', 'platform', 'pdpl', 'ndmo', 'nca', 'iso', 'manual'];
const PRIORITIES = ['high', 'medium', 'low'];
const A_OPEN = ['open', 'in_progress', 'done'];
const TREATMENTS = ['mitigate', 'accept', 'transfer', 'avoid'];
const FRAMEWORKS = ['SAMA ITGF', 'SAMA CSF', 'NCA ECC', 'ISO 27001', 'PDPL', 'NDMO', 'Other'];
const KINDS = ['document', 'screenshot', 'export', 'record', 'link'];
const MAX_FILE = 8 * 1024 * 1024;
// what an auditor accepts as evidence: documents, spreadsheets, images, exported text and mail - never a web page or a program
const EVIDENCE_TYPES = ['pdf', 'docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'txt', 'log', 'eml', 'msg', 'json', 'xml'];
const { fileCheck } = require('./check');
const { isHuman } = require('./approve-scopes');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status, statusCode: status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n || 200);
const same = (a, b) => !!String(a || '').trim() && String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
const human = isHuman;
function day(v, name, required) {
  const t = s(v, 10);
  if (!t) { if (required) throw bad(name + ' is required (YYYY-MM-DD)'); return null; }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t) || Number.isNaN(Date.parse(t + 'T00:00:00Z')) || new Date(t + 'T00:00:00Z').toISOString().slice(0, 10) !== t) throw bad(name + ' must be a date (YYYY-MM-DD)');
  return t;
}
function score(v, name) { const n = Number(v); if (!Number.isInteger(n) || n < 1 || n > 5) throw bad(name + ' must be 1-5'); return n; }
const band = (x) => (x == null ? null : x >= 15 ? 'high' : x >= 8 ? 'medium' : 'low');
const list = (v, n, max) => (Array.isArray(v) ? v : String(v == null ? '' : v).split(/[,\n]/)).map((x) => s(x, n)).filter(Boolean).filter((x, i, a) => a.indexOf(x) === i).slice(0, max || 50);

function createGrcRegisters(app, opts = {}) {
  const st = app.store, now = opts.now || (() => (app.now ? app.now() : Date.now()));
  const C = { actions: st.collection('grc_actions'), risks: st.collection('grc_risks'), exceptions: st.collection('grc_exceptions'), evidence: st.collection('grc_evidence'), files: st.collection('grc_files') };
  const counters = st.collection('counters'), assets = st.collection('assets');
  const policies = opts.policies || (() => { try { return require('./grc-policy-file')(); } catch (e) { return []; } })();
  const controls = opts.controls || (() => { try { return require('./grc').CONTROL_MAP; } catch (e) { return {}; } })();
  const today = () => new Date(now()).toISOString().slice(0, 10);
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };
  function nextId(prefix, name) { const n = ((counters.get(name) || {}).n || 0) + 1; counters.put({ id: name, n }); return prefix + '-' + String(n).padStart(4, '0'); }
  const hist = (rec, who, what) => { rec.history = (rec.history || []).concat([{ at: iso(), by: (who && who.user) || '', what: s(what, 600) }]).slice(-200); };
  function must(col, id, what) { const r = C[col].get(s(id, 40)); if (!r) throw bad(what + ' not found', 404); return r; }
  function approver(who, other, what) {
    if (!who || String(who.role || '').toLowerCase() !== 'admin') throw bad(what + ' needs an administrator', 403);
    if (!human(who.user)) throw bad('only a person approves: ' + (who.user || 'this identity') + ' is a service / AI identity', 403);
    if (same(who.user, other)) throw bad('four eyes: ' + what + ' must be done by someone other than ' + other, 403);
  }
  function storeFile(b, who) {
    if (b.url) { const u = s(b.url, 1000); if (!/^https?:\/\//i.test(u)) throw bad('a reference must be an http(s) address'); return { kind: 'link', url: u, filename: s(b.filename, 200) || u, at: iso(), by: who.user }; }
    const name = s(b.filename, 200); if (!name) throw bad('a file name is required');
    if (typeof b.content_b64 !== 'string' || !b.content_b64) throw bad('the file content is missing');
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.content_b64)) throw bad('the file content is not base64');
    const buf = Buffer.from(b.content_b64, 'base64');
    if (!buf.length) throw bad('the file is empty'); if (buf.length > MAX_FILE) throw bad('the file is larger than 8 MB: link it instead');
    // the type must be allowed and the bytes must really be that type (engine/check.js fileCheck): a renamed .exe, an
    // .html or an .svg (both can carry script) never becomes evidence
    const fc = fileCheck(name, buf, { max: MAX_FILE, allow: EVIDENCE_TYPES });
    const sha = crypto.createHash('sha256').update(buf).digest('hex');
    if (b.sha256 && s(b.sha256, 64).toLowerCase() !== sha) throw bad('the file arrived damaged (SHA-256 differs from what the browser computed) - upload it again');
    const fid = 'F-' + sha.slice(0, 16) + '-' + crypto.randomBytes(3).toString('hex');
    C.files.put({ id: fid, filename: fc.name, type: fc.ext, mime: fc.mime, size: buf.length, sha256: sha, content_b64: buf.toString('base64'), at: iso(), by: who.user });
    return { kind: 'file', file_id: fid, filename: fc.name, type: fc.ext, size: buf.length, sha256: sha, at: iso(), by: who.user };
  }

  /* ---------- remediation actions ---------- */
  function actionView(a) {
    const t = today(), overdue = !!(a.due && A_OPEN.includes(a.status) && a.status !== 'done' && a.due < t);
    return Object.assign({}, a, { overdue, due_soon: !!(a.due && A_OPEN.includes(a.status) && !overdue && a.due <= new Date(now() + 14 * DAY).toISOString().slice(0, 10)), evidence_count: (a.evidence || []).length });
  }
  function actionFields(b, cur) {
    const o = {};
    if (!cur || 'title' in b) { o.title = s(b.title, 200); if (o.title.length < 3) throw bad('a title is required'); }
    if (!cur || 'source' in b) { o.source = SOURCES.includes(b.source) ? b.source : 'manual'; }
    if ('ref' in b) o.ref = s(b.ref, 120);
    if ('description' in b) o.description = s(b.description, 4000);
    if ('owner' in b) o.owner = s(b.owner, 120);
    if ('due' in b) o.due = day(b.due, 'due date');
    if (!cur || 'priority' in b) o.priority = PRIORITIES.includes(b.priority) ? b.priority : (cur ? cur.priority : 'medium');
    if ('framework' in b) o.framework = FRAMEWORKS.includes(b.framework) ? b.framework : '';
    return o;
  }
  function actionCreate(b, who) {
    const o = actionFields(b || {}, null);
    if (o.source !== 'manual' && !o.ref) throw bad('an action from ' + o.source + ' needs the reference it came from');
    const dup = o.ref && C.actions.all((x) => x.source === o.source && x.ref === o.ref && A_OPEN.includes(x.status))[0];
    if (dup && !b.allow_duplicate) throw bad('an open action already tracks ' + o.source + ' ' + o.ref + ': ' + dup.id, 409);
    const rec = Object.assign({ id: nextId('ACT', 'grc_actions'), status: 'open', evidence: [], created_by: who.user, created_at: iso(), ref: '', description: '', owner: '', due: null, framework: '' }, o);
    hist(rec, who, 'created' + (o.ref ? ' from ' + o.source + ' ' + o.ref : ''));
    C.actions.put(rec); audit(who, 'grc.action.create', rec.id, { source: rec.source, ref: rec.ref, owner: rec.owner, due: rec.due });
    return actionView(rec);
  }
  function actionUpdate(id, b, who) {
    const a = must('actions', id, 'action'); if (!A_OPEN.includes(a.status)) throw bad('this action is ' + a.status, 409);
    const o = actionFields(b || {}, a), changed = Object.keys(o).filter((k) => JSON.stringify(a[k]) !== JSON.stringify(o[k]));
    if (!changed.length) return actionView(a);
    const rec = Object.assign({}, a, o); hist(rec, who, 'changed ' + changed.join(', ') + (o.due && o.due !== a.due ? ' (due ' + (a.due || '—') + ' → ' + o.due + ')' : ''));
    C.actions.put(rec); audit(who, 'grc.action.update', a.id, { changed });
    return actionView(rec);
  }
  function actionStatus(id, b, who) {
    const a = must('actions', id, 'action'), to = s(b.status, 20), note = s(b.note, 1000), rec = Object.assign({}, a);
    if (to === 'in_progress') { if (a.status !== 'open') throw bad('only an open action can be started', 409); rec.status = 'in_progress'; }
    else if (to === 'done') {
      if (!['open', 'in_progress'].includes(a.status)) throw bad('this action is ' + a.status, 409);
      if (!note && !(a.evidence || []).length) throw bad('say what was done, or attach evidence, before marking it done');
      rec.status = 'done'; rec.done_by = who.user; rec.done_at = iso(); rec.done_note = note;
    } else if (to === 'closed') {
      if (a.status !== 'done') throw bad('an action is verified closed only after it was marked done', 409);
      if (!human(who.user)) throw bad('only a person verifies an action closed', 403);
      if (same(who.user, a.done_by)) throw bad('four eyes: ' + a.done_by + ' marked it done - someone else verifies it', 403);
      rec.status = 'closed'; rec.closed_by = who.user; rec.closed_at = iso(); rec.closure_note = note;
    } else if (to === 'open') {
      if (a.status !== 'done') throw bad('only a done action can be sent back', 409);
      if (!note) throw bad('say why it is not done'); rec.status = 'open'; rec.done_by = null; rec.done_at = null;
    } else if (to === 'cancelled') {
      if (!A_OPEN.includes(a.status)) throw bad('this action is ' + a.status, 409);
      if (!note) throw bad('a reason is required to cancel'); rec.status = 'cancelled'; rec.cancelled_by = who.user; rec.cancelled_at = iso();
    } else throw bad('status must be in_progress, done, closed, open or cancelled');
    hist(rec, who, a.status + ' → ' + rec.status + (note ? ': ' + note : ''));
    C.actions.put(rec); audit(who, 'grc.action.' + rec.status, a.id, { from: a.status, note });
    return actionView(rec);
  }
  function actionEvidence(id, b, who) {
    const a = must('actions', id, 'action'); if (a.status === 'closed' || a.status === 'cancelled') throw bad('this action is ' + a.status, 409);
    const f = storeFile(b || {}, who); f.note = s(b.note, 500);
    const rec = Object.assign({}, a, { evidence: (a.evidence || []).concat([f]).slice(-50) }); hist(rec, who, 'evidence added: ' + f.filename);
    C.actions.put(rec); audit(who, 'grc.action.evidence', a.id, { filename: f.filename, sha256: f.sha256 || null, url: f.url || null });
    return actionView(rec);
  }
  function actionList(q = {}) {
    let rows = C.actions.all().map(actionView);
    if (q.status === 'open') rows = rows.filter((a) => A_OPEN.includes(a.status)); else if (q.status) rows = rows.filter((a) => a.status === q.status);
    if (q.source) rows = rows.filter((a) => a.source === q.source);
    if (q.ref) rows = rows.filter((a) => a.ref === q.ref);
    if (q.overdue === '1') rows = rows.filter((a) => a.overdue);
    return { items: rows.sort((x, y) => (x.overdue === y.overdue ? String(x.due || '9999').localeCompare(String(y.due || '9999')) : x.overdue ? -1 : 1)), sources: SOURCES, priorities: PRIORITIES };
  }

  /* ---------- risks ---------- */
  function riskView(r) {
    const inh = r.likelihood * r.impact, res = r.residual_likelihood && r.residual_impact ? r.residual_likelihood * r.residual_impact : null;
    const acts = C.actions.all((a) => a.source === 'risk' && a.ref === r.id);
    return Object.assign({}, r, { inherent: inh, inherent_band: band(inh), residual: res, residual_band: band(res), review_overdue: !!(r.status === 'open' && r.review_due && r.review_due < today()),
      actions: acts.map((a) => ({ id: a.id, title: a.title, status: a.status, due: a.due })), open_actions: acts.filter((a) => A_OPEN.includes(a.status)).length });
  }
  function riskFields(b, cur) {
    const o = {};
    if (!cur || 'title' in b) { o.title = s(b.title, 200); if (o.title.length < 3) throw bad('a title is required'); }
    for (const [k, n] of [['description', 4000], ['category', 80], ['owner', 120], ['cause', 1000], ['consequence', 1000]]) if (k in b) o[k] = s(b[k], n);
    if (!cur || 'likelihood' in b) o.likelihood = score(b.likelihood, 'likelihood');
    if (!cur || 'impact' in b) o.impact = score(b.impact, 'impact');
    for (const k of ['residual_likelihood', 'residual_impact']) if (k in b) o[k] = b[k] === '' || b[k] == null ? null : score(b[k], k.replace('_', ' '));
    if (!cur || 'treatment' in b) { o.treatment = TREATMENTS.includes(b.treatment) ? b.treatment : 'mitigate'; }
    if ('controls' in b) o.controls = list(b.controls, 40, 40);
    if ('assets' in b) { o.assets = list(b.assets, 60, 100); const miss = o.assets.filter((x) => !assets.get(x)); if (miss.length) throw bad('asset not found: ' + miss.slice(0, 5).join(', ')); }
    if ('review_due' in b) o.review_due = day(b.review_due, 'review date');
    if ('source_ref' in b) o.source_ref = s(b.source_ref, 160);   // the live finding it was rated from (GET /grc/live candidates)
    return o;
  }
  function riskCreate(b, who) {
    const o = riskFields(b || {}, null);
    const rec = Object.assign({ id: nextId('RSK', 'grc_risks'), status: 'open', description: '', category: '', owner: '', controls: [], assets: [], residual_likelihood: null, residual_impact: null, review_due: null, acceptance: null, created_by: who.user, created_at: iso() }, o);
    hist(rec, who, 'created · inherent ' + rec.likelihood + '×' + rec.impact + ' · ' + rec.treatment);
    C.risks.put(rec); audit(who, 'grc.risk.create', rec.id, { score: rec.likelihood * rec.impact, treatment: rec.treatment, owner: rec.owner });
    return riskView(rec);
  }
  function riskUpdate(id, b, who) {
    const r = must('risks', id, 'risk'); if (r.status !== 'open') throw bad('this risk is closed', 409);
    const o = riskFields(b || {}, r), changed = Object.keys(o).filter((k) => JSON.stringify(r[k]) !== JSON.stringify(o[k]));
    if (!changed.length) return riskView(r);
    const rec = Object.assign({}, r, o);
    // an accepted risk whose rating or treatment changes is no longer the risk that was accepted
    if (r.acceptance && changed.some((k) => ['likelihood', 'impact', 'residual_likelihood', 'residual_impact', 'treatment'].includes(k))) { rec.acceptance = null; hist(rec, who, 'acceptance withdrawn: the rating or treatment changed'); }
    hist(rec, who, 'changed ' + changed.join(', ')); C.risks.put(rec); audit(who, 'grc.risk.update', r.id, { changed });
    return riskView(rec);
  }
  function riskAccept(id, b, who) {
    const r = must('risks', id, 'risk'); if (r.status !== 'open') throw bad('this risk is closed', 409);
    if (r.treatment !== 'accept') throw bad('set the treatment to "accept" first');
    approver(who, r.owner, 'accepting a risk');
    const note = s(b.note, 1000); if (!note) throw bad('record why the risk is accepted');
    const rec = Object.assign({}, r, { acceptance: { by: who.user, at: iso(), note, until: day(b.until, 'accepted until') || r.review_due || null } });
    hist(rec, who, 'risk accepted: ' + note); C.risks.put(rec); audit(who, 'grc.risk.accept', r.id, { note });
    return riskView(rec);
  }
  function riskClose(id, b, who) {
    const r = must('risks', id, 'risk'); if (r.status !== 'open') throw bad('this risk is already closed', 409);
    const note = s(b.note, 1000); if (!note) throw bad('say why the risk is closed');
    const rec = Object.assign({}, r, { status: 'closed', closed_by: who.user, closed_at: iso(), closure_note: note });
    hist(rec, who, 'closed: ' + note); C.risks.put(rec); audit(who, 'grc.risk.close', r.id, { note });
    return riskView(rec);
  }
  function riskList() {
    const rows = C.risks.all().map(riskView).sort((x, y) => (y.status === 'open') - (x.status === 'open') || (y.residual || y.inherent) - (x.residual || x.inherent));
    const heat = (key1, key2) => { const m = {}; for (const r of rows) if (r.status === 'open' && r[key1] && r[key2]) { const k = r[key1] + 'x' + r[key2]; m[k] = (m[k] || 0) + 1; } return m; };
    return { items: rows, treatments: TREATMENTS, heat: { inherent: heat('likelihood', 'impact'), residual: heat('residual_likelihood', 'residual_impact') } };
  }

  /* ---------- policy exceptions ---------- */
  const policyOf = (id) => policies.find((p) => p.doc_id === id) || null;
  function excView(x) {
    const t = today(), expired = x.status === 'approved' && x.expires && x.expires < t;
    const p = policyOf(x.policy_id);
    return Object.assign({}, x, { state: expired ? 'expired' : x.status, expiring_soon: !!(x.status === 'approved' && !expired && x.expires && x.expires <= new Date(now() + 30 * DAY).toISOString().slice(0, 10)), policy_title: p ? p.title : '' });
  }
  function excCreate(b, who) {
    const pid = s(b.policy_id, 40); if (!policyOf(pid)) throw bad('choose an approved policy (policy_id) from the register');
    const title = s(b.title, 200); if (title.length < 3) throw bad('a title is required');
    const reason = s(b.reason, 2000); if (!reason) throw bad('the business reason is required');
    const starts = day(b.starts, 'start date') || today(), expires = day(b.expires, 'expiry date', true);
    if (expires <= starts) throw bad('the exception must end after it starts');
    if (Date.parse(expires) - Date.parse(starts) > 366 * DAY) throw bad('an exception lasts at most 12 months - renew it with a new request');
    const rec = { id: nextId('EXC', 'grc_exceptions'), policy_id: pid, title, reason, compensating: s(b.compensating, 2000), scope: s(b.scope, 500), starts, expires, status: 'requested',
      requested_by: who.user, requested_at: iso(), decided_by: null, decided_at: null, decision_note: '' };
    hist(rec, who, 'requested · ' + starts + ' → ' + expires);
    C.exceptions.put(rec); audit(who, 'grc.exception.request', rec.id, { policy: pid, expires });
    return excView(rec);
  }
  function excDecide(id, b, who) {
    const x = must('exceptions', id, 'exception'); if (x.status !== 'requested') throw bad('this exception is already ' + x.status, 409);
    const d = s(b.decision, 10); if (!['approve', 'reject'].includes(d)) throw bad('decision must be approve or reject');
    approver(who, x.requested_by, d === 'approve' ? 'approving an exception' : 'rejecting an exception');
    const note = s(b.note, 1000); if (d === 'reject' && !note) throw bad('give the reason for rejecting');
    if (d === 'approve' && !x.compensating && !note) throw bad('approving an exception with no compensating control needs a note saying why that is acceptable');
    const rec = Object.assign({}, x, { status: d === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decision_note: note });
    hist(rec, who, rec.status + (note ? ': ' + note : '')); C.exceptions.put(rec); audit(who, 'grc.exception.' + rec.status, x.id, { note });
    return excView(rec);
  }
  function excRevoke(id, b, who) {
    const x = must('exceptions', id, 'exception'); if (x.status !== 'approved') throw bad('only an approved exception can be revoked', 409);
    if (String(who.role || '').toLowerCase() !== 'admin') throw bad('revoking an exception needs an administrator', 403);
    const note = s(b.note, 1000); if (!note) throw bad('give the reason for revoking');
    const rec = Object.assign({}, x, { status: 'revoked', revoked_by: who.user, revoked_at: iso(), revoke_note: note });
    hist(rec, who, 'revoked: ' + note); C.exceptions.put(rec); audit(who, 'grc.exception.revoke', x.id, { note });
    return excView(rec);
  }
  function excList() {
    return { items: C.exceptions.all().map(excView).sort((a, b) => String(a.expires).localeCompare(String(b.expires))), policies: policies.map((p) => ({ doc_id: p.doc_id, title: p.title })) };
  }

  /* ---------- evidence ---------- */
  function evView(e) {
    const t = today(), soon = new Date(now() + 30 * DAY).toISOString().slice(0, 10);
    return Object.assign({}, e, { state: e.status === 'retired' ? 'retired' : !e.next_due ? 'current' : e.next_due < t ? 'stale' : e.next_due <= soon ? 'due_soon' : 'current' });
  }
  function evCreate(b, who) {
    const fw = FRAMEWORKS.includes(b.framework) ? b.framework : null; if (!fw) throw bad('framework must be one of ' + FRAMEWORKS.join(', '));
    const control = s(b.control, 40); if (!control) throw bad('the control it evidences is required');
    if (fw === 'SAMA ITGF' && !controls[control]) throw bad('unknown SAMA IT governance control ' + control);
    const title = s(b.title, 200); if (title.length < 3) throw bad('a title is required');
    const kind = KINDS.includes(b.kind) ? b.kind : (b.url ? 'link' : 'document');
    const collected = day(b.collected, 'collected date') || today();
    const valid = b.valid_days === '' || b.valid_days == null ? 365 : Number(b.valid_days);
    if (!Number.isInteger(valid) || valid < 0 || valid > 1825) throw bad('validity must be 0-1825 days (0 = does not expire)');
    const f = storeFile(b, who);
    const rec = { id: nextId('EVD', 'grc_evidence'), framework: fw, control, title, kind, description: s(b.description, 2000), owner: s(b.owner, 120), collected, valid_days: valid,
      next_due: valid ? new Date(Date.parse(collected + 'T00:00:00Z') + valid * DAY).toISOString().slice(0, 10) : null, file: f, status: 'active', created_by: who.user, created_at: iso() };
    hist(rec, who, 'added: ' + f.filename); C.evidence.put(rec); audit(who, 'grc.evidence.add', rec.id, { framework: fw, control, filename: f.filename, sha256: f.sha256 || null });
    return evView(rec);
  }
  function evRetire(id, b, who) {
    const e = must('evidence', id, 'evidence'); if (e.status === 'retired') throw bad('already retired', 409);
    const note = s(b.note, 1000); if (!note) throw bad('say why it is retired (superseded, wrong control …)');
    const rec = Object.assign({}, e, { status: 'retired', retired_by: who.user, retired_at: iso(), retire_note: note });
    hist(rec, who, 'retired: ' + note); C.evidence.put(rec); audit(who, 'grc.evidence.retire', e.id, { note });
    return evView(rec);
  }
  function evList() {
    const rows = C.evidence.all().map(evView);
    const coverage = Object.entries(controls).map(([k, c]) => {
      const mine = rows.filter((e) => e.framework === 'SAMA ITGF' && e.control === k && e.state !== 'retired');
      const cur = mine.filter((e) => e.state !== 'stale');
      return { control: k, module: c.module || '', items: mine.length, current: cur.length, latest: mine.map((e) => e.collected).sort().pop() || null, state: cur.length ? (cur.every((e) => e.state === 'due_soon') ? 'due_soon' : 'current') : mine.length ? 'stale' : 'missing' };
    });
    return { items: rows.sort((a, b) => String(b.collected).localeCompare(String(a.collected))), frameworks: FRAMEWORKS, kinds: KINDS, coverage };
  }
  // a download is a custody event: who took a copy of which evidence, and when (Evidence & Chain of Custody reads it)
  function file(id, who) { const f = C.files.get(s(id, 60)); if (!f) throw bad('file not found', 404); if (who) audit(who, 'grc.evidence.file', f.id, { filename: f.filename, sha256: f.sha256 }); return { filename: f.filename, size: f.size, sha256: f.sha256, content_b64: f.content_b64 }; }

  /* ---------- live: the platform's own gaps feed the registers ----------
     Governance gaps the platform measures become remediation actions by themselves - SAMA CSF controls with a gap (SIEM
     coverage), failing GRC controls, DR systems whose recovery test is overdue or failed, assets without an owner - each
     with the record it came from, never twice (an open action with the same source + reference is kept), unassigned,
     due by the priority policy (grc.live.due_days). When the source stops reporting a gap the action says so in its
     history and shows "source cleared"; it is never closed by the platform - a person verifies and another closes it
     (four eyes). A source that could not be read changes nothing. Operational findings (AI engineer work items, SOC
     cases) keep their own lifecycle and are only offered as candidates to rate as risks: likelihood x impact is a
     judgement a person makes, never set here. */
  const LIVE_WHO = { user: 'system:grc-live', role: 'service', ip: '' };
  const liveMeta = st.collection('grc_live');
  const liveCfg = () => Object.assign({ enabled: true, interval_min: 30, due_days: { high: 30, medium: 60, low: 90 } }, (app.config && app.config.grc && app.config.grc.live) || {});
  function dueFor(pri) { const d = Number((liveCfg().due_days || {})[pri]) || (pri === 'high' ? 30 : pri === 'medium' ? 60 : 90); return new Date(now() + d * DAY).toISOString().slice(0, 10); }
  function gapsFrom(S) {
    const out = {}, ok = {}, L = (id) => (S[id] && S[id].state === 'live' ? S[id].data : null);
    const sm = L('sama'); ok.sama = !!(sm && Array.isArray(sm.controls));
    if (ok.sama) for (const c of sm.controls.filter((x) => x.status === 'gap')) out['sama|' + c.id] = { source: 'sama', ref: s(c.id, 120), framework: 'SAMA CSF', priority: 'high', owner: s(c.owner, 120),
      title: 'SAMA CSF ' + s(c.id, 20) + ' ' + s(c.title, 120) + ': close the gap', description: 'The SIEM\'s SAMA CSF coverage reports this control as a gap' + (c.detail ? ': ' + s(c.detail, 600) : '.') + ' Open SAMA Compliance for the evidence it expects.' };
    const g = L('grc'); ok.control = !!(g && g.control_status);
    if (ok.control) for (const [k, v] of Object.entries(g.control_status)) if (v && (v.state || v.status) === 'fail') out['control|' + k] = { source: 'control', ref: s(k, 120), priority: 'high', owner: '',
      title: 'Control "' + s(k, 80) + '" failing: fix and re-test', description: 'GRC control automation reports this control failing' + (v.detail ? ': ' + s(v.detail, 600) : '.') };
    const dr = L('drills'); ok.drill = !!(dr && Array.isArray(dr.systems));
    if (ok.drill) for (const x of dr.systems.filter((y) => y.overdue)) out['drill|' + x.system] = { source: 'drill', ref: s(x.system, 120), priority: 'high', owner: s(x.owner, 120),
      title: s(x.system, 80) + ': recovery test ' + (x.last_result === 'fail' ? 'failed - repeat it' : x.last ? 'overdue' : 'never performed'), description: 'DR & BCM drills: ' + (x.last ? 'last test ' + s(x.last.executed, 10) + ' (' + s(x.last_result, 20) + ')' : 'no recovery test recorded') + '.' };
    const ow = L('ownership'); ok.platform = !!ow;
    if (ow && ow.assets && (ow.missing_business || ow.missing_it)) out['platform|ownership:coverage'] = { source: 'platform', ref: 'ownership:coverage', priority: ow.business_pct != null && ow.business_pct < 50 ? 'high' : 'medium', owner: '',
      title: 'Assign owners: ' + [ow.missing_business ? ow.missing_business + ' assets without a business owner' : '', ow.missing_it ? ow.missing_it + ' without an IT owner' : ''].filter(Boolean).join(', '), description: 'Asset Ownership reports assets without an accountable owner.' };
    return { gaps: out, read: ok };
  }
  async function liveSync(who) {
    const C2 = app.addons && app.addons.ciso; if (!C2 || typeof C2.collect !== 'function') { const r = { at: iso(), ok: false, error: 'AI CISO is not installed - the platform\'s gaps cannot be read (install/add-ciso.sh)' }; liveMeta.put(Object.assign({ id: 'last' }, r)); return r; }
    const S = await C2.collect(), G = gapsFrom(S), t = iso(), created = [], cleared = [], back = [];
    for (const [k, gp] of Object.entries(G.gaps)) {
      const open = C.actions.all((a) => a.source === gp.source && a.ref === gp.ref && A_OPEN.includes(a.status))[0];
      if (open) {
        if (open.live_cleared_at) { const rec = Object.assign({}, open, { live_cleared_at: null, live_seen_at: t }); hist(rec, LIVE_WHO, 'the platform reports this gap again'); C.actions.put(rec); back.push(open.id); }
        else if (open.live_seen_at !== t) { C.actions.put(Object.assign({}, open, { live_seen_at: t })); }
        continue;
      }
      const a = actionCreate({ title: gp.title, source: gp.source, ref: gp.ref, description: gp.description, owner: gp.owner, priority: gp.priority, due: dueFor(gp.priority), framework: gp.framework || '' }, LIVE_WHO);
      C.actions.put(Object.assign(C.actions.get(a.id), { live: true, live_seen_at: t })); created.push(a.id);
    }
    // gone from a source that WAS read: say so on the open action, never close it
    for (const a of C.actions.all((x) => A_OPEN.includes(x.status) && x.live && !x.live_cleared_at)) {
      if (!G.read[a.source] || G.gaps[a.source + '|' + a.ref]) continue;
      const rec = Object.assign({}, a, { live_cleared_at: t }); hist(rec, LIVE_WHO, 'the platform no longer reports this gap - verify the fix, mark it done and have someone else close it');
      C.actions.put(rec); cleared.push(a.id);
    }
    const risks = typeof C2.risks === 'function' ? C2.risks(S) : [], rated = new Set(C.risks.all((r) => r.status === 'open' && r.source_ref).map((r) => r.source_ref));
    const candidates = risks.filter((r) => (r.severity === 'critical' || r.severity === 'high') && !rated.has(r.ref)).slice(0, 60)
      .map((r) => ({ ref: s(r.ref, 160), severity: r.severity, domain: r.domain, title: s(r.title, 200), source: s(r.source, 80), link: s(r.link, 80) }));
    const sources = Object.fromEntries(Object.entries(S).map(([k2, v]) => [k2, v.state]));
    const res = { at: t, ok: true, by: (who && who.user) || LIVE_WHO.user, created, cleared, back, gaps: Object.keys(G.gaps).length, read: G.read, sources, candidates };
    liveMeta.put(Object.assign({ id: 'last' }, res));
    if (created.length || cleared.length || back.length) audit(who || LIVE_WHO, 'grc.live.sync', 'grc_actions', { created: created.length, cleared: cleared.length, back: back.length });
    return res;
  }
  function liveView() { const l = liveMeta.get('last'); return l ? Object.assign({}, l, { candidates: (l.candidates || []).filter((c) => !C.risks.all((r) => r.status === 'open' && r.source_ref === c.ref).length) }) : { at: null, ok: null, candidates: [] }; }

  function workspace(who) {
    const a = actionList().items, r = riskList().items, x = excList().items, e = evList();
    const me = who && who.user;
    return {
      at: iso(),
      actions: { open: a.filter((v) => A_OPEN.includes(v.status)).length, overdue: a.filter((v) => v.overdue).length, due_soon: a.filter((v) => v.due_soon).length,
        awaiting_verification: a.filter((v) => v.status === 'done').length, closed_30d: a.filter((v) => v.status === 'closed' && v.closed_at && Date.parse(v.closed_at) > now() - 30 * DAY).length },
      risks: { open: r.filter((v) => v.status === 'open').length, high: r.filter((v) => v.status === 'open' && (v.residual_band || v.inherent_band) === 'high').length,
        review_overdue: r.filter((v) => v.review_overdue).length, awaiting_acceptance: r.filter((v) => v.status === 'open' && v.treatment === 'accept' && !v.acceptance).length },
      exceptions: { active: x.filter((v) => v.state === 'approved').length, requested: x.filter((v) => v.state === 'requested').length, expiring_soon: x.filter((v) => v.expiring_soon).length, expired: x.filter((v) => v.state === 'expired').length },
      evidence: { items: e.items.filter((v) => v.state !== 'retired').length, stale: e.items.filter((v) => v.state === 'stale').length, due_soon: e.items.filter((v) => v.state === 'due_soon').length,
        sama_controls: e.coverage.length, sama_missing: e.coverage.filter((c) => c.state === 'missing').length, sama_current: e.coverage.filter((c) => c.state === 'current' || c.state === 'due_soon').length },
      live: (() => { const l = liveMeta.get('last'); return l ? { at: l.at, ok: l.ok, error: l.error || null, gaps: l.gaps || 0, created: (l.created || []).length, cleared: (l.cleared || []).length, candidates: liveView().candidates.length, from_platform: a.filter((v) => v.live && A_OPEN.includes(v.status)).length } : null; })(),
      mine: me ? {
        actions: a.filter((v) => A_OPEN.includes(v.status) && same(v.owner, me)).map((v) => ({ id: v.id, title: v.title, due: v.due, overdue: v.overdue, status: v.status })),
        verify: a.filter((v) => v.status === 'done' && !same(v.done_by, me)).map((v) => ({ id: v.id, title: v.title, done_by: v.done_by })),
        risks_to_review: r.filter((v) => v.review_overdue && same(v.owner, me)).map((v) => ({ id: v.id, title: v.title, review_due: v.review_due })),
      } : null,
    };
  }

  return { actionCreate, actionUpdate, actionStatus, actionEvidence, actionList, riskCreate, riskUpdate, riskAccept, riskClose, riskList,
    excCreate, excDecide, excRevoke, excList, evCreate, evRetire, evList, file, workspace, liveSync, liveView, liveCfg, SOURCES, FRAMEWORKS };
}

function registerGrcRegisters(srv, app, opts = {}) {
  const R = createGrcRegisters(app, opts);
  (app.addons = app.addons || {}).grcRegisters = R;   // other modules raise actions through it (PDPL self-assessment gaps)
  const b = (ctx) => ctx.body || {}, up = { maxBody: 12 * 1024 * 1024 };
  srv.route('GET', '/grc/workspace', (ctx) => void ctx.need('viewer') || R.workspace(ctx.who));
  srv.route('GET', '/grc/actions', (ctx) => void ctx.need('viewer') || R.actionList(ctx.query || {}));
  srv.route('POST', '/grc/actions', (ctx) => { ctx.need('operator'); return R.actionCreate(b(ctx), ctx.who); });
  srv.route('POST', '/grc/actions/:id/status', (ctx) => { ctx.need('operator'); return R.actionStatus(ctx.params.id, b(ctx), ctx.who); });
  srv.route('POST', '/grc/actions/:id/evidence', (ctx) => { ctx.need('operator'); return R.actionEvidence(ctx.params.id, b(ctx), ctx.who); }, up);
  srv.route('POST', '/grc/actions/:id', (ctx) => { ctx.need('operator'); return R.actionUpdate(ctx.params.id, b(ctx), ctx.who); });
  srv.route('GET', '/grc/risks', (ctx) => void ctx.need('viewer') || R.riskList());
  srv.route('POST', '/grc/risks', (ctx) => { ctx.need('operator'); return R.riskCreate(b(ctx), ctx.who); });
  srv.route('POST', '/grc/risks/:id/accept', (ctx) => { ctx.need('operator'); return R.riskAccept(ctx.params.id, b(ctx), ctx.who); });
  srv.route('POST', '/grc/risks/:id/close', (ctx) => { ctx.need('operator'); return R.riskClose(ctx.params.id, b(ctx), ctx.who); });
  srv.route('POST', '/grc/risks/:id', (ctx) => { ctx.need('operator'); return R.riskUpdate(ctx.params.id, b(ctx), ctx.who); });
  srv.route('GET', '/grc/exceptions', (ctx) => void ctx.need('viewer') || R.excList());
  srv.route('POST', '/grc/exceptions', (ctx) => { ctx.need('operator'); return R.excCreate(b(ctx), ctx.who); });
  srv.route('POST', '/grc/exceptions/:id/decide', (ctx) => { ctx.need('operator'); return R.excDecide(ctx.params.id, b(ctx), ctx.who); });
  srv.route('POST', '/grc/exceptions/:id/revoke', (ctx) => { ctx.need('operator'); return R.excRevoke(ctx.params.id, b(ctx), ctx.who); });
  srv.route('GET', '/grc/evidence', (ctx) => void ctx.need('viewer') || R.evList());
  srv.route('POST', '/grc/evidence', (ctx) => { ctx.need('operator'); return R.evCreate(b(ctx), ctx.who); }, up);
  srv.route('POST', '/grc/evidence/:id/retire', (ctx) => { ctx.need('operator'); return R.evRetire(ctx.params.id, b(ctx), ctx.who); });
  srv.route('GET', '/grc/files/:id', (ctx) => { ctx.need('operator'); return R.file(ctx.params.id, ctx.who); });
  srv.route('GET', '/grc/live', (ctx) => { ctx.need('viewer'); return R.liveView(); });
  srv.route('POST', '/grc/live/sync', async (ctx) => { ctx.need('operator'); return R.liveSync(ctx.who); });
  // the registers follow the platform on their own: first read 2 minutes after start, then every grc.live.interval_min
  if (!opts.noTimer && R.liveCfg().enabled !== false) {
    const { guardOf } = require('./errors');
    const t1 = setTimeout(guardOf(app, 'grc.live', () => R.liveSync(null)), 120000), t2 = setInterval(guardOf(app, 'grc.live', () => R.liveSync(null)), Math.max(5, Number(R.liveCfg().interval_min) || 30) * 60000);
    if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  }
  (app.addons = app.addons || {}).grcRegisters = R;
  return R;
}

module.exports = { createGrcRegisters, registerGrcRegisters, SOURCES, FRAMEWORKS, TREATMENTS };
