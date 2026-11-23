// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Vendor risk for processors (PDPL Art. 8; Implementing Regulation Art. 17). The rules are Python (pyengine/pdpl_vendor.py):
 * the inherent tier from what each vendor handles (the processing activities that name it), the questionnaire, the score,
 * the residual risk, the re-assessment schedule and the findings. This file validates, decides who may act, stores the
 * assessments and writes the audit record.
 *
 *   An assessment: started for a rated vendor (one open at a time) → the questionnaire file is downloaded and sent to the
 *   vendor (sent) → the vendor's filled-in file is imported, or a person types an answer the vendor gave by letter (returned)
 *   → a person reviews every answer: accepted, or challenged with a note (challenged counts as not met) → submitted →
 *   approved by the DPO or an administrator who did not submit it (four-eyes), or sent back with a note.
 *   On approval: the processor's due-diligence checks (Processors page) are set from the answers, the vendor's tier,
 *   score, residual risk and next due date are kept, and every gap becomes a GRC remediation action (source pdpl, ref
 *   <assessment>:<question>, never twice while one is open). Nothing is sent to the vendor from here: the file goes by the
 *   channel the contract names. Every write is by a person and audited.
 *
 *   GET  /pdpl/vendors                                operator  tiers, assessments, schedule, findings
 *   GET  /pdpl/vendors/questions                      operator  the questionnaire
 *   POST /pdpl/vendors/:pid/assessments               operator  {return_by?}                                   audited
 *   GET  /pdpl/vendors/assessments/:id                operator  answers, reviews, score, gaps, blockers
 *   GET  /pdpl/vendors/assessments/:id/questionnaire  operator  the CSV to send (marks it sent)                 audited
 *   POST /pdpl/vendors/assessments/:id/answers        operator  {csv} the vendor's returned file               audited
 *   POST /pdpl/vendors/assessments/:id/answer         operator  {qid, answer, evidence?, note?}                audited
 *   POST /pdpl/vendors/assessments/:id/review         operator  {qid, verdict: accepted|challenged, note?}     audited
 *   POST /pdpl/vendors/assessments/:id/submit         operator                                                 audited
 *   POST /pdpl/vendors/assessments/:id/decide         the DPO / an administrator, not the submitter {decision: approve|reject, note?}  audited
 *   POST /pdpl/vendors/assessments/:id/cancel         operator  {note}                                         audited
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const same = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
const QIDS = /^[A-Z]{3}-\d$/;

function createVendor(app, PD, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = () => store.collection('pdpl_vendor_assessments');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  async function rules(op, body) { const r = await PD.rules(op, body); if (r && r.refuse) throw httpErr(r.refuse.status, r.refuse.error); return r; }
  const profile = () => PD.records('profile')[0] || {};
  const isDpo = (who) => !!profile().dpo_user && same(profile().dpo_user, who.user);
  const hist = (a, who, what) => { a.history = (a.history || []).concat([{ at: iso(), by: who.user, what }]).slice(-100); };
  function getA(id) { const a = col().get(id); if (!a) throw httpErr(404, 'no vendor assessment ' + id); return a; }
  function open(id, states) { const a = getA(id); if (!states.includes(a.status)) throw httpErr(409, id + ' is ' + a.status + ' - this step needs ' + states.join(' or ')); return a; }
  const full = async (a) => rules('pdpl.vendor_assessment', { assessment: a });

  async function view() { return rules('pdpl.vendor_view', { assessments: col().all() }); }
  async function findings() { if (!PD.records('processor').length) return []; return (await view()).findings || []; }

  async function start(pid, b, who) {
    human(who, 'starts a vendor assessment');
    const p = PD.records('processor').find((r) => r.id === pid); if (!p) throw httpErr(404, 'no processor ' + pid);
    if (p.status === 'archived') throw httpErr(409, pid + ' is archived');
    const cur = col().all((a) => a.processor_id === pid && !['approved', 'cancelled'].includes(a.status))[0];
    if (cur) throw httpErr(409, 'an assessment of ' + p.name + ' is already open: ' + cur.id);
    const t = await rules('pdpl.vendor_tier', { processor: p });
    if (!t.tier) throw httpErr(409, 'the vendor is not rated yet: ' + t.why[0]);
    const rb = b.return_by || new Date(now() + 21 * DAY).toISOString().slice(0, 10);
    if (Date.parse(rb + 'T23:59:59Z') < now()) throw httpErr(400, 'return_by must be today or later');
    let n = col().size() + 1, id = 'VRA-' + String(n).padStart(3, '0'); while (col().get(id)) id = 'VRA-' + String(++n).padStart(3, '0');
    const a = { id, processor_id: pid, vendor: p.name, tier: t.tier, tier_why: t.why, status: 'draft', return_by: rb, answers: {}, reviews: {}, created_by: who.user, created_at: iso(), history: [] };
    hist(a, who, 'started (' + t.tier + ' risk)'); col().put(a);
    audit(who, 'pdpl.vendor.start', id, { processor: pid, tier: t.tier, return_by: rb });
    return full(a);
  }
  async function questionnaire(id, who) {
    human(who, 'sends a vendor questionnaire'); const a = open(id, ['draft', 'sent', 'returned']);
    const p = PD.records('processor').find((r) => r.id === a.processor_id) || {};
    const out = await rules('pdpl.vendor_csv', { assessment: a, processor: p });
    if (a.status === 'draft') { a.status = 'sent'; a.sent_by = who.user; a.sent_at = iso(); hist(a, who, 'questionnaire downloaded to send'); col().put(a); }
    audit(who, 'pdpl.vendor.questionnaire', id, { status: a.status });
    return out;
  }
  async function importAnswers(id, b, who) {
    human(who, 'records a vendor\'s answers'); const a = open(id, ['sent', 'returned']);
    const r = await rules('pdpl.vendor_import', { csv: b.csv });
    if (!r.answered) throw httpErr(400, 'csv: no answered question found' + (r.errors.length ? ' (' + r.errors.slice(0, 3).join('; ') + ')' : ''));
    let changed = 0;
    for (const [q, v] of Object.entries(r.answers)) {
      const old = a.answers[q];
      if (!old || old.answer !== v.answer || old.evidence !== v.evidence) { changed++; delete a.reviews[q]; }   // a changed answer is reviewed again
      a.answers[q] = Object.assign({}, v, { source: 'vendor file', at: iso() });
    }
    a.status = 'returned'; a.imported_by = who.user; a.imported_at = iso();
    hist(a, who, 'vendor file imported: ' + r.answered + ' answer(s), ' + changed + ' new or changed' + (r.errors.length ? ', ' + r.errors.length + ' row(s) refused' : '')); col().put(a);
    audit(who, 'pdpl.vendor.answers', id, { answered: r.answered, changed, refused: r.errors.length });
    return Object.assign(await full(a), { imported: { answered: r.answered, of: r.of, changed, errors: r.errors } });
  }
  async function answer(id, b, who) {
    human(who, 'records a vendor\'s answer'); const a = open(id, ['sent', 'returned']);
    if (b.answer !== 'na' && b.answer !== 'no' && !b.evidence) throw httpErr(400, 'evidence is required for a yes / partial answer: what the vendor showed (certificate no., clause, report)');
    a.answers[b.qid] = { answer: b.answer, evidence: b.evidence || '', note: b.note || '', source: 'typed by ' + who.user, at: iso() }; delete a.reviews[b.qid];
    a.status = 'returned'; hist(a, who, b.qid + ' answered ' + b.answer); col().put(a);
    audit(who, 'pdpl.vendor.answer', id, { qid: b.qid, answer: b.answer });
    return full(a);
  }
  async function review(id, b, who) {
    human(who, 'reviews a vendor\'s answer'); const a = open(id, ['returned']);
    if (!a.answers[b.qid]) throw httpErr(409, b.qid + ' has no answer to review yet');
    if (b.verdict === 'challenged' && !b.note) throw httpErr(400, 'note is required: say what is missing or doubtful, so the vendor can answer it');
    a.reviews[b.qid] = { verdict: b.verdict, note: b.note || '', by: who.user, at: iso() };
    hist(a, who, b.qid + ' ' + b.verdict); col().put(a);
    audit(who, 'pdpl.vendor.review', id, { qid: b.qid, verdict: b.verdict });
    return full(a);
  }
  async function submit(id, who) {
    human(who, 'submits a vendor assessment'); const a = open(id, ['returned']);
    const v = await full(a); if (!v.can_submit) throw httpErr(409, 'not ready: ' + v.blockers.join('; '));
    a.status = 'submitted'; a.submitted_by = who.user; a.submitted_at = iso(); hist(a, who, 'submitted (score ' + v.score + '%, ' + v.residual + ' residual)'); col().put(a);
    audit(who, 'pdpl.vendor.submit', id, { score: v.score, residual: v.residual });
    return full(a);
  }
  async function decide(id, b, who) {
    human(who, 'approves a vendor assessment'); const a = open(id, ['submitted']);
    if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (profile().dpo_user || 'not named') + ') or an administrator approves a vendor assessment');
    if (same(a.submitted_by, who.user)) throw httpErr(403, 'four-eyes: the person who submitted the assessment cannot approve it');
    if (b.decision === 'reject') {
      if (!b.note) throw httpErr(400, 'note is required: say what must be redone');
      a.status = 'returned'; a.rejected_by = who.user; a.rejected_at = iso(); a.reject_note = b.note; hist(a, who, 'sent back: ' + b.note); col().put(a);
      audit(who, 'pdpl.vendor.reject', id, { note: b.note.slice(0, 200) });
      return full(a);
    }
    const v = await full(a), out = { actions: [], skipped: [] };
    const G = (app.addons && app.addons.grcRegisters) || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { return null; } })();
    const dueDays = { high: 30, medium: 60, low: 90 };
    for (const g of v.gaps) {
      if (!G) { out.skipped.push(g.id + ': GRC registers not installed'); continue; }
      try {
        const act = G.actionCreate({ title: 'Vendor ' + a.vendor + ' - ' + g.domain + ' (' + g.id + '): ' + g.q.slice(0, 120), source: 'pdpl', ref: id + ':' + g.id, framework: 'PDPL', priority: g.priority,
          due: new Date(now() + dueDays[g.priority] * DAY).toISOString().slice(0, 10), description: 'Vendor assessment ' + id + ' (' + a.tier + ' risk): answered "' + g.answer + '"' + (g.challenged ? ', challenged' : '') + (g.note ? ' - ' + g.note : '') + '. Agree the fix with the vendor and close with its evidence.' }, who);
        out.actions.push(act.id);
      } catch (e) { out.skipped.push(g.id + ': ' + String(e.message).slice(0, 120)); }
    }
    Object.assign(a, { status: 'approved', approved_by: who.user, approved_at: iso(), approve_note: b.note || '', score: v.score, residual: v.residual, grc_actions: out.actions });
    hist(a, who, 'approved: score ' + v.score + '%, ' + v.residual + ' residual, ' + out.actions.length + ' GRC action(s)'); col().put(a);
    // the Processors page's due-diligence checks follow the approved answers
    PD.putRecord({ kind: 'processor', id: a.processor_id, assessment: v.dd, assessed: iso().slice(0, 10), assessment_evidence: 'vendor assessment ' + id + ' (' + v.score + '%)', assessed_by: who.user,
      vendor_risk: { tier: a.tier, score: v.score, residual: v.residual, assessment: id, approved_at: a.approved_at } }, who);
    audit(who, 'pdpl.vendor.approve', id, { processor: a.processor_id, score: v.score, residual: v.residual, grc_actions: out.actions, skipped: out.skipped.length });
    return Object.assign(await full(a), { result: out });
  }
  async function cancel(id, b, who) {
    human(who, 'cancels a vendor assessment'); const a = open(id, ['draft', 'sent', 'returned', 'submitted']);
    a.status = 'cancelled'; a.cancelled_by = who.user; a.cancel_note = b.note; hist(a, who, 'cancelled: ' + b.note); col().put(a);
    audit(who, 'pdpl.vendor.cancel', id, { note: b.note.slice(0, 200) });
    return full(a);
  }
  return { view, findings, start, questionnaire, importAnswers, answer, review, submit, decide, cancel, get: (id) => full(getA(id)), questions: () => rules('pdpl.vendor_questions', {}) };
}

function registerVendorRoutes(srv, app, V) {
  const { body, param } = require('./check');
  const AID = (ctx) => { const id = param(ctx.params.id, 'id'); if (!/^VRA-\d{3,}$/.test(id)) throw httpErr(400, 'id must be a vendor assessment id (VRA-nnn)'); return id; };
  const QID = { required: true, max: 6, re: QIDS, msg: 'qid must be a question id (e.g. CER-1)' };
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };   // vendor assessments are PDPL records: operator and above
  srv.route('GET', '/pdpl/vendors', op(() => V.view()));
  srv.route('GET', '/pdpl/vendors/questions', op(() => V.questions()));
  srv.route('POST', '/pdpl/vendors/:pid/assessments', op((ctx) => {
    const pid = param(ctx.params.pid, 'pid'); if (!/^PD-PROCESSOR-\d{3,}$/.test(pid)) throw httpErr(400, 'pid must be a processor id (PD-PROCESSOR-nnn)');
    return V.start(pid, body(ctx.body).str('return_by', { max: 10, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'return_by must be a date (YYYY-MM-DD)' }).done(), ctx.who);
  }));
  srv.route('GET', '/pdpl/vendors/assessments/:id', op((ctx) => V.get(AID(ctx))));
  srv.route('GET', '/pdpl/vendors/assessments/:id/questionnaire', op((ctx) => V.questionnaire(AID(ctx), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/answers', op((ctx) => V.importAnswers(AID(ctx), body(ctx.body).str('csv', { required: true, max: 200000, re: /^[^\u0000]*$/s, msg: 'csv must be text' }).done(), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/answer', op((ctx) => V.answer(AID(ctx), body(ctx.body).str('qid', QID).oneOf('answer', ['yes', 'partial', 'no', 'na'], { required: true }).str('evidence', { max: 500 }).str('note', { max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/review', op((ctx) => V.review(AID(ctx), body(ctx.body).str('qid', QID).oneOf('verdict', ['accepted', 'challenged'], { required: true }).str('note', { max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/submit', op((ctx) => V.submit(AID(ctx), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/decide', op((ctx) => V.decide(AID(ctx), body(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 }).done(), ctx.who)));
  srv.route('POST', '/pdpl/vendors/assessments/:id/cancel', op((ctx) => V.cancel(AID(ctx), body(ctx.body).str('note', { required: true, min: 5, max: 500 }).done(), ctx.who)));
}

module.exports = { createVendor, registerVendorRoutes };
