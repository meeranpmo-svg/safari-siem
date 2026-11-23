// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
/*
 * PDPL Self-Assessment (PDPL -> Self-Assessment, {P} = /api/itam): a guided questionnaire over the AI PDPL Consultant's 24
 * requirements (questions and scoring in pyengine/pdpl_assessment.py), one assessment per cycle:
 *   draft -> submitted -> approved | rejected (back to draft)
 * Every answer needs its evidence (yes / partial) or a note (no / not applicable). The registers' automated result is shown
 * beside each question as a suggestion; a person answers. Approval is four-eyes: the DPO named in the PDPL profile or an
 * administrator, a person, never the one who submitted. On approval:
 *   - each requirement's roll-up is written as its confirmation (engine/pdpl.js confirm) by the approver, so the compliance
 *     statement the DPO signs reads the same answers;
 *   - every question answered no / partial becomes a GRC remediation action (source "pdpl", framework PDPL, ref
 *     "<assessment>:<question>"), unassigned, due by priority - never twice for the same open reference.
 * The assessment is an internal self-assessment, not an SDAIA certificate; the page says so.
 *
 *   GET  /pdpl/assessment/summary              viewer    latest approved score and chapter scores (no answers)
 *   GET  /pdpl/assessment[?id=]                operator  the current (or chosen) assessment with questions, answers, scores
 *   POST /pdpl/assessment {cycle}              operator  start one (only when none is open)                      audited
 *   POST /pdpl/assessment/:id/answer {qid, answer, evidence?, note?}  operator  draft only                       audited
 *   POST /pdpl/assessment/:id/submit           operator  every question answered                                 audited
 *   POST /pdpl/assessment/:id/decide {decision: approve|reject, note?}  DPO / administrator, four-eyes           audited
 */
const ANSWERS = ['yes', 'partial', 'no', 'na'];
const QID = /^P\d{2}-\d$/;
const CYCLE = /^[A-Za-z0-9 ._()/-]{3,40}$/;
const OPEN = ['draft', 'submitted'];
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createPdplAssessment(app, opts = {}) {
  const now = opts.now || Date.now, col = app.store.collection('pdpl_assessments');
  const iso = () => new Date(now()).toISOString();
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const PD = () => (app.addons && app.addons.pdpl) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (!r || r.ok === false) {
      if (app.log && app.log.every) app.log.every('pdpl-assess:py', 600000, 'warn', 'PDPL assessment: the rules (Python) did not answer', { op, err: String((r && r.error) || '').slice(0, 200) });
      throw httpErr(409, 'The PDPL assessment rules run in Python and Python did not answer - run the update so pyengine is installed');
    }
    return r;
  }
  async function auto() {
    const P = PD(); if (!P) return [];
    try { return (await P.assess()).requirements || []; }
    catch (e) { if (app.log && app.log.every) app.log.every('pdpl-assess:auto', 600000, 'warn', 'PDPL assessment: the registers could not be read for suggestions', { err: e.message }); return []; }
  }
  const all = () => col.all(() => true).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  const must = (id) => { const a = col.get(id); if (!a) throw httpErr(404, 'no PDPL assessment ' + id); return a; };
  const hist = (a, who, what) => { a.history = (a.history || []).concat([{ at: iso(), by: who.user, role: who.role, what: String(what).slice(0, 300) }]).slice(-500); };
  async function full(a) {
    const v = await rules('pdplassess.view', { assessment: a, auto: await auto() });
    const pub = Object.assign({}, a); delete pub.answers;
    return Object.assign(pub, { questions: v.questions, chapters: v.chapters, requirements: v.requirements, score: v.score, progress: v.progress, gaps: v.gaps, conflicts: v.conflicts, missing: v.missing, ready_to_submit: v.ready_to_submit });
  }
  async function get(id) {
    const A = all(); const a = id ? must(id) : (A.find((x) => OPEN.includes(x.status)) || A[0] || null);
    const past = A.map((x) => ({ id: x.id, cycle: x.cycle, status: x.status, score: x.score == null ? null : x.score, approved_at: x.approved_at || null, approved_by: x.approved_by || null }));
    if (!a) { const q = await rules('pdplassess.questions'); return { assessment: null, past, chapters: q.chapters, questions: q.questions.length, profile_dpo: dpo() }; }
    return { assessment: await full(a), past, profile_dpo: dpo() };
  }
  function dpo() { const P = PD(); const p = P ? (P.records('profile')[0] || {}) : {}; return p.dpo_user || null; }
  async function summary() {
    const a = all().find((x) => x.status === 'approved');
    if (!a) return { approved: null, note: 'No approved PDPL self-assessment yet.' };
    return { approved: { id: a.id, cycle: a.cycle, score: a.score, chapters: a.chapters || [], approved_at: a.approved_at, approved_by: a.approved_by } };
  }
  async function start(input, who) {
    const b = body(input || {}).str('cycle', { required: true, max: 40, re: CYCLE, msg: 'cycle must be 3-40 letters, digits, spaces or . _ - / ( )' }).done();
    const open = all().find((x) => OPEN.includes(x.status));
    if (open) throw httpErr(409, 'assessment ' + open.id + ' (' + open.cycle + ') is still ' + open.status + ' - finish it first');
    const n = all().length + 1, id = 'PA-' + new Date(now()).getUTCFullYear() + '-' + String(n).padStart(3, '0');
    const a = { id, cycle: b.cycle, status: 'draft', answers: {}, version: 1, created_by: who.user, created_at: iso() };
    hist(a, who, 'started'); col.put(a); audit(who, 'pdpl.assessment.start', id, { cycle: b.cycle });
    return full(a);
  }
  async function answer(id, input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot answer the PDPL assessment');
    const b = body(input || {}).str('qid', { required: true, re: QID, msg: 'qid must be a question id (Pnn-n)' }).oneOf('answer', ANSWERS, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.answer === 'yes' || o.answer === 'partial') && !o.evidence ? 'evidence is required for yes / partial: name the document, register or record relied on' : null))
      .rule((o) => ((o.answer === 'no' || o.answer === 'na') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    const a = must(id); if (a.status !== 'draft') throw httpErr(409, 'assessment ' + id + ' is ' + a.status + ' - answers can be changed only in a draft');
    const q = await rules('pdplassess.questions'); if (!q.questions.some((x) => x.id === b.qid)) throw httpErr(400, 'qid: no question ' + b.qid);
    const prev = (a.answers || {})[b.qid];
    a.answers = Object.assign({}, a.answers, { [b.qid]: { answer: b.answer, evidence: b.evidence || '', note: b.note || '', by: who.user, at: iso() } });
    a.version = (a.version || 1) + 1; hist(a, who, b.qid + ': ' + (prev ? prev.answer + ' -> ' : '') + b.answer); col.put(a);
    audit(who, 'pdpl.assessment.answer', id, { qid: b.qid, answer: b.answer, previous: prev ? prev.answer : null });
    return full(a);
  }
  async function submit(id, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot submit the PDPL assessment');
    const a = must(id); if (a.status !== 'draft') throw httpErr(409, 'assessment ' + id + ' is ' + a.status);
    const v = await full(a);
    if (!v.ready_to_submit) throw httpErr(400, v.missing.length + ' question(s) not answered yet: ' + v.missing.slice(0, 8).join(', ') + (v.missing.length > 8 ? ' …' : ''));
    Object.assign(a, { status: 'submitted', submitted_by: who.user, submitted_at: iso(), score: v.score, chapters: v.chapters.map((c) => ({ area: c.area, score: c.score, gaps: c.gaps })) });
    hist(a, who, 'submitted for approval (score ' + v.score + '%)'); col.put(a);
    audit(who, 'pdpl.assessment.submit', id, { score: v.score, gaps: v.gaps.length, conflicts: v.conflicts.length });
    return full(a);
  }
  async function decide(id, input, who) {
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const a = must(id); if (a.status !== 'submitted') throw httpErr(409, 'assessment ' + id + ' is ' + a.status + ' - only a submitted assessment is decided');
    if (isService(who.user)) throw httpErr(403, 'only a person approves: ' + who.user + ' is a service / AI identity');
    if (!(who.role === 'admin' || same(dpo(), who.user))) throw httpErr(403, 'approving the PDPL assessment needs the DPO named in the PDPL profile or an administrator');
    if (same(a.submitted_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' submitted this assessment and cannot also decide it');
    if (b.decision === 'reject') {
      Object.assign(a, { status: 'draft', rejected_by: who.user, rejected_at: iso(), reject_note: b.note });
      hist(a, who, 'rejected: ' + b.note); col.put(a); audit(who, 'pdpl.assessment.reject', id, { note: b.note });
      return full(a);
    }
    const v = await full(a), out = { confirmed: [], confirm_failed: [], actions: [], action_skipped: [] };
    const P = PD();
    for (const r of v.requirements) {
      if (!P) break;
      const conf = { id: r.id, status: r.result, evidence: r.evidence || (r.result === 'compliant' || r.result === 'partial' ? 'PDPL self-assessment ' + id : ''), note: r.note || (r.result === 'non_compliant' || r.result === 'not_applicable' ? 'PDPL self-assessment ' + id : '') };
      try { await P.confirm(conf, who); out.confirmed.push(r.id); } catch (e) { out.confirm_failed.push(r.id + ': ' + String(e.message).slice(0, 120)); }
    }
    const G = (app.addons && app.addons.grcRegisters) || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { return null; } })();
    const dueDays = { high: 30, medium: 60, low: 90 };
    for (const g of v.gaps) {
      if (!G) break;
      const pri = g.weight >= 2 && g.answer === 'no' ? 'high' : g.answer === 'no' ? 'medium' : 'low';
      try {
        const act = G.actionCreate({ title: 'PDPL ' + g.req + ' (' + g.ref + '): ' + g.text.slice(0, 150), source: 'pdpl', ref: id + ':' + g.id, framework: 'PDPL', priority: pri,
          due: new Date(now() + dueDays[pri] * DAY).toISOString().slice(0, 10), description: 'PDPL self-assessment ' + id + ' (' + a.cycle + ') answered "' + g.answer + '"' + (g.note ? ': ' + g.note : '') + '. Close it with the evidence that the requirement is now met.' }, who);
        out.actions.push(act.id);
      } catch (e) { out.action_skipped.push(g.id + ': ' + String(e.message).slice(0, 120)); }
    }
    Object.assign(a, { status: 'approved', approved_by: who.user, approved_at: iso(), approve_note: b.note || '', score: v.score, chapters: v.chapters.map((c) => ({ area: c.area, score: c.score, gaps: c.gaps })), grc_actions: out.actions });
    hist(a, who, 'approved; ' + out.confirmed.length + ' requirement confirmations written, ' + out.actions.length + ' GRC actions created'); col.put(a);
    audit(who, 'pdpl.assessment.approve', id, { score: v.score, confirmed: out.confirmed.length, confirm_failed: out.confirm_failed.length, grc_actions: out.actions, skipped: out.action_skipped.length });
    return Object.assign(await full(a), { result: out });
  }
  return { get, summary, start, answer, submit, decide };
}

function registerPdplAssessmentRoutes(srv, app, A) {
  srv.route('GET', '/pdpl/assessment/summary', (ctx) => { ctx.need('viewer'); return A.summary(); });
  srv.route('GET', '/pdpl/assessment', (ctx) => {
    ctx.need('operator');
    const q = body(ctx.query || {}).str('id', { max: 40, id: true }).done();
    return A.get(q.id);
  });
  srv.route('POST', '/pdpl/assessment', (ctx) => { ctx.need('operator'); return A.start(ctx.body, ctx.who); });
  srv.route('POST', '/pdpl/assessment/:id/answer', (ctx) => { ctx.need('operator'); return A.answer(param(ctx.params.id), ctx.body, ctx.who); });
  srv.route('POST', '/pdpl/assessment/:id/submit', (ctx) => { ctx.need('operator'); return A.submit(param(ctx.params.id), ctx.who); });
  srv.route('POST', '/pdpl/assessment/:id/decide', (ctx) => { ctx.need('operator'); return A.decide(param(ctx.params.id), ctx.body, ctx.who); });
}

module.exports = { createPdplAssessment, registerPdplAssessmentRoutes };
