// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { createGapEngagement, registerGapRoutes } = require('./gap-engagement');
/*
 * PDPL Implementation Gap Assessment (PDPL -> Start a PDPL Gap Assessment, {P} = /api/itam/pdpl/gap). The seven steps and their
 * rules are in engine/gap-engagement.js; this adapter says what is PDPL about them:
 *   evidence   14 standard items, each with the Law / Implementing Regulation article it proves
 *   baseline   how many records each PDPL register holds (an empty register is a finding) and the automated requirement results
 *   review     the PDPL Self-Assessment (engine/pdpl-assessment.js, 40 questions over 24 requirements): started for this
 *              engagement or the open one linked; answered, submitted and approved by the DPO there (four eyes)
 *   gaps       every question answered no / partial / unanswered in the approved self-assessment
 *   GRC        the action the approval created (source pdpl, ref <assessment>:<question>) carries the plan's owner and date
 *   approver   the DPO named in the PDPL profile
 * Routes (team = the lead, the assessors or an administrator; every write audited as pdpl.gap.*):
 *   GET  /pdpl/gap | /pdpl/gap/:id | /pdpl/gap/:id/report?format=html|csv            operator
 *   POST /pdpl/gap {name, lead, assessors[], sponsor, departments[], systems?, scope_note?, start, target}     operator
 *   POST /pdpl/gap/:id/scope | kickoff {due} | evidence/:rid {status, reference?, note?} | baseline | review   team
 *   POST /pdpl/gap/:id/gaps/:gid {likelihood, impact, root_cause, recommendation, owner, target} | plan       team
 *   POST /pdpl/gap/:id/report/summary {summary} | report/sign                                                  lead
 *   POST /pdpl/gap/:id/report/approve                                         DPO / administrator, not the signer
 */
const EVIDENCE = [
  ['dpo', 'DPO appointment letter and the DPO\'s role description', 'IR Art. 32'],
  ['policy', 'Privacy policy / notice published to data subjects', 'Law Art. 12; IR Art. 4'],
  ['ropa', 'Record of processing activities for the department', 'IR Art. 33'],
  ['legal_basis', 'Legal basis per processing purpose (consent wording, contracts, legitimate-interest assessments)', 'Law Art. 5-6; IR Art. 11-16'],
  ['consent', 'Consent records and the withdrawal mechanism', 'IR Art. 11-12'],
  ['dsar', 'Data-subject request procedure and the request log (last 12 months)', 'Law Art. 4; IR Art. 3-10'],
  ['dpia', 'Impact assessments for sensitive, large-scale or new-technology processing', 'Law Art. 22; IR Art. 25'],
  ['processors', 'Processor contracts with the PDPL clauses and their assessments', 'Law Art. 8; IR Art. 17'],
  ['transfers', 'Cross-border transfers: destination, legal basis, safeguards and risk assessments', 'Law Art. 29; CBTR'],
  ['retention', 'Retention schedule and destruction records', 'Law Art. 18; IR Art. 19'],
  ['breach', 'Breach response procedure, breach log and SDAIA notifications', 'Law Art. 20; IR Art. 24'],
  ['security', 'Security controls protecting personal data (access, encryption, logging)', 'Law Art. 19; IR Art. 23'],
  ['training', 'Privacy training records for staff handling personal data', 'IR Art. 32'],
  ['marketing', 'Direct marketing consent and opt-out handling', 'Law Art. 25-26; IR Art. 28-29'],
];
const BASE_KINDS = ['ropa', 'dpia', 'dsr', 'breach', 'transfer', 'processor', 'consent_purpose', 'retention', 'training', 'steward'];
const KIND_NAME = { ropa: 'Processing activities (RoPA)', dpia: 'Impact assessments', dsr: 'Data-subject requests', breach: 'Breaches', transfer: 'Cross-border transfers', processor: 'Processors', consent_purpose: 'Consent purposes', retention: 'Retention rules', training: 'Training records', steward: 'Data stewards' };
const FIX = { ropa: 'pdpl-ropa.html', dpia: 'pdpl-dpia.html', dsr: 'pdpl-dsar.html', breach: 'pdpl-breach.html', transfer: 'pdpl-transfers.html', processor: 'pdpl-processors.html', retention: 'pdpl-retention.html' };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const PD = (app) => (app.addons && app.addons.pdpl) || null, AS = (app) => (app.addons && app.addons.pdplAssessment) || null;

const ADAPTER = {
  fw: 'pdpl', name: 'PDPL', collection: 'pdpl_gap', prefix: 'PGA', audit: 'pdpl.gap.', evidence: EVIDENCE,
  steps: ['Team & scope', 'Kick-off & evidence requests', 'Register baseline', 'Questionnaire & DPO approval', 'Gap rating', 'Remediation plan', 'Report & sign-off'],
  approverName: 'DPO', reviewName: 'PDPL self-assessment', gid: /^P\d{2}-\d$/, gidName: 'question id (Pnn-n)', reqLabel: 'Requirement', textLabel: 'Question',
  reportTitle: 'PDPL Implementation Gap Assessment',
  disclaimer: 'An internal gap assessment against the Personal Data Protection Law and its Implementing Regulation. It is not an SDAIA certificate; SDAIA (or a body it accredits) remains the only authority for certification.',
  note: 'An internal PDPL implementation gap assessment: it measures the gap between what the Law and its Implementing Regulation require and what the organisation can show. It is not an SDAIA certificate.',
  approver: (app) => { const P = PD(app); const p = P ? (P.records('profile')[0] || {}) : {}; return p.dpo_user || null; },
  async baseline(app) {
    const P = PD(app); if (!P) throw httpErr(409, 'the PDPL module is not installed - run the platform update');
    const counts = {}; for (const k of BASE_KINDS) counts[k] = P.records(k).length;
    let automated = null; try { const v = await P.view(true); automated = { compliance_pct: v.compliance_pct, counts: v.counts }; }
    catch (er) { if (app.log && app.log.every) app.log.every('pdpl-gap:base', 600000, 'warn', 'PDPL gap: the automated requirement results could not be read', { err: er.message }); }
    const empty = BASE_KINDS.filter((k) => !counts[k]);
    return { counts, empty, automated, table: BASE_KINDS.map((k) => ({ key: k, label: KIND_NAME[k], value: counts[k], flag: !counts[k], flag_text: 'empty', fix: FIX[k] || null })),
      summary: automated && automated.compliance_pct != null ? 'automated requirement results ' + automated.compliance_pct + '%' : '' };
  },
  async startReview(app, e, who) {
    const A = AS(app); if (!A) throw httpErr(409, 'the PDPL Self-Assessment is not installed - run the platform update');
    const cur = await A.get();
    if (cur.assessment && ['draft', 'submitted'].includes(cur.assessment.status)) return cur.assessment.id;
    const cycle = (e.id + ' ' + e.name).replace(/[^A-Za-z0-9 ._()/-]/g, ' ').replace(/\s+/g, ' ').slice(0, 40).trim();
    return (await A.start({ cycle }, who)).id;
  },
  async review(app, e) {
    const A = AS(app); if (!A) return null; const a = (await A.get(e.review_id)).assessment; if (!a) return null;
    const approved = a.status === 'approved';
    return { id: a.id, label: a.cycle, status: a.status, done: approved, score: a.score, progress: a.progress, chapters: (a.chapters || []).map((c) => ({ area: c.area, score: c.score, gaps: c.gaps })),
      submitted_by: a.submitted_by || null, approved_by: a.approved_by || null, what: a.id + ' ' + a.status + (a.progress ? ' · ' + a.progress.answered + '/' + a.progress.total + ' answered' : ''),
      block: a.status === 'draft' ? 'answer every question and submit it on the PDPL Self-Assessment page' : a.status === 'submitted' ? 'the DPO or an administrator approves it on the Self-Assessment page - not the submitter' : null,
      link: { href: 'pdpl-assessment.html', text: a.status === 'draft' ? 'Open the Self-Assessment to answer and submit' : 'Open the Self-Assessment to approve' } };
  },
  async gaps(app, e) {
    const a = (await AS(app).get(e.review_id)).assessment; if (!a || a.status !== 'approved') return [];
    return (a.gaps || []).map((g) => ({ id: g.id, req: g.req, area: g.area, ref: g.ref, text: g.text, answer: g.answer, note: g.note, weight: g.weight, action_ref: a.id + ':' + g.id }));
  },
  action: (e, g) => ({ source: 'pdpl', ref: g.action_ref, framework: 'PDPL', title: 'PDPL ' + g.req + ' (' + g.ref + '): ' + String(g.text).slice(0, 150) }),
};
const createPdplGap = (app, opts = {}) => createGapEngagement(app, ADAPTER, opts);
function registerPdplGap(srv, app, G0) {
  const G = G0 && G0.list ? G0 : createPdplGap(app, G0 || {});
  app.addons = app.addons || {}; app.addons.pdplGap = G;
  return registerGapRoutes(srv, app, G, '/pdpl/gap');
}
module.exports = { createPdplGap, registerPdplGap, EVIDENCE, ADAPTER };
