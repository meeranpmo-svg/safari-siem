// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { createGapEngagement, registerGapRoutes } = require('./gap-engagement');
/*
 * ISO/IEC 27001:2022 Gap Assessment (ISO 27001 -> Start an ISO 27001 Gap Assessment, {P} = /api/itam/iso27001/gap). The seven steps
 * and their rules are in engine/gap-engagement.js; this adapter says what is ISO 27001 about them:
 *   evidence   the documented information the standard requires (clauses 4-10) and the key Annex A records, each with its clause /
 *              control - 20 items per department in scope
 *   baseline   the ISMS register as it stands (engine/iso27001.js): result counts for clauses and Annex A, the Statement of
 *              Applicability state and which evidence sources are connected (not connected = "not measured", never a pass)
 *   review     the ISMS register: every clause and Annex A control is verified by the platform's own evidence, or recorded by a person
 *              (evidence for met / partial, a note for not met / not applicable) and approved by the ISMS manager named in the ISO
 *              profile (four eyes). Complete when nothing is pending, not measured or without evidence
 *   gaps       every clause or control whose result is gap or partial
 *   GRC        the action "Send gaps to GRC" creates (source iso, ref iso:<id>) - created here when missing - carries the plan's
 *              owner and date
 *   approver   the ISMS manager named in the ISO 27001 profile
 * Routes as engine/pdpl-gap.js, under /iso27001/gap; every write audited as iso.gap.*.
 */
const EVIDENCE = [
  ['scope', 'ISMS scope statement with its boundaries and interfaces', 'Clause 4.3'],
  ['context', 'Internal / external issues and interested parties with their requirements', 'Clause 4.1, 4.2'],
  ['policy', 'Information security policy approved by top management', 'Clause 5.2'],
  ['roles', 'ISMS roles, responsibilities and authorities', 'Clause 5.3; A.5.2'],
  ['risk_method', 'Risk assessment and risk treatment methodology', 'Clause 6.1.2, 6.1.3'],
  ['risk_results', 'Risk assessment results, risk treatment plan and risk owners\' acceptance', 'Clause 8.2, 8.3'],
  ['soa', 'Statement of Applicability (controls included / excluded, with justification)', 'Clause 6.1.3 d'],
  ['objectives', 'Information security objectives and plans to achieve them', 'Clause 6.2'],
  ['competence', 'Competence records and the awareness programme', 'Clause 7.2, 7.3; A.6.3'],
  ['documents', 'Document control procedure and the list of controlled documents', 'Clause 7.5'],
  ['monitoring', 'Monitoring and measurement results (KPIs)', 'Clause 9.1'],
  ['audit', 'Internal audit programme and the last audit report', 'Clause 9.2'],
  ['review', 'Management review minutes and decisions', 'Clause 9.3'],
  ['nc', 'Nonconformity and corrective action records', 'Clause 10.2'],
  ['assets', 'Asset inventory with owners, acceptable use and classification', 'A.5.9, A.5.10, A.5.12'],
  ['access', 'Access control policy and the last access review', 'A.5.15, A.5.18, A.8.2'],
  ['suppliers', 'Supplier security: contracts, assessments and monitoring', 'A.5.19 to A.5.22'],
  ['incidents', 'Incident management procedure and the incident log', 'A.5.24 to A.5.28'],
  ['continuity', 'ICT readiness for business continuity: plans and test results', 'A.5.29, A.5.30'],
  ['technical', 'Technical records: backups, logging, vulnerability management, change management', 'A.8.8, A.8.13, A.8.15, A.8.32'],
];
const RESULTS = [['verified', 'Verified by the platform'], ['met', 'Recorded as met (approved)'], ['partial', 'Partial'], ['gap', 'Gap'], ['pending', 'Recorded, awaiting the ISMS manager\'s approval'], ['not_measured', 'Not measured (source not connected)'], ['no_evidence', 'Needs a person to record it'], ['not_applicable', 'Not applicable']];
const OPEN = ['pending', 'not_measured', 'no_evidence'];
const SEV = { high: 3, medium: 2, low: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
// the register is one Python call; within one request (cx, from the engine) the review, the gaps and the approver share one read
const reg = (app, cx) => { const I = app.addons && app.addons.iso27001; if (!I) throw httpErr(409, 'the ISO 27001 module is not installed - run the platform update'); if (!cx) return I.view(); return cx.iso || (cx.iso = I.view()); };
const items = (v) => (v.clauses || []).concat(v.annex || []);

const ADAPTER = {
  fw: 'iso', name: 'ISO 27001', collection: 'iso_gap', prefix: 'IGA', audit: 'iso.gap.', evidence: EVIDENCE,
  steps: ['Team & scope', 'Kick-off & evidence requests', 'ISMS register baseline', 'Clause & control review, ISMS manager approval', 'Gap rating', 'Remediation plan', 'Report & sign-off'],
  approverName: 'ISMS manager', reviewName: 'ISO 27001 clause & control review', gid: /^(?:A\.[5-8]\.\d{1,2}|(?:4|5|6|7|8|9|10)\.\d(?:\.\d)?)$/, gidName: 'ISO 27001 clause or Annex A control (e.g. 6.1.2, A.5.9)',
  reqLabel: 'Clause / control', textLabel: 'Requirement', reportTitle: 'ISO/IEC 27001:2022 Gap Assessment',
  disclaimer: 'An internal gap assessment against ISO/IEC 27001:2022. It is not a certification audit; only an accredited certification body certifies an ISMS (Stage 1 and Stage 2 audits).',
  note: 'An internal ISO/IEC 27001:2022 gap assessment: it measures the gap between the standard (clauses 4-10 and Annex A) and what the organisation can show. It is not a certification audit.',
  approver: async (app, cx) => { if (!(app.addons && app.addons.iso27001)) return null; const v = await reg(app, cx); return (v.profile && v.profile.isms_manager) || null; },
  async baseline(app) {
    const v = await reg(app), all = items(v), counts = {}; for (const [k] of RESULTS) counts[k] = 0; for (const c of all) counts[c.result] = (counts[c.result] || 0) + 1;
    const off = (v.sources || []).filter((s) => !s.connected).map((s) => s.id), soa = v.soa_state || {};
    const table = RESULTS.map(([k, label]) => ({ key: k, label: 'Clauses & controls: ' + label, value: counts[k] || 0, flag: (k === 'gap' || OPEN.includes(k)) && counts[k] > 0, flag_text: String(counts[k] || 0), fix: k === 'gap' || OPEN.includes(k) ? 'iso27001.html' : null }))
      .concat([{ key: 'soa', label: 'Statement of Applicability', value: soa.approved_at ? 1 : 0, text: soa.approved_at ? 'approved ' + String(soa.approved_at).slice(0, 10) : soa.proposed_at ? 'proposed, awaiting approval' : 'not approved', flag: !soa.approved_at, flag_text: soa.proposed_at ? 'awaiting approval' : 'not approved', fix: 'iso27001.html' },
        { key: 'manager', label: 'ISMS manager named', value: v.profile && v.profile.isms_manager ? 1 : 0, text: (v.profile && v.profile.isms_manager) || 'not named', flag: !(v.profile && v.profile.isms_manager), flag_text: 'not named', fix: 'iso27001.html' }])
      .concat((v.sources || []).map((s) => ({ key: 'src:' + s.id, label: 'Evidence source: ' + s.id, value: s.connected ? 1 : 0, text: s.connected ? 'connected' : 'not connected', flag: !s.connected, flag_text: 'not connected', fix: null })));
    return { counts, empty: off, score: v.score == null ? null : v.score, controls: all.length, table, summary: 'register score ' + (v.score == null ? '—' : v.score + '%') + ' · ' + (v.clauses || []).length + ' clauses, ' + (v.annex || []).length + ' Annex A controls · ' + off.length + ' evidence source(s) not connected' };
  },
  // the ISMS register is always there: the review is the register itself, seen from this engagement
  async startReview(app) { await reg(app); return 'ISMS-REGISTER'; },
  async review(app, e, cx) {
    const v = await reg(app, cx), all = items(v), cnt = {}; for (const c of all) cnt[c.result] = (cnt[c.result] || 0) + 1;
    const open = OPEN.reduce((a, k) => a + (cnt[k] || 0), 0), total = all.length, done = open === 0;
    const parts = [cnt.pending ? cnt.pending + ' recorded and awaiting the ISMS manager\'s approval' : '', cnt.no_evidence ? cnt.no_evidence + ' to be recorded by a person (with evidence or a note)' : '', cnt.not_measured ? cnt.not_measured + ' not measured - connect the source or record them by hand' : ''].filter(Boolean);
    return { id: 'ISMS-REGISTER', label: 'ISO/IEC 27001:2022 clauses and Annex A', status: done ? 'approved' : 'open', done, score: v.score, progress: { answered: total - open, total },
      chapters: (v.groups || []).map((g) => ({ area: (g.kind === 'clause' ? 'Clause ' : '') + g.code + ' ' + g.name, score: g.score, gaps: (g.counts && g.counts.gap) || 0 })), submitted_by: null, approved_by: (v.profile && v.profile.isms_manager) || null,
      what: (total - open) + ' of ' + total + ' clauses & controls assessed · score ' + (v.score == null ? '—' : v.score + '%'), block: done ? null : 'on the ISO 27001 page: ' + parts.join('; '),
      link: { href: 'iso27001.html', text: 'Open the ISO 27001 register to record and approve' } };
  },
  async gaps(app, e, cx) {
    const v = await reg(app, cx);
    return items(v).filter((c) => c.result === 'gap' || c.result === 'partial').map((c) => ({ id: c.id, req: (c.kind === 'clause' ? 'Clause ' : '') + c.id, area: c.group_name, ref: (c.kind === 'clause' ? 'ISO/IEC 27001:2022 clause ' : 'ISO/IEC 27001:2022 Annex ') + c.id,
      text: c.title, answer: c.result, note: c.why || '', weight: SEV[c.severity] || 0 }));
  },
  // ML inputs: severity and the register's reason (gaps with one missing record or source cluster together)
  async features(app, e, cx) { const v = await reg(app, cx), out = {}; for (const c of items(v)) out[c.id] = { severity: c.severity, cause: c.why || null }; return out; },
  action: (e, g) => ({ source: 'iso', ref: 'iso:' + g.id, framework: 'ISO 27001', title: 'ISO 27001 ' + g.id + ': ' + String(g.text).slice(0, 150) }),
};

const createIsoGap = (app, opts = {}) => createGapEngagement(app, ADAPTER, opts);
function registerIsoGap(srv, app, G0) {
  const G = G0 && G0.list ? G0 : createIsoGap(app, G0 || {});
  app.addons = app.addons || {}; app.addons.isoGap = G;
  return registerGapRoutes(srv, app, G, '/iso27001/gap');
}
module.exports = { createIsoGap, registerIsoGap, EVIDENCE, ADAPTER };
