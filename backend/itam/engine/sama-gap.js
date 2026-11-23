// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { createGapEngagement, registerGapRoutes } = require('./gap-engagement');
/*
 * SAMA Cyber Security Framework Gap Assessment (SAMA CSF -> Start a SAMA CSF Gap Assessment, {P} = /api/itam/sama-ia/gap). The seven
 * steps and their rules are in engine/gap-engagement.js; this adapter says what is SAMA CSF (and the Insurance Authority circular)
 * about them:
 *   evidence   18 standard items across the four SAMA CSF domains (3.1 leadership & governance, 3.2 risk management & compliance,
 *              3.3 operations & technology, 3.4 third parties) and the Insurance Authority cyber circular, each with its section
 *   baseline   the SAMA register as it stands (engine/sama-ia.js): result counts, the overall maturity score against the target
 *              level, the evidence pillars and which sources are connected (not connected = "not measured", never a pass)
 *   review     the SAMA register: every requirement is verified by the platform's own evidence (shared with the NCA ECC register),
 *              or recorded by a person and approved by the CISO (four eyes). Complete when nothing is pending, not measured or
 *              without evidence
 *   gaps       every requirement whose result is gap or partial
 *   GRC        the action "Send gaps to GRC" creates (source sama, ref sama:<id>) - created here when missing - carries the plan's
 *              owner and date
 *   approver   the CISO (named in the NCA ECC profile, which the SAMA register shares)
 *   ML inputs  features(): the register's chance-of-gap model per requirement (p_gap, regression, flapping), severity and cause
 * Routes as engine/pdpl-gap.js, under /sama-ia/gap; every write audited as sama.gap.*.
 */
const EVIDENCE = [
  ['strategy', 'Board-approved cyber security strategy and the cyber security committee charter and minutes', 'SAMA CSF 3.1.1, 3.1.2'],
  ['function', 'Cyber security function independent of IT, CISO appointment and organisation chart', 'SAMA CSF 3.1.1'],
  ['policy', 'Cyber security policy and the supporting standards, approved and reviewed', 'SAMA CSF 3.1.3'],
  ['roles', 'Cyber security roles and responsibilities (RACI) across the business', 'SAMA CSF 3.1.4'],
  ['projects', 'Cyber security in project management and the change process', 'SAMA CSF 3.1.5'],
  ['awareness', 'Awareness and training programme with attendance and phishing results', 'SAMA CSF 3.1.6, 3.1.7'],
  ['risk', 'Cyber security risk management methodology, register and treatment plans', 'SAMA CSF 3.2.1'],
  ['compliance', 'Regulatory compliance register and the last compliance review', 'SAMA CSF 3.2.2'],
  ['review_audit', 'Cyber security review and audit reports (internal and independent)', 'SAMA CSF 3.2.3, 3.2.4'],
  ['assets', 'Information asset inventory and classification', 'SAMA CSF 3.3.2, 3.3.3'],
  ['iam', 'Identity and access management: access reviews, privileged access, MFA', 'SAMA CSF 3.3.5'],
  ['protection', 'Application, change, infrastructure, cryptography and BYOD security controls', 'SAMA CSF 3.3.6 to 3.3.10'],
  ['secure_disposal', 'Secure disposal of information assets', 'SAMA CSF 3.3.11'],
  ['payments', 'Payment systems and electronic banking services security (where applicable)', 'SAMA CSF 3.3.12, 3.3.13'],
  ['monitoring', 'Cyber security event management: SIEM coverage, use cases, SOC procedure, log retention', 'SAMA CSF 3.3.14'],
  ['incident', 'Incident management and threat intelligence: response plan, incident log, TI sources', 'SAMA CSF 3.3.15, 3.3.16'],
  ['vulnerability', 'Vulnerability management: scan reports, patching evidence and the last penetration test', 'SAMA CSF 3.3.17'],
  ['thirdparty', 'Third-party and outsourcing: contracts with security clauses, assessments, cloud decisions', 'SAMA CSF 3.4.1 to 3.4.3; IA cyber circular'],
];
const RESULTS = [['verified', 'Verified by the platform'], ['met', 'Recorded as met (approved)'], ['partial', 'Partial'], ['gap', 'Gap'], ['pending', 'Recorded, awaiting the CISO\'s approval'], ['not_measured', 'Not measured (source not connected)'], ['no_evidence', 'Needs a person to record it'], ['not_applicable', 'Not applicable']];
const OPEN = ['pending', 'not_measured', 'no_evidence'];
const SEV = { high: 3, medium: 2, low: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
// the register is one Python call; within one request (cx, from the engine) the review, the gaps and the approver share one read
const reg = (app, cx) => { const S = app.addons && app.addons.samaIa; if (!S) throw httpErr(409, 'the SAMA CSF module is not installed - run the platform update'); const w = { user: 'sama-gap', role: 'admin' }; if (!cx) return S.view(w); return cx.sama || (cx.sama = S.view(w)); };
const items = (v) => (v.requirements || []).concat((v.ia && v.ia.requirements) || []);
const scoreOf = (v) => (v.overall && v.overall.score != null ? v.overall.score : null);

const ADAPTER = {
  fw: 'sama', name: 'SAMA CSF', collection: 'sama_gap', prefix: 'SGA', audit: 'sama.gap.', evidence: EVIDENCE,
  steps: ['Team & scope', 'Kick-off & evidence requests', 'SAMA register baseline', 'Requirement review & CISO approval', 'Gap rating', 'Remediation plan', 'Report & sign-off'],
  approverName: 'CISO', reviewName: 'SAMA CSF requirement review', gid: /^(?:SA-3\.[1-4]\.\d{1,2}-\d{2}|IA-277-\d{2})$/, gidName: 'SAMA requirement (SA-3.n.n-nn or IA-277-nn)',
  reqLabel: 'Subdomain', textLabel: 'Requirement', reportTitle: 'SAMA Cyber Security Framework Gap Assessment',
  disclaimer: 'An internal gap assessment against the SAMA Cyber Security Framework and the Insurance Authority cyber circular. It is not a SAMA or Insurance Authority assessment; the official self-assessment is the one the regulator requires in its own format.',
  note: 'An internal SAMA CSF gap assessment: it measures the gap between the framework (and the Insurance Authority cyber circular) and what the organisation can show. It is not the regulator\'s assessment.',
  approver: async (app, cx) => { if (!(app.addons && app.addons.samaIa)) return null; const v = await reg(app, cx); return (v.profile && v.profile.ciso) || null; },
  async baseline(app) {
    const v = await reg(app), all = items(v), counts = {}; for (const [k] of RESULTS) counts[k] = 0; for (const c of all) counts[c.result] = (counts[c.result] || 0) + 1;
    const off = (v.sources || []).filter((s) => !s.connected).map((s) => s.id), sc = scoreOf(v);
    const table = RESULTS.map(([k, label]) => ({ key: k, label: 'Requirements: ' + label, value: counts[k] || 0, flag: (k === 'gap' || OPEN.includes(k)) && counts[k] > 0, flag_text: String(counts[k] || 0), fix: k === 'gap' || OPEN.includes(k) ? 'sama-ia.html' : null }))
      .concat([{ key: 'target', label: 'Maturity: overall status / target level', value: sc == null ? 0 : sc, text: ((v.overall && v.overall.status) || '—') + ' / target ' + (v.target_level != null ? v.target_level : '—'), flag: false },
        { key: 'ciso', label: 'CISO named', value: v.profile && v.profile.ciso ? 1 : 0, text: (v.profile && v.profile.ciso) || 'not named', flag: !(v.profile && v.profile.ciso), flag_text: 'not named', fix: 'nca-ecc.html' }])
      .concat((v.sources || []).map((s) => ({ key: 'src:' + s.id, label: 'Evidence source: ' + s.id, value: s.connected ? 1 : 0, text: s.connected ? 'connected' : 'not connected', flag: !s.connected, flag_text: 'not connected', fix: null })));
    return { counts, empty: off, score: sc, controls: all.length, table, summary: 'register score ' + (sc == null ? '—' : sc + '%') + ' · ' + all.length + ' requirements · ' + off.length + ' evidence source(s) not connected' };
  },
  // the SAMA register is always there: the review is the register itself, seen from this engagement
  async startReview(app) { await reg(app); return 'SAMA-REGISTER'; },
  async review(app, e, cx) {
    const v = await reg(app, cx), all = items(v), cnt = {}; for (const c of all) cnt[c.result] = (cnt[c.result] || 0) + 1;
    const open = OPEN.reduce((a, k) => a + (cnt[k] || 0), 0), total = all.length, done = open === 0, sc = scoreOf(v);
    const parts = [cnt.pending ? cnt.pending + ' recorded and awaiting the CISO\'s approval' : '', cnt.no_evidence ? cnt.no_evidence + ' to be recorded by a person (with evidence or a note)' : '', cnt.not_measured ? cnt.not_measured + ' not measured - connect the source or record them by hand' : ''].filter(Boolean);
    return { id: 'SAMA-REGISTER', label: 'SAMA CSF requirements and the IA cyber circular', status: done ? 'approved' : 'open', done, score: sc, progress: { answered: total - open, total },
      chapters: (v.domains || []).map((d) => ({ area: d.id + ' ' + d.name, score: d.score, gaps: (d.counts && d.counts.not) || 0 })), submitted_by: null, approved_by: (v.profile && v.profile.ciso) || null,
      what: (total - open) + ' of ' + total + ' requirements assessed · score ' + (sc == null ? '—' : sc + '%'), block: done ? null : 'on the SAMA CSF page: ' + parts.join('; '),
      link: { href: 'sama-ia.html', text: 'Open the SAMA CSF register to record and approve' } };
  },
  async gaps(app, e, cx) {
    const v = await reg(app, cx);
    return items(v).filter((c) => c.result === 'gap' || c.result === 'partial').map((c) => ({ id: c.id, req: c.subdomain + ' ' + c.subdomain_name, area: c.domain === 'IA' ? 'Insurance Authority' : c.domain,
      ref: c.domain === 'IA' ? 'IA cyber circular' : 'SAMA CSF ' + c.subdomain, text: c.title, answer: c.result, note: c.why || '', weight: SEV[c.severity] || 0 }));
  },
  // the ML inputs: the register's own chance-of-gap model per requirement (p_gap over its run history, regression, flapping), the severity,
  // and the cause - the register's reason, so gaps with one missing record or evidence source cluster together
  async features(app, e, cx) { const v = await reg(app, cx), out = {};
    for (const c of items(v)) { const h = c.history || {}; out[c.id] = { severity: c.severity, p_gap: typeof h.p_gap === 'number' ? h.p_gap : null, runs: h.runs || 0, regression: !!h.regression, flapping: !!h.flapping, cause: c.why || null, pillar: c.pillar_name || c.pillar }; }
    return out; },
  action: (e, g) => ({ source: 'sama', ref: 'sama:' + g.id, framework: 'SAMA CSF', title: 'SAMA ' + g.id + ': ' + String(g.text).slice(0, 150) }),
};

const createSamaGap = (app, opts = {}) => createGapEngagement(app, ADAPTER, opts);
function registerSamaGap(srv, app, G0) {
  const G = G0 && G0.list ? G0 : createSamaGap(app, G0 || {});
  app.addons = app.addons || {}; app.addons.samaGap = G;
  return registerGapRoutes(srv, app, G, '/sama-ia/gap');
}
module.exports = { createSamaGap, registerSamaGap, EVIDENCE, ADAPTER };
