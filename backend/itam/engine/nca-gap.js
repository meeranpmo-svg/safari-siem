// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { createGapEngagement, registerGapRoutes } = require('./gap-engagement');
/*
 * NCA ECC Gap Assessment (NCA ECC -> Start an NCA ECC Gap Assessment, {P} = /api/itam/nca-ecc/gap). The seven steps and their rules
 * are in engine/gap-engagement.js; this adapter says what is NCA ECC-1:2018 about them:
 *   evidence   16 standard items across the five domains (governance, defence, resilience, third-party & cloud, ICS), each with
 *              the ECC subdomain it proves
 *   baseline   the ECC register as it stands: which evidence sources are connected (a source that is not connected leaves its
 *              controls "not measured" - a finding, never a pass), the result counts and the score
 *   review     the NCA ECC control register (engine/nca-ecc.js): every control is either verified by the platform's own evidence
 *              or recorded by a person with evidence / a note and approved by the CISO named in the ECC profile (four eyes).
 *              The review is complete when no control is pending approval, not measured or without evidence
 *   gaps       every control whose result is gap or partial
 *   GRC        the action "Send gaps to GRC" creates (source nca, ref ecc:<control>) - created here when missing - carries the
 *              plan's owner and date
 *   approver   the CISO named in the ECC profile
 * Routes as engine/pdpl-gap.js, under /nca-ecc/gap; every write audited as nca.gap.*.
 */
const EVIDENCE = [
  ['strategy', 'Approved cybersecurity strategy and roadmap', 'ECC 1-1'],
  ['function', 'Cybersecurity function: organisation chart, roles, reporting line to the head of the organisation', 'ECC 1-2, 1-4'],
  ['policies', 'Approved cybersecurity policies and procedures, with review dates', 'ECC 1-3'],
  ['risk', 'Cybersecurity risk methodology and the risk register', 'ECC 1-5'],
  ['projects', 'Cybersecurity in IT projects and change management (security requirements, testing before go-live)', 'ECC 1-6'],
  ['compliance', 'Compliance with laws and regulations: the obligations list and the last compliance review', 'ECC 1-7, 1-8'],
  ['hr', 'Cybersecurity in HR: screening, NDAs, joiners / movers / leavers', 'ECC 1-9'],
  ['awareness', 'Awareness and training programme with attendance records', 'ECC 1-10'],
  ['assets', 'Asset inventory with owners and classification', 'ECC 2-1'],
  ['iam', 'Identity and access management: access reviews, privileged accounts, MFA', 'ECC 2-2'],
  ['protection', 'System and network protection: hardening, patching, malware protection, email and web security', 'ECC 2-3 to 2-5'],
  ['crypto_data', 'Data protection and cryptography: classification, encryption standards, key management', 'ECC 2-6 to 2-8'],
  ['logging', 'Event logs and monitoring: SIEM sources, retention, the SOC procedure', 'ECC 2-12'],
  ['incident', 'Incident and threat management: the response plan, the incident log, threat intelligence', 'ECC 2-13'],
  ['vuln_test', 'Vulnerability management and penetration testing: scan reports and the last pen-test report', 'ECC 2-10, 2-11'],
  ['resilience', 'Business continuity and disaster recovery for cybersecurity: plans and the last test results', 'ECC 3-1'],
  ['thirdparty', 'Third-party and cloud: contracts with cybersecurity clauses, vendor assessments, cloud hosting decisions', 'ECC 4-1, 4-2'],
];
const RESULTS = [['verified', 'Verified by the platform'], ['met', 'Recorded as met (approved)'], ['partial', 'Partial'], ['gap', 'Gap'], ['pending', 'Recorded, awaiting CISO approval'], ['not_measured', 'Not measured (source not connected)'], ['no_evidence', 'Needs a person to record it'], ['not_applicable', 'Not applicable']];
const OPEN = ['pending', 'not_measured', 'no_evidence'];
const SEV = { high: 3, medium: 2, low: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const EC0 = (app) => { const N = app.addons && app.addons.ncaEcc; if (!N) throw httpErr(409, 'the NCA ECC module is not installed - run the platform update'); return N; };
// the register is one Python call; within one request (cx, from the engine) the review, the gaps and the approver share one read
const reg = (app, cx) => { const N = EC0(app); if (!cx) return N.view(); return cx.ecc || (cx.ecc = N.view()); };

const ADAPTER = {
  fw: 'nca', name: 'NCA ECC', collection: 'nca_gap', prefix: 'NGA', audit: 'nca.gap.', evidence: EVIDENCE,
  steps: ['Team & scope', 'Kick-off & evidence requests', 'Control register baseline', 'Control review & CISO approval', 'Gap rating', 'Remediation plan', 'Report & sign-off'],
  approverName: 'CISO', reviewName: 'NCA ECC control review', gid: /^ZS-[1-5]-\d{1,2}-\d{2}$/, gidName: 'register control (ZS-n-n-nn)', reqLabel: 'Subdomain', textLabel: 'Control',
  reportTitle: 'NCA ECC Gap Assessment',
  disclaimer: 'An internal gap assessment against the NCA Essential Cybersecurity Controls (ECC-1:2018). It is not an NCA certificate or an NCA assessment; the official compliance assessment is the one the NCA requires through its own portal and tools.',
  note: 'An internal NCA ECC gap assessment: it measures the gap between the Essential Cybersecurity Controls and what the organisation can show. It is not an NCA certificate.',
  approver: async (app, cx) => { if (!(app.addons && app.addons.ncaEcc)) return null; const v = await reg(app, cx); return (v.profile && v.profile.ciso_user) || null; },
  async baseline(app) {
    const v = await reg(app), counts = {}; for (const [k] of RESULTS) counts[k] = 0; for (const c of v.controls) counts[c.result] = (counts[c.result] || 0) + 1;
    const off = (v.sources || []).filter((s) => !s.connected).map((s) => s.id);
    const table = RESULTS.map(([k, label]) => ({ key: k, label: 'Controls: ' + label, value: counts[k] || 0, flag: (k === 'gap' || OPEN.includes(k)) && counts[k] > 0, flag_text: String(counts[k] || 0), fix: k === 'gap' || OPEN.includes(k) ? 'nca-ecc.html' : null }))
      .concat((v.sources || []).map((s) => ({ key: 'src:' + s.id, label: 'Evidence source: ' + s.id, value: s.connected ? 1 : 0, text: s.connected ? 'connected' : 'not connected', flag: !s.connected, flag_text: 'not connected', fix: null })));
    return { counts, empty: off, score: v.score == null ? null : v.score, controls: v.controls.length, table, summary: 'register score ' + (v.score == null ? '—' : v.score + '%') + ' · ' + v.controls.length + ' controls · ' + off.length + ' evidence source(s) not connected' };
  },
  // the ECC register is always there: the review is the register itself, seen from this engagement
  async startReview(app) { await reg(app); return 'ECC-REGISTER'; },
  async review(app, e, cx) {
    const v = await reg(app, cx), cnt = {}; for (const c of v.controls) cnt[c.result] = (cnt[c.result] || 0) + 1;
    const open = OPEN.reduce((a, k) => a + (cnt[k] || 0), 0), total = v.controls.length, done = open === 0;
    const parts = [cnt.pending ? cnt.pending + ' recorded and awaiting the CISO\'s approval' : '', cnt.no_evidence ? cnt.no_evidence + ' to be recorded by a person (with evidence or a note)' : '', cnt.not_measured ? cnt.not_measured + ' not measured - connect the source or record them by hand' : ''].filter(Boolean);
    return { id: 'ECC-REGISTER', label: 'NCA ECC-1:2018 control register', status: done ? 'approved' : 'open', done, score: v.score, progress: { answered: total - open, total },
      chapters: (v.domains || []).map((d) => ({ area: d.name, score: d.score, gaps: (d.counts && d.counts.gap) || 0 })), submitted_by: null, approved_by: (v.profile && v.profile.ciso_user) || null,
      what: (total - open) + ' of ' + total + ' controls assessed · score ' + (v.score == null ? '—' : v.score + '%'), block: done ? null : 'on the NCA ECC page: ' + parts.join('; '),
      link: { href: 'nca-ecc.html', text: 'Open the NCA ECC register to record and approve controls' } };
  },
  async gaps(app, e, cx) {
    const v = await reg(app, cx);
    return v.controls.filter((c) => c.result === 'gap' || c.result === 'partial').map((c) => ({ id: c.id, req: c.subdomain + ' ' + c.subdomain_name, area: c.domain_name, ref: (c.official && c.official.length ? c.official.join(', ') : 'ECC ' + c.subdomain),
      text: c.title, answer: c.result, note: c.why || '', weight: SEV[c.severity] || 0 }));
  },
  // ML inputs: severity and the register's reason (gaps with one missing record or source cluster together)
  async features(app, e, cx) { const v = await reg(app, cx), out = {}; for (const c of v.controls) out[c.id] = { severity: c.severity, cause: c.why || null }; return out; },
  action: (e, g) => ({ source: 'nca', ref: 'ecc:' + g.id, framework: 'NCA ECC', title: 'NCA ECC ' + g.req.split(' ')[0] + ' ' + g.id + ': ' + String(g.text).slice(0, 150) }),
};

const createNcaGap = (app, opts = {}) => createGapEngagement(app, ADAPTER, opts);
function registerNcaGap(srv, app, G0) {
  const G = G0 && G0.list ? G0 : createNcaGap(app, G0 || {});
  app.addons = app.addons || {}; app.addons.ncaGap = G;
  return registerGapRoutes(srv, app, G, '/nca-ecc/gap');
}
module.exports = { createNcaGap, registerNcaGap, EVIDENCE, ADAPTER };
