// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * SOC 2 and ISO/IEC 42001 readiness ({P} = /api/itam, Compliance -> SOC 2 & ISO 42001). Two voluntary frameworks a vendor or a
 * regulated company may choose: SOC 2 (AICPA Trust Services Criteria - an ATTESTATION issued by a licensed CPA firm) and ISO/IEC
 * 42001:2023 (AI management system - a CERTIFICATE issued by an accredited body). This module measures READINESS; it issues
 * neither, and the page says so. Item titles are this platform's own short wording - the standards' texts are copyrighted and
 * are not reproduced.
 *
 * STATUS of an item, in order:
 *   1. a confirmation approved by a second person within 12 months (level + evidence) - a person's judgement wins
 *   2. otherwise DERIVED from the NCA ECC register controls the item maps to (engine/nca-ecc.js, the crosswalk hub): every mapped
 *      control fully met -> fully; any not met -> not; otherwise partially; none assessed -> not assessed. The derivation names the
 *      controls it used.
 *   3. an item with no mapping and no approved confirmation is NOT ASSESSED - never compliant.
 * SOC 2 scope: Security (the common criteria) is always in scope; Availability, Confidentiality, Processing Integrity and Privacy
 * are chosen by an administrator. Out-of-scope items are "not applicable" and leave the score.
 * Confirmation is four-eyes: an operator submits {level, evidence, note}; an administrator who did not submit it approves or
 * rejects (a reason is required to reject); never a service or AI identity. Everything is audited. Both frameworks feed the
 * Framework Crosswalk and the Gap Analysis (engine/crosswalk.js) through view().
 *
 *   GET  /frameworks-x                                  viewer    both frameworks: items, levels, counts, % fully, scope
 *   POST /frameworks-x/settings {soc2_scope[]}          admin                                                        audited
 *   POST /frameworks-x/:fw/items/:id/confirm {level, evidence?, note?}   operator  -> pending                        audited
 *   POST /frameworks-x/:fw/items/:id/decide {decision, note?}            admin, not the submitter                     audited
 *   GET  /frameworks-x/:fw/export                       operator  readiness sheet (CSV)                              audited
 */
const DAY = 86400000, YEAR = 365 * DAY;
const LEVELS = ['fully', 'partially', 'not', 'na'];
const SOC2_CATS = ['security', 'availability', 'confidentiality', 'processing_integrity', 'privacy'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

// [id, title, group, category, severity, ecc[]]
const SOC2 = [
  ['CC1.1', 'Commitment to integrity and ethical values', 'CC1 Control environment', 'security', 'medium', ['ZS-1-9-01']],
  ['CC1.2', 'Board oversight of internal control', 'CC1 Control environment', 'security', 'medium', ['ZS-1-2-02']],
  ['CC1.3', 'Structures, reporting lines and authorities', 'CC1 Control environment', 'security', 'medium', ['ZS-1-2-01', 'ZS-1-4-01']],
  ['CC1.4', 'Competent people attracted, developed and retained', 'CC1 Control environment', 'security', 'medium', ['ZS-1-10-01', 'ZS-1-10-02']],
  ['CC1.5', 'People held accountable for their control responsibilities', 'CC1 Control environment', 'security', 'medium', ['ZS-1-4-01', 'ZS-1-3-02']],
  ['CC2.1', 'Relevant, quality information supports internal control', 'CC2 Communication & information', 'security', 'medium', ['ZS-2-12-01']],
  ['CC2.2', 'Objectives and responsibilities communicated internally', 'CC2 Communication & information', 'security', 'medium', ['ZS-1-3-01', 'ZS-1-10-01']],
  ['CC2.3', 'Communication with external parties', 'CC2 Communication & information', 'security', 'medium', ['ZS-4-1-02', 'ZS-2-13-01']],
  ['CC3.1', 'Objectives specified so risks can be identified', 'CC3 Risk assessment', 'security', 'medium', ['ZS-1-1-01']],
  ['CC3.2', 'Risks identified and analysed', 'CC3 Risk assessment', 'security', 'high', ['ZS-1-5-01']],
  ['CC3.3', 'Fraud risk considered', 'CC3 Risk assessment', 'security', 'medium', ['ZS-1-5-01']],
  ['CC3.4', 'Significant changes identified and assessed', 'CC3 Risk assessment', 'security', 'medium', ['ZS-1-6-01']],
  ['CC4.1', 'Ongoing and separate evaluations of controls', 'CC4 Monitoring activities', 'security', 'medium', ['ZS-1-8-01']],
  ['CC4.2', 'Deficiencies communicated and corrected in time', 'CC4 Monitoring activities', 'security', 'medium', ['ZS-1-5-02']],
  ['CC5.1', 'Control activities chosen to mitigate risks', 'CC5 Control activities', 'security', 'medium', ['ZS-1-5-02']],
  ['CC5.2', 'General controls over technology', 'CC5 Control activities', 'security', 'high', ['ZS-2-3-01', 'ZS-2-2-01']],
  ['CC5.3', 'Controls deployed through policies and procedures', 'CC5 Control activities', 'security', 'medium', ['ZS-1-3-01']],
  ['CC6.1', 'Logical access security over protected assets', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-2-01', 'ZS-2-1-01']],
  ['CC6.2', 'Users registered and authorised before access', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-2-03']],
  ['CC6.3', 'Access granted, changed and removed by role', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-2-02']],
  ['CC6.4', 'Physical access to facilities restricted', 'CC6 Logical & physical access', 'security', 'medium', ['ZS-2-14-01']],
  ['CC6.5', 'Data and assets disposed of securely', 'CC6 Logical & physical access', 'security', 'medium', ['ZS-2-7-01']],
  ['CC6.6', 'Protection against threats from outside the boundary', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-5-01', 'ZS-2-15-01']],
  ['CC6.7', 'Information protected in transmission and movement', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-8-01', 'ZS-2-7-03']],
  ['CC6.8', 'Malicious software prevented and detected', 'CC6 Logical & physical access', 'security', 'high', ['ZS-2-3-03']],
  ['CC7.1', 'Configuration changes and new vulnerabilities detected', 'CC7 System operations', 'security', 'high', ['ZS-2-10-01', 'ZS-2-3-01']],
  ['CC7.2', 'Systems monitored for anomalies and security events', 'CC7 System operations', 'security', 'high', ['ZS-2-12-02', 'ZS-2-12-01']],
  ['CC7.3', 'Security events evaluated to decide on incidents', 'CC7 System operations', 'security', 'high', ['ZS-2-12-02']],
  ['CC7.4', 'Incidents responded to under a plan', 'CC7 System operations', 'security', 'high', ['ZS-2-13-01']],
  ['CC7.5', 'Recovery from incidents', 'CC7 System operations', 'security', 'high', ['ZS-3-1-01']],
  ['CC8.1', 'Changes authorised, tested, approved and implemented', 'CC8 Change management', 'security', 'high', ['ZS-1-6-01', 'ZS-1-6-02']],
  ['CC9.1', 'Business disruption risk mitigated', 'CC9 Risk mitigation', 'security', 'medium', ['ZS-3-1-01', 'ZS-3-1-02']],
  ['CC9.2', 'Vendor and business partner risk managed', 'CC9 Risk mitigation', 'security', 'medium', ['ZS-4-1-01', 'ZS-4-1-02']],
  ['A1.1', 'Capacity managed to meet commitments', 'A1 Availability', 'availability', 'medium', []],
  ['A1.2', 'Environmental protection, backup and recovery infrastructure', 'A1 Availability', 'availability', 'high', ['ZS-2-9-01']],
  ['A1.3', 'Recovery plans tested', 'A1 Availability', 'availability', 'high', ['ZS-2-9-02', 'ZS-3-1-01']],
  ['C1.1', 'Confidential information identified and protected', 'C1 Confidentiality', 'confidentiality', 'high', ['ZS-2-7-01']],
  ['C1.2', 'Confidential information disposed of', 'C1 Confidentiality', 'confidentiality', 'medium', ['ZS-2-7-01']],
  ['PI1.1', 'Processing objectives and specifications defined', 'PI1 Processing integrity', 'processing_integrity', 'medium', []],
  ['PI1.2', 'Inputs complete and accurate', 'PI1 Processing integrity', 'processing_integrity', 'medium', []],
  ['PI1.3', 'Processing complete, accurate and timely', 'PI1 Processing integrity', 'processing_integrity', 'medium', []],
  ['PI1.4', 'Outputs complete, accurate and delivered as intended', 'PI1 Processing integrity', 'processing_integrity', 'medium', []],
  ['PI1.5', 'Stored data complete and accurate', 'PI1 Processing integrity', 'processing_integrity', 'medium', []],
  ['P1.1', 'Notice of privacy practices', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P2.1', 'Choice and consent', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P3.1', 'Collection limited to stated objectives', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P3.2', 'Explicit consent where required', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P4.1', 'Use limited to stated objectives', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P4.2', 'Personal information retained only as needed', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P4.3', 'Personal information disposed of securely', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P5.1', 'Data subjects can access their information', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P5.2', 'Data subjects can correct their information', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P6.1', 'Disclosure to third parties only as agreed', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02', 'ZS-4-1-02']],
  ['P6.2', 'Record of authorised disclosures', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P6.3', 'Record of unauthorised disclosures (breaches)', 'P Privacy', 'privacy', 'high', ['ZS-2-13-01']],
  ['P6.4', 'Third parties commit to privacy obligations', 'P Privacy', 'privacy', 'medium', ['ZS-4-1-02']],
  ['P6.5', 'Third parties report breaches to the company', 'P Privacy', 'privacy', 'medium', ['ZS-4-1-02']],
  ['P6.6', 'Breaches notified to subjects and regulators', 'P Privacy', 'privacy', 'high', ['ZS-2-13-01', 'ZS-2-7-02']],
  ['P6.7', 'Accounting of disclosures given to subjects', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P7.1', 'Personal information kept accurate and complete', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
  ['P8.1', 'Privacy inquiries, complaints and disputes handled', 'P Privacy', 'privacy', 'medium', ['ZS-2-7-02']],
];
const ISO42001 = [
  ['4.1', 'Context of the organisation and its AI roles', 'Clause 4 Context', '', 'medium', []],
  ['4.2', 'Interested parties and their expectations of AI', 'Clause 4 Context', '', 'medium', []],
  ['4.3', 'Scope of the AI management system', 'Clause 4 Context', '', 'high', []],
  ['4.4', 'AI management system established and maintained', 'Clause 4 Context', '', 'high', []],
  ['5.1', 'Leadership commitment to the AI management system', 'Clause 5 Leadership', '', 'medium', ['ZS-1-2-02']],
  ['5.2', 'AI policy approved', 'Clause 5 Leadership', '', 'high', ['ZS-1-3-01']],
  ['5.3', 'AI roles, responsibilities and authorities', 'Clause 5 Leadership', '', 'medium', ['ZS-1-4-01']],
  ['6.1', 'AI risks and opportunities addressed; AI risk assessment, treatment and impact assessment planned', 'Clause 6 Planning', '', 'high', ['ZS-1-5-01']],
  ['6.2', 'AI objectives and plans to achieve them', 'Clause 6 Planning', '', 'medium', []],
  ['6.3', 'Changes to the AI management system planned', 'Clause 6 Planning', '', 'medium', ['ZS-1-6-01']],
  ['7.1', 'Resources for the AI management system', 'Clause 7 Support', '', 'medium', []],
  ['7.2', 'Competence of people working on AI', 'Clause 7 Support', '', 'medium', ['ZS-1-10-02']],
  ['7.3', 'Awareness of the AI policy and responsibilities', 'Clause 7 Support', '', 'medium', ['ZS-1-10-01']],
  ['7.4', 'Internal and external communication about AI', 'Clause 7 Support', '', 'medium', []],
  ['7.5', 'Documented information controlled', 'Clause 7 Support', '', 'medium', ['ZS-1-3-01']],
  ['8.1', 'Operational planning and control of AI processes', 'Clause 8 Operation', '', 'medium', []],
  ['8.2', 'AI risk assessment performed', 'Clause 8 Operation', '', 'high', ['ZS-1-5-01']],
  ['8.3', 'AI risk treatment implemented', 'Clause 8 Operation', '', 'high', ['ZS-1-5-02']],
  ['8.4', 'AI system impact assessment performed', 'Clause 8 Operation', '', 'high', []],
  ['9.1', 'AI performance monitored and measured', 'Clause 9 Performance evaluation', '', 'medium', []],
  ['9.2', 'Internal audit of the AI management system', 'Clause 9 Performance evaluation', '', 'medium', ['ZS-1-8-01']],
  ['9.3', 'Management review', 'Clause 9 Performance evaluation', '', 'medium', []],
  ['10.1', 'Continual improvement', 'Clause 10 Improvement', '', 'medium', []],
  ['10.2', 'Nonconformity and corrective action', 'Clause 10 Improvement', '', 'medium', ['ZS-1-5-02']],
  ['A.2.2', 'AI policy documented', 'A.2 Policies related to AI', '', 'high', ['ZS-1-3-01']],
  ['A.2.3', 'AI policy aligned with other organisational policies', 'A.2 Policies related to AI', '', 'medium', ['ZS-1-3-01']],
  ['A.2.4', 'AI policy reviewed', 'A.2 Policies related to AI', '', 'medium', ['ZS-1-3-01']],
  ['A.3.2', 'AI roles and responsibilities assigned', 'A.3 Internal organisation', '', 'medium', ['ZS-1-4-01']],
  ['A.3.3', 'Process to report concerns about AI', 'A.3 Internal organisation', '', 'medium', []],
  ['A.4.2', 'Resources for AI systems documented', 'A.4 Resources for AI systems', '', 'medium', []],
  ['A.4.3', 'Data resources documented', 'A.4 Resources for AI systems', '', 'medium', ['ZS-2-7-01']],
  ['A.4.4', 'Tooling resources documented', 'A.4 Resources for AI systems', '', 'low', []],
  ['A.4.5', 'System and computing resources documented', 'A.4 Resources for AI systems', '', 'low', ['ZS-2-1-01']],
  ['A.4.6', 'Human resources and competences documented', 'A.4 Resources for AI systems', '', 'low', ['ZS-1-10-02']],
  ['A.5.2', 'AI system impact assessment process', 'A.5 Assessing impacts of AI systems', '', 'high', []],
  ['A.5.3', 'Impact assessments documented', 'A.5 Assessing impacts of AI systems', '', 'high', []],
  ['A.5.4', 'Impact on individuals and groups assessed', 'A.5 Assessing impacts of AI systems', '', 'high', ['ZS-2-7-02']],
  ['A.5.5', 'Societal impacts assessed', 'A.5 Assessing impacts of AI systems', '', 'medium', []],
  ['A.6.1.2', 'Objectives for responsible AI development', 'A.6 AI system life cycle', '', 'medium', []],
  ['A.6.1.3', 'Processes for responsible AI design and development', 'A.6 AI system life cycle', '', 'high', ['ZS-1-6-02']],
  ['A.6.2.2', 'AI system requirements specified', 'A.6 AI system life cycle', '', 'medium', ['ZS-1-6-01']],
  ['A.6.2.3', 'Design and development documented', 'A.6 AI system life cycle', '', 'medium', ['ZS-1-6-02']],
  ['A.6.2.4', 'AI system verified and validated', 'A.6 AI system life cycle', '', 'high', ['ZS-1-6-01']],
  ['A.6.2.5', 'AI system deployment planned and approved', 'A.6 AI system life cycle', '', 'high', ['ZS-1-6-01']],
  ['A.6.2.6', 'AI system operated and monitored', 'A.6 AI system life cycle', '', 'high', ['ZS-2-12-02']],
  ['A.6.2.7', 'Technical documentation of the AI system', 'A.6 AI system life cycle', '', 'medium', []],
  ['A.6.2.8', 'AI system event logs recorded', 'A.6 AI system life cycle', '', 'high', ['ZS-2-12-01', 'ZS-2-12-03']],
  ['A.7.2', 'Data for development and enhancement managed', 'A.7 Data for AI systems', '', 'medium', ['ZS-2-7-01']],
  ['A.7.3', 'Acquisition of data defined', 'A.7 Data for AI systems', '', 'medium', []],
  ['A.7.4', 'Quality of data for AI', 'A.7 Data for AI systems', '', 'high', []],
  ['A.7.5', 'Data provenance recorded', 'A.7 Data for AI systems', '', 'medium', []],
  ['A.7.6', 'Data preparation defined', 'A.7 Data for AI systems', '', 'medium', []],
  ['A.8.2', 'System documentation and information for users', 'A.8 Information for interested parties', '', 'medium', []],
  ['A.8.3', 'External reporting of adverse impacts', 'A.8 Information for interested parties', '', 'medium', []],
  ['A.8.4', 'Communication of AI incidents', 'A.8 Information for interested parties', '', 'high', ['ZS-2-13-01']],
  ['A.8.5', 'Information shared with interested parties', 'A.8 Information for interested parties', '', 'low', []],
  ['A.9.2', 'Processes for responsible use of AI', 'A.9 Use of AI systems', '', 'high', []],
  ['A.9.3', 'Objectives for responsible use of AI', 'A.9 Use of AI systems', '', 'medium', []],
  ['A.9.4', 'AI used as intended', 'A.9 Use of AI systems', '', 'high', []],
  ['A.10.2', 'Responsibilities allocated between parties', 'A.10 Third-party & customer relationships', '', 'medium', ['ZS-4-1-02']],
  ['A.10.3', 'Suppliers of AI assessed', 'A.10 Third-party & customer relationships', '', 'medium', ['ZS-4-1-01']],
  ['A.10.4', 'Customer expectations of AI addressed', 'A.10 Third-party & customer relationships', '', 'medium', []],
];
const FWS = {
  soc2: { key: 'soc2', name: 'SOC 2 (Trust Services Criteria)', short: 'SOC 2', issuer: 'an attestation report issued by a licensed CPA firm (Type I: design at a point in time; Type II: operating over 3-12 months)', items: SOC2 },
  iso42001: { key: 'iso42001', name: 'ISO/IEC 42001:2023 AI management system', short: 'ISO 42001', issuer: 'a certificate issued by an accredited certification body after a stage 1 and stage 2 audit', items: ISO42001 },
};

function createFrameworksX(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { every() {} };
  const conf = () => store.collection('fx_confirmations'), cfgC = () => store.collection('fx_cfg');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const settings = () => Object.assign({ soc2_scope: ['security'] }, (cfgC().get('settings') || {}).value || {});
  const same = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();

  async function eccLevels() {
    const E = app.addons && app.addons.ncaEcc;
    if (!E || typeof E.view !== 'function') return { ok: false, why: 'NCA ECC is not installed', map: {} };
    try {
      const v = await E.view(); const map = {};
      for (const c of v.controls || []) map[c.id] = levelOf(c);
      return { ok: true, map };
    } catch (e) { if (L.every) L.every('fx:ecc', 600000, 'warn', 'SOC 2 / ISO 42001: NCA ECC could not be read', { err: String(e.message).slice(0, 160) }); return { ok: false, why: 'NCA ECC could not be read', map: {} }; }
  }
  function derive(ecc, E) {
    if (!ecc.length) return { level: 'not_assessed', why: 'no mapped control - confirm it with evidence' };
    if (!E.ok) return { level: 'not_assessed', why: E.why };
    const L2 = ecc.map((id) => [id, E.map[id] || 'not_assessed']), lv = L2.map((x) => x[1]).filter((x) => x !== 'na');
    const named = L2.map((x) => x[0] + ' ' + x[1].replace('_', ' ')).join(', ');
    if (!lv.length) return { level: 'na', why: 'mapped controls are not applicable: ' + named };
    if (lv.every((x) => x === 'not_assessed')) return { level: 'not_assessed', why: 'mapped NCA ECC controls not assessed yet: ' + named };
    if (lv.every((x) => x === 'fully')) return { level: 'fully', why: 'from NCA ECC: ' + named };
    if (lv.some((x) => x === 'not')) return { level: 'not', why: 'from NCA ECC: ' + named };
    return { level: 'partially', why: 'from NCA ECC: ' + named };
  }
  async function build(key) {
    const F = FWS[key]; const E = await eccLevels(), S = settings(), t = now();
    const C = Object.fromEntries(conf().all((c) => c.fw === key).map((c) => [c.item, c]));
    const items = F.items.map(([id, title, group, cat, severity, ecc]) => {
      const c = C[id], fresh = c && c.status === 'approved' && t - Date.parse(c.decided_at) <= YEAR;
      const inScope = key !== 'soc2' || cat === 'security' || S.soc2_scope.includes(cat);
      let level, why, source;
      if (!inScope) { level = 'na'; why = 'category not in the SOC 2 scope'; source = 'scope'; }
      else if (fresh) { level = c.level; why = 'confirmed by ' + c.by + ', approved by ' + c.decided_by + ' on ' + c.decided_at.slice(0, 10) + (c.evidence ? ' - evidence: ' + c.evidence : ''); source = 'confirmed'; }
      else { const d = derive(ecc, E); level = d.level; why = d.why; source = ecc.length ? 'derived' : 'none'; }
      return { id, title, group, category: cat || null, severity, ecc, level, why, source, in_scope: inScope,
        pending: c && c.status === 'pending' ? { level: c.level, by: c.by, at: c.at, evidence: c.evidence, note: c.note } : null,
        expired: !!(c && c.status === 'approved' && !fresh) };
    });
    const live = items.filter((x) => x.level !== 'na'), cnt = { fully: 0, partially: 0, not: 0, not_assessed: 0 };
    for (const x of live) cnt[x.level]++;
    const groups = [...new Set(items.map((x) => x.group))].map((g) => { const I = items.filter((x) => x.group === g && x.level !== 'na'); return { group: g, items: I.length, fully: I.filter((x) => x.level === 'fully').length, gaps: I.filter((x) => x.level === 'not' || x.level === 'partially').length }; });
    return { key, name: F.name, short: F.short, issuer: F.issuer, items, groups, counts: cnt, in_scope: live.length,
      pct_fully: live.length ? Math.round((100 * cnt.fully) / live.length) : null, pct_assessed: live.length ? Math.round((100 * (live.length - cnt.not_assessed)) / live.length) : null,
      pending: items.filter((x) => x.pending).length, ecc: E.ok ? 'connected' : E.why, scope: key === 'soc2' ? S.soc2_scope : null };
  }
  async function viewAll(who) {
    const out = { frameworks: [await build('soc2'), await build('iso42001')], categories: SOC2_CATS, can_admin: who.role === 'admin',
      note: 'Readiness only. SOC 2 is attested by a licensed CPA firm and ISO/IEC 42001 is certified by an accredited body - this platform prepares the evidence, it does not issue either. Item titles are short summaries, not the standards\' text.' };
    if (who.role === 'viewer') for (const f of out.frameworks) for (const x of f.items) { if (x.pending) x.pending = { level: x.pending.level }; x.why = x.source === 'confirmed' ? 'confirmed' : x.why; }
    return out;
  }
  // for the crosswalk / gap analysis
  async function view(key) { const f = await build(key); return { items: f.items.map((x) => ({ id: x.id, title: x.title, group: x.group, severity: x.severity, level: x.level, why: x.why, ecc: x.ecc.slice() })) }; }

  function fwOf(fw) { if (!FWS[fw]) throw httpErr(404, 'no framework "' + String(fw).slice(0, 40) + '" (soc2, iso42001)'); return FWS[fw]; }
  function itemOf(F, id) { const it = F.items.find((x) => x[0] === id); if (!it) throw httpErr(404, 'no item ' + id + ' in ' + F.short); return it; }
  function confirm(fw, id, input, who) {
    const F = fwOf(fw); itemOf(F, id);
    const b = body(input || {}).oneOf('level', LEVELS, { required: true }).str('evidence', { max: 1000 }).str('note', { max: 1000 })
      .rule((o) => (['fully', 'partially'].includes(o.level) && !o.evidence ? 'evidence is required for "' + o.level + '": name the document, record or system that shows it' : null))
      .rule((o) => (o.level === 'na' && !o.note ? 'note is required for "not applicable": say why' : null)).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a person confirms a control, not a service or AI identity');
    const key = fw + ':' + id, prev = conf().get(key);
    const rec = { id: key, fw, item: id, level: b.level, evidence: b.evidence || '', note: b.note || '', by: who.user, at: iso(), status: 'pending',
      history: ((prev && prev.history) || []).concat(prev && prev.status !== 'pending' ? [{ level: prev.level, status: prev.status, by: prev.by, decided_by: prev.decided_by || null, at: prev.decided_at || prev.at }] : []).slice(-10) };
    conf().put(rec); audit(who, 'fx.confirm', key, { level: b.level, evidence: !!b.evidence });
    return { ok: true, id: key, status: 'pending' };
  }
  function decide(fw, id, input, who) {
    const F = fwOf(fw); itemOf(F, id);
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required to reject: say what is missing' : null)).done();
    if (!isHuman(who.user)) throw httpErr(403, 'only a person approves - ' + who.user + ' is a service or AI identity');
    const key = fw + ':' + id, c = conf().get(key);
    if (!c || c.status !== 'pending') throw httpErr(409, 'nothing pending for ' + F.short + ' ' + id);
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' submitted this confirmation and cannot also approve it');
    Object.assign(c, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decision_note: b.note || '' });
    conf().put(c); audit(who, 'fx.' + b.decision, key, { level: c.level, submitted_by: c.by });
    return { ok: true, id: key, status: c.status };
  }
  function setSettings(input, who) {
    const b = body(input || {}).list('soc2_scope', { item: SOC2_CATS, unique: true, max: 5, required: true }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a person sets the scope');
    const scope = [...new Set(['security'].concat(b.soc2_scope))];
    cfgC().put({ id: 'settings', value: { soc2_scope: scope }, by: who.user, at: iso() });
    audit(who, 'fx.settings', 'soc2_scope', { scope }); return { ok: true, soc2_scope: scope };
  }
  async function exportCsv(fw, who) {
    fwOf(fw); const f = await build(fw);
    const q = (x) => { let v = String(x == null ? '' : x); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
    const rows = [['Framework', 'Item', 'Title', 'Group', 'Severity', 'In scope', 'Status', 'Source', 'Basis', 'Mapped NCA ECC', 'Pending']].concat(
      f.items.map((x) => [f.short, x.id, x.title, x.group, x.severity, x.in_scope ? 'yes' : 'no', x.level.replace('_', ' '), x.source, x.why, x.ecc.join(' '), x.pending ? x.pending.level + ' by ' + x.pending.by : '']));
    audit(who, 'fx.export', fw, { items: f.items.length });
    return { filename: f.short.replace(/\W+/g, '-') + '-readiness-' + iso().slice(0, 10) + '.csv', csv: rows.map((r) => r.map(q).join(',')).join('\r\n') };
  }
  return { viewAll, view, confirm, decide, setSettings, exportCsv, FWS };
}
// one level for every engine's result vocabulary; anything unknown is "not assessed" (same rule as the crosswalk)
function levelOf(x) {
  const l = String(x.level || x.nca_level || '').toLowerCase();
  if (['fully', 'partially', 'not', 'not_assessed'].includes(l)) return l;
  if (l === 'not_applicable' || l === 'na') return 'na';
  const r = String(x.result || x.status || '').toLowerCase();
  if (['verified', 'confirmed', 'compliant', 'met', 'ok', 'pass', 'fully', 'fully_compliant'].includes(r)) return 'fully';
  if (['partial', 'partially', 'partially_compliant'].includes(r)) return 'partially';
  if (['gap', 'fail', 'failed', 'not', 'not_compliant', 'non_compliant'].includes(r)) return 'not';
  if (['na', 'not_applicable', 'n/a'].includes(r)) return 'na';
  return 'not_assessed';
}

function registerFrameworksX(srv, app, X) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const FW = (ctx) => param(ctx.params.fw, 'fw'), ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/frameworks-x', (ctx) => { ctx.need('viewer'); return X.viewAll(W(ctx)); });
  srv.route('POST', '/frameworks-x/settings', (ctx) => { ctx.need('admin'); return X.setSettings(ctx.body, W(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/frameworks-x/:fw/items/:id/confirm', (ctx) => { ctx.need('operator'); return X.confirm(FW(ctx), ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/frameworks-x/:fw/items/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(FW(ctx), ID(ctx), ctx.body, W(ctx)); }, { maxBody: 2048 });
  srv.route('GET', '/frameworks-x/:fw/export', (ctx) => { ctx.need('operator'); return X.exportCsv(FW(ctx), W(ctx)); });
}

module.exports = { createFrameworksX, registerFrameworksX, SOC2, ISO42001, levelOf };
