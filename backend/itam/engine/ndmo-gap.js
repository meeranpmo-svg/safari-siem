// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { createGapEngagement, registerGapRoutes } = require('./gap-engagement');
/*
 * NDMO Gap Assessment (NDMO -> Start an NDMO Gap Assessment, {P} = /api/itam/ndmo/gap). The seven steps and their rules are in
 * engine/gap-engagement.js; this adapter says what is NDMO (Data Management and Personal Data Protection Standards) about them:
 *   evidence   one standard item per NDMO domain (15) plus the data management strategy, each with its domain
 *   baseline   the NDMO register as it stands (engine/ndmo.js): result counts, maturity per domain (0-5), the Chief Data Officer
 *              and how many official NDMO controls are mapped
 *   review     the NDMO register: every control is passed by the platform's own evidence, or recorded by a person and approved by
 *              the Chief Data Officer (four eyes). Complete when nothing is pending or without evidence
 *   gaps       every control whose result is gap or partial
 *   GRC        the action "Send gaps to GRC" creates (source ndmo, ref ndmo:<id>) - created here when missing - carries the plan's
 *              owner and date
 *   approver   the Chief Data Officer named in the NDMO profile
 * Routes as engine/pdpl-gap.js, under /ndmo/gap; every write audited as ndmo.gap.*.
 */
const EVIDENCE = [
  ['strategy', 'Data management strategy, the Chief Data Officer appointment and the data management office charter', 'DG - Data Governance'],
  ['governance', 'Data governance policies, the data management committee and its minutes, data owners and stewards', 'DG - Data Governance'],
  ['catalog', 'Data catalogue and business glossary with metadata for the key data assets', 'MCM - Data Catalog and Metadata'],
  ['quality', 'Data quality rules, measurements and the issue log', 'DQ - Data Quality'],
  ['operations', 'Database operations: backups, restore tests, storage and performance management', 'DO - Data Operations'],
  ['documents', 'Document and content management: records lifecycle, retention and archiving', 'DCM - Document and Content Management'],
  ['architecture', 'Data architecture and models for the core systems', 'DAM - Data Architecture and Modelling'],
  ['sharing', 'Data sharing agreements and the interoperability / integration inventory', 'DSI - Data Sharing and Interoperability'],
  ['master', 'Reference and master data: owners, golden sources and change control', 'RMD - Reference and Master Data'],
  ['bi', 'Business intelligence and analytics: report inventory and data lineage', 'BIA - Business Intelligence and Analytics'],
  ['value', 'Data value realisation: data use cases and their benefits', 'DVR - Data Value Realization'],
  ['open', 'Open data: the decision on publishable data sets (or why the domain does not apply)', 'OD - Open Data'],
  ['foi', 'Freedom of information: the request procedure and log (or why the domain does not apply)', 'FOI - Freedom of Information'],
  ['classification', 'Data classification policy and the classified data inventory', 'DC - Data Classification'],
  ['personal', 'Personal data protection: the PDPL programme records (RoPA, consent, DSAR, breach handling)', 'PDP - Personal Data Protection'],
  ['security', 'Data security and protection: access control, encryption and monitoring of data stores', 'DSP - Data Security and Protection'],
];
const RESULTS = [['auto_pass', 'Passed on the platform\'s evidence'], ['met', 'Recorded as met (approved)'], ['partial', 'Partial'], ['gap', 'Gap'], ['pending', 'Recorded, awaiting the CDO\'s approval'], ['no_evidence', 'Needs a person to record it'], ['not_applicable', 'Not applicable']];
const OPEN = ['pending', 'no_evidence', 'not_measured'];
const SEV = { high: 3, medium: 2, low: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
// the register is one Python call; within one request (cx, from the engine) the review, the gaps and the approver share one read
const reg = (app, cx) => { const N = app.addons && app.addons.ndmo; if (!N) throw httpErr(409, 'the NDMO module is not installed - run the platform update'); if (!cx) return N.view(); return cx.ndmo || (cx.ndmo = N.view()); };

const ADAPTER = {
  fw: 'ndmo', name: 'NDMO', collection: 'ndmo_gap', prefix: 'DGA', audit: 'ndmo.gap.', evidence: EVIDENCE,
  steps: ['Team & scope', 'Kick-off & evidence requests', 'NDMO register baseline', 'Control review & CDO approval', 'Gap rating', 'Remediation plan', 'Report & sign-off'],
  approverName: 'Chief Data Officer', reviewName: 'NDMO control review', gid: /^ZS-[A-Z]{2,3}-\d{2}$/, gidName: 'NDMO register control (ZS-XX-nn)',
  reqLabel: 'Domain', textLabel: 'Control', reportTitle: 'NDMO Data Management Gap Assessment',
  disclaimer: 'An internal gap assessment against the NDMO Data Management and Personal Data Protection Standards. It is not an NDMO / SDAIA assessment; the official compliance assessment is the one the regulator requires in its own format.',
  note: 'An internal NDMO gap assessment: it measures the gap between the NDMO Data Management and Personal Data Protection Standards and what the organisation can show. It is not the regulator\'s assessment.',
  approver: async (app, cx) => { if (!(app.addons && app.addons.ndmo)) return null; const v = await reg(app, cx); return (v.profile && v.profile.cdo_user) || null; },
  async baseline(app) {
    const v = await reg(app), all = v.controls || [], counts = {}; for (const [k] of RESULTS) counts[k] = 0; for (const c of all) counts[c.result] = (counts[c.result] || 0) + 1;
    const cov = v.coverage || {}, cdo = v.profile && v.profile.cdo_user;
    const table = RESULTS.map(([k, label]) => ({ key: k, label: 'Controls: ' + label, value: counts[k] || 0, flag: (k === 'gap' || OPEN.includes(k)) && counts[k] > 0, flag_text: String(counts[k] || 0), fix: k === 'gap' || OPEN.includes(k) ? 'ndmo.html' : null }))
      .concat((v.maturity || []).map((d) => ({ key: 'dom:' + d.domain, label: 'Maturity: ' + d.name, value: d.level == null ? 0 : d.level, text: d.level == null ? 'not applicable' : 'level ' + d.level + ' - ' + d.level_name + (d.score != null ? ' (' + d.score + '%)' : ''), flag: d.level === 0, flag_text: 'level 0 - ' + (d.level_name || 'absence'), fix: d.level === 0 ? 'ndmo.html' : null })))
      .concat([{ key: 'cdo', label: 'Chief Data Officer named', value: cdo ? 1 : 0, text: cdo || 'not named', flag: !cdo, flag_text: 'not named', fix: 'ndmo.html' },
        { key: 'official', label: 'Official NDMO controls imported / mapped', value: cov.total || 0, text: (cov.total || 0) + ' imported, ' + (cov.mapped || 0) + ' mapped', flag: !cov.total, flag_text: 'not imported', fix: 'ndmo.html' }]);
    return { counts, empty: (v.maturity || []).filter((d) => d.level === 0).map((d) => d.domain), score: v.score == null ? null : v.score, controls: all.length, table,
      summary: 'register score ' + (v.score == null ? '—' : v.score + '%') + ' · ' + all.length + ' controls in ' + (v.maturity || []).length + ' domains' };
  },
  // the NDMO register is always there: the review is the register itself, seen from this engagement
  async startReview(app) { await reg(app); return 'NDMO-REGISTER'; },
  async review(app, e, cx) {
    const v = await reg(app, cx), all = v.controls || [], cnt = {}; for (const c of all) cnt[c.result] = (cnt[c.result] || 0) + 1;
    const open = OPEN.reduce((a, k) => a + (cnt[k] || 0), 0), total = all.length, done = open === 0;
    const parts = [cnt.pending ? cnt.pending + ' recorded and awaiting the Chief Data Officer\'s approval' : '', cnt.no_evidence ? cnt.no_evidence + ' to be recorded by a person (with evidence or a note)' : '', cnt.not_measured ? cnt.not_measured + ' not measured' : ''].filter(Boolean);
    return { id: 'NDMO-REGISTER', label: 'NDMO Data Management and Personal Data Protection Standards', status: done ? 'approved' : 'open', done, score: v.score, progress: { answered: total - open, total },
      chapters: (v.maturity || []).map((d) => ({ area: d.name + (d.level != null ? ' (level ' + d.level + ')' : ''), score: d.score, gaps: d.gaps || 0 })), submitted_by: null, approved_by: (v.profile && v.profile.cdo_user) || null,
      what: (total - open) + ' of ' + total + ' controls assessed · score ' + (v.score == null ? '—' : v.score + '%'), block: done ? null : 'on the NDMO page: ' + parts.join('; '),
      link: { href: 'ndmo.html', text: 'Open the NDMO register to record and approve controls' } };
  },
  async gaps(app, e, cx) {
    const v = await reg(app, cx);
    return (v.controls || []).filter((c) => c.result === 'gap' || c.result === 'partial').map((c) => ({ id: c.id, req: c.domain + ' ' + c.domain_name, area: c.domain_name, ref: c.official && c.official.length ? 'NDMO ' + c.official.join(', ') : 'NDMO ' + c.domain,
      text: c.title, answer: c.result, note: c.why || '', weight: SEV[c.severity] || 0 }));
  },
  // ML inputs: severity and the register's reason (gaps with one missing record or source cluster together)
  async features(app, e, cx) { const v = await reg(app, cx), out = {}; for (const c of (v.controls || [])) out[c.id] = { severity: c.severity, cause: c.why || null }; return out; },
  action: (e, g) => ({ source: 'ndmo', ref: 'ndmo:' + g.id, framework: 'NDMO', title: 'NDMO ' + g.id + ' (' + g.area + '): ' + String(g.text).slice(0, 150) }),
};

const createNdmoGap = (app, opts = {}) => createGapEngagement(app, ADAPTER, opts);
function registerNdmoGap(srv, app, G0) {
  const G = G0 && G0.list ? G0 : createNdmoGap(app, G0 || {});
  app.addons = app.addons || {}; app.addons.ndmoGap = G;
  return registerGapRoutes(srv, app, G, '/ndmo/gap');
}
module.exports = { createNdmoGap, registerNdmoGap, EVIDENCE, ADAPTER };
