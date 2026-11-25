// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Department framework checklist: what each department of the company must keep doing, period after period, to stay on the
 * frameworks (SAMA CSF, NCA ECC, PDPL, NDMO, the Insurance Authority view) - and whether it is. The audit checklist
 * (audit-checklist.js) asks "is the control in place?" once a year; this asks each department "did you do it this month /
 * quarter / half / year?", and has the auditor check the answer.
 *
 * ONE catalogue of obligations, each owned by a department, with a frequency, the framework references it serves and the
 * evidence expected. An admin names each department's head (and optionally a deputy). Every period:
 *   - the head (or deputy) ATTESTS each obligation: done (with the evidence reference - the evidence stays in the document
 *     store, never in this platform: PDPL), partly done, not done, or not applicable (with a note saying why);
 *   - an auditor REVIEWS the attestation: verified, or exception with a note. Four-eyes: never the person who attested, never
 *     the department's own head or deputy (independence), never a service / AI identity.
 * Each obligation reads in the shared compliance language (compliance-levels.js):
 *   fully      done and verified by the auditor
 *   partially  partly done (attested or verified)
 *   not        not done, an exception raised by the auditor, or OVERDUE (the last period ended, the grace days passed and
 *              nothing was attested)
 *   not assessed  no head named, attested done but not yet verified, or the first period still open
 * Tracking starts when the department's head is named: a period that ended before that is not owed. A period's attestation
 * may be given until GRACE_DAYS after it ends; later it is still accepted and marked late. Periods are in Riyadh time.
 * The framework mapping is domain-level: a draft for the compliance team to verify against the framework texts.
 *
 *   GET  /dept-checklist?dept=&fw=     viewer   statuses, % per department / framework (evidence, notes, names: operators - PDPL)
 *   GET  /dept-checklist/owners        viewer   departments and whether a head is named (names for operators)
 *   POST /dept-checklist/owners        admin    {dept, head, deputy?}                                              audited
 *   POST /dept-checklist/attest        operator {id, period?, status: done|partly|not_done|not_applicable, evidence?, note?}  audited
 *   POST /dept-checklist/review        operator {id, period, decision: verified|exception, note?}                  audited
 *   GET  /dept-checklist/export        operator the checklist as CSV                                               audited
 */
const CL = require('./compliance-levels');
const DAY = 86400000, GRACE_DAYS = 15, RIYADH = 3 * 3600000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || '').trim());
const USER = { max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._@\\-]{1,79}$/ };
const U = (k, required) => Object.assign({ required: !!required, msg: k + ': a user name (letters, digits, space . _ - @ \\)' }, USER);

// the organisation's sector (brand setting): an insurer's business departments, or an operations & maintenance group's
const INSURER = /^(insurer|insurance)$/i.test(String(require('./brand').sector || ''));
const DEPTS = [
  ['hr', 'Human Resources'], ['infra', 'IT Infrastructure'], ['apps', 'IT Applications'], ['cyber', 'Cyber Security'],
  ['grc', 'Governance, Risk & Compliance'], ['dpo', 'Data Protection Office'], ['data', 'Data Management Office'], ['legal', 'Legal'],
  ['procurement', 'Procurement'], ['admin', 'Administration & Facilities'], ['finance', 'Finance'],
].concat(INSURER ? [['underwriting', 'Underwriting'], ['claims', 'Claims'], ['customer', 'Customer Service'], ['marketing', 'Marketing']]
  // an operations & maintenance group (brand setting: sector, departments): its own business departments
  : [['operations', 'Operations and Maintenance'], ['projects', 'Projects and Site Workforce'], ['hse', 'Health, Safety and Environment'], ['fleet', 'Fleet and Transport'], ['site_security', 'Site Security and Access Control'], ['group_services', 'Services for Group Companies']]);
const DEPT = Object.fromEntries(DEPTS);
const FWS = [['sama', 'SAMA Cyber Security Framework'], ['nca', 'NCA ECC'], ['pdpl', 'PDPL (SDAIA)'], ['ndmo', 'NDMO data management'], ['ia', 'Insurance Authority (IA)']];
const FREQ = { M: 'monthly', Q: 'quarterly', H: 'half-yearly', Y: 'yearly' };

// [id, department, frequency, SAMA CSF domains, NCA ECC sub-domains, PDPL articles, NDMO domains, obligation, evidence expected]
const O = (id, dept, freq, sama, nca, pdpl, ndmo, title, evidence) => ({ id, dept, freq, sama, nca, pdpl, ndmo, title, evidence });
const OBLIGATIONS = [
  // ---- Human Resources
  O('DO-01', 'hr', 'Q', ['3.3.1'], ['1-9'], [], [], 'Every joiner this period was screened (identity, references, criminal record where the law allows) before getting access', 'Screening log for the period\'s joiners'),
  O('DO-02', 'hr', 'Q', ['3.3.1', '3.3.5'], ['1-9', '2-2'], [], [], 'Every leaver this period was reported to IT on or before the last day so access was removed', 'Leavers list with the IT request reference for each'),
  O('DO-03', 'hr', 'Y', ['3.1.6', '3.1.7'], ['1-10'], ['Art. 19'], ['PDP'], 'Every employee completed the cyber security and personal data protection awareness this year', 'Completion report from the learning system'),
  O('DO-04', 'hr', 'Y', ['3.3.1'], ['1-9'], ['Art. 19'], ['DSP'], 'Every employee signed the confidentiality and acceptable use acknowledgement (new joiners on day one)', 'Signed acknowledgements register'),
  O('DO-05', 'hr', 'H', ['3.3.1'], ['1-9'], ['Art. 11', 'Art. 18'], ['PDP'], 'Employee personal files hold only what is needed, and files past their retention period were destroyed', 'Retention review record; destruction log'),
  // ---- IT Infrastructure
  O('DO-06', 'infra', 'M', ['3.3.8', '3.3.17'], ['2-3', '2-10'], [], [], 'Security patches were applied to servers, network devices and desktops within the patching policy\'s time limits', 'Monthly patch compliance report; exceptions with approval'),
  O('DO-07', 'infra', 'Q', ['3.3.8', 'BCM'], ['2-9'], [], ['DO'], 'A restore from backup was tested for the critical systems and it worked', 'Restore test record (system, date, result, time taken)'),
  O('DO-08', 'infra', 'Q', ['3.3.3'], ['2-1'], [], [], 'The asset register was reconciled with discovery (owner, classification, serial number) and differences fixed', 'Reconciliation report'),
  O('DO-09', 'infra', 'Q', ['3.3.5'], ['2-2'], [], [], 'Privileged accounts on infrastructure were reviewed and the ones not needed removed', 'Privileged access review signed by the manager'),
  O('DO-10', 'infra', 'H', ['3.3.8'], ['2-5'], [], [], 'Firewall rules were reviewed: unused, too-wide and expired rules removed', 'Firewall rule review record'),
  O('DO-11', 'infra', 'M', ['3.3.7'], ['1-6'], [], [], 'Every change to production went through change management (approved before, reviewed after)', 'Change register for the month; emergency changes reviewed'),
  O('DO-12', 'infra', 'Y', ['BCM'], ['3-1'], [], [], 'The disaster recovery plan was tested and the lessons recorded', 'DR test report and action plan'),
  // ---- IT Applications
  O('DO-13', 'apps', 'Q', ['3.3.5'], ['2-2'], ['Art. 19'], ['DSP'], 'User access to business applications was reviewed by the business owners and leavers / movers corrected', 'Access review per application, signed'),
  O('DO-14', 'apps', 'M', ['3.3.7', '3.3.6'], ['1-6', '2-15'], [], [], 'Every application release was tested and approved, with a security test for internet-facing changes', 'Release register with test and approval references'),
  O('DO-15', 'apps', 'Y', ['3.3.6'], ['2-15', '2-11'], [], [], 'Internet-facing applications were penetration tested and the findings tracked to closure', 'Penetration test report; remediation tracker'),
  O('DO-16', 'apps', 'H', ['3.3.6'], ['2-7'], ['Art. 11', 'Art. 19'], ['DQ', 'DSP'], 'Test environments use masked data, not live customer personal data', 'Masking procedure and the last check of the test databases'),
  // ---- Cyber Security
  O('DO-17', 'cyber', 'M', ['3.3.17'], ['2-10'], [], [], 'Vulnerability scans ran on every network segment and critical / high findings were fixed or risk-accepted on time', 'Scan reports; remediation status; risk acceptances'),
  O('DO-18', 'cyber', 'M', ['3.3.14'], ['2-12'], [], [], 'Security monitoring covered the critical systems (log sources reporting) and alerts were triaged', 'Log source coverage report; SOC monthly report'),
  O('DO-19', 'cyber', 'Q', ['3.3.15'], ['2-13'], ['Art. 20'], [], 'Security incidents were handled under the incident procedure, with lessons learned recorded', 'Incident register; post-incident reviews'),
  O('DO-20', 'cyber', 'H', ['3.1.6'], ['1-10'], [], [], 'A phishing simulation was run and the people who failed were trained', 'Simulation results; follow-up training record'),
  O('DO-21', 'cyber', 'Y', ['3.1.3'], ['1-3'], [], [], 'Cyber security policies and standards were reviewed and approved', 'Policy review record and approval'),
  O('DO-22', 'cyber', 'Q', ['3.3.16'], ['2-13'], [], [], 'Threat intelligence was reviewed and relevant indicators blocked', 'Threat intelligence log'),
  // ---- Governance, Risk & Compliance
  O('DO-23', 'grc', 'Q', ['3.2.1'], ['1-5'], [], [], 'The risk register was reviewed: ratings, owners and treatment plans up to date', 'Risk register review minutes'),
  O('DO-24', 'grc', 'Q', ['3.1.1'], ['1-2'], [], ['DG'], 'The cyber security committee met and its decisions were minuted', 'Committee minutes'),
  O('DO-25', 'grc', 'Y', ['3.2.2', '3.2.4'], ['1-7', '1-8'], [], [], 'Compliance with SAMA CSF / NCA ECC was self-assessed and the gaps given owners and dates', 'Self-assessment; gap remediation plan'),
  O('DO-26', 'grc', 'Y', ['BCM'], ['3-1'], [], [], 'The business impact analysis and business continuity plans were reviewed and approved', 'BIA and BCP review record'),
  // ---- Data Protection Office
  O('DO-27', 'dpo', 'Q', [], [], ['IR Art. 33'], ['PDP'], 'The record of processing activities (RoPA) was reviewed with each department and updated', 'RoPA review record'),
  O('DO-28', 'dpo', 'M', [], [], ['Art. 4'], ['PDP'], 'Every data subject request was answered within 30 days (or extended with notice and reasons)', 'DSAR register with response dates'),
  O('DO-29', 'dpo', 'Q', [], [], ['Art. 22'], ['PDP'], 'A data protection impact assessment was done for every new or changed high-risk processing', 'DPIA register'),
  O('DO-30', 'dpo', 'Q', [], [], ['Art. 20'], ['PDP'], 'Personal data breaches were assessed, and the ones that must be were notified to SDAIA within 72 hours', 'Breach register with notification times'),
  O('DO-31', 'dpo', 'H', [], [], ['Art. 29'], ['PDP', 'DSI'], 'Transfers of personal data outside the Kingdom were reviewed against their legal basis and safeguards', 'Transfer register and risk assessments'),
  O('DO-32', 'dpo', 'Y', [], [], ['Art. 12'], ['PDP'], 'The privacy notice was reviewed and matches what is actually collected and why', 'Privacy notice review record'),
  // ---- Data Management Office
  O('DO-33', 'data', 'Q', [], ['2-7'], [], ['DC'], 'New data sets were classified and existing classifications reviewed', 'Data classification register'),
  O('DO-34', 'data', 'Q', [], [], [], ['DQ'], 'Data quality checks ran on the critical data (policy, claims, customer) and issues were assigned', 'Data quality report and issue log'),
  O('DO-35', 'data', 'H', [], [], [], ['MCM', 'DG'], 'The data catalogue and data owners / stewards were reviewed', 'Catalogue review record'),
  // ---- Legal
  O('DO-36', 'legal', 'Q', ['3.4.1'], ['4-1'], ['Art. 8'], ['PDP'], 'New contracts with service providers handling personal data or systems include the data protection and security clauses', 'Contract checklist per new contract'),
  O('DO-37', 'legal', 'H', ['3.2.2'], ['1-7'], [], [], 'New or changed laws and regulator circulars were tracked and their owners told', 'Regulatory change log'),
  // ---- Procurement
  O('DO-38', 'procurement', 'Q', ['3.4.1', '3.4.2'], ['4-1'], ['Art. 8'], [], 'Every new IT / outsourcing supplier had a security and data protection assessment before signing', 'Supplier assessments for the period'),
  O('DO-39', 'procurement', 'Y', ['3.4.3'], ['4-2'], ['Art. 29'], [], 'Cloud services in use were reviewed: approved, data location known, exit plan in place', 'Cloud services register review'),
  // ---- Administration & Facilities
  O('DO-40', 'admin', 'Q', ['3.3.2'], ['2-14'], [], [], 'Physical access to the data centre and secure areas was reviewed and visitor logs checked', 'Access list review; visitor log check'),
  O('DO-41', 'admin', 'Q', ['3.3.11'], ['2-7'], ['Art. 18'], ['DSP', 'DCM'], 'Paper records and media were destroyed securely, with a certificate', 'Destruction certificates'),
  // ---- Finance
  O('DO-42', 'finance', 'Q', ['3.3.5'], ['2-2'], [], [], 'Segregation of duties in the finance system was reviewed (no one raises and approves the same payment)', 'SoD review record'),
  O('DO-43', 'finance', 'Y', ['3.1.1'], ['1-2'], [], [], 'The cyber security budget was approved and its spending reported', 'Budget approval; spending report'),
  // ---- Underwriting, Claims, Customer Service, Marketing (business departments that hold personal data)
  O('DO-44', 'underwriting', 'H', [], [], ['Art. 11', 'Art. 23'], ['PDP'], 'Policy applications collect only the personal and health data needed, and health data access is limited', 'Form review; access list for health data'),
  O('DO-45', 'claims', 'Q', ['3.3.5'], [], ['Art. 19', 'Art. 23'], ['PDP', 'DSP'], 'Access to claims files (including medical reports) was reviewed and limited to the people handling them', 'Access review for the claims system'),
  O('DO-46', 'claims', 'H', [], [], ['Art. 18'], ['DCM'], 'Closed claims past their retention period were destroyed or anonymised (unless on legal hold)', 'Retention run record; legal hold list'),
  O('DO-47', 'customer', 'Q', [], [], ['Art. 4'], ['PDP'], 'Customer requests about their personal data reached the Data Protection Office the same day', 'Request hand-off log'),
  O('DO-48', 'customer', 'H', ['3.1.6'], [], ['Art. 19'], ['PDP'], 'Customer service staff verify the caller\'s identity before discussing a policy or claim', 'Call quality sample results'),
  O('DO-49', 'marketing', 'Q', [], [], ['Art. 25', 'Art. 5'], ['PDP'], 'Marketing messages went only to customers who consented, and opt-outs were honoured', 'Consent check of the campaign lists; opt-out log'),
].filter((o) => INSURER || !['underwriting', 'claims', 'customer', 'marketing'].includes(o.dept)).concat(INSURER ? [] : [
  // ---- Operations & maintenance, projects, HSE, fleet, site security, services for group companies
  O('DO-50', 'operations', 'Q', [], ['2-2'], ['Art. 19'], ['DSP'], 'Technician and subcontractor accounts on client systems (CMMS, BMS, remote access) were reviewed and leavers removed', 'Access review of the client systems; removals list'),
  O('DO-51', 'operations', 'H', [], [], ['Art. 11'], ['PDP'], 'Service reports and work orders sent to clients carry only the personal data the client needs', 'Sample of service reports reviewed'),
  O('DO-52', 'projects', 'Q', [], ['2-7'], ['Art. 18', 'Art. 23'], ['PDP', 'DSP'], 'Site attendance records (biometric included) are accessible only to the people who need them, and past their retention period are deleted', 'Access list of the attendance system; retention run record'),
  O('DO-53', 'projects', 'H', [], [], ['Art. 18'], ['DCM'], 'Subcontractor workforce lists received for a project were deleted or returned when the project closed', 'Closed-project list with deletion / return record'),
  O('DO-54', 'hse', 'H', [], ['2-7'], ['Art. 23'], ['PDP'], 'Injury, medical and fitness-for-work records are kept apart, with access limited to HSE and the clinic', 'Access list; storage location of HSE medical records'),
  O('DO-55', 'fleet', 'Q', [], [], ['Art. 11', 'Art. 22'], ['PDP'], 'Vehicle tracking data was used only for its stated purposes, access was reviewed, and no tracking runs off duty', 'Purpose statement; access review; tracking schedule'),
  O('DO-56', 'site_security', 'Q', [], ['2-14'], ['Art. 18'], ['DCM'], 'CCTV recordings past their retention period were deleted, and every access to footage was logged with its reason', 'Retention setting of each recorder; footage access log'),
  O('DO-57', 'site_security', 'Q', [], ['2-2'], [], [], 'Lost or returned site badges were disabled the same day, and badges of leavers and finished contractors were collected', 'Badge disable log; leavers / contractors reconciliation'),
  O('DO-58', 'group_services', 'H', [], ['4-1'], ['Art. 8'], ['DSP'], 'Every group company whose personal data we process has a current data processing agreement accepted by the DPO', 'PDPL Group Companies register'),
  O('DO-59', 'group_services', 'Q', [], [], ['Art. 20'], ['PDP'], 'Incidents touching a group company\'s data were reported to that company within the agreed hours', 'Breach notices to group companies'),
]);
for (const o of OBLIGATIONS) o.ia = o.sama.slice();   // IA keeps insurers on the SAMA CSF (circular UTC/277/202401)

const STATUSES = ['done', 'partly', 'not_done', 'not_applicable'];
const LEVEL = { verified: 'fully', partly: 'partially', not_done: 'not', exception: 'not', overdue: 'not', awaiting_review: 'not_assessed', open: 'not_assessed', no_owner: 'not_assessed', not_applicable: 'na' };

// a period in Riyadh time: key, start, end (inclusive, ms)
function periodOf(freq, t) {
  const d = new Date(t + RIYADH), y = d.getUTCFullYear(), m = d.getUTCMonth();
  const span = { M: 1, Q: 3, H: 6, Y: 12 }[freq], first = Math.floor(m / span) * span;
  const start = Date.UTC(y, first, 1) - RIYADH, end = Date.UTC(y, first + span, 1) - RIYADH - 1;
  const key = freq === 'M' ? y + '-' + String(m + 1).padStart(2, '0') : freq === 'Q' ? y + '-Q' + (first / 3 + 1) : freq === 'H' ? y + '-H' + (first / 6 + 1) : String(y);
  return { key, start, end, due: end + GRACE_DAYS * DAY };
}
const prevOf = (freq, p) => periodOf(freq, p.start - 1);

function createDeptChecklist(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const att = () => app.store.collection('dept_attest'), own = () => app.store.collection('dept_owners');
  const log = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what); };
  const ownerOf = (dept) => own().get(dept) || null;
  const recOf = (o, key) => att().get(o.id + '|' + key) || null;

  function slimRec(r, op) {
    if (!r) return null;
    const base = { period: r.period, status: r.status, at: r.at, late: !!r.late, review: r.review ? { decision: r.review.decision, at: r.review.at } : null };
    return op ? Object.assign(base, { evidence: r.evidence || '', note: r.note || '', by: r.by, review: r.review ? Object.assign({}, r.review) : null }) : base;
  }
  function stateOf(o, op) {
    const ow = ownerOf(o.dept), cur = periodOf(o.freq, now()), prev = prevOf(o.freq, cur);
    const rc = recOf(o, cur.key), rp = recOf(o, prev.key), rec = rc || rp;
    const from = ow ? Date.parse(ow.since) : null, prevOwed = !!(ow && prev.end >= from);
    let result, why;
    if (!ow && !rec) { result = 'no_owner'; why = 'no head named for ' + DEPT[o.dept] + ' - an admin names one'; }
    else if (rec) {
      const p = rec.period;
      if (rec.review && rec.review.decision === 'exception') { result = 'exception'; why = 'the auditor raised an exception for ' + p; }
      else if (rec.status === 'not_applicable') { result = 'not_applicable'; why = 'not applicable for ' + p + (rec.review ? ' (verified)' : ' (attested)'); }
      else if (rec.status === 'not_done') { result = 'not_done'; why = 'attested not done for ' + p; }
      else if (rec.status === 'partly') { result = 'partly'; why = 'partly done for ' + p + (rec.review ? ' (verified)' : ''); }
      else if (rec.review) { result = 'verified'; why = 'done and verified for ' + p; }
      else { result = 'awaiting_review'; why = 'attested done for ' + p + ' - the auditor to verify'; }
    } else if (prevOwed && now() > prev.due) { result = 'overdue'; why = prev.key + ' ended and nothing was attested ' + GRACE_DAYS + ' days after'; }
    else { result = 'open'; why = 'first period ' + cur.key + ' open - attest by ' + new Date(cur.due).toISOString().slice(0, 10); }
    const history = [];
    for (let p = cur, i = 0; i < 4; i++, p = prevOf(o.freq, p)) { const r = recOf(o, p.key); history.push({ period: p.key, due: new Date(p.due).toISOString().slice(0, 10), rec: slimRec(r, op) }); }
    return { id: o.id, dept: o.dept, dept_name: DEPT[o.dept], freq: o.freq, frequency: FREQ[o.freq], title: o.title, evidence_expected: o.evidence,
      sama: o.sama, nca: o.nca, pdpl: o.pdpl, ndmo: o.ndmo, ia: o.ia, current_period: cur.key, previous_period: prev.key, attest_by: new Date(cur.due).toISOString().slice(0, 10),
      result, why, level: CL.levelOf(result, LEVEL), current: slimRec(rc, op), previous: slimRec(rp, op), history,
      days_overdue: result === 'overdue' ? Math.floor((now() - prev.due) / DAY) : 0 };
  }
  function view(q = {}, op) {
    const all = OBLIGATIONS.map((o) => stateOf(o, op));
    const departments = CL.group(all, 'dept', LEVEL, DEPTS).map((g) => {
      const ow = ownerOf(g.key), rows = all.filter((r) => r.dept === g.key);
      return Object.assign(g, { head: ow ? (op ? ow.head : 'named') : null, deputy: ow && op ? ow.deputy || null : undefined, since: ow ? ow.since : null, obligations: rows.length,
        overdue: rows.filter((r) => r.result === 'overdue').length, awaiting_review: rows.filter((r) => r.result === 'awaiting_review').length, exceptions: rows.filter((r) => r.result === 'exception').length });
    });
    const frameworks = FWS.map(([k, name]) => Object.assign({ key: k, name }, CL.levels(all.filter((r) => r[k].length), LEVEL), { obligations: all.filter((r) => r[k].length).length }));
    let items = all;
    if (q.dept) items = items.filter((r) => r.dept === q.dept);
    if (q.fw) items = items.filter((r) => r[q.fw].length);
    return { generated_at: iso(), overall: CL.levels(all, LEVEL), departments, frameworks, items, grace_days: GRACE_DAYS,
      counts: { obligations: all.length, overdue: all.filter((r) => r.result === 'overdue').length, awaiting_review: all.filter((r) => r.result === 'awaiting_review').length, exceptions: all.filter((r) => r.result === 'exception').length, no_owner: departments.filter((d) => !d.head).length },
      note: 'Fully compliant = done and verified by an auditor; an attestation not yet verified is not counted as compliant. Overdue = the last period ended, ' + GRACE_DAYS + ' days passed and nothing was attested. Tracking starts when the department head is named. The framework mapping is domain-level: a draft for the compliance team to verify, not a certification.' };
  }
  function owners(op) { return DEPTS.map(([k, name]) => { const ow = ownerOf(k); return { dept: k, name, named: !!ow, head: ow && op ? ow.head : undefined, deputy: ow && op ? ow.deputy || null : undefined, since: ow ? ow.since : null, obligations: OBLIGATIONS.filter((o) => o.dept === k).length }; }); }
  function setOwner(b, who) {
    human(who, 'name a department head');
    if (isService(b.head) || (b.deputy && isService(b.deputy))) throw httpErr(400, 'head: a named person, not a service or AI identity');
    if (b.deputy && same(b.deputy, b.head)) throw httpErr(400, 'deputy must be a different person from the head');
    const prev = ownerOf(b.dept);
    const rec = { id: b.dept, head: b.head, deputy: b.deputy || '', since: prev ? prev.since : iso(), by: who.user, at: iso() };
    own().put(rec);
    log(who, 'dept-checklist.owner', b.dept, { head: b.head, deputy: b.deputy || null, previous: prev ? { head: prev.head, deputy: prev.deputy || null } : null });
    return { dept: b.dept, name: DEPT[b.dept], head: rec.head, deputy: rec.deputy || null, since: rec.since };
  }
  function obligation(id) { const o = OBLIGATIONS.find((x) => x.id === id); if (!o) throw httpErr(404, 'no department obligation ' + id); return o; }
  function periodFor(o, key) {
    const cur = periodOf(o.freq, now()), prev = prevOf(o.freq, cur);
    if (!key || key === cur.key) return cur;
    if (key === prev.key) return prev;
    throw httpErr(400, 'period must be ' + cur.key + ' (current) or ' + prev.key + ' (previous) for a ' + FREQ[o.freq] + ' obligation');
  }
  function attest(b, who) {
    human(who, 'attest a department obligation');
    const o = obligation(b.id), ow = ownerOf(o.dept);
    if (!ow) throw httpErr(409, 'no head named for ' + DEPT[o.dept] + ': an admin names the department head first (Department checklist → Department heads)');
    if (!same(who.user, ow.head) && !same(who.user, ow.deputy)) throw httpErr(403, 'only the head or deputy of ' + DEPT[o.dept] + ' can attest its obligations');
    const p = periodFor(o, b.period), prev = recOf(o, p.key);
    if (prev && prev.review && prev.review.decision === 'verified') throw httpErr(409, o.id + ' for ' + p.key + ' is already verified by the auditor - it cannot be changed');
    const rec = { id: o.id + '|' + p.key, obligation: o.id, dept: o.dept, period: p.key, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: iso(), late: now() > p.due,
      history: prev ? (prev.history || []).concat([{ status: prev.status, evidence: prev.evidence, note: prev.note, by: prev.by, at: prev.at, review: prev.review || null }]).slice(-10) : [] };
    att().put(rec);
    log(who, 'dept-checklist.attest', o.id, { period: p.key, status: b.status, late: rec.late, resubmitted: !!prev, evidence: rec.evidence.slice(0, 200) });
    return stateOf(o, true);
  }
  function review(b, who) {
    human(who, 'review a department attestation');
    const o = obligation(b.id), p = periodFor(o, b.period), rec = recOf(o, p.key), ow = ownerOf(o.dept);
    if (!rec) throw httpErr(404, 'nothing attested for ' + o.id + ' in ' + p.key);
    if (rec.review) throw httpErr(409, o.id + ' for ' + p.key + ' was already reviewed (' + rec.review.decision + ')' + (rec.review.decision === 'exception' ? ' - the department attests again first' : ''));
    if (same(rec.by, who.user)) throw httpErr(403, 'four-eyes: the person who attested cannot review it');
    if (ow && (same(ow.head, who.user) || same(ow.deputy, who.user))) throw httpErr(403, 'independence: the head or deputy of ' + DEPT[o.dept] + ' cannot review its own attestations');
    if (b.decision === 'exception' && !b.note) throw httpErr(400, 'note is required: say what the evidence does not show');
    const r = Object.assign({}, rec, { review: { decision: b.decision, note: b.note || '', by: who.user, role: who.role, at: iso() } });
    att().put(r);
    log(who, 'dept-checklist.review', o.id, { period: p.key, decision: b.decision, attested_by: rec.by, note: (b.note || '').slice(0, 200) });
    return stateOf(o, true);
  }
  // what the audit dashboard puts first: overdue obligations and exceptions
  function attention() {
    const v = view({}, true);
    return { departments: v.departments, overall: v.overall, counts: v.counts,
      items: v.items.filter((r) => r.result === 'overdue' || r.result === 'exception').map((r) => ({ id: r.id, title: r.title, dept: r.dept_name, result: r.result, days_overdue: r.days_overdue, period: r.result === 'overdue' ? r.previous_period : (r.current || r.previous || {}).period })) };
  }
  function exportCsv(who) {
    const v = view({}, true);
    const cell = (x) => { let t = String(x == null ? '' : x).slice(0, 1000); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };   // no formula injection in Excel
    const L = [['Section', 'Item', 'Department', 'Frequency', 'Status', 'Fully %', 'Partially %', 'Not %', 'Not assessed %', 'Detail', 'Attested by', 'Reviewed by', 'Evidence'].map(cell).join(',')];
    const pr = (n) => [n.pct.fully, n.pct.partially, n.pct.not, n.pct.not_assessed];
    L.push(['Overall', 'All obligations', '', '', v.overall.status].concat(pr(v.overall), [v.overall.applicable + ' applicable', '', '', '']).map(cell).join(','));
    for (const d of v.departments) L.push(['Department', d.name, d.name, '', d.status].concat(pr(d), ['head ' + (d.head || 'not named') + ', overdue ' + d.overdue, '', '', '']).map(cell).join(','));
    for (const f of v.frameworks) L.push(['Framework', f.name, '', '', f.status].concat(pr(f), [f.obligations + ' obligation(s)', '', '', '']).map(cell).join(','));
    for (const r of v.items) { const rec = r.current || r.previous; L.push(['Obligation', r.id + ' ' + r.title, r.dept_name, r.frequency, r.result, '', '', '', '', r.why, rec ? rec.by : '', rec && rec.review ? rec.review.by : '', rec ? rec.evidence : ''].map(cell).join(',')); }
    log(who, 'dept-checklist.export', 'dept-checklist', { rows: L.length - 1 });
    return { filename: 'department-checklist-' + v.generated_at.slice(0, 10) + '.csv', csv: L.join('\r\n') };
  }
  return { view, owners, setOwner, attest, review, attention, exportCsv, OBLIGATIONS, DEPTS };
}

function registerDeptChecklistRoutes(srv, app, D) {
  const { body } = require('./check');
  const isOp = (ctx) => ctx.who && (ctx.who.role === 'operator' || ctx.who.role === 'admin');
  const ID = { required: true, re: /^DO-\d{2}$/, msg: 'id must be a department obligation id (DO-nn)' };
  const PERIOD = { max: 7, re: /^\d{4}(-(0[1-9]|1[0-2]|Q[1-4]|H[12]))?$/, msg: 'period must be YYYY, YYYY-MM, YYYY-Qn or YYYY-Hn' };
  srv.route('GET', '/dept-checklist', (ctx) => {
    ctx.need('viewer');
    const q = body(ctx.query || {}).oneOf('dept', DEPTS.map((d) => d[0])).oneOf('fw', FWS.map((f) => f[0])).done();
    return D.view(q, isOp(ctx));
  });
  srv.route('GET', '/dept-checklist/owners', (ctx) => { ctx.need('viewer'); return D.owners(isOp(ctx)); });
  srv.route('POST', '/dept-checklist/owners', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).oneOf('dept', DEPTS.map((d) => d[0]), { required: true }).str('head', U('head', true)).str('deputy', U('deputy')).done();
    return D.setOwner(b, ctx.who);
  });
  srv.route('POST', '/dept-checklist/attest', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', ID).str('period', PERIOD).oneOf('status', STATUSES, { required: true }).str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'done' || o.status === 'partly') && !o.evidence ? 'evidence is required: where the evidence is (document reference)' : null))
      .rule((o) => ((o.status === 'not_done' || o.status === 'not_applicable' || o.status === 'partly') && !o.note ? 'note is required: say what was not done, or why it does not apply' : null)).done();
    return D.attest(b, ctx.who);
  });
  srv.route('POST', '/dept-checklist/review', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', ID).str('period', Object.assign({ required: true }, PERIOD)).oneOf('decision', ['verified', 'exception'], { required: true }).str('note', { max: 1000 }).done();
    return D.review(b, ctx.who);
  });
  srv.route('GET', '/dept-checklist/export', (ctx) => { ctx.need('operator'); return D.exportCsv(ctx.who); });
}

module.exports = { createDeptChecklist, registerDeptChecklistRoutes, OBLIGATIONS, DEPTS, periodOf, STATUSES, GRACE_DAYS };
