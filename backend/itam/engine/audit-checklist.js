// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Audit checklist by framework: SAMA Cyber Security Framework, NCA Essential Cybersecurity Controls (ECC-2:2024) and the
 * Insurance Authority view (IA circular UTC/277/202401 keeps insurers on the SAMA CSF, plus the circular's own contact-
 * mailbox requirement). ONE catalogue of audit checks, each mapped to its SAMA CSF domain(s) and NCA ECC sub-domain(s), so
 * the three checklists cannot disagree: the same check reads the same in each.
 *
 * Every check states the control requirement, the audit procedure and the evidence expected. Two sources fill it:
 *   - the AI auditors (engine/auditors.js): a check linked to their tests takes the last automated result. A failed test
 *     makes the check NON-COMPLIANT whatever a person recorded (automated evidence of a failure is not overridden; the
 *     conflict is shown). A passed test alone reads "automated test passed - auditor to confirm": a test covers part of a
 *     domain, never all of it, so it is not counted as compliant until a person confirms.
 *   - the human auditor: compliant / partially compliant / non-compliant / not applicable, with the evidence reference and
 *     a note; due again after 12 months. Recorded by a named person (operator or admin; never a service / AI identity),
 *     every assessment audited.
 * A check with neither is NOT ASSESSED - never compliant. The mapping is domain-level: a draft for the compliance team to
 * verify against the framework texts, not a certification.
 *
 *   GET  /audit-checklist?fw=sama|nca|ia     viewer (statuses; evidence, notes and names for operators - PDPL)
 *   POST /audit-checklist/assess             operator {id, status, evidence?, note?}  audited
 *
 * Evidence requests (the PBC list - "provided by client"): every check of the framework that is not assessed, not
 * compliant, partial, awaiting confirmation of an automated pass, or past its 12 months becomes a request to the owning
 * department for the evidence it expects. The auditor ISSUES the open requests with a due date; the owner records where
 * the evidence is (a document reference - the evidence itself stays in the document store, never in this platform's
 * repository: PDPL); a DIFFERENT person accepts it or rejects it with a reason (four-eyes; never a service / AI identity).
 * An issued request past its due date is overdue - the AI IT Auditor's IT-19 raises it to the owner. Every step audited.
 *   GET  /audit-checklist/requests?fw=       operator  the PBC list (state per request, counts by state and department)
 *   POST /audit-checklist/requests/issue     operator  {fw, due (YYYY-MM-DD, today..+90 days), ids?}  issue open requests
 *   POST /audit-checklist/requests/respond   operator  {id, reference, note?}   the owner: where the evidence is
 *   POST /audit-checklist/requests/decide    operator  {id, decision: accept|reject, note?}  not the responder; reject needs a note
 */
const DAY = 86400000, VALID_DAYS = 365;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || '').trim());

const SAMA = {
  '3.1.1': 'Cyber Security Governance', '3.1.2': 'Cyber Security Strategy', '3.1.3': 'Cyber Security Policy', '3.1.4': 'Cyber Security Roles and Responsibilities',
  '3.1.5': 'Cyber Security in Project Management', '3.1.6': 'Cyber Security Awareness', '3.1.7': 'Cyber Security Training', '3.2.1': 'Cyber Security Risk Management',
  '3.2.2': 'Regulatory Compliance', '3.2.3': 'Compliance with International Industry Standards', '3.2.4': 'Cyber Security Review', '3.2.5': 'Cyber Security Audits',
  '3.3.1': 'Human Resources', '3.3.2': 'Physical Security', '3.3.3': 'Asset Management', '3.3.4': 'Cyber Security Architecture', '3.3.5': 'Identity and Access Management',
  '3.3.6': 'Application Security', '3.3.7': 'Change Management', '3.3.8': 'Infrastructure Security', '3.3.9': 'Cryptography', '3.3.10': 'Bring Your Own Device (BYOD)',
  '3.3.11': 'Secure Disposal of Information Assets', '3.3.12': 'Payment Systems', '3.3.13': 'Electronic Banking Services', '3.3.14': 'Cyber Security Event Management',
  '3.3.15': 'Cyber Security Incident Management', '3.3.16': 'Threat Management', '3.3.17': 'Vulnerability Management', '3.4.1': 'Contract and Vendor Management',
  '3.4.2': 'Outsourcing', '3.4.3': 'Cloud Computing', BCM: 'SAMA Business Continuity Management Framework',
};
const NCA = {
  '1-1': 'Cybersecurity Strategy', '1-2': 'Cybersecurity Management', '1-3': 'Cybersecurity Policies and Procedures', '1-4': 'Cybersecurity Roles and Responsibilities',
  '1-5': 'Cybersecurity Risk Management', '1-6': 'Cybersecurity in Information Technology Projects', '1-7': 'Compliance with Cybersecurity Standards, Laws and Regulations',
  '1-8': 'Periodical Cybersecurity Review and Audit', '1-9': 'Cybersecurity in Human Resources', '1-10': 'Cybersecurity Awareness and Training Program',
  '2-1': 'Asset Management', '2-2': 'Identity and Access Management', '2-3': 'Information System and Processing Facilities Protection', '2-4': 'Email Protection',
  '2-5': 'Networks Security Management', '2-6': 'Mobile Devices Security', '2-7': 'Data and Information Protection', '2-8': 'Cryptography', '2-9': 'Backup and Recovery Management',
  '2-10': 'Vulnerabilities Management', '2-11': 'Penetration Testing', '2-12': 'Cybersecurity Event Logs and Monitoring Management', '2-13': 'Cybersecurity Incident and Threat Management',
  '2-14': 'Physical Security', '2-15': 'Web Application Security', '3-1': 'Cybersecurity Resilience Aspects of Business Continuity Management', '4-1': 'Third-Party Cybersecurity',
  '4-2': 'Cloud Computing and Hosting Cybersecurity',
};
const IA_EXTRA = { 'IA-277': 'Cyber-incident contact mailbox, not tied to one employee (circular UTC/277/202401)' };
const FW = {
  sama: { name: 'SAMA Cyber Security Framework', domains: SAMA },
  nca: { name: 'NCA Essential Cybersecurity Controls (ECC-2:2024)', domains: NCA },
  ia: { name: 'Insurance Authority (IA) - SAMA CSF baseline', domains: Object.assign({}, SAMA, IA_EXTRA),
    basis: 'The Insurance Authority has not published its own cyber security framework. Circular UTC/277/202401 (January 2024) keeps insurers on the rules issued before, so the IA checklist is the SAMA CSF checklist plus the circular\'s own requirement (IA-277).' },
};
const DEPT = { infra: 'IT Infrastructure', apps: 'IT Applications', cyber: 'Cyber Security', grc: 'Governance, Risk & Compliance', audit: 'IT & Cyber Security Audit', platform: 'Platform administration', hr: 'Human Resources', admin: 'Administration & Facilities' };

// [id, owner, SAMA domains, NCA sub-domains, AI auditor tests, requirement, audit procedure, evidence expected]
const C = (id, owner, sama, nca, auto, title, procedure, evidence) => ({ id, owner, sama, nca, auto, title, procedure, evidence });
const CHECKS = [
  // ---- governance
  C('AC-01', 'grc', ['3.1.1'], ['1-2'], [], 'A cyber security committee is established, chaired by senior management, and meets as its charter requires', 'Inspect the committee charter and the minutes of the last 12 months; confirm membership, quorum and that decisions are followed up.', 'Committee charter; minutes; action tracker'),
  C('AC-02', 'grc', ['3.1.1'], ['1-2'], [], 'The cyber security function is independent of IT operations and reports to an appropriate level', 'Inspect the organisation chart and the CISO\'s reporting line; confirm the function is separate from IT operations.', 'Approved organisation chart; CISO job description'),
  C('AC-03', 'grc', ['3.1.2'], ['1-1'], [], 'A cyber security strategy is approved by the board, aligned with the business strategy and reviewed periodically', 'Inspect the strategy, its approval and its roadmap; check progress against the roadmap.', 'Approved strategy; roadmap with status'),
  C('AC-04', 'grc', ['3.1.3'], ['1-3'], ['IT-08'], 'Cyber security policies and procedures are approved, published, and reviewed within their review cycle', 'Sample the policy register; confirm each policy is approved, communicated and reviewed on time.', 'Policy register; approval records; review dates'),
  C('AC-05', 'audit', ['3.1.4'], ['1-4'], ['IT-03'], 'Cyber security roles and responsibilities are defined, assigned to named people and segregated', 'Inspect the RACI and role assignments; confirm every AI engineer and critical activity has a named human approver.', 'RACI; role assignments; approver list'),
  C('AC-06', 'apps', ['3.1.5'], ['1-6'], [], 'Cyber security requirements are included in every IT project and change, with a security sign-off before go-live', 'Sample projects delivered in the period; check for security requirements, a risk assessment and security sign-off.', 'Project files; security sign-off'),
  C('AC-07', 'grc', ['3.1.6'], ['1-10'], [], 'A cyber security awareness programme runs for all staff, including phishing simulations, and its effectiveness is measured', 'Inspect the programme plan, completion rates and phishing simulation results.', 'Awareness plan; completion report; simulation results'),
  C('AC-08', 'grc', ['3.1.7'], ['1-10'], [], 'Staff with cyber security and IT roles receive role-specific training', 'Sample technical staff; confirm training records against the training plan.', 'Training plan; training records'),
  // ---- risk, compliance, review, audit
  C('AC-09', 'grc', ['3.2.1'], ['1-5'], [], 'A cyber security risk methodology is approved; risks are identified, rated, owned and treated', 'Inspect the methodology and the risk register; sample risks for owners, ratings, treatment plans and review dates.', 'Risk methodology; risk register; treatment plans'),
  C('AC-10', 'grc', ['3.2.1'], ['1-5', '1-6'], [], 'A risk assessment is done before new systems, major changes and third-party onboarding', 'Sample new systems and vendors in the period; confirm a risk assessment preceded go-live.', 'Risk assessments; go-live approvals'),
  C('AC-11', 'grc', ['3.2.2'], ['1-7'], ['CY-08'], 'Regulatory requirements (SAMA, IA, NCA, PDPL) are identified and compliance is monitored', 'Inspect the compliance register and the monitoring results; confirm gaps have remediation plans.', 'Compliance register; Live Compliance report; remediation plans'),
  C('AC-12', 'grc', ['3.2.3'], ['1-7'], [], 'Applicable international standards (ISO/IEC 27001, PCI DSS where card data is handled) are identified and followed', 'Inspect the standards adopted and any certificates or assessments.', 'Certificates; assessment reports'),
  C('AC-13', 'audit', ['3.2.4'], ['1-8'], [], 'The cyber security posture is reviewed periodically (at least yearly) by the cyber security function', 'Inspect the review reports and confirm findings are tracked to closure.', 'Review reports; finding tracker'),
  C('AC-14', 'audit', ['3.2.5'], ['1-8'], ['CY-07'], 'Cyber security is audited independently (at least every three years) and audit findings are remediated', 'Inspect the audit plan, the last independent audit report and the status of its findings.', 'Audit plan; audit report; finding status'),
  // ---- human resources
  C('AC-15', 'hr', ['3.3.1'], ['1-9'], [], 'Screening is done before employment, and staff sign the confidentiality and acceptable-use terms', 'Sample joiners; check screening, signed NDA and acceptable-use acknowledgment.', 'HR files; signed acknowledgments'),
  C('AC-16', 'grc', ['3.3.1'], ['1-9', '2-2'], ['IT-12', 'CY-21'], 'Leavers hand back assets and their access is removed on their last day', 'Sample leavers; compare the last working day with account disablement and asset return.', 'Leaver list; handover records; account disable dates'),
  // ---- physical
  C('AC-17', 'admin', ['3.3.2'], ['2-14'], [], 'Data centres and comms rooms have controlled access, CCTV and environmental protection', 'Inspect access lists and logs, CCTV retention, fire suppression and environmental monitoring.', 'Access logs; CCTV retention; maintenance records'),
  C('AC-18', 'infra', ['3.3.2'], ['2-14'], ['IT-13'], 'Equipment is maintained and under vendor support or warranty', 'Compare critical equipment with support contracts and warranty dates.', 'Support contracts; warranty register'),
  // ---- assets
  C('AC-19', 'infra', ['3.3.3'], ['2-1'], ['IT-04', 'IT-11'], 'The asset register is complete and accurate (owner, classification, serial number) and matches what is on the network', 'Reconcile the register with discovery; sample assets for owner, classification and serial number.', 'Asset register; reconciliation report'),
  C('AC-20', 'apps', ['3.3.3'], ['2-1'], ['IT-10'], 'Software is licensed and within what is owned', 'Compare deployed software with licence entitlements (Oracle core factor).', 'Licence register; compliance matrix'),
  C('AC-21', 'grc', ['3.3.3'], ['2-7'], [], 'Information is classified and handled according to its classification', 'Inspect the classification policy and sample systems for their classification and handling.', 'Classification scheme; data inventory'),
  // ---- architecture
  C('AC-22', 'cyber', ['3.3.4'], ['2-5'], [], 'A cyber security architecture is defined, with network zones and security controls documented', 'Inspect the architecture document and the network diagram; confirm they match the current estate.', 'Architecture document; network diagrams'),
  // ---- IAM
  C('AC-23', 'cyber', ['3.3.5'], ['2-2'], ['CY-17', 'CY-18'], 'Access is granted on least privilege and need-to-know, approved and reviewed periodically', 'Sample user access reviews of the last period; confirm approvals and that removals were applied.', 'Access requests; access review records'),
  C('AC-24', 'cyber', ['3.3.5'], ['2-2'], ['CY-16'], 'Privileged access is restricted, uses separate accounts and multi-factor authentication, and is monitored', 'Inspect the privileged account list, MFA enforcement and privileged session monitoring.', 'Privileged account list; MFA configuration; PAM logs'),
  C('AC-25', 'cyber', ['3.3.5'], ['2-2'], ['CY-24'], 'Multi-factor authentication protects remote access and internet-facing services', 'Inspect VPN, e-mail and portal sign-in configuration for MFA.', 'MFA configuration; sign-in policy'),
  // ---- application security
  C('AC-26', 'apps', ['3.3.6'], ['2-15', '1-6'], [], 'Applications are developed and acquired securely (secure coding, code review, security testing before release)', 'Sample releases; check for security testing and fixed findings before release.', 'SDLC procedure; test reports'),
  C('AC-27', 'apps', ['3.3.6'], ['2-15'], ['CY-14'], 'Web applications are protected (WAF, TLS, valid certificates) and tested', 'Inspect WAF coverage, TLS configuration and certificate validity of public sites.', 'WAF policy; certificate inventory; scan results'),
  // ---- change
  C('AC-28', 'audit', ['3.3.7'], ['1-6', '2-3'], ['IT-02', 'CY-04'], 'Changes are requested, assessed, approved by a different named person and recorded before they are applied', 'Sample changes in the period; confirm request, risk assessment, independent approval and post-implementation review.', 'Change records; approvals; four-eyes evidence'),
  // ---- infrastructure
  C('AC-29', 'infra', ['3.3.8'], ['2-3'], ['IT-06'], 'Critical security patches are installed within the patch policy timelines', 'Compare patch compliance reports with the policy timelines; sample servers and computers.', 'Patch policy; patch compliance report'),
  C('AC-30', 'infra', ['3.3.8'], ['2-3'], ['CY-15'], 'Servers and computers have endpoint protection and report to central management', 'Compare the endpoint console with the asset register; check coverage and signature currency.', 'Endpoint management console report'),
  C('AC-31', 'infra', ['3.3.8'], ['2-3'], ['CY-19'], 'Systems are hardened against an approved secure configuration baseline', 'Inspect the baselines (CIS or vendor) and the latest configuration compliance scan.', 'Hardening standards; configuration scan'),
  C('AC-32', 'cyber', ['3.3.8', '3.3.4'], ['2-5'], ['CY-10', 'CY-20'], 'Networks are segmented, perimeter rules are reviewed, and nothing critical is exposed to the internet', 'Inspect firewall rule reviews, segmentation and an external exposure scan.', 'Firewall rule review; external scan'),
  C('AC-33', 'cyber', ['3.3.8'], ['2-4'], [], 'E-mail is protected: anti-phishing, anti-malware, SPF / DKIM / DMARC and attachment sandboxing', 'Inspect the e-mail security configuration and the DNS records of the mail domains.', 'Mail security policy; DNS records'),
  C('AC-34', 'infra', ['3.3.8'], ['2-3'], ['IT-14'], 'Capacity is monitored and has room to grow', 'Inspect capacity reports and forecasts for storage and virtualisation.', 'Capacity report'),
  // ---- crypto
  C('AC-35', 'cyber', ['3.3.9'], ['2-8'], ['CY-06', 'CY-12'], 'Cryptography follows an approved standard; keys and stored credentials are protected', 'Inspect the cryptography standard, key custody and how stored credentials are sealed.', 'Cryptography standard; key custody records'),
  C('AC-36', 'platform', ['3.3.9', '3.3.5'], ['2-8', '2-2'], ['CY-13'], 'No secret is stored in clear text in files or scripts', 'Inspect the latest secret-leak scan and its follow-up.', 'Secret-leak scan report'),
  // ---- BYOD / mobile
  C('AC-37', 'cyber', ['3.3.10'], ['2-6'], ['CY-26'], 'Mobile and personal devices that reach company data are enrolled, encrypted and can be wiped', 'Inspect the BYOD / mobile policy and the MDM enrolment report.', 'BYOD policy; MDM report'),
  // ---- disposal
  C('AC-38', 'infra', ['3.3.11'], ['2-7', '2-1'], [], 'Media and equipment are securely wiped or destroyed at disposal, with a certificate', 'Sample disposed assets; check wipe / destruction certificates.', 'Disposal register; destruction certificates'),
  // ---- payment / e-banking (insurer: where applicable)
  C('AC-39', 'apps', ['3.3.12'], ['2-7'], [], 'Card and payment data is protected (PCI DSS where card data is handled), or recorded as not applicable', 'Confirm whether card data is stored, processed or transmitted; if so inspect the PCI DSS evidence.', 'Payment data flow; PCI DSS AoC or not-applicable statement'),
  C('AC-40', 'apps', ['3.3.13'], ['2-15'], [], 'Online customer services (portal, apps) authenticate customers securely and are monitored for fraud, or are recorded as not applicable', 'Inspect customer sign-in controls, session protection and fraud monitoring of the customer portal.', 'Portal security configuration; fraud monitoring'),
  // ---- event management
  C('AC-41', 'cyber', ['3.3.14'], ['2-12'], ['IT-01', 'CY-05', 'CY-11'], 'Security events are logged from every critical asset, kept intact, and monitored by the SOC', 'Compare log sources with critical assets; confirm retention and that the audit trail is intact.', 'Log source coverage; retention configuration; audit trail verification'),
  C('AC-42', 'cyber', ['3.3.14'], ['2-12'], ['IT-17'], 'Logs are retained for at least the required period (12 months or as regulation requires)', 'Inspect SIEM retention settings and the oldest searchable record.', 'Retention settings'),
  // ---- incidents
  C('AC-43', 'cyber', ['3.3.15'], ['2-13'], ['CY-09'], 'Incidents are detected, triaged and handled within the defined SLA, following an approved response plan', 'Sample incidents; compare detection, acknowledgement and resolution times with the SLA.', 'Incident response plan; incident records; SLA report'),
  C('AC-44', 'cyber', ['3.3.15'], ['2-13', '1-7'], [], 'Significant incidents are reported to SAMA / IA / NCA within the required time', 'Sample reportable incidents; confirm the notification and its timing.', 'Regulator notifications'),
  // ---- threat
  C('AC-45', 'cyber', ['3.3.16'], ['2-13'], [], 'Threat intelligence is collected, assessed and acted on', 'Inspect the threat intelligence sources and examples of actions taken.', 'Threat intel feeds; action records'),
  // ---- vulnerability
  C('AC-46', 'cyber', ['3.3.17'], ['2-10'], ['CY-01', 'CY-03'], 'Vulnerabilities are scanned and remediated on time; end-of-life systems are isolated or have an approved exception', 'Inspect scan coverage, remediation times and the end-of-life list with exceptions.', 'Vulnerability reports; exception register'),
  C('AC-47', 'cyber', ['3.3.17'], ['2-11'], ['CY-02'], 'Penetration tests and VAPT are done on time (critical systems quarterly, others twice a year) and findings fixed', 'Inspect the testing schedule, the reports and the remediation of findings.', 'Testing schedule; pentest reports; remediation status'),
  // ---- third party / outsourcing / cloud
  C('AC-48', 'grc', ['3.4.1'], ['4-1'], ['IT-07'], 'Contracts with vendors include cyber security requirements and are current', 'Sample vendor contracts for security clauses, right to audit and expiry.', 'Vendor contracts; vendor register'),
  C('AC-49', 'grc', ['3.4.1'], ['4-1'], [], 'Vendors are assessed for cyber security before onboarding and periodically', 'Sample vendors; inspect the security assessment.', 'Vendor assessments'),
  C('AC-50', 'grc', ['3.4.2'], ['4-1'], [], 'Material outsourcing is approved by the regulator where required and its risks are managed', 'Inspect the outsourcing register and regulator approvals.', 'Outsourcing register; approvals'),
  C('AC-51', 'cyber', ['3.4.3'], ['4-2', '2-7'], ['CY-14'], 'Cloud services are approved, and data residency stays in the Kingdom unless a transfer basis is recorded (PDPL)', 'Inspect the cloud service register, hosting locations and PDPL transfer records.', 'Cloud register; hosting locations; transfer assessments'),
  // ---- backup / BCM
  C('AC-52', 'infra', ['3.3.8', 'BCM'], ['2-9'], ['IT-05'], 'Backups are taken, succeed, are protected and are restored in tests', 'Inspect backup job results and restore test records.', 'Backup reports; restore tests'),
  C('AC-53', 'infra', ['BCM'], ['3-1'], ['IT-09', 'IT-18'], 'Business continuity and disaster recovery plans are approved and tested; drills pass and are signed off', 'Inspect the BCP / DRP, the drill schedule and the results.', 'BCP; DRP; drill reports'),
  // ---- data protection
  C('AC-54', 'grc', ['3.3.3', '3.2.2'], ['2-7'], [], 'Personal data is processed under PDPL: records of processing, purpose, retention and data subject requests', 'Inspect the records of processing, the retention schedule and the data subject request log.', 'RoPA; retention schedule; DSR log'),
  C('AC-55', 'cyber', ['3.3.8'], ['2-7'], [], 'Data leakage is prevented and monitored (DLP)', 'Inspect DLP policies, coverage and incident handling.', 'DLP policy; DLP incidents'),
  // ---- IA circular
  C('AC-56', 'cyber', ['3.3.15'], ['2-13'], [], 'A dedicated cyber-incident contact mailbox, not tied to one employee, is registered with the Insurance Authority', 'Confirm the mailbox exists, is monitored by more than one person and was given to the IA.', 'Mailbox configuration; IA notification'),
  C('AC-57', 'apps', ['3.3.5', '3.3.14'], ['2-2', '2-12'], ['IT-15'], 'Databases audit privileged and account activity, the audit trail cannot be switched off unseen, and DBA work is matched to approved changes', 'Inspect the database audit configuration (unified audit policies), the audit trail coverage and a sample of privileged actions against changes.', 'Database audit configuration; audit trail report; change records'),
  C('AC-58', 'apps', ['3.3.6', '3.3.7', 'BCM'], ['2-15', '2-12', '3-1'], ['IT-16'], 'Business applications have no unaccepted single point of failure, are changed under four-eyes control and every server is logged', 'Inspect the application inventory, resilience design, change records of the period and log coverage per server.', 'Application inventory; change records; log coverage'),
  // what a human IT auditor asks next (PBC staples), automated where the platform holds the evidence
  C('AC-59', 'audit', ['3.3.7'], ['1-6', '2-3'], [], 'Emergency changes are approved retrospectively within the defined time and reviewed', 'Sample emergency changes in the period; confirm retrospective approval by a different person and a post-implementation review.', 'Emergency change records; CAB minutes'),
  C('AC-60', 'apps', ['3.3.6', '3.3.7'], ['2-15', '2-3'], [], 'Development, test and production are separated; developers have no standing access to production', 'Inspect the environment design and production access lists; sample developers for production rights.', 'Environment diagram; production access list'),
  C('AC-61', 'cyber', ['3.4.1', '3.3.5'], ['4-1', '2-2'], ['CY-25'], 'Third-party and vendor remote access is approved, time-bound, uses MFA and is monitored', 'Inspect the vendor access list, VPN / remote tool accounts, their expiry and session logs.', 'Vendor access register; VPN accounts; session logs'),
  C('AC-62', 'infra', ['3.3.5'], ['2-2'], ['CY-22'], 'No shared, generic or default account is used; built-in accounts are disabled or renamed and kept for break-glass', 'Inspect AD and system accounts for generic names, built-in Administrator / Guest status and break-glass records.', 'Account listing; break-glass log'),
  C('AC-63', 'infra', ['3.3.7', '3.3.8'], ['2-3'], ['CY-23'], 'Configuration changes to network and security devices are detected and each one is matched to an approved change', 'Compare configuration change history with the change register for the period.', 'Configuration history; change register'),
  C('AC-64', 'cyber', ['3.3.14'], ['2-12'], [], 'Security logs and alerts are reviewed daily by the SOC and the review is evidenced', 'Sample days in the period; inspect the SOC shift reports, alert handling and sign-offs.', 'SOC shift reports; alert queue history'),
  C('AC-65', 'infra', ['3.3.8', '3.3.14'], ['2-3', '2-12'], ['CY-19'], 'Systems synchronise time from approved sources so logs can be correlated', 'Inspect NTP configuration on servers, network devices and the SIEM.', 'NTP configuration'),
  C('AC-66', 'cyber', ['3.3.8'], ['2-6', '2-8'], ['CY-26'], 'Laptops and removable media holding company data are encrypted', 'Inspect the encryption policy and the device compliance report (BitLocker / FileVault / Intune).', 'Encryption policy; Intune compliance report'),
  C('AC-67', 'audit', ['3.2.5'], ['1-8'], ['IT-19'], 'Evidence requested by the auditors (PBC list) is provided completely and on time', 'Inspect the evidence request list: due dates, responses and rejected items.', 'PBC list with responses')
];
// AC-56 also answers IA-277
for (const c of CHECKS) { c.ia = c.sama.slice(); if (c.id === 'AC-56') c.ia.push('IA-277'); }

const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];

function createChecklist(app, opts = {}) {
  const now = opts.now || Date.now, col = () => app.store.collection('audit_checklist');
  const A = () => (app.addons || {}).auditors;
  function autoOf(c) {
    if (!c.auto.length) return null;
    const AU = A(); if (!AU) return { state: 'not_tested', tests: c.auto.map((id) => ({ id, state: 'not_run', detail: 'AI auditors not installed' })) };
    const all = {}; for (const id of ['itaudit', 'cyberaudit']) for (const t of AU.programme(id, false).tests) all[t.id] = t;
    const tests = c.auto.map((id) => { const t = all[id]; return t ? { id, title: t.title, state: t.state, detail: t.detail, findings: t.findings } : { id, state: 'not_run', detail: 'not in the programme' }; });
    const state = tests.some((t) => t.state === 'fail') ? 'fail' : tests.some((t) => t.state === 'pass') ? 'pass' : 'not_tested';
    return { state, tests };
  }
  function resultOf(c, op) {
    const auto = autoOf(c), m = col().get(c.id), due = m ? Date.parse(m.at) + VALID_DAYS * DAY : null, expired = m && due < now();
    let result, why;
    if (auto && auto.state === 'fail') { result = 'non_compliant'; why = 'an AI auditor test fails: ' + auto.tests.filter((t) => t.state === 'fail').map((t) => t.id).join(', '); }
    else if (m && !expired) { result = m.status; why = 'assessed by the auditor'; }
    else if (auto && auto.state === 'pass') { result = 'auto_pass'; why = 'automated test passed - auditor to confirm'; }
    else { result = 'not_assessed'; why = m && expired ? 'the last assessment is over 12 months old - re-assess' : 'not assessed yet'; }
    const conflict = !!(auto && auto.state === 'fail' && m && !expired && (m.status === 'compliant' || m.status === 'not_applicable'));
    const assessment = m ? (op ? { status: m.status, evidence: m.evidence || '', note: m.note || '', by: m.by, role: m.role, at: m.at, due: new Date(due).toISOString(), expired: !!expired } : { status: m.status, at: m.at, due: new Date(due).toISOString(), expired: !!expired }) : null;
    return { id: c.id, title: c.title, procedure: c.procedure, evidence_expected: c.evidence, owner: c.owner, owner_name: DEPT[c.owner], sama: c.sama, nca: c.nca, ia: c.ia, auto, assessment, result, why, conflict };
  }
  function view(fw, op) {
    const F = FW[fw]; if (!F) throw httpErr(400, 'fw must be one of: sama, nca, ia');
    const rows = CHECKS.map((c) => resultOf(c, op));
    const RANK = { non_compliant: 5, not_assessed: 4, partial: 3, auto_pass: 2, compliant: 1, not_applicable: 0 };
    const domains = Object.keys(F.domains).map((code) => {
      const ids = rows.filter((r) => r[fw].includes(code)).map((r) => r.id), rs = rows.filter((r) => ids.includes(r.id));
      const worst = rs.reduce((w, r) => (RANK[r.result] > RANK[w] ? r.result : w), 'not_applicable');
      return { code, name: F.domains[code], checks: ids, result: rs.length ? worst : 'not_assessed' };
    });
    const counts = { compliant: 0, partial: 0, non_compliant: 0, not_applicable: 0, auto_pass: 0, not_assessed: 0 };
    const inFw = rows.filter((r) => r[fw].length); for (const r of inFw) counts[r.result]++;
    const scored = counts.compliant + counts.partial + counts.non_compliant + counts.auto_pass + counts.not_assessed;
    return { fw, name: F.name, basis: F.basis || null, generated_at: new Date(now()).toISOString(), checks: inFw, domains, counts,
      compliance_pct: scored ? Math.round((counts.compliant + counts.partial / 2) / scored * 1000) / 10 : null,
      assessed_pct: inFw.length ? Math.round((inFw.length - counts.not_assessed - counts.auto_pass) / inFw.length * 100) : null,
      note: 'Compliance % counts only what a person confirmed (partial = half); an automated pass awaits confirmation and a check not assessed counts against. The mapping is domain-level: a draft for the compliance team to verify, not a certification.' };
  }
  function assess(b, who) {
    const c = CHECKS.find((x) => x.id === b.id); if (!c) throw httpErr(404, 'no audit check ' + b.id);
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot record an audit assessment');
    const prev = col().get(c.id) || null;
    const rec = { id: c.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: new Date(now()).toISOString() };
    col().put(rec);
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'audit.checklist.assess', target: c.id, detail: { status: b.status, previous: prev ? prev.status : null, evidence: rec.evidence.slice(0, 200) } });
    return resultOf(c, true);
  }
  // ---- evidence requests (PBC list)
  const pbc = () => app.store.collection('audit_pbc');
  const OPEN = new Set(['not_assessed', 'non_compliant', 'partial', 'auto_pass']);
  const dayEnd = (d) => Date.parse(String(d).slice(0, 10) + 'T23:59:59Z');
  function requestOf(r, op) {
    const q = pbc().get(r.id) || null;
    const overdue = !!(q && q.state === 'issued' && q.due && dayEnd(q.due) < now());
    return { ref: 'PBC-' + r.id, id: r.id, title: r.title, owner: r.owner, owner_name: r.owner_name, evidence_expected: r.evidence_expected, procedure: r.procedure,
      result: r.result, why: r.why, failing_tests: r.auto ? r.auto.tests.filter((t) => t.state === 'fail').map((t) => t.id) : [],
      state: q ? q.state : 'not_issued', overdue, days_overdue: overdue ? Math.floor((now() - dayEnd(q.due)) / DAY) : 0, due: q ? q.due : null, issued_at: q ? q.issued_at : null,
      issued_by: q && op ? q.issued_by : undefined, response: q && q.response && op ? q.response : undefined, decision: q && q.decision && op ? q.decision : undefined };
  }
  function requests(fw, op) {
    const v = view(fw, true);
    const items = v.checks.filter((r) => OPEN.has(r.result) || (r.assessment && r.assessment.expired) || (pbc().get(r.id) && pbc().get(r.id).state !== 'accepted')).map((r) => requestOf(r, op));
    const by_state = { not_issued: 0, issued: 0, provided: 0, accepted: 0, overdue: 0 }, by_owner = {};
    for (const x of items) { by_state[x.state] = (by_state[x.state] || 0) + 1; if (x.overdue) by_state.overdue++; const o = by_owner[x.owner_name] = by_owner[x.owner_name] || { open: 0, overdue: 0 }; if (x.state !== 'accepted') o.open++; if (x.overdue) o.overdue++; }
    return { fw, name: v.name, generated_at: new Date(now()).toISOString(), items, by_state, by_owner,
      note: 'A request asks the owning department for the evidence the check expects. Accepting the evidence does not by itself make the check compliant: the auditor then assesses the check.' };
  }
  const human = (who) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot act on an evidence request'); };
  const log = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  function issue(b, who) {
    human(who);
    const today = new Date(now()).toISOString().slice(0, 10), max = new Date(now() + 90 * DAY).toISOString().slice(0, 10);
    if (b.due < today || b.due > max) throw httpErr(400, 'due must be between ' + today + ' and ' + max);
    const list = requests(b.fw, true).items.filter((x) => (!b.ids || !b.ids.length || b.ids.includes(x.id)) && (x.state === 'not_issued' || x.state === 'issued'));
    if (b.ids && b.ids.length) { const known = new Set(list.map((x) => x.id)); const bad = b.ids.filter((i) => !known.has(i)); if (bad.length) throw httpErr(409, 'not an open, unanswered request in ' + b.fw + ': ' + bad.join(', ')); }
    const at = new Date(now()).toISOString();
    for (const x of list) { const q = pbc().get(x.id); pbc().put(Object.assign({}, q || {}, { id: x.id, state: 'issued', due: b.due, issued_at: (q && q.issued_at) || at, issued_by: who.user, reissued_at: q ? at : undefined })); }
    log(who, 'audit.pbc.issue', b.fw, { due: b.due, requests: list.length, ids: list.map((x) => x.id).slice(0, 80) });
    return { issued: list.length, due: b.due };
  }
  function respond(b, who) {
    human(who);
    const q = pbc().get(b.id); if (!q) throw httpErr(404, 'no evidence request issued for ' + b.id);
    if (q.state !== 'issued') throw httpErr(409, 'request ' + b.id + ' is ' + q.state + ' - only an issued request can be answered');
    const rec = Object.assign({}, q, { state: 'provided', response: { reference: b.reference, note: b.note || '', by: who.user, at: new Date(now()).toISOString(), late: !!(q.due && dayEnd(q.due) < now()) } });
    pbc().put(rec); log(who, 'audit.pbc.respond', b.id, { reference: b.reference.slice(0, 200), late: rec.response.late });
    return { id: b.id, state: rec.state, response: rec.response };
  }
  function decide(b, who) {
    human(who);
    const q = pbc().get(b.id); if (!q) throw httpErr(404, 'no evidence request issued for ' + b.id);
    if (q.state !== 'provided') throw httpErr(409, 'request ' + b.id + ' is ' + q.state + ' - only provided evidence can be accepted or rejected');
    if (String(q.response.by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who provided the evidence cannot accept or reject it');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say what is missing from the evidence');
    const decision = { decision: b.decision, note: b.note || '', by: who.user, at: new Date(now()).toISOString() };
    const rec = Object.assign({}, q, { state: b.decision === 'accept' ? 'accepted' : 'issued', decision, history: (q.history || []).concat([{ response: q.response, decision }]).slice(-20) });
    if (b.decision === 'reject') delete rec.response;
    pbc().put(rec); log(who, 'audit.pbc.' + b.decision, b.id, { note: decision.note.slice(0, 200), reference: q.response.reference.slice(0, 200) });
    return { id: b.id, state: rec.state, decision };
  }
  return { view, assess, requests, issue, respond, decide, CHECKS, FW };
}

function registerChecklistRoutes(srv, app, CL) {
  const { body } = require('./check');
  const isOp = (ctx) => ctx.who && (ctx.who.role === 'operator' || ctx.who.role === 'admin');
  srv.route('GET', '/audit-checklist', (ctx) => {
    ctx.need('viewer');
    const q = body(ctx.query || {}).oneOf('fw', ['sama', 'nca', 'ia'], { def: 'sama' }).done();
    return CL.view(q.fw, isOp(ctx));
  });
  srv.route('POST', '/audit-checklist/assess', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', { required: true, re: /^AC-\d{2}$/, msg: 'id must be an audit check id (AC-nn)' }).oneOf('status', STATUSES, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for a compliant or partially compliant result' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why the control does not apply' : null)).done();
    return CL.assess(b, ctx.who);
  });
  srv.route('GET', '/audit-checklist/requests', (ctx) => {
    ctx.need('operator');
    const q = body(ctx.query || {}).oneOf('fw', ['sama', 'nca', 'ia'], { def: 'sama' }).done();
    return CL.requests(q.fw, true);
  });
  const ID = { required: true, re: /^AC-\d{2}$/, msg: 'id must be an audit check id (AC-nn)' };
  srv.route('POST', '/audit-checklist/requests/issue', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('fw', ['sama', 'nca', 'ia'], { required: true }).date('due', { required: true }).list('ids', { max: 200, item: 'id' })
      .rule((o) => ((o.ids || []).some((i) => !/^AC-\d{2}$/.test(i)) ? 'ids must be audit check ids (AC-nn)' : null)).done();
    return CL.issue(b, ctx.who);
  });
  srv.route('POST', '/audit-checklist/requests/respond', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', ID).str('reference', { required: true, max: 300 }).str('note', { max: 1000 }).done();
    return CL.respond(b, ctx.who);
  });
  srv.route('POST', '/audit-checklist/requests/decide', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', ID).oneOf('decision', ['accept', 'reject'], { required: true }).str('note', { max: 1000 }).done();
    return CL.decide(b, ctx.who);
  });
}

module.exports = { createChecklist, registerChecklistRoutes, CHECKS, FW, STATUSES };
