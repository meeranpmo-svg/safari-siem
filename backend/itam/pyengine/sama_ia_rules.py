# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""SAMA Cyber Security Framework and Insurance Authority (IA) automated assessment. Python decides, Node.js commits
(engine/sama-ia.js): this module reads only what it is given and writes nothing.

  sama.view  {facts, profile, ecc_profile, confirms, ecc_confirms, history, settings, now}
             -> 4 domains, 32 subdomains, the assessable requirements with their evidence PILLAR (GRC, Hardening, Pentest /
                VAPT, SIEM logs, Operations), an indicative SAMA maturity level per subdomain, the IA view, the pillars'
                coverage, the trend and forecast, and the remediation priorities

One evidence collection: the automated checks are the NCA ECC register's own (nca_ecc_rules), run on the same facts, plus
the SIEM's SAMA control statuses, continuous control monitoring and the audit teams' findings - so SAMA, NCA ECC and ISO
27001 can never disagree about the same evidence. A manual requirement a person confirmed and a second person approved in
the NCA ECC register counts here too (its id is named), so nobody records the same evidence twice.

Results, as in the ECC register: verified / gap from automated evidence (a gap is never hidden by a confirmation), met /
partial / gap from a person's confirmation approved by a second person, pending while waiting for that approval,
not_measured when the source is not connected, no_evidence when nothing shows it yet.

Maturity (SAMA's six levels, 0 non-existent .. 5 adaptive; SAMA expects at least level 3 "structured and formalized") is
INDICATIVE, from this register: the rule for each level is printed with the result. It is not SAMA's or an auditor's rating.

Learning from history (one snapshot a day): the chance that a requirement is a gap at the next run is the posterior mean of
a Beta(1,1) prior updated with its last 30 runs; a requirement that was met and is now a gap is a regression; the score's
trend is a least-squares line over the runs, forecast 30 days ahead only with 3 runs or more. Priorities = severity x how far
from met x (1 + chance of a gap) (+1 for a regression), with every factor shown. Standard library only.
"""
from datetime import datetime, timezone

import nca_ecc_rules as E
from org_brand import fill as _org_fill

DAY = 86400000
_n = E._n
_src = E._src

DOMAINS = {'3.1': 'Cyber Security Leadership and Governance', '3.2': 'Cyber Security Risk Management and Compliance',
           '3.3': 'Cyber Security Operations and Technology', '3.4': 'Third Party Cyber Security'}
SUB = {
    '3.1.1': 'Cyber Security Governance', '3.1.2': 'Cyber Security Strategy', '3.1.3': 'Cyber Security Policy',
    '3.1.4': 'Cyber Security Roles and Responsibilities', '3.1.5': 'Cyber Security in Project Management',
    '3.1.6': 'Cyber Security Awareness', '3.1.7': 'Cyber Security Training', '3.2.1': 'Cyber Security Risk Management',
    '3.2.2': 'Regulatory Compliance', '3.2.3': 'Compliance with International Industry Standards', '3.2.4': 'Cyber Security Review',
    '3.2.5': 'Cyber Security Audits', '3.3.1': 'Human Resources', '3.3.2': 'Physical Security', '3.3.3': 'Asset Management',
    '3.3.4': 'Cyber Security Architecture', '3.3.5': 'Identity and Access Management', '3.3.6': 'Application Security',
    '3.3.7': 'Change Management', '3.3.8': 'Infrastructure Security', '3.3.9': 'Cryptography', '3.3.10': 'Bring Your Own Device (BYOD)',
    '3.3.11': 'Secure Disposal of Information Assets', '3.3.12': 'Payment Systems', '3.3.13': 'Electronic Banking Services',
    '3.3.14': 'Cyber Security Event Management', '3.3.15': 'Cyber Security Incident Management', '3.3.16': 'Threat Management',
    '3.3.17': 'Vulnerability Management', '3.4.1': 'Contract and Vendor Management', '3.4.2': 'Outsourcing', '3.4.3': 'Cloud Computing',
}
# subdomains whose applicability to an insurer the CISO decides (payment systems and e-banking are bank services)
DECIDE = ['3.3.12', '3.3.13']
PILLARS = {'grc': 'GRC', 'hardening': 'Hardening', 'pentest': 'Pentest / VAPT', 'siem': 'SIEM logs', 'ops': 'Operations'}
TARGET = 3
LEVELS = {0: 'Non-existent', 1: 'Ad-hoc', 2: 'Repeatable but informal', 3: 'Structured and formalized', 4: 'Managed and measurable', 5: 'Adaptive'}


def _ecc(fn):
    """an NCA ECC check run with the ECC profile (CISO, strategy, committee live there)"""
    return lambda f, pr, now: fn(f, pr.get('_ecc') or {}, now)


def s_siem(ids, what):
    return lambda f, pr, now: E._siem_sama(f, ids, what)


def s_hardening_cov(f, pr, now):
    h = _src(f, 'hardening')
    if not h or not _n(h.get('assets')):
        return None, 'not measured: no asset in the hardening register (Hardening -> scan)'
    cov, want = h.get('coverage_pct'), _n((pr.get('_settings') or {}).get('hardening_coverage_pct') or 90)
    if cov is None:
        return None, 'not measured: no asset scanned for hardening yet'
    return (True, str(cov) + ' % of ' + str(_n(h.get('assets'))) + ' assets assessed against the hardening baseline') if _n(cov) >= want \
        else (False, 'only ' + str(cov) + ' % of ' + str(_n(h.get('assets'))) + ' assets assessed against the hardening baseline (target ' + str(want) + ' %)')


def s_hardening_critical(f, pr, now):
    h = _src(f, 'hardening')
    if not h or h.get('score') is None:
        return None, 'not measured: no hardening result yet'
    c = _n(h.get('critical_fail'))
    return (False, str(c) + ' critical hardening failure(s) open across scanned assets') if c else (True, 'no critical hardening failure on scanned assets (score ' + str(h.get('score')) + ')')


def s_ccm(tests, what):
    def fn(f, pr, now):
        c = _src(f, 'ccm')
        if not c or not c.get('run'):
            return None, 'not measured: continuous control monitoring has not run yet (Audit -> Control Monitoring)'
        st = {t.get('id'): t for t in c.get('tests') or []}
        got = [st[t] for t in tests if t in st and st[t].get('status') != 'not_testable']
        if not got:
            return None, 'not measured: nothing to test yet for ' + what
        bad = [t['id'] + ' ' + t.get('name', '') + ' (' + str(t.get('exceptions')) + ' exception(s))' for t in got if t.get('status') == 'exceptions']
        return (False, 'control monitoring: ' + '; '.join(bad)) if bad else (True, 'control monitoring: ' + ', '.join(t['id'] for t in got) + ' effective over the whole audit trail')
    return fn


def s_audit(f, pr, now):
    a = _src(f, 'audit')
    if not a or a.get('teams') is None:
        return None, 'not measured: no audit team is set up (Audit -> IT / Cyber / Internal Audit Team)'
    if not _n(a.get('engagements')):
        return False, 'no audit engagement started yet (plan, fieldwork, report)'
    o = _n(a.get('overdue'))
    return (False, str(o) + ' audit finding(s) past their due date') if o else (True, str(_n(a.get('engagements'))) + ' audit engagement(s) under way or reported, no finding overdue')


def s_pdpl(f, pr, now):
    p = _src(f, 'pdpl')
    if not p or p.get('compliance_pct') is None:
        return None, 'not measured: the PDPL register has not been assessed'
    pct = _n(p.get('compliance_pct'))
    return (True, 'PDPL register ' + str(pct) + ' % compliant') if pct >= 80 else (False, 'PDPL register only ' + str(pct) + ' % compliant (Personal Data Protection Law)')


def _inf(f, k):
    i = (f or {}).get('infra') or {}
    v = i.get(k)
    return v if isinstance(v, dict) else None


def s_leavers(f, pr, now):
    o = _inf(f, 'offboarding')
    if not o:
        return None, 'not measured: HR offboarding is not in use (User Desktops -> HR Offboarding)'
    if not _n(o.get('total')):
        return None, 'not measured: no leaver has gone through HR offboarding yet'
    bad = _n(o.get('overdue')) + _n(o.get('failed'))
    return (False, str(bad) + ' leaver(s) past their last day whose account is not disabled (or the disable failed)') if bad else (True, str(_n(o.get('total'))) + ' leaver(s) offboarded, every account disabled by the last day')


def s_access_reviews(f, pr, now):
    a = _inf(f, 'access_reviews')
    if not a or not _n(a.get('campaigns')):
        return None, 'not measured: no user access review campaign yet (Identity & Sign-in -> Access Reviews)'
    if _n(a.get('overdue')):
        return False, str(_n(a.get('overdue'))) + ' access review campaign(s) past their due date'
    d = a.get('last_done_days')
    if d is None or d > 100:
        return False, 'no access review campaign closed in the last quarter' + ('' if d is None else ' (last one ' + str(d) + ' days ago)')
    if _n(a.get('removal_failed')):
        return False, str(_n(a.get('removal_failed'))) + ' access removal(s) decided in a review failed'
    return True, 'quarterly access review closed ' + str(d) + ' days ago, removals applied'


def s_pam(f, pr, now):
    m = _inf(f, 'pam')
    if not m or not m.get('connected') or not _n(m.get('groups')):
        return None, 'not measured: just-in-time privileged access is not set up (Identity & Sign-in -> Privileged Access)'
    if _n(m.get('expire_failed')):
        return False, str(_n(m.get('expire_failed'))) + ' privileged grant(s) whose removal at expiry failed'
    return True, str(_n(m.get('groups'))) + ' privileged group(s) granted just in time, with approval, and removed at expiry'


def s_nhi(f, pr, now):
    n = _inf(f, 'nhi')
    if not n or not n.get('connected'):
        return None, 'not measured: the directory / Entra service accounts are not read (Identity & Sign-in -> Non-Human Identities)'
    bad = [str(_n(n.get(k))) + ' ' + w for k, w in (('no_owner', 'without an owner'), ('old_secret', 'with an old secret / kerberoastable'), ('expiring', 'with an expiring or expired credential')) if _n(n.get(k))]
    return (False, 'service accounts: ' + ', '.join(bad)) if bad else (True, str(_n(n.get('total'))) + ' service accounts owned and rotated')


def s_mdm(f, pr, now):
    m = _inf(f, 'mdm')
    if not m:
        return None, 'not measured: mobile device management is not configured (Connections & Setup -> MDM)'
    return (True, 'mobile devices are managed (MDM / Intune connected; wipe on leaving is part of offboarding)') if m.get('ready') else (None, 'not measured: the MDM connection is not ready (Connections & Setup -> MDM)')


def s_internal_scan(f, pr, now):
    v = _inf(f, 'vulnscan')
    if not v or not v.get('connected'):
        return None, 'not measured: internal Greenbone scans are not connected (Pentest & Vulnerabilities -> Vulnerability Scans)'
    if not v.get('last_scan'):
        return False, 'the internal scanner is connected but has never completed a scan'
    c, h = _n(v.get('critical')), _n(v.get('high'))
    return (False, 'internal scans: ' + str(c) + ' critical and ' + str(h) + ' high finding(s) open') if (c or h) else (True, 'internal scans: no critical or high finding open (last scan ' + str(v.get('last_scan'))[:10] + ')')


def s_eol(f, pr, now):
    l = _inf(f, 'lifecycle')
    if not l:
        return None, 'not measured: the end-of-life register is not available (Assets -> Lifecycle)'
    need = _n(l.get('isolation_required'))
    if need:
        return False, str(need) + ' end-of-life system(s) need isolation and are neither isolated nor under an approved exception'
    return True, str(_n(l.get('eol'))) + ' end-of-life system(s), every one isolated or under an approved exception'


POL = E.a_policy
# (id, subdomain, requirement, evidence a person shows, pillar, automated check or None, severity, NCA ECC control whose approved
#  confirmation also counts here)
R = [
    ('SA-3.1.1-01', '3.1.1', 'A cyber security function is established under a full-time CISO, independent of IT', 'CISO appointment; organisation chart', 'grc', _ecc(E.a_ciso), 'high', 'ZS-1-2-01'),
    ('SA-3.1.1-02', '3.1.1', 'A cyber security committee mandated by the board meets and records its decisions', 'committee charter; minutes', 'grc', _ecc(E.a_committee), 'medium', 'ZS-1-2-02'),
    ('SA-3.1.2-01', '3.1.2', 'A cyber security strategy aligned with the business is approved and reviewed', 'approved strategy; roadmap', 'grc', _ecc(E.a_strategy), 'high', 'ZS-1-1-01'),
    ('SA-3.1.3-01', '3.1.3', 'Cyber security policies are approved, published and reviewed on schedule', 'policy set with review dates', 'grc', E.a_policies_current, 'high', 'ZS-1-3-01'),
    ('SA-3.1.3-02', '3.1.3', 'Policy owners attest that their policies are followed', 'owner attestations', 'grc', E.a_attested, 'medium', 'ZS-1-3-02'),
    ('SA-3.1.4-01', '3.1.4', 'Cyber security roles and responsibilities are defined, assigned and approved', 'RACI; role assignments', 'grc', E.a_roles, 'medium', 'ZS-1-4-01'),
    ('SA-3.1.5-01', '3.1.5', 'Cyber security requirements are part of projects (risk assessment, security testing before go-live)', 'project security reviews', 'grc', None, 'medium', 'ZS-1-6-01'),
    ('SA-3.1.6-01', '3.1.6', 'A cyber security awareness programme runs for all staff, with records', 'awareness plan; attendance', 'grc', E.a_training, 'medium', 'ZS-1-10-01'),
    ('SA-3.1.7-01', '3.1.7', 'Staff in cyber security and sensitive roles receive specialised training', 'training records', 'grc', None, 'low', 'ZS-1-10-02'),
    ('SA-3.2.1-01', '3.2.1', 'Cyber security risks are identified, assessed and reviewed in a risk register', 'risk register; methodology', 'grc', E.a_risk, 'high', 'ZS-1-5-01'),
    ('SA-3.2.1-02', '3.2.1', 'Risk treatment actions are tracked to closure on time', 'action register', 'grc', E.a_actions, 'medium', 'ZS-1-5-02'),
    ('SA-3.2.2-01', '3.2.2', 'Applicable laws and regulations (SAMA, IA, NCA, PDPL) are identified and complied with', 'legal and regulatory register', 'grc', POL(r'compliance|regulatory', 'compliance policy'), 'high', 'ZS-1-7-01'),
    ('SA-3.2.2-02', '3.2.2', 'Personal data is protected as the PDPL requires', 'PDPL compliance', 'grc', s_pdpl, 'high', 'ZS-2-7-02'),
    ('SA-3.2.3-01', '3.2.3', 'International standards (ISO 27001, CIS benchmarks) are adopted where relevant', 'standards register; baseline', 'hardening', s_hardening_cov, 'medium', None),
    ('SA-3.2.4-01', '3.2.4', 'Cyber security controls are reviewed periodically and continuously monitored', 'review reports', 'grc', s_ccm(['CT-01', 'CT-02', 'CT-06'], 'segregation of duties, approvals and trail integrity'), 'medium', None),
    ('SA-3.2.5-01', '3.2.5', 'Cyber security is audited independently, and audit findings are closed on time', 'audit plan; reports', 'grc', s_audit, 'medium', 'ZS-1-8-01'),
    ('SA-3.3.1-01', '3.3.1', 'Cyber security is covered before, during and at the end of employment', 'HR procedure; leaver records', 'ops', s_leavers, 'medium', 'ZS-1-9-01'),
    ('SA-3.3.2-01', '3.3.2', 'Physical access to data centres and sensitive areas is controlled and logged', 'access logs; visitor records', 'ops', None, 'medium', 'ZS-2-14-01'),
    ('SA-3.3.3-01', '3.3.3', 'An inventory of information assets is kept current', 'asset register', 'ops', E.a_assets, 'high', 'ZS-2-1-01'),
    ('SA-3.3.3-02', '3.3.3', 'Every asset has a named owner', 'ownership matrix', 'ops', E.a_owners, 'medium', 'ZS-2-1-02'),
    ('SA-3.3.4-01', '3.3.4', 'Networks are segmented and protected by firewalls and intrusion prevention', 'network diagram; firewall review', 'siem', E.a_netsec, 'high', 'ZS-2-5-01'),
    ('SA-3.3.5-01', '3.3.5', 'Access follows least privilege; MFA for remote and privileged access', 'access policy; MFA configuration', 'siem', E.a_privileged, 'high', 'ZS-2-2-01'),
    ('SA-3.3.5-02', '3.3.5', 'Nobody approves their own access or change; roles are not self-granted', 'access reviews; approval records', 'grc', s_ccm(['CT-01', 'CT-07', 'CT-08'], 'segregation of duties and role changes'), 'high', 'ZS-2-2-02'),
    ('SA-3.3.5-03', '3.3.5', 'An identity and access management policy is approved', 'IAM policy', 'grc', POL(r'access (control|management)|identity', 'access control policy'), 'medium', 'ZS-2-2-03'),
    ('SA-3.3.5-04', '3.3.5', 'User access is reviewed every quarter and access no longer needed is removed', 'access review campaigns; sign-offs', 'grc', s_access_reviews, 'high', None),
    ('SA-3.3.5-05', '3.3.5', 'Privileged access is granted just in time, approved by a second person and removed at expiry', 'PAM requests and approvals', 'ops', s_pam, 'high', None),
    ('SA-3.3.5-06', '3.3.5', 'Service accounts and app registrations have owners and rotated credentials', 'non-human identity register', 'ops', s_nhi, 'medium', None),
    ('SA-3.3.6-01', '3.3.6', 'Secure development standards apply to in-house and outsourced applications', 'secure SDLC standard', 'grc', POL(r'secure (software )?development|sdlc|application', 'secure development policy'), 'medium', 'ZS-1-6-02'),
    ('SA-3.3.6-02', '3.3.6', 'Web applications are protected and tested before go-live', 'WAF; test reports', 'pentest', None, 'high', 'ZS-2-15-01'),
    ('SA-3.3.7-01', '3.3.7', 'Changes are approved by someone other than the requester and recorded', 'change records', 'grc', s_ccm(['CT-01', 'CT-02'], 'change approvals'), 'medium', None),
    ('SA-3.3.8-01', '3.3.8', 'Servers, workstations and network devices are hardened to an approved baseline', 'hardening results', 'hardening', E.a_hardening, 'high', 'ZS-2-3-01'),
    ('SA-3.3.8-02', '3.3.8', 'No critical hardening failure is left open', 'hardening results', 'hardening', s_hardening_critical, 'high', None),
    ('SA-3.3.8-03', '3.3.8', 'Security patches are applied on time', 'patch compliance report', 'hardening', E.a_patch, 'high', 'ZS-2-3-02'),
    ('SA-3.3.8-04', '3.3.8', 'Backups are taken, protected and restores are tested', 'backup and restore reports', 'ops', E.a_backup, 'high', 'ZS-2-9-01'),
    ('SA-3.3.8-05', '3.3.8', 'E-mail is filtered and the mail domains are protected by SPF, DKIM and DMARC', 'mail gateway reports; DNS', 'ops', E.a_mail_auth, 'medium', 'ZS-2-4-02'),
    ('SA-3.3.9-01', '3.3.9', 'Encryption in transit uses valid certificates and strong keys', 'certificate inventory', 'ops', E.a_crypto, 'medium', 'ZS-2-8-01'),
    ('SA-3.3.9-02', '3.3.9', 'A cryptography standard (algorithms, keys, key management) is approved', 'cryptography standard', 'grc', POL(r'crypt', 'cryptography standard'), 'medium', 'ZS-2-8-02'),
    ('SA-3.3.10-01', '3.3.10', 'Personal and mobile devices reaching company data are managed (MDM, encryption, wipe)', 'MDM policy and report', 'ops', s_mdm, 'medium', 'ZS-2-6-01'),
    ('SA-3.3.11-01', '3.3.11', 'Information assets are disposed of securely, with records', 'disposal certificates', 'ops', None, 'medium', None),
    ('SA-3.3.12-01', '3.3.12', 'Payment systems the company runs meet SAMA\'s payment security requirements', 'payment systems review', 'ops', None, 'high', None),
    ('SA-3.3.13-01', '3.3.13', 'Online services to customers (portals, apps) are protected (MFA, fraud monitoring)', 'e-service security review', 'pentest', None, 'high', None),
    ('SA-3.3.14-01', '3.3.14', 'Security event logs of every critical system reach the SIEM', 'log source coverage', 'siem', E.a_logs, 'high', 'ZS-2-12-01'),
    ('SA-3.3.14-02', '3.3.14', 'Security events are monitored and alerts are acted on', 'SOC monitoring records', 'siem', E.a_monitor, 'high', 'ZS-2-12-02'),
    ('SA-3.3.14-03', '3.3.14', 'Security event logs are kept for at least 12 months', 'retention configuration', 'siem', E.a_retention, 'medium', 'ZS-2-12-03'),
    ('SA-3.3.15-01', '3.3.15', 'Incidents are handled to a plan and reported to SAMA / IA as required', 'incident plan; incident records', 'siem', E.a_incident, 'high', 'ZS-2-13-01'),
    ('SA-3.3.15-02', '3.3.15', 'Recovery is drilled and drills are signed off', 'DR / BCM drill records', 'ops', E.a_bcm, 'medium', 'ZS-3-1-01'),
    ('SA-3.3.16-01', '3.3.16', 'Threat intelligence is received and acted on', 'threat intelligence feeds; actions', 'siem', E.a_threat, 'medium', 'ZS-2-13-02'),
    ('SA-3.3.17-01', '3.3.17', 'Vulnerabilities are scanned periodically and fixed by severity', 'scan reports', 'pentest', E.a_vulns, 'high', 'ZS-2-10-01'),
    ('SA-3.3.17-02', '3.3.17', 'Penetration tests cover every in-scope asset on schedule', 'pentest reports; cadence', 'pentest', E.a_pentest, 'high', 'ZS-2-11-01'),
    ('SA-3.3.17-03', '3.3.17', 'Internet-facing systems expose no risky services', 'external attack surface', 'pentest', E.a_exposed, 'high', 'ZS-2-10-02'),
    ('SA-3.3.17-04', '3.3.17', 'Internal networks are scanned with an authenticated scanner and critical / high findings are fixed', 'internal scan reports', 'pentest', s_internal_scan, 'high', None),
    ('SA-3.3.8-06', '3.3.8', 'End-of-life systems are replaced, or isolated under an approved exception', 'lifecycle register; exceptions', 'hardening', s_eol, 'high', None),
    ('SA-3.4.1-01', '3.4.1', 'Third parties are risk-rated and assessed on schedule', 'vendor register', 'grc', E.a_vendors, 'medium', 'ZS-4-1-01'),
    ('SA-3.4.1-02', '3.4.1', 'Contracts carry cyber security and confidentiality requirements', 'contract clauses', 'grc', None, 'medium', 'ZS-4-1-02'),
    ('SA-3.4.2-01', '3.4.2', 'Outsourced services carry no high residual risk unaccepted', 'vendor risk ratings', 'grc', E.a_vendor_risk, 'medium', None),
    ('SA-3.4.3-01', '3.4.3', 'Cloud services are approved, with data residency and responsibilities agreed', 'cloud register; contracts', 'grc', None, 'medium', 'ZS-4-2-01'),
]
# the Insurance Authority keeps insurers on the SAMA CSF (circular UTC/277/202401) and adds its own contact requirement
IA_R = [
    ('IA-277-01', 'IA', 'A cyber-incident contact mailbox exists that is not tied to one employee, and IA has it', 'mailbox; IA acknowledgement', 'grc', None, 'medium', None),
]
# what to implement where the platform has no automated check yet: the recommendation shown with the requirement and in the
# "Coverage & value" view. Each names a concrete source or workflow, so the requirement can move from a person's confirmation to
# an automated check.
RECOMMEND = {
    'SA-3.1.5-01': 'Add a security gate to projects: each go-live records a security risk assessment and a penetration test, and new applications join the security testing cadence (Pentest & Vulnerabilities).',
    'SA-3.1.7-01': 'Import the training system (LMS) completions for security and privileged roles, so specialised training is measured instead of confirmed.',
    'SA-3.3.2-01': 'Send the badge-access and CCTV system logs of the data centres to the SIEM; data-centre access then becomes an automated SIEM check.',
    'SA-3.3.6-02': 'Put every internet-facing web application (customer portal, claims, agents) on the quarterly testing cadence and onboard the WAF logs to the SIEM.',
    'SA-3.3.11-01': 'Record the disposal certificate against each retired asset in the asset register, so secure disposal is evidenced per asset.',
    'SA-3.3.12-01': _org_fill('Decide applicability; if {{org.short}} runs a payment channel, add it to the testing cadence and its logs to the SIEM.'),
    'SA-3.3.13-01': 'For the customer portal and mobile app: quarterly penetration test, MFA evidence from the identity provider and fraud-monitoring use cases in the SIEM.',
    'SA-3.4.1-02': 'Add the cyber security / confidentiality clause checklist to each vendor record, so contracts without the clauses are listed automatically.',
    'SA-3.4.3-01': 'Keep a cloud-service register (provider, data, region, owner) next to the PDPL cross-border transfers, so unapproved cloud use is visible.',
    'IA-277-01': 'Create the shared cyber-incident mailbox in Exchange and record IA\'s acknowledgement; the platform can then check the mailbox exists and is shared.',
}
OK = ('verified', 'met')
SCORE = {'verified': 1.0, 'met': 1.0, 'partial': 0.5}
LEVEL_OF = {'verified': 'compliant', 'met': 'compliant', 'partial': 'partially', 'gap': 'not', 'pending': 'not_assessed', 'not_measured': 'not_assessed', 'no_evidence': 'not_assessed'}
KEYS = ['compliant', 'partially', 'not', 'not_assessed']


def _conf(confirms, rid):
    c = (confirms or {}).get(rid)
    return c if isinstance(c, dict) and c.get('status') in E.STATUSES else None


def _req(row, facts, pr, confirms, ecc_confirms, dec, notes):
    rid, sub, title, ev, pillar, fn, sev, ecc = row
    st, auto = None, None
    if fn:
        try:
            st, auto = fn(facts or {}, pr, pr.get('_now') or 0)
        except (TypeError, ValueError, KeyError, AttributeError) as e:
            st, auto = None, 'automated evidence could not be read (' + type(e).__name__ + ')'
    c = _conf(confirms, rid)
    via = None
    if not (c and c.get('approved_by')) and ecc:
        e2 = _conf(ecc_confirms, ecc)
        if e2 and e2.get('approved_by'):
            c, via = e2, ecc
    approved = bool(c and c.get('approved_by'))
    if sub in DECIDE and dec.get(sub) == 'not_applicable':
        res, why = 'not_applicable', _org_fill('the CISO decided this does not apply to {{org.short}}: ') + str(notes.get(sub) or 'no reason recorded')
    elif st is False:
        res, why = 'gap', auto
    elif st is True:
        res, why = 'verified', auto
    elif approved:
        res = {'compliant': 'met', 'partial': 'partial', 'non_compliant': 'gap', 'not_applicable': 'not_applicable'}[c['status']]
        why = 'confirmed by ' + str(c.get('by')) + ', approved by ' + str(c.get('approved_by')) + (' (in the NCA ECC register, ' + via + ')' if via else '') + ': ' + str(c.get('evidence') or c.get('note') or '')
    elif c:
        res, why = 'pending', 'recorded by ' + str(c.get('by')) + ' as ' + c['status'].replace('_', ' ') + ' - waiting for a second person to approve'
    elif fn:
        res, why = 'not_measured', auto
    else:
        res, why = 'no_evidence', 'no automated source: a person records it with ' + ev
    return {'id': rid, 'subdomain': sub, 'subdomain_name': SUB.get(sub, 'Insurance Authority'), 'domain': sub[:3] if sub != 'IA' else 'IA',
            'title': title, 'evidence_hint': ev, 'pillar': pillar, 'pillar_name': PILLARS[pillar], 'automated': fn is not None, 'auto': auto,
            'result': res, 'why': why, 'severity': sev, 'ecc': ecc, 'via_ecc': via, 'recommend': RECOMMEND.get(rid),
            'support': 'automated' if fn is not None else 'workflow',
            'conflict': bool(st is False and c and c.get('status') in ('compliant', 'not_applicable')),
            'decide': sub in DECIDE and not dec.get(sub),
            'confirmation': ({k: c.get(k) for k in ('status', 'evidence', 'note', 'by', 'at', 'approved_by', 'approved_at')} if c and not via else None)}


def _pct(cnt, total):
    if not total:
        return {k: 0 for k in KEYS}
    raw = {k: 100.0 * cnt.get(k, 0) / total for k in KEYS}
    out = {k: int(raw[k]) for k in KEYS}
    for k in sorted(KEYS, key=lambda k: raw[k] - out[k], reverse=True)[:100 - sum(out.values())]:
        out[k] += 1
    return out


def _levels(rows):
    app = [r for r in rows if r['result'] != 'not_applicable']
    cnt = {k: 0 for k in KEYS}
    for r in app:
        cnt[LEVEL_OF.get(r['result'], 'not_assessed')] += 1
    n = len(app)
    st = 'not_applicable' if not n else 'compliant' if cnt['compliant'] == n else 'partially' if (cnt['compliant'] or cnt['partially']) else 'not' if cnt['not'] else 'not_assessed'
    score = round(100.0 * sum(SCORE.get(r['result'], 0) for r in app) / n) if n else None
    return {'status': st, 'counts': cnt, 'pct': _pct(cnt, n), 'applicable': n, 'score': score}


def _maturity(rows, hist_ok):
    """indicative SAMA level for one subdomain, with the rule that decided it"""
    app = [r for r in rows if r['result'] != 'not_applicable']
    if not app:
        return {'level': None, 'name': 'Not applicable', 'why': 'every requirement was decided not applicable'}
    assessed = [r for r in app if LEVEL_OF.get(r['result']) != 'not_assessed']
    if not assessed:
        return {'level': None, 'name': 'Not assessed', 'why': 'no evidence yet - connect the source or record the evidence'}
    ok = [r for r in assessed if r['result'] in OK]
    some = [r for r in assessed if r['result'] in OK + ('partial',)]
    grc_ok = any(r['pillar'] == 'grc' and r['result'] in OK for r in app) or not any(r['pillar'] == 'grc' for r in app)
    incomplete = len(assessed) < len(app)
    if not some:
        lv, why = 0, 'every assessed requirement is a gap'
    elif len(ok) < len(app):
        lv, why = (2, 'practised and partly documented, gaps remain') if grc_ok and some else (1, 'practised in part, not documented or not consistent')
    else:
        lv, why = 3, 'every requirement met, documented and in place'
        auto_all = all(r['result'] == 'verified' for r in app if r['automated'])
        if auto_all and hist_ok.get('stable5'):
            lv, why = 4, 'met, evidenced automatically and stable over the last 5 runs (measured continuously)'
            if hist_ok.get('stable90'):
                lv, why = 5, 'met continuously for 90 days with no regression (improving / adaptive)'
    if incomplete and lv > 2:
        lv, why = 2, 'capped at 2 - ' + str(len(app) - len(assessed)) + ' requirement(s) not assessed yet'
    return {'level': lv, 'name': LEVELS[lv], 'why': why, 'incomplete': incomplete}


def _history(history, rows, now):
    """per requirement: runs seen, gaps, chance of a gap next run (Beta(1,1) posterior mean), regression, flapping"""
    runs = sorted([h for h in history or [] if isinstance(h, dict) and isinstance(h.get('results'), dict)], key=lambda h: _n(h.get('at')))
    last30 = runs[-30:]
    out = {}
    for r in rows:
        seq = [h['results'].get(r['id']) for h in last30 if h['results'].get(r['id'])]
        gaps = sum(1 for x in seq if x == 'gap')
        prev = seq[-1] if seq else None
        flips = sum(1 for a, b in zip(seq[-10:], seq[-10:][1:]) if (a in OK) != (b in OK))
        out[r['id']] = {'runs': len(seq), 'gaps': gaps, 'p_gap': round((gaps + 1.0) / (len(seq) + 2.0), 3),
                        'regression': bool(prev in OK and r['result'] == 'gap'), 'flapping': flips >= 3, 'last': prev}
    return runs, out


def _where(why):
    """the place to go named in a "not measured" reason - "(Connections & Setup -> SIEM)" - never the description around it"""
    import re
    found = [x.strip() for x in re.findall(r'\(([^()]*)\)', why or '') if x.strip()[:1].isupper()]
    arrows = [x for x in found if '->' in x]
    return (arrows or found)[-1:]


def _trend(runs, now):
    pts = [(_n(h.get('at')) / DAY, _n(h.get('score'))) for h in runs if h.get('score') is not None]
    if len(pts) < 3:
        return {'runs': len(pts), 'slope_per_30d': None, 'forecast_30d': None, 'note': 'a forecast needs 3 daily runs or more (' + str(len(pts)) + ' so far)'}
    mx = sum(x for x, _ in pts) / len(pts); my = sum(y for _, y in pts) / len(pts)
    vx = sum((x - mx) ** 2 for x, _ in pts)
    slope = sum((x - mx) * (y - my) for x, y in pts) / vx if vx else 0.0
    fc = my + slope * (now / DAY + 30 - mx)
    return {'runs': len(pts), 'slope_per_30d': round(slope * 30, 1), 'forecast_30d': max(0, min(100, round(fc))),
            'note': 'least-squares line over ' + str(len(pts)) + ' daily runs - an indication, not a promise'}


def view(req):
    facts = req.get('facts') or {}
    now = _n(req.get('now')) or int(datetime.now(timezone.utc).timestamp() * 1000)
    pr = dict(req.get('profile') or {})
    pr['_ecc'] = req.get('ecc_profile') or {}
    pr['_settings'] = req.get('settings') or {}
    pr['_now'] = now
    dec = pr.get('applicability') or {}
    notes = pr.get('applicability_note') if isinstance(pr.get('applicability_note'), dict) else {}
    conf, econf = req.get('confirms') or {}, req.get('ecc_confirms') or {}
    rows = [_req(x, facts, pr, conf, econf, dec, notes) for x in R]
    ia_rows = [_req(x, facts, pr, conf, econf, dec, notes) for x in IA_R]
    runs, H = _history(req.get('history'), rows + ia_rows, now)
    for r in rows + ia_rows:
        r['history'] = H[r['id']]
    # a subdomain is "stable" when it was fully met in each of the last 5 runs / every run of the last 90 days (>= 12 runs)
    def stable(sub, k, days=None):
        hs = [h for h in runs if not days or _n(h.get('at')) >= now - days * DAY]
        hs = hs[-k:] if not days else hs
        if len(hs) < (k if not days else 12):
            return False
        ids = [r['id'] for r in rows if r['subdomain'] == sub and r['result'] != 'not_applicable']
        return all(all(h['results'].get(i) in OK for i in ids) for h in hs)
    subs = []
    for sid, name in SUB.items():
        sr = [r for r in rows if r['subdomain'] == sid]
        lv = _levels(sr)
        mat = _maturity(sr, {'stable5': stable(sid, 5), 'stable90': stable(sid, 0, 90)})
        pil = {}
        for r in sr:
            p = pil.setdefault(r['pillar'], {'ok': 0, 'gap': 0, 'other': 0})
            p['ok' if r['result'] in OK else 'gap' if r['result'] == 'gap' else 'other'] += 1
        subs.append(dict({'id': sid, 'name': name, 'domain': sid[:3], 'maturity': mat, 'pillars': pil, 'decide': sid in DECIDE and not dec.get(sid),
                          'below_target': mat['level'] is not None and mat['level'] < TARGET}, **lv))
    doms = [dict({'id': d, 'name': n}, **_levels([r for r in rows if r['domain'] == d]),
                 subdomains=len([s for s in subs if s['domain'] == d]), at_target=len([s for s in subs if s['domain'] == d and (s['maturity']['level'] or 0) >= TARGET])) for d, n in DOMAINS.items()]
    overall = _levels(rows)
    rated = [s for s in subs if s['maturity']['level'] is not None]
    pillars = []
    for k, nm in PILLARS.items():
        pr_ = [r for r in rows if r['pillar'] == k and r['result'] != 'not_applicable']
        auto = [r for r in pr_ if r['automated']]
        pillars.append({'id': k, 'name': nm, 'requirements': len(pr_), 'automated': len(auto),
                        'connected': len([r for r in auto if r['result'] != 'not_measured']), 'ok': len([r for r in pr_ if r['result'] in OK]),
                        'gaps': len([r for r in pr_ if r['result'] == 'gap']), 'not_assessed': len([r for r in pr_ if LEVEL_OF.get(r['result']) == 'not_assessed']),
                        'score': _levels(pr_)['score']})
    SEV = {'high': 3, 'medium': 2, 'low': 1}
    DIST = {'gap': 1.0, 'partial': 0.5, 'no_evidence': 0.6, 'pending': 0.3, 'not_measured': 0.4}
    pri = []
    for r in rows + ia_rows:
        if r['result'] in OK or r['result'] == 'not_applicable':
            continue
        h = r['history']
        sc = SEV[r['severity']] * DIST.get(r['result'], 0.5) * (1 + h['p_gap']) + (1 if h['regression'] else 0)
        why = [r['severity'] + ' severity', r['result'].replace('_', ' '), str(round(h['p_gap'] * 100)) + ' % chance of a gap next run (' + str(h['runs']) + ' run(s) seen)']
        if h['regression']:
            why.append('regression - it was met at the last run')
        if h['flapping']:
            why.append('flapping - it changed 3+ times in the last 10 runs')
        pri.append({'id': r['id'], 'subdomain': r['subdomain'], 'title': r['title'], 'pillar': r['pillar_name'], 'result': r['result'], 'score': round(sc, 2), 'why': why, 'action': r['why']})
    pri.sort(key=lambda x: -x['score'])
    ia = _levels(rows + ia_rows)
    allr = [r for r in rows + ia_rows if r['result'] != 'not_applicable']
    auto = [r for r in allr if r['automated']]
    value = {'requirements': len(allr), 'automated': len(auto), 'automated_connected': len([r for r in auto if r['result'] != 'not_measured']),
             'automated_pct': round(100.0 * len(auto) / len(allr)) if allr else 0, 'workflow': len(allr) - len(auto),
             'from_ecc': len([r for r in allr if r['via_ecc']]), 'connect': sorted({w for r in auto if r['result'] == 'not_measured' for w in _where(r['why'])}),
             'recommendations': [{'id': r['id'], 'subdomain': r['subdomain'], 'title': r['title'], 'recommend': r['recommend'], 'result': r['result']} for r in allr if r['recommend'] and r['result'] not in OK]}
    return {'ok': True, 'framework': 'SAMA Cyber Security Framework', 'target_level': TARGET, 'levels': LEVELS,
            'overall': overall, 'domains': doms, 'subdomains': subs, 'requirements': rows, 'pillars': pillars,
            'readiness': {'subdomains': len(subs), 'rated': len(rated), 'at_target': len([s for s in rated if s['maturity']['level'] >= TARGET]),
                          'below_target': len([s for s in rated if s['maturity']['level'] < TARGET]), 'not_assessed': len(subs) - len(rated),
                          'average_level': round(sum(s['maturity']['level'] for s in rated) / len(rated), 1) if rated else None},
            'ia': {'name': 'Insurance Authority - SAMA CSF baseline for insurers', 'circular': 'UTC/277/202401', 'requirements': ia_rows, 'levels': ia,
                   'note': 'The Insurance Authority keeps insurers on the SAMA Cyber Security Framework and adds its own requirements; this view is the SAMA register plus the IA items, scored together.'},
            'trend': _trend(runs, now), 'priorities': pri[:25], 'value': value,
            'regressions': [r['id'] for r in rows + ia_rows if r['history']['regression']],
            'snapshot': {'at': now, 'score': overall['score'], 'results': {r['id']: r['result'] for r in rows + ia_rows}},
            'decide': [s for s in DECIDE if not dec.get(s)],
            'sources': [{'id': k, 'connected': bool(_src(facts, k))} for k in ('grc', 'risk', 'drills', 'ownership', 'hardening', 'pentest', 'cadence', 'certs', 'mail', 'vendor', 'pdpl', 'siem', 'ccm', 'audit')],
            'note': 'Indicative, from this register: SAMA maturity levels and scores are the platform\'s reading of the evidence, not SAMA\'s or an auditor\'s rating. Requirement texts are the platform\'s plain-language summary of each SAMA subdomain - verify against the SAMA CSF text.'}


OPS = {'sama.view': view}
