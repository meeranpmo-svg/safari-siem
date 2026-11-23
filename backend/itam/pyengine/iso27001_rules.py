# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""ISO/IEC 27001:2022 ISMS register, internal audit programme and certification readiness. Python decides, Node.js commits
(engine/iso27001.js): this module reads only what it is given and writes nothing.

  iso.view     {facts, profile, ecc_profile, confirms, ecc_confirms, soa, audits, reviews, ncs, history, now}
               -> clauses 4-10, the 93 Annex A controls, themes, the Statement of Applicability, readiness, findings
  iso.plan     {rows, start, months, now}       -> the internal audit programme: every clause and Annex A theme audited once
                                                   per cycle, the units with the most gaps first
  iso.prepare  {unit, rows, now}                -> the working paper for one audit: a test per requirement with the
                                                   evidence the platform holds, and a PROPOSED finding the auditor decides
  iso.pack     {view, reviews, ncs, audits, now} -> the management review inputs ISO 27001 clause 9.3.2 (a)-(g) asks for

Efficiency: the automated evidence is the NCA ECC register's own checks (nca_ecc_rules), run on the same facts, so one
collection serves both frameworks and the two can never disagree; a manual control a person already confirmed and a second
person approved in the NCA ECC register counts here too (its id is named), so nobody records the same evidence twice.

Results, as in the ECC register: verified / gap from automated evidence (a gap is never hidden by a confirmation), met /
partial / gap from a person's confirmation approved by a second person, pending while waiting for that approval,
not_measured when the source is not connected, no_evidence when nothing shows it yet. The control titles are the Annex A
names; the readiness score is indicative, from this register - it is not a certification body's opinion. Standard library only.
"""
import hashlib
import json
from datetime import datetime, timezone

import nca_ecc_rules as E

DAY = 86400000
STATUSES = E.STATUSES
_within = E._within
_n = E._n
ms = E.ms


def _ecc(fn):
    """an NCA ECC check run with the ECC profile (CISO, strategy, committee live there)"""
    return lambda f, pr, now: fn(f, pr.get('_ecc') or {}, now)


def _days(pr, key, days, what):
    v = pr.get(key)
    if not v:
        return False, 'no ' + what + ' recorded in the ISO 27001 profile'
    return (True, what + ' ' + str(v)[:10]) if _within(v, pr['_now'], days) else (False, what + ' ' + str(v)[:10] + ' - older than ' + str(days // 30) + ' months, review it')


# ---- the ISMS clauses (4-10): checks on this module's own records and the profile
def c_context(f, pr, now):
    return _days(pr, 'context_reviewed', 365, 'internal and external issues reviewed')


def c_parties(f, pr, now):
    return _days(pr, 'parties_reviewed', 365, 'interested parties and their requirements reviewed')


def c_scope(f, pr, now):
    if not (pr.get('scope') or '').strip():
        return False, 'no ISMS scope statement recorded'
    if not pr.get('scope_approved'):
        return False, 'the ISMS scope is written but not approved'
    return True, 'ISMS scope approved ' + str(pr['scope_approved'])[:10] + ': ' + str(pr['scope'])[:120]


def c_isms(f, pr, now):
    need = [('scope', c_scope(f, pr, now)[0]), ('policy', c_policy(f, pr, now)[0]), ('SoA', c_soa(f, pr, now)[0]), ('risk method', bool(pr.get('risk_method_approved')))]
    miss = [k for k, ok in need if not ok]
    return (False, 'the ISMS is not yet established: missing ' + ', '.join(miss)) if miss else (True, 'scope, policy, risk method and Statement of Applicability in place')


def c_leadership(f, pr, now):
    rv = [r for r in pr.get('_reviews') or [] if r.get('status') == 'held']
    last = max(rv, key=lambda r: ms(r.get('held_on')) or 0) if rv else None
    if not last:
        return False, 'no management review held yet - top management shows commitment there (clause 5.1 / 9.3)'
    if not _within(last.get('held_on'), now, 365):
        return False, 'last management review ' + str(last.get('held_on'))[:10] + ' - more than a year ago'
    return True, 'management review ' + str(last.get('held_on'))[:10] + ' chaired by ' + str(last.get('chaired_by') or '?')


def c_policy(f, pr, now):
    ok, why = E._pol(f, r'information security polic|isms polic', now)
    if ok is None:
        return None, 'not measured: ' + why
    return ok, why if ok else (why if 'review' in why else 'no approved information security policy in the GRC register')


def c_roles(f, pr, now):
    if not pr.get('isms_manager'):
        return False, 'no ISMS manager named in the ISO 27001 profile'
    ok, why = E.a_roles(f, pr, now)
    return (ok, 'ISMS manager ' + pr['isms_manager'] + '; ' + why) if ok is not None else (True, 'ISMS manager ' + pr['isms_manager'] + ' (Roles & Functions not defined yet)')


def c_risk(f, pr, now):
    if not pr.get('risk_method_approved'):
        return False, 'no approved risk assessment method recorded (clause 6.1.2)'
    return E.a_risk(f, pr, now)


def c_soa(f, pr, now):
    s = pr.get('_soa') or {}
    if not s.get('approved_by'):
        return False, 'the Statement of Applicability is not approved' + (' (version ' + str(s.get('version')) + ' waits for a second person)' if s.get('proposed_by') else '')
    if s.get('stale'):
        return False, 'the approved Statement of Applicability (v' + str(s.get('version')) + ') no longer matches the register: ' + s['stale']
    if not _within(s.get('approved_at'), now, 365):
        return False, 'the Statement of Applicability was approved ' + str(s.get('approved_at'))[:10] + ' - review it yearly'
    return True, 'Statement of Applicability v' + str(s.get('version')) + ' approved by ' + str(s.get('approved_by')) + ' ' + str(s.get('approved_at'))[:10]


def c_objectives(f, pr, now):
    obj = [o for o in pr.get('objectives') or [] if isinstance(o, dict)]
    if not obj:
        return False, 'no information security objectives recorded (clause 6.2)'
    bad = [o.get('objective', '?')[:60] for o in obj if not (o.get('measure') and o.get('owner') and o.get('target'))]
    if bad:
        return False, str(len(bad)) + ' objective(s) without a measure, target or owner: ' + '; '.join(bad[:3])
    late = [o.get('objective', '?')[:60] for o in obj if not _within(o.get('measured_on'), now, 120)]
    return (False, str(len(late)) + ' objective(s) not measured in 4 months: ' + '; '.join(late[:3])) if late else (True, str(len(obj)) + ' objective(s) with measure, target and owner, all measured')


def c_measure(f, pr, now):
    h = pr.get('_history') or []
    if len(h) < 2:
        return None, 'not measured yet: the register keeps a daily snapshot - the trend shows after the second day'
    return True, 'register measured daily (' + str(len(h)) + ' snapshot(s)); objectives: ' + c_objectives(f, pr, now)[1]


def c_audit(f, pr, now):
    A = pr.get('_audits') or []
    if not A:
        return False, 'no internal audit programme - generate it on the ISO 27001 page (clause 9.2)'
    over = [a['unit'] for a in A if a.get('status') not in ('reported', 'cancelled') and (ms(a.get('due')) or 0) < now]
    done = [a for a in A if a.get('status') == 'reported' and _within(a.get('reported_at'), now, 400)]
    if over:
        return False, str(len(over)) + ' internal audit(s) overdue: ' + ', '.join(over[:4])
    if not done:
        return False, 'the programme has started but no internal audit is reported yet'
    return True, str(len(done)) + ' of ' + str(len(A)) + ' programme audit(s) reported, none overdue'


def c_review(f, pr, now):
    ok, why = c_leadership(f, pr, now)
    if not ok:
        return ok, why
    rv = [r for r in pr.get('_reviews') or [] if r.get('status') == 'held']
    last = max(rv, key=lambda r: ms(r.get('held_on')) or 0)
    if not (last.get('decisions') or '').strip():
        return False, 'the last management review recorded no decisions (clause 9.3.3)'
    return True, why + ', decisions recorded'


def c_nc(f, pr, now):
    N = [x for x in pr.get('_ncs') or [] if x.get('status') != 'cancelled']
    if not N:
        return None, 'no nonconformity recorded yet - they come from the internal audits'
    over = [x['id'] for x in N if x.get('status') not in ('closed',) and (ms(x.get('due')) or 0) < now]
    noact = [x['id'] for x in N if x.get('status') == 'open' and not x.get('corrective_action')]
    if over:
        return False, str(len(over)) + ' nonconformit(ies) past due: ' + ', '.join(over[:5])
    if noact:
        return False, str(len(noact)) + ' nonconformit(ies) without a root cause and corrective action: ' + ', '.join(noact[:5])
    return True, str(len(N)) + ' nonconformit(ies): every one has a corrective action, none overdue'


# (id, clause group, title, evidence a person shows, check or None, severity)
CL = [
    ('4.1', '4', 'Understanding the organization and its context', 'context analysis (internal / external issues)', c_context, 'medium'),
    ('4.2', '4', 'Understanding the needs and expectations of interested parties', 'interested parties register', c_parties, 'medium'),
    ('4.3', '4', 'Determining the scope of the ISMS', 'approved scope statement', c_scope, 'high'),
    ('4.4', '4', 'Information security management system', 'ISMS manual / framework', c_isms, 'high'),
    ('5.1', '5', 'Leadership and commitment', 'management review minutes; resource approvals', c_leadership, 'high'),
    ('5.2', '5', 'Information security policy', 'approved information security policy', c_policy, 'high'),
    ('5.3', '5', 'Organizational roles, responsibilities and authorities', 'ISMS roles; appointment letters', c_roles, 'medium'),
    ('6.1.1', '6', 'Actions to address risks and opportunities - general', 'risk and opportunity register', _ecc(E.a_actions), 'medium'),
    ('6.1.2', '6', 'Information security risk assessment', 'risk method; risk register', c_risk, 'high'),
    ('6.1.3', '6', 'Information security risk treatment (Statement of Applicability)', 'risk treatment plan; approved SoA', c_soa, 'high'),
    ('6.2', '6', 'Information security objectives and planning to achieve them', 'objectives with measures, targets, owners', c_objectives, 'medium'),
    ('6.3', '6', 'Planning of changes', 'change plans for the ISMS', None, 'low'),
    ('7.1', '7', 'Resources', 'budget and staffing approvals', None, 'low'),
    ('7.2', '7', 'Competence', 'competence matrix; training records', _ecc(E.a_training), 'medium'),
    ('7.3', '7', 'Awareness', 'awareness programme; attendance', _ecc(E.a_training), 'medium'),
    ('7.4', '7', 'Communication', 'communication plan', None, 'low'),
    ('7.5', '7', 'Documented information', 'document control; review dates', _ecc(E.a_policies_current), 'medium'),
    ('8.1', '8', 'Operational planning and control', 'operational plans; action register', _ecc(E.a_actions), 'medium'),
    ('8.2', '8', 'Information security risk assessment (at planned intervals)', 'risk reviews', _ecc(E.a_risk), 'medium'),
    ('8.3', '8', 'Information security risk treatment (implemented)', 'treatment actions closed', _ecc(E.a_actions), 'medium'),
    ('9.1', '9', 'Monitoring, measurement, analysis and evaluation', 'measurement results', c_measure, 'medium'),
    ('9.2', '9', 'Internal audit', 'audit programme; audit reports', c_audit, 'high'),
    ('9.3', '9', 'Management review', 'management review minutes and decisions', c_review, 'high'),
    ('10.1', '10', 'Continual improvement', 'improvement log', None, 'low'),
    ('10.2', '10', 'Nonconformity and corrective action', 'nonconformity register; corrective actions', c_nc, 'high'),
]
CL_GROUP = {'4': 'Context of the organization', '5': 'Leadership', '6': 'Planning', '7': 'Support', '8': 'Operation',
            '9': 'Performance evaluation', '10': 'Improvement'}

P = E.a_policy
# Annex A: (id, theme, title, evidence hint, ECC register controls whose approved confirmation also counts, check, severity)
AX = [
    ('A.5.1', '5', 'Policies for information security', 'approved policy set', ['ZS-1-3-01'], _ecc(E.a_policies_current), 'high'),
    ('A.5.2', '5', 'Information security roles and responsibilities', 'RACI; appointments', ['ZS-1-4-01'], _ecc(E.a_roles), 'medium'),
    ('A.5.3', '5', 'Segregation of duties', 'segregation matrix; four-eyes records', [], None, 'medium'),
    ('A.5.4', '5', 'Management responsibilities', 'policy attestations by managers', ['ZS-1-3-02'], _ecc(E.a_attested), 'medium'),
    ('A.5.5', '5', 'Contact with authorities', 'authority contact list (NCA, SAMA, IA, SDAIA)', [], None, 'low'),
    ('A.5.6', '5', 'Contact with special interest groups', 'memberships; advisories received', [], None, 'low'),
    ('A.5.7', '5', 'Threat intelligence', 'threat intelligence feeds and actions', ['ZS-2-13-02'], _ecc(E.a_threat), 'medium'),
    ('A.5.8', '5', 'Information security in project management', 'project security reviews', ['ZS-1-6-01'], None, 'medium'),
    ('A.5.9', '5', 'Inventory of information and other associated assets', 'asset register', ['ZS-2-1-01'], _ecc(E.a_assets), 'high'),
    ('A.5.10', '5', 'Acceptable use of information and other associated assets', 'acceptable use policy', ['ZS-2-1-03'], P(r'acceptable use', 'acceptable use policy'), 'low'),
    ('A.5.11', '5', 'Return of assets', 'leaver asset returns', ['ZS-1-9-01'], None, 'medium'),
    ('A.5.12', '5', 'Classification of information', 'classification policy', ['ZS-2-7-01'], P(r'classification', 'data classification policy'), 'high'),
    ('A.5.13', '5', 'Labelling of information', 'labelling procedure; labels in use', [], None, 'low'),
    ('A.5.14', '5', 'Information transfer', 'transfer rules; mail protection', ['ZS-2-4-02'], _ecc(E.a_mail_auth), 'medium'),
    ('A.5.15', '5', 'Access control', 'access control policy', ['ZS-2-2-03'], P(r'access (control|management)|identity', 'access control policy'), 'high'),
    ('A.5.16', '5', 'Identity management', 'joiner / mover / leaver records', ['ZS-2-2-01'], _ecc(E.a_privileged), 'high'),
    ('A.5.17', '5', 'Authentication information', 'password / MFA standard', [], None, 'high'),
    ('A.5.18', '5', 'Access rights', 'access review records', ['ZS-2-2-02'], None, 'high'),
    ('A.5.19', '5', 'Information security in supplier relationships', 'supplier assessments', ['ZS-4-1-01'], _ecc(E.a_vendors), 'high'),
    ('A.5.20', '5', 'Addressing information security within supplier agreements', 'contract clauses', ['ZS-4-1-02'], _ecc(E.a_vendor_risk), 'medium'),
    ('A.5.21', '5', 'Managing information security in the ICT supply chain', 'ICT supplier requirements', [], None, 'medium'),
    ('A.5.22', '5', 'Monitoring, review and change management of supplier services', 'supplier review records', ['ZS-4-1-01'], _ecc(E.a_vendors), 'medium'),
    ('A.5.23', '5', 'Information security for use of cloud services', 'cloud register; hosting locations', ['ZS-4-2-01', 'ZS-4-2-02'], lambda f, pr, now: E._pdpl(f, 'P-11', 'cross-border transfers'), 'high'),
    ('A.5.24', '5', 'Information security incident management planning and preparation', 'incident plan', ['ZS-2-13-01'], _ecc(E.a_incident), 'high'),
    ('A.5.25', '5', 'Assessment and decision on information security events', 'triage records', ['ZS-2-12-02'], _ecc(E.a_monitor), 'high'),
    ('A.5.26', '5', 'Response to information security incidents', 'incident records', ['ZS-2-13-01'], _ecc(E.a_incident), 'high'),
    ('A.5.27', '5', 'Learning from information security incidents', 'post-incident reviews', [], None, 'medium'),
    ('A.5.28', '5', 'Collection of evidence', 'evidence handling procedure', [], None, 'medium'),
    ('A.5.29', '5', 'Information security during disruption', 'BCM plan covering security', ['ZS-3-1-01'], _ecc(E.a_bcm), 'high'),
    ('A.5.30', '5', 'ICT readiness for business continuity', 'DR drill reports', ['ZS-2-9-02'], _ecc(E.a_restore), 'high'),
    ('A.5.31', '5', 'Legal, statutory, regulatory and contractual requirements', 'legal and regulatory register', ['ZS-1-7-01'], P(r'compliance|regulatory', 'compliance policy'), 'medium'),
    ('A.5.32', '5', 'Intellectual property rights', 'licence compliance', [], None, 'low'),
    ('A.5.33', '5', 'Protection of records', 'records retention schedule', [], None, 'medium'),
    ('A.5.34', '5', 'Privacy and protection of PII', 'PDPL compliance', ['ZS-2-7-02'], lambda f, pr, now: E._pdpl(f, 'P-13', 'security of personal data'), 'high'),
    ('A.5.35', '5', 'Independent review of information security', 'independent audit report', ['ZS-1-8-01'], P(r'audit', 'audit policy'), 'medium'),
    ('A.5.36', '5', 'Compliance with policies, rules and standards for information security', 'compliance checks', ['ZS-1-3-02'], _ecc(E.a_attested), 'medium'),
    ('A.5.37', '5', 'Documented operating procedures', 'operating procedures', [], None, 'low'),
    ('A.6.1', '6', 'Screening', 'background checks', ['ZS-1-9-01'], None, 'medium'),
    ('A.6.2', '6', 'Terms and conditions of employment', 'contract security clauses', ['ZS-1-9-01'], None, 'medium'),
    ('A.6.3', '6', 'Information security awareness, education and training', 'awareness records', ['ZS-1-10-01'], _ecc(E.a_training), 'medium'),
    ('A.6.4', '6', 'Disciplinary process', 'disciplinary procedure', [], None, 'low'),
    ('A.6.5', '6', 'Responsibilities after termination or change of employment', 'leaver agreements', ['ZS-1-9-01'], None, 'medium'),
    ('A.6.6', '6', 'Confidentiality or non-disclosure agreements', 'signed NDAs', [], None, 'medium'),
    ('A.6.7', '6', 'Remote working', 'remote working policy', [], P(r'remote|telework', 'remote working policy'), 'medium'),
    ('A.6.8', '6', 'Information security event reporting', 'reporting channel; reports', [], None, 'medium'),
    ('A.7.1', '7', 'Physical security perimeters', 'perimeter design', ['ZS-2-14-01'], None, 'medium'),
    ('A.7.2', '7', 'Physical entry', 'access logs', ['ZS-2-14-01'], None, 'medium'),
    ('A.7.3', '7', 'Securing offices, rooms and facilities', 'site security review', [], None, 'low'),
    ('A.7.4', '7', 'Physical security monitoring', 'CCTV / alarm records', ['ZS-2-14-01'], None, 'medium'),
    ('A.7.5', '7', 'Protecting against physical and environmental threats', 'environmental controls', [], None, 'medium'),
    ('A.7.6', '7', 'Working in secure areas', 'secure area rules', [], None, 'low'),
    ('A.7.7', '7', 'Clear desk and clear screen', 'clear desk policy; screen lock GPO', [], P(r'clear desk|clear screen', 'clear desk policy'), 'low'),
    ('A.7.8', '7', 'Equipment siting and protection', 'data centre layout', [], None, 'low'),
    ('A.7.9', '7', 'Security of assets off-premises', 'off-site asset rules', [], None, 'low'),
    ('A.7.10', '7', 'Storage media', 'media handling procedure', [], None, 'medium'),
    ('A.7.11', '7', 'Supporting utilities', 'UPS / generator tests', [], None, 'medium'),
    ('A.7.12', '7', 'Cabling security', 'cabling standard', [], None, 'low'),
    ('A.7.13', '7', 'Equipment maintenance', 'maintenance records', [], None, 'low'),
    ('A.7.14', '7', 'Secure disposal or re-use of equipment', 'disposal certificates', [], None, 'medium'),
    ('A.8.1', '8', 'User endpoint devices', 'endpoint standard; MDM', ['ZS-2-6-01'], None, 'medium'),
    ('A.8.2', '8', 'Privileged access rights', 'privileged access list; reviews', ['ZS-2-2-01'], _ecc(E.a_privileged), 'high'),
    ('A.8.3', '8', 'Information access restriction', 'access matrix', ['ZS-2-2-01'], _ecc(E.a_privileged), 'high'),
    ('A.8.4', '8', 'Access to source code', 'repository access list', [], None, 'medium'),
    ('A.8.5', '8', 'Secure authentication', 'MFA configuration', ['ZS-2-2-01'], _ecc(E.a_privileged), 'high'),
    ('A.8.6', '8', 'Capacity management', 'capacity reports', [], None, 'low'),
    ('A.8.7', '8', 'Protection against malware', 'EDR coverage', ['ZS-2-3-03'], None, 'high'),
    ('A.8.8', '8', 'Management of technical vulnerabilities', 'scan and remediation records', ['ZS-2-10-01'], _ecc(E.a_vulns), 'high'),
    ('A.8.9', '8', 'Configuration management', 'hardening baselines and results', ['ZS-2-3-01'], _ecc(E.a_hardening), 'high'),
    ('A.8.10', '8', 'Information deletion', 'deletion / destruction records', [], None, 'medium'),
    ('A.8.11', '8', 'Data masking', 'masking standard', [], None, 'medium'),
    ('A.8.12', '8', 'Data leakage prevention', 'DLP policy and reports', ['ZS-2-7-03'], None, 'medium'),
    ('A.8.13', '8', 'Information backup', 'backup reports', ['ZS-2-9-01'], _ecc(E.a_backup), 'high'),
    ('A.8.14', '8', 'Redundancy of information processing facilities', 'DR site; failover tests', ['ZS-3-1-01'], _ecc(E.a_bcm), 'medium'),
    ('A.8.15', '8', 'Logging', 'log source inventory', ['ZS-2-12-01'], _ecc(E.a_logs), 'high'),
    ('A.8.16', '8', 'Monitoring activities', 'SOC monitoring reports', ['ZS-2-12-02'], _ecc(E.a_monitor), 'high'),
    ('A.8.17', '8', 'Clock synchronization', 'NTP configuration', [], None, 'low'),
    ('A.8.18', '8', 'Use of privileged utility programs', 'utility program restrictions', [], None, 'low'),
    ('A.8.19', '8', 'Installation of software on operational systems', 'software installation control', ['ZS-2-3-02'], _ecc(E.a_patch), 'medium'),
    ('A.8.20', '8', 'Networks security', 'network security design', ['ZS-2-5-01'], _ecc(E.a_netsec), 'high'),
    ('A.8.21', '8', 'Security of network services', 'network service agreements', ['ZS-2-5-02'], None, 'medium'),
    ('A.8.22', '8', 'Segregation of networks', 'segmentation design', ['ZS-2-5-01'], _ecc(E.a_netsec), 'high'),
    ('A.8.23', '8', 'Web filtering', 'web filter policy', [], None, 'medium'),
    ('A.8.24', '8', 'Use of cryptography', 'certificate inventory; crypto standard', ['ZS-2-8-01', 'ZS-2-8-02'], _ecc(E.a_crypto), 'high'),
    ('A.8.25', '8', 'Secure development life cycle', 'secure SDLC standard', ['ZS-1-6-02'], P(r'secure (software )?development|sdlc|application security', 'secure development policy'), 'medium'),
    ('A.8.26', '8', 'Application security requirements', 'application security requirements', ['ZS-2-15-01'], None, 'medium'),
    ('A.8.27', '8', 'Secure system architecture and engineering principles', 'architecture principles', [], None, 'medium'),
    ('A.8.28', '8', 'Secure coding', 'code review records', ['ZS-1-6-02'], None, 'medium'),
    ('A.8.29', '8', 'Security testing in development and acceptance', 'pentest / VAPT reports', ['ZS-2-11-01'], _ecc(E.a_pentest), 'high'),
    ('A.8.30', '8', 'Outsourced development', 'outsourced development contracts', [], None, 'medium'),
    ('A.8.31', '8', 'Separation of development, test and production environments', 'environment separation', [], None, 'medium'),
    ('A.8.32', '8', 'Change management', 'change records', ['ZS-1-6-01'], None, 'medium'),
    ('A.8.33', '8', 'Test information', 'test data rules', [], None, 'low'),
    ('A.8.34', '8', 'Protection of information systems during audit testing', 'audit test agreements', [], None, 'low'),
]
THEMES = [('5', 'Organizational controls'), ('6', 'People controls'), ('7', 'Physical controls'), ('8', 'Technological controls')]
THEME_NAME = dict(THEMES)
IDS = set([c[0] for c in CL] + [a[0] for a in AX])

# the internal audit programme: every clause and every Annex A control falls in exactly one unit
UNITS = [
    ('ISMS', 'ISMS core: clauses 4-10', lambda r: r['kind'] == 'clause'),
    ('A5-GOV', 'Governance, roles, threat intelligence, projects (A.5.1-5.8)', lambda r: r['kind'] == 'annex' and r['num'][0] == 5 and r['num'][1] <= 8),
    ('A5-ASSET', 'Assets, classification and access (A.5.9-5.18)', lambda r: r['kind'] == 'annex' and r['num'][0] == 5 and 9 <= r['num'][1] <= 18),
    ('A5-SUPP', 'Suppliers and cloud (A.5.19-5.23)', lambda r: r['kind'] == 'annex' and r['num'][0] == 5 and 19 <= r['num'][1] <= 23),
    ('A5-INC', 'Incidents and continuity (A.5.24-5.30)', lambda r: r['kind'] == 'annex' and r['num'][0] == 5 and 24 <= r['num'][1] <= 30),
    ('A5-COMP', 'Compliance, privacy and procedures (A.5.31-5.37)', lambda r: r['kind'] == 'annex' and r['num'][0] == 5 and r['num'][1] >= 31),
    ('A6', 'People controls (A.6)', lambda r: r['kind'] == 'annex' and r['num'][0] == 6),
    ('A7', 'Physical controls (A.7)', lambda r: r['kind'] == 'annex' and r['num'][0] == 7),
    ('A8-ACC', 'Endpoints and access (A.8.1-8.5)', lambda r: r['kind'] == 'annex' and r['num'][0] == 8 and r['num'][1] <= 5),
    ('A8-OPS', 'Operations: malware, vulnerabilities, backup, logging (A.8.6-8.19)', lambda r: r['kind'] == 'annex' and r['num'][0] == 8 and 6 <= r['num'][1] <= 19),
    ('A8-NET', 'Network security and cryptography (A.8.20-8.24)', lambda r: r['kind'] == 'annex' and r['num'][0] == 8 and 20 <= r['num'][1] <= 24),
    ('A8-DEV', 'Development, change and testing (A.8.25-8.34)', lambda r: r['kind'] == 'annex' and r['num'][0] == 8 and r['num'][1] >= 25),
]
UNIT_NAME = {u[0]: u[1] for u in UNITS}


def _num(cid):
    return tuple(int(x) for x in cid.replace('A.', '').split('.'))


def _conf(confirms, cid):
    c = (confirms or {}).get(cid) or {}
    return c if c.get('status') in STATUSES else None


def _ecc_conf(ecc_confirms, ids):
    """an NCA ECC confirmation approved by a second person, reused (the first of the linked controls that has one)"""
    for i in ids:
        c = _conf(ecc_confirms, i)
        if c and c.get('approved_by'):
            return i, c
    return None, None


def _one(kind, cid, grp, title, ev, ecc_ids, fn, sev, facts, pr, confirms, ecc_confirms, soa_excl, now):
    st, auto = None, None
    if fn:
        try:
            st, auto = fn(facts or {}, pr, now)
        except (TypeError, ValueError, KeyError, AttributeError) as e:
            st, auto = None, 'automated evidence could not be read (' + type(e).__name__ + ')'
    c = _conf(confirms, cid)
    eid, ec = _ecc_conf(ecc_confirms, ecc_ids)
    approved = bool(c and c.get('approved_by'))
    via = None
    if kind == 'annex' and cid in soa_excl:
        res, why = 'not_applicable', 'excluded in the Statement of Applicability: ' + str(soa_excl[cid] or 'no justification recorded')
    elif st is False:
        res, why = 'gap', auto
    elif st is True:
        res, why = 'verified', auto
    elif approved:
        res = {'compliant': 'met', 'partial': 'partial', 'non_compliant': 'gap', 'not_applicable': 'not_applicable'}[c['status']]
        why = 'confirmed by ' + str(c.get('by')) + ', approved by ' + str(c.get('approved_by')) + ': ' + (c.get('evidence') or c.get('note') or '')
    elif ec and ec['status'] in ('compliant', 'partial', 'non_compliant'):
        res = {'compliant': 'met', 'partial': 'partial', 'non_compliant': 'gap'}[ec['status']]
        via = eid
        why = 'from NCA ECC ' + eid + ' (confirmed by ' + str(ec.get('by')) + ', approved by ' + str(ec.get('approved_by')) + '): ' + (ec.get('evidence') or ec.get('note') or '')
    elif c:
        res, why = 'pending', 'recorded by ' + str(c.get('by')) + ' as ' + c['status'].replace('_', ' ') + ' - waiting for a second person to approve'
    elif fn:
        res, why = 'not_measured', auto
    else:
        res, why = 'no_evidence', 'no automated source: a person records it with ' + ev + (' (or confirm NCA ECC ' + ', '.join(ecc_ids) + ' once - it counts here too)' if ecc_ids else '')
    return {'id': cid, 'kind': kind, 'group': grp, 'group_name': (CL_GROUP if kind == 'clause' else THEME_NAME)[grp], 'num': list(_num(cid)),
            'title': title, 'evidence_hint': ev, 'automated': fn is not None, 'auto': auto, 'auto_state': st, 'result': res, 'why': why, 'severity': sev,
            'ecc': list(ecc_ids), 'via_ecc': via, 'conflict': bool(st is False and c and c.get('status') in ('compliant', 'not_applicable')),
            'confirmation': ({k: c.get(k) for k in ('status', 'evidence', 'note', 'by', 'at', 'approved_by', 'approved_at')} if c else None)}


def rows_of(req):
    now = req.get('now') or 0
    pr = dict(req.get('profile') or {})
    soa = req.get('soa') or {}
    pr.update({'_ecc': req.get('ecc_profile') or {}, '_now': now, '_reviews': req.get('reviews') or [], '_audits': req.get('audits') or [],
               '_ncs': req.get('ncs') or [], '_history': req.get('history') or [], '_soa': soa})
    excl = {k: v for k, v in (soa.get('exclusions') or {}).items() if k in IDS}
    out = []
    for cid, grp, title, ev, fn, sev in CL:
        out.append(_one('clause', cid, grp, title, ev, [], fn, sev, req.get('facts'), pr, req.get('confirms'), req.get('ecc_confirms'), excl, now))
    for cid, grp, title, ev, ecc_ids, fn, sev in AX:
        out.append(_one('annex', cid, grp, title, ev, ecc_ids, fn, sev, req.get('facts'), pr, req.get('confirms'), req.get('ecc_confirms'), excl, now))
    return out, pr


def soa_rows(rows, soa):
    """the Statement of Applicability: every Annex A control, included or excluded with a justification, and how it is met"""
    excl = (soa or {}).get('exclusions') or {}
    REASON = {'verified': 'implemented - verified by the platform', 'met': 'implemented - confirmed and approved', 'partial': 'partly implemented',
              'gap': 'not implemented - treatment action required', 'pending': 'implementation recorded, awaiting approval', 'not_measured': 'not yet measured',
              'no_evidence': 'implementation not evidenced yet', 'not_applicable': 'excluded'}
    out = []
    for r in rows:
        if r['kind'] != 'annex':
            continue
        inc = r['id'] not in excl
        out.append({'id': r['id'], 'title': r['title'], 'applicable': inc,
                    'justification': ('risk treatment and baseline requirement' + (' (also NCA ECC ' + ', '.join(r['ecc']) + ')' if r['ecc'] else '')) if inc else str(excl[r['id']] or ''),
                    'implementation': REASON.get(r['result'], r['result']), 'result': r['result'], 'evidence': r['why']})
    return out


def soa_hash(soa_list):
    """what an approval commits to: applicability and justification of every control (not the moving evidence)"""
    s = json.dumps([[x['id'], x['applicable'], x['justification'] if not x['applicable'] else ''] for x in soa_list], separators=(',', ':'))
    return hashlib.sha256(s.encode()).hexdigest()


SCORE = {'verified': 1.0, 'met': 1.0, 'partial': 0.5}


def _roll(rs):
    app = [r for r in rs if r['result'] != 'not_applicable']
    cnt = {}
    for r in rs:
        cnt[r['result']] = cnt.get(r['result'], 0) + 1
    lv = E._nca(app)
    if not app:
        return {'score': None, 'counts': cnt, 'controls': len(rs), 'levels': lv}
    return {'score': round(100 * sum(SCORE.get(r['result'], 0) for r in app) / len(app)), 'counts': cnt, 'controls': len(rs), 'levels': lv,
            'automated': sum(1 for r in app if r['automated']), 'verified_auto': sum(1 for r in app if r['result'] == 'verified'),
            'via_ecc': sum(1 for r in app if r['via_ecc'])}


def readiness(rows, ncs):
    by = {r['id']: r for r in rows}
    ok = lambda i: by[i]['result'] in ('verified', 'met')
    s1 = [{'id': i, 'title': by[i]['title'], 'ok': ok(i), 'why': by[i]['why']} for i in ('4.3', '4.4', '5.2', '5.3', '6.1.2', '6.1.3', '6.2', '9.2', '9.3')]
    ann = [r for r in rows if r['kind'] == 'annex' and r['result'] != 'not_applicable']
    impl = sum(1 for r in ann if r['result'] in ('verified', 'met'))
    major = [x['id'] for x in ncs or [] if x.get('grade') == 'major' and x.get('status') not in ('closed', 'cancelled')]
    s2pct = round(100 * impl / len(ann)) if ann else 0
    blockers = [x['id'] + ' ' + x['title'] for x in s1 if not x['ok']] + (['open major nonconformit(ies): ' + ', '.join(major)] if major else [])
    stage = 'stage2' if not blockers and s2pct >= 90 else 'stage1' if all(x['ok'] for x in s1) else 'not_ready'
    return {'stage': stage, 'stage1': s1, 'stage1_ok': sum(1 for x in s1 if x['ok']), 'annex_implemented': impl, 'annex_applicable': len(ann),
            'annex_pct': s2pct, 'open_major': major, 'blockers': blockers[:12],
            'note': 'Indicative, from this register - the certification body decides. Stage 2 is shown when every Stage 1 item is met, no major nonconformity is open and at least 90% of the applicable Annex A controls are implemented.'}


def findings(rows, pr, audits, ncs, soa, now):
    F = []
    for r in rows:
        if r['result'] == 'gap':
            F.append({'key': 'iso:' + r['id'], 'severity': r['severity'], 'kind': 'iso-' + r['kind'],
                      'title': 'ISO 27001 ' + r['id'] + ' ' + r['title'], 'evidence': [x for x in [r['why'], ('a person recorded it as compliant, but the automated evidence shows the gap' if r['conflict'] else '')] if x],
                      'recommendation': 'Close the gap and keep the evidence (' + r['evidence_hint'] + '); the register re-checks it on every patrol.', 'requirement': r['id']})
    for a in audits or []:
        if a.get('status') not in ('reported', 'cancelled') and (ms(a.get('due')) or 0) < now:
            F.append({'key': 'iso:audit:' + str(a.get('id')), 'severity': 'high' if a.get('unit') == 'ISMS' else 'medium', 'kind': 'iso-audit',
                      'title': 'ISO 27001 internal audit ' + str(a.get('id')) + ' (' + UNIT_NAME.get(a.get('unit'), a.get('unit')) + ') is overdue',
                      'evidence': ['due ' + str(a.get('due'))[:10] + ', status ' + str(a.get('status')) + (', auditor ' + a['auditor'] if a.get('auditor') else ', no auditor assigned')],
                      'recommendation': 'Assign an independent auditor and complete it - the working paper is already prepared from the register.', 'requirement': '9.2'})
    for x in ncs or []:
        if x.get('status') not in ('closed', 'cancelled') and (ms(x.get('due')) or 0) < now:
            F.append({'key': 'iso:nc:' + str(x.get('id')), 'severity': 'high' if x.get('grade') == 'major' else 'medium', 'kind': 'iso-nc',
                      'title': 'ISO 27001 nonconformity ' + str(x.get('id')) + ' (' + str(x.get('grade')) + ', ' + str(x.get('requirement')) + ') past due',
                      'evidence': [str(x.get('statement') or '')[:200], 'owner ' + str(x.get('owner') or 'none') + ', status ' + str(x.get('status'))],
                      'recommendation': 'Record the root cause and the corrective action; a different person verifies it worked before it closes.', 'requirement': '10.2'})
    un = [r for r in rows if r['result'] in ('no_evidence', 'not_measured')]
    if un:
        F.append({'key': 'iso:evidence', 'severity': 'low', 'kind': 'iso-evidence', 'title': 'ISO 27001: ' + str(len(un)) + ' requirement(s) not evidenced yet',
                  'evidence': [r['id'] + ': ' + r['why'][:120] for r in un][:8], 'recommendation': 'Connect the source named, or record the evidence once (a second person approves); an approved NCA ECC confirmation counts too.', 'requirement': 'evidence'})
    return F


def view(req):
    now = req.get('now') or 0
    rows, pr = rows_of(req)
    soa = req.get('soa') or {}
    sl = soa_rows(rows, soa)
    h = soa_hash(sl)
    stale = ''
    if soa.get('approved_by') and soa.get('hash') and soa['hash'] != h:
        stale = 'applicability or a justification changed since it was approved'
    if stale:
        soa = dict(soa, stale=stale)
        pr['_soa'] = soa
        rows, pr = rows_of(dict(req, soa=soa))
    cl = [r for r in rows if r['kind'] == 'clause']
    ax = [r for r in rows if r['kind'] == 'annex']
    groups = [dict({'code': g, 'name': n, 'kind': 'clause'}, **_roll([r for r in cl if r['group'] == g])) for g, n in CL_GROUP.items()]
    themes = [dict({'code': t, 'name': n, 'kind': 'annex'}, **_roll([r for r in ax if r['group'] == t])) for t, n in THEMES]
    facts = req.get('facts') or {}
    srcs = [{'id': k, 'connected': bool(E._src(facts, k))} for k in ('grc', 'risk', 'drills', 'ownership', 'hardening', 'pentest', 'cadence', 'certs', 'mail', 'vendor', 'pdpl', 'siem')]
    for r in rows:
        r['level'] = 'not_applicable' if r['result'] == 'not_applicable' else E.NCA_LEVEL.get(r['result'], 'not_assessed')
    total = _roll(rows)
    return {'ok': True, 'clauses': cl, 'annex': ax, 'groups': groups, 'themes': themes, 'score': total['score'], 'counts': total['counts'], 'levels': total['levels'],
            'clauses_roll': _roll(cl), 'annex_roll': _roll(ax), 'automated': total.get('automated', 0), 'via_ecc': total.get('via_ecc', 0), 'sources': srcs,
            'soa': {'rows': sl, 'hash': h, 'applicable': sum(1 for x in sl if x['applicable']), 'excluded': sum(1 for x in sl if not x['applicable']),
                    'stale': stale, 'approved_hash': soa.get('hash')},
            'readiness': readiness(rows, req.get('ncs')), 'findings': findings(rows, pr, req.get('audits'), req.get('ncs'), soa, now),
            'note': 'ISO/IEC 27001:2022 clauses 4-10 and Annex A, verified from the platform\'s evidence (the same checks as the NCA ECC register). The score and readiness are indicative - the certification body decides.'}


def _unit_of(r):
    for uid, _, fn in UNITS:
        if fn(r):
            return uid
    return None


def plan(req):
    """every unit once per cycle, spread evenly; the units with the most gaps / unevidenced items first (risk-based, 9.2.2)"""
    rows = req.get('rows') or []
    months = max(3, min(36, _n(req.get('months')) or 12))
    start = ms(req.get('start')) or req.get('now') or 0
    weight = {}
    for r in rows:
        u = _unit_of(dict(r, num=tuple(r.get('num') or _num(r['id']))))
        if not u:
            continue
        w = {'gap': 3, 'partial': 2, 'pending': 1, 'not_measured': 1, 'no_evidence': 1}.get(r.get('result'), 0) * (2 if r.get('severity') == 'high' else 1)
        weight[u] = weight.get(u, 0) + w
    order = sorted(UNITS, key=lambda u: (-weight.get(u[0], 0), UNITS.index(u)))
    step = months / float(len(order))
    out = []
    for i, (uid, name, _) in enumerate(order):
        due = datetime.fromtimestamp((start + int((i + 1) * step * 30.44 * DAY)) / 1000.0, tz=timezone.utc).strftime('%Y-%m-%d')
        scope = [r['id'] for r in rows if _unit_of(dict(r, num=tuple(r.get('num') or _num(r['id'])))) == uid]
        out.append({'unit': uid, 'name': name, 'due': due, 'risk': weight.get(uid, 0), 'scope': scope})
    return {'ok': True, 'audits': out, 'months': months}


def prepare(req):
    """the working paper: a test per requirement in the unit, the evidence the platform holds, a proposed finding"""
    uid = req.get('unit')
    if uid not in UNIT_NAME:
        return {'ok': False, 'error': 'unknown audit unit ' + str(uid)}
    tests = []
    for r in req.get('rows') or []:
        if _unit_of(dict(r, num=tuple(r.get('num') or _num(r['id'])))) != uid or r.get('result') == 'not_applicable':
            continue
        res = r.get('result')
        if res == 'gap':
            grade = 'major' if (r.get('kind') == 'clause' and r.get('severity') == 'high') else 'minor'
        elif res == 'partial':
            grade = 'ofi'
        elif res in ('no_evidence', 'not_measured', 'pending'):
            grade = 'evidence_request'
        else:
            grade = 'conforming'
        tests.append({'id': r['id'], 'title': r.get('title'), 'method': 'automated re-performance' if r.get('auto_state') is not None else 'inspection of approved confirmation' if res in ('met', 'partial') else 'inquiry and inspection',
                      'result': res, 'evidence': r.get('why'), 'proposed': grade, 'evidence_hint': r.get('evidence_hint')})
    cnt = {}
    for t in tests:
        cnt[t['proposed']] = cnt.get(t['proposed'], 0) + 1
    return {'ok': True, 'unit': uid, 'name': UNIT_NAME[uid], 'tests': tests, 'proposed': cnt,
            'note': 'Prepared from the register on ' + datetime.fromtimestamp((req.get('now') or 0) / 1000.0, tz=timezone.utc).strftime('%Y-%m-%d') + '. Every proposed finding is the auditor\'s to accept, change or drop.'}


def pack(req):
    """ISO 27001 9.3.2 inputs (a)-(g), built from the records - the meeting and its decisions stay with people"""
    v = req.get('view') or {}
    now = req.get('now') or 0
    rv = [r for r in req.get('reviews') or [] if r.get('status') == 'held']
    prev = max(rv, key=lambda r: ms(r.get('held_on')) or 0) if rv else None
    ncs = [x for x in req.get('ncs') or [] if x.get('status') != 'cancelled']
    aud = req.get('audits') or []
    hist = req.get('history') or []
    since = ms(prev.get('held_on')) if prev else 0
    rep = [a for a in aud if a.get('status') == 'reported' and (ms(a.get('reported_at')) or 0) >= (since or 0)]
    trend = None
    if hist:
        first = next((h for h in hist if (ms(h.get('at')) or 0) >= (since or 0)), hist[0])
        trend = {'from': first.get('score'), 'to': v.get('score'), 'since': first.get('at')}
    gaps = [r['id'] + ' ' + r['title'] for r in (v.get('clauses') or []) + (v.get('annex') or []) if r.get('result') == 'gap']
    pr = req.get('profile') or {}
    ofis = [t for a in rep for t in (a.get('findings') or []) if t.get('grade') == 'ofi']
    return {'ok': True, 'since': prev.get('held_on') if prev else None, 'inputs': [
        {'id': 'a', 'title': 'Status of actions from previous management reviews', 'items': [str(x.get('title')) + ' - ' + str(x.get('status', 'open')) for x in (prev or {}).get('actions_status') or []] or (['no previous review'] if not prev else ['no action recorded at the last review'])},
        {'id': 'b', 'title': 'Changes in external and internal issues relevant to the ISMS', 'items': ['issues last reviewed ' + str(pr.get('context_reviewed') or 'never')[:10]]},
        {'id': 'c', 'title': 'Changes in needs and expectations of interested parties', 'items': ['interested parties last reviewed ' + str(pr.get('parties_reviewed') or 'never')[:10]]},
        {'id': 'd1', 'title': 'Nonconformities and corrective actions', 'items': ['%d open (%d major), %d closed' % (sum(1 for x in ncs if x.get('status') != 'closed'), sum(1 for x in ncs if x.get('status') != 'closed' and x.get('grade') == 'major'), sum(1 for x in ncs if x.get('status') == 'closed'))]},
        {'id': 'd2', 'title': 'Monitoring and measurement results', 'items': (['register score %s%% (was %s%% on %s)' % (trend['to'], trend['from'], str(trend['since'])[:10])] if trend else ['register score %s%%' % v.get('score')]) + ['%d gap(s): %s' % (len(gaps), '; '.join(gaps[:6]))]},
        {'id': 'd3', 'title': 'Audit results', 'items': ['%s (%s): %s' % (a.get('id'), UNIT_NAME.get(a.get('unit'), a.get('unit')), ', '.join('%s %s' % (k, n) for k, n in sorted((a.get('summary') or {}).items())) or 'no finding') for a in rep] or ['no internal audit reported since the last review']},
        {'id': 'd4', 'title': 'Fulfilment of information security objectives', 'items': ['%s: %s (target %s, owner %s)' % (o.get('objective'), o.get('current') or 'not measured', o.get('target'), o.get('owner')) for o in pr.get('objectives') or []] or ['no objective recorded']},
        {'id': 'e', 'title': 'Feedback from interested parties', 'items': ['recorded by the ISMS manager at the meeting']},
        {'id': 'f', 'title': 'Results of risk assessment and status of risk treatment plan', 'items': [x['why'] for x in (v.get('clauses') or []) if x['id'] in ('6.1.2', '8.3')]},
        {'id': 'g', 'title': 'Opportunities for continual improvement', 'items': ['%s: %s' % (t.get('requirement'), t.get('statement')) for t in ofis][:10] or ['none raised by the audits']},
    ], 'readiness': v.get('readiness'), 'generated_at': datetime.fromtimestamp(now / 1000.0, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}


OPS = {'iso.view': view, 'iso.plan': plan, 'iso.prepare': prepare, 'iso.pack': pack}
