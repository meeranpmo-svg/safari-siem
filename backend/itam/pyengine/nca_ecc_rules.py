# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""NCA Essential Cybersecurity Controls (ECC-1:2018) verification register. Python decides, Node.js commits
(engine/nca-ecc.js): this module reads only the facts it is given and writes nothing.

  ecc.view     {facts, profile, confirms, official, mapping, now} -> domains, subdomains, controls, scores, gaps, findings
  ecc.import   {rows}                                             -> {rows, errors} the official control list, checked
  ecc.suggest  {official, mapping}                                -> a register control for each unmapped official control

The 5 domains and 29 subdomains are ECC-1:2018's. The controls below are THIS PLATFORM'S plain-language register for
the organisation (ids ZS-<subdomain>-nn, e.g. ZS-2-10-01), written for the CISO to verify - they are not the official ECC
control text. The official controls (2-10-3-1 ...) come from the NCA document through the import and are mapped to a
register control; the subdomain in the official code decides which register controls a suggestion may pick.

Each control has automated evidence where the platform or the SIEM holds it:
  verified      the automated evidence shows the control is working
  gap           the automated evidence shows a gap (never hidden by a person's confirmation)
  not_measured  the source that would show it is not connected - the result says what to connect
A control with no automated evidence, or one not measured, is met only when a person records it with evidence and a second
person approves it (the CISO named in the profile or an administrator, never the one who recorded it, never a service or AI
identity). The compliance score is indicative, from this register - it is not NCA's own assessment. Standard library only.
"""
import re
from datetime import datetime, timezone

DAY = 86400000

DOMAINS = [('1', 'Cybersecurity Governance'), ('2', 'Cybersecurity Defense'), ('3', 'Cybersecurity Resilience'),
           ('4', 'Third-Party and Cloud Computing Cybersecurity'), ('5', 'Industrial Control Systems Cybersecurity')]
DOMAIN_NAME = dict(DOMAINS)
SUBDOMAINS = [
    ('1-1', 'Cybersecurity Strategy'), ('1-2', 'Cybersecurity Management'), ('1-3', 'Cybersecurity Policies and Procedures'),
    ('1-4', 'Cybersecurity Roles and Responsibilities'), ('1-5', 'Cybersecurity Risk Management'),
    ('1-6', 'Cybersecurity in Information Technology Projects'), ('1-7', 'Compliance with Cybersecurity Standards, Laws and Regulations'),
    ('1-8', 'Periodical Cybersecurity Review and Audit'), ('1-9', 'Cybersecurity in Human Resources'),
    ('1-10', 'Cybersecurity Awareness and Training Program'),
    ('2-1', 'Asset Management'), ('2-2', 'Identity and Access Management'), ('2-3', 'Information System and Processing Facilities Protection'),
    ('2-4', 'Email Protection'), ('2-5', 'Networks Security Management'), ('2-6', 'Mobile Devices Security'),
    ('2-7', 'Data and Information Protection'), ('2-8', 'Cryptography'), ('2-9', 'Backup and Recovery Management'),
    ('2-10', 'Vulnerabilities Management'), ('2-11', 'Penetration Testing'), ('2-12', 'Cybersecurity Event Logs and Monitoring Management'),
    ('2-13', 'Cybersecurity Incident and Threat Management'), ('2-14', 'Physical Security'), ('2-15', 'Web Application Security'),
    ('3-1', 'Cybersecurity Resilience Aspects of Business Continuity Management'),
    ('4-1', 'Third-Party Cybersecurity'), ('4-2', 'Cloud Computing and Hosting Cybersecurity'),
    ('5-1', 'Industrial Control Systems (ICS) Protection'),
]
SUB_NAME = dict(SUBDOMAINS)
# the CISO records whether these apply to the company, and why (an insurer usually runs no ICS; cloud depends on use)
DECIDE = {'4-2', '5-1'}
STATUSES = ('compliant', 'partial', 'non_compliant', 'not_applicable')


def ms(v):
    if isinstance(v, (int, float)):
        return int(v)
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    try:
        if len(s) == 10:
            d = datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        else:
            d = datetime.fromisoformat(s[:-1] + '+00:00' if s.endswith('Z') else s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def _n(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _within(v, now, days):
    t = ms(v)
    return t is not None and now - t <= days * DAY


def _src(f, k):
    """a fact source: None when not connected (the page says what to connect)"""
    s = (f or {}).get(k)
    return s if isinstance(s, dict) and s.get('available') else None


MONTHS = {m: i for i, m in enumerate(['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'], 1)}


def _review_ms(v):
    t = ms(v)
    if t is not None:
        return t
    m = re.match(r'^\s*([A-Za-z]+)\s+(\d{4})\s*$', str(v or ''))
    if not m or m.group(1).lower() not in MONTHS:
        return None
    y, mo = int(m.group(2)), MONTHS[m.group(1).lower()]
    return int(datetime(y + (mo == 12), mo % 12 + 1, 1, tzinfo=timezone.utc).timestamp() * 1000) - 1


def _pol(f, rx, now):
    g = _src(f, 'grc')
    if not g:
        return None, 'the GRC policy register was not read'
    for p in g.get('policies') or []:
        if not re.search(rx, str(p.get('title') or ''), re.I) or not re.search(r'approved|active|effective|published', str(p.get('status') or ''), re.I):
            continue
        nr = _review_ms(p.get('next_review'))
        if nr and nr < now:
            return False, str(p.get('title')) + ' - approved, but its review was due ' + str(p.get('next_review'))
        return True, str(p.get('title')) + ' (GRC policy register)'
    return False, 'no approved policy in the GRC register matching this control - GRC -> Policies & Controls'


def _sig(f, key):
    g = _src(f, 'grc')
    return ((g or {}).get('control_status') or {}).get(key) if g else None


def _siem_sama(f, ids, what):
    """the SIEM's SAMA CSF evidence for the overlapping controls (only SIEM-evidenced ones count)"""
    s = _src(f, 'siem')
    if not s or not isinstance(s.get('sama'), dict):
        return None, 'not measured: the SIEM link does not answer - connect it (Connections & Setup -> SIEM) to read ' + what
    st = [(i, s['sama'].get(i)) for i in ids if s['sama'].get(i) in ('covered', 'partial', 'gap')]
    if not st:
        return None, 'not measured: the SIEM evidences none of SAMA ' + ', '.join(ids) + ' (' + what + ')'
    bad = [i + ' ' + v for i, v in st if v != 'covered']
    return (False, 'SIEM: SAMA ' + ', '.join(bad) + ' (' + what + ')') if bad else (True, 'SIEM: SAMA ' + ', '.join(i for i, _ in st) + ' covered (' + what + ')')


def _pdpl(f, rid, what):
    p = _src(f, 'pdpl')
    if not p:
        return None, 'not measured: the AI PDPL Consultant is not installed'
    r = (p.get('requirements') or {}).get(rid)
    if r == 'compliant':
        return True, 'PDPL ' + rid + ' ' + what + ': compliant (AI PDPL Consultant)'
    if r in ('non_compliant', 'partial'):
        return False, 'PDPL ' + rid + ' ' + what + ': ' + r.replace('_', ' ') + ' (AI PDPL Consultant)'
    return None, 'PDPL ' + rid + ' ' + what + ': not assessed yet'


# ---- automated evidence: (True shows it | False shows a gap | None not measured, evidence)
def a_ciso(f, pr, now):
    if pr.get('ciso_user') and pr.get('function_established'):
        rep = pr.get('reports_to') or ''
        if rep and re.search(r'\b(cio|it)\b', rep, re.I):
            return False, 'the cybersecurity function reports to ' + rep + ' - ECC expects it independent of IT'
        return True, 'CISO ' + pr['ciso_user'] + '; cybersecurity function established ' + str(pr['function_established']) + (', reports to ' + rep if rep else '')
    return False, 'no CISO and / or cybersecurity function recorded in the ECC profile'


def a_strategy(f, pr, now):
    if not pr.get('strategy_approved'):
        return False, 'no approved cybersecurity strategy recorded in the ECC profile'
    return (True, 'strategy approved ' + pr['strategy_approved']) if _within(pr['strategy_approved'], now, 3 * 365) else (False, 'strategy approved ' + pr['strategy_approved'] + ' - older than 3 years, review it')


def a_committee(f, pr, now):
    last = pr.get('committee_last_met')
    if not last:
        return False, 'no cybersecurity steering committee meeting recorded'
    return (True, 'steering committee last met ' + str(last)[:10]) if _within(last, now, 120) else (False, 'steering committee last met ' + str(last)[:10] + ' - more than a quarter ago')


def a_policies_current(f, pr, now):
    g = _src(f, 'grc')
    if not g:
        return None, 'not measured: the GRC policy register was not read'
    ov = _n(g.get('reviews_overdue'))
    return (False, str(ov) + ' of ' + str(_n(g.get('total'))) + ' policies past their review date') if ov else (True, str(_n(g.get('total'))) + ' policies, all within their review cycle')


def a_attested(f, pr, now):
    g = _src(f, 'grc')
    if not g or not _n(g.get('total')):
        return None, 'not measured: no policy register read'
    a, t = _n(g.get('attested')), _n(g.get('total'))
    return (True, str(a) + ' of ' + str(t) + ' policies attested by their owners') if a * 2 >= t else (False, 'only ' + str(a) + ' of ' + str(t) + ' policies attested by their owners')


def a_roles(f, pr, now):
    s = _sig(f, 'roles')
    if not s or s.get('state') == 'unknown':
        return None, 'not measured: no roles defined in Roles & Functions'
    return (s.get('state') == 'pass', 'Roles & Functions: ' + str(s.get('metric') or '') + ' - ' + str(s.get('detail') or ''))


def a_risk(f, pr, now):
    r = _src(f, 'risk')
    if not r:
        return None, 'not measured: the GRC risk register was not read'
    if not _n(r.get('total')):
        return False, 'the GRC risk register is empty'
    ov = _n(r.get('review_overdue'))
    return (False, str(ov) + ' risk(s) past their review date') if ov else (True, str(_n(r.get('total'))) + ' risk(s) registered, reviews current')


def a_actions(f, pr, now):
    r = _src(f, 'risk')
    if not r:
        return None, 'not measured: the GRC registers were not read'
    if not _n(r.get('total')) and not _n(r.get('actions_open')):
        return None, 'not measured: no risk and no remediation action recorded yet (GRC -> Registers)'
    od = _n(r.get('actions_overdue'))
    return (False, str(od) + ' remediation action(s) overdue') if od else (True, str(_n(r.get('actions_open'))) + ' open remediation action(s), none overdue')


def a_assets(f, pr, now):
    s = _sig(f, 'assets')
    if not s or s.get('state') == 'unknown':
        return None, 'not measured: no assets registered yet (Asset Discovery)'
    return (s.get('state') == 'pass', 'asset register: ' + str(s.get('metric') or '') + ' - ' + str(s.get('detail') or ''))


def a_owners(f, pr, now):
    o = _src(f, 'ownership')
    if not o or not _n(o.get('assets')):
        return None, 'not measured: no assets to own yet'
    mi, mb, n = _n(o.get('missing_it')), _n(o.get('missing_business')), _n(o.get('assets'))
    return (True, 'every one of ' + str(n) + ' assets has an IT and a business owner') if not (mi or mb) else (False, str(mb) + ' of ' + str(n) + ' assets without a business owner, ' + str(mi) + ' without an IT owner')


def a_privileged(f, pr, now):
    return _siem_sama(f, ['3.3.5'], 'identity and access management')


def a_hardening(f, pr, now):
    h = _src(f, 'hardening')
    if not h or not _n(h.get('assets')):
        return None, 'not measured: no hardening snapshot yet (Hardening -> scan)'
    cov, cf = h.get('coverage_pct'), _n(h.get('critical_fail'))
    if cov is None or cov < 80:
        return False, 'hardening coverage ' + str(cov) + '% of assets - scan the rest'
    return (False, str(cf) + ' critical hardening check(s) failing') if cf else (True, 'hardening: ' + str(cov) + '% of assets scanned, score ' + str(h.get('score')) + ', no critical failure')


def a_patch(f, pr, now):
    s = _sig(f, 'patch')
    if not s or s.get('state') == 'unknown':
        return None, 'not measured: connect Endpoint Central (patch management)'
    return (s.get('state') == 'pass', 'patching: ' + str(s.get('metric') or '') + ' - ' + str(s.get('detail') or ''))


def a_mail(f, pr, now):
    m = _src(f, 'mail')
    if not m:
        return None, 'not measured: no mail gateway or mail reputation connected (Email -> Mail servers)'
    bad = _n(m.get('listed'))
    if not _n(m.get('ips')):
        return None, 'not measured: no public mail IP recorded'
    return (False, str(bad) + ' public mail IP(s) on a block list') if bad else (True, str(_n(m.get('ips'))) + ' public mail IP(s), none block-listed')


def a_mail_auth(f, pr, now):
    m = _src(f, 'mail')
    if not m or m.get('dmarc') is None:
        return None, 'not measured: no domain checked for SPF / DKIM / DMARC'
    return (bool(m.get('dmarc')), 'DMARC ' + ('enforced' if m.get('dmarc') else 'missing or not enforcing') + ' on the mail domain')


def a_netsec(f, pr, now):
    return _siem_sama(f, ['3.3.8'], 'infrastructure / network security')


def a_crypto(f, pr, now):
    c = _src(f, 'certs')
    if not c or not _n(c.get('endpoints')):
        return None, 'not measured: no TLS endpoint registered (Certificates)'
    bad = _n(c.get('expired')) + _n(c.get('weak'))
    return (False, str(_n(c.get('expired'))) + ' expired certificate(s), ' + str(_n(c.get('weak'))) + ' weak key(s)') if bad else (True, str(_n(c.get('endpoints'))) + ' TLS endpoint(s), none expired, no weak key')


def a_backup(f, pr, now):
    s = _sig(f, 'backup')
    if not s or s.get('state') == 'unknown':
        return None, 'not measured: no backup platform connected'
    return (s.get('state') == 'pass', 'backups: ' + str(s.get('metric') or '') + ' - ' + str(s.get('detail') or ''))


def a_restore(f, pr, now):
    d = _src(f, 'drills')
    if not d:
        return None, 'not measured: the DR & BCM drill register was not read'
    if not _n(d.get('systems_total')):
        return False, 'no system has a recovery drill recorded'
    ov = _n(d.get('systems_overdue'))
    return (False, str(ov) + ' of ' + str(_n(d.get('systems_total'))) + ' systems past their drill cadence') if ov else (True, str(_n(d.get('systems_tested'))) + ' system(s) recovery-tested within cadence')


def a_vulns(f, pr, now):
    p = _src(f, 'pentest')
    if not p or not _n(p.get('assets')):
        return None, 'not measured: no asset in the attack-surface assessment yet (Asset Discovery)'
    by = p.get('by_severity') or {}
    c, h = _n(by.get('critical')), _n(by.get('high'))
    return (False, str(c) + ' critical and ' + str(h) + ' high open finding(s)') if (c or h) else (True, str(_n(p.get('findings'))) + ' open finding(s), none critical or high')


def a_exposed(f, pr, now):
    p = _src(f, 'pentest')
    if not p or not _n(p.get('assets')):
        return None, 'not measured: no asset in the attack-surface assessment yet (Asset Discovery)'
    e = _n(p.get('exposed_assets'))
    return (False, str(e) + ' internet-facing asset(s) with risky services exposed') if e else (True, str(_n(p.get('internet_facing'))) + ' internet-facing asset(s), none with risky services')


def a_pentest(f, pr, now):
    c = _src(f, 'cadence')
    if not c or not _n(c.get('assets')):
        return None, 'not measured: no asset in the security testing schedule'
    o = _n(c.get('out_of_policy'))
    return (False, str(o) + ' of ' + str(_n(c.get('assets'))) + ' assets never tested or overdue for a penetration test / VAPT') if o else (True, 'all ' + str(_n(c.get('assets'))) + ' assets tested within the security testing cadence')


def a_logs(f, pr, now):
    s = _src(f, 'siem')
    lf = (s or {}).get('logflow') if s else None
    if not isinstance(lf, dict) or not _n(lf.get('required')):
        return None, 'not measured: the SIEM log-flow assurance does not answer (connect the SIEM link)'
    sil = _n(lf.get('silent')) + _n(lf.get('not_onboarded')) + _n(lf.get('no_connector'))
    return (False, str(sil) + ' of ' + str(_n(lf.get('required'))) + ' required log sources silent or not onboarded') if sil else (True, 'all ' + str(_n(lf.get('required'))) + ' required log sources reporting to the SIEM')


def a_retention(f, pr, now):
    s = _src(f, 'siem')
    if not s or s.get('retention_days') is None:
        return None, 'not measured: the SIEM did not report its log retention'
    d = _n(s.get('retention_days'))
    return (True, 'SIEM keeps logs ' + str(d) + ' days') if d >= 365 else (False, 'SIEM keeps logs ' + str(d) + ' days - ECC expects at least 12 months')


def a_monitor(f, pr, now):
    return _siem_sama(f, ['3.3.14'], 'event management / monitoring')


def a_incident(f, pr, now):
    return _siem_sama(f, ['3.3.15'], 'incident management')


def a_threat(f, pr, now):
    return _siem_sama(f, ['3.3.16'], 'threat management')


def a_bcm(f, pr, now):
    d = _src(f, 'drills')
    if not d:
        return None, 'not measured: the DR & BCM drill register was not read'
    if not _n(d.get('completed_12m')):
        return False, 'no DR / BCM drill completed in 12 months'
    return (False, str(_n(d.get('awaiting_signoff'))) + ' completed drill(s) not signed off') if _n(d.get('awaiting_signoff')) else (True, str(_n(d.get('completed_12m'))) + ' drill(s) completed and signed off in 12 months')


def a_vendors(f, pr, now):
    v = _src(f, 'vendor')
    if not v or not _n(v.get('vendors')):
        return None, 'not measured: no third party recorded (PDPL -> Processors)'
    bad = _n(v.get('due')) + _n(v.get('unrated'))
    return (False, str(_n(v.get('due'))) + ' vendor assessment(s) overdue, ' + str(_n(v.get('unrated'))) + ' vendor(s) not rated') if bad else (True, str(_n(v.get('vendors'))) + ' third parties rated and assessed in date')


def a_vendor_risk(f, pr, now):
    v = _src(f, 'vendor')
    if not v or not _n(v.get('vendors')):
        return None, 'not measured: no third party recorded'
    h = _n(v.get('high_residual'))
    return (False, str(h) + ' vendor(s) with high residual risk') if h else (True, 'no vendor with high residual risk')


def a_policy(rx, what):
    def fn(f, pr, now):
        ok, why = _pol(f, rx, now)
        if ok is None:
            return None, 'not measured: ' + why
        return ok, why if ok else (why if 'review' in why else 'no approved ' + what + ' in the GRC register')
    return fn


def a_training(f, pr, now):
    t = (f or {}).get('training_12m')
    if t is None:
        return None, 'not measured: no training register read'
    return (True, str(t) + ' awareness / training session(s) recorded in 12 months') if _n(t) else (False, 'no cybersecurity awareness session recorded in 12 months')


# (id, subdomain, title, evidence a person shows, automated evidence or None, severity of a gap)
C = [
    ('ZS-1-1-01', '1-1', 'A cybersecurity strategy and roadmap are approved by the head of the company and reviewed periodically', 'approved strategy; roadmap', a_strategy, 'high'),
    ('ZS-1-2-01', '1-2', 'A cybersecurity function is established, led by a full-time Saudi CISO, independent of IT', 'organisation chart; CISO appointment', a_ciso, 'high'),
    ('ZS-1-2-02', '1-2', 'A cybersecurity steering committee meets periodically and records its decisions', 'committee charter; minutes', a_committee, 'medium'),
    ('ZS-1-3-01', '1-3', 'Cybersecurity policies and procedures are approved, published and reviewed on schedule', 'policy set with review dates', a_policies_current, 'high'),
    ('ZS-1-3-02', '1-3', 'Policy owners confirm that their policies are followed', 'owner attestations', a_attested, 'medium'),
    ('ZS-1-4-01', '1-4', 'Cybersecurity roles and responsibilities are defined, assigned and approved', 'RACI; role assignments', a_roles, 'medium'),
    ('ZS-1-5-01', '1-5', 'A cybersecurity risk methodology is approved and risks are assessed and reviewed', 'risk register; methodology', a_risk, 'high'),
    ('ZS-1-5-02', '1-5', 'Risk treatment and remediation actions are tracked to closure on time', 'action register', a_actions, 'medium'),
    ('ZS-1-6-01', '1-6', 'Cybersecurity requirements are part of IT projects and changes (secure design, testing before go-live)', 'project / change security reviews', None, 'medium'),
    ('ZS-1-6-02', '1-6', 'Secure software development standards are applied to in-house and outsourced applications', 'secure SDLC standard; code review records', a_policy(r'secure (software )?development|sdlc|application security', 'secure development policy'), 'medium'),
    ('ZS-1-7-01', '1-7', 'National cybersecurity laws and regulations (NCA, SAMA, Insurance Authority, PDPL) are identified and complied with', 'legal and regulatory register', a_policy(r'compliance|regulatory', 'compliance policy'), 'medium'),
    ('ZS-1-8-01', '1-8', 'Cybersecurity controls are reviewed periodically by a party independent of the cybersecurity function', 'internal audit report', a_policy(r'audit', 'audit policy'), 'medium'),
    ('ZS-1-9-01', '1-9', 'Cybersecurity is covered before, during and at the end of employment (screening, agreements, access removal)', 'HR procedure; leaver records', None, 'medium'),
    ('ZS-1-10-01', '1-10', 'A cybersecurity awareness programme runs for all staff, with records', 'awareness plan; attendance', a_training, 'medium'),
    ('ZS-1-10-02', '1-10', 'Staff in sensitive roles receive specialised cybersecurity training', 'training records', None, 'low'),
    ('ZS-2-1-01', '2-1', 'An inventory of information and technology assets is kept current', 'asset register', a_assets, 'high'),
    ('ZS-2-1-02', '2-1', 'Every asset has a named business owner and IT owner', 'ownership matrix', a_owners, 'medium'),
    ('ZS-2-1-03', '2-1', 'An acceptable use policy for assets is approved', 'acceptable use policy', a_policy(r'acceptable use', 'acceptable use policy'), 'low'),
    ('ZS-2-2-01', '2-2', 'Access follows least privilege and need to know; multi-factor authentication for remote and privileged access', 'access policy; MFA configuration', a_privileged, 'high'),
    ('ZS-2-2-02', '2-2', 'User and privileged access is reviewed periodically', 'access review records', None, 'high'),
    ('ZS-2-2-03', '2-2', 'An identity and access management policy is approved', 'IAM policy', a_policy(r'access (control|management)|identity', 'access control policy'), 'medium'),
    ('ZS-2-3-01', '2-3', 'Servers, workstations and network devices are hardened to an approved baseline', 'hardening results', a_hardening, 'high'),
    ('ZS-2-3-02', '2-3', 'Security patches are applied on time', 'patch compliance report', a_patch, 'high'),
    ('ZS-2-3-03', '2-3', 'Anti-malware / EDR protects every endpoint and server', 'EDR coverage report', None, 'high'),
    ('ZS-2-4-01', '2-4', 'E-mail is filtered for spam, phishing and malware, and the mail servers are not block-listed', 'mail gateway reports', a_mail, 'high'),
    ('ZS-2-4-02', '2-4', 'SPF, DKIM and DMARC protect the company\'s mail domains', 'DNS records', a_mail_auth, 'medium'),
    ('ZS-2-5-01', '2-5', 'Networks are segmented and protected by firewalls and intrusion prevention', 'network diagram; firewall policy review', a_netsec, 'high'),
    ('ZS-2-5-02', '2-5', 'Firewall rules and network device configurations are reviewed periodically', 'rule review records', None, 'medium'),
    ('ZS-2-6-01', '2-6', 'Mobile devices and BYOD that reach company data are managed (MDM, encryption, remote wipe)', 'MDM policy and report', None, 'medium'),
    ('ZS-2-7-01', '2-7', 'Data is classified and protected according to its classification', 'classification policy; labels', a_policy(r'classification', 'data classification policy'), 'high'),
    ('ZS-2-7-02', '2-7', 'Personal data is protected as the PDPL requires', 'PDPL compliance', lambda f, pr, now: _pdpl(f, 'P-13', 'security of personal data'), 'high'),
    ('ZS-2-7-03', '2-7', 'Data loss prevention watches e-mail, web and endpoints', 'DLP policy and reports', None, 'medium'),
    ('ZS-2-8-01', '2-8', 'Encryption in transit uses valid certificates and strong keys', 'certificate inventory', a_crypto, 'high'),
    ('ZS-2-8-02', '2-8', 'A cryptography standard (algorithms, key lengths, key management) is approved', 'cryptography standard', a_policy(r'crypto|encryption|key management', 'cryptography standard'), 'medium'),
    ('ZS-2-9-01', '2-9', 'Backups of critical systems and data are taken and protected', 'backup reports', a_backup, 'high'),
    ('ZS-2-9-02', '2-9', 'Restores are tested periodically', 'restore test records', a_restore, 'high'),
    ('ZS-2-10-01', '2-10', 'Vulnerabilities are found by periodic scanning and fixed by severity', 'scan reports; remediation records', a_vulns, 'high'),
    ('ZS-2-10-02', '2-10', 'Internet-facing systems expose no risky services', 'external scan', a_exposed, 'high'),
    ('ZS-2-11-01', '2-11', 'Penetration tests cover every in-scope asset on schedule (critical assets more often)', 'pentest reports', a_pentest, 'high'),
    ('ZS-2-12-01', '2-12', 'Security event logs of every critical system reach the SIEM', 'log source inventory', a_logs, 'high'),
    ('ZS-2-12-02', '2-12', 'Security events are monitored and alerts are acted on (SOC)', 'SOC reports', a_monitor, 'high'),
    ('ZS-2-12-03', '2-12', 'Security event logs are kept for at least 12 months (log retention)', 'retention configuration', a_retention, 'medium'),
    ('ZS-2-13-01', '2-13', 'Cybersecurity incidents are handled to a plan and reported to NCA as required', 'incident plan; incident records', a_incident, 'high'),
    ('ZS-2-13-02', '2-13', 'Threat intelligence is received and acted on', 'threat intelligence feeds and actions', a_threat, 'medium'),
    ('ZS-2-14-01', '2-14', 'Physical access to data centres and sensitive areas is controlled, logged and reviewed', 'access logs; CCTV', None, 'medium'),
    ('ZS-2-15-01', '2-15', 'Web applications are protected (WAF, secure configuration, multi-tier architecture) and tested', 'WAF policy; application test reports', None, 'high'),
    ('ZS-3-1-01', '3-1', 'Business continuity covers cybersecurity, and disaster recovery is drilled and signed off', 'BCM plan; drill reports', a_bcm, 'high'),
    ('ZS-3-1-02', '3-1', 'A business continuity / disaster recovery policy is approved', 'BCM / DR policy', a_policy(r'continuity|disaster recovery|\bbcm\b|\bdr\b', 'business continuity policy'), 'medium'),
    ('ZS-4-1-01', '4-1', 'Third parties are risk-rated and assessed on schedule', 'vendor assessments', a_vendors, 'high'),
    ('ZS-4-1-02', '4-1', 'Contracts with third parties carry cybersecurity and confidentiality requirements; high residual risk is treated', 'contract clauses; treatment plans', a_vendor_risk, 'medium'),
    ('ZS-4-2-01', '4-2', 'Cloud and hosting services are approved, with data hosted in the Kingdom where required', 'cloud register; hosting locations', lambda f, pr, now: _pdpl(f, 'P-11', 'cross-border transfers'), 'high'),
    ('ZS-4-2-02', '4-2', 'Cloud security responsibilities are agreed in the contract and reviewed', 'cloud contracts', None, 'medium'),
    ('ZS-5-1-01', '5-1', 'Industrial control systems are segmented from the corporate network and protected', 'ICS architecture', None, 'high'),
]
CONTROLS = {c[0]: c for c in C}


def _conf(confirms, cid):
    c = (confirms or {}).get(cid) or {}
    return c if c.get('status') in STATUSES else None


def controls(facts, profile, confirms, now):
    pr = profile or {}
    dec = pr.get('applicability') or {}
    notes = pr.get('applicability_note') if isinstance(pr.get('applicability_note'), dict) else {}
    out = []
    for cid, sub, title, ev, fn, sev in C:
        st, auto = None, None
        if fn:
            try:
                st, auto = fn(facts or {}, pr, now)
            except (TypeError, ValueError, KeyError, AttributeError) as e:
                st, auto = None, 'automated evidence could not be read (' + type(e).__name__ + ')'
        c = _conf(confirms, cid)
        approved = bool(c and c.get('approved_by'))
        if sub in DECIDE and dec.get(sub) == 'not_applicable':
            res, why = 'not_applicable', 'the CISO decided this subdomain does not apply: ' + str(notes.get(sub) or 'no reason recorded')
        elif st is False:
            res, why = 'gap', auto
        elif st is True:
            res, why = 'verified', auto
        elif approved:
            res = {'compliant': 'met', 'partial': 'partial', 'non_compliant': 'gap', 'not_applicable': 'not_applicable'}[c['status']]
            why = 'confirmed by ' + str(c.get('by')) + ', approved by ' + str(c.get('approved_by')) + ': ' + (c.get('evidence') or c.get('note') or '')
        elif c:
            res, why = 'pending', 'recorded by ' + str(c.get('by')) + ' as ' + c['status'].replace('_', ' ') + ' - waiting for a second person to approve'
        elif fn:
            res, why = 'not_measured', auto
        else:
            res, why = 'no_evidence', 'no automated source: a person records it with ' + ev
        out.append({'id': cid, 'subdomain': sub, 'subdomain_name': SUB_NAME[sub], 'domain': sub.split('-')[0], 'domain_name': DOMAIN_NAME[sub.split('-')[0]],
                    'title': title, 'evidence_hint': ev, 'automated': fn is not None, 'auto': auto, 'auto_state': st, 'result': res, 'why': why, 'severity': sev,
                    'conflict': bool(st is False and c and c.get('status') in ('compliant', 'not_applicable')),
                    'confirmation': ({k: c.get(k) for k in ('status', 'evidence', 'note', 'by', 'at', 'approved_by', 'approved_at')} if c else None)})
    return out


SCORE = {'verified': 1.0, 'met': 1.0, 'partial': 0.5}
# NCA's own assessment language: each applicable control is fully compliant, partially compliant, not compliant or not assessed
# yet (no evidence, source not connected, or waiting for the second person's approval - never counted as compliant)
NCA_LEVEL = {'verified': 'fully', 'met': 'fully', 'partial': 'partially', 'gap': 'not', 'pending': 'not_assessed', 'not_measured': 'not_assessed', 'no_evidence': 'not_assessed'}
NCA_KEYS = ['fully', 'partially', 'not', 'not_assessed']


def _pct(cnt, total):
    """whole percentages that add up to exactly 100 (largest remainder), so the four parts of a bar never show 99 or 101"""
    if not total:
        return {k: 0 for k in NCA_KEYS}
    raw = {k: 100.0 * cnt.get(k, 0) / total for k in NCA_KEYS}
    out = {k: int(raw[k]) for k in NCA_KEYS}
    for k in sorted(NCA_KEYS, key=lambda k: raw[k] - out[k], reverse=True)[:100 - sum(out.values())]:
        out[k] += 1
    return out


def _nca(app):
    cnt = {k: 0 for k in NCA_KEYS}
    for r in app:
        cnt[NCA_LEVEL.get(r['result'], 'not_assessed')] += 1
    n = len(app)
    if not n:
        st = 'not_applicable'
    elif cnt['fully'] == n:
        st = 'fully_compliant'
    elif cnt['fully'] or cnt['partially']:
        st = 'partially_compliant'
    elif cnt['not']:
        st = 'not_compliant'
    else:
        st = 'not_assessed'
    return {'status': st, 'counts': cnt, 'pct': _pct(cnt, n), 'applicable': n}
WORST = ['gap', 'partial', 'pending', 'not_measured', 'no_evidence', 'met', 'verified', 'not_applicable']


def _roll(rs):
    app = [r for r in rs if r['result'] != 'not_applicable']
    cnt = {}
    for r in rs:
        cnt[r['result']] = cnt.get(r['result'], 0) + 1
    if not app:
        return {'score': None, 'status': 'not_applicable', 'counts': cnt, 'controls': len(rs), 'nca': _nca(app)}
    sc = round(100 * sum(SCORE.get(r['result'], 0) for r in app) / len(app))
    st = 'gap' if cnt.get('gap') else 'compliant' if sc == 100 else 'partial' if sc > 0 else 'not_verified'
    return {'score': sc, 'status': st, 'counts': cnt, 'controls': len(rs), 'nca': _nca(app),
            'automated': sum(1 for r in app if r['automated']), 'verified_auto': sum(1 for r in app if r['result'] == 'verified')}


def findings(rows, profile, coverage):
    F = []
    for r in rows:
        if r['result'] == 'gap':
            F.append({'key': 'ecc:' + r['id'], 'severity': r['severity'], 'kind': 'ecc-' + r['subdomain'],
                      'title': 'NCA ECC ' + r['subdomain'] + ' ' + r['subdomain_name'] + ' - ' + r['id'] + ': ' + r['title'],
                      'evidence': [x for x in [r['why'], ('a person recorded it as compliant, but the automated evidence shows the gap' if r['conflict'] else '')] if x],
                      'recommendation': 'Close the gap and keep the evidence (' + r['evidence_hint'] + '); the register re-checks it on every patrol.', 'requirement': r['id']})
    pr = profile or {}
    for sub, name in SUBDOMAINS:
        un = [r for r in rows if r['subdomain'] == sub and r['result'] in ('no_evidence', 'not_measured')]
        if sub in DECIDE and not (pr.get('applicability') or {}).get(sub):
            F.append({'key': 'ecc:decide:' + sub, 'severity': 'low', 'kind': 'ecc-' + sub, 'title': 'NCA ECC ' + sub + ' ' + name + ': decide whether it applies to the company',
                      'evidence': ['the CISO records whether it applies, and why'], 'recommendation': 'NCA ECC page -> Profile: record the decision and the reason.', 'requirement': sub})
        elif un:
            F.append({'key': 'ecc:evidence:' + sub, 'severity': 'low', 'kind': 'ecc-' + sub, 'title': 'NCA ECC ' + sub + ' ' + name + ': ' + str(len(un)) + ' control(s) not verified yet',
                      'evidence': [r['id'] + ': ' + r['why'] for r in un][:8], 'recommendation': 'Connect the source named, or record the evidence on the NCA ECC page (a second person approves).', 'requirement': sub})
    if coverage and coverage.get('total') and coverage.get('unmapped'):
        F.append({'key': 'ecc:official:unmapped', 'severity': 'low', 'kind': 'ecc-official', 'title': 'NCA ECC: ' + str(coverage['unmapped']) + ' official control(s) not mapped to the register',
                  'evidence': [x['code'] + ' ' + x['title'][:80] for x in coverage.get('unmapped_list', [])][:8], 'recommendation': 'NCA ECC page -> Official list: map each one (suggestions are offered).', 'requirement': 'official'})
    return F


def coverage(official, mapping, rows):
    off, mp = official or [], mapping or {}
    res = {r['id']: r['result'] for r in rows}
    un = [o for o in off if mp.get(o.get('code')) not in CONTROLS]
    by, st = {}, {}
    for o in off:
        cid = mp.get(o.get('code'))
        if cid in CONTROLS:
            by.setdefault(cid, []).append(o['code'])
        k = res.get(cid, 'unmapped') if cid in CONTROLS else 'unmapped'
        st[k] = st.get(k, 0) + 1
    return {'total': len(off), 'mapped': len(off) - len(un), 'unmapped': len(un), 'by_result': st, 'by_control': by,
            'unmapped_list': [{'code': o['code'], 'subdomain': o.get('subdomain'), 'title': o.get('title', '')} for o in un][:200]}


def view(req):
    now = req.get('now') or 0
    rows = controls(req.get('facts'), req.get('profile'), req.get('confirms'), now)
    cov = coverage(req.get('official'), req.get('mapping'), rows)
    for r in rows:
        r['official'] = cov['by_control'].get(r['id'], [])
    subs = [dict({'code': s, 'name': n, 'domain': s.split('-')[0], 'decide': s in DECIDE}, **_roll([r for r in rows if r['subdomain'] == s])) for s, n in SUBDOMAINS]
    doms = [dict({'code': d, 'name': n}, **_roll([r for r in rows if r['domain'] == d])) for d, n in DOMAINS]
    total = _roll(rows)
    facts = req.get('facts') or {}
    srcs = [{'id': k, 'connected': bool(_src(facts, k))} for k in ('grc', 'risk', 'drills', 'ownership', 'hardening', 'pentest', 'cadence', 'certs', 'mail', 'vendor', 'pdpl', 'siem')]
    for r in rows:
        r['nca_level'] = 'not_applicable' if r['result'] == 'not_applicable' else NCA_LEVEL.get(r['result'], 'not_assessed')
    return {'ok': True, 'domains': doms, 'subdomains': subs, 'controls': rows, 'score': total['score'], 'counts': total['counts'], 'nca': total['nca'],
            'automated': sum(1 for r in rows if r['automated']), 'sources': srcs,
            'coverage': {k: v for k, v in cov.items() if k != 'by_control'}, 'findings': findings(rows, req.get('profile'), cov),
            'note': 'Register controls (ZS-...) are this platform\'s plain-language register for the CISO to verify against NCA ECC-1:2018; the official ECC controls come from the imported list. The score is indicative, from this register - not NCA\'s own assessment.'}


CODE = re.compile(r'^(?:ECC[ -]?)?([1-5])-(\d{1,2})(?:-(\d{1,2})){0,3}(?:-[PT]\d{1,2})?$', re.I)


def _sub_of(code):
    m = CODE.match(str(code or '').strip())
    if not m:
        return None
    s = m.group(1) + '-' + str(int(m.group(2)))
    return s if s in SUB_NAME else None


def import_rows(req):
    rows, errs, seen = [], [], set()
    for i, r in enumerate(req.get('rows') or []):
        code = re.sub(r'\s+', '', str((r or {}).get('code') or ''))
        title = re.sub(r'\s+', ' ', str((r or {}).get('title') or '')).strip()
        sub = _sub_of(code)
        if not sub:
            errs.append('row ' + str(i + 1) + ': "' + code[:30] + '" is not an ECC control code (e.g. 2-10-3-1)')
            continue
        if not title:
            errs.append('row ' + str(i + 1) + ': ' + code + ' has no title')
            continue
        if code.upper() in seen:
            errs.append('row ' + str(i + 1) + ': ' + code + ' appears twice')
            continue
        seen.add(code.upper())
        rows.append({'code': code, 'subdomain': sub, 'subdomain_name': SUB_NAME[sub], 'title': title[:1000], 'spec': str((r or {}).get('spec') or '')[:4000]})
    return {'ok': True, 'rows': rows, 'errors': errs[:50], 'error_count': len(errs)}


STOP = set('the and of to a in for is are be by with on or its at as an from that this every each all their'.split())


def _words(s):
    return set(w for w in re.findall(r'[a-z]{3,}', str(s or '').lower()) if w not in STOP)


def suggest(req):
    mp = req.get('mapping') or {}
    out = []
    for o in req.get('official') or []:
        if mp.get(o.get('code')) in CONTROLS:
            continue
        sub = o.get('subdomain') or _sub_of(o.get('code'))
        cands = [c for c in C if c[1] == sub]
        if not cands:
            continue
        w = _words(str(o.get('title')) + ' ' + str(o.get('spec') or ''))
        best = max(cands, key=lambda c: (len(w & _words(c[2] + ' ' + c[3])), -C.index(c)))
        out.append({'code': o['code'], 'control': best[0], 'title': best[2], 'subdomain': sub, 'overlap': len(w & _words(best[2] + ' ' + best[3]))})
    return {'ok': True, 'suggestions': out}


OPS = {'ecc.view': view, 'ecc.import': import_rows, 'ecc.suggest': suggest}
