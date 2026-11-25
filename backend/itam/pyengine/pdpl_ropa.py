# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""RoPA by department (Records of Processing Activities, PDPL Implementing Regulation Art. 33) - the rules behind the
RoPA campaign (engine/pdpl-ropa.js commits what these decide).

How a consultant builds a RoPA, automated: the DPO opens a campaign; each department's data steward describes the
department's processing activities in a guided questionnaire, starting from
  - TEMPLATES: the processing a department typically runs - an insurer's or an operations & maintenance company's, by sector (a starting point - every field is confirmed or
    changed by the steward; a template is never a record), and
  - EVIDENCE: the systems the Data Catalog found holding personal data that the asset register gives to the department,
    and the categories found in them,
then submits; the DPO (a different person) approves or returns it with comments; approved activities become the register.
Every draft is checked as it is written: the Art. 33 contents, the legal basis against the data, impact-assessment
triggers, transfers, retention, recipients, and what the systems hold but the activity does not declare.

  pdpl.ropa_templates      {}                                           -> departments and their template activities
  pdpl.ropa_campaign_view  {campaign, drafts, records, scans, assets, now} -> per department: progress, drafts with issues,
                                                                          suggestions; totals; findings
  pdpl.ropa_approve_plan   {drafts, records}                            -> the register writes an approval makes
  pdpl.ropa_export         {records}                                    -> the Art. 33 register (columns + rows)
"""
from datetime import datetime, timezone
from org_brand import fill as _org_fill
from org_brand import ORG as _ORG

DAY = 86400000
# PDPL Art. 1 sensitive data. Credit data is NOT sensitive: it is its own class (Art. 24, IR Arts. 11 / 27) - explicit consent,
# the person told of every disclosure request - but no impact assessment and no 'sensitive' label because of it.
SENSITIVE = ('health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage')
FIELDS = [('name', 'Activity name'), ('purpose', 'Purpose'), ('legal_basis', 'Legal basis'), ('data_categories', 'Data categories'), ('subjects', 'Data subjects'),
          ('systems', 'Systems'), ('retention_months', 'Retention period'), ('recipients', 'Recipients (internal, processors, authorities)'), ('security_measures', 'Security measures'),
          ('owner', 'Owner department')]
FLAGS = ('automated_decision', 'large_scale_monitoring', 'fraud_scoring', 'profiling', 'automated_underwriting', 'telematics', 'transfer_outside', 'reinsurance_outside')


def ms(v):
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    if len(s) == 10:
        s += 'T00:00:00'
    try:
        d = datetime.fromisoformat(s.replace('Z', '+00:00'))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def _n(v):
    return str(v or '').strip().lower()


def A(key, name, purpose, basis, cats, subjects, recipients='', flags=(), hint=''):
    return {'key': key, 'name': name, 'purpose': purpose, 'legal_basis': basis, 'data_categories': list(cats), 'subjects': subjects, 'recipients': recipients,
            'flags': list(flags), 'hint': hint}


# Typical processing at a Saudi insurer, per department. Suggestions to start from, never records: the steward confirms or
# changes every field, and the legal basis in particular is the DPO's call (sensitive and credit data need explicit consent
# or another basis the law gives; legitimate interest never covers sensitive data).
TEMPLATES_INSURER = [
    ('underwriting', 'Underwriting', ['underwriting', 'motor', 'medical underwriting', 'pricing'], [
        A('uw_quote', 'Quotation and policy issuance', 'Assess the risk, price and issue the policy', 'contract', ['identity', 'contact', 'financial'], 'Applicants, policyholders, insured persons, drivers', 'Brokers / agents, reinsurers, Najm / Elm where used'),
        A('uw_medical', 'Medical underwriting', 'Assess health risk for medical / life cover', 'explicit_consent', ['identity', 'contact', 'health'], 'Applicants and insured members', 'Medical reviewers, reinsurers', ['automated_underwriting'], 'Health data: explicit consent or another basis the law gives; DPIA required.'),
        A('uw_pricing', 'Pricing models and risk scoring', 'Price policies from risk factors', 'contract', ['identity', 'financial', 'location'], 'Applicants and policyholders', 'Actuarial', ['automated_underwriting', 'profiling'], 'Automated pricing or profiling needs an impact assessment.')]),
    ('claims', 'Claims', ['claims', 'motor claims', 'medical claims'], [
        A('cl_motor', 'Motor claims handling', 'Register, assess and settle motor claims', 'contract', ['identity', 'contact', 'financial', 'location'], 'Claimants, third parties, drivers, witnesses', 'Surveyors, workshops, Najm, reinsurers'),
        A('cl_medical', 'Medical claims processing', 'Assess and pay medical claims', 'contract', ['identity', 'health', 'financial'], 'Insured members, patients', 'Providers (hospitals, clinics), TPA, CHI where required, reinsurers', (), 'Health data under the Council of Health Insurance controls; tiered access.'),
        A('cl_recovery', 'Recoveries and subrogation', 'Recover claim costs from liable parties', 'legitimate_interest', ['identity', 'contact', 'financial'], 'Third parties, claimants', 'Lawyers, other insurers', (), 'Legitimate interest needs a written assessment.')]),
    ('customer_service', 'Customer Service / Call Centre', ['customer service', 'call centre', 'call center', 'contact centre'], [
        A('cs_calls', 'Customer calls and call recording', 'Answer enquiries, record calls for quality and evidence', 'contract', ['identity', 'contact'], 'Customers and callers', 'Call-centre platform provider'),
        A('cs_complaints', 'Complaints handling', 'Record and resolve complaints, report to the regulator', 'legal_obligation', ['identity', 'contact', 'financial'], 'Complainants', 'Insurance Authority / SAMA when escalated'),
        A('cs_dsar', 'Data subject requests', 'Answer access, correction and destruction requests', 'legal_obligation', ['identity', 'contact'], 'Data subjects', 'DPO')]),
    ('sales', 'Sales and Distribution', ['sales', 'distribution', 'brokers', 'bancassurance', 'agents'], [
        A('sa_leads', 'Leads and prospects', 'Contact prospects who asked for a quote', 'consent', ['identity', 'contact'], 'Prospects', 'Brokers / agents'),
        A('sa_commission', 'Broker and agent commissions', 'Calculate and pay commissions', 'contract', ['identity', 'financial'], 'Brokers, agents', 'Finance')]),
    ('marketing', 'Marketing', ['marketing', 'communications', 'digital'], [
        A('mk_campaigns', 'Marketing campaigns (SMS, e-mail)', 'Send offers to people who agreed', 'consent', ['identity', 'contact'], 'Customers and prospects who opted in', 'SMS / e-mail providers', ('profiling',), 'Prior consent and an easy opt-out (PDPL Art. 25).'),
        A('mk_web', 'Website and app analytics, cookies', 'Measure site use and improve the service', 'consent', ['identity', 'location'], 'Visitors', 'Analytics provider', ('profiling',))]),
    ('hr', 'Human Resources', ['hr', 'human resources', 'people', 'personnel'], [
        A('hr_recruit', 'Recruitment', 'Select candidates', 'contract', ['identity', 'contact', 'employment'], 'Candidates', 'Recruitment agencies'),
        A('hr_payroll', 'Payroll and benefits', 'Pay salaries and benefits, GOSI', 'legal_obligation', ['identity', 'financial', 'employment'], 'Employees', 'Bank, GOSI, Mudad / Qiwa'),
        A('hr_medical', 'Employee medical insurance and sick leave', 'Provide cover and manage sick leave', 'contract', ['identity', 'health', 'employment'], 'Employees and dependants', 'Insurer / TPA', (), 'Health data: tiered access.')]),
    ('finance', 'Finance', ['finance', 'accounts', 'treasury', 'collections'], [
        A('fi_payments', 'Premium collection and refunds', 'Collect premiums and pay refunds', 'contract', ['identity', 'financial'], 'Policyholders', 'Banks, payment gateways (SADAD / mada)'),
        A('fi_aml', 'Anti-money-laundering checks', 'Screen customers and report suspicious activity', 'legal_obligation', ['identity', 'financial', 'criminal'], 'Customers and beneficiaries', 'SAFIU when required', (), 'Criminal-record data is sensitive: tiered access, DPIA.')]),
    ('it', 'IT and Information Security', ['it', 'information technology', 'security', 'cyber security', 'infosec'], [
        A('it_accounts', 'User accounts and access management', 'Give and remove system access', 'contract', ['identity', 'employment'], 'Employees, contractors', 'Directory / cloud providers'),
        A('it_logs', 'Security monitoring and logs (SIEM)', 'Detect and investigate security incidents', 'legal_obligation', ['identity', 'location'], 'Employees, customers using online services', 'SOC provider', ('large_scale_monitoring',), 'Continuous monitoring needs an impact assessment; NCA / SAMA require it.')]),
    ('actuarial', 'Actuarial', ['actuarial', 'risk modelling'], [
        A('ac_reserving', 'Reserving and pricing studies', 'Set reserves and review prices', 'legal_obligation', ['identity', 'financial', 'health'], 'Policyholders, claimants', 'Appointed actuary, reinsurers', ('profiling',), 'Use pseudonymised data where the study allows.')]),
    ('fraud', 'Fraud and Special Investigations', ['fraud', 'special investigations', 'siu'], [
        A('fr_detect', 'Fraud detection and investigation', 'Detect and investigate suspected insurance fraud', 'legal_obligation', ['identity', 'contact', 'financial', 'health', 'criminal'], 'Claimants, policyholders, third parties, providers', 'Law enforcement, other insurers when lawful', ('fraud_scoring',), 'Fraud scoring needs an impact assessment; every access to a file needs a case reference (Access Intelligence).')]),
    ('reinsurance', 'Reinsurance', ['reinsurance', 'retrocession'], [
        A('re_cession', 'Reinsurance cessions and bordereaux', 'Cede risks and report to reinsurers', 'contract', ['identity', 'financial', 'health'], 'Policyholders, insured members, claimants', 'Reinsurers (often outside the Kingdom)', ('reinsurance_outside', 'transfer_outside'), 'Record each reinsurer as a transfer; send pseudonymised or aggregated bordereaux where the treaty allows.')]),
    ('legal', 'Legal and Compliance', ['legal', 'compliance', 'regulatory'], [
        A('lg_cases', 'Litigation and legal cases', 'Defend and pursue legal claims', 'legal_obligation', ['identity', 'contact', 'financial', 'health'], 'Claimants, counterparties, witnesses', 'Lawyers, courts'),
        A('lg_regulator', 'Regulatory reporting', 'Report to the Insurance Authority, SAMA, ZATCA and others', 'legal_obligation', ['identity', 'financial'], 'Policyholders, employees', 'Regulators')]),
    ('procurement', 'Procurement', ['procurement', 'purchasing', 'vendors'], [
        A('pr_vendors', 'Vendor management', 'Select and manage suppliers', 'contract', ['identity', 'contact', 'financial'], 'Supplier contacts', 'Finance')]),
    ('facilities', 'Facilities and Physical Security', ['facilities', 'admin', 'administration', 'physical security'], [
        A('fa_cctv', 'CCTV', 'Protect premises and people', 'legitimate_interest', ['biometric', 'location'], 'Employees, visitors', 'Security provider', ('large_scale_monitoring',), 'CCTV is continuous monitoring: impact assessment; legitimate interest cannot cover biometric identification.'),
        A('fa_visitors', 'Visitor management', 'Register visitors to the premises', 'legitimate_interest', ['identity', 'contact'], 'Visitors', '')]),
]
# Typical processing at an operations & maintenance company of a group (project sites, workforce, fleet, services run for the
# group companies). Suggestions to start from, never records: the steward confirms or changes every field; the legal basis is the
# DPO's call. Where the company processes FOR a group company (shared services), the group company is the controller and the
# activity is recorded with that controller and a data processing agreement (PDPL Art. 8).
TEMPLATES_OM = [
    ('hr', 'Human Resources', ['hr', 'human resources', 'people', 'personnel'], [
        A('hr_recruit', 'Recruitment', 'Select candidates for site and office roles', 'contract', ['identity', 'contact', 'employment'], 'Candidates', 'Recruitment agencies'),
        A('hr_payroll', 'Payroll, GOSI and WPS', 'Pay salaries and allowances, register with GOSI, file the wage protection system', 'legal_obligation', ['identity', 'financial', 'employment'], 'Employees', 'Bank, GOSI, Mudad / Qiwa'),
        A('hr_iqama', 'Iqama, visas and travel', 'Obtain and renew residence permits and visas, book travel', 'legal_obligation', ['identity', 'contact', 'parentage'], 'Expatriate employees and dependants', 'Muqeem / Jawazat, travel agency'),
        A('hr_medical', 'Employee medical insurance and sick leave', 'Provide cover and manage sick leave', 'contract', ['identity', 'health', 'employment'], 'Employees and dependants', 'Insurer / TPA', (), 'Health data: tiered access.'),
        A('hr_training', 'Training and certifications', 'Keep the competence and certificates site work needs', 'contract', ['identity', 'employment'], 'Employees, subcontractor staff', 'Training providers, clients asking for proof')]),
    ('operations', 'Operations and Maintenance', ['operations', 'maintenance', 'o&m', 'service delivery', 'facility management'], [
        A('om_workorders', 'Work orders and service records', 'Plan, dispatch and record maintenance work at client sites', 'contract', ['identity', 'contact', 'location', 'employment'], 'Technicians, client site contacts, occupants who report faults', 'Clients (service reports), CMMS provider'),
        A('om_helpdesk', 'Service requests and complaints', 'Receive and resolve fault reports and complaints from sites', 'contract', ['identity', 'contact'], 'Occupants, tenants, client staff', 'Clients')]),
    ('projects', 'Projects and Site Workforce', ['projects', 'sites', 'project sites', 'construction'], [
        A('pj_attendance', 'Site attendance and time-keeping', 'Record who works on which site and for how long', 'contract', ['identity', 'biometric', 'location', 'employment'], 'Employees, subcontractor workers', 'Clients (manpower reports)', ('large_scale_monitoring',), 'Fingerprint or face attendance is biometric: explicit consent or another basis the law gives, and an impact assessment; offer a non-biometric option.'),
        A('pj_subcontractor', 'Subcontractor workforce lists', 'Receive and check the workers subcontractors send to sites', 'contract', ['identity', 'employment'], 'Subcontractor workers', 'Clients, site security')]),
    ('hse', 'Health, Safety and Environment', ['hse', 'safety', 'health and safety', 'qhse'], [
        A('hse_incidents', 'Incident and injury reports', 'Investigate and report incidents and injuries', 'legal_obligation', ['identity', 'health', 'employment'], 'Employees, subcontractor workers, visitors', 'GOSI (occupational injury), clients, insurer', (), 'Injury details are health data: tiered access.'),
        A('hse_fitness', 'Fitness-for-work and medical checks', 'Confirm workers are fit for high-risk work', 'legal_obligation', ['identity', 'health', 'employment'], 'Employees, subcontractor workers', 'Occupational health clinic', (), 'Keep only the fit / not-fit result outside the clinic.')]),
    ('fleet', 'Fleet and Transport', ['fleet', 'transport', 'vehicles', 'logistics'], [
        A('fl_tracking', 'Vehicle tracking and driver behaviour', 'Locate vehicles, plan routes and keep drivers safe', 'legitimate_interest', ['identity', 'location', 'employment'], 'Drivers', 'Telematics provider', ('telematics', 'profiling'), 'Tracking and driver scoring need an impact assessment and a written legitimate-interest assessment; no tracking off duty.'),
        A('fl_licences', 'Driving licences and traffic violations', 'Check licences and settle violations', 'legal_obligation', ['identity', 'employment'], 'Drivers', 'Muroor / Absher, leasing company')]),
    ('site_security', 'Site Security and Access Control', ['security', 'site security', 'access control', 'physical security'], [
        A('ss_access', 'Site access badges and gate logs', 'Control who enters sites and offices', 'legitimate_interest', ['identity', 'biometric', 'location'], 'Employees, contractors, visitors', 'Clients (site owners), security provider', ('large_scale_monitoring',), 'Biometric gates need explicit consent or another basis the law gives; legitimate interest cannot cover biometric data.'),
        A('ss_cctv', 'CCTV at sites and offices', 'Protect people and property', 'legitimate_interest', ['identity', 'location'], 'Employees, visitors, the public near sites', 'Security provider, police on request', ('large_scale_monitoring',), 'CCTV is continuous monitoring: impact assessment, signs, short retention.')]),
    ('group_services', 'Services for Group Companies', ['group services', 'shared services', 'group', 'group companies'], [
        A('gs_shared', 'Shared services run for a group company', 'Run HR, payroll, IT or maintenance for a group company under its instructions', 'contract', ['identity', 'contact', 'financial', 'employment'], 'The group company\'s employees and customers', 'The group company (controller)', (), 'Here the group company is the controller and this company the processor: record the controller and keep a data processing agreement.')]),
    ('procurement', 'Procurement', ['procurement', 'purchasing', 'vendors', 'contracts'], [
        A('pr_vendors', 'Vendor and subcontractor management', 'Select, contract and pay suppliers and subcontractors', 'contract', ['identity', 'contact', 'financial'], 'Supplier and subcontractor contacts', 'Finance')]),
    ('finance', 'Finance', ['finance', 'accounts', 'treasury'], [
        A('fi_payments', 'Payments and expense claims', 'Pay suppliers and staff expense claims', 'contract', ['identity', 'financial'], 'Employees, suppliers', 'Banks'),
        A('fi_einvoice', 'E-invoicing', 'Issue and file e-invoices', 'legal_obligation', ['identity', 'financial'], 'Clients and suppliers (contacts)', 'ZATCA')]),
    ('it', 'IT and Information Security', ['it', 'information technology', 'security operations', 'cyber security', 'infosec'], [
        A('it_accounts', 'User accounts and access management', 'Give and remove system access', 'contract', ['identity', 'employment'], 'Employees, contractors', 'Directory / cloud providers (Microsoft 365)'),
        A('it_logs', 'Security monitoring and logs (SIEM)', 'Detect and investigate security incidents', 'legal_obligation', ['identity', 'location'], 'Employees, contractors, users of online services', 'SOC provider', ('large_scale_monitoring',), 'Continuous monitoring needs an impact assessment; the NCA ECC requires it.')]),
    ('legal', 'Legal and Compliance', ['legal', 'compliance', 'regulatory'], [
        A('lg_cases', 'Legal cases and labour disputes', 'Defend and pursue legal claims', 'legal_obligation', ['identity', 'contact', 'financial', 'employment'], 'Employees, counterparties, witnesses', 'Lawyers, courts, labour offices'),
        A('lg_regulator', 'Regulatory reporting', 'Report to the authorities that apply', 'legal_obligation', ['identity', 'financial'], 'Employees', 'Regulators')]),
]
_SECTOR = str((_ORG or {}).get('sector') or '').lower()


def _pick(sector):
    return TEMPLATES_INSURER if str(sector or '').lower() in ('insurer', 'insurance') else TEMPLATES_OM


TEMPLATES = _pick(_SECTOR)


def _use(req):
    """the template set for this request: req.sector (the platform setting) or the brand's sector"""
    global TEMPLATES, TPL
    TEMPLATES = _pick((req or {}).get('sector') or _SECTOR)
    TPL = {d[0]: d for d in TEMPLATES}
TPL = {d[0]: d for d in TEMPLATES}


def dept_key(name):
    n = _n(name)
    for k, label, aliases, _ in TEMPLATES:
        if n == k or n == _n(label) or n in aliases:
            return k
    return None


def templates(req):
    _use(req)
    return {'departments': [{'key': k, 'name': label, 'aliases': aliases, 'activities': acts} for k, label, aliases, acts in TEMPLATES],
            'note': 'Templates are the processing a department of ' + ('an insurer' if TEMPLATES is TEMPLATES_INSURER else 'an operations and maintenance company') + ' typically runs - a starting point only. Every field is confirmed or changed by the department; a template never becomes a record by itself.'}


def check(d, records, scans_by_system):
    """issues for one draft activity: [{level: gap|warn, field, text}]"""
    out = []
    for k, label in FIELDS:
        if d.get(k) in (None, '', []):
            out.append({'level': 'gap', 'field': k, 'text': label + ' missing (Implementing Regulation Art. 33)'})
    cats = d.get('data_categories') or []
    sens = [c for c in cats if c in SENSITIVE]
    b = d.get('legal_basis')
    if b == 'legitimate_interest' and sens:
        out.append({'level': 'gap', 'field': 'legal_basis', 'text': 'Legitimate interest cannot cover sensitive data (' + ', '.join(sens) + ') - choose another basis'})
    if b == 'legitimate_interest' and 'credit' in cats:
        out.append({'level': 'gap', 'field': 'legal_basis', 'text': 'Credit data needs the person\'s explicit consent (Implementing Regulation Arts. 11, 27) - legitimate interest does not cover it'})
    if b == 'legitimate_interest' and not d.get('lia_done'):
        out.append({'level': 'warn', 'field': 'lia_done', 'text': 'Legitimate interest needs a written assessment before processing'})
    if b == 'consent' and (sens or 'credit' in cats or d.get('automated_decision')):
        out.append({'level': 'gap', 'field': 'legal_basis', 'text': 'Sensitive or credit data, or solely automated decisions, need explicit consent (or another basis the law gives)'})
    triggers = [c for c in sens] + [f for f in ('automated_decision', 'large_scale_monitoring', 'fraud_scoring', 'profiling', 'automated_underwriting', 'telematics') if d.get(f)]
    if (d.get('sources') or 1) >= 2:
        triggers.append('several sources combined')
    if triggers:
        out.append({'level': 'warn', 'field': 'dpia', 'text': 'Needs an impact assessment (' + ', '.join(t.replace('_', ' ') for t in triggers) + ') - the DPIA page opens it once approved'})
    if (d.get('transfer_outside') or d.get('reinsurance_outside')):
        out.append({'level': 'warn', 'field': 'transfer_outside', 'text': 'Data leaves the Kingdom: each recipient is recorded as a transfer with its basis and risk assessment'})
    found = set()
    for s in d.get('systems') or []:
        for c in scans_by_system.get(_n(s), []):
            found.add(c)
    undeclared = sorted(found - set(cats))
    if undeclared:
        out.append({'level': 'warn', 'field': 'data_categories', 'text': 'The Data Catalog found ' + ', '.join(undeclared) + ' data in these systems but the activity does not declare it - add it, or check the data is needed (minimum data, Art. 11)'})
    if d.get('retention_months') and int(d.get('retention_months') or 0) > 240:
        out.append({'level': 'warn', 'field': 'retention_months', 'text': 'Retention over 20 years - give the legal reference'})
    return out


def _scans_by_system(scans):
    m = {}
    for s in scans or []:
        cats = sorted({c.get('category') for c in s.get('columns') or [] if c.get('confirmed') is not False and c.get('category')})
        for k in (s.get('label'), s.get('host'), s.get('service')):
            if k:
                m.setdefault(_n(k), set()).update(cats)
    return m


def _sys_by_dept(scans, assets):
    """systems with personal data per department: the asset register gives a host its department"""
    a_by = {}
    for a in assets or []:
        for k in (a.get('name'), a.get('hostname'), a.get('mgmt_ip')):
            if k:
                a_by[_n(k)] = a
    out = {}
    for s in scans or []:
        if not s.get('ok'):
            continue
        a = a_by.get(_n(s.get('host'))) or a_by.get(_n(s.get('label')))
        if a and a.get('department'):
            cats = sorted({x.get('category') for x in s.get('columns') or [] if x.get('confirmed') is not False and x.get('category')})
            if cats:
                out.setdefault(_n(a.get('department')), []).append({'system': s.get('label'), 'categories': cats})
    return out


def assist_context(req):
    """what the RoPA assistant may show the model for one activity: the steward's fields, the checks, the department's
    template activities and the systems the Data Catalog found in the department - nothing from other departments"""
    _use(req)
    d, dept = req.get('draft') or {}, req.get('department') or ''
    scans, assets = req.get('scans') or [], req.get('assets') or []
    k = dept_key(dept)
    tpls = TPL[k][3] if k else []
    tpl = next((t for t in tpls if t['key'] == d.get('template')), None)
    systems = _sys_by_dept(scans, assets).get(_n(dept), [])
    sbs = _scans_by_system(scans)
    own = [{'system': s, 'categories': sorted(sbs.get(_n(s), set()))} for s in d.get('systems') or []]
    return {'issues': check(d, req.get('records') or [], sbs), 'template': tpl, 'department_templates': [{'key': t['key'], 'name': t['name']} for t in tpls],
            'department_systems': systems, 'draft_systems': own, 'fields': [[f, l] for f, l in FIELDS],
            'known_systems': sorted({x['system'] for x in systems if x.get('system')} | set(d.get('systems') or []))}


def campaign_view(req):
    _use(req)
    c, drafts, recs, now = req.get('campaign') or {}, req.get('drafts') or [], req.get('records') or [], req.get('now') or 0
    scans, assets = req.get('scans') or [], req.get('assets') or []
    sbs = _scans_by_system(scans)
    sys_by_dept = _sys_by_dept(scans, assets)
    ropa = [r for r in recs if r.get('kind') == 'ropa' and r.get('status') != 'archived']
    due = ms(c.get('due'))
    depts, F = [], []
    for name, st in (c.get('departments') or {}).items():
        mine = [d for d in drafts if d.get('department') == name and d.get('status') != 'removed']
        rows = []
        for d in mine:
            iss = check(d, recs, sbs)
            filled = sum(1 for k, _ in FIELDS if d.get(k) not in (None, '', []))
            rows.append({'id': d['id'], 'name': d.get('name'), 'template': d.get('template'), 'ropa_id': d.get('ropa_id'), 'issues': iss, 'gaps': sum(1 for i in iss if i['level'] == 'gap'),
                         'complete': round(filled * 100.0 / len(FIELDS)), 'updated_at': d.get('updated_at'), 'updated_by': d.get('updated_by'), 'fields': {k: d.get(k) for k in [f for f, _ in FIELDS] + list(FLAGS) + ['lia_done', 'sources', 'volume', 'retention_basis', 'controller_notes']}})
        k = dept_key(name)
        used = {d.get('template') for d in mine}
        tpl = [t for t in (TPL[k][3] if k else []) if t['key'] not in used]
        covered = {_n(s) for d in mine for s in d.get('systems') or []} | {_n(s) for r in ropa if _n(r.get('owner')) == _n(name) for s in r.get('systems') or []}
        evidence = [x for x in sys_by_dept.get(_n(name), []) if _n(x['system']) not in covered]
        keep = [f for f, _ in FIELDS] + list(FLAGS) + ['lia_done', 'sources', 'volume', 'retention_basis', 'controller_notes']
        existing = [dict({k: r.get(k) for k in keep if r.get(k) not in (None, '', [])}, id=r['id'], version=r.get('version') or 1, reviewed=r.get('reviewed'))
                    for r in ropa if _n(r.get('owner')) == _n(name) and not any(d.get('ropa_id') == r['id'] for d in mine)]
        progress = round(sum(r['complete'] for r in rows) / len(rows)) if rows else 0
        status = st.get('status') or 'not_started'
        if status == 'not_started' and rows:
            status = 'in_progress'
        late = bool(due and now > due and status != 'approved')
        depts.append({'department': name, 'template_key': k, 'steward': st.get('steward'), 'status': status, 'late': late, 'progress': progress, 'drafts': rows,
                      'gaps': sum(r['gaps'] for r in rows), 'suggest_templates': tpl, 'suggest_systems': evidence, 'existing_records': existing,
                      'submitted_by': st.get('submitted_by'), 'submitted_at': st.get('submitted_at'), 'reviewed_by': st.get('reviewed_by'), 'reviewed_at': st.get('reviewed_at'), 'comments': st.get('comments') or [],
                      'can_submit': bool(rows) and not any(r['gaps'] for r in rows) and status in ('in_progress', 'returned', 'not_started')})
        tgt = {'type': 'pdpl', 'id': c.get('id'), 'name': name}
        if c.get('status') == 'open' and late:
            F.append({'key': 'ropa:' + str(c.get('id')) + ':' + _n(name) + ':late', 'severity': 'medium', 'title': 'RoPA campaign "' + str(c.get('name')) + '": ' + name + ' not approved by ' + str(c.get('due')),
                      'evidence': ['status ' + status, 'steward ' + str(st.get('steward') or 'none named')], 'recommendation': 'Remind the data steward; the DPO reviews what was submitted.', 'requirement': 'P-04', 'target': tgt})
        if c.get('status') == 'open' and status == 'submitted' and ms(st.get('submitted_at')) and now - ms(st.get('submitted_at')) > 7 * DAY:
            F.append({'key': 'ropa:' + str(c.get('id')) + ':' + _n(name) + ':review', 'severity': 'low', 'title': name + ' submitted its RoPA over 7 days ago - waiting for review',
                      'evidence': [], 'recommendation': 'The DPO (or another person than the submitter) approves or returns it with comments.', 'requirement': 'P-04', 'target': tgt})
        if c.get('status') == 'open' and not st.get('steward'):
            F.append({'key': 'ropa:' + str(c.get('id')) + ':' + _n(name) + ':steward', 'severity': 'low', 'title': name + ' has no data steward to complete its RoPA', 'evidence': [],
                      'recommendation': 'Name the data steward on the Programme page.', 'requirement': 'P-04', 'target': tgt})
    depts.sort(key=lambda x: (x['status'] == 'approved', -x['gaps'], x['department']))
    n = len(depts)
    return {'campaign': {k: c.get(k) for k in ('id', 'name', 'due', 'status', 'created_by', 'created_at', 'closed_at')}, 'departments': depts,
            'totals': {'departments': n, 'approved': sum(1 for d in depts if d['status'] == 'approved'), 'submitted': sum(1 for d in depts if d['status'] == 'submitted'),
                       'late': sum(1 for d in depts if d['late']), 'activities': sum(len(d['drafts']) for d in depts), 'gaps': sum(d['gaps'] for d in depts),
                       'progress': round(sum(d['progress'] for d in depts) / n) if n else 0},
            'findings': F, 'fields': [[k, l] for k, l in FIELDS]}


def approve_plan(req):
    """the register writes an approval makes: an update of the linked record, or a new record"""
    recs = {r['id']: r for r in req.get('records') or [] if r.get('kind') == 'ropa'}
    keep = [f for f, _ in FIELDS] + list(FLAGS) + ['lia_done', 'sources', 'volume', 'retention_basis', 'controller_notes']
    out = []
    for d in req.get('drafts') or []:
        if d.get('status') == 'removed':
            continue
        fields = {k: d.get(k) for k in keep if d.get(k) not in (None, '', [])}
        cur = recs.get(d.get('ropa_id'))
        changed = sorted(k for k, v in fields.items() if not cur or cur.get(k) != v)
        out.append({'draft': d['id'], 'op': 'update' if cur else 'create', 'ropa_id': cur['id'] if cur else None, 'fields': fields, 'changed': changed,
                    'version': int((cur or {}).get('version') or 0) + 1})
    return {'writes': out}


def export(req):
    recs = [r for r in req.get('records') or [] if r.get('kind') == 'ropa' and r.get('status') != 'archived']
    prof = next((r for r in req.get('records') or [] if r.get('kind') == 'profile'), {}) or {}
    tr = [r for r in req.get('records') or [] if r.get('kind') == 'transfer']
    dept = _n(req.get('department'))
    cols = ['Id', 'Version', 'Department', 'Activity', 'Purpose', 'Legal basis', 'Data categories', 'Sensitive', 'Credit data', 'Data subjects', 'Approx. number of data subjects', 'Systems', 'Recipients',
            'Transfers outside the Kingdom (country, basis)', 'Retention (months)', 'Retention basis', 'Security measures', 'Controller', 'DPO', 'Approved by', 'Approved on', 'Last reviewed']
    rows = []
    for r in sorted(recs, key=lambda x: (_n(x.get('owner')), _n(x.get('name')))):
        if dept and _n(r.get('owner')) != dept:
            continue
        rows.append([r['id'], r.get('version') or 1, r.get('owner'), r.get('name'), r.get('purpose'), r.get('legal_basis'), ', '.join(r.get('data_categories') or []),
                     ', '.join(c for c in r.get('data_categories') or [] if c in SENSITIVE), 'yes' if 'credit' in (r.get('data_categories') or []) else 'no', r.get('subjects'), r.get('volume'), ', '.join(r.get('systems') or []),
                     ', '.join(r.get('recipients') or []) if isinstance(r.get('recipients'), list) else r.get('recipients'),
                     '; '.join(str(t.get('country')) + ' (' + str(t.get('basis') or 'no basis') + ')' for t in tr if t.get('ropa_id') == r['id']), r.get('retention_months'), r.get('retention_basis'),
                     r.get('security_measures'), _org_fill('{{org.name}}'), prof.get('dpo_user') or '', r.get('approved_by'), r.get('approved_at'), r.get('reviewed')])
    return {'columns': cols, 'rows': rows, 'note': 'Records of processing activities - Implementing Regulation Art. 33: kept for the processing period plus 5 years and given to SDAIA on request.'}


OPS = {'pdpl.ropa_templates': templates, 'pdpl.ropa_campaign_view': campaign_view, 'pdpl.ropa_approve_plan': approve_plan, 'pdpl.ropa_export': export, 'pdpl.ropa_assist_context': assist_context}
