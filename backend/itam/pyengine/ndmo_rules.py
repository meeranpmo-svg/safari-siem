# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""NDMO data management register (National Data Management Office, SDAIA: Data Management and Personal Data Protection
Standards), tailored to an insurer. Python decides, Node.js commits (engine/ndmo.js): this module reads only the facts it
is given and writes nothing.

  ndmo.view     {facts, profile, confirms, official, mapping, now} -> domains, controls, maturity, gaps, findings, coverage
  ndmo.import   {rows}                                             -> {rows, errors} the official control list, checked
  ndmo.suggest  {official, mapping}                                -> a suggested register control for each unmapped official one

The 15 domains are the NDMO standard's. The controls below are THIS PLATFORM'S plain-language register for the organisation
(ids ZS-<domain>-nn), written for the Chief Data Officer to verify - they are not the official NDMO control text. The
official controls come from the NDMO document itself through the import (Excel / CSV saved as rows); each official control
is then mapped to a register control, so a result here answers for the official ones mapped to it.

A control is MET when a person confirmed it with evidence and a second person approved that (four eyes), or when the
automated evidence the platform holds shows it (shown as "automated evidence - awaiting confirmation"). The registers win
over a person: when the automated evidence shows a gap, a confirmation does not hide it. The maturity level is indicative,
computed from this register - it is not NDMO's own assessment. The Personal Data Protection domain is read from the AI PDPL
Consultant (the PDPL requirements), so the two can never disagree. Standard library only.
"""
import re
from datetime import datetime, timezone

DAY = 86400000

# the 15 NDMO domains (short codes used here; the official ones come with the imported list)
DOMAINS = [
    ('DG', 'Data Governance'), ('MCM', 'Data Catalog and Metadata'), ('DQ', 'Data Quality'), ('DO', 'Data Operations'),
    ('DCM', 'Document and Content Management'), ('DAM', 'Data Architecture and Modelling'), ('DSI', 'Data Sharing and Interoperability'),
    ('RMD', 'Reference and Master Data Management'), ('BIA', 'Business Intelligence and Analytics'), ('DVR', 'Data Value Realization'),
    ('OD', 'Open Data'), ('FOI', 'Freedom of Information'), ('DC', 'Data Classification'), ('PDP', 'Personal Data Protection'),
    ('DSP', 'Data Security and Protection'),
]
DOMAIN_NAME = dict(DOMAINS)
# written mainly for public entities: the Chief Data Officer records whether they apply to the company and why
DECIDE = {'OD', 'FOI'}
LEVELS = ['Absence', 'Establishing', 'Defined', 'Activated', 'Managed', 'Pioneer']
STATUSES = ('compliant', 'partial', 'non_compliant', 'not_applicable')


def ms(v):
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
    t = ms(v) if isinstance(v, str) else (v if isinstance(v, (int, float)) else None)
    return t is not None and now - t <= days * DAY


def _pol(facts, rx):
    """the GRC policy register: (True, title) approved and in review date; (None, why) approved but its review is
    overdue; (False, None) no such policy"""
    now = facts.get('_now') or 0
    for p in facts.get('grc_policies') or []:
        if not re.search(rx, str(p.get('title') or ''), re.I):
            continue
        if not re.search(r'approved|active|effective|published', str(p.get('status') or ''), re.I):
            continue
        nr = _review_ms(p.get('next_review'))
        if nr and nr < now:
            return None, p.get('title') + ' - its review was due ' + str(p['next_review'])
        return True, p.get('title')
    return False, None


MONTHS = {m: i for i, m in enumerate(['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'], 1)}


def _review_ms(v):
    """a review date as the register writes it: an ISO date, or "November 2026" (due by the end of that month)"""
    t = ms(v)
    if t is not None:
        return t
    m = re.match(r'^\s*([A-Za-z]+)\s+(\d{4})\s*$', str(v or ''))
    if not m or m.group(1).lower() not in MONTHS:
        return None
    y, mo = int(m.group(2)), MONTHS[m.group(1).lower()]
    nxt = datetime(y + (mo == 12), mo % 12 + 1, 1, tzinfo=timezone.utc)
    return int(nxt.timestamp() * 1000) - 1


def _req(facts, rid):
    p = facts.get('pdpl') or {}
    return (p.get('requirements') or {}).get(rid)


# ---- automated evidence: (state, evidence) where state is True (shows it), False (shows a gap) or None (nothing to read)
def a_cdo(f, pr, now):
    if pr.get('cdo_user') and pr.get('dmo_established'):
        return True, 'Chief Data Officer ' + pr['cdo_user'] + '; data management office established ' + str(pr['dmo_established'])
    return False, 'no Chief Data Officer and / or data management office recorded in the NDMO profile'


def a_strategy(f, pr, now):
    if not pr.get('strategy_approved'):
        return False, 'no approved data management strategy recorded in the NDMO profile'
    return (True, 'strategy approved ' + pr['strategy_approved']) if _within(pr['strategy_approved'], now, 3 * 365) else (False, 'strategy approved ' + pr['strategy_approved'] + ' - older than 3 years, review it')


def a_committee(f, pr, now):
    last = pr.get('committee_last_met') or (f.get('records') or {}).get('committee_last')
    if not last:
        return False, 'no data governance committee meeting recorded'
    return (True, 'committee last met ' + str(last)[:10]) if _within(last, now, 120) else (False, 'committee last met ' + str(last)[:10] + ' - more than a quarter ago')


def a_owners(f, pr, now):
    r = f.get('records') or {}
    deps = set(d for d in (r.get('ropa_departments') or []) if d)
    have = set(d for d in (r.get('stewards_departments') or []) if d)
    if not deps:
        return None, 'no department owns a processing activity yet'
    miss = sorted(deps - have)
    return (True, 'a data steward in each of ' + str(len(deps)) + ' department(s)') if not miss else (False, 'no data steward in: ' + ', '.join(miss[:8]))


def a_training(f, pr, now):
    n = _n((f.get('records') or {}).get('training_12m'))
    return (True, str(n) + ' training session(s) recorded in 12 months') if n else (False, 'no data protection / data management training recorded in 12 months')


def a_audit_policy(f, pr, now):
    rv = (f.get('records') or {}).get('programme_review_last')
    if rv and _within(rv, now, 365):
        return True, 'data protection programme review ' + str(rv)[:10]
    ok, t = _pol(f, r'internal .*audit')
    if ok is True:
        return None, t + ' is in the GRC register; no data management review recorded in 12 months'
    return False, (t or 'no internal audit policy in the GRC register') + '; no data management review recorded in 12 months'


def a_catalog(f, pr, now):
    c = f.get('catalog') or {}
    n = _n(c.get('db_scans'))
    if not n:
        return False, 'no database scanned by the Data Catalog yet'
    return (True, str(n) + ' database(s) in the Data Catalog, last scan ' + str(c.get('db_last_scan') or '')[:10]) if _within(c.get('db_last_scan'), now, 30) else (False, 'the Data Catalog has not scanned for more than 30 days')


def a_metadata(f, pr, now):
    r = f.get('records') or {}
    t, c = _n(r.get('ropa_total')), _n(r.get('ropa_complete'))
    if not t:
        return False, 'no processing activity recorded'
    pct = round(100 * c / t)
    return (pct >= 80, str(c) + ' of ' + str(t) + ' processing activities have owner, purpose, basis, categories, systems and retention (' + str(pct) + '%)')


def a_catalog_fresh(f, pr, now):
    c = f.get('catalog') or {}
    if not _n(c.get('db_scans')):
        return False, 'no automated scan yet'
    return (True, 'scanned within 7 days') if _within(c.get('db_last_scan'), now, 7) else (False, 'last automated scan ' + str(c.get('db_last_scan') or '')[:10] + ' - the weekly scan is late')


def a_unstructured(f, pr, now):
    n = _n((f.get('catalog') or {}).get('files_scanned'))
    return (True, str(n) + ' file(s) scanned (SharePoint / OneDrive / file shares)') if n else (None, 'no file discovery connected (SharePoint / OneDrive / file shares)')


def a_dbmon(f, pr, now):
    o = f.get('ops') or {}
    n = _n(o.get('db_targets'))
    return (True, str(n) + ' database(s) monitored' + (', ' + str(_n(o.get('morning_reports_7d'))) + ' morning health check(s) in 7 days' if _n(o.get('morning_reports_7d')) else '')) if n else (False, 'no database is monitored (Databases page)')


def a_backup(f, pr, now):
    o = f.get('ops') or {}
    ok, t = _pol(f, r'backup')
    if _n(o.get('backup_platforms')):
        return True, str(_n(o.get('backup_platforms'))) + ' backup platform(s), ' + str(_n(o.get('backup_objects'))) + ' protected object(s)' + ((' · ' + t) if t else '')
    if ok is not False:
        return None, t + ' - no backup platform connected to show it works'
    return False, 'no backup platform connected and no backup policy in the GRC register'


def a_retention(f, pr, now):
    r = f.get('records') or {}
    t, w = _n(r.get('ropa_total')), _n(r.get('ropa_with_retention'))
    if not t:
        return None, 'no processing activity recorded'
    return (w == t, str(w) + ' of ' + str(t) + ' activities have a retention period')


def a_ret_rules(f, pr, now):
    n = _n((f.get('records') or {}).get('retention_rules'))
    return (True, str(n) + ' retention rule(s) in the schedule') if n else (False, 'no retention rule in the schedule')


def a_destruction(f, pr, now):
    r = f.get('records') or {}
    due, done = _n(r.get('destruction_due')), _n(r.get('destruction_done_12m'))
    if due:
        return False, str(due) + ' destruction run(s) overdue'
    return (True, str(done) + ' destruction run(s) evidenced in 12 months') if done else (None, 'no destruction due or done yet')


def a_holds(f, pr, now):
    n = _n((f.get('records') or {}).get('holds_overdue'))
    return (False, str(n) + ' legal hold(s) past their review date') if n else (True, 'every legal hold reviewed on time')


def a_arch(f, pr, now):
    o = f.get('ops') or {}
    n = _n(o.get('app_routes'))
    ok, t = _pol(f, r'enterprise architecture')
    if n:
        return True, str(n) + ' application route map(s) (users to database)' + ((' · ' + t) if t else '')
    if ok is not False:
        return None, t + ' - no application route map drawn yet'
    return False, 'no application route map and no enterprise architecture policy in the GRC register'


def a_pbd(f, pr, now):
    n = _n((f.get('records') or {}).get('pbd_12m'))
    return (True, str(n) + ' privacy-by-design review(s) in 12 months') if n else (False, 'no privacy-by-design review of a new system recorded in 12 months')


def a_agreements(f, pr, now):
    r = f.get('records') or {}
    t, w = _n(r.get('processors')), _n(r.get('processors_with_agreement'))
    if not t:
        return None, 'no processor recorded'
    return (w == t, str(w) + ' of ' + str(t) + ' processors / partners have a written agreement')


def a_sharing(f, pr, now):
    r = f.get('records') or {}
    t, w = _n(r.get('transfers')), _n(r.get('transfers_with_basis'))
    if not (t or _n(r.get('processors'))):
        return False, 'no external sharing recorded (TPAs, reinsurers, Najm, regulators)'
    return (w == t, str(_n(r.get('processors'))) + ' processor(s); ' + str(w) + ' of ' + str(t) + ' transfer(s) with a recorded basis')


def a_pdpl(rid, what):
    def fn(f, pr, now):
        p = f.get('pdpl') or {}
        if not p.get('available'):
            return None, 'the AI PDPL Consultant is not answering'
        r = _req(f, rid)
        if r is None:
            return None, rid + ' not assessed'
        if r == 'non_compliant':
            return False, 'PDPL ' + rid + ' (' + what + '): non-compliant on the PDPL registers'
        if r in ('compliant', 'auto_pass'):
            return True, 'PDPL ' + rid + ' (' + what + '): ' + ('confirmed compliant' if r == 'compliant' else 'automated check passed')
        if r == 'not_applicable':
            return True, 'PDPL ' + rid + ': not applicable (recorded on the PDPL page)'
        return None, 'PDPL ' + rid + ' (' + what + '): ' + r.replace('_', ' ')
    return fn


def a_pdpl_all(f, pr, now):
    p = f.get('pdpl') or {}
    if not p.get('available'):
        return None, 'the AI PDPL Consultant is not answering'
    nc = [k for k, v in (p.get('requirements') or {}).items() if v == 'non_compliant']
    return (not nc, 'PDPL compliance ' + str(p.get('compliance_pct', 0)) + '%' + ('; non-compliant: ' + ', '.join(sorted(nc)[:10]) if nc else '; no requirement non-compliant'))


def a_access(f, pr, now):
    p = f.get('pdpl') or {}
    bad = [x for x in (p.get('findings') or []) if str(x.get('key', '')).startswith('access:') and x.get('severity') in ('critical', 'high')]
    if not p.get('access_connected'):
        return None, 'no system sends its sensitive-record access log yet (Access Intelligence)'
    return (not bad, 'sensitive-record access log connected' + (' - ' + str(len(bad)) + ' high / critical exception(s) open' if bad else ', no high exception open'))


def a_classified(f, pr, now):
    c, r = f.get('catalog') or {}, f.get('records') or {}
    if not _n(c.get('db_scans')):
        return False, 'nothing scanned: personal and sensitive data not located yet'
    t, cat = _n(r.get('ropa_total')), _n(r.get('ropa_with_categories'))
    return (t > 0 and cat == t, str(_n(c.get('db_scans'))) + ' database(s) scanned; ' + str(cat) + ' of ' + str(t) + ' activities declare their data categories')


def a_sensitive(f, pr, now):
    p = f.get('pdpl') or {}
    if not p.get('available'):
        return None, 'the AI PDPL Consultant is not answering'
    bad = [x for x in (p.get('findings') or []) if re.search(r'sensitive|P-14|P-06', str(x.get('key', ''))) and x.get('severity') in ('critical', 'high')]
    return (not bad, 'sensitive data controls: ' + (str(len(bad)) + ' high / critical gap(s) on the PDPL registers' if bad else 'no high gap on the PDPL registers'))


def a_policy(rx, what):
    """an approved policy in the GRC register (signed set, or a draft approved on Policies & Controls)"""
    def fn(f, pr, now):
        ok, t = _pol(f, rx)
        if ok is True:
            return True, t + ' (GRC policy register)'
        if ok is None:
            return False, t
        return None, 'no approved ' + what + ' in the GRC register - GRC -> Policies & Controls offers a starter draft to complete and approve'
    return fn


# (id, domain, title, evidence a person shows, automated evidence or None, severity of a gap)
C = [
    ('ZS-DG-01', 'DG', 'A Chief Data Officer is named and a data management office is established', 'appointment decision; data management office charter', a_cdo, 'high'),
    ('ZS-DG-02', 'DG', 'A data management and personal data protection strategy is approved by top management', 'approved strategy and roadmap', a_strategy, 'high'),
    ('ZS-DG-03', 'DG', 'A data governance committee meets at least quarterly and records its decisions', 'committee charter; minutes', a_committee, 'medium'),
    ('ZS-DG-04', 'DG', 'Every department that owns data has a named data owner and data steward', 'data ownership matrix', a_owners, 'medium'),
    ('ZS-DG-05', 'DG', 'Data management policies (governance, quality, classification, sharing, retention) are approved and published', 'approved policy set', a_policy(r'data (governance|management)', 'data governance policy'), 'medium'),
    ('ZS-DG-06', 'DG', 'Staff are trained on data management and personal data protection', 'training records', a_training, 'medium'),
    ('ZS-DG-07', 'DG', 'Data management compliance is reviewed (internal audit or programme review) at least yearly', 'review report; audit plan', a_audit_policy, 'medium'),
    ('ZS-MCM-01', 'MCM', 'A data catalog lists the data assets of every core system (policy admin, claims, medical, finance)', 'catalog export', a_catalog, 'high'),
    ('ZS-MCM-02', 'MCM', 'Business and technical metadata (owner, purpose, system, retention) is recorded for each data asset', 'metadata in the catalog / records of processing', a_metadata, 'medium'),
    ('ZS-MCM-03', 'MCM', 'The catalog is kept current by automated scanning', 'scan schedule and results', a_catalog_fresh, 'low'),
    ('ZS-MCM-04', 'MCM', 'Unstructured data (SharePoint, OneDrive, file shares) is in the catalog too', 'file discovery results', a_unstructured, 'low'),
    ('ZS-DQ-01', 'DQ', 'Data quality rules are defined for critical data (policyholder, insured, claims, premiums, providers)', 'data quality rules per data set', None, 'medium'),
    ('ZS-DQ-02', 'DQ', 'Data quality is measured and reported to the data owners', 'data quality dashboard / report', None, 'medium'),
    ('ZS-DQ-03', 'DQ', 'Data quality issues are logged and tracked to resolution', 'issue log', None, 'low'),
    ('ZS-DQ-04', 'DQ', 'Core systems are reconciled (policy admin vs finance, claims vs payments, regulatory reports vs source)', 'reconciliation evidence', None, 'medium'),
    ('ZS-DO-01', 'DO', 'Databases are inventoried and monitored (availability, capacity, errors)', 'database monitoring', a_dbmon, 'medium'),
    ('ZS-DO-02', 'DO', 'Backups are taken, protected and restore-tested', 'backup policy; restore test records', a_backup, 'high'),
    ('ZS-DO-03', 'DO', 'Every processing activity has a retention period applied in its systems', 'retention per activity', a_retention, 'medium'),
    ('ZS-DO-04', 'DO', 'Storage and capacity are planned for data growth', 'capacity plan', None, 'low'),
    ('ZS-DCM-01', 'DCM', 'A document and records management policy covers paper and electronic records (policies, claims files)', 'records management policy', a_policy(r'retention|records management|disposal', 'records retention / disposal policy'), 'medium'),
    ('ZS-DCM-02', 'DCM', 'A retention schedule exists for documents and records', 'retention schedule', a_ret_rules, 'medium'),
    ('ZS-DCM-03', 'DCM', 'Records are destroyed at the end of retention, with evidence', 'destruction certificates', a_destruction, 'medium'),
    ('ZS-DCM-04', 'DCM', 'Legal holds stop destruction and are reviewed on time', 'legal hold register', a_holds, 'medium'),
    ('ZS-DAM-01', 'DAM', 'The data architecture (systems, data flows, interfaces) is documented', 'architecture diagrams; route maps', a_arch, 'medium'),
    ('ZS-DAM-02', 'DAM', 'Data models of core systems are maintained', 'data models', None, 'low'),
    ('ZS-DAM-03', 'DAM', 'New systems and changes are reviewed for data and privacy by design before go-live', 'design review records', a_pbd, 'medium'),
    ('ZS-DSI-01', 'DSI', 'Every external party receiving data (TPAs, brokers, reinsurers, cloud) has a written data sharing agreement', 'agreements', a_agreements, 'high'),
    ('ZS-DSI-02', 'DSI', 'Data sharing with regulators and industry bodies (Insurance Authority, SAMA, Najm, CHI) is recorded with its basis', 'sharing register', a_sharing, 'medium'),
    ('ZS-DSI-03', 'DSI', 'Sharing outside the Kingdom is assessed and has a lawful basis', 'transfer risk assessments', a_pdpl('P-11', 'cross-border transfers'), 'high'),
    ('ZS-DSI-04', 'DSI', 'Integration interfaces (APIs, file exchanges) are inventoried and secured', 'interface inventory', None, 'low'),
    ('ZS-RMD-01', 'RMD', 'Master data (customer / policyholder, provider, vehicle) has one authoritative source', 'master data design', None, 'medium'),
    ('ZS-RMD-02', 'RMD', 'Reference data (lines of business, ICD / CPT codes, vehicle makes, regions) is controlled and versioned', 'reference data register', None, 'low'),
    ('ZS-RMD-03', 'RMD', 'Duplicate customer records are detected and merged', 'duplicate detection results', None, 'low'),
    ('ZS-BIA-01', 'BIA', 'Reports and analytics use approved data sources with named owners', 'report inventory', None, 'low'),
    ('ZS-BIA-02', 'BIA', 'Regulatory reports (Insurance Authority, SAMA, CHI) are produced from controlled data and reconciled', 'report controls', None, 'medium'),
    ('ZS-BIA-03', 'BIA', 'Personal data used in analytics is minimised, anonymised or pseudonymised', 'anonymisation evidence', a_pdpl('P-21', 'anonymisation / pseudonymisation'), 'medium'),
    ('ZS-DVR-01', 'DVR', 'Data use cases with business value (pricing, fraud, retention) are identified and owned', 'use-case register', None, 'low'),
    ('ZS-DVR-02', 'DVR', 'The value delivered by data initiatives is measured', 'value measures', None, 'low'),
    ('ZS-OD-01', 'OD', 'Whether the open data rules apply to the company is decided and documented', 'decision record', None, 'low'),
    ('ZS-OD-02', 'OD', 'Where they apply, open datasets are identified and published to plan', 'open data plan', None, 'low'),
    ('ZS-FOI-01', 'FOI', 'Whether the freedom of information rules apply to the company is decided and documented', 'decision record', None, 'low'),
    ('ZS-FOI-02', 'FOI', 'Where they apply, information requests are answered within the set time', 'request log', None, 'low'),
    ('ZS-DC-01', 'DC', 'A data classification policy (Top Secret, Secret, Restricted, Public) is approved', 'classification policy', a_policy(r'classification', 'data classification policy'), 'high'),
    ('ZS-DC-02', 'DC', 'Data assets are classified and the classification is recorded', 'classified catalog', a_classified, 'medium'),
    ('ZS-DC-03', 'DC', 'Classifications are reviewed periodically and when data changes', 'review records', None, 'low'),
    ('ZS-DC-04', 'DC', 'Sensitive personal data (health, criminal, beliefs ...) is identified and protected as such', 'sensitive data register', a_sensitive, 'high'),
    ('ZS-PDP-01', 'PDP', 'The Personal Data Protection Law requirements are met (AI PDPL Consultant)', 'PDPL compliance statement', a_pdpl_all, 'high'),
    ('ZS-PDP-02', 'PDP', 'Records of processing activities are complete and reviewed', 'records of processing', a_pdpl('P-04', 'records of processing'), 'high'),
    ('ZS-PDP-03', 'PDP', 'Data subject requests are answered within the legal time', 'request log', a_pdpl('P-08', 'data subject rights'), 'high'),
    ('ZS-PDP-04', 'PDP', 'Personal data breaches are notified to SDAIA within 72 hours', 'breach register', a_pdpl('P-09', 'breach notification'), 'high'),
    ('ZS-PDP-05', 'PDP', 'Impact assessments are done where required', 'impact assessments', a_pdpl('P-07', 'impact assessments'), 'high'),
    ('ZS-PDP-06', 'PDP', 'Consent is recorded and can be withdrawn on every channel', 'consent ledger', a_pdpl('P-05', 'legal basis and consent'), 'medium'),
    ('ZS-PDP-07', 'PDP', 'A data protection officer is appointed', 'appointment', a_pdpl('P-01', 'data protection officer'), 'high'),
    ('ZS-DSP-01', 'DSP', 'Security controls protect data according to its classification (NCA ECC)', 'security test results', a_pdpl('P-13', 'information security'), 'high'),
    ('ZS-DSP-02', 'DSP', 'Access to sensitive records is logged and exceptions are reviewed', 'access log reviews', a_access, 'high'),
    ('ZS-DSP-03', 'DSP', 'Data is encrypted at rest and in transit where its classification requires', 'encryption evidence', None, 'high'),
    ('ZS-DSP-04', 'DSP', 'Data loss prevention watches e-mail, web and endpoints', 'DLP policy and reports', None, 'medium'),
]
CONTROLS = {c[0]: c for c in C}


def _conf(confirms, cid):
    c = (confirms or {}).get(cid) or {}
    return c if c.get('status') in STATUSES else None


def _approved(c):
    return bool(c and c.get('approved_by'))


def controls(facts, profile, confirms, now):
    facts = dict(facts or {}, _now=now)
    pr = profile or {}
    dec = pr.get('applicability') or {}
    out = []
    for cid, dom, title, ev, fn, sev in C:
        st, auto = None, None
        if fn:
            try:
                st, auto = fn(facts, pr, now)
            except (TypeError, ValueError, KeyError, AttributeError) as e:
                st, auto = None, 'automated evidence could not be read (' + type(e).__name__ + ')'
        c = _conf(confirms, cid)
        appl = dec.get(dom) if dom in DECIDE else None
        if dom in DECIDE and appl == 'not_applicable':
            notes = pr.get('applicability_note') if isinstance(pr.get('applicability_note'), dict) else {}
            res, why = 'not_applicable', 'the Chief Data Officer decided this domain does not apply: ' + str(notes.get(dom) or 'no reason recorded')
        elif st is False:
            res, why = 'gap', auto
        elif c and _approved(c):
            res = {'compliant': 'met', 'partial': 'partial', 'non_compliant': 'gap', 'not_applicable': 'not_applicable'}[c['status']]
            why = ('confirmed by ' + str(c.get('by')) + ', approved by ' + str(c.get('approved_by')) + ': ' + (c.get('evidence') or c.get('note') or ''))
        elif st is True:
            res, why = 'auto_pass', auto
        elif c:
            res, why = 'pending', 'recorded by ' + str(c.get('by')) + ' as ' + c['status'].replace('_', ' ') + ' - waiting for a second person to approve'
        else:
            res, why = 'no_evidence', auto or 'no evidence yet: a person records it with ' + ev
        conflict = bool(st is False and c and c.get('status') in ('compliant', 'not_applicable'))
        out.append({'id': cid, 'domain': dom, 'domain_name': DOMAIN_NAME[dom], 'title': title, 'evidence_hint': ev, 'automated': fn is not None,
                    'auto': auto, 'auto_state': st, 'result': res, 'why': why, 'severity': sev, 'conflict': conflict,
                    'confirmation': ({k: c.get(k) for k in ('status', 'evidence', 'note', 'by', 'at', 'approved_by', 'approved_at')} if c else None)})
    return out


SCORE = {'met': 1.0, 'auto_pass': 1.0, 'partial': 0.5}


def maturity(rows):
    """indicative level per domain from this register: 0 Absence ... 5 Pioneer (5 needs every control confirmed by people)"""
    out = []
    for dom, name in DOMAINS:
        rs = [r for r in rows if r['domain'] == dom]
        app = [r for r in rs if r['result'] != 'not_applicable']
        if not app:
            out.append({'domain': dom, 'name': name, 'controls': len(rs), 'applicable': 0, 'score': None, 'level': None, 'level_name': 'Not applicable', 'met': 0, 'auto': 0, 'gaps': 0, 'no_evidence': 0})
            continue
        sc = round(100 * sum(SCORE.get(r['result'], 0) for r in app) / len(app))
        lvl = 0 if sc == 0 else 1 if sc < 20 else 2 if sc < 40 else 3 if sc < 60 else 4 if sc < 90 else 5
        if lvl == 5 and any(r['result'] == 'auto_pass' for r in app):
            lvl = 4   # Pioneer only when people have confirmed every control
        out.append({'domain': dom, 'name': name, 'controls': len(rs), 'applicable': len(app), 'score': sc, 'level': lvl, 'level_name': LEVELS[lvl],
                    'met': sum(1 for r in app if r['result'] == 'met'), 'auto': sum(1 for r in app if r['result'] == 'auto_pass'),
                    'gaps': sum(1 for r in app if r['result'] == 'gap'), 'no_evidence': sum(1 for r in app if r['result'] in ('no_evidence', 'pending')),
                    'decide': dom in DECIDE})
    return out


def findings(rows, profile, coverage):
    """the duty engineer's work items: each gap, one item per domain for controls with no evidence, the official list"""
    F = []
    for r in rows:
        if r['result'] == 'gap':
            F.append({'key': 'ndmo:' + r['id'], 'severity': r['severity'], 'kind': 'ndmo-' + r['domain'].lower(),
                      'title': 'NDMO ' + r['domain_name'] + ' - ' + r['id'] + ': ' + r['title'],
                      'evidence': [x for x in [r['why'], ('a person recorded it as compliant, but the registers show the gap' if r['conflict'] else '')] if x],
                      'recommendation': 'Close the gap and keep the evidence (' + r['evidence_hint'] + '); the register re-checks it on every patrol.', 'requirement': r['id']})
    pr = profile or {}
    for dom, name in DOMAINS:
        ne = [r for r in rows if r['domain'] == dom and r['result'] == 'no_evidence']
        if ne and not (dom in DECIDE and not (pr.get('applicability') or {}).get(dom)):
            F.append({'key': 'ndmo:evidence:' + dom, 'severity': 'low', 'kind': 'ndmo-' + dom.lower(), 'title': 'NDMO ' + name + ': ' + str(len(ne)) + ' control(s) with no evidence yet',
                      'evidence': [r['id'] + ' ' + r['title'] for r in ne][:8], 'recommendation': 'Record the evidence for each control on the NDMO page (a second person approves).', 'requirement': dom})
        if dom in DECIDE and not (pr.get('applicability') or {}).get(dom):
            F.append({'key': 'ndmo:decide:' + dom, 'severity': 'low', 'kind': 'ndmo-' + dom.lower(), 'title': 'NDMO ' + name + ': decide whether it applies to the company',
                      'evidence': ['written mainly for public entities - the Chief Data Officer records whether and how it applies, and why'],
                      'recommendation': 'NDMO page -> Profile: record the decision and the reason.', 'requirement': dom})
    if coverage and coverage.get('total') and coverage.get('unmapped'):
        F.append({'key': 'ndmo:official:unmapped', 'severity': 'low', 'kind': 'ndmo-official', 'title': 'NDMO: ' + str(coverage['unmapped']) + ' official control(s) not mapped to the register',
                  'evidence': [x['code'] + ' ' + x['title'][:80] for x in coverage.get('unmapped_list', [])][:8], 'recommendation': 'NDMO page -> Official list: map each one (suggestions are offered).', 'requirement': 'official'})
    return F


def coverage(official, mapping, rows):
    off = official or []
    mp = mapping or {}
    res = {r['id']: r['result'] for r in rows}
    un = [o for o in off if o.get('code') not in mp or mp.get(o.get('code')) not in CONTROLS]
    by = {}
    for o in off:
        cid = mp.get(o.get('code'))
        if cid in CONTROLS:
            by.setdefault(cid, []).append(o['code'])
    st = {}
    for o in off:
        cid = mp.get(o.get('code'))
        k = res.get(cid, 'unmapped') if cid in CONTROLS else 'unmapped'
        st[k] = st.get(k, 0) + 1
    return {'total': len(off), 'mapped': len(off) - len(un), 'unmapped': len(un), 'unmapped_list': [{'code': o['code'], 'domain': o.get('domain'), 'title': o.get('title', '')} for o in un][:200],
            'by_control': by, 'by_result': st}


def view(req):
    now = req.get('now') or 0
    rows = controls(req.get('facts'), req.get('profile'), req.get('confirms'), now)
    cov = coverage(req.get('official'), req.get('mapping'), rows)
    for r in rows:
        r['official'] = cov['by_control'].get(r['id'], [])
    mat = maturity(rows)
    app = [r for r in rows if r['result'] != 'not_applicable']
    overall = round(100 * sum(SCORE.get(r['result'], 0) for r in app) / len(app)) if app else None
    counts = {}
    for r in rows:
        counts[r['result']] = counts.get(r['result'], 0) + 1
    pdpl = (req.get('facts') or {}).get('pdpl') or {}
    return {'ok': True, 'domains': [{'code': d, 'name': n, 'decide': d in DECIDE} for d, n in DOMAINS], 'controls': rows, 'maturity': mat, 'score': overall,
            'counts': counts, 'levels': LEVELS, 'coverage': {k: v for k, v in cov.items() if k != 'by_control'},
            'findings': findings(rows, req.get('profile'), cov),
            'pdpl': {'available': bool(pdpl.get('available')), 'compliance_pct': pdpl.get('compliance_pct'), 'non_compliant': sorted(k for k, v in (pdpl.get('requirements') or {}).items() if v == 'non_compliant')},
            'note': 'Register controls (ZS-...) are this platform\'s plain-language register for the Chief Data Officer to verify; the official NDMO controls come from the imported list. The maturity level is indicative, from this register - not NDMO\'s own assessment.'}


CODE = re.compile(r'^[A-Za-z]{1,6}[ ._-]?\d{1,3}(?:[._-]\d{1,3}){0,3}[A-Za-z]?$')


def _dom(v):
    s = str(v or '').strip()
    if not s:
        return None
    for d, n in DOMAINS:
        if s.upper() == d or s.lower() == n.lower():
            return d
    low = s.lower()
    for d, n in DOMAINS:
        if n.lower() in low or low in n.lower():
            return d
    alias = {'metadata': 'MCM', 'catalog': 'MCM', 'quality': 'DQ', 'operations': 'DO', 'document': 'DCM', 'content': 'DCM', 'architecture': 'DAM', 'sharing': 'DSI',
             'interoperability': 'DSI', 'master': 'RMD', 'reference': 'RMD', 'intelligence': 'BIA', 'analytics': 'BIA', 'value': 'DVR', 'open': 'OD', 'freedom': 'FOI',
             'classification': 'DC', 'personal': 'PDP', 'privacy': 'PDP', 'security': 'DSP', 'governance': 'DG'}
    for k, d in alias.items():
        if k in low:
            return d
    return None


def import_rows(req):
    rows, errors, out, seen = req.get('rows') or [], [], [], set()
    if not isinstance(rows, list):
        return {'ok': True, 'rows': [], 'errors': ['rows must be a list']}
    if len(rows) > 3000:
        return {'ok': True, 'rows': [], 'errors': ['too many rows (' + str(len(rows)) + '): at most 3000']}
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict):
            errors.append('row ' + str(i) + ': not a row'); continue
        code, title = str(r.get('code') or '').strip(), re.sub(r'\s+', ' ', str(r.get('title') or '')).strip()
        dom = _dom(r.get('domain')) or _dom(code.split('.')[0].split('-')[0].rstrip('0123456789 '))
        if not CODE.match(code):
            errors.append('row ' + str(i) + ': code "' + code[:30] + '" is not a control code (e.g. DG.1.1)'); continue
        if code.upper() in seen:
            errors.append('row ' + str(i) + ': code ' + code + ' appears twice'); continue
        if not title:
            errors.append('row ' + str(i) + ' (' + code + '): title is empty'); continue
        if not dom:
            errors.append('row ' + str(i) + ' (' + code + '): domain "' + str(r.get('domain') or '')[:40] + '" is not one of the 15 NDMO domains'); continue
        seen.add(code.upper())
        out.append({'code': code, 'domain': dom, 'title': title[:500], 'spec': re.sub(r'\s+', ' ', str(r.get('spec') or '')).strip()[:2000]})
    return {'ok': True, 'rows': out, 'errors': errors[:200], 'error_count': len(errors)}


STOP = set('the a an and or of to for in on by with is are be every each its their it as at from that this data where which who when'.split())


def _words(s):
    return set(w for w in re.findall(r'[a-z]{3,}', str(s).lower()) if w not in STOP)


def suggest(req):
    """for each unmapped official control: the register control in the same domain whose words overlap most (a suggestion
    for the administrator to accept - never applied by itself)"""
    mp = req.get('mapping') or {}
    out = []
    for o in req.get('official') or []:
        if o.get('code') in mp:
            continue
        ow = _words(o.get('title', '') + ' ' + o.get('spec', ''))
        best, bs = None, 0.0
        for cid, dom, title, ev, fn, sev in C:
            if dom != o.get('domain'):
                continue
            cw = _words(title + ' ' + ev)
            s = len(ow & cw) / float(len(ow | cw) or 1)
            if s > bs:
                best, bs = cid, s
        if best is None:
            best = next((c[0] for c in C if c[1] == o.get('domain')), None)
        if best:
            out.append({'code': o['code'], 'control': best, 'score': round(bs, 2), 'title': CONTROLS[best][2]})
    return {'ok': True, 'suggestions': out}


OPS = {'ndmo.view': view, 'ndmo.import': import_rows, 'ndmo.suggest': suggest}
