# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""SAMA IT audit readiness (engine/sama-itaudit.js). The five areas SAMA expects an IT audit of a financial institution to cover and the
four stages of the audit process, each checked against evidence the platform already holds. A check with no source is NOT MEASURED
(never a pass); every state names its evidence and, when it is a gap, what to do.

op sama.itaudit  {facts: {...}, history: [{day, score, areas: {id: pct}}], now}
  checks     [{id, area, title, ref, state: met|partial|gap|not_measured, evidence, fix, weight}]
  areas      per area: checks met / partial / gap / not measured, score % over the measured checks
  readiness  overall %, measured share, trend (least squares over the last 30 daily scores, needs 5), weakest area
  findings   for every gap a draft audit finding: condition, criteria (the SAMA reference), cause, effect, recommendation, rating
"""

AREAS = [
    ('governance', 'Information security governance'),
    ('cyber_risk', 'Cyber risk management'),
    ('data', 'Data protection and privacy'),
    ('incident', 'Incident management and response'),
    ('bcdr', 'Business continuity and disaster recovery'),
    ('process', 'Audit process: plan, test, report, monitor'),
]


def _n(v):
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def checks(f):
    out = []

    def add(area, cid, title, ref, state, evidence, fix, weight=1, effect=''):
        out.append({'id': cid, 'area': area, 'title': title, 'ref': ref, 'state': state, 'evidence': evidence, 'fix': fix if state in ('gap', 'partial') else '', 'weight': weight, 'effect': effect})

    def nm(area, cid, title, ref, why, fix):
        add(area, cid, title, ref, 'not_measured', why, fix)

    # ---- governance
    p = f.get('plan')
    if p is None:
        nm('governance', 'gov-plan', 'IT audit scope and plan approved for the year', 'SAMA CSF 3.1.6 / IT Governance Framework', 'the IT Audit team module is not installed', 'Install the IT Audit team (Audit menu).')
    else:
        st = 'met' if p.get('approved') else 'partial' if p.get('draft') else 'gap'
        add('governance', 'gov-plan', 'IT audit scope and plan approved for the year', 'SAMA CSF 3.1.6 / IT Governance Framework', st,
            'approved plan for %s' % p.get('year') if p.get('approved') else ('a draft plan waits for the Head of Audit' if p.get('draft') else 'no audit plan for %s' % p.get('year')),
            'Propose the risk-based plan (IT Audit -> Plan) and have the Head of Audit approve it.', 2, 'audits are not driven by risk; regulators expect an approved annual plan')
    c = f.get('critical_assets')
    if c is None:
        nm('governance', 'gov-critical', 'Critical IT systems identified', 'SAMA CSF 3.3.2', 'the asset register is not readable', 'Check IT Asset Management.')
    else:
        add('governance', 'gov-critical', 'Critical IT systems identified', 'SAMA CSF 3.3.2', 'met' if c > 0 else 'gap', '%d business-critical asset(s) marked in the register' % c,
            'Mark business-critical systems (testing tier or a critical tag) so audits and tests start from them.', 2, 'the audit scope cannot be risk-based without them')
    r = f.get('senior_reporting')
    if r is None:
        nm('governance', 'gov-report', 'Security reported to senior management', 'SAMA CSF 3.1.3', 'no executive report or CISO brief source', 'Schedule the Executive report in the Reporting Center.')
    else:
        add('governance', 'gov-report', 'Security reported to senior management', 'SAMA CSF 3.1.3', 'met' if r.get('ok') else 'gap', r.get('evidence', ''),
            'Schedule the Executive IT & security summary (Reporting Center) to senior management, at least monthly.', 1, 'leadership is not kept informed of risk')
    o = _n(f.get('owners_pct'))
    if o is None:
        nm('governance', 'gov-owners', 'Roles and accountability: owners named', 'SAMA CSF 3.1.2', 'ownership is not measured', 'Open Ownership & Reconciliation.')
    else:
        add('governance', 'gov-owners', 'Roles and accountability: owners named', 'SAMA CSF 3.1.2', 'met' if o >= 90 else 'partial' if o >= 60 else 'gap', '%d%% of assets have both an IT and a business owner' % o,
            'Name the IT and business owner of every asset (Ownership & Reconciliation).', 1, 'nobody is accountable for some systems')
    # ---- cyber risk
    v = f.get('vapt')
    if v is None:
        nm('cyber_risk', 'risk-vuln', 'Vulnerabilities remediated within the SLA', 'SAMA CSF 3.3.8 / NCA ECC 2-10', 'no vulnerability source connected', 'Connect Greenbone, FireCompass or Tenable (VAPT Center).')
    else:
        b, crit = v.get('breached', 0), v.get('critical', 0)
        add('cyber_risk', 'risk-vuln', 'Vulnerabilities remediated within the SLA', 'SAMA CSF 3.3.8 / NCA ECC 2-10', 'met' if b == 0 and crit == 0 else 'partial' if b <= 5 and crit == 0 else 'gap',
            '%d open, %d critical, %d past the SLA' % (v.get('open', 0), crit, b), 'Fix the findings past their SLA first (VAPT Center -> Fix first).', 2, 'known weaknesses stay exploitable')
    t = f.get('testing')
    if t is None:
        nm('cyber_risk', 'risk-tests', 'Regular security testing', 'SAMA CSF 3.3.8 / NCA ECC 2-11', 'the testing cadence is not installed', 'Set the testing cadence (Penetration testing).')
    else:
        ov = t.get('overdue', 0)
        add('cyber_risk', 'risk-tests', 'Regular security testing', 'SAMA CSF 3.3.8 / NCA ECC 2-11', 'met' if ov == 0 else 'partial' if ov <= 3 else 'gap',
            '%d asset(s) never tested or overdue; last internal scan %s' % (ov, t.get('last_scan') or 'never'), 'Request the overdue tests from the VAPT Center scan wizard.', 2, 'weaknesses are found late or not at all')
    pr = f.get('policy_reviews')
    if pr is None:
        nm('cyber_risk', 'risk-policy', 'Cyber policies reviewed periodically', 'SAMA CSF 3.1.4', 'the policy register is not installed', 'Open GRC -> Policies.')
    else:
        add('cyber_risk', 'risk-policy', 'Cyber policies reviewed periodically', 'SAMA CSF 3.1.4', 'met' if pr == 0 else 'partial' if pr <= 3 else 'gap', '%d policy review(s) overdue' % pr,
            'Review the overdue policies and record the review (GRC -> Policies).', 1, 'policies drift from current threats')
    # ---- data protection
    ce = f.get('certs')
    if ce is None:
        nm('data', 'data-encryption', 'Encryption in transit (certificates valid)', 'SAMA CSF 3.3.5', 'certificates are not monitored', 'Open Certificates.')
    else:
        add('data', 'data-encryption', 'Encryption in transit (certificates valid)', 'SAMA CSF 3.3.5', 'met' if ce.get('expired', 0) == 0 else 'gap',
            '%d expired, %d expiring' % (ce.get('expired', 0), ce.get('expiring', 0)), 'Renew the expired certificates (Certificates -> renewals).', 1, 'encrypted channels fail or fall back to plain text')
    ar = f.get('access_review')
    if ar is None:
        nm('data', 'data-access', 'Access reviewed and recertified', 'SAMA CSF 3.3.5 / NCA ECC 2-2', 'access reviews are not installed', 'Open Access Reviews.')
    else:
        d = ar.get('days_since')
        add('data', 'data-access', 'Access reviewed and recertified', 'SAMA CSF 3.3.5 / NCA ECC 2-2', 'met' if d is not None and d <= 100 else 'partial' if d is not None and d <= 200 else 'gap',
            'last access review closed %s' % ('%d days ago' % d if d is not None else 'never'), 'Run the quarterly access review campaign (Access Reviews).', 2, 'leavers and excess rights keep access to data')
    pd = _n(f.get('pdpl_pct'))
    if pd is None:
        nm('data', 'data-pdpl', 'Personal data protection (PDPL) controls', 'PDPL / SAMA CSF 3.3.5', 'the PDPL self-assessment is not measured', 'Complete the PDPL self-assessment.')
    else:
        add('data', 'data-pdpl', 'Personal data protection (PDPL) controls', 'PDPL / SAMA CSF 3.3.5', 'met' if pd >= 80 else 'partial' if pd >= 50 else 'gap', 'PDPL compliance %d%%' % pd,
            'Close the PDPL gaps (PDPL -> Self-assessment).', 2, 'customer data is exposed to regulatory and identity-theft risk')
    nm('data', 'data-mfa', 'Multi-factor authentication enforced', 'SAMA CSF 3.3.5', 'no source on this platform reports MFA coverage', 'Record MFA coverage as evidence in the IT audit engagement (Entra ID / VPN reports).')
    # ---- incident
    n = f.get('notify')
    if n is None:
        nm('incident', 'inc-routing', 'Incidents detected and routed to a responder', 'SAMA CSF 3.3.15', 'Notification & Escalation is not installed', 'Install Notification & Escalation.')
    else:
        add('incident', 'inc-routing', 'Incidents detected and routed to a responder', 'SAMA CSF 3.3.15', 'met' if n.get('policies', 0) > 0 and n.get('teams', 0) > 0 and n.get('enabled') else 'gap',
            '%d routing polic(ies), %d team(s), %s' % (n.get('policies', 0), n.get('teams', 0), 'running' if n.get('enabled') else 'paused'),
            'Add teams, on-call rotas and routing policies (Notification & Escalation).', 2, 'an alert at night reaches nobody')
        ack = _n(n.get('median_ack_min'))
        if ack is None:
            nm('incident', 'inc-response', 'Prompt response (time to acknowledge)', 'SAMA CSF 3.3.15', 'needs 5 acknowledged incidents to learn', 'Keep acknowledging incidents in Notification & Escalation.')
        else:
            add('incident', 'inc-response', 'Prompt response (time to acknowledge)', 'SAMA CSF 3.3.15', 'met' if ack <= 30 else 'partial' if ack <= 120 else 'gap', 'median time to acknowledge %g min' % ack,
                'Shorten the first escalation step and check the on-call rota.', 1, 'attacks run longer before someone acts')
    bt = f.get('breach')
    if bt is None:
        nm('incident', 'inc-notify', 'Regulator notified of breaches', 'SAMA Cyber Incident reporting / PDPL Art. 20', 'the PDPL breach workflow is not installed', 'Open PDPL -> Breach.')
    else:
        late = bt.get('late', 0)
        add('incident', 'inc-notify', 'Regulator notified of breaches', 'SAMA Cyber Incident reporting / PDPL Art. 20', 'met' if late == 0 else 'gap',
            '%d breach(es) recorded, %d notified late or not at all' % (bt.get('total', 0), late), 'Complete the regulator notification track for each breach (PDPL -> Breach).', 2, 'regulatory sanctions')
    # ---- BC / DR
    dr = f.get('drills')
    if dr is None:
        nm('bcdr', 'bc-drills', 'BCP / DR plans tested regularly', 'SAMA BCM Framework', 'DR & BCM Drills are not installed', 'Open GRC -> DR & BCM Drills.')
    else:
        add('bcdr', 'bc-drills', 'BCP / DR plans tested regularly', 'SAMA BCM Framework', 'met' if dr.get('passed_12m', 0) > 0 and dr.get('failed_open', 0) == 0 else 'partial' if dr.get('done_12m', 0) > 0 else 'gap',
            '%d drill(s) in 12 months, %d passed' % (dr.get('done_12m', 0), dr.get('passed_12m', 0)), 'Run and sign off a DR drill for each critical system (DR & BCM Drills).', 2, 'recovery may fail when it is needed')
    rd = _n(f.get('dr_readiness'))
    if rd is None:
        nm('bcdr', 'bc-dr', 'DR site ready (replication within RPO)', 'SAMA BCM Framework', 'no replication stream reported', 'Connect Nutanix / Data Guard (DR Studio).')
    else:
        add('bcdr', 'bc-dr', 'DR site ready (replication within RPO)', 'SAMA BCM Framework', 'met' if rd >= 80 else 'partial' if rd >= 55 else 'gap', 'DR readiness %d / 100' % rd,
            'Bring the streams past their RPO back (DR Studio).', 2, 'data loss beyond the RPO on failover')
    bk = _n(f.get('backup_pct'))
    if bk is None:
        nm('bcdr', 'bc-backup', 'Backups cover critical systems', 'SAMA CSF 3.3.13', 'no backup platform connected', 'Connect the backup platform (Backup Status).')
    else:
        add('bcdr', 'bc-backup', 'Backups cover critical systems', 'SAMA CSF 3.3.13', 'met' if bk >= 95 else 'partial' if bk >= 80 else 'gap', 'backup coverage %d%%' % bk,
            'Add the unprotected assets to a backup job (Backup Status).', 1, 'unrecoverable data loss')
    # ---- process
    e = f.get('engagements')
    if e is not None:
        add('process', 'proc-testing', 'Controls tested in audit engagements', 'IIA 2300 / SAMA audit expectations', 'met' if e.get('fieldwork_done', 0) > 0 else 'partial' if e.get('active', 0) > 0 else 'gap',
            '%d engagement(s) this year, %d past fieldwork' % (e.get('total', 0), e.get('fieldwork_done', 0)), 'Run the planned engagements: sample, test and conclude (IT Audit).', 1, 'controls are asserted, not tested')
        add('process', 'proc-report', 'Audit reports documented and approved', 'IIA 2400 / regulator readiness', 'met' if e.get('final', 0) > 0 else 'gap', '%d final, signed report(s) this year' % e.get('final', 0),
            'Complete and approve the engagement reports (IT Audit -> Report).', 1, 'nothing to show the regulator')
    else:
        nm('process', 'proc-testing', 'Controls tested in audit engagements', 'IIA 2300', 'the IT Audit team module is not installed', 'Install the IT Audit team.')
    cm = f.get('ccm')
    if cm is None:
        nm('process', 'proc-monitor', 'Continuous control monitoring', 'SAMA CSF 3.1.6', 'continuous control monitoring is not installed', 'Open Audit -> Continuous monitoring.')
    else:
        add('process', 'proc-monitor', 'Continuous control monitoring', 'SAMA CSF 3.1.6', 'met' if cm.get('run_days') is not None and cm['run_days'] <= 7 and cm.get('exceptions', 0) == 0 else 'partial' if cm.get('run_days') is not None and cm['run_days'] <= 31 else 'gap',
            'last run %s, %d exception(s)' % (('%d days ago' % cm['run_days']) if cm.get('run_days') is not None else 'never', cm.get('exceptions', 0)), 'Run continuous monitoring weekly and resolve its exceptions.', 1, 'control failures go unseen between audits')
    return out


def _lsq(ys):
    n = len(ys)
    mx, my = (n - 1) / 2.0, sum(ys) / float(n)
    sxx = sum((x - mx) ** 2 for x in range(n))
    return (sum((x - mx) * (y - my) for x, y in zip(range(n), ys)) / sxx) if sxx else 0.0


def op_assess(req):
    cs = checks(req.get('facts') or {})
    val = {'met': 1.0, 'partial': 0.5, 'gap': 0.0}
    areas = []
    for aid, name in AREAS:
        L = [c for c in cs if c['area'] == aid]
        m = [c for c in L if c['state'] != 'not_measured']
        w = sum(c['weight'] for c in m)
        score = round(100 * sum(val[c['state']] * c['weight'] for c in m) / w) if w else None
        areas.append({'id': aid, 'name': name, 'score': score, 'met': sum(1 for c in L if c['state'] == 'met'), 'partial': sum(1 for c in L if c['state'] == 'partial'),
                      'gap': sum(1 for c in L if c['state'] == 'gap'), 'not_measured': sum(1 for c in L if c['state'] == 'not_measured'), 'checks': len(L)})
    m = [c for c in cs if c['state'] != 'not_measured']
    w = sum(c['weight'] for c in m)
    overall = round(100 * sum(val[c['state']] * c['weight'] for c in m) / w) if w else None
    hist = sorted([h for h in (req.get('history') or []) if isinstance(h, dict) and h.get('score') is not None], key=lambda h: h['day'])[-30:]
    trend = None
    if len(hist) >= 5:
        sl = _lsq([float(h['score']) for h in hist])
        trend = {'days': len(hist), 'per_day': round(sl, 2), 'text': ('improving %.1f points a day' % sl) if sl > 0.2 else ('falling %.1f points a day' % -sl) if sl < -0.2 else 'steady'}
    measured = [a for a in areas if a['score'] is not None]
    weakest = min(measured, key=lambda a: a['score']) if measured else None
    findings = []
    for c in cs:
        if c['state'] not in ('gap', 'partial'):
            continue
        findings.append({'check': c['id'], 'area': c['area'], 'title': c['title'] + (' - partly met' if c['state'] == 'partial' else ' - not met'),
                         'condition': c['evidence'], 'criteria': c['ref'] + ': ' + c['title'].lower(), 'cause': 'shown by the platform\'s own records (' + c['evidence'] + ')',
                         'effect': c['effect'] or 'the control objective is not achieved', 'recommendation': c['fix'],
                         'rating': 'high' if c['weight'] >= 2 and c['state'] == 'gap' else 'medium' if c['state'] == 'gap' else 'low'})
    return {'ok': True, 'checks': cs, 'areas': areas, 'readiness': {'score': overall, 'measured': len(m), 'checks': len(cs), 'trend': trend,
            'weakest': weakest['name'] if weakest else None, 'text': ('%d%% over %d of %d checks that have evidence' % (overall, len(m), len(cs))) if overall is not None else 'no check has evidence yet'},
            'findings': sorted(findings, key=lambda f: {'high': 0, 'medium': 1, 'low': 2}[f['rating']])}


OPS = {'sama.itaudit': op_assess}
