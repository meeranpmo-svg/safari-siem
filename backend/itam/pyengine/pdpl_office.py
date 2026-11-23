# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The Privacy Office: the PDPL organisation and its workflow (engine/pdpl-office.js decides who may do what and stores).

  pdpl.office_plan  {findings, records, tasks, cfg, extra, now}  -> {org, tasks, events, calendar, gaps, roadmap}

The organisation is read from what the registers already hold - the DPO (profile), the named owner of each PDPL function
(Governance -> accountability), each department's data steward / deputy / privacy champion (Programme -> stewards) - plus
what the office itself keeps: the privacy committee (chair and members), the data owner of each system, the deadline per
severity and when to escalate.

Every PDPL finding the platform raises becomes ONE task routed to a named person:
  a finding about a department's processing  -> that department's data steward (deputy, then champion)
  otherwise                                  -> the owner of the PDPL function the requirement belongs to (then deputy)
  nobody named                               -> the DPO; no DPO -> unassigned, and the gap is reported
Deadline = first seen + the days set for its severity. Overdue -> escalated to the DPO; overdue for longer -> to the
committee chair. A task is closed only when the finding is gone from the registers: a person saying "done" is a claim,
kept open (claimed) until the next run confirms it. A risk the committee accepted stops escalation until its end date.
Recurring duties (annual RoPA review, 6-monthly access review of sensitive data, quarterly committee, yearly programme
review, yearly training per department, yearly processor review) appear in the calendar and become tasks when due.
"""
try:
    from pdpl_ar import translate as _ar, why_ar as _why_ar, gap_ar as _gap_ar, evidence_ar as _ev_ar, STEP_AR, PHASE_AR, MAINTAIN_AR, ROADMAP_NOTE_AR, FN_AR
except ImportError:   # an update that did not ship the Arabic catalogue: everything stays English
    def _ar(f):
        return {}
    _why_ar = _gap_ar = _ev_ar = lambda x: x
    STEP_AR, PHASE_AR, MAINTAIN_AR, ROADMAP_NOTE_AR, FN_AR = {}, {}, {}, None, {}
DAY = 86400000
SEV = ('critical', 'high', 'medium', 'low')
DEFAULT_SLA = {'critical': 2, 'high': 7, 'medium': 30, 'low': 60}
FUNCTIONS = {'inventory': 'Data inventory and mapping', 'approval': 'Processing approval and contracts', 'requests': 'Data subject requests',
             'incidents': 'Security incident and breach response', 'training': 'Staff training and awareness', 'sdaia': 'SDAIA liaison and documentation'}
# which PDPL function answers for each requirement (pyengine/pdpl_rules.py REQS)
REQ_FUNCTION = {'P-01': 'sdaia', 'P-02': 'sdaia', 'P-03': 'sdaia', 'P-24': 'sdaia', 'P-04': 'inventory', 'P-12': 'inventory', 'P-16': 'inventory', 'P-21': 'inventory',
                'P-22': 'inventory', 'P-05': 'approval', 'P-06': 'approval', 'P-07': 'approval', 'P-10': 'approval', 'P-11': 'approval', 'P-14': 'approval',
                'P-15': 'approval', 'P-17': 'approval', 'P-19': 'approval', 'P-20': 'approval', 'P-08': 'requests', 'P-18': 'requests', 'P-09': 'incidents',
                'P-13': 'incidents', 'P-23': 'training'}
# a department's processing is described and fixed by the department; decisions on breaches, requests and SDAIA stay central
DEPT_FUNCTIONS = ('inventory', 'approval', 'training')


def _n(v):
    return str(v or '').strip().lower()


def ms(v):
    if v is None or v == '':
        return None
    if isinstance(v, (int, float)):
        return int(v)
    import datetime
    s = str(v).strip()
    try:
        if len(s) == 10:
            return int(datetime.datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
        return int(datetime.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000)
    except ValueError:
        return None


def iso(t):
    import datetime
    return datetime.datetime.fromtimestamp(t / 1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _req(f):
    r = f.get('requirement')
    if r:
        return r
    k = str(f.get('key') or '')
    return k.split(':')[0] if k.startswith('P-') else None


def org_of(records, cfg):
    prof = next((r for r in records if r.get('kind') == 'profile'), {}) or {}
    acc = {x.get('function'): x for x in records if x.get('kind') == 'accountability' and x.get('status') != 'archived'}
    depts = {}
    for s in records:
        if s.get('kind') != 'steward' or s.get('status') == 'archived' or not s.get('department'):
            continue
        d = depts.setdefault(_n(s['department']), {'department': s['department'], 'data_steward': None, 'deputy': None, 'champion': None})
        d[s.get('role') or 'data_steward'] = d.get(s.get('role') or 'data_steward') or s.get('user')
    for r in records:   # a department that owns processing but has nobody is still part of the organisation (and a gap)
        if r.get('kind') == 'ropa' and r.get('status') != 'archived' and r.get('owner'):
            depts.setdefault(_n(r['owner']), {'department': r['owner'], 'data_steward': None, 'deputy': None, 'champion': None})
    com = cfg.get('committee') or {}
    return {'dpo': prof.get('dpo_user'), 'dpo_deputy': cfg.get('dpo_deputy'),
            'functions': [{'function': k, 'label': l, 'user': (acc.get(k) or {}).get('user'), 'deputy': (acc.get(k) or {}).get('deputy')} for k, l in FUNCTIONS.items()],
            'departments': sorted(depts.values(), key=lambda x: _n(x['department'])),
            'committee': {'chair': com.get('chair'), 'members': com.get('members') or []},
            'owners': cfg.get('owners') or []}


def _dept_of(f, ropa, depts):
    t = f.get('target') or {}
    if t.get('id') in ropa:
        return ropa[t['id']].get('owner')
    for k in (t.get('name'), t.get('department')):
        if k and _n(k) in depts:
            return depts[_n(k)]['department']
    parts = str(f.get('key') or '').split(':')
    for p in parts:   # a finding that names the activity only in its key (sens:<ropa id>, P-07:dpia:<ropa id>)
        if p in ropa:
            return ropa[p].get('owner')
    # RoPA campaign findings: ropa:<campaign>:<department>:<what>
    if len(parts) >= 4 and parts[0] == 'ropa' and parts[2] in depts:
        return depts[parts[2]]['department']
    return None


def route(f, org, ropa):
    """(assignee, why, department, function) for one finding"""
    depts = {_n(d['department']): d for d in org['departments']}
    fn = REQ_FUNCTION.get(_req(f) or '')
    dept = _dept_of(f, ropa, depts)
    t = f.get('target') or {}
    if t.get('type') in ('database', 'system', 'file_share', 'site') or f.get('system'):
        sys_ = _n(t.get('name') or f.get('system'))
        o = next((x for x in org['owners'] if _n(x.get('system')) == sys_), None)
        if o and o.get('user'):
            return o['user'], 'data owner of ' + str(o.get('system')), dept, fn
    if dept and (fn in DEPT_FUNCTIONS or fn is None):
        d = depts.get(_n(dept)) or {}
        for role in ('data_steward', 'deputy', 'champion'):
            if d.get(role):
                return d[role], role.replace('_', ' ') + ' of ' + dept, dept, fn
    if fn:
        a = next((x for x in org['functions'] if x['function'] == fn), {})
        if a.get('user'):
            return a['user'], 'owner of ' + FUNCTIONS[fn], dept, fn
        if a.get('deputy'):
            return a['deputy'], 'deputy owner of ' + FUNCTIONS[fn], dept, fn
    if org.get('dpo'):
        return org['dpo'], 'the DPO (nobody else is named for this)', dept, fn
    return None, 'nobody named - appoint the DPO and the function owners', dept, fn


def duties(records, org, now):
    """recurring PDPL duties: [{key, title, due, assignee, why, department, requirement}]"""
    out = []
    depts = {_n(d['department']): d for d in org['departments']}

    def steward(dept):
        d = depts.get(_n(dept)) or {}
        return d.get('data_steward') or d.get('deputy') or d.get('champion')

    def fn_owner(fn):
        a = next((x for x in org['functions'] if x['function'] == fn), {})
        return a.get('user') or a.get('deputy')
    live = lambda k: [r for r in records if r.get('kind') == k and r.get('status') != 'archived']
    for r in live('ropa'):
        last = ms(r.get('reviewed')) or ms(r.get('approved_at')) or ms(r.get('created_at'))
        if last:
            who = steward(r.get('owner')) or fn_owner('inventory') or org.get('dpo')
            out.append({'key': 'duty:ropa-review:' + r['id'], 'title': 'Annual review of "' + str(r.get('name')) + '" (' + r['id'] + ')', 'due': last + 365 * DAY, 'assignee': who,
                        'why': 'records of processing are reviewed at least yearly', 'department': r.get('owner'), 'requirement': 'P-04', 'target': {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}})
    for c in live('sensitive_control'):
        last = ms(c.get('access_review'))
        r = next((x for x in live('ropa') if x.get('id') == c.get('ropa_id')), None)
        if last and r:
            out.append({'key': 'duty:access-review:' + r['id'], 'title': 'Access review of sensitive data in "' + str(r.get('name')) + '"', 'due': last + 183 * DAY,
                        'assignee': steward(r.get('owner')) or fn_owner('approval') or org.get('dpo'), 'why': 'access to sensitive data is reviewed every 6 months', 'department': r.get('owner'),
                        'requirement': 'P-13', 'target': {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}})
    meets = sorted([ms(m.get('date')) for m in live('committee_meeting') if ms(m.get('date'))])
    out.append({'key': 'duty:committee', 'title': 'Privacy committee meeting (quarterly)', 'due': (meets[-1] + 92 * DAY) if meets else now, 'assignee': org['committee'].get('chair') or org.get('dpo'),
                'why': 'the committee meets at least quarterly', 'department': None, 'requirement': 'P-01', 'target': {'type': 'pdpl', 'id': 'committee', 'name': 'Privacy committee'}})
    revs = sorted([ms(m.get('date')) for m in live('programme_review') if ms(m.get('date'))])
    out.append({'key': 'duty:programme-review', 'title': 'Yearly PDPL programme review', 'due': (revs[-1] + 365 * DAY) if revs else now, 'assignee': org.get('dpo'),
                'why': 'the programme is reviewed at least once a year', 'department': None, 'requirement': 'P-01', 'target': {'type': 'pdpl', 'id': 'programme', 'name': 'PDPL programme'}})
    trained = {}
    for t in live('training'):
        k = _n(t.get('team'))
        if ms(t.get('date')):
            trained[k] = max(trained.get(k, 0), ms(t.get('date')))
    for d in org['departments']:
        last = trained.get(_n(d['department']))
        out.append({'key': 'duty:training:' + _n(d['department']), 'title': 'PDPL training for ' + d['department'], 'due': (last + 365 * DAY) if last else now,
                    'assignee': d.get('champion') or d.get('data_steward') or fn_owner('training') or org.get('dpo'), 'why': 'staff who handle personal data are trained yearly',
                    'department': d['department'], 'requirement': 'P-23', 'target': {'type': 'pdpl', 'id': 'training', 'name': d['department']}})
    for p in live('processor'):
        last = ms(p.get('reviewed')) or ms(p.get('assessed_at')) or ms(p.get('created_at'))
        if last:
            out.append({'key': 'duty:processor-review:' + p['id'], 'title': 'Yearly review of processor "' + str(p.get('name')) + '"', 'due': last + 365 * DAY,
                        'assignee': fn_owner('approval') or org.get('dpo'), 'why': 'processors are assessed periodically', 'department': None, 'requirement': 'P-10',
                        'target': {'type': 'pdpl', 'id': p['id'], 'name': p.get('name')}})
    return out


def plan(req):
    findings, records, tasks = req.get('findings') or [], req.get('records') or [], req.get('tasks') or []
    cfg, now = req.get('cfg') or {}, req.get('now') or 0
    sla = dict(DEFAULT_SLA, **{k: int(v) for k, v in (cfg.get('sla_days') or {}).items() if k in SEV and v})
    esc_days = int(cfg.get('escalate_days') or 7)
    org = org_of(records, cfg)
    ropa = {r['id']: r for r in records if r.get('kind') == 'ropa'}
    by_key = {t['key']: t for t in tasks}
    events, seen, out = [], set(), []

    def ev(kind, t, detail=None):
        events.append({'event': kind, 'task': t['id'] if t.get('id') else None, 'key': t['key'], 'assignee': t.get('assignee'), 'detail': detail or {}})

    # the work: findings now, plus duties that are due (a duty already raised as a finding on the same target is not doubled)
    work = []
    for f in findings:
        a, why, dept, fn = route(f, org, ropa)
        work.append({'key': 'f:' + str(f.get('key')), 'source': 'finding', 'title': f.get('title'), 'severity': f.get('severity') if f.get('severity') in SEV else 'medium',
                     'requirement': _req(f), 'function': fn, 'department': dept, 'assignee': a, 'why': why, 'recommendation': f.get('recommendation'),
                     'evidence': (f.get('evidence') or [])[:6], 'target': f.get('target') or {}, 'ar': _ar(f)})
    targets = {(_n((w['target'] or {}).get('id')), w['requirement']) for w in work}
    cal = []
    for d in duties(records, org, now):
        cal.append({'key': d['key'], 'title': d['title'], 'title_ar': _ar(d).get('title_ar'), 'due': iso(d['due']), 'assignee': d['assignee'], 'department': d['department'], 'overdue': d['due'] <= now,
                    'soon': now < d['due'] <= now + 30 * DAY})
        if d['due'] <= now and (_n(d['target'].get('id')), d['requirement']) not in targets:
            work.append({'key': d['key'], 'source': 'duty', 'title': d['title'], 'severity': 'medium', 'requirement': d['requirement'], 'function': REQ_FUNCTION.get(d['requirement']),
                         'department': d['department'], 'assignee': d['assignee'], 'why': d['why'], 'recommendation': 'Do it and record it on the PDPL page; the task closes when the register shows it.',
                         'evidence': [], 'target': d['target'], 'due_from': d['due'], 'ar': _ar(d)})
    for w in work:
        seen.add(w['key'])
        t = dict(by_key.get(w['key']) or {})
        new = not t
        if new or t.get('status') == 'closed':
            reopened = not new
            t = {'key': w['key'], 'status': 'open', 'first_seen': iso(now), 'history': (t.get('history') or []) if reopened else [],
                 'assignee': None, 'escalation': 0, 'id': t.get('id')}
            t['history'].append({'at': iso(now), 'by': 'system:privacy-office', 'what': 'reopened - the registers show it again' if reopened else 'raised'})
        for k in ('source', 'title', 'severity', 'requirement', 'function', 'department', 'recommendation', 'evidence', 'target'):
            t[k] = w[k]
        t['title_ar'] = w['ar'].get('title_ar')   # Arabic for e-mails / Teams (pyengine/pdpl_ar.py); None = English only
        t['recommendation_ar'] = w['ar'].get('recommendation_ar')
        # routing: a person's reassignment stands until that person leaves the organisation; otherwise follow the rules
        if not t.get('assigned_by') or t.get('assignee') is None:
            if t.get('assignee') != w['assignee']:
                if t.get('assignee'):
                    t['history'].append({'at': iso(now), 'by': 'system:privacy-office', 'what': 'routed to ' + str(w['assignee']) + ' (' + w['why'] + ')'})
                t['assignee'] = w['assignee']
            t['why'] = w['why']
        t['why_ar'] = _why_ar(t.get('why'))
        start = w.get('due_from') or ms(t.get('first_seen')) or now
        due = start + sla[t['severity']] * DAY
        if t.get('due_override'):
            due = ms(t['due_override']) or due
        t['due'] = iso(due)
        accepted = t.get('status') == 'risk_accepted' and (ms(t.get('risk_until')) or 0) > now
        if t.get('status') == 'risk_accepted' and not accepted:
            t['status'] = 'open'
            t['history'].append({'at': iso(now), 'by': 'system:privacy-office', 'what': 'risk acceptance ended ' + str(t.get('risk_until')) + ' - open again'})
            ev('risk_expired', t)
        level = 0
        if not accepted and now > due:
            level = 2 if now > due + esc_days * DAY else 1
        if level > (t.get('escalation') or 0):
            to = org['committee'].get('chair') if level == 2 else org.get('dpo')
            to = to or org.get('dpo')
            t['escalated_to'] = to
            t['history'].append({'at': iso(now), 'by': 'system:privacy-office', 'what': ('escalated to the committee chair ' if level == 2 else 'overdue - escalated to the DPO ') + str(to or '(not named)')})
            ev('escalated', t, {'level': level, 'to': to})
        t['escalation'] = max(level, t.get('escalation') or 0) if not accepted else 0
        t['overdue'] = not accepted and now > due
        if new:
            ev('raised', t)
        out.append(t)
    # gone from the registers: closed, verified - whatever anyone claimed
    for t in tasks:
        if t['key'] in seen or t.get('status') == 'closed':
            continue
        t = dict(t)
        t['history'] = (t.get('history') or []) + [{'at': iso(now), 'by': 'system:privacy-office', 'what': 'closed - the registers no longer show it' + (' (confirms the claim by ' + str(t.get('claimed_by')) + ')' if t.get('status') == 'claimed' else '')}]
        t['status'], t['closed_at'], t['overdue'] = 'closed', iso(now), False
        ev('closed', t, {'was': (by_key.get(t['key']) or {}).get('status')})
        out.append(t)
    gaps = []
    if not org.get('dpo'):
        gaps.append('No DPO named (Identity: PDPL profile) - every unrouted task has nobody')
    gaps += ['No owner for "' + f['label'] + '" (Governance)' for f in org['functions'] if not f.get('user')]
    gaps += [d['department'] + ' has no data steward' for d in org['departments'] if not d.get('data_steward')]
    gaps += [d['department'] + ' has no privacy champion' for d in org['departments'] if not d.get('champion')]
    if not org['committee'].get('chair'):
        gaps.append('No privacy committee chair - level-2 escalations go to the DPO')
    cal.sort(key=lambda x: x['due'])
    for f in org['functions']:
        f['label_ar'] = FN_AR.get(f['function'])
    return {'org': org, 'tasks': out, 'events': events, 'calendar': cal, 'gaps': gaps, 'gaps_ar': [_gap_ar(g) for g in gaps], 'sla_days': sla, 'escalate_days': esc_days,
            'roadmap': roadmap(records, org, findings, out, req.get('extra') or {}, now)}


# ---------------------------------------------------------------- Route map: implementation phase by phase, then maintenance
# A step is DONE when what it needs is in the registers and no finding is open for its requirements; IN PROGRESS when
# something is there but findings remain; NOT STARTED when nothing is recorded. Nothing here is typed in by hand: the map
# moves when the registers move. Effort figures are planning estimates for sizing the team, never measurements.
def _live(records, k):
    return [r for r in records if r.get('kind') == k and r.get('status') != 'archived']


def _steps(records, org, extra, now):
    P = next((r for r in records if r.get('kind') == 'profile'), {}) or {}
    ropa, dsr, br = _live(records, 'ropa'), _live(records, 'dsr'), _live(records, 'breach')
    meets = [ms(m.get('date')) for m in _live(records, 'committee_meeting') if ms(m.get('date'))]
    revs = [ms(m.get('date')) for m in _live(records, 'programme_review') if ms(m.get('date'))]
    depts = org['departments']
    named = [f for f in org['functions'] if f.get('user')]
    sens = [r for r in ropa if set(r.get('data_categories') or []) & {'health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage'}]
    li = [r for r in ropa if r.get('legal_basis') == 'legitimate_interest']
    cons = [r for r in ropa if r.get('legal_basis') in ('consent', 'explicit_consent')]
    trained = {_n(t.get('team')) for t in _live(records, 'training') if ms(t.get('date')) and now - ms(t.get('date')) <= 365 * DAY}
    camp = extra.get('campaigns') or []
    S = lambda **k: k
    return [
        # 1 Mobilise and govern
        S(phase=1, id='dpo', label='Appoint the DPO (reports to top management, may stop processing)', reqs=['P-01'], have=bool(P.get('dpo_user')), ev='DPO: ' + str(P.get('dpo_user') or 'not named'), page='pdpl-governance.html'),
        S(phase=1, id='owners', label='Name an owner for each PDPL function', reqs=[], have=len(named) > 0, full=len(named) == len(org['functions']), ev='%d of %d functions owned' % (len(named), len(org['functions'])), page='pdpl-governance.html'),
        S(phase=1, id='committee', label='Set up the privacy committee (chair, Legal, IT, HR, Operations) and meet quarterly', reqs=[], have=bool(org['committee'].get('chair') or meets),
          full=bool(org['committee'].get('chair')) and bool(meets) and now - max(meets) <= 92 * DAY, ev='chair ' + str(org['committee'].get('chair') or 'not named') + ', ' + str(len(meets)) + ' meeting(s)', page='pdpl-office.html'),
        S(phase=1, id='stewards', label='Name a data steward and a privacy champion in every department', reqs=[], have=any(d.get('data_steward') for d in depts),
          full=bool(depts) and all(d.get('data_steward') and d.get('champion') for d in depts), ev='%d of %d departments with a steward, %d with a champion' % (sum(1 for d in depts if d.get('data_steward')), len(depts), sum(1 for d in depts if d.get('champion'))), page='pdpl-programme.html'),
        S(phase=1, id='sdaia', label='Register on SDAIA\'s National Data Governance Platform; publish the privacy policy', reqs=['P-02', 'P-03'], have=bool(P.get('sdaia_registered') or P.get('privacy_policy_published')), ev='registered: ' + ('yes' if P.get('sdaia_registered') else 'no') + ', privacy policy: ' + ('yes' if P.get('privacy_policy_published') else 'no'), page='ai-pdpl.html'),
        # 2 Discover and map
        S(phase=2, id='discover', label='Discover personal data in databases, SharePoint / OneDrive and file shares (Data Catalog)', reqs=[], have=(extra.get('scans') or 0) > 0, full=(extra.get('scans_ok') or 0) > 0, ev='%d source(s) scanned, %d read' % (extra.get('scans') or 0, extra.get('scans_ok') or 0), page='pdpl-catalog.html'),
        S(phase=2, id='ropa-campaign', label='Run the RoPA campaign: every department describes its processing', reqs=[], have=bool(camp), full=bool(camp) and any(c.get('approved') == c.get('departments') and c.get('departments') for c in camp),
          ev=('; '.join('%s: %d of %d departments approved' % (c.get('name'), c.get('approved') or 0, c.get('departments') or 0) for c in camp[:2]) or 'no campaign yet'), page='pdpl-ropa-collect.html'),
        S(phase=2, id='ropa', label='Complete the register (Art. 33) and keep it for processing + 5 years', reqs=['P-04', 'P-24', 'P-16'], have=bool(ropa), ev='%d processing activities' % len(ropa), page='pdpl-ropa.html'),
        # 3 Lawful basis and transparency
        S(phase=3, id='basis', label='A lawful basis for every activity; explicit consent for sensitive / credit data and automated decisions', reqs=['P-05'], have=bool(ropa), ev='%d activities, %d on consent' % (len(ropa), len(cons)), page='pdpl-ropa.html'),
        S(phase=3, id='lia', label='Legitimate interest only with a written assessment, never for sensitive data', reqs=['P-06'], have=True, ev='%d on legitimate interest' % len(li), page='pdpl-ropa.html'),
        S(phase=3, id='consent', label='Consent ledger: provable consent, withdrawal as easy as giving it, marketing opt-out', reqs=['P-19', 'P-20'], have=bool(_live(records, 'consent_purpose')) or not cons, ev='%d consent purpose(s)' % len(_live(records, 'consent_purpose')), page='ai-pdpl.html'),
        # 4 Risk controls
        S(phase=4, id='dpia', label='Impact assessment before high-risk processing (sensitive data, monitoring, automated decisions, combined sources)', reqs=['P-07'], have=bool(ropa), ev='%d signed DPIA(s)' % sum(1 for d in _live(records, 'dpia') if d.get('completed')), page='pdpl-dpia.html'),
        S(phase=4, id='sensitive', label='Controls on sensitive and credit data (tiered access, encryption, masking, logging)', reqs=['P-13', 'P-14', 'P-15'], have=bool(_live(records, 'sensitive_control')) or not sens, ev='%d sensitive activities, %d with controls recorded' % (len(sens), len(_live(records, 'sensitive_control'))), page='pdpl-sensitive.html'),
        S(phase=4, id='transfers', label='Transfers outside the Kingdom: basis and transfer risk assessment (reinsurance, TPAs, cloud)', reqs=['P-11'], have=True, ev='%d transfer(s) recorded' % len(_live(records, 'transfer')), page='pdpl-transfers.html'),
        S(phase=4, id='access-log', label='Sensitive-access log from claims / medical / fraud systems, reviewed four-eyes', reqs=[], have=bool(extra.get('access_sources')), ev='%d system(s) sending access events' % (extra.get('access_sources') or 0), page='pdpl-access.html'),
        # 5 Rights and breach readiness
        S(phase=5, id='dsar', label='Data subject requests answered within 30 days (identity checked, every system searched)', reqs=['P-08', 'P-18'], have=bool(dsr) or bool(next((f for f in org['functions'] if f['function'] == 'requests' and f.get('user')), None)), ev='%d request(s) recorded; requests owner %s' % (len(dsr), next((f.get('user') for f in org['functions'] if f['function'] == 'requests'), None) or 'not named'), page='pdpl-dsar.html'),
        S(phase=5, id='breach', label='Breach response: 72-hour SDAIA clock, IA / SAMA / NCA / CHI track, people told when harm is likely', reqs=['P-09'], have=bool(next((f for f in org['functions'] if f['function'] == 'incidents' and f.get('user')), None)), ev='%d breach(es) recorded; incidents owner %s' % (len(br), next((f.get('user') for f in org['functions'] if f['function'] == 'incidents'), None) or 'not named'), page='pdpl-breach.html'),
        # 6 Vendors and retention
        S(phase=6, id='processors', label='Processors under PDPL terms, assessed and reviewed yearly; sub-processors approved', reqs=['P-10'], have=bool(_live(records, 'processor')), ev='%d processor(s)' % len(_live(records, 'processor')), page='pdpl-processors.html'),
        S(phase=6, id='retention', label='Retention schedule for every activity; destruction carried out and recorded (legal holds respected)', reqs=['P-12'], have=bool(_live(records, 'retention')), ev='%d retention rule(s), %d destruction run(s)' % (len(_live(records, 'retention')), len(_live(records, 'destruction'))), page='ai-pdpl.html'),
        # 7 People
        S(phase=7, id='training', label='Yearly PDPL training for every department that handles personal data', reqs=['P-23'], have=bool(trained), full=bool(depts) and all(_n(d['department']) in trained for d in depts), ev='%d of %d departments trained this year' % (sum(1 for d in depts if _n(d['department']) in trained), len(depts)), page='pdpl-programme.html'),
        S(phase=7, id='pbd', label='Privacy by design: every new system or change reviewed before go-live', reqs=[], have=bool(_live(records, 'pbd_review')), ev='%d review(s)' % len(_live(records, 'pbd_review')), page='pdpl-governance.html'),
        # 8 Assure and maintain
        S(phase=8, id='assess', label='Self-assessment and the DPO / management statement each year', reqs=[], have=bool(extra.get('statement_signed')), ev='statement ' + ('signed ' + str(extra.get('statement_signed')) if extra.get('statement_signed') else 'not signed'), page='pdpl-assessment.html'),
        S(phase=8, id='review', label='Yearly programme review; every finding an action with an owner and a due date', reqs=[], have=bool(revs), full=bool(revs) and now - max(revs) <= 365 * DAY, ev=('last review ' + iso(max(revs))[:10]) if revs else 'never reviewed', page='pdpl-governance.html'),
    ]


PHASES = [
    (1, 'Mobilise and govern', 'Who is accountable', ['DPO', 'Privacy committee (Legal, IT, HR, Operations)', 'Function owners', 'Data steward + privacy champion per department'], 'Weeks 0-4 (estimate)'),
    (2, 'Discover and map', 'What personal data we hold, where and why', ['Data stewards', 'DBA / system owners for read-only scan accounts', 'DPO review'], 'Weeks 2-10 (estimate)'),
    (3, 'Lawful basis and transparency', 'On what basis, and what people are told', ['Legal', 'DPO', 'Marketing / Customer Service for consent'], 'Weeks 6-12 (estimate)'),
    (4, 'Risk controls', 'Sensitive data, high-risk processing and data leaving the Kingdom', ['DPO', 'CISO / IT Security', 'Medical, Claims, Reinsurance stewards'], 'Weeks 8-16 (estimate)'),
    (5, 'Rights and breach readiness', 'Answer people in 30 days; notify in 72 hours', ['Customer Service (requests)', 'SOC / incident owner', 'Legal / Compliance for regulators'], 'Weeks 10-16 (estimate)'),
    (6, 'Vendors and retention', 'Processors, sub-processors, how long data is kept', ['Procurement', 'Legal', 'System owners for destruction'], 'Weeks 12-20 (estimate)'),
    (7, 'People and culture', 'Training and privacy by design', ['HR / training', 'Privacy champions', 'Project managers'], 'Weeks 12-24 (estimate)'),
    (8, 'Assure and maintain', 'Run it every year without a project', ['DPO', 'Internal Audit', 'Committee'], 'Ongoing'),
]
MAINTAIN = [('Daily', 'New tasks routed; requests and breach clocks watched; sensitive-access exceptions reviewed', 'Privacy Office engine, DPO'),
            ('Monthly', 'Overdue tasks and escalations at the DPO; Data Catalog rescans; new processors', 'DPO, function owners'),
            ('Quarterly', 'Privacy committee: escalations, risk acceptances, decisions', 'Committee chair'),
            ('6-monthly', 'Access review of sensitive data per activity', 'Data stewards / system owners'),
            ('Yearly', 'RoPA campaign and review, DPIA refresh, processor reviews, training, programme review, statement', 'DPO, stewards, Internal Audit')]


def roadmap(records, org, findings, tasks, extra, now):
    open_by_req = {}
    for f in findings:
        r = _req(f)
        if r:
            open_by_req[r] = open_by_req.get(r, 0) + 1
    steps = []
    for s in _steps(records, org, extra, now):
        opened = sum(open_by_req.get(r, 0) for r in s['reqs'])
        full = s.get('full', True)
        state = 'todo' if not s['have'] else ('done' if (opened == 0 and full) else 'active')
        steps.append({'phase': s['phase'], 'id': s['id'], 'label': s['label'], 'label_ar': STEP_AR.get(s['id']), 'evidence_ar': _ev_ar(s['ev']), 'state': state, 'evidence': s['ev'], 'open_findings': opened, 'requirements': s['reqs'], 'page': s['page']})
    phases = []
    for n, name, goal, res, when in PHASES:
        st = [s for s in steps if s['phase'] == n]
        done = sum(1 for s in st if s['state'] == 'done')
        state = 'done' if st and done == len(st) else ('active' if any(s['state'] != 'todo' for s in st) else 'todo')
        reqs = {r for s in st for r in s['requirements']}
        open_t = [t for t in tasks if t.get('status') not in ('closed',) and t.get('requirement') in reqs]
        A = PHASE_AR.get(n) or (None, None, None, None)
        phases.append({'phase': n, 'name': name, 'goal': goal, 'name_ar': A[0], 'goal_ar': A[1], 'resources_ar': A[2], 'when_ar': A[3], 'state': state, 'done': done, 'steps': len(st), 'progress': round(done * 100.0 / len(st)) if st else 0,
                       'resources': res, 'when': when, 'open_tasks': len(open_t), 'overdue_tasks': sum(1 for t in open_t if t.get('overdue'))})
    total = len(steps)
    return {'phases': phases, 'steps': steps, 'progress': round(sum(1 for s in steps if s['state'] == 'done') * 100.0 / total) if total else 0,
            'maintain': [dict({'cadence': c, 'what': w, 'who': who}, **dict(zip(('cadence_ar', 'what_ar', 'who_ar'), MAINTAIN_AR.get(c) or (None, None, None)))) for c, w, who in MAINTAIN], 'note_ar': ROADMAP_NOTE_AR,
            'note': 'Each step reads the registers: done = recorded and no open finding; in progress = recorded with findings open; not started = nothing recorded. Time frames are planning estimates for sizing the team, not measurements.'}


OPS = {'pdpl.office_plan': plan}
