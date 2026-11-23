# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The PDPL operating pages (engine/pdpl-workflows.js): Records of Processing, Sensitive Data Controls, Data Subject
Requests, DPIA, Cross-Border Transfers, Breach Response, Processor Management and the PDPL Programme (stewards, team
playbooks, maturity). Python decides, Node.js commits: this module reads only the PDPL records it is given and writes
nothing. Standard library only.

  pdpl.ropa_view       {records, now}            every activity: completeness, linked DPIA / transfers / retention /
                                                  consent / sensitive controls / steward, and the SDAIA export rows
  pdpl.sensitive_view  {records, now}            sensitive activities and the controls each needs (health, credit, ...)
  pdpl.dsar_view       {records, now}            every request: stage, due date, what blocks the answer
  pdpl.dsar_letter     {request, profile, now}   the response to the data subject, Arabic and English
  pdpl.dpia_view       {records, now}            which activities need an assessment, why, and its state
  pdpl.transfer_tia    {answers}                 transfer impact assessment score (Cross-Border Transfer Regulation Art. 8)
  pdpl.transfer_view   {records, now}            every transfer: basis, assessment, gaps
  pdpl.breach_view     {records, now}            every breach: the 72-hour clock and the playbook
  pdpl.processor_view  {records, now}            every processor: agreement, due diligence, review, sub-processors
  pdpl.maturity_score  {answers}                 the four-area maturity score
  pdpl.programme_view  {records, confirms, now}  departments, stewards, playbooks, maturity, measured indicators
  pdpl.policy_view     {records, policies, drafts, now}  the PDPL policy set: approved / draft / missing, what each covers
  pdpl.policy_draft    {id, policies, drafts}    the outline a new GRC draft starts from (refused when one exists)

Article references are as read from the law and its regulations, for the DPO to verify.
"""
from datetime import datetime, timezone

from pdpl_rules import insurer_triggers
from org_brand import fill as _org_fill

DAY = 86400000
# PDPL Art. 1 sensitive data. Credit data is NOT sensitive: it is its own class (Art. 24, IR Arts. 11 / 27) - explicit consent,
# the person told of every disclosure request - but no impact assessment and no 'sensitive' label because of it.
SENSITIVE = ('health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage')
SEVN = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def ms(v):
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    if len(s) == 10:
        s += 'T00:00:00'
    s = s.replace('Z', '+00:00')
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def day(t):
    return datetime.fromtimestamp(t / 1000, tz=timezone.utc).strftime('%Y-%m-%d') if t else None


def _by(records, kind):
    return [r for r in records or [] if r.get('kind') == kind and r.get('status') != 'archived']


def _norm(v):
    return str(v or '').strip().lower()


# ---------------------------------------------------------------- Records of Processing
ROPA_FIELDS = [('name', 'Activity'), ('purpose', 'Purpose'), ('legal_basis', 'Legal basis'), ('data_categories', 'Data categories'), ('subjects', 'Data subjects'),
               ('systems', 'Systems'), ('retention_months', 'Retention (months)'), ('owner', 'Owner (department)'), ('reviewed', 'Last reviewed')]


def _dpia_need(r):
    why = []
    sens = [c for c in r.get('data_categories') or [] if c in SENSITIVE]
    if sens:
        why.append('sensitive data (' + ', '.join(sens) + ')')
    if (r.get('sources') or 1) >= 2:
        why.append('data from %s sources combined' % r.get('sources'))
    if r.get('large_scale_monitoring'):
        why.append('continuous / large-scale monitoring')
    if r.get('automated_decision'):
        why.append('solely automated decisions')
    return why + insurer_triggers(r)


def ropa_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    acts = _by(recs, 'ropa')
    dpias, transfers, rules, purposes, controls, stewards = _by(recs, 'dpia'), _by(recs, 'transfer'), _by(recs, 'retention'), _by(recs, 'consent_purpose'), _by(recs, 'sensitive_control'), _by(recs, 'steward')
    out, export = [], []
    for r in acts:
        miss = [label for k, label in ROPA_FIELDS if r.get(k) in (None, '', [])]
        sys_ = {_norm(x) for x in r.get('systems') or []}
        d = sorted([x for x in dpias if x.get('ropa_id') == r['id']], key=lambda x: str(x.get('completed') or ''), reverse=True)
        need = _dpia_need(r)
        stw = [s for s in stewards if _norm(s.get('department')) == _norm(r.get('owner'))]
        sens = [c for c in r.get('data_categories') or [] if c in SENSITIVE]
        row = {'id': r['id'], 'name': r.get('name'), 'owner': r.get('owner'), 'legal_basis': r.get('legal_basis'), 'data_categories': r.get('data_categories') or [], 'systems': r.get('systems') or [],
               'completeness': round((len(ROPA_FIELDS) - len(miss)) * 100.0 / len(ROPA_FIELDS)), 'missing': miss,
               'reviewed': r.get('reviewed'), 'review_due': not ms(r.get('reviewed')) or now - ms(r.get('reviewed')) > 365 * DAY,
               'dpia': 'not needed' if not need else ('signed ' + str(d[0].get('completed')) if d and d[0].get('completed') else ('draft' if d else 'missing')), 'dpia_needed_for': need,
               'transfers': [t['id'] for t in transfers if t.get('ropa_id') == r['id']] + (['marked as transferred outside'] if r.get('transfer_outside') and not any(t.get('ropa_id') == r['id'] for t in transfers) else []),
               'retention_rule': [q['id'] for q in rules if q.get('ropa_id') == r['id'] or (sys_ & {_norm(x) for x in q.get('systems') or []})],
               'consent_purposes': [p['id'] for p in purposes if p.get('ropa_id') == r['id']],
               'sensitive': sens, 'sensitive_controls': bool([c for c in controls if c.get('ropa_id') == r['id']]) if sens else None,
               'steward': stw[0].get('user') if stw else None, 'from_discovery': r.get('from_discovery'), 'volume': r.get('volume'),
               'recipients': (r.get('recipients') or []) + [str(pr.get('name')) for pr in _by(recs, 'processor') if pr['id'] in (r.get('processor_ids') or [])]}
        out.append(row)
        export.append([r.get('id'), r.get('name'), r.get('purpose'), r.get('legal_basis'), ', '.join(r.get('data_categories') or []), r.get('subjects'), ', '.join(r.get('systems') or []),
                       ', '.join(t.get('country', '') + ' (' + str(t.get('basis') or 'no basis') + ')' for t in transfers if t.get('ropa_id') == r['id']), r.get('retention_months'), r.get('owner'), r.get('reviewed'),
                       r.get('volume'), ', '.join((r.get('recipients') or []) + [str(pr.get('name')) for pr in _by(recs, 'processor') if pr['id'] in (r.get('processor_ids') or [])])])
    out.sort(key=lambda x: x['completeness'])
    return {'activities': out, 'complete': sum(1 for x in out if not x['missing']), 'total': len(out),
            'export_columns': ['Id', 'Activity', 'Purpose', 'Legal basis', 'Data categories', 'Data subjects', 'Systems', 'Transfers outside the Kingdom (basis)', 'Retention (months)', 'Owner', 'Last reviewed', 'Approx. data subjects', 'Recipients and processors'],
            'export_rows': export, 'note': 'The register of processing activities (Implementing Regulation Art. 33): kept for the processing period plus 5 years and given to SDAIA on request.'}


# ---------------------------------------------------------------- Sensitive Data Controls
CONTROLS = [
    ('lawful_basis', 'Explicit consent or another documented lawful basis for the sensitive data', None),
    ('access_tiers', 'Access limited to named roles (tiered access, need to know)', None),
    ('encryption_at_rest', 'Encrypted at rest', None),
    ('masking_nonprod', 'Masked / pseudonymised outside production (test, analytics)', None),
    ('access_logged', 'Every access logged and monitored by the SOC', None),
    ('access_review', 'Access reviewed in the last 6 months', None),
    ('dpia', 'Impact assessment completed and signed', None),
    ('health_chi', 'Health data handled under the Council of Health Insurance / MoH controls, processing stages documented', 'health'),
    ('credit_notice', 'Credit data: consent, and the person told of every disclosure request (Credit Information Law)', 'credit'),
    ('biometric_purpose', 'Biometric data used only for the stated identification purpose', 'biometric'),
]


def sensitive_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    controls = {c.get('ropa_id'): c for c in _by(recs, 'sensitive_control')}
    dpias = {d.get('ropa_id') for d in _by(recs, 'dpia') if d.get('completed')}
    out, F = [], []
    for r in _by(recs, 'ropa'):
        cats = r.get('data_categories') or []
        sens = [x for x in cats if x in SENSITIVE]
        special = sens + (['credit'] if 'credit' in cats else [])   # credit is not sensitive but has its own controls
        if not special:
            continue
        c = controls.get(r['id']) or {}
        rows = []
        for key, label, only in CONTROLS:
            if only and only not in special:
                continue
            if key == 'dpia' and not sens:
                continue   # credit data alone does not require an impact assessment
            if key == 'dpia':
                ok = r['id'] in dpias
            elif key == 'access_review':
                t = ms(c.get('access_review'))
                ok = bool(t and now - t <= 183 * DAY)
            elif key == 'access_tiers':
                ok = bool(c.get('access_tiers'))
            else:
                ok = bool(c.get(key))
            rows.append({'control': key, 'label': label, 'ok': ok})
        gaps = [x['label'] for x in rows if not x['ok']]
        out.append({'id': r['id'], 'name': r.get('name'), 'owner': r.get('owner'), 'sensitive': sens, 'credit': 'credit' in cats, 'controls': rows, 'gaps': len(gaps), 'recorded': bool(c),
                    'access_tiers': c.get('access_tiers') or [], 'evidence': c.get('evidence') or ''})
        if gaps:
            F.append({'key': 'sens:' + r['id'], 'severity': 'high' if ('health' in special or 'credit' in special or not c) else 'medium',
                      'title': '"' + str(r.get('name')) + '" (' + ', '.join(special) + '): ' + str(len(gaps)) + ' control(s) missing', 'evidence': gaps[:6],
                      'recommendation': 'Put the missing controls in place and record them (Sensitive Data Controls).', 'requirement': 'P-14' if 'health' in special else 'P-15' if 'credit' in special else 'P-13'})
    out.sort(key=lambda x: -x['gaps'])
    return {'activities': out, 'findings': F, 'note': 'Sensitive data (PDPL Art. 1): health, genetic, biometric, criminal and security records, religious, intellectual or political beliefs, racial or ethnic origin, unknown parentage. Credit data is not sensitive data but has its own rules (Art. 24, Implementing Regulation Art. 27: explicit consent, the person told of every disclosure request) - it is listed here for those controls; it does not by itself require an impact assessment.'}


# ---------------------------------------------------------------- Data Subject Requests
REFUSAL_GROUNDS = {'repetitive': 'the request repeats one already answered', 'unfounded': 'the request is manifestly unfounded', 'disproportionate': 'answering needs disproportionate effort',
                   'legal': 'another law requires the data to be kept or not disclosed', 'identity': 'the requester\'s identity could not be verified', 'third_party': 'answering would disclose another person\'s personal data'}
TYPES = {'access': 'access to the personal data we hold about you', 'copy': 'a copy of your personal data', 'correction': 'correction of your personal data', 'destruction': 'destruction of your personal data',
         'withdraw_consent': 'withdrawal of your consent', 'objection': 'objection to the processing of your personal data', 'other': 'your request about your personal data'}
TYPES_AR = {'access': 'الاطلاع على بياناتك الشخصية لدينا', 'copy': 'الحصول على نسخة من بياناتك الشخصية', 'correction': 'تصحيح بياناتك الشخصية', 'destruction': 'إتلاف بياناتك الشخصية',
            'withdraw_consent': 'الرجوع عن موافقتك', 'objection': 'الاعتراض على معالجة بياناتك الشخصية', 'other': 'طلبك المتعلق ببياناتك الشخصية'}


def _dsar_one(r, now):
    rc = ms(r.get('received'))
    limit = 60 if r.get('extended') and r.get('extension_notified') else 30
    due = rc + limit * DAY if rc else None
    closed = r.get('stage') in ('responded', 'refused', 'withdrawn') or bool(r.get('responded'))
    tasks = r.get('tasks') or []
    blockers = []
    if not r.get('identity_verified'):
        blockers.append('identity not verified')
    open_t = [t['system'] for t in tasks if t.get('status') == 'open']
    if open_t:
        blockers.append('open in: ' + ', '.join(open_t))
    if not tasks and r.get('type') in ('access', 'copy', 'correction', 'destruction'):
        blockers.append('no system listed (where does this person\'s data live? search for them with "Find this person")')
    end = ms(r.get('responded')) or now
    return {'id': r['id'], 'ref': r.get('ref'), 'type': r.get('type'), 'channel': r.get('channel'), 'received': r.get('received'), 'stage': r.get('stage') or ('responded' if r.get('responded') else 'received'),
            'assigned_to': r.get('assigned_to'), 'due': day(due), 'days_left': None if closed or not due else int((due - now) // DAY), 'overdue': bool(due and end > due),
            'extended': bool(r.get('extended')), 'identity_verified': bool(r.get('identity_verified')), 'identity_method': r.get('identity_method'), 'tasks': tasks,
            'blockers': [] if closed else blockers, 'can_respond': not closed and not blockers, 'outcome': r.get('outcome'), 'refusal_ground': r.get('refusal_ground'), 'responded': r.get('responded'),
            'correlation': r.get('correlation') or [],
            'intake': {k: (r.get('intake') or {}).get(k) for k in ('source_name', 'auto_verified', 'searched', 'found_in', 'search_error', 'repetitive_of')} if r.get('intake') else None,
            'flags': [f for f in ((r.get('intake') or {}).get('flags') or []) if not closed]}


def dsar_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    rows = sorted([_dsar_one(r, now) for r in _by(recs, 'dsr')], key=lambda x: (x['stage'] in ('responded', 'refused', 'withdrawn'), x['days_left'] if x['days_left'] is not None else 9999))
    open_ = [x for x in rows if x['stage'] not in ('responded', 'refused', 'withdrawn')]
    return {'requests': rows, 'open': len(open_), 'overdue': sum(1 for x in open_ if x['overdue']), 'due_7d': sum(1 for x in open_ if x['days_left'] is not None and 0 <= x['days_left'] <= 7),
            'refusal_grounds': REFUSAL_GROUNDS, 'types': TYPES,
            'note': 'Answer within 30 days of receipt; once, with notice and reasons, the period may be extended by 30 days (PDPL Art. 4; Implementing Regulation). Only a reference is kept here - the person\'s details stay in the customer systems.'}


def dsar_letter(req):
    r, p = req.get('request') or {}, req.get('profile') or {}
    t, out = r.get('type') or 'other', r.get('outcome')
    contact = p.get('dpo_contact') or p.get('dpo_user') or 'the Data Protection Officer'
    ref = r.get('ref') or r.get('id')
    if r.get('stage') == 'refused' or out == 'refused':
        g = REFUSAL_GROUNDS.get(r.get('refusal_ground'), 'the request could not be met')
        en_body = 'We are unable to meet your request for %s because %s.' % (TYPES.get(t), g)
        ar_body = 'نعتذر عن تلبية طلبك بشأن %s للسبب التالي: %s.' % (TYPES_AR.get(t), g)
    elif r.get('extended') and not r.get('responded'):
        en_body = 'We need more time to complete your request for %s. We will answer within a further 30 days. Reason: %s.' % (TYPES.get(t), r.get('extension_reason') or '-')
        ar_body = 'نحتاج إلى مزيد من الوقت لاستكمال طلبك بشأن %s، وسنرد خلال ثلاثين يوماً إضافية. السبب: %s.' % (TYPES_AR.get(t), r.get('extension_reason') or '-')
    else:
        done = {'access': 'The personal data we hold about you is enclosed.', 'copy': 'A copy of your personal data is enclosed in a commonly used electronic format.',
                'correction': 'Your personal data has been corrected and the parties we disclosed it to have been told.', 'destruction': 'Your personal data has been destroyed, except where a law requires us to keep it.',
                'withdraw_consent': 'Your consent has been withdrawn and the processing based on it has stopped.', 'objection': 'We have reviewed the processing you objected to.', 'other': 'We have completed your request.'}
        done_ar = {'access': 'مرفق البيانات الشخصية التي نحتفظ بها عنك.', 'copy': 'مرفق نسخة من بياناتك الشخصية بصيغة إلكترونية شائعة.', 'correction': 'تم تصحيح بياناتك الشخصية وإبلاغ الجهات التي أفصحنا لها عنها.',
                   'destruction': 'تم إتلاف بياناتك الشخصية، باستثناء ما يلزمنا النظام بالاحتفاظ به.', 'withdraw_consent': 'تم الرجوع عن موافقتك وإيقاف المعالجة القائمة عليها.', 'objection': 'راجعنا المعالجة التي اعترضت عليها.', 'other': 'تم استكمال طلبك.'}
        en_body = done.get(t) + (' Part of the request could not be met: ' + str(r.get('response_note')) if out == 'partially' else '')
        ar_body = done_ar.get(t) + (' تعذر تلبية جزء من الطلب: ' + str(r.get('response_note')) if out == 'partially' else '')
    en = (_org_fill('Reference: %s\n\nDear customer,\n\nThank you for your request for %s, received on %s.\n\n%s\n\nIf you are not satisfied with this answer you may contact our Data Protection Officer (%s), '
          'or complain to the Saudi Data & AI Authority (SDAIA).\n\n{{org.name}}')) % (ref, TYPES.get(t), r.get('received'), en_body, contact)
    ar = (_org_fill('المرجع: %s\n\nعزيزنا العميل،\n\nنشكرك على طلبك بشأن %s المستلم بتاريخ %s.\n\n%s\n\nإذا لم تكن راضياً عن هذا الرد يمكنك التواصل مع مسؤول حماية البيانات الشخصية (%s) '
          'أو تقديم شكوى إلى الهيئة السعودية للبيانات والذكاء الاصطناعي (سدايا).\n\n{{org.name_ar}}')) % (ref, TYPES_AR.get(t), r.get('received'), ar_body, contact)
    return {'en': en, 'ar': ar, 'note': 'A draft: review it, attach what the request needs from the customer systems, and send it through the channel the request came in.'}


# ---------------------------------------------------------------- DPIA
def dpia_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    dpias = _by(recs, 'dpia')
    out = []
    for r in _by(recs, 'ropa'):
        need = _dpia_need(r)
        d = sorted([x for x in dpias if x.get('ropa_id') == r['id']], key=lambda x: str(x.get('updated_at') or ''), reverse=True)
        signed = [x for x in d if x.get('completed')]
        st = 'not needed' if not need and not d else 'signed' if signed else 'draft' if d else 'missing'
        outdated = bool(signed and ms(r.get('updated_at')) and ms(signed[0].get('updated_at')) and ms(r.get('updated_at')) > ms(signed[0].get('updated_at')) + DAY)
        if signed and ms(signed[0].get('completed')) and now - ms(signed[0].get('completed')) > 730 * DAY:
            outdated = True
        out.append({'id': r['id'], 'name': r.get('name'), 'needed_for': need, 'state': st, 'outdated': outdated, 'latest': (signed or d or [{}])[0].get('id'),
                    'residual': ((signed or d or [{}])[0].get('score') or {}).get('level'), 'outcome': (signed or d or [{}])[0].get('outcome')})
    order = {'missing': 0, 'draft': 1, 'signed': 2, 'not needed': 3}
    out.sort(key=lambda x: (order.get(x['state'], 9), not x['outdated']))
    return {'activities': out, 'missing': sum(1 for x in out if x['state'] == 'missing'), 'outdated': sum(1 for x in out if x['outdated']),
            'note': 'An impact assessment is required before processing sensitive data, combining sources, continuous monitoring, solely automated decisions or new technology with serious privacy risk (PDPL Art. 22; Implementing Regulation Art. 25). Re-assess when the activity changes, at least every 2 years.'}


# ---------------------------------------------------------------- Cross-Border Transfers
PURPOSES = ['agreement_kingdom', 'kingdom_interest', 'contract_with_subject', 'central_operations', 'service_to_subject', 'research']
TIA_Q = [
    {'id': 'purpose', 'q': 'Permitted purpose of the transfer (PDPL Art. 29)', 'opts': [[p, 0, 0] for p in PURPOSES] + [['none of these', 3, 3]]},
    {'id': 'recipient_law', 'q': 'Does the recipient country have personal data protection law and a supervisory authority?', 'opts': [['adequacy decision by SDAIA', 0, 0], ['yes', 1, 0], ['no / unknown', 3, 1]]},
    {'id': 'gov_access', 'q': 'Can public authorities there access the data without safeguards comparable to the Kingdom?', 'opts': [['no', 0, 0], ['unclear', 1, 1], ['yes', 2, 2]]},
    {'id': 'sensitive', 'q': 'Does the transfer include sensitive or credit data?', 'opts': [['no', 0, 0], ['yes', 1, 3]]},
    {'id': 'scale', 'q': 'Scale and frequency', 'opts': [['occasional, few people', 0, 0], ['regular', 1, 1], ['continuous or large scale', 2, 2]]},
    {'id': 'minimised', 'q': 'Only the minimum data needed is transferred', 'opts': [['yes', 0, 0], ['partly', 1, 1], ['no', 2, 1]]},
    {'id': 'encryption', 'q': 'Encrypted in transit and at rest, keys held in the Kingdom', 'opts': [['yes, keys in the Kingdom', 0, 0], ['encrypted, keys with the recipient', 1, 0], ['no', 2, 2]]},
    {'id': 'onward', 'q': 'Onward transfers by the recipient', 'opts': [['none / contractually forbidden', 0, 0], ['allowed with our approval', 1, 0], ['not controlled', 2, 2]]},
    {'id': 'national_security', 'q': 'Could the transfer prejudice national security or the vital interests of the Kingdom? (PDPL Art. 29(2))', 'opts': [['no', 0, 0], ['unclear', 2, 2], ['yes', 3, 3]]},
    {'id': 'necessity', 'q': 'Is the transfer extremely necessary to preserve the data subject\'s life or vital interests, or to prevent, examine or treat disease? (PDPL Art. 29(3))', 'opts': [['no', 0, 0], ['yes', 0, 0]]},
]
SAFEGUARDS = ('bcr', 'scc', 'certification', 'code_of_conduct')


def transfer_conditions(a, basis):
    """PDPL Art. 29: a permitted purpose (29(1)) and three conditions (29(2)): no prejudice to national security or the Kingdom's
    vital interests; an adequate level of protection outside the Kingdom, at least equal to the PDPL, based on SDAIA's assessment;
    only the minimum personal data needed. Where the Transfer Regulation lets appropriate safeguards stand in (its Art. 4 cases),
    the adequacy and minimum-data conditions are replaced by them; where the transfer is extremely necessary to preserve the
    data subject's life or vital interests or to prevent, examine or treat disease (29(3)), they do not apply. The national
    security condition always applies."""
    C = []
    purpose = a.get('purpose')
    C.append({'id': 'purpose', 'ref': 'Art. 29(1)', 'label': 'A permitted purpose', 'state': 'not_met' if purpose in (None, '', 'none of these') else 'met',
              'why': 'no purpose listed in Art. 29(1) or the regulations' if purpose in (None, '', 'none of these') else purpose.replace('_', ' ')})
    ns = a.get('national_security')
    C.append({'id': 'security', 'ref': 'Art. 29(2)', 'label': 'No prejudice to national security or the Kingdom\'s vital interests',
              'state': 'met' if ns == 'no' else 'not_met' if ns == 'yes' else 'unclear', 'why': {'no': 'assessed: no prejudice', 'yes': 'the transfer could prejudice national security or the Kingdom\'s vital interests', 'unclear': 'not yet settled - the DPO decides before any transfer'}.get(ns, 'not answered')})
    necessity = a.get('necessity') == 'yes' or basis == 'exemption_vital'
    replaced = basis in SAFEGUARDS or basis in ('exemption_contract', 'exemption_public')
    if necessity:
        why = 'does not apply: the transfer is extremely necessary for the data subject\'s life or vital interests, or to prevent, examine or treat disease (Art. 29(3))'
        C.append({'id': 'adequacy', 'ref': 'Art. 29(2)', 'label': 'Adequate protection outside the Kingdom (SDAIA assessment)', 'state': 'disapplied', 'why': why})
        C.append({'id': 'minimum', 'ref': 'Art. 29(2)', 'label': 'Only the minimum personal data needed', 'state': 'disapplied', 'why': why})
    elif replaced:
        why = ('replaced by the appropriate safeguards of the basis (%s) - Transfer Regulation Art. 4' % basis) if basis in SAFEGUARDS else 'an exemption case of the Transfer Regulation (Art. 4): record the appropriate safeguards applied in their place'
        C.append({'id': 'adequacy', 'ref': 'Art. 29(2)', 'label': 'Adequate protection outside the Kingdom (SDAIA assessment)', 'state': 'safeguards', 'why': why})
        C.append({'id': 'minimum', 'ref': 'Art. 29(2)', 'label': 'Only the minimum personal data needed', 'state': 'safeguards', 'why': why})
    else:
        rl, mn = a.get('recipient_law'), a.get('minimised')
        adeq = rl == 'adequacy decision by SDAIA' or basis == 'adequacy'
        C.append({'id': 'adequacy', 'ref': 'Art. 29(2)', 'label': 'Adequate protection outside the Kingdom (SDAIA assessment)', 'state': 'met' if adeq else 'not_met',
                  'why': 'SDAIA adequacy decision' if adeq else 'a local data protection law is not enough - the protection must be found adequate by SDAIA, or appropriate safeguards used instead' if rl == 'yes' else 'no adequate protection shown'})
        C.append({'id': 'minimum', 'ref': 'Art. 29(2)', 'label': 'Only the minimum personal data needed', 'state': 'met' if mn == 'yes' else 'not_met',
                  'why': 'only the minimum is transferred' if mn == 'yes' else 'more than the minimum is transferred - cut the data to what the purpose needs' if mn in ('partly', 'no') else 'not answered'})
    return C


def transfer_tia(req):
    a = req.get('answers') or {}
    basis = (req.get('transfer') or {}).get('basis')
    L = S = 0
    why, missing = [], []
    for q in TIA_Q:
        opt = next((o for o in q['opts'] if o[0] == a.get(q['id'])), None)
        if opt is None:
            missing.append(q['id'])
            continue
        L += opt[1]
        S += opt[2]
        if opt[1] or opt[2]:
            why.append('%s: %s (+%d likelihood, +%d severity)' % (q['id'], opt[0], opt[1], opt[2]))
    if missing:
        return {'refuse': {'status': 400, 'error': 'answer every question: ' + ', '.join(missing)}}
    score = L + S
    conds = transfer_conditions(a, basis)
    failed = [c for c in conds if c['state'] == 'not_met']
    unclear = [c for c in conds if c['state'] == 'unclear']
    level = 'high' if score >= 9 or failed else 'medium' if score >= 4 or unclear else 'low'
    need = ['%s (%s): %s' % (c['label'], c['ref'], c['why']) for c in failed]
    if unclear:
        need.append('settle whether the transfer could prejudice national security or the Kingdom\'s vital interests before it happens')
    if any(c['state'] == 'safeguards' and 'record the appropriate safeguards' in c['why'] for c in conds):
        need.append('record the appropriate safeguards applied in place of the adequacy and minimum-data conditions')
    if a.get('purpose') == 'none of these':
        need.append('the transfer has no permitted purpose under Art. 29 - it must not happen')
    if a.get('recipient_law') == 'no / unknown':
        need.append('appropriate safeguards (SDAIA standard contractual clauses, BCR, certification or code of conduct)')
    if a.get('sensitive') == 'yes':
        need.append('a risk assessment kept on file for sensitive data (continuous or large-scale sensitive transfers always need one)')
    if a.get('encryption') == 'no':
        need.append('encryption in transit and at rest')
    if a.get('onward') == 'not controlled':
        need.append('contractual control of onward transfers')
    return {'likelihood': L, 'severity': S, 'score': score, 'level': level, 'why': why, 'required': need, 'conditions': conds,
            'outcome': 'not_permitted' if failed else 'stop' if level == 'high' or unclear else 'proceed_with_measures' if need or level == 'medium' else 'proceed'}


def transfer_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    out = []
    for t in _by(recs, 'transfer'):
        tia = t.get('tia') or {}
        gaps = []
        if not t.get('basis'):
            gaps.append('no transfer basis')
        if t.get('flow_type') in ('reinsurance', 'retrocession') and t.get('data_form') == 'identified' and t.get('sensitive') and not t.get('identified_why'):
            gaps.append('identified sensitive data to a reinsurer without a recorded reason (send pseudonymised or aggregated bordereaux where the treaty allows)')
        if t.get('flow_type') and not t.get('data_form'):
            gaps.append('what is sent is not recorded (aggregated, pseudonymised or identified)')
        if t.get('basis') not in (None, '', 'adequacy') and not tia.get('signed_by'):
            gaps.append('impact assessment not signed (required for safeguards and exemptions)')
        if (t.get('sensitive') or t.get('large_scale')) and not tia.get('signed_by'):
            gaps.append('sensitive / large-scale transfer without a signed assessment')
        if tia.get('score') and tia['score'].get('outcome') in ('stop', 'not_permitted'):
            gaps.append('the assessment says the transfer must stop')
        out.append({'id': t['id'], 'name': t.get('name'), 'country': t.get('country'), 'ropa_id': t.get('ropa_id'), 'basis': t.get('basis'), 'flow_type': t.get('flow_type'), 'counterparty': t.get('counterparty'), 'data_form': t.get('data_form'), 'identified_why': t.get('identified_why'), 'sensitive': bool(t.get('sensitive')),
                    'large_scale': bool(t.get('large_scale')), 'tia': {'level': (tia.get('score') or {}).get('level'), 'outcome': (tia.get('score') or {}).get('outcome'),
                    'prepared_by': tia.get('prepared_by'), 'signed_by': tia.get('signed_by'), 'signed_at': tia.get('signed_at')}, 'gaps': gaps})
    return {'transfers': out, 'questions': [{'id': q['id'], 'question': q['q'], 'options': [o[0] for o in q['opts']]} for q in TIA_Q], 'purposes': PURPOSES,
            'conditions_note': 'PDPL Art. 29: a permitted purpose and three conditions - no prejudice to national security or the Kingdom\'s vital interests; adequate protection outside the Kingdom, at least equal to the PDPL, based on SDAIA\'s assessment; only the minimum data needed. Appropriate safeguards replace the adequacy and minimum-data conditions in the Transfer Regulation\'s Art. 4 cases; Art. 29(3) disapplies them where the transfer is extremely necessary for the data subject\'s life or vital interests, or to prevent, examine or treat disease. Article numbers are for the DPO to verify against the official text.',
            'note': 'A transfer outside the Kingdom needs a permitted purpose (Art. 29), a basis (adequacy decision, appropriate safeguards or an exemption) and, for safeguards, exemptions and continuous or large-scale sensitive data, a risk assessment (Cross-Border Transfer Regulation Art. 8).'}


# ---------------------------------------------------------------- Breach Response
PLAYBOOK = [('contain', 'Contain: stop the leak (disable the account, block the link, isolate the host)'), ('assess', 'Assess: what data, how many people, sensitive?, likely harm'),
            ('notify_sdaia', 'Notify SDAIA within 72 hours of awareness'), ('notify_subjects', 'Notify the data subjects when harm is likely'),
            ('remediate', 'Remediate: fix the cause'), ('lessons', 'Lessons learned and policy / control changes')]


# other regulators an insurer may have to tell besides SDAIA. Whether each applies, and its deadline, comes from the circulars
# the organisation follows: the deadline in hours is set by an administrator in the PDPL profile (notify_hours_<key>); the
# platform does not assume one. A regulator with no recorded decision stays "to decide" - never silently "not required".
REGULATORS = [('ia', 'Insurance Authority'), ('sama', 'Saudi Central Bank (SAMA)'), ('nca', 'National Cybersecurity Authority (NCA)'), ('chi', 'Council of Health Insurance (CHI)'), ('other', 'Other authority')]


def _iso(t):
    return datetime.fromtimestamp(t / 1000, tz=timezone.utc).isoformat().replace('+00:00', 'Z') if t else None


def _regulators(b, prof, now):
    aw, regs, out = ms(b.get('aware_at')), b.get('regulators') or {}, []
    for k, label in REGULATORS:
        d = regs.get(k)
        if k == 'other' and not d:
            continue
        hours = prof.get('notify_hours_' + k) if k != 'other' else (d or {}).get('hours')
        row = {'key': k, 'label': (d or {}).get('name') or label if k == 'other' else label, 'hours': hours, 'decided': bool(d), 'required': None, 'deadline': None, 'hours_left': None, 'late': False,
               'notified_at': None, 'ref': None, 'reason': None, 'by': None, 'at': None}
        if not d:
            row['status'] = 'to decide'
        elif d.get('required') is False:
            row.update(required=False, reason=d.get('reason'), by=d.get('by'), at=d.get('at'), status='not required')
        else:
            dl = aw + int(hours) * 3600000 if aw and hours else None
            sent = ms(d.get('notified_at'))
            row.update(required=True, by=d.get('by'), at=d.get('at'), notified_at=d.get('notified_at'), ref=d.get('ref'), deadline=_iso(dl),
                       hours_left=None if not dl or sent else round((dl - now) / 3600000.0, 1), late=bool(dl and (sent or now) > dl))
            row['status'] = ('notified late' if row['late'] else 'notified') if sent else ('overdue' if row['late'] else 'due' if dl else 'due - deadline not set')
        out.append(row)
    return out


def breach_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    prof = next((r for r in recs if r.get('kind') == 'profile'), {}) or {}
    out, F = [], []
    for b in _by(recs, 'breach'):
        aw = ms(b.get('aware_at'))
        dl = aw + 72 * 3600000 if aw else None
        pb = b.get('playbook') or {}
        steps = []
        for k, label in PLAYBOOK:
            done = pb.get(k)
            if k == 'notify_sdaia' and b.get('sdaia_notified_at'):
                done = done or {'at': b.get('sdaia_notified_at'), 'by': 'register'}
            if k == 'notify_subjects' and (b.get('subjects_notified_at') or b.get('harm_likely') is False):
                done = done or {'at': b.get('subjects_notified_at') or '', 'by': 'register', 'note': 'not required: harm not likely' if b.get('harm_likely') is False else ''}
            steps.append({'step': k, 'label': label, 'done': bool(done), 'at': (done or {}).get('at'), 'by': (done or {}).get('by'), 'note': (done or {}).get('note')})
        regs = _regulators(b, prof, now)
        reg_open = [r for r in regs if r['status'] == 'to decide' or (r['required'] and not r['notified_at'])]
        nxt = next((x for x in steps if not x['done']), None)
        sent = ms(b.get('sdaia_notified_at'))
        tgt = {'type': 'pdpl', 'id': b['id'], 'name': b.get('ref')}
        for r in regs:
            if r['required'] and not r['notified_at'] and r['late']:
                F.append({'key': 'breach:' + b['id'] + ':reg:' + r['key'], 'severity': 'high', 'title': 'Breach ' + str(b.get('ref')) + ': ' + r['label'] + ' not notified - its ' + str(r['hours']) + '-hour deadline has passed',
                          'evidence': ['aware ' + str(b.get('aware_at')), 'deadline ' + str(r['deadline'])], 'recommendation': 'Notify ' + r['label'] + ' now with what is known, record the reference, and explain the delay.', 'requirement': 'P-09', 'target': tgt})
        if aw and now - aw > 72 * 3600000 and any(r['status'] == 'to decide' for r in regs):
            F.append({'key': 'breach:' + b['id'] + ':reg:undecided', 'severity': 'medium', 'title': 'Breach ' + str(b.get('ref')) + ': no decision recorded on notifying ' + ', '.join(r['label'] for r in regs if r['status'] == 'to decide'),
                      'evidence': ['aware ' + str(b.get('aware_at'))], 'recommendation': 'For each regulator record whether its instructions require notification (and notify), or why they do not.', 'requirement': 'P-09', 'target': tgt})
        out.append({'id': b['id'], 'ref': b.get('ref'), 'description': b.get('description'), 'aware_at': b.get('aware_at'), 'deadline': day(dl) and datetime.fromtimestamp(dl / 1000, tz=timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'hours_left': None if not dl or sent else round((dl - now) / 3600000.0, 1), 'late': bool(dl and (sent or now) > dl), 'steps': steps,
                    'next': nxt['label'] if nxt else ('Decide and notify the other regulators (' + ', '.join(r['label'] for r in reg_open) + ')' if reg_open else None),
                    'closed': not nxt and not reg_open, 'regulators': regs, 'regulators_open': len(reg_open), 'subjects_count': b.get('subjects_count'), 'categories': b.get('categories') or [], 'source_case': b.get('source_case')})
    out.sort(key=lambda x: (x['closed'], x['hours_left'] if x['hours_left'] is not None else 9999))
    return {'breaches': out, 'playbook': [{'step': k, 'label': l} for k, l in PLAYBOOK], 'open': sum(1 for x in out if not x['closed']), 'findings': F,
            'regulators': [{'key': k, 'label': l, 'hours': prof.get('notify_hours_' + k)} for k, l in REGULATORS if k != 'other'],
            'regulator_note': _org_fill('Besides SDAIA, an insurer may have to notify the Insurance Authority, SAMA, the NCA or the Council of Health Insurance under their own instructions. '
                              'Record a decision for each regulator on every breach. Deadlines are the hours an administrator sets in the PDPL profile from the circulars {{org.short}} follows - the platform assumes none.')}


# ---------------------------------------------------------------- Processor Management
DD = [('iso27001', 'ISO/IEC 27001 certificate (or equivalent audit report)', 2), ('pdpl_terms', 'Agreement carries the PDPL processor terms (purpose, duration, breach notice, sub-processors, foreign law)', 3),
      ('breach_24h', 'Commits to tell us of a breach within 24 hours', 2), ('data_in_ksa', 'Processes and stores the data in the Kingdom', 2), ('deletion_at_end', 'Returns or deletes the data at the end of the contract', 1),
      ('audit_right', 'We may audit (or receive independent audit results)', 1), ('staff_confidentiality', 'Its staff are bound by confidentiality and trained', 1)]


def processor_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    out, F = [], []
    total = sum(w for _, _, w in DD)
    for p in _by(recs, 'processor'):
        a = p.get('assessment') or {}
        score = round(sum(w for k, _, w in DD if a.get(k)) * 100.0 / total) if a else None
        at = ms(p.get('assessed'))
        subs = p.get('subprocessors') or []
        row = {'id': p['id'], 'name': p.get('name'), 'role': p.get('role') or 'processor', 'service': p.get('service'), 'outside_ksa': bool(p.get('outside_ksa')), 'agreement': p.get('agreement'), 'clauses': p.get('clauses') or [],
               'score': score, 'checks': [{'key': k, 'label': l, 'ok': bool(a.get(k))} for k, l, _ in DD] if a else [], 'assessed': p.get('assessed'),
               'review_due': not at or now - at > 365 * DAY, 'subprocessors': subs, 'pending_subprocessors': sum(1 for x in subs if x.get('status') == 'pending')}
        out.append(row)
        if score is not None and score < 60:
            F.append({'key': 'proc:' + p['id'] + ':dd', 'severity': 'high', 'title': 'Processor ' + str(p.get('name')) + ': due diligence ' + str(score) + '%', 'evidence': [x['label'] for x in row['checks'] if not x['ok']][:5],
                      'recommendation': 'Close the gaps with the processor, or replace it.', 'requirement': 'P-10'})
    out.sort(key=lambda x: (x['score'] if x['score'] is not None else -1))
    return {'processors': out, 'checks': [{'key': k, 'label': l, 'weight': w} for k, l, w in DD], 'findings': F,
            'note': 'A processor works only on our written instructions, with sufficient guarantees; we assess it periodically, approve each sub-processor in advance, and a processor that breaks the agreement becomes a controller (PDPL Art. 8; Implementing Regulation Art. 17).'}


# ---------------------------------------------------------------- PDPL Programme: maturity, stewards, playbooks
MATURITY = {
    'mapping': ('Data mapping & ownership', [('map', 'Every system holding personal data is in the records of processing'), ('owners', 'Each activity has a named owner department and data steward'),
                                             ('discovery', 'Personal data is discovered automatically, not only declared'), ('lineage', 'Flows to processors and outside the Kingdom are mapped')]),
    'consent': ('Consent management', [('capture', 'Consent is captured at every touchpoint (web, app, branch, call centre)'), ('ledger', 'Consents and withdrawals are recorded centrally and provable'),
                                       ('check', 'Marketing and profiling systems check consent before processing'), ('withdrawal', 'Withdrawal is as easy as giving consent and stops processing')]),
    'people': ('Team responsibilities & training', [('stewards', 'A data steward in each department'), ('playbooks', 'Team playbooks for consent, classification, sharing and deletion'),
                                                    ('training', 'Staff who handle personal data are trained every year'), ('dpo', 'A DPO is appointed and known')]),
    'audit': ('Documentation & audit readiness', [('requests', 'Data subject requests are tracked and answered within 30 days'), ('breach', 'A breach can be notified to SDAIA within 72 hours'),
                                                  ('evidence', 'Every requirement has evidence a person confirmed'), ('retrieve', 'A person\'s data can be found, retrieved and deleted within 72 hours')]),
}
LEVELS = [(0, 'Initial'), (25, 'Developing'), (50, 'Defined'), (75, 'Managed'), (90, 'Optimised')]
ANSWER = {'no': 0, 'partly': 50, 'yes': 100}


def maturity_score(req):
    a = req.get('answers') or {}
    cats, missing = {}, []
    for cid, (name, qs) in MATURITY.items():
        vals = []
        for qid, _ in qs:
            v = a.get(cid + '.' + qid)
            if v not in ANSWER:
                missing.append(cid + '.' + qid)
                continue
            vals.append(ANSWER[v])
        if vals:
            cats[cid] = {'name': name, 'score': round(sum(vals) / len(vals))}
    if missing:
        return {'refuse': {'status': 400, 'error': 'answer every question (yes / partly / no): ' + ', '.join(missing[:6]) + (' …' if len(missing) > 6 else '')}}
    overall = round(sum(c['score'] for c in cats.values()) / len(cats))
    level = [l for t, l in LEVELS if overall >= t][-1]
    return {'categories': cats, 'overall': overall, 'level': level}


def programme_view(req):
    recs, confirms, now = req.get('records') or [], req.get('confirms') or {}, req.get('now') or 0
    acts = _by(recs, 'ropa')
    stewards, playbooks = _by(recs, 'steward'), _by(recs, 'playbook')
    depts = sorted({_norm(a.get('owner')) for a in acts if a.get('owner')} | {_norm(s.get('department')) for s in stewards if s.get('department')})
    rows = []
    for d in depts:
        st = [s for s in stewards if _norm(s.get('department')) == d]
        pb = [p for p in playbooks if _norm(p.get('team')) == d]
        rows.append({'department': d, 'activities': [a['id'] for a in acts if _norm(a.get('owner')) == d], 'stewards': [{'user': s.get('user'), 'role': s.get('role'), 'id': s['id']} for s in st],
                     'playbooks': [{'id': p['id'], 'title': p.get('title'), 'tool': p.get('tool'), 'review_due': not ms(p.get('reviewed')) or now - ms(p.get('reviewed')) > 365 * DAY} for p in pb],
                     'gap': not any(s.get('role') == 'data_steward' for s in st)})
    latest = sorted([m for m in _by(recs, 'maturity')], key=lambda m: str(m.get('created_at') or ''), reverse=True)
    dsr = _by(recs, 'dsr')
    measured = {
        'ropa_complete_pct': round(sum(1 for a in acts if all(a.get(k) not in (None, '', []) for k, _ in ROPA_FIELDS)) * 100.0 / len(acts)) if acts else None,
        'activities_with_steward_pct': round(sum(1 for a in acts if any(_norm(s.get('department')) == _norm(a.get('owner')) and s.get('role') == 'data_steward' for s in stewards)) * 100.0 / len(acts)) if acts else None,
        'consent_purposes_live': sum(1 for p in _by(recs, 'consent_purpose') if (p.get('events') or 0) > 0),
        'dsr_on_time_pct': round(sum(1 for r in dsr if not _dsar_one(r, now)['overdue']) * 100.0 / len(dsr)) if dsr else None,
        'requirements_confirmed_pct': round(sum(1 for c in confirms.values() if c.get('status') in ('compliant', 'not_applicable')) * 100.0 / 24),
    }
    return {'departments': rows, 'maturity': latest[0] if latest else None, 'history': [{'id': m['id'], 'at': m.get('created_at'), 'overall': (m.get('score') or {}).get('overall'), 'level': (m.get('score') or {}).get('level')} for m in latest[:12]],
            'questions': {cid: {'name': name, 'questions': [{'id': cid + '.' + qid, 'question': q} for qid, q in qs]} for cid, (name, qs) in MATURITY.items()},
            'measured': measured, 'roles': {'legal': 'Interprets PDPL and NDMO controls, drafts policy', 'governance': 'Sets data standards, ownership, lifecycle rules', 'it': 'Implements encryption, access, consent systems',
                                             'marketing': 'Handles opt-ins, cookie banners, data usage logs', 'product': 'Builds in privacy by design (defaults, transparency)'},
            'obligations': _obligations(recs, confirms, now), 'penalties': PENALTY,
            'training': sorted([{'id': t['id'], 'team': t.get('team'), 'topic': t.get('topic'), 'date': t.get('date'), 'attendees': t.get('attendees'), 'audience': t.get('audience'), 'onboarding': bool(t.get('onboarding'))} for t in _by(recs, 'training')], key=lambda x: str(x['date'] or ''), reverse=True)[:50],
            'note': 'PDPL is fully enforceable since 14 September 2024. Each department names a data steward - the bridge between the compliance goals and its day-to-day work.'}


# ---------------------------------------------------------------- Controller obligations and penalty exposure
# The obligations a controller carries (PDPL and its Implementing Regulation, as summarised in PwC's KSA PDPL series, part 1)
# and what the platform's registers show for each. 'confirm' = a person must confirm it; the platform cannot see it.
PENALTY = {'fine': 'warning, or a fine up to SAR 5,000,000 (doubled for a repeat violation) - PDPL Art. 36',
           'criminal': 'up to 2 years in prison and / or a fine up to SAR 3,000,000 for disclosing or publishing sensitive data to harm or for gain - PDPL Art. 35',
           'note': 'Courts may also order confiscation of what was gained and publication of the judgment. Figures as read from the law (amended by M/148) for the DPO to verify.'}


def _obligations(recs, confirms, now):
    P = next((r for r in recs or [] if r.get('kind') == 'profile'), {}) or {}
    acts, dsr, br = _by(recs, 'ropa'), _by(recs, 'dsr'), _by(recs, 'breach')
    procs, tr, tra = _by(recs, 'processor'), _by(recs, 'transfer'), _by(recs, 'training')
    sens = [a for a in acts if [c for c in a.get('data_categories') or [] if c in SENSITIVE]]
    signed = {d.get('ropa_id') for d in _by(recs, 'dpia') if d.get('completed')}
    year = [t for t in tra if ms(t.get('date')) and now - ms(t.get('date')) <= 365 * DAY]
    cp = _by(recs, 'consent_purpose')

    def st(ok, part=False):
        return 'met' if ok else 'partly' if part else 'gap'
    rows = [
        ('register', 'Registered on SDAIA\'s national register of controllers', st(P.get('sdaia_registered') and P.get('sdaia_ref'), P.get('sdaia_registered')), 'profile: SDAIA registration', 'fine'),
        ('dpo', 'A Data Protection Officer appointed (sensitive data / large-scale monitoring)', st(P.get('dpo_user') and P.get('dpo_appointed'), P.get('dpo_user')), 'profile: DPO', 'fine'),
        ('privacy_policy', 'Privacy policy published and available before collection', st(P.get('privacy_policy_published') and P.get('privacy_policy_url'), P.get('privacy_policy_url')), 'profile: privacy policy', 'fine'),
        ('ropa', 'Records of processing kept for every activity', st(acts and all(not [k for k, _ in ROPA_FIELDS if a.get(k) in (None, '', [])] for a in acts), bool(acts)), '%d activities' % len(acts), 'fine'),
        ('basis', 'A lawful basis for every activity (explicit consent for sensitive and credit data)', st(acts and all(a.get('legal_basis') for a in acts) and all(a.get('legal_basis') != 'legitimate_interest' for a in sens), any(a.get('legal_basis') for a in acts)), 'records of processing', 'fine'),
        ('dpia', 'Impact assessment signed for every activity that needs one', st(all(a['id'] in signed for a in acts if _dpia_need(a)), bool(signed)), '%d of %d' % (sum(1 for a in acts if _dpia_need(a) and a['id'] in signed), sum(1 for a in acts if _dpia_need(a))), 'fine'),
        ('rights', 'Data subject requests answered within 30 days', st(not any(_dsar_one(r, now)['overdue'] for r in dsr)), '%d requests, %d late' % (len(dsr), sum(1 for r in dsr if _dsar_one(r, now)['overdue'])), 'fine'),
        ('breach', 'Breaches notified to SDAIA within 72 hours', st(not any(ms(b.get('aware_at')) and (ms(b.get('sdaia_notified_at')) or now) - ms(b.get('aware_at')) > 72 * 3600000 and b.get('harm_likely') is not False for b in br)), '%d breaches recorded' % len(br), 'fine'),
        ('processors', 'Written agreements with every processor, assessed periodically', st(procs and all(p.get('agreement') and p.get('assessed') for p in procs), bool(procs)), '%d processors' % len(procs), 'fine'),
        ('transfers', 'A permitted purpose and basis for every transfer outside the Kingdom', st(all(t.get('basis') for t in tr)), '%d transfers' % len(tr), 'fine'),
        ('marketing', 'Prior consent and an easy opt-out for marketing and advertising', st(any(p.get('marketing') for p in cp), False) if cp else 'confirm', 'consent purposes flagged marketing', 'fine'),
        ('training', 'Staff who handle personal data trained in the last 12 months', st(bool(year), bool(tra)), '%d sessions in 12 months' % len(year), 'fine'),
        ('dpo_line', 'The DPO reports to executive management or a board committee and can stop risky processing', st(P.get('dpo_reports_to') and P.get('dpo_can_stop'), P.get('dpo_reports_to') or P.get('dpo_can_stop')), 'profile: ' + (('reports to ' + str(P.get('dpo_reports_to'))) if P.get('dpo_reports_to') else 'reporting line not recorded'), 'fine'),
        ('committee', 'A data protection committee (legal, IT, HR, operations) meets at least quarterly', st(any(ms(m.get('date')) and now - ms(m.get('date')) <= 92 * DAY for m in _by(recs, 'committee_meeting')), bool(_by(recs, 'committee_meeting'))), '%d meetings recorded' % len(_by(recs, 'committee_meeting')), 'fine'),
        ('accountability', 'A named person for each PDPL function', st(len({x.get('function') for x in _by(recs, 'accountability') if x.get('user')}) >= len(FUNCTIONS), bool(_by(recs, 'accountability'))), '%d of %d functions named' % (len({x.get('function') for x in _by(recs, 'accountability') if x.get('user')}), len(FUNCTIONS)), 'fine'),
        ('pbd', 'Privacy reviewed before new systems and products go live', st(bool(_by(recs, 'pbd_review')) and not any(r.get('state') in (None, 'submitted') and ms(r.get('go_live')) and ms(r.get('go_live')) < now for r in _by(recs, 'pbd_review'))), '%d privacy-by-design reviews' % len(_by(recs, 'pbd_review')), 'fine'),
        ('review', 'The programme is reviewed at least yearly and its actions closed', st(any(ms(r.get('date')) and now - ms(r.get('date')) <= 365 * DAY for r in _by(recs, 'programme_review')), bool(_by(recs, 'programme_review'))), '%d programme reviews' % len(_by(recs, 'programme_review')), 'fine'),
        ('sensitive', 'Sensitive data never disclosed except as the law allows', 'confirm', 'Sensitive Data Controls', 'criminal'),
        ('id_copies', 'Official identity documents copied only where a law requires it or an authority asks', 'confirm', 'a person confirms', 'fine'),
    ]
    return [{'id': i, 'obligation': o, 'state': s, 'evidence': e, 'penalty': PENALTY[p], 'criminal': p == 'criminal'} for i, o, s, e, p in rows]


# ---------------------------------------------------------------- PDPL policy set
# The policies and procedures PDPL expects a controller to have, what each must cover (drawn from the law and its
# regulations - an outline for the DPO and legal to complete, not policy text), the page that runs it day to day, and what
# the registers show. Titles match the GRC gap drafts (engine/grc.js GAP_DRAFTS) so an existing draft is recognised.
POLICIES = [
    ('PP-01', 'Personal Data Protection Policy', 'PDPL Arts. 5, 10-19; IR Arts. 11-23', 'ai-pdpl.html', 'all',
     ['Principles: lawful basis, purpose limitation, minimum necessary data, accuracy, retention, security', 'Roles: controller, DPO, data owners and stewards, processors',
      'Lawful bases and when each applies; explicit consent for sensitive and credit data', 'Data subject rights and how they are exercised', 'Accountability: records, assessments, audits, sanctions for breaches of the policy']),
    ('PP-02', 'Privacy Notice', 'PDPL Arts. 12-13; IR Art. 4', 'ai-pdpl.html', 'notice',
     [_org_fill('Identity and contact of {{org.short}} and its DPO'), 'Purposes and legal basis; which fields are mandatory and which optional', 'Who the data is disclosed to; whether it leaves the Kingdom',
      'Consequences of not providing the data', 'Data subject rights and how to exercise them; the right to complain to SDAIA', 'Published before collection, in Arabic and English']),
    ('PP-03', 'Data Classification & Handling Policy', 'PDPL Art. 19; IR Art. 23; NDMO', 'pdpl-sensitive.html', None,
     ['Classification levels and who assigns them', 'Personal and sensitive data marked as such', 'Handling, labelling, storage, sharing and disposal rules per level', 'Encryption and access rules per level']),
    ('PP-04', 'Consent Management Procedure', 'PDPL Arts. 5-6; IR Arts. 11-12', 'ai-pdpl.html#consent', 'consent',
     ['Consent freely given, specific, informed, provable, one consent per purpose', 'Explicit consent for sensitive data, credit data and solely automated decisions',
      'Consent never a condition of a service unless the service needs that processing', 'Withdrawal at any time, as easy as giving it; processing stops and recipients are told', 'Records of consent kept with time and method']),
    ('PP-05', 'Data Subject Rights Procedure', 'PDPL Art. 4; IR Arts. 3-10', 'pdpl-dsar.html', 'dsr',
     ['Channels for requests (branch, call centre, e-mail, web) and logging every request, including oral ones', 'Identity verification before answering', 'Answer within 30 days; one extension of 30 days with notice and reasons',
      'Refusal only on the allowed grounds, with notice to the requester', 'Correction notified to everyone the data was disclosed to', 'Requests from legal guardians']),
    ('PP-06', 'Data Retention & Disposal Policy', 'PDPL Art. 18; IR Art. 19', 'ai-pdpl.html#retention', 'retention',
     ['Retention period per data category and its legal reference', 'Destruction or anonymisation without undue delay when the purpose ends', 'Legal holds (claims, court cases) and their release',
      'Secure disposal methods including backups and media', 'Evidence of every destruction run']),
    ('PP-07', 'Data Breach Notification Policy', 'PDPL Art. 20; IR Art. 24', 'pdpl-breach.html', 'breach',
     ['What counts as a personal data breach; how it is reported internally', 'Assessment of harm: data, people, sensitivity, likely consequences', 'Notification to SDAIA within 72 hours of awareness, with the required contents; reasons if late',
      'Notification to data subjects without undue delay when harm is likely, in plain language', 'Record of every breach, notified or not']),
    ('PP-08', 'Data Protection Impact Assessment Procedure', 'PDPL Art. 22; IR Art. 25', 'pdpl-dpia.html', 'dpia',
     ['When an assessment is required (sensitive data, linked sources, monitoring, new technology, automated decisions)', 'Contents: purpose, basis, nature, scope, context, necessity, impact, measures',
      'Who prepares it and who signs it (DPO, four-eyes)', 'Re-assessment on change and at a fixed interval', 'Copy to the processors concerned']),
    ('PP-09', 'Cross-Border Data Transfer & Residency Policy', 'PDPL Art. 29; Cross-Border Transfer Regulation', 'pdpl-transfers.html', 'transfer',
     ['Permitted purposes for a transfer', 'Bases: adequacy, appropriate safeguards (SCC, BCR, certification, code of conduct), exemptions', 'Transfer impact assessment before safeguarded, exempted or large-scale sensitive transfers',
      'Minimum data transferred; onward transfers controlled', 'Stopping a transfer when the risk is high or safeguards fail']),
    ('PP-10', 'Processor & Third-Party Data Protection Policy', 'PDPL Art. 8; IR Art. 17', 'pdpl-processors.html', 'processor',
     ['Due diligence before a processor is engaged', 'Agreement contents: purpose, categories, duration, breach notice, sub-processors, foreign law', 'Written instructions; periodic assessment of compliance',
      'Prior approval of every sub-processor', 'Return or deletion of data at the end of the contract']),
    ('PP-11', 'Sensitive, Health & Credit Data Handling Standard', 'PDPL Arts. 23-24; IR Arts. 26-27', 'pdpl-sensitive.html', 'sensitive',
     ['Explicit consent or another documented basis for sensitive data', 'Health data: Council of Health Insurance / MoH controls, tiered access, every processing stage documented',
      'Credit data: consent and notice of every disclosure request (Credit Information Law)', 'Masking outside production; access logged and reviewed']),
    ('PP-12', 'Records of Processing Procedure', 'IR Art. 33', 'pdpl-ropa.html', 'ropa',
     ['Contents of the register per activity', 'Owner of each entry and review interval', 'Kept for the processing period plus 5 years', 'Provided to SDAIA on request']),
    ('PP-13', 'Marketing & Communications Consent Policy', 'PDPL Arts. 25-26; IR Arts. 28-29', 'ai-pdpl.html#consent', 'marketing',
     ['Prior consent for marketing and awareness messages', 'Sender clearly identified', 'Opt-out as easy as opt-in, free, effective immediately', 'No sensitive data used for direct marketing']),
    ('PP-14', 'Data Protection Officer Charter', 'IR Art. 32', 'ai-pdpl.html', 'dpo',
     ['Appointment, independence and reporting line', 'Duties: SDAIA contact, impact assessments, breach notification, requests and complaints, records of processing', 'Resources and access to processing activities']),
    ('PP-15', 'Privacy Training & Awareness Standard', 'PDPL Art. 19; IR Art. 23', 'pdpl-programme.html', 'training',
     ['Who must be trained and how often', 'Role-specific content for staff who handle personal data', 'Records of attendance']),
    ('PP-16', 'Privacy by Design Standard', 'PDPL Arts. 11, 19, 22', 'pdpl-programme.html', None,
     ['Privacy requirements in every new system and change', 'Privacy-protective defaults', 'Impact assessment at design stage where required']),
]
POLICY_ALIASES = {'PP-02': ['privacy policy'], 'PP-09': ['cross-border data transfer policy'], 'PP-10': ['outsourcing & third-party risk management policy']}


def _signal(kind, recs, now):
    P = next((r for r in recs or [] if r.get('kind') == 'profile'), {}) or {}
    n = lambda k: len(_by(recs, k))
    return {'all': None, 'notice': 'published at ' + str(P.get('privacy_policy_url')) if P.get('privacy_policy_published') else 'not marked published in the PDPL profile',
            'consent': '%d consent purposes' % n('consent_purpose'), 'dsr': '%d requests recorded' % n('dsr'), 'retention': '%d retention rules' % n('retention'),
            'breach': '%d breaches recorded' % n('breach'), 'dpia': '%d assessments' % n('dpia'), 'transfer': '%d transfers' % n('transfer'), 'processor': '%d processors' % n('processor'),
            'sensitive': '%d activities with recorded controls' % n('sensitive_control'), 'ropa': '%d processing activities' % n('ropa'),
            'marketing': '%d marketing purposes' % sum(1 for p in _by(recs, 'consent_purpose') if p.get('marketing')), 'dpo': ('DPO ' + str(P.get('dpo_user'))) if P.get('dpo_user') else 'no DPO named',
            'training': '%d training sessions' % n('training')}.get(kind) if kind else None


def policy_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    reg, drafts = req.get('policies') or [], req.get('drafts') or []
    rows = []
    for pid, title, ref, page, sig, covers in POLICIES:
        names = {title.lower()} | set(POLICY_ALIASES.get(pid, []))
        ap = next((p for p in reg if _norm(p.get('title')) in names), None)
        dr = sorted([d for d in drafts if _norm(d.get('title')) in names], key=lambda d: d.get('updated') or 0, reverse=True)
        d0 = dr[0] if dr else None
        apd = next((d for d in dr if d.get('status') == 'approved'), None)
        # a revision (newer draft / in review) of an approved policy: the approved version stays in force, the revision rides beside it
        rev = {'state': d0['status'].replace('-', '_'), 'doc': d0.get('id'), 'version': d0.get('version')} if (ap or apd) and d0 and d0 is not apd and d0.get('status') in ('draft', 'in-review') else None
        if ap:
            state, ref_id = 'approved', ap.get('doc_id')
        elif apd:
            state, ref_id, d0 = 'approved', apd.get('id'), apd
        elif d0 and d0.get('status') in ('draft', 'in-review'):
            state, ref_id = d0['status'].replace('-', '_'), d0.get('id')
        else:
            state, ref_id = 'missing', d0.get('id') if d0 else None
        due = (ap or {}).get('review') or {}
        rows.append({'id': pid, 'title': title, 'ref': ref, 'page': page, 'state': state, 'doc': ref_id, 'version': (ap or d0 or {}).get('version'),
                     'owner': (ap or d0 or {}).get('owner'), 'review_overdue': bool(due.get('overdue')), 'next_review': (ap or {}).get('next_review'),
                     'approved_by': (d0 or {}).get('approved_by') if not ap else (ap.get('approver')), 'in_practice': _signal(sig, recs, now), 'covers': covers,
                     'can_draft': state == 'missing', 'full_draft': bool(_policy_text(pid)), 'revision': rev})
    c = {k: sum(1 for r in rows if r['state'] == k) for k in ('approved', 'in_review', 'draft', 'missing')}
    return {'policies': rows, 'counts': c, 'total': len(rows),
            'note': 'The policy set PDPL expects of a controller. "What it must cover" is drawn from the law and its regulations as an outline for the DPO and legal to complete - it is not policy text. A draft is written and approved on GRC Policies & Controls (an administrator who did not write it approves).'}


def _policy_text(pid):
    try:
        from pdpl_policy_texts import text_of
    except ImportError:   # an older install without the drafts file: the outline is used, as before
        return None
    return text_of(pid)


def _policy_sections(text):
    from pdpl_policy_texts import sections_of
    return sections_of(text)


def policy_draft(req):
    pid = req.get('id')
    row = next((x for x in POLICIES if x[0] == pid), None)
    if not row:
        return {'refuse': {'status': 404, 'error': 'no PDPL policy ' + str(pid)}}
    v = policy_view(req)
    cur = next(r for r in v['policies'] if r['id'] == pid)
    if not cur['can_draft']:
        return {'refuse': {'status': 409, 'error': row[1] + ' is already ' + cur['state'].replace('_', ' ') + (' (' + str(cur['doc']) + ')' if cur['doc'] else '')}}
    full = _policy_text(pid)
    if full:
        # a full first draft exists (pdpl_policy_texts.py): it becomes the body, its section headings the requirement list.
        # Still a draft - approved only on GRC Policies by an administrator who did not write or change it.
        return {'draft': {'title': row[1], 'domain': 'Data Protection', 'frameworks': 'PDPL (' + row[2] + ')', 'control': row[3],
                          'purpose': _org_fill('Set out how {{org.short}} meets ') + row[2] + '. Full first draft - complete every [bracketed] item before approval.',
                          'requirements': _policy_sections(full), 'body': full}}
    return {'draft': {'title': row[1], 'domain': 'Data Protection', 'frameworks': 'PDPL (' + row[2] + ')', 'control': row[3],
                      'purpose': _org_fill('Set out how {{org.short}} meets ') + row[2] + '.', 'requirements': ['Outline from the law - to be completed by the DPO and legal:'] + row[5], 'body': ''}}


# ---------------------------------------------------------------- Governance: accountability, committee, privacy by design, programme review
FUNCTIONS = [('inventory', 'Data inventory and mapping'), ('approval', 'Processing approval and contracts'), ('requests', 'Data subject requests'),
             ('incidents', 'Security incident and breach response'), ('training', 'Staff training and awareness'), ('sdaia', 'SDAIA liaison and documentation')]
COMMITTEE_DEPTS = ['legal', 'it', 'hr', 'operations']
REVIEW_CHECKS = [('followed', 'Documented processes are actually being followed'), ('changes', 'Changes in business operations or data flows'),
                 ('guidance', 'New SDAIA guidance or enforcement signals'), ('processors', 'Third-party processor compliance'), ('incidents', 'Incident frequency and root causes')]
PBD_Q = [('personal', 'Does it process personal data?', ['no', 'yes']), ('sensitive', 'Sensitive or credit data?', ['no', 'yes']),
         ('new_tech', 'New technology, AI or automated decisions?', ['no', 'yes']), ('sources', 'Combines data from two or more sources?', ['no', 'yes']),
         ('outside', 'Data stored or accessed outside the Kingdom?', ['no', 'yes']), ('processor', 'A vendor / processor handles the data?', ['no', 'yes']),
         ('minimised', 'Only the fields needed for the purpose are collected?', ['yes', 'partly', 'no']), ('controls', 'Access control, encryption and logging designed in?', ['yes', 'partly', 'no']),
         ('retention', 'Retention period decided and deletion built in?', ['yes', 'no']), ('notice', 'Privacy notice / consent wording updated?', ['yes', 'no', 'not needed'])]


def pbd_assess(req):
    a = req.get('answers') or {}
    miss = [q for q, _, opts in PBD_Q if a.get(q) not in opts]
    if miss:
        return {'refuse': {'status': 400, 'error': 'answer every question: ' + ', '.join(miss)}}
    need, dpia = [], a['personal'] == 'yes' and 'yes' in (a['sensitive'], a['new_tech'], a['sources'])
    if a['personal'] == 'no':
        return {'dpia_required': False, 'required': [], 'ready': True, 'note': 'no personal data - no further privacy review needed'}
    if dpia:
        need.append('an impact assessment signed before go-live (DPIA page)')
    if a['outside'] == 'yes':
        need.append('a transfer basis and transfer impact assessment (Cross-Border Transfers)')
    if a['processor'] == 'yes':
        need.append('a processor agreement with the PDPL terms and due diligence (Processors)')
    if a['minimised'] != 'yes':
        need.append('reduce the fields collected to what the purpose needs')
    if a['controls'] != 'yes':
        need.append('access control, encryption and logging in the design')
    if a['retention'] != 'yes':
        need.append('a retention period and deletion (Retention schedule)')
    if a['notice'] == 'no':
        need.append('update the privacy notice / consent wording before collection')
    need.append('add or update the activity in the records of processing')
    return {'dpia_required': dpia, 'required': need, 'ready': not [x for x in need if not x.startswith('add or update')]}


def governance_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    P = next((r for r in recs if r.get('kind') == 'profile'), {}) or {}
    acc = {x.get('function'): x for x in _by(recs, 'accountability')}
    functions = [{'function': k, 'label': l, 'user': (acc.get(k) or {}).get('user'), 'deputy': (acc.get(k) or {}).get('deputy'), 'id': (acc.get(k) or {}).get('id')} for k, l in FUNCTIONS]
    meets = sorted(_by(recs, 'committee_meeting'), key=lambda m: str(m.get('date') or ''), reverse=True)
    last = ms(meets[0].get('date')) if meets else None
    year = [m for m in meets if ms(m.get('date')) and now - ms(m.get('date')) <= 365 * DAY]
    present = {_norm(d) for m in year for d in m.get('departments') or []}
    pbd = []
    for r in sorted(_by(recs, 'pbd_review'), key=lambda x: str(x.get('created_at') or ''), reverse=True):
        sc = r.get('score') or {}
        pbd.append({'id': r['id'], 'name': r.get('name'), 'type': r.get('type'), 'go_live': r.get('go_live'), 'state': r.get('state') or 'submitted', 'requested_by': r.get('created_by'),
                    'dpia_required': sc.get('dpia_required'), 'required': sc.get('required') or [], 'decided_by': r.get('decided_by'), 'note': r.get('decision_note'),
                    'late': bool(r.get('state') in (None, 'submitted') and ms(r.get('go_live')) and ms(r.get('go_live')) < now)})
    revs = sorted(_by(recs, 'programme_review'), key=lambda x: str(x.get('date') or ''), reverse=True)
    actions = []
    for rv in revs:
        for i, x in enumerate(rv.get('actions') or []):
            actions.append(dict(x, review=rv['id'], n=i + 1, overdue=bool(x.get('status') != 'done' and ms(x.get('due')) and ms(x.get('due')) < now)))
    acts, tra = _by(recs, 'ropa'), _by(recs, 'training')
    depts = sorted({_norm(a.get('owner')) for a in acts if a.get('owner')})
    trained = {_norm(t.get('team')) for t in tra if ms(t.get('date')) and now - ms(t.get('date')) <= 365 * DAY}
    return {'dpo': {'user': P.get('dpo_user'), 'reports_to': P.get('dpo_reports_to'), 'can_stop': bool(P.get('dpo_can_stop')), 'appointed': P.get('dpo_appointed'),
                    'ok': bool(P.get('dpo_user') and P.get('dpo_reports_to') and P.get('dpo_can_stop'))},
            'functions': functions, 'functions_gap': [f['label'] for f in functions if not f['user']],
            'committee': {'meetings': [{'id': m['id'], 'date': m.get('date'), 'departments': m.get('departments') or [], 'attendees': m.get('attendees') or [], 'decisions': m.get('decisions'), 'actions': m.get('actions') or []} for m in meets[:20]],
                          'last': meets[0].get('date') if meets else None, 'overdue': not last or now - last > 92 * DAY, 'missing_departments': [d for d in COMMITTEE_DEPTS if d not in present], 'required': COMMITTEE_DEPTS},
            'pbd': pbd, 'pbd_questions': [{'id': q, 'question': t, 'options': o} for q, t, o in PBD_Q],
            'reviews': [{'id': r['id'], 'date': r.get('date'), 'reviewer': r.get('created_by'), 'checks': r.get('checks') or {}, 'summary': r.get('summary')} for r in revs[:10]],
            'review_checks': [{'id': k, 'label': l} for k, l in REVIEW_CHECKS], 'review_overdue': not revs or now - (ms(revs[0].get('date')) or 0) > 365 * DAY,
            'actions': actions, 'open_actions': sum(1 for x in actions if x.get('status') != 'done'), 'overdue_actions': sum(1 for x in actions if x['overdue']),
            'untrained_departments': [d for d in depts if d not in trained],
            'note': 'Accountability sits with named people, not job titles. The committee meets at least quarterly; the programme is reviewed at least once a year and every finding becomes an action with an owner and a due date.'}


OPS = {
    'pdpl.ropa_view': ropa_view, 'pdpl.sensitive_view': sensitive_view, 'pdpl.dsar_view': dsar_view, 'pdpl.dsar_letter': dsar_letter, 'pdpl.dpia_view': dpia_view,
    'pdpl.transfer_tia': transfer_tia, 'pdpl.transfer_view': transfer_view, 'pdpl.breach_view': breach_view, 'pdpl.processor_view': processor_view,
    'pdpl.maturity_score': maturity_score, 'pdpl.programme_view': programme_view, 'pdpl.policy_view': policy_view, 'pdpl.policy_draft': policy_draft,
    'pdpl.governance_view': governance_view, 'pdpl.pbd_assess': pbd_assess,
}
