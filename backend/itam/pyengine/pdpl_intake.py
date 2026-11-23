# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Data subject request intake (engine/pdpl-intake.js): the rules for a request the customer portal, the app or the
call-centre system sends in - who it is routed to, whether the channel's identity check is strong enough to count as
verified, whether the same person already has the same request open (then it is the same request, not a new one) or had
it answered recently (flagged as possibly repetitive - only the DPO may refuse it), the due date, and the acknowledgement
the channel shows the person in Arabic and English. Python decides; Node.js commits (PDPL Art. 4, Implementing Regulation
Arts. 3-10: 30 days, identity verified, every request documented).

The person's identifier never reaches this file: Node.js passes only a one-way reference (HMAC) and the requests already
recorded under the same reference.
"""
import datetime
from org_brand import fill as _org_fill

DAY = 86400000
METHODS = {
    'nafath': 'Nafath (national single sign-on)',
    'absher_otp': 'one-time code to the mobile registered with Absher',
    'policy_number_and_otp': 'policy number and a one-time code to the registered mobile',
    'registered_email': 'reply from the e-mail address on file',
    'national_id_in_branch': 'original ID seen in a branch',
    'none': 'not checked by the channel',
}
DEFAULT_STRONG = ['nafath', 'national_id_in_branch']
TYPES = {'access': 'access to the personal data we hold about you', 'copy': 'a copy of your personal data', 'correction': 'correction of your personal data', 'destruction': 'destruction of your personal data',
         'withdraw_consent': 'withdrawal of your consent', 'objection': 'objection to the processing of your personal data', 'other': 'your request about your personal data'}
TYPES_AR = {'access': 'الاطلاع على بياناتك الشخصية لدينا', 'copy': 'الحصول على نسخة من بياناتك الشخصية', 'correction': 'تصحيح بياناتك الشخصية', 'destruction': 'إتلاف بياناتك الشخصية',
            'withdraw_consent': 'الرجوع عن موافقتك', 'objection': 'الاعتراض على معالجة بياناتك الشخصية', 'other': 'طلبك المتعلق ببياناتك الشخصية'}
CLOSED = ('responded', 'refused', 'withdrawn')
REPEAT_DAYS = 180


def ms(v):
    if not v:
        return None
    s = str(v)
    try:
        if len(s) == 10:
            return int(datetime.datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
        return int(datetime.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000)
    except ValueError:
        return None


def day(t):
    return datetime.datetime.fromtimestamp(t / 1000, datetime.timezone.utc).strftime('%Y-%m-%d') if t else None


def settings_of(s):
    s = s or {}
    strong = [m for m in (s.get('strong_methods') or DEFAULT_STRONG) if m in METHODS and m != 'none']
    return {'assignees': {k: v for k, v in (s.get('assignees') or {}).items() if k in TYPES and v}, 'default_assignee': s.get('default_assignee') or None,
            'strong_methods': strong, 'auto_search': bool(s.get('auto_search')), 'updated_by': s.get('updated_by'), 'updated_at': s.get('updated_at')}


def decide(req):
    r, now = req.get('request') or {}, req.get('now') or 0
    S = settings_of(req.get('settings'))
    t = r.get('type') if r.get('type') in TYPES else 'other'
    received = ms(r.get('received')) or now
    prior = [x for x in (req.get('history') or []) if x.get('type') == t]
    open_same = next((x for x in prior if (x.get('stage') or 'received') not in CLOSED), None)
    if open_same:
        # the same person, the same kind of request, still open: one request, answered once (no second clock)
        return {'action': 'existing', 'request': open_same.get('id'), 'reference': open_same.get('ref'), 'due': open_same.get('due'),
                'ack': ack(t, open_same.get('ref'), open_same.get('received'), open_same.get('due'), req.get('profile'), again=True), 'why': 'the same request from this person is already open'}
    answered = [x for x in prior if x.get('stage') in ('responded',) and ms(x.get('responded') or x.get('received')) and now - ms(x.get('responded') or x.get('received')) <= REPEAT_DAYS * DAY]
    method = r.get('identity_method') if r.get('identity_method') in METHODS else 'none'
    verified = method in S['strong_methods']
    assignee = S['assignees'].get(t) or S['default_assignee']
    due = received + 30 * DAY
    ref = r.get('ref')
    flags = []
    if answered:
        flags.append({'flag': 'possibly_repetitive', 'detail': 'the same request from this person was answered on ' + ', '.join(str(x.get('responded') or x.get('received'))[:10] for x in answered[:3]) + ' (' + ', '.join(str(x.get('ref')) for x in answered[:3]) + ') - only the DPO may refuse it as repetitive, with the reason'})
    if not verified:
        flags.append({'flag': 'verify_identity', 'detail': 'the channel checked identity by "' + METHODS[method] + '", which is not accepted as verification - a person verifies the requester before the search'})
    if not assignee:
        flags.append({'flag': 'unassigned', 'detail': 'no handler is set for ' + t + ' requests - the DPO assigns it (Intake settings)'})
    return {'action': 'create', 'type': t, 'received': day(received) if len(str(r.get('received') or '')) <= 10 else r.get('received'), 'due': day(due),
            'stage': 'in_progress' if verified else 'verifying', 'identity_verified': verified, 'identity_method': method, 'identity_label': METHODS[method],
            'assign_to': assignee, 'auto_search': bool(S['auto_search'] and verified and r.get('has_identifier')), 'flags': flags,
            'repetitive_of': [x.get('ref') for x in answered[:5]], 'ack': ack(t, ref, day(received), day(due), req.get('profile'))}


def ack(t, ref, received, due, profile, again=False):
    p = profile or {}
    contact = p.get('dpo_contact') or 'the Data Protection Officer'
    en = (_org_fill('Reference: %s\n\n%sWe have received your request for %s on %s. We will answer by %s. If we need to confirm your identity we will contact you through the channel you used. '
          'Questions: %s.\n\n{{org.name}}')) % (ref, 'This request is already open with us. ' if again else '', TYPES.get(t), received, due, contact)
    ar = (_org_fill('المرجع: %s\n\n%sاستلمنا طلبك بشأن %s بتاريخ %s، وسنرد عليه في موعد أقصاه %s. إذا احتجنا إلى التحقق من هويتك فسنتواصل معك عبر القناة التي استخدمتها. '
          'للاستفسار: %s.\n\n{{org.name_ar}}')) % (ref, 'هذا الطلب قائم لدينا بالفعل. ' if again else '', TYPES_AR.get(t), received, due, contact)
    return {'en': en, 'ar': ar}


def view(req):
    recs, now, keys = req.get('records') or [], req.get('now') or 0, req.get('keys') or []
    S = settings_of(req.get('settings'))
    rows = [r for r in recs if r.get('kind') == 'dsr' and r.get('intake')]
    recent = [r for r in rows if (ms(r.get('created_at')) or 0) >= now - 30 * DAY]
    by_channel = {}
    for r in recent:
        by_channel[r.get('channel') or 'other'] = by_channel.get(r.get('channel') or 'other', 0) + 1
    live_keys = [k for k in keys if not k.get('revoked_at')]
    F = []
    if live_keys and not S['default_assignee'] and not S['assignees']:
        F.append({'key': 'intake:assignee', 'severity': 'high', 'title': 'Requests arrive automatically but no handler is set', 'evidence': ['%d intake key(s) active' % len(live_keys)],
                  'recommendation': 'Set a default handler (and one per request type if needed) on the Data Subject Requests page → Intake.', 'requirement': 'P-08'})
    stale = [r for r in rows if (r.get('stage') or 'received') == 'verifying' and (ms(r.get('created_at')) or now) < now - 5 * DAY]
    if stale:
        F.append({'key': 'intake:verify', 'severity': 'medium', 'title': '%d request(s) waiting more than 5 days for identity verification' % len(stale), 'evidence': [str(r.get('ref')) for r in stale[:6]],
                  'recommendation': 'Verify the requesters (Data Subject Requests → Verify) - the 30 days run from receipt, not from verification.', 'requirement': 'P-08'})
    log = sorted([{'id': r['id'], 'ref': r.get('ref'), 'type': r.get('type'), 'channel': r.get('channel'), 'source': (r.get('intake') or {}).get('source_name'), 'at': r.get('created_at'),
                   'stage': r.get('stage'), 'auto_verified': bool((r.get('intake') or {}).get('auto_verified')), 'auto_searched': bool((r.get('intake') or {}).get('searched')),
                   'found_in': (r.get('intake') or {}).get('found_in'), 'flags': [f['flag'] for f in (r.get('intake') or {}).get('flags') or []], 'assigned_to': r.get('assigned_to')} for r in rows],
                 key=lambda x: str(x['at'] or ''), reverse=True)[:200]
    return {'settings': S, 'methods': METHODS, 'types': TYPES, 'summary': {'last_30_days': len(recent), 'by_channel': by_channel, 'auto_verified': sum(1 for r in recent if (r.get('intake') or {}).get('auto_verified')),
            'auto_searched': sum(1 for r in recent if (r.get('intake') or {}).get('searched')), 'repetitive_flagged': sum(1 for r in recent if any(f.get('flag') == 'possibly_repetitive' for f in (r.get('intake') or {}).get('flags') or [])),
            'keys_active': len(live_keys)}, 'log': log, 'findings': F,
            'note': 'The customer portal, the app and the call-centre system send each request here with their own reference and how they checked the person. Only that reference and a one-way code of the identifier are kept - never the identifier itself.'}


OPS = {'pdpl.intake_decide': decide, 'pdpl.intake_view': view}
