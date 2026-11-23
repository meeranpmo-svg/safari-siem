# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Non-Human Identities (NHI): every identity that is not a person - directory service accounts, managed service accounts,
Entra app registrations, the platform's own connector credentials, agent keys and API keys, and the AI engineers. Python
decides, Node.js commits (engine/nhi.js): this module reads only the facts it is given and writes nothing.

  nhi.view   {facts, register, policy, now} -> items (one per identity, with its risks), counts, findings, sources

An identity is listed only from a source that reported it; a source not connected is named with what to connect, never read
as "no identities". Risks are judged from what the source reports (privilege, password / secret age, expiry, last use,
Kerberos flags, permissions) and from the register a person keeps (owner, purpose, review). Every risk carries the fix. The
platform never disables an account or rotates a secret: decommissioning is a request a second person approves and a person
carries out. Standard library only.
"""
from datetime import datetime, timezone

DAY = 86400000
SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
POLICY = {'rotation_days': 365, 'privileged_rotation_days': 90, 'dormant_days': 90, 'secret_max_days': 730, 'expiry_warn_days': 30,
          'review_days': 365, 'key_unused_days': 90, 'agent_stale_days': 30, 'many_app_permissions': 5}
KINDS = {'service_user': 'AD service account', 'gmsa': 'Group managed service account', 'smsa': 'Managed service account',
         'entra_app': 'Entra app registration', 'connector': 'Platform connector credential', 'scan_credential': 'Discovery / scan credential',
         'agent': 'Platform agent key', 'enrol_token': 'Agent enrolment token', 'api_key': 'Platform API key', 'ai_engineer': 'AI engineer identity'}


def ms(v):
    if isinstance(v, (int, float)):
        return int(v)
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    try:
        d = datetime.fromisoformat(s[:-1] + '+00:00' if s.endswith('Z') else s) if len(s) > 10 else datetime.strptime(s, '%Y-%m-%d')
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def days_since(v, now):
    t = ms(v)
    return None if t is None else int((now - t) // DAY)


def days_until(v, now):
    t = ms(v)
    return None if t is None else int((t - now) // DAY)


def _risk(out, key, sev, text, fix):
    out.append({'key': key, 'severity': sev, 'text': text, 'fix': fix})


def _src(facts, k):
    s = (facts or {}).get(k)
    return s if isinstance(s, dict) else {}


# ---- one function per source: (items) with risks judged from what the source reports
def ad_items(f, P, now):
    out = []
    for a in (_src(f, 'ad').get('accounts') or []):
        r, priv = [], bool(a.get('privileged'))
        rot = P['privileged_rotation_days'] if priv else P['rotation_days']
        managed = bool(a.get('managed'))
        enabled = not a.get('disabled')
        if enabled:
            if a.get('pwd_not_required'):
                _risk(r, 'pwd_not_required', 'critical', 'the account may have an empty password (PASSWD_NOTREQD)', 'clear PASSWD_NOTREQD and set a long random password, or move the service to a gMSA')
            if priv:
                _risk(r, 'privileged', 'high' if not managed else 'medium', 'member of ' + (', '.join(a.get('privileged_groups') or []) or 'a privileged group'),
                      'give the service only the rights it needs (delegated permissions, a tiered admin model); a service account in Domain Admins is a domain takeover path')
            if a.get('no_preauth'):
                _risk(r, 'no_preauth', 'high', 'Kerberos pre-authentication is off - the password hash can be requested by anyone (AS-REP roasting)', 'turn pre-authentication back on')
            if a.get('delegation'):
                _risk(r, 'delegation', 'high', 'trusted for unconstrained delegation - it can impersonate any user who connects to it', 'use constrained or resource-based delegation')
            age = a.get('pwd_age_days')
            if not managed and a.get('spn') and age is not None and age > rot:
                _risk(r, 'kerberoast', 'high' if priv else 'medium', 'has a service principal name and a %d-day-old password - the ticket can be cracked offline (Kerberoasting)' % age,
                      'rotate to a 25+ character random password or convert to a gMSA (rotated by AD every 30 days)')
            elif not managed and age is not None and age > rot:
                _risk(r, 'old_secret', 'medium', 'password last changed %d days ago (policy %d days)' % (age, rot), 'rotate the password and update every service that uses it, or convert to a gMSA')
            if not managed and a.get('pwd_never_expires'):
                _risk(r, 'never_expires', 'low', 'password never expires - rotation depends on people remembering', 'record a rotation date, or convert to a gMSA')
            if a.get('dormant') or a.get('never_logon'):
                _risk(r, 'unused', 'medium', 'no sign-in for %d+ days' % P['dormant_days'] if a.get('dormant') else 'has never signed in',
                      'confirm with the owner whether it is still needed; if not, request decommissioning')
        out.append({'id': a.get('id') or ('ad:' + str(a.get('name'))), 'source': 'ad', 'kind': a.get('kind') or 'service_user', 'name': a.get('name'),
                    'detail': a.get('description') or ', '.join(a.get('why') or []), 'privileged': priv, 'enabled': enabled,
                    'secret_age_days': a.get('pwd_age_days'), 'last_used': a.get('last_logon'), 'expires': None, 'facts': {
                        'why': a.get('why') or [], 'spn': (a.get('spn') or [])[:5], 'groups': a.get('privileged_groups') or [], 'managed': managed,
                        'pwd_interval_days': a.get('pwd_interval_days'), 'host': a.get('host') or ''}, 'risks': r})
    return out


def entra_items(f, P, now):
    out = []
    for a in (_src(f, 'entra').get('apps') or []):
        r, creds = [], (a.get('secrets') or []) + (a.get('certs') or [])
        ends = [(c, days_until(c.get('end'), now)) for c in creds]
        live = [x for x in ends if x[1] is not None and x[1] >= 0]
        for c, d in ends:
            label = ('secret' if c in (a.get('secrets') or []) else 'certificate') + (' "' + c.get('name') + '"' if c.get('name') else '')
            if d is not None and d < 0:
                _risk(r, 'expired:' + label, 'medium' if not live else 'low', label + ' expired %d days ago' % -d, 'remove the expired credential; if the app still needs one, add a certificate (preferred) and update the service')
            elif d is not None and d <= P['expiry_warn_days']:
                _risk(r, 'expiring:' + label, 'medium', label + ' expires in %d days - the integration stops when it does' % d, 'add a new credential, switch the service to it, then remove the old one')
            life = (ms(c.get('end')) - ms(c.get('start'))) // DAY if ms(c.get('end')) and ms(c.get('start')) else None
            if life is not None and life > P['secret_max_days'] and c in (a.get('secrets') or []):
                _risk(r, 'long_secret:' + label, 'medium', label + ' is valid for %d days (policy %d)' % (life, P['secret_max_days']), 'replace it with a shorter-lived secret or a certificate')
        if a.get('owners') is not None and not a.get('owners'):
            _risk(r, 'no_entra_owner', 'medium', 'no owner in Entra ID - nobody is accountable for its permissions and secrets', 'add an owner in Entra ID (and record one here)')
        n = int(a.get('app_permissions') or 0)
        if n >= P['many_app_permissions']:
            _risk(r, 'many_permissions', 'medium', '%d application permissions (act without a user)' % n, 'review each application permission and remove what the app does not use')
        if str(a.get('audience') or '').endswith(('MultipleOrgs', 'PersonalMicrosoftAccount')):
            _risk(r, 'multi_tenant', 'low', 'sign-in open to other organisations (' + str(a.get('audience')) + ')', 'set the audience to this organisation only unless the app is meant to be multi-tenant')
        nxt = min([d for _, d in live], default=None)
        out.append({'id': 'entra:' + str(a.get('app_id') or a.get('id')), 'source': 'entra', 'kind': 'entra_app', 'name': a.get('name') or a.get('app_id'),
                    'detail': '%d secret(s), %d certificate(s), %d application / %d delegated permission(s)' % (len(a.get('secrets') or []), len(a.get('certs') or []), n, int(a.get('delegated_permissions') or 0)),
                    'privileged': n >= P['many_app_permissions'], 'enabled': True, 'secret_age_days': None, 'last_used': None,
                    'expires': (datetime.fromtimestamp((now + nxt * DAY) / 1000, timezone.utc).strftime('%Y-%m-%d') if nxt is not None else None),
                    'facts': {'app_id': a.get('app_id'), 'owners': a.get('owners'), 'audience': a.get('audience')}, 'risks': r})
    return out


def platform_items(f, P, now):
    p, out = _src(f, 'platform'), []
    for c in p.get('connectors') or []:
        r, age = [], days_since(c.get('set_at'), now)
        if age is not None and age > P['rotation_days']:
            _risk(r, 'old_secret', 'medium', 'set %d days ago (policy %d)' % (age, P['rotation_days']), 'rotate it at the source and save the new value (Connections & Setup)')
        out.append({'id': 'itam:connector:' + c['id'], 'source': 'platform', 'kind': 'connector', 'name': c['id'], 'detail': 'sealed in the platform vault',
                    'privileged': False, 'enabled': True, 'secret_age_days': age, 'last_used': None, 'expires': None, 'facts': {'set_by': c.get('by')}, 'risks': r})
    for c in p.get('credentials') or []:
        r, age = [], days_since(c.get('updated_at') or c.get('created_at'), now)
        if age is not None and age > P['rotation_days']:
            _risk(r, 'old_secret', 'medium', 'last changed %d days ago (policy %d)' % (age, P['rotation_days']), 'rotate the account password on the target and update the credential (Asset Discovery -> Credentials)')
        if c.get('kind') == 'snmp_v2c':
            _risk(r, 'cleartext', 'medium', 'SNMPv2c - the community string travels in clear', 'move the device to SNMPv3 (authPriv) and replace the credential')
        tested = days_since(c.get('last_tested'), now)
        if not c.get('in_use'):
            _risk(r, 'unused', 'low', 'not used by any discovery scope', 'delete it if nothing needs it')
        elif tested is None or tested > 90:
            _risk(r, 'untested', 'low', 'not tested for %s' % ('ever' if tested is None else '%d days' % tested), 'run Test on the credential to confirm it still works and is read-only')
        out.append({'id': 'itam:cred:' + c['id'], 'source': 'platform', 'kind': 'scan_credential', 'name': c.get('label') or c['id'], 'detail': (c.get('kind') or '') + (' -> ' + c['target'] if c.get('target') else ''),
                    'privileged': False, 'enabled': True, 'secret_age_days': age, 'last_used': c.get('last_tested'), 'expires': None, 'facts': {'kind': c.get('kind'), 'scopes': c.get('scopes') or []}, 'risks': r})
    for a in p.get('agents') or []:
        r, seen, age = [], days_since(a.get('last_seen'), now), days_since(a.get('enrolled_at'), now)
        active = a.get('status') == 'active'
        if active and seen is not None and seen > P['agent_stale_days']:
            _risk(r, 'stale_key', 'medium', 'agent key still active but the agent has not reported for %d days' % seen, 'revoke the agent key if the machine is gone; re-enrol it if it comes back')
        out.append({'id': 'itam:agent:' + a['id'], 'source': 'platform', 'kind': 'agent', 'name': a.get('name') or a['id'], 'detail': (a.get('platform') or '') + (' · ' + a['site'] if a.get('site') else ''),
                    'privileged': False, 'enabled': active, 'secret_age_days': age, 'last_used': a.get('last_seen'), 'expires': None, 'facts': {}, 'risks': r})
    for t in p.get('enrol_tokens') or []:
        r = []
        if not t.get('used_at') and not t.get('revoked') and (days_until(t.get('expires_at'), now) or 0) < 0:
            _risk(r, 'expired_token', 'low', 'expired and never used', 'revoke it to keep the list clean')
        if t.get('used_at') or t.get('revoked'):
            continue
        out.append({'id': 'itam:enrol:' + str(t['id']), 'source': 'platform', 'kind': 'enrol_token', 'name': t.get('note') or 'enrolment token', 'detail': t.get('site') or '',
                    'privileged': False, 'enabled': True, 'secret_age_days': days_since(t.get('created_at'), now), 'last_used': None, 'expires': (t.get('expires_at') or '')[:10] or None, 'facts': {}, 'risks': r})
    for k in p.get('api_keys') or []:
        if k.get('revoked_at'):
            continue
        r, age, used = [], days_since(k.get('created_at'), now), days_since(k.get('last_used'), now)
        if age is not None and age > P['rotation_days']:
            _risk(r, 'old_secret', 'medium', 'issued %d days ago (policy %d)' % (age, P['rotation_days']), 'issue a new key to the sending system, then revoke this one')
        if (used is None and (age or 0) > P['key_unused_days']) or (used is not None and used > P['key_unused_days']):
            _risk(r, 'unused', 'low', 'not used for %s' % ('ever' if used is None else '%d days' % used), 'revoke it if the sending system no longer uses it')
        out.append({'id': 'itam:key:' + k['area'] + ':' + k['id'], 'source': 'platform', 'kind': 'api_key', 'name': k.get('name') or k['id'], 'detail': k['area'] + ' API key (stored as a hash only)',
                    'privileged': False, 'enabled': True, 'secret_age_days': age, 'last_used': k.get('last_used'), 'expires': None, 'facts': {'area': k['area']}, 'risks': r})
    for e in p.get('ai_engineers') or []:
        r = []
        if not e.get('people'):
            _risk(r, 'no_human_approver', 'medium', 'no named human approver - only administrators can decide its proposals', 'Roles & Functions: give the matching team role the "' + e['scope'] + '" approval scope')
        out.append({'id': 'ai:' + e['scope'], 'source': 'platform', 'kind': 'ai_engineer', 'name': e.get('engineer') or e['scope'], 'detail': 'proposes ' + (e.get('approves') or 'changes') + '; a person approves',
                    'privileged': False, 'enabled': True, 'secret_age_days': None, 'last_used': None, 'expires': None, 'facts': {'approvers': e.get('people') or []}, 'risks': r})
    return out


def view(req):
    now = int(req.get('now') or 0)
    P = dict(POLICY, **{k: v for k, v in (req.get('policy') or {}).items() if k in POLICY and isinstance(v, (int, float)) and v > 0})
    f = req.get('facts') or {}
    reg = req.get('register') or {}
    items = ad_items(f, P, now) + entra_items(f, P, now) + platform_items(f, P, now)
    for it in items:
        rec = reg.get(it['id']) or {}
        it['owner'] = rec.get('owner') or None
        it['purpose'] = rec.get('purpose') or None
        it['criticality'] = rec.get('criticality') or None
        it['review'] = rec.get('review') or None
        it['decommission'] = rec.get('decommission') or None
        if it['kind'] != 'ai_engineer' and it['enabled']:
            if not it['owner']:
                _risk(it['risks'], 'no_owner', 'high' if it['privileged'] else 'medium', 'no owner recorded - nobody is accountable for it', 'record the owner (a person) and what it is for')
            rv = days_since((it['review'] or {}).get('at'), now)
            if it['owner'] and (rv is None or rv > P['review_days']):
                _risk(it['risks'], 'review_due', 'low', 'owner review ' + ('never done' if rv is None else 'done %d days ago' % rv), 'the owner confirms it is still needed and its access is right')
        dc = it['decommission'] or {}
        if dc.get('status') == 'done' and it['enabled'] and it['source'] in ('ad', 'entra'):
            _risk(it['risks'], 'decommission_not_effective', 'high', 'recorded as decommissioned by ' + str(dc.get('done_by')) + ' but the source still reports it enabled', 'disable / delete it at the source; the register re-checks on every sync')
        it['risks'].sort(key=lambda x: -SEV[x['severity']])
        it['risk'] = it['risks'][0]['severity'] if it['risks'] else 'none'
        it['kind_name'] = KINDS.get(it['kind'], it['kind'])
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'none': 5}
    items.sort(key=lambda x: (order[x['risk']], x['source'], str(x['name']).lower()))
    counts = {'total': len(items), 'by_kind': {}, 'by_risk': {}, 'no_owner': 0, 'privileged': 0, 'old_secret': 0, 'expiring': 0, 'unused': 0}
    for it in items:
        counts['by_kind'][it['kind']] = counts['by_kind'].get(it['kind'], 0) + 1
        counts['by_risk'][it['risk']] = counts['by_risk'].get(it['risk'], 0) + 1
        keys = {r['key'].split(':')[0] for r in it['risks']}
        counts['no_owner'] += 'no_owner' in keys
        counts['privileged'] += bool(it['privileged'] and it['enabled'])
        counts['old_secret'] += bool(keys & {'old_secret', 'kerberoast'})
        counts['expiring'] += bool(keys & {'expiring', 'expired'})
        counts['unused'] += bool(keys & {'unused', 'stale_key'})
    findings = [{'key': 'nhi:' + it['id'], 'severity': it['risk'], 'kind': 'nhi-' + it['kind'], 'title': KINDS.get(it['kind'], it['kind']) + ' ' + str(it['name']) + ': ' + it['risks'][0]['text'],
                 'evidence': [r['severity'] + ': ' + r['text'] for r in it['risks']][:6], 'recommendation': it['risks'][0]['fix'], 'requirement': it['id']}
                for it in items if it['risk'] in ('critical', 'high', 'medium')]
    srcs = []
    for k, name, hint in (('ad', 'Active Directory (through the SIEM)', 'connect AD on the SIEM (Identity & Sign-in -> AD settings)'),
                          ('entra', 'Entra ID app registrations (through the SIEM)', 'grant Application.Read.All to the SIEM app registration'),
                          ('platform', 'This platform (vault, agents, API keys, AI engineers)', '')):
        s = _src(f, k)
        srcs.append({'id': k, 'name': name, 'connected': bool(s.get('available')), 'reason': s.get('reason') or (hint if not s.get('available') else ''), 'updated': s.get('synced') or s.get('updated')})
    return {'ok': True, 'items': items, 'counts': counts, 'findings': findings, 'sources': srcs, 'policy': P, 'kinds': KINDS,
            'note': 'Identities come only from sources that reported them; a source not connected is named, never read as "none". The platform never disables an account or rotates a secret - decommissioning is approved by a second person and done by a person.'}


OPS = {'nhi.view': view}
