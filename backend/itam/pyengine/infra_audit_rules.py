# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The AI auditors' infrastructure tests (engine/auditors.js CY-16..CY-20, IT-15, IT-16). Python decides, Node.js reads the
evidence from the SIEM (GET /api/soc/audit/evidence/*) and records the result: this module reads only what it is given
and writes nothing. Standard library only.

  infra_audit.ad_privileged {evidence, now}   privileged groups and accounts (Microsoft AD tiering, CIS, ISO A.8.2)
  infra_audit.ad_accounts   {evidence, now}   account and Kerberos hygiene (CIS, ISO A.5.16 / A.5.18, SAMA 3.3.5)
  infra_audit.ad_policy     {evidence, now}   domain password and lockout policy (CIS Windows Server 1.1 / 1.2)
  infra_audit.switches      {devices, configs, now}   Cisco IOS hardening (CIS Cisco IOS benchmark level 1)
  infra_audit.firewalls     {devices, now}    rule base, management access, logging, subscriptions (CIS FortiGate / PAN-OS,
                                              Cisco ASA)
  infra_audit.database      {report, now}     Database Audit report → audit trail, privileged use, configuration (CIS Oracle)
  infra_audit.applications  {report, now}     Application Audit reports → resilience, changes, logging per application
  infra_audit.leavers       {handovers, evidence, now}  leavers (Staff Handover) whose AD account is still enabled or used
  infra_audit.ad_generic    {evidence}        built-in Administrator / Guest, generic / shared names, admins with a mailbox
  infra_audit.config_changes {devices, now}   device configuration changed with no applied change plan (unauthorised)
  infra_audit.m365_mfa      {m365}            MFA registration, Conditional Access enabled, risky users not remediated
  infra_audit.m365_accounts {m365, now}       guests and licensed users not signed in for 90 days
  infra_audit.intune        {m365, now}       devices not compliant with the Intune policy, devices not checking in
  infra_audit.retention     {platform, now}   SIEM log retention against the required period
  infra_audit.dr            {engineer, items, now}  DR replication (AI Virtualization Administrator's open DR findings)

Every op returns {findings: [{key, severity, title, evidence[], recommendation, columns, items}], checked, scope[]}.
A check whose input is missing is listed in "scope" as not checked - it is never passed. Thresholds are the benchmark
values named in each finding, so an auditor can trace the criterion.
"""
import re
from datetime import datetime, timezone
from org_brand import fill as _org_fill

DAY = 86400000
SEVN = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def ms(v):
    if not v or not isinstance(v, str):
        return None
    s = v.strip().replace('Z', '+00:00')
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def day(v):
    t = ms(v) if isinstance(v, str) else v
    return datetime.fromtimestamp(t / 1000, tz=timezone.utc).strftime('%Y-%m-%d') if t else 'never'


def _f(key, sev, title, evidence, rec, columns=None, items=None):
    out = {'key': key, 'severity': sev, 'title': title, 'evidence': [e for e in evidence if e], 'recommendation': rec}
    if columns is not None:
        out['columns'] = columns
        out['items'] = [[('' if c is None else str(c)) for c in row] for row in (items or [])]
    return out


def _names(rows, n=10):
    xs = [r['sam'] if isinstance(r, dict) else str(r) for r in rows]
    return ', '.join(xs[:n]) + (' … +%d more' % (len(xs) - n) if len(xs) > n else '')


# ---------------------------------------------------------------- Active Directory
UCOLS = ['Account', 'Name', 'Enabled', 'Privileged groups', 'Last logon', 'Password last set', 'Created', 'Flags']


def _flags(u):
    return ' '.join(k for k in ('pwd_never_expires', 'pwd_not_required', 'no_preauth', 'delegation', 'dormant', 'service_account', 'admin_orphan', 'expired') if u.get(k))


def _urow(u):
    return [u.get('sam'), u.get('name'), 'no' if u.get('disabled') else 'yes', ' | '.join(u.get('privileged_groups') or []), day(u.get('last_logon')),
            day(u.get('pwd_last_set')), day(u.get('created')), _flags(u)]


def _age_days(v, now):
    t = ms(v)
    return None if not t else (now - t) / DAY


def ad_privileged(req):
    ev, now = req.get('evidence') or {}, req.get('now')
    users = ev.get('users') or []
    groups = {str(g.get('name', '')).lower(): g for g in ev.get('groups') or []}
    by = {u.get('sam'): u for u in users}
    F, scope = [], []
    priv = [u for u in users if u.get('privileged')]
    en = [u for u in priv if not u.get('disabled')]

    def members(name):
        g = groups.get(name.lower())
        return None if g is None else [by.get(m.get('sam')) or {'sam': m.get('sam')} for m in g.get('members') or []]

    for name, limit, sev in (('Enterprise Admins', 0, 'high'), ('Schema Admins', 0, 'medium'), ('Domain Admins', 5, 'medium')):
        m = members(name)
        if m is None:
            scope.append(name + ': group not read by the AD sync')
            continue
        live = [u for u in m if not u.get('disabled')]
        if len(live) > limit:
            F.append(_f('group:' + name.lower().replace(' ', '-'), sev, '%s has %d enabled member(s) (criterion: %s)' % (name, len(live), 'empty except during a change' if limit == 0 else 'at most %d' % limit),
                        ['members: ' + _names(live)],
                        'Microsoft AD tiering / CIS: keep %s %s; use a separate, named admin account per person and remove standing membership that is not needed.' % (name, 'empty and add members only for the change window' if limit == 0 else 'small'),
                        UCOLS, [_urow(u) for u in live]))
    rules = [
        ('pwd-never-expires', 'high', lambda u: u.get('pwd_never_expires'), 'privileged account(s) whose password never expires',
         'Clear "Password never expires" on every privileged account (CIS; SAMA 3.3.5). For a service account that must not expire use a gMSA.'),
        ('dormant', 'high', lambda u: u.get('dormant'), 'privileged account(s) not used for %s days or more' % int(ev.get('dormant_days') or 90),
         'Disable privileged accounts that are not used (ISO A.8.2, A.5.18): a dormant admin account is a target nobody watches.'),
        ('service', 'high', lambda u: u.get('service_account'), 'service account(s) in a privileged group',
         'Service accounts should hold only the rights their service needs: remove them from Domain / Enterprise / Builtin admin groups; use delegated rights or gMSA.'),
        ('old-password', 'medium', lambda u: (_age_days(u.get('pwd_last_set'), now) or 0) > 365, 'privileged account(s) whose password is older than 365 days',
         _org_fill('Change privileged passwords at least yearly (CIS; {{org.short}} password policy), or move them under a PAM vault that rotates them.')),
        ('never-logon', 'medium', lambda u: not u.get('last_logon'), 'privileged account(s) that have never signed in',
         'An admin account nobody uses should not exist: remove it, or record who owns it and why.'),
    ]
    for key, sev, test, what, rec in rules:
        hit = [u for u in en if test(u)]
        if hit:
            F.append(_f('priv:' + key, sev, '%d %s' % (len(hit), what), ['accounts: ' + _names(hit)], rec, UCOLS, [_urow(u) for u in hit]))
    dis = [u for u in priv if u.get('disabled')]
    if dis:
        F.append(_f('priv:disabled-member', 'low', '%d disabled account(s) still in a privileged group' % len(dis), ['accounts: ' + _names(dis)],
                    'Remove disabled accounts from privileged groups: re-enabling one would silently restore its rights.', UCOLS, [_urow(u) for u in dis]))
    orph = [u for u in users if u.get('admin_orphan') and not u.get('disabled')]
    if orph:
        F.append(_f('priv:admincount-orphan', 'low', '%d account(s) with adminCount=1 that are no longer privileged' % len(orph), ['accounts: ' + _names(orph)],
                    'Clear adminCount and re-enable inheritance on these accounts (AdminSDHolder leftovers keep stale permissions).', UCOLS, [_urow(u) for u in orph]))
    return {'findings': F, 'checked': len(priv), 'scope': scope, 'summary': {'privileged': len(priv), 'privileged_enabled': len(en)}}


def ad_accounts(req):
    ev, now = req.get('evidence') or {}, req.get('now')
    users = ev.get('users') or []
    en = [u for u in users if not u.get('disabled')]
    F, scope = [], []
    rules = [
        ('no-preauth', 'high', lambda u: u.get('no_preauth'), 'account(s) without Kerberos pre-authentication (AS-REP roastable)',
         'Clear "Do not require Kerberos preauthentication" (CIS; MITRE T1558.004): anyone can request a ticket for these accounts and crack it offline.'),
        ('pwd-not-required', 'high', lambda u: u.get('pwd_not_required'), 'account(s) allowed to have an empty password (PASSWD_NOTREQD)',
         'Clear the PASSWD_NOTREQD flag (userAccountControl 0x20) and set a password that meets policy.'),
        ('delegation', 'high', lambda u: u.get('delegation'), 'user account(s) trusted for unconstrained delegation',
         'Replace unconstrained delegation with constrained / resource-based delegation (CIS; MITRE T1558); mark admin accounts "sensitive and cannot be delegated".'),
        ('dormant', 'medium', lambda u: u.get('dormant') and not u.get('privileged'), 'enabled account(s) not used for %d days or more' % int(ev.get('dormant_days') or 90),
         'Review with HR and the account owners; disable accounts that are no longer needed (ISO A.5.18 access rights review; SAMA 3.3.5).'),
        ('never-logon', 'low', lambda u: not u.get('last_logon') and (_age_days(u.get('created'), now) or 0) > 30, 'enabled account(s) created more than 30 days ago that have never signed in',
         'Remove accounts that were created and never used, or record why they exist.'),
        ('pwd-never-expires', 'medium', lambda u: u.get('pwd_never_expires') and not u.get('privileged') and not u.get('service_account'), 'user account(s) whose password never expires',
         'Clear "Password never expires" for people\'s accounts; only documented service accounts (better: gMSA) may keep it.'),
        ('expired-enabled', 'low', lambda u: u.get('expired'), 'account(s) past their expiry date but still enabled',
         'Disable expired accounts (the expiry date is the owner\'s end date; HR leavers process).'),
    ]
    for key, sev, test, what, rec in rules:
        hit = [u for u in en if test(u)]
        if hit:
            F.append(_f('acct:' + key, sev, '%d %s' % (len(hit), what), ['accounts: ' + _names(hit)], rec, UCOLS, [_urow(u) for u in hit]))
    k = next((u for u in users if str(u.get('sam', '')).lower() == 'krbtgt'), None)
    if k is None:
        scope.append('krbtgt: account not in the AD sync (its password age is not checked)')
    else:
        a = _age_days(k.get('pwd_last_set'), now)
        if a is None or a > 180:
            F.append(_f('acct:krbtgt', 'high', 'krbtgt password %s' % ('last changed %d days ago' % a if a is not None else 'change date not known'),
                        ['password last set ' + day(k.get('pwd_last_set')), 'criterion: at least every 180 days'],
                        'Reset the krbtgt password twice (Microsoft New-KrbtgtKeys procedure, with replication between resets): an old krbtgt key keeps forged (golden) tickets valid.',
                        UCOLS, [_urow(k)]))
    return {'findings': F, 'checked': len(en), 'scope': scope, 'summary': {'users': len(users), 'enabled': len(en)}}


def ad_policy(req):
    p = (req.get('evidence') or {}).get('policy')
    if not p:
        return {'findings': [], 'checked': 0, 'scope': ['the domain password policy was not read (the SIEM AD sync reads it from the domain head; update the SIEM)'], 'not_read': True}
    cols = ['Setting', 'Value', 'Criterion (CIS Windows Server L1)', 'Result']
    rows, bad = [], []

    def chk(name, val, ok, crit, sev):
        if val is None:
            rows.append([name, 'not read', crit, 'not checked'])
            return
        good = ok(val)
        rows.append([name, val, crit, 'meets' if good else 'does not meet'])
        if not good:
            bad.append((sev, name, val, crit))

    chk('Minimum password length', p.get('min_length'), lambda v: v >= 14, '14 or more', 'high')
    chk('Password history', p.get('history'), lambda v: v >= 24, '24 or more', 'medium')
    chk('Maximum password age (days)', p.get('max_age_days'), lambda v: 0 < v <= 365, '1 to 365 (0 = never expires)', 'medium')
    chk('Minimum password age (days)', p.get('min_age_days'), lambda v: v >= 1, '1 or more', 'low')
    chk('Complexity required', p.get('complexity'), lambda v: v is True, 'enabled', 'high')
    chk('Reversible encryption', p.get('reversible'), lambda v: v is False, 'disabled', 'high')
    chk('Account lockout threshold', p.get('lockout_threshold'), lambda v: 0 < v <= 5, '1 to 5 failed attempts (0 = never locks)', 'high')
    chk('Account lockout duration (minutes)', p.get('lockout_minutes'), lambda v: v == 0 or v >= 15, '15 or more (0 = until an admin unlocks)', 'medium')
    chk('Lockout observation window (minutes)', p.get('lockout_window_minutes'), lambda v: v >= 15, '15 or more', 'low')
    F = []
    if bad:
        sev = max(bad, key=lambda b: SEVN[b[0]])[0]
        F.append(_f('policy:domain', sev, '%d domain password / lockout setting(s) below the benchmark' % len(bad),
                    ['%s = %s (criterion %s)' % (b[1], b[2], b[3]) for b in bad[:6]],
                    'Set them in the Default Domain Policy (Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies); use fine-grained password policies for admins and service accounts where a stricter value is needed. SAMA 3.3.5 / NCA ECC 2-2-3.',
                    cols, rows))
    return {'findings': F, 'checked': len(rows), 'scope': ['fine-grained password policies (PSOs) are not read'], 'rows': rows}


# ---------------------------------------------------------------- Cisco IOS / ASA configuration
DCOLS = ['Device', 'Site', 'Role', 'IP', 'Detail']


def _blocks(text):
    """running-config → [(header, [child lines])] for top-level lines."""
    out, cur = [], None
    for raw in (text or '').splitlines():
        line = raw.rstrip()
        if not line or line.startswith('!'):
            continue
        if line[0] in ' \t':
            if cur is not None:
                cur[1].append(line.strip())
        else:
            cur = (line.strip(), [])
            out.append(cur)
    return out


def ios_checks(text):
    """→ [(key, severity, title, detail, recommendation)] for one IOS running-config (CIS Cisco IOS benchmark L1)."""
    B = _blocks(text)
    top = [h for h, _ in B]
    has = lambda rx: any(re.search(rx, h) for h in top)
    out = []
    add = lambda k, s, t, d, r: out.append((k, s, t, d, r))
    if not has(r'^service password-encryption\b'):
        add('password-encryption', 'medium', 'service password-encryption is not set', 'no "service password-encryption" line', 'Configure "service password-encryption" (CIS 1.6.1) - and keep secrets as type 8 / 9.')
    if has(r'^enable password\b'):
        add('enable-password', 'high', 'enable password is used (reversible or clear text)', 'enable password present', 'Replace with "enable algorithm-type scrypt secret …" (type 9) and remove "enable password" (CIS 1.1.x).')
    if not has(r'^enable secret\b'):
        add('enable-secret', 'high', 'no enable secret is configured', 'no "enable secret" line', 'Configure "enable algorithm-type scrypt secret …" (type 9).')
    elif has(r'^enable secret (0|5|7)\b'):
        add('enable-secret-weak', 'medium', 'enable secret uses a weak hash type (0 / 5 / 7)', [h for h in top if h.startswith('enable secret')][0].split(' <')[0], 'Re-enter it with "algorithm-type scrypt" (type 9) or sha256 (type 8).')
    weak_users = [h.split()[1] for h in top if re.match(r'^username \S+ .*\b(password|secret (0|5|7))\b', h)]
    if weak_users:
        add('local-user-weak', 'high', 'local user(s) with a reversible or weak password: ' + ', '.join(weak_users[:5]), ', '.join(weak_users[:10]),
            'Use "username X algorithm-type scrypt secret …" for every local user and keep local users for break-glass only.')
    if not has(r'^aaa new-model\b'):
        add('aaa', 'medium', 'AAA is not enabled (aaa new-model)', 'no "aaa new-model"', 'Enable AAA and authenticate administrators against TACACS+ / RADIUS (ISE) with local fallback (CIS 1.1.1-1.1.4).')
    elif not has(r'^aaa authentication login \S+ group\b'):
        add('aaa-central', 'medium', 'administrator logins are not authenticated against TACACS+ / RADIUS', 'no "aaa authentication login … group …"', 'Authenticate admins centrally so each change is attributed to a named person (ISO A.5.16).')
    if not has(r'^ip ssh version 2\b'):
        add('ssh-v2', 'medium', 'SSH version 2 is not enforced', 'no "ip ssh version 2"', 'Configure "ip ssh version 2" (CIS 1.2.x).')
    vty = [(h, kids) for h, kids in B if h.startswith('line vty')]
    for h, kids in vty:
        ti = [k for k in kids if k.startswith('transport input')]
        if not ti or re.search(r'\b(telnet|all)\b', ti[-1]):
            add('vty-telnet:' + h, 'high', h + ': Telnet allowed', ti[-1] if ti else 'no transport input line (IOS default may allow telnet)', 'Set "transport input ssh" on every vty line (CIS 1.2.2).')
        if not any(k.startswith('access-class') for k in kids):
            add('vty-acl:' + h, 'medium', h + ': no access-class limits who may log in', 'no access-class', 'Apply an access-class allowing only the management network / jump hosts (CIS 1.2.4).')
        et = [k for k in kids if k.startswith('exec-timeout')]
        if et:
            p = et[-1].split()
            mins = int(p[1]) if len(p) > 1 and p[1].isdigit() else 10
            secs = int(p[2]) if len(p) > 2 and p[2].isdigit() else 0
            if (mins == 0 and secs == 0) or mins > 10:
                add('vty-timeout:' + h, 'medium', h + ': idle sessions do not time out within 10 minutes', et[-1], 'Set "exec-timeout 10 0" or less (CIS 1.2.5).')
    for h, kids in B:
        if h.startswith('line con'):
            et = [k for k in kids if k.startswith('exec-timeout')]
            if et and et[-1].split()[1:3] == ['0', '0']:
                add('con-timeout', 'low', 'console session never times out', et[-1], 'Set "exec-timeout 10 0" on line con 0 (CIS 1.2.x).')
    if has(r'^ip http server\b'):
        add('http-server', 'medium', 'the HTTP server is enabled', 'ip http server', 'Configure "no ip http server"; if the web UI is needed use "ip http secure-server" with an access-class (CIS 1.3.x).')
    comm = [h for h in top if h.startswith('snmp-server community')]
    if any(re.search(r'\bRW\b', h) for h in comm):
        add('snmp-rw', 'high', 'an SNMP read-write community is configured', 'snmp-server community … RW', 'Remove RW communities; use SNMPv3 with authPriv for monitoring (CIS 1.5.x).')
    noacl = [h for h in comm if not re.search(r'\b(RO|RW)\s+\S+', h)]
    if noacl:
        add('snmp-acl', 'medium', 'SNMP community without an access list', '; '.join(noacl[:3]), 'Bind every community to an ACL of the monitoring servers, or move to SNMPv3 (CIS 1.5.3).')
    if not has(r'^logging (host )?\d') and not has(r'^logging host\b'):
        add('logging', 'medium', 'no syslog server is configured', 'no "logging host"', 'Send logs to the SIEM collector: "logging host <collector>" + "logging trap informational" (CIS 2.x; SAMA 3.3.14).')
    if not has(r'^service timestamps log datetime'):
        add('timestamps', 'low', 'log messages carry no date/time stamp', 'no "service timestamps log datetime"', 'Configure "service timestamps log datetime msec show-timezone".')
    if not has(r'^ntp server\b') and not has(r'^sntp server\b'):
        add('ntp', 'medium', 'no NTP server is configured', 'no "ntp server"', 'Configure NTP to the internal time sources so logs line up for investigations (CIS 2.2.x).')
    if not has(r'^banner (login|motd)\b'):
        add('banner', 'low', 'no login banner', 'no "banner login" / "banner motd"', 'Configure an authorised-use-only banner approved by Legal (CIS 1.4.x).')
    if not has(r'^no ip source-route\b'):
        add('source-route', 'low', 'IP source routing is not disabled', 'no "no ip source-route"', 'Configure "no ip source-route" (CIS 3.1.1).')
    return out


def asa_checks(text):
    """Cisco ASA running-config (CIS Cisco ASA benchmark, management plane)."""
    B = _blocks(text)
    top = [h for h, _ in B]
    has = lambda rx: any(re.search(rx, h) for h in top)
    out = []
    add = lambda k, s, t, d, r: out.append((k, s, t, d, r))
    tel = [h for h in top if re.match(r'^telnet \d', h)]
    if tel:
        add('telnet', 'high', 'Telnet management is allowed', '; '.join(tel[:3]), 'Remove the "telnet" lines; manage the ASA over SSH only.')
    if not has(r'^ssh version 2\b'):
        add('ssh-v2', 'medium', 'SSH version 2 is not enforced', 'no "ssh version 2"', 'Configure "ssh version 2".')
    if has(r'^ssh 0\.0\.0\.0 0\.0\.0\.0 '):
        add('ssh-any', 'high', 'SSH management is allowed from any address', [h for h in top if h.startswith('ssh 0.0.0.0')][0], 'Limit "ssh" to the management network.')
    if not has(r'^aaa authentication ssh console\b'):
        add('aaa-ssh', 'medium', 'SSH logins are not authenticated through AAA', 'no "aaa authentication ssh console …"', 'Authenticate administrators through TACACS+ / RADIUS with LOCAL fallback.')
    if not has(r'^logging host\b'):
        add('logging', 'medium', 'no syslog server is configured', 'no "logging host"', 'Send logs to the SIEM collector ("logging host <if> <collector>", "logging enable").')
    if not has(r'^ntp server\b'):
        add('ntp', 'medium', 'no NTP server is configured', 'no "ntp server"', 'Configure NTP.')
    if has(r'^http 0\.0\.0\.0 0\.0\.0\.0 '):
        add('asdm-any', 'high', 'ASDM / HTTPS management is allowed from any address', [h for h in top if h.startswith('http 0.0.0.0')][0], 'Limit "http" to the management network.')
    if not has(r'^banner (login|motd)\b'):
        add('banner', 'low', 'no login banner', 'no banner', 'Configure an authorised-use-only banner.')
    return out


def _group(rows):
    """[(device, key, sev, title, detail, rec)] → one finding per check, every device named."""
    g = {}
    for d, key, sev, title, detail, rec in rows:
        base = key.split(':')[0]
        x = g.setdefault(base, {'sev': sev, 'rec': rec, 'title': title, 'devs': [], 'rows': []})
        if SEVN[sev] > SEVN[x['sev']]:
            x['sev'] = sev
        if d['name'] not in x['devs']:
            x['devs'].append(d['name'])
        x['rows'].append([d.get('name'), d.get('site'), d.get('role'), d.get('ip'), title if ':' in key else detail])
    return g


def switches(req):
    devs = [d for d in req.get('devices') or [] if d.get('vendor') == 'cisco-ios']
    configs = req.get('configs') or {}
    F, scope, rows, unread = [], [], [], []
    for d in devs:
        txt = configs.get(d['id'])
        if not txt:
            c = d.get('config') or {}
            unread.append([d.get('name'), d.get('site'), d.get('role'), d.get('ip'), c.get('error') or 'not captured yet'])
            continue
        for k, s, t, det, rec in ios_checks(txt):
            rows.append((d, k, s, t, det if isinstance(det, str) else str(det), rec))
        for it in d.get('security') or []:
            if it.get('kind') in ('telnet-open', 'http-open', 'snmp-v2c', 'snmp-nopriv', 'cert-expired'):
                rows.append((d, 'probe-' + it['kind'], it.get('severity') or 'medium', it.get('title'), '; '.join(it.get('evidence') or []), it.get('rec') or ''))
    for base, x in _group(rows).items():
        F.append(_f('ios:' + base, x['sev'], '%s - %d switch(es)' % (x['title'].split(':')[-1].strip() if base.startswith('vty') else x['title'], len(x['devs'])),
                    ['devices: ' + ', '.join(x['devs'][:10]) + (' … +%d more' % (len(x['devs']) - 10) if len(x['devs']) > 10 else '')], x['rec'], DCOLS, x['rows']))
    if unread:
        F.append(_f('ios:not-read', 'low', '%d Cisco switch(es) whose configuration the auditor could not read' % len(unread), [', '.join(r[0] for r in unread[:10])],
                    'Give the read-only SSH login and trust the host key (Network Engineer → Devices → SSH) so the configuration can be audited; an unread device is not audited.',
                    DCOLS, unread))
    if not devs:
        scope.append('no Cisco IOS device in the SIEM network inventory')
    return {'findings': F, 'checked': len(devs) - len(unread), 'devices': len(devs), 'scope': scope}


FW_VENDORS = ('fortigate', 'paloalto', 'cisco-asa')
FW_KINDS = {
    'fw-any-any': 'any-any', 'pa-any-any': 'any-any', 'fw-internet-any': 'internet-any', 'fw-nolog': 'no-log', 'pa-nolog': 'no-log',
    'mgmt-telnet': 'mgmt-clear', 'mgmt-http': 'mgmt-clear', 'pa-mgmt-telnet': 'mgmt-clear', 'pa-mgmt-http': 'mgmt-clear', 'telnet-open': 'mgmt-clear', 'http-open': 'mgmt-clear',
    'mgmt-wan': 'mgmt-wan', 'fw-admin-anywhere': 'admin-anywhere', 'fw-default-admin': 'default-admin',
    'cert-expired': 'cert', 'cert-expiring': 'cert', 'snmp-v2c': 'snmp', 'snmp-nopriv': 'snmp', 'mon-insecure-tls': 'monitoring-tls',
}
FW_TEXT = {
    'any-any': ('high', 'allow rules that permit any source to any destination on any service', 'Replace each with specific sources, destinations and services; check its hit count first (CIS FortiGate / PAN-OS; SAMA 3.3.7; NCA ECC 2-5-3).'),
    'internet-any': ('high', 'rules that let the internet reach any internal address', 'Limit the destination to published servers (VIP / NAT) and their services only.'),
    'no-log': ('medium', 'allow rules that do not log traffic', 'Enable logging on every allow rule and forward it to the SIEM (SAMA 3.3.14; NCA ECC 2-12).'),
    'mgmt-clear': ('high', 'management over Telnet / HTTP (clear text)', 'Disable Telnet and HTTP administration; use SSH and HTTPS from the management network only.'),
    'mgmt-wan': ('medium', 'administration reachable on internet-facing interfaces', 'Remove HTTPS / SSH administration from WAN interfaces; manage through the management network or VPN.'),
    'admin-anywhere': ('medium', 'administrators who can log in from any address', 'Set trusted hosts for every administrator (management subnet / jump host).'),
    'default-admin': ('low', 'the default "admin" account exists', 'Use named administrators and disable or rename the default account.'),
    'cert': ('medium', 'management certificates expired or expiring', 'Renew the device certificates (Certificates page tracks the renewal).'),
    'snmp': ('medium', 'SNMP v2c / v3 without privacy used to monitor the firewall', 'Monitor with SNMPv3 authPriv (SHA / AES).'),
    'monitoring-tls': ('medium', 'monitoring connections that do not verify the firewall certificate', 'Pin the certificate fingerprint in Network Engineer → Devices → Credentials.'),
}


def firewalls(req):
    now = req.get('now')
    devs = [d for d in req.get('devices') or [] if d.get('vendor') in FW_VENDORS]
    configs = req.get('configs') or {}
    F, scope, g = [], [], {}
    noreview, lic, stale = [], [], []
    for d in devs:
        base = [d.get('name'), d.get('vendor'), d.get('site'), d.get('role'), d.get('ip')]
        for it in d.get('security') or []:
            k = FW_KINDS.get(it.get('kind'))
            if k:
                g.setdefault(k, []).append(base + [it.get('key') or '', it.get('title') or '', '; '.join(it.get('evidence') or [])])
        if d.get('vendor') == 'cisco-asa':
            txt = configs.get(d['id'])
            if txt:
                for k, s, t, det, rec in asa_checks(txt):
                    g.setdefault('asa:' + k, []).append(base + [k, t, det if isinstance(det, str) else str(det)])
                    FW_TEXT.setdefault('asa:' + k, (s, 'Cisco ASA: ' + t, rec))
            else:
                noreview.append(base + [(d.get('config') or {}).get('error') or 'configuration not captured'])
        else:
            mon = d.get('monitoring') or {}
            denied = any('not allowed' in str(e) for e in d.get('security_errors') or [])
            if not mon.get('api') or denied:
                noreview.append(base + ['configuration read not allowed for the API key' if denied else 'no read-only API key: the rule base cannot be reviewed'])
        for l in d.get('licenses') or []:
            t = ms(l.get('expires')) if isinstance(l.get('expires'), str) else l.get('expires')
            if t and now and t < now:
                lic.append(base + [l.get('name') or '', day(t)])
        sa = ms(d.get('security_at'))
        if not sa or (now and now - sa > 2 * DAY):
            stale.append(base + [day(sa) if sa else 'never'])
    cols = ['Firewall', 'Vendor', 'Site', 'Role', 'IP', 'Rule / object', 'Condition', 'Evidence']
    for k, rows in g.items():
        sev, what, rec = FW_TEXT[k]
        names = sorted(set(r[0] for r in rows))
        F.append(_f('fw:' + k, sev, '%d %s (%s)' % (len(rows), what, ', '.join(names[:5])), ['firewalls: ' + ', '.join(names)], rec, cols, rows))
    if lic:
        F.append(_f('fw:subscription', 'high', '%d expired security subscription(s) / support on firewalls' % len(lic), [', '.join(sorted(set(r[0] for r in lic)))],
                    'Renew: an expired IPS / AV / URL subscription means that protection is no longer updated; expired support means no firmware or RMA.',
                    ['Firewall', 'Vendor', 'Site', 'Role', 'IP', 'Licence', 'Expired'], lic))
    if noreview:
        F.append(_f('fw:not-reviewed', 'medium', '%d firewall(s) whose rule base the auditor cannot review' % len(noreview), [', '.join(r[0] for r in noreview[:10])],
                    'Give a read-only API key with configuration read (FortiGate REST API admin / PAN-OS XML API role "Configuration" read) or the ASA SSH login, so the rule base is audited every day. A rule base not read is not audited.',
                    ['Firewall', 'Vendor', 'Site', 'Role', 'IP', 'Why'], noreview))
    if stale:
        F.append(_f('fw:checks-stale', 'low', '%d firewall(s) without a security check in the last 48 hours' % len(stale), [', '.join(r[0] for r in stale[:10])],
                    'Check the SIEM network poller and the device credentials (Network Engineer → Status).', ['Firewall', 'Vendor', 'Site', 'Role', 'IP', 'Last check'], stale))
    if not devs:
        scope.append('no firewall (FortiGate / Palo Alto / Cisco ASA) in the SIEM network inventory')
    return {'findings': F, 'checked': len(devs), 'scope': scope, 'vendors': sorted(set(d.get('vendor') for d in devs))}


# ---------------------------------------------------------------- databases and applications (their audit reports)
def _from_report_findings(prefix, items, label, cols_extra=None):
    g = {}
    for x in items:
        a = x.get('area') or 'Other'
        e = g.setdefault(a, {'sev': x.get('severity') or 'low', 'rows': []})
        if SEVN.get(x.get('severity'), 1) > SEVN.get(e['sev'], 1):
            e['sev'] = x.get('severity')
        e['rows'].append(x)
    return g


DB_REC = {
    'Coverage': 'Grant AUDIT_VIEWER to the platform\'s read-only account, or switch unified auditing on, so every database sends its audit trail (SAMA 3.3.14; NCA ECC 2-12).',
    'Audit configuration': 'Enable the unified audit policies SAMA / NCA expect (ORA_LOGON_FAILURES, ORA_SECURECONFIG, ORA_ACCOUNT_MGMT) and a trail cleanup / archive job (CIS Oracle 19c section 5).',
    'Audit tampering': 'Treat audit changes as an incident until each is matched to an approved change: who disabled or changed auditing, and why.',
    'Privileged use': 'Match each privileged action to an approved change or on-call ticket; use named DBA accounts, not SYS / SYSTEM (CIS Oracle 19c section 4; ISO A.8.2).',
    'Failed logons': 'Investigate repeated failures (password guessing or a broken application credential); lock unused accounts.',
    'Accounts': 'Match each account and privilege change to an access request (ISO A.5.18).',
}


def database(req):
    r = req.get('report') or {}
    F = []
    cols = ['Severity', 'Finding', 'Evidence', 'Recommendation']
    g = _from_report_findings('db', r.get('findings') or [], 'database')
    for area, e in g.items():
        F.append(_f('db:' + re.sub(r'[^a-z0-9]+', '-', area.lower()).strip('-'), e['sev'], '%s: %d finding(s) in the database audit' % (area, len(e['rows'])),
                    [x.get('title') for x in e['rows'][:4]], DB_REC.get(area, e['rows'][0].get('recommendation') or 'See the Database Audit page.'),
                    cols, [[x.get('severity'), x.get('title'), '; '.join(x.get('evidence') or []), x.get('recommendation')] for x in e['rows']]))
    scope = []
    if not r.get('posture'):
        scope.append('no database reported its audit configuration in the last 48 hours (the configuration checks did not run)')
        F.append(_f('db:no-posture', 'medium', 'The audit configuration of the databases could not be checked', ['no audit_config record from any database in 48 hours'],
                    'Let the platform connection read the audit configuration (Databases → Add database script grants AUDIT_VIEWER and SELECT on the audit views).'))
    if not (r.get('summary') or {}).get('events') and not (r.get('coverage') or []):
        scope.append('no database audit record in the period and no monitored database')
    return {'findings': F, 'checked': len(r.get('coverage') or []) or len(r.get('posture') or []), 'scope': scope, 'summary': r.get('summary') or {}}


APP_REC = {
    'Resilience': 'Remove single points of failure for critical applications, or record the accepted risk; keep the DR copy current (ISO A.8.14; SAMA BCM).',
    'Changes': 'Every change on an application server goes through a change plan approved by a different, named person, and is validated after it is applied (ISO A.8.32).',
    'Log coverage': 'Every server of an application sends its logs to the SIEM; a silent server is not monitored (ISO A.8.15; SAMA 3.3.14).',
    'Security activity': 'Investigate failed logons and account changes on application servers against access requests (ISO A.5.18).',
}


def applications(req):
    r = req.get('report') or {}
    apps = r.get('applications') or []
    cols = ['Application', 'Critical', 'Severity', 'Finding', 'Evidence', 'Recommendation']
    g, errors = {}, []
    for a in apps:
        ap = a.get('application') or {}
        if a.get('error'):
            errors.append([ap.get('name') or ap.get('key'), 'yes' if ap.get('critical') else 'no', a.get('error')])
            continue
        for x in a.get('findings') or []:
            sev = x.get('severity') or 'low'
            if sev == 'high' and not ap.get('critical') and x.get('area') == 'Resilience':
                sev = 'medium'   # a single server is a finding everywhere, high only for a critical application
            e = g.setdefault(x.get('area') or 'Other', {'sev': sev, 'rows': [], 'apps': []})
            if SEVN.get(sev, 1) > SEVN.get(e['sev'], 1):
                e['sev'] = sev
            if ap.get('name') not in e['apps']:
                e['apps'].append(ap.get('name'))
            e['rows'].append([ap.get('name'), 'yes' if ap.get('critical') else 'no', sev, x.get('title'), '; '.join(x.get('evidence') or []), x.get('recommendation')])
    F = []
    for area, e in g.items():
        F.append(_f('app:' + re.sub(r'[^a-z0-9]+', '-', area.lower()).strip('-'), e['sev'], '%s: %d finding(s) across %d application(s)' % (area, len(e['rows']), len(e['apps'])),
                    ['applications: ' + ', '.join(e['apps'][:10])], APP_REC.get(area, 'See Application Audit for each application.'), cols, e['rows']))
    scope = []
    if errors:
        scope.append('%d application(s) could not be audited: %s' % (len(errors), ', '.join(str(x[0]) for x in errors[:5])))
    if r.get('total', 0) > len(apps):
        scope.append('%d of %d applications audited (critical first)' % (len(apps), r.get('total')))
    return {'findings': F, 'checked': len(apps) - len(errors), 'scope': scope}



# ---------------------------------------------------------------- round 2: what a human IT auditor asks next
def leavers(req):
    now = req.get('now') or 0
    hs = [h for h in req.get('handovers') or [] if h.get('last_day') and h.get('state') != 'cancelled']
    users = (req.get('evidence') or {}).get('users') or []
    by = {}
    for u in users:
        for k in (u.get('sam'), (u.get('name') or '').strip()):
            if k:
                by.setdefault(k.lower(), u)
    cols = ['Leaver', 'Team', 'Last day', 'AD account', 'Enabled', 'Last logon', 'Privileged groups', 'Handover']
    still, used, notfound, scope = [], [], [], []
    for h in hs:
        end = ms(str(h['last_day'])[:10] + 'T23:59:59Z')
        if not end or end > now:
            continue
        u = by.get(str(h.get('leaver') or '').lower().split('@')[0].split('\\')[-1]) or by.get(str(h.get('leaver_name') or '').strip().lower())
        if not u:
            notfound.append(h.get('leaver_name') or h.get('leaver'))
            continue
        row = [h.get('leaver_name') or h.get('leaver'), h.get('team'), str(h['last_day'])[:10], u.get('sam'), 'no' if u.get('disabled') else 'yes', day(u.get('last_logon')), ' | '.join(u.get('privileged_groups') or []), h.get('state') or '']
        ll = ms(u.get('last_logon'))
        if ll and ll > end + DAY:
            used.append(row)
        elif not u.get('disabled') and now - end > DAY:
            still.append(row)
    F = []
    if used:
        F.append(_f('signed-in-after', 'critical', '%d leaver account(s) signed in after the last working day' % len(used), [', '.join(r[0] for r in used[:10])],
                    'Treat as a security incident until explained: disable the account, reset its credentials and review what it accessed after the last day (ISO A.6.5; SAMA 3.3.1).', cols, used))
    if still:
        F.append(_f('still-enabled', 'high' if any(r[6] for r in still) else 'medium', '%d leaver account(s) still enabled after the last working day' % len(still), [', '.join(r[0] for r in still[:10])],
                    'Disable the AD account on the last working day (the Staff Handover access checklist), then remove group memberships (ISO A.5.18; SAMA 3.3.1 / 3.3.5).', cols, still))
    if notfound:
        scope.append('%d leaver(s) not found in AD by user name (already deleted, or recorded under another name): %s' % (len(notfound), ', '.join(str(x) for x in notfound[:5])))
    return {'findings': F, 'checked': len(hs), 'scope': scope}


GENERIC = re.compile(r'^(test|temp|tmp|guest|user\d*|admin\d*|administrator\d+|training|trainee|demo|scan(ner)?|shared|generic|helpdesk|support|kiosk|reception|staff|it|ops)([-_.]?\d*)$', re.I)


def ad_generic(req):
    users = (req.get('evidence') or {}).get('users') or []
    F, scope = [], []
    if users and not any(u.get('rid') for u in users):
        scope.append('the SIEM did not send the account RIDs (update the SIEM): built-in Administrator / Guest not identified')
    g = [u for u in users if u.get('rid') == '501' and not u.get('disabled')]
    if g:
        F.append(_f('guest', 'high', 'the built-in Guest account is enabled', ['account ' + g[0].get('sam')], 'Disable the built-in Guest account (CIS Windows Server 2.3.1.2).', UCOLS, [_urow(u) for u in g]))
    a = [u for u in users if u.get('rid') == '500' and not u.get('disabled')]
    for u in a:
        if str(u.get('sam', '')).lower() == 'administrator':
            F.append(_f('builtin-admin-name', 'medium', 'the built-in Administrator account is enabled and still named "Administrator"', ['account ' + u.get('sam')],
                        'Rename the built-in Administrator (CIS 2.3.1.5), keep its password in the vault for break-glass use only, and use named admin accounts day to day.', UCOLS, [_urow(u)]))
        if u.get('last_logon') and (req.get('now') or 0) - (ms(u.get('last_logon')) or 0) < 30 * DAY:
            F.append(_f('builtin-admin-used', 'medium', 'the built-in Administrator account was used in the last 30 days (last logon %s)' % day(u.get('last_logon')), ['account ' + u.get('sam')],
                        'A shared built-in account cannot be attributed to a person (ISO A.5.16): use named admin accounts; record each break-glass use.', UCOLS, [_urow(u)]))
    gen = [u for u in users if not u.get('disabled') and not u.get('service_account') and u.get('rid') not in ('500', '501') and GENERIC.match(str(u.get('sam', '')))]
    if gen:
        F.append(_f('generic', 'medium', '%d enabled generic or shared account(s)' % len(gen), ['accounts: ' + _names(gen)],
                    'Every account belongs to one named person (ISO A.5.16; SAMA 3.3.5). Disable shared and test accounts, or record the owner and the business reason and review them quarterly.', UCOLS, [_urow(u) for u in gen]))
    mb = [u for u in users if u.get('privileged') and not u.get('disabled') and u.get('has_mail')]
    if mb:
        F.append(_f('admin-mailbox', 'medium', '%d privileged account(s) with a mailbox (used as an everyday account)' % len(mb), ['accounts: ' + _names(mb)],
                    'Give administrators a separate admin account without mail or internet use (Microsoft tiering; CIS): phishing an everyday account must not give domain admin.', UCOLS, [_urow(u) for u in mb]))
    return {'findings': F, 'checked': len(users), 'scope': scope}


APPLIED = ('applied', 'validated', 'validation-failed', 'executed', 'done')


def config_changes(req):
    now, days = req.get('now') or 0, int(req.get('days') or 90)
    cols = ['Device', 'Site', 'Changed between', 'and', 'New configuration (SHA-256)', 'Change plans on the device near that time']
    rows, devs, scope = [], 0, []
    for d in req.get('devices') or []:
        h = ((d.get('config') or {}).get('history')) or []
        if not h:
            continue
        devs += 1
        plans = d.get('changes') or []
        for x in h[1:]:
            seen, prev = ms(x.get('first_seen')), ms(x.get('previous_read'))
            if not seen or now - seen > days * DAY:
                continue
            lo, hi = (prev or seen - 2 * DAY) - 3600000, seen + 3600000
            ok = [c for c in plans if c.get('status') in APPLIED and ms(c.get('applied_at')) and lo <= ms(c.get('applied_at')) <= hi and c.get('decided_by')]
            if ok:
                continue
            near = [c for c in plans if ms(c.get('proposed_at')) and abs(ms(c.get('proposed_at')) - seen) < 7 * DAY]
            rows.append([d.get('name'), d.get('site'), day(prev) if prev else 'first read', day(seen), (x.get('sha256') or '')[:16] + '…',
                         '; '.join('%s %s (%s)' % (c.get('id'), c.get('status'), c.get('title')) for c in near[:3]) or 'none'])
    F = []
    if rows:
        F.append(_f('unauthorised', 'high', '%d configuration change(s) on %d device(s) with no approved, applied change plan' % (len(rows), len(set(r[0] for r in rows))),
                    ['devices: ' + ', '.join(sorted(set(r[0] for r in rows)))[:250]],
                    'Find who changed each device and why (device logs in the SIEM, AAA accounting). Raise a retrospective change for a legitimate emergency change; treat an unexplained change as a security incident (ISO A.8.32; SAMA 3.3.7).',
                    cols, rows))
    if not devs:
        scope.append('no device configuration has been captured twice yet (the daily capture needs at least two reads)')
    scope.append('FortiGate / Palo Alto configuration changes are not compared (no configuration capture for them yet)')
    return {'findings': F, 'checked': devs, 'scope': scope}


def m365_mfa(req):
    m = req.get('m365') or {}
    F, scope = [], []
    mfa, ca, ru = m.get('mfa'), m.get('conditional_access'), m.get('risky_users')
    cols = ['User', 'UPN', 'Admin role']
    if mfa is None:
        scope.append('MFA registration not read (Graph permission UserAuthenticationMethod.Read.All + AuditLog.Read.All)')
    else:
        nr = mfa.get('notRegistered') or []
        adm = [u for u in nr if u.get('admin')]
        if adm:
            F.append(_f('admin-no-mfa', 'critical', '%d administrator(s) without MFA registered' % len(adm), [', '.join(u.get('upn') or u.get('name') for u in adm[:10])],
                        'Register MFA for every administrator now and enforce it with Conditional Access (SAMA 3.3.5; NCA ECC 2-2-3; CIS Microsoft 365 1.1.1).', cols, [[u.get('name'), u.get('upn'), 'yes'] for u in adm]))
        users = mfa.get('users') or 0
        other = [u for u in nr if not u.get('admin')]
        if users and other and len(nr) * 100.0 / users > 2:
            F.append(_f('users-no-mfa', 'high' if len(nr) * 100.0 / users > 10 else 'medium', '%d of %d users (%d%%) without MFA registered' % (len(nr), users, round(len(nr) * 100.0 / users)),
                        [', '.join(u.get('upn') or '' for u in other[:10])], 'Run an MFA registration campaign and require MFA for all users with Conditional Access (CIS Microsoft 365 1.1.2).', cols, [[u.get('name'), u.get('upn'), 'no'] for u in other]))
    if ca is None:
        scope.append('Conditional Access not read (Graph permission Policy.Read.All)')
    else:
        on = [p for p in ca if p.get('state') == 'enabled']
        if not on:
            F.append(_f('no-ca', 'high', 'no Conditional Access policy is enabled (%d defined)' % len(ca), [', '.join('%s (%s)' % (p.get('name'), p.get('state')) for p in ca[:8]) or 'none defined'],
                        'Enable policies that require MFA for all users and admins and block legacy authentication (CIS Microsoft 365 5.2.x).', ['Policy', 'State', 'Modified'], [[p.get('name'), p.get('state'), day(p.get('modified'))] for p in ca]))
    if ru is None:
        scope.append('risky users not read (Graph permission IdentityRiskyUser.Read.All, Entra ID P2)')
    else:
        open_ = [u for u in ru if u.get('state') in ('atRisk', 'confirmedCompromised') and u.get('level') in ('high', 'medium')]
        if open_:
            F.append(_f('risky', 'high', '%d user(s) at medium / high sign-in risk not remediated' % len(open_), [', '.join(u.get('upn') for u in open_[:10])],
                        'Investigate each, reset the password and revoke sessions, then confirm safe or compromised in Entra ID Protection.', ['User', 'UPN', 'Level', 'State', 'Updated'],
                        [[u.get('name'), u.get('upn'), u.get('level'), u.get('state'), day(u.get('updated'))] for u in open_]))
    return {'findings': F, 'checked': (mfa or {}).get('users') or 0, 'scope': scope, 'not_read': mfa is None and ca is None}


def m365_accounts(req):
    m, now = req.get('m365') or {}, req.get('now') or 0
    users = m.get('users')
    if users is None:
        return {'findings': [], 'checked': 0, 'scope': ['Microsoft 365 users not read (Graph permission User.Read.All)'], 'not_read': True}
    scope = []
    if users and all(u.get('last') is None and 'last' not in u for u in users):
        return {'findings': [], 'checked': 0, 'scope': ['sign-in activity not read (AuditLog.Read.All and Entra ID P1 are needed for signInActivity)'], 'not_read': True}
    cols = ['Name', 'UPN', 'Guest', 'Licensed', 'Created', 'Last sign-in']
    stale = lambda u: (not u.get('last') and (now - (ms(u.get('created')) or now)) > 30 * DAY) or (u.get('last') and now - (ms(u.get('last')) or now) > 90 * DAY)
    g = [u for u in users if u.get('enabled') and u.get('guest') and stale(u)]
    mem = [u for u in users if u.get('enabled') and not u.get('guest') and u.get('licensed') and stale(u)]
    F = []
    row = lambda u: [u.get('name'), u.get('upn'), 'yes' if u.get('guest') else 'no', 'yes' if u.get('licensed') else 'no', day(u.get('created')), day(u.get('last'))]
    if g:
        F.append(_f('stale-guests', 'medium', '%d guest account(s) not signed in for 90 days (or never)' % len(g), [', '.join(u.get('upn') or '' for u in g[:8])],
                    'Remove guests nobody uses, and run an Entra access review for guests every quarter (ISO A.5.18; SAMA 3.4.1 third parties).', cols, [row(u) for u in g]))
    if mem:
        F.append(_f('stale-users', 'medium', '%d licensed user account(s) not signed in for 90 days' % len(mem), [', '.join(u.get('upn') or '' for u in mem[:8])],
                    'Confirm with HR: disable leavers and reclaim their licences; keep a record for long absences.', cols, [row(u) for u in mem]))
    return {'findings': F, 'checked': len(users), 'scope': scope}


def intune(req):
    m, now = req.get('m365') or {}, req.get('now') or 0
    d = m.get('intune')
    if d is None:
        return {'findings': [], 'checked': 0, 'scope': ['Intune devices not read (Graph permission DeviceManagementManagedDevices.Read.All)'], 'not_read': True}
    cols = ['Device', 'User', 'OS', 'Compliance', 'Last check-in']
    row = lambda x: [x.get('name'), x.get('upn'), x.get('os'), x.get('compliance'), day(x.get('last_sync'))]
    nc = [x for x in d if str(x.get('compliance', '')).lower() in ('noncompliant', 'ingraceperiod', 'error', 'conflict')]
    old = [x for x in d if x.get('last_sync') and now - (ms(x.get('last_sync')) or now) > 30 * DAY]
    F = []
    if nc:
        pct = round(len(nc) * 100.0 / max(1, len(d)))
        F.append(_f('noncompliant', 'high' if pct >= 10 else 'medium', '%d of %d devices (%d%%) not compliant with the Intune policy' % (len(nc), len(d), pct), [', '.join(x.get('name') or '' for x in nc[:10])],
                    'Fix the failing settings (encryption, OS version, defender, password) and block non-compliant devices from company data with Conditional Access (SAMA 3.3.10; NCA ECC 2-6).', cols, [row(x) for x in nc]))
    if old:
        F.append(_f('not-checking-in', 'low', '%d device(s) not checked in with Intune for 30 days' % len(old), [', '.join(x.get('name') or '' for x in old[:10])],
                    'Retire lost or replaced devices from Intune; a device that does not check in gets no policy or patches.', cols, [row(x) for x in old]))
    return {'findings': F, 'checked': len(d), 'scope': []}


def retention(req):
    p, now = req.get('platform') or {}, req.get('now') or 0
    r, need = p.get('retention_days'), p.get('required_retention_days') or 365
    cols = ['Setting', 'Value', 'Required']
    rows = [['SIEM event retention (days)', r, need], ['Archive (cold tier) retention (days)', p.get('archive_retention_days'), '-'], ['Oldest event kept', day(p.get('oldest_event')) if p.get('oldest_event') else 'not read', '-']]
    F, scope = [], []
    if r is None:
        return {'findings': [], 'checked': 0, 'scope': ['the SIEM retention setting was not read'], 'not_read': True}
    if r < need:
        F.append(_f('short', 'high', 'SIEM keeps events for %d days - %d days are required' % (r, need), ['retention_days = %d' % r],
                    'Raise retention_days (and storage) to the required period: SAMA 3.3.14 / NCA ECC 2-12 expect at least 12 months of security logs.', cols, rows))
    if p.get('oldest_error'):
        scope.append('the oldest stored event could not be read: ' + p['oldest_error'])
    elif p.get('oldest_event'):
        age = (now - (ms(p['oldest_event']) or now)) / DAY
        scope.append('oldest event kept is %d days old (%s) - a younger store is expected while the platform is less than %d days old' % (age, day(p['oldest_event']), need))
    return {'findings': F, 'checked': 1, 'scope': scope, 'rows': rows}


def dr(req):
    e = req.get('engineer') or {}
    if not e or e.get('not_connected') or not e.get('last_patrol'):
        return {'findings': [], 'checked': 0, 'scope': ['the AI Virtualization Administrator has not patrolled a virtualisation platform (no DR replication read)'], 'not_read': True}
    items = [x for x in req.get('items') or [] if str(x.get('kind', '')).startswith('dr-')]
    cols = ['Work item', 'Severity', 'Finding', 'Status', 'Since']
    F = []
    g = {}
    for x in items:
        k = 'rpo' if x.get('kind') in ('dr-rpo', 'dr-replication-stuck') else 'copy' if x.get('kind') in ('dr-no-remote', 'dr-no-schedule', 'dr-unprotected') else 'site'
        g.setdefault(k, []).append(x)
    T = {'rpo': ('DR replication behind its RPO or stuck', 'Restore replication (link, remote cluster), then take an out-of-band replicated snapshot and confirm it on the DR site (SAMA BCM; ISO A.8.14).'),
         'copy': ('workloads without a DR copy or schedule', 'Add the VMs to a protection domain with a remote site and a schedule that meets the RPO agreed with the business.'),
         'site': ('DR site / replication health problems', 'Fix the remote site connection or the split protection domain before the next failover is needed.')}
    for k, xs in g.items():
        sev = max((x.get('severity') or 'medium' for x in xs), key=lambda v: SEVN.get(v, 1))
        F.append(_f('dr-' + k, sev, '%d %s' % (len(xs), T[k][0]), [x.get('title') for x in xs[:4]], T[k][1], cols,
                    [[x.get('id'), x.get('severity'), x.get('title'), x.get('status'), day(x.get('first_seen') or x.get('detected_at'))] for x in xs]))
    return {'findings': F, 'checked': 1, 'scope': ['Oracle Data Guard / own replication lag is not part of this test (Replication & Data Guard page)']}


OPS = {
    'infra_audit.ad_privileged': ad_privileged,
    'infra_audit.ad_accounts': ad_accounts,
    'infra_audit.ad_policy': ad_policy,
    'infra_audit.switches': switches,
    'infra_audit.firewalls': firewalls,
    'infra_audit.database': database,
    'infra_audit.applications': applications,
    'infra_audit.leavers': leavers,
    'infra_audit.ad_generic': ad_generic,
    'infra_audit.config_changes': config_changes,
    'infra_audit.m365_mfa': m365_mfa,
    'infra_audit.m365_accounts': m365_accounts,
    'infra_audit.intune': intune,
    'infra_audit.retention': retention,
    'infra_audit.dr': dr,
}
