# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Baseline hardening scan (engine/hardening.js): every IT asset's security settings against its CIS benchmark, mapped to
SAMA CSF 3.3.8 (infrastructure security, secure configuration and hardening) and NCA ECC 2-3, plus the domain clause a
setting belongs to (identity 3.3.5 / ECC 2-2, logging 3.3.14 / ECC 2-12, cryptography 3.3.9 / ECC 2-8, vulnerability
3.3.17 / ECC 2-10, network 3.3.8 / ECC 2-5).

Facts come from read-only sources only:
  esxi      vSphere host properties read through vCenter / the host (virt-capacity.js hostHardening)
  nutanix   Prism cluster security configuration (virt-capacity.js ntxClient.hardening)
  windows   the SIEM agent's daily snapshot (secedit export, auditpol, fixed registry values, services, firewall, BitLocker,
            Defender) - SIEM GET /api/soc/hardening/snapshots
  unix      the platform's SSH read (inv-helper.py ssh_health, h_* commands) for Oracle Linux / Linux / Solaris
  ios       the Cisco running-config the SIEM captures (secrets already removed) - same checks as the AI auditors
  firewall  the SIEM network poller's security findings for FortiGate / Palo Alto / Cisco ASA

Each check answers pass / fail / not_checked. A setting that could not be read is NOT CHECKED, never passed. A failed
check carries the evidence, a fix and a rollback for a PERSON to run: nothing here changes a device.
The CIS reference is the benchmark section (title), not a recommendation number - numbers move between releases.

  {"op": "hardening.assess", "assets": [{id, name, ip, platform, kind, at, data}], "now", "max_age_days"}
      -> {assets[{id, name, ip, platform, kind, state, at, score, counts, checks[]}], summary}
  {"op": "hardening.script", "kind", "platform", "name", "checks": [{id, fix, rollback, title}]}  -> {script}
"""
import re

DAY = 86400000
W = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

SAMA_HARD = 'SAMA CSF 3.3.8 Infrastructure security (secure configuration and hardening)'
NCA_HARD = 'NCA ECC 2-3 Information system and processing facilities protection'
DOMAIN = {
    'iam': ('SAMA CSF 3.3.5 Identity and access management', 'NCA ECC 2-2 Identity and access management'),
    'log': ('SAMA CSF 3.3.14 Cybersecurity event management', 'NCA ECC 2-12 Cybersecurity event logs and monitoring'),
    'crypto': ('SAMA CSF 3.3.9 Cryptography', 'NCA ECC 2-8 Cryptography'),
    'vuln': ('SAMA CSF 3.3.17 Vulnerability management', 'NCA ECC 2-10 Vulnerabilities management'),
    'net': ('SAMA CSF 3.3.8 Infrastructure security (network)', 'NCA ECC 2-5 Network security management'),
    'malware': ('SAMA CSF 3.3.8 Infrastructure security (malware protection)', 'NCA ECC 2-3 Malware protection'),
    'hard': (SAMA_HARD, NCA_HARD),
}


def rnd(x):
    return int(x + 0.5)   # half up, as the page rounds (Python's round() is half-even)


def ms(v):
    if isinstance(v, (int, float)):
        return int(v)
    if not v:
        return None
    m = re.match(r'^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d))?)?', str(v))
    if not m:
        return None
    import calendar
    y, mo, d, h, mi, s = [int(x or 0) for x in m.groups()]
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) * 1000


def num(v):
    try:
        if v is None or v == '':
            return None
        return int(str(v).strip().split(',')[-1] if ',' in str(v) else float(str(v).strip()))
    except (ValueError, TypeError):
        return None


def P(evidence):
    return ('pass', evidence)


def F(evidence):
    return ('fail', evidence)


def N(why):
    return ('not_checked', why)


# ---------------------------------------------------------------------------------------------------------- Windows
def _ptype(d):
    t = ((d.get('os') or {}).get('product_type'))
    return {1: 'workstation', 2: 'dc', 3: 'server'}.get(t, 'server')


def _sec(d, k):
    sp = d.get('secpol')
    if not isinstance(sp, dict):
        return 'unread'
    return num(sp.get(k))


def _reg(d, k):
    r = d.get('reg')
    return num(r.get(k)) if isinstance(r, dict) else 'unread'


def _min(k, lim, label):
    def t(d):
        v = _sec(d, k)
        if v == 'unread':
            return N('the security policy (secedit) was not readable on this machine')
        if v is None:
            return N(label + ' is not in the exported policy')
        return P('%s = %s' % (label, v)) if v >= lim else F('%s = %s (needs %d or more)' % (label, v, lim))
    return t


def _regeq(k, want, default, label, ok_values=None):
    ok_values = ok_values or [want]

    def t(d):
        v = _reg(d, k)
        if v == 'unread':
            return N('registry values were not read')
        shown = v if v is not None else 'not set (Windows default %s)' % default
        eff = v if v is not None else default
        if eff is None:
            return F('%s is not set' % label)
        return P('%s = %s' % (label, shown)) if eff in ok_values else F('%s = %s (should be %s)' % (label, shown, want))
    return t


AUDIT = {   # subcategory GUID -> (name, needs) ; needs: 's' success, 'f' failure, 'sf' both (CIS Advanced Audit Policy)
    '{0CCE923F-69AE-11D9-BED3-505054503030}': ('Credential Validation', 'sf'),
    '{0CCE9237-69AE-11D9-BED3-505054503030}': ('Security Group Management', 's'),
    '{0CCE9235-69AE-11D9-BED3-505054503030}': ('User Account Management', 'sf'),
    '{0CCE9215-69AE-11D9-BED3-505054503030}': ('Logon', 'sf'),
    '{0CCE9216-69AE-11D9-BED3-505054503030}': ('Logoff', 's'),
    '{0CCE9217-69AE-11D9-BED3-505054503030}': ('Account Lockout', 'f'),
    '{0CCE921B-69AE-11D9-BED3-505054503030}': ('Special Logon', 's'),
    '{0CCE922B-69AE-11D9-BED3-505054503030}': ('Process Creation', 's'),
    '{0CCE922F-69AE-11D9-BED3-505054503030}': ('Audit Policy Change', 's'),
    '{0CCE9211-69AE-11D9-BED3-505054503030}': ('Security System Extension', 's'),
    '{0CCE9212-69AE-11D9-BED3-505054503030}': ('System Integrity', 'sf'),
    '{0CCE9228-69AE-11D9-BED3-505054503030}': ('Sensitive Privilege Use', 'sf'),
}
AUDIT_VAL = {'success and failure': 'sf', 'success': 's', 'failure': 'f', 'no auditing': ''}


def _audit(d):
    ap = d.get('auditpol')
    if not isinstance(ap, dict) or not ap:
        return N('auditpol could not be read (the agent runs as SYSTEM; check the agent log)')
    miss, unknown = [], []
    for g, (name, need) in AUDIT.items():
        raw = ap.get(g, ap.get(g.lower()))
        if raw is None:   # auditpol lists every subcategory: one missing from the read counts as not audited
            miss.append('%s (not listed)' % name)
            continue
        have = AUDIT_VAL.get(str(raw).strip().lower())
        if have is None:
            unknown.append(name)
            continue
        if any(c not in have for c in need):
            miss.append('%s (needs %s)' % (name, {'s': 'Success', 'f': 'Failure', 'sf': 'Success and Failure'}[need]))
    if unknown and not miss:
        return N('audit settings in a language the scan does not read: ' + ', '.join(unknown[:4]))
    return F('not audited: ' + '; '.join(miss)) if miss else P('the %d required audit subcategories are audited' % len(AUDIT))


def _fw(d):
    fw = d.get('firewall')
    if not isinstance(fw, list) or not fw:
        return N('Windows Firewall profiles were not read')
    off = [p.get('name') for p in fw if not p.get('enabled')]
    return F('profile(s) off: ' + ', '.join(off)) if off else P('Domain / Private / Public profiles on')


def _fw_in(d):
    fw = d.get('firewall')
    if not isinstance(fw, list) or not fw:
        return N('Windows Firewall profiles were not read')
    allow = [p.get('name') for p in fw if str(p.get('inbound')).lower() == 'allow']
    return F('inbound default Allow on: ' + ', '.join(allow)) if allow else P('inbound default Block (or not configured = Block)')


def _smb1(d):
    s = d.get('smb')
    if isinstance(s, dict):
        return F('SMBv1 server enabled') if s.get('smb1') else P('SMBv1 server disabled')
    v = _reg(d, 'SMB1Server')
    if v == 'unread':
        return N('SMB configuration not read')
    return F('SMB1 = 1') if v == 1 else P('SMB1 = %s' % ('not set' if v is None else v))


def _smb_sign(d):
    if _ptype(d) == 'workstation':
        v = _reg(d, 'SmbClientSigning')
        if v == 'unread':
            return N('registry values were not read')
        return P('SMB client signing required') if v == 1 else F('SMB client signing not required (RequireSecuritySignature = %s)' % ('not set' if v is None else v))
    s = d.get('smb')
    if isinstance(s, dict):
        return P('SMB server signing required') if s.get('signing_required') else F('SMB server signing not required')
    v = _reg(d, 'SmbServerSigning')
    if v == 'unread':
        return N('SMB configuration not read')
    return P('SMB server signing required') if v == 1 else F('SMB server signing not required')


def _rdp(d):
    deny = _reg(d, 'RdpDeny')
    if deny == 'unread':
        return N('registry values were not read')
    if deny == 1:
        return P('Remote Desktop is off')
    nla = _reg(d, 'RdpNla')
    return P('Remote Desktop requires Network Level Authentication') if nla == 1 else F('Remote Desktop is on without Network Level Authentication (UserAuthentication = %s)' % ('not set' if nla is None else nla))


def _tls(k, label):
    def t(d):
        v = _reg(d, k)
        if v == 'unread':
            return N('registry values were not read')
        if v == 0:
            return P('%s server disabled in SCHANNEL' % label)
        return F('%s server not disabled (SCHANNEL Enabled = %s)' % (label, 'not set - OS default may allow it' if v is None else v))
    return t


def _bitlocker(d):
    if _ptype(d) != 'workstation':
        return None   # not part of the server baseline
    b = d.get('bitlocker')
    if not isinstance(b, list):
        return N('BitLocker status not readable (no TPM / the WMI class is absent)')
    osd = [v for v in b if str(v.get('drive', '')).upper().startswith('C')]
    if not osd:
        return F('the system drive is not an encryptable volume')
    return P('system drive protected') if osd[0].get('protection') == 1 else F('system drive not protected by BitLocker')


def _defender(d):
    m = d.get('defender')
    if not isinstance(m, dict):
        return N('Microsoft Defender not present - confirm the endpoint protection product in use (EDR page)')
    bad = []
    if not m.get('realtime'):
        bad.append('real-time protection off')
    age = m.get('signature_age_days')
    if isinstance(age, int) and age > 2:
        bad.append('signatures %d days old' % age)
    return F('; '.join(bad)) if bad else P('real-time on, signatures %s day(s) old' % age)


def _svc_off(names, only=None, label=''):
    def t(d):
        if only and _ptype(d) not in only:
            return None
        sv = d.get('services')
        if not isinstance(sv, dict):
            return N('services were not read')
        on = ['%s (%s, %s)' % (n, sv[n].get('start'), sv[n].get('state')) for n in names if n in sv and (str(sv[n].get('start')).lower() == 'auto' or str(sv[n].get('state')).lower() == 'running')]
        return F('running or automatic: ' + ', '.join(on)) if on else P((label or ', '.join(names)) + ': disabled or not installed')
    return t


def _hotfix(d, now):
    h = d.get('last_hotfix')
    if not h:
        return N('installed updates not readable')
    t = ms(h)
    if not t or not now:
        return N('update date not readable')
    days = (now - t) // DAY
    return P('last update %s (%d days ago)' % (h, days)) if days <= 45 else F('last update %s - %d days ago (patch monthly; CIS / SAMA 3.3.17)' % (h, days))


def _admin_rename(d):
    sp = d.get('secpol')
    if not isinstance(sp, dict):
        return N('the security policy (secedit) was not readable')
    if _ptype(d) == 'dc':
        return None
    n = str(sp.get('NewAdministratorName') or '').strip('"')
    if not n:
        return N('the built-in administrator name is not in the exported policy')
    return F('built-in administrator still named "Administrator"') if n.lower() == 'administrator' else P('built-in administrator renamed')


def _guest(d):
    g = d.get('guest_enabled')
    if g is None:
        v = _sec(d, 'EnableGuestAccount')
        if v in ('unread', None):
            return N('guest account state not readable')
        return F('Guest account enabled') if v == 1 else P('Guest account disabled')
    return F('Guest account enabled') if g else P('Guest account disabled')


def _lockout(d):
    v = _sec(d, 'LockoutBadCount')
    if v == 'unread':
        return N('the security policy (secedit) was not readable')
    if v is None:
        return N('lockout threshold not in the exported policy')
    return P('lockout after %d attempts' % v) if 1 <= v <= 5 else F('lockout threshold = %d (%s)' % (v, 'never locks' if v == 0 else 'more than 5'))


def _maxage(d):
    v = _sec(d, 'MaximumPasswordAge')
    if v == 'unread':
        return N('the security policy (secedit) was not readable')
    if v is None:
        return N('maximum password age not in the exported policy')
    return P('passwords expire after %d days' % v) if 1 <= v <= 365 else F('maximum password age = %s' % ('never' if v in (0, -1) else v))


def _idle(d):
    v = _reg(d, 'InactivityTimeoutSecs')
    if v == 'unread':
        return N('registry values were not read')
    return P('screen locks after %d s' % v) if v and 0 < v <= 900 else F('machine inactivity limit = %s (should be 900 s or less)' % ('not set' if v is None else v))


def _seclog(d):
    v = _reg(d, 'SecurityLogMaxKB')
    if v == 'unread':
        return N('registry values were not read')
    if v is None:
        return F('Security log size not set (default 20 MB)')
    kb = v // 1024 if v > 4 * 1024 * 1024 else v
    return P('Security log %d KB' % kb) if kb >= 196608 else F('Security log %d KB (needs 196,608 KB or more)' % kb)


PS = 'PowerShell (elevated)'
WIN = [
    # id, title, sev, cis section, domain, test, fix, rollback
    ('WIN-PW-LEN', 'Minimum password length is 14 or more', 'high', 'Account Policies / Password Policy', 'iam', _min('MinimumPasswordLength', 14, 'MinimumPasswordLength'),
     'net accounts /minpwlen:14   # domain accounts: Default Domain Policy > Password Policy', 'net accounts /minpwlen:<previous value>'),
    ('WIN-PW-CPLX', 'Password complexity is required', 'high', 'Account Policies / Password Policy', 'iam',
     lambda d: N('the security policy (secedit) was not readable') if _sec(d, 'PasswordComplexity') == 'unread' else (P('PasswordComplexity = 1') if _sec(d, 'PasswordComplexity') == 1 else F('PasswordComplexity = %s' % _sec(d, 'PasswordComplexity'))),
     'Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > "Password must meet complexity requirements" = Enabled', 'Set the same policy back to Disabled'),
    ('WIN-PW-AGE', 'Passwords expire (365 days or less)', 'medium', 'Account Policies / Password Policy', 'iam', _maxage,
     'net accounts /maxpwage:365', 'net accounts /maxpwage:<previous value>'),
    ('WIN-PW-HIST', 'Password history is 24 or more', 'medium', 'Account Policies / Password Policy', 'iam', _min('PasswordHistorySize', 24, 'PasswordHistorySize'),
     'net accounts /uniquepw:24', 'net accounts /uniquepw:<previous value>'),
    ('WIN-PW-REV', 'Passwords are not stored with reversible encryption', 'critical', 'Account Policies / Password Policy', 'crypto',
     lambda d: N('the security policy (secedit) was not readable') if _sec(d, 'ClearTextPassword') == 'unread' else (F('ClearTextPassword = 1') if _sec(d, 'ClearTextPassword') == 1 else P('ClearTextPassword = %s' % _sec(d, 'ClearTextPassword'))),
     'Group Policy: Password Policy > "Store passwords using reversible encryption" = Disabled, then reset the affected passwords', 'Set the policy back to Enabled (not recommended)'),
    ('WIN-LOCK', 'Account lockout after 5 or fewer failed attempts', 'high', 'Account Policies / Account Lockout Policy', 'iam', _lockout,
     'net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15', 'net accounts /lockoutthreshold:<previous value>'),
    ('WIN-GUEST', 'Guest account is disabled', 'high', 'Local Policies / Security Options (Accounts)', 'iam', _guest,
     'Get-LocalUser -SID (Get-LocalUser | Where-Object SID -like "*-501").SID | Disable-LocalUser', 'Enable-LocalUser -Name Guest'),
    ('WIN-ADMIN-NAME', 'Built-in administrator account is renamed', 'low', 'Local Policies / Security Options (Accounts)', 'iam', _admin_rename,
     'Rename-LocalUser -Name Administrator -NewName <site standard name>', 'Rename-LocalUser -Name <new name> -NewName Administrator'),
    ('WIN-NTLM', 'LAN Manager authentication: NTLMv2 only, refuse LM and NTLM', 'high', 'Local Policies / Security Options (Network security)', 'crypto', _regeq('LmCompatibilityLevel', 5, 3, 'LmCompatibilityLevel'),
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord   # test legacy apps first',
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel -Value <previous value> -Type DWord'),
    ('WIN-NOLMHASH', 'LM hash is not stored', 'high', 'Local Policies / Security Options (Network security)', 'crypto', _regeq('NoLMHash', 1, 1, 'NoLMHash'),
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name NoLMHash -Value 1 -Type DWord', 'Remove-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name NoLMHash'),
    ('WIN-ANON', 'Anonymous enumeration of accounts and shares is refused', 'medium', 'Local Policies / Security Options (Network access)', 'iam', _regeq('RestrictAnonymous', 1, 0, 'RestrictAnonymous'),
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RestrictAnonymous -Value 1 -Type DWord', 'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RestrictAnonymous -Value 0 -Type DWord'),
    ('WIN-WDIGEST', 'WDigest does not keep clear-text credentials in memory', 'high', 'MS Security Guide (administrative templates)', 'crypto', _regeq('WDigestUseLogonCredential', 0, 0, 'UseLogonCredential'),
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential -Value 0 -Type DWord',
     'Remove-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential'),
    ('WIN-LSA-PPL', 'LSA runs as a protected process', 'medium', 'MS Security Guide (administrative templates)', 'crypto', _regeq('RunAsPPL', 1, 0, 'RunAsPPL', [1, 2]),
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -Value 1 -Type DWord   # reboot; check LSA plug-ins (audit mode first)',
     'Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -Value 0 -Type DWord   # reboot'),
    ('WIN-UAC', 'User Account Control is on', 'high', 'Local Policies / Security Options (User Account Control)', 'hard', _regeq('EnableLUA', 1, 1, 'EnableLUA'),
     'Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -Value 1 -Type DWord   # reboot',
     'Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -Value 0 -Type DWord'),
    ('WIN-IDLE', 'Machine locks after 15 minutes of inactivity', 'low', 'Local Policies / Security Options (Interactive logon)', 'iam', _idle,
     'Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name InactivityTimeoutSecs -Value 900 -Type DWord',
     'Remove-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name InactivityTimeoutSecs'),
    ('WIN-SMB1', 'SMBv1 is disabled', 'critical', 'MS Security Guide (administrative templates)', 'net', _smb1,
     'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force', 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force'),
    ('WIN-SMB-SIGN', 'SMB signing is required', 'medium', 'Local Policies / Security Options (Microsoft network server / client)', 'net', _smb_sign,
     'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; Set-SmbClientConfiguration -RequireSecuritySignature $true -Force',
     'Set-SmbServerConfiguration -RequireSecuritySignature $false -Force; Set-SmbClientConfiguration -RequireSecuritySignature $false -Force'),
    ('WIN-RDP-NLA', 'Remote Desktop requires Network Level Authentication', 'high', 'Administrative Templates / Remote Desktop Services', 'iam', _rdp,
     "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord",
     "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 0 -Type DWord"),
    ('WIN-LLMNR', 'LLMNR (multicast name resolution) is off', 'medium', 'Administrative Templates / Network / DNS Client', 'net', _regeq('LlmnrOff', 0, None, 'EnableMulticast'),
     "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord",
     "Remove-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast"),
    ('WIN-AUTORUN', 'AutoRun is off for all drives', 'medium', 'Administrative Templates / AutoPlay Policies', 'malware', _regeq('NoAutorun', 255, None, 'NoDriveTypeAutoRun'),
     'Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer -Name NoDriveTypeAutoRun -Value 255 -Type DWord',
     'Remove-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer -Name NoDriveTypeAutoRun'),
    ('WIN-TLS10', 'TLS 1.0 is disabled (server side)', 'medium', 'Cryptography (SCHANNEL protocols)', 'crypto', _tls('Tls10Server', 'TLS 1.0'),
     "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name Enabled -Value 0 -Type DWord   # reboot; check old clients",
     "Remove-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name Enabled   # reboot"),
    ('WIN-TLS11', 'TLS 1.1 is disabled (server side)', 'medium', 'Cryptography (SCHANNEL protocols)', 'crypto', _tls('Tls11Server', 'TLS 1.1'),
     "New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name Enabled -Value 0 -Type DWord   # reboot",
     "Remove-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name Enabled   # reboot"),
    ('WIN-FW', 'Windows Firewall is on for every profile', 'high', 'Windows Defender Firewall with Advanced Security', 'net', _fw,
     'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True', 'Set-NetFirewallProfile -Profile <profile> -Enabled False'),
    ('WIN-FW-IN', 'Windows Firewall blocks inbound by default', 'medium', 'Windows Defender Firewall with Advanced Security', 'net', _fw_in,
     'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block   # list the allow rules first: Get-NetFirewallRule -Direction Inbound -Enabled True',
     'Set-NetFirewallProfile -Profile <profile> -DefaultInboundAction Allow'),
    ('WIN-AUDIT', 'Advanced audit policy records the required events', 'high', 'Advanced Audit Policy Configuration', 'log', _audit,
     'auditpol /set /subcategory:"Credential Validation","User Account Management","Logon","System Integrity","Sensitive Privilege Use" /success:enable /failure:enable; auditpol /set /subcategory:"Security Group Management","Logoff","Special Logon","Process Creation","Audit Policy Change","Security System Extension" /success:enable; auditpol /set /subcategory:"Account Lockout" /failure:enable',
     'auditpol /restore /file:<backup taken first with: auditpol /backup /file:C:\\Temp\\auditpol.csv>'),
    ('WIN-SECLOG', 'Security event log is 196,608 KB or larger', 'medium', 'Administrative Templates / Event Log Service', 'log', _seclog,
     'wevtutil sl Security /ms:201326592', 'wevtutil sl Security /ms:<previous size in bytes>'),
    ('WIN-PSLOG', 'PowerShell script block logging is on', 'medium', 'Administrative Templates / Windows PowerShell', 'log', _regeq('ScriptBlockLogging', 1, None, 'EnableScriptBlockLogging'),
     "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord",
     "Remove-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging"),
    ('WIN-WINRM-ENC', 'WinRM refuses unencrypted traffic', 'medium', 'Administrative Templates / Windows Remote Management', 'crypto', _regeq('WinRMAllowUnencrypted', 0, 0, 'AllowUnencryptedTraffic'),
     "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service' -Name AllowUnencryptedTraffic -Value 0 -Type DWord",
     "Remove-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service' -Name AllowUnencryptedTraffic"),
    ('WIN-BITLOCKER', 'System drive is encrypted with BitLocker (workstations)', 'high', 'Administrative Templates / BitLocker Drive Encryption', 'crypto', _bitlocker,
     'Enable-BitLocker -MountPoint C: -TpmProtector -EncryptionMethod XtsAes256; Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector   # escrow the recovery key in AD / Entra first',
     'Disable-BitLocker -MountPoint C:'),
    ('WIN-DEFENDER', 'Anti-malware: real-time protection on, signatures current', 'high', 'Administrative Templates / Microsoft Defender Antivirus', 'malware', _defender,
     'Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature', 'Set-MpPreference -DisableRealtimeMonitoring $true   # only with another anti-malware product active'),
    ('WIN-SPOOLER-DC', 'Print Spooler is off on domain controllers', 'high', 'System Services', 'hard', _svc_off(['Spooler'], only=('dc',), label='Print Spooler'),
     'Stop-Service Spooler; Set-Service Spooler -StartupType Disabled', 'Set-Service Spooler -StartupType Automatic; Start-Service Spooler'),
    ('WIN-SVC', 'Unneeded services are off (Remote Registry, Telnet, SSDP, UPnP, Xbox)', 'medium', 'System Services', 'hard',
     _svc_off(['RemoteRegistry', 'TlntSvr', 'SSDPSRV', 'upnphost', 'XblGameSave']),
     "foreach ($s in 'RemoteRegistry','SSDPSRV','upnphost','XblGameSave') { if (Get-Service $s -ErrorAction SilentlyContinue) { Stop-Service $s -Force; Set-Service $s -StartupType Disabled } }",
     'Set-Service <service> -StartupType Manual'),
    ('WIN-PATCH', 'Security updates installed in the last 45 days', 'high', 'Vulnerability management', 'vuln', None,
     'Install the latest cumulative update (WSUS / Intune / Windows Update) and reboot in the maintenance window', 'Uninstall the update: wusa /uninstall /kb:<KB number>'),
]


# ------------------------------------------------------------------------------------------------------------- Unix
def _kv(text, sep=r'\s+'):
    out = {}
    for line in str(text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        p = re.split(sep, line, maxsplit=1)
        if len(p) == 2 and p[0] and p[0].lower() not in out:   # sshd: the first value wins
            out[p[0].lower()] = p[1].strip()
    return out


def _sshd(h):
    t = str(h.get('sshd') or '')
    return _kv(t) if t.strip() else None


def _ssh(key, ok, label, default=None):
    def t(h, plat):
        c = _sshd(h)
        if c is None:
            return N('sshd_config not readable by the monitoring login (0600 on recent releases) - grant read with a sudoers rule for "cat /etc/ssh/sshd_config" or run sshd -T')
        v = c.get(key.lower(), default)
        if v is None:
            return F('%s is not set' % label)
        return P('%s %s' % (label, v)) if ok(v) else F('%s %s' % (label, v))
    return t


def _ssh_ciphers(h, plat):
    c = _sshd(h)
    if c is None:
        return N('sshd_config not readable by the monitoring login')
    weak = [x for x in re.split(r'[,\s]+', c.get('ciphers', '') + ',' + c.get('macs', '')) if re.search(r'cbc|arcfour|3des|hmac-md5|hmac-sha1-96|umac-64', x, re.I)]
    if weak:
        return F('weak ciphers / MACs allowed: ' + ', '.join(weak[:6]))
    return P('no weak ciphers / MACs listed' + ('' if c.get('ciphers') else ' (OS defaults; on Oracle Linux 8+ the system crypto policy decides)'))


def _logindefs(key, ok, label):
    def t(h, plat):
        if plat == 'solaris':
            return None
        kv = _kv(h.get('logindefs'))
        if not kv:
            return N('/etc/login.defs not readable')
        v = num(kv.get(key.lower()))
        if v is None:
            return F('%s not set' % label)
        return P('%s %s' % (label, v)) if ok(v) else F('%s %s' % (label, v))
    return t


def _pwq(h, plat):
    if plat == 'solaris':
        kv = _kv(h.get('solaris'), sep='=')
        v = num(kv.get('passlength'))
        if v is None:
            return N('/etc/default/passwd PASSLENGTH not readable')
        return P('PASSLENGTH=%d' % v) if v >= 14 else F('PASSLENGTH=%d (needs 14)' % v)
    kv = _kv(h.get('pwquality'), sep=r'\s*=\s*')
    if not kv:
        return F('pwquality.conf has no settings (minlen defaults to 9)') if str(h.get('logindefs') or '').strip() else N('pwquality.conf not readable')
    v = num(kv.get('minlen'))
    return P('minlen = %d' % v) if v and v >= 14 else F('minlen = %s (needs 14)' % (v if v is not None else 'default 9'))


def _faillock(h, plat):
    if plat == 'solaris':
        kv = _kv(h.get('solaris'), sep='=')
        lk, rt = kv.get('lock_after_retries'), num(kv.get('retries'))
        if lk is None and rt is None:
            return N('/etc/security/policy.conf not readable')
        return P('LOCK_AFTER_RETRIES=YES, RETRIES=%s' % rt) if str(lk).upper() == 'YES' and (rt or 5) <= 5 else F('LOCK_AFTER_RETRIES=%s RETRIES=%s' % (lk, rt))
    t = str(h.get('faillock') or '')
    if not t.strip():
        return F('pam_faillock not configured (no lockout after failed logins)')
    m = re.search(r'deny\s*=\s*(\d+)', t)
    d = int(m.group(1)) if m else 3   # faillock default deny = 3
    return P('faillock deny = %d' % d) if 1 <= d <= 5 else F('faillock deny = %d' % d)


SYSCTL = [('net.ipv4.ip_forward', '0'), ('net.ipv4.conf.all.accept_redirects', '0'), ('net.ipv4.conf.all.send_redirects', '0'),
          ('net.ipv4.conf.all.accept_source_route', '0'), ('net.ipv4.tcp_syncookies', '1'), ('kernel.randomize_va_space', '2')]


def _sysctl(h, plat):
    if plat == 'solaris':
        r = str(h.get('solaris') or '')
        if 'forwarding' not in r:
            return N('routeadm not readable')
        bad = [l.strip() for l in r.splitlines() if 'forwarding' in l and re.search(r'current=enabled|persistent=enabled', l)]
        return F('IP forwarding enabled: ' + '; '.join(bad[:2])) if bad else P('IP forwarding disabled')
    kv = _kv(h.get('sysctl'), sep=r'\s*=\s*')
    if not kv:
        return N('sysctl not readable')
    bad = ['%s = %s (should be %s)' % (k, kv[k], v) for k, v in SYSCTL if k in kv and kv[k] != v]
    return F('; '.join(bad)) if bad else P('network and kernel parameters as CIS (%d checked)' % len([k for k, _ in SYSCTL if k in kv]))


def _selinux(h, plat):
    if plat == 'solaris':
        return None
    v = str(h.get('selinux') or '').strip()
    if not v:
        return N('getenforce not available')
    return P('SELinux Enforcing') if v.lower() == 'enforcing' else F('SELinux ' + v)


def _ufw(h, plat):
    t = str(h.get('firewall') or '')
    if not t.strip():
        return N('firewall state not readable')
    if plat == 'solaris':
        return P('IP Filter online') if re.search(r'ipfilter online', t) else F('IP Filter not online')
    return P('host firewall active') if re.search(r'^active$', t, re.M) else F('no host firewall active (firewalld / nftables / iptables)')


def _auditd(h, plat):
    t = str(h.get('auditd') or '')
    if not t.strip():
        return N('audit service state not readable')
    return P('audit service running') if re.search(r'^(active|auditd online)$', t, re.M) else F('audit service not running: ' + t.strip().splitlines()[0][:60])


BAD_SVC = ('telnet', 'rsh', 'rlogin', 'rexec', 'tftp', 'xinetd', 'vsftpd', 'finger', 'shell')


def _usvc(h, plat):
    t = str(h.get('services') or '')
    if not t.strip():
        return N('service list not readable')
    on = []
    for l in t.splitlines():
        p = l.split()
        if len(p) >= 2 and p[1] in ('enabled', 'static') and any(b in p[0] for b in BAD_SVC):
            on.append(p[0])
        elif len(p) >= 2 and p[0] == 'online' and any(b in p[1] for b in BAD_SVC + ('ftp',)):
            on.append(p[1])
    return F('legacy clear-text services enabled: ' + ', '.join(on)) if on else P('no telnet / rsh / rlogin / tftp / ftp services enabled')


def _uid0(h, plat):
    t = [x.strip() for x in str(h.get('uid0') or '').splitlines() if x.strip()]
    if not t:
        return N('/etc/passwd not readable')
    extra = [x for x in t if x != 'root']
    return F('accounts with UID 0 besides root: ' + ', '.join(extra)) if extra else P('only root has UID 0')


def _perms(h, plat):
    t = str(h.get('perms') or '')
    if not t.strip():
        return N('file modes not readable')
    bad = []
    for l in t.splitlines():
        p = l.split()
        if len(p) < 9:
            continue
        mode, f = p[0], p[-1]
        if f.endswith('shadow') and (mode[7] != '-' or mode[8] != '-' or mode[9] != '-'):
            bad.append('%s %s (others may read)' % (f, mode))
        if f in ('/etc/passwd', '/etc/group') and (mode[5] == 'w' or mode[8] == 'w'):
            bad.append('%s %s (writable by group / others)' % (f, mode))
    return F('; '.join(bad)) if bad else P('/etc/passwd, /etc/shadow, /etc/group modes as CIS')


def _tmp(h, plat):
    t = str(h.get('tmp') or '').strip()
    if not t:
        return F('/tmp is not a separate filesystem') if plat != 'solaris' else N('/tmp mount not readable')
    miss = [o for o in ('nodev', 'nosuid', 'noexec') if o not in t] if plat != 'solaris' else [o for o in ('nosuid',) if o not in t]
    return F('/tmp mounted without ' + ', '.join(miss)) if miss else P('/tmp mounted ' + ','.join(o for o in ('nodev', 'nosuid', 'noexec') if o in t))


def _syslog(h, plat):
    t = str(h.get('rsyslog') or '')
    if not t.strip():
        return N('syslog configuration not readable')
    if not re.search(r'@', t):
        return F('logs are not forwarded to a remote collector (SIEM)')
    return P('logs forwarded: ' + [l for l in t.splitlines() if '@' in l][0].strip()[:80])


def _updates(h, plat):
    t = str(h.get('updates') or '').strip()
    if not t or t == 'na':
        return N('no package manager security advisory list on this host (Solaris: check pkg update -n)')
    n = num(t)
    if n is None:
        return N('security advisory list not readable')
    return P('no pending security advisories (local cache)') if n == 0 else F('%d pending security advisories (from the local dnf cache - run dnf updateinfo to refresh)' % n)


def _sol_console(h, plat):
    if plat != 'solaris':
        return None
    kv = _kv(h.get('solaris'), sep='=')
    if 'console' not in kv:
        return F('CONSOLE not set in /etc/default/login (root may log in remotely)') if str(h.get('solaris') or '').strip() else N('/etc/default/login not readable')
    return P('root login restricted to the console') if kv.get('console') == '/dev/console' else F('CONSOLE=%s' % kv.get('console'))


UX = [
    ('UX-SSH-ROOT', 'SSH: root cannot log in directly', 'high', 'SSH Server Configuration', 'iam', _ssh('PermitRootLogin', lambda v: v.lower() == 'no', 'PermitRootLogin', 'prohibit-password'),
     "sed -i.bak 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd   # Solaris: svcadm refresh ssh",
     'cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && systemctl reload sshd'),
    ('UX-SSH-EMPTY', 'SSH: empty passwords refused', 'high', 'SSH Server Configuration', 'iam', _ssh('PermitEmptyPasswords', lambda v: v.lower() == 'no', 'PermitEmptyPasswords', 'no'),
     "echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config && sshd -t && systemctl reload sshd", 'remove the line from /etc/ssh/sshd_config and reload sshd'),
    ('UX-SSH-TRIES', 'SSH: 4 or fewer authentication attempts', 'medium', 'SSH Server Configuration', 'iam', _ssh('MaxAuthTries', lambda v: (num(v) or 99) <= 4, 'MaxAuthTries', '6'),
     "sed -i.bak 's/^#\\?MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd", 'cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && systemctl reload sshd'),
    ('UX-SSH-X11', 'SSH: X11 forwarding off', 'low', 'SSH Server Configuration', 'hard', _ssh('X11Forwarding', lambda v: v.lower() == 'no', 'X11Forwarding', 'no'),
     "sed -i.bak 's/^#\\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd", 'cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && systemctl reload sshd'),
    ('UX-SSH-IDLE', 'SSH: idle sessions end within 15 minutes', 'medium', 'SSH Server Configuration', 'iam', _ssh('ClientAliveInterval', lambda v: 0 < (num(v) or 0) <= 900, 'ClientAliveInterval', '0'),
     "printf 'ClientAliveInterval 300\\nClientAliveCountMax 3\\n' >> /etc/ssh/sshd_config && sshd -t && systemctl reload sshd", 'remove the two lines from /etc/ssh/sshd_config and reload sshd'),
    ('UX-SSH-CRYPTO', 'SSH: no weak ciphers or MACs', 'medium', 'SSH Server Configuration', 'crypto', _ssh_ciphers,
     'update-crypto-policies --set DEFAULT   # Oracle Linux 8+; or list strong Ciphers / MACs in sshd_config, then sshd -t && systemctl reload sshd',
     'update-crypto-policies --set <previous policy>'),
    ('UX-PASS-MAX', 'Passwords expire within 365 days', 'medium', 'User Accounts and Environment', 'iam', _logindefs('PASS_MAX_DAYS', lambda v: 0 < v <= 365, 'PASS_MAX_DAYS'),
     "sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs   # existing accounts: chage --maxdays 365 <user>", 'cp /etc/login.defs.bak /etc/login.defs'),
    ('UX-PASS-MIN', 'Minimum days between password changes is 1 or more', 'low', 'User Accounts and Environment', 'iam', _logindefs('PASS_MIN_DAYS', lambda v: v >= 1, 'PASS_MIN_DAYS'),
     "sed -i.bak 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs", 'cp /etc/login.defs.bak /etc/login.defs'),
    ('UX-PASS-LEN', 'Minimum password length is 14', 'high', 'PAM / password quality', 'iam', _pwq,
     "echo 'minlen = 14' >> /etc/security/pwquality.conf   # Solaris: PASSLENGTH=14 in /etc/default/passwd", 'remove the line again'),
    ('UX-LOCKOUT', 'Accounts lock after 5 or fewer failed logins', 'high', 'PAM / account lockout', 'iam', _faillock,
     "authselect enable-feature with-faillock && printf 'deny = 5\\nunlock_time = 900\\n' >> /etc/security/faillock.conf   # Solaris: LOCK_AFTER_RETRIES=YES in policy.conf",
     'authselect disable-feature with-faillock'),
    ('UX-SYSCTL', 'Network and kernel parameters as CIS', 'medium', 'Network Configuration / kernel parameters', 'net', _sysctl,
     "printf 'net.ipv4.conf.all.accept_redirects = 0\\nnet.ipv4.conf.all.send_redirects = 0\\nnet.ipv4.conf.all.accept_source_route = 0\\nnet.ipv4.tcp_syncookies = 1\\nkernel.randomize_va_space = 2\\n' > /etc/sysctl.d/60-cis.conf && sysctl --system   # ip_forward only where the host is not a router",
     'rm /etc/sysctl.d/60-cis.conf && sysctl --system'),
    ('UX-SELINUX', 'SELinux is enforcing', 'high', 'Mandatory Access Control', 'hard', _selinux,
     "sed -i.bak 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && setenforce 1   # run permissive first and review audit2why", "setenforce 0 && cp /etc/selinux/config.bak /etc/selinux/config"),
    ('UX-FIREWALL', 'Host firewall is active', 'high', 'Host Based Firewall', 'net', _ufw,
     'systemctl enable --now firewalld   # Solaris: svcadm enable network/ipfilter (rules in /etc/ipf/ipf.conf first)', 'systemctl disable --now firewalld'),
    ('UX-AUDITD', 'Audit daemon is running', 'high', 'Logging and Auditing (auditd)', 'log', _auditd,
     'systemctl enable --now auditd   # Solaris: audit -s', 'systemctl disable --now auditd'),
    ('UX-SYSLOG', 'Logs are forwarded to the SIEM', 'high', 'Logging and Auditing (rsyslog)', 'log', _syslog,
     "echo '*.* @@<SIEM collector>:514' > /etc/rsyslog.d/90-siem.conf && systemctl restart rsyslog", 'rm /etc/rsyslog.d/90-siem.conf && systemctl restart rsyslog'),
    ('UX-SERVICES', 'No legacy clear-text services (telnet, rsh, rlogin, tftp, ftp)', 'high', 'Services', 'hard', _usvc,
     'systemctl disable --now telnet.socket rsh.socket rlogin.socket rexec.socket tftp.socket vsftpd xinetd   # Solaris: svcadm disable telnet ftp rlogin shell finger',
     'systemctl enable --now <service>'),
    ('UX-UID0', 'Only root has UID 0', 'critical', 'User Accounts and Environment', 'iam', _uid0,
     'usermod -u <new uid> <account>   # or remove the account after review', 'usermod -u 0 <account>'),
    ('UX-PERMS', 'Account files have restricted permissions', 'high', 'System File Permissions', 'hard', _perms,
     'chmod 644 /etc/passwd /etc/group; chmod 000 /etc/shadow /etc/gshadow   # Solaris: chmod 400 /etc/shadow', 'chmod <previous mode> <file>'),
    ('UX-TMP', '/tmp is a separate filesystem mounted nodev,nosuid,noexec', 'low', 'Filesystem Configuration', 'hard', _tmp,
     'systemctl unmask tmp.mount && systemctl enable --now tmp.mount   # then add nodev,nosuid,noexec to its options', 'systemctl disable --now tmp.mount'),
    ('UX-UPDATES', 'No pending security updates', 'high', 'Initial Setup / software updates', 'vuln', _updates,
     'dnf -y update --security   # in the maintenance window; Solaris: pkg update', 'dnf history undo <transaction id>'),
    ('UX-SOL-CONSOLE', 'Solaris: root may log in on the console only', 'high', 'Solaris 11 / user access', 'iam', _sol_console,
     "sed -i.bak 's|^#\\?CONSOLE=.*|CONSOLE=/dev/console|' /etc/default/login", 'cp /etc/default/login.bak /etc/default/login'),
]


# ---------------------------------------------------------------------------------------------- network devices
IOS_KEYS = [   # ios_checks keys (infra_audit_rules) -> title, severity, domain
    ('password-encryption', 'Passwords in the configuration are encrypted', 'medium', 'crypto'),
    ('enable-password', 'No reversible "enable password"', 'high', 'crypto'),
    ('enable-secret', 'An enable secret with a strong hash is configured', 'high', 'crypto'),
    ('local-user-weak', 'Local users use strong password hashes', 'high', 'iam'),
    ('aaa', 'AAA with central authentication (TACACS+ / RADIUS)', 'medium', 'iam'),
    ('ssh-v2', 'SSH version 2 is enforced', 'medium', 'crypto'),
    ('vty-telnet', 'VTY lines accept SSH only (no Telnet)', 'high', 'crypto'),
    ('vty-acl', 'VTY lines limited by an access-class', 'medium', 'net'),
    ('vty-timeout', 'Idle management sessions time out (10 min)', 'medium', 'iam'),
    ('http-server', 'HTTP management server is off', 'medium', 'hard'),
    ('snmp-rw', 'No SNMP read-write community', 'high', 'net'),
    ('snmp-acl', 'SNMP communities limited by an ACL', 'medium', 'net'),
    ('logging', 'Logs are sent to the SIEM', 'medium', 'log'),
    ('timestamps', 'Log messages carry date and time', 'low', 'log'),
    ('ntp', 'NTP is configured', 'medium', 'log'),
    ('banner', 'Login banner is set', 'low', 'hard'),
    ('source-route', 'IP source routing is disabled', 'low', 'net'),
]

FW_KEYS = [   # firewall security finding kinds (SIEM network poller) -> title, severity, domain, fix
    ('any-any', 'No allow rule from any source to any destination on any service', 'high', 'net', 'Replace each any-any rule with specific sources, destinations and services (check the hit count first)'),
    ('internet-any', 'The internet cannot reach any internal address', 'high', 'net', 'Limit inbound rules to the published servers (VIP / NAT) and their services'),
    ('no-log', 'Every allow rule logs traffic', 'medium', 'log', 'Enable logging on every allow rule and forward it to the SIEM'),
    ('mgmt-clear', 'No management over Telnet / HTTP', 'high', 'crypto', 'Disable Telnet and HTTP administration; SSH and HTTPS from the management network only'),
    ('mgmt-wan', 'No administration on internet-facing interfaces', 'medium', 'net', 'Remove HTTPS / SSH administration from WAN interfaces'),
    ('admin-anywhere', 'Administrators limited to trusted hosts', 'medium', 'iam', 'Set trusted hosts for every administrator (management subnet / jump host)'),
    ('default-admin', 'Default "admin" account removed or renamed', 'low', 'iam', 'Use named administrators and disable or rename the default account'),
    ('snmp', 'SNMPv3 with privacy for monitoring', 'medium', 'crypto', 'Monitor with SNMPv3 authPriv (SHA / AES)'),
]
FW_KIND = {
    'fw-any-any': 'any-any', 'pa-any-any': 'any-any', 'fw-internet-any': 'internet-any', 'fw-nolog': 'no-log', 'pa-nolog': 'no-log',
    'mgmt-telnet': 'mgmt-clear', 'mgmt-http': 'mgmt-clear', 'pa-mgmt-telnet': 'mgmt-clear', 'pa-mgmt-http': 'mgmt-clear', 'telnet-open': 'mgmt-clear', 'http-open': 'mgmt-clear',
    'mgmt-wan': 'mgmt-wan', 'fw-admin-anywhere': 'admin-anywhere', 'fw-default-admin': 'default-admin', 'snmp-v2c': 'snmp', 'snmp-nopriv': 'snmp',
}


# ------------------------------------------------------------------------------------------------ Palo Alto (PAN-OS)
# Facts: the SIEM's read-only PAN-OS configuration read (netops/fwfacts.js: type=config&action=show on fixed xpaths,
# "show system info", "show counter global"), kept beside the security findings. A section the API key may not read is null.
def _pa(f, sec):
    return f.get(sec) if isinstance(f.get(sec), dict) or isinstance(f.get(sec), list) else None


def _pa_nc(f, sec):
    why = next((u.get('reason') for u in f.get('unread') or [] if u.get('section') == sec), None)
    return N('%s not read%s' % (sec, (' - ' + why) if why else ' (API key without Configuration read, or no security run yet)'))


def _pa_sys(key, ok, pass_msg, fail_msg):
    def t(f):
        s = _pa(f, 'system')
        if s is None:
            return _pa_nc(f, 'system')
        v = s.get(key)
        return P(pass_msg(v)) if ok(v) else F(fail_msg(v))
    return t


def _pa_version(f):
    i = _pa(f, 'info')
    v = str((i or {}).get('version') or '')
    m = re.match(r'^(\d+)\.(\d+)', v)
    if not m:
        return _pa_nc(f, 'info') if i is None else N('PAN-OS version not reported')
    mm = (int(m.group(1)), int(m.group(2)))
    return P('PAN-OS %s - check it is on the latest preferred maintenance release' % v) if mm >= (10, 2) else F('PAN-OS %s is past its end of life - upgrade to a supported release (10.2 / 11.x)' % v)


def _pa_mgmt(f):
    m = _pa(f, 'management')
    if m is None:
        return _pa_nc(f, 'management')
    t = m.get('idle_timeout') or 60
    return P('administrator idle time-out %d min' % t) if t <= 10 else F('administrator idle time-out %d min (CIS: 10 or less)%s' % (t, '' if m.get('idle_timeout') else ' - the PAN-OS default'))


def _pa_lockout(f):
    m = _pa(f, 'management')
    if m is None:
        return _pa_nc(f, 'management')
    a, t = m.get('lockout_attempts'), m.get('lockout_time')
    if not a:
        return F('no administrator lockout after failed logins')
    return P('locked for %s min after %d failed logins' % (t, a)) if a <= 5 and (t or 0) >= 15 else F('lockout after %s failed logins for %s min (CIS: 5 or fewer, 15 min or more)' % (a, t))


def _pa_pwd(f):
    p = _pa(f, 'password')
    if p is None:
        return _pa_nc(f, 'password')
    if not p.get('enabled'):
        return F('password complexity is not enabled for local administrators')
    n = p.get('min_length') or 0
    return P('password complexity on, minimum %d characters' % n) if n >= 12 else F('password complexity on but minimum length %d (CIS: 12 or more)' % n)


def _pa_updates(f):
    s = _pa(f, 'system')
    if s is None:
        return _pa_nc(f, 'system')
    u = s.get('updates') or {}
    bad = [k for k in ('threats', 'anti-virus', 'wildfire') if not u.get(k) or u[k].get('action') != 'download-and-install']
    return F('not scheduled to download AND install: ' + ', '.join(bad)) if bad else P('threats, anti-virus and WildFire updates download and install on a schedule')


UNTRUST = re.compile(r'untrust|internet|outside|wan|isp|external|dmz', re.I)


def _pa_zpp(f):
    z = _pa(f, 'zones')
    if z is None:
        return _pa_nc(f, 'zones')
    ext = [x for x in z if UNTRUST.search(x.get('name') or '')]
    if not ext:
        return N('no internet-facing zone recognised by name (untrust / internet / outside / wan / dmz)')
    bad = [x['name'] for x in ext if not x.get('zpp')]
    return F('internet-facing zones without a Zone Protection profile: ' + ', '.join(bad)) if bad else P('Zone Protection on ' + ', '.join(x['name'] for x in ext))


def _pa_rules(pred, fail_msg, pass_msg):
    def t(f):
        r = _pa(f, 'rules')
        if r is None:
            return _pa_nc(f, 'rules')
        bad = [x['name'] for x in r.get('items') or [] if not x.get('disabled') and x.get('action') == 'allow' and pred(x)]
        return F('%s: %d (%s)' % (fail_msg, len(bad), ', '.join(bad[:8]))) if bad else P(pass_msg)
    return t


def _anyof(x, k):
    return 'any' in (x.get(k) or [])


def _pa_session(key, want, label):
    def t(f):
        s = _pa(f, 'session')
        if s is None:
            return _pa_nc(f, 'session')
        return P('%s = %s' % (label, s.get(key))) if s.get(key) == want else F('%s = %s (CIS: %s)' % (label, s.get(key), want))
    return t


PA = [
    ('PA-VERSION', 'PAN-OS is a supported release', 'critical', 'Device setup / software', 'vuln', _pa_version,
     'request system software check; request system software download version <release>; request system software install version <release>   # HA: passive peer first', 'request system software install version <previous>; request restart system'),
    ('PA-BANNER', 'A login banner is set', 'low', 'Device setup / management', 'hard', _pa_sys('banner', lambda v: v, lambda v: 'login banner set', lambda v: 'no login banner'),
     'set deviceconfig system login-banner "Authorised use only. Activity is monitored and recorded."', 'delete deviceconfig system login-banner'),
    ('PA-NTP', 'Two NTP servers are configured', 'low', 'Device setup / services', 'log', _pa_sys('ntp', lambda v: len(v or []) >= 2, lambda v: 'NTP: ' + ', '.join(v), lambda v: '%d NTP server(s) configured (CIS: 2)' % len(v or [])),
     'set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <ntp1>; set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address <ntp2>', 'delete deviceconfig system ntp-servers secondary-ntp-server'),
    ('PA-PERMITIP', 'Management access is limited to permitted IP addresses', 'high', 'Device setup / management', 'net', _pa_sys('permitted_ip', lambda v: (v or 0) > 0, lambda v: '%d permitted address range(s)' % v, lambda v: 'the management interface accepts logins from any address'),
     'set deviceconfig system permitted-ip <management-subnet>   # add the jump hosts / management network first', 'delete deviceconfig system permitted-ip <management-subnet>'),
    ('PA-TELNET', 'Telnet is disabled on the management interface', 'high', 'Device setup / management', 'crypto', _pa_sys('telnet_off', lambda v: v is not False, lambda v: 'Telnet disabled' + (' (default)' if v is None else ''), lambda v: 'Telnet enabled on the management interface'),
     'set deviceconfig system service disable-telnet yes', 'set deviceconfig system service disable-telnet no'),
    ('PA-HTTP', 'HTTP is disabled on the management interface', 'high', 'Device setup / management', 'crypto', _pa_sys('http_off', lambda v: v is not False, lambda v: 'HTTP disabled' + (' (default)' if v is None else ''), lambda v: 'HTTP enabled on the management interface'),
     'set deviceconfig system service disable-http yes', 'set deviceconfig system service disable-http no'),
    ('PA-SNMP', 'SNMP uses v3', 'medium', 'Device setup / services', 'crypto', _pa_sys('snmp', lambda v: v != 'v2c', lambda v: 'SNMP %s' % (v or 'not configured'), lambda v: 'SNMP v2c (community in clear text)'),
     'set deviceconfig system snmp-setting access-setting version v3 users <user> authpwd <auth> privpwd <priv> view <view>   # then delete the v2c community', 'set deviceconfig system snmp-setting access-setting version v2c snmp-community-string <community>'),
    ('PA-IDLE', 'Administrator sessions time out after 10 minutes', 'medium', 'Device setup / management', 'iam', _pa_mgmt,
     'set deviceconfig setting management idle-timeout 10', 'set deviceconfig setting management idle-timeout 60'),
    ('PA-LOCKOUT', 'Administrators are locked out after failed logins', 'high', 'Device setup / management', 'iam', _pa_lockout,
     'set deviceconfig setting management admin-lockout failed-attempts 5 lockout-time 15', 'delete deviceconfig setting management admin-lockout'),
    ('PA-PWD', 'Local administrator password complexity (12 characters)', 'high', 'Device setup / authentication', 'iam', _pa_pwd,
     'set mgt-config password-complexity enabled yes minimum-length 12 minimum-uppercase-letters 1 minimum-lowercase-letters 1 minimum-numeric-letters 1 minimum-special-characters 1 password-history-count 24', 'set mgt-config password-complexity enabled no'),
    ('PA-DEFADMIN', 'The default "admin" account is not used', 'medium', 'Device setup / authentication', 'iam', lambda f: _pa_nc(f, 'admins') if _pa(f, 'admins') is None else (F('the default "admin" account exists (%d administrators)' % f['admins']['count']) if f['admins'].get('default_admin') else P('%d named administrators, no "admin"' % f['admins']['count'])),
     'Create named administrators (RADIUS / SAML with MFA), confirm they can log in, then: delete mgt-config users admin', 'set mgt-config users admin permissions role-based superuser yes   # and set a new password interactively'),
    ('PA-SYSLOG', 'Logs are forwarded to a syslog server (the SIEM)', 'medium', 'Logging and monitoring', 'log', lambda f: _pa_nc(f, 'syslog') if _pa(f, 'syslog') is None else (P('%d syslog server profile(s)' % f['syslog']['profiles']) if f['syslog'].get('profiles') else F('no syslog server profile - logs stay on the firewall')),
     'set shared log-settings syslog SIEM server siem transport SSL port 6514 server <siem-ip> format BSD facility LOG_USER   # and a log forwarding profile on every rule', 'delete shared log-settings syslog SIEM'),
    ('PA-UPDATES', 'Threat, antivirus and WildFire updates install automatically', 'high', 'Dynamic updates', 'vuln', _pa_updates,
     'set deviceconfig system update-schedule threats recurring daily at 02:00 action download-and-install; set deviceconfig system update-schedule anti-virus recurring hourly at 15 action download-and-install; set deviceconfig system update-schedule wildfire recurring every-min action download-and-install', 'set deviceconfig system update-schedule threats recurring daily action download-only'),
    ('PA-ZPP', 'Internet-facing zones have Zone Protection', 'high', 'Zone protection', 'net', _pa_zpp,
     'set network profiles zone-protection-profile ZP-internet flood tcp-syn enable yes syn-cookies activation-rate 10000 alarm-rate 10000 maximal-rate 40000; set zone <untrust-zone> network zone-protection-profile ZP-internet', 'delete zone <untrust-zone> network zone-protection-profile'),
    ('PA-NONSYN', 'TCP sessions must start with a SYN (reject non-SYN)', 'medium', 'Device setup / session', 'net', _pa_session('reject_non_syn', 'yes', 'tcp-reject-non-syn'),
     'set deviceconfig setting session tcp-reject-non-syn yes   # fix asymmetric routing first (Connectivity Troubleshooter)', 'set deviceconfig setting session tcp-reject-non-syn no'),
    ('PA-ASYM', 'Asymmetric path packets are dropped', 'medium', 'Device setup / TCP', 'net', _pa_session('asymmetric_path', 'drop', 'asymmetric-path'),
     'set deviceconfig setting tcp asymmetric-path drop', 'set deviceconfig setting tcp asymmetric-path bypass'),
    ('PA-ANYANY', 'No rule allows any source to any destination for any application', 'critical', 'Security policy', 'net', _pa_rules(lambda x: _anyof(x, 'source') and _anyof(x, 'destination') and _anyof(x, 'application'), 'any / any / any allow rules', 'no any / any / any allow rule'),
     'set rulebase security rules <rule> source <specific> destination <specific> application [ <apps> ]   # or disable it after checking its hit count: show rule-hit-count vsys vsys-name vsys1 rule-base security rules rule-name <rule>', 'Restore the rule from the previous configuration version (Device > Setup > Operations > Load configuration version)'),
    ('PA-PROFILE', 'Every allow rule has security profiles', 'high', 'Security policy', 'vuln', _pa_rules(lambda x: not x.get('profile'), 'allow rules without a security profile (no AV / IPS / URL inspection)', 'every allow rule has a security profile group'),
     'set rulebase security rules <rule> profile-setting group <best-practice-profile-group>', 'delete rulebase security rules <rule> profile-setting'),
    ('PA-APPDEFAULT', 'Application rules use service application-default', 'medium', 'Security policy', 'net', _pa_rules(lambda x: not _anyof(x, 'application') and _anyof(x, 'service'), 'rules allowing applications on any port', 'application rules are limited to the applications\' default ports'),
     'set rulebase security rules <rule> service application-default', 'set rulebase security rules <rule> service any'),
    ('PA-LOGEND', 'Every allow rule logs at session end', 'medium', 'Logging and monitoring', 'log', _pa_rules(lambda x: not x.get('log_end'), 'allow rules without end-of-session logging', 'every allow rule logs at session end'),
     'set rulebase security rules <rule> log-end yes log-setting <forwarding-profile>', 'set rulebase security rules <rule> log-end no'),
    ('PA-DECRYPT', 'SSL decryption policy exists', 'medium', 'Decryption', 'crypto', lambda f: _pa_nc(f, 'decryption') if _pa(f, 'decryption') is None else (P('%d decryption rule(s)' % f['decryption']['count']) if f['decryption'].get('count') else F('no decryption rule - threats inside TLS are not inspected')),
     'Create a decryption rule (SSL Forward Proxy) for user web traffic with a no-decrypt rule above it for finance / health categories and pinned applications (Exchange / Microsoft 365)', 'delete rulebase decryption rules <rule>'),
]


def paloalto(f):
    return [_check(cid, title, sev, 'CIS Palo Alto Firewall Benchmark', sec, dom, *t(f), fix=fix, rollback=rb) for cid, title, sev, sec, dom, t, fix, rb in PA]


# ------------------------------------------------------------------------------------------------ VMware ESXi
# Facts: virt-capacity.js hostHardening (read-only vSphere properties). PowerCLI fixes run against vCenter (Connect-VIServer).
def _opt(h, k):
    o = h.get('options')
    if not isinstance(o, dict):
        return 'unread'
    return o.get(k)


def _esx_num(k, ok, label, default=None, unset_fails=True):
    def t(h):
        v = _opt(h, k)
        if v == 'unread':
            return N('advanced settings not readable by the vCenter role (needs Host > Configuration read)')
        if v is None:   # config.option lists every advanced setting with its current value: absent = not on this release
            return N('%s does not exist on this ESXi release' % label)
        b = str(v).strip().lower()
        n = 1 if b == 'true' else 0 if b == 'false' else num(v)
        if n is None:
            return F('%s is empty' % label) if unset_fails else N('%s not readable' % label)
        return P('%s = %s' % (label, n)) if ok(n) else F('%s = %s' % (label, n))
    return t


def _esx_svc(key, label, must_be_off=True):
    def t(h):
        sv = h.get('services')
        if not isinstance(sv, dict):
            return N('services not readable by the vCenter role')
        x = sv.get(key)
        if x is None:
            return P('%s not present on this host' % label)
        on = x.get('running') or str(x.get('policy') or '').lower() in ('on', 'automatic')
        if must_be_off:
            return F('%s running=%s, start policy=%s' % (label, x.get('running'), x.get('policy'))) if on else P('%s stopped, start policy %s' % (label, x.get('policy')))
        return P('%s running' % label) if x.get('running') else F('%s not running (policy %s)' % (label, x.get('policy')))
    return t


def _esx_pwq(h):
    v = _opt(h, 'Security.PasswordQualityControl')
    if v == 'unread':
        return N('advanced settings not readable by the vCenter role')
    if v is None:
        return N('Security.PasswordQualityControl does not exist on this ESXi release')
    if not v:
        return F('Security.PasswordQualityControl is empty')
    m = re.search(r'min=([^\s]+)', str(v))
    vals = [num(x) for x in (m.group(1).split(',') if m else []) if x.strip().lower() != 'disabled']
    vals = [x for x in vals if x is not None]
    if not vals:
        return F('no minimum length in "%s"' % v)
    return P('minimum password length %d (%s)' % (min(vals), v)) if min(vals) >= 14 else F('passwords as short as %d characters allowed (%s)' % (min(vals), v))


def _esx_syslog(h):
    v = _opt(h, 'Syslog.global.logHost')
    if v == 'unread':
        return N('advanced settings not readable by the vCenter role')
    if v is None:
        return N('Syslog.global.logHost not reported')
    return P('logs forwarded to ' + str(v)[:120]) if v and str(v).strip() else F('Syslog.global.logHost is empty - logs stay on the host')


def _esx_ntp(h):
    srv = h.get('ntp')
    if srv is None:
        return N('NTP configuration not readable')
    sv = h.get('services') if isinstance(h.get('services'), dict) else {}
    run = (sv.get('ntpd') or {}).get('running')
    if not srv:
        return F('no NTP server configured')
    if run is False:
        return F('NTP servers %s configured but ntpd is not running' % ', '.join(srv[:3]))
    return P('NTP %s%s' % (', '.join(srv[:3]), '' if run else ' (service state not reported)'))


def _esx_lockdown(h):
    v = h.get('lockdown')
    if v is None:
        return N('lockdown mode not reported (ESXi 6.0+ through vCenter)')
    return P('lockdown mode ' + v) if v in ('lockdownNormal', 'lockdownStrict') else F('lockdown mode ' + v)


SENSITIVE_RULESETS = ('sshServer', 'snmp', 'webAccess', 'CIMHttpServer', 'CIMHttpsServer', 'CIMSLP', 'vSphereClient', 'nfsClient')


def _esx_fw(h):
    f = h.get('firewall')
    if not isinstance(f, dict):
        return N('firewall configuration not readable')
    bad = []
    if f.get('incoming_blocked') is False:
        bad.append('default incoming policy allows traffic')
    open_all = [r['key'] for r in f.get('rulesets') or [] if r.get('enabled') and r.get('all_ip') and r.get('key') in SENSITIVE_RULESETS]
    if open_all:
        bad.append('enabled services open to any address: ' + ', '.join(open_all))
    return F('; '.join(bad)) if bad else P('incoming blocked by default; management services limited to allowed addresses')


def _esx_vsw(h):
    if h.get('vswitches') is None and h.get('portgroups') is None:
        return N('virtual switch policy not readable')
    bad = []
    for kind, rows in (('vSwitch', h.get('vswitches') or []), ('port group', h.get('portgroups') or [])):
        for r in rows:
            on = [n for n, k in (('promiscuous', 'promiscuous'), ('MAC changes', 'mac_changes'), ('forged transmits', 'forged')) if r.get(k) is True]
            if on:
                bad.append('%s %s: %s' % (kind, r.get('name') or '?', ', '.join(on)))
    return F('; '.join(bad[:8]) + (' …' if len(bad) > 8 else '')) if bad else P('promiscuous mode, MAC changes and forged transmits rejected (standard switches)')


def _esx_version(h):
    v = str(h.get('version') or '')
    m = re.match(r'^(\d+)\.(\d+)', v)
    if not m:
        return N('version not reported')
    major = int(m.group(1))
    return P('ESXi %s build %s' % (v, h.get('build') or '?')) if major >= 7 else F('ESXi %s is out of general support - upgrade to 7.0 U3 or 8.0' % v)


ESX = [
    ('ESX-SSH', 'SSH service is stopped and does not start with the host', 'high', 'Management / services', 'iam', _esx_svc('TSM-SSH', 'SSH'),
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'TSM-SSH' | Set-VMHostService -Policy Off | Stop-VMHostService -Confirm:$false",
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'TSM-SSH' | Set-VMHostService -Policy <previous> | Start-VMHostService"),
    ('ESX-SHELL', 'ESXi Shell is stopped and does not start with the host', 'high', 'Management / services', 'iam', _esx_svc('TSM', 'ESXi Shell'),
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'TSM' | Set-VMHostService -Policy Off | Stop-VMHostService -Confirm:$false",
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'TSM' | Set-VMHostService -Policy <previous> | Start-VMHostService"),
    ('ESX-SLP', 'SLP (port 427, used by ESXiArgs ransomware) is stopped', 'critical', 'Management / services', 'vuln', _esx_svc('slpd', 'SLP'),
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'slpd' | Set-VMHostService -Policy Off | Stop-VMHostService -Confirm:$false; Get-VMHostFirewallException -VMHost <host> -Name 'CIM SLP' | Set-VMHostFirewallException -Enabled $false",
     "Get-VMHost <host> | Get-VMHostService | Where-Object Key -eq 'slpd' | Set-VMHostService -Policy On | Start-VMHostService"),
    ('ESX-SHELL-TO', 'ESXi Shell and SSH sessions end within 15 minutes', 'medium', 'Management / timeouts', 'iam', _esx_num('UserVars.ESXiShellInteractiveTimeOut', lambda n: 0 < n <= 900, 'UserVars.ESXiShellInteractiveTimeOut', 0),
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900 -Confirm:$false; Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-DCUI-TO', 'DCUI session ends within 10 minutes', 'low', 'Management / timeouts', 'iam', _esx_num('UserVars.DcuiTimeOut', lambda n: 0 < n <= 600, 'UserVars.DcuiTimeOut', 600),
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-LOCKOUT', 'Accounts lock after 5 or fewer failed logins', 'high', 'Accounts and authentication', 'iam', _esx_num('Security.AccountLockFailures', lambda n: 1 <= n <= 5, 'Security.AccountLockFailures', 5),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 5 -Confirm:$false; Get-VMHost <host> | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-UNLOCK', 'A locked account stays locked at least 15 minutes', 'medium', 'Accounts and authentication', 'iam', _esx_num('Security.AccountUnlockTime', lambda n: n >= 900, 'Security.AccountUnlockTime', 120),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-PWQ', 'Local passwords are at least 14 characters', 'high', 'Accounts and authentication', 'iam', _esx_pwq,
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value 'retry=3 min=disabled,disabled,disabled,disabled,15' -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value '<previous value>' -Confirm:$false"),
    ('ESX-PWHIST', 'Password history keeps the last 5 or more', 'low', 'Accounts and authentication', 'iam', _esx_num('Security.PasswordHistory', lambda n: n >= 5, 'Security.PasswordHistory', 0),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-LOCKDOWN', 'Lockdown mode is enabled (managed through vCenter only)', 'medium', 'Management / access', 'iam', _esx_lockdown,
     "(Get-VMHost <host> | Get-View).EnterLockdownMode()   # keep an exception user for break-glass (DCUI.Access)",
     "(Get-VMHost <host> | Get-View).ExitLockdownMode()"),
    ('ESX-MOB', 'Managed Object Browser is disabled', 'medium', 'Management / services', 'hard', _esx_num('Config.HostAgent.plugins.solo.enableMob', lambda n: n == 0, 'Config.HostAgent.plugins.solo.enableMob', None, False),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value $false -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value $true -Confirm:$false"),
    ('ESX-SYSLOG', 'Logs are forwarded to the SIEM', 'high', 'Logging', 'log', _esx_syslog,
     "Get-VMHost <host> | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value 'tcp://<SIEM collector>:514' -Confirm:$false; Get-VMHostFirewallException -VMHost <host> -Name syslog | Set-VMHostFirewallException -Enabled $true",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value '<previous>' -Confirm:$false"),
    ('ESX-NTP', 'Time is synchronised with NTP', 'medium', 'Logging', 'log', _esx_ntp,
     "Add-VMHostNtpServer -VMHost <host> -NtpServer <ntp1>,<ntp2>; Get-VMHostService -VMHost <host> | Where-Object Key -eq 'ntpd' | Set-VMHostService -Policy On | Start-VMHostService",
     "Remove-VMHostNtpServer -VMHost <host> -NtpServer <server> -Confirm:$false"),
    ('ESX-FW', 'Host firewall blocks by default and limits management services to allowed addresses', 'high', 'Network / firewall', 'net', _esx_fw,
     "Get-VMHostFirewallException -VMHost <host> -Name 'SSH Server' | Get-View   # then: (Get-VMHost <host> | Get-View).ConfigManager.FirewallSystem -> UpdateRuleset with AllowedHosts = management subnet",
     "restore the ruleset's previous allowed-hosts list (allIp = true)"),
    ('ESX-VSWITCH', 'Virtual switches reject promiscuous mode, MAC changes and forged transmits', 'medium', 'Network / virtual switches', 'net', _esx_vsw,
     "Get-VirtualSwitch -VMHost <host> -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false -MacChanges $false -ForgedTransmits $false",
     "Get-VirtualSwitch -VMHost <host> -Standard -Name <vSwitch> | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous <previous> -MacChanges <previous> -ForgedTransmits <previous>"),
    ('ESX-BPDU', 'Guest BPDUs are blocked', 'low', 'Network / virtual switches', 'net', _esx_num('Net.BlockGuestBPDU', lambda n: n == 1, 'Net.BlockGuestBPDU', 0),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 0 -Confirm:$false"),
    ('ESX-SALT', 'Memory page sharing is salted per VM', 'low', 'Virtual machines / isolation', 'hard', _esx_num('Mem.ShareForceSalting', lambda n: n == 2, 'Mem.ShareForceSalting', 2),
     "Get-VMHost <host> | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value <previous> -Confirm:$false"),
    ('ESX-SHELLWARN', 'The shell-enabled warning is not suppressed', 'low', 'Management / services', 'hard', _esx_num('UserVars.SuppressShellWarning', lambda n: n == 0, 'UserVars.SuppressShellWarning', 0),
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 0 -Confirm:$false",
     "Get-VMHost <host> | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 1 -Confirm:$false"),
    ('ESX-VERSION', 'ESXi is a supported release (7.0 or later)', 'high', 'Patching and support', 'vuln', _esx_version,
     'Upgrade with vSphere Lifecycle Manager to the latest ESXi 7.0 U3 / 8.0 patch in a maintenance window', 'Boot the previous image from the alternate boot bank (Shift+R at boot)'),
]


def esxi(f):
    h = f.get('host') or {}
    out = []
    for cid, title, sev, sec, dom, t, fix, rb in ESX:
        r = t(h)
        if cid == 'ESX-LOCKDOWN' and r[0] == 'not_checked' and not h.get('read', {}).get('lockdown', True):
            r = N('lockdown mode not readable (standalone host, or ESXi older than 6.0)')
        out.append(_check(cid, title, sev, 'CIS VMware ESXi Benchmark / vSphere Security Configuration Guide', sec, dom, r[0], r[1], fix.replace('<host>', h.get('name') or '<host>'), rb.replace('<host>', h.get('name') or '<host>')))
    return out


# ------------------------------------------------------------------------------------------------------ Nutanix
# Facts: virt-capacity.js ntxClient.hardening (Prism v2.0 cluster security config, v1 authconfig / remote syslog). The
# Nutanix baseline is its STIG, enforced on the CVMs and AHV by SCMA (Security Configuration Management Automation).
def _scma(key, part, label, want=True):
    def t(f):
        c = f.get('cluster') or {}
        x = c.get(part)
        if not isinstance(x, dict):
            return N('%s security configuration not reported by this Prism / AOS' % ('AHV' if part == 'hv_scma' else 'CVM'))
        v = x.get(key)
        if v is None:
            return N('%s not reported' % label)
        return P('%s %s' % (label, 'on' if v else 'off')) if v == want else F('%s %s' % (label, 'on' if v else 'off'))
    return t


def _ntx_sched(f):
    x = (f.get('cluster') or {}).get('scma')
    if not isinstance(x, dict) or not x.get('schedule'):
        return N('SCMA schedule not reported by this Prism / AOS')
    sc = str(x['schedule']).upper()
    return P('SCMA self-heals ' + sc.lower()) if sc in ('HOURLY', 'DAILY') else F('SCMA schedule ' + sc.lower() + ' - drift from the STIG baseline is corrected only ' + sc.lower())


def _ntx_lockdown(f):
    c = f.get('cluster') or {}
    if c.get('lockdown') is None and c.get('password_remote_login') is None:
        return N('cluster lockdown not reported by this Prism / AOS')
    if c.get('lockdown') or c.get('password_remote_login') is False:
        return P('cluster lockdown on: SSH to the CVMs / hosts by key only')
    return F('password SSH logins to the CVMs / hosts are allowed (cluster lockdown off)')


def _ntx_list(key, label, minimum=1):
    def t(f):
        v = (f.get('cluster') or {}).get(key)
        if v is None:
            return N('%s not reported' % label)
        return P('%s: %s' % (label, ', '.join(v[:4]))) if len(v) >= minimum else F('%s: %d configured (needs %d)' % (label, len(v), minimum))
    return t


def _ntx_auth(f):
    a = f.get('auth')
    if a is None:
        return N('authentication configuration not readable (Prism v1 authconfig)')
    return P('%d directory service(s) for Prism logins' % a['directories']) if a.get('directories') else F('no directory service - Prism is used with local accounts only')


def _ntx_syslog(f):
    x = f.get('syslog')
    if x is None:
        return N('remote syslog configuration not readable on this Prism - check ncli rsyslog-config list')
    return P('%d remote syslog server(s)' % x['servers']) if x.get('servers') else F('no remote syslog server - CVM and hypervisor logs stay on the cluster')


def _ntx_version(f):
    h = f.get('host') or {}
    v = str(h.get('version') or '')
    return P(v) if v else N('hypervisor version not reported')


NTX = [
    ('NTX-SCMA-CVM-AIDE', 'CVM file integrity monitoring (AIDE) is on', 'medium', 'STIG / SCMA (CVM)', 'hard', _scma('aide', 'scma', 'CVM AIDE'),
     'ncli cluster edit-cvm-security-params enable-aide=true', 'ncli cluster edit-cvm-security-params enable-aide=false'),
    ('NTX-SCMA-CVM-PWD', 'CVM high-strength passwords are enforced', 'high', 'STIG / SCMA (CVM)', 'iam', _scma('high_strength_password', 'scma', 'CVM high-strength passwords'),
     'ncli cluster edit-cvm-security-params enable-high-strength-password=true', 'ncli cluster edit-cvm-security-params enable-high-strength-password=false'),
    ('NTX-SCMA-CVM-BANNER', 'CVM login banner is on', 'low', 'STIG / SCMA (CVM)', 'hard', _scma('banner', 'scma', 'CVM banner'),
     'ncli cluster edit-cvm-security-params enable-banner=true', 'ncli cluster edit-cvm-security-params enable-banner=false'),
    ('NTX-SCMA-SNMPV3', 'SNMP is limited to v3', 'medium', 'STIG / SCMA (CVM)', 'crypto', _scma('snmpv3_only', 'scma', 'SNMPv3 only'),
     'ncli cluster edit-cvm-security-params enable-snmpv3-only=true   # configure SNMPv3 users first', 'ncli cluster edit-cvm-security-params enable-snmpv3-only=false'),
    ('NTX-SCMA-SCHED', 'SCMA corrects drift hourly or daily', 'medium', 'STIG / SCMA (CVM)', 'hard', _ntx_sched,
     'ncli cluster edit-cvm-security-params schedule=hourly', 'ncli cluster edit-cvm-security-params schedule=<previous>'),
    ('NTX-SCMA-AHV-AIDE', 'AHV file integrity monitoring (AIDE) is on', 'medium', 'STIG / SCMA (AHV)', 'hard', _scma('aide', 'hv_scma', 'AHV AIDE'),
     'ncli cluster edit-hypervisor-security-params enable-aide=true', 'ncli cluster edit-hypervisor-security-params enable-aide=false'),
    ('NTX-SCMA-AHV-PWD', 'AHV high-strength passwords are enforced', 'high', 'STIG / SCMA (AHV)', 'iam', _scma('high_strength_password', 'hv_scma', 'AHV high-strength passwords'),
     'ncli cluster edit-hypervisor-security-params enable-high-strength-password=true', 'ncli cluster edit-hypervisor-security-params enable-high-strength-password=false'),
    ('NTX-SCMA-AHV-BANNER', 'AHV login banner is on', 'low', 'STIG / SCMA (AHV)', 'hard', _scma('banner', 'hv_scma', 'AHV banner'),
     'ncli cluster edit-hypervisor-security-params enable-banner=true', 'ncli cluster edit-hypervisor-security-params enable-banner=false'),
    ('NTX-LOCKDOWN', 'Cluster lockdown: SSH by key only, no password logins', 'high', 'Access', 'iam', _ntx_lockdown,
     'Prism > Settings > Cluster Lockdown: add the administrators\' public keys, then clear "Enable Remote Login with Password"', 'Prism > Settings > Cluster Lockdown: tick "Enable Remote Login with Password"'),
    ('NTX-AUTH', 'Prism logins use the directory (named accounts)', 'medium', 'Access', 'iam', _ntx_auth,
     'Prism > Settings > Authentication: add the Active Directory (LDAPS) and map groups to roles; keep local admin for break-glass only', 'remove the directory from Prism > Settings > Authentication'),
    ('NTX-NTP', 'At least two NTP servers are configured', 'medium', 'Logging', 'log', _ntx_list('ntp', 'NTP servers', 2),
     'ncli cluster add-to-ntp-servers servers=<ntp1>,<ntp2>', 'ncli cluster remove-from-ntp-servers servers=<server>'),
    ('NTX-DNS', 'DNS servers are configured', 'low', 'Logging', 'net', _ntx_list('dns', 'DNS servers', 1),
     'ncli cluster add-to-name-servers servers=<dns1>,<dns2>', 'ncli cluster remove-from-name-servers servers=<server>'),
    ('NTX-SYSLOG', 'Logs are forwarded to the SIEM', 'high', 'Logging', 'log', _ntx_syslog,
     'ncli rsyslog-config add-server name=siem relp-enabled=false ip-address=<SIEM collector> port=514 network-protocol=tcp; ncli rsyslog-config set-status enable=true', 'ncli rsyslog-config remove-server name=siem'),
    ('NTX-VERSION', 'Hypervisor version is reported (check it against the Nutanix support matrix)', 'low', 'Patching and support', 'vuln', _ntx_version,
     'Upgrade AOS / AHV with LCM in a maintenance window', 'LCM does not roll back - restore from the pre-upgrade plan'),
]


def nutanix(f):
    return [_check(cid, title, sev, 'Nutanix STIG / SCMA baseline', sec, dom, *t(f), fix, rb) for cid, title, sev, sec, dom, t, fix, rb in NTX]


# --------------------------------------------------------------------------------------------- IIS (agent 1.3)
def _iis_sites(d, pred, fail_msg, pass_msg):
    iis = d.get('iis') or {}
    sites = iis.get('sites')
    if not isinstance(sites, list):
        return N('IIS sites not read')
    bad = [x.get('name') for x in sites if pred(x)]
    return F(fail_msg + ': ' + ', '.join(str(b) for b in bad[:10])) if bad else P(pass_msg)


def _iis_val(key, bad_val, label):
    def t(d):
        v = (d.get('iis') or {}).get(key)
        if v is None:
            return N('%s not read' % label)
        return F('%s = %s' % (label, v)) if v == bad_val else P('%s = %s' % (label, v))
    return t


IIS = [
    ('IIS-HTTPS', 'Every site has an HTTPS binding', 'high', 'Transport encryption', 'crypto', lambda d: _iis_sites(d, lambda x: 'https' not in (x.get('protocols') or []) and str(x.get('state', '')).lower() == 'started', 'started sites without HTTPS', 'every started site has an HTTPS binding'),
     "New-WebBinding -Name '<site>' -Protocol https -Port 443   # then bind the certificate: (Get-WebBinding -Name '<site>' -Protocol https).AddSslCertificate('<thumbprint>', 'My')", "Remove-WebBinding -Name '<site>' -Protocol https -Port 443"),
    ('IIS-DIRBROWSE', 'Directory browsing is off', 'medium', 'Configure authentication and authorization', 'hard', lambda d: _iis_sites(d, lambda x: x.get('directory_browse') is True, 'directory browsing on', 'directory browsing off on every site'),
     "Set-WebConfigurationProperty -PSPath 'IIS:\\Sites\\<site>' -Filter system.webServer/directoryBrowse -Name enabled -Value $false", "Set-WebConfigurationProperty -PSPath 'IIS:\\Sites\\<site>' -Filter system.webServer/directoryBrowse -Name enabled -Value $true"),
    ('IIS-ERRORS', 'Detailed errors are not shown to visitors', 'medium', 'Request filtering and other restriction modules', 'hard', _iis_val('error_mode', 'Detailed', 'httpErrors errorMode'),
     "Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/httpErrors -Name errorMode -Value DetailedLocalOnly", "Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/httpErrors -Name errorMode -Value Detailed"),
    ('IIS-LOGGING', 'Every site logs requests', 'medium', 'IIS logging recommendations', 'log', lambda d: _iis_sites(d, lambda x: x.get('logging') is False, 'logging off', 'logging on for every site'),
     "Set-ItemProperty 'IIS:\\Sites\\<site>' -Name logFile.enabled -Value $true", "Set-ItemProperty 'IIS:\\Sites\\<site>' -Name logFile.enabled -Value $false"),
    ('IIS-SERVERHDR', 'The Server header is removed', 'low', 'Request filtering and other restriction modules', 'hard', lambda d: N('removeServerHeader not read (IIS 10 or later)') if (d.get('iis') or {}).get('remove_server_header') is None else (P('Server header removed') if d['iis']['remove_server_header'] else F('Server header sent (reveals IIS version)')),
     "Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/security/requestFiltering -Name removeServerHeader -Value $true", "Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/security/requestFiltering -Name removeServerHeader -Value $false"),
    ('IIS-POWEREDBY', 'The X-Powered-By header is removed', 'low', 'Request filtering and other restriction modules', 'hard', _iis_val('powered_by', True, 'X-Powered-By header present'),
     "Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/httpProtocol/customHeaders -Name . -AtElement @{name='X-Powered-By'}", "Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/httpProtocol/customHeaders -Name . -Value @{name='X-Powered-By';value='ASP.NET'}"),
    ('IIS-WEBDAV', 'WebDAV is not installed', 'medium', 'Basic configurations', 'hard', _iis_val('webdav', True, 'WebDAV module installed'),
     "Uninstall-WindowsFeature Web-DAV-Publishing", "Install-WindowsFeature Web-DAV-Publishing"),
    ('IIS-POOLID', 'No application pool runs as LocalSystem', 'high', 'Basic configurations (application pool identity)', 'iam', lambda d: N('application pools not read') if not isinstance((d.get('iis') or {}).get('pools'), list) else (lambda bad: F('pools running as LocalSystem: ' + ', '.join(bad[:10])) if bad else P('no pool runs as LocalSystem'))([x.get('name') for x in d['iis']['pools'] if str(x.get('identity')).lower() == 'localsystem']),
     "Set-ItemProperty 'IIS:\\AppPools\\<pool>' -Name processModel.identityType -Value ApplicationPoolIdentity", "Set-ItemProperty 'IIS:\\AppPools\\<pool>' -Name processModel.identityType -Value LocalSystem"),
]


# ------------------------------------------------------------------------------------------ Hyper-V (agent 1.3)
def _hv_vms(d, pred, fail_msg, pass_msg, gen2=False):
    vms = (d.get('hyperv') or {}).get('vms')
    if not isinstance(vms, list):
        return N('Hyper-V VMs not read')
    pool = [v for v in vms if not gen2 or v.get('generation') == 2]
    bad = [v.get('name') for v in pool if pred(v)]
    return F('%s: %d (%s)' % (fail_msg, len(bad), ', '.join(str(b) for b in bad[:8]))) if bad else P(pass_msg % len(pool))


HYPERV = [
    ('HV-MIG-AUTH', 'Live migration authenticates with Kerberos', 'high', 'Hyper-V host / live migration', 'iam',
     lambda d: N('Hyper-V host settings not read') if not d.get('hyperv') else (P('live migration off') if not d['hyperv'].get('migration_enabled') else (P('Kerberos') if str(d['hyperv'].get('migration_auth')).lower() == 'kerberos' else F('live migration uses ' + str(d['hyperv'].get('migration_auth'))))),
     'Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos   # configure constrained delegation for the hosts first', 'Set-VMHost -VirtualMachineMigrationAuthenticationType CredSSP'),
    ('HV-MIG-NET', 'Live migration is limited to its own network', 'medium', 'Hyper-V host / live migration', 'net',
     lambda d: N('Hyper-V host settings not read') if not d.get('hyperv') else (F('live migration may use any network') if d['hyperv'].get('migration_enabled') and d['hyperv'].get('migration_any_network') else P('migration limited to chosen networks (or off)')),
     'Set-VMHost -UseAnyNetworkForMigration $false; Add-VMMigrationNetwork <migration subnet>', 'Set-VMHost -UseAnyNetworkForMigration $true'),
    ('HV-SECUREBOOT', 'Generation 2 VMs boot with Secure Boot', 'medium', 'Virtual machines', 'hard', lambda d: _hv_vms(d, lambda v: v.get('secure_boot') is False, 'generation 2 VMs without Secure Boot', 'Secure Boot on all %d generation 2 VMs', True),
     'Set-VMFirmware -VMName <vm> -EnableSecureBoot On   # VM powered off; Linux guests need the Microsoft UEFI CA template', 'Set-VMFirmware -VMName <vm> -EnableSecureBoot Off'),
    ('HV-MACSPOOF', 'VMs may not spoof MAC addresses', 'medium', 'Virtual machines / network', 'net', lambda d: _hv_vms(d, lambda v: v.get('mac_spoofing') is True, 'VMs with MAC address spoofing on', 'MAC spoofing off on all %d VMs'),
     'Set-VMNetworkAdapter -VMName <vm> -MacAddressSpoofing Off   # keep it only on NLB / nested virtualization VMs, documented', 'Set-VMNetworkAdapter -VMName <vm> -MacAddressSpoofing On'),
    ('HV-GUARDS', 'DHCP guard and router guard are on', 'low', 'Virtual machines / network', 'net', lambda d: _hv_vms(d, lambda v: v.get('dhcp_guard') is False or v.get('router_guard') is False, 'VMs without DHCP / router guard', 'DHCP and router guard on all %d VMs'),
     'Set-VMNetworkAdapter -VMName <vm> -DhcpGuard On -RouterGuard On   # not on the DHCP servers / routers themselves', 'Set-VMNetworkAdapter -VMName <vm> -DhcpGuard Off -RouterGuard Off'),
    ('HV-GUESTSVC', 'Guest Service Interface (host-to-guest file copy) is off', 'low', 'Virtual machines / integration services', 'hard', lambda d: _hv_vms(d, lambda v: v.get('guest_service') is True, 'VMs with Guest Service Interface on', 'Guest Service Interface off on all %d VMs'),
     "Disable-VMIntegrationService -VMName <vm> -Name 'Guest Service Interface'", "Enable-VMIntegrationService -VMName <vm> -Name 'Guest Service Interface'"),
    ('HV-ENHANCED', 'Enhanced session mode is off', 'low', 'Hyper-V host', 'hard',
     lambda d: N('Hyper-V host settings not read') if not d.get('hyperv') else (F('enhanced session mode on (clipboard / drive redirection into VMs)') if d['hyperv'].get('enhanced_session') else P('enhanced session mode off')),
     'Set-VMHost -EnableEnhancedSessionMode $false', 'Set-VMHost -EnableEnhancedSessionMode $true'),
]


# ------------------------------------------------------------------------------------- Active Directory (agent 1.4)
def _ad(d):
    return d.get('ad') if isinstance(d.get('ad'), dict) and not d['ad'].get('error') else None


def _ad_pwd(key, ok, want, label):
    def t(d):
        pw = (_ad(d) or {}).get('pwd')
        if not isinstance(pw, dict) or pw.get(key) is None:
            return N('default domain password policy not read')
        v = pw[key]
        return P('%s = %s' % (label, v)) if ok(v) else F('%s = %s (should be %s)' % (label, v, want))
    return t


def _ad_acc(key, label, limit=0):
    def t(d):
        x = ((_ad(d) or {}).get('accounts') or {}).get(key)
        if not isinstance(x, dict):
            return N('%s not read from the directory' % label)
        n = int(x.get('count') or 0)
        names = ', '.join(str(v) for v in (x.get('names') or [])[:10])
        return F('%d %s%s' % (n, label, (': ' + names + (' ...' if n > 10 else '')) if names else '')) if n > limit else P('no %s' % label if not limit else '%d %s (limit %d)' % (n, label, limit))
    return t


def _ad_grp(key, label, limit):
    def t(d):
        g = ((_ad(d) or {}).get('groups') or {}).get(key)
        if not isinstance(g, dict):
            return N('%s membership not readable from this domain controller' % label)
        n = int(g.get('count') or 0)
        names = ', '.join(str(v) for v in (g.get('names') or [])[:10])
        return F('%s has %d members (keep %d or fewer): %s' % (label, n, limit, names)) if n > limit else P('%s: %d member(s)%s' % (label, n, (' - ' + names) if names else ''))
    return t


def _ad_krbtgt(d):
    a = _ad(d) or {}
    v = a.get('krbtgt_age_days')
    if v is None:
        return N('krbtgt password age not read')
    return P('krbtgt password set %d days ago' % v) if v <= 180 else F('krbtgt password set %d days ago (reset at least every 180 days)' % v)


def _ad_level(d):
    a = _ad(d) or {}
    m = str(a.get('domain_mode') or '')
    if not m:
        return N('domain functional level not read')
    yr = re.search(r'(20\d\d)', m)
    ok = yr and int(yr.group(1)) >= 2016
    return P('domain %s, forest %s' % (m, a.get('forest_mode') or '?')) if ok else F('domain functional level %s - raise to Windows2016Domain once every DC runs 2016 or later' % m)


def _ad_flag(key, ok_when, pass_msg, fail_msg, label):
    def t(d):
        a = _ad(d)
        if a is None or a.get(key) is None:
            return N('%s not read' % label)
        return P(pass_msg) if a[key] == ok_when else F(fail_msg)
    return t


def _ad_ldap(d):
    a = _ad(d)
    if a is None or a.get('ldap_signing') is None:
        return N('LDAPServerIntegrity not set on this DC (the default does not require signing)') if a is not None else N('LDAP settings not read')
    sig, cb = a.get('ldap_signing'), a.get('ldap_channel_binding') or 0
    if sig != 2:
        return F('LDAP signing is not required (LDAPServerIntegrity = %s)' % sig)
    return P('LDAP signing required, channel binding = %s' % cb) if cb >= 1 else F('LDAP signing required but channel binding is off (LdapEnforceChannelBinding = 0)')


def _ad_laps(d):
    a = _ad(d)
    if a is None or a.get('laps_computers') is None or not a.get('computers'):
        return N('LAPS coverage not read')
    pct = 100.0 * a['laps_computers'] / a['computers']
    return P('LAPS manages %d of %d computers (%d%%)' % (a['laps_computers'], a['computers'], rnd(pct))) if pct >= 90 else F('LAPS manages %d of %d computers (%d%%) - the rest share or keep unmanaged local admin passwords' % (a['laps_computers'], a['computers'], rnd(pct)))


AD = [
    ('AD-PWLEN', 'Domain password policy: minimum length 14', 'high', 'Account Policies / Password Policy', 'iam', _ad_pwd('min_length', lambda v: v >= 14, '14 or more', 'MinPasswordLength'),
     "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -MinPasswordLength 14   # or a fine-grained policy for people, longer for admins", "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -MinPasswordLength <previous>"),
    ('AD-COMPLEX', 'Domain password policy: complexity on', 'medium', 'Account Policies / Password Policy', 'iam', _ad_pwd('complexity', lambda v: v is True, 'enabled', 'ComplexityEnabled'),
     "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ComplexityEnabled $true", "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ComplexityEnabled $false"),
    ('AD-HISTORY', 'Domain password policy: 24 passwords remembered', 'medium', 'Account Policies / Password Policy', 'iam', _ad_pwd('history', lambda v: v >= 24, '24', 'PasswordHistoryCount'),
     "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -PasswordHistoryCount 24", "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -PasswordHistoryCount <previous>"),
    ('AD-LOCKOUT', 'Domain lockout after 5 or fewer bad passwords', 'high', 'Account Policies / Account Lockout Policy', 'iam', _ad_pwd('lockout_threshold', lambda v: 0 < v <= 5, '1 to 5', 'LockoutThreshold'),
     "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00", "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -LockoutThreshold <previous>"),
    ('AD-REVERSIBLE', 'Passwords are not stored with reversible encryption', 'critical', 'Account Policies / Password Policy', 'crypto', _ad_pwd('reversible', lambda v: v is False, 'disabled', 'ReversibleEncryptionEnabled'),
     "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ReversibleEncryptionEnabled $false   # then have the affected users change their password", "Set-ADDefaultDomainPasswordPolicy -Identity <domain> -ReversibleEncryptionEnabled $true"),
    ('AD-KRBTGT', 'krbtgt password reset within 180 days', 'high', 'Kerberos / Golden Ticket protection', 'iam', _ad_krbtgt,
     "Reset the krbtgt password TWICE, at least 10 hours (the maximum ticket lifetime) apart, with Microsoft's New-KrbtgtKeys.ps1 in a change window; confirm replication between the resets", "None needed: tickets issued before the reset stay valid until they expire; do not reset a third time in a hurry"),
    ('AD-DA', 'Domain Admins kept to 5 or fewer named accounts', 'high', 'Privileged access', 'iam', _ad_grp('domain_admins', 'Domain Admins', 5),
     "Remove-ADGroupMember -Identity 'Domain Admins' -Members <account>   # give delegated rights instead; keep a break-glass account", "Add-ADGroupMember -Identity 'Domain Admins' -Members <account>"),
    ('AD-EA', 'Enterprise Admins empty outside forest changes', 'high', 'Privileged access', 'iam', _ad_grp('enterprise_admins', 'Enterprise Admins', 1),
     "Remove-ADGroupMember -Identity 'Enterprise Admins' -Members <account>   # add back only for the change window", "Add-ADGroupMember -Identity 'Enterprise Admins' -Members <account>"),
    ('AD-SA', 'Schema Admins empty outside schema changes', 'high', 'Privileged access', 'iam', _ad_grp('schema_admins', 'Schema Admins', 0),
     "Remove-ADGroupMember -Identity 'Schema Admins' -Members <account>", "Add-ADGroupMember -Identity 'Schema Admins' -Members <account>"),
    ('AD-PROTUSERS', 'Admins are in Protected Users', 'medium', 'Privileged access', 'iam', lambda d: N('Protected Users not read') if not isinstance(((_ad(d) or {}).get('groups') or {}).get('protected_users'), dict) else (F('Protected Users is empty - admin credentials can be cached and delegated') if not d['ad']['groups']['protected_users'].get('count') else P('%d account(s) in Protected Users' % d['ad']['groups']['protected_users']['count'])),
     "Add-ADGroupMember -Identity 'Protected Users' -Members <admin account>   # test each admin first: no NTLM, no delegation, no cached logon", "Remove-ADGroupMember -Identity 'Protected Users' -Members <admin account>"),
    ('AD-NEVEREXP', 'No enabled user with a password that never expires', 'medium', 'Accounts', 'iam', _ad_acc('pwd_never_expires', 'enabled users whose password never expires'),
     "Set-ADUser <account> -PasswordNeverExpires $false   # service accounts: move to gMSA (New-ADServiceAccount)", "Set-ADUser <account> -PasswordNeverExpires $true"),
    ('AD-NOTREQ', 'No enabled user may have an empty password', 'critical', 'Accounts', 'iam', _ad_acc('pwd_not_required', 'enabled users with PASSWD_NOTREQD'),
     "Set-ADAccountControl <account> -PasswordNotRequired $false", "Set-ADAccountControl <account> -PasswordNotRequired $true"),
    ('AD-PREAUTH', 'Kerberos pre-authentication is required (no AS-REP roasting)', 'high', 'Kerberos', 'iam', _ad_acc('no_preauth', 'enabled users without Kerberos pre-authentication'),
     "Set-ADAccountControl <account> -DoesNotRequirePreAuth $false", "Set-ADAccountControl <account> -DoesNotRequirePreAuth $true"),
    ('AD-ADMINSPN', 'No privileged user has a service principal name (Kerberoasting)', 'high', 'Kerberos', 'iam', _ad_acc('admin_spn', 'privileged users with an SPN'),
     "Set-ADUser <account> -ServicePrincipalNames @{Remove='<spn>'}   # run the service as a gMSA instead", "Set-ADUser <account> -ServicePrincipalNames @{Add='<spn>'}"),
    ('AD-STALE', 'No enabled user idle for more than 90 days', 'medium', 'Accounts', 'iam', _ad_acc('stale_users', 'enabled users with no logon in 90 days'),
     "Disable-ADAccount <account>   # after the owner confirms (Staff handover / leavers process)", "Enable-ADAccount <account>"),
    ('AD-UNCONSTR', 'No computer other than DCs trusted for unconstrained delegation', 'high', 'Kerberos', 'iam', _ad_acc('unconstrained', 'computers (not DCs) with unconstrained delegation'),
     "Set-ADComputer <computer> -TrustedForDelegation $false   # use constrained / resource-based delegation", "Set-ADComputer <computer> -TrustedForDelegation $true"),
    ('AD-RECYCLE', 'AD Recycle Bin is enabled', 'medium', 'Recovery', 'hard', _ad_flag('recycle_bin', True, 'AD Recycle Bin enabled', 'AD Recycle Bin is off - a deleted object needs an authoritative restore', 'Recycle Bin'),
     "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>", "None: the Recycle Bin cannot be disabled once enabled (that is why it is a change to approve)"),
    ('AD-LEVEL', 'Domain functional level 2016 or later', 'medium', 'Domain configuration', 'hard', _ad_level,
     "Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain   # only when every DC runs Windows Server 2016 or later", "None: lowering the functional level is limited - take a system-state backup of a DC first"),
    ('AD-LDAP', 'LDAP signing and channel binding are required', 'high', 'Domain controller / LDAP', 'net', _ad_ldap,
     "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 2; Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LdapEnforceChannelBinding -Value 1   # check event 2889 for clients still binding unsigned first",
     "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -Value 1; Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LdapEnforceChannelBinding -Value 0"),
    ('AD-LAPS', 'LAPS manages local administrator passwords (90% of computers)', 'high', 'Privileged access', 'iam', _ad_laps,
     "Windows LAPS: Update-LapsADSchema; Set-LapsADComputerSelfPermission -Identity <OU>; enable the 'Configure password backup directory' policy for the computer OUs", "Unlink the LAPS policy (passwords already set stay as they are)"),
]


# --------------------------------------------------------------------------------------- Exchange Server (agent 1.4)
def _ex(d):
    return d.get('exchange') if isinstance(d.get('exchange'), dict) and not d['exchange'].get('error') else None


def _ex_build(d):
    b = str((_ex(d) or {}).get('build') or '')
    m = re.match(r'^(?:Version )?(\d+)\.(\d+)[ .](?:\(Build )?(\d+)', b)
    if not m:
        return N('Exchange build not read')
    major, minor, build = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if major < 15 or (major == 15 and minor == 0):
        return F('Exchange %s (2013 or older) is out of support' % b)
    if minor == 1:
        return F('Exchange 2016 (%s) left extended support on 14 Oct 2025 - move to Exchange Server Subscription Edition' % b)
    if minor == 2 and build < 2562:
        return F('Exchange 2019 (%s) left extended support on 14 Oct 2025 - move to Exchange Server Subscription Edition' % b)
    return P('Exchange Server Subscription Edition build %s - keep it on the latest CU and security update' % b)


def _ex_val(key, ok, pass_msg, fail_msg, label):
    def t(d):
        e = _ex(d)
        if e is None or e.get(key) is None:
            return N('%s not read' % label)
        return P(pass_msg) if ok(e[key]) else F(fail_msg % e[key] if '%' in fail_msg else fail_msg)
    return t


def _ex_relay(d):
    rc = (_ex(d) or {}).get('receive')
    if not isinstance(rc, list):
        return N('receive connectors not read')
    relay = [x['name'] for x in rc if x.get('enabled') and x.get('open_relay')]
    unk = [x['name'] for x in rc if x.get('enabled') and x.get('anonymous') and x.get('open_relay') is None]
    if relay:
        return F('anonymous users may relay to any recipient on: ' + ', '.join(relay))
    if unk:
        return N('anonymous connectors whose relay permission could not be read: ' + ', '.join(unk))
    return P('no receive connector lets anonymous users relay')


def _ex_tls(d):
    e = _ex(d)
    if e is None:
        return N('SCHANNEL settings not read')
    on = [n for n, k in (('TLS 1.0', 'tls10_server'), ('TLS 1.1', 'tls11_server')) if e.get(k) != 0]
    return F('%s not disabled for the server side (Exchange 2016 CU or later supports TLS 1.2 only)' % ' and '.join(on)) if on else P('TLS 1.0 and 1.1 disabled on the server side')


EXCH = [
    ('EX-BUILD', 'Exchange is a supported release on a current build', 'critical', 'Patching and support', 'vuln', _ex_build,
     "Run the Exchange Health Checker (HealthChecker.ps1); install the latest CU and security update; plan the in-place upgrade from 2019 CU14/CU15 to Exchange Server SE", "Exchange CUs cannot be uninstalled - restore the server from backup / recover with setup /m:RecoverServer"),
    ('EX-MODERNAUTH', 'Modern authentication (OAuth) is enabled', 'high', 'Authentication', 'iam', _ex_val('modern_auth', lambda v: v is True, 'OAuth2ClientProfileEnabled = True', 'modern authentication is off - Outlook signs in with basic / NTLM', 'OAuth2ClientProfileEnabled'),
     "Set-OrganizationConfig -OAuth2ClientProfileEnabled $true   # with ADFS / hybrid modern auth configured first", "Set-OrganizationConfig -OAuth2ClientProfileEnabled $false"),
    ('EX-ADMINAUDIT', 'Administrator audit logging is on', 'high', 'Audit logging', 'log', _ex_val('admin_audit', lambda v: v is True, 'admin audit log enabled', 'admin audit logging is off - cmdlets run by administrators are not recorded', 'AdminAuditLogEnabled'),
     "Set-AdminAuditLogConfig -AdminAuditLogEnabled $true -AdminAuditLogAgeLimit 365.00:00:00", "Set-AdminAuditLogConfig -AdminAuditLogEnabled $false"),
    ('EX-MBXAUDIT', 'Mailbox auditing is on for the organisation', 'high', 'Audit logging', 'log', _ex_val('mailbox_audit_off', lambda v: v is False, 'mailbox auditing by default on', 'mailbox auditing is disabled for the organisation (AuditDisabled = True)', 'AuditDisabled'),
     "Set-OrganizationConfig -AuditDisabled $false", "Set-OrganizationConfig -AuditDisabled $true"),
    ('EX-AUTOFWD', 'Automatic forwarding to external domains is blocked', 'high', 'Mail flow / data leakage', 'net', _ex_val('auto_forward', lambda v: v is False, 'auto-forward to the Default remote domain blocked', 'mailboxes may auto-forward to any external domain (data leakage, PDPL)', 'Default remote domain'),
     "Set-RemoteDomain -Identity Default -AutoForwardEnabled $false   # add a remote domain per approved partner if needed", "Set-RemoteDomain -Identity Default -AutoForwardEnabled $true"),
    ('EX-RELAY', 'No receive connector is an open relay', 'critical', 'Mail flow', 'net', _ex_relay,
     "Get-ReceiveConnector '<server>\\<connector>' | Remove-ADPermission -User 'NT AUTHORITY\\ANONYMOUS LOGON' -ExtendedRights 'Ms-Exch-SMTP-Accept-Any-Recipient'   # restrict RemoteIPRanges to the devices that must relay", "Get-ReceiveConnector '<server>\\<connector>' | Add-ADPermission -User 'NT AUTHORITY\\ANONYMOUS LOGON' -ExtendedRights 'Ms-Exch-SMTP-Accept-Any-Recipient'"),
    ('EX-ECP', 'The Exchange admin center is not published externally', 'high', 'Client access', 'net', _ex_val('ecp_external', lambda v: v is False, 'no external URL for the admin center', 'the Exchange admin center (ECP) has an external URL with admin access on', 'ECP virtual directory'),
     "Set-EcpVirtualDirectory '<server>\\ecp (Default Web Site)' -ExternalUrl $null   # or block /ecp at the reverse proxy / WAF for outside addresses", "Set-EcpVirtualDirectory '<server>\\ecp (Default Web Site)' -ExternalUrl <previous URL>"),
    ('EX-OWABASIC', 'OWA does not accept basic authentication', 'medium', 'Client access', 'iam', _ex_val('owa_basic', lambda v: v is False, 'OWA basic authentication off', 'OWA accepts basic authentication', 'OWA virtual directory'),
     "Set-OwaVirtualDirectory '<server>\\owa (Default Web Site)' -BasicAuthentication $false   # forms / modern auth stays", "Set-OwaVirtualDirectory '<server>\\owa (Default Web Site)' -BasicAuthentication $true"),
    ('EX-EP', 'Extended Protection is required', 'high', 'Client access', 'crypto', _ex_val('ep_ews', lambda v: str(v).lower() == 'require', 'Extended Protection required (EWS)', 'Extended Protection is %s on EWS - NTLM relay attacks are possible', 'ExtendedProtectionTokenChecking'),
     "Run Microsoft's ExchangeExtendedProtectionManagement.ps1 (checks TLS consistency first, then sets Require on every virtual directory)", "ExchangeExtendedProtectionManagement.ps1 -RollbackType RestoreIISAppConfig"),
    ('EX-MALWARE', 'The built-in anti-malware scan is not bypassed', 'medium', 'Anti-malware', 'vuln', _ex_val('malware_bypass', lambda v: v is False, 'anti-malware filtering active', 'anti-malware filtering is bypassed on this server', 'BypassFiltering'),
     "& $env:ExchangeInstallPath\\Scripts\\Enable-AntimalwareScanning.ps1   # unless a gateway (Libraesva) scans every message - then record that as the compensating control", "& $env:ExchangeInstallPath\\Scripts\\Disable-AntimalwareScanning.ps1"),
    ('EX-TLS', 'TLS 1.0 and 1.1 are disabled', 'medium', 'Transport encryption', 'crypto', _ex_tls,
     "Follow Microsoft's 'Exchange Server TLS guidance' part 2/3: set SCHANNEL Protocols\\TLS 1.0 and 1.1 Server Enabled=0 and .NET SchUseStrongCrypto=1, then restart", "Set the same SCHANNEL Server Enabled values back to 1 and restart"),
]


def components(d, now):
    """IIS / Hyper-V checks from the same Windows snapshot, where the role is installed."""
    out = []
    iis = d.get('iis')
    if isinstance(iis, dict):
        if iis.get('error'):
            out.append(_check('IIS-READ', 'IIS settings readable by the agent', 'low', 'CIS Microsoft IIS 10 Benchmark', 'Basic configurations', 'hard', 'not_checked', 'IIS read failed: ' + str(iis['error'])[:200]))
        else:
            for cid, title, sev, sec, dom, t, fix, rb in IIS:
                r = t(d)
                out.append(_check(cid, title, sev, 'CIS Microsoft IIS 10 Benchmark', sec, dom, r[0], r[1], fix, rb))
    hv = d.get('hyperv')
    if isinstance(hv, dict):
        if hv.get('error'):
            out.append(_check('HV-READ', 'Hyper-V settings readable by the agent', 'low', 'Microsoft Hyper-V security baseline', 'Hyper-V host', 'hard', 'not_checked', 'Hyper-V read failed: ' + str(hv['error'])[:200]))
        else:
            for cid, title, sev, sec, dom, t, fix, rb in HYPERV:
                r = t(d)
                out.append(_check(cid, title, sev, 'Microsoft Hyper-V security baseline (Windows Server)', sec, dom, r[0], r[1], fix, rb))
    for key, rules, bench, label, read_id in (('ad', AD, 'CIS Microsoft Windows Server Benchmark (Domain Controller) and Microsoft AD security guidance', 'Active Directory', 'AD-READ'),
                                              ('exchange', EXCH, 'CIS Microsoft Exchange Server Benchmark and Microsoft Exchange security guidance', 'Exchange', 'EX-READ')):
        x = d.get(key)
        if not isinstance(x, dict):
            continue
        if x.get('error'):
            out.append(_check(read_id, '%s settings readable by the agent' % label, 'medium', bench, 'Read access', 'hard', 'not_checked', '%s read failed: %s' % (label, str(x['error'])[:200])))
            continue
        dom = x.get('domain') or ''
        for cid, title, sev, sec, dm, t, fix, rb in rules:
            r = t(d)
            out.append(_check(cid, title, sev, bench, sec, dm, r[0], (r[1] + (' [' + dom + ']' if dom else '')) if key == 'ad' else r[1], fix.replace('<domain>', dom or '<domain>'), rb.replace('<domain>', dom or '<domain>')))
    return out


# ------------------------------------------------------------------------------------------------- Proxmox VE
def _pve_node(key, ok, label):
    def t(f):
        v = (f.get('host') or {}).get(key)
        if v is None:
            return N('%s not readable by the API token (needs PVEAuditor on /)' % label)
        return P(ok[1](v)) if ok[0](v) else F(ok[2](v))
    return t


def _pve_cert(f):
    certs = (f.get('host') or {}).get('certs')
    if certs is None:
        return N('certificates not readable by the API token')
    proxy = [c for c in certs if 'pveproxy' in c.get('file', '')] or [c for c in certs if 'pve-ssl' in c.get('file', '')]
    if not proxy:
        return N('the web interface certificate was not listed')
    c = proxy[0]
    if 'Proxmox Virtual Environment' in c.get('issuer', '') or c.get('issuer') == c.get('subject'):
        return F('the web interface uses the self-signed Proxmox certificate (%s)' % c.get('file'))
    return P('web interface certificate issued by ' + c.get('issuer', '')[:80])


def _pve_cluster(fn):
    def t(f):
        return fn(f.get('cluster') or {})
    return t


def _pve_tfa(c):
    users, tfa = c.get('users'), c.get('tfa')
    if users is None or tfa is None:
        return N('users / second factors not readable by the API token')
    people = [u['userid'] for u in users if u.get('enable') and '!' not in u['userid']]
    without = [u for u in people if u not in tfa]
    return F('%d enabled user(s) without a second factor: %s' % (len(without), ', '.join(without[:8]))) if without else P('every enabled user has a second factor')


def _pve_version(c):
    v = str(c.get('version') or '')
    m = re.match(r'^(\d+)', v)
    if not m:
        return N('version not reported')
    return P('Proxmox VE ' + v) if int(m.group(1)) >= 8 else F('Proxmox VE %s is end of life - upgrade to 8.x' % v)


PVE = [
    ('PVE-FW-DC', 'Datacenter firewall is enabled', 'high', 'Firewall', 'net', _pve_cluster(lambda c: N('datacenter firewall not readable by the API token') if c.get('firewall') is None else (P('datacenter firewall on, inbound policy ' + str(c['firewall'].get('policy_in') or 'DROP')) if c['firewall'].get('enable') else F('datacenter firewall off - node and VM firewall rules are not enforced'))),
     "pvesh set /cluster/firewall/options --enable 1   # add the management / cluster allow rules first, or you lock yourself out", "pvesh set /cluster/firewall/options --enable 0"),
    ('PVE-FW-NODE', 'Node firewall is enabled', 'medium', 'Firewall', 'net', _pve_node('firewall', (lambda v: v is True, lambda v: 'node firewall on', lambda v: 'node firewall off'), 'Node firewall'),
     "pvesh set /nodes/<node>/firewall/options --enable 1", "pvesh set /nodes/<node>/firewall/options --enable 0"),
    ('PVE-REALM', 'Administrators log in through the directory (named accounts)', 'medium', 'Authentication', 'iam', _pve_cluster(lambda c: N('realms not readable by the API token') if c.get('realms') is None else (P('directory realm(s): ' + ', '.join(r['realm'] for r in c['realms'] if r['type'] in ('ad', 'ldap', 'openid'))) if any(r['type'] in ('ad', 'ldap', 'openid') for r in c['realms']) else F('only local realms (pam / pve) - no directory sign-in'))),
     "pveum realm add corp --type ad --domain corp.example --server1 <dc> --secure 1   # then sync groups and grant roles to groups", "pveum realm delete corp"),
    ('PVE-TFA', 'Every enabled user has a second factor', 'high', 'Authentication', 'iam', _pve_cluster(_pve_tfa),
     "Datacenter > Permissions > Two Factor: add TOTP / WebAuthn for each user; then require it on the realm (pveum realm modify <realm> --tfa type=oath)", "pveum realm modify <realm> --delete tfa"),
    ('PVE-ROOT', 'root@pam is kept for break-glass only', 'medium', 'Authentication', 'iam', _pve_cluster(lambda c: N('users not readable by the API token') if c.get('users') is None else (F('root@pam is enabled and is the only administrator account') if [u for u in c['users'] if u.get('enable') and '!' not in u['userid']] == [{'userid': 'root@pam', 'enable': True}] else P('named administrator accounts exist beside root@pam'))),
     "pveum user add <name>@<realm>; pveum acl modify / --users <name>@<realm> --roles Administrator   # keep root@pam with a strong password and a second factor for emergencies", "pveum user delete <name>@<realm>"),
    ('PVE-UPDATES', 'No pending package updates', 'high', 'Updates', 'vuln', _pve_node('updates', (lambda v: v == 0, lambda v: 'no pending updates (last apt refresh)', lambda v: '%d pending package update(s)' % v), 'Pending updates'),
     "apt update && apt full-upgrade   # node by node, migrating guests away first", "restore the node from its backup (packages are not rolled back by apt)"),
    ('PVE-CERT', 'The web interface uses a trusted certificate', 'medium', 'Certificates', 'crypto', _pve_cert,
     "pvenode acme account register default <mail>; pvenode config set --acme domains=<fqdn>; pvenode acme cert order   # or upload the internal CA certificate in Node > System > Certificates", "pvenode cert delete   # back to the self-signed certificate"),
    ('PVE-BACKUP', 'Backup jobs are defined', 'medium', 'Backup', 'hard', _pve_cluster(lambda c: N('backup jobs not readable by the API token') if c.get('backup_jobs') is None else (P('%d enabled backup job(s)' % c['backup_jobs']) if c['backup_jobs'] else F('no enabled backup job - guests are not backed up by Proxmox'))),
     "Datacenter > Backup > Add (Proxmox Backup Server or a storage target, all guests, daily)", "remove the backup job"),
    ('PVE-VERSION', 'Proxmox VE is a supported release (8.x)', 'high', 'Updates', 'vuln', _pve_cluster(_pve_version),
     "Follow the pve7to8 checklist and upgrade node by node", "restore the node from its backup"),
]


def proxmox(f):
    name = (f.get('host') or {}).get('name') or '<node>'
    return [_check(cid, title, sev, 'Proxmox VE security hardening (vendor guidance; Debian CIS for the base OS)', sec, dom, *t(f), fix.replace('<node>', name), rb.replace('<node>', name))
            for cid, title, sev, sec, dom, t, fix, rb in PVE]


# --------------------------------------------------------------------------------------- databases (db_harden)
def _rows(db, name):
    r = (db.get('results') or {}).get(name)
    return r


def _db_nc(db, name, grant):
    e = (db.get('errors') or {}).get(name)
    return N('not readable by the monitoring login%s - %s' % ((' (' + e + ')') if e else '', grant))


ORA_GRANT = 'GRANT SELECT_CATALOG_ROLE TO <login>; GRANT SELECT ON SYS.DBA_USERS_WITH_DEFPWD TO <login>;'
MS_GRANT = 'GRANT VIEW SERVER STATE, VIEW ANY DEFINITION TO [<login>];'
PG_GRANT = 'GRANT pg_read_all_settings TO <login>; (pg_hba_file_rules needs a superuser before PostgreSQL 16, or pg_read_all_settings on 16+)'


def _ora_param(name, ok, want):
    def t(db):
        rows = _rows(db, 'params')
        if rows is None:
            return _db_nc(db, 'params', ORA_GRANT)
        v = {str(r[0]).lower(): (r[1] if r[1] is not None else '') for r in rows}.get(name)
        if v is None:
            return N('%s does not exist on this Oracle release' % name)
        return P('%s = %s' % (name, v)) if ok(str(v).upper()) else F('%s = %s (should be %s)' % (name, v, want))
    return t


def _ora_list(name, fail_msg, pass_msg):
    def t(db):
        rows = _rows(db, name)
        if rows is None:
            return _db_nc(db, name, ORA_GRANT)
        items = [str(r[0]) for r in rows]
        return F(fail_msg + ': ' + ', '.join(items[:10])) if items else P(pass_msg)
    return t


def _ora_profile(res, ok, want):
    def t(db):
        rows = _rows(db, 'profile')
        if rows is None:
            return _db_nc(db, 'profile', ORA_GRANT)
        v = {str(r[0]): str(r[1]) for r in rows}.get(res)
        if v is None:
            return N(res + ' not reported')
        return P('DEFAULT profile %s = %s' % (res, v)) if ok(v.upper()) else F('DEFAULT profile %s = %s (should be %s)' % (res, v, want))
    return t


def _ora_audit(db):
    u = _rows(db, 'unified')
    if u and str(u[0][0]).upper() == 'TRUE':
        return P('Unified Auditing enabled')
    rows = _rows(db, 'params')
    if rows is None:
        return _db_nc(db, 'params', ORA_GRANT)
    v = {str(r[0]).lower(): str(r[1] or '') for r in rows}.get('audit_trail', '')
    return P('audit_trail = ' + v) if v.upper() not in ('', 'NONE', 'FALSE') else F('no auditing: audit_trail = %s and Unified Auditing is off' % (v or 'NONE'))


def _num_or(v, big):
    s = str(v).upper()
    if s in ('UNLIMITED',):
        return big
    try:
        return float(s)
    except ValueError:
        return None


ORA = [
    ('ORA-DEFPWD', 'No open account uses a default password', 'critical', 'Oracle Database Installation and Patching / users', 'iam', _ora_list('defpwd', 'open accounts with default passwords', 'no open account with a default password'),
     "ALTER USER <user> PASSWORD EXPIRE ACCOUNT LOCK;   -- for each listed account, then give it a strong password if it is needed", "ALTER USER <user> ACCOUNT UNLOCK;"),
    ('ORA-SAMPLE', 'Sample schemas are locked or removed', 'medium', 'Oracle Database Installation and Patching / users', 'hard', _ora_list('sample', 'open sample schemas', 'no open sample schema'),
     "ALTER USER <schema> ACCOUNT LOCK PASSWORD EXPIRE;   -- or drop them: DROP USER <schema> CASCADE;", "ALTER USER <schema> ACCOUNT UNLOCK;"),
    ('ORA-FAILED', 'Accounts lock after 5 or fewer failed logins', 'high', 'Oracle User Access and Authorization (profiles)', 'iam', _ora_profile('FAILED_LOGIN_ATTEMPTS', lambda v: (_num_or(v, 999) or 999) <= 5, '5 or fewer'),
     "ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LOCK_TIME 1;", "ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS <previous>;"),
    ('ORA-LIFETIME', 'Passwords expire within 90 days (person accounts)', 'medium', 'Oracle User Access and Authorization (profiles)', 'iam', _ora_profile('PASSWORD_LIFE_TIME', lambda v: (_num_or(v, 9999) or 9999) <= 90, '90 or fewer'),
     "ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 90;   -- give service accounts their own profile", "ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME <previous>;"),
    ('ORA-VERIFY', 'A password complexity function is set', 'high', 'Oracle User Access and Authorization (profiles)', 'iam', _ora_profile('PASSWORD_VERIFY_FUNCTION', lambda v: v not in ('NULL', 'DEFAULT', ''), 'ORA12C_STRONG_VERIFY_FUNCTION'),
     "ALTER PROFILE DEFAULT LIMIT PASSWORD_VERIFY_FUNCTION ORA12C_STRONG_VERIFY_FUNCTION;", "ALTER PROFILE DEFAULT LIMIT PASSWORD_VERIFY_FUNCTION NULL;"),
    ('ORA-REUSE', 'Passwords cannot be reused (20 or more)', 'low', 'Oracle User Access and Authorization (profiles)', 'iam', _ora_profile('PASSWORD_REUSE_MAX', lambda v: (_num_or(v, 0) or 0) >= 20 and v != 'UNLIMITED', '20 or more'),
     "ALTER PROFILE DEFAULT LIMIT PASSWORD_REUSE_MAX 20 PASSWORD_REUSE_TIME 365;", "ALTER PROFILE DEFAULT LIMIT PASSWORD_REUSE_MAX <previous>;"),
    ('ORA-REMOTE-OS', 'Remote OS authentication is off', 'critical', 'Oracle Parameter Settings', 'iam', _ora_param('remote_os_authent', lambda v: v == 'FALSE', 'FALSE'),
     "ALTER SYSTEM SET remote_os_authent = FALSE SCOPE = SPFILE;   -- restart in the maintenance window", "ALTER SYSTEM SET remote_os_authent = TRUE SCOPE = SPFILE;"),
    ('ORA-DICT', 'O7_DICTIONARY_ACCESSIBILITY is off', 'high', 'Oracle Parameter Settings', 'iam', _ora_param('o7_dictionary_accessibility', lambda v: v == 'FALSE', 'FALSE'),
     "ALTER SYSTEM SET o7_dictionary_accessibility = FALSE SCOPE = SPFILE;", "ALTER SYSTEM SET o7_dictionary_accessibility = TRUE SCOPE = SPFILE;"),
    ('ORA-CASE', 'Passwords are case sensitive', 'medium', 'Oracle Parameter Settings', 'iam', _ora_param('sec_case_sensitive_logon', lambda v: v == 'TRUE', 'TRUE'),
     "ALTER SYSTEM SET sec_case_sensitive_logon = TRUE SCOPE = BOTH;", "ALTER SYSTEM SET sec_case_sensitive_logon = FALSE SCOPE = BOTH;"),
    ('ORA-SYSAUDIT', 'SYS operations are audited', 'high', 'Oracle Parameter Settings', 'log', _ora_param('audit_sys_operations', lambda v: v == 'TRUE', 'TRUE'),
     "ALTER SYSTEM SET audit_sys_operations = TRUE SCOPE = SPFILE;", "ALTER SYSTEM SET audit_sys_operations = FALSE SCOPE = SPFILE;"),
    ('ORA-AUDIT', 'Database auditing is on (Unified Auditing or audit_trail)', 'high', 'Oracle Audit/Logging Policies', 'log', _ora_audit,
     "ALTER SYSTEM SET audit_trail = DB, EXTENDED SCOPE = SPFILE;   -- or enable Unified Auditing (relink) and the ORA_SECURECONFIG policy", "ALTER SYSTEM SET audit_trail = NONE SCOPE = SPFILE;"),
    ('ORA-PUBLIC', 'PUBLIC cannot execute network / file packages', 'high', 'Oracle User Access and Authorization (PUBLIC grants)', 'net', _ora_list('public_exec', 'EXECUTE granted to PUBLIC on', 'no risky package executable by PUBLIC'),
     "REVOKE EXECUTE ON <package> FROM PUBLIC;   -- grant it back to the schemas that need it", "GRANT EXECUTE ON <package> TO PUBLIC;"),
    ('ORA-DBA', 'Only SYS and SYSTEM hold the DBA role', 'high', 'Oracle User Access and Authorization (roles)', 'iam', _ora_list('dba_role', 'accounts with DBA', 'only SYS / SYSTEM hold DBA'),
     "REVOKE DBA FROM <grantee>;   -- give named DBAs the privileges they need, reviewed quarterly", "GRANT DBA TO <grantee>;"),
]


def _ms_cfg(name, want, sev_name):
    def t(db):
        rows = _rows(db, 'configs')
        if rows is None:
            return _db_nc(db, 'configs', MS_GRANT)
        v = {str(r[0]).lower(): r[1] for r in rows}.get(name.lower())
        if v is None:
            return N('%s does not exist on this SQL Server release' % name)
        return P('%s = %s' % (name, v)) if int(v) == want else F('%s = %s (should be %s)' % (name, v, want))
    return t


def _ms_list(name, fail_msg, pass_msg, grant=MS_GRANT):
    def t(db):
        rows = _rows(db, name)
        if rows is None:
            return _db_nc(db, name, grant)
        items = [str(r[0]) for r in rows]
        return F(fail_msg + ': ' + ', '.join(items[:10])) if items else P(pass_msg)
    return t


def _ms_sa(db):
    rows = _rows(db, 'sa')
    if rows is None:
        return _db_nc(db, 'sa', MS_GRANT)
    if not rows:
        return N('sa login not visible')
    name, disabled = str(rows[0][0]), rows[0][1] in (1, True, '1', 'True')
    bad = []
    if not disabled:
        bad.append('enabled')
    if name.lower() == 'sa':
        bad.append('not renamed')
    return F('the sa login is ' + ' and '.join(bad)) if bad else P('sa is disabled and renamed (%s)' % name)


def _ms_auth(db):
    rows = _rows(db, 'server')
    if not rows:
        return _db_nc(db, 'server', MS_GRANT)
    return P('Windows authentication only') if str(rows[0][0]) == '1' else F('mixed mode: SQL logins with passwords are allowed')


def _ms_audit(db):
    rows = _rows(db, 'audits')
    if rows is None:
        return _db_nc(db, 'audits', MS_GRANT)
    on = [str(r[0]) for r in rows if r[1] in (1, True, '1', 'True')]
    return P('server audit(s) running: ' + ', '.join(on[:5])) if on else F('no server audit is running - logins and permission changes are not recorded')


def _ms_version(db):
    rows = _rows(db, 'server')
    if not rows:
        return N('version not reported')
    v = str(rows[0][1])
    m = re.match(r'^(\d+)\.', v)
    return (P('SQL Server %s %s' % (v, rows[0][2])) if int(m.group(1)) >= 13 else F('SQL Server %s is out of extended support - upgrade' % v)) if m else N('version not read')


MSSQL = [
    ('MS-XPCMD', 'xp_cmdshell is disabled', 'critical', 'Surface Area Reduction', 'hard', _ms_cfg('xp_cmdshell', 0, 'critical'),
     "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;", "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"),
    ('MS-CLR', 'CLR is disabled (or strict security on)', 'medium', 'Surface Area Reduction', 'hard', _ms_cfg('clr enabled', 0, 'medium'),
     "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;", "EXEC sp_configure 'clr enabled', 1; RECONFIGURE;"),
    ('MS-ADHOC', 'Ad Hoc Distributed Queries are disabled', 'medium', 'Surface Area Reduction', 'hard', _ms_cfg('Ad Hoc Distributed Queries', 0, 'medium'),
     "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;", "EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;"),
    ('MS-OLE', 'OLE Automation procedures are disabled', 'medium', 'Surface Area Reduction', 'hard', _ms_cfg('Ole Automation Procedures', 0, 'medium'),
     "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;", "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"),
    ('MS-REMOTEACC', 'Remote access is disabled', 'medium', 'Surface Area Reduction', 'net', _ms_cfg('remote access', 0, 'medium'),
     "EXEC sp_configure 'remote access', 0; RECONFIGURE;   -- takes effect after a restart", "EXEC sp_configure 'remote access', 1; RECONFIGURE;"),
    ('MS-STARTUP', 'Startup procedures are not scanned', 'low', 'Surface Area Reduction', 'hard', _ms_cfg('scan for startup procs', 0, 'low'),
     "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE;", "EXEC sp_configure 'scan for startup procs', 1; RECONFIGURE;"),
    ('MS-XDB', 'Cross-database ownership chaining is off', 'medium', 'Surface Area Reduction', 'iam', _ms_cfg('cross db ownership chaining', 0, 'medium'),
     "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;", "EXEC sp_configure 'cross db ownership chaining', 1; RECONFIGURE;"),
    ('MS-TRACE', 'Default trace is enabled', 'low', 'Auditing and Logging', 'log', _ms_cfg('default trace enabled', 1, 'low'),
     "EXEC sp_configure 'default trace enabled', 1; RECONFIGURE;", "EXEC sp_configure 'default trace enabled', 0; RECONFIGURE;"),
    ('MS-SA', 'The sa login is disabled and renamed', 'high', 'Authentication and Authorization', 'iam', _ms_sa,
     "ALTER LOGIN [sa] DISABLE; ALTER LOGIN [sa] WITH NAME = [<new name>];", "ALTER LOGIN [<new name>] WITH NAME = [sa]; ALTER LOGIN [sa] ENABLE;"),
    ('MS-AUTH', 'Windows authentication only', 'medium', 'Authentication and Authorization', 'iam', _ms_auth,
     "-- SQL Server Configuration Manager / SSMS > Server properties > Security > Windows Authentication mode, then restart (move SQL logins to AD first)", "-- switch back to SQL Server and Windows Authentication mode, restart"),
    ('MS-POLICY', 'SQL logins enforce the Windows password policy and expiry', 'medium', 'Password Policies', 'iam', _ms_list('policy', 'SQL logins without CHECK_POLICY / CHECK_EXPIRATION', 'every enabled SQL login checks the password policy'),
     "ALTER LOGIN [<login>] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;", "ALTER LOGIN [<login>] WITH CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;"),
    ('MS-SYSADMIN', 'sysadmin members are few and named', 'medium', 'Authentication and Authorization', 'iam', lambda db: (lambda r: r if r[0] != 'pass' and r[0] != 'fail' else (F('sysadmin members: %d (%s)' % (len(_rows(db, 'sysadmins')), ', '.join(str(x[0]) for x in _rows(db, 'sysadmins')[:8]))) if len(_rows(db, 'sysadmins')) > 4 else P('sysadmin members: ' + ', '.join(str(x[0]) for x in _rows(db, 'sysadmins')[:8]))))(_ms_list('sysadmins', 'x', 'x')(db)),
     "ALTER SERVER ROLE sysadmin DROP MEMBER [<login>];   -- keep two named DBAs and the break-glass account", "ALTER SERVER ROLE sysadmin ADD MEMBER [<login>];"),
    ('MS-TRUST', 'No user database is TRUSTWORTHY', 'high', 'Authentication and Authorization', 'iam', _ms_list('trustworthy', 'TRUSTWORTHY databases', 'no user database is TRUSTWORTHY'),
     "ALTER DATABASE [<db>] SET TRUSTWORTHY OFF;", "ALTER DATABASE [<db>] SET TRUSTWORTHY ON;"),
    ('MS-PUBLIC', 'The public server role has only the default permissions', 'medium', 'Authentication and Authorization', 'iam', _ms_list('public_perms', 'extra permissions granted to public', 'public has only VIEW ANY DATABASE / CONNECT'),
     "REVOKE <permission> FROM public;", "GRANT <permission> TO public;"),
    ('MS-AUDIT', 'A server audit is running', 'high', 'Auditing and Logging', 'log', _ms_audit,
     "CREATE SERVER AUDIT [SIEM] TO APPLICATION_LOG; ALTER SERVER AUDIT [SIEM] WITH (STATE = ON); CREATE SERVER AUDIT SPECIFICATION [SIEM-spec] FOR SERVER AUDIT [SIEM] ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP), ADD (AUDIT_CHANGE_GROUP), ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP) WITH (STATE = ON);",
     "ALTER SERVER AUDIT SPECIFICATION [SIEM-spec] WITH (STATE = OFF); ALTER SERVER AUDIT [SIEM] WITH (STATE = OFF);"),
    ('MS-VERSION', 'SQL Server is a supported release (2016 or later)', 'high', 'Installation, Updates and Patches', 'vuln', _ms_version,
     "-- install the latest cumulative update; plan the upgrade of out-of-support releases", "-- uninstall the cumulative update from Programs and Features"),
]


def _pg_set(name, ok, want, grant=PG_GRANT):
    def t(db):
        rows = _rows(db, 'settings')
        if rows is None:
            return _db_nc(db, 'settings', grant)
        v = {str(r[0]): str(r[1]) for r in rows}.get(name)
        if v is None:
            return N('%s not visible to the monitoring login' % name)
        return P('%s = %s' % (name, v)) if ok(v) else F('%s = %s (should be %s)' % (name, v, want))
    return t


def _pg_hba(db):
    rows = _rows(db, 'hba')
    if rows is None:
        return _db_nc(db, 'hba', PG_GRANT)
    bad = ['%s %s %s %s' % (r[0], r[1], r[2], r[4]) for r in rows if str(r[4]) in ('trust', 'password', 'md5') or (str(r[0]) == 'host' and str(r[4]) not in ('reject',) and not str(r[0]).startswith('hostssl') and str(r[4]) not in ('peer', 'ident'))]
    weak = [x for x in bad if x.split()[-1] in ('trust', 'password')]
    nossl = [x for x in bad if x.split()[0] == 'host']
    if weak:
        return F('pg_hba allows trust / clear-text password: ' + '; '.join(weak[:5]))
    if nossl:
        return F('pg_hba allows network logins without TLS (host instead of hostssl): ' + '; '.join(nossl[:5]))
    return P('pg_hba uses hostssl with scram / certificate authentication')


def _pg_supers(db):
    rows = _rows(db, 'supers')
    if rows is None:
        return _db_nc(db, 'supers', PG_GRANT)
    names = [str(r[0]) for r in rows]
    return F('%d superusers: %s' % (len(names), ', '.join(names[:8]))) if len(names) > 2 else P('superusers: ' + ', '.join(names))


def _pg_version(db):
    rows = _rows(db, 'version')
    if not rows:
        return N('version not reported')
    v = str(rows[0][0])
    m = re.match(r'^(\d+)', v)
    return (P('PostgreSQL ' + v) if int(m.group(1)) >= 13 else F('PostgreSQL %s is out of community support - upgrade' % v)) if m else N('version not read')


PG = [
    ('PG-SSL', 'TLS is enabled', 'high', 'Connection and Login', 'crypto', _pg_set('ssl', lambda v: v == 'on', 'on'),
     "ALTER SYSTEM SET ssl = 'on';   -- with ssl_cert_file / ssl_key_file set; SELECT pg_reload_conf();", "ALTER SYSTEM SET ssl = 'off'; SELECT pg_reload_conf();"),
    ('PG-SCRAM', 'Passwords are stored as SCRAM-SHA-256', 'high', 'Connection and Login', 'crypto', _pg_set('password_encryption', lambda v: v.lower() == 'scram-sha-256', 'scram-sha-256'),
     "ALTER SYSTEM SET password_encryption = 'scram-sha-256'; SELECT pg_reload_conf();   -- then reset each password so it is re-hashed", "ALTER SYSTEM SET password_encryption = 'md5'; SELECT pg_reload_conf();"),
    ('PG-HBA', 'pg_hba: no trust / clear-text, network logins over TLS', 'critical', 'Connection and Login', 'iam', _pg_hba,
     "-- pg_hba.conf: replace trust / password / md5 with scram-sha-256, host with hostssl; then SELECT pg_reload_conf();", "-- restore the previous pg_hba.conf and SELECT pg_reload_conf();"),
    ('PG-LOGCONN', 'Connections and disconnections are logged', 'medium', 'Logging Monitoring and Auditing', 'log', lambda db: (lambda a, b: a if a[0] != 'pass' else b)(_pg_set('log_connections', lambda v: v == 'on', 'on')(db), _pg_set('log_disconnections', lambda v: v == 'on', 'on')(db)),
     "ALTER SYSTEM SET log_connections = 'on'; ALTER SYSTEM SET log_disconnections = 'on'; SELECT pg_reload_conf();", "ALTER SYSTEM SET log_connections = 'off'; ALTER SYSTEM SET log_disconnections = 'off'; SELECT pg_reload_conf();"),
    ('PG-LOGSTMT', 'DDL statements are logged', 'medium', 'Logging Monitoring and Auditing', 'log', _pg_set('log_statement', lambda v: v in ('ddl', 'mod', 'all'), 'ddl'),
     "ALTER SYSTEM SET log_statement = 'ddl'; SELECT pg_reload_conf();", "ALTER SYSTEM SET log_statement = 'none'; SELECT pg_reload_conf();"),
    ('PG-AUDIT', 'pgAudit is loaded', 'medium', 'Logging Monitoring and Auditing', 'log', _pg_set('shared_preload_libraries', lambda v: 'pgaudit' in v, 'includes pgaudit'),
     "ALTER SYSTEM SET shared_preload_libraries = 'pgaudit';   -- keep the existing libraries; restart, then CREATE EXTENSION pgaudit; ALTER SYSTEM SET pgaudit.log = 'ddl,role';", "-- remove pgaudit from shared_preload_libraries and restart"),
    ('PG-LISTEN', 'PostgreSQL listens only on the needed addresses', 'low', 'Connection and Login', 'net', _pg_set('listen_addresses', lambda v: v.strip() not in ('*', '0.0.0.0', '::'), 'specific addresses'),
     "ALTER SYSTEM SET listen_addresses = '<server address>';   -- restart", "ALTER SYSTEM SET listen_addresses = '*';"),
    ('PG-SUPERS', 'Superusers are few (2 or fewer)', 'medium', 'User Access and Authorization', 'iam', _pg_supers,
     "ALTER ROLE <role> NOSUPERUSER;   -- grant the predefined roles it needs instead", "ALTER ROLE <role> SUPERUSER;"),
    ('PG-PUBLIC', 'PUBLIC cannot create objects in the public schema', 'medium', 'User Access and Authorization', 'iam', lambda db: _db_nc(db, 'public_create', PG_GRANT) if _rows(db, 'public_create') is None else (F('PUBLIC may CREATE in schema public') if _rows(db, 'public_create') and str(_rows(db, 'public_create')[0][0]).lower() in ('true', '1') else P('PUBLIC cannot CREATE in schema public')),
     "REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- in each database", "GRANT CREATE ON SCHEMA public TO PUBLIC;"),
    ('PG-VERSION', 'PostgreSQL is a supported release (13 or later)', 'high', 'Installation and Patches', 'vuln', _pg_version,
     "-- install the latest minor release; plan the major upgrade (pg_upgrade)", "-- reinstall the previous minor release"),
]

DB_SETS = {'oracle': ('CIS Oracle Database Benchmark', ORA, 'Oracle'), 'mssql': ('CIS Microsoft SQL Server Benchmark', MSSQL, 'SQL Server'), 'postgres': ('CIS PostgreSQL Benchmark', PG, 'PostgreSQL')}


def db_checks(db, idx):
    bench, rules, label = DB_SETS.get(db.get('engine'), (None, [], ''))
    if not bench:
        return []
    tag = '%s %s' % (label, db.get('instance') or '')
    login = db.get('login') or '<login>'
    if not db.get('results'):
        return [_check('DB-READ-%d' % idx, '[%s] the database could be read' % tag.strip(), 'medium', bench, 'Read access', 'hard', 'not_checked',
                       'the read-only login could not read it: ' + str(db.get('error') or 'not read yet - press Scan now'), lang='sql')]
    out = []
    for cid, title, sev, sec, dom, t, fix, rb in rules:
        st, ev = t(db)
        ev = ev.replace('<login>', login)
        out.append(_check('%s-%d' % (cid, idx), '[%s] %s' % (tag.strip(), title), sev, bench, sec, dom, st, ev, fix, rb, lang='sql'))
    return out


def _check(cid, title, sev, cis_bench, cis_sec, dom, state, evidence, fix='', rollback='', lang=None):
    s, n = DOMAIN.get(dom, DOMAIN['hard'])
    refs = [SAMA_HARD, NCA_HARD] + ([s, n] if dom != 'hard' else [])
    out = {'id': cid, 'title': title, 'severity': sev, 'cis': '%s - %s' % (cis_bench, cis_sec), 'refs': refs, 'state': state, 'evidence': str(evidence)[:400]}
    if state == 'fail':
        out['fix'], out['rollback'] = fix, rollback
    if lang:
        out['lang'] = lang
    return out


def _bench_win(d):
    cap = str((d.get('os') or {}).get('caption') or '')
    m = re.search(r'Windows (Server \d{4}|1[01])', cap)
    return 'CIS Microsoft Windows %s Benchmark' % (m.group(1) if m else ('11 / Server' if _ptype(d) == 'workstation' else 'Server'))


def windows(d, now):
    bench, out = _bench_win(d), []
    for cid, title, sev, sec, dom, t, fix, rb in WIN:
        r = _hotfix(d, now) if cid == 'WIN-PATCH' else t(d)
        if r is None:
            continue
        out.append(_check(cid, title, sev, bench, sec, dom, r[0], r[1], fix, rb))
    return out + components(d, now)


def unix(h, plat):
    bench = 'CIS Oracle Solaris 11 Benchmark' if plat == 'solaris' else 'CIS Oracle Linux Benchmark'
    out = []
    for cid, title, sev, sec, dom, t, fix, rb in UX:
        r = t(h, plat)
        if r is None:
            continue
        out.append(_check(cid, title, sev, bench, sec, dom, r[0], r[1], fix, rb))
    return out


def ios(text):
    import infra_audit_rules as IA
    found = {}
    for k, sev, t, det, rec in IA.ios_checks(text or ''):
        found.setdefault(k.split(':')[0], []).append((t, det if isinstance(det, str) else str(det), rec))
    out = []
    for k, title, sev, dom in IOS_KEYS:
        if k in found:
            f = found[k]
            out.append(_check('IOS-' + k.upper(), title, sev, 'CIS Cisco IOS Benchmark', 'Management / Control / Data plane', dom, 'fail',
                              '; '.join(x[0] for x in f)[:400], f[0][2], 'Restore the previous line from the saved configuration (show archive / the SIEM capture)'))
        else:
            out.append(_check('IOS-' + k.upper(), title, sev, 'CIS Cisco IOS Benchmark', 'Management / Control / Data plane', dom, 'pass', 'not found in the running-config'))
    return out


def firewall(dev, now):
    vendor = dev.get('vendor') or ''
    bench = {'fortigate': 'CIS Fortinet FortiGate Benchmark', 'paloalto': 'CIS Palo Alto Firewall Benchmark', 'cisco-asa': 'CIS Cisco ASA Benchmark'}.get(vendor, 'CIS firewall benchmark')
    sa = ms(dev.get('security_at'))
    fresh = sa and now and now - sa <= 2 * DAY
    reviewable = (dev.get('monitoring') or {}).get('api') and not any('not allowed' in str(e) for e in dev.get('security_errors') or [])
    seen = {}
    for it in dev.get('security') or []:
        k = FW_KIND.get(it.get('kind'))
        if k:
            seen.setdefault(k, []).append((it.get('key') or '') + ' ' + (it.get('title') or ''))
    if vendor == 'paloalto' and isinstance(dev.get('facts'), dict):
        # the configuration was read: judge it against the CIS PAN-OS benchmark; a failed management probe (Telnet / HTTP
        # answering) still counts against the device
        out = paloalto(dev['facts'])
        if 'mgmt-clear' in seen:
            out.append(_check('FW-MGMT-CLEAR', 'No management over Telnet / HTTP', 'high', bench, 'Device management', 'crypto', 'fail', '; '.join(x.strip() for x in seen['mgmt-clear'])[:400],
                              'Disable Telnet and HTTP administration; SSH and HTTPS from the management network only', 'set deviceconfig system service disable-telnet no'))
        return out
    out = []
    for k, title, sev, dom, fix in FW_KEYS:
        if k in seen:
            out.append(_check('FW-' + k.upper(), title, sev, bench, 'Device management / Policy', dom, 'fail', '; '.join(x.strip() for x in seen[k])[:400], fix,
                              'Re-apply the previous policy revision (FortiGate: revision history / PAN-OS: load config version)'))
        elif not reviewable:
            out.append(_check('FW-' + k.upper(), title, sev, bench, 'Device management / Policy', dom, 'not_checked', 'no read-only API key with configuration read: the rule base cannot be reviewed'))
        elif not fresh:
            out.append(_check('FW-' + k.upper(), title, sev, bench, 'Device management / Policy', dom, 'not_checked', 'no security check in the last 48 hours (SIEM network poller)'))
        else:
            out.append(_check('FW-' + k.upper(), title, sev, bench, 'Device management / Policy', dom, 'pass', 'not found by the latest check'))
    return out


def score(checks):
    w_all = sum(W[c['severity']] for c in checks if c['state'] in ('pass', 'fail'))
    w_ok = sum(W[c['severity']] for c in checks if c['state'] == 'pass')
    counts = {s: len([c for c in checks if c['state'] == s]) for s in ('pass', 'fail', 'not_checked')}
    counts['critical_fail'] = len([c for c in checks if c['state'] == 'fail' and c['severity'] in ('critical', 'high')])
    return (rnd(100.0 * w_ok / w_all) if w_all else None), counts


def assess(req):
    now = req.get('now')
    max_age = (req.get('max_age_days') or 7) * DAY
    out = []
    for a in req.get('assets') or []:
        kind, data = a.get('kind'), a.get('data')
        base = {k: a.get(k) for k in ('id', 'name', 'ip', 'platform', 'kind', 'site', 'criticality')}
        dbs = [x for x in (a.get('dbs') or []) if isinstance(x, dict)]
        if not data and not dbs:
            out.append(dict(base, state='not_scanned', why=a.get('why') or 'no scan source for this asset', at=None, score=None, counts={'pass': 0, 'fail': 0, 'not_checked': 0, 'critical_fail': 0}, checks=[]))
            continue
        at_s = a.get('at') or max([x.get('at') or '' for x in dbs] or ['']) or None
        at = ms(at_s)
        if not data:
            checks = []
        elif kind == 'windows':
            checks = windows(data, now)
        elif kind == 'unix':
            checks = unix(data, a.get('platform') or 'linux')
        elif kind == 'ios':
            checks = ios(data)
        elif kind == 'firewall':
            checks = firewall(data, now)
        elif kind == 'esxi':
            checks = esxi(data)
        elif kind == 'nutanix':
            checks = nutanix(data)
        elif kind == 'proxmox':
            checks = proxmox(data)
        else:
            checks = []
        for i, db in enumerate(dbs[:20]):
            checks = checks + db_checks(db, i + 1)
        sc, counts = score(checks)
        st = 'stale' if (at and now and now - at > max_age) else 'scanned'
        out.append(dict(base, state=st, partial=not data or None, at=at_s, score=sc, counts=counts, checks=checks))
    scanned = [x for x in out if x['state'] != 'not_scanned']
    by = {}
    for x in out:
        b = by.setdefault(x.get('platform') or 'other', {'assets': 0, 'scanned': 0, 'score_sum': 0, 'scored': 0, 'fail': 0})
        b['assets'] += 1
        if x['state'] != 'not_scanned':
            b['scanned'] += 1
            b['fail'] += x['counts']['fail']
            if x['score'] is not None:
                b['score_sum'] += x['score']
                b['scored'] += 1
    for b in by.values():
        ssum, n = b.pop('score_sum'), b.pop('scored')
        b['score'] = rnd(ssum / n) if n else None
    scores = [x['score'] for x in scanned if x['score'] is not None]
    top = {}
    for x in scanned:
        for c in x['checks']:
            if c['state'] == 'fail':
                t = top.setdefault(c['id'], {'id': c['id'], 'title': c['title'], 'severity': c['severity'], 'assets': 0})
                t['assets'] += 1
    return {'ok': True, 'assets': out, 'summary': {
        'assets': len(out), 'scanned': len(scanned), 'not_scanned': len(out) - len(scanned), 'stale': len([x for x in out if x['state'] == 'stale']),
        'coverage_pct': rnd(100.0 * len(scanned) / len(out)) if out else None,
        'score': rnd(sum(scores) / len(scores)) if scores else None,
        'fail': sum(x['counts']['fail'] for x in scanned), 'critical_fail': sum(x['counts']['critical_fail'] for x in scanned),
        'by_platform': by,
        'top_failures': sorted(top.values(), key=lambda t: (-W[t['severity']], -t['assets']))[:15],
    }}


COMMENT = {'windows': '#', 'unix': '#', 'ios': '!', 'firewall': '#', 'esxi': '#', 'nutanix': '#', 'proxmox': '#', 'sql': '--'}


def script(req):
    kind = req.get('kind') or 'windows'
    checks = [x for x in req.get('checks') or [] if x.get('fix')]
    if not checks:
        return {'ok': False, 'error': 'no failed check with a fix was selected'}
    shells = {'windows': 'PowerShell (run elevated)', 'unix': 'sh (as root)', 'ios': 'Cisco IOS configuration mode', 'firewall': 'the firewall console',
              'esxi': 'VMware PowerCLI after Connect-VIServer <vCenter>', 'nutanix': 'a CVM shell (ncli) as an administrator',
              'proxmox': 'a Proxmox node shell as root (pvesh / pveum)', 'sql': 'the database client as a DBA (sqlplus / sqlcmd / psql)'}
    # the OS fixes and the database fixes run in different tools, so each gets its own section and comment syntax
    groups = []
    for lang in [kind, 'sql']:
        g = [x for x in checks if (x.get('lang') == 'sql') == (lang == 'sql')]
        if g:
            groups.append((lang, g))
    L = []
    for lang, g in groups:
        c = COMMENT.get(lang, '#')
        L += ['%s ===== REVIEW BEFORE RUNNING ===== baseline hardening fixes for %s (%s)' % (c, req.get('name') or '?', 'databases' if lang == 'sql' else (req.get('platform') or kind)),
              '%s Generated by the platform from the baseline scan. Nothing was changed on the device. Run in %s,' % (c, shells.get(lang, '')),
              '%s in an approved change window (SAMA CSF 3.3.7 change management), after a backup / snapshot.' % c, '']
        for x in g:
            L += ['%s [%s] %s' % (c, x.get('id'), x.get('title') or ''), str(x.get('fix')), '']
        L += ['%s ===== ROLLBACK (only if a fix breaks something) =====' % c]
        for x in g:
            L += ['%s [%s] undo' % (c, x.get('id')), '%s %s' % (c, x.get('rollback') or 'restore from the backup taken before the change'), '']
        L.append('')
    return {'ok': True, 'script': '\n'.join(L).rstrip() + '\n', 'sql': any(lang == 'sql' for lang, _ in groups), 'os': any(lang != 'sql' for lang, _ in groups)}


OPS = {
    'hardening.assess': assess,
    'hardening.script': script,
}
