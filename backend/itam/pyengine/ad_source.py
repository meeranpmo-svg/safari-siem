# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Active Directory computer objects - migration step 5b (docs/PYTHON-MIGRATION.md). Answers exactly like
engine/discovery/methods/ad.js: LDAPS (or LDAP + StartTLS - never cleartext) through ldap_client.py, one simple bind with
the discovery service account, a paged subtree search. Nothing is written.
  collect(cred, opts) -> {ok, computers[{dn, name, fqdn, os, os_version, last_logon, ou, enabled, is_dc}], latency_ms}
  test(cred, opts)    -> the diag result
Standard library only (Python 3.8+).
"""
import math
import re
import time
from datetime import datetime, timedelta, timezone

import diag
import ldap_client as L

ATTRS = ['cn', 'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'distinguishedName', 'primaryGroupID']
DEFAULT_CA = '/etc/ssl/corp-hq/corp-ca.pem'


def ou_of(dn):
    parts = re.split(r',(?=(?:OU|CN|DC)=)', dn or '', flags=re.I)
    ous = [p[3:] for p in parts if re.match(r'^OU=', p, re.I)]
    if ous:
        return ' / '.join(ous)
    return 'Computers' if any(re.match(r'^CN=Computers$', p, re.I) for p in parts) else None


def _number(s):
    """Number(s) || 0, then ToInt32 for the bit test"""
    try:
        n = float(s.strip()) if s.strip() else 0.0
    except ValueError:
        return 0
    if not math.isfinite(n):
        return 0
    return int(n)


def _iso_ms(ms):
    t = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)


def file_time_to_ms(v):
    s = ('' if v is None else str(v)).strip()
    if not re.match(r'^\d+$', s) or s == '0' or s == '9223372036854775807':
        return 0
    ms = float(s) / 1e4 - L.FILETIME_EPOCH_MS
    return math.floor(ms + 0.5) if ms > 0 else 0


def map_entry(e):
    def g(n):
        return L.first(e, n)
    uac = _number(g('userAccountControl'))
    ms = file_time_to_ms(g('lastLogonTimestamp'))
    dn = e.get('dn') or g('distinguishedName')
    ou = ou_of(dn)
    pg = g('primaryGroupID')
    return {'dn': dn, 'name': g('cn') or g('name') or L.first_rdn_value(dn), 'fqdn': (g('dNSHostName') or '').lower() or None,
            'os': g('operatingSystem') or None, 'os_version': g('operatingSystemVersion') or None,
            'last_logon': _iso_ms(ms) if ms else None, 'ou': ou, 'enabled': not (uac & L.UAC_ACCOUNTDISABLE),
            'is_dc': pg == '516' or pg == '521' or bool(re.search('domain controllers', ou or '', re.I))}


def classify(e):
    c = getattr(e, 'code', None)
    msg = str(e)
    if c in (49, 'EMPTY_PASSWORD', 'EMPTY_DN', 48):
        return 'auth', 'auth', True
    if c == 50:
        return 'authz', 'authz', True
    if c == 'CA_FILE':
        return 'config', 'config', False
    if re.search(r'certificate|TLS|self.signed|altname', msg, re.I):
        return 'tls', 'tls', False
    if c == 'TIMEOUT':
        return 'timeout', 'connect', False
    if getattr(e, 'transport', False):
        return 'unreachable', 'connect', False
    if isinstance(e, L.LdapError) and re.search('invalid LDAP server URL|invalid ip', msg):
        return 'config', 'config', False
    return 'protocol', 'read', True


def _client(cred, o):
    t = cred.get('target') if isinstance(cred.get('target'), dict) else {}
    servers = [{'url': u, 'ip': t['ip']} if t.get('ip') and i == 0 else u for i, u in enumerate(t.get('servers') or [])]
    return L.Client({'servers': servers, 'caFile': t.get('ca_file') or o.get('caFile') or DEFAULT_CA, 'timeoutMs': o.get('timeoutMs') or 15000})


def _sec(cred):
    s = cred.get('secret') if isinstance(cred.get('secret'), dict) else {}
    return s.get('bind_dn'), s.get('password')


def _base(cred):
    t = cred.get('target') if isinstance(cred.get('target'), dict) else {}
    return t.get('base_dn')


def _ms(t0):
    return int((time.time() - t0) * 1000)


def collect(cred, o):
    t0 = time.time()
    try:
        c = _client(cred, o)
        dn, pw = _sec(cred)

        def fn(conn):
            conn.bind(dn, pw)
            return conn.search(_base(cred), {'scope': 'sub', 'filter': '(objectClass=computer)', 'attributes': ATTRS, 'pageSize': 500, 'maxEntries': o.get('maxEntries') or 50000})
        r = c.run(fn)
        return {'ok': True, 'computers': [map_entry(x) for x in r['entries']], 'latency_ms': _ms(t0)}
    except Exception as e:   # noqa: BLE001 - every failure is classified, as in Node.js
        return {'ok': False, 'error_class': classify(e)[0], 'latency_ms': _ms(t0)}


def test(cred, o):
    t0 = time.time()
    try:
        c = _client(cred, o)
        dn, pw = _sec(cred)

        def fn(conn):
            conn.bind(dn, pw)
            return conn.search(_base(cred), {'scope': 'base', 'filter': '(objectClass=*)', 'attributes': ['distinguishedName'], 'maxEntries': 1})
        c.run(fn)
        return diag.result('ldap', _ms(t0))
    except Exception as e:   # noqa: BLE001
        code, stage, trusted = classify(e)
        return diag.from_error('ldap', diag.DErr(code, str(e), stage, None, trusted), _ms(t0))
