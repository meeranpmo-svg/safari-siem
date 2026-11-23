# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""SNMP device collection for Asset Discovery - migration step 5c (docs/PYTHON-MIGRATION.md). Answers exactly like
collect() in engine/discovery/methods/snmp.js: system group, interface MACs, ENTITY-MIB serial / model, LLDP and CDP
neighbours, the device's ARP table. Read-only (snmp_client.py cannot encode a SetRequest).
The per-address liveness probe of a sweep stays in Node.js (one shared UDP socket for thousands of addresses).
  collect(host, cred, opts) -> {ok, sys{descr, object_id, name, location}, macs[], mac, serial, model, neighbours[], arp[], latency_ms}
  SNMPv3 privacy without the `cryptography` package -> {ok: False, error_class: 'missing_python'} (the Node.js reader answers)
"""
import re
import time

import snmp_client as S

OID = {'sysDescr': '1.3.6.1.2.1.1.1.0', 'sysObjectID': '1.3.6.1.2.1.1.2.0', 'sysName': '1.3.6.1.2.1.1.5.0', 'sysLocation': '1.3.6.1.2.1.1.6.0',
       'ipNetToMediaPhysAddress': '1.3.6.1.2.1.4.22.1.2', 'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6', 'ifName': '1.3.6.1.2.1.31.1.1.1.1',
       'entPhysicalEntry': '1.3.6.1.2.1.47.1.1.1.1', 'lldpRemEntry': '1.0.8802.1.1.2.1.4.1.1', 'lldpLocPortEntry': '1.0.8802.1.1.2.1.3.7.1',
       'lldpRemManAddrEntry': '1.0.8802.1.1.2.1.4.2.1', 'cdpCacheEntry': '1.3.6.1.4.1.9.9.23.1.2.1.1'}
AUTH_CODES = ('wrongDigests', 'unknownUserNames', 'authenticationFailure', 'decryptionError', 'unsupportedSecLevels', 'authorizationError', 'noAccess')


def session_options(cred, o):
    t = cred.get('target') if isinstance(cred.get('target'), dict) else {}
    s = cred.get('secret') if isinstance(cred.get('secret'), dict) else {}
    base = {'port': t.get('port') or 161, 'timeout_ms': o.get('timeout') or 1500, 'retries': 1 if o.get('retries') is None else o.get('retries'), 'max_repetitions': 20}
    kind = cred.get('kind')
    if kind == 'snmp_v2c':
        base.update(version='2c', community=s.get('community'))
        return base
    if kind == 'snmp_v3':
        priv = bool(s.get('priv_password')) and t.get('priv_protocol') != 'none'
        base.update(version='3', user=s.get('user'), auth_protocol=t.get('auth_protocol') or 'sha', auth_password=s.get('auth_password'),
                    priv_protocol='aes' if priv else None, priv_password=s.get('priv_password') if priv else None)
        return base
    raise S.SnmpError('config', 'credential kind %s is not SNMP' % kind)


def error_class(e):
    c = getattr(e, 'code', None)
    if c == 'timeout':
        return 'timeout'
    if c in AUTH_CODES:
        return 'auth'
    if c == 'config':
        return 'config'
    if c == 'send':
        return 'unreachable'
    return 'protocol'


def mac_of(b):
    return ':'.join('%02x' % x for x in b) if isinstance(b, bytes) and len(b) == 6 and any(b) else None


def st(vb):
    return S.vb_string(vb)


def _jsnum(s):
    """Number(s) for an OID part ('' = 0, not a number = NaN)"""
    if s == '':
        return 0
    return int(s) if re.match(r'^\d+$', s) else float('nan')


def _jstr(n):
    return 'NaN' if isinstance(n, float) and n != n else str(n)


def decode_man_addr_index(suffix):
    p = [_jsnum(x) for x in suffix.split('.')]
    if len(p) < 6:
        return None
    tm, lp, ri, sub, ln = p[:5]
    addr = p[5:5 + ln] if isinstance(ln, int) else []
    ok = sub == 1 and ln == 4 and len(addr) == 4 and all(isinstance(a, int) for a in addr)
    return {'key': '%s.%s.%s' % (_jstr(tm), _jstr(lp), _jstr(ri)), 'localPort': lp, 'ip': '.'.join(str(a) for a in addr) if ok else None}


def parse_lldp(rem_rows, loc_rows, man_vbs):
    local = {r['index']: (st(r['cols'].get(4)) or st(r['cols'].get(3)) or r['index']) for r in (loc_rows or [])}
    ip_by_key = {}
    for vb in man_vbs or []:
        d = decode_man_addr_index(vb['oid'][len(OID['lldpRemManAddrEntry']) + 3:])
        if d and d['ip'] and d['key'] not in ip_by_key:
            ip_by_key[d['key']] = d['ip']
    out = []
    for r in rem_rows or []:
        parts = r['index'].split('.')
        lp = parts[1] if len(parts) > 1 else None
        sub = S.vb_number(r['cols'].get(4))
        c5 = r['cols'].get(5)
        raw = c5['value'] if c5 and isinstance(c5.get('value'), bytes) else None
        out.append({'via': 'lldp', 'local_port': local.get(lp) or lp or None, 'remote_name': st(r['cols'].get(9)) or None,
                    'remote_port': st(r['cols'].get(8)) or st(r['cols'].get(7)) or None, 'remote_mac': mac_of(raw) if sub == 4 else None,
                    'remote_chassis': mac_of(raw) if sub == 4 else (st(c5) or None), 'remote_ip': ip_by_key.get(r['index'])})
    return out


def parse_cdp(rows, if_names):
    out = []
    for r in rows or []:
        if_index = r['index'].split('.')[0]
        at = S.vb_number(r['cols'].get(3))
        c4 = r['cols'].get(4)
        addr = c4['value'] if c4 and isinstance(c4.get('value'), bytes) else None
        out.append({'via': 'cdp', 'local_port': (if_names or {}).get(if_index) or if_index or None, 'remote_name': st(r['cols'].get(6)) or None,
                    'remote_port': st(r['cols'].get(7)) or None, 'remote_platform': st(r['cols'].get(8)) or None,
                    'remote_ip': '.'.join(str(x) for x in addr) if at == 1 and addr and len(addr) == 4 else None, 'remote_mac': None, 'remote_chassis': None})
    return out


def parse_arp(vbs):
    out, seen = [], set()
    for vb in vbs:
        p = str(vb.get('oid') or '')[len(OID['ipNetToMediaPhysAddress']) + 1:].split('.')
        if len(p) != 5:
            continue
        ip, mac = '.'.join(p[1:]), mac_of(vb.get('value'))
        if not mac or mac == 'ff:ff:ff:ff:ff:ff' or re.match(r'^0\.|^127\.|^2(2[4-9]|3\d)\.', ip) or ip in seen:
            continue
        seen.add(ip)
        out.append({'ip': ip, 'mac': mac})
    return out


def model_from_descr(d):
    if not d:
        return None
    m = (re.search(r'\b((?:WS-|C)\d{4}[A-Z]{0,2}(?:-[A-Z0-9]+)+)\b', d, re.I) or re.search(r'\b(Catalyst\s+\d{4}[A-Z]?(?:\s+Series)?)', d, re.I)
         or re.search(r'\b(Nexus\s*\d{4}[A-Z0-9-]*)', d, re.I))
    return m.group(1).strip() if m and not re.search(r'K9|-M$|UNIVERSAL|IPBASE|LANBASE', m.group(1), re.I) else None


def model_from_sys_descr(d):
    if not d or not re.search('cisco', d, re.I):
        return None
    direct = model_from_descr(d)
    if direct:
        return direct
    img = re.search(r'\(([A-Z0-9_]+?)(?:-[A-Z0-9]+)*-M\)|\((CAT\d+K[A-Z0-9_]*)\)|\b(C\d{4}[A-Z]{0,3})\s+Software', d, re.I)
    if not img:
        return None
    code = (img.group(1) or img.group(2) or img.group(3)).upper()
    fam = re.match(r'^CAT(\d+)K', code)
    if fam:
        return 'Catalyst %s000 series (%s)' % (fam.group(1), code)
    c = re.match(r'^C(\d{4})([A-Z]{0,3})', code)
    return ('Catalyst %s%s series (%s)' % (c.group(1), '-' + c.group(2) if c.group(2) else '', code)) if c else 'Cisco (%s)' % code


def _entity_rows(s, soft):
    base, rows = OID['entPhysicalEntry'], {}
    for col in (5, 2, 11, 13):
        for vb in soft(lambda: s.walk('%s.%d' % (base, col), 2000)) or []:
            idx = vb['oid'][len(base) + 2 + len(str(col)):]
            rows.setdefault(idx, {'index': idx, 'cols': {}})['cols'][col] = vb
    return list(rows.values())


def collect(host, cred, o):
    t0 = time.time()
    sess = None
    try:
        sess = S.Session(host, **session_options(cred, o))
        sysv = sess.get([OID['sysDescr'], OID['sysObjectID'], OID['sysName'], OID['sysLocation']])
        g = lambda i: sysv[i] if i < len(sysv) else None   # noqa: E731
        res = {'ok': True, 'latency_ms': 0,
               'sys': {'descr': st(g(0)) or None, 'object_id': g(1)['value'] if g(1) and g(1)['type'] == 'OID' else None, 'name': st(g(2)) or None, 'location': st(g(3)) or None},
               'macs': [], 'mac': None, 'serial': None, 'model': None, 'neighbours': []}

        def soft(fn):   # optional MIBs may be absent
            try:
                return fn()
            except S.NeedsCrypto:
                raise
            except Exception:   # noqa: BLE001
                return None
        for vb in soft(lambda: sess.walk(OID['ifPhysAddress'], 512)) or []:
            m = mac_of(vb.get('value'))
            if m and m not in res['macs']:
                res['macs'].append(m)
        res['mac'] = res['macs'][0] if res['macs'] else None
        ent = _entity_rows(sess, soft)
        if ent:
            with_serial = [r for r in ent if st(r['cols'].get(11))]
            chassis = (next((r for r in with_serial if S.vb_number(r['cols'].get(5)) == 3), None) or (with_serial[0] if with_serial else None)
                       or next((r for r in ent if S.vb_number(r['cols'].get(5)) == 3), None))
            if chassis:
                res['serial'] = st(chassis['cols'].get(11)) or None
                res['model'] = st(chassis['cols'].get(13)) or model_from_descr(st(chassis['cols'].get(2))) or None
        if not res['model']:
            res['model'] = model_from_sys_descr(res['sys']['descr'])
        rem = soft(lambda: sess.table(OID['lldpRemEntry'], 2000))
        if rem:
            loc = soft(lambda: sess.table(OID['lldpLocPortEntry'], 2000))
            man = soft(lambda: sess.walk(OID['lldpRemManAddrEntry'] + '.3', 2000))
            res['neighbours'].extend(parse_lldp(rem, loc, man))
        cdp = soft(lambda: sess.table(OID['cdpCacheEntry'], 2000))
        if cdp:
            names = soft(lambda: sess.walk(OID['ifName'], 2000))
            if_names = {vb['oid'].split('.')[-1]: st(vb) for vb in (names or [])}
            res['neighbours'].extend(parse_cdp(cdp, if_names))
        res['arp'] = parse_arp(soft(lambda: sess.walk(OID['ipNetToMediaPhysAddress'], 20000)) or [])
        res['latency_ms'] = int((time.time() - t0) * 1000)
        return res
    except S.NeedsCrypto as e:
        return {'ok': False, 'error_class': 'missing_python', 'error': str(e)}
    except Exception as e:   # noqa: BLE001 - classified like the Node.js method
        return {'ok': False, 'error_class': error_class(e), 'latency_ms': int((time.time() - t0) * 1000)}
    finally:
        if sess:
            sess.close()
