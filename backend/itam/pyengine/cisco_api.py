# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Cisco Support API exchange - migration step 3 (docs/PYTHON-MIGRATION.md). Answers exactly like coverageFetch() in
engine/cisco-support.js: serial numbers in, one entry per serial out, in the order Cisco answered. Nothing is stored.

coverage({token_url, base_url, client_id, client_secret, serials, per_call})
  -> {entries: [[serial, data, kind]], error?, error_class?}     kind = covered | not_covered | unknown
Only the OAuth token POST and the coverage-summary GET (CISCO_CALLS) are ever sent; entries of the batches read before an
error are kept. Standard library only (Python 3.8+).
"""
import json
import re
import urllib.parse

import httpc
from jscompat import form_encode, iso, js_str, truthy

CISCO_CALLS = [('POST', re.compile(r'^/oauth2/default/v1/token$|^/as/token\.oauth2$')),
               ('GET', re.compile(r'^/sn2info/v2/coverage/summary/serial_numbers/[A-Z0-9,]{1,4000}$'))]
LOOPBACK_HOSTS = {'127.0.0.1', 'localhost'}
PER_CALL = 50
_CTRL = re.compile('[\u0000-\u001f\u007f]')
_MON = 'jan feb mar apr may jun jul aug sep oct nov dec'.split(' ')


class _Fail(Exception):
    def __init__(self, message, error_class=None):
        super().__init__(message)
        self.error_class = error_class


def s(v, max_len=200):
    """String(v == null ? '' : v) without control characters, trimmed, cut"""
    return _CTRL.sub(' ', '' if v is None else js_str(v)).strip()[:max_len or 200]


def norm_serial(v):
    """String(v || '').toUpperCase(), A-Z 0-9 only, 40 characters"""
    return re.sub(r'[^A-Z0-9]', '', js_str(v).upper() if truthy(v) else '')[:40]


def date_of(v):
    t = (js_str(v) if truthy(v) else '').strip()
    if not t:
        return None
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})', t)
    if m:
        return '%s-%s-%s' % m.groups()
    m = re.match(r'^(\d{1,2})[-/ ]([A-Za-z]{3})[A-Za-z]*[-/ ](\d{2,4})$', t)      # 15-Mar-2027 (CCW)
    if m and m.group(2).lower() in _MON:
        y = '20' + m.group(3) if len(m.group(3)) == 2 else m.group(3)
        return '%s-%02d-%s' % (y, _MON.index(m.group(2).lower()) + 1, m.group(1).rjust(2, '0'))
    m = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', t)                              # dd/mm/yyyy (Saudi exports)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        d, mo = (a, b) if a > 12 else (b, a) if b > 12 else (a, b)
        return '%s-%02d-%02d' % (m.group(3), mo, d)
    p = iso(t)   # Date.parse fallback: the ISO forms (the Cisco API writes YYYY-MM-DD, caught above)
    return p[:10] if p else None


def allowed(method, url):
    try:
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or '')
    except ValueError:
        return False
    if not (u.scheme == 'https' or (u.scheme == 'http' and host in LOOPBACK_HOSTS)):
        return False
    return any(m == method and rx.search(u.path or '/') for m, rx in CISCO_CALLS)


def api_row(x):
    yes = bool(re.match(r'^(yes|true|y)$', '' if x.get('is_covered') is None else js_str(x.get('is_covered')), re.I))
    opl = x.get('orderable_pid_list')
    first = opl[0] if isinstance(opl, list) and opl else None
    pid = None
    if truthy(first) and isinstance(first, dict):
        pid = first.get('orderable_pid') if truthy(first.get('orderable_pid')) else first.get('pid')
    if not truthy(pid):
        pid = x.get('base_pid_list') if truthy(x.get('base_pid_list')) else ''
    return {'covered': yes, 'end': date_of(x.get('coverage_end_date') if truthy(x.get('coverage_end_date')) else x.get('covered_product_line_end_date')),
            'contract': s(x.get('service_contract_number'), 60), 'service_level': s(x.get('service_line_descr'), 120),
            'warranty_end': date_of(x.get('warranty_end_date')), 'warranty_type': s(x.get('warranty_type'), 60),
            'pid': s(pid if isinstance(pid, str) else '', 60), 'customer': s(x.get('contract_site_customer_name'), 120)}


def _get(o, k):
    return o.get(k) if isinstance(o, dict) else None


def coverage(o):
    entries = []
    try:
        if not allowed('POST', o.get('token_url') or ''):
            raise _Fail('token URL is not a Cisco OAuth token endpoint')
        body = form_encode([('grant_type', 'client_credentials'), ('client_id', js_str(o.get('client_id'))),
                            ('client_secret', js_str(o.get('client_secret')))])
        t = httpc.request(o['token_url'], 'POST', {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'},
                          body, timeout_ms=20000)
        if t['status'] in (401, 400):
            raise _Fail('Cisco refused the API client (check the client id / secret)', 'auth')
        tok = _get(t['json'], 'access_token')
        if t['status'] != 200 or not truthy(t['json']) or not truthy(tok):
            raise _Fail('token request failed (HTTP %s)' % t['status'], 'api')
        serials = o.get('serials') or []
        per = o.get('per_call') or PER_CALL
        for i in range(0, len(serials), per):
            part = serials[i:i + per]
            url = js_str(o.get('base_url')) + '/sn2info/v2/coverage/summary/serial_numbers/' + ','.join(part)
            if not allowed('GET', url):
                raise _Fail('refused: not a coverage-summary call')
            r = httpc.request(url, 'GET', {'Authorization': 'Bearer ' + js_str(tok), 'Accept': 'application/json'}, timeout_ms=30000)
            if r['status'] in (401, 403):
                raise _Fail('Cisco refused the coverage call (HTTP %s): the API client needs the Serial Number to Information API'
                            % r['status'], 'auth')
            if r['status'] != 200 or not truthy(r['json']):
                raise _Fail('coverage call failed (HTTP %s)' % r['status'], 'api')
            rows = _get(r['json'], 'serial_numbers')
            seen = set()
            for x in (rows if isinstance(rows, list) else []):
                x = x if isinstance(x, dict) else {}
                sn = norm_serial(x.get('sr_no'))
                if not sn or sn not in part:
                    continue
                seen.add(sn)
                er, e2 = x.get('ErrorResponse'), x.get('error')
                if truthy(er) or truthy(e2):
                    txt = json.dumps(er, separators=(',', ':'), ensure_ascii=False) if truthy(er) else e2
                    entries.append([sn, {'covered': None, 'error': s(txt, 200)}, 'unknown'])
                    continue
                v = api_row(x)
                entries.append([sn, v, 'covered' if v['covered'] else 'not_covered'])
            for sn in part:
                if sn not in seen:
                    entries.append([sn, {'covered': None, 'error': 'Cisco returned nothing for this serial'}, 'unknown'])
        return {'entries': entries}
    except _Fail as e:
        return {'entries': entries, 'error': s(str(e), 300), 'error_class': e.error_class or 'network'}
    except httpc.HttpcError as e:
        return {'entries': entries, 'error': s(str(e), 300), 'error_class': 'network'}
