# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""End of life & isolation - migration step 6d (docs/PYTHON-MIGRATION.md). view(inp) answers exactly like view() in
engine/lifecycle.js (the End of Life page): every device the platform knows (inventory, Asset Discovery, virtualization
hosts, storage arrays) evaluated against the end-of-support rules, deduplicated by serial, with its isolation request,
risk exception, "isolation required" and the action. The inputs are what Node.js read; nothing is written here.
The synchronous callers of evaluate() (budget.js, pentest.js) keep the Node.js one until they move (step 8).
Standard library only (Python 3.8+).
"""
import functools
import math
import re

from jscompat import MISSING, iso, js_round, js_str, truthy

DAY, SOON_DAYS = 86400000, 180
CLOSED = ('retired', 'disposed')
WIN11 = {'22000': ['21H2', '2023-10-10', '2024-10-08'], '22621': ['22H2', '2024-10-08', '2025-10-14'], '22631': ['23H2', '2025-11-11', '2026-11-10'],
         '26100': ['24H2', '2026-10-13', '2027-10-12'], '26200': ['25H2', '2027-10-12', '2028-10-10']}
WIN10_LTSC = {'14393': ['LTSB 2016', '2026-10-13'], '17763': ['LTSC 2019', '2029-01-09'], '19044': ['LTSC 2021', '2027-01-12']}
_F = re.I | re.ASCII   # JavaScript's \d \w \b are ASCII-only
RULES = [(re.compile(p, _F), prod, eol) for p, prod, eol in [
    (r'windows\s*server\s*2003', 'Windows Server 2003', '2015-07-14'),
    (r'windows\s*server\s*2008', 'Windows Server 2008 / 2008 R2', '2020-01-14'),
    (r'windows\s*server\s*2012', 'Windows Server 2012 / 2012 R2', '2023-10-10'),
    (r'windows\s*server\s*2016', 'Windows Server 2016', '2027-01-12'),
    (r'windows\s*server\s*2019', 'Windows Server 2019', '2029-01-09'),
    (r'windows\s*server\s*2022', 'Windows Server 2022', '2031-10-14'),
    (r'windows\s*server\s*2025', 'Windows Server 2025', '2034-10-10'),
    (r'windows\s*xp', 'Windows XP', '2014-04-08'),
    (r'windows\s*vista', 'Windows Vista', '2017-04-11'),
    (r'windows\s*7\b', 'Windows 7', '2020-01-14'),
    (r'windows\s*8(\.1)?\b', 'Windows 8.1', '2023-01-10'),
    (r'centos( linux)?\s*(release\s*)?6\b', 'CentOS 6', '2020-11-30'),
    (r'centos( linux)?\s*(release\s*)?7\b', 'CentOS 7', '2024-06-30'),
    (r'centos\s*stream\s*8', 'CentOS Stream 8', '2024-05-31'),
    (r'centos( linux)?\s*(release\s*)?8\b', 'CentOS Linux 8', '2021-12-31'),
    (r'(red\s*hat|rhel)[^0-9]{0,30}\b6(\.\d+)?\b', 'Red Hat Enterprise Linux 6', '2020-11-30'),
    (r'(red\s*hat|rhel)[^0-9]{0,30}\b7(\.\d+)?\b', 'Red Hat Enterprise Linux 7', '2024-06-30'),
    (r'(red\s*hat|rhel)[^0-9]{0,30}\b8(\.\d+)?\b', 'Red Hat Enterprise Linux 8', '2029-05-31'),
    (r'ubuntu\s*14\.04', 'Ubuntu 14.04 LTS', '2019-04-30'),
    (r'ubuntu\s*16\.04', 'Ubuntu 16.04 LTS', '2021-04-30'),
    (r'ubuntu\s*18\.04', 'Ubuntu 18.04 LTS', '2023-05-31'),
    (r'ubuntu\s*20\.04', 'Ubuntu 20.04 LTS', '2025-05-31'),
    (r'debian[^0-9]{0,20}\b8\b', 'Debian 8', '2020-06-30'),
    (r'debian[^0-9]{0,20}\b9\b', 'Debian 9', '2022-06-30'),
    (r'debian[^0-9]{0,20}\b10\b', 'Debian 10', '2024-06-30'),
    (r'debian[^0-9]{0,20}\b11\b', 'Debian 11', '2026-08-31'),
    (r'solaris\s*11\.4|sunos[^\n]{0,30}5\.11[^\n]{0,20}11\.4', 'Oracle Solaris 11.4', '2034-11-30'),
    (r'solaris\s*11(\.[0-3])?\b|sunos[^\n]{0,30}5\.11\b', 'Oracle Solaris 11.0 - 11.3', None),
    (r'solaris\s*([2-9]|10)\b|sunos[^\n]{0,30}5\.([5-9]|10)\b', 'Oracle Solaris 10 or older', None),
    (r'esxi?\s*(server\s*)?5\.\d', 'VMware ESXi 5.x', None),
    (r'esxi?\s*(server\s*)?6\.0', 'VMware ESXi 6.0', '2020-03-12'),
    (r'esxi?\s*(server\s*)?6\.[57]', 'VMware ESXi 6.5 / 6.7', '2022-10-15'),
    (r'esxi?\s*(server\s*)?7\.0', 'VMware ESXi 7.0', '2025-10-02'),
    (r'fortios\s*v?5\.|fortigate[^\n]{0,40}\bv5\.\d', 'FortiOS 5.x', None),
    (r'fortios\s*v?6\.0\b|fortigate[^\n]{0,40}\bv6\.0\.', 'FortiOS 6.0', None),
    (r'fortios\s*v?6\.2\b|fortigate[^\n]{0,40}\bv6\.2\.', 'FortiOS 6.2', '2024-09-28'),
    (r'fortios\s*v?6\.4\b|fortigate[^\n]{0,40}\bv6\.4\.', 'FortiOS 6.4', '2025-09-30'),
    (r'cisco ios software[^\n]{0,80}version 12\.', 'Cisco IOS 12.x', None),
    (r'cisco ios software[^\n]{0,80}version 15\.[01]\b', 'Cisco IOS 15.0 / 15.1', None),
    (r'ios-xe[^\n]{0,40}\b3\.\d+\.', 'Cisco IOS XE 3.x', None),
    (r'pan-?os\s*[5-8]\.|pan-?os\s*9\.0', 'PAN-OS 9.0 or older', None),
    (r'pan-?os\s*9\.1|pan-?os\s*10\.0', 'PAN-OS 9.1 / 10.0', None),
]]


def g(o, k):
    return o.get(k, MISSING) if isinstance(o, dict) else MISSING


def T(v):
    return v is not MISSING and truthy(v)


def orv(*a):
    for v in a[:-1]:
        if T(v):
            return v
    return a[-1]


def S(v):
    if v is MISSING:
        return 'undefined'
    if isinstance(v, list):
        return ','.join('' if x is None or x is MISSING else S(x) for x in v)
    return js_str(v)


def s(v, mx=500):
    return re.sub('[\u0000-\u001f\u007f]', ' ', '' if v is None or v is MISSING else S(v)).strip()[:mx or 500]


def _ms(v):
    r = iso(v) if isinstance(v, str) else None
    if r is None:
        return None
    import calendar
    return calendar.timegm((int(r[0:4]), int(r[5:7]), int(r[8:10]), int(r[11:13]), int(r[14:16]), int(r[17:19]), 0, 0, 0)) * 1000 + int(r[20:23])


def compile_rules(extra):
    out = []
    for r in extra if isinstance(extra, list) else []:
        if not (T(r) and T(g(r, 'pattern'))):
            continue
        try:
            rx = re.compile(S(r['pattern']), _F)
        except re.error:
            continue   # an invalid pattern is skipped, as in Node.js
        out.append((rx, s(g(r, 'product'), 120) or S(r['pattern']), S(r['eol'])[:10] if T(g(r, 'eol')) else None))
    return out + RULES


def evaluate(text, rules, now):
    t = s(text, 2000)
    if not t:
        return {'status': 'unknown', 'product': '', 'eol': None, 'days': None}

    def res(product, eol, note=None):
        if eol is None:
            return {'product': product, 'eol': None, 'status': 'eol', 'days': None, 'note': note or 'vendor end of support has passed'}
        p = _ms(eol + 'T00:00:00Z')
        days = None if p is None else js_round((p - now) / DAY)
        status = 'supported' if days is None else 'eol' if days < 0 else 'soon' if days <= SOON_DAYS else 'supported'
        return {'product': product, 'eol': eol, 'days': days, 'status': status, 'note': note or ''}
    m = re.search(r'\b10\.0[.\s(]+(\d{5})\b', t, re.ASCII) or re.search(r'\bbuild\s*(\d{5})\b', t, _F) or re.search(r'\((\d{5})\)', t, re.ASCII)
    build = m.group(1) if m else None
    if re.search(r'windows\s*11', t, _F) and build and build in WIN11:
        w, ent = WIN11[build], bool(re.search('enterprise|education', t, re.I))
        return res('Windows 11 %s (%s)' % (w[0], 'Enterprise / Education' if ent else 'Home / Pro'), w[2] if ent else w[1])
    if re.search(r'windows\s*10', t, _F) and not re.search('server', t, re.I):
        if re.search('ltsc|ltsb', t, re.I) and build and build in WIN10_LTSC:
            return res('Windows 10 Enterprise %s' % WIN10_LTSC[build][0], WIN10_LTSC[build][1])
        return res('Windows 10', '2025-10-14', 'paid Extended Security Updates (ESU) may still cover it')
    for rx, product, eol in rules:
        if rx.search(t):
            return res(product, eol)
    return {'status': 'unknown', 'product': '', 'eol': None, 'days': None}


def _text_of(x):
    return ' · '.join(S(v) for v in (g(x, 'os'), g(x, 'os_version'), g(x, 'firmware'), g(x, 'sys_descr'), g(x, 'model')) if T(v))


def _ser(v):
    return s(v, 80).upper()


def _js_lt(a, b):
    return a.encode('utf-16-be') < b.encode('utf-16-be')


def items(inp, all_):
    rules, now = compile_rules(inp.get('extra_rules')), inp['now']
    out, seen = [], set()

    def add(o, text):
        e = evaluate(text, rules, now)
        if not all_ and e['status'] in ('supported', 'unknown'):
            return
        if o['serial']:
            if o['serial'] in seen:
                return
            seen.add(o['serial'])
        o['os'] = text
        o.update(e)
        out.append(o)
    for a in inp.get('assets') or []:
        if g(a, 'status') in CLOSED:
            continue
        add({'key': 'asset:' + S(a['id']), 'source': 'inventory', 'id': a['id'], 'name': orv(g(a, 'name'), g(a, 'asset_tag'), g(a, 'mgmt_ip'), a['id']), 'type': orv(g(a, 'type'), ''), 'ip': orv(g(a, 'mgmt_ip'), ''),
             'mac': orv(g(a, 'mac'), ''), 'site': orv(g(a, 'site'), ''), 'serial': _ser(g(a, 'serial')), 'vendor': s(g(a, 'vendor'), 80), 'model': s(g(a, 'model'), 120), 'asset_tag': s(g(a, 'asset_tag'), 60)}, _text_of(a))
    for d in inp.get('devices') or []:
        if g(d, 'status') == 'ignored' or T(g(d, 'asset_id')):
            continue
        macs = g(d, 'macs')
        ex = g(d, 'extra')
        add({'key': 'disc:' + S(d['id']), 'source': 'discovery', 'id': d['id'], 'name': orv(g(d, 'hostname'), g(d, 'ip'), d['id']), 'type': orv(g(d, 'type'), ''), 'ip': orv(g(d, 'ip'), ''),
             'mac': orv(g(d, 'mac'), (macs[0] if isinstance(macs, list) and macs else MISSING) if T(macs) else MISSING, ''), 'site': orv(g(d, 'site'), ''),
             'serial': _ser(orv(g(d, 'serial'), g(ex, 'serial') if T(ex) else ex)), 'vendor': s(g(d, 'vendor'), 80), 'model': s(g(d, 'model'), 120), 'decision': g(d, 'status')}, _text_of(d))
    for m in inp.get('virt') or []:
        for h in g(m, 'hosts') if isinstance(g(m, 'hosts'), list) else []:
            add({'key': 'virt:' + S(m['id']) + ':' + S(g(h, 'id')), 'source': 'virtualization', 'id': g(h, 'id'), 'name': orv(g(h, 'name'), g(h, 'id')), 'type': 'hypervisor', 'ip': orv(g(h, 'ip'), ''), 'mac': '',
                 'site': orv(g(m, 'site'), ''), 'serial': _ser(g(h, 'serial')), 'vendor': s(g(h, 'vendor'), 80), 'model': s(g(h, 'model'), 120), 'platform': orv(g(m, 'label'), '')},
                ' · '.join(S(v) for v in (g(h, 'version'), g(h, 'model')) if T(v)))
    for sn in inp.get('storage') or []:
        y = orv(g(sn, 'system'), {})
        if not T(g(y, 'name')) and not T(g(y, 'serial')):
            continue
        add({'key': 'storage:' + S(sn['id']), 'source': 'storage', 'id': sn['id'], 'name': orv(g(y, 'name'), sn['id']), 'type': 'storage', 'ip': '', 'mac': '', 'site': '', 'serial': _ser(g(y, 'serial')), 'vendor': '',
             'model': s(g(y, 'model'), 120)}, ' · '.join(S(v) for v in (g(y, 'model'), g(y, 'version')) if T(v)))
        for c in g(sn, 'controllers') if isinstance(g(sn, 'controllers'), list) else []:
            if T(g(c, 'serial')):
                add({'key': 'storage:' + S(sn['id']) + ':' + S(g(c, 'name')), 'source': 'storage', 'id': sn['id'], 'name': S(orv(g(y, 'name'), sn['id'])) + ' / ' + S(orv(g(c, 'name'), 'controller')), 'type': 'storage',
                     'ip': '', 'mac': '', 'site': '', 'serial': _ser(c['serial']), 'vendor': '', 'model': s(g(c, 'model'), 120)}, ' · '.join(S(v) for v in (g(c, 'model'), g(y, 'version')) if T(v)))
    open_ = {}
    for r in inp.get('requests') or []:
        if g(r, 'state') not in ('released', 'rejected'):
            open_[g(r, 'key')] = {'id': g(r, 'id'), 'state': g(r, 'state')}
    today = iso(now)[:10]
    exm = {}
    for x in inp.get('exceptions') or []:
        if g(x, 'state') not in ('pending', 'approved'):
            continue
        st = 'expired' if x['state'] == 'approved' and isinstance(g(x, 'expires'), str) and _js_lt(x['expires'], today) else x['state']
        if st != 'expired' or g(x, 'key') not in exm:
            exm[g(x, 'key')] = {'id': g(x, 'id'), 'state': st, 'expires': g(x, 'expires'), 'owner': g(x, 'owner')}
    for i in out:
        if i['key'] in open_:
            i['isolation'] = open_[i['key']]
        if i['key'] in exm:
            i['exception'] = exm[i['key']]
        infra = i['type'] in ('hypervisor', 'storage') or bool(re.search(r'esxi|nutanix|\bahv\b', S(orv(i.get('product'), '')) + ' ' + S(orv(i.get('os'), '')), re.I))
        exc_ok = bool(i.get('exception')) and i['exception']['state'] == 'approved'
        iso_ = i.get('isolation')
        i['isolation_required'] = i['status'] == 'eol' and not infra and not exc_ok and not (iso_ and iso_['state'] == 'isolated')
        if i['status'] == 'eol' and exc_ok:
            ow = i['exception'].get('owner')
            i['action'] = 'risk exception until ' + S(i['exception']['expires']) + (' (owner ' + S(ow) + ')' if T(ow) else '') + ' - then isolate, upgrade or renew'
        elif i['status'] == 'eol' and infra:
            i['action'] = 'upgrade or replace (cannot be isolated without stopping its workloads)'
        elif i['isolation_required']:
            i['action'] = ('isolation ' + S(iso_['state'])) if iso_ else ('isolate until upgraded or replaced' if T(i['ip']) or T(i['mac']) else 'isolate - no IP / MAC known, find it on the network first')
        elif i['status'] == 'eol':
            i['action'] = 'isolated - plan the upgrade / replacement'
        elif i['status'] == 'soon':
            i['action'] = 'plan the upgrade before ' + S(orv(i.get('eol'), 'end of support'))

    def cmp(x, y):   # the comparator of lifecycle.js, as it is (it never answers 0)
        if x['status'] == y['status']:
            return -1 if _js_lt(S(orv(x.get('eol'), '')), S(orv(y.get('eol'), ''))) else 1
        return -1 if x['status'] == 'eol' else 1
    out.sort(key=functools.cmp_to_key(cmp))
    return out


def view(inp):
    lst = items(inp, bool(inp.get('all')))
    now = inp['now']
    today = iso(now)[:10]
    by = lambda st: len([i for i in lst if i['status'] == st])   # noqa: E731
    exc, reqs = inp.get('exceptions') or [], inp.get('requests') or []
    summary = {'exceptions': len([i for i in lst if i.get('exception') and i['exception']['state'] == 'approved']), 'exceptions_pending': len([x for x in exc if g(x, 'state') == 'pending']),
               'isolation_required': len([i for i in lst if i['isolation_required']]), 'without_serial': len([i for i in lst if i['status'] in ('eol', 'soon') and not i['serial']]),
               'eol': by('eol'), 'soon': by('soon'), 'servers': len([i for i in lst if i['status'] == 'eol' and re.search('server|vm', S(i['type']))]),
               'network': len([i for i in lst if i['status'] == 'eol' and re.search('network|switch|router|firewall', S(i['type']))]),
               'isolated': len([r for r in reqs if g(r, 'state') == 'isolated']), 'pending': len([r for r in reqs if g(r, 'state') == 'pending'])}

    def desc(key):   # (a, b) => (a.created_at < b.created_at ? 1 : -1)
        def c(a, b):
            x, y = g(a, key), g(b, key)
            lt = isinstance(x, str) and isinstance(y, str) and _js_lt(x, y)
            return 1 if lt else -1
        return functools.cmp_to_key(c)
    exceptions = [dict(x, state='expired' if g(x, 'state') == 'approved' and isinstance(g(x, 'expires'), str) and _js_lt(x['expires'], today) else g(x, 'state')) for x in exc]
    exceptions.sort(key=desc('created_at'))
    requests = sorted(reqs, key=desc('created_at'))
    approvers = inp.get('approvers') or []
    return _clean({'summary': summary, 'exceptions': exceptions[:300], 'items': lst, 'requests': requests[:200],
                   'isolation': {'method': 'fortigate' if inp.get('fortigate') else 'manual', 'approvers': approvers if approvers else ['any other administrator'], 'soon_days': SOON_DAYS}})


def _clean(v):
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if x is not MISSING}
    if isinstance(v, list):
        return [None if x is MISSING else _clean(x) for x in v]
    return v
