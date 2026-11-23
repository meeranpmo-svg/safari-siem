# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Server & asset reconciliation rules - migration step 6a (docs/PYTHON-MIGRATION.md). compare(inputs) answers exactly like
compareCore() in engine/reconcile.js: the inputs are what Node.js read (assets, discovery devices, accepted differences,
settings, the clock and the three SIEM answers); nothing is read or written here.
Also the asset checks it relies on: winCheck / exchangeWhy (engine/sysadmin-sync.js) and netCheck (engine/netops-sync.js).
Standard library only (Python 3.8+).
"""
import functools
import re
import unicodedata

from jscompat import MISSING, iso, js_str, truthy

CLOSED = {'retired', 'disposed', 'lost'}
CLOSED_SYNC = {'retired', 'disposed'}          # sysadmin-sync / netops-sync know only these two
SERVERISH = {'server', 'vm', 'storage'}
DEV_SERVER = {'server', 'vm', 'hypervisor'}
PASSIVE_TRUSTED = ['ad', 'vcenter', 'nutanix', 'hyperv', 'azure', 'aws']
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
DAY = 86400000
SEV = {'high': 3, 'warn': 2, 'info': 1}


# ---- JavaScript value rules -----------------------------------------------------------------------------------------
def g(o, k):
    return o.get(k, MISSING) if isinstance(o, dict) else MISSING


def T(v):
    return v is not MISSING and truthy(v)


def S(v):
    if v is MISSING:
        return 'undefined'
    if isinstance(v, list):
        return ','.join('' if x is None or x is MISSING else S(x) for x in v)
    return js_str(v)


def low(v):
    """reconcile.js: String(v == null ? '' : v).toLowerCase().trim()"""
    return ('' if v is None or v is MISSING else S(v)).lower().strip()


def low2(v):
    """sysadmin-sync.js / netops-sync.js: String(v || '').toLowerCase()"""
    return S(v).lower() if T(v) else ''


def short(n):
    v = low(n)
    return '' if IP_RE.match(v) else v.split('.')[0]


def arr(v):
    """x || [] used as a list (a non-list is concatenated as one value, like Array.concat)"""
    if not T(v):
        return []
    return v if isinstance(v, list) else [v]


def ms(v):
    """Date.parse(iso) (NaN = None)"""
    r = iso(v) if isinstance(v, str) else None
    if r is None:
        return None
    import calendar
    return calendar.timegm((int(r[0:4]), int(r[5:7]), int(r[8:10]), int(r[11:13]), int(r[14:16]), int(r[17:19]), 0, 0, 0)) * 1000 + int(r[20:23])


def closed(a, which=None):
    st = g(a, 'status')
    return isinstance(st, str) and st in (which or CLOSED)


# String.prototype.localeCompare (ICU root collation, as Node.js runs it): whitespace, then punctuation / symbols in ICU
# order, digits, then letters case-insensitively; ties go lower case first, then by code point.
_PUNCT = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"


def _pkey(c):
    i = _PUNCT.find(c)
    if i >= 0:
        return (0, i, '')
    if c.isspace():
        return (0, -1, c)
    if c.isdigit():
        return (2, int(c) if c in '0123456789' else ord(c), '')
    if c.isalpha():
        return (3, 0, _base(c).casefold())   # primary: the base letter (É sorts with E, as in ICU)
    return (1, ord(c), '')


def _base(c):
    d = unicodedata.normalize('NFD', c)
    return ''.join(x for x in d if not unicodedata.combining(x)) or c


def _accents(c):
    return ''.join(x for x in unicodedata.normalize('NFD', c) if unicodedata.combining(x))


def locale_compare(a, b):
    pa, pb = [_pkey(c) for c in a], [_pkey(c) for c in b]
    if pa != pb:
        return -1 if pa < pb else 1
    sa, sb = [_accents(c) for c in a], [_accents(c) for c in b]   # secondary: no accent before an accent
    if sa != sb:
        return -1 if sa < sb else 1
    ta, tb = [0 if c.islower() or not c.isalpha() else 1 for c in a], [0 if c.islower() or not c.isalpha() else 1 for c in b]
    if ta != tb:
        return -1 if ta < tb else 1
    return 0 if a == b else (-1 if a < b else 1)


# ---- asset helpers (reconcile.js) -----------------------------------------------------------------------------------
def ips_of(a):
    return [x for x in [g(a, 'mgmt_ip'), g(a, 'ip')] + arr(g(a, 'ips')) if IP_RE.match(S(x) if T(x) else '')]


def main_ip(a):
    l = ips_of(a)
    return l[0] if l else ''


def last_seen_of(a):
    vals = [g(a, 'last_seen')] + [g(s, 'last_seen') for s in arr(g(a, 'sources'))]
    vals = sorted((S(x) for x in vals if T(x)), key=lambda s: s.encode('utf-16-be'))
    return vals[-1] if vals else None


def trusted_methods(d):
    m = g(d, 'methods')
    return [k for k, v in (m.items() if isinstance(m, dict) else []) if not T(g(v, 'untrusted'))]


# ---- sysadmin-sync.js -------------------------------------------------------------------------------------------------
def _ip_of_sync(a):
    for x in [g(a, 'mgmt_ip'), g(a, 'ip'), g(g(a, 'discovery'), 'ip') if T(g(a, 'discovery')) else MISSING]:
        if IP_RE.match(S(x) if T(x) else ''):
            return x
    return ''


def _join(*vals):
    return ' '.join('' if v is None or v is MISSING else S(v) for v in vals)


def _sw_name(x):
    return S(orv(g(x, 'name'), x) if T(x) else x)


def orv(*a):
    for v in a[:-1]:
        if T(v):
            return v
    return a[-1]


def win_os(a):
    disc = g(a, 'discovery')
    if re.search('windows', low2(_join(g(a, 'os'), g(disc, 'os') if T(disc) else disc))):
        return True
    return any(re.search('windows server', _sw_name(x), re.I) for x in arr(g(a, 'software')))


def exchange_why(a):
    sw = next((x for x in arr(g(a, 'software')) if re.search('microsoft exchange server', _sw_name(x), re.I)), None)
    if sw is not None:
        return 'software: ' + S(orv(g(sw, 'name'), sw))[:80]
    if 'exchange' in [low2(t) for t in arr(g(a, 'tags'))]:
        return 'tag: exchange'
    if re.search(r'\bexchange\b', ' '.join(S(x) for x in (g(a, 'os'), g(a, 'model'), g(a, 'notes'))), re.I):
        return 'asset record mentions Exchange'
    host = low2(g(a, 'name')).split('.')[0]
    if re.search(r'^(exch|exchange|mbx|exc|ex20\d\d|ex1[369])[-_]?\d*[a-z]?$|[-_](exch|mbx|exchange)\d*$', host):
        return 'host name ' + S(g(a, 'name'))
    if re.search(r'(^|[-_])mail(srv|svr|server)?[-_]?\d*[a-z]?($|[-_])', host) and win_os(a):
        return 'host name ' + S(g(a, 'name')) + ' (Windows mail server)'
    return ''


def win_check(a, ip_fn=None):
    if not T(a) or closed(a, CLOSED_SYNC):
        return {'ok': False, 'why': 'retired'}
    ex, win = exchange_why(a), win_os(a)
    if not ex and not win:
        return {'ok': False, 'why': 'not a Windows server'}
    if g(a, 'type') not in ('server', 'vm'):
        return {'ok': False, 'why': 'type is "%s" - set the type to Server or VM' % S(g(a, 'type'))}
    if not T(ip_fn(a) if ip_fn else _ip_of_sync(a)):
        return {'ok': False, 'why': 'no IP address - add the management IP'}
    return {'ok': True}


def is_windows(a):
    return win_check(a)['ok']


# ---- netops-sync.js ---------------------------------------------------------------------------------------------------
NOT_NET_CLASS = ['printer', 'phone', 'workstation', 'server', 'vm', 'cloud', 'storage']
NET_MODEL = re.compile(r'^(WS-C|C9\d{3}|C8\d{3}|C1\d{3}|ISR|ASR|N\dK|N\d{2}K|ASA|FPR|AIR-|C9800|CBS\d|SG\d{3}|IE-\d|FG-|FortiGate|PA-\d|FortiSwitch|FS-\d)', re.I)


def net_check(a, ip_fn=None):
    if not T(a) or closed(a, CLOSED_SYNC):
        return {'ok': False, 'why': 'retired'}
    t = [low2(x) for x in arr(g(a, 'tags'))]
    disc = g(a, 'discovery')
    cls = low2(g(disc, 'class') if T(disc) else disc)
    looks = g(a, 'type') == 'network' or bool(NET_MODEL.search(S(orv(g(a, 'model'), '')))) or any(x in ('switch', 'router', 'firewall') for x in t)
    if not looks:
        return {'ok': False, 'why': 'not a network device'}
    if g(a, 'type') != 'network':
        return {'ok': False, 'why': 'type is "%s" - set the type to Network to monitor it in the AI Network Engineer' % S(g(a, 'type'))}
    if cls and cls in NOT_NET_CLASS and not any(x in ('switch', 'router', 'firewall', 'core', 'distribution', 'access') for x in t):
        return {'ok': False, 'why': 'discovery classed it as %s - add a tag switch / router / firewall if it is one' % cls}
    if not T(ip_fn(a) if ip_fn else g(a, 'mgmt_ip')):
        return {'ok': False, 'why': 'no IP address - add the management IP'}
    return {'ok': True}


# ---- compare --------------------------------------------------------------------------------------------------------
def compare(inp):
    st = dict({'stale_days': 30, 'alive_days': 7, 'ad_logon_days': 90}, **(inp.get('settings') or {}))
    t = inp['now']
    at = iso(t)
    all_ = inp.get('assets') or []
    active = [a for a in all_ if not closed(a)]
    servers = [a for a in active if g(a, 'type') in SERVERISH]
    dev_list = inp.get('devices') or []
    dev_by_id = {}
    for d in dev_list:
        dev_by_id[g(d, 'id')] = d
    dev_of_asset = {}
    for d in dev_list:
        if T(g(d, 'asset_id')):
            p = dev_of_asset.get(d['asset_id'])
            if p is None or (isinstance(g(p, 'last_seen'), str) and isinstance(g(d, 'last_seen'), str) and p['last_seen'] < d['last_seen']):
                dev_of_asset[d['asset_id']] = d
    by_ip, by_mac, by_serial, by_uuid, by_name = {}, {}, {}, {}, {}

    def push(m, k, a):
        if not k:
            return
        m.setdefault(k, []).append(a)
    for a in active:
        for ip in ips_of(a):
            push(by_ip, ip, a)
        for m in [g(a, 'mac')] + arr(g(a, 'macs')):
            push(by_mac, low(m), a)
        push(by_serial, low(g(a, 'serial')), a)
        push(by_uuid, low(g(a, 'uuid')), a)
        push(by_name, short(g(a, 'name')), a)
    issues = []

    def add(o):
        x = {'sev': 'warn'}
        x.update(o)
        issues.append(x)

    def recent(v, days):
        if not T(v):
            return False
        p = ms(v)
        return p is not None and t - p <= days * DAY

    def locked_by(a, k):
        lk, pv = g(a, 'locked'), g(a, 'prov')
        if T(lk) and T(g(lk, k)):
            return 'manual edit (locked)'
        return orv(g(pv, k) if T(pv) else MISSING, '') if T(pv) else ''

    nm = lambda a: g(a, 'name')   # noqa: E731 - a.name (absent stays absent)

    # 1. asset vs its linked discovery device
    for a in servers:
        disc = g(a, 'discovery')
        d = dev_of_asset.get(a['id']) or (dev_by_id.get(g(disc, 'device_id')) if T(disc) else None)
        if not d or not recent(g(d, 'last_seen'), st['stale_days']):
            continue
        src = ', '.join(trusted_methods(d)) or 'discovery'
        mi = main_ip(a)
        if T(g(d, 'ip')) and mi and mi not in arr(g(d, 'ips')) and d['ip'] not in ips_of(a):
            add({'id': 'ip:%s' % a['id'], 'kind': 'ip_mismatch', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': mi, 'field': 'mgmt_ip', 'have': mi, 'found': d['ip'], 'source': src, 'held_by': locked_by(a, 'mgmt_ip'), 'fix': 'apply'})
        if T(g(d, 'os')) and T(g(a, 'os')) and os_differs(a['os'], d['os']):
            add({'id': 'os:%s' % a['id'], 'kind': 'os_mismatch', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': mi, 'field': 'os', 'have': a['os'], 'found': d['os'], 'source': src, 'held_by': locked_by(a, 'os'), 'fix': 'apply'})
        dn = short(orv(g(d, 'hostname'), g(d, 'fqdn')))
        if dn and short(g(a, 'name')) and dn != short(g(a, 'name')):
            add({'id': 'name:%s' % a['id'], 'kind': 'name_mismatch', 'sev': 'info', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': mi, 'field': 'name', 'have': nm(a), 'found': orv(g(d, 'hostname'), g(d, 'fqdn')), 'source': src, 'held_by': locked_by(a, 'name'), 'fix': 'apply'})
        ex = g(d, 'extra')
        ad = g(ex, 'ad') if T(ex) else ex
        if T(ad) and T(g(d, 'methods')) and T(g(d['methods'], 'ad')) and g(a, 'status') == 'in_use':
            if g(ad, 'enabled') is False:
                add({'id': 'addis:%s' % a['id'], 'kind': 'ad_disabled', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': mi, 'have': 'in use', 'found': 'computer account disabled in AD' + (' (' + S(ad['ou']) + ')' if T(g(ad, 'ou')) else ''), 'source': 'ad'})
            elif T(g(ad, 'last_logon')) and not recent(ad['last_logon'], st['ad_logon_days']):
                add({'id': 'adold:%s' % a['id'], 'kind': 'ad_stale', 'sev': 'info', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': mi, 'have': 'in use', 'found': 'last AD logon ' + S(ad['last_logon'])[:10], 'source': 'ad'})
    closed_servers = [x for x in all_ if closed(x) and g(x, 'type') in SERVERISH]
    # 2. retired / disposed but still seen
    for a in closed_servers:
        d = dev_of_asset.get(a['id'])
        if d and recent(g(d, 'last_seen'), st['alive_days']):
            add({'id': 'alive:%s' % a['id'], 'kind': 'retired_alive', 'sev': 'high', 'asset_id': a['id'], 'device_id': g(d, 'id'), 'name': nm(a), 'ip': main_ip(a) or g(d, 'ip'),
                 'have': a['status'], 'found': 'seen ' + S(d['last_seen'])[:16].replace('T', ' ', 1) + ' by ' + (', '.join(trusted_methods(d)) or 'discovery'), 'source': 'discovery'})
    # 3. server in a source but not in inventory, or unlinked although an asset matches
    for d in dev_list:
        if g(d, 'status') != 'new' or T(g(d, 'asset_id')) or g(d, 'type') not in DEV_SERVER or not recent(g(d, 'last_seen'), st['stale_days']):
            continue
        meth = trusted_methods(d)
        if not meth:
            continue
        ex = g(d, 'extra')
        vc = g(ex, 'vcenter') if T(ex) else ex
        cand = []
        for m in arr(g(d, 'macs')):
            cand += by_mac.get(low(m)) or []
        cand += by_serial.get(low(g(d, 'serial'))) or []
        cand += by_uuid.get(low(g(vc, 'uuid') if T(vc) else vc)) or []
        match = cand[0] if cand else None
        if match is None:
            l = by_ip.get(g(d, 'ip')) or [] if T(g(d, 'ip')) else []
            if T(g(d, 'ip')) and len(l) == 1 and short(g(l[0], 'name')) == short(g(d, 'hostname')):
                match = l[0]
        if match is not None:
            add({'id': 'link:%s' % d['id'], 'kind': 'unlinked', 'sev': 'info', 'device_id': d['id'], 'asset_id': match['id'], 'name': orv(g(d, 'hostname'), g(d, 'ip')), 'ip': g(d, 'ip'),
                 'have': 'asset ' + S(orv(g(match, 'name'), match['id'])), 'found': 'discovery result not linked to it', 'source': ', '.join(meth), 'fix': 'merge'})
        elif any(m in PASSIVE_TRUSTED for m in meth):
            add({'id': 'new:%s' % d['id'], 'kind': 'not_in_inventory', 'device_id': d['id'], 'name': orv(g(d, 'hostname'), g(d, 'ip')), 'ip': g(d, 'ip'), 'have': 'not in inventory',
                 'found': S(orv(g(d, 'type'), 'server')) + (' · ' + S(d['os']) if T(g(d, 'os')) else ''), 'source': ', '.join(meth), 'fix': 'approve'})
    # 4. duplicates, incomplete, stale
    dup_seen = set()
    for k, lst in [('IP ' + k2, v) for k2, v in by_ip.items()] + [('name ' + k2, v) for k2, v in by_name.items()]:
        l = [a for a in lst if g(a, 'type') in SERVERISH]
        ids = []
        for a in l:
            if a['id'] not in ids:
                ids.append(a['id'])
        if len(ids) < 2 or k in dup_seen:
            continue
        dup_seen.add(k)
        add({'id': 'dup:%s' % k, 'kind': 'duplicate', 'name': ' / '.join(S(orv(g(a, 'name'), a['id'])) for a in l)[:160], 'ip': k[3:] if k.startswith('IP ') else main_ip(l[0]),
             'asset_ids': ids, 'have': '%d assets share %s' % (len(ids), k), 'found': '', 'source': 'inventory'})
    for a in servers:
        if not main_ip(a):
            add({'id': 'noip:%s' % a['id'], 'kind': 'missing_ip', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'have': 'no IP address', 'found': '', 'source': 'inventory'})
        if not T(g(a, 'os')) and g(a, 'type') != 'storage':
            add({'id': 'noos:%s' % a['id'], 'kind': 'missing_os', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': 'no operating system', 'found': '', 'source': 'inventory'})
        ls, d = last_seen_of(a), dev_of_asset.get(a['id'])
        if ls and not recent(ls, st['stale_days']) and not (d and recent(g(d, 'last_seen'), st['stale_days'])):
            add({'id': 'stale:%s' % a['id'], 'kind': 'stale', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': g(a, 'status'), 'found': 'no source has reported it since ' + ls[:10], 'source': 'inventory'})
    # 5. SIEM: Server Availability + AI Server Administrators
    avail, targets, netdevs = inp['avail'], inp['targets'], inp['netdevs']

    def dget(r, *ks):
        o = r.get('data')
        for k in ks:
            o = g(o, k) if T(o) else MISSING
        return o
    av_hosts = dget(avail, 'hosts') if avail.get('ok') else MISSING
    tg_items = dget(targets, 'items') if targets.get('ok') else MISSING
    nd_items = dget(netdevs, 'items') if netdevs.get('ok') else MISSING
    sources = {
        'inventory': {'ok': True, 'servers': len(servers)},
        'discovery': {'ok': True, 'linked': len([d for d in dev_list if T(g(d, 'asset_id'))]), 'servers_seen': len([d for d in dev_list if g(d, 'type') in DEV_SERVER and recent(g(d, 'last_seen'), st['stale_days'])])},
        'availability': {'ok': True, 'hosts': len(av_hosts if isinstance(av_hosts, dict) else {})} if avail.get('ok') else {'ok': False, 'error': avail.get('error')},
        'server_admins': {'ok': True, 'servers': len(tg_items if isinstance(tg_items, list) else [])} if targets.get('ok') else {'ok': False, 'error': targets.get('error')},
        'network_engineer': {'ok': True, 'devices': len(nd_items if isinstance(nd_items, list) else [])} if netdevs.get('ok') else {'ok': False, 'error': netdevs.get('error')},
    }
    if avail.get('ok'):
        mp = av_hosts if isinstance(av_hosts, dict) else {}

        def host_of(a):
            for x in ips_of(a):
                h = mp.get(x)
                if T(h):
                    return h
            return None
        for a in servers:
            ip = main_ip(a)
            if not ip or g(a, 'type') == 'storage':
                continue
            if host_of(a) is None:
                add({'id': 'nomon:%s' % a['id'], 'kind': 'not_monitored', 'asset_id': a['id'], 'name': nm(a), 'ip': ip, 'have': 'in inventory', 'found': 'not in Server Availability', 'source': 'availability'})
        for a in closed_servers:
            h = host_of(a)
            if h is not None and g(h, 's') == 'online' and not any(i['id'] == 'alive:%s' % a['id'] for i in issues):
                add({'id': 'alive:%s' % a['id'], 'kind': 'retired_alive', 'sev': 'high', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': a['status'], 'found': 'answering in Server Availability', 'source': 'availability'})
    if targets.get('ok'):
        items = tg_items if isinstance(tg_items, list) else []
        t_by_ip = {}
        for x in items:
            t_by_ip[g(x, 'ip')] = x
        for a in active:
            if not is_windows(a):
                continue
            tg = next((t_by_ip[x] for x in ips_of(a) if T(t_by_ip.get(x))), None)
            why = exchange_why(a)
            if tg is None:
                add({'id': 'noadm:%s' % a['id'], 'kind': 'not_in_server_admin', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': 'Windows server in inventory', 'found': 'not under the AI Windows Server Administrator', 'source': 'server_admins'})
                continue
            is_ex = 'exchange' in arr(g(tg, 'roles'))
            if why and not is_ex:
                add({'id': 'exch:%s' % a['id'], 'kind': 'exchange_mismatch', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': 'Exchange (' + why + ')', 'found': 'not an Exchange server in the AI Exchange Server Administrator', 'source': 'server_admins'})
            if not why and is_ex:
                add({'id': 'exch:%s' % a['id'], 'kind': 'exchange_mismatch', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'ip': main_ip(a), 'have': 'nothing in the asset says Exchange', 'found': 'Exchange server in the AI Exchange Server Administrator', 'source': 'server_admins'})

        def d_ip(a):
            return main_ip(a) or S(orv(g(dev_of_asset.get(g(a, 'id')) or {}, 'ip'), ''))
        for a in active:
            c = win_check(a, d_ip)
            if not c['ok'] and c['why'] != 'not a Windows server' and c['why'] != 'retired':
                ew = exchange_why(a)
                add({'id': 'admskip:%s' % a['id'], 'kind': 'server_admin_not_synced', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'ip': d_ip(a), 'have': 'Exchange (' + ew + ')' if ew else 'Windows server',
                     'found': 'not sent to the AI Server Administrators: ' + c['why'], 'source': 'inventory'})
        for tg in items:
            if T(g(tg, 'ip')) and tg['ip'] not in by_ip:
                add({'id': 'orphan:%s' % S(tg['ip']), 'kind': 'admin_not_in_inventory', 'sev': 'info', 'name': g(tg, 'name'), 'ip': tg['ip'], 'have': 'not in inventory',
                     'found': 'in the AI Server Administrators (' + ', '.join(S(r) for r in arr(g(tg, 'roles'))) + ')', 'source': 'server_admins'})
    # 6. network devices → AI Network Engineer
    if netdevs.get('ok'):
        n_ips = set(g(x, 'ip') for x in (nd_items if isinstance(nd_items, list) else []))

        def dev_ip(a):
            return main_ip(a) or S(orv(g(dev_of_asset.get(g(a, 'id')) or {}, 'ip'), ''))
        for a in active:
            c = net_check(a, dev_ip)
            if c['ok']:
                ip = dev_ip(a)
                if ip not in n_ips:
                    add({'id': 'nonet:%s' % a['id'], 'kind': 'not_in_network_engineer', 'asset_id': a['id'], 'name': nm(a), 'ip': ip, 'have': 'network device in inventory', 'found': 'not in the AI Network Engineer', 'source': 'network_engineer', 'fix': 'netops'})
            elif c['why'] != 'not a network device' and c['why'] != 'retired':
                add({'id': 'netskip:%s' % a['id'], 'kind': 'network_not_synced', 'sev': 'info', 'asset_id': a['id'], 'name': nm(a), 'ip': dev_ip(a),
                     'have': ' '.join(S(x) for x in (g(a, 'vendor'), g(a, 'model')) if T(x)) or g(a, 'type'), 'found': 'not sent to the AI Network Engineer: ' + c['why'], 'source': 'inventory'})
    # accepted differences stay hidden only while the values are the same
    acc = {}
    for r in inp.get('accepted') or []:
        acc[g(r, 'id')] = r
    for i in issues:
        i['sig'] = '|'.join('' if i.get(k, MISSING) in (None, MISSING) else S(i[k]) for k in ('have', 'found'))
        r = acc.get(i['id'])
        if r is not None and g(r, 'sig') == i['sig']:
            i['accepted'] = {'by': g(r, 'by'), 'at': g(r, 'at'), 'reason': g(r, 'reason')}

    def cmp(x, y):
        a1, a2 = 1 if 'accepted' in x else 0, 1 if 'accepted' in y else 0
        if a1 != a2:
            return a1 - a2
        s = SEV.get(y['sev'], 0) - SEV.get(x['sev'], 0)
        if s:
            return s
        c = locale_compare(S(x['kind']), S(y['kind']))
        if c:
            return c
        return locale_compare(S(orv(x.get('name', MISSING), '')), S(orv(y.get('name', MISSING), '')))
    issues.sort(key=functools.cmp_to_key(cmp))
    counts = {}
    for i in issues:
        if 'accepted' not in i:
            counts[i['kind']] = counts.get(i['kind'], 0) + 1
    return _clean({'at': at, 'sources': sources, 'issues': issues, 'counts': counts, 'open': len([i for i in issues if 'accepted' not in i])})


def os_key(s):
    v = re.sub(r'\s+', ' ', re.sub(r'microsoft|\(64-bit\)|\(32-bit\)|®|™', ' ', low(s)))
    if not v:
        return ''
    if re.search('esxi', v):
        return 'esxi'
    if re.search(r'\bahv\b|nutanix', v):
        return 'ahv'
    m = re.search(r'windows server (20\d\d(?: r2)?)', v)
    if m:
        return 'windows server ' + m.group(1)
    m = re.search(r'windows (1[01]|7|8\.1|8)\b', v)
    if m:
        return 'windows ' + m.group(1)
    m = re.search(r'(?:red hat|rhel)[^0-9]*(\d+)', v)
    if m:
        return 'rhel ' + m.group(1)
    for d in ['ubuntu', 'centos', 'oracle linux', 'suse', 'debian', 'rocky', 'almalinux']:
        if d in v:
            m = re.search(r'(\d+)', v[v.index(d):])
            return d + (' ' + m.group(1) if m else '')
    if 'windows' in v:
        return 'windows'
    if 'linux' in v:
        return 'linux'
    if re.search(r'\baix\b', v):
        return 'aix'
    if re.search('solaris|sunos', v):
        return 'solaris'
    return v[:40]


def os_differs(a, b):
    x, y = os_key(a), os_key(b)
    if not x or not y or x == y:
        return False
    if x.startswith(y) or y.startswith(x):
        return False

    def fam(k):
        return 'windows' if k.startswith('windows') else 'linux' if re.search(r'rhel|ubuntu|centos|oracle linux|suse|debian|rocky|alma|^linux', k) else k
    if (x in ('windows', 'linux') or y in ('windows', 'linux')) and fam(x) == fam(y):
        return False
    return True


def _clean(v):
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if x is not MISSING}
    if isinstance(v, list):
        return [None if x is MISSING else _clean(x) for x in v]
    return v
