# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Rule modules over the inventory - migration step 6b / 6c (docs/PYTHON-MIGRATION.md). Each answers exactly like its
Node.js twin, over the inputs Node.js read; nothing is read or written here.
  software model     engine/model/software.js   rollup(assets), licence_compliance(licence, rolled)
  findings           engine/findings.js         findings(inp) - the built-in rules (providers stay in their own modules)
  licence facts      engine/licence-sync.js     licence_facts(inp) - derive + the fill / keep decisions of syncFacts
  unlicensed         engine/licence-sync.js     unlicensed(inp)
Standard library only (Python 3.8+).
"""
import functools
import math
import re

from jscompat import MISSING, iso, js_round, js_str, truthy

DAY = 86400000


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


def arr(v):
    if not T(v):
        return []
    return v if isinstance(v, list) else [v]


def ms_of(v):
    """Date.parse(v) in ms, or None"""
    r = iso(v) if isinstance(v, str) else None
    if r is None:
        return None
    import calendar
    return calendar.timegm((int(r[0:4]), int(r[5:7]), int(r[8:10]), int(r[11:13]), int(r[14:16]), int(r[17:19]), 0, 0, 0)) * 1000 + int(r[20:23])


def _utf16(s):
    return s.encode('utf-16-be')


# ---- engine/model/asset.js s() / engine/model/software.js -----------------------------------------------------------
def s_asset(v, mx=2000):
    if v is None or v is MISSING:
        return ''
    if isinstance(v, bool):
        t = 'true' if v else 'false'
    elif isinstance(v, (int, float)):
        t = js_str(v)
    elif isinstance(v, str):
        t = v
    else:
        t = ''
    return t.strip()[:mx]


def norm_software_entry(raw):
    o = raw if isinstance(raw, dict) else {'name': raw}
    name = s_asset(o.get('name'), 300)
    if not name:
        return None
    return {'name': name, 'publisher': s_asset(o.get('publisher'), 200) or None, 'version': s_asset(o.get('version'), 80) or None,
            'licence_id': s_asset(o.get('licence_id'), 80) or None}


def product_key(sw):
    pub = (sw['publisher'] or '').lower().strip()
    name = re.sub(r'\s+\d[\d.]*$', '', (sw['name'] or '').lower().strip())
    return '%s|%s' % (pub, name)


def rollup(assets):
    m, seen = {}, {}   # seen: the asset ids already counted per product (a set beside the ordered list: 5000 assets took 3 s)
    for a in assets:
        for sw0 in arr(g(a, 'software')):
            sw = norm_software_entry(sw0)
            if not sw:
                continue
            key = product_key(sw)
            e = m.get(key)
            if e is None:
                e = m[key] = {'key': key, 'name': sw['name'], 'publisher': sw['publisher'], 'versions': [], 'installs': 0, 'asset_ids': [], 'licence_id': sw['licence_id'] or None}
            if sw['version'] and sw['version'] not in e['versions']:
                e['versions'].append(sw['version'])
            if sw['licence_id'] and not e['licence_id']:
                e['licence_id'] = sw['licence_id']
            e['installs'] += 1
            aid, ss = g(a, 'id'), seen.setdefault(key, set())
            hk = (type(aid).__name__, aid) if isinstance(aid, (str, int, float, bool)) or aid is None or aid is MISSING else None
            if hk is None:
                if aid not in e['asset_ids']:
                    e['asset_ids'].append(aid)
            elif hk not in ss:
                ss.add(hk)
                e['asset_ids'].append(aid)
    out = []
    for e in m.values():
        out.append(dict(e, versions=sorted(e['versions'], key=_utf16)))
    out.sort(key=lambda x: -x['installs'])   # stable, like Array.prototype.sort
    return out


def licence_compliance(lic, rolled):
    match = S(orv(g(lic, 'product_key_match'), g(lic, 'product'), '')).lower().strip()
    used, products = 0, []
    for p in rolled:
        by_id = p['licence_id'] == g(lic, 'id')
        by_name = bool(match) and (match in ('%s %s' % (p['publisher'] or '', p['name'])).lower() or match in p['name'].lower())
        if by_id or by_name:
            used += p['installs']
            products.append(p['key'])
    seats = g(lic, 'seats')
    if seats is not None and seats is not MISSING:
        comp = 'over' if used > seats else 'under' if used < seats else 'ok'
        delta = used - seats
    else:
        comp, delta = 'unknown', None
    return {'used': used, 'compliance': comp, 'delta': delta, 'products': products}


# ---- engine/findings.js -----------------------------------------------------------------------------------------------
def findings(inp):
    st, now = inp.get('settings') or {}, inp['now']
    not_seen, win = st.get('not_seen_days'), st.get('expiry_window_days')

    def days_until(v):
        t = ms_of(v)
        return None if t is None else js_round((t - now) / DAY)

    def days_since(v):
        t = ms_of(v)
        return None if t is None else js_round((now - t) / DAY)
    live = [a for a in inp.get('assets') or [] if g(a, 'status') not in ('disposed', 'retired')]
    out = []
    for a in live:
        ident = S(orv(g(a, 'asset_tag'), g(a, 'name'), g(a, 'id')))
        aid = g(a, 'id')
        if g(a, 'status') == 'in_use' and T(g(a, 'last_seen')):
            ds = days_since(a['last_seen'])
            if ds is not None and isinstance(not_seen, (int, float)) and ds >= not_seen:
                out.append({'key': 'not_seen:%s' % S(aid), 'kind': 'not_seen', 'severity': 'high' if ds >= not_seen * 3 else 'medium', 'asset_id': aid, 'title': '%s not seen for %d days' % (ident, ds),
                            'detail': 'In use but no source has reported it for %d days (threshold %s). Confirm it is still deployed or move it to lost/retired.' % (ds, js_str(not_seen)), 'evidence': {'last_seen': a['last_seen'], 'days': ds}})
        srcs = []
        for x in arr(g(a, 'sources')):
            v = g(x, 'source')
            if v not in srcs:
                srcs.append(v)
        if T(g(a, 'networked')) and not T(g(a, 'owner')) and 'sensor' in srcs and 'agent' not in srcs and 'manual' not in srcs and g(a, 'type') in ('workstation', 'laptop', 'server', 'other'):
            out.append({'key': 'shadow_it:%s' % S(aid), 'kind': 'shadow_it', 'severity': 'high', 'asset_id': aid, 'title': 'Possible shadow IT: %s' % ident,
                        'detail': 'On the network (sensor-discovered) but unmanaged: no owner and no endpoint agent. Cross-check against ASM/attack-surface and assign an owner or deploy the agent.',
                        'evidence': {'sources': [None if v is MISSING else v for v in srcs], 'mgmt_ip': g(a, 'mgmt_ip')}})
        if g(a, 'status') == 'in_use':
            if not T(g(a, 'owner')) and not T(g(a, 'custodian')):
                out.append({'key': 'missing_owner:%s' % S(aid), 'kind': 'missing_owner', 'severity': 'medium', 'asset_id': aid, 'title': 'No owner/custodian: %s' % ident, 'detail': 'An in-use asset has no owner or custodian recorded.', 'evidence': {}})
            if not T(g(a, 'site')) and not T(g(a, 'location')):
                out.append({'key': 'missing_location:%s' % S(aid), 'kind': 'missing_location', 'severity': 'low', 'asset_id': aid, 'title': 'No location: %s' % ident, 'detail': 'An in-use asset has no site or location recorded.', 'evidence': {}})
            w = g(a, 'warranty')
            if not T(w) or not T(g(w, 'end')):
                out.append({'key': 'missing_warranty:%s' % S(aid), 'kind': 'missing_warranty', 'severity': 'low', 'asset_id': aid, 'title': 'No warranty data: %s' % ident, 'detail': 'No warranty end date recorded; renewal/refresh cannot be planned.', 'evidence': {}})
        w = g(a, 'warranty')
        if T(w) and T(g(w, 'end')):
            end = w['end']
            du = days_until(end)
            if du is not None and du < 0:
                out.append({'key': 'warranty_expired:%s' % S(aid), 'kind': 'warranty_expired', 'severity': 'medium', 'asset_id': aid, 'title': 'Warranty expired: %s' % ident,
                            'detail': 'Warranty ended %d days ago (%s).' % (-du, S(end)[:10]), 'evidence': {'end': end, 'days': du}})
            elif du is not None and isinstance(win, (int, float)) and du <= win:
                out.append({'key': 'warranty_expiring:%s' % S(aid), 'kind': 'warranty_expiring', 'severity': 'medium' if du <= 30 else 'low', 'asset_id': aid, 'title': 'Warranty expiring in %d days: %s' % (du, ident),
                            'detail': 'Warranty ends %s. Plan renewal or refresh.' % S(end)[:10], 'evidence': {'end': end, 'days': du}})
        if T(g(a, 'eol')):
            eol = a['eol']
            du = days_until(eol)
            if du is not None and du < 0:
                out.append({'key': 'eol_passed:%s' % S(aid), 'kind': 'eol_passed', 'severity': 'high', 'asset_id': aid, 'title': 'Past end-of-life: %s' % ident,
                            'detail': 'EOL was %s (%d days ago). Prioritise refresh/replacement.' % (S(eol)[:10], -du), 'evidence': {'eol': eol, 'days': du}})
            elif du is not None and isinstance(win, (int, float)) and du <= win:
                out.append({'key': 'eol_expiring:%s' % S(aid), 'kind': 'eol_expiring', 'severity': 'medium', 'asset_id': aid, 'title': 'Approaching end-of-life: %s' % ident,
                            'detail': 'EOL %s (in %d days). Add to the refresh plan.' % (S(eol)[:10], du), 'evidence': {'eol': eol, 'days': du}})
    rolled = rollup(live)
    for lic in inp.get('licences') or []:
        comp = licence_compliance(lic, rolled)
        lid, prod = g(lic, 'id'), S(g(lic, 'product'))
        if comp['compliance'] == 'over':
            out.append({'key': 'licence_over:%s' % S(lid), 'kind': 'licence_over', 'severity': 'high', 'licence_id': lid, 'title': 'Licence over-deployed: %s' % prod,
                        'detail': '%d installs against %s seats (over by %s). True-up or reclaim installs.' % (comp['used'], js_str(lic['seats']), js_str(comp['delta'])),
                        'evidence': {'seats': lic['seats'], 'used': comp['used'], 'delta': comp['delta'], 'products': comp['products']}})
        elif comp['compliance'] == 'under' and comp['delta'] <= -1:
            out.append({'key': 'licence_under:%s' % S(lid), 'kind': 'licence_under', 'severity': 'low', 'licence_id': lid, 'title': 'Unused licence seats: %s' % prod,
                        'detail': '%d of %s seats used (%s spare). Consider reclaim at renewal.' % (comp['used'], js_str(lic['seats']), js_str(-comp['delta'])),
                        'evidence': {'seats': lic['seats'], 'used': comp['used'], 'delta': comp['delta']}})
        if T(g(lic, 'expiry')):
            du = days_until(lic['expiry'])
            if du is not None and isinstance(win, (int, float)) and du <= win:
                word = 'expired' if du < 0 else 'expiring'
                out.append({'key': 'licence_expiring:%s' % S(lid), 'kind': 'licence_expiring', 'severity': 'high' if du < 0 else 'low', 'licence_id': lid, 'title': 'Licence %s: %s' % (word, prod),
                            'detail': 'Licence %s %s.' % ('expired' if du < 0 else 'expires', S(lic['expiry'])[:10]), 'evidence': {'expiry': lic['expiry'], 'days': du}})
    return _clean({'findings': out})


# ---- engine/licence-sync.js ---------------------------------------------------------------------------------------------
WIN_SERVER = re.compile(r'win[a-z_ ]*\d*[ _]*(server|srv)', re.I)
COMMERCIAL = re.compile(r'\b(microsoft|oracle|adobe|vmware|broadcom|autodesk|ibm|sap|red\s*hat|citrix|veeam|kaspersky|fortinet|tableau|minitab|matlab|mathworks|corel|nitro|foxit|bentley|esri|teamviewer|anydesk|quest|solarwinds|idera|embarcadero|jetbrains)\b', re.I)
BUNDLED = re.compile(r'\b(runtime|redistributable|update|hotfix|security intelligence|language pack|proofing|driver|sdk|\.net|visual c\+\+|edge|onedrive|teams machine-wide|webview|silverlight|xml|odbc|ole db|native client|clr types|management objects|report viewer|setup|bootstrapper|helper|tools for office|click-to-run|access database engine|policy|health|telemetry|compatibility|application compatibility)\b', re.I)


def _tags(a):
    t = g(a, 'tags')
    return [S(x).lower() for x in t] if isinstance(t, list) else []


def is_vm(a):
    return g(a, 'type') == 'vm' or 'vm' in _tags(a)


def is_hypervisor(a):
    return 'esxi-host' in _tags(a) or bool(re.search(r'esxi|vmware\s*esx|nutanix|\bahv\b', S(orv(g(a, 'os'), '')), re.I))


def parse_int(v):
    """int() of licence-sync.js: parseInt(v, 10), kept when 0 < n < 100000"""
    if v is None or v is MISSING:
        return None
    m = re.match(r'^\s*([+-]?\d+)', S(v))
    if not m:
        return None
    n = int(m.group(1))
    return n if 0 < n < 100000 else None


def s_ls(v, mx=120):
    return re.sub(r'\s+', ' ', re.sub('[\u0000-\u001f\u007f]', ' ', '' if v is None or v is MISSING else S(v))).strip()[:mx or 120]


def _num(v):
    if v is None:
        return 0
    if v is MISSING or isinstance(v, (dict, list)):
        return None
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    t = str(v).strip()
    if t == '':
        return 0
    try:
        return float(t)
    except ValueError:
        return None


def derive(a, L):
    r = {}
    vm, hyp, u = is_vm(a), is_hypervisor(a), (g(L, 'unix') if T(L) else MISSING)
    if not vm and not hyp and T(u):
        solaris = bool(re.search('solaris|sunos', S(orv(g(u, 'os'), g(a, 'os'), '')), re.I))
        sv = _num(g(u, 'sockets_v'))
        so, cp = parse_int(g(u, 'sockets')), parse_int(g(u, 'cpus'))
        trusted = solaris or (sv is not None and sv >= 2) or bool(so and cp and so < cp)
        if so and trusted:
            r['sockets'] = {'value': so, 'from': 'SSH login'}
        elif so:
            r['sockets'] = {'skip': 'socket count from an older collector (it counted logical CPUs) - run discovery again'}
        cps = parse_int(g(u, 'cores_per_socket'))
        if cps:
            r['cores_per_socket'] = {'value': cps, 'from': 'SSH login'}
        if re.search(r'sparc|sun4[uvm]', '%s %s %s' % (S(orv(g(u, 'os'), '')), S(orv(g(u, 'model'), '')), S(orv(g(u, 'platform'), ''))), re.I):
            r['cpu_vendor'] = {'value': 'sparc', 'from': 'SSH login'}
    ora = g(L, 'oracle') if T(L) else MISSING
    if T(ora) and T(g(ora, 'edition')):
        e = S(ora['edition'])
        v = 'ee' if re.search('enterprise', e, re.I) else 'se2' if re.search('standard', e, re.I) else 'none' if re.search('express', e, re.I) else None
        if v:
            r['oracle'] = {'value': v, 'from': 'database login (%s)' % s_ls(e, 40)}
        else:
            r['oracle'] = {'skip': 'Oracle %s - set the edition by hand' % s_ls(e, 40)}
    os_ = S(orv(g(a, 'os'), ''))
    if not vm and not hyp and WIN_SERVER.search(os_):
        v = 'dc' if re.search('datacenter', os_, re.I) else 'std' if re.search('standard', os_, re.I) else None
        if v:
            r['windows'] = {'value': v, 'from': 'operating system'}
    return r


def logins_by_asset(live, devices, asset_ids):
    by_ip = {}
    for a in live:
        if T(g(a, 'mgmt_ip')):
            by_ip[a['mgmt_ip']] = a['id']
    out = {}
    for d in devices:
        ex = g(d, 'extra')
        if not (T(ex) and (T(g(ex, 'unix_login')) or T(g(ex, 'db_login')))):
            continue
        aid = d.get('asset_id') if T(g(d, 'asset_id')) and d['asset_id'] in asset_ids else None
        if not aid and T(g(d, 'ip')):
            aid = by_ip.get(d['ip'])
        if not aid:
            continue
        o = out.get(aid) or {}
        u, db = g(ex, 'unix_login'), g(ex, 'db_login')
        if T(u) and not T(g(u, 'error')) and ('unix' not in o or S(orv(g(u, 'at'), '')) > S(orv(g(o['unix'], 'at'), ''))):
            o['unix'] = u
        if T(db) and T(g(db, 'oracle')) and ('oracle' not in o or S(orv(g(d, 'last_seen'), '')) > S(orv(o.get('oracle_seen'), ''))):
            o['oracle'] = db['oracle']
            o['oracle_seen'] = orv(g(d, 'last_seen'), '')
        out[aid] = o
    return out


def _same(x, y):
    """JavaScript ===: a number never equals a string or a boolean; objects only themselves"""
    if x is MISSING or y is MISSING or x is None or y is None:
        return x is y
    if isinstance(x, bool) or isinstance(y, bool):
        return isinstance(x, bool) and isinstance(y, bool) and x == y
    xn, yn = isinstance(x, (int, float)), isinstance(y, (int, float))
    if xn or yn:
        return xn and yn and x == y
    if isinstance(x, str) and isinstance(y, str):
        return x == y
    return x is y


def licence_facts(inp):
    closed = ('retired', 'disposed')
    all_ = inp.get('assets') or []
    asset_ids = set(g(a, 'id') for a in all_)
    live = [a for a in all_ if g(a, 'status') not in closed and (g(a, 'type') == 'server' or is_vm(a) or is_hypervisor(a))]
    logins = logins_by_asset(live, inp.get('devices') or [], asset_ids)
    facts = inp.get('facts') or {}
    at = iso(inp['now'])
    filled, kept, skipped, puts = [], [], [], []
    for a in live:
        want = derive(a, logins.get(a['id']))
        if not want:
            continue
        cur = facts.get(a['id'])
        f = {'id': a['id']}
        if cur:
            f.update(cur)
        auto = dict(f.get('auto') or {}) if isinstance(f.get('auto'), dict) else {}
        name = orv(g(a, 'name'), g(a, 'asset_tag'), a['id'])
        changed = False
        for k, w in want.items():
            if 'skip' in w:
                skipped.append({'asset': name, 'field': k, 'reason': w['skip']})
                continue
            if k in ('sockets', 'cores_per_socket') and f.get('source') == 'nutanix':
                continue
            have, mine = f.get(k, MISSING), auto.get(k)
            empty = have is None or have is MISSING or have == ''
            if not empty and not (T(mine) and _same(g(mine, 'v'), have)):
                if not _same(have, w['value']):
                    kept.append({'asset': name, 'field': k, 'entered': have, 'found': w['value'], 'from': w['from']})
                continue
            if not _same(have, w['value']):
                f[k] = w['value']
                changed = True
                filled.append({'asset': name, 'field': k, 'value': w['value'], 'from': w['from']})
            if not T(mine) or not _same(g(mine, 'v'), w['value']) or g(mine, 'from') != w['from']:
                auto[k] = {'v': w['value'], 'from': w['from'], 'at': at}
                changed = True
        if not changed:
            continue
        f['auto'] = auto
        if not cur:
            f['updated_by'] = 'system:licence-sync'
            f['updated_at'] = at
        puts.append(f)
    return _clean({'puts': puts, 'filled': filled, 'kept': kept, 'skipped': skipped})


def unlicensed(inp):
    rolled = rollup([a for a in inp.get('assets') or [] if g(a, 'status') not in ('retired', 'disposed')])
    covered = set()
    for lic in inp.get('licences') or []:
        covered.update(licence_compliance(lic, rolled)['products'])
    out = [p for p in rolled if p['key'] not in covered and not p['licence_id'] and COMMERCIAL.search('%s %s' % (p['publisher'] or '', p['name'])) and not BUNDLED.search(p['name'])]
    return {'unlicensed': [{'product': p['name'], 'publisher': p['publisher'] or '', 'installs': p['installs'], 'versions': p['versions'][:5]} for p in out[:100]]}


def _clean(v):
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if x is not MISSING}
    if isinstance(v, list):
        return [None if x is MISSING else _clean(x) for x in v]
    return v
