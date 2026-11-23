# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Core-based licence audit - migration step 6e (docs/PYTHON-MIGRATION.md). view(inp) answers exactly like view() in
engine/core-licensing.js (Licence audit -> Core-based licences): Oracle Database EE / SE2 and ODI processor licences with
the VMware scope, Windows Server Standard / Datacenter cores, VMware per-core subscriptions, against the entitlements.
The inputs are what Node.js read (settings, assets, facts, runs_on links, entitlements, the capacity collection's
platforms); nothing is written here. Writes (facts, entitlements, settings) stay in Node.js.
Standard library only (Python 3.8+).
"""
import math
import re

from asset_rules import MISSING, S, T, g, ms_of, orv, parse_int
from jscompat import js_round, num

DAY = 86400000
CLOSED = ('retired', 'disposed')
PRODUCTS = {
    'oracle_ee': {'name': 'Oracle Database Enterprise Edition', 'unit': 'processor licences'},
    'oracle_se2': {'name': 'Oracle Database Standard Edition 2', 'unit': 'processor licences (sockets)'},
    'oracle_odi': {'name': 'Oracle Data Integrator Enterprise Edition (ODI)', 'unit': 'processor licences'},
    'windows_std': {'name': 'Windows Server Standard', 'unit': 'cores'},
    'windows_dc': {'name': 'Windows Server Datacenter', 'unit': 'cores'},
    'vmware': {'name': 'VMware vSphere / VVF / VCF', 'unit': 'cores'},
}
SCOPES = ['host', 'cluster', 'vcenter']
_F = re.I | re.ASCII   # JavaScript's \d \s \b are ASCII-only
WIN_SERVER = re.compile(r'win[a-z_ ]*\d*[ _]*(server|srv)', _F)
_ESXI = re.compile(r'esxi|vmware\s*esx', _F)
_PC_X = re.compile(r'(\d+)\s*(?:x|×|\*)\s*[^,;]*?(\d+)[\s-]*cores?', _F)
_PC_SO = re.compile(r'(\d+)\s*(?:sockets?|cpus?|processors?)\b', _F)
_PC_CO = re.compile(r'(\d+)\s*[\s-]*cores?\s*(per|each|/)?', _F)
_ODI = re.compile(r'oracle\s*data\s*integrator|\bodi\b[^\n]*(agent|studio|12c|11g)|odi[_ -]?(agent|studio)', _F)
_ORA = re.compile(r'oracle.*database|oracle\s*db|oracle\s*\d+[cgi]\b', _F)
_SE2 = re.compile(r'standard\s*edition|\bse2?\b', _F)


def _ceil(x):
    """Math.ceil(x) - Infinity stays Infinity (Python's math.ceil raises)"""
    return x if isinstance(x, float) and not math.isfinite(x) else math.ceil(x)


def _div(a, b):
    """a / b with JavaScript's null (= 0) operands: 0 / 0 = NaN, n / 0 = Infinity"""
    a, b = a or 0, b or 0
    if b == 0:
        return float('nan') if a == 0 else math.copysign(float('inf'), a)
    return a / b


def _tags(a):
    t = g(a, 'tags')
    return [S(x).lower() for x in t] if isinstance(t, list) else []


def is_vm(a):
    return g(a, 'type') == 'vm' or 'vm' in _tags(a)


def is_esxi(a):
    return 'esxi-host' in _tags(a) or bool(_ESXI.search(S(orv(g(a, 'os'), ''))))


def cf_of(f):
    """cfOf in engine/core-licensing.js: a core factor written for this host (entered, or matched from the Oracle table)"""
    v = g(f, 'core_factor') if T(f) else MISSING
    if v is MISSING or v is None or v == '':
        return None
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if n != n or not (0 < n <= 1):
        return None
    return int(n) if n == int(n) else n


def factor_for(vendor, dflt):
    v = S(orv(vendor, '')).lower()
    return 1 if re.search('power|ibm', v) else 0.5 if re.search('intel|amd|xeon|epyc|sparc', v) else dflt


def vendor_of(cpu):
    c = S(orv(cpu, ''))
    return ('amd' if re.search('amd|epyc|opteron', c, re.I) else 'intel' if re.search('intel|xeon', c, re.I)
            else 'ibm power' if re.search('power', c, re.I) else 'sparc' if re.search('sparc', c, re.I) else '')


def parse_cores(cpu):
    c = S(orv(cpu, ''))
    m = _PC_X.search(c)
    if m:
        return {'sockets': parse_int(m.group(1)), 'cores_per_socket': parse_int(m.group(2)), 'from': 'cpu text'}
    so, co = _PC_SO.search(c), _PC_CO.search(c)
    if so and co:
        if co.group(2):
            return {'sockets': parse_int(so.group(1)), 'cores_per_socket': parse_int(co.group(1)), 'from': 'cpu text'}
        q = _div(parse_int(co.group(1)), parse_int(so.group(1)))
        q = q if q != q else _ceil(q)
        return {'sockets': parse_int(so.group(1)), 'cores_per_socket': q if q == q and q else None, 'from': 'cpu text'}
    if co:
        return {'sockets': 1, 'cores_per_socket': parse_int(co.group(1)), 'from': 'cpu text', 'total_only': True}
    return None


def _sw_text(x):
    return '%s %s' % (S(orv(g(x, 'publisher'), '')), S(orv(g(x, 'name'), '')))


def _software(a):
    sw = g(a, 'software')
    return sw if isinstance(sw, list) else []


def odi_of(a, fact):
    o = g(fact, 'odi') if T(fact) else MISSING
    if o in ('yes', 'none'):
        return o == 'yes'
    return any(_ODI.search(_sw_text(x)) for x in _software(a))


def oracle_of(a, fact):
    o = g(fact, 'oracle') if T(fact) else MISSING
    if o in ('ee', 'se2', 'none'):
        return None if o == 'none' else o
    sw = next((x for x in _software(a) if _ORA.search(_sw_text(x))), MISSING)
    if sw is MISSING:   # a monitored database reported its edition itself (V$VERSION banner, written by oracle-licences.js)
        od = g(fact, 'oracle_detected') if T(fact) else MISSING
        return od if od in ('ee', 'se2') else None
    return 'se2' if _SE2.search(S(orv(g(sw, 'name'), ''))) else 'ee'


def _cap_hint(cap):
    if not T(cap):
        return 'install the capacity collection (add-virt-capacity.sh) - it reads sockets and cores from vCenter / Prism - or type the counts in here'
    plats = cap.get('platforms') or []
    if not plats:
        return 'connect vCenter / Prism on the Virtualization page - the capacity collection then reads the cores'
    bad = [p for p in plats if T(g(p, 'error'))]
    if bad:
        return ('the last capacity collection failed (' + '; '.join(S(g(p, 'label')) + ': ' + S(p['error']) for p in bad)
                + ') - fix it on Virtualization → Capacity, or type the counts in here')
    return 'not read yet: Virtualization → Capacity → Collect now (the host must be in the inventory from the vCenter / Prism sync), or type the counts in here'


def _plain(v):
    """the answer as JSON.stringify writes it: Infinity and NaN become null"""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if x is not MISSING}
    if isinstance(v, list):
        return [None if x is MISSING else _plain(x) for x in v]
    if isinstance(v, float) and not math.isfinite(v):
        return None
    return v


def view(inp):
    st, t = inp.get('settings') or {}, inp.get('now')
    fact_by = {}
    for f in inp.get('facts') or []:
        if isinstance(f, dict) and 'id' in f:
            fact_by[f['id']] = f
    live = [a for a in (inp.get('assets') or []) if g(a, 'status') not in CLOSED and (g(a, 'type') == 'server' or is_vm(a) or is_esxi(a))]
    by_id = {a['id']: a for a in live}

    def fact_of(i):
        f = fact_by.get(i)
        return f if T(f) else None

    hosts = []
    for a in live:
        if is_vm(a):
            continue
        f, p = fact_of(a['id']) or {}, parse_cores(g(a, 'cpu')) or {}
        fs, fc = parse_int(g(f, 'sockets')), parse_int(g(f, 'cores_per_socket'))
        sockets = fs or p.get('sockets') or None
        cps = fc or p.get('cores_per_socket') or None
        vendor = orv(g(f, 'cpu_vendor'), vendor_of(g(a, 'cpu')))
        esxi = is_esxi(a)
        src = g(f, 'source')
        cf = cf_of(f)
        hosts.append({'id': a['id'], 'name': orv(g(a, 'name'), g(a, 'asset_tag'), a['id']), 'site': orv(g(a, 'site'), ''), 'os': orv(g(a, 'os'), ''), 'cpu': orv(g(a, 'cpu'), ''), 'esxi': esxi,
                      'cluster': orv(g(f, 'cluster'), ''), 'sockets': sockets, 'cores_per_socket': cps, 'cores': sockets * cps if sockets and cps else None,
                      'cores_from': ('vCenter' if src == 'vcenter' else 'Nutanix Prism' if src == 'nutanix' else 'entered') if fs and fc else (p.get('from') or None),
                      'total_only': not fs and bool(p.get('total_only')),
                      'cpu_vendor': vendor, 'factor': cf if cf is not None else factor_for(vendor, st.get('core_factor')), 'factor_assumed': cf is None and not T(vendor),
                      'factor_source': ('entered' if g(f, 'core_factor_src') == 'entered' else 'table') if cf is not None else 'vendor' if T(vendor) else 'default',
                      'factor_row': orv(g(f, 'core_factor_row'), '') if cf is not None else '',
                      'windows_host': bool(WIN_SERVER.search(S(orv(g(a, 'os'), '')))), 'windows_edition': orv(g(f, 'windows'), 'auto'), 'notes': orv(g(f, 'notes'), ''), 'vms': []})
    hint = _cap_hint(inp.get('capacity'))
    for h in hosts:
        if not h['cores'] and (h['esxi'] or re.search('nutanix|ahv', S(h['os']), re.I)):
            h['cores_hint'] = hint
    host_by = {h['id']: h for h in hosts}

    def cluster_key(h):
        return 'esxi:' + S(orv(h['cluster'], '(cluster not set)')) if h['esxi'] else 'host:' + S(h['id'])

    runs_on = {}
    for r in inp.get('runs_on') or []:
        runs_on.setdefault(g(r, 'from'), []).append(g(r, 'to'))

    def host_of(vm_id):
        for to in runs_on.get(vm_id, []):
            h = by_id.get(to)
            if h is not None and g(h, 'status') not in CLOSED:
                return h
        return None

    vms = []
    for a in live:
        if not is_vm(a):
            continue
        f, h = fact_of(a['id']) or {}, host_of(a['id'])
        vms.append({'id': a['id'], 'name': orv(g(a, 'name'), a['id']), 'os': orv(g(a, 'os'), ''), 'host_id': h['id'] if h else None,
                    'windows': bool(WIN_SERVER.search(S(orv(g(a, 'os'), '')))), 'oracle': oracle_of(a, f), 'odi': odi_of(a, f)})
    for v in vms:
        h = host_by.get(v['host_id']) if v['host_id'] else None
        if h:
            h['vms'].append({'id': v['id'], 'name': v['name'], 'windows': v['windows'], 'oracle': v['oracle'], 'odi': v['odi']})

    # Oracle deployments -> physical hosts to license
    deployments = []
    for a in live:
        if is_vm(a):
            continue
        name = orv(g(a, 'name'), a['id'])
        o = oracle_of(a, fact_of(a['id']))
        if o:
            deployments.append({'id': a['id'], 'name': name, 'edition': o, 'vm': False, 'host_id': a['id']})
        if odi_of(a, fact_of(a['id'])):
            deployments.append({'id': a['id'], 'name': name, 'edition': 'odi', 'vm': False, 'host_id': a['id']})
    for v in vms:
        if v['oracle']:
            deployments.append({'id': v['id'], 'name': v['name'], 'edition': v['oracle'], 'vm': True, 'host_id': v['host_id']})
        if v['odi']:
            deployments.append({'id': v['id'], 'name': v['name'], 'edition': 'odi', 'vm': True, 'host_id': v['host_id']})
    all_esxi = [h for h in hosts if h['esxi']]

    def scope_hosts(d):
        h = host_by.get(d['host_id']) if d['host_id'] else None
        if not h:
            return None
        if not d['vm'] or st.get('oracle_scope') == 'host':
            return [h]
        if st.get('oracle_scope') == 'vcenter':
            return all_esxi if h['esxi'] else [h]
        k = cluster_key(h)
        return [x for x in hosts if cluster_key(x) == k]

    oracle = {'ee': {}, 'se2': {}, 'odi': {}}
    for d in deployments:
        sc = scope_hosts(d)
        d['scope'] = [h['name'] for h in sc] if sc else None
        if not sc:
            d['problem'] = 'the physical host of this VM is not known - link the VM to its host (vCenter sync or CMDB)'
            continue
        for h in sc:
            oracle[d['edition']][h['id']] = h
    unknown = []

    def oracle_need(edition):
        req, nup, missing, rows = 0, 0, [], []
        for h in oracle[edition].values():
            if edition in ('ee', 'odi'):
                if not h['cores']:
                    missing.append(h['name'])
                    continue
                n = _ceil(h['cores'] * h['factor'])
                req += n
                nup += n * 25
                rows.append({'host': h['name'], 'cores': h['cores'], 'factor': h['factor'], 'licences': n})
            else:
                if not h['sockets']:
                    missing.append(h['name'])
                    continue
                req += h['sockets']
                nup += 10
                rows.append({'host': h['name'], 'sockets': h['sockets'], 'licences': h['sockets'], 'problem': 'SE2 is allowed only on servers with at most 2 sockets' if h['sockets'] > 2 else None})
        for n in missing:
            unknown.append({'host': n, 'product': 'oracle_' + edition})
        return {'required': req, 'nup_minimum': nup, 'hosts': rows, 'cores_unknown': missing}

    prod = {'oracle_ee': oracle_need('ee'), 'oracle_se2': oracle_need('se2'), 'oracle_odi': oracle_need('odi')}

    # Windows Server per physical host
    w_std, w_dc, w_rows, w_unknown = 0, 0, [], []
    for h in hosts:
        win_vms = len([v for v in h['vms'] if v['windows']])
        oses = win_vms if win_vms > 0 else (1 if h['windows_host'] else 0)
        if not oses:
            continue
        if not h['sockets'] or not h['cores_per_socket']:
            w_unknown.append(h['name'])
            unknown.append({'host': h['name'], 'product': 'windows'})
            continue
        core_req = max(16, h['sockets'] * max(8, h['cores_per_socket']))
        pairs = _ceil(oses / 2)
        std_cores, dc_cores = core_req * pairs, core_req
        suggest = 'dc' if pairs > st.get('win_dc_ratio') else 'std'
        edition = h['windows_edition'] if h['windows_edition'] in ('std', 'dc') else suggest
        if edition == 'dc':
            w_dc += dc_cores
        else:
            w_std += std_cores
        w_rows.append({'host': h['name'], 'cores': h['cores'], 'licensed_cores': core_req, 'windows_oses': oses, 'standard_cores': std_cores, 'datacenter_cores': dc_cores,
                       'edition': edition, 'suggested': suggest, 'packs': (dc_cores if edition == 'dc' else std_cores) / 2})
    prod['windows_std'] = {'required': w_std, 'hosts': [r for r in w_rows if r['edition'] == 'std'], 'cores_unknown': w_unknown}
    prod['windows_dc'] = {'required': w_dc, 'hosts': [r for r in w_rows if r['edition'] == 'dc'], 'cores_unknown': w_unknown}

    # VMware per ESXi host
    vm, vrows, vmiss = 0, [], []
    for h in all_esxi:
        if not h['sockets'] or not h['cores_per_socket']:
            vmiss.append(h['name'])
            unknown.append({'host': h['name'], 'product': 'vmware'})
            continue
        c = h['sockets'] * max(st.get('vmware_min_per_cpu'), h['cores_per_socket'])
        vm += c
        vrows.append({'host': h['name'], 'cluster': orv(h['cluster'], ''), 'cores': h['cores'], 'licensed_cores': c, 'vms': len(h['vms'])})
    mo = st.get('vmware_min_order')
    applied = bool(vm and vm < mo)
    prod['vmware'] = {'required': mo if applied else vm, 'physical_licensed': vm, 'minimum_order_applied': applied, 'hosts': vrows, 'cores_unknown': vmiss}

    # against what is owned
    entitlements = []
    for e in inp.get('entitlements') or []:
        x = dict(e)
        if T(g(e, 'expiry')):
            ms = ms_of(e['expiry'])
            x['days_left'] = float('nan') if ms is None else js_round((ms - t) / DAY)
        else:
            x['days_left'] = None
        entitlements.append(x)
    summary = []
    for k, meta in PRODUCTS.items():
        mine = [e for e in entitlements if g(e, 'product') == k and not (e['days_left'] is not None and e['days_left'] < 0)]
        owned = 0
        for e in mine:
            owned += num(g(e, 'quantity')) or 0
        p = prod[k]
        status = ('shortfall' if owned < p['required'] else 'incomplete' if p['cores_unknown'] else
                  'not_used' if not p['required'] and not owned else 'compliant')
        expiring = [{'id': g(e, 'id'), 'contract': orv(g(e, 'contract'), ''), 'expiry': g(e, 'expiry'), 'days_left': e['days_left']}
                    for e in mine if e['days_left'] is not None and e['days_left'] <= 90]
        summary.append({'product': k, 'name': meta['name'], 'unit': meta['unit'], 'required': p['required'], 'owned': owned, 'delta': owned - p['required'],
                        'status': status, 'cores_unknown': len(p['cores_unknown']), 'expiring': expiring})
    return _plain({'settings': st, 'products_catalogue': PRODUCTS, 'scopes': SCOPES, 'summary': summary, 'products': prod, 'deployments': deployments, 'hosts': hosts,
                   'unknown': unknown, 'entitlements': entitlements,
                   'counts': {'physical': len(hosts), 'esxi': len(all_esxi), 'vms': len(vms), 'vms_without_host': len([v for v in vms if not v['host_id']]),
                              'cores_unknown': len([h for h in hosts if not h['cores']])}})
