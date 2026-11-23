# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Asset Discovery inventory sources that speak HTTP - migration step 5a (docs/PYTHON-MIGRATION.md). Each answers exactly
like its Node.js twin in engine/discovery/methods/: vcenter.js (vSphere Automation REST + host addresses over SOAP),
esxi.js, nutanix.js, azure.js, aws.js (EC2 Query API, SigV4), cucm.js (AXL + RisPort70). STRICTLY READ ONLY: each keeps
its guard() / allow-list, and credentials arrive on stdin only.

  collect(method, cred, opts) -> the method's collect() answer      test(method, cred, opts) -> the diag result
Standard library only (Python 3.8+).
"""
import base64
import json
import re
import time
import urllib.parse

import diag
import httpc
import sigv4
import virt_capacity as VC
import xmlmini as X
from jscompat import MISSING, encode_uri_component, form_encode, js_round, js_str, num as _num, truthy

D = diag.DErr
CLASSES7 = ('auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol')
IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


# ---- JavaScript value rules used below ------------------------------------------------------------------------------
def g(o, k):
    """o.k (MISSING when o is not an object or has no k)"""
    return o.get(k, MISSING) if isinstance(o, dict) else MISSING


def T(v):
    return v is not MISSING and truthy(v)


def orv(*a):
    """a || b || ... (the last one is returned as is)"""
    for v in a[:-1]:
        if T(v):
            return v
    return a[-1]


def andv(o, *ks):
    """o && o.a && o.a.b ..."""
    for k in ks:
        if not T(o):
            return o
        o = g(o, k)
    return o


def S(v):
    """String(v)"""
    if v is MISSING:
        return 'undefined'
    if isinstance(v, list):
        return ','.join('' if x is None or x is MISSING else S(x) for x in v)
    return js_str(v)


def nullish(v):
    return None if v is MISSING else v


def lst(v):
    return v if isinstance(v, list) else []


def uniq(a):
    out = []
    for x in a:
        if x not in out:
            out.append(x)
    return out


def jparse(r):
    """JSON.parse(text) or null - Node's httpc parses any JSON value (a bare string too)"""
    try:
        return json.loads(r['text'])
    except (ValueError, TypeError):
        return None


def err_class(e):
    c = getattr(e, 'code', None)
    return c if c in CLASSES7 else 'protocol'


def as_derr(e):
    if isinstance(e, D):
        return e
    if isinstance(e, httpc.HttpcError):
        return D(e.code, str(e), presented=e.presented, pin_mismatch=getattr(e, 'pin_mismatch', False))
    if isinstance(e, VC.VErr):
        return D(e.code, str(e))
    return D('protocol', '%s' % e)


def _ms(t0):
    return int((time.time() - t0) * 1000)


def basic(cred):
    s = g(cred, 'secret')
    return 'Basic ' + base64.b64encode(('%s:%s' % (S(g(s, 'username')), S(g(s, 'password')))).encode('utf-8')).decode('ascii')


def req(url, method, headers, body, ca_file=None, pin=None, capture=False, timeout_ms=30000):
    try:
        return httpc.request(url, method, headers, body, timeout_ms=timeout_ms, ca_file=ca_file or None, pin=pin or None, capture_untrusted=bool(capture))
    except httpc.HttpcError as e:
        raise as_derr(e)


# ---- vCenter (vSphere Automation REST) ------------------------------------------------------------------------------
SESSION, READ_PREFIX = '/api/session', '/api/vcenter/'
POWER_VC = {'POWERED_ON': 'on', 'POWERED_OFF': 'off', 'SUSPENDED': 'suspended'}


def vc_guard(method, path):
    if method == 'GET' and path.startswith(READ_PREFIX):
        return
    if method in ('POST', 'DELETE') and path == SESSION:
        return
    raise D('config', 'vcenter discovery is read-only; refusing %s %s' % (method, path))


def unwrap(j):
    return j['value'] if isinstance(j, dict) and 'value' in j else j


def vlist(j):
    v = unwrap(j)
    return v if isinstance(v, list) else []


class VcClient:
    def __init__(self, cred, o):
        self.t = orv(g(cred, 'target'), {})
        self.base = re.sub(r'/+$', '', S(orv(g(self.t, 'base_url'), '')))
        self.cred, self.o, self.sid = cred, o, None

    def call(self, method, path, headers=None):
        vc_guard(method, path)
        h = {'Accept': 'application/json'}
        h.update(headers or {})
        if self.sid:
            h['vmware-api-session-id'] = self.sid
        return req(self.base + path, method, h, '' if method == 'POST' else None, nullish(g(self.t, 'ca_file')), nullish(g(self.t, 'tls_fingerprint')),
                   self.o.get('captureUntrusted'), self.o.get('timeoutMs') or 30000)

    def login(self):
        r = self.call('POST', SESSION, {'Authorization': basic(self.cred)})
        if r['status'] in (401, 403):
            raise D('auth', 'vCenter rejected the credentials', 'auth', r['status'], True)
        if r['status'] < 200 or r['status'] >= 300:
            raise D('protocol', 'vCenter session failed (HTTP %s)' % r['status'], 'auth', r['status'], True)
        j = jparse(r)
        i = j if isinstance(j, str) else unwrap(j)
        if not T(i) or not isinstance(i, str):
            raise D('protocol', 'vCenter returned no session id', 'auth', None, True)
        self.sid = i

    def get(self, path):
        r = self.call('GET', path)
        if r['status'] in (401, 403):
            raise D('authz', 'authenticated but not authorised for %s' % path, 'authz', r['status'], True)
        if r['status'] < 200 or r['status'] >= 300:
            raise D('protocol', 'GET %s: HTTP %s' % (path, r['status']), 'read', r['status'], True)
        return jparse(r)

    def try_get(self, path):
        try:
            return self.get(path)
        except Exception:
            return None

    def logout(self):
        if not self.sid:
            return
        try:
            self.call('DELETE', SESSION)
        except Exception:
            pass
        self.sid = None


def nic_macs(detail):
    n = andv(detail, 'nics')
    if isinstance(n, list):
        vals = [orv(g(x, 'value'), x) if T(x) else x for x in n]
    elif isinstance(n, dict):
        vals = list(n.values())
    else:
        vals = []
    return [S(m).lower() for m in (andv(x, 'mac_address') for x in vals) if T(m)]


def guest_ips(ifaces):
    out, macs = [], []
    for i in vlist(ifaces):
        if T(i) and T(g(i, 'mac_address')):
            macs.append(S(i['mac_address']).lower())
        for a in lst(orv(andv(i, 'ip', 'ip_addresses'), [])):
            ipa = g(a, 'ip_address') if T(a) else MISSING
            if T(a) and IPV4.match(S(orv(ipa, ''))):
                out.append(ipa)
    return {'ips': out, 'macs': macs}


def vcenter_collect(cred, o):
    t0 = time.time()
    c = VcClient(cred, o)
    try:
        c.login()
        hosts = []
        for h in vlist(c.get('/api/vcenter/host')):
            if not isinstance(h, dict):
                raise TypeError('host')
            hosts.append({'id': S(orv(g(h, 'host'), g(h, 'id'), '')), 'name': orv(g(h, 'name'), None), 'state': S(orv(g(h, 'connection_state'), '')).lower() or None})
        if hosts and o.get('hostIps') is not False:
            try:
                _, ha = VC._vc(orv(g(cred, 'target'), {}), orv(g(cred, 'secret'), {}), {})
                addr = ha()
                by_id, by_name = {}, {}
                for a in addr:
                    by_id[a['id']] = a
                    by_name[S(a['name']).lower()] = a
                for h in hosts:
                    a = by_id.get(h['id']) or by_name.get(S(h['name'] or '').lower())
                    if a and a['ip']:
                        h['ip'], h['vmk'] = a['ip'], a['vmk']
            except Exception:
                pass   # addresses stay empty - DNS is the fallback
        vms, seen, mx = [], set(), o.get('maxVms') or 5000
        for h in hosts:
            for v in vlist(c.get('/api/vcenter/vm?hosts=%s' % encode_uri_component(h['id']))):
                if not isinstance(v, dict):
                    raise TypeError('vm')
                vid = S(orv(g(v, 'vm'), g(v, 'id'), ''))
                if not vid or vid in seen or len(vms) >= mx:
                    continue
                seen.add(vid)
                e = encode_uri_component(vid)
                detail = orv(unwrap(c.try_get('/api/vcenter/vm/%s' % e)), {})
                ifs = c.try_get('/api/vcenter/vm/%s/guest/networking/interfaces' % e)
                ident = orv(unwrap(c.try_get('/api/vcenter/vm/%s/guest/identity' % e)), {})
                gi = guest_ips(ifs)
                macs = uniq(nic_macs(detail) + gi['macs'])
                iip = g(ident, 'ip_address')
                ips = uniq(gi['ips'] + ([iip] if T(iip) and IPV4.match(S(iip)) else []))
                fn = g(ident, 'full_name')
                ps = S(orv(g(v, 'power_state'), g(detail, 'power_state'), '')).upper()
                vms.append({'id': vid, 'name': orv(g(v, 'name'), g(detail, 'name'), None), 'host_id': h['id'], 'host_name': h['name'],
                            'power_state': POWER_VC.get(ps) or None,
                            'guest_os': orv(orv(g(fn, 'default_message'), fn) if T(fn) else fn, g(detail, 'guest_OS'), g(v, 'guest_OS'), None),
                            'hostname': orv(g(ident, 'host_name'), None), 'ips': ips, 'macs': macs,
                            'uuid': orv(andv(g(detail, 'identity'), 'instance_uuid'), None)})
        return {'ok': True, 'hosts': hosts, 'vms': vms, 'latency_ms': _ms(t0)}
    except Exception as e:
        return {'ok': False, 'error_class': err_class(as_derr(e)), 'latency_ms': _ms(t0)}
    finally:
        c.logout()


def vcenter_test(cred, o):
    t0 = time.time()
    pin = T(andv(g(cred, 'target'), 'tls_fingerprint'))
    c = VcClient(cred, dict(o, captureUntrusted=o.get('captureUntrusted', True)))
    try:
        c.login()
        n = len(vlist(c.get('/api/vcenter/host')))
        return diag.result('vcenter', _ms(t0), pin, 200, {'hosts': n})
    except Exception as e:
        return diag.from_error('vcenter', as_derr(e), _ms(t0), pin)
    finally:
        c.logout()


# ---- standalone ESXi (vSphere Web Services) -------------------------------------------------------------------------
def _host_of(u):
    try:
        x = urllib.parse.urlsplit(S(u))
        if not x.scheme:
            return ''
        return x.hostname or ''
    except ValueError:
        return ''


def _esxi_read(cred, o):
    collect, _ = VC._vc(orv(g(cred, 'target'), {}), orv(g(cred, 'secret'), {}), {'captureUntrusted': o.get('captureUntrusted'), 'timeoutMs': o.get('timeoutMs')})
    return VC.from_vcenter(collect())


_ESXI_IP4 = re.compile(r'^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')


def esxi_collect(cred, o):
    t0 = time.time()
    try:
        m = _esxi_read(cred, o)
        addr = _host_of(andv(g(cred, 'target'), 'base_url'))

        def name(h):
            return addr if len(m['hosts']) == 1 and (not h['name'] or re.match(r'^localhost(\.|$)', h['name'], re.I)) else h['name']
        hn = {h['id']: name(h) for h in m['hosts']}
        return {'ok': True, 'latency_ms': _ms(t0),
                'hosts': [{'id': h['id'], 'name': name(h), 'state': h['state'], 'ip': h['ip'] or (addr if len(m['hosts']) == 1 and _ESXI_IP4.match(addr or '') else None)} for h in m['hosts']],
                'vms': [{'id': v['id'], 'name': v['name'], 'host_id': v['host_id'], 'host_name': hn.get(v['host_id']) or '', 'power_state': v['power'], 'guest_os': v['guest_os'],
                         'hostname': v['name'], 'ips': v['ips'] if isinstance(v.get('ips'), list) else [], 'macs': [], 'uuid': v['uuid'] or None} for v in m['vms']]}
    except Exception as e:
        d = as_derr(e)
        return {'ok': False, 'error_class': err_class(d), 'error': str(d)[:200], 'latency_ms': _ms(t0)}


def esxi_test(cred, o):
    t0 = time.time()
    pin = T(andv(g(cred, 'target'), 'tls_fingerprint'))
    try:
        m = _esxi_read(cred, dict(o, captureUntrusted=o.get('captureUntrusted', True)))
        return diag.result('esxi', _ms(t0), pin, 200, {'hosts': len(m['hosts']), 'vms': len(m['vms'])})
    except Exception as e:
        return diag.from_error('esxi', as_derr(e), _ms(t0), pin)


# ---- Nutanix Prism --------------------------------------------------------------------------------------------------
V3 = re.compile(r'^/api/nutanix/v3/(hosts|vms|clusters)/list$')
V2 = re.compile(r'^/PrismGateway/services/rest/v2\.0/(hosts|vms|cluster)(\?[A-Za-z0-9_=&]*)?$')
POWER_NTX = {'on': 'on', 'off': 'off', 'paused': 'suspended', 'suspended': 'suspended'}


def ntx_guard(method, path):
    if method == 'POST' and V3.search(path):
        return
    if method == 'GET' and V2.search(path):
        return
    raise D('config', 'nutanix discovery is read-only; refusing %s %s' % (method, path))


def ntx_base(url):
    b = re.sub(r'/+$', '', S(orv(url, '')).strip())
    if not re.match(r'^https://', b, re.I):
        raise D('config', 'Prism URL must start with https://')
    try:
        u = urllib.parse.urlsplit(b)
        port = u.port
        if not u.hostname:
            raise ValueError('host')
    except ValueError:
        raise D('config', 'invalid Prism URL')
    if port is None or port == 443:
        host = u.hostname if ':' not in u.hostname else '[%s]' % u.hostname
        b = 'https://%s:9440%s' % (host, re.sub(r'/+$', '', u.path or '/'))
    return b


class NtxClient:
    def __init__(self, cred, o):
        self.t = orv(g(cred, 'target'), {})
        self.base = ntx_base(g(self.t, 'base_url'))
        self.auth, self.o = basic(cred), o

    def call(self, method, path, body=None):
        ntx_guard(method, path)
        h = {'Accept': 'application/json', 'Authorization': self.auth}
        if body:
            h['Content-Type'] = 'application/json'
        r = req(self.base + path, method, h, json.dumps(body, separators=(',', ':'), ensure_ascii=False) if body else None,
                nullish(g(self.t, 'ca_file')), nullish(g(self.t, 'tls_fingerprint')), self.o.get('captureUntrusted'), self.o.get('timeoutMs') or 30000)
        if r['status'] == 401:
            raise D('auth', 'Prism rejected the credentials', 'auth', r['status'], True)
        if r['status'] == 403:
            raise D('authz', 'authenticated but not authorised for %s' % path, 'authz', r['status'], True)
        return r

    def list3(self, kind, mx):
        out = []
        for off in range(0, mx, 500):
            r = self.call('POST', '/api/nutanix/v3/%ss/list' % kind, {'kind': kind, 'length': 500, 'offset': off})
            if r['status'] == 404:
                e = D('protocol', 'not Prism Central', 'read', 404, True)
                e.not_pc = True
                raise e
            if r['status'] < 200 or r['status'] >= 300:
                raise D('protocol', '%s list: HTTP %s' % (kind, r['status']), 'read', r['status'], True)
            j = jparse(r)
            ents = orv(andv(j, 'entities'), [])
            if not isinstance(ents, list):
                raise TypeError('entities')
            out.extend(ents)
            tot = andv(j, 'metadata', 'total_matches')
            tot = _num(tot) if T(tot) else tot
            if not ents or len(ents) < 500 or (T(tot) and len(out) >= tot):
                break
        return out

    def get2(self, path):
        r = self.call('GET', '/PrismGateway/services/rest/v2.0/' + path)
        if r['status'] < 200 or r['status'] >= 300:
            raise D('protocol', 'GET %s: HTTP %s' % (path, r['status']), 'read', r['status'], True)
        return orv(jparse(r), {})


def n_(v):
    x = _num(v)
    return js_round(x) if x is not None and x > 0 else None


def ip_(v):
    s = S(orv(v, ''))
    return s if IPV4.match(s) else None


def _cps(sockets, cores):
    return js_round(cores / sockets) if sockets and cores else None


def from_v3(hosts_raw, vms_raw, clusters_raw):
    clusters = []
    for c in clusters_raw:
        sl = orv(andv(g(c, 'status'), 'resources', 'config', 'service_list'), [])
        if (isinstance(sl, list) and 'PRISM_CENTRAL' in sl) or (isinstance(sl, str) and 'PRISM_CENTRAL' in sl):
            continue
        sm = g(orv(g(orv(g(orv(g(c, 'status'), {}), 'resources'), {}), 'config'), {}), 'software_map')
        nos = g(orv(sm, {}), 'NOS')
        clusters.append({'id': orv(andv(g(c, 'metadata'), 'uuid'), ''), 'name': orv(andv(g(c, 'status'), 'name'), andv(g(c, 'spec'), 'name'), ''),
                         'version': orv(g(nos, 'version'), None) if T(nos) else None})
    hosts = []
    for h in hosts_raw:
        s = orv(g(h, 'status'), {})
        r = orv(g(s, 'resources'), {})
        hv = orv(g(r, 'hypervisor'), {})
        sockets, cores = n_(g(r, 'num_cpu_sockets')), n_(g(r, 'num_cpu_cores'))
        x = {'id': orv(andv(g(h, 'metadata'), 'uuid'), ''), 'name': orv(g(s, 'name'), andv(g(h, 'spec'), 'name'), ''), 'ip': ip_(g(hv, 'ip')),
             'cvm_ip': ip_(andv(g(r, 'controller_vm'), 'ip')), 'ipmi_ip': ip_(andv(g(r, 'ipmi'), 'ip')), 'cluster': orv(andv(g(s, 'cluster_reference'), 'name'), ''),
             'sockets': sockets, 'cores': cores, 'cores_per_socket': _cps(sockets, cores), 'cpu_model': orv(g(r, 'cpu_model'), None), 'serial': orv(g(r, 'serial_number'), None),
             'model': orv(andv(g(r, 'block'), 'block_model'), None), 'hypervisor': orv(g(hv, 'hypervisor_full_name'), None)}
        if T(x['id']) and (x['ip'] or T(x['hypervisor']) or T(x['cluster']) or x['sockets'] or T(x['serial'])):
            hosts.append(x)
    by_host = {h['id']: h for h in hosts}
    vms = []
    for v in vms_raw:
        s = orv(g(v, 'status'), {})
        r = orv(g(s, 'resources'), {})
        hr = orv(g(r, 'host_reference'), {})
        macs, ips = [], []
        for nic in lst(orv(g(r, 'nic_list'), [])):
            if T(g(nic, 'mac_address')):
                macs.append(S(nic['mac_address']).lower())
            for e in lst(orv(g(nic, 'ip_endpoint_list'), [])):
                if ip_(g(e, 'ip')):
                    ips.append(e['ip'])
        hh = by_host.get(g(hr, 'uuid')) if isinstance(g(hr, 'uuid'), str) else None
        x = {'id': orv(andv(g(v, 'metadata'), 'uuid'), ''), 'name': orv(g(s, 'name'), andv(g(v, 'spec'), 'name'), ''), 'host_id': orv(g(hr, 'uuid'), None),
             'host_name': orv(g(hr, 'name'), hh['name'] if hh else MISSING, None), 'cluster': orv(andv(g(s, 'cluster_reference'), 'name'), hh['cluster'] if hh else MISSING, ''),
             'power_state': POWER_NTX.get(S(orv(g(r, 'power_state'), '')).lower()) or None,
             'vcpus': orv(n_(g(r, 'num_sockets')), 1) * orv(n_(g(r, 'num_vcpus_per_socket')), 1), 'memory_mb': n_(g(r, 'memory_size_mib')), 'ips': uniq(ips), 'macs': uniq(macs)}
        if T(x['id']):
            vms.append(x)
    return {'clusters': clusters, 'hosts': hosts, 'vms': vms}


def from_v2(hosts_j, vms_j, cluster_j):
    cname = orv(andv(cluster_j, 'name'), '')
    hosts = []
    for h in lst(orv(andv(hosts_j, 'entities'), [])):
        sockets, cores = n_(g(h, 'num_cpu_sockets')), n_(g(h, 'num_cpu_cores'))
        x = {'id': orv(g(h, 'uuid'), ''), 'name': orv(g(h, 'name'), ''), 'ip': ip_(g(h, 'hypervisor_address')), 'cvm_ip': ip_(g(h, 'service_vmexternal_ip')),
             'ipmi_ip': ip_(g(h, 'ipmi_address')), 'cluster': cname, 'sockets': sockets, 'cores': cores, 'cores_per_socket': _cps(sockets, cores),
             'cpu_model': orv(g(h, 'cpu_model'), None), 'serial': orv(g(h, 'serial'), None), 'model': orv(g(h, 'block_model_name'), None), 'hypervisor': orv(g(h, 'hypervisor_full_name'), None)}
        if T(x['id']):
            hosts.append(x)
    by_host = {h['id']: h for h in hosts}
    vms = []
    for v in lst(orv(andv(vms_j, 'entities'), [])):
        macs, ips = [], []
        for nic in lst(orv(g(v, 'vm_nics'), [])):
            if T(g(nic, 'mac_address')):
                macs.append(S(nic['mac_address']).lower())
            cand = [g(nic, 'ip_address')]
            for extra in (orv(g(nic, 'ip_addresses'), []), orv(g(nic, 'requested_ip_address'), [])):
                cand.extend(extra if isinstance(extra, list) else [extra])
            for a in cand:
                if ip_(a):
                    ips.append(a)
        hu = g(v, 'host_uuid')
        hh = by_host.get(hu) if isinstance(hu, str) else None
        nv = n_(g(v, 'num_vcpus'))
        x = {'id': orv(g(v, 'uuid'), ''), 'name': orv(g(v, 'name'), ''), 'host_id': orv(hu, None), 'host_name': hh['name'] if hh else None, 'cluster': cname,
             'power_state': POWER_NTX.get(S(orv(g(v, 'power_state'), '')).lower()) or None, 'vcpus': nv * orv(n_(g(v, 'num_cores_per_vcpu')), 1) if nv else None,
             'memory_mb': n_(g(v, 'memory_mb')), 'ips': uniq(ips), 'macs': uniq(macs)}
        if T(x['id']):
            vms.append(x)
    clusters = [{'id': orv(andv(cluster_j, 'uuid'), ''), 'name': cname, 'version': orv(andv(cluster_j, 'version'), None)}] if cname else []
    return {'clusters': clusters, 'hosts': hosts, 'vms': vms}


def _all(*fns):
    """Promise.all of the Node.js module: every call is made (Node starts them together), the first failure is raised"""
    res, first = [], None
    for f in fns:
        try:
            res.append(f())
        except Exception as e:   # noqa: PERF203
            res.append(None)
            first = first or e
    if first:
        raise first
    return res


def nutanix_collect(cred, o):
    t0 = time.time()
    try:
        c = NtxClient(cred, o)
        try:
            h, v, cl = _all(lambda: c.list3('host', 2000), lambda: c.list3('vm', o.get('maxVms') or 10000), lambda: c.list3('cluster', 500))
            out = {'ok': True, 'api': 'v3', 'latency_ms': _ms(t0)}
            out.update(from_v3(h, v, cl))
            return out
        except D as e:
            if not e.not_pc:
                raise
            h, v, cl = _all(lambda: c.get2('hosts'), lambda: c.get2('vms?include_vm_nic_config=true'), lambda: c.get2('cluster'))
            out = {'ok': True, 'api': 'v2', 'latency_ms': _ms(t0)}
            out.update(from_v2(h, v, cl))
            return out
    except Exception as e:
        d = as_derr(e)
        return {'ok': False, 'error_class': err_class(d), 'error': str(d)[:200], 'latency_ms': _ms(t0)}


def nutanix_test(cred, o):
    t0 = time.time()
    pin = T(andv(g(cred, 'target'), 'tls_fingerprint'))
    try:
        c = NtxClient(cred, dict(o, captureUntrusted=o.get('captureUntrusted', True)))
        try:
            n = len(c.list3('host', 500))
        except D as e:
            if not e.not_pc:
                raise
            n = len(lst(orv(g(c.get2('hosts'), 'entities'), [])))
        return diag.result('nutanix', _ms(t0), pin, 200, {'hosts': n})
    except Exception as e:
        return diag.from_error('nutanix', as_derr(e), _ms(t0), pin)


# ---- Azure (Resource Graph) -----------------------------------------------------------------------------------------
AZ_QUERY = '\n'.join([
    "Resources | where type =~ 'microsoft.compute/virtualmachines'",
    '| extend nics = properties.networkProfile.networkInterfaces | mv-expand nic = nics | extend nicId = tolower(tostring(nic.id))',
    "| join kind=leftouter (Resources | where type =~ 'microsoft.network/networkinterfaces' | extend nicId = tolower(id), mac = tostring(properties.macAddress)",
    '  | mv-expand ipc = properties.ipConfigurations | extend privateIp = tostring(ipc.properties.privateIPAddress) | project nicId, mac, privateIp) on nicId',
    '| project id, name, location, resourceGroup, subscriptionId, osType = tostring(properties.storageProfile.osDisk.osType),',
    '  vmSize = tostring(properties.hardwareProfile.vmSize), powerState = tostring(properties.extended.instanceView.powerState.code), mac, privateIp',
])


def norm_mac(m):
    h = re.sub(r'[^0-9a-f]', '', S(orv(m, '')).lower())
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def az_token(cred, o):
    login = re.sub(r'/+$', '', S(orv(o.get('login_base', MISSING), 'https://login.microsoftonline.com')))
    t, s = g(cred, 'target'), g(cred, 'secret')
    form = form_encode([('grant_type', 'client_credentials'), ('client_id', S(g(t, 'client_id'))), ('client_secret', S(g(s, 'client_secret'))),
                        ('scope', 'https://management.azure.com/.default')])
    r = req('%s/%s/oauth2/v2.0/token' % (login, encode_uri_component(S(g(t, 'tenant_id')))), 'POST',
            {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}, form, o.get('caFile'), None, False, o.get('timeoutMs') or 30000)
    if r['status'] in (400, 401, 403):
        raise D('auth', 'Azure AD rejected the app credentials', 'auth', r['status'], True)
    j = jparse(r)
    if r['status'] >= 300 or not T(j) or not T(g(j, 'access_token')):
        raise D('protocol', 'Azure AD token HTTP %s' % r['status'], 'auth', r['status'], True)
    return j['access_token']


def az_query(cred, o, bearer, q, skip, top):
    arm = re.sub(r'/+$', '', S(orv(o.get('arm_base', MISSING), 'https://management.azure.com')))
    opts = {'$top': top or 1000}
    if skip:
        opts['$skipToken'] = skip
    body = {'query': q, 'options': opts}
    subs = andv(g(cred, 'target'), 'subscriptions')
    if T(subs) and T(g(subs, 'length') if isinstance(subs, dict) else (len(subs) if isinstance(subs, (list, str)) else MISSING)):
        body['subscriptions'] = subs
    r = req('%s/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01' % arm, 'POST',
            {'Authorization': 'Bearer %s' % S(bearer), 'Content-Type': 'application/json', 'Accept': 'application/json'},
            json.dumps(body, separators=(',', ':'), ensure_ascii=False), o.get('caFile'), None, False, o.get('timeoutMs') or 60000)
    if r['status'] in (401, 403):
        raise D('authz', 'Azure Resource Graph not authorised (Reader role?)', 'authz', r['status'], True)
    j = jparse(r)
    if r['status'] >= 300 or not T(j):
        raise D('protocol', 'Resource Graph HTTP %s' % r['status'], 'read', r['status'], True)
    return j


def az_rows(j):
    d = g(j, 'data')
    if isinstance(d, list):
        return d
    if isinstance(g(d, 'rows'), list) and isinstance(g(d, 'columns'), list):
        cols = [g(c, 'name') for c in d['columns']]
        return [{(S(c)): (r[i] if isinstance(r, list) and i < len(r) else None) for i, c in enumerate(cols)} for r in d['rows']]
    return []


def az_fold(rows):
    by = {}
    for r in rows:
        if not isinstance(r, dict):
            raise TypeError('row')
        rid = S(orv(g(r, 'id'), '')).lower()
        if not rid:
            continue
        v = by.get(rid)
        if v is None:
            ps = g(r, 'powerState')
            v = {'id': rid, 'name': orv(g(r, 'name'), None), 'location': orv(g(r, 'location'), None), 'resource_group': orv(g(r, 'resourceGroup'), None),
                 'subscription': orv(g(r, 'subscriptionId'), None), 'os_type': orv(g(r, 'osType'), None), 'size': orv(g(r, 'vmSize'), None),
                 'power': re.sub(r'^PowerState/', '', S(ps), flags=re.I) if T(ps) else None, 'ips': [], 'macs': []}
        pip = g(r, 'privateIp')
        if T(pip) and IPV4.match(S(pip)) and pip not in v['ips']:
            v['ips'].append(pip)
        m = norm_mac(g(r, 'mac'))
        if m and m not in v['macs']:
            v['macs'].append(m)
        by[rid] = v
    return list(by.values())


def azure_collect(cred, o):
    t0 = time.time()
    try:
        bearer = az_token(cred, o)
        rows, skip, pages = [], None, 0
        while True:
            j = az_query(cred, o, bearer, AZ_QUERY, skip, 1000)
            rows.extend(az_rows(j))
            skip = orv(g(j, '$skipToken'), None)
            pages += 1
            if not (skip and pages < 100):
                break
        return {'ok': True, 'vms': az_fold(rows), 'latency_ms': _ms(t0)}
    except Exception as e:
        return {'ok': False, 'error_class': err_class(as_derr(e)), 'latency_ms': _ms(t0)}


def azure_test(cred, o):
    t0 = time.time()
    try:
        b = az_token(cred, o)
        az_query(cred, o, b, 'Resources | project id | limit 1', None, 1)
        return diag.result('azure', _ms(t0), False, 200)
    except Exception as e:
        return diag.from_error('azure', as_derr(e), _ms(t0))


# ---- AWS EC2 --------------------------------------------------------------------------------------------------------
EC2_VERSION = '2016-11-15'


def parse_describe(text, region):
    doc = X.parse(text)
    out = []
    rs = X.find(doc, 'reservationSet')
    for res in rs.children if rs is not None else []:
        account = X.child_text(res, 'ownerId') or None
        inst = X.child(res, 'instancesSet')
        for i in inst.children if inst is not None else []:
            tags = X.child(i, 'tagSet')
            name_tag = next((t for t in tags.children if X.child_text(t, 'key') == 'Name'), None) if tags is not None else None
            nis = X.child(i, 'networkInterfaceSet')
            macs = [m for m in (X.child_text(n, 'macAddress').lower() for n in nis.children) if m] if nis is not None else []
            st = X.child(i, 'instanceState')
            pl = X.child(i, 'placement')
            out.append({'id': X.child_text(i, 'instanceId'), 'name': X.child_text(name_tag, 'value') if name_tag is not None else None,
                        'type': X.child_text(i, 'instanceType') or None, 'state': (X.child_text(st, 'name') or None) if st is not None else None,
                        'private_ip': X.child_text(i, 'privateIpAddress') or None, 'public_ip': X.child_text(i, 'ipAddress') or None,
                        'private_dns': X.child_text(i, 'privateDnsName') or None, 'macs': macs,
                        'platform': X.child_text(i, 'platformDetails') or ('Windows' if X.child_text(i, 'platform') == 'windows' else 'Linux/UNIX'),
                        'region': region, 'az': (X.child_text(pl, 'availabilityZone') or None) if pl is not None else None, 'account': account})
    nx = X.find(doc, 'nextToken')
    return {'instances': [x for x in out if x['id']], 'nextToken': (nx.text.strip() or None) if nx is not None else None}


def aws_describe(cred, region, o, token, mx):
    tpl = S(orv(o.get('endpoint', MISSING), 'https://ec2.{region}.amazonaws.com'))
    base = re.sub(r'/+$', '', tpl.replace('{region}', S(region), 1))
    qs = [('Action', 'DescribeInstances'), ('Version', EC2_VERSION), ('MaxResults', S(mx))]
    if token:
        qs.append(('NextToken', token))
    url = '%s/?%s' % (base, form_encode(qs))
    s = g(cred, 'secret')
    sg = sigv4.sign({'method': 'GET', 'url': url, 'region': S(region), 'service': 'ec2', 'accessKeyId': S(g(s, 'access_key_id')),
                     'secretAccessKey': S(g(s, 'secret_access_key')), 'amzDate': o.get('amzDate')})
    r = req(url, 'GET', sg['headers'], None, o.get('caFile'), None, False, o.get('timeoutMs') or 30000)
    et = r['text'] if r['status'] >= 400 else ''
    if 'UnauthorizedOperation' in et:
        raise D('authz', 'AWS access key lacks ec2:DescribeInstances', 'authz', r['status'], True)
    if r['status'] in (401, 403) or re.search('AuthFailure|SignatureDoesNotMatch|InvalidClientTokenId', et):
        raise D('auth', 'AWS rejected the access key', 'auth', r['status'], True)
    if r['status'] >= 400:
        raise D('protocol', 'EC2 DescribeInstances HTTP %s' % r['status'], 'read', r['status'], True)
    return parse_describe(r['text'], region)


def aws_collect(cred, o):
    t0 = time.time()
    try:
        out = []
        regions = orv(andv(g(cred, 'target'), 'regions'), [])
        for region in lst(regions):
            token, pages = None, 0
            while True:
                r = aws_describe(cred, region, o, token, 1000)
                out.extend(r['instances'])
                token = r['nextToken']
                pages += 1
                if not (token and pages < 100):
                    break
        return {'ok': True, 'instances': out, 'latency_ms': _ms(t0)}
    except Exception as e:
        return {'ok': False, 'error_class': err_class(as_derr(e)), 'latency_ms': _ms(t0)}


def aws_test(cred, o):
    t0 = time.time()
    try:
        regions = g(g(cred, 'target'), 'regions')
        if not isinstance(regions, (list, str)):
            raise TypeError('regions')
        aws_describe(cred, regions[0] if regions else MISSING, o, None, 5)
        return diag.result('aws', _ms(t0), False, 200)
    except Exception as e:
        return diag.from_error('aws', as_derr(e), _ms(t0))


# ---- Cisco Unified CM (AXL + RisPort70) -----------------------------------------------------------------------------
def axl_envelope(ver, op, inner):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/%s">'
            '<soapenv:Header/><soapenv:Body><ns:%s>%s</ns:%s></soapenv:Body></soapenv:Envelope>') % (X.esc(ver), op, inner, op)


def _int32(v):
    x = _num(v)
    return 0 if x is None else int(x) & 0xFFFFFFFF if int(x) & 0x80000000 == 0 else (int(x) & 0xFFFFFFFF) - 0x100000000


def list_phone_body(ver, skip, first):
    return axl_envelope(ver, 'listPhone', '<searchCriteria><name>%%</name></searchCriteria>'
                        '<returnedTags><name/><description/><product/><model/><protocol/><devicePoolName/></returnedTags>'
                        '<skip>%d</skip><first>%d</first>' % (_int32(skip), _int32(first)))


def ris_body(names):
    items = ''.join('<soap:item><soap:Item>%s</soap:Item></soap:item>' % X.esc(n) for n in (names if names else ['*']))
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">'
            '<soapenv:Header/><soapenv:Body><soap:selectCmDevice><soap:StateInfo></soap:StateInfo><soap:CmSelectionCriteria>'
            '<soap:MaxReturnedDevices>1000</soap:MaxReturnedDevices><soap:DeviceClass>Phone</soap:DeviceClass><soap:Model>255</soap:Model>'
            '<soap:Status>Any</soap:Status><soap:NodeName></soap:NodeName><soap:SelectBy>Name</soap:SelectBy>'
            '<soap:SelectItems>%s</soap:SelectItems><soap:Protocol>Any</soap:Protocol><soap:DownloadStatus>Any</soap:DownloadStatus>'
            '</soap:CmSelectionCriteria></soap:selectCmDevice></soapenv:Body></soapenv:Envelope>') % items


def mac_from_name(name):
    m = re.match(r'^(?:SEP|ATA|BAT)?([0-9A-Fa-f]{12})$', S(orv(name, '')))
    return ':'.join(m.group(1).lower()[i:i + 2] for i in range(0, 12, 2)) if m else None


def parse_list_phone(text):
    out = []
    for p in X.find_all(X.parse(text), 'phone'):
        name = X.child_text(p, 'name')
        x = {'name': name, 'mac': mac_from_name(name), 'description': X.child_text(p, 'description') or None,
             'model': X.child_text(p, 'model') or X.child_text(p, 'product') or None, 'device_pool': X.child_text(p, 'devicePoolName') or None,
             'protocol': X.child_text(p, 'protocol') or None}
        if name:
            out.append(x)
    return out


def parse_ris(text):
    out = {}
    for dev in X.find_all(X.parse(text), 'CmDevices'):
        for it in dev.children:
            name = X.child_text(it, 'Name')
            if not name:
                continue
            ipn = X.child(it, 'IPAddress')
            ip = (X.text_of(ipn, 'IP') or ipn.text.strip()) if ipn is not None else ''
            status = X.child_text(it, 'Status') or None
            prev = out.get(name)
            if prev is None or (status == 'Registered' and prev['status'] != 'Registered'):
                out[name] = {'status': status, 'ip': ip if IPV4.match(ip) else None}
    return out


def fault_of(text):
    try:
        f = X.find(X.parse(text), 'Fault')
        return (X.text_of(f, 'faultstring') or 'SOAP fault') if f is not None else None
    except Exception:
        return None


def cucm_caller(cred, o):
    t = orv(g(cred, 'target'), {})
    host, port = g(t, 'host'), orv(g(t, 'port'), 8443)
    auth = basic(cred)

    def soap(path, action, body):
        r = req('https://%s:%s%s' % (S(host), S(port), path), 'POST', {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': action, 'Authorization': auth, 'Accept': 'text/xml'},
                body, nullish(g(t, 'ca_file')), None, o.get('captureUntrusted'), o.get('timeoutMs') or 30000)
        if r['status'] in (401, 403):
            raise D('auth', 'CUCM rejected the credentials', 'auth', r['status'], True)
        if r['status'] >= 400:
            raise D('protocol', 'CUCM %s: HTTP %s%s' % (action, r['status'], ' (SOAP fault)' if fault_of(r['text']) else ''), 'read', r['status'], True)
        return r['text']
    return soap


def cucm_collect(cred, o):
    t0 = time.time()
    ver = S(orv(andv(g(cred, 'target'), 'axl_version'), '12.5'))
    soap = cucm_caller(cred, o)
    try:
        phones, page, skip = [], o.get('pageSize') or 500, 0
        while skip < 50000:
            batch = parse_list_phone(soap('/axl/', '"CUCM:DB ver=%s listPhone"' % ver, list_phone_body(ver, skip, page)))
            phones.extend(batch)
            if len(batch) < page:
                break
            skip += page
        reg = {}
        for i in range(0, len(phones), 1000):
            try:
                for k, v in parse_ris(soap('/realtimeservice2/services/RISService70', 'selectCmDevice', ris_body([p['name'] for p in phones[i:i + 1000]]))).items():
                    reg[k] = v
            except Exception as e:
                if getattr(e, 'code', None) == 'auth':
                    raise   # RIS is optional, a rejected login is not
        for p in phones:
            r = reg.get(p['name'])
            p['status'] = r['status'] if r else None
            p['ip'] = r['ip'] if r else None
        return {'ok': True, 'phones': phones, 'latency_ms': _ms(t0)}
    except Exception as e:
        return {'ok': False, 'error_class': err_class(as_derr(e)), 'latency_ms': _ms(t0)}


def cucm_test(cred, o):
    t0 = time.time()
    ver = S(orv(andv(g(cred, 'target'), 'axl_version'), '12.5'))
    try:
        cucm_caller(cred, dict(o, captureUntrusted=o.get('captureUntrusted', True)))('/axl/', '"CUCM:DB ver=%s getCCMVersion"' % ver, axl_envelope(ver, 'getCCMVersion', ''))
        return diag.result('cucm_axl', _ms(t0), False, 200)
    except Exception as e:
        return diag.from_error('cucm_axl', as_derr(e), _ms(t0))


def _ad():
    import ad_source   # loaded only when Active Directory is asked for
    return ad_source


def _snmp():
    import snmp_source   # loaded only when SNMP is asked for
    return snmp_source


def _snmp_test(c, o):
    return {'ok': False, 'error_class': 'config', 'error': 'the SNMP probe runs in Node.js'}


METHODS = {'ad': (lambda c, o: _ad().collect(c, o), lambda c, o: _ad().test(c, o)),
           'snmp': (lambda c, o: _snmp().collect(o.get('host'), c, o), _snmp_test), 'vcenter': (vcenter_collect, vcenter_test), 'esxi': (esxi_collect, esxi_test), 'nutanix': (nutanix_collect, nutanix_test),
           'azure': (azure_collect, azure_test), 'aws': (aws_collect, aws_test), 'cucm': (cucm_collect, cucm_test)}


def run(op, method, cred, opts):
    m = METHODS.get(method)
    if not m:
        return {'ok': False, 'error_class': 'config', 'error': 'unknown discovery method %r' % method}
    return (m[0] if op == 'collect' else m[1])(cred if isinstance(cred, dict) else {}, opts if isinstance(opts, dict) else {})
