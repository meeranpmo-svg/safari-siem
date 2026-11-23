# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""VMware vCenter / ESXi (vSphere Web Services, SOAP) and Nutanix Prism capacity readers - migration step 4
(docs/PYTHON-MIGRATION.md). Answers exactly like vcSoap().collect() + fromVcenter(), vcSoap().hostAddresses() and
ntxClient().collect() in engine/virt-capacity.js. READ ONLY: only the calls in SOAP_OK / NTX_OK can be sent.

  vcenter(target, secret, opts)        -> the capacity model {clusters, hosts, datastores, vms, usage, vm_usage, health}
  vcenter_hosts(target, secret, opts)  -> [{id, name, ip, vmk, portgroup}]   each host's management address
  nutanix(target, secret, opts)        -> {clusters, hosts, datastores, vms, usage, vm_usage[, alerts]}
  failure                              -> {ok: False, error_class, error}
Standard library only (Python 3.8+).
"""
import base64
import json
import re
import urllib.parse

import httpc
import xmlmini as X
from jscompat import MISSING, iso, js_round, js_str, num as _num, truthy


class VErr(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def num(v=MISSING):
    return None if isinstance(v, X.Node) else _num(v)


def S(v=MISSING):
    """String(v) - undefined / arrays as JavaScript writes them"""
    if v is MISSING:
        return 'undefined'
    if isinstance(v, list):
        return ','.join('' if x is None or x is MISSING else S(x) for x in v)
    return js_str(v)


def orv(*a):
    """a || b || c"""
    for v in a[:-1]:
        if v is not MISSING and truthy(v):
            return v
    return a[-1]


def g(o, k):
    """o.k (undefined = MISSING); o null/undefined is a TypeError in JavaScript, here MISSING (only used where JS guards)"""
    return o.get(k, MISSING) if isinstance(o, dict) else MISSING


def tv(v):
    """a MISSING value read as a truthy test"""
    return v is not MISSING and truthy(v)


def nn(v):
    """!= null"""
    return v is not None and v is not MISSING


def _str(v):
    return v if isinstance(v, str) else ''


def _req(url, method, headers, body, target, o, timeout):
    return httpc.request(url, method, headers, body, timeout_ms=o.get('timeoutMs') or timeout,
                         ca_file=target.get('ca_file') or None, pin=target.get('tls_fingerprint') or None,
                         capture_untrusted=bool(o.get('captureUntrusted')))


# ---- vCenter (SOAP) -------------------------------------------------------------------------------------------------
SOAP_OK = {'RetrieveServiceContent', 'Login', 'Logout', 'CreateContainerView', 'DestroyView', 'RetrievePropertiesEx', 'ContinueRetrievePropertiesEx'}
PROPS = {
    'HostSystem': ['name', 'parent', 'runtime.connectionState', 'runtime.inMaintenanceMode', 'summary.hardware.vendor', 'summary.hardware.model', 'summary.hardware.cpuModel', 'summary.hardware.cpuMhz',
                   'summary.hardware.numCpuPkgs', 'summary.hardware.numCpuCores', 'summary.hardware.numCpuThreads', 'summary.hardware.memorySize', 'summary.quickStats.overallCpuUsage', 'summary.quickStats.overallMemoryUsage', 'summary.config.product.fullName'],
    'ClusterComputeResource': ['name', 'summary.numHosts', 'summary.totalCpu', 'summary.totalMemory', 'summary.effectiveCpu', 'summary.effectiveMemory'],
    'Datastore': ['summary.name', 'summary.type', 'summary.capacity', 'summary.freeSpace', 'summary.uncommitted', 'summary.accessible'],
    'VirtualMachine': ['name', 'config.instanceUuid', 'config.template', 'config.guestFullName', 'config.hardware.numCPU', 'config.hardware.memoryMB', 'runtime.powerState', 'runtime.host',
                       'summary.storage.committed', 'summary.storage.uncommitted', 'summary.quickStats.overallCpuUsage', 'summary.quickStats.guestMemoryUsage'],
}
HEALTH = {
    'HostSystem': ['overallStatus'],
    'ClusterComputeResource': ['overallStatus', 'configuration.dasConfig.enabled', 'configuration.drsConfig.enabled'],
    'Datastore': ['overallStatus'],
    'VirtualMachine': ['runtime.consolidationNeeded', 'guest.toolsRunningStatus', 'snapshot.rootSnapshotList'],
}
_ENV = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">')
IP4 = re.compile(r'^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')


def _vc(target, secret, o):
    url = re.sub(r'/+$', '', S(target.get('base_url', MISSING))) + '/sdk'
    st = {'cookie': ''}

    def call(method, inner):
        if method not in SOAP_OK:
            raise VErr('config', 'vCenter capacity is read-only; refusing %s' % method)
        body = _ENV + '<soapenv:Body><%s xmlns="urn:vim25">%s</%s></soapenv:Body></soapenv:Envelope>' % (method, inner, method)
        headers = {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'urn:vim25/6.7'}
        if st['cookie']:
            headers['Cookie'] = st['cookie']
        r = _req(url, 'POST', headers, body, target, o, 60000)
        sc = r['headers'].get('set-cookie')
        for x in (sc if isinstance(sc, list) else [sc] if sc else []):
            c = str(x).split(';')[0]
            if re.match(r'^vmware_soap_session=', c):
                st['cookie'] = c
                break
        try:
            doc = X.parse(r['text'] or '')
        except ValueError:
            raise VErr('protocol', 'vCenter answered with something that is not SOAP')
        fault = X.find(doc, 'Fault')
        if fault is not None:
            fs, detail = X.text_of(fault, 'faultstring'), X.find(fault, 'detail')
            kind = detail.children[0].name if detail is not None and detail.children else ''
            code = 'auth' if re.search('InvalidLogin', kind + fs, re.I) else 'authz' if re.search('NoPermission|NotAuthenticated', kind + fs, re.I) else 'protocol'
            raise VErr(code, 'vCenter: %s' % (fs or kind or 'SOAP fault'))
        if r['status'] < 200 or r['status'] >= 300:
            raise VErr('config' if r['status'] == 404 else 'protocol', 'vCenter %s: HTTP %s' % (method, r['status']))
        return doc

    def ref(typ, v):
        return '<_this type="%s">%s</_this>' % (typ, X.esc(v))

    def objects(doc):
        out = []
        for ob in X.find_all(doc, 'objects'):
            obj = X.child(ob, 'obj')
            p = {'_id': obj.text.strip() if obj is not None else '', '_type': obj.attrs.get('type') if obj is not None else ''}
            for ps in [x for x in ob.children if x.name == 'propSet']:
                v = X.child(ps, 'val')
                p[X.child_text(ps, 'name')] = (v if v.children and not v.text.strip() else v.text.strip()) if v is not None else ''
            out.append(p)
        return out

    def session(fn):
        sc = X.find(call('RetrieveServiceContent', ref('ServiceInstance', 'ServiceInstance')), 'returnval')
        root, pc, vm, sm = (X.child_text(sc, k) for k in ('rootFolder', 'propertyCollector', 'viewManager', 'sessionManager'))
        if not root or not pc or not vm or not sm:
            raise VErr('protocol', 'vCenter: unexpected service content')
        call('Login', ref('SessionManager', sm) + '<userName>%s</userName><password>%s</password>'
             % (X.esc(secret.get('username')), X.esc(secret.get('password'))))

        def retrieve(typ, paths):
            view = X.text_of(X.find(call('CreateContainerView', ref('ViewManager', vm) + '<container type="Folder">%s</container><type>%s</type><recursive>true</recursive>'
                                         % (X.esc(root), typ)), 'returnval'))
            try:
                spec = ('<specSet><propSet><type>%s</type>%s</propSet><objectSet><obj type="ContainerView">%s</obj><skip>true</skip>'
                        % (typ, ''.join('<pathSet>%s</pathSet>' % p for p in paths), X.esc(view))
                        + '<selectSet xsi:type="TraversalSpec"><name>traverseView</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet></objectSet></specSet>')
                doc = call('RetrievePropertiesEx', ref('PropertyCollector', pc) + spec + '<options><maxObjects>1000</maxObjects></options>')
                allo = objects(doc)
                for _ in range(100):
                    tok = X.text_of(X.find(doc, 'returnval'), 'token')
                    if not tok:
                        break
                    doc = call('ContinueRetrievePropertiesEx', ref('PropertyCollector', pc) + '<token>%s</token>' % X.esc(tok))
                    allo.extend(objects(doc))
                return allo
            finally:
                try:
                    call('DestroyView', '<_this type="ContainerView">%s</_this>' % X.esc(view))
                except Exception:
                    pass   # the view ends with the session
        try:
            return fn(retrieve)
        finally:
            try:
                call('Logout', ref('SessionManager', sm))
            except Exception:
                pass   # the session times out on its own

    def host_addresses():
        def run(retrieve):
            out = []
            for h in retrieve('HostSystem', ['name', 'config.network.vnic']):
                d = {'id': h['_id'], 'name': _str(h.get('name'))}
                d.update(mgmt_nic(h.get('config.network.vnic')))
                out.append(d)
            return out
        return session(run)

    def collect():
        def run(retrieve):
            out = {}
            for typ in PROPS:
                out[typ] = retrieve(typ, PROPS[typ])
            try:   # serial number (vSphere 6.7+) in its own call: an older vCenter rejects the property
                m = {x['_id']: x.get('hardware.systemInfo.serialNumber') for x in retrieve('HostSystem', ['hardware.systemInfo.serialNumber'])}
                for h in out['HostSystem']:
                    v = m.get(h['_id'])
                    h['serial'] = v if v is not None and (isinstance(v, X.Node) or truthy(v)) else ''
            except Exception:
                pass
            try:   # management address in its own call too: a role without Host.Config read sees no vnic
                rows = retrieve('HostSystem', ['config.network.vnic'])
                m = {x['_id']: mgmt_nic(x.get('config.network.vnic')) for x in rows}
                allv = {x['_id']: vmk_nics(x.get('config.network.vnic')) for x in rows}
                for h in out['HostSystem']:
                    n = m.get(h['_id'])
                    if n and n['ip']:
                        h['mgmt_ip'], h['mgmt_vmk'] = n['ip'], n['vmk']
                    h['vmks'] = allv.get(h['_id']) or []
            except Exception:
                pass
            try:   # VM guest addresses (VMware Tools reports them) in their own call: an older vCenter or a narrow role must not stop the rest
                m = {x['_id']: guest_ips(x.get('guest.ipAddress'), x.get('guest.net')) for x in retrieve('VirtualMachine', ['guest.ipAddress', 'guest.net'])}
                for v in out['VirtualMachine']:
                    l = m.get(v['_id'])
                    if l:
                        v['ips'] = l
            except Exception:
                pass
            out['_health'] = {}
            for typ, keys in HEALTH.items():
                try:
                    m = {x['_id']: x for x in retrieve(typ, keys)}
                    for ob in out.get(typ) or []:
                        h = m.get(ob['_id'])
                        if h is not None:
                            for k in keys:
                                if k in h:
                                    ob[k] = h[k]
                    out['_health'][typ] = True
                except Exception:
                    out['_health'][typ] = False
            return out
        return session(run)

    return collect, host_addresses


def guest_ips(primary, net):
    """guestIps in engine/virt-capacity.js: guest.ipAddress, then every NIC's ipAddress in guest.net, filtered like Prism's"""
    l = [primary] if isinstance(primary, str) else []
    if isinstance(net, X.Node):
        l += [n.text.strip() for n in X.find_all(net, 'ipAddress') if isinstance(n.text, str)]
    return nic_ips([], l)


def vmk_nics(val):
    """every VMkernel interface with an IPv4 address (management, vMotion, vSAN, storage ...) - a host has several"""
    if not isinstance(val, X.Node):
        return []
    out = []
    for n in X.find_all(val, 'HostVirtualNic'):
        sp = X.child(n, 'spec')
        ip = X.child(sp, 'ip') if sp is not None else None
        d = {'vmk': X.child_text(n, 'device') or None, 'portgroup': X.child_text(n, 'portgroup') or None, 'ip': X.child_text(ip, 'ipAddress') if ip is not None else ''}
        if IP4.match(d['ip']):
            out.append(d)
    return out[:16]


def mgmt_nic(val):
    """HostSystem config.network.vnic -> the management VMkernel interface {ip, vmk, portgroup}"""
    if not isinstance(val, X.Node):
        return {'ip': None, 'vmk': None, 'portgroup': None}
    nics = []
    for n in X.find_all(val, 'HostVirtualNic'):
        sp = X.child(n, 'spec')
        ip = X.child(sp, 'ip') if sp is not None else None
        d = {'vmk': X.child_text(n, 'device'), 'portgroup': X.child_text(n, 'portgroup'), 'ip': X.child_text(ip, 'ipAddress') if ip is not None else ''}
        if IP4.match(d['ip']):
            nics.append(d)
    n = next((x for x in nics if re.search('management', x['portgroup'], re.I)), None) or next((x for x in nics if x['vmk'] == 'vmk0'), None) or (nics[0] if nics else None)
    return {'ip': n['ip'], 'vmk': n['vmk'] or None, 'portgroup': n['portgroup'] or None} if n else {'ip': None, 'vmk': None, 'portgroup': None}


def from_vcenter(raw):
    H = raw.get('_health') or {}

    def b(v):
        return True if v == 'true' else False if v == 'false' else None

    def status(v):
        return _str(v) if re.match(r'^(green|yellow|red|gray)$', _str(v)) else None

    def gv(o, k):
        return o.get(k, MISSING)

    clusters = []
    for c in raw.get('ClusterComputeResource') or []:
        em = num(gv(c, 'summary.effectiveMemory'))
        clusters.append({'id': c['_id'], 'name': _str(c.get('name')), 'cpu_mhz': num(gv(c, 'summary.totalCpu')), 'mem_bytes': num(gv(c, 'summary.totalMemory')),
                         'eff_cpu_mhz': num(gv(c, 'summary.effectiveCpu')), 'eff_mem_bytes': em * 1048576 if em is not None else None,
                         'status': status(c.get('overallStatus')), 'ha': b(c.get('configuration.dasConfig.enabled')), 'drs': b(c.get('configuration.drsConfig.enabled'))})
    cname = {c['id']: c['name'] for c in clusters}
    hosts = []
    for h in raw.get('HostSystem') or []:
        parent, mhz, cores = _str(h.get('parent')), num(gv(h, 'summary.hardware.cpuMhz')), num(gv(h, 'summary.hardware.numCpuCores'))
        mu = num(gv(h, 'summary.quickStats.overallMemoryUsage'))
        hosts.append({'id': h['_id'], 'name': _str(h.get('name')), 'cluster_id': parent if parent in cname else None, 'cluster': cname.get(parent) or 'Standalone hosts',
                      'vendor': _str(h.get('summary.hardware.vendor')), 'model': _str(h.get('summary.hardware.model')), 'serial': _str(h.get('serial')),
                      'cpu_model': re.sub(r'\s+', ' ', _str(h.get('summary.hardware.cpuModel'))), 'sockets': num(gv(h, 'summary.hardware.numCpuPkgs')), 'cores': cores,
                      'threads': num(gv(h, 'summary.hardware.numCpuThreads')), 'cpu_mhz': mhz * cores if truthy(mhz) and truthy(cores) else None,
                      'cpu_used_mhz': num(gv(h, 'summary.quickStats.overallCpuUsage')), 'mem_bytes': num(gv(h, 'summary.hardware.memorySize')),
                      'mem_used_bytes': mu * 1048576 if mu is not None else None,
                      'ip': _str(h.get('mgmt_ip')) or None, 'vmk': _str(h.get('mgmt_vmk')) or None,
                      'vmks': [{'vmk': _str(v.get('vmk')) or None, 'portgroup': _str(v.get('portgroup')) or None, 'ip': _str(v.get('ip'))} for v in h['vmks']] if isinstance(h.get('vmks'), list) else [],
                      'version': _str(h.get('summary.config.product.fullName')), 'state': _str(h.get('runtime.connectionState')) or 'unknown',
                      'maintenance': h.get('runtime.inMaintenanceMode') == 'true', 'status': status(h.get('overallStatus'))})
    datastores = [{'id': d['_id'], 'name': _str(d.get('summary.name')), 'type': _str(d.get('summary.type')), 'capacity': num(gv(d, 'summary.capacity')),
                   'free': num(gv(d, 'summary.freeSpace')), 'uncommitted': num(gv(d, 'summary.uncommitted')), 'accessible': d.get('summary.accessible') != 'false',
                   'status': status(d.get('overallStatus'))} for d in raw.get('Datastore') or []]

    def snaps(v):
        n = v.get('snapshot.rootSnapshotList')
        if not isinstance(n, X.Node):
            return {'count': 0, 'oldest': None} if truthy(H.get('VirtualMachine')) else None
        t = [x for x in (iso(c.text.strip()) for c in X.find_all(n, 'createTime')) if x]
        return {'count': len(t), 'oldest': min(t) if t else None}

    def tools(v):
        t = _str(v.get('guest.toolsRunningStatus'))
        if not t:
            return None
        return 'running' if re.search('Running$', t) and 'NotRunning' not in t else 'not-running'

    vms = []
    for v in raw.get('VirtualMachine') or []:
        if v.get('config.template') == 'true':
            continue
        ps = _str(v.get('runtime.powerState'))
        vms.append({'id': v['_id'], 'name': _str(v.get('name')), 'uuid': _str(v.get('config.instanceUuid')), 'host_id': _str(v.get('runtime.host')) or None,
                    'power': 'on' if re.search('poweredOn', ps, re.I) else 'suspended' if re.search('suspended', ps, re.I) else 'off', 'guest_os': _str(v.get('config.guestFullName')),
                    'vcpus': num(gv(v, 'config.hardware.numCPU')), 'mem_mb': num(gv(v, 'config.hardware.memoryMB')), 'disk_bytes': num(gv(v, 'summary.storage.committed')),
                    'disk_uncommitted': num(gv(v, 'summary.storage.uncommitted')), 'cpu_used_mhz': num(gv(v, 'summary.quickStats.overallCpuUsage')),
                    'mem_used_mb': num(gv(v, 'summary.quickStats.guestMemoryUsage')), 'snapshots': snaps(v), 'consolidate': b(v.get('runtime.consolidationNeeded')), 'tools': tools(v),
                    'ips': v['ips'] if isinstance(v.get('ips'), list) else []})
    return {'clusters': clusters, 'hosts': hosts, 'datastores': datastores, 'vms': vms, 'usage': True, 'vm_usage': True, 'health': H}


# ---- Nutanix --------------------------------------------------------------------------------------------------------
NTX_OK = [re.compile(r'^/PrismGateway/services/rest/v2\.0/(cluster|hosts|storage_containers)$'),
          re.compile(r'^/PrismGateway/services/rest/v2\.0/alerts\?resolved=false&count=500$'),
          re.compile(r'^/PrismGateway/services/rest/v2\.0/vms\?include_vm_disk_config=true&include_vm_nic_config=true$'),
          re.compile(r'^/api/nutanix/v3/(hosts|vms|clusters)/list$'),
          re.compile(r'^/PrismGateway/services/rest/v1/vms\?count=500&page=\d{1,2}$')]


_IP_OK = re.compile(r'^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$', re.I)
_IP_SKIP = re.compile(r'^(169\.254\.|127\.|0\.0\.0\.0$)|^(fe80:|::1?$)', re.I)
_MAC_OK = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


def nic_ips(have, *lists):
    """nicIps in engine/virt-capacity.js: unique, IPv4 first, link-local / loopback / unspecified dropped, at most 16"""
    out = list(have or [])
    for l in lists:
        for x in l if isinstance(l, list) else []:
            ip = x.strip() if isinstance(x, str) else ''
            if not ip or ip in out or not _IP_OK.search(ip) or _IP_SKIP.search(ip):
                continue
            out.append(ip)
    return ([x for x in out if '.' in x] + [x for x in out if '.' not in x])[:16]


def nic_macs(lst):
    out = []
    for x in lst or []:
        m = x.strip().lower() if isinstance(x, str) else ''
        if _MAC_OK.search(m) and m not in out:
            out.append(m)
    return out[:16]


_IP4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_IP6 = re.compile(r'^[0-9a-fA-F:]+$')


def ntx_ip(v):
    """a well-formed IPv4 / IPv6 address as text, else None (same rule as ntxIp in virt-capacity.js)"""
    s = '' if v is MISSING or v is None else js_str(v).strip()
    return s if _IP4.match(s) or (_IP6.match(s) and ':' in s and len(s) <= 39) else None


def ntx_addrs(host, cvm, ipmi):
    """Nutanix host addresses for the power plans (virt-power.js): hypervisor, its CVM, the IPMI controller"""
    o = {}
    for k, v in (('ip', host), ('cvm_ip', cvm), ('bmc_ip', ipmi)):
        x = ntx_ip(v)
        if x:
            o[k] = x
    return o


def ntx_base(u):
    b = re.sub(r'/+$', '', S(u) if u is not MISSING and truthy(u) else '')
    try:
        x = urllib.parse.urlsplit(b)
        port = x.port
    except ValueError:
        raise VErr('config', 'invalid Prism URL')
    if not x.scheme or not x.hostname:
        raise VErr('config', 'invalid Prism URL')
    default = {'https': 443, 'http': 80}.get(x.scheme.lower())
    if port is None or port == default:
        host = x.hostname if ':' not in x.hostname else '[%s]' % x.hostname
        b = '%s://%s:9440%s' % (x.scheme.lower(), host, re.sub(r'/+$', '', x.path or '/'))
    return b


def _ntx(target, secret, o):
    base = ntx_base(target.get('base_url', MISSING))
    user, pw = secret.get('username', MISSING), secret.get('password', MISSING)
    auth = 'Basic ' + base64.b64encode(('%s:%s' % (S(user), S(pw))).encode('utf-8')).decode('ascii')

    def call(method, path, body=None):
        if not any(rx.search(path) for rx in NTX_OK) or (method == 'POST' and not path.endswith('/list')) or method not in ('GET', 'POST'):
            raise VErr('config', 'Nutanix capacity is read-only; refusing %s %s' % (method, path))
        headers = {'Accept': 'application/json', 'Authorization': auth}
        if body:
            headers['Content-Type'] = 'application/json'
        r = _req(base + path, method, headers, json.dumps(body, separators=(',', ':'), ensure_ascii=False) if body else None, target, o, 60000)
        if r['status'] == 401:
            raise VErr('auth', 'Prism rejected the credentials')
        if r['status'] == 403:
            raise VErr('authz', 'Prism: not authorised for %s' % path)
        return r

    def ppm(v=MISSING):
        n = num(v)
        return None if n is None or n < 0 else n / 1e6

    def ok2(r):
        return 200 <= r['status'] < 300

    v1ips = {}   # the v1 list's ipAddresses (Prism learns them from NGT or IPAM)

    def vm_stats():
        m = {}
        try:
            for page in range(1, 41):
                r = call('GET', '/PrismGateway/services/rest/v1/vms?count=500&page=%d' % page)
                ents = g(r['json'], 'entities')
                if not ok2(r) or not truthy(r['json']) or not isinstance(ents, list):
                    break
                for x in ents:
                    if isinstance(x, dict) and tv(x.get('uuid', MISSING)):
                        m[S(x['uuid'])] = x.get('stats') if truthy(x.get('stats')) else {}
                        ia = x.get('ipAddresses', MISSING)
                        if isinstance(ia, list) and ia:
                            v1ips[S(x['uuid'])] = ia
                if len(ents) < 500:
                    break
        except Exception:
            pass   # keep what was read
        return m

    def first(*a):
        for v in a:
            if v is not None:
                return v
        return None

    def r1(v):
        return None if v is None else js_round(v * 10) / 10

    def with_use(vm, St):
        k = vm['uuid'] if truthy(vm.get('uuid')) else vm['id']
        if k in v1ips:
            vm['ips'] = nic_ips(vm.get('ips'), v1ips[k])
        s = St.get(k)
        if s is None:
            return vm
        s = s if isinstance(s, dict) else {}
        cpu = ppm(s.get('hypervisor_cpu_usage_ppm', MISSING))
        mem = first(ppm(s.get('guest.memory_usage_ppm', MISSING)), ppm(s.get('memory_usage_ppm', MISSING)), ppm(s.get('hypervisor_memory_usage_ppm', MISSING)))

        def n(k):
            x = num(s.get(k, MISSING))
            return None if x is None or x < 0 else x
        lat = n('controller_avg_io_latency_usecs')
        vm.update({'cpu_pct': None if cpu is None else r1(cpu * 100),
                   'mem_used_mb': js_round(vm['mem_mb'] * mem) if mem is not None and truthy(vm.get('mem_mb')) else None,
                   'iops': n('controller_num_iops'), 'io_latency_ms': None if lat is None else js_round(lat / 100) / 10, 'io_kbps': n('controller_io_bandwidth_kBps')})
        return vm

    def v2_nic_ips(n):
        if not isinstance(n, dict):
            return []
        ia = n.get('ip_addresses')
        return ([n['ip_address']] if n.get('ip_address') is not None else []) + (ia if isinstance(ia, list) else []) + \
            ([n['requested_ip_address']] if n.get('requested_ip_address') is not None else [])

    def andget(o, k):
        """o && o.k"""
        if o is MISSING or not truthy(o):
            return o
        return g(o, k)

    def disk_sum(lst, keep, size_key):
        tot = 0
        for d in lst if isinstance(lst, list) else []:
            d = d if isinstance(d, dict) else {}
            if keep(d):
                tot += orv(num(d.get(size_key, MISSING)), 0)
        return tot if truthy(tot) else None

    def alert_title(a):
        t = S(orv(a.get('alert_title', MISSING), a.get('message', MISSING), ''))
        types, vals = orv(a.get('context_types', MISSING), []), orv(a.get('context_values', MISSING), [])

        def rep(m):
            k = m.group(0)[1:-1]
            i = types.index(k) if isinstance(types, list) and k in types else -1
            if i < 0:
                return m.group(0)
            return S(vals[i]) if isinstance(vals, list) and i < len(vals) else 'undefined'
        return re.sub(r'\{[a-z_]+\}', rep, t, flags=re.I)[:300]

    def collect():
        v2 = '/PrismGateway/services/rest/v2.0/'
        hr = call('GET', v2 + 'hosts')
        hents = g(hr['json'], 'entities')
        if ok2(hr) and truthy(hr['json']) and isinstance(hents, list):
            cr = call('GET', v2 + 'cluster')
            vr = call('GET', v2 + 'vms?include_vm_disk_config=true&include_vm_nic_config=true')
            try:
                sr = call('GET', v2 + 'storage_containers')
            except Exception:
                sr = None
            c = cr['json'] if truthy(cr['json']) else {}
            c = c if isinstance(c, dict) else {}
            us = orv(c.get('usage_stats', MISSING), {})
            us = us if isinstance(us, dict) else {}
            stats = c.get('stats', MISSING)
            cl0 = {'id': S(orv(c.get('uuid', MISSING), 'cluster')), 'name': S(orv(c.get('name', MISSING), 'Nutanix cluster')),
                   'storage_capacity': num(us.get('storage.capacity_bytes', MISSING)), 'storage_used': num(us.get('storage.usage_bytes', MISSING)),
                   'cpu_ratio': ppm(andget(stats, 'hypervisor_cpu_usage_ppm')), 'mem_ratio': ppm(andget(stats, 'hypervisor_memory_usage_ppm'))}
            clusters = [cl0]
            hosts = []
            for h in hents:
                h = h if isinstance(h, dict) else {}
                st = orv(h.get('stats', MISSING), {})
                st = st if isinstance(st, dict) else {}
                cpu, mem = num(h.get('cpu_capacity_in_hz', MISSING)), num(h.get('memory_capacity_in_bytes', MISSING))
                cr2, mr = ppm(st.get('hypervisor_cpu_usage_ppm', MISSING)), ppm(st.get('hypervisor_memory_usage_ppm', MISSING))
                state = h.get('state', MISSING)
                hosts.append({'id': S(h.get('uuid', MISSING)), 'name': S(orv(h.get('name', MISSING), '')), 'cluster_id': cl0['id'], 'cluster': cl0['name'], 'vendor': 'Nutanix',
                              'model': S(orv(h.get('block_model_name', MISSING), '')), 'serial': S(orv(h.get('serial', MISSING), h.get('block_serial', MISSING), '')),
                              'cpu_model': S(orv(h.get('cpu_model', MISSING), '')), 'sockets': num(h.get('num_cpu_sockets', MISSING)), 'cores': num(h.get('num_cpu_cores', MISSING)),
                              'threads': num(h.get('num_cpu_threads', MISSING)), 'cpu_mhz': cpu / 1e6 if truthy(cpu) else None,
                              'cpu_used_mhz': js_round(cpu / 1e6 * cr2) if truthy(cpu) and cr2 is not None else None,
                              'mem_bytes': mem, 'mem_used_bytes': js_round(mem * mr) if truthy(mem) and mr is not None else None,
                              'version': S(orv(h.get('hypervisor_full_name', MISSING), 'Nutanix AHV')),
                              'state': 'connected' if S(orv(state, 'NORMAL')).lower() == 'normal' else S(orv(state, '')).lower(),
                              'maintenance': bool(re.search('maintenance', S(orv(h.get('host_maintenance_mode_reason', MISSING), state, '')), re.I)),
                              **ntx_addrs(h.get('hypervisor_address', MISSING), h.get('service_vmexternal_ip', MISSING), h.get('ipmi_address', MISSING))})
            vents = g(vr['json'], 'entities') if truthy(vr['json']) else MISSING
            vms = []
            for v in vents if isinstance(vents, list) else []:
                v = v if isinstance(v, dict) else {}
                nics = v.get('vm_nics') if isinstance(v.get('vm_nics'), list) else []
                vcpus = orv(num(v.get('num_vcpus', MISSING)), 0) * orv(num(v.get('num_cores_per_vcpu', MISSING)), 1)
                vms.append({'id': S(v.get('uuid', MISSING)), 'name': S(orv(v.get('name', MISSING), '')), 'uuid': S(v.get('uuid', MISSING)),
                            'host_id': S(v['host_uuid']) if tv(v.get('host_uuid', MISSING)) else None,
                            'power': 'on' if S(orv(v.get('power_state', MISSING), '')).lower() == 'on' else 'off',
                            'vcpus': vcpus if truthy(vcpus) else None, 'mem_mb': num(v.get('memory_mb', MISSING)),
                            'disk_bytes': disk_sum(orv(v.get('vm_disk_info', MISSING), []), lambda d: not truthy(d.get('is_cdrom')), 'size'),
                            'cpu_used_mhz': None, 'mem_used_mb': None, 'ips': nic_ips([], *[v2_nic_ips(n) for n in nics]), 'macs': nic_macs([n.get('mac_address') if isinstance(n, dict) else None for n in nics])})
            sents = g(sr['json'], 'entities') if sr is not None and truthy(sr['json']) else MISSING
            datastores = []
            for s in sents if isinstance(sents, list) else []:
                s = s if isinstance(s, dict) else {}
                u = orv(s.get('usage_stats', MISSING), {})
                u = u if isinstance(u, dict) else {}
                capb = orv(num(u.get('storage.capacity_bytes', MISSING)), num(s.get('max_capacity', MISSING)))
                used = num(u.get('storage.usage_bytes', MISSING))
                datastores.append({'id': S(orv(s.get('storage_container_uuid', MISSING), s.get('name', MISSING))), 'name': 'container ' + S(orv(s.get('name', MISSING), '')),
                                   'type': 'Nutanix', 'capacity': capb, 'free': capb - used if capb is not None and used is not None else None, 'uncommitted': None, 'accessible': True})
            alerts = None
            try:   # unresolved Prism alerts (best effort)
                ar = call('GET', v2 + 'alerts?resolved=false&count=500')
                if ok2(ar) and truthy(ar['json']):
                    alerts = []
                    aents = orv(g(ar['json'], 'entities'), [])
                    if not isinstance(aents, list):
                        raise TypeError('entities')   # .map() of a non-list throws in Node.js too: alerts stay "not reported"
                    for a in aents:
                        if not isinstance(a, dict):
                            raise TypeError('alert')
                        sev = S(a.get('severity', MISSING))
                        ae = orv(a.get('affected_entities', MISSING), [])
                        e0 = orv(ae[0] if isinstance(ae, list) and ae else MISSING, {})
                        us_ = a.get('created_time_stamp_in_usecs', MISSING)
                        item = {'id': S(orv(a.get('id', MISSING), a.get('alert_uid', MISSING), '')),
                                'severity': 'critical' if re.search('critical', sev, re.I) else 'warning' if re.search('warning', sev, re.I) else 'info',
                                'title': alert_title(a), 'entity': orv(g(e0, 'entity_name'), ''),
                                'created': _usecs_iso(us_) if tv(us_) else None,
                                'acknowledged': truthy(a.get('acknowledged'))}
                        if truthy(item['id']):
                            alerts.append(item)
            except Exception:
                alerts = None
            St = vm_stats()
            for v in vms:
                with_use(v, St)
            return {'clusters': clusters, 'hosts': hosts, 'datastores': datastores, 'vms': vms, 'usage': True, 'vm_usage': len(St) > 0, 'alerts': alerts}

        # Prism Central: v3 lists (capacity and allocation, no usage)
        def lst(kind):
            out = []
            for off in range(0, 20000, 500):
                r = call('POST', '/api/nutanix/v3/%ss/list' % kind, {'kind': kind, 'length': 500, 'offset': off})
                if not ok2(r):
                    raise VErr('protocol', 'Prism %s list: HTTP %s' % (kind, r['status']))
                e = orv(andget(r['json'] if truthy(r['json']) else r['json'], 'entities'), [])
                e = e if isinstance(e, list) else []
                out.extend(e)
                if len(e) < 500:
                    break
            return out
        Hs, Vs, Cs = lst('host'), lst('vm'), lst('cluster')

        def dget(o, *ks):
            """((o.a || {}).b || {}) ..."""
            for k in ks:
                o = orv(g(o, k), {})
            return o
        cl = []
        for c in Cs:
            svc = orv(g(dget(c, 'status', 'resources', 'config'), 'service_list'), [])
            if isinstance(svc, list) and 'PRISM_CENTRAL' in svc:
                continue
            cl.append({'id': orv(andget(g(c, 'metadata'), 'uuid'), ''), 'name': orv(andget(g(c, 'status'), 'name'), '')})
        cn = {c['id']: c['name'] for c in cl}
        hosts = []
        for h in Hs:
            hs = g(h, 'status')
            if not (tv(hs) and tv(g(hs, 'resources')) and tv(g(g(hs, 'resources'), 'hypervisor'))):
                continue
            r = hs['resources']
            cref = orv(g(hs, 'cluster_reference'), {})
            cid = orv(g(cref, 'uuid'), '')
            cap, mib = num(g(r, 'cpu_capacity_hz')), num(g(r, 'memory_capacity_mib'))
            hosts.append({'id': h['metadata']['uuid'], 'name': orv(g(hs, 'name'), ''), 'cluster_id': cid, 'cluster': orv(cn.get(cid, MISSING), g(cref, 'name'), 'Nutanix'),
                          'vendor': 'Nutanix', 'model': orv(andget(g(r, 'block'), 'block_model'), ''), 'serial': orv(g(r, 'serial_number'), ''),
                          'cpu_model': orv(g(r, 'cpu_model'), ''), 'sockets': num(g(r, 'num_cpu_sockets')), 'cores': num(g(r, 'num_cpu_cores')), 'threads': None,
                          'cpu_mhz': cap / 1e6 if truthy(cap) else None, 'cpu_used_mhz': None, 'mem_bytes': mib * 1048576 if truthy(mib) else None, 'mem_used_bytes': None,
                          'version': orv(andget(g(r, 'hypervisor'), 'hypervisor_full_name'), 'Nutanix AHV'), 'state': 'connected', 'maintenance': False,
                          **ntx_addrs(andget(g(r, 'hypervisor'), 'ip'), andget(g(r, 'controller_vm'), 'ip'), andget(g(r, 'ipmi'), 'ip'))})
        vms = []
        for v in Vs:
            vs = orv(g(v, 'status'), {})
            r = orv(g(vs, 'resources'), {})
            vcpus = orv(num(g(r, 'num_sockets')), 0) * orv(num(g(r, 'num_vcpus_per_socket')), 1)
            nl = r.get('nic_list') if isinstance(r, dict) and isinstance(r.get('nic_list'), list) and r.get('nic_list') else MISSING
            if nl is MISSING:   # status carries the learned addresses; spec only the requested ones
                sp = orv(g(orv(g(v, 'spec'), {}), 'resources'), {})
                nl = sp.get('nic_list') if isinstance(sp, dict) and isinstance(sp.get('nic_list'), list) else []
            vms.append({'id': v['metadata']['uuid'], 'name': orv(g(vs, 'name'), ''), 'uuid': v['metadata']['uuid'], 'host_id': orv(g(orv(g(r, 'host_reference'), {}), 'uuid'), None),
                        'power': 'on' if S(orv(g(r, 'power_state'), '')).upper() == 'ON' else 'off', 'vcpus': vcpus if truthy(vcpus) else None, 'mem_mb': num(g(r, 'memory_size_mib')),
                        'disk_bytes': disk_sum(orv(g(r, 'disk_list'), []), lambda d: g(orv(g(d, 'device_properties'), {}), 'device_type') != 'CDROM', 'disk_size_bytes'),
                        'cpu_used_mhz': None, 'mem_used_mb': None,
                        'ips': nic_ips([], *[[e.get('ip') if isinstance(e, dict) else None for e in (n.get('ip_endpoint_list') if isinstance(n, dict) and isinstance(n.get('ip_endpoint_list'), list) else [])] for n in nl]),
                        'macs': nic_macs([n.get('mac_address') if isinstance(n, dict) else None for n in nl])})
        St = vm_stats()
        for v in vms:
            with_use(v, St)
        return {'clusters': cl, 'hosts': hosts, 'datastores': [], 'vms': vms, 'usage': False, 'vm_usage': len(St) > 0}

    return collect


def _usecs_iso(v):
    """new Date(Number(v) / 1000).toISOString() - throws (RangeError) on a value that is not a number, as Node.js does"""
    n = _num(v)
    r = iso(n / 1000) if n is not None else None
    if r is None:
        raise ValueError('invalid time value')
    return r


def _clean(v):
    """MISSING never reaches the answer (JavaScript drops undefined from JSON)"""
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if x is not MISSING}
    if isinstance(v, list):
        return [None if x is MISSING else _clean(x) for x in v]
    return v


def _run(fn):
    try:
        return _clean(fn())
    except VErr as e:
        return {'ok': False, 'error_class': e.code, 'error': str(e)[:300]}
    except httpc.HttpcError as e:
        out = {'ok': False, 'error_class': e.code, 'error': str(e)[:300]}
        if e.presented:
            out['presented'] = e.presented
        return out


def vcenter(target, secret, opts):
    collect, _ = _vc(target or {}, secret or {}, opts or {})
    return _run(lambda: from_vcenter(collect()))


def vcenter_hosts(target, secret, opts):
    _, hosts = _vc(target or {}, secret or {}, opts or {})
    return _run(hosts)


def nutanix(target, secret, opts):
    return _run(lambda: _ntx(target or {}, secret or {}, opts or {})())
