// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Capacity of the VMware vCenter and Nutanix Prism platforms connected on the Virtualization page, for IT Asset
// Management and the capacity planning report. READ ONLY, with the platform logins already saved there (engine/virt.js).
//
//   vCenter  vSphere Web Services (SOAP, {base}/sdk) - a standalone ESXi host (kind esxi) speaks the same API: RetrieveServiceContent, Login, CreateContainerView,
//            RetrievePropertiesEx / ContinueRetrievePropertiesEx, DestroyView, Logout - nothing else can be sent (SOAP_OK).
//            Hosts (vendor, model, serial, ESXi version, CPU model / sockets / cores / MHz, memory, CPU and memory in
//            use, connection, maintenance), clusters, datastores (capacity, free, uncommitted) and VMs (vCPU, memory,
//            committed / uncommitted disk, CPU and guest memory in use, power state; templates left out).
//            Health, each in its own call so an older vCenter or a missing privilege never stops the capacity read (HEALTH):
//            host / cluster / datastore overall status, cluster HA and DRS, VM snapshots (count, oldest), disk consolidation
//            needed, VMware Tools running.
//   Nutanix  Prism Element v2 (GET cluster, hosts, vms, storage_containers, unresolved alerts): capacity and the usage Prism reports
//            (hypervisor CPU / memory ppm, storage). Prism Central has no v2 usage: it falls back to v3 lists (capacity
//            and allocation only; usage reads "not reported").
//
//   GET  /virt/capacity             the report: clusters, hosts, datastores, VMs, headroom, forecast     any role
//   POST /virt/capacity/run         collect now                                                          admin
//   POST /virt/capacity/live        fetch the live counters now (host / VM CPU and memory in use, state, power); also every
//                                   live_sec seconds (default 60, 0 = off) between full collections      operator
//   POST /virt/capacity/settings    {vcpu_ratio, cpu_max_pct, mem_max_pct, storage_max_pct, n_plus_1, interval_min} admin
//
// After each collection the ITAM records of the hosts and VMs get vendor / model / serial / OS / CPU / memory / disk -
// only where the field is empty or was filled by this add-on before, never over a value a person entered (locked).
// Each host's sockets / cores per socket / cluster also go into the core-based licence audit (core_lic_facts, source
// vcenter or nutanix) - never over counts a person entered there. vSphere's numCpuCores is the host TOTAL (all sockets).
// A daily sample per cluster is kept 2 years for the trend; the forecast says how much history it rests on.
// Added to an existing install with one registration line (install/add-virt-capacity.sh).
const httpc = require('./discovery/httpc');
const X = require('./discovery/xml');
const { createSealer } = require('./discovery/vault');

const SYS = { user: 'system:virt-capacity', role: 'admin', ip: '' };
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const err = (code, msg) => Object.assign(new Error(msg), { code });
const DAY = 86400000;
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
// Nutanix host addresses (same host record, no extra call): hypervisor, its CVM and the IPMI controller - for the power
// plans (virt-power.js). Only well-formed IPv4 / IPv6 text is kept.
const ntxIp = (v) => { const s = String(v == null ? '' : v).trim(); return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (/^[0-9a-fA-F:]+$/.test(s) && s.includes(':') && s.length <= 39) ? s : null; };
function ntxAddrs(host, cvm, ipmi) { const o = {}, h = ntxIp(host), c = ntxIp(cvm), b = ntxIp(ipmi); if (h) o.ip = h; if (c) o.cvm_ip = c; if (b) o.bmc_ip = b; return o; }
const GB = 1024 * 1024 * 1024;
const DEFAULTS = { vcpu_ratio: 4, cpu_max_pct: 80, mem_max_pct: 90, storage_max_pct: 80, n_plus_1: true, interval_min: 60, live_sec: 60, dr_rpo_min: 60 };

// ---- vCenter (SOAP) --------------------------------------------------------------------------------------------------
const SOAP_OK = new Set(['RetrieveServiceContent', 'Login', 'Logout', 'CreateContainerView', 'DestroyView', 'RetrievePropertiesEx', 'ContinueRetrievePropertiesEx']);
const PROPS = {
  HostSystem: ['name', 'parent', 'runtime.connectionState', 'runtime.inMaintenanceMode', 'summary.hardware.vendor', 'summary.hardware.model', 'summary.hardware.cpuModel', 'summary.hardware.cpuMhz',
    'summary.hardware.numCpuPkgs', 'summary.hardware.numCpuCores', 'summary.hardware.numCpuThreads', 'summary.hardware.memorySize', 'summary.quickStats.overallCpuUsage', 'summary.quickStats.overallMemoryUsage', 'summary.config.product.fullName'],
  ClusterComputeResource: ['name', 'summary.numHosts', 'summary.totalCpu', 'summary.totalMemory', 'summary.effectiveCpu', 'summary.effectiveMemory'],
  Datastore: ['summary.name', 'summary.type', 'summary.capacity', 'summary.freeSpace', 'summary.uncommitted', 'summary.accessible'],
  VirtualMachine: ['name', 'config.instanceUuid', 'config.template', 'config.guestFullName', 'config.hardware.numCPU', 'config.hardware.memoryMB', 'runtime.powerState', 'runtime.host',
    'summary.storage.committed', 'summary.storage.uncommitted', 'summary.quickStats.overallCpuUsage', 'summary.quickStats.guestMemoryUsage'],
};
// health properties, read type by type after the capacity ones (a fault here leaves that health field "not reported")
const HEALTH = {
  HostSystem: ['overallStatus'],
  ClusterComputeResource: ['overallStatus', 'configuration.dasConfig.enabled', 'configuration.drsConfig.enabled'],
  Datastore: ['overallStatus'],
  VirtualMachine: ['runtime.consolidationNeeded', 'guest.toolsRunningStatus', 'snapshot.rootSnapshotList'],
};
function vcSoap(target, secret, o = {}) {
  const req = o.request || httpc.request, url = String(target.base_url).replace(/\/+$/, '') + '/sdk';
  let cookie = '';
  async function call(method, inner) {
    if (!SOAP_OK.has(method)) throw err('config', `vCenter capacity is read-only; refusing ${method}`);
    const body = '<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
      + `<soapenv:Body><${method} xmlns="urn:vim25">${inner}</${method}></soapenv:Body></soapenv:Envelope>`;
    const headers = { 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: 'urn:vim25/6.7' };
    if (cookie) headers.Cookie = cookie;
    const r = await req(url, { method: 'POST', headers, body, caFile: target.ca_file || undefined, pin: target.tls_fingerprint || undefined, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 60000 });
    const sc = r.headers && (r.headers['set-cookie'] || r.headers['Set-Cookie']);
    const c = (Array.isArray(sc) ? sc : sc ? [sc] : []).map((x) => String(x).split(';')[0]).find((x) => /^vmware_soap_session=/.test(x));
    if (c) cookie = c;
    let doc; try { doc = X.parse(r.text || ''); } catch (e) { throw err('protocol', 'vCenter answered with something that is not SOAP'); }
    const fault = X.find(doc, 'Fault');
    if (fault) {
      const fs = X.textOf(fault, 'faultstring'), detail = X.find(fault, 'detail'), kind = detail && detail.children[0] ? detail.children[0].name : '';
      throw err(/InvalidLogin/i.test(kind + fs) ? 'auth' : /NoPermission|NotAuthenticated/i.test(kind + fs) ? 'authz' : 'protocol', `vCenter: ${fs || kind || 'SOAP fault'}`);
    }
    if (r.status < 200 || r.status >= 300) throw err(r.status === 404 ? 'config' : 'protocol', `vCenter ${method}: HTTP ${r.status}`);
    return doc;
  }
  const ref = (type, v) => `<_this type="${type}">${X.esc(v)}</_this>`;
  function objects(doc) {
    const out = [];
    for (const ob of X.findAll(doc, 'objects')) {
      const obj = X.child(ob, 'obj'), p = { _id: obj ? obj.text.trim() : '', _type: obj ? obj.attrs.type : '' };
      for (const ps of ob.children.filter((x) => x.name === 'propSet')) { const v = X.child(ps, 'val'); p[X.childText(ps, 'name')] = v ? (v.children.length && !v.text.trim() ? v : v.text.trim()) : ''; }
      out.push(p);
    }
    return out;
  }
  // one logged-in session around fn(retrieve); logged out whatever happens
  async function session(fn) {
    const sc = X.find(await call('RetrieveServiceContent', ref('ServiceInstance', 'ServiceInstance')), 'returnval');
    const root = X.childText(sc, 'rootFolder'), pc = X.childText(sc, 'propertyCollector'), vm = X.childText(sc, 'viewManager'), sm = X.childText(sc, 'sessionManager');
    if (!root || !pc || !vm || !sm) throw err('protocol', 'vCenter: unexpected service content');
    await call('Login', ref('SessionManager', sm) + `<userName>${X.esc(secret.username)}</userName><password>${X.esc(secret.password)}</password>`);
    try { return await fn(retrieve); } finally { try { await call('Logout', ref('SessionManager', sm)); } catch (e) { /* session times out on its own */ } }
    async function retrieve(type, paths) {
      const view = X.textOf(X.find(await call('CreateContainerView', ref('ViewManager', vm) + `<container type="Folder">${X.esc(root)}</container><type>${type}</type><recursive>true</recursive>`), 'returnval'));
      try {
        const spec = `<specSet><propSet><type>${type}</type>${paths.map((p) => `<pathSet>${p}</pathSet>`).join('')}</propSet><objectSet><obj type="ContainerView">${X.esc(view)}</obj><skip>true</skip>`
          + '<selectSet xsi:type="TraversalSpec"><name>traverseView</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet></objectSet></specSet>';
        let doc = await call('RetrievePropertiesEx', ref('PropertyCollector', pc) + spec + '<options><maxObjects>1000</maxObjects></options>');
        const all = objects(doc);
        for (let i = 0; i < 100; i++) {
          const tok = X.textOf(X.find(doc, 'returnval') || { name: '', children: [], text: '' }, 'token');
          if (!tok) break;
          doc = await call('ContinueRetrievePropertiesEx', ref('PropertyCollector', pc) + `<token>${X.esc(tok)}</token>`);
          all.push(...objects(doc));
        }
        return all;
      } finally { try { await call('DestroyView', `<_this type="ContainerView">${X.esc(view)}</_this>`); } catch (e) { /* the view ends with the session */ } }
    }
  }
  // each host's management address: its VMkernel interface on the management port group (else vmk0, else the first
  // with an IPv4 address) - what vCenter itself uses, so no DNS is needed. [{id, name, ip, vmk, portgroup}]
  async function hostAddresses() {
    return session(async (retrieve) => (await retrieve('HostSystem', ['name', 'config.network.vnic'])).map((h) => Object.assign({ id: h._id, name: str(h.name) }, mgmtNic(h['config.network.vnic']))));
  }
  async function collect() {
    return session(async (retrieve) => {
      const out = {};
      for (const type of Object.keys(PROPS)) out[type] = await retrieve(type, PROPS[type]);
      // serial number (vSphere 6.7+) in its own call: an older vCenter rejects the property and that must not stop the rest
      try { const s = await retrieve('HostSystem', ['hardware.systemInfo.serialNumber']); const m = new Map(s.map((x) => [x._id, x['hardware.systemInfo.serialNumber']])); for (const h of out.HostSystem) h.serial = m.get(h._id) || ''; } catch (e) { /* serial stays empty */ }
      // management address in its own call too: a role without Host.Config read sees no vnic, and that must not stop the rest
      try { const s = await retrieve('HostSystem', ['config.network.vnic']); const m = new Map(s.map((x) => [x._id, mgmtNic(x['config.network.vnic'])])); const all = new Map(s.map((x) => [x._id, vmkNics(x['config.network.vnic'])])); for (const h of out.HostSystem) { const n = m.get(h._id); if (n && n.ip) { h.mgmt_ip = n.ip; h.mgmt_vmk = n.vmk; } h.vmks = all.get(h._id) || []; } } catch (e) { /* address stays empty - DNS is the fallback */ }
      // VM guest addresses (VMware Tools reports them) in their own call: an older vCenter or a narrow role must not stop the rest
      try { const s = await retrieve('VirtualMachine', ['guest.ipAddress', 'guest.net']); const m = new Map(s.map((x) => [x._id, guestIps(x['guest.ipAddress'], x['guest.net'])])); for (const v of out.VirtualMachine) { const l = m.get(v._id); if (l && l.length) v.ips = l; } } catch (e) { /* VM addresses stay "not reported" */ }
      out._health = {};
      for (const type of Object.keys(HEALTH)) {
        try { const rows = await retrieve(type, HEALTH[type]); const m = new Map(rows.map((x) => [x._id, x])); for (const o of out[type] || []) { const h = m.get(o._id); if (h) for (const k of HEALTH[type]) if (k in h) o[k] = h[k]; } out._health[type] = true; } catch (e) { out._health[type] = false; }
      }
      return out;
    });
  }
  // live counters only (Fetch now / every minute): host and VM CPU and memory in use, connection and power - two calls
  async function live() {
    return session(async (retrieve) => {
      const H = await retrieve('HostSystem', ['summary.quickStats.overallCpuUsage', 'summary.quickStats.overallMemoryUsage', 'runtime.connectionState']);
      const V = await retrieve('VirtualMachine', ['summary.quickStats.overallCpuUsage', 'summary.quickStats.guestMemoryUsage', 'runtime.powerState', 'runtime.host']);
      return { hosts: H.map((h) => ({ id: h._id, cpu_used_mhz: num(h['summary.quickStats.overallCpuUsage']), mem_used_bytes: num(h['summary.quickStats.overallMemoryUsage']) != null ? num(h['summary.quickStats.overallMemoryUsage']) * 1048576 : null, state: str(h['runtime.connectionState']) || undefined })),
        vms: V.map((v) => ({ id: v._id, cpu_used_mhz: num(v['summary.quickStats.overallCpuUsage']), mem_used_mb: num(v['summary.quickStats.guestMemoryUsage']), host_id: str(v['runtime.host']) || undefined,
          power: /poweredOn/i.test(str(v['runtime.powerState'])) ? 'on' : /suspended/i.test(str(v['runtime.powerState'])) ? 'suspended' : 'off' })) };
    });
  }
  // baseline hardening (Baseline Hardening page, pyengine/hardening_rules.py): each host's security settings, READ-ONLY - the
  // same RetrievePropertiesEx as the rest. Each part in its own call: a role that cannot read one part leaves that part null
  // ("not checked"), never a pass. [{id, name, version, build, services, options, ntp, firewall, vswitches, portgroups, lockdown, read}]
  async function hostHardening() {
    return session(async (retrieve) => {
      const hosts = (await retrieve('HostSystem', ['name', 'config.product.version', 'config.product.build'])).map((h) => ({ id: h._id, name: str(h.name), version: str(h['config.product.version']), build: str(h['config.product.build']), read: {} }));
      const by = new Map(hosts.map((h) => [h.id, h]));
      const part = async (key, paths, fn) => {
        try { for (const r of await retrieve('HostSystem', paths)) { const h = by.get(r._id); if (h) { h[key] = fn(r); h.read[key] = true; } } }
        catch (e) { for (const h of hosts) { h[key] = null; h.read[key] = false; } }
      };
      await part('services', ['config.service.service'], (r) => esxServices(r['config.service.service']));
      await part('options', ['config.option'], (r) => esxOptions(r['config.option']));
      await part('ntp', ['config.dateTimeInfo.ntpConfig.server'], (r) => { const v = r['config.dateTimeInfo.ntpConfig.server']; return v && typeof v === 'object' ? v.children.map((c) => c.text.trim()).filter(Boolean) : (v ? [String(v)] : []); });
      await part('firewall', ['config.firewall'], (r) => esxFirewall(r['config.firewall']));
      await part('vswitches', ['config.network.vswitch'], (r) => esxSec(r['config.network.vswitch'], 'HostVirtualSwitch', (n) => X.childText(n, 'name')));
      await part('portgroups', ['config.network.portgroup'], (r) => esxSec(r['config.network.portgroup'], 'HostPortGroup', (n) => X.textOf(X.child(n, 'spec'), 'name')));
      await part('lockdown', ['config.lockdownMode'], (r) => str(r['config.lockdownMode']) || null);
      return hosts;
    });
  }
  // virtual networking (Virtual Network Map, virt-network.js): switches, port groups / VLANs, uplinks, VMkernel interfaces and
  // their services, distributed switches and port groups, each VM's networks and guest NICs. READ-ONLY, the same
  // RetrievePropertiesEx as the rest; each part in its own call - a part the role cannot read is listed in read_errors
  async function network() {
    return session(async (retrieve) => {
      const errors = [];
      const get = async (type, paths, label) => { try { return await retrieve(type, paths); } catch (e) { errors.push(label + ': ' + String(e.message || e).slice(0, 160)); return null; } };
      return require('./virt-net-read').fromVsphere({
        clusters: await get('ClusterComputeResource', ['name'], 'clusters'),
        hosts: await get('HostSystem', ['name', 'parent', 'runtime.connectionState', 'runtime.inMaintenanceMode'], 'hosts'),
        net: await get('HostSystem', ['config.network.vswitch', 'config.network.portgroup', 'config.network.pnic', 'config.network.vnic', 'config.network.proxySwitch'], 'host networking'),
        nicmgr: await get('HostSystem', ['config.virtualNicManagerInfo.netConfig'], 'VMkernel services'),
        dvs: await get('DistributedVirtualSwitch', ['name', 'config.maxMtu', 'config.uuid'], 'distributed switches'),
        dvpg: await get('DistributedVirtualPortgroup', ['name', 'config.distributedVirtualSwitch', 'config.defaultPortConfig', 'config.uplink'], 'distributed port groups'),
        nets: await get('Network', ['name'], 'networks'),
        vms: await get('VirtualMachine', ['name', 'runtime.host', 'runtime.powerState', 'network', 'guest.net', 'config.template'], 'VMs'),
      }, errors);
    });
  }
  return { collect, hostAddresses, live, hostHardening, network };
}
const str = (v) => (typeof v === 'string' ? v : '');
const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
// a VMware VM's addresses: guest.ipAddress (primary) then every NIC's ipAddress in guest.net - same filtering as Prism's (nicIps)
function guestIps(primary, net) {
  const l = [];
  if (typeof primary === 'string') l.push(primary);
  if (net && typeof net === 'object') for (const n of X.findAll(net, 'ipAddress')) if (n && typeof n.text === 'string') l.push(n.text.trim());
  return nicIps([], l);
}
// HostSystem config.network.vnic (ArrayOfHostVirtualNic) → the management VMkernel interface {ip, vmk, portgroup}
// ---- ESXi hardening facts (parsed from the SOAP values; only the settings the baseline checks are kept)
const ESX_OPTIONS = ['UserVars.ESXiShellTimeOut', 'UserVars.ESXiShellInteractiveTimeOut', 'UserVars.DcuiTimeOut', 'UserVars.SuppressShellWarning', 'Security.AccountLockFailures',
  'Security.AccountUnlockTime', 'Security.PasswordQualityControl', 'Security.PasswordHistory', 'Security.PasswordMaxDays', 'Config.HostAgent.plugins.solo.enableMob', 'Syslog.global.logHost',
  'Net.BlockGuestBPDU', 'Mem.ShareForceSalting', 'UserVars.ESXiVPsDisabledProtocols', 'Config.HostAgent.log.level', 'DCUI.Access'];
const xbool = (v) => (v === 'true' ? true : v === 'false' ? false : null);
function esxServices(val) {
  const out = {}; if (!val || typeof val !== 'object') return out;
  for (const n of X.findAll(val, 'HostService')) { const k = X.childText(n, 'key'); if (k) out[k] = { running: xbool(X.childText(n, 'running')), policy: X.childText(n, 'policy') || null }; }
  return out;
}
function esxOptions(val) {
  const out = {}; if (!val || typeof val !== 'object') return out;
  for (const n of X.findAll(val, 'OptionValue')) { const k = X.childText(n, 'key'); if (ESX_OPTIONS.includes(k)) out[k] = X.childText(n, 'value').slice(0, 300); }
  return out;
}
function esxFirewall(val) {
  if (!val || typeof val !== 'object') return null;
  const dp = X.child(val, 'defaultPolicy');
  return { incoming_blocked: dp ? xbool(X.childText(dp, 'incomingBlocked')) : null, outgoing_blocked: dp ? xbool(X.childText(dp, 'outgoingBlocked')) : null,
    rulesets: X.findAll(val, 'ruleset').map((r) => { const ah = X.child(r, 'allowedHosts'); return { key: X.childText(r, 'key'), enabled: xbool(X.childText(r, 'enabled')), all_ip: ah ? xbool(X.childText(ah, 'allIp')) : null }; }).filter((r) => r.key) };
}
function esxSec(val, tag, nameOf) {
  if (!val || typeof val !== 'object') return [];
  return X.findAll(val, tag).map((n) => { const sp = X.child(n, 'spec'), pol = sp && X.child(sp, 'policy'), sec = pol && X.child(pol, 'security');
    return { name: nameOf(n), promiscuous: sec ? xbool(X.childText(sec, 'allowPromiscuous')) : null, mac_changes: sec ? xbool(X.childText(sec, 'macChanges')) : null, forged: sec ? xbool(X.childText(sec, 'forgedTransmits')) : null }; });
}
// every VMkernel interface with an IPv4 address (management, vMotion, vSAN, storage, replication ...) - a host has several
function vmkNics(val) {
  if (!val || typeof val !== 'object') return [];
  return X.findAll(val, 'HostVirtualNic').map((n) => { const sp = X.child(n, 'spec'), ip = sp && X.child(sp, 'ip'); return { vmk: X.childText(n, 'device') || null, portgroup: X.childText(n, 'portgroup') || null, ip: ip ? X.childText(ip, 'ipAddress') : '' }; })
    .filter((n) => IP4.test(n.ip)).slice(0, 16);
}
function mgmtNic(val) {
  if (!val || typeof val !== 'object') return { ip: null, vmk: null, portgroup: null };
  const nics = X.findAll(val, 'HostVirtualNic').map((n) => { const sp = X.child(n, 'spec'), ip = sp && X.child(sp, 'ip'); return { vmk: X.childText(n, 'device'), portgroup: X.childText(n, 'portgroup'), ip: ip ? X.childText(ip, 'ipAddress') : '' }; })
    .filter((n) => IP4.test(n.ip));
  const n = nics.find((x) => /management/i.test(x.portgroup)) || nics.find((x) => x.vmk === 'vmk0') || nics[0];
  return n ? { ip: n.ip, vmk: n.vmk || null, portgroup: n.portgroup || null } : { ip: null, vmk: null, portgroup: null };
}
const cpuVendor = (m) => (/amd|epyc/i.test(String(m || '')) ? 'amd' : /intel|xeon/i.test(String(m || '')) ? 'intel' : '');
function fromVcenter(raw) {
  const H = raw._health || {}, bool = (v) => (v === 'true' ? true : v === 'false' ? false : null), status = (v) => (/^(green|yellow|red|gray)$/.test(str(v)) ? str(v) : null);
  const clusters = (raw.ClusterComputeResource || []).map((c) => ({ id: c._id, name: str(c.name), cpu_mhz: num(c['summary.totalCpu']), mem_bytes: num(c['summary.totalMemory']), eff_cpu_mhz: num(c['summary.effectiveCpu']), eff_mem_bytes: num(c['summary.effectiveMemory']) != null ? num(c['summary.effectiveMemory']) * 1048576 : null,
    status: status(c.overallStatus), ha: bool(c['configuration.dasConfig.enabled']), drs: bool(c['configuration.drsConfig.enabled']) }));
  const cname = new Map(clusters.map((c) => [c.id, c.name]));
  const hosts = (raw.HostSystem || []).map((h) => {
    const parent = str(h.parent), mhz = num(h['summary.hardware.cpuMhz']), cores = num(h['summary.hardware.numCpuCores']);
    return { id: h._id, name: str(h.name), cluster_id: cname.has(parent) ? parent : null, cluster: cname.get(parent) || 'Standalone hosts', vendor: str(h['summary.hardware.vendor']), model: str(h['summary.hardware.model']), serial: str(h.serial),
      cpu_model: str(h['summary.hardware.cpuModel']).replace(/\s+/g, ' '), sockets: num(h['summary.hardware.numCpuPkgs']), cores, threads: num(h['summary.hardware.numCpuThreads']), cpu_mhz: mhz && cores ? mhz * cores : null,
      cpu_used_mhz: num(h['summary.quickStats.overallCpuUsage']), mem_bytes: num(h['summary.hardware.memorySize']), mem_used_bytes: num(h['summary.quickStats.overallMemoryUsage']) != null ? num(h['summary.quickStats.overallMemoryUsage']) * 1048576 : null,
      ip: str(h.mgmt_ip) || null, vmk: str(h.mgmt_vmk) || null, vmks: Array.isArray(h.vmks) ? h.vmks.map((v) => ({ vmk: str(v.vmk) || null, portgroup: str(v.portgroup) || null, ip: str(v.ip) })) : [],
      version: str(h['summary.config.product.fullName']), state: str(h['runtime.connectionState']) || 'unknown', maintenance: h['runtime.inMaintenanceMode'] === 'true', status: status(h.overallStatus) };
  });
  const datastores = (raw.Datastore || []).map((d) => ({ id: d._id, name: str(d['summary.name']), type: str(d['summary.type']), capacity: num(d['summary.capacity']), free: num(d['summary.freeSpace']), uncommitted: num(d['summary.uncommitted']), accessible: d['summary.accessible'] !== 'false', status: status(d.overallStatus) }));
  // snapshot tree (nested VirtualMachineSnapshotTree): count every snapshot and keep the oldest creation time
  const snaps = (v) => { const n = v['snapshot.rootSnapshotList']; if (!n || typeof n !== 'object') return H.VirtualMachine ? { count: 0, oldest: null } : null; const t = X.findAll(n, 'createTime').map((x) => Date.parse(x.text.trim())).filter(Number.isFinite); return { count: t.length, oldest: t.length ? new Date(Math.min(...t)).toISOString() : null }; };
  const vms = (raw.VirtualMachine || []).filter((v) => v['config.template'] !== 'true').map((v) => ({ id: v._id, name: str(v.name), uuid: str(v['config.instanceUuid']), host_id: str(v['runtime.host']) || null,
    power: /poweredOn/i.test(str(v['runtime.powerState'])) ? 'on' : /suspended/i.test(str(v['runtime.powerState'])) ? 'suspended' : 'off', guest_os: str(v['config.guestFullName']),
    vcpus: num(v['config.hardware.numCPU']), mem_mb: num(v['config.hardware.memoryMB']), disk_bytes: num(v['summary.storage.committed']), disk_uncommitted: num(v['summary.storage.uncommitted']),
    cpu_used_mhz: num(v['summary.quickStats.overallCpuUsage']), mem_used_mb: num(v['summary.quickStats.guestMemoryUsage']),
    ips: Array.isArray(v.ips) ? v.ips : [],
    snapshots: snaps(v), consolidate: bool(v['runtime.consolidationNeeded']), tools: str(v['guest.toolsRunningStatus']) ? (/Running$/.test(str(v['guest.toolsRunningStatus'])) && !/NotRunning/.test(str(v['guest.toolsRunningStatus'])) ? 'running' : 'not-running') : null }));
  return { clusters, hosts, datastores, vms, usage: true, vm_usage: true, health: H };
}

// ---- Nutanix ---------------------------------------------------------------------------------------------------------
const NTX_OK = [/^\/PrismGateway\/services\/rest\/v2\.0\/(cluster|hosts|storage_containers|networks)$/,
  // virtual network map (read-only): each host's NICs, and the v4 virtual switches (bonds) where the AOS has them
  /^\/PrismGateway\/services\/rest\/v2\.0\/hosts\/[0-9a-f-]{36}\/host_nics$/, /^\/api\/networking\/v4\.0\/config\/virtual-switches$/,
  // baseline hardening (read-only): directory authentication and remote syslog configuration - Prism Element v1
  /^\/PrismGateway\/services\/rest\/v1\/(authconfig|remote_syslog_servers)$/, /^\/PrismGateway\/services\/rest\/v2\.0\/alerts\?resolved=false&count=500$/, /^\/PrismGateway\/services\/rest\/v2\.0\/vms\?include_vm_disk_config=true&include_vm_nic_config=true$/, /^\/api\/nutanix\/v3\/(hosts|vms|clusters)\/list$/,
  // per-VM usage (CPU, memory, IOPS, latency, bandwidth): v2.0 has no VM stats, the v1 VM list does - GET, paged
  /^\/PrismGateway\/services\/rest\/v1\/vms\?count=500&page=\d{1,2}$/,
  // DR / replication (read-only): protection domains, remote sites, replications in progress, a protection domain's recent DR
  // snapshots (name URL-encoded, count bounded) - Prism Element v2; Leap protection rules and recovery plans - Prism Central v3 lists
  /^\/PrismGateway\/services\/rest\/v2\.0\/(protection_domains|remote_sites|protection_domains\/replications)$/,
  /^\/PrismGateway\/services\/rest\/v2\.0\/protection_domains\/[A-Za-z0-9%._-]{1,240}\/dr_snapshots\?count=\d{1,3}$/,
  /^\/api\/nutanix\/v3\/(protection_rules|recovery_plans)\/list$/];
function ntxBase(u) { let b = String(u || '').replace(/\/+$/, ''); try { const x = new URL(b); if (!x.port) b = `${x.protocol}//${x.hostname}:9440${x.pathname.replace(/\/+$/, '')}`; } catch (e) { throw err('config', 'invalid Prism URL'); } return b; }
// a VM's addresses as Prism reports them: unique, IPv4 before IPv6, link-local / loopback / unspecified dropped (not reachable
// and not the VM's address in any useful sense), at most 16
function nicIps(have, ...lists) {
  const out = (have || []).slice();
  for (const l of lists) for (const x of Array.isArray(l) ? l : []) {
    const ip = typeof x === 'string' ? x.trim() : '';
    if (!ip || out.includes(ip) || !/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$/i.test(ip) || /^(169\.254\.|127\.|0\.0\.0\.0$)|^(fe80:|::1?$)/i.test(ip)) continue;
    out.push(ip);
  }
  return out.filter((x) => x.includes('.')).concat(out.filter((x) => !x.includes('.'))).slice(0, 16);
}
function nicMacs(list) { const out = []; for (const x of list || []) { const m = typeof x === 'string' ? x.trim().toLowerCase() : ''; if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m) && !out.includes(m)) out.push(m); } return out.slice(0, 16); }
function ntxClient(target, secret, o = {}) {
  const req = o.request || httpc.request, base = ntxBase(target.base_url), auth = 'Basic ' + Buffer.from(`${secret.username}:${secret.password}`).toString('base64');
  async function call(method, path, body) {
    if (!NTX_OK.some((re) => re.test(path)) || (method === 'POST' && !/\/list$/.test(path)) || (method !== 'GET' && method !== 'POST')) throw err('config', `Nutanix capacity is read-only; refusing ${method} ${path}`);
    const r = await req(base + path, { method, headers: Object.assign({ Accept: 'application/json', Authorization: auth }, body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : null, caFile: target.ca_file || undefined, pin: target.tls_fingerprint || undefined, timeoutMs: o.timeoutMs || 60000 });
    if (r.status === 401) throw err('auth', 'Prism rejected the credentials');
    if (r.status === 403) throw err('authz', `Prism: not authorised for ${path}`);
    return r;
  }
  const ppm = (v) => (num(v) == null || num(v) < 0 ? null : num(v) / 1e6);
  // per-VM usage from the v1 VM list, joined by uuid. Best effort: a Prism without it (or a user not allowed to read it)
  // keeps capacity and allocation, and the VMs' usage stays null - shown as "not reported", never as 0
  async function vmStats() {
    const m = new Map(); m.ips = new Map();   // ips: the v1 list's ipAddresses (Prism learns them from NGT or IPAM)
    try {
      for (let page = 1; page <= 40; page++) {
        const r = await call('GET', `/PrismGateway/services/rest/v1/vms?count=500&page=${page}`);
        if (r.status < 200 || r.status >= 300 || !r.json || !Array.isArray(r.json.entities)) break;
        for (const x of r.json.entities) if (x && x.uuid) { m.set(String(x.uuid), x.stats || {}); if (Array.isArray(x.ipAddresses) && x.ipAddresses.length) m.ips.set(String(x.uuid), x.ipAddresses); }
        if (r.json.entities.length < 500) break;
      }
    } catch (e) { /* keep what was read */ }
    return m;
  }
  const first = (...a) => { for (const v of a) if (v != null) return v; return null; };
  const r1 = (v) => (v == null ? null : Math.round(v * 10) / 10);
  function withUse(vm, S) {
    if (S.ips && S.ips.has(vm.uuid || vm.id)) vm.ips = nicIps(vm.ips, S.ips.get(vm.uuid || vm.id));
    const s = S.get(vm.uuid || vm.id); if (!s) return vm;
    const cpu = ppm(s.hypervisor_cpu_usage_ppm), mem = first(ppm(s['guest.memory_usage_ppm']), ppm(s.memory_usage_ppm), ppm(s.hypervisor_memory_usage_ppm));
    const n = (k) => (num(s[k]) == null || num(s[k]) < 0 ? null : num(s[k]));
    const lat = n('controller_avg_io_latency_usecs');
    return Object.assign(vm, { cpu_pct: cpu == null ? null : r1(cpu * 100), mem_used_mb: mem != null && vm.mem_mb ? Math.round(vm.mem_mb * mem) : null,
      iops: n('controller_num_iops'), io_latency_ms: lat == null ? null : Math.round(lat / 100) / 10, io_kbps: n('controller_io_bandwidth_kBps') });
  }
  async function collect() {
    const v2 = '/PrismGateway/services/rest/v2.0/';
    const hr = await call('GET', v2 + 'hosts');
    if (hr.status >= 200 && hr.status < 300 && hr.json && Array.isArray(hr.json.entities)) {
      const cr = await call('GET', v2 + 'cluster'), vr = await call('GET', v2 + 'vms?include_vm_disk_config=true&include_vm_nic_config=true');
      let sr = null; try { sr = await call('GET', v2 + 'storage_containers'); } catch (e) { sr = null; }
      const c = cr.json || {}, us = c.usage_stats || {};
      const clusters = [{ id: String(c.uuid || 'cluster'), name: String(c.name || 'Nutanix cluster'), storage_capacity: num(us['storage.capacity_bytes']), storage_used: num(us['storage.usage_bytes']), cpu_ratio: ppm(c.stats && c.stats.hypervisor_cpu_usage_ppm), mem_ratio: ppm(c.stats && c.stats.hypervisor_memory_usage_ppm) }];
      const hosts = hr.json.entities.map((h) => {
        const st = h.stats || {}, cpu = num(h.cpu_capacity_in_hz), mem = num(h.memory_capacity_in_bytes), cr2 = ppm(st.hypervisor_cpu_usage_ppm), mr = ppm(st.hypervisor_memory_usage_ppm);
        return { id: String(h.uuid), name: String(h.name || ''), cluster_id: clusters[0].id, cluster: clusters[0].name, vendor: 'Nutanix', model: String(h.block_model_name || ''), serial: String(h.serial || h.block_serial || ''),
          cpu_model: String(h.cpu_model || ''), sockets: num(h.num_cpu_sockets), cores: num(h.num_cpu_cores), threads: num(h.num_cpu_threads), cpu_mhz: cpu ? cpu / 1e6 : null, cpu_used_mhz: cpu && cr2 != null ? Math.round(cpu / 1e6 * cr2) : null,
          mem_bytes: mem, mem_used_bytes: mem && mr != null ? Math.round(mem * mr) : null, version: String(h.hypervisor_full_name || 'Nutanix AHV'), state: String(h.state || 'NORMAL').toLowerCase() === 'normal' ? 'connected' : String(h.state || '').toLowerCase(), maintenance: /maintenance/i.test(String(h.host_maintenance_mode_reason || h.state || '')),
          ...ntxAddrs(h.hypervisor_address, h.service_vmexternal_ip, h.ipmi_address) };
      });
      const vms = ((vr.json && vr.json.entities) || []).map((v) => ({ id: String(v.uuid), name: String(v.name || ''), uuid: String(v.uuid), host_id: v.host_uuid ? String(v.host_uuid) : null, power: String(v.power_state || '').toLowerCase() === 'on' ? 'on' : 'off',
        vcpus: (num(v.num_vcpus) || 0) * (num(v.num_cores_per_vcpu) || 1) || null, mem_mb: num(v.memory_mb), disk_bytes: (v.vm_disk_info || []).filter((d) => !d.is_cdrom).reduce((a, d) => a + (num(d.size) || 0), 0) || null, cpu_used_mhz: null, mem_used_mb: null,
        ips: nicIps([], ...(Array.isArray(v.vm_nics) ? v.vm_nics : []).map((n) => [].concat(n && n.ip_address != null ? [n.ip_address] : [], n && Array.isArray(n.ip_addresses) ? n.ip_addresses : [], n && n.requested_ip_address != null ? [n.requested_ip_address] : []))),
        macs: nicMacs((Array.isArray(v.vm_nics) ? v.vm_nics : []).map((n) => n && n.mac_address)) }));
      const datastores = ((sr && sr.json && sr.json.entities) || []).map((s) => { const u = s.usage_stats || {}, capb = num(u['storage.capacity_bytes']) || num(s.max_capacity), used = num(u['storage.usage_bytes']); return { id: String(s.storage_container_uuid || s.name), name: 'container ' + String(s.name || ''), type: 'Nutanix', capacity: capb, free: capb != null && used != null ? capb - used : null, uncommitted: null, accessible: true }; });
      // unresolved Prism alerts (best effort: a user without the alert view keeps the capacity read)
      let alerts = null;
      try { const ar = await call('GET', v2 + 'alerts?resolved=false&count=500'); if (ar.status >= 200 && ar.status < 300 && ar.json) alerts = (ar.json.entities || []).map((a) => ({ id: String(a.id || a.alert_uid || ''), severity: /critical/i.test(String(a.severity)) ? 'critical' : /warning/i.test(String(a.severity)) ? 'warning' : 'info',
        title: String(a.alert_title || a.message || '').replace(/\{[a-z_]+\}/gi, (m) => { const k = m.slice(1, -1), i = (a.context_types || []).indexOf(k); return i >= 0 ? String((a.context_values || [])[i]) : m; }).slice(0, 300),
        entity: ((a.affected_entities || [])[0] || {}).entity_name || '', created: a.created_time_stamp_in_usecs ? new Date(Number(a.created_time_stamp_in_usecs) / 1000).toISOString() : null, acknowledged: !!a.acknowledged })).filter((a) => a.id); } catch (e) { alerts = null; }
      const S = await vmStats(); vms.forEach((v) => withUse(v, S));
      return { clusters, hosts, datastores, vms, usage: true, vm_usage: S.size > 0, alerts };
    }
    // Prism Central: v3 lists (capacity and allocation, no usage)
    const list = async (kind) => { const out = []; for (let off = 0; off < 20000; off += 500) { const r = await call('POST', `/api/nutanix/v3/${kind}s/list`, { kind, length: 500, offset: off }); if (r.status < 200 || r.status >= 300) throw err('protocol', `Prism ${kind} list: HTTP ${r.status}`); const e = (r.json && r.json.entities) || []; out.push(...e); if (e.length < 500) break; } return out; };
    const [H, V, C] = [await list('host'), await list('vm'), await list('cluster')];
    const cl = C.filter((c) => !(((((c.status || {}).resources || {}).config || {}).service_list) || []).includes('PRISM_CENTRAL')).map((c) => ({ id: (c.metadata && c.metadata.uuid) || '', name: (c.status && c.status.name) || '' }));
    const cn = new Map(cl.map((c) => [c.id, c.name]));
    const hosts = H.filter((h) => h.status && h.status.resources && h.status.resources.hypervisor).map((h) => { const r = h.status.resources, cid = (h.status.cluster_reference || {}).uuid || ''; return { id: h.metadata.uuid, name: h.status.name || '', cluster_id: cid, cluster: cn.get(cid) || (h.status.cluster_reference || {}).name || 'Nutanix', vendor: 'Nutanix', model: (r.block && r.block.block_model) || '', serial: r.serial_number || '',
      cpu_model: r.cpu_model || '', sockets: num(r.num_cpu_sockets), cores: num(r.num_cpu_cores), threads: null, cpu_mhz: num(r.cpu_capacity_hz) ? num(r.cpu_capacity_hz) / 1e6 : null, cpu_used_mhz: null, mem_bytes: num(r.memory_capacity_mib) ? num(r.memory_capacity_mib) * 1048576 : null, mem_used_bytes: null,
      version: (r.hypervisor && r.hypervisor.hypervisor_full_name) || 'Nutanix AHV', state: 'connected', maintenance: false, ...ntxAddrs((r.hypervisor || {}).ip, (r.controller_vm || {}).ip, (r.ipmi || {}).ip) }; });
    const vms = V.map((v) => { const r = (v.status || {}).resources || {}; return { id: v.metadata.uuid, name: (v.status || {}).name || '', uuid: v.metadata.uuid, host_id: (r.host_reference || {}).uuid || null, power: String(r.power_state || '').toUpperCase() === 'ON' ? 'on' : 'off',
      vcpus: (num(r.num_sockets) || 0) * (num(r.num_vcpus_per_socket) || 1) || null, mem_mb: num(r.memory_size_mib), disk_bytes: (r.disk_list || []).filter((d) => (d.device_properties || {}).device_type !== 'CDROM').reduce((a, d) => a + (num(d.disk_size_bytes) || 0), 0) || null, cpu_used_mhz: null, mem_used_mb: null,
      // status carries the learned addresses; spec only the requested ones (a VM without NGT/IPAM may report none)
      ...(() => { const nl = Array.isArray(r.nic_list) && r.nic_list.length ? r.nic_list : (Array.isArray((((v.spec || {}).resources || {}).nic_list)) ? v.spec.resources.nic_list : []);
        return { ips: nicIps([], ...nl.map((n) => (n && Array.isArray(n.ip_endpoint_list) ? n.ip_endpoint_list : []).map((e) => e && e.ip))), macs: nicMacs(nl.map((n) => n && n.mac_address)) }; })() }; });
    // Prism Central lists carry no usage; its v1 VM list does on most releases (best effort, same join)
    const S = await vmStats(); vms.forEach((v) => withUse(v, S));
    return { clusters: cl, hosts, datastores: [], vms, usage: false, vm_usage: S.size > 0 };
  }
  // ---- DR replication (best effort, each part on its own: a Prism or a user without one keeps the rest, and what was not
  // read is listed in read_errors - never shown as healthy). Field names vary between AOS releases, so each value is taken
  // from the names Prism uses and left null ("not reported") when none is there.
  const usec = (v) => (num(v) > 0 ? new Date(num(v) / 1000).toISOString() : null);
  // a protection domain's shortest schedule interval in minutes (MINUTELY / HOURLY / DAILY / WEEKLY x every_nth)
  const schedMin = (list) => { const per = { MINUTELY: 1, HOURLY: 60, DAILY: 1440, WEEKLY: 10080 }; const v = (list || []).map((c) => (per[String(c.type || '').toUpperCase()] || 0) * (num(c.every_nth) || 1)).filter((x) => x > 0); return v.length ? Math.min(...v) : null; };
  async function drRead(vmNames) {
    const v2 = '/PrismGateway/services/rest/v2.0/', out = { read_errors: [], protection_domains: [], remote_sites: [], replications: [], leap: null, unprotected_vms: null };
    const get = async (path, what) => { try { const r = await call('GET', path); if (r.status === 404) return null; if (r.status < 200 || r.status >= 300 || !r.json) { out.read_errors.push(`${what}: HTTP ${r.status}`); return null; } return r.json; } catch (e) { out.read_errors.push(`${what}: ${e.message}`); return null; } };
    const pdj = await get(v2 + 'protection_domains', 'protection domains');
    if (pdj) {
      for (const d of (pdj.entities || []).slice(0, 200)) {
        const name = String(d.name || ''); if (!name) continue;
        const remotes = [].concat(d.remote_site_names || [], (d.remote_site_list || []).map((x) => x.name || x), ((d.cron_schedules || []).flatMap((c) => Object.keys(c.remote_retention_policy || c.remote_max_snapshots || {})))).map(String).filter((x, i, a) => x && a.indexOf(x) === i);
        const pd = { name, active: d.active === true ? true : d.active === false ? false : null, metro: !!(d.metro_avail && d.metro_avail.role), vms: (d.vms || []).map((x) => String(x.vm_name || x.name || '')).filter(Boolean),
          remote_sites: remotes, schedule_min: schedMin(d.cron_schedules), last_snapshot_at: null, last_replicated_at: null, replicated_to: null, pending: num(d.pending_replication_count), ongoing: num(d.ongoing_replication_count) };
        const sj = await get(v2 + 'protection_domains/' + encodeURIComponent(name) + '/dr_snapshots?count=20', 'DR snapshots of ' + name);
        for (const x of (sj && sj.entities) || []) {
          const at = usec(x.snapshot_create_time_usecs || x.created_time_usecs); if (!at) continue;
          if (!pd.last_snapshot_at || at > pd.last_snapshot_at) pd.last_snapshot_at = at;
          // a snapshot that exists on a remote site (replicated): the remote names Prism lists for it, or a remote location type
          const where = [].concat(x.remote_site_names || [], x.replicated_remote_sites || [], (x.locations || []).filter((l) => /remote/i.test(String(l.location_type || l.type || ''))).map((l) => l.remote_site_name || l.name || 'remote')).map(String).filter(Boolean);
          if (where.length && (!pd.last_replicated_at || at > pd.last_replicated_at)) { pd.last_replicated_at = at; pd.replicated_to = where.join(', '); }
        }
        out.protection_domains.push(pd);
      }
    }
    const rsj = await get(v2 + 'remote_sites', 'remote sites');
    if (rsj) out.remote_sites = (rsj.entities || []).slice(0, 50).map((r) => { const st = String(r.status || r.health || r.connection_status || ''); return { name: String(r.name || ''), address: ((r.remote_ip_ports && Object.keys(r.remote_ip_ports)) || []).join(', ') || String(r.remote_address || ''),
      status: st || null, healthy: !st ? null : /^(ok|good|healthy|connected|normal|reachable|up)$/i.test(st), compression: r.compression_enabled == null ? null : !!r.compression_enabled, bandwidth_kbps: num(r.max_bps) != null ? Math.round(num(r.max_bps) / 1000) : null }; }).filter((r) => r.name);
    const repj = await get(v2 + 'protection_domains/replications', 'replications in progress');
    if (repj) out.replications = (repj.entities || []).slice(0, 100).map((x) => ({ protection_domain: String(x.protection_domain_name || ''), remote_site: String(x.remote_site_name || (x.remote_site_names || [])[0] || ''), direction: /recei/i.test(String(x.replication_operation || '')) ? 'receiving' : 'sending',
      started_at: usec(x.start_time_usecs || x.replication_start_time_in_usecs), pct: num(x.completed_percentage != null ? x.completed_percentage : x.percentage_complete), bytes_done: num(x.completed_bytes || x.replicated_bytes), bytes_total: num(x.total_bytes) }));
    if (pdj && vmNames) { const prot = new Set(out.protection_domains.flatMap((d) => d.vms)); out.unprotected_vms = vmNames.filter((n) => n && !prot.has(n)).slice(0, 500); }
    return out;
  }
  // Prism Central (Leap): protection rules with their RPO, recovery plans
  async function leapRead() {
    const out = { read_errors: [], rules: [], plans: [] };
    const list = async (kind) => { try { const r = await call('POST', `/api/nutanix/v3/${kind}s/list`, { kind, length: 200, offset: 0 }); if (r.status === 404) return null; if (r.status < 200 || r.status >= 300 || !r.json) { out.read_errors.push(`${kind}s: HTTP ${r.status}`); return null; } return r.json.entities || []; } catch (e) { out.read_errors.push(`${kind}s: ${e.message}`); return null; } };
    const R = await list('protection_rule'), P = await list('recovery_plan');
    if (!R && !P) return null;
    out.rules = (R || []).map((x) => { const res = ((x.spec || {}).resources) || {}, conn = res.availability_zone_connectivity_list || [];
      const rpo = conn.flatMap((c) => (c.snapshot_schedule_list || []).map((sch) => num(sch.recovery_point_objective_secs))).filter((v) => v > 0);
      return { name: String((x.spec || {}).name || (x.status || {}).name || ''), state: String((x.status || {}).state || ''), rpo_min: rpo.length ? Math.round(Math.min(...rpo) / 60) : null,
        targets: conn.map((c) => (c.destination_availability_zone_index != null ? 'zone ' + c.destination_availability_zone_index : '')).filter(Boolean) }; }).filter((x) => x.name);
    out.plans = (P || []).map((x) => ({ name: String((x.spec || {}).name || (x.status || {}).name || ''), state: String((x.status || {}).state || ''), stages: (((x.spec || {}).resources || {}).stage_list || []).length })).filter((x) => x.name);
    return out;
  }
  // live counters only: hosts' hypervisor CPU / memory (Prism Element) and every VM's usage, joined to the last full read's VMs
  async function live(prevVms) {
    const out = { hosts: [], vms: [] };
    const hr = await call('GET', '/PrismGateway/services/rest/v2.0/hosts');
    if (hr.status >= 200 && hr.status < 300 && hr.json && Array.isArray(hr.json.entities)) out.hosts = hr.json.entities.map((h) => { const st = h.stats || {}, cpu = num(h.cpu_capacity_in_hz), mem = num(h.memory_capacity_in_bytes), cr2 = ppm(st.hypervisor_cpu_usage_ppm), mr = ppm(st.hypervisor_memory_usage_ppm);
      return { id: String(h.uuid), cpu_used_mhz: cpu && cr2 != null ? Math.round(cpu / 1e6 * cr2) : null, mem_used_bytes: mem && mr != null ? Math.round(mem * mr) : null }; });
    const S = await vmStats();
    out.vms = (prevVms || []).filter((v) => S.has(v.uuid || v.id)).map((v) => { const c = withUse({ id: v.id, uuid: v.uuid, mem_mb: v.mem_mb }, S); return { id: v.id, cpu_pct: c.cpu_pct, mem_used_mb: c.mem_used_mb, iops: c.iops, io_latency_ms: c.io_latency_ms, io_kbps: c.io_kbps }; });
    // DR state with every live read too, so a missed RPO shows within a minute
    if (out.hosts.length) { out.dr = await drRead((prevVms || []).filter((v) => v.power === 'on').map((v) => v.name)); out.dr.at = new Date().toISOString(); }
    else { const leap = await leapRead(); if (leap) out.dr = { at: new Date().toISOString(), read_errors: leap.read_errors, protection_domains: [], remote_sites: [], replications: [], leap: { rules: leap.rules, plans: leap.plans }, unprotected_vms: null }; }
    return out;
  }
  // DR on its own (after a Python capacity read, which does not read it): Prism Element protection domains, else Leap
  async function dr(vmNames) {
    const hr = await call('GET', '/PrismGateway/services/rest/v2.0/hosts');
    if (hr.status >= 200 && hr.status < 300 && hr.json && Array.isArray(hr.json.entities)) { const d = await drRead(vmNames); d.at = new Date().toISOString(); return d; }
    const leap = await leapRead(); return leap ? { at: new Date().toISOString(), read_errors: leap.read_errors, protection_domains: [], remote_sites: [], replications: [], leap: { rules: leap.rules, plans: leap.plans }, unprotected_vms: null } : null;
  }
  // baseline hardening (Baseline Hardening page): the cluster's security configuration as Prism reports it - security
  // compliance (SCMA) for the CVMs and the hypervisor, cluster lockdown, NTP / DNS, directory authentication, remote syslog.
  // GET only; a part Prism does not answer (an older AOS, a role without access) is null = "not checked", never a pass.
  async function hardening() {
    const v2 = '/PrismGateway/services/rest/v2.0/', v1 = '/PrismGateway/services/rest/v1/', ok = (r) => r && r.status >= 200 && r.status < 300 && r.json;
    const cr = await call('GET', v2 + 'cluster');
    if (!ok(cr)) throw err('protocol', 'Prism: the cluster could not be read (HTTP ' + (cr && cr.status) + ')');
    const c = cr.json, scma = (x) => (x && typeof x === 'object' ? { schedule: x.schedule ? String(x.schedule) : null, aide: x.enable_aide == null ? null : !!x.enable_aide, core: x.enable_core == null ? null : !!x.enable_core,
      high_strength_password: x.enable_high_strength_password == null ? null : !!x.enable_high_strength_password, banner: x.enable_banner == null ? null : !!x.enable_banner, snmpv3_only: x.enable_snmpv3_only == null ? null : !!x.enable_snmpv3_only } : null);
    const out = { cluster: { id: String(c.uuid || ''), name: String(c.name || ''), version: String(c.full_version || c.version || ''), ntp: Array.isArray(c.ntp_servers) ? c.ntp_servers.map(String) : null,
      dns: Array.isArray(c.name_servers) ? c.name_servers.map(String) : null, scma: scma(c.security_compliance_config), hv_scma: scma(c.hypervisor_security_compliance_config),
      lockdown: c.enable_lock_down == null ? null : !!c.enable_lock_down, password_remote_login: c.enable_password_remote_login_to_cluster == null ? null : !!c.enable_password_remote_login_to_cluster,
      smtp: c.smtp_server && c.smtp_server.address ? true : c.smtp_server === undefined ? null : false }, auth: null, syslog: null, hosts: [] };
    try { const r = await call('GET', v1 + 'authconfig'); if (ok(r)) out.auth = { directories: Array.isArray(r.json.directoryList) ? r.json.directoryList.length : 0, auth_types: Array.isArray(r.json.authTypeList) ? r.json.authTypeList.map(String) : [] }; } catch (e) { out.auth = null; }
    try { const r = await call('GET', v1 + 'remote_syslog_servers'); if (ok(r)) { const l = Array.isArray(r.json) ? r.json : Array.isArray(r.json.entities) ? r.json.entities : []; out.syslog = { servers: l.length }; } } catch (e) { out.syslog = null; }
    try { const r = await call('GET', v2 + 'hosts'); if (ok(r) && Array.isArray(r.json.entities)) out.hosts = r.json.entities.map((h) => Object.assign({ id: String(h.uuid), name: String(h.name || ''), version: String(h.hypervisor_full_name || '') }, ntxAddrs(h.hypervisor_address, h.service_vmexternal_ip, h.ipmi_address))); } catch (e) { out.hosts = []; }
    return out;
  }
  // virtual networking (Virtual Network Map): host NICs (link, speed), AHV networks / VLANs, VM NICs, virtual switches (v4, if
  // the AOS has it). GET only; a part Prism does not answer is listed in read_errors
  async function network() {
    const v2 = '/PrismGateway/services/rest/v2.0/', ok = (r) => r && r.status >= 200 && r.status < 300 && r.json, errors = [], R = { nics: {} };
    const hr = await call('GET', v2 + 'hosts'); if (!ok(hr)) throw err('protocol', 'Prism: the hosts could not be read (HTTP ' + (hr && hr.status) + ') - the network map needs Prism Element');
    R.hosts = (hr.json.entities || []).filter((h) => h && /^[0-9a-f-]{36}$/i.test(String(h.uuid)));
    try { const cr = await call('GET', v2 + 'cluster'); if (ok(cr)) R.cluster = cr.json; } catch (e) { errors.push('cluster: ' + e.message); }
    for (const h of R.hosts) { try { const r = await call('GET', v2 + 'hosts/' + h.uuid + '/host_nics'); if (ok(r)) R.nics[h.uuid] = Array.isArray(r.json) ? r.json : (r.json.entities || []); else errors.push('host NICs of ' + h.name + ': HTTP ' + r.status); } catch (e) { errors.push('host NICs of ' + h.name + ': ' + e.message); } }
    try { const r = await call('GET', v2 + 'networks'); if (ok(r)) R.networks = r.json.entities || []; else errors.push('networks: HTTP ' + r.status); } catch (e) { errors.push('networks: ' + e.message); }
    try { const r = await call('GET', v2 + 'vms?include_vm_disk_config=true&include_vm_nic_config=true'); if (ok(r)) R.vms = r.json.entities || []; else errors.push('VMs: HTTP ' + r.status); } catch (e) { errors.push('VMs: ' + e.message); }
    try { const r = await call('GET', '/api/networking/v4.0/config/virtual-switches'); if (ok(r)) R.vswitches = Array.isArray(r.json.data) ? r.json.data : []; } catch (e) { /* older AOS: no v4 networking API - the bonds stay unread */ }
    return require('./virt-net-read').fromNutanix(R, errors);
  }
  return { collect, live, dr, hardening, network };
}

// ---- the add-on ------------------------------------------------------------------------------------------------------
function createVirtCapacity(app, opts = {}) {
  const { store } = app;
  const facts = store.collection('core_lic_facts');
  const plats = store.collection('virt_platforms'), latest = store.collection('virt_capacity'), hist = store.collection('virt_capacity_hist'), vmHist = store.collection('virt_vm_hist'), cfgCol = store.collection('virt_capacity_cfg');
  const assets = store.collection('assets'), devs = store.collection('disc_devices');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-virt-platforms' });
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  let running = null;

  // Where to read from: the platforms on the Virtualization page AND every vCenter / Nutanix login already saved in Asset
  // Discovery (a scope's credential) — so a platform set up once on the asset side feeds Capacity Planning and the AI
  // Virtualization Administrator without being entered a second time. Same address in both = one source (the page wins).
  const discVault = () => opts.discoveryVault || (app.discovery && app.discovery.vault) || null;
  const normUrl = (u) => String(u || '').trim().toLowerCase().replace(/\/+$/, '');
  function sources() {
    const out = [], seen = new Set();
    for (const p of plats.all((x) => x.kind === 'vcenter' || x.kind === 'esxi' || x.kind === 'nutanix')) { out.push(Object.assign({}, p, { origin: 'virtualization' })); seen.add(normUrl(p.base_url)); }
    const V = discVault(); let list = [];
    try { list = V && typeof V.list === 'function' ? V.list() || [] : []; } catch (e) { list = []; }
    for (const c of list) {
      if (!c || (c.kind !== 'vcenter' && c.kind !== 'nutanix')) continue;
      const t = c.target || {}, u = normUrl(t.base_url);
      if (!u || seen.has(u)) continue;
      seen.add(u);
      out.push({ id: 'dv_' + c.id, cred_id: c.id, kind: c.kind, label: c.label || t.base_url, base_url: t.base_url, site: '', origin: 'asset-discovery', enc: true });
    }
    return out;
  }

  function settings() { return Object.assign({}, DEFAULTS, (cfgCol.get('cfg') || {}).value || {}); }
  function setSettings(b, who) {
    const v = settings(), lim = { vcpu_ratio: [1, 20], cpu_max_pct: [10, 100], mem_max_pct: [10, 100], storage_max_pct: [10, 100], interval_min: [15, 1440], live_sec: [0, 3600], dr_rpo_min: [1, 10080] };
    for (const k of Object.keys(lim)) if (k in b) { const n = Number(b[k]); if (!Number.isFinite(n) || n < lim[k][0] || n > lim[k][1]) throw bad(`${k} must be ${lim[k][0]}-${lim[k][1]}`); v[k] = k === 'vcpu_ratio' ? Math.round(n * 10) / 10 : Math.round(n); }
    if ('n_plus_1' in b) v.n_plus_1 = b.n_plus_1 === true;
    cfgCol.put({ id: 'cfg', value: v, by: who.user, at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.capacity.settings', target: 'capacity', detail: v });
    return report();
  }

  function uidIndex() { const m = new Map(); for (const d of devs.all((x) => x.asset_id)) for (const u of d.uids || []) m.set(u, d.asset_id); return m; }
  function fill(assetId, f, src, out) {
    const a = assetId && assets.get(assetId); if (!a) return;
    const ch = [];
    for (const [k, v] of Object.entries(f)) {
      if (v == null || v === '' || (a.locked && a.locked[k])) continue;
      const mine = a.prov && a.prov[k] === src;
      if ((a[k] == null || a[k] === '' || mine) && a[k] !== v) ch.push(k);
    }
    if (!ch.length) return;
    assets.patch(assetId, (x) => { x.prov = x.prov || {}; for (const k of ch) { x[k] = f[k]; x.prov[k] = src; } x.updated_at = new Date(now()).toISOString(); return x; });
    out.assets_filled++;
  }
  const gb = (b) => (b == null ? null : Math.round(b / GB));
  function enrich(p, m, out) {
    const idx = uidIndex(), src = p.kind === 'nutanix' ? 'nutanix' : 'vcenter';
    const ad = p.origin === 'asset-discovery';   // Asset Discovery keys vCenter hosts/VMs without the platform id
    for (const h of m.hosts) {
      const aid = idx.get(p.kind === 'nutanix' ? `ntnx-host:${h.id}`.toLowerCase() : (ad ? `vc-host:${h.id}` : `vc-host:${p.id}:${h.id}`).toLowerCase());
      // the counts first, unambiguously: "2 sockets, 24 cores each" (h.cores is the host total; a CPU model such as
      // "EPYC 7543 32-Core" must not be read as the core count)
      const cps = h.sockets && h.cores && h.cores % h.sockets === 0 ? h.cores / h.sockets : null;
      fill(aid, { vendor: h.vendor || null, model: h.model || null, serial: h.serial || null, os: h.version || null, mem_gb: gb(h.mem_bytes),
        cpu: h.cores ? (cps ? `${h.sockets} sockets, ${cps} cores each (${h.cores} cores) · ${h.cpu_model || 'CPU'}` : `${h.cores} cores total · ${h.cpu_model || 'CPU'}`) : null }, src, out);
      if (aid && cps) {
        const f = facts.get(aid);
        // never over counts a person entered (source 'entered' or none with values) - the platform's own reading only replaces itself
        if (!f || f.source === src || (!f.sockets && !f.cores_per_socket)) {
          const cl = h.cluster && h.cluster !== 'Standalone hosts' ? h.cluster : '';
          const nf = Object.assign({}, f || { id: aid }, { sockets: h.sockets, cores_per_socket: cps, cluster: (f && f.source !== src && f.cluster) || cl || (f && f.cluster) || '', cpu_vendor: (f && f.cpu_vendor) || cpuVendor(h.cpu_model), source: src, updated_by: SYS.user, updated_at: new Date(now()).toISOString() });
          if (!f || f.sockets !== nf.sockets || f.cores_per_socket !== nf.cores_per_socket || f.cluster !== nf.cluster) { facts.put(nf); out.cores_filled = (out.cores_filled || 0) + 1; }
        }
      } else if (aid && h.cores) out.cores_uneven = (out.cores_uneven || 0) + 1;
    }
    for (const v of m.vms) {
      const aid = idx.get(p.kind === 'nutanix' ? `ntnx:${v.id}`.toLowerCase() : `vc:${v.uuid || (ad ? v.id : p.id + ':' + v.id)}`.toLowerCase());
      fill(aid, { cpu: v.vcpus ? `${v.vcpus} vCPU` : null, mem_gb: v.mem_mb ? Math.round(v.mem_mb / 1024 * 10) / 10 : null, disk_gb: gb(v.disk_bytes) }, src, out);
    }
  }
  /* the platform read runs in Python (pyengine/virt_capacity.py, docs/PYTHON-MIGRATION.md step 4); config
     virt_capacity.engine = "node", an injected request (tests) or no Python → vcSoap / ntxClient above */
  const py = opts.request || ((app.config && app.config.virt_capacity) || {}).engine === 'node' ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3', timeoutMs: 15 * 60000 }); } catch (e) { return null; } })();
  // Nutanix DR state, read once after the capacity read (Node.js or Python): never fails the capacity read
  async function withDr(m, target, secret) {
    try { m.dr = await ntxClient(target, secret, { request: opts.request }).dr((m.vms || []).filter((v) => v.power === 'on').map((v) => v.name)); }
    catch (e) { m.dr = { at: new Date().toISOString(), read_errors: ['DR: ' + e.message], protection_domains: [], remote_sites: [], replications: [], leap: null, unprotected_vms: null }; }
  }
  async function readPlatform(kind, target, secret) {
    const vc = kind === 'vcenter' || kind === 'esxi';
    if (py) {
      const r = await py.call(vc ? 'virt.vcenter' : 'virt.nutanix', { target, secret: { username: secret.username, password: secret.password }, opts: {} });
      if (!(r && r.error_class === 'missing_python')) {
        if (!r || r.ok === false) throw Object.assign(err((r && r.error_class) || 'protocol', (r && r.error) || 'the Python reader gave no answer'), r && r.presented ? { presented: r.presented } : {});
        if (!vc) await withDr(r, target, secret);
        return Object.assign(r, { engine: 'python' });
      }
    }
    const m = vc ? fromVcenter(await vcSoap(target, secret, { request: opts.request }).collect()) : await ntxClient(target, secret, { request: opts.request }).collect();
    if (!vc) await withDr(m, target, secret);
    return Object.assign(m, { engine: 'node' });
  }
  // open the platform's credentials, run fn(target, secret), always release them
  async function withCred(p, fn) {
    if (p.origin === 'asset-discovery') {
      const V = discVault(); if (!V || typeof V.open !== 'function') throw bad('Asset Discovery credential vault not available', 503);
      const c = V.open(p.cred_id), t = c.target || {};
      try { return await fn({ base_url: t.base_url, ca_file: t.ca_file || undefined, tls_fingerprint: t.tls_fingerprint || undefined }, c.secret); } finally { c.release(); }
    }
    if (!p.enc) throw bad('user name and password not set', 409);
    const secret = JSON.parse(sealer.unseal(p.id, p.enc));
    try { return await fn({ base_url: p.base_url, ca_file: p.ca_file || undefined, tls_fingerprint: p.tls_fingerprint || undefined }, secret); } finally { secret.password = null; }
  }
  // live: the light read for every platform that has a full read to patch (Node.js reader, read-only calls only)
  let living = null;
  async function live(who = SYS) {
    if (running) return { skipped: 'a full collection is running' };
    if (living) return living;
    living = (async () => {
      const res = [];
      for (const p of sources().filter((x) => x.enc)) {
        const prev = latest.get(p.id), at = new Date(now()).toISOString(), out = { platform_id: p.id, label: p.label, at, ok: true };
        if (!prev) { out.ok = false; out.error = 'no full collection yet - run Collect now first'; res.push(out); continue; }
        try {
          const vc = p.kind === 'vcenter' || p.kind === 'esxi';
          const L = await withCred(p, (target, secret) => (vc ? vcSoap(target, secret, { request: opts.request }).live() : ntxClient(target, secret, { request: opts.request }).live(prev.vms)));
          const hm = new Map(L.hosts.map((h) => [h.id, h])), vm = new Map(L.vms.map((v) => [v.id, v])), clean = (o) => Object.fromEntries(Object.entries(o).filter(([k, v]) => k !== 'id' && v !== undefined));
          latest.patch(p.id, (x) => { x.hosts = (x.hosts || []).map((h) => (hm.has(h.id) ? Object.assign({}, h, clean(hm.get(h.id))) : h)); x.vms = (x.vms || []).map((v) => (vm.has(v.id) ? Object.assign({}, v, clean(vm.get(v.id))) : v)); if (L.dr) x.dr = L.dr; x.live_at = at; delete x.live_error; return x; });
          Object.assign(out, { hosts: L.hosts.length, vms: L.vms.length });
        } catch (e) { out.ok = false; out.error = String(e.message || e).slice(0, 300); latest.patch(p.id, (x) => { x.live_error = out.error; x.live_error_at = at; return x; }); }
        res.push(out);
      }
      cfgCol.put({ id: 'last_live', value: { at: new Date(now()).toISOString(), results: res } });
      if (who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.capacity.live', target: 'capacity', detail: res.map((r) => ({ label: r.label, ok: r.ok, error: r.error })) });
      return res;
    })().finally(() => { living = null; });
    return living;
  }
  async function collectOne(p) {
    if (p.origin === 'asset-discovery') {
      const V = discVault(); if (!V || typeof V.open !== 'function') throw bad('Asset Discovery credential vault not available', 503);
      const c = V.open(p.cred_id), t = c.target || {};
      const target = { base_url: t.base_url, ca_file: t.ca_file || undefined, tls_fingerprint: t.tls_fingerprint || undefined };
      try { return await readPlatform(p.kind, target, c.secret); } finally { c.release(); }
    }
    if (!p.enc) throw bad('user name and password not set', 409);
    const secret = JSON.parse(sealer.unseal(p.id, p.enc)), target = { base_url: p.base_url, ca_file: p.ca_file || undefined, tls_fingerprint: p.tls_fingerprint || undefined };
    try { return await readPlatform(p.kind, target, secret); } finally { secret.password = null; }
  }
  // onlyId: collect one platform now (a platform just synced on Virtualization / just added) - its result joins the last run's
  // results, and the hourly cadence (last_run.at) is not moved
  async function run(who = SYS, onlyId) {
    if (running) return running;
    running = (async () => {
      const res = [];
      for (const p of sources().filter((x) => x.enc && (!onlyId || x.id === onlyId))) {
        const out = { platform_id: p.id, label: p.label, kind: p.kind, origin: p.origin, at: new Date(now()).toISOString(), ok: true, assets_filled: 0 };
        try {
          const m = await collectOne(p);
          Object.assign(out, { hosts: m.hosts.length, vms: m.vms.length, clusters: m.clusters.length, datastores: m.datastores.length, engine: m.engine });
          latest.put(Object.assign({ id: p.id, label: p.label, kind: p.kind, site: p.site || '', at: out.at }, m));
          sample(p, m);
          sampleVms(p, m);
          enrich(p, m, out);
        } catch (e) {
          out.ok = false; out.error = String(e.message || e).slice(0, 300); out.error_class = e.code || 'protocol';
          const prev = latest.get(p.id); if (prev) latest.patch(p.id, (x) => { x.last_error = out.error; x.last_error_at = out.at; return x; });
        }
        res.push(out);
      }
      if (onlyId) { const prev = (cfgCol.get('last_run') || {}).value; cfgCol.put({ id: 'last_run', value: { at: prev ? prev.at : new Date(now()).toISOString(), results: ((prev && prev.results) || []).filter((r) => r.platform_id !== onlyId).concat(res) } }); }
      else cfgCol.put({ id: 'last_run', value: { at: new Date(now()).toISOString(), results: res } });
      if (who !== SYS || res.some((r) => !r.ok)) audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.capacity.run', target: 'capacity', detail: res.map((r) => ({ label: r.label, ok: r.ok, hosts: r.hosts, vms: r.vms, error: r.error })) });
      return res;
    })().finally(() => { running = null; });
    return running;
  }

  // ---- model → report ----
  function clusterView(p, m, c, st) {
    const hs = m.hosts.filter((h) => (c.id ? h.cluster_id === c.id : !h.cluster_id)), hids = new Set(hs.map((h) => h.id));
    const vms = m.vms.filter((v) => hids.has(v.host_id)), on = vms.filter((v) => v.power === 'on'), up = hs.filter((h) => h.state === 'connected' && !h.maintenance);
    const S = (L, k) => L.reduce((a, x) => a + (x[k] || 0), 0), has = (L, k) => L.some((x) => x[k] != null);
    const cores = S(up, 'cores'), cpu = S(up, 'cpu_mhz'), mem = S(up, 'mem_bytes');
    const big = (k) => up.reduce((a, h) => Math.max(a, h[k] || 0), 0), np1 = st.n_plus_1 && up.length > 1;
    const coresE = cores - (np1 ? big('cores') : 0), memE = mem - (np1 ? big('mem_bytes') : 0), cpuE = cpu - (np1 ? big('cpu_mhz') : 0);
    const vcpus = S(on, 'vcpus'), vmMem = S(on, 'mem_mb') * 1048576;
    const cpuUsed = has(up, 'cpu_used_mhz') ? S(up, 'cpu_used_mhz') : (c.cpu_ratio != null ? cpu * c.cpu_ratio : null);
    const memUsed = has(up, 'mem_used_bytes') ? S(up, 'mem_used_bytes') : (c.mem_ratio != null ? mem * c.mem_ratio : null);
    const avg = on.length ? { vcpus: vcpus / on.length, mem: vmMem / on.length, disk: S(on, 'disk_bytes') / on.length } : null;
    const memBasis = Math.max(vmMem, memUsed || 0);
    const room = avg ? {
      cpu: Math.max(0, Math.floor((coresE * st.vcpu_ratio - vcpus) / Math.max(avg.vcpus, 1))),
      mem: Math.max(0, Math.floor((memE * st.mem_max_pct / 100 - memBasis) / Math.max(avg.mem, 1))),
    } : null;
    if (room) room.limit = room.cpu <= room.mem ? 'CPU (vCPU per core)' : 'memory';
    return { platform: p.label, kind: p.kind, id: c.id || 'standalone:' + p.id, name: c.name || 'Standalone hosts', hosts: hs.length, hosts_up: up.length, vms: vms.length, vms_on: on.length,
      cores, cpu_ghz: cpu ? Math.round(cpu / 100) / 10 : null, cpu_used_pct: cpuUsed != null && cpu ? Math.round(cpuUsed / cpu * 1000) / 10 : null,
      mem_gb: gb(mem), mem_used_pct: memUsed != null && mem ? Math.round(memUsed / mem * 1000) / 10 : null, vm_mem_gb: gb(vmMem), mem_alloc_pct: mem ? Math.round(vmMem / mem * 1000) / 10 : null,
      vcpus, vcpu_ratio: cores ? Math.round(vcpus / cores * 100) / 100 : null, n_plus_1: np1, cores_after_n1: coresE, mem_gb_after_n1: gb(memE), cpu_ghz_after_n1: cpuE ? Math.round(cpuE / 100) / 10 : null,
      storage_gb: gb(c.storage_capacity), storage_used_pct: c.storage_capacity && c.storage_used != null ? Math.round(c.storage_used / c.storage_capacity * 1000) / 10 : null,
      avg_vm: avg ? { vcpus: Math.round(avg.vcpus * 10) / 10, mem_gb: Math.round(avg.mem / GB * 10) / 10, disk_gb: gb(avg.disk) } : null, room, usage_reported: cpuUsed != null || memUsed != null,
      ha: c.ha == null ? null : c.ha, drs: c.drs == null ? null : c.drs, status: c.status || null };
  }
  function sample(p, m) {
    const st = settings(), day = new Date(now()).toISOString().slice(0, 10);
    const cl = (m.clusters.length ? m.clusters : []).concat(m.hosts.some((h) => !h.cluster_id) ? [{ id: null, name: 'Standalone hosts' }] : []).map((c) => clusterView(p, m, c, st));
    const ds = m.datastores.reduce((a, d) => ({ cap: a.cap + (d.capacity || 0), free: a.free + (d.free || 0) }), { cap: 0, free: 0 });
    hist.put({ id: `${p.id}:${day}`, pid: p.id, day, at: now(), clusters: cl.map((c) => ({ id: c.id, mem_used_pct: c.mem_used_pct, mem_alloc_pct: c.mem_alloc_pct, cpu_used_pct: c.cpu_used_pct, vcpus: c.vcpus, vms_on: c.vms_on, storage_used_pct: c.storage_used_pct })), ds_cap: ds.cap, ds_used: ds.cap - ds.free });
    const cut = new Date(now() - 730 * DAY).toISOString().slice(0, 10);
    for (const h of hist.all((x) => x.pid === p.id && x.day < cut)) hist.remove(h.id);
  }
  // VM CPU %: Prism reports it; vSphere reports MHz, so it is read against the host's per-core speed × the VM's vCPUs
  function vmPct(vm, hostById) {
    if (vm.cpu_pct != null) return vm.cpu_pct;
    const h = hostById.get(vm.host_id);
    if (vm.cpu_used_mhz == null || !vm.vcpus || !h || !h.cpu_mhz || !h.cores) return null;
    return Math.round(vm.cpu_used_mhz / (vm.vcpus * h.cpu_mhz / h.cores) * 1000) / 10;
  }
  const memPct = (vm) => (vm.mem_used_mb != null && vm.mem_mb ? Math.round(vm.mem_used_mb / vm.mem_mb * 1000) / 10 : null);
  // one compact sample per platform per hour: running VMs that reported usage → [cpu %, mem %, IOPS, latency ms]; 31 days kept
  const VM_HIST_DAYS = 31;
  function sampleVms(p, m) {
    const hb = new Map(m.hosts.map((h) => [h.id, h])), v = {}; let n = 0, cs = 0, cn = 0, ms = 0, mn = 0, io = 0;
    for (const vm of m.vms) {
      if (vm.power !== 'on') continue;
      const c = vmPct(vm, hb), me = memPct(vm), i = vm.iops != null ? vm.iops : null, l = vm.io_latency_ms != null ? vm.io_latency_ms : null;
      if (c == null && me == null && i == null) continue;
      v[vm.id] = [c, me, i, l]; n++;
      if (c != null) { cs += c; cn++; } if (me != null) { ms += me; mn++; } if (i != null) io += i;
    }
    if (!n) return;
    const hour = new Date(now()).toISOString().slice(0, 13);
    vmHist.put({ id: `${p.id}:${hour}`, pid: p.id, at: now(), v, agg: { cpu: cn ? Math.round(cs / cn * 10) / 10 : null, mem: mn ? Math.round(ms / mn * 10) / 10 : null, iops: Math.round(io), n } });
    const cut = now() - VM_HIST_DAYS * DAY;
    for (const h of vmHist.all((x) => x.pid === p.id && x.at < cut)) vmHist.remove(h.id);
  }
  // history for the graphs: one VM ({pid, vm}) or each platform's averages ({pid?})
  function vmHistory(q = {}) {
    const days = Math.min(VM_HIST_DAYS, Math.max(1, Math.round(Number(q.days) || 7))), since = now() - days * DAY;
    const pick = (pid) => vmHist.all((x) => x.pid === pid && x.at >= since).sort((a, b) => a.at - b.at);
    if (q.vm) {
      if (!q.pid) throw bad('pid is required with vm');
      const pts = pick(String(q.pid)).filter((h) => h.v && h.v[q.vm]).map((h) => { const r = h.v[q.vm]; return { t: h.at, cpu: r[0], mem: r[1], iops: r[2], lat: r[3] }; });
      return { days, pid: String(q.pid), vm: String(q.vm), points: pts };
    }
    const list = sources().filter((p) => !q.pid || p.id === String(q.pid));
    return { days, series: list.map((p) => ({ pid: p.id, label: p.label, kind: p.kind, points: pick(p.id).map((h) => Object.assign({ t: h.at }, h.agg)) })) };
  }
  // least-squares slope per day over the samples; days until `limit` %, or null when the trend is flat / falling
  function trend(points, limit) {
    const pts = points.filter((x) => x.v != null); if (pts.length < 2) return { days_of_history: pts.length ? 1 : 0 };
    const t0 = pts[0].t, xs = pts.map((x) => (x.t - t0) / DAY), ys = pts.map((x) => x.v), n = xs.length, mx = xs.reduce((a, b) => a + b, 0) / n, my = ys.reduce((a, b) => a + b, 0) / n;
    const sxx = xs.reduce((a, x) => a + (x - mx) * (x - mx), 0); const span = xs[n - 1];
    if (!sxx) return { days_of_history: Math.round(span) };
    const slope = xs.reduce((a, x, i) => a + (x - mx) * (ys[i] - my), 0) / sxx, last = ys[n - 1];
    return { days_of_history: Math.round(span), per_month: Math.round(slope * 30 * 10) / 10, days_to_limit: slope > 0.0001 && last < limit ? Math.round((limit - last) / slope) : last >= limit ? 0 : null, reliable: span >= 30 && n >= 14 };
  }
  /* DR replication across every Nutanix platform: per protection domain the expected RPO (its schedule, else the Leap rule,
     else dr_rpo_min), the age of the last copy on a remote site, and a status; then the cross-site check (the same protection
     domain active on two sites, or on none). A status is computed only from what Prism reported - missing data is "unknown". */
  function drView(st) {
    const t = now(), sites = [], byName = new Map();
    for (const p of sources().filter((x) => x.kind === 'nutanix')) {
      const m = latest.get(p.id); if (!m) continue;
      const d = m.dr || null, rules = (d && d.leap && d.leap.rules) || [];
      const pds = ((d && d.protection_domains) || []).map((x) => {
        const expected = x.schedule_min || st.dr_rpo_min, basis = x.last_replicated_at ? 'replicated' : x.last_snapshot_at ? 'snapshot' : null, last = x.last_replicated_at || x.last_snapshot_at;
        const age = last ? Math.round((t - Date.parse(last)) / 60000) : null;
        let status, why;
        if (x.active === false) { status = 'standby'; why = 'inactive here - the copy is received from the active site, whose RPO is checked there'; }
        else if (!x.remote_sites.length && !x.metro) { status = 'no-remote'; why = 'snapshots stay on this cluster only - no remote site, so there is no DR copy'; }
        else if (!x.schedule_min) { status = 'no-schedule'; why = 'no snapshot schedule - nothing is replicated unless someone takes one by hand'; }
        else if (age == null) { status = 'unknown'; why = 'Prism reported no DR snapshot for it'; }
        else if (age > expected * 4) { status = 'critical'; why = `last ${basis === 'replicated' ? 'replicated copy' : 'snapshot'} ${age} min ago, RPO ${expected} min (more than 4x)`; }
        else if (age > expected * 2) { status = 'late'; why = `last ${basis === 'replicated' ? 'replicated copy' : 'snapshot'} ${age} min ago, RPO ${expected} min (more than 2x)`; }
        else { status = 'ok'; why = `last ${basis === 'replicated' ? 'replicated copy' : 'snapshot'} ${age} min ago, within RPO ${expected} min`; }
        if (status === 'ok' && basis === 'snapshot') why += ' - replication to the remote site was not reported, only the local snapshot';
        const repl = ((d && d.replications) || []).filter((r) => r.protection_domain === x.name), stuck = repl.find((r) => r.started_at && (t - Date.parse(r.started_at)) / 60000 > expected * 3);
        const row = Object.assign({}, x, { rpo_min: expected, age_min: age, basis, status, why, replicating: repl, stuck: stuck ? { remote_site: stuck.remote_site, minutes: Math.round((t - Date.parse(stuck.started_at)) / 60000), pct: stuck.pct } : null });
        if (!byName.has(x.name)) byName.set(x.name, []); byName.get(x.name).push({ platform: p.label, site: p.site || '', active: x.active });
        return row;
      });
      sites.push({ platform_id: p.id, platform: p.label, site: p.site || '', at: d ? d.at : null, read: !!d, read_errors: (d && d.read_errors) || [], protection_domains: pds, remote_sites: (d && d.remote_sites) || [],
        replications: (d && d.replications) || [], unprotected_vms: d ? d.unprotected_vms : null, leap: d ? d.leap : null, leap_rules_rpo: rules.map((r) => ({ name: r.name, rpo_min: r.rpo_min, state: r.state })) });
    }
    const cross = [];
    for (const [name, L] of byName) if (L.length > 1) {
      const act = L.filter((x) => x.active === true);
      if (act.length > 1) cross.push({ name, status: 'both-active', why: `active on ${act.map((x) => x.platform).join(' and ')} - both sides think they own it (split brain)`, sites: L });
      else if (!act.length && L.every((x) => x.active === false)) cross.push({ name, status: 'none-active', why: `inactive on ${L.map((x) => x.platform).join(' and ')} - nobody is protecting it`, sites: L });
    }
    const all = sites.flatMap((x) => x.protection_domains);
    return { sites, cross, totals: { protection_domains: all.length, ok: all.filter((x) => x.status === 'ok').length, late: all.filter((x) => x.status === 'late').length, critical: all.filter((x) => x.status === 'critical').length,
      no_remote: all.filter((x) => x.status === 'no-remote').length, unprotected_vms: sites.reduce((a, x) => a + ((x.unprotected_vms || []).length), 0), remote_sites_down: sites.reduce((a, x) => a + x.remote_sites.filter((r) => r.healthy === false).length, 0), cross: cross.length } };
  }
  // A VM's address: what the platform reported, else what discovery holds for the same VM (its uid, then the asset's management
  // address), else a Network Discovery device with one of the VM's MACs (ARP / switch tables). The source is always named, and a
  // VM nobody reported stays empty - shown as "no IP reported", never guessed from its name.
  function addrIndex() {
    const uid = new Map(), mac = new Map();
    for (const d of devs.all((x) => (x.ips && x.ips.length) || x.ip || x.asset_id)) {
      const ips = (d.ips && d.ips.length ? d.ips : [d.ip]).filter(Boolean);
      for (const u of d.uids || []) uid.set(String(u).toLowerCase(), { ips, asset_id: d.asset_id || null });
      for (const m of d.macs || []) if (!mac.has(String(m).toLowerCase())) mac.set(String(m).toLowerCase(), ips);
    }
    return { uid, mac };
  }
  function vmAddr(p, vm, AX) {
    if (vm.ips && vm.ips.length) return { ips: vm.ips, src: p.kind === 'nutanix' ? 'prism' : 'vcenter' };
    const key = p.kind === 'nutanix' ? `ntnx:${vm.id}` : `vc:${vm.uuid || (p.origin === 'asset-discovery' ? vm.id : p.id + ':' + vm.id)}`;
    const d = AX.uid.get(key.toLowerCase());
    if (d && d.ips.length) return { ips: d.ips, src: 'discovery' };
    const a = d && d.asset_id ? assets.get(d.asset_id) : null;
    if (a && a.mgmt_ip) return { ips: [a.mgmt_ip], src: 'asset' };
    for (const m of vm.macs || []) { const x = AX.mac.get(m); if (x && x.length) return { ips: x, src: 'mac' }; }
    return { ips: [], src: null };
  }
  // for Power Control: one address index, then (platformId, vm) → {ips, src} with the same order of sources as the report
  function vmAddrLookup() {
    const AX = addrIndex(), P = new Map(sources().map((p) => [p.id, p]));
    return (pid, vm) => (P.has(pid) && vm ? vmAddr(P.get(pid), vm, AX) : { ips: [], src: null });
  }
  function report() {
    const st = settings(), out = { settings: st, last_run: (cfgCol.get('last_run') || {}).value || null, last_live: (cfgCol.get('last_live') || {}).value || null, platforms: [], clusters: [], hosts: [], datastores: [], vms_off: [], top_vms: [], vms: [], totals: {} };
    const since = now() - 90 * DAY, AX = addrIndex();
    for (const p of sources()) {
      const m = latest.get(p.id);
      out.platforms.push({ id: p.id, label: p.label, kind: p.kind, site: p.site || '', origin: p.origin, at: m ? m.at : null, live_at: m && m.live_at ? m.live_at : null, live_error: m && m.live_error && (!m.live_at || m.live_error_at >= m.live_at) ? m.live_error : null, usage: m ? m.usage : null, vm_usage: m ? !!m.vm_usage : null, error: m && m.last_error && (!m.at || m.last_error_at > m.at) ? m.last_error : null, collected: !!m, credentials_set: !!p.enc });
      if (!m) continue;
      const H = hist.all((x) => x.pid === p.id && x.at >= since).sort((a, b) => a.at - b.at);
      const cls = (m.clusters.length ? m.clusters : []).concat(m.hosts.some((h) => !h.cluster_id) ? [{ id: null, name: 'Standalone hosts' }] : []);
      for (const c of cls) {
        const v = clusterView(p, m, c, st), cid = v.id;
        const series = (k) => H.map((h) => ({ t: h.at, v: ((h.clusters || []).find((x) => x.id === cid) || {})[k] }));
        v.forecast = { memory: trend(series(v.mem_used_pct != null ? 'mem_used_pct' : 'mem_alloc_pct'), st.mem_max_pct), cpu: trend(series('cpu_used_pct'), st.cpu_max_pct), storage: v.storage_used_pct != null ? trend(series('storage_used_pct'), st.storage_max_pct) : null };
        out.clusters.push(v);
      }
      const byHost = new Map(); for (const vm of m.vms) { const o = byHost.get(vm.host_id) || { vms: 0, on: 0, vcpus: 0, mem: 0 }; o.vms++; if (vm.power === 'on') { o.on++; o.vcpus += vm.vcpus || 0; o.mem += vm.mem_mb || 0; } byHost.set(vm.host_id, o); }
      for (const h of m.hosts) { const a = byHost.get(h.id) || { vms: 0, on: 0, vcpus: 0, mem: 0 };
        out.hosts.push({ platform: p.label, cluster: h.cluster, name: h.name, ip: h.ip || null, vmks: h.vmks || [], cvm_ip: h.cvm_ip || null, vendor: h.vendor, model: h.model, serial: h.serial, version: h.version, cpu_model: h.cpu_model, sockets: h.sockets, cores: h.cores, cores_per_socket: h.sockets && h.cores && h.cores % h.sockets === 0 ? h.cores / h.sockets : null, status: h.status || null,
          cpu_ghz: h.cpu_mhz ? Math.round(h.cpu_mhz / 100) / 10 : null, cpu_used_pct: h.cpu_used_mhz != null && h.cpu_mhz ? Math.round(h.cpu_used_mhz / h.cpu_mhz * 1000) / 10 : null,
          mem_gb: gb(h.mem_bytes), mem_used_pct: h.mem_used_bytes != null && h.mem_bytes ? Math.round(h.mem_used_bytes / h.mem_bytes * 1000) / 10 : null,
          vms: a.vms, vms_on: a.on, vcpus: a.vcpus, vcpu_ratio: h.cores ? Math.round(a.vcpus / h.cores * 100) / 100 : null, vm_mem_gb: Math.round(a.mem / 1024), state: h.state, maintenance: h.maintenance }); }
      const dsH = H.map((h) => ({ t: h.at, v: h.ds_cap ? h.ds_used / h.ds_cap * 100 : null }));
      for (const d of m.datastores) out.datastores.push({ platform: p.label, name: d.name, type: d.type, capacity_gb: gb(d.capacity), free_gb: gb(d.free), used_pct: d.capacity ? Math.round((d.capacity - (d.free || 0)) / d.capacity * 1000) / 10 : null,
        provisioned_pct: d.capacity && d.uncommitted != null ? Math.round((d.capacity - (d.free || 0) + d.uncommitted) / d.capacity * 1000) / 10 : null, accessible: d.accessible });
      if (m.datastores.length) out.storage_trend = Object.assign(out.storage_trend || {}, { [p.label]: trend(dsH, st.storage_max_pct) });
      const hn = new Map(m.hosts.map((h) => [h.id, h.name])), hb = new Map(m.hosts.map((h) => [h.id, h]));
      for (const vm of m.vms) {
        const on = vm.power === 'on', mp = memPct(vm), ad = vmAddr(p, vm, AX);
        const r = { id: vm.id, pid: p.id, platform: p.label, kind: p.kind, cluster: (hb.get(vm.host_id) || {}).cluster || '', name: vm.name, host: hn.get(vm.host_id) || '', power: vm.power, vcpus: vm.vcpus, mem_gb: vm.mem_mb ? Math.round(vm.mem_mb / 1024 * 10) / 10 : null, disk_gb: gb(vm.disk_bytes), guest_os: vm.guest_os || '',
          ips: ad.ips, ip_src: ad.src, macs: vm.macs || [],
          // provisioned disk: Nutanix reports the configured size; vSphere committed + uncommitted (thin disks grow into it)
          disk_prov_gb: p.kind === 'nutanix' ? gb(vm.disk_bytes) : vm.disk_uncommitted != null ? gb((vm.disk_bytes || 0) + vm.disk_uncommitted) : null,
          // usage only for a running VM: a stopped VM's last reading is not its utilisation
          cpu_used_mhz: on ? vm.cpu_used_mhz : null, cpu_pct: on ? vmPct(vm, hb) : null, mem_used_pct: on && mp != null ? Math.round(mp) : null,
          iops: on && vm.iops != null ? vm.iops : null, io_latency_ms: on && vm.io_latency_ms != null ? vm.io_latency_ms : null, io_kbps: on && vm.io_kbps != null ? vm.io_kbps : null,
          // vSphere health (read in its own call; null = not reported, never 'fine'): snapshot count / oldest, disks to consolidate, Tools
          snapshots: vm.snapshots || null, consolidate: vm.consolidate == null ? null : vm.consolidate, tools: on && vm.tools ? vm.tools : null };
        out.vms.push(r);   // every VM, for the per-platform lists (top_vms / vms_off below are cut for the overview cards)
        if (vm.power !== 'on') out.vms_off.push(r); else out.top_vms.push(r);
      }
    }
    out.top_vms.sort((a, b) => (b.mem_gb || 0) - (a.mem_gb || 0) || (b.vcpus || 0) - (a.vcpus || 0)); out.top_vms = out.top_vms.slice(0, 50);
    out.vms_off.sort((a, b) => (b.mem_gb || 0) - (a.mem_gb || 0)); out.vms_off = out.vms_off.slice(0, 200);
    out.vms.sort((a, b) => String(a.platform).localeCompare(String(b.platform)) || String(a.name).localeCompare(String(b.name)));
    out.vms_capped = out.vms.length > 20000; if (out.vms_capped) out.vms = out.vms.slice(0, 20000);
    const S = (L, k) => L.reduce((a, x) => a + (x[k] || 0), 0);
    out.totals = { clusters: out.clusters.length, hosts: out.hosts.length, vms: S(out.clusters, 'vms'), vms_on: S(out.clusters, 'vms_on'), cores: S(out.clusters, 'cores'), vcpus: S(out.clusters, 'vcpus'), mem_gb: S(out.clusters, 'mem_gb'), vm_mem_gb: S(out.clusters, 'vm_mem_gb'),
      storage_gb: S(out.datastores, 'capacity_gb') + S(out.clusters.filter((c) => c.kind === 'nutanix' && !out.datastores.some((d) => d.platform === c.platform)), 'storage_gb'), storage_free_gb: S(out.datastores, 'free_gb'), reclaim_mem_gb: Math.round(S(out.vms_off, 'mem_gb')), reclaim_disk_gb: S(out.vms_off, 'disk_gb') };
    out.dr = drView(st);
    return out;
  }
  async function tick() {
    const st = settings(), last = (cfgCol.get('last_run') || {}).value;
    if (running) return null;
    // a platform with no reading yet (just added on Virtualization / Asset Discovery) is collected now, not at the next hourly run;
    // one that failed is retried after 10 minutes, so a broken platform is not polled every minute
    const failedRecently = (id) => { const r = last && (last.results || []).find((x) => x.platform_id === id); return !!(r && !r.ok && now() - Date.parse(r.at) < 10 * 60000); };
    const fresh = sources().filter((x) => x.enc && !latest.get(x.id) && !failedRecently(x.id));
    if (fresh.length && last && now() - Date.parse(last.at) < st.interval_min * 60000) { for (const p of fresh) await run(SYS, p.id); return 'new-platforms'; }
    if (last && now() - Date.parse(last.at) < st.interval_min * 60000) return null;
    if (!sources().some((x) => x.enc)) return null;
    return run();
  }
  function collectPlatform(id, who = SYS) { return run(who, String(id)); }
  // live counters every live_sec seconds (0 = off; values 1-29 are raised to 30 so the platforms are not hammered)
  async function liveTick() {
    const st = settings(), sec = Number(st.live_sec) || 0; if (!sec) return null;
    const last = (cfgCol.get('last_live') || {}).value;
    if (running || living || (last && now() - Date.parse(last.at) < Math.max(30, sec) * 1000)) return null;
    if (!sources().some((x) => x.enc && latest.get(x.id))) return null;
    return live();
  }
  /* Over-provisioning report (VMware and Nutanix), computed from what the platforms reported - never estimated:
     - clusters / hosts: vCPU per physical core against the target, memory configured on running VMs against physical memory
       and against the memory target, storage provisioned against capacity (vSphere datastores: used + uncommitted; Nutanix:
       the VMs' configured disks against the cluster's storage)
     - VMs: right-sizing from this server's own hourly samples (virt_vm_hist, up to 31 days). The 95th percentile is the basis,
       not the average, so a VM that is busy one hour a day keeps what it needs. A recommendation needs OP.min_samples samples;
       with fewer the VM is listed as "not enough history", never as oversized. A cut is at most half of what is configured in
       one step (change in steps, measure again). vSphere "memory in use" is active guest memory, which reads low - the page
       says so - and Nutanix guest memory needs NGT; without it the hypervisor figure is used.
     - powered-off VMs: memory and disk they still hold. */
  const OP = { cpu_target_pct: 70, mem_target_pct: 80, min_samples: 72, under_pct: 90 };
  function pct95(a) { const v = a.filter((x) => x != null && Number.isFinite(x)).sort((x, y) => x - y); if (!v.length) return null; return v[Math.min(v.length - 1, Math.ceil(v.length * 0.95) - 1)]; }
  function overprov(q = {}) {
    const days = Math.min(VM_HIST_DAYS, Math.max(1, Math.round(Number(q.days) || 30))), since = now() - days * DAY, R = report(), st = R.settings;
    const samp = new Map();   // pid|vm -> {cpu:[], mem:[], first, n}
    for (const h of vmHist.all((x) => x.at >= since)) for (const [id, r] of Object.entries(h.v || {})) {
      const k = h.pid + '|' + id, o = samp.get(k) || { cpu: [], mem: [], first: h.at, n: 0 };
      o.cpu.push(r[0]); o.mem.push(r[1]); o.n++; if (h.at < o.first) o.first = h.at; samp.set(k, o);
    }
    const r1 = (v) => (v == null ? null : Math.round(v * 10) / 10);
    const vms = [], under = [], short = [];
    let save_vcpu = 0, save_mem = 0;
    for (const v of R.vms) {
      if (v.power !== 'on') continue;
      const o = samp.get(v.pid + '|' + v.id), base = { platform: v.platform, pid: v.pid, kind: v.kind, cluster: v.cluster, host: v.host, id: v.id, name: v.name, vcpus: v.vcpus, mem_gb: v.mem_gb };
      if (!o || o.n < OP.min_samples) { short.push(Object.assign(base, { samples: o ? o.n : 0 })); continue; }
      const c95 = pct95(o.cpu), m95 = pct95(o.mem), cmax = o.cpu.reduce((a, x) => (x != null && x > a ? x : a), 0);
      const row = Object.assign(base, { samples: o.n, history_days: r1((now() - o.first) / DAY), cpu_p95: r1(c95), cpu_max: r1(cmax), mem_p95: r1(m95) });
      if (v.vcpus && c95 != null) {
        const need = Math.max(1, Math.ceil(v.vcpus * c95 / OP.cpu_target_pct)), to = Math.max(need, Math.ceil(v.vcpus / 2));
        if (to < v.vcpus) { row.vcpus_to = to; row.save_vcpu = v.vcpus - to; }
        if (c95 >= OP.under_pct) row.cpu_short = true;
      }
      if (v.mem_gb && m95 != null) {
        const need = Math.max(2, Math.ceil(v.mem_gb * m95 / OP.mem_target_pct)), to = Math.max(need, Math.ceil(v.mem_gb / 2));
        if (to <= v.mem_gb - 2) { row.mem_to = to; row.save_mem_gb = r1(v.mem_gb - to); }
        if (m95 >= OP.under_pct) row.mem_short = true;
      }
      if (row.save_vcpu || row.save_mem_gb) { vms.push(row); save_vcpu += row.save_vcpu || 0; save_mem += row.save_mem_gb || 0; }
      if (row.cpu_short || row.mem_short) under.push(row);
    }
    vms.sort((a, b) => (b.save_mem_gb || 0) - (a.save_mem_gb || 0) || (b.save_vcpu || 0) - (a.save_vcpu || 0));
    const lvl = (v, warn, bad) => (v == null ? null : v > bad ? 'over' : v > warn ? 'near' : 'ok');
    const byCl = new Map(); for (const v of R.vms) { const k = v.platform + '|' + v.cluster, o = byCl.get(k) || { prov: 0, known: 0 }; if (v.disk_prov_gb != null) { o.prov += v.disk_prov_gb; o.known++; } byCl.set(k, o); }
    const clusters = R.clusters.map((c) => {
      const d = byCl.get(c.platform + '|' + c.name) || { prov: 0, known: 0 };
      const sp = c.kind === 'nutanix' && c.storage_gb ? r1(d.prov / c.storage_gb * 100) : null;
      return { platform: c.platform, kind: c.kind, cluster: c.name, hosts: c.hosts_up, cores: c.cores, vcpus: c.vcpus, vcpu_ratio: c.vcpu_ratio, vcpu_target: st.vcpu_ratio, cpu: lvl(c.vcpu_ratio, st.vcpu_ratio * 0.85, st.vcpu_ratio),
        mem_gb: c.mem_gb, vm_mem_gb: c.vm_mem_gb, mem_alloc_pct: c.mem_alloc_pct, mem_used_pct: c.mem_used_pct, mem: lvl(c.mem_alloc_pct, st.mem_max_pct, 100),
        storage_gb: c.kind === 'nutanix' ? c.storage_gb : null, disk_prov_gb: c.kind === 'nutanix' ? r1(d.prov) : null, storage_prov_pct: sp, storage: lvl(sp, 90, 100),
        n_plus_1: c.n_plus_1, cores_after_n1: c.cores_after_n1, vcpu_ratio_n1: c.cores_after_n1 ? Math.round(c.vcpus / c.cores_after_n1 * 100) / 100 : null };
    });
    const datastores = R.datastores.map((d) => ({ platform: d.platform, name: d.name, type: d.type, capacity_gb: d.capacity_gb, free_gb: d.free_gb, used_pct: d.used_pct, provisioned_pct: d.provisioned_pct,
      provisioned_gb: d.provisioned_pct != null && d.capacity_gb ? Math.round(d.capacity_gb * d.provisioned_pct / 100) : null, storage: lvl(d.provisioned_pct, 90, 100) }));
    const hosts = R.hosts.map((h) => ({ platform: h.platform, cluster: h.cluster, name: h.name, cores: h.cores, vcpus: h.vcpus, vcpu_ratio: h.vcpu_ratio, mem_gb: h.mem_gb, vm_mem_gb: h.vm_mem_gb,
      mem_alloc_pct: h.mem_gb && h.vm_mem_gb != null ? r1(h.vm_mem_gb / h.mem_gb * 100) : null, cpu: lvl(h.vcpu_ratio, st.vcpu_ratio * 0.85, st.vcpu_ratio) }));
    const off = R.vms.filter((v) => v.power !== 'on').map((v) => ({ platform: v.platform, pid: v.pid, kind: v.kind, cluster: v.cluster, id: v.id, name: v.name, vcpus: v.vcpus, mem_gb: v.mem_gb, disk_gb: v.disk_gb, disk_prov_gb: v.disk_prov_gb }))
      .sort((a, b) => (b.mem_gb || 0) - (a.mem_gb || 0));
    return { at: new Date(now()).toISOString(), days, basis: Object.assign({}, OP, { vcpu_ratio: st.vcpu_ratio, mem_max_pct: st.mem_max_pct }), platforms: R.platforms.map((p) => ({ id: p.id, label: p.label, kind: p.kind, site: p.site || '' })),
      clusters, hosts, datastores, vms, under, short, off,
      totals: { vms_to_resize: vms.length, save_vcpu, save_mem_gb: r1(save_mem), under: under.length, short_history: short.length, off: off.length, off_mem_gb: r1(off.reduce((a, v) => a + (v.mem_gb || 0), 0)), off_disk_gb: off.reduce((a, v) => a + (v.disk_prov_gb != null ? v.disk_prov_gb : v.disk_gb || 0), 0),
        clusters_over_cpu: clusters.filter((c) => c.cpu === 'over').length, clusters_over_mem: clusters.filter((c) => c.mem === 'over').length, storage_over: clusters.filter((c) => c.storage === 'over').length + datastores.filter((d) => d.storage === 'over').length } };
  }
  // baseline hardening facts for every vCenter / ESXi / Nutanix connection (Baseline Hardening page reads them): one
  // read-only pass, kept per platform in virt_hardening; a platform that fails keeps its last facts with the error beside them
  const hardCol = store.collection('virt_hardening');
  let hardening = null;
  async function hardeningRead(who = SYS) {
    if (hardening) return hardening;
    hardening = (async () => {
      const res = [];
      for (const p of sources().filter((x) => x.enc).concat(plats.all((x) => x.kind === 'proxmox' && x.enc).map((x) => Object.assign({}, x, { origin: 'virtualization' })))) {
        const at = new Date(now()).toISOString(), out = { platform_id: p.id, label: p.label, kind: p.kind, at, ok: true };
        if (p.kind === 'proxmox') {   // Proxmox VE: the read-only API token (discovery/methods/proxmox.js hardening)
          try {
            const r = await withCred(p, (target, secret) => require('./discovery/methods/proxmox').hardening({ target, secret }, { request: opts.request }));
            hardCol.put({ id: p.id, kind: 'proxmox', label: p.label, at, error: null, hosts: r.nodes, cluster: { version: r.version, firewall: r.cluster_firewall, realms: r.realms, users: r.users, tfa: r.tfa, backup_jobs: r.backup_jobs } });
            out.hosts = r.nodes.length;
          } catch (e) {
            out.ok = false; out.error = String(e.message || e).slice(0, 300);
            const prev = hardCol.get(p.id); hardCol.put(Object.assign({ id: p.id, kind: 'proxmox', label: p.label, hosts: [] }, prev || {}, { error: out.error, error_at: at }));
          }
          res.push(out); continue;
        }
        try {
          const vc = p.kind === 'vcenter' || p.kind === 'esxi';
          const r = await withCred(p, (target, secret) => (vc ? vcSoap(target, secret, { request: opts.request }).hostHardening() : ntxClient(target, secret, { request: opts.request }).hardening()));
          hardCol.put({ id: p.id, kind: vc ? 'esxi' : 'nutanix', label: p.label, at, error: null, hosts: vc ? r : r.hosts, cluster: vc ? null : r.cluster, auth: vc ? null : r.auth, syslog: vc ? null : r.syslog });
          out.hosts = (vc ? r : r.hosts).length;
        } catch (e) {
          out.ok = false; out.error = String(e.message || e).slice(0, 300);
          const prev = hardCol.get(p.id); hardCol.put(Object.assign({ id: p.id, kind: p.kind === 'nutanix' ? 'nutanix' : 'esxi', label: p.label, hosts: [] }, prev || {}, { error: out.error, error_at: at }));
          if (app.log && app.log.every) app.log.every('virt-hardening:' + p.id, 3600000, 'warn', 'virt: hardening read failed', { platform: p.label, err: out.error });
        }
        res.push(out);
      }
      cfgCol.put({ id: 'last_hardening', value: { at: new Date(now()).toISOString(), results: res } });
      if (who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.hardening.read', target: 'virtualization', detail: res.map((r) => ({ label: r.label, ok: r.ok, hosts: r.hosts, error: r.error })) });
      return res;
    })().finally(() => { hardening = null; });
    return hardening;
  }
  const hardeningFacts = () => hardCol.all(() => true);
  // virtual networking for the Virtual Network Map (virt-network.js): one read per platform, the same logins, read-only
  const netCol = store.collection('virt_network');
  let netting = null;
  async function networkRead(who = SYS) {
    if (netting) return netting;
    netting = (async () => {
      const res = [];
      for (const p of sources().filter((x) => x.enc)) {
        const at = new Date(now()).toISOString(), vc = p.kind === 'vcenter' || p.kind === 'esxi', out = { platform_id: p.id, label: p.label, kind: vc ? 'vsphere' : 'nutanix', at, ok: true };
        try {
          const r = await withCred(p, (target, secret) => (vc ? vcSoap(target, secret, { request: opts.request }) : ntxClient(target, secret, { request: opts.request })).network());
          netCol.put(Object.assign({ id: p.id, label: p.label, site: p.site || '', at, error: null }, r));
          out.hosts = r.hosts.length; out.vms = r.vms.length; out.read_errors = r.read_errors.length;
        } catch (e) {
          out.ok = false; out.error = String(e.message || e).slice(0, 300);
          const prev = netCol.get(p.id); netCol.put(Object.assign({ id: p.id, label: p.label, kind: out.kind, hosts: [], vms: [], networks: [], clusters: [], dvs: [], read_errors: [] }, prev || {}, { error: out.error, error_at: at }));
          if (app.log && app.log.every) app.log.every('virt-network:' + p.id, 3600000, 'warn', 'virt: network read failed', { platform: p.label, err: out.error });
        }
        res.push(out);
      }
      cfgCol.put({ id: 'last_network', value: { at: new Date(now()).toISOString(), results: res } });
      if (who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.network.read', target: 'virtualization', detail: res.map((r) => ({ label: r.label, ok: r.ok, hosts: r.hosts, error: r.error })) });
      return res;
    })().finally(() => { netting = null; });
    return netting;
  }
  const networkFacts = () => netCol.all(() => true);
  const networkSources = () => sources().map((p) => ({ id: p.id, label: p.label, kind: p.kind, has_login: !!p.enc }));
  return { run, live, liveTick, report, settings, setSettings, tick, trend, fromVcenter, vmHistory, overprov, collectPlatform, vmAddrLookup, hardeningRead, hardeningFacts, networkRead, networkFacts, networkSources };
}

function registerVirtCapacity(srv, app) {
  const C = createVirtCapacity(app);
  (app.addons = app.addons || {}).virtCapacity = C;
  srv.route('GET', '/virt/capacity', (ctx) => void ctx.need('viewer') || C.report());
  srv.route('GET', '/virt/capacity/vm-history', (ctx) => void ctx.need('viewer') || C.vmHistory(ctx.query || {}));
  srv.route('GET', '/virt/capacity/overprovisioning', (ctx) => void ctx.need('viewer') || C.overprov(ctx.query || {}));
  srv.route('POST', '/virt/capacity/run', async (ctx) => { ctx.need('admin'); return { results: await C.run(ctx.who), report: C.report() }; });
  srv.route('POST', '/virt/capacity/live', async (ctx) => { ctx.need('operator'); return { results: await C.live(ctx.who), report: C.report() }; });
  srv.route('POST', '/virt/capacity/settings', (ctx) => { ctx.need('admin'); return C.setSettings(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'virt-capacity.tick', () => C.tick()), 150000), t2 = setInterval(guardOf(app, 'virt-capacity.tick', () => C.tick()), 60000), t3 = setInterval(guardOf(app, 'virt-capacity.live', () => C.liveTick()), 15000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref(); if (t3.unref) t3.unref();
  return C;
}

module.exports = { createVirtCapacity, registerVirtCapacity, vcSoap, ntxClient, fromVcenter, mgmtNic, vmkNics, guestIps, PROPS, SOAP_OK, NTX_OK };
