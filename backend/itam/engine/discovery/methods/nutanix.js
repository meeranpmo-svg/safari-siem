// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Nutanix Prism inventory for discovery — STRICTLY READ ONLY.
 *   Prism Central (v3 API): POST /api/nutanix/v3/{hosts,vms,clusters}/list — "list" calls are POSTs by API design but
 *   only read. Prism Element (v2 API, fallback when the address is a cluster, not Prism Central): GET
 *   /PrismGateway/services/rest/v2.0/{hosts,vms,cluster}. guard() refuses every other method / path before a socket opens.
 *   Basic auth on every call (Prism has no session to log out of). Port 9440 when the URL gives none.
 *
 *   collect(cred, {request?}) → {ok, api: 'v3'|'v2', clusters[{id, name, version}],
 *       hosts[{id, name, ip, cvm_ip, ipmi_ip, cluster, sockets, cores, cores_per_socket, cpu_model, serial, model, hypervisor}],
 *       vms[{id, name, host_id, host_name, cluster, power_state, vcpus, memory_mb, ips[], macs[]}]} | {ok:false, error_class}
 *   test(cred) → diag result (captures an untrusted self-signed certificate for Trust & pin, like vCenter)
 * cred = {target: {base_url, ca_file?, tls_fingerprint?}, secret: {username, password}}. A read-only "Viewer" (Prism
 * Central) or "Viewer" cluster role is enough.
 */
const httpc = require('../httpc');
const diag = require('../diag');
if (diag.SYS && !diag.SYS.nutanix) diag.SYS.nutanix = 'Nutanix Prism';   // name used in the test messages

const V3 = /^\/api\/nutanix\/v3\/(hosts|vms|clusters)\/list$/;
const V2 = /^\/PrismGateway\/services\/rest\/v2\.0\/(hosts|vms|cluster)(\?[A-Za-z0-9_=&]*)?$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const POWER = { on: 'on', off: 'off', paused: 'suspended', suspended: 'suspended' };

function guard(method, path) {
  if (method === 'POST' && V3.test(path)) return;
  if (method === 'GET' && V2.test(path)) return;
  throw Object.assign(new Error(`nutanix discovery is read-only; refusing ${method} ${path}`), { code: 'config' });
}
function errorClass(e) { return ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol'; }
function baseOf(url) {
  let b = String(url || '').trim().replace(/\/+$/, '');
  if (!/^https:\/\//i.test(b)) throw Object.assign(new Error('Prism URL must start with https://'), { code: 'config' });
  try { const u = new URL(b); if (!u.port) b = `${u.protocol}//${u.hostname}:9440${u.pathname.replace(/\/+$/, '')}`; } catch { throw Object.assign(new Error('invalid Prism URL'), { code: 'config' }); }
  return b;
}

function createClient(cred, o = {}) {
  const t = cred.target || {};
  const base = baseOf(t.base_url);
  const req = o.request || httpc.request;
  const auth = 'Basic ' + Buffer.from(`${cred.secret.username}:${cred.secret.password}`).toString('base64');
  async function call(method, path, body) {
    guard(method, path);
    const r = await req(base + path, { method, headers: Object.assign({ Accept: 'application/json', Authorization: auth }, body ? { 'Content-Type': 'application/json' } : {}),
      body: body ? JSON.stringify(body) : null, caFile: t.ca_file, pin: t.tls_fingerprint, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 30000 });
    if (r.status === 401) throw diag.err('auth', 'Prism rejected the credentials', { stage: 'auth', http: r.status, tlsTrusted: true });
    if (r.status === 403) throw diag.err('authz', `authenticated but not authorised for ${path}`, { stage: 'authz', http: r.status, tlsTrusted: true });
    return r;
  }
  // v3 list with paging (length 500)
  async function list3(kind, max) {
    const out = [];
    for (let offset = 0; offset < max; offset += 500) {
      const r = await call('POST', `/api/nutanix/v3/${kind}s/list`, { kind, length: 500, offset });
      if (r.status === 404) { const e = diag.err('protocol', 'not Prism Central', { stage: 'read', http: 404, tlsTrusted: true }); e.notPc = true; throw e; }
      if (r.status < 200 || r.status >= 300) throw diag.err('protocol', `${kind} list: HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
      const ents = (r.json && r.json.entities) || [];
      out.push(...ents);
      const total = r.json && r.json.metadata && Number(r.json.metadata.total_matches);
      if (!ents.length || ents.length < 500 || (total && out.length >= total)) break;
    }
    return out;
  }
  async function get2(path) {
    const r = await call('GET', '/PrismGateway/services/rest/v2.0/' + path);
    if (r.status < 200 || r.status >= 300) throw diag.err('protocol', `GET ${path}: HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
    return r.json || {};
  }
  return { list3, get2 };
}

const n = (v) => { const x = Number(v); return Number.isFinite(x) && x > 0 ? Math.round(x) : null; };
const ip = (v) => (IPV4.test(String(v || '')) ? String(v) : null);

function fromV3(hostsRaw, vmsRaw, clustersRaw) {
  const clusters = clustersRaw.filter((c) => !((c.status && c.status.resources && c.status.resources.config && c.status.resources.config.service_list) || []).includes('PRISM_CENTRAL'))
    .map((c) => ({ id: (c.metadata && c.metadata.uuid) || '', name: (c.status && c.status.name) || (c.spec && c.spec.name) || '', version: ((((c.status || {}).resources || {}).config || {}).software_map || {}).NOS ? c.status.resources.config.software_map.NOS.version || null : null }));
  const hosts = hostsRaw.map((h) => {
    const s = h.status || {}, r = s.resources || {}, hv = r.hypervisor || {};
    const sockets = n(r.num_cpu_sockets), cores = n(r.num_cpu_cores);
    return { id: (h.metadata && h.metadata.uuid) || '', name: s.name || (h.spec && h.spec.name) || '', ip: ip(hv.ip), cvm_ip: ip(r.controller_vm && r.controller_vm.ip), ipmi_ip: ip(r.ipmi && r.ipmi.ip),
      cluster: (s.cluster_reference && s.cluster_reference.name) || '', sockets, cores, cores_per_socket: sockets && cores ? Math.round(cores / sockets) : null,
      cpu_model: r.cpu_model || null, serial: r.serial_number || null, model: (r.block && r.block.block_model) || null, hypervisor: hv.hypervisor_full_name || null };
  }).filter((h) => h.id && (h.ip || h.hypervisor || h.cluster || h.sockets || h.serial));   // Prism Central's own entry has none of these (a host without a reported hypervisor address is kept)
  const byHost = new Map(hosts.map((h) => [h.id, h]));
  const vms = vmsRaw.map((v) => {
    const s = v.status || {}, r = s.resources || {}, hr = r.host_reference || {}, macs = [], ips = [];
    for (const nic of r.nic_list || []) { if (nic.mac_address) macs.push(String(nic.mac_address).toLowerCase()); for (const e of nic.ip_endpoint_list || []) if (ip(e.ip)) ips.push(e.ip); }
    const h = byHost.get(hr.uuid);
    return { id: (v.metadata && v.metadata.uuid) || '', name: s.name || (v.spec && v.spec.name) || '', host_id: hr.uuid || null, host_name: hr.name || (h && h.name) || null,
      cluster: (s.cluster_reference && s.cluster_reference.name) || (h && h.cluster) || '', power_state: POWER[String(r.power_state || '').toLowerCase()] || null,
      vcpus: (n(r.num_sockets) || 1) * (n(r.num_vcpus_per_socket) || 1), memory_mb: n(r.memory_size_mib), ips: [...new Set(ips)], macs: [...new Set(macs)] };
  }).filter((v) => v.id);
  return { clusters, hosts, vms };
}

function fromV2(hostsJ, vmsJ, clusterJ) {
  const cname = (clusterJ && clusterJ.name) || '';
  const hosts = ((hostsJ && hostsJ.entities) || []).map((h) => {
    const sockets = n(h.num_cpu_sockets), cores = n(h.num_cpu_cores);
    return { id: h.uuid || '', name: h.name || '', ip: ip(h.hypervisor_address), cvm_ip: ip(h.service_vmexternal_ip), ipmi_ip: ip(h.ipmi_address), cluster: cname,
      sockets, cores, cores_per_socket: sockets && cores ? Math.round(cores / sockets) : null, cpu_model: h.cpu_model || null, serial: h.serial || null, model: h.block_model_name || null, hypervisor: h.hypervisor_full_name || null };
  }).filter((h) => h.id);
  const byHost = new Map(hosts.map((h) => [h.id, h]));
  const vms = ((vmsJ && vmsJ.entities) || []).map((v) => {
    const macs = [], ips = [];
    for (const nic of v.vm_nics || []) { if (nic.mac_address) macs.push(String(nic.mac_address).toLowerCase()); for (const a of [nic.ip_address].concat(nic.ip_addresses || [], nic.requested_ip_address || [])) if (ip(a)) ips.push(a); }
    const h = byHost.get(v.host_uuid);
    return { id: v.uuid || '', name: v.name || '', host_id: v.host_uuid || null, host_name: h ? h.name : null, cluster: cname, power_state: POWER[String(v.power_state || '').toLowerCase()] || null,
      vcpus: n(v.num_vcpus) ? n(v.num_vcpus) * (n(v.num_cores_per_vcpu) || 1) : null, memory_mb: n(v.memory_mb), ips: [...new Set(ips)], macs: [...new Set(macs)] };
  }).filter((v) => v.id);
  return { clusters: cname ? [{ id: (clusterJ && clusterJ.uuid) || '', name: cname, version: (clusterJ && clusterJ.version) || null }] : [], hosts, vms };
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  try {
    const c = createClient(cred, o);
    const max = o.maxVms || 10000;
    try {
      const [h, v, cl] = await Promise.all([c.list3('host', 2000), c.list3('vm', max), c.list3('cluster', 500)]);
      return Object.assign({ ok: true, api: 'v3', latency_ms: Date.now() - t0 }, fromV3(h, v, cl));
    } catch (e) {
      if (!e.notPc) throw e;
      const [h, v, cl] = await Promise.all([c.get2('hosts'), c.get2('vms?include_vm_nic_config=true'), c.get2('cluster')]);
      return Object.assign({ ok: true, api: 'v2', latency_ms: Date.now() - t0 }, fromV2(h, v, cl));
    }
  } catch (e) { return { ok: false, error_class: errorClass(e), error: String(e.message || '').slice(0, 200), latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now();
  const pin = !!(cred.target && cred.target.tls_fingerprint);
  try {
    const c = createClient(cred, Object.assign({ captureUntrusted: true }, o));
    let hosts;
    try { hosts = (await c.list3('host', 500)).length; } catch (e) { if (!e.notPc) throw e; hosts = ((await c.get2('hosts')).entities || []).length; }
    return diag.result('nutanix', { latency_ms: Date.now() - t0, pin, http: 200, discovered: { hosts } });
  } catch (e) { return diag.fromError('nutanix', e, { latency_ms: Date.now() - t0, pin }); }
}

module.exports = { collect, test, guard, fromV3, fromV2, baseOf };
