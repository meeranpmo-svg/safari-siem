// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Standalone VMware ESXi host (no vCenter) for the Virtualization page - STRICTLY READ ONLY.
 * ESXi has no vSphere Automation REST API (/api/vcenter/...), which is why methods/vcenter.js cannot read it; it does speak
 * the same vSphere Web Services (SOAP, https://<host>/sdk) as vCenter. The client is virt-capacity.js's vcSoap, whose
 * SOAP_OK allow-list refuses every method that could change anything (only RetrieveServiceContent, Login,
 * CreateContainerView, RetrievePropertiesEx / Continue, DestroyView, Logout are sent). Use a local ESXi account with the
 * Read-only role (Host → Permissions), not root.
 *   collect(cred, {request?}) → {ok, hosts[{id, name, state, ip}], vms[{id, name, host_id, host_name, power_state, guest_os,
 *                                 hostname, ips[], macs[], uuid}]} | {ok:false, error_class, error}   (same shape as vcenter.js)
 *   test(cred) → diag result (an untrusted self-signed certificate is captured for Trust & pin, never trusted silently)
 */
const diag = require('../diag');

const V = () => require('../../virt-capacity');   // required lazily: virt-capacity.js loads discovery modules itself
const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return ''; } };

async function read(cred, o) { const M = V(); return M.fromVcenter(await M.vcSoap(cred.target || {}, cred.secret || {}, o).collect()); }

async function collect(cred, o = {}) {
  const t0 = Date.now();
  try {
    const m = await read(cred, o), addr = hostOf((cred.target || {}).base_url);
    // a standalone host often calls itself localhost.localdomain: name it by the address it was added with
    const name = (h) => (m.hosts.length === 1 && (!h.name || /^localhost(\.|$)/i.test(h.name)) ? addr : h.name);
    const hn = new Map(m.hosts.map((h) => [h.id, name(h)]));
    return { ok: true, latency_ms: Date.now() - t0,
      // a standalone host IS the address it was added with: when it did not report its vmk address (a read-only role often
      // cannot read Host.Config), that address is its management IP - never used for its VMs
      hosts: m.hosts.map((h) => ({ id: h.id, name: name(h), state: h.state, ip: h.ip || (m.hosts.length === 1 && IP4.test(addr) ? addr : null) })),
      vms: m.vms.map((v) => ({ id: v.id, name: v.name, host_id: v.host_id, host_name: hn.get(v.host_id) || '', power_state: v.power, guest_os: v.guest_os, hostname: v.name, ips: Array.isArray(v.ips) ? v.ips : [], macs: [], uuid: v.uuid || null })) };
  } catch (e) {
    return { ok: false, error_class: ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e.code) ? e.code : 'protocol', error: String(e.message || e).slice(0, 200), latency_ms: Date.now() - t0 };
  }
}

async function test(cred, o = {}) {
  const t0 = Date.now(), pin = !!(cred.target && cred.target.tls_fingerprint);
  try {
    const m = await read(cred, Object.assign({ captureUntrusted: true }, o));
    return diag.result('esxi', { latency_ms: Date.now() - t0, pin, http: 200, discovered: { hosts: m.hosts.length, vms: m.vms.length } });
  } catch (e) {
    return diag.fromError('esxi', e, { latency_ms: Date.now() - t0, pin });
  }
}

module.exports = { collect, test };
