// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * VMware vCenter inventory for discovery — STRICTLY READ ONLY (guard pattern from sentra-infra engine/vcenter/client.js).
 * The only non-GET requests are our own session login (POST /api/session, Basic auth) and logout (DELETE /api/session).
 * Every inventory call is a GET under /api/vcenter/; anything else is refused by guard() before a socket is opened.
 *
 *   collect(cred, {request?}) → {ok, hosts[{id, name, state, ip}], vms[{id, name, host_id, host_name, power_state, guest_os,
 *                                 hostname, ips[], macs[], uuid}]} | {ok:false, error_class}
 *   test(cred) → {ok, latency_ms} | {ok:false, error_class}
 * Paths (vSphere Automation REST 7.0U2+/8.0): /api/vcenter/host, /api/vcenter/vm?hosts=<id>, /api/vcenter/vm/<id>,
 * /api/vcenter/vm/<id>/guest/networking/interfaces and /guest/identity (both need VMware Tools — "verify"; read best-effort).
 */
const httpc = require('../httpc');
const diag = require('../diag');

const SESSION = '/api/session';
const READ_PREFIX = '/api/vcenter/';
const unwrap = (j) => (j && typeof j === 'object' && !Array.isArray(j) && 'value' in j ? j.value : j);
const list = (j) => { const v = unwrap(j); return Array.isArray(v) ? v : []; };
const POWER = { POWERED_ON: 'on', POWERED_OFF: 'off', SUSPENDED: 'suspended' };

function guard(method, path) {
  if (method === 'GET' && path.startsWith(READ_PREFIX)) return;
  if ((method === 'POST' || method === 'DELETE') && path === SESSION) return;
  throw Object.assign(new Error(`vcenter discovery is read-only; refusing ${method} ${path}`), { code: 'config' });
}

function errorClass(e) { return ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol'; }

function createClient(cred, o = {}) {
  const t = cred.target || {};
  const base = String(t.base_url || '').replace(/\/+$/, '');
  const req = o.request || httpc.request;
  let sid = null;
  async function call(method, path, headers = {}) {
    guard(method, path);
    const h = Object.assign({ Accept: 'application/json' }, headers);
    if (sid) h['vmware-api-session-id'] = sid;
    return req(base + path, { method, headers: h, body: method === 'POST' ? '' : null, caFile: t.ca_file, pin: t.tls_fingerprint, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 30000 });
  }
  // TLS succeeded once we have a response; mark auth/authz/protocol errors from here as trusted (stage after TLS).
  async function login() {
    const r = await call('POST', SESSION, { Authorization: 'Basic ' + Buffer.from(`${cred.secret.username}:${cred.secret.password}`).toString('base64') });
    if (r.status === 401 || r.status === 403) throw diag.err('auth', 'vCenter rejected the credentials', { stage: 'auth', http: r.status, tlsTrusted: true });
    if (r.status < 200 || r.status >= 300) throw diag.err('protocol', `vCenter session failed (HTTP ${r.status})`, { stage: 'auth', http: r.status, tlsTrusted: true });
    const id = typeof r.json === 'string' ? r.json : unwrap(r.json);
    if (!id || typeof id !== 'string') throw diag.err('protocol', 'vCenter returned no session id', { stage: 'auth', tlsTrusted: true });
    sid = id;
  }
  async function get(path) {
    const r = await call('GET', path);
    if (r.status === 401 || r.status === 403) throw diag.err('authz', `authenticated but not authorised for ${path}`, { stage: 'authz', http: r.status, tlsTrusted: true });
    if (r.status < 200 || r.status >= 300) throw diag.err('protocol', `GET ${path}: HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
    return r.json;
  }
  const tryGet = (path) => get(path).catch(() => null);
  async function logout() { if (!sid) return; try { await call('DELETE', SESSION); } catch { /* best effort */ } sid = null; }
  return { login, logout, get, tryGet };
}

function nicMacs(detail) {
  const n = detail && detail.nics;
  const vals = Array.isArray(n) ? n.map((x) => (x && x.value) || x) : n && typeof n === 'object' ? Object.values(n) : [];
  return vals.map((x) => x && x.mac_address).filter(Boolean).map((m) => String(m).toLowerCase());
}
function guestIps(ifaces) {
  const out = []; const macs = [];
  for (const i of list(ifaces)) {
    if (i && i.mac_address) macs.push(String(i.mac_address).toLowerCase());
    for (const a of (i && i.ip && i.ip.ip_addresses) || []) if (a && /^\d{1,3}(\.\d{1,3}){3}$/.test(a.ip_address || '')) out.push(a.ip_address);
  }
  return { ips: out, macs };
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  const c = createClient(cred, o);
  try {
    await c.login();
    const hosts = list(await c.get('/api/vcenter/host')).map((h) => ({ id: String(h.host || h.id || ''), name: h.name || null, state: String(h.connection_state || '').toLowerCase() || null }));
    // the REST host list has no address: each host's management VMkernel IP comes from the read-only vSphere SOAP reader
    // (virt-capacity.js, allow-listed methods only). A role that cannot read host networking simply leaves it empty.
    if (hosts.length && o.hostIps !== false) {
      try {
        const addr = await require('../../virt-capacity').vcSoap(cred.target || {}, cred.secret || {}, { request: o.request }).hostAddresses();
        const byId = new Map(addr.map((a) => [a.id, a])), byName = new Map(addr.map((a) => [String(a.name).toLowerCase(), a]));
        for (const h of hosts) { const a = byId.get(h.id) || byName.get(String(h.name || '').toLowerCase()); if (a && a.ip) { h.ip = a.ip; h.vmk = a.vmk; } }
      } catch (e) { /* addresses stay empty - DNS is the fallback */ }
    }
    const vms = []; const seen = new Set();
    const max = o.maxVms || 5000;
    for (const h of hosts) {
      const hv = list(await c.get(`/api/vcenter/vm?hosts=${encodeURIComponent(h.id)}`));
      for (const v of hv) {
        const id = String(v.vm || v.id || '');
        if (!id || seen.has(id) || vms.length >= max) continue;
        seen.add(id);
        const detail = unwrap(await c.tryGet(`/api/vcenter/vm/${encodeURIComponent(id)}`)) || {};
        const ifs = await c.tryGet(`/api/vcenter/vm/${encodeURIComponent(id)}/guest/networking/interfaces`);
        const ident = unwrap(await c.tryGet(`/api/vcenter/vm/${encodeURIComponent(id)}/guest/identity`)) || {};
        const g = guestIps(ifs);
        const macs = [...new Set(nicMacs(detail).concat(g.macs))];
        const ips = [...new Set(g.ips.concat(ident.ip_address && /^\d{1,3}(\.\d{1,3}){3}$/.test(ident.ip_address) ? [ident.ip_address] : []))];
        vms.push({
          id, name: v.name || detail.name || null, host_id: h.id, host_name: h.name,
          power_state: POWER[String(v.power_state || detail.power_state || '').toUpperCase()] || null,
          guest_os: (ident.full_name && (ident.full_name.default_message || ident.full_name)) || detail.guest_OS || v.guest_OS || null,
          hostname: ident.host_name || null, ips, macs,
          uuid: (detail.identity && detail.identity.instance_uuid) || null,
        });
      }
    }
    return { ok: true, hosts, vms, latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; } finally { await c.logout(); }
}

// Classified connection test for the vault + Connect Wizard. captureUntrusted defaults ON here so an untrusted
// self-signed certificate is captured (subject/issuer/validity/fingerprint256) for Trust & pin — never silently trusted.
async function test(cred, o = {}) {
  const t0 = Date.now();
  const pin = !!(cred.target && cred.target.tls_fingerprint);
  const c = createClient(cred, Object.assign({ captureUntrusted: true }, o));
  try {
    await c.login();
    const hosts = list(await c.get('/api/vcenter/host'));
    return diag.result('vcenter', { latency_ms: Date.now() - t0, pin, http: 200, discovered: { hosts: hosts.length } });
  } catch (e) {
    return diag.fromError('vcenter', e, { latency_ms: Date.now() - t0, pin });
  } finally { await c.logout(); }
}

module.exports = { collect, test, guard, createClient, nicMacs, guestIps };
