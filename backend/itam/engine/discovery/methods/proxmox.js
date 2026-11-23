// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Proxmox VE - STRICTLY READ ONLY, with an API token (Datacenter > Permissions > API Tokens; give the token the built-in
 * PVEAuditor role on "/", privilege separation on). The token id goes in the user name field (user@realm!tokenid), the
 * secret in the password field; it travels only in the Authorization header (PVEAPIToken=...). Only GET, and only the paths
 * in READ_OK - anything else is refused before a socket is opened.
 *   collect(cred) -> {ok, hosts[{id, name, ip, state}], vms[{id, name, host_id, host_name, power_state, kind, vcpus, memory_mb}]}
 *   test(cred)    -> classified connection test (diag)
 *   hardening(cred) -> {version, cluster_firewall, nodes[{name, ip, firewall, updates, certs, subscription}], realms, users, tfa, backup_jobs}
 *                      each part null when the token may not read it ("not checked" on Baseline Hardening, never a pass)
 */
const httpc = require('../httpc');
const diag = require('../diag');

const NODE = '[A-Za-z0-9][A-Za-z0-9._-]{0,62}';
const READ_OK = [/^\/api2\/json\/(version|nodes|cluster\/status|cluster\/firewall\/options|cluster\/backup|access\/domains|access\/tfa)$/, /^\/api2\/json\/cluster\/resources\?type=vm$/,
  /^\/api2\/json\/access\/users\?full=1$/, new RegExp(`^/api2/json/nodes/${NODE}/(firewall/options|apt/update|certificates/info|subscription)$`)];
const MAX_VMS = 5000;

function guard(method, path) {
  if (method === 'GET' && READ_OK.some((re) => re.test(path))) return;
  throw Object.assign(new Error(`Proxmox is read-only; refusing ${method} ${path}`), { code: 'config' });
}

function createClient(cred, o = {}) {
  const t = cred.target || {}, base = String(t.base_url || '').replace(/\/+$/, ''), req = o.request || httpc.request;
  const auth = `PVEAPIToken=${cred.secret.username}=${cred.secret.password}`;
  async function get(path) {
    guard('GET', path);
    const r = await req(base + path, { method: 'GET', headers: { Accept: 'application/json', Authorization: auth }, body: null, caFile: t.ca_file, pin: t.tls_fingerprint, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 30000 });
    if (r.status === 401) throw diag.err('auth', 'Proxmox rejected the API token', { stage: 'auth', http: 401, tlsTrusted: true });
    if (r.status === 403) throw diag.err('authz', `the API token may not read ${path.split('?')[0]}`, { stage: 'authz', http: 403, tlsTrusted: true });
    if (r.status < 200 || r.status >= 300) throw diag.err('protocol', `GET ${path.split('?')[0]}: HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
    return r.json && 'data' in r.json ? r.json.data : null;
  }
  const tryGet = (path) => get(path).catch(() => undefined);   // undefined = not readable, kept apart from an empty answer
  return { get, tryGet };
}

const IP4 = /^\d{1,3}(\.\d{1,3}){3}$/;
async function nodesOf(c) {
  const st = await c.tryGet('/api2/json/cluster/status'), byName = new Map();
  for (const x of Array.isArray(st) ? st : []) if (x && x.type === 'node' && x.name) byName.set(x.name, IP4.test(x.ip || '') ? x.ip : null);
  const nodes = (await c.get('/api2/json/nodes')) || [];
  return nodes.map((n) => ({ id: String(n.node), name: String(n.node), ip: byName.get(n.node) || null, state: String(n.status || '').toLowerCase() === 'online' ? 'connected' : String(n.status || 'unknown') }));
}

async function collect(cred, o = {}) {
  const t0 = Date.now(), c = createClient(cred, o);
  try {
    const hosts = await nodesOf(c);
    const res = (await c.tryGet('/api2/json/cluster/resources?type=vm')) || [];
    const vms = (Array.isArray(res) ? res : []).filter((v) => v && v.vmid != null && !v.template).slice(0, MAX_VMS).map((v) => ({ id: String(v.vmid), name: String(v.name || 'vm-' + v.vmid), host_id: String(v.node || ''), host_name: String(v.node || ''),
      power_state: v.status === 'running' ? 'on' : v.status === 'stopped' ? 'off' : String(v.status || ''), kind: v.type === 'lxc' ? 'container' : 'vm', vcpus: Number(v.maxcpu) || null, memory_mb: v.maxmem ? Math.round(Number(v.maxmem) / 1048576) : null, ips: [], macs: [] }));
    return { ok: true, hosts, vms, latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol', error: e.message, latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now(), pin = !!(cred.target && cred.target.tls_fingerprint), c = createClient(cred, Object.assign({ captureUntrusted: true }, o));
  try {
    const v = await c.get('/api2/json/version'), n = await c.get('/api2/json/nodes');
    return diag.result('proxmox', { latency_ms: Date.now() - t0, pin, http: 200, discovered: { hosts: (n || []).length, version: v && v.version } });
  } catch (e) { return diag.fromError('proxmox', e, { latency_ms: Date.now() - t0, pin }); }
}

async function hardening(cred, o = {}) {
  const c = createClient(cred, o);
  const ver = await c.get('/api2/json/version'), nodes = await nodesOf(c);
  const fw = await c.tryGet('/api2/json/cluster/firewall/options');
  const out = { version: ver ? String(ver.version || '') : null, cluster_firewall: fw === undefined ? null : { enable: !!(fw && Number(fw.enable)), policy_in: fw && fw.policy_in ? String(fw.policy_in) : null },
    realms: null, users: null, tfa: null, backup_jobs: null, nodes: [] };
  const dom = await c.tryGet('/api2/json/access/domains');
  if (Array.isArray(dom)) out.realms = dom.map((d) => ({ realm: String(d.realm), type: String(d.type) }));
  const us = await c.tryGet('/api2/json/access/users?full=1');
  if (Array.isArray(us)) out.users = us.slice(0, 500).map((u) => ({ userid: String(u.userid), enable: u.enable === undefined ? true : !!Number(u.enable) }));
  const tfa = await c.tryGet('/api2/json/access/tfa');
  if (Array.isArray(tfa)) out.tfa = tfa.filter((x) => x && Array.isArray(x.entries) && x.entries.some((e) => e && e.enable !== 0 && e.enable !== false)).map((x) => String(x.userid));
  const bj = await c.tryGet('/api2/json/cluster/backup');
  if (Array.isArray(bj)) out.backup_jobs = bj.filter((j) => j && (j.enabled === undefined || Number(j.enabled))).length;
  for (const n of nodes.slice(0, 64)) {
    const nf = await c.tryGet(`/api2/json/nodes/${encodeURIComponent(n.name)}/firewall/options`), up = await c.tryGet(`/api2/json/nodes/${encodeURIComponent(n.name)}/apt/update`);
    const ce = await c.tryGet(`/api2/json/nodes/${encodeURIComponent(n.name)}/certificates/info`), su = await c.tryGet(`/api2/json/nodes/${encodeURIComponent(n.name)}/subscription`);
    out.nodes.push({ id: n.id, name: n.name, ip: n.ip, firewall: nf === undefined ? null : !!(nf && Number(nf.enable)), updates: Array.isArray(up) ? up.length : null,
      certs: Array.isArray(ce) ? ce.map((x) => ({ file: String(x.filename || ''), issuer: String(x.issuer || '').slice(0, 200), subject: String(x.subject || '').slice(0, 200), notafter: Number(x.notafter) || null })) : null,
      subscription: su === undefined ? null : String((su && su.status) || 'unknown') });
  }
  return out;
}

module.exports = { collect, test, hardening, guard, READ_OK };
