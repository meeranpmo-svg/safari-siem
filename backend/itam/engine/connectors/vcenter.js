// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only vSphere REST connector. Coordinates with the separate sentra-infra vCenter work: sentra-infra is not present
// in this workspace and no vcenter adapter was found to reuse, so this module is written here. If sentra-infra later
// ships engine/connectors/vcenter.js, converge on its session/parse shape and have one own the read.
//
// Flow (vSphere 7/8 REST): POST {base}/api/session (Basic auth) → session id; GET /api/vcenter/host and
// /api/vcenter/vm with header vmware-api-session-id. Older 6.7: /rest/com/vmware/cis/session + /rest/vcenter/*.
// This connector ONLY issues GETs after the session POST; it never powers VMs on/off or changes anything.
//
// Parsing is pure and separated from HTTP so tests run against captured fixtures with NO network.
const https = require('node:https');
const http = require('node:http');

// unwrap the 6.7 {"value": ...} envelope if present
const val = (j) => (j && typeof j === 'object' && 'value' in j && !Array.isArray(j) ? j.value : j);

function parseHosts(json) {
  const arr = Array.isArray(val(json)) ? val(json) : [];
  return arr.map((h) => ({
    source_id: String(h.host || h.host_id || h.name || ''),
    fields: {
      name: h.name || null, type: 'server', uuid: h.hardware_uuid || h.uuid || null,
      vendor: h.vendor || null, model: h.model || null,
      cpu: h.cpu_model || (h.cpu_count ? `${h.cpu_count} CPU` : null),
      mem_gb: h.memory_size_MiB ? Math.round(Number(h.memory_size_MiB) / 1024) : (h.memory_gb || null),
      os: h.product || h.esxi_version ? `VMware ESXi ${h.esxi_version || ''}`.trim() : null,
      networked: true, tags: ['vcenter', 'esxi-host'],
    },
    power: h.connection_state || h.power_state || null,
  }));
}

function parseVms(json) {
  const arr = Array.isArray(val(json)) ? val(json) : [];
  return arr.map((v) => ({
    source_id: String(v.vm || v.vm_id || v.name || ''),
    host_source_id: v.host ? String(v.host) : null,
    fields: {
      name: v.name || null, type: 'vm', uuid: v.instance_uuid || v.uuid || v.identity_uuid || null,
      cpu: v.cpu_count ? `${v.cpu_count} vCPU` : null,
      mem_gb: v.memory_size_MiB ? Math.round(Number(v.memory_size_MiB) / 1024) : (v.memory_gb || null),
      os: v.guest_OS || v.guest_os || null,
      mgmt_ip: (v.identity && v.identity.ip_address) || v.ip_address || null,
      networked: true, tags: ['vcenter', 'vm'],
    },
    power: v.power_state || null,
  }));
}

// VM→host runs_on relationship hints (by source_id). Caller resolves source_ids to asset ids after ingest.
function vmHostRelationships(vms) {
  const out = [];
  for (const v of vms) if (v.host_source_id) out.push({ vm_source_id: v.source_id, host_source_id: v.host_source_id, type: 'runs_on' });
  return out;
}

function request(method, url, headers, body, timeoutMs, insecure) {
  return new Promise((resolve) => {
    let u; try { u = new URL(url); } catch { return resolve({ ok: false, error: 'bad vcenter url' }); }
    const mod = u.protocol === 'https:' ? https : http;
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const opts = { protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, timeout: timeoutMs, headers: Object.assign({ Accept: 'application/json' }, data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}, headers || {}) };
    if (u.protocol === 'https:' && insecure) opts.rejectUnauthorized = false;
    const r = mod.request(opts, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > 32 * 1024 * 1024) res.destroy(); else chunks.push(c); });
      res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* may be empty */ } resolve({ ok: res.statusCode < 400, status: res.statusCode, json: j, headers: res.headers }); });
      res.on('error', () => resolve({ ok: false, error: 'vcenter response failed' }));
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    r.on('error', (e) => resolve({ ok: false, error: `vcenter unreachable (${e.code || 'error'})` }));
    if (data) r.write(data);
    r.end();
  });
}

// createVcenterConnector({config, getCreds, fetchImpl?})
//   getCreds() → {user, pass}. fetchImpl({kind}) is injectable for tests ('hosts'|'vms' → raw json), no network.
function createVcenterConnector({ config, getCreds, fetchImpl } = {}) {
  const c = (config && config.vcenter) || {};
  const base = String(c.base_url || '').replace(/\/+$/, '');
  const configured = !!base || !!fetchImpl;
  // transport policy: HTTPS with verified certificates only. http:// or insecure_tls is refused unless the explicit
  // lab-mode flag (config.vcenter.lab_mode === true) is set — the Basic-auth password must never cross in clear/unverified.
  const lab = c.lab_mode === true;
  function transportError() {
    if (!/^https:\/\//i.test(base) && !lab) return 'vcenter base_url must be https:// (http is allowed only with vcenter.lab_mode)';
    if (c.insecure_tls && !lab) return 'vcenter insecure_tls is refused outside vcenter.lab_mode';
    return null;
  }

  async function fetchRaw(kind) {
    if (fetchImpl) return fetchImpl({ kind });
    if (!base) return { ok: false, error: 'vcenter base_url not configured' };
    const te = transportError();
    if (te) return { ok: false, error: te };
    const creds = typeof getCreds === 'function' ? getCreds() : {};
    if (!creds.user || !creds.pass) return { ok: false, error: 'vcenter credentials not set' };
    const basic = 'Basic ' + Buffer.from(`${creds.user}:${creds.pass}`).toString('base64');
    const insecure = lab && c.insecure_tls === true;
    const sess = await request('POST', `${base}/api/session`, { Authorization: basic }, undefined, c.timeout_ms || 30000, insecure);
    const sid = sess.ok ? (val(sess.json) || sess.json) : null;
    if (!sid || typeof sid !== 'string') return { ok: false, error: `vcenter session failed (HTTP ${sess.status || '?'})` };
    const path = kind === 'hosts' ? '/api/vcenter/host' : '/api/vcenter/vm';
    const r = await request('GET', base + path, { 'vmware-api-session-id': sid }, undefined, c.timeout_ms || 30000, insecure);
    // best-effort logout (read-only connector leaves no session behind)
    request('DELETE', `${base}/api/session`, { 'vmware-api-session-id': sid }, undefined, 5000, insecure).catch(() => { /* logout is best effort: the session expires on vCenter anyway */ });
    return r.ok ? { ok: true, json: r.json } : { ok: false, error: `vcenter ${kind} read failed (HTTP ${r.status || '?'})` };
  }

  return {
    configured,
    async status() { return { configured, base_url: base || null }; },
    async pull() {
      const hr = await fetchRaw('hosts');
      if (!hr.ok) return { ok: false, error: hr.error };
      const vr = await fetchRaw('vms');
      if (!vr.ok) return { ok: false, error: vr.error };
      const hosts = parseHosts(hr.json);
      const vms = parseVms(vr.json);
      return { ok: true, hosts, vms, relationships: vmHostRelationships(vms) };
    },
  };
}

module.exports = { createVcenterConnector, parseHosts, parseVms, vmHostRelationships };
