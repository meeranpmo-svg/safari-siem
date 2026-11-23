// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// sentra-netops subscription. ITAM SUBSCRIBES to the devices sentra-netops already discovered — it does NOT re-poll the
// devices itself. Reads the netops device + topology model over its HTTP API (or an injected bridge in tests).
// Maps a netops device record into normalised ITAM asset fields, and LLDP neighbour edges into connected_to hints.
const http = require('node:http');
const https = require('node:https');

const NETOPS_TYPE_MAP = {
  switch: 'network', router: 'network', ap: 'network', 'access-point': 'network', accesspoint: 'network',
  firewall: 'network', gateway: 'network', wlc: 'network', bridge: 'network',
  phone: 'phone', 'ip-phone': 'phone', voip: 'phone',
  server: 'server', printer: 'printer', ups: 'ups', storage: 'storage', camera: 'peripheral',
};

// map one netops device record → ITAM asset fields (+ a stable source_id)
function mapDevice(d) {
  const o = d && typeof d === 'object' ? d : {};
  const t = String(o.type || o.device_type || o.category || '').toLowerCase();
  const macs = Array.isArray(o.interfaces) ? o.interfaces.map((i) => i && (i.mac || i.mac_address)).filter(Boolean) : [];
  return {
    fields: {
      name: o.hostname || o.name || o.sysName || null,
      type: NETOPS_TYPE_MAP[t] || 'network',
      vendor: o.vendor || o.manufacturer || null,
      model: o.model || o.hw_model || null,
      serial: o.serial || o.serial_number || null,
      mgmt_ip: o.mgmt_ip || o.ip || o.management_ip || null,
      mac: o.mac || o.base_mac || (macs[0] || null),
      macs,
      os: o.os || o.firmware || o.sw_version || null,
      site: o.site || o.location_site || null,
      networked: true,
      tags: ['netops'],
    },
    source_id: String(o.id || o.device_id || o.mgmt_ip || o.hostname || ''),
    last_seen: o.last_seen || o.last_polled || null,
    raw_id: o.id || o.device_id || null,
  };
}

// topology edges → connected_to relationship hints keyed by netops device id.
// returns [{a_source_id, b_source_id, type:'connected_to', via}]
function mapTopology(edges) {
  const out = [];
  for (const e of Array.isArray(edges) ? edges : []) {
    const a = e && (e.local_device || e.a || e.from); const b = e && (e.remote_device || e.b || e.to);
    if (a == null || b == null || String(a) === String(b)) continue;
    out.push({ a_source_id: String(a), b_source_id: String(b), type: 'connected_to', via: (e.local_port || e.port || null) });
  }
  return out;
}

function getJson(url, headers, timeoutMs) {
  return new Promise((resolve) => {
    let u; try { u = new URL(url); } catch { return resolve({ ok: false, error: 'bad netops url' }); }
    const mod = u.protocol === 'https:' ? https : http;
    const r = mod.request({ protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET', timeout: timeoutMs, headers: headers || {} }, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > 16 * 1024 * 1024) res.destroy(); else chunks.push(c); });
      res.on('end', () => { try { resolve({ ok: true, status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch { resolve({ ok: false, error: 'unreadable netops response' }); } });
      res.on('error', () => resolve({ ok: false, error: 'netops response failed' }));
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    r.on('error', (e) => resolve({ ok: false, error: `netops unreachable (${e.code || 'error'})` }));
    r.end();
  });
}

// createNetopsConnector({config, getToken, fetchImpl?}) → { configured, status(), devices(), topology() }
//   fetchImpl({path}) is injectable for tests (returns {devices|edges|json}); the real one calls the netops API.
function createNetopsConnector({ config, getToken, fetchImpl } = {}) {
  const c = (config && config.netops) || {};
  const base = String(c.base_url || '').replace(/\/+$/, '');
  const configured = !!base || !!fetchImpl;

  async function call(path) {
    if (fetchImpl) return fetchImpl({ path });
    if (!base) return { ok: false, error: 'netops base_url not configured' };
    const token = typeof getToken === 'function' ? getToken() : '';
    const headers = Object.assign({ Accept: 'application/json' }, token ? { Authorization: `Bearer ${token}` } : {});
    return getJson(base + path, headers, c.timeout_ms || 20000);
  }

  return {
    configured,
    async status() { return { configured, base_url: base ? base.replace(/\/\/[^/]*@/, '//') : null }; },
    async devices() {
      const r = await call(c.devices_path || '/devices');
      if (!r.ok) return { ok: false, error: r.error };
      const arr = Array.isArray(r.devices) ? r.devices : Array.isArray(r.json) ? r.json : (r.json && Array.isArray(r.json.devices) ? r.json.devices : []);
      return { ok: true, devices: arr.map(mapDevice) };
    },
    async topology() {
      const r = await call(c.topology_path || '/topology');
      if (!r.ok) return { ok: false, error: r.error };
      const arr = Array.isArray(r.edges) ? r.edges : Array.isArray(r.json) ? r.json : (r.json && Array.isArray(r.json.edges) ? r.json.edges : []);
      return { ok: true, edges: mapTopology(arr) };
    },
  };
}

module.exports = { createNetopsConnector, mapDevice, mapTopology, NETOPS_TYPE_MAP };
