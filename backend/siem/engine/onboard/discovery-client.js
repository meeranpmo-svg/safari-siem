// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Default HTTP client to the sentra-itam Asset-Discovery engine, used by the Add-Devices bulk hub (method B, range
 * auto-discovery). It only READS the discovery engine's scopes + results and triggers a run — it never reimplements
 * scanning and never bypasses the pre-scan gate (startRun enforces that server-side; bulk.js also refuses an active
 * run when scope.gate.open is false). Node stdlib only.
 *   createDiscoveryClient({config, log}) → { scope(id, who), run(id, who), results(query, who), assets(query, who) }
 * Config (config.onboard.discovery): { base_url:"http://127.0.0.1:9130", prefix:"/api/itam/discovery",
 *   secret_file:"/etc/sentra-itam/proxy-secret", timeout_ms:20000 }. The proxy secret authenticates the server-to-server
 * call exactly like sentra-itam → sentra-siem does in reverse (X-Sentra-Proxy-Secret + X-Auth-User/Role).
 */
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const { URL } = require('node:url');

function request(url, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method: opts.method || 'GET', headers: opts.headers || {}, timeout: opts.timeoutMs || 20000 }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => { let json = null; try { json = data ? JSON.parse(data) : null; } catch { /* non-json */ } resolve({ status: res.statusCode, json, text: data }); });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function createDiscoveryClient({ config, log } = {}) {
  const dc = ((config && config.onboard) || {}).discovery || {};
  const base = String(dc.base_url || 'http://127.0.0.1:9130').replace(/\/+$/, '');
  const prefix = (dc.prefix || '/api/itam/discovery').replace(/\/+$/, '');
  const timeoutMs = Number(dc.timeout_ms) || 20000;
  const lg = log || { warn() {}, error() {} };

  function secret() {
    if (!dc.secret_file) { const e = new Error('discovery secret_file not configured'); e.status = 503; throw e; }
    let txt;
    try { txt = String(fs.readFileSync(dc.secret_file, 'utf8')).trim(); } catch (e) { const er = new Error(`discovery proxy secret not readable (${e.code || 'error'})`); er.status = 503; throw er; }
    let v = txt;
    if (txt.startsWith('{')) { try { v = String(JSON.parse(txt).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) { const e = new Error('discovery proxy secret missing or too short'); e.status = 503; throw e; }
    return v;
  }
  async function call(method, path, who, qs, pre) {
    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String((who && who.user) || 'system:sentra-siem').slice(0, 200), 'X-Auth-Role': who && who.role === 'admin' ? 'admin' : 'viewer', Accept: 'application/json' };
    let url = base + (pre === undefined ? prefix : pre) + path;
    if (qs) { const p = new URLSearchParams(qs); url += '?' + p.toString(); }
    let r;
    try { r = await request(url, { method, headers, timeoutMs }); } catch (e) { const er = new Error(`discovery not reachable (${e.code || 'error'})`); er.status = 502; throw er; }
    if (r.status === 401 || r.status === 403) { const e = new Error('discovery refused the platform credentials'); e.status = 502; throw e; }
    if (r.status >= 300 || !r.json) { const e = new Error((r.json && r.json.error) || `discovery HTTP ${r.status}`); e.status = r.status < 500 ? r.status : 502; throw e; }
    return r.json;
  }

  return {
    async scope(id, who) { const j = await call('GET', `/scopes/${encodeURIComponent(id)}`, who); return j.scope || null; },
    async run(id, who) { const j = await call('POST', `/scopes/${encodeURIComponent(id)}/run`, who); return j.run || null; },
    async results(query, who) { const j = await call('GET', '/results', who, query || {}); return { devices: (j && j.devices) || [], total: (j && j.total) || 0 }; },
    /* the IT asset inventory itself (same engine, one level up from /discovery) - read only */
    async assets(query, who) { const j = await call('GET', '/assets', who, query || {}, prefix.replace(/\/discovery$/, '')); return { assets: (j && j.assets) || [], total: (j && j.total) || 0 }; },
    /* support contracts covering one asset (by ip / name / serial) + the Cisco serial check - read only */
    async coverage(query, who) { return call('GET', '/support-contracts/coverage', who, query || {}, prefix.replace(/\/discovery$/, '')); },
    /* per-asset SIEM log coverage the inventory computes (log-flow assurance, onboard/assurance.js) - read only */
    async logCoverage(who) { return call('GET', '/log-coverage', who); },
    async contracts(who) { return call('GET', '/support-contracts', who, null, prefix.replace(/\/discovery$/, '')); },
  };
}

module.exports = { createDiscoveryClient, request };
