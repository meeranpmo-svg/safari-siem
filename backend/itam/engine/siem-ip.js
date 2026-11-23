// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// IP and MAC addresses for user PCs, laptops and servers from the SIEM. Active Directory lists the computers but often
// without an address (no / stale DNS record, laptops on Wi-Fi or VPN, PCs outside the scanned ranges). The SIEM sees
// every domain computer authenticate to the domain controllers from its current address, and FortiGate device
// identification adds the MAC: POST {siem}/api/soc/hostmap {names} (sentra-siem engine/soc/hostmap.js).
//   Fills discovery results (disc_devices) that have a host name but no IP or no MAC, and inventory assets (workstation,
//   laptop, server, vm) with an empty management IP / MAC. Never overwrites an address that is already set.
//   Runs 2 minutes after start, then every discovery.siem.ip_enrich_minutes (default 15; 0 = off).
//   POST /discovery/siem-ip   run now (admin)        GET /discovery/siem-ip   last result
// Self-contained (stored collections + loopback HTTP), so it can be added to an existing install with one registration
// line (install/add-siem-ip.sh) whatever version the rest is.
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

const CLOSED = { retired: 1, disposed: 1 };
const TYPES = { workstation: 1, laptop: 1, server: 1, vm: 1 };
const short = (n) => String(n || '').trim().toLowerCase().split('.')[0];
const hex12 = (m) => { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h : ''; };
const macFmt = (m) => { const h = hex12(m); return h && h !== '000000000000' && h !== 'ffffffffffff' ? h.match(/.{2}/g).join(':') : ''; };

function createSiemIp(app, opts = {}) {
  const { store } = app;
  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
  const audit = (e) => { if (app.audit) app.audit(e); };
  const log = app.log || { info() {}, warn() {} };
  let last = { at: null, ok: null };

  function secret() {
    if (!sc.secret_file) throw new Error('SIEM connection not configured (discovery.siem.secret_file)');
    const txt = String((opts.readFile || ((p) => fs.readFileSync(p, 'utf8')))(sc.secret_file)).trim();
    let v = txt; if (txt.startsWith('{')) { try { v = String(JSON.parse(txt).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw new Error('SIEM proxy secret missing');
    return v;
  }
  function post(path, body) {
    if (opts.request) return opts.request(path, body);
    return new Promise((ok, bad) => {
      const u = new URL(base + prefix + path), data = JSON.stringify(body), lib = u.protocol === 'https:' ? https : http;
      const r = lib.request(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': 'system:itam-siem-ip', 'X-Auth-Role': 'viewer' }, timeout: 90000 }, (res) => {
        let t = ''; res.setEncoding('utf8'); res.on('data', (c) => { if (t.length < 5e6) t += c; });
        res.on('end', () => { let j = null; try { j = JSON.parse(t); } catch { j = null; } if (res.statusCode !== 200) bad(new Error(`SIEM HTTP ${res.statusCode}${j && j.error ? ': ' + j.error : ''}`)); else ok(j); });
      });
      r.on('timeout', () => r.destroy(new Error('SIEM timeout'))); r.on('error', bad); r.end(data);
    });
  }

  async function run(who) {
    const devices = store.collection('disc_devices'), assets = store.collection('assets');
    const devs = devices.all((d) => d.status !== 'ignored' && d.hostname && (!d.ip || !(d.macs || []).length));
    const ass = assets.all((a) => !CLOSED[a.status] && TYPES[a.type] && a.name && (!a.mgmt_ip || !a.mac));
    const names = [...new Set(devs.map((d) => short(d.hostname)).concat(ass.map((a) => short(a.name))).filter(Boolean))];
    const res = { at: new Date().toISOString(), ok: true, asked: names.length, found: 0, devices_ip: 0, devices_mac: 0, assets_ip: 0, assets_mac: 0 };
    if (!names.length) { last = res; return res; }
    const hosts = {};
    for (let i = 0; i < names.length; i += 2000) {
      const j = await post('/hostmap', { names: names.slice(i, i + 2000) });
      Object.assign(hosts, (j && j.hosts) || {});
    }
    res.found = Object.keys(hosts).length;
    const now = res.at;
    for (const d of devs) {
      const h = hosts[short(d.hostname)]; if (!h || !h.ip) continue;
      const mac = macFmt(h.mac);
      devices.patch(d.id, (x) => {
        x.ips = Array.isArray(x.ips) ? x.ips : []; x.macs = Array.isArray(x.macs) ? x.macs : [];
        if (!x.ip) { x.ip = h.ip; if (!x.ips.includes(h.ip)) x.ips = [h.ip].concat(x.ips).slice(0, 16); res.devices_ip++; }
        if (mac && !x.macs.some((m) => hex12(m) === hex12(mac))) { x.macs = x.macs.concat(mac).slice(0, 16); x.mac = x.mac || x.macs[0]; res.devices_mac++; }
        x.methods = x.methods || {}; const m = x.methods.siem || { first_seen: now, count: 0 };
        x.methods.siem = { first_seen: m.first_seen, last_seen: now, count: (m.count || 0) + 1 };
        x.extra = x.extra || {}; x.extra.siem = { ip: h.ip, mac: mac || undefined, via: h.via, seen: h.seen };
      });
    }
    for (const a of ass) {
      const h = hosts[short(a.name)]; if (!h || !h.ip) continue;
      const mac = macFmt(h.mac);
      assets.patch(a.id, (x) => {
        x.prov = x.prov || {};
        if (!x.mgmt_ip) { x.mgmt_ip = h.ip; x.prov.mgmt_ip = 'siem'; res.assets_ip++; }
        if (!x.mac && mac) { x.mac = mac; x.prov.mac = 'siem'; res.assets_mac++; }
        x.updated_at = now;
      });
    }
    last = res;
    audit({ by: (who && who.user) || 'system:itam-siem-ip', role: (who && who.role) || 'system', action: 'discovery.siem_ip', target: 'discovery', detail: res });
    return res;
  }
  async function safeRun(who) { try { return await run(who); } catch (e) { last = { at: new Date().toISOString(), ok: false, error: e.message }; log.warn('siem ip lookup failed', { err: e.message }); return last; } }
  return { run, safeRun, last: () => last };
}

function registerSiemIp(srv, app) {
  const x = createSiemIp(app);
  srv.route('GET', '/discovery/siem-ip', (ctx) => { ctx.need('operator'); return x.last(); });
  srv.route('POST', '/discovery/siem-ip', (ctx) => { ctx.need('admin'); return x.safeRun(ctx.who); });
  const min = Number((((app.config || {}).discovery || {}).siem || {}).ip_enrich_minutes);
  const every = Number.isFinite(min) ? min : 15;
  if (every > 0) {
    const t0 = setTimeout(() => { const job = guardOf(app, 'siem-ip.run', () => x.safeRun().then((r) => { if (r && r.ok === false) throw new Error(r.error || 'SIEM IP lookup failed'); })); job(); const t = setInterval(job, every * 60000); if (t.unref) t.unref(); }, 120000);
    if (t0.unref) t0.unref();
  }
  (app.addons = app.addons || {}).siemIp = x;   // reachable from Sync all now (engine/reconcile.js)
  return x;
}

module.exports = { createSiemIp, registerSiemIp };
