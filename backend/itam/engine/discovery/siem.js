// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ROLE_PASS = new Set(['admin', 'analyst']);
/*
 * ITAM → SIEM: turn an approved asset into a SIEM log source, watch that it keeps sending, and (optionally) bridge
 * rogue-device alerts into the SIEM.
 *   connect(assetId, {kind?}, who) → POST {siem}/api/soc/onboard/sources {id, kind, site, match_ip, label} (server side,
 *       loopback, X-Sentra-Proxy-Secret from discovery.siem.secret_file + the admin's identity) → returns the SIEM's one-time
 *       token + rendered steps to the admin ONCE. Only the source id/kind is stored on the asset — never the token.
 *   health() → GET {siem}/api/soc/onboard/sources; marks connected assets receiving / silent / waiting / missing; an asset
 *       whose source has sent nothing for > discovery.siem.silent_minutes raises the ITAM finding "siem_silent".
 *   bridge(events) → optional POST of {source:'itam', kind:'rogue-device', …} NDJSON to the SIEM HTTP ingest
 *       (/ingest/<src_id>, header X-Sentra-Token) — OFF by default (discovery.siem.bridge.enabled).
 *   kindFor(asset) → {kind|null, reason}: the device-type → SIEM connector mapping table below.
 */
const fs = require('node:fs');
const httpc = require('./httpc');

// connector kinds this module may create (all exist in sentra-siem engine/onboard/catalog.json; mode token or syslog)
const CONNECTABLE = ['windows', 'dc', 'linux', 'fortigate', 'palo-alto', 'cisco', 'cisco-asa-ftd', 'check-point', 'sophos-firewall', 'sonicwall', 'f5-afm', 'f5-bigip', 'vmware-esxi-hosts', 'dell-idrac', 'hpe-ilo', 'syslog'];
const TOKEN_KINDS = ['windows', 'dc'];
// mapping table (first match wins) — shown in the UI and docs
const KIND_TABLE = [
  { when: 'Windows domain controller (AD)', kind: 'dc', test: (c) => c.windows && c.dc },
  { when: 'Windows server or workstation', kind: 'windows', test: (c) => c.windows },
  { when: 'VMware ESXi host', kind: 'vmware-esxi-hosts', test: (c) => /esxi/.test(c.os) },
  { when: 'Fortinet FortiGate firewall', kind: 'fortigate', test: (c) => c.cls === 'firewall' && /forti/.test(c.vendor + c.os) },
  { when: 'Palo Alto Networks firewall', kind: 'palo-alto', test: (c) => c.cls === 'firewall' && /palo alto|pan-os/.test(c.vendor + c.os) },
  { when: 'Cisco ASA / Firepower', kind: 'cisco-asa-ftd', test: (c) => c.cls === 'firewall' && /cisco/.test(c.vendor) },
  { when: 'Check Point firewall', kind: 'check-point', test: (c) => c.cls === 'firewall' && /check ?point/.test(c.vendor) },
  { when: 'Sophos firewall', kind: 'sophos-firewall', test: (c) => c.cls === 'firewall' && /sophos/.test(c.vendor) },
  { when: 'SonicWall firewall', kind: 'sonicwall', test: (c) => c.cls === 'firewall' && /sonicwall/.test(c.vendor) },
  { when: 'F5 BIG-IP', kind: 'f5-bigip', test: (c) => /f5/.test(c.vendor) },
  { when: 'Cisco switch / router / AP', kind: 'cisco', test: (c) => ['switch', 'router', 'ap'].includes(c.cls) && /cisco/.test(c.vendor) },
  { when: 'Dell iDRAC / HPE iLO (out-of-band)', kind: 'dell-idrac', test: (c) => /idrac/.test(c.os + c.name) },
  { when: 'HPE iLO', kind: 'hpe-ilo', test: (c) => /\bilo\b/.test(c.os + c.name) },
  { when: 'Oracle Solaris / AIX / HP-UX server (syslog)', kind: 'syslog', test: (c) => /solaris|sunos|\baix\b|hp-ux/.test(c.os) },
  { when: 'Linux / Unix server', kind: 'linux', test: (c) => /linux|ubuntu|red hat|rhel|centos|debian|suse|unix/.test(c.os) },
  { when: 'Other network device (switch / router / AP / firewall)', kind: 'syslog', test: (c) => ['switch', 'router', 'ap', 'firewall'].includes(c.cls) },
];
const NOT_APPLICABLE = { printer: 'printers are monitored by the print module', phone: 'IP phones log through CUCM, not individually', cloud: 'cloud instances are onboarded through the cloud connectors' };

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

function kindFor(a) {
  const disc = a.discovery || {};
  const c = {
    cls: disc.class || ({ network: 'switch', server: 'server', workstation: 'workstation', laptop: 'workstation', vm: 'vm', printer: 'printer', phone: 'phone' }[a.type] || 'unknown'),
    vendor: String(disc.vendor || a.vendor || '').toLowerCase(), os: String(disc.os || a.os || '').toLowerCase(), name: String(a.name || '').toLowerCase(),
  };
  c.windows = /windows/.test(c.os); c.dc = !!disc.is_dc;
  if (NOT_APPLICABLE[c.cls]) return { kind: null, reason: NOT_APPLICABLE[c.cls] };
  for (const row of KIND_TABLE) if (row.test(c)) return { kind: row.kind, reason: row.when };
  return { kind: null, reason: 'no automatic mapping — choose the connector kind' };
}

function slug(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }

function createSiem({ config, log, assets, store, audit, findings, request, readFile }) {
  const sc = ((config && config.discovery) || {}).siem || {};
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, '');
  const prefix = sc.prefix || '/api/soc';
  const req = request || httpc.request;
  const read = readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const siteMap = Object.assign((() => { try { return Object.fromEntries((require('../brand').sites || []).map((x) => [x.name, x.id])); } catch (e) { return {}; /* no brand file */ } })(), sc.site_map || {});
  const silentMs = Math.max(5, Number(sc.silent_minutes) || 60) * 60000;
  let lastHealth = null;

  function secret() {
    if (!sc.secret_file) throw bad('SIEM connection not configured (discovery.siem.secret_file)', 503);
    let txt;
    try { txt = String(read(sc.secret_file)).trim(); } catch (e) { throw bad(`SIEM proxy secret file not readable (${e.code || 'error'})`, 503); }
    let v = txt;
    if (txt.startsWith('{')) { try { v = String(JSON.parse(txt).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw bad('SIEM proxy secret missing or shorter than 16 characters', 503);
    return v;
  }
  // roles sent through as they are: admin, and analyst - the read-only role of the platform's own auditing jobs (AI auditors,
  // Baseline Hardening) for the SIEM evidence routes that refuse viewers (named accounts, how machines are defended). Every
  // other role (operator included) is sent as viewer, as before: a write in the SIEM still needs an administrator here.
  async function call(method, path, who, body) {
    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String(who.user || 'system').slice(0, 200), 'X-Auth-Role': ROLE_PASS.has(who.role) ? who.role : 'viewer', Accept: 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    let r;
    try { r = await req(base + prefix + path, { method, headers, body: body ? JSON.stringify(body) : null, timeoutMs: 20000 }); } catch (e) { throw bad(`SIEM not reachable (${e.code || 'error'})`, 502); }
    return r;
  }

  async function connect(assetId, body, who) {
    const a = assets.raw(String(assetId || ''));
    if (!a) throw bad('asset not found', 404);
    if (a.status === 'disposed' || a.status === 'retired') throw bad(`asset is ${a.status}`, 409);
    if (a.siem && a.siem.source_id) throw bad(`asset already connected to the SIEM as ${a.siem.source_id}`, 409);
    const auto = kindFor(a);
    let kind = body && body.kind ? String(body.kind) : auto.kind;
    if (!kind) throw bad(`cannot choose a SIEM connector automatically: ${auto.reason}`, 409);
    if (!CONNECTABLE.includes(kind)) throw bad(`kind must be one of ${CONNECTABLE.join(', ')}`);
    const site = siteMap[a.site] || (Object.values(siteMap).includes(a.site) ? a.site : null);
    if (!site) throw bad(`asset site "${a.site || ''}" is not mapped to a SIEM site (discovery.siem.site_map)`, 409);
    if (!TOKEN_KINDS.includes(kind) && !a.mgmt_ip) throw bad('a syslog source needs the asset management IP', 409);
    const label = String(a.name || a.mgmt_ip || a.id).slice(0, 100);
    const stem = ('itam-' + (slug(a.name) || slug(a.mgmt_ip) || a.id.slice(3))).slice(0, 36).replace(/-+$/, '');
    let r = null; let id = null;
    for (let i = 1; i <= 5; i++) {
      id = i === 1 ? stem : `${stem}-${i}`;
      r = await call('POST', '/onboard/sources', who, { id, kind, site, match_ip: a.mgmt_ip || undefined, label });
      if (r.status !== 409) break;
    }
    if (r.status === 401 || r.status === 403) throw bad('the SIEM refused the platform credentials (check the proxy secret file)', 502);
    if (r.status >= 300 || !r.json || !r.json.source) throw bad(`SIEM: ${(r.json && r.json.error) || `HTTP ${r.status}`}`, 502);
    const src = r.json.source;
    const now = new Date().toISOString();
    store.collection('assets').patch(a.id, (x) => { x.siem = { source_id: src.id || id, kind, site, connected_at: now, connected_by: who.user, state: 'waiting', last_seen: null, checked_at: null, alert: false }; });
    if (audit) audit({ by: who.user, role: who.role, ip: who.ip, action: 'discovery.connect', target: a.id, detail: { source_id: src.id || id, kind, site, auto_kind: auto.kind, match_ip: a.mgmt_ip || null } });
    return {
      asset_id: a.id, source_id: src.id || id, kind, site, token: r.json.token || null, token_shown_once: !!r.json.token,
      instructions: r.json.instructions || [], steps: r.json.steps || [], network: r.json.network || null, prerequisites: r.json.prerequisites || [], kit_url: r.json.kit_url || null, siem: r.json.siem || null,
    };
  }

  async function health(now = Date.now()) {
    const connected = assets.all().filter((a) => a.siem && a.siem.source_id && a.status !== 'disposed');
    if (!connected.length) { lastHealth = { at: new Date(now).toISOString(), ok: true, checked: 0 }; return lastHealth; }
    let r;
    try { r = await call('GET', '/onboard/sources', { user: 'system:itam-discovery', role: 'viewer' }); } catch (e) { lastHealth = { at: new Date(now).toISOString(), ok: false, error: e.message }; return lastHealth; }
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.sources)) { lastHealth = { at: new Date(now).toISOString(), ok: false, error: `SIEM HTTP ${r.status}` }; return lastHealth; }
    const rows = new Map(r.json.sources.map((s) => [s.id, s]));
    // the server's own logs may arrive through ANOTHER source (one agent source shared by many servers, a syslog relay):
    // GET /reporting-hosts lists every machine that sent logs, so such an asset is receiving, "via" that source
    const rep = new Map();
    try {
      const rh = await call('GET', '/reporting-hosts?hours=168', { user: 'system:itam-discovery', role: 'viewer' });
      if (rh && rh.status === 200 && rh.json && Array.isArray(rh.json.hosts)) for (const h of rh.json.hosts) {
        const k = String(h.host || '').toLowerCase(); if (!k) continue;
        if (!rep.has(k)) rep.set(k, h); if (k.indexOf('.') > 0 && !rep.has(k.split('.')[0])) rep.set(k.split('.')[0], h);
        if (h.ip && !rep.has('ip:' + h.ip)) rep.set('ip:' + h.ip, h);
      }
    } catch (e) { /* older SIEM without /reporting-hosts */ }
    const hostRow = (a) => {
      for (const v of [a.name, a.hostname, a.fqdn]) { const k = String(v || '').toLowerCase().trim(); if (!k) continue; if (rep.has(k)) return rep.get(k); if (k.indexOf('.') > 0 && rep.has(k.split('.')[0])) return rep.get(k.split('.')[0]); }
      return a.mgmt_ip && rep.has('ip:' + a.mgmt_ip) ? rep.get('ip:' + a.mgmt_ip) : null;
    };
    let silent = 0;
    for (const a of connected) {
      const row = rows.get(a.siem.source_id);
      let last = row && row.last_seen ? Number(row.last_seen) : null;
      const since = last || Date.parse(a.siem.connected_at) || now;
      let state = !row ? 'missing' : row.state || 'waiting';
      let via = null;
      const h = state !== 'receiving' ? hostRow(a) : null;
      const ht = h && h.last_seen ? Date.parse(h.last_seen) : NaN;
      if (h && Number.isFinite(ht) && h.src_id !== a.siem.source_id) {
        if (now - ht <= silentMs) { state = 'receiving'; via = h.src_id; last = ht; }
        else if (!last || ht > last) { via = h.src_id; last = ht; }
      }
      const alert = state !== 'receiving' && (!row || now - (last || since) > silentMs);
      if (alert) silent++;
      store.collection('assets').patch(a.id, (x) => { x.siem = Object.assign({}, x.siem, { state, via, last_seen: last ? new Date(last).toISOString() : null, checked_at: new Date(now).toISOString(), alert }); });
    }
    if (findings) findings.syncKinds(['siem_silent'], { user: 'system:itam-discovery', role: 'system' });
    lastHealth = { at: new Date(now).toISOString(), ok: true, checked: connected.length, silent };
    return lastHealth;
  }

  // Read-only: the SIEM's current log sources (id/kind/state/last_seen + whatever match fields it exposes), for
  // log-coverage matching. Tolerant — returns {ok:false, error} when the SIEM is unreachable (never throws).
  async function fetchSources(now = Date.now()) {
    let r;
    try { r = await call('GET', '/onboard/sources', { user: 'system:itam-discovery', role: 'viewer' }); } catch (e) { return { ok: false, at: new Date(now).toISOString(), error: e.message }; }
    if (r.status !== 200 || !r.json || !Array.isArray(r.json.sources)) return { ok: false, at: new Date(now).toISOString(), error: `SIEM HTTP ${r.status}` };
    return { ok: true, at: new Date(now).toISOString(), sources: r.json.sources };
  }

  // findings provider: connected assets whose source went silent
  function silentFindings() {
    return assets.all().filter((a) => a.siem && a.siem.alert && a.status !== 'disposed').map((a) => ({
      key: `siem_silent:${a.id}`, kind: 'siem_silent', severity: 'high', asset_id: a.id, label: 'Discovery',
      title: `SIEM log source silent: ${a.name || a.mgmt_ip || a.id}`,
      detail: `The SIEM source ${a.siem.source_id} (${a.siem.kind}) has not delivered events for more than ${Math.round(silentMs / 60000)} minutes (state: ${a.siem.state}). Check the device's log forwarding, the network path to the SIEM and the source in SOC > Sources.`,
      evidence: { source_id: a.siem.source_id, state: a.siem.state, last_seen: a.siem.last_seen, checked_at: a.siem.checked_at },
    }));
  }

  async function bridge(events) {
    const b = sc.bridge || {};
    if (!b.enabled || !events.length) return { sent: 0, enabled: !!b.enabled };
    let token;
    try { token = String(read(b.token_file)).trim(); } catch (e) { return { sent: 0, error: `bridge token file not readable (${e.code || 'error'})` }; }
    try {
      const r = await req(b.url || `${base}/ingest/itam-bridge`, { method: 'POST', headers: { 'X-Sentra-Token': token, 'Content-Type': 'application/x-ndjson' }, body: events.map((e) => JSON.stringify(e)).join('\n') + '\n', timeoutMs: 15000 });
      return r.status < 300 ? { sent: events.length } : { sent: 0, error: `HTTP ${r.status}` };
    } catch (e) { return { sent: 0, error: e.code || 'error' }; }
  }

  // call(method, path, who, body) → {status, json}: the ONE authenticated loopback link to the SIEM API (proxy secret +
  // identity). Reused by engine/monitoring-membership.js (inventory "Log collection" actions) — no parallel SIEM link.
  return { connect, health, fetchSources, silentFindings, bridge, kindFor, call, lastHealth: () => lastHealth, configured: () => !!sc.secret_file, siteMap, silentMinutes: () => Math.round(silentMs / 60000) };
}

module.exports = { createSiem, kindFor, KIND_TABLE, CONNECTABLE, NOT_APPLICABLE, slug };
