// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Kaspersky Security Center (KSC) OpenAPI — read-only endpoint posture. Ported from an earlier collector
 * (monitoring/agent/connectors/ksc.js) and adapted to the SIEM's read-only HTTPS client (TLS pinning).
 *   https://<ksc>:13299/api/v1.0/<Class.Method>
 *   1. login  Authorization: KSCBasic user="<b64>", pass="<b64>", internal="1"  → session cookie (+ KSCSession header)
 *   2. HostGroup.FindHosts → strAccessor   3. ChunkAccessor.GetItemsChunk (paged)   4. ChunkAccessor.Release
 * READ-ONLY: only login / logout / FindHosts / GetItemsChunk / Release are ever called (ALLOWED). Field names differ
 * between KSC versions, so a field KSC did not send stays absent — it is never guessed.
 */
const { request } = require('../secops/https');

const ALLOWED = new Set(['login', 'logout', 'HostGroup.FindHosts', 'ChunkAccessor.GetItemsChunk', 'ChunkAccessor.Release']);
const FIELDS = ['KLHST_WKS_DN', 'KLHST_WKS_DNSNAME', 'KLHST_WKS_IP_LONG', 'KLHST_WKS_STATUS_ID', 'KLHST_WKS_RTP_STATE',
  'KLHST_WKS_LAST_FULLSCAN', 'KLHST_WKS_LAST_VISIBLE', 'KLHST_WKS_LAST_INFECTED', 'KLHST_WKS_LAST_UPDATE',
  'KLHST_WKS_VIRUS_COUNT', 'KLHST_WKS_NAG_VERSION_DISPLAY'];
// KLHST_WKS_RTP_STATE: 4..8 are the "running" states; 0 unknown, 1 stopped, 2 suspended, 3 starting, 9 failure
const RTP = { 0: 'unknown', 1: 'stopped', 2: 'suspended', 3: 'starting', 4: 'running', 5: 'running (max protection)', 6: 'running (max speed)', 7: 'running (recommended)', 8: 'running (custom)', 9: 'failure' };
const b64 = (s) => Buffer.from(String(s || ''), 'utf8').toString('base64');

function session(cfg) {
  const host = String(cfg.host || '').trim(); if (!host) throw new Error('KSC host required');
  const port = cfg.port || 13299, tls = cfg.tls || {}; let cookie = '', kscSession = '';
  const call = async (method, body) => {
    if (!ALLOWED.has(method)) throw new Error('refused: ' + method + ' is not a read-only KSC call');
    const headers = {};
    if (method === 'login') headers.Authorization = 'KSCBasic user="' + b64(cfg.user) + '", pass="' + b64(cfg.pass) + '", internal="' + (cfg.internal === false ? '0' : '1') + '"';
    if (cookie) headers.Cookie = cookie;
    if (kscSession) headers.KSCSession = kscSession;
    const r = await request({ url: 'https://' + host + ':' + port + '/api/v1.0/' + method, method: 'POST', headers, body: body || {}, tls, timeoutMs: cfg.timeoutMs || 15000 });
    if (r.cookie) cookie = r.cookie;
    if (r.headers && r.headers.kscsession) kscSession = r.headers.kscsession;
    if (r.status === 401) throw new Error('KSC ' + method + ' HTTP 401 (wrong user/password, or the account has no rights)');
    if (r.status >= 400) throw new Error('KSC ' + method + ' HTTP ' + r.status + ' ' + String(r.text || '').slice(0, 120));
    if (r.json && r.json.PxgError) throw new Error('KSC ' + method + ': ' + String(r.json.PxgError.message || JSON.stringify(r.json.PxgError)).slice(0, 160));
    return r.json || {};
  };
  return { login: () => call('login', {}), logout: () => call('logout', {}).catch(() => { /* logout is best effort: the session expires on the server */ }), call };
}

const unwrap = (v) => (v && typeof v === 'object' && 'type' in v && 'value' in v) ? v.value : v;
const ipOf = (n) => { n = Number(unwrap(n)); if (!Number.isFinite(n) || n <= 0) return ''; n = n >>> 0; return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); };
const iso = (v) => { v = unwrap(v); const t = Date.parse(v); return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : ''; };

function normHost(p) {
  const g = (k) => unwrap(p[k]);
  const rtp = g('KLHST_WKS_RTP_STATE'), status = g('KLHST_WKS_STATUS_ID'), vc = Number(g('KLHST_WKS_VIRUS_COUNT'));
  return { host: String(g('KLHST_WKS_DN') || g('KLHST_WKS_DNSNAME') || '').slice(0, 120), ip: ipOf(p.KLHST_WKS_IP_LONG),
    protection: rtp != null && +rtp >= 4 && +rtp <= 8, rtpState: rtp == null ? 'not reported' : (RTP[+rtp] || 'code ' + rtp),
    status: status == null ? 'not reported' : (+status === 0 ? 'ok' : +status === 1 ? 'critical' : +status === 2 ? 'warning' : 'code ' + status),
    agentVersion: String(g('KLHST_WKS_NAG_VERSION_DISPLAY') || '').slice(0, 40), lastScan: iso(p.KLHST_WKS_LAST_FULLSCAN),
    lastSeen: iso(p.KLHST_WKS_LAST_VISIBLE), lastUpdate: iso(p.KLHST_WKS_LAST_UPDATE), lastInfected: iso(p.KLHST_WKS_LAST_INFECTED),
    threats: Number.isFinite(vc) ? vc : null };
}

async function findHosts(cfg, opt = {}) {
  const s = session(cfg); await s.login();
  try {
    const f = await s.call('HostGroup.FindHosts', { wstrFilter: opt.filter || '', vecFieldsToReturn: opt.fields || FIELDS, vecFieldsToOrder: [], pParams: {}, lMaxLifeTime: 600 });
    const acc = f.strAccessor; if (!acc) throw new Error('KSC FindHosts returned no accessor');
    const total = Number(unwrap(f.PxgRetVal)) || 0, max = Math.min(opt.max || 5000, total || opt.max || 5000), out = [];
    try {
      for (let start = 0; start < max; start += 200) {
        const c = await s.call('ChunkAccessor.GetItemsChunk', { strAccessor: acc, nStart: start, nCount: Math.min(200, max - start) });
        const items = ((c.pChunk && c.pChunk.KLCSP_ITERATOR_ARRAY) || []).map((x) => (x && x.value) || x);
        out.push(...items); if (items.length < Math.min(200, max - start)) break;
      }
    } finally { await s.call('ChunkAccessor.Release', { strAccessor: acc }).catch(() => { /* releasing the accessor is best effort: KSC frees it on timeout */ }); }
    return { total, rows: out };
  } finally { await s.logout(); }
}

async function snapshot(cfg) {
  const r = await findHosts(cfg, { max: cfg.maxHosts || 5000 });
  const hosts = r.rows.map(normHost).filter((h) => h.host);
  const staleDays = cfg.dbStaleDays || 3, now = Date.now();
  let protectedN = 0, outdated = 0, infected = 0, critical = 0;
  for (const h of hosts) {
    if (h.protection) protectedN++;
    if (h.lastUpdate && (now - Date.parse(h.lastUpdate)) > staleDays * 86400000) { outdated++; h.dbOutdated = true; }
    if (h.threats && h.threats > 0) infected++;
    if (h.status === 'critical') critical++;
  }
  return { source: 'kaspersky-ksc', at: Date.now(), total: r.total, hosts,
    summary: { hosts: hosts.length, protected: protectedN, unprotected: hosts.length - protectedN, outdated, infected, critical, dbStaleDays: staleDays } };
}

async function probe(cfg) {
  const r = await findHosts(cfg, { max: 1 });
  const row = r.rows[0] || {};
  return { hostsInKsc: r.total, fieldsReturned: FIELDS.filter((k) => row[k] != null), fieldsMissing: FIELDS.filter((k) => row[k] == null), sample: r.rows[0] ? normHost(row) : null };
}

module.exports = { snapshot, probe, normHost, ipOf, FIELDS, RTP, ALLOWED };
