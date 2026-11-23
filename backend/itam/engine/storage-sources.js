// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only clients for storage arrays. collect(cred, opts) →
//   {ok, platform, system: {name, model, version, serial, health}, controllers: [{name, state, health, model, serial}],
//    pools: [{name, owner, health, size_bytes, used_bytes, free_bytes}], volumes: [{name, container, state, size_bytes, used_bytes}],
//    disks: {total, failed: [{name, state, model, serial, location}], spares}, events: [{at, severity, message}], ms}
//   | {ok:false, error_class, error, presented?}
// Only GET requests (and the MSA session sign-in / sign-out, which are GETs too); guard() refuses anything else before a
// socket is opened. Nothing on an array can be created, changed or deleted from here.
//   NetApp ONTAP 9.6+ REST: https://<cluster management LIF>/api, HTTP Basic with a read-only account (role "readonly",
//     application http). GET /api/cluster, /cluster/nodes, /storage/aggregates, /storage/volumes, /storage/disks,
//     /support/ems/events (optional).
//   HPE MSA 2060 / 2062 (and MSA 1060/2050, firmware with the REST "api" interface): https://<controller>, GET /api/login
//     with HTTP Basic (newer firmware) or /api/login/<sha256("user_password")> (older), header "datatype: json"; the
//     session key goes in the "sessionKey" header; GET /api/show/system, controllers, pools, disk-groups, disks, volumes,
//     events/last/50; GET /api/exit at the end. Use a "monitor" (read-only) user.
// Field names marked with alternatives are read defensively (firmware versions differ); a value the array does not
// report stays null - never guessed.
const crypto = require('node:crypto');
const httpc = require('./discovery/httpc');

const ERR = (code, message, extra) => Object.assign(new Error(message), { code }, extra || {});
const cls = (e) => (['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol');
const iso = (v) => { if (v == null || v === '') return null; const t = typeof v === 'number' ? v : Date.parse(String(v).replace(' ', 'T')); return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : null; };
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const first = (o, ...ks) => { for (const k of ks) { const v = k.split('.').reduce((x, p) => (x == null ? x : x[p]), o); if (v !== undefined && v !== null && v !== '') return v; } return null; };

const ALLOW = {
  ontap: (m, p) => m === 'GET' && /^\/api\/(cluster|cluster\/nodes|storage\/aggregates|storage\/volumes|storage\/disks|support\/ems\/events)(\?|$)/.test(p),
  msa: (m, p) => m === 'GET' && /^\/api\/(login(\/(?:[0-9a-f]{32}|[0-9a-f]{64}))?|exit|show\/(system|controllers|pools|disk-groups|disks|volumes|events\/last\/\d{1,3}))$/.test(p),
};
// what to check on the array when it answers 401 (shown on the Storage page next to the error)
const AUTH_HINT = {
  ontap: ' - on the cluster run "security login show -user-or-group-name <user>": it needs application http, authentication method password, role readonly, on the cluster (admin) SVM, not locked; reset with "security login password -username <user>" and enter the same password here',
  msa: ' - the user needs the monitor role with the WBI/API interface enabled',
};
function guard(kind, method, path) { if (ALLOW[kind] && ALLOW[kind](method, path)) return; throw ERR('config', `${kind} storage reading is read-only; refusing ${method} ${path}`); }
function baseOf(url) {
  const b = String(url || '').trim().replace(/\/+$/, '');
  // https; plain http only for a loopback test array (httpc refuses http to anything else anyway)
  if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/.*)?$/.test(b) && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?(\/.*)?$/.test(b)) throw ERR('config', 'the address must be https://<host or IP>[:port]');
  const u = new URL(b); return `${u.protocol}//${u.hostname}${u.port ? ':' + u.port : ''}`;
}
function client(kind, cred, o) {
  const t = cred.target || {}, base = baseOf(t.base_url), req = o.request || httpc.request;
  async function call(path, headers) {
    guard(kind, 'GET', path);
    const r = await req(base + path, { method: 'GET', headers: Object.assign({ Accept: 'application/json' }, headers || {}), caFile: t.ca_file || undefined, pin: t.tls_fingerprint || undefined, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 60000 });
    if (r.status === 401) throw ERR('auth', `${kind}: the credentials were rejected (HTTP 401)` + (AUTH_HINT[kind] || ''));
    if (r.status === 403) throw ERR('authz', `${kind}: the account may not read ${path.split('?')[0]} (HTTP 403) - use a read-only / monitor account with API access`);
    if (r.status < 200 || r.status >= 300) throw ERR('protocol', `${kind}: GET ${path.split('?')[0]} answered HTTP ${r.status}`, { http: r.status });
    if (r.json == null) throw ERR('protocol', `${kind}: ${path.split('?')[0]} did not answer JSON`);
    return r.json;
  }
  return { call };
}
const pct = (u, s) => (s ? Math.round(u / s * 1000) / 10 : null);

// ---------------------------------------------------------------- NetApp ONTAP --------------------------------------
async function ontap(cred, o = {}) {
  const t0 = Date.now();
  try {
    const s = cred.secret || {}; if (!s.username || !s.password) throw ERR('config', 'ONTAP needs a user name and password (read-only role)');
    const c = client('ontap', cred, o), H = { Authorization: 'Basic ' + Buffer.from(`${s.username}:${s.password}`).toString('base64') };
    const recs = (j) => (Array.isArray(j && j.records) ? j.records : []);
    const cl = await c.call('/api/cluster?fields=name,version,uuid', H);
    const nodes = recs(await c.call('/api/cluster/nodes?fields=name,model,serial_number,state,ha,uptime&max_records=100', H));
    const aggr = recs(await c.call('/api/storage/aggregates?fields=name,state,node.name,space.block_storage.size,space.block_storage.used,space.block_storage.available&max_records=1000', H));
    const vols = recs(await c.call('/api/storage/volumes?fields=name,svm.name,state,type,space.size,space.used,space.available,aggregates.name&max_records=10000', H));
    let disks = [];
    try { disks = recs(await c.call('/api/storage/disks?fields=name,state,container_type,model,serial_number,node.name,bay,shelf.uid&max_records=10000', H)); } catch (e) { if (e.code !== 'authz' && e.http !== 404) throw e; }
    let events = [];
    try { events = recs(await c.call('/api/support/ems/events?message.severity=emergency|alert|error&max_records=50&order_by=time%20desc&fields=time,log_message,message.severity,node.name', H)); } catch (e) { if (!['authz', 'protocol'].includes(e.code)) throw e; }
    const failedStates = /broken|failed|offline|unknown|removed/i;
    return {
      ok: true, platform: 'ontap', ms: Date.now() - t0,
      system: { name: cl.name || null, model: (nodes[0] && nodes[0].model) || null, version: first(cl, 'version.full', 'version.generation') || null, serial: (nodes[0] && nodes[0].serial_number) || null, health: nodes.some((n) => n.state && n.state !== 'up') ? 'degraded' : 'ok' },
      controllers: nodes.map((n) => ({ name: n.name, state: n.state || null, health: !n.state ? null : n.state === 'up' ? 'ok' : 'degraded', model: n.model || null, serial: n.serial_number || null, ha_partner: first(n, 'ha.partners.0.name') })),
      pools: aggr.map((a) => { const sz = num(first(a, 'space.block_storage.size')), us = num(first(a, 'space.block_storage.used')), av = num(first(a, 'space.block_storage.available')); return { name: a.name, owner: first(a, 'node.name'), health: a.state === 'online' ? 'ok' : a.state ? 'degraded' : null, state: a.state || null, size_bytes: sz, used_bytes: us, free_bytes: av, used_pct: pct(us, sz) }; }),
      volumes: vols.map((v) => { const sz = num(first(v, 'space.size')), us = num(first(v, 'space.used')); return { name: v.name, container: first(v, 'svm.name'), pool: first(v, 'aggregates.0.name'), state: v.state || null, type: v.type || null, size_bytes: sz, used_bytes: us, used_pct: pct(us, sz) }; }),
      disks: { total: disks.length, reported: disks.length > 0, spares: disks.filter((d) => d.container_type === 'spare').length,
        failed: disks.filter((d) => failedStates.test(d.state || '') || d.container_type === 'broken').map((d) => ({ name: d.name, state: d.state || d.container_type, model: d.model || null, serial: d.serial_number || null, location: [first(d, 'node.name'), d.bay != null ? 'bay ' + d.bay : ''].filter(Boolean).join(' ') })) },
      events: events.map((e) => ({ at: iso(e.time), severity: String(first(e, 'message.severity') || '').toLowerCase(), message: String(e.log_message || '').slice(0, 300), node: first(e, 'node.name') })),
    };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
}

// ---------------------------------------------------------------- HPE MSA ------------------------------------------
const BLOCK = 512;
const msaHealth = (v) => { const s = String(v == null ? '' : v).toLowerCase(); return !s ? null : /^(ok|0)$/.test(s) ? 'ok' : /degrad|^1$/.test(s) ? 'degraded' : /fault|^2$/.test(s) ? 'fault' : 'unknown'; };
const msaBytes = (o, numKey, txtKey) => { const n = num(o[numKey]); if (n != null) return n * BLOCK; const m = /^([\d.]+)\s*([KMGTP]?B)$/i.exec(String(o[txtKey] || '').trim()); if (!m) return null; const mult = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12, PB: 1e15 }[m[2].toUpperCase()]; return Math.round(Number(m[1]) * mult); };
const list = (j, ...keys) => { for (const k of keys) if (Array.isArray(j && j[k])) return j[k]; return []; };
async function msa(cred, o = {}) {
  const t0 = Date.now(); let c = null, key = null;
  try {
    const s = cred.secret || {}; if (!s.username || !s.password) throw ERR('config', 'MSA needs a user name and password (monitor role)');
    c = client('msa', cred, o);
    const D = { datatype: 'json' };
    const ok = (j) => { const st = (list(j, 'status')[0]) || {}; return Number(st['return-code']) === 1 ? st.response : null; };
    try { key = ok(await c.call('/api/login', Object.assign({ Authorization: 'Basic ' + Buffer.from(`${s.username}:${s.password}`).toString('base64') }, D))); } catch (e) { if (e.code === 'tls' || e.code === 'config') throw e; }
    // older firmware: SHA-256 of "user_password" (MSA 2050 / 2052), then MD5 (MSA 2040 / 1040 / P2000 G3)
    for (const alg of ['sha256', 'md5']) { if (key) break; try { key = ok(await c.call('/api/login/' + crypto.createHash(alg).update(`${s.username}_${s.password}`).digest('hex'), D)); } catch (e) { if (e.code !== 'auth' && e.code !== 'protocol') throw e; } }
    if (!key) throw ERR('auth', 'MSA: sign-in refused (wrong user / password, or the user has no API access)');
    const H = Object.assign({ sessionKey: key }, D);
    const sys = list(await c.call('/api/show/system', H), 'system')[0] || {};
    const ctl = list(await c.call('/api/show/controllers', H), 'controllers');
    let pools = list(await c.call('/api/show/pools', H), 'pools');
    if (!pools.length) pools = list(await c.call('/api/show/disk-groups', H), 'disk-groups');   // linear storage
    const drv = list(await c.call('/api/show/disks', H), 'drives', 'disks');
    const vols = list(await c.call('/api/show/volumes', H), 'volumes');
    let ev = []; try { ev = list(await c.call('/api/show/events/last/50', H), 'events'); } catch (e) { if (e.code !== 'protocol') throw e; }
    return {
      ok: true, platform: 'msa', ms: Date.now() - t0,
      system: { name: sys['system-name'] || null, model: sys['product-id'] || sys['product-brand'] || null, version: (ctl[0] && (ctl[0]['sc-fw'] || ctl[0]['bundle-version'])) || null, serial: sys['midplane-serial-number'] || null, health: msaHealth(sys.health || sys['health-numeric']) },
      controllers: ctl.map((x) => ({ name: x['controller-id'] ? 'Controller ' + x['controller-id'] : x['durable-id'] || null, state: x.status || null, health: msaHealth(x.health || x['health-numeric']), model: x.model || null, serial: x['serial-number'] || null })),
      pools: pools.map((p) => { const sz = msaBytes(p, 'total-size-numeric', 'total-size') || msaBytes(p, 'size-numeric', 'size'), fr = msaBytes(p, 'total-avail-numeric', 'total-avail') || msaBytes(p, 'freespace-numeric', 'freespace'); const us = sz != null && fr != null ? sz - fr : null; return { name: p.name || null, owner: p.owner || p['preferred-owner'] || null, health: msaHealth(p.health || p['health-numeric']), state: p.status || null, size_bytes: sz, used_bytes: us, free_bytes: fr, used_pct: pct(us, sz) }; }),
      volumes: vols.map((v) => { const sz = msaBytes(v, 'size-numeric', 'size'), us = msaBytes(v, 'allocated-size-numeric', 'allocated-size'); return { name: v['volume-name'] || v.name || null, container: v['storage-pool-name'] || v['virtual-disk-name'] || null, pool: v['storage-pool-name'] || null, state: msaHealth(v.health || v['health-numeric']) === 'ok' ? 'online' : (v.health || null), type: v['volume-type'] || null, size_bytes: sz, used_bytes: us, used_pct: pct(us, sz) }; }),
      disks: { total: drv.length, reported: drv.length > 0, spares: drv.filter((d) => /spare/i.test(d.usage || '')).length,
        failed: drv.filter((d) => /fault|degrad/i.test(String(d.health || '')) || /fail|leftover/i.test(String(d.usage || ''))).map((d) => ({ name: d.location || d['durable-id'] || null, state: d.usage || d.health || null, model: d.model || null, serial: d['serial-number'] || null, location: d.location || null })) },
      events: ev.filter((e) => /error|critical|warning/i.test(e.severity || '')).map((e) => ({ at: iso(e['time-stamp']), severity: String(e.severity || '').toLowerCase(), message: String(e.message || '').slice(0, 300), node: e.controller || null })),
    };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
  finally { if (c && key) { try { await c.call('/api/exit', { sessionKey: key, datatype: 'json' }); } catch { /* best effort */ } } }
}

// ---------------------------------------------------------------- Synology DSM (SA / FS / RS / DS) ------------------
// DSM Web API over HTTPS, POST form calls (the password never travels in a URL). Only these API methods may be called;
// DSM has no read-only administrator role, so the allow-list is what keeps the reader read-only.
const SYN_ALLOW = { 'SYNO.API.Auth': ['login', 'logout'], 'SYNO.Core.System': ['info'], 'SYNO.Storage.CGI.Storage': ['load_info'] };
const SYN_ERR = { 400: 'wrong user name or password', 401: 'the account is disabled', 402: 'permission denied', 403: 'two-factor sign-in is required for this account - use a dedicated monitoring account without 2FA, restricted to this server’s IP',
  404: 'two-factor code failed', 406: 'two-factor sign-in is enforced for this account', 407: 'this server’s IP is blocked by DSM auto-block', 105: 'the account may not read storage information - it must be in the administrators group (DSM has no read-only administrator)', 119: 'session expired' };
const synHealth = (v) => { const t = String(v == null ? '' : v).toLowerCase(); return !t ? null : /^(normal|healthy|ok|initialized|background)/.test(t) ? 'ok' : /degrad|warning|attention|repair|rebuild|sync|expand/.test(t) ? 'degraded' : /crash|fail|broken|abnormal|not_exist|critical/.test(t) ? 'fault' : 'unknown'; };
async function synology(cred, o = {}) {
  const t0 = Date.now(); let sid = null, base = null, req = null, t = null;
  const call = async (api, method, version, extra) => {
    if (!SYN_ALLOW[api] || !SYN_ALLOW[api].includes(method)) throw ERR('config', `synology storage reading is read-only; refusing ${api}.${method}`);
    const form = new URLSearchParams(Object.assign({ api, method, version: String(version) }, extra || {}, sid ? { _sid: sid } : {})).toString();
    const r = await req(base + '/webapi/entry.cgi', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form,
      caFile: t.ca_file || undefined, pin: t.tls_fingerprint || undefined, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 60000 });
    if (r.status === 401 || r.status === 403) throw ERR('auth', `synology: HTTP ${r.status}`);
    if (r.status < 200 || r.status >= 300) throw ERR('protocol', `synology: ${api} answered HTTP ${r.status}`, { http: r.status });
    if (r.json == null) throw ERR('protocol', `synology: ${api} did not answer JSON (is this the DSM address, port 5001?)`);
    if (!r.json.success) { const code = Number(r.json.error && r.json.error.code); const msg = SYN_ERR[code] || `DSM error ${code}`;
      throw ERR(api === 'SYNO.API.Auth' && code !== 407 ? 'auth' : code === 105 || code === 402 ? 'authz' : code === 407 ? 'unreachable' : 'protocol', `synology: ${msg} (${api}.${method}, code ${code})`); }
    return r.json.data || {};
  };
  try {
    const s = cred.secret || {}; if (!s.username || !s.password) throw ERR('config', 'Synology needs a user name and password (a dedicated DSM account in the administrators group, 2FA off, limited to this server)');
    t = cred.target || {}; base = baseOf(t.base_url); req = o.request || httpc.request;
    sid = (await call('SYNO.API.Auth', 'login', 6, { account: s.username, passwd: s.password, session: 'ZyberonMonitor', format: 'sid' })).sid || null;
    if (!sid) throw ERR('auth', 'synology: sign-in returned no session');
    let sys = {}; try { sys = await call('SYNO.Core.System', 'info', 1); } catch (e) { if (e.code !== 'authz' && e.code !== 'protocol') throw e; }
    const st = await call('SYNO.Storage.CGI.Storage', 'load_info', 1);
    const arr = (x) => (Array.isArray(x) ? x : []);
    const disks = arr(st.disks), pools = arr(st.storagePools), vols = arr(st.volumes);
    const size = (o2, k) => num(first(o2, 'size.' + k, k));
    const failed = disks.filter((d) => synHealth(d.status) === 'fault' || synHealth(d.overview_status) === 'fault' || /crash|fail/i.test(String(d.smart_status || '')));
    const worstOf = (xs) => (xs.includes('fault') ? 'fault' : xs.includes('degraded') ? 'degraded' : xs.length ? 'ok' : null);
    return {
      ok: true, platform: 'synology', ms: Date.now() - t0,
      system: { name: sys.hostname || sys.server_name || null, model: sys.model || null, version: sys.firmware_ver || sys.version_string || null, serial: sys.serial || null,
        health: worstOf(pools.map((p) => synHealth(p.status)).concat(vols.map((v) => synHealth(v.status)), failed.length ? ['fault'] : [], sys.temperature_warn === true ? ['degraded'] : [])) },
      controllers: [{ name: 'DSM', state: sys.up_time ? 'up ' + sys.up_time : null, health: sys.temperature_warn === true ? 'degraded' : sys.model ? 'ok' : null, model: sys.model || null, serial: sys.serial || null }],
      pools: pools.map((p) => { const sz = size(p, 'total'), us = size(p, 'used'); return { name: p.desc || p.display_name || p.id || null, owner: p.raidType || p.device_type || null, health: synHealth(p.status), state: p.status || null, size_bytes: sz, used_bytes: us, free_bytes: sz != null && us != null ? sz - us : null, used_pct: pct(us, sz) }; }),
      volumes: vols.map((v) => { const sz = size(v, 'total'), us = size(v, 'used'); return { name: v.display_name || v.vol_path || v.id || null, container: v.pool_path || null, pool: v.pool_path || null, state: synHealth(v.status) === 'ok' ? 'online' : (v.status || null), type: v.fs_type || null, size_bytes: sz, used_bytes: us, used_pct: pct(us, sz) }; }),
      disks: { total: disks.length, reported: disks.length > 0, spares: arr(st.hotSpares).length || disks.filter((d) => /spare/i.test(String(d.used_by || d.status || ''))).length,
        failed: failed.map((d) => ({ name: d.name || d.id || null, state: d.status || d.overview_status || null, model: d.model || null, serial: d.serial || null, location: d.longName || d.container && d.container.str || null })) },
      events: [],
    };
  } catch (e) { return { ok: false, error_class: cls(e), error: e.message, presented: e.presented || null, ms: Date.now() - t0 }; }
  finally { if (sid) { try { await call('SYNO.API.Auth', 'logout', 6, { session: 'ZyberonMonitor' }); } catch { /* best effort */ } } }
}

async function test(kind, cred, o = {}) {
  const fn = { ontap, msa, synology }[kind];
  if (!fn) return { ok: false, error_class: 'config', error: 'unknown storage platform' };
  const r = await fn(cred, Object.assign({ captureUntrusted: true }, o));
  return r.ok ? { ok: true, message: `Connected: ${r.system.name || r.system.model || 'array'} - ${r.pools.length} pool(s), ${r.volumes.length} volume(s), ${r.disks.total} disk(s).` } : r;
}

module.exports = { ontap, msa, synology, test, guard, baseOf, SYN_ALLOW };
