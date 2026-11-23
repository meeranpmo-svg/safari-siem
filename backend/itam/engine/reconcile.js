// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Server & asset reconciliation: one place that says where IT Asset Management disagrees with what the sources report,
// and keeps approved records fed from them.
//   GET  /reconcile               {report, job, settings}                                            operator
//   POST /reconcile/run           recompute now (refresh + compare)                                   operator
//   POST /reconcile/sync-all      run every source now, then recompute; progress in GET /reconcile    admin
//   POST /reconcile/fix           {id}  apply the fix the issue offers (apply value / merge / approve) admin
//   POST /reconcile/accept        {id, reason}  "this difference is correct" - comes back if the values change  admin
//   POST /reconcile/unaccept      {id}                                                                admin
//   PUT  /reconcile/settings      {stale_days, alive_days, auto_refresh, auto_sync_hours}             admin
// Sync all also runs on its own every auto_sync_hours (default 24, 0 = off), so the CMDB follows its sources without a person
// pressing the button; the last run (every step, its result) is kept across restarts and shown with each source's freshness.
// Why it exists: once Asset Discovery approved a device, later AD / vCenter / Nutanix / Hyper-V sightings updated the
// discovery record only, so the asset kept the IP and OS from the day it was approved. REFRESH now pushes the linked
// device's current facts into the asset through the normal merge engine (source 'discovery'): a field an administrator
// edited by hand is locked and never overwritten, and a higher-priority source (agent, vCenter connector) still wins.
// COMPARE then lists what is still different, with the source that says so:
//   ip / os / name mismatch with the linked discovery device · server in a source but not in inventory (or unlinked
//   although an asset matches) · AD computer disabled / not logged on for 90 days while the asset is in use · retired
//   asset still seen · two active assets with the same IP or name · server / VM without IP or OS · not monitored by
//   Server Availability · Windows server not under the AI Windows Server Administrator · Exchange role disagreeing
//   between the asset and the AI Exchange Server Administrator · SIEM server list entries with no asset · network device
//   (switch / router / firewall) not in the AI Network Engineer, or not sent there and why (fix: send now).
// A source that cannot be read is reported as NOT CHECKED with its reason - never as "no differences".
// Fixes are explicit admin actions, audited: an applied value is a manual edit (it locks the field, as any human edit).
// Self-contained (stored collections), added with one registration line (install/add-reconcile.sh).
const fs = require('node:fs');
const { exchangeWhy, isWindows, winCheck } = require('./sysadmin-sync');
const { netCheck } = require('./netops-sync');

const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const SERVERISH = { server: 1, vm: 1, storage: 1 };
const DEV_SERVER = { server: 1, vm: 1, hypervisor: 1 };
const PASSIVE_TRUSTED = ['ad', 'vcenter', 'nutanix', 'hyperv', 'azure', 'aws'];
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const DAY = 86400000;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v == null ? '' : v).toLowerCase().trim();
const short = (n) => { const v = low(n); return IP_RE.test(v) ? '' : v.split('.')[0]; };
const SYS = { user: 'system:itam-reconcile', role: 'admin', ip: '' };
const SEV = { high: 3, warn: 2, info: 1 };

// OS → comparable key. Generic family vs specific version is NOT a mismatch ("Windows" vs "Windows Server 2019").
function osKey(s) {
  const v = low(s).replace(/microsoft|\(64-bit\)|\(32-bit\)|®|™/g, ' ').replace(/\s+/g, ' ');
  if (!v) return '';
  let m;
  if (/esxi/.test(v)) return 'esxi';
  if (/\bahv\b|nutanix/.test(v)) return 'ahv';
  if ((m = v.match(/windows server (20\d\d(?: r2)?)/))) return 'windows server ' + m[1];
  if ((m = v.match(/windows (1[01]|7|8\.1|8)\b/))) return 'windows ' + m[1];
  if ((m = v.match(/(?:red hat|rhel)[^0-9]*(\d+)/))) return 'rhel ' + m[1];
  for (const d of ['ubuntu', 'centos', 'oracle linux', 'suse', 'debian', 'rocky', 'almalinux']) {
    if (v.includes(d)) { m = v.slice(v.indexOf(d)).match(/(\d+)/); return d + (m ? ' ' + m[1] : ''); }
  }
  if (/windows/.test(v)) return 'windows';
  if (/linux/.test(v)) return 'linux';
  if (/\baix\b/.test(v)) return 'aix';
  if (/solaris|sunos/.test(v)) return 'solaris';
  return v.slice(0, 40);
}
function osDiffers(a, b) {
  const x = osKey(a), y = osKey(b);
  if (!x || !y || x === y) return false;
  if (x.startsWith(y) || y.startsWith(x)) return false;               // "windows" vs "windows server 2019"
  const fam = (k) => (/^windows/.test(k) ? 'windows' : /rhel|ubuntu|centos|oracle linux|suse|debian|rocky|alma|^linux/.test(k) ? 'linux' : k);
  if ((x === 'windows' || x === 'linux' || y === 'windows' || y === 'linux') && fam(x) === fam(y)) return false;
  return true;
}
const ipsOf = (a) => [a.mgmt_ip, a.ip].concat(a.ips || []).filter((x) => IP_RE.test(String(x || '')));
const mainIp = (a) => ipsOf(a)[0] || '';
const lastSeenOf = (a) => [a.last_seen].concat((a.sources || []).map((s) => s.last_seen)).filter(Boolean).sort().pop() || null;
const trustedMethods = (d) => Object.entries(d.methods || {}).filter(([, m]) => !m.untrusted).map(([k]) => k);

// ---- compare: pure, over what was read (the Python twin pyengine/reconcile_rules.py answers the same, step 6a) -------
//   inp = {assets, devices, accepted, settings, now, avail, targets, netdevs}   (the SIEM answers: {ok, data} | {ok:false, error})
function compareCore(inp) {
    const st = inp.settings, t = inp.now, at = new Date(t).toISOString();
    const all = inp.assets, active = all.filter((a) => !CLOSED[a.status]);
    const servers = active.filter((a) => SERVERISH[a.type]);
    const devList = inp.devices;
    const devById = new Map(devList.map((d) => [d.id, d]));
    const devOfAsset = new Map();
    for (const d of devList) if (d.asset_id) { const p = devOfAsset.get(d.asset_id); if (!p || p.last_seen < d.last_seen) devOfAsset.set(d.asset_id, d); }
    const byIp = new Map(), byMac = new Map(), bySerial = new Map(), byUuid = new Map(), byName = new Map();
    const push = (m, k, a) => { if (!k) return; const l = m.get(k) || []; l.push(a); m.set(k, l); };
    for (const a of active) {
      for (const ip of ipsOf(a)) push(byIp, ip, a);
      for (const m of [a.mac].concat(a.macs || [])) push(byMac, low(m), a);
      push(bySerial, low(a.serial), a); push(byUuid, low(a.uuid), a); push(byName, short(a.name), a);
    }
    const issues = [];
    const add = (o) => issues.push(Object.assign({ sev: 'warn' }, o));
    const recent = (iso, days) => iso && t - Date.parse(iso) <= days * DAY;
    const lockedBy = (a, k) => (a.locked && a.locked[k] ? 'manual edit (locked)' : (a.prov && a.prov[k]) || '');

    // 1. asset vs its linked discovery device
    for (const a of servers) {
      const d = devOfAsset.get(a.id) || (a.discovery && devById.get(a.discovery.device_id));
      if (!d || !recent(d.last_seen, st.stale_days)) continue;
      const src = trustedMethods(d).join(', ') || 'discovery';
      if (d.ip && mainIp(a) && !(d.ips || []).includes(mainIp(a)) && !ipsOf(a).includes(d.ip))
        add({ id: `ip:${a.id}`, kind: 'ip_mismatch', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a), field: 'mgmt_ip', have: mainIp(a), found: d.ip, source: src, held_by: lockedBy(a, 'mgmt_ip'), fix: 'apply' });
      if (d.os && a.os && osDiffers(a.os, d.os))
        add({ id: `os:${a.id}`, kind: 'os_mismatch', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a), field: 'os', have: a.os, found: d.os, source: src, held_by: lockedBy(a, 'os'), fix: 'apply' });
      const dn = short(d.hostname || d.fqdn);
      if (dn && short(a.name) && dn !== short(a.name))
        add({ id: `name:${a.id}`, kind: 'name_mismatch', sev: 'info', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a), field: 'name', have: a.name, found: d.hostname || d.fqdn, source: src, held_by: lockedBy(a, 'name'), fix: 'apply' });
      const ad = d.extra && d.extra.ad;
      if (ad && d.methods && d.methods.ad && a.status === 'in_use') {
        if (ad.enabled === false) add({ id: `addis:${a.id}`, kind: 'ad_disabled', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a), have: 'in use', found: 'computer account disabled in AD' + (ad.ou ? ' (' + ad.ou + ')' : ''), source: 'ad' });
        else if (ad.last_logon && !recent(ad.last_logon, st.ad_logon_days)) add({ id: `adold:${a.id}`, kind: 'ad_stale', sev: 'info', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a), have: 'in use', found: 'last AD logon ' + ad.last_logon.slice(0, 10), source: 'ad' });
      }
    }
    // 2. retired / disposed but still seen
    for (const a of all.filter((x) => CLOSED[x.status] && SERVERISH[x.type])) {
      const d = devOfAsset.get(a.id);
      if (d && recent(d.last_seen, st.alive_days)) add({ id: `alive:${a.id}`, kind: 'retired_alive', sev: 'high', asset_id: a.id, device_id: d.id, name: a.name, ip: mainIp(a) || d.ip, have: a.status, found: 'seen ' + d.last_seen.slice(0, 16).replace('T', ' ') + ' by ' + (trustedMethods(d).join(', ') || 'discovery'), source: 'discovery' });
    }
    // 3. server in a source but not in inventory, or unlinked although an asset matches
    for (const d of devList) {
      if (d.status !== 'new' || d.asset_id || !DEV_SERVER[d.type] || !recent(d.last_seen, st.stale_days)) continue;
      const meth = trustedMethods(d);
      if (!meth.length) continue;
      const match = [].concat(...(d.macs || []).map((m) => byMac.get(low(m)) || []), bySerial.get(low(d.serial)) || [], byUuid.get(low(d.extra && d.extra.vcenter && d.extra.vcenter.uuid)) || [])[0]
        || (d.ip && (byIp.get(d.ip) || []).length === 1 && short(byIp.get(d.ip)[0].name) === short(d.hostname) ? byIp.get(d.ip)[0] : null);
      if (match) add({ id: `link:${d.id}`, kind: 'unlinked', sev: 'info', device_id: d.id, asset_id: match.id, name: d.hostname || d.ip, ip: d.ip, have: 'asset ' + (match.name || match.id), found: 'discovery result not linked to it', source: meth.join(', '), fix: 'merge' });
      else if (meth.some((m) => PASSIVE_TRUSTED.includes(m))) add({ id: `new:${d.id}`, kind: 'not_in_inventory', device_id: d.id, name: d.hostname || d.ip, ip: d.ip, have: 'not in inventory', found: (d.type || 'server') + (d.os ? ' · ' + d.os : ''), source: meth.join(', '), fix: 'approve' });
    }
    // 4. duplicates, incomplete, stale
    const dupSeen = new Set();
    for (const [k, list] of [...byIp.entries()].map(([k, l]) => ['IP ' + k, l]).concat([...byName.entries()].map(([k, l]) => ['name ' + k, l]))) {
      const l = list.filter((a) => SERVERISH[a.type]);
      const ids = [...new Set(l.map((a) => a.id))];
      if (ids.length < 2 || dupSeen.has(k)) continue;
      dupSeen.add(k);
      add({ id: `dup:${k}`, kind: 'duplicate', name: l.map((a) => a.name || a.id).join(' / ').slice(0, 160), ip: k.startsWith('IP ') ? k.slice(3) : mainIp(l[0]), asset_ids: ids, have: ids.length + ' assets share ' + k, found: '', source: 'inventory' });
    }
    for (const a of servers) {
      if (!mainIp(a)) add({ id: `noip:${a.id}`, kind: 'missing_ip', sev: 'info', asset_id: a.id, name: a.name, have: 'no IP address', found: '', source: 'inventory' });
      if (!a.os && a.type !== 'storage') add({ id: `noos:${a.id}`, kind: 'missing_os', sev: 'info', asset_id: a.id, name: a.name, ip: mainIp(a), have: 'no operating system', found: '', source: 'inventory' });
      const ls = lastSeenOf(a), d = devOfAsset.get(a.id);
      if (ls && !recent(ls, st.stale_days) && !(d && recent(d.last_seen, st.stale_days))) add({ id: `stale:${a.id}`, kind: 'stale', sev: 'info', asset_id: a.id, name: a.name, ip: mainIp(a), have: a.status, found: 'no source has reported it since ' + ls.slice(0, 10), source: 'inventory' });
    }
    // 5. SIEM: Server Availability + AI Server Administrators
    const { avail, targets, netdevs } = inp;
    const sources = {
      inventory: { ok: true, servers: servers.length },
      discovery: { ok: true, linked: devList.filter((d) => d.asset_id).length, servers_seen: devList.filter((d) => DEV_SERVER[d.type] && recent(d.last_seen, st.stale_days)).length },
      availability: avail.ok ? { ok: true, hosts: Object.keys((avail.data && avail.data.hosts) || {}).length } : { ok: false, error: avail.error },
      server_admins: targets.ok ? { ok: true, servers: ((targets.data && targets.data.items) || []).length } : { ok: false, error: targets.error },
      network_engineer: netdevs.ok ? { ok: true, devices: ((netdevs.data && netdevs.data.items) || []).length } : { ok: false, error: netdevs.error },
    };
    if (avail.ok) {
      const map = (avail.data && avail.data.hosts) || {};
      for (const a of servers) {
        const ip = mainIp(a);
        if (!ip || a.type === 'storage') continue;
        const h = ipsOf(a).map((x) => map[x]).find(Boolean);
        if (!h) add({ id: `nomon:${a.id}`, kind: 'not_monitored', asset_id: a.id, name: a.name, ip, have: 'in inventory', found: 'not in Server Availability', source: 'availability' });
        else if (h.s === 'online' && CLOSED[a.status]) { /* covered by retired_alive when discovery saw it */ }
      }
      for (const a of all.filter((x) => CLOSED[x.status] && SERVERISH[x.type])) {
        const h = ipsOf(a).map((x) => map[x]).find(Boolean);
        if (h && h.s === 'online' && !issues.some((i) => i.id === `alive:${a.id}`)) add({ id: `alive:${a.id}`, kind: 'retired_alive', sev: 'high', asset_id: a.id, name: a.name, ip: mainIp(a), have: a.status, found: 'answering in Server Availability', source: 'availability' });
      }
    }
    if (targets.ok) {
      const items = (targets.data && targets.data.items) || [];
      const tByIp = new Map(items.map((x) => [x.ip, x]));
      for (const a of active) {
        if (!isWindows(a)) continue;
        const tg = ipsOf(a).map((x) => tByIp.get(x)).find(Boolean), why = exchangeWhy(a);
        if (!tg) { add({ id: `noadm:${a.id}`, kind: 'not_in_server_admin', asset_id: a.id, name: a.name, ip: mainIp(a), have: 'Windows server in inventory', found: 'not under the AI Windows Server Administrator', source: 'server_admins' }); continue; }
        const isEx = (tg.roles || []).includes('exchange');
        if (why && !isEx) add({ id: `exch:${a.id}`, kind: 'exchange_mismatch', asset_id: a.id, name: a.name, ip: mainIp(a), have: 'Exchange (' + why + ')', found: 'not an Exchange server in the AI Exchange Server Administrator', source: 'server_admins' });
        if (!why && isEx) add({ id: `exch:${a.id}`, kind: 'exchange_mismatch', sev: 'info', asset_id: a.id, name: a.name, ip: mainIp(a), have: 'nothing in the asset says Exchange', found: 'Exchange server in the AI Exchange Server Administrator', source: 'server_admins' });
      }
      // Windows / Exchange servers the sync does not send, and why (no IP, wrong type …)
      const dIp = (a) => mainIp(a) || ((devOfAsset.get(a.id) || {}).ip || '');
      for (const a of active) { const c = winCheck(a, dIp); if (!c.ok && c.why !== 'not a Windows server' && c.why !== 'retired') add({ id: `admskip:${a.id}`, kind: 'server_admin_not_synced', sev: 'info', asset_id: a.id, name: a.name, ip: dIp(a), have: exchangeWhy(a) ? 'Exchange (' + exchangeWhy(a) + ')' : 'Windows server', found: 'not sent to the AI Server Administrators: ' + c.why, source: 'inventory' }); }
      for (const tg of items) if (tg.ip && !byIp.has(tg.ip)) add({ id: `orphan:${tg.ip}`, kind: 'admin_not_in_inventory', sev: 'info', name: tg.name, ip: tg.ip, have: 'not in inventory', found: 'in the AI Server Administrators (' + (tg.roles || []).join(', ') + ')', source: 'server_admins' });
    }
    // 6. network devices → AI Network Engineer (sent by netops-sync; this says which are missing and why)
    if (netdevs.ok) {
      const nIps = new Set(((netdevs.data && netdevs.data.items) || []).map((d) => d.ip));
      const devIp = (a) => mainIp(a) || ((devOfAsset.get(a.id) || {}).ip || '');
      for (const a of active) {
        const c = netCheck(a, devIp);
        if (c.ok) { const ip = devIp(a); if (!nIps.has(ip)) add({ id: `nonet:${a.id}`, kind: 'not_in_network_engineer', asset_id: a.id, name: a.name, ip, have: 'network device in inventory', found: 'not in the AI Network Engineer', source: 'network_engineer', fix: 'netops' }); }
        else if (c.why !== 'not a network device' && c.why !== 'retired') add({ id: `netskip:${a.id}`, kind: 'network_not_synced', sev: 'info', asset_id: a.id, name: a.name, ip: devIp(a), have: [a.vendor, a.model].filter(Boolean).join(' ') || a.type, found: 'not sent to the AI Network Engineer: ' + c.why, source: 'inventory' });
      }
    }
    // accepted differences stay hidden only while the values are the same
    const acc = new Map(inp.accepted.map((r) => [r.id, r]));
    for (const i of issues) { i.sig = [i.have, i.found].join('|'); const r = acc.get(i.id); if (r && r.sig === i.sig) i.accepted = { by: r.by, at: r.at, reason: r.reason }; }
    issues.sort((x, y) => (!!x.accepted - !!y.accepted) || (SEV[y.sev] - SEV[x.sev]) || String(x.kind).localeCompare(y.kind) || String(x.name || '').localeCompare(String(y.name || '')));
    const counts = {};
    for (const i of issues) if (!i.accepted) counts[i.kind] = (counts[i.kind] || 0) + 1;
    return { at, sources, issues, counts, open: issues.filter((i) => !i.accepted).length };
}

// configured devices that are not in the asset register (one JS pass after the shared rules, same issue shape): the hosts
// of monitored databases (Database Servers - fix: link it there), and hosts added to Server Availability by hand that no
// active asset has. "Wherever a device is configured, it is aligned with an asset."
function alignmentIssues(inp) {
  const out = [], active = inp.assets.filter((a) => !CLOSED[a.status]), byIp = new Set();
  for (const a of active) for (const ip of ipsOf(a)) byIp.add(ip);
  for (const d of inp.devices) if (d.asset_id && d.ip) byIp.add(d.ip);
  for (const s of ((inp.dbservers && inp.dbservers.servers) || [])) if (!s.asset) out.push({ id: `dbsrv:${s.ip}`, kind: 'db_server_not_in_inventory', sev: 'warn', name: s.host, ip: s.ip,
    have: 'not in inventory', found: 'runs ' + (s.databases || []).map((x) => x.instance || x.service).filter(Boolean).join(', ') + (s.asset_suggestion ? ' (same name as asset ' + s.asset_suggestion.name + ' - confirm in Database Servers)' : ''), source: 'database_servers' });
  if (inp.avail && inp.avail.ok) for (const [ip, h] of Object.entries((inp.avail.data && inp.avail.data.hosts) || {})) if (IP_RE.test(ip) && !byIp.has(ip)) out.push({ id: `monorphan:${ip}`, kind: 'monitored_not_in_inventory', sev: 'info', name: (h && (h.name || h.n)) || ip, ip,
    have: 'not in inventory', found: 'monitored in Server Availability', source: 'availability' });
  return out;
}
function withAlignment(report, inp) {
  const extra = alignmentIssues(inp); if (!extra.length && !inp.dbservers) return report;
  const acc = new Map(inp.accepted.map((r) => [r.id, r]));
  for (const i of extra) { i.sig = [i.have, i.found].join('|'); const r = acc.get(i.id); if (r && r.sig === i.sig) i.accepted = { by: r.by, at: r.at, reason: r.reason }; }
  report.issues = report.issues.concat(extra).sort((x, y) => (!!x.accepted - !!y.accepted) || (SEV[y.sev] - SEV[x.sev]) || String(x.kind).localeCompare(y.kind) || String(x.name || '').localeCompare(String(y.name || '')));
  report.counts = {}; for (const i of report.issues) if (!i.accepted) report.counts[i.kind] = (report.counts[i.kind] || 0) + 1;
  report.open = report.issues.filter((i) => !i.accepted).length;
  if (report.sources) report.sources.database_servers = inp.dbservers ? { ok: true, servers: (inp.dbservers.servers || []).length } : { ok: false, error: 'Database Servers not installed' };
  return report;
}

// only the fields the rules read cross to Python (never the lifecycle history)
const A_KEYS = ['id', 'name', 'status', 'type', 'mgmt_ip', 'ip', 'ips', 'mac', 'macs', 'serial', 'uuid', 'os', 'locked', 'prov', 'discovery', 'last_seen', 'tags', 'software', 'model', 'notes', 'vendor'];
const D_KEYS = ['id', 'asset_id', 'status', 'type', 'last_seen', 'methods', 'ip', 'ips', 'os', 'hostname', 'fqdn', 'macs', 'serial'];
const pick = (o, ks) => { const r = {}; for (const k of ks) if (o[k] !== undefined) r[k] = o[k]; return r; };
const slimA = (a) => Object.assign(pick(a, A_KEYS), Array.isArray(a.sources) ? { sources: a.sources.map((s) => ({ last_seen: s && s.last_seen })) } : {});
const slimD = (d) => Object.assign(pick(d, D_KEYS), d.extra ? { extra: { ad: d.extra.ad, vcenter: d.extra.vcenter ? { uuid: d.extra.vcenter.uuid } : d.extra.vcenter } } : {});
function createReconcile(app, opts = {}) {
  const { store } = app;
  const assetsCol = store.collection('assets'), devs = store.collection('disc_devices');
  const accepted = store.collection('reconcile_accepted'), conf = store.collection('reconcile_settings');
  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
  const request = opts.request || require('./discovery/httpc').request;
  const read = opts.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  let report = null, job = (conf.get('last_sync') || {}).value || null, running = null;   // the last Sync all survives a restart

  function settings() { return Object.assign({ stale_days: 30, alive_days: 7, ad_logon_days: 90, auto_refresh: true, auto_sync_hours: 24 }, (conf.get('settings') || {}).values || {}); }

  // ---- SIEM (Server Availability map, AI Server Administrators list), read-only ------------------------------------
  function secret() {
    if (!sc.secret_file) throw bad('SIEM link not configured (discovery.siem.secret_file)');
    let v; try { v = String(read(sc.secret_file)).trim(); } catch (e) { throw bad(`SIEM proxy secret file not readable (${e.code || 'error'})`); }
    if (v.startsWith('{')) { try { v = String(JSON.parse(v).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw bad('SIEM proxy secret missing');
    return v;
  }
  async function siemGet(path) {
    try {
      const r = await request(base + prefix + path, { method: 'GET', headers: { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': SYS.user, 'X-Auth-Role': 'admin', Accept: 'application/json' }, timeoutMs: 20000 });
      if (r.status === 404) return { ok: false, error: 'not installed in the SIEM (404) - update the SIEM engine' };
      if (r.status !== 200 || !r.json) return { ok: false, error: `SIEM answered HTTP ${r.status}` };
      return { ok: true, data: r.json };
    } catch (e) { return { ok: false, error: e.status ? e.message : `SIEM not reachable (${e.code || e.message || 'error'})` }; }
  }

  // ---- refresh: approved devices → their assets (merge engine; locked fields and higher sources win) ---------------
  function refresh() {
    const out = { assets_updated: 0, fields: {} };
    if (!app.assets || typeof app.assets.upsert !== 'function') return out;
    for (const d of devs.all((x) => x.asset_id && (x.status === 'approved' || x.status === 'merged'))) {
      if (d.refreshed_at && d.refreshed_at >= d.last_seen) continue;
      if (!trustedMethods(d).length) continue;                         // self-asserted only (agent-key Hyper-V)
      const a = assetsCol.get(d.asset_id);
      if (!a || CLOSED[a.status]) continue;
      const f = {};
      if (d.hostname && !IP_RE.test(d.hostname)) f.name = d.hostname;
      if (d.ip) f.mgmt_ip = d.ip;
      if (d.os) f.os = d.os;
      if (d.serial) f.serial = d.serial;
      if (d.model) f.model = d.model;
      if (d.mac) { f.mac = d.mac; f.macs = d.macs; }
      if (d.extra && d.extra.vcenter && d.extra.vcenter.uuid) f.uuid = d.extra.vcenter.uuid;
      try {
        const r = app.assets.upsert(f, 'discovery', { source_id: d.id, at: d.last_seen }, { forceAssetId: d.asset_id });
        if (r.changed && r.changed.length) { out.assets_updated++; for (const k of r.changed) out.fields[k] = (out.fields[k] || 0) + 1; }
      } catch { continue; }
      devs.patch(d.id, (x) => { x.refreshed_at = d.last_seen; });
    }
    return out;
  }

  // ---- compare: read everything, then the rules run in Python (pyengine/reconcile_rules.py) - config reconcile.engine =
  // "node", an injected request (tests) or no Python → compareCore() above
  const py = opts.request || ((app.config && app.config.reconcile) || {}).engine === 'node' ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: (((app.config && app.config.discovery) || {}).python_bin) || '/opt/sentra-siem/pyenv/bin/python3', timeoutMs: 5 * 60000 }); } catch (e) { return null; } })();
  async function compare() {
    const [avail, targets, netdevs] = await Promise.all([siemGet('/netops/avail/map'), siemGet('/sysadmin/targets'), siemGet('/netops/devices')]);
    const inp = { assets: assetsCol.all(), devices: devs.all(), accepted: accepted.all(), settings: settings(), now: now(), avail, targets, netdevs };
    let dbservers = null; try { const S = (app.addons || {}).dbServers; dbservers = S ? S.view() : null; } catch (e) { dbservers = null; }
    const align = Object.assign({}, inp, { dbservers });
    if (py) {
      const r = await py.call('rules.reconcile', Object.assign({}, inp, { assets: inp.assets.map(slimA), devices: inp.devices.map(slimD) }));
      if (r && Array.isArray(r.issues)) return withAlignment(Object.assign(r, { engine: 'python' }), align);
      // never a missing report because of the new engine: Node.js answers and the report says why
      return withAlignment(Object.assign(compareCore(inp), { engine: 'node (python ' + (r && r.error_class === 'missing_python' ? 'unavailable' : 'failed') + ': ' + String((r && r.error) || 'no answer').slice(0, 200) + ')' }), align);
    }
    return withAlignment(Object.assign(compareCore(inp), { engine: 'node' }), align);
  }

  async function run(who = SYS) {
    if (running) return running;
    running = (async () => {
      try {
        const r = settings().auto_refresh ? refresh() : { assets_updated: 0, fields: {}, off: true };
        const c = await compare();
        report = Object.assign(c, { by: who.user, refresh: r });
        if (r.assets_updated) audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.refresh', target: 'assets', detail: r });
        return report;
      } finally { running = null; }
    })();
    return running;
  }

  // ---- Sync all now: every source, then recompute ------------------------------------------------------------------
  function syncAll(who) {
    if (job && job.state === 'running') return { job };
    const ad = app.addons || {}, steps = [];
    const plat = (key, col, label) => {
      const mod = ad[key];
      if (!mod || typeof mod.sync !== 'function') { steps.push({ name: label, state: 'not installed' }); return; }
      const list = store.collection(col).all((p) => p.enc);
      if (!list.length) { steps.push({ name: label, state: 'nothing configured' }); return; }
      for (const p of list) steps.push({ name: label + ': ' + (p.label || p.id), fn: () => mod.sync(p.id, who) });
    };
    plat('virt', 'virt_platforms', 'Virtualization');
    plat('storage', 'storage_platforms', 'Storage');
    plat('backup', 'backup_platforms', 'Backup');
    // discovery scopes that only READ systems of record (AD, vCenter, Nutanix, Hyper-V, cloud); scans that send packets
    // (sweep / SNMP / ports) keep their own schedule and safety gate and are not started from here
    const disc = app.discovery;
    if (disc && typeof disc.listScopes === 'function') {
      let scopes = []; try { scopes = disc.listScopes() || []; } catch { scopes = []; }
      if (scopes.items) scopes = scopes.items;
      const ACTIVE = require('./discovery/scopes').ACTIVE;
      for (const s of scopes) {
        if (s.status !== 'active') continue;
        const on = Object.entries(s.methods || {}).filter(([, m]) => m && m.enabled).map(([k]) => k);
        if (!on.length) continue;
        if (on.some((k) => ACTIVE.includes(k))) { steps.push({ name: 'Discovery: ' + s.name, state: 'skipped - this scope sends packets (' + on.filter((k) => ACTIVE.includes(k)).join(', ') + '); it runs on its schedule' }); continue; }
        steps.push({ name: 'Discovery: ' + s.name + ' (' + on.join(', ') + ')', fn: async () => { const r = disc.startRun(s.id, { trigger: 'manual', who }); if (typeof disc.wait === 'function') { let to; try { await Promise.race([disc.wait(r.id), new Promise((ok) => { to = setTimeout(ok, 10 * 60000); if (to.unref) to.unref(); })]); } catch { /* still running */ } clearTimeout(to); } return { run: r.id }; } });
      }
    }
    // the other sources that write into the CMDB: Endpoint Central computers, vCenter / Nutanix capacity facts, licence facts
    const meCfg = (store.collection('me_config').get('cfg') || {}).ec || {};
    if (!ad.manageengine || typeof ad.manageengine.syncEc !== 'function') steps.push({ name: 'Endpoint Central', state: 'not installed' });
    else if (!meCfg.base_url || !meCfg.enc) steps.push({ name: 'Endpoint Central', state: 'nothing configured' });
    else steps.push({ name: 'Endpoint Central', fn: () => ad.manageengine.syncEc(who) });
    if (ad.virtCapacity && typeof ad.virtCapacity.run === 'function') steps.push({ name: 'vCenter / Nutanix capacity facts', fn: async () => { const r = await ad.virtCapacity.run(who); const L = Array.isArray(r) ? r : (r && r.results) || []; const bad = L.filter((x) => x && x.ok === false); return bad.length && bad.length === L.length ? { ok: false, error: bad.map((x) => x.label + ': ' + x.error).join('; ') } : { hosts: L.reduce((a, x) => a + (x.hosts || 0), 0), vms: L.reduce((a, x) => a + (x.vms || 0), 0) }; } });
    else steps.push({ name: 'vCenter / Nutanix capacity facts', state: 'not installed' });
    if (ad.licenceSync && typeof ad.licenceSync.run === 'function') steps.push({ name: 'Licence facts', fn: () => ad.licenceSync.run(who) });
    else steps.push({ name: 'Licence facts', state: 'not installed' });
    for (const [key, label, fn] of [['siemIp', 'IP / MAC from SIEM logs', 'safeRun'], ['sysadminSync', 'AI Server Administrators', 'run'], ['netopsSync', 'AI Network Engineer', 'run'], ['infraSync', 'Infrastructure Automation', 'run']]) {
      if (ad[key] && typeof ad[key][fn] === 'function') steps.push({ name: label, fn: () => ad[key][fn](who) });
      else steps.push({ name: label, state: 'not installed' });
    }
    job = { state: 'running', started_at: new Date(now()).toISOString(), by: who.user, trigger: who.user === SYS.user ? 'schedule' : 'manual', steps: steps.map((s) => ({ name: s.name, state: s.state || 'waiting' })) };
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.sync_all', target: 'sources', detail: { steps: steps.length } });
    const cur = job;
    (async () => {
      const brief = (r) => { if (!r || typeof r !== 'object') return ''; if (r.sync) r = r.sync; if (r.ok === false) return 'failed: ' + String(r.error || 'error').slice(0, 160); const keys = ['computers', 'hosts', 'vms', 'approved', 'added', 'arrays', 'jobs', 'updated', 'filled', 'run']; return keys.filter((k) => r[k] != null && !(Array.isArray(r[k]) && !r[k].length)).map((k) => k + ' ' + (Array.isArray(r[k]) ? r[k].length : r[k])).join(' · '); };
      await Promise.all(steps.map(async (s, i) => {
        if (!s.fn) return;
        cur.steps[i].state = 'running';
        try { const r = await s.fn(); const b = brief(r); cur.steps[i].state = /^failed/.test(b) ? 'failed' : 'done'; cur.steps[i].detail = b; }
        catch (e) { cur.steps[i].state = 'failed'; cur.steps[i].detail = String(e.message || e).slice(0, 200); }
      }));
      try { await run(who); } catch { /* the report keeps its previous version */ }
      cur.state = 'done'; cur.finished_at = new Date(now()).toISOString();
      cur.failed = cur.steps.filter((x) => x.state === 'failed').length;
      conf.put({ id: 'last_sync', value: cur });
    })();
    return { job };
  }

  // ---- fixes ---------------------------------------------------------------------------------------------------------
  async function fix(id, who) {
    const cur = await compare();
    const i = cur.issues.find((x) => x.id === String(id || ''));
    if (!i) throw bad('this difference is no longer there - refresh the page', 409);
    let result;
    if (i.fix === 'apply') result = app.assets.edit(i.asset_id, { [i.field]: i.found }, who);
    else if (i.fix === 'merge') result = app.discovery.merge(i.device_id, i.asset_id, who);
    else if (i.fix === 'approve') result = app.discovery.approve(i.device_id, who);
    else if (i.fix === 'netops') { const ns = app.addons && app.addons.netopsSync; if (!ns) throw bad('the AI Network Engineer sync is not installed (install/add-netops-sync.sh)', 409); result = await ns.run(who); if (!result.ok) throw bad(result.error || 'sync failed', 502); const f = result.failed.find((x) => x.asset_id === i.asset_id); if (f) throw bad('the AI Network Engineer refused it: ' + f.error, 502); }
    else throw bad('this difference has no automatic fix - correct it at the source or accept it', 400);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.fix', target: i.asset_id || i.device_id, detail: { kind: i.kind, field: i.field || null, from: i.have, to: i.found, source: i.source } });
    await run(who);
    return { fixed: i.id, kind: i.kind, report, result: result && (result.asset_id || (result.asset && result.asset.id)) || null };
  }
  async function accept(b, who) {
    const why = String(b.reason || '').trim().slice(0, 300);
    if (why.length < 3) throw bad('give a reason (min 3 characters) - it is kept with the decision');
    const cur = await compare();
    const i = cur.issues.find((x) => x.id === String(b.id || ''));
    if (!i) throw bad('this difference is no longer there - refresh the page', 409);
    accepted.put({ id: i.id, sig: i.sig, kind: i.kind, reason: why, by: who.user, at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.accept', target: i.id, detail: { kind: i.kind, have: i.have, found: i.found, reason: why } });
    return run(who);
  }
  async function unaccept(b, who) {
    if (!accepted.get(String(b.id || ''))) throw bad('not accepted', 404);
    accepted.remove(String(b.id));
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.unaccept', target: String(b.id), detail: null });
    return run(who);
  }
  function putSettings(b, who) {
    const v = settings();
    const num = (k, lo, hi) => { if (k in b) { const n = Number(b[k]); if (!Number.isInteger(n) || n < lo || n > hi) throw bad(`${k} must be ${lo}-${hi}`); v[k] = n; } };
    num('stale_days', 1, 365); num('alive_days', 1, 90); num('ad_logon_days', 7, 730); num('auto_sync_hours', 0, 168);
    if ('auto_refresh' in b) v.auto_refresh = b.auto_refresh === true;
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'reconcile.settings', target: 'settings', detail: v });
    return { settings: v };
  }
  // how fresh each CMDB source is: the newest sighting per discovery method and the last read of each connected platform
  function freshness() {
    const t = now(), out = [], st = settings(), age = (at) => (at ? Math.round((t - Date.parse(at)) / 3600000) : null);
    const byMethod = {};
    for (const d of store.collection('disc_devices').all()) for (const [m, v] of Object.entries(d.methods || {})) { const at = (v && (v.last_seen || v.at)) || d.last_seen; if (at && (!byMethod[m] || at > byMethod[m])) byMethod[m] = at; }
    for (const [m, at] of Object.entries(byMethod)) out.push({ source: 'Discovery · ' + m, last: at, age_h: age(at) });
    for (const [col, label] of [['virt_platforms', 'Virtualization'], ['storage_platforms', 'Storage'], ['backup_platforms', 'Backup']]) for (const p of store.collection(col).all()) { const at = (p.last_sync && p.last_sync.at) || null; out.push({ source: label + ' · ' + (p.label || p.id), last: at, age_h: age(at), error: p.last_sync && p.last_sync.ok === false ? p.last_sync.error || 'failed' : null }); }
    const ec = store.collection('me_config').get('cfg'); if (ec && ec.ec && ec.ec.enc) { const ls = ec.ec.last_sync || null, at = ls && ls.at || null; out.push({ source: 'Endpoint Central', last: at, age_h: age(at), error: ls && ls.ok === false ? ls.error || 'failed' : null }); }
    const limit = Math.max(24, (st.auto_sync_hours || 24) * 2);
    for (const x of out) x.stale = x.age_h == null || x.age_h > limit;
    return out.sort((a, b) => (b.stale - a.stale) || String(a.source).localeCompare(String(b.source)));
  }
  function view() { return { report, job, settings: settings(), running: !!running, freshness: freshness() }; }
  function tick() {
    const p = run();   // a failure reaches the job register (engine/errors.js) through the promise tick returns
    // the scheduled Sync all: when the last one is older than auto_sync_hours (and nothing is running)
    const h = settings().auto_sync_hours;
    if (h > 0 && !(job && job.state === 'running')) {
      const last = job && (job.finished_at || job.started_at) ? Date.parse(job.finished_at || job.started_at) : 0;
      if (now() - last >= h * 3600000) { try { syncAll(SYS); } catch (e) { if (app.log) app.log.warn('reconcile: scheduled Sync all not started - the next tick tries again', { err: e.message }); } }
    }
    return p;
  }
  return { run, refresh, compare, syncAll, fix, accept, unaccept, putSettings, view, tick: guardOf(app, 'reconcile.tick', tick),  /* a direct call (Sync now, tests) can never reject unhandled */ freshness };
}

function registerReconcile(srv, app) {
  const R = createReconcile(app);
  srv.route('GET', '/reconcile', async (ctx) => { ctx.need('operator'); if (!R.view().report) await R.run(); return R.view(); });
  srv.route('POST', '/reconcile/run', async (ctx) => { ctx.need('operator'); await R.run(ctx.who); return R.view(); });
  srv.route('POST', '/reconcile/sync-all', (ctx) => { ctx.need('admin'); return R.syncAll(ctx.who); });
  srv.route('POST', '/reconcile/fix', async (ctx) => { ctx.need('admin'); return R.fix((ctx.body || {}).id, ctx.who); });
  srv.route('POST', '/reconcile/accept', async (ctx) => { ctx.need('admin'); await R.accept(ctx.body || {}, ctx.who); return R.view(); });
  srv.route('POST', '/reconcile/unaccept', async (ctx) => { ctx.need('admin'); await R.unaccept(ctx.body || {}, ctx.who); return R.view(); });
  srv.route('PUT', '/reconcile/settings', (ctx) => { ctx.need('admin'); return R.putSettings(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'reconcile.tick', R.tick), 150000), t2 = setInterval(guardOf(app, 'reconcile.tick', R.tick), 15 * 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).reconcile = R;
  return R;
}

module.exports = { alignmentIssues, createReconcile, registerReconcile, osKey, osDiffers, compareCore, slimA, slimD };
