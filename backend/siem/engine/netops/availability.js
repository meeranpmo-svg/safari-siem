// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Server / IT device availability (SAMA CSF business-continuity and patch-management evidence).
 *   createAvailability({ state, config, log, ch, evidence?, discovery?, probe?, now? })
 *     .start() .stop() .scan() .list() .get(id) .put(input, by) .remove(id, by) .importHosts(items, by)
 *     .importFromDiscovery(who) .importFromInventory(who) .settings() .setSettings(s, by) .view() .detail(id) .ipMap()
 * Inventory sync (default on, every 10 min): every IT Asset Management asset of type server / vm / storage (or tagged
 * "cloud") with a management IP is monitored; hosts added this way (source "inventory") are removed again when the
 * asset is retired, disposed, lost, deleted or loses its IP. Hosts added by hand are never removed by the sync.
 * Checks every `interval_s` (60 s): ping, then TCP to the usual service ports (Windows 3389/445/135, Linux 22, other
 * 22/443/80/3389) — a host is ONLINE when any answers. It turns OFFLINE only after 2 failed checks in a row.
 * Kept per host: current status and since when (state changes in "avail_events", 90 days), availability % over
 * 24 h / 7 d / 30 d (ClickHouse net_metrics "host_up"), last restart and unexpected shutdowns from the SIEM's logs
 * (Windows 6005/6009/12/6013 uptime, 6008; Linux boot messages), and "running N days without a restart" against
 * `reboot_max_days` (patching).
 * HA / DR: hosts are grouped by `service` (set by an administrator) or, when unset, by name ("asiirisdbnp1/np2",
 * "app-a/app-b", "erp-dr" → same group, marked inferred). Per group: single server = single point of failure,
 * fewer online than members = running without redundancy (single-server / no-DR are not raised for non-production
 * names — uat/test/dev/qa/lab/np — unless an administrator sets requires_ha), no member at a DR site (subnet map) or with role "dr" =
 * no DR copy.
 */
const net = require('node:net');
const crypto = require('node:crypto');

const DEFAULTS = { interval_s: 60, concurrency: 32, fail_threshold: 2, reboot_max_days: 30, subnets: [], sync_inventory: true, sync_interval_s: 600, sync_types: ['server', 'vm', 'storage'] };
const CLOSED = ['retired', 'disposed', 'lost'];
const ROLES = ['primary', 'secondary', 'dr', 'standalone', ''];

function ipInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
function inCidr(ip, cidr) {
  const [b, bits] = String(cidr).split('/'); const n = Number(bits);
  if (!net.isIPv4(ip) || !net.isIPv4(b) || !(n >= 0 && n <= 32)) return false;
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0; return ((ipInt(ip) & mask) >>> 0) === ((ipInt(b) & mask) >>> 0);
}
function stem(name) {
  let s = String(name || '').toLowerCase().split('.')[0];
  s = s.replace(/[-_](dr|bcp|drc)$/, '').replace(/(dr|drc)$/, '');
  s = s.replace(/[-_][ab]$/, '').replace(/[-_]?0?[1-9]$/, '');
  return s;
}
/* non-production by name (UAT / test / dev / QA / lab / "np" = non-production): HA and DR are not expected */
function nonProd(name) { return /(^|[-_.])(uat|test|tst|dev|qa|lab|sandbox|sbx|stg|staging)([-_.\d]|$)|uat|np(\d*)?$/i.test(String(name || '').toLowerCase().split('.')[0]); }
function clean(v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max); }

/* pure: HA / DR / SPOF evaluation */
function evaluate(hosts, status, settings) {
  const siteOf = (h) => { for (const s of settings.subnets || []) if (inCidr(h.ip, s.cidr)) return s; return null; };
  const groups = new Map();
  for (const h of hosts) {
    const key = h.service ? 'svc:' + h.service.toLowerCase() : 'auto:' + stem(h.name);
    if (!groups.has(key)) groups.set(key, { key, name: h.service || stem(h.name), inferred: !h.service, members: [] });
    groups.get(key).members.push(h);
  }
  const out = [];
  for (const g of groups.values()) {
    const isDr = (h) => h.role === 'dr' || !!(siteOf(h) && siteOf(h).dr);
    const prod = g.members.filter((h) => !isDr(h)), dr = g.members.filter(isDr);
    const online = (arr) => arr.filter((h) => (status[h.id] || {}).status === 'online').length;
    const critical = g.members.some((h) => h.critical);
    const required = g.members.some((h) => h.requires_ha === true || (h.requires_ha == null && !nonProd(h.name)));
    const issues = [];
    if (g.members.length === 1) issues.push('single-server');
    else if (prod.length === 1 && g.members.length > 1 && !dr.length) issues.push('single-server');
    if (prod.length > 1 && online(prod) < prod.length && online(prod) > 0) issues.push('no-redundancy-now');
    if (online(g.members) === 0 && g.members.some((h) => (status[h.id] || {}).status === 'offline')) issues.push('service-down'); // every member offline, wherever it is
    if (!dr.length) issues.push('no-dr');
    else if (online(dr) === 0) issues.push('dr-offline');
    if (!required) for (const x of ['single-server', 'no-dr', 'dr-offline']) { const i = issues.indexOf(x); if (i >= 0) issues.splice(i, 1); }
    out.push({ key: g.key, name: g.name, required, inferred: g.inferred && g.members.length > 1 ? true : g.inferred, critical, members: g.members.map((h) => h.id), production: prod.length, production_online: online(prod), dr: dr.length, dr_online: online(dr),
      ha: prod.length >= 2, issues, status: issues.includes('service-down') ? 'down' : issues.includes('no-redundancy-now') ? 'degraded' : issues.includes('single-server') ? 'spof' : issues.length ? 'warning' : 'ok' });
  }
  return out;
}

function createAvailability({ state, config, log, ch, evidence, discovery, probe, now } = {}) {
  const L = log || { info() {}, warn() {} }, clock = now || Date.now;
  const hostsCol = state.collection('avail_hosts'), evCol = state.collection('avail_events'), cfgCol = state.collection('avail_settings');
  const live = new Map(); let timer = null, syncTimer = null, running = false;
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';
  const stats = { scans: 0, last_scan_ms: 0, last_scan_at: 0 };
  let cacheAvail = { at: 0, data: {} }, cacheBoot = { at: 0, data: {} }, cachePerf = { at: 0, data: {} };

  function settings() { return Object.assign({}, DEFAULTS, ((config && config.netops) || {}).availability || {}, (cfgCol.get('settings') || {}).value || {}); }
  function setSettings(s, by) {
    const cur = (cfgCol.get('settings') || {}).value || {}, v = Object.assign({}, cur);
    if (s.reboot_max_days !== undefined) { const n = Number(s.reboot_max_days); if (!(n >= 1 && n <= 365)) throw Object.assign(new Error('reboot_max_days must be 1-365'), { code: 400 }); v.reboot_max_days = Math.round(n); }
    if (s.sync_inventory !== undefined) v.sync_inventory = s.sync_inventory === true || s.sync_inventory === 'true';
    if (s.subnets !== undefined) {
      if (!Array.isArray(s.subnets) || s.subnets.length > 100) throw Object.assign(new Error('subnets must be a list (max 100)'), { code: 400 });
      v.subnets = s.subnets.map((x) => { const cidr = clean(x.cidr, 18); const [b, bits] = cidr.split('/'); if (!net.isIPv4(b) || !(Number(bits) >= 8 && Number(bits) <= 32)) throw Object.assign(new Error('invalid CIDR ' + cidr), { code: 400 }); return { cidr, site: clean(x.site, 60), dr: !!x.dr }; });
    }
    cfgCol.put({ id: 'settings', value: v, updated: clock(), updated_by: by || '' }); return settings();
  }
  function validate(input, ex) {
    const h = Object.assign({}, ex || {});
    if (!ex) { h.id = clean(input.id, 64).toLowerCase() || 'h-' + crypto.createHash('sha1').update(String(input.ip) + String(input.name)).digest('hex').slice(0, 12); if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(h.id)) throw Object.assign(new Error('invalid host id'), { code: 400 }); }
    if (input.ip !== undefined || !ex) { h.ip = clean(input.ip, 45); if (!net.isIP(h.ip)) throw Object.assign(new Error('valid IP address required'), { code: 400 }); }
    if (input.name !== undefined || !ex) h.name = clean(input.name || h.ip, 120);
    for (const k of ['site', 'service', 'kind', 'os', 'owner']) if (input[k] !== undefined) h[k] = clean(input[k], 80);
    if (input.role !== undefined) { if (!ROLES.includes(input.role)) throw Object.assign(new Error('role must be primary, secondary, dr or standalone'), { code: 400 }); h.role = input.role; }
    if (input.critical !== undefined) h.critical = !!input.critical;
    if (input.source !== undefined) h.source = input.source === 'inventory' ? 'inventory' : 'manual';
    if (input.asset_id !== undefined) h.asset_id = clean(input.asset_id, 64);
    if (input.requires_ha !== undefined) h.requires_ha = input.requires_ha === null || input.requires_ha === 'auto' || input.requires_ha === '' ? null : !!input.requires_ha && input.requires_ha !== 'false';
    if (input.monitor !== undefined) h.monitor = input.monitor !== false;
    if (input.ports !== undefined) { const p = (Array.isArray(input.ports) ? input.ports : []).map(Number).filter((x) => x > 0 && x < 65536).slice(0, 8); h.ports = p; }
    if (h.monitor === undefined) h.monitor = true;
    return h;
  }

  /* ---------- probing */
  const defaultProbe = async (h) => {
    const t0 = clock();
    const c = require('./collectors');
    const r = await c.ping(h.ip, { count: 2, timeoutMs: 4000 });
    if (!r.unavailable && r.received > 0) return { up: true, method: 'ping', rtt: r.rtt_avg_ms };
    const os = String(h.os || '').toLowerCase();
    const ports = h.ports && h.ports.length ? h.ports : /win/.test(os) ? [3389, 445, 135] : /linux|unix|esx|solaris|sunos|aix|hp-ux/.test(os) ? [22, 443] : [22, 443, 3389, 80];
    for (const p of ports) {
      const ok = await new Promise((res) => { const s = net.connect({ host: h.ip, port: p, timeout: 1500 }); const d = (v) => { s.destroy(); res(v); }; s.once('connect', () => d(true)); s.once('timeout', () => d(false)); s.once('error', (e) => d(e.code === 'ECONNREFUSED')); });
      if (ok) return { up: true, method: 'tcp/' + p, rtt: clock() - t0 };
    }
    return { up: false, method: r.unavailable ? 'tcp' : 'ping+tcp' };
  };
  const doProbe = probe || defaultProbe;
  function record(h, from, to, at) {
    evCol.put({ id: h.id + ':' + at, host: h.id, from, to, at });
  }
  async function check(h) {
    const t = clock(), r = await doProbe(h).catch(() => ({ up: false, method: 'error' }));
    const s = live.get(h.id) || { status: 'unknown', since: t, fails: 0, first_seen: t };
    s.last_check = t; s.method = r.method; s.rtt = r.rtt;
    if (r.up) {
      s.fails = 0; s.last_ok = t;
      if (s.status !== 'online') { if (s.status !== 'unknown') record(h, s.status, 'online', t); s.status = 'online'; s.since = t; }
    } else {
      s.fails = (s.fails || 0) + 1;
      if (s.status !== 'offline' && s.fails >= settings().fail_threshold) { const at = s.last_ok && s.status === 'online' ? s.last_ok : t; record(h, s.status, 'offline', at); s.status = 'offline'; s.since = at; }
    }
    live.set(h.id, s);
    return { h, up: r.up };
  }
  async function scan() {
    if (running) return; running = true; const t0 = clock();
    try {
      const list = hostsCol.all((h) => h.monitor !== false), out = []; let i = 0;
      const worker = async () => { while (i < list.length) { const h = list[i++]; out.push(await check(h)); } };
      await Promise.all(Array.from({ length: Math.min(settings().concurrency, list.length || 1) }, worker));
      if (ch && out.length) { const ts = Math.floor(t0 / 1000); ch.insertRows(db + '.net_metrics', out.map((o) => ({ ts, device: o.h.id, site: o.h.site || '', key: '', metric: 'host_up', value: o.up ? 1 : 0 }))).catch((e) => L.warn('availability metrics insert failed', { err: e.message })); }
      prune();
    } finally { running = false; stats.scans++; stats.last_scan_ms = clock() - t0; stats.last_scan_at = t0; }
  }
  function prune() { const cut = clock() - 90 * 86400000; if (Math.random() < 0.05) for (const e of evCol.all((x) => x.at < cut)) evCol.remove(e.id); }
  /* restore state after a restart: last recorded transition per host gives status + since */
  function restore() { const last = {}; for (const e of evCol.all()) if (!last[e.host] || e.at > last[e.host].at) last[e.host] = e; for (const [id, e] of Object.entries(last)) live.set(id, { status: e.to, since: e.at, fails: 0, restored: true }); }

  /* ---------- SIEM-derived: availability % and restarts (cached) */
  async function availability() {
    if (!ch || clock() - cacheAvail.at < 300000) return cacheAvail.data;
    try {
      const rows = await ch.query(`SELECT device, round(100*avgIf(value, ts >= now() - INTERVAL 1 DAY),2) AS d1, round(100*avgIf(value, ts >= now() - INTERVAL 7 DAY),2) AS d7, round(100*avg(value),2) AS d30
        FROM ${db}.net_metrics WHERE metric = 'host_up' AND ts >= now() - INTERVAL 30 DAY GROUP BY device`, {}, { readonly: true, timeout_ms: 15000 });
      const m = {}; for (const r of rows) m[r.device] = { d1: Number.isFinite(+r.d1) ? +r.d1 : null, d7: +r.d7, d30: +r.d30 };
      cacheAvail = { at: clock(), data: m };
    } catch (e) { L.warn('availability query failed', { err: e.message }); }
    return cacheAvail.data;
  }
  async function restarts() {
    if (!ch || clock() - cacheBoot.at < 900000) return cacheBoot.data;
    const hosts = hostsCol.all(); if (!hosts.length) return {};
    try {
      const ips = hosts.map((h) => h.ip), names = hosts.map((h) => h.name.toLowerCase()), shorts = hosts.map((h) => h.name.toLowerCase().split('.')[0]);
      const rows = await ch.query(`SELECT host_ip, lower(host) AS h,
          maxIf(ts, event_code IN ('6005','6009','12') OR match(message, '(?i)Linux version [0-9]|systemd\\\\[1\\\\]: Startup finished|kernel: Command line:')) AS boot_evt,
          argMaxIf(toUInt64OrZero(extract(message, '(?i)uptime is ([0-9]+) seconds')), ts, event_code = '6013') AS up_s, maxIf(ts, event_code = '6013') AS up_ts,
          countIf(event_code = '6008' AND ts >= now() - INTERVAL 30 DAY) AS unexpected, maxIf(ts, event_code IN ('1074','6006')) AS shutdown_evt
        FROM ${db}.events WHERE ts >= now() - INTERVAL 400 DAY AND (host_ip IN {ips:Array(String)} OR lower(host) IN {names:Array(String)} OR lower(host) IN {shorts:Array(String)})
          AND (event_code IN ('6005','6006','6008','6009','6013','12','1074') OR match(message, '(?i)Linux version [0-9]|Startup finished|kernel: Command line:'))
        GROUP BY host_ip, h`, { ips: { type: 'Array(String)', value: ips }, names: { type: 'Array(String)', value: names }, shorts: { type: 'Array(String)', value: shorts } }, { readonly: true, timeout_ms: 20000 });
      const m = {};
      for (const h of hosts) {
        const n = h.name.toLowerCase(), sh = n.split('.')[0];
        for (const r of rows.filter((x) => x.host_ip === h.ip || x.h === n || x.h === sh || x.h.split('.')[0] === sh)) {
          const t = (v) => { const x = Date.parse(String(v).replace(' ', 'T') + 'Z'); return x > 86400000 ? x : 0; };
          let boot = t(r.boot_evt); const upS = Number(r.up_s), upTs = t(r.up_ts);
          if (upS > 0 && upTs) boot = Math.max(boot, upTs - upS * 1000);
          const cur = m[h.id] || { last_boot: 0, unexpected_30d: 0 };
          m[h.id] = { last_boot: Math.max(cur.last_boot, boot), unexpected_30d: cur.unexpected_30d + Number(r.unexpected || 0), last_shutdown: Math.max(cur.last_shutdown || 0, t(r.shutdown_evt)) };
        }
      }
      cacheBoot = { at: clock(), data: m };
    } catch (e) { L.warn('restart query failed', { err: e.message }); }
    return cacheBoot.data;
  }

  /* latest CPU / memory / disk from the Windows agent heartbeat (agent 1.1+, every 5 min), matched by IP or name */
  async function perf() {
    if (!ch || clock() - cachePerf.at < 60000) return cachePerf.data;
    const hosts = hostsCol.all(); if (!hosts.length) return {};
    try {
      const ips = hosts.map((h) => h.ip), names = hosts.map((h) => h.name.toLowerCase()), shorts = hosts.map((h) => h.name.toLowerCase().split('.')[0]);
      const rows = await ch.query(`SELECT host_ip, lower(host) AS h, max(ts) AS at, argMax(fields['cpu_pct'], ts) AS cpu, argMax(fields['mem_pct'], ts) AS mem,
          argMax(fields['mem_total_gb'], ts) AS mem_gb, argMax(fields['disk_max_pct'], ts) AS disk, argMax(fields['disks'], ts) AS disks
        FROM ${db}.events WHERE ts >= now() - INTERVAL 1 DAY AND action = 'agent-heartbeat' AND mapContains(fields, 'cpu_pct')
          AND (host_ip IN {ips:Array(String)} OR lower(host) IN {names:Array(String)} OR lower(host) IN {shorts:Array(String)} OR splitByChar('.', lower(host))[1] IN {shorts:Array(String)})
        GROUP BY host_ip, h`, { ips: { type: 'Array(String)', value: ips }, names: { type: 'Array(String)', value: names }, shorts: { type: 'Array(String)', value: shorts } }, { readonly: true, timeout_ms: 15000 });
      const m = {}, t = (v) => { const x = Date.parse(String(v).replace(' ', 'T') + 'Z'); return x > 86400000 ? x : 0; }, n = (v) => (v === '' || v == null || !Number.isFinite(Number(v)) ? null : Number(v));
      for (const h of hosts) {
        const nm = h.name.toLowerCase(), sh = nm.split('.')[0];
        const r = rows.filter((x) => x.host_ip === h.ip || x.h === nm || x.h === sh || x.h.split('.')[0] === sh).sort((a, b) => t(b.at) - t(a.at))[0];
        if (!r) continue;
        const disks = String(r.disks || '').split(';').map((d) => d.split('|')).filter((d) => d.length === 3).map(([dev, size, free]) => ({ dev, size_gb: Number(size), free_gb: Number(free), used_pct: Number(size) > 0 ? Math.round((1 - Number(free) / Number(size)) * 1000) / 10 : null }));
        m[h.id] = { at: t(r.at), cpu_pct: n(r.cpu), mem_pct: n(r.mem), mem_gb: n(r.mem_gb), disk_max_pct: n(r.disk), disks };
      }
      cachePerf = { at: clock(), data: m };
    } catch (e) { L.warn('resource usage query failed', { err: e.message }); }
    return cachePerf.data;
  }

  async function view() {
    const st = settings(), hosts = hostsCol.all(), status = Object.fromEntries(live), av = await availability(), bt = await restarts(), pf = await perf(), t = clock();
    const groups = evaluate(hosts, status, st), byHost = {};
    for (const g of groups) for (const id of g.members) byHost[id] = g;
    const siteOf = (h) => { for (const s of st.subnets || []) if (inCidr(h.ip, s.cidr)) return s; return null; };
    const items = hosts.map((h) => {
      const s = status[h.id] || { status: 'unknown' }, g = byHost[h.id], b = bt[h.id] || {}, sub = siteOf(h);
      const bootAge = b.last_boot ? Math.floor((t - b.last_boot) / 86400000) : null;
      const flags = [];
      if (s.status === 'offline') flags.push('offline');
      if (bootAge != null && bootAge > st.reboot_max_days) flags.push('reboot-overdue');
      if (b.unexpected_30d) flags.push('unexpected-shutdowns');
      const p = pf[h.id] && t - pf[h.id].at < 30 * 60000 ? pf[h.id] : null;   // older than 30 min = stale, not shown as current
      if (p && p.cpu_pct >= 90) flags.push('cpu-high');
      if (p && p.mem_pct >= 90) flags.push('memory-high');
      if (p && p.disk_max_pct >= 90) flags.push('disk-full');
      if (g) for (const i of g.issues) flags.push(i);
      return Object.assign({}, h, { site: h.site || (sub && sub.site) || '', dr_site: !!(sub && sub.dr) || h.role === 'dr', status: s.status, since: s.since || null, duration_s: s.since ? Math.round((t - s.since) / 1000) : null,
        last_check: s.last_check || null, method: s.method || '', rtt_ms: s.rtt != null ? Math.round(s.rtt * 10) / 10 : null, availability: av[h.id] || null,
        resources: p, resources_last: pf[h.id] ? pf[h.id].at : null, last_boot: b.last_boot || null, days_since_boot: bootAge, unexpected_shutdowns_30d: b.unexpected_30d || 0, group: g ? { key: g.key, name: g.name, status: g.status, inferred: g.inferred, required: g.required, members: g.members.length } : null, flags });
    });
    const order = { offline: 0, unknown: 1, online: 2 };
    items.sort((a, b) => order[a.status] - order[b.status] || (b.flags.length - a.flags.length) || a.name.localeCompare(b.name));
    const sum = { total: items.length, online: items.filter((i) => i.status === 'online').length, offline: items.filter((i) => i.status === 'offline').length, unknown: items.filter((i) => i.status === 'unknown').length,
      reboot_overdue: items.filter((i) => i.flags.includes('reboot-overdue')).length, spof: groups.filter((g) => g.issues.includes('single-server')).length, no_dr: groups.filter((g) => g.issues.includes('no-dr')).length,
      degraded: groups.filter((g) => g.status === 'degraded' || g.status === 'down').length, longest_offline_s: Math.max(0, ...items.filter((i) => i.status === 'offline').map((i) => i.duration_s || 0)) };
    return { summary: sum, items, groups, settings: st, scanner: Object.assign({ interval_s: st.interval_s, monitored: hosts.filter((h) => h.monitor !== false).length }, stats) };
  }
  async function detail(id) {
    const v = await view(), h = v.items.find((x) => x.id === id); if (!h) return null;
    const events = evCol.all((e) => e.host === id).sort((a, b) => b.at - a.at).slice(0, 200);
    const g = h.group ? v.groups.find((x) => x.key === h.group.key) : null;
    return { host: h, events, group: g ? Object.assign({}, g, { member_hosts: g.members.map((m) => v.items.find((x) => x.id === m)).filter(Boolean).map((x) => ({ id: x.id, name: x.name, ip: x.ip, status: x.status, role: x.role, dr_site: x.dr_site, site: x.site })) }) : null };
  }

  const api = {
    start() {
      restore(); if (timer) return;
      setTimeout(guardJob('netops.availability.scan', () => scan()), 20000).unref(); timer = setInterval(guardJob('netops.availability.scan', () => scan()), Math.max(30, settings().interval_s) * 1000); timer.unref();
      // a failed sync (typically IT Asset Management restarting during an update) is retried after 1 minute, up to 5 times,
      // instead of waiting for the next 10-minute round
      let retries = 0, retryTimer = null;
      const sync = () => {
        if (!settings().sync_inventory || !discovery || typeof discovery.assets !== 'function') return;
        api.importFromInventory().then((r) => {
          if (stats.last_sync_error) L.info('inventory sync recovered', { eligible: r.eligible, added: r.added, removed: r.removed });
          stats.last_sync_error = ''; retries = 0;
        }).catch((e) => {
          stats.last_sync_error = e.message; stats.last_sync_error_at = clock();
          L.warn('inventory sync failed', { err: e.message, retry_in_s: retries < 5 ? 60 : null });
          if (retries < 5 && !retryTimer) { retries++; retryTimer = setTimeout(() => { retryTimer = null; sync(); }, 60000); retryTimer.unref(); }
        });
      };
      setTimeout(sync, 30000).unref(); syncTimer = setInterval(guardJob('netops.availability.sync', sync), Math.max(60, settings().sync_interval_s) * 1000); syncTimer.unref();
    },
    stop() { if (timer) clearInterval(timer); timer = null; if (syncTimer) clearInterval(syncTimer); syncTimer = null; },
    scan, view, detail, settings, setSettings, restore,
    async checkNow(id) { const h = hostsCol.get(id); if (!h) throw Object.assign(new Error('host not found'), { code: 404 }); const s0 = live.get(id); if (s0) s0.fails = Math.max(0, settings().fail_threshold - 1); await check(h); return live.get(id); },
    list: () => hostsCol.all(),
    get: (id) => hostsCol.get(id) || null,
    put(input, by) { const ex = input.id ? hostsCol.get(String(input.id).toLowerCase()) : null; const h = validate(input, ex); h.updated = clock(); h.updated_by = by || ''; if (!ex) h.created = h.updated; hostsCol.put(h); return h; },
    remove(id) { if (!hostsCol.get(id)) throw Object.assign(new Error('host not found'), { code: 404 }); hostsCol.remove(id); live.delete(id); for (const e of evCol.all((x) => x.host === id)) evCol.remove(e.id); return { removed: id }; },
    importHosts(items, by) {
      if (!Array.isArray(items) || items.length > 5000) throw Object.assign(new Error('items must be a list (max 5000)'), { code: 400 });
      const res = { added: 0, updated: 0, skipped: 0, errors: [] };
      for (const it of items) {
        const ip = clean(it.ip || (Array.isArray(it.ips) && it.ips[0]), 45); if (!net.isIP(ip)) { res.skipped++; continue; }
        const ex = hostsCol.all((h) => h.ip === ip)[0];
        try {
          if (ex) { this.put(Object.assign({ id: ex.id }, { name: ex.name === ex.ip ? (it.hostname || it.name || ex.name) : ex.name, os: ex.os || it.os || '', kind: ex.kind || it.kind || it.class || it.type || '', site: ex.site || it.site || '' }, it.asset_id && !ex.asset_id ? { asset_id: it.asset_id } : {}), by); res.updated++; }
          else { this.put(Object.assign({ ip, name: it.hostname || it.name || ip, os: it.os || '', kind: it.kind || it.class || it.type || '', site: it.site || '', service: it.service || '', role: ROLES.includes(it.role) ? it.role : '' }, it.source ? { source: it.source } : {}, it.asset_id ? { asset_id: it.asset_id } : {}), by); res.added++; }
        } catch (e) { res.errors.push(ip + ': ' + e.message); }
      }
      return res;
    },
    async importFromDiscovery(who) {
      if (!discovery) throw Object.assign(new Error('asset discovery is not configured in the SIEM (config.onboard.discovery)'), { code: 503 });
      const r = await discovery.results({}, who);
      const servers = (r.devices || []).filter((d) => !/printer|phone|camera|ap$|access point|workstation|laptop|desktop/i.test(String(d.class || d.type || d.kind || '')));
      return Object.assign({ discovered: (r.devices || []).length }, this.importHosts(servers.map((d) => ({ ip: d.ip || (d.ips || [])[0], hostname: d.hostname || d.name, os: d.os, kind: d.kind || d.class || d.type, site: d.site })), who && who.user));
    },
    async importFromInventory(who) {
      if (!discovery || typeof discovery.assets !== 'function') throw Object.assign(new Error('IT Asset Management is not linked to the SIEM (config.onboard.discovery) - run install/link-itam.sh'), { code: 503 });
      const st = settings(), types = Array.isArray(st.sync_types) && st.sync_types.length ? st.sync_types : DEFAULTS.sync_types;
      const r = await discovery.assets({ limit: 5000 }, who || { user: 'system:availability-sync', role: 'viewer' });
      const out = { fetched: r.assets.length, eligible: 0, skipped_no_ip: [], skipped_type: 0, removed: 0 };
      const keep = new Set(), items = [];
      for (const a of r.assets) {
        if (CLOSED.includes(a.status)) continue;
        const cloud = (a.tags || []).map((t) => String(t).toLowerCase()).includes('cloud');
        if (!types.includes(a.type) && !cloud) { out.skipped_type++; continue; }
        const ip = clean(a.mgmt_ip, 45);
        if (!net.isIP(ip)) { if (out.skipped_no_ip.length < 50) out.skipped_no_ip.push(a.name || a.asset_tag || a.id); continue; }
        out.eligible++; keep.add(a.id);
        items.push({ ip, name: a.name || a.asset_tag || ip, os: a.os || '', kind: a.type || '', site: a.site || '', source: 'inventory', asset_id: clean(a.id, 64) });
      }
      Object.assign(out, this.importHosts(items, (who && who.user) || 'system:availability-sync'));
      for (const h of hostsCol.all((x) => x.source === 'inventory' && x.asset_id && !keep.has(x.asset_id))) { this.remove(h.id); out.removed++; }
      stats.last_sync_at = clock(); stats.last_sync = { added: out.added, updated: out.updated, removed: out.removed, eligible: out.eligible, skipped_no_ip: out.skipped_no_ip.length };
      return out;
    },
    ipMap() { const m = {}; for (const h of hostsCol.all()) { const s = live.get(h.id); if (s) m[h.ip] = { s: s.status, since: s.since }; } return m; },
    stats: () => stats,
  };
  return api;
}

module.exports = { createAvailability, evaluate, stem, nonProd, inCidr, DEFAULTS };
