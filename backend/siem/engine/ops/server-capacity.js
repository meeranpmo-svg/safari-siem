// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SERVER CAPACITY from what the SIEM agents already send: every agent heartbeat (parse/windows.js agent-heartbeat; agent 1.1+) carries
 * CPU %, memory used % and total, and each fixed disk's size and free space. Per server and day (Riyadh time) the 95th percentile of
 * CPU and memory and the last disk reading are kept; from those:
 *   forecast     least squares over the daily values (7+ days): the date CPU p95 or memory p95 reaches 90 %, and each disk 95 % full
 *   rightsize    oversized - CPU p95 under 20 % and memory p95 under 40 % for the whole window; undersized - CPU or memory p95 over
 *                85 % on half the days or more
 *   unusual      the last day against the server's OWN days before it (robust z over median / MAD) - a jump a fixed threshold misses
 * Read-only: nothing is changed on a server. No personal data (server names and figures only).
 *   GET {P}/capacity/servers   ?days=7-90 (default 30)   viewer
 */
const DAY = 86400000;
const r1 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 10) / 10);
const med = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
function lsq(pts) { const k = pts.length; if (k < 7) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; for (const [x, y] of pts) { sx += x; sy += y; sxy += x * y; sxx += x * x; } const d = k * sxx - sx * sx; if (!d) return null; const b = (k * sxy - sx * sy) / d; return { b, a: (sy - b * sx) / k }; }
// days from the last point until the fitted line reaches the limit (null: flat, falling or already above)
function daysTo(pts, limit) { const f = lsq(pts); if (!f || f.b <= 0) return null; const last = pts[pts.length - 1][0], at = (limit - f.a) / f.b - last; return at > 0 && at < 3650 ? Math.round(at) : at <= 0 ? 0 : null; }
function zLast(vals) { if (vals.length < 8) return null; const base = vals.slice(0, -1), m = med(base), mad = med(base.map((v) => Math.abs(v - m))) || 1; return (vals[vals.length - 1] - m) / (1.4826 * mad); }
const parseDisks = (s) => String(s || '').split(';').map((d) => d.split('|')).filter((d) => d.length === 3).map(([dev, size, free]) => ({ dev, size: Number(size), free: Number(free) })).filter((d) => d.size > 0 && Number.isFinite(d.free));

// rows: [{host, d: 'YYYY-MM-DD', cpu95, mem95, mem_gb, disks: 'C:|100|20;D:|500|300'}]
function analyse(rows, o = {}) {
  const days = o.days || 30, by = new Map();
  for (const r of rows || []) { const h = String(r.host || '').toLowerCase(); if (!h) continue; (by.get(h) || by.set(h, { host: r.host, days: [] }).get(h)).days.push(r); }
  const servers = [], F = [];
  for (const x of by.values()) {
    const D = x.days.sort((a, b) => String(a.d).localeCompare(String(b.d))), idx = (d) => Math.round(Date.parse(d.d + 'T00:00:00Z') / DAY);
    const cpu = D.filter((d) => d.cpu95 != null && Number.isFinite(+d.cpu95)).map((d) => [idx(d), +d.cpu95]), mem = D.filter((d) => d.mem95 != null && Number.isFinite(+d.mem95)).map((d) => [idx(d), +d.mem95]);
    const last = D[D.length - 1], disks = parseDisks(last.disks).map((k) => {
      const pts = D.map((d) => { const m = parseDisks(d.disks).find((q) => q.dev === k.dev); return m ? [idx(d), 100 * (1 - m.free / m.size)] : null; }).filter(Boolean);
      return { dev: k.dev, size_gb: k.size, free_gb: k.free, used_pct: r1(100 * (1 - k.free / k.size)), days_to_95: daysTo(pts, 95), z: r1(zLast(pts.map((p) => p[1]))) };
    });
    const s = { host: x.host, days: D.length, last_day: last.d, cpu_p95: r1(cpu.length ? cpu[cpu.length - 1][1] : null), mem_p95: r1(mem.length ? mem[mem.length - 1][1] : null), mem_gb: last.mem_gb == null ? null : +last.mem_gb,
      cpu_days_to_90: daysTo(cpu, 90), mem_days_to_90: daysTo(mem, 90), cpu_z: r1(zLast(cpu.map((p) => p[1]))), mem_z: r1(zLast(mem.map((p) => p[1]))), disks,
      series: D.map((d) => ({ d: d.d, cpu: d.cpu95 == null ? null : r1(+d.cpu95), mem: d.mem95 == null ? null : r1(+d.mem95) })) };
    const allC = cpu.map((p) => p[1]), allM = mem.map((p) => p[1]);
    s.fit = D.length < 7 ? 'learning' : allC.length && allM.length && Math.max(...allC) < 20 && Math.max(...allM) < 40 ? 'oversized'
      : (allC.filter((v) => v > 85).length >= allC.length / 2 && allC.length) || (allM.filter((v) => v > 85).length >= allM.length / 2 && allM.length) ? 'undersized' : 'right';
    const add = (sev, code, what, why, fix) => F.push({ severity: sev, code, host: x.host, what, why, fix });
    for (const k of disks) {
      if (k.used_pct >= 95) add('high', 'disk-full', k.dev + ' is ' + k.used_pct + '% full', k.free_gb + ' GB free of ' + k.size_gb + ' GB', 'Free space or extend the volume now');
      else if (k.days_to_95 != null && k.days_to_95 <= 30) add(k.days_to_95 <= 7 ? 'high' : 'medium', 'disk-trend', k.dev + ' reaches 95 % in about ' + k.days_to_95 + ' day(s)', 'its daily growth over ' + D.length + ' days, now ' + k.used_pct + '%', 'Plan the extension or clean-up before then');
      if (k.z != null && k.z >= 4) add('medium', 'disk-jump', k.dev + ' grew unusually on ' + last.d, 'robust z ' + k.z + ' against its own days before', 'Look for a dump, a log that stopped rotating or a backup written locally');
    }
    if (s.mem_days_to_90 != null && s.mem_days_to_90 <= 60) add(s.mem_days_to_90 <= 14 ? 'high' : 'medium', 'mem-trend', 'Memory p95 reaches 90 % in about ' + s.mem_days_to_90 + ' day(s)', 'now ' + s.mem_p95 + '%, rising day by day', 'Add memory, or move a workload off this server');
    if (s.cpu_days_to_90 != null && s.cpu_days_to_90 <= 60) add(s.cpu_days_to_90 <= 14 ? 'high' : 'medium', 'cpu-trend', 'CPU p95 reaches 90 % in about ' + s.cpu_days_to_90 + ' day(s)', 'now ' + s.cpu_p95 + '%, rising day by day', 'Add vCPUs / cores or spread the load');
    if (s.fit === 'undersized') add('medium', 'undersized', 'Runs above 85 % on most days', 'CPU p95 ' + s.cpu_p95 + '%, memory p95 ' + s.mem_p95 + '%', 'Give it more CPU / memory, or split the workload');
    if (s.fit === 'oversized') add('low', 'oversized', 'Uses little of what it has', 'CPU p95 never above 20 %, memory p95 never above 40 % in ' + D.length + ' days', 'Reduce its CPU / memory (a VM) or host more on it - capacity to reclaim');
    if ((s.cpu_z != null && s.cpu_z >= 4) || (s.mem_z != null && s.mem_z >= 4)) add('medium', 'unusual', 'Unusual load on ' + last.d, 'robust z CPU ' + (s.cpu_z == null ? '-' : s.cpu_z) + ', memory ' + (s.mem_z == null ? '-' : s.mem_z) + ' against its own days before', 'Check what started that day - a job, an update, an attack');
    servers.push(s);
  }
  const SEV = { high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  servers.sort((a, b) => Math.min(...[a.cpu_days_to_90, a.mem_days_to_90, ...a.disks.map((k) => k.days_to_95)].filter((v) => v != null), 1e9) - Math.min(...[b.cpu_days_to_90, b.mem_days_to_90, ...b.disks.map((k) => k.days_to_95)].filter((v) => v != null), 1e9));
  const fit = (f) => servers.filter((s) => s.fit === f).length;
  return { days, servers, findings: F.slice(0, 300), kpis: { servers: servers.length, findings: F.length, high: F.filter((f) => f.severity === 'high').length, oversized: fit('oversized'), undersized: fit('undersized'), learning: fit('learning'),
    disks_30d: F.filter((f) => f.code === 'disk-trend' || f.code === 'disk-full').length },
    note: 'From the SIEM agent heartbeat on each server (CPU, memory, disks). Daily 95th percentiles in Riyadh time; a forecast needs 7 days. Servers without the agent are not measured here.' };
}

function register(api, deps) {
  const { wrap, prefixOf, HttpError } = require('../soc/routeutil');
  const P = prefixOf(deps);
  api.route('GET', `${P}/capacity/servers`, wrap(deps, 'viewer', async (ctx) => {
    const v = (ctx.query || {}).days, days = v === undefined || v === '' ? 30 : Number(v);
    if (!Number.isInteger(days) || days < 7 || days > 90) throw new HttpError(400, 'days must be a whole number 7-90');
    const ch = deps.ch; if (!ch || typeof ch.query !== 'function') throw new HttpError(503, 'the event store is not available');
    const db = ((deps.config || {}).clickhouse || {}).database || 'siem', t = (deps.now || Date.now)();
    const sql = `SELECT host, toString(toDate(ts, 'Asia/Riyadh')) AS d, quantile(0.95)(toFloat64OrNull(fields['cpu_pct'])) AS cpu95, quantile(0.95)(toFloat64OrNull(fields['mem_pct'])) AS mem95,
      max(toFloat64OrNull(fields['mem_total_gb'])) AS mem_gb, argMax(fields['disks'], ts) AS disks FROM ${db}.events
      WHERE action = 'agent-heartbeat' AND ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts <= fromUnixTimestamp64Milli({t_to:Int64}) GROUP BY host, d ORDER BY host, d LIMIT 100000`;
    const rows = await ch.query(sql, { t_from: { type: 'Int64', value: t - days * DAY }, t_to: { type: 'Int64', value: t } }, { readonly: true, settings: { max_execution_time: 60 } });
    return ctx.ok(analyse(rows, { days }));
  }));
}

module.exports = { register, analyse, daysTo, zLast };
