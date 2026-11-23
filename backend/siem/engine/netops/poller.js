// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Poll scheduler: every `interval_s` each device is polled (ping, SNMP and/or vendor API, per device.poll) with at most
 * `concurrency` devices at a time. The merged snapshot gets rates from counter deltas against the previous poll:
 * interface in/out bits per second, utilisation % of speed, errors and discards per minute.
 *   createPoller({ inventory, config, log, ch?, collectors?, now? })
 *     .start() .stop() .pollDevice(id) → snapshot   .snapshot(id) .snapshots() → {id: snapshot}   .stats()
 *   Snapshots stay in memory (latest per device) and, when ClickHouse is available, a compact row set per poll goes to
 *   <db>.net_metrics (history for trends and capacity forecasting).
 */
const defaultCollectors = require('./collectors');
const security = require('./security');
const WLC = require('./wlc');

function n(v) { if (v === null || v === undefined || v === '') return null; try { return BigInt(String(v).split('.')[0]); } catch (e) { return null; } }

function withRates(cur, prev) {
  if (!prev || !cur.interfaces) return cur;
  const dt = (cur.at - prev.at) / 1000; if (!(dt > 5)) return cur;
  const pm = new Map((prev.interfaces || []).map((i) => [i.name, i]));
  for (const i of cur.interfaces) {
    const p = pm.get(i.name); if (!p) continue;
    const rate = (a, b) => { const x = n(a), y = n(b); if (x === null || y === null || x < y) return null; return Number(x - y) * 8 / dt; }; // counter reset/wrap → no sample
    i.in_bps = rate(i.in_octets, p.in_octets); i.out_bps = rate(i.out_octets, p.out_octets);
    if (i.speed_mbps) {
      const cap = i.speed_mbps * 1e6, u = (b) => (b == null ? null : Math.round(b / cap * 1000) / 10);
      i.util_in = u(i.in_bps); i.util_out = u(i.out_bps);
      if ((i.util_in || 0) > 150 || (i.util_out || 0) > 150) { i.util_in = i.util_out = null; i.util_note = 'rate above the reported link speed — speed setting or counters look wrong'; } // never alarm on an impossible value
    }
    const per = (a, b) => (a >= b ? Math.round((a - b) / dt * 60 * 10) / 10 : null);
    i.err_per_min = per((i.in_errors || 0) + (i.out_errors || 0), (p.in_errors || 0) + (p.out_errors || 0));
    i.disc_per_min = per((i.in_discards || 0) + (i.out_discards || 0), (p.in_discards || 0) + (p.out_discards || 0));
    if (p.oper && i.oper && p.oper !== i.oper) i.changed = p.oper + '→' + i.oper;
  }
  for (const t of cur.tunnels || []) { const p = (prev.tunnels || []).find((x) => x.name === t.name); if (p && p.status !== t.status) t.changed = p.status + '→' + t.status; }
  for (const nb of cur.neighbors || []) { const p = (prev.neighbors || []).find((x) => x.proto === nb.proto && x.peer === nb.peer); if (p && p.up !== nb.up) nb.changed = p.state + '→' + nb.state; }
  return cur;
}

function createPoller({ inventory, config, log, ch, collectors, now } = {}) {
  const C = collectors || defaultCollectors, L = log || { info() {}, warn() {}, error() {} }, clock = now || Date.now;
  const opt = Object.assign({ interval_s: 120, concurrency: 8, history: true }, (config && config.netops) || {});
  const snaps = new Map(); let timer = null, running = false;
  const stats = { polls: 0, failures: 0, last_cycle_ms: 0, last_cycle_at: 0, history_rows: 0, history_errors: 0 };
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';

  async function pollDevice(id, opts = {}) {
    const dev = inventory.get(id); if (!dev) throw Object.assign(new Error('device not found'), { code: 404 });
    const cred = inventory.credentials(id), t0 = clock();
    const snap = { device_id: id, at: t0, vendor: dev.vendor, site: dev.site, errors: [], sources: [] };
    const jobs = [];
    if (dev.poll && dev.poll.ping !== false) jobs.push(C.ping(dev.ip).then((r) => { if (r.unavailable) snap.errors.push('ping: ' + r.error); else { snap.reach = r; snap.sources.push('ping'); } }));
    // a UPS also answers the standard UPS-MIB (RFC 1628) - battery, runtime, load, alarms; read only
    if (dev.role === 'ups' && dev.poll && dev.poll.snmp && cred.snmp && C.upsCollect) jobs.push(C.upsCollect(dev, cred.snmp).then((r) => { snap.ups = r; }).catch((e) => snap.errors.push('ups-mib: ' + e.message)));
    // a wireless LAN controller (role wlc) also answers its vendor's wireless MIB - APs, radios, channels, client counts; read only
    const wlcFn = C.wlcCollect || (C === defaultCollectors ? WLC.collect : null);   // injected collectors without wlcCollect skip it
    if (dev.role === 'wlc' && dev.poll && dev.poll.snmp && cred.snmp && wlcFn) jobs.push(wlcFn(dev, cred.snmp).then((r) => { snap.wlc = r; }).catch((e) => snap.errors.push('wlc: ' + e.message)));
    if (dev.poll && dev.poll.snmp && cred.snmp) jobs.push(C.snmpCollect(dev, cred.snmp).then((r) => { merge(snap, r); snap.sources.push('snmp'); }).catch((e) => snap.errors.push('snmp: ' + e.message)));
    if (dev.poll && dev.poll.api && cred.api) {
      const fn = { fortigate: C.fortigate, paloalto: C.paloalto, genian: C.genian, edgeconnect: C.edgeconnect, 'cisco-ucs': C.ucs }[dev.vendor];
      if (fn) jobs.push(fn(dev, cred.api).then((r) => { const errs = r.errors || []; delete r.errors; merge(snap, r, true); snap.sources.push('api'); for (const e of errs) snap.errors.push('api ' + e); }).catch((e) => snap.errors.push('api: ' + e.message)));
    }
    if (dev.poll && ((dev.poll.snmp && !cred.snmp) || (dev.poll.api && !cred.api))) snap.errors.push('polling enabled but credentials are not set');
    await Promise.all(jobs);
    const prevSnap = snaps.get(id), sec = prevSnap && prevSnap.security;
    if (opt.security !== false && (!sec || t0 - sec.at >= Math.max(600, opt.security_interval_s || 21600) * 1000 || opts.forceSecurity)) {
      try { snap.security = await (C.security || security.check)(dev, cred, { now: t0 }); } catch (e) { snap.errors.push('security checks: ' + e.message); if (sec) snap.security = sec; }
    } else if (sec) snap.security = sec;
    // support contract + subscriptions as the device reports them (FortiGate / PAN-OS API), every few hours
    const lic = prevSnap && prevSnap.licenses, licFn = C.licenses;   // injected collectors without licenses() skip it
    if (licFn && dev.poll && dev.poll.api && cred.api && (dev.vendor === 'fortigate' || dev.vendor === 'paloalto') && opt.licenses !== false) {
      if (!lic || t0 - lic.at >= Math.max(3600, opt.licenses_interval_s || 21600) * 1000 || opts.forceSecurity) {
        try { const l = await licFn(dev, cred.api); if (l) snap.licenses = l; } catch (e) { snap.errors.push('licences: ' + e.message); if (lic) snap.licenses = lic; }
      } else snap.licenses = lic;
    }
    snap.duration_ms = clock() - t0;
    snap.ok = !!(snap.sources.length && (!snap.reach || snap.reach.received > 0 || snap.sources.length > 1));
    withRates(snap, snaps.get(id));
    snaps.set(id, snap); stats.polls++; if (!snap.ok) stats.failures++;
    if (opt.history && ch) history(dev, snap).catch((e) => { stats.history_errors++; L.warn('net_metrics insert failed', { err: e.message }); });
    return snap;
  }
  function merge(snap, part, apiWins) {
    for (const [k, v] of Object.entries(part || {})) {
      if (v == null) continue;
      if (k === 'system') { snap.system = snap.system || {}; for (const [a, b] of Object.entries(v)) if (b != null && b !== '' && (apiWins || snap.system[a] == null)) snap.system[a] = b; }
      else if (Array.isArray(v)) { if (apiWins || !snap[k] || !snap[k].length) snap[k] = v; }
      else snap[k] = v;
    }
  }
  async function history(dev, s) {
    const ts = Math.floor(s.at / 1000), rows = [];
    const add = (key, metric, value) => { if (value != null && Number.isFinite(Number(value))) rows.push({ ts, device: dev.id, site: dev.site, key, metric, value: Number(value) }); };
    if (s.reach) { add('', 'loss_pct', s.reach.loss_pct); add('', 'rtt_ms', s.reach.rtt_avg_ms); add('', 'jitter_ms', s.reach.jitter_ms); }
    if (s.system) { add('', 'cpu_pct', s.system.cpu_pct); add('', 'mem_pct', s.system.mem_pct); add('', 'sessions', s.system.sessions); }
    for (const i of s.interfaces || []) { if (i.in_bps == null && i.oper !== 'down') continue; add(i.name, 'in_bps', i.in_bps); add(i.name, 'out_bps', i.out_bps); add(i.name, 'util_pct', Math.max(i.util_in || 0, i.util_out || 0)); add(i.name, 'err_per_min', i.err_per_min); add(i.name, 'oper_up', i.oper === 'up' ? 1 : 0); }
    for (const p of s.paths || []) { add(p.name + '/' + p.member, 'path_loss_pct', p.loss_pct); add(p.name + '/' + p.member, 'path_latency_ms', p.latency_ms); add(p.name + '/' + p.member, 'path_jitter_ms', p.jitter_ms); }
    for (const t of s.tunnels || []) add(t.name, 'tunnel_up', t.status === 'up' ? 1 : 0);
    if (s.wlc && s.wlc.summary) { add('', 'wlc_aps_up', s.wlc.summary.aps_up); add('', 'wlc_aps_down', s.wlc.summary.aps_down); add('', 'wlc_clients', s.wlc.summary.clients); add('', 'wlc_max_ch_util_pct', s.wlc.summary.max_ch_util_pct); for (const w of (s.wlc.ssids || []).slice(0, 50)) add(w.ssid, 'wlc_ssid_clients', w.clients); }
    if (!rows.length) return;
    await ch.insertRows(db + '.net_metrics', rows.slice(0, 5000)); stats.history_rows += rows.length;
  }
  async function cycle() {
    if (running) return; running = true; const t0 = clock();
    try {
      const ids = inventory.list().map((d) => d.id); let i = 0;
      const worker = async () => { while (i < ids.length) { const id = ids[i++]; try { await pollDevice(id); } catch (e) { stats.failures++; L.warn('netops poll failed', { id, err: e.message }); } } };
      await Promise.all(Array.from({ length: Math.min(opt.concurrency, ids.length) }, worker));
    } finally { running = false; stats.last_cycle_ms = clock() - t0; stats.last_cycle_at = t0; }
  }
  return {
    pollDevice, cycle,
    start() { if (timer) return; setTimeout(guardJob('netops.poller.cycle', () => cycle()), 15000).unref(); timer = setInterval(guardJob('netops.poller.cycle', () => cycle()), Math.max(30, opt.interval_s) * 1000); timer.unref(); },
    stop() { if (timer) clearInterval(timer); timer = null; },
    snapshot: (id) => snaps.get(id) || null,
    snapshots: () => Object.fromEntries(snaps),
    forget: (id) => snaps.delete(id),
    stats: () => Object.assign({ devices: inventory.list().length, interval_s: opt.interval_s, running }, stats),
  };
}

module.exports = { createPoller, withRates };
