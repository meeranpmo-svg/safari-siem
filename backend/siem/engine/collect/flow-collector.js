// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Flow collector: UDP listeners for NetFlow v5 / v9, IPFIX and sFlow v5 (every listener decodes every format - the version
 * is in the datagram), an exporter allow-list, per-exporter statistics, and one-minute rollups to ClickHouse.
 *
 *   createFlowCollector({ ch, config, log, now, getSettings, mapper, billable, observers, onMinute })
 *     .start() .stop() .restart()      listeners on getSettings().ports (none while enabled is false)
 *     .handle(buf, peerIp)             one datagram (the socket handler; tests call it directly)
 *     .flush(force?) → {minutes, rows} closes every finished minute: rows to ClickHouse, the minute's summary to onMinute
 *     .live() → last 60 minutes         .stats() → listeners, counters, exporters, unknown senders, templates
 *
 * Only exporters on the allow-list are decoded; a datagram from any other address is counted per sender (the 1000 most
 * recent) and dropped. Sampling: bytes and packets are multiplied by the exporter's rate - the administrator's setting for
 * that exporter first, then what the exporter announced (v5 header, v9 / IPFIX options or record fields, sFlow sample) -
 * so totals are estimates of the real traffic and the page says so.
 * Bounded memory: at most max_keys rollup rows per minute (extra flows are added to one "(overflow)" row per exporter, so
 * the bytes stay in the totals), max_keys / 2 per-address rows, raw_per_minute raw records per exporter (and 20 000 in all),
 * templates per exporter and in all (flow-collector-decode.js), and at most 3 open minutes.
 * ClickHouse (engine/store/schema.sql):
 *   flow_minute      one-minute rollups: exporter, interface in / out, addresses, service port, protocol, DSCP, application
 *   flow_if_minute   bytes / packets / flows per exporter interface and direction per minute (utilisation, forecasting)
 *   flow_ip_hour     bytes per private / group address and application per hour (IP groups, billing, patterns)
 *   flow_raw         a bounded sample of the decoded records (7 days)
 * A failed insert is counted and logged (once a minute per table) and that minute's rows are dropped - the collector never
 * holds an unbounded backlog.
 */
const dgram = require('node:dgram');
const net = require('node:net');
const { decode, createTemplateCache } = require('./flow-collector-decode');
const { createAppMapper } = require('./flow-collector-apps');
const { normPeer } = require('./sources');
const { guard } = require('../util/errors');
const { isPrivate } = require('../detect/ip');

const RING = 60, MAX_OPEN_MINUTES = 3, MAX_UNKNOWN = 1000, MAX_EXPORTERS = 2000, RAW_TOTAL = 20000, INSERT_CHUNK = 50000;
const SEP = '\u0001';
const noop = { info() {}, warn() {}, error() {}, debug() {}, every() {} };

function createFlowCollector(o = {}) {
  const L = Object.assign({}, noop, o.log || {}), NOW = o.now || Date.now, ch = o.ch || null, sock = o.dgram || dgram;
  const db = (o.config && o.config.clickhouse && o.config.clickhouse.database) || 'siem';
  const every = (k, ms, lvl, msg, f) => { if (typeof L.every === 'function') L.every(k, ms, lvl, msg, f); else L[lvl](msg, f); };
  let cfg = null, allow = new Map(), cache = null, mapper = createAppMapper([]);
  const exporters = new Map(), unknown = new Map(), buckets = new Map(), ring = [], sockets = [], listeners = {}, listenErrors = [];
  const c = { datagrams: 0, accepted: 0, rejected_unknown: 0, malformed: 0, records: 0, invalid_records: 0, no_template: 0, overflow_records: 0, overflow_ips: 0,
    observer_errors: 0, rows_written: 0, insert_errors: 0, rows_dropped: 0, raw_dropped: 0, flushes: 0, minutes_forced: 0 };
  let timer = null, running = false;

  function reload() {
    cfg = o.getSettings();
    allow = new Map((cfg.exporters || []).map((e) => [e.ip, e]));
    if (!cache) cache = createTemplateCache({ ttlMs: cfg.template_ttl_s * 1000, now: NOW });
    mapper = o.mapper ? o.mapper() : createAppMapper([]);
  }
  reload();

  function statOf(ip, e) {
    let s = exporters.get(ip);
    if (!s) {
      if (exporters.size >= MAX_EXPORTERS) exporters.delete(exporters.keys().next().value);
      s = { ip, datagrams: 0, records: 0, bytes: 0, packets: 0, errors: 0, invalid: 0, no_template: 0, counters: 0, last_error: '', last_error_at: 0, first_seen: NOW(), last_seen: 0, versions: {}, sampling: null, agent: '' };
      exporters.set(ip, s);
    }
    s.name = e.name || '';
    return s;
  }
  function bucketOf(m) {
    let b = buckets.get(m);
    if (!b) {
      while (buckets.size >= MAX_OPEN_MINUTES) { const old = Math.min(...buckets.keys()); c.minutes_forced++; closeMinute(old); }
      b = { m, keys: new Map(), ifs: new Map(), ips: new Map(), raw: [], rawPer: new Map(), bytes: 0, packets: 0, flows: 0 };
      buckets.set(m, b);
    }
    return b;
  }
  const rate = (v) => { const n = Math.round(Number(v)); return Number.isFinite(n) && n >= 1 ? Math.min(n, 1e6) : 1; };

  function ingest(rec, ip, e, s, version, t) {
    const sr = rate(e.sampling || rec.sampling || 1), bytes = rec.bytes * sr, packets = rec.packets * sr;
    const app = mapper.classify(rec), sv = mapper.service(rec), dscp = rec.tos >> 2;
    const b = bucketOf(Math.floor(t / 60000)), max = cfg.max_keys;
    let key = [ip, rec.if_in, rec.if_out, rec.src, rec.dst, sv.sport, sv.dport, rec.proto, dscp, app].join(SEP), a = b.keys.get(key);
    if (!a && b.keys.size >= max) { c.overflow_records++; key = ip + SEP + 'overflow'; a = b.keys.get(key); if (!a) { a = { exporter: ip, if_in: 0, if_out: 0, src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, proto: 0, dscp: 0, app: '(overflow)', bytes: 0, packets: 0, flows: 0 }; b.keys.set(key, a); } }
    if (!a) { a = { exporter: ip, if_in: rec.if_in, if_out: rec.if_out, src_ip: rec.src, dst_ip: rec.dst, src_port: sv.sport, dst_port: sv.dport, proto: rec.proto, dscp, app, bytes: 0, packets: 0, flows: 0 }; b.keys.set(key, a); }
    a.bytes += bytes; a.packets += packets; a.flows++;
    b.bytes += bytes; b.packets += packets; b.flows++;
    const addIf = (idx, dir) => { if (!idx) return; const k = ip + SEP + idx + SEP + dir; let x = b.ifs.get(k); if (!x) { if (b.ifs.size >= 20000) return; x = { exporter: ip, if_index: idx, dir, bytes: 0, packets: 0, flows: 0 }; b.ifs.set(k, x); } x.bytes += bytes; x.packets += packets; x.flows++; };
    addIf(rec.if_in, 'in'); addIf(rec.if_out, 'out');
    const addIp = (addr, dir) => {
      if (!(isPrivate(addr) || (o.billable && o.billable(addr)))) return;
      const k = ip + SEP + addr + SEP + dir + SEP + app; let x = b.ips.get(k);
      if (!x) { if (b.ips.size >= max / 2) { c.overflow_ips++; return; } x = { exporter: ip, ip: addr, dir, app, bytes: 0, packets: 0 }; b.ips.set(k, x); }
      x.bytes += bytes; x.packets += packets;
    };
    addIp(rec.src, 'src'); addIp(rec.dst, 'dst');
    if (cfg.raw_per_minute > 0) {
      const n = b.rawPer.get(ip) || 0;
      if (n < cfg.raw_per_minute && b.raw.length < RAW_TOTAL) { b.rawPer.set(ip, n + 1); b.raw.push({ ts: Math.floor(t / 1000), exporter: ip, version: String(version), src_ip: rec.src, dst_ip: rec.dst, src_port: rec.sport, dst_port: rec.dport, proto: rec.proto, tos: rec.tos, tcp_flags: rec.tcp_flags, if_in: rec.if_in, if_out: rec.if_out, bytes, packets, sampling: sr, app }); }
      else c.raw_dropped++;
    }
    s.records++; s.bytes += bytes; s.packets += packets; c.records++;
    if (o.observers && o.observers.length) {
      const f = { exporter: ip, src: rec.src, dst: rec.dst, sport: rec.sport, dport: rec.dport, proto: rec.proto, tcp_flags: rec.tcp_flags, bytes, packets, app, if_in: rec.if_in, if_out: rec.if_out, at: t };
      for (const fn of o.observers) { try { fn(f); } catch (err) { c.observer_errors++; every('netflow-observer', 60000, 'error', 'netflow: flow analytics observer failed', { err: String(err && err.message).slice(0, 200) }); } }
    }
  }

  function handle(buf, peer) {
    const t = NOW(); c.datagrams++;
    const ip = normPeer(peer), e = allow.get(ip);
    if (!e) {
      c.rejected_unknown++;
      let u = unknown.get(ip);
      if (!u) { if (unknown.size >= MAX_UNKNOWN) unknown.delete(unknown.keys().next().value); u = { ip, datagrams: 0, first_seen: t, last_seen: 0 }; unknown.set(ip, u); }
      u.datagrams++; u.last_seen = t;
      every('netflow-unknown-' + ip, 3600000, 'warn', 'netflow: datagram from a sender that is not on the exporter allow-list - dropped (NetFlow Analytics → Exporters & settings)', { peer: ip });
      return { accepted: false, reason: 'not on the exporter allow-list' };
    }
    const s = statOf(ip, e);
    let r;
    try { r = decode(buf, { exporter: ip, cache, now: NOW }); } catch (err) {
      c.malformed++; s.errors++; s.last_error = String(err && err.message).slice(0, 200); s.last_error_at = t;
      every('netflow-decode-' + ip, 60000, 'warn', 'netflow: malformed datagram dropped', { exporter: ip, bytes: buf && buf.length, err: s.last_error });
      return { accepted: false, reason: s.last_error };
    }
    c.accepted++; s.datagrams++; s.last_seen = t; s.versions[r.version] = (s.versions[r.version] || 0) + 1;
    s.invalid += r.invalid || 0; s.no_template += r.no_template || 0; s.counters += r.counters || 0; c.invalid_records += r.invalid || 0; c.no_template += r.no_template || 0;
    if (r.sampling) s.sampling = r.sampling; if (r.agent) s.agent = r.agent;
    if (r.no_template) every('netflow-notemplate-' + ip, 600000, 'info', 'netflow: data before its template - dropped until the exporter re-sends the template', { exporter: ip, version: r.version });
    if (r.invalid) every('netflow-invalid-' + ip, 600000, 'warn', 'netflow: records with impossible values dropped', { exporter: ip, invalid: r.invalid });
    for (const rec of r.records) ingest(rec, ip, e, s, r.version, t);
    return { accepted: true, records: r.records.length, version: r.version };
  }

  // a finished minute → rows + summary; the bucket leaves memory before anything is awaited
  const pending = [];
  function closeMinute(m) {
    const b = buckets.get(m); if (!b) return; buckets.delete(m);
    const minute = m * 60, hour = Math.floor(m / 60) * 3600;
    const rows = [...b.keys.values()].map((a) => Object.assign({ minute }, a));
    const ifRows = [...b.ifs.values()].map((x) => Object.assign({ minute }, x));
    const ipRows = [...b.ips.values()].map((x) => Object.assign({ hour }, x));
    const exp = {}, apps = new Map(), talk = new Map();
    for (const a of rows) {
      const e = exp[a.exporter] || (exp[a.exporter] = { bytes: 0, packets: 0, flows: 0 }); e.bytes += a.bytes; e.packets += a.packets; e.flows += a.flows;
      apps.set(a.app, (apps.get(a.app) || 0) + a.bytes);
      if (a.src_ip) talk.set(a.src_ip, (talk.get(a.src_ip) || 0) + a.bytes);
      if (a.dst_ip) talk.set(a.dst_ip, (talk.get(a.dst_ip) || 0) + a.bytes);
    }
    const top = (m2, n) => [...m2.entries()].sort((x, y) => y[1] - x[1]).slice(0, n);
    const summary = { minute: m * 60000, bytes: b.bytes, packets: b.packets, flows: b.flows, exporters: exp,
      interfaces: ifRows.slice(0, 2000).map((x) => ({ exporter: x.exporter, if_index: x.if_index, dir: x.dir, bytes: x.bytes, packets: x.packets })),
      apps: top(apps, 20).map(([app, bytes]) => ({ app, bytes })), talkers: top(talk, 20).map(([ip, bytes]) => ({ ip, bytes })) };
    ring.push(summary); while (ring.length > RING) ring.shift();
    if (o.onMinute) { try { o.onMinute(Object.assign({}, summary, { ips: ipRows, app_totals: Object.fromEntries(apps), all_talkers: top(talk, 200).map(([ip, bytes]) => ({ ip, bytes })) })); } catch (err) { c.observer_errors++; every('netflow-onminute', 60000, 'error', 'netflow: minute analytics failed', { err: String(err && err.message).slice(0, 200) }); } }
    pending.push(['flow_minute', rows], ['flow_if_minute', ifRows], ['flow_ip_hour', ipRows], ['flow_raw', b.raw]);
  }
  async function insert(table, rows) {
    if (!rows.length) return;
    if (!ch || typeof ch.insertRows !== 'function') { c.rows_dropped += rows.length; return; }
    for (let i = 0; i < rows.length; i += INSERT_CHUNK) {
      const part = rows.slice(i, i + INSERT_CHUNK);
      try { await ch.insertRows(db + '.' + table, part); c.rows_written += part.length; } catch (err) {
        c.insert_errors++; c.rows_dropped += part.length;
        every('netflow-insert-' + table, 60000, 'error', 'netflow: rollup insert failed - this minute\'s rows are dropped', { table, rows: part.length, err: String(err && err.message).slice(0, 200) });
      }
    }
  }
  async function flush(force) {
    const cur = Math.floor(NOW() / 60000);
    const due = [...buckets.keys()].filter((m) => force || m < cur).sort((a, b) => a - b);
    for (const m of due) closeMinute(m);
    const work = pending.splice(0);
    let rows = 0; for (const [t, r] of work) { rows += r.length; await insert(t, r); }
    if (cache) cache.sweep();
    c.flushes++;
    return { minutes: due.length, rows };
  }

  // the flush loop reschedules itself in finally, aligned just after each minute boundary
  function schedule() { if (!running) return; timer = setTimeout(tick, 60000 - (NOW() % 60000) + 250); if (timer.unref) timer.unref(); }
  const tick = guard('netflow.collector.flush', async () => { try { await flush(false); } finally { schedule(); } });

  async function bindOne(port, name, host) {
    const s = sock.createSocket({ type: net.isIPv6(host) ? 'udp6' : 'udp4', reuseAddr: true });
    s.on('message', (msg, rinfo) => {
      try { handle(msg, rinfo.address); } catch (err) { c.malformed++; every('netflow-handler', 60000, 'error', 'netflow: datagram handler failed', { err: String(err && err.message).slice(0, 200) }); }
    });
    await new Promise((resolve, reject) => {
      s.once('error', reject);
      s.bind({ port, address: host }, () => {
        s.removeListener('error', reject);
        s.on('error', (err) => every('netflow-sock-' + name, 60000, 'error', 'netflow: listener error', { listener: name, err: err.message }));
        try { s.setRecvBufferSize(8 * 1024 * 1024); } catch (err) { L.debug('netflow: receive buffer not enlarged (OS limit net.core.rmem_max)', { err: err.message }); }
        listeners[name] = { host, port: s.address().port };
        resolve();
      });
    });
    sockets.push(s);
  }
  async function start() {
    if (running) return;
    reload();
    listenErrors.length = 0;
    if (!cfg.enabled) { L.info('netflow: collector disabled (NetFlow Analytics → Exporters & settings)'); return; }
    const seen = new Set();
    for (const [name, port] of Object.entries(cfg.ports || {})) {
      if (!port || seen.has(port)) continue; seen.add(port);
      try { await bindOne(port, name, cfg.host); } catch (err) { listenErrors.push({ listener: name, port, error: String(err.message).slice(0, 200) }); L.error('netflow: listener not started', { listener: name, port, err: err.message }); }
    }
    running = true; schedule();
    L.info('netflow: listening', { listeners, exporters: allow.size });
  }
  async function stop() {
    running = false;
    if (timer) clearTimeout(timer); timer = null;
    await Promise.all(sockets.splice(0).map((s) => new Promise((r) => { try { s.close(() => r()); } catch (err) { r(); /* already closed */ } })));
    for (const k of Object.keys(listeners)) delete listeners[k];
    await flush(true);
  }
  async function restart() { await stop(); await start(); }

  function stats() {
    const ex = [...exporters.values()].map((s) => Object.assign({}, s, { configured: allow.has(s.ip), templates: cache ? cache.count(s.ip) : 0 }));
    for (const [ip, e] of allow) if (!exporters.has(ip)) ex.push({ ip, name: e.name || '', configured: true, datagrams: 0, records: 0, bytes: 0, packets: 0, errors: 0, invalid: 0, no_template: 0, counters: 0, last_seen: 0, versions: {}, sampling: null, templates: 0 });
    let open = 0; for (const b of buckets.values()) open += b.keys.size;
    return { enabled: !!cfg.enabled, running, listeners: Object.assign({}, listeners), listen_errors: listenErrors.slice(), counters: Object.assign({}, c),
      exporters: ex.sort((a, b) => b.last_seen - a.last_seen), unknown: [...unknown.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, 50),
      templates: cache ? cache.stats() : null, open_rows: open, limits: { max_keys: cfg.max_keys, raw_per_minute: cfg.raw_per_minute, template_ttl_s: cfg.template_ttl_s } };
  }
  return { start, stop, restart, reload, handle, flush, stats, live: () => ring.slice(), get running() { return running; } };
}

module.exports = { createFlowCollector };
