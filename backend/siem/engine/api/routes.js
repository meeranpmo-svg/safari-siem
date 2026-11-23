// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Core API routes: health, search, histogram, top, tail (SSE), sources. (Ingest is registered by collect/http-ingest.js.)
//   register(api, { ch, config, log, search, tail, pipeline, writer, spool, syslog, ingest, tracker, parser, detector, extras })
// Response shapes follow the portal UI conventions (ui/sentra-soc-module.js).
const { VERSION } = require('../config');
const { verifyChain } = require('../store/writer');

const str = (v, max = 4096) => (v === undefined || v === null ? '' : String(v).slice(0, max));

function register(api, deps) {
  const { ch, config, log, search, tail, pipeline, writer, spool, syslog, ingest, tracker, parser } = deps;
  const started = Date.now();
  let chCache = { at: 0, v: null };
  let igCache = { at: 0, v: null };

  async function chHealth() {
    if (Date.now() - chCache.at < 5000 && chCache.v) return chCache.v;
    const t0 = Date.now();
    let v;
    try {
      const ok = await ch.ping(2000);
      if (!ok) v = { ok: false, error: 'ping failed' };
      else {
        const r = await ch.query('SELECT version() AS version', {}, { timeout_ms: 3000 });
        v = { ok: true, version: r[0] && r[0].version, latency_ms: Date.now() - t0 };
      }
    } catch (e) { v = { ok: false, error: e.message }; }
    chCache = { at: Date.now(), v };
    return v;
  }

  async function integrity(chOk) {
    const ws = writer ? writer.stats() : {};
    const local = { chain_len: ws.seq || 0, batches: ws.seq || 0, last_hash: ws.chain_head || null, lost_batches: ws.spool_failures || 0 };
    if (!chOk || !writer) return { ...local, ok: null, status: 'unknown', note: 'ClickHouse unavailable — chain not verified' };
    if (Date.now() - igCache.at > 60000 || !igCache.v) {
      try { igCache = { at: Date.now(), v: await verifyChain(ch, { node: writer.node, limit: 5000, retentionDays: config.retention_days }) }; } catch (e) { igCache = { at: Date.now(), v: { ok: null, status: 'unknown', error: e.message } }; }
    }
    const v = igCache.v;
    const lost = (ws.spool_failures || 0) + ((spool && spool.stats().dropped_batches) || 0);
    // a gap in the chain is only explained while batches wait in the spool; otherwise it is reported
    const spooled = spool ? spool.stats().bytes > 0 : false;
    const unexplainedGaps = (v.gaps || 0) > 0 && !spooled;
    const status = v.ok === false ? v.status : lost ? 'data-lost' : unexplainedGaps ? 'gaps' : v.status;
    return { ...local, ...v, ok: v.ok === null ? null : v.ok && lost === 0 && !unexplainedGaps, status, lost_batches: lost, last_verified: v.verified_at };
  }

  // relays configured (sources[].type "relay") or seen by the HTTPS ingest, with their live statistics
  function relayList() {
    const live = ingest && typeof ingest.relayStats === 'function' ? safeArr(() => ingest.relayStats()) : [];
    const byId = new Map(live.map((r) => [r.relay_id, r]));
    for (const s of config.sources || []) {
      if (s && s.type === 'relay' && !byId.has(s.id)) byId.set(s.id, { relay_id: s.id, collector: 'relay:' + s.id, last_batch: null, batches: 0, events: 0, rejected: 0, header_replays: 0, eps_1m: 0, peers_seen: 0, files_seen: 0, peers: [], files: [] });
    }
    return [...byId.values()];
  }

  function collectors() {
    const out = [];
    const sc = config.syslog || {};
    const ss = syslog ? syslog.stats() : { listeners: {}, peers: [] };
    const epsBy = {};
    for (const p of ss.peers || []) epsBy[p.collector] = (epsBy[p.collector] || 0) + p.eps_1m;
    const add = (name, key, conf) => {
      const l = ss.listeners[key];
      const enabled = !!(conf && conf.enabled !== false && (key !== 'tls' || conf.enabled));
      out.push({ name, enabled, listening: !!l, ok: enabled ? !!l : null, bind: l ? `${l.host}:${l.port}` : (conf ? `${sc.host}:${conf.port}` : ''), port: l ? l.port : conf && conf.port, eps: Math.round((epsBy[name] || 0) * 10) / 10, error: enabled && !l ? 'not listening' : undefined });
    };
    add('syslog-udp', 'udp', sc.udp);
    add('syslog-tcp', 'tcp', sc.tcp);
    add('syslog-tls', 'tls', sc.tls);
    const hs = ingest ? ingest.stats() : null;
    const addr = api.address ? api.address() : null;
    out.push({ name: 'http-ingest', enabled: true, listening: !!addr, ok: !!addr, bind: addr ? `${addr.address}:${addr.port} /ingest/<src_id>` : '', port: addr ? addr.port : undefined, requests: hs ? hs.requests : 0, accepted: hs ? hs.accepted : 0, auth_failures: hs ? hs.auth_failures : 0 });
    for (const r of relayList()) {
      const fresh = r.last_batch && Date.now() - r.last_batch < 300000;
      out.push({ name: r.collector, enabled: true, listening: null, ok: !!fresh, eps: r.eps_1m, last_batch: r.last_batch, batches: r.batches, events: r.events, rejected: r.rejected, peers_seen: r.peers_seen, error: fresh ? undefined : 'no batch from relay in the last 5 minutes' });
    }
    for (const [name, s] of Object.entries(deps.extras || {})) {
      const st = typeof s === 'function' ? s() : s;
      out.push({ name, enabled: !!(st && st.enabled), listening: null, ok: st && st.enabled ? !!st.implemented : null, ...(st || {}) });
    }
    return out;
  }

  api.route('GET', '/api/soc/health', async (ctx) => {
    if (!ctx.role) {
      // without the proxy secret (no identity) only the overall status is shown — no URLs, versions or bind addresses
      const ck = await chHealth();
      const spl = spool ? spool.stats() : null;
      return { status: !ck.ok || (spl && spl.bytes > 0) ? 'degraded' : 'ok' };
    }
    const mem = process.memoryUsage();
    const p = pipeline.stats();
    const det = deps.detector;
    let detector = { running: false };
    if (det && typeof det.stats === 'function') {
      const d = safe(() => det.stats());
      detector = { running: true, ...d, rules: Array.isArray(d.rules) ? (d.rules_loaded !== undefined ? d.rules_loaded : d.rules.length) : d.rules };
    }
    const clickhouse = await chHealth();
    const sp = spool ? spool.stats() : null;
    const ig = await integrity(clickhouse.ok);
    const degraded = !clickhouse.ok || (sp && sp.bytes > 0) || ig.ok === false;
    return {
      status: degraded ? 'degraded' : 'ok',
      engine: { status: degraded ? 'degraded' : 'ok', version: VERSION, node: process.version, pid: process.pid, uptime_s: Math.round((Date.now() - started) / 1000), rss_mb: Math.round(mem.rss / 1048576), heap_mb: Math.round(mem.heapUsed / 1048576), node_name: config.node_name },
      clickhouse: { ...clickhouse, url: ch.url, client: ch.stats ? ch.stats() : undefined },
      spool: sp,
      integrity: ig,
      collectors: collectors(),
      eps: { now: p.eps_10s, m1: p.eps_1m, '1m': p.eps_1m },
      pipeline: p,
      writer: writer ? writer.stats() : null,
      detector,
      tail: tail ? tail.stats() : null,
      parser: parser ? parser.stats().by_parser : null,
    };
  });

  api.route('POST', '/api/soc/search', async (ctx) => {
    // raw events hold personal data (sign-ins, mailbox and logon activity of named people - PDPL): analyst and above
    ctx.need('analyst');
    const b = ctx.body || {};
    return search({ q: str(b.q), from: b.from, to: b.to, limit: b.limit === undefined ? 100 : b.limit, offset: b.offset, fields: b.fields, order: b.order });
  }, { auditRead: true });

  api.route('POST', '/api/soc/histogram', async (ctx) => {
    // raw events hold personal data (sign-ins, mailbox and logon activity of named people - PDPL): analyst and above
    ctx.need('analyst');
    const b = ctx.body || {};
    return search.histogram({ q: str(b.q), from: b.from, to: b.to, buckets: b.buckets === undefined ? 60 : b.buckets });
  }, { auditRead: true });

  api.route('POST', '/api/soc/top', async (ctx) => {
    // raw events hold personal data (sign-ins, mailbox and logon activity of named people - PDPL): analyst and above
    ctx.need('analyst');
    const b = ctx.body || {};
    return search.top({ q: str(b.q), from: b.from, to: b.to, field: b.field, limit: b.limit === undefined ? 10 : b.limit });
  }, { auditRead: true });

  // Log Monitor & Analysis (logmon.js): volume, rate against the window's median, severity mix, top values and log template mining
  // (new / spiking / dropped patterns against the previous window) - read only, analysts and above (raw lines are personal data)
  require('./logmon').register(api, { search });

  api.route('GET', '/api/soc/tail', (ctx) => { ctx.need('analyst'); return tail.handler(ctx); }, { auditRead: true });   // live raw events: personal data, analyst and above

  api.route('GET', '/api/soc/sources', async (ctx) => {
    ctx.need('viewer');   // log source statistics: any signed-in role (no event content, no personal data)
    const live = new Map(tracker.summary().map((s) => [s.src_id, s]));
    let today = null;
    try {
      const rows = await ch.query(
        `SELECT src_id, any(src_type) AS src_type, sum(events) AS events, sum(parse_errors) AS parse_errors, max(minute) AS last_minute
         FROM ${(config.clickhouse && config.clickhouse.database) || 'siem'}.stats_minute
         WHERE minute >= toStartOfDay(now({tz:String})) GROUP BY src_id`,
        { tz: { type: 'String', value: config.timezone || 'UTC' } }, { readonly: true, timeout_ms: 5000 });
      today = new Map(rows.map((r) => [r.src_id, r]));
    } catch (e) {
      if (log) log.every('sources-today', 60000, 'warn', 'sources: stats_minute unavailable', { err: e.message });
    }
    const now = Date.now();
    const relays = relayList();
    const relayById = new Map(relays.map((r) => [r.relay_id, r]));
    const ids = new Set([...(config.sources || []).map((s) => s.id), ...live.keys(), ...(today ? today.keys() : [])]);
    const cfgById = new Map((config.sources || []).map((s) => [s.id, s]));
    const out = [];
    for (const id of ids) {
      const c = cfgById.get(id);
      const rl = c && c.type === 'relay' ? relayById.get(id) : null;
      if (rl) { // a relay produces no events of its own (they carry the original senders' src_id): report its batches
        const lastSeen = rl.last_batch || 0;
        out.push({
          src_id: id, configured: true, src_type: 'relay', type: 'relay', collector: rl.collector, last_seen: lastSeen || null,
          eps_1m: rl.eps_1m, eps_1h: 0, events_today: null, parse_errors_today: null, events_since_start: rl.events, parse_error_rate: 0, hosts: [],
          status: !lastSeen || now - lastSeen > ((c.silent_after_s || 300) * 1000) ? 'silent' : rl.last_rejection_at && now - rl.last_rejection_at < 900000 ? 'errors' : 'ok',
          relay: { batches: rl.batches, events: rl.events, rejected: rl.rejected, last_rejection: rl.last_rejection, header_replays: rl.header_replays, peers_seen: rl.peers_seen, files_seen: rl.files_seen, peers: rl.peers.slice(0, 50), files: rl.files.slice(0, 50), allowed_peers: [].concat(c.allowed_peers || []) },
        });
        continue;
      }
      const l = live.get(id);
      const t = today && today.get(id);
      const silentAfter = ((c && c.silent_after_s) || 900) * 1000;
      const lastSeen = l ? l.last_seen : (t && t.last_minute ? Date.parse(t.last_minute) : 0);
      const perr = l && l.eps_1h ? l.parse_error_rate_1h : (t && Number(t.events) ? Math.round((Number(t.parse_errors) / Number(t.events)) * 1000) / 1000 : (l ? l.parse_error_rate_1h : 0));
      let status = 'ok';
      if (!lastSeen || now - lastSeen > silentAfter) status = 'silent';
      else if (perr > 0.2) status = 'errors';
      out.push({
        src_id: id, configured: !!c, src_type: (l && l.src_type) || (t && t.src_type) || (c && c.type) || '', type: (c && c.type) || '',
        collector: (l && l.collector) || (c && c.collector) || '',
        last_seen: lastSeen || null, eps_1m: l ? l.eps_1m : 0, eps_1h: l ? l.eps_1h : 0,
        events_today: t ? Number(t.events) : (l ? l.events_since_start : 0), parse_errors_today: t ? Number(t.parse_errors) : null,
        events_since_start: l ? l.events_since_start : 0, parse_error_rate: perr, hosts: l ? l.hosts : [], status,
      });
    }
    out.sort((a, b) => (b.status === 'silent') - (a.status === 'silent') || (b.last_seen || 0) - (a.last_seen || 0));
    // relays: collector info for agentless relays (last batch, eps, peers seen); events of relayed sources carry
    // collector "relay:<relay id>" in their own rows
    return { sources: out, stats_available: !!today, relays: relays.map((r) => ({ ...r, peers: r.peers.slice(0, 200), files: r.files.slice(0, 200) })) };
  });
}

function safe(fn) { try { return fn() || {}; } catch (e) { return { error: e.message }; } }
function safeArr(fn) { try { const v = fn(); return Array.isArray(v) ? v : []; } catch { return []; } }

module.exports = { register };
